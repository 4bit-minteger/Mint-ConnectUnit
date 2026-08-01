use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use indexmap::IndexMap;
use tokio::net::UdpSocket;

use super::background_cc::{BackgroundCcConfig, BackgroundCcEngine, CcUpdateCounters};
use super::pacing_defaults::{
    PaceRateMode, APD_SOJOURN_MS_MAX, APD_SOJOURN_MS_MIN, APD_SOJOURN_TARGET_MAX_GAP_MS,
    APD_TARGET_SOJOURN_MS_MAX, APD_TARGET_SOJOURN_MS_MIN, DEFAULT_APD_CONFIRM_TICKS,
    DEFAULT_APD_COOLDOWN_MS, DEFAULT_APD_DRAIN_FREEZE_DRR, DEFAULT_APD_DRAIN_TICK_US,
    DEFAULT_APD_ENABLED, DEFAULT_APD_HIGH_WM, DEFAULT_APD_LOW_WM, DEFAULT_APD_MAX_SOJOURN_MS,
    DEFAULT_APD_REQUIRE_CC_HEADROOM, DEFAULT_APD_SOJOURN_ENABLED, DEFAULT_APD_SPINLOOP_BUDGET_MS,
    DEFAULT_APD_TARGET_SOJOURN_MS, DEFAULT_DRAIN_MAX_BURST, DEFAULT_DRR_SMALL_PACKET_PRIORITY,
    DEFAULT_DRR_SMALL_PACKET_THRESHOLD_BYTES, DEFAULT_MAX_TICK_WORK_US,
    DEFAULT_PACE_BUDGET_PACKETS, DEFAULT_PACE_BURST_PER_TICK, DEFAULT_PACE_MAX_QUEUE,
    DEFAULT_PACE_TARGET_PPS, DEFAULT_PACE_TICK_US, DEFAULT_RAMP_MAX_BURST, DEFAULT_SHED_ENABLED,
    DEFAULT_SHED_MAX_PER_TICK, DEFAULT_SHED_MAX_SOJOURN_MS, DEFAULT_SHED_MIN_FILL,
    DRR_BULK_HOL_FORCE_MS, DRR_SMALL_BULK_FORCE_AFTER, DRR_SMALL_PACKET_THRESHOLD_MAX,
    DRR_SMALL_PACKET_THRESHOLD_MIN, SHED_MAX_PER_TICK_MAX, SHED_MAX_PER_TICK_MIN, SHED_MIN_FILL_HI,
    SHED_MIN_FILL_LO, SHED_SOJOURN_MS_MAX, SHED_SOJOURN_MS_MIN,
};

// ── APD types ────────────────────────────────────────────────────────────────

const APD_WM_GAP: f32 = 0.1;
const APD_WM_SANITIZE_GAP: f32 = 0.1;
const APD_WM_EPS: f32 = 1e-6;

/// Single-threshold cap: `high_watermark == low_watermark` (queue fill ratio).
pub fn apd_is_cap_mode(cfg: ApdConfig) -> bool {
    (cfg.high_watermark - cfg.low_watermark).abs() < APD_WM_EPS
}

/// Phase of the Adaptive Precision Drain state machine.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ApdPhase {
    Cooldown,
    Alert,
    Drain,
}

/// User-facing configuration for APD (all fields validated by `sanitize()`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ApdConfig {
    pub enabled: bool,
    pub high_watermark: f32,
    pub low_watermark: f32,
    pub ramp_max_burst: u64,
    pub drain_max_burst: u64,
    /// Per-episode spin time cap in Drain (ms). `0` = no time limit (exit on low watermark only).
    pub spinloop_budget_ms: u32,
    pub drain_tick_us: u64,
    /// Ticks above high watermark before Drain. `0` = enter Drain on first tick above high.
    pub confirm_ticks: u32,
    pub cooldown_ms: u32,
    pub drain_freeze_drr: bool,
    pub sojourn_enabled: bool,
    pub max_sojourn_ms: f32,
    pub target_sojourn_ms: f32,
    /// When true and background CC is enabled, suppress APD ramp-up / Drain arm /
    /// mid-Drain spin unless at least one non-empty data peer is CC-sendable.
    pub require_cc_headroom: bool,
}

impl Default for ApdConfig {
    fn default() -> Self {
        Self {
            enabled: DEFAULT_APD_ENABLED,
            high_watermark: DEFAULT_APD_HIGH_WM,
            low_watermark: DEFAULT_APD_LOW_WM,
            ramp_max_burst: DEFAULT_RAMP_MAX_BURST,
            drain_max_burst: DEFAULT_DRAIN_MAX_BURST,
            spinloop_budget_ms: DEFAULT_APD_SPINLOOP_BUDGET_MS,
            drain_tick_us: DEFAULT_APD_DRAIN_TICK_US,
            confirm_ticks: DEFAULT_APD_CONFIRM_TICKS,
            cooldown_ms: DEFAULT_APD_COOLDOWN_MS,
            drain_freeze_drr: DEFAULT_APD_DRAIN_FREEZE_DRR,
            sojourn_enabled: DEFAULT_APD_SOJOURN_ENABLED,
            max_sojourn_ms: DEFAULT_APD_MAX_SOJOURN_MS as f32,
            target_sojourn_ms: DEFAULT_APD_TARGET_SOJOURN_MS as f32,
            require_cc_headroom: DEFAULT_APD_REQUIRE_CC_HEADROOM,
        }
    }
}

impl ApdConfig {
    /// Enforce `high >= low` and `high >= low + gap` (or single cap when equal), then absolute bounds.
    pub fn enforce_watermark_pair(low_wm: f32, high_wm: f32) -> (f32, f32) {
        let low = low_wm.clamp(0.10, 0.80);
        let high = high_wm;
        if (high - low).abs() < APD_WM_EPS {
            let cap = low.clamp(0.20, 0.95);
            return (cap, cap);
        }
        let floor = 0.20_f32.max(low).max(low + APD_WM_GAP);
        let high = high.max(low).max(floor).clamp(floor, 0.95);
        (low, high)
    }

    /// Clamp to documented user ranges (APD plan §7.1) before `sanitize()`.
    pub fn clamp_to_user_ranges(&mut self, base_tick_us: u64, base_burst_per_tick: u64) {
        self.low_watermark = self.low_watermark.clamp(0.10, 0.80);
        if apd_is_cap_mode(*self) {
            let cap = self.low_watermark.clamp(0.20, 0.95).clamp(0.10, 0.80);
            self.low_watermark = cap;
            self.high_watermark = cap;
        } else {
            let (l, h) = Self::enforce_watermark_pair(self.low_watermark, self.high_watermark);
            self.low_watermark = l;
            self.high_watermark = h;
        }
        let floor = base_burst_per_tick.max(1);
        self.ramp_max_burst = self.ramp_max_burst.clamp(floor, 200);
        self.drain_max_burst = self.drain_max_burst.clamp(1, self.ramp_max_burst.max(1));
        self.spinloop_budget_ms = self.spinloop_budget_ms.clamp(0, 100);
        self.drain_tick_us = self.drain_tick_us.min(base_tick_us.max(1));
        self.confirm_ticks = self.confirm_ticks.clamp(0, 10);
        self.cooldown_ms = self.cooldown_ms.clamp(0, 500);
        self.max_sojourn_ms = self
            .max_sojourn_ms
            .clamp(APD_SOJOURN_MS_MIN as f32, APD_SOJOURN_MS_MAX as f32);
        self.target_sojourn_ms = self.target_sojourn_ms.clamp(
            APD_TARGET_SOJOURN_MS_MIN as f32,
            APD_TARGET_SOJOURN_MS_MAX as f32,
        );
        let gap = APD_SOJOURN_TARGET_MAX_GAP_MS as f32;
        if self.target_sojourn_ms + gap > self.max_sojourn_ms {
            self.target_sojourn_ms =
                (self.max_sojourn_ms - gap).max(APD_TARGET_SOJOURN_MS_MIN as f32);
        }
    }

    pub fn sanitize(&mut self) {
        self.low_watermark = self.low_watermark.clamp(0.0, 1.0);
        self.high_watermark = self.high_watermark.clamp(0.0, 1.0);
        if apd_is_cap_mode(*self) {
            let cap = self
                .low_watermark
                .max(self.high_watermark)
                .clamp(0.20, 0.95);
            self.low_watermark = cap;
            self.high_watermark = cap;
        } else {
            let gap = APD_WM_SANITIZE_GAP;
            if self.high_watermark < self.low_watermark + gap {
                self.high_watermark = self.low_watermark + gap;
            }
            self.high_watermark = self.high_watermark.clamp(0.20, 1.0);
            self.low_watermark = self.low_watermark.clamp(0.0, self.high_watermark - gap);
        }
        self.ramp_max_burst = self.ramp_max_burst.max(1);
        self.drain_max_burst = self.drain_max_burst.max(1).min(self.ramp_max_burst);
        self.max_sojourn_ms = self
            .max_sojourn_ms
            .clamp(APD_SOJOURN_MS_MIN as f32, APD_SOJOURN_MS_MAX as f32);
        self.target_sojourn_ms = self.target_sojourn_ms.clamp(
            APD_TARGET_SOJOURN_MS_MIN as f32,
            APD_TARGET_SOJOURN_MS_MAX as f32,
        );
        let gap = APD_SOJOURN_TARGET_MAX_GAP_MS as f32;
        if self.target_sojourn_ms + gap > self.max_sojourn_ms {
            self.target_sojourn_ms =
                (self.max_sojourn_ms - gap).max(APD_TARGET_SOJOURN_MS_MIN as f32);
        }
    }
}

/// Linear ramp target between base and max burst using queue fill between low/high watermarks.
fn apd_ramp_target_burst(fill_ratio: f32, base_burst: u64, max_burst: u64, cfg: ApdConfig) -> u64 {
    let max_burst = max_burst.max(base_burst);
    if apd_is_cap_mode(cfg) {
        if fill_ratio > cfg.high_watermark {
            return max_burst;
        }
        return base_burst;
    }
    if fill_ratio <= cfg.low_watermark {
        return base_burst;
    }
    let range = (cfg.high_watermark - cfg.low_watermark).max(f32::EPSILON);
    let t = ((fill_ratio - cfg.low_watermark) / range).clamp(0.0, 1.0);
    let burst = base_burst as f32 + t * (max_burst as f32 - base_burst as f32);
    burst.round().max(base_burst as f32) as u64
}

pub fn apd_config_from_network(cfg: &crate::config::NetworkConfig) -> ApdConfig {
    let tick = super::pacing_defaults::effective_pace_tick_us(cfg.pace_tick_us);
    let base_burst = super::pacing_defaults::effective_base_max_burst(cfg.base_max_burst);
    let mut apd = ApdConfig {
        enabled: cfg.apd_enabled,
        high_watermark: cfg.apd_high_watermark,
        low_watermark: cfg.apd_low_watermark,
        ramp_max_burst: cfg.ramp_max_burst,
        drain_max_burst: cfg.drain_max_burst,
        spinloop_budget_ms: cfg.apd_spinloop_budget_ms,
        drain_tick_us: cfg.apd_drain_tick_us,
        confirm_ticks: cfg.apd_confirm_ticks,
        cooldown_ms: cfg.apd_cooldown_ms,
        drain_freeze_drr: cfg.apd_drain_freeze_drr,
        sojourn_enabled: cfg.apd_sojourn_enabled,
        max_sojourn_ms: cfg.apd_max_sojourn_ms as f32,
        target_sojourn_ms: cfg.apd_target_sojourn_ms as f32,
        require_cc_headroom: cfg.apd_require_cc_headroom,
    };
    apd.clamp_to_user_ranges(tick, base_burst);
    apd.sanitize();
    apd
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ShedConfig {
    pub enabled: bool,
    pub max_sojourn_ms: f32,
    pub min_fill: f32,
    pub max_per_tick: u32,
}

impl Default for ShedConfig {
    fn default() -> Self {
        Self {
            enabled: DEFAULT_SHED_ENABLED,
            max_sojourn_ms: DEFAULT_SHED_MAX_SOJOURN_MS as f32,
            min_fill: DEFAULT_SHED_MIN_FILL,
            max_per_tick: DEFAULT_SHED_MAX_PER_TICK,
        }
    }
}

impl ShedConfig {
    pub fn sanitize(&mut self, apd_cfg: ApdConfig) {
        self.max_sojourn_ms = self
            .max_sojourn_ms
            .clamp(SHED_SOJOURN_MS_MIN as f32, SHED_SOJOURN_MS_MAX as f32);
        self.min_fill = self.min_fill.clamp(SHED_MIN_FILL_LO, SHED_MIN_FILL_HI);
        self.max_per_tick = self
            .max_per_tick
            .clamp(SHED_MAX_PER_TICK_MIN, SHED_MAX_PER_TICK_MAX);
        if self.enabled && apd_cfg.enabled && apd_cfg.sojourn_enabled {
            self.max_sojourn_ms = self.max_sojourn_ms.max(apd_cfg.max_sojourn_ms);
        }
    }
}

pub fn shed_config_from_network(cfg: &crate::config::NetworkConfig) -> ShedConfig {
    let mut shed = ShedConfig {
        enabled: cfg.shed_enabled,
        max_sojourn_ms: cfg.shed_max_sojourn_ms as f32,
        min_fill: cfg.shed_min_fill,
        max_per_tick: cfg.shed_max_per_tick,
    };
    shed.sanitize(apd_config_from_network(cfg));
    shed
}

struct ApdDecision {
    effective_burst: u64,
    freeze_drr: bool,
}

struct ApdState {
    phase: ApdPhase,
    confirm_counter: u32,
    drain_entered_at: Option<Instant>,
    cooldown_until: Option<Instant>,
    cfg: ApdConfig,
    // Metrics counters.
    drain_episodes: u64,
    drain_ms_total: u64,
    packets_drained: u64,
    drain_budget_hits: u64,
    // Signal cache — last values written; avoids redundant stores in engine.rs.
    last_pure_spin: bool,
    last_tick_us: u64,
    /// Tier-1 asymmetric ramp burst (packets per engine tick).
    ramp_burst: u64,
    last_fill_ratio: f32,
    last_effective_burst: u64,
    ramp_active_ticks: u64,
    ramp_pinned_ticks: u64,
    drain_arm_fill: u64,
    drain_arm_sojourn: u64,
    last_max_sojourn_ms: u64,
    cc_headroom_suppressions: u64,
}

impl ApdState {
    fn new(cfg: ApdConfig) -> Self {
        Self {
            phase: ApdPhase::Cooldown,
            confirm_counter: 0,
            drain_entered_at: None,
            cooldown_until: None,
            cfg,
            drain_episodes: 0,
            drain_ms_total: 0,
            packets_drained: 0,
            drain_budget_hits: 0,
            last_pure_spin: false,
            last_tick_us: 0,
            ramp_burst: 0,
            last_fill_ratio: 0.0,
            last_effective_burst: 0,
            ramp_active_ticks: 0,
            ramp_pinned_ticks: 0,
            drain_arm_fill: 0,
            drain_arm_sojourn: 0,
            last_max_sojourn_ms: 0,
            cc_headroom_suppressions: 0,
        }
    }
}

pub const MIN_PACE_TICK_US: u64 = 1;

pub fn queue_split_limits(total: usize) -> (usize, usize) {
    const MIN_DATA_QUEUE_FOR_FEC_GROUP: usize = 32;
    let total = total.max(2);
    let mut data = (total * 2 / 3).max(1);
    if total >= MIN_DATA_QUEUE_FOR_FEC_GROUP * 2 {
        data = data.max(MIN_DATA_QUEUE_FOR_FEC_GROUP);
    }
    if data >= total {
        data = total.saturating_sub(1).max(1);
    }
    let control = total.saturating_sub(data).max(1);
    (data, control)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PacingQueueSnapshot {
    pub data_queued: usize,
    pub control_queued: usize,
    pub retransmit_queued: usize,
    pub queue_capacity: usize,
    pub fill_ratio: f32,
}

#[derive(Clone, Copy, Debug)]
pub struct PacingConfig {
    pub tick_us: u64,
    pub target_pps: u64,
    pub base_max_burst: u64,
    pub budget_cap_packets: f64,
    pub max_queue_packets: usize,

    pub max_data_queue_packets: usize,
    pub max_control_queue_packets: usize,
    pub max_retransmit_queue_packets: usize,
    pub drr_quantum: usize,
    pub drr_enabled: bool,
    pub drr_small_packet_priority: bool,
    pub drr_small_packet_threshold_bytes: usize,
    pub drr_rtt_aware: bool,
    pub drr_rtt_scale_min: f32,
    pub drr_rtt_scale_max: f32,
    pub min_control_reserved_bytes_per_tick: usize,
    pub min_retransmit_reserved_bytes_per_tick: usize,
    pub max_tick_work_us: u64,
    pub apd: ApdConfig,
    pub shed: ShedConfig,
    pub background_cc: BackgroundCcConfig,
    pub pace_rate_mode: PaceRateMode,
    pub target_bps: u64,
}

impl Default for PacingConfig {
    fn default() -> Self {
        let max_queue_packets = DEFAULT_PACE_MAX_QUEUE as usize;
        let (max_data_queue_packets, max_control_queue_packets) =
            queue_split_limits(max_queue_packets);
        Self {
            tick_us: DEFAULT_PACE_TICK_US as u64,
            target_pps: DEFAULT_PACE_TARGET_PPS as u64,
            base_max_burst: DEFAULT_PACE_BURST_PER_TICK as u64,
            budget_cap_packets: DEFAULT_PACE_BUDGET_PACKETS,
            max_queue_packets,
            max_data_queue_packets,
            max_control_queue_packets,
            max_retransmit_queue_packets: (max_control_queue_packets / 3).max(4),
            drr_quantum: 1500,
            drr_enabled: true,
            drr_small_packet_priority: DEFAULT_DRR_SMALL_PACKET_PRIORITY,
            drr_small_packet_threshold_bytes: DEFAULT_DRR_SMALL_PACKET_THRESHOLD_BYTES as usize,
            drr_rtt_aware: crate::net::pacing_defaults::DEFAULT_DRR_RTT_AWARE,
            drr_rtt_scale_min: crate::net::pacing_defaults::effective_drr_rtt_scale_min(
                crate::net::pacing_defaults::DEFAULT_DRR_RTT_SCALE_MIN,
            ),
            drr_rtt_scale_max: crate::net::pacing_defaults::effective_drr_rtt_scale_max(
                crate::net::pacing_defaults::DEFAULT_DRR_RTT_SCALE_MAX,
            ),
            min_control_reserved_bytes_per_tick:
                crate::net::pacing_defaults::DEFAULT_MIN_CONTROL_RESERVED_BYTES_PER_TICK as usize,
            min_retransmit_reserved_bytes_per_tick:
                crate::net::pacing_defaults::DEFAULT_MIN_RETRANSMIT_RESERVED_BYTES_PER_TICK as usize,
            max_tick_work_us: DEFAULT_MAX_TICK_WORK_US,
            apd: ApdConfig::default(),
            shed: ShedConfig::default(),
            background_cc: BackgroundCcConfig::default(),
            pace_rate_mode: PaceRateMode::Bytes,
            target_bps: 1_000_000,
        }
    }
}

pub const MIN_DRR_QUANTUM: usize = 1500;

/// Per-peer DRR quantum from base RTT vs reference median (fairness; not smoothed/QD).
fn scaled_drr_quantum(
    base: usize,
    peer_rtt_ms: f32,
    rtt_ref_ms: f32,
    aware: bool,
    scale_min: f32,
    scale_max: f32,
) -> usize {
    let base = base.max(1);
    if !aware || rtt_ref_ms <= 0.0 || peer_rtt_ms <= 0.0 {
        return base.max(MIN_DRR_QUANTUM);
    }
    let scale = (peer_rtt_ms / rtt_ref_ms).clamp(scale_min, scale_max);
    let q = (base as f32 * scale).round() as usize;
    q.max(MIN_DRR_QUANTUM)
}

fn median_positive_rtt(mut samples: Vec<f32>) -> f32 {
    samples.retain(|v| *v > 0.0);
    if samples.is_empty() {
        return -1.0;
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = samples.len() / 2;
    if samples.len() % 2 == 1 {
        samples[mid]
    } else {
        (samples[mid - 1] + samples[mid]) * 0.5
    }
}

impl PacingConfig {
    pub fn refresh_queue_splits(&mut self) {
        let (d, c) = queue_split_limits(self.max_queue_packets);
        self.max_data_queue_packets = d;
        self.max_control_queue_packets = c;
        self.max_retransmit_queue_packets = (c / 3).max(4);
    }

    pub fn sanitize(&mut self) {
        self.drr_quantum = self.drr_quantum.max(MIN_DRR_QUANTUM);
        self.drr_small_packet_threshold_bytes = self.drr_small_packet_threshold_bytes.clamp(
            DRR_SMALL_PACKET_THRESHOLD_MIN,
            DRR_SMALL_PACKET_THRESHOLD_MAX,
        );
        self.drr_rtt_scale_min =
            crate::net::pacing_defaults::effective_drr_rtt_scale_min(self.drr_rtt_scale_min as f64);
        self.drr_rtt_scale_max =
            crate::net::pacing_defaults::effective_drr_rtt_scale_max(self.drr_rtt_scale_max as f64);
        if self.drr_rtt_scale_min > self.drr_rtt_scale_max {
            self.drr_rtt_scale_min = self.drr_rtt_scale_max;
        }
        let max_reserved = crate::net::pacing_defaults::PACE_RESERVED_BYTES_PER_TICK_MAX as usize;
        self.min_control_reserved_bytes_per_tick =
            self.min_control_reserved_bytes_per_tick.min(max_reserved);
        self.min_retransmit_reserved_bytes_per_tick = self
            .min_retransmit_reserved_bytes_per_tick
            .min(max_reserved);
        self.refresh_queue_splits();
        self.apd.sanitize();
        self.shed.sanitize(self.apd);
    }
}

pub struct PacingEngine {
    pub config: PacingConfig,
    control_q: VecDeque<QueuedPacket>,
    retransmit_q: VecDeque<QueuedPacket>,
    peer_queues: IndexMap<SocketAddr, PeerDataQueue>,

    non_empty_peers: usize,
    budget: f64,
    last_tick: Instant,
    dropped_packets: u64,
    dropped_data: u64,
    dropped_control_normal: u64,
    dropped_control_retransmit: u64,
    consecutive_errors: u32,
    interleave_counter: u8,
    drr_cursor: usize,
    apd: ApdState,
    reserved_ctrl_sends: u64,
    reserved_rtx_sends: u64,
    drr_small_priority_pops: u64,
    drr_bulk_force_pops: u64,
    shed_sojourn: u64,
    cached_rtt_ref_ms: f32,
    drr_rtt_scale_applied: u64,
    cc_rate_limited_events: u64,
    background_cc: BackgroundCcEngine,
}

pub enum TickResult {
    Progress(usize),

    SocketDead {
        error: std::io::Error,
        last_failed_dest: Option<SocketAddr>,
    },
}
struct QueuedPacket {
    pkt: Bytes,
    dest: SocketAddr,
    enqueued_at: Instant,
}

struct QueuedData {
    pkt: Bytes,
    enqueued_at: Instant,
}

struct PeerDataQueue {
    small: VecDeque<QueuedData>,
    bulk: VecDeque<QueuedData>,
    deficit: usize,
    consecutive_small_pops: u8,
    /// DRR fairness RTT (route `rtt_base_ms` / propagation); not smoothed RTT.
    rtt_ms: f32,
    queuing_delay_ms: f32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeerPopKind {
    SmallPriority,
    Bulk,
    BulkForced,
}

impl PeerDataQueue {
    fn new() -> Self {
        Self {
            small: VecDeque::new(),
            bulk: VecDeque::new(),
            deficit: 0,
            consecutive_small_pops: 0,
            rtt_ms: -1.0,
            queuing_delay_ms: -1.0,
        }
    }

    fn is_small_packet(pkt_len: usize, priority_on: bool, threshold: usize) -> bool {
        priority_on && pkt_len < threshold
    }

    fn drop_oldest_for_capacity(&mut self) {
        if !self.bulk.is_empty() {
            let _ = self.bulk.pop_front();
        } else {
            let _ = self.small.pop_front();
        }
    }

    fn push(&mut self, pkt: Bytes, max_depth: usize, priority_on: bool, threshold: usize) -> bool {
        let entry = QueuedData {
            pkt,
            enqueued_at: Instant::now(),
        };
        let to_small = Self::is_small_packet(entry.pkt.len(), priority_on, threshold);
        if self.small.len() + self.bulk.len() >= max_depth {
            self.drop_oldest_for_capacity();
            if to_small {
                self.small.push_back(entry);
            } else {
                self.bulk.push_back(entry);
            }
            return false;
        }
        if to_small {
            self.small.push_back(entry);
        } else {
            self.bulk.push_back(entry);
        }
        true
    }

    fn push_back_classified(&mut self, entry: QueuedData, priority_on: bool, threshold: usize) {
        if Self::is_small_packet(entry.pkt.len(), priority_on, threshold) {
            self.small.push_back(entry);
        } else {
            self.bulk.push_back(entry);
        }
    }

    fn push_front_requeue(&mut self, entry: QueuedData, priority_on: bool, threshold: usize) {
        if Self::is_small_packet(entry.pkt.len(), priority_on, threshold) {
            self.small.push_front(entry);
        } else {
            self.bulk.push_front(entry);
        }
    }

    fn pop_fifo_by_age(&mut self) -> Option<QueuedData> {
        match (self.small.front(), self.bulk.front()) {
            (Some(s), Some(b)) => {
                if s.enqueued_at <= b.enqueued_at {
                    self.small.pop_front()
                } else {
                    self.bulk.pop_front()
                }
            }
            (Some(_), None) => self.small.pop_front(),
            (None, Some(_)) => self.bulk.pop_front(),
            (None, None) => None,
        }
    }

    fn bulk_hol_sojourn_ms(&self, now: Instant) -> f32 {
        self.bulk
            .front()
            .map(|e| now.duration_since(e.enqueued_at).as_secs_f32() * 1000.0)
            .unwrap_or(0.0)
    }

    fn bulk_front_sojourn_ms(&self, now: Instant) -> Option<f32> {
        self.bulk
            .front()
            .map(|e| now.duration_since(e.enqueued_at).as_secs_f32() * 1000.0)
    }

    fn pop_bulk_front(&mut self) -> Option<QueuedData> {
        self.bulk.pop_front()
    }

    fn should_force_bulk(&self, now: Instant) -> bool {
        if self.bulk.is_empty() {
            return false;
        }
        self.consecutive_small_pops >= DRR_SMALL_BULK_FORCE_AFTER
            || self.bulk_hol_sojourn_ms(now) >= DRR_BULK_HOL_FORCE_MS as f32
    }

    fn pop_data(
        &mut self,
        priority_on: bool,
        _threshold: usize,
        now: Instant,
    ) -> Option<(QueuedData, PeerPopKind)> {
        if self.small.is_empty() && self.bulk.is_empty() {
            return None;
        }
        if !priority_on {
            return self.pop_fifo_by_age().map(|e| (e, PeerPopKind::Bulk));
        }
        if self.should_force_bulk(now) {
            self.consecutive_small_pops = 0;
            return self.bulk.pop_front().map(|e| (e, PeerPopKind::BulkForced));
        }
        if !self.small.is_empty() {
            self.consecutive_small_pops = self.consecutive_small_pops.saturating_add(1);
            return self
                .small
                .pop_front()
                .map(|e| (e, PeerPopKind::SmallPriority));
        }
        self.consecutive_small_pops = 0;
        self.bulk.pop_front().map(|e| (e, PeerPopKind::Bulk))
    }

    fn front_len(&self, priority_on: bool, _threshold: usize, now: Instant) -> usize {
        if self.small.is_empty() && self.bulk.is_empty() {
            return 0;
        }
        if !priority_on {
            return match (self.small.front(), self.bulk.front()) {
                (Some(s), Some(b)) => {
                    if s.enqueued_at <= b.enqueued_at {
                        s.pkt.len()
                    } else {
                        b.pkt.len()
                    }
                }
                (Some(s), None) => s.pkt.len(),
                (None, Some(b)) => b.pkt.len(),
                (None, None) => 0,
            };
        }
        if self.should_force_bulk(now) {
            return self.bulk.front().map(|p| p.pkt.len()).unwrap_or(0);
        }
        if let Some(p) = self.small.front() {
            return p.pkt.len();
        }
        self.bulk.front().map(|p| p.pkt.len()).unwrap_or(0)
    }

    fn hol_sojourn_ms(&self, now: Instant) -> f32 {
        let small_ms = self
            .small
            .front()
            .map(|e| now.duration_since(e.enqueued_at).as_secs_f32() * 1000.0)
            .unwrap_or(0.0);
        let bulk_ms = self.bulk_hol_sojourn_ms(now);
        small_ms.max(bulk_ms)
    }

    fn is_empty(&self) -> bool {
        self.small.is_empty() && self.bulk.is_empty()
    }

    fn len(&self) -> usize {
        self.small.len() + self.bulk.len()
    }
}

enum NextPacket {
    Control(QueuedPacket),
    Data {
        pkt: Bytes,
        dest: SocketAddr,
        enqueued_at: Instant,
    },
}

impl PacingEngine {
    pub fn new() -> Self {
        Self {
            config: PacingConfig::default(),
            control_q: VecDeque::new(),
            retransmit_q: VecDeque::new(),
            peer_queues: IndexMap::new(),
            non_empty_peers: 0,
            budget: 0.0,
            last_tick: Instant::now(),
            dropped_packets: 0,
            dropped_data: 0,
            dropped_control_normal: 0,
            dropped_control_retransmit: 0,
            consecutive_errors: 0,
            interleave_counter: 0,
            drr_cursor: 0,
            apd: ApdState::new(ApdConfig::default()),
            reserved_ctrl_sends: 0,
            reserved_rtx_sends: 0,
            drr_small_priority_pops: 0,
            drr_bulk_force_pops: 0,
            shed_sojourn: 0,
            cached_rtt_ref_ms: -1.0,
            drr_rtt_scale_applied: 0,
            cc_rate_limited_events: 0,
            background_cc: BackgroundCcEngine::new(BackgroundCcConfig::default()),
        }
    }

    fn budget_cap_value(&self) -> f64 {
        match self.config.pace_rate_mode {
            PaceRateMode::Pps => self.config.budget_cap_packets,
            PaceRateMode::Bytes => self.config.budget_cap_packets * 1300.0,
        }
    }

    fn budget_has_room(&self) -> bool {
        match self.config.pace_rate_mode {
            PaceRateMode::Pps => self.budget >= 1.0,
            PaceRateMode::Bytes => self.budget >= 64.0,
        }
    }

    fn budget_consume(&mut self, pkt_len: usize) {
        let cost = match self.config.pace_rate_mode {
            PaceRateMode::Pps => 1.0,
            PaceRateMode::Bytes => pkt_len as f64,
        };
        self.budget -= cost;
    }

    pub fn set_background_cc_config(&mut self, cc: BackgroundCcConfig) {
        self.config.background_cc = cc;
        self.background_cc.set_config(cc);
    }

    pub fn on_cc_sample(&mut self, dest: SocketAddr, qd_ms: f64, loss_ewma: f64) {
        self.background_cc.on_cc_sample(dest, qd_ms, loss_ewma);
    }

    pub fn cc_metrics_snapshot(&self) -> (f64, f64, f64) {
        self.background_cc.rate_distribution()
    }

    pub fn cc_delivery_metrics_snapshot(&self) -> (f64, f64, f64) {
        self.background_cc.delivery_rate_distribution()
    }

    pub fn cc_counters(&self) -> CcUpdateCounters {
        self.background_cc.counters()
    }

    pub fn cc_take_event_counters(&mut self) -> CcUpdateCounters {
        self.background_cc.take_counters()
    }

    pub fn remove_cc_peer(&mut self, dest: SocketAddr) {
        self.background_cc.remove_peer(dest);
    }

    fn background_cc_can_send(
        &self,
        dest: SocketAddr,
        front_len: usize,
        hol_sojourn_ms: f32,
    ) -> bool {
        if front_len == 0 {
            return true;
        }
        self.background_cc
            .can_send_data(dest, front_len, hol_sojourn_ms)
    }

    fn record_background_cc_rate_limit(&mut self) {
        self.cc_rate_limited_events = self.cc_rate_limited_events.saturating_add(1);
    }

    pub fn cc_rate_limited_events(&self) -> u64 {
        self.cc_rate_limited_events
    }

    fn apply_peer_qd_hint(q: &mut PeerDataQueue, qd_ms: Option<f32>) {
        if let Some(qd) = qd_ms {
            if qd >= 0.0 {
                q.queuing_delay_ms = qd;
            }
        }
    }

    fn apply_peer_rtt_hint(q: &mut PeerDataQueue, rtt_ms: Option<f32>) {
        if let Some(r) = rtt_ms {
            if r > 0.0 {
                q.rtt_ms = r;
            }
        }
    }

    fn refresh_drr_rtt_ref(&mut self) {
        if !self.config.drr_rtt_aware || !self.config.drr_enabled {
            self.cached_rtt_ref_ms = -1.0;
            return;
        }
        let samples: Vec<f32> = self
            .peer_queues
            .values()
            .filter(|q| !q.is_empty())
            .map(|q| q.rtt_ms)
            .collect();
        self.cached_rtt_ref_ms = median_positive_rtt(samples);
    }

    fn peer_lane_config(&self) -> (bool, usize) {
        (
            self.config.drr_small_packet_priority,
            self.config.drr_small_packet_threshold_bytes,
        )
    }

    fn record_peer_pop_kind(&mut self, kind: PeerPopKind) {
        match kind {
            PeerPopKind::SmallPriority => {
                self.drr_small_priority_pops = self.drr_small_priority_pops.saturating_add(1);
            }
            PeerPopKind::BulkForced => {
                self.drr_bulk_force_pops = self.drr_bulk_force_pops.saturating_add(1);
            }
            PeerPopKind::Bulk => {}
        }
    }

    pub fn enqueue(&mut self, pkt: Bytes, dest: SocketAddr, is_control: bool) -> bool {
        if is_control {
            let _ = self.enqueue_control(pkt, dest);
            true
        } else {
            self.enqueue_peer(pkt, dest)
        }
    }

    pub fn enqueue_data(&mut self, pkt: Bytes, dest: SocketAddr) -> bool {
        self.enqueue_peer(pkt, dest)
    }

    pub fn enqueue_peer(&mut self, pkt: Bytes, dest: SocketAddr) -> bool {
        self.enqueue_peer_with_rtt(pkt, dest, None)
    }

    pub fn enqueue_peer_with_rtt(
        &mut self,
        pkt: Bytes,
        dest: SocketAddr,
        rtt_ms: Option<f32>,
    ) -> bool {
        self.enqueue_peer_with_hints(pkt, dest, rtt_ms, None)
    }

    pub fn enqueue_peer_with_hints(
        &mut self,
        pkt: Bytes,
        dest: SocketAddr,
        rtt_ms: Option<f32>,
        queuing_delay_ms: Option<f32>,
    ) -> bool {
        let cap = self.config.max_data_queue_packets.max(1);
        let (priority_on, threshold) = self.peer_lane_config();
        let q = self
            .peer_queues
            .entry(dest)
            .or_insert_with(PeerDataQueue::new);
        self.background_cc.ensure_peer(dest);
        Self::apply_peer_rtt_hint(q, rtt_ms);
        Self::apply_peer_qd_hint(q, queuing_delay_ms);
        let was_empty = q.is_empty();
        let kept = q.push(pkt, cap, priority_on, threshold);
        if was_empty && !q.is_empty() {
            self.non_empty_peers = self.non_empty_peers.saturating_add(1);
        }
        if !kept {
            self.dropped_packets = self.dropped_packets.saturating_add(1);
            self.dropped_data = self.dropped_data.saturating_add(1);
        }
        kept
    }

    pub fn try_enqueue_peer_batch(
        &mut self,
        dest: SocketAddr,
        pkts: &[Bytes],
        rtt_ms: Option<f32>,
        queuing_delay_ms: Option<f32>,
    ) -> bool {
        if pkts.is_empty() {
            return true;
        }
        let cap = self.config.max_data_queue_packets.max(1);
        let (priority_on, threshold) = self.peer_lane_config();
        let q = self
            .peer_queues
            .entry(dest)
            .or_insert_with(PeerDataQueue::new);
        self.background_cc.ensure_peer(dest);
        Self::apply_peer_rtt_hint(q, rtt_ms);
        Self::apply_peer_qd_hint(q, queuing_delay_ms);
        if q.len() + pkts.len() > cap {
            return false;
        }
        let was_empty = q.is_empty();
        for p in pkts {
            q.push_back_classified(
                QueuedData {
                    pkt: p.clone(),
                    enqueued_at: Instant::now(),
                },
                priority_on,
                threshold,
            );
        }
        if was_empty && !q.is_empty() {
            self.non_empty_peers = self.non_empty_peers.saturating_add(1);
        }
        true
    }

    pub fn peer_data_queue_len(&self, dest: SocketAddr) -> usize {
        self.peer_queues.get(&dest).map(|q| q.len()).unwrap_or(0)
    }

    /// Snapshot of per-peer data queue lengths for worker observability publish.
    pub fn peer_data_lens_snapshot(&self) -> Vec<(SocketAddr, usize)> {
        self.peer_queues
            .iter()
            .map(|(d, q)| (*d, q.len()))
            .collect()
    }

    pub fn remove_peer(&mut self, dest: SocketAddr) {
        if let Some(idx) = self.peer_queues.get_index_of(&dest) {
            if self
                .peer_queues
                .get_index(idx)
                .is_some_and(|(_, q)| !q.is_empty())
            {
                self.non_empty_peers = self.non_empty_peers.saturating_sub(1);
            }
            self.peer_queues.shift_remove_index(idx);
            if self.drr_cursor > 0 && idx < self.drr_cursor {
                self.drr_cursor -= 1;
            }
            if self.peer_queues.is_empty() {
                self.drr_cursor = 0;
            } else {
                self.drr_cursor %= self.peer_queues.len();
            }
        }
        self.background_cc.remove_peer(dest);
    }

    pub fn enqueue_control(&mut self, pkt: Bytes, dest: SocketAddr) -> bool {
        self.enqueue_control_with_source(pkt, dest, false)
    }

    pub fn enqueue_retransmit(&mut self, pkt: Bytes, dest: SocketAddr) -> bool {
        self.enqueue_control_with_source(pkt, dest, true)
    }

    fn enqueue_control_with_source(
        &mut self,
        pkt: Bytes,
        dest: SocketAddr,
        retransmit: bool,
    ) -> bool {
        let now = Instant::now();
        if retransmit {
            let cap = self.config.max_retransmit_queue_packets.max(1);
            let mut evicted = false;
            while self.retransmit_q.len() >= cap {
                if self.retransmit_q.pop_front().is_some() {
                    self.dropped_packets = self.dropped_packets.saturating_add(1);
                    self.dropped_control_retransmit =
                        self.dropped_control_retransmit.saturating_add(1);
                    evicted = true;
                } else {
                    break;
                }
            }
            self.retransmit_q.push_back(QueuedPacket {
                pkt,
                dest,
                enqueued_at: now,
            });
            return evicted;
        }
        let cap = self.config.max_control_queue_packets.max(1);
        if self.control_q.is_empty() {
            self.interleave_counter = 3;
        }
        let mut evicted = false;
        while self.control_q.len() >= cap {
            if self.control_q.pop_front().is_some() {
                self.dropped_packets = self.dropped_packets.saturating_add(1);
                self.dropped_control_normal = self.dropped_control_normal.saturating_add(1);
                evicted = true;
            } else {
                break;
            }
        }
        self.control_q.push_back(QueuedPacket {
            pkt,
            dest,
            enqueued_at: now,
        });
        evicted
    }

    pub fn reserved_ctrl_sends(&self) -> u64 {
        self.reserved_ctrl_sends
    }

    pub fn reserved_rtx_sends(&self) -> u64 {
        self.reserved_rtx_sends
    }

    pub fn drr_small_priority_pops(&self) -> u64 {
        self.drr_small_priority_pops
    }

    pub fn drr_bulk_force_pops(&self) -> u64 {
        self.drr_bulk_force_pops
    }

    pub fn drr_rtt_scale_applied(&self) -> u64 {
        self.drr_rtt_scale_applied
    }

    fn reserved_may_send(pkt_len: usize, remaining: usize, phase_initial: usize) -> bool {
        if remaining == 0 {
            return false;
        }
        if remaining == phase_initial {
            true
        } else {
            pkt_len <= remaining
        }
    }

    fn reserved_consume(remaining: usize, phase_initial: usize, pkt_len: usize) -> usize {
        if remaining == phase_initial && pkt_len > remaining {
            0
        } else {
            remaining.saturating_sub(pkt_len)
        }
    }

    /// Sends one queued control/retransmit packet; requeues on `WouldBlock`.
    fn try_send_queued_packet<F>(
        &mut self,
        try_send: &mut F,
        q: QueuedPacket,
        retransmit: bool,
        sent: &mut usize,
    ) -> Result<(), Option<TickResult>>
    where
        F: FnMut(&[u8], SocketAddr) -> Result<(), std::io::Error>,
    {
        let pkt = &q.pkt;
        let dest = q.dest;
        match try_send(pkt, dest) {
            Ok(()) => {
                self.consecutive_errors = 0;
                *sent += 1;
                self.budget_consume(pkt.len());
                Ok(())
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    if retransmit {
                        self.retransmit_q.push_front(q);
                    } else {
                        self.control_q.push_front(q);
                    }
                    Err(None)
                } else {
                    if retransmit {
                        self.retransmit_q.push_front(q);
                    } else {
                        self.control_q.push_front(q);
                    }
                    self.consecutive_errors = self.consecutive_errors.saturating_add(1);
                    if self.consecutive_errors >= 5 {
                        Err(Some(TickResult::SocketDead {
                            error: e,
                            last_failed_dest: Some(dest),
                        }))
                    } else {
                        Err(Some(TickResult::Progress(*sent)))
                    }
                }
            }
        }
    }

    fn try_send_next_packet<F>(
        &mut self,
        try_send: &mut F,
        item: NextPacket,
        sent: &mut usize,
        count_apd_drain: bool,
    ) -> Result<(), Option<TickResult>>
    where
        F: FnMut(&[u8], SocketAddr) -> Result<(), std::io::Error>,
    {
        let (pkt, dest) = match &item {
            NextPacket::Control(q) => (&q.pkt, q.dest),
            NextPacket::Data { pkt, dest, .. } => (pkt, *dest),
        };
        match try_send(pkt, dest) {
            Ok(()) => {
                self.consecutive_errors = 0;
                *sent += 1;
                self.budget_consume(pkt.len());
                if let NextPacket::Data { dest, pkt, .. } = &item {
                    self.background_cc.consume_send_bytes(*dest, pkt.len());
                }
                if count_apd_drain && self.apd.cfg.enabled && self.apd.phase == ApdPhase::Drain {
                    self.apd.packets_drained = self.apd.packets_drained.saturating_add(1);
                }
                Ok(())
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    match item {
                        NextPacket::Control(q) => self.control_q.push_front(q),
                        NextPacket::Data {
                            pkt,
                            dest,
                            enqueued_at,
                        } => self.requeue_data_at_front(dest, pkt, enqueued_at),
                    }
                    Err(None)
                } else {
                    match item {
                        NextPacket::Control(q) => self.control_q.push_front(q),
                        NextPacket::Data {
                            pkt,
                            dest,
                            enqueued_at,
                        } => self.requeue_data_at_front(dest, pkt, enqueued_at),
                    }
                    self.consecutive_errors = self.consecutive_errors.saturating_add(1);
                    if self.consecutive_errors >= 5 {
                        Err(Some(TickResult::SocketDead {
                            error: e,
                            last_failed_dest: Some(dest),
                        }))
                    } else {
                        Err(Some(TickResult::Progress(*sent)))
                    }
                }
            }
        }
    }

    fn drain_reserved_prefix<F>(
        &mut self,
        try_send: &mut F,
        deadline: Instant,
        sent: &mut usize,
    ) -> Option<TickResult>
    where
        F: FnMut(&[u8], SocketAddr) -> Result<(), std::io::Error>,
    {
        let rtx_initial = self.config.min_retransmit_reserved_bytes_per_tick;
        let ctrl_initial = self.config.min_control_reserved_bytes_per_tick;
        if rtx_initial == 0 && ctrl_initial == 0 {
            return None;
        }

        let mut rtx_remaining = rtx_initial;
        while rtx_remaining > 0 {
            if Instant::now() >= deadline || !self.budget_has_room() {
                break;
            }
            let pkt_len = self.retransmit_q.front().map(|q| q.pkt.len()).unwrap_or(0);
            if pkt_len == 0 {
                break;
            }
            if !Self::reserved_may_send(pkt_len, rtx_remaining, rtx_initial) {
                break;
            }
            let q = self.retransmit_q.pop_front().expect("front checked");
            match self.try_send_queued_packet(try_send, q, true, sent) {
                Ok(()) => {
                    self.reserved_rtx_sends = self.reserved_rtx_sends.saturating_add(1);
                    rtx_remaining = Self::reserved_consume(rtx_remaining, rtx_initial, pkt_len);
                }
                Err(Some(tr)) => return Some(tr),
                Err(None) => return Some(TickResult::Progress(*sent)),
            }
        }

        let mut ctrl_remaining = ctrl_initial;
        while ctrl_remaining > 0 {
            if Instant::now() >= deadline || !self.budget_has_room() {
                break;
            }
            let pkt_len = self.control_q.front().map(|q| q.pkt.len()).unwrap_or(0);
            if pkt_len == 0 {
                break;
            }
            if !Self::reserved_may_send(pkt_len, ctrl_remaining, ctrl_initial) {
                break;
            }
            let q = self.control_q.pop_front().expect("front checked");
            match self.try_send_queued_packet(try_send, q, false, sent) {
                Ok(()) => {
                    self.reserved_ctrl_sends = self.reserved_ctrl_sends.saturating_add(1);
                    ctrl_remaining = Self::reserved_consume(ctrl_remaining, ctrl_initial, pkt_len);
                }
                Err(Some(tr)) => return Some(tr),
                Err(None) => return Some(TickResult::Progress(*sent)),
            }
        }

        None
    }

    pub fn tick(&mut self, socket: &UdpSocket) -> TickResult {
        self.tick_with(|pkt, dest| socket.try_send_to(pkt, dest).map(|_| ()).map_err(|e| e))
    }

    fn tick_with<F>(&mut self, mut try_send: F) -> TickResult
    where
        F: FnMut(&[u8], SocketAddr) -> Result<(), std::io::Error>,
    {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_tick);
        self.last_tick = now;
        let deadline = now + Duration::from_micros(self.config.max_tick_work_us.max(100));
        match self.config.pace_rate_mode {
            PaceRateMode::Pps => {
                self.budget += elapsed.as_secs_f64() * self.config.target_pps as f64;
            }
            PaceRateMode::Bytes => {
                self.budget += elapsed.as_secs_f64() * self.config.target_bps as f64;
            }
        }
        self.budget = self.budget.min(self.budget_cap_value());
        self.background_cc.refill_all_tokens(elapsed.as_secs_f64());
        self.refresh_drr_rtt_ref();

        // APD: compute decision once per tick (gated on enabled flag — zero cost when off).
        let (effective_burst, freeze_drr) = if self.apd.cfg.enabled {
            let fill = self.queue_fill_ratio();
            let hol_sojourn_ms = self.max_hol_sojourn_ms(now);
            self.apd.last_max_sojourn_ms = hol_sojourn_ms.round() as u64;
            let decision = self.apd_step(fill, now, hol_sojourn_ms);
            (decision.effective_burst, decision.freeze_drr)
        } else {
            (self.config.base_max_burst, false)
        };

        let mut sent = 0;
        self.shed_stale_bulk_rr(now, deadline);
        if let Some(tr) = self.drain_reserved_prefix(&mut try_send, deadline, &mut sent) {
            return tr;
        }

        for _ in 0..effective_burst {
            if Instant::now() >= deadline {
                break;
            }
            if !self.budget_has_room() {
                break;
            }
            let Some(item) = self.pop_next_apd(freeze_drr) else {
                break;
            };
            match self.try_send_next_packet(&mut try_send, item, &mut sent, true) {
                Ok(()) => {}
                Err(Some(tr)) => return tr,
                Err(None) => return TickResult::Progress(sent),
            }
        }
        TickResult::Progress(sent)
    }
}

#[cfg(test)]
impl PacingEngine {
    pub(crate) fn tick_simulated_ok(&mut self) -> TickResult {
        self.tick_with(|_pkt, _dest| Ok(()))
    }
}

#[cfg(test)]
impl PacingEngine {
    pub(crate) fn refresh_drr_rtt_ref_for_test(&mut self) {
        self.refresh_drr_rtt_ref();
    }

    pub(crate) fn cached_rtt_ref_ms_for_test(&self) -> f32 {
        self.cached_rtt_ref_ms
    }
}

impl PacingEngine {
    pub fn set_config(&mut self, mut cfg: PacingConfig) {
        cfg.sanitize();
        let apd_cfg_changed = self.apd.cfg != cfg.apd;
        self.apd.cfg = cfg.apd;
        self.background_cc.set_config(cfg.background_cc);
        // Reset signal cache so engine.rs writes the correct initial values to
        // PaceClockShared on the very next tick after a reconfiguration.
        self.apd.last_pure_spin = false;
        self.apd.last_tick_us = 0;
        if apd_cfg_changed {
            self.reset_apd_runtime_state();
        }
        self.config = cfg;
        self.last_tick = Instant::now();
        self.budget = self.budget.min(cfg.budget_cap_packets);
        self.consecutive_errors = 0;
        self.non_empty_peers = self.peer_queues.values().filter(|q| !q.is_empty()).count();
    }

    /// Clear queues and per-session pacing/CC/APD runtime; keep applied config.
    pub fn reset_session_runtime(&mut self) {
        self.control_q.clear();
        self.retransmit_q.clear();
        self.peer_queues.clear();
        self.non_empty_peers = 0;
        self.budget = 0.0;
        self.dropped_packets = 0;
        self.dropped_data = 0;
        self.dropped_control_normal = 0;
        self.dropped_control_retransmit = 0;
        self.consecutive_errors = 0;
        self.interleave_counter = 0;
        self.drr_cursor = 0;
        self.reserved_ctrl_sends = 0;
        self.reserved_rtx_sends = 0;
        self.drr_small_priority_pops = 0;
        self.drr_bulk_force_pops = 0;
        self.shed_sojourn = 0;
        self.cached_rtt_ref_ms = -1.0;
        self.drr_rtt_scale_applied = 0;
        self.cc_rate_limited_events = 0;
        self.background_cc = BackgroundCcEngine::new(self.config.background_cc);
        self.reset_apd_runtime_state();
        self.apd.last_pure_spin = false;
        self.apd.last_tick_us = 0;
        self.apd.drain_episodes = 0;
        self.apd.drain_ms_total = 0;
        self.apd.packets_drained = 0;
        self.apd.drain_budget_hits = 0;
        self.apd.ramp_active_ticks = 0;
        self.apd.ramp_pinned_ticks = 0;
        self.apd.last_effective_burst = self.config.base_max_burst;
        self.apd.drain_arm_fill = 0;
        self.apd.drain_arm_sojourn = 0;
        self.apd.last_max_sojourn_ms = 0;
        self.apd.cc_headroom_suppressions = 0;
        self.last_tick = Instant::now();
    }

    fn reset_apd_runtime_state(&mut self) {
        self.apd.phase = ApdPhase::Cooldown;
        self.apd.confirm_counter = 0;
        self.apd.drain_entered_at = None;
        self.apd.cooldown_until = None;
        self.apd.ramp_burst = self.config.base_max_burst;
        self.apd.last_fill_ratio = 0.0;
    }

    /// Instant queue depths and aggregate fill for runtime dashboard / APD.
    pub fn queue_snapshot(&self) -> PacingQueueSnapshot {
        let data_queued = self.peer_queues.values().map(|q| q.len()).sum::<usize>();
        let control_queued = self.control_q.len();
        let retransmit_queued = self.retransmit_q.len();
        let total = data_queued + control_queued + retransmit_queued;
        let cap = (self.non_empty_peers.max(1) * self.config.max_data_queue_packets)
            + self.config.max_control_queue_packets
            + self.config.max_retransmit_queue_packets;
        let fill_ratio = (total as f32 / cap.max(1) as f32).clamp(0.0, 1.0);
        PacingQueueSnapshot {
            data_queued,
            control_queued,
            retransmit_queued,
            queue_capacity: cap,
            fill_ratio,
        }
    }

    /// Fraction of queue capacity currently occupied, clamped to [0, 1].
    fn queue_fill_ratio(&self) -> f32 {
        self.queue_snapshot().fill_ratio
    }

    /// Head-of-line sojourn across control, retransmit, and peer data queues (ms).
    fn max_hol_sojourn_ms(&self, now: Instant) -> f32 {
        let mut max_ms = 0.0_f32;
        if let Some(q) = self.control_q.front() {
            max_ms = max_ms.max(now.duration_since(q.enqueued_at).as_secs_f32() * 1000.0);
        }
        if let Some(q) = self.retransmit_q.front() {
            max_ms = max_ms.max(now.duration_since(q.enqueued_at).as_secs_f32() * 1000.0);
        }
        for q in self.peer_queues.values() {
            max_ms = max_ms.max(q.hol_sojourn_ms(now));
        }
        max_ms
    }

    fn shed_stale_bulk_rr(&mut self, now: Instant, deadline: Instant) {
        let cfg = self.config.shed;
        if !cfg.enabled || self.non_empty_peers == 0 || self.queue_fill_ratio() < cfg.min_fill {
            return;
        }
        let n = self.peer_queues.len();
        if n == 0 {
            return;
        }
        let mut dropped = 0_u32;
        for _ in 0..n {
            if dropped >= cfg.max_per_tick || Instant::now() >= deadline {
                break;
            }
            let idx = self.drr_cursor % n;
            self.drr_cursor = self.drr_cursor.wrapping_add(1);
            let should_drop = self
                .peer_queues
                .get_index(idx)
                .and_then(|(_, q)| q.bulk_front_sojourn_ms(now))
                .is_some_and(|soj| soj > cfg.max_sojourn_ms);
            if !should_drop {
                continue;
            }
            let now_empty = if let Some((_, q)) = self.peer_queues.get_index_mut(idx) {
                let _ = q.pop_bulk_front();
                q.is_empty()
            } else {
                false
            };
            if now_empty {
                self.non_empty_peers = self.non_empty_peers.saturating_sub(1);
            }
            self.shed_sojourn = self.shed_sojourn.saturating_add(1);
            self.dropped_packets = self.dropped_packets.saturating_add(1);
            dropped = dropped.saturating_add(1);
        }
    }

    pub fn dropped_packets(&self) -> u64 {
        self.dropped_packets
    }

    pub fn dropped_data(&self) -> u64 {
        self.dropped_data
    }

    pub fn dropped_control_normal(&self) -> u64 {
        self.dropped_control_normal
    }

    pub fn dropped_control_retransmit(&self) -> u64 {
        self.dropped_control_retransmit
    }

    pub fn shed_sojourn(&self) -> u64 {
        self.shed_sojourn
    }

    /// Returns the current APD signal: `(pure_spin, drain_tick_us)`.
    /// Called by engine.rs to relay values to `PaceClockShared` after each tick.
    pub fn apd_signal(&self) -> (bool, u64) {
        (self.apd.last_pure_spin, self.apd.last_tick_us)
    }

    /// Returns cumulative APD metrics: `(episodes, ms_total, pkts_drained, budget_hits, phase)`.
    pub fn apd_metrics(&self) -> (u64, u64, u64, u64, ApdPhase) {
        (
            self.apd.drain_episodes,
            self.apd.drain_ms_total,
            self.apd.packets_drained,
            self.apd.drain_budget_hits,
            self.apd.phase,
        )
    }

    /// Ramp observability: `(ramp_active_ticks, ramp_pinned_ticks, last_effective_burst)`.
    pub fn apd_ramp_observability(&self) -> (u64, u64, u64) {
        (
            self.apd.ramp_active_ticks,
            self.apd.ramp_pinned_ticks,
            self.apd.last_effective_burst,
        )
    }

    /// Sojourn observability: `(drain_arm_fill, drain_arm_sojourn, last_max_sojourn_ms)`.
    pub fn apd_sojourn_observability(&self) -> (u64, u64, u64) {
        (
            self.apd.drain_arm_fill,
            self.apd.drain_arm_sojourn,
            self.apd.last_max_sojourn_ms,
        )
    }

    /// Ticks where CC headroom gate suppressed APD ramp-up, Drain arm, or mid-Drain spin.
    pub fn apd_cc_headroom_suppressions(&self) -> u64 {
        self.apd.cc_headroom_suppressions
    }

    /// True when background CC is off, no non-empty data peers exist (vacuous), or at least
    /// one non-empty peer HOL passes `can_send_data` (including `hol_escape`).
    fn any_peer_data_cc_sendable(&self, now: Instant) -> bool {
        if !self.config.background_cc.enabled {
            return true;
        }
        let (priority_on, threshold) = self.peer_lane_config();
        let mut scanned = 0usize;
        for (dest, q) in self.peer_queues.iter() {
            if q.is_empty() {
                continue;
            }
            scanned = scanned.saturating_add(1);
            let front_len = q.front_len(priority_on, threshold, now);
            let hol = q.hol_sojourn_ms(now);
            if self.background_cc_can_send(*dest, front_len, hol) {
                return true;
            }
        }
        scanned == 0
    }

    /// Decay ramp toward base without allowing pin/increase (CC headroom suppress path).
    fn apd_decay_ramp_burst_only(&mut self, fill_ratio: f32, base_burst: u64) {
        if self.apd.ramp_burst == 0 {
            self.apd.ramp_burst = base_burst;
        }
        self.apd.ramp_burst = self.apd.ramp_burst.saturating_sub(1).max(base_burst);
        self.apd.last_fill_ratio = fill_ratio;
    }

    fn apd_update_ramp_burst(
        &mut self,
        fill_ratio: f32,
        base_burst: u64,
        cfg: ApdConfig,
        ramp_ceiling: u64,
    ) {
        let max_burst = ramp_ceiling.max(base_burst);
        let target = apd_ramp_target_burst(fill_ratio, base_burst, max_burst, cfg);
        if self.apd.ramp_burst == 0 {
            self.apd.ramp_burst = base_burst;
        }
        if fill_ratio > self.apd.last_fill_ratio + f32::EPSILON {
            self.apd.ramp_burst = target;
        } else {
            self.apd.ramp_burst = self.apd.ramp_burst.saturating_sub(1).max(target);
        }
        self.apd.last_fill_ratio = fill_ratio;
        if self.apd.ramp_burst > base_burst {
            self.apd.ramp_active_ticks = self.apd.ramp_active_ticks.saturating_add(1);
        }
        if self.apd.ramp_burst >= max_burst {
            self.apd.ramp_pinned_ticks = self.apd.ramp_pinned_ticks.saturating_add(1);
        }
    }

    fn apd_ramp_pinned(&self, base_burst: u64, _cfg: ApdConfig, ramp_ceiling: u64) -> bool {
        self.apd.ramp_burst >= ramp_ceiling.max(base_burst)
    }

    fn apd_exit_drain_to_cooldown(&mut self, now: Instant, budget_hit: bool) -> ApdDecision {
        let cfg = self.apd.cfg;
        let base_burst = self.config.base_max_burst;
        if budget_hit {
            self.apd.drain_budget_hits = self.apd.drain_budget_hits.saturating_add(1);
        }
        if let Some(entered) = self.apd.drain_entered_at {
            let ms = entered.elapsed().as_millis() as u64;
            self.apd.drain_ms_total = self.apd.drain_ms_total.saturating_add(ms);
        }
        self.apd.phase = ApdPhase::Cooldown;
        self.apd.cooldown_until = Some(now + Duration::from_millis(cfg.cooldown_ms as u64));
        self.apd.drain_entered_at = None;
        self.apd.confirm_counter = 0;
        self.apd.last_pure_spin = false;
        self.apd.last_tick_us = 0;
        let burst = self.apd.ramp_burst.max(base_burst);
        self.apd.last_effective_burst = burst;
        ApdDecision {
            effective_burst: burst,
            freeze_drr: false,
        }
    }

    /// Runs one step of the APD state machine given the current queue fill ratio and
    /// wall-clock instant. Returns the send budget and clock mode for this tick.
    fn apd_step(&mut self, fill_ratio: f32, now: Instant, hol_sojourn_ms: f32) -> ApdDecision {
        let cfg = self.apd.cfg;
        let base_burst = self.config.base_max_burst;
        let ramp_ceiling = cfg.ramp_max_burst.max(base_burst);
        let drain_burst = cfg.drain_max_burst.clamp(1, ramp_ceiling);
        let suppress_cc = cfg.require_cc_headroom && !self.any_peer_data_cc_sendable(now);

        match self.apd.phase {
            ApdPhase::Cooldown => {
                let cooldown_done = self.apd.cooldown_until.map(|t| now >= t).unwrap_or(true);
                if cooldown_done {
                    self.apd.phase = ApdPhase::Alert;
                    self.apd.confirm_counter = 0;
                    self.apd.cooldown_until = None;
                }
                if suppress_cc {
                    self.apd_decay_ramp_burst_only(fill_ratio, base_burst);
                    self.apd.cc_headroom_suppressions =
                        self.apd.cc_headroom_suppressions.saturating_add(1);
                } else {
                    self.apd_update_ramp_burst(fill_ratio, base_burst, cfg, ramp_ceiling);
                }
                self.apd.last_pure_spin = false;
                self.apd.last_tick_us = 0;
                let burst = self.apd.ramp_burst.max(base_burst);
                self.apd.last_effective_burst = burst;
                ApdDecision {
                    effective_burst: burst,
                    freeze_drr: false,
                }
            }

            ApdPhase::Alert => {
                if suppress_cc {
                    self.apd_decay_ramp_burst_only(fill_ratio, base_burst);
                    self.apd.cc_headroom_suppressions =
                        self.apd.cc_headroom_suppressions.saturating_add(1);
                } else {
                    self.apd_update_ramp_burst(fill_ratio, base_burst, cfg, ramp_ceiling);
                }
                let pinned = self.apd_ramp_pinned(base_burst, cfg, ramp_ceiling);
                let fill_arm = pinned && fill_ratio > cfg.high_watermark;
                let sojourn_arm = cfg.sojourn_enabled && hol_sojourn_ms > cfg.max_sojourn_ms;
                if (fill_arm || sojourn_arm) && !suppress_cc {
                    let enter = if cfg.confirm_ticks == 0 {
                        true
                    } else {
                        self.apd.confirm_counter = self.apd.confirm_counter.saturating_add(1);
                        self.apd.confirm_counter >= cfg.confirm_ticks
                    };
                    if enter {
                        if sojourn_arm {
                            self.apd.drain_arm_sojourn =
                                self.apd.drain_arm_sojourn.saturating_add(1);
                        } else if fill_arm {
                            self.apd.drain_arm_fill = self.apd.drain_arm_fill.saturating_add(1);
                        }
                        self.apd.phase = ApdPhase::Drain;
                        self.apd.drain_entered_at = Some(now);
                        self.apd.drain_episodes = self.apd.drain_episodes.saturating_add(1);
                        self.apd.last_pure_spin = true;
                        self.apd.last_tick_us = cfg.drain_tick_us;
                        self.apd.last_effective_burst = drain_burst;
                        return ApdDecision {
                            effective_burst: drain_burst,
                            freeze_drr: cfg.drain_freeze_drr,
                        };
                    }
                } else if cfg.confirm_ticks > 0 {
                    self.apd.confirm_counter = self.apd.confirm_counter.saturating_sub(1);
                }
                self.apd.last_pure_spin = false;
                self.apd.last_tick_us = 0;
                let burst = self.apd.ramp_burst.max(base_burst);
                self.apd.last_effective_burst = burst;
                ApdDecision {
                    effective_burst: burst,
                    freeze_drr: false,
                }
            }

            ApdPhase::Drain => {
                if suppress_cc {
                    self.apd.cc_headroom_suppressions =
                        self.apd.cc_headroom_suppressions.saturating_add(1);
                    return self.apd_exit_drain_to_cooldown(now, false);
                }

                let budget_exhausted = cfg.spinloop_budget_ms > 0
                    && self
                        .apd
                        .drain_entered_at
                        .map(|t| {
                            t.elapsed() >= Duration::from_millis(cfg.spinloop_budget_ms as u64)
                        })
                        .unwrap_or(false);

                let fill_exit = fill_ratio < cfg.low_watermark;
                let sojourn_exit = !cfg.sojourn_enabled || hol_sojourn_ms < cfg.target_sojourn_ms;
                if budget_exhausted || (fill_exit && sojourn_exit) {
                    return self.apd_exit_drain_to_cooldown(now, budget_exhausted);
                }

                self.apd.last_pure_spin = true;
                self.apd.last_tick_us = cfg.drain_tick_us;
                self.apd.last_effective_burst = drain_burst;
                ApdDecision {
                    effective_burst: drain_burst,
                    freeze_drr: cfg.drain_freeze_drr,
                }
            }
        }
    }

    fn requeue_data_at_front(&mut self, dest: SocketAddr, pkt: Bytes, enqueued_at: Instant) {
        let (priority_on, threshold) = self.peer_lane_config();
        let q = self
            .peer_queues
            .entry(dest)
            .or_insert_with(PeerDataQueue::new);
        let was_empty = q.is_empty();
        q.push_front_requeue(QueuedData { pkt, enqueued_at }, priority_on, threshold);
        if was_empty {
            self.non_empty_peers = self.non_empty_peers.saturating_add(1);
        }
    }

    fn try_pop_control_interleaved(&mut self) -> Option<NextPacket> {
        let ctrl_pressure =
            self.control_q.len().saturating_mul(2) >= self.config.max_control_queue_packets.max(1);
        let ctrl_aging = self
            .control_q
            .front()
            .map(|q| q.enqueued_at.elapsed() >= Duration::from_millis(8))
            .unwrap_or(false);
        let ctrl_divisor = if ctrl_pressure || ctrl_aging { 2 } else { 4 };
        self.interleave_counter = self.interleave_counter.wrapping_add(1);
        if self.interleave_counter % ctrl_divisor == 0 {
            return self.control_q.pop_front().map(NextPacket::Control);
        }
        None
    }

    /// Pop the next packet to send, using pure round-robin when `freeze_drr` is
    /// true (APD drain mode — fairness over deficit accuracy).
    fn pop_next_apd(&mut self, freeze_drr: bool) -> Option<NextPacket> {
        if !freeze_drr {
            return self.pop_next();
        }
        // Retransmit priority is always preserved.
        if let Some(pkt) = self.retransmit_q.pop_front() {
            return Some(NextPacket::Control(pkt));
        }
        if let Some(pkt) = self.try_pop_control_interleaved() {
            return Some(pkt);
        }
        // Round-robin over peer queues, ignoring deficit counters.
        let (priority_on, threshold) = self.peer_lane_config();
        let now = Instant::now();
        let n = self.peer_queues.len();
        for _ in 0..n {
            let idx = self.drr_cursor % n;
            self.drr_cursor = self.drr_cursor.wrapping_add(1);
            let popped = {
                let gate = self.peer_queues.get_index(idx).map(|(dest, q)| {
                    (
                        *dest,
                        q.front_len(priority_on, threshold, now),
                        q.hol_sojourn_ms(now),
                    )
                });
                if let Some((dest, front_len, hol)) = gate {
                    if front_len > 0 && !self.background_cc_can_send(dest, front_len, hol) {
                        self.record_background_cc_rate_limit();
                        None
                    } else if let Some((dest, q)) = self.peer_queues.get_index_mut(idx) {
                        q.pop_data(priority_on, threshold, now)
                            .map(|(entry, kind)| (*dest, entry, kind, q.is_empty()))
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            if let Some((dest, entry, kind, now_empty)) = popped {
                self.record_peer_pop_kind(kind);
                if now_empty {
                    self.non_empty_peers = self.non_empty_peers.saturating_sub(1);
                }
                return Some(NextPacket::Data {
                    pkt: entry.pkt,
                    dest,
                    enqueued_at: entry.enqueued_at,
                });
            }
        }
        self.control_q.pop_front().map(NextPacket::Control)
    }

    fn pop_next(&mut self) -> Option<NextPacket> {
        if let Some(pkt) = self.retransmit_q.pop_front() {
            return Some(NextPacket::Control(pkt));
        }
        if let Some(pkt) = self.try_pop_control_interleaved() {
            return Some(pkt);
        }
        if !self.config.drr_enabled {
            let (priority_on, threshold) = self.peer_lane_config();
            let now = Instant::now();
            for idx in 0..self.peer_queues.len() {
                let gate = self.peer_queues.get_index(idx).map(|(dest, q)| {
                    (
                        *dest,
                        q.front_len(priority_on, threshold, now),
                        q.hol_sojourn_ms(now),
                    )
                });
                if let Some((dest, front_len, hol)) = gate {
                    if front_len > 0 && !self.background_cc_can_send(dest, front_len, hol) {
                        self.record_background_cc_rate_limit();
                        continue;
                    }
                    let popped = if let Some((dest, q)) = self.peer_queues.get_index_mut(idx) {
                        q.pop_data(priority_on, threshold, now)
                            .map(|(entry, kind)| (*dest, entry, kind, q.is_empty()))
                    } else {
                        None
                    };
                    if let Some((dest, entry, kind, now_empty)) = popped {
                        self.record_peer_pop_kind(kind);
                        if now_empty {
                            self.non_empty_peers = self.non_empty_peers.saturating_sub(1);
                        }
                        return Some(NextPacket::Data {
                            pkt: entry.pkt,
                            dest,
                            enqueued_at: entry.enqueued_at,
                        });
                    }
                }
            }
            return self.control_q.pop_front().map(NextPacket::Control);
        }

        let n = self.peer_queues.len();
        if n == 0 {
            return self.control_q.pop_front().map(NextPacket::Control);
        }

        if self.non_empty_peers == 0 {
            return self.control_q.pop_front().map(NextPacket::Control);
        }

        let (priority_on, threshold) = self.peer_lane_config();
        let now = Instant::now();
        let drr_rtt_aware = self.config.drr_rtt_aware;
        let drr_scale_min = self.config.drr_rtt_scale_min;
        let drr_scale_max = self.config.drr_rtt_scale_max;
        let rtt_ref_ms = self.cached_rtt_ref_ms;
        let base_quantum = self.config.drr_quantum.max(1);
        let mut rtt_scale_hits = 0u64;
        for _ in 0..(n * 2) {
            let idx = self.drr_cursor % n;
            self.drr_cursor = self.drr_cursor.wrapping_add(1);
            let send = {
                enum DrrSendPlan {
                    Skip,
                    RateCheck {
                        dest: SocketAddr,
                        front_len: usize,
                        hol_ms: f32,
                    },
                }
                let plan = if let Some((dest, q)) = self.peer_queues.get_index_mut(idx) {
                    if q.is_empty() {
                        q.deficit = 0;
                        DrrSendPlan::Skip
                    } else {
                        let peer_rtt = q.rtt_ms;
                        let quantum = scaled_drr_quantum(
                            base_quantum,
                            peer_rtt,
                            rtt_ref_ms,
                            drr_rtt_aware,
                            drr_scale_min,
                            drr_scale_max,
                        );
                        if drr_rtt_aware
                            && rtt_ref_ms > 0.0
                            && peer_rtt > 0.0
                            && quantum != base_quantum.max(MIN_DRR_QUANTUM)
                        {
                            rtt_scale_hits = rtt_scale_hits.saturating_add(1);
                        }
                        q.deficit = q.deficit.saturating_add(quantum);
                        let front_len = q.front_len(priority_on, threshold, now);
                        let deficit_cap = quantum.saturating_mul(4).max(front_len);
                        if q.deficit > deficit_cap {
                            q.deficit = deficit_cap;
                        }
                        if front_len == 0 || front_len > q.deficit {
                            DrrSendPlan::Skip
                        } else {
                            DrrSendPlan::RateCheck {
                                dest: *dest,
                                front_len,
                                hol_ms: q.hol_sojourn_ms(now),
                            }
                        }
                    }
                } else {
                    DrrSendPlan::Skip
                };
                match plan {
                    DrrSendPlan::Skip => None,
                    DrrSendPlan::RateCheck {
                        dest,
                        front_len,
                        hol_ms,
                    } => {
                        if !self.background_cc_can_send(dest, front_len, hol_ms) {
                            self.record_background_cc_rate_limit();
                            None
                        } else if let Some((dest, q)) = self.peer_queues.get_index_mut(idx) {
                            q.deficit -= front_len;
                            let popped = q.pop_data(priority_on, threshold, now);
                            let now_empty = q.is_empty();
                            popped.map(|(entry, kind)| (*dest, entry, kind, now_empty))
                        } else {
                            None
                        }
                    }
                }
            };
            if let Some((dest, entry, kind, now_empty)) = send {
                self.record_peer_pop_kind(kind);
                if now_empty {
                    self.non_empty_peers = self.non_empty_peers.saturating_sub(1);
                }
                return Some(NextPacket::Data {
                    pkt: entry.pkt,
                    dest,
                    enqueued_at: entry.enqueued_at,
                });
            }
        }
        self.drr_rtt_scale_applied = self.drr_rtt_scale_applied.saturating_add(rtt_scale_hits);

        self.control_q.pop_front().map(NextPacket::Control)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    #[test]
    fn remove_peer_adjusts_cursor_safely() {
        let mut p = PacingEngine::new();
        p.enqueue_peer(Bytes::from_static(b"A"), addr(1));
        p.enqueue_peer(Bytes::from_static(b"B"), addr(2));
        p.enqueue_peer(Bytes::from_static(b"C"), addr(3));
        p.drr_cursor = 2;
        p.remove_peer(addr(1));
        assert!(p.drr_cursor <= p.peer_queues.len().max(1));
    }

    #[test]
    fn drr_no_starvation_for_small_peers() {
        let mut p = PacingEngine::new();
        p.config.drr_quantum = 1500;
        for _ in 0..20 {
            p.enqueue_peer(Bytes::from(vec![0u8; 200]), addr(10));
        }
        p.enqueue_peer(Bytes::from(vec![1u8; 200]), addr(11));
        p.enqueue_peer(Bytes::from(vec![2u8; 200]), addr(12));

        let mut saw_11 = false;
        let mut saw_12 = false;
        for _ in 0..10 {
            if let Some(NextPacket::Data { dest, .. }) = p.pop_next() {
                if dest == addr(11) {
                    saw_11 = true;
                } else if dest == addr(12) {
                    saw_12 = true;
                }
            }
        }
        assert!(saw_11);
        assert!(saw_12);
    }

    #[test]
    fn drr_single_peer_throughput_sanity() {
        let mut p = PacingEngine::new();
        p.config.drr_quantum = 1500;
        p.config.max_data_queue_packets = 1000;
        for _ in 0..1000 {
            p.enqueue_peer(Bytes::from(vec![9u8; 200]), addr(20));
        }
        let mut popped = 0usize;
        for _ in 0..1000 {
            if let Some(NextPacket::Data { .. }) = p.pop_next() {
                popped += 1;
            }
        }
        assert_eq!(popped, 1000);
    }

    #[test]
    fn try_enqueue_peer_batch_all_or_nothing() {
        let mut p = PacingEngine::new();
        p.config.max_data_queue_packets = 4;
        let d = addr(7);
        assert!(p.enqueue_peer(Bytes::from_static(b"a"), d));
        assert!(p.enqueue_peer(Bytes::from_static(b"b"), d));
        let pkts = vec![
            Bytes::from_static(b"c"),
            Bytes::from_static(b"d"),
            Bytes::from_static(b"e"),
        ];
        assert!(!p.try_enqueue_peer_batch(d, &pkts, None, None));
        assert_eq!(p.peer_data_queue_len(d), 2);
        let pkts2 = vec![Bytes::from_static(b"c")];
        assert!(p.try_enqueue_peer_batch(d, &pkts2, None, None));
        assert_eq!(p.peer_data_queue_len(d), 3);
    }

    #[test]
    fn first_control_packet_after_idle_is_not_interleave_delayed() {
        let mut p = PacingEngine::new();
        p.enqueue_control(Bytes::from_static(b"C"), addr(1));
        assert!(matches!(p.pop_next(), Some(NextPacket::Control(_))));
    }

    #[test]
    fn apd_freeze_drr_interleaves_control_with_data() {
        let mut p = PacingEngine::new();
        p.config.max_control_queue_packets = 4;
        p.enqueue_peer(Bytes::from_static(b"d1"), addr(1));
        p.enqueue_peer(Bytes::from_static(b"d2"), addr(2));
        p.enqueue_control(Bytes::from_static(b"c1"), addr(3));
        p.enqueue_control(Bytes::from_static(b"c2"), addr(4));

        let mut saw_control_while_data_queued = false;
        let mut data_remaining = 2usize;
        for _ in 0..8 {
            match p.pop_next_apd(true) {
                Some(NextPacket::Control(_)) => {
                    if data_remaining > 0 {
                        saw_control_while_data_queued = true;
                    }
                }
                Some(NextPacket::Data { .. }) => {
                    data_remaining = data_remaining.saturating_sub(1);
                }
                None => break,
            }
        }
        assert!(saw_control_while_data_queued);
    }

    // ── APD unit tests ───────────────────────────────────────────────────────

    fn apd_engine() -> PacingEngine {
        let mut p = PacingEngine::new();
        let mut cfg = p.config;
        cfg.apd = ApdConfig {
            enabled: true,
            high_watermark: 0.75,
            low_watermark: 0.30,
            ramp_max_burst: 24,
            drain_max_burst: 6,
            spinloop_budget_ms: 6,
            drain_tick_us: 0,
            confirm_ticks: 3,
            cooldown_ms: 80,
            drain_freeze_drr: true,
            sojourn_enabled: true,
            max_sojourn_ms: 20.0,
            target_sojourn_ms: 8.0,
            require_cc_headroom: true,
        };
        p.set_config(cfg);
        p
    }

    #[test]
    fn apd_disabled_uses_base_burst() {
        let mut p = PacingEngine::new();
        let mut cfg = p.config;
        cfg.apd.enabled = false;
        p.set_config(cfg);
        assert!(!p.config.apd.enabled);
        // When disabled the APD state machine is never reached.
        let fill = p.queue_fill_ratio();
        assert_eq!(fill, 0.0);
        // apd_signal must stay at (false, 0) indefinitely.
        assert_eq!(p.apd_signal(), (false, 0));
    }

    #[test]
    fn apd_fill_ratio_zero_denominator_safe() {
        let p = PacingEngine::new();
        // Empty engine — denominator guarded by .max(1), must not panic.
        assert_eq!(p.queue_fill_ratio(), 0.0);
    }

    #[test]
    fn apd_fill_ratio_clamped_to_one() {
        let mut p = apd_engine();
        // Fill peer queue well beyond capacity.
        p.config.max_data_queue_packets = 2;
        for _ in 0..100 {
            p.enqueue_peer(Bytes::from_static(b"x"), addr(1));
        }
        let r = p.queue_fill_ratio();
        assert!(r <= 1.0, "fill_ratio must be ≤ 1.0, got {r}");
    }

    #[test]
    fn apd_cooldown_to_alert_transition() {
        let mut p = apd_engine();
        let now = Instant::now();
        // Fresh engine starts in Cooldown; cooldown_until is None, so it moves to Alert.
        p.apd_step(0.0, now, 0.0);
        assert_eq!(p.apd.phase, ApdPhase::Alert);
        assert!(!p.apd.last_pure_spin);
    }

    #[test]
    fn apd_alert_confirm_ticks_required_before_drain() {
        let mut p = apd_engine();
        let now = Instant::now();
        // Advance to Alert phase first.
        p.apd_step(0.0, now, 0.0);
        assert_eq!(p.apd.phase, ApdPhase::Alert);

        // confirm_ticks = 3: need 3 consecutive ticks above high_wm.
        p.apd_step(0.80, now, 0.0); // counter = 1
        assert_eq!(p.apd.phase, ApdPhase::Alert);
        p.apd_step(0.80, now, 0.0); // counter = 2
        assert_eq!(p.apd.phase, ApdPhase::Alert);
        p.apd_step(0.80, now, 0.0); // counter = 3 → Drain
        assert_eq!(p.apd.phase, ApdPhase::Drain);
        assert_eq!(p.apd.drain_episodes, 1);
    }

    #[test]
    fn apd_alert_counter_decrements_on_low_fill() {
        let mut p = apd_engine();
        let now = Instant::now();
        p.apd_step(0.0, now, 0.0); // → Alert
        p.apd_step(0.80, now, 0.0); // counter = 1
        p.apd_step(0.20, now, 0.0); // counter back to 0 (saturating_sub)
        assert_eq!(p.apd.confirm_counter, 0);
        assert_eq!(p.apd.phase, ApdPhase::Alert);
    }

    #[test]
    fn apd_drain_exits_on_low_watermark() {
        let mut p = apd_engine();
        let now = Instant::now();
        p.apd_step(0.0, now, 0.0); // → Alert
        for _ in 0..3 {
            p.apd_step(0.80, now, 0.0); // → Drain after 3 ticks
        }
        assert_eq!(p.apd.phase, ApdPhase::Drain);

        // Fill drops below low_watermark.
        p.apd_step(0.10, now, 0.0);
        assert_eq!(p.apd.phase, ApdPhase::Cooldown);
        assert!(p.apd.cooldown_until.is_some());
        assert_eq!(p.apd_signal(), (false, 0));
    }

    #[test]
    fn apd_drain_uses_drain_max_burst() {
        let mut p = apd_engine();
        let now = Instant::now();
        p.apd_step(0.0, now, 0.0);
        for _ in 0..3 {
            p.apd_step(0.80, now, 0.0);
        }
        let decision = p.apd_step(0.80, now, 0.0);
        assert_eq!(decision.effective_burst, 6);
    }

    #[test]
    fn apd_no_drain_below_high_watermark() {
        let mut p = apd_engine();
        let now = Instant::now();
        p.apd_step(0.0, now, 0.0);
        for _ in 0..10 {
            p.apd_step(0.50, now, 0.0);
            assert_eq!(p.apd.phase, ApdPhase::Alert);
        }
    }

    #[test]
    fn apd_budget_exhaustion_triggers_cooldown() {
        let mut p = apd_engine();
        p.apd.cfg.spinloop_budget_ms = 1;
        let now = Instant::now();
        p.apd_step(0.0, now, 0.0); // → Alert
        for _ in 0..3 {
            p.apd_step(0.80, now, 0.0); // → Drain
        }
        assert_eq!(p.apd.phase, ApdPhase::Drain);
        std::thread::sleep(Duration::from_millis(5));
        p.apd_step(0.80, Instant::now(), 0.0);
        assert_eq!(p.apd.phase, ApdPhase::Cooldown);
        assert_eq!(p.apd.drain_budget_hits, 1);
    }

    #[test]
    fn apd_spinloop_budget_zero_no_time_exit() {
        let mut p = apd_engine();
        p.apd.cfg.spinloop_budget_ms = 0;
        let now = Instant::now();
        p.apd_step(0.0, now, 0.0);
        for _ in 0..3 {
            p.apd_step(0.80, now, 0.0);
        }
        assert_eq!(p.apd.phase, ApdPhase::Drain);
        for _ in 0..5 {
            p.apd_step(0.80, now, 0.0);
            assert_eq!(p.apd.phase, ApdPhase::Drain);
        }
        assert_eq!(p.apd.drain_budget_hits, 0);
    }

    #[test]
    fn apd_spinloop_budget_zero_exits_on_low_fill() {
        let mut p = apd_engine();
        p.apd.cfg.spinloop_budget_ms = 0;
        let now = Instant::now();
        p.apd_step(0.0, now, 0.0);
        for _ in 0..3 {
            p.apd_step(0.80, now, 0.0);
        }
        assert_eq!(p.apd.phase, ApdPhase::Drain);
        p.apd_step(0.10, now, 0.0);
        assert_eq!(p.apd.phase, ApdPhase::Cooldown);
    }

    #[test]
    fn apd_confirm_ticks_zero_enters_drain_immediately() {
        let mut p = apd_engine();
        p.apd.cfg.confirm_ticks = 0;
        let now = Instant::now();
        p.apd_step(0.0, now, 0.0);
        assert_eq!(p.apd.phase, ApdPhase::Alert);
        p.apd_step(0.80, now, 0.0);
        assert_eq!(p.apd.phase, ApdPhase::Drain);
    }

    #[test]
    fn apd_clamp_spin_and_confirm_ranges() {
        let mut apd = ApdConfig::default();
        apd.spinloop_budget_ms = 0;
        apd.confirm_ticks = 0;
        apd.clamp_to_user_ranges(500, 12);
        assert_eq!(apd.spinloop_budget_ms, 0);
        assert_eq!(apd.confirm_ticks, 0);
        apd.spinloop_budget_ms = 200;
        apd.confirm_ticks = 99;
        apd.clamp_to_user_ranges(500, 12);
        assert_eq!(apd.spinloop_budget_ms, 100);
        assert_eq!(apd.confirm_ticks, 10);
    }

    #[test]
    fn apd_set_config_resets_signal_cache() {
        let mut p = apd_engine();
        p.apd.last_pure_spin = true;
        p.apd.last_tick_us = 300;
        let cfg = p.config;
        p.set_config(cfg);
        assert_eq!(p.apd_signal(), (false, 0));
    }

    #[test]
    fn apd_config_from_network_default_round_trip() {
        use crate::config::NetworkConfig;
        let net = NetworkConfig::default();
        let apd = super::apd_config_from_network(&net);
        assert!(apd.enabled);
        assert!((apd.high_watermark - 0.6).abs() < f32::EPSILON);
        assert!((apd.low_watermark - 0.1).abs() < f32::EPSILON);
        assert_eq!(apd.ramp_max_burst, 8);
        assert_eq!(apd.drain_max_burst, 2);
        assert_eq!(apd.drain_tick_us, 50);
        assert_eq!(apd.confirm_ticks, 2);
        assert_eq!(apd.cooldown_ms, 2);
        assert_eq!(apd.spinloop_budget_ms, 4);
        assert!(apd.sojourn_enabled);
        assert!((apd.max_sojourn_ms - 6.0).abs() < f32::EPSILON);
        assert!((apd.target_sojourn_ms - 2.0).abs() < f32::EPSILON);
        assert!(apd.require_cc_headroom);
    }

    #[test]
    fn apd_clamp_to_user_ranges_caps_drain_tick() {
        let mut apd = ApdConfig::default();
        apd.drain_tick_us = 9999;
        apd.ramp_max_burst = 1;
        apd.clamp_to_user_ranges(500, 12);
        assert_eq!(apd.drain_tick_us, 500);
        assert_eq!(apd.ramp_max_burst, 12);
    }

    #[test]
    fn apd_clamp_to_user_ranges_watermark_bounds() {
        let mut apd = ApdConfig::default();
        apd.low_watermark = 0.05;
        apd.high_watermark = 0.15;
        apd.clamp_to_user_ranges(500, 12);
        assert!((apd.low_watermark - 0.10).abs() < f32::EPSILON);
        assert!((apd.high_watermark - 0.20).abs() < f32::EPSILON);
        apd.low_watermark = 0.9;
        apd.high_watermark = 0.99;
        apd.clamp_to_user_ranges(500, 12);
        assert!((apd.low_watermark - 0.80).abs() < f32::EPSILON);
        assert!((apd.high_watermark - 0.95).abs() < f32::EPSILON);
    }

    #[test]
    fn apd_enforce_watermark_pair_high_not_below_low() {
        let (l, h) = ApdConfig::enforce_watermark_pair(0.55, 0.40);
        assert!((l - 0.55).abs() < f32::EPSILON);
        assert!(h >= l + APD_WM_GAP - f32::EPSILON);
        assert!(h >= l);
        let (l2, h2) = ApdConfig::enforce_watermark_pair(0.75, 0.72);
        assert!((l2 - 0.75).abs() < f32::EPSILON);
        assert!(h2 >= 0.85 - f32::EPSILON);
    }

    #[test]
    fn apd_sanitize_allows_cap_mode() {
        let mut apd = ApdConfig::default();
        apd.low_watermark = 0.5;
        apd.high_watermark = 0.5;
        apd.sanitize();
        assert!(apd_is_cap_mode(apd));
        assert!((apd.low_watermark - 0.5).abs() < f32::EPSILON);
        assert!((apd.high_watermark - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn apd_sanitize_separates_when_below_gap() {
        let mut apd = ApdConfig::default();
        apd.low_watermark = 0.3;
        apd.high_watermark = 0.35;
        apd.sanitize();
        assert!(!apd_is_cap_mode(apd));
        assert!((apd.high_watermark - 0.4).abs() < f32::EPSILON);
    }

    #[test]
    fn apd_cap_mode_confirm_then_drain() {
        let mut p = apd_engine();
        p.apd.cfg.high_watermark = 0.5;
        p.apd.cfg.low_watermark = 0.5;
        p.apd.cfg.confirm_ticks = 1;
        let now = Instant::now();
        p.apd_step(0.0, now, 0.0);
        assert_eq!(p.apd.phase, ApdPhase::Alert);
        p.apd_step(0.51, now, 0.0);
        assert_eq!(p.apd.phase, ApdPhase::Drain);
    }

    #[test]
    fn apd_cap_mode_exits_below_cap() {
        let mut p = apd_engine();
        p.apd.cfg.high_watermark = 0.5;
        p.apd.cfg.low_watermark = 0.5;
        p.apd.cfg.confirm_ticks = 1;
        let now = Instant::now();
        p.apd_step(0.0, now, 0.0);
        p.apd_step(0.51, now, 0.0);
        assert_eq!(p.apd.phase, ApdPhase::Drain);
        p.apd_step(0.49, now, 0.0);
        assert_eq!(p.apd.phase, ApdPhase::Cooldown);
    }

    fn pin_apd_ramp(p: &mut PacingEngine, now: Instant) {
        p.apd_step(0.0, now, 0.0);
        for _ in 0..2 {
            p.apd_step(0.80, now, 0.0);
        }
        let ceiling = p.apd.cfg.ramp_max_burst.max(p.config.base_max_burst);
        p.apd.ramp_burst = ceiling;
        assert_eq!(p.apd.phase, ApdPhase::Alert);
    }

    #[test]
    fn apd_sojourn_arm_enters_drain_when_fill_low() {
        let mut p = apd_engine();
        let now = Instant::now();
        pin_apd_ramp(&mut p, now);
        for _ in 0..3 {
            p.apd_step(0.05, now, 25.0);
        }
        assert_eq!(p.apd.phase, ApdPhase::Drain);
        assert_eq!(p.apd.drain_arm_sojourn, 1);
    }

    #[test]
    fn apd_sojourn_exit_requires_young_hol() {
        let mut p = apd_engine();
        let now = Instant::now();
        pin_apd_ramp(&mut p, now);
        for _ in 0..3 {
            p.apd_step(0.05, now, 25.0);
        }
        assert_eq!(p.apd.phase, ApdPhase::Drain);
        p.apd_step(0.05, now, 15.0);
        assert_eq!(p.apd.phase, ApdPhase::Drain);
        p.apd_step(0.05, now, 5.0);
        assert_eq!(p.apd.phase, ApdPhase::Cooldown);
    }

    #[test]
    fn apd_sojourn_disabled_exit_on_fill_only() {
        let mut p = apd_engine();
        p.apd.cfg.sojourn_enabled = false;
        let now = Instant::now();
        pin_apd_ramp(&mut p, now);
        for _ in 0..3 {
            p.apd_step(0.80, now, 0.0);
        }
        assert_eq!(p.apd.phase, ApdPhase::Drain);
        p.apd_step(0.10, now, 50.0);
        assert_eq!(p.apd.phase, ApdPhase::Cooldown);
    }

    #[test]
    fn apd_sojourn_sanitize_target_below_max() {
        let mut apd = ApdConfig::default();
        apd.max_sojourn_ms = 10.0;
        apd.target_sojourn_ms = 12.0;
        apd.sanitize();
        assert!(apd.target_sojourn_ms + 2.0 <= apd.max_sojourn_ms + f32::EPSILON);
    }

    #[test]
    fn max_hol_sojourn_ms_from_aged_data_packet() {
        let mut p = PacingEngine::new();
        let dest = addr(9);
        let q = p.peer_queues.entry(dest).or_insert_with(PeerDataQueue::new);
        q.push_front_requeue(
            QueuedData {
                pkt: Bytes::from_static(b"stale"),
                enqueued_at: Instant::now() - Duration::from_millis(30),
            },
            false,
            200,
        );
        p.non_empty_peers = 1;
        let now = Instant::now();
        let ms = p.max_hol_sojourn_ms(now);
        assert!(ms >= 25.0, "expected aged HOL sojourn, got {ms}");
    }

    fn pacing_for_reserved_tick(ctrl: usize, rtx: usize) -> PacingEngine {
        let mut p = PacingEngine::new();
        let mut cfg = p.config;
        cfg.apd.enabled = false;
        cfg.pace_rate_mode = PaceRateMode::Pps;
        cfg.budget_cap_packets = 64.0;
        cfg.base_max_burst = 4;
        cfg.min_control_reserved_bytes_per_tick = ctrl;
        cfg.min_retransmit_reserved_bytes_per_tick = rtx;
        p.set_config(cfg);
        p.budget = 64.0;
        p
    }

    #[test]
    fn reserved_bytes_sanitize_clamps() {
        let mut cfg = PacingConfig::default();
        cfg.min_control_reserved_bytes_per_tick = 99_999;
        cfg.min_retransmit_reserved_bytes_per_tick = 99_999;
        cfg.sanitize();
        assert_eq!(
            cfg.min_control_reserved_bytes_per_tick,
            crate::net::pacing_defaults::PACE_RESERVED_BYTES_PER_TICK_MAX as usize
        );
        assert_eq!(
            cfg.min_retransmit_reserved_bytes_per_tick,
            crate::net::pacing_defaults::PACE_RESERVED_BYTES_PER_TICK_MAX as usize
        );
    }

    #[test]
    fn reserved_control_drains_with_data_flood() {
        let dest = addr(42);
        let mut p = pacing_for_reserved_tick(200, 0);
        for _ in 0..20 {
            p.enqueue_peer(Bytes::from_static(b"dddddddddd"), dest);
        }
        p.enqueue_control(Bytes::from_static(b"ctrl"), dest);
        let r = p.tick_simulated_ok();
        assert!(matches!(r, TickResult::Progress(n) if n >= 1));
        assert!(p.reserved_ctrl_sends() >= 1);
        assert_eq!(p.queue_snapshot().control_queued, 0);
    }

    #[test]
    fn reserved_zero_does_not_prefix_drain_control() {
        let dest = addr(43);
        let mut p = pacing_for_reserved_tick(0, 0);
        p.config.base_max_burst = 1;
        p.enqueue_peer(Bytes::from_static(b"data"), dest);
        p.enqueue_control(Bytes::from_static(b"ctrl"), dest);
        let r = p.tick_simulated_ok();
        assert!(matches!(r, TickResult::Progress(_)));
        assert_eq!(p.reserved_ctrl_sends(), 0);
        assert_eq!(p.reserved_rtx_sends(), 0);
    }

    #[test]
    fn reserved_rtx_drains_before_control() {
        let dest = addr(44);
        let mut p = pacing_for_reserved_tick(200, 200);
        p.config.target_pps = 1;
        p.enqueue_control(Bytes::from_static(b"ctrl"), dest);
        p.enqueue_retransmit(Bytes::from_static(b"rtx"), dest);
        // One token only: rtx reserved prefix wins; control stays queued.
        p.last_tick = Instant::now();
        p.budget = 1.0;
        let _ = p.tick_simulated_ok();
        assert_eq!(p.reserved_rtx_sends(), 1);
        assert_eq!(p.reserved_ctrl_sends(), 0);
        assert_eq!(p.queue_snapshot().control_queued, 1);
    }

    #[test]
    fn reserved_control_drains_under_apd_drain_freeze_drr() {
        let dest = addr(45);
        let mut p = apd_engine();
        p.config.min_control_reserved_bytes_per_tick = 200;
        p.config.min_retransmit_reserved_bytes_per_tick = 0;
        p.budget = 64.0;
        let now = Instant::now();
        pin_apd_ramp(&mut p, now);
        for _ in 0..3 {
            p.apd_step(0.05, now, 25.0);
        }
        assert_eq!(p.apd.phase, ApdPhase::Drain);
        for _ in 0..20 {
            p.enqueue_peer(Bytes::from_static(b"dddddddddd"), dest);
        }
        p.enqueue_control(Bytes::from_static(b"ctrl"), dest);
        let _ = p.tick_simulated_ok();
        assert!(p.reserved_ctrl_sends() >= 1);
        assert_eq!(p.queue_snapshot().control_queued, 0);
    }

    fn pop_next_data(p: &mut PacingEngine) -> Option<Bytes> {
        match p.pop_next() {
            Some(NextPacket::Data { pkt, .. }) => Some(pkt),
            _ => None,
        }
    }

    fn shed_engine() -> PacingEngine {
        let mut p = PacingEngine::new();
        p.config.shed.enabled = true;
        p.config.shed.max_sojourn_ms = 10.0;
        p.config.shed.min_fill = 0.0;
        p.config.shed.max_per_tick = 8;
        p
    }

    fn push_aged_bulk(p: &mut PacingEngine, dest: SocketAddr, age_ms: u64) {
        let q = p.peer_queues.entry(dest).or_insert_with(PeerDataQueue::new);
        q.push_front_requeue(
            QueuedData {
                pkt: Bytes::from(vec![0u8; 300]),
                enqueued_at: Instant::now() - Duration::from_millis(age_ms),
            },
            true,
            200,
        );
        p.non_empty_peers = p.non_empty_peers.max(1);
    }

    #[test]
    fn shed_off_no_drop_on_aged_bulk() {
        let mut p = shed_engine();
        p.config.shed.enabled = false;
        let dest = addr(90);
        push_aged_bulk(&mut p, dest, 30);
        let before = p.peer_data_queue_len(dest);
        p.shed_stale_bulk_rr(Instant::now(), Instant::now() + Duration::from_millis(5));
        assert_eq!(p.peer_data_queue_len(dest), before);
        assert_eq!(p.shed_sojourn(), 0);
    }

    #[test]
    fn shed_on_fill_below_threshold_no_drop() {
        let mut p = shed_engine();
        p.config.shed.min_fill = 1.0;
        let dest = addr(91);
        push_aged_bulk(&mut p, dest, 30);
        p.shed_stale_bulk_rr(Instant::now(), Instant::now() + Duration::from_millis(5));
        assert_eq!(p.peer_data_queue_len(dest), 1);
        assert_eq!(p.shed_sojourn(), 0);
    }

    #[test]
    fn shed_on_aged_bulk_drops_only_bulk_preserves_small() {
        let mut p = shed_engine();
        let dest = addr(92);
        push_aged_bulk(&mut p, dest, 30);
        p.enqueue_peer(Bytes::from(vec![0u8; 50]), dest);
        p.shed_stale_bulk_rr(Instant::now(), Instant::now() + Duration::from_millis(5));
        let q = p.peer_queues.get(&dest).expect("queue");
        assert_eq!(q.bulk.len(), 0);
        assert_eq!(q.small.len(), 1);
        assert_eq!(p.shed_sojourn(), 1);
    }

    #[test]
    fn shed_respects_max_per_tick_cap() {
        let mut p = shed_engine();
        p.config.shed.max_per_tick = 1;
        let d1 = addr(93);
        let d2 = addr(94);
        push_aged_bulk(&mut p, d1, 30);
        push_aged_bulk(&mut p, d2, 30);
        p.non_empty_peers = 2;
        p.shed_stale_bulk_rr(Instant::now(), Instant::now() + Duration::from_millis(5));
        let rem = p.peer_data_queue_len(d1) + p.peer_data_queue_len(d2);
        assert_eq!(rem, 1);
        assert_eq!(p.shed_sojourn(), 1);
    }

    #[test]
    fn shed_boundary_fill_equal_min_fill() {
        let mut p = shed_engine();
        let dest = addr(95);
        push_aged_bulk(&mut p, dest, 30);
        let fill = p.queue_fill_ratio();
        p.config.shed.min_fill = fill;
        p.shed_stale_bulk_rr(Instant::now(), Instant::now() + Duration::from_millis(5));
        assert_eq!(p.peer_data_queue_len(dest), 0);
        assert_eq!(p.shed_sojourn(), 1);
    }

    #[test]
    fn shed_counter_separate_from_dropped_data() {
        let mut p = shed_engine();
        let dest = addr(96);
        push_aged_bulk(&mut p, dest, 30);
        p.shed_stale_bulk_rr(Instant::now(), Instant::now() + Duration::from_millis(5));
        assert_eq!(p.shed_sojourn(), 1);
        assert_eq!(p.dropped_data(), 0);
    }

    #[test]
    fn shed_reset_session_runtime_resets_counter() {
        let mut p = shed_engine();
        let dest = addr(97);
        push_aged_bulk(&mut p, dest, 30);
        p.shed_stale_bulk_rr(Instant::now(), Instant::now() + Duration::from_millis(5));
        assert_eq!(p.shed_sojourn(), 1);
        p.reset_session_runtime();
        assert_eq!(p.shed_sojourn(), 0);
    }

    #[test]
    fn drr_small_packet_priority_serves_small_first() {
        let mut p = PacingEngine::new();
        p.config.drr_small_packet_priority = true;
        p.config.drr_small_packet_threshold_bytes = 200;
        let d = addr(70);
        p.enqueue_peer(Bytes::from(vec![0u8; 300]), d);
        p.enqueue_peer(Bytes::from(vec![0u8; 50]), d);
        let pkt = pop_next_data(&mut p).expect("data");
        assert_eq!(pkt.len(), 50);
        assert!(p.drr_small_priority_pops() >= 1);
    }

    #[test]
    fn drr_small_packet_priority_off_preserves_fifo() {
        let mut p = PacingEngine::new();
        p.config.drr_small_packet_priority = false;
        p.config.drr_small_packet_threshold_bytes = 200;
        let d = addr(71);
        p.enqueue_peer(Bytes::from(vec![0u8; 300]), d);
        p.enqueue_peer(Bytes::from(vec![0u8; 50]), d);
        let pkt = pop_next_data(&mut p).expect("data");
        assert_eq!(pkt.len(), 300);
        assert_eq!(p.drr_small_priority_pops(), 0);
    }

    #[test]
    fn drr_bulk_force_after_consecutive_small_pops() {
        let mut p = PacingEngine::new();
        p.config.drr_small_packet_priority = true;
        p.config.drr_small_packet_threshold_bytes = 200;
        let d = addr(72);
        p.enqueue_peer(Bytes::from(vec![0u8; 300]), d);
        for _ in 0..8 {
            p.enqueue_peer(Bytes::from(vec![0u8; 50]), d);
        }
        for _ in 0..8 {
            let pkt = pop_next_data(&mut p).expect("small");
            assert_eq!(pkt.len(), 50);
        }
        let bulk = pop_next_data(&mut p).expect("bulk forced");
        assert_eq!(bulk.len(), 300);
        assert!(p.drr_bulk_force_pops() >= 1);
    }

    #[test]
    fn drr_bulk_force_when_hol_aged_before_small() {
        let mut p = PacingEngine::new();
        p.config.drr_small_packet_priority = true;
        p.config.drr_small_packet_threshold_bytes = 200;
        let d = addr(74);
        let q = p.peer_queues.entry(d).or_insert_with(PeerDataQueue::new);
        q.push_front_requeue(
            QueuedData {
                pkt: Bytes::from(vec![0u8; 300]),
                enqueued_at: Instant::now() - Duration::from_millis(20),
            },
            true,
            200,
        );
        p.non_empty_peers = 1;
        p.enqueue_peer(Bytes::from(vec![0u8; 50]), d);
        let first = pop_next_data(&mut p).expect("aged bulk forced first");
        assert_eq!(first.len(), 300);
        assert!(p.drr_bulk_force_pops() >= 1);
        let second = pop_next_data(&mut p).expect("small after");
        assert_eq!(second.len(), 50);
    }

    #[test]
    fn drr_hol_sojourn_includes_aged_bulk_behind_small() {
        let mut p = PacingEngine::new();
        p.config.drr_small_packet_priority = true;
        let dest = addr(73);
        let q = p.peer_queues.entry(dest).or_insert_with(PeerDataQueue::new);
        q.push_front_requeue(
            QueuedData {
                pkt: Bytes::from(vec![0u8; 300]),
                enqueued_at: Instant::now() - Duration::from_millis(25),
            },
            true,
            200,
        );
        p.non_empty_peers = 1;
        p.enqueue_peer(Bytes::from(vec![0u8; 10]), dest);
        let ms = p.max_hol_sojourn_ms(Instant::now());
        assert!(ms >= 20.0, "expected bulk HOL in max sojourn, got {ms}");
    }

    #[test]
    fn drr_small_threshold_sanitize_clamps() {
        let mut cfg = PacingConfig::default();
        cfg.drr_small_packet_threshold_bytes = 10;
        cfg.sanitize();
        assert_eq!(
            cfg.drr_small_packet_threshold_bytes,
            DRR_SMALL_PACKET_THRESHOLD_MIN
        );
        cfg.drr_small_packet_threshold_bytes = 900;
        cfg.sanitize();
        assert_eq!(
            cfg.drr_small_packet_threshold_bytes,
            DRR_SMALL_PACKET_THRESHOLD_MAX
        );
    }

    #[test]
    fn scaled_drr_quantum_clamps_and_rtt_aware_off() {
        assert_eq!(scaled_drr_quantum(1500, 20.0, 50.0, true, 0.5, 2.0), 1500);
        assert_eq!(scaled_drr_quantum(1500, 80.0, 50.0, true, 0.5, 2.0), 2400);
        assert_eq!(scaled_drr_quantum(1500, 80.0, 50.0, false, 0.5, 2.0), 1500);
        assert_eq!(scaled_drr_quantum(1500, -1.0, 50.0, true, 0.5, 2.0), 1500);
    }

    #[test]
    fn scaled_drr_quantum_base_rtt_ignores_bufferbloat_spread() {
        // Same base RTT → same quantum even if smoothed RTT would have differed.
        let base = 50.0_f32;
        let q_a = scaled_drr_quantum(1500, base, 50.0, true, 0.5, 2.0);
        let q_b = scaled_drr_quantum(1500, base, 50.0, true, 0.5, 2.0);
        assert_eq!(q_a, q_b);
        assert_eq!(q_a, 1500);
        // Distinct bases still differentiate (ref = median base 50).
        assert_eq!(scaled_drr_quantum(1500, 20.0, 50.0, true, 0.5, 2.0), 1500);
        assert_eq!(scaled_drr_quantum(1500, 80.0, 50.0, true, 0.5, 2.0), 2400);
    }

    #[test]
    fn scaled_drr_quantum_missing_base_does_not_scale() {
        assert_eq!(scaled_drr_quantum(1500, -1.0, 50.0, true, 0.5, 2.0), 1500);
        assert_eq!(scaled_drr_quantum(1500, 0.0, 50.0, true, 0.5, 2.0), 1500);
    }

    #[test]
    fn drr_rtt_ref_median_from_active_peers() {
        let mut p = PacingEngine::new();
        p.config.drr_rtt_aware = true;
        let a = addr(61);
        let b = addr(62);
        p.enqueue_peer_with_rtt(Bytes::from_static(b"a"), a, Some(20.0));
        p.enqueue_peer_with_rtt(Bytes::from_static(b"b"), b, Some(80.0));
        p.refresh_drr_rtt_ref_for_test();
        assert!((p.cached_rtt_ref_ms_for_test() - 50.0).abs() < 0.01);
    }

    #[test]
    fn drr_rtt_scale_sanitize_clamps() {
        let mut cfg = PacingConfig::default();
        cfg.drr_rtt_scale_min = 0.05;
        cfg.drr_rtt_scale_max = 9.0;
        cfg.sanitize();
        assert!((cfg.drr_rtt_scale_min - 0.1).abs() < f32::EPSILON);
        assert!((cfg.drr_rtt_scale_max - 4.0).abs() < f32::EPSILON);
        cfg.drr_rtt_scale_min = 2.5;
        cfg.drr_rtt_scale_max = 1.0;
        cfg.sanitize();
        assert_eq!(cfg.drr_rtt_scale_min, cfg.drr_rtt_scale_max);
    }

    #[test]
    fn background_cc_fifo_rate_limits_without_tokens() {
        use crate::net::background_cc::BackgroundCcConfig;

        let mut p = PacingEngine::new();
        p.config.drr_enabled = false;
        let cc_cfg = BackgroundCcConfig {
            enabled: true,
            initial_rate_bps: 8_000.0,
            min_rate_bps: 8_000.0,
            max_rate_bps: 8_000.0,
            burst_cap_bytes: 100.0,
            rate_smoothing_alpha: 0.0,
            ..BackgroundCcConfig::default()
        };
        p.set_background_cc_config(cc_cfg);
        let throttled = addr(70);
        let clear = addr(71);
        p.enqueue_peer(Bytes::from(vec![0u8; 1400]), throttled);
        p.enqueue_peer(Bytes::from(vec![1u8; 1400]), clear);
        p.background_cc.set_peer_tokens_for_test(throttled, 0.0);
        p.background_cc.set_peer_tokens_for_test(clear, 10_000.0);
        match p.pop_next() {
            Some(NextPacket::Data { dest, .. }) => assert_eq!(dest, clear),
            _ => panic!("expected clear peer data packet"),
        }
        assert!(p.cc_rate_limited_events() >= 1);
    }

    fn enable_cc_starve(p: &mut PacingEngine, dest: SocketAddr) {
        use crate::net::background_cc::BackgroundCcConfig;
        let cc_cfg = BackgroundCcConfig {
            enabled: true,
            hol_escape_ms: 50,
            burst_cap_bytes: 100.0,
            ..BackgroundCcConfig::default()
        };
        p.set_background_cc_config(cc_cfg);
        p.enqueue_peer(Bytes::from(vec![0u8; 200]), dest);
        p.background_cc.set_peer_tokens_for_test(dest, 0.0);
    }

    #[test]
    fn apd_cc_headroom_suppresses_drain_and_ramp_pin() {
        let mut p = apd_engine();
        p.apd.cfg.confirm_ticks = 1;
        let dest = addr(80);
        enable_cc_starve(&mut p, dest);
        let now = Instant::now();
        let ceiling = p.apd.cfg.ramp_max_burst.max(p.config.base_max_burst);
        p.apd_step(0.0, now, 0.0); // → Alert
        for _ in 0..8 {
            p.apd_step(0.95, now, 100.0);
        }
        assert_ne!(p.apd.phase, ApdPhase::Drain);
        assert!(p.apd.ramp_burst < ceiling);
        assert!(p.apd_cc_headroom_suppressions() >= 1);
    }

    #[test]
    fn apd_cc_headroom_allows_drain_when_peer_has_tokens() {
        let mut p = apd_engine();
        let dest = addr(81);
        enable_cc_starve(&mut p, dest);
        p.background_cc.set_peer_tokens_for_test(dest, 10_000.0);
        let now = Instant::now();
        pin_apd_ramp(&mut p, now);
        p.apd.cfg.confirm_ticks = 1;
        p.apd_step(0.95, now, 100.0);
        assert_eq!(p.apd.phase, ApdPhase::Drain);
    }

    #[test]
    fn apd_cc_headroom_disabled_allows_drain_under_cc_starve() {
        let mut p = apd_engine();
        p.apd.cfg.require_cc_headroom = false;
        let dest = addr(82);
        enable_cc_starve(&mut p, dest);
        let now = Instant::now();
        pin_apd_ramp(&mut p, now);
        p.apd.cfg.confirm_ticks = 1;
        p.apd_step(0.95, now, 100.0);
        assert_eq!(p.apd.phase, ApdPhase::Drain);
    }

    #[test]
    fn apd_cc_headroom_vacuous_without_data_peers_allows_drain() {
        use crate::net::background_cc::BackgroundCcConfig;

        let mut p = apd_engine();
        p.set_background_cc_config(BackgroundCcConfig {
            enabled: true,
            ..BackgroundCcConfig::default()
        });
        // Control-only backlog: no non-empty data peers → vacuous headroom.
        p.enqueue_control(Bytes::from_static(b"ctrl"), addr(83));
        let now = Instant::now();
        pin_apd_ramp(&mut p, now);
        p.apd.cfg.confirm_ticks = 1;
        p.apd_step(0.95, now, 100.0);
        assert_eq!(p.apd.phase, ApdPhase::Drain);
    }

    #[test]
    fn apd_cc_headroom_early_exits_drain_when_tokens_gone() {
        let mut p = apd_engine();
        p.apd.cfg.spinloop_budget_ms = 0; // would otherwise stick in Drain
        let dest = addr(84);
        enable_cc_starve(&mut p, dest);
        p.background_cc.set_peer_tokens_for_test(dest, 10_000.0);
        let now = Instant::now();
        pin_apd_ramp(&mut p, now);
        p.apd.cfg.confirm_ticks = 1;
        p.apd_step(0.95, now, 100.0);
        assert_eq!(p.apd.phase, ApdPhase::Drain);
        p.background_cc.set_peer_tokens_for_test(dest, 0.0);
        p.apd_step(0.95, now, 100.0);
        assert_eq!(p.apd.phase, ApdPhase::Cooldown);
        assert!(p.apd_cc_headroom_suppressions() >= 1);
    }

    #[test]
    fn apd_require_cc_headroom_toml_default_true() {
        use crate::config::NetworkConfig;
        use crate::config_toml::NetworkConfigFile;

        let net = NetworkConfig::default();
        assert!(net.apd_require_cc_headroom);
        let file = NetworkConfigFile::from(&net);
        assert!(file.apd.apd_require_cc_headroom);
        let round = NetworkConfig::from(file);
        assert!(round.apd_require_cc_headroom);
        let apd = super::apd_config_from_network(&round);
        assert!(apd.require_cc_headroom);
    }
}
