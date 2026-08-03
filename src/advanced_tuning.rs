//! Advanced runtime tuning (failover / timers / reliable / FEC / PMTUD).
//!
//! All fields default to the hard-coded constants the engine used before this
//! preserves today's behavior byte-for-byte. `clamp()` enforces hard floors /
//! ceilings / ordering invariants before any value reaches the runtime. Persisted
//! as sectioned tables in `NetInfo/config.toml` (`[failover]`, `[timers]`,
//! `[fec]`, `[congestion]`, …); apply live with `config reload`.

use serde::{Deserialize, Serialize};

// ── Failover ───────────────────────────────────────────────────────────────
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FailoverTuning {
    pub d2r_quality_min: i32,
    pub d2r_loss_max: f64,
    pub d2r_jitter_max: f64,
    pub r2d_quality_min: i32,
    pub r2d_success_min: i32,
    pub hold_down_secs: u64,
}

impl Default for FailoverTuning {
    fn default() -> Self {
        Self {
            d2r_quality_min: crate::routing::failover::D2R_QUALITY_MIN,
            d2r_loss_max: crate::routing::failover::D2R_LOSS_MAX,
            d2r_jitter_max: crate::routing::failover::D2R_JITTER_MAX,
            r2d_quality_min: crate::routing::failover::R2D_QUALITY_MIN,
            r2d_success_min: crate::routing::failover::R2D_SUCCESS_MIN,
            hold_down_secs: crate::routing::failover::HOLD_DOWN_SECS,
        }
    }
}

// ── Timers ─────────────────────────────────────────────────────────────────
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TimerTuning {
    pub keepalive_secs: u64,
    pub msyn_secs: u64,
    pub pmtud_tick_ms: u64,
    pub pmtud_raise_secs: u64,
    pub ping_watchdog_ms: u64,
    pub stale_tick_secs: u64,
    pub stale_mark_secs: u64,
    pub stale_evict_secs: u64,
}

impl Default for TimerTuning {
    fn default() -> Self {
        Self {
            keepalive_secs: 5,
            msyn_secs: 15,
            pmtud_tick_ms: 50,
            pmtud_raise_secs: 60,
            ping_watchdog_ms: 100,
            stale_tick_secs: 30,
            stale_mark_secs: 35,
            stale_evict_secs: 45,
        }
    }
}

// ── Reliable ───────────────────────────────────────────────────────────────
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ReliableTuning {
    pub rto_min_ms: u32,
    pub rto_max_ms: u32,
    pub max_pending: usize,
    pub retries_left: u8,
    pub send_scratch_bytes: usize,
}

impl Default for ReliableTuning {
    fn default() -> Self {
        Self {
            rto_min_ms: 75,
            rto_max_ms: 400,
            max_pending: 256,
            retries_left: 1,
            send_scratch_bytes: 1500,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BufferReuseTuning {
    pub encrypt_scratch_bytes: usize,
    pub control_scratch_bytes: usize,
    pub plain_data_scratch_bytes: usize,
    pub decrypt_scratch_bytes: usize,
    pub fec_frame_scratch_bytes: usize,
}

impl Default for BufferReuseTuning {
    fn default() -> Self {
        Self {
            encrypt_scratch_bytes: 2048,
            control_scratch_bytes: 512,
            plain_data_scratch_bytes: 2048,
            decrypt_scratch_bytes: 2048,
            fec_frame_scratch_bytes: crate::net::packet::FEC_COMPACT_HEADER_LEN
                + crate::net::fec::FEC_SHARD_PAYLOAD_SIZE,
        }
    }
}

impl BufferReuseTuning {
    pub fn clamp(&mut self) {
        self.encrypt_scratch_bytes = self.encrypt_scratch_bytes.clamp(64, 1_048_576);
        self.control_scratch_bytes = self.control_scratch_bytes.clamp(32, 131_072);
        self.plain_data_scratch_bytes = self.plain_data_scratch_bytes.clamp(64, 1_048_576);
        self.decrypt_scratch_bytes = self.decrypt_scratch_bytes.clamp(64, 1_048_576);
        self.fec_frame_scratch_bytes = self.fec_frame_scratch_bytes.clamp(64, 1_048_576);
    }
}

// ── FEC ────────────────────────────────────────────────────────────────────
/// Upper bound for `shard_payload_size`. Values above the compile-time
/// `FEC_SHARD_PAYLOAD_SIZE` (1279) are rejected/clamped because the v3 wire
/// format cannot carry larger shards without a protocol-version bump.
const FEC_SHARD_PAYLOAD_MAX: usize = crate::net::fec::FEC_SHARD_PAYLOAD_SIZE;
const FEC_SHARD_PAYLOAD_MIN: usize = crate::net::fec::FEC_SHARD_PAYLOAD_MIN;

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FecTuning {
    pub shard_payload_size: usize,
    pub flush_ms: u64,
    pub flush_aggressive_ms: u64,
    pub adaptive_off_below: f64,
    pub adaptive_on_above: f64,
    /// Runtime cap on data+parity shards; never exceeds compile-time `FEC_MAX_TOTAL_SHARDS`.
    pub fec_max_total_shards: usize,
}

impl Default for FecTuning {
    fn default() -> Self {
        Self {
            shard_payload_size: 1024,
            flush_ms: 2,
            flush_aggressive_ms: 1,
            adaptive_off_below: 0.015,
            adaptive_on_above: 0.03,
            fec_max_total_shards: 16,
        }
    }
}

// ── Routing EWMA / quality score ────────────────────────────────────────────
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RoutingEwmaTuning {
    pub rtt_ewma_old: f64,
    pub rtt_ewma_new: f64,
    pub jitter_ewma_old: f64,
    pub jitter_ewma_new: f64,
    pub loss_ewma_decay: f64,
    pub loss_ewma_success_delta: f64,
    pub loss_ewma_fail_bump: f64,
    pub bw_ewma_old: f64,
    pub bw_ewma_new: f64,
    pub quality_initial: i32,
    pub quality_loss_scale: f64,
    pub quality_loss_penalty_cap: f64,
    pub quality_jitter_div: f64,
    pub quality_jitter_penalty_cap: f64,
    pub rtt_score_clamp_ms: i64,
}

impl Default for RoutingEwmaTuning {
    fn default() -> Self {
        Self {
            rtt_ewma_old: 0.8,
            rtt_ewma_new: 0.2,
            jitter_ewma_old: 0.8,
            jitter_ewma_new: 0.2,
            loss_ewma_decay: 0.85,
            loss_ewma_success_delta: 0.01,
            loss_ewma_fail_bump: 0.05,
            bw_ewma_old: 0.85,
            bw_ewma_new: 0.15,
            quality_initial: 50,
            quality_loss_scale: 60.0,
            quality_loss_penalty_cap: 40.0,
            quality_jitter_div: 3.0,
            quality_jitter_penalty_cap: 30.0,
            rtt_score_clamp_ms: 500,
        }
    }
}

impl RoutingEwmaTuning {
    fn renormalize_pair(old: &mut f64, new: &mut f64) {
        *old = old.clamp(0.0, 1.0);
        *new = new.clamp(0.0, 1.0);
        let sum = *old + *new;
        if sum > 0.0 {
            *old /= sum;
            *new /= sum;
        } else {
            *old = 0.5;
            *new = 0.5;
        }
    }

    pub fn clamp(&mut self) {
        Self::renormalize_pair(&mut self.rtt_ewma_old, &mut self.rtt_ewma_new);
        Self::renormalize_pair(&mut self.jitter_ewma_old, &mut self.jitter_ewma_new);
        Self::renormalize_pair(&mut self.bw_ewma_old, &mut self.bw_ewma_new);
        self.loss_ewma_decay = self.loss_ewma_decay.clamp(0.5, 0.999);
        self.loss_ewma_success_delta = self.loss_ewma_success_delta.clamp(0.0, 0.1);
        self.loss_ewma_fail_bump = self.loss_ewma_fail_bump.clamp(0.0, 0.5);
        self.quality_initial = self.quality_initial.clamp(0, 100);
        self.quality_loss_scale = self.quality_loss_scale.clamp(0.0, 200.0);
        self.quality_loss_penalty_cap = self.quality_loss_penalty_cap.clamp(0.0, 100.0);
        self.quality_jitter_div = self.quality_jitter_div.clamp(1.0, 30.0);
        self.quality_jitter_penalty_cap = self.quality_jitter_penalty_cap.clamp(0.0, 100.0);
        self.rtt_score_clamp_ms = self.rtt_score_clamp_ms.clamp(50, 2000);
    }
}

// ── Engine per-tick / STUN / MSYN limits ────────────────────────────────────
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineLimitsTuning {
    pub max_direct_retry_per_tick: usize,
    pub max_pending_heal_probes: usize,
    pub max_pending_stun_queries: usize,
    pub max_cc_probes_per_tick: usize,
    pub max_secondary_retry_per_tick: usize,
    pub stun_cache_ttl_secs: u64,
    pub msyn_body_max: usize,
    /// Max serialized MSYN v4 JSON part size before compound wrap.
    pub msyn_shard_budget_bytes: usize,
    pub heal_cooldown_ms: u64,
}

impl Default for EngineLimitsTuning {
    fn default() -> Self {
        Self {
            max_direct_retry_per_tick: 8,
            max_pending_heal_probes: 96,
            max_pending_stun_queries: 8,
            max_cc_probes_per_tick: 32,
            max_secondary_retry_per_tick: 4,
            stun_cache_ttl_secs: 30,
            msyn_body_max: 524_288,
            msyn_shard_budget_bytes: 1200,
            heal_cooldown_ms: 1_000,
        }
    }
}

impl EngineLimitsTuning {
    pub fn clamp(&mut self) {
        self.max_direct_retry_per_tick = self.max_direct_retry_per_tick.clamp(1, 256);
        self.max_pending_heal_probes = self.max_pending_heal_probes.clamp(1, 1024);
        self.max_pending_stun_queries = self.max_pending_stun_queries.clamp(1, 64);
        self.max_cc_probes_per_tick = self.max_cc_probes_per_tick.clamp(1, 256);
        self.max_secondary_retry_per_tick = self.max_secondary_retry_per_tick.clamp(1, 256);
        self.stun_cache_ttl_secs = self.stun_cache_ttl_secs.clamp(1, 600);
        self.msyn_body_max = self.msyn_body_max.clamp(4096, 524_288);
        let shard_hi = 4096usize.min(self.msyn_body_max);
        self.msyn_shard_budget_bytes = self.msyn_shard_budget_bytes.clamp(512, shard_hi);
        self.heal_cooldown_ms = self.heal_cooldown_ms.clamp(50, 60_000);
    }
}

// ── Canonical hole-punch workflow ───────────────────────────────────────────
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HolePunchTuning {
    pub punch_stage1_packets: usize,
    pub punch_stage1_gap_ms: u64,
    pub punch_stage1_observe_ms: u64,
    pub punch_stage2_observe_secs: u64,
    pub punch_stage2_pps: u32,
    pub punch_stage3_pps: u32,
    pub punch_stage3_max_secs: u64,
    pub punch_stage3_batch_gap_ms: u64,
    pub punch_max_expanded_targets: usize,
    pub punch_wide_min_width: usize,
    pub punch_wide_max_width: usize,
    pub punch_random_port_min: u16,
    pub punch_random_port_max: u16,
}

impl Default for HolePunchTuning {
    fn default() -> Self {
        Self {
            punch_stage1_packets: crate::net::decentralized::CANONICAL_STAGE1_PACKETS,
            punch_stage1_gap_ms: crate::net::decentralized::CANONICAL_STAGE1_GAP_MS,
            punch_stage1_observe_ms: crate::net::decentralized::CANONICAL_STAGE1_OBSERVE_MS,
            punch_stage2_observe_secs: crate::net::decentralized::CANONICAL_STAGE2_OBSERVE_SECS,
            punch_stage2_pps: crate::net::decentralized::JOIN_OVERLAY_WIDE_PPS,
            punch_stage3_pps: crate::net::decentralized::JOIN_OVERLAY_RANDOM_PPS,
            punch_stage3_max_secs: crate::net::decentralized::JOIN_OVERLAY_RANDOM_MAX_SECS,
            punch_stage3_batch_gap_ms: 500,
            punch_max_expanded_targets: crate::net::decentralized::MAX_EXPANDED_PUNCH_TARGETS,
            punch_wide_min_width: crate::net::decentralized::JOIN_OVERLAY_WIDE_MIN_WIDTH,
            punch_wide_max_width: crate::net::decentralized::JOIN_OVERLAY_WIDE_MAX_WIDTH,
            punch_random_port_min: 1024,
            punch_random_port_max: 65535,
        }
    }
}

impl HolePunchTuning {
    pub fn clamp(&mut self) {
        self.punch_stage1_packets = self.punch_stage1_packets.clamp(1, 16);
        self.punch_stage1_gap_ms = self.punch_stage1_gap_ms.clamp(1, 1000);
        self.punch_stage1_observe_ms = self.punch_stage1_observe_ms.min(10_000);
        self.punch_stage2_observe_secs = self.punch_stage2_observe_secs.min(30);
        self.punch_stage2_pps = self.punch_stage2_pps.clamp(1, 2000);
        self.punch_stage3_pps = self.punch_stage3_pps.clamp(1, 2000);
        self.punch_stage3_max_secs = self.punch_stage3_max_secs.clamp(1, 120);
        self.punch_stage3_batch_gap_ms = self.punch_stage3_batch_gap_ms.min(5000);
        self.punch_max_expanded_targets = self.punch_max_expanded_targets.clamp(32, 2048);
        self.punch_wide_min_width = self.punch_wide_min_width.max(1).min(2048);
        self.punch_wide_max_width = self.punch_wide_max_width.max(1).min(2048);
        if self.punch_wide_max_width < self.punch_wide_min_width {
            self.punch_wide_max_width = self.punch_wide_min_width;
        }
        if self.punch_random_port_min == 0 {
            self.punch_random_port_min = 1;
        }
        if self.punch_random_port_max == 0 {
            self.punch_random_port_max = 1;
        }
        if self.punch_random_port_min > self.punch_random_port_max {
            std::mem::swap(
                &mut self.punch_random_port_min,
                &mut self.punch_random_port_max,
            );
        }
    }
}

// ── Congestion (RTT base + FEC loss classifier) ─────────────────────────────
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CongestionTuning {
    pub rtt_base_tracking: bool,
    pub loss_classifier_enabled: bool,
    pub target_queue_delay_ms: u32,
    pub congestion_loss_threshold: f64,
    pub base_rtt_window_secs: u64,
    pub base_rtt_stale_windows: u8,
    /// Reject forward OWD sample (and reset base cold) when `|sample − base|` exceeds this (ms).
    pub owd_clock_jump_reject_ms: u64,
    /// Compact ping probe period for congestion telemetry (`0` = off). Independent of `keepalive_secs`.
    pub probe_interval_ms: u64,
    /// How long after last congestive delay sample FEC recovery step-down may fire (`0` = off).
    pub fec_recovery_recency_ms: u64,
    /// LEDBAT background CC pacing per peer (default on).
    #[serde(rename = "congestion_enabled")]
    pub enabled: bool,
    /// Multiplicative decrease strength when queuing delay exceeds target.
    pub gain: f64,
    /// Force send when peer HOL sojourn reaches this (starve escape).
    pub hol_escape_ms: u32,
    pub initial_rate_bps: f64,
    pub additive_increase_bps: f64,
    pub min_decrease_factor: f64,
    pub rate_smoothing_alpha: f64,
    pub min_rate_bps: f64,
    pub max_rate_bps: f64,
    pub loss_multiplicative_decrease: f64,
    pub burst_cap_bytes: u64,
    /// Window for delivered TX rate samples before one EWMA update.
    pub delivery_rate_window_ms: u32,
    /// Weight of a new delivery-rate window sample.
    pub delivery_rate_ewma_alpha: f64,
    /// Multiplier applied to delivery EWMA on a hard-anchored decrease.
    pub delivery_anchor_factor: f64,
    /// Ceiling/delivery ratio that triggers hard-anchored decrease.
    pub delivery_decouple_ratio: f64,
}

impl Default for CongestionTuning {
    fn default() -> Self {
        Self {
            rtt_base_tracking: true,
            loss_classifier_enabled: true,
            target_queue_delay_ms: crate::net::background_cc::DEFAULT_TARGET_QUEUE_DELAY_MS,
            congestion_loss_threshold: 0.7,
            base_rtt_window_secs: 4,
            base_rtt_stale_windows: 3,
            owd_clock_jump_reject_ms: crate::routing::DEFAULT_OWD_CLOCK_JUMP_REJECT_MS,
            probe_interval_ms: 40,
            fec_recovery_recency_ms: 1_200,
            enabled: true,
            gain: crate::net::background_cc::DEFAULT_GAIN,
            hol_escape_ms: crate::net::background_cc::DEFAULT_HOL_ESCAPE_MS,
            initial_rate_bps: crate::net::background_cc::DEFAULT_INITIAL_RATE_BPS,
            additive_increase_bps: crate::net::background_cc::DEFAULT_ADDITIVE_INCREASE_BPS,
            min_decrease_factor: crate::net::background_cc::DEFAULT_MIN_DECREASE_FACTOR,
            rate_smoothing_alpha: crate::net::background_cc::DEFAULT_RATE_SMOOTHING_ALPHA,
            min_rate_bps: crate::net::background_cc::DEFAULT_MIN_RATE_BPS,
            max_rate_bps: crate::net::background_cc::DEFAULT_MAX_RATE_BPS,
            loss_multiplicative_decrease: crate::net::background_cc::DEFAULT_LOSS_MD,
            burst_cap_bytes: crate::net::background_cc::DEFAULT_BURST_CAP_BYTES,
            delivery_rate_window_ms: crate::net::background_cc::DEFAULT_DELIVERY_RATE_WINDOW_MS,
            delivery_rate_ewma_alpha: crate::net::background_cc::DEFAULT_DELIVERY_RATE_EWMA_ALPHA,
            delivery_anchor_factor: crate::net::background_cc::DEFAULT_DELIVERY_ANCHOR_FACTOR,
            delivery_decouple_ratio: crate::net::background_cc::DEFAULT_DELIVERY_DECOUPLE_RATIO,
        }
    }
}

impl CongestionTuning {
    pub fn clamp_rate_knobs(&mut self) {
        self.gain = self.gain.clamp(0.1, 4.0);
        self.hol_escape_ms = self.hol_escape_ms.clamp(4, 100);
        self.min_decrease_factor = self.min_decrease_factor.clamp(0.1, 0.9);
        self.additive_increase_bps = self.additive_increase_bps.clamp(4_000.0, 1_000_000.0);
        self.rate_smoothing_alpha = self.rate_smoothing_alpha.clamp(0.0, 0.95);
        self.min_rate_bps = self.min_rate_bps.clamp(1_000.0, f64::MAX);
        self.max_rate_bps = self.max_rate_bps.clamp(self.min_rate_bps, 50_000_000.0);
        self.loss_multiplicative_decrease = self.loss_multiplicative_decrease.clamp(0.3, 0.9);
        self.burst_cap_bytes = self.burst_cap_bytes.clamp(512, 256 * 1024);
        self.initial_rate_bps = self
            .initial_rate_bps
            .clamp(self.min_rate_bps, self.max_rate_bps);
        self.delivery_rate_window_ms = self.delivery_rate_window_ms.clamp(100, 5_000);
        self.delivery_rate_ewma_alpha = self.delivery_rate_ewma_alpha.clamp(0.05, 1.0);
        self.delivery_anchor_factor = self.delivery_anchor_factor.clamp(0.5, 0.99);
        self.delivery_decouple_ratio = self.delivery_decouple_ratio.clamp(1.05, 3.0);
    }

    pub fn to_background_cc_config(&self) -> crate::net::background_cc::BackgroundCcConfig {
        crate::net::background_cc::BackgroundCcConfig {
            enabled: self.enabled,
            gain: self.gain,
            min_decrease_factor: self.min_decrease_factor,
            additive_increase_bps: self.additive_increase_bps,
            rate_smoothing_alpha: self.rate_smoothing_alpha,
            initial_rate_bps: self.initial_rate_bps,
            min_rate_bps: self.min_rate_bps,
            max_rate_bps: self.max_rate_bps,
            loss_multiplicative_decrease: self.loss_multiplicative_decrease,
            burst_cap_bytes: self.burst_cap_bytes as f64,
            target_queue_delay_ms: self.target_queue_delay_ms,
            hol_escape_ms: self.hol_escape_ms,
            delivery_rate_window_ms: self.delivery_rate_window_ms,
            delivery_rate_ewma_alpha: self.delivery_rate_ewma_alpha,
            delivery_anchor_factor: self.delivery_anchor_factor,
            delivery_decouple_ratio: self.delivery_decouple_ratio,
            loss_classifier_enabled: self.loss_classifier_enabled,
            congestion_loss_threshold: self.congestion_loss_threshold,
            qd_telemetry_valid: self.rtt_base_tracking,
        }
    }
}

/// Timer period for the CC probe loop (`3600s` when probes are disabled).
pub fn cc_probe_timer_period_ms(probe_interval_ms: u64) -> u64 {
    if probe_interval_ms == 0 {
        3_600_000
    } else {
        probe_interval_ms.clamp(20, 1000)
    }
}

// ── PMTUD ───────────────────────────────────────────────────────────────────
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PmtudTuning {
    pub probe_timeout_ms: u64,
    pub confirm_count: u8,
    pub resolve_epsilon: usize,
    pub raise_step: usize,
    pub max_probes_per_search: u32,
    pub max_concurrent_peers: usize,
    pub stable_downgrade_batches: u8,
}

impl Default for PmtudTuning {
    fn default() -> Self {
        Self {
            probe_timeout_ms: 500,
            confirm_count: 3,
            resolve_epsilon: 8,
            raise_step: 32,
            max_probes_per_search: 64,
            max_concurrent_peers: 4,
            stable_downgrade_batches: 4,
        }
    }
}

// ── Aggregate ───────────────────────────────────────────────────────────────
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct AdvancedTuning {
    #[serde(default, flatten)]
    pub failover: FailoverTuning,
    #[serde(default, flatten)]
    pub timers: TimerTuning,
    #[serde(default, flatten)]
    pub reliable: ReliableTuning,
    #[serde(default, flatten)]
    pub fec: FecTuning,
    #[serde(default, flatten)]
    pub congestion: CongestionTuning,
    #[serde(default, flatten)]
    pub pmtud: PmtudTuning,
    #[serde(default, flatten)]
    pub routing_ewma: RoutingEwmaTuning,
    #[serde(default, flatten)]
    pub engine_limits: EngineLimitsTuning,
    #[serde(default, flatten)]
    pub hole_punch: HolePunchTuning,
    #[serde(default, flatten)]
    pub buffers: BufferReuseTuning,
}

impl AdvancedTuning {
    /// Build from a network config snapshot, applying `clamp()`.
    pub fn from_network_config(cfg: &crate::config::NetworkConfig) -> Self {
        let mut t = cfg.advanced.clone();
        t.clamp();
        t
    }

    /// Enforce hard floors / ceilings / ordering invariants.
    pub fn clamp(&mut self) {
        // Failover
        self.failover.d2r_loss_max = self.failover.d2r_loss_max.clamp(0.0, 1.0);
        self.failover.d2r_jitter_max = self.failover.d2r_jitter_max.max(0.0);
        self.failover.d2r_quality_min = self.failover.d2r_quality_min.clamp(0, 100);
        self.failover.r2d_quality_min = self.failover.r2d_quality_min.clamp(0, 100);
        if self.failover.r2d_quality_min < self.failover.d2r_quality_min {
            self.failover.r2d_quality_min = self.failover.d2r_quality_min;
        }
        self.failover.r2d_success_min = self.failover.r2d_success_min.max(1);
        self.failover.hold_down_secs = self.failover.hold_down_secs.max(0);

        // Timers
        self.timers.keepalive_secs = self.timers.keepalive_secs.max(1);
        self.timers.msyn_secs = self.timers.msyn_secs.max(1);
        self.timers.pmtud_tick_ms = self.timers.pmtud_tick_ms.clamp(10, 1000);
        self.timers.pmtud_raise_secs = self.timers.pmtud_raise_secs.max(1);
        self.timers.ping_watchdog_ms = self.timers.ping_watchdog_ms.max(10);
        self.timers.stale_tick_secs = self.timers.stale_tick_secs.max(1);
        self.timers.stale_mark_secs = self.timers.stale_mark_secs.max(1);
        self.timers.stale_evict_secs = self.timers.stale_evict_secs.max(1);
        // stale_tick < stale_mark < stale_evict
        if self.timers.stale_mark_secs <= self.timers.stale_tick_secs {
            self.timers.stale_mark_secs = self.timers.stale_tick_secs + 1;
        }
        if self.timers.stale_evict_secs <= self.timers.stale_mark_secs {
            self.timers.stale_evict_secs = self.timers.stale_mark_secs + 1;
        }

        // Reliable
        self.reliable.rto_min_ms = self.reliable.rto_min_ms.max(5);
        self.reliable.rto_max_ms = self.reliable.rto_max_ms.max(self.reliable.rto_min_ms);
        self.reliable.max_pending = self.reliable.max_pending.max(16);
        self.reliable.retries_left = self.reliable.retries_left.min(8);
        self.reliable.send_scratch_bytes = self.reliable.send_scratch_bytes.clamp(64, 1_048_576);

        // FEC
        self.fec.shard_payload_size = self
            .fec
            .shard_payload_size
            .clamp(FEC_SHARD_PAYLOAD_MIN, FEC_SHARD_PAYLOAD_MAX);
        self.fec.flush_ms = self.fec.flush_ms.max(1);
        self.fec.flush_aggressive_ms = self.fec.flush_aggressive_ms.max(1);
        self.fec.adaptive_off_below = self.fec.adaptive_off_below.clamp(0.0, 0.5);
        self.fec.adaptive_on_above = self.fec.adaptive_on_above.clamp(0.0, 0.5);
        if self.fec.adaptive_on_above < self.fec.adaptive_off_below {
            self.fec.adaptive_on_above = self.fec.adaptive_off_below;
        }
        self.fec.fec_max_total_shards = self
            .fec
            .fec_max_total_shards
            .clamp(2, crate::net::fec::FEC_MAX_TOTAL_SHARDS);

        // Congestion
        self.congestion.target_queue_delay_ms =
            self.congestion.target_queue_delay_ms.clamp(10, 150);
        self.congestion.congestion_loss_threshold =
            self.congestion.congestion_loss_threshold.clamp(0.3, 0.95);
        self.congestion.base_rtt_window_secs = self.congestion.base_rtt_window_secs.clamp(1, 60);
        self.congestion.base_rtt_stale_windows =
            self.congestion.base_rtt_stale_windows.clamp(1, 10);
        self.congestion.owd_clock_jump_reject_ms = self
            .congestion
            .owd_clock_jump_reject_ms
            .clamp(1_000, 600_000);
        if self.congestion.probe_interval_ms != 0 {
            self.congestion.probe_interval_ms = self.congestion.probe_interval_ms.clamp(20, 1000);
        }
        if self.congestion.fec_recovery_recency_ms != 0 {
            self.congestion.fec_recovery_recency_ms =
                self.congestion.fec_recovery_recency_ms.clamp(100, 60_000);
        }
        self.congestion.gain = self.congestion.gain.clamp(0.1, 4.0);
        self.congestion.clamp_rate_knobs();

        self.routing_ewma.clamp();
        self.engine_limits.clamp();
        self.hole_punch.clamp();
        self.buffers.clamp();

        // PMTUD
        self.pmtud.stable_downgrade_batches = self.pmtud.stable_downgrade_batches.max(1);
        self.pmtud.probe_timeout_ms = self.pmtud.probe_timeout_ms.clamp(50, 10_000);
        self.pmtud.confirm_count = self.pmtud.confirm_count.clamp(1, 8);
        self.pmtud.resolve_epsilon = self.pmtud.resolve_epsilon.clamp(1, 8);
        self.pmtud.raise_step = self.pmtud.raise_step.clamp(1, 512);
        self.pmtud.max_probes_per_search = self.pmtud.max_probes_per_search.clamp(8, 256);
        self.pmtud.max_concurrent_peers = self.pmtud.max_concurrent_peers.clamp(1, 64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_engine_constants() {
        let d = AdvancedTuning::default();
        assert_eq!(
            d.failover.d2r_quality_min,
            crate::routing::failover::D2R_QUALITY_MIN
        );
        assert_eq!(
            d.failover.d2r_loss_max,
            crate::routing::failover::D2R_LOSS_MAX
        );
        assert_eq!(
            d.failover.d2r_jitter_max,
            crate::routing::failover::D2R_JITTER_MAX
        );
        assert_eq!(
            d.failover.r2d_quality_min,
            crate::routing::failover::R2D_QUALITY_MIN
        );
        assert_eq!(
            d.failover.r2d_success_min,
            crate::routing::failover::R2D_SUCCESS_MIN
        );
        assert_eq!(
            d.failover.hold_down_secs,
            crate::routing::failover::HOLD_DOWN_SECS
        );

        assert_eq!(d.reliable.rto_min_ms, 75);
        assert_eq!(d.reliable.rto_max_ms, 400);
        assert_eq!(d.reliable.max_pending, 256);
        assert_eq!(d.reliable.retries_left, 1);
        assert_eq!(d.reliable.send_scratch_bytes, 1500);

        assert_eq!(d.fec.shard_payload_size, 1024);
        assert_eq!(d.fec.flush_ms, 2);
        assert_eq!(d.fec.flush_aggressive_ms, 1);
        assert_eq!(d.fec.adaptive_off_below, 0.015);
        assert_eq!(d.fec.adaptive_on_above, 0.03);
        assert_eq!(d.fec.fec_max_total_shards, 16);

        assert_eq!(d.pmtud.probe_timeout_ms, 500);
        assert_eq!(d.pmtud.confirm_count, 3);
        assert_eq!(d.pmtud.resolve_epsilon, 8);
        assert_eq!(d.pmtud.raise_step, 32);
        assert_eq!(d.pmtud.max_probes_per_search, 64);
        assert_eq!(d.pmtud.max_concurrent_peers, 4);
        assert_eq!(d.pmtud.stable_downgrade_batches, 4);

        assert_eq!(d.timers.keepalive_secs, 5);
        assert_eq!(d.timers.msyn_secs, 15);
        assert_eq!(d.timers.pmtud_tick_ms, 50);
        assert_eq!(d.timers.pmtud_raise_secs, 60);
        assert_eq!(d.timers.ping_watchdog_ms, 100);
        assert_eq!(d.timers.stale_tick_secs, 30);
        assert_eq!(d.timers.stale_mark_secs, 35);
        assert_eq!(d.timers.stale_evict_secs, 45);

        assert!(d.congestion.rtt_base_tracking);
        assert!(d.congestion.loss_classifier_enabled);
        assert_eq!(d.congestion.target_queue_delay_ms, 15);
        assert_eq!(d.congestion.congestion_loss_threshold, 0.7);
        assert_eq!(d.congestion.base_rtt_window_secs, 4);
        assert_eq!(d.congestion.base_rtt_stale_windows, 3);
        assert_eq!(
            d.congestion.owd_clock_jump_reject_ms,
            crate::routing::DEFAULT_OWD_CLOCK_JUMP_REJECT_MS
        );
        assert_eq!(d.congestion.probe_interval_ms, 40);
        assert_eq!(d.congestion.fec_recovery_recency_ms, 1_200);
        assert!(d.congestion.enabled);
        assert_eq!(d.congestion.gain, 0.1);
        assert_eq!(d.congestion.hol_escape_ms, 12);
        assert_eq!(d.congestion.initial_rate_bps, 2_000_000.0);
        assert_eq!(d.congestion.additive_increase_bps, 28_000.0);
        assert_eq!(d.congestion.min_decrease_factor, 0.9);
        assert_eq!(d.congestion.rate_smoothing_alpha, 0.9);
        assert_eq!(d.congestion.loss_multiplicative_decrease, 0.9);
        assert_eq!(d.congestion.min_rate_bps, 1_800_000.0);
        assert_eq!(d.congestion.max_rate_bps, 25_000_000.0);
        assert_eq!(d.congestion.burst_cap_bytes, 16_000);
        assert_eq!(d.congestion.delivery_rate_window_ms, 750);
        assert_eq!(d.congestion.delivery_rate_ewma_alpha, 0.25);
        assert_eq!(d.congestion.delivery_anchor_factor, 0.95);
        assert_eq!(d.congestion.delivery_decouple_ratio, 1.5);

        assert_eq!(d.routing_ewma.rtt_ewma_old, 0.8);
        assert_eq!(d.routing_ewma.rtt_ewma_new, 0.2);
        assert_eq!(d.routing_ewma.loss_ewma_decay, 0.85);
        assert_eq!(d.routing_ewma.loss_ewma_success_delta, 0.01);
        assert_eq!(d.routing_ewma.loss_ewma_fail_bump, 0.05);
        assert_eq!(d.routing_ewma.bw_ewma_old, 0.85);
        assert_eq!(d.routing_ewma.quality_initial, 50);
        assert_eq!(d.routing_ewma.quality_loss_penalty_cap, 40.0);

        assert_eq!(d.engine_limits.max_direct_retry_per_tick, 8);
        assert_eq!(d.engine_limits.max_secondary_retry_per_tick, 4);
        assert_eq!(d.engine_limits.max_pending_heal_probes, 96);
        assert_eq!(d.engine_limits.msyn_body_max, 524_288);
        assert_eq!(d.engine_limits.msyn_shard_budget_bytes, 1200);
        assert_eq!(d.engine_limits.stun_cache_ttl_secs, 30);

        assert_eq!(d.hole_punch.punch_stage1_packets, 3);
        assert_eq!(d.hole_punch.punch_stage2_pps, 128);
        assert_eq!(d.hole_punch.punch_stage3_pps, 64);
        assert_eq!(d.buffers.encrypt_scratch_bytes, 2048);
        assert_eq!(d.buffers.control_scratch_bytes, 512);
        assert_eq!(d.buffers.plain_data_scratch_bytes, 2048);
        assert_eq!(d.buffers.decrypt_scratch_bytes, 2048);
        assert_eq!(
            d.buffers.fec_frame_scratch_bytes,
            crate::net::packet::FEC_COMPACT_HEADER_LEN + crate::net::fec::FEC_SHARD_PAYLOAD_SIZE
        );
        assert_eq!(d.hole_punch.punch_max_expanded_targets, 512);
        assert_eq!(d.hole_punch.punch_random_port_min, 1024);
        assert_eq!(d.hole_punch.punch_random_port_max, 65535);
    }

    #[test]
    fn clamp_congestion_rate_knobs() {
        let mut t = AdvancedTuning::default();
        t.congestion.gain = 0.01;
        t.congestion.min_decrease_factor = 0.01;
        t.congestion.hol_escape_ms = 1;
        t.congestion.initial_rate_bps = 100.0;
        t.congestion.delivery_rate_window_ms = 10;
        t.congestion.delivery_rate_ewma_alpha = 0.01;
        t.congestion.delivery_anchor_factor = 0.1;
        t.congestion.delivery_decouple_ratio = 1.0;
        t.clamp();
        assert_eq!(t.congestion.gain, 0.1);
        assert_eq!(t.congestion.min_decrease_factor, 0.1);
        assert_eq!(t.congestion.hol_escape_ms, 4);
        assert!(t.congestion.initial_rate_bps >= t.congestion.min_rate_bps);
        assert_eq!(t.congestion.delivery_rate_window_ms, 100);
        assert_eq!(t.congestion.delivery_rate_ewma_alpha, 0.05);
        assert_eq!(t.congestion.delivery_anchor_factor, 0.5);
        assert_eq!(t.congestion.delivery_decouple_ratio, 1.05);

        t.congestion.gain = 9.0;
        t.congestion.hol_escape_ms = 200;
        t.congestion.delivery_rate_window_ms = 9_000;
        t.congestion.delivery_rate_ewma_alpha = 2.0;
        t.congestion.delivery_anchor_factor = 1.5;
        t.congestion.delivery_decouple_ratio = 9.0;
        t.clamp();
        assert_eq!(t.congestion.gain, 4.0);
        assert_eq!(t.congestion.hol_escape_ms, 100);
        assert_eq!(t.congestion.delivery_rate_window_ms, 5_000);
        assert_eq!(t.congestion.delivery_rate_ewma_alpha, 1.0);
        assert_eq!(t.congestion.delivery_anchor_factor, 0.99);
        assert_eq!(t.congestion.delivery_decouple_ratio, 3.0);
    }

    #[test]
    fn to_background_cc_config_maps_enabled_and_initial_rate() {
        let mut t = AdvancedTuning::default();
        t.congestion.enabled = true;
        t.congestion.min_rate_bps = 500_000.0;
        t.congestion.initial_rate_bps = 1_000_000.0;
        t.clamp();
        let cfg = t.congestion.to_background_cc_config();
        assert!(cfg.enabled);
        assert_eq!(cfg.initial_rate_bps, 1_000_000.0);
        assert_eq!(
            cfg.target_queue_delay_ms,
            t.congestion.target_queue_delay_ms
        );
        assert!(cfg.loss_classifier_enabled);
        assert_eq!(
            cfg.congestion_loss_threshold,
            t.congestion.congestion_loss_threshold
        );
        assert!(cfg.qd_telemetry_valid);
    }

    #[test]
    fn to_background_cc_config_maps_classifier_and_qd_validity() {
        let mut t = AdvancedTuning::default();
        t.congestion.loss_classifier_enabled = false;
        t.congestion.congestion_loss_threshold = 0.8;
        t.congestion.rtt_base_tracking = false;
        let cfg = t.congestion.to_background_cc_config();
        assert!(!cfg.loss_classifier_enabled);
        assert!((cfg.congestion_loss_threshold - 0.8).abs() < f64::EPSILON);
        assert!(!cfg.qd_telemetry_valid);
    }

    #[test]
    fn clamp_probe_interval_ms() {
        let mut t = AdvancedTuning::default();
        t.congestion.probe_interval_ms = 0;
        t.clamp();
        assert_eq!(t.congestion.probe_interval_ms, 0);

        t.congestion.probe_interval_ms = 1;
        t.clamp();
        assert_eq!(t.congestion.probe_interval_ms, 20);

        t.congestion.probe_interval_ms = 5000;
        t.clamp();
        assert_eq!(t.congestion.probe_interval_ms, 1000);

        t.congestion.probe_interval_ms = 100;
        t.clamp();
        assert_eq!(t.congestion.probe_interval_ms, 100);
    }

    #[test]
    fn clamp_fec_recovery_recency_ms() {
        let mut t = AdvancedTuning::default();
        t.congestion.fec_recovery_recency_ms = 0;
        t.clamp();
        assert_eq!(t.congestion.fec_recovery_recency_ms, 0);

        t.congestion.fec_recovery_recency_ms = 50;
        t.clamp();
        assert_eq!(t.congestion.fec_recovery_recency_ms, 100);

        t.congestion.fec_recovery_recency_ms = 120_000;
        t.clamp();
        assert_eq!(t.congestion.fec_recovery_recency_ms, 60_000);

        t.congestion.fec_recovery_recency_ms = 5_000;
        t.clamp();
        assert_eq!(t.congestion.fec_recovery_recency_ms, 5_000);
    }

    #[test]
    fn congestion_toml_round_trip() {
        let raw = r#"
[congestion]
rtt_base_tracking = false
loss_classifier_enabled = true
target_queue_delay_ms = 45
congestion_loss_threshold = 0.8
base_rtt_window_secs = 20
base_rtt_stale_windows = 5
owd_clock_jump_reject_ms = 45000
delivery_rate_window_ms = 250
delivery_rate_ewma_alpha = 0.4
delivery_anchor_factor = 0.85
delivery_decouple_ratio = 1.5
"#;
        #[derive(Deserialize)]
        struct Wrap {
            congestion: CongestionTuning,
        }
        let mut w: Wrap = toml::from_str(raw).expect("parse");
        w.congestion.target_queue_delay_ms = 999;
        w.congestion.base_rtt_window_secs = 0;
        let mut t = AdvancedTuning::default();
        t.congestion = w.congestion;
        t.clamp();
        assert_eq!(t.congestion.target_queue_delay_ms, 150);
        assert_eq!(t.congestion.base_rtt_window_secs, 1);
        assert_eq!(t.congestion.owd_clock_jump_reject_ms, 45_000);
        assert_eq!(t.congestion.delivery_rate_window_ms, 250);
        assert_eq!(t.congestion.delivery_rate_ewma_alpha, 0.4);
        assert_eq!(t.congestion.delivery_anchor_factor, 0.85);
        assert_eq!(t.congestion.delivery_decouple_ratio, 1.5);
    }

    #[test]
    fn serde_omit_equals_default() {
        let json = "{}";
        let parsed: AdvancedTuning = serde_json::from_str(json).unwrap();
        assert_eq!(parsed, AdvancedTuning::default());
    }

    #[test]
    fn serde_partial_uses_defaults_for_missing() {
        let json = r#"{"retries_left":3}"#;
        let parsed: AdvancedTuning = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.reliable.retries_left, 3);
        // Other reliable fields fall back to default.
        assert_eq!(parsed.reliable.rto_min_ms, 75);
        // Other groups fall back to default.
        assert_eq!(parsed.failover, FailoverTuning::default());
    }

    #[test]
    fn clamp_orders_stale_timers() {
        let mut t = AdvancedTuning::default();
        // Inverted: mark > evict should be repaired.
        t.timers.stale_tick_secs = 50;
        t.timers.stale_mark_secs = 40;
        t.timers.stale_evict_secs = 30;
        t.clamp();
        assert!(t.timers.stale_tick_secs < t.timers.stale_mark_secs);
        assert!(t.timers.stale_mark_secs < t.timers.stale_evict_secs);
    }

    #[test]
    fn clamp_rto_min_le_max() {
        let mut t = AdvancedTuning::default();
        t.reliable.rto_min_ms = 5000;
        t.reliable.rto_max_ms = 10;
        t.clamp();
        assert!(t.reliable.rto_min_ms <= t.reliable.rto_max_ms);
    }

    #[test]
    fn clamp_shard_payload_size_caps_at_wire_max() {
        let mut t = AdvancedTuning::default();
        t.fec.shard_payload_size = 5000;
        t.clamp();
        assert_eq!(
            t.fec.shard_payload_size,
            crate::net::fec::FEC_SHARD_PAYLOAD_SIZE
        );
        t.fec.shard_payload_size = 100;
        t.clamp();
        assert_eq!(t.fec.shard_payload_size, FEC_SHARD_PAYLOAD_MIN);
    }

    #[test]
    fn clamp_retries_left_caps() {
        let mut t = AdvancedTuning::default();
        t.reliable.retries_left = 99;
        t.clamp();
        assert_eq!(t.reliable.retries_left, 8);
    }

    #[test]
    fn clamp_adaptive_thresholds_ordered() {
        let mut t = AdvancedTuning::default();
        t.fec.adaptive_off_below = 0.4;
        t.fec.adaptive_on_above = 0.01;
        t.clamp();
        assert!(t.fec.adaptive_on_above >= t.fec.adaptive_off_below);
    }

    #[test]
    fn clamp_pmtud_knobs() {
        let mut t = AdvancedTuning::default();
        t.pmtud.probe_timeout_ms = 1;
        t.pmtud.confirm_count = 0;
        t.pmtud.resolve_epsilon = 99;
        t.pmtud.raise_step = 0;
        t.pmtud.max_probes_per_search = 1;
        t.pmtud.max_concurrent_peers = 0;
        t.clamp();
        assert_eq!(t.pmtud.probe_timeout_ms, 50);
        assert_eq!(t.pmtud.confirm_count, 1);
        assert_eq!(t.pmtud.resolve_epsilon, 8);
        assert_eq!(t.pmtud.raise_step, 1);
        assert_eq!(t.pmtud.max_probes_per_search, 8);
        assert_eq!(t.pmtud.max_concurrent_peers, 1);
    }

    #[test]
    fn clamp_failover_quality_ordering() {
        let mut t = AdvancedTuning::default();
        t.failover.d2r_quality_min = 80;
        t.failover.r2d_quality_min = 20;
        t.clamp();
        assert!(t.failover.r2d_quality_min >= t.failover.d2r_quality_min);
    }

    #[test]
    fn clamp_failover_jitter_max_non_negative() {
        let mut t = AdvancedTuning::default();
        t.failover.d2r_jitter_max = -10.0;
        t.clamp();
        assert!(t.failover.d2r_jitter_max >= 0.0);
    }

    #[test]
    fn clamp_routing_ewma_renormalizes_pairs() {
        let mut t = AdvancedTuning::default();
        t.routing_ewma.rtt_ewma_old = 2.0;
        t.routing_ewma.rtt_ewma_new = 2.0;
        t.routing_ewma.loss_ewma_decay = 0.1;
        t.clamp();
        assert!((t.routing_ewma.rtt_ewma_old - 0.5).abs() < 1e-9);
        assert!((t.routing_ewma.rtt_ewma_new - 0.5).abs() < 1e-9);
        assert_eq!(t.routing_ewma.loss_ewma_decay, 0.5);
    }

    #[test]
    fn clamp_engine_limits_and_fec_max_shards() {
        let mut t = AdvancedTuning::default();
        t.engine_limits.msyn_body_max = 10_000_000;
        t.engine_limits.msyn_shard_budget_bytes = 10_000;
        t.engine_limits.max_direct_retry_per_tick = 0;
        t.fec.fec_max_total_shards = 999;
        t.clamp();
        assert_eq!(t.engine_limits.msyn_body_max, 524_288);
        assert_eq!(t.engine_limits.msyn_shard_budget_bytes, 4096);
        assert_eq!(t.engine_limits.max_direct_retry_per_tick, 1);
        assert_eq!(
            t.fec.fec_max_total_shards,
            crate::net::fec::FEC_MAX_TOTAL_SHARDS
        );
    }

    #[test]
    fn clamp_hole_punch_width_and_ports() {
        let mut t = AdvancedTuning::default();
        t.hole_punch.punch_wide_min_width = 400;
        t.hole_punch.punch_wide_max_width = 100;
        t.hole_punch.punch_random_port_min = 5000;
        t.hole_punch.punch_random_port_max = 2000;
        t.clamp();
        assert!(t.hole_punch.punch_wide_max_width >= t.hole_punch.punch_wide_min_width);
        assert!(t.hole_punch.punch_random_port_min <= t.hole_punch.punch_random_port_max);
    }
}
