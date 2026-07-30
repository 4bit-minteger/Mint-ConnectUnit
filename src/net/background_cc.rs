//! Per-peer LEDBAT-style background congestion control (bytes/s) for the pacing engine.

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::routing::failover;

pub const DEFAULT_BURST_CAP_BYTES: u64 = 16_000;
pub const DEFAULT_GAIN: f64 = 0.35;
pub const DEFAULT_MIN_DECREASE_FACTOR: f64 = 0.85;
pub const DEFAULT_ADDITIVE_INCREASE_BPS: f64 = 48_000.0;
pub const DEFAULT_RATE_SMOOTHING_ALPHA: f64 = 0.8;
pub const DEFAULT_MIN_RATE_BPS: f64 = 1_500_000.0;
pub const DEFAULT_MAX_RATE_BPS: f64 = 20_000_000.0;
pub const DEFAULT_INITIAL_RATE_BPS: f64 = 8_000_000.0;
pub const DEFAULT_LOSS_MD: f64 = 0.85;
pub const DEFAULT_HOL_ESCAPE_MS: u32 = 5;
pub const DEFAULT_TARGET_QUEUE_DELAY_MS: u32 = 10;

/// Runtime copy of user tuning (from `CongestionTuning`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BackgroundCcConfig {
    pub enabled: bool,
    pub gain: f64,
    pub min_decrease_factor: f64,
    pub additive_increase_bps: f64,
    pub rate_smoothing_alpha: f64,
    pub initial_rate_bps: f64,
    pub min_rate_bps: f64,
    pub max_rate_bps: f64,
    pub loss_multiplicative_decrease: f64,
    pub burst_cap_bytes: f64,
    pub target_queue_delay_ms: u32,
    pub hol_escape_ms: u32,
}

impl Default for BackgroundCcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            gain: DEFAULT_GAIN,
            min_decrease_factor: DEFAULT_MIN_DECREASE_FACTOR,
            additive_increase_bps: DEFAULT_ADDITIVE_INCREASE_BPS,
            rate_smoothing_alpha: DEFAULT_RATE_SMOOTHING_ALPHA,
            initial_rate_bps: DEFAULT_INITIAL_RATE_BPS,
            min_rate_bps: DEFAULT_MIN_RATE_BPS,
            max_rate_bps: DEFAULT_MAX_RATE_BPS,
            loss_multiplicative_decrease: DEFAULT_LOSS_MD,
            burst_cap_bytes: DEFAULT_BURST_CAP_BYTES as f64,
            target_queue_delay_ms: DEFAULT_TARGET_QUEUE_DELAY_MS,
            hol_escape_ms: DEFAULT_HOL_ESCAPE_MS,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PeerCcState {
    pub rate_bps: f64,
    pub smoothed_rate_bps: f64,
    pub token_bytes: f64,
    pub last_loss_ewma: f64,
}

impl PeerCcState {
    fn new(initial_rate_bps: f64) -> Self {
        Self {
            rate_bps: initial_rate_bps,
            smoothed_rate_bps: initial_rate_bps,
            token_bytes: 0.0,
            last_loss_ewma: 0.0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CcUpdateCounters {
    pub increase_events: u64,
    pub decrease_events: u64,
    pub loss_decrease_events: u64,
}

pub struct BackgroundCcEngine {
    pub config: BackgroundCcConfig,
    peers: HashMap<SocketAddr, PeerCcState>,
    counters: CcUpdateCounters,
}

impl BackgroundCcEngine {
    pub fn new(config: BackgroundCcConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
            counters: CcUpdateCounters::default(),
        }
    }

    pub fn set_config(&mut self, config: BackgroundCcConfig) {
        self.config = config;
    }

    pub fn counters(&self) -> CcUpdateCounters {
        self.counters
    }

    pub fn reset_counters(&mut self) {
        self.counters = CcUpdateCounters::default();
    }

    pub fn take_counters(&mut self) -> CcUpdateCounters {
        let c = self.counters;
        self.counters = CcUpdateCounters::default();
        c
    }

    pub fn peer_rate_bps(&self, dest: SocketAddr) -> Option<f64> {
        self.peers.get(&dest).map(|p| p.smoothed_rate_bps)
    }

    pub fn rate_distribution(&self) -> (f64, f64, f64) {
        if self.peers.is_empty() {
            return (0.0, 0.0, 0.0);
        }
        let mut min = f64::MAX;
        let mut max = 0.0_f64;
        let mut sum = 0.0_f64;
        for p in self.peers.values() {
            let r = p.smoothed_rate_bps;
            min = min.min(r);
            max = max.max(r);
            sum += r;
        }
        let n = self.peers.len() as f64;
        (min, sum / n, max)
    }

    pub fn refill_all_tokens(&mut self, dt_secs: f64) {
        if !self.config.enabled || dt_secs <= 0.0 {
            return;
        }
        let cap = self.config.burst_cap_bytes;
        for st in self.peers.values_mut() {
            let rate = st.smoothed_rate_bps;
            st.token_bytes = (st.token_bytes + rate * dt_secs).min(cap);
        }
    }

    pub fn on_cc_sample(&mut self, dest: SocketAddr, qd_ms: f64, loss_ewma: f64) {
        if !self.config.enabled {
            return;
        }
        let initial = self.config.initial_rate_bps;
        let st = self
            .peers
            .entry(dest)
            .or_insert_with(|| PeerCcState::new(initial));
        apply_background_cc_rate_update(st, &self.config, qd_ms, loss_ewma, &mut self.counters);
    }

    pub fn can_send_data(&self, dest: SocketAddr, pkt_len: usize, hol_sojourn_ms: f32) -> bool {
        if !self.config.enabled {
            return true;
        }
        let Some(st) = self.peers.get(&dest) else {
            return true;
        };
        peer_can_send_bytes(st, &self.config, pkt_len, hol_sojourn_ms)
    }

    pub fn consume_send_bytes(&mut self, dest: SocketAddr, pkt_len: usize) {
        if !self.config.enabled {
            return;
        }
        if let Some(st) = self.peers.get_mut(&dest) {
            let len = pkt_len as f64;
            st.token_bytes = (st.token_bytes - len).max(0.0);
        }
    }

    pub fn ensure_peer(&mut self, dest: SocketAddr) {
        if !self.config.enabled {
            return;
        }
        let initial = self.config.initial_rate_bps;
        self.peers
            .entry(dest)
            .or_insert_with(|| PeerCcState::new(initial));
    }

    pub fn remove_peer(&mut self, dest: SocketAddr) {
        self.peers.remove(&dest);
    }

    #[cfg(test)]
    pub fn set_peer_tokens_for_test(&mut self, dest: SocketAddr, token_bytes: f64) {
        let initial = self.config.initial_rate_bps;
        self.peers
            .entry(dest)
            .or_insert_with(|| PeerCcState::new(initial));
        if let Some(st) = self.peers.get_mut(&dest) {
            st.token_bytes = token_bytes;
        }
    }
}

pub fn peer_can_send_bytes(
    st: &PeerCcState,
    cfg: &BackgroundCcConfig,
    pkt_len: usize,
    hol_sojourn_ms: f32,
) -> bool {
    if hol_sojourn_ms >= cfg.hol_escape_ms as f32 {
        return true;
    }
    let len = pkt_len as f64;
    if st.token_bytes >= len {
        return true;
    }
    if len > cfg.burst_cap_bytes && st.token_bytes > 0.0 {
        return true;
    }
    false
}

pub fn apply_background_cc_rate_update(
    st: &mut PeerCcState,
    cfg: &BackgroundCcConfig,
    qd_ms: f64,
    loss_ewma: f64,
    counters: &mut CcUpdateCounters,
) {
    let loss_edge =
        loss_ewma > failover::D2R_LOSS_MAX && st.last_loss_ewma <= failover::D2R_LOSS_MAX;
    st.last_loss_ewma = loss_ewma;

    if loss_edge {
        st.rate_bps = (st.rate_bps * cfg.loss_multiplicative_decrease).max(cfg.min_rate_bps);
        counters.loss_decrease_events = counters.loss_decrease_events.saturating_add(1);
    }

    if qd_ms >= 0.0 {
        let target = cfg.target_queue_delay_ms.max(1) as f64;
        let delay_ratio = qd_ms / target;
        if delay_ratio <= 1.0 {
            st.rate_bps += cfg.additive_increase_bps;
            counters.increase_events = counters.increase_events.saturating_add(1);
        } else {
            let raw = 1.0 - cfg.gain * (delay_ratio - 1.0);
            let decrease_factor = raw.clamp(cfg.min_decrease_factor, 1.0);
            st.rate_bps *= decrease_factor;
            counters.decrease_events = counters.decrease_events.saturating_add(1);
        }
    }

    st.rate_bps = st.rate_bps.clamp(cfg.min_rate_bps, cfg.max_rate_bps);
    let alpha = cfg.rate_smoothing_alpha.clamp(0.0, 0.95);
    st.smoothed_rate_bps = alpha * st.smoothed_rate_bps + (1.0 - alpha) * st.rate_bps;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg() -> BackgroundCcConfig {
        BackgroundCcConfig {
            enabled: true,
            target_queue_delay_ms: 20,
            min_rate_bps: 8_000.0,
            ..BackgroundCcConfig::default()
        }
    }

    #[test]
    fn additive_when_delay_below_target() {
        let mut st = PeerCcState::new(100_000.0);
        let cfg = test_cfg();
        let mut c = CcUpdateCounters::default();
        let before = st.rate_bps;
        apply_background_cc_rate_update(&mut st, &cfg, 10.0, 0.0, &mut c);
        assert!(st.rate_bps > before);
        assert_eq!(c.increase_events, 1);
    }

    #[test]
    fn multiplicative_decrease_when_delay_above_target() {
        let mut st = PeerCcState::new(100_000.0);
        let cfg = test_cfg();
        let mut c = CcUpdateCounters::default();
        let before = st.rate_bps;
        apply_background_cc_rate_update(&mut st, &cfg, 40.0, 0.0, &mut c);
        assert!(st.rate_bps < before);
        assert_eq!(c.decrease_events, 1);
    }

    #[test]
    fn loss_edge_triggers_multiplicative_decrease() {
        let mut st = PeerCcState::new(200_000.0);
        st.last_loss_ewma = 0.05;
        let cfg = test_cfg();
        let mut c = CcUpdateCounters::default();
        apply_background_cc_rate_update(&mut st, &cfg, -1.0, 0.15, &mut c);
        assert!(st.rate_bps < 200_000.0);
        assert_eq!(c.loss_decrease_events, 1);
    }

    #[test]
    fn hol_escape_allows_send_without_tokens() {
        let st = PeerCcState {
            token_bytes: 0.0,
            ..PeerCcState::new(100_000.0)
        };
        let cfg = test_cfg();
        let escape = cfg.hol_escape_ms as f32;
        assert!(peer_can_send_bytes(&st, &cfg, 1400, escape));
        assert!(peer_can_send_bytes(&st, &cfg, 1400, escape + 1.0));
        assert!(!peer_can_send_bytes(
            &st,
            &cfg,
            1400,
            (escape - 1.0).max(0.0)
        ));
    }
}
