//! Single source of truth for pacing / APD defaults and effective-value fallbacks.

pub const DEFAULT_PACE_TICK_US: i64 = 300;
pub const DEFAULT_PACE_TARGET_PPS: i64 = 8_000;
pub const DEFAULT_PACE_BURST_PER_TICK: i64 = 2;
pub const DEFAULT_PACE_BUDGET_PACKETS: f64 = 32.0;
pub const DEFAULT_PACE_MAX_QUEUE: i64 = 192;

pub const DEFAULT_PACE_SPIN_WINDOW_US: i64 = 50;
pub const DEFAULT_PACE_FAB_ENABLED: bool = true;
pub const DEFAULT_PACE_FAB_FALLBACK_TICK_US: i64 = 500;

pub const DEFAULT_MAX_TICK_WORK_US: u64 = 150;

pub const PACE_TICK_US_MAX: u64 = 1_000_000;
pub const PACE_TARGET_PPS_MIN: u64 = 100;
pub const PACE_TARGET_PPS_MAX: u64 = 200_000;
pub const PACE_BURST_PER_TICK_MIN: u64 = 1;
pub const PACE_BURST_PER_TICK_MAX: u64 = 1024;
pub const PACE_BUDGET_PACKETS_MIN: f64 = 1.0;
pub const PACE_BUDGET_PACKETS_MAX: f64 = 4096.0;
pub const PACE_MAX_QUEUE_MIN: usize = 1;
pub const PACE_MAX_QUEUE_MAX: usize = 8192;

pub const DEFAULT_TUN_INJECT_QUEUE: i64 = 512;
pub const DEFAULT_TUN_FROM_ADAPTER_QUEUE: i64 = 256;

pub const DEFAULT_APD_ENABLED: bool = true;
pub const DEFAULT_APD_HIGH_WM: f32 = 0.40;
pub const DEFAULT_APD_LOW_WM: f32 = 0.10;
/// Absolute burst ceiling for Tier-1 ramp (not “extra” packets).
pub const DEFAULT_RAMP_MAX_BURST: u64 = 6;
/// Max packets/tick during Tier-2 drain (pure-spin); independent of ramp ceiling.
pub const DEFAULT_DRAIN_MAX_BURST: u64 = 3;
pub const DEFAULT_APD_SPINLOOP_BUDGET_MS: u32 = 3;
pub const DEFAULT_APD_DRAIN_TICK_US: u64 = 100;
pub const DEFAULT_APD_CONFIRM_TICKS: u32 = 4;
pub const DEFAULT_APD_COOLDOWN_MS: u32 = 2;
pub const DEFAULT_APD_DRAIN_FREEZE_DRR: bool = true;
pub const DEFAULT_APD_SOJOURN_ENABLED: bool = true;
pub const DEFAULT_APD_MAX_SOJOURN_MS: u32 = 10;
pub const DEFAULT_APD_TARGET_SOJOURN_MS: u32 = 2;
/// When CC is on, suppress APD ramp-up / Drain arm / mid-Drain spin unless a data peer is CC-sendable.
pub const DEFAULT_APD_REQUIRE_CC_HEADROOM: bool = true;
pub const DEFAULT_SHED_ENABLED: bool = true;
pub const DEFAULT_SHED_MAX_SOJOURN_MS: u32 = 30;
pub const DEFAULT_SHED_MIN_FILL: f32 = 0.3;
pub const DEFAULT_SHED_MAX_PER_TICK: u32 = 1;
pub const DEFAULT_MIN_CONTROL_RESERVED_BYTES_PER_TICK: u32 = 256;
pub const DEFAULT_MIN_RETRANSMIT_RESERVED_BYTES_PER_TICK: u32 = 256;
pub const DEFAULT_DRR_SMALL_PACKET_PRIORITY: bool = true;
pub const DEFAULT_DRR_SMALL_PACKET_THRESHOLD_BYTES: u32 = 384;
pub const DEFAULT_DRR_RTT_AWARE: bool = true;
pub const DEFAULT_DRR_RTT_SCALE_MIN: f64 = 0.5;
pub const DEFAULT_DRR_RTT_SCALE_MAX: f64 = 2.5;
pub const DRR_RTT_SCALE_MIN_LO: f64 = 0.1;
pub const DRR_RTT_SCALE_MIN_HI: f64 = 1.0;
pub const DRR_RTT_SCALE_MAX_LO: f64 = 1.0;
pub const DRR_RTT_SCALE_MAX_HI: f64 = 4.0;
pub const DRR_SMALL_PACKET_THRESHOLD_MIN: usize = 64;
pub const DRR_SMALL_PACKET_THRESHOLD_MAX: usize = 512;
/// Consecutive small-lane pops before forcing one bulk packet (per peer).
pub const DRR_SMALL_BULK_FORCE_AFTER: u8 = 8;
/// Bulk HOL age (ms) that forces a bulk pop ahead of small lane.
pub const DRR_BULK_HOL_FORCE_MS: u32 = 8;
pub const PACE_RESERVED_BYTES_PER_TICK_MAX: u32 = 8192;
pub const APD_SOJOURN_MS_MIN: u32 = 2;
pub const APD_SOJOURN_MS_MAX: u32 = 500;
pub const APD_TARGET_SOJOURN_MS_MIN: u32 = 1;
pub const APD_TARGET_SOJOURN_MS_MAX: u32 = 200;
pub const APD_SOJOURN_TARGET_MAX_GAP_MS: u32 = 2;
pub const SHED_SOJOURN_MS_MIN: u32 = 2;
pub const SHED_SOJOURN_MS_MAX: u32 = 500;
pub const SHED_MIN_FILL_LO: f32 = 0.1;
pub const SHED_MIN_FILL_HI: f32 = 0.95;
pub const SHED_MAX_PER_TICK_MIN: u32 = 1;
pub const SHED_MAX_PER_TICK_MAX: u32 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaceRateMode {
    Pps,
    Bytes,
}

impl PaceRateMode {
    pub fn from_config_str(s: &str) -> Self {
        if s.eq_ignore_ascii_case("bytes") {
            Self::Bytes
        } else {
            Self::Pps
        }
    }
}

#[inline]
pub fn effective_pace_tick_us(v: i64) -> u64 {
    let value = if v > 0 {
        v as u64
    } else {
        DEFAULT_PACE_TICK_US as u64
    };
    value
        .min(PACE_TICK_US_MAX)
        .max(crate::net::pace_clock::MIN_PACE_TICK_US)
}

#[inline]
pub fn effective_pace_target_pps(v: i64) -> u64 {
    let value = if v > 0 {
        v as u64
    } else {
        DEFAULT_PACE_TARGET_PPS as u64
    };
    value.clamp(PACE_TARGET_PPS_MIN, PACE_TARGET_PPS_MAX)
}

#[inline]
pub fn effective_pace_target_bps(v: i64, pace_target_pps: i64) -> u64 {
    if v > 0 {
        return v as u64;
    }
    effective_pace_target_pps(pace_target_pps).saturating_mul(1300)
}

#[inline]
pub fn effective_pace_rate_mode(s: &str) -> PaceRateMode {
    PaceRateMode::from_config_str(s)
}

#[inline]
pub fn effective_base_max_burst(v: i64) -> u64 {
    let value = if v > 0 {
        v as u64
    } else {
        DEFAULT_PACE_BURST_PER_TICK as u64
    };
    value.clamp(PACE_BURST_PER_TICK_MIN, PACE_BURST_PER_TICK_MAX)
}

#[inline]
pub fn effective_pace_budget_cap_packets(v: f64) -> f64 {
    let value = if v > 0.0 {
        v
    } else {
        DEFAULT_PACE_BUDGET_PACKETS
    };
    value.clamp(PACE_BUDGET_PACKETS_MIN, PACE_BUDGET_PACKETS_MAX)
}

#[inline]
pub fn effective_pace_max_queue_packets(v: i64) -> usize {
    let value = if v > 0 {
        v as usize
    } else {
        DEFAULT_PACE_MAX_QUEUE as usize
    };
    value.clamp(PACE_MAX_QUEUE_MIN, PACE_MAX_QUEUE_MAX)
}

#[inline]
pub fn effective_tun_inject_queue_packets(v: i64) -> usize {
    let value = if v > 0 {
        v as usize
    } else {
        DEFAULT_TUN_INJECT_QUEUE as usize
    };
    value.clamp(1, 8192)
}

#[inline]
pub fn effective_tun_from_adapter_queue_packets(v: i64) -> usize {
    let value = if v > 0 {
        v as usize
    } else {
        DEFAULT_TUN_FROM_ADAPTER_QUEUE as usize
    };
    value.clamp(1, 8192)
}

/// Per-tick reserved byte budget for control/retransmit prefix drain (`0` = disabled).
#[inline]
pub fn effective_reserved_bytes_per_tick(v: u32) -> usize {
    (v as usize).min(PACE_RESERVED_BYTES_PER_TICK_MAX as usize)
}

#[inline]
pub fn effective_drr_small_packet_threshold_bytes(v: u32) -> usize {
    let value = if v == 0 {
        DEFAULT_DRR_SMALL_PACKET_THRESHOLD_BYTES as usize
    } else {
        v as usize
    };
    value.clamp(
        DRR_SMALL_PACKET_THRESHOLD_MIN,
        DRR_SMALL_PACKET_THRESHOLD_MAX,
    )
}

#[inline]
pub fn effective_drr_rtt_scale_min(v: f64) -> f32 {
    let value = if v.is_finite() && v > 0.0 {
        v
    } else {
        DEFAULT_DRR_RTT_SCALE_MIN
    };
    value.clamp(DRR_RTT_SCALE_MIN_LO, DRR_RTT_SCALE_MIN_HI) as f32
}

#[inline]
pub fn effective_drr_rtt_scale_max(v: f64) -> f32 {
    let value = if v.is_finite() && v > 0.0 {
        v
    } else {
        DEFAULT_DRR_RTT_SCALE_MAX
    };
    value.clamp(DRR_RTT_SCALE_MAX_LO, DRR_RTT_SCALE_MAX_HI) as f32
}

#[inline]
pub fn effective_shed_max_sojourn_ms(v: u32) -> u32 {
    if v == 0 {
        DEFAULT_SHED_MAX_SOJOURN_MS
    } else {
        v.clamp(SHED_SOJOURN_MS_MIN, SHED_SOJOURN_MS_MAX)
    }
}

#[inline]
pub fn effective_shed_min_fill(v: f32) -> f32 {
    if v.is_finite() {
        v.clamp(SHED_MIN_FILL_LO, SHED_MIN_FILL_HI)
    } else {
        DEFAULT_SHED_MIN_FILL
    }
}

#[inline]
pub fn effective_shed_max_per_tick(v: u32) -> u32 {
    if v == 0 {
        DEFAULT_SHED_MAX_PER_TICK
    } else {
        v.clamp(SHED_MAX_PER_TICK_MIN, SHED_MAX_PER_TICK_MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_pace_apd_defaults_match_low_latency_profile() {
        assert_eq!(DEFAULT_PACE_TICK_US, 300);
        assert_eq!(DEFAULT_PACE_TARGET_PPS, 8_000);
        assert_eq!(DEFAULT_PACE_BURST_PER_TICK, 2);
        assert_eq!(DEFAULT_PACE_BUDGET_PACKETS, 32.0);
        assert_eq!(DEFAULT_PACE_MAX_QUEUE, 192);
        assert_eq!(DEFAULT_TUN_INJECT_QUEUE, 512);
        assert_eq!(DEFAULT_TUN_FROM_ADAPTER_QUEUE, 256);
        assert_eq!(DEFAULT_PACE_FAB_ENABLED, true);
        assert_eq!(DEFAULT_PACE_FAB_FALLBACK_TICK_US, 500);
        assert_eq!(DEFAULT_APD_HIGH_WM, 0.40);
        assert_eq!(DEFAULT_APD_CONFIRM_TICKS, 4);
        assert_eq!(DEFAULT_APD_DRAIN_TICK_US, 100);
        assert_eq!(DEFAULT_APD_SPINLOOP_BUDGET_MS, 3);
        assert_eq!(DEFAULT_RAMP_MAX_BURST, 6);
        assert_eq!(DEFAULT_DRAIN_MAX_BURST, 3);
        assert_eq!(DEFAULT_APD_MAX_SOJOURN_MS, 10);
        assert_eq!(DEFAULT_APD_TARGET_SOJOURN_MS, 2);
        assert!(DEFAULT_APD_REQUIRE_CC_HEADROOM);
        assert!(DEFAULT_SHED_ENABLED);
        assert_eq!(DEFAULT_SHED_MAX_SOJOURN_MS, 30);
        assert!((DEFAULT_SHED_MIN_FILL - 0.3).abs() < f32::EPSILON);
        assert_eq!(DEFAULT_SHED_MAX_PER_TICK, 1);
        assert_eq!(DEFAULT_DRR_SMALL_PACKET_THRESHOLD_BYTES, 384);
        assert_eq!(DEFAULT_MIN_CONTROL_RESERVED_BYTES_PER_TICK, 256);
        assert_eq!(DEFAULT_MIN_RETRANSMIT_RESERVED_BYTES_PER_TICK, 256);
        assert_eq!(DEFAULT_DRR_RTT_SCALE_MAX, 2.5);
        // base < ramp ceiling (interactive UX invariant)
        assert!(DEFAULT_PACE_BURST_PER_TICK < DEFAULT_RAMP_MAX_BURST as i64);
        // target sojourn must stay below max − gap
        assert!(
            DEFAULT_APD_TARGET_SOJOURN_MS + APD_SOJOURN_TARGET_MAX_GAP_MS
                < DEFAULT_APD_MAX_SOJOURN_MS
        );
    }
}
