use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct EngineMetrics {
    pub pacing_dropped_packets: AtomicU64,
    pub pacing_tick_skip_count: AtomicU64,
    pub pacing_overshoot_count: AtomicU64,
    pub pacing_adaptive_fallback_count: AtomicU64,
    pub timer_resolution_requested_us: AtomicU64,
    pub timer_resolution_applied_us: AtomicU64,
    pub timer_resolution_fallback_count: AtomicU64,
    pub relay_fallback_events: AtomicU64,
    pub relay_drop_no_hop: AtomicU64,
    pub relay_fallback_direct_no_hop: AtomicU64,
    pub relay_send_owner_events: AtomicU64,
    pub relay_send_hop_events: AtomicU64,
    pub auth_failures: AtomicU64,
    pub tun_inject_drops: AtomicU64,
    pub tun_inject_lagged: AtomicU64,
    pub tun_inject_wrong_dst_drops: AtomicU64,
    pub para_notify_drops: AtomicU64,
    pub fec_oversize_bypass_count: AtomicU64,
    pub fec_mtu_bypass_count: AtomicU64,
    pub fec_drain_passthrough_count: AtomicU64,
    pub fec_group_invalid_count: AtomicU64,
    pub fec_flush_sparse_passthrough_count: AtomicU64,
    pub fec_encoded_shards_total: AtomicU64,
    pub fec_recovered_packets_total: AtomicU64,
    pub fec_decode_fail_count: AtomicU64,
    pub pacing_drop_data_fec: AtomicU64,
    pub pacing_drop_data_normal: AtomicU64,
    pub pacing_shed_sojourn: AtomicU64,
    pub pacing_cmd_channel_full: AtomicU64,
    pub pacing_drop_control: AtomicU64,
    pub rawperf_send_error_count: AtomicU64,
    pub retransmit_direct_count: AtomicU64,
    pub retransmit_fallback_count: AtomicU64,
    pub transition_dedup_drops: AtomicU64,
    pub control_decode_errors: AtomicU64,
    pub heal_spawned: AtomicU64,
    pub heal_succeeded: AtomicU64,
    pub unauth_drop_crypto_gate: AtomicU64,
    pub unauth_drop_plain_data_crypto: AtomicU64,
    pub pacing_tick_duration_us: AtomicU64,
    pub pacing_tick_sent_packets: AtomicU64,
    pub pacing_drop_control_normal: AtomicU64,
    pub pacing_drop_control_retransmit: AtomicU64,
    pub fec_ratio_flush_count: AtomicU64,
    pub fec_decoder_groups_hwm: AtomicU64,
    pub heal_cooldown_blocked: AtomicU64,
    pub control_path_race_extra: AtomicU64,
    pub route_hijack_reject_count: AtomicU64,
    pub stale_to_candidate_promotions: AtomicU64,
    pub reliable_unknown_inner_tag: AtomicU64,
    pub owner_forward_unknown_dst: AtomicU64,
    pub peer_forward_unknown_dst: AtomicU64,
    // ── APD metrics ──────────────────────────────────────────────────────────
    pub apd_drain_episodes: AtomicU64,
    pub apd_drain_ms_total: AtomicU64,
    pub apd_packets_drained: AtomicU64,
    pub apd_drain_budget_hits: AtomicU64,
    pub apd_ramp_active_ticks: AtomicU64,
    pub apd_ramp_pinned_ticks: AtomicU64,
    pub apd_last_effective_burst: AtomicU64,
    pub apd_drain_arm_fill: AtomicU64,
    pub apd_drain_arm_sojourn: AtomicU64,
    pub apd_last_max_sojourn_ms: AtomicU64,
    pub apd_cc_headroom_suppressions: AtomicU64,
    pub fec_congestive_hold_count: AtomicU64,
    pub fec_classifier_allow_count: AtomicU64,
    pub fec_recovery_stepdown_count: AtomicU64,
    pub cc_rate_limited_events: AtomicU64,
    pub cc_rate_bps_min: AtomicU64,
    pub cc_rate_bps_avg: AtomicU64,
    pub cc_rate_bps_max: AtomicU64,
    pub cc_increase_events_total: AtomicU64,
    pub cc_decrease_events_total: AtomicU64,
    pub cc_loss_decrease_events_total: AtomicU64,
    pub drr_small_priority_pops: AtomicU64,
    pub drr_bulk_force_pops: AtomicU64,
    pub drr_rtt_scale_applied: AtomicU64,
}

impl EngineMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_relay_fallback(&self, n: u64) {
        self.relay_fallback_events.fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_relay_drop_no_hop(&self) {
        self.relay_drop_no_hop.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_relay_fallback_direct_no_hop(&self) {
        self.relay_fallback_direct_no_hop
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_relay_send_owner(&self) {
        self.relay_send_owner_events.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_relay_send_hop(&self) {
        self.relay_send_hop_events.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_auth_failures(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tun_inject_drops(&self) {
        self.tun_inject_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tun_inject_lagged(&self, n: u64) {
        self.tun_inject_lagged.fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_tun_inject_wrong_dst_drops(&self) {
        self.tun_inject_wrong_dst_drops
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_para_notify_drops(&self) {
        self.para_notify_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_fec_oversize_bypass(&self) {
        self.fec_oversize_bypass_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_fec_mtu_bypass(&self) {
        self.fec_mtu_bypass_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_fec_drain_passthrough(&self, n: u64) {
        self.fec_drain_passthrough_count
            .fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_fec_group_invalid(&self) {
        self.fec_group_invalid_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_fec_flush_sparse_passthrough(&self, n: u64) {
        self.fec_flush_sparse_passthrough_count
            .fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_fec_encoded_shards(&self, n: u64) {
        self.fec_encoded_shards_total
            .fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_fec_recovered_packets(&self, n: u64) {
        self.fec_recovered_packets_total
            .fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_fec_decode_failures(&self) {
        self.fec_decode_fail_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_pacing_drop_data_fec(&self) {
        self.pacing_drop_data_fec.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_pacing_drop_data_normal(&self) {
        self.pacing_drop_data_normal.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_pacing_cmd_channel_full(&self) {
        self.pacing_cmd_channel_full.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_pacing_drop_data_normal(&self, v: u64) {
        self.pacing_drop_data_normal.store(v, Ordering::Relaxed);
    }

    pub fn set_pacing_shed_sojourn(&self, v: u64) {
        self.pacing_shed_sojourn.store(v, Ordering::Relaxed);
    }

    pub fn set_pacing_drop_control_normal(&self, v: u64) {
        self.pacing_drop_control_normal.store(v, Ordering::Relaxed);
    }

    pub fn set_pacing_drop_control_retransmit(&self, v: u64) {
        self.pacing_drop_control_retransmit
            .store(v, Ordering::Relaxed);
    }

    pub fn inc_pacing_drop_control(&self) {
        self.pacing_drop_control.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rawperf_send_errors(&self) {
        self.rawperf_send_error_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_retransmit_counts(&self, direct: u64, fallback: u64) {
        self.retransmit_direct_count
            .store(direct, Ordering::Relaxed);
        self.retransmit_fallback_count
            .store(fallback, Ordering::Relaxed);
    }

    pub fn inc_transition_dedup_drops(&self) {
        self.transition_dedup_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_control_decode_errors(&self) {
        self.control_decode_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_heal_spawned(&self) {
        self.heal_spawned.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_heal_succeeded(&self) {
        self.heal_succeeded.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_unauth_drop_crypto_gate(&self) {
        self.unauth_drop_crypto_gate.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_unauth_drop_plain_data_crypto(&self) {
        self.unauth_drop_plain_data_crypto
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_pacing_tick_observed(&self, duration_us: u64, sent_packets: u64) {
        self.pacing_tick_duration_us
            .store(duration_us, Ordering::Relaxed);
        self.pacing_tick_sent_packets
            .store(sent_packets, Ordering::Relaxed);
    }

    pub fn inc_pacing_drop_control_normal(&self) {
        self.pacing_drop_control_normal
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_pacing_drop_control_retransmit(&self) {
        self.pacing_drop_control_retransmit
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_reliable_unknown_inner_tag(&self) {
        self.reliable_unknown_inner_tag
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_owner_forward_unknown_dst(&self) {
        self.owner_forward_unknown_dst
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_peer_forward_unknown_dst(&self) {
        self.peer_forward_unknown_dst
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_fec_ratio_flush(&self) {
        self.fec_ratio_flush_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_fec_decoder_groups_hwm(&self, v: u64) {
        self.fec_decoder_groups_hwm.store(v, Ordering::Relaxed);
    }

    pub fn inc_heal_cooldown_blocked(&self) {
        self.heal_cooldown_blocked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_control_path_race_extra(&self, n: u64) {
        if n > 0 {
            self.control_path_race_extra.fetch_add(n, Ordering::Relaxed);
        }
    }

    pub fn inc_route_hijack_reject(&self) {
        self.route_hijack_reject_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_stale_to_candidate_promotions(&self) {
        self.stale_to_candidate_promotions
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_pacing_dropped(&self, v: u64) {
        self.pacing_dropped_packets.store(v, Ordering::Relaxed);
    }

    pub fn set_pacing_tick_skips(&self, v: u64) {
        self.pacing_tick_skip_count.store(v, Ordering::Relaxed);
    }

    pub fn set_pacing_overshoots(&self, v: u64) {
        self.pacing_overshoot_count.store(v, Ordering::Relaxed);
    }

    pub fn set_pacing_adaptive_fallback_count(&self, v: u64) {
        self.pacing_adaptive_fallback_count
            .store(v, Ordering::Relaxed);
    }

    pub fn set_timer_resolution(&self, requested_us: u64, applied_us: u64, fallback_count: u64) {
        self.timer_resolution_requested_us
            .store(requested_us, Ordering::Relaxed);
        self.timer_resolution_applied_us
            .store(applied_us, Ordering::Relaxed);
        self.timer_resolution_fallback_count
            .store(fallback_count, Ordering::Relaxed);
    }

    pub fn set_apd_metrics(
        &self,
        drain_episodes: u64,
        drain_ms_total: u64,
        packets_drained: u64,
        drain_budget_hits: u64,
    ) {
        self.apd_drain_episodes
            .store(drain_episodes, Ordering::Relaxed);
        self.apd_drain_ms_total
            .store(drain_ms_total, Ordering::Relaxed);
        self.apd_packets_drained
            .store(packets_drained, Ordering::Relaxed);
        self.apd_drain_budget_hits
            .store(drain_budget_hits, Ordering::Relaxed);
    }

    pub fn set_apd_ramp_observability(
        &self,
        ramp_active_ticks: u64,
        ramp_pinned_ticks: u64,
        last_effective_burst: u64,
    ) {
        self.apd_ramp_active_ticks
            .store(ramp_active_ticks, Ordering::Relaxed);
        self.apd_ramp_pinned_ticks
            .store(ramp_pinned_ticks, Ordering::Relaxed);
        self.apd_last_effective_burst
            .store(last_effective_burst, Ordering::Relaxed);
    }

    pub fn set_apd_sojourn_observability(
        &self,
        drain_arm_fill: u64,
        drain_arm_sojourn: u64,
        last_max_sojourn_ms: u64,
    ) {
        self.apd_drain_arm_fill
            .store(drain_arm_fill, Ordering::Relaxed);
        self.apd_drain_arm_sojourn
            .store(drain_arm_sojourn, Ordering::Relaxed);
        self.apd_last_max_sojourn_ms
            .store(last_max_sojourn_ms, Ordering::Relaxed);
    }

    pub fn set_apd_cc_headroom_suppressions(&self, n: u64) {
        self.apd_cc_headroom_suppressions
            .store(n, Ordering::Relaxed);
    }

    pub fn inc_fec_congestive_hold(&self) {
        self.fec_congestive_hold_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_fec_classifier_allow(&self) {
        self.fec_classifier_allow_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_fec_recovery_stepdown(&self) {
        self.fec_recovery_stepdown_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_cc_rate_limited_events(&self, n: u64) {
        self.cc_rate_limited_events.store(n, Ordering::Relaxed);
    }

    pub fn set_background_cc_rates(&self, min_bps: f64, avg_bps: f64, max_bps: f64) {
        self.cc_rate_bps_min
            .store(min_bps.round() as u64, Ordering::Relaxed);
        self.cc_rate_bps_avg
            .store(avg_bps.round() as u64, Ordering::Relaxed);
        self.cc_rate_bps_max
            .store(max_bps.round() as u64, Ordering::Relaxed);
    }

    pub fn set_cc_event_counters(&self, increase: u64, decrease: u64, loss_decrease: u64) {
        self.cc_increase_events_total
            .store(increase, Ordering::Relaxed);
        self.cc_decrease_events_total
            .store(decrease, Ordering::Relaxed);
        self.cc_loss_decrease_events_total
            .store(loss_decrease, Ordering::Relaxed);
    }

    pub fn set_drr_small_priority_pops(&self, n: u64) {
        self.drr_small_priority_pops.store(n, Ordering::Relaxed);
    }

    pub fn set_drr_bulk_force_pops(&self, n: u64) {
        self.drr_bulk_force_pops.store(n, Ordering::Relaxed);
    }

    pub fn set_drr_rtt_scale_applied(&self, n: u64) {
        self.drr_rtt_scale_applied.store(n, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drr_observability_setters_store_absolute_counts() {
        let m = EngineMetrics::new();
        m.set_drr_small_priority_pops(3);
        m.set_drr_bulk_force_pops(2);
        m.set_drr_rtt_scale_applied(7);
        assert_eq!(m.drr_small_priority_pops.load(Ordering::Relaxed), 3);
        assert_eq!(m.drr_bulk_force_pops.load(Ordering::Relaxed), 2);
        assert_eq!(m.drr_rtt_scale_applied.load(Ordering::Relaxed), 7);
    }
}
