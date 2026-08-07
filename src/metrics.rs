use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub struct EngineMetrics {
    enabled: AtomicBool,
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
    pub relay_send_hop_events: AtomicU64,
    pub auth_failures: AtomicU64,
    pub tun_inject_drops: AtomicU64,
    pub tun_inject_lagged: AtomicU64,
    pub tun_inject_wrong_dst_drops: AtomicU64,
    pub para_notify_drops: AtomicU64,
    pub fec_oversize_bypass_count: AtomicU64,
    pub fec_mtu_bypass_count: AtomicU64,
    pub pmtud_tx_oversize_drop: AtomicU64,
    pub pmtud_revalidate_hints: AtomicU64,
    pub pmtud_probes_sent: AtomicU64,
    pub pmtud_probe_acks: AtomicU64,
    pub pmtud_pmar_ignored: AtomicU64,
    pub pmtud_probe_timeouts: AtomicU64,
    pub pmtud_revalidate_fail_events: AtomicU64,
    pub pmtud_recheck_recovered_events: AtomicU64,
    pub pmtud_softdown_events: AtomicU64,
    pub pmtud_probe_anomaly_events: AtomicU64,
    pub pmtud_late_ack_events: AtomicU64,
    pub pmtud_early_wake_events: AtomicU64,
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
    pub fec_tx_cmd_channel_full: AtomicU64,
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
    pub hub_forward_unknown_dst: AtomicU64,
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
    pub cc_delivery_bps_min: AtomicU64,
    pub cc_delivery_bps_avg: AtomicU64,
    pub cc_delivery_bps_max: AtomicU64,
    pub cc_increase_events_total: AtomicU64,
    pub cc_decrease_events_total: AtomicU64,
    pub cc_loss_decrease_events_total: AtomicU64,
    pub cc_delivery_anchor_events_total: AtomicU64,
    pub cc_loss_ignored_random_events_total: AtomicU64,
    pub owd_samples_applied_total: AtomicU64,
    pub owd_samples_rejected_total: AtomicU64,
    pub drr_small_priority_pops: AtomicU64,
    pub drr_bulk_force_pops: AtomicU64,
    pub drr_rtt_scale_applied: AtomicU64,
    pub outbound_note_total: AtomicU64,
    pub outbound_note_poison_recover_total: AtomicU64,
    pub keepalive_sent_total: AtomicU64,
    pub keepalive_suppressed_total: AtomicU64,
}

impl Default for EngineMetrics {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            pacing_dropped_packets: AtomicU64::new(0),
            pacing_tick_skip_count: AtomicU64::new(0),
            pacing_overshoot_count: AtomicU64::new(0),
            pacing_adaptive_fallback_count: AtomicU64::new(0),
            timer_resolution_requested_us: AtomicU64::new(0),
            timer_resolution_applied_us: AtomicU64::new(0),
            timer_resolution_fallback_count: AtomicU64::new(0),
            relay_fallback_events: AtomicU64::new(0),
            relay_drop_no_hop: AtomicU64::new(0),
            relay_fallback_direct_no_hop: AtomicU64::new(0),
            relay_send_hop_events: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
            tun_inject_drops: AtomicU64::new(0),
            tun_inject_lagged: AtomicU64::new(0),
            tun_inject_wrong_dst_drops: AtomicU64::new(0),
            para_notify_drops: AtomicU64::new(0),
            fec_oversize_bypass_count: AtomicU64::new(0),
            fec_mtu_bypass_count: AtomicU64::new(0),
            pmtud_tx_oversize_drop: AtomicU64::new(0),
            pmtud_revalidate_hints: AtomicU64::new(0),
            pmtud_probes_sent: AtomicU64::new(0),
            pmtud_probe_acks: AtomicU64::new(0),
            pmtud_pmar_ignored: AtomicU64::new(0),
            pmtud_probe_timeouts: AtomicU64::new(0),
            pmtud_revalidate_fail_events: AtomicU64::new(0),
            pmtud_recheck_recovered_events: AtomicU64::new(0),
            pmtud_softdown_events: AtomicU64::new(0),
            pmtud_probe_anomaly_events: AtomicU64::new(0),
            pmtud_late_ack_events: AtomicU64::new(0),
            pmtud_early_wake_events: AtomicU64::new(0),
            fec_drain_passthrough_count: AtomicU64::new(0),
            fec_group_invalid_count: AtomicU64::new(0),
            fec_flush_sparse_passthrough_count: AtomicU64::new(0),
            fec_encoded_shards_total: AtomicU64::new(0),
            fec_recovered_packets_total: AtomicU64::new(0),
            fec_decode_fail_count: AtomicU64::new(0),
            pacing_drop_data_fec: AtomicU64::new(0),
            pacing_drop_data_normal: AtomicU64::new(0),
            pacing_shed_sojourn: AtomicU64::new(0),
            pacing_cmd_channel_full: AtomicU64::new(0),
            fec_tx_cmd_channel_full: AtomicU64::new(0),
            pacing_drop_control: AtomicU64::new(0),
            rawperf_send_error_count: AtomicU64::new(0),
            retransmit_direct_count: AtomicU64::new(0),
            retransmit_fallback_count: AtomicU64::new(0),
            transition_dedup_drops: AtomicU64::new(0),
            control_decode_errors: AtomicU64::new(0),
            heal_spawned: AtomicU64::new(0),
            heal_succeeded: AtomicU64::new(0),
            unauth_drop_crypto_gate: AtomicU64::new(0),
            unauth_drop_plain_data_crypto: AtomicU64::new(0),
            pacing_tick_duration_us: AtomicU64::new(0),
            pacing_tick_sent_packets: AtomicU64::new(0),
            pacing_drop_control_normal: AtomicU64::new(0),
            pacing_drop_control_retransmit: AtomicU64::new(0),
            fec_ratio_flush_count: AtomicU64::new(0),
            fec_decoder_groups_hwm: AtomicU64::new(0),
            heal_cooldown_blocked: AtomicU64::new(0),
            control_path_race_extra: AtomicU64::new(0),
            route_hijack_reject_count: AtomicU64::new(0),
            stale_to_candidate_promotions: AtomicU64::new(0),
            reliable_unknown_inner_tag: AtomicU64::new(0),
            hub_forward_unknown_dst: AtomicU64::new(0),
            apd_drain_episodes: AtomicU64::new(0),
            apd_drain_ms_total: AtomicU64::new(0),
            apd_packets_drained: AtomicU64::new(0),
            apd_drain_budget_hits: AtomicU64::new(0),
            apd_ramp_active_ticks: AtomicU64::new(0),
            apd_ramp_pinned_ticks: AtomicU64::new(0),
            apd_last_effective_burst: AtomicU64::new(0),
            apd_drain_arm_fill: AtomicU64::new(0),
            apd_drain_arm_sojourn: AtomicU64::new(0),
            apd_last_max_sojourn_ms: AtomicU64::new(0),
            apd_cc_headroom_suppressions: AtomicU64::new(0),
            fec_congestive_hold_count: AtomicU64::new(0),
            fec_classifier_allow_count: AtomicU64::new(0),
            fec_recovery_stepdown_count: AtomicU64::new(0),
            cc_rate_limited_events: AtomicU64::new(0),
            cc_rate_bps_min: AtomicU64::new(0),
            cc_rate_bps_avg: AtomicU64::new(0),
            cc_rate_bps_max: AtomicU64::new(0),
            cc_delivery_bps_min: AtomicU64::new(0),
            cc_delivery_bps_avg: AtomicU64::new(0),
            cc_delivery_bps_max: AtomicU64::new(0),
            cc_increase_events_total: AtomicU64::new(0),
            cc_decrease_events_total: AtomicU64::new(0),
            cc_loss_decrease_events_total: AtomicU64::new(0),
            cc_delivery_anchor_events_total: AtomicU64::new(0),
            cc_loss_ignored_random_events_total: AtomicU64::new(0),
            owd_samples_applied_total: AtomicU64::new(0),
            owd_samples_rejected_total: AtomicU64::new(0),
            drr_small_priority_pops: AtomicU64::new(0),
            drr_bulk_force_pops: AtomicU64::new(0),
            drr_rtt_scale_applied: AtomicU64::new(0),
            outbound_note_total: AtomicU64::new(0),
            outbound_note_poison_recover_total: AtomicU64::new(0),
            keepalive_sent_total: AtomicU64::new(0),
            keepalive_suppressed_total: AtomicU64::new(0),
        }
    }
}

impl EngineMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    /// Zero every counter field. Does not change `enabled`.
    pub fn reset(&self) {
        self.pacing_dropped_packets.store(0, Ordering::Relaxed);
        self.pacing_tick_skip_count.store(0, Ordering::Relaxed);
        self.pacing_overshoot_count.store(0, Ordering::Relaxed);
        self.pacing_adaptive_fallback_count
            .store(0, Ordering::Relaxed);
        self.timer_resolution_requested_us
            .store(0, Ordering::Relaxed);
        self.timer_resolution_applied_us.store(0, Ordering::Relaxed);
        self.timer_resolution_fallback_count
            .store(0, Ordering::Relaxed);
        self.relay_fallback_events.store(0, Ordering::Relaxed);
        self.relay_drop_no_hop.store(0, Ordering::Relaxed);
        self.relay_fallback_direct_no_hop
            .store(0, Ordering::Relaxed);
        self.relay_send_hop_events.store(0, Ordering::Relaxed);
        self.auth_failures.store(0, Ordering::Relaxed);
        self.tun_inject_drops.store(0, Ordering::Relaxed);
        self.tun_inject_lagged.store(0, Ordering::Relaxed);
        self.tun_inject_wrong_dst_drops.store(0, Ordering::Relaxed);
        self.para_notify_drops.store(0, Ordering::Relaxed);
        self.fec_oversize_bypass_count.store(0, Ordering::Relaxed);
        self.fec_mtu_bypass_count.store(0, Ordering::Relaxed);
        self.pmtud_tx_oversize_drop.store(0, Ordering::Relaxed);
        self.pmtud_revalidate_hints.store(0, Ordering::Relaxed);
        self.pmtud_probes_sent.store(0, Ordering::Relaxed);
        self.pmtud_probe_acks.store(0, Ordering::Relaxed);
        self.pmtud_pmar_ignored.store(0, Ordering::Relaxed);
        self.pmtud_probe_timeouts.store(0, Ordering::Relaxed);
        self.pmtud_revalidate_fail_events
            .store(0, Ordering::Relaxed);
        self.pmtud_recheck_recovered_events
            .store(0, Ordering::Relaxed);
        self.pmtud_softdown_events.store(0, Ordering::Relaxed);
        self.pmtud_probe_anomaly_events.store(0, Ordering::Relaxed);
        self.pmtud_late_ack_events.store(0, Ordering::Relaxed);
        self.pmtud_early_wake_events.store(0, Ordering::Relaxed);
        self.fec_drain_passthrough_count.store(0, Ordering::Relaxed);
        self.fec_group_invalid_count.store(0, Ordering::Relaxed);
        self.fec_flush_sparse_passthrough_count
            .store(0, Ordering::Relaxed);
        self.fec_encoded_shards_total.store(0, Ordering::Relaxed);
        self.fec_recovered_packets_total.store(0, Ordering::Relaxed);
        self.fec_decode_fail_count.store(0, Ordering::Relaxed);
        self.pacing_drop_data_fec.store(0, Ordering::Relaxed);
        self.pacing_drop_data_normal.store(0, Ordering::Relaxed);
        self.pacing_shed_sojourn.store(0, Ordering::Relaxed);
        self.pacing_cmd_channel_full.store(0, Ordering::Relaxed);
        self.fec_tx_cmd_channel_full.store(0, Ordering::Relaxed);
        self.pacing_drop_control.store(0, Ordering::Relaxed);
        self.rawperf_send_error_count.store(0, Ordering::Relaxed);
        self.retransmit_direct_count.store(0, Ordering::Relaxed);
        self.retransmit_fallback_count.store(0, Ordering::Relaxed);
        self.transition_dedup_drops.store(0, Ordering::Relaxed);
        self.control_decode_errors.store(0, Ordering::Relaxed);
        self.heal_spawned.store(0, Ordering::Relaxed);
        self.heal_succeeded.store(0, Ordering::Relaxed);
        self.unauth_drop_crypto_gate.store(0, Ordering::Relaxed);
        self.unauth_drop_plain_data_crypto
            .store(0, Ordering::Relaxed);
        self.pacing_tick_duration_us.store(0, Ordering::Relaxed);
        self.pacing_tick_sent_packets.store(0, Ordering::Relaxed);
        self.pacing_drop_control_normal.store(0, Ordering::Relaxed);
        self.pacing_drop_control_retransmit
            .store(0, Ordering::Relaxed);
        self.fec_ratio_flush_count.store(0, Ordering::Relaxed);
        self.fec_decoder_groups_hwm.store(0, Ordering::Relaxed);
        self.heal_cooldown_blocked.store(0, Ordering::Relaxed);
        self.control_path_race_extra.store(0, Ordering::Relaxed);
        self.route_hijack_reject_count.store(0, Ordering::Relaxed);
        self.stale_to_candidate_promotions
            .store(0, Ordering::Relaxed);
        self.reliable_unknown_inner_tag.store(0, Ordering::Relaxed);
        self.hub_forward_unknown_dst.store(0, Ordering::Relaxed);
        self.apd_drain_episodes.store(0, Ordering::Relaxed);
        self.apd_drain_ms_total.store(0, Ordering::Relaxed);
        self.apd_packets_drained.store(0, Ordering::Relaxed);
        self.apd_drain_budget_hits.store(0, Ordering::Relaxed);
        self.apd_ramp_active_ticks.store(0, Ordering::Relaxed);
        self.apd_ramp_pinned_ticks.store(0, Ordering::Relaxed);
        self.apd_last_effective_burst.store(0, Ordering::Relaxed);
        self.apd_drain_arm_fill.store(0, Ordering::Relaxed);
        self.apd_drain_arm_sojourn.store(0, Ordering::Relaxed);
        self.apd_last_max_sojourn_ms.store(0, Ordering::Relaxed);
        self.apd_cc_headroom_suppressions
            .store(0, Ordering::Relaxed);
        self.fec_congestive_hold_count.store(0, Ordering::Relaxed);
        self.fec_classifier_allow_count.store(0, Ordering::Relaxed);
        self.fec_recovery_stepdown_count.store(0, Ordering::Relaxed);
        self.cc_rate_limited_events.store(0, Ordering::Relaxed);
        self.cc_rate_bps_min.store(0, Ordering::Relaxed);
        self.cc_rate_bps_avg.store(0, Ordering::Relaxed);
        self.cc_rate_bps_max.store(0, Ordering::Relaxed);
        self.cc_delivery_bps_min.store(0, Ordering::Relaxed);
        self.cc_delivery_bps_avg.store(0, Ordering::Relaxed);
        self.cc_delivery_bps_max.store(0, Ordering::Relaxed);
        self.cc_increase_events_total.store(0, Ordering::Relaxed);
        self.cc_decrease_events_total.store(0, Ordering::Relaxed);
        self.cc_loss_decrease_events_total
            .store(0, Ordering::Relaxed);
        self.cc_delivery_anchor_events_total
            .store(0, Ordering::Relaxed);
        self.cc_loss_ignored_random_events_total
            .store(0, Ordering::Relaxed);
        self.owd_samples_applied_total.store(0, Ordering::Relaxed);
        self.owd_samples_rejected_total.store(0, Ordering::Relaxed);
        self.drr_small_priority_pops.store(0, Ordering::Relaxed);
        self.drr_bulk_force_pops.store(0, Ordering::Relaxed);
        self.drr_rtt_scale_applied.store(0, Ordering::Relaxed);
        self.outbound_note_total.store(0, Ordering::Relaxed);
        self.outbound_note_poison_recover_total
            .store(0, Ordering::Relaxed);
        self.keepalive_sent_total.store(0, Ordering::Relaxed);
        self.keepalive_suppressed_total.store(0, Ordering::Relaxed);
    }

    pub fn inc_relay_fallback(&self, n: u64) {
        if !self.is_enabled() {
            return;
        }
        self.relay_fallback_events.fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_relay_drop_no_hop(&self) {
        if !self.is_enabled() {
            return;
        }
        self.relay_drop_no_hop.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_relay_fallback_direct_no_hop(&self) {
        if !self.is_enabled() {
            return;
        }
        self.relay_fallback_direct_no_hop
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_relay_send_hop(&self) {
        if !self.is_enabled() {
            return;
        }
        self.relay_send_hop_events.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_auth_failures(&self) {
        if !self.is_enabled() {
            return;
        }
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tun_inject_drops(&self) {
        if !self.is_enabled() {
            return;
        }
        self.tun_inject_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tun_inject_lagged(&self, n: u64) {
        if !self.is_enabled() {
            return;
        }
        self.tun_inject_lagged.fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_tun_inject_wrong_dst_drops(&self) {
        if !self.is_enabled() {
            return;
        }
        self.tun_inject_wrong_dst_drops
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_para_notify_drops(&self) {
        if !self.is_enabled() {
            return;
        }
        self.para_notify_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_fec_oversize_bypass(&self) {
        if !self.is_enabled() {
            return;
        }
        self.fec_oversize_bypass_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_fec_mtu_bypass(&self) {
        if !self.is_enabled() {
            return;
        }
        self.fec_mtu_bypass_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_pmtud_tx_oversize_drop(&self) {
        if !self.is_enabled() {
            return;
        }
        self.pmtud_tx_oversize_drop.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_pmtud_revalidate_hints(&self) {
        if !self.is_enabled() {
            return;
        }
        self.pmtud_revalidate_hints.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_pmtud_probes_sent(&self) {
        if !self.is_enabled() {
            return;
        }
        self.pmtud_probes_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_pmtud_probe_acks(&self) {
        if !self.is_enabled() {
            return;
        }
        self.pmtud_probe_acks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_pmtud_pmar_ignored(&self) {
        if !self.is_enabled() {
            return;
        }
        self.pmtud_pmar_ignored.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_pmtud_events(&self, e: crate::pmtud::PmtudEventCounts) {
        if !self.is_enabled() {
            return;
        }
        if e.probe_timeouts > 0 {
            self.pmtud_probe_timeouts
                .fetch_add(e.probe_timeouts, Ordering::Relaxed);
        }
        if e.revalidate_fail_events > 0 {
            self.pmtud_revalidate_fail_events
                .fetch_add(e.revalidate_fail_events, Ordering::Relaxed);
        }
        if e.recheck_recovered_events > 0 {
            self.pmtud_recheck_recovered_events
                .fetch_add(e.recheck_recovered_events, Ordering::Relaxed);
        }
        if e.softdown_events > 0 {
            self.pmtud_softdown_events
                .fetch_add(e.softdown_events, Ordering::Relaxed);
        }
        if e.probe_anomaly_events > 0 {
            self.pmtud_probe_anomaly_events
                .fetch_add(e.probe_anomaly_events, Ordering::Relaxed);
        }
        if e.late_ack_events > 0 {
            self.pmtud_late_ack_events
                .fetch_add(e.late_ack_events, Ordering::Relaxed);
        }
        if e.early_wake_events > 0 {
            self.pmtud_early_wake_events
                .fetch_add(e.early_wake_events, Ordering::Relaxed);
        }
    }

    pub fn inc_fec_drain_passthrough(&self, n: u64) {
        if !self.is_enabled() {
            return;
        }
        self.fec_drain_passthrough_count
            .fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_fec_group_invalid(&self) {
        if !self.is_enabled() {
            return;
        }
        self.fec_group_invalid_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_fec_flush_sparse_passthrough(&self, n: u64) {
        if !self.is_enabled() {
            return;
        }
        self.fec_flush_sparse_passthrough_count
            .fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_fec_encoded_shards(&self, n: u64) {
        if !self.is_enabled() {
            return;
        }
        self.fec_encoded_shards_total
            .fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_fec_recovered_packets(&self, n: u64) {
        if !self.is_enabled() {
            return;
        }
        self.fec_recovered_packets_total
            .fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_fec_decode_failures(&self) {
        if !self.is_enabled() {
            return;
        }
        self.fec_decode_fail_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_pacing_drop_data_fec(&self) {
        if !self.is_enabled() {
            return;
        }
        self.pacing_drop_data_fec.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_pacing_drop_data_normal(&self) {
        if !self.is_enabled() {
            return;
        }
        self.pacing_drop_data_normal.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_pacing_cmd_channel_full(&self) {
        if !self.is_enabled() {
            return;
        }
        self.pacing_cmd_channel_full.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_fec_tx_cmd_channel_full(&self) {
        if !self.is_enabled() {
            return;
        }
        self.fec_tx_cmd_channel_full.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_pacing_drop_data_normal(&self, v: u64) {
        if !self.is_enabled() {
            return;
        }
        self.pacing_drop_data_normal.store(v, Ordering::Relaxed);
    }

    pub fn set_pacing_shed_sojourn(&self, v: u64) {
        if !self.is_enabled() {
            return;
        }
        self.pacing_shed_sojourn.store(v, Ordering::Relaxed);
    }

    pub fn set_pacing_drop_control_normal(&self, v: u64) {
        if !self.is_enabled() {
            return;
        }
        self.pacing_drop_control_normal.store(v, Ordering::Relaxed);
    }

    pub fn set_pacing_drop_control_retransmit(&self, v: u64) {
        if !self.is_enabled() {
            return;
        }
        self.pacing_drop_control_retransmit
            .store(v, Ordering::Relaxed);
    }

    pub fn inc_pacing_drop_control(&self) {
        if !self.is_enabled() {
            return;
        }
        self.pacing_drop_control.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rawperf_send_errors(&self) {
        if !self.is_enabled() {
            return;
        }
        self.rawperf_send_error_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_retransmit_counts(&self, direct: u64, fallback: u64) {
        if !self.is_enabled() {
            return;
        }
        self.retransmit_direct_count
            .store(direct, Ordering::Relaxed);
        self.retransmit_fallback_count
            .store(fallback, Ordering::Relaxed);
    }

    pub fn inc_transition_dedup_drops(&self) {
        if !self.is_enabled() {
            return;
        }
        self.transition_dedup_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_control_decode_errors(&self) {
        if !self.is_enabled() {
            return;
        }
        self.control_decode_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_heal_spawned(&self) {
        if !self.is_enabled() {
            return;
        }
        self.heal_spawned.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_heal_succeeded(&self) {
        if !self.is_enabled() {
            return;
        }
        self.heal_succeeded.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_unauth_drop_crypto_gate(&self) {
        if !self.is_enabled() {
            return;
        }
        self.unauth_drop_crypto_gate.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_unauth_drop_plain_data_crypto(&self) {
        if !self.is_enabled() {
            return;
        }
        self.unauth_drop_plain_data_crypto
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_pacing_tick_observed(&self, duration_us: u64, sent_packets: u64) {
        if !self.is_enabled() {
            return;
        }
        self.pacing_tick_duration_us
            .store(duration_us, Ordering::Relaxed);
        self.pacing_tick_sent_packets
            .store(sent_packets, Ordering::Relaxed);
    }

    pub fn inc_pacing_drop_control_normal(&self) {
        if !self.is_enabled() {
            return;
        }
        self.pacing_drop_control_normal
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_pacing_drop_control_retransmit(&self) {
        if !self.is_enabled() {
            return;
        }
        self.pacing_drop_control_retransmit
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_reliable_unknown_inner_tag(&self) {
        if !self.is_enabled() {
            return;
        }
        self.reliable_unknown_inner_tag
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_hub_forward_unknown_dst(&self) {
        if !self.is_enabled() {
            return;
        }
        self.hub_forward_unknown_dst.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_fec_ratio_flush(&self) {
        if !self.is_enabled() {
            return;
        }
        self.fec_ratio_flush_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_fec_decoder_groups_hwm(&self, v: u64) {
        if !self.is_enabled() {
            return;
        }
        self.fec_decoder_groups_hwm.store(v, Ordering::Relaxed);
    }

    pub fn inc_heal_cooldown_blocked(&self) {
        if !self.is_enabled() {
            return;
        }
        self.heal_cooldown_blocked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_control_path_race_extra(&self, n: u64) {
        if !self.is_enabled() || n == 0 {
            return;
        }
        self.control_path_race_extra.fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_route_hijack_reject(&self) {
        if !self.is_enabled() {
            return;
        }
        self.route_hijack_reject_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_stale_to_candidate_promotions(&self) {
        if !self.is_enabled() {
            return;
        }
        self.stale_to_candidate_promotions
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_pacing_dropped(&self, v: u64) {
        if !self.is_enabled() {
            return;
        }
        self.pacing_dropped_packets.store(v, Ordering::Relaxed);
    }

    pub fn set_pacing_tick_skips(&self, v: u64) {
        if !self.is_enabled() {
            return;
        }
        self.pacing_tick_skip_count.store(v, Ordering::Relaxed);
    }

    pub fn set_pacing_overshoots(&self, v: u64) {
        if !self.is_enabled() {
            return;
        }
        self.pacing_overshoot_count.store(v, Ordering::Relaxed);
    }

    pub fn set_pacing_adaptive_fallback_count(&self, v: u64) {
        if !self.is_enabled() {
            return;
        }
        self.pacing_adaptive_fallback_count
            .store(v, Ordering::Relaxed);
    }

    pub fn set_timer_resolution(&self, requested_us: u64, applied_us: u64, fallback_count: u64) {
        if !self.is_enabled() {
            return;
        }
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
        if !self.is_enabled() {
            return;
        }
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
        if !self.is_enabled() {
            return;
        }
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
        if !self.is_enabled() {
            return;
        }
        self.apd_drain_arm_fill
            .store(drain_arm_fill, Ordering::Relaxed);
        self.apd_drain_arm_sojourn
            .store(drain_arm_sojourn, Ordering::Relaxed);
        self.apd_last_max_sojourn_ms
            .store(last_max_sojourn_ms, Ordering::Relaxed);
    }

    pub fn set_apd_cc_headroom_suppressions(&self, n: u64) {
        if !self.is_enabled() {
            return;
        }
        self.apd_cc_headroom_suppressions
            .store(n, Ordering::Relaxed);
    }

    pub fn inc_fec_congestive_hold(&self) {
        if !self.is_enabled() {
            return;
        }
        self.fec_congestive_hold_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_fec_classifier_allow(&self) {
        if !self.is_enabled() {
            return;
        }
        self.fec_classifier_allow_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_fec_recovery_stepdown(&self) {
        if !self.is_enabled() {
            return;
        }
        self.fec_recovery_stepdown_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_cc_rate_limited_events(&self, n: u64) {
        if !self.is_enabled() {
            return;
        }
        self.cc_rate_limited_events.store(n, Ordering::Relaxed);
    }

    pub fn set_background_cc_rates(&self, min_bps: f64, avg_bps: f64, max_bps: f64) {
        if !self.is_enabled() {
            return;
        }
        self.cc_rate_bps_min
            .store(min_bps.round() as u64, Ordering::Relaxed);
        self.cc_rate_bps_avg
            .store(avg_bps.round() as u64, Ordering::Relaxed);
        self.cc_rate_bps_max
            .store(max_bps.round() as u64, Ordering::Relaxed);
    }

    pub fn set_background_cc_delivery_rates(&self, min_bps: f64, avg_bps: f64, max_bps: f64) {
        if !self.is_enabled() {
            return;
        }
        self.cc_delivery_bps_min
            .store(min_bps.round() as u64, Ordering::Relaxed);
        self.cc_delivery_bps_avg
            .store(avg_bps.round() as u64, Ordering::Relaxed);
        self.cc_delivery_bps_max
            .store(max_bps.round() as u64, Ordering::Relaxed);
    }

    pub fn set_cc_event_counters(
        &self,
        increase: u64,
        decrease: u64,
        loss_decrease: u64,
        delivery_anchor: u64,
        loss_ignored_random: u64,
    ) {
        if !self.is_enabled() {
            return;
        }
        self.cc_increase_events_total
            .store(increase, Ordering::Relaxed);
        self.cc_decrease_events_total
            .store(decrease, Ordering::Relaxed);
        self.cc_loss_decrease_events_total
            .store(loss_decrease, Ordering::Relaxed);
        self.cc_delivery_anchor_events_total
            .store(delivery_anchor, Ordering::Relaxed);
        self.cc_loss_ignored_random_events_total
            .store(loss_ignored_random, Ordering::Relaxed);
    }

    pub fn inc_owd_samples_applied(&self) {
        if !self.is_enabled() {
            return;
        }
        self.owd_samples_applied_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_owd_samples_rejected(&self) {
        if !self.is_enabled() {
            return;
        }
        self.owd_samples_rejected_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_drr_small_priority_pops(&self, n: u64) {
        if !self.is_enabled() {
            return;
        }
        self.drr_small_priority_pops.store(n, Ordering::Relaxed);
    }

    pub fn set_drr_bulk_force_pops(&self, n: u64) {
        if !self.is_enabled() {
            return;
        }
        self.drr_bulk_force_pops.store(n, Ordering::Relaxed);
    }

    pub fn set_drr_rtt_scale_applied(&self, n: u64) {
        if !self.is_enabled() {
            return;
        }
        self.drr_rtt_scale_applied.store(n, Ordering::Relaxed);
    }

    pub fn inc_outbound_note(&self) {
        if !self.is_enabled() {
            return;
        }
        self.outbound_note_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_outbound_note_poison_recover(&self) {
        if !self.is_enabled() {
            return;
        }
        self.outbound_note_poison_recover_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_keepalive_sent(&self) {
        if !self.is_enabled() {
            return;
        }
        self.keepalive_sent_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_keepalive_suppressed(&self) {
        if !self.is_enabled() {
            return;
        }
        self.keepalive_suppressed_total
            .fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drr_observability_setters_store_absolute_counts() {
        let m = EngineMetrics::new();
        m.set_enabled(true);
        m.set_drr_small_priority_pops(3);
        m.set_drr_bulk_force_pops(2);
        m.set_drr_rtt_scale_applied(7);
        assert_eq!(m.drr_small_priority_pops.load(Ordering::Relaxed), 3);
        assert_eq!(m.drr_bulk_force_pops.load(Ordering::Relaxed), 2);
        assert_eq!(m.drr_rtt_scale_applied.load(Ordering::Relaxed), 7);
    }

    #[test]
    fn disabled_by_default_mutations_are_noop() {
        let m = EngineMetrics::new();
        assert!(!m.is_enabled());
        m.inc_auth_failures();
        m.set_drr_small_priority_pops(9);
        assert_eq!(m.auth_failures.load(Ordering::Relaxed), 0);
        assert_eq!(m.drr_small_priority_pops.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn enable_inc_then_reset_clears() {
        let m = EngineMetrics::new();
        m.set_enabled(true);
        m.inc_auth_failures();
        m.inc_auth_failures();
        assert_eq!(m.auth_failures.load(Ordering::Relaxed), 2);
        m.reset();
        assert!(m.is_enabled());
        assert_eq!(m.auth_failures.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn disable_stops_further_accumulation() {
        let m = EngineMetrics::new();
        m.set_enabled(true);
        m.inc_auth_failures();
        m.set_enabled(false);
        m.reset();
        m.inc_auth_failures();
        assert_eq!(m.auth_failures.load(Ordering::Relaxed), 0);
    }
}
