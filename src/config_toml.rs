//! Sectioned on-disk schema for `NetInfo/config.toml`.
//!
//! Runtime [`NetworkConfig`](crate::config::NetworkConfig) stays flat for engine/CLI;
//! only encode/parse go through this DTO.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::advanced_tuning::{
    BufferReuseTuning, CongestionTuning, EngineLimitsTuning, FailoverTuning, FecTuning,
    HolePunchTuning, PmtudTuning, ReliableTuning, RoutingEwmaTuning, TimerTuning,
};
use crate::config::{NetworkConfig, PeerInfo};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct NetworkConfigFile {
    pub session: SessionFile,
    #[serde(default)]
    pub peers: Vec<PeerInfo>,
    pub parasitic: ParasiticFile,
    pub adapter: AdapterFile,
    pub pacing: PacingFile,
    pub apd: ApdFile,
    pub drr: DrrFile,
    pub fec: FecFile,
    pub decentralized: DecentralizedFile,
    pub failover: FailoverTuning,
    pub timers: TimerTuning,
    pub reliable: ReliableTuning,
    pub congestion: CongestionTuning,
    pub pmtud: PmtudTuning,
    pub routing_ewma: RoutingEwmaTuning,
    pub engine_limits: EngineLimitsTuning,
    pub hole_punch: HolePunchTuning,
    pub buffers: BufferReuseTuning,
}

impl Default for NetworkConfigFile {
    fn default() -> Self {
        Self::from(&NetworkConfig::default())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub(crate) struct SessionFile {
    pub server_name: String,
    pub network_id: String,
    pub role: String,
    pub virtual_ip: String,
    pub owner_real_ip: String,
    pub owner_port: u16,
    pub listen_port: u16,
    pub node_id: String,
    pub crypto_key: String,
    pub public_invite_code: String,
    pub membership_version: u64,
    pub last_membership_hash: String,
    pub created_at: i64,
    pub subnet_prefix: u8,
    pub owner_endpoints_cache: Vec<String>,
}

impl Default for SessionFile {
    fn default() -> Self {
        let d = NetworkConfig::default();
        Self {
            server_name: d.server_name,
            network_id: d.network_id,
            role: d.role,
            virtual_ip: d.virtual_ip,
            owner_real_ip: d.owner_real_ip,
            owner_port: d.owner_port,
            listen_port: d.listen_port,
            node_id: d.node_id,
            crypto_key: d.crypto_key,
            public_invite_code: d.public_invite_code,
            membership_version: d.membership_version,
            last_membership_hash: d.last_membership_hash,
            created_at: d.created_at,
            subnet_prefix: d.subnet_prefix,
            owner_endpoints_cache: d.owner_endpoints_cache,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ParasiticFile {
    pub parasitic_enabled: bool,
    pub parasitic_peer_vip: String,
    pub parasitic_self_vip: String,
    pub parasitic_peer_port: u16,
    pub parasitic_peer_node_id: String,
    pub parasitic_self_is_owner: bool,
    #[serde(default = "default_parasitic_use_public_toml")]
    pub parasitic_use_public: bool,
}

fn default_parasitic_use_public_toml() -> bool {
    true
}

impl Default for ParasiticFile {
    fn default() -> Self {
        let d = NetworkConfig::default();
        Self {
            parasitic_enabled: d.parasitic_enabled,
            parasitic_peer_vip: d.parasitic_peer_vip,
            parasitic_self_vip: d.parasitic_self_vip,
            parasitic_peer_port: d.parasitic_peer_port,
            parasitic_peer_node_id: d.parasitic_peer_node_id,
            parasitic_self_is_owner: d.parasitic_self_is_owner,
            parasitic_use_public: d.parasitic_use_public,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct AdapterFile {
    pub udp_sndbuf: i32,
    pub udp_rcvbuf: i32,
    pub adapter_mtu: i32,
    pub wintun_ring_bytes: u32,
    pub wintun_ipv4_interface_metric: u32,
}

impl Default for AdapterFile {
    fn default() -> Self {
        let d = NetworkConfig::default();
        Self {
            udp_sndbuf: d.udp_sndbuf,
            udp_rcvbuf: d.udp_rcvbuf,
            adapter_mtu: d.adapter_mtu,
            wintun_ring_bytes: d.wintun_ring_bytes,
            wintun_ipv4_interface_metric: d.wintun_ipv4_interface_metric,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct PacingFile {
    pub pace_tick_us: i64,
    pub pace_target_pps: i64,
    pub pace_rate_mode: String,
    pub pace_target_bps: i64,
    pub base_max_burst: i64,
    pub pace_budget_cap_packets: f64,
    pub pace_max_queue_packets: i64,
    pub tun_inject_queue_packets: i64,
    pub tun_from_adapter_queue_packets: i64,
    pub pace_clock_mode: String,
    pub pace_spin_window_us: i64,
    pub pace_fab_enabled: bool,
    pub pace_fab_fallback_tick_us: i64,
    pub cpu_affinity: String,
    pub process_priority_level: u8,
    pub rawperf_enabled: bool,
    pub retransmit_bypass_pps: f64,
    pub low_latency_timer_enabled: bool,
}

impl Default for PacingFile {
    fn default() -> Self {
        let d = NetworkConfig::default();
        Self {
            pace_tick_us: d.pace_tick_us,
            pace_target_pps: d.pace_target_pps,
            pace_rate_mode: d.pace_rate_mode,
            pace_target_bps: d.pace_target_bps,
            base_max_burst: d.base_max_burst,
            pace_budget_cap_packets: d.pace_budget_cap_packets,
            pace_max_queue_packets: d.pace_max_queue_packets,
            tun_inject_queue_packets: d.tun_inject_queue_packets,
            tun_from_adapter_queue_packets: d.tun_from_adapter_queue_packets,
            pace_clock_mode: d.pace_clock_mode,
            pace_spin_window_us: d.pace_spin_window_us,
            pace_fab_enabled: d.pace_fab_enabled,
            pace_fab_fallback_tick_us: d.pace_fab_fallback_tick_us,
            cpu_affinity: d.cpu_affinity,
            process_priority_level: d.process_priority_level,
            rawperf_enabled: d.rawperf_enabled,
            retransmit_bypass_pps: d.retransmit_bypass_pps,
            low_latency_timer_enabled: d.low_latency_timer_enabled,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ApdFile {
    pub apd_enabled: bool,
    pub apd_high_watermark: f32,
    pub apd_low_watermark: f32,
    pub ramp_max_burst: u64,
    pub drain_max_burst: u64,
    pub apd_spinloop_budget_ms: u32,
    pub apd_drain_tick_us: u64,
    pub apd_confirm_ticks: u32,
    pub apd_cooldown_ms: u32,
    pub apd_drain_freeze_drr: bool,
    pub apd_sojourn_enabled: bool,
    pub apd_max_sojourn_ms: u32,
    pub apd_target_sojourn_ms: u32,
    pub apd_require_cc_headroom: bool,
    pub shed_enabled: bool,
    pub shed_max_sojourn_ms: u32,
    pub shed_min_fill: f32,
    pub shed_max_per_tick: u32,
}

impl Default for ApdFile {
    fn default() -> Self {
        let d = NetworkConfig::default();
        Self {
            apd_enabled: d.apd_enabled,
            apd_high_watermark: d.apd_high_watermark,
            apd_low_watermark: d.apd_low_watermark,
            ramp_max_burst: d.ramp_max_burst,
            drain_max_burst: d.drain_max_burst,
            apd_spinloop_budget_ms: d.apd_spinloop_budget_ms,
            apd_drain_tick_us: d.apd_drain_tick_us,
            apd_confirm_ticks: d.apd_confirm_ticks,
            apd_cooldown_ms: d.apd_cooldown_ms,
            apd_drain_freeze_drr: d.apd_drain_freeze_drr,
            apd_sojourn_enabled: d.apd_sojourn_enabled,
            apd_max_sojourn_ms: d.apd_max_sojourn_ms,
            apd_target_sojourn_ms: d.apd_target_sojourn_ms,
            apd_require_cc_headroom: d.apd_require_cc_headroom,
            shed_enabled: d.shed_enabled,
            shed_max_sojourn_ms: d.shed_max_sojourn_ms,
            shed_min_fill: d.shed_min_fill,
            shed_max_per_tick: d.shed_max_per_tick,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct DrrFile {
    pub drr_enabled: bool,
    pub drr_small_packet_priority: bool,
    pub drr_small_packet_threshold_bytes: u32,
    pub min_control_reserved_bytes_per_tick: u32,
    pub min_retransmit_reserved_bytes_per_tick: u32,
    pub drr_rtt_aware: bool,
    pub drr_rtt_scale_min: f64,
    pub drr_rtt_scale_max: f64,
}

impl Default for DrrFile {
    fn default() -> Self {
        let d = NetworkConfig::default();
        Self {
            drr_enabled: d.drr_enabled,
            drr_small_packet_priority: d.drr_small_packet_priority,
            drr_small_packet_threshold_bytes: d.drr_small_packet_threshold_bytes,
            min_control_reserved_bytes_per_tick: d.min_control_reserved_bytes_per_tick,
            min_retransmit_reserved_bytes_per_tick: d.min_retransmit_reserved_bytes_per_tick,
            drr_rtt_aware: d.drr_rtt_aware,
            drr_rtt_scale_min: d.drr_rtt_scale_min,
            drr_rtt_scale_max: d.drr_rtt_scale_max,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct FecFile {
    pub fec_enabled: bool,
    pub fec_force_data_shards: u8,
    pub fec_force_parity_shards: u8,
    pub shard_payload_size: usize,
    pub flush_ms: u64,
    pub flush_aggressive_ms: u64,
    pub adaptive_off_below: f64,
    pub adaptive_on_above: f64,
    pub fec_max_total_shards: usize,
}

impl Default for FecFile {
    fn default() -> Self {
        let d = NetworkConfig::default();
        let fec = d.advanced.fec;
        Self {
            fec_enabled: d.fec_enabled,
            fec_force_data_shards: d.fec_force_data_shards,
            fec_force_parity_shards: d.fec_force_parity_shards,
            shard_payload_size: fec.shard_payload_size,
            flush_ms: fec.flush_ms,
            flush_aggressive_ms: fec.flush_aggressive_ms,
            adaptive_off_below: fec.adaptive_off_below,
            adaptive_on_above: fec.adaptive_on_above,
            fec_max_total_shards: fec.fec_max_total_shards,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct DecentralizedFile {
    pub decentralized_enabled: bool,
    pub decentralized_trackers: Vec<String>,
    pub decentralized_announce_secs: u64,
    pub decentralized_join_deadline_secs: u64,
    pub join_method: String,
}

impl Default for DecentralizedFile {
    fn default() -> Self {
        let d = NetworkConfig::default();
        Self {
            decentralized_enabled: d.decentralized_enabled,
            decentralized_trackers: d.decentralized_trackers,
            decentralized_announce_secs: d.decentralized_announce_secs,
            decentralized_join_deadline_secs: d.decentralized_join_deadline_secs,
            join_method: d.join_method,
        }
    }
}

impl From<&NetworkConfig> for NetworkConfigFile {
    fn from(cfg: &NetworkConfig) -> Self {
        Self {
            session: SessionFile {
                server_name: cfg.server_name.clone(),
                network_id: cfg.network_id.clone(),
                role: cfg.role.clone(),
                virtual_ip: cfg.virtual_ip.clone(),
                owner_real_ip: cfg.owner_real_ip.clone(),
                owner_port: cfg.owner_port,
                listen_port: cfg.listen_port,
                node_id: cfg.node_id.clone(),
                crypto_key: cfg.crypto_key.clone(),
                public_invite_code: cfg.public_invite_code.clone(),
                membership_version: cfg.membership_version,
                last_membership_hash: cfg.last_membership_hash.clone(),
                created_at: cfg.created_at,
                subnet_prefix: cfg.subnet_prefix,
                owner_endpoints_cache: cfg.owner_endpoints_cache.clone(),
            },
            peers: cfg.peers.clone(),
            parasitic: ParasiticFile {
                parasitic_enabled: cfg.parasitic_enabled,
                parasitic_peer_vip: cfg.parasitic_peer_vip.clone(),
                parasitic_self_vip: cfg.parasitic_self_vip.clone(),
                parasitic_peer_port: cfg.parasitic_peer_port,
                parasitic_peer_node_id: cfg.parasitic_peer_node_id.clone(),
                parasitic_self_is_owner: cfg.parasitic_self_is_owner,
                parasitic_use_public: cfg.parasitic_use_public,
            },
            adapter: AdapterFile {
                udp_sndbuf: cfg.udp_sndbuf,
                udp_rcvbuf: cfg.udp_rcvbuf,
                adapter_mtu: cfg.adapter_mtu,
                wintun_ring_bytes: cfg.wintun_ring_bytes,
                wintun_ipv4_interface_metric: cfg.wintun_ipv4_interface_metric,
            },
            pacing: PacingFile {
                pace_tick_us: cfg.pace_tick_us,
                pace_target_pps: cfg.pace_target_pps,
                pace_rate_mode: cfg.pace_rate_mode.clone(),
                pace_target_bps: cfg.pace_target_bps,
                base_max_burst: cfg.base_max_burst,
                pace_budget_cap_packets: cfg.pace_budget_cap_packets,
                pace_max_queue_packets: cfg.pace_max_queue_packets,
                tun_inject_queue_packets: cfg.tun_inject_queue_packets,
                tun_from_adapter_queue_packets: cfg.tun_from_adapter_queue_packets,
                pace_clock_mode: cfg.pace_clock_mode.clone(),
                pace_spin_window_us: cfg.pace_spin_window_us,
                pace_fab_enabled: cfg.pace_fab_enabled,
                pace_fab_fallback_tick_us: cfg.pace_fab_fallback_tick_us,
                cpu_affinity: cfg.cpu_affinity.clone(),
                process_priority_level: cfg.process_priority_level,
                rawperf_enabled: cfg.rawperf_enabled,
                retransmit_bypass_pps: cfg.retransmit_bypass_pps,
                low_latency_timer_enabled: cfg.low_latency_timer_enabled,
            },
            apd: ApdFile {
                apd_enabled: cfg.apd_enabled,
                apd_high_watermark: cfg.apd_high_watermark,
                apd_low_watermark: cfg.apd_low_watermark,
                ramp_max_burst: cfg.ramp_max_burst,
                drain_max_burst: cfg.drain_max_burst,
                apd_spinloop_budget_ms: cfg.apd_spinloop_budget_ms,
                apd_drain_tick_us: cfg.apd_drain_tick_us,
                apd_confirm_ticks: cfg.apd_confirm_ticks,
                apd_cooldown_ms: cfg.apd_cooldown_ms,
                apd_drain_freeze_drr: cfg.apd_drain_freeze_drr,
                apd_sojourn_enabled: cfg.apd_sojourn_enabled,
                apd_max_sojourn_ms: cfg.apd_max_sojourn_ms,
                apd_target_sojourn_ms: cfg.apd_target_sojourn_ms,
                apd_require_cc_headroom: cfg.apd_require_cc_headroom,
                shed_enabled: cfg.shed_enabled,
                shed_max_sojourn_ms: cfg.shed_max_sojourn_ms,
                shed_min_fill: cfg.shed_min_fill,
                shed_max_per_tick: cfg.shed_max_per_tick,
            },
            drr: DrrFile {
                drr_enabled: cfg.drr_enabled,
                drr_small_packet_priority: cfg.drr_small_packet_priority,
                drr_small_packet_threshold_bytes: cfg.drr_small_packet_threshold_bytes,
                min_control_reserved_bytes_per_tick: cfg.min_control_reserved_bytes_per_tick,
                min_retransmit_reserved_bytes_per_tick: cfg.min_retransmit_reserved_bytes_per_tick,
                drr_rtt_aware: cfg.drr_rtt_aware,
                drr_rtt_scale_min: cfg.drr_rtt_scale_min,
                drr_rtt_scale_max: cfg.drr_rtt_scale_max,
            },
            fec: FecFile {
                fec_enabled: cfg.fec_enabled,
                fec_force_data_shards: cfg.fec_force_data_shards,
                fec_force_parity_shards: cfg.fec_force_parity_shards,
                shard_payload_size: cfg.advanced.fec.shard_payload_size,
                flush_ms: cfg.advanced.fec.flush_ms,
                flush_aggressive_ms: cfg.advanced.fec.flush_aggressive_ms,
                adaptive_off_below: cfg.advanced.fec.adaptive_off_below,
                adaptive_on_above: cfg.advanced.fec.adaptive_on_above,
                fec_max_total_shards: cfg.advanced.fec.fec_max_total_shards,
            },
            decentralized: DecentralizedFile {
                decentralized_enabled: cfg.decentralized_enabled,
                decentralized_trackers: cfg.decentralized_trackers.clone(),
                decentralized_announce_secs: cfg.decentralized_announce_secs,
                decentralized_join_deadline_secs: cfg.decentralized_join_deadline_secs,
                join_method: cfg.join_method.clone(),
            },
            failover: cfg.advanced.failover,
            timers: cfg.advanced.timers,
            reliable: cfg.advanced.reliable,
            congestion: cfg.advanced.congestion,
            pmtud: cfg.advanced.pmtud.clone(),
            routing_ewma: cfg.advanced.routing_ewma,
            engine_limits: cfg.advanced.engine_limits,
            hole_punch: cfg.advanced.hole_punch,
            buffers: cfg.advanced.buffers,
        }
    }
}

impl From<NetworkConfigFile> for NetworkConfig {
    fn from(file: NetworkConfigFile) -> Self {
        let mut cfg = NetworkConfig::default();
        cfg.server_name = file.session.server_name;
        cfg.network_id = file.session.network_id;
        cfg.role = file.session.role;
        cfg.virtual_ip = file.session.virtual_ip;
        cfg.owner_real_ip = file.session.owner_real_ip;
        cfg.owner_port = file.session.owner_port;
        cfg.listen_port = file.session.listen_port;
        cfg.node_id = file.session.node_id;
        cfg.crypto_key = file.session.crypto_key;
        cfg.public_invite_code = file.session.public_invite_code;
        cfg.membership_version = file.session.membership_version;
        cfg.last_membership_hash = file.session.last_membership_hash;
        cfg.created_at = file.session.created_at;
        cfg.subnet_prefix = file.session.subnet_prefix;
        cfg.owner_endpoints_cache = file.session.owner_endpoints_cache;
        cfg.peers = file.peers;
        cfg.parasitic_enabled = file.parasitic.parasitic_enabled;
        cfg.parasitic_peer_vip = file.parasitic.parasitic_peer_vip;
        cfg.parasitic_self_vip = file.parasitic.parasitic_self_vip;
        cfg.parasitic_peer_port = file.parasitic.parasitic_peer_port;
        cfg.parasitic_peer_node_id = file.parasitic.parasitic_peer_node_id;
        cfg.parasitic_self_is_owner = file.parasitic.parasitic_self_is_owner;
        cfg.parasitic_use_public = file.parasitic.parasitic_use_public;
        cfg.udp_sndbuf = file.adapter.udp_sndbuf;
        cfg.udp_rcvbuf = file.adapter.udp_rcvbuf;
        cfg.adapter_mtu = file.adapter.adapter_mtu;
        cfg.wintun_ring_bytes = file.adapter.wintun_ring_bytes;
        cfg.wintun_ipv4_interface_metric = file.adapter.wintun_ipv4_interface_metric;
        cfg.pace_tick_us = file.pacing.pace_tick_us;
        cfg.pace_target_pps = file.pacing.pace_target_pps;
        cfg.pace_rate_mode = file.pacing.pace_rate_mode;
        cfg.pace_target_bps = file.pacing.pace_target_bps;
        cfg.base_max_burst = file.pacing.base_max_burst;
        cfg.pace_budget_cap_packets = file.pacing.pace_budget_cap_packets;
        cfg.pace_max_queue_packets = file.pacing.pace_max_queue_packets;
        cfg.tun_inject_queue_packets = file.pacing.tun_inject_queue_packets;
        cfg.tun_from_adapter_queue_packets = file.pacing.tun_from_adapter_queue_packets;
        cfg.pace_clock_mode = file.pacing.pace_clock_mode;
        cfg.pace_spin_window_us = file.pacing.pace_spin_window_us;
        cfg.pace_fab_enabled = file.pacing.pace_fab_enabled;
        cfg.pace_fab_fallback_tick_us = file.pacing.pace_fab_fallback_tick_us;
        cfg.cpu_affinity = file.pacing.cpu_affinity;
        cfg.process_priority_level = file.pacing.process_priority_level;
        cfg.rawperf_enabled = file.pacing.rawperf_enabled;
        cfg.retransmit_bypass_pps = file.pacing.retransmit_bypass_pps;
        cfg.low_latency_timer_enabled = file.pacing.low_latency_timer_enabled;
        cfg.apd_enabled = file.apd.apd_enabled;
        cfg.apd_high_watermark = file.apd.apd_high_watermark;
        cfg.apd_low_watermark = file.apd.apd_low_watermark;
        cfg.ramp_max_burst = file.apd.ramp_max_burst;
        cfg.drain_max_burst = file.apd.drain_max_burst;
        cfg.apd_spinloop_budget_ms = file.apd.apd_spinloop_budget_ms;
        cfg.apd_drain_tick_us = file.apd.apd_drain_tick_us;
        cfg.apd_confirm_ticks = file.apd.apd_confirm_ticks;
        cfg.apd_cooldown_ms = file.apd.apd_cooldown_ms;
        cfg.apd_drain_freeze_drr = file.apd.apd_drain_freeze_drr;
        cfg.apd_sojourn_enabled = file.apd.apd_sojourn_enabled;
        cfg.apd_max_sojourn_ms = file.apd.apd_max_sojourn_ms;
        cfg.apd_target_sojourn_ms = file.apd.apd_target_sojourn_ms;
        cfg.apd_require_cc_headroom = file.apd.apd_require_cc_headroom;
        cfg.shed_enabled = file.apd.shed_enabled;
        cfg.shed_max_sojourn_ms = file.apd.shed_max_sojourn_ms;
        cfg.shed_min_fill = file.apd.shed_min_fill;
        cfg.shed_max_per_tick = file.apd.shed_max_per_tick;
        cfg.drr_enabled = file.drr.drr_enabled;
        cfg.drr_small_packet_priority = file.drr.drr_small_packet_priority;
        cfg.drr_small_packet_threshold_bytes = file.drr.drr_small_packet_threshold_bytes;
        cfg.min_control_reserved_bytes_per_tick = file.drr.min_control_reserved_bytes_per_tick;
        cfg.min_retransmit_reserved_bytes_per_tick =
            file.drr.min_retransmit_reserved_bytes_per_tick;
        cfg.drr_rtt_aware = file.drr.drr_rtt_aware;
        cfg.drr_rtt_scale_min = file.drr.drr_rtt_scale_min;
        cfg.drr_rtt_scale_max = file.drr.drr_rtt_scale_max;
        cfg.fec_enabled = file.fec.fec_enabled;
        cfg.fec_force_data_shards = file.fec.fec_force_data_shards;
        cfg.fec_force_parity_shards = file.fec.fec_force_parity_shards;
        cfg.decentralized_enabled = file.decentralized.decentralized_enabled;
        cfg.decentralized_trackers = file.decentralized.decentralized_trackers;
        cfg.decentralized_announce_secs = file.decentralized.decentralized_announce_secs;
        cfg.decentralized_join_deadline_secs = file.decentralized.decentralized_join_deadline_secs;
        cfg.join_method = file.decentralized.join_method;
        cfg.advanced.failover = file.failover;
        cfg.advanced.timers = file.timers;
        cfg.advanced.reliable = file.reliable;
        cfg.advanced.fec = FecTuning {
            shard_payload_size: file.fec.shard_payload_size,
            flush_ms: file.fec.flush_ms,
            flush_aggressive_ms: file.fec.flush_aggressive_ms,
            adaptive_off_below: file.fec.adaptive_off_below,
            adaptive_on_above: file.fec.adaptive_on_above,
            fec_max_total_shards: file.fec.fec_max_total_shards,
        };
        cfg.advanced.congestion = file.congestion;
        cfg.advanced.pmtud = file.pmtud;
        cfg.advanced.routing_ewma = file.routing_ewma;
        cfg.advanced.engine_limits = file.engine_limits;
        cfg.advanced.hole_punch = file.hole_punch;
        cfg.advanced.buffers = file.buffers;
        cfg
    }
}

fn compact_apd_watermark_floats(root: &mut toml::map::Map<String, toml::Value>) {
    let Some(toml::Value::Table(apd)) = root.get_mut("apd") else {
        return;
    };
    for key in ["apd_low_watermark", "apd_high_watermark"] {
        if let Some(toml::Value::Float(v)) = apd.get_mut(key) {
            // Round away f32→f64 binary noise (e.g. 0.10_f32 → 0.10000000149…).
            *v = (*v * 1_000_000.0).round() / 1_000_000.0;
        }
    }
}

/// Collapse `key = [ … ]` onto one line (toml pretty-printer emits one item/line).
fn inline_named_array(toml_text: &str, key: &str) -> String {
    let needle = format!("{key} = [");
    let Some(start) = toml_text.find(&needle) else {
        return toml_text.to_string();
    };
    let values_start = start + needle.len();
    let rest = &toml_text[values_start..];
    let Some(end_rel) = rest.find(']') else {
        return toml_text.to_string();
    };
    let items: Vec<&str> = rest[..end_rel]
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let mut out = String::with_capacity(toml_text.len());
    out.push_str(&toml_text[..start]);
    out.push_str(&format!("{key} = [{}]", items.join(", ")));
    out.push_str(&rest[end_rel + 1..]);
    out
}

/// Encode `NetworkConfig` for `NetInfo/config.toml`: sectioned tables, compact
/// APD watermarks, inline `probe_sizes`.
pub(crate) fn encode_network_config_toml(cfg: &NetworkConfig) -> Result<String> {
    let file = NetworkConfigFile::from(cfg);
    let mut value =
        toml::Value::try_from(&file).map_err(|e| anyhow::anyhow!("config toml encode: {e}"))?;
    if let Some(root) = value.as_table_mut() {
        compact_apd_watermark_floats(root);
    }
    let pretty =
        toml::to_string_pretty(&value).map_err(|e| anyhow::anyhow!("config toml pretty: {e}"))?;
    Ok(inline_named_array(&pretty, "probe_sizes"))
}

pub(crate) fn parse_network_config_toml(raw: &str) -> Result<NetworkConfig> {
    let file: NetworkConfigFile =
        toml::from_str(raw).map_err(|e| anyhow::anyhow!("config toml decode: {e}"))?;
    let mut cfg = NetworkConfig::from(file);
    cfg.advanced.clamp();
    Ok(cfg)
}
