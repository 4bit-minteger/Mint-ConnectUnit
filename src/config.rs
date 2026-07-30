use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;

use anyhow::Result;
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::config_toml::{encode_network_config_toml, parse_network_config_toml};

/// Joiner-only durable peer roster cap (owner uses unbounded `add_peer`).
pub const JOINER_ROSTER_MAX: usize = 64;

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
pub struct PeerInfo {
    pub node_id: String,
    pub name: String,
    pub virtual_ip: String,
    pub real_ip: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NetworkConfig {
    pub server_name: String,
    pub network_id: String,
    pub role: String,
    pub virtual_ip: String,
    pub owner_real_ip: String,
    pub owner_port: u16,
    pub listen_port: u16,
    pub node_id: String,
    pub crypto_key: String,
    #[serde(default)]
    pub public_invite_code: String,
    #[serde(default)]
    pub parasitic_enabled: bool,
    #[serde(default)]
    pub parasitic_peer_vip: String,
    #[serde(default)]
    pub parasitic_self_vip: String,
    #[serde(default)]
    pub parasitic_peer_port: u16,

    #[serde(default)]
    pub parasitic_peer_node_id: String,

    #[serde(default)]
    pub parasitic_self_is_owner: bool,

    /// `true` = Public parasitic (VIP + STUN); `false` = LAN parasitic (no STUN/UPnP).
    #[serde(default = "default_parasitic_use_public")]
    pub parasitic_use_public: bool,
    pub peers: Vec<PeerInfo>,
    pub owner_endpoints_cache: Vec<String>,
    pub membership_version: u64,
    pub last_membership_hash: String,
    pub created_at: i64,
    pub udp_sndbuf: i32,
    pub udp_rcvbuf: i32,
    pub adapter_mtu: i32,
    pub wintun_ring_bytes: u32,

    #[serde(default = "default_wintun_ipv4_interface_metric")]
    pub wintun_ipv4_interface_metric: u32,
    pub pace_tick_us: i64,
    pub pace_target_pps: i64,
    #[serde(default = "default_pace_rate_mode")]
    pub pace_rate_mode: String,
    #[serde(default = "default_pace_target_bps")]
    pub pace_target_bps: i64,
    #[serde(default = "default_base_max_burst")]
    pub base_max_burst: i64,
    /// Max token-bucket balance in **packet units** (`1..=4096`). Always packet-equivalent:
    /// with `pace_rate_mode=bytes`, the engine caps at `value × 1300` bytes — never enter raw bytes here.
    pub pace_budget_cap_packets: f64,
    pub pace_max_queue_packets: i64,

    #[serde(default = "default_tun_inject_queue_packets")]
    pub tun_inject_queue_packets: i64,

    /// mpsc capacity for Wintun reader → engine (startup-only).
    #[serde(default = "default_tun_from_adapter_queue_packets")]
    pub tun_from_adapter_queue_packets: i64,

    #[serde(default = "default_pace_clock_mode")]
    pub pace_clock_mode: String,

    #[serde(default = "default_pace_spin_window_us")]
    pub pace_spin_window_us: i64,

    #[serde(default = "default_pace_fab_enabled")]
    pub pace_fab_enabled: bool,

    #[serde(default = "default_pace_fab_fallback_tick_us")]
    pub pace_fab_fallback_tick_us: i64,

    #[serde(default = "default_subnet_prefix")]
    pub subnet_prefix: u8,

    /// Logical CPU spec for process affinity (Windows). Empty = exclude CPUs 0 and 1.
    #[serde(default)]
    pub cpu_affinity: String,

    /// Windows process priority class: 1=realtime, 2=high, 3=normal.
    #[serde(default = "default_process_priority_level")]
    pub process_priority_level: u8,

    // ── APD (Adaptive Precision Drain) ──────────────────────────────────────
    #[serde(default = "default_apd_enabled")]
    pub apd_enabled: bool,
    #[serde(default = "default_apd_high_watermark")]
    pub apd_high_watermark: f32,
    #[serde(default = "default_apd_low_watermark")]
    pub apd_low_watermark: f32,
    #[serde(default = "default_ramp_max_burst")]
    pub ramp_max_burst: u64,
    #[serde(default = "default_drain_max_burst")]
    pub drain_max_burst: u64,
    #[serde(default = "default_apd_spinloop_budget_ms")]
    pub apd_spinloop_budget_ms: u32,
    #[serde(default = "default_apd_drain_tick_us")]
    pub apd_drain_tick_us: u64,
    #[serde(default = "default_apd_confirm_ticks")]
    pub apd_confirm_ticks: u32,
    #[serde(default = "default_apd_cooldown_ms")]
    pub apd_cooldown_ms: u32,
    #[serde(default = "default_apd_drain_freeze_drr")]
    pub apd_drain_freeze_drr: bool,
    #[serde(default = "default_apd_sojourn_enabled")]
    pub apd_sojourn_enabled: bool,
    #[serde(default = "default_apd_max_sojourn_ms")]
    pub apd_max_sojourn_ms: u32,
    #[serde(default = "default_apd_target_sojourn_ms")]
    pub apd_target_sojourn_ms: u32,
    #[serde(default = "default_apd_require_cc_headroom")]
    pub apd_require_cc_headroom: bool,
    #[serde(default = "default_shed_enabled")]
    pub shed_enabled: bool,
    #[serde(default = "default_shed_max_sojourn_ms")]
    pub shed_max_sojourn_ms: u32,
    #[serde(default = "default_shed_min_fill")]
    pub shed_min_fill: f32,
    #[serde(default = "default_shed_max_per_tick")]
    pub shed_max_per_tick: u32,

    #[serde(default = "default_drr_enabled")]
    pub drr_enabled: bool,
    #[serde(default = "default_drr_small_packet_priority")]
    pub drr_small_packet_priority: bool,
    #[serde(default = "default_drr_small_packet_threshold_bytes")]
    pub drr_small_packet_threshold_bytes: u32,
    #[serde(default = "default_min_control_reserved_bytes_per_tick")]
    pub min_control_reserved_bytes_per_tick: u32,
    #[serde(default = "default_min_retransmit_reserved_bytes_per_tick")]
    pub min_retransmit_reserved_bytes_per_tick: u32,
    #[serde(default = "default_drr_rtt_aware")]
    pub drr_rtt_aware: bool,
    #[serde(default = "default_drr_rtt_scale_min")]
    pub drr_rtt_scale_min: f64,
    #[serde(default = "default_drr_rtt_scale_max")]
    pub drr_rtt_scale_max: f64,
    #[serde(default = "default_fec_enabled")]
    pub fec_enabled: bool,
    /// Non-zero with `fec_force_parity_shards` => fixed FEC ratio (see `fec_force_ratio` in CLI).
    #[serde(default)]
    pub fec_force_data_shards: u8,
    #[serde(default)]
    pub fec_force_parity_shards: u8,
    #[serde(default = "default_rawperf_enabled")]
    pub rawperf_enabled: bool,
    #[serde(default = "default_retransmit_bypass_pps")]
    pub retransmit_bypass_pps: f64,
    #[serde(default = "default_low_latency_timer_enabled")]
    pub low_latency_timer_enabled: bool,

    #[serde(default)]
    pub decentralized_enabled: bool,
    #[serde(default)]
    pub decentralized_trackers: Vec<String>,
    #[serde(default = "default_decentralized_announce_secs")]
    pub decentralized_announce_secs: u64,
    #[serde(default = "default_decentralized_join_deadline_secs")]
    pub decentralized_join_deadline_secs: u64,
    #[serde(default)]
    pub join_method: String,

    /// Runtime tuning (failover / timers / reliable / FEC / PMTUD / congestion).
    /// On disk these live in sectioned TOML tables via `config_toml` (not flattened).
    #[serde(default, flatten)]
    pub advanced: crate::advanced_tuning::AdvancedTuning,
}

fn default_pace_clock_mode() -> String {
    "hybrid".to_string()
}

fn default_pace_spin_window_us() -> i64 {
    crate::net::pacing_defaults::DEFAULT_PACE_SPIN_WINDOW_US
}

fn default_pace_fab_enabled() -> bool {
    crate::net::pacing_defaults::DEFAULT_PACE_FAB_ENABLED
}

fn default_pace_fab_fallback_tick_us() -> i64 {
    crate::net::pacing_defaults::DEFAULT_PACE_FAB_FALLBACK_TICK_US
}

fn default_tun_inject_queue_packets() -> i64 {
    crate::net::pacing_defaults::DEFAULT_TUN_INJECT_QUEUE
}

fn default_tun_from_adapter_queue_packets() -> i64 {
    crate::net::pacing_defaults::DEFAULT_TUN_FROM_ADAPTER_QUEUE
}

fn default_apd_drain_tick_us() -> u64 {
    crate::net::pacing_defaults::DEFAULT_APD_DRAIN_TICK_US
}

fn default_subnet_prefix() -> u8 {
    24
}

fn default_parasitic_use_public() -> bool {
    true
}

fn default_pace_rate_mode() -> String {
    "bytes".to_string()
}

fn default_pace_target_bps() -> i64 {
    50_000_000
}

fn default_wintun_ipv4_interface_metric() -> u32 {
    1
}

fn default_process_priority_level() -> u8 {
    2
}

fn default_apd_enabled() -> bool {
    true
}

fn default_apd_high_watermark() -> f32 {
    crate::net::pacing_defaults::DEFAULT_APD_HIGH_WM
}
fn default_apd_low_watermark() -> f32 {
    crate::net::pacing_defaults::DEFAULT_APD_LOW_WM
}
fn default_base_max_burst() -> i64 {
    crate::net::pacing_defaults::DEFAULT_PACE_BURST_PER_TICK
}
fn default_ramp_max_burst() -> u64 {
    crate::net::pacing_defaults::DEFAULT_RAMP_MAX_BURST
}
fn default_drain_max_burst() -> u64 {
    crate::net::pacing_defaults::DEFAULT_DRAIN_MAX_BURST
}
fn default_apd_spinloop_budget_ms() -> u32 {
    crate::net::pacing_defaults::DEFAULT_APD_SPINLOOP_BUDGET_MS
}
fn default_apd_confirm_ticks() -> u32 {
    crate::net::pacing_defaults::DEFAULT_APD_CONFIRM_TICKS
}
fn default_apd_cooldown_ms() -> u32 {
    crate::net::pacing_defaults::DEFAULT_APD_COOLDOWN_MS
}
fn default_apd_drain_freeze_drr() -> bool {
    true
}

fn default_apd_sojourn_enabled() -> bool {
    crate::net::pacing_defaults::DEFAULT_APD_SOJOURN_ENABLED
}

fn default_apd_max_sojourn_ms() -> u32 {
    crate::net::pacing_defaults::DEFAULT_APD_MAX_SOJOURN_MS
}

fn default_apd_target_sojourn_ms() -> u32 {
    crate::net::pacing_defaults::DEFAULT_APD_TARGET_SOJOURN_MS
}

fn default_apd_require_cc_headroom() -> bool {
    crate::net::pacing_defaults::DEFAULT_APD_REQUIRE_CC_HEADROOM
}

fn default_shed_enabled() -> bool {
    crate::net::pacing_defaults::DEFAULT_SHED_ENABLED
}

fn default_shed_max_sojourn_ms() -> u32 {
    crate::net::pacing_defaults::DEFAULT_SHED_MAX_SOJOURN_MS
}

fn default_shed_min_fill() -> f32 {
    crate::net::pacing_defaults::DEFAULT_SHED_MIN_FILL
}

fn default_shed_max_per_tick() -> u32 {
    crate::net::pacing_defaults::DEFAULT_SHED_MAX_PER_TICK
}

fn default_drr_enabled() -> bool {
    true
}

fn default_drr_small_packet_priority() -> bool {
    crate::net::pacing_defaults::DEFAULT_DRR_SMALL_PACKET_PRIORITY
}

fn default_drr_small_packet_threshold_bytes() -> u32 {
    crate::net::pacing_defaults::DEFAULT_DRR_SMALL_PACKET_THRESHOLD_BYTES
}

fn default_min_control_reserved_bytes_per_tick() -> u32 {
    crate::net::pacing_defaults::DEFAULT_MIN_CONTROL_RESERVED_BYTES_PER_TICK
}

fn default_min_retransmit_reserved_bytes_per_tick() -> u32 {
    crate::net::pacing_defaults::DEFAULT_MIN_RETRANSMIT_RESERVED_BYTES_PER_TICK
}

fn default_drr_rtt_aware() -> bool {
    crate::net::pacing_defaults::DEFAULT_DRR_RTT_AWARE
}

fn default_drr_rtt_scale_min() -> f64 {
    crate::net::pacing_defaults::DEFAULT_DRR_RTT_SCALE_MIN
}

fn default_drr_rtt_scale_max() -> f64 {
    crate::net::pacing_defaults::DEFAULT_DRR_RTT_SCALE_MAX
}

fn default_fec_enabled() -> bool {
    true
}

fn default_rawperf_enabled() -> bool {
    false
}

fn default_retransmit_bypass_pps() -> f64 {
    1000.0
}

fn default_low_latency_timer_enabled() -> bool {
    true
}

fn default_decentralized_announce_secs() -> u64 {
    120
}

fn default_decentralized_join_deadline_secs() -> u64 {
    120
}

/// Well-known public trackers used when `decentralized_trackers` is empty.
/// UDP (BEP15) + HTTP (BEP3) dual pairs are front-loaded for firewall diversity.
pub const DEFAULT_TRACKERS: &[&str] = &[
    // Dual prefix (udp then http, same host:port)
    "udp://tracker.opentrackr.org:1337/announce",
    "http://tracker.opentrackr.org:1337/announce",
    "udp://open.stealth.si:80/announce",
    "http://open.stealth.si:80/announce",
    "udp://open.tracker.cl:1337/announce",
    "http://open.tracker.cl:1337/announce",
    "udp://open.demonii.com:1337/announce",
    "http://open.demonii.com:1337/announce",
    "udp://zer0day.ch:1337/announce",
    "http://zer0day.ch:1337/announce",
    // UDP-only tail
    "udp://tracker.torrent.eu.org:451/announce",
    "udp://exodus.desync.com:6969/announce",
    "udp://tracker-udp.gbitt.info:80/announce",
    "udp://tracker.qu.ax:6969/announce",
    "udp://tracker.publictracker.xyz:6969/announce",
    "udp://evan.im:6969/announce",
    "udp://tracker.tryhackx.org:6969/announce",
    "udp://tracker.moeking.me:6969/announce",
    "udp://tracker.tiny-vps.com:6969/announce",
    "udp://wepzone.net:6969/announce",
    "udp://retracker.lanta-net.ru:2710/announce",
];

pub fn effective_decentralized_trackers(cfg: &NetworkConfig) -> Vec<String> {
    if cfg.decentralized_trackers.is_empty() {
        DEFAULT_TRACKERS.iter().map(|s| (*s).to_string()).collect()
    } else {
        cfg.decentralized_trackers.clone()
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        const UDP_SNDBUF_DEFAULT: i32 = 256 * 1024;
        const UDP_RCVBUF_DEFAULT: i32 = 2 * 1024 * 1024;
        Self {
            server_name: String::new(),
            network_id: String::new(),
            role: String::new(),
            virtual_ip: String::new(),
            owner_real_ip: String::new(),
            owner_port: 0,
            listen_port: 0,
            node_id: String::new(),
            crypto_key: String::new(),
            public_invite_code: String::new(),
            parasitic_enabled: false,
            parasitic_peer_vip: String::new(),
            parasitic_self_vip: String::new(),
            parasitic_peer_port: 0,
            parasitic_peer_node_id: String::new(),
            parasitic_self_is_owner: false,
            parasitic_use_public: true,
            peers: Vec::new(),
            owner_endpoints_cache: Vec::new(),
            membership_version: 0,
            last_membership_hash: String::new(),
            created_at: 0,
            udp_sndbuf: UDP_SNDBUF_DEFAULT,
            udp_rcvbuf: UDP_RCVBUF_DEFAULT,
            adapter_mtu: 1340,
            wintun_ring_bytes: 4 * 1024 * 1024,
            wintun_ipv4_interface_metric: default_wintun_ipv4_interface_metric(),
            pace_tick_us: crate::net::pacing_defaults::DEFAULT_PACE_TICK_US,
            pace_target_pps: crate::net::pacing_defaults::DEFAULT_PACE_TARGET_PPS,
            pace_rate_mode: default_pace_rate_mode(),
            pace_target_bps: default_pace_target_bps(),
            base_max_burst: default_base_max_burst(),
            pace_budget_cap_packets: crate::net::pacing_defaults::DEFAULT_PACE_BUDGET_PACKETS,
            pace_max_queue_packets: crate::net::pacing_defaults::DEFAULT_PACE_MAX_QUEUE,
            tun_inject_queue_packets: default_tun_inject_queue_packets(),
            tun_from_adapter_queue_packets: default_tun_from_adapter_queue_packets(),
            pace_clock_mode: default_pace_clock_mode(),
            pace_spin_window_us: default_pace_spin_window_us(),
            pace_fab_enabled: default_pace_fab_enabled(),
            pace_fab_fallback_tick_us: default_pace_fab_fallback_tick_us(),
            subnet_prefix: 24,
            cpu_affinity: String::new(),
            process_priority_level: default_process_priority_level(),
            apd_enabled: default_apd_enabled(),
            apd_high_watermark: default_apd_high_watermark(),
            apd_low_watermark: default_apd_low_watermark(),
            ramp_max_burst: default_ramp_max_burst(),
            drain_max_burst: default_drain_max_burst(),
            apd_spinloop_budget_ms: default_apd_spinloop_budget_ms(),
            apd_drain_tick_us: default_apd_drain_tick_us(),
            apd_confirm_ticks: default_apd_confirm_ticks(),
            apd_cooldown_ms: default_apd_cooldown_ms(),
            apd_drain_freeze_drr: default_apd_drain_freeze_drr(),
            apd_sojourn_enabled: default_apd_sojourn_enabled(),
            apd_max_sojourn_ms: default_apd_max_sojourn_ms(),
            apd_target_sojourn_ms: default_apd_target_sojourn_ms(),
            apd_require_cc_headroom: default_apd_require_cc_headroom(),
            shed_enabled: default_shed_enabled(),
            shed_max_sojourn_ms: default_shed_max_sojourn_ms(),
            shed_min_fill: default_shed_min_fill(),
            shed_max_per_tick: default_shed_max_per_tick(),
            drr_enabled: default_drr_enabled(),
            drr_small_packet_priority: default_drr_small_packet_priority(),
            drr_small_packet_threshold_bytes: default_drr_small_packet_threshold_bytes(),
            min_control_reserved_bytes_per_tick: default_min_control_reserved_bytes_per_tick(),
            min_retransmit_reserved_bytes_per_tick: default_min_retransmit_reserved_bytes_per_tick(
            ),
            drr_rtt_aware: default_drr_rtt_aware(),
            drr_rtt_scale_min: default_drr_rtt_scale_min(),
            drr_rtt_scale_max: default_drr_rtt_scale_max(),
            fec_enabled: default_fec_enabled(),
            fec_force_data_shards: 0,
            fec_force_parity_shards: 0,
            rawperf_enabled: default_rawperf_enabled(),
            retransmit_bypass_pps: default_retransmit_bypass_pps(),
            low_latency_timer_enabled: default_low_latency_timer_enabled(),
            decentralized_enabled: false,
            decentralized_trackers: Vec::new(),
            decentralized_announce_secs: default_decentralized_announce_secs(),
            decentralized_join_deadline_secs: default_decentralized_join_deadline_secs(),
            join_method: String::new(),
            advanced: crate::advanced_tuning::AdvancedTuning::default(),
        }
    }
}

impl NetworkConfig {
    /// Copies performance-related fields from `other` into `self`.
    /// Identity, session, peers, and network topology are unchanged.
    pub fn merge_performance_from(&mut self, other: &NetworkConfig) {
        self.udp_sndbuf = other.udp_sndbuf;
        self.udp_rcvbuf = other.udp_rcvbuf;
        self.adapter_mtu = other.adapter_mtu;
        self.wintun_ring_bytes = other.wintun_ring_bytes;
        self.wintun_ipv4_interface_metric = other.wintun_ipv4_interface_metric;
        self.pace_tick_us = other.pace_tick_us;
        self.pace_target_pps = other.pace_target_pps;
        self.pace_rate_mode = other.pace_rate_mode.clone();
        self.pace_target_bps = other.pace_target_bps;
        self.base_max_burst = other.base_max_burst;
        self.pace_budget_cap_packets = other.pace_budget_cap_packets;
        self.pace_max_queue_packets = other.pace_max_queue_packets;
        self.tun_inject_queue_packets = other.tun_inject_queue_packets;
        self.tun_from_adapter_queue_packets = other.tun_from_adapter_queue_packets;
        self.pace_clock_mode = other.pace_clock_mode.clone();
        self.pace_spin_window_us = other.pace_spin_window_us;
        self.pace_fab_enabled = other.pace_fab_enabled;
        self.pace_fab_fallback_tick_us = other.pace_fab_fallback_tick_us;
        self.cpu_affinity = other.cpu_affinity.clone();
        self.process_priority_level = other.process_priority_level;
        self.apd_enabled = other.apd_enabled;
        self.apd_high_watermark = other.apd_high_watermark;
        self.apd_low_watermark = other.apd_low_watermark;
        self.ramp_max_burst = other.ramp_max_burst;
        self.drain_max_burst = other.drain_max_burst;
        self.apd_spinloop_budget_ms = other.apd_spinloop_budget_ms;
        self.apd_drain_tick_us = other.apd_drain_tick_us;
        self.apd_confirm_ticks = other.apd_confirm_ticks;
        self.apd_cooldown_ms = other.apd_cooldown_ms;
        self.apd_drain_freeze_drr = other.apd_drain_freeze_drr;
        self.apd_sojourn_enabled = other.apd_sojourn_enabled;
        self.apd_max_sojourn_ms = other.apd_max_sojourn_ms;
        self.apd_target_sojourn_ms = other.apd_target_sojourn_ms;
        self.apd_require_cc_headroom = other.apd_require_cc_headroom;
        self.shed_enabled = other.shed_enabled;
        self.shed_max_sojourn_ms = other.shed_max_sojourn_ms;
        self.shed_min_fill = other.shed_min_fill;
        self.shed_max_per_tick = other.shed_max_per_tick;
        self.drr_enabled = other.drr_enabled;
        self.drr_small_packet_priority = other.drr_small_packet_priority;
        self.drr_small_packet_threshold_bytes = other.drr_small_packet_threshold_bytes;
        self.min_control_reserved_bytes_per_tick = other.min_control_reserved_bytes_per_tick;
        self.min_retransmit_reserved_bytes_per_tick = other.min_retransmit_reserved_bytes_per_tick;
        self.drr_rtt_aware = other.drr_rtt_aware;
        self.drr_rtt_scale_min = other.drr_rtt_scale_min;
        self.drr_rtt_scale_max = other.drr_rtt_scale_max;
        self.fec_enabled = other.fec_enabled;
        self.fec_force_data_shards = other.fec_force_data_shards;
        self.fec_force_parity_shards = other.fec_force_parity_shards;
        self.rawperf_enabled = other.rawperf_enabled;
        self.retransmit_bypass_pps = other.retransmit_bypass_pps;
        self.low_latency_timer_enabled = other.low_latency_timer_enabled;
        self.advanced = other.advanced.clone();
    }

    /// Resets only performance-related fields to [`NetworkConfig::default`] values.
    /// Identity, session, peers, and network topology are unchanged.
    pub fn reset_performance_fields(&mut self) {
        let d = Self::default();
        self.merge_performance_from(&d);
    }
}

pub struct ConfigManager {
    path: PathBuf,
    inner: Mutex<NetworkConfig>,
    snapshot: ArcSwap<NetworkConfig>,
    save_tx: mpsc::Sender<NetworkConfig>,
}

#[derive(Default)]
pub struct IPPool {
    prefix: Option<[u8; 3]>,
    allocated: HashMap<String, String>,
    vip_to_node: HashMap<String, String>,
    used: HashSet<u8>,
}

impl IPPool {
    pub fn new(owner_vip: &str) -> Self {
        let mut pool = Self::default();
        let octets: Vec<u8> = owner_vip
            .split('.')
            .filter_map(|v| v.parse::<u8>().ok())
            .collect();
        if octets.len() == 4 {
            pool.prefix = Some([octets[0], octets[1], octets[2]]);
            pool.used.insert(1);
        }
        pool
    }

    fn remove_octet_from_used(&mut self, vip: &str) {
        if let Some(last) = vip
            .split('.')
            .next_back()
            .and_then(|v| v.parse::<u8>().ok())
        {
            self.used.remove(&last);
        }
    }

    fn remove_allocated_entries_for_vip(&mut self, vip: &str) {
        let stale: Vec<String> = self
            .allocated
            .iter()
            .filter(|(_, v)| v.as_str() == vip)
            .map(|(n, _)| n.clone())
            .collect();
        for n in stale {
            self.allocated.remove(&n);
        }
    }

    pub fn allocate(&mut self, node_id: &str) -> Option<String> {
        if node_id.trim().is_empty() {
            return None;
        }
        if let Some(v) = self.allocated.get(node_id) {
            self.vip_to_node
                .entry(v.clone())
                .or_insert_with(|| node_id.to_string());
            return Some(v.clone());
        }
        let prefix = self.prefix?;
        for h in 2..=254u8 {
            if self.used.insert(h) {
                let vip = format!("{}.{}.{}.{}", prefix[0], prefix[1], prefix[2], h);
                self.allocated.insert(node_id.to_string(), vip.clone());
                self.vip_to_node.insert(vip.clone(), node_id.to_string());
                return Some(vip);
            }
        }
        None
    }

    pub fn release(&mut self, vip: &str) {
        let _ = self.vip_to_node.remove(vip);
        self.remove_allocated_entries_for_vip(vip);
        self.remove_octet_from_used(vip);
    }

    pub fn mark_used(&mut self, vip: &str) {
        if let Some(last) = vip
            .split('.')
            .next_back()
            .and_then(|v| v.parse::<u8>().ok())
        {
            self.used.insert(last);
        }
    }

    pub fn ensure_allocated(&mut self, node_id: &str, vip: &str) {
        let node_id = node_id.trim();
        let vip = vip.trim();
        if node_id.is_empty() || vip.is_empty() {
            return;
        }
        let node_owned = node_id.to_string();
        let vip_owned = vip.to_string();

        if let Some(old_node) = self.vip_to_node.get(vip).cloned() {
            if old_node != node_owned {
                self.remove_allocated_entries_for_vip(vip);
                self.vip_to_node.remove(vip);
            }
        }

        if let Some(prev_vip) = self.allocated.get(&node_owned).cloned() {
            if prev_vip != vip_owned {
                if self
                    .vip_to_node
                    .get(&prev_vip)
                    .map(|n| n == &node_owned)
                    .unwrap_or(false)
                {
                    self.vip_to_node.remove(&prev_vip);
                }
                self.remove_allocated_entries_for_vip(&prev_vip);
                self.remove_octet_from_used(&prev_vip);
            }
        }

        self.allocated.insert(node_owned.clone(), vip_owned.clone());
        self.vip_to_node.insert(vip_owned.clone(), node_owned);
        self.mark_used(&vip_owned);
    }
}

impl ConfigManager {
    pub fn new(path: PathBuf) -> Arc<Self> {
        let (save_tx, save_rx) = mpsc::channel::<NetworkConfig>();
        let save_path = path.clone();
        let _ = std::thread::Builder::new()
            .name("mint-config-save".to_string())
            .spawn(move || {
                while let Ok(mut pending) = save_rx.recv() {
                    while let Ok(next) = save_rx.try_recv() {
                        pending = next;
                    }
                    if let Err(err) = save_atomic(save_path.clone(), &pending) {
                        eprintln!("config save failed: {err}");
                    }
                }
            });
        Arc::new(Self {
            path,
            inner: Mutex::new(NetworkConfig::default()),
            snapshot: ArcSwap::from_pointee(NetworkConfig::default()),
            save_tx,
        })
    }

    pub fn snapshot(&self) -> Arc<NetworkConfig> {
        self.snapshot.load_full()
    }

    pub fn update<F: FnOnce(&mut NetworkConfig)>(&self, updater: F) {
        let mut guard = self.inner.lock();
        updater(&mut guard);
        let snapshot = Arc::new(guard.clone());
        self.snapshot.store(snapshot.clone());
        let _ = self.save_tx.send((*snapshot).clone());
    }

    pub fn load(&self) -> Result<()> {
        if !self.path.exists() {
            return Ok(());
        }
        let raw = std::fs::read_to_string(&self.path)?;
        let cfg = parse_network_config_toml(&raw)?;
        {
            let mut g = self.inner.lock();
            *g = cfg.clone();
        }
        self.snapshot.store(Arc::new(cfg));
        Ok(())
    }

    /// Merge performance fields from the on-disk TOML into the live config and persist.
    pub fn reload_performance_from_disk(&self) -> Result<()> {
        if !self.path.exists() {
            anyhow::bail!("config file not found: {}", self.path.display());
        }
        let raw = std::fs::read_to_string(&self.path)?;
        let disk = parse_network_config_toml(&raw)?;
        self.update(|live| live.merge_performance_from(&disk));
        Ok(())
    }

    pub fn add_peer(&self, peer: PeerInfo) {
        self.update(|cfg| {
            cfg.peers.retain(|p| p.virtual_ip != peer.virtual_ip);
            cfg.peers.push(peer);
        });
    }

    pub fn remove_peer_by_vip(&self, vip: &str) {
        self.update(|cfg| cfg.peers.retain(|p| p.virtual_ip != vip));
    }

    /// Joiner roster: VIP-keyed upsert with dirty no-op and FIFO cap.
    pub fn upsert_joiner_roster_peer(&self, peer: PeerInfo) {
        let snap = self.snapshot();
        if let Some(existing) = snap.peers.iter().find(|p| p.virtual_ip == peer.virtual_ip) {
            if existing == &peer {
                return;
            }
            let peer = peer.clone();
            self.update(move |cfg| {
                if let Some(slot) = cfg
                    .peers
                    .iter_mut()
                    .find(|p| p.virtual_ip == peer.virtual_ip)
                {
                    *slot = peer;
                }
            });
            return;
        }
        self.update(move |cfg| {
            while cfg.peers.len() >= JOINER_ROSTER_MAX {
                cfg.peers.remove(0);
            }
            cfg.peers.push(peer);
        });
    }

    /// Joiner roster remove; no-op if VIP absent.
    pub fn remove_joiner_roster_vip(&self, vip: &str) {
        if !self.snapshot().peers.iter().any(|p| p.virtual_ip == vip) {
            return;
        }
        self.remove_peer_by_vip(vip);
    }

    pub fn remove_peers_by_endpoint(&self, endpoint: &str, node_id: &str) -> Vec<PeerInfo> {
        let mut removed = Vec::new();
        self.update(|cfg| {
            let mut kept = Vec::with_capacity(cfg.peers.len());
            for p in cfg.peers.drain(..) {
                let endpoint_match = p.real_ip == endpoint;
                let node_match = !node_id.is_empty() && p.node_id == node_id;
                if endpoint_match || node_match {
                    removed.push(p);
                } else {
                    kept.push(p);
                }
            }
            cfg.peers = kept;
        });
        removed
    }

    pub fn find_peer_by_node_id(&self, node_id: &str) -> Option<PeerInfo> {
        if node_id.is_empty() {
            return None;
        }
        self.snapshot()
            .peers
            .iter()
            .find(|p| p.node_id == node_id)
            .cloned()
    }

    pub fn used_virtual_ips(&self) -> Vec<String> {
        let snap = self.snapshot();
        let mut out = Vec::with_capacity(snap.peers.len() + 1);
        for p in &snap.peers {
            if !p.virtual_ip.is_empty() {
                out.push(p.virtual_ip.clone());
            }
        }
        if !snap.virtual_ip.is_empty() {
            out.push(snap.virtual_ip.clone());
        }
        out
    }

    pub fn clear_and_delete(&self) -> Result<()> {
        {
            let mut g = self.inner.lock();
            *g = NetworkConfig::default();
            self.snapshot.store(Arc::new(NetworkConfig::default()));
        }
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }

    pub fn get_network_id(&self) -> String {
        self.snapshot().network_id.clone()
    }

    pub fn get_role(&self) -> String {
        self.snapshot().role.clone()
    }

    pub fn get_crypto_key_hex(&self) -> String {
        self.snapshot().crypto_key.clone()
    }

    pub fn get_listen_port(&self) -> u16 {
        self.snapshot().listen_port
    }

    pub fn set_network_basics(
        &self,
        server_name: String,
        network_id: String,
        role: String,
        virtual_ip: String,
        node_id: String,
        listen_port: u16,
    ) {
        self.update(|cfg| {
            cfg.server_name = server_name;
            cfg.network_id = network_id;
            cfg.role = role;
            cfg.virtual_ip = virtual_ip;
            cfg.node_id = node_id;
            cfg.listen_port = listen_port;
        });
    }
}

fn promote_tmp_to_path(tmp: &PathBuf, dest: &PathBuf) -> Result<()> {
    if std::fs::rename(tmp, dest).is_err() {
        #[cfg(windows)]
        {
            std::fs::copy(tmp, dest)?;
            let _ = std::fs::remove_file(tmp);
        }
        #[cfg(not(windows))]
        {
            std::fs::rename(tmp, dest)?;
        }
    }
    Ok(())
}

fn save_atomic(path: PathBuf, cfg: &NetworkConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = unique_tmp_path(&path);
    std::fs::write(&tmp, encode_network_config_toml(cfg)?)?;
    promote_tmp_to_path(&tmp, &path)?;
    Ok(())
}

fn unique_tmp_path(path: &PathBuf) -> PathBuf {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let mut ext = OsString::from("tmp.");
    ext.push(std::process::id().to_string());
    ext.push(".");
    ext.push(now_ms.to_string());
    path.with_extension(ext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joiner_roster_dirty_upsert_skips_unchanged() {
        let path = std::env::temp_dir().join(format!(
            "mint-roster-dirty-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        let mgr = ConfigManager::new(path.clone());
        let peer = PeerInfo {
            node_id: "n1".into(),
            name: "n1".into(),
            virtual_ip: "10.0.0.5".into(),
            real_ip: "1.2.3.4:5000".into(),
        };
        mgr.upsert_joiner_roster_peer(peer.clone());
        mgr.upsert_joiner_roster_peer(peer);
        assert_eq!(mgr.snapshot().peers.len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn joiner_roster_fifo_drops_oldest_on_new_vip() {
        let path = std::env::temp_dir().join(format!(
            "mint-roster-fifo-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        let mgr = ConfigManager::new(path.clone());
        for i in 0..JOINER_ROSTER_MAX {
            mgr.upsert_joiner_roster_peer(PeerInfo {
                node_id: format!("n{i}"),
                name: format!("n{i}"),
                virtual_ip: format!("10.0.0.{}", i + 2),
                real_ip: format!("1.2.3.4:{i}"),
            });
        }
        assert_eq!(mgr.snapshot().peers.len(), JOINER_ROSTER_MAX);
        mgr.upsert_joiner_roster_peer(PeerInfo {
            node_id: "new".into(),
            name: "new".into(),
            virtual_ip: "10.0.0.99".into(),
            real_ip: "9.9.9.9:1".into(),
        });
        let snap = mgr.snapshot();
        assert_eq!(snap.peers.len(), JOINER_ROSTER_MAX);
        assert!(!snap.peers.iter().any(|p| p.virtual_ip == "10.0.0.2"));
        assert!(snap.peers.iter().any(|p| p.virtual_ip == "10.0.0.99"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn concurrent_updates_persist_latest_snapshot() {
        let path = std::env::temp_dir().join(format!(
            "mint-config-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        let manager = ConfigManager::new(path.clone());
        let mut workers = Vec::new();
        for _ in 0..4 {
            let m = manager.clone();
            workers.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    m.update(|cfg| cfg.membership_version += 1);
                }
            }));
        }
        for w in workers {
            w.join().unwrap();
        }
        let expected = 200;
        assert_eq!(manager.snapshot().membership_version, expected);

        let mut persisted = None;
        for _ in 0..100 {
            if let Ok(raw) = std::fs::read_to_string(&path) {
                if let Ok(cfg) = parse_network_config_toml(&raw) {
                    persisted = Some(cfg.membership_version);
                    if cfg.membership_version == expected {
                        break;
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(persisted, Some(expected));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ippool_release_frees_mark_used_octet() {
        let mut pool = IPPool::new("10.0.0.1");
        pool.mark_used("10.0.0.5");
        assert!(pool.used.contains(&5));
        pool.release("10.0.0.5");
        assert!(!pool.used.contains(&5));
    }

    #[test]
    fn ippool_release_mark_used_then_allocate_reuses_octet() {
        let mut pool = IPPool::new("10.0.0.1");
        pool.allocate("a").expect("a");
        pool.allocate("b").expect("b");
        pool.allocate("c").expect("c");
        pool.mark_used("10.0.0.5");
        pool.release("10.0.0.5");
        let vip = pool.allocate("n1").expect("alloc after release");
        assert_eq!(vip, "10.0.0.5");
    }

    #[test]
    fn ippool_release_frees_allocated_octet() {
        let mut pool = IPPool::new("10.0.0.1");
        let vip = pool.allocate("n1").expect("alloc");
        pool.release(&vip);
        let vip2 = pool.allocate("n2").expect("realloc");
        assert_eq!(vip, vip2);
    }

    #[test]
    fn ippool_duplicate_release_is_safe() {
        let mut pool = IPPool::new("10.0.0.1");
        let vip = pool.allocate("node-z").expect("alloc");
        pool.release(&vip);
        pool.release(&vip);
        let vip2 = pool.allocate("node-y").expect("realloc");
        assert_eq!(vip, vip2);
    }

    #[test]
    fn ippool_ensure_allocated_updates_all_maps() {
        let mut pool = IPPool::new("10.0.0.1");
        pool.ensure_allocated("node-a", "10.0.0.7");
        assert_eq!(pool.allocated.get("node-a"), Some(&"10.0.0.7".to_string()));
        assert_eq!(
            pool.vip_to_node.get("10.0.0.7"),
            Some(&"node-a".to_string())
        );
        assert!(pool.used.contains(&7));
        pool.release("10.0.0.7");
        assert!(!pool.used.contains(&7));
        assert!(pool.allocated.get("node-a").is_none());
        assert!(pool.vip_to_node.get("10.0.0.7").is_none());
    }

    #[test]
    fn ippool_ensure_allocated_evicts_prior_owner_same_vip() {
        let mut pool = IPPool::new("10.0.0.1");
        let vip = pool.allocate("node-a").expect("alloc a");
        assert_eq!(vip, "10.0.0.2");
        pool.ensure_allocated("node-b", "10.0.0.2");
        assert!(pool.allocated.get("node-a").is_none());
        assert_eq!(pool.allocated.get("node-b"), Some(&"10.0.0.2".to_string()));
        assert_eq!(
            pool.vip_to_node.get("10.0.0.2"),
            Some(&"node-b".to_string())
        );
        assert_eq!(pool.allocate("node-a").expect("re-a"), "10.0.0.3");
    }

    #[test]
    fn ippool_ensure_allocated_node_changes_vip_frees_old_octet() {
        let mut pool = IPPool::new("10.0.0.1");
        pool.ensure_allocated("node-x", "10.0.0.5");
        assert!(pool.used.contains(&5));
        pool.ensure_allocated("node-x", "10.0.0.6");
        assert!(!pool.used.contains(&5));
        assert!(pool.used.contains(&6));
        assert_eq!(pool.allocated.get("node-x"), Some(&"10.0.0.6".to_string()));
        assert_eq!(
            pool.vip_to_node.get("10.0.0.6"),
            Some(&"node-x".to_string())
        );
        assert!(pool.vip_to_node.get("10.0.0.5").is_none());
    }

    #[test]
    fn ippool_release_removes_phantom_same_vip() {
        let mut pool = IPPool::new("10.0.0.1");
        pool.allocate("node-a").expect("a");
        pool.ensure_allocated("node-b", "10.0.0.2");
        pool.allocated
            .insert("phantom".to_string(), "10.0.0.2".to_string());
        pool.release("10.0.0.2");
        assert!(pool.allocated.values().all(|v| v.as_str() != "10.0.0.2"));
        assert!(!pool.used.contains(&2));
    }

    #[test]
    fn network_config_toml_round_trip_default() {
        let cfg = NetworkConfig::default();
        let raw = encode_network_config_toml(&cfg).expect("serialize");
        let back = parse_network_config_toml(&raw).expect("deserialize");
        assert_eq!(back, cfg);
    }

    #[test]
    fn network_config_toml_encode_is_sectioned_inline_probe_compact_wm() {
        let cfg = NetworkConfig::default();
        let raw = encode_network_config_toml(&cfg).expect("encode");
        for section in [
            "[session]",
            "[drr]",
            "[fec]",
            "[congestion]",
            "[pmtud]",
            "[apd]",
            "[timers]",
        ] {
            assert!(raw.contains(section), "missing section {section}: {raw}");
        }
        assert!(
            !raw.contains("[advanced]"),
            "must not write [advanced]: {raw}"
        );
        assert!(
            !raw.contains("[advanced."),
            "must not write nested advanced tables: {raw}"
        );
        // Tuning keys live under tables, not as root scalars before the first `[`.
        let root_prefix = raw.split('[').next().unwrap_or(&raw);
        assert!(
            !root_prefix.contains("keepalive_secs = "),
            "keepalive_secs must not be a root key: {raw}"
        );
        assert!(
            raw.contains(
                "probe_sizes = [1500, 1460, 1400, 1350, 1300, 1250, 1200, 1100, 1000, 576]"
            ),
            "probe_sizes must be a single inline line: {raw}"
        );
        assert!(
            raw.contains("apd_low_watermark = 0.1\n")
                || raw.contains("apd_low_watermark = 0.1\r\n"),
            "apd_low_watermark must not dump f32 noise: {raw}"
        );
        assert!(
            !raw.contains("0.10000000149011612"),
            "f32 binary expansion must not appear"
        );
        assert!(
            raw.contains("congestion_enabled = "),
            "congestion throttle flag must use congestion_enabled"
        );
    }

    #[test]
    fn network_config_toml_loads_sectioned_tuning_keys() {
        let sectioned = r#"
[session]
server_name = "s"
network_id = "n"
role = "peer"
virtual_ip = "10.0.0.2"
owner_real_ip = "1.2.3.4"
owner_port = 7878
listen_port = 7878
node_id = "id"
crypto_key = "aa"

[adapter]
udp_sndbuf = 262144
udp_rcvbuf = 1048576
adapter_mtu = 1340
wintun_ring_bytes = 2097152

[pacing]
pace_tick_us = 250
pace_target_pps = 24000
base_max_burst = 6
pace_budget_cap_packets = 8.0
pace_max_queue_packets = 64

[timers]
keepalive_secs = 9
stale_tick_secs = 50
stale_mark_secs = 40
stale_evict_secs = 30

[fec]
shard_payload_size = 9999
fec_max_total_shards = 32
fec_force_data_shards = 4
fec_force_parity_shards = 2

[routing_ewma]
rtt_ewma_old = 0.6
rtt_ewma_new = 0.4

[engine_limits]
max_direct_retry_per_tick = 64

[hole_punch]
punch_stage2_pps = 200
"#;
        let cfg = parse_network_config_toml(sectioned).expect("sectioned");
        assert_eq!(cfg.advanced.timers.keepalive_secs, 9);
        assert_eq!(
            cfg.advanced.fec.shard_payload_size,
            crate::net::fec::FEC_SHARD_PAYLOAD_SIZE
        );
        assert!((cfg.advanced.routing_ewma.rtt_ewma_old - 0.6).abs() < 1e-9);
        assert!((cfg.advanced.routing_ewma.rtt_ewma_new - 0.4).abs() < 1e-9);
        assert_eq!(cfg.advanced.engine_limits.max_direct_retry_per_tick, 64);
        assert_eq!(cfg.advanced.hole_punch.punch_stage2_pps, 200);
        assert_eq!(cfg.advanced.fec.fec_max_total_shards, 32);
        assert_eq!(cfg.fec_force_data_shards, 4);
        assert_eq!(cfg.fec_force_parity_shards, 2);
    }

    #[test]
    fn network_config_toml_rejects_unknown_root_table() {
        let nested = r#"
[session]
server_name = "s"
network_id = "n"
role = "peer"
virtual_ip = "10.0.0.2"
owner_real_ip = "1.2.3.4"
owner_port = 7878
listen_port = 7878
node_id = "id"
crypto_key = "aa"

[advanced]
keepalive_secs = 9
"#;
        let err = parse_network_config_toml(nested).expect_err("unknown root table must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("unknown field") || msg.contains("advanced"),
            "unexpected err: {err}"
        );
    }

    #[test]
    fn network_config_toml_partial_sections_clamp_on_load() {
        let raw = r#"
[session]
server_name = "s"
network_id = "n"
role = "peer"
virtual_ip = "10.0.0.2"
owner_real_ip = "1.2.3.4"
owner_port = 7878
listen_port = 7878
node_id = "id"
crypto_key = "aa"

[timers]
stale_tick_secs = 50
stale_mark_secs = 40
stale_evict_secs = 30

[fec]
shard_payload_size = 9999
"#;
        let cfg = parse_network_config_toml(raw).expect("parse partial");
        assert!(cfg.advanced.timers.stale_tick_secs < cfg.advanced.timers.stale_mark_secs);
        assert!(cfg.advanced.timers.stale_mark_secs < cfg.advanced.timers.stale_evict_secs);
        assert_eq!(
            cfg.advanced.fec.shard_payload_size,
            crate::net::fec::FEC_SHARD_PAYLOAD_SIZE
        );
    }

    #[test]
    fn reset_performance_fields_preserves_identity() {
        let mut cfg = NetworkConfig::default();
        cfg.server_name = "srv".into();
        cfg.network_id = "net-1".into();
        cfg.role = "owner".into();
        cfg.virtual_ip = "10.0.0.1".into();
        cfg.node_id = "node-a".into();
        cfg.crypto_key = "deadbeef".into();
        cfg.listen_port = 7878;
        cfg.peers.push(PeerInfo {
            node_id: "p1".into(),
            name: "peer".into(),
            virtual_ip: "10.0.0.2".into(),
            real_ip: "1.2.3.4:7878".into(),
        });
        cfg.membership_version = 42;
        cfg.public_invite_code = "invite".into();
        cfg.parasitic_enabled = true;
        cfg.parasitic_use_public = false;

        cfg.udp_sndbuf = 1;
        cfg.pace_tick_us = 9999;
        cfg.cpu_affinity = "2-4".into();
        cfg.process_priority_level = 3;

        let server_name = cfg.server_name.clone();
        let network_id = cfg.network_id.clone();
        let role = cfg.role.clone();
        let virtual_ip = cfg.virtual_ip.clone();
        let node_id = cfg.node_id.clone();
        let crypto_key = cfg.crypto_key.clone();
        let listen_port = cfg.listen_port;
        let peers_len = cfg.peers.len();
        let peer_node = cfg.peers[0].node_id.clone();
        let membership_version = cfg.membership_version;
        let public_invite_code = cfg.public_invite_code.clone();
        let parasitic_enabled = cfg.parasitic_enabled;
        let parasitic_use_public = cfg.parasitic_use_public;

        cfg.reset_performance_fields();

        let d = NetworkConfig::default();
        assert_eq!(cfg.udp_sndbuf, d.udp_sndbuf);
        assert_eq!(cfg.pace_tick_us, d.pace_tick_us);
        assert_eq!(cfg.cpu_affinity, d.cpu_affinity);
        assert_eq!(cfg.process_priority_level, d.process_priority_level);

        assert_eq!(cfg.server_name, server_name);
        assert_eq!(cfg.network_id, network_id);
        assert_eq!(cfg.role, role);
        assert_eq!(cfg.virtual_ip, virtual_ip);
        assert_eq!(cfg.node_id, node_id);
        assert_eq!(cfg.crypto_key, crypto_key);
        assert_eq!(cfg.listen_port, listen_port);
        assert_eq!(cfg.peers.len(), peers_len);
        assert_eq!(cfg.peers[0].node_id, peer_node);
        assert_eq!(cfg.membership_version, membership_version);
        assert_eq!(cfg.public_invite_code, public_invite_code);
        assert_eq!(cfg.parasitic_enabled, parasitic_enabled);
        assert_eq!(cfg.parasitic_use_public, parasitic_use_public);
    }

    #[test]
    fn reset_performance_fields_resets_advanced() {
        let mut cfg = NetworkConfig::default();
        cfg.advanced.reliable.retries_left = 5;
        cfg.advanced.timers.keepalive_secs = 99;
        assert_ne!(cfg.advanced, NetworkConfig::default().advanced);

        cfg.reset_performance_fields();

        assert_eq!(cfg.advanced, NetworkConfig::default().advanced);
        assert_eq!(cfg.advanced.reliable.retries_left, 1);
        assert_eq!(cfg.advanced.timers.keepalive_secs, 5);
    }

    #[test]
    fn reload_performance_from_disk_preserves_identity() {
        let path = std::env::temp_dir().join(format!(
            "mint-reload-perf-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        let mgr = ConfigManager::new(path.clone());
        mgr.update(|c| {
            c.network_id = "live-net".into();
            c.crypto_key = "secret".into();
            c.membership_version = 99;
            c.udp_sndbuf = 111;
        });
        std::thread::sleep(std::time::Duration::from_millis(50));

        let mut disk = mgr.snapshot().as_ref().clone();
        disk.udp_sndbuf = 222222;
        disk.pace_tick_us = 12345;
        std::fs::write(&path, encode_network_config_toml(&disk).unwrap()).unwrap();

        mgr.reload_performance_from_disk().unwrap();
        let snap = mgr.snapshot();
        assert_eq!(snap.network_id, "live-net");
        assert_eq!(snap.crypto_key, "secret");
        assert_eq!(snap.membership_version, 99);
        assert_eq!(snap.udp_sndbuf, 222222);
        assert_eq!(snap.pace_tick_us, 12345);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn decentralized_config_toml_round_trip() {
        let mut cfg = NetworkConfig::default();
        cfg.decentralized_enabled = true;
        cfg.decentralized_trackers = vec!["udp://example.com:1337/announce".into()];
        cfg.join_method = "decentralized".into();
        let raw = encode_network_config_toml(&cfg).unwrap();
        let back = parse_network_config_toml(&raw).unwrap();
        assert!(back.decentralized_enabled);
        assert_eq!(back.decentralized_trackers.len(), 1);
        assert_eq!(back.join_method, "decentralized");
        assert_eq!(back.decentralized_join_deadline_secs, 120);
    }

    #[test]
    fn network_config_toml_omitted_decentralized_fields_use_defaults() {
        let raw = r#"
[session]
server_name = "s"
network_id = "n"
role = "peer"
virtual_ip = "10.0.0.2"
owner_real_ip = "1.2.3.4"
owner_port = 7878
listen_port = 7878
node_id = "id"
crypto_key = "aa"

[pacing]
pace_tick_us = 250
pace_target_pps = 24000
base_max_burst = 6
pace_budget_cap_packets = 8.0
pace_max_queue_packets = 64
"#;
        let cfg = parse_network_config_toml(raw).expect("parse minimal toml");
        assert_eq!(cfg.base_max_burst, 6);
        assert!(!cfg.decentralized_enabled);
        assert!(cfg.decentralized_trackers.is_empty());
        assert_eq!(cfg.decentralized_announce_secs, 120);
        assert_eq!(cfg.decentralized_join_deadline_secs, 120);
        assert!(cfg.join_method.is_empty());
        assert!(!effective_decentralized_trackers(&cfg).is_empty());
    }

    fn tracker_authority(url: &str) -> Option<(String, u16)> {
        let ep = crate::nat::tracker::parse_tracker_endpoint(url)?;
        Some((ep.host, ep.port))
    }

    #[test]
    fn default_trackers_list_invariants() {
        assert_eq!(DEFAULT_TRACKERS.len(), 21);
        assert!(DEFAULT_TRACKERS.len() <= 28);
        for url in DEFAULT_TRACKERS {
            assert!(
                !url.starts_with("https://"),
                "default list must not include https: {url}"
            );
            assert!(
                crate::nat::tracker::parse_tracker_endpoint(url).is_some(),
                "unparseable tracker url: {url}"
            );
        }

        let mut udp_authorities: std::collections::HashSet<(String, u16)> =
            std::collections::HashSet::new();
        for url in DEFAULT_TRACKERS {
            if let Some(url) = url.strip_prefix("udp://") {
                let auth = url.split_once('/').map(|(a, _)| a).unwrap_or(url);
                if let Some((host, port)) = auth.rsplit_once(':') {
                    if let Ok(port) = port.parse::<u16>() {
                        udp_authorities.insert((host.to_string(), port));
                    }
                }
            }
        }
        for url in DEFAULT_TRACKERS {
            if url.starts_with("http://") {
                let auth = tracker_authority(url).expect("http url");
                assert!(
                    udp_authorities.contains(&auth),
                    "http entry missing udp sibling {:?}: {url}",
                    auth
                );
            }
        }

        let mut i = 0usize;
        while i + 1 < DEFAULT_TRACKERS.len() {
            let udp = DEFAULT_TRACKERS[i];
            let http = DEFAULT_TRACKERS[i + 1];
            if udp.starts_with("udp://")
                && http.starts_with("http://")
                && tracker_authority(udp) == tracker_authority(http)
            {
                i += 2;
            } else {
                break;
            }
        }
        assert_eq!(i, 10, "expected five udp+http dual pairs at list prefix");
        for url in &DEFAULT_TRACKERS[i..] {
            assert!(
                url.starts_with("udp://"),
                "udp-only tail expected, got: {url}"
            );
        }
    }

    #[test]
    fn shed_fields_round_trip_and_defaults() {
        let cfg = NetworkConfig::default();
        assert!(cfg.shed_enabled);
        assert_eq!(cfg.shed_max_sojourn_ms, 50);
        assert!((cfg.shed_min_fill - 0.2).abs() < f32::EPSILON);
        assert_eq!(cfg.shed_max_per_tick, 2);

        let raw = encode_network_config_toml(&cfg).expect("encode");
        let back = parse_network_config_toml(&raw).expect("decode");
        assert_eq!(back.shed_enabled, cfg.shed_enabled);
        assert_eq!(back.shed_max_sojourn_ms, cfg.shed_max_sojourn_ms);
        assert!((back.shed_min_fill - cfg.shed_min_fill).abs() < f32::EPSILON);
        assert_eq!(back.shed_max_per_tick, cfg.shed_max_per_tick);
    }

    #[test]
    fn merge_performance_copies_shed_fields() {
        let mut base = NetworkConfig::default();
        let mut src = NetworkConfig::default();
        src.shed_enabled = true;
        src.shed_max_sojourn_ms = 44;
        src.shed_min_fill = 0.72;
        src.shed_max_per_tick = 19;
        base.merge_performance_from(&src);
        assert!(base.shed_enabled);
        assert_eq!(base.shed_max_sojourn_ms, 44);
        assert!((base.shed_min_fill - 0.72).abs() < f32::EPSILON);
        assert_eq!(base.shed_max_per_tick, 19);
    }
}
