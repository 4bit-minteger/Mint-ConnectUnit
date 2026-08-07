use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::ui_events::UiSink;
use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use parking_lot::RwLock;
use serde::Deserialize;
use serde_json::json;
use smallvec::SmallVec;
use socket2::SockRef;
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::{interval, interval_at, Interval, MissedTickBehavior};

use crate::bcast::BroadcastDeduplicator;
use crate::config::PeerInfo;
use crate::crypto::{
    decode_wire_counter, derive_control_plane_material, derive_data_plane_material,
    floatunit_subnet_base_vip, now_epoch_ms, AeadKey, ControlPlaneAead, ControlRateLimiter,
    CtrlReplayTable, DataPlaneAead, DataReplayWindow, Key, DATA_TAG_LEN, WIRE_COUNTER_LEN,
};
use crate::metrics::EngineMetrics;
use crate::nat::{ice::IceCandidate, stun};
use crate::net::claim_gossip::{
    build_gossip_digest_rotated, claim_still_live, install_fight_suppress, install_leave_tombstone,
    merge_claim, prune_fight_suppress, prune_leave_tombstones, remove_claim, remove_claims_for_vip,
    rotate_endpoints, select_leave_tombs_for_gossip, settle_duplicate_vips,
    should_reroll_for_vip_fight, ClaimRecord, FightSuppress, LeaveTombstone,
    CLAIM_GOSSIP_DIGEST_MAX, CLAIM_GOSSIP_LEAVE_TOMBS_MAX, FIGHT_SUPPRESS_TTL, LEAVE_TOMBSTONE_TTL,
};
use crate::net::decentralized::{
    DecentralizedState, HttpAnnounceResult, TrackerDatagramEvent, DECENTRALIZED_RESOLVE_TIMEOUT,
};
use crate::net::fec::{
    adaptive_fec_ratio_hyst_tuned, effective_shard_payload_size, fec_delay_is_congestive,
    FecDecoder, FEC_SHARD_LEN_PREFIX,
};
use crate::net::fec_tx_worker::{
    start_fec_tx_worker, FecTxEvent, FecTxHandle, FecTxTuning, NormalOfferKind,
};
use crate::net::outbound_udp::OutboundUdpClock;
use crate::net::pacing::PacingQueueSnapshot;
use crate::net::pacing::{PacingConfig, PacingEngine};
use crate::net::pacing_worker::{start_pacing_worker, PacingEvent, PacingWorkerHandle};
use crate::net::packet::*;
use crate::net::punch_workflow;
use crate::net::reliable::{ReliableChannel, SendResult};
use crate::net::retransmit::RetransmitDirectSender;
use crate::net::size_loss::{replay_gap, SizeLossTable};
use crate::pmtud::{
    PathMtuDiscovery, PeerMtuSnapshot, PeerTickInput, SizeHealth, MIN_ADAPTER_PAYLOAD_MTU,
};
use crate::routing::{
    same_subnet, should_relay, should_relay_snap, PathKind, RelaySelection, RouteState,
    RoutingTable,
};
use crate::runtime_trace::RuntimeTrace;
use crate::term_style;

const STUN_QUERY_DEADLINE_SLACK: Duration = Duration::from_secs(2);
const DECENTRALIZED_JOIN_OVERLAY_KEY: &str = "decentralized-join-overlay";
const DECENTRALIZED_RECONNECT_FASTPATH_KEY: &str = "decentralized-reconnect-fastpath";
const PEER_RECONNECT_KEY_PREFIX: &str = "peer-reconnect:";
const PEER_RECONNECT_UNBOUND_KEY: &str = "peer-reconnect:unbound";
const PEER_RECONNECT_ANNOUNCE_BUDGET: usize = 8;
const PEER_RECONNECT_MAX_DISTINCT_KEYS: usize = 4;
const PEER_RECONNECT_COOLDOWN: Duration = Duration::from_secs(30);

use crate::net::pace_clock::{self, PaceClockApply, PaceClockShared};

#[derive(Debug, Clone)]
pub struct JoinAck {
    /// Acker peer VIP (route target), not an assigned VIP for the joiner.
    pub peer_vip: String,
    pub peer_node_id: String,
    pub subnet_prefix: u8,
    pub peer_endpoint: SocketAddr,
    /// Local VIP after any conflict resolution during handshake.
    pub local_vip: String,
    pub vip_epoch: u64,
}

fn try_deliver_join_ack(
    join_tx: &mut Option<oneshot::Sender<Option<JoinAck>>>,
    ack: JoinAck,
) -> bool {
    join_tx
        .take()
        .map(|tx| tx.send(Some(ack)).is_ok())
        .unwrap_or(false)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum ReliableDedupKey {
    VipU32(u32),
    Addr(SocketAddr),
}

#[derive(Debug)]
pub enum EngineCmd {
    Shutdown,
    PingAll,
    PeerRouteRemoved {
        vip: String,
    },
    SetCryptoKey(Key, Option<oneshot::Sender<()>>),
    AddCryptoKey(Key),
    BindPeerKey {
        peer: SocketAddr,
        key: Key,
    },
    SetJoinSender(oneshot::Sender<Option<JoinAck>>),
    PrepareJoin {
        join_tx: oneshot::Sender<Option<JoinAck>>,
        key: Key,
        /// Direct join target when known (manual join). Decentralized join may omit and rely on tracker fan-out.
        target: Option<SocketAddr>,
        body: Vec<u8>,
    },
    SendJoin {
        target: SocketAddr,
        body: Vec<u8>,
    },
    ManualPunch {
        target: SocketAddr,
        count: usize,
    },
    StartPunchWorkflow {
        key: String,
        bases: Vec<SocketAddr>,
        log_stages: bool,
    },
    StopPunchWorkflow {
        key: String,
    },
    SetPeerKeepalive {
        key: String,
        targets: Vec<SocketAddr>,
        interval_ms: u64,
    },
    StopPeerKeepalive {
        key: String,
    },
    SetIdentity {
        my_vip: String,
        my_node_id: String,
        subnet_prefix: u8,
        vip_epoch: u64,
        reply: Option<oneshot::Sender<()>>,
    },
    SetSocketBuffers {
        sndbuf: i32,
        rcvbuf: i32,
        reply: oneshot::Sender<(i32, i32)>,
    },
    SetPaceClock(PaceClockApply),
    SetPacing(PacingConfig),

    SetPacingAndPaceClock {
        cfg: PacingConfig,
        apply: PaceClockApply,
    },
    SetDrrEnabled(bool),
    SetRetransmitBypassPps(f64),
    SetRawPerf(bool),
    SetFecEnabled(bool),
    SetFecConfig {
        data_shards: u8,
        parity_shards: u8,
        force_ratio: bool,
    },
    /// Atomically apply the full advanced-tuning block (already clamped).
    /// `reply` receives the effective values after apply.
    ApplyAdvancedTuning {
        tuning: crate::advanced_tuning::AdvancedTuning,
        reply: oneshot::Sender<crate::advanced_tuning::AdvancedTuning>,
    },
    QueryFecStats {
        reply: oneshot::Sender<Vec<(SocketAddr, u8, u8, f64)>>,
    },
    SetCandidates(Vec<IceCandidate>),
    SendPeerRelay {
        relay_ep: SocketAddr,
        dst_node: String,
        kind: String,
        payload: serde_json::Value,
    },
    SetMembershipVersion(u64),
    BroadcastLeave {
        node_id: String,
        vip: String,
        vip_epoch: u64,
        event_id: String,
    },
    TriggerClaimGossip,
    QueryPublicEndpoint {
        timeout: Duration,
        force_refresh: bool,
        reply: oneshot::Sender<Option<stun::PublicEndpoint>>,
    },
    SetAdapterName(String),
    /// Freeze or unfreeze PMTUD from configured adapter MTU (`pin_mtu` + `adapter_mtu`).
    SetMtuPin {
        pin_mtu: bool,
        adapter_mtu: u16,
    },
    PingPeer {
        dest: SocketAddr,
        timeout_ms: u64,
        reply: oneshot::Sender<i64>,
    },
    ParaSendHello {
        target_vip: SocketAddr,
        payload: Vec<u8>,
    },
    ParaSendReply {
        target_vip: SocketAddr,
        payload: Vec<u8>,
    },
    ParaSendOk {
        target_vip: SocketAddr,
        payload: Vec<u8>,
    },
    ParaSendPunchAck {
        target: SocketAddr,
        payload: Vec<u8>,
    },
    ParaSetListener {
        notify_tx: mpsc::Sender<ParaSignal>,
        replace_existing: bool,
        reply: Option<oneshot::Sender<u64>>,
    },
    ParaRemoveListener {
        listener_id: u64,
    },
    QueryRuntimeSnapshot {
        reply: oneshot::Sender<RuntimeSnapshot>,
    },
    /// Enable + reset dashboard counters / traffic trace for a `runtime` view session.
    RuntimeViewBegin {
        reply: oneshot::Sender<()>,
    },
    /// Disable + reset dashboard counters / traffic trace when leaving `runtime`.
    RuntimeViewEnd {
        reply: oneshot::Sender<()>,
    },
    StartDecentralized {
        room_id: [u8; 20],
        trackers: Vec<String>,
        announce_secs: u64,
        is_joiner: bool,
        join_body: Option<Vec<u8>>,
        node_id: String,
    },
    StopDecentralized,
    CancelJoinWait,
    TakePendingJoinAck {
        reply: oneshot::Sender<Option<JoinAck>>,
    },
    QueryDiscoveredCount {
        reply: oneshot::Sender<usize>,
    },
    /// Full in-process session wipe (routing, crypto, punch, decentralized).
    /// Used by CLI `remove` so a later create/join on the same daemon is clean.
    ResetSession {
        reply: oneshot::Sender<()>,
    },
}

/// Engine-side snapshot for the CLI `runtime` live dashboard (1 Hz).
#[derive(Clone, Debug)]
pub struct RuntimeSnapshot {
    pub pacing: PacingQueueSnapshot,
    pub udp_sndbuf: i32,
    pub udp_rcvbuf: i32,
    pub tun_inject_capacity: usize,
    pub tun_inject_receivers: usize,
    pub pmtud_peers: Vec<PeerMtuSnapshot>,
    pub pin_mtu: bool,
    pub path_mtu: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ParaCandidate {
    pub ip: String,
    pub port: u16,
    pub kind: String,
}

#[derive(Debug, Clone)]
pub enum ParaSignal {
    HelloReceived {
        from: SocketAddr,
        public_ip: String,
        public_port: u16,
        network_id: String,
        node_id: String,
        candidates: Vec<ParaCandidate>,
        start_at_ms: u64,
        session_id: String,
    },
    ReplyReceived {
        from: SocketAddr,
        public_ip: String,
        public_port: u16,
        network_id: String,
        node_id: String,
        candidates: Vec<ParaCandidate>,
        agreed_start_at_ms: u64,
        session_id: String,
        responder_vip: String,
    },
    OkReceived {
        from: SocketAddr,
        node_id: String,
        session_id: String,
    },
    PunchAckReceived {
        from: SocketAddr,
        node_id: String,
        session_id: String,
    },
}

type LeaveHandler = Arc<dyn Fn(String) + Send + Sync>;
type EndpointLearnedHandler = Arc<dyn Fn(String, SocketAddr) + Send + Sync>;

#[derive(Clone, Debug)]
pub enum RosterChange {
    Upsert(PeerInfo),
    Remove(String),
}

type RosterChangedHandler = Arc<dyn Fn(RosterChange) + Send + Sync>;

/// old_vip, new_vip, vip_epoch
pub type IdentityChangedHandler = Arc<dyn Fn(String, String, u64) + Send + Sync>;

const VIP_REROLL_RETRY_INTERVAL: Duration = Duration::from_secs(30);

pub struct EngineState {
    pub crypto_keys: CryptoPool,
    pub data_ciphers: HashMap<(u32, u32), Arc<DataPlaneAead>>,
    pub control_ciphers: HashMap<[u8; 32], Arc<ControlPlaneAead>>,
    pub data_send_ctr: HashMap<u32, u64>,
    pub data_replay: HashMap<u32, DataReplayWindow>,
    pub my_vip: String,
    pub my_vip_u32: u32,
    pub my_node_id: String,
    pub vip_epoch: u64,
    pub candidates: Vec<IceCandidate>,
    pub tun_inject_tx: broadcast::Sender<Bytes>,
    pub join_tx: Option<oneshot::Sender<Option<JoinAck>>>,
    pub membership_version: u64,
    pub adapter_name: Option<String>,
    pub last_applied_adapter_mtu: u16,

    pub subnet_prefix: u8,

    feature_flags: RuntimeFeatureFlags,
    pub prev_path_kind: HashMap<u32, PathKind>,
    pub pending_heal_vips: HashSet<String>,
}

pub struct CryptoPool {
    primary: Option<Arc<AeadKey>>,
    extras: Vec<Arc<AeadKey>>,
    per_peer: HashMap<SocketAddr, Arc<AeadKey>>,
}

const MAX_EXTRA_KEYS: usize = 8;

impl CryptoPool {
    fn new() -> Self {
        Self {
            primary: None,
            extras: Vec::new(),
            per_peer: HashMap::new(),
        }
    }

    fn trim_extras(&mut self) {
        if self.extras.len() > MAX_EXTRA_KEYS {
            let n = self.extras.len() - MAX_EXTRA_KEYS;
            self.extras.drain(0..n);
        }
    }

    fn has_any(&self) -> bool {
        self.primary.is_some() || !self.extras.is_empty() || !self.per_peer.is_empty()
    }

    fn shared_signing_key(&self) -> Option<Arc<AeadKey>> {
        self.primary()
            .or_else(|| self.extras.last().cloned())
            .or_else(|| self.per_peer.values().next().cloned())
    }

    fn primary(&self) -> Option<Arc<AeadKey>> {
        self.primary.clone()
    }

    fn set_primary(&mut self, key: Key) -> Arc<AeadKey> {
        let key = Arc::new(AeadKey::from_key(key));
        self.primary = Some(key.clone());
        if !self.extras.iter().any(|k| k.as_ref() == key.as_ref()) {
            self.extras.push(key.clone());
        }
        self.trim_extras();
        key
    }

    fn add_key(&mut self, key: Key) -> Arc<AeadKey> {
        if let Some(existing) = self.primary.as_ref() {
            if existing.as_key().0 == key.0 {
                return existing.clone();
            }
        }
        if let Some(existing) = self
            .extras
            .iter()
            .find(|existing| existing.as_key().0 == key.0)
        {
            return existing.clone();
        }
        let ak = Arc::new(AeadKey::from_key(key));
        self.extras.push(ak.clone());
        self.trim_extras();
        ak
    }

    fn bind_peer_key(&mut self, peer: SocketAddr, key: Arc<AeadKey>) {
        self.per_peer.insert(peer, key);
    }

    fn unbind_peer(&mut self, peer: SocketAddr) {
        self.per_peer.remove(&peer);
    }

    fn prune_per_peer_orphans(&mut self, rt: &RoutingTable) {
        self.per_peer.retain(|addr, _| rt.tracks_endpoint(*addr));
    }

    fn key_for_peer(&self, peer: SocketAddr) -> Option<Arc<AeadKey>> {
        self.per_peer.get(&peer).cloned()
    }

    fn key_for_dest(&self, dest: SocketAddr) -> Option<Arc<AeadKey>> {
        self.key_for_peer(dest)
            .or_else(|| self.primary())
            .or_else(|| self.extras.last().cloned())
    }

    fn keys_for_decrypt(&self, source: SocketAddr) -> SmallVec<[Arc<AeadKey>; 10]> {
        let mut out: SmallVec<[Arc<AeadKey>; 10]> = SmallVec::new();
        let mut push_ptr_unique = |candidate: Arc<AeadKey>| {
            let ptr = Arc::as_ptr(&candidate);
            if out.iter().any(|k| Arc::as_ptr(k) == ptr) {
                return;
            }
            out.push(candidate);
        };
        if let Some(bound) = self.key_for_peer(source) {
            if self
                .primary
                .as_ref()
                .is_some_and(|p| Arc::ptr_eq(p, &bound))
            {
                push_ptr_unique(bound);
                return out;
            }
            push_ptr_unique(bound);
        }
        if let Some(primary) = self.primary() {
            push_ptr_unique(primary);
        }
        for extra in self.extras.iter().rev() {
            push_ptr_unique(extra.clone());
        }
        out
    }

    fn clear(&mut self) {
        self.primary = None;
        self.extras.clear();
        self.per_peer.clear();
    }

    #[cfg(test)]
    fn extras_len(&self) -> usize {
        self.extras.len()
    }
}

#[derive(Clone)]
pub(crate) struct PunchState {
    pub(crate) my_vip: String,
    pub(crate) crypto_key: Option<Arc<AeadKey>>,
    pub(crate) ctrl_send_ctr: Arc<AtomicU64>,
}

pub(crate) type PunchStateView = Arc<RwLock<PunchState>>;

#[derive(Default)]
struct PeerFecSendState {
    ratio_last: Option<(u8, u8)>,
    ratio_last_change: Option<Instant>,
    /// Last time queuing delay exceeded the congestive threshold (FEC recovery).
    last_congestive_at: Option<Instant>,
    /// Peer-reported wire-loss fraction from pong (`loss_permille/1000`). FEC-only.
    rx_loss_ewma: f64,
    queuing_delay_ms_cached: Option<f64>,
}

struct PacingThreadControl {
    stop: Arc<AtomicBool>,
    shared: Arc<PaceClockShared>,
    tick_skips: Arc<AtomicU64>,
    overshoots: Arc<AtomicU64>,
    adaptive_fallbacks: Arc<AtomicU64>,
    join: Option<JoinHandle<()>>,
}

pub struct P2PEngine {
    pub socket: Arc<UdpSocket>,
    pub routing: Arc<RwLock<RoutingTable>>,
    pacing: PacingWorkerHandle,
    pacing_tick_tx: mpsc::Sender<()>,
    pub reliable: ReliableChannel,
    retransmit_sender: RetransmitDirectSender,
    reliable_tick_buf: SmallVec<[(Bytes, SocketAddr); 8]>,
    reliable_failure_buf: Vec<(u32, SocketAddr)>,
    fec_send_by_dest: HashMap<SocketAddr, PeerFecSendState>,
    fec_decoders: HashMap<SocketAddr, FecDecoder>,
    fec_enabled: bool,
    fec_tx: FecTxHandle,
    last_fec_effective_shard: Option<usize>,
    advanced_tuning: crate::advanced_tuning::AdvancedTuning,
    fec_forced_ratio: Option<(u8, u8)>,
    fec_shard_payload_size: usize,
    fec_flush_standard: Duration,
    fec_flush_aggressive: Duration,
    fec_adaptive_off_below: f64,
    fec_adaptive_on_above: f64,
    encrypt_scratch: BytesMut,
    control_scratch: BytesMut,
    plain_data_scratch: BytesMut,
    decrypt_scratch: BytesMut,
    rawperf_mode: bool,
    pub pmtud: PathMtuDiscovery,
    /// Operator-requested MTU pin (`pin_mtu` config).
    mtu_pin: bool,
    /// Configured Wintun adapter MTU used when `mtu_pin` is true.
    configured_adapter_mtu: u16,
    size_loss: SizeLossTable,
    pub bcast_dedup: BroadcastDeduplicator,
    pub tun_rx: mpsc::Receiver<Bytes>,
    pub cmd_rx: mpsc::Receiver<EngineCmd>,
    pub state: EngineState,
    state_view: Arc<RwLock<PunchState>>,
    pub leave_handler: Option<LeaveHandler>,
    pub endpoint_learned_handler: Option<EndpointLearnedHandler>,
    roster_changed_handler: Option<RosterChangedHandler>,
    identity_changed_handler: Option<IdentityChangedHandler>,
    reliable_seen: HashSet<(ReliableDedupKey, u32)>,
    reliable_seen_timeline: VecDeque<(tokio::time::Instant, ReliableDedupKey, u32)>,
    /// Leave event dedupe (reused for MLEA deduplication).
    msmd_seen: HashSet<Arc<str>>,
    msmd_timeline: VecDeque<(tokio::time::Instant, Arc<str>)>,
    claim_map: HashMap<String, ClaimRecord>,
    leave_tombs: HashMap<String, LeaveTombstone>,
    fight_suppress: HashMap<String, FightSuppress>,
    pending_claim_gossip: bool,
    vip_reroll_retry_after: Option<Instant>,
    claim_gossip_digest_cursor: usize,
    claim_gossip_fanout_cursor: usize,
    manual_punch_stops: HashMap<String, Arc<AtomicBool>>,
    ice_check_stops: HashMap<String, Arc<AtomicBool>>,
    peer_keepalive_stops: HashMap<String, Arc<AtomicBool>>,
    ctrl_send_ctr: Arc<AtomicU64>,
    ctrl_replay: CtrlReplayTable,
    ctrl_limiter: ControlRateLimiter,

    plain_data_limiter: ControlRateLimiter,
    join_rate_limiter: ControlRateLimiter,
    join_ip_rate_limiter: ControlRateLimiter,
    keepalive_interval: Interval,
    sync_interval: Interval,
    direct_retry_interval: Interval,
    direct_retry_cursor: usize,
    pmtud_interval: Interval,
    stale_evict_interval: Interval,
    rx_bw_flush_interval: Interval,
    pacing_thread: PacingThreadControl,
    stun_poll_interval: Interval,
    stun_keepalive_interval: Interval,
    stun_keepalive_addr: Option<SocketAddr>,
    pending_stun_queries: HashMap<u64, PendingStunQuery>,
    stun_resolve_tx: mpsc::UnboundedSender<ResolvedStunQuery>,
    stun_resolve_rx: mpsc::UnboundedReceiver<ResolvedStunQuery>,
    next_stun_query_id: u64,
    active_stun_query_ids: HashSet<u64>,
    cached_stun_endpoint: Option<(Instant, stun::PublicEndpoint)>,
    pending_pings: HashMap<u64, PendingPing>,
    next_ping_id: u64,
    /// Consecutive CC-probe timeouts per endpoint (reset on any matched pong).
    probe_miss_by_ep: HashMap<SocketAddr, u32>,
    heal_cooldown_until: HashMap<String, Instant>,
    ping_watchdog_interval: Interval,
    cc_probe_interval: Interval,
    cc_probe_cursor: usize,
    para_notify_txs: HashMap<u64, mpsc::Sender<ParaSignal>>,
    next_para_listener_id: u64,
    metrics: Arc<EngineMetrics>,
    last_prepare_join_at: Option<Instant>,
    last_tun_inject_drop_warn: Option<Instant>,

    last_pmtud_netsh_at: Option<Instant>,
    last_relay_stale_drop_warn: Option<Instant>,
    last_relay_degraded_no_hop_warn: Option<Instant>,
    last_reliable_seen_warn: Option<Instant>,

    rx_bytes_pending: HashMap<SocketAddr, u64>,
    last_seen_pending: HashMap<SocketAddr, Instant>,
    rx_bytes_pending_vip: HashMap<u32, u64>,

    broadcast_scratch: Vec<SocketAddr>,
    cc_probe_scratch: Vec<SocketAddr>,
    tick_done_seq: u64,
    runtime_trace: Arc<RuntimeTrace>,
    applied_udp_sndbuf: i32,
    applied_udp_rcvbuf: i32,
    tun_inject_capacity: usize,
    ui: UiSink,
    decentralized: DecentralizedState,
    decentralized_interval: Interval,
    decentralized_resolve_tx: mpsc::UnboundedSender<(usize, Vec<SocketAddr>)>,
    decentralized_resolve_rx: mpsc::UnboundedReceiver<(usize, Vec<SocketAddr>)>,
    decentralized_http_tx: mpsc::UnboundedSender<HttpAnnounceResult>,
    decentralized_http_rx: mpsc::UnboundedReceiver<HttpAnnounceResult>,
    pending_join_ack: Option<JoinAck>,
    join_overlay_last_peers: HashSet<SocketAddr>,
    reconnect_fastpath_last_ep: Option<SocketAddr>,
    reconnect_fastpath_last_at: Option<Instant>,
    peer_reconnect_cooldown_until: HashMap<String, Instant>,
    outbound_udp: Arc<OutboundUdpClock>,
}

struct PendingPing {
    dest: SocketAddr,
    allow_ip_match: bool,
    deadline: Instant,
    sent_at_ms: u64,
    kind: PendingPingKind,
}

enum PendingPingKind {
    User { reply: oneshot::Sender<i64> },
    Heal { vip: String, endpoint: SocketAddr },
    Probe,
}

/// Increment consecutive probe-miss streak; returns true when streak >= threshold
/// (caller should `note_fail` at most once per endpoint per expire sweep).
fn record_probe_miss(
    streak: &mut HashMap<SocketAddr, u32>,
    dest: SocketAddr,
    threshold: u32,
) -> bool {
    let n = streak.entry(dest).or_insert(0);
    *n = n.saturating_add(1);
    *n >= threshold
}

struct PendingStunQuery {
    votes: HashMap<String, usize>,
    txns: HashMap<[u8; 12], ()>,
    deadline: Instant,
    reply: oneshot::Sender<Option<stun::PublicEndpoint>>,

    early_stun: Vec<Bytes>,
}

struct ResolvedStunQuery {
    query_id: u64,
    txns: HashMap<[u8; 12], ()>,
    chosen_stun_addr: Option<SocketAddr>,
    timeout: Duration,
}

fn new_cc_probe_interval(cg: &crate::advanced_tuning::CongestionTuning) -> Interval {
    let ms = crate::advanced_tuning::cc_probe_timer_period_ms(cg.probe_interval_ms);
    let period = Duration::from_millis(ms);
    let now = tokio::time::Instant::now();
    let mut i = interval_at(now + period, period);
    i.set_missed_tick_behavior(MissedTickBehavior::Delay);
    i
}

fn new_pacing_stack(
    socket: Arc<UdpSocket>,
    pace_clock_apply: PaceClockApply,
    initial_pace_tick_us: u64,
    initial_pacing: PacingEngine,
    outbound_udp: Arc<OutboundUdpClock>,
    metrics: Arc<EngineMetrics>,
) -> (PacingWorkerHandle, mpsc::Sender<()>, PacingThreadControl) {
    let tick = pace_clock::clamp_tick_us(initial_pace_tick_us);
    let tick_skips = Arc::new(AtomicU64::new(0));
    let overshoots = Arc::new(AtomicU64::new(0));
    let adaptive_fallbacks = Arc::new(AtomicU64::new(0));
    let shared = Arc::new(PaceClockShared::new(pace_clock_apply, tick));
    let mut initial_pacing = initial_pacing;
    if initial_pacing.config.tick_us != tick {
        let mut cfg = initial_pacing.config;
        cfg.tick_us = tick;
        initial_pacing.set_config(cfg);
    }
    let spawn = start_pacing_worker(
        socket,
        shared.clone(),
        initial_pacing,
        outbound_udp,
        metrics,
    );
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let join = pace_clock::start_pace_clock_thread(
        spawn.tick_tx.clone(),
        shared.clone(),
        stop_thread,
        tick_skips.clone(),
        overshoots.clone(),
        adaptive_fallbacks.clone(),
    );
    let control = PacingThreadControl {
        stop,
        shared,
        tick_skips,
        overshoots,
        adaptive_fallbacks,
        join,
    };
    (spawn.handle, spawn.tick_tx, control)
}

#[derive(Debug, Deserialize)]
struct ParaHelloMsg {
    node_id: String,
    public_ip: String,
    public_port: u16,
    #[serde(default)]
    network_id: String,
    ts_ms: u64,
    #[serde(default)]
    candidates: Vec<ParaCandidate>,
    #[serde(default)]
    start_at_ms: u64,
    #[serde(default)]
    session_id: String,
}

#[derive(Debug, Deserialize)]
struct ParaReplyMsg {
    node_id: String,
    public_ip: String,
    public_port: u16,
    #[serde(default)]
    network_id: String,
    ts_ms: u64,
    #[serde(default)]
    candidates: Vec<ParaCandidate>,
    #[serde(default)]
    agreed_start_at_ms: u64,
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    responder_vip: String,
}

#[derive(Debug, Deserialize)]
struct ParaOkMsg {
    node_id: String,
    ts_ms: u64,
    #[serde(default)]
    session_id: String,
}

#[derive(Debug, Deserialize)]
struct ParaPunchAckMsg {
    node_id: String,
    ts_ms: u64,
    #[serde(default)]
    session_id: String,
}

#[derive(Debug, Clone, Copy)]
struct RuntimeFeatureFlags {
    multipath_core: bool,
    dual_write_transition: bool,
    predictive_heal: bool,
    multipath_bandwidth_prober: bool,
    control_path_race: bool,
}

impl Default for RuntimeFeatureFlags {
    fn default() -> Self {
        Self {
            multipath_core: true,
            dual_write_transition: true,
            predictive_heal: true,
            multipath_bandwidth_prober: false,
            control_path_race: true,
        }
    }
}

impl P2PEngine {
    pub fn new(
        socket: Arc<UdpSocket>,
        routing: Arc<RwLock<RoutingTable>>,
        tun_rx: mpsc::Receiver<Bytes>,
        tun_inject_tx: broadcast::Sender<Bytes>,
        cmd_rx: mpsc::Receiver<EngineCmd>,
        my_vip: Ipv4Addr,
        my_node_id: String,
        subnet_prefix: u8,
        metrics: Arc<EngineMetrics>,
        pace_clock_apply: PaceClockApply,
        initial_pace_tick_us: u64,
        runtime_trace: Arc<RuntimeTrace>,
        tun_inject_capacity: usize,
        ui: UiSink,
    ) -> Self {
        let default_buffers = crate::advanced_tuning::AdvancedTuning::default().buffers;
        let sock_ref = SockRef::from(&*socket);
        let applied_udp_sndbuf = sock_ref.send_buffer_size().unwrap_or(256 * 1024) as i32;
        let applied_udp_rcvbuf = sock_ref.recv_buffer_size().unwrap_or(1024 * 1024) as i32;
        let tun_inject_capacity = tun_inject_capacity.max(1);
        let my_vip_s = my_vip.to_string();
        let subnet_prefix = subnet_prefix.clamp(8, 30);
        let mut keepalive_interval = interval(Duration::from_secs(5));
        keepalive_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut sync_interval = interval(Duration::from_secs(15));
        sync_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut direct_retry_interval = interval(Duration::from_secs(5));
        direct_retry_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut pmtud_interval = interval(Duration::from_secs(60));
        pmtud_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut stale_evict_interval = interval(Duration::from_secs(30));
        stale_evict_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut rx_bw_flush_interval = interval(Duration::from_millis(250));
        rx_bw_flush_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let outbound_udp = OutboundUdpClock::shared();
        let (pacing, pacing_tick_tx, pacing_thread) = new_pacing_stack(
            socket.clone(),
            pace_clock_apply,
            initial_pace_tick_us,
            PacingEngine::new(),
            outbound_udp.clone(),
            metrics.clone(),
        );
        let fec_tx = start_fec_tx_worker(
            pacing.ingress.clone(),
            metrics.clone(),
            FecTxTuning {
                shard: crate::net::fec::FEC_SHARD_PAYLOAD_SIZE,
                flush_std: crate::net::fec::FEC_FLUSH_TIMEOUT,
                flush_agg: crate::net::fec::FEC_FLUSH_TIMEOUT_AGGRESSIVE,
                frame_scratch: default_buffers.fec_frame_scratch_bytes,
            },
        );
        let mut stun_poll_interval = interval(Duration::from_millis(200));
        stun_poll_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut stun_keepalive_interval = interval(Duration::from_secs(5));
        stun_keepalive_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut ping_watchdog_interval = interval(Duration::from_millis(150));
        ping_watchdog_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let cc_probe_interval =
            new_cc_probe_interval(&crate::advanced_tuning::CongestionTuning::default());
        let mut decentralized_interval = interval(Duration::from_secs(5));
        decentralized_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let (stun_resolve_tx, stun_resolve_rx) = mpsc::unbounded_channel();
        let (decentralized_resolve_tx, decentralized_resolve_rx) = mpsc::unbounded_channel();
        let (decentralized_http_tx, decentralized_http_rx) = mpsc::unbounded_channel();
        let ctrl_send_ctr = Arc::new(AtomicU64::new(0));
        let state_view = Arc::new(RwLock::new(PunchState {
            my_vip: my_vip_s.clone(),
            crypto_key: None,
            ctrl_send_ctr: ctrl_send_ctr.clone(),
        }));
        Self {
            socket,
            routing,
            pacing,
            pacing_tick_tx,
            reliable: ReliableChannel::new(),
            retransmit_sender: RetransmitDirectSender::new(1000.0),
            reliable_tick_buf: SmallVec::new(),
            reliable_failure_buf: Vec::new(),
            fec_send_by_dest: HashMap::new(),
            fec_decoders: HashMap::new(),
            fec_enabled: true,
            fec_tx,
            last_fec_effective_shard: None,
            advanced_tuning: crate::advanced_tuning::AdvancedTuning::default(),
            fec_forced_ratio: None,
            fec_shard_payload_size: 1024,
            fec_flush_standard: crate::net::fec::FEC_FLUSH_TIMEOUT,
            fec_flush_aggressive: crate::net::fec::FEC_FLUSH_TIMEOUT_AGGRESSIVE,
            fec_adaptive_off_below: 0.025,
            fec_adaptive_on_above: 0.05,
            encrypt_scratch: BytesMut::with_capacity(default_buffers.encrypt_scratch_bytes),
            control_scratch: BytesMut::with_capacity(default_buffers.control_scratch_bytes),
            plain_data_scratch: BytesMut::with_capacity(default_buffers.plain_data_scratch_bytes),
            decrypt_scratch: BytesMut::with_capacity(default_buffers.decrypt_scratch_bytes),
            rawperf_mode: false,
            pmtud: PathMtuDiscovery::new(),
            mtu_pin: false,
            configured_adapter_mtu: 1340,
            size_loss: SizeLossTable::new(),
            bcast_dedup: BroadcastDeduplicator::new(),
            tun_rx,
            cmd_rx,
            state_view,
            state: EngineState {
                crypto_keys: CryptoPool::new(),
                data_ciphers: HashMap::new(),
                control_ciphers: HashMap::new(),
                data_send_ctr: HashMap::new(),
                data_replay: HashMap::new(),
                my_vip: my_vip_s,
                my_vip_u32: u32::from(my_vip),
                my_node_id,
                vip_epoch: 0,
                candidates: Vec::new(),
                tun_inject_tx,
                join_tx: None,
                membership_version: 0,
                adapter_name: None,
                last_applied_adapter_mtu: 0,
                subnet_prefix,
                feature_flags: RuntimeFeatureFlags::default(),
                prev_path_kind: HashMap::new(),
                pending_heal_vips: HashSet::new(),
            },
            leave_handler: None,
            endpoint_learned_handler: None,
            roster_changed_handler: None,
            identity_changed_handler: None,
            reliable_seen: HashSet::new(),
            reliable_seen_timeline: VecDeque::new(),
            msmd_seen: HashSet::new(),
            msmd_timeline: VecDeque::new(),
            claim_map: HashMap::new(),
            leave_tombs: HashMap::new(),
            fight_suppress: HashMap::new(),
            pending_claim_gossip: false,
            vip_reroll_retry_after: None,
            claim_gossip_digest_cursor: 0,
            claim_gossip_fanout_cursor: 0,
            manual_punch_stops: HashMap::new(),
            ice_check_stops: HashMap::new(),
            peer_keepalive_stops: HashMap::new(),
            ctrl_send_ctr,
            ctrl_replay: CtrlReplayTable::new(),
            ctrl_limiter: ControlRateLimiter::new(400.0, 400.0),
            plain_data_limiter: ControlRateLimiter::new(200.0, 200.0),
            join_rate_limiter: ControlRateLimiter::new(8.0, 4.0),
            join_ip_rate_limiter: ControlRateLimiter::new(32.0, 16.0),
            keepalive_interval,
            sync_interval,
            direct_retry_interval,
            direct_retry_cursor: 0,
            pmtud_interval,
            stale_evict_interval,
            rx_bw_flush_interval,
            pacing_thread,
            stun_poll_interval,
            stun_keepalive_interval,
            stun_keepalive_addr: None,
            pending_stun_queries: HashMap::new(),
            stun_resolve_tx,
            stun_resolve_rx,
            next_stun_query_id: 1,
            active_stun_query_ids: HashSet::new(),
            cached_stun_endpoint: None,
            pending_pings: HashMap::new(),
            next_ping_id: 1,
            probe_miss_by_ep: HashMap::new(),
            heal_cooldown_until: HashMap::new(),
            ping_watchdog_interval,
            cc_probe_interval,
            cc_probe_cursor: 0,
            para_notify_txs: HashMap::new(),
            next_para_listener_id: 1,
            metrics,
            last_prepare_join_at: None,
            last_tun_inject_drop_warn: None,
            last_pmtud_netsh_at: None,
            last_relay_stale_drop_warn: None,
            last_relay_degraded_no_hop_warn: None,
            last_reliable_seen_warn: None,
            rx_bytes_pending: HashMap::new(),
            last_seen_pending: HashMap::new(),
            rx_bytes_pending_vip: HashMap::new(),
            broadcast_scratch: Vec::new(),
            cc_probe_scratch: Vec::new(),
            tick_done_seq: 0,
            runtime_trace,
            applied_udp_sndbuf,
            applied_udp_rcvbuf,
            tun_inject_capacity,
            ui,
            decentralized: DecentralizedState::default(),
            decentralized_interval,
            decentralized_resolve_tx,
            decentralized_resolve_rx,
            decentralized_http_tx,
            decentralized_http_rx,
            pending_join_ack: None,
            join_overlay_last_peers: HashSet::new(),
            reconnect_fastpath_last_ep: None,
            reconnect_fastpath_last_at: None,
            peer_reconnect_cooldown_until: HashMap::new(),
            outbound_udp,
        }
    }

    fn cached_public_socket_addr(&self) -> Option<SocketAddr> {
        self.cached_stun_endpoint.as_ref().and_then(|(_, ep)| {
            ep.ip
                .parse::<Ipv4Addr>()
                .ok()
                .map(|ip| SocketAddr::from((ip, ep.port)))
        })
    }

    fn stop_decentralized_discovery(&mut self) {
        self.decentralized.stop();
        self.reconnect_fastpath_last_ep = None;
        self.reconnect_fastpath_last_at = None;
        self.stop_join_punch_overlay();
        self.stop_decentralized_reconnect_fastpath();
        self.stop_all_peer_reconnect_workflows();
        if let Some(stop) = self.manual_punch_stops.remove("decentralized") {
            stop.store(true, Ordering::Release);
        }
    }

    fn stop_decentralized_reconnect_fastpath(&mut self) {
        if let Some(stop) = self
            .manual_punch_stops
            .remove(DECENTRALIZED_RECONNECT_FASTPATH_KEY)
        {
            stop.store(true, Ordering::Release);
        }
    }

    fn reset_reconnect_fastpath_state(&mut self) {
        self.reconnect_fastpath_last_ep = None;
        self.reconnect_fastpath_last_at = None;
        self.stop_decentralized_reconnect_fastpath();
    }

    fn stop_join_punch_overlay_task(&mut self) {
        if let Some(stop) = self
            .manual_punch_stops
            .remove(DECENTRALIZED_JOIN_OVERLAY_KEY)
        {
            stop.store(true, Ordering::Release);
        }
    }

    fn stop_join_punch_overlay(&mut self) {
        self.stop_join_punch_overlay_task();
        self.join_overlay_last_peers.clear();
    }

    fn stop_punch_workflow_key(&mut self, key: &str) {
        if let Some(stop) = self.manual_punch_stops.remove(key) {
            stop.store(true, Ordering::Release);
        }
    }

    fn spawn_punch_workflow(&mut self, key: &str, bases: Vec<SocketAddr>, log_stages: bool) {
        if bases.is_empty() {
            return;
        }
        self.stop_punch_workflow_key(key);
        let stop = Arc::new(AtomicBool::new(false));
        self.manual_punch_stops
            .insert(key.to_string(), stop.clone());
        let socket = self.socket.clone();
        let state_view = self.state_view.clone();
        let ui = self.ui.clone();
        let punch = self.advanced_tuning.hole_punch;
        tokio::spawn(async move {
            punch_workflow::run_canonical_punch_workflow(
                socket,
                state_view,
                bases,
                punch,
                stop,
                log_stages,
                move |stage| {
                    if log_stages {
                        ui.emit_plain_live(format!("[PUNCH] \"Stage\": {stage}"));
                        ui.emit_plain_live("waiting...".to_string());
                    }
                },
            )
            .await;
        });
    }

    fn spawn_decentralized_join_punch(&mut self) {
        if self.state.join_tx.is_none() || !self.decentralized.is_joiner() {
            return;
        }
        let bases = self
            .decentralized
            .join_punch_base_targets(self.cached_public_socket_addr());
        let bases = self.filter_decentralized_punch_targets(bases);
        if bases.is_empty() {
            return;
        }
        self.stop_join_punch_overlay_task();
        self.spawn_punch_workflow(DECENTRALIZED_JOIN_OVERLAY_KEY, bases, true);
    }

    fn on_join_wait_finished(&mut self) {
        // MPJA accepted: leave join-wait UI/punch mode immediately (tracker logs + intensity).
        self.decentralized.set_joiner_active(false);
        self.stop_join_punch_overlay();
        self.stop_decentralized_reconnect_fastpath();
    }

    fn filter_decentralized_punch_targets(&self, targets: Vec<SocketAddr>) -> Vec<SocketAddr> {
        let rt = self.routing.read();
        targets
            .into_iter()
            .filter(|ep| {
                let Some(vip) = rt.ep_to_vip.get(ep) else {
                    return true;
                };
                let Some(entry) = rt.table.get(vip.as_str()) else {
                    return true;
                };
                !matches!(entry.state, RouteState::Active)
            })
            .collect()
    }

    fn on_decentralized_tracker_event(&mut self, event: TrackerDatagramEvent) {
        self.maybe_emit_tracker_responded(&event.tracker_url);
        if let Some(info) = event.announce {
            if self.state.join_tx.is_some() && self.decentralized.is_joiner() {
                let announce_peers: HashSet<SocketAddr> = info.peers.iter().copied().collect();
                let material = info.first_announce_in_join
                    || announce_peers
                        .iter()
                        .any(|p| !self.join_overlay_last_peers.contains(p));
                if material {
                    self.join_overlay_last_peers.extend(announce_peers);
                    self.spawn_decentralized_join_punch();
                }
            } else {
                self.try_peer_reconnect_from_announce(&info.peers);
            }
        }
    }

    fn try_peer_reconnect_from_announce(&mut self, peers: &[SocketAddr]) {
        if self.state.join_tx.is_some() || !self.decentralized.is_active() {
            return;
        }
        if !self.has_peer_vip_in_rt() {
            return;
        }
        if !self.has_crypto() {
            return;
        }
        let my_vip = self.state.my_vip.clone();
        let mut vip_bases: HashMap<String, Vec<SocketAddr>> = HashMap::new();
        let mut unbound_bases: Vec<SocketAddr> = Vec::new();
        let mut budget = 0usize;
        for addr in peers {
            if budget >= PEER_RECONNECT_ANNOUNCE_BUDGET {
                break;
            }
            budget += 1;
            let rt = self.routing.read();
            match unique_ip_peer_vip(&rt, &my_vip, addr.ip()) {
                UniqueIpMatch::Bound(vip) => {
                    if peer_route_needs_work(&rt, &vip, *addr) {
                        vip_bases.entry(vip).or_default().push(*addr);
                    }
                }
                UniqueIpMatch::Unbound => {
                    if peer_announce_needs_work_unbound(&rt, *addr) {
                        unbound_bases.push(*addr);
                    }
                }
            }
        }
        for (vip, mut bases) in vip_bases {
            bases.sort();
            bases.dedup();
            let key = format!("{PEER_RECONNECT_KEY_PREFIX}{vip}");
            self.spawn_peer_reconnect_workflow(&key, bases, &vip);
        }
        if !unbound_bases.is_empty() {
            unbound_bases.sort();
            unbound_bases.dedup();
            self.spawn_peer_reconnect_workflow(
                PEER_RECONNECT_UNBOUND_KEY,
                unbound_bases,
                "unbound",
            );
        }
    }

    /// Only during active join wait (`join_tx`). Owner / post-join / restore: fully silent.
    fn maybe_emit_tracker_responded(&mut self, tracker_url: &str) {
        if !self.decentralized.is_active() || self.state.join_tx.is_none() {
            return;
        }
        self.ui
            .emit_plain_live(format!("[TRACKER] \"{}\": Responded!", tracker_url));
    }

    fn spawn_decentralized_punch_pass(&mut self, targets: Vec<SocketAddr>) {
        if targets.is_empty() {
            return;
        }
        if let Some(stop) = self.manual_punch_stops.remove("decentralized") {
            stop.store(true, Ordering::Release);
        }
        let stop = Arc::new(AtomicBool::new(false));
        self.manual_punch_stops
            .insert("decentralized".to_string(), stop.clone());
        let socket = self.socket.clone();
        let state_view = self.state_view.clone();
        tokio::spawn(async move {
            const SPACING: Duration = Duration::from_millis(2);
            const BURST_PER_TARGET: u32 = 2;
            for target in targets {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let snap = state_view.read().clone();
                let hpch_body = snap.my_vip.into_bytes();
                let hpch_pkt = build_signed_or_plain_static(
                    snap.crypto_key,
                    &snap.ctrl_send_ctr,
                    PKT_HPCH,
                    &hpch_body,
                );
                for _ in 0..BURST_PER_TARGET {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    let _ = socket.send_to(&hpch_pkt, target).await;
                    tokio::time::sleep(SPACING).await;
                }
            }
        });
    }

    async fn run_decentralized_tick(&mut self) {
        if !self.decentralized.is_active() {
            return;
        }
        for (slot_idx, lookup) in self.decentralized.take_pending_resolves() {
            let tx = self.decentralized_resolve_tx.clone();
            tokio::spawn(async move {
                let addrs: Vec<SocketAddr> = match tokio::time::timeout(
                    DECENTRALIZED_RESOLVE_TIMEOUT,
                    tokio::net::lookup_host(&lookup),
                )
                .await
                {
                    Ok(Ok(iter)) => iter.filter(|a| a.is_ipv4()).collect(),
                    _ => Vec::new(),
                };
                let _ = tx.send((slot_idx, addrs));
            });
        }
        let self_ep = self.cached_public_socket_addr();
        let announce_port = self.decentralized.announce_port(self_ep);
        for work in self
            .decentralized
            .take_pending_http_announces(announce_port)
        {
            let tx = self.decentralized_http_tx.clone();
            tokio::spawn(async move {
                let outcome = match crate::nat::tracker::http_tracker_announce(
                    &work.host,
                    work.port,
                    &work.request_target,
                )
                .await
                {
                    Ok(body) => crate::nat::tracker::parse_http_announce_body(&body)
                        .map_err(|e| e.to_string()),
                    Err(e) => Err(e.to_string()),
                };
                let _ = tx.send(HttpAnnounceResult {
                    slot_idx: work.slot_idx,
                    generation: work.generation,
                    tracker_url: work.tracker_url,
                    outcome,
                });
            });
        }
        let join_pending = self.state.join_tx.is_some();
        let socket = self.socket.clone();
        let out = self
            .decentralized
            .tick(&socket, self_ep, join_pending)
            .await;
        let punch_targets = self.filter_decentralized_punch_targets(out.punch_targets);
        if self.state.join_tx.is_none() {
            self.spawn_decentralized_punch_pass(punch_targets);
        }
        for (ep, body) in out.join_fanout {
            self.send_ctrl_signed_to(ep, PKT_HPCH, self.state.my_vip.as_bytes())
                .await;
            self.send_ctrl_signed_to(ep, PKT_JOIN, &body).await;
        }
    }

    #[inline]
    fn ui_out(&self, msg: String) {
        self.ui.emit_plain(msg);
    }

    #[inline]
    fn ui_err(&self, msg: String) {
        self.ui.emit_stderr(msg);
    }

    pub fn set_leave_handler(&mut self, handler: LeaveHandler) {
        self.leave_handler = Some(handler);
    }

    pub fn set_endpoint_learned_handler(&mut self, handler: EndpointLearnedHandler) {
        self.endpoint_learned_handler = Some(handler);
    }

    pub fn set_roster_changed_handler(&mut self, handler: RosterChangedHandler) {
        self.roster_changed_handler = Some(handler);
    }

    pub fn set_identity_changed_handler(&mut self, handler: IdentityChangedHandler) {
        self.identity_changed_handler = Some(handler);
    }

    fn remember_endpoint(&self, vip: &str, ep: SocketAddr) {
        if self.state.my_vip.is_empty() {
            return;
        }
        if vip.parse::<Ipv4Addr>().is_err() {
            debug_assert!(false, "remember_endpoint: invalid VIP '{}'", vip);
            return;
        }
        if let Some(handler) = &self.endpoint_learned_handler {
            handler(vip.to_string(), ep);
        }
    }

    fn notify_roster_upsert(&self, vip: &str, ep: SocketAddr, node_id: Option<&str>) {
        if self.roster_changed_handler.is_none() {
            return;
        }
        if vip == self.state.my_vip {
            return;
        }
        let node_id = node_id
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                self.routing
                    .read()
                    .table
                    .get(vip)
                    .map(|e| e.node_id.to_string())
                    .unwrap_or_default()
            });
        if let Some(handler) = &self.roster_changed_handler {
            let vip_epoch = self
                .claim_map
                .get(node_id.as_str())
                .map(|c| c.vip_epoch)
                .unwrap_or(0);
            handler(RosterChange::Upsert(PeerInfo {
                node_id: node_id.clone(),
                name: node_id,
                virtual_ip: vip.to_string(),
                real_ip: ep.to_string(),
                vip_epoch,
            }));
        }
    }

    fn notify_roster_remove(&self, vip: &str) {
        if self.roster_changed_handler.is_none() {
            return;
        }
        if let Some(handler) = &self.roster_changed_handler {
            handler(RosterChange::Remove(vip.to_string()));
        }
    }

    fn stop_peer_reconnect_for_vip(&mut self, vip: &str) {
        let key = format!("{PEER_RECONNECT_KEY_PREFIX}{vip}");
        self.stop_punch_workflow_key(&key);
    }

    fn stop_all_peer_reconnect_workflows(&mut self) {
        let keys: Vec<String> = self
            .manual_punch_stops
            .keys()
            .filter(|k| k.starts_with(PEER_RECONNECT_KEY_PREFIX))
            .cloned()
            .collect();
        for key in keys {
            self.stop_punch_workflow_key(&key);
        }
        self.peer_reconnect_cooldown_until.clear();
    }

    fn distinct_peer_reconnect_key_count(&self) -> usize {
        self.manual_punch_stops
            .keys()
            .filter(|k| k.starts_with(PEER_RECONNECT_KEY_PREFIX))
            .count()
    }

    fn peer_reconnect_on_cooldown(&self, cooldown_key: &str) -> bool {
        self.peer_reconnect_cooldown_until
            .get(cooldown_key)
            .is_some_and(|at| at.elapsed() < PEER_RECONNECT_COOLDOWN)
    }

    fn spawn_peer_reconnect_workflow(
        &mut self,
        key: &str,
        bases: Vec<SocketAddr>,
        cooldown_key: &str,
    ) {
        if bases.is_empty() {
            return;
        }
        let is_existing = self.manual_punch_stops.contains_key(key);
        if !is_existing
            && self.distinct_peer_reconnect_key_count() >= PEER_RECONNECT_MAX_DISTINCT_KEYS
        {
            return;
        }
        if self.peer_reconnect_on_cooldown(cooldown_key) {
            return;
        }
        self.spawn_punch_workflow(key, bases, false);
        if self.manual_punch_stops.contains_key(key) {
            self.peer_reconnect_cooldown_until
                .insert(cooldown_key.to_string(), Instant::now());
        }
    }

    fn has_peer_vip_in_rt(&self) -> bool {
        let rt = self.routing.read();
        let my = self.state.my_vip.as_str();
        rt.table.keys().any(|vip| vip.as_str() != my)
    }

    fn has_crypto(&self) -> bool {
        self.state.crypto_keys.has_any()
    }

    fn routing_rtt_hint_ms(&self, from: SocketAddr) -> Option<i32> {
        let rt = self.routing.read();
        let vip = rt.ep_to_vip.get(&from)?;
        let entry = rt.table.get(vip)?;
        if entry.smoothed_rtt_ms > 0.0 {
            Some(entry.smoothed_rtt_ms.round() as i32)
        } else {
            None
        }
    }

    fn endpoint_to_vip_u32(&self, ep: SocketAddr) -> Option<u32> {
        let rt = self.routing.read();
        let vip = rt.ep_to_vip.get(&ep)?;
        vip.parse::<Ipv4Addr>().ok().map(u32::from)
    }

    /// One routing read-guard: VIP + optional DRR RTT hint + queuing-delay hint.
    fn tx_path_hints(&self, dest: SocketAddr) -> (Option<u32>, Option<f32>, Option<f32>) {
        let drr_rtt_aware = self.pacing.load_obs().drr_rtt_aware;
        let rt = self.routing.read();
        let Some(vip_str) = rt.ep_to_vip.get(&dest) else {
            return (None, None, None);
        };
        let vip_u32 = vip_str.parse::<Ipv4Addr>().ok().map(u32::from);
        let Some(entry) = rt.table.get(vip_str) else {
            return (vip_u32, None, None);
        };
        let rtt = if drr_rtt_aware && entry.rtt_base_ms > 0.0 {
            Some(entry.rtt_base_ms as f32)
        } else {
            None
        };
        let qd_raw = crate::routing::effective_queuing_delay_ms(
            entry,
            rt.congestion.owd_prefer_after_samples,
        );
        let qd = if qd_raw >= 0.0 {
            Some(qd_raw as f32)
        } else {
            None
        };
        (vip_u32, rtt, qd)
    }

    fn pacing_enqueue_hints(&self, dest: SocketAddr) -> (Option<f32>, Option<f32>) {
        let (_, rtt, qd) = self.tx_path_hints(dest);
        (rtt, qd)
    }

    fn data_plane_primary_key(&self) -> Option<Key> {
        self.state.crypto_keys.primary().map(|k| k.as_key())
    }

    fn outbound_crypto_key_for(&self, dest: SocketAddr) -> Option<Arc<AeadKey>> {
        self.state.crypto_keys.key_for_dest(dest)
    }

    fn control_plane_cipher(&mut self, key: &AeadKey) -> Option<Arc<ControlPlaneAead>> {
        let material = key.as_key().0;
        if let Some(found) = self.state.control_ciphers.get(&material) {
            return Some(found.clone());
        }
        let aead = Arc::new(derive_control_plane_material(&key.as_key()).ok()?);
        self.state.control_ciphers.insert(material, aead.clone());
        Some(aead)
    }

    fn next_ctrl_send_counter(ctr: &AtomicU64) -> Option<u64> {
        let out = ctr.fetch_add(1, Ordering::Relaxed);
        if out >= (1u64 << 48) {
            return None;
        }
        Some(out)
    }

    fn data_plane_cipher(
        &mut self,
        sender_vip: u32,
        receiver_vip: u32,
    ) -> Option<Arc<DataPlaneAead>> {
        let pair = (sender_vip, receiver_vip);
        if let Some(found) = self.state.data_ciphers.get(&pair) {
            return Some(found.clone());
        }
        let primary = self.data_plane_primary_key()?;
        let aead = derive_data_plane_material(&primary, sender_vip, receiver_vip).ok()?;
        let aead = Arc::new(aead);
        self.state.data_ciphers.insert(pair, aead.clone());
        Some(aead)
    }

    fn next_data_send_counter(&mut self, dest_vip_u32: u32) -> Option<u64> {
        let counter = self.state.data_send_ctr.entry(dest_vip_u32).or_insert(0);
        let out = *counter;
        if out >= (1u64 << 48) {
            return None;
        }
        *counter += 1;
        Some(out)
    }

    fn clear_data_crypto_state(&mut self) {
        self.state.data_ciphers.clear();
        self.state.control_ciphers.clear();
        self.state.data_send_ctr.clear();
        self.state.data_replay.clear();
        self.size_loss.clear();
    }

    fn clear_data_crypto_for_vip(&mut self, vip_u32: u32) {
        self.state.data_send_ctr.remove(&vip_u32);
        self.state.data_replay.remove(&vip_u32);
        self.size_loss.remove_vip(vip_u32);
        self.state
            .data_ciphers
            .retain(|(sender, receiver), _| *sender != vip_u32 && *receiver != vip_u32);
    }

    fn touch_routing_endpoint(&mut self, from: SocketAddr) {
        self.last_seen_pending.insert(from, Instant::now());
        let needs_promote = self.routing.read().is_endpoint_stale(from);
        if needs_promote {
            if let Some(_) = self.routing.write().promote_stale_if_needed(from) {
                self.metrics.inc_stale_to_candidate_promotions();
            }
        }
    }

    fn flush_last_seen_pending(&mut self) {
        if self.last_seen_pending.is_empty() {
            return;
        }
        let batch = std::mem::take(&mut self.last_seen_pending);
        self.routing.write().apply_last_seen_batch(batch);
    }

    fn try_para_notify(&mut self, sig: ParaSignal) {
        if self.para_notify_txs.is_empty() {
            return;
        }
        let is_critical = matches!(
            sig,
            ParaSignal::ReplyReceived { .. }
                | ParaSignal::OkReceived { .. }
                | ParaSignal::PunchAckReceived { .. }
        );
        let ui = self.ui.clone();
        self.para_notify_txs
            .retain(|listener_id, tx| match tx.try_send(sig.clone()) {
                Ok(()) => true,
                Err(TrySendError::Full(_)) => {
                    self.metrics.inc_para_notify_drops();
                    if is_critical {
                        ui.emit_stderr(term_style::fmt_para_line_stderr(format_args!(
                            " Listener {} dropped critical notify signal (channel full)",
                            listener_id
                        )));
                    }
                    true
                }
                Err(TrySendError::Closed(_)) => false,
            });
    }

    async fn stop_background_loops(&mut self) {
        self.stop_fec_tx_worker().await;
        self.stop_pacing_thread().await;
        for (_, stop) in self.manual_punch_stops.drain() {
            stop.store(true, Ordering::Release);
        }
        for (_, stop) in self.ice_check_stops.drain() {
            stop.store(true, Ordering::Release);
        }
        for (_, stop) in self.peer_keepalive_stops.drain() {
            stop.store(true, Ordering::Release);
        }
    }

    async fn stop_fec_tx_worker(&mut self) {
        if let Some(join) = self.fec_tx.request_stop() {
            self.drain_fec_tx_events();
            let _ = tokio::task::spawn_blocking(move || {
                let _ = join.join();
            })
            .await;
        }
    }

    fn update_pacing_tick(&self, tick_us: u64) {
        let t = pace_clock::clamp_tick_us(tick_us);
        self.pacing_thread
            .shared
            .tick_us
            .store(t, Ordering::Release);
    }

    fn spawn_pacing_clock_thread_reusing_shared(&mut self) {
        let tick = pace_clock::clamp_tick_us(self.pacing.load_obs().tick_us);
        self.pacing_thread
            .shared
            .tick_us
            .store(tick, Ordering::Release);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        self.pacing_thread.join = pace_clock::start_pace_clock_thread(
            self.pacing_tick_tx.clone(),
            self.pacing_thread.shared.clone(),
            stop_thread,
            self.pacing_thread.tick_skips.clone(),
            self.pacing_thread.overshoots.clone(),
            self.pacing_thread.adaptive_fallbacks.clone(),
        );
        self.pacing_thread.stop = stop;
    }

    async fn stop_pace_clock_only(&mut self) {
        self.pacing_thread.stop.store(true, Ordering::Release);
        if let Some(join) = self.pacing_thread.join.take() {
            let _ = tokio::task::spawn_blocking(move || {
                let _ = join.join();
            })
            .await;
        }
    }

    async fn stop_pacing_thread(&mut self) {
        self.stop_pace_clock_only().await;
        while self.pacing.event_rx.try_recv().is_ok() {}
        if let Some(join) = self.pacing.request_stop() {
            let _ = tokio::task::spawn_blocking(move || {
                let _ = join.join();
            })
            .await;
        }
    }

    /// Tear down membership, crypto, routes, and discovery so the engine can
    /// accept a fresh create/join without process restart.
    async fn reset_session_state(&mut self) {
        self.stop_decentralized_discovery();
        if let Some(tx) = self.state.join_tx.take() {
            let _ = tx.send(None);
        }
        self.pending_join_ack = None;
        self.stop_background_loops().await;
        self.state.crypto_keys.clear();
        self.clear_data_crypto_state();
        self.state.my_vip.clear();
        self.state.my_vip_u32 = 0;
        self.state.subnet_prefix = 24;
        self.state.candidates.clear();
        self.state.my_node_id.clear();
        self.claim_map.clear();
        self.leave_tombs.clear();
        self.fight_suppress.clear();
        {
            let mut rt = self.routing.write();
            *rt = RoutingTable::new();
        }
        {
            let mut sv = self.state_view.write();
            sv.my_vip.clear();
            sv.crypto_key = None;
        }
        self.bcast_dedup = BroadcastDeduplicator::new();
        self.reliable_seen.clear();
        self.reliable_seen_timeline.clear();
        self.msmd_seen.clear();
        self.msmd_timeline.clear();
        self.ctrl_replay.clear();
        self.ctrl_send_ctr.store(0, Ordering::Relaxed);
        self.pmtud = PathMtuDiscovery::new();
        self.heal_cooldown_until.clear();
        self.pending_pings.clear();
        self.probe_miss_by_ep.clear();
        self.fec_decoders.clear();
        self.fec_send_by_dest.clear();
        self.state.prev_path_kind.clear();
        self.state.pending_heal_vips.clear();
        self.rx_bytes_pending.clear();
        self.rx_bytes_pending_vip.clear();
        self.last_seen_pending.clear();
        self.reliable.reset_session();
        self.outbound_udp.clear();
        self.restart_pacing_after_session_reset().await;
    }

    async fn restart_pacing_after_session_reset(&mut self) {
        let apply = self.pacing_thread.shared.load_apply();
        let prev_cfg = self.pacing.load_obs().config;
        self.stop_pacing_thread().await;
        let mut engine = PacingEngine::new();
        engine.set_config(prev_cfg);
        engine.reset_session_runtime();
        let tick = pace_clock::clamp_tick_us(engine.config.tick_us);
        let (pacing, pacing_tick_tx, pacing_thread) = new_pacing_stack(
            self.socket.clone(),
            apply,
            tick,
            engine,
            self.outbound_udp.clone(),
            self.metrics.clone(),
        );
        self.pacing = pacing;
        self.pacing_tick_tx = pacing_tick_tx;
        self.pacing_thread = pacing_thread;
        self.fec_tx = start_fec_tx_worker(
            self.pacing.ingress.clone(),
            self.metrics.clone(),
            self.fec_tx_tuning(),
        );
        self.last_fec_effective_shard = self.fec_effective_shard_payload_size();
    }

    fn fec_tx_tuning(&self) -> FecTxTuning {
        FecTxTuning {
            shard: self
                .fec_effective_shard_payload_size()
                .unwrap_or(self.fec_shard_payload_size),
            flush_std: self.fec_flush_standard,
            flush_agg: self.fec_flush_aggressive,
            frame_scratch: self.advanced_tuning.buffers.fec_frame_scratch_bytes,
        }
    }

    fn refresh_pacing_thread_metrics(&self) {
        if !self.metrics.is_enabled() {
            return;
        }
        self.metrics
            .set_pacing_tick_skips(self.pacing_thread.tick_skips.load(Ordering::Relaxed));
        self.metrics
            .set_pacing_overshoots(self.pacing_thread.overshoots.load(Ordering::Relaxed));
        self.metrics.set_pacing_adaptive_fallback_count(
            self.pacing_thread
                .adaptive_fallbacks
                .load(Ordering::Relaxed),
        );
        let obs = self.pacing.load_obs();
        self.metrics.set_apd_metrics(
            obs.apd_episodes,
            obs.apd_ms_total,
            obs.apd_pkts_drained,
            obs.apd_budget_hits,
        );
        self.metrics.set_apd_ramp_observability(
            obs.apd_ramp_active,
            obs.apd_ramp_pinned,
            obs.apd_last_burst,
        );
        self.metrics.set_apd_sojourn_observability(
            obs.apd_arm_fill,
            obs.apd_arm_sojourn,
            obs.apd_max_sojourn,
        );
        self.metrics
            .set_apd_cc_headroom_suppressions(obs.apd_cc_headroom_suppressions);
        self.metrics
            .set_cc_rate_limited_events(obs.cc_rate_limited_events);
        self.metrics
            .set_drr_small_priority_pops(obs.drr_small_priority_pops);
        self.metrics
            .set_drr_bulk_force_pops(obs.drr_bulk_force_pops);
        self.metrics
            .set_drr_rtt_scale_applied(obs.drr_rtt_scale_applied);
        self.metrics
            .set_background_cc_rates(obs.cc_min_bps, obs.cc_avg_bps, obs.cc_max_bps);
        self.metrics.set_background_cc_delivery_rates(
            obs.cc_delivery_min_bps,
            obs.cc_delivery_avg_bps,
            obs.cc_delivery_max_bps,
        );
        self.metrics.set_cc_event_counters(
            obs.cc_counters.increase_events,
            obs.cc_counters.decrease_events,
            obs.cc_counters.loss_decrease_events,
            obs.cc_counters.delivery_anchor_events,
            obs.cc_counters.loss_ignored_random_events,
        );
    }

    async fn runtime_view_begin(&mut self) {
        self.pacing.reset_observability_counters_async().await;
        self.pacing_thread.tick_skips.store(0, Ordering::Relaxed);
        self.pacing_thread.overshoots.store(0, Ordering::Relaxed);
        self.pacing_thread
            .adaptive_fallbacks
            .store(0, Ordering::Relaxed);
        self.retransmit_sender.sent_direct = 0;
        self.retransmit_sender.sent_fallback = 0;
        self.metrics.reset();
        self.metrics.set_enabled(true);
        self.runtime_trace.reset();
        self.runtime_trace.set_enabled(true);
    }

    fn runtime_view_end(&self) {
        self.metrics.set_enabled(false);
        self.metrics.reset();
        self.runtime_trace.set_enabled(false);
        self.runtime_trace.reset();
    }

    pub async fn run(mut self) {
        let mut recv_buf = vec![0u8; 65535];
        loop {
            select! {
                recv = self.socket.recv_from(&mut recv_buf) => {
                    if let Ok((n, from)) = recv {
                        let data = &recv_buf[..n];
                        if self.handle_stun_datagram(data) {
                            continue;
                        }
                        let dg = self.decentralized.handle_datagram(from, data);
                        if dg.handled {
                            if let Some(event) = dg.event {
                                self.on_decentralized_tracker_event(event);
                            }
                            continue;
                        }
                        if looks_like_stun(data) {
                            continue;
                        }
                        self.handle_packet(data, from).await;
                    }
                }
                Some(pkt) = self.tun_rx.recv() => {
                    let _ = self.handle_tun_packet(pkt).await;
                }
                Some(cmd) = self.cmd_rx.recv() => {
                    if self.handle_cmd(cmd).await {
                        break;
                    }
                }
                Some(resolved) = self.stun_resolve_rx.recv() => {
                    self.handle_stun_resolve_result(resolved);
                }
                Some((slot_idx, addrs)) = self.decentralized_resolve_rx.recv() => {
                    self.decentralized.add_resolved_addrs(slot_idx, addrs);
                    self.decentralized.clear_resolve_in_flight(slot_idx);
                }
                Some(http_result) = self.decentralized_http_rx.recv() => {
                    if let Some(event) = self.decentralized.apply_http_announce_result(http_result) {
                        self.on_decentralized_tracker_event(event);
                    }
                }
                _ = self.keepalive_interval.tick() => {
                    self.send_keepalives().await;
                }
                _ = self.sync_interval.tick() => {
                    let now = Instant::now();
                    prune_leave_tombstones(&mut self.leave_tombs, now);
                    prune_fight_suppress(&mut self.fight_suppress, now);
                    self.flush_pending_claim_gossip().await;
                    self.broadcast_claim_gossip().await;
                }
                _ = self.direct_retry_interval.tick() => {
                    self.direct_retry_tick();
                }
                _ = self.pmtud_interval.tick() => {
                    self.drive_pmtud_tick().await;
                }
                _ = self.stale_evict_interval.tick() => {
                    let stale_age = Duration::from_secs(self.advanced_tuning.timers.stale_evict_secs);
                    let now = Instant::now();
                    let victims: Vec<(String, SocketAddr, Option<String>)> = {
                        let mut rt = self.routing.write();
                        rt.mark_stale_if_idle(Duration::from_secs(self.advanced_tuning.timers.stale_mark_secs));
                        rt.table
                            .iter()
                            .filter(|(_, e)| {
                                e.state == RouteState::Stale
                                    && now.duration_since(e.last_seen) > stale_age
                            })
                            .map(|(vip, e)| {
                                let node_id = (!e.node_id.is_empty())
                                    .then(|| e.node_id.to_string());
                                (vip.clone(), e.endpoint, node_id)
                            })
                            .collect()
                    };
                    {
                        let mut rt = self.routing.write();
                        for (vip, _, _) in &victims {
                            rt.remove(vip);
                        }
                    }
                    for (vip, _, node_id) in &victims {
                        self.on_peer_route_removed(vip, node_id.as_deref());
                        if let Some(nid) = node_id {
                            remove_claim(&mut self.claim_map, nid);
                        } else {
                            // Route lacked node_id — still drop claim ghosts by VIP.
                            let _ = remove_claims_for_vip(&mut self.claim_map, vip);
                        }
                    }
                    for (_, ep, _) in victims {
                        self.invalidate_fec_qd_cache(ep);
                        self.state.crypto_keys.unbind_peer(ep);
                        self.reliable.flush_dest(ep);
                        self.teardown_fec_peer(ep);
                    }
                    self.prune_orphan_per_peer_keys();
                    self.prune_fec_decoders();
                }
                _ = self.rx_bw_flush_interval.tick() => {
                    self.flush_rx_byte_counters();
                    self.flush_last_seen_pending();
                }
                Some(ev) = self.pacing.event_rx.recv() => {
                    let PacingEvent::TickDone {
                        sent,
                        tick_duration_us,
                        socket_dead,
                    } = ev;
                    self.metrics
                        .set_pacing_tick_observed(tick_duration_us, sent as u64);
                    if let Some((err, last_failed_dest)) = socket_dead {
                        self.ui_err(format!("  [PACE] socket send loop unhealthy: {err}"));
                        if let Some(dest) = last_failed_dest {
                            if !dest.ip().is_unspecified() {
                                let fail = self.routing.write().note_fail(dest, None);
                                self.refresh_fec_qd_cache(dest);
                                if self.state.feature_flags.predictive_heal {
                                    if let (Some(vip), true) = (fail.vip, fail.needs_heal) {
                                        self.spawn_predictive_heal(vip).await;
                                    }
                                }
                            }
                        }
                    }
                    if self.metrics.is_enabled() {
                        self.tick_done_seq = self.tick_done_seq.wrapping_add(1);
                        if self.tick_done_seq % 8 == 0 {
                            let obs = self.pacing.load_obs();
                            self.metrics.set_pacing_dropped(obs.dropped_packets);
                            self.metrics.set_pacing_drop_data_normal(obs.dropped_data);
                            self.metrics.set_pacing_shed_sojourn(obs.shed_sojourn);
                            self.metrics
                                .set_pacing_drop_control_normal(obs.dropped_control_normal);
                            self.metrics
                                .set_pacing_drop_control_retransmit(obs.dropped_control_retransmit);
                            self.refresh_pacing_thread_metrics();
                        }
                    }
                    let drain = self
                        .pacing_thread
                        .shared
                        .apd_pure_spin
                        .load(Ordering::Acquire);
                    self.fec_tx.request_flush_due(drain);
                    self.reliable.tick_into(
                        &mut self.reliable_tick_buf,
                        &mut self.reliable_failure_buf,
                    );
                    let reliable_failures: Vec<_> =
                        self.reliable_failure_buf.drain(..).collect();
                    for (_seq, dest) in reliable_failures {
                        let fail = self.routing.write().note_fail(dest, None);
                        self.refresh_fec_qd_cache(dest);
                        if self.state.feature_flags.predictive_heal {
                            if let (Some(vip), true) = (fail.vip, fail.needs_heal) {
                                self.spawn_predictive_heal(vip).await;
                            }
                        }
                    }
                    for (pkt, dest) in self.reliable_tick_buf.drain(..) {
                        if self.retransmit_sender.consume_token() {
                            match self.socket.try_send_to(&pkt, dest) {
                                Ok(_) => {
                                    self.retransmit_sender.sent_direct =
                                        self.retransmit_sender.sent_direct.saturating_add(1);
                                }
                                Err(_) => {
                                    self.retransmit_sender.sent_fallback =
                                        self.retransmit_sender.sent_fallback.saturating_add(1);
                                    let _ = self.pacing.enqueue_retransmit(pkt, dest);
                                }
                            }
                        } else {
                            self.retransmit_sender.sent_fallback =
                                self.retransmit_sender.sent_fallback.saturating_add(1);
                            let _ = self.pacing.enqueue_retransmit(pkt, dest);
                        }
                    }
                    self.metrics.set_retransmit_counts(
                        self.retransmit_sender.sent_direct,
                        self.retransmit_sender.sent_fallback,
                    );
                }
                Some(ev) = self.fec_tx.event_rx.recv() => {
                    self.apply_fec_tx_event(ev);
                }
                _ = self.stun_poll_interval.tick() => {
                    self.poll_stun_query();
                }
                _ = self.stun_keepalive_interval.tick() => {
                    self.send_stun_keepalive().await;
                }
                _ = self.decentralized_interval.tick() => {
                    self.run_decentralized_tick().await;
                    self.send_claim_presence_tick().await;
                }
                _ = self.ping_watchdog_interval.tick() => {
                    let heal_vips = self.expire_pending_pings();
                    for vip in heal_vips {
                        self.spawn_predictive_heal(vip).await;
                    }
                }
                _ = self.cc_probe_interval.tick() => {
                    self.send_cc_probes().await;
                }
            }
        }
    }

    async fn apply_pmar_body(&mut self, from: SocketAddr, body: &[u8]) {
        if body.len() < 10 {
            return;
        }
        if self.mtu_pin || self.pmtud.is_pinned() {
            return;
        }
        let sz = u16::from_be_bytes([body[0], body[1]]) as usize;
        let session_id = u32::from_be_bytes([body[2], body[3], body[4], body[5]]);
        let probe_id = u32::from_be_bytes([body[6], body[7], body[8], body[9]]);
        let (ok, min_changed, ev) =
            self.pmtud
                .on_ack(from, sz, probe_id, session_id, Instant::now());
        if ok {
            self.metrics.inc_pmtud_probe_acks();
        } else {
            self.metrics.inc_pmtud_pmar_ignored();
        }
        self.metrics.add_pmtud_events(ev);
        if min_changed {
            let enc_overhead = if self.has_crypto() {
                MENC_WIRE_OVERHEAD
            } else {
                0
            };
            let suggested = self.pmtud.suggested_adapter_mtu(enc_overhead) as u16;
            self.try_apply_adapter_mtu(suggested);
            self.sync_fec_shard_ceiling_to_path_mtu();
        }
    }

    async fn handle_packet(&mut self, buf: &[u8], from: SocketAddr) {
        let kind = match parse_datagram(buf) {
            Some(v) => v,
            None => return,
        };
        match kind {
            DatagramKind::Control(tag, body) => {
                self.handle_parsed_packet(tag, body, from).await;
            }
            DatagramKind::Compact(CompactPacketType::Fec, _) => {
                let decoder = self
                    .fec_decoders
                    .entry(from)
                    .or_insert_with(FecDecoder::new);
                let decoded = decoder.push_shard(buf);
                self.metrics
                    .set_fec_decoder_groups_hwm(decoder.group_count() as u64);
                if decoded.invalid {
                    self.metrics.inc_fec_group_invalid();
                    self.metrics.inc_fec_decode_failures();
                }
                if !decoded.recovered.is_empty() {
                    self.metrics
                        .inc_fec_recovered_packets(decoded.recovered.len() as u64);
                }
                let shards_new = decoded.shards_new;
                let shards_missing = decoded.shards_missing;
                let recovered = decoded.recovered;
                if shards_new > 0 || shards_missing > 0 {
                    if let Some(vip) = self.endpoint_to_vip_u32(from) {
                        self.size_loss.note_wire_obs(
                            vip,
                            shards_missing as u64,
                            shards_new as u64,
                            Instant::now(),
                        );
                    }
                }
                for pkt in recovered {
                    if let Some((ty, inner_body)) = parse_compact(&pkt) {
                        self.handle_compact_packet(ty, inner_body, from, true).await;
                    }
                }
            }
            DatagramKind::Compact(ty, body) => {
                self.handle_compact_packet(ty, body, from, false).await;
            }
        }
    }

    async fn handle_compact_packet(
        &mut self,
        ty: CompactPacketType,
        body: &[u8],
        from: SocketAddr,
        from_fec_recovery: bool,
    ) {
        match ty {
            CompactPacketType::Reliable => {
                self.handle_reliable_packet(body, from).await;
            }
            CompactPacketType::Ack => {
                if body.len() < 4 {
                    return;
                }
                let seq = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                self.reliable.on_ack(seq, from);
            }
            CompactPacketType::Encrypted => {
                if body.len() < WIRE_COUNTER_LEN + DATA_TAG_LEN {
                    return;
                }
                let Some(peer_vip_u32) = self.endpoint_to_vip_u32(from) else {
                    self.metrics.inc_unauth_drop_crypto_gate();
                    return;
                };
                if self.state.my_vip_u32 == 0 {
                    self.metrics.inc_unauth_drop_crypto_gate();
                    return;
                }
                let mut counter_wire = [0u8; WIRE_COUNTER_LEN];
                counter_wire.copy_from_slice(&body[..WIRE_COUNTER_LEN]);
                let counter = decode_wire_counter(&counter_wire);
                let replay_allowed = self
                    .state
                    .data_replay
                    .get(&peer_vip_u32)
                    .map(|w| w.allows(counter))
                    .unwrap_or(true);
                if !replay_allowed {
                    return;
                }
                let Some(aead) = self.data_plane_cipher(peer_vip_u32, self.state.my_vip_u32) else {
                    self.metrics.inc_unauth_drop_crypto_gate();
                    return;
                };
                let mut aad = [0u8; 8];
                aad[..4].copy_from_slice(&peer_vip_u32.to_be_bytes());
                aad[4..].copy_from_slice(&self.state.my_vip_u32.to_be_bytes());
                self.decrypt_scratch.clear();
                if aead
                    .decrypt_framed_payload_into(
                        &counter_wire,
                        &aad,
                        &body[WIRE_COUNTER_LEN..],
                        &mut self.decrypt_scratch,
                    )
                    .is_ok()
                {
                    let now = Instant::now();
                    let frame_len = COMPACT_HEADER_LEN + body.len();
                    let gap = {
                        let top = self
                            .state
                            .data_replay
                            .get(&peer_vip_u32)
                            .map(|w| w.top())
                            .unwrap_or(None);
                        replay_gap(top, counter)
                    };
                    self.state
                        .data_replay
                        .entry(peer_vip_u32)
                        .or_insert_with(DataReplayWindow::new)
                        .commit(counter);
                    self.size_loss
                        .note_encrypted_commit(peer_vip_u32, frame_len, gap, now);
                    // Wire-origin only: FEC recovery must not dilute shard wire-loss.
                    if !from_fec_recovery {
                        self.size_loss.note_wire_obs(peer_vip_u32, gap, 1, now);
                    }
                    let plain = self.decrypt_scratch.split().freeze();
                    self.handle_mdat_like(plain, from).await;
                }
            }
            CompactPacketType::Data => {
                let src_key = src_addr_key(from);
                if self.has_crypto() {
                    self.metrics.inc_unauth_drop_plain_data_crypto();
                    return;
                }
                if !self.plain_data_limiter.allow(src_key) {
                    return;
                }
                self.plain_data_scratch.clear();
                self.plain_data_scratch.reserve(body.len());
                self.plain_data_scratch.extend_from_slice(body);
                let plain = self.plain_data_scratch.split().freeze();
                if let Some(vip) = self.endpoint_to_vip_u32(from) {
                    let frame_len = COMPACT_HEADER_LEN + body.len();
                    self.size_loss.note_rx(vip, frame_len, Instant::now());
                }
                self.handle_mdat_like(plain, from).await;
            }
            CompactPacketType::Ping => {
                self.handle_ping_body(body, from).await;
            }
            CompactPacketType::Pong => {
                self.handle_pong_body(body, from).await;
            }
            CompactPacketType::Fec | CompactPacketType::JoinAck => {}
        }
    }

    async fn handle_parsed_packet(&mut self, tag: [u8; 4], body: &[u8], from: SocketAddr) {
        if tag == *PKT_PMTU {
            if body.len() < 10 {
                return;
            }
            let mut resp = Vec::with_capacity(4 + 10);
            resp.extend_from_slice(PKT_PMAR);
            resp.extend_from_slice(&body[..10]);
            let _ = self.socket.send_to(&resp, from).await;
            return;
        }
        if tag == *PKT_PMAR {
            self.apply_pmar_body(from, body).await;
            return;
        }
        if tag == *PKT_CTSIG {
            self.handle_signed_wrapper(body, from).await;
            return;
        }
        self.dispatch_control(tag, body, from, false).await;
    }

    async fn handle_tun_packet(&mut self, pkt: Bytes) -> Result<()> {
        if pkt.len() < 20 {
            return Ok(());
        }
        self.runtime_trace.add_tun_egress(pkt.len() as u64);
        let dst_u32 = u32::from_be_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);

        if dst_u32 == self.state.my_vip_u32 && self.state.my_vip_u32 != 0 {
            self.inject_to_tun(pkt);
            return Ok(());
        }

        let multipath_core = self.state.feature_flags.multipath_core;
        let dual_write = self.state.feature_flags.dual_write_transition;

        struct RouteSnap {
            ep: SocketAddr,
            vip: Option<String>,
            relay_snap: Option<crate::routing::RelayPathSnapshot>,
            multipath_active: Option<(SocketAddr, PathKind)>,
            transition_active: Option<(SocketAddr, PathKind)>,
            failover: crate::advanced_tuning::FailoverTuning,
        }
        let snap = {
            let rt = self.routing.read();
            let Some(ep) = rt.lookup_by_vip_u32(dst_u32) else {
                if is_broadcast_or_multicast(&pkt) {
                    if !self.bcast_dedup.is_fresh(&pkt) {
                        return Ok(());
                    }
                    rt.push_endpoints_excluding_stale(&mut self.broadcast_scratch);
                    drop(rt);
                    for i in 0..self.broadcast_scratch.len() {
                        let ep = self.broadcast_scratch[i];
                        self.send_data_with_fallback_direct(ep, &pkt).await;
                    }
                    self.broadcast_scratch.clear();
                    return Ok(());
                }
                let hub = match rt.select_broadcast_relay_hop(&self.state.my_vip, None) {
                    RelaySelection::Hop(ep) => Some(ep),
                    RelaySelection::None => None,
                };
                drop(rt);
                if let Some(hub_ep) = hub {
                    self.send_data_with_fallback(hub_ep, &pkt).await;
                }
                return Ok(());
            };
            let vip = rt.lookup_vip_by_u32(dst_u32);
            let relay_snap = rt.relay_snapshot_by_u32(dst_u32);
            let (multipath_active, transition_active) = if let Some(vip_ref) = vip.as_ref() {
                let entry = rt.table.get(vip_ref);
                let mp = if multipath_core {
                    entry
                        .and_then(|e| e.path_set.as_ref())
                        .and_then(|ps| ps.active_endpoint_kind())
                } else {
                    None
                };
                let trans = if dual_write {
                    rt.transition_state(vip_ref)
                } else {
                    None
                };
                (mp, trans)
            } else {
                (None, None)
            };
            RouteSnap {
                ep,
                vip,
                relay_snap,
                multipath_active,
                transition_active,
                failover: rt.failover,
            }
        };

        let mut target = snap.ep;
        let mut target_kind = PathKind::Direct;
        if let Some((ep, kind)) = snap.multipath_active {
            if kind != PathKind::HubRelay {
                target = ep;
                target_kind = kind;
            }
        }

        let mut relay_selection: Option<RelaySelection> = None;
        if let Some(ref rs) = snap.relay_snap {
            let want_relay = should_relay_snap(rs, &snap.failover);
            if want_relay {
                if let Some(ref dest_vip) = snap.vip {
                    let selection = {
                        let rt = self.routing.read();
                        rt.select_relay_endpoint(dest_vip, &self.state.my_vip, None)
                    };
                    match selection {
                        RelaySelection::Hop(hop) => {
                            target = hop;
                            target_kind = PathKind::HubRelay;
                            relay_selection = Some(selection);
                        }
                        RelaySelection::None if rs.state == RouteState::Stale => {
                            self.metrics.inc_relay_drop_no_hop();
                            let warn_at = Instant::now();
                            let warn = self
                                .last_relay_stale_drop_warn
                                .map(|t| warn_at.duration_since(t) >= Duration::from_secs(5))
                                .unwrap_or(true);
                            if warn {
                                self.ui_err(
                                    "  [DATA] relay drop: no relay hop and route Stale (dst)"
                                        .to_string(),
                                );
                                self.last_relay_stale_drop_warn = Some(warn_at);
                            }
                            return Ok(());
                        }
                        RelaySelection::None => {
                            self.metrics.inc_relay_fallback_direct_no_hop();
                            let warn_at = Instant::now();
                            let warn = self
                                .last_relay_degraded_no_hop_warn
                                .map(|t| warn_at.duration_since(t) >= Duration::from_secs(5))
                                .unwrap_or(true);
                            if warn {
                                self.ui_err(
                                    "  [DATA] relay: no relay hop; send direct to peer (best effort)"
                                        .to_string(),
                                );
                                self.last_relay_degraded_no_hop_warn = Some(warn_at);
                            }
                            target = snap.ep;
                            target_kind = PathKind::Direct;
                        }
                    }
                }
            }
        }

        let dest_vip_ref = snap.vip.as_deref();

        let prev_path_kind_for_dst = self.state.prev_path_kind.get(&dst_u32).copied();

        if dual_write {
            if let Some(vip) = snap.vip.as_ref() {
                if matches!(prev_path_kind_for_dst, Some(prev) if prev != target_kind) {
                    let old_ep = snap.ep;
                    let old_kind = prev_path_kind_for_dst.unwrap_or(PathKind::Direct);
                    self.routing.write().begin_transition(
                        vip,
                        old_ep,
                        old_kind,
                        Duration::from_millis(600),
                    );
                    self.send_via_kind(target, target_kind, &pkt, dest_vip_ref)
                        .await;
                    self.send_via_kind(old_ep, old_kind, &pkt, dest_vip_ref)
                        .await;
                } else if let Some((old_ep, old_kind)) = snap.transition_active {
                    self.send_via_kind(target, target_kind, &pkt, dest_vip_ref)
                        .await;
                    self.send_via_kind(old_ep, old_kind, &pkt, dest_vip_ref)
                        .await;
                } else {
                    self.send_via_kind(target, target_kind, &pkt, dest_vip_ref)
                        .await;
                }
            } else {
                self.send_via_kind(target, target_kind, &pkt, dest_vip_ref)
                    .await;
            }
        } else {
            self.send_via_kind(target, target_kind, &pkt, dest_vip_ref)
                .await;
        }

        if let (Some(vip), Some(sel)) = (snap.vip.as_ref(), relay_selection) {
            self.apply_relay_path_stamp(vip, sel);
        }

        if let Some(vip) = snap.vip.as_ref() {
            if target_kind == PathKind::HubRelay
                && prev_path_kind_for_dst != Some(PathKind::HubRelay)
            {
                self.routing.write().note_relay_fallback(vip);
                self.metrics.inc_relay_fallback(1);
            }
            self.state.prev_path_kind.insert(dst_u32, target_kind);
        }
        Ok(())
    }

    async fn spawn_predictive_heal(&mut self, vip: String) {
        if !self.state.feature_flags.predictive_heal {
            return;
        }
        if let Some(until) = self.heal_cooldown_until.get(&vip) {
            if *until > Instant::now() {
                self.metrics.inc_heal_cooldown_blocked();
                return;
            }
        }
        let pending_heal_count = self
            .pending_pings
            .values()
            .filter(|p| matches!(p.kind, PendingPingKind::Heal { .. }))
            .count();
        if pending_heal_count >= self.advanced_tuning.engine_limits.max_pending_heal_probes {
            return;
        }
        if !self.state.pending_heal_vips.insert(vip.clone()) {
            return;
        }
        self.metrics.inc_heal_spawned();
        let primary = {
            let rt = self.routing.read();
            rt.table.get(&vip).map(|e| e.endpoint)
        };
        let Some(primary) = primary else {
            self.state.pending_heal_vips.remove(&vip);
            return;
        };
        let candidates = self.control_race_dests(primary);
        if candidates.is_empty() {
            self.state.pending_heal_vips.remove(&vip);
            return;
        }
        let mut probes_sent = 0usize;
        let race_extra = candidates.len().saturating_sub(1) as u64;
        for ep in candidates.into_iter().take(3) {
            let ping_id = self.allocate_ping_id();
            let ts = now_epoch_ms();
            let mut payload = [0u8; 16];
            payload[..8].copy_from_slice(&ping_id.to_le_bytes());
            payload[8..].copy_from_slice(&ts.to_le_bytes());
            let deadline = Instant::now() + Duration::from_millis(750);
            self.pending_pings.insert(
                ping_id,
                PendingPing {
                    dest: ep,
                    allow_ip_match: false,
                    deadline,
                    sent_at_ms: ts,
                    kind: PendingPingKind::Heal {
                        vip: vip.clone(),
                        endpoint: ep,
                    },
                },
            );
            if self
                .send_compact_to(ep, CompactPacketType::Ping, &payload)
                .await
            {
                probes_sent += 1;
            } else {
                self.pending_pings.remove(&ping_id);
            }
        }
        self.metrics.inc_control_path_race_extra(race_extra);
        if probes_sent == 0 {
            self.state.pending_heal_vips.remove(&vip);
            self.heal_cooldown_until.insert(
                vip,
                Instant::now()
                    + Duration::from_millis(self.advanced_tuning.engine_limits.heal_cooldown_ms),
            );
        }
    }

    fn handle_heal_success(&mut self, vip: String, endpoint: SocketAddr, rtt_ms: i64) {
        if !self.state.pending_heal_vips.contains(&vip) {
            return;
        }
        let has_remaining = self
            .pending_pings
            .values()
            .any(|x| matches!(&x.kind, PendingPingKind::Heal { vip: other, .. } if other == &vip));
        if !has_remaining {
            self.state.pending_heal_vips.remove(&vip);
        }
        self.heal_cooldown_until.remove(&vip);
        let mut rt = self.routing.write();
        let tracked_ok = rt
            .vip_for_data_endpoint(endpoint, None)
            .map(|v| v == vip)
            .unwrap_or(false);
        if !tracked_ok {
            return;
        }
        self.metrics.inc_heal_succeeded();
        let ewma = rt.routing_ewma;
        let advanced = self.state.feature_flags.multipath_bandwidth_prober;
        if let Some(entry) = rt.table.get_mut(&vip) {
            if let Some(ps) = entry.path_set.as_mut() {
                ps.note_rtt_for_endpoint(endpoint, rtt_ms.max(1) as f64, &ewma);
                ps.reselect_active(advanced);
            }
        }
    }

    fn inject_to_tun(&mut self, raw: Bytes) {
        let n = raw.len() as u64;
        match self.state.tun_inject_tx.send(raw) {
            Ok(_) => {
                self.runtime_trace.add_tun_ingress(n);
            }
            Err(_) => {
                self.metrics.inc_tun_inject_drops();
                let now = Instant::now();
                let warn = self
                    .last_tun_inject_drop_warn
                    .map(|t| now.duration_since(t) >= Duration::from_secs(2))
                    .unwrap_or(true);
                if warn {
                    self.ui_err(
                        "  [TUN] inject queue full; dropping packet (increase channel or reduce load)"
                            .to_string(),
                    );
                    self.last_tun_inject_drop_warn = Some(now);
                }
            }
        }
    }

    fn cleanup_peer_sidecars(&mut self, node_id: Option<&str>) {
        if let Some(nid) = node_id.filter(|s| !s.is_empty()) {
            if let Some(stop) = self.ice_check_stops.remove(nid) {
                stop.store(true, Ordering::Release);
            }
        }
    }

    fn on_peer_route_removed(&mut self, vip: &str, node_id: Option<&str>) {
        self.cleanup_peer_sidecars(node_id);
        self.heal_cooldown_until.remove(vip);
        self.state.pending_heal_vips.remove(vip);
        if let Some(u) = crate::routing::ipv4_to_u32(vip) {
            self.state.prev_path_kind.remove(&u);
            self.clear_data_crypto_for_vip(u);
        }
    }

    fn note_rx_bytes(&mut self, from: SocketAddr, bytes: u64) {
        let counter = self.rx_bytes_pending.entry(from).or_insert(0);
        *counter = counter.saturating_add(bytes);
    }

    fn note_rx_bytes_for_dst(&mut self, dst_vip_u32: u32, bytes: u64) {
        let counter = self.rx_bytes_pending_vip.entry(dst_vip_u32).or_insert(0);
        *counter = counter.saturating_add(bytes);
    }

    fn flush_rx_byte_counters(&mut self) {
        let has_src = !self.rx_bytes_pending.is_empty();
        let has_dst = !self.rx_bytes_pending_vip.is_empty();
        if !has_src && !has_dst {
            return;
        }
        let advanced = self.state.feature_flags.multipath_bandwidth_prober;
        let batch = std::mem::take(&mut self.rx_bytes_pending);
        let by_dst = std::mem::take(&mut self.rx_bytes_pending_vip);
        let mut rt = self.routing.write();
        if has_src {
            rt.note_bytes_received_batch(batch, advanced, None);
        }
        if has_dst {
            for (dst_u32, bytes) in by_dst {
                rt.note_bytes_received_for_vip_u32(dst_u32, bytes, advanced);
            }
        }
    }

    fn prune_fec_decoders(&mut self) {
        let tracked: HashSet<SocketAddr> = self.routing.read().ep_to_vip.keys().copied().collect();
        let now = Instant::now();
        let mut wire_obs: Vec<(SocketAddr, u16)> = Vec::new();
        self.fec_decoders.retain(|ep, decoder| {
            let missing = decoder.evict_expired();
            if missing > 0 {
                wire_obs.push((*ep, missing));
            }
            tracked.contains(ep) || !decoder.is_empty()
        });
        for (ep, missing) in wire_obs {
            if let Some(vip) = self.endpoint_to_vip_u32(ep) {
                self.size_loss.note_wire_obs(vip, missing as u64, 0, now);
            }
        }
    }

    fn allocate_ping_id(&mut self) -> u64 {
        for _ in 0..16 {
            let id = rand::random::<u64>();
            if id != 0 && !self.pending_pings.contains_key(&id) {
                return id;
            }
        }
        loop {
            let id = self.next_ping_id;
            self.next_ping_id = self.next_ping_id.wrapping_add(1).max(1);
            if !self.pending_pings.contains_key(&id) {
                return id;
            }
        }
    }

    async fn send_relay_hop(&mut self, hop: SocketAddr, dest_vip: &str, payload: &[u8]) {
        if self.send_menc(hop, payload).await.is_ok() {
            self.metrics.inc_relay_send_hop();
            return;
        }
        let _ = self.routing.write().note_fail(hop, None);
        let selection = {
            let rt = self.routing.read();
            rt.select_relay_endpoint(dest_vip, &self.state.my_vip, Some(hop))
        };
        if let RelaySelection::Hop(alt) = selection {
            if self.send_menc(alt, payload).await.is_ok() {
                self.metrics.inc_relay_send_hop();
                self.apply_relay_path_stamp(dest_vip, RelaySelection::Hop(alt));
            }
        }
    }

    async fn send_data_with_fallback(&mut self, dest: SocketAddr, payload: &[u8]) {
        if self.send_menc(dest, payload).await.is_err() {
            self.send_data_fallback_usable_hub(dest, payload, false)
                .await;
        }
    }

    async fn send_via_kind(
        &mut self,
        dest_ep: SocketAddr,
        kind: PathKind,
        payload: &[u8],
        dest_vip: Option<&str>,
    ) {
        match kind {
            PathKind::Direct | PathKind::IceSrflx => {
                self.send_data_with_fallback(dest_ep, payload).await;
            }
            PathKind::HubRelay => {
                if let Some(vip) = dest_vip {
                    self.send_relay_hop(dest_ep, vip, payload).await;
                }
            }
        }
    }

    async fn send_data_with_fallback_direct(&mut self, dest: SocketAddr, payload: &[u8]) {
        if self.send_menc_direct(dest, payload).await.is_err() {
            self.send_data_fallback_usable_hub(dest, payload, true)
                .await;
        }
    }

    async fn send_data_fallback_usable_hub(
        &mut self,
        dest: SocketAddr,
        payload: &[u8],
        direct: bool,
    ) {
        let hub = {
            let rt = self.routing.read();
            match rt.select_broadcast_relay_hop(&self.state.my_vip, Some(dest)) {
                RelaySelection::Hop(ep) => Some(ep),
                RelaySelection::None => None,
            }
        };
        let Some(hub_ep) = hub else {
            return;
        };
        if direct {
            let _ = self.send_menc_direct(hub_ep, payload).await;
        } else {
            let _ = self.send_menc(hub_ep, payload).await;
        }
    }

    fn apply_relay_path_stamp(&mut self, dest_vip: &str, selection: RelaySelection) {
        let mut rt = self.routing.write();
        match selection {
            RelaySelection::Hop(hop) => rt.stamp_relay_hop(dest_vip, hop),
            RelaySelection::None => rt.clear_relay_path(dest_vip),
        }
    }

    fn sync_dest_relay_path_stamp(&mut self, dest_vip: &str) {
        let selection = {
            let rt = self.routing.read();
            rt.select_relay_endpoint(dest_vip, &self.state.my_vip, None)
        };
        self.apply_relay_path_stamp(dest_vip, selection);
    }

    async fn handle_cmd(&mut self, cmd: EngineCmd) -> bool {
        match cmd {
            EngineCmd::Shutdown => {
                self.stop_background_loops().await;
                true
            }
            EngineCmd::PingAll => {
                self.send_ping_all().await;
                false
            }
            EngineCmd::PeerRouteRemoved { vip } => {
                self.on_peer_route_removed(&vip, None);
                false
            }
            EngineCmd::SetCryptoKey(key, reply) => {
                let key = self.state.crypto_keys.set_primary(key);
                self.clear_data_crypto_state();
                self.state_view.write().crypto_key = Some(key);
                if self.mtu_pin {
                    self.apply_mtu_pin_policy();
                }
                if let Some(tx) = reply {
                    let _ = tx.send(());
                }
                false
            }
            EngineCmd::AddCryptoKey(key) => {
                if self.state.crypto_keys.primary().is_none() {
                    let key = self.state.crypto_keys.set_primary(key);
                    self.clear_data_crypto_state();
                    self.state_view.write().crypto_key = Some(key);
                    if self.mtu_pin {
                        self.apply_mtu_pin_policy();
                    }
                } else {
                    let _ = self.state.crypto_keys.add_key(key);
                }
                false
            }
            EngineCmd::BindPeerKey { peer, key } => {
                let key = self.state.crypto_keys.add_key(key);
                self.state.crypto_keys.bind_peer_key(peer, key);
                false
            }
            EngineCmd::SetJoinSender(tx) => {
                self.state.join_tx = Some(tx);
                false
            }
            EngineCmd::PrepareJoin {
                join_tx,
                key,
                target,
                body,
            } => {
                let now = Instant::now();
                if let Some(prev) = self.last_prepare_join_at {
                    if now.duration_since(prev) < Duration::from_millis(200) {
                        self.ui_err(term_style::fmt_join_line_stderr(format_args!(
                            " PrepareJoin throttled (min 200ms between attempts)"
                        )));
                        let _ = join_tx.send(None);
                        return false;
                    }
                }
                self.last_prepare_join_at = Some(now);

                if let Some(old) = self.state.join_tx.take() {
                    let _ = old.send(None);
                }
                self.state.join_tx = Some(join_tx);
                let key = self.state.crypto_keys.set_primary(key);
                self.state_view.write().crypto_key = Some(key);
                if self.mtu_pin {
                    self.apply_mtu_pin_policy();
                }
                if let Some(target) = target {
                    self.send_ctrl_signed_to(target, PKT_HPCH, self.state.my_vip.as_bytes())
                        .await;

                    self.send_ctrl_signed_to(target, PKT_JOIN, &body).await;

                    let sock = self.socket.clone();
                    let sv = self.state_view.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        let snap = sv.read().clone();
                        let pkt = build_signed_or_plain_static(
                            snap.crypto_key.clone(),
                            &snap.ctrl_send_ctr,
                            PKT_HPCH,
                            snap.my_vip.as_bytes(),
                        );
                        let _ = sock.send_to(&pkt, target).await;
                    });
                }
                if self.decentralized.is_active() && self.decentralized.is_joiner() {
                    self.spawn_decentralized_join_punch();
                }
                false
            }
            EngineCmd::SendJoin { target, body } => {
                self.send_ctrl_signed_to(target, PKT_HPCH, self.state.my_vip.as_bytes())
                    .await;
                self.send_ctrl_signed_to(target, PKT_JOIN, &body).await;
                false
            }
            EngineCmd::ManualPunch { target, count } => {
                let socket = self.socket.clone();
                let state_view = self.state_view.clone();
                tokio::spawn(async move {
                    let snap = state_view.read().clone();
                    let hpch_body = snap.my_vip.into_bytes();
                    let crypto_key = snap.crypto_key;
                    for _ in 0..count {
                        let pkt = build_signed_or_plain_static(
                            crypto_key.clone(),
                            &snap.ctrl_send_ctr,
                            PKT_HPCH,
                            &hpch_body,
                        );
                        let _ = socket.send_to(&pkt, target).await;
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                });
                false
            }
            EngineCmd::StartPunchWorkflow {
                key,
                bases,
                log_stages,
            } => {
                self.spawn_punch_workflow(&key, bases, log_stages);
                false
            }
            EngineCmd::StopPunchWorkflow { key } => {
                self.stop_punch_workflow_key(&key);
                false
            }
            EngineCmd::SetPeerKeepalive {
                key,
                targets,
                interval_ms,
            } => {
                if targets.is_empty() {
                    return false;
                }
                if let Some(stop) = self.peer_keepalive_stops.remove(&key) {
                    stop.store(true, Ordering::Release);
                }
                let stop = Arc::new(AtomicBool::new(false));
                self.peer_keepalive_stops.insert(key, stop.clone());
                let socket = self.socket.clone();
                let state_view = self.state_view.clone();
                let outbound = self.outbound_udp.clone();
                let interval = Duration::from_millis(interval_ms.max(100));
                tokio::spawn(async move {
                    loop {
                        if stop.load(Ordering::Acquire) {
                            break;
                        }
                        let snap = state_view.read().clone();
                        let keepalive_body = snap.my_vip.into_bytes();
                        let crypto_key = snap.crypto_key;
                        let hpch = build_signed_or_plain_static(
                            crypto_key.clone(),
                            &snap.ctrl_send_ctr,
                            PKT_HPCH,
                            &keepalive_body,
                        );
                        let kpal = build_signed_or_plain_static(
                            crypto_key,
                            &snap.ctrl_send_ctr,
                            PKT_KPAL,
                            &keepalive_body,
                        );
                        for target in &targets {
                            if socket.send_to(&hpch, target).await.is_ok() {
                                outbound.note(*target);
                            }
                            if socket.send_to(&kpal, target).await.is_ok() {
                                outbound.note(*target);
                            }
                        }
                        tokio::time::sleep(interval).await;
                    }
                });
                false
            }
            EngineCmd::StopPeerKeepalive { key } => {
                if let Some(stop) = self.peer_keepalive_stops.remove(&key) {
                    stop.store(true, Ordering::Release);
                }
                false
            }
            EngineCmd::SetIdentity {
                my_vip,
                my_node_id,
                subnet_prefix,
                vip_epoch,
                reply,
            } => {
                self.state.my_vip = my_vip.clone();
                self.state.my_node_id = my_node_id;
                self.state.vip_epoch = vip_epoch;
                self.state.my_vip_u32 = my_vip.parse::<Ipv4Addr>().map(u32::from).unwrap_or(0);
                self.state.subnet_prefix = subnet_prefix.clamp(8, 30);
                self.state_view.write().my_vip = my_vip.clone();
                if !my_vip.is_empty() {
                    let prefix = self.state.subnet_prefix;
                    let drained = {
                        let mut rt = self.routing.write();
                        rt.drain_vips_outside_subnet(&my_vip, prefix)
                    };
                    for (vip, _ep, node_id) in drained {
                        let node = (!node_id.is_empty()).then(|| node_id.as_ref());
                        self.on_peer_route_removed(&vip, node);
                    }
                }
                if let Some(tx) = reply {
                    let _ = tx.send(());
                }
                false
            }
            EngineCmd::SetSocketBuffers {
                sndbuf,
                rcvbuf,
                reply,
            } => {
                let sock_ref = SockRef::from(&*self.socket);
                let _ = sock_ref.set_send_buffer_size(sndbuf.max(1) as usize);
                let _ = sock_ref.set_recv_buffer_size(rcvbuf.max(1) as usize);
                let actual_snd = sock_ref
                    .send_buffer_size()
                    .unwrap_or(sndbuf.max(1) as usize) as i32;
                let actual_rcv = sock_ref
                    .recv_buffer_size()
                    .unwrap_or(rcvbuf.max(1) as usize) as i32;
                self.applied_udp_sndbuf = actual_snd;
                self.applied_udp_rcvbuf = actual_rcv;
                let _ = reply.send((actual_snd, actual_rcv));
                false
            }
            EngineCmd::QueryRuntimeSnapshot { reply } => {
                let snap = RuntimeSnapshot {
                    pacing: self.pacing.load_obs().queue,
                    udp_sndbuf: self.applied_udp_sndbuf,
                    udp_rcvbuf: self.applied_udp_rcvbuf,
                    tun_inject_capacity: self.tun_inject_capacity,
                    tun_inject_receivers: self.state.tun_inject_tx.receiver_count(),
                    pmtud_peers: self.pmtud.snapshot(),
                    pin_mtu: self.mtu_pin,
                    path_mtu: self.pmtud.min_mtu(),
                };
                let _ = reply.send(snap);
                false
            }
            EngineCmd::RuntimeViewBegin { reply } => {
                self.runtime_view_begin().await;
                let _ = reply.send(());
                false
            }
            EngineCmd::RuntimeViewEnd { reply } => {
                self.runtime_view_end();
                let _ = reply.send(());
                false
            }
            EngineCmd::SetPaceClock(apply) => {
                self.stop_pace_clock_only().await;
                self.pacing_thread.shared.store_apply(apply);
                let mut cfg = self.pacing.load_obs().config;
                cfg.tick_us = pace_clock::clamp_tick_us(cfg.tick_us);
                self.pacing.set_config(cfg);
                self.pacing_thread
                    .shared
                    .tick_us
                    .store(cfg.tick_us, Ordering::Release);
                self.spawn_pacing_clock_thread_reusing_shared();
                false
            }
            EngineCmd::SetPacing(cfg) => {
                let tick_us = pace_clock::clamp_tick_us(cfg.tick_us);
                self.pacing.set_config(PacingConfig { tick_us, ..cfg });
                self.update_pacing_tick(tick_us);
                false
            }
            EngineCmd::SetPacingAndPaceClock { cfg, apply } => {
                self.stop_pace_clock_only().await;
                self.pacing_thread.shared.store_apply(apply);
                let tick_us = pace_clock::clamp_tick_us(cfg.tick_us);
                self.pacing.set_config(PacingConfig { tick_us, ..cfg });
                self.pacing_thread
                    .shared
                    .tick_us
                    .store(tick_us, Ordering::Release);
                self.spawn_pacing_clock_thread_reusing_shared();
                false
            }
            EngineCmd::SetDrrEnabled(enabled) => {
                self.pacing.set_drr_enabled(enabled);
                false
            }
            EngineCmd::SetRetransmitBypassPps(pps) => {
                self.retransmit_sender.set_max_pps(pps);
                false
            }
            EngineCmd::SetRawPerf(enabled) => {
                self.rawperf_mode = enabled;
                false
            }
            EngineCmd::SetFecEnabled(enabled) => {
                if self.fec_enabled && !enabled {
                    let _ = self.fec_tx.set_encode_enabled(false);
                    self.fec_flush_all_and_drain();
                    self.fec_decoders.clear();
                } else if !self.fec_enabled && enabled {
                    let _ = self.fec_tx.set_encode_enabled(true);
                }
                self.fec_enabled = enabled;
                false
            }
            EngineCmd::SetFecConfig {
                data_shards,
                parity_shards,
                force_ratio,
            } => {
                self.fec_flush_all_and_drain();
                if force_ratio {
                    let total = data_shards as usize + parity_shards as usize;
                    if data_shards == 0
                        || parity_shards == 0
                        || total > self.advanced_tuning.fec.fec_max_total_shards
                    {
                        self.fec_forced_ratio = None;
                    } else {
                        self.fec_forced_ratio = Some((data_shards, parity_shards));
                    }
                } else {
                    self.fec_forced_ratio = None;
                }
                false
            }
            EngineCmd::ApplyAdvancedTuning { tuning, reply } => {
                self.apply_advanced_tuning(tuning);
                let _ = reply.send(self.advanced_tuning.clone());
                false
            }
            EngineCmd::QueryFecStats { reply } => {
                let mut out = Vec::new();
                for (dest, st) in &self.fec_send_by_dest {
                    let Some((ds, ps)) = st.ratio_last else {
                        continue;
                    };
                    out.push((*dest, ds, ps, st.rx_loss_ewma));
                }
                let _ = reply.send(out);
                false
            }
            EngineCmd::SetCandidates(cands) => {
                self.state.candidates = cands;
                false
            }
            EngineCmd::SendPeerRelay {
                relay_ep,
                dst_node,
                kind,
                payload,
            } => {
                let v = json!({
                    "ttl": 1,
                    "dst_node": dst_node,
                    "src_node": self.state.my_node_id,
                    "kind": kind,
                    "payload": payload,
                });
                let body = v.to_string();
                let _ = self
                    .send_control_packet(relay_ep, PKT_PRXY, body.as_bytes())
                    .await;
                false
            }
            EngineCmd::SetMembershipVersion(v) => {
                self.state.membership_version = v;
                false
            }
            EngineCmd::BroadcastLeave {
                node_id,
                vip,
                vip_epoch,
                event_id,
            } => {
                if !self.accept_wire_claim_vip(&vip) {
                    return false;
                }
                let now = Instant::now();
                install_leave_tombstone(
                    &mut self.leave_tombs,
                    &node_id,
                    &vip,
                    vip_epoch,
                    now,
                    LEAVE_TOMBSTONE_TTL,
                );
                remove_claim(&mut self.claim_map, &node_id);
                let body = serde_json::json!({
                    "proto_ver": WIRE_PROTOCOL_VERSION,
                    "event_id": event_id,
                    "node_id": node_id,
                    "vip": vip,
                    "vip_epoch": vip_epoch,
                    "ts_ms": now_epoch_ms(),
                })
                .to_string();
                let members: Vec<SocketAddr> = self.routing.read().endpoints_excluding_stale();
                for ep in members {
                    let _ = self
                        .send_control_packet(ep, PKT_LEAVE, body.as_bytes())
                        .await;
                }
                false
            }
            EngineCmd::TriggerClaimGossip => {
                self.broadcast_claim_gossip().await;
                false
            }
            EngineCmd::QueryPublicEndpoint {
                timeout,
                force_refresh,
                reply,
            } => {
                if force_refresh {
                    self.cached_stun_endpoint = None;
                } else if let Some((at, ep)) = &self.cached_stun_endpoint {
                    let ttl =
                        Duration::from_secs(self.advanced_tuning.engine_limits.stun_cache_ttl_secs);
                    if at.elapsed() <= ttl {
                        let _ = reply.send(Some(ep.clone()));
                        return false;
                    }
                }
                if self.pending_stun_queries.len()
                    >= self.advanced_tuning.engine_limits.max_pending_stun_queries
                {
                    let _ = reply.send(None);
                    return false;
                }
                let query_id = self.next_stun_query_id;
                self.next_stun_query_id = self.next_stun_query_id.wrapping_add(1).max(1);
                self.active_stun_query_ids.insert(query_id);
                self.pending_stun_queries.insert(
                    query_id,
                    PendingStunQuery {
                        votes: HashMap::new(),
                        txns: HashMap::new(),
                        deadline: Instant::now()
                            + timeout.saturating_add(STUN_QUERY_DEADLINE_SLACK),
                        reply,
                        early_stun: Vec::new(),
                    },
                );
                let resolve_tx = self.stun_resolve_tx.clone();
                let socket = self.socket.clone();
                tokio::spawn(async move {
                    let dns_timeout = Duration::from_millis(800);
                    let (l0, l1, l2, l3) = tokio::join!(
                        tokio::time::timeout(
                            dns_timeout,
                            tokio::net::lookup_host((
                                stun::STUN_SERVERS[0].0.to_string(),
                                stun::STUN_SERVERS[0].1
                            ))
                        ),
                        tokio::time::timeout(
                            dns_timeout,
                            tokio::net::lookup_host((
                                stun::STUN_SERVERS[1].0.to_string(),
                                stun::STUN_SERVERS[1].1
                            ))
                        ),
                        tokio::time::timeout(
                            dns_timeout,
                            tokio::net::lookup_host((
                                stun::STUN_SERVERS[2].0.to_string(),
                                stun::STUN_SERVERS[2].1
                            ))
                        ),
                        tokio::time::timeout(
                            dns_timeout,
                            tokio::net::lookup_host((
                                stun::STUN_SERVERS[3].0.to_string(),
                                stun::STUN_SERVERS[3].1
                            ))
                        ),
                    );
                    let mut txns = HashMap::<[u8; 12], ()>::new();
                    let mut chosen_stun_addr: Option<SocketAddr> = None;
                    for res in [l0, l1, l2, l3] {
                        let Ok(Ok(addrs)) = res else {
                            continue;
                        };
                        for addr in addrs.take(2) {
                            if chosen_stun_addr.is_none() {
                                chosen_stun_addr = Some(addr);
                            }
                            let (req, txn) = stun::build_binding_request();
                            if socket.send_to(&req, addr).await.is_ok() {
                                txns.insert(txn, ());
                            }
                        }
                    }
                    let _ = resolve_tx.send(ResolvedStunQuery {
                        query_id,
                        txns,
                        chosen_stun_addr,
                        timeout,
                    });
                });
                false
            }
            EngineCmd::SetAdapterName(name) => {
                if name.trim().is_empty() {
                    self.state.adapter_name = None;
                } else if is_safe_interface_alias(&name) {
                    self.state.adapter_name = Some(name);

                    if self.mtu_pin {
                        self.apply_mtu_pin_policy();
                    } else {
                        let enc_overhead = if self.has_crypto() {
                            MENC_WIRE_OVERHEAD
                        } else {
                            0
                        };
                        let suggested = self.pmtud.suggested_adapter_mtu(enc_overhead) as u16;
                        if suggested >= 576 && suggested <= 1500 {
                            self.try_apply_adapter_mtu(suggested);
                        }
                    }
                }
                false
            }
            EngineCmd::SetMtuPin {
                pin_mtu,
                adapter_mtu,
            } => {
                self.mtu_pin = pin_mtu;
                self.configured_adapter_mtu = adapter_mtu;
                self.apply_mtu_pin_policy();
                false
            }
            EngineCmd::PingPeer {
                dest,
                timeout_ms,
                reply,
            } => {
                let ts = now_epoch_ms();
                let ping_id = self.allocate_ping_id();
                let mut payload = [0u8; 16];
                payload[..8].copy_from_slice(&ping_id.to_le_bytes());
                payload[8..].copy_from_slice(&ts.to_le_bytes());
                let pkt = self.frame_compact_reuse(CompactPacketType::Ping, &payload);
                if self.socket.send_to(&pkt, dest).await.is_err() {
                    let _ = reply.send(-1);
                    return false;
                }
                let deadline =
                    Instant::now() + Duration::from_millis(timeout_ms.max(50).min(60_000));
                self.pending_pings.insert(
                    ping_id,
                    PendingPing {
                        dest,
                        allow_ip_match: true,
                        deadline,
                        sent_at_ms: ts,
                        kind: PendingPingKind::User { reply },
                    },
                );
                false
            }
            EngineCmd::ParaSendHello {
                target_vip,
                payload,
            } => {
                let _ = self
                    .send_control_packet(target_vip, PKT_PARA_HELLO, &payload)
                    .await;
                false
            }
            EngineCmd::ParaSendReply {
                target_vip,
                payload,
            } => {
                let _ = self
                    .send_control_packet(target_vip, PKT_PARA_REPLY, &payload)
                    .await;
                false
            }
            EngineCmd::ParaSendOk {
                target_vip,
                payload,
            } => {
                let _ = self
                    .send_control_packet(target_vip, PKT_PARA_OK, &payload)
                    .await;
                false
            }
            EngineCmd::ParaSendPunchAck { target, payload } => {
                let _ = self
                    .send_control_packet(target, PKT_PARA_PUNCH_ACK, &payload)
                    .await;
                false
            }
            EngineCmd::ParaSetListener {
                notify_tx,
                replace_existing,
                reply,
            } => {
                if replace_existing {
                    self.para_notify_txs.clear();
                } else {
                    self.para_notify_txs.retain(|_, tx| !tx.is_closed());
                }
                let listener_id = self.next_para_listener_id;
                self.next_para_listener_id = self.next_para_listener_id.wrapping_add(1).max(1);
                self.para_notify_txs.insert(listener_id, notify_tx);
                if let Some(reply) = reply {
                    let _ = reply.send(listener_id);
                }
                false
            }
            EngineCmd::ParaRemoveListener { listener_id } => {
                self.para_notify_txs.remove(&listener_id);
                false
            }
            EngineCmd::StartDecentralized {
                room_id,
                trackers,
                announce_secs,
                is_joiner,
                join_body,
                node_id,
            } => {
                if let Some(stop) = self.manual_punch_stops.remove("decentralized") {
                    stop.store(true, Ordering::Release);
                }
                let listen_port = self
                    .socket
                    .local_addr()
                    .map(|a| a.port())
                    .unwrap_or(7878)
                    .max(7878);
                if !node_id.is_empty() {
                    self.state.my_node_id = node_id.clone();
                }
                // Restart/resync (finalize join, profile sync) must stay silent on UI.
                let first_activation = !self.decentralized.is_active();
                self.decentralized.start(
                    room_id,
                    &node_id,
                    trackers,
                    announce_secs,
                    is_joiner,
                    join_body,
                    listen_port,
                );
                self.reset_reconnect_fastpath_state();
                if first_activation {
                    // Live-only: closing/reopening CLI must not replay this line.
                    self.ui.emit_plain_live(format!(
                        "  [Decentralized] Tracker discovery active (room {})",
                        hex::encode(room_id)
                    ));
                }
                false
            }
            EngineCmd::StopDecentralized => {
                self.stop_decentralized_discovery();
                false
            }
            EngineCmd::CancelJoinWait => {
                if let Some(tx) = self.state.join_tx.take() {
                    let _ = tx.send(None);
                }
                self.pending_join_ack = None;
                self.stop_decentralized_discovery();
                false
            }
            EngineCmd::TakePendingJoinAck { reply } => {
                let _ = reply.send(self.pending_join_ack.take());
                false
            }
            EngineCmd::QueryDiscoveredCount { reply } => {
                let _ = reply.send(self.decentralized.discovered_endpoints().len());
                false
            }
            EngineCmd::ResetSession { reply } => {
                self.reset_session_state().await;
                let _ = reply.send(());
                false
            }
        }
    }

    fn apply_hb_body(&mut self, body: &[u8], from: SocketAddr, authenticated: bool) {
        self.touch_routing_endpoint(from);
        if body.is_empty() {
            return;
        }
        if let Ok(vip) = std::str::from_utf8(body).map(str::trim) {
            if vip.parse::<Ipv4Addr>().is_ok() {
                self.learn_route_from_hole_punch_body(body, from, true, authenticated);
            }
        }
    }

    async fn apply_hol_body(&mut self, body: &[u8], from: SocketAddr, authenticated: bool) {
        self.learn_route_from_hole_punch_body(body, from, false, authenticated);
        self.try_stop_ice_checks_for_join_peer(from, body);
        self.send_ctrl_signed_to(from, PKT_HACK, self.state.my_vip.as_bytes())
            .await;
    }

    async fn handle_mctl(&mut self, body: &[u8], from: SocketAddr, authenticated: bool) {
        let Some(parsed) = parse_mctl(body) else {
            return;
        };
        if parsed.signaling_ok {
            if let Some(vip) = parsed.vip.as_deref() {
                if (parsed.flags & MCTL_FLAG_HB) != 0 {
                    self.apply_hb_body(vip, from, authenticated);
                }
                if (parsed.flags & MCTL_FLAG_HOL) != 0 {
                    self.apply_hol_body(vip, from, authenticated).await;
                }
            }
        }
    }

    async fn send_mctl(&mut self, dest: SocketAddr, flags: u16, vip: Option<&[u8]>) -> bool {
        let Some(body) = encode_mctl(flags, vip) else {
            return false;
        };
        self.send_control_packet(dest, PKT_MCTL, &body).await
    }

    fn note_outbound_udp(&self, dest: SocketAddr) {
        let poison_before = self.outbound_udp.poison_recover_total();
        self.outbound_udp.note(dest);
        self.metrics.inc_outbound_note();
        if self.outbound_udp.poison_recover_total() > poison_before {
            self.metrics.inc_outbound_note_poison_recover();
        }
    }

    fn forget_outbound_udp(&self, dest: SocketAddr) {
        self.outbound_udp.remove(dest);
    }

    fn remove_peer_endpoint(&mut self, ep: SocketAddr) {
        self.pacing.remove_peer(ep);
        self.forget_outbound_udp(ep);
        self.pmtud.remove_peer(ep);
    }

    async fn send_keepalives(&mut self) {
        let body = self.state.my_vip.clone().into_bytes();
        let now = Instant::now();
        let keepalive = Duration::from_secs(self.advanced_tuning.timers.keepalive_secs);

        let routes = {
            let rt = self.routing.read();
            rt.endpoints_excluding_stale()
        };

        let retain_keys: HashSet<SocketAddr> = routes.iter().copied().collect();
        self.outbound_udp.retain_only(&retain_keys);

        for &ep in &routes {
            if !self.outbound_udp.needs_refresh(ep, now, keepalive) {
                self.metrics.inc_keepalive_suppressed();
                continue;
            }
            if self
                .send_mctl(ep, MCTL_FLAG_HB, Some(body.as_slice()))
                .await
            {
                self.metrics.inc_keepalive_sent();
            }
        }
    }

    async fn send_ctrl_signed_to(&self, dest: SocketAddr, tag: &[u8; 4], body: &[u8]) -> bool {
        let pkt = build_signed_or_plain_static(
            self.outbound_crypto_key_for(dest),
            &self.ctrl_send_ctr,
            tag,
            body,
        );
        let ok = self.socket.send_to(&pkt, dest).await.is_ok();
        if ok {
            self.note_outbound_udp(dest);
        }
        ok
    }

    fn control_race_dests(&self, primary: SocketAddr) -> Vec<SocketAddr> {
        if !(self.state.feature_flags.multipath_core && self.state.feature_flags.control_path_race)
        {
            return vec![primary];
        }
        let dests = self
            .routing
            .read()
            .control_race_endpoints_for_endpoint(primary, None);
        if dests.is_empty() {
            vec![primary]
        } else {
            dests
        }
    }

    fn enqueue_ctrl_raced(&mut self, primary: SocketAddr, tag: &[u8; 4], body: &[u8]) {
        let dests = self.control_race_dests(primary);
        let extra = dests.len().saturating_sub(1) as u64;
        for ep in dests {
            let pkt = self.build_signed_or_plain_reuse(self.outbound_crypto_key_for(ep), tag, body);
            self.pacing.enqueue_control(pkt, ep);
        }
        self.metrics.inc_control_path_race_extra(extra);
    }

    async fn handle_reliable_packet(&mut self, body: &[u8], from: SocketAddr) {
        if body.len() < 5 {
            return;
        }
        let seq = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        let inner = match CompactPacketType::try_from_byte(body[4]) {
            Ok(CompactPacketType::JoinAck) => CompactPacketType::JoinAck,
            _ => {
                self.metrics.inc_reliable_unknown_inner_tag();
                return;
            }
        };
        let _ = inner;

        let ack = ReliableChannel::ack_packet(seq);
        let _ = self.socket.send_to(&ack, from).await;
        self.cleanup_reliable_seen();
        let dk = {
            let rt = self.routing.read();
            if let Some(vip) = rt.ep_to_vip.get(&from) {
                vip.parse::<Ipv4Addr>()
                    .map(|ip| ReliableDedupKey::VipU32(u32::from(ip)))
                    .unwrap_or(ReliableDedupKey::Addr(from))
            } else {
                ReliableDedupKey::Addr(from)
            }
        };
        if !self.reliable_seen.insert((dk, seq)) {
            return;
        }
        self.reliable_seen_timeline
            .push_back((tokio::time::Instant::now(), dk, seq));
        self.touch_routing_endpoint(from);
        // Compact JoinAck is rejected when crypto is enabled; expect sealed MPJA.
        if self.has_crypto() {
            return;
        }
        self.dispatch_control(*PKT_JACK, &body[5..], from, false)
            .await;
    }

    async fn handle_signed_wrapper(&mut self, body: &[u8], from: SocketAddr) {
        let src_key = src_addr_key(from);
        const MIN_CTRL_AEAD: usize = WIRE_COUNTER_LEN + 4 + DATA_TAG_LEN;
        if body.len() < MIN_CTRL_AEAD {
            self.metrics.inc_auth_failures();
            return;
        }
        let mut counter_wire = [0u8; WIRE_COUNTER_LEN];
        counter_wire.copy_from_slice(&body[..WIRE_COUNTER_LEN]);
        let counter = decode_wire_counter(&counter_wire);
        let sealed = &body[WIRE_COUNTER_LEN..];

        let keys = self.state.crypto_keys.keys_for_decrypt(from);
        let mut chosen_key: Option<Arc<AeadKey>> = None;
        for key in keys {
            let Some(aead) = self.control_plane_cipher(key.as_ref()) else {
                continue;
            };
            self.decrypt_scratch.clear();
            if aead
                .open_into(&counter_wire, sealed, &mut self.decrypt_scratch)
                .is_ok()
            {
                chosen_key = Some(key);
                break;
            }
        }
        let Some(chosen_key) = chosen_key else {
            self.metrics.inc_auth_failures();
            return;
        };
        if self.decrypt_scratch.len() < 4 {
            self.metrics.inc_auth_failures();
            return;
        }
        let mut inner_tag = [0u8; 4];
        inner_tag.copy_from_slice(&self.decrypt_scratch[..4]);
        let frame_body = self.decrypt_scratch[4..].to_vec();

        if !self.ctrl_limiter.allow(src_key) {
            return;
        }
        if !self.ctrl_replay.allows(src_key, counter) {
            return;
        }
        self.ctrl_replay.commit(src_key, counter);
        self.touch_routing_endpoint(from);
        self.state.crypto_keys.bind_peer_key(from, chosen_key);
        self.dispatch_control(inner_tag, &frame_body, from, true)
            .await;
    }

    async fn dispatch_control(
        &mut self,
        tag: [u8; 4],
        body: &[u8],
        from: SocketAddr,
        authenticated: bool,
    ) {
        let src_key = src_addr_key(from);
        let bypass_ctrl_limit = matches!(
            tag,
            t if t == *PKT_HPCH
                || t == *PKT_HACK
                || t == *PKT_KPAL
                || t == *PKT_MCTL
                || t == *PKT_JACK
        );
        if !authenticated {
            if !bypass_ctrl_limit && !self.ctrl_limiter.allow(src_key) {
                return;
            }
        }

        if self.has_crypto() && !authenticated && !allow_unauth_control_tag_with_crypto(tag) {
            self.metrics.inc_unauth_drop_crypto_gate();
            return;
        }

        if tag == *PKT_PARA_HELLO {
            let Ok(v) = serde_json::from_slice::<ParaHelloMsg>(body) else {
                return;
            };
            if !is_recent_para_ts(v.ts_ms) {
                return;
            }
            self.try_para_notify(ParaSignal::HelloReceived {
                from,
                public_ip: v.public_ip,
                public_port: v.public_port,
                network_id: v.network_id,
                node_id: v.node_id,
                candidates: v.candidates,
                start_at_ms: v.start_at_ms,
                session_id: v.session_id,
            });
            return;
        }

        if tag == *PKT_PARA_REPLY {
            let Ok(v) = serde_json::from_slice::<ParaReplyMsg>(body) else {
                return;
            };
            if !is_recent_para_ts(v.ts_ms) {
                return;
            }
            self.try_para_notify(ParaSignal::ReplyReceived {
                from,
                public_ip: v.public_ip,
                public_port: v.public_port,
                network_id: v.network_id,
                node_id: v.node_id,
                candidates: v.candidates,
                agreed_start_at_ms: v.agreed_start_at_ms,
                session_id: v.session_id,
                responder_vip: v.responder_vip,
            });
            return;
        }

        if tag == *PKT_PARA_OK {
            let Ok(v) = serde_json::from_slice::<ParaOkMsg>(body) else {
                return;
            };
            if !is_recent_para_ts(v.ts_ms) {
                return;
            }
            self.try_para_notify(ParaSignal::OkReceived {
                from,
                node_id: v.node_id,
                session_id: v.session_id,
            });
            return;
        }

        if tag == *PKT_PARA_PUNCH_ACK {
            let Ok(v) = serde_json::from_slice::<ParaPunchAckMsg>(body) else {
                return;
            };
            if !is_recent_para_ts(v.ts_ms) {
                return;
            }
            self.try_para_notify(ParaSignal::PunchAckReceived {
                from,
                node_id: v.node_id,
                session_id: v.session_id,
            });
            return;
        }

        if tag == *PKT_RDYS || tag == *PKT_MSTR {
            self.touch_routing_endpoint(from);
            return;
        }

        if tag == *PKT_MERR {
            if let Some(tx) = self.state.join_tx.take() {
                let _ = tx.send(None);
            }
            return;
        }

        if tag == *PKT_JOIN {
            // Any member with identity may ack a claim hello (equal-peer join).
            if self.state.my_vip.is_empty() || self.state.my_node_id.is_empty() {
                return;
            }
            if !self.join_rate_limiter.allow(join_rate_key(from)) {
                return;
            }
            if !self.join_ip_rate_limiter.allow(join_ip_key(from)) {
                return;
            }
            if body.len() > 8192 {
                return;
            }
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
                return;
            };
            let wire_ver = v.get("proto_ver").and_then(|x| x.as_u64());
            if wire_ver != Some(WIRE_PROTOCOL_VERSION) {
                let err = json!({
                    "error": "wire_protocol_mismatch",
                    "expected": WIRE_PROTOCOL_VERSION,
                    "got": wire_ver.unwrap_or(0),
                });
                let _ = self
                    .send_control_packet(from, PKT_MERR, err.to_string().as_bytes())
                    .await;
                return;
            }
            let node = v
                .get("node_id")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string();
            if node.is_empty() || node.len() > 64 {
                return;
            }
            let claim_vip = v
                .get("vip")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let claim_epoch = v.get("vip_epoch").and_then(|x| x.as_u64()).unwrap_or(0);
            if !self.accept_wire_claim_vip(&claim_vip) {
                return;
            }
            let peer_cands_json = v.get("candidates").cloned();
            let already_known = self.routing.read().lookup_ep_by_node(&node).is_some();
            self.apply_remote_claim(&node, &claim_vip, claim_epoch, from);
            let reply = json!({
                "proto_ver": WIRE_PROTOCOL_VERSION,
                "node_id": self.state.my_node_id,
                "vip": self.state.my_vip,
                "vip_epoch": self.state.vip_epoch,
                "prefix": self.state.subnet_prefix,
                "candidates": self.state.candidates,
                "crypto_required": self.has_crypto(),
            });
            let reply_body = reply.to_string();
            if self.has_crypto() {
                let sent = self
                    .send_control_packet(from, PKT_JACK, reply_body.as_bytes())
                    .await;
                if !sent {
                    let key = self
                        .outbound_crypto_key_for(from)
                        .or_else(|| self.state.crypto_keys.shared_signing_key());
                    if let Some(key) = key {
                        if let Some(sealed) =
                            self.seal_control_body(key.as_ref(), PKT_JACK, reply_body.as_bytes())
                        {
                            let pkt = self.frame_with_tag_reuse(PKT_CTSIG, &sealed);
                            let _ = self.pacing.enqueue_retransmit(pkt, from);
                        }
                    }
                }
            } else {
                let rtt_hint = self.routing_rtt_hint_ms(from);
                match self.reliable.send(
                    CompactPacketType::JoinAck,
                    reply_body.as_bytes(),
                    from,
                    rtt_hint,
                ) {
                    SendResult::Queued { seq, packet } => {
                        if self.socket.send_to(&packet, from).await.is_ok() {
                            self.reliable.mark_sent(seq, Instant::now());
                        }
                    }
                    SendResult::Backpressure => {
                        let raw = frame_with_tag(PKT_JACK, reply_body.as_bytes());
                        let _ = self.pacing.enqueue_retransmit(Bytes::from(raw), from);
                    }
                }
            }

            self.send_ctrl_signed_to(from, PKT_HPCH, self.state.my_vip.as_bytes())
                .await;
            self.broadcast_claim_gossip().await;
            if let Some(cands_val) = peer_cands_json {
                if let Ok(cands) = serde_json::from_value::<Vec<IceCandidate>>(cands_val) {
                    if !cands.is_empty() {
                        self.start_ice_checks(cands, node.clone()).await;
                    }
                }
            }
            if !already_known {
                self.ui
                    .emit_plain_live(term_style::fmt_join_line(format_args!(
                        " Member ack join hello: node={} vip={} from={}",
                        node, claim_vip, from
                    )));
            }
            return;
        }

        if tag == *PKT_JACK {
            if body.len() > 8192 {
                return;
            }
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
                return;
            };
            let wire_ver = v.get("proto_ver").and_then(|x| x.as_u64());
            if wire_ver != Some(WIRE_PROTOCOL_VERSION) {
                self.ui_err(term_style::fmt_join_line_stderr(format_args!(
                    " MPJA rejected: wire proto_ver {:?} (need {}).",
                    wire_ver, WIRE_PROTOCOL_VERSION
                )));
                return;
            }
            if !jack_mpja_body_valid(&v, from, self.unit_network_key().as_ref()) {
                return;
            }
            let peer_vip = v
                .get("vip")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let peer_node_id = v
                .get("node_id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let peer_epoch = v.get("vip_epoch").and_then(|x| x.as_u64()).unwrap_or(0);
            let prefix = v
                .get("prefix")
                .and_then(|x| x.as_u64())
                .map(|n| n as u8)
                .unwrap_or(24)
                .clamp(8, 30);
            if self.state.join_tx.is_none() && !self.decentralized.is_joiner() {
                // Idle member: still learn acker claim for presence, but do not complete join.
                self.apply_remote_claim(&peer_node_id, &peer_vip, peer_epoch, from);
                return;
            }
            self.apply_remote_claim(&peer_node_id, &peer_vip, peer_epoch, from);
            let ack = JoinAck {
                peer_vip: peer_vip.clone(),
                peer_node_id: peer_node_id.clone(),
                subnet_prefix: prefix,
                peer_endpoint: from,
                local_vip: self.state.my_vip.clone(),
                vip_epoch: self.state.vip_epoch,
            };
            let delivered = try_deliver_join_ack(&mut self.state.join_tx, ack.clone());
            if !delivered && !self.decentralized.is_joiner() {
                return;
            }
            self.state.subnet_prefix = prefix;
            self.on_join_wait_finished();
            if delivered {
                self.ui_out(term_style::fmt_join_line(format_args!(
                    " MPJA received. Join handshake confirmed."
                )));
            } else {
                self.pending_join_ack = Some(ack);
                self.ui_out(term_style::fmt_join_line(format_args!(
                    " MPJA received; completing join..."
                )));
            }
            self.send_ctrl_signed_to(from, PKT_KPAL, self.state.my_vip.as_bytes())
                .await;
            self.send_ctrl_signed_to(from, PKT_HPCH, self.state.my_vip.as_bytes())
                .await;
            if let Some(cands_val) = v.get("candidates") {
                if let Ok(cands) = serde_json::from_value::<Vec<IceCandidate>>(cands_val.clone()) {
                    if !cands.is_empty() {
                        self.start_ice_checks(cands, peer_node_id).await;
                    }
                }
            }
            return;
        }

        if tag == *PKT_CLG {
            if authenticated {
                self.handle_claim_gossip_body(body, from).await;
            }
            return;
        }

        if tag == *PKT_LEAVE {
            if !authenticated {
                return;
            }
            if body.len() > 4096 {
                return;
            }
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
                return;
            };
            let event_id = v.get("event_id").and_then(|x| x.as_str()).unwrap_or("");
            if event_id.is_empty() || !self.mark_msmd_seen(event_id) {
                return;
            }
            let node_id = v.get("node_id").and_then(|x| x.as_str()).unwrap_or("");
            let vip = v.get("vip").and_then(|x| x.as_str()).unwrap_or("");
            let vip_epoch = v.get("vip_epoch").and_then(|x| x.as_u64()).unwrap_or(0);
            if node_id.is_empty() || !self.accept_wire_claim_vip(vip) {
                return;
            }
            let now = Instant::now();
            install_leave_tombstone(
                &mut self.leave_tombs,
                node_id,
                vip,
                vip_epoch,
                now,
                LEAVE_TOMBSTONE_TTL,
            );
            remove_claim(&mut self.claim_map, node_id);
            let leave_evicted: Option<(SocketAddr, Option<String>)> = {
                let mut rt = self.routing.write();
                match rt.table.get(vip) {
                    None => None,
                    Some(entry) => {
                        let node_ok = node_id.is_empty()
                            || entry.node_id.is_empty()
                            || entry.node_id.as_ref() == node_id;
                        if !node_ok {
                            return;
                        }
                        let ep = entry.endpoint;
                        let removed_node =
                            (!entry.node_id.is_empty()).then(|| entry.node_id.to_string());
                        rt.remove(vip);
                        Some((ep, removed_node))
                    }
                }
            };
            let leave_applied = leave_evicted.is_some();
            if leave_applied {
                let removed_node = leave_evicted.as_ref().and_then(|(_, n)| n.as_deref());
                self.on_peer_route_removed(vip, removed_node);
                self.notify_roster_remove(vip);
                self.stop_peer_reconnect_for_vip(vip);
            }
            if let Some((ep, _)) = leave_evicted {
                self.invalidate_fec_qd_cache(ep);
                self.state.crypto_keys.unbind_peer(ep);
                self.reliable.flush_dest(ep);
                self.teardown_fec_peer(ep);
            }
            if leave_applied {
                if let Some(handler) = &self.leave_handler {
                    handler(vip.to_string());
                }
            }
            return;
        }

        if tag == *PKT_PRXY {
            if body.len() > 8192 {
                return;
            }
            if !authenticated {
                let trusted_source = {
                    let rt = self.routing.read();
                    rt.ep_to_vip.contains_key(&from)
                };
                if !trusted_source {
                    self.metrics.inc_unauth_drop_crypto_gate();
                    return;
                }
            }
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
                return;
            };
            let ttl = v.get("ttl").and_then(|x| x.as_u64()).unwrap_or(0);
            let dst_node = v
                .get("dst_node")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let src_node = v
                .get("src_node")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let kind = v
                .get("kind")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let payload = v.get("payload").cloned().unwrap_or(serde_json::Value::Null);

            if dst_node == self.state.my_node_id {
                if kind == "candidates" {
                    if let Ok(cands) = serde_json::from_value::<Vec<IceCandidate>>(payload) {
                        self.start_ice_checks(cands, src_node).await;
                    }
                }
                return;
            }

            let hop_budget = crate::net::packet::prxy_forwarded_ttl(ttl);
            if let Some(fwd_ttl) = hop_budget {
                let src_matches_sender = {
                    let rt = self.routing.read();
                    rt.ep_to_vip.get(&from).is_some_and(|vip| {
                        rt.table.get(vip).is_some_and(|entry| {
                            if !entry.node_id.is_empty() {
                                entry.node_id.as_ref() == src_node
                            } else {
                                rt.node_to_vip.get(&src_node) == Some(vip)
                            }
                        })
                    })
                };
                if !src_matches_sender {
                    return;
                }
                let dst_ep = self.routing.read().lookup_ep_by_node(&dst_node);
                if let Some(dst_ep) = dst_ep {
                    let mut fwd = v.clone();
                    fwd["ttl"] = json!(fwd_ttl);
                    let fwd_body = fwd.to_string();
                    let _ = self
                        .send_control_packet(dst_ep, PKT_PRXY, fwd_body.as_bytes())
                        .await;
                }
            }
            return;
        }

        if tag == *PKT_BREK {
            self.touch_routing_endpoint(from);
            return;
        }

        if tag == *PKT_MCTL {
            self.handle_mctl(body, from, authenticated).await;
            return;
        }

        if tag == *PKT_KPAL {
            self.apply_hb_body(body, from, authenticated);
            return;
        }

        if tag == *PKT_HPCH {
            self.apply_hol_body(body, from, authenticated).await;
            return;
        }

        if tag == *PKT_HACK {
            self.learn_route_from_hole_punch_body(body, from, true, authenticated);
            self.try_stop_ice_checks_for_join_peer(from, body);
            return;
        }
    }

    async fn handle_mdat_like(&mut self, raw: Bytes, from: SocketAddr) {
        if raw.len() < 20 {
            return;
        }
        self.touch_routing_endpoint(from);
        let slice = raw.as_ref();
        let packet_len = raw.len() as u64;
        self.runtime_trace.add_wire_rx(packet_len);
        if self.state.feature_flags.dual_write_transition {
            let transition_active: Option<String> = {
                let rt = self.routing.read();
                rt.ep_to_vip
                    .get(&from)
                    .and_then(|vip| rt.transition_state(vip).is_some().then(|| vip.clone()))
            };
            if let Some(ref vip) = transition_active {
                if !self.bcast_dedup.is_fresh_scoped(vip.as_bytes(), slice) {
                    self.metrics.inc_transition_dedup_drops();
                    return;
                }
            }
        }
        if is_broadcast_or_multicast(slice) {
            if self.bcast_dedup.is_fresh(slice) {
                self.note_rx_bytes(from, packet_len);
                self.inject_to_tun(raw.clone());
                let (mut direct_eps, need_relay): (SmallVec<[SocketAddr; 16]>, bool) = {
                    let rt = self.routing.read();
                    let mut direct: SmallVec<[SocketAddr; 16]> = SmallVec::new();
                    let mut need_relay = false;
                    for (_vip, entry) in rt.table.iter() {
                        if entry.endpoint == from {
                            continue;
                        }
                        if should_relay(entry, &rt.failover) {
                            need_relay = true;
                        } else {
                            direct.push(entry.endpoint);
                        }
                    }
                    (direct, need_relay)
                };
                let hub_ep = if need_relay {
                    let rt = self.routing.read();
                    match rt.select_broadcast_relay_hop(&self.state.my_vip, Some(from)) {
                        RelaySelection::Hop(ep) => Some(ep),
                        RelaySelection::None => None,
                    }
                } else {
                    None
                };
                if let Some(hub) = hub_ep {
                    direct_eps.retain(|ep| *ep != hub);
                }
                for ep in &direct_eps {
                    let _ = self.send_menc_forward(*ep, slice).await;
                }
                if let Some(hub_ep) = hub_ep {
                    if hub_ep != from {
                        let _ = self.send_menc_forward(hub_ep, slice).await;
                    }
                }
            }
            return;
        }
        let dst = u32::from_be_bytes([slice[16], slice[17], slice[18], slice[19]]);
        if dst == self.state.my_vip_u32 && self.state.my_vip_u32 != 0 {
            self.note_rx_bytes_for_dst(dst, packet_len);
            self.inject_to_tun(raw);
            return;
        }
        let trusted = self.routing.read().ep_to_vip.contains_key(&from);
        if trusted {
            let target = self.routing.read().lookup_by_vip_u32(dst);
            if let Some(ep) = target {
                if ep != from {
                    let _ = self.send_menc_forward(ep, slice).await;
                }
            } else {
                self.metrics.inc_hub_forward_unknown_dst();
            }
            return;
        }
        self.metrics.inc_tun_inject_wrong_dst_drops();
    }

    fn frame_with_tag_reuse(&mut self, tag: &[u8; 4], body: &[u8]) -> Bytes {
        self.control_scratch.clear();
        self.control_scratch.reserve(4 + body.len());
        self.control_scratch.extend_from_slice(tag);
        self.control_scratch.extend_from_slice(body);
        self.control_scratch.split().freeze()
    }

    fn frame_compact_reuse(&mut self, ty: CompactPacketType, body: &[u8]) -> Bytes {
        self.control_scratch.clear();
        self.control_scratch.reserve(1 + body.len());
        self.control_scratch.extend_from_slice(&[ty.to_byte()]);
        self.control_scratch.extend_from_slice(body);
        self.control_scratch.split().freeze()
    }

    async fn send_compact_to(
        &mut self,
        dest: SocketAddr,
        ty: CompactPacketType,
        body: &[u8],
    ) -> bool {
        let pkt = self.frame_compact_reuse(ty, body);
        let ok = self.socket.send_to(&pkt, dest).await.is_ok();
        if ok {
            self.note_outbound_udp(dest);
        }
        ok
    }

    async fn handle_ping_body(&mut self, body: &[u8], from: SocketAddr) {
        self.touch_routing_endpoint(from);
        if let Some((ping_id, sender_ts)) = decode_ping_payload(body) {
            let owd = (now_epoch_ms() as i64).saturating_sub(sender_ts as i64);
            let owd_i32 = owd.clamp(i32::MIN as i64, i32::MAX as i64) as i32;
            let loss_permille = self
                .endpoint_to_vip_u32(from)
                .map(|vip| (self.size_loss.loss_ewma(vip) * 1000.0).round() as u32)
                .unwrap_or(0)
                .min(1000);
            let pong = encode_pong_payload(ping_id, sender_ts, owd_i32, loss_permille);
            self.send_compact_to(from, CompactPacketType::Pong, &pong)
                .await;
        }
    }

    async fn handle_pong_body(&mut self, body: &[u8], from: SocketAddr) {
        let Some((ping_id, _fallback_ts, fwd_owd_sample_ms, loss_permille)) =
            decode_pong_payload(body)
        else {
            return;
        };
        self.touch_routing_endpoint(from);
        let now_ms = now_epoch_ms();
        let Some(pending) = self.pending_pings.remove(&ping_id) else {
            return;
        };
        let from_ok = if pending.allow_ip_match {
            pending.dest.ip() == from.ip()
        } else {
            pending.dest == from
        };
        if !from_ok {
            self.pending_pings.insert(ping_id, pending);
            return;
        }
        self.probe_miss_by_ep.remove(&from);
        let rtt = (now_ms.saturating_sub(pending.sent_at_ms)) as i64;
        let (vip_rtt_updated, owd_outcome) = {
            let mut rt = self.routing.write();
            let vip_rtt_updated = rt.note_rtt(from, rtt.max(1), None);
            let owd_outcome = if vip_rtt_updated {
                rt.note_fwd_owd(from, fwd_owd_sample_ms as f64, rtt.max(1) as f64, None)
            } else {
                crate::routing::OwdSampleOutcome::Ignored
            };
            (vip_rtt_updated, owd_outcome)
        };
        match owd_outcome {
            crate::routing::OwdSampleOutcome::Applied => {
                self.metrics.inc_owd_samples_applied();
            }
            crate::routing::OwdSampleOutcome::Rejected => {
                self.metrics.inc_owd_samples_rejected();
            }
            crate::routing::OwdSampleOutcome::Ignored => {}
        }
        // Peer RX wire-loss feeds adaptive FEC only — not CC / routing.loss_ewma.
        let st = self.fec_send_by_dest.entry(from).or_default();
        st.rx_loss_ewma = (loss_permille.min(1000) as f64) / 1000.0;
        self.refresh_fec_qd_cache(from);
        if vip_rtt_updated {
            self.publish_cc_sample_for_endpoint(from);
        }
        match pending.kind {
            PendingPingKind::User { reply } => {
                let _ = reply.send(rtt.max(1));
            }
            PendingPingKind::Heal { vip, endpoint } => {
                self.handle_heal_success(vip, endpoint, rtt.max(1));
            }
            PendingPingKind::Probe => {}
        }
    }

    fn build_signed_or_plain_reuse(
        &mut self,
        crypto_key: Option<Arc<AeadKey>>,
        tag: &[u8; 4],
        body: &[u8],
    ) -> Bytes {
        if is_signaling_tag(*tag) {
            return self.frame_with_tag_reuse(tag, body);
        }
        if let Some(key) = crypto_key.as_ref() {
            if let Some(sealed) = self.seal_control_body(key.as_ref(), tag, body) {
                return self.frame_with_tag_reuse(PKT_CTSIG, &sealed);
            }
            return Bytes::new();
        }
        self.frame_with_tag_reuse(tag, body)
    }

    fn seal_control_body(&mut self, key: &AeadKey, tag: &[u8; 4], body: &[u8]) -> Option<Bytes> {
        let counter = Self::next_ctrl_send_counter(&self.ctrl_send_ctr)?;
        let aead = self.control_plane_cipher(key)?;
        self.encrypt_scratch.clear();
        self.encrypt_scratch.extend_from_slice(tag);
        self.encrypt_scratch.extend_from_slice(body);
        let plain = self.encrypt_scratch.split();
        aead.seal_into(counter, &plain, &mut self.encrypt_scratch)
            .ok()?;
        Some(self.encrypt_scratch.split().freeze())
    }

    fn encrypt_framed_packet_reuse(
        &mut self,
        sender_vip_u32: u32,
        dest_vip_u32: u32,
        payload: &[u8],
    ) -> Result<Bytes> {
        let counter = self
            .next_data_send_counter(dest_vip_u32)
            .ok_or_else(|| anyhow!("counter exhausted"))?;
        let aead = self
            .data_plane_cipher(sender_vip_u32, dest_vip_u32)
            .ok_or_else(|| anyhow!("missing data-plane key"))?;
        let mut aad = [0u8; 8];
        aad[..4].copy_from_slice(&sender_vip_u32.to_be_bytes());
        aad[4..].copy_from_slice(&dest_vip_u32.to_be_bytes());
        aead.encrypt_framed_packet_into(counter, &aad, payload, &mut self.encrypt_scratch)?;
        Ok(self.encrypt_scratch.split().freeze())
    }

    async fn send_menc(&mut self, dest: SocketAddr, payload: &[u8]) -> Result<()> {
        if !self.has_crypto() {
            let pkt = frame_compact(CompactPacketType::Data, payload);
            if self.rawperf_mode {
                if !self.data_udp_fits_path(dest, pkt.len()) {
                    self.note_pmtud_tx_oversize(dest);
                    return Ok(());
                }
                match self.socket.try_send_to(&pkt, dest) {
                    Ok(_) => return Ok(()),
                    Err(e) => {
                        self.metrics.inc_rawperf_send_errors();
                        return Err(e.into());
                    }
                }
            }
            self.fec_send(dest, pkt);
            return Ok(());
        }
        let dest_vip_u32 = match self.endpoint_to_vip_u32(dest) {
            Some(v) => v,
            None => {
                self.metrics.inc_unauth_drop_crypto_gate();
                return Err(anyhow!("missing destination vip"));
            }
        };
        if self.state.my_vip_u32 == 0 {
            self.metrics.inc_unauth_drop_crypto_gate();
            return Err(anyhow!("missing local vip"));
        };
        let pkt = self.encrypt_framed_packet_reuse(self.state.my_vip_u32, dest_vip_u32, payload)?;
        if self.rawperf_mode {
            if !self.data_udp_fits_path(dest, pkt.len()) {
                self.note_pmtud_tx_oversize(dest);
                return Ok(());
            }
            match self.socket.try_send_to(&pkt, dest) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    self.metrics.inc_rawperf_send_errors();
                    return Err(e.into());
                }
            }
        }
        self.fec_send(dest, pkt);
        Ok(())
    }

    async fn send_menc_forward(&mut self, dest: SocketAddr, payload: &[u8]) -> Result<()> {
        if !self.has_crypto() {
            let pkt = frame_compact(CompactPacketType::Data, payload);
            if self.rawperf_mode {
                if !self.data_udp_fits_path(dest, pkt.len()) {
                    self.note_pmtud_tx_oversize(dest);
                    return Ok(());
                }
                match self.socket.try_send_to(&pkt, dest) {
                    Ok(_) => return Ok(()),
                    Err(e) => {
                        self.metrics.inc_rawperf_send_errors();
                        return Err(e.into());
                    }
                }
            }
            self.enqueue_normal_packet(pkt, dest);
            return Ok(());
        }
        let dest_vip_u32 = match self.endpoint_to_vip_u32(dest) {
            Some(v) => v,
            None => {
                self.metrics.inc_unauth_drop_crypto_gate();
                return Err(anyhow!("missing destination vip"));
            }
        };
        if self.state.my_vip_u32 == 0 {
            self.metrics.inc_unauth_drop_crypto_gate();
            return Err(anyhow!("missing local vip"));
        }
        let pkt = self.encrypt_framed_packet_reuse(self.state.my_vip_u32, dest_vip_u32, payload)?;
        if self.rawperf_mode {
            if !self.data_udp_fits_path(dest, pkt.len()) {
                self.note_pmtud_tx_oversize(dest);
                return Ok(());
            }
            match self.socket.try_send_to(&pkt, dest) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    self.metrics.inc_rawperf_send_errors();
                    return Err(e.into());
                }
            }
        }
        self.enqueue_normal_packet(pkt, dest);
        Ok(())
    }

    fn refresh_fec_qd_cache(&mut self, ep: SocketAddr) {
        let qd = {
            let rt = self.routing.read();
            rt.ep_to_vip
                .get(&ep)
                .and_then(|vip| rt.table.get(vip))
                .map(|e| {
                    crate::routing::effective_queuing_delay_ms(
                        e,
                        rt.congestion.owd_prefer_after_samples,
                    )
                })
                .unwrap_or(-1.0)
        };
        let st = self.fec_send_by_dest.entry(ep).or_default();
        st.queuing_delay_ms_cached = Some(qd);
    }

    fn invalidate_fec_qd_cache(&mut self, ep: SocketAddr) {
        if let Some(st) = self.fec_send_by_dest.get_mut(&ep) {
            st.queuing_delay_ms_cached = None;
        }
    }

    fn publish_cc_sample_for_endpoint(&mut self, ep: SocketAddr) {
        let (qd, loss) = {
            let rt = self.routing.read();
            rt.ep_to_vip
                .get(&ep)
                .and_then(|vip| rt.table.get(vip))
                .map(|e| {
                    (
                        crate::routing::effective_queuing_delay_ms(
                            e,
                            rt.congestion.owd_prefer_after_samples,
                        ),
                        e.loss_ewma,
                    )
                })
                .unwrap_or((-1.0, 0.0))
        };
        self.pacing.on_cc_sample(ep, qd, loss);
    }

    fn fec_effective_shard_payload_size(&self) -> Option<usize> {
        effective_shard_payload_size(self.fec_shard_payload_size, self.pmtud.min_mtu())
    }

    /// Flush in-flight FEC groups when the path-MTU-derived shard ceiling changes.
    fn sync_fec_shard_ceiling_to_path_mtu(&mut self) {
        let effective = self.fec_effective_shard_payload_size();
        if self.last_fec_effective_shard == effective {
            return;
        }
        let _ = self.fec_tx.retune_barrier(self.fec_tx_tuning());
        self.drain_fec_tx_events();
        self.last_fec_effective_shard = effective;
    }

    fn teardown_fec_peer(&mut self, ep: SocketAddr) {
        self.fec_send_by_dest.remove(&ep);
        let _ = self.fec_tx.remove_peer_barrier(ep);
        self.fec_decoders.remove(&ep);
        self.probe_miss_by_ep.remove(&ep);
        self.remove_peer_endpoint(ep);
    }

    fn drain_fec_tx_events(&mut self) {
        while let Ok(ev) = self.fec_tx.event_rx.try_recv() {
            self.apply_fec_tx_event(ev);
        }
    }

    fn apply_fec_tx_event(&mut self, ev: FecTxEvent) {
        let FecTxEvent::EnqueueNormal { dest, pkts, kind } = ev;
        match kind {
            NormalOfferKind::Passthrough => {
                self.metrics
                    .inc_fec_flush_sparse_passthrough(pkts.len() as u64);
            }
            NormalOfferKind::BatchFallback => {}
            NormalOfferKind::DrainPassthrough => {
                self.metrics.inc_fec_drain_passthrough(pkts.len() as u64);
            }
        }
        for p in pkts {
            self.enqueue_normal_packet(p, dest);
        }
    }

    fn fec_flush_all_and_drain(&mut self) {
        let _ = self.fec_tx.flush_all_barrier();
        self.drain_fec_tx_events();
    }

    fn fec_send(&mut self, dest: SocketAddr, pkt: Bytes) {
        if !self.fec_enabled {
            self.enqueue_normal_packet(pkt, dest);
            return;
        }
        let now = Instant::now();
        if pkt.len() + FEC_SHARD_LEN_PREFIX > self.fec_shard_payload_size {
            self.metrics.inc_fec_oversize_bypass();
            self.enqueue_normal_packet(pkt, dest);
            return;
        }
        let Some(effective) = self.fec_effective_shard_payload_size() else {
            self.metrics.inc_fec_mtu_bypass();
            self.enqueue_normal_packet(pkt, dest);
            return;
        };
        if pkt.len() + FEC_SHARD_LEN_PREFIX > effective {
            self.metrics.inc_fec_mtu_bypass();
            self.enqueue_normal_packet(pkt, dest);
            return;
        }
        // Peer-reported wire-loss (pong) — FEC adaptive input only, not CC.
        let loss_ewma = self.fec_send_by_dest.entry(dest).or_default().rx_loss_ewma;
        let queuing_delay_ms = {
            let st = self.fec_send_by_dest.entry(dest).or_default();
            if let Some(cached) = st.queuing_delay_ms_cached {
                cached
            } else {
                let val = {
                    let rt = self.routing.read();
                    rt.ep_to_vip
                        .get(&dest)
                        .and_then(|vip| rt.table.get(vip))
                        .map(|e| {
                            crate::routing::effective_queuing_delay_ms(
                                e,
                                rt.congestion.owd_prefer_after_samples,
                            )
                        })
                        .unwrap_or(-1.0)
                };
                st.queuing_delay_ms_cached = Some(val);
                val
            }
        };
        let cg = self.advanced_tuning.congestion;
        let (ds, ps) = {
            let st = self.fec_send_by_dest.entry(dest).or_default();
            let proposed = self.fec_forced_ratio.unwrap_or_else(|| {
                adaptive_fec_ratio_hyst_tuned(
                    loss_ewma,
                    st.ratio_last,
                    self.fec_adaptive_off_below,
                    self.fec_adaptive_on_above,
                )
            });
            let (held, after_hold) = if self.fec_forced_ratio.is_some() {
                (false, proposed)
            } else {
                crate::net::fec::apply_fec_loss_classifier(
                    proposed,
                    st.ratio_last,
                    cg.loss_classifier_enabled,
                    queuing_delay_ms,
                    cg.target_queue_delay_ms,
                    cg.congestion_loss_threshold,
                )
            };
            if held {
                self.metrics.inc_fec_congestive_hold();
            } else if cg.loss_classifier_enabled {
                self.metrics.inc_fec_classifier_allow();
            }
            if cg.loss_classifier_enabled
                && crate::net::fec::fec_delay_is_congestive(
                    queuing_delay_ms,
                    cg.target_queue_delay_ms,
                    cg.congestion_loss_threshold,
                )
            {
                st.last_congestive_at = Some(now);
            }
            let (stepped, ds_ps) = if self.fec_forced_ratio.is_some() {
                (false, after_hold)
            } else {
                crate::net::fec::apply_fec_recovery_stepdown(
                    after_hold,
                    st.ratio_last,
                    cg.loss_classifier_enabled,
                    queuing_delay_ms,
                    cg.target_queue_delay_ms,
                    cg.congestion_loss_threshold,
                    st.last_congestive_at,
                    now,
                    Duration::from_millis(cg.fec_recovery_recency_ms),
                )
            };
            if stepped {
                self.metrics.inc_fec_recovery_stepdown();
            }
            let (ds, ps) = ds_ps;
            let mut applied = (ds, ps);
            if self.fec_forced_ratio.is_none() {
                if let Some(prev) = st.ratio_last {
                    if prev != (ds, ps) {
                        let off_to_on = matches!(prev, (0, 0)) && ds > 0 && ps > 0;
                        let on_to_off =
                            ds == 0 && ps == 0 && matches!(prev, (d, p) if d > 0 && p > 0);
                        let hold_window = if off_to_on || on_to_off {
                            Duration::from_millis(2_000)
                        } else {
                            Duration::from_millis(250)
                        };
                        let hold = st
                            .ratio_last_change
                            .map(|t| now.duration_since(t) < hold_window)
                            .unwrap_or(false);
                        if hold {
                            applied = prev;
                        } else {
                            st.ratio_last = Some((ds, ps));
                            st.ratio_last_change = Some(now);
                        }
                    }
                } else {
                    st.ratio_last = Some((ds, ps));
                    st.ratio_last_change = Some(now);
                }
            } else {
                st.ratio_last = Some((ds, ps));
                st.ratio_last_change = Some(now);
            }
            applied
        };
        let total = ds as usize + ps as usize;
        if ds == 0 || ps == 0 || total > self.advanced_tuning.fec.fec_max_total_shards {
            self.enqueue_normal_packet(pkt, dest);
            return;
        }
        let queue_depth = self.pacing.load_obs().peer_data_queue_len(dest);
        let queue_cap = self.pacing.load_obs().max_data_queue_packets.max(1);
        let (rtt, qd) = self.pacing_enqueue_hints(dest);
        if !self.fec_tx.try_push(
            dest,
            pkt.clone(),
            ds,
            ps,
            Some((queue_depth, queue_cap)),
            rtt,
            qd,
        ) {
            self.metrics.inc_fec_tx_cmd_channel_full();
            self.enqueue_normal_packet(pkt, dest);
        }
    }

    /// Atomically apply the full advanced-tuning block (already clamped).
    pub(crate) fn apply_advanced_tuning(&mut self, tuning: crate::advanced_tuning::AdvancedTuning) {
        let old = std::mem::replace(&mut self.advanced_tuning, tuning.clone());
        let t = self.advanced_tuning.clone();

        // Failover / congestion / routing EWMA → RoutingTable.
        {
            let mut rt = self.routing.write();
            rt.failover = t.failover;
            rt.congestion = t.congestion;
            rt.routing_ewma = t.routing_ewma;
        }

        // Timers: recreate intervals. Use interval_at(now + period, period) so the
        // first tick does not fire immediately after apply.
        let now = tokio::time::Instant::now();
        self.keepalive_interval = interval_at(
            now + Duration::from_secs(t.timers.keepalive_secs),
            Duration::from_secs(t.timers.keepalive_secs),
        );
        self.keepalive_interval
            .set_missed_tick_behavior(MissedTickBehavior::Delay);
        self.sync_interval = interval_at(
            now + Duration::from_secs(t.timers.msyn_secs),
            Duration::from_secs(t.timers.msyn_secs),
        );
        self.sync_interval
            .set_missed_tick_behavior(MissedTickBehavior::Delay);
        self.pmtud_interval = interval_at(
            now + Duration::from_millis(t.timers.pmtud_tick_ms),
            Duration::from_millis(t.timers.pmtud_tick_ms),
        );
        self.pmtud_interval
            .set_missed_tick_behavior(MissedTickBehavior::Delay);
        self.stale_evict_interval = interval_at(
            now + Duration::from_secs(t.timers.stale_tick_secs),
            Duration::from_secs(t.timers.stale_tick_secs),
        );
        self.stale_evict_interval
            .set_missed_tick_behavior(MissedTickBehavior::Delay);
        self.ping_watchdog_interval = interval_at(
            now + Duration::from_millis(t.timers.ping_watchdog_ms),
            Duration::from_millis(t.timers.ping_watchdog_ms),
        );
        self.ping_watchdog_interval
            .set_missed_tick_behavior(MissedTickBehavior::Skip);
        self.cc_probe_interval = new_cc_probe_interval(&t.congestion);

        // Reliable.
        self.reliable.apply_tuning(&t.reliable);
        if self.encrypt_scratch.capacity() < t.buffers.encrypt_scratch_bytes {
            self.encrypt_scratch
                .reserve(t.buffers.encrypt_scratch_bytes - self.encrypt_scratch.capacity());
        }
        if self.control_scratch.capacity() < t.buffers.control_scratch_bytes {
            self.control_scratch
                .reserve(t.buffers.control_scratch_bytes - self.control_scratch.capacity());
        }
        if self.plain_data_scratch.capacity() < t.buffers.plain_data_scratch_bytes {
            self.plain_data_scratch
                .reserve(t.buffers.plain_data_scratch_bytes - self.plain_data_scratch.capacity());
        }
        if self.decrypt_scratch.capacity() < t.buffers.decrypt_scratch_bytes {
            self.decrypt_scratch
                .reserve(t.buffers.decrypt_scratch_bytes - self.decrypt_scratch.capacity());
        }

        // FEC: if shard size / flush timeouts changed, flush encoders first.
        let fec_changed = old.fec.shard_payload_size != t.fec.shard_payload_size
            || old.fec.flush_ms != t.fec.flush_ms
            || old.fec.flush_aggressive_ms != t.fec.flush_aggressive_ms
            || old.buffers.fec_frame_scratch_bytes != t.buffers.fec_frame_scratch_bytes;
        self.fec_shard_payload_size = t.fec.shard_payload_size;
        self.fec_flush_standard = Duration::from_millis(t.fec.flush_ms);
        self.fec_flush_aggressive = Duration::from_millis(t.fec.flush_aggressive_ms);
        self.fec_adaptive_off_below = t.fec.adaptive_off_below;
        self.fec_adaptive_on_above = t.fec.adaptive_on_above;
        if fec_changed {
            let _ = self.fec_tx.retune_barrier(self.fec_tx_tuning());
            self.drain_fec_tx_events();
            self.last_fec_effective_shard = self.fec_effective_shard_payload_size();
        }

        // PMTUD: invalidate in-flight probes and apply new knobs.
        self.pmtud.set_raise_period(t.timers.pmtud_raise_secs);
        self.pmtud.apply_tuning(&t.pmtud);
        self.reschedule_pmtud_interval();

        let cc_cfg = t.congestion.to_background_cc_config();
        self.pacing.set_background_cc(cc_cfg);
    }

    fn data_udp_fits_path(&self, dest: SocketAddr, pkt_len: usize) -> bool {
        pkt_len <= self.pmtud.udp_payload_budget(dest)
    }

    fn note_pmtud_tx_oversize(&mut self, dest: SocketAddr) {
        self.metrics.inc_pmtud_tx_oversize_drop();
        if self.mtu_pin || self.pmtud.is_pinned() {
            return;
        }
        // Adapter suggestion is the primary cure; re-apply even when min_path_mtu
        // is unchanged (config/formula lag vs live TUN MTU).
        let enc_overhead = if self.has_crypto() {
            MENC_WIRE_OVERHEAD
        } else {
            0
        };
        let suggested = self.pmtud.suggested_adapter_mtu(enc_overhead) as u16;
        self.try_apply_adapter_mtu(suggested);
        let now = Instant::now();
        if self.pmtud.request_revalidate(dest, now) {
            self.metrics.inc_pmtud_revalidate_hints();
            self.reschedule_pmtud_interval();
        }
    }

    fn enqueue_normal_packet(&mut self, pkt: Bytes, dest: SocketAddr) {
        if !self.data_udp_fits_path(dest, pkt.len()) {
            self.note_pmtud_tx_oversize(dest);
            return;
        }
        let (vip, rtt, qd) = self.tx_path_hints(dest);
        if let Some(vip) = vip {
            self.size_loss.note_tx_offer(vip, pkt.len(), Instant::now());
        }
        if !self.pacing.try_enqueue_data(pkt, dest, rtt, qd) {
            self.metrics.inc_pacing_cmd_channel_full();
        }
    }

    async fn send_menc_direct(&mut self, dest: SocketAddr, payload: &[u8]) -> Result<()> {
        if !self.has_crypto() {
            let pkt = frame_compact(CompactPacketType::Data, payload);
            if !self.data_udp_fits_path(dest, pkt.len()) {
                self.note_pmtud_tx_oversize(dest);
                return Ok(());
            }
            self.socket.send_to(&pkt, dest).await?;
            return Ok(());
        }
        let dest_vip_u32 = match self.endpoint_to_vip_u32(dest) {
            Some(v) => v,
            None => {
                self.metrics.inc_unauth_drop_crypto_gate();
                return Err(anyhow!("missing destination vip"));
            }
        };
        if self.state.my_vip_u32 == 0 {
            self.metrics.inc_unauth_drop_crypto_gate();
            return Err(anyhow!("missing local vip"));
        }
        let pkt = self.encrypt_framed_packet_reuse(self.state.my_vip_u32, dest_vip_u32, payload)?;
        if !self.data_udp_fits_path(dest, pkt.len()) {
            self.note_pmtud_tx_oversize(dest);
            return Ok(());
        }
        self.socket.send_to(&pkt, dest).await?;
        Ok(())
    }

    async fn send_control_packet(&mut self, dest: SocketAddr, tag: &[u8; 4], body: &[u8]) -> bool {
        let needs_sign = matches!(
            *tag,
            t if t == *PKT_CLG
                || t == *PKT_LEAVE
                || t == *PKT_PRXY
                || t == *PKT_JACK
        );
        if needs_sign {
            let key = self
                .outbound_crypto_key_for(dest)
                .or_else(|| self.state.crypto_keys.shared_signing_key());
            if let Some(key) = key {
                if let Some(sealed) = self.seal_control_body(key.as_ref(), tag, body) {
                    let pkt = self.frame_with_tag_reuse(PKT_CTSIG, &sealed);
                    let ok = self.socket.send_to(&pkt, dest).await.is_ok();
                    if ok {
                        self.note_outbound_udp(dest);
                    }
                    return ok;
                }
                return false;
            }
            if self.has_crypto() {
                self.ui_err(format!(
                    "  [CRYPTO] unsigned control {:?} dropped locally (needs MCTS but no signing key)",
                    std::str::from_utf8(tag).unwrap_or("????")
                ));
                return false;
            }
        }
        let pkt = self.frame_with_tag_reuse(tag, body);
        let ok = self.socket.send_to(&pkt, dest).await.is_ok();
        if ok {
            self.note_outbound_udp(dest);
        }
        ok
    }

    async fn send_probe_pings_to(&mut self, endpoints: &[SocketAddr]) {
        if endpoints.is_empty() {
            return;
        }
        let ts = now_epoch_ms();
        let deadline = Instant::now() + Duration::from_millis(2000);
        for &ep in endpoints {
            let ping_id = self.allocate_ping_id();
            let mut payload = [0u8; 16];
            payload[..8].copy_from_slice(&ping_id.to_le_bytes());
            payload[8..].copy_from_slice(&ts.to_le_bytes());
            self.pending_pings.insert(
                ping_id,
                PendingPing {
                    dest: ep,
                    allow_ip_match: false,
                    deadline,
                    sent_at_ms: ts,
                    kind: PendingPingKind::Probe,
                },
            );
            if !self
                .send_compact_to(ep, CompactPacketType::Ping, &payload)
                .await
            {
                self.pending_pings.remove(&ping_id);
            }
        }
    }

    async fn send_cc_probes(&mut self) {
        if self.advanced_tuning.congestion.probe_interval_ms == 0 {
            return;
        }
        self.cc_probe_scratch.clear();
        {
            let rt = self.routing.read();
            rt.push_endpoints_excluding_stale(&mut self.cc_probe_scratch);
        }
        let n = self.cc_probe_scratch.len();
        if n == 0 {
            return;
        }
        let take_n = n.min(self.advanced_tuning.engine_limits.max_cc_probes_per_tick);
        let start = self.cc_probe_cursor % n;
        let mut batch = Vec::with_capacity(take_n);
        for i in 0..take_n {
            batch.push(self.cc_probe_scratch[(start + i) % n]);
        }
        self.cc_probe_cursor = (start + take_n) % n;
        self.send_probe_pings_to(&batch).await;
    }

    async fn send_ping_all(&mut self) {
        self.cc_probe_scratch.clear();
        {
            let rt = self.routing.read();
            rt.push_endpoints_excluding_stale(&mut self.cc_probe_scratch);
        }
        // Clone into a short-lived slice owner: send_probe_pings_to needs &[SocketAddr]
        // while we hold &mut self. Scratch is only for listing; batch is small.
        let endpoints = self.cc_probe_scratch.clone();
        self.send_probe_pings_to(&endpoints).await;
    }

    fn direct_retry_tick(&mut self) {
        let keepalive_body = self.state.my_vip.as_bytes().to_vec();
        let targets = {
            let rt = self.routing.read();
            let filtered: Vec<SocketAddr> = rt
                .snapshot_for_retry()
                .into_iter()
                .filter(|r| {
                    matches!(
                        r.state,
                        RouteState::Candidate | RouteState::Degraded | RouteState::Stale
                    )
                })
                .map(|r| r.endpoint)
                .collect();
            let n = filtered.len();
            let take_n = n.min(self.advanced_tuning.engine_limits.max_direct_retry_per_tick);
            let start = if n > 0 {
                self.direct_retry_cursor % n
            } else {
                0
            };
            let mut targets = Vec::with_capacity(take_n);
            for i in 0..take_n {
                targets.push(filtered[(start + i) % n]);
            }
            if n > 0 {
                self.direct_retry_cursor = (start + take_n) % n;
            }
            targets
        };
        for ep in targets {
            self.enqueue_ctrl_raced(ep, PKT_HPCH, &keepalive_body);
        }
        if self.state.feature_flags.multipath_bandwidth_prober {
            let secondary_eps: Vec<SocketAddr> = {
                let rt = self.routing.read();
                rt.table
                    .values()
                    .filter_map(|entry| entry.path_set.as_ref())
                    .flat_map(|ps| {
                        ps.paths
                            .iter()
                            .enumerate()
                            .filter_map(|(idx, p)| {
                                p.as_ref()
                                    .filter(|_| idx != ps.active_idx)
                                    .map(|p| p.endpoint)
                            })
                            .collect::<Vec<_>>()
                    })
                    .take(
                        self.advanced_tuning
                            .engine_limits
                            .max_secondary_retry_per_tick,
                    )
                    .collect()
            };
            for ep in secondary_eps {
                let pkt = build_signed_or_plain_static(
                    self.outbound_crypto_key_for(ep),
                    &self.ctrl_send_ctr,
                    PKT_KPAL,
                    &keepalive_body,
                );
                self.pacing.enqueue_control(pkt, ep);
            }
        }
    }

    fn reschedule_pmtud_interval(&mut self) {
        let tick_ms = self.advanced_tuning.timers.pmtud_tick_ms.max(10);
        let raise_secs = self.advanced_tuning.timers.pmtud_raise_secs.max(1);
        let now_tok = tokio::time::Instant::now();
        let now = Instant::now();
        let period = if self.pmtud.needs_fast_tick() {
            Duration::from_millis(tick_ms)
        } else {
            let deadline = self.pmtud.next_deadline(now);
            let wait = deadline.saturating_duration_since(now);
            wait.max(Duration::from_millis(tick_ms))
                .min(Duration::from_secs(raise_secs))
        };
        self.pmtud_interval = interval_at(now_tok + period, period);
        self.pmtud_interval
            .set_missed_tick_behavior(MissedTickBehavior::Delay);
    }

    async fn drive_pmtud_tick(&mut self) {
        let now = Instant::now();
        let cong = &self.advanced_tuning.congestion;
        let mut early_wake = crate::pmtud::PmtudEventCounts::default();
        let mut inputs: Vec<PeerTickInput> = Vec::new();
        {
            let rt = self.routing.read();
            let mut peers = Vec::new();
            rt.push_endpoints_excluding_stale(&mut peers);
            inputs.reserve(peers.len());
            for &ep in &peers {
                let (rtt_ms, qd_ms, vip_u32) = match rt.ep_to_vip.get(&ep).and_then(|vip| {
                    let entry = rt.table.get(vip)?;
                    let vip_u32 = vip.parse::<Ipv4Addr>().ok().map(u32::from);
                    Some((
                        entry.smoothed_rtt_ms,
                        crate::routing::effective_queuing_delay_ms(
                            entry,
                            rt.congestion.owd_prefer_after_samples,
                        ),
                        vip_u32,
                    ))
                }) {
                    Some((rtt, qd, vip)) => (rtt, qd, vip),
                    None => (-1.0, -1.0, None),
                };
                let health = match vip_u32 {
                    Some(vip) => self.size_loss.health(vip, now),
                    None => SizeHealth::default(),
                };
                let qd_ok = qd_ms >= 0.0
                    && cong.rtt_base_tracking
                    && !fec_delay_is_congestive(
                        qd_ms,
                        cong.target_queue_delay_ms,
                        cong.congestion_loss_threshold,
                    );
                if health.large_collapsed && qd_ok && self.pmtud.request_early_wake(ep, now) {
                    early_wake.early_wake_events = early_wake.early_wake_events.saturating_add(1);
                }
                inputs.push(PeerTickInput {
                    addr: ep,
                    health,
                    rtt_ms,
                });
            }
        }
        self.metrics.add_pmtud_events(early_wake);

        let old_min = self.pmtud.min_mtu();
        let (intents, events) = self.pmtud.on_tick(now, &inputs);
        self.metrics.add_pmtud_events(events);
        for intent in intents {
            let payload_len = intent.size.saturating_sub(44);
            let mut body = Vec::with_capacity(10 + payload_len);
            body.extend_from_slice(&(intent.size as u16).to_be_bytes());
            body.extend_from_slice(&intent.search_gen.to_be_bytes());
            body.extend_from_slice(&intent.probe_id.to_be_bytes());
            body.resize(10 + payload_len, 0xAB);
            let frame = frame_with_tag(PKT_PMTU, &body);
            match self.socket.send_to(&frame, intent.peer).await {
                Ok(_) => {
                    self.metrics.inc_pmtud_probes_sent();
                }
                Err(e) if is_udp_message_too_long(&e) => {
                    self.metrics.inc_pmtud_probes_sent();
                    let ev =
                        self.pmtud
                            .on_send_hard_fail(intent.peer, intent.probe_id, Instant::now());
                    self.metrics.add_pmtud_events(ev);
                }
                Err(_) => {
                    // Transient send errors: wait for probe timeout / confirm path.
                }
            }
        }
        if self.pmtud.min_mtu() != old_min {
            if !self.mtu_pin && !self.pmtud.is_pinned() {
                let enc_overhead = if self.has_crypto() {
                    MENC_WIRE_OVERHEAD
                } else {
                    0
                };
                let suggested = self.pmtud.suggested_adapter_mtu(enc_overhead) as u16;
                self.try_apply_adapter_mtu(suggested);
                self.sync_fec_shard_ceiling_to_path_mtu();
            }
        }
        self.reschedule_pmtud_interval();
    }

    async fn broadcast_claim_gossip(&mut self) {
        if self.state.my_vip.is_empty() || self.state.my_node_id.is_empty() {
            return;
        }
        let own = ClaimRecord {
            node_id: self.state.my_node_id.clone(),
            vip: self.state.my_vip.clone(),
            vip_epoch: self.state.vip_epoch,
            ep_hints: vec![],
        };
        let now = Instant::now();
        // Enrich empty ep_hints from the live routing table so third-party claims
        // remain punchable after gossip.
        {
            let rt = self.routing.read();
            for claim in self.claim_map.values_mut() {
                if claim.ep_hints.is_empty() {
                    if let Some(entry) = rt.table.get(&claim.vip) {
                        if matches!(
                            entry.state,
                            RouteState::Active | RouteState::Candidate | RouteState::Degraded
                        ) {
                            claim.ep_hints.push(entry.endpoint.to_string());
                        }
                    }
                }
            }
        }
        let digest = build_gossip_digest_rotated(
            &own,
            &self.claim_map,
            &self.leave_tombs,
            now,
            CLAIM_GOSSIP_DIGEST_MAX,
            self.claim_gossip_digest_cursor,
        );
        self.claim_gossip_digest_cursor = self.claim_gossip_digest_cursor.saturating_add(1);

        let mut leave_tombs =
            select_leave_tombs_for_gossip(&self.leave_tombs, now, CLAIM_GOSSIP_LEAVE_TOMBS_MAX);
        let mut claims_json: Vec<serde_json::Value> = digest
            .iter()
            .map(|c| {
                serde_json::json!({
                    "node_id": c.node_id,
                    "vip": c.vip,
                    "vip_epoch": c.vip_epoch,
                    "ep_hints": c.ep_hints,
                })
            })
            .collect();
        let max = self.advanced_tuning.engine_limits.msyn_body_max;
        let mut leaves_json: Vec<serde_json::Value> = leave_tombs
            .iter()
            .map(|t| {
                serde_json::json!({
                    "node_id": t.node_id,
                    "vip": t.vip,
                    "vip_epoch": t.vip_epoch,
                })
            })
            .collect();
        let mut body_bytes = serde_json::json!({
            "proto_ver": WIRE_PROTOCOL_VERSION,
            "from": self.state.my_node_id,
            "ts_ms": now_epoch_ms(),
            "claims": claims_json,
            "leaves": leaves_json,
        })
        .to_string()
        .into_bytes();
        // Trim tombs first, then claims (keep own claim at index 0).
        while body_bytes.len() > max && !leave_tombs.is_empty() {
            leave_tombs.pop();
            leaves_json = leave_tombs
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "node_id": t.node_id,
                        "vip": t.vip,
                        "vip_epoch": t.vip_epoch,
                    })
                })
                .collect();
            body_bytes = serde_json::json!({
                "proto_ver": WIRE_PROTOCOL_VERSION,
                "from": self.state.my_node_id,
                "ts_ms": now_epoch_ms(),
                "claims": claims_json,
                "leaves": leaves_json,
            })
            .to_string()
            .into_bytes();
        }
        while body_bytes.len() > max && claims_json.len() > 1 {
            claims_json.pop();
            body_bytes = serde_json::json!({
                "proto_ver": WIRE_PROTOCOL_VERSION,
                "from": self.state.my_node_id,
                "ts_ms": now_epoch_ms(),
                "claims": claims_json,
                "leaves": leaves_json,
            })
            .to_string()
            .into_bytes();
        }
        if body_bytes.len() > max {
            return;
        }
        let active_eps: Vec<SocketAddr> = {
            let rt = self.routing.read();
            rt.table
                .values()
                .filter(|e| e.state == RouteState::Active)
                .map(|e| e.endpoint)
                .collect()
        };
        let targets = rotate_endpoints(&active_eps, self.claim_gossip_fanout_cursor, 8);
        self.claim_gossip_fanout_cursor = self.claim_gossip_fanout_cursor.saturating_add(1);
        for ep in targets {
            let _ = self.send_control_packet(ep, PKT_CLG, &body_bytes).await;
        }
    }

    async fn flush_pending_claim_gossip(&mut self) {
        if !self.pending_claim_gossip {
            return;
        }
        self.pending_claim_gossip = false;
        self.broadcast_claim_gossip().await;
    }

    async fn handle_claim_gossip_body(&mut self, body: &[u8], from: SocketAddr) {
        if body.len() > self.advanced_tuning.engine_limits.msyn_body_max {
            return;
        }
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
            return;
        };
        let now = Instant::now();
        if let Some(leaves_arr) = v.get("leaves").and_then(|x| x.as_array()) {
            for item in leaves_arr {
                let node_id = item.get("node_id").and_then(|x| x.as_str()).unwrap_or("");
                let vip = item.get("vip").and_then(|x| x.as_str()).unwrap_or("");
                let vip_epoch = item.get("vip_epoch").and_then(|x| x.as_u64()).unwrap_or(0);
                if node_id.is_empty() || !self.accept_wire_claim_vip(vip) {
                    continue;
                }
                install_leave_tombstone(
                    &mut self.leave_tombs,
                    node_id,
                    vip,
                    vip_epoch,
                    now,
                    LEAVE_TOMBSTONE_TTL,
                );
            }
        }
        let Some(claims_arr) = v.get("claims").and_then(|x| x.as_array()) else {
            return;
        };
        let claims_arr_len = claims_arr.len();
        let gossip_from_node = v.get("from").and_then(|x| x.as_str()).unwrap_or("");
        let mut should_gossip = false;
        let mut pending_routes: Vec<(
            String,
            String,
            u64,
            crate::net::claim_gossip::MergeOutcome,
            Vec<String>,
        )> = Vec::new();
        for item in claims_arr {
            let node_id = item.get("node_id").and_then(|x| x.as_str()).unwrap_or("");
            let vip = item.get("vip").and_then(|x| x.as_str()).unwrap_or("");
            let vip_epoch = item.get("vip_epoch").and_then(|x| x.as_u64()).unwrap_or(0);
            let ep_hints: Vec<String> = item
                .get("ep_hints")
                .and_then(|x| x.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            if node_id.is_empty() || !self.accept_wire_claim_vip(vip) {
                continue;
            }
            if node_id == self.state.my_node_id {
                continue;
            }
            let incoming = ClaimRecord {
                node_id: node_id.to_string(),
                vip: vip.to_string(),
                vip_epoch,
                ep_hints: ep_hints.clone(),
            };
            let outcome = merge_claim(
                &mut self.claim_map,
                incoming,
                &self.leave_tombs,
                &mut self.fight_suppress,
                now,
            );
            match outcome {
                crate::net::claim_gossip::MergeOutcome::Rejected
                | crate::net::claim_gossip::MergeOutcome::BlockedByTombstone
                | crate::net::claim_gossip::MergeOutcome::BlockedByFight => {
                    continue;
                }
                crate::net::claim_gossip::MergeOutcome::IgnoredStale
                | crate::net::claim_gossip::MergeOutcome::Accepted => {
                    pending_routes.push((
                        node_id.to_string(),
                        vip.to_string(),
                        vip_epoch,
                        outcome,
                        ep_hints,
                    ));
                }
            }
        }
        if self.apply_claim_settle_and_local_fight(None) {
            should_gossip = true;
        }
        for (node_id, vip, vip_epoch, outcome, ep_hints) in pending_routes {
            let may_route = claim_still_live(&self.claim_map, &node_id, &vip, vip_epoch)
                && matches!(
                    outcome,
                    crate::net::claim_gossip::MergeOutcome::Accepted
                        | crate::net::claim_gossip::MergeOutcome::IgnoredStale
                );
            if !may_route || vip == self.state.my_vip {
                if matches!(outcome, crate::net::claim_gossip::MergeOutcome::Accepted) {
                    should_gossip = true;
                }
                continue;
            }
            let ep = if !gossip_from_node.is_empty() && node_id == gossip_from_node {
                Some(from)
            } else {
                ep_hints.iter().find_map(|h| h.parse::<SocketAddr>().ok())
            }
            .or_else(|| {
                if gossip_from_node.is_empty() && claims_arr_len == 1 {
                    Some(from)
                } else {
                    None
                }
            });
            if let Some(ep) = ep {
                self.update_route(&vip, ep, Some(&node_id));
                self.notify_roster_upsert(&vip, ep, Some(&node_id));
                if matches!(outcome, crate::net::claim_gossip::MergeOutcome::Accepted) {
                    should_gossip = true;
                }
            } else if matches!(outcome, crate::net::claim_gossip::MergeOutcome::Accepted) {
                should_gossip = true;
            }
        }
        if should_gossip || self.pending_claim_gossip {
            self.pending_claim_gossip = false;
            self.broadcast_claim_gossip().await;
        }
    }

    async fn start_ice_checks(&mut self, mut candidates: Vec<IceCandidate>, src_node: String) {
        if candidates.is_empty() {
            return;
        }
        candidates.sort_by_key(|c| match c.kind.as_str() {
            "srflx" => 0,
            "upnp" => 1,
            "host" => 2,
            _ => 3,
        });
        let mut targets: Vec<SocketAddr> = Vec::with_capacity(candidates.len());
        for cand in &candidates {
            if let Ok(addr) = format!("{}:{}", cand.ip, cand.port).parse::<SocketAddr>() {
                targets.push(addr);
            }
        }
        if targets.is_empty() {
            return;
        }
        let socket = self.socket.clone();
        let state_view = self.state_view.clone();
        if let Some(stop) = self.ice_check_stops.remove(&src_node) {
            stop.store(true, Ordering::Release);
        }
        let stop = Arc::new(AtomicBool::new(false));
        self.ice_check_stops.insert(src_node, stop.clone());

        tokio::spawn(async move {
            const MAX_PER_TICK: usize = 8;
            let phases: [(Duration, usize); 3] = [
                (Duration::from_millis(30), 50),
                (Duration::from_millis(100), 20),
                (Duration::from_millis(500), 6),
            ];
            let mut next_idx = 0usize;
            for (delay, ticks) in phases {
                for _ in 0..ticks {
                    if stop.load(Ordering::Acquire) {
                        return;
                    }
                    let snap = state_view.read().clone();
                    let take = MAX_PER_TICK.min(targets.len());
                    let pkt = build_signed_or_plain_static(
                        snap.crypto_key.clone(),
                        &snap.ctrl_send_ctr,
                        PKT_HPCH,
                        snap.my_vip.as_bytes(),
                    );
                    for k in 0..take {
                        if stop.load(Ordering::Acquire) {
                            return;
                        }
                        let idx = (next_idx + k) % targets.len();
                        let _ = socket.send_to(&pkt, targets[idx]).await;
                    }
                    next_idx = (next_idx + take) % targets.len().max(1);
                    tokio::task::yield_now().await;
                    tokio::time::sleep(delay).await;
                }
            }
        });
    }

    fn try_apply_adapter_mtu(&mut self, mtu: u16) {
        if !(MIN_ADAPTER_PAYLOAD_MTU as u16..=1500).contains(&mtu) {
            return;
        }
        if mtu == self.state.last_applied_adapter_mtu && self.state.last_applied_adapter_mtu != 0 {
            return;
        }
        let prev = self.state.last_applied_adapter_mtu;
        let now = Instant::now();
        let delta_bytes = (mtu as i32 - prev as i32).unsigned_abs();
        let allow_netsh = prev == 0
            || delta_bytes >= 32
            || self
                .last_pmtud_netsh_at
                .map(|t| now.duration_since(t) >= Duration::from_secs(30))
                .unwrap_or(true);
        if !allow_netsh {
            return;
        }
        let Some(name) = self.state.adapter_name.clone() else {
            self.state.last_applied_adapter_mtu = 0;
            return;
        };
        if !is_safe_interface_alias(&name) {
            return;
        }
        self.last_pmtud_netsh_at = Some(now);
        self.state.last_applied_adapter_mtu = mtu;

        let adapter_name = name;
        tokio::task::spawn_blocking(move || {
            #[cfg(windows)]
            {
                let _ = std::process::Command::new("netsh")
                    .args([
                        "interface",
                        "ipv4",
                        "set",
                        "subinterface",
                        &adapter_name,
                        &format!("mtu={}", mtu),
                        "store=persistent",
                    ])
                    .creation_flags(0x08000000)
                    .output();
            }
            #[cfg(not(windows))]
            {
                let _ = (adapter_name, mtu);
            }
        });
    }

    /// Apply or clear MTU pin from `mtu_pin` + `configured_adapter_mtu`.
    fn apply_mtu_pin_policy(&mut self) {
        if self.mtu_pin {
            let enc_overhead = if self.has_crypto() {
                MENC_WIRE_OVERHEAD
            } else {
                0
            };
            let path = PathMtuDiscovery::path_mtu_from_adapter(
                self.configured_adapter_mtu as usize,
                enc_overhead,
            );
            self.pmtud.set_pinned(Some(path));
            let adapter = self.configured_adapter_mtu.clamp(576, 1500);
            // Bypass netsh rate-limit so pin takes effect immediately.
            self.state.last_applied_adapter_mtu = 0;
            self.last_pmtud_netsh_at = None;
            self.try_apply_adapter_mtu(adapter);
            self.sync_fec_shard_ceiling_to_path_mtu();
            self.reschedule_pmtud_interval();
        } else {
            self.pmtud.set_pinned(None);
            self.sync_fec_shard_ceiling_to_path_mtu();
            self.reschedule_pmtud_interval();
        }
    }

    fn unit_network_key(&self) -> Option<Key> {
        self.state
            .crypto_keys
            .shared_signing_key()
            .map(|k| k.as_key())
    }

    fn accept_wire_claim_vip(&self, vip: &str) -> bool {
        crate::net::claim::accept_wire_claim_vip(self.unit_network_key().as_ref(), vip)
    }

    fn apply_remote_claim(
        &mut self,
        remote_node_id: &str,
        remote_vip: &str,
        remote_epoch: u64,
        from: SocketAddr,
    ) {
        if remote_node_id.is_empty() || !self.accept_wire_claim_vip(remote_vip) {
            return;
        }
        let incoming = ClaimRecord {
            node_id: remote_node_id.to_string(),
            vip: remote_vip.to_string(),
            vip_epoch: remote_epoch,
            ep_hints: vec![from.to_string()],
        };
        let now = Instant::now();
        let outcome = merge_claim(
            &mut self.claim_map,
            incoming,
            &self.leave_tombs,
            &mut self.fight_suppress,
            now,
        );
        match outcome {
            crate::net::claim_gossip::MergeOutcome::Rejected
            | crate::net::claim_gossip::MergeOutcome::BlockedByTombstone
            | crate::net::claim_gossip::MergeOutcome::BlockedByFight => {
                return;
            }
            crate::net::claim_gossip::MergeOutcome::IgnoredStale
            | crate::net::claim_gossip::MergeOutcome::Accepted => {}
        }
        let _ = self.apply_claim_settle_and_local_fight(Some(remote_node_id));
        let may_route = claim_still_live(&self.claim_map, remote_node_id, remote_vip, remote_epoch)
            && matches!(
                outcome,
                crate::net::claim_gossip::MergeOutcome::Accepted
                    | crate::net::claim_gossip::MergeOutcome::IgnoredStale
            );
        if may_route && remote_vip != self.state.my_vip {
            self.update_route(remote_vip, from, Some(remote_node_id));
            self.notify_roster_upsert(remote_vip, from, Some(remote_node_id));
        }
    }

    /// Settle duplicate VIPs and optionally reroll local identity on a fight.
    /// Returns true when local VIP changed (caller should gossip).
    fn apply_claim_settle_and_local_fight(&mut self, fight_peer: Option<&str>) -> bool {
        let pre_claims: HashMap<String, ClaimRecord> = self.claim_map.clone();
        let losers = settle_duplicate_vips(&mut self.claim_map);
        let mut changed = false;
        let now = Instant::now();
        for loser in losers {
            if loser == self.state.my_node_id {
                if self
                    .try_local_vip_reroll(fight_peer.unwrap_or("peer"), &self.state.my_vip.clone())
                {
                    changed = true;
                } else {
                    // Reroll deferred/exhausted — keep a self claim so the map stays consistent.
                    self.claim_map.insert(
                        self.state.my_node_id.clone(),
                        ClaimRecord {
                            node_id: self.state.my_node_id.clone(),
                            vip: self.state.my_vip.clone(),
                            vip_epoch: self.state.vip_epoch,
                            ep_hints: vec![],
                        },
                    );
                }
            } else if let Some(pre) = pre_claims.get(&loser) {
                remove_claim(&mut self.claim_map, &loser);
                let removed = {
                    let mut rt = self.routing.write();
                    match rt.table.get(&pre.vip) {
                        None => None,
                        Some(entry) => {
                            let node_ok = entry.node_id.is_empty()
                                || entry.node_id.as_ref() == loser.as_str();
                            if !node_ok {
                                None
                            } else {
                                let ep = entry.endpoint;
                                rt.remove(&pre.vip);
                                Some(ep)
                            }
                        }
                    }
                };
                if removed.is_some() {
                    self.on_peer_route_removed(&pre.vip, Some(&loser));
                    self.stop_peer_reconnect_for_vip(&pre.vip);
                }
                let _ = install_fight_suppress(
                    &mut self.fight_suppress,
                    &loser,
                    &pre.vip,
                    pre.vip_epoch,
                    now,
                    FIGHT_SUPPRESS_TTL,
                );
                // Claim map changed — push digest so peers see the settled view sooner.
                changed = true;
            }
        }
        // Cross-node fight may remain even when settle did not remove local yet.
        let contested = self.state.my_vip.clone();
        let fighters: Vec<(String, String)> = self
            .claim_map
            .values()
            .filter(|c| c.node_id != self.state.my_node_id)
            .filter(|c| {
                should_reroll_for_vip_fight(
                    &self.state.my_node_id,
                    &self.state.my_vip,
                    &c.node_id,
                    &c.vip,
                )
            })
            .map(|c| (c.node_id.clone(), c.vip.clone()))
            .collect();
        for (peer_nid, peer_vip) in fighters {
            let _ = peer_vip;
            if self.try_local_vip_reroll(&peer_nid, &contested) {
                changed = true;
                break;
            }
        }
        if changed {
            self.pending_claim_gossip = true;
        }
        changed
    }

    fn occupied_vips_for_reroll(&self, contested: &str) -> HashSet<String> {
        let mut set: HashSet<String> = self.claim_map.values().map(|c| c.vip.clone()).collect();
        {
            let rt = self.routing.read();
            set.extend(rt.table.keys().cloned());
        }
        set.insert(self.state.my_vip.clone());
        if !contested.is_empty() {
            set.insert(contested.to_string());
        }
        set
    }

    /// Attempt local VIP reroll after losing a fight. On exhaustion, schedule retry.
    fn try_local_vip_reroll(&mut self, peer_node_id: &str, contested_vip: &str) -> bool {
        let occupied = self.occupied_vips_for_reroll(contested_vip);
        let base = self
            .unit_network_key()
            .map(|k| floatunit_subnet_base_vip(&k))
            .unwrap_or_else(|| self.state.my_vip.clone());
        match crate::net::claim::pick_free_vip(&base, |c| occupied.contains(c)) {
            Some(new_vip) => {
                let old = self.state.my_vip.clone();
                if self.apply_local_vip_change(new_vip.clone()) {
                    self.vip_reroll_retry_after = None;
                    self.ui_out(term_style::fmt_join_line(format_args!(
                        " claim node={} vip={} epoch={}",
                        self.state.my_node_id, new_vip, self.state.vip_epoch
                    )));
                    self.ui_out(term_style::fmt_join_line(format_args!(
                        " lost VIP fight with {}; was {}",
                        peer_node_id, old
                    )));
                    true
                } else {
                    false
                }
            }
            None => {
                self.ui_err(term_style::fmt_join_line_stderr(format_args!(
                    " VIP pool exhausted; cannot reroll after fight with {peer_node_id}"
                )));
                self.vip_reroll_retry_after = Some(Instant::now() + VIP_REROLL_RETRY_INTERVAL);
                false
            }
        }
    }

    fn apply_local_vip_change(&mut self, new_vip: String) -> bool {
        if new_vip.is_empty() || new_vip == self.state.my_vip {
            return false;
        }
        if !self.accept_wire_claim_vip(&new_vip) {
            return false;
        }
        let old = self.state.my_vip.clone();
        self.state.vip_epoch = self.state.vip_epoch.saturating_add(1);
        self.state.my_vip = new_vip.clone();
        self.state.my_vip_u32 = new_vip.parse::<Ipv4Addr>().map(u32::from).unwrap_or(0);
        self.state_view.write().my_vip = new_vip.clone();
        self.claim_map.insert(
            self.state.my_node_id.clone(),
            ClaimRecord {
                node_id: self.state.my_node_id.clone(),
                vip: new_vip.clone(),
                vip_epoch: self.state.vip_epoch,
                ep_hints: vec![],
            },
        );
        let old_ep = {
            let mut rt = self.routing.write();
            let ep = rt.table.get(&old).map(|e| e.endpoint);
            rt.remove(&old);
            ep
        };
        if let Some(ep) = old_ep {
            self.invalidate_fec_qd_cache(ep);
            self.teardown_fec_peer(ep);
        }
        self.stop_peer_reconnect_for_vip(&old);
        self.pending_claim_gossip = true;
        if let Some(handler) = &self.identity_changed_handler {
            handler(old, new_vip, self.state.vip_epoch);
        }
        true
    }

    fn retry_vip_fight_if_due(&mut self) {
        let Some(after) = self.vip_reroll_retry_after else {
            return;
        };
        if Instant::now() < after {
            return;
        }
        self.vip_reroll_retry_after = None;
        let _ = self.apply_claim_settle_and_local_fight(None);
    }

    async fn send_claim_presence_tick(&mut self) {
        if self.state.my_vip.is_empty() || self.state.my_node_id.is_empty() {
            return;
        }
        self.retry_vip_fight_if_due();
        self.flush_pending_claim_gossip().await;
        // Skip while actively joining — fanout already sends MPJN claims.
        if self.state.join_tx.is_some() || self.decentralized.is_joiner() {
            return;
        }
        let body = json!({
            "proto_ver": WIRE_PROTOCOL_VERSION,
            "node_id": self.state.my_node_id,
            "vip": self.state.my_vip,
            "vip_epoch": self.state.vip_epoch,
            "ts_ms": now_epoch_ms(),
            "candidates": self.state.candidates,
        })
        .to_string();
        let body_bytes = body.into_bytes();
        let targets: Vec<SocketAddr> = {
            let rt = self.routing.read();
            rt.table
                .values()
                .filter(|e| e.state == RouteState::Active)
                .map(|e| e.endpoint)
                .take(8)
                .collect()
        };
        for ep in targets {
            self.send_ctrl_signed_to(ep, PKT_JOIN, &body_bytes).await;
        }
    }

    fn mark_msmd_seen(&mut self, event_id: &str) -> bool {
        const MAX_MSMD_CACHE: usize = 4_096;
        let now = tokio::time::Instant::now();
        if self.msmd_seen.contains(event_id) {
            return false;
        }
        while let Some((ts, _)) = self.msmd_timeline.front() {
            if now.duration_since(*ts) < Duration::from_secs(120) {
                break;
            }
            if let Some((_, id)) = self.msmd_timeline.pop_front() {
                self.msmd_seen.remove(id.as_ref());
            }
        }
        while self.msmd_seen.len() >= MAX_MSMD_CACHE {
            if let Some((_, id)) = self.msmd_timeline.pop_front() {
                self.msmd_seen.remove(id.as_ref());
            } else {
                break;
            }
        }
        let shared: Arc<str> = Arc::from(event_id);
        self.msmd_timeline.push_back((now, Arc::clone(&shared)));
        self.msmd_seen.insert(shared);
        true
    }

    fn cleanup_reliable_seen(&mut self) {
        prune_reliable_seen_cache(
            &mut self.reliable_seen_timeline,
            &mut self.reliable_seen,
            tokio::time::Instant::now(),
        );
        if self.reliable_seen_timeline.len() >= 16_000 {
            let should_warn = self
                .last_reliable_seen_warn
                .is_none_or(|t| Instant::now().duration_since(t) >= Duration::from_secs(30));
            if should_warn {
                self.last_reliable_seen_warn = Some(Instant::now());
                self.ui_err(format!(
                    "  [WARN] reliable_seen near cap: {} entries",
                    self.reliable_seen_timeline.len()
                ));
            }
        }
    }

    fn handle_stun_datagram(&mut self, buf: &[u8]) -> bool {
        if self.pending_stun_queries.is_empty() {
            return false;
        }
        if !looks_like_stun(buf) {
            return false;
        }
        let mut matched = false;
        let mut completed: Vec<(u64, stun::PublicEndpoint)> = Vec::new();
        for (query_id, query) in self.pending_stun_queries.iter_mut() {
            if query.txns.is_empty() {
                if query.early_stun.len() < 32 {
                    query.early_stun.push(Bytes::copy_from_slice(buf));
                    matched = true;
                }
                continue;
            }
            let Some(ep) = stun::parse_stun_response(buf, &query.txns) else {
                continue;
            };
            matched = true;
            let key = format!("{}:{}", ep.ip, ep.port);
            let c = query.votes.entry(key).or_insert(0);
            *c += 1;
            if *c >= 2 {
                completed.push((*query_id, ep));
            }
            break;
        }
        for (query_id, ep) in completed {
            self.active_stun_query_ids.remove(&query_id);
            self.cached_stun_endpoint = Some((Instant::now(), ep.clone()));
            if let Some(done) = self.pending_stun_queries.remove(&query_id) {
                let _ = done.reply.send(Some(ep));
            }
        }
        matched
    }

    fn poll_stun_query(&mut self) {
        if self.pending_stun_queries.is_empty() {
            return;
        }
        let now = Instant::now();
        let expired_ids: Vec<u64> = self
            .pending_stun_queries
            .iter()
            .filter(|(_, query)| now >= query.deadline)
            .map(|(query_id, _)| *query_id)
            .collect();
        for query_id in expired_ids {
            self.active_stun_query_ids.remove(&query_id);
            if let Some(done) = self.pending_stun_queries.remove(&query_id) {
                let result = done
                    .votes
                    .iter()
                    .max_by_key(|(_, c)| *c)
                    .and_then(|(best, _)| {
                        let (ip, port) = best.split_once(':')?;
                        Some(stun::PublicEndpoint {
                            ip: ip.to_string(),
                            port: port.parse().ok()?,
                        })
                    });
                if let Some(ref ep) = result {
                    self.cached_stun_endpoint = Some((Instant::now(), ep.clone()));
                }
                let _ = done.reply.send(result);
            }
        }
    }

    fn handle_stun_resolve_result(&mut self, resolved: ResolvedStunQuery) {
        if !self.active_stun_query_ids.contains(&resolved.query_id) {
            return;
        }
        let query_id = resolved.query_id;
        if resolved.txns.is_empty() {
            self.stun_keepalive_addr = None;
            self.active_stun_query_ids.remove(&query_id);
            if let Some(p) = self.pending_stun_queries.remove(&query_id) {
                let _ = p.reply.send(None);
            }
            return;
        }
        self.stun_keepalive_addr = resolved.chosen_stun_addr;
        let Some(p) = self.pending_stun_queries.get_mut(&query_id) else {
            self.active_stun_query_ids.remove(&query_id);
            return;
        };
        p.txns = resolved.txns;
        p.deadline = Instant::now() + resolved.timeout;
        let early = std::mem::take(&mut p.early_stun);
        let mut resolved_ep: Option<stun::PublicEndpoint> = None;
        for pkt in early {
            let Some(ep) = stun::parse_stun_response(pkt.as_ref(), &p.txns) else {
                continue;
            };
            let key = format!("{}:{}", ep.ip, ep.port);
            let c = p.votes.entry(key).or_insert(0);
            *c += 1;
            if *c >= 2 {
                resolved_ep = Some(ep);
                break;
            }
        }
        if let Some(ep) = resolved_ep {
            self.active_stun_query_ids.remove(&query_id);
            self.cached_stun_endpoint = Some((Instant::now(), ep.clone()));
            if let Some(done) = self.pending_stun_queries.remove(&query_id) {
                let _ = done.reply.send(Some(ep));
            }
        }
    }

    async fn send_stun_keepalive(&self) {
        let Some(stun_addr) = self.stun_keepalive_addr else {
            return;
        };
        let (req, _) = stun::build_binding_request();
        let _ = self.socket.send_to(&req, stun_addr).await;
    }

    fn expire_pending_pings(&mut self) -> Vec<String> {
        let now = Instant::now();
        let expired: Vec<u64> = self
            .pending_pings
            .iter()
            .filter(|(_, p)| p.deadline <= now)
            .map(|(k, _)| *k)
            .collect();
        let threshold = self.advanced_tuning.engine_limits.probe_miss_fail_threshold;
        let mut fail_eps: HashSet<SocketAddr> = HashSet::new();
        for k in expired {
            if let Some(p) = self.pending_pings.remove(&k) {
                match p.kind {
                    PendingPingKind::User { reply } => {
                        let _ = reply.send(-1);
                    }
                    PendingPingKind::Heal { vip, .. } => {
                        let has_remaining = self.pending_pings.values().any(|x| {
                            matches!(&x.kind, PendingPingKind::Heal { vip: other, .. } if other == &vip)
                        });
                        if !has_remaining {
                            self.state.pending_heal_vips.remove(&vip);
                            self.heal_cooldown_until.insert(
                                vip,
                                Instant::now()
                                    + Duration::from_millis(
                                        self.advanced_tuning.engine_limits.heal_cooldown_ms,
                                    ),
                            );
                        }
                    }
                    PendingPingKind::Probe => {
                        if record_probe_miss(&mut self.probe_miss_by_ep, p.dest, threshold) {
                            fail_eps.insert(p.dest);
                        }
                    }
                }
            }
        }
        let mut heal_vips = Vec::new();
        if fail_eps.is_empty() {
            return heal_vips;
        }
        let predictive = self.state.feature_flags.predictive_heal;
        for dest in fail_eps {
            let fail = self.routing.write().note_fail(dest, None);
            self.refresh_fec_qd_cache(dest);
            if predictive {
                if let (Some(vip), true) = (fail.vip, fail.needs_heal) {
                    heal_vips.push(vip);
                }
            }
        }
        heal_vips
    }

    fn try_stop_ice_checks_for_join_peer(&mut self, from: SocketAddr, body: &[u8]) {
        let Ok(vip) = std::str::from_utf8(body).map(str::trim) else {
            return;
        };
        if vip.parse::<Ipv4Addr>().is_err() {
            return;
        }
        let node_id = {
            let rt = self.routing.read();
            let Some(entry) = rt.table.get(vip) else {
                return;
            };
            if entry.endpoint != from {
                return;
            }
            if entry.node_id.is_empty() {
                return;
            }
            entry.node_id.to_string()
        };
        if let Some(stop) = self.ice_check_stops.remove(node_id.as_str()) {
            stop.store(true, Ordering::Release);
        }
    }

    fn learn_route_from_hole_punch_body(
        &mut self,
        body: &[u8],
        from: SocketAddr,
        _is_ack: bool,
        authenticated: bool,
    ) {
        self.touch_routing_endpoint(from);
        let Ok(vip) = std::str::from_utf8(body).map(str::trim) else {
            return;
        };
        let Ok(vip_ip) = vip.parse::<Ipv4Addr>() else {
            return;
        };
        if !self.accept_wire_claim_vip(vip) {
            return;
        }
        if let Ok(my_vip) = self.state.my_vip.parse::<Ipv4Addr>() {
            let prefix = self.state.subnet_prefix;
            if (8..=30).contains(&prefix) && !same_subnet(my_vip, vip_ip, prefix) {
                return;
            }
        }

        let allow_hijack = {
            let rt = self.routing.read();
            if let Some(existing) = rt.table.get(vip) {
                if existing.endpoint == from {
                    true
                } else {
                    let stale_or_degraded =
                        matches!(existing.state, RouteState::Stale | RouteState::Degraded);
                    if stale_or_degraded {
                        true
                    } else if authenticated {
                        true
                    } else if !self.has_crypto() {
                        false
                    } else {
                        false
                    }
                }
            } else {
                true
            }
        };
        if allow_hijack {
            self.update_route(vip, from, None);
        } else {
            self.metrics.inc_route_hijack_reject();
        }
    }

    fn apply_route_endpoint_change_side_effects(
        &mut self,
        vip: &str,
        ep: SocketAddr,
        old_ep: Option<SocketAddr>,
    ) {
        if let Some(prev) = old_ep {
            self.reliable.migrate_dest(prev, ep);
            if prev != ep {
                self.invalidate_fec_qd_cache(prev);
                self.invalidate_fec_qd_cache(ep);
                self.state.crypto_keys.unbind_peer(prev);
                self.fec_send_by_dest.remove(&prev);
                let _ = self.fec_tx.remove_peer_barrier(prev);
                self.fec_decoders.remove(&prev);
                self.remove_peer_endpoint(prev);
            }
        } else {
            self.invalidate_fec_qd_cache(ep);
        }
        self.remember_endpoint(vip, ep);
    }

    fn update_route(&mut self, vip: &str, ep: SocketAddr, node_id: Option<&str>) {
        if self.state.my_vip.is_empty() || vip == self.state.my_vip {
            return;
        }
        let old_ep = {
            let mut rt = self.routing.write();
            let prev = rt.table.get(vip).map(|e| e.endpoint);
            rt.update(vip, ep, node_id);
            prev
        };
        self.sync_dest_relay_path_stamp(vip);
        self.apply_route_endpoint_change_side_effects(vip, ep, old_ep);
        self.refresh_fec_qd_cache(ep);
    }

    fn prune_orphan_per_peer_keys(&mut self) {
        let rt = self.routing.read();
        self.state.crypto_keys.prune_per_peer_orphans(&*rt);
    }

    #[cfg(test)]
    fn test_pacing_join_thread_present(&self) -> bool {
        self.pacing_thread.join.is_some()
    }

    #[cfg(test)]
    async fn test_expect_pacing_tick(&mut self) {
        tokio::time::timeout(Duration::from_millis(200), self.pacing.event_rx.recv())
            .await
            .expect("pacing tick receive timed out")
            .expect("pacing tick channel closed");
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UniqueIpMatch {
    Bound(String),
    Unbound,
}

fn unique_ip_peer_vip(rt: &RoutingTable, my_vip: &str, announce_ip: IpAddr) -> UniqueIpMatch {
    let mut matches = Vec::new();
    for (vip, entry) in rt.table.iter() {
        if vip.as_str() == my_vip {
            continue;
        }
        if entry.endpoint.ip() == announce_ip {
            matches.push(vip.clone());
        }
    }
    if matches.len() == 1 {
        UniqueIpMatch::Bound(matches.into_iter().next().unwrap())
    } else {
        UniqueIpMatch::Unbound
    }
}

fn peer_route_needs_work(rt: &RoutingTable, vip: &str, candidate: SocketAddr) -> bool {
    let Some(entry) = rt.table.get(vip) else {
        return true;
    };
    match entry.state {
        RouteState::Candidate | RouteState::Degraded | RouteState::Stale => true,
        RouteState::Active => entry.endpoint != candidate,
    }
}

fn peer_announce_needs_work_unbound(rt: &RoutingTable, addr: SocketAddr) -> bool {
    let Some(vip) = rt.ep_to_vip.get(&addr) else {
        return true;
    };
    let Some(entry) = rt.table.get(vip.as_str()) else {
        return true;
    };
    !(matches!(entry.state, RouteState::Active) && entry.endpoint == addr)
}

fn build_signed_or_plain_static(
    crypto_key: Option<Arc<AeadKey>>,
    ctrl_send_ctr: &AtomicU64,
    tag: &[u8; 4],
    body: &[u8],
) -> Bytes {
    if is_signaling_tag(*tag) {
        return frame_with_tag(tag, body);
    }
    if let Some(key) = crypto_key.as_ref() {
        let Some(counter) = P2PEngine::next_ctrl_send_counter(ctrl_send_ctr) else {
            return Bytes::new();
        };
        let Ok(aead) = derive_control_plane_material(&key.as_key()) else {
            return Bytes::new();
        };
        let mut plain = Vec::with_capacity(4 + body.len());
        plain.extend_from_slice(tag);
        plain.extend_from_slice(body);
        let mut sealed = BytesMut::new();
        if aead.seal_into(counter, &plain, &mut sealed).is_err() {
            return Bytes::new();
        }
        return frame_with_tag(PKT_CTSIG, &sealed);
    }
    frame_with_tag(tag, body)
}

pub(crate) fn build_signed_or_plain_static_for_punch(
    crypto_key: Option<Arc<AeadKey>>,
    ctrl_send_ctr: &AtomicU64,
    tag: &[u8; 4],
    body: &[u8],
) -> Bytes {
    build_signed_or_plain_static(crypto_key, ctrl_send_ctr, tag, body)
}

fn allow_unauth_control_tag_with_crypto(tag: [u8; 4]) -> bool {
    matches!(
        tag,
        t if t == *PKT_MERR
            || t == *PKT_PMTU
            || t == *PKT_PMAR
            || t == *PKT_BREK
            || t == *PKT_RDYS
            || t == *PKT_MSTR
            || t == *PKT_PARA_HELLO
            || t == *PKT_PARA_REPLY
            || t == *PKT_PARA_OK
            || t == *PKT_PARA_PUNCH_ACK
            || t == *PKT_KPAL
            || t == *PKT_HPCH
            || t == *PKT_HACK
            || t == *PKT_MCTL
    )
}

fn is_signaling_tag(tag: [u8; 4]) -> bool {
    matches!(
        tag,
        t if t == *PKT_MERR
            || t == *PKT_PARA_HELLO
            || t == *PKT_PARA_REPLY
            || t == *PKT_PARA_OK
            || t == *PKT_PARA_PUNCH_ACK
            || t == *PKT_KPAL
            || t == *PKT_HPCH
            || t == *PKT_HACK
    )
}

fn src_key(ip: IpAddr) -> u64 {
    match ip {
        IpAddr::V4(v4) => u32::from(v4) as u64,
        IpAddr::V6(v6) => {
            let oct = v6.octets();
            let hi = u64::from_be_bytes([
                oct[0], oct[1], oct[2], oct[3], oct[4], oct[5], oct[6], oct[7],
            ]);
            let lo = u64::from_be_bytes([
                oct[8], oct[9], oct[10], oct[11], oct[12], oct[13], oct[14], oct[15],
            ]);
            hi ^ lo
        }
    }
}

fn src_addr_key(from: SocketAddr) -> u64 {
    src_key(from.ip()).rotate_left(17) ^ (from.port() as u64)
}

fn join_rate_key(from: SocketAddr) -> u64 {
    src_addr_key(from)
}

fn join_ip_key(from: SocketAddr) -> u64 {
    src_key(from.ip())
}

fn decode_ping_payload(body: &[u8]) -> Option<(u64, u64)> {
    if body.len() < 16 {
        return None;
    }
    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&body[..8]);
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&body[8..16]);
    Some((u64::from_le_bytes(id_bytes), u64::from_le_bytes(ts_bytes)))
}

fn encode_pong_payload(
    ping_id: u64,
    sender_ts: u64,
    fwd_owd_sample_ms: i32,
    loss_permille: u32,
) -> [u8; 24] {
    let mut out = [0u8; 24];
    out[..8].copy_from_slice(&ping_id.to_le_bytes());
    out[8..16].copy_from_slice(&sender_ts.to_le_bytes());
    out[16..20].copy_from_slice(&fwd_owd_sample_ms.to_le_bytes());
    out[20..24].copy_from_slice(&loss_permille.min(1000).to_le_bytes());
    out
}

fn decode_pong_payload(body: &[u8]) -> Option<(u64, u64, i32, u32)> {
    if body.len() != 24 {
        return None;
    }
    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&body[..8]);
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&body[8..16]);
    let mut owd_bytes = [0u8; 4];
    owd_bytes.copy_from_slice(&body[16..20]);
    let mut loss_bytes = [0u8; 4];
    loss_bytes.copy_from_slice(&body[20..24]);
    Some((
        u64::from_le_bytes(id_bytes),
        u64::from_le_bytes(ts_bytes),
        i32::from_le_bytes(owd_bytes),
        u32::from_le_bytes(loss_bytes).min(1000),
    ))
}

fn prune_reliable_seen_cache(
    timeline: &mut VecDeque<(tokio::time::Instant, ReliableDedupKey, u32)>,
    seen: &mut HashSet<(ReliableDedupKey, u32)>,
    now: tokio::time::Instant,
) {
    while let Some((ts, dk, seq)) = timeline.front().cloned() {
        if now.duration_since(ts) < Duration::from_secs(60) {
            break;
        }
        timeline.pop_front();
        seen.remove(&(dk, seq));
    }
    while timeline.len() > 16_384 {
        if let Some((_, dk, seq)) = timeline.pop_front() {
            seen.remove(&(dk, seq));
        }
    }
}

fn looks_like_stun(buf: &[u8]) -> bool {
    if buf.len() < 20 {
        return false;
    }
    let msg_type_ok = (buf[0] & 0b1100_0000) == 0;
    let magic_ok = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) == 0x2112A442;
    msg_type_ok && magic_ok
}

fn is_safe_interface_alias(s: &str) -> bool {
    if s.is_empty() || s.len() > 128 {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.' | '(' | ')'))
}

fn is_valid_sync_endpoint(ep: SocketAddr) -> bool {
    if ep.ip().is_unspecified() || ep.ip().is_multicast() || ep.ip().is_loopback() {
        return false;
    }
    if let IpAddr::V4(v4) = ep.ip() {
        let oct = v4.octets();
        if oct[0] == 169 && oct[1] == 254 {
            return false;
        }
    }
    true
}

fn jack_mpja_body_valid(v: &serde_json::Value, from: SocketAddr, unit_key: Option<&Key>) -> bool {
    let vip = v.get("vip").and_then(|x| x.as_str()).unwrap_or("");
    let node_id = v.get("node_id").and_then(|x| x.as_str()).unwrap_or("");
    let prefix = v
        .get("prefix")
        .and_then(|x| x.as_u64())
        .map(|n| n as u8)
        .unwrap_or(24)
        .clamp(8, 30);
    crate::net::claim::accept_wire_claim_vip(unit_key, vip)
        && !node_id.is_empty()
        && node_id.len() <= 64
        && (8..=30).contains(&prefix)
        && is_valid_sync_endpoint(from)
}

fn is_recent_para_ts(ts_ms: u64) -> bool {
    let now = now_epoch_ms();
    let delta = if now >= ts_ms {
        now - ts_ms
    } else {
        ts_ms - now
    };
    delta <= 90_000
}

fn is_broadcast_or_multicast(pkt: &[u8]) -> bool {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return false;
    }
    let dst = [pkt[16], pkt[17], pkt[18], pkt[19]];
    dst == [255, 255, 255, 255] || (224..=239).contains(&dst[0])
}

#[cfg(test)]
fn first_free_vip_u32_in_subnet(
    my_vip_u32: u32,
    subnet_prefix: u8,
    is_occupied: impl Fn(u32) -> bool,
) -> Option<u32> {
    if my_vip_u32 == 0 {
        return None;
    }
    let prefix = subnet_prefix.clamp(8, 30);
    let mask = u32::MAX << (32 - u32::from(prefix));
    let host_mask = !mask;
    let base = my_vip_u32 & mask;
    let max_host = host_mask.saturating_sub(1);

    let host_lo = if max_host <= 2 { 1 } else { 2 };
    for host in host_lo..=max_host {
        let candidate_u32 = base | host;
        if candidate_u32 == my_vip_u32 {
            continue;
        }
        if !is_occupied(candidate_u32) {
            return Some(candidate_u32);
        }
    }
    None
}

fn is_udp_message_too_long(err: &std::io::Error) -> bool {
    // Windows WSAEMSGSIZE=10040; Linux/macOS EMSGSIZE typically 90.
    matches!(err.raw_os_error(), Some(10040) | Some(90))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MintCrypto;
    use crate::net::PaceClockApply;
    use std::net::SocketAddrV4;

    #[test]
    fn join_ack_deliver_false_when_receiver_dropped() {
        let (tx, rx) = oneshot::channel::<Option<JoinAck>>();
        drop(rx);
        let mut join_tx = Some(tx);
        let ack = JoinAck {
            peer_vip: "10.0.0.1".into(),
            peer_node_id: "peer-a".into(),
            subnet_prefix: 24,
            peer_endpoint: "127.0.0.1:1".parse().unwrap(),
            local_vip: "10.0.0.2".into(),
            vip_epoch: 0,
        };
        assert!(!try_deliver_join_ack(&mut join_tx, ack));
        assert!(join_tx.is_none());
    }

    #[test]
    fn join_ack_deliver_true_when_receiver_alive() {
        let (tx, rx) = oneshot::channel::<Option<JoinAck>>();
        let mut join_tx = Some(tx);
        let ack = JoinAck {
            peer_vip: "10.0.0.1".into(),
            peer_node_id: "peer-a".into(),
            subnet_prefix: 24,
            peer_endpoint: "127.0.0.1:1".parse().unwrap(),
            local_vip: "10.0.0.2".into(),
            vip_epoch: 0,
        };
        assert!(try_deliver_join_ack(&mut join_tx, ack));
        assert!(rx.blocking_recv().unwrap().is_some());
    }

    #[test]
    fn decode_ping_payload_requires_id_and_ts() {
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&42u64.to_le_bytes());
        buf[8..].copy_from_slice(&1000u64.to_le_bytes());
        assert_eq!(decode_ping_payload(&buf), Some((42, 1000)));

        assert_eq!(decode_ping_payload(&777u64.to_le_bytes()), None);
    }

    #[test]
    fn pong_payload_round_trip_and_short_rejected() {
        let enc = encode_pong_payload(7, 1_700_000_000_000, -42, 50);
        assert_eq!(
            decode_pong_payload(&enc),
            Some((7, 1_700_000_000_000, -42, 50))
        );
        assert_eq!(decode_pong_payload(&enc[..16]), None);
        assert_eq!(decode_pong_payload(&enc[..19]), None);
        assert_eq!(decode_pong_payload(&enc[..20]), None);
        assert_eq!(decode_pong_payload(&enc[..23]), None);
        let mut long = enc.to_vec();
        long.push(0);
        assert_eq!(decode_pong_payload(&long), None);
    }

    #[test]
    fn pong_owd_field_matches_recv_minus_sender_ts() {
        let sender_ts = 1_000u64;
        let recv_ts = 1_035u64;
        let owd = (recv_ts as i64).saturating_sub(sender_ts as i64) as i32;
        let enc = encode_pong_payload(99, sender_ts, owd, 0);
        let decoded = decode_pong_payload(&enc).unwrap();
        assert_eq!(decoded.2, 35);
        assert_eq!(decoded.3, 0);
    }

    #[test]
    fn pong_loss_permille_clamped_at_encode() {
        let enc = encode_pong_payload(1, 2, 3, 5000);
        assert_eq!(decode_pong_payload(&enc), Some((1, 2, 3, 1000)));
    }

    #[test]
    fn adaptive_fec_ratio_turns_on_above_rx_loss() {
        // Mirrors fec_send consumption: rx_loss_ewma past on_above engages ladder.
        let on_above = 0.05;
        let off_below = 0.025;
        assert_eq!(
            adaptive_fec_ratio_hyst_tuned(0.0, None, off_below, on_above),
            (0, 0)
        );
        assert_eq!(
            adaptive_fec_ratio_hyst_tuned(0.05, None, off_below, on_above),
            (7, 1)
        );
        assert_eq!(
            adaptive_fec_ratio_hyst_tuned(0.05, Some((0, 0)), off_below, on_above),
            (7, 1)
        );
    }

    #[test]
    fn first_free_vip_slash24_skips_network_owner_and_broadcast() {
        let my = u32::from(Ipv4Addr::new(10, 0, 0, 88));
        let got = first_free_vip_u32_in_subnet(my, 24, |_| false).unwrap();
        assert_eq!(Ipv4Addr::from(got), Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn first_free_vip_slash30_peer_when_owner_high() {
        let my = u32::from(Ipv4Addr::new(192, 168, 1, 2));
        let got = first_free_vip_u32_in_subnet(my, 30, |_| false).unwrap();
        assert_eq!(Ipv4Addr::from(got), Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn first_free_vip_respects_occupied_map() {
        let my = u32::from(Ipv4Addr::new(10, 0, 0, 5));
        let occ: HashSet<u32> = HashSet::from([
            u32::from(Ipv4Addr::new(10, 0, 0, 2)),
            u32::from(Ipv4Addr::new(10, 0, 0, 3)),
        ]);
        let got = first_free_vip_u32_in_subnet(my, 24, |u| occ.contains(&u)).unwrap();
        assert_eq!(Ipv4Addr::from(got), Ipv4Addr::new(10, 0, 0, 4));
    }

    #[test]
    fn crypto_mode_requires_auth_for_route_learning_tags() {
        assert!(allow_unauth_control_tag_with_crypto(*PKT_KPAL));
        assert!(allow_unauth_control_tag_with_crypto(*PKT_HPCH));
        assert!(allow_unauth_control_tag_with_crypto(*PKT_HACK));
        assert!(allow_unauth_control_tag_with_crypto(*PKT_MCTL));
        assert!(!allow_unauth_control_tag_with_crypto(*PKT_JOIN));
        assert!(!allow_unauth_control_tag_with_crypto(*PKT_JACK));
    }

    #[test]
    fn encode_mctl_hb_hol_one_datagram_body() {
        let body = encode_mctl(MCTL_FLAG_HB | MCTL_FLAG_HOL, Some(b"10.0.0.2")).unwrap();
        let p = parse_mctl(&body).unwrap();
        assert_eq!(p.flags, MCTL_FLAG_HB | MCTL_FLAG_HOL);
        assert!(p.signaling_ok);
    }

    #[tokio::test]
    async fn hpch_unauth_creates_route_when_crypto_enabled() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rt = Arc::new(RwLock::new(RoutingTable::new()));
        let (_tun_tx, tun_rx) = mpsc::channel(8);
        let (inject_tx, _inject_rx) = broadcast::channel(8);
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let metrics = Arc::new(EngineMetrics::new());
        let key = MintCrypto::generate_key();
        let my_vip = crate::net::claim::member_host_ipv4(&key, 2);
        let peer_vip = crate::net::claim::member_host_vip(&key, 3);
        let mut eng = P2PEngine::new(
            Arc::new(socket),
            rt.clone(),
            tun_rx,
            inject_tx,
            cmd_rx,
            my_vip,
            "n".to_string(),
            24,
            metrics,
            PaceClockApply::default(),
            500,
            Arc::new(RuntimeTrace::new()),
            8,
            crate::ui_events::UiEventBus::new(),
        );
        let _ = eng.state.crypto_keys.set_primary(key);
        eng.state_view.write().crypto_key = eng.state.crypto_keys.primary();
        let from: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        eng.learn_route_from_hole_punch_body(peer_vip.as_bytes(), from, false, false);
        assert_eq!(rt.read().lookup(&peer_vip), Some(from));
    }

    #[tokio::test]
    async fn hpch_unauth_does_not_hijack_active_peer() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rt = Arc::new(RwLock::new(RoutingTable::new()));
        let (_tun_tx, tun_rx) = mpsc::channel(8);
        let (inject_tx, _inject_rx) = broadcast::channel(8);
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let metrics = Arc::new(EngineMetrics::new());
        let mut eng = P2PEngine::new(
            Arc::new(socket),
            rt.clone(),
            tun_rx,
            inject_tx,
            cmd_rx,
            Ipv4Addr::new(10, 1, 1, 2),
            "n".to_string(),
            24,
            metrics,
            PaceClockApply::default(),
            500,
            Arc::new(RuntimeTrace::new()),
            8,
            crate::ui_events::UiEventBus::new(),
        );
        let _ = eng
            .state
            .crypto_keys
            .set_primary(MintCrypto::generate_key());
        eng.state_view.write().crypto_key = eng.state.crypto_keys.primary();
        let active_ep: SocketAddr = "127.0.0.1:41000".parse().unwrap();
        let hijack_ep: SocketAddr = "127.0.0.1:42000".parse().unwrap();
        {
            let mut w = rt.write();
            w.update("10.1.1.5", active_ep, Some("peer-a"));
            if let Some(entry) = w.table.get_mut("10.1.1.5") {
                entry.state = RouteState::Active;
            }
        }
        eng.learn_route_from_hole_punch_body(b"10.1.1.5", hijack_ep, false, false);
        assert_eq!(rt.read().lookup("10.1.1.5"), Some(active_ep));
    }

    #[test]
    fn src_addr_key_separates_cgnat_ports() {
        let a: SocketAddr = "203.0.113.7:1111".parse().unwrap();
        let b: SocketAddr = "203.0.113.7:2222".parse().unwrap();
        assert_ne!(src_addr_key(a), src_addr_key(b));
        assert_eq!(src_addr_key(a), src_addr_key(a));
    }

    #[test]
    fn prune_reliable_seen_prefers_ttl_then_capacity() {
        let now = tokio::time::Instant::now();
        let old = now - Duration::from_secs(120);
        let recent = now - Duration::from_secs(10);
        let ka = ReliableDedupKey::Addr(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)));
        let kb = ReliableDedupKey::VipU32(u32::from(Ipv4Addr::new(10, 0, 0, 2)));

        let mut timeline = VecDeque::from([(old, ka.clone(), 1), (recent, kb.clone(), 2)]);
        let mut seen = HashSet::from([(ka.clone(), 1), (kb.clone(), 2)]);
        prune_reliable_seen_cache(&mut timeline, &mut seen, now);
        assert_eq!(timeline.len(), 1);
        assert!(seen.contains(&(kb, 2)));
        assert!(!seen.contains(&(ka, 1)));
    }

    #[test]
    fn dedup_survives_nat_rebind_same_vip() {
        let now = tokio::time::Instant::now();
        let dk = ReliableDedupKey::VipU32(u32::from(Ipv4Addr::new(10, 1, 0, 5)));
        let mut timeline = VecDeque::from([(now, dk.clone(), 7)]);
        let mut seen = HashSet::from([(dk.clone(), 7)]);
        assert!(!seen.insert((dk.clone(), 7)));
        assert_eq!(seen.len(), 1);
        prune_reliable_seen_cache(&mut timeline, &mut seen, now);
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn dedup_separates_cgnat_peers_same_ip_diff_vip() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let k1 = ReliableDedupKey::VipU32(u32::from(Ipv4Addr::new(10, 0, 0, 2)));
        let k2 = ReliableDedupKey::VipU32(u32::from(Ipv4Addr::new(10, 0, 0, 3)));
        let mut seen = HashSet::new();
        assert!(seen.insert((k1.clone(), 1)));
        assert!(seen.insert((k2.clone(), 1)));
        assert_eq!(seen.len(), 2);
        let _ = ip;
    }

    #[test]
    fn dedup_separates_cgnat_same_public_ip_diff_port() {
        let a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 1111));
        let b = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 2222));
        let ka = ReliableDedupKey::Addr(a);
        let kb = ReliableDedupKey::Addr(b);
        let mut seen = HashSet::new();
        assert!(seen.insert((ka.clone(), 5)));
        assert!(seen.insert((kb.clone(), 5)));
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn crypto_pool_has_any_includes_per_peer_bindings() {
        let mut pool = CryptoPool::new();
        assert!(!pool.has_any());
        let k = MintCrypto::generate_key();
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1234));
        let ak = pool.add_key(k);
        pool.bind_peer_key(addr, ak);
        assert!(pool.has_any());
    }

    #[test]
    fn crypto_pool_shared_signing_key_falls_back_to_any_per_peer() {
        let mut pool = CryptoPool::new();
        let k = MintCrypto::generate_key();
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 2222));
        let ak = pool.add_key(k);
        pool.bind_peer_key(addr, ak);
        assert!(pool.shared_signing_key().is_some());
    }

    #[test]
    fn extras_capped_evicts_oldest_first() {
        let mut pool = CryptoPool::new();
        let _ = pool.set_primary(MintCrypto::generate_key());
        for _ in 0..12 {
            let _ = pool.add_key(MintCrypto::generate_key());
        }
        assert_eq!(pool.extras_len(), MAX_EXTRA_KEYS);
        assert!(pool.primary().is_some());
    }

    #[test]
    fn crypto_pool_shared_signing_key_falls_back_to_primary() {
        let mut pool = CryptoPool::new();
        let k = MintCrypto::generate_key();
        pool.set_primary(k);
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 99), 9));
        assert!(pool.shared_signing_key().is_some());
        assert!(pool.key_for_dest(addr).is_some());
    }

    #[test]
    fn crypto_pool_prune_per_peer_drops_orphans() {
        let mut pool = CryptoPool::new();
        let _ = pool.set_primary(MintCrypto::generate_key());
        let addr: SocketAddr = "198.51.100.10:6000".parse().unwrap();
        let k = pool.add_key(MintCrypto::generate_key());
        pool.bind_peer_key(addr, k);
        let rt = RoutingTable::new();
        pool.prune_per_peer_orphans(&rt);
        assert!(pool.key_for_peer(addr).is_none());

        let mut rt = RoutingTable::new();
        rt.update("10.0.0.2", addr, None);
        let k2 = pool.add_key(MintCrypto::generate_key());
        pool.bind_peer_key(addr, k2);
        pool.prune_per_peer_orphans(&rt);
        assert!(pool.key_for_peer(addr).is_some());
    }

    #[test]
    fn encode_mctl_hb_hol_roundtrip() {
        let vip = b"10.0.0.2";
        let body = encode_mctl(MCTL_FLAG_HB | MCTL_FLAG_HOL, Some(vip)).unwrap();
        let p = parse_mctl(&body).unwrap();
        assert!(p.signaling_ok);
        assert_eq!(p.flags, MCTL_FLAG_HB | MCTL_FLAG_HOL);
        assert_eq!(p.vip.as_deref(), Some(vip.as_slice()));
    }

    #[test]
    fn unique_ip_peer_vip_single_and_multi() {
        let mut rt = RoutingTable::new();
        let a: SocketAddr = "203.0.113.1:1000".parse().unwrap();
        let b: SocketAddr = "203.0.113.2:2000".parse().unwrap();
        let shared_a: SocketAddr = "203.0.113.9:1000".parse().unwrap();
        let shared_b: SocketAddr = "203.0.113.9:2000".parse().unwrap();
        rt.update("10.1.1.5", a, Some("p5"));
        rt.update("10.1.1.6", b, Some("p6"));
        assert_eq!(
            super::unique_ip_peer_vip(&rt, "10.1.1.2", a.ip()),
            super::UniqueIpMatch::Bound("10.1.1.5".to_string())
        );
        rt.update("10.1.1.7", shared_a, Some("p7"));
        rt.update("10.1.1.8", shared_b, Some("p8"));
        assert_eq!(
            super::unique_ip_peer_vip(&rt, "10.1.1.2", shared_a.ip()),
            super::UniqueIpMatch::Unbound
        );
    }

    #[test]
    fn peer_route_needs_work_active_wrong_endpoint() {
        let mut rt = RoutingTable::new();
        let old: SocketAddr = "203.0.113.7:1111".parse().unwrap();
        let new_ep: SocketAddr = "203.0.113.7:2222".parse().unwrap();
        rt.update("10.1.1.5", old, Some("p"));
        if let Some(e) = rt.table.get_mut("10.1.1.5") {
            e.state = RouteState::Active;
        }
        assert!(super::peer_route_needs_work(&rt, "10.1.1.5", new_ep));
        assert!(!super::peer_route_needs_work(&rt, "10.1.1.5", old));
    }

    #[tokio::test]
    async fn hpch_auth_rebinds_active_peer() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rt = Arc::new(RwLock::new(RoutingTable::new()));
        let (_tun_tx, tun_rx) = mpsc::channel(8);
        let (inject_tx, _inject_rx) = broadcast::channel(8);
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let metrics = Arc::new(EngineMetrics::new());
        let mut eng = P2PEngine::new(
            Arc::new(socket),
            rt.clone(),
            tun_rx,
            inject_tx,
            cmd_rx,
            Ipv4Addr::new(10, 1, 1, 2),
            "n".to_string(),
            24,
            metrics,
            PaceClockApply::default(),
            500,
            Arc::new(RuntimeTrace::new()),
            8,
            crate::ui_events::UiEventBus::new(),
        );
        let active_ep: SocketAddr = "127.0.0.1:41000".parse().unwrap();
        let hijack_ep: SocketAddr = "127.0.0.1:42000".parse().unwrap();
        {
            let mut w = rt.write();
            w.update("10.1.1.5", active_ep, Some("peer-a"));
            if let Some(entry) = w.table.get_mut("10.1.1.5") {
                entry.state = RouteState::Active;
            }
        }
        eng.learn_route_from_hole_punch_body(b"10.1.1.5", hijack_ep, true, true);
        assert_eq!(rt.read().lookup("10.1.1.5"), Some(hijack_ep));
    }

    #[test]
    fn claim_conflict_loser_rerolls_in_engine_state() {
        // Pure helper path used by apply_remote_claim.
        assert!(crate::net::claim::local_loses_vip_conflict("bbb", "aaa"));
        let occupied = |c: &str| c == "10.1.1.7";
        let new = crate::net::claim::pick_free_vip("10.1.1.7", occupied).unwrap();
        assert_ne!(new, "10.1.1.7");
        assert!(crate::net::claim::claim_vip_valid(&new));
    }

    #[test]
    fn jack_mpja_rejects_missing_node_id() {
        let from: SocketAddr = "198.51.100.10:5000".parse().unwrap();
        let v = json!({
            "vip": "10.0.0.5",
            "vip_epoch": 0,
            "prefix": 24
        });
        assert!(!super::jack_mpja_body_valid(&v, from, None));
    }

    #[test]
    fn jack_mpja_accepts_valid_peer_claim() {
        let from: SocketAddr = "198.51.100.10:5000".parse().unwrap();
        let v = json!({
            "vip": "10.0.0.5",
            "node_id": "member-a",
            "vip_epoch": 0,
            "prefix": 24
        });
        assert!(super::jack_mpja_body_valid(&v, from, None));
    }

    #[test]
    fn jack_mpja_rejects_out_of_unit_when_keyed() {
        let from: SocketAddr = "198.51.100.10:5000".parse().unwrap();
        let key = Key([0x55; 32]);
        let v = json!({
            "vip": "10.1.1.5",
            "node_id": "member-a",
            "vip_epoch": 0,
            "prefix": 24
        });
        assert!(!super::jack_mpja_body_valid(&v, from, Some(&key)));
        let in_unit = crate::net::claim::member_host_vip(&key, 5);
        let v2 = json!({
            "vip": in_unit,
            "node_id": "member-a",
            "vip_epoch": 0,
            "prefix": 24
        });
        assert!(super::jack_mpja_body_valid(&v2, from, Some(&key)));
    }

    #[tokio::test]
    async fn coverage_keepalive_suppresses_after_note_and_clears_on_reset() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rt = Arc::new(RwLock::new(RoutingTable::new()));
        let (_tun_tx, tun_rx) = mpsc::channel(8);
        let (inject_tx, _inject_rx) = broadcast::channel(8);
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let metrics = Arc::new(EngineMetrics::new());
        metrics.set_enabled(true);
        let mut eng = P2PEngine::new(
            Arc::new(socket),
            rt.clone(),
            tun_rx,
            inject_tx,
            cmd_rx,
            Ipv4Addr::new(10, 1, 1, 2),
            "n".to_string(),
            24,
            metrics.clone(),
            PaceClockApply::default(),
            500,
            Arc::new(RuntimeTrace::new()),
            8,
            crate::ui_events::UiEventBus::new(),
        );
        let ep: SocketAddr = "127.0.0.1:45000".parse().unwrap();
        {
            let mut w = rt.write();
            w.update("10.1.1.5", ep, Some("peer-a"));
            if let Some(entry) = w.table.get_mut("10.1.1.5") {
                entry.state = RouteState::Active;
            }
        }
        eng.send_keepalives().await;
        assert!(metrics.keepalive_sent_total.load(Ordering::Relaxed) >= 1);
        let sent_after_idle = metrics.keepalive_sent_total.load(Ordering::Relaxed);
        eng.note_outbound_udp(ep);
        eng.send_keepalives().await;
        assert!(
            metrics.keepalive_suppressed_total.load(Ordering::Relaxed) >= 1,
            "recent note must suppress keepalive"
        );
        assert_eq!(
            metrics.keepalive_sent_total.load(Ordering::Relaxed),
            sent_after_idle
        );
        eng.reset_session_state().await;
        assert!(eng.outbound_udp.last(ep).is_none());
    }

    #[tokio::test]
    async fn pacing_thread_restarts_after_session_reset() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rt = Arc::new(RwLock::new(RoutingTable::new()));
        let (_tun_tx, tun_rx) = mpsc::channel(8);
        let (inject_tx, _inject_rx) = broadcast::channel(8);
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let metrics = Arc::new(EngineMetrics::new());
        let mut eng = P2PEngine::new(
            Arc::new(socket),
            rt.clone(),
            tun_rx,
            inject_tx,
            cmd_rx,
            Ipv4Addr::new(10, 1, 1, 2),
            "n".to_string(),
            24,
            metrics,
            PaceClockApply::default(),
            500,
            Arc::new(RuntimeTrace::new()),
            8,
            crate::ui_events::UiEventBus::new(),
        );
        assert!(eng.test_pacing_join_thread_present());
        eng.stop_background_loops().await;
        assert!(!eng.test_pacing_join_thread_present());
        eng.restart_pacing_after_session_reset().await;
        assert!(eng.test_pacing_join_thread_present());
        eng.test_expect_pacing_tick().await;
    }

    #[tokio::test]
    async fn allocate_ping_id_unique_with_many_pending_user_pings() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rt = Arc::new(RwLock::new(RoutingTable::new()));
        let (_tun_tx, tun_rx) = mpsc::channel(8);
        let (inject_tx, _inject_rx) = broadcast::channel(8);
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let metrics = Arc::new(EngineMetrics::new());
        let mut eng = P2PEngine::new(
            Arc::new(socket),
            rt,
            tun_rx,
            inject_tx,
            cmd_rx,
            Ipv4Addr::new(10, 1, 1, 2),
            "n".to_string(),
            24,
            metrics,
            PaceClockApply::default(),
            500,
            Arc::new(RuntimeTrace::new()),
            8,
            crate::ui_events::UiEventBus::new(),
        );
        let dest: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut ids = HashSet::new();
        for _ in 0..32 {
            let id = eng.allocate_ping_id();
            assert!(ids.insert(id), "duplicate ping id {id}");
            let (reply, _rx) = oneshot::channel();
            eng.pending_pings.insert(
                id,
                PendingPing {
                    dest,
                    allow_ip_match: true,
                    deadline: Instant::now() + Duration::from_secs(5),
                    sent_at_ms: 0,
                    kind: PendingPingKind::User { reply },
                },
            );
        }
    }

    async fn test_engine() -> P2PEngine {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rt = Arc::new(RwLock::new(RoutingTable::new()));
        let (_tun_tx, tun_rx) = mpsc::channel(8);
        let (inject_tx, _inject_rx) = broadcast::channel(8);
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let metrics = Arc::new(EngineMetrics::new());
        P2PEngine::new(
            Arc::new(socket),
            rt,
            tun_rx,
            inject_tx,
            cmd_rx,
            Ipv4Addr::new(10, 1, 1, 2),
            "n".to_string(),
            24,
            metrics,
            PaceClockApply::default(),
            500,
            Arc::new(RuntimeTrace::new()),
            8,
            crate::ui_events::UiEventBus::new(),
        )
    }

    fn insert_expired_probe(eng: &mut P2PEngine, dest: SocketAddr) {
        let id = eng.allocate_ping_id();
        eng.pending_pings.insert(
            id,
            PendingPing {
                dest,
                allow_ip_match: false,
                deadline: Instant::now() - Duration::from_millis(1),
                sent_at_ms: 0,
                kind: PendingPingKind::Probe,
            },
        );
    }

    #[test]
    fn record_probe_miss_reports_from_threshold_onward() {
        let dest: SocketAddr = "198.51.100.1:1".parse().unwrap();
        let mut streak = HashMap::new();
        let threshold = 8u32;
        let mut should_fail = 0u32;
        for i in 1..=20 {
            if record_probe_miss(&mut streak, dest, threshold) {
                should_fail += 1;
                assert!(i >= threshold);
            }
        }
        assert_eq!(should_fail, 20 - threshold + 1);
        assert_eq!(streak.get(&dest).copied(), Some(20));
    }

    #[tokio::test]
    async fn probe_miss_under_threshold_does_not_note_fail() {
        let mut eng = test_engine().await;
        let dest: SocketAddr = "198.51.100.9:9".parse().unwrap();
        eng.routing.write().update("10.1.0.9", dest, None);
        let threshold = eng.advanced_tuning.engine_limits.probe_miss_fail_threshold;
        for _ in 0..(threshold - 1) {
            insert_expired_probe(&mut eng, dest);
        }
        let heals = eng.expire_pending_pings();
        assert!(heals.is_empty());
        assert_eq!(eng.routing.read().table["10.1.0.9"].fail_streak, 0);
        assert_eq!(
            eng.probe_miss_by_ep.get(&dest).copied(),
            Some(threshold - 1)
        );
    }

    #[tokio::test]
    async fn probe_miss_at_threshold_notes_fail_once_per_sweep() {
        let mut eng = test_engine().await;
        let dest: SocketAddr = "198.51.100.9:9".parse().unwrap();
        eng.routing.write().update("10.1.0.9", dest, None);
        let threshold = eng.advanced_tuning.engine_limits.probe_miss_fail_threshold;
        for _ in 0..threshold {
            insert_expired_probe(&mut eng, dest);
        }
        let heals = eng.expire_pending_pings();
        assert!(heals.is_empty());
        assert_eq!(
            eng.routing.read().table["10.1.0.9"].fail_streak,
            1,
            "batch of threshold misses => one note_fail"
        );

        insert_expired_probe(&mut eng, dest);
        let heals = eng.expire_pending_pings();
        assert!(heals.is_empty());
        assert_eq!(
            eng.routing.read().table["10.1.0.9"].fail_streak,
            2,
            "next sweep adds one more note_fail"
        );
    }

    #[tokio::test]
    async fn matched_pong_resets_probe_miss_streak() {
        let mut eng = test_engine().await;
        let dest: SocketAddr = "198.51.100.9:9".parse().unwrap();
        eng.routing.write().update("10.1.0.9", dest, None);
        eng.probe_miss_by_ep.insert(dest, 20);
        let ping_id = eng.allocate_ping_id();
        eng.pending_pings.insert(
            ping_id,
            PendingPing {
                dest,
                allow_ip_match: false,
                deadline: Instant::now() + Duration::from_secs(5),
                sent_at_ms: now_epoch_ms().saturating_sub(5),
                kind: PendingPingKind::Probe,
            },
        );
        let body = encode_pong_payload(ping_id, 1, 1, 0);
        eng.handle_pong_body(&body, dest).await;
        assert!(
            !eng.probe_miss_by_ep.contains_key(&dest),
            "pong must clear streak"
        );

        let threshold = eng.advanced_tuning.engine_limits.probe_miss_fail_threshold;
        for _ in 0..(threshold - 1) {
            insert_expired_probe(&mut eng, dest);
        }
        eng.expire_pending_pings();
        assert_eq!(
            eng.routing.read().table["10.1.0.9"].fail_streak,
            0,
            "misses after reset must re-accumulate from zero"
        );
        assert_eq!(
            eng.probe_miss_by_ep.get(&dest).copied(),
            Some(threshold - 1)
        );
    }
}
