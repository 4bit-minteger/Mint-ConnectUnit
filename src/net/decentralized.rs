use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use crate::nat::tracker::{
    build_announce_request, build_connect_request, build_http_announce_request_target,
    parse_announce_response, parse_connect_response, parse_tracker_endpoint, parse_tracker_url,
    peer_id_from_room_and_node, TrackerScheme, TransactionId,
};

const CONNECTION_TTL: Duration = Duration::from_secs(55);
const PENDING_TTL: Duration = Duration::from_secs(20);
const HTTP_PENDING_TTL: Duration = Duration::from_secs(20);
const MAX_FANOUT_MPJN_PER_TICK: usize = 8;
const MAX_PUNCH_TARGETS: usize = 64;
pub const MAX_EXPANDED_PUNCH_TARGETS: usize = 512;
pub const JOIN_OVERLAY_NARROW_WIDTH: usize = 64;
pub const JOIN_OVERLAY_WIDE_MIN_WIDTH: usize = 32;
pub const JOIN_OVERLAY_WIDE_MAX_WIDTH: usize = 256;
pub const JOIN_OVERLAY_NARROW_PPS: u32 = 64;
pub const JOIN_OVERLAY_WIDE_PPS: u32 = 128;
pub const JOIN_OVERLAY_RANDOM_PPS: u32 = 64;
pub const JOIN_OVERLAY_RANDOM_MAX_SECS: u64 = 10;
pub const JOIN_OVERLAY_INVITE_PRE_WIDTH: usize = 256;
const SYMMETRIC_SCAN_WIDTH: usize = 128;
const SYMMETRIC_SCAN_WIDTH_OWNER_HINT: usize = 256;
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(8);
pub const DECENTRALIZED_RESOLVE_TIMEOUT: Duration = RESOLVE_TIMEOUT;
const PORT_MIN: u16 = 1;
const PORT_MAX: u16 = u16::MAX;
const MAX_REANNOUNCE_SECS: u64 = 300;
const MAX_ACTIVE_TRACKERS: usize = 32;
const MAX_HTTP_IN_FLIGHT: usize = 4;
const DISCOVERED_TTL: Duration = Duration::from_secs(300);
const MAX_DISCOVERED: usize = 256;

struct TrackerSlot {
    url: String,
    scheme: TrackerScheme,
    host: String,
    port: u16,
    path: String,
    addrs: Vec<SocketAddr>,
    use_idx: usize,
    last_announce: Option<Instant>,
    server_interval_secs: u64,
    resolve_in_flight: bool,
    http_in_flight: bool,
    http_in_flight_since: Option<Instant>,
}

#[derive(Default)]
pub struct DecentralizedState {
    active: bool,
    generation: u64,
    room_id: [u8; 20],
    peer_id: [u8; 20],
    announce_secs: u64,
    slots: Vec<TrackerSlot>,
    is_joiner: bool,
    join_body: Option<Vec<u8>>,
    join_owner_hint: Option<SocketAddr>,
    pending: HashMap<[u8; 4], PendingOp>,
    connections: HashMap<SocketAddr, TrackerConn>,
    discovered: HashMap<SocketAddr, Instant>,
    listen_port: u16,
    had_join_announce_response: bool,
}

/// Work item for an async BEP3 HTTP announce (engine spawns the request).
#[derive(Clone, Debug)]
pub struct HttpAnnounceWork {
    pub slot_idx: usize,
    pub generation: u64,
    pub tracker_url: String,
    pub host: String,
    pub port: u16,
    pub request_target: String,
}

/// Result delivered back to the engine select loop.
#[derive(Debug)]
pub struct HttpAnnounceResult {
    pub slot_idx: usize,
    pub generation: u64,
    pub tracker_url: String,
    pub outcome: Result<(u32, Vec<SocketAddr>), String>,
}

pub struct DecentralizedTickOutput {
    pub punch_targets: Vec<SocketAddr>,
    pub join_fanout: Vec<(SocketAddr, Vec<u8>)>,
}

#[derive(Clone, Debug)]
pub struct AnnounceInfo {
    pub peers: Vec<SocketAddr>,
    pub first_announce_in_join: bool,
}

#[derive(Clone, Debug)]
pub struct TrackerDatagramEvent {
    pub tracker_url: String,
    pub announce: Option<AnnounceInfo>,
}

#[derive(Debug, Default)]
pub struct DatagramHandleResult {
    pub handled: bool,
    pub event: Option<TrackerDatagramEvent>,
}

struct PendingOp {
    kind: PendingKind,
    tracker: SocketAddr,
    created: Instant,
}

enum PendingKind {
    Connect,
    Announce,
}

struct TrackerConn {
    id: u64,
    expires: Instant,
}

impl TrackerSlot {
    fn try_new(url: String, announce_secs: u64) -> Option<Self> {
        let ep = parse_tracker_endpoint(&url)?;
        Some(Self {
            url,
            scheme: ep.scheme,
            host: ep.host,
            port: ep.port,
            path: ep.path,
            addrs: Vec::new(),
            use_idx: 0,
            last_announce: None,
            server_interval_secs: announce_secs,
            resolve_in_flight: false,
            http_in_flight: false,
            http_in_flight_since: None,
        })
    }

    fn current_addr(&self) -> Option<SocketAddr> {
        if self.addrs.is_empty() {
            return None;
        }
        let idx = self.use_idx % self.addrs.len();
        Some(self.addrs[idx])
    }

    fn rotate_addr(&mut self) {
        if !self.addrs.is_empty() {
            self.use_idx = (self.use_idx + 1) % self.addrs.len();
        }
    }

    fn announce_due(&self, announce_secs: u64) -> bool {
        let wait = self
            .server_interval_secs
            .max(announce_secs)
            .min(MAX_REANNOUNCE_SECS);
        match self.last_announce {
            None => true,
            Some(t) => t.elapsed() >= Duration::from_secs(wait),
        }
    }

    fn is_udp(&self) -> bool {
        self.scheme == TrackerScheme::Udp
    }

    fn is_http(&self) -> bool {
        // HTTPS deferred (no TLS stack yet); HTTP plaintext only.
        self.scheme == TrackerScheme::Http
    }
}

impl DecentralizedState {
    pub fn start(
        &mut self,
        room_id: [u8; 20],
        node_id: &str,
        trackers: Vec<String>,
        announce_secs: u64,
        is_joiner: bool,
        join_body: Option<Vec<u8>>,
        join_owner_hint: Option<SocketAddr>,
        listen_port: u16,
    ) {
        let announce_secs = announce_secs.max(60);
        self.generation = self.generation.wrapping_add(1);
        self.active = true;
        self.room_id = room_id;
        self.peer_id = peer_id_from_room_and_node(&room_id, node_id);
        self.announce_secs = announce_secs;
        self.slots = trackers
            .into_iter()
            .filter_map(|url| TrackerSlot::try_new(url, announce_secs))
            .take(MAX_ACTIVE_TRACKERS)
            .collect();
        self.is_joiner = is_joiner;
        self.join_body = join_body;
        self.join_owner_hint = join_owner_hint;
        self.pending.clear();
        self.connections.clear();
        self.discovered.clear();
        self.listen_port = listen_port;
        self.had_join_announce_response = false;
    }

    pub fn stop(&mut self) {
        let gen = self.generation.wrapping_add(1);
        *self = Self::default();
        self.generation = gen;
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn announce_port(&self, self_public_ep: Option<SocketAddr>) -> u16 {
        self_public_ep.map(|e| e.port()).unwrap_or(self.listen_port)
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn is_joiner(&self) -> bool {
        self.is_joiner
    }

    pub fn set_joiner_active(&mut self, active: bool) {
        self.is_joiner = active;
    }

    pub fn discovered_endpoints(&self) -> Vec<SocketAddr> {
        self.discovered.keys().copied().collect()
    }

    pub fn join_owner_hint(&self) -> Option<SocketAddr> {
        self.join_owner_hint
    }

    pub fn join_punch_base_targets(
        &mut self,
        self_public_ep: Option<SocketAddr>,
    ) -> Vec<SocketAddr> {
        self.exact_targets(self_public_ep)
    }

    pub fn take_pending_resolves(&mut self) -> Vec<(usize, String)> {
        if !self.active {
            return Vec::new();
        }
        let mut out = Vec::new();
        for (idx, slot) in self.slots.iter_mut().enumerate() {
            if !slot.is_udp() {
                continue;
            }
            if slot.addrs.is_empty() && !slot.resolve_in_flight {
                let Some((host, port)) = parse_tracker_url(&slot.url) else {
                    continue;
                };
                slot.resolve_in_flight = true;
                out.push((idx, format!("{host}:{port}")));
            }
        }
        out
    }

    /// Collect due HTTP announce jobs (marks slots in-flight). HTTPS slots are skipped.
    pub fn take_pending_http_announces(&mut self, announce_port: u16) -> Vec<HttpAnnounceWork> {
        if !self.active {
            return Vec::new();
        }
        self.sweep_expired_http_inflight();
        let mut in_flight = self.slots.iter().filter(|s| s.http_in_flight).count();
        let mut out = Vec::new();
        let room_id = self.room_id;
        let peer_id = self.peer_id;
        let announce_secs = self.announce_secs;
        let generation = self.generation;
        for (idx, slot) in self.slots.iter_mut().enumerate() {
            if in_flight >= MAX_HTTP_IN_FLIGHT {
                break;
            }
            if !slot.is_http() || slot.http_in_flight || !slot.announce_due(announce_secs) {
                continue;
            }
            let request_target = build_http_announce_request_target(
                &slot.path,
                &room_id,
                &peer_id,
                announce_port,
                50,
            );
            slot.http_in_flight = true;
            slot.http_in_flight_since = Some(Instant::now());
            in_flight += 1;
            out.push(HttpAnnounceWork {
                slot_idx: idx,
                generation,
                tracker_url: slot.url.clone(),
                host: slot.host.clone(),
                port: slot.port,
                request_target,
            });
        }
        out
    }

    pub fn apply_http_announce_result(
        &mut self,
        result: HttpAnnounceResult,
    ) -> Option<TrackerDatagramEvent> {
        if !self.active || result.generation != self.generation {
            return None;
        }
        if let Some(slot) = self.slots.get_mut(result.slot_idx) {
            slot.http_in_flight = false;
            slot.http_in_flight_since = None;
        } else {
            return None;
        }

        let (interval, peers) = match result.outcome {
            Ok(v) => v,
            Err(_) => return None,
        };

        if let Some(slot) = self.slots.get_mut(result.slot_idx) {
            slot.server_interval_secs = (interval as u64).max(60);
            slot.last_announce = Some(Instant::now());
        }
        for ep in &peers {
            self.note_discovered(*ep);
        }
        let first_announce_in_join = self.is_joiner && !self.had_join_announce_response;
        if self.is_joiner {
            self.had_join_announce_response = true;
        }
        Some(TrackerDatagramEvent {
            tracker_url: result.tracker_url,
            announce: Some(AnnounceInfo {
                peers,
                first_announce_in_join,
            }),
        })
    }

    pub fn clear_resolve_in_flight(&mut self, slot_idx: usize) {
        if let Some(slot) = self.slots.get_mut(slot_idx) {
            slot.resolve_in_flight = false;
        }
    }

    pub fn add_resolved_addrs(&mut self, slot_idx: usize, addrs: Vec<SocketAddr>) {
        let Some(slot) = self.slots.get_mut(slot_idx) else {
            return;
        };
        for a in addrs {
            if a.is_ipv4() && !slot.addrs.contains(&a) {
                slot.addrs.push(a);
            }
        }
    }

    fn slot_index_for_tracker_addr(&self, addr: SocketAddr) -> Option<usize> {
        self.slots.iter().position(|s| s.addrs.contains(&addr))
    }

    fn sweep_expired_pending(&mut self) {
        self.pending
            .retain(|_, op| op.created.elapsed() < PENDING_TTL);
    }

    fn sweep_expired_http_inflight(&mut self) {
        let now = Instant::now();
        for slot in &mut self.slots {
            if !slot.http_in_flight {
                continue;
            }
            let stale = slot
                .http_in_flight_since
                .map(|t| now.duration_since(t) >= HTTP_PENDING_TTL)
                .unwrap_or(true);
            if stale {
                slot.http_in_flight = false;
                slot.http_in_flight_since = None;
            }
        }
    }

    fn has_pending_in_flight(&self, tracker: SocketAddr, kind: PendingKind) -> bool {
        self.pending.values().any(|op| {
            op.tracker == tracker
                && matches!(
                    (&op.kind, &kind),
                    (PendingKind::Connect, PendingKind::Connect)
                        | (PendingKind::Announce, PendingKind::Announce)
                )
        })
    }

    fn note_discovered(&mut self, ep: SocketAddr) {
        self.discovered.insert(ep, Instant::now());
    }

    fn prune_discovered(&mut self) {
        let now = Instant::now();
        self.discovered
            .retain(|_, seen| now.duration_since(*seen) < DISCOVERED_TTL);
        if self.discovered.len() <= MAX_DISCOVERED {
            return;
        }
        let mut entries: Vec<(SocketAddr, Instant)> =
            self.discovered.iter().map(|(e, t)| (*e, *t)).collect();
        entries.sort_by_key(|(_, t)| *t);
        let drop_n = self.discovered.len().saturating_sub(MAX_DISCOVERED);
        for (ep, _) in entries.into_iter().take(drop_n) {
            self.discovered.remove(&ep);
        }
    }

    fn exact_targets(&mut self, self_public_ep: Option<SocketAddr>) -> Vec<SocketAddr> {
        self.prune_discovered();
        let mut entries: Vec<(SocketAddr, Instant)> =
            self.discovered.iter().map(|(e, t)| (*e, *t)).collect();
        entries.sort_by_key(|(_, t)| std::cmp::Reverse(*t));
        let mut targets: Vec<SocketAddr> = entries
            .into_iter()
            .map(|(e, _)| e)
            .filter(|ep| self_public_ep.map(|s| s != *ep).unwrap_or(true))
            .take(MAX_PUNCH_TARGETS)
            .collect();
        if let Some(hint) = self.join_owner_hint {
            if !targets.contains(&hint) {
                targets.push(hint);
            }
        }
        targets
    }

    pub fn handle_datagram(&mut self, from: SocketAddr, data: &[u8]) -> DatagramHandleResult {
        if !self.active || data.len() < 16 {
            return DatagramHandleResult::default();
        }
        let txn_bytes: [u8; 4] = match data[4..8].try_into() {
            Ok(b) => b,
            Err(_) => return DatagramHandleResult::default(),
        };
        let Some(op) = self.pending.remove(&txn_bytes) else {
            return DatagramHandleResult::default();
        };
        if from != op.tracker {
            self.pending.insert(txn_bytes, op);
            return DatagramHandleResult::default();
        }
        let tracker_url = self
            .slot_index_for_tracker_addr(op.tracker)
            .and_then(|idx| self.slots.get(idx).map(|s| s.url.clone()))
            .unwrap_or_else(|| op.tracker.to_string());
        let txn = TransactionId(txn_bytes);
        match op.kind {
            PendingKind::Connect => match parse_connect_response(data, txn) {
                Ok(cid) => {
                    self.connections.insert(
                        op.tracker,
                        TrackerConn {
                            id: cid,
                            expires: Instant::now() + CONNECTION_TTL,
                        },
                    );
                    DatagramHandleResult {
                        handled: true,
                        event: Some(TrackerDatagramEvent {
                            tracker_url,
                            announce: None,
                        }),
                    }
                }
                Err(_) => DatagramHandleResult {
                    handled: true,
                    event: None,
                },
            },
            PendingKind::Announce => {
                if let Ok((interval, peers)) = parse_announce_response(data, txn) {
                    if let Some(idx) = self.slot_index_for_tracker_addr(op.tracker) {
                        if let Some(slot) = self.slots.get_mut(idx) {
                            slot.server_interval_secs = interval.max(60) as u64;
                            slot.last_announce = Some(Instant::now());
                        }
                    }
                    for ep in &peers {
                        self.note_discovered(*ep);
                    }
                    let first_announce_in_join = self.is_joiner && !self.had_join_announce_response;
                    if self.is_joiner {
                        self.had_join_announce_response = true;
                    }
                    return DatagramHandleResult {
                        handled: true,
                        event: Some(TrackerDatagramEvent {
                            tracker_url,
                            announce: Some(AnnounceInfo {
                                peers,
                                first_announce_in_join,
                            }),
                        }),
                    };
                }
                DatagramHandleResult {
                    handled: true,
                    event: None,
                }
            }
        }
    }

    async fn tick_tracker_slot(
        &mut self,
        slot_idx: usize,
        socket: &Arc<UdpSocket>,
        announce_port: u16,
    ) {
        if !self
            .slots
            .get(slot_idx)
            .map(|s| s.is_udp())
            .unwrap_or(false)
        {
            return;
        }
        let Some(tracker_ep) = self.slots.get(slot_idx).and_then(|s| s.current_addr()) else {
            return;
        };
        if !self
            .slots
            .get(slot_idx)
            .map(|s| s.announce_due(self.announce_secs))
            .unwrap_or(false)
        {
            return;
        }

        let need_connect = match self.connections.get(&tracker_ep) {
            Some(c) => Instant::now() >= c.expires,
            None => true,
        };

        if need_connect {
            if self.has_pending_in_flight(tracker_ep, PendingKind::Connect) {
                return;
            }
            let txn = TransactionId::random();
            self.pending.insert(
                txn.0,
                PendingOp {
                    kind: PendingKind::Connect,
                    tracker: tracker_ep,
                    created: Instant::now(),
                },
            );
            let pkt = build_connect_request(txn);
            if socket.send_to(&pkt, tracker_ep).await.is_err() {
                self.pending.remove(&txn.0);
                if let Some(slot) = self.slots.get_mut(slot_idx) {
                    slot.rotate_addr();
                }
            }
            return;
        }

        let Some(conn) = self.connections.get(&tracker_ep).map(|c| c.id) else {
            return;
        };
        if self.has_pending_in_flight(tracker_ep, PendingKind::Announce) {
            return;
        }
        let txn = TransactionId::random();
        self.pending.insert(
            txn.0,
            PendingOp {
                kind: PendingKind::Announce,
                tracker: tracker_ep,
                created: Instant::now(),
            },
        );
        let pkt =
            build_announce_request(conn, txn, &self.room_id, &self.peer_id, announce_port, 50);
        if socket.send_to(&pkt, tracker_ep).await.is_err() {
            self.pending.remove(&txn.0);
            self.connections.remove(&tracker_ep);
            if let Some(slot) = self.slots.get_mut(slot_idx) {
                slot.rotate_addr();
            }
        }
    }

    pub async fn tick(
        &mut self,
        socket: &Arc<UdpSocket>,
        self_public_ep: Option<SocketAddr>,
        join_pending: bool,
    ) -> DecentralizedTickOutput {
        let mut out = DecentralizedTickOutput {
            punch_targets: Vec::new(),
            join_fanout: Vec::new(),
        };
        if !self.active {
            return out;
        }

        self.sweep_expired_pending();

        let announce_port = self_public_ep.map(|e| e.port()).unwrap_or(self.listen_port);

        let slot_count = self.slots.len();
        for slot_idx in 0..slot_count {
            self.tick_tracker_slot(slot_idx, socket, announce_port)
                .await;
        }

        let targets = self.exact_targets(self_public_ep);
        if !targets.is_empty() {
            out.punch_targets = expand_symmetric_targets(
                &targets,
                self.join_owner_hint,
                MAX_EXPANDED_PUNCH_TARGETS,
            );
        }

        if self.is_joiner && join_pending {
            if let Some(body) = self.join_body.clone() {
                let mut fan: Vec<SocketAddr> = Vec::with_capacity(MAX_FANOUT_MPJN_PER_TICK);
                if let Some(hint) = self.join_owner_hint {
                    fan.push(hint);
                }
                for ep in &targets {
                    if fan.len() >= MAX_FANOUT_MPJN_PER_TICK {
                        break;
                    }
                    if !fan.contains(ep) {
                        fan.push(*ep);
                    }
                }
                for ep in fan {
                    out.join_fanout.push((ep, body.clone()));
                }
            }
        }

        out
    }
}

fn build_symmetric_punch_targets(ip: std::net::IpAddr, port: u16, width: usize) -> Vec<SocketAddr> {
    let scan = width.max(1);
    let half = (scan / 2) as i32;
    let mut start = port as i32 - half;
    if start < PORT_MIN as i32 {
        start = PORT_MIN as i32;
    }
    let mut out = Vec::with_capacity(scan);
    for offset in 0..scan {
        let p = start + offset as i32;
        if p > PORT_MAX as i32 {
            break;
        }
        if p >= PORT_MIN as i32 {
            out.push(SocketAddr::new(ip, p as u16));
        }
    }
    out
}

fn expand_symmetric_targets(
    base_targets: &[SocketAddr],
    owner_hint: Option<SocketAddr>,
    max_total: usize,
) -> Vec<SocketAddr> {
    let mut dedup = HashSet::with_capacity(max_total.min(1024));
    let mut expanded = Vec::with_capacity(max_total.min(1024));

    for ep in base_targets {
        if dedup.insert(*ep) {
            expanded.push(*ep);
            if expanded.len() >= max_total {
                return expanded;
            }
        }
    }

    for ep in base_targets {
        let width = if Some(*ep) == owner_hint {
            SYMMETRIC_SCAN_WIDTH_OWNER_HINT
        } else {
            SYMMETRIC_SCAN_WIDTH
        };
        for cand in build_symmetric_punch_targets(ep.ip(), ep.port(), width) {
            if dedup.insert(cand) {
                expanded.push(cand);
                if expanded.len() >= max_total {
                    return expanded;
                }
            }
        }
    }
    expanded
}

pub fn join_wide_per_peer_width(
    peer_count: usize,
    max_expanded: usize,
    min_width: usize,
    max_width: usize,
) -> usize {
    let n = peer_count.max(1);
    let max_expanded = max_expanded.max(1);
    let min_width = min_width.max(1);
    let max_width = max_width.max(min_width);
    (max_expanded / n).clamp(min_width, max_width)
}

pub fn expand_intensity_symmetric(
    base_targets: &[SocketAddr],
    per_peer_width: usize,
    max_total: usize,
) -> Vec<SocketAddr> {
    let mut dedup = HashSet::with_capacity(max_total.min(1024));
    let mut expanded = Vec::with_capacity(max_total.min(1024));

    for ep in base_targets {
        if dedup.insert(*ep) {
            expanded.push(*ep);
            if expanded.len() >= max_total {
                return expanded;
            }
        }
    }

    for ep in base_targets {
        for cand in build_symmetric_punch_targets(ep.ip(), ep.port(), per_peer_width) {
            if dedup.insert(cand) {
                expanded.push(cand);
                if expanded.len() >= max_total {
                    return expanded;
                }
            }
        }
    }
    expanded
}

pub fn invite_pre_punch_targets(hint: SocketAddr, max_total: usize) -> Vec<SocketAddr> {
    expand_intensity_symmetric(&[hint], JOIN_OVERLAY_INVITE_PRE_WIDTH, max_total)
}

/// Canonical punch workflow — stage 1 direct burst to each base endpoint.
pub const CANONICAL_STAGE1_PACKETS: usize = 3;
pub const CANONICAL_STAGE1_GAP_MS: u64 = 50;
pub const CANONICAL_STAGE1_OBSERVE_MS: u64 = 500;
pub const CANONICAL_STAGE2_OBSERVE_SECS: u64 = 1;

/// Stage 2 symmetric scan (single pass, global budget from punch tuning).
pub fn canonical_stage2_targets(
    base_targets: &[SocketAddr],
    punch: &crate::advanced_tuning::HolePunchTuning,
) -> Vec<SocketAddr> {
    if base_targets.is_empty() {
        return Vec::new();
    }
    let width = join_wide_per_peer_width(
        base_targets.len(),
        punch.punch_max_expanded_targets,
        punch.punch_wide_min_width,
        punch.punch_wide_max_width,
    );
    expand_intensity_symmetric(base_targets, width, punch.punch_max_expanded_targets)
}

pub fn canonical_covered_after_stage2(
    base_targets: &[SocketAddr],
    stage2: &[SocketAddr],
) -> HashSet<SocketAddr> {
    let mut covered = HashSet::with_capacity(base_targets.len().saturating_add(stage2.len()));
    for ep in base_targets {
        covered.insert(*ep);
    }
    for ep in stage2 {
        covered.insert(*ep);
    }
    covered
}

pub fn build_random_residual_targets(
    base_targets: &[SocketAddr],
    covered: &HashSet<SocketAddr>,
    max_total: usize,
    port_min: u16,
    port_max: u16,
    rng: &mut impl rand::Rng,
) -> Vec<SocketAddr> {
    let mut dedup = HashSet::with_capacity(max_total.min(1024));
    let mut expanded = Vec::with_capacity(max_total.min(1024));
    let mut ips: Vec<std::net::IpAddr> = base_targets.iter().map(|e| e.ip()).collect();
    ips.sort();
    ips.dedup();
    if ips.is_empty() {
        return expanded;
    }
    let (lo, hi) = if port_min <= port_max {
        (port_min, port_max)
    } else {
        (port_max, port_min)
    };
    let mut ip_idx = 0usize;
    let mut attempts = 0usize;
    let max_attempts = max_total.saturating_mul(32).max(64);
    while expanded.len() < max_total && attempts < max_attempts {
        attempts += 1;
        let ip = ips[ip_idx % ips.len()];
        ip_idx = ip_idx.saturating_add(1);
        let port = rng.gen_range(lo..=hi);
        let cand = SocketAddr::new(ip, port);
        if covered.contains(&cand) || !dedup.insert(cand) {
            continue;
        }
        expanded.push(cand);
    }
    expanded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn announce_uses_public_port_when_known() {
        fn announce_port_for(self_public_ep: Option<SocketAddr>, listen_port: u16) -> u16 {
            self_public_ep.map(|e| e.port()).unwrap_or(listen_port)
        }

        let public = SocketAddr::from((Ipv4Addr::new(14, 241, 251, 119), 53958));
        assert_eq!(announce_port_for(Some(public), 7878), 53958);
        assert_eq!(announce_port_for(None, 7878), 7878);
    }

    #[tokio::test]
    async fn pending_bounded_when_tracker_silent() {
        let socket = Arc::new(
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .unwrap(),
        );
        let tracker = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 1337));
        let mut d = DecentralizedState::default();
        d.start(
            [1; 20],
            "node",
            vec!["udp://192.0.2.1:1337/announce".into()],
            60,
            false,
            None,
            None,
            7878,
        );
        d.slots[0].addrs.push(tracker);

        for _ in 0..30 {
            let _ = d.tick(&socket, None, false).await;
        }
        assert!(
            d.pending.len() <= d.slots.len() * 2,
            "pending must stay bounded, got {}",
            d.pending.len()
        );
    }

    #[tokio::test]
    async fn tick_emits_fresh_targets_each_call() {
        let socket = Arc::new(
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .unwrap(),
        );
        let mut d = DecentralizedState::default();
        d.active = true;
        d.listen_port = 7878;
        d.note_discovered(SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 4000)));

        let out1 = d.tick(&socket, None, false).await;
        assert!(!out1.punch_targets.is_empty());
        let out2 = d.tick(&socket, None, false).await;
        assert!(!out2.punch_targets.is_empty());
    }

    #[test]
    fn discovered_prunes_stale_and_caps() {
        let mut d = DecentralizedState::default();
        d.active = true;
        let ep = SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 4000));
        d.discovered.insert(
            ep,
            Instant::now()
                .checked_sub(DISCOVERED_TTL + Duration::from_secs(5))
                .unwrap(),
        );
        d.prune_discovered();
        assert!(!d.discovered.contains_key(&ep));

        for i in 0..(MAX_DISCOVERED + 10) {
            d.note_discovered(SocketAddr::from((
                Ipv4Addr::new(10, 0, 0, 1),
                4000 + i as u16,
            )));
        }
        d.prune_discovered();
        assert!(d.discovered.len() <= MAX_DISCOVERED);
    }

    #[test]
    fn take_pending_resolves_all_empty_slots() {
        let mut d = DecentralizedState::default();
        d.active = true;
        d.slots = vec![
            TrackerSlot::try_new("udp://a.example.com:1337/announce".into(), 180).unwrap(),
            TrackerSlot::try_new("udp://b.example.com:80/announce".into(), 180).unwrap(),
        ];
        let pending = d.take_pending_resolves();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].0, 0);
        assert_eq!(pending[1].0, 1);
        assert!(d.slots[0].resolve_in_flight);
        assert!(d.slots[1].resolve_in_flight);
        assert!(d.take_pending_resolves().is_empty());
    }

    #[test]
    fn add_resolved_addrs_per_slot() {
        let mut d = DecentralizedState::default();
        d.slots = vec![
            TrackerSlot::try_new("udp://a.example.com:1337/announce".into(), 180).unwrap(),
            TrackerSlot::try_new("udp://b.example.com:80/announce".into(), 180).unwrap(),
        ];
        let a1 = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 1337));
        let b1 = SocketAddr::from((Ipv4Addr::new(2, 2, 2, 2), 80));
        d.add_resolved_addrs(0, vec![a1]);
        d.add_resolved_addrs(1, vec![b1]);
        assert_eq!(d.slots[0].addrs, vec![a1]);
        assert_eq!(d.slots[1].addrs, vec![b1]);
    }

    #[test]
    fn announce_due_independent_per_slot() {
        let mut s0 = TrackerSlot::try_new("udp://a.example.com:1337/announce".into(), 180).unwrap();
        s0.server_interval_secs = 120;
        s0.last_announce = Some(Instant::now());
        let mut s1 = TrackerSlot::try_new("udp://b.example.com:80/announce".into(), 180).unwrap();
        s1.last_announce = None;
        assert!(!s0.announce_due(180));
        assert!(s1.announce_due(180));
    }

    #[test]
    fn handle_datagram_announce_unions_discovered() {
        use crate::nat::tracker::{ACTION_ANNOUNCE_RESPONSE, ANNOUNCE_HEADER_LEN};

        let mut d = DecentralizedState::default();
        d.active = true;
        let tracker = SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 1337));
        d.slots = vec![TrackerSlot::try_new("udp://9.9.9.9:1337/announce".into(), 180).unwrap()];
        d.slots[0].addrs.push(tracker);

        let txn = TransactionId([1, 2, 3, 4]);
        d.pending.insert(
            txn.0,
            PendingOp {
                kind: PendingKind::Announce,
                tracker,
                created: Instant::now(),
            },
        );

        let mut resp = vec![0u8; ANNOUNCE_HEADER_LEN + 12];
        resp[0..4].copy_from_slice(&ACTION_ANNOUNCE_RESPONSE.to_be_bytes());
        resp[4..8].copy_from_slice(&txn.0);
        resp[8..12].copy_from_slice(&180u32.to_be_bytes());
        resp[20..24].copy_from_slice(&[10, 0, 0, 1]);
        resp[24..26].copy_from_slice(&7878u16.to_be_bytes());
        resp[26..30].copy_from_slice(&[10, 0, 0, 2]);
        resp[30..32].copy_from_slice(&7879u16.to_be_bytes());

        assert!(d.handle_datagram(tracker, &resp).handled);
        assert_eq!(d.discovered.len(), 2);
        let result = d.handle_datagram(tracker, &resp);
        assert!(!result.handled);
    }

    #[test]
    fn handle_datagram_announce_emits_event() {
        use crate::nat::tracker::{ACTION_ANNOUNCE_RESPONSE, ANNOUNCE_HEADER_LEN};

        let mut d = DecentralizedState::default();
        d.active = true;
        d.is_joiner = true;
        let tracker = SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 1337));
        d.slots = vec![
            TrackerSlot::try_new("udp://tracker.example.com:1337/announce".into(), 180).unwrap(),
        ];
        d.slots[0].addrs.push(tracker);

        let txn = TransactionId([1, 2, 3, 4]);
        d.pending.insert(
            txn.0,
            PendingOp {
                kind: PendingKind::Announce,
                tracker,
                created: Instant::now(),
            },
        );

        let mut resp = vec![0u8; ANNOUNCE_HEADER_LEN + 6];
        resp[0..4].copy_from_slice(&ACTION_ANNOUNCE_RESPONSE.to_be_bytes());
        resp[4..8].copy_from_slice(&txn.0);
        resp[8..12].copy_from_slice(&180u32.to_be_bytes());
        resp[20..24].copy_from_slice(&[10, 0, 0, 1]);
        resp[24..26].copy_from_slice(&7878u16.to_be_bytes());

        let result = d.handle_datagram(tracker, &resp);
        assert!(result.handled);
        let event = result.event.expect("tracker event");
        assert_eq!(event.tracker_url, "udp://tracker.example.com:1337/announce");
        let info = event.announce.expect("announce info");
        assert!(info.first_announce_in_join);
        assert_eq!(info.peers.len(), 1);
    }

    #[test]
    fn canonical_stage2_targets_single_peer_width() {
        let punch = crate::advanced_tuning::HolePunchTuning::default();
        let base = SocketAddr::from((Ipv4Addr::LOCALHOST, 50_000));
        let stage2 = canonical_stage2_targets(&[base], &punch);
        assert!(stage2.len() <= MAX_EXPANDED_PUNCH_TARGETS);
        assert!(stage2.contains(&base));
    }

    #[test]
    fn canonical_covered_unions_stage2() {
        let punch = crate::advanced_tuning::HolePunchTuning::default();
        let base = SocketAddr::from((Ipv4Addr::LOCALHOST, 50_000));
        let stage2 = canonical_stage2_targets(&[base], &punch);
        let covered = canonical_covered_after_stage2(&[base], &stage2);
        assert!(covered.len() >= stage2.len());
    }

    #[test]
    fn join_wide_per_peer_width_clamps() {
        assert_eq!(
            join_wide_per_peer_width(
                1,
                MAX_EXPANDED_PUNCH_TARGETS,
                JOIN_OVERLAY_WIDE_MIN_WIDTH,
                JOIN_OVERLAY_WIDE_MAX_WIDTH
            ),
            256
        );
        assert_eq!(
            join_wide_per_peer_width(
                4,
                MAX_EXPANDED_PUNCH_TARGETS,
                JOIN_OVERLAY_WIDE_MIN_WIDTH,
                JOIN_OVERLAY_WIDE_MAX_WIDTH
            ),
            128
        );
        assert_eq!(
            join_wide_per_peer_width(
                32,
                MAX_EXPANDED_PUNCH_TARGETS,
                JOIN_OVERLAY_WIDE_MIN_WIDTH,
                JOIN_OVERLAY_WIDE_MAX_WIDTH
            ),
            32
        );
    }

    #[test]
    fn expand_intensity_respects_budget() {
        let bases: Vec<SocketAddr> = (0..16u8)
            .map(|i| SocketAddr::from((Ipv4Addr::new(i, 0, 0, 1), 4000)))
            .collect();
        let width = join_wide_per_peer_width(
            16,
            MAX_EXPANDED_PUNCH_TARGETS,
            JOIN_OVERLAY_WIDE_MIN_WIDTH,
            JOIN_OVERLAY_WIDE_MAX_WIDTH,
        );
        let expanded = expand_intensity_symmetric(&bases, width, 512);
        assert!(expanded.len() <= 512);
    }

    #[test]
    fn random_residual_excludes_covered() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let base = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 4000));
        let covered: HashSet<SocketAddr> = expand_intensity_symmetric(&[base], 64, 512)
            .into_iter()
            .collect();
        let residual = build_random_residual_targets(&[base], &covered, 64, 1024, 65535, &mut rng);
        assert!(residual.len() <= 64);
        for ep in &residual {
            assert!(!covered.contains(ep));
        }
    }

    #[test]
    fn expand_exact_first_all_base_before_cap() {
        let mut bases = Vec::new();
        for i in 0..80u8 {
            bases.push(SocketAddr::from((Ipv4Addr::new(i, 0, 0, 1), 4000)));
        }
        let cap = 512usize;
        let expanded = expand_symmetric_targets(&bases, None, cap);
        for ep in &bases {
            assert!(
                expanded.contains(ep),
                "exact endpoint {ep} must appear before symmetric expansion fills cap"
            );
        }
    }

    #[test]
    fn start_clamps_tracker_count() {
        let mut d = DecentralizedState::default();
        let urls: Vec<String> = (0..40)
            .map(|i| format!("udp://t{i}.example.com:1337/announce"))
            .collect();
        d.start([0; 20], "node", urls, 180, false, None, None, 7878);
        assert_eq!(d.slots.len(), MAX_ACTIVE_TRACKERS);
    }

    #[test]
    fn reconnect_tick_includes_newly_discovered_endpoint() {
        let mut d = DecentralizedState::default();
        d.active = true;
        d.listen_port = 7878;
        d.note_discovered(SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 5000)));
        let targets = d.exact_targets(None);
        d.note_discovered(SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 5001)));
        let expanded = expand_symmetric_targets(&d.exact_targets(None), None, 512);
        let new_ep = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 5001));
        assert!(targets.contains(&SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 5000))));
        assert!(expanded.contains(&new_ep));
    }

    #[test]
    fn http_announce_merges_discovered_and_emits_event() {
        let mut d = DecentralizedState::default();
        d.start(
            [3; 20],
            "node",
            vec!["http://tracker.example.com:8080/announce".into()],
            60,
            true,
            None,
            None,
            7878,
        );
        assert_eq!(d.slots.len(), 1);
        assert!(d.slots[0].is_http());

        let work = d.take_pending_http_announces(53958);
        assert_eq!(work.len(), 1);
        assert!(work[0].request_target.contains("port=53958"));
        assert!(d.slots[0].http_in_flight);
        assert!(d.take_pending_http_announces(53958).is_empty());

        let peer = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 9), 9000));
        let event = d
            .apply_http_announce_result(HttpAnnounceResult {
                slot_idx: 0,
                generation: work[0].generation,
                tracker_url: work[0].tracker_url.clone(),
                outcome: Ok((180, vec![peer])),
            })
            .expect("event");
        assert!(!d.slots[0].http_in_flight);
        assert!(d.discovered.contains_key(&peer));
        let info = event.announce.expect("announce");
        assert!(info.first_announce_in_join);
        assert_eq!(info.peers, vec![peer]);
    }

    #[test]
    fn http_announce_result_ignored_after_stop() {
        let mut d = DecentralizedState::default();
        d.start(
            [3; 20],
            "node",
            vec!["http://tracker.example.com/announce".into()],
            60,
            false,
            None,
            None,
            7878,
        );
        let work = d.take_pending_http_announces(7878);
        assert_eq!(work.len(), 1);
        let gen = work[0].generation;
        d.stop();
        assert!(d
            .apply_http_announce_result(HttpAnnounceResult {
                slot_idx: 0,
                generation: gen,
                tracker_url: work[0].tracker_url.clone(),
                outcome: Ok((120, vec![SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 5))])),
            })
            .is_none());
        assert!(d.discovered.is_empty());
    }

    #[test]
    fn https_slots_are_kept_but_not_announced() {
        let mut d = DecentralizedState::default();
        d.start(
            [1; 20],
            "n",
            vec![
                "https://secure.example.com/announce".into(),
                "udp://udp.example.com:1337/announce".into(),
            ],
            60,
            false,
            None,
            None,
            7878,
        );
        assert_eq!(d.slots.len(), 2);
        assert!(d.take_pending_http_announces(7878).is_empty());
        assert_eq!(d.take_pending_resolves().len(), 1);
    }

    #[test]
    fn take_pending_resolves_skips_http_slots() {
        let mut d = DecentralizedState::default();
        d.active = true;
        d.slots = vec![
            TrackerSlot::try_new("http://h.example.com/announce".into(), 180).unwrap(),
            TrackerSlot::try_new("udp://u.example.com:1337/announce".into(), 180).unwrap(),
        ];
        let pending = d.take_pending_resolves();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, 1);
    }
}
