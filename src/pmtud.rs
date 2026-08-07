use crate::net::packet::UNDERLAY_IPV4_UDP_OVERHEAD;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

pub const DEFAULT_MTU: usize = 1220;

/// RFC1918 IPv4 only (`10/8`, `172.16/12`, `192.168/16`). Used for LAN PMTUD
/// probe routing and never-acked soft-down floor; not APIPA/CGNAT/IPv6 ULA.
pub fn is_rfc1918_private_ip(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4.is_private())
}
const MIN_MTU: usize = 576;
const MAX_MTU: usize = 1500;
/// Sentinel: one past the largest probeable IP MTU.
const FIRST_BAD_SENTINEL: usize = MAX_MTU + 1;
/// TUN / adapter payload floor (matches `suggested_adapter_mtu` clamp).
pub const MIN_ADAPTER_PAYLOAD_MTU: usize = 280;
/// Per-peer cooldown for TX-oversize early wake hints.
const REVALIDATE_HINT_COOLDOWN: Duration = Duration::from_secs(5);
/// Cooldown for data-plane size-collapse early wake (distinct from TX-oversize hint).
const EARLY_WAKE_COOLDOWN: Duration = Duration::from_secs(10);
const ANOMALY_REARM_CAP: Duration = Duration::from_secs(5);
const ADAPTIVE_TIMEOUT_CAP: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Plateau,
    Raise,
    Binary,
    Revalidate,
    Recheck,
    DownSearch,
    Frozen,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Phase::Plateau => "plateau",
            Phase::Raise => "raise",
            Phase::Binary => "binary",
            Phase::Revalidate => "revalidate",
            Phase::Recheck => "recheck",
            Phase::DownSearch => "down_search",
            Phase::Frozen => "frozen",
        }
    }

    fn is_searching(self) -> bool {
        matches!(
            self,
            Phase::Raise | Phase::Binary | Phase::Revalidate | Phase::Recheck | Phase::DownSearch
        )
    }
}

#[derive(Clone, Debug)]
struct Inflight {
    probe_id: u32,
    size: usize,
    deadline: Instant,
    confirms_left: u8,
}

#[derive(Clone, Debug)]
struct GraceProbe {
    probe_id: u32,
    size: usize,
    search_gen: u32,
    deadline: Instant,
}

#[derive(Clone, Debug)]
struct PeerState {
    last_good: usize,
    first_bad: usize,
    stable: usize,
    phase: Phase,
    step: usize,
    inflight: Option<Inflight>,
    search_gen: u32,
    probes_used: u32,
    consecutive_lower_campaigns: u8,
    next_raise_at: Instant,
    /// When DownSearch started, previous stable for hysteresis accounting.
    down_from_stable: Option<usize>,
    /// Last time an oversize TX hint advanced `next_raise_at`.
    last_revalidate_hint_at: Option<Instant>,
    /// Last data-plane early-wake (size collapse).
    last_early_wake_at: Option<Instant>,
    /// Late-ACK grace after final probe timeout in Revalidate/Recheck.
    grace: Option<GraceProbe>,
    /// At least one ACK observed during the current DownSearch.
    downsearch_got_ack: bool,
    /// Cached RTT for adaptive probe timeout (`< 0` = unknown).
    rtt_ms: f64,
    large_alive: bool,
    /// At least one successful probe ACK for this peer (any phase).
    ever_acked: bool,
}

impl PeerState {
    fn new(now: Instant, raise_period: Duration, raise_step: usize) -> Self {
        Self {
            last_good: DEFAULT_MTU,
            first_bad: FIRST_BAD_SENTINEL,
            stable: DEFAULT_MTU,
            phase: Phase::Plateau,
            step: raise_step,
            inflight: None,
            search_gen: 1,
            probes_used: 0,
            consecutive_lower_campaigns: 0,
            next_raise_at: now + raise_period,
            down_from_stable: None,
            last_revalidate_hint_at: None,
            last_early_wake_at: None,
            grace: None,
            downsearch_got_ack: false,
            rtt_ms: -1.0,
            large_alive: false,
            ever_acked: false,
        }
    }

    fn window_closed(&self, epsilon: usize) -> bool {
        self.first_bad.saturating_sub(self.last_good) <= epsilon
    }

    fn abort_inflight(&mut self) {
        self.inflight = None;
        self.grace = None;
        self.search_gen = self.search_gen.wrapping_add(1);
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ProbeIntent {
    pub peer: SocketAddr,
    pub size: usize,
    pub probe_id: u32,
    pub search_gen: u32,
}

/// Data-plane corroboration flags for one endpoint (from SizeLossTracker).
#[derive(Clone, Copy, Debug, Default)]
pub struct SizeHealth {
    pub warm: bool,
    pub large_alive: bool,
    pub large_collapsed: bool,
}

/// Per-tick metric deltas produced by the FSM (engine merges into EngineMetrics).
#[derive(Clone, Copy, Debug, Default)]
pub struct PmtudEventCounts {
    pub probe_timeouts: u64,
    pub revalidate_fail_events: u64,
    pub recheck_recovered_events: u64,
    pub softdown_events: u64,
    pub probe_anomaly_events: u64,
    pub late_ack_events: u64,
    pub early_wake_events: u64,
}

#[derive(Clone, Debug)]
pub struct PeerMtuSnapshot {
    pub endpoint: SocketAddr,
    pub phase: String,
    pub last_good: usize,
    pub stable: usize,
    pub first_bad: usize,
    pub probes_used: u32,
}

/// Per-peer inputs for one PMTUD tick.
#[derive(Clone, Copy, Debug)]
pub struct PeerTickInput {
    pub addr: SocketAddr,
    pub health: SizeHealth,
    /// Routing smoothed RTT in ms; `< 0` means unknown.
    pub rtt_ms: f64,
}

pub struct PathMtuDiscovery {
    peers: HashMap<SocketAddr, PeerState>,
    min_path_mtu: usize,
    /// When set, PLPMTUD search is frozen at this IP-total MTU.
    pinned: Option<usize>,
    probe_id_counter: u32,
    rr_cursor: usize,
    /// Configured floor for adaptive probe timeout.
    probe_timeout: Duration,
    confirm_count: u8,
    resolve_epsilon: usize,
    raise_step: usize,
    max_probes_per_search: u32,
    max_concurrent_peers: usize,
    stable_downgrade_batches: u8,
    raise_period: Duration,
}

impl PathMtuDiscovery {
    pub fn new() -> Self {
        let t = crate::advanced_tuning::PmtudTuning::default();
        let timers = crate::advanced_tuning::TimerTuning::default();
        Self {
            peers: HashMap::new(),
            min_path_mtu: DEFAULT_MTU,
            pinned: None,
            probe_id_counter: 0,
            rr_cursor: 0,
            probe_timeout: Duration::from_millis(t.probe_timeout_ms),
            confirm_count: t.confirm_count,
            resolve_epsilon: t.resolve_epsilon,
            raise_step: t.raise_step,
            max_probes_per_search: t.max_probes_per_search,
            max_concurrent_peers: t.max_concurrent_peers,
            stable_downgrade_batches: t.stable_downgrade_batches,
            raise_period: Duration::from_secs(timers.pmtud_raise_secs),
        }
    }

    pub fn apply_tuning(&mut self, t: &crate::advanced_tuning::PmtudTuning) {
        self.probe_timeout = Duration::from_millis(t.probe_timeout_ms);
        self.confirm_count = t.confirm_count;
        self.resolve_epsilon = t.resolve_epsilon;
        self.raise_step = t.raise_step;
        self.max_probes_per_search = t.max_probes_per_search;
        self.max_concurrent_peers = t.max_concurrent_peers;
        self.stable_downgrade_batches = t.stable_downgrade_batches;
        if self.pinned.is_some() {
            return;
        }
        for peer in self.peers.values_mut() {
            peer.abort_inflight();
            peer.step = self.raise_step;
            peer.probes_used = 0;
            if peer.phase.is_searching() {
                peer.phase = Phase::Plateau;
                peer.next_raise_at = Instant::now() + self.raise_period;
            }
        }
    }

    pub fn set_raise_period(&mut self, secs: u64) {
        self.raise_period = Duration::from_secs(secs.max(1));
    }

    pub fn is_pinned(&self) -> bool {
        self.pinned.is_some()
    }

    /// Freeze or unfreeze path MTU. `Some(m)` clamps to `MIN_MTU..=MAX_MTU`.
    pub fn set_pinned(&mut self, path_mtu: Option<usize>) {
        match path_mtu {
            Some(m) => {
                let m = Self::clamp_size(m);
                self.pinned = Some(m);
                self.min_path_mtu = m;
                let raise_period = self.raise_period;
                for peer in self.peers.values_mut() {
                    peer.abort_inflight();
                    peer.last_good = m;
                    peer.stable = m;
                    peer.first_bad = m.saturating_add(1).min(FIRST_BAD_SENTINEL);
                    peer.phase = Phase::Frozen;
                    peer.probes_used = 0;
                    peer.next_raise_at = Instant::now() + raise_period;
                    peer.down_from_stable = None;
                    peer.downsearch_got_ack = false;
                }
            }
            None => {
                self.pinned = None;
                self.min_path_mtu = DEFAULT_MTU;
                let raise_period = self.raise_period;
                let raise_step = self.raise_step;
                let now = Instant::now();
                for peer in self.peers.values_mut() {
                    *peer = PeerState::new(now, raise_period, raise_step);
                }
            }
        }
    }

    /// IP-total path MTU implied by a TUN adapter payload MTU (inverse of suggestion).
    pub fn path_mtu_from_adapter(adapter_mtu: usize, enc_overhead: usize) -> usize {
        // Match CLI effective_adapter_mtu range (576..=1500).
        let adapter = adapter_mtu.clamp(MIN_MTU, MAX_MTU);
        adapter
            .saturating_add(UNDERLAY_IPV4_UDP_OVERHEAD)
            .saturating_add(enc_overhead)
            .clamp(MIN_MTU, MAX_MTU)
    }

    pub fn remove_peer(&mut self, peer: SocketAddr) {
        if self.peers.remove(&peer).is_some() {
            self.recalc_min();
        }
    }

    pub fn min_mtu(&self) -> usize {
        self.min_path_mtu
    }

    /// ACK-proven IP-total MTU for `peer`, if tracked.
    pub fn peer_last_good(&self, peer: SocketAddr) -> Option<usize> {
        self.peers.get(&peer).map(|p| p.last_good)
    }

    /// Max UDP payload bytes that fit the peer's proven IP MTU (or global min).
    pub fn udp_payload_budget(&self, peer: SocketAddr) -> usize {
        let ip_mtu = self
            .peers
            .get(&peer)
            .map(|p| p.last_good)
            .unwrap_or(self.min_path_mtu);
        ip_mtu.saturating_sub(UNDERLAY_IPV4_UDP_OVERHEAD)
    }

    /// TUN / adapter payload MTU from proven path MTU (IP total − underlay − enc).
    pub fn suggested_adapter_mtu(&self, enc_overhead: usize) -> usize {
        let after = self
            .min_path_mtu
            .saturating_sub(UNDERLAY_IPV4_UDP_OVERHEAD + enc_overhead);
        after.clamp(MIN_ADAPTER_PAYLOAD_MTU, MAX_MTU)
    }

    pub fn snapshot(&self) -> Vec<PeerMtuSnapshot> {
        let mut out: Vec<_> = self
            .peers
            .iter()
            .map(|(ep, p)| PeerMtuSnapshot {
                endpoint: *ep,
                phase: p.phase.as_str().to_string(),
                last_good: p.last_good,
                stable: p.stable,
                first_bad: p.first_bad,
                probes_used: p.probes_used,
            })
            .collect();
        out.sort_by_key(|s| s.endpoint);
        out
    }

    /// Configured probe-timeout floor in milliseconds (adaptive timeout never goes below this).
    pub fn probe_timeout_floor_ms(&self) -> u64 {
        self.probe_timeout.as_millis() as u64
    }

    /// Place `peer` on Plateau at `mtu` so the next due tick revalidates (no raise room).
    pub fn seed_plateau_at(&mut self, peer: SocketAddr, mtu: usize, now: Instant) {
        let raise_period = self.raise_period;
        let raise_step = self.raise_step;
        let st = self
            .peers
            .entry(peer)
            .or_insert_with(|| PeerState::new(now, raise_period, raise_step));
        let m = Self::clamp_size(mtu);
        st.last_good = m;
        st.stable = m;
        st.first_bad = m.saturating_add(1).min(FIRST_BAD_SENTINEL);
        st.phase = Phase::Plateau;
        st.next_raise_at = now;
        st.inflight = None;
        st.grace = None;
        st.probes_used = 0;
        self.recalc_min();
    }

    /// Early-wake Plateau/Frozen so the next tick can Raise or Revalidate (TX-oversize hint).
    /// Does not abort inflight, change phase, or bump `search_gen`.
    pub fn request_revalidate(&mut self, peer: SocketAddr, now: Instant) -> bool {
        if self.pinned.is_some() {
            return false;
        }
        let Some(st) = self.peers.get_mut(&peer) else {
            return false;
        };
        if let Some(prev) = st.last_revalidate_hint_at {
            if now.saturating_duration_since(prev) < REVALIDATE_HINT_COOLDOWN {
                return false;
            }
        }
        match st.phase {
            Phase::Plateau | Phase::Frozen => {
                st.next_raise_at = now;
                st.last_revalidate_hint_at = Some(now);
                true
            }
            _ => false,
        }
    }

    /// Data-plane size-collapse early wake (10s cooldown, Plateau/Frozen only).
    pub fn request_early_wake(&mut self, peer: SocketAddr, now: Instant) -> bool {
        if self.pinned.is_some() {
            return false;
        }
        let Some(st) = self.peers.get_mut(&peer) else {
            return false;
        };
        if let Some(prev) = st.last_early_wake_at {
            if now.saturating_duration_since(prev) < EARLY_WAKE_COOLDOWN {
                return false;
            }
        }
        match st.phase {
            Phase::Plateau | Phase::Frozen => {
                st.next_raise_at = now;
                st.last_early_wake_at = Some(now);
                true
            }
            _ => false,
        }
    }

    /// Next time the engine should wake for PMTUD (lazy tick).
    pub fn next_deadline(&self, now: Instant) -> Instant {
        let mut next = now + self.raise_period;
        let mut any_active = false;
        for peer in self.peers.values() {
            if let Some(inf) = &peer.inflight {
                next = next.min(inf.deadline);
                any_active = true;
            }
            if let Some(g) = &peer.grace {
                next = next.min(g.deadline);
                any_active = true;
            }
            match peer.phase {
                Phase::Raise
                | Phase::Binary
                | Phase::Revalidate
                | Phase::Recheck
                | Phase::DownSearch => {
                    any_active = true;
                    next = next.min(now);
                }
                Phase::Frozen | Phase::Plateau => {
                    next = next.min(peer.next_raise_at);
                }
            }
        }
        if any_active {
            next
        } else if self.peers.is_empty() {
            now + self.raise_period
        } else {
            next
        }
    }

    pub fn needs_fast_tick(&self) -> bool {
        self.peers.values().any(|p| {
            p.inflight.is_some()
                || p.grace.is_some()
                || p.phase.is_searching()
                || (p.phase == Phase::Frozen && p.inflight.is_none())
        })
    }

    fn next_probe_id(&mut self) -> u32 {
        self.probe_id_counter = self.probe_id_counter.wrapping_add(1);
        self.probe_id_counter
    }

    fn recalc_min(&mut self) {
        if let Some(m) = self.pinned {
            self.min_path_mtu = m;
            return;
        }
        self.min_path_mtu = self
            .peers
            .values()
            .map(|p| p.last_good)
            .min()
            .unwrap_or(DEFAULT_MTU);
    }

    fn ensure_peer(&mut self, peer: SocketAddr, now: Instant) -> &mut PeerState {
        let raise_period = self.raise_period;
        let raise_step = self.raise_step;
        let pinned = self.pinned;
        self.peers.entry(peer).or_insert_with(|| {
            let mut st = PeerState::new(now, raise_period, raise_step);
            if let Some(m) = pinned {
                st.last_good = m;
                st.stable = m;
                st.first_bad = m.saturating_add(1).min(FIRST_BAD_SENTINEL);
                st.phase = Phase::Frozen;
            }
            st
        })
    }

    fn clamp_size(sz: usize) -> usize {
        sz.clamp(MIN_MTU, MAX_MTU)
    }

    fn timeout_for_peer(&self, peer: &PeerState) -> Duration {
        let floor = self.probe_timeout;
        if peer.rtt_ms < 0.0 {
            return floor;
        }
        let adaptive_ms = (4.0 * peer.rtt_ms).round().max(0.0) as u64;
        let floor_ms = floor.as_millis() as u64;
        let cap_ms = ADAPTIVE_TIMEOUT_CAP.as_millis() as u64;
        let ms = adaptive_ms.max(floor_ms).min(cap_ms);
        Duration::from_millis(ms)
    }

    fn raise_target(peer: &PeerState) -> Option<usize> {
        if peer.last_good >= MAX_MTU {
            return None;
        }
        let hi = peer.first_bad.saturating_sub(1).min(MAX_MTU);
        if hi <= peer.last_good {
            return None;
        }
        let t = (peer.last_good + peer.step).min(hi);
        if t > peer.last_good {
            Some(t)
        } else {
            None
        }
    }

    fn binary_target(peer: &PeerState) -> Option<usize> {
        let lo = peer.last_good;
        let hi = peer.first_bad;
        if hi <= lo + 1 {
            return None;
        }
        let mid = lo + (hi - lo) / 2;
        if mid > lo && mid < hi {
            Some(Self::clamp_size(mid))
        } else {
            None
        }
    }

    fn enter_frozen(peer: &mut PeerState, now: Instant, raise_period: Duration) {
        peer.inflight = None;
        peer.grace = None;
        peer.phase = Phase::Frozen;
        peer.next_raise_at = now + raise_period;
        peer.probes_used = 0;
    }

    fn enter_plateau(
        peer: &mut PeerState,
        now: Instant,
        raise_period: Duration,
        raise_step: usize,
        downgrade_batches: u8,
    ) {
        peer.inflight = None;
        peer.grace = None;
        peer.phase = Phase::Plateau;
        peer.next_raise_at = now + raise_period;
        peer.probes_used = 0;
        peer.step = raise_step;

        if let Some(from) = peer.down_from_stable.take() {
            if peer.last_good < from {
                peer.consecutive_lower_campaigns =
                    peer.consecutive_lower_campaigns.saturating_add(1);
                if peer.consecutive_lower_campaigns >= downgrade_batches {
                    peer.stable = peer.last_good;
                    peer.consecutive_lower_campaigns = 0;
                }
            } else {
                peer.consecutive_lower_campaigns = 0;
            }
        }
    }

    fn finish_downsearch_plateau(
        peer: &mut PeerState,
        now: Instant,
        raise_period: Duration,
        raise_step: usize,
        downgrade_batches: u8,
    ) {
        if !peer.downsearch_got_ack {
            peer.first_bad = FIRST_BAD_SENTINEL;
        }
        Self::enter_plateau(peer, now, raise_period, raise_step, downgrade_batches);
    }

    fn maybe_budget_freeze(
        peer: &mut PeerState,
        now: Instant,
        raise_period: Duration,
        max_probes: u32,
    ) -> bool {
        if peer.phase == Phase::Recheck {
            return false;
        }
        if peer.probes_used >= max_probes {
            Self::enter_frozen(peer, now, raise_period);
            true
        } else {
            false
        }
    }

    fn begin_probe(
        peer: &mut PeerState,
        probe_id: u32,
        size: usize,
        deadline: Instant,
        confirms: u8,
    ) {
        peer.grace = None;
        peer.inflight = Some(Inflight {
            probe_id,
            size: Self::clamp_size(size),
            deadline,
            confirms_left: confirms,
        });
        peer.probes_used = peer.probes_used.saturating_add(1);
    }

    fn soft_down_last_good(peer: &PeerState) -> usize {
        if peer.last_good < peer.stable {
            MIN_MTU.max(peer.last_good / 2)
        } else {
            MIN_MTU.max(peer.stable / 2)
        }
    }

    fn apply_soft_down(&mut self, ep: SocketAddr, now: Instant, events: &mut PmtudEventCounts) {
        let raise_step = self.raise_step;
        let raise_period = self.raise_period;
        let epsilon = self.resolve_epsilon;
        let downgrade_batches = self.stable_downgrade_batches;
        let Some(peer) = self.peers.get_mut(&ep) else {
            return;
        };
        let mut new_lg = Self::soft_down_last_good(peer);
        if is_rfc1918_private_ip(ep.ip()) && !peer.ever_acked {
            new_lg = new_lg.max(DEFAULT_MTU);
        }
        peer.first_bad = peer.stable.max(new_lg + 1);
        peer.last_good = new_lg;
        peer.down_from_stable = Some(peer.stable);
        peer.downsearch_got_ack = false;
        peer.phase = Phase::DownSearch;
        peer.probes_used = 0;
        peer.step = raise_step;
        peer.search_gen = peer.search_gen.wrapping_add(1);
        peer.inflight = None;
        peer.grace = None;
        events.softdown_events = events.softdown_events.saturating_add(1);
        // Floor can close the window immediately; finish so Raise can retry
        // (DownSearch is only scheduled when binary_target is Some).
        if peer.window_closed(epsilon) {
            Self::finish_downsearch_plateau(peer, now, raise_period, raise_step, downgrade_batches);
        }
        self.recalc_min();
    }

    /// Lift stuck never-acked RFC1918 peers whose `last_good` fell below the
    /// discovery floor (e.g. endpoint morph public → private after soft-downs).
    fn heal_unacked_private_floor(&mut self, now: Instant) {
        let raise_step = self.raise_step;
        let mut healed = false;
        let eps: Vec<SocketAddr> = self.peers.keys().copied().collect();
        for ep in eps {
            let Some(peer) = self.peers.get_mut(&ep) else {
                continue;
            };
            if !is_rfc1918_private_ip(ep.ip()) || peer.ever_acked || peer.last_good >= DEFAULT_MTU {
                continue;
            }
            peer.last_good = DEFAULT_MTU;
            peer.stable = DEFAULT_MTU;
            peer.first_bad = FIRST_BAD_SENTINEL;
            peer.inflight = None;
            peer.grace = None;
            peer.search_gen = peer.search_gen.wrapping_add(1);
            peer.phase = Phase::Plateau;
            peer.next_raise_at = now;
            peer.probes_used = 0;
            peer.step = raise_step;
            peer.down_from_stable = None;
            peer.downsearch_got_ack = false;
            peer.consecutive_lower_campaigns = 0;
            healed = true;
        }
        if healed {
            self.recalc_min();
        }
    }

    fn apply_anomaly(&mut self, ep: SocketAddr, now: Instant, events: &mut PmtudEventCounts) {
        let raise_period = self.raise_period;
        let raise_step = self.raise_step;
        let Some(peer) = self.peers.get_mut(&ep) else {
            return;
        };
        peer.inflight = None;
        peer.grace = None;
        peer.phase = Phase::Plateau;
        peer.probes_used = 0;
        peer.step = raise_step;
        let rearm = raise_period.min(ANOMALY_REARM_CAP);
        peer.next_raise_at = now + rearm;
        events.probe_anomaly_events = events.probe_anomaly_events.saturating_add(1);
    }

    fn enter_recheck(&mut self, ep: SocketAddr, events: &mut PmtudEventCounts) {
        let Some(peer) = self.peers.get_mut(&ep) else {
            return;
        };
        peer.inflight = None;
        peer.grace = None;
        peer.phase = Phase::Recheck;
        peer.probes_used = 0;
        peer.search_gen = peer.search_gen.wrapping_add(1);
        events.revalidate_fail_events = events.revalidate_fail_events.saturating_add(1);
    }

    /// Drive timeouts, grace expiry, phase starts, and emit probes.
    pub fn on_tick(
        &mut self,
        now: Instant,
        peers: &[PeerTickInput],
    ) -> (Vec<ProbeIntent>, PmtudEventCounts) {
        let mut events = PmtudEventCounts::default();
        if self.pinned.is_some() {
            return (Vec::new(), events);
        }
        self.heal_unacked_private_floor(now);
        let active: std::collections::HashSet<SocketAddr> = peers.iter().map(|p| p.addr).collect();
        let stale: Vec<SocketAddr> = self
            .peers
            .keys()
            .copied()
            .filter(|p| !active.contains(p))
            .collect();
        for p in &stale {
            self.peers.remove(p);
        }
        if !stale.is_empty() {
            self.recalc_min();
        }

        for input in peers {
            let st = self.ensure_peer(input.addr, now);
            st.rtt_ms = input.rtt_ms;
            st.large_alive = input.health.warm && input.health.large_alive;
        }

        // Expire grace windows → confirmed timeout fail.
        let grace_expired: Vec<SocketAddr> = self
            .peers
            .iter()
            .filter_map(|(ep, p)| p.grace.as_ref().filter(|g| now >= g.deadline).map(|_| *ep))
            .collect();
        for ep in grace_expired {
            let size = self
                .peers
                .get(&ep)
                .and_then(|p| p.grace.as_ref().map(|g| g.size))
                .unwrap_or(MIN_MTU);
            if let Some(p) = self.peers.get_mut(&ep) {
                p.grace = None;
            }
            events.probe_timeouts = events.probe_timeouts.saturating_add(1);
            self.apply_timeout_confirmed_fail(ep, size, now, &mut events);
        }

        // Process inflight timeouts.
        let mut timed_out: Vec<SocketAddr> = Vec::new();
        for (ep, peer) in self.peers.iter() {
            if let Some(inf) = &peer.inflight {
                if now >= inf.deadline && inf.probe_id != 0 {
                    timed_out.push(*ep);
                }
            }
        }
        let mut intents: Vec<ProbeIntent> = Vec::new();
        for ep in timed_out {
            if let Some(intent) = self.on_timeout(ep, now, &mut events) {
                intents.push(intent);
            }
        }

        let eps: Vec<SocketAddr> = peers.iter().map(|p| p.addr).collect();
        for ep in &eps {
            let Some(peer) = self.peers.get_mut(ep) else {
                continue;
            };
            if peer.inflight.is_some() || peer.grace.is_some() {
                continue;
            }
            match peer.phase {
                Phase::Plateau if now >= peer.next_raise_at => {
                    peer.probes_used = 0;
                    peer.step = self.raise_step;
                    peer.search_gen = peer.search_gen.wrapping_add(1);
                    if Self::raise_target(peer).is_some() {
                        peer.phase = Phase::Raise;
                    } else {
                        peer.phase = Phase::Revalidate;
                    }
                }
                Phase::Frozen if now >= peer.next_raise_at => {
                    peer.phase = Phase::Plateau;
                    peer.step = self.raise_step;
                    peer.probes_used = 0;
                    peer.search_gen = peer.search_gen.wrapping_add(1);
                    peer.next_raise_at = now;
                    if Self::raise_target(peer).is_some() {
                        peer.phase = Phase::Raise;
                    } else {
                        peer.phase = Phase::Revalidate;
                    }
                }
                _ => {}
            }
        }

        let mut want: Vec<SocketAddr> = Vec::new();
        for ep in &eps {
            let Some(peer) = self.peers.get(ep) else {
                continue;
            };
            if peer.inflight.is_some() || peer.grace.is_some() {
                continue;
            }
            let wants = match peer.phase {
                Phase::Raise => Self::raise_target(peer).is_some(),
                Phase::Binary | Phase::DownSearch => Self::binary_target(peer).is_some(),
                Phase::Revalidate | Phase::Recheck => true,
                Phase::Plateau | Phase::Frozen => false,
            };
            if wants {
                want.push(*ep);
            }
        }

        if want.is_empty() {
            return (intents, events);
        }

        let already = intents.len();
        let cap = self
            .max_concurrent_peers
            .saturating_sub(already)
            .min(want.len());
        if self.rr_cursor >= want.len() {
            self.rr_cursor = 0;
        }
        let mut issued = 0;
        for i in 0..want.len() {
            if issued >= cap {
                break;
            }
            let idx = (self.rr_cursor + i) % want.len();
            let ep = want[idx];
            if let Some(intent) = self.issue_probe(ep, now) {
                intents.push(intent);
                issued += 1;
            }
        }
        self.rr_cursor = self.rr_cursor.wrapping_add(issued.max(1));

        (intents, events)
    }

    fn issue_probe(&mut self, ep: SocketAddr, now: Instant) -> Option<ProbeIntent> {
        let confirms = self.confirm_count;
        let max_probes = self.max_probes_per_search;
        let raise_period = self.raise_period;
        let epsilon = self.resolve_epsilon;
        let raise_step = self.raise_step;
        let downgrade_batches = self.stable_downgrade_batches;

        let timeout = {
            let peer = self.peers.get(&ep)?;
            self.timeout_for_peer(peer)
        };

        let peer = self.peers.get_mut(&ep)?;
        if peer.inflight.is_some() || peer.grace.is_some() {
            return None;
        }
        if Self::maybe_budget_freeze(peer, now, raise_period, max_probes) {
            return None;
        }

        let size = match peer.phase {
            Phase::Raise => Self::raise_target(peer)?,
            Phase::Binary | Phase::DownSearch => {
                if peer.window_closed(epsilon) {
                    if peer.phase == Phase::DownSearch {
                        Self::finish_downsearch_plateau(
                            peer,
                            now,
                            raise_period,
                            raise_step,
                            downgrade_batches,
                        );
                    } else {
                        Self::enter_plateau(peer, now, raise_period, raise_step, downgrade_batches);
                    }
                    return None;
                }
                Self::binary_target(peer)?
            }
            Phase::Revalidate | Phase::Recheck => Self::clamp_size(peer.stable),
            Phase::Plateau | Phase::Frozen => return None,
        };

        let probe_id = self.next_probe_id();
        let peer = self.peers.get_mut(&ep)?;
        let gen = peer.search_gen;
        Self::begin_probe(peer, probe_id, size, now + timeout, confirms);
        Some(ProbeIntent {
            peer: ep,
            size,
            probe_id,
            search_gen: gen,
        })
    }

    fn on_timeout(
        &mut self,
        ep: SocketAddr,
        now: Instant,
        events: &mut PmtudEventCounts,
    ) -> Option<ProbeIntent> {
        let raise_period = self.raise_period;
        let max_probes = self.max_probes_per_search;

        let timeout = {
            let peer = self.peers.get(&ep)?;
            self.timeout_for_peer(peer)
        };

        let Some(peer) = self.peers.get_mut(&ep) else {
            return None;
        };
        let Some(inf) = peer.inflight.take() else {
            return None;
        };
        events.probe_timeouts = events.probe_timeouts.saturating_add(1);

        if inf.confirms_left > 1 {
            let left = inf.confirms_left - 1;
            let size = inf.size;
            // Recheck: do not count against max_probes / freeze.
            if peer.phase != Phase::Recheck {
                peer.probes_used = peer.probes_used.saturating_add(1);
                if peer.probes_used >= max_probes {
                    Self::enter_frozen(peer, now, raise_period);
                    return None;
                }
            }
            let probe_id = self.next_probe_id();
            let peer = self.peers.get_mut(&ep)?;
            let gen = peer.search_gen;
            peer.inflight = Some(Inflight {
                probe_id,
                size,
                deadline: now + timeout,
                confirms_left: left,
            });
            return Some(ProbeIntent {
                peer: ep,
                size,
                probe_id,
                search_gen: gen,
            });
        }

        // Final timeout: grace for Revalidate/Recheck; immediate fail otherwise.
        let phase = peer.phase;
        let gen = peer.search_gen;
        if matches!(phase, Phase::Revalidate | Phase::Recheck) {
            peer.grace = Some(GraceProbe {
                probe_id: inf.probe_id,
                size: inf.size,
                search_gen: gen,
                deadline: now + timeout,
            });
            return None;
        }

        self.apply_timeout_confirmed_fail(ep, inf.size, now, events);
        None
    }

    fn apply_timeout_confirmed_fail(
        &mut self,
        ep: SocketAddr,
        size: usize,
        now: Instant,
        events: &mut PmtudEventCounts,
    ) {
        let raise_period = self.raise_period;
        let raise_step = self.raise_step;
        let epsilon = self.resolve_epsilon;
        let downgrade_batches = self.stable_downgrade_batches;
        let max_probes = self.max_probes_per_search;

        let phase = self.peers.get(&ep).map(|p| p.phase);
        let large_alive = self.peers.get(&ep).map(|p| p.large_alive).unwrap_or(false);

        match phase {
            Some(Phase::Raise) => {
                let Some(peer) = self.peers.get_mut(&ep) else {
                    return;
                };
                let sz = Self::clamp_size(size);
                peer.inflight = None;
                peer.first_bad = sz;
                peer.step = raise_step;
                peer.phase = Phase::Binary;
                if peer.window_closed(epsilon) {
                    Self::enter_plateau(peer, now, raise_period, raise_step, downgrade_batches);
                } else {
                    let _ = Self::maybe_budget_freeze(peer, now, raise_period, max_probes);
                }
            }
            Some(Phase::Binary) => {
                let Some(peer) = self.peers.get_mut(&ep) else {
                    return;
                };
                let sz = Self::clamp_size(size);
                peer.inflight = None;
                peer.first_bad = sz.min(peer.first_bad);
                if peer.window_closed(epsilon) {
                    Self::enter_plateau(peer, now, raise_period, raise_step, downgrade_batches);
                } else {
                    let _ = Self::maybe_budget_freeze(peer, now, raise_period, max_probes);
                }
            }
            Some(Phase::Revalidate) => {
                if large_alive {
                    self.apply_anomaly(ep, now, events);
                } else {
                    self.enter_recheck(ep, events);
                }
            }
            Some(Phase::Recheck) => {
                self.apply_soft_down(ep, now, events);
            }
            Some(Phase::DownSearch) => {
                let Some(peer) = self.peers.get_mut(&ep) else {
                    return;
                };
                let sz = Self::clamp_size(size);
                peer.inflight = None;
                peer.first_bad = sz.min(peer.first_bad);
                if peer.window_closed(epsilon) {
                    Self::finish_downsearch_plateau(
                        peer,
                        now,
                        raise_period,
                        raise_step,
                        downgrade_batches,
                    );
                } else {
                    let _ = Self::maybe_budget_freeze(peer, now, raise_period, max_probes);
                }
            }
            _ => {}
        }
    }

    pub fn on_ack(
        &mut self,
        peer_addr: SocketAddr,
        size: usize,
        probe_id: u32,
        search_gen: u32,
        now: Instant,
    ) -> (bool, bool, PmtudEventCounts) {
        let mut events = PmtudEventCounts::default();
        if self.pinned.is_some() {
            return (false, false, events);
        }
        let raise_period = self.raise_period;
        let raise_step = self.raise_step;
        let epsilon = self.resolve_epsilon;
        let downgrade_batches = self.stable_downgrade_batches;
        let sz = Self::clamp_size(size);

        let resolved_peer_addr = if self.peers.contains_key(&peer_addr) {
            Some(peer_addr)
        } else {
            let mut candidate: Option<SocketAddr> = None;
            for (addr, state) in &self.peers {
                if addr.ip() != peer_addr.ip() {
                    continue;
                }
                let inflight_match = match &state.inflight {
                    Some(inf) => {
                        state.search_gen == search_gen
                            && inf.probe_id != 0
                            && inf.probe_id == probe_id
                            && inf.size == sz
                    }
                    None => false,
                };
                let grace_match = if state.inflight.is_none() {
                    match &state.grace {
                        Some(g) => {
                            g.probe_id == probe_id
                                && g.search_gen == search_gen
                                && g.size == sz
                                && now <= g.deadline
                        }
                        None => false,
                    }
                } else {
                    false
                };
                if !inflight_match && !grace_match {
                    continue;
                }
                if candidate.is_some() {
                    return (false, false, events);
                }
                candidate = Some(*addr);
            }
            candidate
        };
        let Some(resolved_peer_addr) = resolved_peer_addr else {
            return (false, false, events);
        };
        let Some(peer) = self.peers.get_mut(&resolved_peer_addr) else {
            return (false, false, events);
        };

        // Late-ACK grace match (Revalidate/Recheck).
        if peer.inflight.is_none() {
            if let Some(g) = peer.grace.clone() {
                if g.probe_id == probe_id
                    && g.search_gen == search_gen
                    && g.size == sz
                    && now <= g.deadline
                {
                    let was_recheck = peer.phase == Phase::Recheck;
                    peer.grace = None;
                    peer.ever_acked = true;
                    Self::enter_plateau(peer, now, raise_period, raise_step, downgrade_batches);
                    events.late_ack_events = 1;
                    if was_recheck {
                        events.recheck_recovered_events = 1;
                    }
                    self.recalc_min();
                    return (true, false, events);
                }
            }
            return (false, false, events);
        }

        if search_gen != peer.search_gen {
            return (false, false, events);
        }
        let Some(inf) = &peer.inflight else {
            return (false, false, events);
        };
        if inf.probe_id == 0 || inf.probe_id != probe_id {
            return (false, false, events);
        }
        if sz != inf.size {
            return (false, false, events);
        }
        peer.inflight = None;
        peer.grace = None;
        peer.ever_acked = true;
        let old_min = self.min_path_mtu;
        let phase = peer.phase;

        match phase {
            Phase::Raise => {
                peer.last_good = sz;
                if peer.last_good > peer.stable {
                    peer.stable = peer.last_good;
                    peer.consecutive_lower_campaigns = 0;
                }
                peer.step = peer.step.saturating_mul(2).max(raise_step);
                if Self::raise_target(peer).is_none() {
                    if peer.last_good >= MAX_MTU {
                        peer.first_bad = FIRST_BAD_SENTINEL;
                    }
                    Self::enter_plateau(peer, now, raise_period, raise_step, downgrade_batches);
                }
            }
            Phase::Binary => {
                peer.last_good = sz.max(peer.last_good);
                if peer.last_good > peer.stable {
                    peer.stable = peer.last_good;
                    peer.consecutive_lower_campaigns = 0;
                }
                if peer.window_closed(epsilon) {
                    Self::enter_plateau(peer, now, raise_period, raise_step, downgrade_batches);
                }
            }
            Phase::Revalidate => {
                Self::enter_plateau(peer, now, raise_period, raise_step, downgrade_batches);
            }
            Phase::Recheck => {
                Self::enter_plateau(peer, now, raise_period, raise_step, downgrade_batches);
                events.recheck_recovered_events = 1;
            }
            Phase::DownSearch => {
                peer.last_good = sz.max(peer.last_good);
                peer.downsearch_got_ack = true;
                if peer.window_closed(epsilon) {
                    Self::finish_downsearch_plateau(
                        peer,
                        now,
                        raise_period,
                        raise_step,
                        downgrade_batches,
                    );
                }
            }
            Phase::Plateau | Phase::Frozen => {}
        }

        self.recalc_min();
        (true, self.min_path_mtu != old_min, events)
    }

    /// Local EMSGSIZE / message-too-long: soft-down for Revalidate/Recheck (skip anomaly).
    pub fn on_send_hard_fail(
        &mut self,
        peer_addr: SocketAddr,
        probe_id: u32,
        now: Instant,
    ) -> PmtudEventCounts {
        let mut events = PmtudEventCounts::default();
        if self.pinned.is_some() {
            return events;
        }
        let Some(peer) = self.peers.get(&peer_addr) else {
            return events;
        };
        let Some(inf) = &peer.inflight else {
            return events;
        };
        if inf.probe_id != probe_id || inf.probe_id == 0 {
            return events;
        }
        let size = inf.size;
        let phase = peer.phase;

        match phase {
            Phase::Revalidate | Phase::Recheck => {
                if let Some(p) = self.peers.get_mut(&peer_addr) {
                    p.inflight = None;
                    p.grace = None;
                }
                if phase == Phase::Revalidate {
                    events.revalidate_fail_events = 1;
                }
                self.apply_soft_down(peer_addr, now, &mut events);
            }
            _ => {
                self.apply_timeout_confirmed_fail(peer_addr, size, now, &mut events);
            }
        }
        events
    }
}

impl Default for PathMtuDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> SocketAddr {
        "198.51.100.1:5000".parse().unwrap()
    }

    fn tick_one(p: &mut PathMtuDiscovery, now: Instant, ep: SocketAddr) -> Vec<ProbeIntent> {
        let (intents, _) = p.on_tick(
            now,
            &[PeerTickInput {
                addr: ep,
                health: SizeHealth::default(),
                rtt_ms: -1.0,
            }],
        );
        intents
    }

    fn tick_health(
        p: &mut PathMtuDiscovery,
        now: Instant,
        ep: SocketAddr,
        health: SizeHealth,
    ) -> (Vec<ProbeIntent>, PmtudEventCounts) {
        p.on_tick(
            now,
            &[PeerTickInput {
                addr: ep,
                health,
                rtt_ms: -1.0,
            }],
        )
    }

    fn advance_raise(p: &mut PathMtuDiscovery, now: Instant) {
        if let Some(st) = p.peers.get_mut(&peer()) {
            st.next_raise_at = now;
        }
    }

    fn force_revalidate(p: &mut PathMtuDiscovery, ep: SocketAddr, now: Instant, last_good: usize) {
        let st = p.peers.get_mut(&ep).unwrap();
        st.last_good = last_good;
        st.stable = last_good;
        st.first_bad = last_good + 1;
        st.phase = Phase::Plateau;
        st.next_raise_at = now;
        st.inflight = None;
        st.grace = None;
        p.recalc_min();
    }

    #[test]
    fn suggested_adapter_mtu_subtracts_underlay_and_enc() {
        let mut p = PathMtuDiscovery::new();
        p.min_path_mtu = 576;
        assert_eq!(p.suggested_adapter_mtu(56), 492);
        p.min_path_mtu = 1220;
        assert_eq!(
            p.suggested_adapter_mtu(crate::net::packet::MENC_WIRE_OVERHEAD),
            1169
        );
    }

    #[test]
    fn path_mtu_from_adapter_round_trips_suggestion() {
        let enc = crate::net::packet::MENC_WIRE_OVERHEAD;
        for adapter in [576usize, 1200, 1340, 1400] {
            let path = PathMtuDiscovery::path_mtu_from_adapter(adapter, enc);
            let mut p = PathMtuDiscovery::new();
            p.min_path_mtu = path;
            // Suggestion clamps to MIN_ADAPTER..=MAX; round-trip within that band.
            let suggested = p.suggested_adapter_mtu(enc);
            assert_eq!(
                PathMtuDiscovery::path_mtu_from_adapter(suggested, enc),
                path
            );
        }
        let path_plain = PathMtuDiscovery::path_mtu_from_adapter(1340, 0);
        assert_eq!(path_plain, 1340 + UNDERLAY_IPV4_UDP_OVERHEAD);
    }

    #[test]
    fn pin_freezes_tick_and_ignores_ack() {
        let mut p = PathMtuDiscovery::new();
        let ep = peer();
        let now = Instant::now();
        tick_one(&mut p, now, ep);
        let path = PathMtuDiscovery::path_mtu_from_adapter(1340, 0);
        p.set_pinned(Some(path));
        assert!(p.is_pinned());
        assert_eq!(p.min_mtu(), path);
        assert_eq!(p.peers.get(&ep).unwrap().phase, Phase::Frozen);
        assert_eq!(p.peers.get(&ep).unwrap().last_good, path);

        let (intents, _) = p.on_tick(
            now + Duration::from_secs(120),
            &[PeerTickInput {
                addr: ep,
                health: SizeHealth::default(),
                rtt_ms: 20.0,
            }],
        );
        assert!(intents.is_empty());
        assert!(!p.request_revalidate(ep, now + Duration::from_secs(120)));
        assert!(!p.request_early_wake(ep, now + Duration::from_secs(120)));

        let (ok, min_changed, _) = p.on_ack(ep, path + 32, 1, 1, now);
        assert!(!ok);
        assert!(!min_changed);
        assert_eq!(p.min_mtu(), path);
    }

    #[test]
    fn unpin_restores_discovery_floor() {
        let mut p = PathMtuDiscovery::new();
        let ep = peer();
        let now = Instant::now();
        tick_one(&mut p, now, ep);
        p.set_pinned(Some(1400));
        p.set_pinned(None);
        assert!(!p.is_pinned());
        assert_eq!(p.min_mtu(), DEFAULT_MTU);
        assert_eq!(p.peers.get(&ep).unwrap().last_good, DEFAULT_MTU);
        assert_eq!(p.peers.get(&ep).unwrap().phase, Phase::Plateau);
    }

    #[test]
    fn udp_payload_budget_peer_and_fallback() {
        let mut p = PathMtuDiscovery::new();
        let ep = peer();
        let now = Instant::now();
        tick_one(&mut p, now, ep);
        p.peers.get_mut(&ep).unwrap().last_good = 1400;
        p.recalc_min();
        assert_eq!(p.udp_payload_budget(ep), 1400 - UNDERLAY_IPV4_UDP_OVERHEAD);
        let unknown: SocketAddr = "198.51.100.9:9".parse().unwrap();
        assert_eq!(
            p.udp_payload_budget(unknown),
            p.min_mtu() - UNDERLAY_IPV4_UDP_OVERHEAD
        );
        assert_eq!(p.peer_last_good(ep), Some(1400));
        assert_eq!(p.peer_last_good(unknown), None);
    }

    #[test]
    fn request_revalidate_plateau_cooldown_and_active_noop() {
        let mut p = PathMtuDiscovery::new();
        let ep = peer();
        let now = Instant::now();
        tick_one(&mut p, now, ep);
        assert!(p.peers.get(&ep).unwrap().phase == Phase::Plateau);
        assert!(p.request_revalidate(ep, now));
        assert!(p.peers.get(&ep).unwrap().next_raise_at <= now);
        assert!(!p.request_revalidate(ep, now + Duration::from_secs(1)));
        assert!(p.request_revalidate(ep, now + Duration::from_secs(5)));

        p.peers.get_mut(&ep).unwrap().phase = Phase::Raise;
        assert!(!p.request_revalidate(ep, now + Duration::from_secs(20)));
        p.peers.get_mut(&ep).unwrap().phase = Phase::Binary;
        assert!(!p.request_revalidate(ep, now + Duration::from_secs(30)));

        p.peers.get_mut(&ep).unwrap().phase = Phase::Frozen;
        p.peers.get_mut(&ep).unwrap().next_raise_at = now + Duration::from_secs(60);
        p.peers.get_mut(&ep).unwrap().last_revalidate_hint_at = None;
        assert!(p.request_revalidate(ep, now + Duration::from_secs(40)));
        assert!(p.peers.get(&ep).unwrap().next_raise_at <= now + Duration::from_secs(40));

        let unknown: SocketAddr = "198.51.100.9:9".parse().unwrap();
        assert!(!p.request_revalidate(unknown, now));
    }

    #[test]
    fn binary_converges_to_planted_ceiling() {
        let mut p = PathMtuDiscovery::new();
        p.confirm_count = 1;
        p.resolve_epsilon = 1;
        let ep = peer();
        let mut now = Instant::now();
        tick_one(&mut p, now, ep);
        advance_raise(&mut p, now);

        let ceiling = 1377usize;
        for _ in 0..80 {
            now += Duration::from_millis(10);
            let intents = tick_one(&mut p, now, ep);
            if intents.is_empty() {
                let st = p.peers.get(&ep).unwrap();
                if st.phase == Phase::Plateau && st.window_closed(1) {
                    break;
                }
                advance_raise(&mut p, now);
                continue;
            }
            for intent in intents {
                if intent.size <= ceiling {
                    let (ok, _, _) = p.on_ack(
                        intent.peer,
                        intent.size,
                        intent.probe_id,
                        intent.search_gen,
                        now,
                    );
                    assert!(ok);
                } else {
                    p.on_send_hard_fail(intent.peer, intent.probe_id, now);
                }
            }
        }
        let st = p.peers.get(&ep).unwrap();
        assert_eq!(st.last_good, ceiling);
        assert!(st.first_bad <= ceiling + 1);
        assert_eq!(p.min_mtu(), ceiling);
    }

    #[test]
    fn loss_then_ack_does_not_mark_fail() {
        let mut p = PathMtuDiscovery::new();
        p.confirm_count = 3;
        let ep = peer();
        let now = Instant::now();
        p.ensure_peer(ep, now);
        advance_raise(&mut p, now);
        let intents = tick_one(&mut p, now, ep);
        assert_eq!(intents.len(), 1);
        let first_size = intents[0].size;
        let later = now + p.probe_timeout + Duration::from_millis(1);
        let intents = tick_one(&mut p, later, ep);
        assert_eq!(intents.len(), 1, "expect retransmit after one timeout");
        assert_eq!(intents[0].size, first_size);
        let intent = intents[0];
        let (ok, _, _) = p.on_ack(
            intent.peer,
            intent.size,
            intent.probe_id,
            intent.search_gen,
            later,
        );
        assert!(ok);
        assert_eq!(p.peers.get(&ep).unwrap().last_good, intent.size);
        assert!(p.peers.get(&ep).unwrap().first_bad > first_size);
    }

    #[test]
    fn three_timeouts_mark_fail() {
        let mut p = PathMtuDiscovery::new();
        p.confirm_count = 3;
        let ep = peer();
        let mut now = Instant::now();
        p.ensure_peer(ep, now);
        advance_raise(&mut p, now);
        let intents = tick_one(&mut p, now, ep);
        let size = intents[0].size;
        for _ in 0..3 {
            now += p.probe_timeout + Duration::from_millis(1);
            let _ = tick_one(&mut p, now, ep);
        }
        let st = p.peers.get(&ep).unwrap();
        assert_eq!(st.first_bad, size);
        assert!(matches!(st.phase, Phase::Binary));
    }

    #[test]
    fn late_probe_id_and_gen_ignored() {
        let mut p = PathMtuDiscovery::new();
        let ep = peer();
        let now = Instant::now();
        p.ensure_peer(ep, now);
        advance_raise(&mut p, now);
        let intents = tick_one(&mut p, now, ep);
        let intent = intents[0];
        let (ok, _, _) = p.on_ack(
            ep,
            intent.size,
            intent.probe_id.wrapping_add(1),
            intent.search_gen,
            now,
        );
        assert!(!ok);
        let (ok, _, _) = p.on_ack(
            ep,
            intent.size,
            intent.probe_id,
            intent.search_gen.wrapping_add(1),
            now,
        );
        assert!(!ok);
        let st = p.peers.get(&ep).unwrap();
        assert_eq!(st.last_good, DEFAULT_MTU);
    }

    #[test]
    fn budget_exceeded_enters_frozen() {
        let mut p = PathMtuDiscovery::new();
        p.max_probes_per_search = 3;
        p.confirm_count = 1;
        p.resolve_epsilon = 1;
        let ep = peer();
        let mut now = Instant::now();
        p.ensure_peer(ep, now);
        advance_raise(&mut p, now);
        for _ in 0..10 {
            now += Duration::from_millis(1);
            let intents = tick_one(&mut p, now, ep);
            for intent in intents {
                p.on_send_hard_fail(intent.peer, intent.probe_id, now);
            }
            let st = p.peers.get(&ep).unwrap();
            if st.phase == Phase::Frozen {
                assert_eq!(st.last_good, DEFAULT_MTU);
                return;
            }
        }
        panic!("expected Frozen");
    }

    #[test]
    fn hard_fail_skips_confirms() {
        let mut p = PathMtuDiscovery::new();
        p.confirm_count = 3;
        let ep = peer();
        let now = Instant::now();
        p.ensure_peer(ep, now);
        advance_raise(&mut p, now);
        let intents = tick_one(&mut p, now, ep);
        let intent = intents[0];
        p.on_send_hard_fail(intent.peer, intent.probe_id, now);
        let st = p.peers.get(&ep).unwrap();
        assert_eq!(st.first_bad, intent.size);
        assert!(matches!(st.phase, Phase::Binary));
        assert!(st.inflight.is_none());
    }

    #[test]
    fn min_mtu_never_equals_inflight_size() {
        let mut p = PathMtuDiscovery::new();
        let ep = peer();
        let now = Instant::now();
        p.ensure_peer(ep, now);
        advance_raise(&mut p, now);
        let intents = tick_one(&mut p, now, ep);
        let probe_sz = intents[0].size;
        assert_ne!(p.min_mtu(), probe_sz);
        assert_eq!(p.min_mtu(), DEFAULT_MTU);
    }

    #[test]
    fn revalidate_timeout_large_alive_anomaly_keeps_last_good() {
        let mut p = PathMtuDiscovery::new();
        p.confirm_count = 1;
        let ep = peer();
        let mut now = Instant::now();
        p.ensure_peer(ep, now);
        force_revalidate(&mut p, ep, now, 1400);
        let intents = tick_one(&mut p, now, ep);
        assert_eq!(intents.len(), 1);
        assert!(matches!(p.peers.get(&ep).unwrap().phase, Phase::Revalidate));

        now += p.probe_timeout + Duration::from_millis(1);
        let health = SizeHealth {
            warm: true,
            large_alive: true,
            large_collapsed: false,
        };
        let (_, ev) = tick_health(&mut p, now, ep, health);
        // Grace arm
        assert!(p.peers.get(&ep).unwrap().grace.is_some());
        now += p.probe_timeout + Duration::from_millis(1);
        let (_, ev2) = tick_health(&mut p, now, ep, health);
        assert!(ev.probe_timeouts + ev2.probe_timeouts >= 1);
        assert!(ev2.probe_anomaly_events >= 1 || ev.probe_anomaly_events >= 1);
        let st = p.peers.get(&ep).unwrap();
        assert_eq!(st.last_good, 1400);
        assert!(matches!(st.phase, Phase::Plateau));
    }

    #[test]
    fn revalidate_timeout_enters_recheck_then_softdown() {
        let mut p = PathMtuDiscovery::new();
        p.confirm_count = 1;
        let ep = peer();
        let mut now = Instant::now();
        p.ensure_peer(ep, now);
        force_revalidate(&mut p, ep, now, 1400);
        let _ = tick_one(&mut p, now, ep);
        now += p.probe_timeout + Duration::from_millis(1);
        let _ = tick_one(&mut p, now, ep); // arm grace
        now += p.probe_timeout + Duration::from_millis(1);
        let (intents, _) = tick_health(&mut p, now, ep, SizeHealth::default()); // expire → Recheck (+ maybe probe)
        assert!(matches!(p.peers.get(&ep).unwrap().phase, Phase::Recheck));

        let intents = if intents.is_empty() {
            now += Duration::from_millis(1);
            tick_one(&mut p, now, ep)
        } else {
            intents
        };
        assert!(!intents.is_empty());
        now += p.probe_timeout + Duration::from_millis(1);
        let _ = tick_one(&mut p, now, ep); // grace
        now += p.probe_timeout + Duration::from_millis(1);
        let (_, ev) = tick_health(&mut p, now, ep, SizeHealth::default());
        let st = p.peers.get(&ep).unwrap();
        assert!(matches!(st.phase, Phase::DownSearch));
        assert_eq!(st.last_good, 700); // 1400/2
        assert!(ev.softdown_events >= 1);
    }

    #[test]
    fn soft_down_zero_ack_opens_raise() {
        let mut p = PathMtuDiscovery::new();
        p.confirm_count = 1;
        p.resolve_epsilon = 1;
        let ep = peer();
        let mut now = Instant::now();
        p.ensure_peer(ep, now);
        {
            let st = p.peers.get_mut(&ep).unwrap();
            st.last_good = 700;
            st.stable = 1400;
            st.first_bad = 1400;
            st.phase = Phase::DownSearch;
            st.down_from_stable = Some(1400);
            st.downsearch_got_ack = false;
            st.inflight = None;
        }
        p.recalc_min();
        // Fail all probes until window closes.
        for _ in 0..40 {
            now += Duration::from_millis(1);
            let intents = tick_one(&mut p, now, ep);
            for intent in intents {
                p.on_send_hard_fail(intent.peer, intent.probe_id, now);
            }
            if p.peers.get(&ep).unwrap().phase == Phase::Plateau {
                break;
            }
        }
        let st = p.peers.get(&ep).unwrap();
        assert_eq!(st.phase, Phase::Plateau);
        assert_eq!(st.first_bad, FIRST_BAD_SENTINEL);
        assert!(PathMtuDiscovery::raise_target(st).is_some());
    }

    #[test]
    fn hard_fail_revalidate_softdown_skips_recheck() {
        let mut p = PathMtuDiscovery::new();
        p.confirm_count = 3;
        let ep = peer();
        let now = Instant::now();
        p.ensure_peer(ep, now);
        force_revalidate(&mut p, ep, now, 1400);
        let intents = tick_one(&mut p, now, ep);
        let intent = intents[0];
        let ev = p.on_send_hard_fail(intent.peer, intent.probe_id, now);
        assert!(ev.softdown_events >= 1);
        let st = p.peers.get(&ep).unwrap();
        assert!(matches!(st.phase, Phase::DownSearch));
        assert_eq!(st.last_good, 700);
        assert!(!matches!(st.phase, Phase::Recheck));
    }

    #[test]
    fn late_ack_grace_recovers_revalidate() {
        let mut p = PathMtuDiscovery::new();
        p.confirm_count = 1;
        let ep = peer();
        let mut now = Instant::now();
        p.ensure_peer(ep, now);
        force_revalidate(&mut p, ep, now, 1400);
        let intents = tick_one(&mut p, now, ep);
        let intent = intents[0];
        now += p.probe_timeout + Duration::from_millis(1);
        let _ = tick_one(&mut p, now, ep);
        assert!(p.peers.get(&ep).unwrap().grace.is_some());
        let (ok, _, ev) = p.on_ack(
            intent.peer,
            intent.size,
            intent.probe_id,
            intent.search_gen,
            now,
        );
        assert!(ok);
        assert_eq!(ev.late_ack_events, 1);
        assert_eq!(p.peers.get(&ep).unwrap().last_good, 1400);
        assert!(matches!(p.peers.get(&ep).unwrap().phase, Phase::Plateau));
    }

    #[test]
    fn adaptive_timeout_clamps() {
        let mut p = PathMtuDiscovery::new();
        p.probe_timeout = Duration::from_millis(1000);
        let ep = peer();
        let now = Instant::now();
        p.ensure_peer(ep, now);
        p.peers.get_mut(&ep).unwrap().rtt_ms = 50.0;
        assert_eq!(
            p.timeout_for_peer(p.peers.get(&ep).unwrap()),
            Duration::from_millis(1000)
        );
        p.peers.get_mut(&ep).unwrap().rtt_ms = 400.0;
        assert_eq!(
            p.timeout_for_peer(p.peers.get(&ep).unwrap()),
            Duration::from_millis(1600)
        );
        p.peers.get_mut(&ep).unwrap().rtt_ms = 2000.0;
        assert_eq!(
            p.timeout_for_peer(p.peers.get(&ep).unwrap()),
            Duration::from_millis(5000)
        );
    }

    #[test]
    fn progressive_halving_second_softdown() {
        let mut p = PathMtuDiscovery::new();
        let ep = peer();
        let now = Instant::now();
        p.ensure_peer(ep, now);
        {
            let st = p.peers.get_mut(&ep).unwrap();
            st.last_good = 700;
            st.stable = 1400;
            st.first_bad = 1400;
            st.phase = Phase::Recheck;
        }
        let mut ev = PmtudEventCounts::default();
        p.apply_soft_down(ep, now, &mut ev);
        assert_eq!(p.peers.get(&ep).unwrap().last_good, 350.max(MIN_MTU));
        // 700/2 = 350 → clamp MIN 576
        assert_eq!(p.peers.get(&ep).unwrap().last_good, 576);
    }

    #[test]
    fn downgrade_after_failed_revalidate_campaigns() {
        let mut p = PathMtuDiscovery::new();
        p.confirm_count = 1;
        p.stable_downgrade_batches = 3;
        p.resolve_epsilon = 1;
        let ep = peer();
        let mut now = Instant::now();
        p.ensure_peer(ep, now);
        force_revalidate(&mut p, ep, now, 1400);

        for campaign in 0..3 {
            {
                let st = p.peers.get_mut(&ep).unwrap();
                st.phase = Phase::Plateau;
                if campaign == 0 {
                    st.last_good = 1400;
                    st.stable = 1400;
                    st.first_bad = 1401;
                } else {
                    // After soft-down + downsearch with ACKs, last_good may be lower.
                    st.first_bad = st.last_good + 1;
                    if st.last_good >= st.stable {
                        st.stable = st.last_good;
                    }
                }
                st.next_raise_at = now;
                st.inflight = None;
                st.grace = None;
            }
            p.recalc_min();
            let mut intents = tick_one(&mut p, now, ep);
            if intents.is_empty() {
                now += Duration::from_millis(1);
                intents = tick_one(&mut p, now, ep);
            }
            assert!(!intents.is_empty(), "campaign {campaign} expected probe");
            let intent = intents[0];
            // hard_fail on revalidate → soft-down
            p.on_send_hard_fail(intent.peer, intent.probe_id, now);
            assert!(matches!(p.peers.get(&ep).unwrap().phase, Phase::DownSearch));
            let lower = 1280usize;
            for _ in 0..40 {
                now += Duration::from_millis(1);
                let intents = tick_one(&mut p, now, ep);
                for intent in intents {
                    if intent.size <= lower {
                        let _ = p.on_ack(
                            intent.peer,
                            intent.size,
                            intent.probe_id,
                            intent.search_gen,
                            now,
                        );
                    } else {
                        p.on_send_hard_fail(intent.peer, intent.probe_id, now);
                    }
                }
                if p.peers.get(&ep).unwrap().phase == Phase::Plateau {
                    break;
                }
            }
            assert_eq!(p.peers.get(&ep).unwrap().phase, Phase::Plateau);
        }
        let st = p.peers.get(&ep).unwrap();
        assert_eq!(st.stable, st.last_good);
        assert!(st.stable <= 1280);
    }

    #[test]
    fn remove_peer_recalcs_min() {
        let mut p = PathMtuDiscovery::new();
        let a: SocketAddr = "198.51.100.1:1".parse().unwrap();
        let b: SocketAddr = "198.51.100.2:2".parse().unwrap();
        let now = Instant::now();
        p.ensure_peer(a, now);
        p.ensure_peer(b, now);
        p.peers.get_mut(&a).unwrap().last_good = 1300;
        p.peers.get_mut(&b).unwrap().last_good = 1400;
        p.recalc_min();
        assert_eq!(p.min_mtu(), 1300);
        p.remove_peer(a);
        assert_eq!(p.min_mtu(), 1400);
    }

    #[test]
    fn snapshot_lists_peers() {
        let mut p = PathMtuDiscovery::new();
        let ep = peer();
        let now = Instant::now();
        tick_one(&mut p, now, ep);
        let snap = p.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].endpoint, ep);
        assert_eq!(snap[0].phase, "plateau");
    }

    fn private_peer() -> SocketAddr {
        "192.168.0.100:7878".parse().unwrap()
    }

    fn same_ip_peer(port: u16) -> SocketAddr {
        format!("198.51.100.1:{port}").parse().unwrap()
    }

    #[test]
    fn is_rfc1918_private_ip_predicate() {
        assert!(is_rfc1918_private_ip("192.168.1.1".parse().unwrap()));
        assert!(is_rfc1918_private_ip("10.0.0.1".parse().unwrap()));
        assert!(is_rfc1918_private_ip("172.16.0.1".parse().unwrap()));
        assert!(!is_rfc1918_private_ip("198.51.100.1".parse().unwrap()));
        assert!(!is_rfc1918_private_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_rfc1918_private_ip("169.254.1.1".parse().unwrap()));
    }

    #[test]
    fn never_acked_private_softdown_floors_at_default_mtu() {
        let mut p = PathMtuDiscovery::new();
        let ep = private_peer();
        let now = Instant::now();
        p.ensure_peer(ep, now);
        {
            let st = p.peers.get_mut(&ep).unwrap();
            st.last_good = DEFAULT_MTU;
            st.stable = DEFAULT_MTU;
            assert!(!st.ever_acked);
        }
        let mut ev = PmtudEventCounts::default();
        p.apply_soft_down(ep, now, &mut ev);
        assert_eq!(p.peers.get(&ep).unwrap().last_good, DEFAULT_MTU);
        assert_eq!(ev.softdown_events, 1);
    }

    #[test]
    fn public_softdown_still_reaches_min_mtu() {
        let mut p = PathMtuDiscovery::new();
        let ep = peer();
        let now = Instant::now();
        p.ensure_peer(ep, now);
        {
            let st = p.peers.get_mut(&ep).unwrap();
            st.last_good = 700;
            st.stable = 1400;
        }
        let mut ev = PmtudEventCounts::default();
        p.apply_soft_down(ep, now, &mut ev);
        assert_eq!(p.peers.get(&ep).unwrap().last_good, MIN_MTU);
    }

    #[test]
    fn ever_acked_private_softdown_can_go_below_default() {
        let mut p = PathMtuDiscovery::new();
        let ep = private_peer();
        let now = Instant::now();
        p.ensure_peer(ep, now);
        {
            let st = p.peers.get_mut(&ep).unwrap();
            st.ever_acked = true;
            st.last_good = 1400;
            st.stable = 1400;
        }
        let mut ev = PmtudEventCounts::default();
        p.apply_soft_down(ep, now, &mut ev);
        assert_eq!(p.peers.get(&ep).unwrap().last_good, 700);
    }

    #[test]
    fn on_ack_sets_ever_acked() {
        let mut p = PathMtuDiscovery::new();
        p.confirm_count = 1;
        let ep = private_peer();
        let now = Instant::now();
        p.ensure_peer(ep, now);
        {
            let st = p.peers.get_mut(&ep).unwrap();
            st.next_raise_at = now;
            st.first_bad = FIRST_BAD_SENTINEL;
        }
        let intents = tick_one(&mut p, now, ep);
        assert!(!intents.is_empty());
        let intent = intents[0];
        let (ok, _, _) = p.on_ack(
            intent.peer,
            intent.size,
            intent.probe_id,
            intent.search_gen,
            now,
        );
        assert!(ok);
        assert!(p.peers.get(&ep).unwrap().ever_acked);
    }

    #[test]
    fn never_acked_private_softdown_floor_then_raise_retries() {
        let mut p = PathMtuDiscovery::new();
        p.confirm_count = 1;
        let ep = private_peer();
        let now = Instant::now();
        p.ensure_peer(ep, now);
        {
            let st = p.peers.get_mut(&ep).unwrap();
            st.last_good = DEFAULT_MTU;
            st.stable = DEFAULT_MTU;
            st.first_bad = FIRST_BAD_SENTINEL;
        }
        let mut ev = PmtudEventCounts::default();
        p.apply_soft_down(ep, now, &mut ev);
        assert_eq!(p.peers.get(&ep).unwrap().last_good, DEFAULT_MTU);
        // Floor closes the window → finish_downsearch immediately (Raise reopen).
        let st = p.peers.get(&ep).unwrap();
        assert!(matches!(st.phase, Phase::Plateau));
        assert_eq!(st.first_bad, FIRST_BAD_SENTINEL);
        assert_eq!(st.consecutive_lower_campaigns, 0);

        {
            let st = p.peers.get_mut(&ep).unwrap();
            st.next_raise_at = now;
        }
        let intents = tick_one(&mut p, now, ep);
        assert!(!intents.is_empty());
        assert!(intents[0].size > DEFAULT_MTU);
    }

    #[test]
    fn heal_unacked_private_floor_restores_default() {
        let mut p = PathMtuDiscovery::new();
        let ep = private_peer();
        let now = Instant::now();
        p.ensure_peer(ep, now);
        {
            let st = p.peers.get_mut(&ep).unwrap();
            st.last_good = MIN_MTU;
            st.stable = MIN_MTU;
            st.first_bad = MIN_MTU + 1;
            st.phase = Phase::Plateau;
            st.ever_acked = false;
        }
        p.recalc_min();
        assert_eq!(p.min_mtu(), MIN_MTU);

        let _ = tick_one(&mut p, now, ep);
        let st = p.peers.get(&ep).unwrap();
        assert_eq!(st.last_good, DEFAULT_MTU);
        assert_eq!(st.stable, DEFAULT_MTU);
        assert_eq!(st.first_bad, FIRST_BAD_SENTINEL);
        assert!(matches!(
            st.phase,
            Phase::Raise | Phase::Plateau | Phase::Revalidate
        ));
        assert_eq!(p.min_mtu(), DEFAULT_MTU);
    }

    #[test]
    fn heal_morph_shaped_stuck_private_after_public_like_softdowns() {
        // Simulate endpoint that soft-downed to 576 before main-socket probes worked.
        let mut p = PathMtuDiscovery::new();
        let ep = private_peer();
        let now = Instant::now();
        p.ensure_peer(ep, now);
        {
            let st = p.peers.get_mut(&ep).unwrap();
            st.last_good = MIN_MTU;
            st.stable = 1400;
            st.first_bad = 1401;
            st.ever_acked = false;
            st.phase = Phase::DownSearch;
        }
        p.heal_unacked_private_floor(now);
        let st = p.peers.get(&ep).unwrap();
        assert_eq!(st.last_good, DEFAULT_MTU);
        assert_eq!(st.stable, DEFAULT_MTU);
        assert!(matches!(st.phase, Phase::Plateau));
        assert_eq!(st.next_raise_at, now);
    }

    #[test]
    fn on_ack_accepts_same_ip_different_port_with_unique_match() {
        let mut p = PathMtuDiscovery::new();
        p.confirm_count = 1;
        let ep = same_ip_peer(5000);
        let now = Instant::now();
        p.ensure_peer(ep, now);
        {
            let st = p.peers.get_mut(&ep).unwrap();
            st.next_raise_at = now;
            st.first_bad = FIRST_BAD_SENTINEL;
        }
        let intents = tick_one(&mut p, now, ep);
        assert!(!intents.is_empty());
        let intent = intents[0];
        let remapped: SocketAddr = "198.51.100.1:6000".parse().unwrap();
        let (ok, _, _) = p.on_ack(
            remapped,
            intent.size,
            intent.probe_id,
            intent.search_gen,
            now,
        );
        assert!(ok);
        assert!(p.peers.get(&ep).unwrap().ever_acked);
    }

    #[test]
    fn on_ack_same_ip_ambiguous_inflight_rejected() {
        let mut p = PathMtuDiscovery::new();
        p.confirm_count = 1;
        let ep_a = same_ip_peer(5000);
        let ep_b = same_ip_peer(5001);
        let now = Instant::now();
        p.ensure_peer(ep_a, now);
        p.ensure_peer(ep_b, now);
        {
            let st = p.peers.get_mut(&ep_a).unwrap();
            st.search_gen = 7;
            st.inflight = Some(Inflight {
                probe_id: 11,
                size: 1400,
                confirms_left: 1,
                deadline: now + Duration::from_secs(1),
            });
        }
        {
            let st = p.peers.get_mut(&ep_b).unwrap();
            st.search_gen = 7;
            st.inflight = Some(Inflight {
                probe_id: 11,
                size: 1400,
                confirms_left: 1,
                deadline: now + Duration::from_secs(1),
            });
        }
        let remapped: SocketAddr = "198.51.100.1:6500".parse().unwrap();
        let (ok, _, _) = p.on_ack(remapped, 1400, 11, 7, now);
        assert!(!ok);
        assert!(p.peers.get(&ep_a).unwrap().inflight.is_some());
        assert!(p.peers.get(&ep_b).unwrap().inflight.is_some());
    }

    #[test]
    fn on_ack_same_ip_wrong_probe_rejected() {
        let mut p = PathMtuDiscovery::new();
        p.confirm_count = 1;
        let ep = same_ip_peer(5002);
        let now = Instant::now();
        p.ensure_peer(ep, now);
        {
            let st = p.peers.get_mut(&ep).unwrap();
            st.search_gen = 9;
            st.inflight = Some(Inflight {
                probe_id: 21,
                size: 1300,
                confirms_left: 1,
                deadline: now + Duration::from_secs(1),
            });
        }
        let remapped: SocketAddr = "198.51.100.1:6600".parse().unwrap();
        let (ok, _, _) = p.on_ack(remapped, 1300, 22, 9, now);
        assert!(!ok);
        assert!(p.peers.get(&ep).unwrap().inflight.is_some());
    }
}
