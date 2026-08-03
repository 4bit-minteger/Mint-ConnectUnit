use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

const TOMBSTONE_TTL: Duration = Duration::from_secs(300);
const TOMBSTONE_MIN_RETENTION: Duration = Duration::from_secs(600);
const TOMBSTONE_PRUNE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RouteState {
    Candidate,
    Active,
    Degraded,
    Stale,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PathKind {
    Direct,
    OwnerRelay,
    IceSrflx,
}

#[derive(Clone, Debug, Default)]
pub struct NoteFailResult {
    pub vip: Option<String>,
    pub needs_heal: bool,
}

#[derive(Clone, Debug)]
pub struct PathCandidate {
    pub kind: PathKind,
    pub endpoint: SocketAddr,
    pub smoothed_rtt_ms: f64,
    pub loss_ewma: f64,
    pub bandwidth_ewma_kbps: f64,
    pub last_probed: Instant,
    pub active: bool,
    pub consecutive_failures: u8,
}

impl PathCandidate {
    pub fn new(kind: PathKind, endpoint: SocketAddr, active: bool) -> Self {
        Self {
            kind,
            endpoint,
            smoothed_rtt_ms: -1.0,
            loss_ewma: 0.0,
            bandwidth_ewma_kbps: 0.0,
            last_probed: Instant::now(),
            active,
            consecutive_failures: 0,
        }
    }

    pub fn score_core(&self) -> f64 {
        const RTT_CEILING_MS: f64 = 400.0;
        let rtt_norm = if self.smoothed_rtt_ms < 0.0 {
            0.5
        } else {
            (self.smoothed_rtt_ms / RTT_CEILING_MS).min(1.0)
        };
        let loss = self.loss_ewma.min(1.0);
        0.7 * (1.0 - rtt_norm) + 0.3 * (1.0 - loss)
    }

    pub fn score_advanced(&self) -> f64 {
        const BW_CEILING_KBPS: f64 = 50_000.0;
        let bw = if self.bandwidth_ewma_kbps > 0.0 {
            (self.bandwidth_ewma_kbps / BW_CEILING_KBPS).min(1.0)
        } else {
            0.3
        };
        0.4 * self.score_core() + 0.6 * bw
    }

    pub fn is_usable(&self) -> bool {
        self.active && self.consecutive_failures < 5
    }

    pub fn note_rtt(&mut self, rtt_ms: f64, ewma: &crate::advanced_tuning::RoutingEwmaTuning) {
        if self.smoothed_rtt_ms < 0.0 {
            self.smoothed_rtt_ms = rtt_ms;
        } else {
            self.smoothed_rtt_ms =
                ewma.rtt_ewma_old * self.smoothed_rtt_ms + ewma.rtt_ewma_new * rtt_ms;
        }
        self.loss_ewma =
            (self.loss_ewma * ewma.loss_ewma_decay - ewma.loss_ewma_success_delta).max(0.0);
        self.last_probed = Instant::now();
        self.consecutive_failures = 0;
        self.active = true;
    }

    pub fn note_failure(&mut self, ewma: &crate::advanced_tuning::RoutingEwmaTuning) {
        self.loss_ewma =
            (self.loss_ewma * ewma.loss_ewma_decay + ewma.loss_ewma_fail_bump).min(1.0);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
    }

    pub fn note_bandwidth(
        &mut self,
        bytes: u64,
        elapsed_ms: u64,
        ewma: &crate::advanced_tuning::RoutingEwmaTuning,
    ) {
        if elapsed_ms == 0 {
            return;
        }
        let kbps = (bytes as f64 * 8.0) / elapsed_ms as f64;
        if self.bandwidth_ewma_kbps <= 0.0 {
            self.bandwidth_ewma_kbps = kbps;
        } else {
            self.bandwidth_ewma_kbps =
                ewma.bw_ewma_old * self.bandwidth_ewma_kbps + ewma.bw_ewma_new * kbps;
        }
    }
}

const SWITCH_SCORE_GAP: f64 = 0.15;
const SWITCH_CONFIRMING_TIME: Duration = Duration::from_secs(3);
const FORCED_SWITCH_SCORE_GAP: f64 = 0.40;
const CRISIS_SCORE_THRESHOLD: f64 = 0.1;

#[derive(Clone, Debug)]
pub struct PathSet {
    pub paths: [Option<PathCandidate>; 3],
    pub active_idx: usize,
    pub last_secondary_probe: Instant,
    switch_candidate_idx: Option<usize>,
    switch_candidate_since: Option<Instant>,
}

fn path_score(p: &PathCandidate, advanced_scoring: bool) -> f64 {
    if advanced_scoring {
        p.score_advanced()
    } else {
        p.score_core()
    }
}

impl PathSet {
    pub fn new(direct_ep: SocketAddr) -> Self {
        let mut paths: [Option<PathCandidate>; 3] = [None, None, None];
        paths[0] = Some(PathCandidate::new(PathKind::Direct, direct_ep, true));
        Self {
            paths,
            active_idx: 0,
            last_secondary_probe: Instant::now(),
            switch_candidate_idx: None,
            switch_candidate_since: None,
        }
    }

    pub fn set_direct(&mut self, endpoint: SocketAddr) {
        if let Some(direct) = self.paths[0].as_mut() {
            direct.endpoint = endpoint;
        } else {
            self.paths[0] = Some(PathCandidate::new(PathKind::Direct, endpoint, true));
        }
    }

    pub fn set_relay(&mut self, endpoint: SocketAddr) {
        self.paths[1] = Some(PathCandidate::new(PathKind::OwnerRelay, endpoint, true));
    }

    pub fn set_srflx(&mut self, endpoint: SocketAddr) {
        self.paths[2] = Some(PathCandidate::new(PathKind::IceSrflx, endpoint, false));
    }

    pub fn best_path(&self, advanced_scoring: bool) -> Option<(usize, &PathCandidate)> {
        self.paths
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.as_ref().filter(|p| p.is_usable()).map(|p| (i, p)))
            .max_by(|(_, a), (_, b)| {
                let sa = if advanced_scoring {
                    a.score_advanced()
                } else {
                    a.score_core()
                };
                let sb = if advanced_scoring {
                    b.score_advanced()
                } else {
                    b.score_core()
                };
                sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    pub fn reselect_active(&mut self, advanced_scoring: bool) {
        let current_score = self
            .paths
            .get(self.active_idx)
            .and_then(|p| p.as_ref())
            .filter(|p| p.is_usable())
            .map(|p| path_score(p, advanced_scoring))
            .unwrap_or(0.0);

        let Some((best_idx, best_path)) = self.best_path(advanced_scoring) else {
            return;
        };

        if best_idx == self.active_idx {
            self.switch_candidate_idx = None;
            self.switch_candidate_since = None;
            return;
        }

        let best_score = path_score(best_path, advanced_scoring);
        let gap = best_score - current_score;

        if gap >= FORCED_SWITCH_SCORE_GAP || current_score < CRISIS_SCORE_THRESHOLD {
            self.active_idx = best_idx;
            self.switch_candidate_idx = None;
            self.switch_candidate_since = None;
            return;
        }

        if gap >= SWITCH_SCORE_GAP {
            match self.switch_candidate_idx {
                Some(idx) if idx == best_idx => {
                    let since = self.switch_candidate_since.unwrap_or_else(Instant::now);
                    if Instant::now().duration_since(since) >= SWITCH_CONFIRMING_TIME {
                        self.active_idx = best_idx;
                        self.switch_candidate_idx = None;
                        self.switch_candidate_since = None;
                    }
                }
                _ => {
                    self.switch_candidate_idx = Some(best_idx);
                    self.switch_candidate_since = Some(Instant::now());
                }
            }
        } else {
            self.switch_candidate_idx = None;
            self.switch_candidate_since = None;
        }
    }

    pub fn active_endpoint_kind(&self) -> Option<(SocketAddr, PathKind)> {
        let p = self.paths.get(self.active_idx)?.as_ref()?;
        Some((p.endpoint, p.kind))
    }

    /// Live control-race targets: unique endpoints with `consecutive_failures < 5`,
    /// active path first, capped at 3. Does not require `PathCandidate::active`
    /// (srflx may be inactive for data).
    pub fn control_race_endpoints(&self) -> Vec<SocketAddr> {
        let mut out = Vec::with_capacity(3);
        if let Some((active_ep, _)) = self.active_endpoint_kind() {
            if self
                .paths
                .iter()
                .flatten()
                .any(|p| p.endpoint == active_ep && p.consecutive_failures < 5)
            {
                out.push(active_ep);
            }
        }
        for p in self.paths.iter().flatten() {
            if out.len() >= 3 {
                break;
            }
            if p.consecutive_failures >= 5 {
                continue;
            }
            if !out.contains(&p.endpoint) {
                out.push(p.endpoint);
            }
        }
        out
    }

    pub fn note_rtt_for_endpoint(
        &mut self,
        ep: SocketAddr,
        rtt_ms: f64,
        ewma: &crate::advanced_tuning::RoutingEwmaTuning,
    ) {
        for p in self.paths.iter_mut().flatten() {
            if p.endpoint == ep {
                p.note_rtt(rtt_ms, ewma);
                return;
            }
        }
    }

    pub fn note_failure_for_endpoint(
        &mut self,
        ep: SocketAddr,
        ewma: &crate::advanced_tuning::RoutingEwmaTuning,
    ) {
        for p in self.paths.iter_mut().flatten() {
            if p.endpoint == ep {
                p.note_failure(ewma);
                return;
            }
        }
    }

    pub fn note_bandwidth_for_endpoint(
        &mut self,
        ep: SocketAddr,
        bytes: u64,
        elapsed_ms: u64,
        ewma: &crate::advanced_tuning::RoutingEwmaTuning,
    ) {
        for p in self.paths.iter_mut().flatten() {
            if p.endpoint == ep {
                p.note_bandwidth(bytes, elapsed_ms, ewma);
                return;
            }
        }
    }
}

#[derive(Clone, Copy)]
pub struct RelayPathSnapshot {
    pub state: RouteState,
    pub quality_score: i32,
    pub loss_ewma: f64,
    pub jitter_ms: f64,
    pub success_streak: i32,
    pub hold_down_until: Option<Instant>,
}

impl RelayPathSnapshot {
    fn from_entry(e: &RouteEntry) -> Self {
        Self {
            state: e.state,
            quality_score: e.quality_score,
            loss_ewma: e.loss_ewma,
            jitter_ms: e.jitter_ms,
            success_streak: e.success_streak,
            hold_down_until: e.hold_down_until,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RouteEntry {
    pub endpoint: SocketAddr,
    pub node_id: Arc<str>,
    pub state: RouteState,
    pub last_seen: Instant,
    pub smoothed_rtt_ms: f64,
    pub jitter_ms: f64,
    pub last_rtt_ms: i64,
    pub loss_ewma: f64,
    pub quality_score: i32,
    pub success_streak: i32,
    pub fail_streak: i32,
    pub hold_down_until: Option<Instant>,

    pub last_modified_revision: u64,
    pub path_set: Option<PathSet>,
    pub rx_bytes_since_last_bw_calc: u64,
    pub rx_bw_calc_at: Instant,
    pub dual_write_until: Option<Instant>,
    pub dual_write_old_ep: Option<SocketAddr>,
    pub dual_write_old_kind: Option<PathKind>,

    pub rtt_base_ms: f64,
    pub rtt_base_window_min: f64,
    pub rtt_base_window_start: Instant,
    pub rtt_base_stale_count: u8,
    pub queuing_delay_ms: f64,

    /// Windowed min forward one-way delay; `None` = cold (allows negative base under clock skew).
    pub owd_base_ms: Option<f64>,
    pub owd_base_window_min: f64,
    pub owd_base_window_start: Instant,
    pub owd_base_stale_count: u8,
    /// `max(0, owd_sample − owd_base)` when warm; meaningful only if `owd_base_ms.is_some()`.
    pub fwd_queuing_delay_ms: f64,
}

#[derive(Clone, Debug)]
pub struct RouteSyncRow {
    pub vip: Arc<str>,
    pub endpoint: SocketAddr,
    pub node_id: Arc<str>,
    pub state: RouteState,
    pub last_modified_revision: u64,
}

#[derive(Clone, Copy)]
pub struct RouteRetryRow {
    pub endpoint: SocketAddr,
    pub state: RouteState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelaySelection {
    Hop(SocketAddr),
    None,
}

pub struct RoutingTable {
    pub table: HashMap<String, RouteEntry>,
    pub ep_to_vip: HashMap<SocketAddr, String>,
    /// Secondary endpoints from multipath (relay / srflx), excluding primary `entry.endpoint`.
    pub path_ep_to_vip: HashMap<SocketAddr, String>,
    pub node_to_vip: HashMap<String, String>,
    pub vip_u32_to_vip: HashMap<u32, String>,
    pub revision: u64,

    pub tombstones: HashMap<String, (u64, Instant)>,
    last_tombstone_prune: Instant,

    /// Failover thresholds (defaults match the `failover` module consts).
    pub failover: crate::advanced_tuning::FailoverTuning,
    pub congestion: crate::advanced_tuning::CongestionTuning,
    pub routing_ewma: crate::advanced_tuning::RoutingEwmaTuning,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
            ep_to_vip: HashMap::new(),
            path_ep_to_vip: HashMap::new(),
            node_to_vip: HashMap::new(),
            vip_u32_to_vip: HashMap::new(),
            revision: 0,
            tombstones: HashMap::new(),
            last_tombstone_prune: Instant::now(),
            failover: crate::advanced_tuning::FailoverTuning::default(),
            congestion: crate::advanced_tuning::CongestionTuning::default(),
            routing_ewma: crate::advanced_tuning::RoutingEwmaTuning::default(),
        }
    }

    fn clear_path_ep_index_for_vip(&mut self, vip: &str) {
        self.path_ep_to_vip.retain(|_, v| v != vip);
    }

    pub fn rebuild_path_ep_index_for_vip(&mut self, vip: &str) {
        self.clear_path_ep_index_for_vip(vip);
        let Some(entry) = self.table.get(vip) else {
            return;
        };
        let primary = entry.endpoint;
        if let Some(ps) = entry.path_set.as_ref() {
            for p in ps.paths.iter().flatten() {
                if p.endpoint != primary {
                    self.path_ep_to_vip.insert(p.endpoint, vip.to_string());
                }
            }
        }
    }

    pub fn prune_tombstones(&mut self, retain_vips: &HashSet<String>) {
        let now = Instant::now();
        self.tombstones.retain(|vip, (_, created)| {
            if retain_vips.contains(vip) {
                return true;
            }
            let age = now.duration_since(*created);
            age < TOMBSTONE_MIN_RETENTION || age < TOMBSTONE_TTL
        });
        self.last_tombstone_prune = now;
    }

    pub fn update(&mut self, vip: &str, ep: SocketAddr, node_id: Option<&str>) {
        let now = Instant::now();
        if now.duration_since(self.last_tombstone_prune) >= TOMBSTONE_PRUNE_INTERVAL {
            self.prune_tombstones(&HashSet::new());
        }

        if let Some(prev_vip) = self.ep_to_vip.get(&ep).cloned() {
            if prev_vip != vip {
                let prev_node = self
                    .table
                    .get(&prev_vip)
                    .map(|entry| entry.node_id.as_ref())
                    .unwrap_or_default();
                let prev_state = self
                    .table
                    .get(&prev_vip)
                    .map(|entry| entry.state)
                    .unwrap_or(RouteState::Candidate);
                let incoming_node = node_id.unwrap_or_default();
                let conflicting_identity = !prev_node.is_empty()
                    && !incoming_node.is_empty()
                    && prev_node != incoming_node;
                let ambiguous_identity = !prev_node.is_empty() && incoming_node.is_empty();
                let allow_ambiguous_rebind = ambiguous_identity
                    && matches!(prev_state, RouteState::Stale | RouteState::Degraded);
                if conflicting_identity || (ambiguous_identity && !allow_ambiguous_rebind) {
                    eprintln!(
                        "  [ROUTE] rejected endpoint alias: ep={} prev_vip={} new_vip={} prev_node={} new_node={} prev_state={:?}",
                        ep, prev_vip, vip, prev_node, incoming_node, prev_state
                    );
                    return;
                }
                if allow_ambiguous_rebind {
                    eprintln!(
                        "  [ROUTE] allowing endpoint alias rebind on degraded/stale route: ep={} prev_vip={} new_vip={}",
                        ep, prev_vip, vip
                    );
                }
                if !incoming_node.is_empty() && prev_node == incoming_node {
                    self.remove(&prev_vip);
                } else if prev_node.is_empty() && !incoming_node.is_empty() {
                    // PrepareJoin placeholder owner route (no node_id) → identified owner VIP.
                    self.remove(&prev_vip);
                } else {
                    self.ep_to_vip.remove(&ep);
                }
            }
        }
        let old = self
            .table
            .get(vip)
            .map(|e| (e.endpoint, Arc::clone(&e.node_id), e.state));
        let quality_initial = self.routing_ewma.quality_initial;
        let entry = self.table.entry(vip.to_string()).or_insert(RouteEntry {
            endpoint: ep,
            node_id: Arc::<str>::from(""),
            state: RouteState::Candidate,
            last_seen: now,
            smoothed_rtt_ms: -1.0,
            jitter_ms: 0.0,
            last_rtt_ms: -1,
            loss_ewma: 0.0,
            quality_score: quality_initial,
            success_streak: 0,
            fail_streak: 0,
            hold_down_until: None,
            last_modified_revision: 0,
            path_set: Some(PathSet::new(ep)),
            rx_bytes_since_last_bw_calc: 0,
            rx_bw_calc_at: now,
            dual_write_until: None,
            dual_write_old_ep: None,
            dual_write_old_kind: None,
            rtt_base_ms: -1.0,
            rtt_base_window_min: f64::INFINITY,
            rtt_base_window_start: now,
            rtt_base_stale_count: 0,
            queuing_delay_ms: 0.0,
            owd_base_ms: None,
            owd_base_window_min: f64::INFINITY,
            owd_base_window_start: now,
            owd_base_stale_count: 0,
            fwd_queuing_delay_ms: 0.0,
        });
        let ep_changed = old
            .as_ref()
            .map(|(old_ep, _, _)| *old_ep != ep)
            .unwrap_or(true);
        let node_changed = node_id.is_some()
            && old
                .as_ref()
                .map(|(_, old_node, _)| old_node.as_ref() != node_id.unwrap_or_default())
                .unwrap_or(true);
        let is_new_entry = old.is_none();

        entry.endpoint = ep;
        if let Some(ps) = entry.path_set.as_mut() {
            ps.set_direct(ep);
        } else {
            entry.path_set = Some(PathSet::new(ep));
        }
        entry.last_seen = now;
        if let Some(node) = node_id {
            if entry.node_id.as_ref() != node {
                entry.node_id = Arc::<str>::from(node);
            }
        }
        let effective_node = if entry.node_id.is_empty() {
            None
        } else {
            Some(Arc::clone(&entry.node_id))
        };

        if let Some((old_endpoint, old_node_id, _)) = old {
            self.ep_to_vip.remove(&old_endpoint);
            if !old_node_id.is_empty() && effective_node.as_deref() != Some(old_node_id.as_ref()) {
                self.node_to_vip.remove(old_node_id.as_ref());
            }
        }
        self.ep_to_vip.insert(ep, vip.to_string());
        if let Some(node) = effective_node {
            self.node_to_vip.insert(node.to_string(), vip.to_string());
        }
        if let Some(u) = ipv4_to_u32(vip) {
            self.vip_u32_to_vip.insert(u, vip.to_string());
        }
        self.tombstones.remove(vip);
        if is_new_entry || ep_changed || node_changed {
            self.revision = self.revision.wrapping_add(1);
            if let Some(e) = self.table.get_mut(vip) {
                e.last_modified_revision = self.revision;
            }
        }
        self.rebuild_path_ep_index_for_vip(vip);
    }

    pub fn lookup(&self, vip: &str) -> Option<SocketAddr> {
        self.table.get(vip).map(|e| e.endpoint)
    }

    pub fn last_seen_for_vip(&self, vip: &str) -> Option<Instant> {
        self.table.get(vip).map(|e| e.last_seen)
    }

    pub fn tracks_endpoint(&self, addr: SocketAddr) -> bool {
        self.ep_to_vip.contains_key(&addr)
    }

    /// Drops remote routes whose VIP is not in `my_vip`'s subnet (e.g. peer-cache / join placeholders).
    pub fn drain_vips_outside_subnet(
        &mut self,
        my_vip: &str,
        prefix: u8,
    ) -> Vec<(String, SocketAddr, Arc<str>)> {
        let Ok(anchor) = my_vip.parse::<Ipv4Addr>() else {
            return Vec::new();
        };
        let victims: Vec<String> = self
            .table
            .keys()
            .filter(|vip| {
                vip.parse::<Ipv4Addr>()
                    .map(|ip| !same_subnet(anchor, ip, prefix))
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        let mut removed = Vec::with_capacity(victims.len());
        for vip in victims {
            let Some(entry) = self.table.get(&vip) else {
                continue;
            };
            let ep = entry.endpoint;
            let node_id = Arc::clone(&entry.node_id);
            self.remove(&vip);
            removed.push((vip, ep, node_id));
        }
        removed
    }

    pub fn lookup_by_vip_u32(&self, vip_u32: u32) -> Option<SocketAddr> {
        let vip = self.vip_u32_to_vip.get(&vip_u32)?;
        self.lookup(vip)
    }

    pub fn lookup_vip_by_u32(&self, vip_u32: u32) -> Option<String> {
        self.vip_u32_to_vip.get(&vip_u32).cloned()
    }

    pub fn relay_snapshot_by_u32(&self, vip_u32: u32) -> Option<RelayPathSnapshot> {
        let vip = self.vip_u32_to_vip.get(&vip_u32)?;
        let e = self.table.get(vip.as_str())?;
        Some(RelayPathSnapshot::from_entry(e))
    }

    pub fn lookup_ep_by_node(&self, node_id: &str) -> Option<SocketAddr> {
        let vip = self.node_to_vip.get(node_id)?;
        self.lookup(vip)
    }

    pub fn remove(&mut self, vip: &str) {
        self.clear_path_ep_index_for_vip(vip);
        if let Some(entry) = self.table.remove(vip) {
            if self
                .ep_to_vip
                .get(&entry.endpoint)
                .is_some_and(|mapped| mapped == vip)
            {
                self.ep_to_vip.remove(&entry.endpoint);
            }
            if !entry.node_id.is_empty() {
                self.node_to_vip.remove(entry.node_id.as_ref());
            }
        }
        if let Some(u) = ipv4_to_u32(vip) {
            self.vip_u32_to_vip.remove(&u);
        }
        self.revision = self.revision.wrapping_add(1);
        self.tombstones
            .insert(vip.to_string(), (self.revision, Instant::now()));
    }

    pub fn is_endpoint_stale(&self, ep: SocketAddr) -> bool {
        self.ep_to_vip
            .get(&ep)
            .and_then(|vip| self.table.get(vip))
            .is_some_and(|e| matches!(e.state, RouteState::Stale))
    }

    pub fn apply_last_seen_batch(&mut self, batch: HashMap<SocketAddr, Instant>) {
        for (ep, ts) in batch {
            if let Some(vip) = self.ep_to_vip.get(&ep).cloned() {
                if let Some(entry) = self.table.get_mut(&vip) {
                    entry.last_seen = ts;
                }
            }
        }
    }

    pub fn promote_stale_if_needed(&mut self, ep: SocketAddr) -> Option<String> {
        if !self.ep_to_vip.contains_key(&ep) {
            return None;
        }
        let vip = self.ep_to_vip.get(&ep)?.clone();
        let entry = self.table.get_mut(&vip)?;
        if matches!(entry.state, RouteState::Stale) {
            entry.last_seen = Instant::now();
            entry.state = RouteState::Candidate;
            return Some(vip);
        }
        None
    }

    pub fn touch_endpoint(&mut self, ep: SocketAddr) -> Option<String> {
        if !self.ep_to_vip.contains_key(&ep) {
            return None;
        }
        let now = Instant::now();
        if let Some(vip) = self.ep_to_vip.get(&ep).cloned() {
            if let Some(entry) = self.table.get_mut(&vip) {
                entry.last_seen = now;
            }
        }
        self.promote_stale_if_needed(ep)
    }

    pub fn all_endpoints_except(&self, exclude: SocketAddr) -> Vec<SocketAddr> {
        self.table
            .values()
            .filter(|e| e.endpoint != exclude)
            .map(|e| e.endpoint)
            .collect()
    }

    pub fn all_endpoints(&self) -> Vec<SocketAddr> {
        self.table.values().map(|e| e.endpoint).collect()
    }

    pub fn all_active_endpoints(&self) -> Vec<SocketAddr> {
        self.table
            .values()
            .filter(|e| matches!(e.state, RouteState::Active))
            .map(|e| e.endpoint)
            .collect()
    }

    pub fn endpoints_excluding_stale(&self) -> Vec<SocketAddr> {
        self.table
            .values()
            .filter(|e| !matches!(e.state, RouteState::Stale))
            .map(|e| e.endpoint)
            .collect()
    }

    pub fn push_endpoints_excluding_stale(&self, out: &mut Vec<SocketAddr>) {
        out.clear();
        out.extend(
            self.table
                .values()
                .filter(|e| !matches!(e.state, RouteState::Stale))
                .map(|e| e.endpoint),
        );
    }

    pub fn count_under_relay_path(&self, now: Instant) -> usize {
        self.table
            .values()
            .filter(|e| {
                should_relay(e, &self.failover) || !can_return_to_direct(e, now, &self.failover)
            })
            .count()
    }

    /// Returns `true` when VIP-level RTT / queuing delay was updated (active path
    /// or no `path_set`). Secondary-path samples only update `PathCandidate`.
    pub fn note_rtt(
        &mut self,
        from: SocketAddr,
        rtt_ms: i64,
        ignore_relay_ep: Option<SocketAddr>,
    ) -> bool {
        let Some(vip) = self.vip_for_data_endpoint(from, ignore_relay_ep) else {
            return false;
        };
        let Some(entry) = self.table.get_mut(&vip) else {
            return false;
        };
        let is_active_path = entry
            .path_set
            .as_ref()
            .and_then(|ps| ps.active_endpoint_kind())
            .map(|(ep, _)| ep == from)
            .unwrap_or(true);
        let now = Instant::now();
        let failover = self.failover;
        let congestion = self.congestion;
        let routing_ewma = self.routing_ewma;
        entry.last_seen = now;
        if is_active_path {
            if entry.smoothed_rtt_ms < 0.0 {
                entry.smoothed_rtt_ms = rtt_ms as f64;
                entry.jitter_ms = 0.0;
            }
            entry.last_rtt_ms = rtt_ms;
            apply_rtt_sample(entry, rtt_ms, &failover, &congestion, &routing_ewma, now);
        }
        if let Some(ps) = entry.path_set.as_mut() {
            ps.note_rtt_for_endpoint(from, rtt_ms as f64, &routing_ewma);
            ps.reselect_active(false);
        }
        is_active_path
    }

    /// Apply a forward OWD sample on the active path VIP (caller already gated on active path).
    /// Returns whether the sample was applied or rejected by the clock-jump guard.
    pub fn note_fwd_owd(
        &mut self,
        from: SocketAddr,
        owd_sample_ms: f64,
        ignore_relay_ep: Option<SocketAddr>,
    ) -> OwdSampleOutcome {
        let Some(vip) = self.vip_for_data_endpoint(from, ignore_relay_ep) else {
            return OwdSampleOutcome::Ignored;
        };
        let Some(entry) = self.table.get_mut(&vip) else {
            return OwdSampleOutcome::Ignored;
        };
        let is_active_path = entry
            .path_set
            .as_ref()
            .and_then(|ps| ps.active_endpoint_kind())
            .map(|(ep, _)| ep == from)
            .unwrap_or(true);
        if !is_active_path {
            return OwdSampleOutcome::Ignored;
        }
        let now = Instant::now();
        let congestion = self.congestion;
        update_owd_base_on_sample(entry, owd_sample_ms, now, &congestion)
    }

    /// Control-race destinations for a known endpoint (or `[ep]` if unmapped / no PathSet).
    pub fn control_race_endpoints_for_endpoint(
        &self,
        ep: SocketAddr,
        ignore_relay_ep: Option<SocketAddr>,
    ) -> Vec<SocketAddr> {
        let Some(vip) = self.vip_for_data_endpoint(ep, ignore_relay_ep) else {
            return vec![ep];
        };
        let Some(entry) = self.table.get(&vip) else {
            return vec![ep];
        };
        if let Some(ps) = entry.path_set.as_ref() {
            let raced = ps.control_race_endpoints();
            if !raced.is_empty() {
                return raced;
            }
        }
        vec![entry.endpoint]
    }

    pub fn note_fail(
        &mut self,
        from: SocketAddr,
        ignore_relay_ep: Option<SocketAddr>,
    ) -> NoteFailResult {
        let Some(vip) = self.vip_for_data_endpoint(from, ignore_relay_ep) else {
            return NoteFailResult::default();
        };
        if let Some(entry) = self.table.get_mut(&vip) {
            entry.fail_streak = (entry.fail_streak + 1).min(100);
            entry.success_streak = (entry.success_streak - 1).max(0);
            let ewma = self.routing_ewma;
            entry.loss_ewma =
                (entry.loss_ewma * ewma.loss_ewma_decay + ewma.loss_ewma_fail_bump).min(1.0);
            let loss_penalty = (entry.loss_ewma * ewma.quality_loss_scale)
                .min(ewma.quality_loss_penalty_cap) as i32;
            entry.quality_score = (entry.quality_score - loss_penalty).max(0);
            if entry.fail_streak >= 3 {
                entry.state = RouteState::Degraded;
            }
            if entry.fail_streak >= 6 {
                entry.state = RouteState::Stale;
            }
            if let Some(ps) = entry.path_set.as_mut() {
                ps.note_failure_for_endpoint(from, &ewma);
                ps.reselect_active(false);
            }
            let needs_heal = entry.fail_streak >= 3;
            return NoteFailResult {
                vip: Some(vip),
                needs_heal,
            };
        }
        NoteFailResult::default()
    }

    pub fn note_bytes_received(
        &mut self,
        from: SocketAddr,
        bytes: u64,
        advanced_scoring: bool,
        ignore_relay_ep: Option<SocketAddr>,
    ) {
        let Some(vip) = self.vip_for_data_endpoint(from, ignore_relay_ep) else {
            return;
        };
        self.note_bytes_received_for_vip(&vip, from, bytes, advanced_scoring);
    }

    /// RX attributed by destination VIP (e.g. unicast TUN inject); PathSet uses direct `endpoint`.
    pub fn note_bytes_received_for_vip_u32(
        &mut self,
        dst_vip_u32: u32,
        bytes: u64,
        advanced_scoring: bool,
    ) {
        let Some(vip) = self.lookup_vip_by_u32(dst_vip_u32) else {
            return;
        };
        let path_ep = self.table.get(&vip).map(|e| e.endpoint);
        let Some(path_ep) = path_ep else {
            return;
        };
        self.note_bytes_received_for_vip(&vip, path_ep, bytes, advanced_scoring);
    }

    fn note_bytes_received_for_vip(
        &mut self,
        vip: &str,
        path_ep: SocketAddr,
        bytes: u64,
        advanced_scoring: bool,
    ) {
        if let Some(entry) = self.table.get_mut(vip) {
            entry.rx_bytes_since_last_bw_calc =
                entry.rx_bytes_since_last_bw_calc.saturating_add(bytes);
            let elapsed_ms = entry.rx_bw_calc_at.elapsed().as_millis() as u64;
            if elapsed_ms >= 500 {
                let ewma = self.routing_ewma;
                if let Some(ps) = entry.path_set.as_mut() {
                    ps.note_bandwidth_for_endpoint(
                        path_ep,
                        entry.rx_bytes_since_last_bw_calc,
                        elapsed_ms,
                        &ewma,
                    );
                    ps.reselect_active(advanced_scoring);
                }
                entry.rx_bytes_since_last_bw_calc = 0;
                entry.rx_bw_calc_at = Instant::now();
            }
        }
    }

    pub fn note_bytes_received_batch<I>(
        &mut self,
        batch: I,
        advanced_scoring: bool,
        ignore_relay_ep: Option<SocketAddr>,
    ) where
        I: IntoIterator<Item = (SocketAddr, u64)>,
    {
        for (from, bytes) in batch {
            self.note_bytes_received(from, bytes, advanced_scoring, ignore_relay_ep);
        }
    }

    pub fn begin_transition(
        &mut self,
        vip: &str,
        old_ep: SocketAddr,
        old_kind: PathKind,
        window: Duration,
    ) {
        if let Some(entry) = self.table.get_mut(vip) {
            let now = Instant::now();
            let active = entry
                .dual_write_until
                .map(|until| now < until)
                .unwrap_or(false);
            if !active {
                entry.dual_write_until = Some(now + window);
                entry.dual_write_old_ep = Some(old_ep);
                entry.dual_write_old_kind = Some(old_kind);
            }
        }
    }

    pub fn transition_state(&self, vip: &str) -> Option<(SocketAddr, PathKind)> {
        let entry = self.table.get(vip)?;
        let until = entry.dual_write_until?;
        if Instant::now() >= until {
            return None;
        }
        Some((entry.dual_write_old_ep?, entry.dual_write_old_kind?))
    }

    pub fn end_transition(&mut self, vip: &str) {
        if let Some(entry) = self.table.get_mut(vip) {
            entry.dual_write_until = None;
            entry.dual_write_old_ep = None;
            entry.dual_write_old_kind = None;
        }
    }

    pub fn snapshot(&self) -> Vec<(String, RouteEntry)> {
        self.table
            .iter()
            .map(|(vip, e)| (vip.clone(), e.clone()))
            .collect()
    }

    pub fn snapshot_for_retry(&self) -> Vec<RouteRetryRow> {
        self.table
            .values()
            .map(|e| RouteRetryRow {
                endpoint: e.endpoint,
                state: e.state,
            })
            .collect()
    }

    pub fn sync_snapshot(&self) -> Vec<RouteSyncRow> {
        self.table
            .iter()
            .map(|(vip, e)| RouteSyncRow {
                vip: Arc::<str>::from(vip.as_str()),
                endpoint: e.endpoint,
                node_id: Arc::clone(&e.node_id),
                state: e.state,
                last_modified_revision: e.last_modified_revision,
            })
            .collect()
    }

    pub fn mark_stale_if_idle(&mut self, idle_threshold: Duration) {
        let now = Instant::now();
        for entry in self.table.values_mut() {
            if now.duration_since(entry.last_seen) > idle_threshold
                && entry.state != RouteState::Stale
            {
                entry.state = RouteState::Stale;
            }
        }
    }

    pub fn evict_old_stale(&mut self, stale_age: Duration) {
        let now = Instant::now();
        let to_remove: Vec<String> = self
            .table
            .iter()
            .filter(|(_, e)| {
                e.state == RouteState::Stale && now.duration_since(e.last_seen) > stale_age
            })
            .map(|(vip, _)| vip.clone())
            .collect();
        for vip in to_remove {
            self.remove(&vip);
        }
    }

    pub fn note_relay_fallback(&mut self, vip: &str) {
        if let Some(entry) = self.table.get_mut(vip) {
            let now = Instant::now();
            let hold_active = entry.hold_down_until.map_or(false, |t| t > now);
            if !hold_active {
                entry.hold_down_until =
                    Some(now + Duration::from_secs(self.failover.hold_down_secs));
            }
        }
    }

    /// Clears multipath relay slot (paths[1]) and rebuilds secondary endpoint index.
    pub fn clear_relay_path(&mut self, vip: &str) {
        if let Some(entry) = self.table.get_mut(vip) {
            if let Some(ps) = entry.path_set.as_mut() {
                ps.paths[1] = None;
                if ps.active_idx == 1 {
                    ps.active_idx = 0;
                }
                ps.switch_candidate_idx = None;
                ps.switch_candidate_since = None;
            }
        }
        self.rebuild_path_ep_index_for_vip(vip);
    }

    /// Stamps path_set slot 1 from a live relay hop selection.
    pub fn stamp_relay_hop(&mut self, dest_vip: &str, hop: SocketAddr) {
        let Some(entry) = self.table.get_mut(dest_vip) else {
            return;
        };
        if entry.path_set.is_none() {
            entry.path_set = Some(PathSet::new(entry.endpoint));
        }
        if let Some(ps) = entry.path_set.as_mut() {
            ps.set_relay(hop);
        }
        self.rebuild_path_ep_index_for_vip(dest_vip);
    }

    pub(crate) fn hop_usable(
        &self,
        ep: SocketAddr,
        dest_vip: Option<&str>,
        my_vip: &str,
        exclude: Option<SocketAddr>,
    ) -> bool {
        if exclude == Some(ep) {
            return false;
        }
        let Some(hop_vip) = self.ep_to_vip.get(&ep) else {
            return false;
        };
        if hop_vip == my_vip {
            return false;
        }
        if let Some(dest) = dest_vip {
            if hop_vip == dest {
                return false;
            }
            if self.table.get(dest).is_some_and(|e| e.endpoint == ep) {
                return false;
            }
        }
        let Some(entry) = self.table.get(hop_vip.as_str()) else {
            return false;
        };
        if entry.fail_streak >= 3 {
            return false;
        }
        !should_relay(entry, &self.failover)
    }

    fn sticky_relay_hop(&self, dest_vip: &str) -> Option<SocketAddr> {
        let entry = self.table.get(dest_vip)?;
        let ps = entry.path_set.as_ref()?;
        let relay = ps.paths[1].as_ref()?;
        Some(relay.endpoint)
    }

    fn best_usable_peer_hop(
        &self,
        dest_vip: Option<&str>,
        owner_vip: &str,
        my_vip: &str,
        exclude: Option<SocketAddr>,
    ) -> Option<SocketAddr> {
        let mut best: Option<(&str, SocketAddr, i32, f64)> = None;
        for (vip, entry) in &self.table {
            if vip == my_vip || vip == owner_vip {
                continue;
            }
            if dest_vip.is_some_and(|d| d == vip) {
                continue;
            }
            let ep = entry.endpoint;
            if !self.hop_usable(ep, dest_vip, my_vip, exclude) {
                continue;
            }
            let rtt_sort = if entry.smoothed_rtt_ms < 0.0 {
                f64::INFINITY
            } else {
                entry.smoothed_rtt_ms
            };
            let replace = match best {
                None => true,
                Some((best_vip, _, best_q, best_rtt)) => {
                    entry.quality_score > best_q
                        || (entry.quality_score == best_q
                            && (rtt_sort < best_rtt
                                || (rtt_sort == best_rtt && vip.as_str() < best_vip)))
                }
            };
            if replace {
                best = Some((vip.as_str(), ep, entry.quality_score, rtt_sort));
            }
        }
        best.map(|(_, ep, _, _)| ep)
    }

    pub fn select_relay_endpoint(
        &self,
        dest_vip: &str,
        owner_vip: &str,
        my_vip: &str,
        exclude: Option<SocketAddr>,
    ) -> RelaySelection {
        if !owner_vip.is_empty() {
            if let Some(owner_ep) = self.lookup(owner_vip) {
                if self.hop_usable(owner_ep, Some(dest_vip), my_vip, exclude) {
                    return RelaySelection::Hop(owner_ep);
                }
            }
        }
        if let Some(sticky) = self.sticky_relay_hop(dest_vip) {
            if self.hop_usable(sticky, Some(dest_vip), my_vip, exclude) {
                return RelaySelection::Hop(sticky);
            }
        }
        if let Some(peer_ep) = self.best_usable_peer_hop(Some(dest_vip), owner_vip, my_vip, exclude)
        {
            return RelaySelection::Hop(peer_ep);
        }
        RelaySelection::None
    }

    pub fn select_broadcast_relay_hop(
        &self,
        owner_vip: &str,
        my_vip: &str,
        exclude: Option<SocketAddr>,
    ) -> RelaySelection {
        if !owner_vip.is_empty() {
            if let Some(owner_ep) = self.lookup(owner_vip) {
                if self.hop_usable(owner_ep, None, my_vip, exclude) {
                    return RelaySelection::Hop(owner_ep);
                }
            }
        }
        if let Some(peer_ep) = self.best_usable_peer_hop(None, owner_vip, my_vip, exclude) {
            return RelaySelection::Hop(peer_ep);
        }
        RelaySelection::None
    }

    /// Resolve VIP for a data-plane endpoint (direct `ep_to_vip` or multipath path).
    pub fn vip_for_data_endpoint(
        &self,
        ep: SocketAddr,
        ignore_relay_ep: Option<SocketAddr>,
    ) -> Option<String> {
        if ignore_relay_ep == Some(ep) {
            return None;
        }
        self.ep_to_vip
            .get(&ep)
            .or_else(|| self.path_ep_to_vip.get(&ep))
            .cloned()
    }
}

pub mod failover {
    pub const D2R_QUALITY_MIN: i32 = 35;
    pub const D2R_LOSS_MAX: f64 = 0.12;
    pub const D2R_JITTER_MAX: f64 = 50.0;
    pub const R2D_QUALITY_MIN: i32 = 50;
    pub const R2D_SUCCESS_MIN: i32 = 3;
    pub const HOLD_DOWN_SECS: u64 = 2;
}

pub fn apply_rtt_sample(
    entry: &mut RouteEntry,
    rtt_ms: i64,
    fo: &crate::advanced_tuning::FailoverTuning,
    congestion: &crate::advanced_tuning::CongestionTuning,
    ewma: &crate::advanced_tuning::RoutingEwmaTuning,
    now: Instant,
) {
    let delta = (rtt_ms as f64 - entry.smoothed_rtt_ms).abs();
    entry.jitter_ms = ewma.jitter_ewma_old * entry.jitter_ms + ewma.jitter_ewma_new * delta;
    entry.smoothed_rtt_ms =
        ewma.rtt_ewma_old * entry.smoothed_rtt_ms + ewma.rtt_ewma_new * rtt_ms as f64;
    update_rtt_base_on_sample(entry, rtt_ms as f64, now, congestion);
    entry.loss_ewma =
        (entry.loss_ewma * ewma.loss_ewma_decay - ewma.loss_ewma_success_delta).max(0.0);
    let bounded = rtt_ms.clamp(0, ewma.rtt_score_clamp_ms) as i32;
    let jitter_penalty =
        (entry.jitter_ms / ewma.quality_jitter_div).min(ewma.quality_jitter_penalty_cap) as i32;
    let loss_penalty =
        (entry.loss_ewma * ewma.quality_loss_scale).min(ewma.quality_loss_penalty_cap) as i32;
    entry.quality_score = (100 - bounded / 5 - jitter_penalty - loss_penalty).max(0);
    entry.success_streak = (entry.success_streak + 1).min(100);
    entry.fail_streak = (entry.fail_streak - 1).max(0);
    if entry.success_streak >= 2 && entry.quality_score >= fo.d2r_quality_min {
        entry.state = RouteState::Active;
    } else if entry.quality_score < fo.d2r_quality_min {
        entry.state = RouteState::Degraded;
    }
    if entry.quality_score >= fo.r2d_quality_min && entry.success_streak >= fo.r2d_success_min * 2 {
        entry.hold_down_until = None;
    }
}

/// LEDBAT-style base RTT window (plan §1.4). No-op when `rtt_base_tracking` is false.
pub fn update_rtt_base_on_sample(
    entry: &mut RouteEntry,
    rtt_sample_ms: f64,
    now: Instant,
    cg: &crate::advanced_tuning::CongestionTuning,
) {
    if !cg.rtt_base_tracking {
        return;
    }
    if entry.rtt_base_ms < 0.0 {
        entry.rtt_base_ms = rtt_sample_ms;
        entry.rtt_base_window_min = rtt_sample_ms;
        entry.rtt_base_window_start = now;
        entry.queuing_delay_ms = (entry.smoothed_rtt_ms - entry.rtt_base_ms).max(0.0);
        return;
    }

    entry.rtt_base_window_min = entry.rtt_base_window_min.min(rtt_sample_ms);

    let window = Duration::from_secs(cg.base_rtt_window_secs);
    if now.duration_since(entry.rtt_base_window_start) >= window {
        let window_min = entry.rtt_base_window_min;
        if window_min < entry.rtt_base_ms {
            entry.rtt_base_ms = window_min;
            entry.rtt_base_stale_count = 0;
        } else if window_min > entry.rtt_base_ms {
            entry.rtt_base_stale_count = entry.rtt_base_stale_count.saturating_add(1);
            if entry.rtt_base_stale_count >= cg.base_rtt_stale_windows {
                entry.rtt_base_ms = window_min;
                entry.rtt_base_stale_count = 0;
            }
        } else {
            entry.rtt_base_stale_count = 0;
        }
        entry.rtt_base_window_min = f64::INFINITY;
        entry.rtt_base_window_start = now;
    }

    if entry.smoothed_rtt_ms >= 0.0 && entry.rtt_base_ms >= 0.0 {
        entry.queuing_delay_ms = (entry.smoothed_rtt_ms - entry.rtt_base_ms).max(0.0);
    }
}

/// Absolute clock-jump guard default for forward OWD samples (ms).
pub const DEFAULT_OWD_CLOCK_JUMP_REJECT_MS: u64 = 30_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwdSampleOutcome {
    Ignored,
    Applied,
    Rejected,
}

fn reset_owd_base_cold(entry: &mut RouteEntry, now: Instant) {
    entry.owd_base_ms = None;
    entry.owd_base_window_min = f64::INFINITY;
    entry.owd_base_window_start = now;
    entry.owd_base_stale_count = 0;
}

/// LEDBAT-style min forward-OWD window. No-op when `rtt_base_tracking` is false.
/// On clock jump (`|sample − base| > `cfg `owd_clock_jump_reject_ms`), invalidates base (cold).
pub fn update_owd_base_on_sample(
    entry: &mut RouteEntry,
    owd_sample_ms: f64,
    now: Instant,
    cg: &crate::advanced_tuning::CongestionTuning,
) -> OwdSampleOutcome {
    if !cg.rtt_base_tracking {
        return OwdSampleOutcome::Ignored;
    }
    let jump_ms = cg.owd_clock_jump_reject_ms as f64;
    if let Some(base) = entry.owd_base_ms {
        if (owd_sample_ms - base).abs() > jump_ms {
            reset_owd_base_cold(entry, now);
            return OwdSampleOutcome::Rejected;
        }
    }

    if entry.owd_base_ms.is_none() {
        entry.owd_base_ms = Some(owd_sample_ms);
        entry.owd_base_window_min = owd_sample_ms;
        entry.owd_base_window_start = now;
        entry.owd_base_stale_count = 0;
        entry.fwd_queuing_delay_ms = 0.0;
        return OwdSampleOutcome::Applied;
    }

    let mut base = entry.owd_base_ms.unwrap_or(owd_sample_ms);
    entry.owd_base_window_min = entry.owd_base_window_min.min(owd_sample_ms);

    let window = Duration::from_secs(cg.base_rtt_window_secs);
    if now.duration_since(entry.owd_base_window_start) >= window {
        let window_min = entry.owd_base_window_min;
        if window_min < base {
            entry.owd_base_ms = Some(window_min);
            base = window_min;
            entry.owd_base_stale_count = 0;
        } else if window_min > base {
            entry.owd_base_stale_count = entry.owd_base_stale_count.saturating_add(1);
            if entry.owd_base_stale_count >= cg.base_rtt_stale_windows {
                entry.owd_base_ms = Some(window_min);
                base = window_min;
                entry.owd_base_stale_count = 0;
            }
        } else {
            entry.owd_base_stale_count = 0;
        }
        entry.owd_base_window_min = f64::INFINITY;
        entry.owd_base_window_start = now;
    }

    entry.fwd_queuing_delay_ms = (owd_sample_ms - base).max(0.0);
    OwdSampleOutcome::Applied
}

/// QD for CC/FEC: forward OWD when warm, else RTT-QD, else cold (`-1`).
pub fn effective_queuing_delay_ms(entry: &RouteEntry) -> f64 {
    if entry.owd_base_ms.is_some() {
        entry.fwd_queuing_delay_ms
    } else if entry.rtt_base_ms >= 0.0 {
        entry.queuing_delay_ms
    } else {
        -1.0
    }
}

pub fn should_relay(entry: &RouteEntry, fo: &crate::advanced_tuning::FailoverTuning) -> bool {
    should_relay_snap(&RelayPathSnapshot::from_entry(entry), fo)
}

pub fn should_relay_snap(
    s: &RelayPathSnapshot,
    fo: &crate::advanced_tuning::FailoverTuning,
) -> bool {
    s.quality_score < fo.d2r_quality_min
        || s.state == RouteState::Degraded
        || s.state == RouteState::Stale
        || s.loss_ewma > fo.d2r_loss_max
        || s.jitter_ms > fo.d2r_jitter_max
}

pub fn can_return_to_direct(
    entry: &RouteEntry,
    now: Instant,
    fo: &crate::advanced_tuning::FailoverTuning,
) -> bool {
    can_return_to_direct_snap(&RelayPathSnapshot::from_entry(entry), now, fo)
}

pub fn can_return_to_direct_snap(
    s: &RelayPathSnapshot,
    now: Instant,
    fo: &crate::advanced_tuning::FailoverTuning,
) -> bool {
    s.quality_score >= fo.r2d_quality_min
        && s.success_streak >= fo.r2d_success_min
        && s.hold_down_until.map_or(true, |t| t <= now)
}

pub fn ipv4_to_u32(ip: &str) -> Option<u32> {
    let parsed: Ipv4Addr = ip.parse().ok()?;
    Some(u32::from(parsed))
}

pub fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, prefix: u8) -> bool {
    let p = prefix.min(32);
    if p == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - p);
    (u32::from(a) & mask) == (u32::from(b) & mask)
}

pub fn owner_vip_with_prefix(my_vip: &str, prefix: u8) -> String {
    let Ok(addr) = my_vip.parse::<Ipv4Addr>() else {
        return my_vip.to_string();
    };
    let p = prefix.clamp(1, 30);
    let mask = u32::MAX << (32 - p);
    let net = u32::from(addr) & mask;
    let host_mask = if p >= 32 {
        0u32
    } else {
        (1u32 << (32 - p)) - 1
    };
    let owner_u32 = net | (1u32 & host_mask);
    Ipv4Addr::from(owner_u32).to_string()
}

pub fn owner_vip(my_vip: &str) -> String {
    owner_vip_with_prefix(my_vip, 24)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_clears_endpoint_mappings() {
        let mut rt = RoutingTable::new();
        let ep: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        assert!(!rt.tracks_endpoint(ep));
        rt.update("10.0.0.2", ep, None);
        assert!(rt.tracks_endpoint(ep));
        assert!(rt.touch_endpoint(ep).is_none());
        rt.remove("10.0.0.2");
        assert!(!rt.tracks_endpoint(ep));
        assert!(rt.lookup("10.0.0.2").is_none());
        assert!(!rt
            .vip_u32_to_vip
            .contains_key(&u32::from(Ipv4Addr::new(10, 0, 0, 2))));
    }

    #[test]
    fn touch_endpoint_returns_vip_when_recovering_from_stale() {
        let mut rt = RoutingTable::new();
        let ep: SocketAddr = "198.51.100.1:5000".parse().unwrap();
        rt.update("10.0.0.5", ep, None);
        rt.table.get_mut("10.0.0.5").unwrap().state = RouteState::Stale;
        assert_eq!(rt.touch_endpoint(ep), Some("10.0.0.5".to_string()));
        assert_eq!(
            rt.table.get("10.0.0.5").unwrap().state,
            RouteState::Candidate
        );
        assert!(rt.touch_endpoint(ep).is_none());
    }

    #[test]
    fn prune_tombstones_retains_pending_vip() {
        let mut rt = RoutingTable::new();
        // Age is irrelevant: retain_vips short-circuits before TTL checks.
        // Do not use Instant::now() - large Duration (overflow on short uptime).
        rt.tombstones
            .insert("10.0.0.9".to_string(), (1, Instant::now()));
        let mut retain = HashSet::new();
        retain.insert("10.0.0.9".to_string());
        rt.prune_tombstones(&retain);
        assert!(rt.tombstones.contains_key("10.0.0.9"));
    }

    #[test]
    fn apply_last_seen_batch_updates_without_promotion() {
        let mut rt = RoutingTable::new();
        let ep: SocketAddr = "198.51.100.2:5000".parse().unwrap();
        rt.update("10.0.0.6", ep, None);
        let before = rt.table.get("10.0.0.6").unwrap().last_seen;
        std::thread::sleep(std::time::Duration::from_millis(5));
        let ts = Instant::now();
        let mut batch = HashMap::new();
        batch.insert(ep, ts);
        rt.apply_last_seen_batch(batch);
        let after = rt.table.get("10.0.0.6").unwrap().last_seen;
        assert!(after > before);
        assert_eq!(
            rt.table.get("10.0.0.6").unwrap().state,
            RouteState::Candidate
        );
    }

    #[test]
    fn note_fail_penalizes_quality_score() {
        let mut rt = RoutingTable::new();
        let ep: SocketAddr = "127.0.0.1:10001".parse().unwrap();
        rt.update("10.0.0.3", ep, None);
        let before = rt.table.get("10.0.0.3").unwrap().quality_score;
        let _ = rt.note_fail(ep, None);
        let after = rt.table.get("10.0.0.3").unwrap().quality_score;
        assert!(after < before);
    }

    #[test]
    fn note_fail_needs_heal_after_three_failures() {
        let mut rt = RoutingTable::new();
        let ep: SocketAddr = "127.0.0.1:10002".parse().unwrap();
        rt.update("10.0.0.4", ep, None);
        assert!(!rt.note_fail(ep, None).needs_heal);
        assert!(!rt.note_fail(ep, None).needs_heal);
        let r = rt.note_fail(ep, None);
        assert!(r.needs_heal);
        assert_eq!(r.vip.as_deref(), Some("10.0.0.4"));
    }

    #[test]
    fn note_bytes_received_batch_ignores_untracked_endpoints() {
        let mut rt = RoutingTable::new();
        let ep: SocketAddr = "127.0.0.1:10001".parse().unwrap();
        let unknown: SocketAddr = "127.0.0.1:10002".parse().unwrap();
        rt.update("10.0.0.3", ep, None);
        rt.note_bytes_received_batch([(ep, 1500), (unknown, 9999)], false, None);
        assert_eq!(
            rt.table
                .get("10.0.0.3")
                .unwrap()
                .rx_bytes_since_last_bw_calc,
            1500
        );
    }

    #[test]
    fn same_subnet_respects_prefix() {
        let a = Ipv4Addr::new(10, 1, 0, 5);
        let b = Ipv4Addr::new(10, 1, 3, 9);
        assert!(same_subnet(a, b, 22));
        assert!(!same_subnet(a, Ipv4Addr::new(10, 2, 0, 1), 22));
    }

    #[test]
    fn owner_vip_with_prefix_for_slash_24_matches_factory() {
        assert_eq!(
            owner_vip_with_prefix("10.20.30.2", 24),
            owner_vip("10.20.30.2")
        );
    }

    #[test]
    fn endpoints_excluding_stale_skips_stale_only() {
        let mut rt = RoutingTable::new();
        let ep1: SocketAddr = "198.51.100.1:1".parse().unwrap();
        let ep2: SocketAddr = "198.51.100.2:2".parse().unwrap();
        rt.update("10.1.0.2", ep1, None);
        rt.update("10.1.0.3", ep2, None);
        if let Some(e) = rt.table.get_mut("10.1.0.3") {
            e.state = RouteState::Stale;
        }
        let eps = rt.endpoints_excluding_stale();
        assert_eq!(eps.len(), 1);
        assert!(eps.contains(&ep1));
    }

    #[test]
    fn remove_shared_endpoint_keeps_canonical_ep_to_vip() {
        let mut rt = RoutingTable::new();
        let ep: SocketAddr = "198.51.100.50:7000".parse().unwrap();
        rt.update("10.0.0.1", ep, None);
        rt.update("104.27.25.1", ep, None);
        assert!(rt.table.contains_key("10.0.0.1"));
        assert_eq!(rt.lookup("104.27.25.1"), Some(ep));
        rt.remove("10.0.0.1");
        assert!(!rt.table.contains_key("10.0.0.1"));
        assert_eq!(rt.lookup("104.27.25.1"), Some(ep));
        assert!(rt.tracks_endpoint(ep));
    }

    #[test]
    fn identified_owner_rebind_drops_prepare_join_placeholder() {
        let mut rt = RoutingTable::new();
        let ep: SocketAddr = "203.0.113.44:9000".parse().unwrap();
        rt.update("10.0.0.1", ep, None);
        rt.update("104.27.25.1", ep, Some("owner-node"));
        assert!(!rt.table.contains_key("10.0.0.1"));
        assert_eq!(rt.lookup("104.27.25.1"), Some(ep));
    }

    #[test]
    fn drain_vips_outside_subnet_removes_only_foreign_routes() {
        let mut rt = RoutingTable::new();
        let ep_a: SocketAddr = "198.51.100.1:1".parse().unwrap();
        let ep_b: SocketAddr = "198.51.100.2:2".parse().unwrap();
        rt.update("10.0.0.1", ep_a, None);
        rt.update("104.27.25.2", ep_b, Some("peer-a"));
        let drained = rt.drain_vips_outside_subnet("104.27.25.3", 24);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, "10.0.0.1");
        assert!(rt.lookup("104.27.25.2").is_some());
    }

    #[test]
    fn update_node_mapping_does_not_leave_stale_reverse_entry() {
        let mut rt = RoutingTable::new();
        let ep: SocketAddr = "198.51.100.9:9000".parse().unwrap();
        rt.update("10.9.0.2", ep, Some("node-a"));
        assert_eq!(rt.lookup_ep_by_node("node-a"), Some(ep));

        rt.update("10.9.0.2", ep, Some("node-b"));
        assert_eq!(rt.lookup_ep_by_node("node-b"), Some(ep));
        assert_eq!(rt.lookup_ep_by_node("node-a"), None);
    }

    #[test]
    fn update_endpoint_move_removes_old_vip_mappings() {
        let mut rt = RoutingTable::new();
        let ep: SocketAddr = "203.0.113.10:4000".parse().unwrap();
        rt.update("10.8.0.2", ep, Some("node-c"));
        rt.update("10.8.0.3", ep, Some("node-c"));
        assert!(rt.lookup("10.8.0.2").is_none());
        assert_eq!(rt.lookup("10.8.0.3"), Some(ep));
        assert_eq!(rt.lookup_ep_by_node("node-c"), Some(ep));
    }

    #[test]
    fn last_seen_for_vip_returns_some_after_update() {
        let mut rt = RoutingTable::new();
        let ep: SocketAddr = "203.0.113.30:3000".parse().unwrap();
        assert!(rt.last_seen_for_vip("10.10.0.2").is_none());
        rt.update("10.10.0.2", ep, None);
        assert!(rt.last_seen_for_vip("10.10.0.2").is_some());
    }

    #[test]
    fn path_set_reselect_moves_to_better_rtt_path() {
        let mut ps = PathSet::new("198.51.100.10:1000".parse().unwrap());
        ps.set_relay("198.51.100.20:2000".parse().unwrap());
        ps.note_rtt_for_endpoint(
            "198.51.100.10:1000".parse().unwrap(),
            180.0,
            &crate::advanced_tuning::RoutingEwmaTuning::default(),
        );
        ps.note_rtt_for_endpoint(
            "198.51.100.20:2000".parse().unwrap(),
            30.0,
            &crate::advanced_tuning::RoutingEwmaTuning::default(),
        );
        ps.reselect_active(false);
        assert_eq!(ps.active_idx, 0);
        ps.switch_candidate_since = Some(Instant::now() - Duration::from_secs(4));
        ps.reselect_active(false);
        let (_, kind) = ps.active_endpoint_kind().unwrap();
        assert_eq!(kind, PathKind::OwnerRelay);
    }

    #[test]
    fn path_set_no_switch_when_score_gap_small() {
        let mut ps = PathSet::new("198.51.100.10:1000".parse().unwrap());
        ps.set_relay("198.51.100.20:2000".parse().unwrap());
        ps.note_rtt_for_endpoint(
            "198.51.100.10:1000".parse().unwrap(),
            50.0,
            &crate::advanced_tuning::RoutingEwmaTuning::default(),
        );
        ps.note_rtt_for_endpoint(
            "198.51.100.20:2000".parse().unwrap(),
            45.0,
            &crate::advanced_tuning::RoutingEwmaTuning::default(),
        );
        ps.reselect_active(false);
        assert_eq!(ps.active_idx, 0);
        ps.switch_candidate_since = Some(Instant::now() - Duration::from_secs(10));
        ps.reselect_active(false);
        assert_eq!(ps.active_idx, 0);
    }

    #[test]
    fn path_set_forced_switch_when_gap_large() {
        let mut ps = PathSet::new("198.51.100.10:1000".parse().unwrap());
        ps.set_relay("198.51.100.20:2000".parse().unwrap());
        if let Some(direct) = ps.paths[0].as_mut() {
            direct.smoothed_rtt_ms = 380.0;
            direct.loss_ewma = 0.5;
        }
        ps.note_rtt_for_endpoint(
            "198.51.100.20:2000".parse().unwrap(),
            20.0,
            &crate::advanced_tuning::RoutingEwmaTuning::default(),
        );
        ps.reselect_active(false);
        let (_, kind) = ps.active_endpoint_kind().unwrap();
        assert_eq!(kind, PathKind::OwnerRelay);
    }

    #[test]
    fn path_set_confirmed_switch_after_duration() {
        let mut ps = PathSet::new("198.51.100.10:1000".parse().unwrap());
        ps.set_relay("198.51.100.20:2000".parse().unwrap());
        ps.note_rtt_for_endpoint(
            "198.51.100.10:1000".parse().unwrap(),
            200.0,
            &crate::advanced_tuning::RoutingEwmaTuning::default(),
        );
        ps.note_rtt_for_endpoint(
            "198.51.100.20:2000".parse().unwrap(),
            40.0,
            &crate::advanced_tuning::RoutingEwmaTuning::default(),
        );
        ps.reselect_active(false);
        assert_eq!(ps.switch_candidate_idx, Some(1));
        ps.switch_candidate_since =
            Some(Instant::now() - SWITCH_CONFIRMING_TIME - Duration::from_secs(1));
        ps.reselect_active(false);
        assert_eq!(ps.active_idx, 1);
    }

    #[test]
    fn note_relay_fallback_does_not_refresh_active_hold_down() {
        let mut rt = RoutingTable::new();
        let ep: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        rt.update("10.0.0.2", ep, None);
        rt.note_relay_fallback("10.0.0.2");
        let first = rt.table.get("10.0.0.2").unwrap().hold_down_until;
        rt.note_relay_fallback("10.0.0.2");
        let second = rt.table.get("10.0.0.2").unwrap().hold_down_until;
        assert_eq!(first, second);
        if let Some(e) = rt.table.get_mut("10.0.0.2") {
            e.hold_down_until = Some(Instant::now() - Duration::from_secs(1));
        }
        rt.note_relay_fallback("10.0.0.2");
        let third = rt.table.get("10.0.0.2").unwrap().hold_down_until.unwrap();
        assert!(third > Instant::now());
    }

    #[test]
    fn loss_ewma_rises_under_moderate_packet_loss() {
        let mut rt = RoutingTable::new();
        let ep: SocketAddr = "127.0.0.1:11000".parse().unwrap();
        rt.update("10.0.0.9", ep, None);
        for i in 0..40 {
            if i % 3 == 0 {
                let _ = rt.note_fail(ep, None);
            } else {
                rt.note_rtt(ep, 50, None);
            }
        }
        assert!(
            rt.table.get("10.0.0.9").unwrap().loss_ewma > 0.0,
            "expected positive loss_ewma under ~33% loss"
        );
    }

    #[test]
    fn note_rtt_via_relay_endpoint_updates_path_candidate_only() {
        let mut rt = RoutingTable::new();
        let direct: SocketAddr = "198.51.100.10:1000".parse().unwrap();
        let relay: SocketAddr = "198.51.100.20:2000".parse().unwrap();
        rt.update("10.0.0.5", direct, None);
        rt.table
            .get_mut("10.0.0.5")
            .unwrap()
            .path_set
            .as_mut()
            .unwrap()
            .set_relay(relay);
        rt.rebuild_path_ep_index_for_vip("10.0.0.5");
        // Seed VIP RTT from active (direct) path.
        assert!(rt.note_rtt(direct, 30, None));
        let before_qd = rt.table.get("10.0.0.5").unwrap().queuing_delay_ms;
        let before_last = rt.table.get("10.0.0.5").unwrap().last_rtt_ms;
        // Secondary path must not move VIP-level RTT / queuing delay.
        assert!(!rt.note_rtt(relay, 42, None));
        let entry = rt.table.get("10.0.0.5").unwrap();
        assert_eq!(entry.last_rtt_ms, before_last);
        assert_eq!(entry.queuing_delay_ms, before_qd);
        let relay_rtt = entry.path_set.as_ref().unwrap().paths[1]
            .as_ref()
            .unwrap()
            .smoothed_rtt_ms;
        assert!((relay_rtt - 42.0).abs() < 0.01);
    }

    #[test]
    fn note_rtt_active_path_updates_vip_queuing_delay() {
        let mut rt = RoutingTable::new();
        let direct: SocketAddr = "198.51.100.10:1000".parse().unwrap();
        let relay: SocketAddr = "198.51.100.20:2000".parse().unwrap();
        rt.update("10.0.0.5", direct, None);
        rt.table
            .get_mut("10.0.0.5")
            .unwrap()
            .path_set
            .as_mut()
            .unwrap()
            .set_relay(relay);
        rt.rebuild_path_ep_index_for_vip("10.0.0.5");
        assert!(rt.note_rtt(direct, 40, None));
        assert!(rt.note_rtt(direct, 80, None));
        let entry = rt.table.get("10.0.0.5").unwrap();
        assert!(entry.queuing_delay_ms > 0.0);
        assert_eq!(entry.last_rtt_ms, 80);
    }

    #[test]
    fn control_race_endpoints_active_first_cap_and_dedup() {
        let direct: SocketAddr = "198.51.100.10:1000".parse().unwrap();
        let relay: SocketAddr = "198.51.100.20:2000".parse().unwrap();
        let srflx: SocketAddr = "198.51.100.30:3000".parse().unwrap();
        let mut ps = PathSet::new(direct);
        ps.set_relay(relay);
        ps.set_srflx(srflx);
        // Force active to relay.
        ps.active_idx = 1;
        let eps = ps.control_race_endpoints();
        assert_eq!(eps.len(), 3);
        assert_eq!(eps[0], relay);
        assert!(eps.contains(&direct));
        assert!(eps.contains(&srflx));

        // Failed path excluded.
        ps.paths[2].as_mut().unwrap().consecutive_failures = 5;
        let eps2 = ps.control_race_endpoints();
        assert_eq!(eps2.len(), 2);
        assert_eq!(eps2[0], relay);
        assert!(!eps2.contains(&srflx));
    }

    #[test]
    fn control_race_endpoints_for_endpoint_falls_back_to_primary() {
        let mut rt = RoutingTable::new();
        let direct: SocketAddr = "198.51.100.10:1000".parse().unwrap();
        let relay: SocketAddr = "198.51.100.20:2000".parse().unwrap();
        rt.update("10.0.0.5", direct, None);
        rt.table
            .get_mut("10.0.0.5")
            .unwrap()
            .path_set
            .as_mut()
            .unwrap()
            .set_relay(relay);
        rt.rebuild_path_ep_index_for_vip("10.0.0.5");
        let raced = rt.control_race_endpoints_for_endpoint(direct, None);
        assert_eq!(raced.len(), 2);
        assert_eq!(raced[0], direct);
        assert!(raced.contains(&relay));
        let unknown: SocketAddr = "203.0.113.9:9".parse().unwrap();
        assert_eq!(
            rt.control_race_endpoints_for_endpoint(unknown, None),
            vec![unknown]
        );
    }

    #[test]
    fn vip_for_data_endpoint_ignores_shared_owner_relay_ep() {
        let mut rt = RoutingTable::new();
        let direct: SocketAddr = "198.51.100.10:1000".parse().unwrap();
        let owner: SocketAddr = "198.51.100.1:2000".parse().unwrap();
        rt.update("10.0.0.5", direct, None);
        rt.table
            .get_mut("10.0.0.5")
            .unwrap()
            .path_set
            .as_mut()
            .unwrap()
            .set_relay(owner);
        rt.rebuild_path_ep_index_for_vip("10.0.0.5");
        assert_eq!(rt.vip_for_data_endpoint(owner, Some(owner)), None);
        assert_eq!(
            rt.vip_for_data_endpoint(direct, Some(owner)),
            Some("10.0.0.5".to_string())
        );
    }

    #[test]
    fn note_bytes_received_for_vip_u32_attributes_to_dst_peer() {
        let mut rt = RoutingTable::new();
        let direct: SocketAddr = "198.51.100.10:1000".parse().unwrap();
        let owner: SocketAddr = "198.51.100.20:2000".parse().unwrap();
        rt.update("10.0.0.7", direct, None);
        rt.table
            .get_mut("10.0.0.7")
            .unwrap()
            .path_set
            .as_mut()
            .unwrap()
            .set_relay(owner);
        rt.rebuild_path_ep_index_for_vip("10.0.0.7");
        let dst_u32 = u32::from(std::net::Ipv4Addr::new(10, 0, 0, 7));
        rt.note_bytes_received_for_vip_u32(dst_u32, 4096, false);
        assert_eq!(
            rt.table
                .get("10.0.0.7")
                .unwrap()
                .rx_bytes_since_last_bw_calc,
            4096
        );
        assert_eq!(rt.vip_for_data_endpoint(owner, Some(owner)), None);
    }

    #[test]
    fn rtt_base_tracks_min_and_queuing_delay() {
        use crate::advanced_tuning::CongestionTuning;
        let cg = CongestionTuning {
            base_rtt_window_secs: 10,
            ..CongestionTuning::default()
        };
        let now = Instant::now();
        let mut entry = RouteEntry {
            endpoint: "127.0.0.1:1".parse().unwrap(),
            node_id: Arc::from("n"),
            state: RouteState::Active,
            last_seen: now,
            smoothed_rtt_ms: 100.0,
            jitter_ms: 0.0,
            last_rtt_ms: 100,
            loss_ewma: 0.0,
            quality_score: 80,
            success_streak: 5,
            fail_streak: 0,
            hold_down_until: None,
            last_modified_revision: 0,
            path_set: None,
            rx_bytes_since_last_bw_calc: 0,
            rx_bw_calc_at: now,
            dual_write_until: None,
            dual_write_old_ep: None,
            dual_write_old_kind: None,
            rtt_base_ms: 100.0,
            rtt_base_window_min: 100.0,
            rtt_base_window_start: now - Duration::from_secs(11),
            rtt_base_stale_count: 0,
            queuing_delay_ms: 0.0,
            owd_base_ms: None,
            owd_base_window_min: f64::INFINITY,
            owd_base_window_start: now,
            owd_base_stale_count: 0,
            fwd_queuing_delay_ms: 0.0,
        };
        update_rtt_base_on_sample(&mut entry, 60.0, now, &cg);
        assert_eq!(entry.rtt_base_ms, 60.0);
        entry.smoothed_rtt_ms = 90.0;
        update_rtt_base_on_sample(&mut entry, 90.0, now, &cg);
        assert!((entry.queuing_delay_ms - 30.0).abs() < 0.01);
    }

    #[test]
    fn rtt_base_stale_windows_before_increase() {
        use crate::advanced_tuning::CongestionTuning;
        let cg = CongestionTuning {
            base_rtt_stale_windows: 2,
            base_rtt_window_secs: 1,
            ..CongestionTuning::default()
        };
        let now = Instant::now();
        let mut entry = RouteEntry {
            endpoint: "127.0.0.1:1".parse().unwrap(),
            node_id: Arc::from("n"),
            state: RouteState::Active,
            last_seen: now,
            smoothed_rtt_ms: 50.0,
            jitter_ms: 0.0,
            last_rtt_ms: 50,
            loss_ewma: 0.0,
            quality_score: 80,
            success_streak: 5,
            fail_streak: 0,
            hold_down_until: None,
            last_modified_revision: 0,
            path_set: None,
            rx_bytes_since_last_bw_calc: 0,
            rx_bw_calc_at: now,
            dual_write_until: None,
            dual_write_old_ep: None,
            dual_write_old_kind: None,
            rtt_base_ms: 50.0,
            rtt_base_window_min: 80.0,
            rtt_base_window_start: now - Duration::from_secs(2),
            rtt_base_stale_count: 0,
            queuing_delay_ms: 0.0,
            owd_base_ms: None,
            owd_base_window_min: f64::INFINITY,
            owd_base_window_start: now,
            owd_base_stale_count: 0,
            fwd_queuing_delay_ms: 0.0,
        };
        update_rtt_base_on_sample(&mut entry, 80.0, now, &cg);
        assert_eq!(entry.rtt_base_ms, 50.0);
        assert_eq!(entry.rtt_base_stale_count, 1);
        entry.rtt_base_window_min = 80.0;
        entry.rtt_base_window_start = now - Duration::from_secs(2);
        update_rtt_base_on_sample(&mut entry, 80.0, now, &cg);
        assert_eq!(entry.rtt_base_ms, 80.0);
    }

    fn blank_route_entry(now: Instant) -> RouteEntry {
        RouteEntry {
            endpoint: "127.0.0.1:1".parse().unwrap(),
            node_id: Arc::from("n"),
            state: RouteState::Active,
            last_seen: now,
            smoothed_rtt_ms: 50.0,
            jitter_ms: 0.0,
            last_rtt_ms: 50,
            loss_ewma: 0.0,
            quality_score: 80,
            success_streak: 5,
            fail_streak: 0,
            hold_down_until: None,
            last_modified_revision: 0,
            path_set: None,
            rx_bytes_since_last_bw_calc: 0,
            rx_bw_calc_at: now,
            dual_write_until: None,
            dual_write_old_ep: None,
            dual_write_old_kind: None,
            rtt_base_ms: -1.0,
            rtt_base_window_min: f64::INFINITY,
            rtt_base_window_start: now,
            rtt_base_stale_count: 0,
            queuing_delay_ms: 0.0,
            owd_base_ms: None,
            owd_base_window_min: f64::INFINITY,
            owd_base_window_start: now,
            owd_base_stale_count: 0,
            fwd_queuing_delay_ms: 0.0,
        }
    }

    #[test]
    fn owd_base_tracks_min_and_fwd_queuing_delay() {
        use crate::advanced_tuning::CongestionTuning;
        let cg = CongestionTuning {
            base_rtt_window_secs: 10,
            ..CongestionTuning::default()
        };
        let now = Instant::now();
        let mut entry = blank_route_entry(now);
        assert_eq!(
            update_owd_base_on_sample(&mut entry, 100.0, now, &cg),
            OwdSampleOutcome::Applied
        );
        assert_eq!(entry.owd_base_ms, Some(100.0));
        assert_eq!(entry.fwd_queuing_delay_ms, 0.0);

        entry.owd_base_window_start = now - Duration::from_secs(11);
        assert_eq!(
            update_owd_base_on_sample(&mut entry, 60.0, now, &cg),
            OwdSampleOutcome::Applied
        );
        assert_eq!(entry.owd_base_ms, Some(60.0));

        assert_eq!(
            update_owd_base_on_sample(&mut entry, 90.0, now, &cg),
            OwdSampleOutcome::Applied
        );
        assert!((entry.fwd_queuing_delay_ms - 30.0).abs() < 0.01);
    }

    #[test]
    fn owd_base_stale_windows_before_increase() {
        use crate::advanced_tuning::CongestionTuning;
        let cg = CongestionTuning {
            base_rtt_stale_windows: 2,
            base_rtt_window_secs: 1,
            ..CongestionTuning::default()
        };
        let now = Instant::now();
        let mut entry = blank_route_entry(now);
        entry.owd_base_ms = Some(50.0);
        entry.owd_base_window_min = 80.0;
        entry.owd_base_window_start = now - Duration::from_secs(2);
        entry.owd_base_stale_count = 0;
        assert_eq!(
            update_owd_base_on_sample(&mut entry, 80.0, now, &cg),
            OwdSampleOutcome::Applied
        );
        assert_eq!(entry.owd_base_ms, Some(50.0));
        assert_eq!(entry.owd_base_stale_count, 1);
        entry.owd_base_window_min = 80.0;
        entry.owd_base_window_start = now - Duration::from_secs(2);
        assert_eq!(
            update_owd_base_on_sample(&mut entry, 80.0, now, &cg),
            OwdSampleOutcome::Applied
        );
        assert_eq!(entry.owd_base_ms, Some(80.0));
    }

    #[test]
    fn owd_clock_jump_rejects_and_resets_cold() {
        use crate::advanced_tuning::CongestionTuning;
        let cg = CongestionTuning::default();
        let now = Instant::now();
        let mut entry = blank_route_entry(now);
        assert_eq!(
            update_owd_base_on_sample(&mut entry, -5000.0, now, &cg),
            OwdSampleOutcome::Applied
        );
        assert_eq!(entry.owd_base_ms, Some(-5000.0));
        assert_eq!(
            update_owd_base_on_sample(
                &mut entry,
                -5000.0 + DEFAULT_OWD_CLOCK_JUMP_REJECT_MS as f64 + 1.0,
                now,
                &cg
            ),
            OwdSampleOutcome::Rejected
        );
        assert!(entry.owd_base_ms.is_none());
        assert_eq!(effective_queuing_delay_ms(&entry), -1.0);
    }

    #[test]
    fn owd_negative_base_stays_warm_for_effective_qd() {
        use crate::advanced_tuning::CongestionTuning;
        let cg = CongestionTuning::default();
        let now = Instant::now();
        let mut entry = blank_route_entry(now);
        assert_eq!(
            update_owd_base_on_sample(&mut entry, -2000.0, now, &cg),
            OwdSampleOutcome::Applied
        );
        assert_eq!(
            update_owd_base_on_sample(&mut entry, -1950.0, now, &cg),
            OwdSampleOutcome::Applied
        );
        assert!((entry.fwd_queuing_delay_ms - 50.0).abs() < 0.01);
        assert!((effective_queuing_delay_ms(&entry) - 50.0).abs() < 0.01);
    }

    #[test]
    fn effective_queuing_delay_precedence_fwd_rtt_cold() {
        let now = Instant::now();
        let mut entry = blank_route_entry(now);
        assert_eq!(effective_queuing_delay_ms(&entry), -1.0);

        entry.rtt_base_ms = 40.0;
        entry.queuing_delay_ms = 12.0;
        assert!((effective_queuing_delay_ms(&entry) - 12.0).abs() < 0.01);

        entry.owd_base_ms = Some(-100.0);
        entry.fwd_queuing_delay_ms = 7.0;
        assert!((effective_queuing_delay_ms(&entry) - 7.0).abs() < 0.01);
    }

    fn healthy_route(rt: &mut RoutingTable, vip: &str, ep: SocketAddr) {
        rt.update(vip, ep, None);
        if let Some(e) = rt.table.get_mut(vip) {
            e.state = RouteState::Active;
            e.quality_score = 90;
            e.fail_streak = 0;
        }
    }

    #[test]
    fn select_relay_prefer_owner_over_better_peer_rtt() {
        let mut rt = RoutingTable::new();
        let owner_ep: SocketAddr = "198.51.100.1:2000".parse().unwrap();
        let peer_ep: SocketAddr = "198.51.100.2:3000".parse().unwrap();
        let dest_ep: SocketAddr = "198.51.100.3:4000".parse().unwrap();
        healthy_route(&mut rt, "10.1.1.1", owner_ep);
        healthy_route(&mut rt, "10.1.1.2", peer_ep);
        healthy_route(&mut rt, "10.1.1.3", dest_ep);
        if let Some(e) = rt.table.get_mut("10.1.1.2") {
            e.smoothed_rtt_ms = 5.0;
        }
        if let Some(e) = rt.table.get_mut("10.1.1.1") {
            e.smoothed_rtt_ms = 200.0;
        }
        match rt.select_relay_endpoint("10.1.1.3", "10.1.1.1", "10.1.1.4", None) {
            RelaySelection::Hop(ep) => assert_eq!(ep, owner_ep),
            RelaySelection::None => panic!("expected owner hop"),
        }
    }

    #[test]
    fn select_relay_zombie_owner_uses_peer() {
        let mut rt = RoutingTable::new();
        let owner_ep: SocketAddr = "198.51.100.1:2000".parse().unwrap();
        let peer_ep: SocketAddr = "198.51.100.2:3000".parse().unwrap();
        let dest_ep: SocketAddr = "198.51.100.3:4000".parse().unwrap();
        rt.update("10.1.1.1", owner_ep, None);
        if let Some(e) = rt.table.get_mut("10.1.1.1") {
            e.state = RouteState::Stale;
        }
        healthy_route(&mut rt, "10.1.1.2", peer_ep);
        healthy_route(&mut rt, "10.1.1.3", dest_ep);
        match rt.select_relay_endpoint("10.1.1.3", "10.1.1.1", "10.1.1.4", None) {
            RelaySelection::Hop(ep) => assert_eq!(ep, peer_ep),
            RelaySelection::None => panic!("expected peer hop"),
        }
    }

    #[test]
    fn select_relay_respects_exclude() {
        let mut rt = RoutingTable::new();
        let owner_ep: SocketAddr = "198.51.100.1:2000".parse().unwrap();
        let peer_ep: SocketAddr = "198.51.100.2:3000".parse().unwrap();
        let dest_ep: SocketAddr = "198.51.100.3:4000".parse().unwrap();
        healthy_route(&mut rt, "10.1.1.1", owner_ep);
        healthy_route(&mut rt, "10.1.1.2", peer_ep);
        healthy_route(&mut rt, "10.1.1.3", dest_ep);
        match rt.select_relay_endpoint("10.1.1.3", "10.1.1.1", "10.1.1.4", Some(owner_ep)) {
            RelaySelection::Hop(ep) => assert_eq!(ep, peer_ep),
            RelaySelection::None => panic!("expected peer after exclude owner"),
        }
    }

    #[test]
    fn select_relay_sticky_skips_unusable_stamped_owner() {
        let mut rt = RoutingTable::new();
        let owner_ep: SocketAddr = "198.51.100.1:2000".parse().unwrap();
        let peer_ep: SocketAddr = "198.51.100.2:3000".parse().unwrap();
        let dest_ep: SocketAddr = "198.51.100.3:4000".parse().unwrap();
        rt.update("10.1.1.1", owner_ep, None);
        if let Some(e) = rt.table.get_mut("10.1.1.1") {
            e.state = RouteState::Stale;
        }
        healthy_route(&mut rt, "10.1.1.2", peer_ep);
        healthy_route(&mut rt, "10.1.1.3", dest_ep);
        rt.stamp_relay_hop("10.1.1.3", owner_ep);
        match rt.select_relay_endpoint("10.1.1.3", "10.1.1.1", "10.1.1.4", None) {
            RelaySelection::Hop(ep) => assert_eq!(ep, peer_ep),
            RelaySelection::None => panic!("expected peer when sticky owner unusable"),
        }
    }

    #[test]
    fn select_relay_none_when_no_candidate() {
        let mut rt = RoutingTable::new();
        let owner_ep: SocketAddr = "198.51.100.1:2000".parse().unwrap();
        let dest_ep: SocketAddr = "198.51.100.3:4000".parse().unwrap();
        rt.update("10.1.1.1", owner_ep, None);
        if let Some(e) = rt.table.get_mut("10.1.1.1") {
            e.state = RouteState::Stale;
        }
        healthy_route(&mut rt, "10.1.1.3", dest_ep);
        assert_eq!(
            rt.select_relay_endpoint("10.1.1.3", "10.1.1.1", "10.1.1.4", None),
            RelaySelection::None
        );
    }

    #[test]
    fn select_broadcast_relay_hop_prefers_owner_then_peer() {
        let mut rt = RoutingTable::new();
        let owner_ep: SocketAddr = "198.51.100.1:2000".parse().unwrap();
        let peer_ep: SocketAddr = "198.51.100.2:3000".parse().unwrap();
        let from: SocketAddr = "198.51.100.9:9000".parse().unwrap();
        healthy_route(&mut rt, "10.1.1.1", owner_ep);
        healthy_route(&mut rt, "10.1.1.2", peer_ep);
        match rt.select_broadcast_relay_hop("10.1.1.1", "10.1.1.4", Some(from)) {
            RelaySelection::Hop(ep) => assert_eq!(ep, owner_ep),
            RelaySelection::None => panic!("expected owner for bcast"),
        }
        if let Some(e) = rt.table.get_mut("10.1.1.1") {
            e.state = RouteState::Stale;
        }
        match rt.select_broadcast_relay_hop("10.1.1.1", "10.1.1.4", Some(from)) {
            RelaySelection::Hop(ep) => assert_eq!(ep, peer_ep),
            RelaySelection::None => panic!("expected peer hub"),
        }
        assert_eq!(
            rt.select_broadcast_relay_hop("10.1.1.1", "10.1.1.4", Some(peer_ep)),
            RelaySelection::None
        );
    }

    #[test]
    fn clear_relay_path_removes_slot_and_rebuilds_index() {
        let mut rt = RoutingTable::new();
        let direct: SocketAddr = "198.51.100.10:1000".parse().unwrap();
        let relay: SocketAddr = "198.51.100.20:2000".parse().unwrap();
        rt.update("10.0.0.5", direct, None);
        rt.stamp_relay_hop("10.0.0.5", relay);
        assert!(rt.path_ep_to_vip.contains_key(&relay));
        rt.clear_relay_path("10.0.0.5");
        assert!(!rt.path_ep_to_vip.contains_key(&relay));
        assert!(rt
            .table
            .get("10.0.0.5")
            .unwrap()
            .path_set
            .as_ref()
            .unwrap()
            .paths[1]
            .is_none());
    }

    #[test]
    fn vip_for_data_endpoint_peer_hub_not_dest() {
        let mut rt = RoutingTable::new();
        let direct: SocketAddr = "198.51.100.10:1000".parse().unwrap();
        let owner: SocketAddr = "198.51.100.1:2000".parse().unwrap();
        let peer_hub: SocketAddr = "198.51.100.30:3000".parse().unwrap();
        rt.update("10.0.0.5", direct, None);
        rt.update("10.0.0.9", peer_hub, None);
        rt.table
            .get_mut("10.0.0.5")
            .unwrap()
            .path_set
            .as_mut()
            .unwrap()
            .set_relay(owner);
        rt.rebuild_path_ep_index_for_vip("10.0.0.5");
        assert_eq!(
            rt.vip_for_data_endpoint(peer_hub, Some(owner)),
            Some("10.0.0.9".to_string())
        );
    }

    #[test]
    fn apply_rtt_sample_honors_custom_ewma() {
        use crate::advanced_tuning::{CongestionTuning, FailoverTuning, RoutingEwmaTuning};
        let now = Instant::now();
        let mut entry = RouteEntry {
            endpoint: "127.0.0.1:1".parse().unwrap(),
            node_id: Arc::from("n"),
            state: RouteState::Active,
            last_seen: now,
            smoothed_rtt_ms: 100.0,
            jitter_ms: 0.0,
            last_rtt_ms: 100,
            loss_ewma: 0.2,
            quality_score: 80,
            success_streak: 1,
            fail_streak: 0,
            hold_down_until: None,
            last_modified_revision: 0,
            path_set: None,
            rx_bytes_since_last_bw_calc: 0,
            rx_bw_calc_at: now,
            dual_write_until: None,
            dual_write_old_ep: None,
            dual_write_old_kind: None,
            rtt_base_ms: -1.0,
            rtt_base_window_min: f64::INFINITY,
            rtt_base_window_start: now,
            rtt_base_stale_count: 0,
            queuing_delay_ms: 0.0,
            owd_base_ms: None,
            owd_base_window_min: f64::INFINITY,
            owd_base_window_start: now,
            owd_base_stale_count: 0,
            fwd_queuing_delay_ms: 0.0,
        };
        let mut ewma = RoutingEwmaTuning::default();
        ewma.rtt_ewma_old = 0.5;
        ewma.rtt_ewma_new = 0.5;
        ewma.loss_ewma_decay = 0.9;
        ewma.loss_ewma_success_delta = 0.0;
        apply_rtt_sample(
            &mut entry,
            50,
            &FailoverTuning::default(),
            &CongestionTuning {
                rtt_base_tracking: false,
                ..CongestionTuning::default()
            },
            &ewma,
            now,
        );
        assert!((entry.smoothed_rtt_ms - 75.0).abs() < 1e-9);
        assert!((entry.loss_ewma - 0.18).abs() < 1e-9);
    }

    #[test]
    fn note_fail_honors_custom_loss_bump() {
        let mut rt = RoutingTable::new();
        let ep: SocketAddr = "203.0.113.40:4000".parse().unwrap();
        rt.update("10.0.0.40", ep, None);
        rt.routing_ewma.loss_ewma_decay = 1.0;
        rt.routing_ewma.loss_ewma_fail_bump = 0.25;
        rt.routing_ewma.quality_loss_scale = 0.0;
        let before = rt.table.get("10.0.0.40").unwrap().loss_ewma;
        let _ = rt.note_fail(ep, None);
        let after = rt.table.get("10.0.0.40").unwrap().loss_ewma;
        assert!((after - (before + 0.25)).abs() < 1e-9);
    }

    fn healthy_relay_snap(jitter_ms: f64) -> RelayPathSnapshot {
        RelayPathSnapshot {
            state: RouteState::Active,
            quality_score: 80,
            loss_ewma: 0.01,
            jitter_ms,
            success_streak: 10,
            hold_down_until: None,
        }
    }

    #[test]
    fn should_relay_trips_on_high_jitter_despite_healthy_quality() {
        let fo = crate::advanced_tuning::FailoverTuning::default();
        let s = healthy_relay_snap(fo.d2r_jitter_max + 1.0);
        assert!(should_relay_snap(&s, &fo));
    }

    #[test]
    fn should_relay_ignores_jitter_at_or_below_threshold() {
        let fo = crate::advanced_tuning::FailoverTuning::default();
        let at = healthy_relay_snap(fo.d2r_jitter_max);
        let below = healthy_relay_snap(fo.d2r_jitter_max - 1.0);
        assert!(!should_relay_snap(&at, &fo));
        assert!(!should_relay_snap(&below, &fo));
    }

    #[test]
    fn can_return_to_direct_ignores_jitter() {
        let fo = crate::advanced_tuning::FailoverTuning::default();
        let s = healthy_relay_snap(fo.d2r_jitter_max + 100.0);
        assert!(s.quality_score >= fo.r2d_quality_min);
        assert!(s.success_streak >= fo.r2d_success_min);
        assert!(can_return_to_direct_snap(&s, Instant::now(), &fo));
    }
}
