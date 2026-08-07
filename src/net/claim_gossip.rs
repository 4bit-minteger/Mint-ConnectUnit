//! FloatUnit claim-gossip merge + leave tombstones + VIP-fight suppress.
//! Pure helpers — no I/O; engine wires signed MCLG / MLEA on top.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::claim::{claim_vip_valid, local_loses_vip_conflict};

/// Max claims (excluding sender self which is always included) in one MCLG digest.
pub const CLAIM_GOSSIP_DIGEST_MAX: usize = 32;

/// Max leave tombstones attached to one MCLG body.
pub const CLAIM_GOSSIP_LEAVE_TOMBS_MAX: usize = 8;

/// Default TTL for graceful-leave tombstones.
pub const LEAVE_TOMBSTONE_TTL: Duration = Duration::from_secs(300);

/// TTL for observer suppress of a losing VIP-fight claim.
pub const FIGHT_SUPPRESS_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimRecord {
    pub node_id: String,
    pub vip: String,
    pub vip_epoch: u64,
    pub ep_hints: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct LeaveTombstone {
    pub node_id: String,
    pub vip: String,
    pub vip_epoch: u64,
    pub expires_at: Instant,
}

/// Blocks re-accept of an identical losing VIP-fight claim until expiry.
#[derive(Debug, Clone)]
pub struct FightSuppress {
    pub node_id: String,
    pub vip: String,
    pub vip_epoch: u64,
    pub expires_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeOutcome {
    /// Stored or refreshed the claim.
    Accepted,
    /// Incoming was stale (lower/equal epoch with no useful change).
    IgnoredStale,
    /// Blocked by an active leave tombstone for this node_id.
    BlockedByTombstone,
    /// Blocked by an active VIP-fight suppress for identical (node_id, vip, epoch).
    BlockedByFight,
    /// Invalid claim fields.
    Rejected,
}

/// Per-`node_id` LWW by `vip_epoch`. Equal epoch + identical vip → no-op (IgnoredStale).
/// Equal epoch + conflicting vip for same node_id → keep existing (IgnoredStale).
/// Active fight suppress blocks the identical losing triple and **slides** its TTL
/// so continuous loser gossip cannot re-enter after the original 30s window.
pub fn merge_claim(
    map: &mut HashMap<String, ClaimRecord>,
    incoming: ClaimRecord,
    tombs: &HashMap<String, LeaveTombstone>,
    fight_suppress: &mut HashMap<String, FightSuppress>,
    now: Instant,
) -> MergeOutcome {
    if incoming.node_id.is_empty() || !claim_vip_valid(&incoming.vip) {
        return MergeOutcome::Rejected;
    }
    if let Some(t) = tombs.get(&incoming.node_id) {
        if t.expires_at > now && incoming.vip_epoch <= t.vip_epoch {
            return MergeOutcome::BlockedByTombstone;
        }
    }
    if fight_suppress_blocks(
        fight_suppress,
        &incoming.node_id,
        &incoming.vip,
        incoming.vip_epoch,
        now,
    ) {
        let _ = install_fight_suppress(
            fight_suppress,
            &incoming.node_id,
            &incoming.vip,
            incoming.vip_epoch,
            now,
            FIGHT_SUPPRESS_TTL,
        );
        return MergeOutcome::BlockedByFight;
    }
    match map.get(&incoming.node_id) {
        None => {
            map.insert(incoming.node_id.clone(), incoming);
            MergeOutcome::Accepted
        }
        Some(existing) if incoming.vip_epoch > existing.vip_epoch => {
            map.insert(incoming.node_id.clone(), incoming);
            MergeOutcome::Accepted
        }
        Some(existing)
            if incoming.vip_epoch == existing.vip_epoch && incoming.vip == existing.vip =>
        {
            // Refresh hints if provided; still counts as stale no-op for routing churn.
            if !incoming.ep_hints.is_empty() && incoming.ep_hints != existing.ep_hints {
                let mut refreshed = existing.clone();
                refreshed.ep_hints = incoming.ep_hints;
                map.insert(incoming.node_id.clone(), refreshed);
                return MergeOutcome::Accepted;
            }
            MergeOutcome::IgnoredStale
        }
        Some(_) => MergeOutcome::IgnoredStale,
    }
}

/// Install or refresh a VIP-fight suppress entry for a remote loser.
pub fn install_fight_suppress(
    suppress: &mut HashMap<String, FightSuppress>,
    node_id: &str,
    vip: &str,
    vip_epoch: u64,
    now: Instant,
    ttl: Duration,
) -> bool {
    if node_id.is_empty() || !claim_vip_valid(vip) {
        return false;
    }
    suppress.insert(
        node_id.to_string(),
        FightSuppress {
            node_id: node_id.to_string(),
            vip: vip.to_string(),
            vip_epoch,
            expires_at: now + ttl,
        },
    );
    true
}

/// True while a non-expired suppress blocks the identical losing claim triple.
pub fn fight_suppress_blocks(
    suppress: &HashMap<String, FightSuppress>,
    node_id: &str,
    vip: &str,
    vip_epoch: u64,
    now: Instant,
) -> bool {
    match suppress.get(node_id) {
        Some(s) if s.expires_at > now && s.vip == vip && s.vip_epoch == vip_epoch => true,
        _ => false,
    }
}

/// Drop expired VIP-fight suppress entries.
pub fn prune_fight_suppress(suppress: &mut HashMap<String, FightSuppress>, now: Instant) {
    suppress.retain(|_, s| s.expires_at > now);
}

/// Remove every live claim whose VIP matches `vip` (used when stale route has no `node_id`).
pub fn remove_claims_for_vip(map: &mut HashMap<String, ClaimRecord>, vip: &str) -> Vec<String> {
    let doomed: Vec<String> = map
        .iter()
        .filter(|(_, c)| c.vip == vip)
        .map(|(nid, _)| nid.clone())
        .collect();
    for nid in &doomed {
        map.remove(nid);
    }
    doomed
}

/// True when a claim is still the canonical live entry after settle.
pub fn claim_still_live(
    map: &HashMap<String, ClaimRecord>,
    node_id: &str,
    vip: &str,
    vip_epoch: u64,
) -> bool {
    match map.get(node_id) {
        Some(c) if c.vip == vip && c.vip_epoch == vip_epoch => true,
        _ => false,
    }
}

/// True when remote claim should force the local peer to reroll (cross-node VIP fight).
/// Epoch is not used for the fight itself — lower hex `node_id` wins.
pub fn should_reroll_for_vip_fight(
    local_node_id: &str,
    local_vip: &str,
    remote_node_id: &str,
    remote_vip: &str,
) -> bool {
    remote_vip == local_vip && local_loses_vip_conflict(local_node_id, remote_node_id)
}

/// After merges: for each VIP claimed by >1 live node, keep lex-smaller `node_id`.
/// Returns loser `node_id`s that were removed from `map`.
pub fn settle_duplicate_vips(map: &mut HashMap<String, ClaimRecord>) -> Vec<String> {
    let mut by_vip: HashMap<String, Vec<String>> = HashMap::new();
    for (nid, rec) in map.iter() {
        by_vip.entry(rec.vip.clone()).or_default().push(nid.clone());
    }
    let mut losers = Vec::new();
    for (_vip, mut nodes) in by_vip {
        if nodes.len() < 2 {
            continue;
        }
        nodes.sort();
        let _winner = nodes[0].clone();
        for nid in nodes.into_iter().skip(1) {
            map.remove(&nid);
            losers.push(nid);
        }
    }
    losers
}

/// Install or refresh a leave tombstone. Returns false if `event` looks empty/invalid.
pub fn install_leave_tombstone(
    tombs: &mut HashMap<String, LeaveTombstone>,
    node_id: &str,
    vip: &str,
    vip_epoch: u64,
    now: Instant,
    ttl: Duration,
) -> bool {
    if node_id.is_empty() || !claim_vip_valid(vip) {
        return false;
    }
    tombs.insert(
        node_id.to_string(),
        LeaveTombstone {
            node_id: node_id.to_string(),
            vip: vip.to_string(),
            vip_epoch,
            expires_at: now + ttl,
        },
    );
    true
}

/// Drop expired leave tombstones.
pub fn prune_leave_tombstones(tombs: &mut HashMap<String, LeaveTombstone>, now: Instant) {
    tombs.retain(|_, t| t.expires_at > now);
}

/// True while a non-expired tombstone blocks reclaim at `epoch` or below.
pub fn leave_tombstone_blocks(
    tombs: &HashMap<String, LeaveTombstone>,
    node_id: &str,
    claim_epoch: u64,
    now: Instant,
) -> bool {
    match tombs.get(node_id) {
        Some(t) if t.expires_at > now && claim_epoch <= t.vip_epoch => true,
        _ => false,
    }
}

/// Build MCLG digest: own claim first, then up to `max_others` live claims starting at
/// `start_idx` in the sorted-by-node_id list (rotation cursor).
pub fn build_gossip_digest(
    own: &ClaimRecord,
    map: &HashMap<String, ClaimRecord>,
    tombs: &HashMap<String, LeaveTombstone>,
    now: Instant,
    max_others: usize,
) -> Vec<ClaimRecord> {
    build_gossip_digest_rotated(own, map, tombs, now, max_others, 0)
}

/// Same as [`build_gossip_digest`] with an explicit rotation cursor into sorted others.
pub fn build_gossip_digest_rotated(
    own: &ClaimRecord,
    map: &HashMap<String, ClaimRecord>,
    tombs: &HashMap<String, LeaveTombstone>,
    now: Instant,
    max_others: usize,
    start_idx: usize,
) -> Vec<ClaimRecord> {
    let mut out = Vec::with_capacity(1 + max_others.min(map.len()));
    out.push(own.clone());
    let mut others: Vec<&ClaimRecord> = map
        .values()
        .filter(|c| c.node_id != own.node_id)
        .filter(|c| !leave_tombstone_blocks(tombs, &c.node_id, c.vip_epoch, now))
        .collect();
    others.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    if others.is_empty() || max_others == 0 {
        return out;
    }
    let n = others.len();
    let start = start_idx % n;
    for i in 0..max_others.min(n) {
        out.push(others[(start + i) % n].clone());
    }
    out
}

/// Compact leave-tomb list for MCLG (newest first by remaining TTL, capped).
pub fn select_leave_tombs_for_gossip(
    tombs: &HashMap<String, LeaveTombstone>,
    now: Instant,
    max: usize,
) -> Vec<LeaveTombstone> {
    let mut live: Vec<&LeaveTombstone> = tombs.values().filter(|t| t.expires_at > now).collect();
    live.sort_by(|a, b| b.expires_at.cmp(&a.expires_at));
    live.into_iter().take(max).cloned().collect()
}

/// Rotate fanout: take up to `cap` Active endpoints starting at `cursor`.
pub fn rotate_endpoints(
    eps: &[std::net::SocketAddr],
    cursor: usize,
    cap: usize,
) -> Vec<std::net::SocketAddr> {
    if eps.is_empty() || cap == 0 {
        return Vec::new();
    }
    let n = eps.len();
    let start = cursor % n;
    let take = cap.min(n);
    let mut out = Vec::with_capacity(take);
    for i in 0..take {
        out.push(eps[(start + i) % n]);
    }
    out
}

/// Remove a node from the claim map after leave (caller also installs tombstone).
pub fn remove_claim(map: &mut HashMap<String, ClaimRecord>, node_id: &str) -> Option<ClaimRecord> {
    map.remove(node_id)
}

/// True when route/roster may refresh from an IgnoredStale merge (canonical match).
pub fn stale_allows_ep_refresh(
    map: &HashMap<String, ClaimRecord>,
    node_id: &str,
    vip: &str,
    vip_epoch: u64,
) -> bool {
    match map.get(node_id) {
        Some(c) if c.vip == vip && c.vip_epoch == vip_epoch => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, vip: &str, epoch: u64) -> ClaimRecord {
        ClaimRecord {
            node_id: id.to_string(),
            vip: vip.to_string(),
            vip_epoch: epoch,
            ep_hints: vec![],
        }
    }

    #[test]
    fn epoch_lww_accepts_newer() {
        let mut map = HashMap::new();
        let tombs = HashMap::new();
        let mut suppress = HashMap::new();
        let now = Instant::now();
        assert_eq!(
            merge_claim(
                &mut map,
                rec("aaa", "10.0.0.2", 0),
                &tombs,
                &mut suppress,
                now
            ),
            MergeOutcome::Accepted
        );
        assert_eq!(
            merge_claim(
                &mut map,
                rec("aaa", "10.0.0.3", 1),
                &tombs,
                &mut suppress,
                now
            ),
            MergeOutcome::Accepted
        );
        assert_eq!(map["aaa"].vip, "10.0.0.3");
        assert_eq!(map["aaa"].vip_epoch, 1);
    }

    #[test]
    fn epoch_lww_ignores_stale() {
        let mut map = HashMap::new();
        let tombs = HashMap::new();
        let mut suppress = HashMap::new();
        let now = Instant::now();
        merge_claim(
            &mut map,
            rec("aaa", "10.0.0.3", 5),
            &tombs,
            &mut suppress,
            now,
        );
        assert_eq!(
            merge_claim(
                &mut map,
                rec("aaa", "10.0.0.2", 4),
                &tombs,
                &mut suppress,
                now
            ),
            MergeOutcome::IgnoredStale
        );
        assert_eq!(map["aaa"].vip, "10.0.0.3");
    }

    #[test]
    fn equal_epoch_same_vip_noop() {
        let mut map = HashMap::new();
        let tombs = HashMap::new();
        let mut suppress = HashMap::new();
        let now = Instant::now();
        merge_claim(
            &mut map,
            rec("aaa", "10.0.0.2", 1),
            &tombs,
            &mut suppress,
            now,
        );
        assert_eq!(
            merge_claim(
                &mut map,
                rec("aaa", "10.0.0.2", 1),
                &tombs,
                &mut suppress,
                now
            ),
            MergeOutcome::IgnoredStale
        );
    }

    #[test]
    fn equal_epoch_conflicting_vip_keeps_existing() {
        let mut map = HashMap::new();
        let tombs = HashMap::new();
        let mut suppress = HashMap::new();
        let now = Instant::now();
        merge_claim(
            &mut map,
            rec("aaa", "10.0.0.2", 1),
            &tombs,
            &mut suppress,
            now,
        );
        assert_eq!(
            merge_claim(
                &mut map,
                rec("aaa", "10.0.0.9", 1),
                &tombs,
                &mut suppress,
                now
            ),
            MergeOutcome::IgnoredStale
        );
        assert_eq!(map["aaa"].vip, "10.0.0.2");
    }

    #[test]
    fn vip_fight_lower_node_wins() {
        assert!(should_reroll_for_vip_fight(
            "bbb", "10.0.0.5", "aaa", "10.0.0.5"
        ));
        assert!(!should_reroll_for_vip_fight(
            "aaa", "10.0.0.5", "bbb", "10.0.0.5"
        ));
        assert!(!should_reroll_for_vip_fight(
            "aaa", "10.0.0.5", "bbb", "10.0.0.6"
        ));
    }

    #[test]
    fn settle_drops_lex_loser() {
        let mut map = HashMap::new();
        map.insert("bbb".into(), rec("bbb", "10.0.0.5", 0));
        map.insert("aaa".into(), rec("aaa", "10.0.0.5", 0));
        map.insert("ccc".into(), rec("ccc", "10.0.0.6", 0));
        let losers = settle_duplicate_vips(&mut map);
        assert!(losers.contains(&"bbb".to_string()));
        assert!(!map.contains_key("bbb"));
        assert!(map.contains_key("aaa"));
        assert!(map.contains_key("ccc"));
    }

    #[test]
    fn digest_rotates_past_first_n() {
        let mut map = HashMap::new();
        let tombs = HashMap::new();
        let now = Instant::now();
        for i in 0..5u8 {
            let id = format!("n{i}");
            map.insert(id.clone(), rec(&id, &format!("10.0.0.{}", i + 1), 0));
        }
        let own = rec("zzz", "10.0.0.9", 1);
        let dig0 = build_gossip_digest_rotated(&own, &map, &tombs, now, 2, 0);
        let dig2 = build_gossip_digest_rotated(&own, &map, &tombs, now, 2, 2);
        assert_eq!(dig0[1].node_id, "n0");
        assert_eq!(dig0[2].node_id, "n1");
        assert_eq!(dig2[1].node_id, "n2");
        assert_eq!(dig2[2].node_id, "n3");
    }

    #[test]
    fn tombstone_blocks_stale_reclaim() {
        let mut map = HashMap::new();
        let mut tombs = HashMap::new();
        let mut suppress = HashMap::new();
        let now = Instant::now();
        assert!(install_leave_tombstone(
            &mut tombs,
            "aaa",
            "10.0.0.2",
            3,
            now,
            LEAVE_TOMBSTONE_TTL
        ));
        assert_eq!(
            merge_claim(
                &mut map,
                rec("aaa", "10.0.0.2", 3),
                &tombs,
                &mut suppress,
                now
            ),
            MergeOutcome::BlockedByTombstone
        );
        assert_eq!(
            merge_claim(
                &mut map,
                rec("aaa", "10.0.0.2", 2),
                &tombs,
                &mut suppress,
                now
            ),
            MergeOutcome::BlockedByTombstone
        );
    }

    #[test]
    fn newer_epoch_after_tombstone_allowed_when_expired() {
        let mut map = HashMap::new();
        let mut tombs = HashMap::new();
        let mut suppress = HashMap::new();
        let now = Instant::now();
        install_leave_tombstone(
            &mut tombs,
            "aaa",
            "10.0.0.2",
            3,
            now,
            Duration::from_millis(1),
        );
        let later = now + Duration::from_secs(1);
        prune_leave_tombstones(&mut tombs, later);
        assert_eq!(
            merge_claim(
                &mut map,
                rec("aaa", "10.0.0.4", 4),
                &tombs,
                &mut suppress,
                later
            ),
            MergeOutcome::Accepted
        );
    }

    #[test]
    fn newer_epoch_beats_active_tombstone() {
        let mut map = HashMap::new();
        let mut tombs = HashMap::new();
        let mut suppress = HashMap::new();
        let now = Instant::now();
        install_leave_tombstone(&mut tombs, "aaa", "10.0.0.2", 3, now, LEAVE_TOMBSTONE_TTL);
        assert_eq!(
            merge_claim(
                &mut map,
                rec("aaa", "10.0.0.4", 4),
                &tombs,
                &mut suppress,
                now
            ),
            MergeOutcome::Accepted
        );
    }

    #[test]
    fn fight_suppress_blocks_identical_triple() {
        let mut map = HashMap::new();
        let tombs = HashMap::new();
        let mut suppress = HashMap::new();
        let now = Instant::now();
        assert!(install_fight_suppress(
            &mut suppress,
            "bbb",
            "10.0.0.5",
            0,
            now,
            FIGHT_SUPPRESS_TTL
        ));
        assert_eq!(
            merge_claim(
                &mut map,
                rec("bbb", "10.0.0.5", 0),
                &tombs,
                &mut suppress,
                now
            ),
            MergeOutcome::BlockedByFight
        );
        assert_eq!(
            merge_claim(
                &mut map,
                rec("bbb", "10.0.0.5", 1),
                &tombs,
                &mut suppress,
                now
            ),
            MergeOutcome::Accepted
        );
        map.clear();
        assert_eq!(
            merge_claim(
                &mut map,
                rec("bbb", "10.0.0.6", 0),
                &tombs,
                &mut suppress,
                now
            ),
            MergeOutcome::Accepted
        );
    }

    #[test]
    fn fight_suppress_prunes_on_expiry() {
        let mut map = HashMap::new();
        let tombs = HashMap::new();
        let mut suppress = HashMap::new();
        let now = Instant::now();
        install_fight_suppress(
            &mut suppress,
            "bbb",
            "10.0.0.5",
            0,
            now,
            Duration::from_millis(1),
        );
        let later = now + Duration::from_secs(1);
        prune_fight_suppress(&mut suppress, later);
        assert_eq!(
            merge_claim(
                &mut map,
                rec("bbb", "10.0.0.5", 0),
                &tombs,
                &mut suppress,
                later
            ),
            MergeOutcome::Accepted
        );
    }

    #[test]
    fn fight_suppress_slides_ttl_on_repeated_block() {
        let mut map = HashMap::new();
        let tombs = HashMap::new();
        let mut suppress = HashMap::new();
        let t0 = Instant::now();
        install_fight_suppress(
            &mut suppress,
            "bbb",
            "10.0.0.5",
            0,
            t0,
            Duration::from_millis(50),
        );
        let t1 = t0 + Duration::from_millis(40);
        assert_eq!(
            merge_claim(
                &mut map,
                rec("bbb", "10.0.0.5", 0),
                &tombs,
                &mut suppress,
                t1
            ),
            MergeOutcome::BlockedByFight
        );
        // Without slide, suppress would expire at t0+50ms; after slide it lasts FIGHT_SUPPRESS_TTL.
        let t2 = t0 + Duration::from_millis(80);
        assert_eq!(
            merge_claim(
                &mut map,
                rec("bbb", "10.0.0.5", 0),
                &tombs,
                &mut suppress,
                t2
            ),
            MergeOutcome::BlockedByFight
        );
        assert!(suppress["bbb"].expires_at > t2);
    }

    #[test]
    fn remove_claims_for_vip_drops_all_matching() {
        let mut map = HashMap::new();
        map.insert("aaa".into(), rec("aaa", "10.0.0.5", 0));
        map.insert("bbb".into(), rec("bbb", "10.0.0.6", 0));
        map.insert("ccc".into(), rec("ccc", "10.0.0.5", 1));
        let removed = remove_claims_for_vip(&mut map, "10.0.0.5");
        assert_eq!(removed.len(), 2);
        assert!(!map.contains_key("aaa"));
        assert!(!map.contains_key("ccc"));
        assert!(map.contains_key("bbb"));
    }

    #[test]
    fn digest_includes_self_and_sorted_others() {
        let mut map = HashMap::new();
        let tombs = HashMap::new();
        let now = Instant::now();
        map.insert("ccc".into(), rec("ccc", "10.0.0.3", 0));
        map.insert("bbb".into(), rec("bbb", "10.0.0.2", 0));
        map.insert("aaa".into(), rec("aaa", "10.0.0.1", 0));
        let own = rec("zzz", "10.0.0.9", 1);
        let dig = build_gossip_digest(&own, &map, &tombs, now, 2);
        assert_eq!(dig[0].node_id, "zzz");
        assert_eq!(dig[1].node_id, "aaa");
        assert_eq!(dig[2].node_id, "bbb");
        assert_eq!(dig.len(), 3);
    }

    #[test]
    fn reject_invalid_vip() {
        let mut map = HashMap::new();
        let tombs = HashMap::new();
        let mut suppress = HashMap::new();
        let now = Instant::now();
        assert_eq!(
            merge_claim(
                &mut map,
                rec("aaa", "10.0.0.0", 0),
                &tombs,
                &mut suppress,
                now
            ),
            MergeOutcome::Rejected
        );
    }
}
