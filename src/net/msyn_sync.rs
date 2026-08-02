//! Pure MSYN v4 body builders, sharding, assemble helpers, and peer-sync advance guards.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::routing::RouteSyncRow;

pub const MSYN_PROTO_VER: u64 = 4;
pub const MSYN_SCHEMA_VER: u64 = 1;
pub const MSYN_ASSEMBLE_MAX_BUFFERS_PER_FROM: usize = 8;
pub const MSYN_ASSEMBLE_MAX_PARTS_TOTAL: u64 = 64;
pub const MSYN_ASSEMBLE_TTL: Duration = Duration::from_secs(30);
/// Joiner apply window (and owner epoch send cap). Must stay in sync with ingest.
pub const MSYN_APPLY_MAX_ROUTES: usize = 1024;
pub const MSYN_APPLY_MAX_REMOVED: usize = 1024;
/// Bytes reserved so a JSON part wrapped as sealed `MCTL`+MSYN(+HB vip) fits under the
/// configured shard budget on the wire:
/// `MCTS(4)+ctr(6)+tag(16)+inner_tag(4)+flags(2)+vip_len(1)+vip(15)+msyn_len(4)`.
pub const MSYN_SHARD_WRAP_RESERVE: usize = 4 + 6 + 16 + 4 + 2 + 1 + 15 + 4;
const MSYN_JSON_BUDGET_FLOOR: usize = 256;

/// JSON packing budget derived from configured `msyn_shard_budget_bytes` (wire-oriented).
pub fn effective_msyn_json_budget(configured: usize) -> usize {
    configured
        .saturating_sub(MSYN_SHARD_WRAP_RESERVE)
        .max(MSYN_JSON_BUDGET_FLOOR)
}

pub fn collect_removed_vips(
    last: u64,
    tombs: &[(String, u64)],
    pending: Option<&HashSet<String>>,
) -> Vec<String> {
    let mut set = HashSet::new();
    for (vip, rev) in tombs {
        if *rev > last {
            set.insert(vip.clone());
        }
    }
    if let Some(p) = pending {
        for vip in p {
            set.insert(vip.clone());
        }
    }
    set.into_iter().collect()
}

pub fn peer_owes_removals(
    last: u64,
    tombs: &[(String, u64)],
    pending: Option<&HashSet<String>>,
) -> bool {
    if pending.is_some_and(|p| !p.is_empty()) {
        return true;
    }
    tombs.iter().any(|(_, rev)| *rev > last)
}

pub fn should_advance_peer_sync(
    sync_ok: bool,
    last: u64,
    tombs: &[(String, u64)],
    pending: Option<&HashSet<String>>,
) -> bool {
    sync_ok && !peer_owes_removals(last, tombs, pending)
}

/// After a successful MSYN send and `clear_pending_delivered`, advance when no VIPs remain
/// in this peer's `peer_pending_removals` (tombstones with `rev > last` alone must not block).
pub fn should_advance_peer_sync_after_send(
    sync_ok: bool,
    pending_after: Option<&HashSet<String>>,
) -> bool {
    sync_ok && !pending_after.is_some_and(|p| !p.is_empty())
}

/// After a successful MSYN send, drop VIPs that were included in `removed` from this peer's pending set.
pub fn clear_pending_delivered(pending: &mut HashSet<String>, removed_vips: &[String]) {
    for vip in removed_vips {
        pending.remove(vip);
    }
}

#[derive(Debug, Clone)]
pub struct MsynRouteItem {
    pub vip: String,
    pub ep: String,
    pub node_id: String,
}

impl MsynRouteItem {
    fn from_sync_row(r: &RouteSyncRow) -> Self {
        Self {
            vip: r.vip.as_ref().to_string(),
            ep: r.endpoint.to_string(),
            node_id: r.node_id.as_ref().to_string(),
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "vip": self.vip,
            "ep": self.ep,
            "node_id": self.node_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShardError {
    EntryTooLarge { kind: &'static str, bytes: usize },
    TooManyParts { parts: u32 },
    EpochTooLarge { routes: usize, removed: usize },
}

fn serialize_part(
    from_rev: u64,
    to_rev: u64,
    sync_id: u64,
    part_idx: u32,
    parts_total: u32,
    routes: &[MsynRouteItem],
    removed: &[String],
) -> String {
    let routes_json: Vec<Value> = routes.iter().map(|r| r.to_json()).collect();
    json!({
        "proto_ver": MSYN_PROTO_VER,
        "schema_ver": MSYN_SCHEMA_VER,
        "from_rev": from_rev,
        "to_rev": to_rev,
        "sync_id": sync_id,
        "part_idx": part_idx,
        "parts_total": parts_total,
        "routes": routes_json,
        "removed": removed,
    })
    .to_string()
}

/// Greedy-pack routes and removed into v4 parts under `budget` bytes each.
pub fn shard_msyn_epoch(
    from_rev: u64,
    to_rev: u64,
    sync_id: u64,
    routes: &[MsynRouteItem],
    removed: &[String],
    budget: usize,
) -> Result<Vec<String>, ShardError> {
    if routes.len() > MSYN_APPLY_MAX_ROUTES || removed.len() > MSYN_APPLY_MAX_REMOVED {
        return Err(ShardError::EpochTooLarge {
            routes: routes.len(),
            removed: removed.len(),
        });
    }

    #[derive(Default)]
    struct Acc {
        routes: Vec<MsynRouteItem>,
        removed: Vec<String>,
    }

    let mut finished: Vec<Acc> = Vec::new();
    let mut cur = Acc::default();

    let fits =
        |acc: &Acc, extra_route: Option<&MsynRouteItem>, extra_removed: Option<&str>| -> bool {
            let mut routes = acc.routes.clone();
            let mut removed = acc.removed.clone();
            if let Some(r) = extra_route {
                routes.push(r.clone());
            }
            if let Some(v) = extra_removed {
                removed.push(v.to_string());
            }
            // part_idx/parts_total placeholders — length stable enough for packing probe
            let probe = serialize_part(from_rev, to_rev, sync_id, 0, 1, &routes, &removed);
            probe.len() <= budget
        };

    let push_alone_route = |r: &MsynRouteItem| -> Result<Acc, ShardError> {
        let alone = Acc {
            routes: vec![r.clone()],
            removed: Vec::new(),
        };
        if !fits(&Acc::default(), Some(r), None) {
            let n = serialize_part(from_rev, to_rev, sync_id, 0, 1, &alone.routes, &[]).len();
            return Err(ShardError::EntryTooLarge {
                kind: "route",
                bytes: n,
            });
        }
        Ok(alone)
    };

    let push_alone_removed = |v: &str| -> Result<Acc, ShardError> {
        let alone = Acc {
            routes: Vec::new(),
            removed: vec![v.to_string()],
        };
        if !fits(&Acc::default(), None, Some(v)) {
            let n = serialize_part(from_rev, to_rev, sync_id, 0, 1, &[], &alone.removed).len();
            return Err(ShardError::EntryTooLarge {
                kind: "removed",
                bytes: n,
            });
        }
        Ok(alone)
    };

    for v in removed {
        if fits(&cur, None, Some(v.as_str())) {
            cur.removed.push(v.clone());
        } else {
            if !cur.routes.is_empty() || !cur.removed.is_empty() {
                finished.push(std::mem::take(&mut cur));
            }
            cur = push_alone_removed(v)?;
        }
    }
    for r in routes {
        if fits(&cur, Some(r), None) {
            cur.routes.push(r.clone());
        } else {
            if !cur.routes.is_empty() || !cur.removed.is_empty() {
                finished.push(std::mem::take(&mut cur));
            }
            cur = push_alone_route(r)?;
        }
    }
    if !cur.routes.is_empty() || !cur.removed.is_empty() || finished.is_empty() {
        finished.push(cur);
    }

    let parts_total = finished.len() as u32;
    if parts_total as u64 > MSYN_ASSEMBLE_MAX_PARTS_TOTAL {
        return Err(ShardError::TooManyParts { parts: parts_total });
    }
    let mut out = Vec::with_capacity(finished.len());
    for (idx, acc) in finished.into_iter().enumerate() {
        out.push(serialize_part(
            from_rev,
            to_rev,
            sync_id,
            idx as u32,
            parts_total,
            &acc.routes,
            &acc.removed,
        ));
    }
    Ok(out)
}

pub fn build_msyn_delta_shards(
    last: u64,
    current_rev: u64,
    sync_id: u64,
    snapshot: &[RouteSyncRow],
    tombs: &[(String, u64)],
    pending: Option<&HashSet<String>>,
    budget: usize,
) -> Result<Option<Vec<String>>, ShardError> {
    let routes: Vec<MsynRouteItem> = snapshot
        .iter()
        .filter(|r| r.last_modified_revision > last)
        .map(MsynRouteItem::from_sync_row)
        .collect();
    let removed = collect_removed_vips(last, tombs, pending);
    if routes.is_empty() && removed.is_empty() {
        return Ok(None);
    }
    Ok(Some(shard_msyn_epoch(
        last,
        current_rev,
        sync_id,
        &routes,
        &removed,
        budget,
    )?))
}

pub fn build_msyn_full_shards(
    to_rev: u64,
    sync_id: u64,
    routes: &[MsynRouteItem],
    removed: &[String],
    budget: usize,
) -> Result<Vec<String>, ShardError> {
    shard_msyn_epoch(0, to_rev, sync_id, routes, removed, budget)
}

pub fn routes_from_snapshot_non_stale(snapshot: &[RouteSyncRow]) -> Vec<MsynRouteItem> {
    snapshot
        .iter()
        .filter(|r| !matches!(r.state, crate::routing::RouteState::Stale))
        .map(MsynRouteItem::from_sync_row)
        .collect()
}

#[derive(Debug, Clone)]
pub struct MsynPartPayload {
    pub routes: Vec<Value>,
    pub removed: Vec<String>,
}

#[derive(Debug)]
pub struct PartialMsyn {
    pub sync_id: u64,
    pub from_rev: u64,
    pub to_rev: u64,
    pub parts_total: u32,
    pub parts: HashMap<u32, MsynPartPayload>,
    pub first_seen: Instant,
}

impl PartialMsyn {
    pub fn is_complete(&self) -> bool {
        self.parts_total > 0 && self.parts.len() as u32 == self.parts_total
    }

    pub fn assemble_removed_then_routes(&self) -> (Vec<String>, Vec<Value>) {
        let mut removed = Vec::new();
        let mut routes = Vec::new();
        for idx in 0..self.parts_total {
            if let Some(p) = self.parts.get(&idx) {
                removed.extend(p.removed.iter().cloned());
                routes.extend(p.routes.iter().cloned());
            }
        }
        (removed, routes)
    }
}

pub type MsynAssembleMap = HashMap<(SocketAddr, u64), PartialMsyn>;

#[derive(Debug)]
pub enum MsynIngestOutcome {
    Ignored,
    /// First valid part of a new incomplete epoch was accepted.
    Buffered {
        first_part: bool,
    },
    Complete(PartialMsyn),
}

fn parse_u64(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(|x| x.as_u64())
}

fn parse_u32(v: &Value, key: &str) -> Option<u32> {
    parse_u64(v, key).and_then(|x| u32::try_from(x).ok())
}

/// Sweep incomplete buffers older than TTL.
pub fn sweep_msyn_assemble(map: &mut MsynAssembleMap, now: Instant) {
    map.retain(|_, p| now.saturating_duration_since(p.first_seen) < MSYN_ASSEMBLE_TTL);
}

/// Drop oldest incomplete buffer for `from` when over cap.
fn enforce_buffer_cap(map: &mut MsynAssembleMap, from: SocketAddr) {
    let mut keys: Vec<(u64, Instant)> = map
        .iter()
        .filter(|((f, _), _)| *f == from)
        .map(|((_, sid), p)| (*sid, p.first_seen))
        .collect();
    if keys.len() <= MSYN_ASSEMBLE_MAX_BUFFERS_PER_FROM {
        return;
    }
    keys.sort_by_key(|(_, t)| *t);
    while keys.len() > MSYN_ASSEMBLE_MAX_BUFFERS_PER_FROM {
        if let Some((sid, _)) = keys.first().copied() {
            map.remove(&(from, sid));
            keys.remove(0);
        } else {
            break;
        }
    }
}

/// Ingest one v4 MSYN JSON object. Does not apply routing side effects.
pub fn ingest_msyn_part(
    map: &mut MsynAssembleMap,
    from: SocketAddr,
    v: &Value,
    applied_to_rev: u64,
    now: Instant,
) -> MsynIngestOutcome {
    sweep_msyn_assemble(map, now);

    let Some(proto_ver) = parse_u64(v, "proto_ver") else {
        return MsynIngestOutcome::Ignored;
    };
    if proto_ver != MSYN_PROTO_VER {
        return MsynIngestOutcome::Ignored;
    }
    let Some(schema_ver) = parse_u64(v, "schema_ver") else {
        return MsynIngestOutcome::Ignored;
    };
    if schema_ver != MSYN_SCHEMA_VER {
        return MsynIngestOutcome::Ignored;
    }
    let Some(sync_id) = parse_u64(v, "sync_id") else {
        return MsynIngestOutcome::Ignored;
    };
    let Some(from_rev) = parse_u64(v, "from_rev") else {
        return MsynIngestOutcome::Ignored;
    };
    let Some(to_rev) = parse_u64(v, "to_rev") else {
        return MsynIngestOutcome::Ignored;
    };
    let Some(part_idx) = parse_u32(v, "part_idx") else {
        return MsynIngestOutcome::Ignored;
    };
    let Some(parts_total) = parse_u32(v, "parts_total") else {
        return MsynIngestOutcome::Ignored;
    };
    if parts_total == 0 || parts_total as u64 > MSYN_ASSEMBLE_MAX_PARTS_TOTAL {
        return MsynIngestOutcome::Ignored;
    }
    if part_idx >= parts_total {
        return MsynIngestOutcome::Ignored;
    }
    if to_rev <= applied_to_rev {
        return MsynIngestOutcome::Ignored;
    }

    // Supersede incomplete buffers from same sender (different sync_id only).
    let stale_keys: Vec<(SocketAddr, u64)> = map
        .iter()
        .filter(|((f, _), p)| {
            *f == from && p.sync_id != sync_id && (p.to_rev < to_rev || p.to_rev == to_rev)
        })
        .map(|(k, _)| *k)
        .collect();
    for k in stale_keys {
        map.remove(&k);
    }

    // Lower to_rev than an incomplete buffer for this from → ignore.
    if map
        .iter()
        .any(|((f, _), p)| *f == from && p.sync_id != sync_id && p.to_rev > to_rev)
    {
        return MsynIngestOutcome::Ignored;
    }

    let routes = v
        .get("routes")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let removed: Vec<String> = v
        .get("removed")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let key = (from, sync_id);
    let first_part;
    if let Some(existing) = map.get_mut(&key) {
        if existing.parts_total != parts_total
            || existing.from_rev != from_rev
            || existing.to_rev != to_rev
        {
            map.remove(&key);
            return MsynIngestOutcome::Ignored;
        }
        existing
            .parts
            .insert(part_idx, MsynPartPayload { routes, removed });
        first_part = false;
    } else {
        let mut parts = HashMap::new();
        parts.insert(part_idx, MsynPartPayload { routes, removed });
        map.insert(
            key,
            PartialMsyn {
                sync_id,
                from_rev,
                to_rev,
                parts_total,
                parts,
                first_seen: now,
            },
        );
        first_part = true;
        enforce_buffer_cap(map, from);
    }

    let Some(buf) = map.get(&key) else {
        return MsynIngestOutcome::Ignored;
    };
    if buf.is_complete() {
        let complete = map.remove(&key).expect("just checked");
        MsynIngestOutcome::Complete(complete)
    } else {
        MsynIngestOutcome::Buffered { first_part }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t1_tomb_rev_gt_last_in_removed() {
        let tombs = vec![("10.0.0.3".to_string(), 6u64)];
        let parts = build_msyn_delta_shards(3, 6, 1, &[], &tombs, None, 1200)
            .unwrap()
            .expect("body");
        assert_eq!(parts.len(), 1);
        let v: Value = serde_json::from_str(&parts[0]).unwrap();
        assert_eq!(v.get("proto_ver").and_then(|x| x.as_u64()), Some(4));
        let removed = v.get("removed").and_then(|x| x.as_array()).unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].as_str(), Some("10.0.0.3"));
    }

    #[test]
    fn t4_pending_only_produces_removed_body() {
        let mut pending = HashSet::new();
        pending.insert("10.0.0.5".to_string());
        let parts = build_msyn_delta_shards(5, 6, 2, &[], &[], Some(&pending), 1200)
            .unwrap()
            .expect("pending must produce body");
        let v: Value = serde_json::from_str(&parts[0]).unwrap();
        assert!(v
            .get("routes")
            .and_then(|x| x.as_array())
            .unwrap()
            .is_empty());
        let removed = v.get("removed").and_then(|x| x.as_array()).unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(v.get("part_idx").and_then(|x| x.as_u64()), Some(0));
        assert_eq!(v.get("parts_total").and_then(|x| x.as_u64()), Some(1));
    }

    #[test]
    fn should_not_advance_when_pending_owed() {
        let mut pending = HashSet::new();
        pending.insert("10.0.0.5".to_string());
        assert!(!should_advance_peer_sync(true, 5, &[], Some(&pending)));
    }

    #[test]
    fn should_not_advance_when_tomb_owed() {
        let tombs = vec![("10.0.0.3".to_string(), 6u64)];
        assert!(!should_advance_peer_sync(true, 3, &tombs, None));
    }

    #[test]
    fn should_advance_when_nothing_owed() {
        assert!(should_advance_peer_sync(true, 6, &[], None));
    }

    #[test]
    fn after_send_advances_when_pending_empty() {
        assert!(should_advance_peer_sync_after_send(true, None));
        let empty = HashSet::new();
        assert!(should_advance_peer_sync_after_send(true, Some(&empty)));
    }

    #[test]
    fn after_send_blocked_when_pending_nonempty() {
        let mut pending = HashSet::new();
        pending.insert("10.0.0.5".to_string());
        assert!(!should_advance_peer_sync_after_send(true, Some(&pending)));
        assert!(!should_advance_peer_sync_after_send(false, None));
    }

    #[test]
    fn shards_split_under_small_budget() {
        let routes: Vec<_> = (0..20)
            .map(|i| MsynRouteItem {
                vip: format!("10.0.0.{}", i + 2),
                ep: format!("198.51.100.{}:4000", i + 1),
                node_id: format!("node-{i}"),
            })
            .collect();
        let parts = build_msyn_full_shards(3, 9, &routes, &[], 350).unwrap();
        assert!(parts.len() > 1);
        for (i, p) in parts.iter().enumerate() {
            assert!(p.len() <= 350, "part {i} len {}", p.len());
            let v: Value = serde_json::from_str(p).unwrap();
            assert_eq!(v["parts_total"].as_u64(), Some(parts.len() as u64));
            assert_eq!(v["part_idx"].as_u64(), Some(i as u64));
            assert_eq!(v["proto_ver"].as_u64(), Some(4));
        }
    }

    #[test]
    fn assemble_removed_then_routes_order() {
        let from: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut map = MsynAssembleMap::new();
        let now = Instant::now();
        let p0 = json!({
            "proto_ver": 4, "schema_ver": 1, "from_rev": 0, "to_rev": 5,
            "sync_id": 1, "part_idx": 0, "parts_total": 2,
            "routes": [{"vip":"10.0.0.2","ep":"1.1.1.1:1","node_id":"a"}],
            "removed": []
        });
        let p1 = json!({
            "proto_ver": 4, "schema_ver": 1, "from_rev": 0, "to_rev": 5,
            "sync_id": 1, "part_idx": 1, "parts_total": 2,
            "routes": [],
            "removed": ["10.0.0.9"]
        });
        assert!(matches!(
            ingest_msyn_part(&mut map, from, &p0, 0, now),
            MsynIngestOutcome::Buffered { first_part: true }
        ));
        let MsynIngestOutcome::Complete(done) = ingest_msyn_part(&mut map, from, &p1, 0, now)
        else {
            panic!("expected complete");
        };
        let (removed, routes) = done.assemble_removed_then_routes();
        assert_eq!(removed, vec!["10.0.0.9".to_string()]);
        assert_eq!(routes.len(), 1);
    }

    #[test]
    fn envelope_mismatch_drops_buffer() {
        let from: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let mut map = MsynAssembleMap::new();
        let now = Instant::now();
        let p0 = json!({
            "proto_ver": 4, "schema_ver": 1, "from_rev": 0, "to_rev": 5,
            "sync_id": 3, "part_idx": 0, "parts_total": 2,
            "routes": [], "removed": []
        });
        let bad = json!({
            "proto_ver": 4, "schema_ver": 1, "from_rev": 0, "to_rev": 5,
            "sync_id": 3, "part_idx": 1, "parts_total": 3,
            "routes": [], "removed": []
        });
        let _ = ingest_msyn_part(&mut map, from, &p0, 0, now);
        assert!(matches!(
            ingest_msyn_part(&mut map, from, &bad, 0, now),
            MsynIngestOutcome::Ignored
        ));
        assert!(map.get(&(from, 3)).is_none());
    }

    #[test]
    fn too_many_parts_errors_instead_of_emitting() {
        // One route per part under a tight budget → 65 parts exceeds assemble max (64).
        let routes: Vec<_> = (0..65)
            .map(|i| MsynRouteItem {
                vip: format!("10.0.{}.{}", i / 250 + 1, (i % 250) + 2),
                ep: format!("198.51.100.{}:4000", (i % 200) + 1),
                node_id: format!("node-{i}"),
            })
            .collect();
        let err = build_msyn_full_shards(1, 1, &routes, &[], 200).unwrap_err();
        assert!(
            matches!(err, ShardError::TooManyParts { parts: 65 }),
            "{err:?}"
        );
    }

    #[test]
    fn epoch_over_apply_cap_errors() {
        let routes: Vec<_> = (0..MSYN_APPLY_MAX_ROUTES + 1)
            .map(|i| MsynRouteItem {
                vip: format!("10.{}.{}.{}", (i / 65025) + 1, (i / 255) % 256, i % 255 + 1),
                ep: format!("203.0.113.{}:9", (i % 200) + 1),
                node_id: format!("n{i}"),
            })
            .collect();
        let err = build_msyn_full_shards(1, 1, &routes, &[], 1200).unwrap_err();
        assert!(
            matches!(
                err,
                ShardError::EpochTooLarge {
                    routes: n,
                    ..
                } if n == MSYN_APPLY_MAX_ROUTES + 1
            ),
            "{err:?}"
        );
    }

    #[test]
    fn effective_json_budget_reserves_wrap() {
        assert_eq!(
            effective_msyn_json_budget(1200),
            1200 - MSYN_SHARD_WRAP_RESERVE
        );
        assert_eq!(effective_msyn_json_budget(10), MSYN_JSON_BUDGET_FLOOR);
    }
}
