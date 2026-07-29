//! Pure MSYN delta/full body builders and peer-sync advance guards.

use std::collections::HashSet;

use serde_json::json;

use crate::routing::RouteSyncRow;

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

pub fn build_msyn_delta_body(
    last: u64,
    current_rev: u64,
    snapshot: &[RouteSyncRow],
    tombs: &[(String, u64)],
    pending: Option<&HashSet<String>>,
) -> Option<String> {
    let routes_delta: Vec<serde_json::Value> = snapshot
        .iter()
        .filter(|r| r.last_modified_revision > last)
        .map(|r| {
            json!({
                "vip": r.vip.as_ref(),
                "ep": r.endpoint.to_string(),
                "node_id": r.node_id.as_ref(),
            })
        })
        .collect();
    let removed: Vec<String> = collect_removed_vips(last, tombs, pending);
    if routes_delta.is_empty() && removed.is_empty() {
        return None;
    }
    let removed_json: Vec<&str> = removed.iter().map(|s| s.as_str()).collect();
    Some(
        json!({
            "proto_ver": 3,
            "schema_ver": 1,
            "from_rev": last,
            "to_rev": current_rev,
            "routes": routes_delta,
            "removed": removed_json,
        })
        .to_string(),
    )
}

pub fn msyn_full_body_string(to_rev: u64, routes_full_json: &str, removed_vips: &[&str]) -> String {
    let removed_json = serde_json::to_string(removed_vips).unwrap_or_else(|_| "[]".into());
    format!(
        r#"{{"proto_ver":3,"schema_ver":1,"from_rev":0,"to_rev":{},"routes":{},"removed":{}}}"#,
        to_rev, routes_full_json, removed_json
    )
}

/// After a successful MSYN send, drop VIPs that were included in `removed` from this peer's pending set.
pub fn clear_pending_delivered(pending: &mut HashSet<String>, removed_vips: &[String]) {
    for vip in removed_vips {
        pending.remove(vip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t1_tomb_rev_gt_last_in_removed() {
        let tombs = vec![("10.0.0.3".to_string(), 6u64)];
        let body = build_msyn_delta_body(3, 6, &[], &tombs, None).expect("body");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let removed = v.get("removed").and_then(|x| x.as_array()).unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].as_str(), Some("10.0.0.3"));
    }

    #[test]
    fn t4_pending_only_produces_removed_body() {
        let mut pending = HashSet::new();
        pending.insert("10.0.0.5".to_string());
        let body = build_msyn_delta_body(5, 6, &[], &[], Some(&pending))
            .expect("pending must produce body");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v
            .get("routes")
            .and_then(|x| x.as_array())
            .unwrap()
            .is_empty());
        let removed = v.get("removed").and_then(|x| x.as_array()).unwrap();
        assert_eq!(removed.len(), 1);
    }

    #[test]
    fn should_not_advance_when_pending_owed() {
        let mut pending = HashSet::new();
        pending.insert("10.0.0.5".to_string());
        assert!(!should_advance_peer_sync(true, 5, &[], Some(&pending)));
    }

    #[test]
    fn should_not_advance_when_tomb_owed() {
        // Pre-send `should_advance_peer_sync` only (tomb rev > last blocks before send).
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
}
