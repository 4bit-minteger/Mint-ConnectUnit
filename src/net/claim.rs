//! FloatUnit self-claimed VIP helpers.

use std::net::Ipv4Addr;

use crate::crypto::{derive_floatunit_subnet24, floatunit_subnet_base_vip, Key};

/// Lexicographically smaller hex `node_id` wins a VIP conflict.
#[inline]
pub fn node_id_wins(local_node_id: &str, remote_node_id: &str) -> bool {
    local_node_id < remote_node_id
}

/// True when remote claim should force the local peer to reroll.
#[inline]
pub fn local_loses_vip_conflict(local_node_id: &str, remote_node_id: &str) -> bool {
    !node_id_wins(local_node_id, remote_node_id) && local_node_id != remote_node_id
}

/// Pick a free host in `1..=254` under the /24-style prefix of `base_vip`.
/// `occupied` receives candidate VIP strings already taken (including local).
pub fn pick_free_vip(base_vip: &str, occupied: impl Fn(&str) -> bool) -> Option<String> {
    let octets: Vec<u8> = base_vip
        .split('.')
        .filter_map(|v| v.parse::<u8>().ok())
        .collect();
    if octets.len() != 4 {
        return None;
    }
    let prefix = [octets[0], octets[1], octets[2]];
    // Deterministic scan from a hash of base so rerolls don't always land on .1.
    let start = (octets[3] as u16).wrapping_mul(37).wrapping_add(17) % 254;
    for offset in 0..254u16 {
        let host = ((start + offset) % 254) as u8 + 1; // 1..=254
        let cand = format!("{}.{}.{}.{}", prefix[0], prefix[1], prefix[2], host);
        if !occupied(&cand) {
            return Some(cand);
        }
    }
    None
}

/// True when `vip` is a valid host inside the key-derived FloatUnit `/24`.
pub fn vip_in_floatunit_subnet(key: &Key, vip: &str) -> bool {
    if !claim_vip_valid(vip) {
        return false;
    }
    let Ok(ip) = vip.parse::<Ipv4Addr>() else {
        return false;
    };
    let o = ip.octets();
    let p = derive_floatunit_subnet24(key);
    o[0] == p[0] && o[1] == p[1] && o[2] == p[2]
}

/// Pick a random free host in the key-derived `/24` (used at mint/join).
pub fn random_member_vip_in_unit(key: &Key) -> String {
    use rand::Rng;
    let base = floatunit_subnet_base_vip(key);
    let p = derive_floatunit_subnet24(key);
    let mut rng = rand::thread_rng();
    // Prefer a random host; fall back to deterministic scan if unlucky collisions.
    for _ in 0..32 {
        let h: u8 = rng.gen_range(1..=254);
        let cand = format!("{}.{}.{}.{}", p[0], p[1], p[2], h);
        if claim_vip_valid(&cand) {
            return cand;
        }
    }
    pick_free_vip(&base, |_| false).unwrap_or_else(|| format!("{}.{}.{}.2", p[0], p[1], p[2]))
}

/// Resolve mint/join VIP: keep in-unit VIP, else re-pick inside the derived `/24`.
/// Returns `(vip, bumped)` where `bumped` means the saved VIP was replaced.
pub fn resolve_member_vip(key: &Key, existing: &str) -> (String, bool) {
    let existing = existing.trim();
    if !existing.is_empty() && vip_in_floatunit_subnet(key, existing) {
        return (existing.to_string(), false);
    }
    (random_member_vip_in_unit(key), true)
}

/// Validate a self-claimed VIP string for join/claim wire bodies.
pub fn claim_vip_valid(vip: &str) -> bool {
    let Ok(ip) = vip.parse::<Ipv4Addr>() else {
        return false;
    };
    !ip.is_unspecified()
        && !ip.is_broadcast()
        && !ip.is_multicast()
        && !ip.is_loopback()
        && ip.octets()[3] != 0
        && ip.octets()[3] != 255
}

/// Accept a VIP on FloatUnit claim/join/gossip/leave wire paths.
/// With a unit key, VIP must lie in the key-derived `/24`; without crypto, only
/// [`claim_vip_valid`] applies.
#[inline]
pub fn accept_wire_claim_vip(unit_key: Option<&Key>, vip: &str) -> bool {
    match unit_key {
        Some(k) => vip_in_floatunit_subnet(k, vip),
        None => claim_vip_valid(vip),
    }
}

/// Host `1..=254` inside the key-derived FloatUnit `/24`.
pub fn member_host_vip(key: &Key, host: u8) -> String {
    let p = derive_floatunit_subnet24(key);
    let h = if host == 0 || host == 255 { 1 } else { host };
    format!("{}.{}.{}.{}", p[0], p[1], p[2], h)
}

/// Same as [`member_host_vip`], as [`Ipv4Addr`].
pub fn member_host_ipv4(key: &Key, host: u8) -> Ipv4Addr {
    member_host_vip(key, host)
        .parse()
        .unwrap_or(Ipv4Addr::new(10, 0, 0, 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_node_id_wins() {
        assert!(node_id_wins("a", "b"));
        assert!(!node_id_wins("b", "a"));
        assert!(local_loses_vip_conflict("bbb", "aaa"));
        assert!(!local_loses_vip_conflict("aaa", "bbb"));
        assert!(!local_loses_vip_conflict("same", "same"));
    }

    #[test]
    fn pick_free_skips_occupied() {
        let base = "10.1.1.5";
        let got = pick_free_vip(base, |c| c == "10.1.1.5" || c.ends_with(".1")).unwrap();
        assert_ne!(got, "10.1.1.5");
        assert!(!got.ends_with(".1"));
        assert!(claim_vip_valid(&got));
    }

    #[test]
    fn claim_vip_rejects_junk() {
        assert!(!claim_vip_valid(""));
        assert!(!claim_vip_valid("10.0.0.0"));
        assert!(!claim_vip_valid("10.0.0.255"));
        assert!(claim_vip_valid("10.0.0.2"));
    }

    #[test]
    fn same_key_same_subnet() {
        let key = Key([0x42; 32]);
        let a = derive_floatunit_subnet24(&key);
        let b = derive_floatunit_subnet24(&key);
        assert_eq!(a, b);
        assert_eq!(a[0], 10);
        let vip = random_member_vip_in_unit(&key);
        assert!(vip_in_floatunit_subnet(&key, &vip));
        let other = Key([0x43; 32]);
        // Extremely unlikely equal for distinct keys; still must be valid /24 hosts.
        assert!(vip_in_floatunit_subnet(
            &other,
            &random_member_vip_in_unit(&other)
        ));
    }

    #[test]
    fn resolve_replaces_out_of_unit() {
        let key = Key([0x11; 32]);
        let (vip, bumped) = resolve_member_vip(&key, "203.0.113.9");
        assert!(bumped);
        assert!(vip_in_floatunit_subnet(&key, &vip));
        let (same, bumped2) = resolve_member_vip(&key, &vip);
        assert!(!bumped2);
        assert_eq!(same, vip);
    }

    #[test]
    fn accept_wire_requires_unit_subnet_when_keyed() {
        let key = Key([0xAB; 32]);
        let in_unit = member_host_vip(&key, 7);
        assert!(accept_wire_claim_vip(Some(&key), &in_unit));
        let p = derive_floatunit_subnet24(&key);
        let wrong_subnet = format!("{}.{}.{}.7", p[0], p[1].wrapping_add(1), p[2]);
        assert!(!accept_wire_claim_vip(Some(&key), &wrong_subnet));
        assert!(!accept_wire_claim_vip(Some(&key), "203.0.113.9"));
        assert!(accept_wire_claim_vip(None, "10.1.1.7"));
        assert!(!accept_wire_claim_vip(None, "10.1.1.0"));
    }
}
