use std::collections::hash_map::RandomState;
use std::collections::{HashSet, VecDeque};
use std::hash::{BuildHasher, Hash, Hasher};
use std::time::{Duration, Instant};

pub struct BroadcastDeduplicator {
    seen: HashSet<u128>,
    timeline: VecDeque<(Instant, u128)>,
    hasher_state: RandomState,
}

impl BroadcastDeduplicator {
    const TTL: Duration = Duration::from_millis(2000);
    const MAX_CACHE: usize = 4096;

    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
            timeline: VecDeque::new(),
            hasher_state: RandomState::new(),
        }
    }

    pub fn is_fresh(&mut self, packet: &[u8]) -> bool {
        self.evict();
        let key = self.make_key(packet);
        if self.seen.contains(&key) {
            return false;
        }
        self.seen.insert(key);
        self.timeline.push_back((Instant::now(), key));
        if self.timeline.len() > Self::MAX_CACHE {
            if let Some((_, old)) = self.timeline.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }

    pub fn is_fresh_scoped(&mut self, scope: &[u8], packet: &[u8]) -> bool {
        self.evict();
        let key = self.make_scoped_key(scope, packet);
        if self.seen.contains(&key) {
            return false;
        }
        self.seen.insert(key);
        self.timeline.push_back((Instant::now(), key));
        if self.timeline.len() > Self::MAX_CACHE {
            if let Some((_, old)) = self.timeline.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }

    fn evict(&mut self) {
        let now = Instant::now();
        while let Some((t, key)) = self.timeline.front().copied() {
            if now.duration_since(t) < Self::TTL {
                break;
            }
            self.timeline.pop_front();
            self.seen.remove(&key);
        }
    }

    fn make_key(&self, packet: &[u8]) -> u128 {
        let mut hasher_a = self.hasher_state.build_hasher();
        let mut hasher_b = self.hasher_state.build_hasher();
        b"mint-bcast-key-a".hash(&mut hasher_a);
        b"mint-bcast-key-b".hash(&mut hasher_b);
        let prefix = packet.len().min(128);
        if prefix >= 20 {
            let mut header = [0u8; 20];
            header.copy_from_slice(&packet[..20]);
            header[8] = 0;
            header[10] = 0;
            header[11] = 0;
            header.hash(&mut hasher_a);
            header.hash(&mut hasher_b);
            if prefix > 20 {
                packet[20..prefix].hash(&mut hasher_a);
                packet[20..prefix].hash(&mut hasher_b);
            }
        } else {
            let mut short = [0u8; 20];
            short[..prefix].copy_from_slice(&packet[..prefix]);
            if prefix > 8 {
                short[8] = 0;
            }
            if prefix > 11 {
                short[10] = 0;
                short[11] = 0;
            }
            short[..prefix].hash(&mut hasher_a);
            short[..prefix].hash(&mut hasher_b);
        }
        if packet.len() > 128 {
            let tail = &packet[packet.len().saturating_sub(32)..];
            tail.hash(&mut hasher_a);
            tail.hash(&mut hasher_b);
        }
        packet.len().hash(&mut hasher_a);
        packet.len().hash(&mut hasher_b);
        let hi = hasher_a.finish() as u128;
        let lo = hasher_b.finish().rotate_left(13) as u128;
        (hi << 64) | lo
    }

    fn make_scoped_key(&self, scope: &[u8], packet: &[u8]) -> u128 {
        let key = self.make_key(packet);
        let mut scope_hasher = self.hasher_state.build_hasher();
        b"mint-bcast-scope".hash(&mut scope_hasher);
        scope.hash(&mut scope_hasher);
        let scope_hash = scope_hasher.finish();
        let mixed = scope_hash.wrapping_mul(0x9E37_79B1_85EB_CA87);
        let scope_key = ((mixed as u128) << 64) | (mixed.rotate_left(17) as u128);
        key.rotate_left(29) ^ scope_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_includes_payload_prefix_to_reduce_collisions() {
        let d = BroadcastDeduplicator::new();
        let mut pkt_a = [0u8; 40];
        let mut pkt_b = [0u8; 40];
        pkt_a[0] = 0x45;
        pkt_b[0] = 0x45;
        pkt_a[16..20].copy_from_slice(&[10, 0, 0, 255]);
        pkt_b[16..20].copy_from_slice(&[10, 0, 0, 255]);
        pkt_a[20..28].copy_from_slice(b"payload1");
        pkt_b[20..28].copy_from_slice(b"payload2");
        assert_ne!(d.make_key(&pkt_a), d.make_key(&pkt_b));
    }

    #[test]
    fn key_distinguishes_packets_differing_after_64_bytes() {
        let d = BroadcastDeduplicator::new();
        let mut base = vec![0x45u8; 80];
        base[16..20].copy_from_slice(&[10, 0, 0, 5]);
        let mut a = base.clone();
        let mut b = base;
        a[70] = 0x01;
        b[70] = 0x02;
        assert_ne!(d.make_key(&a), d.make_key(&b));
    }

    #[test]
    fn key_distinguishes_same_prefix_different_lengths() {
        let d = BroadcastDeduplicator::new();
        let short = vec![0x45u8; 40];
        let mut long = vec![0x45u8; 50];
        long[..40].copy_from_slice(&short);
        assert_ne!(d.make_key(&short), d.make_key(&long));
    }

    #[test]
    fn key_distinguishes_same_first_128_different_tail() {
        let d = BroadcastDeduplicator::new();
        let mut a = vec![0x45u8; 200];
        let mut b = a.clone();
        a[16..20].copy_from_slice(&[10, 0, 0, 5]);
        b[16..20].copy_from_slice(&[10, 0, 0, 5]);
        a[180] = 1;
        b[180] = 2;
        assert_ne!(d.make_key(&a), d.make_key(&b));
    }

    #[test]
    fn scoped_dedup_keeps_same_payload_for_different_scope() {
        let mut d = BroadcastDeduplicator::new();
        let pkt = vec![1u8; 64];
        assert!(d.is_fresh_scoped(b"peer-a", &pkt));
        assert!(d.is_fresh_scoped(b"peer-b", &pkt));
        assert!(!d.is_fresh_scoped(b"peer-a", &pkt));
    }
}
