//! Size-bucketed RX loss / rate tracker for PMTUD data-plane corroboration (H-5).
//! O(1) per packet, fixed buckets, no heap alloc on the hot path beyond HashMap entry insert.

use crate::pmtud::SizeHealth;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const BUCKET_COUNT: usize = 4;
const EWMA_ALPHA: f64 = 0.2;
const WARM_COMMITS: u64 = 64;
const WARM_MIN_COMMITS: u64 = 8;
const WARM_AGE: Duration = Duration::from_secs(3);
const LARGE_ALIVE_RATE: f64 = 2.0;
const LARGE_COLLAPSED_LARGE_MAX: f64 = 0.5;
const LARGE_COLLAPSED_SMALL_MIN: f64 = 2.0;
const LARGE_ALIVE_MEMORY: Duration = Duration::from_secs(10);
const TX_OFFER_RECENT: Duration = Duration::from_secs(1);
const GAP_CLAMP: u64 = 64;
const RATE_TICK: Duration = Duration::from_millis(100);

#[derive(Clone, Debug)]
struct Bucket {
    /// EWMA packet rate (pkt/s).
    rate: f64,
    /// Packets since last rate tick.
    pending: u64,
    last_tick: Instant,
}

impl Bucket {
    fn new(now: Instant) -> Self {
        Self {
            rate: 0.0,
            pending: 0,
            last_tick: now,
        }
    }

    fn note(&mut self, now: Instant) {
        self.flush(now);
        self.pending = self.pending.saturating_add(1);
    }

    fn note_n(&mut self, n: u64, now: Instant) {
        if n == 0 {
            return;
        }
        self.flush(now);
        self.pending = self.pending.saturating_add(n);
    }

    fn flush(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_tick);
        if elapsed < RATE_TICK {
            return;
        }
        let secs = elapsed.as_secs_f64().max(1e-3);
        let sample = self.pending as f64 / secs;
        self.rate = if self.rate == 0.0 && self.pending == 0 {
            0.0
        } else {
            EWMA_ALPHA * sample + (1.0 - EWMA_ALPHA) * self.rate
        };
        self.pending = 0;
        self.last_tick = now;
    }
}

#[derive(Clone, Debug)]
struct VipTracker {
    buckets: [Bucket; BUCKET_COUNT],
    created_at: Instant,
    commits: u64,
    last_large_alive_at: Option<Instant>,
    last_tx_offer_at: Option<Instant>,
    /// True once encrypted path observed a gap-capable commit (enables large_collapsed).
    encrypted_seen: bool,
}

impl VipTracker {
    fn new(now: Instant) -> Self {
        Self {
            buckets: std::array::from_fn(|_| Bucket::new(now)),
            created_at: now,
            commits: 0,
            last_large_alive_at: None,
            last_tx_offer_at: None,
            encrypted_seen: false,
        }
    }

    fn warm(&self, now: Instant) -> bool {
        self.commits >= WARM_COMMITS
            || (now.saturating_duration_since(self.created_at) >= WARM_AGE
                && self.commits >= WARM_MIN_COMMITS)
    }

    fn flush_all(&mut self, now: Instant) {
        for b in &mut self.buckets {
            b.flush(now);
        }
    }

    fn large_rate(&self) -> f64 {
        // buckets 2 (>1000) + 3 (>1300)
        self.buckets[2].rate + self.buckets[3].rate
    }

    fn small_rate(&self) -> f64 {
        self.buckets[0].rate
    }

    fn health(&mut self, now: Instant) -> SizeHealth {
        self.flush_all(now);
        let warm = self.warm(now);
        let large = self.large_rate();
        let large_alive = warm && large >= LARGE_ALIVE_RATE;
        if large_alive {
            self.last_large_alive_at = Some(now);
        }
        let had_large = self
            .last_large_alive_at
            .map(|t| now.saturating_duration_since(t) <= LARGE_ALIVE_MEMORY)
            .unwrap_or(false);
        let tx_offer = self
            .last_tx_offer_at
            .map(|t| now.saturating_duration_since(t) <= TX_OFFER_RECENT)
            .unwrap_or(false);
        let large_collapsed = warm
            && self.encrypted_seen
            && had_large
            && large < LARGE_COLLAPSED_LARGE_MAX
            && self.small_rate() >= LARGE_COLLAPSED_SMALL_MIN
            && tx_offer;
        SizeHealth {
            warm,
            large_alive,
            large_collapsed,
        }
    }
}

#[inline]
pub fn bucket_index(frame_len: usize) -> usize {
    if frame_len <= 600 {
        0
    } else if frame_len <= 1000 {
        1
    } else if frame_len <= 1300 {
        2
    } else {
        3
    }
}

/// Per-VIP size-bucketed RX rate / gap tracker.
#[derive(Default)]
pub struct SizeLossTable {
    by_vip: HashMap<u32, VipTracker>,
}

impl SizeLossTable {
    pub fn new() -> Self {
        Self {
            by_vip: HashMap::new(),
        }
    }

    fn entry(&mut self, vip: u32, now: Instant) -> &mut VipTracker {
        self.by_vip
            .entry(vip)
            .or_insert_with(|| VipTracker::new(now))
    }

    /// Plain or encrypted RX rate sample (no gap).
    pub fn note_rx(&mut self, vip: u32, frame_len: usize, now: Instant) {
        let t = self.entry(vip, now);
        t.commits = t.commits.saturating_add(1);
        t.buckets[bucket_index(frame_len)].note(now);
    }

    /// Encrypted commit: RX rate + optional gap attributed to reveal frame bucket (biased).
    pub fn note_encrypted_commit(&mut self, vip: u32, frame_len: usize, gap: u64, now: Instant) {
        let t = self.entry(vip, now);
        t.encrypted_seen = true;
        t.commits = t.commits.saturating_add(1);
        let idx = bucket_index(frame_len);
        t.buckets[idx].note(now);
        let g = gap.min(GAP_CLAMP);
        if g > 0 {
            // Bias: lost packets attributed to reveal bucket — documented in plan.
            t.buckets[idx].note_n(g, now);
        }
    }

    pub fn note_tx_offer(&mut self, vip: u32, frame_len: usize, now: Instant) {
        if frame_len <= 1000 {
            return;
        }
        let t = self.entry(vip, now);
        t.last_tx_offer_at = Some(now);
    }

    pub fn health(&mut self, vip: u32, now: Instant) -> SizeHealth {
        match self.by_vip.get_mut(&vip) {
            Some(t) => t.health(now),
            None => SizeHealth::default(),
        }
    }

    pub fn remove_vip(&mut self, vip: u32) {
        self.by_vip.remove(&vip);
    }

    pub fn clear(&mut self) {
        self.by_vip.clear();
    }
}

/// Gap before committing `counter` into a replay window (`0` if no prior top or not ahead).
#[inline]
pub fn replay_gap(top: Option<u64>, counter: u64) -> u64 {
    match top {
        Some(t) if counter > t => (counter - t - 1).min(GAP_CLAMP),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_boundaries() {
        assert_eq!(bucket_index(600), 0);
        assert_eq!(bucket_index(601), 1);
        assert_eq!(bucket_index(1000), 1);
        assert_eq!(bucket_index(1001), 2);
        assert_eq!(bucket_index(1300), 2);
        assert_eq!(bucket_index(1301), 3);
    }

    #[test]
    fn gap_clamp_and_cold() {
        assert_eq!(replay_gap(None, 10), 0);
        assert_eq!(replay_gap(Some(5), 5), 0);
        assert_eq!(replay_gap(Some(5), 6), 0);
        assert_eq!(replay_gap(Some(5), 10), 4);
        assert_eq!(replay_gap(Some(1), 200), 64);
    }

    #[test]
    fn warm_gate_blocks_alive() {
        let mut t = SizeLossTable::new();
        let now = Instant::now();
        for _ in 0..7 {
            t.note_rx(1, 1200, now);
        }
        let h = t.health(1, now);
        assert!(!h.warm);
        assert!(!h.large_alive);
    }

    #[test]
    fn large_alive_after_warm_commits() {
        let mut t = SizeLossTable::new();
        let mut now = Instant::now();
        for _ in 0..64 {
            t.note_rx(1, 1200, now);
        }
        now += Duration::from_millis(200);
        // Drive rate: many large packets over a tick.
        for _ in 0..20 {
            t.note_rx(1, 1200, now);
        }
        now += Duration::from_millis(150);
        let h = t.health(1, now);
        assert!(h.warm);
        assert!(h.large_alive);
    }
}
