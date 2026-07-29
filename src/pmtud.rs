use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

pub const PROBE_SIZES: [usize; 10] = [1500, 1460, 1400, 1350, 1300, 1250, 1200, 1100, 1000, 576];
pub const DEFAULT_MTU: usize = 1220;
const MIN_ADAPTER_PAYLOAD_MTU: usize = 280;
const STABLE_DOWNGRADE_BATCHES: u8 = 3;

#[derive(Clone, Debug)]
pub struct MtuRow {
    pub mtu: usize,
    pub stable: usize,
    pub batch: u32,
    pub batch_confirmed: bool,

    pub consecutive_lower_batches: u8,
}

pub struct PathMtuDiscovery {
    rows: HashMap<SocketAddr, MtuRow>,
    session_id: u32,
    current_batch: u32,
    probe_counter: Arc<AtomicU32>,
    min_path_mtu: usize,
    probe_sizes: Vec<usize>,
    stable_downgrade_batches: u8,
}

impl PathMtuDiscovery {
    pub fn new() -> Self {
        Self {
            rows: HashMap::new(),
            session_id: rand::random(),
            current_batch: 0,
            probe_counter: Arc::new(AtomicU32::new(0)),
            min_path_mtu: DEFAULT_MTU,
            probe_sizes: PROBE_SIZES.to_vec(),
            stable_downgrade_batches: STABLE_DOWNGRADE_BATCHES,
        }
    }

    /// Apply PMTUD tuning. Caller must stop any in-flight probe task before
    /// calling so the new ladder takes effect on the next batch.
    pub fn apply_tuning(&mut self, t: &crate::advanced_tuning::PmtudTuning) {
        self.probe_sizes = t.probe_sizes.clone();
        self.stable_downgrade_batches = t.stable_downgrade_batches;
    }

    /// Probe ladder currently in use (sorted descending by `clamp()`).
    pub fn probe_sizes(&self) -> &[usize] {
        &self.probe_sizes
    }

    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    pub fn next_probe_id(&self) -> u32 {
        self.probe_counter.fetch_add(1, Ordering::Relaxed)
    }

    pub fn probe_counter(&self) -> Arc<AtomicU32> {
        self.probe_counter.clone()
    }

    pub fn start_new_batch(&mut self) {
        for row in self.rows.values_mut() {
            if row.batch != self.current_batch {
                continue;
            }
            if row.batch_confirmed && row.mtu > 0 && row.mtu < row.stable {
                row.consecutive_lower_batches = row.consecutive_lower_batches.saturating_add(1);
                if row.consecutive_lower_batches >= self.stable_downgrade_batches {
                    row.stable = row.mtu.clamp(576, 1500);
                    row.consecutive_lower_batches = 0;
                }
            } else if row.batch_confirmed && row.mtu >= row.stable {
                row.consecutive_lower_batches = 0;
            }
        }

        self.current_batch = self.current_batch.wrapping_add(1);

        self.session_id = rand::random();
        for row in self.rows.values_mut() {
            row.batch = self.current_batch;
            row.mtu = 0;
            row.batch_confirmed = false;
        }
        self.recalc_min();
    }

    pub fn record(
        &mut self,
        peer: SocketAddr,
        size: usize,
        session_id: u32,
        _probe_id: u32,
    ) -> (bool, bool) {
        if session_id != self.session_id {
            return (false, false);
        }
        let row = self.rows.entry(peer).or_insert(MtuRow {
            mtu: 0,
            stable: DEFAULT_MTU,
            batch: self.current_batch,
            batch_confirmed: false,
            consecutive_lower_batches: 0,
        });
        if row.batch != self.current_batch {
            row.batch = self.current_batch;
            row.mtu = 0;
            row.batch_confirmed = false;
        }
        let sz = size.clamp(576, 1500);
        row.mtu = if row.mtu == 0 { sz } else { row.mtu.max(sz) };
        if row.mtu > row.stable {
            row.stable = row.mtu;
            row.consecutive_lower_batches = 0;
        }
        row.batch_confirmed = true;
        let old_min = self.min_path_mtu;
        self.recalc_min();
        (true, self.min_path_mtu != old_min)
    }

    fn recalc_min(&mut self) {
        self.min_path_mtu = self
            .rows
            .values()
            .filter(|r| r.batch == self.current_batch)
            .map(|r| {
                if r.batch_confirmed && r.mtu > 0 {
                    r.mtu
                } else {
                    r.stable
                }
            })
            .min()
            .unwrap_or(DEFAULT_MTU);
    }

    pub fn max_mtu(&self) -> usize {
        self.rows
            .values()
            .map(|r| if r.mtu > 0 { r.mtu } else { r.stable })
            .max()
            .unwrap_or(DEFAULT_MTU)
    }

    pub fn min_mtu(&self) -> usize {
        self.min_path_mtu
    }

    pub fn suggested_adapter_mtu(&self, enc_overhead: usize) -> usize {
        let raw = self.min_path_mtu;
        let after = raw.saturating_sub(enc_overhead);
        after.clamp(MIN_ADAPTER_PAYLOAD_MTU, 1500)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggested_adapter_mtu_does_not_inflate_after_overhead() {
        let mut p = PathMtuDiscovery::new();
        p.min_path_mtu = 576;
        assert_eq!(p.suggested_adapter_mtu(56), 520);
    }

    #[test]
    fn mtu_decreases_after_repeated_lower_batches() {
        let mut p = PathMtuDiscovery::new();
        let peer: SocketAddr = "198.51.100.1:5000".parse().unwrap();

        p.record(peer, 1500, p.session_id(), 1);
        assert_eq!(p.min_mtu(), 1500);
        p.start_new_batch();

        for _ in 0..3 {
            p.record(peer, 1280, p.session_id(), 2);
            p.start_new_batch();
        }
        let row = p.rows.get(&peer).unwrap();
        assert_eq!(row.stable, 1280);
        assert!(p.min_mtu() <= 1280);
    }

    #[test]
    fn mtu_recovers_when_batch_has_no_confirmation() {
        let mut p = PathMtuDiscovery::new();
        let peer: SocketAddr = "198.51.100.2:5001".parse().unwrap();
        p.record(peer, 1400, p.session_id(), 1);
        let prev_min = p.min_mtu();

        p.start_new_batch();
        assert_eq!(p.min_mtu(), prev_min);
    }

    #[test]
    fn late_pmar_previous_session_id_ignored() {
        let mut p = PathMtuDiscovery::new();
        let peer: SocketAddr = "198.51.100.3:5002".parse().unwrap();
        let old_sid = p.session_id();
        p.record(peer, 1500, old_sid, 1);
        p.start_new_batch();
        let (accepted, _) = p.record(peer, 1200, old_sid, 2);
        assert!(!accepted);
        let row = p.rows.get(&peer).unwrap();
        assert_eq!(row.mtu, 0);
    }
}
