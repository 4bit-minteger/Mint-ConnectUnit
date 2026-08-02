//! Shared last-outbound UDP timestamps for coverage-gated keepalives.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Shared map of last successful outbound UDP send per destination.
#[derive(Debug)]
pub struct OutboundUdpClock {
    map: Mutex<HashMap<SocketAddr, Instant>>,
    note_total: AtomicU64,
    poison_recover_total: AtomicU64,
}

impl Default for OutboundUdpClock {
    fn default() -> Self {
        Self::new()
    }
}

impl OutboundUdpClock {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            note_total: AtomicU64::new(0),
            poison_recover_total: AtomicU64::new(0),
        }
    }

    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    fn lock_map(&self) -> std::sync::MutexGuard<'_, HashMap<SocketAddr, Instant>> {
        self.map.lock().unwrap_or_else(|e| {
            self.poison_recover_total.fetch_add(1, Ordering::Relaxed);
            e.into_inner()
        })
    }

    /// Record a verified successful UDP send toward `dest`.
    pub fn note(&self, dest: SocketAddr) {
        let now = Instant::now();
        self.lock_map().insert(dest, now);
        self.note_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn last(&self, dest: SocketAddr) -> Option<Instant> {
        self.lock_map().get(&dest).copied()
    }

    /// True when there is no recent outbound within `keepalive`.
    pub fn needs_refresh(&self, dest: SocketAddr, now: Instant, keepalive: Duration) -> bool {
        match self.last(dest) {
            None => true,
            Some(last) => now.saturating_duration_since(last) >= keepalive,
        }
    }

    pub fn clear(&self) {
        self.lock_map().clear();
    }

    pub fn remove(&self, dest: SocketAddr) {
        self.lock_map().remove(&dest);
    }

    /// Drop keys not present in `keep`.
    pub fn retain_only(&self, keep: &std::collections::HashSet<SocketAddr>) {
        self.lock_map().retain(|addr, _| keep.contains(addr));
    }

    pub fn note_total(&self) -> u64 {
        self.note_total.load(Ordering::Relaxed)
    }

    pub fn poison_recover_total(&self) -> u64 {
        self.poison_recover_total.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn ep(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port))
    }

    #[test]
    fn note_suppresses_refresh_within_window() {
        let clock = OutboundUdpClock::new();
        let dest = ep(9);
        let now = Instant::now();
        assert!(clock.needs_refresh(dest, now, Duration::from_secs(5)));
        clock.note(dest);
        assert!(!clock.needs_refresh(dest, Instant::now(), Duration::from_secs(5)));
        assert_eq!(clock.note_total(), 1);
    }

    #[test]
    fn clear_and_retain() {
        let clock = OutboundUdpClock::new();
        let a = ep(1);
        let b = ep(2);
        clock.note(a);
        clock.note(b);
        let mut keep = std::collections::HashSet::new();
        keep.insert(a);
        clock.retain_only(&keep);
        assert!(clock.last(a).is_some());
        assert!(clock.last(b).is_none());
        clock.clear();
        assert!(clock.last(a).is_none());
    }
}
