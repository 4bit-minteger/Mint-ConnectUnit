use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Byte counters for the `runtime` live dashboard. Only incremented when `enabled` is true.
#[derive(Debug, Default)]
pub struct RuntimeTrace {
    pub enabled: AtomicBool,
    pub tun_egress_bytes: AtomicU64,
    pub tun_ingress_bytes: AtomicU64,
    pub wire_tx_bytes: AtomicU64,
    pub wire_rx_bytes: AtomicU64,
}

impl RuntimeTrace {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    pub fn reset(&self) {
        self.tun_egress_bytes.store(0, Ordering::Relaxed);
        self.tun_ingress_bytes.store(0, Ordering::Relaxed);
        self.wire_tx_bytes.store(0, Ordering::Relaxed);
        self.wire_rx_bytes.store(0, Ordering::Relaxed);
    }

    #[inline]
    pub fn add_tun_egress(&self, n: u64) {
        if self.is_enabled() {
            self.tun_egress_bytes.fetch_add(n, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn add_tun_ingress(&self, n: u64) {
        if self.is_enabled() {
            self.tun_ingress_bytes.fetch_add(n, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn add_wire_tx(&self, n: u64) {
        if self.is_enabled() {
            self.wire_tx_bytes.fetch_add(n, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn add_wire_rx(&self, n: u64) {
        if self.is_enabled() {
            self.wire_rx_bytes.fetch_add(n, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_only_when_enabled() {
        let t = RuntimeTrace::new();
        t.add_tun_egress(100);
        assert_eq!(t.tun_egress_bytes.load(Ordering::Relaxed), 0);
        t.set_enabled(true);
        t.add_tun_egress(50);
        assert_eq!(t.tun_egress_bytes.load(Ordering::Relaxed), 50);
        t.reset();
        assert_eq!(t.tun_egress_bytes.load(Ordering::Relaxed), 0);
        t.set_enabled(false);
        t.add_wire_rx(999);
        assert_eq!(t.wire_rx_bytes.load(Ordering::Relaxed), 0);
    }
}
