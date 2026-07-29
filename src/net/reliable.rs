use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use smallvec::SmallVec;

use crate::net::packet::CompactPacketType;

const MAX_PENDING: usize = 256;

const RTO_MIN_MS: u32 = 50;
const RTO_MAX_MS: u32 = 400;
const DEFAULT_SRTT_MS: i32 = 100;
const DEFAULT_RTTVAR_MS: i32 = 50;
const SRTT_MIN_MS: i32 = 5;

fn compute_rto_ms(srtt_ms: i32, rttvar_ms: i32, rto_min: u32, rto_max: u32) -> u32 {
    let srtt = srtt_ms.max(SRTT_MIN_MS);
    let rttvar = rttvar_ms.max(1);
    (srtt + (4 * rttvar).max(10)).clamp(rto_min as i32, rto_max as i32) as u32
}

fn initial_rto_for_send(
    srtt_ms: i32,
    rttvar_ms: i32,
    rtt_hint_ms: Option<i32>,
    rto_min: u32,
    rto_max: u32,
) -> u32 {
    let base = compute_rto_ms(srtt_ms, rttvar_ms, rto_min, rto_max);
    let hinted = rtt_hint_ms.filter(|r| *r > 0).map(|r| {
        let rv = (r / 2).max(10);
        compute_rto_ms(r.max(20), rv, rto_min, rto_max)
    });
    match hinted {
        Some(h) => base.min(h),
        None => base,
    }
}

pub enum SendResult {
    Queued { seq: u32, packet: Bytes },
    Backpressure,
}

pub struct ReliableChannel {
    next_seq: u32,
    pending: BTreeMap<u32, PendingPacket>,
    /// Min-heap via `Reverse`: earliest `(Instant, seq)` at top. Stale entries (seq removed or
    /// `next_at` changed) are skipped on pop.
    due_heap: BinaryHeap<Reverse<(Instant, u32)>>,
    next_due_at: Option<Instant>,
    pub srtt_ms: i32,
    pub rttvar_ms: i32,
    rto_min_ms: u32,
    rto_max_ms: u32,
    max_pending: usize,
    retries_left: u8,
    send_scratch: BytesMut,
}

struct PendingPacket {
    data: Bytes,
    dest: SocketAddr,
    next_at: Option<Instant>,
    enqueued_at: Instant,
    actual_sent_at: Option<Instant>,
    retransmitted: bool,
    retries_left: u8,
    rto_ms: u32,
}

impl ReliableChannel {
    pub fn new() -> Self {
        Self {
            next_seq: 1,
            pending: BTreeMap::new(),
            due_heap: BinaryHeap::new(),
            next_due_at: None,
            srtt_ms: DEFAULT_SRTT_MS,
            rttvar_ms: DEFAULT_RTTVAR_MS,
            rto_min_ms: RTO_MIN_MS,
            rto_max_ms: RTO_MAX_MS,
            max_pending: MAX_PENDING,
            retries_left: 1,
            send_scratch: BytesMut::with_capacity(1500),
        }
    }

    /// Apply reliable tuning. RTO bounds take effect on the next retransmit;
    /// `max_pending` gates only newly-queued packets; `retries_left` applies to
    /// packets queued after this call (in-flight pending packets keep their
    /// already-assigned retry budget).
    pub fn apply_tuning(&mut self, t: &crate::advanced_tuning::ReliableTuning) {
        self.rto_min_ms = t.rto_min_ms;
        self.rto_max_ms = t.rto_max_ms;
        self.max_pending = t.max_pending;
        self.retries_left = t.retries_left;
        self.set_send_scratch_capacity(t.send_scratch_bytes);
    }

    pub fn set_send_scratch_capacity(&mut self, capacity: usize) {
        if self.send_scratch.capacity() < capacity {
            self.send_scratch
                .reserve(capacity - self.send_scratch.capacity());
        }
    }

    pub fn reset_session(&mut self) {
        self.pending.clear();
        self.due_heap.clear();
        self.next_due_at = None;
        self.next_seq = 1;
        self.srtt_ms = DEFAULT_SRTT_MS;
        self.rttvar_ms = DEFAULT_RTTVAR_MS;
    }

    fn pop_stale_due_heap_top(&mut self) {
        while let Some(&Reverse((t, seq))) = self.due_heap.peek() {
            let valid = match self.pending.get(&seq) {
                None => false,
                Some(p) => p.next_at == Some(t),
            };
            if valid {
                break;
            }
            self.due_heap.pop();
        }
    }

    fn refresh_next_due_from_heap(&mut self) {
        self.pop_stale_due_heap_top();
        self.next_due_at = self.due_heap.peek().map(|r| r.0 .0);
    }

    fn rebuild_due_heap_from_pending(&mut self) {
        self.due_heap.clear();
        for (&seq, p) in &self.pending {
            if let Some(t) = p.next_at {
                self.due_heap.push(Reverse((t, seq)));
            }
        }
        self.refresh_next_due_from_heap();
    }

    pub fn send(
        &mut self,
        inner: CompactPacketType,
        body: &[u8],
        dest: SocketAddr,
        rtt_hint_ms: Option<i32>,
    ) -> SendResult {
        if self.pending.len() >= self.max_pending {
            return SendResult::Backpressure;
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.send_scratch.clear();
        self.send_scratch.reserve(6 + body.len());
        self.send_scratch
            .extend_from_slice(&[CompactPacketType::Reliable.to_byte()]);
        self.send_scratch.extend_from_slice(&seq.to_be_bytes());
        self.send_scratch.extend_from_slice(&[inner.to_byte()]);
        self.send_scratch.extend_from_slice(body);
        let bytes = self.send_scratch.split().freeze();
        let now = Instant::now();

        let initial_rto = initial_rto_for_send(
            self.srtt_ms,
            self.rttvar_ms,
            rtt_hint_ms,
            self.rto_min_ms,
            self.rto_max_ms,
        );

        let initial_next_at = Some(now + Duration::from_millis(initial_rto as u64));
        self.pending.insert(
            seq,
            PendingPacket {
                data: bytes.clone(),
                dest,
                next_at: initial_next_at,
                enqueued_at: now,
                actual_sent_at: None,
                retransmitted: false,
                retries_left: self.retries_left,
                rto_ms: initial_rto,
            },
        );
        if let Some(due) = initial_next_at {
            self.due_heap.push(Reverse((due, seq)));
            self.refresh_next_due_from_heap();
        }
        SendResult::Queued { seq, packet: bytes }
    }

    pub fn mark_sent(&mut self, seq: u32, sent_at: Instant) {
        if let Some(p) = self.pending.get_mut(&seq) {
            if p.actual_sent_at.is_none() {
                p.actual_sent_at = Some(sent_at);
                let new_deadline = sent_at + Duration::from_millis(p.rto_ms as u64);
                p.next_at = Some(new_deadline);
                self.due_heap.push(Reverse((new_deadline, seq)));
                self.refresh_next_due_from_heap();
            }
        }
    }

    pub fn ack_packet(seq: u32) -> Bytes {
        let mut b = BytesMut::with_capacity(5);
        b.extend_from_slice(&[CompactPacketType::Ack.to_byte()]);
        b.extend_from_slice(&seq.to_be_bytes());
        b.freeze()
    }

    pub fn on_ack(&mut self, seq: u32, from: SocketAddr) {
        let addr_ok = self
            .pending
            .get(&seq)
            .map(|p| from == p.dest || from.ip() == p.dest.ip())
            .unwrap_or(false);
        if !addr_ok {
            return;
        }
        if let Some(p) = self.pending.remove(&seq) {
            if !p.retransmitted {
                let sent = p.actual_sent_at.unwrap_or(p.enqueued_at);
                let rtt_ms = sent.elapsed().as_millis().max(1) as i32;
                let rttvar = (3 * self.rttvar_ms + (self.srtt_ms - rtt_ms).abs()) / 4;
                let srtt = (7 * self.srtt_ms + rtt_ms) / 8;
                self.rttvar_ms = rttvar.max(1);
                self.srtt_ms = srtt.max(SRTT_MIN_MS);
            }
        }
        self.refresh_next_due_from_heap();
    }

    pub fn migrate_dest(&mut self, old_dest: SocketAddr, new_dest: SocketAddr) {
        if old_dest == new_dest {
            return;
        }
        for p in self.pending.values_mut() {
            if p.dest == old_dest {
                p.dest = new_dest;
            }
        }
        self.refresh_next_due_from_heap();
    }

    pub fn flush_dest(&mut self, dest: SocketAddr) {
        self.pending.retain(|_, p| p.dest != dest);
        self.rebuild_due_heap_from_pending();
    }

    pub fn tick_into(
        &mut self,
        out: &mut SmallVec<[(Bytes, SocketAddr); 8]>,
        permanent_failures: &mut Vec<(u32, SocketAddr)>,
    ) {
        out.clear();
        permanent_failures.clear();
        if self.pending.is_empty() {
            self.due_heap.clear();
            self.next_due_at = None;
            return;
        }
        let now = Instant::now();
        loop {
            self.pop_stale_due_heap_top();
            let Some(&Reverse((t, _seq))) = self.due_heap.peek() else {
                if !self.pending.is_empty() {
                    self.rebuild_due_heap_from_pending();
                    if self.due_heap.is_empty() {
                        self.next_due_at = self.pending.values().filter_map(|p| p.next_at).min();
                        return;
                    }
                    continue;
                }
                self.next_due_at = None;
                return;
            };
            if t > now {
                self.next_due_at = Some(t);
                return;
            }
            let Some(Reverse((t, seq))) = self.due_heap.pop() else {
                continue;
            };
            let Some(p) = self.pending.get_mut(&seq) else {
                continue;
            };
            if p.next_at != Some(t) {
                continue;
            }
            if p.retries_left == 0 {
                permanent_failures.push((seq, p.dest));
                self.pending.remove(&seq);
                continue;
            }
            p.retransmitted = true;
            p.retries_left -= 1;
            p.rto_ms = (p.rto_ms * 2).clamp(self.rto_min_ms, self.rto_max_ms);
            let new_at = now + Duration::from_millis(p.rto_ms as u64);
            p.next_at = Some(new_at);
            out.push((p.data.clone(), p.dest));
            self.due_heap.push(Reverse((new_at, seq)));
        }
    }

    #[cfg(test)]
    pub fn tick(&mut self) -> Vec<(Bytes, SocketAddr)> {
        let mut buf = SmallVec::new();
        let mut failures = Vec::new();
        self.tick_into(&mut buf, &mut failures);
        buf.into_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    #[test]
    fn send_returns_backpressure_when_pending_full() {
        let mut chan = ReliableChannel::new();
        for _ in 0..MAX_PENDING {
            let out = chan.send(CompactPacketType::JoinAck, b"body", addr(1000), None);
            assert!(matches!(out, SendResult::Queued { .. }));
        }
        let out = chan.send(CompactPacketType::JoinAck, b"body", addr(1000), None);
        assert!(matches!(out, SendResult::Backpressure));
    }

    #[test]
    fn migrate_dest_allows_ack_from_new_endpoint() {
        let mut chan = ReliableChannel::new();
        let seq = match chan.send(CompactPacketType::JoinAck, b"body", addr(1000), None) {
            SendResult::Queued { seq, .. } => seq,
            SendResult::Backpressure => panic!("unexpected backpressure"),
        };
        chan.migrate_dest(addr(1000), addr(2000));
        chan.on_ack(seq, addr(2000));
        assert!(chan.pending.is_empty());
    }

    #[test]
    fn on_ack_accepts_same_ip_different_port_nat_rebind() {
        let mut chan = ReliableChannel::new();
        let old = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 1000));
        let new = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 2000));
        let seq = match chan.send(CompactPacketType::JoinAck, b"body", old, None) {
            SendResult::Queued { seq, .. } => seq,
            SendResult::Backpressure => panic!("unexpected backpressure"),
        };
        chan.on_ack(seq, new);
        assert!(chan.pending.is_empty());
    }

    #[test]
    fn on_ack_rejects_different_ip() {
        let mut chan = ReliableChannel::new();
        let dest = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 1000));
        let other = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 2), 1000));
        let seq = match chan.send(CompactPacketType::JoinAck, b"body", dest, None) {
            SendResult::Queued { seq, .. } => seq,
            SendResult::Backpressure => panic!("unexpected backpressure"),
        };
        chan.on_ack(seq, other);
        assert!(!chan.pending.is_empty());
    }

    #[test]
    fn flush_dest_removes_only_matching_pending() {
        let mut chan = ReliableChannel::new();
        let a = addr(1000);
        let b = addr(1001);
        assert!(matches!(
            chan.send(CompactPacketType::JoinAck, b"a", a, None),
            SendResult::Queued { .. }
        ));
        assert!(matches!(
            chan.send(CompactPacketType::JoinAck, b"b", b, None),
            SendResult::Queued { .. }
        ));
        assert_eq!(chan.pending.len(), 2);
        chan.flush_dest(a);
        assert_eq!(chan.pending.len(), 1);
        let remaining_dest = chan.pending.values().next().expect("one pending").dest;
        assert_eq!(remaining_dest, b);
    }

    #[test]
    fn mark_sent_uses_actual_timestamp_for_rtt() {
        let mut chan = ReliableChannel::new();
        let seq = match chan.send(CompactPacketType::JoinAck, b"body", addr(1000), None) {
            SendResult::Queued { seq, .. } => seq,
            SendResult::Backpressure => panic!("unexpected backpressure"),
        };
        let before = Instant::now();
        chan.mark_sent(seq, before - Duration::from_millis(10));
        chan.on_ack(seq, addr(1000));
        assert!(chan.srtt_ms < DEFAULT_SRTT_MS);
    }

    #[test]
    fn default_initial_rto_within_expected_range() {
        let mut chan = ReliableChannel::new();
        let SendResult::Queued { seq, .. } =
            chan.send(CompactPacketType::JoinAck, b"body", addr(1000), None)
        else {
            panic!("expected queued");
        };
        let rto = chan.pending.get(&seq).unwrap().rto_ms;
        assert!(rto >= RTO_MIN_MS && rto <= 300);
    }

    #[test]
    fn rtt_hint_lowers_initial_rto_for_packet() {
        let mut chan = ReliableChannel::new();
        let SendResult::Queued { seq, .. } =
            chan.send(CompactPacketType::JoinAck, b"body", addr(1000), Some(5))
        else {
            panic!("expected queued");
        };
        let rto = chan.pending.get(&seq).unwrap().rto_ms;
        assert!(rto <= 80, "hinted rto was {rto}");
    }

    #[test]
    fn retransmit_rto_clamps_at_max() {
        let mut chan = ReliableChannel::new();
        let seq = match chan.send(CompactPacketType::JoinAck, b"body", addr(1000), None) {
            SendResult::Queued { seq, .. } => seq,
            SendResult::Backpressure => panic!("unexpected backpressure"),
        };
        if let Some(p) = chan.pending.get_mut(&seq) {
            p.rto_ms = 1500;
            p.next_at = Some(Instant::now() - Duration::from_secs(1));
            p.retries_left = 1;
        }
        chan.rebuild_due_heap_from_pending();
        let _ = chan.tick();
        let rto = chan.pending.get(&seq).unwrap().rto_ms;
        assert_eq!(rto, RTO_MAX_MS);
    }

    #[test]
    fn queued_packet_retransmits_on_initial_rto_even_without_mark_sent() {
        let mut chan = ReliableChannel::new();
        assert!(matches!(
            chan.send(CompactPacketType::JoinAck, b"body", addr(1000), None),
            SendResult::Queued { .. }
        ));

        for p in chan.pending.values_mut() {
            p.next_at = Some(Instant::now() - Duration::from_secs(1));
        }
        chan.rebuild_due_heap_from_pending();
        assert_eq!(chan.tick().len(), 1);
    }

    #[test]
    fn tick_into_early_exits_when_nothing_due() {
        let mut chan = ReliableChannel::new();
        let mut out = SmallVec::new();
        assert!(matches!(
            chan.send(CompactPacketType::JoinAck, b"b", addr(1), None),
            SendResult::Queued { .. }
        ));
        assert!(chan.next_due_at.is_some());
        let mut failures = Vec::new();
        chan.tick_into(&mut out, &mut failures);
        assert!(out.is_empty());
        assert!(failures.is_empty());
    }

    #[test]
    fn mark_sent_arms_retransmission_timer() {
        let mut chan = ReliableChannel::new();
        let seq = match chan.send(CompactPacketType::JoinAck, b"body", addr(1000), None) {
            SendResult::Queued { seq, .. } => seq,
            SendResult::Backpressure => panic!("unexpected backpressure"),
        };
        chan.mark_sent(seq, Instant::now() - Duration::from_secs(5));
        assert_eq!(chan.tick().len(), 1);
    }

    #[test]
    fn tick_into_reports_permanent_failure_when_retries_exhausted() {
        let mut chan = ReliableChannel::new();
        let dest = addr(1000);
        let seq = match chan.send(CompactPacketType::JoinAck, b"body", dest, None) {
            SendResult::Queued { seq, .. } => seq,
            SendResult::Backpressure => panic!("unexpected backpressure"),
        };
        chan.mark_sent(seq, Instant::now() - Duration::from_secs(60));
        if let Some(p) = chan.pending.get_mut(&seq) {
            p.retries_left = 0;
            p.next_at = Some(Instant::now() - Duration::from_secs(1));
        }
        chan.rebuild_due_heap_from_pending();
        let mut out = SmallVec::new();
        let mut failures = Vec::new();
        chan.tick_into(&mut out, &mut failures);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0], (seq, dest));
        assert!(!chan.pending.contains_key(&seq));
    }

    #[test]
    fn tick_into_many_acks_does_not_full_scan_pending() {
        let mut chan = ReliableChannel::new();
        for i in 0..MAX_PENDING {
            assert!(matches!(
                chan.send(
                    CompactPacketType::JoinAck,
                    &i.to_le_bytes(),
                    addr(1000),
                    None
                ),
                SendResult::Queued { .. }
            ));
        }
        for seq in 1u32..=MAX_PENDING as u32 {
            chan.on_ack(seq, addr(1000));
        }
        assert!(chan.pending.is_empty());
        assert!(chan.due_heap.is_empty());
    }
}
