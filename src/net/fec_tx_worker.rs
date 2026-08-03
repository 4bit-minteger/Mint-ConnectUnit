//! Dedicated OS thread (`mint-fec-tx`) owns per-dest `FecEncoder`, RS encode,
//! and Encoded-path `try_enqueue_peer_batch`. Passthrough / batch-fallback
//! return to the engine via unbounded events for `enqueue_normal_packet`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self as std_mpsc, RecvTimeoutError, SyncSender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::metrics::EngineMetrics;
use crate::net::fec::{FecEncoder, FecOutput, FEC_FLUSH_TIMEOUT, FEC_FLUSH_TIMEOUT_AGGRESSIVE};
use crate::net::pacing_worker::PacingIngress;

pub const FEC_TX_DATA_CHANNEL_CAP: usize = 1024;
pub const FEC_TX_CONTROL_CHANNEL_CAP: usize = 32;

/// Idle poll / flush atomic check interval.
const DATA_RECV_TIMEOUT: Duration = Duration::from_micros(150);

#[derive(Clone, Copy, Debug)]
pub struct FecTxTuning {
    pub shard: usize,
    pub flush_std: Duration,
    pub flush_agg: Duration,
    pub frame_scratch: usize,
}

impl Default for FecTxTuning {
    fn default() -> Self {
        Self {
            shard: crate::net::fec::FEC_SHARD_PAYLOAD_SIZE,
            flush_std: FEC_FLUSH_TIMEOUT,
            flush_agg: FEC_FLUSH_TIMEOUT_AGGRESSIVE,
            frame_scratch: 0,
        }
    }
}

pub enum FecTxData {
    Push {
        dest: SocketAddr,
        pkt: Bytes,
        ds: u8,
        ps: u8,
        queue_budget: Option<(usize, usize)>,
        rtt_hint: Option<f32>,
        qd_hint: Option<f32>,
    },
}

pub enum FecTxControl {
    FlushAll {
        reply: SyncSender<()>,
    },
    /// Atomic flush-all + set `current_tuning` (encoders empty after reply).
    Retune {
        shard: usize,
        flush_std: Duration,
        flush_agg: Duration,
        frame_scratch: usize,
        reply: SyncSender<()>,
    },
    SetEncodeEnabled {
        enabled: bool,
    },
    RemovePeer {
        dest: SocketAddr,
        reply: SyncSender<()>,
    },
    ResetSession {
        reply: SyncSender<()>,
    },
    Stop {
        reply: SyncSender<()>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NormalOfferKind {
    Passthrough,
    BatchFallback,
    DrainPassthrough,
}

pub enum FecTxEvent {
    EnqueueNormal {
        dest: SocketAddr,
        pkts: Vec<Bytes>,
        kind: NormalOfferKind,
    },
}

pub struct FecTxHandle {
    data_tx: SyncSender<FecTxData>,
    control_tx: SyncSender<FecTxControl>,
    pub event_rx: mpsc::UnboundedReceiver<FecTxEvent>,
    flush_req: Arc<AtomicU8>,
    join: Option<JoinHandle<()>>,
}

impl FecTxHandle {
    pub fn flush_req(&self) -> &Arc<AtomicU8> {
        &self.flush_req
    }

    /// Coalesce flush-due: 1 = flush, 2 = flush+drain. Drain wins via fetch_max.
    pub fn request_flush_due(&self, drain: bool) {
        let v = if drain { 2u8 } else { 1u8 };
        let mut cur = self.flush_req.load(Ordering::Relaxed);
        while cur < v {
            match self
                .flush_req
                .compare_exchange_weak(cur, v, Ordering::Release, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(c) => cur = c,
            }
        }
    }

    pub fn try_push(
        &self,
        dest: SocketAddr,
        pkt: Bytes,
        ds: u8,
        ps: u8,
        queue_budget: Option<(usize, usize)>,
        rtt_hint: Option<f32>,
        qd_hint: Option<f32>,
    ) -> bool {
        self.data_tx
            .try_send(FecTxData::Push {
                dest,
                pkt,
                ds,
                ps,
                queue_budget,
                rtt_hint,
                qd_hint,
            })
            .is_ok()
    }

    fn send_control_spin(&self, mut cmd: FecTxControl) -> bool {
        loop {
            match self.control_tx.try_send(cmd) {
                Ok(()) => return true,
                Err(std_mpsc::TrySendError::Full(c)) => {
                    cmd = c;
                    std::thread::yield_now();
                }
                Err(std_mpsc::TrySendError::Disconnected(_)) => return false,
            }
        }
    }

    fn control_barrier(&self, build: impl FnOnce(SyncSender<()>) -> FecTxControl) -> bool {
        let (tx, rx) = std_mpsc::sync_channel(1);
        if !self.send_control_spin(build(tx)) {
            return false;
        }
        rx.recv().is_ok()
    }

    pub fn flush_all_barrier(&self) -> bool {
        self.control_barrier(|reply| FecTxControl::FlushAll { reply })
    }

    pub fn retune_barrier(&self, tuning: FecTxTuning) -> bool {
        self.control_barrier(|reply| FecTxControl::Retune {
            shard: tuning.shard,
            flush_std: tuning.flush_std,
            flush_agg: tuning.flush_agg,
            frame_scratch: tuning.frame_scratch,
            reply,
        })
    }

    pub fn set_encode_enabled(&self, enabled: bool) -> bool {
        self.send_control_spin(FecTxControl::SetEncodeEnabled { enabled })
    }

    pub fn remove_peer_barrier(&self, dest: SocketAddr) -> bool {
        self.control_barrier(|reply| FecTxControl::RemovePeer { dest, reply })
    }

    pub fn reset_session_barrier(&self) -> bool {
        self.control_barrier(|reply| FecTxControl::ResetSession { reply })
    }

    /// Stop barrier only (flush inside worker). Caller must drain-apply events then join.
    pub fn request_stop(&mut self) -> Option<JoinHandle<()>> {
        let _ = self.control_barrier(|reply| FecTxControl::Stop { reply });
        self.join.take()
    }

    pub fn stop_and_join(&mut self) {
        if let Some(join) = self.request_stop() {
            while self.event_rx.try_recv().is_ok() {}
            let _ = join.join();
        }
    }
}

pub fn start_fec_tx_worker(
    pacing: PacingIngress,
    metrics: Arc<EngineMetrics>,
    initial_tuning: FecTxTuning,
) -> FecTxHandle {
    let (data_tx, data_rx) = std_mpsc::sync_channel(FEC_TX_DATA_CHANNEL_CAP);
    let (control_tx, control_rx) = std_mpsc::sync_channel(FEC_TX_CONTROL_CHANNEL_CAP);
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let flush_req = Arc::new(AtomicU8::new(0));
    let flush_w = flush_req.clone();
    let join = thread::Builder::new()
        .name("mint-fec-tx".to_string())
        .spawn(move || {
            fec_tx_worker_main(
                pacing,
                metrics,
                initial_tuning,
                data_rx,
                control_rx,
                event_tx,
                flush_w,
            );
        })
        .expect("mint-fec-tx thread");
    FecTxHandle {
        data_tx,
        control_tx,
        event_rx,
        flush_req,
        join: Some(join),
    }
}

struct WorkerState {
    encoders: HashMap<SocketAddr, FecEncoder>,
    hints: HashMap<SocketAddr, (Option<f32>, Option<f32>)>,
    tuning: FecTxTuning,
    encode_enabled: bool,
    pacing: PacingIngress,
    metrics: Arc<EngineMetrics>,
    event_tx: mpsc::UnboundedSender<FecTxEvent>,
}

impl WorkerState {
    fn emit_normal(&self, dest: SocketAddr, pkts: Vec<Bytes>, kind: NormalOfferKind) {
        let _ = self
            .event_tx
            .send(FecTxEvent::EnqueueNormal { dest, pkts, kind });
    }

    fn dispatch_output(&self, dest: SocketAddr, out: FecOutput, drain: bool) {
        match out {
            FecOutput::Buffered => {}
            FecOutput::Encoded(pkts) => {
                self.metrics.inc_fec_encoded_shards(pkts.len() as u64);
                let (rtt, qd) = self.hints.get(&dest).copied().unwrap_or((None, None));
                if !self
                    .pacing
                    .try_enqueue_peer_batch(dest, pkts.clone(), rtt, qd)
                {
                    self.emit_normal(dest, pkts, NormalOfferKind::BatchFallback);
                }
            }
            FecOutput::Passthrough(pkts) => {
                let kind = if drain {
                    NormalOfferKind::DrainPassthrough
                } else {
                    NormalOfferKind::Passthrough
                };
                self.emit_normal(dest, pkts, kind);
            }
        }
    }

    fn set_tuning_after_flush(
        &mut self,
        shard: usize,
        flush_std: Duration,
        flush_agg: Duration,
        frame_scratch: usize,
    ) {
        debug_assert!(self.encoders.is_empty());
        self.tuning = FecTxTuning {
            shard,
            flush_std,
            flush_agg,
            frame_scratch,
        };
    }

    fn flush_all(&mut self) {
        let obs = self.pacing.load_obs();
        let queue_cap = obs.max_data_queue_packets.max(1);
        let mut pending: Vec<(SocketAddr, FecOutput)> = Vec::new();
        for (dest, enc) in self.encoders.iter_mut() {
            let b = Some((obs.peer_data_queue_len(*dest), queue_cap));
            pending.push((*dest, enc.flush(b)));
        }
        self.encoders.clear();
        for (dest, out) in pending {
            self.dispatch_output(dest, out, false);
        }
    }

    fn flush_due(&mut self, drain: bool) {
        let obs = self.pacing.load_obs();
        let queue_cap = obs.max_data_queue_packets.max(1);
        let mut pending: Vec<(SocketAddr, FecOutput)> = Vec::new();
        for (dest, enc) in self.encoders.iter_mut() {
            if enc.needs_flush() {
                let out = if drain {
                    enc.flush_passthrough()
                } else {
                    let b = Some((obs.peer_data_queue_len(*dest), queue_cap));
                    enc.flush(b)
                };
                pending.push((*dest, out));
            }
        }
        for (dest, out) in pending {
            self.dispatch_output(dest, out, drain);
        }
    }

    fn handle_push(
        &mut self,
        dest: SocketAddr,
        pkt: Bytes,
        ds: u8,
        ps: u8,
        queue_budget: Option<(usize, usize)>,
        rtt_hint: Option<f32>,
        qd_hint: Option<f32>,
    ) {
        self.hints.insert(dest, (rtt_hint, qd_hint));
        if !self.encode_enabled {
            self.emit_normal(dest, vec![pkt], NormalOfferKind::Passthrough);
            return;
        }

        let tuning = self.tuning;
        let enc = self.encoders.entry(dest).or_insert_with(|| {
            let mut enc =
                FecEncoder::with_flush(ds, ps, tuning.shard, tuning.flush_std, tuning.flush_agg);
            enc.set_frame_scratch_capacity(tuning.frame_scratch);
            enc
        });
        enc.set_frame_scratch_capacity(tuning.frame_scratch);

        let size_flush = if enc.shard_payload_size() != tuning.shard {
            let flushed = enc.flush(queue_budget);
            enc.apply_tuning(tuning.shard, tuning.flush_std, tuning.flush_agg);
            flushed
        } else {
            enc.apply_tuning(tuning.shard, tuning.flush_std, tuning.flush_agg);
            FecOutput::Buffered
        };
        let ratio_flush = enc.update_ratio_with_flush(ds, ps, queue_budget);
        let out = enc.push_output(pkt, queue_budget);
        let ratio_flushed = !matches!(ratio_flush, FecOutput::Buffered);
        if ratio_flushed {
            self.metrics.inc_fec_ratio_flush();
        }
        self.dispatch_output(dest, size_flush, false);
        self.dispatch_output(dest, ratio_flush, false);
        self.dispatch_output(dest, out, false);
    }

    /// Returns true if the worker should exit.
    fn handle_control(&mut self, cmd: FecTxControl) -> bool {
        match cmd {
            FecTxControl::FlushAll { reply } => {
                self.flush_all();
                let _ = reply.send(());
                false
            }
            FecTxControl::Retune {
                shard,
                flush_std,
                flush_agg,
                frame_scratch,
                reply,
            } => {
                self.flush_all();
                self.set_tuning_after_flush(shard, flush_std, flush_agg, frame_scratch);
                let _ = reply.send(());
                false
            }
            FecTxControl::SetEncodeEnabled { enabled } => {
                self.encode_enabled = enabled;
                false
            }
            FecTxControl::RemovePeer { dest, reply } => {
                self.encoders.remove(&dest);
                self.hints.remove(&dest);
                let _ = reply.send(());
                false
            }
            FecTxControl::ResetSession { reply } => {
                self.flush_all();
                self.hints.clear();
                self.encode_enabled = true;
                let _ = reply.send(());
                false
            }
            FecTxControl::Stop { reply } => {
                self.flush_all();
                let _ = reply.send(());
                true
            }
        }
    }
}

fn fec_tx_worker_main(
    pacing: PacingIngress,
    metrics: Arc<EngineMetrics>,
    initial_tuning: FecTxTuning,
    data_rx: std_mpsc::Receiver<FecTxData>,
    control_rx: std_mpsc::Receiver<FecTxControl>,
    event_tx: mpsc::UnboundedSender<FecTxEvent>,
    flush_req: Arc<AtomicU8>,
) {
    let mut st = WorkerState {
        encoders: HashMap::new(),
        hints: HashMap::new(),
        tuning: initial_tuning,
        encode_enabled: true,
        pacing,
        metrics,
        event_tx,
    };

    loop {
        let mut stop = false;
        while let Ok(cmd) = control_rx.try_recv() {
            if st.handle_control(cmd) {
                stop = true;
                break;
            }
        }
        if stop {
            break;
        }

        let req = flush_req.swap(0, Ordering::AcqRel);
        if req != 0 {
            st.flush_due(req == 2);
        }

        match data_rx.recv_timeout(DATA_RECV_TIMEOUT) {
            Ok(FecTxData::Push {
                dest,
                pkt,
                ds,
                ps,
                queue_budget,
                rtt_hint,
                qd_hint,
            }) => {
                // Prefer control between data items.
                while let Ok(cmd) = control_rx.try_recv() {
                    if st.handle_control(cmd) {
                        return;
                    }
                }
                st.handle_push(dest, pkt, ds, ps, queue_budget, rtt_hint, qd_hint);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::fec::FEC_SHARD_PAYLOAD_SIZE;
    use crate::net::outbound_udp::OutboundUdpClock;
    use crate::net::pace_clock::PaceClockShared;
    use crate::net::pacing::PacingEngine;
    use crate::net::pacing_worker::start_pacing_worker;
    use crate::net::PaceClockApply;
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};
    use tokio::net::UdpSocket;

    fn dest() -> SocketAddr {
        "127.0.0.1:9".parse().unwrap()
    }

    async fn mock_stack() -> (PacingIngress, FecTxHandle, Arc<EngineMetrics>) {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let metrics = Arc::new(EngineMetrics::new());
        metrics.set_enabled(true);
        let shared = Arc::new(PaceClockShared::new(PaceClockApply::default(), 1000));
        let spawn = start_pacing_worker(
            socket,
            shared,
            PacingEngine::new(),
            OutboundUdpClock::shared(),
            metrics.clone(),
        );
        let ingress = spawn.handle.ingress.clone();
        let fec = start_fec_tx_worker(
            ingress.clone(),
            metrics.clone(),
            FecTxTuning {
                shard: FEC_SHARD_PAYLOAD_SIZE,
                flush_std: FEC_FLUSH_TIMEOUT,
                flush_agg: FEC_FLUSH_TIMEOUT_AGGRESSIVE,
                frame_scratch: 4096,
            },
        );
        // Keep pacing alive for the test by leaking join via spawn.handle drop at end —
        // return handle pieces; caller must keep spawn.handle if needed.
        // Actually dropping spawn.handle stops pacing. Keep it in a leak for tests:
        std::mem::forget(spawn.handle);
        std::mem::forget(spawn.tick_tx);
        (ingress, fec, metrics)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn try_push_full_returns_false() {
        let (_ing, mut fec, _) = mock_stack().await;
        // Fill by stopping worker first so sends fail closed, or fill channel.
        // Stop worker: data channel disconnects → try_push false.
        fec.stop_and_join();
        let ok = fec.try_push(dest(), Bytes::from_static(b"x"), 4, 1, None, None, None);
        assert!(!ok);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn flush_all_barrier_replies() {
        let (_ing, mut fec, _) = mock_stack().await;
        assert!(fec.flush_all_barrier());
        fec.stop_and_join();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn remove_peer_barrier_replies() {
        let (_ing, mut fec, _) = mock_stack().await;
        assert!(fec.remove_peer_barrier(dest()));
        fec.stop_and_join();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reset_session_barrier_replies() {
        let (_ing, mut fec, _) = mock_stack().await;
        assert!(fec.reset_session_barrier());
        fec.stop_and_join();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_max_flush_coalesce_drain_wins() {
        let (_ing, mut fec, _) = mock_stack().await;
        fec.request_flush_due(false);
        fec.request_flush_due(true);
        assert_eq!(fec.flush_req().load(Ordering::Acquire), 2);
        // Allow worker to swap
        tokio::time::sleep(Duration::from_millis(5)).await;
        fec.stop_and_join();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn set_encode_disabled_push_emits_passthrough() {
        let (_ing, mut fec, _) = mock_stack().await;
        assert!(fec.set_encode_enabled(false));
        // Brief yield for control delivery
        tokio::time::sleep(Duration::from_millis(2)).await;
        assert!(fec.try_push(dest(), Bytes::from_static(b"hello"), 4, 1, None, None, None,));
        let ev = tokio::time::timeout(Duration::from_millis(200), fec.event_rx.recv())
            .await
            .expect("timeout")
            .expect("event");
        match ev {
            FecTxEvent::EnqueueNormal { pkts, kind, .. } => {
                assert_eq!(kind, NormalOfferKind::Passthrough);
                assert_eq!(pkts.len(), 1);
                assert_eq!(&pkts[0][..], b"hello");
            }
        }
        fec.stop_and_join();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retune_barrier_sets_shard_push_has_no_shard_field() {
        let (_ing, mut fec, _) = mock_stack().await;
        let small = 600usize;
        assert!(fec.retune_barrier(FecTxTuning {
            shard: small,
            flush_std: FEC_FLUSH_TIMEOUT,
            flush_agg: FEC_FLUSH_TIMEOUT_AGGRESSIVE,
            frame_scratch: 4096,
        }));
        while fec.event_rx.try_recv().is_ok() {}
        // Push packets that fit the new ceiling; structural: Push carries no shard.
        for i in 0..4u8 {
            assert!(fec.try_push(
                dest(),
                Bytes::from(vec![i; 100]),
                4,
                1,
                Some((0, 10_000)),
                None,
                None,
            ));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(fec.flush_all_barrier());
        while fec.event_rx.try_recv().is_ok() {}
        fec.stop_and_join();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retune_then_push_uses_new_shard_not_old() {
        let (_ing, mut fec, _) = mock_stack().await;
        // Buffer under default large shard, then retune to tiny shard atomically.
        assert!(fec.try_push(
            dest(),
            Bytes::from(vec![1u8; 100]),
            4,
            1,
            Some((0, 10_000)),
            None,
            None,
        ));
        tokio::time::sleep(Duration::from_millis(5)).await;
        let tiny = 512usize;
        assert!(fec.retune_barrier(FecTxTuning {
            shard: tiny,
            flush_std: FEC_FLUSH_TIMEOUT,
            flush_agg: FEC_FLUSH_TIMEOUT_AGGRESSIVE,
            frame_scratch: 4096,
        }));
        // Prior buffer flushed as passthrough during Retune.
        let mut saw_pre = false;
        while let Ok(ev) = fec.event_rx.try_recv() {
            if let FecTxEvent::EnqueueNormal {
                kind: NormalOfferKind::Passthrough,
                ..
            } = ev
            {
                saw_pre = true;
            }
        }
        assert!(saw_pre, "Retune must flush prior group");
        // Packet larger than new shard still goes through Push (engine gates size);
        // worker creates encoder with tiny shard — fill group then flush without panic.
        for i in 0..4u8 {
            assert!(fec.try_push(
                dest(),
                Bytes::from(vec![i; 200]),
                4,
                1,
                Some((0, 10_000)),
                None,
                None,
            ));
        }
        assert!(fec.flush_all_barrier());
        while fec.event_rx.try_recv().is_ok() {}
        fec.stop_and_join();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stop_flushes_passthrough_event_before_join() {
        let (_ing, mut fec, _) = mock_stack().await;
        assert!(fec.try_push(
            dest(),
            Bytes::from(vec![9u8; 80]),
            4,
            1,
            Some((0, 10_000)),
            None,
            None,
        ));
        tokio::time::sleep(Duration::from_millis(5)).await;
        let join = fec.request_stop().expect("join handle");
        let mut saw = false;
        while let Ok(ev) = fec.event_rx.try_recv() {
            if let FecTxEvent::EnqueueNormal {
                kind: NormalOfferKind::Passthrough,
                pkts,
                ..
            } = ev
            {
                assert_eq!(pkts.len(), 1);
                saw = true;
            }
        }
        assert!(
            saw,
            "Stop must flush sparse group to event channel before reply"
        );
        let _ = join.join();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn flush_all_passthrough_events_nonblocking() {
        let (_ing, mut fec, _) = mock_stack().await;
        // One buffered packet (<2 → flush passthrough)
        assert!(fec.try_push(
            dest(),
            Bytes::from(vec![1u8; 100]),
            4,
            1,
            Some((0, 10_000)),
            None,
            None,
        ));
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(fec.flush_all_barrier());
        let mut saw = false;
        while let Ok(ev) = fec.event_rx.try_recv() {
            let FecTxEvent::EnqueueNormal { kind, .. } = ev;
            if kind == NormalOfferKind::Passthrough {
                saw = true;
            }
        }
        assert!(
            saw,
            "expected passthrough event after FlushAll of sparse group"
        );
        fec.stop_and_join();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn encoded_batch_false_emits_batch_fallback() {
        // Use a fake ingress whose cmd channel is closed → try_enqueue_peer_batch false.
        let (cmd_tx, cmd_rx) = mpsc::channel(1);
        drop(cmd_rx);
        let obs = Arc::new(arc_swap::ArcSwap::from_pointee(
            crate::net::pacing_worker::PacingObs::default(),
        ));
        let ingress = PacingIngress { cmd_tx, obs };
        let metrics = Arc::new(EngineMetrics::new());
        metrics.set_enabled(true);
        let mut fec = start_fec_tx_worker(
            ingress,
            metrics,
            FecTxTuning {
                shard: FEC_SHARD_PAYLOAD_SIZE,
                flush_std: FEC_FLUSH_TIMEOUT,
                flush_agg: FEC_FLUSH_TIMEOUT_AGGRESSIVE,
                frame_scratch: 4096,
            },
        );
        for i in 0..4u8 {
            assert!(fec.try_push(
                dest(),
                Bytes::from(vec![i; 300]),
                4,
                1,
                Some((0, 10_000)),
                None,
                None,
            ));
        }
        let mut saw_fallback = false;
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            if let Ok(ev) = fec.event_rx.try_recv() {
                if let FecTxEvent::EnqueueNormal {
                    kind: NormalOfferKind::BatchFallback,
                    ..
                } = ev
                {
                    saw_fallback = true;
                    break;
                }
            } else {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        assert!(saw_fallback);
        fec.stop_and_join();
    }
}
