//! Single-owner pacing worker: OS thread owns `PacingEngine`, clock ticks via
//! `channel(1)`, engine mutates via FIFO commands.
//!
//! Hot-path data/control/retransmit are fire-and-forget. Only FEC
//! `TryEnqueuePeerBatch` keeps a SyncSender ack for all-or-nothing semantics.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc as std_mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use arc_swap::ArcSwap;
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::background_cc::{BackgroundCcConfig, CcUpdateCounters};
use super::pace_clock::PaceClockShared;
use super::pacing::{ApdPhase, PacingConfig, PacingEngine, PacingQueueSnapshot, TickResult};

/// Bound for engine→worker command channel. Data uses try_send; critical cmds spin.
pub const PACING_CMD_CHANNEL_CAP: usize = 1024;

#[derive(Clone, Debug)]
pub struct PacingObs {
    pub queue: PacingQueueSnapshot,
    pub peer_data_lens: HashMap<SocketAddr, usize>,
    pub apd_phase: ApdPhase,
    pub apd_pure_spin: bool,
    pub apd_tick_us: u64,
    pub apd_episodes: u64,
    pub apd_ms_total: u64,
    pub apd_pkts_drained: u64,
    pub apd_budget_hits: u64,
    pub apd_ramp_active: u64,
    pub apd_ramp_pinned: u64,
    pub apd_last_burst: u64,
    pub apd_arm_fill: u64,
    pub apd_arm_sojourn: u64,
    pub apd_max_sojourn: u64,
    pub apd_cc_headroom_suppressions: u64,
    pub dropped_packets: u64,
    pub dropped_data: u64,
    pub shed_sojourn: u64,
    pub dropped_control_normal: u64,
    pub dropped_control_retransmit: u64,
    pub cc_rate_limited_events: u64,
    pub drr_small_priority_pops: u64,
    pub drr_bulk_force_pops: u64,
    pub drr_rtt_scale_applied: u64,
    pub cc_min_bps: f64,
    pub cc_avg_bps: f64,
    pub cc_max_bps: f64,
    pub cc_delivery_min_bps: f64,
    pub cc_delivery_avg_bps: f64,
    pub cc_delivery_max_bps: f64,
    pub cc_counters: CcUpdateCounters,
    pub drr_rtt_aware: bool,
    pub drr_enabled: bool,
    pub max_data_queue_packets: usize,
    pub tick_us: u64,
    pub config: PacingConfig,
}

impl Default for PacingObs {
    fn default() -> Self {
        let config = PacingConfig::default();
        Self {
            queue: PacingQueueSnapshot::default(),
            peer_data_lens: HashMap::new(),
            apd_phase: ApdPhase::Cooldown,
            apd_pure_spin: false,
            apd_tick_us: 0,
            apd_episodes: 0,
            apd_ms_total: 0,
            apd_pkts_drained: 0,
            apd_budget_hits: 0,
            apd_ramp_active: 0,
            apd_ramp_pinned: 0,
            apd_last_burst: 0,
            apd_arm_fill: 0,
            apd_arm_sojourn: 0,
            apd_max_sojourn: 0,
            apd_cc_headroom_suppressions: 0,
            dropped_packets: 0,
            dropped_data: 0,
            shed_sojourn: 0,
            dropped_control_normal: 0,
            dropped_control_retransmit: 0,
            cc_rate_limited_events: 0,
            drr_small_priority_pops: 0,
            drr_bulk_force_pops: 0,
            drr_rtt_scale_applied: 0,
            cc_min_bps: 0.0,
            cc_avg_bps: 0.0,
            cc_max_bps: 0.0,
            cc_delivery_min_bps: 0.0,
            cc_delivery_avg_bps: 0.0,
            cc_delivery_max_bps: 0.0,
            cc_counters: CcUpdateCounters::default(),
            drr_rtt_aware: config.drr_rtt_aware,
            drr_enabled: config.drr_enabled,
            max_data_queue_packets: config.max_data_queue_packets,
            tick_us: config.tick_us,
            config,
        }
    }
}

impl PacingObs {
    pub fn peer_data_queue_len(&self, dest: SocketAddr) -> usize {
        self.peer_data_lens.get(&dest).copied().unwrap_or(0)
    }

    fn from_engine(p: &PacingEngine) -> Self {
        let (apd_episodes, apd_ms_total, apd_pkts_drained, apd_budget_hits, apd_phase) =
            p.apd_metrics();
        let (apd_pure_spin, apd_tick_us) = p.apd_signal();
        let (apd_ramp_active, apd_ramp_pinned, apd_last_burst) = p.apd_ramp_observability();
        let (apd_arm_fill, apd_arm_sojourn, apd_max_sojourn) = p.apd_sojourn_observability();
        let (cc_min_bps, cc_avg_bps, cc_max_bps) = p.cc_metrics_snapshot();
        let (cc_delivery_min_bps, cc_delivery_avg_bps, cc_delivery_max_bps) =
            p.cc_delivery_metrics_snapshot();
        let mut peer_data_lens = HashMap::with_capacity(p.config.max_data_queue_packets.min(64));
        for (dest, len) in p.peer_data_lens_snapshot() {
            peer_data_lens.insert(dest, len);
        }
        Self {
            queue: p.queue_snapshot(),
            peer_data_lens,
            apd_phase,
            apd_pure_spin,
            apd_tick_us,
            apd_episodes,
            apd_ms_total,
            apd_pkts_drained,
            apd_budget_hits,
            apd_ramp_active,
            apd_ramp_pinned,
            apd_last_burst,
            apd_arm_fill,
            apd_arm_sojourn,
            apd_max_sojourn,
            apd_cc_headroom_suppressions: p.apd_cc_headroom_suppressions(),
            dropped_packets: p.dropped_packets(),
            dropped_data: p.dropped_data(),
            shed_sojourn: p.shed_sojourn(),
            dropped_control_normal: p.dropped_control_normal(),
            dropped_control_retransmit: p.dropped_control_retransmit(),
            cc_rate_limited_events: p.cc_rate_limited_events(),
            drr_small_priority_pops: p.drr_small_priority_pops(),
            drr_bulk_force_pops: p.drr_bulk_force_pops(),
            drr_rtt_scale_applied: p.drr_rtt_scale_applied(),
            cc_min_bps,
            cc_avg_bps,
            cc_max_bps,
            cc_delivery_min_bps,
            cc_delivery_avg_bps,
            cc_delivery_max_bps,
            cc_counters: p.cc_counters(),
            drr_rtt_aware: p.config.drr_rtt_aware,
            drr_enabled: p.config.drr_enabled,
            max_data_queue_packets: p.config.max_data_queue_packets,
            tick_us: p.config.tick_us,
            config: p.config,
        }
    }
}

pub enum PacingCommand {
    EnqueueData {
        pkt: Bytes,
        dest: SocketAddr,
        rtt_hint: Option<f32>,
        qd_hint: Option<f32>,
    },
    TryEnqueuePeerBatch {
        dest: SocketAddr,
        pkts: Vec<Bytes>,
        rtt_hint: Option<f32>,
        qd_hint: Option<f32>,
        reply: std_mpsc::SyncSender<bool>,
    },
    EnqueueControl {
        pkt: Bytes,
        dest: SocketAddr,
    },
    EnqueueRetransmit {
        pkt: Bytes,
        dest: SocketAddr,
    },
    RemovePeer {
        dest: SocketAddr,
    },
    OnCcSample {
        dest: SocketAddr,
        qd_ms: f64,
        loss_ewma: f64,
    },
    SetConfig {
        cfg: PacingConfig,
    },
    SetDrrEnabled {
        enabled: bool,
    },
    SetBackgroundCc {
        config: BackgroundCcConfig,
    },
    ResetSession,
    Stop,
}

fn reply_channel() -> (std_mpsc::SyncSender<bool>, std_mpsc::Receiver<bool>) {
    std_mpsc::sync_channel(1)
}

fn wait_reply(rx: std_mpsc::Receiver<bool>) -> bool {
    rx.recv().unwrap_or(false)
}

pub enum PacingEvent {
    TickDone {
        sent: usize,
        tick_duration_us: u64,
        socket_dead: Option<(std::io::Error, Option<SocketAddr>)>,
    },
}

pub struct PacingWorkerHandle {
    pub cmd_tx: mpsc::Sender<PacingCommand>,
    pub event_rx: mpsc::UnboundedReceiver<PacingEvent>,
    pub obs: Arc<ArcSwap<PacingObs>>,
    pub stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl PacingWorkerHandle {
    pub fn load_obs(&self) -> arc_swap::Guard<Arc<PacingObs>> {
        self.obs.load()
    }

    /// Deliver a command without tokio blocking APIs (safe on current_thread runtime).
    fn send_cmd_spin(&self, mut cmd: PacingCommand) -> bool {
        loop {
            match self.cmd_tx.try_send(cmd) {
                Ok(()) => return true,
                Err(mpsc::error::TrySendError::Full(c)) => {
                    cmd = c;
                    std::thread::yield_now();
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return false,
            }
        }
    }

    /// Fire-and-forget data enqueue. Returns false if channel Full/Closed.
    pub fn try_enqueue_data(
        &self,
        pkt: Bytes,
        dest: SocketAddr,
        rtt_hint: Option<f32>,
        qd_hint: Option<f32>,
    ) -> bool {
        self.cmd_tx
            .try_send(PacingCommand::EnqueueData {
                pkt,
                dest,
                rtt_hint,
                qd_hint,
            })
            .is_ok()
    }

    pub async fn enqueue_data_async(
        &self,
        pkt: Bytes,
        dest: SocketAddr,
        rtt_hint: Option<f32>,
        qd_hint: Option<f32>,
    ) -> bool {
        self.cmd_tx
            .send(PacingCommand::EnqueueData {
                pkt,
                dest,
                rtt_hint,
                qd_hint,
            })
            .await
            .is_ok()
    }

    /// Fire-and-forget control; spins if channel full. Returns whether delivered to channel.
    pub fn enqueue_control(&self, pkt: Bytes, dest: SocketAddr) -> bool {
        self.send_cmd_spin(PacingCommand::EnqueueControl { pkt, dest })
    }

    pub async fn enqueue_control_async(&self, pkt: Bytes, dest: SocketAddr) -> bool {
        self.cmd_tx
            .send(PacingCommand::EnqueueControl { pkt, dest })
            .await
            .is_ok()
    }

    /// Fire-and-forget retransmit; spins if channel full.
    pub fn enqueue_retransmit(&self, pkt: Bytes, dest: SocketAddr) -> bool {
        self.send_cmd_spin(PacingCommand::EnqueueRetransmit { pkt, dest })
    }

    pub fn try_enqueue_peer_batch(
        &self,
        dest: SocketAddr,
        pkts: Vec<Bytes>,
        rtt_hint: Option<f32>,
        qd_hint: Option<f32>,
    ) -> bool {
        let (reply_tx, reply_rx) = reply_channel();
        match self.cmd_tx.try_send(PacingCommand::TryEnqueuePeerBatch {
            dest,
            pkts,
            rtt_hint,
            qd_hint,
            reply: reply_tx,
        }) {
            Ok(()) => wait_reply(reply_rx),
            Err(_) => false,
        }
    }

    pub async fn try_enqueue_peer_batch_async(
        &self,
        dest: SocketAddr,
        pkts: Vec<Bytes>,
        rtt_hint: Option<f32>,
        qd_hint: Option<f32>,
    ) -> bool {
        let (reply_tx, reply_rx) = reply_channel();
        match self.cmd_tx.try_send(PacingCommand::TryEnqueuePeerBatch {
            dest,
            pkts,
            rtt_hint,
            qd_hint,
            reply: reply_tx,
        }) {
            Ok(()) => {
                tokio::task::yield_now().await;
                wait_reply(reply_rx)
            }
            Err(_) => false,
        }
    }

    pub fn remove_peer(&self, dest: SocketAddr) {
        let _ = self.send_cmd_spin(PacingCommand::RemovePeer { dest });
    }

    pub async fn remove_peer_async(&self, dest: SocketAddr) {
        let _ = self.cmd_tx.send(PacingCommand::RemovePeer { dest }).await;
    }

    pub fn on_cc_sample(&self, dest: SocketAddr, qd_ms: f64, loss_ewma: f64) {
        let _ = self.send_cmd_spin(PacingCommand::OnCcSample {
            dest,
            qd_ms,
            loss_ewma,
        });
    }

    pub fn set_config(&self, cfg: PacingConfig) {
        let _ = self.send_cmd_spin(PacingCommand::SetConfig { cfg });
    }

    pub async fn set_config_async(&self, cfg: PacingConfig) {
        let _ = self.cmd_tx.send(PacingCommand::SetConfig { cfg }).await;
    }

    pub fn set_drr_enabled(&self, enabled: bool) {
        let _ = self.send_cmd_spin(PacingCommand::SetDrrEnabled { enabled });
    }

    pub async fn set_drr_enabled_async(&self, enabled: bool) {
        let _ = self
            .cmd_tx
            .send(PacingCommand::SetDrrEnabled { enabled })
            .await;
    }

    pub fn set_background_cc(&self, config: BackgroundCcConfig) {
        let _ = self.send_cmd_spin(PacingCommand::SetBackgroundCc { config });
    }

    pub fn reset_session(&self) {
        let _ = self.send_cmd_spin(PacingCommand::ResetSession);
    }

    pub async fn reset_session_async(&self) {
        let _ = self.cmd_tx.send(PacingCommand::ResetSession).await;
    }

    pub fn request_stop(&mut self) -> Option<JoinHandle<()>> {
        self.stop.store(true, Ordering::Release);
        let _ = self.cmd_tx.try_send(PacingCommand::Stop);
        let _ = self.send_cmd_spin(PacingCommand::Stop);
        self.join.take()
    }

    pub fn stop_and_join(&mut self) {
        if let Some(join) = self.request_stop() {
            let _ = join.join();
        }
    }
}

pub struct PacingWorkerSpawn {
    pub handle: PacingWorkerHandle,
    /// Clock thread must send ticks here (`channel(1)`).
    pub tick_tx: mpsc::Sender<()>,
}

pub fn start_pacing_worker(
    socket: Arc<UdpSocket>,
    clock_shared: Arc<PaceClockShared>,
    initial: PacingEngine,
) -> PacingWorkerSpawn {
    let (cmd_tx, cmd_rx) = mpsc::channel(PACING_CMD_CHANNEL_CAP);
    let (tick_tx, tick_rx) = mpsc::channel(1);
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let obs = Arc::new(ArcSwap::from_pointee(PacingObs::from_engine(&initial)));
    let stop = Arc::new(AtomicBool::new(false));
    let obs_w = obs.clone();
    let stop_w = stop.clone();
    let join = thread::Builder::new()
        .name("mint-pacing".to_string())
        .spawn(move || {
            pacing_worker_main(
                socket,
                clock_shared,
                initial,
                cmd_rx,
                tick_rx,
                event_tx,
                obs_w,
                stop_w,
            );
        })
        .expect("mint-pacing thread");
    PacingWorkerSpawn {
        handle: PacingWorkerHandle {
            cmd_tx,
            event_rx,
            obs,
            stop,
            join: Some(join),
        },
        tick_tx,
    }
}

fn publish_obs(obs: &Arc<ArcSwap<PacingObs>>, pacing: &PacingEngine) {
    obs.store(Arc::new(PacingObs::from_engine(pacing)));
}

fn publish_apd(shared: &PaceClockShared, pacing: &PacingEngine) {
    let (apd_spin, apd_tick) = pacing.apd_signal();
    // Publish tick before spin: Release on apd_pure_spin must be last.
    shared.apd_tick_us.store(apd_tick, Ordering::Relaxed);
    shared.apd_pure_spin.store(apd_spin, Ordering::Release);
}

/// Returns `(stop, needs_obs_publish)`.
fn handle_command(pacing: &mut PacingEngine, cmd: PacingCommand) -> (bool, bool) {
    match cmd {
        PacingCommand::EnqueueData {
            pkt,
            dest,
            rtt_hint,
            qd_hint,
        } => {
            let _ = pacing.enqueue_peer_with_hints(pkt, dest, rtt_hint, qd_hint);
            (false, false)
        }
        PacingCommand::TryEnqueuePeerBatch {
            dest,
            pkts,
            rtt_hint,
            qd_hint,
            reply,
        } => {
            let ok = pacing.try_enqueue_peer_batch(dest, &pkts, rtt_hint, qd_hint);
            let _ = reply.send(ok);
            (false, false)
        }
        PacingCommand::EnqueueControl { pkt, dest } => {
            let _ = pacing.enqueue_control(pkt, dest);
            (false, false)
        }
        PacingCommand::EnqueueRetransmit { pkt, dest } => {
            let _ = pacing.enqueue_retransmit(pkt, dest);
            (false, false)
        }
        PacingCommand::RemovePeer { dest } => {
            pacing.remove_peer(dest);
            (false, true)
        }
        PacingCommand::OnCcSample {
            dest,
            qd_ms,
            loss_ewma,
        } => {
            pacing.on_cc_sample(dest, qd_ms, loss_ewma);
            (false, false)
        }
        PacingCommand::SetConfig { cfg } => {
            pacing.set_config(cfg);
            (false, true)
        }
        PacingCommand::SetDrrEnabled { enabled } => {
            pacing.config.drr_enabled = enabled;
            (false, true)
        }
        PacingCommand::SetBackgroundCc { config } => {
            pacing.set_background_cc_config(config);
            (false, true)
        }
        PacingCommand::ResetSession => {
            pacing.reset_session_runtime();
            (false, true)
        }
        PacingCommand::Stop => (true, false),
    }
}

fn pacing_worker_main(
    socket: Arc<UdpSocket>,
    clock_shared: Arc<PaceClockShared>,
    mut pacing: PacingEngine,
    mut cmd_rx: mpsc::Receiver<PacingCommand>,
    mut tick_rx: mpsc::Receiver<()>,
    event_tx: mpsc::UnboundedSender<PacingEvent>,
    obs: Arc<ArcSwap<PacingObs>>,
    stop: Arc<AtomicBool>,
) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return,
    };
    rt.block_on(async move {
        publish_obs(&obs, &pacing);
        loop {
            if stop.load(Ordering::Acquire) {
                while let Ok(cmd) = cmd_rx.try_recv() {
                    let (stop_cmd, need_obs) = handle_command(&mut pacing, cmd);
                    if need_obs {
                        publish_obs(&obs, &pacing);
                    }
                    if stop_cmd {
                        publish_obs(&obs, &pacing);
                        return;
                    }
                }
                publish_obs(&obs, &pacing);
                return;
            }
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(cmd) => {
                            let (stop_cmd, need_obs) = handle_command(&mut pacing, cmd);
                            if need_obs {
                                publish_obs(&obs, &pacing);
                            }
                            if stop_cmd {
                                publish_obs(&obs, &pacing);
                                return;
                            }
                        }
                        None => return,
                    }
                }
                t = tick_rx.recv() => {
                    if t.is_none() {
                        return;
                    }
                    let started = Instant::now();
                    let tick_result = pacing.tick(&socket);
                    publish_apd(&clock_shared, &pacing);
                    publish_obs(&obs, &pacing);
                    let tick_duration_us = started.elapsed().as_micros() as u64;
                    let (sent, socket_dead) = match tick_result {
                        TickResult::Progress(sent) => (sent, None),
                        TickResult::SocketDead {
                            error,
                            last_failed_dest,
                        } => (0, Some((error, last_failed_dest))),
                    };
                    let _ = event_tx.send(PacingEvent::TickDone {
                        sent,
                        tick_duration_us,
                        socket_dead,
                    });
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;

    use crate::net::pace_clock::{PaceClockApply, PaceClockShared};

    fn addr(octet: u8) -> SocketAddr {
        format!("10.0.0.{}:1", octet).parse().unwrap()
    }

    async fn test_socket() -> Arc<UdpSocket> {
        Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())
    }

    fn spawn_worker(socket: Arc<UdpSocket>) -> PacingWorkerSpawn {
        let shared = Arc::new(PaceClockShared::new(PaceClockApply::default(), 1000));
        start_pacing_worker(socket, shared, PacingEngine::new())
    }

    #[tokio::test]
    async fn fifo_remove_peer_barrier_drops_stale_from_obs() {
        let sock = test_socket().await;
        let mut spawn = spawn_worker(sock);
        {
            let h = &spawn.handle;
            assert!(
                h.enqueue_data_async(Bytes::from_static(b"a"), addr(1), None, None)
                    .await
            );
            h.remove_peer_async(addr(1)).await;
            for _ in 0..50 {
                if h.load_obs().peer_data_queue_len(addr(1)) == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            assert_eq!(h.load_obs().peer_data_queue_len(addr(1)), 0);
            assert!(
                h.enqueue_data_async(Bytes::from_static(b"b"), addr(1), None, None)
                    .await
            );
            // Force obs publish via RemovePeer no-op path: set_config publishes.
            h.set_config_async(h.load_obs().config).await;
            for _ in 0..50 {
                if h.load_obs().peer_data_queue_len(addr(1)) == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            assert_eq!(h.load_obs().peer_data_queue_len(addr(1)), 1);
        }
        spawn.handle.stop_and_join();
    }

    #[tokio::test]
    async fn try_enqueue_peer_batch_oneshot_all_or_nothing() {
        let sock = test_socket().await;
        let mut spawn = spawn_worker(sock);
        {
            let h = &spawn.handle;
            let mut cfg = PacingConfig::default();
            cfg.max_queue_packets = 3;
            cfg.refresh_queue_splits();
            h.set_config_async(cfg).await;
            for _ in 0..50 {
                if h.load_obs().max_data_queue_packets == 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            assert_eq!(h.load_obs().max_data_queue_packets, 2);
            assert!(
                h.enqueue_data_async(Bytes::from_static(b"a"), addr(2), None, None)
                    .await
            );
            assert!(
                h.enqueue_data_async(Bytes::from_static(b"b"), addr(2), None, None)
                    .await
            );
            let batch = vec![Bytes::from_static(b"c"), Bytes::from_static(b"d")];
            assert!(
                !h.try_enqueue_peer_batch_async(addr(2), batch, None, None)
                    .await
            );
            h.set_config_async(h.load_obs().config).await;
            for _ in 0..50 {
                if h.load_obs().peer_data_queue_len(addr(2)) == 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            assert_eq!(h.load_obs().peer_data_queue_len(addr(2)), 2);
        }
        spawn.handle.stop_and_join();
    }

    #[tokio::test]
    async fn reset_session_clears_queues() {
        let sock = test_socket().await;
        let mut spawn = spawn_worker(sock);
        {
            let h = &spawn.handle;
            assert!(
                h.enqueue_data_async(Bytes::from_static(b"x"), addr(3), None, None)
                    .await
            );
            h.reset_session_async().await;
            for _ in 0..50 {
                if h.load_obs().queue.data_queued == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            assert_eq!(h.load_obs().queue.data_queued, 0);
        }
        spawn.handle.stop_and_join();
    }

    #[tokio::test]
    async fn try_enqueue_returns_false_when_command_channel_full() {
        let (cmd_tx, _cmd_rx) = mpsc::channel::<PacingCommand>(2);
        assert!(cmd_tx
            .try_send(PacingCommand::EnqueueData {
                pkt: Bytes::from_static(b"0"),
                dest: addr(1),
                rtt_hint: None,
                qd_hint: None,
            })
            .is_ok());
        assert!(cmd_tx
            .try_send(PacingCommand::EnqueueData {
                pkt: Bytes::from_static(b"1"),
                dest: addr(1),
                rtt_hint: None,
                qd_hint: None,
            })
            .is_ok());
        assert!(matches!(
            cmd_tx.try_send(PacingCommand::EnqueueData {
                pkt: Bytes::from_static(b"2"),
                dest: addr(1),
                rtt_hint: None,
                qd_hint: None,
            }),
            Err(mpsc::error::TrySendError::Full(_))
        ));
    }

    #[tokio::test]
    async fn fire_and_forget_data_does_not_block_caller() {
        let sock = test_socket().await;
        let mut spawn = spawn_worker(sock);
        let h = &spawn.handle;
        let start = Instant::now();
        for i in 0..512 {
            let _ = h.try_enqueue_data(Bytes::from(vec![i as u8]), addr(5), None, None);
        }
        // Must not SyncSender-wait per packet (would be >> few ms under load).
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "fire-and-forget enqueue blocked too long: {:?}",
            start.elapsed()
        );
        spawn.handle.stop_and_join();
    }

    #[tokio::test]
    async fn enqueue_storm_still_delivers_tick_done() {
        let sock = test_socket().await;
        let mut spawn = spawn_worker(sock);
        let tick_tx = spawn.tick_tx.clone();
        let h = &spawn.handle;
        for i in 0..256 {
            let _ = h
                .enqueue_data_async(Bytes::from(vec![i as u8]), addr(6), None, None)
                .await;
        }
        tick_tx.try_send(()).unwrap();
        let ev = tokio::time::timeout(Duration::from_millis(500), spawn.handle.event_rx.recv())
            .await
            .expect("tick starved under enqueue storm")
            .expect("event");
        match ev {
            PacingEvent::TickDone { .. } => {}
        }
        spawn.handle.stop_and_join();
    }

    #[tokio::test]
    async fn enqueue_before_after_remove_peer_ordering() {
        let sock = test_socket().await;
        let mut spawn = spawn_worker(sock);
        let h = &spawn.handle;
        assert!(
            h.enqueue_data_async(Bytes::from_static(b"pre"), addr(7), None, None)
                .await
        );
        h.remove_peer_async(addr(7)).await;
        for _ in 0..50 {
            if h.load_obs().peer_data_queue_len(addr(7)) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(h.load_obs().peer_data_queue_len(addr(7)), 0);
        assert!(
            h.enqueue_data_async(Bytes::from_static(b"post"), addr(7), None, None)
                .await
        );
        h.set_config_async(h.load_obs().config).await;
        for _ in 0..50 {
            if h.load_obs().peer_data_queue_len(addr(7)) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(h.load_obs().peer_data_queue_len(addr(7)), 1);
        spawn.handle.stop_and_join();
    }

    #[tokio::test]
    async fn tick_produces_tick_done_event() {
        let sock = test_socket().await;
        let mut spawn = spawn_worker(sock.clone());
        let tick_tx = spawn.tick_tx.clone();
        assert!(
            spawn
                .handle
                .enqueue_data_async(Bytes::from_static(b"z"), addr(4), None, None)
                .await
        );
        tick_tx.try_send(()).unwrap();
        let ev = tokio::time::timeout(Duration::from_millis(200), spawn.handle.event_rx.recv())
            .await
            .expect("timeout")
            .expect("event");
        match ev {
            PacingEvent::TickDone { .. } => {}
        }
        spawn.handle.stop_and_join();
    }
}
