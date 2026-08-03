use std::collections::{HashMap, HashSet};
use std::env;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use parking_lot::RwLock;
use serde::Serialize;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;

use crate::bootstrap::{self, ReconnectOutcome};
use crate::config::{effective_decentralized_trackers, ConfigManager, IPPool, PeerInfo};
use crate::cpu_affinity;
use crate::crypto::{
    decode_invite, derive_network_id, encode_invite, now_epoch_ms, room_id_20b, room_id_hex,
    InvitePayload, Key, MintCrypto, PROTO_UDP,
};
use crate::metrics::EngineMetrics;
use crate::nat::{ice, stun, upnp};
use crate::net::engine::{
    EngineCmd, JoinAck, ParaCandidate as ParaEngineCandidate, ParaSignal, RuntimeSnapshot,
};
use crate::net::pace_clock::{self, PaceClockApply};
use crate::net::pacing::PacingConfig;
use crate::net::packet::WIRE_PROTOCOL_VERSION;
use crate::netinfo::{self, ensure_netinfo_dir};
use crate::process_priority;
use crate::routing::{owner_vip, RoutingTable};
use crate::runtime_trace::RuntimeTrace;
use crate::term_style;
#[cfg(windows)]
use crate::tun::{wintun::WintunAdapter, VirtualNetworkInterface};
use crate::windows_timer::{LowLatencyTimerGuard, TimerResolutionStatus};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppState {
    FirstRun,
    CommandLoop,
    Exiting,
}

const PORT_MIN: u16 = 1024;
const PORT_MAX: u16 = 65535;
const MAX_PEERS: usize = 253;

/// Fixed line count for `paint_runtime_frame` (header + flags + traffic + 2-col metrics).
const RUNTIME_DISPLAY_LINE_COUNT: usize = 53;
/// Minimum width of the left metrics column (right column follows after 2 spaces).
const RUNTIME_METRIC_COL_WIDTH: usize = 48;

const DEFAULT_UDP_SOCKBUF: i32 = 2 * 1024 * 1024;
const DEFAULT_UDP_RCVBUF: i32 = 2 * 1024 * 1024;
const UDP_SOCKBUF_MIN: i32 = 128 * 1024;
const UDP_SOCKBUF_MAX: i32 = 64 * 1024 * 1024;

const DEFAULT_WINTUN_RING_BYTES: u32 = 8 * 1024 * 1024;
const WINTUN_RING_MIN_BYTES: u32 = 128 * 1024;
const WINTUN_RING_MAX_BYTES: u32 = 32 * 1024 * 1024;
const WINTUN_IPV4_METRIC_MAX: u32 = 999_999;

use crate::net::pacing_defaults::{self as pace_def};

const DEFAULT_TUN_INJECT_QUEUE: usize = pace_def::DEFAULT_TUN_INJECT_QUEUE as usize;
const DEFAULT_TUN_FROM_ADAPTER_QUEUE: usize = pace_def::DEFAULT_TUN_FROM_ADAPTER_QUEUE as usize;

const JOIN_HANDSHAKE_PUNCH_KEY: &str = "join-handshake";
const PARA_PUNCH_WORKFLOW_DEADLINE_SECS: u64 = 25;
const PARA_SIGNAL_ATTEMPTS: u32 = 10;
const PARA_SIGNAL_PAUSE_MS: u64 = 1500;
const PARA_SIGNAL_JITTER_PCT: u64 = 20;
const PARA_LAN_DISCOVER_MS: u64 = 2500;
const PARA_OK_REDUNDANCY: u32 = 3;
const PARA_OK_GAP_MS: u64 = 200;
const PARA_PUNCH_ACK_REDUNDANCY: u32 = 5;
const PARA_PUNCH_ACK_GAP_MS: u64 = 150;
const PARA_START_BUFFER_MS: u64 = 1500;
const PARA_MAX_CLOCK_SKEW_MS: u64 = 5000;
const PARA_OK_WAIT_MS: u64 = 1500;
const PARA_KEEPALIVE_COUNT: u32 = 3;
const PARA_KEEPALIVE_GAP_MS: u64 = 100;
/// STUN attempts on headless daemon before failing (no interactive retry prompt).
const HEADLESS_STUN_ATTEMPTS: u32 = 3;

const PARA_OWNER_PASSIVE_MIN_BURST_WALL_MS: u64 = 1000;
const PARA_PEER_PUNCH_MIN_WALL_MS: u64 = 1000;

const PARA_PUNCH_ROUTE_DEBOUNCE_MS: u64 = 250;

const PARA_OWNER_ACK_DEADLINE_MS: u64 = 45_000;

const BANNER_DELAY_FIRST_RUN_MS: u64 = 20;

const WINTUN_CREATE_TIMEOUT_SECS: u64 = 45;

const PARA_OWNER_ACK_KEEPALIVE_PPS: u32 = 4;
const PARA_SESSION_TTL_MS: u64 = 90_000;
const PARA_MAX_PENDING_SESSIONS: usize = 16;

/// Invite-join choices normally prompted on the CLI client (daemon headless).
#[derive(Clone, Copy, Debug)]
struct JoinInviteRunOpts {
    use_public: bool,
    skip_share_gate: bool,
}

impl JoinInviteRunOpts {
    fn from_ipc(lan_mode: Option<bool>) -> Self {
        Self {
            use_public: !lan_mode.unwrap_or(false),
            skip_share_gate: true,
        }
    }

    fn daemon_default() -> Self {
        Self {
            use_public: true,
            skip_share_gate: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct ParaCandidate {
    ip: String,
    port: u16,
    kind: String,
}

#[derive(Debug, Clone, PartialEq)]
enum ParaState {
    HelloSent {
        attempts: u32,
    },
    ReplyReceived {
        peer_ep: SocketAddr,
        start_at_ms: u64,
    },
    OkSent {
        peer_ep: SocketAddr,
        start_at_ms: u64,
    },
    WaitingStart {
        peer_ep: SocketAddr,
        start_at_ms: u64,
        ok_confirmed: bool,
    },
    Punching,
    Connected,
    Failed {
        reason: String,
    },
}

#[derive(Debug, Clone)]
enum PendingParaSessionStatus {
    Pending,
    Running,
    Superseded,
    Closed,
}

#[derive(Debug, Clone)]
struct PendingParaSession {
    session_id: String,
    remote_node_id: String,
    signal_from: SocketAddr,
    remote_candidates: Vec<SocketAddr>,
    remote_vip: String,
    remote_ep: Option<SocketAddr>,
    created_at_ms: u64,
    agreed_start_at_ms: u64,
    agreed_key_raw: [u8; 32],
    lease_token: u64,
    status: PendingParaSessionStatus,
}

#[derive(Debug)]
struct PendingAckWait {
    tx: mpsc::Sender<()>,
    expiry_ms: u64,
    expected_node_id: String,
    expected_sources: HashSet<SocketAddr>,
    expected_vip: String,
}

async fn cli_ping_peer_rtt(
    cmd_tx: mpsc::Sender<EngineCmd>,
    ip: &str,
    port: u16,
    timeout_ms: u64,
) -> i64 {
    let Ok(target) = format!("{ip}:{port}").parse::<SocketAddr>() else {
        return -1;
    };
    let (tx, rx) = oneshot::channel();
    if cmd_tx
        .send(EngineCmd::PingPeer {
            dest: target,
            timeout_ms,
            reply: tx,
        })
        .await
        .is_err()
    {
        return -1;
    }
    match tokio::time::timeout(Duration::from_millis(timeout_ms + 200), rx).await {
        Ok(Ok(rtt)) => rtt,
        _ => -1,
    }
}

pub struct Cli {
    config: Arc<ConfigManager>,
    routing: Arc<RwLock<RoutingTable>>,
    cmd_tx: mpsc::Sender<EngineCmd>,
    peer_cache_reset_tx: Option<mpsc::UnboundedSender<oneshot::Sender<()>>>,
    owner_vip_pool: Option<Arc<parking_lot::Mutex<IPPool>>>,
    engine_metrics: Option<Arc<EngineMetrics>>,
    runtime_trace: Arc<RuntimeTrace>,
    state: AppState,
    pacing: PacingConfig,
    fec_enabled: bool,
    autoclear: bool,
    low_latency_timer: bool,
    last_timer_status: Option<TimerResolutionStatus>,
    #[cfg(windows)]
    timer_guard: Option<LowLatencyTimerGuard>,
    rawperf_enabled: bool,
    fec_forced_ratio: Option<(u8, u8)>,
    retransmit_bypass_pps: f64,
    tun_from_tun_tx: mpsc::Sender<Bytes>,
    tun_inject_rx: Option<broadcast::Receiver<Bytes>>,
    upnp_mapping: Option<upnp::UPnPMapping>,
    upnp_refresh_stop: Option<Arc<AtomicBool>>,
    upnp_refresh_task: Option<JoinHandle<()>>,
    parasitic_listener_stop: Option<Arc<AtomicBool>>,
    parasitic_listener_task: Option<JoinHandle<()>>,
    #[cfg(windows)]
    vni: Option<Arc<WintunAdapter>>,
    #[cfg(windows)]
    vni_slot: Arc<RwLock<Option<Arc<WintunAdapter>>>>,
    #[cfg(windows)]
    inject_task: Option<JoinHandle<()>>,
    /// Daemon has no stdin; interactive prompts must run on the CLI client.
    headless: bool,
    /// Set after session-open home was produced for BootstrapSnapshot (once per daemon life).
    reconnect_home_shown: bool,
}

impl Cli {
    pub fn new(
        config: Arc<ConfigManager>,
        routing: Arc<RwLock<RoutingTable>>,
        cmd_tx: mpsc::Sender<EngineCmd>,
        tun_from_tun_tx: mpsc::Sender<Bytes>,
        tun_inject_rx: broadcast::Receiver<Bytes>,
        peer_cache_reset_tx: Option<mpsc::UnboundedSender<oneshot::Sender<()>>>,
        owner_vip_pool: Option<Arc<parking_lot::Mutex<IPPool>>>,
        engine_metrics: Option<Arc<EngineMetrics>>,
        runtime_trace: Arc<RuntimeTrace>,
        headless: bool,
    ) -> Self {
        let snap = config.snapshot();
        let state = if snap.network_id.is_empty() {
            AppState::FirstRun
        } else {
            AppState::CommandLoop
        };
        let pacing = pacing_config_from_network(snap.as_ref());
        let fec_forced_ratio = fec_forced_ratio_from_network(snap.as_ref());
        let mut cli = Self {
            config,
            routing,
            cmd_tx,
            peer_cache_reset_tx,
            owner_vip_pool,
            engine_metrics,
            runtime_trace,
            state,
            pacing,
            fec_enabled: snap.fec_enabled,
            autoclear: true,
            low_latency_timer: snap.low_latency_timer_enabled,
            last_timer_status: None,
            #[cfg(windows)]
            timer_guard: None,
            rawperf_enabled: snap.rawperf_enabled,
            fec_forced_ratio,
            retransmit_bypass_pps: effective_retransmit_bypass_pps(snap.retransmit_bypass_pps),
            tun_from_tun_tx,
            tun_inject_rx: Some(tun_inject_rx),
            upnp_mapping: None,
            upnp_refresh_stop: None,
            upnp_refresh_task: None,
            parasitic_listener_stop: None,
            parasitic_listener_task: None,
            #[cfg(windows)]
            vni: None,
            #[cfg(windows)]
            vni_slot: Arc::new(RwLock::new(None)),
            #[cfg(windows)]
            inject_task: None,
            headless,
            reconnect_home_shown: false,
        };
        cli.apply_low_latency_timer_state();
        cli
    }

    fn report_timer_resolution(&mut self, status: TimerResolutionStatus) {
        self.last_timer_status = Some(status);
        if let Some(metrics) = &self.engine_metrics {
            metrics.set_timer_resolution(
                status.requested_us,
                status.applied_us,
                status.fallback_count,
            );
        }
        if status.applied_us > 0 {
            crate::cli_println!(
                "{}",
                term_style::fmt_info_line(format_args!(
                    " Windows timer resolution requested={}us applied={}us fallback_count={}",
                    status.requested_us, status.applied_us, status.fallback_count
                ))
            );
        } else if self.low_latency_timer {
            crate::cli_eprintln!(
                "[warn] Failed to request Windows timer resolution (requested={}us, fallback_count={})",
                status.requested_us, status.fallback_count
            );
        }
    }

    fn reapply_timer_metrics_after_view_begin(&self) {
        if let (Some(metrics), Some(status)) = (&self.engine_metrics, self.last_timer_status) {
            metrics.set_timer_resolution(
                status.requested_us,
                status.applied_us,
                status.fallback_count,
            );
        }
    }

    pub async fn runtime_view_begin(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCmd::RuntimeViewBegin { reply: tx })
            .await
            .map_err(|_| anyhow!("engine command channel closed"))?;
        match tokio::time::timeout(Duration::from_millis(500), rx).await {
            Ok(Ok(())) => {
                self.reapply_timer_metrics_after_view_begin();
                Ok(())
            }
            _ => Err(anyhow!("runtime view begin timed out")),
        }
    }

    pub async fn runtime_view_end(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCmd::RuntimeViewEnd { reply: tx })
            .await
            .map_err(|_| anyhow!("engine command channel closed"))?;
        match tokio::time::timeout(Duration::from_millis(500), rx).await {
            Ok(Ok(())) => Ok(()),
            _ => Err(anyhow!("runtime view end timed out")),
        }
    }

    pub fn runtime_view_end_best_effort(&self) {
        let (tx, _rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .try_send(EngineCmd::RuntimeViewEnd { reply: tx });
    }

    fn apply_low_latency_timer_state(&mut self) {
        #[cfg(windows)]
        {
            if self.low_latency_timer {
                if self.timer_guard.is_none() {
                    let (guard, status) = LowLatencyTimerGuard::request();
                    let active = guard.is_active();
                    self.timer_guard = Some(guard);
                    if active {
                        self.report_timer_resolution(status);
                    }
                }
            } else {
                self.timer_guard = None;
                if let Some(metrics) = &self.engine_metrics {
                    metrics.set_timer_resolution(0, 0, 0);
                }
            }
        }
        #[cfg(not(windows))]
        {
            let _ = self.low_latency_timer;
        }
    }

    fn set_low_latency_timer(&mut self, enabled: bool) {
        if self.low_latency_timer == enabled {
            return;
        }
        self.low_latency_timer = enabled;
        self.config
            .update(|c| c.low_latency_timer_enabled = enabled);
        self.apply_low_latency_timer_state();
        if enabled {
            #[cfg(not(windows))]
            crate::cli_println!(
                "{}",
                term_style::fmt_info_line(format_args!(
                    " Windows timer resolution is only available on Windows."
                ))
            );
        } else {
            crate::cli_println!(
                "{}",
                term_style::fmt_info_line(format_args!(
                    " Windows timer resolution: off (system default)"
                ))
            );
        }
    }

    fn refresh_owner_vip_pool_from_config(&mut self, force_rebuild: bool) {
        let snap = self.config.snapshot();
        if snap.role != "owner" || snap.virtual_ip.is_empty() {
            if force_rebuild {
                self.owner_vip_pool = None;
            }
            return;
        }
        if self.owner_vip_pool.is_some() && !force_rebuild {
            return;
        }
        let owner_vip = snap.virtual_ip.clone();
        let mut pool = IPPool::new(&owner_vip);
        for used in self.config.used_virtual_ips() {
            if used != owner_vip {
                pool.mark_used(&used);
            }
        }
        for p in &snap.peers {
            if !p.node_id.is_empty() && !p.virtual_ip.is_empty() {
                pool.ensure_allocated(&p.node_id, &p.virtual_ip);
            }
        }
        self.owner_vip_pool = Some(Arc::new(parking_lot::Mutex::new(pool)));
    }

    /// Push FEC/DRR/rawperf/retransmit settings from saved config into the live engine.
    pub async fn apply_saved_runtime_perf_to_engine(&self) -> Result<()> {
        let snap = self.config.snapshot();
        if self
            .cmd_tx
            .send(EngineCmd::SetFecEnabled(snap.fec_enabled))
            .await
            .is_err()
        {
            return Err(anyhow!("engine unavailable: cannot apply saved FEC toggle"));
        }
        let (data, parity, force) =
            if snap.fec_force_data_shards > 0 && snap.fec_force_parity_shards > 0 {
                (
                    snap.fec_force_data_shards,
                    snap.fec_force_parity_shards,
                    true,
                )
            } else {
                (10, 2, false)
            };
        if self
            .cmd_tx
            .send(EngineCmd::SetFecConfig {
                data_shards: data,
                parity_shards: parity,
                force_ratio: force,
            })
            .await
            .is_err()
        {
            return Err(anyhow!("engine unavailable: cannot apply saved FEC ratio"));
        }
        if self
            .cmd_tx
            .send(EngineCmd::SetDrrEnabled(snap.drr_enabled))
            .await
            .is_err()
        {
            return Err(anyhow!("engine unavailable: cannot apply saved DRR toggle"));
        }
        if self
            .cmd_tx
            .send(EngineCmd::SetRawPerf(snap.rawperf_enabled))
            .await
            .is_err()
        {
            return Err(anyhow!(
                "engine unavailable: cannot apply saved rawperf toggle"
            ));
        }
        let rtrx = effective_retransmit_bypass_pps(snap.retransmit_bypass_pps);
        if self
            .cmd_tx
            .send(EngineCmd::SetRetransmitBypassPps(rtrx))
            .await
            .is_err()
        {
            return Err(anyhow!(
                "engine unavailable: cannot apply saved retransmit bypass"
            ));
        }
        let adapter_mtu = effective_adapter_mtu(snap.adapter_mtu) as u16;
        if self
            .cmd_tx
            .send(EngineCmd::SetMtuPin {
                pin_mtu: snap.pin_mtu,
                adapter_mtu,
            })
            .await
            .is_err()
        {
            return Err(anyhow!("engine unavailable: cannot apply saved MTU pin"));
        }
        Ok(())
    }

    /// Engine/daemon startup: restore adapter, sync profile, parasitic listener (no REPL).
    pub async fn run_daemon_bootstrap(&mut self) -> Result<()> {
        let peer_parasitic_defer = self.daemon_bootstrap_before_reconnect().await?;
        let outcome = if peer_parasitic_defer {
            self.parasitic_auto_reconnect().await?
        } else {
            ReconnectOutcome::Skipped
        };
        let _ = self
            .daemon_bootstrap_finalize(outcome, peer_parasitic_defer)
            .await?;
        Ok(())
    }

    /// Pre-reconnect daemon bootstrap (adapter, engine sync, passive listener).
    pub async fn daemon_bootstrap_before_reconnect(&mut self) -> Result<bool> {
        let snap_at_start = self.config.snapshot();
        let parasitic_at_start = snap_at_start.parasitic_enabled;
        let role_at_start = snap_at_start.role.clone();
        drop(snap_at_start);
        let peer_parasitic_defer = parasitic_at_start && role_at_start == "peer";
        if !peer_parasitic_defer {
            self.restore_adapter_from_saved_session().await?;
        }
        let apply = PaceClockApply::from_network_config(self.config.snapshot().as_ref());
        let _ = self.cmd_tx.try_send(EngineCmd::SetPacingAndPaceClock {
            cfg: self.pacing,
            apply,
        });
        let _ = self.apply_saved_runtime_perf_to_engine().await;
        if self.state == AppState::CommandLoop {
            if let Err(e) = self.sync_engine_from_saved_profile().await {
                crate::cli_eprintln!(
                    "{}",
                    term_style::fmt_info_line_stderr(format_args!(
                        " Engine profile sync skipped: {e}"
                    ))
                );
            }
            self.ensure_parasitic_passive_listener().await?;
        }
        Ok(peer_parasitic_defer)
    }

    /// Post-reconnect: session-open home block (+ SessionReady on headless).
    pub async fn daemon_bootstrap_finalize(
        &mut self,
        outcome: ReconnectOutcome,
        parasitic_attempted: bool,
    ) -> Result<bootstrap::BootstrapSnapshot> {
        if self.state != AppState::CommandLoop || !self.has_active_profile() {
            return Ok(bootstrap::BootstrapSnapshot {
                complete: true,
                parasitic_attempted,
                outcome: None,
                home_lines: vec![],
            });
        }
        let effective = outcome;
        if self.reconnect_home_shown {
            return Ok(bootstrap::BootstrapSnapshot {
                complete: true,
                parasitic_attempted,
                outcome: Some(effective),
                home_lines: vec![],
            });
        }
        if self.headless {
            // Home lines go into the snapshot only; CLI takes them once (not UI replay).
            let home_lines = self
                .emit_session_home_block(effective, false, false)
                .await?;
            return Ok(bootstrap::BootstrapSnapshot {
                complete: true,
                parasitic_attempted,
                outcome: Some(effective),
                home_lines,
            });
        }
        let home_lines = self
            .emit_session_home_block(effective, false, false)
            .await?;
        Ok(bootstrap::BootstrapSnapshot {
            complete: true,
            parasitic_attempted,
            outcome: Some(effective),
            home_lines,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        self.run_daemon_bootstrap().await?;

        if self.state == AppState::CommandLoop && !self.reconnect_home_shown {
            let _ = self
                .emit_session_home_block(ReconnectOutcome::Skipped, false, false)
                .await?;
        }

        while self.state != AppState::Exiting {
            if self.state == AppState::FirstRun {
                self.show_first_run_menu().await?;
                continue;
            }

            crate::cli_print!("{}", term_style::fmt_input_prompt());
            io::stdout().flush()?;
            let line = read_line_async().await?;
            if line.is_empty() {
                continue;
            }
            self.process_command(line).await?;
        }
        Ok(())
    }

    async fn ensure_parasitic_passive_listener(&mut self) -> Result<()> {
        let snap = self.config.snapshot();
        let should_run = self.state == AppState::CommandLoop
            && snap.role == "owner"
            && !snap.network_id.is_empty()
            && !snap.crypto_key.is_empty()
            && !snap.virtual_ip.is_empty();
        drop(snap);

        if !should_run {
            self.stop_parasitic_passive_listener();
            return Ok(());
        }
        if self.parasitic_listener_task.is_some() {
            return Ok(());
        }

        let stop = Arc::new(AtomicBool::new(false));
        let (sig_tx, mut sig_rx) = mpsc::channel::<ParaSignal>(2048);
        let listener_id = register_para_listener(&self.cmd_tx, sig_tx, true).await;

        let cmd_tx = self.cmd_tx.clone();
        let config = self.config.clone();
        let routing = self.routing.clone();
        let owner_vip_pool = self.owner_vip_pool.clone();
        let stop_flag = stop.clone();
        self.parasitic_listener_stop = Some(stop);
        self.parasitic_listener_task = Some(tokio::spawn(async move {
            let mut sessions: HashMap<String, PendingParaSession> = HashMap::new();
            let mut pending_oks: HashMap<String, u64> = HashMap::new();
            let mut pending_acks: HashMap<String, PendingAckWait> = HashMap::new();
            let mut node_to_session: HashMap<String, String> = HashMap::new();
            let mut active_from: HashMap<SocketAddr, String> = HashMap::new();
            let mut running_sessions: HashMap<String, PendingParaSession> = HashMap::new();
            let mut vip_owners: HashMap<String, (String, u64)> = HashMap::new();
            let mut peer_candidates: HashMap<String, Vec<SocketAddr>> = HashMap::new();
            let mut peer_node_to_vip: HashMap<String, String> = HashMap::new();
            let mut lease_counter: u64 = 1;
            let mut workers =
                tokio::task::JoinSet::<(String, String, SocketAddr, String, u64, bool)>::new();
            let mut reply_tasks = tokio::task::JoinSet::<(SocketAddr, Vec<u8>)>::new();
            let mut session_punch_cancel: HashMap<String, Arc<AtomicBool>> = HashMap::new();
            const OK_BEFORE_HELLO_GRACE_MS: u64 = 3_000;

            let cleanup_vip = |vip: &str,
                               routing: &Arc<RwLock<RoutingTable>>,
                               pool: &Option<Arc<parking_lot::Mutex<IPPool>>>,
                               config: &Arc<ConfigManager>| {
                if vip.is_empty() {
                    return;
                }
                routing.write().remove(vip);
                let _ = cmd_tx.try_send(crate::net::engine::EngineCmd::PeerRouteRemoved {
                    vip: vip.to_string(),
                });
                if let Some(pool) = pool.as_ref() {
                    pool.lock().release(vip);
                }
                config.remove_peer_by_vip(vip);
            };
            let should_cleanup_vip =
                |vip: &str,
                 session_id: &str,
                 lease_token: u64,
                 vip_owners: &HashMap<String, (String, u64)>,
                 running_sessions: &HashMap<String, PendingParaSession>| {
                    if !vip_owner_matches(vip_owners, vip, session_id, lease_token) {
                        return false;
                    }
                    !running_sessions.values().any(|s| {
                        s.remote_vip == vip
                            && s.session_id != session_id
                            && matches!(s.status, PendingParaSessionStatus::Running)
                    })
                };

            let spawn_session_worker =
                |workers: &mut tokio::task::JoinSet<(
                    String,
                    String,
                    SocketAddr,
                    String,
                    u64,
                    bool,
                )>,
                 cmd_tx: &mpsc::Sender<EngineCmd>,
                 routing: &Arc<RwLock<RoutingTable>>,
                 pending_acks: &mut HashMap<String, PendingAckWait>,
                 session_punch_cancel: &mut HashMap<String, Arc<AtomicBool>>,
                 session: PendingParaSession| {
                    let cmd_tx = cmd_tx.clone();
                    let routing = routing.clone();
                    let punch_cancel = Arc::new(AtomicBool::new(false));
                    session_punch_cancel.insert(session.session_id.clone(), punch_cancel.clone());
                    let (ack_tx, mut ack_rx) = mpsc::channel::<()>(4);
                    let mut expected_sources = HashSet::new();
                    expected_sources.insert(session.signal_from);
                    if let Some(peer) = session.remote_ep {
                        expected_sources.insert(peer);
                    }
                    for peer in &session.remote_candidates {
                        expected_sources.insert(*peer);
                    }
                    pending_acks.insert(
                        session.session_id.clone(),
                        PendingAckWait {
                            tx: ack_tx,
                            expiry_ms: now_epoch_ms().saturating_add(PARA_SESSION_TTL_MS),
                            expected_node_id: session.remote_node_id.clone(),
                            expected_sources,
                            expected_vip: session.remote_vip.clone(),
                        },
                    );
                    workers.spawn(async move {
                        wait_until_para_start(session.agreed_start_at_ms).await;
                        let key_raw = session.agreed_key_raw;
                        // Keep owner primary network key; only bind/add for this peer.
                        let _ = cmd_tx.send(EngineCmd::AddCryptoKey(Key(key_raw))).await;
                        let mut bind_targets = Vec::new();
                        let mut seen_targets = HashSet::new();
                        if seen_targets.insert(session.signal_from) {
                            bind_targets.push(session.signal_from);
                        }
                        if let Some(peer) = session.remote_ep {
                            if seen_targets.insert(peer) {
                                bind_targets.push(peer);
                            }
                        }
                        for peer in &session.remote_candidates {
                            if seen_targets.insert(*peer) {
                                bind_targets.push(*peer);
                            }
                        }
                        for peer in bind_targets {
                            let _ = cmd_tx
                                .send(EngineCmd::BindPeerKey {
                                    peer,
                                    key: Key(key_raw),
                                })
                                .await;
                        }
                        let ready = run_parasitic_punch_worker(
                            cmd_tx.clone(),
                            routing.clone(),
                            session.remote_candidates.clone(),
                            session.remote_vip.clone(),
                            format!("para-passive-{}", session.session_id),
                            punch_cancel,
                        )
                        .await;
                        if ready {
                            let keepalive_key = format!("para-ack-{}", session.session_id);
                            let _ = cmd_tx
                                .send(EngineCmd::SetPeerKeepalive {
                                    key: keepalive_key.clone(),
                                    targets: session.remote_candidates.clone(),
                                    interval_ms: 1000 / PARA_OWNER_ACK_KEEPALIVE_PPS as u64,
                                })
                                .await;
                            let ack_wait = tokio::time::timeout(
                                Duration::from_millis(PARA_OWNER_ACK_DEADLINE_MS),
                                ack_rx.recv(),
                            )
                            .await;
                            let _ = cmd_tx
                                .send(EngineCmd::StopPeerKeepalive { key: keepalive_key })
                                .await;
                            let acked = ack_wait.ok().flatten().is_some();
                            return (
                                session.session_id.clone(),
                                session.remote_node_id.clone(),
                                session.signal_from,
                                session.remote_vip.clone(),
                                session.lease_token,
                                acked,
                            );
                        }
                        (
                            session.session_id.clone(),
                            session.remote_node_id.clone(),
                            session.signal_from,
                            session.remote_vip.clone(),
                            session.lease_token,
                            false,
                        )
                    });
                };

            loop {
                while let Some(done) = workers.try_join_next() {
                    if let Ok((sid, node_id, from, vip, lease, acked)) = done {
                        pending_acks.remove(&sid);
                        session_punch_cancel.remove(&sid);
                        pending_oks.remove(&sid);
                        if let Some(session) = running_sessions.get_mut(&sid) {
                            session.status = PendingParaSessionStatus::Closed;
                        }
                        running_sessions.remove(&sid);
                        sessions.remove(&sid);
                        if active_from.get(&from).map(|v| v == &sid).unwrap_or(false) {
                            active_from.remove(&from);
                        }
                        if node_to_session
                            .get(&node_id)
                            .map(|v| v == &sid)
                            .unwrap_or(false)
                        {
                            node_to_session.remove(&node_id);
                        }
                        if acked {
                            crate::cli_println!(
                                "{}",
                                term_style::fmt_para_passive_line_success(format_args!(
                                    " Connected (session={} node={}).",
                                    sid, node_id
                                ))
                            );
                            let _ = cmd_tx.send(EngineCmd::TriggerMembershipBroadcast).await;
                            let new_cands =
                                peer_candidates.get(&node_id).cloned().unwrap_or_default();
                            let other_pairs: Vec<(String, Vec<SocketAddr>)> = peer_candidates
                                .iter()
                                .filter(|(other_node, _)| other_node.as_str() != node_id.as_str())
                                .map(|(n, c)| (n.clone(), c.clone()))
                                .collect();
                            for (other_node, other_cands) in other_pairs {
                                let other_vip = match peer_node_to_vip.get(&other_node).cloned() {
                                    Some(v) => v,
                                    None => continue,
                                };
                                let other_ep = { routing.read().lookup(&other_vip) };
                                let Some(other_ep) = other_ep else { continue };
                                let new_payload =
                                    serde_json::to_value(candidates_to_ice(&new_cands))
                                        .unwrap_or(json!([]));
                                let _ = cmd_tx
                                    .send(EngineCmd::SendPeerRelay {
                                        relay_ep: other_ep,
                                        dst_node: other_node.clone(),
                                        kind: "candidates".to_string(),
                                        payload: new_payload,
                                    })
                                    .await;
                                let other_payload =
                                    serde_json::to_value(candidates_to_ice(&other_cands))
                                        .unwrap_or(json!([]));
                                let _ = cmd_tx
                                    .send(EngineCmd::SendPeerRelay {
                                        relay_ep: from,
                                        dst_node: node_id.clone(),
                                        kind: "candidates".to_string(),
                                        payload: other_payload,
                                    })
                                    .await;
                            }
                        } else if should_cleanup_vip(
                            &vip,
                            &sid,
                            lease,
                            &vip_owners,
                            &running_sessions,
                        ) {
                            let route_still_live = {
                                let rt = routing.read();
                                rt.table
                                    .get(&vip)
                                    .map(|entry| {
                                        matches!(
                                            entry.state,
                                            crate::routing::RouteState::Active
                                                | crate::routing::RouteState::Candidate
                                        )
                                    })
                                    .unwrap_or(false)
                            };
                            if route_still_live {
                                crate::cli_println!(
                                    "{}",
                                    term_style::fmt_para_passive_line(format_args!(
                                        " ACK timeout but route still live; skip rollback (sid={}).",
                                        sid
                                    ))
                                );
                            } else {
                                vip_owners.remove(&vip);
                                peer_candidates.remove(&node_id);
                                peer_node_to_vip.remove(&node_id);
                                cleanup_vip(&vip, &routing, &owner_vip_pool, &config);
                                crate::cli_println!(
                                    "{}",
                                    term_style::fmt_para_passive_line(format_args!(
                                        " Rollback: peer ack timeout (sid={}).",
                                        sid
                                    ))
                                );
                            }
                        }
                    }
                }
                while let Some(done) = reply_tasks.try_join_next() {
                    if let Ok((target_vip, payload)) = done {
                        let _ = cmd_tx
                            .send(EngineCmd::ParaSendReply {
                                target_vip,
                                payload,
                            })
                            .await;
                    }
                }
                if stop_flag.load(Ordering::Acquire) {
                    workers.abort_all();
                    reply_tasks.abort_all();
                    let all_owned_vips: Vec<String> = vip_owners.keys().cloned().collect();
                    for vip in all_owned_vips {
                        cleanup_vip(&vip, &routing, &owner_vip_pool, &config);
                    }
                    peer_candidates.clear();
                    peer_node_to_vip.clear();
                    break;
                }
                let recv = tokio::time::timeout(Duration::from_millis(600), sig_rx.recv()).await;
                let Ok(Some(sig)) = recv else {
                    let now = now_epoch_ms();
                    let stale: Vec<(String, String, SocketAddr, String, u64)> = sessions
                        .iter()
                        .filter(|(_, s)| now.saturating_sub(s.created_at_ms) > PARA_SESSION_TTL_MS)
                        .map(|(sid, s)| {
                            (
                                sid.clone(),
                                s.remote_node_id.clone(),
                                s.signal_from,
                                s.remote_vip.clone(),
                                s.lease_token,
                            )
                        })
                        .collect();
                    for (sid, node, from, vip, lease) in stale {
                        if let Some(session) = sessions.get_mut(&sid) {
                            session.status = PendingParaSessionStatus::Closed;
                        }
                        sessions.remove(&sid);
                        if node_to_session
                            .get(&node)
                            .map(|v| v == &sid)
                            .unwrap_or(false)
                        {
                            node_to_session.remove(&node);
                        }
                        if active_from.get(&from).map(|v| v == &sid).unwrap_or(false) {
                            active_from.remove(&from);
                        }
                        if should_cleanup_vip(&vip, &sid, lease, &vip_owners, &running_sessions) {
                            vip_owners.remove(&vip);
                            peer_candidates.remove(&node);
                            peer_node_to_vip.remove(&node);
                            cleanup_vip(&vip, &routing, &owner_vip_pool, &config);
                        }
                    }
                    pending_oks.retain(|_, expiry| now <= *expiry);
                    pending_acks.retain(|_, wait| now <= wait.expiry_ms);
                    continue;
                };
                let snap = config.snapshot();
                if snap.role != "owner" || snap.network_id.is_empty() || snap.crypto_key.is_empty()
                {
                    continue;
                }
                match sig {
                    ParaSignal::HelloReceived {
                        from,
                        public_ip,
                        public_port,
                        proposed_key: _,
                        proposed_vip_subnet,
                        candidates,
                        start_at_ms,
                        session_id,
                        node_id,
                        discover_only,
                        ..
                    } => {
                        let remote_node_id = node_id.trim().to_string();
                        if remote_node_id.is_empty() {
                            continue;
                        }
                        if discover_only {
                            let snap_for_reply = snap.clone();
                            let cmd_tx_for_reply = cmd_tx.clone();
                            let reply_network_id = snap_for_reply.network_id.clone();
                            let session_id_for_reply = session_id.clone();
                            reply_tasks.spawn(async move {
                                let local_candidates = owner_reply_para_candidates(
                                    &snap_for_reply,
                                    &cmd_tx_for_reply,
                                    from,
                                    Duration::from_secs(1),
                                )
                                .await;
                                let reply = build_owner_para_reply_bytes(
                                    &snap_for_reply,
                                    &local_candidates,
                                    "",
                                    &reply_network_id,
                                    now_epoch_ms() + PARA_START_BUFFER_MS,
                                    &session_id_for_reply,
                                    false,
                                );
                                (from, reply)
                            });
                            continue;
                        }
                        if session_id.is_empty() {
                            continue;
                        }
                        if running_sessions.contains_key(&session_id) {
                            continue;
                        }
                        if let Some(existing) = sessions.get(&session_id) {
                            if existing.remote_node_id != remote_node_id {
                                continue;
                            }
                            active_from.insert(from, session_id.clone());
                            node_to_session.insert(remote_node_id.clone(), session_id.clone());
                            let snap_for_reply = snap.clone();
                            let cmd_tx_for_reply = cmd_tx.clone();
                            let assigned_vip_for_reply = existing.remote_vip.clone();
                            let session_id_for_reply = existing.session_id.clone();
                            let agreed_start_at_ms = existing.agreed_start_at_ms;
                            let reply_network_id_for_reply = if snap_for_reply.network_id.is_empty()
                            {
                                derive_network_id(&Key(existing.agreed_key_raw))
                            } else {
                                snap_for_reply.network_id.clone()
                            };
                            reply_tasks.spawn(async move {
                                let local_candidates = owner_reply_para_candidates(
                                    &snap_for_reply,
                                    &cmd_tx_for_reply,
                                    from,
                                    Duration::from_secs(1),
                                )
                                .await;
                                let reply = build_owner_para_reply_bytes(
                                    &snap_for_reply,
                                    &local_candidates,
                                    &assigned_vip_for_reply,
                                    &reply_network_id_for_reply,
                                    agreed_start_at_ms,
                                    &session_id_for_reply,
                                    true,
                                );
                                (from, reply)
                            });
                            continue;
                        }
                        if let Some(prev_sid) = active_from.get(&from).cloned() {
                            if prev_sid != session_id {
                                if let Some(prev) = sessions.get_mut(&prev_sid) {
                                    prev.status = PendingParaSessionStatus::Superseded;
                                }
                                if let Some(prev) = sessions.remove(&prev_sid) {
                                    peer_candidates.remove(&prev.remote_node_id);
                                    peer_node_to_vip.remove(&prev.remote_node_id);
                                    if should_cleanup_vip(
                                        &prev.remote_vip,
                                        &prev.session_id,
                                        prev.lease_token,
                                        &vip_owners,
                                        &running_sessions,
                                    ) {
                                        vip_owners.remove(&prev.remote_vip);
                                        cleanup_vip(
                                            &prev.remote_vip,
                                            &routing,
                                            &owner_vip_pool,
                                            &config,
                                        );
                                    }
                                }
                                if let Some(prev) = running_sessions.get_mut(&prev_sid) {
                                    prev.status = PendingParaSessionStatus::Superseded;
                                }
                                pending_oks.remove(&prev_sid);
                                pending_acks.remove(&prev_sid);
                                active_from.remove(&from);
                            }
                        }
                        if let Some(prev_sid) = node_to_session.get(&remote_node_id).cloned() {
                            if prev_sid != session_id {
                                if let Some(prev) = sessions.get_mut(&prev_sid) {
                                    prev.status = PendingParaSessionStatus::Superseded;
                                }
                                if let Some(prev) = sessions.remove(&prev_sid) {
                                    peer_candidates.remove(&prev.remote_node_id);
                                    peer_node_to_vip.remove(&prev.remote_node_id);
                                    if should_cleanup_vip(
                                        &prev.remote_vip,
                                        &prev.session_id,
                                        prev.lease_token,
                                        &vip_owners,
                                        &running_sessions,
                                    ) {
                                        vip_owners.remove(&prev.remote_vip);
                                        cleanup_vip(
                                            &prev.remote_vip,
                                            &routing,
                                            &owner_vip_pool,
                                            &config,
                                        );
                                    }

                                    if active_from
                                        .get(&prev.signal_from)
                                        .map(|sid| sid == &prev_sid)
                                        .unwrap_or(false)
                                    {
                                        active_from.remove(&prev.signal_from);
                                    }
                                }
                                if let Some(prev) = running_sessions.get_mut(&prev_sid) {
                                    prev.status = PendingParaSessionStatus::Superseded;
                                }
                                pending_oks.remove(&prev_sid);
                                pending_acks.remove(&prev_sid);
                                node_to_session.remove(&remote_node_id);
                            }
                        }
                        if sessions.len() >= PARA_MAX_PENDING_SESSIONS
                            && !sessions.contains_key(&session_id)
                        {
                            continue;
                        }
                        let Ok(agreed_key_raw) = parse_key_hex_32(snap.crypto_key.trim()) else {
                            crate::cli_eprintln!(
                                "{}",
                                term_style::fmt_para_line_stderr(format_args!(
                                    " Passive: reject HELLO (invalid owner crypto_key)."
                                ))
                            );
                            continue;
                        };
                        let ep = if is_rfc1918_private_ip(from.ip()) {
                            from
                        } else if let Ok(parsed) = make_socket_addr(&public_ip, public_port) {
                            parsed
                        } else {
                            continue;
                        };
                        let mut remote_candidates = candidates_to_socket_addrs(&candidates);
                        if is_rfc1918_private_ip(from.ip()) {
                            remote_candidates.retain(|a| is_rfc1918_private_ip(a.ip()));
                        }
                        if !remote_candidates.contains(&ep) {
                            remote_candidates.push(ep);
                        }
                        let assigned_vip = if let Some(pool) = owner_vip_pool.as_ref() {
                            let endpoint = ep.to_string();

                            let preserve_vip = config
                                .find_peer_by_node_id(&remote_node_id)
                                .map(|p| p.virtual_ip)
                                .filter(|v| !v.is_empty());
                            let removed =
                                config.remove_peers_by_endpoint(&endpoint, &remote_node_id);
                            for peer in removed {
                                if peer.virtual_ip.is_empty() {
                                    continue;
                                }
                                if preserve_vip
                                    .as_deref()
                                    .map(|kept| kept == peer.virtual_ip)
                                    .unwrap_or(false)
                                {
                                    continue;
                                }
                                routing.write().remove(&peer.virtual_ip);
                                pool.lock().release(&peer.virtual_ip);
                            }
                            let assigned = {
                                let mut guard = pool.lock();
                                if let Some(vip) = preserve_vip.clone() {
                                    guard.ensure_allocated(&remote_node_id, &vip);
                                    Some(vip)
                                } else if let Some(existing) =
                                    config.find_peer_by_node_id(&remote_node_id)
                                {
                                    guard.ensure_allocated(&remote_node_id, &existing.virtual_ip);
                                    Some(existing.virtual_ip)
                                } else {
                                    guard.allocate(&remote_node_id)
                                }
                            };
                            if let Some(vip) = assigned {
                                config.add_peer(PeerInfo {
                                    node_id: remote_node_id.clone(),
                                    name: remote_node_id.clone(),
                                    virtual_ip: vip.clone(),
                                    real_ip: endpoint,
                                });
                                vip
                            } else {
                                let snap_for_reply = snap.clone();
                                let cmd_tx_for_reply = cmd_tx.clone();
                                let session_id_for_reply = session_id.clone();
                                reply_tasks.spawn(async move {
                                    let local_candidates = owner_reply_para_candidates(
                                        &snap_for_reply,
                                        &cmd_tx_for_reply,
                                        from,
                                        Duration::from_secs(1),
                                    )
                                    .await;
                                    let reject = build_owner_para_reply_bytes(
                                        &snap_for_reply,
                                        &local_candidates,
                                        "",
                                        "",
                                        now_epoch_ms() + PARA_START_BUFFER_MS,
                                        &session_id_for_reply,
                                        false,
                                    );
                                    (from, reject)
                                });
                                continue;
                            }
                        } else {
                            let owner_subnet = if snap.virtual_ip.is_empty() {
                                proposed_vip_subnet
                            } else {
                                snap.virtual_ip.clone()
                            };
                            vip_from_owner_subnet(&owner_subnet, false)
                                .unwrap_or_else(|_| "10.0.0.2".to_string())
                        };

                        let agreed_start_at_ms = compute_agreed_start_at_ms(
                            start_at_ms,
                            now_epoch_ms() + PARA_START_BUFFER_MS,
                        );

                        let reply_network_id = if snap.network_id.is_empty() {
                            derive_network_id(&Key(agreed_key_raw))
                        } else {
                            snap.network_id.clone()
                        };
                        let session_remote_cands = remote_candidates.clone();
                        let session = PendingParaSession {
                            session_id: session_id.clone(),
                            remote_node_id: remote_node_id.clone(),
                            signal_from: from,
                            remote_candidates,
                            remote_vip: assigned_vip.clone(),
                            remote_ep: Some(ep),
                            created_at_ms: now_epoch_ms(),
                            agreed_start_at_ms,
                            agreed_key_raw,
                            lease_token: lease_counter,
                            status: PendingParaSessionStatus::Pending,
                        };
                        lease_counter = lease_counter.wrapping_add(1);

                        vip_owners.insert(
                            assigned_vip.clone(),
                            (session_id.clone(), session.lease_token),
                        );
                        peer_candidates.insert(remote_node_id.clone(), session_remote_cands);
                        peer_node_to_vip.insert(remote_node_id.clone(), assigned_vip.clone());
                        sessions.insert(session_id.clone(), session);
                        node_to_session.insert(remote_node_id, session_id.clone());
                        active_from.insert(from, session_id.clone());
                        let snap_for_reply = snap.clone();
                        let cmd_tx_for_reply = cmd_tx.clone();
                        let assigned_vip_for_reply = assigned_vip.clone();
                        let reply_network_id_for_reply = reply_network_id.clone();
                        let session_id_for_reply = session_id.clone();
                        reply_tasks.spawn(async move {
                            let local_candidates = owner_reply_para_candidates(
                                &snap_for_reply,
                                &cmd_tx_for_reply,
                                from,
                                Duration::from_secs(3),
                            )
                            .await;
                            let reply = build_owner_para_reply_bytes(
                                &snap_for_reply,
                                &local_candidates,
                                &assigned_vip_for_reply,
                                &reply_network_id_for_reply,
                                agreed_start_at_ms,
                                &session_id_for_reply,
                                true,
                            );
                            (from, reply)
                        });
                        if pending_oks.remove(&session_id).is_some() {
                            if let Some(mut session) = sessions.remove(&session_id) {
                                if !pending_acks.contains_key(&session.session_id) {
                                    session.status = PendingParaSessionStatus::Running;
                                    running_sessions
                                        .insert(session.session_id.clone(), session.clone());
                                    spawn_session_worker(
                                        &mut workers,
                                        &cmd_tx,
                                        &routing,
                                        &mut pending_acks,
                                        &mut session_punch_cancel,
                                        session,
                                    );
                                }
                            }
                        }
                    }
                    ParaSignal::ReplyReceived {
                        session_id,
                        assigned_vip,
                        candidates,
                        ..
                    } => {
                        if session_id.is_empty() {
                            continue;
                        }
                        if let Some(session) = sessions.get_mut(&session_id) {
                            if !assigned_vip.is_empty() {
                                session.remote_vip = assigned_vip;
                            }
                            let mut remote_candidates = candidates_to_socket_addrs(&candidates);
                            if remote_candidates.is_empty() {
                                if let Some(ep) = session.remote_ep {
                                    remote_candidates.push(ep);
                                }
                            }
                            session.remote_candidates = remote_candidates;
                        }
                    }
                    ParaSignal::OkReceived { session_id, .. } => {
                        if session_id.is_empty() {
                            continue;
                        }

                        if pending_acks.contains_key(&session_id) {
                            continue;
                        }
                        if let Some(mut session) = sessions.remove(&session_id) {
                            session.status = PendingParaSessionStatus::Running;
                            running_sessions.insert(session.session_id.clone(), session.clone());
                            spawn_session_worker(
                                &mut workers,
                                &cmd_tx,
                                &routing,
                                &mut pending_acks,
                                &mut session_punch_cancel,
                                session,
                            );
                        } else {
                            pending_oks.insert(
                                session_id,
                                now_epoch_ms().saturating_add(OK_BEFORE_HELLO_GRACE_MS),
                            );
                        }
                    }
                    ParaSignal::PunchAckReceived {
                        from,
                        node_id,
                        session_id,
                    } => {
                        if session_id.is_empty() {
                            continue;
                        }
                        if let Some(waiter) = pending_acks.get_mut(&session_id) {
                            let node_ok = waiter.expected_node_id.is_empty()
                                || waiter.expected_node_id == node_id;
                            let dynamic_route_ok = if waiter.expected_vip.is_empty() {
                                false
                            } else {
                                let rt_ep = { routing.read().lookup(&waiter.expected_vip) };
                                rt_ep.map(|ep| ep == from).unwrap_or(false)
                            };
                            let ip_ok = waiter.expected_sources.iter().any(|s| s.ip() == from.ip());
                            if dynamic_route_ok {
                                waiter.expected_sources.insert(from);
                            } else if ip_ok {
                                waiter.expected_sources.insert(from);
                            }
                            let source_ok = waiter.expected_sources.contains(&from);
                            if node_ok && (source_ok || dynamic_route_ok || ip_ok) {
                                stop_para_passive_punch_loops(&cmd_tx, &session_id);
                                if let Some(cancel) = session_punch_cancel.get(&session_id) {
                                    cancel.store(true, Ordering::Release);
                                }
                                let _ = waiter.tx.try_send(());
                            } else {
                                crate::cli_eprintln!(
                                    "{}",
                                    term_style::fmt_para_passive_line_stderr(format_args!(
                                        " Ignored ACK sid={} from={} node={} (source_ok={} node_ok={} dynamic_route_ok={} ip_ok={})",
                                        session_id,
                                        from,
                                        node_id,
                                        source_ok,
                                        node_ok,
                                        dynamic_route_ok,
                                        ip_ok
                                    ))
                                );
                            }
                        }
                    }
                }
            }
            if let Some(listener_id) = listener_id {
                let _ = cmd_tx
                    .send(EngineCmd::ParaRemoveListener { listener_id })
                    .await;
            }
        }));
        crate::cli_println!(
            "{}",
            term_style::fmt_para_line(format_args!(" Passive listener armed (owner mode)."))
        );
        Ok(())
    }

    fn stop_parasitic_passive_listener(&mut self) {
        if let Some(stop) = self.parasitic_listener_stop.take() {
            stop.store(true, Ordering::Release);
        }
        if let Some(task) = self.parasitic_listener_task.take() {
            task.abort();
        }
    }

    #[cfg(windows)]
    async fn wintun_create_with_timeout(
        &self,
        vip_ip: std::net::Ipv4Addr,
        prefix: u8,
        ring: u32,
        ipv4_metric: u32,
        mtu_to_apply: i32,
    ) -> Result<Arc<WintunAdapter>> {
        let create_fut = tokio::task::spawn_blocking(move || -> Result<Arc<WintunAdapter>> {
            let adapter = Arc::new(
                WintunAdapter::create(
                    crate::tun::wintun::WINTUN_ADAPTER_NAME,
                    vip_ip,
                    prefix,
                    ring,
                    ipv4_metric,
                )
                .map_err(|e| anyhow!("failed to create Wintun adapter: {e}"))?,
            );
            if (576..=1500).contains(&mtu_to_apply) {
                let _ = adapter.set_mtu(mtu_to_apply as u16);
            }
            Ok(adapter)
        });
        match tokio::time::timeout(Duration::from_secs(WINTUN_CREATE_TIMEOUT_SECS), create_fut)
            .await
        {
            Ok(Ok(Ok(adapter))) => Ok(adapter),
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(e)) => Err(anyhow!("wintun create task join failed: {e}")),
            Err(_) => Err(anyhow!(
                "Wintun init timed out after {WINTUN_CREATE_TIMEOUT_SECS}s"
            )),
        }
    }

    pub async fn restore_adapter_from_saved_session(&mut self) -> Result<()> {
        #[cfg(windows)]
        {
            if self.vni.is_some() {
                return Ok(());
            }
            let snap = self.config.snapshot();
            if snap.network_id.is_empty() || snap.virtual_ip.is_empty() {
                return Ok(());
            }
            let vip_ip = match snap.virtual_ip.parse::<std::net::Ipv4Addr>() {
                Ok(v) => v,
                Err(e) => {
                    crate::cli_println!(
                        "{}",
                        term_style::fmt_bang_line(format_args!(
                            " Cannot restore Wintun: invalid VIP '{}': {e}",
                            snap.virtual_ip
                        ))
                    );
                    return Ok(());
                }
            };
            let ring = effective_wintun_ring_bytes(snap.wintun_ring_bytes);
            let ipv4_metric =
                effective_wintun_ipv4_interface_metric(snap.wintun_ipv4_interface_metric);
            let mtu_to_apply = snap.adapter_mtu;
            let wintun_prefix = snap.subnet_prefix.clamp(8, 30);

            let adapter = self
                .wintun_create_with_timeout(vip_ip, wintun_prefix, ring, ipv4_metric, mtu_to_apply)
                .await?;
            self.wire_adapter(adapter.clone());
            self.vni = Some(adapter);
            crate::cli_println!(
                "{}",
                term_style::fmt_info_line(format_args!(
                    " Restored Wintun adapter for {}/{}",
                    snap.virtual_ip,
                    snap.subnet_prefix.clamp(8, 30)
                ))
            );
        }
        Ok(())
    }

    #[cfg(windows)]
    fn wire_adapter(&mut self, adapter: Arc<WintunAdapter>) {
        adapter.start_read_loop(self.tun_from_tun_tx.clone());
        let adapter_name = adapter.name().to_string();
        *self.vni_slot.write() = Some(adapter.clone());
        if let Some(rx) = self.tun_inject_rx.take() {
            let slot = self.vni_slot.clone();
            let metrics = self.engine_metrics.clone();
            self.inject_task = Some(tokio::spawn(async move {
                let mut inject_rx = rx;
                let mut last_lag_warn_at: Option<Instant> = None;
                loop {
                    match inject_rx.recv().await {
                        Ok(pkt) => {
                            let current = slot.read().as_ref().cloned();
                            if let Some(vni) = current {
                                let _ = vni.send(&pkt);
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            if let Some(m) = metrics.as_ref() {
                                m.inc_tun_inject_lagged(n as u64);
                            }
                            let now = Instant::now();
                            let should_warn = last_lag_warn_at
                                .map(|t| now.duration_since(t) >= Duration::from_secs(5))
                                .unwrap_or(true);
                            if should_warn {
                                crate::cli_eprintln!(
                                    "  [TUN] inject receiver lagged by {} packets; dropping stale packets",
                                    n
                                );
                                last_lag_warn_at = Some(now);
                            }
                            continue;
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }));
        }
        let _ = self
            .cmd_tx
            .try_send(EngineCmd::SetAdapterName(adapter_name));
        let snap = self.config.snapshot();
        let _ = self.cmd_tx.try_send(EngineCmd::SetMtuPin {
            pin_mtu: snap.pin_mtu,
            adapter_mtu: effective_adapter_mtu(snap.adapter_mtu) as u16,
        });
    }

    /// First-run menu only (headless first open uses `crate::banner::render_banner_to_stdout`).
    async fn print_minteger_banner_slow(&self, line_delay_ms: u64) {
        for line in crate::banner::banner_lines() {
            crate::cli_println_live!("{line}");
            if line_delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(line_delay_ms)).await;
            }
        }
    }

    fn clear_screen_if_enabled(&self) {
        if self.autoclear {
            clear_screen();
        }
    }

    async fn emit_first_run_menu_lines(&mut self) -> Result<()> {
        crate::cli_println!("  [1]  Create a new home");
        crate::cli_println!("  [2]  Join an existing network");
        crate::cli_println!("  [3]  Exit");
        crate::cli_println!("  -----------");
        Ok(())
    }

    /// After reconnect: build home lines (headless: snapshot only; else print to UI).
    async fn emit_session_home_block(
        &mut self,
        outcome: ReconnectOutcome,
        clear_before: bool,
        emit_session_ready: bool,
    ) -> Result<Vec<String>> {
        if self.state != AppState::CommandLoop {
            return Ok(vec![]);
        }
        let snap = self.config.snapshot();
        let lines = bootstrap::session_home_lines(
            outcome,
            &snap.server_name,
            &snap.network_id,
            &snap.virtual_ip,
            &snap.role,
        );
        if self.headless {
            // Client clears + renders via TakeSessionHome once; never enter UI replay ring.
            self.reconnect_home_shown = true;
            return Ok(lines);
        }
        if clear_before {
            crate::cli_emit::emit_clear_screen();
        }
        for line in &lines {
            crate::cli_println!("{line}");
        }
        if emit_session_ready {
            crate::cli_emit::emit_session_ready();
        }
        self.reconnect_home_shown = true;
        Ok(lines)
    }

    async fn emit_post_para_reconnect_home(&mut self, clear_screen_first: bool) -> Result<()> {
        let _ = self
            .emit_session_home_block(ReconnectOutcome::Connected, clear_screen_first, false)
            .await?;
        Ok(())
    }

    async fn emit_command_loop_home(&mut self) -> Result<()> {
        if self.state != AppState::CommandLoop {
            return Ok(());
        }
        // Do not clear: hole-punch / reconnect logs must stay visible above the home block.
        crate::cli_println!();
        crate::cli_println!("  ────────────────────────────────────────────────────────");
        let snap = self.config.snapshot();
        let lines = bootstrap::session_home_lines(
            ReconnectOutcome::Skipped,
            &snap.server_name,
            &snap.network_id,
            &snap.virtual_ip,
            &snap.role,
        );
        for line in lines.iter().filter(|l| !l.is_empty()) {
            crate::cli_println!("{line}");
        }
        Ok(())
    }

    async fn handle_first_run_line(&mut self, line: String) -> Result<()> {
        match line.as_str() {
            "1" => crate::cli_println!(
                "{}",
                term_style::fmt_bang_line(format_args!(" Create from the CLI client menu [1]."))
            ),
            "2" => {
                if let Err(e) = self.handle_join_entry().await {
                    crate::cli_println!("{}", term_style::fmt_bang_line(format_args!(" {e}")));
                }
            }
            "3" => {
                self.handle_exit().await;
                self.state = AppState::Exiting;
            }
            _ => crate::cli_println!(
                "{}",
                term_style::fmt_bang_line(format_args!(" Invalid choice. Enter 1, 2, or 3."))
            ),
        }
        Ok(())
    }

    async fn show_first_run_menu(&mut self) -> Result<()> {
        self.print_minteger_banner_slow(BANNER_DELAY_FIRST_RUN_MS)
            .await;
        crate::cli_println!("  [1]  Create a new home");
        crate::cli_println!("  [2]  Join an existing network");
        crate::cli_println!("  [3]  Exit");
        crate::cli_println!("  -----------");
        crate::cli_print!("> Select [1-3]: ");
        io::stdout().flush()?;
        match self.read_line().await?.as_str() {
            "1" => crate::cli_println!(
                "{}",
                term_style::fmt_bang_line(format_args!(" Create from the CLI client menu [1]."))
            ),
            "2" => {
                if let Err(e) = self.handle_join_entry().await {
                    crate::cli_println!("{}", term_style::fmt_bang_line(format_args!(" {e}")));
                }
            }
            "3" => {
                self.handle_exit().await;
                self.state = AppState::Exiting;
            }
            _ => crate::cli_println!(
                "{}",
                term_style::fmt_bang_line(format_args!(" Invalid choice. Enter 1, 2, or 3."))
            ),
        }
        Ok(())
    }

    pub async fn process_command(&mut self, line: String) -> Result<()> {
        let line = normalize_command(line);
        if line.is_empty() {
            if self.state == AppState::FirstRun {
                return self.emit_first_run_menu_lines().await;
            }
            if self.state == AppState::CommandLoop {
                return self.emit_command_loop_home().await;
            }
            return Ok(());
        }
        if self.state == AppState::FirstRun {
            return self.handle_first_run_line(line).await;
        }
        let mut parts = line.split_whitespace();
        let cmd = parts.next().unwrap_or_default();
        let skip_pre_clear = command_skips_autoclear(cmd);
        if !skip_pre_clear {
            self.clear_screen_if_enabled();
        }
        let cmd_result: Result<()> = match cmd {
            "help" | "?" => {
                self.print_help();
                Ok(())
            }
            "list" => {
                self.handle_list();
                Ok(())
            }
            "runtime" => self.handle_runtime_live().await,
            "ping" => self.handle_ping().await,
            "kick" => self.handle_kick(parts.next()).await,
            "stun" => self.handle_stun().await,
            "punch" => {
                let args: Vec<&str> = parts.collect();
                if args.len() > 2 {
                    crate::cli_println!(
                        "  Usage: mint punch <public_ip>:<public_port> (or mint punch <public_ip> <public_port>)"
                    );
                    Ok(())
                } else {
                    self.handle_punch(args.first().copied(), args.get(1).copied())
                        .await
                }
            }
            "config" => {
                let args: Vec<&str> = parts.collect();
                self.handle_config(&args).await
            }
            "autoclear-on" => {
                self.autoclear = true;
                crate::cli_println!(
                    "{}",
                    term_style::fmt_info_line(format_args!(" Screen autoclear: on"))
                );
                Ok(())
            }
            "autoclear-off" => {
                self.autoclear = false;
                crate::cli_println!(
                    "{}",
                    term_style::fmt_info_line(format_args!(" Screen autoclear: off"))
                );
                Ok(())
            }
            "remove" => self.handle_remove().await,
            "stop" => {
                self.handle_exit().await;
                Ok(())
            }
            _ => {
                crate::cli_println!("  Unknown command '{cmd}'. Type '?'.");
                Ok(())
            }
        };
        if let Err(e) = cmd_result {
            crate::cli_println!("{}", term_style::fmt_bang_line(format_args!(" {e}")));
        }
        Ok(())
    }

    pub async fn create_network_with_params(
        &mut self,
        name: String,
        port: u16,
        vip: String,
        subnet_prefix: u8,
    ) -> Result<()> {
        self.stop_parasitic_passive_listener();
        let vip = if vip.trim().is_empty() {
            random_owner_vip()
        } else {
            vip
        };
        crate::cli_println!(
            "{}",
            term_style::fmt_nat_line(format_args!(" Attempting UPnP port mapping..."))
        );
        let local_ip = get_local_ip();
        let local_ip_parsed: std::net::Ipv4Addr = local_ip
            .parse()
            .unwrap_or(std::net::Ipv4Addr::new(127, 0, 0, 1));
        self.upnp_cleanup_if_any().await;
        let upnp_result = tokio::time::timeout(
            std::time::Duration::from_secs(4),
            upnp::discover_and_add_port(&local_ip, port, "MintP2P"),
        )
        .await
        .ok()
        .flatten();
        match &upnp_result {
            Some(m) => crate::cli_println!(
                "{}",
                term_style::fmt_nat_line(format_args!(
                    " UPnP: port {port} mapped (ext IP: {})",
                    m.external_ip
                ))
            ),
            None => crate::cli_println!(
                "{}",
                term_style::fmt_nat_line(format_args!(
                    " UPnP failed or router unsupported. Manual port forward may be needed."
                ))
            ),
        }
        if let Some(ref m) = upnp_result {
            self.upnp_set_mapping(m.clone());
        }
        crate::cli_println!(
            "{}",
            term_style::fmt_nat_line(format_args!(" Querying STUN for public endpoint..."))
        );
        let stun_ep = self
            .query_public_endpoint_from_engine(std::time::Duration::from_secs(5))
            .await;
        if let Some(ref ep) = stun_ep {
            crate::cli_println!(
                "{}",
                term_style::fmt_nat_line(format_args!(
                    " STUN: public endpoint {}:{}",
                    ep.ip, ep.port
                ))
            );
        } else {
            crate::cli_println!(
                "{}",
                term_style::fmt_nat_line(format_args!(
                    " STUN: no response (may be behind strict NAT)"
                ))
            );
        }

        if let Some(ref ep) = stun_ep {
            let ip_mismatch = upnp_result
                .as_ref()
                .is_some_and(|m| !m.external_ip.is_empty() && m.external_ip != ep.ip);
            let upnp_port_ignored = upnp_result.as_ref().is_some_and(|m| ep.port != m.ext_port);
            if ip_mismatch || upnp_port_ignored {
                crate::cli_println!(
                    "{}",
                    term_style::fmt_bang_line(format_args!(
                        " Owner appears behind double-NAT/CGNAT (UPnP vs STUN mismatch). \
                         Decentralized join for new peers may be unstable until inbound UDP is reachable. \
                         Prefer port-forward on the router, a host with a public IP, or relay when available."
                    ))
                );
            }
        }

        let key = MintCrypto::generate_key();
        let network_id = derive_network_id(&key);
        let node_id = hex::encode(rand::random::<[u8; 16]>());

        let candidates =
            ice::gather_candidates(&local_ip, port, stun_ep.as_ref(), upnp_result.as_ref());
        let _ = self.cmd_tx.send(EngineCmd::SetCandidates(candidates)).await;

        let invite_ip: [u8; 4] = if let Some(ref ep) = stun_ep {
            ep.ip
                .parse::<std::net::Ipv4Addr>()
                .map(|a| a.octets())
                .unwrap_or(local_ip_parsed.octets())
        } else {
            local_ip_parsed.octets()
        };
        let invite_port = stun_ep.as_ref().map(|ep| ep.port).unwrap_or(port);
        let public_invite = encode_invite(&InvitePayload {
            mode: 1,
            owner_ip: invite_ip,
            owner_port: invite_port,
            key: key.0,
            protocol: PROTO_UDP,
        });

        ensure_netinfo_dir()?;
        self.config.set_network_basics(
            if name.is_empty() {
                "Mint".to_string()
            } else {
                name.clone()
            },
            network_id.clone(),
            "owner".to_string(),
            vip.clone(),
            node_id,
            port,
        );
        self.config.update(|cfg| {
            cfg.crypto_key = hex::encode(key.0);
            cfg.owner_port = port;
            cfg.owner_real_ip = local_ip.clone();
            cfg.public_invite_code = public_invite.clone();
            cfg.parasitic_enabled = false;
            cfg.parasitic_peer_vip.clear();
            cfg.parasitic_self_vip.clear();
            cfg.parasitic_peer_port = 0;
            cfg.parasitic_peer_node_id.clear();
            cfg.parasitic_self_is_owner = false;
            cfg.parasitic_use_public = true;
            cfg.subnet_prefix = subnet_prefix;
            cfg.decentralized_enabled = true;
            cfg.join_method = "decentralized".to_string();
        });
        self.refresh_owner_vip_pool_from_config(true);

        #[cfg(windows)]
        {
            let vip_ip = vip
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| anyhow!("invalid owner vip: {vip}"))?;
            let snap = self.config.snapshot();
            let ring = effective_wintun_ring_bytes(snap.wintun_ring_bytes);
            let ipv4_metric =
                effective_wintun_ipv4_interface_metric(snap.wintun_ipv4_interface_metric);
            let wintun_prefix = subnet_prefix.clamp(8, 30);
            let adapter = tokio::task::spawn_blocking(move || -> Result<Arc<WintunAdapter>> {
                Ok(Arc::new(
                    WintunAdapter::create(
                        crate::tun::wintun::WINTUN_ADAPTER_NAME,
                        vip_ip,
                        wintun_prefix,
                        ring,
                        ipv4_metric,
                    )
                    .map_err(|e| anyhow!("failed to create Wintun adapter: {e}"))?,
                ))
            })
            .await
            .map_err(|e| anyhow!("wintun create task join failed: {e}"))??;
            self.wire_adapter(adapter.clone());
            self.vni = Some(adapter);
            crate::cli_println!(
                "{}",
                term_style::fmt_info_line(format_args!(
                    " Wintun adapter created for {vip}/{}",
                    subnet_prefix.clamp(8, 30)
                ))
            );
        }

        let _ = self
            .cmd_tx
            .send(EngineCmd::SetCryptoKey(Key(key.0), None))
            .await;
        let _ = self
            .cmd_tx
            .send(EngineCmd::SetIdentity {
                is_owner: true,
                my_vip: vip.clone(),
                my_node_id: self.config.snapshot().node_id.clone(),
                subnet_prefix: self.config.snapshot().subnet_prefix.clamp(8, 30),
                reply: None,
            })
            .await;
        let node_id = self.config.snapshot().node_id.clone();
        let _ = self
            .start_decentralized_engine(None, false, None, None, &node_id)
            .await;
        self.state = AppState::CommandLoop;
        self.ensure_parasitic_passive_listener().await?;

        let display_name = if name.is_empty() { "Mint" } else { &name };
        crate::cli_println!();
        crate::cli_println!("  [■■■■■■■■]");
        crate::cli_println!("  │  Network : {:<46}", display_name);
        crate::cli_println!("  │  Net ID  : {:<46}", network_id);
        crate::cli_println!(
            "  │  VIP     : {:<46}",
            format!("{vip}/{}  (owner)", self.config.snapshot().subnet_prefix)
        );
        crate::cli_println!("  │> Invite  : {public_invite}");
        crate::cli_println!();
        Ok(())
    }

    async fn handle_join_entry(&mut self) -> Result<()> {
        crate::cli_println!("  Join mode:");
        crate::cli_println!("    [1] Decentralized (default)");
        crate::cli_println!("    [2] Parasitic");
        crate::cli_println!("    [3] Manual");
        crate::cli_print!("  Choose [1/2/3, default 1]: ");
        io::stdout().flush()?;
        let mode = self.read_line().await?;
        let t = mode.trim();
        if t == "2" {
            return self.handle_join_parasitic().await;
        }
        if t == "3" {
            crate::cli_print!("  Invite code: ");
            io::stdout().flush()?;
            let invite = self.read_line().await?;
            if invite.is_empty() {
                return Err(anyhow!("invite code is required"));
            }
            return self
                .handle_join(&invite, self.resolve_join_invite_opts().await?)
                .await;
        }
        crate::cli_print!("  Invite code: ");
        io::stdout().flush()?;
        let invite = self.read_line().await?;
        if invite.is_empty() {
            return Err(anyhow!("invite code is required"));
        }
        self.handle_join_decentralized(&invite).await
    }

    async fn resolve_join_invite_opts(&self) -> Result<JoinInviteRunOpts> {
        if self.headless {
            return Ok(JoinInviteRunOpts::daemon_default());
        }
        crate::cli_println!();
        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(" Connection mode:"))
        );
        crate::cli_println!("    [1] Public (STUN + punch, default)");
        crate::cli_println!("    [2] LAN");
        crate::cli_print!("  Choose [1/2, default 1]: ");
        io::stdout().flush()?;
        let mode_line = self.read_line().await?;
        let use_public = !(mode_line.trim() == "2");
        Ok(JoinInviteRunOpts {
            use_public,
            skip_share_gate: false,
        })
    }

    async fn start_decentralized_engine(
        &self,
        network_key: Option<[u8; 32]>,
        is_joiner: bool,
        join_body: Option<Vec<u8>>,
        join_owner_hint: Option<std::net::SocketAddr>,
        node_id: &str,
    ) -> Result<()> {
        let key_raw = match network_key {
            Some(k) => k,
            None => {
                let snap = self.config.snapshot();
                if snap.crypto_key.trim().is_empty() {
                    return Err(anyhow!(
                        "decentralized discovery requires network crypto key"
                    ));
                }
                parse_key_hex_32(snap.crypto_key.trim())?
            }
        };
        let snap = self.config.snapshot();
        let room = room_id_20b(&Key(key_raw), PROTO_UDP);
        let trackers = effective_decentralized_trackers(&snap);
        let announce_secs = snap.decentralized_announce_secs.max(60);
        self.cmd_tx
            .send(EngineCmd::StartDecentralized {
                room_id: room,
                trackers,
                announce_secs,
                is_joiner,
                join_body,
                join_owner_hint,
                node_id: node_id.to_string(),
            })
            .await?;
        Ok(())
    }

    async fn try_take_pending_join_ack(&self) -> Option<JoinAck> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .send(EngineCmd::TakePendingJoinAck { reply: reply_tx })
            .await;
        match tokio::time::timeout(Duration::from_secs(2), reply_rx).await {
            Ok(Ok(Some(ack))) => Some(ack),
            _ => None,
        }
    }

    async fn wait_pending_join_ack(&self, grace: Duration) -> Option<JoinAck> {
        let step = Duration::from_millis(250);
        let mut remaining = grace;
        while remaining > Duration::ZERO {
            if let Some(ack) = self.try_take_pending_join_ack().await {
                return Some(ack);
            }
            let sleep_for = remaining.min(step);
            tokio::time::sleep(sleep_for).await;
            remaining = remaining.saturating_sub(sleep_for);
        }
        self.try_take_pending_join_ack().await
    }

    async fn finalize_peer_join_from_ack(
        &mut self,
        ack: JoinAck,
        parsed: &InvitePayload,
        local_node_id: String,
        port: u16,
        owner_hint: SocketAddr,
    ) -> Result<()> {
        let vip = ack.vip;
        let owner_subnet = ack.subnet_prefix.clamp(8, 30);
        let owner_udp = ack.owner_endpoint;

        ensure_netinfo_dir()?;
        self.config.set_network_basics(
            "Mint".to_string(),
            derive_network_id(&Key(parsed.key)),
            "peer".to_string(),
            vip.clone(),
            local_node_id.clone(),
            port,
        );
        self.config.update(|cfg| {
            cfg.owner_real_ip = owner_udp.ip().to_string();
            cfg.owner_port = owner_udp.port();
            cfg.crypto_key = hex::encode(parsed.key);
            cfg.parasitic_enabled = false;
            cfg.decentralized_enabled = true;
            cfg.join_method = "decentralized".to_string();
            cfg.subnet_prefix = owner_subnet;
        });

        #[cfg(windows)]
        {
            let vip_ip = vip
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| anyhow!("invalid assigned vip: {vip}"))?;
            let snap = self.config.snapshot();
            let ring = effective_wintun_ring_bytes(snap.wintun_ring_bytes);
            let ipv4_metric =
                effective_wintun_ipv4_interface_metric(snap.wintun_ipv4_interface_metric);
            let wintun_prefix = owner_subnet;
            let adapter = tokio::task::spawn_blocking(move || -> Result<Arc<WintunAdapter>> {
                Ok(Arc::new(
                    WintunAdapter::create(
                        crate::tun::wintun::WINTUN_ADAPTER_NAME,
                        vip_ip,
                        wintun_prefix,
                        ring,
                        ipv4_metric,
                    )
                    .map_err(|e| anyhow!("failed to create Wintun adapter: {e}"))?,
                ))
            })
            .await
            .map_err(|e| anyhow!("wintun create task join failed: {e}"))??;
            self.wire_adapter(adapter.clone());
            self.vni = Some(adapter);
        }

        let _ = self
            .cmd_tx
            .send(EngineCmd::SetIdentity {
                is_owner: false,
                my_vip: vip.clone(),
                my_node_id: local_node_id,
                subnet_prefix: owner_subnet,
                reply: None,
            })
            .await;

        let _ = self
            .start_decentralized_engine(
                None,
                false,
                None,
                Some(owner_hint),
                &self.config.snapshot().node_id,
            )
            .await;

        self.state = AppState::CommandLoop;
        self.ensure_parasitic_passive_listener().await?;
        crate::cli_println!("  ✓ Joined network (Decentralized)!");
        crate::cli_println!("    │  Virtual IP  : {}", vip);
        crate::cli_println!("    │  Owner       : {}", owner_udp);
        Ok(())
    }

    async fn handle_join_decentralized(&mut self, invite: &str) -> Result<()> {
        self.stop_parasitic_passive_listener();
        let parsed = decode_invite(invite)?;
        let owner_hint = std::net::SocketAddr::from((parsed.owner_ip, parsed.owner_port));
        let local_ip = get_local_ip();
        let port = self.config.get_listen_port().max(7878);
        let local_node_id = {
            let existing = self.config.snapshot().node_id.clone();
            if existing.is_empty() {
                hex::encode(rand::random::<[u8; 16]>())
            } else {
                existing
            }
        };
        let _room = room_id_20b(&Key(parsed.key), parsed.protocol);
        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(
                " Network ID hash: {}",
                derive_network_id(&Key(parsed.key))
            ))
        );
        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(
                " Decentralized room_id: {}",
                room_id_hex(&Key(parsed.key), parsed.protocol)
            ))
        );
        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(" Owner hint (invite): {}", owner_hint))
        );

        self.upnp_cleanup_if_any().await;
        let upnp_result = tokio::time::timeout(
            std::time::Duration::from_secs(4),
            upnp::discover_and_add_port(&local_ip, port, "MintegerP2P-Decentralized"),
        )
        .await
        .ok()
        .flatten();
        if let Some(ref m) = upnp_result {
            self.upnp_set_mapping(m.clone());
        }

        let stun_ep = self
            .query_public_endpoint_from_engine(std::time::Duration::from_secs(3))
            .await;
        let candidates =
            ice::gather_candidates(&local_ip, port, stun_ep.as_ref(), upnp_result.as_ref());
        let _ = self
            .cmd_tx
            .send(EngineCmd::SetCandidates(candidates.clone()))
            .await;

        let body = serde_json::json!({
            "proto_ver": WIRE_PROTOCOL_VERSION,
            "node_id": local_node_id.clone(),
            "ts_ms": now_epoch_ms(),
            "rtt_hint_ms": 100,
            "nat_hint": "unknown",
            "candidates": candidates,
        })
        .to_string()
        .into_bytes();

        let _ = self
            .cmd_tx
            .send(EngineCmd::SetCryptoKey(Key(parsed.key), None))
            .await;

        self.start_decentralized_engine(
            Some(parsed.key),
            true,
            Some(body.clone()),
            Some(owner_hint),
            &local_node_id,
        )
        .await?;

        let deadline_secs = self
            .config
            .snapshot()
            .decentralized_join_deadline_secs
            .max(30);
        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(
                " Waiting for owner (MPJA) via tracker discovery (up to {deadline_secs}s)..."
            ))
        );

        let (tx, rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .send(EngineCmd::PrepareJoin {
                join_tx: tx,
                key: Key(parsed.key),
                owner: owner_hint,
                body: body.clone(),
            })
            .await;

        let ack = match tokio::time::timeout(Duration::from_secs(deadline_secs), rx).await {
            Ok(Ok(Some(ack))) => ack,
            Ok(Ok(None)) => {
                let _ = self.cmd_tx.send(EngineCmd::CancelJoinWait).await;
                return Err(anyhow!("join rejected by owner"));
            }
            Ok(Err(_)) => {
                if let Some(ack) = self.wait_pending_join_ack(Duration::from_secs(3)).await {
                    ack
                } else {
                    let _ = self.cmd_tx.send(EngineCmd::CancelJoinWait).await;
                    crate::cli_println!(
                        "{}",
                        term_style::fmt_bang_line(format_args!(
                            " Owner offline or unreachable. No profile saved; retry from the menu ([2] Join) when owner is online."
                        ))
                    );
                    return Err(anyhow!("join timeout waiting owner response"));
                }
            }
            Err(_) => {
                if let Some(ack) = self.wait_pending_join_ack(Duration::from_secs(3)).await {
                    ack
                } else {
                    let _ = self.cmd_tx.send(EngineCmd::CancelJoinWait).await;
                    crate::cli_println!(
                        "{}",
                        term_style::fmt_bang_line(format_args!(
                            " Owner offline or unreachable. No profile saved; retry from the menu ([2] Join) when owner is online."
                        ))
                    );
                    return Err(anyhow!("join timeout waiting owner response"));
                }
            }
        };

        self.finalize_peer_join_from_ack(ack, &parsed, local_node_id, port, owner_hint)
            .await
    }

    pub async fn join_decentralized_code(&mut self, invite: String) -> Result<()> {
        self.handle_join_decentralized(&invite).await
    }

    async fn handle_join(&mut self, invite: &str, opts: JoinInviteRunOpts) -> Result<()> {
        self.stop_parasitic_passive_listener();
        let parsed = decode_invite(invite)?;
        let owner = std::net::SocketAddr::from((parsed.owner_ip, parsed.owner_port));

        let local_ip = get_local_ip();
        let port = self.config.get_listen_port().max(7878);
        let local_node_id = {
            let existing = self.config.snapshot().node_id.clone();
            if existing.is_empty() {
                hex::encode(rand::random::<[u8; 16]>())
            } else {
                existing
            }
        };

        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(
                " Network ID hash: {}",
                crate::crypto::derive_network_id(&Key(parsed.key))
            ))
        );
        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(" Target owner: {}", owner))
        );
        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(" Local node_id: {}", local_node_id))
        );

        let use_public = opts.use_public;
        if use_public {
            crate::cli_println!(
                "{}",
                term_style::fmt_join_line(format_args!(" Connection: Public (STUN + punch)"))
            );
        } else {
            crate::cli_println!(
                "{}",
                term_style::fmt_join_line(format_args!(" Connection: LAN"))
            );
        }

        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(" Step 1/6: Initializing UDP engine..."))
        );
        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(" UDP engine ready on local port {}.", port))
        );

        let mut upnp_result: Option<upnp::UPnPMapping> = None;
        if use_public {
            self.upnp_cleanup_if_any().await;
            crate::cli_print!(
                "{}",
                term_style::fmt_join_line(format_args!(
                    " Step 1b/6: Trying UPnP port mapping on UDP {port}..."
                ))
            );
            io::stdout().flush()?;
            upnp_result = tokio::time::timeout(
                std::time::Duration::from_secs(4),
                upnp::discover_and_add_port(&local_ip, port, "MintegerP2P-Join"),
            )
            .await
            .ok()
            .flatten();
            match &upnp_result {
                Some(m) => crate::cli_println!(
                    " ✓ UPnP mapping active (ext_port={}, ext_ip={}).",
                    m.ext_port,
                    m.external_ip
                ),
                None => crate::cli_println!(
                    " failed (router unsupported/disabled). Continuing without UPnP."
                ),
            }
        }
        if let Some(ref m) = upnp_result {
            self.upnp_set_mapping(m.clone());
        }

        let stun_ep = if use_public {
            crate::cli_print!(
                "{}",
                term_style::fmt_join_line(format_args!(
                    " Step 2/6: Gathering ICE candidates via STUN..."
                ))
            );
            io::stdout().flush()?;
            self.query_public_endpoint_from_engine(std::time::Duration::from_secs(3))
                .await
        } else {
            crate::cli_println!(
                "{}",
                term_style::fmt_join_line(format_args!(
                    " Step 2/6: LAN mode — using host candidate only..."
                ))
            );
            None
        };
        let candidates =
            ice::gather_candidates(&local_ip, port, stun_ep.as_ref(), upnp_result.as_ref());
        let _ = self
            .cmd_tx
            .send(EngineCmd::SetCandidates(candidates.clone()))
            .await;
        if use_public {
            if let Some(ref ep) = stun_ep {
                crate::cli_println!(
                    " {} candidate(s) ready (srflx {}:{}).",
                    candidates.len(),
                    ep.ip,
                    ep.port
                );
                if let Some(ref m) = upnp_result {
                    if ep.port != m.ext_port {
                        crate::cli_println!(
                            "{}",
                            term_style::fmt_join_line(format_args!(
                                " [warn] Router/NAT is using public port {} (requested {}).",
                                ep.port, m.ext_port
                            ))
                        );
                        crate::cli_println!(
                            "{}",
                            term_style::fmt_join_line(format_args!(
                                " [warn] Share STUN endpoint with owner."
                            ))
                        );
                    }
                }
                crate::cli_println!(
                    "{}",
                    term_style::fmt_join_line(format_args!(
                        " Your public endpoint: {}:{}",
                        ep.ip, ep.port
                    ))
                );
                if opts.skip_share_gate {
                    crate::cli_println!(
                        "{}",
                        term_style::fmt_join_line(format_args!(
                            " Share this endpoint with the owner on the CLI client, then punching starts automatically."
                        ))
                    );
                } else {
                    crate::cli_println!("{}", term_style::fmt_join_line(format_args!(" Share this with owner, then press Enter to start manual retry punching...")));
                }
            } else {
                crate::cli_println!(" {} candidate(s) ready (no srflx).", candidates.len());
                if opts.skip_share_gate {
                    crate::cli_println!(
                        "{}",
                        term_style::fmt_join_line(format_args!(
                            " STUN did not return a public endpoint; continuing with manual retry punching."
                        ))
                    );
                } else {
                    crate::cli_println!("{}", term_style::fmt_join_line(format_args!(" STUN did not return a public endpoint. Press Enter to continue with manual retry punching anyway...")));
                }
            }
            if !opts.skip_share_gate {
                let _ = self.read_line().await?;
            }
        }

        if use_public {
            crate::cli_println!(
                "{}",
                term_style::fmt_join_line(format_args!(
                    " Step 3/6: Starting tiered hole punch toward owner..."
                ))
            );
        } else {
            crate::cli_println!(
                "{}",
                term_style::fmt_join_line(format_args!(
                    " Step 3/6: LAN mode — tiered hole punch toward owner."
                ))
            );
        }

        let body = serde_json::json!({
            "proto_ver": WIRE_PROTOCOL_VERSION,
            "node_id": local_node_id.clone(),
            "ts_ms": now_epoch_ms(),
            "rtt_hint_ms": 100,
            "nat_hint": "unknown",
            "candidates": candidates,
        })
        .to_string()
        .into_bytes();

        let _ = self
            .cmd_tx
            .send(EngineCmd::StartPunchWorkflow {
                key: JOIN_HANDSHAKE_PUNCH_KEY.to_string(),
                bases: vec![owner],
                log_stages: true,
            })
            .await;

        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(
                " Step 4/6: Waiting for owner acknowledgment (MPJA)..."
            ))
        );
        let mut assigned_vip: Option<String> = None;
        let mut join_subnet_prefix: Option<u8> = None;
        let mut owner_observed: Option<std::net::SocketAddr> = None;
        let max_attempts = 5u32;
        for attempt in 1..=max_attempts {
            crate::cli_println!(
                "{}",
                term_style::fmt_join_line(format_args!(
                    " Attempt {attempt}/{max_attempts}: requesting MPJA..."
                ))
            );
            let (tx, rx) = oneshot::channel();
            let _ = self
                .cmd_tx
                .send(EngineCmd::PrepareJoin {
                    join_tx: tx,
                    key: Key(parsed.key),
                    owner,
                    body: body.clone(),
                })
                .await;

            match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
                Ok(Ok(Some(ack))) => {
                    crate::cli_println!("  ✓ Owner assigned virtual IP: {}", ack.vip);
                    join_subnet_prefix = Some(ack.subnet_prefix);
                    owner_observed = Some(ack.owner_endpoint);
                    assigned_vip = Some(ack.vip);
                    break;
                }
                Ok(Ok(None)) => {
                    let _ = self
                        .cmd_tx
                        .send(EngineCmd::StopPunchWorkflow {
                            key: JOIN_HANDSHAKE_PUNCH_KEY.to_string(),
                        })
                        .await;
                    return Err(anyhow!("join rejected by owner"));
                }
                Ok(Err(_)) => {}
                Err(_) => {}
            }
            let backoff_ms = 300u64.saturating_mul(1u64 << (attempt - 1));
            tokio::time::sleep(std::time::Duration::from_millis(backoff_ms.min(3000))).await;
        }
        let _ = self
            .cmd_tx
            .send(EngineCmd::StopPunchWorkflow {
                key: JOIN_HANDSHAKE_PUNCH_KEY.to_string(),
            })
            .await;

        let vip = match assigned_vip {
            Some(v) => v,
            None => {
                crate::cli_println!(
                    "{}",
                    term_style::fmt_bang_line(format_args!(
                        " Owner did not respond within the join retry window (~{} seconds max).",
                        20
                    ))
                );
                return Err(anyhow!("join timeout waiting owner response"));
            }
        };
        let owner_udp = owner_observed.unwrap_or(owner);

        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(
                " Step 5/6: Config saved, initializing virtual interface..."
            ))
        );
        ensure_netinfo_dir()?;
        self.config.set_network_basics(
            "Mint".to_string(),
            derive_network_id(&Key(parsed.key)),
            "peer".to_string(),
            vip.clone(),
            local_node_id,
            port,
        );
        let owner_subnet = join_subnet_prefix.unwrap_or(24).clamp(8, 30);
        self.config.update(|cfg| {
            cfg.owner_real_ip = owner_udp.ip().to_string();
            cfg.owner_port = owner_udp.port();
            cfg.crypto_key = hex::encode(parsed.key);
            cfg.parasitic_enabled = false;
            cfg.parasitic_peer_vip.clear();
            cfg.parasitic_self_vip.clear();
            cfg.parasitic_peer_port = 0;
            cfg.parasitic_peer_node_id.clear();
            cfg.parasitic_self_is_owner = false;
            cfg.subnet_prefix = owner_subnet;
        });

        #[cfg(windows)]
        {
            let vip_ip = vip
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| anyhow!("invalid assigned vip: {vip}"))?;
            let snap = self.config.snapshot();
            let ring = effective_wintun_ring_bytes(snap.wintun_ring_bytes);
            let ipv4_metric =
                effective_wintun_ipv4_interface_metric(snap.wintun_ipv4_interface_metric);
            let wintun_prefix = owner_subnet;
            let adapter = tokio::task::spawn_blocking(move || -> Result<Arc<WintunAdapter>> {
                Ok(Arc::new(
                    WintunAdapter::create(
                        crate::tun::wintun::WINTUN_ADAPTER_NAME,
                        vip_ip,
                        wintun_prefix,
                        ring,
                        ipv4_metric,
                    )
                    .map_err(|e| anyhow!("failed to create Wintun adapter: {e}"))?,
                ))
            })
            .await
            .map_err(|e| anyhow!("wintun create task join failed: {e}"))??;
            self.wire_adapter(adapter.clone());
            self.vni = Some(adapter);
            crate::cli_println!(
                "{}",
                term_style::fmt_info_line(format_args!(
                    " Wintun adapter ready for {vip}/{owner_subnet}"
                ))
            );
        }

        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(" Step 6/6: Starting data plane..."))
        );
        let _ = self
            .cmd_tx
            .send(EngineCmd::SetIdentity {
                is_owner: false,
                my_vip: vip.clone(),
                my_node_id: self.config.snapshot().node_id.clone(),
                subnet_prefix: self.config.snapshot().subnet_prefix.clamp(8, 30),
                reply: None,
            })
            .await;

        self.state = AppState::CommandLoop;
        self.ensure_parasitic_passive_listener().await?;
        crate::cli_println!();
        crate::cli_println!("  ✓ Joined network!");
        crate::cli_println!(
            "[■■■]================------------------------===========------------===------>>"
        );
        crate::cli_println!("    │  Network ID  : {}", self.config.snapshot().network_id);
        crate::cli_println!("    │  Virtual IP  : {}", vip);
        crate::cli_println!("    │  Node ID     : {}", self.config.snapshot().node_id);
        crate::cli_println!("    │  Role        : Peer");
        crate::cli_println!("    │  Owner       : {}", owner_udp);
        crate::cli_println!(
            "[■■■■■]================----------====----====----====----====----====-->>"
        );
        Ok(())
    }

    pub async fn join_invite_code(&mut self, invite: String, lan_mode: Option<bool>) -> Result<()> {
        let opts = JoinInviteRunOpts::from_ipc(lan_mode);
        self.handle_join(&invite, opts).await
    }

    async fn handle_join_parasitic(&mut self) -> Result<()> {
        self.stop_parasitic_passive_listener();
        let snap = self.config.snapshot();
        if !snap.network_id.is_empty() && !snap.parasitic_enabled {
            return Err(anyhow!(
                "active network exists. run 'remove' first, then choose [2] Join from the menu."
            ));
        }
        let listen_port = self.config.get_listen_port().max(7878);
        drop(snap);

        if self.headless {
            return Err(anyhow!(
                "interactive parasitic join must use the CLI client wizard (Public VIP or LAN discover)"
            ));
        }

        crate::cli_println!("  Parasitic mode:");
        crate::cli_println!("    [1] Public (VIP signaling, default)");
        crate::cli_println!("    [2] LAN (UDP broadcast discover)");
        crate::cli_print!("  Choose [1/2, default 1]: ");
        io::stdout().flush()?;
        let mode = self.read_line().await?;
        if mode.trim() == "2" {
            let owners = self.discover_parasitic_lan().await?;
            let target = select_parasitic_lan_target_interactive(self, &owners).await?;
            return self.join_parasitic_lan_with_target(target).await;
        }

        crate::cli_println!(
            "{}",
            term_style::fmt_para_line(format_args!(
                " Use any pre-existing VPN/route as a signaling pipe."
            ))
        );
        crate::cli_println!(
            "{}",
            term_style::fmt_para_line(format_args!(
                " Both sides must reach each other on UDP at the VIP/port below."
            ))
        );
        crate::cli_print!("  Peer VIP (ip or ip:port): ");
        io::stdout().flush()?;
        let peer_vip_input = self.read_line().await?;
        crate::cli_print!("  Your VIP (ip or ip:port): ");
        io::stdout().flush()?;
        let self_vip_input = self.read_line().await?;
        crate::cli_print!("  UPnP port (default {listen_port}): ");
        io::stdout().flush()?;
        let upnp_port = self.read_line().await?.parse::<u16>().ok();
        self.join_parasitic_with_params(peer_vip_input, self_vip_input, upnp_port)
            .await
    }

    pub async fn join_parasitic_with_params(
        &mut self,
        peer_vip_input: String,
        self_vip_input: String,
        upnp_port: Option<u16>,
    ) -> Result<()> {
        self.stop_parasitic_passive_listener();
        let snap = self.config.snapshot();
        if !snap.network_id.is_empty() && !snap.parasitic_enabled {
            return Err(anyhow!(
                "active network exists. run 'remove' first, then choose [2] Join from the menu."
            ));
        }
        let listen_port = self.config.get_listen_port().max(7878);
        let local_node_id = if snap.node_id.is_empty() {
            let nid = hex::encode(rand::random::<[u8; 16]>());
            self.config.update(|cfg| {
                if cfg.node_id.is_empty() {
                    cfg.node_id = nid.clone();
                }
            });
            self.config.snapshot().node_id.clone()
        } else {
            snap.node_id.clone()
        };
        drop(snap);
        let upnp_port_for_retry = upnp_port;
        let upnp_port = upnp_port_for_retry.unwrap_or(listen_port);
        let (peer_vip, peer_vip_target) = parse_vip_signal_target(&peer_vip_input, listen_port)?;
        let (self_vip, _) = parse_vip_signal_target(&self_vip_input, listen_port)?;

        if self_vip == peer_vip {
            return Err(anyhow!(
                "peer VIP and your VIP must be different (would self-loop the signaling pipe)"
            ));
        }

        self.upnp_cleanup_if_any().await;
        crate::cli_println!(
            "{}",
            term_style::fmt_para_line(format_args!(
                " Step 1/6: Trying UPnP mapping on UDP {upnp_port}..."
            ))
        );
        let local_ip = get_local_ip();
        let upnp_result = tokio::time::timeout(
            Duration::from_secs(4),
            upnp::discover_and_add_port(&local_ip, upnp_port, "MintegerP2P-Parasitic"),
        )
        .await
        .ok()
        .flatten();
        if let Some(ref m) = upnp_result {
            crate::cli_println!(
                "{}",
                term_style::fmt_para_line(format_args!(
                    " UPnP mapped ext_port={}, ext_ip={}",
                    m.ext_port, m.external_ip
                ))
            );
            self.upnp_set_mapping(m.clone());
        } else {
            crate::cli_println!(
                "{}",
                term_style::fmt_para_line(format_args!(" UPnP unavailable, continuing."))
            );
        }

        let stun_ep = if self.headless {
            let mut found = None;
            for attempt in 1..=HEADLESS_STUN_ATTEMPTS {
                crate::cli_println!(
                    "{}",
                    term_style::fmt_para_line(format_args!(
                        " Step 2/6: STUN public endpoint lookup..."
                    ))
                );
                let ep = self
                    .query_public_endpoint_from_engine(Duration::from_secs(3))
                    .await;
                if let Some(ep) = ep {
                    found = Some(ep);
                    break;
                }
                crate::cli_println!(
                    "{}",
                    term_style::fmt_para_line(format_args!(
                        " STUN failed (attempt {attempt}/{HEADLESS_STUN_ATTEMPTS})."
                    ))
                );
            }
            found.ok_or_else(|| {
                anyhow!(
                    "STUN failed after {HEADLESS_STUN_ATTEMPTS} attempts. Check connectivity, then run remove and choose [2] Join → Parasitic from the menu."
                )
            })?
        } else {
            let stun_ep = loop {
                crate::cli_println!(
                    "{}",
                    term_style::fmt_para_line(format_args!(
                        " Step 2/6: STUN public endpoint lookup..."
                    ))
                );
                let ep = self
                    .query_public_endpoint_from_engine(Duration::from_secs(3))
                    .await;
                if ep.is_some() {
                    break ep;
                }
                crate::cli_println!(
                    "{}",
                    term_style::fmt_para_line(format_args!(" STUN failed."))
                );
                if self
                    .prompt_retry_or_invite(
                        "  Choose [1] Retry STUN  [2] Back to invite (default 1): ",
                    )
                    .await?
                {
                    continue;
                }
                return self.fallback_to_invite_flow().await;
            };
            let Some(stun_ep) = stun_ep else {
                return self.fallback_to_invite_flow().await;
            };
            stun_ep
        };
        let local_public = make_socket_addr(&stun_ep.ip, stun_ep.port)?;
        crate::cli_println!(
            "{}",
            term_style::fmt_para_line(format_args!(" Local public endpoint: {}", local_public))
        );
        let local_candidates = gather_local_para_candidates(
            &self.config.snapshot(),
            &self.cmd_tx,
            Duration::from_secs(3),
        )
        .await;

        let existing_key_hex = self.config.snapshot().crypto_key.clone();
        let proposed_key_hex = if existing_key_hex.is_empty() {
            hex::encode(MintCrypto::generate_key().0)
        } else {
            existing_key_hex.clone()
        };
        let proposed_subnet = random_owner_vip();
        let session_id = hex::encode(rand::random::<[u8; 8]>());
        let proposed_start_at_ms = now_epoch_ms() + PARA_START_BUFFER_MS;

        let (sig_tx, mut sig_rx) = mpsc::channel::<ParaSignal>(2048);
        let listener_id = register_para_listener(&self.cmd_tx, sig_tx, false).await;

        let mut remote_candidates: Vec<SocketAddr> = Vec::new();
        let mut remote_public: Option<SocketAddr> = None;
        let mut remote_node_id = String::new();
        let mut remote_key_hex: Option<String> = None;
        let mut remote_subnet: Option<String> = None;
        let mut assigned_local_vip: Option<String> = None;
        let mut remote_vip: Option<String> = None;
        let mut agreed_network_id: Option<String> = None;
        let mut role_decided: Option<bool> = None;
        let mut finalized_owner_is_local: Option<bool> = None;
        let mut finalized_local_vip: Option<String> = None;
        let mut finalized_key_hex: Option<String> = None;
        let mut finalized_network_id: Option<String> = None;
        let mut state = ParaState::HelloSent { attempts: 0 };
        let mut seen_sessions = HashSet::new();

        crate::cli_println!(
            "{}",
            term_style::fmt_para_line(format_args!(
                " Step 3/6: Exchanging parasitic signals via VIP..."
            ))
        );
        loop {
            state = match state {
                ParaState::HelloSent { attempts } => {
                    if attempts >= PARA_SIGNAL_ATTEMPTS {
                        ParaState::Failed {
                            reason: "signaling timeout".to_string(),
                        }
                    } else {
                        let hello = json!({
                            "node_id": local_node_id,
                            "public_ip": local_public.ip().to_string(),
                            "public_port": local_public.port(),
                            "proposed_key_hex": proposed_key_hex,
                            "proposed_vip_subnet": proposed_subnet,
                            "ts_ms": now_epoch_ms(),
                            "candidates": local_candidates.clone(),
                            "start_at_ms": proposed_start_at_ms,
                            "session_id": session_id,
                        })
                        .to_string()
                        .into_bytes();
                        let _ = self
                            .cmd_tx
                            .send(EngineCmd::ParaSendHello {
                                target_vip: peer_vip_target,
                                payload: hello,
                            })
                            .await;
                        crate::cli_println!(
                            "{}",
                            term_style::fmt_para_line(format_args!(
                                " Signal attempt {}/{}",
                                attempts + 1,
                                PARA_SIGNAL_ATTEMPTS
                            ))
                        );
                        let wait =
                            tokio::time::timeout(para_signal_pause_duration(), sig_rx.recv()).await;
                        match wait {
                            Ok(Some(ParaSignal::HelloReceived {
                                public_ip,
                                public_port,
                                proposed_key,
                                proposed_vip_subnet,
                                node_id,
                                candidates,
                                start_at_ms,
                                session_id: remote_session_id,
                                ..
                            })) => {
                                if !remote_session_id.is_empty()
                                    && !seen_sessions.insert(remote_session_id.clone())
                                {
                                    ParaState::HelloSent {
                                        attempts: attempts + 1,
                                    }
                                } else {
                                    if let Ok(ep) = make_socket_addr(&public_ip, public_port) {
                                        remote_public = Some(ep);
                                    }
                                    remote_candidates = candidates_to_socket_addrs(&candidates);
                                    if let Some(ep) = remote_public {
                                        if !remote_candidates.contains(&ep) {
                                            remote_candidates.push(ep);
                                        }
                                    }
                                    remote_node_id = node_id.clone();
                                    remote_key_hex = Some(proposed_key.clone());
                                    remote_subnet = Some(proposed_vip_subnet.clone());
                                    let owner_is_local = local_node_id <= node_id;
                                    let chosen_key_hex = if owner_is_local {
                                        proposed_key_hex.clone()
                                    } else {
                                        proposed_key
                                    };
                                    let chosen_subnet = if owner_is_local {
                                        proposed_subnet.clone()
                                    } else {
                                        proposed_vip_subnet
                                    };
                                    let assigned_for_remote =
                                        vip_from_owner_subnet(&chosen_subnet, !owner_is_local)?;
                                    let assigned_for_local =
                                        vip_from_owner_subnet(&chosen_subnet, owner_is_local)?;
                                    remote_vip = Some(assigned_for_remote.clone());
                                    assigned_local_vip = Some(assigned_for_local.clone());
                                    role_decided = Some(owner_is_local);
                                    if let Ok(key_arr) = parse_key_hex_32(&chosen_key_hex) {
                                        agreed_network_id = Some(derive_network_id(&Key(key_arr)));
                                    }
                                    let agreed_start_at_ms = compute_agreed_start_at_ms(
                                        start_at_ms,
                                        now_epoch_ms() + PARA_START_BUFFER_MS,
                                    );
                                    let reply = json!({
                                        "node_id": local_node_id,
                                        "public_ip": local_public.ip().to_string(),
                                        "public_port": local_public.port(),
                                        "assigned_vip": assigned_for_remote,
                                        "network_id": agreed_network_id.clone().unwrap_or_default(),
                                        "ts_ms": now_epoch_ms(),
                                        "candidates": local_candidates.clone(),
                                        "agreed_start_at_ms": agreed_start_at_ms,
                                        "session_id": session_id,
                                        "responder_vip": assigned_for_local,
                                        "responder_is_owner": owner_is_local,
                                    })
                                    .to_string()
                                    .into_bytes();
                                    let _ = self
                                        .cmd_tx
                                        .send(EngineCmd::ParaSendReply {
                                            target_vip: peer_vip_target,
                                            payload: reply,
                                        })
                                        .await;
                                    if let Some(ep) = remote_public {
                                        ParaState::ReplyReceived {
                                            peer_ep: ep,
                                            start_at_ms: agreed_start_at_ms,
                                        }
                                    } else {
                                        ParaState::HelloSent {
                                            attempts: attempts + 1,
                                        }
                                    }
                                }
                            }
                            Ok(Some(ParaSignal::ReplyReceived {
                                public_ip,
                                public_port,
                                assigned_vip,
                                network_id,
                                node_id,
                                candidates,
                                agreed_start_at_ms: peer_start,
                                session_id: remote_session_id,
                                responder_vip,
                                responder_is_owner,
                                ..
                            })) => {
                                if !remote_session_id.is_empty() && remote_session_id != session_id
                                {
                                    ParaState::HelloSent {
                                        attempts: attempts + 1,
                                    }
                                } else if assigned_vip.is_empty() {
                                    ParaState::Failed {
                                        reason: "peer rejected parasitic (vip pool full)"
                                            .to_string(),
                                    }
                                } else {
                                    if let Ok(ep) = make_socket_addr(&public_ip, public_port) {
                                        remote_public = Some(ep);
                                    }
                                    remote_candidates = candidates_to_socket_addrs(&candidates);
                                    if let Some(ep) = remote_public {
                                        if !remote_candidates.contains(&ep) {
                                            remote_candidates.push(ep);
                                        }
                                    }
                                    remote_node_id = node_id;
                                    assigned_local_vip = Some(assigned_vip);

                                    let owner_is_local_now = if responder_is_owner {
                                        false
                                    } else if remote_node_id.is_empty() {
                                        true
                                    } else {
                                        local_node_id <= remote_node_id
                                    };
                                    role_decided = Some(owner_is_local_now);

                                    remote_vip = if !responder_vip.is_empty() {
                                        Some(responder_vip)
                                    } else if owner_is_local_now {
                                        Some(
                                            vip_from_owner_subnet(
                                                &owner_vip(
                                                    assigned_local_vip
                                                        .as_deref()
                                                        .unwrap_or("10.0.0.1"),
                                                ),
                                                false,
                                            )
                                            .unwrap_or_else(|_| "10.0.0.2".to_string()),
                                        )
                                    } else {
                                        Some(owner_vip(
                                            assigned_local_vip.as_deref().unwrap_or("10.0.0.2"),
                                        ))
                                    };
                                    agreed_network_id = Some(network_id);
                                    let agreed_start_at_ms = compute_agreed_start_at_ms(
                                        peer_start,
                                        now_epoch_ms() + PARA_START_BUFFER_MS,
                                    );
                                    if let Some(ep) = remote_public {
                                        ParaState::ReplyReceived {
                                            peer_ep: ep,
                                            start_at_ms: agreed_start_at_ms,
                                        }
                                    } else {
                                        ParaState::HelloSent {
                                            attempts: attempts + 1,
                                        }
                                    }
                                }
                            }
                            _ => ParaState::HelloSent {
                                attempts: attempts + 1,
                            },
                        }
                    }
                }
                ParaState::ReplyReceived {
                    peer_ep,
                    start_at_ms,
                } => {
                    let _ = send_para_ok_redundant(
                        &self.cmd_tx,
                        peer_vip_target,
                        &local_node_id,
                        &session_id,
                    )
                    .await;
                    ParaState::OkSent {
                        peer_ep,
                        start_at_ms,
                    }
                }
                ParaState::OkSent {
                    peer_ep,
                    start_at_ms,
                } => {
                    let wait =
                        tokio::time::timeout(Duration::from_millis(PARA_OK_WAIT_MS), sig_rx.recv())
                            .await;
                    match wait {
                        Ok(Some(ParaSignal::OkReceived {
                            session_id: sid, ..
                        })) if sid.is_empty() || sid == session_id => ParaState::WaitingStart {
                            peer_ep,
                            start_at_ms,
                            ok_confirmed: true,
                        },
                        _ => ParaState::WaitingStart {
                            peer_ep,
                            start_at_ms,
                            ok_confirmed: false,
                        },
                    }
                }
                ParaState::WaitingStart {
                    peer_ep,
                    start_at_ms,
                    ok_confirmed,
                } => {
                    let _ = peer_ep;
                    if !ok_confirmed {
                        let retry_wait_ms = (start_at_ms.saturating_sub(now_epoch_ms()))
                            .min(PARA_OK_WAIT_MS)
                            .max(200);
                        let retry_wait = tokio::time::timeout(
                            Duration::from_millis(retry_wait_ms),
                            sig_rx.recv(),
                        )
                        .await;
                        let got_ok = matches!(
                            retry_wait,
                            Ok(Some(ParaSignal::OkReceived { session_id: sid, .. }))
                                if sid.is_empty() || sid == session_id
                        );
                        if !got_ok {
                            crate::cli_eprintln!(
                                "{}",
                                term_style::fmt_para_line_stderr(format_args!(
                                    " owner did not confirm OK within {}ms; proceeding optimistically.",
                                    PARA_OK_WAIT_MS
                                ))
                            );
                            wait_until_para_start(start_at_ms).await;
                            ParaState::Punching
                        } else {
                            wait_until_para_start(start_at_ms).await;
                            ParaState::Punching
                        }
                    } else {
                        wait_until_para_start(start_at_ms).await;
                        ParaState::Punching
                    }
                }
                ParaState::Punching => {
                    let owner_is_local_now = role_decided.unwrap_or_else(|| {
                        if remote_node_id.is_empty() {
                            true
                        } else {
                            local_node_id <= remote_node_id
                        }
                    });
                    let rv = remote_vip.clone().unwrap_or_else(|| {
                        if owner_is_local_now {
                            vip_from_owner_subnet(
                                &owner_vip(assigned_local_vip.as_deref().unwrap_or("10.0.0.1")),
                                false,
                            )
                            .unwrap_or_else(|_| "10.0.0.2".to_string())
                        } else {
                            owner_vip(assigned_local_vip.as_deref().unwrap_or("10.0.0.2"))
                        }
                    });
                    let chosen_key_hex = if owner_is_local_now {
                        proposed_key_hex.clone()
                    } else if let Some(ref k) = remote_key_hex {
                        k.clone()
                    } else if !existing_key_hex.is_empty() {
                        existing_key_hex.clone()
                    } else {
                        crate::cli_println!(
                            "{}",
                            term_style::fmt_para_line(format_args!(
                                " Key fallback: using local proposed key (reply-only path)."
                            ))
                        );
                        proposed_key_hex.clone()
                    };
                    let chosen_subnet = if owner_is_local_now {
                        proposed_subnet.clone()
                    } else {
                        remote_subnet.clone().unwrap_or_else(|| {
                            owner_vip(assigned_local_vip.as_deref().unwrap_or("10.0.0.2"))
                        })
                    };
                    let local_vip_now = assigned_local_vip.clone().unwrap_or_else(|| {
                        vip_from_owner_subnet(&chosen_subnet, owner_is_local_now)
                            .unwrap_or_else(|_| "10.0.0.2".to_string())
                    });
                    let network_id_now = if let Some(ref id) = agreed_network_id {
                        id.clone()
                    } else {
                        derive_network_id(&Key(parse_key_hex_32(&chosen_key_hex)?))
                    };
                    if remote_candidates.is_empty() {
                        if let Some(ep) = remote_public {
                            remote_candidates.push(ep);
                        }
                    }
                    if remote_candidates.is_empty() {
                        ParaState::Failed {
                            reason: "missing remote endpoint".to_string(),
                        }
                    } else {
                        let peer_public_ep = remote_public
                            .or_else(|| remote_candidates.first().copied())
                            .ok_or_else(|| anyhow!("missing peer endpoint after signaling"))?;
                        let key_raw = parse_key_hex_32(&chosen_key_hex)?;
                        let mut bound_targets = HashSet::new();
                        for candidate in &remote_candidates {
                            if bound_targets.insert(*candidate) {
                                let _ = self
                                    .cmd_tx
                                    .send(EngineCmd::BindPeerKey {
                                        peer: *candidate,
                                        key: Key(key_raw),
                                    })
                                    .await;
                            }
                        }
                        self.apply_parasitic_identity(
                            owner_is_local_now,
                            &local_vip_now,
                            &local_node_id,
                            key_raw,
                            peer_public_ep,
                        )
                        .await?;
                        if self
                            .run_parasitic_punch(
                                &remote_candidates,
                                &rv,
                                PARA_PEER_PUNCH_MIN_WALL_MS,
                            )
                            .await
                        {
                            let ack_target =
                                { self.routing.read().lookup(&rv).unwrap_or(peer_vip_target) };
                            if !owner_is_local_now && ack_target != peer_public_ep {
                                let _ = self
                                    .cmd_tx
                                    .send(EngineCmd::SetOwnerEndpoint(ack_target, None))
                                    .await;
                                let _ = self
                                    .cmd_tx
                                    .send(EngineCmd::BindPeerKey {
                                        peer: ack_target,
                                        key: Key(key_raw),
                                    })
                                    .await;
                            }
                            let ack_targets = {
                                let rt = self.routing.read();
                                collect_para_punch_ack_targets(
                                    &rt,
                                    &rv,
                                    &remote_candidates,
                                    &[peer_public_ep, peer_vip_target],
                                )
                            };
                            let _ = send_para_punch_ack_redundant(
                                &self.cmd_tx,
                                &ack_targets,
                                &local_node_id,
                                &session_id,
                            )
                            .await;
                            finalized_owner_is_local = Some(owner_is_local_now);
                            finalized_local_vip = Some(local_vip_now);
                            finalized_key_hex = Some(chosen_key_hex);
                            finalized_network_id = Some(network_id_now);
                            ParaState::Connected
                        } else {
                            ParaState::Failed {
                                reason: "punch failed".to_string(),
                            }
                        }
                    }
                }
                ParaState::Connected => break,
                ParaState::Failed { reason } => {
                    crate::cli_println!(
                        "{}",
                        term_style::fmt_para_line(format_args!(" {reason}."))
                    );
                    if self.headless {
                        unregister_para_listener(&self.cmd_tx, listener_id).await;
                        return Err(anyhow!(
                            "parasitic join failed: {reason}. Run remove, then choose [2] Join → Parasitic from the menu."
                        ));
                    }
                    if self
                        .prompt_retry_or_invite(
                            "  Choose [1] Retry parasitic  [2] Back to invite (default 1): ",
                        )
                        .await?
                    {
                        unregister_para_listener(&self.cmd_tx, listener_id).await;
                        return Box::pin(self.join_parasitic_with_params(
                            peer_vip_input.clone(),
                            self_vip_input.clone(),
                            upnp_port_for_retry,
                        ))
                        .await;
                    }
                    unregister_para_listener(&self.cmd_tx, listener_id).await;
                    return self.fallback_to_invite_flow().await;
                }
            };
            if matches!(state, ParaState::Connected) {
                break;
            }
        }
        unregister_para_listener(&self.cmd_tx, listener_id).await;

        let _peer_public_ep = remote_public
            .or_else(|| remote_candidates.first().copied())
            .ok_or_else(|| anyhow!("missing peer endpoint after signaling"))?;
        let owner_is_local = finalized_owner_is_local
            .ok_or_else(|| anyhow!("missing finalized role after punch"))?;
        let local_vip = finalized_local_vip
            .ok_or_else(|| anyhow!("missing finalized local vip after punch"))?;
        let chosen_key_hex =
            finalized_key_hex.ok_or_else(|| anyhow!("missing finalized key after punch"))?;
        let network_id = finalized_network_id
            .ok_or_else(|| anyhow!("missing finalized network id after punch"))?;

        crate::cli_println!(
            "{}",
            term_style::fmt_para_line(format_args!(" Step 4/6: Running punch sequences..."))
        );

        crate::cli_println!(
            "{}",
            term_style::fmt_para_line(format_args!(" Step 5/6: Saving profile..."))
        );
        ensure_netinfo_dir()?;
        self.config.set_network_basics(
            "Mint".to_string(),
            network_id.clone(),
            if owner_is_local {
                "owner".to_string()
            } else {
                "peer".to_string()
            },
            local_vip.clone(),
            local_node_id.clone(),
            listen_port,
        );
        let remote_node_id_save = remote_node_id.clone();
        self.config.update(|cfg| {
            cfg.owner_real_ip.clear();
            cfg.owner_port = 0;
            cfg.owner_endpoints_cache.clear();
            cfg.crypto_key = chosen_key_hex.clone();
            cfg.parasitic_enabled = true;
            cfg.parasitic_peer_vip = peer_vip.clone();
            cfg.parasitic_self_vip = self_vip.clone();
            cfg.parasitic_peer_port = peer_vip_target.port();
            cfg.parasitic_peer_node_id = remote_node_id_save.clone();
            cfg.parasitic_self_is_owner = owner_is_local;
            cfg.parasitic_use_public = true;
            cfg.join_method = "parasitic".to_string();
        });
        self.refresh_owner_vip_pool_from_config(owner_is_local);

        #[cfg(windows)]
        {
            let vip_ip = local_vip
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| anyhow!("invalid parasitic vip: {local_vip}"))?;
            let snap = self.config.snapshot();
            let ring = effective_wintun_ring_bytes(snap.wintun_ring_bytes);
            let ipv4_metric =
                effective_wintun_ipv4_interface_metric(snap.wintun_ipv4_interface_metric);
            let para_prefix = snap.subnet_prefix.clamp(8, 30);
            let wintun_prefix = para_prefix;
            let adapter = tokio::task::spawn_blocking(move || -> Result<Arc<WintunAdapter>> {
                Ok(Arc::new(
                    WintunAdapter::create(
                        crate::tun::wintun::WINTUN_ADAPTER_NAME,
                        vip_ip,
                        wintun_prefix,
                        ring,
                        ipv4_metric,
                    )
                    .map_err(|e| anyhow!("failed to create Wintun adapter: {e}"))?,
                ))
            })
            .await
            .map_err(|e| anyhow!("wintun create task join failed: {e}"))??;
            self.wire_adapter(adapter.clone());
            self.vni = Some(adapter);
            crate::cli_println!(
                "{}",
                term_style::fmt_info_line(format_args!(
                    " Wintun adapter ready for {local_vip}/{para_prefix}"
                ))
            );
        }
        self.state = AppState::CommandLoop;
        self.ensure_parasitic_passive_listener().await?;
        crate::cli_println!(
            "{}",
            term_style::fmt_para_line(format_args!(" Step 6/6: Connected."))
        );
        crate::cli_println!(
            "  \" Parasitic join completed ({})",
            if owner_is_local { "owner" } else { "peer" }
        );
        Ok(())
    }

    /// Broadcast discover_only MPHI; return distinct owners (headless-safe).
    pub async fn discover_parasitic_lan(&mut self) -> Result<Vec<crate::ipc::ParasiticLanOwner>> {
        self.stop_parasitic_passive_listener();
        let snap = self.config.snapshot();
        if !snap.network_id.is_empty() && !snap.parasitic_enabled {
            return Err(anyhow!(
                "active network exists. run 'remove' first, then choose [2] Join from the menu."
            ));
        }
        let listen_port = self.config.get_listen_port().max(7878);
        let local_node_id = if snap.node_id.is_empty() {
            let nid = hex::encode(rand::random::<[u8; 16]>());
            self.config.update(|cfg| {
                if cfg.node_id.is_empty() {
                    cfg.node_id = nid.clone();
                }
            });
            self.config.snapshot().node_id.clone()
        } else {
            snap.node_id.clone()
        };
        drop(snap);

        let local_ip = get_local_ip();
        let local_public = make_socket_addr(&local_ip, listen_port)?;
        let local_candidates = gather_local_para_candidates_inner(
            &self.config.snapshot(),
            &self.cmd_tx,
            Duration::from_secs(1),
            false,
            true,
        )
        .await;
        let session_id = hex::encode(rand::random::<[u8; 8]>());
        let proposed_start_at_ms = now_epoch_ms() + PARA_START_BUFFER_MS;
        let proposed_key_hex = hex::encode(MintCrypto::generate_key().0);
        let proposed_subnet = random_owner_vip();

        let (sig_tx, mut sig_rx) = mpsc::channel::<ParaSignal>(2048);
        let listener_id = register_para_listener(&self.cmd_tx, sig_tx, false).await;

        let targets = para_lan_discovery_targets(&local_ip, listen_port);
        crate::cli_println!(
            "{}",
            term_style::fmt_para_line(format_args!(
                " LAN discover: broadcasting on {} target(s) for {PARA_LAN_DISCOVER_MS}ms…",
                targets.len()
            ))
        );

        let hello = json!({
            "node_id": local_node_id,
            "public_ip": local_public.ip().to_string(),
            "public_port": local_public.port(),
            "proposed_key_hex": proposed_key_hex,
            "proposed_vip_subnet": proposed_subnet,
            "ts_ms": now_epoch_ms(),
            "candidates": local_candidates,
            "start_at_ms": proposed_start_at_ms,
            "session_id": session_id,
            "discover_only": true,
        })
        .to_string()
        .into_bytes();

        for target in &targets {
            let _ = self
                .cmd_tx
                .send(EngineCmd::ParaSendHello {
                    target_vip: *target,
                    payload: hello.clone(),
                })
                .await;
        }

        let deadline = Instant::now() + Duration::from_millis(PARA_LAN_DISCOVER_MS);
        let mut owners: HashMap<(String, String), crate::ipc::ParasiticLanOwner> = HashMap::new();
        while Instant::now() < deadline {
            let remain = deadline.saturating_duration_since(Instant::now());
            if remain.is_zero() {
                break;
            }
            match tokio::time::timeout(remain, sig_rx.recv()).await {
                Ok(Some(ParaSignal::ReplyReceived {
                    from,
                    network_id,
                    node_id,
                    responder_is_owner,
                    network_name,
                    assigned_vip,
                    ..
                })) => {
                    if !responder_is_owner || network_id.is_empty() {
                        continue;
                    }
                    // discover_only replies use empty assigned_vip
                    let _ = assigned_vip;
                    let key = (network_id.clone(), from.to_string());
                    owners
                        .entry(key)
                        .or_insert_with(|| crate::ipc::ParasiticLanOwner {
                            network_name,
                            network_id,
                            from: from.to_string(),
                            node_id,
                        });
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }

        unregister_para_listener(&self.cmd_tx, listener_id).await;
        let mut list: Vec<_> = owners.into_values().collect();
        list.sort_by(|a, b| {
            a.network_name
                .cmp(&b.network_name)
                .then(a.network_id.cmp(&b.network_id))
                .then(a.from.cmp(&b.from))
        });
        crate::cli_println!(
            "{}",
            term_style::fmt_para_line(format_args!(
                " LAN discover: {} owner reply(ies).",
                list.len()
            ))
        );
        Ok(list)
    }

    /// Unicast admit Hello to owner LAN target and complete punch (headless-safe).
    pub async fn join_parasitic_lan_from_str(&mut self, target: String) -> Result<()> {
        let listen_port = self.config.get_listen_port().max(7878);
        let addr = parse_vip_signal_target(target.trim(), listen_port)?.1;
        self.join_parasitic_lan_with_target(addr).await
    }

    /// Unicast real Hello to owner LAN target and complete punch (headless-safe).
    pub async fn join_parasitic_lan_with_target(&mut self, target: SocketAddr) -> Result<()> {
        self.stop_parasitic_passive_listener();
        let snap = self.config.snapshot();
        if !snap.network_id.is_empty() && !snap.parasitic_enabled {
            return Err(anyhow!(
                "active network exists. run 'remove' first, then choose [2] Join from the menu."
            ));
        }
        if !is_rfc1918_private_ip(target.ip()) {
            return Err(anyhow!(
                "LAN parasitic target must be a private IPv4 address (got {target})"
            ));
        }
        let listen_port = self.config.get_listen_port().max(7878);
        let local_node_id = if snap.node_id.is_empty() {
            let nid = hex::encode(rand::random::<[u8; 16]>());
            self.config.update(|cfg| {
                if cfg.node_id.is_empty() {
                    cfg.node_id = nid.clone();
                }
            });
            self.config.snapshot().node_id.clone()
        } else {
            snap.node_id.clone()
        };
        drop(snap);

        let local_ip = get_local_ip();
        let local_public = make_socket_addr(&local_ip, listen_port)?;
        let self_vip = local_ip.clone();
        let peer_vip = target.ip().to_string();
        let peer_vip_target = target;

        crate::cli_println!(
            "{}",
            term_style::fmt_para_line(format_args!(
                " LAN parasitic: joining owner at {peer_vip_target} (no STUN/UPnP)…"
            ))
        );

        let local_candidates = gather_local_para_candidates_inner(
            &self.config.snapshot(),
            &self.cmd_tx,
            Duration::from_secs(1),
            false,
            true,
        )
        .await;
        let proposed_key_hex = hex::encode(MintCrypto::generate_key().0);
        let proposed_subnet = random_owner_vip();
        let session_id = hex::encode(rand::random::<[u8; 8]>());
        let proposed_start_at_ms = now_epoch_ms() + PARA_START_BUFFER_MS;

        let (sig_tx, mut sig_rx) = mpsc::channel::<ParaSignal>(2048);
        let listener_id = register_para_listener(&self.cmd_tx, sig_tx, false).await;

        let mut remote_candidates: Vec<SocketAddr> = Vec::new();
        let mut remote_public: Option<SocketAddr> = None;
        let mut remote_node_id = String::new();
        let mut assigned_local_vip: Option<String> = None;
        let mut remote_vip: Option<String> = None;
        let mut agreed_network_id: Option<String> = None;
        let mut network_key_hex: Option<String> = None;
        let mut agreed_start: Option<u64> = None;
        let mut state = ParaState::HelloSent { attempts: 0 };

        loop {
            state = match state {
                ParaState::HelloSent { attempts } => {
                    if attempts >= PARA_SIGNAL_ATTEMPTS {
                        ParaState::Failed {
                            reason: "LAN signaling timeout".to_string(),
                        }
                    } else {
                        let hello = json!({
                            "node_id": local_node_id,
                            "public_ip": local_public.ip().to_string(),
                            "public_port": local_public.port(),
                            "proposed_key_hex": proposed_key_hex,
                            "proposed_vip_subnet": proposed_subnet,
                            "ts_ms": now_epoch_ms(),
                            "candidates": local_candidates.clone(),
                            "start_at_ms": proposed_start_at_ms,
                            "session_id": session_id,
                            "discover_only": false,
                        })
                        .to_string()
                        .into_bytes();
                        let _ = self
                            .cmd_tx
                            .send(EngineCmd::ParaSendHello {
                                target_vip: peer_vip_target,
                                payload: hello,
                            })
                            .await;
                        crate::cli_println!(
                            "{}",
                            term_style::fmt_para_line(format_args!(
                                " LAN signal attempt {}/{}",
                                attempts + 1,
                                PARA_SIGNAL_ATTEMPTS
                            ))
                        );
                        let wait =
                            tokio::time::timeout(para_signal_pause_duration(), sig_rx.recv()).await;
                        match wait {
                            Ok(Some(ParaSignal::ReplyReceived {
                                from,
                                public_ip,
                                public_port,
                                assigned_vip,
                                network_id,
                                node_id,
                                candidates,
                                agreed_start_at_ms: peer_start,
                                session_id: remote_session_id,
                                responder_vip,
                                responder_is_owner,
                                network_key_hex: reply_key,
                                ..
                            })) => {
                                if !remote_session_id.is_empty() && remote_session_id != session_id
                                {
                                    ParaState::HelloSent {
                                        attempts: attempts + 1,
                                    }
                                } else if !responder_is_owner {
                                    ParaState::HelloSent {
                                        attempts: attempts + 1,
                                    }
                                } else if assigned_vip.is_empty() {
                                    ParaState::Failed {
                                        reason: "owner rejected parasitic (vip pool full)"
                                            .to_string(),
                                    }
                                } else if reply_key.trim().is_empty() {
                                    ParaState::Failed {
                                        reason: "owner reply missing network_key_hex".to_string(),
                                    }
                                } else {
                                    remote_public = Some(from);
                                    if is_rfc1918_private_ip(from.ip()) {
                                        // prefer signal from
                                    } else if let Ok(ep) = make_socket_addr(&public_ip, public_port)
                                    {
                                        if is_rfc1918_private_ip(ep.ip()) {
                                            remote_public = Some(ep);
                                        }
                                    }
                                    remote_candidates = filter_private_socket_addrs(
                                        &candidates_to_socket_addrs(&candidates),
                                    );
                                    if let Some(ep) = remote_public {
                                        if is_rfc1918_private_ip(ep.ip())
                                            && !remote_candidates.contains(&ep)
                                        {
                                            remote_candidates.push(ep);
                                        }
                                    }
                                    if !remote_candidates.contains(&peer_vip_target) {
                                        remote_candidates.push(peer_vip_target);
                                    }
                                    remote_node_id = node_id;
                                    assigned_local_vip = Some(assigned_vip);
                                    remote_vip = if !responder_vip.is_empty() {
                                        Some(responder_vip)
                                    } else {
                                        None
                                    };
                                    agreed_network_id = Some(network_id);
                                    network_key_hex = Some(reply_key);
                                    let start = compute_agreed_start_at_ms(
                                        peer_start,
                                        now_epoch_ms() + PARA_START_BUFFER_MS,
                                    );
                                    agreed_start = Some(start);
                                    if let Some(ep) = remote_public {
                                        ParaState::ReplyReceived {
                                            peer_ep: ep,
                                            start_at_ms: start,
                                        }
                                    } else {
                                        ParaState::HelloSent {
                                            attempts: attempts + 1,
                                        }
                                    }
                                }
                            }
                            _ => ParaState::HelloSent {
                                attempts: attempts + 1,
                            },
                        }
                    }
                }
                ParaState::ReplyReceived {
                    peer_ep,
                    start_at_ms,
                } => {
                    let _ = send_para_ok_redundant(
                        &self.cmd_tx,
                        peer_vip_target,
                        &local_node_id,
                        &session_id,
                    )
                    .await;
                    ParaState::OkSent {
                        peer_ep,
                        start_at_ms,
                    }
                }
                ParaState::OkSent {
                    peer_ep,
                    start_at_ms,
                } => {
                    let wait =
                        tokio::time::timeout(Duration::from_millis(PARA_OK_WAIT_MS), sig_rx.recv())
                            .await;
                    match wait {
                        Ok(Some(ParaSignal::OkReceived {
                            session_id: sid, ..
                        })) if sid.is_empty() || sid == session_id => ParaState::WaitingStart {
                            peer_ep,
                            start_at_ms,
                            ok_confirmed: true,
                        },
                        _ => ParaState::WaitingStart {
                            peer_ep,
                            start_at_ms,
                            ok_confirmed: false,
                        },
                    }
                }
                ParaState::WaitingStart {
                    peer_ep,
                    start_at_ms,
                    ok_confirmed,
                } => {
                    let _ = peer_ep;
                    if !ok_confirmed {
                        let retry_wait_ms = (start_at_ms.saturating_sub(now_epoch_ms()))
                            .min(PARA_OK_WAIT_MS)
                            .max(200);
                        let retry_wait = tokio::time::timeout(
                            Duration::from_millis(retry_wait_ms),
                            sig_rx.recv(),
                        )
                        .await;
                        let _ = matches!(
                            retry_wait,
                            Ok(Some(ParaSignal::OkReceived { session_id: sid, .. }))
                                if sid.is_empty() || sid == session_id
                        );
                    }
                    wait_until_para_start(start_at_ms).await;
                    ParaState::Punching
                }
                ParaState::Punching => {
                    let chosen_key_hex = network_key_hex.clone().unwrap_or_default();
                    let local_vip_now = assigned_local_vip.clone().unwrap_or_default();
                    let network_id_now = agreed_network_id.clone().unwrap_or_default();
                    let rv = remote_vip
                        .clone()
                        .unwrap_or_else(|| owner_vip(local_vip_now.as_str()));
                    if chosen_key_hex.is_empty()
                        || local_vip_now.is_empty()
                        || network_id_now.is_empty()
                    {
                        ParaState::Failed {
                            reason: "incomplete LAN admit reply".to_string(),
                        }
                    } else if remote_candidates.is_empty() {
                        ParaState::Failed {
                            reason: "missing private remote endpoint".to_string(),
                        }
                    } else {
                        let peer_public_ep = remote_public
                            .or_else(|| remote_candidates.first().copied())
                            .ok_or_else(|| anyhow!("missing peer endpoint after LAN signaling"))?;
                        let key_raw = parse_key_hex_32(&chosen_key_hex)?;
                        let mut bound_targets = HashSet::new();
                        for candidate in &remote_candidates {
                            if bound_targets.insert(*candidate) {
                                let _ = self
                                    .cmd_tx
                                    .send(EngineCmd::BindPeerKey {
                                        peer: *candidate,
                                        key: Key(key_raw),
                                    })
                                    .await;
                            }
                        }
                        self.apply_parasitic_identity(
                            false,
                            &local_vip_now,
                            &local_node_id,
                            key_raw,
                            peer_public_ep,
                        )
                        .await?;
                        if self
                            .run_parasitic_punch(
                                &remote_candidates,
                                &rv,
                                PARA_PEER_PUNCH_MIN_WALL_MS,
                            )
                            .await
                        {
                            let ack_target =
                                { self.routing.read().lookup(&rv).unwrap_or(peer_vip_target) };
                            if ack_target != peer_public_ep {
                                let _ = self
                                    .cmd_tx
                                    .send(EngineCmd::SetOwnerEndpoint(ack_target, None))
                                    .await;
                                let _ = self
                                    .cmd_tx
                                    .send(EngineCmd::BindPeerKey {
                                        peer: ack_target,
                                        key: Key(key_raw),
                                    })
                                    .await;
                            }
                            let ack_targets = {
                                let rt = self.routing.read();
                                collect_para_punch_ack_targets(
                                    &rt,
                                    &rv,
                                    &remote_candidates,
                                    &[peer_public_ep, peer_vip_target],
                                )
                            };
                            let _ = send_para_punch_ack_redundant(
                                &self.cmd_tx,
                                &ack_targets,
                                &local_node_id,
                                &session_id,
                            )
                            .await;
                            // Stash for finalize via outer vars
                            agreed_start = Some(agreed_start.unwrap_or(proposed_start_at_ms));
                            network_key_hex = Some(chosen_key_hex);
                            assigned_local_vip = Some(local_vip_now);
                            agreed_network_id = Some(network_id_now);
                            remote_vip = Some(rv);
                            remote_public = Some(peer_public_ep);
                            ParaState::Connected
                        } else {
                            ParaState::Failed {
                                reason: "punch failed".to_string(),
                            }
                        }
                    }
                }
                ParaState::Connected => break,
                ParaState::Failed { reason } => {
                    unregister_para_listener(&self.cmd_tx, listener_id).await;
                    return Err(anyhow!(
                        "LAN parasitic join failed: {reason}. Check AP isolation, owner listen port (default 7878), then retry."
                    ));
                }
            };
            if matches!(state, ParaState::Connected) {
                break;
            }
        }
        unregister_para_listener(&self.cmd_tx, listener_id).await;

        let local_vip =
            assigned_local_vip.ok_or_else(|| anyhow!("missing assigned VIP after LAN punch"))?;
        let chosen_key_hex =
            network_key_hex.ok_or_else(|| anyhow!("missing network key after LAN punch"))?;
        let network_id =
            agreed_network_id.ok_or_else(|| anyhow!("missing network_id after LAN punch"))?;

        crate::cli_println!(
            "{}",
            term_style::fmt_para_line(format_args!(" Saving LAN parasitic profile…"))
        );
        ensure_netinfo_dir()?;
        self.config.set_network_basics(
            "Mint".to_string(),
            network_id,
            "peer".to_string(),
            local_vip.clone(),
            local_node_id.clone(),
            listen_port,
        );
        let remote_node_id_save = remote_node_id.clone();
        self.config.update(|cfg| {
            cfg.owner_real_ip.clear();
            cfg.owner_port = 0;
            cfg.owner_endpoints_cache.clear();
            cfg.crypto_key = chosen_key_hex;
            cfg.parasitic_enabled = true;
            cfg.parasitic_peer_vip = peer_vip;
            cfg.parasitic_self_vip = self_vip;
            cfg.parasitic_peer_port = peer_vip_target.port();
            cfg.parasitic_peer_node_id = remote_node_id_save;
            cfg.parasitic_self_is_owner = false;
            cfg.parasitic_use_public = false;
            cfg.join_method = "parasitic".to_string();
            cfg.decentralized_enabled = false;
        });
        self.refresh_owner_vip_pool_from_config(false);

        #[cfg(windows)]
        {
            let vip_ip = local_vip
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| anyhow!("invalid parasitic vip: {local_vip}"))?;
            let snap = self.config.snapshot();
            let ring = effective_wintun_ring_bytes(snap.wintun_ring_bytes);
            let ipv4_metric =
                effective_wintun_ipv4_interface_metric(snap.wintun_ipv4_interface_metric);
            let para_prefix = snap.subnet_prefix.clamp(8, 30);
            let wintun_prefix = para_prefix;
            let adapter = tokio::task::spawn_blocking(move || -> Result<Arc<WintunAdapter>> {
                Ok(Arc::new(
                    WintunAdapter::create(
                        crate::tun::wintun::WINTUN_ADAPTER_NAME,
                        vip_ip,
                        wintun_prefix,
                        ring,
                        ipv4_metric,
                    )
                    .map_err(|e| anyhow!("failed to create Wintun adapter: {e}"))?,
                ))
            })
            .await
            .map_err(|e| anyhow!("wintun create task join failed: {e}"))??;
            self.wire_adapter(adapter.clone());
            self.vni = Some(adapter);
            crate::cli_println!(
                "{}",
                term_style::fmt_info_line(format_args!(
                    " Wintun adapter ready for {local_vip}/{para_prefix}"
                ))
            );
        }
        self.state = AppState::CommandLoop;
        self.ensure_parasitic_passive_listener().await?;
        crate::cli_println!(
            "{}",
            term_style::fmt_para_line(format_args!(" LAN parasitic join completed (peer)."))
        );
        Ok(())
    }

    async fn fallback_to_invite_flow(&mut self) -> Result<()> {
        if self.headless {
            return Err(anyhow!(
                "parasitic join aborted. Run remove, then choose [2] Join from the menu (invite or parasitic)."
            ));
        }
        crate::cli_print!("  Invite code: ");
        io::stdout().flush()?;
        let invite = self.read_line().await?;
        if invite.is_empty() {
            return Err(anyhow!("invite code is required"));
        }
        self.handle_join(&invite, self.resolve_join_invite_opts().await?)
            .await
    }

    async fn prompt_retry_or_invite(&self, prompt: &str) -> Result<bool> {
        if self.headless {
            return Err(anyhow!(
                "parasitic join needs a choice on the CLI client ({prompt}). Run remove, then choose [2] Join from the menu."
            ));
        }
        crate::cli_print!("{prompt}");
        io::stdout().flush()?;
        let choice = self.read_line().await?;
        Ok(choice.trim() != "2")
    }

    async fn sync_engine_from_saved_profile(&self) -> Result<()> {
        let snap = self.config.snapshot();
        if snap.virtual_ip.is_empty() || snap.network_id.is_empty() {
            return Ok(());
        }
        if snap.role != "owner" && snap.role != "peer" {
            return Ok(());
        }
        let node_id = snap.node_id.trim();
        if node_id.is_empty() {
            return Ok(());
        }
        let is_owner = snap.role == "owner";
        let vip = snap.virtual_ip.trim().to_string();

        if !snap.crypto_key.trim().is_empty() {
            if let Ok(key_raw) = parse_key_hex_32(snap.crypto_key.trim()) {
                let (key_tx, key_rx) = oneshot::channel();
                self.cmd_tx
                    .send(EngineCmd::SetCryptoKey(Key(key_raw), Some(key_tx)))
                    .await?;
                let _ = tokio::time::timeout(Duration::from_secs(1), key_rx).await;
            }
        }

        let (id_tx, id_rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCmd::SetIdentity {
                is_owner,
                my_vip: vip,
                my_node_id: node_id.to_string(),
                subnet_prefix: snap.subnet_prefix.clamp(8, 30),
                reply: Some(id_tx),
            })
            .await?;
        let _ = tokio::time::timeout(Duration::from_secs(1), id_rx).await;

        if !is_owner
            && !snap.parasitic_enabled
            && !snap.owner_real_ip.trim().is_empty()
            && snap.owner_port > 0
        {
            if let Ok(owner_ep) = make_socket_addr(snap.owner_real_ip.trim(), snap.owner_port) {
                let (o_tx, o_rx) = oneshot::channel();
                self.cmd_tx
                    .send(EngineCmd::SetOwnerEndpoint(owner_ep, Some(o_tx)))
                    .await?;
                let _ = tokio::time::timeout(Duration::from_secs(1), o_rx).await;
            }
        }
        if snap.decentralized_enabled {
            let node_id = snap.node_id.clone();
            let _ = self
                .start_decentralized_engine(None, false, None, None, &node_id)
                .await;
        }
        Ok(())
    }

    async fn apply_parasitic_identity(
        &self,
        owner_is_local: bool,
        local_vip: &str,
        local_node_id: &str,
        key_raw: [u8; 32],
        peer_public_ep: SocketAddr,
    ) -> Result<()> {
        let (key_tx, key_rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .send(EngineCmd::SetCryptoKey(Key(key_raw), Some(key_tx)))
            .await;
        let _ = tokio::time::timeout(Duration::from_secs(1), key_rx).await;
        let _ = self
            .cmd_tx
            .send(EngineCmd::BindPeerKey {
                peer: peer_public_ep,
                key: Key(key_raw),
            })
            .await;

        let snap = self.config.snapshot();
        let (id_tx, id_rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .send(EngineCmd::SetIdentity {
                is_owner: owner_is_local,
                my_vip: local_vip.to_string(),
                my_node_id: local_node_id.to_string(),
                subnet_prefix: snap.subnet_prefix.clamp(8, 30),
                reply: Some(id_tx),
            })
            .await;
        let _ = tokio::time::timeout(Duration::from_secs(1), id_rx).await;

        if !owner_is_local {
            let (owner_tx, owner_rx) = oneshot::channel();
            let _ = self
                .cmd_tx
                .send(EngineCmd::SetOwnerEndpoint(peer_public_ep, Some(owner_tx)))
                .await;
            let _ = tokio::time::timeout(Duration::from_secs(1), owner_rx).await;
        }
        Ok(())
    }

    async fn run_parasitic_punch(
        &self,
        remote_candidates: &[SocketAddr],
        remote_vip: &str,
        min_wall_ms: u64,
    ) -> bool {
        if remote_candidates.is_empty() {
            return false;
        }
        prepare_para_punch_route(&self.routing, &self.cmd_tx, remote_vip);
        for target in remote_candidates {
            let _ = self
                .cmd_tx
                .send(EngineCmd::ManualPunch {
                    target: *target,
                    count: PARA_KEEPALIVE_COUNT as usize,
                })
                .await;
            tokio::time::sleep(Duration::from_millis(PARA_KEEPALIVE_GAP_MS)).await;
        }

        let wf_key = format!("para-active-{remote_vip}");
        let phase_start = std::time::Instant::now();
        let _ = self
            .cmd_tx
            .send(EngineCmd::StartPunchWorkflow {
                key: wf_key.clone(),
                bases: remote_candidates.to_vec(),
                log_stages: true,
            })
            .await;
        let ok = self
            .wait_for_parasitic_punch_ready(
                remote_vip,
                remote_candidates,
                phase_start,
                std::time::Instant::now() + Duration::from_secs(PARA_PUNCH_WORKFLOW_DEADLINE_SECS),
                min_wall_ms,
            )
            .await;
        let _ = self
            .cmd_tx
            .send(EngineCmd::StopPunchWorkflow { key: wf_key })
            .await;
        ok
    }

    async fn wait_for_parasitic_punch_ready(
        &self,
        remote_vip: &str,
        peer_candidates: &[SocketAddr],
        phase_start: std::time::Instant,
        deadline: std::time::Instant,
        min_wall_ms: u64,
    ) -> bool {
        wait_for_parasitic_punch_ready(
            &self.routing,
            remote_vip,
            peer_candidates,
            phase_start,
            deadline,
            min_wall_ms,
            None,
        )
        .await
    }

    pub async fn parasitic_auto_reconnect(&mut self) -> Result<ReconnectOutcome> {
        let snap = self.config.snapshot();
        if !snap.parasitic_enabled
            || snap.parasitic_peer_vip.is_empty()
            || snap.crypto_key.is_empty()
            || snap.role != "peer"
        {
            drop(snap);
            self.ensure_parasitic_passive_listener().await?;
            return Ok(ReconnectOutcome::Skipped);
        }
        self.stop_parasitic_passive_listener();
        let listen_port = snap.listen_port.max(7878);
        let local_node_id = snap.node_id.clone();
        let local_vip = snap.virtual_ip.clone();
        let role_owner = snap.role == "owner";
        let peer_signal_port = if snap.parasitic_peer_port == 0 {
            listen_port
        } else {
            snap.parasitic_peer_port
        };
        let peer_target = parse_vip_signal_target(&snap.parasitic_peer_vip, peer_signal_port)?.1;
        let key_hex = snap.crypto_key.clone();
        let use_public = snap.parasitic_use_public;
        drop(snap);

        crate::cli_println_live!(
            "{}",
            term_style::fmt_para_line(format_args!(
                " Auto-reconnect: signaling and hole punch toward {peer_target}…"
            ))
        );

        let key_arr = parse_key_hex_32(&key_hex)?;
        let (key_tx, key_rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCmd::SetCryptoKey(Key(key_arr), Some(key_tx)))
            .await?;
        let _ = tokio::time::timeout(Duration::from_secs(1), key_rx).await;
        let (id_tx, id_rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCmd::SetIdentity {
                is_owner: role_owner,
                my_vip: local_vip.clone(),
                my_node_id: local_node_id.clone(),
                subnet_prefix: self.config.snapshot().subnet_prefix.clamp(8, 30),
                reply: Some(id_tx),
            })
            .await?;
        let _ = tokio::time::timeout(Duration::from_secs(1), id_rx).await;

        let local_ip = get_local_ip();
        let local_public = if use_public {
            self.upnp_cleanup_if_any().await;
            if let Ok(Some(m)) = tokio::time::timeout(
                Duration::from_secs(4),
                upnp::discover_and_add_port(&local_ip, listen_port, "MintegerP2P-Parasitic-Auto"),
            )
            .await
            {
                self.upnp_set_mapping(m);
            }
            let Some(stun_ep) = self
                .query_public_endpoint_from_engine_force(Duration::from_secs(3))
                .await
            else {
                crate::cli_println!(
                    "{}",
                    term_style::fmt_para_line(format_args!(
                        " Auto reconnect skipped: STUN unavailable."
                    ))
                );
                self.ensure_parasitic_passive_listener().await?;
                return Ok(ReconnectOutcome::Failed);
            };
            make_socket_addr(&stun_ep.ip, stun_ep.port)?
        } else {
            make_socket_addr(&local_ip, listen_port)?
        };
        let local_candidates = gather_local_para_candidates_inner(
            &self.config.snapshot(),
            &self.cmd_tx,
            Duration::from_secs(3),
            true,
            !use_public,
        )
        .await;
        let session_id = hex::encode(rand::random::<[u8; 8]>());
        let proposed_start_at_ms = now_epoch_ms() + PARA_START_BUFFER_MS;

        let (sig_tx, mut sig_rx) = mpsc::channel::<ParaSignal>(2048);
        let listener_id = register_para_listener(&self.cmd_tx, sig_tx, false).await;

        let mut remote_public: Option<SocketAddr> = None;
        let mut remote_vip: Option<String> = None;
        let mut remote_candidates: Vec<SocketAddr> = Vec::new();
        let mut ok_ready = false;
        let mut agreed_start_at_ms: Option<u64> = None;
        for _ in 0..PARA_SIGNAL_ATTEMPTS {
            let hello = json!({
                "node_id": local_node_id,
                "public_ip": local_public.ip().to_string(),
                "public_port": local_public.port(),
                "proposed_key_hex": key_hex,
                "proposed_vip_subnet": owner_vip(&local_vip),
                "ts_ms": now_epoch_ms(),
                "candidates": local_candidates.clone(),
                "start_at_ms": proposed_start_at_ms,
                "session_id": session_id,
            })
            .to_string()
            .into_bytes();
            let _ = self
                .cmd_tx
                .send(EngineCmd::ParaSendHello {
                    target_vip: peer_target,
                    payload: hello,
                })
                .await;
            let wait = tokio::time::timeout(para_signal_pause_duration(), sig_rx.recv()).await;
            if let Ok(Some(sig)) = wait {
                match sig {
                    ParaSignal::HelloReceived {
                        public_ip,
                        public_port,
                        candidates,
                        start_at_ms,
                        session_id: sid,
                        ..
                    } => {
                        if !sid.is_empty() && sid != session_id {
                            continue;
                        }
                        if let Ok(ep) = make_socket_addr(&public_ip, public_port) {
                            remote_public = Some(ep);
                        }
                        remote_candidates = candidates_to_socket_addrs(&candidates);
                        if !use_public {
                            remote_candidates = filter_private_socket_addrs(&remote_candidates);
                            remote_public = Some(peer_target);
                            if !remote_candidates.contains(&peer_target) {
                                remote_candidates.push(peer_target);
                            }
                        } else if let Some(ep) = remote_public {
                            if !remote_candidates.contains(&ep) {
                                remote_candidates.push(ep);
                            }
                        }
                        remote_vip =
                            Some(vip_from_owner_subnet(&owner_vip(&local_vip), !role_owner)?);
                        agreed_start_at_ms = Some(compute_agreed_start_at_ms(
                            start_at_ms,
                            now_epoch_ms() + PARA_START_BUFFER_MS,
                        ));
                        let reply = json!({
                            "node_id": local_node_id,
                            "public_ip": local_public.ip().to_string(),
                            "public_port": local_public.port(),
                            "assigned_vip": remote_vip.clone().unwrap_or_default(),
                            "network_id": self.config.snapshot().network_id.clone(),
                            "ts_ms": now_epoch_ms(),
                            "candidates": local_candidates.clone(),
                            "agreed_start_at_ms": agreed_start_at_ms.unwrap_or(proposed_start_at_ms),
                            "session_id": session_id,
                            "responder_vip": local_vip.clone(),
                            "responder_is_owner": role_owner,
                        })
                        .to_string()
                        .into_bytes();
                        let _ = self
                            .cmd_tx
                            .send(EngineCmd::ParaSendReply {
                                target_vip: peer_target,
                                payload: reply,
                            })
                            .await;
                    }
                    ParaSignal::ReplyReceived {
                        public_ip,
                        public_port,
                        assigned_vip,
                        candidates,
                        agreed_start_at_ms: peer_start,
                        session_id: sid,
                        ..
                    } => {
                        if !sid.is_empty() && sid != session_id {
                            continue;
                        }
                        if assigned_vip.is_empty() {
                            crate::cli_eprintln!(
                                "{}",
                                term_style::fmt_para_line_stderr(format_args!(
                                    " Auto-reconnect rejected by owner (pool full or error reply)."
                                ))
                            );
                            break;
                        }
                        if let Ok(ep) = make_socket_addr(&public_ip, public_port) {
                            remote_public = Some(ep);
                        }
                        remote_candidates = candidates_to_socket_addrs(&candidates);
                        if !use_public {
                            remote_candidates = filter_private_socket_addrs(&remote_candidates);
                            remote_public = Some(peer_target);
                            if !remote_candidates.contains(&peer_target) {
                                remote_candidates.push(peer_target);
                            }
                        } else if let Some(ep) = remote_public {
                            if !remote_candidates.contains(&ep) {
                                remote_candidates.push(ep);
                            }
                        }
                        agreed_start_at_ms = Some(compute_agreed_start_at_ms(
                            peer_start,
                            now_epoch_ms() + PARA_START_BUFFER_MS,
                        ));
                        remote_vip =
                            Some(vip_from_owner_subnet(&owner_vip(&local_vip), !role_owner)?);
                        let _ = send_para_ok_redundant(
                            &self.cmd_tx,
                            peer_target,
                            &local_node_id,
                            &session_id,
                        )
                        .await;
                        ok_ready = true;
                    }
                    ParaSignal::OkReceived {
                        session_id: sid, ..
                    } => {
                        if !sid.is_empty() && sid != session_id {
                            continue;
                        }
                        ok_ready = true;
                    }
                    ParaSignal::PunchAckReceived { .. } => {}
                }
            }
            if remote_public.is_some() && ok_ready {
                break;
            }
        }

        if let (Some(peer_public_ep), Some(rv)) = (remote_public, remote_vip) {
            if !role_owner {
                let _ = self
                    .cmd_tx
                    .send(EngineCmd::SetOwnerEndpoint(peer_public_ep, None))
                    .await;
            }
            wait_until_para_start(agreed_start_at_ms.unwrap_or(proposed_start_at_ms)).await;
            if remote_candidates.is_empty() {
                remote_candidates.push(peer_public_ep);
            }
            let mut bound_targets = HashSet::new();
            for candidate in &remote_candidates {
                if bound_targets.insert(*candidate) {
                    let _ = self
                        .cmd_tx
                        .send(EngineCmd::BindPeerKey {
                            peer: *candidate,
                            key: Key(key_arr),
                        })
                        .await;
                }
            }
            self.apply_parasitic_identity(
                role_owner,
                &local_vip,
                &local_node_id,
                key_arr,
                peer_public_ep,
            )
            .await?;
            if self
                .run_parasitic_punch(&remote_candidates, &rv, PARA_PEER_PUNCH_MIN_WALL_MS)
                .await
            {
                if !role_owner {
                    let ack_target = { self.routing.read().lookup(&rv).unwrap_or(peer_public_ep) };
                    if ack_target != peer_public_ep {
                        let _ = self
                            .cmd_tx
                            .send(EngineCmd::SetOwnerEndpoint(ack_target, None))
                            .await;
                        let _ = self
                            .cmd_tx
                            .send(EngineCmd::BindPeerKey {
                                peer: ack_target,
                                key: Key(key_arr),
                            })
                            .await;
                    }
                }
                #[cfg(windows)]
                {
                    if self.vni.is_none() {
                        let vip_ip = local_vip
                            .parse::<std::net::Ipv4Addr>()
                            .map_err(|_| anyhow!("invalid parasitic vip: {local_vip}"))?;
                        let snap_now = self.config.snapshot();
                        let ring = effective_wintun_ring_bytes(snap_now.wintun_ring_bytes);
                        let ipv4_metric = effective_wintun_ipv4_interface_metric(
                            snap_now.wintun_ipv4_interface_metric,
                        );
                        let para_prefix = snap_now.subnet_prefix.clamp(8, 30);
                        let mtu_to_apply = snap_now.adapter_mtu;
                        let adapter = match self
                            .wintun_create_with_timeout(
                                vip_ip,
                                para_prefix,
                                ring,
                                ipv4_metric,
                                mtu_to_apply,
                            )
                            .await
                        {
                            Ok(a) => a,
                            Err(e) => {
                                crate::cli_println!(
                                    "{}",
                                    term_style::fmt_info_line(format_args!(" {e}"))
                                );
                                unregister_para_listener(&self.cmd_tx, listener_id).await;
                                self.ensure_parasitic_passive_listener().await?;
                                return Ok(ReconnectOutcome::Failed);
                            }
                        };
                        self.wire_adapter(adapter.clone());
                        self.vni = Some(adapter);
                        crate::cli_println!(
                            "{}",
                            term_style::fmt_info_line(format_args!(
                                " Wintun adapter ready for {local_vip}/{para_prefix}"
                            ))
                        );
                    }
                }
                let ack_targets = {
                    let rt = self.routing.read();
                    collect_para_punch_ack_targets(
                        &rt,
                        &rv,
                        &remote_candidates,
                        &[peer_public_ep, peer_target],
                    )
                };
                let _ = send_para_punch_ack_redundant(
                    &self.cmd_tx,
                    &ack_targets,
                    &local_node_id,
                    &session_id,
                )
                .await;
                if self.headless {
                    // Home block emitted in daemon_bootstrap_finalize.
                } else {
                    self.emit_post_para_reconnect_home(true).await?;
                }
                unregister_para_listener(&self.cmd_tx, listener_id).await;
                self.ensure_parasitic_passive_listener().await?;
                return Ok(ReconnectOutcome::Connected);
            } else {
                let hint = if use_public {
                    " Auto-reconnect failed. Use punch, or run remove and choose [2] Join → Parasitic from the menu."
                } else {
                    " Auto-reconnect failed (LAN). Owner IP may have changed — run remove, then Join → Parasitic → LAN."
                };
                crate::cli_println_live!("{}", term_style::fmt_para_line(format_args!("{hint}")));
            }
        } else {
            let hint = if use_public {
                " Auto-reconnect timeout."
            } else {
                " Auto-reconnect timeout (LAN). Re-run Join → Parasitic → LAN if the owner DHCP address changed."
            };
            crate::cli_println_live!("{}", term_style::fmt_para_line(format_args!("{hint}")));
        }
        unregister_para_listener(&self.cmd_tx, listener_id).await;
        self.ensure_parasitic_passive_listener().await?;
        Ok(if remote_public.is_some() {
            ReconnectOutcome::Failed
        } else {
            ReconnectOutcome::TimedOut
        })
    }
    fn handle_list(&self) {
        let s = self.config.snapshot();
        crate::cli_println!();
        crate::cli_println!("     [status]");
        crate::cli_println!("[■■■■]======[■■■■]");
        crate::cli_println!("  │|  Server Name : {}", s.server_name);
        crate::cli_println!("  │|  Network ID  : {}", s.network_id);
        crate::cli_println!("  │|  Role        : {}", s.role);
        crate::cli_println!("  │|  Virtual IP  : {}", s.virtual_ip);
        crate::cli_println!("  │|  Node ID     : {}", s.node_id);
        crate::cli_println!("  │|  Listen Port : {}", s.listen_port);
        crate::cli_println!("  │|  Peers       : {}/{}", s.peers.len(), MAX_PEERS);
        if !s.public_invite_code.is_empty() {
            crate::cli_println!("  │|> Invite ID <-  {}", s.public_invite_code);
        }

        let routes = self.routing.read().snapshot();
        if !routes.is_empty() {
            crate::cli_println!("  ├── Routing Table ({} entries)", routes.len());
            for (vip, entry) in &routes {
                let rtt = if entry.last_rtt_ms < 0 {
                    "  --".to_string()
                } else {
                    format!("{:4}ms", entry.last_rtt_ms)
                };
                crate::cli_println!(
                    "  │  {:<15}  {:21}  RTT:{rtt}  Q:{:3}  {:?}",
                    vip,
                    entry.endpoint,
                    entry.quality_score,
                    entry.state,
                );
            }
        }

        for (idx, p) in s.peers.iter().enumerate() {
            crate::cli_println!("  [{:>2}] {:<15} {:<21}", idx + 1, p.virtual_ip, p.real_ip,);
        }
    }

    /// All performance fields persisted in the network config file (`reset_performance_fields` scope).
    fn print_persisted_performance_config(&self) {
        let s = self.config.snapshot();
        crate::cli_println!("  --- netsh / adapter ---");
        Self::print_netsh_saved_summary(s.as_ref());
        {
            let m = effective_wintun_ipv4_interface_metric(s.wintun_ipv4_interface_metric);
            if m == 0 {
                crate::cli_println!("  saved_wintun_ipv4_metric: off (Windows default routing)");
            } else {
                crate::cli_println!("  saved_wintun_ipv4_metric: {m} (lower = higher priority)");
            }
        }
        crate::cli_println!("  --- buffers ---");
        crate::cli_println!(
            "  saved_udp_sndbuf       : {}",
            effective_udp_sndbuf(s.udp_sndbuf)
        );
        crate::cli_println!(
            "  saved_udp_rcvbuf       : {}",
            effective_udp_rcvbuf(s.udp_rcvbuf)
        );
        crate::cli_println!(
            "  saved_wintun_ring      : {}",
            effective_wintun_ring_bytes(s.wintun_ring_bytes)
        );
        crate::cli_println!("  --- pacing ---");
        let eff_tick = pace_def::effective_pace_tick_us(s.pace_tick_us);
        let eff_spin = pace_clock::spin_window_from_config(s.as_ref(), eff_tick);
        crate::cli_println!("  saved_pace_tick_us     : {}", eff_tick);
        crate::cli_println!(
            "  saved_pace_spin_window_us: {} ({})",
            eff_spin,
            pace_spin_style_hint(eff_tick, eff_spin)
        );
        crate::cli_println!(
            "  saved_pace_target_pps  : {}",
            pace_def::effective_pace_target_pps(s.pace_target_pps)
        );
        crate::cli_println!("  saved_pace_rate_mode   : {}", s.pace_rate_mode);
        crate::cli_println!(
            "  saved_pace_target_bps  : {}",
            pace_def::effective_pace_target_bps(s.pace_target_bps, s.pace_target_pps)
        );
        crate::cli_println!(
            "  saved_base_max_burst   : {} pkt/tick",
            pace_def::effective_base_max_burst(s.base_max_burst)
        );
        crate::cli_println!(
            "  saved_pace_budget      : {} packets",
            pace_def::effective_pace_budget_cap_packets(s.pace_budget_cap_packets)
        );
        crate::cli_println!(
            "  saved_pace_queue       : {} packets",
            pace_def::effective_pace_max_queue_packets(s.pace_max_queue_packets)
        );
        crate::cli_println!(
            "  saved_pace_clock_mode  : {}",
            if s.pace_clock_mode.trim().is_empty() {
                "(default)".to_string()
            } else {
                s.pace_clock_mode.clone()
            }
        );
        crate::cli_println!("  --- TUN queues ---");
        let tun_from = s.tun_from_adapter_queue_packets;
        if tun_from > 0 {
            crate::cli_println!("  saved_tun_from_adapter_queue : {tun_from} packets");
        } else {
            crate::cli_println!(
                "  saved_tun_from_adapter_queue : {DEFAULT_TUN_FROM_ADAPTER_QUEUE} packets (default)"
            );
        }
        let tun_q = s.tun_inject_queue_packets;
        if tun_q > 0 {
            crate::cli_println!("  saved_tun_inject_queue : {tun_q} packets");
        } else {
            crate::cli_println!(
                "  saved_tun_inject_queue : {DEFAULT_TUN_INJECT_QUEUE} packets (default)"
            );
        }
        crate::cli_println!("  --- pace-fab ---");
        crate::cli_println!("  saved_pace_fab_enabled : {}", s.pace_fab_enabled);
        crate::cli_println!(
            "  saved_pace_fab_fallback_tick_us: {}",
            s.pace_fab_fallback_tick_us
        );
        crate::cli_println!("  --- pace (APD) ---");
        crate::cli_println!("  saved_apd_enabled      : {}", s.apd_enabled);
        crate::cli_println!("  saved_apd_high_wm      : {:.2}", s.apd_high_watermark);
        crate::cli_println!("  saved_apd_low_wm       : {:.2}", s.apd_low_watermark);
        crate::cli_println!("  saved_ramp_max_burst   : {} pkt/tick", s.ramp_max_burst);
        crate::cli_println!("  saved_drain_max_burst  : {} pkt/tick", s.drain_max_burst);
        crate::cli_println!("  saved_apd_spin_budget  : {} ms", s.apd_spinloop_budget_ms);
        crate::cli_println!(
            "  saved_apd_drain_tick   : {} us (0 = base tick)",
            s.apd_drain_tick_us
        );
        crate::cli_println!("  saved_apd_confirm      : {} ticks", s.apd_confirm_ticks);
        crate::cli_println!("  saved_apd_cooldown     : {} ms", s.apd_cooldown_ms);
        crate::cli_println!("  saved_apd_freeze_drr   : {}", s.apd_drain_freeze_drr);
        crate::cli_println!(
            "  saved_ctrl_reserved_b/tick: {} bytes",
            pace_def::effective_reserved_bytes_per_tick(s.min_control_reserved_bytes_per_tick)
        );
        crate::cli_println!(
            "  saved_rtx_reserved_b/tick : {} bytes",
            pace_def::effective_reserved_bytes_per_tick(s.min_retransmit_reserved_bytes_per_tick)
        );
        crate::cli_println!("  saved_apd_sojourn      : {}", s.apd_sojourn_enabled);
        crate::cli_println!("  saved_apd_max_sojourn  : {} ms", s.apd_max_sojourn_ms);
        crate::cli_println!("  saved_apd_target_sojourn: {} ms", s.apd_target_sojourn_ms);
        crate::cli_println!(
            "  saved_apd_require_cc_headroom: {}",
            s.apd_require_cc_headroom
        );
        crate::cli_println!("  saved_shed_enabled     : {}", s.shed_enabled);
        crate::cli_println!("  saved_shed_max_sojourn : {} ms", s.shed_max_sojourn_ms);
        crate::cli_println!("  saved_shed_min_fill    : {:.2}", s.shed_min_fill);
        crate::cli_println!("  saved_shed_max_per_tick: {}", s.shed_max_per_tick);
        crate::cli_println!("  --- runtime toggles (saved) ---");
        crate::cli_println!("  saved_drr_enabled      : {}", s.drr_enabled);
        crate::cli_println!("  saved_drr_small_prio   : {}", s.drr_small_packet_priority);
        crate::cli_println!(
            "  saved_drr_small_thr_b  : {}",
            pace_def::effective_drr_small_packet_threshold_bytes(
                s.drr_small_packet_threshold_bytes
            )
        );
        crate::cli_println!("  saved_drr_rtt_aware    : {}", s.drr_rtt_aware);
        crate::cli_println!(
            "  saved_drr_rtt_scale_min: {:.2}",
            pace_def::effective_drr_rtt_scale_min(s.drr_rtt_scale_min)
        );
        crate::cli_println!(
            "  saved_drr_rtt_scale_max: {:.2}",
            pace_def::effective_drr_rtt_scale_max(s.drr_rtt_scale_max)
        );
        crate::cli_println!("  saved_fec_enabled      : {}", s.fec_enabled);
        if s.fec_force_data_shards > 0 && s.fec_force_parity_shards > 0 {
            crate::cli_println!(
                "  saved_fec_ratio        : forced data={} parity={}",
                s.fec_force_data_shards,
                s.fec_force_parity_shards
            );
        } else {
            crate::cli_println!("  saved_fec_ratio        : adaptive");
        }
        crate::cli_println!("  saved_rawperf_enabled  : {}", s.rawperf_enabled);
        crate::cli_println!(
            "  saved_retransmit_bypass_pps: {:.1}",
            effective_retransmit_bypass_pps(s.retransmit_bypass_pps)
        );
        crate::cli_println!("  saved_low_latency_timer: {}", s.low_latency_timer_enabled);
        crate::cli_println!("  --- process ---");
        let level = process_priority::normalize_process_priority_level(s.process_priority_level);
        crate::cli_println!(
            "  saved_process_priority : {} ({})",
            level,
            process_priority::prio_level_label(level)
        );
        let spec = s.cpu_affinity.trim();
        if spec.is_empty() {
            crate::cli_println!("  saved_cpu_affinity     : default (exclude logical CPUs 0,1)");
        } else {
            crate::cli_println!("  saved_cpu_affinity     : \"{spec}\"");
        }
        crate::cli_println!("  --- advanced ---");
        Self::print_advanced_block(&s.advanced);
    }

    fn print_advanced_block(a: &crate::advanced_tuning::AdvancedTuning) {
        crate::cli_println!("  failover: d2r_quality_min={} d2r_loss_max={:.3} d2r_jitter_max={:.1} r2d_quality_min={} r2d_success_min={} hold_down_secs={}",
            a.failover.d2r_quality_min, a.failover.d2r_loss_max, a.failover.d2r_jitter_max, a.failover.r2d_quality_min, a.failover.r2d_success_min, a.failover.hold_down_secs);
        crate::cli_println!("  timers: keepalive={}s msyn={}s pmtud_tick={}ms pmtud_raise={}s ping_watchdog={}ms stale_tick={}s stale_mark={}s stale_evict={}s",
            a.timers.keepalive_secs, a.timers.msyn_secs, a.timers.pmtud_tick_ms, a.timers.pmtud_raise_secs, a.timers.ping_watchdog_ms, a.timers.stale_tick_secs, a.timers.stale_mark_secs, a.timers.stale_evict_secs);
        crate::cli_println!(
            "  reliable: rto_min={}ms rto_max={}ms max_pending={} retries_left={}",
            a.reliable.rto_min_ms,
            a.reliable.rto_max_ms,
            a.reliable.max_pending,
            a.reliable.retries_left
        );
        crate::cli_println!("  fec: shard_payload_size={} flush={}ms flush_aggressive={}ms adaptive_off_below={:.3} adaptive_on_above={:.3} fec_max_total_shards={}",
            a.fec.shard_payload_size, a.fec.flush_ms, a.fec.flush_aggressive_ms, a.fec.adaptive_off_below, a.fec.adaptive_on_above, a.fec.fec_max_total_shards);
        crate::cli_println!(
            "  pmtud: timeout={}ms confirm={} epsilon={} raise_step={} max_probes={} max_peers={} stable_downgrade_batches={}",
            a.pmtud.probe_timeout_ms,
            a.pmtud.confirm_count,
            a.pmtud.resolve_epsilon,
            a.pmtud.raise_step,
            a.pmtud.max_probes_per_search,
            a.pmtud.max_concurrent_peers,
            a.pmtud.stable_downgrade_batches
        );
        crate::cli_println!(
            "  congestion: congestion_enabled={} gain={:.2} hol_escape_ms={} initial_rate_bps={:.0} add_inc_bps={:.0} min_dec={:.2} rate_smooth={:.2} min_rate_bps={:.0} max_rate_bps={:.0} loss_md={:.2} burst_cap_bytes={} delivery_window_ms={} delivery_ewma_a={:.2} delivery_anchor={:.2} delivery_decouple={:.2} rtt_base_tracking={} loss_classifier={} target_q_delay_ms={} loss_thr={:.2} base_rtt_window_s={} stale_windows={} owd_jump_ms={} probe_interval_ms={} fec_recovery_recency_ms={}",
            a.congestion.enabled,
            a.congestion.gain,
            a.congestion.hol_escape_ms,
            a.congestion.initial_rate_bps,
            a.congestion.additive_increase_bps,
            a.congestion.min_decrease_factor,
            a.congestion.rate_smoothing_alpha,
            a.congestion.min_rate_bps,
            a.congestion.max_rate_bps,
            a.congestion.loss_multiplicative_decrease,
            a.congestion.burst_cap_bytes,
            a.congestion.delivery_rate_window_ms,
            a.congestion.delivery_rate_ewma_alpha,
            a.congestion.delivery_anchor_factor,
            a.congestion.delivery_decouple_ratio,
            a.congestion.rtt_base_tracking,
            a.congestion.loss_classifier_enabled,
            a.congestion.target_queue_delay_ms,
            a.congestion.congestion_loss_threshold,
            a.congestion.base_rtt_window_secs,
            a.congestion.base_rtt_stale_windows,
            a.congestion.owd_clock_jump_reject_ms,
            a.congestion.probe_interval_ms,
            a.congestion.fec_recovery_recency_ms
        );
        crate::cli_println!(
            "  routing_ewma: rtt={:.2}/{:.2} jitter={:.2}/{:.2} loss_decay={:.3} success_delta={:.3} fail_bump={:.3} bw={:.2}/{:.2} q_init={} loss_scale={:.0} loss_cap={:.0} jitter_div={:.1} jitter_cap={:.0} rtt_clamp_ms={}",
            a.routing_ewma.rtt_ewma_old,
            a.routing_ewma.rtt_ewma_new,
            a.routing_ewma.jitter_ewma_old,
            a.routing_ewma.jitter_ewma_new,
            a.routing_ewma.loss_ewma_decay,
            a.routing_ewma.loss_ewma_success_delta,
            a.routing_ewma.loss_ewma_fail_bump,
            a.routing_ewma.bw_ewma_old,
            a.routing_ewma.bw_ewma_new,
            a.routing_ewma.quality_initial,
            a.routing_ewma.quality_loss_scale,
            a.routing_ewma.quality_loss_penalty_cap,
            a.routing_ewma.quality_jitter_div,
            a.routing_ewma.quality_jitter_penalty_cap,
            a.routing_ewma.rtt_score_clamp_ms
        );
        crate::cli_println!(
            "  engine_limits: direct_retry/tick={} heal_pending={} stun_pending={} cc_probes/tick={} secondary_retry/tick={} stun_ttl={}s msyn_body_max={} msyn_shard_budget={} heal_cooldown_ms={} probe_miss_fail_threshold={}",
            a.engine_limits.max_direct_retry_per_tick,
            a.engine_limits.max_pending_heal_probes,
            a.engine_limits.max_pending_stun_queries,
            a.engine_limits.max_cc_probes_per_tick,
            a.engine_limits.max_secondary_retry_per_tick,
            a.engine_limits.stun_cache_ttl_secs,
            a.engine_limits.msyn_body_max,
            a.engine_limits.msyn_shard_budget_bytes,
            a.engine_limits.heal_cooldown_ms,
            a.engine_limits.probe_miss_fail_threshold
        );
        crate::cli_println!(
            "  hole_punch: s1_pkts={} s1_gap_ms={} s1_obs_ms={} s2_obs_s={} s2_pps={} s3_pps={} s3_max_s={} s3_gap_ms={} max_targets={} wide_w={}-{} rand_ports={}-{}",
            a.hole_punch.punch_stage1_packets,
            a.hole_punch.punch_stage1_gap_ms,
            a.hole_punch.punch_stage1_observe_ms,
            a.hole_punch.punch_stage2_observe_secs,
            a.hole_punch.punch_stage2_pps,
            a.hole_punch.punch_stage3_pps,
            a.hole_punch.punch_stage3_max_secs,
            a.hole_punch.punch_stage3_batch_gap_ms,
            a.hole_punch.punch_max_expanded_targets,
            a.hole_punch.punch_wide_min_width,
            a.hole_punch.punch_wide_max_width,
            a.hole_punch.punch_random_port_min,
            a.hole_punch.punch_random_port_max
        );
    }

    /// Handler for the top-level `config` command.
    ///
    /// - `config` / `config show` → print persisted performance fields.
    /// - `config reload`           → merge performance from disk and apply live.
    /// - `config reset`            → factory performance defaults and apply live.
    async fn handle_config(&mut self, args: &[&str]) -> Result<()> {
        let sub = args.first().copied().unwrap_or("show");
        match sub {
            "show" | "" => {
                crate::cli_println!("\n[Saved config (persisted performance)]");
                self.print_persisted_performance_config();
                Ok(())
            }
            "reload" => self.apply_config_reload().await,
            "reset" => self.apply_performance_defaults().await,
            other => Err(anyhow::anyhow!(
                "usage: config [show|reload|reset] (got `{other}`)"
            )),
        }
    }

    fn sync_runtime_flags_from_config_snapshot(&mut self) {
        let snap = self.config.snapshot();
        self.fec_enabled = snap.fec_enabled;
        self.fec_forced_ratio = fec_forced_ratio_from_network(snap.as_ref());
        self.rawperf_enabled = snap.rawperf_enabled;
        self.retransmit_bypass_pps = effective_retransmit_bypass_pps(snap.retransmit_bypass_pps);
        self.set_low_latency_timer(snap.low_latency_timer_enabled);
    }

    async fn apply_advanced_tuning_live(&mut self) -> Result<()> {
        let tuning = self.config.snapshot().advanced.clone();
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCmd::ApplyAdvancedTuning { tuning, reply: tx })
            .await
            .map_err(|_| anyhow::anyhow!("engine unavailable: cannot apply advanced tuning"))?;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), rx)
            .await
            .map_err(|_| anyhow::anyhow!("timeout applying advanced tuning"))?
            .map_err(|_| anyhow::anyhow!("engine dropped advanced tuning reply"))?;
        Ok(())
    }

    /// Apply saved performance settings to the live engine (after config snapshot is updated).
    ///
    /// `previous` is the pre-change snapshot used to skip disruptive adapter work (Wintun
    /// recreate / netsh / sockbuf) when those knobs did not change. Soft knobs (pacing,
    /// advanced tuning, CPU affinity, process priority) always apply.
    async fn apply_persisted_performance_live(
        &mut self,
        factory_defaults: bool,
        previous: Option<&crate::config::NetworkConfig>,
    ) -> Result<()> {
        self.rebuild_pacing_from_snapshot();
        self.sync_runtime_flags_from_config_snapshot();

        let snap = self.config.snapshot();
        let plan = adapter_live_apply_plan(previous, snap.as_ref());
        let apply = PaceClockApply::from_network_config(snap.as_ref());

        if self
            .cmd_tx
            .send(EngineCmd::SetPacingAndPaceClock {
                cfg: self.pacing,
                apply: apply.clone(),
            })
            .await
            .is_err()
        {
            crate::cli_println!(
                "{}",
                term_style::fmt_bang_line(format_args!(
                    " Engine unavailable: pacing not applied live (saved to config)."
                ))
            );
        }

        if self
            .cmd_tx
            .send(EngineCmd::SetPaceClock(apply))
            .await
            .is_err()
        {
            crate::cli_println!(
                "{}",
                term_style::fmt_bang_line(format_args!(
                    " Engine unavailable: pace-fab clock not applied live."
                ))
            );
        }

        if let Err(e) = self.apply_saved_runtime_perf_to_engine().await {
            crate::cli_println!(
                "{}",
                term_style::fmt_bang_line(format_args!(
                    " Engine unavailable: runtime perf knobs not fully applied: {e}"
                ))
            );
        }

        if let Err(e) = self.apply_advanced_tuning_live().await {
            crate::cli_println!(
                "{}",
                term_style::fmt_bang_line(format_args!(
                    " Engine unavailable: advanced tuning not applied live: {e}"
                ))
            );
        }

        if factory_defaults {
            if let Err(e) = process_priority::apply_mint_process_priority(2) {
                crate::cli_println!(
                    "{}",
                    term_style::fmt_bang_line(format_args!(
                        " Could not apply process priority: {e}"
                    ))
                );
            }
            let n_cpus = cpu_affinity::logical_cpu_count();
            if n_cpus <= 2 {
                crate::cli_println!(
                    "{}",
                    term_style::fmt_info_line(format_args!(
                        " CPU affinity: skipped ({n_cpus} logical CPU(s); need >2 for default exclude 0,1)"
                    ))
                );
            } else if let Err(e) = cpu_affinity::apply_cpu_affinity_from_spec("") {
                crate::cli_println!(
                    "{}",
                    term_style::fmt_bang_line(format_args!(" Could not apply CPU affinity: {e}"))
                );
            } else {
                crate::cli_println!(
                    "{}",
                    term_style::fmt_info_line(format_args!(
                        " CPU affinity: default (exclude logical CPUs 0,1)"
                    ))
                );
            }
        } else {
            let snap = self.config.snapshot();
            let level =
                process_priority::normalize_process_priority_level(snap.process_priority_level);
            if let Err(e) = process_priority::apply_mint_process_priority(level) {
                crate::cli_println!(
                    "{}",
                    term_style::fmt_bang_line(format_args!(
                        " Could not apply process priority: {e}"
                    ))
                );
            }
            let spec = snap.cpu_affinity.trim();
            if let Err(e) = cpu_affinity::apply_cpu_affinity_from_spec(spec) {
                crate::cli_println!(
                    "{}",
                    term_style::fmt_bang_line(format_args!(" Could not apply CPU affinity: {e}"))
                );
            }
        }

        if self.has_active_profile() {
            if plan.apply_netsh {
                if factory_defaults {
                    if let Err(e) = self.apply_netsh_settings(1340, Some(1)).await {
                        crate::cli_println!(
                            "{}",
                            term_style::fmt_bang_line(format_args!(
                                " Could not apply netsh defaults: {e}"
                            ))
                        );
                    }
                } else {
                    let snap = self.config.snapshot();
                    let mtu = effective_adapter_mtu(snap.adapter_mtu);
                    let raw_metric = snap.wintun_ipv4_interface_metric;
                    let ipv4_metric_arg = if raw_metric == 0 {
                        Some(0u32)
                    } else {
                        Some(effective_wintun_ipv4_interface_metric(raw_metric))
                    };
                    if let Err(e) = self.apply_netsh_settings(mtu, ipv4_metric_arg).await {
                        crate::cli_println!(
                            "{}",
                            term_style::fmt_bang_line(format_args!(
                                " Could not apply saved netsh settings: {e}"
                            ))
                        );
                    }
                }
            }
            if plan.apply_socket_buffers || plan.recreate_wintun_ring {
                if let Err(e) = self
                    .apply_performance_buffers_live(
                        plan.apply_socket_buffers,
                        plan.recreate_wintun_ring,
                    )
                    .await
                {
                    crate::cli_println!(
                        "{}",
                        term_style::fmt_bang_line(format_args!(
                            " Could not apply buffer settings: {e}"
                        ))
                    );
                }
            }
        }

        Ok(())
    }

    pub async fn apply_config_reload(&mut self) -> Result<()> {
        let before = (*self.config.snapshot()).clone();
        self.config
            .reload_performance_from_disk()
            .map_err(|e| anyhow::anyhow!("config reload failed: {e}"))?;
        let after = self.config.snapshot();
        let needs_reconnect_hint = restart_sensitive_perf_changed(&before, after.as_ref());
        self.apply_persisted_performance_live(false, Some(&before))
            .await?;
        if needs_reconnect_hint {
            crate::cli_println!(
                "{}",
                term_style::fmt_info_line(format_args!(
                    " TUN ring / inject queue changes may need reconnect or restart to take full effect."
                ))
            );
        }
        crate::cli_println!(
            "  ✓ Performance settings reloaded from NetInfo/config.toml (applied live)."
        );
        Ok(())
    }

    async fn query_runtime_snapshot(&self) -> Option<RuntimeSnapshot> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCmd::QueryRuntimeSnapshot { reply: tx })
            .await
            .ok()?;
        match tokio::time::timeout(Duration::from_millis(500), rx).await {
            Ok(Ok(snap)) => Some(snap),
            _ => None,
        }
    }

    fn runtime_rate_line(label: &str, mbps: Option<f64>, mib: f64) -> String {
        match mbps {
            Some(m) => format!("  {label:<26}: {m:.1} Mbps  (session {mib:.2} MiB)"),
            None => format!("  {label:<26}: —"),
        }
    }

    /// Pack engine-metric KV rows into two side-by-side columns (left = first half).
    fn runtime_push_metric_columns(lines: &mut Vec<String>, items: &[String]) {
        let mid = items.len().div_ceil(2);
        let col_w = RUNTIME_METRIC_COL_WIDTH;
        for i in 0..mid {
            let left = items[i].trim_start();
            match items.get(mid + i) {
                Some(right) => {
                    lines.push(format!("  {left:<col_w$}  {}", right.trim_start()));
                }
                None => lines.push(format!("  {left}")),
            }
        }
    }

    fn runtime_push_traffic_and_buffers(
        &self,
        lines: &mut Vec<String>,
        snap: Option<&RuntimeSnapshot>,
        rates: Option<&RuntimeRateView>,
    ) {
        lines.push("  --- VPN traffic (1s rate) ---".to_string());
        let r = rates.cloned().unwrap_or_default();
        lines.push(Self::runtime_rate_line(
            "tun egress (host→vpn)",
            r.tun_egress_mbps,
            r.tun_egress_mib,
        ));
        lines.push(Self::runtime_rate_line(
            "tun ingress (vpn→host)",
            r.tun_ingress_mbps,
            r.tun_ingress_mib,
        ));
        lines.push(Self::runtime_rate_line(
            "wire tx (data frames)",
            r.wire_tx_mbps,
            r.wire_tx_mib,
        ));
        lines.push(Self::runtime_rate_line(
            "wire rx (data plane)",
            r.wire_rx_mbps,
            r.wire_rx_mib,
        ));
        lines.push("  --- buffers / queues ---".to_string());
        if let Some(s) = snap {
            let p = &s.pacing;
            lines.push(format!(
                "  pacing data queue      : {} pkts (cap ~{} per peer)",
                p.data_queued,
                self.config.snapshot().pace_max_queue_packets.max(1)
            ));
            lines.push(format!(
                "  pacing ctrl / retx     : {} / {} pkts",
                p.control_queued, p.retransmit_queued
            ));
            lines.push(format!(
                "  pacing fill (aggregate): {:.1}%",
                p.fill_ratio * 100.0
            ));
            lines.push(format!(
                "  tun inject broadcast   : {} receiver(s), cap {} pkts",
                s.tun_inject_receivers, s.tun_inject_capacity
            ));
            lines.push(format!(
                "  udp sndbuf / rcvbuf    : {} / {} KiB (applied)",
                s.udp_sndbuf / 1024,
                s.udp_rcvbuf / 1024
            ));
            if s.pin_mtu {
                lines.push(format!(
                    "  pmtud                  : pinned path_mtu={} (adapter locked)",
                    s.path_mtu
                ));
            } else {
                lines.push(format!(
                    "  pmtud                  : active min_path={}",
                    s.path_mtu
                ));
            }
            if s.pmtud_peers.is_empty() {
                lines.push("  pmtud_peers             : (none)".to_string());
            } else {
                let p0 = &s.pmtud_peers[0];
                lines.push(format!(
                    "  pmtud_peers             : {} {} lg={} st={} ({} peer(s))",
                    p0.endpoint,
                    p0.phase,
                    p0.last_good,
                    p0.stable,
                    s.pmtud_peers.len()
                ));
            }
        } else {
            lines.push("  pacing data queue      : —".to_string());
            lines.push("  pacing ctrl / retx     : —".to_string());
            lines.push("  pacing fill (aggregate): —".to_string());
            lines.push("  tun inject broadcast   : —".to_string());
            lines.push("  udp sndbuf / rcvbuf    : —".to_string());
            lines.push("  pmtud                  : —".to_string());
            lines.push("  pmtud_peers             : —".to_string());
        }
        let ring = effective_wintun_ring_bytes(self.config.snapshot().wintun_ring_bytes);
        lines.push(format!(
            "  wintun ring (configured): {} MiB",
            ring / (1024 * 1024)
        ));
    }

    /// Fixed line count for in-place terminal refresh (`handle_runtime_live`).
    fn runtime_display_lines(
        &self,
        snap: Option<&RuntimeSnapshot>,
        rates: Option<&RuntimeRateView>,
    ) -> Vec<String> {
        use std::sync::atomic::Ordering;
        use std::time::Instant;

        let mut lines = Vec::with_capacity(RUNTIME_DISPLAY_LINE_COUNT);
        lines.push("  --- runtime (refresh 1s) ---".to_string());
        let relay_gauge = self.routing.read().count_under_relay_path(Instant::now());
        lines.push(format!(
            "  relay_path_routes      : {} (snapshot: prefer-relay / hold-down)",
            relay_gauge
        ));
        let fec_mode = self
            .fec_forced_ratio
            .map(|(d, p)| format!("forced {d}:{p}"))
            .unwrap_or_else(|| "adaptive".to_string());
        lines.push(format!(
            "  drr_enabled(runtime)   : {}",
            self.pacing.drr_enabled
        ));
        lines.push(format!("  fec_enabled(runtime)   : {}", self.fec_enabled));
        lines.push(format!("  fec_mode(runtime)      : {}", fec_mode));
        lines.push(format!(
            "  rawperf_enabled        : {}",
            self.rawperf_enabled
        ));
        lines.push(format!(
            "  retransmit_bypass_pps  : {:.1}",
            self.retransmit_bypass_pps
        ));
        lines.push(format!(
            "  low_latency_timer      : {}",
            if self.low_latency_timer { "on" } else { "off" }
        ));

        self.runtime_push_traffic_and_buffers(&mut lines, snap, rates);

        let na = |label: &str| format!("  {label:<22}: — (engine not running)");
        let mut metric_items: Vec<String> = Vec::with_capacity(61);
        match &self.engine_metrics {
            Some(m) => {
                metric_items.push(format!(
                    "  apd_drain_activations  : {}",
                    m.apd_drain_episodes.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  apd_packets_sent       : {}",
                    m.apd_packets_drained.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  apd_ramp_active_ticks  : {}",
                    m.apd_ramp_active_ticks.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  apd_ramp_pinned_ticks  : {}",
                    m.apd_ramp_pinned_ticks.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  apd_effective_burst    : {} pkt/tick",
                    m.apd_last_effective_burst.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  apd_drain_arm_fill     : {}",
                    m.apd_drain_arm_fill.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  apd_drain_arm_sojourn  : {}",
                    m.apd_drain_arm_sojourn.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  apd_max_sojourn_ms     : {}",
                    m.apd_last_max_sojourn_ms.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  apd_cc_headroom_suppressions: {}",
                    m.apd_cc_headroom_suppressions.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  cc_rate_limited        : {}",
                    m.cc_rate_limited_events.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  cc_rate_bps_min        : {}",
                    m.cc_rate_bps_min.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  cc_rate_bps_avg        : {}",
                    m.cc_rate_bps_avg.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  cc_rate_bps_max        : {}",
                    m.cc_rate_bps_max.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  cc_delivery_bps_min    : {}",
                    m.cc_delivery_bps_min.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  cc_delivery_bps_avg    : {}",
                    m.cc_delivery_bps_avg.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  cc_delivery_bps_max    : {}",
                    m.cc_delivery_bps_max.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  cc_increase_events     : {}",
                    m.cc_increase_events_total.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  cc_decrease_events     : {}",
                    m.cc_decrease_events_total.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  cc_loss_decrease_events: {}",
                    m.cc_loss_decrease_events_total.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  cc_loss_ignored_random : {}",
                    m.cc_loss_ignored_random_events_total
                        .load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  owd_samples (app/rej)  : {} / {}",
                    m.owd_samples_applied_total.load(Ordering::Relaxed),
                    m.owd_samples_rejected_total.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  cc_delivery_anchor_events: {}",
                    m.cc_delivery_anchor_events_total.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  drr_small_priority_pops: {}",
                    m.drr_small_priority_pops.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  drr_bulk_force_pops    : {}",
                    m.drr_bulk_force_pops.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  drr_rtt_scale_applied  : {}",
                    m.drr_rtt_scale_applied.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  fec_congestive_hold    : {}",
                    m.fec_congestive_hold_count.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  fec_classifier_allow   : {}",
                    m.fec_classifier_allow_count.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  fec_recovery_stepdown  : {}",
                    m.fec_recovery_stepdown_count.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  pacing_dropped_packets : {}",
                    m.pacing_dropped_packets.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  relay_fallback_events  : {}",
                    m.relay_fallback_events.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  auth_failures          : {}",
                    m.auth_failures.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  tun_inject_drops       : {}",
                    m.tun_inject_drops.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  fec_oversize_bypass    : {}",
                    m.fec_oversize_bypass_count.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  fec_mtu_bypass         : {}",
                    m.fec_mtu_bypass_count.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  pmtud_tx_oversize_drop : {}",
                    m.pmtud_tx_oversize_drop.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  pmtud_revalidate_hints : {}",
                    m.pmtud_revalidate_hints.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  pmtud_probes_sent      : {}",
                    m.pmtud_probes_sent.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  pmtud_probe_acks       : {}",
                    m.pmtud_probe_acks.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  pmtud_probe_timeouts   : {}",
                    m.pmtud_probe_timeouts.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  pmtud_revalidate_fails : {}",
                    m.pmtud_revalidate_fail_events.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  pmtud_recheck_recovered: {}",
                    m.pmtud_recheck_recovered_events.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  pmtud_softdown_events  : {}",
                    m.pmtud_softdown_events.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  pmtud_probe_anomaly    : {}",
                    m.pmtud_probe_anomaly_events.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  pmtud_late_ack_events  : {}",
                    m.pmtud_late_ack_events.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  pmtud_early_wake       : {}",
                    m.pmtud_early_wake_events.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  fec_drain_passthrough  : {}",
                    m.fec_drain_passthrough_count.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  fec_group_invalid      : {}",
                    m.fec_group_invalid_count.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  fec_flush_passthrough  : {}",
                    m.fec_flush_sparse_passthrough_count.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  fec_encoded_shards     : {}",
                    m.fec_encoded_shards_total.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  fec_recovered_packets  : {}",
                    m.fec_recovered_packets_total.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  fec_decode_fail        : {}",
                    m.fec_decode_fail_count.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  pacing_drop_data_fec   : {}",
                    m.pacing_drop_data_fec.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  pacing_drop_data_norm  : {}",
                    m.pacing_drop_data_normal.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  pacing_shed_sojourn    : {}",
                    m.pacing_shed_sojourn.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  pacing_cmd_chan_full   : {}",
                    m.pacing_cmd_channel_full.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  pacing_drop_control    : {}",
                    m.pacing_drop_control.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  pacing_ctrl_retx_evict : {}",
                    m.pacing_drop_control_retransmit.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  reli_unknown_inner_tag : {}",
                    m.reliable_unknown_inner_tag.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  rawperf_send_errors    : {}",
                    m.rawperf_send_error_count.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  retransmit_direct      : {}",
                    m.retransmit_direct_count.load(Ordering::Relaxed)
                ));
                metric_items.push(format!(
                    "  retransmit_fallback    : {}",
                    m.retransmit_fallback_count.load(Ordering::Relaxed)
                ));
            }
            None => {
                for label in [
                    "apd_drain_activations",
                    "apd_packets_sent",
                    "apd_ramp_active_ticks",
                    "apd_ramp_pinned_ticks",
                    "apd_effective_burst",
                    "apd_drain_arm_fill",
                    "apd_drain_arm_sojourn",
                    "apd_max_sojourn_ms",
                    "apd_cc_headroom_suppressions",
                    "cc_rate_limited",
                    "cc_rate_bps_min",
                    "cc_rate_bps_avg",
                    "cc_rate_bps_max",
                    "cc_delivery_bps_min",
                    "cc_delivery_bps_avg",
                    "cc_delivery_bps_max",
                    "cc_increase_events",
                    "cc_decrease_events",
                    "cc_loss_decrease_events",
                    "cc_loss_ignored_random",
                    "owd_samples (app/rej)",
                    "cc_delivery_anchor_events",
                    "drr_small_priority_pops",
                    "drr_bulk_force_pops",
                    "drr_rtt_scale_applied",
                    "fec_congestive_hold",
                    "fec_classifier_allow",
                    "fec_recovery_stepdown",
                    "pacing_dropped_packets",
                    "relay_fallback_events",
                    "auth_failures",
                    "tun_inject_drops",
                    "fec_oversize_bypass",
                    "fec_mtu_bypass",
                    "pmtud_tx_oversize_drop",
                    "pmtud_revalidate_hints",
                    "pmtud_probes_sent",
                    "pmtud_probe_acks",
                    "pmtud_probe_timeouts",
                    "pmtud_revalidate_fails",
                    "pmtud_recheck_recovered",
                    "pmtud_softdown_events",
                    "pmtud_probe_anomaly",
                    "pmtud_late_ack_events",
                    "pmtud_early_wake",
                    "fec_drain_passthrough",
                    "fec_group_invalid",
                    "fec_flush_passthrough",
                    "fec_encoded_shards",
                    "fec_recovered_packets",
                    "fec_decode_fail",
                    "pacing_drop_data_fec",
                    "pacing_drop_data_norm",
                    "pacing_shed_sojourn",
                    "pacing_cmd_chan_full",
                    "pacing_drop_control",
                    "pacing_ctrl_retx_evict",
                    "reli_unknown_inner_tag",
                    "rawperf_send_errors",
                    "retransmit_direct",
                    "retransmit_fallback",
                ] {
                    metric_items.push(na(label));
                }
            }
        }
        debug_assert_eq!(metric_items.len(), 61);
        Self::runtime_push_metric_columns(&mut lines, &metric_items);
        debug_assert_eq!(lines.len(), RUNTIME_DISPLAY_LINE_COUNT);
        lines
    }

    fn paint_runtime_frame(lines: &[String], footer: &str, first: bool) -> Result<()> {
        if first {
            for l in lines {
                crate::cli_println!("{l}");
            }
            crate::cli_println!("{footer}");
        } else {
            let n = lines.len() + 1;
            crate::cli_print!("\x1B[{n}A");
            for l in lines {
                crate::cli_print!("\x1B[2K\r{l}\n");
            }
            crate::cli_print!("\x1B[2K\r{footer}\n");
        }
        io::stdout()
            .flush()
            .map_err(|e| anyhow!("stdout flush: {e}"))
    }

    pub async fn runtime_snapshot_display_lines(&self) -> Vec<String> {
        let snap = self.query_runtime_snapshot().await;
        let mut rate_tracker = RuntimeRateTracker::new();
        let rates = rate_tracker.sample(&self.runtime_trace);
        self.runtime_display_lines(snap.as_ref(), Some(&rates))
    }

    async fn handle_runtime_live(&self) -> Result<()> {
        if self.headless {
            crate::cli_println!(
                "{}",
                term_style::fmt_info_line(format_args!(" Use `runtime` from the CLI client."))
            );
            return Ok(());
        }
        const FOOTER: &str = "  Press Enter to stop…";

        enter_runtime_terminal()?;
        let _view_session = RuntimeViewSession::enter(self.cmd_tx.clone()).await;
        self.reapply_timer_metrics_after_view_begin();
        let mut rate_tracker = RuntimeRateTracker::new();

        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let snap = self.query_runtime_snapshot().await;
        let lines = self.runtime_display_lines(snap.as_ref(), None);
        Self::paint_runtime_frame(&lines, FOOTER, true)?;

        loop {
            tokio::select! {
                _ = read_line_async() => break,
                _ = interval.tick() => {
                    let snap = self.query_runtime_snapshot().await;
                    let rates = rate_tracker.sample(&self.runtime_trace);
                    let lines = self.runtime_display_lines(snap.as_ref(), Some(&rates));
                    Self::paint_runtime_frame(&lines, FOOTER, false)?;
                }
            }
        }

        leave_runtime_terminal()?;
        Ok(())
    }

    async fn apply_netsh_settings(&self, mtu: i32, ipv4_metric_arg: Option<u32>) -> Result<()> {
        let metric_for_apply = if let Some(m) = ipv4_metric_arg {
            let eff = effective_wintun_ipv4_interface_metric(m);
            self.config.update(|cfg| {
                cfg.adapter_mtu = mtu;
                cfg.wintun_ipv4_interface_metric = eff;
            });
            eff
        } else {
            self.config.update(|cfg| cfg.adapter_mtu = mtu);
            effective_wintun_ipv4_interface_metric(
                self.config.snapshot().wintun_ipv4_interface_metric,
            )
        };

        #[cfg(windows)]
        {
            if let Some(vni) = &self.vni {
                let vni_clone = vni.clone();
                let name = vni.name().to_string();
                let mtu_u = mtu as u16;
                let m_apply = metric_for_apply;

                let (mtu_res, metric_res) = tokio::task::spawn_blocking(move || {
                    let r_mtu = vni_clone.set_mtu(mtu_u);
                    let r_met = if m_apply > 0 {
                        vni_clone.set_ipv4_interface_metric(m_apply)
                    } else {
                        Ok(())
                    };
                    (r_mtu, r_met)
                })
                .await
                .map_err(|e| anyhow!("netsh apply task join failed: {e}"))?;

                if let Err(e) = mtu_res {
                    crate::cli_println!(
                        "{}",
                        term_style::fmt_bang_line(format_args!(
                            " Could not apply MTU via netsh: {e}"
                        ))
                    );
                } else {
                    crate::cli_println!("  ✓ MTU set to {mtu} on '{name}'.");
                }
                if metric_for_apply > 0 {
                    if let Err(e) = metric_res {
                        crate::cli_println!(
                            "{}",
                            term_style::fmt_bang_line(format_args!(
                                " Could not apply IPv4 interface metric via netsh: {e}"
                            ))
                        );
                    } else {
                        crate::cli_println!(
                            "  ✓ IPv4 interface metric set to {metric_for_apply} on '{name}'."
                        );
                    }
                }
            } else {
                crate::cli_println!(
                    "{}",
                    term_style::fmt_info_line(format_args!(
                        " Adapter not active; values saved and apply on next connect."
                    ))
                );
            }
        }
        #[cfg(not(windows))]
        {
            let _ = metric_for_apply;
        }

        crate::cli_println!(
            "{}",
            term_style::fmt_info_line(format_args!(" Saved to NetInfo/config.toml."))
        );
        Ok(())
    }

    async fn handle_stun(&mut self) -> Result<()> {
        let result = self
            .query_public_endpoint_from_engine(std::time::Duration::from_secs(5))
            .await;
        match result {
            Some(ep) => {
                crate::cli_println!("Public endpoint: {}:{}", ep.ip, ep.port);
                let snap = self.config.snapshot();
                if snap.role == "owner" && !snap.network_id.is_empty() {
                    if let Ok(key) = parse_key_hex_32(&snap.crypto_key) {
                        if let Ok(owner_ip) = ep.ip.parse::<Ipv4Addr>() {
                            let invite = encode_invite(&InvitePayload {
                                mode: 1,
                                owner_ip: owner_ip.octets(),
                                owner_port: ep.port,
                                key,
                                protocol: PROTO_UDP,
                            });
                            crate::cli_println!("  Public invite: {invite}");
                        }
                    }
                }
            }
            None => crate::cli_println!("No STUN response (check firewall/router UDP policy)"),
        }
        Ok(())
    }

    async fn query_public_endpoint_from_engine(
        &self,
        timeout: std::time::Duration,
    ) -> Option<stun::PublicEndpoint> {
        self.query_public_endpoint_from_engine_inner(timeout, false)
            .await
    }

    async fn query_public_endpoint_from_engine_force(
        &self,
        timeout: std::time::Duration,
    ) -> Option<stun::PublicEndpoint> {
        self.query_public_endpoint_from_engine_inner(timeout, true)
            .await
    }

    async fn query_public_endpoint_from_engine_inner(
        &self,
        timeout: std::time::Duration,
        force_refresh: bool,
    ) -> Option<stun::PublicEndpoint> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(EngineCmd::QueryPublicEndpoint {
                timeout,
                force_refresh,
                reply: reply_tx,
            })
            .await
            .is_err()
        {
            return None;
        }
        if let Ok(Some(ep)) = reply_rx.await {
            return Some(ep);
        }
        None
    }

    async fn handle_punch(&self, peer_target: Option<&str>, peer_port: Option<&str>) -> Result<()> {
        let ep = parse_punch_target_args(peer_target, peer_port)?;
        if !self.has_active_profile() {
            crate::cli_println!(
                "\n{}",
                term_style::fmt_bang_line(format_args!(
                    " Network engine is not active. Create or join a network first."
                ))
            );
            return Ok(());
        }
        self.sync_engine_from_saved_profile().await?;
        let target_ip = ep.ip();
        let target_port = ep.port();
        let _ = self
            .cmd_tx
            .send(EngineCmd::StartPunchWorkflow {
                key: "manual-user-punch".to_string(),
                bases: vec![ep],
                log_stages: true,
            })
            .await;
        crate::cli_println!(
            "{}",
            term_style::fmt_punch_line(format_args!(
                " Tiered punch workflow started toward {target_ip}:{target_port}."
            ))
        );
        Ok(())
    }

    async fn handle_ping(&self) -> Result<()> {
        #[derive(Clone)]
        struct PingTarget {
            label: String,
            ip: String,
            port: u16,
        }

        const ROUNDS: usize = 3;
        const TIMEOUT_MS: u64 = 1500;

        let mut targets: Vec<PingTarget> = Vec::new();
        let s = self.config.snapshot();
        let owner_vip = crate::routing::owner_vip(&s.virtual_ip);

        if s.role == "owner" {
            let routes = self.routing.read().snapshot();
            for (vip, entry) in routes {
                if vip == s.virtual_ip {
                    continue;
                }
                let label = vip.clone();
                targets.push(PingTarget {
                    label,
                    ip: entry.endpoint.ip().to_string(),
                    port: entry.endpoint.port(),
                });
            }
            if targets.is_empty() {
                crate::cli_println!(
                    "\n{}",
                    term_style::fmt_info_line(format_args!(" No peers connected."))
                );
                return Ok(());
            }
        } else {
            let routes = self.routing.read().snapshot();
            let owner_route_ep = routes
                .iter()
                .find(|(vip, _)| vip == &owner_vip)
                .map(|(_, e)| e.endpoint);
            if let Some(ep) = owner_route_ep {
                targets.push(PingTarget {
                    label: owner_vip.clone(),
                    ip: ep.ip().to_string(),
                    port: ep.port(),
                });
            } else if !s.owner_real_ip.is_empty() && s.owner_port != 0 {
                targets.push(PingTarget {
                    label: owner_vip.clone(),
                    ip: s.owner_real_ip.clone(),
                    port: s.owner_port,
                });
            }
            for (vip, entry) in routes {
                if vip == s.virtual_ip || vip == owner_vip {
                    continue;
                }
                targets.push(PingTarget {
                    label: vip,
                    ip: entry.endpoint.ip().to_string(),
                    port: entry.endpoint.port(),
                });
            }
            if targets.is_empty() {
                crate::cli_println!(
                    "\n{}",
                    term_style::fmt_info_line(format_args!(" No targets to ping."))
                );
                return Ok(());
            }
        }

        let mut results = vec![[-1_i64; ROUNDS]; targets.len()];

        for r in 0..ROUNDS {
            let mut workers = tokio::task::JoinSet::new();
            for (i, t) in targets.iter().enumerate() {
                let cmd_tx = self.cmd_tx.clone();
                let ip = t.ip.clone();
                let port = t.port;
                workers.spawn(async move {
                    let rtt = cli_ping_peer_rtt(cmd_tx, &ip, port, TIMEOUT_MS).await;
                    (i, rtt)
                });
            }
            while let Some(joined) = workers.join_next().await {
                match joined {
                    Ok((i, rtt)) if i < results.len() => results[i][r] = rtt,
                    _ => {}
                }
            }
            if r + 1 < ROUNDS {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }

        const RTT_W: usize = 7;
        const STATUS_W: usize = 18;
        let peer_w = targets
            .iter()
            .map(|t| t.label.chars().count())
            .max()
            .unwrap_or(4)
            .max("VIP".chars().count())
            .clamp(12, 24);
        let fit_cell = |s: &str, width: usize| -> String {
            let mut out: String = s.chars().take(width).collect();
            if s.chars().count() > width && width > 1 {
                out = out.chars().take(width - 1).collect();
                out.push('…');
            }
            format!("{out:<width$}")
        };
        let ping_row = |a: &str, b: &str, c: &str, d: &str, e: &str| {
            format!(
                "  │ {:<peer_w$} │ {:<RTT_W$} │ {:<RTT_W$} │ {:<RTT_W$} │ {:<STATUS_W$}",
                a, b, c, d, e
            )
        };

        crate::cli_println!("{}", ping_row("VIP", "#1", "#2", "#3", "Status"));
        crate::cli_println!(
            "{}",
            ping_row(
                &"─".repeat(peer_w),
                &"─".repeat(RTT_W),
                &"─".repeat(RTT_W),
                &"─".repeat(RTT_W),
                &"─".repeat(STATUS_W),
            )
        );

        for (i, t) in targets.iter().enumerate() {
            let mut ok = 0_i32;
            let mut sum = 0_i64;
            for &rtt in &results[i] {
                if rtt >= 0 {
                    ok += 1;
                    sum += rtt;
                }
            }

            let fmt_rtt = |rtt: i64| -> String {
                if rtt < 0 {
                    fit_cell("T/O", RTT_W)
                } else {
                    fit_cell(&format!("{rtt}ms"), RTT_W)
                }
            };

            let status = if ok as usize == ROUNDS {
                format!("OK avg {}ms", sum / ok as i64)
            } else if ok == 0 {
                "Offline".to_string()
            } else {
                "Unstable".to_string()
            };

            crate::cli_println!(
                "{}",
                ping_row(
                    &fit_cell(&t.label, peer_w),
                    &fmt_rtt(results[i][0]),
                    &fmt_rtt(results[i][1]),
                    &fmt_rtt(results[i][2]),
                    &fit_cell(&status, STATUS_W),
                )
            );
        }
        Ok(())
    }

    async fn handle_kick(&self, arg: Option<&str>) -> Result<()> {
        if self.config.get_role() != "owner" {
            crate::cli_println!(
                "\n{}",
                term_style::fmt_bang_line(format_args!(" Only the owner can kick peers."))
            );
            return Ok(());
        }
        let Some(n_str) = arg else {
            return Err(anyhow!("usage: kick <name | N | ip:port>"));
        };
        let snap = self.config.snapshot();
        if let Ok(n) = n_str.parse::<usize>() {
            if n == 0 || n > snap.peers.len() {
                crate::cli_println!(
                    "{}",
                    term_style::fmt_bang_line(format_args!(
                        " Invalid peer number. Use 'list' to see peers."
                    ))
                );
            } else {
                let vip = snap.peers[n - 1].virtual_ip.clone();
                let ep = self.routing.read().lookup(&vip);
                if let Some(ep) = ep {
                    let _ = self.cmd_tx.send(EngineCmd::Kick(ep)).await;
                    crate::cli_println!("  Kicked peer #{n} ({vip})");
                } else {
                    crate::cli_println!(
                        "{}",
                        term_style::fmt_bang_line(format_args!(
                            " Peer #{n} ({vip}) not found in routing table."
                        ))
                    );
                }
            }
        } else if let Ok(ep) = n_str.parse::<std::net::SocketAddr>() {
            let _ = self.cmd_tx.send(EngineCmd::Kick(ep)).await;
            crate::cli_println!("  Kicked {ep}");
        } else {
            let peer = snap.peers.iter().find(|p| {
                p.name.eq_ignore_ascii_case(n_str)
                    || p.node_id.eq_ignore_ascii_case(n_str)
                    || p.virtual_ip == n_str
            });
            if let Some(p) = peer {
                let ep_opt = self.routing.read().lookup(&p.virtual_ip);
                if let Some(ep) = ep_opt {
                    let _ = self.cmd_tx.send(EngineCmd::Kick(ep)).await;
                    crate::cli_println!("  Kicked '{}' ({})", p.name, p.virtual_ip);
                } else if let Ok(ep) = p.real_ip.parse::<SocketAddr>() {
                    let _ = self.cmd_tx.send(EngineCmd::Kick(ep)).await;
                    crate::cli_println!("  Kicked '{}' ({})", p.name, p.virtual_ip);
                } else {
                    crate::cli_println!(
                        "{}",
                        term_style::fmt_bang_line(format_args!(
                            " Peer '{}' has no reachable endpoint.",
                            p.name
                        ))
                    );
                }
            } else {
                crate::cli_println!(
                    "{}",
                    term_style::fmt_bang_line(format_args!(
                        " Invalid argument. Use peer name, number or ip:port."
                    ))
                );
            }
        }
        Ok(())
    }

    async fn handle_remove(&mut self) -> Result<()> {
        self.stop_parasitic_passive_listener();
        let snap = self.config.snapshot();
        if !snap.virtual_ip.is_empty() {
            let leave = serde_json::json!({
                "event_id": format!("leave-{}-{}", snap.node_id, now_epoch_ms()),
                "type": "leave",
                "vip": snap.virtual_ip,
                "node_id": snap.node_id,
                "endpoint": "",
            });
            let _ = self.cmd_tx.try_send(EngineCmd::BroadcastMsmd(leave));
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        self.upnp_cleanup_if_any().await;
        #[cfg(windows)]
        {
            if let Some(ref adapter) = self.vni {
                *self.vni_slot.write() = None;
                adapter.close();
            }
            self.vni = None;
        }

        // Hard in-process wipe (routing/crypto/punch/decentralized) before disk clear.
        let (reset_tx, reset_rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(EngineCmd::ResetSession { reply: reset_tx })
            .await
            .is_ok()
        {
            let _ = tokio::time::timeout(Duration::from_secs(5), reset_rx).await;
        } else {
            let _ = self.cmd_tx.try_send(EngineCmd::StopDecentralized);
        }

        self.config.clear_and_delete()?;
        self.owner_vip_pool = None;
        {
            let mut rt = self.routing.write();
            *rt = RoutingTable::new();
        }
        if let Some(tx) = self.peer_cache_reset_tx.as_ref() {
            let (done_tx, done_rx) = oneshot::channel();
            if tx.send(done_tx).is_ok() {
                let _ = tokio::time::timeout(Duration::from_secs(2), done_rx).await;
            }
        }

        if self.headless {
            self.state = AppState::FirstRun;
            self.rebuild_pacing_from_snapshot();
            self.fec_enabled = true;
            self.fec_forced_ratio = None;
            self.rawperf_enabled = false;
            self.retransmit_bypass_pps = 1000.0;
            let _ = self.apply_saved_runtime_perf_to_engine().await;
            crate::cli_println!(
                "{}",
                term_style::fmt_info_line(format_args!(
                    " Session removed. Daemon is idle — choose [1], [2], or [3] Exit from the menu."
                ))
            );
            self.emit_first_run_menu_lines().await?;
            return Ok(());
        }

        crate::cli_println!("session cleared; restarting in 3s…");
        for s in (1..=3).rev() {
            crate::cli_println!("  {s}…");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let exe = env::current_exe().map_err(|e| anyhow!("current_exe: {e}"))?;
        let work_dir = netinfo::exe_dir()?;
        Command::new(exe)
            .args(env::args_os().skip(1))
            .current_dir(work_dir)
            .spawn()
            .map_err(|e| anyhow!("failed to spawn restart: {e}"))?;
        self.shutdown_engine_for_exit().await;
        Ok(())
    }

    pub async fn shutdown_engine_for_exit(&mut self) {
        let _ = self.cmd_tx.try_send(EngineCmd::Shutdown);
        #[cfg(windows)]
        {
            if let Some(ref adapter) = self.vni {
                crate::cli_println!(
                    "{}",
                    term_style::fmt_info_line(format_args!(" Closing Wintun adapter…"))
                );
                *self.vni_slot.write() = None;
                adapter.close();
            }
            self.vni = None;
        }
        self.state = AppState::Exiting;
    }

    pub async fn handle_exit(&mut self) {
        self.stop_parasitic_passive_listener();
        let snap = self.config.snapshot();
        if !snap.virtual_ip.is_empty() {
            let leave = serde_json::json!({
                "event_id": format!("leave-{}-{}", snap.node_id, now_epoch_ms()),
                "type": "leave",
                "vip": snap.virtual_ip,
                "node_id": snap.node_id,
                "endpoint": "",
            });
            let _ = self.cmd_tx.try_send(EngineCmd::BroadcastMsmd(leave));
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        self.upnp_cleanup_if_any().await;
        self.shutdown_engine_for_exit().await;
    }

    fn rebuild_pacing_from_snapshot(&mut self) {
        let snap = self.config.snapshot();
        self.pacing = pacing_config_from_network(snap.as_ref());
    }

    pub async fn apply_performance_defaults(&mut self) -> Result<()> {
        let before = (*self.config.snapshot()).clone();
        self.config.update(|c| c.reset_performance_fields());
        let needs_reconnect_hint =
            restart_sensitive_perf_changed(&before, self.config.snapshot().as_ref());
        self.apply_persisted_performance_live(true, Some(&before))
            .await?;
        if needs_reconnect_hint {
            crate::cli_println!(
                "{}",
                term_style::fmt_info_line(format_args!(
                    " TUN inject queue default saved; applies on next reconnect/restart."
                ))
            );
        }
        crate::cli_println!(
            "  ✓ Performance settings reset to factory defaults (saved to config)."
        );
        Ok(())
    }

    /// Apply UDP socket buffers and/or recreate Wintun for a new ring size.
    ///
    /// Wintun recreate briefly drops the adapter — only call with
    /// `recreate_wintun_ring = true` when the effective ring size changed.
    async fn apply_performance_buffers_live(
        &mut self,
        apply_socket_buffers: bool,
        recreate_wintun_ring: bool,
    ) -> Result<()> {
        let snap = self.config.snapshot();
        let ring = effective_wintun_ring_bytes(snap.wintun_ring_bytes);

        if apply_socket_buffers {
            let snd = effective_udp_sndbuf(snap.udp_sndbuf);
            let rcv = effective_udp_rcvbuf(snap.udp_rcvbuf);
            let (actual_snd, actual_rcv) = {
                let (tx, rx) = oneshot::channel();
                self.cmd_tx
                    .send(EngineCmd::SetSocketBuffers {
                        sndbuf: snd,
                        rcvbuf: rcv,
                        reply: tx,
                    })
                    .await
                    .map_err(|_| {
                        anyhow!("engine unavailable: cannot apply socket buffer immediately")
                    })?;
                match tokio::time::timeout(std::time::Duration::from_secs(2), rx).await {
                    Ok(Ok(v)) => v,
                    _ => {
                        return Err(anyhow!("timeout applying socket buffers to runtime engine"));
                    }
                }
            };
            self.config.update(|cfg| {
                cfg.udp_sndbuf = actual_snd;
                cfg.udp_rcvbuf = actual_rcv;
            });
        }

        #[cfg(windows)]
        if recreate_wintun_ring {
            if let Some(ref old_adapter) = self.vni {
                let snap = self.config.snapshot();
                let vip = snap.virtual_ip.clone();
                if let Ok(vip_ip) = vip.parse::<std::net::Ipv4Addr>() {
                    let adapter_name = old_adapter.name().to_string();
                    *self.vni_slot.write() = None;
                    old_adapter.close();
                    self.vni = None;

                    let mtu_to_apply = snap.adapter_mtu;
                    let ring_for_task = ring;
                    let ipv4_metric_for_task =
                        effective_wintun_ipv4_interface_metric(snap.wintun_ipv4_interface_metric);
                    let adapter_name_for_task = adapter_name.clone();
                    let wintun_prefix = snap.subnet_prefix.clamp(8, 30);
                    let new_adapter =
                        tokio::task::spawn_blocking(move || -> Result<Arc<WintunAdapter>> {
                            let adapter = Arc::new(
                                WintunAdapter::create(
                                    &adapter_name_for_task,
                                    vip_ip,
                                    wintun_prefix,
                                    ring_for_task,
                                    ipv4_metric_for_task,
                                )
                                .map_err(|e| {
                                    anyhow!("failed to apply Wintun ring immediately: {e}")
                                })?,
                            );
                            if (576..=1500).contains(&mtu_to_apply) {
                                let _ = adapter.set_mtu(mtu_to_apply as u16);
                            }
                            Ok(adapter)
                        })
                        .await
                        .map_err(|e| anyhow!("wintun create task join failed: {e}"))??;
                    self.wire_adapter(new_adapter.clone());
                    self.vni = Some(new_adapter);
                }
            }
        }

        #[cfg(not(windows))]
        {
            let _ = (recreate_wintun_ring, ring);
        }

        Ok(())
    }

    fn print_netsh_saved_summary(snap: &crate::config::NetworkConfig) {
        let mtu = snap.adapter_mtu;
        let raw_metric = snap.wintun_ipv4_interface_metric;
        let eff_metric = effective_wintun_ipv4_interface_metric(raw_metric);
        if (576..=1500).contains(&mtu) {
            crate::cli_println!("  Saved adapter_mtu: {mtu} (re-applied on connect)");
        } else {
            crate::cli_println!("  Saved adapter_mtu: (unset — 1340 used on adapter create)");
        }
        crate::cli_println!("  Saved pin_mtu: {}", snap.pin_mtu);
        if eff_metric == 0 {
            crate::cli_println!("  Saved wintun_ipv4_interface_metric: 0 (off)");
        } else {
            crate::cli_println!(
                "  Saved wintun_ipv4_interface_metric: {raw_metric} (effective {eff_metric})"
            );
        }
    }

    fn print_help(&self) {
        crate::cli_println!("\n#===--> Commands ===#");
        crate::cli_println!("   > [ list ]        ------- Routing table");
        crate::cli_println!("   > [ runtime ]        ------- Performance live view");
        crate::cli_println!("   > [ ping ]           --- Ping peers");
        crate::cli_println!("   > [ stun ]      ----------- Query public endpoint");
        crate::cli_println!("   > [ punch <ip:port> ] --- Manual NAT hole punch");
        crate::cli_println!(
            "   > [ autoclear-on|off ]  --- Clear screen each command (on default)"
        );
        crate::cli_println!(
            "   > [ config show|reload|reset ] --- Performance via NetInfo/config.toml"
        );
        crate::cli_println!("   > [ kick <name|N|ip:port> ] [Owner] Remove peer");
        crate::cli_println!("   > [ remove ] ----------- Clear session and config (destructive)");
        crate::cli_println!("   > [ stop ] --------------   Disconnect and quit");
        crate::cli_println!("---");
    }

    fn has_active_profile(&self) -> bool {
        crate::profile::has_active_profile(self.config.snapshot().as_ref())
    }

    async fn read_line(&self) -> Result<String> {
        if self.headless {
            return Err(anyhow!(
                "interactive input must be entered on the CLI client (not the daemon)"
            ));
        }
        read_line_async().await
    }

    fn upnp_set_mapping(&mut self, mapping: upnp::UPnPMapping) {
        self.stop_upnp_refresh_task();
        self.upnp_mapping = Some(mapping.clone());
        if let Some(mapping) = self.upnp_mapping.clone() {
            let stop = Arc::new(AtomicBool::new(false));
            let stop_flag = stop.clone();
            self.upnp_refresh_stop = Some(stop);
            self.upnp_refresh_task = Some(tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(8 * 60));
                loop {
                    ticker.tick().await;
                    if stop_flag.load(Ordering::Acquire) {
                        break;
                    }
                    let _ = upnp::refresh_port(&mapping).await;
                }
            }));
        }
    }

    async fn upnp_cleanup_if_any(&mut self) {
        self.stop_upnp_refresh_task();
        let Some(mapping) = self.upnp_mapping.take() else {
            return;
        };
        let port = mapping.ext_port;
        match tokio::time::timeout(Duration::from_secs(3), upnp::remove_port(&mapping)).await {
            Ok(_) => crate::cli_println!(
                "{}",
                term_style::fmt_nat_line(format_args!(" UPnP: released ext_port={port} on exit."))
            ),
            Err(_) => {
                crate::cli_println!(
                    "{}",
                    term_style::fmt_nat_line(format_args!(
                        " UPnP: cleanup timed out for ext_port={port} (router slow)."
                    ))
                );
            }
        }
    }

    fn stop_upnp_refresh_task(&mut self) {
        if let Some(stop) = self.upnp_refresh_stop.take() {
            stop.store(true, Ordering::Release);
        }
        if let Some(handle) = self.upnp_refresh_task.take() {
            handle.abort();
        }
    }
}

type StdinLineReader = Arc<Mutex<BufReader<tokio::io::Stdin>>>;

static STDIN_LINE_READER: OnceLock<StdinLineReader> = OnceLock::new();

fn stdin_line_reader() -> StdinLineReader {
    STDIN_LINE_READER
        .get_or_init(|| Arc::new(Mutex::new(BufReader::new(tokio::io::stdin()))))
        .clone()
}

async fn read_line_async() -> Result<String> {
    crate::cli_emit::set_stdin_read_active(true);
    let reader = stdin_line_reader();
    let mut guard = reader.lock().await;
    let mut line = String::new();
    let read_result = guard
        .read_line(&mut line)
        .await
        .map_err(|e| anyhow::anyhow!("stdin read error: {e}"));
    drop(guard);
    crate::cli_emit::set_stdin_read_active(false);
    crate::cli_emit::flush_deferred_live_status();
    read_result?;
    Ok(line.trim().to_string())
}

async fn query_stun_via_engine(
    cmd_tx: &mpsc::Sender<EngineCmd>,
    timeout: Duration,
) -> Option<stun::PublicEndpoint> {
    query_stun_via_engine_inner(cmd_tx, timeout, false).await
}

async fn query_stun_via_engine_force(
    cmd_tx: &mpsc::Sender<EngineCmd>,
    timeout: Duration,
) -> Option<stun::PublicEndpoint> {
    query_stun_via_engine_inner(cmd_tx, timeout, true).await
}

async fn query_stun_via_engine_inner(
    cmd_tx: &mpsc::Sender<EngineCmd>,
    timeout: Duration,
    force_refresh: bool,
) -> Option<stun::PublicEndpoint> {
    let (reply_tx, reply_rx) = oneshot::channel();
    if cmd_tx
        .send(EngineCmd::QueryPublicEndpoint {
            timeout,
            force_refresh,
            reply: reply_tx,
        })
        .await
        .is_err()
    {
        return None;
    }
    match reply_rx.await {
        Ok(Some(ep)) => Some(ep),
        _ => None,
    }
}

async fn gather_local_para_candidates(
    snap: &crate::config::NetworkConfig,
    cmd_tx: &mpsc::Sender<EngineCmd>,
    timeout: Duration,
) -> Vec<ParaCandidate> {
    gather_local_para_candidates_inner(snap, cmd_tx, timeout, false, false).await
}

async fn gather_local_para_candidates_force(
    snap: &crate::config::NetworkConfig,
    cmd_tx: &mpsc::Sender<EngineCmd>,
    timeout: Duration,
) -> Vec<ParaCandidate> {
    gather_local_para_candidates_inner(snap, cmd_tx, timeout, true, false).await
}

async fn gather_local_para_candidates_inner(
    snap: &crate::config::NetworkConfig,
    cmd_tx: &mpsc::Sender<EngineCmd>,
    timeout: Duration,
    force_refresh: bool,
    skip_stun: bool,
) -> Vec<ParaCandidate> {
    let mut out = Vec::new();
    if !skip_stun {
        let stun_ep = if force_refresh {
            query_stun_via_engine_force(cmd_tx, timeout).await
        } else {
            query_stun_via_engine(cmd_tx, timeout).await
        };
        if let Some(ep) = stun_ep {
            out.push(ParaCandidate {
                ip: ep.ip,
                port: ep.port,
                kind: "stun".to_string(),
            });
        }
    }
    let local_ip = get_local_ip();
    out.push(ParaCandidate {
        ip: local_ip,
        port: snap.listen_port.max(7878),
        kind: "local".to_string(),
    });
    if !force_refresh {
        for raw in &snap.owner_endpoints_cache {
            if let Ok(ep) = raw.parse::<SocketAddr>() {
                if skip_stun && !is_rfc1918_private_ip(ep.ip()) {
                    continue;
                }
                out.push(ParaCandidate {
                    ip: ep.ip().to_string(),
                    port: ep.port(),
                    kind: "cached".to_string(),
                });
            }
        }
    }
    let mut uniq = HashSet::new();
    out.retain(|c| uniq.insert(format!("{}:{}:{}", c.ip, c.port, c.kind)));
    out
}

fn is_rfc1918_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(_) => false,
    }
}

fn local_only_para_candidates(snap: &crate::config::NetworkConfig) -> Vec<ParaCandidate> {
    vec![ParaCandidate {
        ip: get_local_ip(),
        port: snap.listen_port.max(7878),
        kind: "local".to_string(),
    }]
}

async fn owner_reply_para_candidates(
    snap: &crate::config::NetworkConfig,
    cmd_tx: &mpsc::Sender<EngineCmd>,
    from: SocketAddr,
    force_timeout: Duration,
) -> Vec<ParaCandidate> {
    if is_rfc1918_private_ip(from.ip()) {
        return local_only_para_candidates(snap);
    }
    gather_local_para_candidates_force(snap, cmd_tx, force_timeout).await
}

fn build_owner_para_reply_bytes(
    snap: &crate::config::NetworkConfig,
    local_candidates: &[ParaCandidate],
    assigned_vip: &str,
    network_id: &str,
    agreed_start_at_ms: u64,
    session_id: &str,
    include_network_key: bool,
) -> Vec<u8> {
    let public_ip = local_candidates
        .first()
        .map(|c| c.ip.clone())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let public_port = local_candidates
        .first()
        .map(|c| c.port)
        .unwrap_or(snap.listen_port.max(7878));
    let network_key_hex = if include_network_key {
        snap.crypto_key.clone()
    } else {
        String::new()
    };
    json!({
        "node_id": snap.node_id,
        "public_ip": public_ip,
        "public_port": public_port,
        "assigned_vip": assigned_vip,
        "network_id": network_id,
        "ts_ms": now_epoch_ms(),
        "candidates": local_candidates,
        "agreed_start_at_ms": agreed_start_at_ms,
        "session_id": session_id,
        "responder_vip": snap.virtual_ip,
        "responder_is_owner": true,
        "network_name": snap.server_name,
        "network_key_hex": network_key_hex,
    })
    .to_string()
    .into_bytes()
}

/// UDP targets for LAN parasitic discover broadcasts.
fn para_lan_discovery_targets(local_ip: &str, listen_port: u16) -> Vec<SocketAddr> {
    let mut ports = vec![7878u16, listen_port.max(7878)];
    ports.sort_unstable();
    ports.dedup();
    let mut out = Vec::new();
    let mut push = |ip: Ipv4Addr, port: u16| {
        out.push(SocketAddr::from((ip, port)));
    };
    for port in ports {
        push(Ipv4Addr::BROADCAST, port);
        if let Ok(ip) = local_ip.parse::<Ipv4Addr>() {
            if ip.is_private() && !ip.is_loopback() {
                let o = ip.octets();
                let directed = Ipv4Addr::new(o[0], o[1], o[2], 255);
                if directed != Ipv4Addr::BROADCAST {
                    push(directed, port);
                }
            }
        }
    }
    out
}

fn filter_private_socket_addrs(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    addrs
        .iter()
        .copied()
        .filter(|a| is_rfc1918_private_ip(a.ip()))
        .collect()
}

async fn select_parasitic_lan_target_interactive(
    cli: &Cli,
    owners: &[crate::ipc::ParasiticLanOwner],
) -> Result<SocketAddr> {
    let listen_port = cli.config.get_listen_port().max(7878);
    if owners.is_empty() {
        crate::cli_println!(
            "{}",
            term_style::fmt_para_line(format_args!(
                " No owners replied. AP client isolation may block UDP broadcast."
            ))
        );
        crate::cli_print!("  Owner ip:port (or empty to abort): ");
        io::stdout().flush()?;
        let line = cli.read_line().await?;
        if line.trim().is_empty() {
            return Err(anyhow!(
                "LAN discover found no owners and no fallback target"
            ));
        }
        return Ok(parse_vip_signal_target(line.trim(), listen_port)?.1);
    }
    if owners.len() == 1 {
        return Ok(parse_vip_signal_target(&owners[0].from, listen_port)?.1);
    }
    crate::cli_println!("  Multiple Mint owners on LAN:");
    for (i, o) in owners.iter().enumerate() {
        let name = if o.network_name.is_empty() {
            "(unnamed)"
        } else {
            o.network_name.as_str()
        };
        let short_id = if o.network_id.len() > 12 {
            &o.network_id[..12]
        } else {
            o.network_id.as_str()
        };
        crate::cli_println!(
            "    [{}] {}  id={}…  from={}",
            i + 1,
            name,
            short_id,
            o.from
        );
    }
    crate::cli_print!("  Choose owner [1-{}]: ", owners.len());
    io::stdout().flush()?;
    let line = cli.read_line().await?;
    let idx: usize = line
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid owner selection"))?;
    if idx == 0 || idx > owners.len() {
        return Err(anyhow!("owner selection out of range"));
    }
    Ok(parse_vip_signal_target(&owners[idx - 1].from, listen_port)?.1)
}

fn candidates_to_socket_addrs(cands: &[ParaEngineCandidate]) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for c in cands {
        if let Ok(ep) = make_socket_addr(&c.ip, c.port) {
            if seen.insert(ep) {
                out.push(ep);
            }
        }
    }
    out
}

fn candidates_to_ice(eps: &[SocketAddr]) -> Vec<serde_json::Value> {
    eps.iter()
        .map(|ep| {
            json!({
                "ip": ep.ip().to_string(),
                "port": ep.port(),
                "type": "para",
            })
        })
        .collect()
}

fn compute_agreed_start_at_ms(peer_value: u64, local_default: u64) -> u64 {
    let mut agreed = peer_value.max(local_default);
    let now = now_epoch_ms();
    if agreed <= now {
        agreed = now;
    }
    let max_future = now.saturating_add(PARA_MAX_CLOCK_SKEW_MS);
    if agreed > max_future {
        agreed = max_future;
    }
    agreed
}

fn para_signal_pause_duration() -> Duration {
    let base = PARA_SIGNAL_PAUSE_MS;
    let jitter = (base.saturating_mul(PARA_SIGNAL_JITTER_PCT) / 100).max(1);
    let lower = base.saturating_sub(jitter);
    let upper = base.saturating_add(jitter);
    let ms = if lower >= upper {
        base
    } else {
        use rand::Rng;
        rand::thread_rng().gen_range(lower..=upper)
    };
    Duration::from_millis(ms)
}

fn vip_owner_matches(
    vip_owners: &HashMap<String, (String, u64)>,
    vip: &str,
    session_id: &str,
    lease_token: u64,
) -> bool {
    vip_owners
        .get(vip)
        .map(|(sid, lease)| sid == session_id && *lease == lease_token)
        .unwrap_or(false)
}

async fn register_para_listener(
    cmd_tx: &mpsc::Sender<EngineCmd>,
    notify_tx: mpsc::Sender<ParaSignal>,
    replace_existing: bool,
) -> Option<u64> {
    let (reply_tx, reply_rx) = oneshot::channel();
    let _ = cmd_tx
        .send(EngineCmd::ParaSetListener {
            notify_tx,
            replace_existing,
            reply: Some(reply_tx),
        })
        .await;
    tokio::time::timeout(Duration::from_millis(300), reply_rx)
        .await
        .ok()
        .and_then(|id| id.ok())
}

async fn unregister_para_listener(cmd_tx: &mpsc::Sender<EngineCmd>, listener_id: Option<u64>) {
    if let Some(listener_id) = listener_id {
        let _ = cmd_tx
            .send(EngineCmd::ParaRemoveListener { listener_id })
            .await;
    }
}

async fn send_para_ok_redundant(
    cmd_tx: &mpsc::Sender<EngineCmd>,
    target_vip: SocketAddr,
    local_node_id: &str,
    session_id: &str,
) -> Result<()> {
    for i in 0..PARA_OK_REDUNDANCY {
        let ok = json!({
            "node_id": local_node_id,
            "ts_ms": now_epoch_ms(),
            "session_id": session_id,
        })
        .to_string()
        .into_bytes();
        let _ = cmd_tx
            .send(EngineCmd::ParaSendOk {
                target_vip,
                payload: ok,
            })
            .await;
        if i + 1 < PARA_OK_REDUNDANCY {
            tokio::time::sleep(Duration::from_millis(PARA_OK_GAP_MS)).await;
        }
    }
    Ok(())
}

fn stop_para_passive_punch_loops(cmd_tx: &mpsc::Sender<EngineCmd>, session_id: &str) {
    let key = format!("para-passive-{session_id}");
    let _ = cmd_tx.try_send(EngineCmd::StopPunchWorkflow { key });
}

fn prepare_para_punch_route(
    routing: &Arc<RwLock<RoutingTable>>,
    cmd_tx: &mpsc::Sender<EngineCmd>,
    remote_vip: &str,
) {
    if remote_vip.is_empty() {
        return;
    }
    routing.write().remove(remote_vip);
    let _ = cmd_tx.try_send(EngineCmd::PeerRouteRemoved {
        vip: remote_vip.to_string(),
    });
}

fn collect_para_punch_ack_targets(
    rt: &RoutingTable,
    remote_vip: &str,
    remote_candidates: &[SocketAddr],
    fallbacks: &[SocketAddr],
) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    if let Some(ep) = rt.lookup(remote_vip) {
        if seen.insert(ep) {
            out.push(ep);
        }
    }
    for ep in remote_candidates.iter().chain(fallbacks.iter()) {
        if seen.insert(*ep) {
            out.push(*ep);
        }
    }
    out
}

async fn send_para_punch_ack_redundant(
    cmd_tx: &mpsc::Sender<EngineCmd>,
    targets: &[SocketAddr],
    local_node_id: &str,
    session_id: &str,
) -> Result<()> {
    let mut seen = HashSet::new();
    for target in targets {
        if !seen.insert(*target) {
            continue;
        }
        for i in 0..PARA_PUNCH_ACK_REDUNDANCY {
            let ack = json!({
                "node_id": local_node_id,
                "ts_ms": now_epoch_ms(),
                "session_id": session_id,
            })
            .to_string()
            .into_bytes();
            let _ = cmd_tx
                .send(EngineCmd::ParaSendPunchAck {
                    target: *target,
                    payload: ack,
                })
                .await;
            if i + 1 < PARA_PUNCH_ACK_REDUNDANCY {
                tokio::time::sleep(Duration::from_millis(PARA_PUNCH_ACK_GAP_MS)).await;
            }
        }
    }
    Ok(())
}

async fn wait_until_para_start(start_at_ms: u64) {
    let now = now_epoch_ms();
    if start_at_ms <= now {
        return;
    }
    let wait_ms = start_at_ms.saturating_sub(now).min(PARA_MAX_CLOCK_SKEW_MS);
    tokio::time::sleep(Duration::from_millis(wait_ms)).await;
}

fn punch_route_ready(rt: &RoutingTable, remote_vip: &str, peer_candidates: &[SocketAddr]) -> bool {
    let candidate_set: HashSet<SocketAddr> = peer_candidates.iter().copied().collect();
    if let Some(entry) = rt.table.get(remote_vip) {
        if matches!(
            entry.state,
            crate::routing::RouteState::Active | crate::routing::RouteState::Candidate
        ) {
            if candidate_set.is_empty() || candidate_set.contains(&entry.endpoint) {
                return true;
            }
        }
    }
    for candidate in peer_candidates {
        if let Some(vip) = rt.ep_to_vip.get(candidate) {
            if vip == remote_vip {
                if let Some(entry) = rt.table.get(remote_vip) {
                    if matches!(
                        entry.state,
                        crate::routing::RouteState::Active | crate::routing::RouteState::Candidate
                    ) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

async fn wait_for_parasitic_punch_ready(
    routing: &Arc<RwLock<RoutingTable>>,
    remote_vip: &str,
    peer_candidates: &[SocketAddr],
    burst_start: std::time::Instant,
    deadline: std::time::Instant,
    min_wall_ms: u64,
    punch_cancel: Option<Arc<AtomicBool>>,
) -> bool {
    let min_wall = Duration::from_millis(min_wall_ms);
    let debounce = Duration::from_millis(PARA_PUNCH_ROUTE_DEBOUNCE_MS);
    let poll = Duration::from_millis(250);
    let mut stable_since: Option<std::time::Instant> = None;
    while std::time::Instant::now() < deadline {
        if punch_cancel
            .as_ref()
            .is_some_and(|c| c.load(Ordering::Acquire))
        {
            return true;
        }
        let now = std::time::Instant::now();
        let found = {
            let rt = routing.read();
            punch_route_ready(&rt, remote_vip, peer_candidates)
        };
        if found {
            if stable_since.is_none() {
                stable_since = Some(now);
            }
            if now >= burst_start + min_wall {
                if let Some(since) = stable_since {
                    if now.duration_since(since) >= debounce {
                        return true;
                    }
                }
            }
        } else {
            stable_since = None;
        }
        tokio::time::sleep(poll).await;
    }
    false
}

async fn run_parasitic_punch_worker(
    cmd_tx: mpsc::Sender<EngineCmd>,
    routing: Arc<RwLock<RoutingTable>>,
    remote_candidates: Vec<SocketAddr>,
    remote_vip: String,
    workflow_key: String,
    punch_cancel: Arc<AtomicBool>,
) -> bool {
    if remote_candidates.is_empty() {
        return false;
    }
    let cancel = Some(punch_cancel.clone());
    prepare_para_punch_route(&routing, &cmd_tx, &remote_vip);
    for target in &remote_candidates {
        let _ = cmd_tx
            .send(EngineCmd::ManualPunch {
                target: *target,
                count: PARA_KEEPALIVE_COUNT as usize,
            })
            .await;
        tokio::time::sleep(Duration::from_millis(PARA_KEEPALIVE_GAP_MS)).await;
    }

    let phase_start = std::time::Instant::now();
    let _ = cmd_tx
        .send(EngineCmd::StartPunchWorkflow {
            key: workflow_key.clone(),
            bases: remote_candidates.clone(),
            log_stages: true,
        })
        .await;

    let ok = wait_for_parasitic_punch_ready(
        &routing,
        &remote_vip,
        &remote_candidates,
        phase_start,
        std::time::Instant::now() + Duration::from_secs(PARA_PUNCH_WORKFLOW_DEADLINE_SECS),
        PARA_OWNER_PASSIVE_MIN_BURST_WALL_MS,
        cancel,
    )
    .await;
    let _ = cmd_tx
        .send(EngineCmd::StopPunchWorkflow { key: workflow_key })
        .await;
    ok
}

fn random_owner_vip() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let a: u8 = rng.gen_range(10..=255);
    let b: u8 = rng.gen_range(1..=255);
    let c: u8 = rng.gen_range(1..=255);
    format!("{a}.{b}.{c}.1")
}

/// Commands whose output should survive screen autoclear.
fn command_skips_autoclear(cmd: &str) -> bool {
    ["config", "runtime", "autoclear-on", "autoclear-off"]
        .iter()
        .any(|c| cmd.eq_ignore_ascii_case(c))
}

fn normalize_command(mut line: String) -> String {
    line = line.trim().to_string();
    if line == "mint" {
        return String::new();
    }
    if let Some(rest) = line.strip_prefix("mint ") {
        return rest.trim().to_string();
    }
    line
}

fn get_local_ip() -> String {
    use std::net::UdpSocket;
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return "127.0.0.1".to_string(),
    };
    if sock.connect("8.8.8.8:80").is_err() {
        return "127.0.0.1".to_string();
    }
    sock.local_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}

fn parse_vip_signal_target(input: &str, default_port: u16) -> Result<(String, SocketAddr)> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err(anyhow!("value is required"));
    }
    if let Some((ip_s, port_s)) = raw.rsplit_once(':') {
        if ip_s.contains(':') {
            return Err(anyhow!("IPv6 is not supported for parasitic mode"));
        }
        let ip: Ipv4Addr = ip_s.parse().map_err(|_| anyhow!("invalid IPv4 address"))?;
        let port: u16 = port_s.parse().map_err(|_| anyhow!("invalid port"))?;
        if !(PORT_MIN..=PORT_MAX).contains(&port) {
            return Err(anyhow!("invalid port range {PORT_MIN}-{PORT_MAX}"));
        }
        let ip_text = ip.to_string();
        return Ok((ip_text.clone(), SocketAddr::from((ip, port))));
    }
    let ip: Ipv4Addr = raw.parse().map_err(|_| anyhow!("invalid IPv4 address"))?;
    let port = default_port.clamp(PORT_MIN, PORT_MAX);
    let ip_text = ip.to_string();
    Ok((ip_text.clone(), SocketAddr::from((ip, port))))
}

fn make_socket_addr(ip: &str, port: u16) -> Result<SocketAddr> {
    let ip_v4: Ipv4Addr = ip.parse().map_err(|_| anyhow!("invalid IPv4 address"))?;
    if !(PORT_MIN..=PORT_MAX).contains(&port) {
        return Err(anyhow!("invalid port range {PORT_MIN}-{PORT_MAX}"));
    }
    Ok(SocketAddr::from((ip_v4, port)))
}

fn vip_from_owner_subnet(owner_vip: &str, owner_slot: bool) -> Result<String> {
    let ip: Ipv4Addr = owner_vip
        .parse()
        .map_err(|_| anyhow!("invalid owner vip subnet"))?;
    let [a, b, c, _] = ip.octets();
    Ok(if owner_slot {
        format!("{a}.{b}.{c}.1")
    } else {
        format!("{a}.{b}.{c}.2")
    })
}

fn parse_punch_target_args(
    peer_target: Option<&str>,
    peer_port: Option<&str>,
) -> Result<SocketAddr> {
    let target = peer_target.unwrap_or_default().trim();
    let port_arg = peer_port.unwrap_or_default().trim();
    if target.is_empty() {
        return Err(anyhow!(
            "usage: mint punch <public_ip>:<public_port> (or mint punch <public_ip> <public_port>)"
        ));
    }

    if !port_arg.is_empty() {
        if target.contains(':') {
            return Err(anyhow!(
                "usage: mint punch <public_ip>:<public_port> (or mint punch <public_ip> <public_port>)"
            ));
        }
        let ip: Ipv4Addr = target.parse().map_err(|_| anyhow!("invalid IP address"))?;
        let port: u16 = port_arg.parse().map_err(|_| anyhow!("invalid port"))?;
        if !(PORT_MIN..=PORT_MAX).contains(&port) {
            return Err(anyhow!("invalid port range {PORT_MIN}-{PORT_MAX}"));
        }
        return Ok(SocketAddr::from((ip, port)));
    }

    let Some((ip_s, port_s)) = target.rsplit_once(':') else {
        return Err(anyhow!(
            "usage: mint punch <public_ip>:<public_port> (or mint punch <public_ip> <public_port>)"
        ));
    };
    if ip_s.is_empty() || port_s.is_empty() || ip_s.contains(':') {
        return Err(anyhow!(
            "usage: mint punch <public_ip>:<public_port> (or mint punch <public_ip> <public_port>)"
        ));
    }
    let ip: Ipv4Addr = ip_s.parse().map_err(|_| anyhow!("invalid IP address"))?;
    let port: u16 = port_s.parse().map_err(|_| anyhow!("invalid port"))?;
    if !(PORT_MIN..=PORT_MAX).contains(&port) {
        return Err(anyhow!("invalid port range {PORT_MIN}-{PORT_MAX}"));
    }
    Ok(SocketAddr::from((ip, port)))
}

#[derive(Clone, Default)]
struct RuntimeRateView {
    tun_egress_mbps: Option<f64>,
    tun_ingress_mbps: Option<f64>,
    wire_tx_mbps: Option<f64>,
    wire_rx_mbps: Option<f64>,
    tun_egress_mib: f64,
    tun_ingress_mib: f64,
    wire_tx_mib: f64,
    wire_rx_mib: f64,
}

struct RuntimeRateTracker {
    last_at: Option<Instant>,
    last_tun_eg: u64,
    last_tun_in: u64,
    last_wire_tx: u64,
    last_wire_rx: u64,
}

impl RuntimeRateTracker {
    fn new() -> Self {
        Self {
            last_at: None,
            last_tun_eg: 0,
            last_tun_in: 0,
            last_wire_tx: 0,
            last_wire_rx: 0,
        }
    }

    fn sample(&mut self, trace: &RuntimeTrace) -> RuntimeRateView {
        use std::sync::atomic::Ordering;
        let cur_eg = trace.tun_egress_bytes.load(Ordering::Relaxed);
        let cur_in = trace.tun_ingress_bytes.load(Ordering::Relaxed);
        let cur_tx = trace.wire_tx_bytes.load(Ordering::Relaxed);
        let cur_rx = trace.wire_rx_bytes.load(Ordering::Relaxed);
        let mib = |b: u64| b as f64 / (1024.0 * 1024.0);
        let mut view = RuntimeRateView {
            tun_egress_mib: mib(cur_eg),
            tun_ingress_mib: mib(cur_in),
            wire_tx_mib: mib(cur_tx),
            wire_rx_mib: mib(cur_rx),
            ..Default::default()
        };
        if let Some(t0) = self.last_at {
            let dt = t0.elapsed().as_secs_f64().max(0.001);
            let mbps = |cur: u64, prev: u64| {
                Some((cur.saturating_sub(prev)) as f64 * 8.0 / dt / 1_000_000.0)
            };
            view.tun_egress_mbps = mbps(cur_eg, self.last_tun_eg);
            view.tun_ingress_mbps = mbps(cur_in, self.last_tun_in);
            view.wire_tx_mbps = mbps(cur_tx, self.last_wire_tx);
            view.wire_rx_mbps = mbps(cur_rx, self.last_wire_rx);
        }
        self.last_at = Some(Instant::now());
        self.last_tun_eg = cur_eg;
        self.last_tun_in = cur_in;
        self.last_wire_tx = cur_tx;
        self.last_wire_rx = cur_rx;
        view
    }
}

struct RuntimeViewSession {
    cmd_tx: mpsc::Sender<EngineCmd>,
}

impl RuntimeViewSession {
    async fn enter(cmd_tx: mpsc::Sender<EngineCmd>) -> Self {
        let (tx, rx) = oneshot::channel();
        let _ = cmd_tx.send(EngineCmd::RuntimeViewBegin { reply: tx }).await;
        let _ = tokio::time::timeout(Duration::from_millis(500), rx).await;
        Self { cmd_tx }
    }
}

impl Drop for RuntimeViewSession {
    fn drop(&mut self) {
        let (tx, _rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .try_send(EngineCmd::RuntimeViewEnd { reply: tx });
    }
}

fn clear_screen() {
    crate::cli_emit::emit_clear_screen();
}

fn enter_runtime_terminal() -> Result<()> {
    crate::cli_print!("\x1B[?1049h\x1B[?25l");
    io::stdout()
        .flush()
        .map_err(|e| anyhow!("stdout flush: {e}"))
}

fn leave_runtime_terminal() -> Result<()> {
    crate::cli_print!("\x1B[?25h\x1B[?1049l");
    io::stdout()
        .flush()
        .map_err(|e| anyhow!("stdout flush: {e}"))
}

fn parse_key_hex_32(hex_key: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_key).map_err(|_| anyhow!("invalid key hex"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("invalid key length"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn pacing_config_from_network(snap: &crate::config::NetworkConfig) -> PacingConfig {
    let mq = pace_def::effective_pace_max_queue_packets(snap.pace_max_queue_packets);
    let (dq, cq) = crate::net::pacing::queue_split_limits(mq);
    PacingConfig {
        tick_us: pace_def::effective_pace_tick_us(snap.pace_tick_us),
        target_pps: pace_def::effective_pace_target_pps(snap.pace_target_pps),
        base_max_burst: pace_def::effective_base_max_burst(snap.base_max_burst),
        budget_cap_packets: pace_def::effective_pace_budget_cap_packets(
            snap.pace_budget_cap_packets,
        ),
        max_queue_packets: mq,
        max_data_queue_packets: dq,
        max_control_queue_packets: cq,
        max_retransmit_queue_packets: (cq / 3).max(4),
        drr_quantum: 1500,
        drr_enabled: snap.drr_enabled,
        drr_small_packet_priority: snap.drr_small_packet_priority,
        drr_small_packet_threshold_bytes: pace_def::effective_drr_small_packet_threshold_bytes(
            snap.drr_small_packet_threshold_bytes,
        ),
        min_control_reserved_bytes_per_tick: pace_def::effective_reserved_bytes_per_tick(
            snap.min_control_reserved_bytes_per_tick,
        ),
        min_retransmit_reserved_bytes_per_tick: pace_def::effective_reserved_bytes_per_tick(
            snap.min_retransmit_reserved_bytes_per_tick,
        ),
        drr_rtt_aware: snap.drr_rtt_aware,
        drr_rtt_scale_min: pace_def::effective_drr_rtt_scale_min(snap.drr_rtt_scale_min),
        drr_rtt_scale_max: pace_def::effective_drr_rtt_scale_max(snap.drr_rtt_scale_max),
        max_tick_work_us: crate::net::pacing_defaults::DEFAULT_MAX_TICK_WORK_US,
        apd: crate::net::pacing::apd_config_from_network(snap),
        shed: crate::net::pacing::shed_config_from_network(snap),
        background_cc: snap.advanced.congestion.to_background_cc_config(),
        pace_rate_mode: pace_def::effective_pace_rate_mode(&snap.pace_rate_mode),
        target_bps: pace_def::effective_pace_target_bps(snap.pace_target_bps, snap.pace_target_pps),
    }
}

fn fec_forced_ratio_from_network(snap: &crate::config::NetworkConfig) -> Option<(u8, u8)> {
    if snap.fec_force_data_shards > 0 && snap.fec_force_parity_shards > 0 {
        Some((snap.fec_force_data_shards, snap.fec_force_parity_shards))
    } else {
        None
    }
}

fn effective_retransmit_bypass_pps(v: f64) -> f64 {
    if v.is_finite() && v > 0.0 {
        v
    } else {
        1000.0
    }
}

fn effective_udp_sockbuf(v: i32) -> i32 {
    if (UDP_SOCKBUF_MIN..=UDP_SOCKBUF_MAX).contains(&v) {
        v
    } else {
        DEFAULT_UDP_SOCKBUF
    }
}

fn effective_udp_sndbuf(v: i32) -> i32 {
    effective_udp_sockbuf(v)
}

fn effective_udp_rcvbuf(v: i32) -> i32 {
    if (UDP_SOCKBUF_MIN..=UDP_SOCKBUF_MAX).contains(&v) {
        v
    } else {
        DEFAULT_UDP_RCVBUF
    }
}

fn effective_wintun_ring_bytes(v: u32) -> u32 {
    if (WINTUN_RING_MIN_BYTES..=WINTUN_RING_MAX_BYTES).contains(&v) {
        v
    } else {
        DEFAULT_WINTUN_RING_BYTES
    }
}

fn effective_wintun_ipv4_interface_metric(v: u32) -> u32 {
    match v {
        0 => 0,
        1..=WINTUN_IPV4_METRIC_MAX => v,
        _ => WINTUN_IPV4_METRIC_MAX,
    }
}

fn effective_adapter_mtu(v: i32) -> i32 {
    if (576..=1500).contains(&v) {
        v
    } else {
        1340
    }
}

/// Which disruptive adapter-side applies are needed when moving from `previous` → `next`.
/// Soft knobs (pacing / FEC / advanced) are always applied by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AdapterLiveApplyPlan {
    apply_socket_buffers: bool,
    recreate_wintun_ring: bool,
    apply_netsh: bool,
}

fn adapter_live_apply_plan(
    previous: Option<&crate::config::NetworkConfig>,
    next: &crate::config::NetworkConfig,
) -> AdapterLiveApplyPlan {
    let Some(prev) = previous else {
        return AdapterLiveApplyPlan {
            apply_socket_buffers: true,
            recreate_wintun_ring: true,
            apply_netsh: true,
        };
    };
    AdapterLiveApplyPlan {
        apply_socket_buffers: effective_udp_sndbuf(prev.udp_sndbuf)
            != effective_udp_sndbuf(next.udp_sndbuf)
            || effective_udp_rcvbuf(prev.udp_rcvbuf) != effective_udp_rcvbuf(next.udp_rcvbuf),
        recreate_wintun_ring: effective_wintun_ring_bytes(prev.wintun_ring_bytes)
            != effective_wintun_ring_bytes(next.wintun_ring_bytes),
        apply_netsh: effective_adapter_mtu(prev.adapter_mtu)
            != effective_adapter_mtu(next.adapter_mtu)
            || prev.pin_mtu != next.pin_mtu
            || effective_wintun_ipv4_interface_metric(prev.wintun_ipv4_interface_metric)
                != effective_wintun_ipv4_interface_metric(next.wintun_ipv4_interface_metric),
    }
}

fn restart_sensitive_perf_changed(
    previous: &crate::config::NetworkConfig,
    next: &crate::config::NetworkConfig,
) -> bool {
    effective_wintun_ring_bytes(previous.wintun_ring_bytes)
        != effective_wintun_ring_bytes(next.wintun_ring_bytes)
        || previous.tun_inject_queue_packets != next.tun_inject_queue_packets
        || previous.tun_from_adapter_queue_packets != next.tun_from_adapter_queue_packets
}

fn pace_spin_style_hint(tick_us: u64, spin_window_us: u64) -> &'static str {
    if spin_window_us == 0 {
        "HR/sleep only"
    } else if spin_window_us >= tick_us {
        "full spin"
    } else {
        "hybrid HR+spin"
    }
}

#[cfg(test)]
mod punch_route_ready_tests {
    use super::{punch_route_ready, vip_owner_matches};
    use crate::routing::{RouteState, RoutingTable};
    use std::collections::HashMap;
    use std::net::SocketAddr;

    #[test]
    fn ip_only_same_public_ip_wrong_vip_not_ready() {
        let mut rt = RoutingTable::new();
        let ep_a: SocketAddr = "198.51.100.2:1111".parse().unwrap();
        rt.update("10.0.0.10", ep_a, None);

        let candidates = vec!["198.51.100.2:9999".parse().unwrap()];
        assert!(!punch_route_ready(&rt, "10.0.0.20", &candidates));
    }

    #[test]
    fn same_ip_wrong_port_not_ready_when_candidates_present() {
        let mut rt = RoutingTable::new();
        let ep: SocketAddr = "198.51.100.3:7000".parse().unwrap();
        rt.update("10.0.0.7", ep, None);
        let candidates = vec!["198.51.100.3:9999".parse().unwrap()];
        assert!(!punch_route_ready(&rt, "10.0.0.7", &candidates));
    }

    #[test]
    fn exact_candidate_endpoint_ready() {
        let mut rt = RoutingTable::new();
        let ep: SocketAddr = "198.51.100.3:7000".parse().unwrap();
        rt.update("10.0.0.7", ep, None);
        let candidates = vec![ep];
        assert!(punch_route_ready(&rt, "10.0.0.7", &candidates));
    }

    #[test]
    fn stale_route_is_not_ready() {
        let mut rt = RoutingTable::new();
        let ep: SocketAddr = "198.51.100.4:8000".parse().unwrap();
        rt.update("10.0.0.8", ep, None);
        rt.table.get_mut("10.0.0.8").unwrap().state = RouteState::Stale;
        let candidates = vec!["198.51.100.4:8888".parse().unwrap()];
        assert!(!punch_route_ready(&rt, "10.0.0.8", &candidates));
    }

    #[test]
    fn vip_owner_match_requires_exact_session_and_lease() {
        let mut owners = HashMap::new();
        owners.insert("10.0.0.2".to_string(), ("sid-a".to_string(), 9));
        assert!(vip_owner_matches(&owners, "10.0.0.2", "sid-a", 9));
        assert!(!vip_owner_matches(&owners, "10.0.0.2", "sid-b", 9));
        assert!(!vip_owner_matches(&owners, "10.0.0.2", "sid-a", 10));
        assert!(!vip_owner_matches(&owners, "10.0.0.9", "sid-a", 9));
    }
}

#[cfg(test)]
mod parasitic_lan_helpers_tests {
    use super::{filter_private_socket_addrs, is_rfc1918_private_ip, para_lan_discovery_targets};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn discovery_targets_include_limited_and_directed_broadcast() {
        let targets = para_lan_discovery_targets("192.168.10.5", 7878);
        assert!(targets.contains(&"255.255.255.255:7878".parse().unwrap()));
        assert!(targets.contains(&"192.168.10.255:7878".parse().unwrap()));
        let targets_custom = para_lan_discovery_targets("10.0.0.2", 9999);
        assert!(targets_custom.contains(&"255.255.255.255:7878".parse().unwrap()));
        assert!(targets_custom.contains(&"255.255.255.255:9999".parse().unwrap()));
        assert!(targets_custom.contains(&"10.0.0.255:9999".parse().unwrap()));
    }

    #[test]
    fn filter_keeps_private_drops_public() {
        let addrs = vec![
            "192.168.1.10:7878".parse().unwrap(),
            "8.8.8.8:7878".parse().unwrap(),
            "10.1.2.3:9000".parse().unwrap(),
        ];
        let filtered = filter_private_socket_addrs(&addrs);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|a| is_rfc1918_private_ip(a.ip())));
        assert!(!is_rfc1918_private_ip(IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8
        ))));
        let _: SocketAddr = filtered[0];
    }
}

#[cfg(test)]
mod adapter_live_apply_plan_tests {
    use super::{
        adapter_live_apply_plan, restart_sensitive_perf_changed, AdapterLiveApplyPlan,
        DEFAULT_WINTUN_RING_BYTES,
    };
    use crate::config::NetworkConfig;

    #[test]
    fn unchanged_perf_skips_all_disruptive_applies() {
        let cfg = NetworkConfig::default();
        let plan = adapter_live_apply_plan(Some(&cfg), &cfg);
        assert_eq!(
            plan,
            AdapterLiveApplyPlan {
                apply_socket_buffers: false,
                recreate_wintun_ring: false,
                apply_netsh: false,
            }
        );
        assert!(!restart_sensitive_perf_changed(&cfg, &cfg));
    }

    #[test]
    fn soft_knob_only_change_skips_adapter_work() {
        let prev = NetworkConfig::default();
        let mut next = prev.clone();
        next.pace_tick_us = 999;
        next.fec_enabled = !prev.fec_enabled;
        next.advanced.timers.keepalive_secs = 42;
        let plan = adapter_live_apply_plan(Some(&prev), &next);
        assert_eq!(
            plan,
            AdapterLiveApplyPlan {
                apply_socket_buffers: false,
                recreate_wintun_ring: false,
                apply_netsh: false,
            }
        );
        assert!(!restart_sensitive_perf_changed(&prev, &next));
    }

    #[test]
    fn ring_change_only_requests_wintun_recreate() {
        let prev = NetworkConfig::default();
        let mut next = prev.clone();
        next.wintun_ring_bytes = DEFAULT_WINTUN_RING_BYTES * 2;
        let plan = adapter_live_apply_plan(Some(&prev), &next);
        assert!(plan.recreate_wintun_ring);
        assert!(!plan.apply_socket_buffers);
        assert!(!plan.apply_netsh);
        assert!(restart_sensitive_perf_changed(&prev, &next));
    }

    #[test]
    fn sockbuf_change_does_not_recreate_wintun() {
        let prev = NetworkConfig::default();
        let mut next = prev.clone();
        next.udp_sndbuf = prev.udp_sndbuf + 64 * 1024;
        let plan = adapter_live_apply_plan(Some(&prev), &next);
        assert!(plan.apply_socket_buffers);
        assert!(!plan.recreate_wintun_ring);
        assert!(!plan.apply_netsh);
    }

    #[test]
    fn missing_previous_forces_full_adapter_apply() {
        let next = NetworkConfig::default();
        assert_eq!(
            adapter_live_apply_plan(None, &next),
            AdapterLiveApplyPlan {
                apply_socket_buffers: true,
                recreate_wintun_ring: true,
                apply_netsh: true,
            }
        );
    }

    #[test]
    fn pin_mtu_flip_requests_netsh() {
        let prev = NetworkConfig::default();
        let mut next = prev.clone();
        next.pin_mtu = true;
        let plan = adapter_live_apply_plan(Some(&prev), &next);
        assert!(plan.apply_netsh);
        assert!(!plan.apply_socket_buffers);
        assert!(!plan.recreate_wintun_ring);
    }
}
