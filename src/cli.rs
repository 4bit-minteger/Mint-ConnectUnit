use std::collections::{HashMap, HashSet};
use std::env;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
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
use crate::config::{effective_decentralized_trackers, ConfigManager, MEMBER_ROSTER_MAX};
use crate::cpu_affinity;
use crate::crypto::{
    decode_invite, derive_network_id, encode_invite, now_epoch_ms, room_id_20b, room_id_hex,
    InvitePayload, Key, MintCrypto, INVITE_VERSION, PROTO_UDP,
};
use crate::metrics::EngineMetrics;
use crate::nat::{ice, stun, upnp};
use crate::net::engine::{EngineCmd, JoinAck, ParaSignal, RuntimeSnapshot};
use crate::net::pace_clock::{self, PaceClockApply};
use crate::net::pacing::PacingConfig;
use crate::net::packet::WIRE_PROTOCOL_VERSION;
use crate::netinfo::{self, ensure_netinfo_dir};
use crate::pmtud::is_rfc1918_private_ip;
use crate::process_priority;
use crate::routing::RoutingTable;
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
const PARA_LAN_DISCOVER_MS: u64 = 2500;
const PARA_KEEPALIVE_COUNT: u32 = 3;
const PARA_KEEPALIVE_GAP_MS: u64 = 100;

const PARA_PUNCH_ROUTE_DEBOUNCE_MS: u64 = 250;

const BANNER_DELAY_FIRST_RUN_MS: u64 = 20;

const WINTUN_CREATE_TIMEOUT_SECS: u64 = 45;

/// Invite-join choices normally prompted on the CLI client (daemon headless).
#[derive(Clone, Copy, Debug)]
struct JoinInviteRunOpts {
    use_public: bool,
    skip_share_gate: bool,
    /// Manual join punch target (invite is key-only; endpoint is typed separately).
    target_endpoint: Option<SocketAddr>,
}

impl JoinInviteRunOpts {
    fn from_ipc(lan_mode: Option<bool>, target_endpoint: SocketAddr) -> Self {
        Self {
            use_public: !lan_mode.unwrap_or(false),
            skip_share_gate: true,
            target_endpoint: Some(target_endpoint),
        }
    }

    fn daemon_default() -> Self {
        Self {
            use_public: true,
            skip_share_gate: true,
            target_endpoint: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct ParaCandidate {
    ip: String,
    port: u16,
    kind: String,
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
    lan_presence_stop: Option<Arc<AtomicBool>>,
    lan_presence_task: Option<JoinHandle<()>>,
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
            lan_presence_stop: None,
            lan_presence_task: None,
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

    /// Engine/daemon startup: restore adapter, sync profile, LAN presence listener (no REPL).
    pub async fn run_daemon_bootstrap(&mut self) -> Result<()> {
        self.daemon_bootstrap_before_reconnect().await?;
        let _ = self
            .daemon_bootstrap_finalize(ReconnectOutcome::Skipped)
            .await?;
        Ok(())
    }

    /// Pre-reconnect daemon bootstrap (adapter, engine sync, LAN presence).
    pub async fn daemon_bootstrap_before_reconnect(&mut self) -> Result<()> {
        self.restore_adapter_from_saved_session().await?;
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
            self.ensure_lan_presence_listener().await?;
        }
        Ok(())
    }

    /// Post-reconnect: session-open home block (+ SessionReady on headless).
    pub async fn daemon_bootstrap_finalize(
        &mut self,
        outcome: ReconnectOutcome,
    ) -> Result<bootstrap::BootstrapSnapshot> {
        if self.state != AppState::CommandLoop || !self.has_active_profile() {
            return Ok(bootstrap::BootstrapSnapshot {
                complete: true,
                outcome: None,
                home_lines: vec![],
            });
        }
        let effective = outcome;
        if self.reconnect_home_shown {
            return Ok(bootstrap::BootstrapSnapshot {
                complete: true,
                outcome: Some(effective),
                home_lines: vec![],
            });
        }
        if self.headless {
            let home_lines = self
                .emit_session_home_block(effective, false, false)
                .await?;
            return Ok(bootstrap::BootstrapSnapshot {
                complete: true,
                outcome: Some(effective),
                home_lines,
            });
        }
        let home_lines = self
            .emit_session_home_block(effective, false, false)
            .await?;
        Ok(bootstrap::BootstrapSnapshot {
            complete: true,
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

    async fn ensure_lan_presence_listener(&mut self) -> Result<()> {
        let snap = self.config.snapshot();
        let should_run = self.state == AppState::CommandLoop
            && !snap.network_id.is_empty()
            && !snap.crypto_key.is_empty()
            && !snap.virtual_ip.is_empty();
        drop(snap);

        if !should_run {
            self.stop_lan_presence_listener();
            return Ok(());
        }
        if self.lan_presence_task.is_some() {
            return Ok(());
        }

        let stop = Arc::new(AtomicBool::new(false));
        let (sig_tx, mut sig_rx) = mpsc::channel::<ParaSignal>(2048);
        let listener_id = register_para_listener(&self.cmd_tx, sig_tx, true).await;

        let cmd_tx = self.cmd_tx.clone();
        let config = self.config.clone();
        let stop_flag = stop.clone();
        self.lan_presence_stop = Some(stop);
        self.lan_presence_task = Some(tokio::spawn(async move {
            loop {
                if stop_flag.load(Ordering::Acquire) {
                    break;
                }
                let recv = tokio::time::timeout(Duration::from_millis(600), sig_rx.recv()).await;
                let Ok(Some(sig)) = recv else {
                    continue;
                };
                let snap = config.snapshot();
                if snap.network_id.is_empty()
                    || snap.crypto_key.is_empty()
                    || snap.virtual_ip.is_empty()
                {
                    continue;
                }
                if let ParaSignal::HelloReceived {
                    from,
                    network_id,
                    session_id,
                    ..
                } = sig
                {
                    if network_id != snap.network_id {
                        continue;
                    }
                    let local_ip = get_local_ip();
                    let listen_port = snap.listen_port.max(7878);
                    let local_candidates = local_only_para_candidates(&snap);
                    let reply = json!({
                        "node_id": snap.node_id,
                        "public_ip": local_ip,
                        "public_port": listen_port,
                        "network_id": snap.network_id,
                        "ts_ms": now_epoch_ms(),
                        "candidates": local_candidates,
                        "session_id": session_id,
                        "responder_vip": snap.virtual_ip,
                    })
                    .to_string()
                    .into_bytes();
                    let _ = cmd_tx
                        .send(EngineCmd::ParaSendReply {
                            target_vip: from,
                            payload: reply,
                        })
                        .await;
                }
            }
            if let Some(id) = listener_id {
                let _ = cmd_tx
                    .send(EngineCmd::ParaRemoveListener { listener_id: id })
                    .await;
            }
        }));
        Ok(())
    }

    fn stop_lan_presence_listener(&mut self) {
        if let Some(stop) = self.lan_presence_stop.take() {
            stop.store(true, Ordering::Release);
        }
        if let Some(task) = self.lan_presence_task.take() {
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
        crate::cli_println!("  [1]  Create unit");
        crate::cli_println!("  [2]  Join unit");
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
        let lines = bootstrap::session_home_lines(outcome, &snap.network_id, &snap.virtual_ip);
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
            &snap.network_id,
            &snap.virtual_ip,
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
                term_style::fmt_bang_line(format_args!(" Mint from the CLI client menu [1]."))
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
        crate::cli_println!("  [1]  Create unit");
        crate::cli_println!("  [2]  Join unit");
        crate::cli_println!("  [3]  Exit");
        crate::cli_println!("  -----------");
        crate::cli_print!("> Select [1-3]: ");
        io::stdout().flush()?;
        match self.read_line().await?.as_str() {
            "1" => crate::cli_println!(
                "{}",
                term_style::fmt_bang_line(format_args!(" Mint from the CLI client menu [1]."))
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
        port: u16,
        vip: String,
        _subnet_prefix: u8,
    ) -> Result<()> {
        self.stop_lan_presence_listener();
        // FloatUnit always uses a key-derived /24; prefix is forced to 24.
        let subnet_prefix: u8 = 24;
        let key = MintCrypto::generate_key();
        let vip = {
            let trimmed = vip.trim();
            if trimmed.is_empty() {
                crate::net::claim::random_member_vip_in_unit(&key)
            } else if crate::net::claim::vip_in_floatunit_subnet(&key, trimmed) {
                trimmed.to_string()
            } else {
                return Err(anyhow!(
                    "VIP {trimmed} is outside this FloatUnit /24 (derived from network key); leave VIP empty to auto-pick"
                ));
            }
        };
        crate::cli_println!(
            "{}",
            term_style::fmt_nat_line(format_args!(" Attempting UPnP port mapping..."))
        );
        let local_ip = get_local_ip();
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
                        " Peer appears behind double-NAT/CGNAT (UPnP vs STUN mismatch). \
                         Decentralized join for new peers may be unstable until inbound UDP is reachable. \
                         Prefer port-forward on the router, a host with a public IP, or relay when available."
                    ))
                );
            }
        }

        let network_id = derive_network_id(&key);
        let node_id = hex::encode(rand::random::<[u8; 16]>());

        let candidates =
            ice::gather_candidates(&local_ip, port, stun_ep.as_ref(), upnp_result.as_ref());
        let _ = self.cmd_tx.send(EngineCmd::SetCandidates(candidates)).await;

        let public_invite = encode_invite(&InvitePayload {
            version: INVITE_VERSION,
            protocol: PROTO_UDP,
            key: key.0,
        });

        ensure_netinfo_dir()?;
        self.config
            .set_network_basics(network_id.clone(), vip.clone(), node_id, port);
        self.config.update(|cfg| {
            cfg.crypto_key = hex::encode(key.0);
            cfg.public_invite_code = public_invite.clone();
            cfg.subnet_prefix = 24;
            cfg.decentralized_enabled = true;
            cfg.join_method = "decentralized".to_string();
        });

        #[cfg(windows)]
        {
            let vip_ip = vip
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| anyhow!("invalid member vip: {vip}"))?;
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
                my_vip: vip.clone(),
                my_node_id: self.config.snapshot().node_id.clone(),
                subnet_prefix: self.config.snapshot().subnet_prefix.clamp(8, 30),
                vip_epoch: 0,
                reply: None,
            })
            .await;
        let node_id = self.config.snapshot().node_id.clone();
        let _ = self
            .start_decentralized_engine(None, false, None, &node_id)
            .await;
        self.state = AppState::CommandLoop;
        self.ensure_lan_presence_listener().await?;

        crate::cli_println!();
        crate::cli_println!("  [------------]");
        crate::cli_println!("  │  Unit ID   : {:<44}", network_id);
        crate::cli_println!(
            "  │  VIP       : {:<44}",
            format!("{vip}/{}", self.config.snapshot().subnet_prefix)
        );
        crate::cli_println!("  │> Invite    : {public_invite}");
        crate::cli_println!();
        Ok(())
    }

    async fn handle_join_entry(&mut self) -> Result<()> {
        crate::cli_println!("  Join mode:");
        crate::cli_println!("    [1] Decentralized");
        crate::cli_println!("    [2] Manual");
        crate::cli_print!("  Choose [1/2](1): ");
        io::stdout().flush()?;
        let mode = self.read_line().await?;
        let t = mode.trim();
        if t == "2" {
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
        crate::cli_println!("    [1] Public");
        crate::cli_println!("    [2] LAN");
        crate::cli_print!("  Choose [1/2](1): ");
        io::stdout().flush()?;
        let mode_line = self.read_line().await?;
        let use_public = !(mode_line.trim() == "2");
        crate::cli_print!("  Peer endpoint (ip:port): ");
        io::stdout().flush()?;
        let ep_line = self.read_line().await?;
        let target_endpoint = parse_join_endpoint(ep_line.trim())?;
        Ok(JoinInviteRunOpts {
            use_public,
            skip_share_gate: false,
            target_endpoint: Some(target_endpoint),
        })
    }

    async fn start_decentralized_engine(
        &self,
        network_key: Option<[u8; 32]>,
        is_joiner: bool,
        join_body: Option<Vec<u8>>,
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
    ) -> Result<()> {
        // Self-claimed VIP (may have been rerolled during handshake).
        let vip = if !ack.local_vip.is_empty() {
            ack.local_vip.clone()
        } else {
            self.config.snapshot().virtual_ip.clone()
        };
        let vip_epoch = ack.vip_epoch;
        let subnet: u8 = 24;
        let peer_udp = ack.peer_endpoint;

        ensure_netinfo_dir()?;
        self.config.set_network_basics(
            derive_network_id(&Key(parsed.key)),
            vip.clone(),
            local_node_id.clone(),
            port,
        );
        self.config.update(|cfg| {
            cfg.crypto_key = hex::encode(parsed.key);
            cfg.decentralized_enabled = true;
            cfg.join_method = "decentralized".to_string();
            cfg.subnet_prefix = 24;
            cfg.vip_epoch = vip_epoch;
        });

        #[cfg(windows)]
        {
            let vip_ip = vip
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| anyhow!("invalid self vip: {vip}"))?;
            let snap = self.config.snapshot();
            let ring = effective_wintun_ring_bytes(snap.wintun_ring_bytes);
            let ipv4_metric =
                effective_wintun_ipv4_interface_metric(snap.wintun_ipv4_interface_metric);
            let wintun_prefix = subnet;
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
                my_vip: vip.clone(),
                my_node_id: local_node_id,
                subnet_prefix: subnet,
                vip_epoch,
                reply: None,
            })
            .await;

        let _ = self
            .start_decentralized_engine(None, false, None, &self.config.snapshot().node_id)
            .await;

        self.state = AppState::CommandLoop;
        self.ensure_lan_presence_listener().await?;
        crate::cli_println!("\n	>[ Joined FloatUnit ]");
        crate::cli_println!("   >----------------------<");
        crate::cli_println!("    │  Virtual IP  : {}", vip);
        crate::cli_println!("    │  Peer        : {}", peer_udp);
        Ok(())
    }

    async fn finalize_genesis_join(
        &mut self,
        parsed: &InvitePayload,
        local_node_id: String,
        port: u16,
        vip: String,
        vip_epoch: u64,
        subnet: u8,
    ) -> Result<()> {
        ensure_netinfo_dir()?;
        self.config.set_network_basics(
            derive_network_id(&Key(parsed.key)),
            vip.clone(),
            local_node_id.clone(),
            port,
        );
        self.config.update(|cfg| {
            cfg.crypto_key = hex::encode(parsed.key);
            cfg.decentralized_enabled = true;
            cfg.join_method = "decentralized".to_string();
            cfg.subnet_prefix = 24;
            cfg.vip_epoch = vip_epoch;
        });

        #[cfg(windows)]
        {
            let vip_ip = vip
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| anyhow!("invalid self vip: {vip}"))?;
            let snap = self.config.snapshot();
            let ring = effective_wintun_ring_bytes(snap.wintun_ring_bytes);
            let ipv4_metric =
                effective_wintun_ipv4_interface_metric(snap.wintun_ipv4_interface_metric);
            let wintun_prefix = 24u8;
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
                my_vip: vip.clone(),
                my_node_id: local_node_id,
                subnet_prefix: subnet.clamp(8, 30),
                vip_epoch,
                reply: None,
            })
            .await;

        let _ = self
            .start_decentralized_engine(None, false, None, &self.config.snapshot().node_id)
            .await;

        self.state = AppState::CommandLoop;
        self.ensure_lan_presence_listener().await?;
        crate::cli_println!("\n	>[ Genesis FloatUnit (solo) ]");
        crate::cli_println!("   >----------------------<");
        crate::cli_println!("    │  Virtual IP  : {}", vip);
        Ok(())
    }

    async fn query_discovered_count(&self) -> usize {
        let (tx, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(EngineCmd::QueryDiscoveredCount { reply: tx })
            .await
            .is_err()
        {
            return 0;
        }
        tokio::time::timeout(Duration::from_millis(500), rx)
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or(0)
    }

    async fn handle_join_decentralized(&mut self, invite: &str) -> Result<()> {
        self.stop_lan_presence_listener();
        let parsed = decode_invite(invite)?;
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
        let subnet: u8 = 24;
        let unit_key = Key(parsed.key);
        let (self_vip, vip_replaced) =
            crate::net::claim::resolve_member_vip(&unit_key, &self.config.snapshot().virtual_ip);
        let mut vip_epoch = self.config.snapshot().vip_epoch;
        if vip_replaced {
            vip_epoch = vip_epoch.saturating_add(1);
        }
        let _room = room_id_20b(&unit_key, parsed.protocol);
        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(
                " FloatUnit ID: {}",
                derive_network_id(&unit_key)
            ))
        );
        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(
                " Tracker room_id: {}",
                room_id_hex(&unit_key, parsed.protocol)
            ))
        );
        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(" Self VIP claim: {self_vip}"))
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
            "vip": self_vip,
            "vip_epoch": vip_epoch,
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

        // Persist claim before fanout so genesis / ack finalize share the same VIP.
        self.config.update(|cfg| {
            cfg.virtual_ip = self_vip.clone();
            cfg.vip_epoch = vip_epoch;
            cfg.subnet_prefix = 24;
            cfg.node_id = local_node_id.clone();
        });
        let _ = self
            .cmd_tx
            .send(EngineCmd::SetIdentity {
                my_vip: self_vip.clone(),
                my_node_id: local_node_id.clone(),
                subnet_prefix: subnet,
                vip_epoch,
                reply: None,
            })
            .await;

        self.start_decentralized_engine(Some(parsed.key), true, Some(body.clone()), &local_node_id)
            .await?;

        let deadline_secs = self
            .config
            .snapshot()
            .decentralized_join_deadline_secs
            .max(30);
        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(
                " Waiting for peer ack via tracker discovery (up to {deadline_secs}s)..."
            ))
        );

        let (tx, rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .send(EngineCmd::PrepareJoin {
                join_tx: tx,
                key: Key(parsed.key),
                target: None,
                body: body.clone(),
            })
            .await;

        let ack = match tokio::time::timeout(Duration::from_secs(deadline_secs), rx).await {
            Ok(Ok(Some(ack))) => Some(ack),
            Ok(Ok(None)) => {
                let _ = self.cmd_tx.send(EngineCmd::CancelJoinWait).await;
                return Err(anyhow!("join rejected"));
            }
            Ok(Err(_)) => self.wait_pending_join_ack(Duration::from_secs(3)).await,
            Err(_) => self.wait_pending_join_ack(Duration::from_secs(3)).await,
        };

        if let Some(ack) = ack {
            return self
                .finalize_peer_join_from_ack(ack, &parsed, local_node_id, port)
                .await;
        }

        let _ = self.cmd_tx.send(EngineCmd::CancelJoinWait).await;
        let discovered = self.query_discovered_count().await;
        if discovered == 0 {
            crate::cli_println!(
                "{}",
                term_style::fmt_join_line(format_args!(
                    " No peers discovered — joining as genesis (solo) member."
                ))
            );
            return self
                .finalize_genesis_join(&parsed, local_node_id, port, self_vip, vip_epoch, subnet)
                .await;
        }

        crate::cli_println!(
            "{}",
            term_style::fmt_bang_line(format_args!(
                " Peers seen on tracker but no ack. Retry join when a member is online."
            ))
        );
        Err(anyhow!("join timeout waiting peer ack"))
    }

    pub async fn join_decentralized_code(&mut self, invite: String) -> Result<()> {
        self.handle_join_decentralized(&invite).await
    }

    async fn handle_join(&mut self, invite: &str, opts: JoinInviteRunOpts) -> Result<()> {
        self.stop_lan_presence_listener();
        let parsed = decode_invite(invite)?;
        let target = opts
            .target_endpoint
            .ok_or_else(|| anyhow!("manual join requires peer endpoint (ip:port)"))?;

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
                " FloatUnit ID: {}",
                crate::crypto::derive_network_id(&Key(parsed.key))
            ))
        );
        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(" Target peer: {}", target))
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
                    "{}",
                    term_style::fmt_ok_line(format_args!(
                        " UPnP mapping active (ext_port={}, ext_ip={}).",
                        m.ext_port, m.external_ip
                    ))
                ),
                None => crate::cli_println!(
                    "{}",
                    term_style::fmt_info_line(format_args!(
                        " failed (router unsupported/disabled). Continuing without UPnP."
                    ))
                ),
            }
        }
        if let Some(ref m) = upnp_result {
            self.upnp_set_mapping(m.clone());
        }

        let stun_ep = if use_public {
            crate::cli_print!(
                "{}",
                term_style::fmt_join_line(format_args!(" Gathering ICE candidates via STUN..."))
            );
            io::stdout().flush()?;
            self.query_public_endpoint_from_engine(std::time::Duration::from_secs(3))
                .await
        } else {
            crate::cli_println!(
                "{}",
                term_style::fmt_join_line(format_args!(" LAN mode — using host candidate only..."))
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
                                " [warn] Share STUN endpoint with target peer."
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
                            " Share this endpoint with the peer on the CLI client, then punching starts automatically."
                        ))
                    );
                } else {
                    crate::cli_println!("{}", term_style::fmt_join_line(format_args!(" Share this with the peer, then press Enter to start manual retry punching...")));
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
                term_style::fmt_join_line(format_args!(" Starting hole punch toward peer..."))
            );
        } else {
            crate::cli_println!(
                "{}",
                term_style::fmt_join_line(format_args!(" LAN mode > hole punch toward peer."))
            );
        }

        let subnet: u8 = 24;
        let unit_key = Key(parsed.key);
        let (self_vip, vip_replaced) =
            crate::net::claim::resolve_member_vip(&unit_key, &self.config.snapshot().virtual_ip);
        let mut vip_epoch = self.config.snapshot().vip_epoch;
        if vip_replaced {
            vip_epoch = vip_epoch.saturating_add(1);
        }
        self.config.update(|cfg| {
            cfg.virtual_ip = self_vip.clone();
            cfg.vip_epoch = vip_epoch;
            cfg.subnet_prefix = 24;
            cfg.node_id = local_node_id.clone();
        });
        let _ = self
            .cmd_tx
            .send(EngineCmd::SetIdentity {
                my_vip: self_vip.clone(),
                my_node_id: local_node_id.clone(),
                subnet_prefix: subnet,
                vip_epoch,
                reply: None,
            })
            .await;

        let body = serde_json::json!({
            "proto_ver": WIRE_PROTOCOL_VERSION,
            "node_id": local_node_id.clone(),
            "vip": self_vip,
            "vip_epoch": vip_epoch,
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
                bases: vec![target],
                log_stages: true,
            })
            .await;

        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(" Waiting for peer acknowledgment..."))
        );
        let mut got_ack: Option<JoinAck> = None;
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
                    target: Some(target),
                    body: body.clone(),
                })
                .await;

            match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
                Ok(Ok(Some(ack))) => {
                    crate::cli_println!(
                        "{}",
                        term_style::fmt_ok_line(format_args!(
                            " Peer ack from {} (vip={})",
                            ack.peer_endpoint, ack.peer_vip
                        ))
                    );
                    got_ack = Some(ack);
                    break;
                }
                Ok(Ok(None)) => {
                    let _ = self
                        .cmd_tx
                        .send(EngineCmd::StopPunchWorkflow {
                            key: JOIN_HANDSHAKE_PUNCH_KEY.to_string(),
                        })
                        .await;
                    return Err(anyhow!("join rejected"));
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

        let Some(ack) = got_ack else {
            crate::cli_println!(
                "{}",
                term_style::fmt_bang_line(format_args!(
                    " Peer did not respond within the join retry window (~{} seconds max).",
                    20
                ))
            );
            return Err(anyhow!("join timeout waiting peer ack"));
        };

        self.finalize_peer_join_from_ack(ack, &parsed, local_node_id, port)
            .await
    }

    pub async fn join_invite_code(
        &mut self,
        invite: String,
        lan_mode: Option<bool>,
        endpoint: String,
    ) -> Result<()> {
        let target_endpoint = parse_join_endpoint(endpoint.trim())?;
        let opts = JoinInviteRunOpts::from_ipc(lan_mode, target_endpoint);
        self.handle_join(&invite, opts).await
    }

    /// Broadcast MPHI with local network_id; collect matching MPHR replies.
    /// Requires a configured member unit (network_id + crypto_key + virtual_ip).
    pub async fn discover_lan_members(&mut self) -> Result<Vec<crate::ipc::LanMemberPeer>> {
        let snap = self.config.snapshot();
        if snap.network_id.is_empty() || snap.crypto_key.is_empty() || snap.virtual_ip.is_empty() {
            return Err(anyhow!(
                "unit not configured — network_id, crypto_key, and virtual_ip required"
            ));
        }
        let local_ip = get_local_ip();
        let listen_port = snap.listen_port.max(7878);
        let local_node_id = snap.node_id.clone();
        let network_id = snap.network_id.clone();
        let local_candidates = local_only_para_candidates(&snap);
        drop(snap);

        let (sig_tx, mut sig_rx) = mpsc::channel::<ParaSignal>(2048);
        let listener_id = register_para_listener(&self.cmd_tx, sig_tx, false).await;

        let session_id = hex::encode(rand::random::<[u8; 8]>());
        let targets = para_lan_discovery_targets(&local_ip, listen_port);
        let hello = json!({
            "node_id": local_node_id,
            "public_ip": local_ip,
            "public_port": listen_port,
            "network_id": network_id,
            "ts_ms": now_epoch_ms(),
            "candidates": local_candidates,
            "session_id": session_id,
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
        let mut members: HashMap<String, crate::ipc::LanMemberPeer> = HashMap::new();
        while Instant::now() < deadline {
            let remain = deadline.saturating_duration_since(Instant::now());
            if remain.is_zero() {
                break;
            }
            match tokio::time::timeout(remain, sig_rx.recv()).await {
                Ok(Some(ParaSignal::ReplyReceived {
                    from,
                    network_id: reply_nid,
                    node_id,
                    responder_vip,
                    ..
                })) => {
                    if reply_nid != network_id || responder_vip.is_empty() {
                        continue;
                    }
                    if lan_reply_is_self(&local_node_id, &local_ip, listen_port, from, &node_id) {
                        continue;
                    }
                    members.entry(responder_vip.clone()).or_insert_with(|| {
                        crate::ipc::LanMemberPeer {
                            network_id: reply_nid,
                            from: from.to_string(),
                            node_id,
                        }
                    });
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        unregister_para_listener(&self.cmd_tx, listener_id).await;
        let mut list: Vec<_> = members.into_values().collect();
        list.sort_by(|a, b| a.network_id.cmp(&b.network_id).then(a.from.cmp(&b.from)));
        Ok(list)
    }

    /// Punch private candidates to a LAN member and send PrepareJoin (claim).
    /// Target must be a private IP:port. Requires configured member unit.
    pub async fn assist_lan_member(&mut self, target_str: String) -> Result<()> {
        let snap = self.config.snapshot();
        if snap.network_id.is_empty() || snap.crypto_key.is_empty() || snap.virtual_ip.is_empty() {
            return Err(anyhow!(
                "unit not configured — network_id, crypto_key, and virtual_ip required"
            ));
        }
        let listen_port = snap.listen_port.max(7878);
        let target = parse_vip_signal_target(target_str.trim(), listen_port)?.1;
        if !is_rfc1918_private_ip(target.ip()) {
            return Err(anyhow!(
                "LAN assist target must be a private IPv4 address (got {target})"
            ));
        }
        let local_ip = get_local_ip();
        if lan_reply_is_self(&snap.node_id, &local_ip, listen_port, target, "") {
            return Err(anyhow!(
                "LAN assist target resolves to this member; select a different LAN peer"
            ));
        }
        let key_hex = snap.crypto_key.clone();
        let local_node_id = snap.node_id.clone();
        let self_vip = snap.virtual_ip.clone();
        let vip_epoch = snap.vip_epoch;
        let subnet = snap.subnet_prefix.clamp(8, 30);
        drop(snap);

        let key_arr = parse_key_hex_32(&key_hex)?;
        let (key_tx, key_rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCmd::SetCryptoKey(Key(key_arr), Some(key_tx)))
            .await?;
        let _ = tokio::time::timeout(Duration::from_secs(1), key_rx).await;

        let candidates = ice::gather_candidates(&local_ip, listen_port, None, None);
        let _ = self
            .cmd_tx
            .send(EngineCmd::SetCandidates(candidates.clone()))
            .await;

        let private_targets = filter_private_socket_addrs(&[target]);
        let candidates_to_punch = if private_targets.is_empty() {
            vec![target]
        } else {
            private_targets
        };

        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(
                " LAN assist: punching toward {target}\u{2026}"
            ))
        );
        let _ = self.run_lan_punch(&candidates_to_punch, &self_vip, 0).await;

        let body = serde_json::json!({
            "proto_ver": WIRE_PROTOCOL_VERSION,
            "node_id": local_node_id.clone(),
            "vip": self_vip,
            "vip_epoch": vip_epoch,
            "ts_ms": now_epoch_ms(),
            "rtt_hint_ms": 100,
            "nat_hint": "lan",
            "candidates": candidates,
        })
        .to_string()
        .into_bytes();

        crate::cli_println!(
            "{}",
            term_style::fmt_join_line(format_args!(
                " LAN assist: sending PrepareJoin to {target}\u{2026}"
            ))
        );
        let (tx, rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .send(EngineCmd::PrepareJoin {
                join_tx: tx,
                key: Key(key_arr),
                target: Some(target),
                body,
            })
            .await;

        let subnet_val = subnet;
        let deadline_secs = self
            .config
            .snapshot()
            .decentralized_join_deadline_secs
            .max(30);
        let ack = match tokio::time::timeout(Duration::from_secs(deadline_secs), rx).await {
            Ok(Ok(Some(ack))) => ack,
            _ => {
                let _ = self.cmd_tx.send(EngineCmd::CancelJoinWait).await;
                return Err(anyhow!("LAN assist: no acknowledgment from {target}"));
            }
        };

        let parsed = InvitePayload {
            key: key_arr,
            version: INVITE_VERSION,
            protocol: PROTO_UDP,
        };
        let _ = subnet_val; // subnet comes from JoinAck.subnet_prefix
        self.finalize_peer_join_from_ack(ack, &parsed, local_node_id, listen_port)
            .await
    }

    async fn run_lan_punch(
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
            .wait_for_lan_punch_ready(
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

    async fn wait_for_lan_punch_ready(
        &self,
        remote_vip: &str,
        peer_candidates: &[SocketAddr],
        phase_start: std::time::Instant,
        deadline: std::time::Instant,
        min_wall_ms: u64,
    ) -> bool {
        wait_for_lan_punch_ready(
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

    async fn sync_engine_from_saved_profile(&self) -> Result<()> {
        let snap = self.config.snapshot();
        if snap.virtual_ip.is_empty() || snap.network_id.is_empty() || snap.crypto_key.is_empty() {
            return Ok(());
        }
        let node_id = snap.node_id.trim();
        if node_id.is_empty() {
            return Ok(());
        }

        let key_raw = match parse_key_hex_32(snap.crypto_key.trim()) {
            Ok(k) => k,
            Err(_) => return Ok(()),
        };
        let unit_key = Key(key_raw);
        let (vip, vip_replaced) =
            crate::net::claim::resolve_member_vip(&unit_key, snap.virtual_ip.trim());
        let mut vip_epoch = snap.vip_epoch;
        if vip_replaced {
            vip_epoch = vip_epoch.saturating_add(1);
            self.config.update(|cfg| {
                cfg.virtual_ip = vip.clone();
                cfg.vip_epoch = vip_epoch;
                cfg.subnet_prefix = 24;
            });
        } else if snap.subnet_prefix != 24 {
            self.config.update(|cfg| cfg.subnet_prefix = 24);
        }

        let (key_tx, key_rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCmd::SetCryptoKey(unit_key, Some(key_tx)))
            .await?;
        let _ = tokio::time::timeout(Duration::from_secs(1), key_rx).await;

        let (id_tx, id_rx) = oneshot::channel();
        self.cmd_tx
            .send(EngineCmd::SetIdentity {
                my_vip: vip,
                my_node_id: node_id.to_string(),
                subnet_prefix: 24,
                vip_epoch,
                reply: Some(id_tx),
            })
            .await?;
        let _ = tokio::time::timeout(Duration::from_secs(1), id_rx).await;

        if snap.decentralized_enabled {
            let node_id = snap.node_id.clone();
            let _ = self
                .start_decentralized_engine(None, false, None, &node_id)
                .await;
        }
        Ok(())
    }

    fn handle_list(&self) {
        let s = self.config.snapshot();
        crate::cli_println!();
        crate::cli_println!(" --[STATUS]");
        crate::cli_println!("-=======================>:>");
        crate::cli_println!("  > Unit ID     : {}", s.network_id);
        crate::cli_println!("  > Virtual IP  : {}", s.virtual_ip);
        crate::cli_println!("  > Node ID     : {}", s.node_id);
        crate::cli_println!("  > Listen Port : {}", s.listen_port);
        crate::cli_println!("  > Peers       : {}/{}", s.peers.len(), MEMBER_ROSTER_MAX);
        if !s.public_invite_code.is_empty() {
            crate::cli_println!("-=- Invite ID <-> {}", s.public_invite_code);
        }

        let routes = self.routing.read().snapshot();
        if !routes.is_empty() {
            crate::cli_println!("-==> Routing Table ({} entries)", routes.len());
            for (vip, entry) in &routes {
                let rtt = if entry.last_rtt_ms < 0 {
                    "  --".to_string()
                } else {
                    format!("{:4}ms", entry.last_rtt_ms)
                };
                crate::cli_println!(
                    "  0│  {:<15}  {:21}  RTT:{rtt}  Q:{:3}  {:?}",
                    vip,
                    entry.endpoint,
                    entry.quality_score,
                    entry.state,
                );
            }
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
            "  congestion: congestion_enabled={} gain={:.2} hol_escape_ms={} initial_rate_bps={:.0} add_inc_bps={:.0} min_dec={:.2} rate_smooth={:.2} min_rate_bps={:.0} max_rate_bps={:.0} loss_md={:.2} burst_cap_bytes={} delivery_window_ms={} delivery_ewma_a={:.2} delivery_anchor={:.2} delivery_decouple={:.2} rtt_base_tracking={} loss_classifier={} target_q_delay_ms={} loss_thr={:.2} base_rtt_window_s={} stale_windows={} owd_jump_ms={} owd_rtt_consistency_ms={} owd_prefer_after={} probe_interval_ms={} fec_recovery_recency_ms={}",
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
            a.congestion.owd_rtt_consistency_ms,
            a.congestion.owd_prefer_after_samples,
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
                crate::cli_println!(
                    "\n{}",
                    term_style::fmt_ok_line(format_args!(" [Saved config]"))
                );
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
                    term_style::fmt_ok_line(format_args!(
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
            "{}",
            term_style::fmt_ok_line(format_args!(
                " Performance settings reloaded from NetInfo/config.toml (applied)."
            ))
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
        lines.push("  [--- traffic ---]".to_string());
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
        lines.push("  [--- buffers / queues ---]".to_string());
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
        lines.push("  [--- runtime ---]".to_string());
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
                    "  pmtud_pmar_ignored     : {}",
                    m.pmtud_pmar_ignored.load(Ordering::Relaxed)
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
                    "pmtud_pmar_ignored",
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
                    crate::cli_println!(
                        "{}",
                        term_style::fmt_ok_line(format_args!(" MTU set to {mtu} on '{name}'."))
                    );
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
                            "{}",
                            term_style::fmt_ok_line(format_args!(
                                " IPv4 interface metric set to {metric_for_apply} on '{name}'."
                            ))
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
            term_style::fmt_ok_line(format_args!(" Saved to NetInfo/config.toml."))
        );
        Ok(())
    }

    async fn handle_stun(&mut self) -> Result<()> {
        let result = self
            .query_public_endpoint_from_engine(std::time::Duration::from_secs(5))
            .await;
        match result {
            Some(ep) => {
                crate::cli_println!(" -> Public endpoint: {}:{}", ep.ip, ep.port);
                let snap = self.config.snapshot();
                if !snap.network_id.is_empty() && !snap.crypto_key.is_empty() {
                    if let Ok(key) = parse_key_hex_32(&snap.crypto_key) {
                        let invite = encode_invite(&InvitePayload {
                            version: INVITE_VERSION,
                            protocol: PROTO_UDP,
                            key,
                        });
                        crate::cli_println!(" -> FloatUnit ID: {invite}");
                    }
                }
            }
            None => crate::cli_println!(
                "{}",
                term_style::fmt_info_line(format_args!(" No STUN response"))
            ),
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
                " Punch started toward {target_ip}:{target_port}."
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
        let routes = self.routing.read().snapshot();
        for (vip, entry) in routes {
            if vip == s.virtual_ip {
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
                term_style::fmt_info_line(format_args!(" No peers connected."))
            );
            return Ok(());
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

    async fn handle_remove(&mut self) -> Result<()> {
        self.stop_lan_presence_listener();
        let snap = self.config.snapshot();
        if !snap.virtual_ip.is_empty() {
            let event_id = format!("leave-{}-{}", snap.node_id, now_epoch_ms());
            let _ = self.cmd_tx.try_send(EngineCmd::BroadcastLeave {
                node_id: snap.node_id.clone(),
                vip: snap.virtual_ip.clone(),
                vip_epoch: snap.vip_epoch,
                event_id,
            });
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

        crate::cli_println!(
            "{}",
            term_style::fmt_ok_line(format_args!(" session cleared; restarting in 3s…"))
        );
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
        self.stop_lan_presence_listener();
        let snap = self.config.snapshot();
        if !snap.virtual_ip.is_empty() {
            let event_id = format!("leave-{}-{}", snap.node_id, now_epoch_ms());
            let _ = self.cmd_tx.try_send(EngineCmd::BroadcastLeave {
                node_id: snap.node_id.clone(),
                vip: snap.virtual_ip.clone(),
                vip_epoch: snap.vip_epoch,
                event_id,
            });
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
            "{}",
            term_style::fmt_ok_line(format_args!(
                " Performance settings reset to factory defaults."
            ))
        );
        Ok(())
    }

    /// Persist VIP identity after an engine fight/reroll and recreate Wintun (/24).
    pub async fn apply_identity_changed(&mut self, new_vip: &str, vip_epoch: u64) -> Result<()> {
        self.config.update(|cfg| {
            cfg.virtual_ip = new_vip.to_string();
            cfg.vip_epoch = vip_epoch;
        });

        #[cfg(windows)]
        {
            if let Some(ref old_adapter) = self.vni {
                let Ok(vip_ip) = new_vip.parse::<std::net::Ipv4Addr>() else {
                    crate::cli_eprintln!(
                        "{}",
                        term_style::fmt_bang_line(format_args!(
                            " Identity change: invalid VIP '{new_vip}'"
                        ))
                    );
                    return Ok(());
                };
                let snap = self.config.snapshot();
                let adapter_name = old_adapter.name().to_string();
                *self.vni_slot.write() = None;
                old_adapter.close();
                self.vni = None;

                let mtu_to_apply = snap.adapter_mtu;
                let ring = effective_wintun_ring_bytes(snap.wintun_ring_bytes);
                let ipv4_metric =
                    effective_wintun_ipv4_interface_metric(snap.wintun_ipv4_interface_metric);
                let wintun_prefix = 24u8;
                let adapter_name_for_task = adapter_name.clone();
                let new_adapter =
                    tokio::task::spawn_blocking(move || -> Result<Arc<WintunAdapter>> {
                        let adapter = Arc::new(
                            WintunAdapter::create(
                                &adapter_name_for_task,
                                vip_ip,
                                wintun_prefix,
                                ring,
                                ipv4_metric,
                            )
                            .map_err(|e| {
                                anyhow!("failed to recreate Wintun after identity change: {e}")
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
                crate::cli_println!(
                    "{}",
                    term_style::fmt_info_line(format_args!(
                        " Identity changed: Wintun recreated for {new_vip}/{wintun_prefix}"
                    ))
                );
            }
        }

        #[cfg(not(windows))]
        {
            let _ = (new_vip, vip_epoch);
        }

        Ok(())
    }

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
        crate::cli_println!("\n#===--> COMMANDS ===#");
        crate::cli_println!("   > [ lan ] - LAN discover");
        crate::cli_println!("   > [ list ] - Routing table");
        crate::cli_println!("   > [ ping ] - Ping peers");
        crate::cli_println!("   > [ stun ] - Query public endpoint");
        crate::cli_println!("   > [ stop ] - Disconnect and quit");
        crate::cli_println!("   > [ remove ] - Clear session and config");
        crate::cli_println!("   > [ runtime ] - Performance live view");
        crate::cli_println!("   > [ punch <ip:port> ] - Manual NAT hole punch");
        crate::cli_println!("   > [ autoclear-on|off ] - Auto clear terminal");
        crate::cli_println!("   > [ config show|reload|reset ] - config.toml");
        crate::cli_println!("-----");
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

fn local_only_para_candidates(snap: &crate::config::NetworkConfig) -> Vec<ParaCandidate> {
    vec![ParaCandidate {
        ip: get_local_ip(),
        port: snap.listen_port.max(7878),
        kind: "local".to_string(),
    }]
}

/// UDP targets for LAN discover broadcasts.
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

fn lan_reply_is_self(
    local_node_id: &str,
    local_ip: &str,
    listen_port: u16,
    from: SocketAddr,
    reply_node_id: &str,
) -> bool {
    if !local_node_id.is_empty() && !reply_node_id.is_empty() && reply_node_id == local_node_id {
        return true;
    }
    if let Ok(ip) = local_ip.parse::<Ipv4Addr>() {
        return from == SocketAddr::from((ip, listen_port));
    }
    false
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

async fn wait_for_lan_punch_ready(
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

fn parse_join_endpoint(raw: &str) -> Result<SocketAddr> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(anyhow!("peer endpoint (ip:port) is required"));
    }
    raw.parse::<SocketAddr>()
        .map_err(|_| anyhow!("invalid peer endpoint (expected ip:port): {raw}"))
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
            return Err(anyhow!("IPv6 is not supported"));
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
    use super::punch_route_ready;
    use crate::routing::{RouteState, RoutingTable};
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
}

#[cfg(test)]
mod lan_helpers_tests {
    use super::{filter_private_socket_addrs, lan_reply_is_self, para_lan_discovery_targets};
    use crate::pmtud::is_rfc1918_private_ip;
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

    #[test]
    fn filter_private_only_candidates_returns_private() {
        let addrs: Vec<SocketAddr> = vec![
            "10.0.0.5:7878".parse().unwrap(),
            "172.16.0.1:7878".parse().unwrap(),
            "203.0.113.1:7878".parse().unwrap(),
        ];
        let private = filter_private_socket_addrs(&addrs);
        assert_eq!(private.len(), 2);
        assert!(private.iter().all(|a| is_rfc1918_private_ip(a.ip())));
    }

    #[test]
    fn lan_reply_is_self_by_node_id() {
        let from: SocketAddr = "192.168.1.10:7878".parse().unwrap();
        assert!(lan_reply_is_self(
            "node-local",
            "192.168.1.9",
            7878,
            from,
            "node-local"
        ));
    }

    #[test]
    fn lan_reply_is_self_by_endpoint() {
        let from: SocketAddr = "192.168.1.9:7878".parse().unwrap();
        assert!(lan_reply_is_self(
            "node-local",
            "192.168.1.9",
            7878,
            from,
            "node-remote"
        ));
    }

    #[test]
    fn lan_reply_from_other_peer_is_not_self() {
        let from: SocketAddr = "192.168.1.10:7878".parse().unwrap();
        assert!(!lan_reply_is_self(
            "node-local",
            "192.168.1.9",
            7878,
            from,
            "node-remote"
        ));
    }
}

#[cfg(test)]
mod same_key_lan_discover_tests {
    use crate::net::engine::ParaSignal;
    use std::net::SocketAddr;

    fn make_hello_signal(network_id: &str, session_id: &str) -> ParaSignal {
        ParaSignal::HelloReceived {
            from: "192.168.1.10:7878".parse::<SocketAddr>().unwrap(),
            public_ip: "192.168.1.10".into(),
            public_port: 7878,
            network_id: network_id.into(),
            node_id: "nodeA".into(),
            candidates: vec![],
            start_at_ms: 0,
            session_id: session_id.into(),
        }
    }

    fn make_reply_signal(network_id: &str, responder_vip: &str) -> ParaSignal {
        ParaSignal::ReplyReceived {
            from: "192.168.1.11:7878".parse::<SocketAddr>().unwrap(),
            public_ip: "192.168.1.11".into(),
            public_port: 7878,
            network_id: network_id.into(),
            node_id: "nodeB".into(),
            candidates: vec![],
            agreed_start_at_ms: 0,
            session_id: "sess1".into(),
            responder_vip: responder_vip.into(),
        }
    }

    #[test]
    fn hello_signal_carries_network_id() {
        let sig = make_hello_signal("net-abc", "sess1");
        if let ParaSignal::HelloReceived {
            network_id,
            session_id,
            ..
        } = sig
        {
            assert_eq!(network_id, "net-abc");
            assert_eq!(session_id, "sess1");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn reply_signal_carries_responder_vip_not_key() {
        let sig = make_reply_signal("net-abc", "10.0.0.1");
        if let ParaSignal::ReplyReceived {
            responder_vip,
            network_id,
            ..
        } = sig
        {
            assert_eq!(responder_vip, "10.0.0.1");
            assert_eq!(network_id, "net-abc");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn mismatched_network_id_is_ignored_by_presence_listener() {
        let local_network_id = "net-abc";
        let sig = make_hello_signal("net-xyz", "sess1");
        if let ParaSignal::HelloReceived { network_id, .. } = sig {
            assert_ne!(
                network_id, local_network_id,
                "mismatch should not trigger reply"
            );
        }
    }

    #[test]
    fn matching_network_id_triggers_reply() {
        let local_network_id = "net-abc";
        let sig = make_hello_signal("net-abc", "sess2");
        if let ParaSignal::HelloReceived { network_id, .. } = sig {
            assert_eq!(network_id, local_network_id, "match should trigger reply");
        }
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
