//! VPN daemon: engine + full `Cli` session host; serves IPC to thin CLI clients.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::task::LocalSet;

use crate::bootstrap::{self, BootstrapSnapshot, ReconnectOutcome};
use crate::cli::Cli;
use crate::cli_emit::{begin_capture, end_capture, set_daemon_ui_bus};
use crate::vpn_controller::VpnController;

fn ipc_response_from_capture(result: Result<()>, mut lines: Vec<String>) -> IpcResponse {
    if let Err(e) = result {
        lines.push(format!("[error] {e}"));
    }
    IpcResponse::Ok { lines }
}
use crate::config::ConfigManager;
use crate::cpu_affinity;
use crate::engine_bootstrap::build_engine_runtime;
use crate::ipc::{self, IpcRequest, IpcResponse};
use crate::net::engine::EngineCmd;
use crate::netinfo::{self, ensure_netinfo_dir};
use crate::process_priority;
use crate::profile;

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

pub struct DaemonState {
    pub controller: VpnController,
}

impl DaemonState {
    fn cli_lock(&self) -> parking_lot::MutexGuard<'_, Cli> {
        self.controller.cli.lock()
    }
}

pub async fn run_daemon() -> Result<()> {
    #[cfg(windows)]
    crate::process_display::set_task_manager_name("CoreUnit");

    ensure_netinfo_dir()?;
    let config_path = netinfo::config_path()?;
    let config = ConfigManager::new(config_path);
    let _ = config.load();

    let snap = config.snapshot();
    process_priority::apply_startup_process_priority(snap.process_priority_level);
    cpu_affinity::apply_startup_cpu_affinity(&snap.cpu_affinity);

    #[cfg(windows)]
    crate::daemon::daemon_win::ensure_wintun_dll()?;

    let rt = build_engine_runtime(config.clone()).await?;
    let boot_cmd_tx = rt.cmd_tx.clone();
    let initial_pacing = rt.initial_pacing;

    let cli = Cli::new(
        rt.config.clone(),
        rt.routing,
        rt.cmd_tx,
        rt.tun_from_tun_tx,
        rt.tun_inject_rx,
        Some(rt.peer_cache_reset_tx),
        rt.owner_vip_pool,
        Some(rt.engine_metrics),
        rt.runtime_trace,
        true, // headless: all prompts on CLI client
    );

    set_daemon_ui_bus(rt.ui.clone());
    let controller = VpnController::new(cli, rt.config.clone(), rt.ui.clone());
    let state = Arc::new(DaemonState { controller });

    let engine = rt.engine;
    let local = LocalSet::new();
    local.spawn_local(async move {
        engine.run().await;
    });

    let ui_srv = state.controller.ui.clone();
    local.spawn_local(async move {
        let _ = run_ui_event_server(ui_srv).await;
    });

    local
        .run_until(async {
            let _ = boot_cmd_tx.send(EngineCmd::SetPacing(initial_pacing)).await;
            let state_boot = state.clone();
            tokio::task::spawn_local(async move {
                run_daemon_bootstrap_task(state_boot).await;
            });

            let state_ipc = state.clone();
            run_ipc_server(state_ipc).await
        })
        .await?;

    Ok(())
}

async fn run_daemon_bootstrap_task(state: Arc<DaemonState>) {
    *state.controller.bootstrap.write() = BootstrapSnapshot::pending();

    let peer_defer = match {
        let mut c = state.cli_lock();
        c.daemon_bootstrap_before_reconnect().await
    } {
        Ok(v) => v,
        Err(e) => {
            let _ = state
                .controller
                .ui
                .emit_stderr(format!("daemon bootstrap (pre): {e}"));
            false
        }
    };

    let outcome = if peer_defer {
        let reconnect_fut = async {
            let mut c = state.cli_lock();
            c.parasitic_auto_reconnect().await
        };
        match tokio::time::timeout(
            Duration::from_secs(bootstrap::PARA_AUTO_RECONNECT_DEADLINE_SECS),
            reconnect_fut,
        )
        .await
        {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                let _ = state
                    .controller
                    .ui
                    .emit_stderr(format!("daemon parasitic auto-reconnect: {e}"));
                ReconnectOutcome::Failed
            }
            Err(_) => ReconnectOutcome::TimedOut,
        }
    } else {
        ReconnectOutcome::Skipped
    };

    let snapshot = match {
        let mut c = state.cli_lock();
        c.daemon_bootstrap_finalize(outcome, peer_defer).await
    } {
        Ok(s) => s,
        Err(e) => {
            let _ = state
                .controller
                .ui
                .emit_stderr(format!("daemon bootstrap (finalize): {e}"));
            BootstrapSnapshot {
                complete: true,
                parasitic_attempted: peer_defer,
                outcome: Some(if peer_defer {
                    ReconnectOutcome::Failed
                } else {
                    ReconnectOutcome::Skipped
                }),
                home_lines: vec![],
            }
        }
    };
    let session_ready = snapshot.outcome.is_some();
    // Publish home_lines before SessionReady so TakeSessionHome cannot race empty.
    *state.controller.bootstrap.write() = snapshot;
    if session_ready {
        crate::cli_emit::emit_session_ready();
    }
}

async fn run_ui_event_server(ui: crate::ui_events::UiSink) -> Result<()> {
    use std::net::SocketAddr;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    let addr: SocketAddr = ipc::IPC_UI_ADDR.parse()?;
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (mut stream, _) = listener.accept().await?;
        let ui_conn = ui.clone();
        tokio::task::spawn_local(async move {
            let len = match stream.read_u32_le().await {
                Ok(n) => n,
                Err(_) => return,
            };
            if len > 1024 * 1024 {
                return;
            }
            let mut buf = vec![0u8; len as usize];
            if stream.read_exact(&mut buf).await.is_err() {
                return;
            }
            let sub: ipc::UiSubscribe = match bincode::deserialize(&buf) {
                Ok(s) => s,
                Err(_) => return,
            };
            let replay = ui_conn.replay(sub.replay_lines);
            if ipc::write_ui_frame(&mut stream, &ipc::UiEventFrame::Replay(replay))
                .await
                .is_err()
            {
                return;
            }
            let mut rx = ui_conn.subscribe();
            loop {
                match rx.recv().await {
                    Ok(line) => {
                        let encoded = line.encode();
                        if ipc::write_ui_frame(&mut stream, &ipc::UiEventFrame::Live(encoded))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
        });
    }
}

async fn run_ipc_server(state: Arc<DaemonState>) -> Result<()> {
    use std::net::SocketAddr;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    let addr: SocketAddr = ipc::IPC_ADDR.parse()?;
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (mut stream, _) = listener.accept().await?;
        let state_conn = state.clone();
        tokio::task::spawn_local(async move {
            let mut session_client = false;
            let mut disconnect_accounted = false;
            loop {
                let len = match stream.read_u32_le().await {
                    Ok(n) => n,
                    Err(_) => break,
                };
                if len > 16 * 1024 * 1024 {
                    break;
                }
                let mut buf = vec![0u8; len as usize];
                if stream.read_exact(&mut buf).await.is_err() {
                    break;
                }
                let req: IpcRequest = match bincode::deserialize(&buf) {
                    Ok(r) => r,
                    Err(_) => break,
                };
                if !session_client && !matches!(req, IpcRequest::Ping) {
                    session_client = true;
                    ipc::on_client_connected();
                }
                let exit_daemon = matches!(req, IpcRequest::ShutdownGraceful);
                let is_client_disconnect = matches!(req, IpcRequest::ClientDisconnect);
                let resp = handle_ipc(state_conn.clone(), req).await;
                if is_client_disconnect {
                    disconnect_accounted = true;
                }
                if ipc::write_response_frame(&mut stream, &resp).await.is_err() {
                    break;
                }
                if exit_daemon {
                    std::process::exit(0);
                }
            }
            if session_client && !disconnect_accounted {
                let _ = handle_ipc(state_conn, IpcRequest::ClientDisconnect).await;
            }
        });
    }
}

async fn handle_ipc(state: Arc<DaemonState>, req: IpcRequest) -> IpcResponse {
    match req {
        IpcRequest::Ping => IpcResponse::Pong,
        IpcRequest::HasActiveProfile => {
            let snap = state.controller.config.snapshot();
            IpcResponse::Bool(profile::has_active_profile(snap.as_ref()))
        }
        IpcRequest::BootstrapSnapshot => {
            let snap = state.controller.bootstrap.read().clone();
            let payload = bincode::serialize(&snap).unwrap_or_default();
            IpcResponse::BootstrapSnapshot { payload }
        }
        IpcRequest::TakeSessionHome => {
            let lines = std::mem::take(&mut state.controller.bootstrap.write().home_lines);
            IpcResponse::Ok { lines }
        }
        IpcRequest::ReloadConfigFromDisk => {
            begin_capture();
            let result = {
                let mut cli = state.cli_lock();
                cli.apply_config_reload().await
            };
            let captured = end_capture();
            ipc_response_from_capture(result, captured)
        }
        IpcRequest::ProcessLine { line } => {
            begin_capture();
            let result = {
                let mut cli = state.cli_lock();
                cli.process_command(line).await
            };
            let captured = end_capture();
            ipc_response_from_capture(result, captured)
        }
        IpcRequest::ShutdownGraceful => {
            SHUTDOWN_REQUESTED.store(true, Ordering::Release);
            {
                let mut cli = state.cli_lock();
                cli.handle_exit().await;
            }
            IpcResponse::Ok { lines: vec![] }
        }
        IpcRequest::CreateNetwork {
            name,
            listen_port,
            owner_vip,
            subnet_prefix,
        } => {
            begin_capture();
            let result = {
                let mut cli = state.cli_lock();
                cli.create_network_with_params(name, listen_port, owner_vip, subnet_prefix)
                    .await
            };
            let captured = end_capture();
            ipc_response_from_capture(result, captured)
        }
        IpcRequest::JoinParasitic {
            peer_vip,
            self_vip,
            upnp_port,
        } => {
            begin_capture();
            let result = {
                let mut cli = state.cli_lock();
                cli.join_parasitic_with_params(peer_vip, self_vip, upnp_port)
                    .await
            };
            let captured = end_capture();
            ipc_response_from_capture(result, captured)
        }
        IpcRequest::ResetPerformanceDefaults => {
            begin_capture();
            let result = {
                let mut cli = state.cli_lock();
                cli.apply_performance_defaults().await
            };
            let captured = end_capture();
            ipc_response_from_capture(result, captured)
        }
        IpcRequest::JoinInvite { invite, lan_mode } => {
            begin_capture();
            let result = {
                let mut cli = state.cli_lock();
                cli.join_invite_code(invite, lan_mode).await
            };
            let captured = end_capture();
            ipc_response_from_capture(result, captured)
        }
        IpcRequest::JoinDecentralized { invite } => {
            begin_capture();
            let result = {
                let mut cli = state.cli_lock();
                cli.join_decentralized_code(invite).await
            };
            let captured = end_capture();
            ipc_response_from_capture(result, captured)
        }
        IpcRequest::RuntimeSnapshot => {
            let lines = {
                let cli = state.cli_lock();
                cli.runtime_snapshot_display_lines().await
            };
            let payload = bincode::serialize(&lines).unwrap_or_default();
            IpcResponse::RuntimeSnapshot { payload }
        }
        IpcRequest::ClientDisconnect => {
            let Some(remaining) = ipc::on_client_disconnected() else {
                return IpcResponse::Ok { lines: vec![] };
            };
            if remaining == 0 {
                let snap = state.controller.config.snapshot();
                if profile::should_auto_exit_on_client_disconnect(snap.as_ref()) {
                    let _ = state.controller.ui.emit_plain(format!(
                        "{}",
                        crate::term_style::fmt_info_line(format_args!(
                            " Last CLI client disconnected; stopping VPN daemon."
                        ))
                    ));
                    SHUTDOWN_REQUESTED.store(true, Ordering::Release);
                    {
                        let mut cli = state.cli_lock();
                        cli.shutdown_engine_for_exit().await;
                    }
                    std::process::exit(0);
                }
            }
            IpcResponse::Ok { lines: vec![] }
        }
    }
}

pub mod daemon_win {
    use anyhow::Result;

    #[cfg(windows)]
    pub fn ensure_wintun_dll() -> Result<()> {
        let exe = std::env::current_exe()?;
        let dir = exe
            .parent()
            .ok_or_else(|| anyhow::anyhow!("cannot locate executable directory"))?;
        let dll = dir.join("wintun.dll");
        if !dll.exists() {
            anyhow::bail!("wintun.dll not found next to executable: {}", dll.display());
        }
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn ensure_wintun_dll() -> Result<()> {
        Ok(())
    }
}
