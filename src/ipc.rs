//! Local TCP IPC between CLI client and VPN daemon (127.0.0.1).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

pub const IPC_ADDR: &str = "127.0.0.1:48787";
pub const IPC_UI_ADDR: &str = "127.0.0.1:48788";
pub const IPC_PROTOCOL: u32 = 2;

/// First frame on UI socket must be this; daemon replies with replay then streams live lines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiSubscribe {
    pub replay_lines: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UiEventFrame {
    Replay(Vec<String>),
    Live(String),
}

static CLIENT_COUNT: AtomicUsize = AtomicUsize::new(0);

pub fn on_client_connected() {
    CLIENT_COUNT.fetch_add(1, Ordering::AcqRel);
}

/// Returns remaining CLI clients after this disconnect, or `None` if count was already zero.
pub fn on_client_disconnected() -> Option<usize> {
    let prev = CLIENT_COUNT.fetch_sub(1, Ordering::AcqRel);
    if prev == 0 {
        return None;
    }
    Some(prev - 1)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcRequest {
    Ping,
    /// Run one CLI command line (same as interactive prompt input).
    ProcessLine {
        line: String,
    },
    /// Graceful VPN shutdown (`stop`).
    ShutdownGraceful,
    /// Client UI disconnected (window close / exit); daemon may auto-exit if idle profile.
    ClientDisconnect,
    HasActiveProfile,
    /// Daemon bootstrap / parasitic auto-reconnect progress for session-open ceremony.
    BootstrapSnapshot,
    /// Atomically take session-open home lines (once per daemon bootstrap).
    TakeSessionHome,
    ReloadConfigFromDisk,
    /// Metrics + trace snapshot for client-side `runtime` view.
    RuntimeSnapshot,
    CreateNetwork {
        name: String,
        listen_port: u16,
        owner_vip: String,
        subnet_prefix: u8,
    },
    JoinInvite {
        invite: String,
        /// `Some(true)` = LAN (skip public STUN path); default public.
        lan_mode: Option<bool>,
    },
    JoinParasitic {
        peer_vip: String,
        self_vip: String,
        upnp_port: Option<u16>,
    },
    /// Broadcast discover_only MPHI; returns `ParasiticLanOwners`.
    DiscoverParasiticLan,
    /// Unicast admit Hello to a LAN owner (`ip` or `ip:port`).
    JoinParasiticLan {
        target: String,
    },
    ResetPerformanceDefaults,
    JoinDecentralized {
        invite: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParasiticLanOwner {
    pub network_name: String,
    pub network_id: String,
    pub from: String,
    pub node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcResponse {
    Ok { lines: Vec<String> },
    Err { message: String },
    Bool(bool),
    Pong,
    RuntimeSnapshot { payload: Vec<u8> },
    BootstrapSnapshot { payload: Vec<u8> },
    ParasiticLanOwners { owners: Vec<ParasiticLanOwner> },
}

pub async fn write_frame(stream: &mut TcpStream, req: &IpcRequest) -> Result<()> {
    let payload = bincode::serialize(req)?;
    let len = payload.len() as u32;
    stream.write_u32_le(len).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn read_frame(stream: &mut TcpStream) -> Result<IpcResponse> {
    let len = stream.read_u32_le().await?;
    if len > 16 * 1024 * 1024 {
        return Err(anyhow!("ipc frame too large"));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    Ok(bincode::deserialize(&buf)?)
}

pub async fn request(stream: &mut TcpStream, req: IpcRequest) -> Result<IpcResponse> {
    write_frame(stream, &req).await?;
    read_frame(stream).await
}

#[derive(Clone)]
pub struct IpcClient {
    stream: Arc<Mutex<TcpStream>>,
}

impl IpcClient {
    pub async fn connect() -> Result<Self> {
        let addr: SocketAddr = IPC_ADDR.parse()?;
        let stream = TcpStream::connect(addr).await?;
        Ok(Self {
            stream: Arc::new(Mutex::new(stream)),
        })
    }

    pub async fn call(&self, req: IpcRequest) -> Result<IpcResponse> {
        let mut s = self.stream.lock().await;
        request(&mut *s, req).await
    }

    pub async fn create_network(
        &self,
        name: String,
        listen_port: u16,
        owner_vip: String,
        subnet_prefix: u8,
    ) -> Result<()> {
        match self
            .call(IpcRequest::CreateNetwork {
                name,
                listen_port,
                owner_vip,
                subnet_prefix,
            })
            .await?
        {
            IpcResponse::Ok { lines } => {
                crate::cli_emit::render_lines_to_user_terminal(&lines).await;
                Ok(())
            }
            IpcResponse::Err { message } => Err(anyhow!(message)),
            other => Err(anyhow!("unexpected ipc response: {other:?}")),
        }
    }

    pub async fn join_parasitic(
        &self,
        peer_vip: String,
        self_vip: String,
        upnp_port: Option<u16>,
    ) -> Result<()> {
        match self
            .call(IpcRequest::JoinParasitic {
                peer_vip,
                self_vip,
                upnp_port,
            })
            .await?
        {
            IpcResponse::Ok { lines } => {
                crate::cli_emit::render_lines_to_user_terminal(&lines).await;
                Ok(())
            }
            IpcResponse::Err { message } => Err(anyhow!(message)),
            other => Err(anyhow!("unexpected ipc response: {other:?}")),
        }
    }

    pub async fn discover_parasitic_lan(&self) -> Result<Vec<ParasiticLanOwner>> {
        match self.call(IpcRequest::DiscoverParasiticLan).await? {
            IpcResponse::ParasiticLanOwners { owners } => Ok(owners),
            IpcResponse::Err { message } => Err(anyhow!(message)),
            other => Err(anyhow!("unexpected ipc response: {other:?}")),
        }
    }

    pub async fn join_parasitic_lan(&self, target: String) -> Result<()> {
        match self.call(IpcRequest::JoinParasiticLan { target }).await? {
            IpcResponse::Ok { lines } => {
                crate::cli_emit::render_lines_to_user_terminal(&lines).await;
                Ok(())
            }
            IpcResponse::Err { message } => Err(anyhow!(message)),
            other => Err(anyhow!("unexpected ipc response: {other:?}")),
        }
    }

    pub async fn reset_performance_defaults(&self) -> Result<()> {
        match self.call(IpcRequest::ResetPerformanceDefaults).await? {
            IpcResponse::Ok { lines } => {
                crate::cli_emit::render_lines_to_user_terminal(&lines).await;
                Ok(())
            }
            IpcResponse::Err { message } => Err(anyhow!(message)),
            other => Err(anyhow!("unexpected ipc response: {other:?}")),
        }
    }

    pub async fn join_decentralized(&self, invite: String) -> Result<()> {
        match self.call(IpcRequest::JoinDecentralized { invite }).await? {
            IpcResponse::Ok { lines } => {
                crate::cli_emit::render_lines_to_user_terminal(&lines).await;
                Ok(())
            }
            IpcResponse::Err { message } => Err(anyhow!(message)),
            other => Err(anyhow!("unexpected ipc response: {other:?}")),
        }
    }

    pub async fn join_invite(&self, invite: String, lan_mode: Option<bool>) -> Result<()> {
        match self
            .call(IpcRequest::JoinInvite { invite, lan_mode })
            .await?
        {
            IpcResponse::Ok { lines } => {
                crate::cli_emit::render_lines_to_user_terminal(&lines).await;
                Ok(())
            }
            IpcResponse::Err { message } => Err(anyhow!(message)),
            other => Err(anyhow!("unexpected ipc response: {other:?}")),
        }
    }

    pub async fn runtime_snapshot_lines(&self) -> Result<Vec<String>> {
        match self.call(IpcRequest::RuntimeSnapshot).await? {
            IpcResponse::RuntimeSnapshot { payload } => {
                Ok(bincode::deserialize(&payload).unwrap_or_default())
            }
            other => Err(anyhow!("unexpected ipc response: {other:?}")),
        }
    }

    pub async fn process_line(&self, line: String) -> Result<Vec<String>> {
        match self.call(IpcRequest::ProcessLine { line }).await? {
            IpcResponse::Ok { lines } => Ok(lines),
            IpcResponse::Err { message } => Err(anyhow!(message)),
            other => Err(anyhow!("unexpected ipc response: {other:?}")),
        }
    }

    pub async fn shutdown_graceful(&self) -> Result<()> {
        let _ = self.call(IpcRequest::ShutdownGraceful).await?;
        Ok(())
    }

    pub async fn client_disconnect(&self) -> Result<()> {
        let _ = self.call(IpcRequest::ClientDisconnect).await?;
        Ok(())
    }

    pub async fn has_active_profile(&self) -> Result<bool> {
        match self.call(IpcRequest::HasActiveProfile).await? {
            IpcResponse::Bool(b) => Ok(b),
            other => Err(anyhow!("unexpected ipc response: {other:?}")),
        }
    }

    pub async fn bootstrap_snapshot(&self) -> Result<crate::bootstrap::BootstrapSnapshot> {
        match self.call(IpcRequest::BootstrapSnapshot).await? {
            IpcResponse::BootstrapSnapshot { payload } => {
                Ok(bincode::deserialize(&payload).unwrap_or_default())
            }
            other => Err(anyhow!("unexpected ipc response: {other:?}")),
        }
    }

    /// One-shot session-open home block (cleared after first successful take).
    pub async fn take_session_home(&self) -> Result<Vec<String>> {
        match self.call(IpcRequest::TakeSessionHome).await? {
            IpcResponse::Ok { lines } => Ok(lines),
            other => Err(anyhow!("unexpected ipc response: {other:?}")),
        }
    }
}

/// Ephemeral progress / one-shot notices — skip on UI replay / post-session-ready.
pub fn is_transient_para_ui_line(line: &str) -> bool {
    crate::banner::is_banner_art_line(line)
        || line.contains("[TRACKER]")
        || line.contains("Tracker discovery active")
        || line.contains("[PARA-BURST")
        || line.contains("[PARA-NARROW]")
        || line.contains("[PARA-WIDE]")
        || line.contains("[PARA-PASSIVE-")
        || line.contains("Auto-reconnect: signaling")
        || line.contains("Auto-reconnect failed")
        || line.contains("Auto-reconnect timeout")
        || (line.contains("Attempt:") && line.contains("Sent:") && !line.contains("Finished"))
        || line.contains("Finished (stopped early")
        // Owner join confirm is one-shot; older daemons may still have it in the replay ring.
        || line.contains("Owner confirmed peer join")
        // Daemon bootstrap one-shots: show on first VPN start, never on CLI re-attach replay.
        || line.contains("Restored Wintun adapter")
        || line.contains("Passive listener armed")
        // Session-open home is delivered once via TakeSessionHome; strip leftover ring lines.
        || line.contains("Server profile loaded")
        || (line.contains("Try again later?") && line.contains("Your home is"))
        || (line.contains("Network:") && line.contains("VIP:") && line.contains("Role:"))
}

/// Full-screen clear from an old session-open ceremony — never replay on CLI re-attach.
pub fn is_replay_only_skip_line(line: &str) -> bool {
    line == crate::ui_events::MARK_CLEAR || line == crate::cli_emit::MARK_CLEAR
}

/// Connect to daemon UI port and render events until disconnect.
pub async fn subscribe_ui_events(replay_lines: u32) -> Result<()> {
    subscribe_ui_events_inner(replay_lines, None).await
}

/// UI stream with session-ready gate (suppresses transient PARA after opening ceremony).
pub async fn subscribe_ui_events_gated(
    replay_lines: u32,
    session_ready: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    subscribe_ui_events_inner(replay_lines, Some(session_ready)).await
}

async fn subscribe_ui_events_inner(
    replay_lines: u32,
    session_ready: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> Result<()> {
    let addr: std::net::SocketAddr = IPC_UI_ADDR.parse()?;
    let mut stream = TcpStream::connect(addr).await?;
    let sub = UiSubscribe { replay_lines };
    let payload = bincode::serialize(&sub)?;
    let len = payload.len() as u32;
    stream.write_u32_le(len).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    loop {
        match read_ui_frame(&mut stream).await {
            Ok(UiEventFrame::Replay(lines)) => {
                for l in lines {
                    if l == crate::ui_events::MARK_SESSION_READY {
                        if let Some(g) = session_ready.as_ref() {
                            g.store(true, std::sync::atomic::Ordering::Release);
                        }
                        continue;
                    }
                    if is_replay_only_skip_line(&l) || is_transient_para_ui_line(&l) {
                        continue;
                    }
                    crate::cli_emit::render_to_user_terminal(&l);
                }
            }
            Ok(UiEventFrame::Live(l)) => {
                if l == crate::ui_events::MARK_SESSION_READY {
                    if let Some(g) = session_ready.as_ref() {
                        g.store(true, std::sync::atomic::Ordering::Release);
                    }
                    continue;
                }
                if session_ready
                    .as_ref()
                    .is_some_and(|g| g.load(std::sync::atomic::Ordering::Acquire))
                    && is_transient_para_ui_line(&l)
                {
                    continue;
                }
                crate::cli_emit::render_to_user_terminal(&l);
            }
            Err(_) => break,
        }
    }
    Ok(())
}

pub async fn write_ui_frame(stream: &mut TcpStream, frame: &UiEventFrame) -> Result<()> {
    let payload = bincode::serialize(frame)?;
    let len = payload.len() as u32;
    stream.write_u32_le(len).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn read_ui_frame(stream: &mut TcpStream) -> Result<UiEventFrame> {
    let len = stream.read_u32_le().await?;
    if len > 16 * 1024 * 1024 {
        return Err(anyhow!("ui frame too large"));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    Ok(bincode::deserialize(&buf)?)
}

pub async fn write_response_frame(stream: &mut TcpStream, resp: &IpcResponse) -> Result<()> {
    let payload = bincode::serialize(resp)?;
    let len = payload.len() as u32;
    stream.write_u32_le(len).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(())
}

pub fn spawn_detached_daemon() -> Result<()> {
    let exe = std::env::current_exe()?;
    let work_dir = crate::netinfo::exe_dir()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("daemon").current_dir(work_dir);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.spawn().context("spawn mint daemon")?;
    Ok(())
}

pub async fn ensure_daemon_running() -> Result<()> {
    if daemon_ready().await.is_ok() {
        return Ok(());
    }
    spawn_detached_daemon()?;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(125)).await;
        if daemon_ready().await.is_ok() {
            return Ok(());
        }
    }
    Err(anyhow!(
        "daemon did not become ready on {IPC_ADDR} / {IPC_UI_ADDR}"
    ))
}

async fn daemon_ready() -> Result<()> {
    let addr: SocketAddr = IPC_ADDR.parse()?;
    let mut stream = TcpStream::connect(addr).await?;
    let resp = request(&mut stream, IpcRequest::Ping).await?;
    match resp {
        IpcResponse::Pong => {}
        other => return Err(anyhow!("unexpected ping response: {other:?}")),
    }
    let ui_addr: SocketAddr = IPC_UI_ADDR.parse()?;
    let _ = TcpStream::connect(ui_addr).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_confirmed_peer_join_is_transient_for_replay() {
        let line = "  [JOIN] Owner confirmed peer join: node=abc vip=10.66.0.2 from=1.2.3.4:51820";
        assert!(is_transient_para_ui_line(line));
        assert!(!is_transient_para_ui_line(
            "  [JOIN] MPJA received. Join handshake confirmed."
        ));
    }

    #[test]
    fn session_home_ceremony_lines_are_transient_for_replay() {
        assert!(is_transient_para_ui_line(
            "  [CONFIG] Server profile loaded! Your home is: 'Mint'"
        ));
        assert!(is_transient_para_ui_line(
            "  Network: netid  VIP: 10.66.0.1  Role: owner"
        ));
        assert!(is_replay_only_skip_line(crate::ui_events::MARK_CLEAR));
    }

    #[test]
    fn daemon_bootstrap_one_shots_are_transient_for_replay() {
        assert!(is_transient_para_ui_line(
            "[i] Restored Wintun adapter for 22.136.40.1/24"
        ));
        assert!(is_transient_para_ui_line(
            "  [PARA] Passive listener armed (owner mode)."
        ));
        // Unrelated [i] / [PARA] lines must still pass through.
        assert!(!is_transient_para_ui_line("[i] Screen autoclear: on"));
        assert!(!is_transient_para_ui_line(
            "  [PARA] Peer punch window started."
        ));
    }
}
