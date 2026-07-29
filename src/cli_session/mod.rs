//! Interactive CLI session (user terminal only); VPN work stays on daemon.

mod join_opts;

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::ipc::{self, IpcClient};

/// Wait for daemon session-open UI (home block) before the input prompt.
async fn wait_for_session_open(ipc: &IpcClient, session_ready: Arc<AtomicBool>) {
    const POLL_MS: u64 = 50;
    const MAX_WAIT_MS: u64 = (crate::bootstrap::PARA_AUTO_RECONNECT_DEADLINE_SECS + 15) * 1000;
    let deadline = Instant::now() + Duration::from_millis(MAX_WAIT_MS);
    while Instant::now() < deadline {
        if session_ready.load(Ordering::Acquire) {
            return;
        }
        if ipc
            .bootstrap_snapshot()
            .await
            .ok()
            .is_some_and(|s| s.complete)
        {
            for _ in 0..40 {
                if session_ready.load(Ordering::Acquire) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            return;
        }
        tokio::time::sleep(Duration::from_millis(POLL_MS)).await;
    }
}

pub async fn run() -> Result<()> {
    crate::console_util::setup_console_utf8();
    #[cfg(windows)]
    {
        if !crate::windows_elevation::is_elevated()? {
            anyhow::bail!("Mint requires Administrator privileges.");
        }
    }

    ipc::ensure_daemon_running().await?;
    let ipc = IpcClient::connect().await?;

    let has_profile = ipc.has_active_profile().await.unwrap_or(false);
    let session_ready = Arc::new(AtomicBool::new(false));

    if has_profile {
        let gate = session_ready.clone();
        tokio::task::spawn_local(async move {
            if let Err(e) = ipc::subscribe_ui_events_gated(256, gate).await {
                eprintln!(
                    "{}",
                    crate::term_style::fmt_bang_line(format_args!(
                        " UI event stream ended: {e} (command output still works via IPC)"
                    ))
                );
            }
        });
        wait_for_session_open(&ipc, session_ready).await;
        match ipc.take_session_home().await {
            Ok(lines) if !lines.is_empty() => {
                crate::cli_emit::clear_user_terminal();
                crate::cli_emit::render_lines_to_user_terminal(&lines).await;
            }
            _ => {}
        }
    } else {
        tokio::task::spawn_local(async {
            if let Err(e) = ipc::subscribe_ui_events(256).await {
                eprintln!(
                    "{}",
                    crate::term_style::fmt_bang_line(format_args!(
                        " UI event stream ended: {e} (command output still works via IPC)"
                    ))
                );
            }
        });
        crate::banner::render_banner_to_stdout(crate::banner::BANNER_LINE_DELAY_MS).await;
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        print_ipc_lines(&ipc, String::new()).await?;
    }

    let mut exiting_after_stop = false;
    loop {
        print!("{}", crate::term_style::fmt_input_prompt());
        std::io::stdout().flush()?;

        crate::cli_emit::set_stdin_read_active(true);
        let line = match tokio::task::spawn_blocking(|| {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).map(|_| line)
        })
        .await
        {
            Ok(Ok(l)) => l,
            _ => {
                crate::cli_emit::set_stdin_read_active(false);
                break;
            }
        };
        crate::cli_emit::set_stdin_read_active(false);
        crate::cli_emit::flush_deferred_live_status();
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        if line.eq_ignore_ascii_case("stop")
            || line.eq_ignore_ascii_case("exit")
            || line.eq_ignore_ascii_case("quit")
        {
            let _ = ipc.shutdown_graceful().await;
            exiting_after_stop = true;
            break;
        }

        match dispatch_line(&ipc, &line).await {
            Ok(DispatchOutcome::Continue) => {}
            Ok(DispatchOutcome::ExitApp) => {
                exiting_after_stop = true;
                break;
            }
            Err(e) => {
                println!("{}", crate::term_style::fmt_bang_line(format_args!(" {e}")));
            }
        }
    }

    if !exiting_after_stop {
        let _ = ipc.client_disconnect().await;
    }
    Ok(())
}

async fn profile_active(ipc: &IpcClient) -> bool {
    ipc.has_active_profile().await.unwrap_or(false)
}

fn reject_setup_while_active() -> anyhow::Error {
    anyhow::anyhow!("Active VPN profile. Run remove first, then choose [1] or [2] from the menu.")
}

enum DispatchOutcome {
    Continue,
    ExitApp,
}

async fn dispatch_line(ipc: &IpcClient, line: &str) -> Result<DispatchOutcome> {
    let mut parts = line.split_whitespace();
    let cmd = parts.next().unwrap_or_default();
    match cmd {
        "3" if line.len() == 1 => {
            ipc.shutdown_graceful().await?;
            return Ok(DispatchOutcome::ExitApp);
        }
        "1" | "2" if line.len() == 1 => {
            if profile_active(ipc).await {
                return Err(reject_setup_while_active());
            }
            dispatch_first_run(ipc, cmd).await?;
            Ok(DispatchOutcome::Continue)
        }
        "runtime" => {
            run_runtime_view(ipc).await?;
            Ok(DispatchOutcome::Continue)
        }
        _ => {
            print_ipc_lines(ipc, line.to_string()).await?;
            Ok(DispatchOutcome::Continue)
        }
    }
}

async fn dispatch_first_run(ipc: &IpcClient, key: &str) -> Result<()> {
    match key {
        "1" => run_create_wizard(ipc).await,
        "2" => run_join_entry_wizard(ipc).await,
        _ => print_ipc_lines(ipc, key.to_string()).await,
    }
}

async fn run_create_wizard(ipc: &IpcClient) -> Result<()> {
    println!("  Server name: ");
    std::io::stdout().flush()?;
    let mut name = String::new();
    std::io::stdin().read_line(&mut name)?;
    println!("  Listen port (default 7878): ");
    std::io::stdout().flush()?;
    let mut port_s = String::new();
    std::io::stdin().read_line(&mut port_s)?;
    let port = port_s.trim().parse::<u16>().unwrap_or(7878);
    println!("  Owner VIP (blank = auto): ");
    std::io::stdout().flush()?;
    let mut vip = String::new();
    std::io::stdin().read_line(&mut vip)?;
    println!("  Subnet prefix (default 24): ");
    std::io::stdout().flush()?;
    let mut prefix_s = String::new();
    std::io::stdin().read_line(&mut prefix_s)?;
    let prefix = prefix_s.trim().parse::<u8>().unwrap_or(24);
    ipc.create_network(
        name.trim().to_string(),
        port,
        vip.trim().to_string(),
        prefix,
    )
    .await
}

async fn run_join_entry_wizard(ipc: &IpcClient) -> Result<()> {
    println!("  Join mode:");
    println!("    [1] Decentralized (default)");
    println!("    [2] Parasitic");
    println!("    [3] Manual");
    print!("  Choose [1/2/3, default 1]: ");
    std::io::stdout().flush()?;
    let mut mode = String::new();
    std::io::stdin().read_line(&mut mode)?;
    let t = mode.trim();
    if t == "2" {
        return run_join_parasitic_wizard(ipc).await;
    }
    if t == "3" {
        println!("  Invite code: ");
        std::io::stdout().flush()?;
        let mut invite = String::new();
        std::io::stdin().read_line(&mut invite)?;
        let invite = invite.trim().to_string();
        if invite.is_empty() {
            anyhow::bail!("invite code is required");
        }
        return join_opts::prompt_join_invite_options(ipc, invite).await;
    }
    println!("  Invite code: ");
    std::io::stdout().flush()?;
    let mut invite = String::new();
    std::io::stdin().read_line(&mut invite)?;
    let invite = invite.trim().to_string();
    if invite.is_empty() {
        anyhow::bail!("invite code is required");
    }
    ipc.join_decentralized(invite).await
}

async fn run_join_parasitic_wizard(ipc: &IpcClient) -> Result<()> {
    println!("  Use any pre-existing VPN/route as a signaling pipe.");
    println!("  Both sides must reach each other on UDP at the VIP/port below.");
    println!("  Peer VIP (ip or ip:port): ");
    std::io::stdout().flush()?;
    let mut peer = String::new();
    std::io::stdin().read_line(&mut peer)?;
    println!("  Your VIP (ip or ip:port): ");
    std::io::stdout().flush()?;
    let mut self_vip = String::new();
    std::io::stdin().read_line(&mut self_vip)?;
    println!("  UPnP port (Enter=default listen port): ");
    std::io::stdout().flush()?;
    let mut port_s = String::new();
    std::io::stdin().read_line(&mut port_s)?;
    let upnp_port = port_s.trim().parse::<u16>().ok();
    ipc.join_parasitic(
        peer.trim().to_string(),
        self_vip.trim().to_string(),
        upnp_port,
    )
    .await
}

async fn run_runtime_view(ipc: &IpcClient) -> Result<()> {
    const FOOTER: &str = "  Press Enter to stop…";

    async fn paint_frame(ipc: &IpcClient, footer: &str) {
        let lines = ipc.runtime_snapshot_lines().await.unwrap_or_default();
        print!("\x1B[2J\x1B[H");
        for l in lines {
            println!("{l}");
        }
        println!("{footer}");
    }

    paint_frame(ipc, FOOTER).await;

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;

    let mut enter_wait = tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)
    });

    loop {
        tokio::select! {
            res = &mut enter_wait => {
                let _ = res;
                break;
            }
            _ = interval.tick() => {
                paint_frame(ipc, FOOTER).await;
            }
        }
    }

    let _ = std::io::Write::write_all(&mut std::io::stdout(), b"\n");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    Ok(())
}

pub(super) async fn print_ipc_lines(ipc: &IpcClient, line: String) -> Result<()> {
    match ipc.process_line(line).await {
        Ok(lines) => {
            crate::cli_emit::render_lines_to_user_terminal(&lines).await;
            Ok(())
        }
        Err(e) => Err(e),
    }
}
