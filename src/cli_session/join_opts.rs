//! Shared join-invite prompts (first-run join wizard, manual mode).

use std::io::Write;

use anyhow::{anyhow, Result};

use crate::ipc::IpcClient;

pub async fn prompt_join_invite_options(ipc: &IpcClient, invite: String) -> Result<()> {
    println!("  Connection mode:");
    println!("    [1] Public");
    println!("    [2] LAN");
    print!("  Choose [1/2](1): ");
    std::io::stdout().flush()?;
    let mut conn = String::new();
    std::io::stdin().read_line(&mut conn)?;
    let lan_mode = Some(conn.trim() == "2");
    print!("  Peer endpoint (ip:port): ");
    std::io::stdout().flush()?;
    let mut endpoint = String::new();
    std::io::stdin().read_line(&mut endpoint)?;
    let endpoint = endpoint.trim().to_string();
    if endpoint.is_empty() {
        return Err(anyhow!("peer endpoint (ip:port) is required"));
    }
    ipc.join_invite(invite, lan_mode, endpoint).await
}
