//! Shared join-invite prompts (first-run join wizard, manual mode).

use std::io::Write;

use anyhow::Result;

use crate::ipc::IpcClient;

pub async fn prompt_join_invite_options(ipc: &IpcClient, invite: String) -> Result<()> {
    println!("  Connection mode:");
    println!("    [1] Public (STUN + punch, default)");
    println!("    [2] LAN");
    print!("  Choose [1/2, default 1]: ");
    std::io::stdout().flush()?;
    let mut conn = String::new();
    std::io::stdin().read_line(&mut conn)?;
    let lan_mode = Some(conn.trim() == "2");
    ipc.join_invite(invite, lan_mode).await
}
