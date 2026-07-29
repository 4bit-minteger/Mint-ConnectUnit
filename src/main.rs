#![allow(clippy::all)]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::env;

use anyhow::Result;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "daemon") {
        return mint::daemon::run_daemon().await;
    }
    eprintln!("ConnectUnit: VPN core runs in background.");
    mint::client_main::run_cli_client().await
}
