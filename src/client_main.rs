//! Thin CLI entry: delegates to [`cli_session`].

use anyhow::Result;

pub async fn run_cli_client() -> Result<()> {
    let local = tokio::task::LocalSet::new();
    local.run_until(crate::cli_session::run()).await
}
