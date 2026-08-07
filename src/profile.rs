//! Shared session/profile predicates for daemon lifecycle (auto-exit on client disconnect).

use crate::config::NetworkConfig;

/// True when the node has completed mint/join and has an active VPN profile.
/// Matches `Cli::has_active_profile()` in `cli.rs`.
pub fn has_active_profile(snap: &NetworkConfig) -> bool {
    !snap.crypto_key.is_empty() && !snap.virtual_ip.is_empty()
}

/// When idle (no create/join profile), exit after the last real CLI session ends.
/// Transient `Ping`-only probes do not count as sessions (see `run_ipc_server`).
pub fn should_auto_exit_on_client_disconnect(snap: &NetworkConfig) -> bool {
    !has_active_profile(snap)
}
