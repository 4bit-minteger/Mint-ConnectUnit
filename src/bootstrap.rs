//! Daemon bootstrap / parasitic auto-reconnect outcome (IPC + session-open ceremony).

use serde::{Deserialize, Serialize};

use crate::term_style;

pub const PARA_AUTO_RECONNECT_DEADLINE_SECS: u64 = 60;

/// Encoded on the UI bus; client treats as end of transient PARA stream for session-open.
pub const MARK_SESSION_READY: &str = "\x1bMINT_SESSION_READY\x1b";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReconnectOutcome {
    /// No parasitic auto-reconnect ran (e.g. owner profile).
    Skipped,
    Connected,
    Failed,
    TimedOut,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BootstrapSnapshot {
    pub complete: bool,
    pub parasitic_attempted: bool,
    pub outcome: Option<ReconnectOutcome>,
    /// Pre-rendered home block for the CLI opening ceremony (empty until complete;
    /// consumed once via TakeSessionHome so CLI re-attach stays quiet).
    pub home_lines: Vec<String>,
}

impl BootstrapSnapshot {
    pub fn pending() -> Self {
        Self::default()
    }
}

/// User-visible home block lines (no banner).
pub fn session_home_lines(
    outcome: ReconnectOutcome,
    server_name: &str,
    network_id: &str,
    virtual_ip: &str,
    role: &str,
) -> Vec<String> {
    let head = match outcome {
        ReconnectOutcome::Connected | ReconnectOutcome::Skipped => {
            term_style::fmt_profile_loaded_home_line(server_name)
        }
        ReconnectOutcome::Failed | ReconnectOutcome::TimedOut => {
            term_style::fmt_try_again_home_line(server_name)
        }
    };
    vec![
        String::new(),
        head,
        format!("  Network: {network_id}  VIP: {virtual_ip}  Role: {role}"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_home_never_says_reconnected_word() {
        let lines =
            session_home_lines(ReconnectOutcome::TimedOut, "Mint", "net", "1.2.3.4", "peer");
        let joined = lines.join("\n");
        assert!(!joined.contains("Reconnected, your home is"));
        assert!(joined.contains("Try again later?"));
    }

    #[test]
    fn success_home_says_profile_loaded() {
        let lines = session_home_lines(
            ReconnectOutcome::Connected,
            "Mint",
            "net",
            "1.2.3.4",
            "peer",
        );
        assert!(lines[1].contains("Server profile loaded"));
        assert!(!lines[1].contains("Reconnected"));
    }

    #[test]
    fn skipped_home_says_profile_loaded_not_reconnected() {
        let lines = session_home_lines(ReconnectOutcome::Skipped, "Mint", "net", "1.2.3.4", "peer");
        let joined = lines.join("\n");
        assert!(!joined.contains("Reconnected, your home is"));
        assert!(joined.contains("[CONFIG]"));
        assert!(joined.contains("Server profile loaded"));
    }

    #[test]
    fn owner_skipped_no_longer_shows_no_peers_hint() {
        let lines =
            session_home_lines(ReconnectOutcome::Skipped, "Mint", "net", "1.2.3.4", "owner");
        let joined = lines.join("\n");
        assert!(!joined.contains("No peers connected yet"));
        assert_eq!(lines.len(), 3);
    }
}
