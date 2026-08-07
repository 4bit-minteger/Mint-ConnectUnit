//! Daemon bootstrap outcome (IPC + session-open ceremony).

use serde::{Deserialize, Serialize};

use crate::term_style;

pub const RECONNECT_DEADLINE_SECS: u64 = 60;

/// Encoded on the UI bus; client treats as end of transient PARA stream for session-open.
pub const MARK_SESSION_READY: &str = "\x1bMINT_SESSION_READY\x1b";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReconnectOutcome {
    /// No reconnect ran (e.g. fresh start or already connected).
    Skipped,
    Connected,
    Failed,
    TimedOut,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BootstrapSnapshot {
    pub complete: bool,
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
    network_id: &str,
    virtual_ip: &str,
) -> Vec<String> {
    let head = match outcome {
        ReconnectOutcome::Connected | ReconnectOutcome::Skipped => {
            term_style::fmt_profile_loaded_home_line()
        }
        ReconnectOutcome::Failed | ReconnectOutcome::TimedOut => {
            term_style::fmt_try_again_home_line()
        }
    };
    vec![
        String::new(),
        head,
        format!("  Network: {network_id}  VIP: {virtual_ip}"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_home_never_says_reconnected_word() {
        let lines = session_home_lines(ReconnectOutcome::TimedOut, "net", "1.2.3.4");
        let joined = lines.join("\n");
        assert!(!joined.contains("Reconnected, your home is"));
        assert!(joined.contains("Try again later?"));
    }

    #[test]
    fn success_home_says_profile_loaded() {
        let lines = session_home_lines(ReconnectOutcome::Connected, "net", "1.2.3.4");
        assert!(lines[1].contains("Unit profile loaded"));
        assert!(!lines[1].contains("Reconnected"));
    }

    #[test]
    fn skipped_home_says_profile_loaded_not_reconnected() {
        let lines = session_home_lines(ReconnectOutcome::Skipped, "net", "1.2.3.4");
        let joined = lines.join("\n");
        assert!(!joined.contains("Reconnected, your home is"));
        assert!(joined.contains("[CONFIG]"));
        assert!(joined.contains("Unit profile loaded"));
    }

    #[test]
    fn skipped_home_no_longer_shows_no_peers_hint() {
        let lines = session_home_lines(ReconnectOutcome::Skipped, "net", "1.2.3.4");
        let joined = lines.join("\n");
        assert!(!joined.contains("No peers connected yet"));
        assert_eq!(lines.len(), 3);
        assert!(!joined.contains("Role:"));
    }
}
