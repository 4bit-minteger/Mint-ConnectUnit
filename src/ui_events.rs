//! User-visible terminal lines from engine/daemon → CLI clients (broadcast + replay ring).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

pub const MARK_CLEAR: &str = "\x1bMINT_CLEAR\x1b";
pub const MARK_PROMPT: &str = "\x1bMINT_PROMPT\x1b";
/// Punch-loop progress: client overwrites one terminal row instead of scrolling.
pub const MARK_LIVE_OVERWRITE: &str = "\x1bMINT_LIVE_OWR\x1b";
pub const MARK_SESSION_READY: &str = crate::bootstrap::MARK_SESSION_READY;

const DEFAULT_RING_CAP: usize = 4096;
const BROADCAST_CAP: usize = 1024;

#[derive(Debug, Clone)]
pub enum UiLine {
    Plain(String),
    Stderr(String),
    Clear,
    PromptHint(String),
    SessionReady,
}

impl UiLine {
    pub fn encode(&self) -> String {
        match self {
            UiLine::Plain(s) => s.clone(),
            UiLine::Stderr(s) => format!("[stderr] {s}"),
            UiLine::Clear => MARK_CLEAR.to_string(),
            UiLine::PromptHint(s) => format!("{MARK_PROMPT}{s}"),
            UiLine::SessionReady => MARK_SESSION_READY.to_string(),
        }
    }
}

/// Shared sink for engine and VPN-side tasks.
pub type UiSink = Arc<UiEventBus>;

pub struct UiEventBus {
    tx: broadcast::Sender<UiLine>,
    ring: Mutex<VecDeque<String>>,
    ring_cap: usize,
}

impl UiEventBus {
    pub fn new() -> UiSink {
        Arc::new(Self {
            tx: broadcast::channel(BROADCAST_CAP).0,
            ring: Mutex::new(VecDeque::new()),
            ring_cap: DEFAULT_RING_CAP,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<UiLine> {
        self.tx.subscribe()
    }

    pub fn emit(&self, line: UiLine) {
        let encoded = line.encode();
        {
            let mut ring = self.ring.lock().unwrap();
            if ring.len() >= self.ring_cap {
                ring.pop_front();
            }
            ring.push_back(encoded.clone());
        }
        let _ = self.tx.send(line);
    }

    /// Live subscribers only (hole-punch progress); omitted from replay ring.
    pub fn emit_live_only(&self, line: UiLine) {
        let _ = self.tx.send(line);
    }

    pub fn emit_plain(&self, msg: String) {
        self.emit(UiLine::Plain(msg));
    }

    pub fn emit_plain_live(&self, msg: String) {
        self.emit_live_only(UiLine::Plain(msg));
    }

    pub fn emit_stderr(&self, msg: String) {
        self.emit(UiLine::Stderr(msg));
    }

    pub fn replay(&self, max_lines: u32) -> Vec<String> {
        let ring = self.ring.lock().unwrap();
        let n = max_lines.min(ring.len() as u32) as usize;
        ring.iter()
            .skip(ring.len().saturating_sub(n))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_plain_live_omitted_from_replay_ring() {
        let ui = UiEventBus::new();
        ui.emit_plain("persisted line".to_string());
        ui.emit_plain_live("  [JOIN] MPJA received. Join handshake confirmed.".to_string());
        let replay = ui.replay(100);
        assert_eq!(replay, vec!["persisted line".to_string()]);
    }
}
