//! Terminal output routing: local stdout or IPC capture for the CLI client.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// Prefix on captured lines — client interprets before display.
pub const MARK_CLEAR: &str = "\x1bMINT_CLEAR\x1b";
pub const MARK_PROMPT: &str = "\x1bMINT_PROMPT\x1b";

static CAPTURE: OnceLock<Mutex<Option<Vec<String>>>> = OnceLock::new();
static DAEMON_UI: OnceLock<std::sync::Arc<crate::ui_events::UiEventBus>> = OnceLock::new();
static STDIN_READ_ACTIVE: AtomicBool = AtomicBool::new(false);
static DEFERRED_LIVE_OVERWRITE: OnceLock<Mutex<Option<String>>> = OnceLock::new();

fn deferred_live_overwrite() -> &'static Mutex<Option<String>> {
    DEFERRED_LIVE_OVERWRITE.get_or_init(|| Mutex::new(None))
}

/// While true, live overwrite punch status is buffered instead of written to the terminal.
pub fn set_stdin_read_active(active: bool) {
    STDIN_READ_ACTIVE.store(active, Ordering::Release);
}

/// Print the latest deferred punch status (after stdin read completes).
pub fn flush_deferred_live_status() {
    let line = deferred_live_overwrite().lock().unwrap().take();
    if let Some(display) = line {
        println!("{display}");
    }
}

fn render_live_overwrite_row(display: &str) {
    if STDIN_READ_ACTIVE.load(Ordering::Acquire) {
        *deferred_live_overwrite().lock().unwrap() = Some(display.to_string());
        return;
    }
    print!("\r\x1B[2K{display}");
    let _ = std::io::Write::flush(&mut std::io::stdout());
}

/// Daemon routes all CLI output to the UI event bus (thin clients subscribe).
pub fn set_daemon_ui_bus(bus: std::sync::Arc<crate::ui_events::UiEventBus>) {
    let _ = DAEMON_UI.set(bus);
}

fn daemon_ui_emit(line: crate::ui_events::UiLine) {
    if let Some(ui) = DAEMON_UI.get() {
        ui.emit(line);
    }
}

fn daemon_ui_emit_live(line: crate::ui_events::UiLine) {
    if let Some(ui) = DAEMON_UI.get() {
        ui.emit_live_only(line);
    }
}

/// Hole-punch / in-progress reconnect logs: stream live, never replay-buffered.
pub fn emit_line_live(line: String) {
    if DAEMON_UI.get().is_some() {
        daemon_ui_emit_live(crate::ui_events::UiLine::Plain(line));
        return;
    }
    if let Some(rest) = line.strip_prefix(crate::ui_events::MARK_LIVE_OVERWRITE) {
        render_live_overwrite_row(rest);
        return;
    }
    println!("{line}");
}

fn slot() -> &'static Mutex<Option<Vec<String>>> {
    CAPTURE.get_or_init(|| Mutex::new(None))
}

pub fn begin_capture() {
    *slot().lock().unwrap() = Some(Vec::new());
}

pub fn end_capture() -> Vec<String> {
    slot().lock().unwrap().take().unwrap_or_default()
}

pub fn is_capturing() -> bool {
    slot().lock().unwrap().is_some()
}

fn push_line(line: String) {
    if let Some(buf) = slot().lock().unwrap().as_mut() {
        buf.push(line);
    }
}

pub fn emit_line(line: String) {
    if DAEMON_UI.get().is_some() {
        if is_capturing() {
            push_line(line);
            return;
        }
        daemon_ui_emit(crate::ui_events::UiLine::Plain(line));
        return;
    }
    if is_capturing() {
        push_line(line);
    } else {
        println!("{line}");
    }
}

pub fn emit_stderr_line(line: String) {
    if DAEMON_UI.get().is_some() {
        if is_capturing() {
            push_line(format!("[stderr] {line}"));
            return;
        }
        daemon_ui_emit(crate::ui_events::UiLine::Stderr(line));
        return;
    }
    if is_capturing() {
        push_line(format!("[stderr] {line}"));
    } else {
        eprintln!("{line}");
    }
}

pub fn emit_prompt(text: String) {
    if DAEMON_UI.get().is_some() {
        if is_capturing() {
            push_line(format!("{MARK_PROMPT}{text}"));
            return;
        }
        daemon_ui_emit(crate::ui_events::UiLine::PromptHint(text));
        return;
    }
    if is_capturing() {
        push_line(format!("{MARK_PROMPT}{text}"));
    } else {
        print!("{text}");
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
}

pub fn emit_clear_screen() {
    if DAEMON_UI.get().is_some() {
        if is_capturing() {
            push_line(MARK_CLEAR.to_string());
            return;
        }
        daemon_ui_emit(crate::ui_events::UiLine::Clear);
        return;
    }
    if is_capturing() {
        push_line(MARK_CLEAR.to_string());
    } else {
        print!("\x1B[2J\x1B[H\x1B[3J");
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
}

pub fn emit_session_ready() {
    if DAEMON_UI.get().is_some() {
        if is_capturing() {
            push_line(crate::ui_events::MARK_SESSION_READY.to_string());
            return;
        }
        daemon_ui_emit(crate::ui_events::UiLine::SessionReady);
        return;
    }
}

/// Full-screen clear on the interactive CLI client (e.g. before `more` submenu).
pub fn clear_user_terminal() {
    render_to_user_terminal(MARK_CLEAR);
}

/// Line-by-line pacing on the CLI client (list, ping, more, commands, create/join status).
pub const DISPLAY_LINE_DELAY_MS: u64 = 10;
pub const STATUS_LINE_DELAY_MS: u64 = 100;

/// Colored progress lines ([NAT], Wintun [i], [PARA], punch).
pub fn is_staggered_status_line(line: &str) -> bool {
    if line == MARK_CLEAR || line.starts_with(MARK_PROMPT) {
        return false;
    }
    if line.contains("[■■") {
        return false;
    }
    line.contains("[NAT]")
        || line.contains("[PARA]")
        || line.contains("[PUNCH")
        || line.contains("[P2P]")
        || line.contains("[i]")
}

fn delay_after_line(line: &str) -> u64 {
    if line == MARK_CLEAR || line.starts_with(MARK_PROMPT) {
        return 0;
    }
    if is_staggered_status_line(line) {
        STATUS_LINE_DELAY_MS
    } else {
        DISPLAY_LINE_DELAY_MS
    }
}

/// Render captured IPC / command lines on the interactive client (with optional pacing).
pub async fn render_lines_to_user_terminal(lines: &[String]) {
    for l in lines {
        render_to_user_terminal(l);
        let ms = delay_after_line(l);
        if ms > 0 {
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
    }
}

/// Render one IPC output line on the user's terminal (client process).
pub fn render_to_user_terminal(line: &str) {
    if line == MARK_CLEAR {
        print!("\x1B[2J\x1B[H\x1B[3J");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        return;
    }
    if line == crate::ui_events::MARK_SESSION_READY {
        return;
    }
    if let Some(rest) = line.strip_prefix(crate::ui_events::MARK_LIVE_OVERWRITE) {
        render_live_overwrite_row(rest);
        return;
    }
    if let Some(rest) = line.strip_prefix(MARK_PROMPT) {
        print!("{rest}");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        return;
    }
    println!("{line}");
}
