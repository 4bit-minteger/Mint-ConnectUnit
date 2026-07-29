#![allow(clippy::all)]

pub mod bcast;
#[macro_export]
macro_rules! cli_println {
    () => {
        $crate::cli_emit::emit_line(String::new())
    };
    ($($arg:tt)*) => {
        $crate::cli_emit::emit_line(format!($($arg)*))
    };
}

/// Transient progress (hole punch); live stream only, not stored in UI replay ring.
#[macro_export]
macro_rules! cli_println_live {
    ($($arg:tt)*) => {
        $crate::cli_emit::emit_line_live(format!($($arg)*))
    };
}

#[macro_export]
macro_rules! cli_eprintln {
    ($($arg:tt)*) => {
        $crate::cli_emit::emit_stderr_line(format!($($arg)*))
    };
}

#[macro_export]
macro_rules! cli_print {
    ($($arg:tt)*) => {
        $crate::cli_emit::emit_prompt(format!($($arg)*))
    };
}
pub mod advanced_tuning;
pub mod banner;
pub mod bootstrap;
pub mod cli;
pub mod cli_emit;
pub mod cli_session;
pub mod client_main;
pub mod config;
pub mod console_util;
pub mod cpu_affinity;
pub mod crypto;
pub mod daemon;
pub mod engine_bootstrap;
pub mod ipc;
pub mod metrics;
pub mod nat;
pub mod net;
pub mod netinfo;
pub mod peer_cache;
pub mod pmtud;
pub mod process_display;
pub mod process_priority;
pub mod profile;
pub mod routing;
pub mod runtime_trace;
pub mod term_style;
pub mod tun;
pub mod ui_events;
pub mod vpn_controller;
#[cfg(windows)]
pub mod windows_elevation;
pub mod windows_timer;
