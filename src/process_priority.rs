#[cfg(windows)]
use anyhow::Context;

#[cfg(windows)]
pub fn apply_mint_process_priority(level: u8) -> anyhow::Result<()> {
    use windows::Win32::System::Threading::{
        GetCurrentProcess, SetPriorityClass, HIGH_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS,
        REALTIME_PRIORITY_CLASS,
    };

    let class = match level {
        1 => REALTIME_PRIORITY_CLASS,
        2 => HIGH_PRIORITY_CLASS,
        3 => NORMAL_PRIORITY_CLASS,
        _ => anyhow::bail!("prio: expected 1, 2, or 3 (1=realtime, 2=high, 3=normal)"),
    };

    unsafe {
        SetPriorityClass(GetCurrentProcess(), class)
            .ok()
            .context("SetPriorityClass failed")?;
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn apply_mint_process_priority(_level: u8) -> anyhow::Result<()> {
    anyhow::bail!("prio is only supported on Windows");
}

#[cfg(windows)]
pub fn prio_level_label(level: u8) -> &'static str {
    match level {
        1 => "realtime",
        2 => "high",
        3 => "normal",
        _ => "unknown",
    }
}

#[cfg(not(windows))]
pub fn prio_level_label(_level: u8) -> &'static str {
    "unsupported"
}

pub fn normalize_process_priority_level(level: u8) -> u8 {
    if (1..=3).contains(&level) {
        level
    } else {
        2
    }
}

pub fn apply_startup_process_priority(level: u8) {
    let level = normalize_process_priority_level(level);
    #[cfg(windows)]
    {
        if let Err(e) = apply_mint_process_priority(level) {
            eprintln!(
                "{}",
                crate::term_style::fmt_info_line(format_args!(
                    " Could not set process priority to {}: {e}",
                    prio_level_label(level)
                ))
            );
        }
    }
}
