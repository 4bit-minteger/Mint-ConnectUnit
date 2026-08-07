use std::fmt::Display;
use std::io::IsTerminal;

#[inline]
fn no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some()
}

#[inline]
pub fn use_stdout_ansi() -> bool {
    std::io::stdout().is_terminal() && !no_color()
}

#[inline]
pub fn use_stderr_ansi() -> bool {
    std::io::stderr().is_terminal() && !no_color()
}

const FG_BODY: &str = "\x1b[38;2;238;238;238m";
const RESET: &str = "\x1b[0m";

const FG_INFO: &str = "\x1b[38;2;245;23;7m";
const FG_OK: &str = "\x1b[38;2;5;242;100m";
const FG_JOIN: &str = "\x1b[38;2;29;245;169m";
const FG_PARA: &str = "\x1b[38;2;252;119;3m";
const FG_PUNCH: &str = "\x1b[38;2;193;255;107m";
const FG_RECONNECTED: &str = "\x1b[38;2;2;189;30m";
const FG_INPUT_PROMPT: &str = "\x1b[38;2;81;224;193m";
const FG_WHITE: &str = "\x1b[38;2;255;255;255m";
const FG_NAT: &str = "\x1b[38;2;252;245;96m";

/// Color only the label inside `[...]`; brackets stay body-colored.
fn fmt_tag_out(lead: &str, label: &str, tag_fg: &str, rest: impl Display) -> String {
    let r = rest.to_string();
    if !use_stdout_ansi() {
        return format!("{lead}[{label}]{r}");
    }
    format!("{lead}{FG_BODY}[{tag_fg}{label}{FG_BODY}]{r}{RESET}")
}

fn fmt_tag_err(lead: &str, label: &str, tag_fg: &str, rest: impl Display) -> String {
    let r = rest.to_string();
    if !use_stderr_ansi() {
        return format!("{lead}[{label}]{r}");
    }
    format!("{lead}{FG_BODY}[{tag_fg}{label}{FG_BODY}]{r}{RESET}")
}

pub fn fmt_join_line(rest: impl Display) -> String {
    fmt_tag_out("  ", "JOIN", FG_JOIN, rest)
}

pub fn fmt_join_line_stderr(rest: impl Display) -> String {
    fmt_tag_err("  ", "JOIN", FG_JOIN, rest)
}

pub fn fmt_para_line(rest: impl Display) -> String {
    fmt_tag_out("  ", "PARA", FG_PARA, rest)
}

pub fn fmt_para_line_stderr(rest: impl Display) -> String {
    fmt_tag_err("  ", "PARA", FG_PARA, rest)
}

pub fn fmt_para_passive_line(rest: impl Display) -> String {
    fmt_para_line(rest)
}

pub fn fmt_para_passive_line_stderr(rest: impl Display) -> String {
    fmt_para_line_stderr(rest)
}

pub fn fmt_para_passive_line_success(rest: impl Display) -> String {
    let r = rest.to_string();
    if !use_stdout_ansi() {
        return format!("  [PARA]{r}");
    }
    format!("  {FG_BODY}[{FG_PARA}PARA{FG_BODY}]{FG_RECONNECTED}{r}{RESET}")
}

pub fn fmt_profile_loaded_home_line() -> String {
    if !use_stdout_ansi() {
        return "  [CONFIG] Unit profile loaded!".to_string();
    }
    format!("  {FG_BODY}[{FG_JOIN}CONFIG{FG_BODY}] Unit profile loaded!{RESET}")
}

pub fn fmt_try_again_home_line() -> String {
    "  Try again later?".to_string()
}

pub fn fmt_input_prompt() -> String {
    if !use_stdout_ansi() {
        return "\n<[=Input=]: ".to_string();
    }
    format!("\n{FG_WHITE}<{FG_INPUT_PROMPT}[=Input=]{FG_WHITE}:{RESET} ")
}

pub fn fmt_nat_line(rest: impl Display) -> String {
    fmt_tag_out("  ", "NAT", FG_NAT, rest)
}

/// Attention / error line: `[i]`, flush-left (no indent).
pub fn fmt_info_line(rest: impl Display) -> String {
    fmt_tag_out("", "i", FG_INFO, rest)
}

pub fn fmt_info_line_stderr(rest: impl Display) -> String {
    fmt_tag_err("", "i", FG_INFO, rest)
}

/// Positive / in-progress line: `[^]` with indent; `^` is `#05f264`.
pub fn fmt_ok_line(rest: impl Display) -> String {
    let r = rest.to_string();
    if !use_stdout_ansi() {
        return format!("  [^]{r}");
    }
    format!("  {FG_BODY}[{FG_OK}^{FG_BODY}]{r}{RESET}")
}

pub fn fmt_ok_line_stderr(rest: impl Display) -> String {
    let r = rest.to_string();
    if !use_stderr_ansi() {
        return format!("  [^]{r}");
    }
    format!("  {FG_BODY}[{FG_OK}^{FG_BODY}]{r}{RESET}")
}

pub fn fmt_punch_line(rest: impl Display) -> String {
    fmt_tag_out("  ", "PUNCH", FG_PUNCH, rest)
}

/// Alias for attention lines (same as [`fmt_info_line`]).
pub fn fmt_bang_line(rest: impl Display) -> String {
    fmt_info_line(rest)
}

pub fn fmt_bang_line_stderr(rest: impl Display) -> String {
    fmt_info_line_stderr(rest)
}

pub fn fmt_punch_loop_line(label: &str, rest: impl Display) -> String {
    let r = rest.to_string();
    let label = match label {
        "[JOIN]" | "JOIN" => "JOIN",
        "[PUNCH]" | "PUNCH" => "PUNCH",
        l if l.contains("PARA") => "PARA",
        other => other.trim_start_matches('[').trim_end_matches(']'),
    };
    let tag_fg = match label {
        "JOIN" => FG_JOIN,
        "PUNCH" => FG_PUNCH,
        "PARA" => FG_PARA,
        _ => FG_BODY,
    };
    if !use_stdout_ansi() {
        return format!("  [{label}]{r}");
    }
    format!("  {FG_BODY}[{tag_fg}{label}{FG_BODY}]{r}{RESET}")
}
