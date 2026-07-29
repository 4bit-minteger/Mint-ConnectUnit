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

const FG_BANG: &str = "\x1b[38;2;245;23;7m";
const FG_INFO: &str = "\x1b[38;2;245;23;7m";
const FG_JOIN: &str = "\x1b[38;2;29;245;169m";
const FG_PARA: &str = "\x1b[38;2;252;119;3m";
const FG_PUNCH: &str = "\x1b[38;2;193;255;107m";
const FG_RECONNECTED: &str = "\x1b[38;2;2;189;30m";
const FG_INPUT_PROMPT: &str = "\x1b[38;2;81;224;193m";
const FG_WHITE: &str = "\x1b[38;2;255;255;255m";
const FG_NAT: &str = "\x1b[38;2;252;245;96m";

fn fmt_tag_out(lead: &str, tag: &str, tag_fg: &str, rest: impl Display) -> String {
    let r = rest.to_string();
    if !use_stdout_ansi() {
        return format!("{lead}{tag}{r}");
    }
    format!("{lead}{tag_fg}{tag}{FG_BODY}{r}{RESET}")
}

fn fmt_tag_err(lead: &str, tag: &str, tag_fg: &str, rest: impl Display) -> String {
    let r = rest.to_string();
    if !use_stderr_ansi() {
        return format!("{lead}{tag}{r}");
    }
    format!("{lead}{tag_fg}{tag}{FG_BODY}{r}{RESET}")
}

pub fn fmt_join_line(rest: impl Display) -> String {
    fmt_tag_out("  ", "[JOIN]", FG_JOIN, rest)
}

pub fn fmt_join_line_stderr(rest: impl Display) -> String {
    fmt_tag_err("  ", "[JOIN]", FG_JOIN, rest)
}

pub fn fmt_para_line(rest: impl Display) -> String {
    fmt_tag_out("  ", "[PARA]", FG_PARA, rest)
}

pub fn fmt_para_line_stderr(rest: impl Display) -> String {
    fmt_tag_err("  ", "[PARA]", FG_PARA, rest)
}

pub fn fmt_para_passive_line(rest: impl Display) -> String {
    fmt_tag_out("  ", "[PARA-PASSIVE]", FG_PARA, rest)
}

pub fn fmt_para_passive_line_stderr(rest: impl Display) -> String {
    fmt_tag_err("  ", "[PARA-PASSIVE]", FG_PARA, rest)
}

pub fn fmt_para_passive_line_success(rest: impl Display) -> String {
    let r = rest.to_string();
    if !use_stdout_ansi() {
        return format!("  [PARA-PASSIVE]{r}");
    }
    format!("  {FG_PARA}[PARA-PASSIVE]{FG_RECONNECTED}{r}{RESET}")
}

pub fn fmt_profile_loaded_home_line(server_name: &str) -> String {
    if !use_stdout_ansi() {
        return format!("  [CONFIG] Server profile loaded! Your home is: '{server_name}'");
    }
    format!(
        "  {FG_JOIN}[CONFIG]{FG_BODY} Server profile loaded! Your home is: '{server_name}'{RESET}"
    )
}

pub fn fmt_try_again_home_line(server_name: &str) -> String {
    if !use_stdout_ansi() {
        return format!("  Try again later? Your home is: '{server_name}'");
    }
    format!("  Try again later? {FG_BODY}Your home is: '{server_name}'{RESET}")
}

pub fn fmt_input_prompt() -> String {
    if !use_stdout_ansi() {
        return "\n<[=Input=]: ".to_string();
    }
    format!("\n{FG_WHITE}<{FG_INPUT_PROMPT}[=Input=]{FG_WHITE}:{RESET} ")
}

pub fn fmt_nat_line(rest: impl Display) -> String {
    fmt_tag_out("  ", "[NAT]", FG_NAT, rest)
}

pub fn fmt_info_line(rest: impl Display) -> String {
    fmt_tag_out("", "[i]", FG_INFO, rest)
}

pub fn fmt_info_line_stderr(rest: impl Display) -> String {
    fmt_tag_err("", "[i]", FG_INFO, rest)
}

pub fn fmt_punch_line(rest: impl Display) -> String {
    fmt_tag_out("  ", "[PUNCH]", FG_PUNCH, rest)
}

pub fn fmt_bang_line(rest: impl Display) -> String {
    let r = rest.to_string();
    if !use_stdout_ansi() {
        return format!("[!]{r}");
    }
    format!("{FG_BANG}[!]{FG_BODY}{r}{RESET}")
}

pub fn fmt_bang_line_stderr(rest: impl Display) -> String {
    let r = rest.to_string();
    if !use_stderr_ansi() {
        return format!("[!]{r}");
    }
    format!("{FG_BANG}[!]{FG_BODY}{r}{RESET}")
}

pub fn fmt_punch_loop_line(label: &str, rest: impl Display) -> String {
    let r = rest.to_string();
    if !use_stdout_ansi() {
        return format!("  {label}{r}");
    }
    let tag_fg = match label {
        "[JOIN]" => FG_JOIN,
        "[PUNCH]" => FG_PUNCH,
        "[PARA-PASSIVE-BURST-FIRST]"
        | "[PARA-PASSIVE-NARROW]"
        | "[PARA-PASSIVE-WIDE]"
        | "[PARA-BURST-FIRST]"
        | "[PARA-NARROW]"
        | "[PARA-WIDE]" => FG_PARA,
        _ => FG_BODY,
    };
    format!("  {tag_fg}{label}{FG_BODY}{r}{RESET}")
}
