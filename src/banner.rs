//! ASCII home logo — rendered on the CLI client at first open (no saved profile).

use std::io::Write;
use std::time::Duration;

/// Delay between banner lines (first open).
pub const BANNER_LINE_DELAY_MS: u64 = 20;

pub fn banner_lines() -> &'static [&'static str] {
    &[
        "                    ╔────────╗",
        "               ╔««-{|MÏntege®|}<═┓",
        "               |    ╚══-═┳═-═╝   ╚==╔───╗",
        "        ╔=═════╧═=╗ ╔^╗——|   ╔────╗ ╚─┳─╝┌≡≡≡==--.....",
        "        ╠──0░10░──╣ ╚^╝  ┣+>[| :) |]══┣━<╣ >> ConnectUnit <<",
        "      ┏[|0▒01▓1010|]<+━━━┫╔░╗╚──┳─╝   |  └≡≡≡==--..",
        "      | ╠──1░10▒──╣ [▄▄]—┫╚░╝   |    ╔┻───╗",
        "      ┃ ╚=═══╤═══=╝ ╔=═══╧═══=╗ ┣━»>[|####|",
        "      |======┃==██  ╠──■■■■■──╣ |    ╚────╝",
        "             ┗━━━»>[| ■#####■ |]┛",
        "-----<              ╠──■■■■■──╣",
        "-----------<        ╚=═══════=╝",
        "--------------<",
        "------------------------------------------<",
    ]
}

pub async fn render_banner_to_stdout(line_delay_ms: u64) {
    for line in banner_lines() {
        println!("{line}");
        let _ = std::io::stdout().flush();
        if line_delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(line_delay_ms)).await;
        }
    }
}

/// True for daemon-emitted banner lines (skip on UI replay; client draws banner).
pub fn is_banner_art_line(line: &str) -> bool {
    let t = line.trim();
    t.contains("Minteger")
        || t.contains("ConnectUnit")
        || t.contains('╔')
        || t.contains('╚')
        || t.contains('╠')
        || t.contains('┃')
        || (t.contains("■■") && t.contains('<') && t.len() > 20)
}
