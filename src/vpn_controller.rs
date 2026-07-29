//! Headless VPN control plane: engine host + `Cli` command executor (no local REPL).

use std::sync::Arc;

use parking_lot::{Mutex, RwLock};

use crate::bootstrap::BootstrapSnapshot;
use crate::cli::Cli;
use crate::config::ConfigManager;
use crate::ui_events::UiSink;

pub struct VpnController {
    pub cli: Mutex<Cli>,
    pub config: Arc<ConfigManager>,
    pub ui: UiSink,
    pub bootstrap: Arc<RwLock<BootstrapSnapshot>>,
}

impl VpnController {
    pub fn new(cli: Cli, config: Arc<ConfigManager>, ui: UiSink) -> Self {
        Self {
            cli: Mutex::new(cli),
            config,
            ui,
            bootstrap: Arc::new(RwLock::new(BootstrapSnapshot::pending())),
        }
    }
}
