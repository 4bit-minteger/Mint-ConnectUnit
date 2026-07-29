//! Network persistence paths: `{exe_dir}/NetInfo/config.toml` and `peer_cache.json`.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};

pub const NETINFO_DIR_NAME: &str = "NetInfo";
pub const CONFIG_FILE_NAME: &str = "config.toml";
pub const PEER_CACHE_FILE_NAME: &str = "peer_cache.json";

/// Directory containing `mint.exe` (canonicalized when possible).
pub fn exe_dir() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("current_exe")?;
    let parent = exe
        .parent()
        .ok_or_else(|| anyhow!("executable has no parent directory"))?;
    parent.canonicalize().or_else(|_| Ok(parent.to_path_buf()))
}

pub fn netinfo_dir() -> Result<PathBuf> {
    Ok(exe_dir()?.join(NETINFO_DIR_NAME))
}

pub fn config_path() -> Result<PathBuf> {
    Ok(netinfo_dir()?.join(CONFIG_FILE_NAME))
}

pub fn peer_cache_path() -> Result<PathBuf> {
    Ok(netinfo_dir()?.join(PEER_CACHE_FILE_NAME))
}

pub fn ensure_netinfo_dir() -> Result<()> {
    let dir = netinfo_dir()?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create NetInfo directory {}", dir.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn netinfo_path_suffixes() {
        let parent = Path::new(r"C:\Apps\Mint");
        let netinfo = parent.join(NETINFO_DIR_NAME);
        let cfg = netinfo.join(CONFIG_FILE_NAME);
        let cache = netinfo.join(PEER_CACHE_FILE_NAME);
        assert!(cfg.ends_with("NetInfo/config.toml"));
        assert!(cache.ends_with("NetInfo/peer_cache.json"));
    }
}
