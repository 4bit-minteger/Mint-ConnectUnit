use anyhow::Result;
use bytes::Bytes;

pub trait VirtualNetworkInterface: Send + Sync {
    fn send(&self, data: &[u8]) -> Result<()>;
    fn try_recv(&self) -> Result<Option<Bytes>>;
    fn name(&self) -> &str;
}

#[cfg(windows)]
pub mod wintun;
