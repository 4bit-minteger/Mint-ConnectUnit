use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use bytes::Bytes;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use wintun::{Adapter, Session, Wintun};

use crate::tun::VirtualNetworkInterface;

/// Friendly name shown in Windows Network Connections (set via netsh after create).
pub const WINTUN_ADAPTER_NAME: &str = "WMint-Tunnel";

/// Wintun driver pool type; default UI label is `{type} Tunnel` until `set_name` runs.
const WINTUN_TUNNEL_TYPE: &str = "WMint";

fn ensure_adapter_display_name(adapter: &Adapter) -> Result<()> {
    match adapter.get_name() {
        Ok(current) if current == WINTUN_ADAPTER_NAME => Ok(()),
        _ => adapter
            .set_name(WINTUN_ADAPTER_NAME)
            .map_err(|e| anyhow!("set adapter display name: {e}")),
    }
}

pub struct WintunAdapter {
    _wintun: Wintun,
    _adapter: Arc<Adapter>,
    session: Arc<Session>,
    name: String,
    read_loop_started: AtomicBool,
    read_loop_handle: Mutex<Option<JoinHandle<()>>>,
    shutdown_flag: Arc<AtomicBool>,
}

impl WintunAdapter {
    pub fn create(
        name: &str,
        ip: Ipv4Addr,
        prefix_len: u8,
        ring_bytes: u32,
        ipv4_interface_metric: u32,
    ) -> Result<Self> {
        let wintun = unsafe { wintun::load_from_path("wintun.dll") }
            .map_err(|e| anyhow!("load wintun.dll: {e}"))?;
        let adapter = match Adapter::open(&wintun, name) {
            Ok(a) => a,
            Err(_) => Adapter::create(&wintun, name, WINTUN_TUNNEL_TYPE, None)
                .map_err(|e| anyhow!("create adapter: {e}"))?,
        };
        if let Err(e) = ensure_adapter_display_name(&adapter) {
            eprintln!("  [WINTUN] could not set display name to {WINTUN_ADAPTER_NAME}: {e}");
        }
        let netsh_name = adapter.get_name().unwrap_or_else(|_| name.to_string());

        let _ = adapter.set_address(ip);
        let _ = adapter.set_network_addresses_tuple(
            IpAddr::V4(ip),
            IpAddr::V4(prefix_to_mask(prefix_len)),
            None,
        );

        let cap = ring_bytes
            .max(wintun::MIN_RING_CAPACITY)
            .min(wintun::MAX_RING_CAPACITY)
            .next_power_of_two()
            .min(wintun::MAX_RING_CAPACITY);
        let session = Arc::new(adapter.start_session(cap).map_err(|e| anyhow!("{e}"))?);

        let this = Self {
            _wintun: wintun,
            _adapter: adapter,
            session,
            name: netsh_name,
            read_loop_started: AtomicBool::new(false),
            read_loop_handle: Mutex::new(None),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        };
        if ipv4_interface_metric > 0 {
            if let Err(e) = this.set_ipv4_interface_metric(ipv4_interface_metric) {
                eprintln!("  [WINTUN] could not set IPv4 interface metric={ipv4_interface_metric} (try running as Administrator): {e}");
            }
        }
        Ok(this)
    }

    pub fn start_read_loop(&self, tx: mpsc::Sender<Bytes>) {
        if self.read_loop_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let session = self.session.clone();
        let shutdown_flag = self.shutdown_flag.clone();
        let handle = tokio::task::spawn_blocking(move || loop {
            if shutdown_flag.load(Ordering::Acquire) {
                break;
            }
            match session.receive_blocking() {
                Ok(pkt) => {
                    let bytes = Bytes::copy_from_slice(pkt.bytes());
                    if tx.blocking_send(bytes).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        });
        *self.read_loop_handle.lock() = Some(handle);
    }

    pub fn set_ipv4_interface_metric(&self, metric: u32) -> Result<()> {
        if metric == 0 {
            return Ok(());
        }
        if !(1..=999_999).contains(&metric) {
            bail!("IPv4 interface metric out of range (1..=999999, or 0 to skip)");
        }
        if !is_safe_interface_alias(&self.name) {
            bail!("refusing to invoke netsh with unsafe adapter name");
        }
        use std::os::windows::process::CommandExt;
        let output = std::process::Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "interface",
                &self.name,
                &format!("metric={metric}"),
                "store=persistent",
            ])
            .creation_flags(0x08000000)
            .output()?;
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            let out = String::from_utf8_lossy(&output.stdout);
            bail!("netsh IPv4 interface metric failed: {err}{out}");
        }
        Ok(())
    }

    pub fn set_mtu(&self, mtu: u16) -> Result<()> {
        if !is_safe_interface_alias(&self.name) {
            bail!("refusing to invoke netsh with unsafe adapter name");
        }
        if !(576..=1500).contains(&mtu) {
            bail!("mtu out of range");
        }
        use std::os::windows::process::CommandExt;
        let output = std::process::Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "subinterface",
                &self.name,
                &format!("mtu={mtu}"),
                "store=persistent",
            ])
            .creation_flags(0x08000000)
            .output()?;
        if !output.status.success() {
            bail!("netsh mtu update failed");
        }
        Ok(())
    }

    pub fn shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::Release);
        let _ = self.session.shutdown();
    }

    pub fn close(&self) {
        self.shutdown();
        if let Some(handle) = self.read_loop_handle.lock().take() {
            handle.abort();
        }
    }
}

impl Drop for WintunAdapter {
    fn drop(&mut self) {
        self.shutdown_flag.store(true, Ordering::Release);
        let _ = self.session.shutdown();
        if let Some(handle) = self.read_loop_handle.lock().take() {
            handle.abort();
        }
    }
}

impl VirtualNetworkInterface for WintunAdapter {
    fn send(&self, data: &[u8]) -> Result<()> {
        if data.len() > u16::MAX as usize {
            bail!("packet too large for wintun send");
        }
        let mut pkt = self
            .session
            .allocate_send_packet(data.len() as u16)
            .map_err(|e| anyhow!("allocate send packet: {e}"))?;
        pkt.bytes_mut().copy_from_slice(data);
        self.session.send_packet(pkt);
        Ok(())
    }

    fn try_recv(&self) -> Result<Option<Bytes>> {
        Err(anyhow!(
            "Wintun uses push model via start_read_loop, try_recv is unsupported"
        ))
    }

    fn name(&self) -> &str {
        &self.name
    }
}

fn prefix_to_mask(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    let mask = u32::MAX << (32 - prefix.min(32));
    Ipv4Addr::from(mask.to_be_bytes())
}

fn is_safe_interface_alias(s: &str) -> bool {
    if s.is_empty() || s.len() > 128 {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.' | '(' | ')'))
}
