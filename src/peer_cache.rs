use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::{Deserialize, Serialize};

const MAX_ENDPOINTS_PER_VIP: usize = 32;
const ENDPOINT_TTL_SECS: u64 = 7 * 24 * 3600;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachedEndpoint {
    pub endpoint: String,
    #[serde(default)]
    pub last_seen_epoch_s: u64,
}

#[derive(Default, Clone, Debug)]
pub struct PeerCache {
    pub by_vip: HashMap<String, Vec<CachedEndpoint>>,
}

fn now_epoch_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse_endpoint_list(val: &serde_json::Value, now_s: u64) -> Vec<CachedEndpoint> {
    let Some(arr) = val.as_array() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for el in arr {
        if let Some(s) = el.as_str() {
            if s.parse::<std::net::SocketAddr>().is_ok() {
                out.push(CachedEndpoint {
                    endpoint: s.to_string(),
                    last_seen_epoch_s: now_s,
                });
            }
            continue;
        }
        if let Some(obj) = el.as_object() {
            let ep = obj.get("endpoint").and_then(|x| x.as_str()).unwrap_or("");
            if ep.parse::<std::net::SocketAddr>().is_err() {
                continue;
            }
            let last_seen = obj
                .get("last_seen_epoch_s")
                .and_then(|x| x.as_u64())
                .unwrap_or(now_s);
            out.push(CachedEndpoint {
                endpoint: ep.to_string(),
                last_seen_epoch_s: last_seen,
            });
        }
    }
    out
}

pub fn load_peer_cache(path: &Path) -> Result<PeerCache> {
    if !path.exists() {
        return Ok(PeerCache::default());
    }
    let raw = std::fs::read_to_string(path)?;
    if raw.trim().is_empty() {
        return Ok(PeerCache::default());
    }
    let now_s = now_epoch_s();
    let v: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return Ok(PeerCache::default()),
    };
    let mut cache = PeerCache::default();
    if let Some(map) = v.get("by_vip").and_then(|x| x.as_object()) {
        for (vip, endpoints_val) in map {
            if vip.parse::<std::net::Ipv4Addr>().is_err() {
                continue;
            }
            let list = parse_endpoint_list(endpoints_val, now_s);
            if !list.is_empty() {
                cache.by_vip.insert(vip.clone(), list);
            }
        }
    }
    normalize_cache(&mut cache);
    Ok(cache)
}

pub fn save_peer_cache(path: &Path, cache: &PeerCache) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let now_s = now_epoch_s();
    let mut by_vip: HashMap<String, Vec<CachedEndpoint>> = HashMap::new();
    for (vip, endpoints) in &cache.by_vip {
        if vip.parse::<std::net::Ipv4Addr>().is_err() {
            continue;
        }
        let valid = normalized_endpoints(endpoints, now_s);
        if !valid.is_empty() {
            by_vip.insert(vip.clone(), valid);
        }
    }
    let body = serde_json::json!({ "by_vip": by_vip });
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = path.with_extension(format!("tmp.{nonce}"));
    std::fs::write(&tmp, serde_json::to_vec_pretty(&body)?)?;
    #[cfg(windows)]
    if std::fs::rename(&tmp, path).is_err() {
        std::fs::copy(&tmp, path)?;
        let _ = std::fs::remove_file(&tmp);
    }
    #[cfg(not(windows))]
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

pub fn remember_endpoint(cache: &mut PeerCache, vip: &str, endpoint: &str) {
    if vip.parse::<std::net::Ipv4Addr>().is_err() {
        return;
    }
    if endpoint.parse::<std::net::SocketAddr>().is_err() {
        return;
    }
    let now_s = now_epoch_s();
    let list = cache.by_vip.entry(vip.to_string()).or_default();
    if let Some(pos) = list.iter().position(|e| e.endpoint == endpoint) {
        let mut existing = list.remove(pos);
        existing.last_seen_epoch_s = now_s;
        list.insert(0, existing);
    } else {
        list.insert(
            0,
            CachedEndpoint {
                endpoint: endpoint.to_string(),
                last_seen_epoch_s: now_s,
            },
        );
    }
    if list.len() > MAX_ENDPOINTS_PER_VIP {
        list.truncate(MAX_ENDPOINTS_PER_VIP);
    }
}

fn normalize_cache(cache: &mut PeerCache) {
    let now_s = now_epoch_s();
    cache.by_vip.retain(|vip, endpoints| {
        if vip.parse::<std::net::Ipv4Addr>().is_err() {
            return false;
        }
        let mut out: Vec<CachedEndpoint> = Vec::new();
        let mut seen_ep: HashSet<&str> = HashSet::new();
        for ce in endpoints.iter() {
            if ce.endpoint.is_empty() {
                continue;
            }
            if now_s.saturating_sub(ce.last_seen_epoch_s) > ENDPOINT_TTL_SECS {
                continue;
            }
            if seen_ep.insert(ce.endpoint.as_str()) {
                out.push(ce.clone());
            }
            if out.len() >= MAX_ENDPOINTS_PER_VIP {
                break;
            }
        }
        *endpoints = out;
        !endpoints.is_empty()
    });
}

fn normalized_endpoints(endpoints: &[CachedEndpoint], now_s: u64) -> Vec<CachedEndpoint> {
    let mut out: Vec<CachedEndpoint> = Vec::new();
    let mut seen_ep: HashSet<&str> = HashSet::new();
    for ce in endpoints {
        if ce.endpoint.is_empty() {
            continue;
        }
        if now_s.saturating_sub(ce.last_seen_epoch_s) > ENDPOINT_TTL_SECS {
            continue;
        }
        if seen_ep.insert(ce.endpoint.as_str()) {
            out.push(ce.clone());
        }
        if out.len() >= MAX_ENDPOINTS_PER_VIP {
            break;
        }
    }
    out
}
