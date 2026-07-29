use serde::{Deserialize, Serialize};

use crate::nat::stun::PublicEndpoint;
use crate::nat::upnp::UPnPMapping;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IceCandidate {
    pub ip: String,
    pub port: u16,
    #[serde(rename = "type")]
    pub kind: String,
}

pub fn gather_candidates(
    local_ip: &str,
    local_port: u16,
    stun: Option<&PublicEndpoint>,
    upnp: Option<&UPnPMapping>,
) -> Vec<IceCandidate> {
    let mut out = vec![IceCandidate {
        ip: local_ip.to_string(),
        port: local_port,
        kind: "host".to_string(),
    }];
    if let Some(s) = stun {
        out.push(IceCandidate {
            ip: s.ip.clone(),
            port: s.port,
            kind: "srflx".to_string(),
        });
    }
    if let Some(u) = upnp {
        out.push(IceCandidate {
            ip: u.external_ip.clone(),
            port: u.ext_port,
            kind: "upnp".to_string(),
        });
    }
    out
}
