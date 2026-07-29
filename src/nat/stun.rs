use std::collections::HashMap;
use std::net::Ipv4Addr;

#[derive(Clone, Debug)]
pub struct PublicEndpoint {
    pub ip: String,
    pub port: u16,
}

pub const STUN_SERVERS: &[(&str, u16)] = &[
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun2.l.google.com", 19302),
    ("stun3.l.google.com", 19302),
    ("stun4.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("stun.nextcloud.com", 443),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn parse_stun_response_rejects_wrong_magic() {
        let mut txns = HashMap::new();
        txns.insert([1u8; 12], ());
        let buf = [0u8; 24];
        assert!(parse_stun_response(&buf, &txns).is_none());
    }
}

pub fn build_binding_request() -> ([u8; 20], [u8; 12]) {
    let mut msg = [0u8; 20];
    msg[0] = 0x00;
    msg[1] = 0x01;
    msg[2] = 0x00;
    msg[3] = 0x00;
    msg[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes());
    let txn = rand::random::<[u8; 12]>();
    msg[8..20].copy_from_slice(&txn);
    (msg, txn)
}

pub fn parse_stun_response(buf: &[u8], txns: &HashMap<[u8; 12], ()>) -> Option<PublicEndpoint> {
    const MAGIC: u32 = 0x2112A442;
    if buf.len() < 20
        || buf[0] != 0x01
        || buf[1] != 0x01
        || u32::from_be_bytes(buf[4..8].try_into().ok()?) != MAGIC
    {
        return None;
    }
    let mut txn = [0u8; 12];
    txn.copy_from_slice(&buf[8..20]);
    if !txns.contains_key(&txn) {
        return None;
    }

    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let mut offset = 20;
    let end = (20 + msg_len).min(buf.len());
    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;
        if offset + attr_len > end {
            break;
        }
        let data = &buf[offset..offset + attr_len];
        if attr_type == 0x0020 || attr_type == 0x0001 {
            if data.len() >= 8 && data[1] == 0x01 {
                let mut port = u16::from_be_bytes([data[2], data[3]]);
                let mut ip_bytes = [data[4], data[5], data[6], data[7]];
                if attr_type == 0x0020 {
                    port ^= (MAGIC >> 16) as u16;
                    let magic_bytes = MAGIC.to_be_bytes();
                    for i in 0..4 {
                        ip_bytes[i] ^= magic_bytes[i];
                    }
                }
                let ip = Ipv4Addr::from(ip_bytes).to_string();
                return Some(PublicEndpoint { ip, port });
            }
        }
        offset += attr_len;
        if offset % 4 != 0 {
            offset += 4 - (offset % 4);
        }
    }
    None
}
