use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use anyhow::{bail, Result};
use rand::{thread_rng, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const CONNECT_MAGIC: u64 = 0x4172_7101_980;
pub const ACTION_CONNECT: u32 = 0;
pub const ACTION_ANNOUNCE: u32 = 1;
pub const ACTION_CONNECT_RESPONSE: u32 = 0;
pub const ACTION_ANNOUNCE_RESPONSE: u32 = 1;

pub const CONNECT_REQUEST_LEN: usize = 16;
pub const ANNOUNCE_REQUEST_LEN: usize = 98;
pub const ANNOUNCE_HEADER_LEN: usize = 20;
pub const COMPACT_PEER_LEN: usize = 6;
pub const MAX_PEERS_PER_RESPONSE: usize = 512;
pub const MAX_HTTP_ANNOUNCE_BODY: usize = 128 * 1024;
pub const HTTP_TRACKER_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrackerScheme {
    Udp,
    Http,
    Https,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackerEndpoint {
    pub scheme: TrackerScheme,
    pub host: String,
    pub port: u16,
    /// Path beginning with `/` (query string stripped; announce query is built separately).
    pub path: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionId(pub [u8; 4]);

impl TransactionId {
    pub fn random() -> Self {
        let mut t = [0u8; 4];
        thread_rng().fill_bytes(&mut t);
        Self(t)
    }
}

pub fn build_connect_request(txn: TransactionId) -> [u8; CONNECT_REQUEST_LEN] {
    let mut buf = [0u8; CONNECT_REQUEST_LEN];
    buf[0..8].copy_from_slice(&CONNECT_MAGIC.to_be_bytes());
    buf[8..12].copy_from_slice(&ACTION_CONNECT.to_be_bytes());
    buf[12..16].copy_from_slice(&txn.0);
    buf
}

pub fn parse_connect_response(buf: &[u8], expected_txn: TransactionId) -> Result<u64> {
    if buf.len() < 16 {
        bail!("connect response too short");
    }
    let action = u32::from_be_bytes(
        buf[0..4]
            .try_into()
            .map_err(|_| anyhow::anyhow!("action"))?,
    );
    if action != ACTION_CONNECT_RESPONSE {
        bail!("unexpected connect action");
    }
    let txn: [u8; 4] = buf[4..8].try_into().map_err(|_| anyhow::anyhow!("txn"))?;
    if txn != expected_txn.0 {
        bail!("connect transaction mismatch");
    }
    Ok(u64::from_be_bytes(
        buf[8..16].try_into().map_err(|_| anyhow::anyhow!("conn"))?,
    ))
}

pub fn build_announce_request(
    connection_id: u64,
    txn: TransactionId,
    info_hash: &[u8; 20],
    peer_id: &[u8; 20],
    port: u16,
    num_want: i32,
) -> [u8; ANNOUNCE_REQUEST_LEN] {
    let mut buf = [0u8; ANNOUNCE_REQUEST_LEN];
    buf[0..8].copy_from_slice(&connection_id.to_be_bytes());
    buf[8..12].copy_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
    buf[12..16].copy_from_slice(&txn.0);
    buf[16..36].copy_from_slice(info_hash);
    buf[36..56].copy_from_slice(peer_id);
    // downloaded, left, uploaded = 0
    buf[80..84].copy_from_slice(&0u32.to_be_bytes()); // event: none
    buf[84..88].copy_from_slice(&0u32.to_be_bytes()); // ip: default
    buf[88..92].copy_from_slice(&0u32.to_be_bytes()); // key
    buf[92..96].copy_from_slice(&num_want.to_be_bytes());
    buf[96..98].copy_from_slice(&port.to_be_bytes());
    buf
}

pub fn parse_compact_peers(peer_bytes: &[u8]) -> Result<Vec<SocketAddr>> {
    if !peer_bytes.len().is_multiple_of(COMPACT_PEER_LEN) {
        bail!("malformed compact peer list");
    }
    let n = peer_bytes.len() / COMPACT_PEER_LEN;
    if n > MAX_PEERS_PER_RESPONSE {
        bail!("too many peers");
    }
    let mut peers = Vec::with_capacity(n);
    for chunk in peer_bytes.chunks_exact(COMPACT_PEER_LEN) {
        let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
        let port = u16::from_be_bytes([chunk[4], chunk[5]]);
        if port == 0 {
            continue;
        }
        peers.push(SocketAddr::V4(SocketAddrV4::new(ip, port)));
    }
    Ok(peers)
}

pub fn parse_announce_response(
    buf: &[u8],
    expected_txn: TransactionId,
) -> Result<(u32, Vec<SocketAddr>)> {
    if buf.len() < ANNOUNCE_HEADER_LEN {
        bail!("announce response too short");
    }
    let action = u32::from_be_bytes(
        buf[0..4]
            .try_into()
            .map_err(|_| anyhow::anyhow!("action"))?,
    );
    if action != ACTION_ANNOUNCE_RESPONSE {
        bail!("unexpected announce action");
    }
    let txn: [u8; 4] = buf[4..8].try_into().map_err(|_| anyhow::anyhow!("txn"))?;
    if txn != expected_txn.0 {
        bail!("announce transaction mismatch");
    }
    let interval = u32::from_be_bytes(buf[8..12].try_into().map_err(|_| anyhow::anyhow!("int"))?);
    let peers = parse_compact_peers(&buf[ANNOUNCE_HEADER_LEN..])?;
    Ok((interval, peers))
}

/// Parse `udp://host:port/...` into host/port (DNS must be resolved by caller).
pub fn parse_tracker_url(url: &str) -> Option<(String, u16)> {
    let ep = parse_tracker_endpoint(url)?;
    if ep.scheme != TrackerScheme::Udp {
        return None;
    }
    Some((ep.host, ep.port))
}

/// Parse `udp|http|https://host[:port]/path`.
pub fn parse_tracker_endpoint(url: &str) -> Option<TrackerEndpoint> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("udp://") {
        (TrackerScheme::Udp, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (TrackerScheme::Http, r)
    } else if let Some(r) = url.strip_prefix("https://") {
        (TrackerScheme::Https, r)
    } else {
        return None;
    };

    let (authority, path_raw) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() {
        return None;
    }
    // IPv6 authorities are out of scope (engine discovery is IPv4-only).
    if authority.starts_with('[') {
        return None;
    }

    let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        let port: u16 = p.parse().ok()?;
        if h.is_empty() || port == 0 {
            return None;
        }
        (h.to_string(), port)
    } else {
        let port = match scheme {
            TrackerScheme::Http => 80,
            TrackerScheme::Https => 443,
            TrackerScheme::Udp => return None,
        };
        (authority.to_string(), port)
    };

    let path = if path_raw.is_empty() {
        "/announce".to_string()
    } else {
        let path_only = path_raw.split_once('?').map(|(p, _)| p).unwrap_or(path_raw);
        format!("/{path_only}")
    };

    Some(TrackerEndpoint {
        scheme,
        host,
        port,
        path,
    })
}

pub fn percent_encode_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for &b in bytes {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Build the request-target (`/path?query`) for a BEP3 announce.
pub fn build_http_announce_request_target(
    path: &str,
    info_hash: &[u8; 20],
    peer_id: &[u8; 20],
    port: u16,
    num_want: i32,
) -> String {
    let path = if path.is_empty() { "/announce" } else { path };
    format!(
        "{path}?info_hash={}&peer_id={}&port={port}&uploaded=0&downloaded=0&left=0&compact=1&numwant={num_want}",
        percent_encode_bytes(info_hash),
        percent_encode_bytes(peer_id),
    )
}

/// Parse a BEP3 announce response body (bencode). Requires compact `peers` byte string.
pub fn parse_http_announce_body(body: &[u8]) -> Result<(u32, Vec<SocketAddr>)> {
    let mut idx = 0usize;
    let root = parse_bencode(body, &mut idx)?;
    if idx != body.len() {
        // Trailing junk is common; ignore if we already have a full value.
    }
    let BVal::Dict(entries) = root else {
        bail!("announce body is not a dict");
    };

    for (k, v) in &entries {
        if *k == b"failure reason" {
            let msg = match v {
                BVal::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
                _ => "tracker failure".to_string(),
            };
            bail!("tracker failure: {msg}");
        }
    }

    let mut interval: Option<i64> = None;
    let mut peers_bytes: Option<&[u8]> = None;
    for (k, v) in &entries {
        match *k {
            b"interval" | b"min interval" => {
                if let BVal::Int(n) = v {
                    if interval.is_none() || *k == b"interval" {
                        interval = Some(*n);
                    }
                }
            }
            b"peers" => {
                if let BVal::Bytes(b) = v {
                    peers_bytes = Some(*b);
                } else {
                    bail!("non-compact peers list unsupported");
                }
            }
            _ => {}
        }
    }

    let interval = interval.ok_or_else(|| anyhow::anyhow!("missing interval"))?;
    if !(0..=i64::from(u32::MAX)).contains(&interval) {
        bail!("invalid interval");
    }
    let peers = parse_compact_peers(peers_bytes.unwrap_or_default())?;
    Ok((interval as u32, peers))
}

/// HTTP/1.1 GET announce to a plaintext HTTP tracker. HTTPS is not handled here.
pub async fn http_tracker_announce(host: &str, port: u16, request_target: &str) -> Result<Vec<u8>> {
    let addr = format!("{host}:{port}");
    let mut stream = tokio::time::timeout(HTTP_TRACKER_TIMEOUT, TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow::anyhow!("http tracker connect timeout"))?
        .map_err(|e| anyhow::anyhow!("http tracker connect: {e}"))?;

    let host_header = if port == 80 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let req = format!(
        "GET {request_target} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: mint/0.1\r\nConnection: close\r\nAccept: */*\r\n\r\n"
    );

    tokio::time::timeout(HTTP_TRACKER_TIMEOUT, stream.write_all(req.as_bytes()))
        .await
        .map_err(|_| anyhow::anyhow!("http tracker write timeout"))?
        .map_err(|e| anyhow::anyhow!("http tracker write: {e}"))?;

    let mut buf = Vec::new();
    tokio::time::timeout(HTTP_TRACKER_TIMEOUT, async {
        let mut chunk = [0u8; 4096];
        loop {
            if buf.len() > MAX_HTTP_ANNOUNCE_BODY + 4096 {
                bail!("http tracker response too large");
            }
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > MAX_HTTP_ANNOUNCE_BODY + 8192 {
                bail!("http tracker response too large");
            }
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("http tracker read timeout"))??;

    split_http_body(&buf)
}

fn split_http_body(raw: &[u8]) -> Result<Vec<u8>> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("http tracker: no header terminator"))?;
    let headers = &raw[..sep];
    let body = &raw[sep + 4..];

    let status_line = headers
        .split(|&b| b == b'\n')
        .next()
        .ok_or_else(|| anyhow::anyhow!("http tracker: empty response"))?;
    let status_line = strip_cr(status_line);
    let code = status_line
        .split(|&b| b == b' ')
        .nth(1)
        .and_then(|c| std::str::from_utf8(c).ok())
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| anyhow::anyhow!("http tracker: bad status line"))?;
    if !(200..300).contains(&code) {
        bail!("http tracker status {code}");
    }
    if body.len() > MAX_HTTP_ANNOUNCE_BODY {
        bail!("http tracker body too large");
    }
    Ok(body.to_vec())
}

fn strip_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(&[b'\r']).unwrap_or(line)
}

pub fn peer_id_from_room_and_node(room_id: &[u8; 20], node_id: &str) -> [u8; 20] {
    let mut out = *room_id;
    let nib = node_id.as_bytes();
    let n = nib.len().min(20);
    for i in 0..n {
        out[i] ^= nib[i];
    }
    out
}

#[derive(Debug)]
enum BVal<'a> {
    Int(i64),
    Bytes(&'a [u8]),
    #[allow(dead_code)]
    List(Vec<BVal<'a>>),
    Dict(Vec<(&'a [u8], BVal<'a>)>),
}

fn parse_bencode<'a>(data: &'a [u8], i: &mut usize) -> Result<BVal<'a>> {
    if *i >= data.len() {
        bail!("truncated bencode");
    }
    match data[*i] {
        b'i' => {
            *i += 1;
            let start = *i;
            while *i < data.len() && data[*i] != b'e' {
                *i += 1;
            }
            if *i >= data.len() {
                bail!("bad bencode int");
            }
            let n: i64 = std::str::from_utf8(&data[start..*i])
                .map_err(|_| anyhow::anyhow!("bad int utf8"))?
                .parse()
                .map_err(|_| anyhow::anyhow!("bad int"))?;
            *i += 1;
            Ok(BVal::Int(n))
        }
        b'l' => {
            *i += 1;
            let mut items = Vec::new();
            while *i < data.len() && data[*i] != b'e' {
                items.push(parse_bencode(data, i)?);
            }
            if *i >= data.len() {
                bail!("bad bencode list");
            }
            *i += 1;
            Ok(BVal::List(items))
        }
        b'd' => {
            *i += 1;
            let mut entries = Vec::new();
            while *i < data.len() && data[*i] != b'e' {
                let key = parse_bencode(data, i)?;
                let BVal::Bytes(k) = key else {
                    bail!("dict key not bytes");
                };
                let val = parse_bencode(data, i)?;
                entries.push((k, val));
            }
            if *i >= data.len() {
                bail!("bad bencode dict");
            }
            *i += 1;
            Ok(BVal::Dict(entries))
        }
        b'0'..=b'9' => {
            let start = *i;
            while *i < data.len() && data[*i] != b':' {
                *i += 1;
            }
            if *i >= data.len() {
                bail!("bad bencode bytes");
            }
            let len: usize = std::str::from_utf8(&data[start..*i])
                .map_err(|_| anyhow::anyhow!("bad len utf8"))?
                .parse()
                .map_err(|_| anyhow::anyhow!("bad len"))?;
            *i += 1;
            if data.len().saturating_sub(*i) < len {
                bail!("truncated bencode bytes");
            }
            let bytes = &data[*i..*i + len];
            *i += len;
            Ok(BVal::Bytes(bytes))
        }
        _ => bail!("bad bencode tag"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_roundtrip() {
        let txn = TransactionId([1, 2, 3, 4]);
        let req = build_connect_request(txn);
        assert_eq!(req.len(), CONNECT_REQUEST_LEN);
        let mut resp = [0u8; 16];
        resp[0..4].copy_from_slice(&ACTION_CONNECT_RESPONSE.to_be_bytes());
        resp[4..8].copy_from_slice(&txn.0);
        resp[8..16].copy_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_be_bytes());
        let cid = parse_connect_response(&resp, txn).unwrap();
        assert_eq!(cid, 0xDEAD_BEEF_CAFE_BABE);
    }

    #[test]
    fn announce_parse_peers() {
        let txn = TransactionId([9, 9, 9, 9]);
        let mut resp = vec![0u8; ANNOUNCE_HEADER_LEN + 6];
        resp[0..4].copy_from_slice(&ACTION_ANNOUNCE_RESPONSE.to_be_bytes());
        resp[4..8].copy_from_slice(&txn.0);
        resp[8..12].copy_from_slice(&300u32.to_be_bytes());
        resp[20..24].copy_from_slice(&[203, 0, 113, 1]);
        resp[24..26].copy_from_slice(&7878u16.to_be_bytes());
        let (interval, peers) = parse_announce_response(&resp, txn).unwrap();
        assert_eq!(interval, 300);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].port(), 7878);
    }

    #[test]
    fn announce_rejects_bad_txn() {
        let txn = TransactionId([1, 1, 1, 1]);
        let mut resp = [0u8; 20];
        resp[0..4].copy_from_slice(&ACTION_ANNOUNCE_RESPONSE.to_be_bytes());
        resp[4..8].copy_from_slice(&[2, 2, 2, 2]);
        resp[8..12].copy_from_slice(&60u32.to_be_bytes());
        assert!(parse_announce_response(&resp, txn).is_err());
    }

    #[test]
    fn parse_tracker_url_ok() {
        let (h, p) = parse_tracker_url("udp://tracker.example.com:1337/announce").unwrap();
        assert_eq!(h, "tracker.example.com");
        assert_eq!(p, 1337);
    }

    #[test]
    fn parse_tracker_endpoint_http_default_port() {
        let ep = parse_tracker_endpoint("http://tracker.example.com/announce").unwrap();
        assert_eq!(ep.scheme, TrackerScheme::Http);
        assert_eq!(ep.host, "tracker.example.com");
        assert_eq!(ep.port, 80);
        assert_eq!(ep.path, "/announce");
    }

    #[test]
    fn parse_tracker_endpoint_https() {
        let ep = parse_tracker_endpoint("https://tracker.example.com:443/a").unwrap();
        assert_eq!(ep.scheme, TrackerScheme::Https);
        assert_eq!(ep.port, 443);
        assert_eq!(ep.path, "/a");
    }

    #[test]
    fn parse_tracker_url_rejects_http() {
        assert!(parse_tracker_url("http://tracker.example.com/announce").is_none());
    }

    #[test]
    fn percent_encode_info_hash() {
        let mut hash = [0u8; 20];
        hash[0] = 0x00;
        hash[1] = b'A';
        hash[2] = 0xff;
        let enc = percent_encode_bytes(&hash);
        assert!(enc.starts_with("%00A%FF"));
    }

    #[test]
    fn http_announce_target_contains_compact() {
        let target =
            build_http_announce_request_target("/announce", &[1u8; 20], &[2u8; 20], 7878, 50);
        assert!(target.starts_with("/announce?"));
        assert!(target.contains("compact=1"));
        assert!(target.contains("port=7878"));
        assert!(target.contains("numwant=50"));
    }

    #[test]
    fn parse_http_announce_compact() {
        let peers = [10u8, 0, 0, 1, 0x1e, 0xce]; // 10.0.0.1:7886
        let mut body = Vec::new();
        body.extend_from_slice(b"d8:intervali180e5:peers6:");
        body.extend_from_slice(&peers);
        body.push(b'e');
        let (interval, list) = parse_http_announce_body(&body).unwrap();
        assert_eq!(interval, 180);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].port(), 7886);
    }

    #[test]
    fn parse_http_announce_failure_reason() {
        let body = b"d14:failure reason13:tracker error e";
        assert!(parse_http_announce_body(body).is_err());
    }

    #[tokio::test]
    async fn http_tracker_announce_against_mock() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peers = [203u8, 0, 113, 1, 0x1e, 0xc6]; // 203.0.113.1:7878
        let mut bencode = Vec::new();
        bencode.extend_from_slice(b"d8:intervali120e5:peers6:");
        bencode.extend_from_slice(&peers);
        bencode.push(b'e');
        let body_len = bencode.len();
        let resp = {
            let mut r = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
            )
            .into_bytes();
            r.extend_from_slice(&bencode);
            r
        };

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(&resp).await;
        });

        let target =
            build_http_announce_request_target("/announce", &[9u8; 20], &[8u8; 20], 7878, 50);
        let body = http_tracker_announce("127.0.0.1", addr.port(), &target)
            .await
            .unwrap();
        let (interval, peers) = parse_http_announce_body(&body).unwrap();
        assert_eq!(interval, 120);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].to_string(), "203.0.113.1:7878");
    }
}
