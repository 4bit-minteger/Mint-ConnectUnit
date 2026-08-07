use bytes::{Bytes, BytesMut};

/// Join handshake / wire framing version (independent of MSYN `proto_ver` schema).
pub const WIRE_PROTOCOL_VERSION: u64 = 8;

pub const COMPACT_HEADER_LEN: usize = 1;
pub const CONTROL_TAG_LEN: usize = 4;

/// FEC compact header: type(1) + group_id(4 LE) + shard_idx(1) + data_shards(1) + parity_shards(1) + shard_size(2 LE)
pub const FEC_COMPACT_HEADER_LEN: usize = 10;

pub const PKT_KPAL: &[u8; 4] = b"MKPL";
pub const PKT_JOIN: &[u8; 4] = b"MPJN";
pub const PKT_JACK: &[u8; 4] = b"MPJA";
pub const PKT_PRXY: &[u8; 4] = b"MPRX";

/// One-hop PRXY: clamp inbound ttl to 1; forwarded body carries `0`.
/// Returns `Some(0)` when this hop may forward, else `None`.
pub fn prxy_forwarded_ttl(inbound_ttl: u64) -> Option<u64> {
    (inbound_ttl.min(1) > 0).then_some(0)
}
pub const PKT_HPCH: &[u8; 4] = b"MHOL";
pub const PKT_HACK: &[u8; 4] = b"MHAC";
pub const PKT_PMTU: &[u8; 4] = b"MPMT";
pub const PKT_PMAR: &[u8; 4] = b"MPAR";
/// Signed claim-gossip digest (FloatUnit membership).
pub const PKT_CLG: &[u8; 4] = b"MCLG";
/// Signed graceful leave + tombstone.
pub const PKT_LEAVE: &[u8; 4] = b"MLEA";
pub const PKT_MSTR: &[u8; 4] = b"MSTR";
pub const PKT_MERR: &[u8; 4] = b"MERR";
pub const PKT_BREK: &[u8; 4] = b"MBRK";
pub const PKT_RDYS: &[u8; 4] = b"MRDY";
pub const PKT_CTSIG: &[u8; 4] = b"MCTS";
pub const PKT_MCTL: &[u8; 4] = b"MCTL";
pub const PKT_PARA_HELLO: &[u8; 4] = b"MPHI";
pub const PKT_PARA_REPLY: &[u8; 4] = b"MPHR";
pub const PKT_PARA_OK: &[u8; 4] = b"MPHO";
pub const PKT_PARA_PUNCH_ACK: &[u8; 4] = b"MPPA";

/// Overhead on wire for plain IP payload (compact data tag only).
pub const MDAT_WIRE_OVERHEAD: usize = COMPACT_HEADER_LEN;
/// Overhead for encrypted frame: tag + wire counter + AEAD tag (plaintext not included).
pub const MENC_WIRE_OVERHEAD: usize =
    COMPACT_HEADER_LEN + crate::crypto::WIRE_COUNTER_LEN + crate::crypto::DATA_TAG_LEN;
/// IPv4 header (20) + UDP header (8). PMTUD probe ladder sizes are IP totals;
/// FEC UDP payload must fit in `min_path_mtu - UNDERLAY_IPV4_UDP_OVERHEAD`.
pub const UNDERLAY_IPV4_UDP_OVERHEAD: usize = 28;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CompactPacketType {
    Data = 0x01,
    Encrypted = 0x02,
    Fec = 0x03,
    Reliable = 0x04,
    Ack = 0x05,
    JoinAck = 0x06,
    /// RTT / forward-OWD probe request (`ping_id` + `sender_ts`, 16 B body).
    Ping = 0x07,
    /// Probe reply (echo 16 B + `fwd_owd_sample_ms` i32, 20 B body).
    Pong = 0x08,
}

impl CompactPacketType {
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    pub fn try_from_byte(b: u8) -> Result<Self, InvalidCompactType> {
        match b {
            0x01 => Ok(Self::Data),
            0x02 => Ok(Self::Encrypted),
            0x03 => Ok(Self::Fec),
            0x04 => Ok(Self::Reliable),
            0x05 => Ok(Self::Ack),
            0x06 => Ok(Self::JoinAck),
            0x07 => Ok(Self::Ping),
            0x08 => Ok(Self::Pong),
            0x00 | 0xFF => Err(InvalidCompactType),
            0xFA..=0xFE => Err(InvalidCompactType),
            _ => Err(InvalidCompactType),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidCompactType;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatagramKind<'a> {
    Compact(CompactPacketType, &'a [u8]),
    Control([u8; 4], &'a [u8]),
}

/// First byte `b'M'` => 4-byte ASCII control tag; otherwise compact type byte.
pub fn parse_datagram(buf: &[u8]) -> Option<DatagramKind<'_>> {
    if buf.is_empty() {
        return None;
    }
    if buf[0] == b'M' {
        if buf.len() < CONTROL_TAG_LEN {
            return None;
        }
        let mut tag = [0u8; 4];
        tag.copy_from_slice(&buf[..CONTROL_TAG_LEN]);
        return Some(DatagramKind::Control(tag, &buf[CONTROL_TAG_LEN..]));
    }
    let ty = CompactPacketType::try_from_byte(buf[0]).ok()?;
    Some(DatagramKind::Compact(ty, &buf[1..]))
}

pub fn frame_compact(ty: CompactPacketType, body: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(1 + body.len());
    out.extend_from_slice(&[ty.to_byte()]);
    out.extend_from_slice(body);
    out.freeze()
}

pub fn parse_compact(buf: &[u8]) -> Option<(CompactPacketType, &[u8])> {
    if buf.is_empty() {
        return None;
    }
    let ty = CompactPacketType::try_from_byte(buf[0]).ok()?;
    Some((ty, &buf[1..]))
}

pub fn frame_with_tag(tag: &[u8; 4], body: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(4 + body.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(body);
    out.freeze()
}

pub fn parse_tag(buf: &[u8]) -> Option<([u8; 4], &[u8])> {
    if buf.len() < 4 {
        return None;
    }
    let mut tag = [0u8; 4];
    tag.copy_from_slice(&buf[..4]);
    Some((tag, &buf[4..]))
}

pub const MCTL_FLAG_HB: u16 = 1;
pub const MCTL_FLAG_HOL: u16 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MctlParsed {
    pub flags: u16,
    pub vip: Option<Vec<u8>>,
    /// HB/HOL vip section parsed (or not required).
    pub signaling_ok: bool,
}

/// Encode compound control body (HB/HOL only). Returns `None` if flags require vip but vip empty.
pub fn encode_mctl(flags: u16, vip: Option<&[u8]>) -> Option<Vec<u8>> {
    if flags == 0 {
        return None;
    }
    // Ignore unknown flag bits; only HB/HOL are emitted.
    let flags = flags & (MCTL_FLAG_HB | MCTL_FLAG_HOL);
    if flags == 0 {
        return None;
    }
    let need_vip = (flags & (MCTL_FLAG_HB | MCTL_FLAG_HOL)) != 0;
    if need_vip {
        let v = vip?;
        if v.is_empty() || v.len() > 255 {
            return None;
        }
    }
    let mut out = Vec::with_capacity(2 + 1 + vip.map(|v| v.len()).unwrap_or(0));
    out.extend_from_slice(&flags.to_le_bytes());
    if need_vip {
        let v = vip.unwrap();
        out.push(v.len() as u8);
        out.extend_from_slice(v);
    }
    Some(out)
}

/// Parse MCTL body (HB/HOL). Unknown flag bits are ignored.
pub fn parse_mctl(body: &[u8]) -> Option<MctlParsed> {
    if body.len() < 2 {
        return None;
    }
    let raw_flags = u16::from_le_bytes([body[0], body[1]]);
    if raw_flags == 0 {
        return None;
    }
    let flags = raw_flags & (MCTL_FLAG_HB | MCTL_FLAG_HOL);
    if flags == 0 {
        return None;
    }
    let mut off = 2usize;
    let need_vip = (flags & (MCTL_FLAG_HB | MCTL_FLAG_HOL)) != 0;

    let mut vip = None;
    let mut signaling_ok = !need_vip;
    if need_vip {
        if off >= body.len() {
            return Some(MctlParsed {
                flags,
                vip: None,
                signaling_ok: false,
            });
        }
        let vip_len = body[off] as usize;
        off += 1;
        if vip_len == 0 || off + vip_len > body.len() {
            return Some(MctlParsed {
                flags,
                vip: None,
                signaling_ok: false,
            });
        }
        vip = Some(body[off..off + vip_len].to_vec());
        signaling_ok = true;
    }

    Some(MctlParsed {
        flags,
        vip,
        signaling_ok,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_type_roundtrip_bytes() {
        assert_eq!(CompactPacketType::Data.to_byte(), 0x01);
        assert_eq!(CompactPacketType::Encrypted.to_byte(), 0x02);
        assert_eq!(CompactPacketType::Fec.to_byte(), 0x03);
        assert_eq!(CompactPacketType::Reliable.to_byte(), 0x04);
        assert_eq!(CompactPacketType::Ack.to_byte(), 0x05);
        assert_eq!(CompactPacketType::JoinAck.to_byte(), 0x06);
        assert_eq!(CompactPacketType::Ping.to_byte(), 0x07);
        assert_eq!(CompactPacketType::Pong.to_byte(), 0x08);
        assert_eq!(
            CompactPacketType::try_from_byte(0x01).unwrap(),
            CompactPacketType::Data
        );
        assert_eq!(
            CompactPacketType::try_from_byte(0x07).unwrap(),
            CompactPacketType::Ping
        );
        assert_eq!(
            CompactPacketType::try_from_byte(0x08).unwrap(),
            CompactPacketType::Pong
        );
    }

    #[test]
    fn compact_type_rejects_reserved() {
        assert!(CompactPacketType::try_from_byte(0x00).is_err());
        assert!(CompactPacketType::try_from_byte(0xFF).is_err());
        assert!(CompactPacketType::try_from_byte(0xFA).is_err());
        assert!(CompactPacketType::try_from_byte(0x09).is_err());
    }

    #[test]
    fn frame_compact_exact_bytes() {
        let f = frame_compact(CompactPacketType::Data, b"xy");
        assert_eq!(f.as_ref(), &[0x01, b'x', b'y']);
    }

    #[test]
    fn parse_datagram_control_still_four_byte() {
        let pkt = frame_with_tag(PKT_JOIN, b"{}");
        match parse_datagram(&pkt).unwrap() {
            DatagramKind::Control(tag, body) => {
                assert_eq!(tag, *PKT_JOIN);
                assert_eq!(body, b"{}");
            }
            DatagramKind::Compact(..) => panic!("expected control"),
        }
    }

    #[test]
    fn parse_datagram_compact_path() {
        let pkt = frame_compact(CompactPacketType::Ack, &[0, 0, 0, 1]);
        match parse_datagram(&pkt).unwrap() {
            DatagramKind::Compact(ty, body) => {
                assert_eq!(ty, CompactPacketType::Ack);
                assert_eq!(body, &[0, 0, 0, 1]);
            }
            DatagramKind::Control(..) => panic!("expected compact"),
        }
    }

    #[test]
    fn parse_datagram_compact_ping_pong() {
        let ping = frame_compact(CompactPacketType::Ping, &[0u8; 16]);
        match parse_datagram(&ping).unwrap() {
            DatagramKind::Compact(CompactPacketType::Ping, body) => {
                assert_eq!(body.len(), 16);
            }
            other => panic!("expected compact ping, got {other:?}"),
        }
        let pong = frame_compact(CompactPacketType::Pong, &[0u8; 20]);
        match parse_datagram(&pong).unwrap() {
            DatagramKind::Compact(CompactPacketType::Pong, body) => {
                assert_eq!(body.len(), 20);
            }
            other => panic!("expected compact pong, got {other:?}"),
        }
        assert_eq!(ping[0], 0x07);
        assert_eq!(pong[0], 0x08);
    }

    #[test]
    fn mctl_hb_hol_roundtrip() {
        let vip = b"10.0.0.2";
        let body = encode_mctl(MCTL_FLAG_HB | MCTL_FLAG_HOL, Some(vip)).unwrap();
        let p = parse_mctl(&body).unwrap();
        assert!(p.signaling_ok);
        assert_eq!(p.flags, MCTL_FLAG_HB | MCTL_FLAG_HOL);
        assert_eq!(p.vip.as_deref(), Some(vip.as_slice()));
    }

    #[test]
    fn mctl_ignores_unknown_flag_bits_on_parse() {
        // Wire may carry unknown flag bit 4; HB section still parses.
        let vip = b"10.0.0.1";
        let mut body = encode_mctl(MCTL_FLAG_HB, Some(vip)).unwrap();
        body[0] |= 4; // unknown bit
        let p = parse_mctl(&body).unwrap();
        assert!(p.signaling_ok);
        assert_eq!(p.flags, MCTL_FLAG_HB);
        assert_eq!(p.vip.as_deref(), Some(vip.as_slice()));
    }
}
