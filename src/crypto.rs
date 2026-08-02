use std::collections::HashMap;
use std::time::Instant;

use aegis::aegis128l::Aegis128L;
use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use blake2::{Blake2b512, Digest};
use bytes::BytesMut;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::net::packet::CompactPacketType;
use rand::RngCore;

pub const KEY_LEN: usize = 32;
pub const AEAD_KEY_LEN: usize = 16;
pub const DATA_NONCE_LEN: usize = 16;
pub const DATA_SALT_LEN: usize = 10;
pub const WIRE_COUNTER_LEN: usize = 6;
pub const NONCE_LEN: usize = WIRE_COUNTER_LEN;
pub const DATA_TAG_LEN: usize = 16;
pub const DATA_REPLAY_WINDOW_BITS: usize = 128;
pub const CTRL_REPLAY_MAX_SOURCES: usize = 4096;
pub const CTRL_AAD: &[u8] = b"mcts";
const DATA_REPLAY_MAX_COUNTER: u64 = (1u64 << 48) - 1;
const HKDF_DOMAIN_SALT: &[u8] = b"mint-aegis-128l-v1";
const HKDF_DOMAIN_INFO: &[u8] = b"data";
const HKDF_DOMAIN_INFO_CTRL: &[u8] = b"ctrl";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key(pub [u8; KEY_LEN]);

pub struct MintCrypto;

impl MintCrypto {
    pub fn generate_key() -> Key {
        let mut key = [0u8; KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Key(key)
    }
}

pub struct AeadKey {
    material: [u8; KEY_LEN],
}

impl PartialEq for AeadKey {
    fn eq(&self, other: &Self) -> bool {
        self.material == other.material
    }
}

impl Eq for AeadKey {}

impl AeadKey {
    pub fn new(material: [u8; KEY_LEN]) -> Self {
        Self { material }
    }

    pub fn from_key(key: Key) -> Self {
        Self::new(key.0)
    }

    #[inline]
    pub fn as_key(&self) -> Key {
        Key(self.material)
    }
}

#[derive(Clone)]
pub struct DataPlaneAead {
    key: [u8; AEAD_KEY_LEN],
    salt: [u8; DATA_SALT_LEN],
}

impl DataPlaneAead {
    pub fn new(key: [u8; AEAD_KEY_LEN], salt: [u8; DATA_SALT_LEN]) -> Self {
        Self { key, salt }
    }

    pub fn encrypt_framed_packet_into(
        &self,
        counter: u64,
        aad: &[u8],
        plaintext: &[u8],
        out: &mut BytesMut,
    ) -> Result<()> {
        let counter_wire = encode_wire_counter(counter)?;
        let nonce = nonce_from_counter(&self.salt, &counter_wire);
        let cipher = Aegis128L::<DATA_TAG_LEN>::new(&self.key, &nonce);
        out.clear();
        out.reserve(1 + WIRE_COUNTER_LEN + plaintext.len() + DATA_TAG_LEN);
        out.extend_from_slice(&[CompactPacketType::Encrypted.to_byte()]);
        out.extend_from_slice(&counter_wire);
        out.extend_from_slice(plaintext);
        let body_start = 1 + WIRE_COUNTER_LEN;
        let tag = cipher.encrypt_in_place(&mut out[body_start..], aad);
        out.extend_from_slice(&tag);
        Ok(())
    }

    pub fn decrypt_framed_payload_into(
        &self,
        counter_wire: &[u8; WIRE_COUNTER_LEN],
        aad: &[u8],
        payload: &[u8],
        out: &mut BytesMut,
    ) -> Result<()> {
        if payload.len() < DATA_TAG_LEN {
            out.clear();
            bail!("packet too short");
        }
        let nonce = nonce_from_counter(&self.salt, counter_wire);
        let cipher = Aegis128L::<DATA_TAG_LEN>::new(&self.key, &nonce);
        out.clear();
        out.extend_from_slice(payload);
        let tag_start = out.len() - DATA_TAG_LEN;
        let mut tag = [0u8; DATA_TAG_LEN];
        tag.copy_from_slice(&out[tag_start..]);
        out.truncate(tag_start);
        cipher
            .decrypt_in_place(out.as_mut(), &tag, aad)
            .map_err(|_| anyhow!("decrypt failure"))?;
        Ok(())
    }
}

pub fn derive_data_plane_material(
    network_key: &Key,
    sender_vip: u32,
    receiver_vip: u32,
) -> Result<DataPlaneAead> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_DOMAIN_SALT), &network_key.0);
    let mut info = [0u8; HKDF_DOMAIN_INFO.len() + 8];
    info[..HKDF_DOMAIN_INFO.len()].copy_from_slice(HKDF_DOMAIN_INFO);
    info[HKDF_DOMAIN_INFO.len()..HKDF_DOMAIN_INFO.len() + 4]
        .copy_from_slice(&sender_vip.to_be_bytes());
    info[HKDF_DOMAIN_INFO.len() + 4..].copy_from_slice(&receiver_vip.to_be_bytes());
    let mut okm = [0u8; AEAD_KEY_LEN + DATA_SALT_LEN];
    hk.expand(&info, &mut okm)
        .map_err(|_| anyhow!("hkdf expand failure"))?;
    let mut key = [0u8; AEAD_KEY_LEN];
    let mut salt = [0u8; DATA_SALT_LEN];
    key.copy_from_slice(&okm[..AEAD_KEY_LEN]);
    salt.copy_from_slice(&okm[AEAD_KEY_LEN..]);
    Ok(DataPlaneAead::new(key, salt))
}

#[derive(Clone)]
pub struct ControlPlaneAead {
    key: [u8; AEAD_KEY_LEN],
    salt: [u8; DATA_SALT_LEN],
}

impl ControlPlaneAead {
    pub fn new(key: [u8; AEAD_KEY_LEN], salt: [u8; DATA_SALT_LEN]) -> Self {
        Self { key, salt }
    }

    /// Seal control plaintext (`inner_tag || body`) to `ctr6 || ct || tag16` (no outer `MCTS`).
    pub fn seal_into(&self, counter: u64, plaintext: &[u8], out: &mut BytesMut) -> Result<()> {
        let counter_wire = encode_wire_counter(counter)?;
        let nonce = nonce_from_counter(&self.salt, &counter_wire);
        let cipher = Aegis128L::<DATA_TAG_LEN>::new(&self.key, &nonce);
        out.clear();
        out.reserve(WIRE_COUNTER_LEN + plaintext.len() + DATA_TAG_LEN);
        out.extend_from_slice(&counter_wire);
        out.extend_from_slice(plaintext);
        let body_start = WIRE_COUNTER_LEN;
        let tag = cipher.encrypt_in_place(&mut out[body_start..], CTRL_AAD);
        out.extend_from_slice(&tag);
        Ok(())
    }

    /// Open sealed body (`ctr6 || ct || tag16`) into plaintext (`inner_tag || body`).
    pub fn open_into(
        &self,
        counter_wire: &[u8; WIRE_COUNTER_LEN],
        payload: &[u8],
        out: &mut BytesMut,
    ) -> Result<()> {
        if payload.len() < DATA_TAG_LEN {
            out.clear();
            bail!("packet too short");
        }
        let nonce = nonce_from_counter(&self.salt, counter_wire);
        let cipher = Aegis128L::<DATA_TAG_LEN>::new(&self.key, &nonce);
        out.clear();
        out.extend_from_slice(payload);
        let tag_start = out.len() - DATA_TAG_LEN;
        let mut tag = [0u8; DATA_TAG_LEN];
        tag.copy_from_slice(&out[tag_start..]);
        out.truncate(tag_start);
        cipher
            .decrypt_in_place(out.as_mut(), &tag, CTRL_AAD)
            .map_err(|_| anyhow!("decrypt failure"))?;
        Ok(())
    }
}

pub fn derive_control_plane_material(network_key: &Key) -> Result<ControlPlaneAead> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_DOMAIN_SALT), &network_key.0);
    let mut okm = [0u8; AEAD_KEY_LEN + DATA_SALT_LEN];
    hk.expand(HKDF_DOMAIN_INFO_CTRL, &mut okm)
        .map_err(|_| anyhow!("hkdf expand failure"))?;
    let mut key = [0u8; AEAD_KEY_LEN];
    let mut salt = [0u8; DATA_SALT_LEN];
    key.copy_from_slice(&okm[..AEAD_KEY_LEN]);
    salt.copy_from_slice(&okm[AEAD_KEY_LEN..]);
    Ok(ControlPlaneAead::new(key, salt))
}

#[derive(Clone)]
pub struct DataReplayWindow {
    top: Option<u64>,
    bits: u128,
}

impl DataReplayWindow {
    pub fn new() -> Self {
        Self { top: None, bits: 0 }
    }

    pub fn allows(&self, counter: u64) -> bool {
        let Some(top) = self.top else {
            return true;
        };
        if counter > top {
            return true;
        }
        let delta = top - counter;
        if delta >= DATA_REPLAY_WINDOW_BITS as u64 {
            return false;
        }
        let mask = 1u128 << delta;
        self.bits & mask == 0
    }

    pub fn top(&self) -> Option<u64> {
        self.top
    }

    pub fn commit(&mut self, counter: u64) {
        let Some(top) = self.top else {
            self.top = Some(counter);
            self.bits = 1;
            return;
        };
        if counter > top {
            let shift = (counter - top).min(DATA_REPLAY_WINDOW_BITS as u64) as usize;
            self.bits = if shift >= DATA_REPLAY_WINDOW_BITS {
                0
            } else {
                self.bits << shift
            };
            self.top = Some(counter);
            self.bits |= 1;
            return;
        }
        let delta = top - counter;
        if delta < DATA_REPLAY_WINDOW_BITS as u64 {
            self.bits |= 1u128 << delta;
        }
    }
}

fn encode_wire_counter(counter: u64) -> Result<[u8; WIRE_COUNTER_LEN]> {
    if counter > DATA_REPLAY_MAX_COUNTER {
        bail!("counter exhausted");
    }
    let le = counter.to_le_bytes();
    let mut out = [0u8; WIRE_COUNTER_LEN];
    out.copy_from_slice(&le[..WIRE_COUNTER_LEN]);
    Ok(out)
}

pub fn decode_wire_counter(counter_wire: &[u8; WIRE_COUNTER_LEN]) -> u64 {
    let mut le = [0u8; 8];
    le[..WIRE_COUNTER_LEN].copy_from_slice(counter_wire);
    u64::from_le_bytes(le)
}

fn nonce_from_counter(
    salt: &[u8; DATA_SALT_LEN],
    counter_wire: &[u8; WIRE_COUNTER_LEN],
) -> [u8; DATA_NONCE_LEN] {
    let mut nonce = [0u8; DATA_NONCE_LEN];
    nonce[..DATA_SALT_LEN].copy_from_slice(salt);
    nonce[DATA_SALT_LEN..].copy_from_slice(counter_wire);
    nonce
}

pub fn derive_network_id(key: &Key) -> String {
    let mut hasher = Blake2b512::new();
    hasher.update(key.0);
    let digest = hasher.finalize();
    hex::encode(&digest[..5])
}

/// BEP15 info_hash / decentralized room id (first 20 bytes of SHA-256 over key || protocol).
pub fn room_id_20b(key: &Key, protocol: u8) -> [u8; 20] {
    let mut hasher = Sha256::new();
    sha2::Digest::update(&mut hasher, key.0);
    sha2::Digest::update(&mut hasher, [protocol]);
    let digest = sha2::Digest::finalize(hasher);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[..20]);
    out
}

pub fn room_id_20b_from_raw_key(key: &[u8; 32], protocol: u8) -> [u8; 20] {
    room_id_20b(&Key(*key), protocol)
}

pub fn room_id_hex(key: &Key, protocol: u8) -> String {
    hex::encode(room_id_20b(key, protocol))
}

pub const PROTO_UDP: u8 = 1;

#[derive(Clone, Debug)]
pub struct InvitePayload {
    pub mode: u8,
    pub owner_ip: [u8; 4],
    pub owner_port: u16,
    pub key: [u8; 32],
    pub protocol: u8,
}

pub fn encode_invite(payload: &InvitePayload) -> String {
    let mut raw = Vec::with_capacity(40);
    raw.push(payload.mode);
    raw.extend_from_slice(&payload.owner_ip);
    raw.extend_from_slice(&payload.owner_port.to_be_bytes());
    raw.push(payload.protocol);
    raw.extend_from_slice(&payload.key);
    let out = URL_SAFE_NO_PAD.encode(raw);
    out
}

pub fn decode_invite(invite: &str) -> Result<InvitePayload> {
    let raw = URL_SAFE_NO_PAD.decode(invite)?;
    if raw.len() != 40 {
        bail!("unsupported invite format");
    }
    let mode = raw[0];
    let mut ip = [0u8; 4];
    ip.copy_from_slice(&raw[1..5]);
    let owner_port = u16::from_be_bytes([raw[5], raw[6]]);
    let protocol = raw[7];
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw[8..40]);
    Ok(InvitePayload {
        mode,
        owner_ip: ip,
        owner_port,
        key,
        protocol,
    })
}

pub struct CtrlReplayTable {
    sources: HashMap<u64, (DataReplayWindow, Instant)>,
    max_sources: usize,
}

impl CtrlReplayTable {
    pub fn new() -> Self {
        Self {
            sources: HashMap::with_capacity(8),
            max_sources: CTRL_REPLAY_MAX_SOURCES,
        }
    }

    pub fn clear(&mut self) {
        self.sources.clear();
    }

    pub fn allows(&self, src_key: u64, counter: u64) -> bool {
        match self.sources.get(&src_key) {
            Some((window, _)) => window.allows(counter),
            None => true,
        }
    }

    pub fn commit(&mut self, src_key: u64, counter: u64) {
        let now = Instant::now();
        if let Some((window, last_seen)) = self.sources.get_mut(&src_key) {
            window.commit(counter);
            *last_seen = now;
            return;
        }
        if self.sources.len() >= self.max_sources {
            self.evict_oldest_until_room();
        }
        if self.sources.len() >= self.max_sources {
            return;
        }
        let mut window = DataReplayWindow::new();
        window.commit(counter);
        self.sources.insert(src_key, (window, now));
    }

    fn evict_oldest_until_room(&mut self) {
        while self.sources.len() >= self.max_sources {
            let oldest = self
                .sources
                .iter()
                .min_by_key(|(_, (_, last_seen))| *last_seen)
                .map(|(k, _)| *k);
            let Some(key) = oldest else {
                break;
            };
            self.sources.remove(&key);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.sources.len()
    }

    #[cfg(test)]
    fn contains(&self, src_key: u64) -> bool {
        self.sources.contains_key(&src_key)
    }
}

impl Default for CtrlReplayTable {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ControlRateLimiter {
    entries: HashMap<u64, Bucket>,
    capacity: f64,
    refill_per_sec: f64,
    reap_after: std::time::Duration,
    last_reap: Instant,
}

struct Bucket {
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
}

impl ControlRateLimiter {
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
            refill_per_sec,
            reap_after: std::time::Duration::from_secs(300),
            last_reap: Instant::now(),
        }
    }

    pub fn allow(&mut self, src_key: u64) -> bool {
        let now = Instant::now();
        if now.duration_since(self.last_reap) >= std::time::Duration::from_secs(60) {
            let reap_after = self.reap_after;
            self.entries
                .retain(|_, v| now.duration_since(v.last_seen) <= reap_after);
            self.last_reap = now;
        }

        const MAX_ENTRIES: usize = 65_536;
        if self.entries.len() >= MAX_ENTRIES && !self.entries.contains_key(&src_key) {
            let reap_after = self.reap_after;
            self.entries
                .retain(|_, v| now.duration_since(v.last_seen) <= reap_after);
            self.last_reap = now;
            if self.entries.len() >= MAX_ENTRIES {
                return false;
            }
        }
        let entry = self.entries.entry(src_key).or_insert(Bucket {
            tokens: self.capacity,
            last_refill: now,
            last_seen: now,
        });
        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        entry.last_refill = now;
        entry.last_seen = now;
        entry.tokens = (entry.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        if entry.tokens < 1.0 {
            return false;
        }
        entry.tokens -= 1.0;
        true
    }
}

pub fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn room_id_deterministic_and_20_bytes() {
        let k = Key([7u8; 32]);
        let a = room_id_20b(&k, PROTO_UDP);
        let b = room_id_20b(&k, PROTO_UDP);
        assert_eq!(a, b);
        assert_eq!(a.len(), 20);
        assert_ne!(room_id_20b(&k, PROTO_UDP), room_id_20b(&k, 2));
    }

    #[test]
    fn room_id_same_for_two_endpoint_encodings() {
        let key = [9u8; 32];
        let a = InvitePayload {
            mode: 1,
            owner_ip: [192, 168, 1, 1],
            owner_port: 7878,
            key,
            protocol: PROTO_UDP,
        };
        let b = InvitePayload {
            mode: 1,
            owner_ip: [1, 2, 3, 4],
            owner_port: 9999,
            key,
            protocol: PROTO_UDP,
        };
        let k = Key(key);
        assert_eq!(
            room_id_20b_from_raw_key(&a.key, a.protocol),
            room_id_20b_from_raw_key(&b.key, b.protocol)
        );
        assert_eq!(room_id_hex(&k, PROTO_UDP).len(), 40);
    }

    #[test]
    fn control_plane_aead_roundtrip() {
        let network = Key([3u8; KEY_LEN]);
        let aead = derive_control_plane_material(&network).unwrap();
        let mut plain = Vec::new();
        plain.extend_from_slice(b"JACK");
        plain.extend_from_slice(b"hello-control");
        let mut sealed = BytesMut::new();
        aead.seal_into(7, &plain, &mut sealed).unwrap();
        assert_eq!(sealed.len(), WIRE_COUNTER_LEN + plain.len() + DATA_TAG_LEN);
        assert_ne!(&sealed[..4], b"MCTS");
        let mut ctr = [0u8; WIRE_COUNTER_LEN];
        ctr.copy_from_slice(&sealed[..WIRE_COUNTER_LEN]);
        assert_eq!(decode_wire_counter(&ctr), 7);
        let mut out = BytesMut::new();
        aead.open_into(&ctr, &sealed[WIRE_COUNTER_LEN..], &mut out)
            .unwrap();
        assert_eq!(&out[..], plain.as_slice());
    }

    #[test]
    fn control_plane_rejects_modified_tag() {
        let network = Key([4u8; KEY_LEN]);
        let aead = derive_control_plane_material(&network).unwrap();
        let mut sealed = BytesMut::new();
        aead.seal_into(1, b"JACKx", &mut sealed).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        let mut ctr = [0u8; WIRE_COUNTER_LEN];
        ctr.copy_from_slice(&sealed[..WIRE_COUNTER_LEN]);
        let mut out = BytesMut::new();
        assert!(aead
            .open_into(&ctr, &sealed[WIRE_COUNTER_LEN..], &mut out)
            .is_err());
    }

    #[test]
    fn control_plane_rejects_counter_exhaustion() {
        let network = Key([4u8; KEY_LEN]);
        let aead = derive_control_plane_material(&network).unwrap();
        let mut sealed = BytesMut::new();
        assert!(aead.seal_into(1u64 << 48, b"JACKx", &mut sealed).is_err());
    }

    #[test]
    fn control_and_data_hkdf_are_distinct() {
        let network = Key([8u8; KEY_LEN]);
        let ctrl = derive_control_plane_material(&network).unwrap();
        let data = derive_data_plane_material(&network, 1, 2).unwrap();
        let mut ctrl_sealed = BytesMut::new();
        ctrl.seal_into(3, b"JACKx", &mut ctrl_sealed).unwrap();
        let mut ctr = [0u8; WIRE_COUNTER_LEN];
        ctr.copy_from_slice(&ctrl_sealed[..WIRE_COUNTER_LEN]);
        let aad = aad(1, 2);
        let mut out = BytesMut::new();
        assert!(data
            .decrypt_framed_payload_into(&ctr, &aad, &ctrl_sealed[WIRE_COUNTER_LEN..], &mut out)
            .is_err());
    }

    #[test]
    fn control_rate_limiter_full_table_rejects_new_source() {
        let mut rl = ControlRateLimiter::new(4.0, 0.0);
        for key in 0..65_536u64 {
            assert!(rl.allow(key));
        }
        assert_eq!(rl.entries.len(), 65_536);
        assert!(!rl.allow(99_999));
        assert_eq!(rl.entries.len(), 65_536);
        assert!(rl.entries.contains_key(&42));
    }

    #[test]
    fn ctrl_replay_rejects_duplicate_and_allows_far_ahead() {
        let mut t = CtrlReplayTable::new();
        assert!(t.allows(1, 10));
        t.commit(1, 10);
        assert!(!t.allows(1, 10));
        assert!(t.allows(1, 400));
        t.commit(1, 400);
        assert!(!t.allows(1, 400));
        assert!(!t.allows(1, 10));
    }

    #[test]
    fn ctrl_replay_evicts_oldest_when_at_cap_to_admit_new_source() {
        let mut t = CtrlReplayTable::new();
        for k in 0u64..CTRL_REPLAY_MAX_SOURCES as u64 {
            assert!(t.allows(k, 1), "k={k}");
            t.commit(k, 1);
        }
        assert_eq!(t.len(), CTRL_REPLAY_MAX_SOURCES);
        assert!(t.allows(99_999, 1));
        t.commit(99_999, 1);
        assert!(t.contains(99_999));
        assert_eq!(t.len(), CTRL_REPLAY_MAX_SOURCES);
    }

    fn aad(sender: u32, receiver: u32) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&sender.to_be_bytes());
        out[4..].copy_from_slice(&receiver.to_be_bytes());
        out
    }

    #[test]
    fn aegis_roundtrip_smoke() {
        let network = Key([7u8; KEY_LEN]);
        let aead = derive_data_plane_material(&network, 10, 20).unwrap();
        let mut framed = BytesMut::new();
        let a = aad(10, 20);
        aead.encrypt_framed_packet_into(1, &a, b"hello", &mut framed)
            .unwrap();
        assert_eq!(framed[0], CompactPacketType::Encrypted.to_byte());
        let mut ctr = [0u8; WIRE_COUNTER_LEN];
        ctr.copy_from_slice(&framed[1..1 + WIRE_COUNTER_LEN]);
        let mut plain = BytesMut::new();
        aead.decrypt_framed_payload_into(&ctr, &a, &framed[1 + WIRE_COUNTER_LEN..], &mut plain)
            .unwrap();
        assert_eq!(&plain[..], b"hello");
    }

    #[test]
    fn hkdf_directional_keys_are_distinct() {
        let network = Key([5u8; KEY_LEN]);
        let ab = derive_data_plane_material(&network, 1, 2).unwrap();
        let ba = derive_data_plane_material(&network, 2, 1).unwrap();
        let mut ab_frame = BytesMut::new();
        let aad_ab = aad(1, 2);
        ab.encrypt_framed_packet_into(9, &aad_ab, b"payload", &mut ab_frame)
            .unwrap();
        let mut ctr = [0u8; WIRE_COUNTER_LEN];
        ctr.copy_from_slice(&ab_frame[1..1 + WIRE_COUNTER_LEN]);
        let mut plain = BytesMut::new();
        assert!(ba
            .decrypt_framed_payload_into(
                &ctr,
                &aad_ab,
                &ab_frame[1 + WIRE_COUNTER_LEN..],
                &mut plain
            )
            .is_err());
    }

    #[test]
    fn framed_counter_is_little_endian_6_bytes() {
        let network = Key([1u8; KEY_LEN]);
        let aead = derive_data_plane_material(&network, 11, 22).unwrap();
        let mut framed = BytesMut::new();
        let aad = aad(11, 22);
        let counter = 0x0000_0102_0304_0506u64;
        aead.encrypt_framed_packet_into(counter, &aad, b"x", &mut framed)
            .unwrap();
        assert_eq!(&framed[1..7], &[0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        let mut ctr_wire = [0u8; WIRE_COUNTER_LEN];
        ctr_wire.copy_from_slice(&framed[1..7]);
        assert_eq!(decode_wire_counter(&ctr_wire), counter);
    }

    #[test]
    fn framed_rejects_counter_exhaustion() {
        let network = Key([1u8; KEY_LEN]);
        let aead = derive_data_plane_material(&network, 11, 22).unwrap();
        let mut framed = BytesMut::new();
        let aad = aad(11, 22);
        assert!(aead
            .encrypt_framed_packet_into(1u64 << 48, &aad, b"x", &mut framed)
            .is_err());
    }

    #[test]
    fn decrypt_rejects_aad_mismatch() {
        let network = Key([9u8; KEY_LEN]);
        let aead = derive_data_plane_material(&network, 77, 88).unwrap();
        let mut framed = BytesMut::new();
        let aad_ok = aad(77, 88);
        let aad_bad = aad(77, 89);
        aead.encrypt_framed_packet_into(3, &aad_ok, b"check", &mut framed)
            .unwrap();
        let mut ctr = [0u8; WIRE_COUNTER_LEN];
        ctr.copy_from_slice(&framed[1..1 + WIRE_COUNTER_LEN]);
        let mut out = BytesMut::new();
        assert!(aead
            .decrypt_framed_payload_into(&ctr, &aad_bad, &framed[1 + WIRE_COUNTER_LEN..], &mut out)
            .is_err());
    }

    #[test]
    fn decrypt_rejects_modified_tag() {
        let network = Key([13u8; KEY_LEN]);
        let aead = derive_data_plane_material(&network, 1, 5).unwrap();
        let mut framed = BytesMut::new();
        let aad = aad(1, 5);
        aead.encrypt_framed_packet_into(7, &aad, b"tag", &mut framed)
            .unwrap();
        let last = framed.len() - 1;
        framed[last] ^= 0x01;
        let mut ctr = [0u8; WIRE_COUNTER_LEN];
        ctr.copy_from_slice(&framed[1..1 + WIRE_COUNTER_LEN]);
        let mut out = BytesMut::new();
        assert!(aead
            .decrypt_framed_payload_into(&ctr, &aad, &framed[1 + WIRE_COUNTER_LEN..], &mut out)
            .is_err());
    }

    #[test]
    fn data_replay_window_rejects_duplicate_and_old() {
        let mut w = DataReplayWindow::new();
        assert!(w.allows(10));
        w.commit(10);
        assert!(!w.allows(10));
        assert!(w.allows(11));
        w.commit(11);
        assert!(!w.allows(10));
        assert!(!w.allows(11));
        assert!(w.allows(12));
    }

    #[test]
    fn data_replay_window_allows_far_ahead_and_commits() {
        let mut w = DataReplayWindow::new();
        w.commit(10);
        assert!(w.allows(400));
        w.commit(400);
        assert!(!w.allows(400));
        assert!(!w.allows(10));
    }

    #[test]
    fn control_rate_limiter_reap_unblocks_new_source_after_full() {
        // Avoid Instant::now() - large Duration: panics when monotonic clock history
        // (e.g. Windows QPC since boot) is shorter than the subtracted span.
        let mut rl = ControlRateLimiter::new(2.0, 0.0);
        let old = Instant::now();
        std::thread::sleep(Duration::from_millis(5));
        for key in 0..65_536u64 {
            rl.entries.insert(
                key,
                Bucket {
                    tokens: 1.0,
                    last_refill: old,
                    last_seen: old,
                },
            );
        }
        rl.reap_after = Duration::from_millis(1);
        // Force-reap path runs when map is full; last_reap age is irrelevant.

        assert!(rl.allow(200_001));
        assert!(rl.entries.contains_key(&200_001));
        assert!(rl.entries.len() < 65_536);
    }
}
