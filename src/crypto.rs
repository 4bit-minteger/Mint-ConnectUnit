use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::time::Instant;

use aegis::aegis128l::Aegis128L;
use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use blake2::{Blake2b512, Blake2bMac, Digest};
use bytes::BytesMut;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::net::packet::CompactPacketType;
use hmac::Mac;
use rand::RngCore;

pub const KEY_LEN: usize = 32;
pub const AEAD_KEY_LEN: usize = 16;
pub const DATA_NONCE_LEN: usize = 16;
pub const DATA_SALT_LEN: usize = 10;
pub const WIRE_COUNTER_LEN: usize = 6;
pub const NONCE_LEN: usize = WIRE_COUNTER_LEN;
pub const DATA_TAG_LEN: usize = 16;
pub const MAC_TRUNC_LEN: usize = 16;
pub const DATA_REPLAY_WINDOW_BITS: usize = 128;
const DATA_REPLAY_MAX_COUNTER: u64 = (1u64 << 48) - 1;
const HKDF_DOMAIN_SALT: &[u8] = b"mint-aegis-128l-v1";
const HKDF_DOMAIN_INFO: &[u8] = b"data";

pub const CTRL_TS_FUTURE_TOLERANCE_MS: u64 = 5_000;

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

#[derive(Clone, Debug)]
pub struct CtrlFrame {
    pub timestamp_ms: u64,
    pub inner_tag: [u8; 4],
    pub body: Vec<u8>,
}

pub struct CtrlAuth;

impl CtrlAuth {
    pub fn wrap(key: &Key, inner_tag: &[u8; 4], body: &[u8], ts_ms: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 8 + MAC_TRUNC_LEN + 4 + body.len());
        out.extend_from_slice(b"MCTS");
        out.extend_from_slice(&ts_ms.to_le_bytes());

        let mut mac = <Blake2bMac<blake2::digest::consts::U32> as Mac>::new_from_slice(&key.0)
            .expect("valid key len");
        mac.update(&ts_ms.to_le_bytes());
        mac.update(inner_tag);
        mac.update(body);
        let full = mac.finalize().into_bytes();
        out.extend_from_slice(&full[..MAC_TRUNC_LEN]);
        out.extend_from_slice(inner_tag);
        out.extend_from_slice(body);
        out
    }

    pub fn unwrap_parts<'a>(
        key: &Key,
        payload: &'a [u8],
        now_ms: u64,
        window_ms: u64,
    ) -> Result<(u64, [u8; 4], &'a [u8])> {
        if payload.len() < 4 + 8 + MAC_TRUNC_LEN + 4 {
            bail!("payload too short");
        }
        if &payload[0..4] != b"MCTS" {
            bail!("invalid wrapper tag");
        }
        let ts_ms = u64::from_le_bytes(payload[4..12].try_into().map_err(|_| anyhow!("ts"))?);
        let age_past = now_ms.saturating_sub(ts_ms);
        let age_future = ts_ms.saturating_sub(now_ms);
        let ts_ok = if ts_ms <= now_ms {
            age_past <= window_ms
        } else {
            age_future <= CTRL_TS_FUTURE_TOLERANCE_MS
        };
        if !ts_ok {
            bail!("replay window");
        }

        let mac_start = 12;
        let tag_start = mac_start + MAC_TRUNC_LEN;
        let body_start = tag_start + 4;
        let mut inner_tag = [0u8; 4];
        inner_tag.copy_from_slice(&payload[tag_start..body_start]);
        let body = &payload[body_start..];
        let mac_expected = &payload[mac_start..tag_start];

        let mut mac = <Blake2bMac<blake2::digest::consts::U32> as Mac>::new_from_slice(&key.0)
            .expect("valid key len");
        mac.update(&ts_ms.to_le_bytes());
        mac.update(&inner_tag);
        mac.update(body);
        let full = mac.finalize().into_bytes();

        let mut diff: u8 = 0;
        for (a, b) in full[..MAC_TRUNC_LEN].iter().zip(mac_expected.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            bail!("bad mac");
        }

        Ok((ts_ms, inner_tag, body))
    }

    pub fn unwrap(key: &Key, payload: &[u8], now_ms: u64, window_ms: u64) -> Result<CtrlFrame> {
        let (timestamp_ms, inner_tag, body) = Self::unwrap_parts(key, payload, now_ms, window_ms)?;
        Ok(CtrlFrame {
            timestamp_ms,
            inner_tag,
            body: body.to_vec(),
        })
    }
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

pub const CTRL_REPLAY_WINDOW_MS: u64 =
    SlidingReplayWindow::WINDOW_BITS * SlidingReplayWindow::BUCKET_MS;

pub struct AntiReplayWindow {
    sources: HashMap<u64, (SlidingReplayWindow, u64)>,
    eviction_heap: BinaryHeap<Reverse<(u64, u64)>>,
    max_sources: usize,
}

impl AntiReplayWindow {
    pub fn new() -> Self {
        Self {
            sources: HashMap::with_capacity(8),
            eviction_heap: BinaryHeap::with_capacity(8),
            max_sources: 4096,
        }
    }

    fn rebuild_eviction_heap_from_sources(&mut self) {
        let mut h = BinaryHeap::new();
        for (&k, (_, ls)) in &self.sources {
            h.push(Reverse((*ls, k)));
        }
        self.eviction_heap = h;
    }

    /// Drop heap entries superseded by newer `last_seen` (or removed keys). Rebuild if duplicate
    /// pushes made the heap far larger than `sources`.
    fn prune_eviction_heap(&mut self) {
        const MAX_POP: usize = 64;
        for _ in 0..MAX_POP {
            let obsolete = match self.eviction_heap.peek() {
                None => break,
                Some(Reverse((heap_ts, key))) => match self.sources.get(key) {
                    None => true,
                    Some((_, current)) => *current != *heap_ts,
                },
            };
            if !obsolete {
                break;
            }
            self.eviction_heap.pop();
        }
        let cap = self
            .sources
            .len()
            .saturating_mul(2)
            .max(64)
            .saturating_add(256);
        if self.eviction_heap.len() > cap {
            self.rebuild_eviction_heap_from_sources();
        }
    }

    pub fn accept(&mut self, src_key: u64, ts_ms: u64, now_ms: u64, window_ms: u64) -> bool {
        let age_past = now_ms.saturating_sub(ts_ms);
        let age_future = ts_ms.saturating_sub(now_ms);
        let ts_ok = if ts_ms <= now_ms {
            age_past <= window_ms
        } else {
            age_future <= CTRL_TS_FUTURE_TOLERANCE_MS
        };
        if !ts_ok {
            return false;
        }
        let existing_accept = if let Some((window, last_seen)) = self.sources.get_mut(&src_key) {
            *last_seen = now_ms;
            self.eviction_heap.push(Reverse((now_ms, src_key)));
            Some(window.accept(ts_ms, now_ms, window_ms))
        } else {
            None
        };
        if let Some(accepted) = existing_accept {
            self.prune_eviction_heap();
            return accepted;
        }
        if self.sources.len() >= self.max_sources {
            let threshold = now_ms.saturating_sub(window_ms);
            while self.sources.len() >= self.max_sources {
                let Some(Reverse((heap_seen, key))) = self.eviction_heap.pop() else {
                    break;
                };
                let Some((_, current_seen)) = self.sources.get(&key) else {
                    continue;
                };
                if *current_seen != heap_seen {
                    continue;
                }
                if *current_seen > threshold {
                    break;
                }
                self.sources.remove(&key);
            }
            if self.sources.len() >= self.max_sources {
                self.sources.retain(|_, (_, ls)| *ls > threshold);
            }
        }
        let mut window = SlidingReplayWindow::new();
        let accepted = window.accept(ts_ms, now_ms, window_ms);
        if accepted {
            self.sources.insert(src_key, (window, now_ms));
            self.eviction_heap.push(Reverse((now_ms, src_key)));
            self.prune_eviction_heap();
        }
        accepted
    }
}

#[cfg(test)]
impl AntiReplayWindow {
    pub fn eviction_heap_len(&self) -> usize {
        self.eviction_heap.len()
    }
}

pub struct SlidingReplayWindow {
    bits: [u64; 4],
    top_bucket: u64,
}

impl SlidingReplayWindow {
    pub const WINDOW_BITS: u64 = 256;
    /// Bucket width; `WINDOW_BITS * BUCKET_MS` ≈ 40.96s past skew/replay window (+~15s vs 100ms buckets).
    pub const BUCKET_MS: u64 = 160;

    pub fn new() -> Self {
        Self {
            bits: [0u64; 4],
            top_bucket: 0,
        }
    }

    pub fn accept(&mut self, ts_ms: u64, now_ms: u64, window_ms: u64) -> bool {
        let age_past = now_ms.saturating_sub(ts_ms);
        let age_future = ts_ms.saturating_sub(now_ms);
        let ts_ok = if ts_ms <= now_ms {
            age_past <= window_ms
        } else {
            age_future <= CTRL_TS_FUTURE_TOLERANCE_MS
        };
        if !ts_ok {
            return false;
        }
        let bucket = ts_ms / Self::BUCKET_MS;
        if bucket + Self::WINDOW_BITS <= self.top_bucket {
            return false;
        }
        if bucket > self.top_bucket {
            self.shift_window((bucket - self.top_bucket).min(Self::WINDOW_BITS));
            self.top_bucket = bucket;
        }
        let offset = (self.top_bucket - bucket) as usize;
        if offset >= Self::WINDOW_BITS as usize {
            return false;
        }
        let word = offset / 64;
        let bit = offset % 64;
        let mask = 1u64 << bit;
        if self.bits[word] & mask != 0 {
            return false;
        }
        self.bits[word] |= mask;
        true
    }

    fn shift_window(&mut self, shift: u64) {
        if shift >= Self::WINDOW_BITS {
            self.bits = [0u64; 4];
            return;
        }
        let mut merged: U256 =
            U256::from_words(self.bits[0], self.bits[1], self.bits[2], self.bits[3]);
        merged = merged << (shift as u32);
        self.bits = [merged.w0, merged.w1, merged.w2, merged.w3];
    }
}

#[derive(Clone, Copy)]
struct U256 {
    w0: u64,
    w1: u64,
    w2: u64,
    w3: u64,
}

impl U256 {
    fn from_words(w0: u64, w1: u64, w2: u64, w3: u64) -> Self {
        Self { w0, w1, w2, w3 }
    }
}

impl std::ops::Shl<u32> for U256 {
    type Output = U256;

    fn shl(self, rhs: u32) -> Self::Output {
        if rhs == 0 {
            return self;
        }
        if rhs >= 256 {
            return Self::from_words(0, 0, 0, 0);
        }
        let word_shift = (rhs / 64) as usize;
        let bit_shift = rhs % 64;
        let words = [self.w0, self.w1, self.w2, self.w3];
        let mut out = [0u64; 4];
        for i in 0..4usize {
            if i + word_shift >= 4 {
                continue;
            }
            out[i + word_shift] |= words[i] << bit_shift;
            if bit_shift > 0 && i + word_shift + 1 < 4 {
                out[i + word_shift + 1] |= words[i] >> (64 - bit_shift);
            }
        }
        Self::from_words(out[0], out[1], out[2], out[3])
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
    fn ctrl_auth_unwrap_parts_matches_unwrap() {
        let k = MintCrypto::generate_key();
        let body = b"hello-control";
        let ts = now_epoch_ms();
        let pkt = CtrlAuth::wrap(&k, b"JACK", body, ts);
        let frame = CtrlAuth::unwrap(&k, &pkt, ts, CTRL_REPLAY_WINDOW_MS).unwrap();
        let (ts2, tag2, body2) =
            CtrlAuth::unwrap_parts(&k, &pkt, ts, CTRL_REPLAY_WINDOW_MS).unwrap();
        assert_eq!(frame.timestamp_ms, ts2);
        assert_eq!(frame.inner_tag, tag2);
        assert_eq!(frame.body.as_slice(), body2);
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
    fn anti_replay_accepts_then_rejects_duplicate_ts_bucket() {
        let mut w = AntiReplayWindow::new();
        let now = 1_000_000u64;
        assert!(w.accept(1, now, now, CTRL_REPLAY_WINDOW_MS));
        assert!(!w.accept(1, now, now, CTRL_REPLAY_WINDOW_MS));
    }

    #[test]
    fn anti_replay_evicts_oldest_when_at_cap_to_admit_new_source() {
        let mut w = AntiReplayWindow::new();
        let now = 2_000_000u64;
        for k in 0u64..4096 {
            assert!(
                w.accept(k, now + k, now + k, CTRL_REPLAY_WINDOW_MS),
                "k={k}"
            );
        }
        assert!(w.accept(9999, now, now, CTRL_REPLAY_WINDOW_MS));
        assert!(w.accept(100, now + 10_000, now + 10_000, CTRL_REPLAY_WINDOW_MS));
    }

    #[test]
    fn anti_replay_evicts_stale_entries_when_full_before_new_source() {
        let mut w = AntiReplayWindow::new();
        let window_ms = CTRL_REPLAY_WINDOW_MS;
        let base = 1_000_000u64;
        for k in 0u64..256 {
            assert!(w.accept(k, base + k, base + k, window_ms));
        }
        let now_ms = base + 2 * window_ms + 10_000;
        assert!(w.accept(9999, now_ms, now_ms, window_ms));
    }

    #[test]
    fn anti_replay_eviction_heap_stays_bounded_for_single_hot_source() {
        let mut w = AntiReplayWindow::new();
        let window_ms = CTRL_REPLAY_WINDOW_MS;
        let base = 5_000_000u64;
        for i in 0..10_000 {
            let t = base + i * SlidingReplayWindow::BUCKET_MS;
            assert!(w.accept(42, t, t, window_ms), "i={i}");
        }
        assert!(
            w.eviction_heap_len() <= 512,
            "heap len {}",
            w.eviction_heap_len()
        );
    }

    #[test]
    fn ctrl_auth_unwrap_accepts_slightly_future_timestamp() {
        let k = MintCrypto::generate_key();
        let body = b"body";
        let now = 1_000_000u64;
        let ts = now + CTRL_TS_FUTURE_TOLERANCE_MS / 2;
        let pkt = CtrlAuth::wrap(&k, b"JACK", body, ts);
        CtrlAuth::unwrap_parts(&k, &pkt, now, CTRL_REPLAY_WINDOW_MS)
            .expect("future within tolerance");
    }

    #[test]
    fn ctrl_auth_unwrap_rejects_far_future_timestamp() {
        let k = MintCrypto::generate_key();
        let body = b"body";
        let now = 1_000_000u64;
        let ts = now + CTRL_TS_FUTURE_TOLERANCE_MS + 1;
        let pkt = CtrlAuth::wrap(&k, b"JACK", body, ts);
        assert!(CtrlAuth::unwrap_parts(&k, &pkt, now, CTRL_REPLAY_WINDOW_MS).is_err());
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
        let mut rl = ControlRateLimiter::new(2.0, 0.0);
        let old = Instant::now() - Duration::from_secs(400);
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
        rl.reap_after = Duration::from_secs(300);
        rl.last_reap = Instant::now() - Duration::from_secs(120);

        assert!(rl.allow(200_001));
        assert!(rl.entries.contains_key(&200_001));
        assert!(rl.entries.len() < 65_536);
    }
}
