use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::net::packet::{CompactPacketType, FEC_COMPACT_HEADER_LEN};

pub const FEC_SHARD_PAYLOAD_SIZE: usize = 1279;
pub const FEC_SHARD_LEN_PREFIX: usize = 2;
/// Floor for configured and runtime-effective shard payload size.
pub const FEC_SHARD_PAYLOAD_MIN: usize = 512;
pub const FEC_FLUSH_TIMEOUT: Duration = Duration::from_millis(2);
pub const FEC_FLUSH_TIMEOUT_AGGRESSIVE: Duration = Duration::from_millis(1);
pub const FEC_MAX_TOTAL_SHARDS: usize = 64;

/// Max FEC shard payload that fits under an IP-total path MTU (probe ladder units).
/// Returns `None` when the path cannot host a shard of at least [`FEC_SHARD_PAYLOAD_MIN`].
pub fn effective_shard_payload_size(configured: usize, min_path_mtu: usize) -> Option<usize> {
    use crate::net::packet::UNDERLAY_IPV4_UDP_OVERHEAD;
    let max = min_path_mtu.saturating_sub(UNDERLAY_IPV4_UDP_OVERHEAD + FEC_COMPACT_HEADER_LEN);
    let e = configured.min(max).min(FEC_SHARD_PAYLOAD_SIZE);
    (e >= FEC_SHARD_PAYLOAD_MIN).then_some(e)
}

/// Latency vs FEC efficiency for buffered shards. Mixed sizes in one group use the
/// minimum timeout among packets (most urgent policy wins).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FlushPolicy {
    Immediate,
    Aggressive,
    Standard,
}

fn classify_packet(len: usize) -> FlushPolicy {
    match len {
        0..=255 => FlushPolicy::Immediate,
        256..=799 => FlushPolicy::Aggressive,
        _ => FlushPolicy::Standard,
    }
}

pub enum FecOutput {
    Buffered,
    Encoded(Vec<Bytes>),
    Passthrough(Vec<Bytes>),
}

pub fn adaptive_fec_ratio(loss_ewma: f64) -> (u8, u8) {
    match loss_ewma {
        l if l < 0.020 => (0, 0),
        l if l < 0.050 => (10, 1),
        l if l < 0.100 => (7, 1),
        l if l < 0.150 => (5, 1),
        _ => (4, 2),
    }
}

/// Hysteresis variant with tunable off/on thresholds. `off_below` is the loss
/// fraction at/below which FEC turns off (when already on); `on_above` is the
/// fraction above which FEC turns on (when currently off).
pub fn adaptive_fec_ratio_hyst_tuned(
    loss_ewma: f64,
    prev: Option<(u8, u8)>,
    off_below: f64,
    on_above: f64,
) -> (u8, u8) {
    let was_on = matches!(prev, Some((d, p)) if d > 0 && p > 0);
    if was_on {
        if loss_ewma < off_below {
            return (0, 0);
        }
        return adaptive_fec_ratio(loss_ewma.max(off_below + 0.001));
    }
    if loss_ewma < on_above {
        return (0, 0);
    }
    adaptive_fec_ratio(loss_ewma)
}

/// True when `proposed` enables FEC or increases parity vs `prev` (never true for decreases/off).
pub fn fec_ratio_would_increase_parity(prev: Option<(u8, u8)>, proposed: (u8, u8)) -> bool {
    let prop_on = proposed.0 > 0 && proposed.1 > 0;
    if !prop_on {
        return false;
    }
    let Some(prev) = prev else {
        return true;
    };
    let prev_on = prev.0 > 0 && prev.1 > 0;
    if !prev_on {
        return true;
    }
    let prev_frac = prev.1 as f64 / (prev.0 + prev.1) as f64;
    let prop_frac = proposed.1 as f64 / (proposed.0 + proposed.1) as f64;
    prop_frac > prev_frac + 1e-9 || ((prop_frac - prev_frac).abs() < 1e-9 && proposed.1 > prev.1)
}

/// Test/default-only recency window used by local FEC tests.
pub const FEC_RECOVERY_RECENCY: Duration = Duration::from_millis(1_200);

/// Adaptive parity ladder, highest overhead first (matches `adaptive_fec_ratio`).
const FEC_RATIO_LADDER: [(u8, u8); 4] = [(4, 2), (5, 1), (7, 1), (10, 1)];

fn fec_parity_frac(ratio: (u8, u8)) -> f64 {
    if ratio.0 == 0 || ratio.1 == 0 {
        return 0.0;
    }
    ratio.1 as f64 / (ratio.0 + ratio.1) as f64
}

/// True when `delay_ratio = queuing_delay / target` exceeds the congestive threshold.
pub fn fec_delay_is_congestive(
    queuing_delay_ms: f64,
    target_queue_delay_ms: u32,
    congestion_loss_threshold: f64,
) -> bool {
    let target = target_queue_delay_ms.max(1) as f64;
    queuing_delay_ms / target > congestion_loss_threshold
}

/// One discrete step down the adaptive ladder toward off.
pub fn fec_ratio_step_down(prev: (u8, u8)) -> (u8, u8) {
    if prev.0 == 0 || prev.1 == 0 {
        return (0, 0);
    }
    for (i, &r) in FEC_RATIO_LADDER.iter().enumerate() {
        if r == prev {
            return if i + 1 < FEC_RATIO_LADDER.len() {
                FEC_RATIO_LADDER[i + 1]
            } else {
                (0, 0)
            };
        }
    }
    let prev_frac = fec_parity_frac(prev);
    for &r in &FEC_RATIO_LADDER {
        if fec_parity_frac(r) < prev_frac - 1e-9 {
            return r;
        }
    }
    (0, 0)
}

/// True when `a` has strictly lower parity burden than `b` (including off vs on).
pub fn fec_ratio_is_strictly_lower(a: (u8, u8), b: (u8, u8)) -> bool {
    let a_on = a.0 > 0 && a.1 > 0;
    let b_on = b.0 > 0 && b.1 > 0;
    if !a_on {
        return b_on;
    }
    if !b_on {
        return false;
    }
    let fa = fec_parity_frac(a);
    let fb = fec_parity_frac(b);
    fa < fb - 1e-9 || ((fa - fb).abs() < 1e-9 && a.1 < b.1)
}

/// Congestive-loss gate for adaptive FEC (plan §1.9 / §3.1).
pub fn apply_fec_loss_classifier(
    proposed: (u8, u8),
    ratio_last: Option<(u8, u8)>,
    classifier_enabled: bool,
    queuing_delay_ms: f64,
    target_queue_delay_ms: u32,
    congestion_loss_threshold: f64,
) -> (bool, (u8, u8)) {
    if !classifier_enabled {
        return (false, proposed);
    }
    if !fec_delay_is_congestive(
        queuing_delay_ms,
        target_queue_delay_ms,
        congestion_loss_threshold,
    ) {
        return (false, proposed);
    }
    if !fec_ratio_would_increase_parity(ratio_last, proposed) {
        return (false, proposed);
    }
    if let Some(prev) = ratio_last {
        (true, prev)
    } else {
        (true, (0, 0))
    }
}

/// Post-congestion recovery: one ladder step down while loss EWMA is still sticky.
///
/// Only fires when the classifier is enabled, `recency` is non-zero, delay has
/// recovered below the congestive threshold, FEC is currently on, recent
/// congestion was observed within `recency`, and `proposed` is not already
/// strictly lower than `ratio_last`.
pub fn apply_fec_recovery_stepdown(
    proposed: (u8, u8),
    ratio_last: Option<(u8, u8)>,
    classifier_enabled: bool,
    queuing_delay_ms: f64,
    target_queue_delay_ms: u32,
    congestion_loss_threshold: f64,
    last_congestive_at: Option<Instant>,
    now: Instant,
    recency: Duration,
) -> (bool, (u8, u8)) {
    if !classifier_enabled || recency.is_zero() {
        return (false, proposed);
    }
    let Some(prev) = ratio_last else {
        return (false, proposed);
    };
    if prev.0 == 0 || prev.1 == 0 {
        return (false, proposed);
    }
    if fec_delay_is_congestive(
        queuing_delay_ms,
        target_queue_delay_ms,
        congestion_loss_threshold,
    ) {
        return (false, proposed);
    }
    let Some(at) = last_congestive_at else {
        return (false, proposed);
    };
    if now.saturating_duration_since(at) > recency {
        return (false, proposed);
    }
    if fec_ratio_is_strictly_lower(proposed, prev) {
        return (false, proposed);
    }
    let stepped = fec_ratio_step_down(prev);
    if stepped == prev {
        return (false, proposed);
    }
    (true, stepped)
}

pub struct FecEncoder {
    group_salt: u32,
    group_seq: u32,
    data_shards: u8,
    parity_shards: u8,
    shard_buf: Vec<PendingShard>,
    first_at: Option<Instant>,
    rs_cache: Option<ReedSolomon>,
    rs_cache_data: usize,
    rs_cache_parity: usize,
    shard_pool: Vec<Vec<u8>>,
    group_flush_timeout: Duration,
    shard_payload_size: usize,
    flush_standard: Duration,
    flush_aggressive: Duration,
    frame_scratch: BytesMut,
}

struct PendingShard {
    original: Bytes,
    shard: Vec<u8>,
}

impl FecEncoder {
    pub fn new(data_shards: u8, parity_shards: u8) -> Self {
        Self::with_flush(
            data_shards,
            parity_shards,
            FEC_SHARD_PAYLOAD_SIZE,
            FEC_FLUSH_TIMEOUT,
            FEC_FLUSH_TIMEOUT_AGGRESSIVE,
        )
    }

    pub fn with_flush(
        data_shards: u8,
        parity_shards: u8,
        shard_payload_size: usize,
        flush_standard: Duration,
        flush_aggressive: Duration,
    ) -> Self {
        let mut rng_salt: u32 = rand::random();
        if rng_salt == 0 {
            rng_salt = 0x9e37_79b9;
        }
        Self {
            group_salt: rng_salt,
            group_seq: 1,
            data_shards,
            parity_shards,
            shard_buf: Vec::with_capacity(data_shards.max(1) as usize),
            first_at: None,
            rs_cache: None,
            rs_cache_data: 0,
            rs_cache_parity: 0,
            shard_pool: Vec::new(),
            group_flush_timeout: flush_standard,
            shard_payload_size,
            flush_standard,
            flush_aggressive,
            frame_scratch: BytesMut::with_capacity(FEC_COMPACT_HEADER_LEN + shard_payload_size),
        }
    }

    /// Update shard size / flush timeouts. Caller MUST flush the encoder first
    /// (in-flight groups were encoded with the old shard size).
    pub fn apply_tuning(
        &mut self,
        shard_payload_size: usize,
        flush_standard: Duration,
        flush_aggressive: Duration,
    ) {
        if shard_payload_size != self.shard_payload_size {
            self.shard_pool.clear();
        }
        self.shard_payload_size = shard_payload_size;
        self.flush_standard = flush_standard;
        self.flush_aggressive = flush_aggressive;
    }

    pub fn shard_payload_size(&self) -> usize {
        self.shard_payload_size
    }

    pub fn set_frame_scratch_capacity(&mut self, capacity: usize) {
        if self.frame_scratch.capacity() < capacity {
            self.frame_scratch
                .reserve(capacity - self.frame_scratch.capacity());
        }
    }

    fn flush_timeout_for_policy(&self, policy: FlushPolicy) -> Duration {
        match policy {
            FlushPolicy::Immediate => Duration::ZERO,
            FlushPolicy::Aggressive => self.flush_aggressive,
            FlushPolicy::Standard => self.flush_standard,
        }
    }

    fn reset_group_timing(&mut self) {
        self.first_at = None;
        self.group_flush_timeout = self.flush_standard;
    }

    pub fn ratio(&self) -> (u8, u8) {
        (self.data_shards, self.parity_shards)
    }

    pub fn update_ratio(&mut self, data_shards: u8, parity_shards: u8) {
        let _ = self.update_ratio_with_flush(data_shards, parity_shards, None);
    }

    pub fn update_ratio_with_flush(
        &mut self,
        data_shards: u8,
        parity_shards: u8,
        queue_budget: Option<(usize, usize)>,
    ) -> FecOutput {
        if self.data_shards == data_shards && self.parity_shards == parity_shards {
            return FecOutput::Buffered;
        }
        let pending = self.flush(queue_budget);
        self.shard_buf.clear();
        self.reset_group_timing();
        self.group_seq = self.group_seq.wrapping_add(1).max(1);
        self.data_shards = data_shards;
        self.parity_shards = parity_shards;
        pending
    }

    pub fn needs_flush(&self) -> bool {
        self.first_at
            .map(|t| t.elapsed() >= self.group_flush_timeout)
            .unwrap_or(false)
    }

    pub fn push(&mut self, pkt: Bytes) -> Option<Vec<Bytes>> {
        match self.push_output(pkt, None) {
            FecOutput::Buffered => None,
            FecOutput::Encoded(pkts) | FecOutput::Passthrough(pkts) => Some(pkts),
        }
    }

    pub fn push_output(&mut self, pkt: Bytes, queue_budget: Option<(usize, usize)>) -> FecOutput {
        if self.data_shards == 0 || self.parity_shards == 0 {
            return FecOutput::Passthrough(vec![pkt]);
        }
        if pkt.len() + FEC_SHARD_LEN_PREFIX > self.shard_payload_size {
            return FecOutput::Passthrough(vec![pkt]);
        }
        let total = self.data_shards as usize + self.parity_shards as usize;
        if total == 0 || total > FEC_MAX_TOTAL_SHARDS {
            return FecOutput::Passthrough(vec![pkt]);
        }
        let orig_len = pkt.len();
        let policy = classify_packet(orig_len);
        if self.shard_buf.is_empty() {
            self.group_flush_timeout = self.flush_standard;
        }
        self.group_flush_timeout = self
            .group_flush_timeout
            .min(self.flush_timeout_for_policy(policy));
        if self.first_at.is_none() {
            self.first_at = Some(Instant::now());
        }
        let mut shard = self.take_shard_buf();
        shard[..FEC_SHARD_LEN_PREFIX].copy_from_slice(&(orig_len as u16).to_le_bytes());
        shard[FEC_SHARD_LEN_PREFIX..FEC_SHARD_LEN_PREFIX + orig_len]
            .copy_from_slice(&pkt[..orig_len]);
        self.shard_buf.push(PendingShard {
            original: pkt,
            shard,
        });
        if self.shard_buf.len() >= self.data_shards as usize {
            let total = self.data_shards as usize + self.parity_shards as usize;
            if let Some((ql, cap)) = queue_budget {
                if ql.saturating_add(total) > cap {
                    return self.take_passthrough();
                }
            }
            return FecOutput::Encoded(
                self.encode_and_reset(self.data_shards as usize, self.parity_shards as usize),
            );
        }
        if policy == FlushPolicy::Immediate {
            return self.flush(queue_budget);
        }
        FecOutput::Buffered
    }

    pub fn flush(&mut self, queue_budget: Option<(usize, usize)>) -> FecOutput {
        if self.shard_buf.is_empty() {
            self.shard_buf.clear();
            self.reset_group_timing();
            return FecOutput::Buffered;
        }
        if self.data_shards == 0 || self.parity_shards == 0 {
            return self.take_passthrough();
        }
        let data_n = self.shard_buf.len();
        if data_n < 2 {
            return self.take_passthrough();
        }
        let configured_data = self.data_shards.max(1) as usize;
        let configured_parity = self.parity_shards.max(1) as usize;
        let dynamic_parity = ((data_n * configured_parity) + configured_data - 1) / configured_data;
        let dynamic_parity = dynamic_parity.clamp(1, configured_parity);
        if data_n + dynamic_parity > FEC_MAX_TOTAL_SHARDS {
            return self.take_passthrough();
        }
        let total_shards = data_n + dynamic_parity;
        if let Some((ql, cap)) = queue_budget {
            if ql.saturating_add(total_shards) > cap {
                return self.take_passthrough();
            }
        }
        FecOutput::Encoded(self.encode_and_reset(data_n, dynamic_parity))
    }

    /// Emit buffered originals without Reed–Solomon (no parity amplification).
    pub fn flush_passthrough(&mut self) -> FecOutput {
        if self.shard_buf.is_empty() {
            self.shard_buf.clear();
            self.reset_group_timing();
            return FecOutput::Buffered;
        }
        self.take_passthrough()
    }

    fn encode_and_reset(&mut self, data_shards: usize, parity_shards: usize) -> Vec<Bytes> {
        let need_rebuild = self.rs_cache.is_none()
            || self.rs_cache_data != data_shards
            || self.rs_cache_parity != parity_shards;
        if need_rebuild {
            match ReedSolomon::new(data_shards, parity_shards) {
                Ok(v) => {
                    self.rs_cache = Some(v);
                    self.rs_cache_data = data_shards;
                    self.rs_cache_parity = parity_shards;
                }
                Err(_) => {
                    self.rs_cache = None;
                    return self.take_passthrough_packets();
                }
            }
        }
        let group_id = self.current_group_id();
        let n = data_shards;
        if self.shard_buf.len() < n {
            return self.take_passthrough_packets();
        }
        let mut all_shards: Vec<Vec<u8>> = (0..n)
            .map(|i| std::mem::take(&mut self.shard_buf[i].shard))
            .collect();
        for _ in 0..parity_shards {
            all_shards.push(self.take_shard_buf());
        }
        let rs = match self.rs_cache.as_ref() {
            Some(v) => v,
            None => {
                for p in all_shards.drain(n..) {
                    self.return_shard_buf(p);
                }
                for (i, shard) in all_shards.into_iter().enumerate() {
                    self.shard_buf[i].shard = shard;
                }
                return self.take_passthrough_packets();
            }
        };
        if rs.encode(&mut all_shards).is_err() {
            for p in all_shards.drain(n..) {
                self.return_shard_buf(p);
            }
            for (i, shard) in all_shards.into_iter().enumerate() {
                self.shard_buf[i].shard = shard;
            }
            return self.take_passthrough_packets();
        }
        let mut out = Vec::with_capacity(n + parity_shards);
        for (idx, shard) in all_shards.iter().enumerate() {
            build_fec_packet_into(
                group_id,
                idx as u8,
                data_shards as u8,
                parity_shards as u8,
                shard,
                &mut self.frame_scratch,
            );
            out.push(self.frame_scratch.split().freeze());
        }
        for shard in all_shards {
            self.return_shard_buf(shard);
        }
        self.shard_buf.drain(..n);
        if self.shard_buf.is_empty() {
            self.reset_group_timing();
        } else {
            self.first_at = Some(Instant::now());
            self.group_flush_timeout = self.flush_standard;
        }
        self.group_seq = self.group_seq.wrapping_add(1).max(1);
        out
    }

    fn take_shard_buf(&mut self) -> Vec<u8> {
        let size = self.shard_payload_size;
        match self.shard_pool.pop() {
            Some(mut v) if v.len() == size => {
                v.fill(0);
                v
            }
            Some(mut v) => {
                v.clear();
                v.resize(size, 0);
                v
            }
            None => vec![0u8; size],
        }
    }

    fn return_shard_buf(&mut self, mut v: Vec<u8>) {
        if v.len() == self.shard_payload_size {
            v.fill(0);
            const MAX_POOL: usize = 32;
            if self.shard_pool.len() < MAX_POOL {
                self.shard_pool.push(v);
            }
        }
    }

    fn take_passthrough(&mut self) -> FecOutput {
        let out = self.take_passthrough_packets();
        FecOutput::Passthrough(out)
    }

    fn take_passthrough_packets(&mut self) -> Vec<Bytes> {
        let pending: Vec<PendingShard> = self.shard_buf.drain(..).collect();
        let mut out = Vec::with_capacity(pending.len());
        for s in pending {
            self.return_shard_buf(s.shard);
            out.push(s.original);
        }
        self.reset_group_timing();
        self.group_seq = self.group_seq.wrapping_add(1).max(1);
        out
    }

    fn current_group_id(&self) -> u32 {
        self.group_salt ^ self.group_seq
    }

    #[cfg(test)]
    fn shard_pool_len(&self) -> usize {
        self.shard_pool.len()
    }

    #[cfg(test)]
    fn test_inject_pool_buf(&mut self, buf: Vec<u8>) {
        self.shard_pool.push(buf);
    }
}

const FEC_DECODER_EVICT_INTERVAL: Duration = Duration::from_millis(50);
const FEC_COMPLETED_GROUPS_CAP: usize = 128;

pub struct FecDecoder {
    groups: HashMap<u32, PartialGroup>,
    /// Recently completed group ids — ignore late shards (in-flight parity after early extract).
    completed_groups: VecDeque<u32>,
    group_ttl: Duration,
    max_groups: usize,
    reconstruct_rs: Option<ReedSolomon>,
    reconstruct_rs_data: usize,
    reconstruct_rs_parity: usize,
    last_evict: Instant,
}

struct PartialGroup {
    data_shards: u8,
    parity_shards: u8,
    shard_size: usize,
    received: Vec<Option<Vec<u8>>>,
    received_count: u8,
    created_at: Instant,
}

pub struct FecDecodeResult {
    pub recovered: Vec<Bytes>,
    pub invalid: bool,
    /// New unique shards accepted on this call (0 or 1).
    pub shards_new: u8,
    /// Shards still missing when a group closed/evicted on this call.
    pub shards_missing: u16,
}

impl FecDecodeResult {
    fn invalid_with_missing(shards_missing: u16) -> Self {
        Self {
            recovered: vec![],
            invalid: true,
            shards_new: 0,
            shards_missing,
        }
    }

    fn ok(recovered: Vec<Bytes>, shards_new: u8, shards_missing: u16) -> Self {
        Self {
            recovered,
            invalid: false,
            shards_new,
            shards_missing,
        }
    }
}

#[inline]
fn group_shards_missing(g: &PartialGroup) -> u16 {
    (g.received.len() as u16).saturating_sub(g.received_count as u16)
}

impl FecDecoder {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
            completed_groups: VecDeque::with_capacity(FEC_COMPLETED_GROUPS_CAP),
            group_ttl: Duration::from_millis(200),
            max_groups: 256,
            reconstruct_rs: None,
            reconstruct_rs_data: 0,
            reconstruct_rs_parity: 0,
            last_evict: Instant::now(),
        }
    }

    fn note_completed(&mut self, group_id: u32) {
        if self.completed_groups.len() >= FEC_COMPLETED_GROUPS_CAP {
            self.completed_groups.pop_front();
        }
        self.completed_groups.push_back(group_id);
    }

    pub fn push_shard(&mut self, raw: &[u8]) -> FecDecodeResult {
        let now = Instant::now();
        let mut shards_missing = 0u16;
        if now.duration_since(self.last_evict) >= FEC_DECODER_EVICT_INTERVAL {
            shards_missing = shards_missing.saturating_add(self.evict_at(now));
            self.last_evict = now;
        }
        if raw.len() < FEC_COMPACT_HEADER_LEN || raw[0] != CompactPacketType::Fec.to_byte() {
            return FecDecodeResult::invalid_with_missing(shards_missing);
        }
        let group_id = u32::from_le_bytes([raw[1], raw[2], raw[3], raw[4]]);
        if self.completed_groups.iter().any(|&id| id == group_id) {
            // Late shard after early data-complete extract (typically parity).
            return FecDecodeResult::ok(vec![], 0, shards_missing);
        }
        let shard_idx = raw[5] as usize;
        let data_shards = raw[6];
        let parity_shards = raw[7];
        let shard_size = u16::from_le_bytes([raw[8], raw[9]]) as usize;
        let shard_data = &raw[FEC_COMPACT_HEADER_LEN..];
        let total = data_shards as usize + parity_shards as usize;
        if total == 0
            || total > FEC_MAX_TOTAL_SHARDS
            || shard_idx >= total
            || shard_data.len() < shard_size
            || shard_size < FEC_SHARD_LEN_PREFIX
            || shard_size > FEC_SHARD_PAYLOAD_SIZE
        {
            if let Some(g) = self.groups.remove(&group_id) {
                shards_missing = shards_missing.saturating_add(group_shards_missing(&g));
            }
            return FecDecodeResult::invalid_with_missing(shards_missing);
        }
        let payload = shard_data[..shard_size].to_vec();
        if !self.groups.contains_key(&group_id) && self.groups.len() >= self.max_groups {
            shards_missing = shards_missing.saturating_add(self.evict_oldest_group());
        }
        let group = self.groups.entry(group_id).or_insert_with(|| PartialGroup {
            data_shards,
            parity_shards,
            shard_size,
            received: vec![None; total],
            received_count: 0,
            created_at: Instant::now(),
        });
        if group.data_shards != data_shards
            || group.parity_shards != parity_shards
            || group.shard_size != shard_size
            || group.received.len() != total
        {
            if let Some(g) = self.groups.remove(&group_id) {
                shards_missing = shards_missing.saturating_add(group_shards_missing(&g));
            }
            return FecDecodeResult::invalid_with_missing(shards_missing);
        }
        if group.received[shard_idx].is_some() {
            return FecDecodeResult::ok(vec![], 0, shards_missing);
        }
        group.received[shard_idx] = Some(payload);
        group.received_count = group.received_count.saturating_add(1);
        let data_count = group.received[..group.data_shards as usize]
            .iter()
            .filter(|x| x.is_some())
            .count();
        if data_count == group.data_shards as usize {
            // All data present — extract now. Outstanding parity is not counted as
            // loss (may still be in flight); late parity ignored via completed_groups.
            let (recovered, _) = self.extract_data(group_id);
            self.note_completed(group_id);
            return FecDecodeResult::ok(recovered, 1, shards_missing);
        }
        if group.received_count as usize >= group.data_shards as usize {
            let (recovered, close_missing) = self.reconstruct_and_extract(group_id);
            self.note_completed(group_id);
            return FecDecodeResult::ok(recovered, 1, shards_missing.saturating_add(close_missing));
        }
        FecDecodeResult::ok(vec![], 1, shards_missing)
    }

    /// Reconstruct then extract. Returns `(recovered, shards_missing)`.
    fn reconstruct_and_extract(&mut self, group_id: u32) -> (Vec<Bytes>, u16) {
        let (data_n, parity_n) = match self.groups.get(&group_id) {
            Some(g) => (g.data_shards as usize, g.parity_shards as usize),
            None => return (vec![], 0),
        };
        let need_rebuild = self.reconstruct_rs.is_none()
            || self.reconstruct_rs_data != data_n
            || self.reconstruct_rs_parity != parity_n;
        if need_rebuild {
            match ReedSolomon::new(data_n, parity_n) {
                Ok(v) => {
                    self.reconstruct_rs = Some(v);
                    self.reconstruct_rs_data = data_n;
                    self.reconstruct_rs_parity = parity_n;
                }
                Err(_) => {
                    return self.take_group_as_missing(group_id);
                }
            }
        }
        if self.reconstruct_rs.is_none() {
            return self.take_group_as_missing(group_id);
        }
        let reconstruct_ok = {
            let group = match self.groups.get_mut(&group_id) {
                Some(g) => g,
                None => return (vec![], 0),
            };
            // `reconstruct_rs` and `groups` are distinct fields — split borrow is fine.
            self.reconstruct_rs
                .as_ref()
                .unwrap()
                .reconstruct(&mut group.received)
                .is_ok()
        };
        if !reconstruct_ok {
            return self.take_group_as_missing(group_id);
        }
        self.extract_data(group_id)
    }

    /// Extract data shards. Returns `(recovered, shards_missing)` where missing
    /// is counted from wire receipts (`received_count`) before RS fill-in.
    fn extract_data(&mut self, group_id: u32) -> (Vec<Bytes>, u16) {
        let group = match self.groups.remove(&group_id) {
            Some(g) => g,
            None => return (vec![], 0),
        };
        let missing = group_shards_missing(&group);
        let recovered = group.received[..group.data_shards as usize]
            .iter()
            .filter_map(|shard| {
                let s = shard.as_ref()?;
                let orig_len = u16::from_le_bytes([s[0], s[1]]) as usize;
                if orig_len > s.len().saturating_sub(FEC_SHARD_LEN_PREFIX) {
                    return None;
                }
                Some(Bytes::copy_from_slice(
                    &s[FEC_SHARD_LEN_PREFIX..FEC_SHARD_LEN_PREFIX + orig_len],
                ))
            })
            .collect();
        (recovered, missing)
    }

    fn take_group_as_missing(&mut self, group_id: u32) -> (Vec<Bytes>, u16) {
        match self.groups.remove(&group_id) {
            Some(g) => (vec![], group_shards_missing(&g)),
            None => (vec![], 0),
        }
    }

    fn evict_at(&mut self, now: Instant) -> u16 {
        let ttl = self.group_ttl;
        let mut missing = 0u16;
        self.groups.retain(|_, g| {
            if now.duration_since(g.created_at) < ttl {
                true
            } else {
                missing = missing.saturating_add(group_shards_missing(g));
                false
            }
        });
        missing
    }

    /// Drop TTL-expired groups; returns wire shards still missing on those groups.
    pub fn evict_expired(&mut self) -> u16 {
        let now = Instant::now();
        let missing = self.evict_at(now);
        self.last_evict = now;
        missing
    }

    fn evict_oldest_group(&mut self) -> u16 {
        let oldest = self
            .groups
            .iter()
            .min_by_key(|(_, g)| g.created_at)
            .map(|(id, _)| *id);
        if let Some(id) = oldest {
            return self
                .groups
                .remove(&id)
                .map(|g| group_shards_missing(&g))
                .unwrap_or(0);
        }
        0
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    pub fn group_count(&self) -> usize {
        self.groups.len()
    }
}

#[cfg(test)]
fn build_fec_packet(
    group_id: u32,
    shard_idx: u8,
    data_shards: u8,
    parity_shards: u8,
    shard_data: &[u8],
) -> Bytes {
    let mut buf = BytesMut::with_capacity(FEC_COMPACT_HEADER_LEN + shard_data.len());
    build_fec_packet_into(
        group_id,
        shard_idx,
        data_shards,
        parity_shards,
        shard_data,
        &mut buf,
    );
    buf.freeze()
}

fn build_fec_packet_into(
    group_id: u32,
    shard_idx: u8,
    data_shards: u8,
    parity_shards: u8,
    shard_data: &[u8],
    out: &mut BytesMut,
) {
    out.clear();
    out.reserve(FEC_COMPACT_HEADER_LEN + shard_data.len());
    out.extend_from_slice(&[CompactPacketType::Fec.to_byte()]);
    out.extend_from_slice(&group_id.to_le_bytes());
    out.extend_from_slice(&[shard_idx]);
    out.extend_from_slice(&[data_shards]);
    out.extend_from_slice(&[parity_shards]);
    out.extend_from_slice(&(shard_data.len() as u16).to_le_bytes());
    out.extend_from_slice(shard_data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    /// Payload size that buffers under FEC (above interactive ≤255 B threshold).
    const FEC_BUFFER_TEST_LEN: usize = 300;

    #[test]
    fn adaptive_ratio_boundaries() {
        assert_eq!(adaptive_fec_ratio(0.0), (0, 0));
        assert_eq!(adaptive_fec_ratio(0.02), (10, 1));
        assert_eq!(adaptive_fec_ratio(0.05), (7, 1));
        assert_eq!(adaptive_fec_ratio(0.10), (5, 1));
        assert_eq!(adaptive_fec_ratio(0.15), (4, 2));
    }

    #[test]
    fn fec_loss_classifier_holds_increase_when_congested() {
        let proposed = adaptive_fec_ratio(0.10);
        let prev = Some((10, 1));
        let (held, ratio) = apply_fec_loss_classifier(proposed, prev, true, 50.0, 30, 0.7);
        assert!(held);
        assert_eq!(ratio, prev.unwrap());
    }

    #[test]
    fn fec_loss_classifier_allows_increase_when_delay_low() {
        let proposed = adaptive_fec_ratio(0.10);
        let prev = Some((10, 1));
        let (held, ratio) = apply_fec_loss_classifier(proposed, prev, true, 10.0, 30, 0.7);
        assert!(!held);
        assert_eq!(ratio, proposed);
    }

    #[test]
    fn fec_loss_classifier_allows_decrease_when_congested() {
        let proposed = (0, 0);
        let prev = Some((7, 1));
        let (held, ratio) = apply_fec_loss_classifier(proposed, prev, true, 100.0, 30, 0.7);
        assert!(!held);
        assert_eq!(ratio, (0, 0));
    }

    #[test]
    fn fec_loss_classifier_off_is_noop() {
        let proposed = adaptive_fec_ratio(0.15);
        let (held, ratio) = apply_fec_loss_classifier(proposed, None, false, 200.0, 30, 0.7);
        assert!(!held);
        assert_eq!(ratio, proposed);
    }

    #[test]
    fn fec_ratio_step_down_follows_ladder() {
        assert_eq!(fec_ratio_step_down((4, 2)), (5, 1));
        assert_eq!(fec_ratio_step_down((5, 1)), (7, 1));
        assert_eq!(fec_ratio_step_down((7, 1)), (10, 1));
        assert_eq!(fec_ratio_step_down((10, 1)), (0, 0));
        assert_eq!(fec_ratio_step_down((0, 0)), (0, 0));
    }

    #[test]
    fn fec_recovery_stepdown_after_congestion() {
        let now = Instant::now();
        let prev = Some((4, 2));
        let proposed = adaptive_fec_ratio(0.15); // still sticky high
        let (stepped, ratio) = apply_fec_recovery_stepdown(
            proposed,
            prev,
            true,
            5.0,
            20,
            0.7,
            Some(now - Duration::from_millis(500)),
            now,
            FEC_RECOVERY_RECENCY,
        );
        assert!(stepped);
        assert_eq!(ratio, (5, 1));
    }

    #[test]
    fn fec_recovery_stepdown_skips_without_recency() {
        let now = Instant::now();
        let (stepped, ratio) = apply_fec_recovery_stepdown(
            (4, 2),
            Some((4, 2)),
            true,
            5.0,
            20,
            0.7,
            None,
            now,
            FEC_RECOVERY_RECENCY,
        );
        assert!(!stepped);
        assert_eq!(ratio, (4, 2));
    }

    #[test]
    fn fec_recovery_stepdown_skips_when_recency_expired() {
        let now = Instant::now();
        let (stepped, ratio) = apply_fec_recovery_stepdown(
            (4, 2),
            Some((4, 2)),
            true,
            5.0,
            20,
            0.7,
            Some(now - FEC_RECOVERY_RECENCY - Duration::from_millis(1)),
            now,
            FEC_RECOVERY_RECENCY,
        );
        assert!(!stepped);
        assert_eq!(ratio, (4, 2));
    }

    #[test]
    fn fec_recovery_stepdown_skips_while_still_congested() {
        let now = Instant::now();
        let (stepped, ratio) = apply_fec_recovery_stepdown(
            (4, 2),
            Some((4, 2)),
            true,
            50.0,
            20,
            0.7,
            Some(now),
            now,
            FEC_RECOVERY_RECENCY,
        );
        assert!(!stepped);
        assert_eq!(ratio, (4, 2));
    }

    #[test]
    fn fec_recovery_stepdown_keeps_natural_decrease() {
        let now = Instant::now();
        let proposed = (10, 1);
        let (stepped, ratio) = apply_fec_recovery_stepdown(
            proposed,
            Some((4, 2)),
            true,
            5.0,
            20,
            0.7,
            Some(now - Duration::from_millis(100)),
            now,
            FEC_RECOVERY_RECENCY,
        );
        assert!(!stepped);
        assert_eq!(ratio, proposed);
    }

    #[test]
    fn fec_recovery_stepdown_off_with_classifier_disabled() {
        let now = Instant::now();
        let (stepped, ratio) = apply_fec_recovery_stepdown(
            (4, 2),
            Some((4, 2)),
            false,
            5.0,
            20,
            0.7,
            Some(now),
            now,
            FEC_RECOVERY_RECENCY,
        );
        assert!(!stepped);
        assert_eq!(ratio, (4, 2));
    }

    #[test]
    fn fec_recovery_stepdown_off_when_recency_zero() {
        let now = Instant::now();
        let (stepped, ratio) = apply_fec_recovery_stepdown(
            (4, 2),
            Some((4, 2)),
            true,
            5.0,
            20,
            0.7,
            Some(now),
            now,
            Duration::ZERO,
        );
        assert!(!stepped);
        assert_eq!(ratio, (4, 2));
    }

    #[test]
    fn fec_recovery_ignores_random_loss_without_congestion_history() {
        let now = Instant::now();
        // High loss proposal, low delay, never marked congestive → no step-down.
        let proposed = adaptive_fec_ratio(0.15);
        let (stepped, ratio) = apply_fec_recovery_stepdown(
            proposed,
            Some((4, 2)),
            true,
            5.0,
            20,
            0.7,
            None,
            now,
            FEC_RECOVERY_RECENCY,
        );
        assert!(!stepped);
        assert_eq!(ratio, proposed);
    }

    #[test]
    fn encode_decode_recovers_one_missing_shard() {
        let mut enc = FecEncoder::new(4, 1);
        let mut out = Vec::new();
        let expected: Vec<Bytes> = (0..4)
            .map(|i| Bytes::from(vec![i as u8; FEC_BUFFER_TEST_LEN]))
            .collect();
        for i in 0..4 {
            if let Some(pkts) = enc.push(expected[i].clone()) {
                out = pkts;
            }
        }
        assert_eq!(out.len(), 5);
        let mut dec = FecDecoder::new();
        let mut recovered = Vec::new();
        let mut total_missing = 0u16;
        for (idx, pkt) in out.into_iter().enumerate() {
            if idx == 1 {
                continue;
            }
            let r = dec.push_shard(&pkt);
            total_missing = total_missing.saturating_add(r.shards_missing);
            if !r.recovered.is_empty() {
                recovered = r.recovered;
            }
        }
        assert_eq!(recovered, expected);
        // One data shard dropped on the wire → missing == 1 at group close.
        assert_eq!(total_missing, 1);
    }

    #[test]
    fn encode_decode_recovers_two_missing_data_shards() {
        let mut enc = FecEncoder::new(4, 2);
        let mut out = Vec::new();
        let expected: Vec<Bytes> = (0..4)
            .map(|i| Bytes::from(vec![i as u8; FEC_BUFFER_TEST_LEN]))
            .collect();
        for p in &expected {
            if let Some(pkts) = enc.push(p.clone()) {
                out = pkts;
            }
        }
        assert_eq!(out.len(), 6);
        let mut dec = FecDecoder::new();
        let mut recovered = Vec::new();
        let mut total_missing = 0u16;
        for (idx, pkt) in out.into_iter().enumerate() {
            if idx == 1 || idx == 3 {
                continue;
            }
            let r = dec.push_shard(&pkt);
            total_missing = total_missing.saturating_add(r.shards_missing);
            if !r.recovered.is_empty() {
                recovered = r.recovered;
            }
        }
        assert_eq!(recovered, expected);
        assert_eq!(total_missing, 2);
    }

    #[test]
    fn decoder_full_group_reports_zero_missing() {
        let mut enc = FecEncoder::new(4, 1);
        let mut out = Vec::new();
        for i in 0..4 {
            if let Some(pkts) = enc.push(Bytes::from(vec![i as u8; FEC_BUFFER_TEST_LEN])) {
                out = pkts;
            }
        }
        assert_eq!(out.len(), 5);
        let mut dec = FecDecoder::new();
        let mut close_missing = None;
        let mut new_shards = 0u32;
        for pkt in out {
            let r = dec.push_shard(&pkt);
            new_shards += u32::from(r.shards_new);
            if !r.recovered.is_empty() {
                close_missing = Some(r.shards_missing);
            }
        }
        // Early data-complete extract: outstanding parity is ignored (shards_new=0), not loss.
        assert!(new_shards >= 4, "expected at least all data shards counted");
        assert_eq!(close_missing, Some(0));
    }

    #[test]
    fn decoder_evict_counts_missing_shards() {
        let mut dec = FecDecoder::new();
        // data=5, parity=1 → total 6; deliver 1 shard → missing 5 on TTL evict.
        let p = build_fec_packet(
            9,
            0,
            5,
            1,
            &[16u8, 0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3],
        );
        let r = dec.push_shard(&p);
        assert!(!r.invalid);
        assert_eq!(r.shards_new, 1);
        assert!(!dec.is_empty());
        for group in dec.groups.values_mut() {
            group.created_at = Instant::now() - Duration::from_secs(1);
        }
        let missing = dec.evict_expired();
        assert_eq!(missing, 5);
        assert!(dec.is_empty());
    }

    #[test]
    fn interactive_single_packet_flushes_immediately() {
        let mut enc = FecEncoder::new(4, 1);
        match enc.push_output(Bytes::from(vec![1u8; 100]), None) {
            FecOutput::Passthrough(v) => assert_eq!(v.len(), 1),
            FecOutput::Encoded(_) => {}
            FecOutput::Buffered => panic!("interactive packet must not buffer"),
        }
        assert!(enc.shard_buf.is_empty());
    }

    #[test]
    fn aggressive_packet_flush_timeout_1ms() {
        let mut enc = FecEncoder::new(4, 1);
        assert!(matches!(
            enc.push_output(Bytes::from(vec![2u8; 300]), None),
            FecOutput::Buffered
        ));
        assert!(!enc.needs_flush());
        std::thread::sleep(Duration::from_millis(2));
        assert!(enc.needs_flush());
    }

    #[test]
    fn standard_packet_keeps_2ms_flush() {
        let mut enc = FecEncoder::new(4, 1);
        assert!(matches!(
            enc.push_output(Bytes::from(vec![3u8; 900]), None),
            FecOutput::Buffered
        ));
        std::thread::sleep(Duration::from_millis(1));
        assert!(!enc.needs_flush());
        std::thread::sleep(FEC_FLUSH_TIMEOUT);
        assert!(enc.needs_flush());
    }

    #[test]
    fn flush_timeout_emits_partial_group() {
        let mut enc = FecEncoder::new(4, 1);
        match enc.push_output(Bytes::from(vec![7u8; 120]), None) {
            FecOutput::Passthrough(flushed) => assert_eq!(flushed.len(), 1),
            _ => panic!("120B packet should flush immediately as passthrough"),
        }
        let mut enc = FecEncoder::new(4, 1);
        assert!(matches!(
            enc.push_output(Bytes::from(vec![8u8; 900]), None),
            FecOutput::Buffered
        ));
        std::thread::sleep(FEC_FLUSH_TIMEOUT + Duration::from_millis(2));
        assert!(enc.needs_flush());
        match enc.flush(None) {
            FecOutput::Encoded(flushed) => assert!((2..=5).contains(&flushed.len())),
            FecOutput::Passthrough(flushed) => assert_eq!(flushed.len(), 1),
            FecOutput::Buffered => panic!("unexpected buffered flush"),
        }
    }

    #[test]
    fn simulated_five_percent_loss_still_recovers_payloads() {
        let mut rng = rand::thread_rng();
        let mut sent_payload = 0usize;
        let mut recovered_payload = 0usize;
        let mut dec = FecDecoder::new();
        for g in 0..20 {
            let mut enc = FecEncoder::new(5, 1);
            let mut group = Vec::new();
            for i in 0..5 {
                let payload = Bytes::from(vec![(g * 10 + i) as u8; FEC_BUFFER_TEST_LEN]);
                sent_payload += 1;
                if let Some(pkts) = enc.push(payload) {
                    group = pkts;
                }
            }
            for pkt in group {
                if rng.gen_bool(0.05) {
                    continue;
                }
                let out = dec.push_shard(&pkt);
                recovered_payload += out.recovered.len();
            }
        }
        assert!(recovered_payload >= sent_payload / 2);
    }

    #[test]
    fn oversize_packet_is_passthrough_not_truncated() {
        let mut enc = FecEncoder::new(5, 1);
        let pkt = Bytes::from(vec![1u8; FEC_SHARD_PAYLOAD_SIZE + 50]);
        match enc.push_output(pkt.clone(), None) {
            FecOutput::Passthrough(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].len(), pkt.len());
            }
            _ => panic!("oversize must bypass"),
        }
    }

    #[test]
    fn push_output_insufficient_queue_budget_emits_passthrough() {
        let mut enc = FecEncoder::new(5, 1);
        let budget = Some((5, 10));
        for i in 0..4 {
            let p = Bytes::from(vec![i as u8; FEC_BUFFER_TEST_LEN]);
            assert!(matches!(enc.push_output(p, budget), FecOutput::Buffered));
        }
        let p = Bytes::from(vec![9u8; FEC_BUFFER_TEST_LEN]);
        match enc.push_output(p, budget) {
            FecOutput::Passthrough(v) => assert_eq!(v.len(), 5),
            FecOutput::Buffered => panic!("expected passthrough for budget, got Buffered"),
            FecOutput::Encoded(_) => panic!("expected passthrough for budget, got Encoded"),
        }
    }

    #[test]
    fn decoder_rejects_invariant_mismatch_without_panic() {
        let mut dec = FecDecoder::new();
        let p1 = build_fec_packet(
            7,
            0,
            5,
            1,
            &[16u8, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        );
        let p2 = build_fec_packet(
            7,
            1,
            4,
            2,
            &[16u8, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
        );
        let r1 = dec.push_shard(&p1);
        assert!(!r1.invalid);
        let r2 = dec.push_shard(&p2);
        assert!(r2.invalid);
    }

    #[test]
    fn decoder_evict_expired_clears_idle_groups() {
        let mut dec = FecDecoder::new();
        let p = build_fec_packet(
            9,
            0,
            5,
            1,
            &[16u8, 0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3],
        );
        assert!(!dec.push_shard(&p).invalid);
        assert!(!dec.is_empty());
        for group in dec.groups.values_mut() {
            group.created_at = Instant::now() - Duration::from_secs(1);
        }
        let _ = dec.evict_expired();
        assert!(dec.is_empty());
    }

    #[test]
    fn effective_shard_payload_size_clamps_to_path_mtu() {
        use crate::net::packet::UNDERLAY_IPV4_UDP_OVERHEAD;
        // min_path_mtu 1220 → max shard = 1220 - 28 - 10 = 1182
        assert_eq!(
            effective_shard_payload_size(FEC_SHARD_PAYLOAD_SIZE, 1220),
            Some(1182)
        );
        assert_eq!(
            effective_shard_payload_size(FEC_SHARD_PAYLOAD_SIZE, 1200),
            Some(1162)
        );
        // Below floor 512 after underlay+header → None (need path < 512+28+10 = 550)
        assert_eq!(
            effective_shard_payload_size(FEC_SHARD_PAYLOAD_SIZE, 549),
            None
        );
        assert_eq!(
            effective_shard_payload_size(FEC_SHARD_PAYLOAD_SIZE, 550),
            Some(512)
        );
        // Configured smaller than path budget wins
        assert_eq!(effective_shard_payload_size(900, 1500), Some(900));
        let max = 1220 - UNDERLAY_IPV4_UDP_OVERHEAD - FEC_COMPACT_HEADER_LEN;
        assert_eq!(max, 1182);
    }

    #[test]
    fn flush_passthrough_emits_originals_without_parity() {
        let mut enc = FecEncoder::new(5, 1);
        let a = Bytes::from(vec![1u8; FEC_BUFFER_TEST_LEN]);
        let b = Bytes::from(vec![2u8; FEC_BUFFER_TEST_LEN]);
        assert!(matches!(
            enc.push_output(a.clone(), None),
            FecOutput::Buffered
        ));
        assert!(matches!(
            enc.push_output(b.clone(), None),
            FecOutput::Buffered
        ));
        match enc.flush_passthrough() {
            FecOutput::Passthrough(v) => {
                assert_eq!(v.len(), 2);
                assert_eq!(v[0], a);
                assert_eq!(v[1], b);
            }
            _ => panic!("expected Passthrough, got non-passthrough variant"),
        }
        assert!(matches!(enc.flush_passthrough(), FecOutput::Buffered));
    }

    #[test]
    fn shard_pool_filled_after_full_encode() {
        let mut enc = FecEncoder::new(4, 1);
        let mut encoded = false;
        for i in 0..4 {
            if let Some(_pkts) = enc.push(Bytes::from(vec![i as u8; FEC_BUFFER_TEST_LEN])) {
                encoded = true;
            }
        }
        assert!(encoded);
        assert!(
            enc.shard_pool_len() >= 5,
            "pool len {}",
            enc.shard_pool_len()
        );
    }

    #[test]
    fn shard_pool_reuse_recovers_shorter_payloads() {
        let mut enc = FecEncoder::new(3, 1);
        for i in 0..3 {
            let _ = enc.push(Bytes::from(vec![(10 + i) as u8; 400]));
        }
        assert!(enc.shard_pool_len() >= 4);

        // 256..=799 buffers (Aggressive); must stay above interactive ≤255 flush.
        let expected: Vec<Bytes> = (0..3)
            .map(|i| Bytes::from(vec![(20 + i) as u8; 256]))
            .collect();
        let mut frames = None;
        for p in &expected {
            if let Some(pkts) = enc.push(p.clone()) {
                frames = Some(pkts);
            }
        }
        let frames = frames.expect("second group encoded");
        assert_eq!(frames.len(), 4);

        let mut dec = FecDecoder::new();
        let mut recovered = Vec::new();
        for pkt in &frames {
            let r = dec.push_shard(pkt);
            if !r.recovered.is_empty() {
                recovered = r.recovered;
            }
        }
        assert_eq!(recovered, expected);
    }

    #[test]
    fn take_shard_buf_zeros_dirty_pooled_buffer() {
        let mut enc =
            FecEncoder::with_flush(3, 1, 512, FEC_FLUSH_TIMEOUT, FEC_FLUSH_TIMEOUT_AGGRESSIVE);
        enc.test_inject_pool_buf(vec![0xAB; 512]);
        let buf = enc.take_shard_buf();
        assert_eq!(buf.len(), 512);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn shard_pool_returned_on_queue_budget_passthrough() {
        let mut enc = FecEncoder::new(5, 1);
        let budget = Some((5, 10));
        for i in 0..4 {
            let p = Bytes::from(vec![i as u8; FEC_BUFFER_TEST_LEN]);
            assert!(matches!(enc.push_output(p, budget), FecOutput::Buffered));
        }
        let p = Bytes::from(vec![9u8; FEC_BUFFER_TEST_LEN]);
        match enc.push_output(p, budget) {
            FecOutput::Passthrough(v) => assert_eq!(v.len(), 5),
            FecOutput::Buffered => panic!("expected passthrough for budget, got Buffered"),
            FecOutput::Encoded(_) => panic!("expected passthrough for budget, got Encoded"),
        }
        assert_eq!(enc.shard_pool_len(), 5);
    }

    #[test]
    fn apply_tuning_clears_shard_pool_on_size_change() {
        let mut enc = FecEncoder::new(4, 1);
        for i in 0..4 {
            let _ = enc.push(Bytes::from(vec![i as u8; FEC_BUFFER_TEST_LEN]));
        }
        assert!(enc.shard_pool_len() > 0);
        enc.apply_tuning(
            enc.shard_payload_size(),
            FEC_FLUSH_TIMEOUT,
            FEC_FLUSH_TIMEOUT_AGGRESSIVE,
        );
        assert!(enc.shard_pool_len() > 0, "same size must keep pool");
        let new_size = enc
            .shard_payload_size()
            .saturating_sub(64)
            .max(FEC_SHARD_PAYLOAD_MIN);
        assert_ne!(new_size, enc.shard_payload_size());
        enc.apply_tuning(new_size, FEC_FLUSH_TIMEOUT, FEC_FLUSH_TIMEOUT_AGGRESSIVE);
        assert_eq!(enc.shard_pool_len(), 0);
    }

    #[test]
    fn encoded_shards_fit_under_path_mtu_udp_budget() {
        use crate::net::packet::UNDERLAY_IPV4_UDP_OVERHEAD;
        let min_path_mtu = 1220;
        let shard = effective_shard_payload_size(FEC_SHARD_PAYLOAD_SIZE, min_path_mtu).unwrap();
        let mut enc =
            FecEncoder::with_flush(5, 1, shard, FEC_FLUSH_TIMEOUT, FEC_FLUSH_TIMEOUT_AGGRESSIVE);
        let mut group = None;
        for i in 0..5 {
            let p = Bytes::from(vec![i as u8; 300]);
            if let FecOutput::Encoded(pkts) = enc.push_output(p, None) {
                group = Some(pkts);
            }
        }
        let pkts = group.expect("full group should encode");
        let udp_budget = min_path_mtu - UNDERLAY_IPV4_UDP_OVERHEAD;
        for pkt in pkts {
            assert!(
                pkt.len() <= udp_budget,
                "FEC wire {} exceeds UDP budget {}",
                pkt.len(),
                udp_budget
            );
            assert_eq!(pkt.len(), FEC_COMPACT_HEADER_LEN + shard);
        }
    }
}
