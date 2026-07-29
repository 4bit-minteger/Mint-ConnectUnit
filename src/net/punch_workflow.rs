//! Canonical 3-stage hole punch workflow (shared by join, manual, parasitic, reconnect).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::SeedableRng;
use tokio::net::UdpSocket;

use crate::advanced_tuning::HolePunchTuning;
use crate::net::decentralized::{
    build_random_residual_targets, canonical_covered_after_stage2, canonical_stage2_targets,
};
use crate::net::engine::{build_signed_or_plain_static_for_punch, PunchStateView};
use crate::net::packet::PKT_HPCH;

async fn sleep_cancellable(duration: Duration, stop: &Arc<AtomicBool>) {
    if duration.is_zero() {
        return;
    }
    let step = Duration::from_millis(50);
    let mut remaining = duration;
    while remaining > Duration::ZERO {
        if stop.load(Ordering::Acquire) {
            return;
        }
        let slice = remaining.min(step);
        tokio::time::sleep(slice).await;
        remaining = remaining.saturating_sub(slice);
    }
}

pub(crate) async fn punch_targets_at_pps(
    socket: &Arc<UdpSocket>,
    state_view: &PunchStateView,
    targets: &[SocketAddr],
    pps: u32,
    stop: &Arc<AtomicBool>,
) {
    if targets.is_empty() {
        return;
    }
    let per_send = Duration::from_micros((1_000_000u64 / u64::from(pps.max(1))).max(1));
    let snap = state_view.read().clone();
    let hpch_pkt = build_signed_or_plain_static_for_punch(
        snap.crypto_key.clone(),
        PKT_HPCH,
        snap.my_vip.as_bytes(),
    );
    for target in targets {
        if stop.load(Ordering::Acquire) {
            break;
        }
        let _ = socket.send_to(&hpch_pkt, *target).await;
        sleep_cancellable(per_send, stop).await;
    }
}

async fn punch_stage1_direct(
    socket: &Arc<UdpSocket>,
    state_view: &PunchStateView,
    bases: &[SocketAddr],
    punch: &HolePunchTuning,
    stop: &Arc<AtomicBool>,
) {
    if bases.is_empty() {
        return;
    }
    let gap = Duration::from_millis(punch.punch_stage1_gap_ms);
    for base in bases {
        for _ in 0..punch.punch_stage1_packets {
            if stop.load(Ordering::Acquire) {
                return;
            }
            let snap = state_view.read().clone();
            let pkt = build_signed_or_plain_static_for_punch(
                snap.crypto_key.clone(),
                PKT_HPCH,
                snap.my_vip.as_bytes(),
            );
            let _ = socket.send_to(&pkt, *base).await;
            sleep_cancellable(gap, stop).await;
        }
    }
    sleep_cancellable(Duration::from_millis(punch.punch_stage1_observe_ms), stop).await;
}

pub(crate) async fn run_canonical_punch_workflow(
    socket: Arc<UdpSocket>,
    state_view: PunchStateView,
    bases: Vec<SocketAddr>,
    punch: HolePunchTuning,
    stop: Arc<AtomicBool>,
    log_stages: bool,
    mut on_stage: impl FnMut(u8) + Send,
) {
    if bases.is_empty() {
        return;
    }

    if log_stages {
        on_stage(1);
    }
    punch_stage1_direct(&socket, &state_view, &bases, &punch, &stop).await;
    if stop.load(Ordering::Acquire) {
        return;
    }

    if log_stages {
        on_stage(2);
    }
    let stage2 = canonical_stage2_targets(&bases, &punch);
    punch_targets_at_pps(&socket, &state_view, &stage2, punch.punch_stage2_pps, &stop).await;
    if stop.load(Ordering::Acquire) {
        return;
    }
    sleep_cancellable(Duration::from_secs(punch.punch_stage2_observe_secs), &stop).await;
    if stop.load(Ordering::Acquire) {
        return;
    }

    if log_stages {
        on_stage(3);
    }
    let mut covered = canonical_covered_after_stage2(&bases, &stage2);
    let mut rng = rand::rngs::StdRng::from_entropy();
    let random_deadline = Instant::now() + Duration::from_secs(punch.punch_stage3_max_secs);
    while Instant::now() < random_deadline && !stop.load(Ordering::Acquire) {
        let residual = build_random_residual_targets(
            &bases,
            &covered,
            punch.punch_max_expanded_targets,
            punch.punch_random_port_min,
            punch.punch_random_port_max,
            &mut rng,
        );
        for ep in &residual {
            covered.insert(*ep);
        }
        punch_targets_at_pps(
            &socket,
            &state_view,
            &residual,
            punch.punch_stage3_pps,
            &stop,
        )
        .await;
        if stop.load(Ordering::Acquire) {
            break;
        }
        sleep_cancellable(
            Duration::from_millis(punch.punch_stage3_batch_gap_ms),
            &stop,
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::decentralized::MAX_EXPANDED_PUNCH_TARGETS;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn canonical_stage2_respects_budget_multi_peer() {
        let punch = HolePunchTuning::default();
        let bases: Vec<SocketAddr> = (0..8u8)
            .map(|i| SocketAddr::from((Ipv4Addr::new(i, 0, 0, 1), 40_000)))
            .collect();
        let stage2 = canonical_stage2_targets(&bases, &punch);
        assert!(stage2.len() <= MAX_EXPANDED_PUNCH_TARGETS);
        let covered = canonical_covered_after_stage2(&bases, &stage2);
        for ep in &bases {
            assert!(covered.contains(ep));
        }
    }

    #[test]
    fn canonical_stage2_port_boundary() {
        let punch = HolePunchTuning::default();
        let base = SocketAddr::from((Ipv4Addr::LOCALHOST, 2));
        let stage2 = canonical_stage2_targets(&[base], &punch);
        assert!(!stage2.is_empty());
        assert!(stage2.iter().all(|e| e.port() >= 1));
    }
}
