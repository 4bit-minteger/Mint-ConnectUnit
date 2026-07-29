use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

pub const MIN_PACE_TICK_US: u64 = 1;

pub const PACE_CLOCK_ADAPTIVE_THRESHOLD: u32 = 40;

#[derive(Clone, Copy, Debug)]
pub struct PaceClockApply {
    pub spin_window_us: u64,
    pub fab_enabled: bool,
    pub fab_fallback_us: u64,
}

impl PaceClockApply {
    pub fn from_network_config(cfg: &crate::config::NetworkConfig) -> Self {
        let tick = clamp_tick_us(cfg.pace_tick_us.max(1) as u64);
        let spin_window_us = spin_window_from_config(cfg, tick);
        Self {
            spin_window_us,
            fab_enabled: cfg.pace_fab_enabled,
            fab_fallback_us: (cfg.pace_fab_fallback_tick_us.max(1)) as u64,
        }
    }
}

/// Values for interactive pace prompts: (current, default on Enter).
pub fn pace_spin_prompt_values(cfg: &crate::config::NetworkConfig, tick_us: u64) -> (u64, u64) {
    let stored = clamp_spin_window_us(tick_us, cfg.pace_spin_window_us.max(0) as u64);
    let effective = spin_window_from_config(cfg, tick_us);
    let current = if effective == 0 && stored > 0 {
        stored
    } else {
        effective
    };
    let default = if stored > 0 {
        stored
    } else {
        clamp_spin_window_us(tick_us, 100)
    };
    (current, default)
}

pub fn spin_window_from_config(cfg: &crate::config::NetworkConfig, tick_us: u64) -> u64 {
    let mode = cfg.pace_clock_mode.trim().to_ascii_lowercase();
    let raw = cfg.pace_spin_window_us.max(0) as u64;
    if mode == "spin" {
        clamp_spin_window_us(tick_us, raw)
    } else if mode == "hr" {
        0
    } else {
        clamp_spin_window_us(tick_us, raw)
    }
}

impl Default for PaceClockApply {
    fn default() -> Self {
        Self {
            spin_window_us: 100,
            fab_enabled: true,
            fab_fallback_us: 750,
        }
    }
}

pub struct PaceClockShared {
    pub tick_us: AtomicU64,
    pub spin_window_us: AtomicU64,
    pub fab_enabled: AtomicBool,
    pub fab_fallback_us: AtomicU64,
    /// APD: engine thread sets true to request pure spinloop from clock thread.
    pub apd_pure_spin: AtomicBool,
    /// APD: override tick interval (µs) during drain; 0 = use base tick_us.
    pub apd_tick_us: AtomicU64,
}

impl PaceClockShared {
    pub fn new(apply: PaceClockApply, initial_tick_us: u64) -> Self {
        Self {
            tick_us: AtomicU64::new(initial_tick_us),
            spin_window_us: AtomicU64::new(apply.spin_window_us),
            fab_enabled: AtomicBool::new(apply.fab_enabled),
            fab_fallback_us: AtomicU64::new(apply.fab_fallback_us),
            apd_pure_spin: AtomicBool::new(false),
            apd_tick_us: AtomicU64::new(0),
        }
    }

    pub fn load_apply(&self) -> PaceClockApply {
        PaceClockApply {
            spin_window_us: self.spin_window_us.load(Ordering::Relaxed),
            fab_enabled: self.fab_enabled.load(Ordering::Relaxed),
            fab_fallback_us: self.fab_fallback_us.load(Ordering::Relaxed),
        }
    }

    pub fn store_apply(&self, a: PaceClockApply) {
        self.spin_window_us
            .store(a.spin_window_us, Ordering::Release);
        self.fab_enabled.store(a.fab_enabled, Ordering::Release);
        self.fab_fallback_us
            .store(a.fab_fallback_us, Ordering::Release);
    }
}

#[inline]
pub fn clamp_tick_us(tick: u64) -> u64 {
    tick.max(MIN_PACE_TICK_US).min(1_000_000)
}

#[inline]
pub fn clamp_spin_window_us(tick_us: u64, spin: u64) -> u64 {
    let t = tick_us.max(MIN_PACE_TICK_US);
    spin.min(t)
}

pub fn start_pace_clock_thread(
    pacing_tick_tx: mpsc::Sender<()>,
    shared: Arc<PaceClockShared>,
    stop: Arc<AtomicBool>,
    tick_skips: Arc<AtomicU64>,
    overshoots: Arc<AtomicU64>,
    adaptive_fallbacks: Arc<AtomicU64>,
) -> Option<JoinHandle<()>> {
    thread::Builder::new()
        .name("mint-pacing-clock".to_string())
        .spawn(move || {
            pace_clock_main_loop(
                pacing_tick_tx,
                shared,
                stop,
                tick_skips,
                overshoots,
                adaptive_fallbacks,
            );
        })
        .ok()
}

fn pace_clock_main_loop(
    pacing_tick_tx: mpsc::Sender<()>,
    shared: Arc<PaceClockShared>,
    stop: Arc<AtomicBool>,
    tick_skips: Arc<AtomicU64>,
    overshoots: Arc<AtomicU64>,
    adaptive_fallbacks: Arc<AtomicU64>,
) {
    #[cfg(windows)]
    let mut hr_timer = HrWaitTimer::create();
    #[cfg(not(windows))]
    let mut hr_timer = ();

    let mut next_deadline = Instant::now();
    let mut overshoot_streak = 0u32;

    while !stop.load(Ordering::Acquire) {
        let base_tick_us = shared.tick_us.load(Ordering::Relaxed).max(MIN_PACE_TICK_US);

        // APD: when engine requests pure spinloop, bypass HR Timer and FAB entirely.
        let apd_spin = shared.apd_pure_spin.load(Ordering::Acquire);
        if apd_spin {
            let apd_tick = shared.apd_tick_us.load(Ordering::Relaxed);
            let effective_tick = if apd_tick > 0 { apd_tick } else { base_tick_us };
            next_deadline += Duration::from_micros(effective_tick);
            // Reset overshoot streak so FAB does not activate when APD exits.
            overshoot_streak = 0;
            if spin_until(next_deadline, &stop) {
                break;
            }
        } else {
            let fab_on = shared.fab_enabled.load(Ordering::Relaxed);
            let fab_us = shared.fab_fallback_us.load(Ordering::Relaxed).max(1);

            let mut tick = Duration::from_micros(base_tick_us);
            if fab_on && overshoot_streak >= PACE_CLOCK_ADAPTIVE_THRESHOLD {
                overshoot_streak = 0;
                tick = Duration::from_micros(fab_us);
                adaptive_fallbacks.fetch_add(1, Ordering::Relaxed);
            }

            next_deadline += tick;
            let now = Instant::now();

            let spin_window_us =
                clamp_spin_window_us(base_tick_us, shared.spin_window_us.load(Ordering::Relaxed));
            let spin_window = Duration::from_micros(spin_window_us);

            if next_deadline <= now {
                let overshoot = now.duration_since(next_deadline);
                if overshoot > spin_window {
                    overshoot_streak = overshoot_streak.saturating_add(1);
                    overshoots.fetch_add(1, Ordering::Relaxed);
                } else {
                    overshoot_streak = overshoot_streak.saturating_sub(1);
                }
            } else {
                if wait_until_deadline(next_deadline, spin_window, &mut hr_timer, &stop) {
                    break;
                }
                overshoot_streak = overshoot_streak.saturating_sub(1);
            }
        }

        match pacing_tick_tx.try_send(()) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tick_skips.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => break,
        }
    }
}

#[cfg(windows)]
fn wait_until_deadline(
    deadline: Instant,
    spin_window: Duration,
    hr_timer: &mut Option<HrWaitTimer>,
    stop: &AtomicBool,
) -> bool {
    let now = Instant::now();
    if now >= deadline {
        return stop.load(Ordering::Acquire);
    }
    let remaining = deadline.saturating_duration_since(now);

    if spin_window.is_zero() {
        return wait_coarse_until(deadline, hr_timer, stop);
    }
    if spin_window >= remaining {
        return spin_until(deadline, stop);
    }
    let hr_deadline = deadline - spin_window;
    if wait_coarse_until(hr_deadline, hr_timer, stop) {
        return true;
    }
    spin_until(deadline, stop)
}

#[cfg(not(windows))]
fn wait_until_deadline(
    deadline: Instant,
    spin_window: Duration,
    _hr_timer: &mut (),
    stop: &AtomicBool,
) -> bool {
    let now = Instant::now();
    if now >= deadline {
        return stop.load(Ordering::Acquire);
    }
    let remaining = deadline.saturating_duration_since(now);

    if spin_window.is_zero() {
        return sleep_until(deadline, stop);
    }
    if spin_window >= remaining {
        return spin_until(deadline, stop);
    }
    let coarse_deadline = deadline - spin_window;
    if sleep_until(coarse_deadline, stop) {
        return true;
    }
    spin_until(deadline, stop)
}

#[cfg(windows)]
fn wait_coarse_until(
    deadline: Instant,
    hr_timer: &mut Option<HrWaitTimer>,
    stop: &AtomicBool,
) -> bool {
    if let Some(t) = hr_timer {
        if t.wait_until(deadline, stop) {
            return true;
        }
        return stop.load(Ordering::Acquire);
    }
    sleep_until(deadline, stop)
}

#[cfg(not(windows))]
fn wait_coarse_until(deadline: Instant, _hr_timer: &mut (), stop: &AtomicBool) -> bool {
    sleep_until(deadline, stop)
}

fn sleep_until(deadline: Instant, stop: &AtomicBool) -> bool {
    loop {
        if stop.load(Ordering::Acquire) {
            return true;
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        let rem = deadline.saturating_duration_since(now);
        thread::sleep(rem.min(Duration::from_millis(50)));
    }
}

fn spin_until(deadline: Instant, stop: &AtomicBool) -> bool {
    while Instant::now() < deadline {
        if stop.load(Ordering::Acquire) {
            return true;
        }
        std::hint::spin_loop();
    }
    stop.load(Ordering::Acquire)
}

#[cfg(windows)]
mod hr_win {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Instant;

    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Threading::{
        CreateWaitableTimerExW, SetWaitableTimer, WaitForSingleObjectEx,
        CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS,
    };

    pub struct HrWaitTimer {
        h: HANDLE,
    }

    impl HrWaitTimer {
        pub fn create() -> Option<Self> {
            unsafe {
                let h = CreateWaitableTimerExW(
                    None,
                    None,
                    CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                    TIMER_ALL_ACCESS.0,
                )
                .ok()?;
                Some(Self { h })
            }
        }

        pub fn wait_until(&mut self, deadline: Instant, stop: &AtomicBool) -> bool {
            loop {
                if stop.load(Ordering::Acquire) {
                    return true;
                }
                let now = Instant::now();
                if now >= deadline {
                    return false;
                }
                let rem = deadline.saturating_duration_since(now);
                let slice = rem.min(std::time::Duration::from_millis(50));
                let wait_ms = slice.as_millis().clamp(1, u32::MAX as u128) as u32;
                let ns = rem.as_nanos().min(60_000_000_000_000) as u128;
                let ticks100ns = ((ns + 99) / 100).max(1) as i64;
                let due = ticks100ns.saturating_neg();
                unsafe {
                    if SetWaitableTimer(self.h, &due, 0, None, None, false).is_err() {
                        thread::sleep(slice);
                        continue;
                    }
                    let _ = WaitForSingleObjectEx(self.h, wait_ms, false);
                }
            }
        }
    }

    impl Drop for HrWaitTimer {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.h);
            }
        }
    }
}

#[cfg(windows)]
use hr_win::HrWaitTimer;

#[cfg(not(windows))]
type HrWaitTimer = ();

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetworkConfig;

    #[test]
    fn clamp_tick_us_floor_and_cap() {
        assert_eq!(clamp_tick_us(0), 1);
        assert_eq!(clamp_tick_us(1), 1);
        assert_eq!(clamp_tick_us(2_000_000), 1_000_000);
    }

    #[test]
    fn clamp_spin_window_allows_zero() {
        assert_eq!(clamp_spin_window_us(500, 0), 0);
        assert_eq!(clamp_spin_window_us(500, 600), 500);
        assert_eq!(clamp_spin_window_us(10, 40), 10);
    }

    #[test]
    fn hr_mode_ignores_stored_spin_window() {
        let mut cfg = NetworkConfig::default();
        cfg.pace_clock_mode = "hr".into();
        cfg.pace_spin_window_us = 40;
        cfg.pace_tick_us = 500;
        assert_eq!(spin_window_from_config(&cfg, 500), 0);
    }

    #[test]
    fn spin_mode_keeps_spin_window() {
        let mut cfg = NetworkConfig::default();
        cfg.pace_clock_mode = "spin".into();
        cfg.pace_spin_window_us = 40;
        cfg.pace_tick_us = 500;
        assert_eq!(spin_window_from_config(&cfg, 500), 40);
    }

    #[test]
    fn empty_mode_uses_stored_spin_window() {
        let mut cfg = NetworkConfig::default();
        cfg.pace_clock_mode.clear();
        cfg.pace_spin_window_us = 40;
        cfg.pace_tick_us = 500;
        assert_eq!(spin_window_from_config(&cfg, 500), 40);
    }

    #[test]
    fn default_network_config_applies_spin_window_50() {
        let cfg = NetworkConfig::default();
        assert_eq!(cfg.pace_spin_window_us, 50);
        assert_eq!(cfg.pace_clock_mode, "hybrid");
        assert_eq!(spin_window_from_config(&cfg, 250), 50);
    }

    #[test]
    fn pace_spin_prompt_surfaces_stored_value_in_hr_mode() {
        let mut cfg = NetworkConfig::default();
        cfg.pace_clock_mode = "hr".into();
        cfg.pace_spin_window_us = 100;
        cfg.pace_tick_us = 500;
        assert_eq!(spin_window_from_config(&cfg, 500), 0);
        let (cur, def) = pace_spin_prompt_values(&cfg, 500);
        assert_eq!(cur, 100);
        assert_eq!(def, 100);
    }
}
