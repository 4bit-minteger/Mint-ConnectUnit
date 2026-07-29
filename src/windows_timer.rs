#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(windows)]
use anyhow::{anyhow, Result};

#[cfg(windows)]
const TIMER_REQUEST_500US_100NS: u32 = 5_000;
#[cfg(windows)]
const TIMER_REQUEST_1MS_100NS: u32 = 10_000;

#[cfg(windows)]
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtSetTimerResolution(
        desired_resolution: u32,
        set_resolution: i32,
        current_resolution: *mut u32,
    ) -> i32;
    fn NtQueryTimerResolution(
        minimum_resolution: *mut u32,
        maximum_resolution: *mut u32,
        current_resolution: *mut u32,
    ) -> i32;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TimerResolutionStatus {
    pub requested_us: u64,
    pub applied_us: u64,
    pub fallback_count: u64,
}

#[derive(Debug)]
pub struct LowLatencyTimerGuard {
    active: bool,
}

impl LowLatencyTimerGuard {
    #[inline]
    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn request() -> (Self, TimerResolutionStatus) {
        #[cfg(windows)]
        {
            let mut fallback_count = 0u64;
            match request_once(TIMER_REQUEST_500US_100NS) {
                Ok(applied_100ns) => {
                    return (
                        Self { active: true },
                        TimerResolutionStatus {
                            requested_us: 500,
                            applied_us: (applied_100ns / 10) as u64,
                            fallback_count,
                        },
                    );
                }
                Err(_) => {
                    fallback_count = 1;
                }
            }

            match request_once(TIMER_REQUEST_1MS_100NS) {
                Ok(applied_100ns) => (
                    Self { active: true },
                    TimerResolutionStatus {
                        requested_us: 1_000,
                        applied_us: (applied_100ns / 10) as u64,
                        fallback_count,
                    },
                ),
                Err(_) => (
                    Self { active: false },
                    TimerResolutionStatus {
                        requested_us: 1_000,
                        applied_us: 0,
                        fallback_count,
                    },
                ),
            }
        }
        #[cfg(not(windows))]
        {
            (Self { active: false }, TimerResolutionStatus::default())
        }
    }
}

#[cfg(windows)]
static TIMER_ACTIVE: AtomicBool = AtomicBool::new(false);

#[cfg(windows)]
fn request_once(target_100ns: u32) -> Result<u32> {
    let mut min = 0u32;
    let mut max = 0u32;
    let mut current = 0u32;
    let status = unsafe { NtQueryTimerResolution(&mut min, &mut max, &mut current) };
    if status < 0 {
        return Err(anyhow!(
            "NtQueryTimerResolution failed with status {status:#x}"
        ));
    }
    let desired = target_100ns.clamp(max, min);
    let mut applied = 0u32;
    let set_status = unsafe { NtSetTimerResolution(desired, 1, &mut applied) };
    if set_status < 0 {
        return Err(anyhow!(
            "NtSetTimerResolution failed with status {set_status:#x}"
        ));
    }
    TIMER_ACTIVE.store(true, Ordering::Release);
    Ok(applied)
}

#[cfg(windows)]
fn release() {
    if !TIMER_ACTIVE.swap(false, Ordering::AcqRel) {
        return;
    }
    let mut current = 0u32;
    let _ = unsafe { NtSetTimerResolution(0, 0, &mut current) };
}

impl Drop for LowLatencyTimerGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        if self.active {
            release();
            self.active = false;
        }
    }
}
