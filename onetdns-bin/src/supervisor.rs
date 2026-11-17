//! Process supervisor. The parent loads no filters or caches, so it survives a child that runs
//! out of memory or is killed, and restarts it. It gives up when startup keeps failing.

#[cfg(any(test, target_os = "linux", windows))]
use std::time::Duration;

#[cfg(any(test, target_os = "linux", windows))]
const BASE_RESTART_DELAY: Duration = Duration::from_millis(10);
#[cfg(any(test, target_os = "linux", windows))]
const MAX_RESTART_DELAY: Duration = Duration::from_secs(5);
#[cfg(any(test, target_os = "linux", windows))]
/// Running this long resets the restart delay.
const STABLE_RUNTIME: Duration = Duration::from_secs(30);
#[cfg(any(test, target_os = "linux", windows))]
const MAX_STARTUP_FAILURES: u32 = 5;

#[cfg(any(test, target_os = "linux", windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestartDecision {
    RestartAfter(Duration),
    GiveUp,
}

#[cfg(any(test, target_os = "linux", windows))]
#[derive(Default)]
struct RestartPolicy {
    crash_streak: u32,
    startup_failures: u32,
}

#[cfg(any(test, target_os = "linux", windows))]
impl RestartPolicy {
    /// Reaching ready clears the failure count, or occasional crashes of a long-running server
    /// would add up to giving up.
    fn child_exited(&mut self, ready: bool, runtime: Duration) -> RestartDecision {
        if !ready {
            self.startup_failures = self.startup_failures.saturating_add(1);
            if self.startup_failures >= MAX_STARTUP_FAILURES {
                return RestartDecision::GiveUp;
            }
        } else {
            self.startup_failures = 0;
        }

        if runtime >= STABLE_RUNTIME {
            self.crash_streak = 0;
        }
        let shift = self.crash_streak.min(9);
        self.crash_streak = self.crash_streak.saturating_add(1);
        let delay = BASE_RESTART_DELAY
            .saturating_mul(1u32 << shift)
            .min(MAX_RESTART_DELAY);
        RestartDecision::RestartAfter(delay)
    }
}

/// How this process runs under the supervisor that started it.
#[derive(Default)]
pub struct Joined {
    /// Tells the supervisor this process is ready. None without a supervisor.
    pub ready: Option<Box<dyn FnOnce() + Send>>,
    /// Set for a successor: waits until the process it takes over from lets go of the terminal.
    pub console: Option<crate::tui::Wait>,
}

#[cfg(any(target_os = "linux", windows))]
mod channel;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "linux", windows))]
mod supervise;
#[cfg(windows)]
mod windows;
#[cfg(any(target_os = "linux", windows))]
mod worker;
#[cfg(target_os = "linux")]
use linux as sys;
#[cfg(windows)]
use windows as sys;

#[cfg(any(target_os = "linux", windows))]
pub use supervise::run;
#[cfg(any(target_os = "linux", windows))]
pub use worker::{handing_over, join, settle};
#[cfg(any(target_os = "linux", windows))]
pub(crate) use worker::{request_successor, Requested};

#[cfg(not(any(target_os = "linux", windows)))]
pub fn join(_links: &std::sync::Arc<crate::handoff::Links>) -> crate::error::BoxResult<Joined> {
    Ok(Joined::default())
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn settle(handed: bool, _abort: &dyn Fn() -> bool) -> bool {
    handed
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn handing_over() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_failures_are_bounded() {
        let mut policy = RestartPolicy::default();
        for expected_ms in [10, 20, 40, 80] {
            assert_eq!(
                policy.child_exited(false, Duration::from_millis(1)),
                RestartDecision::RestartAfter(Duration::from_millis(expected_ms))
            );
        }
        assert_eq!(
            policy.child_exited(false, Duration::from_millis(1)),
            RestartDecision::GiveUp
        );
    }

    #[test]
    fn ready_child_resets_startup_failures_and_backoff_is_capped() {
        let mut policy = RestartPolicy::default();
        for _ in 0..3 {
            let _ = policy.child_exited(false, Duration::from_millis(1));
        }
        let _ = policy.child_exited(true, Duration::from_secs(1));
        for _ in 0..20 {
            assert_ne!(
                policy.child_exited(true, Duration::from_secs(1)),
                RestartDecision::GiveUp
            );
        }
        assert_eq!(
            policy.child_exited(true, Duration::from_secs(1)),
            RestartDecision::RestartAfter(MAX_RESTART_DELAY)
        );
    }

    #[test]
    fn stable_runtime_resets_restart_delay() {
        let mut policy = RestartPolicy::default();
        let _ = policy.child_exited(true, Duration::from_secs(1));
        let _ = policy.child_exited(true, Duration::from_secs(1));
        assert_eq!(
            policy.child_exited(true, STABLE_RUNTIME),
            RestartDecision::RestartAfter(BASE_RESTART_DELAY)
        );
    }
}
