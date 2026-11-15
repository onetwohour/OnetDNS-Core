//! Per-request fault isolation, and the reason the release profile uses panic = "unwind": a panic
//! triggered by outside input would otherwise kill the worker thread and every connection it
//! serves. This boundary confines it to one request.
//!
//! Unwinding does not contain OOM, explicit abort, FFI memory corruption, or OS termination;
//! request handling must still not unwrap() or expect() values that come from a request.

use std::cell::Cell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;

thread_local! {
    /// Nesting depth of request boundaries on this thread; 0 is outside.
    static REQUEST_DEPTH: Cell<u32> = const { Cell::new(0) };
}

static INSTALL_HOOK: Once = Once::new();

/// Exported as onetdns_request_panics_total on /metrics.
static REQUEST_PANICS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestPanicked;

struct Boundary;

impl Boundary {
    /// Drop restores the depth, during unwinding too.
    fn enter() -> Self {
        REQUEST_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
        Self
    }
}

impl Drop for Boundary {
    /// Left raised, the next query would look already inside a boundary.
    fn drop(&mut self) {
        REQUEST_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

/// Silences the default panic output inside request boundaries: a backtrace per contained panic
/// would let an attacker flood the logs. Panics outside a boundary are real defects and go to the
/// original hook. Installs once however often it is called.
pub fn install_request_panic_hook() {
    INSTALL_HOOK.call_once(|| {
        let original = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !panic_is_contained() {
                original(info);
            }
        }));
    });
}

/// True on a thread inside a request boundary, where `catch_request` reports the panic.
pub fn panic_is_contained() -> bool {
    REQUEST_DEPTH.with(|depth| depth.get() != 0)
}

/// Runs a request handler and contains its panic. The unit differs by transport: a packet or task
/// for UDP, DNSCrypt, DoQ, and DoH3; a connection for TCP, DoT, and DoH; QUIC drops the connection
/// state but keeps the listener.
///
/// Logs only on power-of-two occurrences, so input that can trigger a panic cannot turn the log
/// into a resource drain.
pub fn catch_request<T>(f: impl FnOnce() -> T) -> Result<T, RequestPanicked> {
    let _boundary = Boundary::enter();
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => Ok(value),
        Err(_) => {
            let count = REQUEST_PANICS.fetch_add(1, Ordering::Relaxed) + 1;
            if count.is_power_of_two() {
                crate::error!(
                    event = "request.panic_isolated",
                    count,
                    "Contained an unexpected error while handling a query; the worker thread keeps running"
                );
            }
            Err(RequestPanicked)
        }
    }
}

pub fn request_panic_count() -> u64 {
    REQUEST_PANICS.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_panic_and_runs_next_request() {
        assert_eq!(catch_request(|| 7), Ok(7));
        assert_eq!(
            catch_request(|| panic!("malicious request")),
            Err(RequestPanicked)
        );
        assert_eq!(catch_request(|| 9), Ok(9));
    }

    #[test]
    fn nested_boundaries_restore_depth_after_unwind() {
        let result = catch_request(|| catch_request(|| panic!("nested")));
        assert_eq!(result, Ok(Err(RequestPanicked)));
        assert_eq!(catch_request(|| 11), Ok(11));
    }
}
