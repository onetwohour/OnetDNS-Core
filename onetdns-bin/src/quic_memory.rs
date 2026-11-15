//! Connection memory budget shared by every DoQ and DoH3 listener. With only a per-connection cap,
//! an attacker multiplies it by the connection count. All QUIC listeners share one atomic counter,
//! and a connection returns its charge when it goes.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

pub(crate) const QUIC_MEMORY_BUDGET: usize = 64 * 1024 * 1024;

/// Cost outside payload accounting: connection state, map buckets, crypto state. It also makes the
/// budget a cap on connections across all listeners.
pub(crate) const QUIC_CONNECTION_BASE_CHARGE: usize = 32 * 1024;

pub(crate) struct QuicMemoryBudget {
    used: AtomicUsize,
    limit: usize,
}

pub(crate) struct QuicRunControl {
    /// Server-wide shutdown.
    shutdown: Arc<AtomicBool>,
    /// This listener only.
    stop: Arc<AtomicBool>,
    memory_budget: Arc<QuicMemoryBudget>,
}

impl QuicRunControl {
    pub(crate) fn new(
        shutdown: Arc<AtomicBool>,
        stop: Arc<AtomicBool>,
        memory_budget: Arc<QuicMemoryBudget>,
    ) -> Self {
        Self {
            shutdown,
            stop,
            memory_budget,
        }
    }

    pub(crate) fn should_stop(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed) || self.stop.load(Ordering::Relaxed)
    }

    pub(crate) fn memory_budget(&self) -> &Arc<QuicMemoryBudget> {
        &self.memory_budget
    }
}

impl Default for QuicMemoryBudget {
    fn default() -> Self {
        Self::new(QUIC_MEMORY_BUDGET)
    }
}

impl QuicMemoryBudget {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            used: AtomicUsize::new(0),
            limit,
        }
    }

    fn try_reserve(&self, bytes: usize) -> bool {
        self.used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.limit)
            })
            .is_ok()
    }

    fn release(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let released = self
            .used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_sub(bytes)
            })
            .is_ok();
        debug_assert!(released, "QUIC memory charge must never go negative");
    }

    pub(crate) fn used_bytes(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    pub(crate) fn limit_bytes(&self) -> usize {
        self.limit
    }
}

/// One connection's charge; Drop returns it on every removal path.
pub(crate) struct QuicMemoryLease {
    budget: Arc<QuicMemoryBudget>,
    charged: usize,
}

impl QuicMemoryLease {
    /// None when the base charge does not fit; the connection is then refused.
    pub(crate) fn try_new(budget: Arc<QuicMemoryBudget>) -> Option<Self> {
        if budget.try_reserve(QUIC_CONNECTION_BASE_CHARGE) {
            Some(Self {
                budget,
                charged: QUIC_CONNECTION_BASE_CHARGE,
            })
        } else {
            None
        }
    }

    /// Grows or shrinks the charge to match the payload held.
    ///
    /// False when growth does not fit; the existing charge stays and Drop returns it.
    pub(crate) fn refresh(&mut self, payload_bytes: usize) -> bool {
        let target = QUIC_CONNECTION_BASE_CHARGE.saturating_add(payload_bytes);
        if target == self.charged {
            return true;
        }
        if target > self.charged {
            let additional = target - self.charged;
            if !self.budget.try_reserve(additional) {
                return false;
            }
        } else {
            self.budget.release(self.charged - target);
        }
        self.charged = target;
        true
    }
}

impl Drop for QuicMemoryLease {
    fn drop(&mut self) {
        self.budget.release(self.charged);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leases_share_one_hard_limit_and_release_exactly_once() {
        let budget = Arc::new(QuicMemoryBudget::new(QUIC_CONNECTION_BASE_CHARGE * 2 + 10));
        let mut first = QuicMemoryLease::try_new(budget.clone()).unwrap();
        let mut second = QuicMemoryLease::try_new(budget.clone()).unwrap();
        assert!(QuicMemoryLease::try_new(budget.clone()).is_none());
        assert!(first.refresh(10));
        assert_eq!(budget.used_bytes(), budget.limit_bytes());

        assert!(!second.refresh(1));
        assert_eq!(budget.used_bytes(), budget.limit_bytes());
        assert!(!second.refresh(usize::MAX));
        assert_eq!(budget.used_bytes(), budget.limit_bytes());

        drop(first);
        assert_eq!(budget.used_bytes(), QUIC_CONNECTION_BASE_CHARGE);
        assert!(second.refresh(1));
        drop(second);
        assert_eq!(budget.used_bytes(), 0);
    }

    #[test]
    fn base_charge_covers_inline_quic_state_with_metadata_headroom() {
        let connection = std::mem::size_of::<onetdns_quic::Connection>();
        let h3 = std::mem::size_of::<onetdns_quic::H3Connection>();
        let largest = connection.max(h3);
        assert!(
            largest <= QUIC_CONNECTION_BASE_CHARGE / 2,
            "inline state {largest}B leaves too little room in the base charge"
        );
    }
}
