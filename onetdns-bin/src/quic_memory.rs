/*!
 * @brief DoQ·DoH3가 공유하는 전역 연결 메모리 예산.
 *
 * @details 연결별 상한만 두면 공격자가 연결 수만큼 그 상한을 곱할 수 있다. 모든 QUIC
 *          수신 주소가 이 원자 계수 하나를 공유하고, 연결이 사라지면 charge도 함께 돌려준다.
 */

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

/** @brief 모든 수신 DoQ·DoH3 연결이 함께 쓸 수 있는 보유량. */
pub(crate) const QUIC_MEMORY_BUDGET: usize = 64 * 1024 * 1024;

/**
 * @brief 연결 구조·map bucket·암호 상태처럼 payload 계수 밖의 비용.
 * @details 64 MiB 예산에서 기존 단일 리스너의 2,048 연결 상한도 동시에 전역 상한이 된다.
 */
pub(crate) const QUIC_CONNECTION_BASE_CHARGE: usize = 32 * 1024;

/** @brief 모든 QUIC 수신 스레드가 공유하는 원자 예산. */
pub(crate) struct QuicMemoryBudget {
    /** @brief 지금 빌려준 바이트. */
    used: AtomicUsize,
    /** @brief 빌려줄 수 있는 최대 바이트. */
    limit: usize,
}

/** @brief QUIC 수신 반복이 함께 유지하는 종료 신호와 공유 예산. */
pub(crate) struct QuicRunControl {
    /** @brief 서비스 전체를 끝내라는 표시. */
    shutdown: Arc<AtomicBool>,
    /** @brief 이 리스너만 끝내라는 표시. */
    stop: Arc<AtomicBool>,
    /** @brief 모든 DoQ·DoH3 리스너가 공유하는 예산. */
    memory_budget: Arc<QuicMemoryBudget>,
}

impl QuicRunControl {
    /** @brief 세 수명 핸들을 하나로 묶는다. */
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

    /** @brief 서비스나 리스너 어느 한쪽이라도 종료를 요청했는지. */
    pub(crate) fn should_stop(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed) || self.stop.load(Ordering::Relaxed)
    }

    /** @brief 새 연결과 진단이 쓸 공유 예산. */
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
    /** @brief 지정한 상한으로 만든다. 작은 상한은 결정적 회귀 테스트에도 쓴다. */
    fn new(limit: usize) -> Self {
        Self {
            used: AtomicUsize::new(0),
            limit,
        }
    }

    /** @brief 추가 charge를 원자적으로 확보한다. */
    fn try_reserve(&self, bytes: usize) -> bool {
        self.used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.limit)
            })
            .is_ok()
    }

    /** @brief 더는 보유하지 않는 charge를 돌려준다. */
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

    /** @brief 지금 빌려준 바이트. 진단과 테스트에 쓴다. */
    pub(crate) fn used_bytes(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    /** @brief 전체 상한. */
    pub(crate) fn limit_bytes(&self) -> usize {
        self.limit
    }
}

/** @brief 연결 하나가 빌린 charge. Drop이 어떤 제거 경로에서도 정확히 반환한다. */
pub(crate) struct QuicMemoryLease {
    /** @brief 공유 예산. */
    budget: Arc<QuicMemoryBudget>,
    /** @brief 이 연결 이름으로 빌린 양. */
    charged: usize,
}

impl QuicMemoryLease {
    /** @brief 연결의 고정 charge부터 확보한다. 모자라면 연결을 만들지 않는다. */
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

    /**
     * @brief 현재 payload 보유량에 맞춰 charge를 증감한다.
     * @return 늘릴 예산이 없으면 false. 기존 charge는 그대로라 이어지는 Drop이 반환한다.
     */
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
    /** @brief 거절된 증액은 계수를 흐리지 않고 모든 Drop이 charge를 돌려주는지. */
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
    /** @brief 기본 charge가 두 서버 상태 기계의 inline 크기에 충분한 여유를 두는지. */
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
