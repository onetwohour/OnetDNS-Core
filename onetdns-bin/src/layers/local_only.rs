/*!
 * @brief domain_needed, bogus_priv, empty_zones 이름을 업스트림으로 보내지 않는 계층.
 */

use std::sync::Arc;

use onetdns_proto::{Message, Name, RecordType};

use super::outcome_to_option;
use crate::native::{ResolveOutcome, Resolver};

/** @brief domain_needed가 막는 범주. */
pub const LOCAL_ONLY_DOMAIN_NEEDED: u8 = 1;
/** @brief bogus_priv가 막는 범주. */
pub const LOCAL_ONLY_BOGUS_PRIV: u8 = 2;
/** @brief empty_zones가 막는 범주. */
pub const LOCAL_ONLY_EMPTY_ZONES: u8 = 4;

/**
 * @brief 밖으로 내보내면 안 되는 이름의 범주를 담아 두는 곳.
 * @details 세 설정은 실행 중에 바뀔 수 있으므로 계층이 값을 복사해 두면 안 된다. 한 번의
 *          Relaxed 로드로 세 범주를 모두 읽도록 비트로 담는다.
 */
pub struct LocalOnlyNames {
    /** @brief 켜진 범주의 비트합. */
    bits: std::sync::atomic::AtomicU8,
}

impl LocalOnlyNames {
    /** @brief 세 설정에서 비트합을 만든다. */
    pub fn new(domain_needed: bool, bogus_priv: bool, empty_zones: bool) -> Self {
        let value = Self {
            bits: std::sync::atomic::AtomicU8::new(0),
        };
        value.set(domain_needed, bogus_priv, empty_zones);
        value
    }

    /** @brief 켜진 범주를 교체한다. */
    pub fn set(&self, domain_needed: bool, bogus_priv: bool, empty_zones: bool) {
        let mut bits = 0u8;
        if domain_needed {
            bits |= LOCAL_ONLY_DOMAIN_NEEDED;
        }
        if bogus_priv {
            bits |= LOCAL_ONLY_BOGUS_PRIV;
        }
        if empty_zones {
            bits |= LOCAL_ONLY_EMPTY_ZONES;
        }
        self.bits.store(bits, std::sync::atomic::Ordering::Relaxed);
    }

    /** @brief 지금 켜진 범주. */
    fn bits(&self) -> u8 {
        self.bits.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/**
 * @brief 밖에 물어보면 안 되는 이름을 업스트림 질의 직전에 끊는 계층.
 *
 * @details domain_needed, bogus_priv, empty_zones가 막으려는 것은 이 이름들이 업스트림 DNS
 *          서버로 새 나가는 것이다. 로컬 권한 영역, DHCP 임대, 스텁 위임, 로컬 주소가
 *          답할 수 있으면 그 답이 먼저 나가야 하므로 이 계층은 그것들보다 안쪽, 상위
 *          질의 바로 앞에 놓인다.
 * @warning 바깥으로 옮기면 자기 설정으로 만든 home.arpa 영역이나 사설 대역 역방향
 *          영역을 자기가 NXDOMAIN으로 덮는다.
 */
pub struct LocalOnlyLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 막을 범주. */
    names: Arc<LocalOnlyNames>,
    /** @brief 막은 답의 수명. */
    block_ttl: Arc<std::sync::atomic::AtomicU32>,
}

impl LocalOnlyLayer {
    /** @brief 로컬 전용 이름 목록을 가진 계층을 만든다. */
    pub fn new(
        inner: Arc<dyn Resolver>,
        names: Arc<LocalOnlyNames>,
        block_ttl: Arc<std::sync::atomic::AtomicU32>,
    ) -> Self {
        LocalOnlyLayer {
            inner,
            names,
            block_ttl,
        }
    }

    /** @brief 이 이름을 밖에 물어보면 안 되는지. */
    fn blocked(&self, name: &Name, qtype: RecordType) -> bool {
        let bits = self.names.bits();
        if bits == 0 {
            return false;
        }
        (bits & LOCAL_ONLY_DOMAIN_NEEDED != 0 && crate::native::is_single_label(name))
            || (bits & LOCAL_ONLY_BOGUS_PRIV != 0
                && qtype == RecordType::PTR
                && crate::native::is_private_reverse(name))
            || (bits & LOCAL_ONLY_EMPTY_ZONES != 0 && crate::native::is_empty_zone(name))
    }
}

impl Resolver for LocalOnlyLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 밖에 물어보면 안 되는 이름이면 NXDOMAIN으로 끊고, 아니면 안으로 넘긴다. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        if let Some(q) = req.questions.first() {
            if self.blocked(&q.name, q.qtype) {
                let ttl = self.block_ttl.load(std::sync::atomic::Ordering::Acquire);
                return ResolveOutcome::Response(crate::native::local_only_negative_response(
                    req, &q.name, ttl,
                ));
            }
        }
        self.inner.resolve_outcome(req)
    }
}
