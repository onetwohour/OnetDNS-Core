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

#[cfg(test)]
/** @brief 범주를 바꾸며 캐시를 비울 때 이미 나간 질의가 그 결과를 되돌리지 않는지. */
mod tests {
    use super::*;
    use crate::layers::test_support::query;
    use onetdns_proto::{RData, Record, ResponseCode};
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::{mpsc, Mutex};

    /** @brief 첫 질의를 붙잡아 두었다가 놓아 주면 업스트림의 PTR 답을 내는 리졸버. */
    struct HeldUpstream {
        /** @brief 첫 질의가 들어왔음을 알릴 곳. 한 번 알리면 비운다. */
        entered: Mutex<Option<mpsc::Sender<()>>>,
        /** @brief 붙잡은 질의를 놓아 줄 신호. */
        release: Mutex<mpsc::Receiver<()>>,
        /** @brief 불린 횟수. */
        calls: AtomicUsize,
    }

    impl Resolver for HeldUpstream {
        /** @brief 첫 질의는 신호가 올 때까지 붙잡고, 모든 질의에 같은 PTR 답을 낸다. */
        fn resolve(&self, req: &Message) -> Option<Message> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let entered = self.entered.lock().unwrap().take();
            if let Some(entered) = entered {
                entered.send(()).unwrap();
                self.release.lock().unwrap().recv().unwrap();
            }
            let q = req.questions.first()?;
            let mut response =
                crate::layers::answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
            response.answers.push(Record::new(
                q.name.clone(),
                300,
                RData::Ptr(Name::from_str("printer.lan").unwrap()),
            ));
            Some(response)
        }
    }

    #[test]
    /**
     * @brief bogus_priv를 켜며 캐시를 비운 뒤, 그 전에 나간 질의의 업스트림 답이 캐시에 다시
     *        들어가지 않는지.
     * @details 들어가면 사설 대역 역방향 질의가 그 답의 수명 동안 업스트림 답을 받는다. 범주를
     *          켜면서 캐시를 비운 뜻이 사라진다.
     */
    fn a_local_only_flush_is_not_undone_by_an_in_flight_answer() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let upstream = Arc::new(HeldUpstream {
            entered: Mutex::new(Some(entered_tx)),
            release: Mutex::new(release_rx),
            calls: AtomicUsize::new(0),
        });
        let names = Arc::new(LocalOnlyNames::new(false, false, false));
        let cache = crate::cache::CacheLayer::new(
            Arc::new(LocalOnlyLayer::new(
                upstream.clone(),
                names.clone(),
                Arc::new(AtomicU32::new(10)),
            )),
            64,
            1,
            0,
            86_400,
            0,
            86_400,
        );
        let handle = cache.handle();
        let chain: Arc<dyn Resolver> = Arc::new(cache);
        let request = query("1.0.168.192.in-addr.arpa", RecordType::PTR);
        let in_flight = {
            let chain = chain.clone();
            let request = request.clone();
            std::thread::spawn(move || chain.resolve(&request))
        };

        entered_rx.recv().unwrap();
        names.set(false, true, false);
        handle.clear();
        release_tx.send(()).unwrap();
        in_flight
            .join()
            .unwrap()
            .expect("붙잡혔던 질의도 답은 받아야 합니다");

        let after = chain.resolve(&request).expect("답");
        assert_eq!(
            after.header.rcode,
            ResponseCode::NXDomain.0,
            "비운 뒤에 도착한 이전 설정의 답이 캐시에 남았습니다"
        );
        assert_eq!(
            upstream.calls.load(Ordering::SeqCst),
            1,
            "켜진 범주의 이름이 업스트림으로 나갔습니다"
        );
    }
}
