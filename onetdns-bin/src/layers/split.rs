/*!
 * @brief 접미사에 따라 전달과 재귀로 갈라 보내는 Split 백엔드.
 */

use std::collections::HashSet;
use std::sync::Arc;

use onetdns_proto::{Message, Name};

use super::configured_name_key;
use crate::native::{ResolveFailure, ResolveOutcome, Resolver};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 이 질의를 어디로 보낼지. */
pub enum Route {
    /** @brief 전달로 보낸다. */
    Forward,
    /** @brief 재귀로 보낸다. */
    Recurse,
}

/** @brief 접미사에 따라 전달과 재귀를 갈라 보내는 것. */
pub struct SplitResolver {
    /** @brief 전달 경로. */
    forward: Arc<dyn Resolver>,
    /** @brief 재귀 경로. */
    recurse: Arc<dyn Resolver>,
    /** @brief 어느 목록에도 없을 때 갈 곳. */
    default: Route,
    /** @brief 재귀로 보낼 접미사들. */
    recurse_suffixes: HashSet<Vec<u8>>,
    /** @brief 전달로 보낼 접미사들. */
    forward_suffixes: HashSet<Vec<u8>>,
}

impl SplitResolver {
    /** @brief 두 경로와 분기 규칙으로 만든다. */
    pub fn new(
        forward: Arc<dyn Resolver>,
        recurse: Arc<dyn Resolver>,
        default: Route,
        recurse_suffixes: &[String],
        forward_suffixes: &[String],
    ) -> Result<Self, String> {
        let recurse_suffixes = recurse_suffixes
            .iter()
            .map(|suffix| {
                configured_name_key(suffix)
                    .ok_or_else(|| format!("재귀 분할 DNS 이름이 올바르지 않습니다: {suffix}"))
            })
            .collect::<Result<HashSet<_>, _>>()?;
        let forward_suffixes = forward_suffixes
            .iter()
            .map(|suffix| {
                configured_name_key(suffix)
                    .ok_or_else(|| format!("전달 분할 DNS 이름이 올바르지 않습니다: {suffix}"))
            })
            .collect::<Result<HashSet<_>, _>>()?;
        if recurse_suffixes
            .intersection(&forward_suffixes)
            .next()
            .is_some()
        {
            return Err(
                "같은 DNS 이름을 재귀와 전달 분할 경로에 동시에 지정할 수 없습니다".to_string(),
            );
        }
        Ok(SplitResolver {
            forward,
            recurse,
            default,
            recurse_suffixes,
            forward_suffixes,
        })
    }

    /** @brief 이 이름을 어디로 보낼지. */
    fn route_for(&self, name: &Name) -> Route {
        let mut key = [0u8; 255];
        for labels in (0..=name.num_labels()).rev() {
            let Some(key) = name.canonical_suffix_key_into(labels, &mut key) else {
                return self.default;
            };
            if self.recurse_suffixes.contains(key) {
                return Route::Recurse;
            }
            if self.forward_suffixes.contains(key) {
                return Route::Forward;
            }
        }
        self.default
    }
}

impl Resolver for SplitResolver {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        match self.resolve_outcome(req) {
            ResolveOutcome::Response(response) => Some(response),
            ResolveOutcome::Failure(_) => None,
        }
    }

    /** @brief 분기 규칙대로 보낸다. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        let Some(q) = req.questions.first() else {
            return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
        };
        match self.route_for(&q.name) {
            Route::Recurse => self.recurse.resolve_outcome(req),
            Route::Forward => self.forward.resolve_outcome(req),
        }
    }
}

#[cfg(test)]
/** @brief Split 경로 선택과 로컬 주소 합성. */
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    use onetdns_proto::{RData, Record, RecordType, ResponseCode};

    use crate::layers::local_address::{LocalAddressLayer, LocalAddressTable};

    #[test]
    /** @brief 분기 규칙과 고정해 둔 주소가 함께 동작하는지. */
    fn split_local_and_routing() {
        let fwd = Mock::new(3, ResponseCode::NoError.0);
        let rec = Mock::new(4, ResponseCode::NoError.0);
        let local_ttl = Arc::new(AtomicU32::new(17));
        let split = SplitResolver::new(
            fwd.clone(),
            rec.clone(),
            Route::Forward,
            &["corp.internal".to_string()],
            &[],
        )
        .unwrap();
        let cached = crate::cache::CacheLayer::new(Arc::new(split), 8, 1, 0, 3_600, 0, 3_600);
        let addresses = Arc::new(
            LocalAddressTable::new(
                &[("router.lan".to_string(), Ipv4Addr::new(192, 168, 0, 1))],
                &[],
                local_ttl.clone(),
            )
            .unwrap(),
        );
        let split = LocalAddressLayer::new(Arc::new(cached), addresses, None);

        let r0 = split.resolve(&query("router.lan", RecordType::A)).unwrap();
        match &r0.answers[0].rdata {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(192, 168, 0, 1)),
            _ => panic!("로컬 A 기대"),
        }
        assert_eq!(r0.answers[0].ttl, 17, "설정한 로컬 TTL");
        local_ttl.store(23, Ordering::Release);
        assert_eq!(
            split
                .resolve(&query("router.lan", RecordType::A))
                .unwrap()
                .answers[0]
                .ttl,
            23,
            "응답 캐시가 있어도 핫 적용한 로컬 TTL"
        );
        local_ttl.store(0, Ordering::Release);
        assert_eq!(
            split
                .resolve(&query("router.lan", RecordType::A))
                .unwrap()
                .answers[0]
                .ttl,
            0,
            "TTL 0을 숨은 하한 없이 보존"
        );
        local_ttl.store(u32::MAX, Ordering::Release);
        assert_eq!(
            split
                .resolve(&query("router.lan", RecordType::A))
                .unwrap()
                .answers[0]
                .ttl,
            u32::MAX,
            "TTL 상한값을 잘라내지 않음"
        );
        let nodata = split
            .resolve(&query("router.lan", RecordType::TXT))
            .unwrap();
        assert!(nodata.answers.is_empty());
        assert!(
            matches!(
                nodata.authorities.as_slice(),
                [Record {
                    ttl: u32::MAX,
                    rdata: RData::Soa(soa),
                    ..
                }] if soa.minimum == u32::MAX
            ),
            "등록된 로컬 이름의 다른 타입은 SOA가 증명하는 NODATA"
        );

        let r1 = split
            .resolve(&query("host.corp.internal", RecordType::A))
            .unwrap();
        assert_eq!(r1.answers[0].ttl, 4, "recurse로 라우팅");

        let r2 = split.resolve(&query("example.com", RecordType::A)).unwrap();
        assert_eq!(r2.answers[0].ttl, 3, "기본 forward");
    }
}
