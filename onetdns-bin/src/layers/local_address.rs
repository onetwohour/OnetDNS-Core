/*!
 * @brief Split 모드에서 로컬 A와 AAAA를 합성하는 계층과 그 주소표.
 */

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, OnceLock};

use onetdns_proto::{Message, Name, RData, Record, RecordType};

use super::{answer_message, configured_name_key, outcome_to_option};
use crate::native::{ResolveFailure, ResolveOutcome, Resolver};

/**
 * @brief 설정에 고정해 둔 이름별 주소.
 * @note 수명을 원자 값으로 잡는다. 설정을 다시 읽었을 때 다음 질의부터 곧바로 반영되게
 *       하려는 것이다.
 */
pub struct LocalAddressTable {
    /** @brief 이름별로 고정해 둔 주소. */
    addresses: HashMap<Vec<u8>, LocalAddresses>,
    /** @brief 답에 담을 수명. 설정을 다시 읽으면 곧바로 반영되도록 따로 둔다. */
    local_ttl: Arc<std::sync::atomic::AtomicU32>,
}

#[derive(Default)]
/** @brief 이름 하나에 걸린 주소들. */
struct LocalAddresses {
    /** @brief 이 이름의 IPv4 주소. */
    a: Option<Ipv4Addr>,
    /** @brief 이 이름의 IPv6 주소. */
    aaaa: Option<Ipv6Addr>,
}

impl LocalAddressTable {
    /** @brief 설정 목록으로 만든다. 이름이 틀리거나 겹치면 실패다. */
    pub fn new(
        local_a: &[(String, Ipv4Addr)],
        local_aaaa: &[(String, Ipv6Addr)],
        local_ttl: Arc<std::sync::atomic::AtomicU32>,
    ) -> Result<Self, String> {
        let mut addresses = HashMap::<Vec<u8>, LocalAddresses>::with_capacity(
            local_a.len().saturating_add(local_aaaa.len()),
        );
        for (name, ip) in local_a {
            let key = configured_name_key(name)
                .ok_or_else(|| format!("로컬 A 레코드 이름이 올바르지 않습니다: {name}"))?;
            if addresses.entry(key).or_default().a.replace(*ip).is_some() {
                return Err(format!("로컬 A 레코드 이름이 중복되었습니다: {name}"));
            }
        }
        for (name, ip) in local_aaaa {
            let key = configured_name_key(name)
                .ok_or_else(|| format!("로컬 AAAA 레코드 이름이 올바르지 않습니다: {name}"))?;
            if addresses
                .entry(key)
                .or_default()
                .aaaa
                .replace(*ip)
                .is_some()
            {
                return Err(format!("로컬 AAAA 레코드 이름이 중복되었습니다: {name}"));
            }
        }
        Ok(Self {
            addresses,
            local_ttl,
        })
    }

    /** @brief 이 이름에 고정해 둔 답. */
    fn local_answer(&self, name: &Name, qtype: RecordType) -> Option<(Vec<Record>, u32)> {
        let mut key = [0u8; 255];
        let key = name.canonical_key_into(&mut key)?;
        let addresses = self.addresses.get(key)?;
        let ttl = self.local_ttl.load(std::sync::atomic::Ordering::Acquire);
        let answers = match qtype {
            RecordType::A => addresses
                .a
                .map(|ip| vec![Record::new(name.clone(), ttl, RData::A(ip))])
                .unwrap_or_default(),
            RecordType::AAAA => addresses
                .aaaa
                .map(|ip| vec![Record::new(name.clone(), ttl, RData::Aaaa(ip))])
                .unwrap_or_default(),
            _ => vec![],
        };
        Some((answers, ttl))
    }
}

/**
 * @brief 고정해 둔 주소를 답하는 계층.
 * @warning 답할 때 그곳에 표시를 남긴다. 남기지 않으면 나중에 바깥 계층의 답을 이
 *          계층의 답으로 오해해 고정 수명 항목으로 승격시킨다.
 */
pub struct LocalAddressLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 고정해 둔 주소표. */
    addresses: Arc<LocalAddressTable>,
    /** @brief 답했음을 표시해 둘 캐시. 승격할 때 남의 답과 구분하려는 것이다. */
    wire_cache: Option<Arc<OnceLock<crate::cache::CacheHandle>>>,
}

impl LocalAddressLayer {
    /** @brief 주소표를 잡은 계층을 만든다. */
    pub fn new(
        inner: Arc<dyn Resolver>,
        addresses: Arc<LocalAddressTable>,
        wire_cache: Option<Arc<OnceLock<crate::cache::CacheHandle>>>,
    ) -> Self {
        Self {
            inner,
            addresses,
            wire_cache,
        }
    }
}

impl Resolver for LocalAddressLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 고정해 둔 이름이면 답하고, 아니면 안으로 넘긴다. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        let Some(q) = req.questions.first() else {
            return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
        };
        if let Some((answers, ttl)) = self.addresses.local_answer(&q.name, q.qtype) {
            if let Some(cache) = self.wire_cache.as_ref().and_then(|slot| slot.get()) {
                cache.ensure_local_wire_candidate(req);
            }
            let mut response = answer_message(req.header.id, q.name.clone(), q.qtype, answers);
            if response.answers.is_empty() {
                response.authorities.push(Record::new(
                    q.name.clone(),
                    ttl,
                    RData::Soa(Box::new(onetdns_proto::Soa {
                        mname: Name::root(),
                        rname: Name::root(),
                        serial: 1,
                        refresh: 3_600,
                        retry: 600,
                        expire: 86_400,
                        minimum: ttl,
                    })),
                ));
            }
            return ResolveOutcome::Response(response);
        }
        self.inner.resolve_outcome(req)
    }
}
