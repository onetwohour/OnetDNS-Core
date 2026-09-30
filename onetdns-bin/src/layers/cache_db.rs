/*!
 * @brief 외부 Redis에 응답을 공유하는 캐시 계층.
 */

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use onetdns_proto::{Message, RecordType, ResponseCode};

use super::{cap_message_ttls, outcome_to_option, semantic_request_key};
use crate::native::{ResolveFailure, ResolveOutcome, Resolver};

/**
 * @brief 이 응답을 담아 두면 안 되는지.
 * @warning 질문과 어긋나거나 잘렸거나 질문한 것이 답에 없으면 담지 않는다. 담으면 남이
 *          끼워 넣은 엉뚱한 답이 눌러앉는다.
 */
fn response_not_cacheable(req: &Message, resp: &Message) -> bool {
    resp.header.rcode != ResponseCode::NoError.0
        || !resp.header.response
        || resp.header.truncated
        || resp.header.opcode != req.header.opcode
        || req.questions.len() != resp.questions.len()
        || !req
            .questions
            .iter()
            .zip(&resp.questions)
            .all(|(request, response)| {
                request.qtype == response.qtype
                    && request.qclass == response.qclass
                    && request.name.eq_ignore_case(&response.name)
            })
        || !crate::cache::has_requested_answer(req, &resp.answers)
}

/**
 * @brief 여러 대가 나눠 쓰는 외부 캐시 계층.
 * @warning 담고 꺼낼 때 키에 해석 맥락을 넣는다. 넣지 않으면 다른 설정으로 실행 중인 서버가
 *          담은 답을 이 서버가 그대로 쓴다.
 */
pub struct CacheDbLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 외부 캐시 클라이언트. */
    redis: Arc<crate::redis::RedisClient>,
    /** @brief 외부 캐시에 담아 둘 기간. */
    expire_secs: u64,
    /** @brief 담을 때 걸 수명 하한. */
    min_ttl: u32,
    /** @brief 담을 때 걸 수명 상한. */
    max_ttl: u32,
    /** @brief 키 앞에 붙일 이름. 다른 설정의 답과 섞이지 않게 한다. */
    namespace: String,
}

impl CacheDbLayer {
    /** @brief 외부 캐시 클라이언트를 잡은 계층을 만든다. */
    pub fn new(
        inner: Arc<dyn Resolver>,
        redis: Arc<crate::redis::RedisClient>,
        expire_secs: u64,
        min_ttl: u32,
        max_ttl: u32,
        namespace: String,
    ) -> Self {
        CacheDbLayer {
            inner,
            redis,
            expire_secs,
            min_ttl,
            max_ttl,
            namespace,
        }
    }

    /** @brief 이 요청의 외부 캐시 키. */
    fn key(&self, request: &Message) -> Option<Vec<u8>> {
        let mut key = format!("onetdns:v2:{}:", self.namespace).into_bytes();
        key.extend_from_slice(&semantic_request_key(request)?);
        Some(key)
    }

    /** @brief 담을 바이트로. */
    fn encode_value(response: &Message) -> Option<Vec<u8>> {
        let stored_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .ok()?;
        let mut value = stored_at.to_be_bytes().to_vec();
        value.extend_from_slice(&response.try_encode().ok()?);
        Some(value)
    }

    /** @brief 담아 둔 바이트를 응답으로. 시각이 앞날이면 거부한다. 남이 담은 것으로 수명을 늘릴 수 있다. */
    fn decode_value(value: &[u8], max_ttl: u32) -> Option<(Message, u64)> {
        let timestamp: [u8; 8] = value.get(..8)?.try_into().ok()?;
        let stored_at = u64::from_be_bytes(timestamp);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let elapsed = now.checked_sub(stored_at)?;
        let remaining_cap = u64::from(max_ttl).checked_sub(elapsed)?;
        if remaining_cap == 0 {
            return None;
        }
        let mut message = Message::parse(value.get(8..)?).ok()?;
        let elapsed = elapsed.min(u64::from(u32::MAX)) as u32;
        let age_section = |records: &mut Vec<onetdns_proto::Record>| {
            records.retain_mut(|record| {
                if record.rtype == RecordType::OPT {
                    return true;
                }
                record.ttl = record.ttl.saturating_sub(elapsed);
                record.ttl > 0
            });
        };
        age_section(&mut message.answers);
        age_section(&mut message.authorities);
        age_section(&mut message.additionals);
        cap_message_ttls(&mut message, remaining_cap as u32);
        let any_live = message
            .answers
            .iter()
            .chain(message.authorities.iter())
            .chain(message.additionals.iter())
            .any(|record| record.rtype != RecordType::OPT);
        any_live.then_some((message, u64::from(elapsed)))
    }
}

impl Resolver for CacheDbLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 외부 캐시를 보고, 없으면 물어 담는다. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        if req.questions.is_empty() {
            return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
        }
        let Some(key) = self.key(req) else {
            return self.inner.resolve_outcome(req);
        };
        if let Some(bytes) = self.redis.get(&key) {
            if let Some((mut m, _elapsed)) = Self::decode_value(&bytes, self.max_ttl) {
                let ttl_fresh = m
                    .answers
                    .iter()
                    .chain(m.authorities.iter())
                    .chain(m.additionals.iter())
                    .any(|record| record.rtype != RecordType::OPT && record.ttl > 0);
                let dnssec_fresh = crate::cache::cache_dnssec_ttl_cap(
                    m.header.authentic_data,
                    &m.answers,
                    &m.authorities,
                    &m.additionals,
                )
                .is_some();
                if ttl_fresh && dnssec_fresh && !response_not_cacheable(req, &m) {
                    m.header.id = req.header.id;
                    m.header.opcode = req.header.opcode;
                    m.header.recursion_desired = req.header.recursion_desired;
                    m.header.checking_disabled = req.header.checking_disabled;
                    m.questions = req.questions.clone();
                    onetdns_forward::note_response_source("external cache");
                    return ResolveOutcome::Response(m);
                }
            }

            self.redis.del(&key);
        }
        let resp = match self.inner.resolve_outcome(req) {
            ResolveOutcome::Response(resp) => resp,

            failure => return failure,
        };
        if resp.header.rcode == ResponseCode::NoError.0
            && !resp.answers.is_empty()
            && !response_not_cacheable(req, &resp)
        {
            let mut stored = resp.clone();
            for record in &mut stored.answers {
                if record.rtype != RecordType::OPT {
                    record.ttl = record.ttl.clamp(self.min_ttl, self.max_ttl);
                }
            }
            for record in stored
                .authorities
                .iter_mut()
                .chain(stored.additionals.iter_mut())
            {
                if record.rtype != RecordType::OPT {
                    record.ttl = record.ttl.min(self.max_ttl);
                }
            }
            let Some(dnssec_cap) = crate::cache::cache_dnssec_ttl_cap(
                resp.header.authentic_data,
                &resp.answers,
                &resp.authorities,
                &resp.additionals,
            ) else {
                return ResolveOutcome::Response(resp);
            };
            cap_message_ttls(&mut stored, dnssec_cap);
            let mut rr_ttl = stored
                .answers
                .iter()
                .filter(|record| record.rtype != RecordType::OPT)
                .map(|record| u64::from(record.ttl))
                .min()
                .unwrap_or(0);
            rr_ttl = rr_ttl.min(u64::from(dnssec_cap));
            let ttl = if self.expire_secs > 0 {
                self.expire_secs.min(rr_ttl)
            } else {
                rr_ttl
            };
            if ttl > 0 {
                if let Some(value) = Self::encode_value(&stored) {
                    self.redis.setex(&key, ttl, &value);
                }
            }
        }
        ResolveOutcome::Response(resp)
    }
}

#[cfg(test)]
/** @brief 공유 캐시 키와 봉투 검증, 나이 계산. */
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use onetdns_proto::{Name, RData, Record, RecordType, ResponseCode};

    use crate::layers::answer_message;
    use crate::native::Resolver;

    /** @brief 이름 공간을 지정한 테스트용 외부 캐시 계층. */
    fn cachedb_with_namespace(namespace: &str) -> CacheDbLayer {
        CacheDbLayer::new(
            EmptyMock::new(false) as Arc<dyn Resolver>,
            Arc::new(crate::redis::RedisClient::new(std::net::SocketAddr::from(
                ([127, 0, 0, 1], 1),
            ))),
            60,
            0,
            3600,
            namespace.to_string(),
        )
    }

    #[test]
    /** @brief 같은 뜻의 질의가 같은 키를 갖는지. */
    fn cachedb_key_normalizes() {
        let layer = cachedb_with_namespace("ns");
        let upper = layer.key(&query("Example.COM", RecordType::A)).unwrap();
        let lower = layer.key(&query("example.com", RecordType::A)).unwrap();
        assert_eq!(upper, lower, "0x20 대소문자는 동일 키로 정규화되어야 함");
        assert!(upper.starts_with(b"onetdns:v2:ns:"));
        let aaaa = layer.key(&query("example.com", RecordType::AAAA)).unwrap();
        assert_ne!(lower, aaaa, "qtype가 다르면 키가 분리되어야 함");
    }

    #[test]
    /** @brief 해석 맥락이 다르면 키도 다른지. 같으면 다른 설정의 답을 이 서버가 쓴다. */
    fn cachedb_key_separates_resolution_contexts() {
        let request = query("example.com", RecordType::A);
        let default_chain = cachedb_with_namespace("recurse-dnssec")
            .key(&request)
            .unwrap();
        let route_chain = cachedb_with_namespace("route-work").key(&request).unwrap();
        let plain_forward = cachedb_with_namespace("forward").key(&request).unwrap();
        assert_ne!(default_chain, route_chain, "클라이언트 라우트는 분리");
        assert_ne!(default_chain, plain_forward, "백엔드·검증 정책은 분리");
    }

    #[test]
    /** @brief 질문과 맞고 온전한 긍정 응답만 받아들이는지. */
    fn cachedb_accepts_only_matching_complete_positive_envelopes() {
        let request = query("cache.example", RecordType::A);
        let q = request.questions[0].clone();
        let mut response = answer_message(
            request.header.id,
            q.name.clone(),
            q.qtype,
            vec![Record::new(
                q.name.clone(),
                300,
                RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            )],
        );
        assert!(!response_not_cacheable(&request, &response));

        response.header.response = false;
        assert!(response_not_cacheable(&request, &response));
        response.header.response = true;
        response.header.truncated = true;
        assert!(response_not_cacheable(&request, &response));
        response.header.truncated = false;
        response.header.rcode = ResponseCode::NXDomain.0;
        assert!(response_not_cacheable(&request, &response));
        response.header.rcode = ResponseCode::NoError.0;
        response.questions[0].qtype = RecordType::AAAA;
        assert!(response_not_cacheable(&request, &response));
        response.questions[0] = q;
        response.answers[0].name = Name::from_str("attacker.example").unwrap();
        assert!(response_not_cacheable(&request, &response));
    }

    #[test]
    /** @brief 앞날로 적힌 시각을 거부하고 구간마다 늙히는지. 안 그러면 남이 수명을 늘릴 수 있다. */
    fn cachedb_rejects_future_timestamp_and_ages_each_section() {
        let request = query("cache.example", RecordType::A);
        let q = request.questions[0].clone();
        let mut response = answer_message(
            request.header.id,
            q.name.clone(),
            q.qtype,
            vec![Record::new(
                q.name,
                100,
                RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            )],
        );
        response.additionals.push(Record::new(
            Name::from_str("ns.cache.example").unwrap(),
            1,
            RData::A(Ipv4Addr::new(192, 0, 2, 53)),
        ));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let wire = response.try_encode().unwrap();

        let mut future = (now + 60).to_be_bytes().to_vec();
        future.extend_from_slice(&wire);
        assert!(CacheDbLayer::decode_value(&future, u32::MAX).is_none());

        let mut aged = now.saturating_sub(2).to_be_bytes().to_vec();
        aged.extend_from_slice(&wire);
        let (decoded, elapsed) = CacheDbLayer::decode_value(&aged, u32::MAX).unwrap();
        assert!(elapsed >= 2);
        assert!(decoded.answers[0].ttl <= 98);
        assert!(decoded.additionals.is_empty());
    }

    #[test]
    /** @brief 현재 최대 TTL이 조회 시점부터 다시 시작되지 않고 삽입 시점부터 적용되는지. */
    fn cachedb_max_ttl_is_an_absolute_age_cap() {
        let request = query("cache.example", RecordType::A);
        let q = request.questions[0].clone();
        let response = answer_message(
            request.header.id,
            q.name.clone(),
            q.qtype,
            vec![Record::new(
                q.name,
                300,
                RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            )],
        );
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut value = now.saturating_sub(2).to_be_bytes().to_vec();
        value.extend_from_slice(&response.try_encode().unwrap());

        let (decoded, elapsed) = CacheDbLayer::decode_value(&value, 5).unwrap();
        let remaining_cap = 5u64.saturating_sub(elapsed) as u32;
        assert!(
            decoded.answers[0].ttl <= remaining_cap,
            "max_ttl은 삽입 뒤 경과 시간만큼 줄어야 합니다: elapsed={elapsed}, ttl={}",
            decoded.answers[0].ttl
        );
    }

    #[test]
    /** @brief 담기엔 너무 큰 응답을 오류로 바꿔 담지 않는지. */
    fn cachedb_does_not_encode_servfail_fallback_for_oversized_value() {
        let request = query("large.cache.example", RecordType::A);
        let q = request.questions[0].clone();
        let response = answer_message(
            request.header.id,
            q.name.clone(),
            q.qtype,
            vec![Record::new(
                q.name,
                300,
                RData::Unknown(65280, vec![0; 65_500]),
            )],
        );
        assert!(CacheDbLayer::encode_value(&response).is_none());
    }
}
