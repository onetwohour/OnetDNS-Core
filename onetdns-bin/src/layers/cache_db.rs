/*!
 * @brief 외부 Redis에 응답을 공유하는 캐시 계층.
 *
 * @details Redis는 믿지 않는 저장소로 다룬다. 값마다 공유 비밀 키로 계산한 HMAC을 붙여 담고,
 *          꺼낼 때 HMAC이 맞지 않으면 버린다. HMAC은 키까지 덮으므로 담긴 값을 다른 키로 옮겨도
 *          통하지 않는다. Redis에 쓸 수 있는 쪽은 값을 지우거나, 같은 키에 담겼던 값을 그 수명
 *          안에서 다시 내놓을 수만 있고 새 답을 만들어 넣지는 못한다.
 */

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use onetdns_core::{ArcSwap, SecretString};
use onetdns_dnssec::Ds;
use onetdns_proto::{Message, RecordType, ResponseCode};
use sha2::Sha256;

use super::{cap_message_ttls, outcome_to_option, semantic_request_key};
use crate::native::{ResolveFailure, ResolveOutcome, Resolver};
use crate::redis::RedisClient;

/** @brief 값과 이름 공간을 계산하는 HMAC. */
type HmacSha256 = Hmac<Sha256>;

/** @brief 키 앞머리. 키를 만드는 방식이나 값의 형식이 바뀌면 판 번호를 올린다. */
const KEY_PREFIX: &str = "onetdns:v4:";
/** @brief 키에 넣는 이름 공간의 16진 길이. 128비트다. */
const NAMESPACE_HEX: usize = 32;
/** @brief 값 앞에 붙는 HMAC 길이. */
const MAC_LEN: usize = 32;
/** @brief 이름 공간을 계산할 때 맨 앞에 넣는 표지. 값 HMAC과 입력이 겹치지 않게 한다. */
const NAMESPACE_LABEL: &[u8] = b"onetdns cachedb namespace\0";
/** @brief 값 HMAC을 계산할 때 맨 앞에 넣는 표지. */
const VALUE_LABEL: &[u8] = b"onetdns cachedb value\0";

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
 * @brief 공유 캐시에서 이 체인의 답이 놓이는 자리를 정하는 값.
 * @details 비밀 키와 해석 맥락, 지금 쓰는 신뢰 앵커가 모두 같은 서버끼리만 서로의 답을 본다.
 */
pub struct CacheDbScope {
    /** @brief 같은 Redis를 쓰는 서버가 함께 갖는 비밀 키. Redis에는 보내지 않는다. */
    pub secret: SecretString,
    /** @brief CacheDbLayer 아래에서 답을 바꾸는 설정을 정규화한 문자열. */
    pub context: String,
    /**
     * @brief 아래 계층이 답을 검증할 때 쓰는 신뢰 앵커.
     * @details 재귀 리졸버의 앵커는 RFC 5011 갱신으로 실행 중에 바뀐다. 그래서 파일 경로가 아니라
     *          지금 쓰는 앵커의 내용으로 이름 공간을 가른다.
     */
    pub anchors: Vec<Arc<ArcSwap<Vec<Ds>>>>,
}

/** @brief 신뢰 앵커 한 벌로 계산한 이름 공간. */
struct Namespace {
    /** @brief 계산에 쓴 앵커. 핸들과 같은 순서다. */
    anchors: Vec<Arc<Vec<Ds>>>,
    /** @brief 키 앞머리. 판 번호와 이름 공간까지 담는다. */
    prefix: Vec<u8>,
}

impl Namespace {
    /** @brief 핸들이 지금 가리키는 앵커가 이 이름 공간을 계산할 때 쓴 것과 같은지. */
    fn is_current(&self, handles: &[Arc<ArcSwap<Vec<Ds>>>]) -> bool {
        self.anchors.len() == handles.len()
            && handles
                .iter()
                .zip(&self.anchors)
                .all(|(handle, anchors)| Arc::ptr_eq(&handle.load(), anchors))
    }

    /** @brief 이 요청의 키. */
    fn key(&self, request: &Message) -> Option<Vec<u8>> {
        let mut key = self.prefix.clone();
        key.extend_from_slice(&semantic_request_key(request)?);
        Some(key)
    }
}

/** @brief 길이를 앞에 붙여 HMAC 입력에 넣는다. 이어 붙인 필드의 경계가 흐려지지 않게 한다. */
fn update_field(mac: &mut HmacSha256, field: &[u8]) {
    mac.update(&(field.len() as u64).to_be_bytes());
    mac.update(field);
}

/**
 * @brief 해석 맥락과 지금 쓰는 신뢰 앵커로 이름 공간을 계산한다.
 * @details 앵커는 정렬하고 중복을 없애 넣는다. 같은 앵커를 다른 순서로 적은 서버끼리도 답을
 *          나눠 쓴다. 비밀 키로 계산하므로 비밀 키가 다른 서버와는 키가 겹치지 않는다.
 */
fn derive_namespace(
    keyed: &HmacSha256,
    context: &str,
    handles: &[Arc<ArcSwap<Vec<Ds>>>],
) -> Namespace {
    let anchors: Vec<Arc<Vec<Ds>>> = handles.iter().map(|handle| handle.load()).collect();
    let mut mac = keyed.clone();
    mac.update(NAMESPACE_LABEL);
    update_field(&mut mac, context.as_bytes());
    mac.update(&(anchors.len() as u64).to_be_bytes());
    for set in &anchors {
        let mut sorted: Vec<&Ds> = set.iter().collect();
        sorted.sort_by(|a, b| {
            (a.key_tag, a.algorithm, a.digest_type, &a.digest).cmp(&(
                b.key_tag,
                b.algorithm,
                b.digest_type,
                &b.digest,
            ))
        });
        sorted.dedup();
        mac.update(&(sorted.len() as u64).to_be_bytes());
        for ds in sorted {
            mac.update(&ds.key_tag.to_be_bytes());
            mac.update(&[ds.algorithm, ds.digest_type]);
            update_field(&mut mac, &ds.digest);
        }
    }
    let digest = format!("{:x}", mac.finalize().into_bytes());
    let mut prefix = KEY_PREFIX.as_bytes().to_vec();
    prefix.extend_from_slice(&digest.as_bytes()[..NAMESPACE_HEX]);
    prefix.push(b':');
    Namespace { anchors, prefix }
}

/**
 * @brief 여러 대가 나눠 쓰는 외부 캐시 계층.
 * @warning 담고 꺼낼 때 키에 해석 맥락과 신뢰 앵커를 넣는다. 넣지 않으면 다른 설정으로 실행 중인
 *          서버가 담은 답을 이 서버가 그대로 쓴다.
 */
pub struct CacheDbLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 외부 캐시 클라이언트. */
    redis: Arc<RedisClient>,
    /** @brief 외부 캐시에 담아 둘 기간. */
    expire_secs: u64,
    /** @brief 담을 때 걸 수명 하한. */
    min_ttl: u32,
    /** @brief 담을 때 걸 수명 상한. */
    max_ttl: u32,
    /** @brief 비밀 키를 넣어 둔 HMAC. 쓸 때마다 복제한다. */
    keyed: HmacSha256,
    /** @brief CacheDbLayer 아래에서 답을 바꾸는 설정. */
    context: String,
    /** @brief 아래 계층이 쓰는 신뢰 앵커의 핸들. */
    anchors: Vec<Arc<ArcSwap<Vec<Ds>>>>,
    /** @brief 마지막으로 계산한 이름 공간. 앵커가 바뀌면 다시 계산한다. */
    namespace: ArcSwap<Namespace>,
    /** @brief HMAC이 맞지 않아 버린 값의 누적 수. 2의 거듭제곱 번째만 기록한다. */
    rejected: AtomicU64,
}

impl CacheDbLayer {
    /** @brief 외부 캐시 클라이언트를 잡은 계층을 만든다. */
    pub fn new(
        inner: Arc<dyn Resolver>,
        redis: Arc<RedisClient>,
        scope: CacheDbScope,
        expire_secs: u64,
        min_ttl: u32,
        max_ttl: u32,
    ) -> Self {
        let CacheDbScope {
            secret,
            context,
            anchors,
        } = scope;
        let keyed =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
        let namespace = ArcSwap::new(Arc::new(derive_namespace(&keyed, &context, &anchors)));
        CacheDbLayer {
            inner,
            redis,
            expire_secs,
            min_ttl,
            max_ttl,
            keyed,
            context,
            anchors,
            namespace,
            rejected: AtomicU64::new(0),
        }
    }

    /** @brief 지금 쓰는 신뢰 앵커에 맞는 이름 공간. 앵커가 바뀌었으면 다시 계산한다. */
    fn namespace(&self) -> Arc<Namespace> {
        let memo = self.namespace.load();
        if memo.is_current(&self.anchors) {
            return memo;
        }
        let fresh = Arc::new(derive_namespace(&self.keyed, &self.context, &self.anchors));
        self.namespace.store(fresh.clone());
        fresh
    }

    /** @brief 이 키에 담긴 값의 HMAC. 담은 시각과 응답까지 덮는다. */
    fn value_mac(&self, key: &[u8], stored_at: u64, wire: &[u8]) -> HmacSha256 {
        let mut mac = self.keyed.clone();
        mac.update(VALUE_LABEL);
        update_field(&mut mac, key);
        mac.update(&stored_at.to_be_bytes());
        mac.update(wire);
        mac
    }

    /** @brief 이 키에 담을 값. HMAC, 담은 시각, 응답 순서다. */
    fn seal(&self, key: &[u8], stored_at: u64, wire: &[u8]) -> Vec<u8> {
        let tag = self.value_mac(key, stored_at, wire).finalize().into_bytes();
        let mut value = Vec::with_capacity(MAC_LEN + 8 + wire.len());
        value.extend_from_slice(&tag);
        value.extend_from_slice(&stored_at.to_be_bytes());
        value.extend_from_slice(wire);
        value
    }

    /** @brief 이 키에서 꺼낸 값의 HMAC을 확인한다. 맞으면 담은 시각과 응답을 돌려준다. */
    fn open<'a>(&self, key: &[u8], value: &'a [u8]) -> Option<(u64, &'a [u8])> {
        let (tag, rest) = value.split_at_checked(MAC_LEN)?;
        let (stored_at, wire) = rest.split_at_checked(8)?;
        let stored_at = u64::from_be_bytes(stored_at.try_into().ok()?);
        self.value_mac(key, stored_at, wire)
            .verify_slice(tag)
            .ok()?;
        Some((stored_at, wire))
    }

    /**
     * @brief HMAC이 맞지 않는 값을 만났음을 기록한다.
     * @details 같은 비밀 키를 쓰는 서버는 이런 값을 만들지 않는다. 이 서버들 말고 다른 누군가가
     *          Redis에 쓰고 있거나 Redis가 값을 망가뜨렸다는 뜻이다.
     */
    fn note_rejected(&self) {
        let count = self.rejected.fetch_add(1, Ordering::Relaxed) + 1;
        if count.is_power_of_two() {
            onetdns_core::warn!(event = "cachedb.value_rejected", addr = %self.redis.addr(), count = count, "Discarded a shared cache value whose authentication tag did not match; something other than these servers is writing to the shared cache, or the cache corrupted the value");
        }
    }

    /**
     * @brief 담아 둔 응답을 읽고, 담은 뒤 지난 시간만큼 레코드 수명을 줄인다.
     * @details 담은 시각이 앞날이면 거부한다. 시계가 앞선 서버가 담은 값을 받으면 그 차이만큼 답이
     *          더 오래 남는다.
     */
    fn decode_value(stored_at: u64, wire: &[u8], max_ttl: u32) -> Option<(Message, u64)> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let elapsed = now.checked_sub(stored_at)?;
        let remaining_cap = u64::from(max_ttl).checked_sub(elapsed)?;
        if remaining_cap == 0 {
            return None;
        }
        let mut message = Message::parse(wire).ok()?;
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

    /** @brief 꺼낸 응답을 이 요청의 답으로 쓸 수 있으면 요청에 맞춘다. */
    fn cached_response(&self, req: &Message, stored_at: u64, wire: &[u8]) -> Option<Message> {
        let (mut m, _elapsed) = Self::decode_value(stored_at, wire, self.max_ttl)?;
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
        if !ttl_fresh || !dnssec_fresh || response_not_cacheable(req, &m) {
            return None;
        }
        m.header.id = req.header.id;
        m.header.opcode = req.header.opcode;
        m.header.recursion_desired = req.header.recursion_desired;
        m.header.checking_disabled = req.header.checking_disabled;
        m.questions = req.questions.clone();
        Some(m)
    }

    /**
     * @brief 담을 만한 응답이면 수명 범위를 걸어 담도록 맡긴다.
     * @return 담기를 맡겼는지.
     */
    fn store(&self, req: &Message, key: &[u8], resp: &Message) -> bool {
        if resp.header.rcode != ResponseCode::NoError.0
            || resp.answers.is_empty()
            || response_not_cacheable(req, resp)
        {
            return false;
        }
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
            return false;
        };
        cap_message_ttls(&mut stored, dnssec_cap);
        let rr_ttl = stored
            .answers
            .iter()
            .filter(|record| record.rtype != RecordType::OPT)
            .map(|record| u64::from(record.ttl))
            .min()
            .unwrap_or(0)
            .min(u64::from(dnssec_cap));
        let ttl = if self.expire_secs > 0 {
            self.expire_secs.min(rr_ttl)
        } else {
            rr_ttl
        };
        if ttl == 0 {
            return false;
        }
        let Ok(stored_at) = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
        else {
            return false;
        };
        let Ok(wire) = stored.try_encode() else {
            return false;
        };
        self.redis
            .setex(key.to_vec(), ttl, self.seal(key, stored_at, &wire));
        true
    }
}

impl Resolver for CacheDbLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /**
     * @brief 외부 캐시를 보고, 없으면 물어 담는다.
     * @details 꺼낸 값을 쓸 수 없으면 새 답으로 덮고, 새 답을 담지 못하면 지운다. 쓰기는 맡겨
     *          두고 기다리지 않으며, 한 키에 지우기와 담기를 함께 맡기지 않는다. 묻는 동안 신뢰
     *          앵커가 바뀌면 담지 않는다. 그 답은 어느 앵커로 검증했는지 알 수 없는데, 이전 앵커의
     *          이름 공간에 새 앵커로 검증한 답을 담거나 그 반대가 된다.
     */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        if req.questions.is_empty() {
            return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
        }
        let namespace = self.namespace();
        let Some(key) = namespace.key(req) else {
            return self.inner.resolve_outcome(req);
        };
        let unusable = match self.redis.get(&key) {
            Some(value) => {
                match self.open(&key, &value) {
                    Some((stored_at, wire)) => {
                        if let Some(response) = self.cached_response(req, stored_at, wire) {
                            onetdns_forward::note_response_source("external cache");
                            return ResolveOutcome::Response(response);
                        }
                    }
                    None => self.note_rejected(),
                }
                true
            }
            None => false,
        };
        let outcome = self.inner.resolve_outcome(req);
        let replaced = match &outcome {
            ResolveOutcome::Response(resp) if namespace.is_current(&self.anchors) => {
                self.store(req, &key, resp)
            }
            _ => false,
        };
        if unusable && !replaced {
            self.redis.del(key);
        }
        outcome
    }
}

#[cfg(test)]
/** @brief 공유 캐시 키, 값 인증, 신뢰 앵커를 따르는 이름 공간, 나이 계산. */
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use crate::redis::fake::{Behavior, FakeRedis};
    use crate::redis::RedisOptions;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use onetdns_proto::{Name, RData, Record, RecordType, ResponseCode};

    use crate::layers::answer_message;
    use crate::native::Resolver;

    /** @brief 공유 비밀 키. */
    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    /** @brief 키 태그 하나만 다른 신뢰 앵커. */
    fn ds(key_tag: u16) -> Ds {
        Ds {
            key_tag,
            algorithm: 8,
            digest_type: 2,
            digest: vec![key_tag as u8; 32],
        }
    }

    /** @brief 이 앵커를 든 핸들. */
    fn anchors(set: Vec<Ds>) -> Arc<ArcSwap<Vec<Ds>>> {
        Arc::new(ArcSwap::new(Arc::new(set)))
    }

    /** @brief 이 범위로 묻는 계층. */
    fn cachedb_layer(
        inner: Arc<dyn Resolver>,
        redis: SocketAddr,
        secret: &str,
        context: &str,
        handles: Vec<Arc<ArcSwap<Vec<Ds>>>>,
    ) -> CacheDbLayer {
        CacheDbLayer::new(
            inner,
            Arc::new(RedisClient::new(RedisOptions {
                addr: redis,
                tls: None,
                auth: None,
            })),
            CacheDbScope {
                secret: secret.into(),
                context: context.to_string(),
                anchors: handles,
            },
            60,
            0,
            3600,
        )
    }

    /** @brief 아무 데도 붙지 않는 계층. 키와 봉투만 볼 때 쓴다. */
    fn offline(context: &str) -> CacheDbLayer {
        cachedb_layer(
            EmptyMock::new(false),
            SocketAddr::from(([127, 0, 0, 1], 1)),
            SECRET,
            context,
            Vec::new(),
        )
    }

    /** @brief 이 계층이 이 요청에 쓰는 키. */
    fn key_of(layer: &CacheDbLayer, request: &Message) -> Vec<u8> {
        layer.namespace().key(request).unwrap()
    }

    /** @brief 지금 시각. */
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    /** @brief 같은 뜻의 질의가 같은 키를 갖고, 이름 공간이 128비트인지. */
    fn cachedb_key_normalizes() {
        let layer = offline("ctx");
        let upper = key_of(&layer, &query("Example.COM", RecordType::A));
        let lower = key_of(&layer, &query("example.com", RecordType::A));
        assert_eq!(upper, lower, "0x20 대소문자는 동일 키로 정규화되어야 함");
        assert!(upper.starts_with(KEY_PREFIX.as_bytes()));
        let namespace = &upper[KEY_PREFIX.len()..KEY_PREFIX.len() + NAMESPACE_HEX];
        assert!(namespace.iter().all(u8::is_ascii_hexdigit));
        assert_eq!(upper[KEY_PREFIX.len() + NAMESPACE_HEX], b':');
        let aaaa = key_of(&layer, &query("example.com", RecordType::AAAA));
        assert_ne!(lower, aaaa, "qtype가 다르면 키가 분리되어야 함");
    }

    #[test]
    /**
     * @brief 해석 맥락, 비밀 키, 신뢰 앵커 가운데 하나만 달라도 키가 다른지.
     * @details 앵커는 정렬해 넣으므로 순서만 다른 앵커는 같은 키를 쓴다.
     */
    fn cachedb_key_separates_contexts_secrets_and_anchors() {
        let request = query("example.com", RecordType::A);
        let redis = SocketAddr::from(([127, 0, 0, 1], 1));
        let key = |secret: &str, context: &str, set: Vec<Ds>| {
            key_of(
                &cachedb_layer(
                    EmptyMock::new(false),
                    redis,
                    secret,
                    context,
                    vec![anchors(set)],
                ),
                &request,
            )
        };
        let original = key(SECRET, "ctx", vec![ds(1), ds(2)]);
        assert_ne!(
            original,
            key(SECRET, "other", vec![ds(1), ds(2)]),
            "context"
        );
        assert_ne!(
            original,
            key(
                "fedcba9876543210fedcba9876543210",
                "ctx",
                vec![ds(1), ds(2)]
            ),
            "secret"
        );
        assert_ne!(original, key(SECRET, "ctx", vec![ds(1)]), "anchors");
        assert_eq!(
            original,
            key(SECRET, "ctx", vec![ds(2), ds(1), ds(2)]),
            "anchor order"
        );
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
    /** @brief 봉투의 HMAC이 키와 시각과 응답을 모두 덮는지. 하나라도 바뀌면 열리지 않아야 한다. */
    fn cachedb_envelope_binds_key_time_and_response() {
        let layer = offline("ctx");
        let key = key_of(&layer, &query("cache.example", RecordType::A));
        let sealed = layer.seal(&key, 1_700_000_000, b"wire");
        assert_eq!(
            layer.open(&key, &sealed),
            Some((1_700_000_000, b"wire".as_slice()))
        );

        let other_key = key_of(&layer, &query("other.example", RecordType::A));
        assert!(
            layer.open(&other_key, &sealed).is_none(),
            "moved to another key"
        );
        for index in [0, MAC_LEN, MAC_LEN + 8] {
            let mut tampered = sealed.clone();
            tampered[index] ^= 1;
            assert!(layer.open(&key, &tampered).is_none(), "byte {index}");
        }
        assert!(
            layer.open(&key, &sealed[..MAC_LEN + 7]).is_none(),
            "truncated"
        );
        let stranger = cachedb_layer(
            EmptyMock::new(false),
            SocketAddr::from(([127, 0, 0, 1], 1)),
            "fedcba9876543210fedcba9876543210",
            "ctx",
            Vec::new(),
        );
        assert!(stranger.open(&key, &sealed).is_none(), "different secret");
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
        let now = now();
        let wire = response.try_encode().unwrap();

        assert!(CacheDbLayer::decode_value(now + 60, &wire, u32::MAX).is_none());

        let (decoded, elapsed) =
            CacheDbLayer::decode_value(now.saturating_sub(2), &wire, u32::MAX).unwrap();
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
        let wire = response.try_encode().unwrap();

        let (decoded, elapsed) =
            CacheDbLayer::decode_value(now().saturating_sub(2), &wire, 5).unwrap();
        let remaining_cap = 5u64.saturating_sub(elapsed) as u32;
        assert!(
            decoded.answers[0].ttl <= remaining_cap,
            "max_ttl은 삽입 뒤 경과 시간만큼 줄어야 합니다: elapsed={elapsed}, ttl={}",
            decoded.answers[0].ttl
        );
    }

    #[test]
    /** @brief 같은 비밀 키와 맥락과 앵커를 쓰는 서버가 담은 답을 다른 서버가 묻지 않고 쓰는지. */
    fn peer_with_the_same_scope_serves_the_shared_answer() {
        let fake = FakeRedis::start(Behavior::default());
        let request = query("shared.example", RecordType::A);
        let writer_inner = Mock::new(60, 0);
        let writer = cachedb_layer(
            writer_inner.clone(),
            fake.addr,
            SECRET,
            "ctx",
            vec![anchors(vec![ds(1)])],
        );
        assert!(writer.resolve(&request).is_some());
        writer.redis.wait_for_writes();
        assert_eq!(fake.keys().len(), 1);

        let reader_inner = Mock::new(70, 0);
        let reader = cachedb_layer(
            reader_inner.clone(),
            fake.addr,
            SECRET,
            "ctx",
            vec![anchors(vec![ds(1)])],
        );
        let answer = reader.resolve(&request).unwrap();
        assert_eq!(first_a(&answer), Ipv4Addr::new(60, 60, 60, 60));
        assert_eq!(reader_inner.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    /**
     * @brief Redis에 직접 넣은 값을 쓰지 않고, 지운 뒤 제대로 물은 답으로 바꾸는지.
     * @details 비밀 키 없이 만든 값은 HMAC이 맞지 않는다. 엄격한 DNSSEC 검증 아래에서도 검증하지
     *          않은 위조 답이 그대로 나가던 경로다.
     */
    fn forged_value_is_rejected_and_replaced() {
        let fake = FakeRedis::start(Behavior::default());
        let request = query("bank.example", RecordType::A);
        let inner = Mock::new(60, 0);
        let honest = cachedb_layer(inner.clone(), fake.addr, SECRET, "ctx", Vec::new());
        let key = key_of(&honest, &request);

        let q = request.questions[0].clone();
        let forged = answer_message(
            request.header.id,
            q.name.clone(),
            q.qtype,
            vec![Record::new(
                q.name,
                300,
                RData::A(Ipv4Addr::new(203, 0, 113, 66)),
            )],
        );
        let mut value = vec![0u8; MAC_LEN];
        value.extend_from_slice(&now().to_be_bytes());
        value.extend_from_slice(&forged.try_encode().unwrap());
        fake.insert(key.clone(), value);

        let answer = honest.resolve(&request).unwrap();
        assert_eq!(first_a(&answer), Ipv4Addr::new(60, 60, 60, 60));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
        assert_eq!(honest.rejected.load(Ordering::Relaxed), 1);
        honest.redis.wait_for_writes();
        let replaced = fake.value(&key).unwrap();
        assert!(honest.open(&key, &replaced).is_some());
        assert_eq!(
            fake.commands.load(Ordering::Acquire),
            2,
            "the lookup and one store, no separate delete"
        );
    }

    #[test]
    /**
     * @brief 쓸 수 없는 값을 새 답으로 덮지 못하면 지우는지.
     * @details 지우기와 담기를 함께 맡기면 워커에서 순서가 바뀌어 새로 담은 값이 지워질 수 있으므로,
     *          새 답을 담지 못할 때만 지운다.
     */
    fn unusable_value_is_deleted_when_no_new_answer_replaces_it() {
        let fake = FakeRedis::start(Behavior::default());
        let request = query("gone.example", RecordType::A);
        let layer = cachedb_layer(
            Mock::new(60, ResponseCode::NXDomain.0),
            fake.addr,
            SECRET,
            "ctx",
            Vec::new(),
        );
        let key = key_of(&layer, &request);
        fake.insert(key.clone(), b"not an envelope".to_vec());

        assert!(layer.resolve(&request).is_some());
        layer.redis.wait_for_writes();
        assert!(fake.value(&key).is_none());
        assert_eq!(layer.rejected.load(Ordering::Relaxed), 1);
        assert_eq!(fake.commands.load(Ordering::Acquire), 2);
    }

    #[test]
    /** @brief 다른 맥락의 키에 담긴 진짜 값을 이 맥락의 키로 옮겨도 쓰지 않는지. */
    fn genuine_value_moved_to_another_context_is_rejected() {
        let fake = FakeRedis::start(Behavior::default());
        let request = query("moved.example", RecordType::A);
        let unvalidated = cachedb_layer(Mock::new(60, 0), fake.addr, SECRET, "forward", Vec::new());
        assert!(unvalidated.resolve(&request).is_some());
        unvalidated.redis.wait_for_writes();
        let source = key_of(&unvalidated, &request);

        let inner = Mock::new(70, 0);
        let strict = cachedb_layer(
            inner.clone(),
            fake.addr,
            SECRET,
            "forward;dnssec=strict",
            Vec::new(),
        );
        let target = key_of(&strict, &request);
        assert_ne!(source, target);
        fake.insert(target, fake.value(&source).unwrap());

        let answer = strict.resolve(&request).unwrap();
        assert_eq!(first_a(&answer), Ipv4Addr::new(70, 70, 70, 70));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
        assert_eq!(strict.rejected.load(Ordering::Relaxed), 1);
    }

    #[test]
    /** @brief RFC 5011 갱신으로 앵커가 바뀌면 새 이름 공간으로 옮겨 가 이전 앵커로 담긴 답을 쓰지 않는지. */
    fn anchor_update_moves_to_a_new_namespace() {
        let fake = FakeRedis::start(Behavior::default());
        let request = query("anchored.example", RecordType::A);
        let handle = anchors(vec![ds(1)]);
        let inner = Mock::new(60, 0);
        let layer = cachedb_layer(
            inner.clone(),
            fake.addr,
            SECRET,
            "ctx",
            vec![handle.clone()],
        );
        assert!(layer.resolve(&request).is_some());
        layer.redis.wait_for_writes();
        let before = key_of(&layer, &request);
        assert!(fake.value(&before).is_some());

        handle.store(Arc::new(vec![ds(1), ds(2)]));
        let after = key_of(&layer, &request);
        assert_ne!(before, after);
        assert!(layer.resolve(&request).is_some());
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            2,
            "the old namespace must not answer"
        );
        layer.redis.wait_for_writes();
        assert!(fake.value(&after).is_some());
    }

    /** @brief 답하는 도중에 신뢰 앵커를 바꾸는 리졸버. RFC 5011 갱신이 끼어든 상황이다. */
    struct AnchorsChangeDuringResolution {
        /** @brief 바꿀 핸들. */
        handle: Arc<ArcSwap<Vec<Ds>>>,
        /** @brief 실제로 답하는 리졸버. */
        inner: Arc<Mock>,
    }

    impl Resolver for AnchorsChangeDuringResolution {
        /** @brief 앵커를 바꾸고 답한다. */
        fn resolve(&self, req: &Message) -> Option<Message> {
            self.handle.store(Arc::new(vec![ds(9)]));
            self.inner.resolve(req)
        }
    }

    #[test]
    /** @brief 묻는 동안 앵커가 바뀌면 담지 않는지. 어느 앵커로 검증한 답인지 알 수 없다. */
    fn anchor_change_during_resolution_skips_the_store() {
        let fake = FakeRedis::start(Behavior::default());
        let handle = anchors(vec![ds(1)]);
        let inner = Arc::new(AnchorsChangeDuringResolution {
            handle: handle.clone(),
            inner: Mock::new(60, 0),
        });
        let layer = cachedb_layer(inner, fake.addr, SECRET, "ctx", vec![handle]);
        assert!(layer
            .resolve(&query("racing.example", RecordType::A))
            .is_some());
        layer.redis.wait_for_writes();
        assert!(fake.keys().is_empty());
        assert_eq!(fake.commands.load(Ordering::Acquire), 1, "only the lookup");
    }

    #[test]
    /** @brief 담기엔 너무 큰 응답을 오류로 바꿔 담지 않는지. */
    fn cachedb_does_not_store_an_oversized_response() {
        /** @brief 담을 수 없을 만큼 큰 답을 내는 리졸버. */
        struct Oversized;
        impl Resolver for Oversized {
            /** @brief 큰 답을 낸다. */
            fn resolve(&self, req: &Message) -> Option<Message> {
                let q = req.questions.first()?;
                Some(answer_message(
                    req.header.id,
                    q.name.clone(),
                    q.qtype,
                    vec![Record::new(
                        q.name.clone(),
                        300,
                        RData::Unknown(65280, vec![0; 65_500]),
                    )],
                ))
            }
        }
        let fake = FakeRedis::start(Behavior::default());
        let request = query("large.cache.example", RecordType(65280));
        let layer = cachedb_layer(Arc::new(Oversized), fake.addr, SECRET, "ctx", Vec::new());
        assert!(layer.resolve(&request).is_some());
        layer.redis.wait_for_writes();
        assert!(fake.keys().is_empty());
    }
}
