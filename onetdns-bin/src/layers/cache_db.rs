//! Cache layer that shares responses through an external Redis, treated as untrusted storage. Each
//! value carries an HMAC under a shared secret and is dropped when it does not match. The HMAC
//! covers the key too, so a value moved to another key fails.
//!
//! Anyone who can write to Redis can only delete values or replay one stored under the same key
//! within its lifetime; they cannot plant a new answer.

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

type HmacSha256 = Hmac<Sha256>;

/// Bump the version when the key derivation or the value format changes.
const KEY_PREFIX: &str = "onetdns:v4:";
/// 128 bits.
const NAMESPACE_HEX: usize = 32;
const MAC_LEN: usize = 32;
/// Keeps the namespace input apart from the value HMAC input.
const NAMESPACE_LABEL: &[u8] = b"onetdns cachedb namespace\0";
const VALUE_LABEL: &[u8] = b"onetdns cachedb value\0";

/// A response that mismatches the question, is truncated, or lacks the requested answer is not
/// stored; otherwise a planted wrong answer would stick.
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

/// Where this chain's answers sit in the shared cache: only servers with the same secret,
/// resolution context, and current trust anchors see each other's answers.
pub struct CacheDbScope {
    /// Shared by every server using the same Redis; never sent to Redis.
    pub secret: SecretString,
    /// Normalized settings below `CacheDbLayer` that change answers.
    pub context: String,
    /// Trust anchors the lower layers validate with. The recursive resolver's anchors change at run
    /// time through RFC 5011 updates, so the namespace follows the anchors' current contents, not a
    /// file path.
    pub anchors: Vec<Arc<ArcSwap<Vec<Ds>>>>,
}

/// Derived from one set of trust anchors.
struct Namespace {
    /// In the same order as the handles.
    anchors: Vec<Arc<Vec<Ds>>>,
    /// Includes the version and the namespace.
    prefix: Vec<u8>,
}

impl Namespace {
    /// Whether the handles still point at the anchors this was derived from.
    fn is_current(&self, handles: &[Arc<ArcSwap<Vec<Ds>>>]) -> bool {
        self.anchors.len() == handles.len()
            && handles
                .iter()
                .zip(&self.anchors)
                .all(|(handle, anchors)| Arc::ptr_eq(&handle.load(), anchors))
    }

    fn key(&self, request: &Message) -> Option<Vec<u8>> {
        let mut key = self.prefix.clone();
        key.extend_from_slice(&semantic_request_key(request)?);
        Some(key)
    }
}

/// Length-prefixed, so field boundaries stay unambiguous.
fn update_field(mac: &mut HmacSha256, field: &[u8]) {
    mac.update(&(field.len() as u64).to_be_bytes());
    mac.update(field);
}

/// Anchors are sorted and deduplicated, so servers listing the same anchors in another order share
/// answers. Keyed by the secret, so servers with different secrets never share keys.
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

/// Keys include the resolution context and the trust anchors; otherwise this server would use
/// answers stored by a server running a different config.
pub struct CacheDbLayer {
    inner: Arc<dyn Resolver>,
    redis: Arc<RedisClient>,
    /// Caps the Redis expiry; 0 leaves it to the records' TTL.
    expire_secs: u64,
    min_ttl: u32,
    max_ttl: u32,
    /// Holds the secret; cloned for each use.
    keyed: HmacSha256,
    context: String,
    anchors: Vec<Arc<ArcSwap<Vec<Ds>>>>,
    /// Last derived; recomputed when the anchors change.
    namespace: ArcSwap<Namespace>,
    /// Values dropped for a bad HMAC; logged at powers of two.
    rejected: AtomicU64,
}

impl CacheDbLayer {
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

    fn namespace(&self) -> Arc<Namespace> {
        let memo = self.namespace.load();
        if memo.is_current(&self.anchors) {
            return memo;
        }
        let fresh = Arc::new(derive_namespace(&self.keyed, &self.context, &self.anchors));
        self.namespace.store(fresh.clone());
        fresh
    }

    /// Covers the key, the storage time, and the response.
    fn value_mac(&self, key: &[u8], stored_at: u64, wire: &[u8]) -> HmacSha256 {
        let mut mac = self.keyed.clone();
        mac.update(VALUE_LABEL);
        update_field(&mut mac, key);
        mac.update(&stored_at.to_be_bytes());
        mac.update(wire);
        mac
    }

    /// HMAC, storage time, then the response.
    fn seal(&self, key: &[u8], stored_at: u64, wire: &[u8]) -> Vec<u8> {
        let tag = self.value_mac(key, stored_at, wire).finalize().into_bytes();
        let mut value = Vec::with_capacity(MAC_LEN + 8 + wire.len());
        value.extend_from_slice(&tag);
        value.extend_from_slice(&stored_at.to_be_bytes());
        value.extend_from_slice(wire);
        value
    }

    /// Returns the storage time and the response when the HMAC matches.
    fn open<'a>(&self, key: &[u8], value: &'a [u8]) -> Option<(u64, &'a [u8])> {
        let (tag, rest) = value.split_at_checked(MAC_LEN)?;
        let (stored_at, wire) = rest.split_at_checked(8)?;
        let stored_at = u64::from_be_bytes(stored_at.try_into().ok()?);
        self.value_mac(key, stored_at, wire)
            .verify_slice(tag)
            .ok()?;
        Some((stored_at, wire))
    }

    /// Servers sharing the secret never write such values, so someone else is writing to Redis, or
    /// Redis corrupted the value.
    fn note_rejected(&self) {
        let count = self.rejected.fetch_add(1, Ordering::Relaxed) + 1;
        if count.is_power_of_two() {
            onetdns_core::warn!(event = "cachedb.value_rejected", addr = %self.redis.addr(), count = count, "Discarded a shared cache value whose authentication tag did not match; something other than these servers is writing to the shared cache, or the cache corrupted the value");
        }
    }

    /// Ages the records by the time since storing, and caps them so the current max TTL counts from
    /// storage. Rejects a storage time in the future: a value stored by a server whose clock runs
    /// ahead would otherwise live longer by the difference.
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

    /// Fits the cached response to this request; None when it is stale or does not answer it.
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

    /// Applies the TTL bounds and queues the write. Returns whether a write was queued.
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
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /// An unusable cached value is overwritten by the new answer, or deleted when that answer
    /// cannot be stored. Writes are queued without waiting, and one key never gets both a delete
    /// and a store queued.
    ///
    /// Nothing is stored when the trust anchors change during resolution: which anchors validated
    /// the answer is unknown, so it could land in the old anchors' namespace or the reverse.
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

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    /// Differs only in its key tag.
    fn ds(key_tag: u16) -> Ds {
        Ds {
            key_tag,
            algorithm: 8,
            digest_type: 2,
            digest: vec![key_tag as u8; 32],
        }
    }

    fn anchors(set: Vec<Ds>) -> Arc<ArcSwap<Vec<Ds>>> {
        Arc::new(ArcSwap::new(Arc::new(set)))
    }

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

    /// Connects nowhere; for looking at keys and envelopes.
    fn offline(context: &str) -> CacheDbLayer {
        cachedb_layer(
            EmptyMock::new(false),
            SocketAddr::from(([127, 0, 0, 1], 1)),
            SECRET,
            context,
            Vec::new(),
        )
    }

    fn key_of(layer: &CacheDbLayer, request: &Message) -> Vec<u8> {
        layer.namespace().key(request).unwrap()
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    /// Equivalent queries share a key, and the namespace is 128 bits.
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
    /// Anchors are sorted, so a different order alone keeps the same key.
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
    /// Changing any one of them must break it.
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
    /// Otherwise a writer could extend lifetimes.
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
    /// The current max TTL counts from storage, not from the lookup.
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
    /// A value made without the secret fails the HMAC.
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
    /// Queuing the delete and the store together could reorder them in the worker and delete the
    /// new value, so it deletes only when no new answer is stored.
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
    /// Answers stored under the old anchors are not used.
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

    /// As when an RFC 5011 update lands mid-resolution.
    struct AnchorsChangeDuringResolution {
        handle: Arc<ArcSwap<Vec<Ds>>>,
        inner: Arc<Mock>,
    }

    impl Resolver for AnchorsChangeDuringResolution {
        fn resolve(&self, req: &Message) -> Option<Message> {
            self.handle.store(Arc::new(vec![ds(9)]));
            self.inner.resolve(req)
        }
    }

    #[test]
    /// Which anchors validated the answer is unknown.
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
    fn cachedb_does_not_store_an_oversized_response() {
        struct Oversized;
        impl Resolver for Oversized {
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
