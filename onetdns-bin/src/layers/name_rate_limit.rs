//! Per-name query rate limit.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use onetdns_core::MutexExt;
use onetdns_proto::{Message, Name, ResponseCode};

use super::{answer_message, now_secs, outcome_to_option};
use crate::native::{ResolveOutcome, Resolver};

/// Random-subdomain floods share the end of the name, so queries are counted by that suffix. Cache
/// hits count too; otherwise a cached name could be flooded without limit.
pub struct NameRateLimitLayer {
    inner: Arc<dyn Resolver>,
    per_sec: u32,
    /// How many labels from the end form the key.
    labels: usize,
    buckets: Mutex<NameRateBuckets>,
    /// Most names counted in one second; new names past it are refused.
    cap: usize,
}

#[derive(Default)]
struct NameRateBuckets {
    window: u64,
    counts: HashMap<Vec<u8>, u32>,
}

impl NameRateLimitLayer {
    pub fn new(inner: Arc<dyn Resolver>, per_sec: u32, labels: usize) -> Self {
        NameRateLimitLayer {
            inner,
            per_sec: per_sec.max(1),
            labels: labels.max(1),
            buckets: Mutex::new(NameRateBuckets::default()),
            cap: 200_000,
        }
    }

    fn key(&self, name: &Name) -> Vec<u8> {
        let mut key = [0u8; 255];
        name.canonical_suffix_key_into(self.labels, &mut key)
            .unwrap_or_default()
            .to_vec()
    }

    fn allow(&self, name: &Name) -> bool {
        let now = now_secs();
        let key = self.key(name);
        let mut b = self.buckets.lock_recover();
        if b.window != now {
            b.window = now;
            b.counts.clear();
        }
        if b.counts.len() >= self.cap && !b.counts.contains_key(&key) {
            return false;
        }
        let count = b.counts.entry(key).or_default();
        *count = count.saturating_add(1);
        *count <= self.per_sec
    }
}

impl Resolver for NameRateLimitLayer {
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        if let Some(q) = req.questions.first() {
            if !self.allow(&q.name) {
                let mut m = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
                m.header.rcode = ResponseCode::ServFail.0;
                return ResolveOutcome::Response(m);
            }
        }
        self.inner.resolve_outcome(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use onetdns_core::MutexExt;
    use onetdns_proto::{Name, RecordType, ResponseCode};

    use crate::native::Resolver;

    #[test]
    fn name_ratelimit_caps_cache_miss_per_name() {
        let inner = Mock::new(7, 0);

        let layer = NameRateLimitLayer::new(inner.clone() as Arc<dyn Resolver>, 3, 2);
        let mut ok = 0;
        let mut limited = 0;
        for i in 0..10 {
            let name = format!("r{i}.victim.com");
            let r = layer.resolve(&query(&name, RecordType::A)).unwrap();
            if r.header.rcode == ResponseCode::ServFail.0 {
                limited += 1;
            } else {
                ok += 1;
            }
        }
        assert_eq!(ok, 3, "한도 3개만 통과");
        assert_eq!(limited, 7, "초과분은 SERVFAIL");
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            3,
            "초과분은 업스트림 미호출"
        );

        let r = layer.resolve(&query("a.other.com", RecordType::A)).unwrap();
        assert_ne!(r.header.rcode, ResponseCode::ServFail.0);
    }

    #[test]
    fn name_ratelimit_includes_response_cache_hits() {
        let inner = Mock::new(7, 0);
        let cache = crate::cache::CacheLayer::new(
            inner.clone() as Arc<dyn Resolver>,
            8,
            1,
            0,
            3_600,
            0,
            3_600,
        );
        let layer = NameRateLimitLayer::new(Arc::new(cache), 1, 2);
        let mut limited = 0;
        for _ in 0..4 {
            let response = layer
                .resolve(&query("hot.victim.example", RecordType::A))
                .unwrap();
            limited += usize::from(response.header.rcode == ResponseCode::ServFail.0);
        }
        assert!(
            limited >= 2,
            "초 경계가 한 번 끼어도 캐시 히트가 이름 제한을 우회하면 안 됨"
        );
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            1,
            "허용된 후속 질의는 응답 캐시에서 처리"
        );
    }

    #[test]
    fn name_ratelimit_full_window_rejects_new_keys_without_dropping_existing_keys() {
        let inner = Mock::new(1, ResponseCode::NoError.0);
        let mut layer = NameRateLimitLayer::new(inner, 2, 2);
        layer.cap = 2;
        let a = Name::from_str("a.example").unwrap();
        let b = Name::from_str("b.example").unwrap();
        let c = Name::from_str("c.example").unwrap();

        assert!(layer.allow(&a));
        assert!(layer.allow(&b));
        assert!(!layer.allow(&c), "포화된 현재 구간의 새 키는 즉시 거부");
        assert!(layer.allow(&a), "이미 추적 중인 키의 남은 예산은 유지");
        assert_eq!(layer.buckets.lock_recover().counts.len(), 2);
    }
}
