//! Refreshes popular answers in the background before they expire.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use onetdns_core::{LruMap, MutexExt};
use onetdns_proto::{Message, ResponseCode};

use super::{outcome_to_option, semantic_request_key};
use crate::native::{ResolveOutcome, Resolver};

/// When `pct` percent of the TTL has passed, clamped to 10–99.
fn refresh_at_pct(now: Instant, ttl: u32, pct: u32) -> Instant {
    let pct = pct.clamp(10, 99) as u64;
    now + Duration::from_secs(((ttl as u64) * pct / 100).max(1))
}

/// How far the expiry derived from one answer can drift. The cache rounds the elapsed time down to
/// whole seconds before subtracting it from the TTL, so for the same answer, receive time plus
/// remaining TTL stays within this.
const SAME_ANSWER_DRIFT: Duration = Duration::from_secs(1);

#[derive(Clone)]
struct PrefetchEntry {
    refresh_at: Instant,
    /// Expiry of the answer `refresh_at` was set from; tells whether a later answer is the same
    /// one.
    expires_at: Instant,
    hits: u32,
    request: Message,
}

impl PrefetchEntry {
    fn new(now: Instant, ttl: u32, pct: u32, request: Message) -> Self {
        PrefetchEntry {
            refresh_at: refresh_at_pct(now, ttl, pct),
            expires_at: now + Duration::from_secs(u64::from(ttl)),
            hits: 1,
            request,
        }
    }

    fn schedule(&mut self, now: Instant, ttl: u32, pct: u32) {
        self.refresh_at = refresh_at_pct(now, ttl, pct);
        self.expires_at = now + Duration::from_secs(u64::from(ttl));
    }

    /// Judged by expiry time.
    fn same_answer(&self, now: Instant, ttl: u32) -> bool {
        let expires_at = now + Duration::from_secs(u64::from(ttl));
        let drift = expires_at
            .saturating_duration_since(self.expires_at)
            .max(self.expires_at.saturating_duration_since(expires_at));
        drift < SAME_ANSWER_DRIFT
    }
}

/// Refreshing every due name at once would spike the load.
const MAX_PREFETCH_REFRESH_BATCH: usize = 64;

/// So the first client after expiry does not wait for an upstream round trip. Only popular names
/// qualify; prefetching everything would load the upstreams.
pub struct PrefetchLayer {
    inner: Arc<dyn Resolver>,
    /// Least recently asked names are evicted when full. Refusing new names instead would let names
    /// asked once hold their slots until expiry and keep out names that became popular meanwhile.
    tracked: Arc<Mutex<LruMap<Vec<u8>, PrefetchEntry>>>,
    ttl_pct: u32,
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

pub type PrefetchRefresher = Arc<dyn Fn(&Message) -> Option<Message> + Send + Sync>;

impl PrefetchLayer {
    pub fn with_policy(
        inner: Arc<dyn Resolver>,
        refresh: PrefetchRefresher,
        tick: Duration,
        cap: usize,
        min_hits: u32,
        ttl_pct: u32,
        shutdown: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        let ttl_pct = ttl_pct.clamp(10, 99);
        let tick = tick.max(Duration::from_millis(100));
        let tracked = Arc::new(Mutex::new(LruMap::<Vec<u8>, PrefetchEntry>::new(cap)));
        let refresh_bg = refresh;
        let tracked_bg = tracked.clone();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_bg = stop.clone();
        let worker = match std::thread::Builder::new()
            .name("onetdns-prefetch".into())
            .spawn(move || loop {
                std::thread::park_timeout(tick);
                if shutdown.load(std::sync::atomic::Ordering::Relaxed)
                    || stop_bg.load(std::sync::atomic::Ordering::Relaxed)
                {
                    break;
                }
                let now = Instant::now();

                let due: Vec<(Vec<u8>, Message)> = {
                    let mut tracked = tracked_bg.lock_recover();
                    let mut due = Vec::new();
                    tracked.retain(|key, entry| {
                        if entry.refresh_at > now {
                            return true;
                        }
                        if entry.hits < min_hits {
                            return false;
                        }
                        if due.len() < MAX_PREFETCH_REFRESH_BATCH {
                            due.push((key.clone(), entry.request.clone()));
                        }
                        true
                    });
                    due
                };
                for (key, request) in due {
                    if stop_bg.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    match refresh_bg(&request) {
                        Some(answer) if !answer.answers.is_empty() => {
                            let ttl = answer
                                .answers
                                .iter()
                                .map(|record| record.ttl)
                                .min()
                                .unwrap_or(0);
                            let mut tracked = tracked_bg.lock_recover();
                            if ttl == 0 {
                                tracked.pop(&key);
                            } else if let Some(entry) = tracked.peek_mut(&key) {
                                // A prefetch is not a client query, so it does not bump the
                                // eviction order.
                                entry.schedule(Instant::now(), ttl, ttl_pct);
                                entry.hits = 0;
                            }
                        }
                        _ => {
                            tracked_bg.lock_recover().pop(&key);
                        }
                    }
                }
            }) {
            Ok(handle) => Some(handle),
            Err(error) => {
                onetdns_core::warn!(event = "cache.prefetch_worker_start_failed", %error, "Could not start the prefetch thread; prefetch is disabled");
                None
            }
        };
        PrefetchLayer {
            inner,
            tracked,
            ttl_pct,
            stop,
            worker,
        }
    }
}

impl Drop for PrefetchLayer {
    /// Wakes the worker so it exits.
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
    }
}

impl Resolver for PrefetchLayer {
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        let resp = match self.inner.resolve_outcome(req) {
            ResolveOutcome::Response(resp) => resp,
            failure => return failure,
        };
        if resp.header.rcode == ResponseCode::NoError.0
            && !resp.answers.is_empty()
            && !req.questions.is_empty()
        {
            let ttl = resp.answers.iter().map(|r| r.ttl).min().unwrap_or(0);
            let Some(key) = semantic_request_key(req) else {
                return ResolveOutcome::Response(resp);
            };
            let mut tracked = self.tracked.lock_recover();
            if ttl == 0 {
                tracked.pop(&key);
                return ResolveOutcome::Response(resp);
            }
            let now = Instant::now();
            match tracked.get_mut(&key) {
                Some(entry) => {
                    entry.hits = entry.hits.saturating_add(1);
                    // Cache hits return the remaining TTL. Rescheduling from it for the same answer
                    // would push the refresh back on every query, so the more popular a name, the
                    // less likely it is refreshed before expiry.
                    if !entry.same_answer(now, ttl) {
                        entry.schedule(now, ttl, self.ttl_pct);
                    }
                }
                None => {
                    let mut request = req.clone();
                    request.header.id = 0;
                    tracked.put(key, PrefetchEntry::new(now, ttl, self.ttl_pct, request));
                }
            }
        }
        ResolveOutcome::Response(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use onetdns_core::MutexExt;
    use onetdns_proto::{Message, RData, Record, RecordType, ResponseCode};

    use crate::layers::{answer_message, semantic_request_key};
    use crate::native::Resolver;

    fn passthrough_refresher(inner: Arc<dyn Resolver>) -> PrefetchRefresher {
        Arc::new(move |req: &Message| inner.resolve(req))
    }

    #[test]
    fn prefetch_popularity_gate() {
        let inner = Mock::new(1, ResponseCode::NoError.0);
        let layer = PrefetchLayer::with_policy(
            inner.clone(),
            passthrough_refresher(inner.clone()),
            Duration::from_millis(40),
            1024,
            2,
            10,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );

        layer.resolve(&query("rare.test", RecordType::A));
        assert_eq!(layer.tracked.lock_recover().len(), 1, "질의 직후 추적됨");
        std::thread::sleep(Duration::from_millis(1300));
        let tracked = layer.tracked.lock_recover().len();
        assert_eq!(
            tracked, 0,
            "인기 미달(hits<min_hits) 항목은 만기 시 추적 해제"
        );
    }

    #[test]
    fn prefetch_never_tracks_zero_ttl_answers() {
        struct ZeroTtlAnswer;
        impl Resolver for ZeroTtlAnswer {
            fn resolve(&self, req: &Message) -> Option<Message> {
                let question = req.questions.first()?;
                Some(answer_message(
                    req.header.id,
                    question.name.clone(),
                    question.qtype,
                    vec![Record::new(
                        question.name.clone(),
                        0,
                        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                    )],
                ))
            }
        }

        let backend: Arc<dyn Resolver> = Arc::new(ZeroTtlAnswer);
        let layer = PrefetchLayer::with_policy(
            backend.clone(),
            passthrough_refresher(backend),
            Duration::from_secs(3600),
            16,
            1,
            50,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );

        layer.resolve(&query("zero.example", RecordType::A));

        assert!(
            layer.tracked.lock_recover().is_empty(),
            "캐시할 수 없는 TTL=0 응답을 prefetch가 추적하면 안 됨"
        );
    }

    #[test]
    fn prefetch_refresh_work_is_bounded_per_cycle() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let refresh_calls = calls.clone();
        let refresher: PrefetchRefresher = Arc::new(move |_| {
            refresh_calls.fetch_add(1, Ordering::SeqCst);
            None
        });
        let layer = PrefetchLayer::with_policy(
            Mock::new(60, ResponseCode::NoError.0),
            refresher,
            Duration::from_secs(3600),
            MAX_PREFETCH_REFRESH_BATCH + 1,
            1,
            50,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );
        {
            let mut tracked = layer.tracked.lock_recover();
            for index in 0..=MAX_PREFETCH_REFRESH_BATCH {
                let request = query(&format!("due-{index}.example"), RecordType::A);
                tracked.put(
                    semantic_request_key(&request).unwrap(),
                    PrefetchEntry {
                        refresh_at: Instant::now(),
                        expires_at: Instant::now(),
                        hits: 1,
                        request,
                    },
                );
            }
        }

        layer.worker.as_ref().unwrap().thread().unpark();
        for _ in 0..100 {
            if calls.load(Ordering::SeqCst) >= MAX_PREFETCH_REFRESH_BATCH {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(20));

        assert_eq!(
            calls.load(Ordering::SeqCst),
            MAX_PREFETCH_REFRESH_BATCH,
            "한 prefetch 주기가 캐시 전체를 한꺼번에 갱신하면 안 됨"
        );
        assert_eq!(layer.tracked.lock_recover().len(), 1);
    }

    #[test]
    fn prefetch_refresh_drops_entry_when_ttl_becomes_zero() {
        let refresher: PrefetchRefresher = Arc::new(|request| {
            let question = request.questions.first()?;
            Some(answer_message(
                request.header.id,
                question.name.clone(),
                question.qtype,
                vec![Record::new(
                    question.name.clone(),
                    0,
                    RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                )],
            ))
        });
        let layer = PrefetchLayer::with_policy(
            Mock::new(60, ResponseCode::NoError.0),
            refresher,
            Duration::from_secs(3600),
            1,
            1,
            50,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );
        let request = query("expires-now.example", RecordType::A);
        layer.tracked.lock_recover().put(
            semantic_request_key(&request).unwrap(),
            PrefetchEntry {
                refresh_at: Instant::now(),
                expires_at: Instant::now(),
                hits: 1,
                request,
            },
        );

        layer.worker.as_ref().unwrap().thread().unpark();
        for _ in 0..100 {
            if layer.tracked.lock_recover().is_empty() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("TTL=0으로 바뀐 prefetch 항목이 제거되지 않았습니다");
    }

    #[test]
    fn prefetch_rewarms_cache_before_expiry() {
        let backend = Mock::new(2, ResponseCode::NoError.0);
        let cache = Arc::new(
            crate::cache::CacheLayer::new(backend.clone(), 1024, 1, 0, 10, 0, 10)
                .with_positive_cache(true),
        );
        let handle = cache.handle();
        let refresher: PrefetchRefresher = {
            let backend = backend.clone();
            Arc::new(move |req: &Message| {
                let epoch = handle.epoch();
                let resp = backend.resolve(req)?;
                handle.store(epoch, req, &resp);
                Some(resp)
            })
        };
        let layer = PrefetchLayer::with_policy(
            cache,
            refresher,
            Duration::from_millis(100),
            1024,
            1,
            50,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );
        layer.resolve(&query("hot.test", RecordType::A));
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1, "최초 미스 1회");

        std::thread::sleep(Duration::from_millis(1300));
        assert_eq!(
            backend.calls.load(Ordering::SeqCst),
            2,
            "만료(2s) 전 프리패치가 캐시를 우회해 재해석"
        );
    }

    #[test]
    fn prefetch_hot_name_refreshes_before_expiry() {
        let backend = Mock::new(4, ResponseCode::NoError.0);
        let cache = Arc::new(
            crate::cache::CacheLayer::new(backend.clone(), 1024, 1, 0, 10, 0, 10)
                .with_positive_cache(true),
        );
        let handle = cache.handle();
        let refreshes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let refresher: PrefetchRefresher = {
            let backend = backend.clone();
            let refreshes = refreshes.clone();
            Arc::new(move |req: &Message| {
                let epoch = handle.epoch();
                let resp = backend.resolve(req)?;
                handle.store(epoch, req, &resp);
                refreshes.fetch_add(1, Ordering::SeqCst);
                Some(resp)
            })
        };
        let layer = PrefetchLayer::with_policy(
            cache,
            refresher,
            Duration::from_millis(100),
            1024,
            1,
            50,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );

        // The answer lives 4 s, so it must refresh at 2 s; queries run every 50 ms until 3.5 s,
        // before it expires.
        let request = query("hot.test", RecordType::A);
        let start = Instant::now();
        layer.resolve(&request);
        while refreshes.load(Ordering::SeqCst) == 0 && start.elapsed() < Duration::from_millis(3500)
        {
            std::thread::sleep(Duration::from_millis(50));
            layer.resolve(&request);
        }

        assert_eq!(
            refreshes.load(Ordering::SeqCst),
            1,
            "계속 묻는 이름이 만료 전에 갱신되지 않았습니다"
        );
        assert_eq!(
            backend.calls.load(Ordering::SeqCst),
            2,
            "대조군이 무효입니다: 첫 질의 뒤의 질의는 캐시가 답해야 합니다"
        );
    }

    #[test]
    fn prefetch_reschedules_when_the_cache_holds_a_different_answer() {
        struct SettableTtl(std::sync::atomic::AtomicU32);
        impl Resolver for SettableTtl {
            fn resolve(&self, req: &Message) -> Option<Message> {
                let question = req.questions.first()?;
                Some(answer_message(
                    req.header.id,
                    question.name.clone(),
                    question.qtype,
                    vec![Record::new(
                        question.name.clone(),
                        self.0.load(Ordering::SeqCst),
                        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                    )],
                ))
            }
        }

        let backend = Arc::new(SettableTtl(std::sync::atomic::AtomicU32::new(100)));
        let layer = PrefetchLayer::with_policy(
            backend.clone(),
            passthrough_refresher(backend.clone()),
            Duration::from_secs(3600),
            16,
            1,
            90,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );
        let request = query("moved.test", RecordType::A);
        let key = semantic_request_key(&request).unwrap();
        layer.resolve(&request);
        let first = layer.tracked.lock_recover().peek(&key).unwrap().refresh_at;

        // After the flush, the new answer has only 10 s left; refreshing on the first schedule, at
        // 90 s, would come after it expires.
        backend.0.store(10, Ordering::SeqCst);
        layer.resolve(&request);

        let tracked = layer.tracked.lock_recover();
        let entry = tracked.peek(&key).unwrap();
        assert!(
            entry.refresh_at < first && entry.refresh_at <= Instant::now() + Duration::from_secs(9),
            "다른 답을 받았는데 처음 답의 일정대로 갱신합니다"
        );
        assert_eq!(entry.hits, 2);
    }

    #[test]
    fn prefetch_hot_name_replaces_cold_entry() {
        let inner = Mock::new(60, ResponseCode::NoError.0);
        let layer = PrefetchLayer::with_policy(
            inner.clone(),
            passthrough_refresher(inner),
            Duration::from_secs(3600),
            2,
            1,
            90,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );
        let key = |name: &str| semantic_request_key(&query(name, RecordType::A)).unwrap();

        layer.resolve(&query("cold-1.test", RecordType::A));
        layer.resolve(&query("cold-2.test", RecordType::A));
        layer.resolve(&query("hot.test", RecordType::A));
        assert!(
            layer.tracked.lock_recover().contains_key(&key("hot.test")),
            "꽉 찬 뒤에 묻기 시작한 이름을 받지 않습니다"
        );

        // Each name asked once evicts an old name, not the one asked again meanwhile.
        layer.resolve(&query("cold-3.test", RecordType::A));
        layer.resolve(&query("hot.test", RecordType::A));
        layer.resolve(&query("cold-4.test", RecordType::A));

        let tracked = layer.tracked.lock_recover();
        assert_eq!(
            tracked.peek(&key("hot.test")).map(|entry| entry.hits),
            Some(2),
            "계속 묻는 이름이 한 번만 물은 이름에 밀려났습니다"
        );
        assert!(tracked.contains_key(&key("cold-4.test")));
        assert_eq!(tracked.len(), 2);
    }

    #[test]
    /// With a minimum hit count of 0, names nobody asks keep being prefetched. If those refreshes
    /// bumped the eviction order, a name a client just asked would be evicted instead.
    fn prefetch_refresh_does_not_keep_an_unasked_name() {
        let inner = Mock::new(60, ResponseCode::NoError.0);
        let layer = PrefetchLayer::with_policy(
            inner.clone(),
            passthrough_refresher(inner),
            Duration::from_secs(3600),
            2,
            0,
            90,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );
        let key = |name: &str| semantic_request_key(&query(name, RecordType::A)).unwrap();
        layer.tracked.lock_recover().put(
            key("unasked.test"),
            PrefetchEntry {
                refresh_at: Instant::now(),
                expires_at: Instant::now(),
                hits: 0,
                request: query("unasked.test", RecordType::A),
            },
        );
        layer.resolve(&query("asked.test", RecordType::A));

        // Moves on only after the refresh and reschedule are seen; otherwise a refresh that bumps
        // the eviction order would pass too.
        layer.worker.as_ref().unwrap().thread().unpark();
        let refreshed = || {
            layer
                .tracked
                .lock_recover()
                .peek(&key("unasked.test"))
                .is_some_and(|entry| entry.refresh_at > Instant::now())
        };
        for _ in 0..100 {
            if refreshed() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            refreshed(),
            "대조군이 무효입니다: 만기가 된 이름을 미리 묻지 않았습니다"
        );

        layer.resolve(&query("new.test", RecordType::A));
        let tracked = layer.tracked.lock_recover();
        assert!(
            tracked.contains_key(&key("asked.test")),
            "미리 물은 이름 대신 클라이언트가 물은 이름이 밀려났습니다"
        );
        assert!(!tracked.contains_key(&key("unasked.test")));
    }

    #[test]
    fn dropping_prefetch_layer_wakes_and_releases_background_state() {
        let inner = Mock::new(60, ResponseCode::NoError.0);
        let layer = PrefetchLayer::with_policy(
            inner.clone(),
            passthrough_refresher(inner),
            Duration::from_secs(3600),
            16,
            1,
            50,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );
        let tracked = Arc::downgrade(&layer.tracked);
        drop(layer);

        for _ in 0..100 {
            if tracked.upgrade().is_none() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("prefetch layer drop 후 background worker가 상태를 계속 보유함");
    }
}
