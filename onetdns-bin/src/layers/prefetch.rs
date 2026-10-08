/*!
 * @brief 만료 전에 인기 있는 응답을 백그라운드에서 갱신하는 계층.
 */

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use onetdns_core::{LruMap, MutexExt};
use onetdns_proto::{Message, ResponseCode};

use super::{outcome_to_option, semantic_request_key};
use crate::native::{ResolveOutcome, Resolver};

/** @brief 수명의 이 비율이 지난 시점. 만료 전에 미리 다시 물으려는 것이다. */
fn refresh_at_pct(now: Instant, ttl: u32, pct: u32) -> Instant {
    let pct = pct.clamp(10, 99) as u64;
    now + Duration::from_secs(((ttl as u64) * pct / 100).max(1))
}

/**
 * @brief 같은 답에서 구한 만료 시각이 흔들리는 폭.
 * @details 캐시는 흐른 시간을 초 단위로 내림해 TTL 에서 빼서 돌려준다. 그래서 같은 답이면
 *          받은 시각에 남은 TTL 을 더한 만료 시각이 이 폭 안에 든다.
 */
const SAME_ANSWER_DRIFT: Duration = Duration::from_secs(1);

#[derive(Clone)]
/** @brief 미리 다시 물을 이름 하나와 그 시점. */
struct PrefetchEntry {
    /** @brief 이 시각이 지나면 미리 다시 묻는다. */
    refresh_at: Instant,
    /** @brief refresh_at 을 정할 때 본 답이 만료되는 시각. 그 뒤에 본 답이 같은 답인지 가른다. */
    expires_at: Instant,
    /** @brief 이 이름을 물은 횟수. 자주 묻는지 구분한다. */
    hits: u32,
    /** @brief 다시 물을 때 쓸 요청. */
    request: Message,
}

impl PrefetchEntry {
    /** @brief 처음 물은 이름을 지금 받은 답의 수명으로 일정을 잡아 만든다. */
    fn new(now: Instant, ttl: u32, pct: u32, request: Message) -> Self {
        PrefetchEntry {
            refresh_at: refresh_at_pct(now, ttl, pct),
            expires_at: now + Duration::from_secs(u64::from(ttl)),
            hits: 1,
            request,
        }
    }

    /** @brief 지금 받은 답의 수명으로 일정을 다시 잡는다. */
    fn schedule(&mut self, now: Instant, ttl: u32, pct: u32) {
        self.refresh_at = refresh_at_pct(now, ttl, pct);
        self.expires_at = now + Duration::from_secs(u64::from(ttl));
    }

    /** @brief 지금 받은 답이 일정을 잡을 때 본 답과 같은지. 만료 시각으로 가른다. */
    fn same_answer(&self, now: Instant, ttl: u32) -> bool {
        let expires_at = now + Duration::from_secs(u64::from(ttl));
        let drift = expires_at
            .saturating_duration_since(self.expires_at)
            .max(self.expires_at.saturating_duration_since(expires_at));
        drift < SAME_ANSWER_DRIFT
    }
}

/** @brief 한 번에 미리 물을 이름 수. 한꺼번에 다 물면 그때마다 부하가 튄다. */
const MAX_PREFETCH_REFRESH_BATCH: usize = 64;

/**
 * @brief 자주 묻는 이름을 만료 전에 미리 다시 묻는 계층.
 * @details 만료 직후 처음 묻는 클라이언트가 업스트림 왕복을 기다리지 않게 하려는 것이다.
 * @warning 자주 묻는 것만 대상으로 삼는다. 전부 미리 물으면 이 서버가 업스트림에 부하를 만든다.
 */
pub struct PrefetchLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /**
     * @brief 미리 물을 이름들. 꽉 차면 가장 오래 묻지 않은 이름을 밀어낸다.
     * @details 꽉 찼을 때 새 이름을 받지 않으면, 한 번 묻고 만 이름들이 만기까지 자리를 지켜
     *          그동안 자주 묻기 시작한 이름이 들어오지 못한다.
     */
    tracked: Arc<Mutex<LruMap<Vec<u8>, PrefetchEntry>>>,
    /** @brief 수명의 이 비율이 지나면 미리 다시 묻는다. */
    ttl_pct: u32,
    /** @brief 뒤에서 실행 중인 것을 끝내라는 표시. */
    stop: Arc<std::sync::atomic::AtomicBool>,
    /** @brief 미리 묻기를 실행하는 스레드. */
    worker: Option<std::thread::JoinHandle<()>>,
}

/** @brief 미리 물을 때 부를 함수. */
pub type PrefetchRefresher = Arc<dyn Fn(&Message) -> Option<Message> + Send + Sync>;

impl PrefetchLayer {
    /** @brief 대상 판단 기준과 갱신 시점으로 만든다. */
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
                                /* 미리 묻는 것은 클라이언트가 물은 것이 아니므로 밀어내는 순서를
                                 * 올리지 않는다. */
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
    /** @brief 뒤에서 실행 중인 갱신을 깨워 끝낸다. */
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
    }
}

impl Resolver for PrefetchLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 답을 넘기면서 자주 묻는 이름이면 갱신 대상으로 올린다. */
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
                    /* 캐시 적중은 남은 TTL 을 돌려준다. 같은 답인데도 그것으로 일정을 다시 잡으면
                     * 물을 때마다 갱신 시점이 뒤로 밀려, 자주 묻는 이름일수록 만료 전에 갱신되지
                     * 않는다. */
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
/** @brief 갱신 대상 선정, 한 주기 작업 한도, 종료 시 정리. */
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

    /** @brief 그대로 넘기는 테스트용 갱신 함수. */
    fn passthrough_refresher(inner: Arc<dyn Resolver>) -> PrefetchRefresher {
        Arc::new(move |req: &Message| inner.resolve(req))
    }

    #[test]
    /** @brief 자주 묻는 이름만 미리 묻는 대상이 되는지. */
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
    /** @brief 수명이 0인 답을 미리 묻는 대상으로 삼지 않는지. */
    fn prefetch_never_tracks_zero_ttl_answers() {
        /** @brief 수명이 0인 답을 내는 테스트용 리졸버. */
        struct ZeroTtlAnswer;
        impl Resolver for ZeroTtlAnswer {
            /** @brief 수명이 0인 답을 돌려준다. */
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
    /** @brief 한 번에 미리 묻는 양이 상한을 지키는지. 안 지키면 그때마다 부하가 튄다. */
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
    /** @brief 수명이 0이 된 항목을 대상에서 빼는지. */
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
    /** @brief 만료 전에 미리 다시 물어 담아 두는지. */
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
    /**
     * @brief 쉬지 않고 묻는 이름도 만료 전에 갱신하는지.
     * @details 캐시 적중이 돌려주는 남은 TTL 로 일정을 다시 잡으면 물을 때마다 갱신 시점이
     *          뒤로 밀려, 묻는 동안에는 한 번도 갱신하지 않고 만료된다.
     */
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

        /* 답의 수명이 4초이므로 2초에 갱신해야 한다. 만료 전인 3.5초까지 50ms 마다 묻는다. */
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
    /** @brief 캐시가 다른 답을 받았으면 그 답의 수명으로 일정을 다시 잡는지. */
    fn prefetch_reschedules_when_the_cache_holds_a_different_answer() {
        /** @brief 테스트가 정한 TTL 로 답하는 리졸버. */
        struct SettableTtl(std::sync::atomic::AtomicU32);
        impl Resolver for SettableTtl {
            /** @brief 지금 정해 둔 TTL 로 답한다. */
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

        /* 캐시를 비운 뒤 다시 받은 답에 10초만 남았다. 처음 잡은 90초 뒤에 갱신하면 그 전에
         * 답이 만료된다. */
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
    /** @brief 지켜볼 이름이 꽉 차도 새로 묻는 이름이 들어오고, 계속 묻는 이름은 남는지. */
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

        /* 한 번만 물은 이름이 들어올 때마다, 그 사이에 다시 물은 이름 대신 오래된 이름이 나간다. */
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
    /**
     * @brief 미리 물은 것으로는 이름이 밀려나지 않게 되지 않는지.
     * @details 최소 적중 횟수가 0이면 아무도 묻지 않는 이름도 계속 미리 묻는다. 그 갱신이
     *          밀어내는 순서를 올리면 클라이언트가 방금 물은 이름이 대신 밀려난다.
     */
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

        /* 갱신하고 일정까지 고친 것을 본 뒤에 넘어간다. 그 전에 넘어가면 밀어내는 순서를
         * 올리는 갱신도 이 테스트를 통과한다. */
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
    /** @brief 사라질 때 뒤에서 실행 중인 것이 깨어나 끝나는지. */
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
