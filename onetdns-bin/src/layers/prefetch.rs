/*!
 * @brief 만료 전에 인기 있는 응답을 백그라운드에서 갱신하는 계층.
 */

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use onetdns_core::MutexExt;
use onetdns_proto::{Message, ResponseCode};

use super::{outcome_to_option, semantic_request_key};
use crate::native::{ResolveOutcome, Resolver};

/** @brief 수명의 이 비율이 지난 시점. 만료 전에 미리 다시 물으려는 것이다. */
fn refresh_at_pct(now: Instant, ttl: u32, pct: u32) -> Instant {
    let pct = pct.clamp(10, 99) as u64;
    now + Duration::from_secs(((ttl as u64) * pct / 100).max(1))
}

#[derive(Clone)]
/** @brief 미리 다시 물을 이름 하나와 그 시점. */
struct PrefetchEntry {
    /** @brief 이 시각이 지나면 미리 다시 묻는다. */
    refresh_at: Instant,
    /** @brief 이 이름을 물은 횟수. 자주 묻는지 구분한다. */
    hits: u32,
    /** @brief 다시 물을 때 쓸 요청. */
    request: Message,
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
    /** @brief 미리 물을 이름들. */
    tracked: Arc<Mutex<HashMap<Vec<u8>, PrefetchEntry>>>,
    /** @brief 지켜볼 이름 수 상한. */
    cap: usize,
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
        let tracked: Arc<Mutex<HashMap<Vec<u8>, PrefetchEntry>>> =
            Arc::new(Mutex::new(HashMap::new()));
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
                    tracked.retain(|_, entry| entry.refresh_at > now || entry.hits >= min_hits);
                    tracked
                        .iter()
                        .filter(|(_, entry)| entry.refresh_at <= now)
                        .take(MAX_PREFETCH_REFRESH_BATCH)
                        .map(|(key, entry)| (key.clone(), entry.request.clone()))
                        .collect()
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
                                tracked.remove(&key);
                            } else if let Some(entry) = tracked.get_mut(&key) {
                                entry.refresh_at = refresh_at_pct(Instant::now(), ttl, ttl_pct);
                                entry.hits = 0;
                            }
                        }
                        _ => {
                            tracked_bg.lock_recover().remove(&key);
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
            cap: cap.max(1),
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
            let mut t = self.tracked.lock_recover();
            if ttl == 0 {
                t.remove(&key);
                return ResolveOutcome::Response(resp);
            }
            let n = t.len();
            match t.get_mut(&key) {
                Some(e) => {
                    e.hits = e.hits.saturating_add(1);
                    e.refresh_at = refresh_at_pct(Instant::now(), ttl, self.ttl_pct);
                }
                None if n < self.cap => {
                    t.insert(
                        key,
                        PrefetchEntry {
                            refresh_at: refresh_at_pct(Instant::now(), ttl, self.ttl_pct),
                            hits: 1,
                            request: {
                                let mut request = req.clone();
                                request.header.id = 0;
                                request
                            },
                        },
                    );
                }
                None => {}
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
                tracked.insert(
                    semantic_request_key(&request).unwrap(),
                    PrefetchEntry {
                        refresh_at: Instant::now(),
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
        layer.tracked.lock_recover().insert(
            semantic_request_key(&request).unwrap(),
            PrefetchEntry {
                refresh_at: Instant::now(),
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
                let resp = backend.resolve(req)?;
                handle.store(req, &resp);
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
