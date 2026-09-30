/*!
 * @brief 백엔드가 실패하면 만료된 응답을 내주는 serve-stale 계층.
 */

use std::collections::HashSet;
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use onetdns_core::{LruMap, MutexExt};
use onetdns_proto::{ede_code, Edns, Message, Record, RecordType, ResponseCode};

use super::{cap_message_ttls, outcome_to_option, retarget_message, semantic_request_key};
use crate::native::{ResolveOutcome, Resolver};

#[derive(Clone)]
/** @brief 담아 둔 응답 하나와 그 신선·유예 기한. */
struct StaleEntry {
    /** @brief 담아 둔 응답. */
    response: Message,
    /** @brief 담은 시각. */
    inserted: Instant,
    /** @brief 이때까지는 그냥 신선한 답으로 내보낸다. */
    fresh_until: Instant,
    /** @brief 이때까지는 업스트림이 죽었을 때만 내보낸다. */
    stale_until: Instant,
    /** @brief 담을 때의 원래 수명. */
    original_ttl: Duration,
}

/** @brief 담아 둘 때 쓰는 키. */
type StaleKey = Vec<u8>;
/** @brief 담아 둔 응답들. */
type StaleStore = Arc<Mutex<LruMap<StaleKey, StaleEntry>>>;
/** @brief 동시에 돌릴 갱신 수. */
const MAX_STALE_REFRESHES: usize = 32;
/** @brief 갱신 일 하나. */
type StaleRefreshJob = Box<dyn FnOnce() + Send + 'static>;
/** @brief 갱신 워커 수. */
const STALE_REFRESH_WORKERS: usize = 8;
/** @brief 갱신 워커 풀. */
static STALE_REFRESH_EXECUTOR: OnceLock<mpsc::SyncSender<StaleRefreshJob>> = OnceLock::new();
/** @brief 실행 중인 갱신 수와 그것이 0이 되기를 기다리는 곳. */
type StaleJobs = Arc<(Mutex<usize>, Condvar)>;

/** @brief 갱신이 끝나면 진행 표시를 지우고 기다리는 쪽을 깨우는 것. */
struct StaleRefreshGuard {
    /** @brief 지금 갱신 중인 이름들. */
    inflight: Arc<Mutex<HashSet<StaleKey>>>,
    /** @brief 이 갱신이 맡은 이름. */
    key: StaleKey,
    /** @brief 실행 중인 갱신 수와 그것이 0이 되기를 기다리는 곳. */
    jobs: StaleJobs,
}

impl Drop for StaleRefreshGuard {
    /** @brief 진행 표시를 지우고 깨운다. 지우지 않으면 그 이름은 다시 갱신되지 않는다. */
    fn drop(&mut self) {
        self.inflight.lock_recover().remove(&self.key);
        let (count, wake) = &*self.jobs;
        let mut count = count.lock_recover();
        *count = count.saturating_sub(1);
        wake.notify_all();
    }
}

/** @brief 갱신 워커 풀. 처음 쓸 때 시작한다. */
fn stale_refresh_executor() -> &'static mpsc::SyncSender<StaleRefreshJob> {
    STALE_REFRESH_EXECUTOR.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<StaleRefreshJob>(MAX_STALE_REFRESHES);
        let rx = Arc::new(Mutex::new(rx));
        for index in 0..STALE_REFRESH_WORKERS {
            let rx = rx.clone();
            if let Err(error) = std::thread::Builder::new()
                .name(format!("onetdns-stale-refresh-{index}"))
                .spawn(move || loop {
                    let job = rx.lock_recover().recv();
                    match job {
                        Ok(job) => job(),
                        Err(_) => break,
                    }
                })
            {
                onetdns_core::warn!(event = "cache.stale_refresh_worker_start_failed", %error, index, "만료 응답 갱신 스레드를 시작하지 못해 해당 기능을 일부 비활성화합니다");
                break;
            }
        }
        tx
    })
}

/** @brief 갱신을 맡긴다. 대기열이 꽉 차면 이번 갱신을 건너뛴다. */
fn submit_stale_refresh(job: impl FnOnce() + Send + 'static) -> bool {
    stale_refresh_executor().try_send(Box::new(job)).is_ok()
}

/**
 * @brief 갱신을 맡기지 못했음을 알린다.
 * @details 계속 실패하면 만료 응답이 갱신되지 않은 채 유예 기간 내내 나간다. 질의마다
 *          호출되는 경로라 2의 거듭제곱 번째만 남긴다.
 */
fn stale_refresh_not_submitted() {
    /** @brief 누적 실패 수. */
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::warn!(event = "cache.stale_refresh_dropped", count = count, "갱신 대기열이 꽉 차 만료 응답을 새로 받아 오지 못했습니다. 유예 기간 동안 낡은 답이 그대로 나갑니다");
    }
}

/** @brief 흐른 만큼 수명을 깎고 다한 것은 뺀다. EDNS 유사 레코드는 수명이 아니므로 건드리지 않는다. */
fn age_fresh_records(records: &mut Vec<Record>, elapsed_secs: u64) {
    records.retain_mut(|record| {
        if record.rtype == RecordType::OPT {
            return true;
        }
        let remaining = u64::from(record.ttl).saturating_sub(elapsed_secs);
        if remaining == 0 {
            false
        } else {
            record.ttl = remaining as u32;
            true
        }
    });
}

/**
 * @brief 업스트림이 답하지 못할 때 만료된 답이라도 내보내는 계층.
 * @details 아무 답도 못 주는 것보다 조금 지난 답이 낫다는 판단이다. 유예 기간과 다시
 *          물을 시점은 설정으로 정한다.
 */
pub struct ServeStaleLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 담아 둔 응답들. */
    store: StaleStore,
    /** @brief 만료 뒤에도 내보낼 수 있는 기간. */
    max_stale: Duration,
    /** @brief 담을 때 걸 수명 하한. */
    min_ttl: u32,
    /** @brief 담을 때 걸 수명 상한. */
    max_ttl: u32,
    /** @brief 지난 답을 내보낼 때 담을 수명. */
    reply_ttl: u32,
    /** @brief 다시 물어 성공하면 유예 기한을 처음부터 다시 잡는지. */
    ttl_reset: bool,
    /** @brief 이만큼 지나면 지난 답부터 내보낸다. 없으면 끝까지 기다린다. */
    client_timeout: Option<Duration>,
    /** @brief 만료된 답을 기다림 없이 먼저 내보내고 뒤에서 다시 묻는지. */
    stale_first: bool,
    /** @brief 지금 갱신 중인 이름들. */
    inflight: Arc<Mutex<HashSet<StaleKey>>>,
    /** @brief 이 계층이 사라지고 있다는 표시. */
    stop: Arc<std::sync::atomic::AtomicBool>,
    /** @brief 서버 전체가 끝나고 있다는 표시. */
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    /** @brief 실행 중인 갱신 수와 그것이 0이 되기를 기다리는 곳. */
    jobs: StaleJobs,
}

impl ServeStaleLayer {
    #[allow(clippy::too_many_arguments)]
    /** @brief 유예 기간과 수명 상하한으로 만든다. */
    pub fn new(
        inner: Arc<dyn Resolver>,
        max_stale: Duration,
        cap: usize,
        min_ttl: u32,
        max_ttl: u32,
        reply_ttl: u32,
        ttl_reset: bool,
        client_timeout: Option<Duration>,
        stale_first: bool,
    ) -> Self {
        let cap = cap.max(1);
        ServeStaleLayer {
            inner,
            store: Arc::new(Mutex::new(LruMap::new(cap))),
            max_stale,
            min_ttl,
            max_ttl,
            // RFC 8767은 만료된 레코드의 수명을 0보다 크게 실으라고 정한다. 0으로 내보내면
            // 받은 쪽이 담아 두지 못해 같은 이름을 곧바로 다시 물어, 업스트림이 죽어 있는 동안
            // 질의가 몰린다. 이 기능이 막으려던 상황을 그대로 만든다.
            reply_ttl: reply_ttl.max(1),
            ttl_reset,
            client_timeout: client_timeout.filter(|d| !d.is_zero()),
            stale_first,
            inflight: Arc::new(Mutex::new(HashSet::new())),
            stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            jobs: Arc::new((Mutex::new(0), Condvar::new())),
        }
    }

    /** @brief 종료 신호를 붙인다. 갱신이 종료를 막지 않게 하려는 것이다. */
    pub fn with_shutdown(mut self, shutdown: Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.shutdown = shutdown;
        self
    }

    /**
     * @brief 응답을 담아 둔다.
     * @warning 담을 자격을 확인한다. 질문한 것이 답에 없는 응답을 담으면, 나중에 업스트림이
     *          죽었을 때 그 엉뚱한 답을 내보낸다.
     */
    fn store_answer_shared(
        store: &StaleStore,
        max_stale: Duration,
        min_ttl: u32,
        max_ttl: u32,
        request: &Message,
        key: StaleKey,
        answer: &Message,
    ) {
        if answer.header.rcode != ResponseCode::NoError.0
            || !crate::cache::has_requested_answer(request, &answer.answers)
        {
            return;
        }
        let mut ttl = answer
            .answers
            .iter()
            .filter(|record| record.rtype != RecordType::OPT)
            .map(|record| record.ttl)
            .min()
            .unwrap_or(0)
            .clamp(min_ttl, max_ttl);
        let mut stored = answer.clone();
        for record in &mut stored.answers {
            if record.rtype != RecordType::OPT {
                record.ttl = record.ttl.clamp(min_ttl, max_ttl);
            }
        }
        for record in stored
            .authorities
            .iter_mut()
            .chain(stored.additionals.iter_mut())
        {
            if record.rtype != RecordType::OPT {
                record.ttl = record.ttl.min(max_ttl);
            }
        }
        let Some(dnssec_cap) = crate::cache::cache_dnssec_ttl_cap(
            answer.header.authentic_data,
            &answer.answers,
            &answer.authorities,
            &answer.additionals,
        ) else {
            return;
        };
        ttl = ttl.min(dnssec_cap);
        cap_message_ttls(&mut stored, dnssec_cap);
        if ttl == 0 {
            return;
        }
        let now = Instant::now();
        let fresh_until = now + Duration::from_secs(u64::from(ttl));
        let stale_until = fresh_until + max_stale;
        store.lock_recover().put(
            key,
            StaleEntry {
                response: stored,
                inserted: now,
                fresh_until,
                stale_until,
                original_ttl: Duration::from_secs(u64::from(ttl)),
            },
        );
    }

    /** @brief 응답을 담아 둔다. */
    fn store_answer(&self, request: &Message, key: StaleKey, answer: &Message) {
        Self::store_answer_shared(
            &self.store,
            self.max_stale,
            self.min_ttl,
            self.max_ttl,
            request,
            key,
            answer,
        );
    }

    /** @brief 담아 둔 것을 꺼낸다. 유예 기한까지 지났으면 지운다. */
    fn cached(&self, key: &StaleKey) -> Option<StaleEntry> {
        let now = Instant::now();
        let mut store = self.store.lock_recover();
        let entry = store.get_mut(key)?;
        if entry.stale_until <= now {
            store.pop(key);
            return None;
        }
        Some(entry.clone())
    }

    /** @brief 아직 신선한 답을 흐른 만큼 깎아 낸다. */
    fn build_fresh(&self, request: &Message, entry: &StaleEntry) -> Message {
        let elapsed = Instant::now()
            .saturating_duration_since(entry.inserted)
            .as_secs();
        let mut response = retarget_message(entry.response.clone(), request);
        age_fresh_records(&mut response.answers, elapsed);
        age_fresh_records(&mut response.authorities, elapsed);
        age_fresh_records(&mut response.additionals, elapsed);
        response
    }

    /**
     * @brief 만료된 답을 내보낼 형태로 만든다.
     * @note 설정한 짧은 수명으로 바꿔 단다. 원래 수명 그대로 보내면 클라이언트가 오래
     *       담아 두어 지난 답이 더 오래 산다.
     */
    fn build_stale(&self, request: &Message, entry: &StaleEntry) -> Message {
        let mut response = retarget_message(entry.response.clone(), request);

        response.header.authentic_data = false;
        let now = Instant::now();
        let keep_stale = |records: &mut Vec<Record>| {
            records.retain_mut(|record| {
                if record.rtype == RecordType::OPT {
                    return true;
                }
                let record_ttl = Duration::from_secs(u64::from(record.ttl));
                let record_stale_until = if record_ttl >= entry.original_ttl {
                    entry
                        .stale_until
                        .checked_add(record_ttl - entry.original_ttl)
                } else {
                    entry
                        .stale_until
                        .checked_sub(entry.original_ttl - record_ttl)
                };
                let still_eligible =
                    record_stale_until.is_some_and(|stale_until| stale_until > now);
                if !still_eligible {
                    return false;
                }
                record.ttl = self.reply_ttl;
                true
            });
        };
        keep_stale(&mut response.answers);
        keep_stale(&mut response.authorities);
        keep_stale(&mut response.additionals);
        let mut edns = request
            .opt()
            .and_then(Edns::from_record)
            .unwrap_or_default();
        edns.extended_rcode = 0;
        edns.version = 0;
        edns.options
            .retain(|(code, _)| *code != onetdns_proto::EDE_OPTION);
        edns.push_ede(ede_code::STALE_ANSWER, "stale answer");
        response.additionals.retain(|r| r.rtype != RecordType::OPT);
        response.additionals.push(
            edns.try_to_record()
                .expect("기존 EDNS 옵션을 줄이고 고정 EDE를 추가한 레코드는 인코딩 가능"),
        );
        response
    }

    /** @brief 설정에 따라 유예 기한을 늘린다. */
    fn extend_stale_if_configured(&self, key: &StaleKey) {
        if !self.ttl_reset {
            return;
        }
        if let Some(entry) = self.store.lock_recover().get_mut(key) {
            entry.stale_until = Instant::now() + self.max_stale;
        }
    }

    /** @brief 이 이름의 갱신을 시작한다. 이미 돌고 있으면 시작하지 않는다. */
    fn begin_refresh(&self, key: &StaleKey) -> bool {
        if self.stop.load(std::sync::atomic::Ordering::Relaxed)
            || self.shutdown.load(std::sync::atomic::Ordering::Relaxed)
        {
            return false;
        }
        let mut inflight = self.inflight.lock_recover();
        if inflight.len() >= MAX_STALE_REFRESHES || !inflight.insert(key.clone()) {
            return false;
        }
        let (count, _) = &*self.jobs;
        let mut count = count.lock_recover();
        *count = count.saturating_add(1);
        true
    }

    /** @brief 뒤에서 다시 묻게 맡긴다. */
    fn spawn_refresh(&self, request: Message, key: StaleKey) {
        if !self.begin_refresh(&key) {
            return;
        }
        let inner = self.inner.clone();
        let store = self.store.clone();
        let inflight = self.inflight.clone();
        let jobs = self.jobs.clone();
        let stop = self.stop.clone();
        let shutdown = self.shutdown.clone();
        let max_stale = self.max_stale;
        let min_ttl = self.min_ttl;
        let max_ttl = self.max_ttl;
        let guard = StaleRefreshGuard {
            inflight,
            key: key.clone(),
            jobs,
        };
        let submitted = submit_stale_refresh(move || {
            let _guard = guard;
            if stop.load(std::sync::atomic::Ordering::Relaxed)
                || shutdown.load(std::sync::atomic::Ordering::Relaxed)
            {
                return;
            }
            if let Some(answer) = inner.resolve(&request) {
                if !stop.load(std::sync::atomic::Ordering::Relaxed)
                    && !shutdown.load(std::sync::atomic::Ordering::Relaxed)
                {
                    Self::store_answer_shared(
                        &store,
                        max_stale,
                        min_ttl,
                        max_ttl,
                        &request,
                        key.clone(),
                        &answer,
                    );
                }
            }
        });
        if !submitted {
            stale_refresh_not_submitted();
        }
    }

    /** @brief 데드라인을 걸어 안으로 묻는다. 데드라인을 넘기면 담아 둔 답을 먼저 내보내려는 것이다. */
    fn resolve_with_timeout(
        &self,
        request: &Message,
        key: &StaleKey,
        timeout: Duration,
    ) -> Option<Option<Message>> {
        if !self.begin_refresh(key) {
            return None;
        }
        let (tx, rx) = mpsc::sync_channel(1);
        let inner = self.inner.clone();
        let request_owned = request.clone();
        let store = self.store.clone();
        let inflight = self.inflight.clone();
        let jobs = self.jobs.clone();
        let stop = self.stop.clone();
        let shutdown = self.shutdown.clone();
        let key_owned = key.clone();
        let max_stale = self.max_stale;
        let min_ttl = self.min_ttl;
        let max_ttl = self.max_ttl;
        let guard = StaleRefreshGuard {
            inflight,
            key: key_owned.clone(),
            jobs,
        };
        if !submit_stale_refresh(move || {
            let _guard = guard;
            if stop.load(std::sync::atomic::Ordering::Relaxed)
                || shutdown.load(std::sync::atomic::Ordering::Relaxed)
            {
                return;
            }
            let result = inner.resolve(&request_owned);
            if !stop.load(std::sync::atomic::Ordering::Relaxed)
                && !shutdown.load(std::sync::atomic::Ordering::Relaxed)
            {
                if let Some(answer) = &result {
                    Self::store_answer_shared(
                        &store,
                        max_stale,
                        min_ttl,
                        max_ttl,
                        &request_owned,
                        key_owned.clone(),
                        answer,
                    );
                }
            }
            let _ = tx.send(result);
        }) {
            stale_refresh_not_submitted();
            return Some(None);
        }
        match rx.recv_timeout(timeout) {
            Ok(result) => Some(result),
            Err(mpsc::RecvTimeoutError::Timeout) => Some(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Some(None),
        }
    }
}

impl Drop for ServeStaleLayer {
    /**
     * @brief 실행 중인 갱신이 끝나기를 기다린다.
     * @warning 기다리지 않으면 갱신이 이미 사라진 것을 건드린다.
     */
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let (count, wake) = &*self.jobs;
        let mut count = count.lock_recover();
        while *count != 0 {
            count = wake.wait(count).unwrap_or_else(|error| error.into_inner());
        }
    }
}

impl Resolver for ServeStaleLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, request: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(request))
    }

    /** @brief 신선하면 그대로, 만료됐으면 갱신을 걸고 지난 답을 내보낸다. */
    fn resolve_outcome(&self, request: &Message) -> ResolveOutcome {
        let Some(key) = semantic_request_key(request) else {
            return self.inner.resolve_outcome(request);
        };
        let now = Instant::now();
        let cached = self.cached(&key);

        if let Some(entry) = &cached {
            if entry.fresh_until > now {
                return ResolveOutcome::Response(self.build_fresh(request, entry));
            }
            if self.stale_first && entry.stale_until > now {
                self.spawn_refresh(request.clone(), key.clone());
                return ResolveOutcome::Response(self.build_stale(request, entry));
            }
        }

        if let (Some(entry), Some(timeout)) = (&cached, self.client_timeout) {
            if entry.stale_until > now {
                match self.resolve_with_timeout(request, &key, timeout) {
                    Some(Some(answer)) => return ResolveOutcome::Response(answer),
                    Some(None) | None => {
                        self.extend_stale_if_configured(&key);
                        return ResolveOutcome::Response(self.build_stale(request, entry));
                    }
                }
            }
        }

        match self.inner.resolve_outcome(request) {
            ResolveOutcome::Response(answer) if answer.header.rcode == ResponseCode::ServFail.0 => {
                if let Some(entry) = cached.filter(|entry| entry.stale_until > Instant::now()) {
                    self.extend_stale_if_configured(&key);
                    ResolveOutcome::Response(self.build_stale(request, &entry))
                } else {
                    ResolveOutcome::Response(answer)
                }
            }
            ResolveOutcome::Response(answer) => {
                self.store_answer(request, key, &answer);
                ResolveOutcome::Response(answer)
            }

            failure => match cached.filter(|entry| entry.stale_until > Instant::now()) {
                Some(entry) => {
                    self.extend_stale_if_configured(&key);
                    ResolveOutcome::Response(self.build_stale(request, &entry))
                }
                None => failure,
            },
        }
    }
}

#[cfg(test)]
/** @brief 만료 응답 제공, 갱신, 보관 한도와 TTL 처리. */
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    use onetdns_core::MutexExt;
    use onetdns_proto::{ede_code, Edns, Message, Name, RData, Record, RecordType, ResponseCode};

    use crate::layers::{answer_message, semantic_request_key, MAX_SEMANTIC_KEY_WIRE};
    use crate::native::Resolver;

    /** @brief 처음 한 번만 답하고 이후 실패하는 테스트용 리졸버. */
    struct FailAfterFirst {
        /** @brief 지금까지 답한 횟수. */
        n: AtomicU32,
    }
    impl Resolver for FailAfterFirst {
        /** @brief 미리 정해 둔 응답을 돌려준다. */
        fn resolve(&self, req: &Message) -> Option<Message> {
            let c = self.n.fetch_add(1, Ordering::SeqCst);
            if c == 0 {
                let q = req.questions.first().unwrap();
                let mut m = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
                m.answers.push(Record::new(
                    q.name.clone(),
                    1,
                    RData::A(Ipv4Addr::new(5, 6, 7, 8)),
                ));
                Some(m)
            } else {
                None
            }
        }
    }

    #[test]
    /** @brief 업스트림이 죽었을 때 담아 둔 답을 내보내는지. */
    fn serve_stale_on_failure() {
        let inner = Arc::new(FailAfterFirst {
            n: AtomicU32::new(0),
        });
        let layer = ServeStaleLayer::new(
            inner,
            Duration::from_secs(3600),
            1024,
            0,
            86_400,
            30,
            false,
            None,
            false,
        );

        let r1 = layer.resolve(&query("x.test", RecordType::A)).unwrap();
        assert_eq!(r1.answers.len(), 1);

        std::thread::sleep(Duration::from_millis(1100));

        let r2 = layer.resolve(&query("x.test", RecordType::A)).unwrap();
        assert_eq!(r2.answers.len(), 1);
        match &r2.answers[0].rdata {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(5, 6, 7, 8)),
            _ => panic!("stale A 기대"),
        }
        assert_eq!(r2.answers[0].ttl, 30, "stale은 짧은 TTL");

        let opt = r2.opt().expect("stale 응답에 OPT");
        let (code, _) = Edns::from_record(opt).unwrap().ede().expect("EDE");
        assert_eq!(code, ede_code::STALE_ANSWER);
    }

    #[test]
    /**
     * @brief 응답 수명을 0으로 설정해도 0으로 나가지 않는지.
     *
     * @details RFC 8767은 만료된 레코드의 수명을 0보다 크게 실으라고 정한다. 0이면 받은
     *          쪽이 담아 두지 못해 같은 이름을 곧바로 다시 묻고, 업스트림이 죽어 있는 동안
     *          질의가 몰린다. 이 기능이 막으려던 상황을 그대로 만든다.
     */
    fn serve_stale_reply_ttl_is_never_zero() {
        let layer = ServeStaleLayer::new(
            Mock::new(1, ResponseCode::ServFail.0),
            Duration::from_secs(60),
            16,
            0,
            86_400,
            0,
            false,
            None,
            false,
        );
        let request = query("stale.example", RecordType::A);
        let entry = StaleEntry {
            response: answer_message(
                1,
                Name::from_str("stale.example").unwrap(),
                RecordType::A,
                vec![Record::new(
                    Name::from_str("stale.example").unwrap(),
                    300,
                    RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                )],
            ),
            inserted: Instant::now(),
            fresh_until: Instant::now(),
            stale_until: Instant::now() + Duration::from_secs(60),
            original_ttl: Duration::from_secs(300),
        };

        let response = layer.build_stale(&request, &entry);
        assert_eq!(
            response.answers[0].ttl, 1,
            "0으로 설정해도 1 아래로는 내려가지 않습니다"
        );
    }

    #[test]
    /** @brief 지난 답을 먼저 내보내고 뒤에서 다시 묻는지. */
    fn serve_stale_refresh_serves_stale_then_refreshes() {
        /** @brief 두 번째부터 느리게 답하는 테스트용 리졸버. */
        struct SlowAfterFirst {
            /** @brief 불린 횟수. */
            calls: AtomicU32,
        }
        impl Resolver for SlowAfterFirst {
            /** @brief 미리 정해 둔 응답을 돌려준다. */
            fn resolve(&self, req: &Message) -> Option<Message> {
                let c = self.calls.fetch_add(1, Ordering::SeqCst);
                if c > 0 {
                    std::thread::sleep(Duration::from_millis(80));
                }
                let q = req.questions.first().unwrap();
                let mut m = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
                m.answers.push(Record::new(
                    q.name.clone(),
                    1,
                    RData::A(Ipv4Addr::new(7, 7, 7, 7)),
                ));
                Some(m)
            }
        }
        let inner = Arc::new(SlowAfterFirst {
            calls: AtomicU32::new(0),
        });
        let layer = ServeStaleLayer::new(
            inner.clone(),
            Duration::from_secs(3600),
            1024,
            0,
            86_400,
            11,
            false,
            Some(Duration::from_millis(5)),
            false,
        );

        let r1 = layer.resolve(&query("x.test", RecordType::A)).unwrap();
        assert!(r1.opt().is_none(), "첫 응답은 stale 아님");
        let c1 = inner.calls.load(Ordering::SeqCst);

        std::thread::sleep(Duration::from_millis(1100));

        let r2 = layer.resolve(&query("x.test", RecordType::A)).unwrap();
        assert_eq!(r2.answers[0].ttl, 11, "serve-stale reply TTL");
        let opt = r2.opt().expect("stale 응답 OPT");
        let (code, _) = Edns::from_record(opt).unwrap().ede().expect("EDE");
        assert_eq!(
            code,
            ede_code::STALE_ANSWER,
            "client_timeout 초과 시 즉시 stale 제공"
        );
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            inner.calls.load(Ordering::SeqCst) > c1,
            "백그라운드 갱신이 inner 재호출"
        );
    }

    #[test]
    /** @brief 만료 응답 먼저 보내기를 켜면 기다림 없이 지난 답을 내고 뒤에서 다시 묻는지. */
    fn stale_first_answers_without_waiting_for_upstream() {
        /** @brief 첫 번째 뒤로는 오래 걸리는 테스트용 리졸버. */
        struct SlowAfterFirst {
            /** @brief 불린 횟수. */
            calls: AtomicU32,
        }
        impl Resolver for SlowAfterFirst {
            /** @brief 수명 1초짜리 답을 돌려준다. */
            fn resolve(&self, req: &Message) -> Option<Message> {
                if self.calls.fetch_add(1, Ordering::SeqCst) > 0 {
                    std::thread::sleep(Duration::from_millis(500));
                }
                let q = req.questions.first().unwrap();
                let mut m = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
                m.answers.push(Record::new(
                    q.name.clone(),
                    1,
                    RData::A(Ipv4Addr::new(7, 7, 7, 7)),
                ));
                Some(m)
            }
        }
        let inner = Arc::new(SlowAfterFirst {
            calls: AtomicU32::new(0),
        });
        let layer = ServeStaleLayer::new(
            inner.clone(),
            Duration::from_secs(3600),
            1024,
            0,
            86_400,
            5,
            false,
            None,
            true,
        );
        layer.resolve(&query("y.test", RecordType::A)).unwrap();
        std::thread::sleep(Duration::from_millis(1100));

        let started = Instant::now();
        let stale = layer.resolve(&query("y.test", RecordType::A)).unwrap();
        assert!(started.elapsed() < Duration::from_millis(300));
        assert_eq!(stale.answers[0].ttl, 5);
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    /** @brief 실행 중인 갱신이 끝나기를 기다리고 사라지는지. 안 기다리면 사라진 것을 건드린다. */
    fn dropping_serve_stale_waits_for_active_refresh() {
        /** @brief 신호를 줄 때까지 답하지 않는 테스트용 리졸버. */
        struct BlockingRefresh {
            /** @brief 들어왔음을 알릴 곳. */
            entered: Mutex<Option<std::sync::mpsc::Sender<()>>>,
            /** @brief 놓아 줄 때까지 기다리는 곳. */
            release: Arc<(Mutex<bool>, Condvar)>,
        }
        impl Resolver for BlockingRefresh {
            /** @brief 신호가 올 때까지 멈춰 있는다. */
            fn resolve(&self, _req: &Message) -> Option<Message> {
                if let Some(entered) = self.entered.lock_recover().take() {
                    let _ = entered.send(());
                }
                let (released, wake) = &*self.release;
                let mut released = released.lock_recover();
                while !*released {
                    released = wake
                        .wait(released)
                        .unwrap_or_else(|error| error.into_inner());
                }
                None
            }
        }

        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let layer = ServeStaleLayer::new(
            Arc::new(BlockingRefresh {
                entered: Mutex::new(Some(entered_tx)),
                release: release.clone(),
            }),
            Duration::from_secs(60),
            8,
            0,
            86_400,
            30,
            false,
            None,
            false,
        );
        let request = query("drop-stale.test", RecordType::A);
        let key = semantic_request_key(&request).unwrap();
        layer.spawn_refresh(request, key);
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let (dropped_tx, dropped_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            drop(layer);
            let _ = dropped_tx.send(());
        });
        assert!(dropped_rx.recv_timeout(Duration::from_millis(50)).is_err());
        let (released, wake) = &*release;
        *released.lock_recover() = true;
        wake.notify_all();
        dropped_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[test]
    /** @brief 담는 양이 상한을 지키고 오래된 것부터 밀리는지. */
    fn serve_stale_store_honors_capacity_and_lru_recency() {
        let layer = ServeStaleLayer::new(
            Mock::new(1, ResponseCode::NoError.0),
            Duration::from_secs(3600),
            2,
            0,
            86_400,
            30,
            false,
            None,
            false,
        );
        let a = query("a.test", RecordType::A);
        let b = query("b.test", RecordType::A);
        let c = query("c.test", RecordType::A);
        let a_key = semantic_request_key(&a).unwrap();
        let b_key = semantic_request_key(&b).unwrap();
        let c_key = semantic_request_key(&c).unwrap();

        layer.resolve(&a).unwrap();
        layer.resolve(&b).unwrap();
        layer.resolve(&a).unwrap();
        layer.resolve(&c).unwrap();

        assert!(layer.cached(&a_key).is_some());
        assert!(layer.cached(&b_key).is_none(), "가장 오래 안 쓴 b가 퇴출");
        assert!(layer.cached(&c_key).is_some());
        assert_eq!(layer.store.lock_recover().len(), 2);
    }

    #[test]
    /** @brief 신선 구간이 설정한 수명 상하한을 지키는지. */
    fn serve_stale_fresh_cache_honors_configured_ttl_bounds() {
        let layer = ServeStaleLayer::new(
            Mock::new(1, ResponseCode::NoError.0),
            Duration::from_secs(3600),
            2,
            5,
            5,
            30,
            false,
            None,
            false,
        );
        let request = query("bounded.example", RecordType::A);
        let key = semantic_request_key(&request).unwrap();
        let answer = answer_message(
            1,
            Name::from_str("bounded.example").unwrap(),
            RecordType::A,
            vec![Record::new(
                Name::from_str("bounded.example").unwrap(),
                300,
                RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            )],
        );

        layer.store_answer(&request, key.clone(), &answer);

        let mut store = layer.store.lock_recover();
        let entry = store.get(&key).expect("serve-stale 캐시 저장");
        assert_eq!(entry.original_ttl, Duration::from_secs(5));
        assert_eq!(entry.response.answers[0].ttl, 5);
        assert!(entry.fresh_until <= Instant::now() + Duration::from_secs(5));
    }

    #[test]
    /** @brief 신선 구간이 서명 만료를 넘지 않는지. */
    fn serve_stale_fresh_window_is_capped_by_rrsig_expiration() {
        let layer = ServeStaleLayer::new(
            Mock::new(1, ResponseCode::NoError.0),
            Duration::from_secs(3600),
            2,
            0,
            86_400,
            30,
            false,
            None,
            false,
        );
        let request = query("signed.example", RecordType::A);
        let key = semantic_request_key(&request).unwrap();
        let answer = Record::new(
            Name::from_str("signed.example").unwrap(),
            3600,
            RData::A(Ipv4Addr::new(192, 0, 2, 10)),
        );
        let mut response = answer_message(1, answer.name.clone(), RecordType::A, vec![answer]);
        response.header.authentic_data = true;

        layer.store_answer(&request, key.clone(), &response);
        assert!(
            layer.store.lock_recover().is_empty(),
            "RRSIG 없는 AD 응답은 stale/fresh 캐시에 넣지 않음"
        );

        let signature = rrsig_record_with_lifetime(&response.answers[0], 5);
        response.answers.push(signature);
        layer.store_answer(&request, key.clone(), &response);
        let entry = layer.cached(&key).expect("서명 응답 저장");
        assert!(entry.original_ttl <= Duration::from_secs(5));
        assert!(
            entry.response.answers.iter().all(|record| record.ttl <= 5),
            "캐시 레코드 TTL도 서명 수명 이하여야 함"
        );

        response.header.authentic_data = false;
        layer.store.lock_recover().clear();
        layer.store_answer(&request, key.clone(), &response);
        let entry = layer.cached(&key).expect("AD=0 서명 응답 저장");
        assert!(entry.original_ttl <= Duration::from_secs(5));
        assert!(
            entry.response.answers.iter().all(|record| record.ttl <= 5),
            "AD=0이어도 stale 캐시가 RRSIG 수명을 연장하면 안 됨"
        );
    }

    #[test]
    /** @brief 질문과 무관한 답을 담지 않는지. 담으면 업스트림이 죽었을 때 그것이 나간다. */
    fn serve_stale_rejects_unrelated_lame_answer() {
        /** @brief 질문과 무관한 답을 내는 테스트용 리졸버. */
        struct UnrelatedAnswer {
            /** @brief 불린 횟수. */
            calls: AtomicU32,
        }
        impl Resolver for UnrelatedAnswer {
            /** @brief 무관한 답을 돌려준다. */
            fn resolve(&self, req: &Message) -> Option<Message> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let q = req.questions.first()?;
                let mut response = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
                response.answers.push(Record::new(
                    Name::from_str("attacker.example").unwrap(),
                    300,
                    RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                ));
                Some(response)
            }
        }

        let inner = Arc::new(UnrelatedAnswer {
            calls: AtomicU32::new(0),
        });
        let layer = ServeStaleLayer::new(
            inner.clone(),
            Duration::from_secs(3600),
            16,
            0,
            86_400,
            30,
            false,
            None,
            false,
        );
        let request = query("victim.example", RecordType::A);

        layer.resolve(&request).unwrap();
        layer.resolve(&request).unwrap();
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
        assert!(layer.store.lock_recover().is_empty());
    }

    #[test]
    /** @brief 딸려 온 기록도 제 수명대로 늙어 빠지는지. */
    fn serve_stale_fresh_hit_ages_and_expires_each_additional_rr() {
        /** @brief 딸린 기록의 수명이 짧은 답을 내는 테스트용 리졸버. */
        struct ShortAdditional;
        impl Resolver for ShortAdditional {
            /** @brief 딸린 기록의 수명이 짧은 답을 돌려준다. */
            fn resolve(&self, req: &Message) -> Option<Message> {
                let q = req.questions.first()?;
                let mut response = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
                response.answers.push(Record::new(
                    q.name.clone(),
                    100,
                    RData::A(Ipv4Addr::new(192, 0, 2, 10)),
                ));
                response.additionals.push(Record::new(
                    Name::from_str("ns.victim.example").unwrap(),
                    5,
                    RData::A(Ipv4Addr::new(192, 0, 2, 53)),
                ));
                Some(response)
            }
        }

        let layer = ServeStaleLayer::new(
            Arc::new(ShortAdditional),
            Duration::from_secs(3600),
            16,
            0,
            86_400,
            30,
            false,
            None,
            false,
        );
        let request = query("victim.example", RecordType::A);
        let key = semantic_request_key(&request).unwrap();
        layer.resolve(&request).unwrap();

        layer.store.lock_recover().get_mut(&key).unwrap().inserted =
            Instant::now() - Duration::from_secs(2);
        let aged = layer.resolve(&request).unwrap();
        assert_eq!(aged.additionals[0].ttl, 3);
        assert!(aged.answers[0].ttl <= 98);

        layer.store.lock_recover().get_mut(&key).unwrap().inserted =
            Instant::now() - Duration::from_secs(6);
        let expired = layer.resolve(&request).unwrap();
        assert!(expired.additionals.is_empty());
        assert!(expired.answers[0].ttl <= 94);
    }

    #[test]
    /** @brief 짧은 딸림 레코드가 자기 stale 구간을 넘긴 뒤 다시 살아나지 않는지. */
    fn serve_stale_does_not_resurrect_expired_additional_records() {
        let layer = ServeStaleLayer::new(
            Mock::new(1, ResponseCode::ServFail.0),
            Duration::from_secs(60),
            16,
            0,
            86_400,
            30,
            false,
            None,
            false,
        );
        let request = query("victim.example", RecordType::A);
        let mut response = answer_message(
            request.header.id,
            request.questions[0].name.clone(),
            RecordType::A,
            vec![Record::new(
                request.questions[0].name.clone(),
                100,
                RData::A(Ipv4Addr::new(192, 0, 2, 10)),
            )],
        );
        response.additionals.push(Record::new(
            Name::from_str("ns.victim.example").unwrap(),
            1,
            RData::A(Ipv4Addr::new(192, 0, 2, 53)),
        ));
        let entry = StaleEntry {
            response,
            inserted: Instant::now() - Duration::from_secs(62),
            fresh_until: Instant::now(),
            stale_until: Instant::now() + Duration::from_secs(60),
            original_ttl: Duration::from_secs(100),
        };

        let stale = layer.build_stale(&request, &entry);
        assert_eq!(stale.answers[0].ttl, 30);
        assert!(
            !stale.additionals.iter().any(|record| {
                record.rtype == RecordType::A
                    && record
                        .name
                        .eq_ignore_case(&Name::from_str("ns.victim.example").unwrap())
            }),
            "개별 TTL 1초와 stale 구간 60초를 모두 지난 glue는 되살리면 안 됩니다"
        );
    }

    #[test]
    /** @brief stale 구간 재설정이 주 답만 살리고 훨씬 짧은 딸림 레코드는 되살리지 않는지. */
    fn serve_stale_ttl_reset_preserves_per_record_ttl_offsets() {
        let layer = ServeStaleLayer::new(
            Mock::new(1, ResponseCode::ServFail.0),
            Duration::from_secs(60),
            16,
            0,
            86_400,
            30,
            true,
            None,
            false,
        );
        let request = query("reset.example", RecordType::A);
        let mut response = answer_message(
            request.header.id,
            request.questions[0].name.clone(),
            RecordType::A,
            vec![Record::new(
                request.questions[0].name.clone(),
                100,
                RData::A(Ipv4Addr::new(192, 0, 2, 10)),
            )],
        );
        response.additionals.push(Record::new(
            Name::from_str("ns.reset.example").unwrap(),
            1,
            RData::A(Ipv4Addr::new(192, 0, 2, 53)),
        ));
        let entry = StaleEntry {
            response,
            inserted: Instant::now() - Duration::from_secs(200),
            fresh_until: Instant::now() - Duration::from_secs(100),
            stale_until: Instant::now() + Duration::from_secs(60),
            original_ttl: Duration::from_secs(100),
        };

        let stale = layer.build_stale(&request, &entry);
        assert_eq!(stale.answers.len(), 1, "재설정한 주 답의 stale 구간은 유지");
        assert!(
            !stale
                .additionals
                .iter()
                .any(|record| record.rtype == RecordType::A),
            "주 답보다 99초 짧은 glue까지 전역 창으로 되살리면 안 됩니다"
        );
    }

    #[test]
    /** @brief 별칭 끝에 답이 있으면 담는지. */
    fn serve_stale_accepts_cname_chain_with_terminal_rrset() {
        /** @brief 별칭 체인이 담긴 답을 내는 테스트용 리졸버. */
        struct AliasAnswer {
            /** @brief 불린 횟수. */
            calls: AtomicU32,
        }
        impl Resolver for AliasAnswer {
            /** @brief 별칭 체인이 담긴 답을 돌려준다. */
            fn resolve(&self, req: &Message) -> Option<Message> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let q = req.questions.first()?;
                let target = Name::from_str("target.example").unwrap();
                let mut response = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
                response.answers.push(Record::new(
                    q.name.clone(),
                    100,
                    RData::Cname(target.clone()),
                ));
                response.answers.push(Record::new(
                    target,
                    100,
                    RData::A(Ipv4Addr::new(192, 0, 2, 20)),
                ));
                Some(response)
            }
        }

        let inner = Arc::new(AliasAnswer {
            calls: AtomicU32::new(0),
        });
        let layer = ServeStaleLayer::new(
            inner.clone(),
            Duration::from_secs(3600),
            16,
            0,
            86_400,
            30,
            false,
            None,
            false,
        );
        let request = query("alias.example", RecordType::A);

        assert_eq!(layer.resolve(&request).unwrap().answers.len(), 2);
        assert_eq!(layer.resolve(&request).unwrap().answers.len(), 2);
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    /** @brief 키로 삼기엔 너무 큰 질의도 답은 받는지. */
    fn oversized_semantic_key_bypasses_stale_state_without_dropping_query() {
        let inner = Mock::new(60, ResponseCode::NoError.0);
        let layer = ServeStaleLayer::new(
            inner.clone(),
            Duration::from_secs(3600),
            16,
            0,
            86_400,
            30,
            false,
            None,
            false,
        );
        let mut request = query("large.example", RecordType::A);
        request.additionals.push(Record::new(
            Name::root(),
            0,
            RData::Unknown(65_000, vec![0; MAX_SEMANTIC_KEY_WIRE + 1]),
        ));

        assert!(semantic_request_key(&request).is_none());
        assert!(layer.resolve(&request).is_some());
        assert!(layer.resolve(&request).is_some());
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
        assert!(layer.store.lock_recover().is_empty());
    }

    #[test]
    /** @brief 질의가 아닌 것이 담아 둔 상태를 건드리지 않는지. */
    fn non_query_envelope_bypasses_semantic_state() {
        let inner = Mock::new(60, ResponseCode::NoError.0);
        let layer = ServeStaleLayer::new(
            inner.clone(),
            Duration::from_secs(3600),
            16,
            0,
            86_400,
            30,
            false,
            None,
            false,
        );
        let mut request = query("envelope.example", RecordType::A);
        request.authorities.push(soa_record("example"));

        assert!(semantic_request_key(&request).is_none());
        assert!(layer.resolve(&request).is_some());
        assert!(layer.resolve(&request).is_some());
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
        assert!(layer.store.lock_recover().is_empty());
    }
}
