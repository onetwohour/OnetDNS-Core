//! RFC 8767 serve-stale: answers with expired responses when the backend fails.

use std::collections::HashSet;
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use onetdns_core::{LruMap, MutexExt};
use onetdns_proto::{ede_code, Edns, Message, Record, RecordType, ResponseCode};

use super::{cap_message_ttls, outcome_to_option, retarget_message, semantic_request_key};
use crate::native::{ResolveOutcome, Resolver};

#[derive(Clone)]
struct StaleEntry {
    response: Message,
    inserted: Instant,
    /// Served as a normal fresh answer until then.
    fresh_until: Instant,
    /// Until then, served only when the upstream fails.
    stale_until: Instant,
    original_ttl: Duration,
}

type StaleKey = Vec<u8>;
type StaleStore = Arc<Mutex<LruMap<StaleKey, StaleEntry>>>;
/// Cap on refreshes in flight; also the queue length.
const MAX_STALE_REFRESHES: usize = 32;
type StaleRefreshJob = Box<dyn FnOnce() + Send + 'static>;
const STALE_REFRESH_WORKERS: usize = 8;
static STALE_REFRESH_EXECUTOR: OnceLock<mpsc::SyncSender<StaleRefreshJob>> = OnceLock::new();
/// Running refresh count, and the condvar waiting for it to reach 0.
type StaleJobs = Arc<(Mutex<usize>, Condvar)>;

/// Clears the in-flight mark and wakes waiters when a refresh ends.
struct StaleRefreshGuard {
    inflight: Arc<Mutex<HashSet<StaleKey>>>,
    key: StaleKey,
    jobs: StaleJobs,
}

impl Drop for StaleRefreshGuard {
    /// A mark left behind would keep that name from ever refreshing again.
    fn drop(&mut self) {
        self.inflight.lock_recover().remove(&self.key);
        let (count, wake) = &*self.jobs;
        let mut count = count.lock_recover();
        *count = count.saturating_sub(1);
        wake.notify_all();
    }
}

/// Started on first use.
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
                onetdns_core::warn!(event = "cache.stale_refresh_worker_start_failed", %error, index, "Could not start the stale-answer refresh thread; part of serve-stale is disabled");
                break;
            }
        }
        tx
    })
}

/// Skips this refresh when the queue is full.
fn submit_stale_refresh(job: impl FnOnce() + Send + 'static) -> bool {
    stale_refresh_executor().try_send(Box::new(job)).is_ok()
}

/// Persistent failures mean the stale answer is served unrefreshed for the whole grace period. Runs
/// per query, so only powers of two are logged.
fn stale_refresh_not_submitted() {
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::warn!(event = "cache.stale_refresh_dropped", count = count, "Refresh queue is full, so a stale answer was not refreshed; the old answer is served until the grace period ends");
    }
}

/// Reduces TTLs by the time passed and drops expired records; OPT is left alone, since its TTL
/// field is not a TTL.
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

/// Serves an expired answer when the upstream cannot answer, on the view that a slightly old answer
/// beats none. The grace period and the retry timing come from the config.
pub struct ServeStaleLayer {
    inner: Arc<dyn Resolver>,
    store: StaleStore,
    /// How long past expiry an answer may still be served.
    max_stale: Duration,
    min_ttl: u32,
    max_ttl: u32,
    /// TTL put on stale answers.
    reply_ttl: u32,
    /// A successful refresh restarts the stale window.
    ttl_reset: bool,
    /// Past this, the stale answer goes out first; None waits to the end.
    client_timeout: Option<Duration>,
    /// Serve the expired answer without waiting and refresh in the background.
    stale_first: bool,
    inflight: Arc<Mutex<HashSet<StaleKey>>>,
    /// Set while this layer is being dropped.
    stop: Arc<std::sync::atomic::AtomicBool>,
    /// Set while the whole server shuts down.
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    jobs: StaleJobs,
}

impl ServeStaleLayer {
    #[allow(clippy::too_many_arguments)]
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
            // RFC 8767 requires stale records to carry a TTL above 0. With 0, the receiver could
            // not cache it and would ask again at once, flooding queries while the upstream is
            // down, the very situation this feature exists to prevent.
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

    /// So refreshes do not hold up shutdown.
    pub fn with_shutdown(mut self, shutdown: Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.shutdown = shutdown;
        self
    }

    /// Checks eligibility: a response lacking the requested answer, once stored, would be served
    /// when the upstream is down.
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

    /// Removes the entry once its stale window has passed too.
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

    /// With TTLs reduced by the time passed.
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

    /// Puts the configured short TTL on it; with the original TTL, clients would hold the old
    /// answer longer.
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
        response.additionals.push(edns.try_to_record().expect(
            "A record that trims existing EDNS options and adds a fixed EDE can always be encoded",
        ));
        response
    }

    fn extend_stale_if_configured(&self, key: &StaleKey) {
        if !self.ttl_reset {
            return;
        }
        if let Some(entry) = self.store.lock_recover().get_mut(key) {
            entry.stale_until = Instant::now() + self.max_stale;
        }
    }

    /// False while stopping, when the name is already refreshing, or at the in-flight cap.
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

    /// Asks the inner layer with a deadline, so the cached answer can go out first once it passes.
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
    /// Waits for running refreshes; otherwise a refresh would touch what is already gone.
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
    fn resolve(&self, request: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(request))
    }

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

    /// Answers once, then fails.
    struct FailAfterFirst {
        n: AtomicU32,
    }
    impl Resolver for FailAfterFirst {
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
    fn serve_stale_refresh_serves_stale_then_refreshes() {
        /// Slow from the second call on.
        struct SlowAfterFirst {
            calls: AtomicU32,
        }
        impl Resolver for SlowAfterFirst {
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
    fn stale_first_answers_without_waiting_for_upstream() {
        /// Slow after the first call.
        struct SlowAfterFirst {
            calls: AtomicU32,
        }
        impl Resolver for SlowAfterFirst {
            /// Answers with a 1-second TTL.
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
    /// Otherwise the refresh would touch what is gone.
    fn dropping_serve_stale_waits_for_active_refresh() {
        /// Blocks until released.
        struct BlockingRefresh {
            entered: Mutex<Option<std::sync::mpsc::Sender<()>>>,
            release: Arc<(Mutex<bool>, Condvar)>,
        }
        impl Resolver for BlockingRefresh {
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
    /// Storing it would serve it when the upstream is down.
    fn serve_stale_rejects_unrelated_lame_answer() {
        struct UnrelatedAnswer {
            calls: AtomicU32,
        }
        impl Resolver for UnrelatedAnswer {
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
    fn serve_stale_fresh_hit_ages_and_expires_each_additional_rr() {
        struct ShortAdditional;
        impl Resolver for ShortAdditional {
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
            inserted: Instant::now(),
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
    /// Resetting the stale window revives the main answer, not a much shorter additional record.
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
            inserted: Instant::now(),
            fresh_until: Instant::now(),
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
    fn serve_stale_accepts_cname_chain_with_terminal_rrset() {
        struct AliasAnswer {
            calls: AtomicU32,
        }
        impl Resolver for AliasAnswer {
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
