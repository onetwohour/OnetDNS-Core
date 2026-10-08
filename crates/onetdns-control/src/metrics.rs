/*!
 * @brief 지표 수집과 실시간 전달.
 *
 * @details 데이터 경로는 상세 로그를 유계 채널에, 통계 전용 이벤트를 워커별 유계 슬롯에 넣고
 *          즉시 돌아간다. 넘치면 상위 목록 귀속만 버린다. 수집 스레드가 이를 꺼내 상위 목록과
 *          구독자를 갱신하고, 누적 계수는 슬롯 잠금 안에서 별도로 정확하게 유지한다.
 * @warning 이 경로가 질의 처리를 막으면 안 된다. 채널이 가득 찼을 때 기다리는 순간
 *          지표 수집이 곧 서비스 장애가 된다.
 */

use std::borrow::Cow;
use std::collections::hash_map::RandomState;
use std::collections::VecDeque;
use std::hash::BuildHasher;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use onetdns_core::{json, MutexExt, Transport};
use onetdns_proto::{Name, RecordType};
use std::sync::mpsc;

thread_local! {

    /** @brief 이 질의가 시작한 시각. 처리 시간을 재려는 것이다. */
    static REQUEST_START: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
}

/** @brief 이 요청이 시작된 뒤 흐른 시간. 타이머가 없으면 0이다. */
fn current_request_latency_us() -> u64 {
    REQUEST_START
        .with(|c| c.get())
        .map(|start| start.elapsed().as_micros().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

/**
 * @brief 요청 처리 시간을 측정하는 범위 보호자.
 * @details 스레드 지역 시작 시각을 설정하고, 사라질 때 이전 값으로 되돌린다. 중첩 요청에서도
 *          바깥 요청의 시각이 보존된다.
 */
pub struct RequestTimer {
    /** @brief 이 타이머가 덮기 전의 시작 시각. */
    prev: Option<Instant>,
}

impl RequestTimer {
    /** @brief 지금부터 측정한다. */
    pub fn start() -> Self {
        Self::start_at(Instant::now())
    }

    /** @brief 지정한 시각부터 측정한다. 요청을 받은 시점을 정확히 넘길 때 쓴다. */
    pub fn start_at(start: Instant) -> Self {
        let prev = REQUEST_START.with(|c| c.replace(Some(start)));
        RequestTimer { prev }
    }

    /** @brief 지금까지 흐른 시간. */
    pub fn elapsed_us(&self) -> u64 {
        current_request_latency_us()
    }
}

impl Drop for RequestTimer {
    /** @brief 처리 시간을 남긴다. */
    fn drop(&mut self) {
        REQUEST_START.with(|c| c.set(self.prev));
    }
}

#[derive(Debug, Clone, Copy)]
/** @brief 질의 하나에 대해 이 서버가 한 처분. */
pub enum Action {
    /** @brief 정상으로 답했다. */
    Resolved,
    /** @brief 차단했다. */
    Blocked,
    /** @brief 다른 답으로 바꿨다. */
    Rewritten,
    /** @brief 접근 제어에 막혔다. */
    Denied,
    /** @brief 속도 제한에 막혔다. */
    Throttled,
    /** @brief 오류로 답했다. */
    ServFail,
    /** @brief 거절로 답했다. */
    Refused,
}

impl Action {
    /**
     * @brief 모든 처분.
     * @note 질의 하나는 반드시 이 중 하나로 끝나므로, 지표의 총 질의 수는 이것들의 합과
     *       같아야 한다. 하나라도 내보내지 않으면 수집기에 설명되지 않는 잔차가 남는다.
     */
    pub const ALL: [Action; 7] = [
        Action::Resolved,
        Action::Blocked,
        Action::Rewritten,
        Action::Denied,
        Action::Throttled,
        Action::ServFail,
        Action::Refused,
    ];

    /** @brief 지표와 로그에 쓸 이름. */
    pub(crate) fn name(self) -> &'static str {
        match self {
            Action::Resolved => "resolved",
            Action::Blocked => "blocked",
            Action::Rewritten => "rewritten",
            Action::Denied => "denied",
            Action::Throttled => "throttled",
            Action::ServFail => "servfail",
            Action::Refused => "refused",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
/** @brief 한 구간의 누적값. 이력 계산의 단위다. */
struct MetricBucket {
    /** @brief 이 구간의 끝 시각. */
    ts_sec: u64,
    /** @brief 이 구간이 덮는 초. 초당 값을 낼 때 나눈다. */
    span_secs: u64,
    /** @brief 질의 수. */
    queries: u64,
    /** @brief 차단 수. */
    blocked: u64,
    /** @brief 지연 합. */
    latency_sum_us: u64,
    /** @brief 지연을 측정한 횟수. 평균을 낼 때 나눈다. */
    latency_count: u64,
    /** @brief 캐시 적중 수. */
    cache_hits: u64,
    /** @brief 캐시 조회 수. */
    cache_lookups: u64,
}

impl MetricBucket {
    /** @brief 다른 구간을 더한다. 넘침은 포화로 막는다. */
    fn add(&mut self, other: MetricBucket) {
        self.span_secs = self.span_secs.saturating_add(other.span_secs);
        self.queries = self.queries.saturating_add(other.queries);
        self.blocked = self.blocked.saturating_add(other.blocked);
        self.latency_sum_us = self.latency_sum_us.saturating_add(other.latency_sum_us);
        self.latency_count = self.latency_count.saturating_add(other.latency_count);
        self.cache_hits = self.cache_hits.saturating_add(other.cache_hits);
        self.cache_lookups = self.cache_lookups.saturating_add(other.cache_lookups);
    }
}

#[derive(Default)]
/**
 * @brief 시간에 따른 지표 이력.
 * @details 초 단위와 분 단위를 따로 둔다. 긴 구간을 초 단위로만 담으면 메모리가 구간
 *          길이에 그대로 비례한다.
 */
struct MetricHistory {
    /** @brief 최근 구간의 초 단위 표본. */
    seconds: VecDeque<MetricBucket>,
    /** @brief 오래된 구간의 분 단위 표본. */
    minutes: VecDeque<MetricBucket>,
    /** @brief 직전 표본의 누적값. 차분을 내는 기준이다. */
    previous: MetricBucket,
    /** @brief 직전 표본 시각. */
    previous_sample_sec: u64,
    /** @brief 이력을 얼마나 보관할지. */
    retention_secs: u64,
}

impl MetricHistory {
    /**
     * @brief 기준점을 지금 값으로 다시 잡는다.
     * @details 저장된 통계를 읽어 들인 직후에 부른다. 그러지 않으면 재시작 직후의 첫
     *          표본이 누적값 전체를 그 순간의 증가분으로 잘못 본다.
     */
    fn reset_baseline(&mut self, counters: MetricBucket, now_sec: u64) {
        self.previous = counters;
        self.previous_sample_sec = now_sec;
        self.seconds.clear();
        self.minutes.clear();
    }

    /** @brief 지금 누적값으로 표본 하나를 만든다. 직전과의 차분이 그 구간의 값이다. */
    fn sample(&mut self, counters: MetricBucket, now_sec: u64) {
        let span_secs = now_sec.saturating_sub(self.previous_sample_sec).max(1);
        let delta = MetricBucket {
            ts_sec: now_sec,
            span_secs,
            queries: counters.queries.saturating_sub(self.previous.queries),
            blocked: counters.blocked.saturating_sub(self.previous.blocked),
            latency_sum_us: counters
                .latency_sum_us
                .saturating_sub(self.previous.latency_sum_us),
            latency_count: counters
                .latency_count
                .saturating_sub(self.previous.latency_count),
            cache_hits: counters.cache_hits.saturating_sub(self.previous.cache_hits),
            cache_lookups: counters
                .cache_lookups
                .saturating_sub(self.previous.cache_lookups),
        };
        self.previous = counters;
        self.previous_sample_sec = now_sec;

        if let Some(last) = self
            .seconds
            .back_mut()
            .filter(|last| last.ts_sec == now_sec)
        {
            last.add(delta);
        } else {
            self.seconds.push_back(delta);
        }
        let minute_sec = now_sec / 60 * 60;
        let minute_delta = MetricBucket {
            ts_sec: minute_sec,
            ..delta
        };
        if let Some(last) = self
            .minutes
            .back_mut()
            .filter(|last| last.ts_sec == minute_sec)
        {
            last.add(minute_delta);
        } else {
            self.minutes.push_back(minute_delta);
        }

        let retention_secs = if self.retention_secs == 0 {
            7 * 24 * 60 * 60
        } else {
            self.retention_secs.max(60)
        };
        let second_cutoff = now_sec.saturating_sub(retention_secs.min(3_600));
        while self
            .seconds
            .front()
            .map(|bucket| bucket.ts_sec < second_cutoff)
            .unwrap_or(false)
        {
            self.seconds.pop_front();
        }
        let minute_cutoff = now_sec.saturating_sub(retention_secs);
        while self
            .minutes
            .front()
            .map(|bucket| bucket.ts_sec < minute_cutoff)
            .unwrap_or(false)
        {
            self.minutes.pop_front();
        }
    }

    #[cfg(test)]
    /** @brief 최근 몇 초를 하나로 합친다. */
    fn aggregate_recent(&self, now_sec: u64, seconds: u64) -> MetricBucket {
        let cutoff = now_sec.saturating_sub(seconds);
        let mut out = MetricBucket::default();
        for bucket in self.seconds.iter().filter(|bucket| bucket.ts_sec >= cutoff) {
            out.add(*bucket);
        }
        out
    }

    /** @brief 요청한 구간을 요청한 점 수로 나눠 돌려준다. 대시보드 그래프의 재료다. */
    fn points(&self, now_sec: u64, range_secs: u64, point_count: usize) -> Vec<MetricPoint> {
        let point_count = point_count.clamp(2, 240);
        let range_secs = range_secs.clamp(60, 7 * 24 * 60 * 60);
        let width = range_secs.div_ceil(point_count as u64).max(1);
        let start = now_sec.saturating_sub(width.saturating_mul(point_count as u64));
        let source = if range_secs <= 3_600 {
            &self.seconds
        } else {
            &self.minutes
        };
        let mut out = Vec::with_capacity(point_count);
        for index in 0..point_count {
            let bin_start = start.saturating_add(width.saturating_mul(index as u64));
            let bin_end = bin_start.saturating_add(width);
            let mut sum = MetricBucket::default();
            for bucket in source
                .iter()
                .filter(|bucket| bucket.ts_sec > bin_start && bucket.ts_sec <= bin_end)
            {
                sum.add(*bucket);
            }
            let avg_latency_ms = if sum.latency_count == 0 {
                0.0
            } else {
                sum.latency_sum_us as f64 / sum.latency_count as f64 / 1_000.0
            };
            let cache_hit_pct = if sum.cache_lookups == 0 {
                0.0
            } else {
                sum.cache_hits as f64 * 100.0 / sum.cache_lookups as f64
            };
            out.push(MetricPoint {
                ts_ms: bin_end.saturating_mul(1_000),
                queries: sum.queries,
                blocked: sum.blocked,
                avg_latency_ms,
                cache_hit_pct,
            });
        }
        out
    }
}

#[derive(Clone, Copy, Default)]
/** @brief 통계 슬롯 잠금 안에서 질의별 전역 atomic 대신 누적하는 값. */
struct StatCounters {
    total: u64,
    resolved: u64,
    blocked: u64,
    rewritten: u64,
    denied: u64,
    refused: u64,
    throttled: u64,
    servfail: u64,
    by_transport: [u64; Transport::COUNT],
}

impl StatCounters {
    /** @brief 질의 하나를 샤드에 더한다. */
    fn record(&mut self, transport: Transport, action: Action) {
        self.total = self.total.saturating_add(1);
        self.by_transport[transport.index()] =
            self.by_transport[transport.index()].saturating_add(1);
        let counter = match action {
            Action::Resolved => &mut self.resolved,
            Action::Blocked => &mut self.blocked,
            Action::Rewritten => &mut self.rewritten,
            Action::Denied => &mut self.denied,
            Action::Refused => &mut self.refused,
            Action::Throttled => &mut self.throttled,
            Action::ServFail => &mut self.servfail,
        };
        *counter = counter.saturating_add(1);
    }

    /** @brief 다른 샤드의 누적값을 포화 덧셈한다. */
    fn add(&mut self, other: &Self) {
        self.total = self.total.saturating_add(other.total);
        self.resolved = self.resolved.saturating_add(other.resolved);
        self.blocked = self.blocked.saturating_add(other.blocked);
        self.rewritten = self.rewritten.saturating_add(other.rewritten);
        self.denied = self.denied.saturating_add(other.denied);
        self.refused = self.refused.saturating_add(other.refused);
        self.throttled = self.throttled.saturating_add(other.throttled);
        self.servfail = self.servfail.saturating_add(other.servfail);
        for (total, value) in self.by_transport.iter_mut().zip(other.by_transport) {
            *total = total.saturating_add(value);
        }
    }
}

#[derive(Default)]
/** @brief 누적 지표. 상세 로그는 원자값에, 기본 통계 경로는 워커별 샤드에 더한다. */
pub struct Metrics {
    /** @brief 전체 질의 수. */
    pub total: AtomicU64,
    /** @brief 정상 해석 수. */
    pub resolved: AtomicU64,
    /** @brief 차단 수. */
    pub blocked: AtomicU64,
    /** @brief 재작성 수. */
    pub rewritten: AtomicU64,
    /** @brief ACL로 막은 수. */
    pub denied: AtomicU64,
    /** @brief 정책으로 거부한 수. */
    pub refused: AtomicU64,
    /** @brief 속도 제한으로 버린 수. */
    pub throttled: AtomicU64,
    /** @brief SERVFAIL 수. */
    pub servfail: AtomicU64,
    /** @brief 전송별 질의 수. */
    pub by_transport: [AtomicU64; Transport::COUNT],

    /** @brief 지연 합. */
    pub latency_sum_us: AtomicU64,
    /** @brief 지연을 측정한 횟수. */
    pub latency_count: AtomicU64,
    /** @brief 캐시 적중 수. */
    pub cache_hits: AtomicU64,
    /** @brief 캐시 조회 수. */
    pub cache_lookups: AtomicU64,

    /** @brief 채널이 가득 차 버린 기록 이벤트 수. 이 값이 오르면 수집이 못 따라가는 것이다. */
    pub dropped_log_events: AtomicU64,
    /**
     * @brief 슬롯이 가득 차 버린 통계 전용 이벤트 수.
     * @details 누적 카운터는 슬롯 상한을 검사하기 전에 이미 샤드에 더하므로 총계는 잃지 않는다. 잃는 것은
     *          상위 도메인·클라이언트 목록의 귀속이라, 이 값이 오르면 상위 목록이 표본이 된다.
     */
    pub dropped_stat_events: AtomicU64,
    /** @brief 구독자에게 못 보낸 이벤트 수. */
    pub dropped_stream_events: AtomicU64,
    /** @brief 디스크 저장 실패 수. */
    pub persist_failures: AtomicU64,
    /** @brief 시간별 이력. 표본 스레드만 쓴다. */
    history: Mutex<MetricHistory>,
    /** @brief 질의 로그가 꺼진 hot path가 전역 cacheline 대신 쓰는 샤드. */
    stat_slots: Option<Arc<Vec<Mutex<StatSlot>>>>,
}

impl Metrics {
    /** @brief 통계 전용 샤드의 누적값을 snapshot 시점에 합친다. */
    fn sharded_stat_counters(&self) -> StatCounters {
        let mut total = StatCounters::default();
        if let Some(slots) = &self.stat_slots {
            for slot in slots.iter() {
                total.add(&slot.lock_recover().counters);
            }
        }
        total
    }

    /** @brief 지금 누적값을 한 번에 읽는다. */
    fn counters(&self) -> MetricBucket {
        let sharded = self.sharded_stat_counters();
        MetricBucket {
            queries: self
                .total
                .load(Ordering::Relaxed)
                .saturating_add(sharded.total),
            blocked: self
                .blocked
                .load(Ordering::Relaxed)
                .saturating_add(sharded.blocked),
            latency_sum_us: self.latency_sum_us.load(Ordering::Relaxed),
            latency_count: self.latency_count.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_lookups: self.cache_lookups.load(Ordering::Relaxed),
            ..MetricBucket::default()
        }
    }

    /** @brief 지금 값으로 이력 표본을 하나 남긴다. */
    fn sample_now(&self) {
        let now_sec = now_ms() / 1_000;
        let counters = self.counters();
        self.history.lock_recover().sample(counters, now_sec);
    }

    /** @brief 이력 보관 기간을 바꾼다. */
    fn set_history_retention(&self, retention_secs: u64) {
        self.history.lock_recover().retention_secs = retention_secs;
    }

    /** @brief 이력 기준점을 다시 잡는다. */
    fn reset_history_baseline(&self) {
        let now_sec = now_ms() / 1_000;
        let counters = self.counters();
        self.history
            .lock_recover()
            .reset_baseline(counters, now_sec);
    }

    /** @brief 그래프용 이력 점들. */
    pub fn history(&self, range_secs: u64, point_count: usize) -> Vec<MetricPoint> {
        self.sample_now();
        let now_sec = now_ms() / 1_000;
        self.history
            .lock_recover()
            .points(now_sec, range_secs, point_count)
    }

    /** @brief 지금 지표 전체를 한 번에 읽는다. */
    pub fn snapshot(&self) -> MetricsSnapshot {
        self.sample_now();
        self.current_snapshot()
    }

    /** @brief 이력 표본을 추가하지 않고 현재 누적값만 읽는다. 저장 경로도 함께 쓴다. */
    pub(crate) fn current_snapshot(&self) -> MetricsSnapshot {
        let sharded = self.sharded_stat_counters();
        let by_transport = Transport::ALL
            .iter()
            .map(|t| {
                (
                    t.name(),
                    self.by_transport[t.index()]
                        .load(Ordering::Relaxed)
                        .saturating_add(sharded.by_transport[t.index()]),
                )
            })
            .collect();

        let latency_count = self.latency_count.load(Ordering::Relaxed);
        let latency_sum_us = self.latency_sum_us.load(Ordering::Relaxed);
        let avg_latency_ms = if latency_count > 0 {
            latency_sum_us as f64 / latency_count as f64 / 1_000.0
        } else {
            0.0
        };
        let cache_lookups = self.cache_lookups.load(Ordering::Relaxed);
        let cache_hit_pct = if cache_lookups > 0 {
            self.cache_hits.load(Ordering::Relaxed) as f64 * 100.0 / cache_lookups as f64
        } else {
            0.0
        };
        MetricsSnapshot {
            total: self
                .total
                .load(Ordering::Relaxed)
                .saturating_add(sharded.total),
            resolved: self
                .resolved
                .load(Ordering::Relaxed)
                .saturating_add(sharded.resolved),
            blocked: self
                .blocked
                .load(Ordering::Relaxed)
                .saturating_add(sharded.blocked),
            rewritten: self
                .rewritten
                .load(Ordering::Relaxed)
                .saturating_add(sharded.rewritten),
            denied: self
                .denied
                .load(Ordering::Relaxed)
                .saturating_add(sharded.denied),
            refused: self
                .refused
                .load(Ordering::Relaxed)
                .saturating_add(sharded.refused),
            throttled: self
                .throttled
                .load(Ordering::Relaxed)
                .saturating_add(sharded.throttled),
            servfail: self
                .servfail
                .load(Ordering::Relaxed)
                .saturating_add(sharded.servfail),
            by_transport,
            avg_latency_ms,
            latency_sum_us,
            latency_count,
            cache_hit_pct,
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_lookups,
            dropped_log_events: self.dropped_log_events.load(Ordering::Relaxed),
            dropped_stat_events: self.dropped_stat_events.load(Ordering::Relaxed),
            dropped_stream_events: self.dropped_stream_events.load(Ordering::Relaxed),
            persist_failures: self.persist_failures.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
/** @brief 그래프의 점 하나. */
pub struct MetricPoint {
    /** @brief 이 지점의 시각. */
    pub ts_ms: u64,
    /** @brief 이 구간 동안 받은 질의 수. 폭으로 나눈 평균 속도가 아니라 합계다. */
    pub queries: u64,
    /** @brief 이 구간 동안 차단한 질의 수. */
    pub blocked: u64,
    /** @brief 평균 처리 시간. */
    pub avg_latency_ms: f64,
    /** @brief 캐시가 맞은 비율. */
    pub cache_hit_pct: f64,
}

#[derive(Debug, Clone)]
/** @brief 대시보드에 보낼 지표 모음. */
pub struct MetricsSnapshot {
    /** @brief 전체 질의 수. */
    pub total: u64,
    /** @brief 정상으로 답한 수. */
    pub resolved: u64,
    /** @brief 차단한 수. */
    pub blocked: u64,
    /** @brief 다른 답으로 바꾼 수. */
    pub rewritten: u64,
    /** @brief 접근 제어에 막힌 수. */
    pub denied: u64,
    /** @brief 거절로 답한 수. */
    pub refused: u64,
    /** @brief 속도 제한에 막힌 수. */
    pub throttled: u64,
    /** @brief 오류로 답한 수. */
    pub servfail: u64,
    /** @brief 전송별 질의 수. */
    pub by_transport: Vec<(&'static str, u64)>,
    /** @brief 평균 처리 시간. */
    pub avg_latency_ms: f64,
    /** @brief 처리 시간 누적. 평균을 수집기가 직접 내도록 원자료로도 낸다. */
    pub latency_sum_us: u64,
    /** @brief 처리 시간을 측정한 질의 수. */
    pub latency_count: u64,
    /** @brief 캐시가 맞은 비율. */
    pub cache_hit_pct: f64,

    /** @brief 캐시가 맞은 수. */
    pub cache_hits: u64,
    /** @brief 캐시를 찾아본 수. */
    pub cache_lookups: u64,
    /** @brief 대기열이 꽉 차 버린 기록 수. */
    pub dropped_log_events: u64,
    /** @brief 슬롯이 꽉 차 버린 통계 전용 이벤트 수. 상위 목록만 표본이 된다. */
    pub dropped_stat_events: u64,
    /** @brief 대기열이 꽉 차 못 보낸 실시간 이벤트 수. */
    pub dropped_stream_events: u64,
    /** @brief 저장에 실패한 횟수. */
    pub persist_failures: u64,
}

#[derive(Debug, Clone)]
/** @brief 질의 하나에 대한 기록. */
pub struct QueryEvent {
    /** @brief 이 기록의 번호. */
    pub id: u64,
    /** @brief 질의가 온 시각. */
    pub ts_ms: u64,
    /** @brief 질의를 보낸 곳. */
    pub client: IpAddr,
    /** @brief 물어본 이름. */
    pub name: Option<Name>,
    /** @brief 질의 종류. */
    pub qtype: String,
    /** @brief 어느 전송으로 왔는지. */
    pub transport: &'static str,
    /** @brief 어떻게 처리했는지. */
    pub action: &'static str,
    /** @brief 응답 코드. */
    pub rcode: String,
    /** @brief 그렇게 처리한 까닭. */
    pub reason: String,
    /** @brief 어느 단계에서 갈렸는지. */
    pub stage: String,
    /** @brief 덧붙일 내용. */
    pub detail: String,

    /** @brief 답 요약. */
    pub answers: String,
    /** @brief 어느 업스트림 서버가 답했는지. */
    pub upstream: String,
    /** @brief 어느 규칙이 걸렸는지. */
    pub rule: String,
    /** @brief 그 규칙이 들어 있던 목록. 목록에 속하지 않는 규칙이면 비어 있다. */
    pub list: String,

    /** @brief 처리에 걸린 시간. */
    pub latency_us: u64,

    /** @brief 질의 기록에 남길지. */
    pub log: bool,
    /** @brief 통계에 넣을지. */
    pub stat: bool,
}

#[derive(Debug)]
/** @brief 상위 목록 집계에만 필요한 최소 질의 정보. */
struct StatEvent {
    /** @brief 질의를 보낸 곳. 익명화 설정까지 적용된 값이다. */
    client: IpAddr,
    /** @brief 물어본 이름. */
    name: Option<Name>,
    /** @brief 차단 상위 목록을 구분하는 처분. */
    action: Action,
}

#[derive(Default)]
/** @brief 워커별 통계 이벤트와 누적 계수를 한 잠금으로 보호하는 샤드. */
struct StatSlot {
    /** @brief collector가 가져갈 상위 목록 이벤트. */
    events: Vec<StatEvent>,
    /** @brief snapshot이 직접 합산하는 질의 누적값. collector가 비워도 유지한다. */
    counters: StatCounters,
}

#[allow(clippy::large_enum_variant)]
/**
 * @brief 수집 스레드에 보내는 실제 로그 또는 통계 슬롯 wake 신호.
 * @note 전체 로그를 box 하면 querylog 질의마다 할당이 하나 늘어나므로 큰 변형을
 *       그대로 둔다.
 */
enum CollectorEvent {
    /** @brief 즉시 처리할 전체 질의 로그. */
    Log(QueryEvent),
    /** @brief 비어 있던 통계 슬롯에 첫 이벤트가 들어왔다. */
    StatsReady,
}

impl QueryEvent {
    /** @brief 이 이벤트를 JSON 한 줄로. 저장과 실시간 전달에 같은 형식을 쓴다. */
    pub fn to_json(&self) -> String {
        format!(
            "{{\"id\":{},\"ts_ms\":{},\"client\":{},\"name\":{},\"qtype\":{},\"transport\":{},\"action\":{},\"rcode\":{},\"reason\":{},\"stage\":{},\"detail\":{},\"answers\":{},\"upstream\":{},\"rule\":{},\"list\":{},\"latency_us\":{}}}",
            self.id,
            self.ts_ms,
            json::escape(&self.client.to_string()),
            json::escape(&self.name.as_ref().map(Name::to_string).unwrap_or_default()),
            json::escape(&self.qtype),
            json::escape(self.transport),
            json::escape(self.action),
            json::escape(&self.rcode),
            json::escape(&self.reason),
            json::escape(&self.stage),
            json::escape(&self.detail),
            json::escape(&self.answers),
            json::escape(&self.upstream),
            json::escape(&self.rule),
            json::escape(&self.list),
            self.latency_us,
        )
    }
}

#[derive(Default, Clone, Copy)]
/** @brief 이벤트에 붙는 진단 정보. 응답 코드와 사유 등이다. */
pub struct EventDiag<'a> {
    /** @brief 응답 코드. */
    pub rcode: &'a str,
    /** @brief 그렇게 처리한 까닭. */
    pub reason: &'a str,
    /** @brief 어느 단계에서 갈렸는지. */
    pub stage: &'a str,
    /** @brief 덧붙일 내용. */
    pub detail: &'a str,
    /** @brief 답 요약. */
    pub answers: &'a str,
    /** @brief 어느 업스트림 서버가 답했는지. */
    pub upstream: &'a str,
    /** @brief 어느 규칙이 걸렸는지. */
    pub rule: &'a str,
    /** @brief 그 규칙이 들어 있던 목록. */
    pub list: &'a str,
}

/** @brief 전송 이름을 고정 문자열로 바꾼다. 이벤트마다 문자열을 새로 만들지 않는다. */
pub(crate) fn intern_transport(s: &str) -> &'static str {
    Transport::ALL
        .into_iter()
        .find(|t| t.name() == s)
        .map(|t| t.name())
        .unwrap_or("do53-udp")
}

/** @brief 처분 이름을 고정 문자열로 바꾼다. */
pub(crate) fn intern_action(s: &str) -> &'static str {
    /** @brief 알려진 처분 이름들. */
    const NAMES: [&str; 7] = [
        "resolved",
        "blocked",
        "rewritten",
        "denied",
        "throttled",
        "servfail",
        "refused",
    ];
    NAMES.into_iter().find(|a| *a == s).unwrap_or("resolved")
}

#[derive(Clone, Default, PartialEq, Eq)]
/** @brief 디스크 보존 설정. */
pub struct PersistOpts {
    /** @brief 질의 기록을 담아 둘 파일. */
    pub querylog_file: Option<PathBuf>,

    /** @brief 통계를 담아 둘 파일. */
    pub stats_file: Option<PathBuf>,

    /** @brief 파일에 쓸 간격. */
    pub flush_secs: u64,
}

impl PersistOpts {
    /** @brief 보존이 켜져 있는지. */
    fn enabled(&self) -> bool {
        self.querylog_file.is_some() || self.stats_file.is_some()
    }
}

#[derive(Clone)]
/** @brief 기록기 설정. */
pub struct RecorderOpts {
    /** @brief 질의 기록을 남길지. */
    pub querylog: bool,

    /** @brief 클라이언트 주소를 가릴지. */
    pub anonymize: bool,

    /** @brief 기록에서 뺄 이름들. */
    pub ignored: Vec<String>,

    /** @brief 통계를 남겨 둘 기간. */
    pub stats_retention_secs: u64,
}

impl Default for RecorderOpts {
    /** @brief 기본 설정. */
    fn default() -> Self {
        Self {
            querylog: true,
            anonymize: false,
            ignored: vec![],
            stats_retention_secs: 0,
        }
    }
}

#[derive(Clone)]
/**
 * @brief 데이터 경로가 쓰는 기록기.
 * @warning record 계열은 절대 막히면 안 된다. 채널이 가득 차면 이벤트를 버리고 즉시 돌아온다.
 */
pub struct Recorder {
    /** @brief 누적 지표. */
    metrics: Arc<Metrics>,
    /** @brief 전체 로그와 통계 슬롯 wake를 보내는 유계 채널. */
    log_tx: mpsc::SyncSender<CollectorEvent>,

    /**
     * @brief 통계 집계만 쓰는 이벤트를 모아 두는 슬롯들.
     *
     * @details 채널 전송은 대기자가 없어도 깨우기 시스템 호출을 낸다. 그 비용이 질의당
     *          커널 시간의 큰 몫이라, 즉시성이 필요 없는 이벤트는 여기 모은다. 비어 있던
     *          슬롯의 첫 push만 수집기를 깨우므로 지속 부하는 drain batch당 최대 한 번만
     *          채널을 건드린다.
     * @invariant 잠금은 슬롯마다 따로이고 잡은 채로 하는 일은 누적·push 또는 이벤트 통째 교체뿐이다.
     *            가득 차면 기다리지 않고 버린다. 지표 수집이 서비스를 막지 않는다는
     *            계약은 그대로다.
     */
    stat_slots: Arc<Vec<Mutex<StatSlot>>>,
    /** @brief collector가 idle wait에 들어가 첫 통계 이벤트의 wake가 필요한지. */
    stat_collector_idle: Arc<AtomicBool>,
    /** @brief 질의 기록을 남길지. */
    querylog: Arc<AtomicBool>,

    /**
     * @brief 모은 것을 볼 수 있는 곳이 있는지.
     *
     * @details 관리 수신 주소도 통계·기록 파일도 없으면 이 기록은 어디로도 나가지 못한다.
     *          그때 질의마다 이벤트를 만드는 것은 만들어서 버리는 일이라 헤드리스 배포가 쓰지도
     *          않는 통계에 해석당 CPU의 4분의 1을 낸다.
     * @invariant 참이 기본값이다. 알려 주지 않은 곳은 종전대로 모은다.
     * @warning 무중단 갱신으로 관리 주소가 생기면 그때 참이 되어야 한다. 세대를 다시
     *          만들지 않는 갱신 경로가 있으므로 그 자리에서도 다시 정해야 한다.
     */
    collecting: Arc<AtomicBool>,
    /** @brief 클라이언트 주소를 가릴지. */
    anonymize: Arc<AtomicBool>,
    /** @brief 통계에서 뺄 도메인 접미사들. 소문자·끝점 없는 형태로만 들어온다. */
    ignored: Arc<RwLock<Vec<Box<str>>>>,

    /** @brief 제외 목록이 비어 있지 않은지. 비었으면 잠금조차 잡지 않는다. */
    ignored_active: Arc<AtomicBool>,
    /** @brief 메모리에 둘 최근 기록 수. */
    log_cap: Arc<AtomicUsize>,
    /** @brief 기록 보존 기간. */
    retention_ms: Arc<AtomicU64>,
    /** @brief 최근 기록. 대시보드가 여기서 읽는다. */
    recent: Arc<Mutex<VecDeque<QueryEvent>>>,
    /** @brief 배경 스레드들. 마지막 기록기가 사라질 때 함께 정리된다. */
    _runtime: Arc<RecorderRuntime>,
}

/** @brief 표본과 수집 스레드의 수명을 잡고 있는 것. */
struct RecorderRuntime {
    /** @brief 멈추라는 신호. */
    stop: Arc<AtomicBool>,
    /** @brief 주기적으로 이력 표본을 남기는 스레드. */
    sampler: Mutex<Option<std::thread::JoinHandle<()>>>,
    /** @brief 채널을 비우며 통계를 갱신하는 스레드. */
    collector: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Drop for RecorderRuntime {
    /** @brief 거두는 스레드를 끝낸다. */
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self
            .sampler
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            thread.thread().unpark();
            if thread.join().is_err() {
                onetdns_core::error!(event = "metrics.sampler_panicked", "History sampling thread exited unexpectedly; hourly history has a gap for this period");
            }
        }
        if let Some(thread) = self
            .collector
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            if thread.join().is_err() {
                onetdns_core::error!(
                    event = "metrics.collector_panicked",
                    "Statistics thread exited unexpectedly; query records have a gap for this period"
                );
            }
        }
    }
}

impl Recorder {
    /** @brief 누적 지표 핸들. */
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /** @brief 기록 설정을 바꾼다. 누적 통계는 그대로 둔다. */
    pub fn reconfigure(
        &self,
        querylog: bool,
        anonymize: bool,
        ignored: Vec<String>,
        log_cap: usize,
        retention_secs: u64,
        stats_retention_secs: u64,
    ) {
        self.querylog.store(querylog, Ordering::Release);
        self.anonymize.store(anonymize, Ordering::Release);
        let ignored_active = !ignored.is_empty();
        *self
            .ignored
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = normalize_ignored(ignored);

        self.ignored_active.store(ignored_active, Ordering::Release);
        self.log_cap.store(log_cap.max(1), Ordering::Release);
        let retention_ms = retention_secs.saturating_mul(1000);
        self.retention_ms.store(retention_ms, Ordering::Release);
        self.metrics.set_history_retention(stats_retention_secs);

        let mut recent = self.recent.lock_recover();
        if retention_ms > 0 {
            let cutoff = now_ms().saturating_sub(retention_ms);
            while recent
                .front()
                .map(|event| event.ts_ms < cutoff)
                .unwrap_or(false)
            {
                recent.pop_front();
            }
        }
        while recent.len() > log_cap.max(1) {
            recent.pop_front();
        }
    }

    /**
     * @brief 질의 기록이 켜져 있는지.
     *
     * @details 기록에만 담기는 값을 호출자가 미리 만들지 않게 하려는 것이다. 꺼진
     *          상태에서 만든 문자열은 그대로 버려진다.
     * @return 켜져 있으면 참.
     */
    pub fn querylog_enabled(&self) -> bool {
        self.querylog.load(Ordering::Acquire)
    }

    /**
     * @brief 모은 것을 볼 수 있는 곳이 있는지 알려 준다.
     *
     * @param on 관리 수신 주소나 통계·기록 파일이 있으면 참.
     */
    pub fn set_collecting(&self, on: bool) {
        self.collecting.store(on, Ordering::Release);
    }

    /**
     * @brief 지금 모으고 있는지.
     *
     * @details 호출자가 기록에만 쓰는 값을 미리 만들지 않게 하려는 것이다. 이름 짓기와
     *          시계 읽기는 질의마다 드는 비용이라 볼 곳이 없으면 하지 않아야 한다.
     * @return 볼 곳이 있으면 참.
     */
    pub fn collecting(&self) -> bool {
        self.collecting.load(Ordering::Acquire)
    }

    #[allow(clippy::too_many_arguments)]
    /** @brief 질의 하나를 기록한다. 처분에서 응답 코드와 사유를 정해 상세 기록으로 넘긴다. */
    pub fn record(
        &self,
        transport: Transport,
        action: Action,
        client: IpAddr,
        name: Option<&Name>,
        qtype: Option<RecordType>,
        log_client: bool,
        stat_client: bool,
    ) {
        let (rcode, reason) = match action {
            Action::ServFail => ("SERVFAIL", "UNSPECIFIED_SERVFAIL"),
            Action::Refused | Action::Denied => ("REFUSED", "POLICY_REFUSED"),
            Action::Blocked => ("NXDOMAIN", "FILTER_BLOCKED"),

            Action::Throttled => ("DROPPED", "RATE_LIMITED"),
            _ => ("NOERROR", ""),
        };
        self.record_detailed(
            transport,
            action,
            client,
            name,
            qtype,
            log_client,
            stat_client,
            EventDiag {
                rcode,
                reason,
                ..Default::default()
            },
        );
    }

    #[allow(clippy::too_many_arguments)]
    /**
     * @brief 진단 정보까지 붙여 질의 하나를 기록한다.
     * @warning 채널에 넣기만 하고 즉시 돌아온다. 가득 차면 버리고 버린 수만 센다.
     *          여기서 기다리면 지표 수집이 곧 서비스 장애가 된다.
     */
    pub fn record_detailed(
        &self,
        transport: Transport,
        action: Action,
        client: IpAddr,
        name: Option<&Name>,
        qtype: Option<RecordType>,
        log_client: bool,
        stat_client: bool,
        diag: EventDiag,
    ) {
        /*
         * 볼 곳이 없으면 세는 것조차 하지 않는다. 누적 지표도 관리 수신 주소를 거쳐야만
         * 읽히므로, 여기서 더한 값은 아무도 읽지 못한 채 사라진다.
         */
        if !self.collecting.load(Ordering::Acquire) {
            return;
        }
        let m = &self.metrics;
        /*
         * 이름은 값으로 담아 보낸다. Name은 Arc라 복제가 참조계수 증가이고, 문자열은
         * 실제로 쓰는 쪽(상위 목록 키, 질의 기록 JSON)에서 만든다.
         */
        let ignored = self.is_ignored(name);
        let do_log = self.querylog.load(Ordering::Acquire) && log_client && !ignored;
        let do_stat = stat_client && !ignored;

        /*
         * 로그 이벤트는 채널로 가므로 누적값도 기존 전역 atomic에 더한다. 기본 log-off 경로는
         * 아래에서 이미 잡는 통계 슬롯 잠금에 세 값을 함께 누적해 전역 cacheline 쓰기를 없앤다.
         */
        if do_stat && do_log {
            m.total.fetch_add(1, Ordering::Relaxed);
            m.by_transport[transport.index()].fetch_add(1, Ordering::Relaxed);
            match action {
                Action::Resolved => m.resolved.fetch_add(1, Ordering::Relaxed),
                Action::Blocked => m.blocked.fetch_add(1, Ordering::Relaxed),
                Action::Rewritten => m.rewritten.fetch_add(1, Ordering::Relaxed),
                Action::Denied => m.denied.fetch_add(1, Ordering::Relaxed),
                Action::Refused => m.refused.fetch_add(1, Ordering::Relaxed),
                Action::Throttled => m.throttled.fetch_add(1, Ordering::Relaxed),
                Action::ServFail => m.servfail.fetch_add(1, Ordering::Relaxed),
            };
        }
        if !do_log && !do_stat {
            return;
        }

        /*
         * 주소는 값으로 담아 보낸다. 문자열로 만드는 일은 실제로 쓰는 쪽으로 미뤄야
         * 워커가 할당하고 수집 스레드가 해제하는 왕복이 생기지 않는다.
         */
        let client_s = if self.anonymize.load(Ordering::Acquire) {
            anonymize_ip(client)
        } else {
            client
        };
        if !do_log {
            /*
             * 통계 집계는 이름·클라이언트·처분만 본다. 전체 QueryEvent를 넣으면 비어 있는
             * String 여덟 개와 로그 전용 필드까지 슬롯에 쓰고 옮기고 버리게 된다.
             */
            let ev = StatEvent {
                client: client_s,
                name: name.cloned(),
                action,
            };
            if !push_stat_event(
                &self.stat_slots[stat_slot_index()],
                &self.stat_collector_idle,
                &self.log_tx,
                transport,
                ev,
            ) {
                let dropped = self
                    .metrics
                    .dropped_stat_events
                    .fetch_add(1, Ordering::Relaxed)
                    .saturating_add(1);
                if dropped == 1 || dropped.is_power_of_two() {
                    onetdns_core::warn!(
                        event = "stats.slot_full",
                        dropped,
                        "Statistics slots are full; some top domain and client counts were lost, but total query counts are intact"
                    );
                }
                return;
            }
            return;
        }

        /*
         * 여기부터는 실제 질의 기록에 담기는 값이다. 통계 전용 경로는 이 문자열들과
         * 시계 읽기를 전혀 거치지 않는다.
         */
        let ev = QueryEvent {
            id: 0,
            ts_ms: now_ms(),
            client: client_s,
            name: name.cloned(),
            qtype: qtype.map(|t| t.name().to_string()).unwrap_or_default(),
            transport: transport.name(),
            action: action.name(),
            rcode: diag.rcode.to_string(),
            reason: diag.reason.to_string(),
            stage: diag.stage.to_string(),
            detail: diag.detail.to_string(),
            answers: diag.answers.to_string(),
            upstream: diag.upstream.to_string(),
            rule: diag.rule.to_string(),
            list: diag.list.to_string(),
            latency_us: current_request_latency_us(),
            log: true,
            stat: do_stat,
        };
        if let Err(error) = self.log_tx.try_send(CollectorEvent::Log(ev)) {
            let dropped = self
                .metrics
                .dropped_log_events
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1);
            if dropped == 1 || dropped.is_power_of_two() {
                match error {
                    mpsc::TrySendError::Full(_) => onetdns_core::warn!(
                        event = "querylog.queue_full",
                        dropped,
                        "Query log queue is full; some entries were not recorded"
                    ),
                    mpsc::TrySendError::Disconnected(_) => onetdns_core::error!(
                        event = "querylog.collector_disconnected",
                        dropped,
                        "Query log writer thread has exited; new entries cannot be saved"
                    ),
                }
            }
        }
    }

    /** @brief 지연만 따로 기록한다. */
    pub fn record_latency_for(&self, micros: u64, stat_client: bool, name: Option<&Name>) {
        if !stat_client {
            return;
        }

        if self.is_ignored(name) {
            return;
        }
        self.metrics
            .latency_sum_us
            .fetch_add(micros, Ordering::Relaxed);
        self.metrics.latency_count.fetch_add(1, Ordering::Relaxed);
    }

    /**
     * @brief 이 이름이 제외 목록에 걸리는지.
     *
     * @details 질의마다 불리는 곳이라 이름을 스택 버퍼에 한 번만 정규화하고 목록은 이미
     *          정규화된 것을 본다. 목록이 비면 잠금조차 잡지 않는다.
     * @param name 질의 이름. 없으면 걸리지 않는 것으로 본다.
     */
    fn is_ignored(&self, name: Option<&Name>) -> bool {
        if !self.ignored_active.load(Ordering::Acquire) {
            return false;
        }
        let Some(name) = name else {
            return false;
        };
        let mut buf = [0u8; MAX_IGNORE_NAME];
        let normalized = normalize_into(name, &mut buf);
        self.ignored
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .any(|d| suffix_matches(&normalized, d))
    }

    /** @brief 캐시 적중 여부를 기록한다. */
    pub fn record_cache(&self, hit: bool) {
        self.metrics.cache_lookups.fetch_add(1, Ordering::Relaxed);
        if hit {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/** @brief 정규화한 이름을 담을 버퍼 크기. 라벨 합은 와이어 길이 상한보다 늘 짧다. */
const MAX_IGNORE_NAME: usize = 256;

/**
 * @brief 제외 목록 항목을 미리 정규화한다.
 *
 * @details 목록은 설정이라 질의마다 바뀌지 않는다. 소문자화와 끝점 제거를 여기서 한 번만
 *          하지 않으면 질의마다 항목 수만큼 문자열을 새로 만들게 된다.
 * @param list 설정에 적힌 그대로의 접미사들.
 * @return 소문자·끝점 없는 형태. 빈 항목은 루트 이름에만 걸리므로 그대로 남긴다.
 */
fn normalize_ignored(list: Vec<String>) -> Vec<Box<str>> {
    list.into_iter()
        .map(|d| {
            d.trim()
                .trim_end_matches('.')
                .to_ascii_lowercase()
                .into_boxed_str()
        })
        .collect()
}

/**
 * @brief 이름을 소문자 점 표기로 스택 버퍼에 담는다.
 *
 * @details 질의마다 불리므로 할당하지 않는 것이 목적이다. 라벨 경계에서만 점을 넣으므로
 *          결과에 끝점이 붙지 않는다.
 * @param buf 결과를 담을 슬롯. 이름 길이 상한상 항상 충분하지만, 넘치면 할당해 돌려준다.
 * @return 소문자 표기. UTF-8이 아닌 라벨은 손실 변환되어 대체 문자가 된다.
 */
fn normalize_into<'a>(name: &Name, buf: &'a mut [u8; MAX_IGNORE_NAME]) -> Cow<'a, str> {
    let mut len = 0usize;
    for (index, label) in name.labels().enumerate() {
        if index != 0 {
            if len >= buf.len() {
                return Cow::Owned(name.to_ascii_lower());
            }
            buf[len] = b'.';
            len += 1;
        }
        for &byte in label {
            if len >= buf.len() {
                return Cow::Owned(name.to_ascii_lower());
            }
            buf[len] = byte.to_ascii_lowercase();
            len += 1;
        }
    }
    String::from_utf8_lossy(&buf[..len])
}

/**
 * @brief 정규화한 이름이 이 접미사에 걸리는지. 라벨 경계에서만 맞는 것으로 본다.
 * @param name normalize_into가 만든 소문자 표기.
 * @param d normalize_ignored가 만든 소문자 접미사.
 */
fn suffix_matches(name: &str, d: &str) -> bool {
    name == d
        || (name.len() > d.len()
            && name.ends_with(d)
            && name.as_bytes()[name.len() - d.len() - 1] == b'.')
}

/** @brief 주소의 host 부분을 가린다. 통계는 남기되 개인을 특정하지 못하게 한다. */
fn anonymize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], 0))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
    }
}

/** @brief 최소 힙. 상위 목록에서 가장 작은 것을 빨리 찾는 데 쓴다. */
type CounterHeap<K> = std::collections::BinaryHeap<std::cmp::Reverse<(u64, K)>>;

#[derive(Default)]
/** @brief 이름별 횟수와 상위 목록 유지 구조. */
pub struct TopCounters {
    /** @brief 이름별 질의 수. */
    pub domains: std::collections::HashMap<Name, u64>,
    /** @brief 이름별 차단 수. */
    pub blocked: std::collections::HashMap<Name, u64>,
    /** @brief 클라이언트별 질의 수. */
    pub clients: std::collections::HashMap<IpAddr, u64>,
    /** @brief 이름별 상위 항목을 뽑는 곳. */
    domains_heap: CounterHeap<Name>,
    /** @brief 차단 이름의 상위 항목을 뽑는 곳. */
    blocked_heap: CounterHeap<Name>,
    /** @brief 클라이언트의 상위 항목을 뽑는 곳. */
    clients_heap: CounterHeap<IpAddr>,
    /** @brief 상한에 닿은 뒤 이름이 맵에 없던 횟수. */
    domains_misses: u64,
    /** @brief 상한에 닿은 뒤 차단 이름이 맵에 없던 횟수. */
    blocked_misses: u64,
    /** @brief 상한에 닿은 뒤 클라이언트가 맵에 없던 횟수. */
    clients_misses: u64,
}

/** @brief 추적할 서로 다른 이름 수 상한. 종류가 많은 트래픽에서 메모리를 묶는다. */
pub(crate) const TOP_CAP: usize = 10_000;

/** @brief 통계 전용 이벤트를 모으는 슬롯 수. 워커가 서로 다른 슬롯을 써 경합을 줄인다. */
const STAT_SLOTS: usize = 16;

/** @brief 슬롯 하나가 담는 이벤트 수. 넘치면 버리고 버린 수를 센다. */
const STAT_SLOT_CAP: usize = 4096;

/** @brief 슬롯에 일이 있을 때의 확인 주기. 부하가 높으면 이 간격으로 계속 비운다. */
const BUSY_DRAIN_INTERVAL: Duration = Duration::from_millis(1);

/** @brief 다음에 배정할 슬롯. */
static NEXT_STAT_SLOT: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /** @brief 이 스레드가 쓸 슬롯. 처음 쓸 때 하나 배정받고 그대로 쓴다. */
    static STAT_SLOT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/** @brief 이 스레드에 배정된 슬롯 번호. */
fn stat_slot_index() -> usize {
    STAT_SLOT.with(|cell| match cell.get() {
        Some(index) => index,
        None => {
            let index = NEXT_STAT_SLOT.fetch_add(1, Ordering::Relaxed) % STAT_SLOTS;
            cell.set(Some(index));
            index
        }
    })
}

/**
 * @brief 통계 이벤트를 슬롯에 넣고 비어 있던 슬롯의 첫 push만 collector에 알린다.
 * @return 슬롯이 가득 차지 않아 넣었으면 참.
 */
fn push_stat_event(
    slot: &Mutex<StatSlot>,
    collector_idle: &AtomicBool,
    wake_tx: &mpsc::SyncSender<CollectorEvent>,
    transport: Transport,
    event: StatEvent,
) -> bool {
    let mut slot = slot.lock_recover();
    slot.counters.record(transport, event.action);
    if slot.events.len() >= STAT_SLOT_CAP {
        return false;
    }
    let wake = slot.events.is_empty();
    slot.events.push(event);
    drop(slot);
    if wake && collector_idle.swap(false, Ordering::AcqRel) {
        /*
         * 채널이 가득 찼다면 collector가 이미 처리할 일을 갖고 있어 다음 loop에서 슬롯도
         * 비운다. wake 자체를 잃은 통계 이벤트로 세면 안 된다.
         */
        let _ = wake_tx.try_send(CollectorEvent::StatsReady);
    }
    true
}

/** @brief 힙을 맵에서 다시 만든다. 지연 삭제가 쌓였을 때 정리한다. */
fn rebuild_heap<K: Eq + std::hash::Hash + Ord + Clone>(
    map: &std::collections::HashMap<K, u64>,
    heap: &mut CounterHeap<K>,
) {
    *heap = map
        .iter()
        .map(|(key, count)| std::cmp::Reverse((*count, key.clone())))
        .collect();
}

/**
 * @brief 상한에 닿은 뒤 몇 번에 한 번만 새 이름을 들일지.
 *
 * @details 서로 다른 이름이 상한보다 많으면 빗나간 질의마다 맵에서 빼고 넣고 힙을
 *          정리하게 된다. 리졸버가 보는 이름은 거의 언제나 상한보다 많으므로 그것이
 *          정상 상태다. 기준을 높여도 상위 목록의 뜻은 그대로다. 자주 오는 이름은 여러
 *          번 빗나가므로 곧 들어오고, 교체하는 값만 내려간다.
 * @invariant 2의 거듭제곱이어야 나머지 연산이 비트 마스크로 합쳐진다.
 */
const ADMIT_EVERY_MISSES: u64 = 16;

/**
 * @brief 이름 하나의 횟수를 올린다. 상한을 넘으면 가장 적은 것을 밀어낸다.
 * @param misses 상한에 닿은 뒤 빗나간 횟수. 이 맵의 문을 좁히는 데 쓴다.
 * @note 종류가 극단적으로 많은 트래픽에서도 메모리가 상한 안에 머물러야 한다.
 */
fn bump<K: Eq + std::hash::Hash + Ord + Clone>(
    map: &mut std::collections::HashMap<K, u64>,
    heap: &mut CounterHeap<K>,
    misses: &mut u64,
    key: &K,
) {
    /*
     * 힙은 실제 축출이 허용되는 순간에만 쓰인다. 상한에 닿았더라도 새 키가 없거나
     * admission 문을 아직 통과하지 않았다면 10,000개 키 복제와 힙 메모리가 필요 없다.
     */
    if let Some(v) = map.get_mut(key) {
        /*
         * 힙은 축출할 때만 읽는다. 올릴 때마다 키를 복제해 밀어 넣을 필요가 없다.
         * 낡은 항목은 축출이 계수 대조로 걸러내고, 다 걸러지면 그때 다시 만든다.
         */
        *v = v.saturating_add(1);
        return;
    }
    if map.len() < TOP_CAP {
        map.insert(key.clone(), 1);
        return;
    }

    /*
     * 여기서부터가 교체하는 경로다. 맵 삭제·삽입과 힙 정리가 모두 여기 있으므로,
     * 이름 종류가 상한보다 많으면 이 값이 질의마다 붙는다.
     */
    *misses = misses.wrapping_add(1);
    if *misses % ADMIT_EVERY_MISSES != 0 {
        return;
    }

    if heap.is_empty() {
        rebuild_heap(map, heap);
    }
    /*
     * 두 바퀴가 상한이다. 첫 바퀴에서 낡은 항목만 나와 힙이 비면 다시 만들고, 그 힙은
     * 맵과 계수가 정확히 같으므로 두 번째 바퀴의 첫 pop이 반드시 유효하다.
     * 이 폴백이 없으면 낡은 힙에서 새 이름이 조용히 버려진다.
     */
    for attempt in 0..2 {
        while let Some(std::cmp::Reverse((count, candidate))) = heap.pop() {
            if map.get(&candidate) != Some(&count) {
                continue;
            }
            map.remove(&candidate);
            let next = count.saturating_add(1);
            map.insert(key.clone(), next);
            heap.push(std::cmp::Reverse((next, key.clone())));
            return;
        }
        if attempt == 0 {
            rebuild_heap(map, heap);
        }
    }
}

/** @brief 상위 n개를 추출한다. */
fn top_n<K: std::fmt::Display>(
    map: &std::collections::HashMap<K, u64>,
    n: usize,
) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = map.iter().map(|(k, c)| (k.to_string(), *c)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

#[derive(Debug, Clone)]
/** @brief 대시보드에 보낼 상위 목록들. */
pub struct TopLists {
    /** @brief 많이 물은 이름들. */
    pub domains: Vec<(String, u64)>,
    /** @brief 많이 차단된 이름들. */
    pub blocked: Vec<(String, u64)>,
    /** @brief 많이 물은 클라이언트들. */
    pub clients: Vec<(String, u64)>,
}

/** @brief 실시간 구독자들의 보내는 쪽. */
type Subscribers = Arc<Mutex<Vec<mpsc::SyncSender<QueryEvent>>>>;

/** @brief 구독 하나. 놓친 구간이 있으면 그 사실도 함께 알린다. */
pub struct QuerySubscription {
    /** @brief 붙기 직전까지의 기록. 붙는 순간의 빈틈을 메운다. */
    pub replay: Vec<QueryEvent>,
    /** @brief 앞으로 올 기록을 받을 곳. */
    pub receiver: mpsc::Receiver<QueryEvent>,
    /** @brief 붙기 전 기록이 이미 밀려나 빠진 것이 있는지. */
    pub replay_gap: bool,
}

#[derive(Clone)]
/** @brief 대시보드가 읽는 쪽 핸들. */
pub struct Stats {
    /** @brief 누적 지표. */
    pub metrics: Arc<Metrics>,
    /** @brief 최근 질의 기록. */
    pub recent: Arc<Mutex<VecDeque<QueryEvent>>>,
    /** @brief 상위 항목 카운터. */
    pub top: Arc<Mutex<TopCounters>>,

    /** @brief 실시간 기록을 받는 쪽들. */
    subscribers: Subscribers,

    /** @brief 남겨 둘 최근 기록 수. */
    log_cap: Arc<AtomicUsize>,

    /** @brief 파일에 담는 설정. */
    persist: Arc<RwLock<PersistOpts>>,
}

impl Stats {
    /** @brief 최근 기록 몇 개. */
    pub fn recent(&self, limit: usize) -> Vec<QueryEvent> {
        let b = self.recent.lock_recover();
        b.iter().rev().take(limit).cloned().collect()
    }

    /** @brief 지금 보존 설정. */
    pub fn persist_opts(&self) -> PersistOpts {
        self.persist
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /**
     * @brief 최근 기록을 지운다.
     * @note 디스크 삭제가 실패하면 메모리도 지우지 않는다. 한쪽만 지우면 재시작 때
     *       지운 줄 알았던 기록이 되살아난다.
     */
    pub fn clear_recent(&self) -> std::io::Result<()> {
        let querylog_file = self
            .persist
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .querylog_file
            .clone();
        let mut recent = self.recent.lock_recover();
        if let Some(path) = querylog_file.as_deref() {
            crate::persist::save_querylog(path, &VecDeque::<QueryEvent>::new())?;
        }
        recent.clear();
        Ok(())
    }

    /** @brief 지금 상태를 디스크에 밀어낸다. */
    pub fn flush_persisted(&self) -> std::io::Result<()> {
        let persist = self.persist_opts();
        if let Some(path) = persist.querylog_file.as_deref() {
            let recent = self.recent.lock_recover();
            crate::persist::save_querylog(path, &recent)?;
        }
        if let Some(path) = persist.stats_file.as_deref() {
            let top = self.top.lock_recover();
            crate::persist::save_stats(path, &self.metrics, &top)?;
        }
        Ok(())
    }

    /** @brief 보존 설정을 바꾼다. 끄기 전에는 마지막 상태를 저장한다. */
    pub fn reconfigure_persist(&self, persist: PersistOpts) -> std::io::Result<()> {
        let mut current_guard = self
            .persist
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = current_guard.clone();
        if current == persist {
            return Ok(());
        }

        let querylog_path_changed = current.querylog_file != persist.querylog_file;
        if querylog_path_changed {
            if let Some(path) = current.querylog_file.as_deref() {
                let recent = self.recent.lock_recover();
                if let Err(error) = crate::persist::save_querylog(path, &recent) {
                    self.metrics
                        .persist_failures
                        .fetch_add(1, Ordering::Relaxed);
                    onetdns_core::warn!(
                        event = "querylog.previous_path_final_flush_failed",
                        path = %path.display(),
                        %error,
                        "Could not save the final state to the old query log file; switching to the new configuration anyway"
                    );
                }
            }
            if let Some(path) = persist.querylog_file.as_deref() {
                let recent = self.recent.lock_recover();
                crate::persist::save_querylog(path, &recent)?;
            }
        }

        let stats_path_changed = current.stats_file != persist.stats_file;
        if stats_path_changed {
            if let Some(path) = current.stats_file.as_deref() {
                let top = self.top.lock_recover();
                if let Err(error) = crate::persist::save_stats(path, &self.metrics, &top) {
                    self.metrics
                        .persist_failures
                        .fetch_add(1, Ordering::Relaxed);
                    onetdns_core::warn!(
                        event = "stats.previous_path_final_flush_failed",
                        path = %path.display(),
                        %error,
                        "Could not save the final state to the old statistics file; switching to the new configuration anyway"
                    );
                }
            }
            if let Some(path) = persist.stats_file.as_deref() {
                let top = self.top.lock_recover();
                crate::persist::save_stats(path, &self.metrics, &top)?;
            }
        }
        *current_guard = persist;
        Ok(())
    }

    /** @brief 이후 이벤트를 실시간으로 받는다. */
    pub fn subscribe(&self) -> mpsc::Receiver<QueryEvent> {
        self.subscribe_after(None).receiver
    }

    /**
     * @brief 특정 번호 이후의 이벤트를 받는다. 놓친 것은 먼저 재생한다.
     * @note 보존 기간이 지나 재생할 수 없으면 그 사실을 함께 알린다. 조용히 건너뛰면
     *       구독자는 빠진 줄도 모른다.
     */
    pub fn subscribe_after(&self, last_id: Option<u64>) -> QuerySubscription {
        let live_capacity = self.log_cap.load(Ordering::Acquire).max(256);
        let (tx, rx) = mpsc::sync_channel::<QueryEvent>(live_capacity);
        let recent = self.recent.lock_recover();
        let mut subscribers = self.subscribers.lock_recover();
        subscribers.push(tx);

        let requested = last_id.filter(|id| *id > 0);
        let replay = match requested {
            Some(id) => recent
                .iter()
                .filter(|event| event.id > id)
                .cloned()
                .collect::<Vec<_>>(),

            None => recent.iter().cloned().collect::<Vec<_>>(),
        };
        let replay_gap = requested.is_some_and(|id| {
            let oldest = recent.front().map(|event| event.id);
            let newest = recent.back().map(|event| event.id);
            match (oldest, newest) {
                (Some(oldest), Some(newest)) => {
                    if newest < id || oldest > id.saturating_add(1) {
                        true
                    } else {
                        let mut expected = id.saturating_add(1);
                        recent.iter().filter(|event| event.id > id).any(|event| {
                            let gap = event.id != expected;
                            expected = event.id.saturating_add(1);
                            gap
                        })
                    }
                }

                _ => true,
            }
        });

        QuerySubscription {
            replay,
            receiver: rx,
            replay_gap,
        }
    }

    /** @brief 상위 목록. */
    pub fn top(&self, n: usize) -> TopLists {
        let t = self.top.lock_recover();
        TopLists {
            domains: top_n(&t.domains, n),
            blocked: top_n(&t.blocked, n),
            clients: top_n(&t.clients, n),
        }
    }
}

/** @brief 수집 스레드가 이벤트 하나를 처리한다. 통계 갱신과 구독자 전달을 함께 한다. */
fn process_event(
    ev: QueryEvent,
    subs: &Subscribers,
    top: &Arc<Mutex<TopCounters>>,
    buf: &Arc<Mutex<VecDeque<QueryEvent>>>,
    retention_ms: &AtomicU64,
    log_cap: &AtomicUsize,
    metrics: &Metrics,
) {
    if ev.log {
        let mut b = buf.lock_recover();
        let retention_ms = retention_ms.load(Ordering::Acquire);
        let log_cap = log_cap.load(Ordering::Acquire).max(1);
        if retention_ms > 0 {
            let cutoff = now_ms().saturating_sub(retention_ms);
            while b.front().map(|e| e.ts_ms < cutoff).unwrap_or(false) {
                b.pop_front();
            }
        }
        while b.len() >= log_cap {
            b.pop_front();
        }
        b.push_back(ev.clone());

        let mut list = subs.lock_recover();
        if !list.is_empty() {
            list.retain(|s| match s.try_send(ev.clone()) {
                Ok(()) => true,

                Err(mpsc::TrySendError::Full(_)) => {
                    let dropped = metrics
                        .dropped_stream_events
                        .fetch_add(1, Ordering::Relaxed)
                        .saturating_add(1);
                    if dropped == 1 || dropped.is_power_of_two() {
                        onetdns_core::warn!(
                            event = "querylog.subscriber_dropped",
                            dropped,
                            "Closed a slow live log subscriber"
                        );
                    }
                    false
                }
                Err(mpsc::TrySendError::Disconnected(_)) => false,
            });
        }
    }
    if ev.stat {
        process_stat_values(
            &ev.client,
            ev.name.as_ref(),
            ev.action == Action::Blocked.name(),
            top,
        );
    }
}

/** @brief 통계 전용 값으로 상위 목록을 갱신한다. */
fn process_stat_values(
    client: &IpAddr,
    name: Option<&Name>,
    blocked_action: bool,
    top: &Arc<Mutex<TopCounters>>,
) {
    let mut t = top.lock_recover();
    process_stat_values_locked(client, name, blocked_action, &mut t);
}

/** @brief 이미 상위 목록 잠금을 가진 batch 안에서 통계 값 하나를 반영한다. */
fn process_stat_values_locked(
    client: &IpAddr,
    name: Option<&Name>,
    blocked_action: bool,
    t: &mut TopCounters,
) {
    let TopCounters {
        domains,
        blocked,
        clients,
        domains_heap,
        blocked_heap,
        clients_heap,
        domains_misses,
        blocked_misses,
        clients_misses,
    } = t;
    if let Some(name) = name {
        /* 키는 대소문자를 구분하므로 바꿔서 넣는다. 이미 소문자면 빌린 참조를 그대로 쓴다. */
        let name = name.to_ascii_lower_name();
        let name = name.as_ref();
        bump(domains, domains_heap, domains_misses, name);
        if blocked_action {
            bump(blocked, blocked_heap, blocked_misses, name);
        }
    }
    bump(clients, clients_heap, clients_misses, client);
}

#[derive(Clone, Copy)]
/** @brief 파일에 보존하는 통계 자료의 종류. */
enum PersistKind {
    /** @brief 상세 질의 기록. */
    Querylog,
    /** @brief 누적 통계. */
    Stats,
}

impl PersistKind {
    /** @brief 구조화 로그에 쓸 고정 이름. */
    fn as_str(self) -> &'static str {
        match self {
            PersistKind::Querylog => "querylog",
            PersistKind::Stats => "stats",
        }
    }
}

/** @brief 저장 종류 하나의 마지막 실패 지문과 경고 시각. */
struct PersistWarningState {
    /** @brief 원문을 보관하지 않는 저장 경로 지문. */
    path: u64,
    /** @brief 원문을 보관하지 않는 오류 문자열 지문. */
    message: u64,
    /** @brief 이 실패를 마지막으로 경고한 시각. */
    last: Instant,
}

/** @brief 저장 종류별 고정 슬롯으로 되풀이 경고를 억제하는 상태. */
struct PersistWarnings {
    /** @brief 입력으로 지문 충돌을 고르지 못하게 하는 프로세스별 상태. */
    fingerprint_state: RandomState,
    /** @brief 질의 기록 저장 실패 슬롯. */
    querylog: Option<PersistWarningState>,
    /** @brief 누적 통계 저장 실패 슬롯. */
    stats: Option<PersistWarningState>,
}

impl Default for PersistWarnings {
    /** @brief 비어 있는 두 저장 실패 슬롯을 만든다. */
    fn default() -> Self {
        Self {
            fingerprint_state: RandomState::new(),
            querylog: None,
            stats: None,
        }
    }
}

impl PersistWarnings {
    /** @brief 저장 종류에 대응하는 고정 슬롯. */
    fn slot_mut(&mut self, kind: PersistKind) -> &mut Option<PersistWarningState> {
        match kind {
            PersistKind::Querylog => &mut self.querylog,
            PersistKind::Stats => &mut self.stats,
        }
    }

    /** @brief 이 실패를 지금 경고해야 하는지 판정하고 지문 상태를 갱신한다. */
    fn should_log(&mut self, kind: PersistKind, path: &Path, message: &str, now: Instant) -> bool {
        let path = self.fingerprint_state.hash_one(("path", path));
        let message = self.fingerprint_state.hash_one(("message", message));
        let slot = self.slot_mut(kind);
        let should_log = slot
            .as_ref()
            .map(|previous| {
                previous.path != path
                    || previous.message != message
                    || now.saturating_duration_since(previous.last) >= Duration::from_secs(60)
            })
            .unwrap_or(true);
        if should_log {
            *slot = Some(PersistWarningState {
                path,
                message,
                last: now,
            });
        }
        should_log
    }

    /** @brief 성공한 저장 종류의 실패 상태를 지운다. */
    fn clear(&mut self, kind: PersistKind) {
        *self.slot_mut(kind) = None;
    }

    #[cfg(test)]
    /** @brief 지금 차 있는 저장 실패 슬롯 수. */
    fn retained_slots(&self) -> usize {
        usize::from(self.querylog.is_some()) + usize::from(self.stats.is_some())
    }
}

/** @brief 저장 실패를 로그로 남긴다. */
fn persist_warning(
    warnings: &mut PersistWarnings,
    kind: PersistKind,
    path: &Path,
    error: Option<&std::io::Error>,
) {
    match error {
        Some(error) => {
            let message = error.to_string();
            let now = Instant::now();
            if warnings.should_log(kind, path, &message, now) {
                onetdns_core::warn!(event = "stats.persist_flush_failed", kind = kind.as_str(), path = %path.display(), error = %error, "Could not save the statistics or query log file");
            }
        }
        None => warnings.clear(kind),
    }
}

/** @brief 지표와 기록을 디스크에 쓴다. */
fn flush_persist(
    persist: &PersistOpts,
    metrics: &Metrics,
    top: &Arc<Mutex<TopCounters>>,
    buf: &Arc<Mutex<VecDeque<QueryEvent>>>,
    warnings: &mut PersistWarnings,
) {
    if let Some(p) = &persist.querylog_file {
        let b = buf.lock_recover();
        match crate::persist::save_querylog(p, &b) {
            Ok(()) => persist_warning(warnings, PersistKind::Querylog, p, None),
            Err(e) => {
                metrics.persist_failures.fetch_add(1, Ordering::Relaxed);
                persist_warning(warnings, PersistKind::Querylog, p, Some(&e));
            }
        }
    }
    if let Some(p) = &persist.stats_file {
        let t = top.lock_recover();
        match crate::persist::save_stats(p, metrics, &t) {
            Ok(()) => persist_warning(warnings, PersistKind::Stats, p, None),
            Err(e) => {
                metrics.persist_failures.fetch_add(1, Ordering::Relaxed);
                persist_warning(warnings, PersistKind::Stats, p, Some(&e));
            }
        }
    }
}

/**
 * @brief 기록기와 읽기 핸들을 만들고 배경 스레드를 시작한다.
 * @details 유계 채널 하나로 데이터 경로와 수집을 나눈다. 이 경계가 있어야 지표가 질의
 *          처리를 막지 않는다.
 */
pub fn channel(
    queue: usize,
    log_cap: usize,
    retention_secs: u64,
    opts: RecorderOpts,
    persist: PersistOpts,
) -> (Recorder, Stats) {
    let (tx, rx) = mpsc::sync_channel::<CollectorEvent>(queue.max(1));
    let stat_slots: Arc<Vec<Mutex<StatSlot>>> = Arc::new(
        (0..STAT_SLOTS)
            .map(|_| Mutex::new(StatSlot::default()))
            .collect::<Vec<_>>(),
    );
    let stat_collector_idle = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(Metrics {
        stat_slots: Some(stat_slots.clone()),
        ..Metrics::default()
    });
    let retention_ms = Arc::new(AtomicU64::new(retention_secs.saturating_mul(1000)));
    let log_cap_state = Arc::new(AtomicUsize::new(log_cap.max(1)));
    let persist_state = Arc::new(RwLock::new(persist.clone()));
    metrics.set_history_retention(opts.stats_retention_secs);

    let mut initial_recent = VecDeque::<QueryEvent>::with_capacity(log_cap);
    let mut initial_top = TopCounters::default();
    if let Some(p) = &persist.querylog_file {
        initial_recent = crate::persist::load_querylog(
            p,
            log_cap,
            retention_ms.load(Ordering::Relaxed),
            now_ms(),
        );
    }
    if let Some(p) = &persist.stats_file {
        crate::persist::load_stats(p, &metrics, &mut initial_top);
    }
    let mut next_event_id = 1u64;
    for ev in &mut initial_recent {
        if ev.id == 0 {
            ev.id = next_event_id;
        }
        next_event_id = next_event_id.max(ev.id.saturating_add(1));
    }
    metrics.reset_history_baseline();
    let stop = Arc::new(AtomicBool::new(false));
    let sampler = {
        let sampled_metrics = Arc::downgrade(&metrics);
        let sampler_stop = stop.clone();
        match std::thread::Builder::new()
            .name("onetdns-metrics-sampler".into())
            .spawn(move || {
                let Some(initial_metrics) = sampled_metrics.upgrade() else {
                    return;
                };
                let initial = initial_metrics.snapshot();
                let initial_latency_sum_us = initial_metrics.latency_sum_us.load(Ordering::Relaxed);
                let initial_latency_count = initial_metrics.latency_count.load(Ordering::Relaxed);
                drop(initial_metrics);
                let mut seconds = 0u64;
                let mut previous_total = initial.total;
                let mut previous_blocked = initial.blocked;
                let mut previous_servfail = initial.servfail;
                let mut previous_dropped_logs = initial.dropped_log_events;
                let mut previous_dropped_stream = initial.dropped_stream_events;
                let mut previous_persist_failures = initial.persist_failures;
                let mut previous_latency_sum_us = initial_latency_sum_us;
                let mut previous_latency_count = initial_latency_count;
                let mut previous_cache_hits = initial.cache_hits;
                let mut previous_cache_lookups = initial.cache_lookups;
                loop {
                    std::thread::park_timeout(Duration::from_secs(1));
                    if sampler_stop.load(Ordering::Acquire) {
                        break;
                    }
                    let Some(metrics) = sampled_metrics.upgrade() else {
                        break;
                    };
                    metrics.sample_now();
                    seconds = seconds.saturating_add(1);
                    if seconds % 60 != 0 {
                        continue;
                    }
                    let snapshot = metrics.snapshot();
                    let latency_sum_us = metrics.latency_sum_us.load(Ordering::Relaxed);
                    let latency_count = metrics.latency_count.load(Ordering::Relaxed);
                    let minute_latency_sum = latency_sum_us.saturating_sub(previous_latency_sum_us);
                    let minute_latency_count = latency_count.saturating_sub(previous_latency_count);
                    let minute_avg_latency_ms = if minute_latency_count > 0 {
                        minute_latency_sum as f64 / minute_latency_count as f64 / 1_000.0
                    } else {
                        0.0
                    };
                    let minute_cache_hits = snapshot.cache_hits.saturating_sub(previous_cache_hits);
                    let minute_cache_lookups = snapshot
                        .cache_lookups
                        .saturating_sub(previous_cache_lookups);
                    let minute_cache_hit_pct = if minute_cache_lookups > 0 {
                        minute_cache_hits as f64 * 100.0 / minute_cache_lookups as f64
                    } else {
                        0.0
                    };
                    let dropped_query_logs = snapshot
                        .dropped_log_events
                        .saturating_sub(previous_dropped_logs);
                    let dropped_live_events = snapshot
                        .dropped_stream_events
                        .saturating_sub(previous_dropped_stream);
                    let persist_failures = snapshot
                        .persist_failures
                        .saturating_sub(previous_persist_failures);
                    if snapshot.total != previous_total
                        || dropped_query_logs > 0
                        || dropped_live_events > 0
                        || persist_failures > 0
                    {
                        onetdns_core::info!(
                            event = "metrics.minute_summary",
                            queries = snapshot.total.saturating_sub(previous_total),
                            blocked = snapshot.blocked.saturating_sub(previous_blocked),
                            servfail = snapshot.servfail.saturating_sub(previous_servfail),
                            total = snapshot.total,
                            avg_latency_ms = minute_avg_latency_ms,
                            cache_hit_pct = minute_cache_hit_pct,
                            dropped_query_logs,
                            dropped_live_events,
                            persist_failures,
                            "DNS activity over the last minute"
                        );
                    }
                    previous_total = snapshot.total;
                    previous_blocked = snapshot.blocked;
                    previous_servfail = snapshot.servfail;
                    previous_dropped_logs = snapshot.dropped_log_events;
                    previous_dropped_stream = snapshot.dropped_stream_events;
                    previous_persist_failures = snapshot.persist_failures;
                    previous_latency_sum_us = latency_sum_us;
                    previous_latency_count = latency_count;
                    previous_cache_hits = snapshot.cache_hits;
                    previous_cache_lookups = snapshot.cache_lookups;
                }
            }) {
            Ok(thread) => Some(thread),
            Err(error) => {
                onetdns_core::warn!(event = "metrics.sampler_start_failed", %error, "Could not start the time-series statistics thread; time-series recording is disabled");
                None
            }
        }
    };

    let recent = Arc::new(Mutex::new(initial_recent));
    let top = Arc::new(Mutex::new(initial_top));
    let subscribers: Subscribers = Arc::new(Mutex::new(Vec::new()));

    let buf = recent.clone();
    let top_c = top.clone();
    let subs = subscribers.clone();
    let metrics_t = metrics.clone();
    let retention_t = retention_ms.clone();
    let log_cap_t = log_cap_state.clone();

    let persist_state_t = persist_state.clone();

    let collector_stop = stop.clone();
    let collector_slots = stat_slots.clone();
    let collector_idle = stat_collector_idle.clone();
    let collector = match std::thread::Builder::new()
        .name("onetdns-metrics-collector".into())
        .spawn(move || {
            let mut last_flush = Instant::now();
            let mut dirty = false;
            let mut persist_warnings = PersistWarnings::default();

            /*
             * 슬롯을 비우는 주기이기도 하다. 길게 잡으면 슬롯이 넘쳐 통계가 표본이 된다.
             * 슬롯 전체 용량을 이 시간 안에 들어오는 질의 수보다 크게 유지해야 한다.
             */
            let poll_interval = Duration::from_millis(20);
            let mut process = |mut ev: QueryEvent| {
                if ev.log {
                    ev.id = next_event_id;
                    next_event_id = next_event_id.saturating_add(1);
                }
                process_event(
                    ev,
                    &subs,
                    &top_c,
                    &buf,
                    &retention_t,
                    &log_cap_t,
                    &metrics_t,
                );
            };
            /*
             * 슬롯에 모인 통계 전용 이벤트를 가져온다. slot 잠금은 통째 교체 동안만,
             * 상위 목록 잠금은 batch 하나 동안만 잡는다.
             */
            let drain_slots = || -> bool {
                let mut seen = false;
                for slot in collector_slots.iter() {
                    let batch = std::mem::take(&mut slot.lock_recover().events);
                    if batch.is_empty() {
                        continue;
                    }
                    seen = true;
                    let mut top = top_c.lock_recover();
                    for ev in batch {
                        process_stat_values_locked(
                            &ev.client,
                            ev.name.as_ref(),
                            matches!(ev.action, Action::Blocked),
                            &mut top,
                        );
                    }
                }
                seen
            };

            /*
             * 슬롯에 일이 있었으면 거의 자지 않고 곧장 다시 본다. 주기 하나로만 비우면
             * 부하가 높을 때 슬롯이 넘쳐 통계가 표본이 된다.
             */
            loop {
                let wait = if drain_slots() {
                    collector_idle.store(false, Ordering::Release);
                    dirty = true;
                    BUSY_DRAIN_INTERVAL
                } else {
                    /*
                     * 첫 drain과 idle 표시 사이에 들어온 이벤트는 표시 뒤 재검사로 잡는다.
                     * 그 뒤 들어온 첫 이벤트는 표시를 내리고 wake token을 보낸다.
                     */
                    collector_idle.store(true, Ordering::Release);
                    if drain_slots() {
                        collector_idle.store(false, Ordering::Release);
                        dirty = true;
                        BUSY_DRAIN_INTERVAL
                    } else {
                        poll_interval
                    }
                };
                match rx.recv_timeout(wait) {
                    Ok(CollectorEvent::Log(ev)) => {
                        process(ev);
                        dirty = true;
                    }
                    Ok(CollectorEvent::StatsReady) => {}
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        /* 보내는 쪽이 사라져도 슬롯에 남은 것은 통계에 반영하고 나간다. */
                        drain_slots();
                        let persist = persist_state_t
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .clone();
                        if persist.enabled() {
                            flush_persist(
                                &persist,
                                &metrics_t,
                                &top_c,
                                &buf,
                                &mut persist_warnings,
                            );
                        }
                        return;
                    }
                }
                if collector_stop.load(Ordering::Acquire) {
                    while let Ok(event) = rx.try_recv() {
                        if let CollectorEvent::Log(ev) = event {
                            process(ev);
                        }
                    }
                    drain_slots();
                    let persist = persist_state_t
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone();
                    if persist.enabled() {
                        flush_persist(&persist, &metrics_t, &top_c, &buf, &mut persist_warnings);
                    }
                    return;
                }
                let persist = persist_state_t
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                let flush_interval = Duration::from_secs(persist.flush_secs.max(1));
                if persist.enabled() && dirty && last_flush.elapsed() >= flush_interval {
                    flush_persist(&persist, &metrics_t, &top_c, &buf, &mut persist_warnings);
                    last_flush = Instant::now();
                    dirty = false;
                }
            }
        }) {
        Ok(thread) => Some(thread),
        Err(error) => {
            onetdns_core::warn!(event = "metrics.collector_start_failed", %error, "Could not start the statistics writer thread; query logging is disabled");
            None
        }
    };
    let runtime = Arc::new(RecorderRuntime {
        stop,
        sampler: Mutex::new(sampler),
        collector: Mutex::new(collector),
    });

    (
        Recorder {
            metrics: metrics.clone(),
            log_tx: tx,
            stat_slots,
            stat_collector_idle,
            querylog: Arc::new(AtomicBool::new(opts.querylog)),
            collecting: Arc::new(AtomicBool::new(true)),
            anonymize: Arc::new(AtomicBool::new(opts.anonymize)),
            ignored_active: Arc::new(AtomicBool::new(!opts.ignored.is_empty())),
            ignored: Arc::new(RwLock::new(normalize_ignored(opts.ignored))),
            log_cap: log_cap_state.clone(),
            retention_ms,
            recent: recent.clone(),
            _runtime: runtime,
        },
        Stats {
            metrics,
            recent,
            top,
            subscribers,
            log_cap: log_cap_state,
            persist: persist_state,
        },
    )
}

/** @brief 현재 Unix 밀리초. */
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
/** @brief 데이터 경로를 막지 않는 것, 설정 변경에도 통계가 살아남는 것, 그리고 구독 끊김 통지. */
mod tests {
    use super::*;

    #[test]
    /** @brief 통계 전용 슬롯이 로그 문자열 구조체 때문에 다시 커지지 않는지. */
    fn stat_event_keeps_slot_memory_compact() {
        let compact = std::mem::size_of::<StatEvent>();
        let full = std::mem::size_of::<QueryEvent>();
        assert!(
            compact <= 64,
            "통계 전용 이벤트가 {compact}바이트라 캐시 친화적 상한을 넘었습니다"
        );
        assert!(
            compact.saturating_mul(4) <= full,
            "통계 전용 이벤트 {compact}B가 전체 로그 이벤트 {full}B와 다시 비슷해졌습니다"
        );
        assert!(
            STAT_SLOTS * STAT_SLOT_CAP * compact <= 4 * 1024 * 1024,
            "모든 통계 슬롯의 payload 상한이 4 MiB를 넘었습니다"
        );
        assert!(
            STAT_SLOTS * std::mem::size_of::<StatCounters>() <= 4 * 1024,
            "샤드 누적 계수가 고정 메모리 4 KiB를 넘었습니다"
        );
    }

    #[test]
    /** @brief idle collector만 첫 슬롯 이벤트로 깨우고 지속 부하 wake는 합쳐지는지. */
    fn stat_slot_wakes_only_an_idle_collector() {
        let (tx, rx) = mpsc::sync_channel(1);
        let slot = Mutex::new(StatSlot::default());
        let idle = AtomicBool::new(false);
        let event = || StatEvent {
            client: IpAddr::V4(Ipv4Addr::LOCALHOST),
            name: None,
            action: Action::Resolved,
        };

        assert!(push_stat_event(
            &slot,
            &idle,
            &tx,
            Transport::Do53Udp,
            event()
        ));
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));

        slot.lock_recover().events.clear();
        idle.store(true, Ordering::Release);
        assert!(push_stat_event(
            &slot,
            &idle,
            &tx,
            Transport::Do53Udp,
            event()
        ));
        assert!(matches!(rx.try_recv(), Ok(CollectorEvent::StatsReady)));
        assert!(!idle.load(Ordering::Acquire));
        assert!(push_stat_event(
            &slot,
            &idle,
            &tx,
            Transport::Do53Udp,
            event()
        ));
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }

    #[test]
    /** @brief log-off 샤드 계수가 즉시 정확하고 저장·복원에도 빠지지 않는지. */
    fn sharded_stat_counters_are_immediate_and_persisted() {
        let opts = RecorderOpts {
            querylog: false,
            ..RecorderOpts::default()
        };
        let (recorder, _stats) = channel(16, 16, 0, opts, PersistOpts::default());
        let name = Name::from_str("sharded.example.").unwrap();
        for (transport, action) in Transport::ALL.into_iter().zip(Action::ALL) {
            recorder.record(
                transport,
                action,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                Some(&name),
                Some(RecordType::A),
                true,
                true,
            );
        }

        let snapshot = recorder.metrics().snapshot();
        assert_eq!(snapshot.total, Action::ALL.len() as u64);
        assert_eq!(snapshot.resolved, 1);
        assert_eq!(snapshot.blocked, 1);
        assert_eq!(snapshot.rewritten, 1);
        assert_eq!(snapshot.denied, 1);
        assert_eq!(snapshot.refused, 1);
        assert_eq!(snapshot.throttled, 1);
        assert_eq!(snapshot.servfail, 1);
        assert!(snapshot.by_transport.iter().all(|(_, count)| *count == 1));

        let path = std::env::temp_dir().join(format!(
            "onetdns-sharded-stats-{}-{}.json",
            std::process::id(),
            now_ms()
        ));
        crate::persist::save_stats(&path, recorder.metrics(), &TopCounters::default()).unwrap();
        let restored = Metrics::default();
        let mut restored_top = TopCounters::default();
        crate::persist::load_stats(&path, &restored, &mut restored_top);
        assert_eq!(restored.snapshot().total, Action::ALL.len() as u64);
        assert_eq!(restored.snapshot().blocked, 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    /** @brief 상위 목록 슬롯이 차도 누적 질의 계수는 한 건도 잃지 않는지. */
    fn full_stat_slot_drops_only_top_attribution() {
        let (tx, _rx) = mpsc::sync_channel(1);
        let slots = Arc::new(vec![Mutex::new(StatSlot::default())]);
        let idle = AtomicBool::new(false);
        let mut accepted = 0usize;
        for _ in 0..STAT_SLOT_CAP + 3 {
            accepted += usize::from(push_stat_event(
                &slots[0],
                &idle,
                &tx,
                Transport::Do53Udp,
                StatEvent {
                    client: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    name: None,
                    action: Action::Resolved,
                },
            ));
        }
        assert_eq!(accepted, STAT_SLOT_CAP);
        assert_eq!(slots[0].lock_recover().events.len(), STAT_SLOT_CAP);

        let metrics = Metrics {
            stat_slots: Some(slots),
            ..Metrics::default()
        };
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.total, (STAT_SLOT_CAP + 3) as u64);
        assert_eq!(snapshot.resolved, snapshot.total);
    }

    #[test]
    /** @brief 여러 워커가 동시에 샤드에 더해도 snapshot 총계가 정확한지. */
    fn sharded_stat_counters_are_exact_under_concurrency() {
        const THREADS: usize = 8;
        const PER_THREAD: usize = 1_000;
        let opts = RecorderOpts {
            querylog: false,
            ..RecorderOpts::default()
        };
        let (recorder, _stats) = channel(16, 16, 0, opts, PersistOpts::default());
        let mut threads = Vec::new();
        for index in 0..THREADS {
            let recorder = recorder.clone();
            threads.push(std::thread::spawn(move || {
                let name = Name::from_str(&format!("worker-{index}.example.")).unwrap();
                for _ in 0..PER_THREAD {
                    recorder.record(
                        Transport::Do53Udp,
                        Action::Resolved,
                        IpAddr::V4(Ipv4Addr::LOCALHOST),
                        Some(&name),
                        Some(RecordType::A),
                        true,
                        true,
                    );
                }
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }

        let snapshot = recorder.metrics().snapshot();
        let expected = (THREADS * PER_THREAD) as u64;
        assert_eq!(snapshot.total, expected);
        assert_eq!(snapshot.resolved, expected);
        assert_eq!(
            snapshot.by_transport[Transport::Do53Udp.index()].1,
            expected
        );
    }

    #[test]
    #[ignore = "마이크로벤치: cargo test -p onetdns-control --release bench_stat_slot_payload -- --ignored --nocapture"]
    /** @brief 전체 로그 이벤트와 compact 통계 이벤트의 슬롯 쓰기 비용을 같은 바이너리에서 측정한다. */
    fn bench_stat_slot_payload() {
        const BATCHES: usize = 256;
        let client = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let name = Name::from_str("stat.example.").unwrap();

        let bench_full = || {
            let started = Instant::now();
            for _ in 0..BATCHES {
                let mut slot = Vec::with_capacity(STAT_SLOT_CAP);
                for _ in 0..STAT_SLOT_CAP {
                    slot.push(QueryEvent {
                        id: 0,
                        ts_ms: 0,
                        client,
                        name: Some(name.clone()),
                        qtype: String::new(),
                        transport: Transport::Do53Udp.name(),
                        action: Action::Resolved.name(),
                        rcode: String::new(),
                        reason: String::new(),
                        stage: String::new(),
                        detail: String::new(),
                        answers: String::new(),
                        upstream: String::new(),
                        rule: String::new(),
                        list: String::new(),
                        latency_us: 0,
                        log: false,
                        stat: true,
                    });
                }
                std::hint::black_box(&slot);
            }
            started.elapsed()
        };
        let bench_compact = || {
            let started = Instant::now();
            for _ in 0..BATCHES {
                let mut slot = Vec::with_capacity(STAT_SLOT_CAP);
                for _ in 0..STAT_SLOT_CAP {
                    slot.push(StatEvent {
                        client,
                        name: Some(name.clone()),
                        action: Action::Resolved,
                    });
                }
                std::hint::black_box(&slot);
            }
            started.elapsed()
        };

        let mut full = [Duration::ZERO; 5];
        let mut compact = [Duration::ZERO; 5];
        for i in 0..5 {
            full[i] = bench_full();
            compact[i] = bench_compact();
        }
        full.sort_unstable();
        compact.sort_unstable();
        let events = (BATCHES * STAT_SLOT_CAP) as f64;
        let full_ns = full[2].as_nanos() as f64 / events;
        let compact_ns = compact[2].as_nanos() as f64 / events;
        eprintln!(
            "stat slot payload: full={}B {:.2}ns/event, compact={}B {:.2}ns/event, speedup={:.2}x",
            std::mem::size_of::<QueryEvent>(),
            full_ns,
            std::mem::size_of::<StatEvent>(),
            compact_ns,
            full_ns / compact_ns
        );
    }

    #[test]
    #[ignore = "마이크로벤치: cargo test -p onetdns-control --release bench_stat_counter_folding -- --ignored --nocapture"]
    /** @brief 전역 누적 atomic 세 번을 이미 잡는 슬롯 잠금에 합칠 가치가 있는지 구분한다. */
    fn bench_stat_counter_folding() {
        const EVENTS: usize = 1_000_000;
        let client = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let name = Name::from_str("counter.example.").unwrap();

        let old = || {
            let total = AtomicU64::new(0);
            let transport = AtomicU64::new(0);
            let resolved = AtomicU64::new(0);
            let slot = Mutex::new(Vec::with_capacity(STAT_SLOT_CAP));
            let started = Instant::now();
            for _ in 0..EVENTS {
                total.fetch_add(1, Ordering::Relaxed);
                transport.fetch_add(1, Ordering::Relaxed);
                resolved.fetch_add(1, Ordering::Relaxed);
                let mut slot = slot.lock_recover();
                if slot.len() == STAT_SLOT_CAP {
                    slot.clear();
                }
                slot.push(StatEvent {
                    client,
                    name: Some(name.clone()),
                    action: Action::Resolved,
                });
            }
            std::hint::black_box((
                total.load(Ordering::Relaxed),
                transport.load(Ordering::Relaxed),
                resolved.load(Ordering::Relaxed),
                slot,
            ));
            started.elapsed()
        };
        let folded = || {
            let slot = Mutex::new((Vec::with_capacity(STAT_SLOT_CAP), [0u64; 3]));
            let started = Instant::now();
            for _ in 0..EVENTS {
                let mut slot = slot.lock_recover();
                slot.1[0] += 1;
                slot.1[1] += 1;
                slot.1[2] += 1;
                if slot.0.len() == STAT_SLOT_CAP {
                    slot.0.clear();
                }
                slot.0.push(StatEvent {
                    client,
                    name: Some(name.clone()),
                    action: Action::Resolved,
                });
            }
            std::hint::black_box(slot);
            started.elapsed()
        };

        let mut baseline = [Duration::ZERO; 6];
        let mut candidate = [Duration::ZERO; 6];
        for index in 0..baseline.len() {
            if index % 2 == 0 {
                baseline[index] = old();
                candidate[index] = folded();
            } else {
                candidate[index] = folded();
                baseline[index] = old();
            }
        }
        baseline.sort_unstable();
        candidate.sort_unstable();
        let old_ns = baseline[baseline.len() / 2].as_nanos() as f64 / EVENTS as f64;
        let new_ns = candidate[candidate.len() / 2].as_nanos() as f64 / EVENTS as f64;
        eprintln!(
            "stat counter folding: atomics+slot={old_ns:.2}ns/event folded={new_ns:.2}ns/event speedup={:.2}x",
            old_ns / new_ns
        );
    }

    #[test]
    #[ignore = "마이크로벤치: cargo test -p onetdns-control --release bench_stat_top_batch_lock -- --ignored --nocapture"]
    /** @brief 상위 목록 잠금을 이벤트마다 잡는 것과 슬롯 batch마다 잡는 비용을 구분한다. */
    fn bench_stat_top_batch_lock() {
        const BATCHES: usize = 128;
        let client = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let name = Name::from_str("stat.example.").unwrap();

        let per_event = || {
            let top = Arc::new(Mutex::new(TopCounters::default()));
            let started = Instant::now();
            for _ in 0..BATCHES {
                for _ in 0..STAT_SLOT_CAP {
                    process_stat_values(&client, Some(&name), false, &top);
                }
            }
            std::hint::black_box(top);
            started.elapsed()
        };
        let batched = || {
            let top = Mutex::new(TopCounters::default());
            let started = Instant::now();
            for _ in 0..BATCHES {
                let mut top = top.lock_recover();
                for _ in 0..STAT_SLOT_CAP {
                    process_stat_values_locked(&client, Some(&name), false, &mut top);
                }
            }
            std::hint::black_box(top);
            started.elapsed()
        };

        let mut old = [Duration::ZERO; 6];
        let mut new = [Duration::ZERO; 6];
        for index in 0..6 {
            if index % 2 == 0 {
                old[index] = per_event();
                new[index] = batched();
            } else {
                new[index] = batched();
                old[index] = per_event();
            }
        }
        old.sort_unstable();
        new.sort_unstable();
        let events = (BATCHES * STAT_SLOT_CAP) as f64;
        let old_ns = old[old.len() / 2].as_nanos() as f64 / events;
        let new_ns = new[new.len() / 2].as_nanos() as f64 / events;
        eprintln!(
            "stat top lock: per_event={old_ns:.2}ns/event batched={new_ns:.2}ns/event speedup={:.2}x",
            old_ns / new_ns
        );
    }

    #[test]
    /** @brief 마지막 기록기가 사라질 때 남은 이벤트를 비우고 스레드를 정리하는지. */
    fn last_recorder_drop_drains_events_and_joins_metrics_threads() {
        let querylog = std::env::temp_dir().join(format!(
            "onetdns-metrics-drain-{}-{}.jsonl",
            std::process::id(),
            now_ms()
        ));
        let (recorder, stats) = channel(
            8,
            8,
            60,
            RecorderOpts::default(),
            PersistOpts {
                querylog_file: Some(querylog.clone()),
                flush_secs: 3_600,
                ..PersistOpts::default()
            },
        );
        let runtime = Arc::downgrade(&recorder._runtime);
        let name = Name::from_str("drain.example").unwrap();
        recorder.record(
            Transport::Do53Udp,
            Action::Resolved,
            "127.0.0.1".parse().unwrap(),
            Some(&name),
            Some(RecordType::A),
            true,
            true,
        );
        let clone = recorder.clone();
        drop(recorder);
        assert!(runtime.upgrade().is_some());

        let started = Instant::now();
        drop(clone);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(runtime.upgrade().is_none());
        assert_eq!(
            stats.recent(1)[0].name.as_ref().map(Name::to_string),
            Some("drain.example.".to_string())
        );
        let persisted = std::fs::read_to_string(&querylog).unwrap();
        assert!(persisted.contains("drain.example."));
        std::fs::remove_file(querylog).unwrap();
    }

    #[test]
    /**
     * @brief 볼 곳이 없다고 알려 주면 질의마다 아무것도 만들지 않는지.
     *
     * @details 헤드리스 배포는 관리 수신 주소도 저장 파일도 없어 여기 쌓인 것을 읽을
     *          길이 없다. 그런데도 이벤트를 만들어 슬롯에 넣으면 해석당 CPU의 4분의 1을
     *          쓰지도 않을 통계에 낸다.
     */
    fn nothing_is_collected_when_nobody_can_read_it() {
        let (recorder, stats) = channel(8, 8, 60, RecorderOpts::default(), PersistOpts::default());
        let name = Name::from_str("unread.example").unwrap();
        let hit = || {
            recorder.record(
                Transport::Do53Udp,
                Action::Resolved,
                "127.0.0.1".parse().unwrap(),
                Some(&name),
                Some(RecordType::A),
                true,
                true,
            );
            let deadline = Instant::now() + Duration::from_millis(500);
            while stats.recent(8).is_empty() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
        };

        recorder.set_collecting(false);
        hit();
        assert_eq!(
            recorder.metrics().snapshot().total,
            0,
            "볼 곳이 없는데 누적 통계를 셌습니다"
        );
        assert!(
            stats.recent(8).is_empty(),
            "볼 곳이 없는데 질의 기록을 남겼습니다"
        );

        /*
         * 대조군. 같은 호출이 볼 곳이 생기면 반드시 남아야 한다. 이것이 없으면 위 단정은
         * 기록기가 전부 고장 나도 통과한다.
         */
        recorder.set_collecting(true);
        hit();
        assert_eq!(
            recorder.metrics().snapshot().total,
            1,
            "볼 곳이 있는데 누적 통계를 세지 않았습니다"
        );
        assert_eq!(
            stats.recent(8).len(),
            1,
            "볼 곳이 있는데 질의 기록을 남기지 않았습니다"
        );
    }

    #[test]
    /** @brief 설정을 바꿔도 누적 통계가 살아남는지. */
    fn reconfigure_preserves_accumulated_metrics() {
        let (recorder, stats) = channel(8, 8, 60, RecorderOpts::default(), PersistOpts::default());
        let name = Name::from_str("keep.example").unwrap();
        for _ in 0..3 {
            recorder.record(
                Transport::Do53Udp,
                Action::Resolved,
                "127.0.0.1".parse().unwrap(),
                Some(&name),
                Some(RecordType::A),
                true,
                true,
            );
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        while stats.recent(8).len() < 3 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(recorder.metrics().snapshot().total, 3);
        assert_eq!(stats.recent(8).len(), 3);

        recorder.reconfigure(false, true, vec!["x".into()], 16, 120, 600);

        assert_eq!(
            recorder.metrics().snapshot().total,
            3,
            "reconfigure 후 누적 통계 보존"
        );
        assert_eq!(stats.recent(8).len(), 3, "reconfigure 후 질의 로그 보존");
    }

    #[test]
    /** @brief 기록 용량을 줄이면 즉시 반영되는지. */
    fn reconfigure_trims_recent_log_immediately() {
        let (recorder, stats) = channel(8, 8, 0, RecorderOpts::default(), PersistOpts::default());
        {
            let mut recent = stats.recent.lock_recover();
            for index in 0..5u64 {
                recent.push_back(QueryEvent {
                    id: index + 1,
                    ts_ms: now_ms(),
                    client: "127.0.0.1".parse().expect("테스트용 주소"),
                    name: Some(
                        Name::from_str(&format!("{index}.example.")).expect("테스트용 이름"),
                    ),
                    qtype: "A".into(),
                    transport: "do53-udp",
                    action: "resolved",
                    rcode: "NOERROR".into(),
                    reason: String::new(),
                    stage: String::new(),
                    detail: String::new(),
                    answers: String::new(),
                    upstream: String::new(),
                    rule: String::new(),
                    list: String::new(),
                    latency_us: 0,
                    log: true,
                    stat: false,
                });
            }
        }
        recorder.reconfigure(true, false, Vec::new(), 2, 0, 0);
        let recent = stats.recent(8);
        assert_eq!(recent.len(), 2);
        assert_eq!(
            recent[0].name.as_ref().map(Name::to_string),
            Some("4.example.".to_string())
        );
        assert_eq!(
            recent[1].name.as_ref().map(Name::to_string),
            Some("3.example.".to_string())
        );
    }

    #[test]
    /** @brief 저장 경로를 계속 바꿔도 실패 경고 상태가 저장 종류 수보다 커지지 않는지. */
    fn persistence_warning_state_is_bounded_by_active_kinds() {
        let mut warnings = PersistWarnings::default();
        let now = Instant::now();
        for index in 0..64 {
            let path = PathBuf::from(format!("unwritable-{index}.json"));
            assert!(warnings.should_log(PersistKind::Stats, &path, "denied", now));
        }
        assert_eq!(
            warnings.retained_slots(),
            1,
            "과거 저장 경로가 프로세스 수명 동안 계속 쌓이면 안 됩니다"
        );

        let path = Path::new("unwritable-63.json");
        assert!(!warnings.should_log(PersistKind::Stats, path, "denied", now));
        assert!(warnings.should_log(PersistKind::Stats, path, "read-only", now));
        assert!(!warnings.should_log(
            PersistKind::Stats,
            path,
            "read-only",
            now + Duration::from_secs(59)
        ));
        assert!(warnings.should_log(
            PersistKind::Stats,
            path,
            "read-only",
            now + Duration::from_secs(60)
        ));

        assert!(warnings.should_log(
            PersistKind::Querylog,
            Path::new("queries.jsonl"),
            "denied",
            now
        ));
        assert_eq!(warnings.retained_slots(), 2);
        warnings.clear(PersistKind::Stats);
        assert_eq!(warnings.retained_slots(), 1);
        warnings.clear(PersistKind::Querylog);
        assert_eq!(warnings.retained_slots(), 0);
    }

    #[test]
    /** @brief 저장 경로가 바뀌어도 통계가 초기화되지 않는지. */
    fn persistence_paths_can_change_without_resetting_stats() {
        let suffix = format!("{}-{}", std::process::id(), now_ms());
        let querylog =
            std::env::temp_dir().join(format!("onetdns-metrics-reconfigure-{suffix}.jsonl"));
        let stats_file =
            std::env::temp_dir().join(format!("onetdns-stats-reconfigure-{suffix}.json"));
        let (recorder, stats) = channel(8, 8, 60, RecorderOpts::default(), PersistOpts::default());
        let name = Name::from_str("persist-switch.example").unwrap();
        recorder.record(
            Transport::Do53Udp,
            Action::Resolved,
            "127.0.0.1".parse().unwrap(),
            Some(&name),
            Some(RecordType::A),
            true,
            true,
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while stats.recent(1).is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }

        stats
            .reconfigure_persist(PersistOpts {
                querylog_file: Some(querylog.clone()),
                stats_file: Some(stats_file.clone()),
                flush_secs: 30,
            })
            .unwrap();

        assert_eq!(recorder.metrics().snapshot().total, 1);
        assert!(std::fs::read_to_string(&querylog)
            .unwrap()
            .contains("persist-switch.example."));
        assert!(std::fs::read_to_string(&stats_file)
            .unwrap()
            .contains("\"total\":\"1\""));
        drop(stats);
        drop(recorder);
        let _ = std::fs::remove_file(querylog);
        let _ = std::fs::remove_file(stats_file);
    }

    #[test]
    /** @brief 보존을 끄기 전에 마지막 상태를 저장하는지. */
    fn disabling_persistence_flushes_the_previous_files() {
        let suffix = format!("{}-{}", std::process::id(), now_ms());
        let querylog =
            std::env::temp_dir().join(format!("onetdns-metrics-disable-persist-{suffix}.jsonl"));
        let stats_file =
            std::env::temp_dir().join(format!("onetdns-stats-disable-persist-{suffix}.json"));
        let (recorder, stats) = channel(
            8,
            8,
            60,
            RecorderOpts::default(),
            PersistOpts {
                querylog_file: Some(querylog.clone()),
                stats_file: Some(stats_file.clone()),
                flush_secs: 3_600,
            },
        );
        let name = Name::from_str("persist-disable.example").unwrap();
        recorder.record(
            Transport::Do53Udp,
            Action::Resolved,
            "127.0.0.1".parse().unwrap(),
            Some(&name),
            Some(RecordType::A),
            true,
            true,
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while stats.recent(1).is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }

        stats.reconfigure_persist(PersistOpts::default()).unwrap();

        assert!(std::fs::read_to_string(&querylog)
            .unwrap()
            .contains("persist-disable.example."));
        assert!(std::fs::read_to_string(&stats_file)
            .unwrap()
            .contains("\"total\":\"1\""));
        drop(stats);
        drop(recorder);
        let _ = std::fs::remove_file(querylog);
        let _ = std::fs::remove_file(stats_file);
    }

    #[test]
    /** @brief 디스크 삭제가 실패하면 메모리도 지우지 않는지. 한쪽만 지우면 재시작 때 되살아난다. */
    fn clear_recent_keeps_memory_when_persistent_clear_fails() {
        let suffix = format!("{}-{}", std::process::id(), now_ms());
        let querylog =
            std::env::temp_dir().join(format!("onetdns-querylog-clear-failure-{suffix}.jsonl"));
        let (recorder, stats) = channel(
            8,
            8,
            60,
            RecorderOpts::default(),
            PersistOpts {
                querylog_file: Some(querylog.clone()),
                stats_file: None,
                flush_secs: 3_600,
            },
        );
        let name = Name::from_str("clear-failure.example").unwrap();
        recorder.record(
            Transport::Do53Udp,
            Action::Resolved,
            "127.0.0.1".parse().unwrap(),
            Some(&name),
            Some(RecordType::A),
            true,
            true,
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while stats.recent(1).is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(stats.recent(8).len(), 1);

        let _ = std::fs::remove_file(&querylog);
        std::fs::create_dir(&querylog).unwrap();
        assert!(stats.clear_recent().is_err());
        assert_eq!(
            stats.recent(8).len(),
            1,
            "영속 파일을 비우지 못하면 메모리 기록도 유지해야 합니다"
        );

        drop(stats);
        drop(recorder);
        let _ = std::fs::remove_dir(querylog);
    }

    #[test]
    /** @brief 익명화가 host 부분만 가리고 대역은 남기는지. */
    fn anonymize_masks_host() {
        assert_eq!(
            anonymize_ip("203.0.113.45".parse().unwrap()).to_string(),
            "203.0.113.0"
        );
        assert_eq!(
            anonymize_ip("2001:db8:1:2:3:4:5:6".parse().unwrap()).to_string(),
            "2001:db8:1:2::"
        );
    }

    #[test]
    /**
     * @brief 상한에 닿으면 가장 적은 항목이 밀려나는지.
     *
     * @details 상한에 닿은 뒤로는 빗나간 질의 몇 번에 한 번만 들인다. 자주 오는 이름은
     *          여러 번 빗나가므로 곧 들어오고, 한 번만 오는 이름은 맵을 흔들지 않는다.
     */
    fn bump_evicts_least_count_when_full() {
        let mut map = std::collections::HashMap::new();
        for i in 0..TOP_CAP {
            map.insert(format!("k{i}"), 5);
        }

        map.insert("k0".to_string(), 1);
        assert_eq!(map.len(), TOP_CAP);

        let mut heap = CounterHeap::new();
        let mut misses = 0u64;
        let newcomer = "newcomer".to_string();
        for _ in 0..ADMIT_EVERY_MISSES {
            bump(&mut map, &mut heap, &mut misses, &newcomer);
        }
        assert_eq!(map.len(), TOP_CAP, "상한을 넘어 자라면 안 됩니다");
        assert!(map.contains_key("newcomer"));
        assert_eq!(map.get("newcomer"), Some(&2));
        assert!(!map.contains_key("k0"));
    }

    #[test]
    /**
     * @brief 한 번만 오는 이름이 맵을 교체하지 않는지.
     *
     * @details 리졸버가 보는 이름 종류는 거의 언제나 상한보다 많다. 빗나갈 때마다 맵에서
     *          빼고 넣고 힙을 정리하면 그 값을 질의마다 내게 되고, 상위 목록은 서로를
     *          밀어내기만 해 뜻도 없어진다.
     */
    fn one_off_names_do_not_churn_the_map() {
        let mut map = std::collections::HashMap::new();
        for i in 0..TOP_CAP {
            map.insert(format!("k{i}"), 5);
        }
        let mut heap = CounterHeap::new();
        let mut misses = 0u64;

        let rounds = ADMIT_EVERY_MISSES as usize * 8;
        for i in 0..rounds {
            bump(&mut map, &mut heap, &mut misses, &format!("once-{i}"));
        }

        let admitted = (0..rounds)
            .filter(|i| map.contains_key(&format!("once-{i}")))
            .count();
        assert_eq!(map.len(), TOP_CAP);
        assert_eq!(
            admitted, 8,
            "한 번만 온 이름이 {admitted}개나 들어왔습니다. 문이 좁혀지지 않았습니다"
        );
    }

    #[test]
    /**
     * @brief 질의 기록이 꺼져 있어도 통계 집계가 온전한지.
     *
     * @details 기록에만 담기는 항목은 꺼진 상태에서 만들지 않는다. 그 최적화가 통계까지
     *          비우면 상위 목록이 빈다. 켠 상태에서는 항목이 실제로 실려야 한다.
     */
    fn querylog_off_still_counts_stats_and_on_carries_detail() {
        let name = Name::from_str("gated.example.").unwrap();
        let shot = |querylog: bool| {
            let (recorder, stats) = channel(
                64,
                100,
                0,
                RecorderOpts {
                    querylog,
                    ..RecorderOpts::default()
                },
                PersistOpts::default(),
            );
            recorder.record(
                Transport::Do53Udp,
                Action::Resolved,
                "127.0.0.1".parse().unwrap(),
                Some(&name),
                Some(RecordType::A),
                true,
                true,
            );
            let deadline = Instant::now() + Duration::from_secs(2);
            while recorder.metrics().snapshot().total == 0 && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            let mut top = stats.top(4);
            let mut seen = stats.recent(4);
            for _ in 0..100 {
                if !top.domains.is_empty() && (!querylog || !seen.is_empty()) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
                top = stats.top(4);
                seen = stats.recent(4);
            }
            (top, seen)
        };

        let (top_off, seen_off) = shot(false);
        assert!(
            top_off.domains.iter().any(|(d, _)| d == "gated.example."),
            "기록을 꺼도 상위 이름 집계는 남아야 합니다"
        );
        assert!(
            seen_off.is_empty(),
            "기록이 꺼졌으면 질의 로그는 비어야 합니다"
        );

        let (top_on, seen_on) = shot(true);
        assert!(
            top_on.domains.iter().any(|(d, _)| d == "gated.example."),
            "기록을 켜도 집계는 그대로여야 합니다"
        );
        assert_eq!(seen_on.len(), 1, "기록이 켜졌으면 항목이 남아야 합니다");
        assert_eq!(seen_on[0].rcode, "NOERROR", "응답 코드가 실려야 합니다");
        assert_eq!(seen_on[0].qtype, "A", "질의 종류가 실려야 합니다");
    }

    #[test]
    /** @brief 상한에 못 미치면 힙을 아예 건드리지 않는지. 축출이 없으므로 유지가 낭비다. */
    fn bump_leaves_heap_untouched_below_capacity() {
        let mut map = std::collections::HashMap::new();
        let mut heap = CounterHeap::new();
        let mut misses = 0u64;
        for i in 0..64 {
            for _ in 0..3 {
                bump(&mut map, &mut heap, &mut misses, &format!("name-{i}"));
            }
        }
        assert_eq!(map.len(), 64);
        assert_eq!(map.get("name-0"), Some(&3), "횟수는 그대로 세어야 합니다");
        assert!(heap.is_empty(), "상한 아래에서는 힙을 만들지 않아야 합니다");
    }

    #[test]
    /** @brief 실제 축출이 허용되기 전에는 상한에 닿아도 힙을 만들지 않는지. */
    fn bump_builds_heap_only_when_eviction_is_admitted() {
        let mut map = std::collections::HashMap::new();
        let mut heap = CounterHeap::new();
        let mut misses = 0u64;
        for i in 0..TOP_CAP {
            bump(&mut map, &mut heap, &mut misses, &format!("k{i}"));
        }
        assert_eq!(map.len(), TOP_CAP);
        assert!(
            heap.is_empty(),
            "축출할 새 이름이 없는데 힙을 미리 만들면 안 됩니다"
        );
        assert_eq!(heap.capacity(), 0, "빈 힙 버퍼도 미리 잡지 않아야 합니다");

        bump(&mut map, &mut heap, &mut misses, &"k0".to_string());
        assert!(heap.is_empty(), "기존 이름 hit도 힙이 필요하지 않습니다");

        for _ in 1..ADMIT_EVERY_MISSES {
            bump(&mut map, &mut heap, &mut misses, &"newcomer".to_string());
        }
        assert!(
            heap.is_empty(),
            "아직 허용되지 않은 miss가 힙을 만들면 안 됩니다"
        );
        assert_eq!(
            heap.capacity(),
            0,
            "거부된 miss도 힙 버퍼를 잡지 않아야 합니다"
        );
        bump(&mut map, &mut heap, &mut misses, &"newcomer".to_string());
        assert_eq!(map.len(), TOP_CAP, "상한을 넘기지 않아야 합니다");
        assert!(map.contains_key("newcomer"), "새 이름이 들어가야 합니다");
        assert_eq!(heap.len(), TOP_CAP, "첫 축출 때 힙이 완성되어야 합니다");
    }

    #[test]
    /**
     * @brief 힙이 낡은 항목으로만 차 있어도 새 이름이 버려지지 않는지.
     *
     * @details 올릴 때 힙을 갱신하지 않으므로 상한에 닿은 뒤 계수를 올리면 힙 항목이
     *          전부 낡는다. 축출이 그 상태에서 힙을 다시 만들지 않으면 새 이름이
     *          조용히 사라진다.
     */
    fn bump_admits_newcomer_even_when_heap_is_entirely_stale() {
        let mut map = std::collections::HashMap::new();
        let mut heap = CounterHeap::new();
        let mut misses = 0u64;
        for i in 0..TOP_CAP {
            bump(&mut map, &mut heap, &mut misses, &format!("k{i}"));
        }
        let first = "first-newcomer".to_string();
        for _ in 0..ADMIT_EVERY_MISSES {
            bump(&mut map, &mut heap, &mut misses, &first);
        }
        assert_eq!(heap.len(), TOP_CAP, "첫 축출이 힙을 만들어야 합니다");

        assert_eq!(map.len(), TOP_CAP);
        /* 첫 축출 뒤 실제로 남은 키를 전부 한 번씩 올려 힙의 계수를 모두 낡게 만든다. */
        let keys: Vec<_> = map.keys().cloned().collect();
        for key in keys {
            bump(&mut map, &mut heap, &mut misses, &key);
        }

        let newcomer = "second-newcomer".to_string();
        for _ in 0..ADMIT_EVERY_MISSES {
            bump(&mut map, &mut heap, &mut misses, &newcomer);
        }
        assert!(
            map.contains_key(&newcomer),
            "낡은 힙에서도 새 이름이 들어가야 합니다"
        );
        assert_eq!(map.len(), TOP_CAP, "상한을 넘기지 않아야 합니다");
    }

    #[test]
    /** @brief 이름 종류가 극단적으로 많아도 메모리가 상한 안에 머무는지. */
    fn bump_heap_remains_bounded_under_high_cardinality() {
        let mut map = std::collections::HashMap::new();
        let mut heap = CounterHeap::new();
        let mut misses = 0u64;
        for i in 0..TOP_CAP * 5 {
            bump(&mut map, &mut heap, &mut misses, &format!("unique-{i}"));
        }
        for _ in 0..TOP_CAP * 3 {
            bump(&mut map, &mut heap, &mut misses, &"hot".to_string());
        }
        assert_eq!(map.len(), TOP_CAP);
        assert!(heap.len() <= TOP_CAP * 2);
        assert!(map.contains_key("hot"));
    }

    #[test]
    /** @brief 제외 목록이 라벨 경계에서만 걸리는지. */
    fn ignored_domain_suffix_match() {
        let matches = |name: &str, d: &str| {
            let name = Name::from_str(name).unwrap();
            let mut buf = [0u8; MAX_IGNORE_NAME];
            let normalized = normalize_into(&name, &mut buf);
            normalize_ignored(vec![d.to_string()])
                .iter()
                .any(|entry| suffix_matches(&normalized, entry))
        };
        assert!(matches("a.b.tracking.test.", "tracking.test"));
        assert!(matches("tracking.test", "tracking.test"));
        assert!(!matches("nottracking.test", "tracking.test"));
        assert!(
            matches("A.B.Tracking.TEST", " Tracking.Test. "),
            "목록 항목의 대소문자·끝점·여백은 미리 정규화되어 판정을 바꾸지 않아야 합니다"
        );
    }

    #[test]
    /** @brief 이름 정규화가 질의마다 할당하지 않는지. */
    fn ignored_name_normalization_does_not_allocate() {
        let mut buf = [0u8; MAX_IGNORE_NAME];
        let name = Name::from_str("a.b.tracking.test").unwrap();
        let normalized = normalize_into(&name, &mut buf);
        assert_eq!(normalized, "a.b.tracking.test");
        assert!(
            matches!(normalized, Cow::Borrowed(_)),
            "정규화 결과는 스택 버퍼를 빌려야 합니다"
        );

        let longest = Name::from_labels(vec![
            vec![b'a'; 63],
            vec![b'b'; 63],
            vec![b'c'; 63],
            vec![b'd'; 61],
        ])
        .expect("길이 상한에 닿는 이름");
        let mut buf = [0u8; MAX_IGNORE_NAME];
        assert!(
            matches!(normalize_into(&longest, &mut buf), Cow::Borrowed(_)),
            "이름 길이 상한에서도 버퍼가 모자라면 안 됩니다"
        );
    }

    #[test]
    /** @brief 대소문자만 다른 같은 이름이 상위 목록에서 갈라지지 않는지. */
    fn top_domains_fold_case_variants_into_one_entry() {
        let (recorder, stats) =
            channel(64, 100, 0, RecorderOpts::default(), PersistOpts::default());
        for label in ["example.test", "EXAMPLE.test", "Example.Test"] {
            let name = Name::from_str(label).unwrap();
            recorder.record(
                Transport::Do53Udp,
                Action::Resolved,
                "127.0.0.1".parse().unwrap(),
                Some(&name),
                Some(RecordType::A),
                false,
                true,
            );
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut top = stats.top(8);
        while top.domains.iter().map(|(_, count)| count).sum::<u64>() < 3
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(5));
            top = stats.top(8);
        }
        assert_eq!(
            top.domains,
            vec![("example.test.".to_string(), 3)],
            "대소문자만 다른 이름은 한 항목으로 모여야 합니다"
        );
    }

    #[test]
    /** @brief 차단 처분이 차단 상위 목록에 실제로 쌓이는지. */
    fn blocked_action_reaches_the_blocked_top_list() {
        let (recorder, stats) =
            channel(64, 100, 0, RecorderOpts::default(), PersistOpts::default());
        let blocked = Name::from_str("ads.example").unwrap();
        let allowed = Name::from_str("ok.example").unwrap();
        for (name, action) in [(&blocked, Action::Blocked), (&allowed, Action::Resolved)] {
            recorder.record(
                Transport::Do53Udp,
                action,
                "127.0.0.1".parse().unwrap(),
                Some(name),
                Some(RecordType::A),
                false,
                true,
            );
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut top = stats.top(8);
        while top.domains.len() < 2 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
            top = stats.top(8);
        }
        assert_eq!(
            top.blocked,
            vec![("ads.example.".to_string(), 1)],
            "차단된 이름만 차단 목록에 들어가야 합니다"
        );
        assert_eq!(top.domains.len(), 2, "전체 목록에는 둘 다 들어가야 합니다");
    }

    #[test]
    /** @brief 제외 목록이 비었으면 잠금조차 잡지 않는지. */
    fn ignored_active_flag_gates_stat_counting() {
        let (rec, _stats) = channel(16, 100, 0, RecorderOpts::default(), PersistOpts::default());
        let total = || rec.metrics().snapshot().total;
        let ignored = Name::from_str("ignored.test").unwrap();
        let other = Name::from_str("other.test").unwrap();
        let record = |name: &Name| {
            rec.record(
                Transport::Do53Udp,
                Action::Resolved,
                "1.2.3.4".parse().unwrap(),
                Some(name),
                Some(RecordType::A),
                true,
                true,
            );
        };

        record(&ignored);
        assert_eq!(total(), 1);

        rec.reconfigure(true, false, vec!["ignored.test".to_string()], 100, 0, 0);
        record(&ignored);
        assert_eq!(total(), 1, "무시 도메인은 카운트되지 않음");

        record(&other);
        assert_eq!(total(), 2, "무시목록 밖 도메인은 카운트");
    }

    #[test]
    /** @brief 타이머가 시간을 재고 중첩에서 이전 값을 되돌리는지. */
    fn request_timer_measures_and_restores() {
        assert_eq!(current_request_latency_us(), 0, "타이머 없으면 0");
        {
            let timer = RequestTimer::start();
            std::thread::sleep(Duration::from_millis(2));
            assert!(timer.elapsed_us() >= 1_000, "경과시간 측정");
            assert!(current_request_latency_us() >= 1_000, "기록 경로가 읽는 값");
        }
        assert_eq!(current_request_latency_us(), 0, "드롭 후 이전 값으로 복원");
    }

    #[test]
    /** @brief 구간 지연이 누적 총합이 아니라 차분으로 나오는지. 총합을 쓰면 재시작 직후 값이 튄다. */
    fn rolling_latency_uses_window_delta_not_persisted_total() {
        let mut history = MetricHistory::default();
        history.reset_baseline(
            MetricBucket {
                latency_sum_us: 9_000_000,
                latency_count: 100,
                cache_hits: 80,
                cache_lookups: 100,
                ..MetricBucket::default()
            },
            1_000,
        );
        history.sample(
            MetricBucket {
                latency_sum_us: 9_120_000,
                latency_count: 104,
                cache_hits: 83,
                cache_lookups: 104,
                ..MetricBucket::default()
            },
            1_001,
        );
        let recent = history.aggregate_recent(1_001, 60);
        assert_eq!(recent.latency_sum_us, 120_000);
        assert_eq!(recent.latency_count, 4);
        assert_eq!(recent.cache_hits, 3);
        assert_eq!(recent.cache_lookups, 4);
        let average_ms = recent.latency_sum_us as f64 / recent.latency_count as f64 / 1_000.0;
        assert_eq!(average_ms, 30.0);
    }

    #[test]
    /** @brief 긴 구간을 요청해도 점이 그 구간을 덮는지. */
    fn history_points_keep_requested_long_range() {
        let mut history = MetricHistory::default();
        history.reset_baseline(MetricBucket::default(), 10_000);
        history.sample(
            MetricBucket {
                queries: 120,
                blocked: 30,
                latency_sum_us: 600_000,
                latency_count: 20,
                ..MetricBucket::default()
            },
            10_060,
        );
        let points = history.points(10_060, 3_600, 59);
        assert_eq!(points.len(), 59);
        assert_eq!(
            points.iter().map(|point| point.queries).sum::<u64>(),
            120,
            "구간을 나눠도 질의 수의 합은 보존되어야 합니다"
        );
        assert!(points.iter().any(|point| point.avg_latency_ms == 30.0));
    }

    #[test]
    /** @brief 바뀐 용량이 읽기 핸들에도 반영되는지. */
    fn stats_shares_reconfigured_log_capacity() {
        let (rec, stats) = channel(8, 32, 0, RecorderOpts::default(), PersistOpts::default());
        assert_eq!(stats.log_cap.load(Ordering::Acquire), 32);

        rec.reconfigure(true, false, Vec::new(), 512, 0, 0);
        assert_eq!(stats.log_cap.load(Ordering::Acquire), 512);
    }

    #[test]
    /** @brief 구독자가 이후 이벤트를 받는지. */
    fn subscribe_receives_broadcast_events() {
        let (rec, stats) = channel(16, 100, 0, RecorderOpts::default(), PersistOpts::default());
        let rx = stats.subscribe();

        rec.record(
            Transport::Do53Udp,
            Action::Blocked,
            "203.0.113.5".parse().unwrap(),
            Some(&Name::from_str("ads.example.com").unwrap()),
            Some(RecordType::A),
            true,
            true,
        );
        let ev = rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("이벤트 수신");
        assert!(ev
            .name
            .as_ref()
            .map(Name::to_string)
            .is_some_and(|n| n.starts_with("ads.example.com")));
        assert_eq!(ev.action, "blocked");
        assert_eq!(ev.client.to_string(), "203.0.113.5");
    }

    #[test]
    /** @brief 놓친 것만 재생하고 이미 받은 것을 다시 주지 않는지. */
    fn subscribe_after_replays_only_missing_events() {
        let (rec, stats) = channel(32, 100, 0, RecorderOpts::default(), PersistOpts::default());
        for name in ["one.example", "two.example", "three.example"] {
            rec.record(
                Transport::Do53Udp,
                Action::Resolved,
                "192.0.2.10".parse().unwrap(),
                Some(&Name::from_str(name).unwrap()),
                Some(RecordType::A),
                true,
                true,
            );
        }
        for _ in 0..100 {
            if stats.recent(10).len() == 3 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let ordered = {
            let recent = stats.recent.lock_recover();
            recent.iter().cloned().collect::<Vec<_>>()
        };
        assert_eq!(ordered.len(), 3);
        let subscription = stats.subscribe_after(Some(ordered[0].id));
        assert!(!subscription.replay_gap);
        assert_eq!(subscription.replay.len(), 2);
        assert_eq!(subscription.replay[0].id, ordered[1].id);
        assert_eq!(subscription.replay[1].id, ordered[2].id);
    }

    #[test]
    /** @brief 기록하지 않는 이벤트가 번호에 구멍을 내지 않는지. 구멍이 나면 구독자가 놓친 줄 안다. */
    fn non_log_events_do_not_gap_log_ids() {
        let (rec, stats) = channel(32, 100, 0, RecorderOpts::default(), PersistOpts::default());
        rec.record(
            Transport::Do53Udp,
            Action::Resolved,
            "192.0.2.1".parse().unwrap(),
            Some(&Name::from_str("a.example").unwrap()),
            Some(RecordType::A),
            true,
            true,
        );

        rec.record(
            Transport::Do53Udp,
            Action::Resolved,
            "192.0.2.2".parse().unwrap(),
            Some(&Name::from_str("stat-only.example").unwrap()),
            Some(RecordType::A),
            false,
            true,
        );
        rec.record(
            Transport::Do53Udp,
            Action::Resolved,
            "192.0.2.3".parse().unwrap(),
            Some(&Name::from_str("b.example").unwrap()),
            Some(RecordType::A),
            true,
            true,
        );
        for _ in 0..100 {
            if stats.recent(10).len() == 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let ordered = {
            let recent = stats.recent.lock_recover();
            recent.iter().cloned().collect::<Vec<_>>()
        };
        assert_eq!(ordered.len(), 2, "로그 이벤트만 recent에 로드되어야");
        assert_eq!(
            ordered[1].id,
            ordered[0].id + 1,
            "로그 ID는 연속이어야: 비로그/드롭 이벤트가 틈을 만들면 안 됨"
        );
        let subscription = stats.subscribe_after(Some(ordered[0].id));
        assert!(
            !subscription.replay_gap,
            "연속 ID이므로 replay_gap이 없어야"
        );
        assert_eq!(subscription.replay.len(), 1);
    }

    #[test]
    /** @brief 보존 기간이 지나 재생할 수 없으면 그 사실을 알리는지. */
    fn subscribe_after_reports_retention_gap() {
        let (rec, stats) = channel(32, 2, 0, RecorderOpts::default(), PersistOpts::default());
        for _ in 0..4 {
            rec.record(
                Transport::Do53Udp,
                Action::Resolved,
                "192.0.2.11".parse().unwrap(),
                None,
                None,
                true,
                true,
            );
        }
        for _ in 0..100 {
            if stats.recent(10).len() == 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let subscription = stats.subscribe_after(Some(0));

        assert!(!subscription.replay_gap);
        assert_eq!(subscription.replay.len(), 2);
        let subscription = stats.subscribe_after(Some(1));
        assert!(subscription.replay_gap);
    }

    #[test]
    /** @brief 번호가 끊긴 경우를 알리는지. */
    fn subscribe_after_reports_internal_id_gap() {
        let (_rec, stats) = channel(8, 8, 0, RecorderOpts::default(), PersistOpts::default());
        {
            let mut recent = stats.recent.lock_recover();
            recent.push_back(QueryEvent {
                id: 10,
                ts_ms: now_ms(),
                client: "192.0.2.1".parse().expect("테스트용 주소"),
                name: Some(Name::from_str("one.example.").expect("테스트용 이름")),
                qtype: "A".into(),
                transport: "do53-udp",
                action: "resolved",
                rcode: "NOERROR".into(),
                reason: String::new(),
                stage: String::new(),
                detail: String::new(),
                answers: String::new(),
                upstream: String::new(),
                rule: String::new(),
                list: String::new(),
                latency_us: 0,
                log: true,
                stat: true,
            });
            recent.push_back(QueryEvent {
                id: 12,
                ts_ms: now_ms(),
                client: "192.0.2.1".parse().expect("테스트용 주소"),
                name: Some(Name::from_str("three.example.").expect("테스트용 이름")),
                qtype: "A".into(),
                transport: "do53-udp",
                action: "resolved",
                rcode: "NOERROR".into(),
                reason: String::new(),
                stage: String::new(),
                detail: String::new(),
                answers: String::new(),
                upstream: String::new(),
                rule: String::new(),
                list: String::new(),
                latency_us: 0,
                log: true,
                stat: true,
            });
        }
        let subscription = stats.subscribe_after(Some(10));
        assert!(subscription.replay_gap);
        assert_eq!(subscription.replay.len(), 1);
        assert_eq!(subscription.replay[0].id, 12);
    }

    #[test]
    /** @brief 재시작으로 기록이 비었을 때도 끊김을 알리는지. */
    fn subscribe_after_reports_restart_gap_when_recent_is_empty() {
        let (_rec, stats) = channel(8, 8, 0, RecorderOpts::default(), PersistOpts::default());
        let subscription = stats.subscribe_after(Some(42));
        assert!(subscription.replay_gap);
        assert!(subscription.replay.is_empty());
    }

    #[test]
    /** @brief 느린 구독자를 끊는지. 붙잡고 있으면 수집 전체가 밀린다. */
    fn slow_subscriber_is_disconnected_on_queue_overflow() {
        let (rec, stats) = channel(1024, 64, 0, RecorderOpts::default(), PersistOpts::default());
        let _rx = stats.subscribe();
        for _ in 0..300 {
            rec.record(
                Transport::Do53Udp,
                Action::Resolved,
                "198.51.100.4".parse().unwrap(),
                None,
                None,
                true,
                true,
            );
        }
        for _ in 0..100 {
            if stats.subscribers.lock_recover().is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(stats.subscribers.lock_recover().is_empty());
        assert!(
            stats
                .metrics
                .dropped_stream_events
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0
        );
    }

    #[test]
    /** @brief 사라진 구독자가 목록에서 정리되는지. */
    fn dropped_subscriber_is_pruned() {
        let (rec, stats) = channel(16, 100, 0, RecorderOpts::default(), PersistOpts::default());
        let rx = stats.subscribe();
        drop(rx);

        for _ in 0..3 {
            rec.record(
                Transport::Do53Udp,
                Action::Resolved,
                "1.2.3.4".parse().unwrap(),
                None,
                None,
                true,
                true,
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(
            stats.subscribers.lock_recover().is_empty(),
            "끊긴 구독자 정리됨"
        );
    }
}
