//! Metric collection and live delivery. The data path puts detailed log events in a bounded channel
//! and stats-only events in bounded per-worker slots, then returns at once; on overflow only
//! top-list attribution is lost. A collector thread drains them into the top lists and subscribers,
//! while cumulative counts stay exact under the slot locks.
//!
//! This path must never block query handling: waiting on a full channel turns metric collection
//! into an outage.

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

    static REQUEST_START: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
}

/// 0 without a running timer.
fn current_request_latency_us() -> u64 {
    REQUEST_START
        .with(|c| c.get())
        .map(|start| start.elapsed().as_micros().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

/// Scope guard timing a request: sets the thread-local start and restores the previous value on
/// drop, so nested requests keep the outer start.
pub struct RequestTimer {
    prev: Option<Instant>,
}

impl RequestTimer {
    pub fn start() -> Self {
        Self::start_at(Instant::now())
    }

    /// For passing the exact time the request arrived.
    pub fn start_at(start: Instant) -> Self {
        let prev = REQUEST_START.with(|c| c.replace(Some(start)));
        RequestTimer { prev }
    }

    pub fn elapsed_us(&self) -> u64 {
        current_request_latency_us()
    }
}

impl Drop for RequestTimer {
    fn drop(&mut self) {
        REQUEST_START.with(|c| c.set(self.prev));
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Action {
    Resolved,
    Blocked,
    Rewritten,
    Denied,
    Throttled,
    ServFail,
    Refused,
}

impl Action {
    /// Every query ends in exactly one of these, so the total equals their sum; leaving one out of
    /// the export leaves an unexplained residue in collectors.
    pub const ALL: [Action; 7] = [
        Action::Resolved,
        Action::Blocked,
        Action::Rewritten,
        Action::Denied,
        Action::Throttled,
        Action::ServFail,
        Action::Refused,
    ];

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
/// Totals for one interval, the unit of history.
pub(crate) struct MetricBucket {
    /// End of the interval.
    pub(crate) ts_sec: u64,
    /// Seconds covered; per-second values divide by it.
    pub(crate) span_secs: u64,
    pub(crate) queries: u64,
    pub(crate) blocked: u64,
    pub(crate) latency_sum_us: u64,
    pub(crate) latency_count: u64,
    pub(crate) cache_hits: u64,
    pub(crate) cache_lookups: u64,
}

impl MetricBucket {
    /// Saturates instead of overflowing.
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
/// Second and minute resolutions are kept apart; storing a long range at one-second resolution
/// would grow memory with the range.
struct MetricHistory {
    /// Recent intervals, one per second.
    seconds: VecDeque<MetricBucket>,
    /// Older intervals, one per minute.
    minutes: VecDeque<MetricBucket>,
    /// Totals at the previous sample; deltas are taken from it.
    previous: MetricBucket,
    previous_sample_sec: u64,
    retention_secs: u64,
}

impl MetricHistory {
    /// Call right after loading saved stats; otherwise the first sample after a restart reads the
    /// whole total as that moment's increase.
    fn reset_baseline(&mut self, counters: MetricBucket, now_sec: u64) {
        self.previous = counters;
        self.previous_sample_sec = now_sec;
        self.seconds.clear();
        self.minutes.clear();
    }

    /// The delta from the previous totals is this interval's value.
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
        self.trim(now_sec);
    }

    /// Adds another process's intervals to the ones here, matching them by end time.
    fn merge(&mut self, seconds: Vec<MetricBucket>, minutes: Vec<MetricBucket>, now_sec: u64) {
        merge_buckets(&mut self.seconds, seconds);
        merge_buckets(&mut self.minutes, minutes);
        self.trim(now_sec);
    }

    fn trim(&mut self, now_sec: u64) {
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
    fn aggregate_recent(&self, now_sec: u64, seconds: u64) -> MetricBucket {
        let cutoff = now_sec.saturating_sub(seconds);
        let mut out = MetricBucket::default();
        for bucket in self.seconds.iter().filter(|bucket| bucket.ts_sec >= cutoff) {
            out.add(*bucket);
        }
        out
    }

    /// Splits the requested range into `point_count` bins for dashboard graphs and returns the
    /// bin width in seconds with the points, oldest first.
    fn points(&self, now_sec: u64, range_secs: u64, point_count: usize) -> (u64, Vec<MetricPoint>) {
        let point_count = point_count.clamp(2, 240);
        let range_secs = range_secs.clamp(60, 7 * 24 * 60 * 60);
        // Rounding down keeps the oldest bin inside the retained records, and whole minutes keep
        // a minute record from straddling two bins.
        let width = (range_secs / point_count as u64).max(1);
        let width = if width >= 60 { width / 60 * 60 } else { width };
        // Bins start on multiples of the width, so a later call changes only the current bin.
        let current = now_sec / width;
        let first = current.saturating_sub(point_count as u64 - 1);
        let source = if range_secs <= 3_600 {
            &self.seconds
        } else {
            &self.minutes
        };
        let mut sums = vec![MetricBucket::default(); point_count];
        for bucket in source {
            let bin = bucket.ts_sec / width;
            if (first..=current).contains(&bin) {
                sums[(bin - first) as usize].add(*bucket);
            }
        }
        let mut out = Vec::with_capacity(point_count);
        for (index, sum) in sums.iter().enumerate() {
            let bin_end = (first + index as u64 + 1).saturating_mul(width);
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
                ts_ms: bin_end.min(now_sec).saturating_mul(1_000),
                queries: sum.queries,
                blocked: sum.blocked,
                avg_latency_ms,
                cache_hit_pct,
            });
        }
        (width, out)
    }
}

/// Both sides are ordered by end time; so is the result.
fn merge_buckets(into: &mut VecDeque<MetricBucket>, from: Vec<MetricBucket>) {
    let mut merged = VecDeque::with_capacity(into.len() + from.len());
    let mut ours = std::mem::take(into).into_iter().peekable();
    let mut theirs = from.into_iter().peekable();
    loop {
        let next = match (ours.peek(), theirs.peek()) {
            (Some(a), Some(b)) if a.ts_sec == b.ts_sec => {
                let mut bucket = ours.next().unwrap_or_default();
                bucket.add(theirs.next().unwrap_or_default());
                bucket
            }
            (Some(a), Some(b)) if a.ts_sec < b.ts_sec => ours.next().unwrap_or_default(),
            (Some(_), Some(_)) | (None, Some(_)) => theirs.next().unwrap_or_default(),
            (Some(_), None) => ours.next().unwrap_or_default(),
            (None, None) => break,
        };
        merged.push_back(next);
    }
    *into = merged;
}

#[derive(Clone, Copy, Default)]
/// Counts accumulated under a stats slot lock instead of global atomics per query.
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
/// Cumulative metrics. The detailed-log path adds to the atomics; the default stats path adds to
/// per-worker shards.
pub struct Metrics {
    pub total: AtomicU64,
    pub resolved: AtomicU64,
    pub blocked: AtomicU64,
    pub rewritten: AtomicU64,
    pub denied: AtomicU64,
    pub refused: AtomicU64,
    pub throttled: AtomicU64,
    pub servfail: AtomicU64,
    pub by_transport: [AtomicU64; Transport::COUNT],

    pub latency_sum_us: AtomicU64,
    pub latency_count: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_lookups: AtomicU64,

    /// Log events dropped because the channel was full; a rising value means collection cannot keep
    /// up.
    pub dropped_log_events: AtomicU64,
    /// Stats-only events dropped on a full slot. Cumulative counters are added to the shard before
    /// the slot limit is checked, so totals are never lost; only top-list attribution is, so a
    /// rising value means the top lists are a sample.
    pub dropped_stat_events: AtomicU64,
    pub dropped_stream_events: AtomicU64,
    pub persist_failures: AtomicU64,
    /// Written only by the sampler thread.
    history: Mutex<MetricHistory>,
    /// Shards the query-log-off hot path writes instead of a global cache line.
    stat_slots: Option<Arc<Vec<Mutex<StatSlot>>>>,
}

impl Metrics {
    fn sharded_stat_counters(&self) -> StatCounters {
        let mut total = StatCounters::default();
        if let Some(slots) = &self.stat_slots {
            for slot in slots.iter() {
                total.add(&slot.lock_recover().counters);
            }
        }
        total
    }

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

    /// Reads the totals under the history lock, so a total added while merging cannot fall between
    /// the read and the sample and show up as a spike.
    fn sample_now(&self) {
        let now_sec = now_ms() / 1_000;
        let mut history = self.history.lock_recover();
        history.sample(self.counters(), now_sec);
    }

    fn set_history_retention(&self, retention_secs: u64) {
        self.history.lock_recover().retention_secs = retention_secs;
    }

    fn reset_history_baseline(&self) {
        let now_sec = now_ms() / 1_000;
        let mut history = self.history.lock_recover();
        history.reset_baseline(self.counters(), now_sec);
    }

    /// Adds totals counted elsewhere. The history baseline moves with them, so they do not read as
    /// this moment's increase.
    pub(crate) fn add_totals(&self, saved: &crate::persist::PersistedStatsSnapshot) {
        self.add_history(saved, Vec::new(), Vec::new());
    }

    /// `add_totals`, also adding the intervals of the history they were counted in.
    fn add_history(
        &self,
        saved: &crate::persist::PersistedStatsSnapshot,
        seconds: Vec<MetricBucket>,
        minutes: Vec<MetricBucket>,
    ) {
        let mut history = self.history.lock_recover();
        for (counter, value) in [
            (&self.total, saved.total),
            (&self.resolved, saved.resolved),
            (&self.blocked, saved.blocked),
            (&self.rewritten, saved.rewritten),
            (&self.denied, saved.denied),
            (&self.refused, saved.refused),
            (&self.throttled, saved.throttled),
            (&self.servfail, saved.servfail),
            (&self.latency_sum_us, saved.latency_sum_us),
            (&self.latency_count, saved.latency_count),
            (&self.cache_hits, saved.cache_hits),
            (&self.cache_lookups, saved.cache_lookups),
            (&self.dropped_log_events, saved.dropped_log_events),
            (&self.dropped_stat_events, saved.dropped_stat_events),
            (&self.dropped_stream_events, saved.dropped_stream_events),
            (&self.persist_failures, saved.persist_failures),
        ] {
            add_saturating(counter, value);
        }
        for (counter, value) in self.by_transport.iter().zip(&saved.by_transport) {
            add_saturating(counter, *value);
        }
        history.previous.add(MetricBucket {
            queries: saved.total,
            blocked: saved.blocked,
            latency_sum_us: saved.latency_sum_us,
            latency_count: saved.latency_count,
            cache_hits: saved.cache_hits,
            cache_lookups: saved.cache_lookups,
            ..MetricBucket::default()
        });
        history.merge(seconds, minutes, now_ms() / 1_000);
    }

    /// The bin width in seconds and the points, oldest first.
    pub fn history(&self, range_secs: u64, point_count: usize) -> (u64, Vec<MetricPoint>) {
        self.sample_now();
        let now_sec = now_ms() / 1_000;
        self.history
            .lock_recover()
            .points(now_sec, range_secs, point_count)
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        self.sample_now();
        self.current_snapshot()
    }

    /// Reads the current totals without adding a history sample; persistence uses it too.
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
pub struct MetricPoint {
    pub ts_ms: u64,
    /// A total for the interval, not a rate.
    pub queries: u64,
    pub blocked: u64,
    pub avg_latency_ms: f64,
    pub cache_hit_pct: f64,
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub total: u64,
    pub resolved: u64,
    pub blocked: u64,
    pub rewritten: u64,
    pub denied: u64,
    pub refused: u64,
    pub throttled: u64,
    pub servfail: u64,
    pub by_transport: Vec<(&'static str, u64)>,
    pub avg_latency_ms: f64,
    /// Raw sum, so collectors can compute the average themselves.
    pub latency_sum_us: u64,
    pub latency_count: u64,
    pub cache_hit_pct: f64,

    pub cache_hits: u64,
    pub cache_lookups: u64,
    pub dropped_log_events: u64,
    /// Only the top lists become a sample.
    pub dropped_stat_events: u64,
    pub dropped_stream_events: u64,
    pub persist_failures: u64,
}

#[derive(Debug, Clone)]
pub struct QueryEvent {
    pub id: u64,
    pub ts_ms: u64,
    pub client: IpAddr,
    pub name: Option<Name>,
    pub qtype: String,
    pub transport: &'static str,
    pub action: &'static str,
    pub rcode: String,
    pub reason: String,
    pub stage: String,
    pub detail: String,

    pub answers: String,
    pub upstream: String,
    /// Empty when the rule belongs to no list.
    pub rule: String,
    pub list: String,

    pub latency_us: u64,

    pub log: bool,
    pub stat: bool,
}

#[derive(Debug)]
/// The minimum a top-list update needs.
struct StatEvent {
    /// Already anonymized when configured.
    client: IpAddr,
    name: Option<Name>,
    /// Selects the blocked top list.
    action: Action,
}

#[derive(Default)]
/// Per-worker shard; one lock guards its events and counters.
struct StatSlot {
    events: Vec<StatEvent>,
    /// Summed by snapshot directly; kept when the collector empties the slot.
    counters: StatCounters,
}

#[allow(clippy::large_enum_variant)]
/// A full log event, or a wake signal for the stats slots. Boxing the large variant would add an
/// allocation per logged query, so it stays inline.
enum CollectorEvent {
    Log(QueryEvent),
    /// The first event entered an empty stats slot.
    StatsReady,
    /// Counts everything still queued, then replies with the state for a successor.
    Export(mpsc::SyncSender<Vec<u8>>),
    /// Counts everything still queued, then adds a predecessor's state.
    Merge(Box<crate::persist::CarriedStats>, mpsc::SyncSender<()>),
}

impl QueryEvent {
    /// One JSON line; persistence and live delivery share the format.
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
pub struct EventDiag<'a> {
    pub rcode: &'a str,
    pub reason: &'a str,
    pub stage: &'a str,
    pub detail: &'a str,
    pub answers: &'a str,
    pub upstream: &'a str,
    pub rule: &'a str,
    pub list: &'a str,
}

/// Maps to a static string, so events do not allocate one.
pub(crate) fn intern_transport(s: &str) -> &'static str {
    Transport::ALL
        .into_iter()
        .find(|t| t.name() == s)
        .map(|t| t.name())
        .unwrap_or("do53-udp")
}

pub(crate) fn intern_action(s: &str) -> &'static str {
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
pub struct PersistOpts {
    pub querylog_file: Option<PathBuf>,

    pub stats_file: Option<PathBuf>,

    pub flush_secs: u64,
}

impl PersistOpts {
    fn enabled(&self) -> bool {
        self.querylog_file.is_some() || self.stats_file.is_some()
    }
}

#[derive(Clone)]
pub struct RecorderOpts {
    pub querylog: bool,

    pub anonymize: bool,

    pub ignored: Vec<String>,

    pub stats_retention_secs: u64,
}

impl Default for RecorderOpts {
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
/// The data path's recorder. record calls never block: on a full channel they drop the event and
/// return.
pub struct Recorder {
    metrics: Arc<Metrics>,
    /// Bounded channel for full log events and stats slot wakeups.
    log_tx: mpsc::SyncSender<CollectorEvent>,

    /// Slots collecting events used only for stats. A channel send makes a wakeup system call even
    /// with no waiter, a large share of kernel time per query, so events that need no immediacy
    /// gather here. Only the first push into an empty slot wakes the collector, so sustained load
    /// touches the channel at most once per drain batch.
    ///
    /// Each slot has its own lock, held only to accumulate, push, or swap out the events. A full
    /// slot drops instead of waiting, so metric collection still never blocks service.
    stat_slots: Arc<Vec<Mutex<StatSlot>>>,
    /// Set while the collector idles, so the first stats event must wake it.
    stat_collector_idle: Arc<AtomicBool>,
    querylog: Arc<AtomicBool>,

    /// Whether anything can read what is collected. With neither a management listener nor stats or
    /// log files, nothing can, and building an event per query is pure waste for a headless
    /// deployment.
    ///
    /// Defaults to true: unless told otherwise, collect.
    ///
    /// A live update that adds a management address must set it true. Some update paths do not
    /// rebuild the generation, so they must set it again in place.
    collecting: Arc<AtomicBool>,
    anonymize: Arc<AtomicBool>,
    /// Lowercase, without a trailing dot.
    ignored: Arc<RwLock<Vec<Box<str>>>>,

    /// Whether the ignore list is non-empty; when empty, the lock is not even taken.
    ignored_active: Arc<AtomicBool>,
    log_cap: Arc<AtomicUsize>,
    retention_ms: Arc<AtomicU64>,
    /// The dashboard reads from here.
    recent: Arc<Mutex<VecDeque<QueryEvent>>>,
    /// Background threads, stopped when the last recorder drops.
    _runtime: Arc<RecorderRuntime>,
}

struct RecorderRuntime {
    stop: Arc<AtomicBool>,
    sampler: Mutex<Option<std::thread::JoinHandle<()>>>,
    collector: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Drop for RecorderRuntime {
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
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// Cumulative stats are kept.
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

    /// Lets callers skip building values only the query log uses; strings built while it is off are
    /// just thrown away.
    pub fn querylog_enabled(&self) -> bool {
        self.querylog.load(Ordering::Acquire)
    }

    /// `on` when a management listener or a stats or log file exists.
    pub fn set_collecting(&self, on: bool) {
        self.collecting.store(on, Ordering::Release);
    }

    /// Lets callers skip building values only the record uses: naming and reading the clock cost
    /// something per query, so skip them when nothing can read the result.
    pub fn collecting(&self) -> bool {
        self.collecting.load(Ordering::Acquire)
    }

    /// Counts what is still queued, then returns what a successor process needs to go on counting
    /// from here: the totals and top lists, the graph history and the query log.
    pub fn export_state(&self) -> Result<Vec<u8>, String> {
        let (reply, state) = mpsc::sync_channel(1);
        self.log_tx
            .send(CollectorEvent::Export(reply))
            .map_err(|_| COLLECTOR_GONE.to_string())?;
        state.recv().map_err(|_| COLLECTOR_GONE.to_string())
    }

    /// Adds a predecessor's `export_state` to what this recorder counted. The recorder must have
    /// started without saved statistics, or they would be counted twice.
    pub fn merge_state(&self, state: &[u8]) -> Result<(), String> {
        let carried = crate::persist::decode_carried(state, Transport::COUNT)?;
        self.merge(carried)
    }

    /// Adds the saved statistics and query log, for a predecessor that ended without handing over
    /// its state. Same precondition as `merge_state`.
    pub fn merge_saved(&self, persist: &PersistOpts) -> Result<(), String> {
        let carried = crate::persist::read_saved(
            persist,
            self.log_cap.load(Ordering::Acquire).max(1),
            self.retention_ms.load(Ordering::Acquire),
            now_ms(),
            Transport::COUNT,
        );
        self.merge(carried)
    }

    fn merge(&self, carried: crate::persist::CarriedStats) -> Result<(), String> {
        let (reply, done) = mpsc::sync_channel(1);
        self.log_tx
            .send(CollectorEvent::Merge(Box::new(carried), reply))
            .map_err(|_| COLLECTOR_GONE.to_string())?;
        done.recv().map_err(|_| COLLECTOR_GONE.to_string())
    }

    #[allow(clippy::too_many_arguments)]
    /// Derives the rcode and reason from the action and passes on to record_detailed.
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
    /// Only enqueues and returns at once; on a full channel it drops the event and counts the drop.
    /// Waiting here would turn metric collection into an outage.
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
        // With nothing to read it, do not even count: cumulative metrics are read only through the
        // management listener, so anything added here would vanish unread.
        if !self.collecting.load(Ordering::Acquire) {
            return;
        }
        let m = &self.metrics;
        // The name goes by value: Name is an Arc, so a clone is a reference count increment, and
        // strings are built only where used (top-list keys, query log JSON).
        let ignored = self.is_ignored(name);
        let do_log = self.querylog.load(Ordering::Acquire) && log_client && !ignored;
        let do_stat = stat_client && !ignored;

        // Log events go through the channel, so their totals go to the global atomics. The default
        // log-off path folds these three into the stats slot lock it takes below, avoiding global
        // cache line writes.
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

        // The address goes by value; stringifying it where it is used avoids the worker allocating
        // and the collector freeing.
        let client_s = if self.anonymize.load(Ordering::Acquire) {
            anonymize_ip(client)
        } else {
            client
        };
        if !do_log {
            // Top lists look only at name, client, and action. A whole QueryEvent would write,
            // move, and drop eight empty Strings and log-only fields through the slot.
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

        // From here on, values go into the actual query log. The stats-only path never builds these
        // strings or reads the clock.
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

    /// Runs per query, so the name is normalized once into a stack buffer and compared against an
    /// already normalized list. An empty list skips the lock. A missing name never matches.
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

    pub fn record_cache(&self, hit: bool) {
        self.metrics.cache_lookups.fetch_add(1, Ordering::Relaxed);
        if hit {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The labels always sum to less than the wire length limit.
const MAX_IGNORE_NAME: usize = 256;

/// Normalizes the ignore list once, since it is configuration and does not change per query;
/// otherwise each query would build a string per entry. Returns lowercase entries without a
/// trailing dot; an empty entry matches only the root and is kept.
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

/// Writes the name in lowercase dotted form into a stack buffer, so the per-query path does not
/// allocate. Dots go only between labels, so there is no trailing dot. The buffer always suffices
/// for the name length limit; if not, the result is allocated. Non-UTF-8 labels convert lossily to
/// replacement characters.
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

/// Matches only at label boundaries. `name` comes from normalize_into, `d` from normalize_ignored.
fn suffix_matches(name: &str, d: &str) -> bool {
    name == d
        || (name.len() > d.len()
            && name.ends_with(d)
            && name.as_bytes()[name.len() - d.len() - 1] == b'.')
}

/// Masks the host part, so stats stay useful without identifying a person.
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

fn add_saturating(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(value))
    });
}

/// Min-heap for finding the smallest top-list entry quickly.
type CounterHeap<K> = std::collections::BinaryHeap<std::cmp::Reverse<(u64, K)>>;

#[derive(Default)]
pub struct TopCounters {
    pub domains: std::collections::HashMap<Name, u64>,
    pub blocked: std::collections::HashMap<Name, u64>,
    pub clients: std::collections::HashMap<IpAddr, u64>,
    domains_heap: CounterHeap<Name>,
    blocked_heap: CounterHeap<Name>,
    clients_heap: CounterHeap<IpAddr>,
    /// Misses of new names after the map reached `TOP_CAP`.
    domains_misses: u64,
    blocked_misses: u64,
    clients_misses: u64,
}

impl TopCounters {
    /// Adds counts made elsewhere. Lists over the cap keep the largest counts.
    pub(crate) fn add_counts(
        &mut self,
        domains: std::collections::HashMap<Name, u64>,
        blocked: std::collections::HashMap<Name, u64>,
        clients: std::collections::HashMap<IpAddr, u64>,
    ) {
        add_capped(&mut self.domains, domains);
        add_capped(&mut self.blocked, blocked);
        add_capped(&mut self.clients, clients);
        // Rebuilt from the maps on the next eviction.
        self.domains_heap.clear();
        self.blocked_heap.clear();
        self.clients_heap.clear();
    }
}

fn add_capped<K: Eq + std::hash::Hash + Ord>(
    map: &mut std::collections::HashMap<K, u64>,
    other: std::collections::HashMap<K, u64>,
) {
    for (key, count) in other {
        let total = map.entry(key).or_default();
        *total = total.saturating_add(count);
    }
    if map.len() <= TOP_CAP {
        return;
    }
    let mut pairs: Vec<(K, u64)> = std::mem::take(map).into_iter().collect();
    // Ties break by key so the kept entries do not vary between runs.
    pairs.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
    pairs.truncate(TOP_CAP);
    map.extend(pairs);
}

/// Bounds memory under high-cardinality traffic.
pub(crate) const TOP_CAP: usize = 10_000;

/// Workers use different slots to reduce contention.
const STAT_SLOTS: usize = 16;

/// A full slot drops events and counts them.
const STAT_SLOT_CAP: usize = 4096;

/// Under load, slots keep draining at this interval.
const BUSY_DRAIN_INTERVAL: Duration = Duration::from_millis(1);

static NEXT_STAT_SLOT: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// Assigned on first use and kept.
    static STAT_SLOT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

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

/// Only the first push into an empty slot notifies the collector. False when the slot is full.
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
        // A full channel means the collector already has work and will drain the slots on its next
        // loop; a lost wakeup must not count as a lost stats event.
        let _ = wake_tx.try_send(CollectorEvent::StatsReady);
    }
    true
}

/// Rebuilt when lazily deleted entries pile up.
fn rebuild_heap<K: Eq + std::hash::Hash + Ord + Clone>(
    map: &std::collections::HashMap<K, u64>,
    heap: &mut CounterHeap<K>,
) {
    *heap = map
        .iter()
        .map(|(key, count)| std::cmp::Reverse((*count, key.clone())))
        .collect();
}

/// Once at the cap, admit a new name only every this many misses. With more distinct names than the
/// cap, every miss would remove from the map, insert, and clean the heap, and a resolver nearly
/// always sees more names than the cap. The top lists keep their meaning: a frequent name misses
/// repeatedly and soon gets in; only churn goes down.
///
/// Must be a power of two, so the modulo becomes a bit mask.
const ADMIT_EVERY_MISSES: u64 = 16;

/// Increments a key, evicting the smallest when over the cap. `misses` counts misses after the cap
/// was reached and narrows this map's admission. Memory must stay within the cap even under extreme
/// cardinality.
fn bump<K: Eq + std::hash::Hash + Ord + Clone>(
    map: &mut std::collections::HashMap<K, u64>,
    heap: &mut CounterHeap<K>,
    misses: &mut u64,
    key: &K,
) {
    // The heap is used only when an eviction is actually admitted. At the cap with no new key, or
    // before the admission gate opens, cloning 10,000 keys and the heap memory are unnecessary.
    if let Some(v) = map.get_mut(key) {
        // The heap is read only on eviction, so increments need not clone and push keys. Eviction
        // filters stale entries by comparing counts, and the heap is rebuilt when all are filtered.
        *v = v.saturating_add(1);
        return;
    }
    if map.len() < TOP_CAP {
        map.insert(key.clone(), 1);
        return;
    }

    // From here on is the replacement path: map delete and insert plus heap cleanup all happen
    // here, so with more distinct names than the cap, this cost would land on every query.
    *misses = misses.wrapping_add(1);
    if *misses % ADMIT_EVERY_MISSES != 0 {
        return;
    }

    if heap.is_empty() {
        rebuild_heap(map, heap);
    }
    // Two rounds at most. If the first round yields only stale entries and empties the heap, it is
    // rebuilt; that heap matches the map's counts exactly, so the second round's first pop is
    // valid. Without this fallback, a stale heap would silently drop the new name.
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
pub struct TopLists {
    pub domains: Vec<(String, u64)>,
    pub blocked: Vec<(String, u64)>,
    pub clients: Vec<(String, u64)>,
}

type Subscribers = Arc<Mutex<Vec<mpsc::SyncSender<QueryEvent>>>>;

/// One subscription, reporting any gap it missed.
pub struct QuerySubscription {
    /// Events recorded just before subscribing, closing the gap at the moment of attaching.
    pub replay: Vec<QueryEvent>,
    pub receiver: mpsc::Receiver<QueryEvent>,
    /// Events from before subscribing were already evicted, so some are missing.
    pub replay_gap: bool,
}

#[derive(Clone)]
/// Read-side handle for the dashboard.
pub struct Stats {
    pub metrics: Arc<Metrics>,
    pub recent: Arc<Mutex<VecDeque<QueryEvent>>>,
    pub top: Arc<Mutex<TopCounters>>,

    subscribers: Subscribers,

    log_cap: Arc<AtomicUsize>,

    persist: Arc<RwLock<PersistOpts>>,
}

impl Stats {
    pub fn recent(&self, limit: usize) -> Vec<QueryEvent> {
        let b = self.recent.lock_recover();
        b.iter().rev().take(limit).cloned().collect()
    }

    pub fn persist_opts(&self) -> PersistOpts {
        self.persist
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// If deleting on disk fails, memory is kept too; clearing only one would bring back records
    /// thought deleted at restart.
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

    /// Saves the last state before persistence is turned off.
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

    pub fn subscribe(&self) -> mpsc::Receiver<QueryEvent> {
        self.subscribe_after(None).receiver
    }

    /// Replays what was missed after `last_id` first. If that is past retention, it says so;
    /// skipping silently, the subscriber would not know anything was lost.
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

    pub fn top(&self, n: usize) -> TopLists {
        let t = self.top.lock_recover();
        TopLists {
            domains: top_n(&t.domains, n),
            blocked: top_n(&t.blocked, n),
            clients: top_n(&t.clients, n),
        }
    }
}

/// Updates stats and delivers to subscribers.
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

fn process_stat_values(
    client: &IpAddr,
    name: Option<&Name>,
    blocked_action: bool,
    top: &Arc<Mutex<TopCounters>>,
) {
    let mut t = top.lock_recover();
    process_stat_values_locked(client, name, blocked_action, &mut t);
}

/// For a batch that already holds the top-list lock.
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
        // Keys are case-sensitive, so fold first; an already lowercase name is borrowed as is.
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
enum PersistKind {
    Querylog,
    Stats,
}

impl PersistKind {
    fn as_str(self) -> &'static str {
        match self {
            PersistKind::Querylog => "querylog",
            PersistKind::Stats => "stats",
        }
    }
}

/// Fingerprint of the last failure of one kind, and when it was reported.
struct PersistWarningState {
    /// Fingerprint, so the path itself is not kept.
    path: u64,
    /// Fingerprint, so the error text is not kept.
    message: u64,
    last: Instant,
}

/// Suppresses repeated warnings, with a fixed slot per kind.
struct PersistWarnings {
    /// Per-process seed, so input cannot choose fingerprint collisions.
    fingerprint_state: RandomState,
    querylog: Option<PersistWarningState>,
    stats: Option<PersistWarningState>,
}

impl Default for PersistWarnings {
    fn default() -> Self {
        Self {
            fingerprint_state: RandomState::new(),
            querylog: None,
            stats: None,
        }
    }
}

impl PersistWarnings {
    fn slot_mut(&mut self, kind: PersistKind) -> &mut Option<PersistWarningState> {
        match kind {
            PersistKind::Querylog => &mut self.querylog,
            PersistKind::Stats => &mut self.stats,
        }
    }

    /// Updates the fingerprint state too.
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

    fn clear(&mut self, kind: PersistKind) {
        *self.slot_mut(kind) = None;
    }

    #[cfg(test)]
    fn retained_slots(&self) -> usize {
        usize::from(self.querylog.is_some()) + usize::from(self.stats.is_some())
    }
}

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

const COLLECTOR_GONE: &str = "The statistics thread is not running";

/// The predecessor's events come first with their IDs; the ones counted here follow, numbered after
/// them. Nothing reads these IDs yet, as the successor's dashboard starts after the merge.
fn merge_carried(
    carried: crate::persist::CarriedStats,
    metrics: &Metrics,
    top: &Mutex<TopCounters>,
    recent: &Mutex<VecDeque<QueryEvent>>,
    next_event_id: &std::cell::Cell<u64>,
    retention_ms: &AtomicU64,
    log_cap: &AtomicUsize,
) {
    let crate::persist::CarriedStats {
        mut totals,
        recent: theirs,
        next_event_id: their_next,
        seconds,
        minutes,
    } = carried;
    metrics.add_history(&totals, seconds, minutes);
    top.lock_recover().add_counts(
        std::mem::take(&mut totals.domains),
        std::mem::take(&mut totals.top_blocked),
        std::mem::take(&mut totals.clients),
    );

    let offset = their_next.saturating_sub(1);
    let mut events = recent.lock_recover();
    let ours = std::mem::replace(&mut *events, theirs);
    events.extend(ours.into_iter().map(|mut event| {
        event.id = event.id.saturating_add(offset);
        event
    }));
    next_event_id.set(next_event_id.get().saturating_add(offset));
    let retention_ms = retention_ms.load(Ordering::Acquire);
    if retention_ms > 0 {
        let cutoff = now_ms().saturating_sub(retention_ms);
        while events.front().is_some_and(|event| event.ts_ms < cutoff) {
            events.pop_front();
        }
    }
    let log_cap = log_cap.load(Ordering::Acquire).max(1);
    while events.len() > log_cap {
        events.pop_front();
    }
}

/// Creates the recorder and read handle and starts the background threads. The bounded channel
/// separates the data path from collection; that boundary keeps metrics from blocking queries.
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
    let next_event_id = std::cell::Cell::new(crate::persist::number_events(&mut initial_recent));
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

            // Also the slot drain period. Too long and slots overflow, turning stats into a sample:
            // total slot capacity must exceed the queries arriving in this time.
            let poll_interval = Duration::from_millis(20);
            let process = |mut ev: QueryEvent| {
                if ev.log {
                    ev.id = next_event_id.get();
                    next_event_id.set(next_event_id.get().saturating_add(1));
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
            // Takes the stats-only events from the slots. A slot lock is held only for the swap,
            // the top-list lock for one batch.
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

            // If the slots had work, look again almost at once; draining only on the period lets
            // slots overflow under load.
            loop {
                let wait = if drain_slots() {
                    collector_idle.store(false, Ordering::Release);
                    dirty = true;
                    BUSY_DRAIN_INTERVAL
                } else {
                    // Events arriving between the first drain and the idle flag are caught by the
                    // recheck after setting it. The first event after that clears the flag and
                    // sends a wake token.
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
                    // Logs sent before a handoff request arrived ahead of it. Stats-only events may
                    // have entered a slot since the last drain.
                    Ok(CollectorEvent::Export(reply)) => {
                        drain_slots();
                        metrics_t.sample_now();
                        let stats_line =
                            crate::persist::stats_json(&metrics_t, &top_c.lock_recover());
                        let history = metrics_t.history.lock_recover();
                        let state = crate::persist::encode_carried(
                            &stats_line,
                            &buf.lock_recover(),
                            next_event_id.get(),
                            &history.seconds,
                            &history.minutes,
                        );
                        drop(history);
                        let _ = reply.send(state);
                    }
                    Ok(CollectorEvent::Merge(carried, reply)) => {
                        drain_slots();
                        merge_carried(
                            *carried,
                            &metrics_t,
                            &top_c,
                            &buf,
                            &next_event_id,
                            &retention_t,
                            &log_cap_t,
                        );
                        dirty = true;
                        let _ = reply.send(());
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        // Even with every sender gone, what remains in the slots is counted before
                        // exiting.
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

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(recorder: &Recorder, name: &str, action: Action, log: bool) {
        recorder.record(
            Transport::Do53Udp,
            action,
            "192.0.2.1".parse().unwrap(),
            Some(&Name::from_str(name).unwrap()),
            Some(RecordType::A),
            log,
            true,
        );
    }

    fn logged_names(stats: &Stats) -> Vec<(u64, String)> {
        stats
            .recent
            .lock_recover()
            .iter()
            .map(|event| (event.id, event.name.as_ref().unwrap().to_string()))
            .collect()
    }

    fn history_queries(recorder: &Recorder) -> u64 {
        let (_, points) = recorder.metrics().history(3_600, 60);
        points.iter().map(|point| point.queries).sum()
    }

    #[test]
    /// The successor's totals, top lists, graph and query log go on from the predecessor's: nothing
    /// counted twice, nothing lost, the predecessor's log IDs kept and its own numbered after them.
    fn a_successor_goes_on_counting_from_the_predecessor_state() {
        let (old, _) = channel(64, 100, 0, RecorderOpts::default(), PersistOpts::default());
        ask(&old, "a1.example", Action::Resolved, true);
        ask(&old, "a2.example", Action::Blocked, true);
        ask(&old, "a3.example", Action::Resolved, true);
        ask(&old, "s1.example", Action::Resolved, false);
        ask(&old, "s2.example", Action::Resolved, false);
        // Exported at once: what is still queued is counted first.
        let state = old.export_state().unwrap();

        let (new, stats) = channel(64, 100, 0, RecorderOpts::default(), PersistOpts::default());
        ask(&new, "b1.example", Action::Resolved, true);
        ask(&new, "a1.example", Action::Resolved, true);
        new.merge_state(&state).unwrap();

        let snapshot = new.metrics().snapshot();
        assert_eq!(snapshot.total, 7);
        assert_eq!(snapshot.blocked, 1);
        assert_eq!(snapshot.resolved, 6);
        let udp = snapshot
            .by_transport
            .iter()
            .find(|(name, _)| *name == Transport::Do53Udp.name())
            .unwrap();
        assert_eq!(udp.1, 7);
        let top = stats.top(10);
        assert_eq!(top.domains[0], ("a1.example.".to_string(), 2));
        assert_eq!(top.blocked, [("a2.example.".to_string(), 1)]);
        assert_eq!(top.clients, [("192.0.2.1".to_string(), 7)]);

        let names = |list: &[&str]| -> Vec<(u64, String)> {
            list.iter()
                .enumerate()
                .map(|(index, name)| (index as u64 + 1, format!("{name}.")))
                .collect()
        };
        assert_eq!(
            logged_names(&stats),
            names(&[
                "a1.example",
                "a2.example",
                "a3.example",
                "b1.example",
                "a1.example"
            ])
        );
        ask(&new, "b2.example", Action::Resolved, true);
        for _ in 0..200 {
            if stats.recent(10).len() == 6 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            logged_names(&stats).last(),
            Some(&(6, "b2.example.".to_string()))
        );

        assert_eq!(
            history_queries(&new),
            8,
            "the graph lost or doubled queries"
        );
        std::thread::sleep(Duration::from_millis(1_100));
        assert_eq!(
            history_queries(&new),
            8,
            "the merged totals showed up as a spike"
        );
    }

    #[test]
    /// A predecessor that ended without handing over its state still saved it; the successor adds
    /// those files instead.
    fn a_successor_adds_the_saved_state_when_none_was_handed_over() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-carried-saved-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let saved = PersistOpts {
            querylog_file: Some(dir.join("querylog.jsonl")),
            stats_file: Some(dir.join("stats.json")),
            flush_secs: 3_600,
        };
        let (old, old_stats) = channel(64, 100, 0, RecorderOpts::default(), saved.clone());
        ask(&old, "a1.example", Action::Resolved, true);
        ask(&old, "a2.example", Action::Blocked, true);
        // Turning persistence off saves the last state, as a predecessor does when it lets go.
        old.export_state().unwrap();
        old_stats
            .reconfigure_persist(PersistOpts::default())
            .unwrap();

        let (new, stats) = channel(64, 100, 0, RecorderOpts::default(), PersistOpts::default());
        ask(&new, "b1.example", Action::Resolved, true);
        new.merge_saved(&saved).unwrap();

        assert_eq!(new.metrics().snapshot().total, 3);
        assert_eq!(
            logged_names(&stats),
            [
                (1, "a1.example.".to_string()),
                (2, "a2.example.".to_string()),
                (3, "b1.example.".to_string())
            ]
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
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
    /// Only an idle collector is woken by the first slot event, and wakeups under sustained load
    /// coalesce.
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
    /// Log-off shard counts are exact at once and survive save and restore.
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
    /// Compares slot write cost of full log events and compact stats events in the same binary.
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
    /// Whether folding three global atomics into the slot lock already held is worth it.
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
    /// Top-list lock per event versus per slot batch.
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
    /// Headless deployments have neither a management listener nor files, so nothing collected here
    /// can be read.
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

        // Control: once there is a reader, the same calls must be recorded. Without this, the
        // assertion above would pass even with a completely broken recorder.
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
    /// Clearing only one would bring them back at restart.
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
    /// Once at the cap, a new name is admitted only every few misses. A frequent name misses
    /// repeatedly and soon gets in; a one-off name does not churn the map.
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
    /// A resolver nearly always sees more distinct names than the cap. Churning the map and heap on
    /// every miss would cost that on every query, and the top lists would only push each other out.
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
    /// Values that only go into the query log are not built while it is off; if that optimization
    /// emptied the stats too, the top lists would be empty. With it on, the values must actually be
    /// carried.
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
    /// Without eviction, maintaining it is waste.
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
    /// Increments do not update the heap, so after reaching the cap, bumping counts makes every
    /// heap entry stale. If eviction did not rebuild the heap then, the new name would vanish
    /// silently.
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
        // Bump every key left after the first eviction once, so all heap counts go stale.
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
    /// With an empty ignore list, the lock is never taken.
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
    /// Using the total would spike right after a restart.
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
        let (_, points) = history.points(10_060, 3_600, 59);
        assert_eq!(points.len(), 59);
        assert_eq!(
            points.iter().map(|point| point.queries).sum::<u64>(),
            120,
            "구간을 나눠도 질의 수의 합은 보존되어야 합니다"
        );
        assert!(points.iter().any(|point| point.avg_latency_ms == 30.0));
    }

    #[test]
    fn history_bins_stay_on_the_clock_between_refreshes() {
        let mut history = MetricHistory::default();
        history.reset_baseline(MetricBucket::default(), 100_000);
        let mut total = 0;
        for sec in 100_001..=103_620 {
            total += sec % 7;
            history.sample(
                MetricBucket {
                    queries: total,
                    ..MetricBucket::default()
                },
                sec,
            );
        }
        let queries = |now| {
            let (width, points) = history.points(now, 3_600, 59);
            assert_eq!(width, 60);
            points.iter().map(|point| point.queries).collect::<Vec<_>>()
        };
        let first = queries(103_620);
        assert_eq!(
            first,
            queries(103_625),
            "다시 계산해도 같은 구간은 같은 값이어야 합니다"
        );
        assert_eq!(
            queries(103_680)[..58],
            first[1..],
            "다음 구간으로 넘어가면 한 칸씩 밀려야 합니다"
        );
        assert!(
            first[0] > 0,
            "가장 오래된 구간도 보관 범위 안에 있어야 합니다"
        );
    }

    #[test]
    fn history_bins_hold_whole_minutes() {
        let mut history = MetricHistory::default();
        let start = 1_000_020;
        history.reset_baseline(MetricBucket::default(), start);
        for minute in 1..=2 * 24 * 60 {
            history.sample(
                MetricBucket {
                    queries: minute * 10,
                    ..MetricBucket::default()
                },
                start + minute * 60,
            );
        }
        let now = start + 2 * 24 * 60 * 60;
        let (width, points) = history.points(now, 86_400, 59);
        assert_eq!(width, 1_440);
        assert!(
            points[..58].iter().all(|point| point.queries == 240),
            "구간마다 분 기록이 같은 수만큼 들어가야 합니다"
        );
        assert_eq!(points[0].ts_ms % 1_440_000, 0);
        assert_eq!(points[58].ts_ms, now * 1_000);
    }

    #[test]
    fn stats_shares_reconfigured_log_capacity() {
        let (rec, stats) = channel(8, 32, 0, RecorderOpts::default(), PersistOpts::default());
        assert_eq!(stats.log_cap.load(Ordering::Acquire), 32);

        rec.reconfigure(true, false, Vec::new(), 512, 0, 0);
        assert_eq!(stats.log_cap.load(Ordering::Acquire), 512);
    }

    #[test]
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
    /// A gap would make subscribers think they missed something.
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
        // The background thread processes records. Two recent records also happens when only the
        // first two or three were processed, and then the record after #1 is still there with no
        // gap, so wait for the last one.
        for _ in 0..100 {
            if stats.recent(1).first().is_some_and(|event| event.id == 4) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let retained: Vec<u64> = stats.recent(10).iter().map(|event| event.id).collect();
        assert_eq!(retained, vec![4, 3], "기록 네 개가 다 처리되지 않았습니다");
        let subscription = stats.subscribe_after(Some(0));

        assert!(!subscription.replay_gap);
        assert_eq!(subscription.replay.len(), 2);
        let subscription = stats.subscribe_after(Some(1));
        assert!(subscription.replay_gap);
    }

    #[test]
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
    fn subscribe_after_reports_restart_gap_when_recent_is_empty() {
        let (_rec, stats) = channel(8, 8, 0, RecorderOpts::default(), PersistOpts::default());
        let subscription = stats.subscribe_after(Some(42));
        assert!(subscription.replay_gap);
        assert!(subscription.replay.is_empty());
    }

    #[test]
    /// Holding on to it would stall all collection.
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
