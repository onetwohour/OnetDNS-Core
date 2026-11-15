//! Response cache, plus coalescing of identical queries in flight: when the same query arrives
//! several times at once, one goes upstream and the rest share its result. The cache is sharded to
//! reduce lock contention.
//!
//! The key must hold everything that changes the response: holding less gives one query another's
//! answer, and holding more makes the cache miss. A response is stored only when what was asked is
//! actually in it, and a negative one only with the authority record that proves it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use onetdns_core::lrumap::LruMap;
use onetdns_core::MutexExt;
use onetdns_proto::{Message, Record, RecordType, ResponseCode};

use crate::native::{ResolveFailure, ResolveOutcome, Resolver};

mod answer;
mod key;
mod ttl;

pub(crate) use answer::{
    age_records, cached_message, has_requested_answer, neg_soa_minimum,
    relevant_negative_soa_minimum, retarget_response, terminal_answer_name,
};
pub(crate) use key::{
    CacheKey, FailureKey, FlightKey, NormalizedRequestKey, MAX_CACHED_REQUEST_WIRE,
};
pub(crate) use ttl::{cache_dnssec_ttl_cap, dnssec_ttl_cap};

/// A resolution in flight, with the result its followers wait for.
struct ClientFlight {
    result: Mutex<Option<Result<Message, ResolveFailure>>>,
    ready: Condvar,

    /// Followers waiting on the condvar; at 0, `complete` skips the notify. Changed only inside
    /// `wait`, and incremented under the result lock, so a follower arriving after `complete` read
    /// 0 sees the result before sleeping.
    waiters: std::sync::atomic::AtomicUsize,

    /// So the leader never waits on its own flight.
    leader_thread: std::thread::ThreadId,
}

/// Wakes the followers even when the leader returns without a result.
struct FlightLeaderGuard<'a> {
    key: FlightKey,
    flight: Arc<ClientFlight>,
    flights: &'a Mutex<HashMap<FlightKey, Arc<ClientFlight>>>,
    finished: bool,
}

impl FlightLeaderGuard<'_> {
    /// Publishes the result and removes the flight from the table.
    fn finish(&mut self, result: Result<Message, ResolveFailure>) {
        self.flight.complete(result);
        self.flights.lock_recover().remove(&self.key);
        self.finished = true;
    }
}

impl Drop for FlightLeaderGuard<'_> {
    /// Otherwise followers would stall until the deadline.
    fn drop(&mut self) {
        if !self.finished {
            self.flight.complete(Err(ResolveFailure::Permanent(None)));
            self.flights.lock_recover().remove(&self.key);
        }
    }
}

impl ClientFlight {
    /// With the current thread as leader.
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            ready: Condvar::new(),
            waiters: std::sync::atomic::AtomicUsize::new(0),
            leader_thread: std::thread::current().id(),
        }
    }

    /// None past the deadline.
    fn wait(&self, timeout: Duration) -> Option<Result<Message, ResolveFailure>> {
        /// Restores the waiter count on every return path.
        struct Waiting<'a>(&'a std::sync::atomic::AtomicUsize);
        impl Drop for Waiting<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let deadline = Instant::now() + timeout;
        let mut result = self.result.lock_recover();
        self.waiters
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _waiting = Waiting(&self.waiters);
        while result.is_none() {
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let remaining = deadline.saturating_duration_since(now);
            let (guard, timed) = self
                .ready
                .wait_timeout(result, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            result = guard;
            if timed.timed_out() && result.is_none() {
                return None;
            }
        }
        Some(
            result
                .as_ref()
                .expect("Client request completion was checked above")
                .clone(),
        )
    }

    /// Skips the notify with no waiters, since it would still be a system call.
    fn complete(&self, result: Result<Message, ResolveFailure>) {
        *self.result.lock_recover() = Some(result);

        if self.waiters.load(std::sync::atomic::Ordering::SeqCst) > 0 {
            self.ready.notify_all();
        }
    }
}

/// Followers still waiting after this answer SERVFAIL.
const CLIENT_FLIGHT_TIMEOUT: Duration = Duration::from_secs(15);
/// Past it, queries go upstream without coalescing.
const MAX_CLIENT_FLIGHTS: usize = 4_096;
/// Doubles with each repeated failure, up to `FAILURE_CACHE_MAX_TTL`.
const FAILURE_CACHE_BASE_TTL: Duration = Duration::from_secs(5);
const FAILURE_CACHE_MAX_TTL: Duration = Duration::from_secs(300);

#[derive(Clone, Copy)]
struct FailureEntry {
    expiry: Instant,
    attempts: u8,
}

/// Sections are sized exactly; spare capacity would cost memory in every entry.
struct StructuredEntry {
    answers: Box<[Record]>,
    authorities: Box<[Record]>,
    additionals: Box<[Record]>,
    inserted: Instant,

    lifetime_secs: u32,
    rcode: u16,
    authentic: bool,
}

/// Marks a slot answered by a configured fixed address. Without it, promotion could not tell
/// another layer's answer apart and would turn it into a fixed-TTL entry.
struct LocalWireMarker;

impl StructuredEntry {
    fn elapsed_secs(&self, now: Instant) -> u32 {
        u32::try_from(now.saturating_duration_since(self.inserted).as_secs()).unwrap_or(u32::MAX)
    }

    fn is_expired_at(&self, elapsed_secs: u32) -> bool {
        elapsed_secs >= self.lifetime_secs
    }

    fn remaining_lifetime(&self, now: Instant) -> Option<u32> {
        let elapsed = self.elapsed_secs(now);
        let remaining = self.lifetime_secs.saturating_sub(elapsed);
        (remaining > 0).then_some(remaining)
    }
}

#[derive(Clone)]
enum Entry {
    Structured(Arc<StructuredEntry>),

    Wire(crate::wirecache::WireEntry),

    /// Bytes whose TTLs never age.
    LocalWire(crate::wirecache::WireEntry),

    /// A fixed address answered; not promoted yet.
    LocalWireMarker(Arc<LocalWireMarker>),
}

impl Entry {
    fn elapsed_secs(&self, now: Instant) -> u32 {
        match self {
            Self::Structured(entry) => entry.elapsed_secs(now),
            Self::Wire(entry) => entry.elapsed_secs(now),
            Self::LocalWire(_) => 0,
            Self::LocalWireMarker(_) => 0,
        }
    }

    fn is_expired_at(&self, elapsed_secs: u32) -> bool {
        match self {
            Self::Structured(entry) => entry.is_expired_at(elapsed_secs),
            Self::Wire(entry) => entry.is_expired_at(elapsed_secs),
            Self::LocalWire(_) => false,
            Self::LocalWireMarker(_) => false,
        }
    }

    fn remaining_lifetime(&self, now: Instant) -> Option<u32> {
        match self {
            Self::Structured(entry) => entry.remaining_lifetime(now),
            Self::Wire(entry) => entry.remaining_lifetime(now),
            Self::LocalWire(_) => Some(u32::MAX),
            Self::LocalWireMarker(_) => Some(u32::MAX),
        }
    }

    /// Checked right before promotion, so an entry replaced meanwhile is not overwritten.
    fn same_allocation(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Structured(left), Self::Structured(right)) => Arc::ptr_eq(left, right),
            (Self::Wire(left), Self::Wire(right)) => {
                crate::wirecache::WireEntry::ptr_eq(left, right)
            }
            (Self::LocalWire(left), Self::LocalWire(right)) => {
                crate::wirecache::WireEntry::ptr_eq(left, right)
            }
            (Self::LocalWireMarker(left), Self::LocalWireMarker(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}

/// Cache generation taken before resolution starts. Every store takes one, so an answer returning
/// after a clear carries an old generation and is not stored. Obtained outside this module only
/// through `epoch`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct CacheEpoch(u64);

/// Sharded response cache plus recent failures.
pub struct NativeCache {
    shards: Vec<Mutex<LruMap<CacheKey, Entry>>>,
    failures: Mutex<LruMap<FailureKey, FailureEntry>>,
    /// Bumped on every clear. `clear` bumps it before emptying anything, and stores recheck it
    /// under the target lock, so an answer from a resolution started before a clear does not
    /// survive it.
    epoch: AtomicU64,
    mask: usize,
    /// Per process, so chosen names cannot pile into one shard.
    hash_keys: [u64; 2],
    min_ttl: u32,
    max_ttl: u32,

    neg_min: u32,
    neg_max: u32,
}

impl NativeCache {
    pub fn new(
        capacity: usize,
        shards: usize,
        min_ttl: u32,
        max_ttl: u32,
        neg_min: u32,
        neg_max: u32,
    ) -> Self {
        let capacity = capacity.max(1);
        let requested = shards.clamp(1, capacity);
        let max_power = 1usize << (usize::BITS - 1 - capacity.leading_zeros());
        let nshards = requested
            .checked_next_power_of_two()
            .unwrap_or(max_power)
            .min(max_power);
        let base = capacity / nshards;
        let remainder = capacity % nshards;
        let shards = (0..nshards)
            .map(|index| Mutex::new(LruMap::new(base + usize::from(index < remainder))))
            .collect();
        Self {
            shards,
            failures: Mutex::new(LruMap::new(capacity.clamp(64, 4096))),
            epoch: AtomicU64::new(0),
            mask: nshards - 1,
            hash_keys: crate::wirecache::random_shard_hash_keys(),
            min_ttl,
            max_ttl,
            neg_min,
            neg_max,
        }
    }

    /// Caps outgoing TTLs like the stored copy. A miss sends the upstream response as is; capping
    /// only the stored copy would give the first client a TTL beyond the config, and since that
    /// client is often a downstream cache, `max_ttl` would bound nothing. Only lowers TTLs, never
    /// raises them.
    ///
    /// `negative` is true for NXDOMAIN or for NODATA proven by an SOA; judging by an empty answer
    /// section alone would treat a referral as negative.
    pub fn clamp_outgoing_ttls(&self, response: &mut Message, negative: bool) {
        let section_cap = if negative { self.neg_max } else { self.max_ttl };
        for record in &mut response.answers {
            record.ttl = record.ttl.min(self.max_ttl);
        }
        for record in response
            .authorities
            .iter_mut()
            .chain(response.additionals.iter_mut())
        {
            if record.rtype == RecordType::OPT {
                continue;
            }
            record.ttl = record.ttl.min(section_cap);
        }
    }

    /// None when too long to store.
    fn key(request: &Message) -> Option<CacheKey> {
        FlightKey::from_request(request)
            .filter(|key| key.as_slice().len() <= MAX_CACHED_REQUEST_WIRE)
    }

    fn idx(&self, key: &[u8]) -> usize {
        if self.mask == 0 {
            return 0;
        }

        (crate::wirecache::shard_hash(key, self.hash_keys) as usize) & self.mask
    }

    #[cfg(test)]
    /// For tests.
    pub fn get(
        &self,
        request: &Message,
    ) -> Option<(u16, Vec<Record>, Vec<Record>, Vec<Record>, bool)> {
        let key = NormalizedRequestKey::from_request(request)?;
        self.get_by_key(key.as_slice())
    }

    /// Ages TTLs by the time elapsed and drops records that ran out.
    fn get_by_key(&self, key: &[u8]) -> Option<(u16, Vec<Record>, Vec<Record>, Vec<Record>, bool)> {
        let idx = self.idx(key);
        let mut shard = self.shards[idx].lock_recover();
        let entry = shard.get(key)?.clone();
        let now = Instant::now();
        let elapsed_secs = entry.elapsed_secs(now);
        if entry.is_expired_at(elapsed_secs) {
            shard.pop(key);
            return None;
        }
        drop(shard);
        match entry {
            Entry::Structured(entry) => {
                let mut answers = entry.answers.to_vec();
                let mut authorities = entry.authorities.to_vec();
                let mut additionals = entry.additionals.to_vec();
                age_records(&mut answers, u64::from(elapsed_secs));
                age_records(&mut authorities, u64::from(elapsed_secs));
                age_records(&mut additionals, u64::from(elapsed_secs));
                Some((
                    entry.rcode,
                    answers,
                    authorities,
                    additionals,
                    entry.authentic,
                ))
            }
            Entry::Wire(entry) => {
                let message = entry.parse_aged_at(elapsed_secs)?;
                Some((
                    message.header.rcode,
                    message.answers,
                    message.authorities,
                    message.additionals,
                    message.header.authentic_data,
                ))
            }
            Entry::LocalWire(entry) => {
                let message = entry.parse_aged_at(0)?;
                Some((
                    message.header.rcode,
                    message.answers,
                    message.authorities,
                    message.additionals,
                    message.header.authentic_data,
                ))
            }
            Entry::LocalWireMarker(_) => None,
        }
    }

    /// Must be taken before reading any state that decides the answer; taken after, an answer built
    /// from pre-clear state would be stored under the post-clear generation.
    pub(crate) fn epoch(&self) -> CacheEpoch {
        CacheEpoch(self.epoch.load(Ordering::Acquire))
    }

    /// Call with the target shard's lock held, or it races `clear`.
    fn is_current(&self, epoch: CacheEpoch) -> bool {
        self.epoch.load(Ordering::Acquire) == epoch.0
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    /// For tests; stores under the current generation.
    pub fn put(
        &self,
        request: &Message,
        rcode: u16,
        answers: &[Record],
        authorities: &[Record],
        additionals: &[Record],
        authentic: bool,
        neg_soa_min: Option<u32>,
    ) {
        let Some(key) = Self::key(request) else {
            return;
        };
        self.put_by_key(
            self.epoch(),
            &key,
            request,
            rcode,
            answers,
            authorities,
            additionals,
            authentic,
            neg_soa_min,
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// Stores only when what was asked is in the answer, and a negative answer only with an
    /// authority record covering it; otherwise an injected unrelated answer would stay in the
    /// cache. The lifetime is the response's shortest TTL clamped to the configured bounds, and
    /// never past the signature expiry.
    ///
    /// `epoch` is taken before the resolution that built this response started.
    fn put_by_key(
        &self,
        epoch: CacheEpoch,
        key: &CacheKey,
        request: &Message,
        rcode: u16,
        answers: &[Record],
        authorities: &[Record],
        additionals: &[Record],
        authentic: bool,
        neg_soa_min: Option<u32>,
    ) {
        if rcode != 0 && rcode != 3 {
            return;
        }
        let Some(question) = request.questions.first() else {
            return;
        };
        let mut answers: Vec<Record> = answers
            .iter()
            .filter(|record| record.class == question.qclass)
            .cloned()
            .collect();
        let mut authorities: Vec<Record> = authorities
            .iter()
            .filter(|record| record.class == question.qclass)
            .cloned()
            .collect();
        let mut additionals: Vec<Record> = additionals
            .iter()
            .filter(|record| record.rtype != RecordType::OPT && record.class == question.qclass)
            .cloned()
            .collect();
        let Some(dnssec_cap) =
            cache_dnssec_ttl_cap(authentic, &answers, &authorities, &additionals)
        else {
            return;
        };
        let has_requested_rrset = has_requested_answer(request, &answers);
        if rcode == ResponseCode::NXDomain.0 && has_requested_rrset {
            return;
        }
        let neg_soa_min = neg_soa_min
            .filter(|_| relevant_negative_soa_minimum(request, &answers, &authorities).is_some());

        if neg_soa_min.is_none() && (rcode == ResponseCode::NXDomain.0 || !has_requested_rrset) {
            return;
        }
        let answer_ttl = answers
            .iter()
            .map(|record| record.ttl)
            .min()
            .unwrap_or(0)
            .clamp(self.min_ttl, self.max_ttl);
        let negative_ttl = neg_soa_min.map(|ttl| ttl.clamp(self.neg_min, self.neg_max));
        let mut ttl = if answers.is_empty() {
            negative_ttl.unwrap_or(0)
        } else if rcode == ResponseCode::NXDomain.0
            || (!has_requested_rrset && negative_ttl.is_some())
        {
            answer_ttl.min(negative_ttl.unwrap_or(answer_ttl))
        } else {
            answer_ttl
        };
        ttl = ttl.min(dnssec_cap);
        if ttl == 0 {
            return;
        }
        for record in &mut answers {
            record.ttl = record.ttl.clamp(self.min_ttl, self.max_ttl);
            record.ttl = record.ttl.min(dnssec_cap);
        }
        if rcode == ResponseCode::NXDomain.0 || !has_requested_rrset {
            for record in &mut authorities {
                if record.rtype == RecordType::SOA {
                    record.ttl = ttl;
                }
            }
        }
        let section_cap = if rcode == ResponseCode::NXDomain.0 || !has_requested_rrset {
            self.neg_max
        } else {
            self.max_ttl
        };
        for record in authorities.iter_mut().chain(additionals.iter_mut()) {
            record.ttl = record.ttl.min(section_cap);
        }
        for record in &mut authorities {
            record.ttl = record.ttl.min(dnssec_cap);
        }
        for record in &mut additionals {
            record.ttl = record.ttl.min(dnssec_cap);
        }
        let now = Instant::now();
        let entry = StructuredEntry {
            rcode,
            answers: answers.into_boxed_slice(),
            authorities: authorities.into_boxed_slice(),
            additionals: additionals.into_boxed_slice(),
            authentic,
            inserted: now,
            lifetime_secs: ttl,
        };
        let idx = self.idx(key.as_slice());
        let mut shard = self.shards[idx].lock_recover();
        if self.is_current(epoch) {
            shard.put(key.clone(), Entry::Structured(Arc::new(entry)));
        }
    }

    fn failure_hit(&self, key: &[u8]) -> Option<u16> {
        let mut failures = self.failures.lock_recover();
        match failures.get(key).copied() {
            Some(entry) if Instant::now() < entry.expiry => Some(ResponseCode::ServFail.0),
            Some(_) => None,
            None => None,
        }
    }

    /// Each repeat doubles the period, since retrying a dead upstream at a fixed interval costs
    /// more.
    ///
    /// `epoch` is taken before the failed resolution started.
    fn remember_failure(&self, epoch: CacheEpoch, key: FailureKey) {
        let now = Instant::now();
        let mut failures = self.failures.lock_recover();
        if !self.is_current(epoch) {
            return;
        }
        let attempts = failures
            .get(&key)
            .map(|entry| entry.attempts.saturating_add(1))
            .unwrap_or(1)
            .min(8);
        let multiplier = 1u32 << u32::from(attempts.saturating_sub(1));
        let ttl = FAILURE_CACHE_BASE_TTL
            .checked_mul(multiplier)
            .unwrap_or(FAILURE_CACHE_MAX_TTL)
            .min(FAILURE_CACHE_MAX_TTL);
        failures.put(
            key,
            FailureEntry {
                expiry: now + ttl,
                attempts,
            },
        );
    }

    fn forget_failure(&self, key: &[u8]) {
        self.failures.lock_recover().pop(key);
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock_recover().len()).sum()
    }

    /// Returns how many were removed. Change any state that affects answers before calling this;
    /// otherwise a resolution taking the new generation reads the old state, and its answer lands
    /// in the emptied cache.
    pub fn clear(&self) -> usize {
        self.epoch.fetch_add(1, Ordering::AcqRel);
        let mut n = 0;
        for s in &self.shards {
            let mut g = s.lock_recover();
            n += g.len();
            g.clear();
        }
        let mut failures = self.failures.lock_recover();
        n += failures.len();
        failures.clear();
        n
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Caches answers and coalesces identical queries.
pub struct CacheLayer {
    inner: Arc<dyn Resolver>,
    cache: Arc<NativeCache>,
    positive_enabled: bool,
    recorder: Option<onetdns_control::Recorder>,
    flights: Mutex<HashMap<FlightKey, Arc<ClientFlight>>>,
}

impl CacheLayer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        inner: Arc<dyn Resolver>,
        capacity: usize,
        shards: usize,
        min_ttl: u32,
        max_ttl: u32,
        neg_min: u32,
        neg_max: u32,
    ) -> Self {
        CacheLayer {
            inner,
            cache: Arc::new(NativeCache::new(
                capacity, shards, min_ttl, max_ttl, neg_min, neg_max,
            )),
            positive_enabled: true,
            recorder: None,
            flights: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_recorder(mut self, recorder: Option<onetdns_control::Recorder>) -> Self {
        self.recorder = recorder;
        self
    }

    pub fn with_positive_cache(mut self, enabled: bool) -> Self {
        self.positive_enabled = enabled;
        self
    }

    /// Remembers failures only, so a dead upstream is not asked on every query. Successful answers
    /// are not stored, so their TTLs are left alone; capping them would send every answer through
    /// this layer with its short cap.
    pub fn failure_guard(inner: Arc<dyn Resolver>, capacity: usize) -> Self {
        Self::new(inner, capacity.max(1), 1, 0, 1, 0, 1).with_positive_cache(false)
    }

    pub fn handle(&self) -> CacheHandle {
        CacheHandle {
            cache: self.cache.clone(),
        }
    }
}

#[derive(Clone)]
pub struct CacheHandle {
    cache: Arc<NativeCache>,
}

pub(crate) struct WirePromotionCandidate {
    /// What the slot held when seen; promotion checks it has not changed.
    entry: Entry,
    lifetime_secs: u32,
    fixed_local_ttl: bool,
}

impl WirePromotionCandidate {
    pub(crate) fn lifetime_secs(&self) -> u32 {
        self.lifetime_secs
    }

    pub(crate) fn has_fixed_local_ttl(&self) -> bool {
        self.fixed_local_ttl
    }
}

impl CacheHandle {
    #[cfg(test)]
    /// For generation swap tests.
    pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.cache, &other.cache)
    }

    pub fn clear(&self) -> usize {
        self.cache.clear()
    }

    /// Take it before resolution starts and pass it when storing.
    pub(crate) fn epoch(&self) -> CacheEpoch {
        self.cache.epoch()
    }

    /// Entries from another filter generation are not used: serving the old generation's allowed
    /// answers would delay every new block.
    pub(crate) fn wire_get(
        &self,
        key: &[u8],
        filter_tag: usize,
        now: Instant,
    ) -> Option<(crate::wirecache::WireEntry, u32)> {
        let idx = self.cache.idx(key);
        let mut shard = self.cache.shards[idx].lock_recover();
        let expired = match shard.get(key)? {
            Entry::Wire(wire) => {
                let elapsed_secs = wire.elapsed_secs(now);
                if wire.is_expired_at(elapsed_secs) {
                    true
                } else if wire.matches_filter(filter_tag) {
                    return Some((wire.clone(), elapsed_secs));
                } else {
                    false
                }
            }
            Entry::LocalWire(wire) => {
                if wire.matches_filter(filter_tag) {
                    return Some((wire.clone(), 0));
                }
                false
            }

            Entry::Structured(_) | Entry::LocalWireMarker(_) => false,
        };
        if expired {
            shard.pop(key);
        }
        None
    }

    pub(crate) fn wire_candidate(
        &self,
        key: &[u8],
        now: Instant,
    ) -> Option<WirePromotionCandidate> {
        let idx = self.cache.idx(key);
        let mut shard = self.cache.shards[idx].lock_recover();
        let entry = shard.get(key)?.clone();
        let Some(lifetime_secs) = entry.remaining_lifetime(now) else {
            shard.pop(key);
            return None;
        };
        Some(WirePromotionCandidate {
            fixed_local_ttl: matches!(&entry, Entry::LocalWire(_) | Entry::LocalWireMarker(_)),
            entry,
            lifetime_secs,
        })
    }

    /// Replaces the slot only if it still holds the candidate; otherwise a newer answer that
    /// arrived meanwhile would be overwritten with an older one.
    ///
    /// `epoch` is taken before the resolution that built `wire` started. The candidate may have
    /// been stored after a clear, so an unchanged candidate alone does not prove `wire` belongs to
    /// the new generation.
    pub(crate) fn promote_wire(
        &self,
        epoch: CacheEpoch,
        key: &[u8],
        candidate: &WirePromotionCandidate,
        wire: crate::wirecache::WireEntry,
    ) -> bool {
        let idx = self.cache.idx(key);
        let mut shard = self.cache.shards[idx].lock_recover();
        if !self.cache.is_current(epoch) {
            return false;
        }
        let Some(current) = shard.get_mut(key) else {
            return false;
        };
        if !current.same_allocation(&candidate.entry) {
            return false;
        }
        *current = if candidate.fixed_local_ttl {
            Entry::LocalWire(wire)
        } else {
            Entry::Wire(wire)
        };
        true
    }

    /// Marks the slot as answered by a fixed address, so promotion can tell it from other answers.
    pub(crate) fn ensure_local_wire_candidate(&self, request: &Message) {
        let Some(key) = NativeCache::key(request) else {
            return;
        };
        let idx = self.cache.idx(key.as_slice());
        let mut shard = self.cache.shards[idx].lock_recover();
        if matches!(
            shard.get(key.as_slice()),
            Some(Entry::LocalWire(_) | Entry::LocalWireMarker(_))
        ) {
            return;
        }
        shard.put(key, Entry::LocalWireMarker(Arc::new(LocalWireMarker)));
    }

    #[cfg(test)]
    /// For tests.
    pub(crate) fn wire_entry_for(&self, request: &Message) -> Option<crate::wirecache::WireEntry> {
        let key = NormalizedRequestKey::from_request(request)?;
        let idx = self.cache.idx(key.as_slice());
        let mut shard = self.cache.shards[idx].lock_recover();
        match shard.get(key.as_slice())? {
            Entry::Wire(wire) | Entry::LocalWire(wire) => Some(wire.clone()),
            Entry::Structured(_) | Entry::LocalWireMarker(_) => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn install_local_wire_for_test(
        &self,
        request: &Message,
        wire: crate::wirecache::WireEntry,
    ) -> bool {
        let Some(key) = NativeCache::key(request) else {
            return false;
        };
        let idx = self.cache.idx(key.as_slice());
        self.cache.shards[idx]
            .lock_recover()
            .put(key, Entry::LocalWire(wire));
        true
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    /// For other lanes, which look up only the cache.
    pub(crate) fn lane_response(&self, request: &Message) -> Option<Message> {
        let key = NormalizedRequestKey::from_request(request)?;
        let (rcode, answers, authorities, additionals, ad) =
            self.cache.get_by_key(key.as_slice())?;
        Some(cached_message(
            request,
            rcode,
            answers,
            authorities,
            additionals,
            ad,
        ))
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    /// For other lanes, which look up only remembered failures.
    pub(crate) fn lane_failure(&self, request: &Message) -> Option<Message> {
        let key = NormalizedRequestKey::from_request(request)?;
        let rcode = self.cache.failure_hit(key.as_slice())?;
        Some(cached_message(
            request,
            rcode,
            vec![],
            vec![],
            vec![],
            false,
        ))
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn lane_remember_failure(&self, epoch: CacheEpoch, request: &Message) {
        if let Some(key) = NormalizedRequestKey::from_request(request) {
            self.cache.remember_failure(epoch, key.into_owned());
        }
    }

    /// `epoch` is taken before the resolution that built `response` started.
    pub fn store(&self, epoch: CacheEpoch, request: &Message, response: &Message) {
        let Some(key) = NativeCache::key(request) else {
            return;
        };
        self.cache.put_by_key(
            epoch,
            &key,
            request,
            response.header.rcode,
            &response.answers,
            &response.authorities,
            &response.additionals,
            response.header.authentic_data,
            neg_soa_minimum(request, response),
        );
    }
}

impl Resolver for CacheLayer {
    fn resolve(&self, req: &Message) -> Option<Message> {
        match self.resolve_outcome(req) {
            ResolveOutcome::Response(response) => Some(response),
            ResolveOutcome::Failure(_) => None,
        }
    }

    /// Checks the cache, and on a miss sends one query upstream and shares the result: the leader
    /// goes out and the rest wait. With the flight table full, or when this thread already leads
    /// the same query, it goes upstream without coalescing, since waiting on itself would deadlock.
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        if req.questions.is_empty() {
            return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
        }
        let Some(request_key) = NormalizedRequestKey::from_request(req) else {
            return self.inner.resolve_outcome(req);
        };
        if self.positive_enabled {
            if let Some((rcode, answers, authorities, additionals, ad)) =
                self.cache.get_by_key(request_key.as_slice())
            {
                if let Some(recorder) = &self.recorder {
                    recorder.record_cache(true);
                    onetdns_forward::note_response_source("cache");
                }
                return ResolveOutcome::Response(cached_message(
                    req,
                    rcode,
                    answers,
                    authorities,
                    additionals,
                    ad,
                ));
            }
        }
        if let Some(rcode) = self.cache.failure_hit(request_key.as_slice()) {
            if let Some(recorder) = &self.recorder {
                recorder.record_cache(true);
                onetdns_forward::note_response_source("cache");
            }
            return ResolveOutcome::Response(cached_message(
                req,
                rcode,
                vec![],
                vec![],
                vec![],
                false,
            ));
        }

        let flight_key = request_key.into_owned();
        let acquired = {
            let mut flights = self.flights.lock_recover();
            if let Some(existing) = flights.get(&flight_key) {
                if existing.leader_thread == std::thread::current().id() {
                    None
                } else {
                    Some((existing.clone(), false))
                }
            } else if flights.len() >= MAX_CLIENT_FLIGHTS {
                None
            } else {
                let flight = Arc::new(ClientFlight::new());
                flights.insert(flight_key.clone(), flight.clone());
                Some((flight, true))
            }
        };
        let Some((flight, leader)) = acquired else {
            if let Some(recorder) = &self.recorder {
                recorder.record_cache(false);
            }
            return self.inner.resolve_outcome(req);
        };

        if !leader {
            return match flight.wait(CLIENT_FLIGHT_TIMEOUT) {
                Some(Ok(response)) => ResolveOutcome::Response(retarget_response(response, req)),
                Some(Err(failure)) => ResolveOutcome::Failure(failure),

                None => ResolveOutcome::Response(cached_message(
                    req,
                    ResponseCode::ServFail.0,
                    vec![],
                    vec![],
                    vec![],
                    false,
                )),
            };
        }

        let mut leader_guard = FlightLeaderGuard {
            key: flight_key.clone(),
            flight: flight.clone(),
            flights: &self.flights,
            finished: false,
        };

        let result = (|| {
            if self.positive_enabled {
                if let Some((rcode, answers, authorities, additionals, ad)) =
                    self.cache.get_by_key(flight_key.as_slice())
                {
                    if let Some(recorder) = &self.recorder {
                        recorder.record_cache(true);
                        onetdns_forward::note_response_source("cache");
                    }
                    return Ok(cached_message(
                        req,
                        rcode,
                        answers,
                        authorities,
                        additionals,
                        ad,
                    ));
                }
            }
            if let Some(rcode) = self.cache.failure_hit(flight_key.as_slice()) {
                if let Some(recorder) = &self.recorder {
                    recorder.record_cache(true);
                    onetdns_forward::note_response_source("cache");
                }
                return Ok(cached_message(req, rcode, vec![], vec![], vec![], false));
            }

            if let Some(recorder) = &self.recorder {
                recorder.record_cache(false);
            }

            let epoch = self.cache.epoch();
            let response = match self.inner.resolve_outcome(req) {
                ResolveOutcome::Response(response) => response,
                ResolveOutcome::Failure(failure) => {
                    self.cache.remember_failure(epoch, flight_key.clone());
                    return Err(failure);
                }
            };
            self.cache.forget_failure(flight_key.as_slice());
            let neg_min = neg_soa_minimum(req, &response);
            let negative = response.header.rcode == ResponseCode::NXDomain.0
                || (response.header.rcode == ResponseCode::NoError.0
                    && neg_min.is_some()
                    && !has_requested_answer(req, &response.answers));
            let mut response = response;
            if self.positive_enabled {
                self.cache.clamp_outgoing_ttls(&mut response, negative);
                self.cache.put_by_key(
                    epoch,
                    &flight_key,
                    req,
                    response.header.rcode,
                    &response.answers,
                    &response.authorities,
                    &response.additionals,
                    response.header.authentic_data,
                    neg_min,
                );
            }
            Ok(response)
        })();

        leader_guard.finish(result.clone());
        match result {
            Ok(response) => ResolveOutcome::Response(retarget_response(response, req)),
            Err(failure) => ResolveOutcome::Failure(failure),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::key::INLINE_REQUEST_KEY_CAPACITY;
    use super::*;
    use onetdns_proto::{Name, RData, Record, Soa};
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(target_pointer_width = "64")]
    #[test]
    /// A larger fixed cost means fewer entries fit in the same memory.
    fn cache_entry_fixed_overhead_stays_small() {
        assert_eq!(
            std::mem::size_of::<Entry>(),
            16,
            "Entry가 커졌습니다. 새 필드를 넣기 전에 기존 필드를 좁힐 수 있는지 확인하십시오"
        );
        assert_eq!(
            std::mem::size_of::<FlightKey>(),
            16,
            "불변 캐시 키가 Vec 크기로 넓어졌습니다"
        );
        assert_eq!(
            std::mem::size_of::<StructuredEntry>(),
            72,
            "구조화 캐시 payload가 불변 answers의 16B owner보다 넓어졌습니다"
        );
    }
    use std::sync::Barrier;

    fn rec(name: &str, ttl: u32) -> Record {
        Record::new(
            Name::from_str(name).unwrap(),
            ttl,
            RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        )
    }

    fn rrsig(name: &str, covered: RecordType, ttl: u32, lifetime: u32) -> Record {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let signature = onetdns_dnssec::Rrsig {
            type_covered: covered.0,
            algorithm: 13,
            labels: Name::from_str(name).unwrap().num_labels() as u8,
            original_ttl: ttl,
            expiration: now.wrapping_add(lifetime),
            inception: now.wrapping_sub(60),
            key_tag: 1,
            signer: Name::from_str("example.test").unwrap(),
            signature: vec![0; 64],
        };
        Record::new(
            Name::from_str(name).unwrap(),
            ttl,
            RData::Unknown(RecordType::RRSIG.0, signature.rdata_bytes()),
        )
    }

    fn soa(name: &str, ttl: u32, minimum: u32) -> Record {
        Record::new(
            Name::from_str(name).unwrap(),
            ttl,
            RData::soa(Soa {
                mname: Name::from_str("ns1.example.test").unwrap(),
                rname: Name::from_str("hostmaster.example.test").unwrap(),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 86400,
                minimum,
            }),
        )
    }

    #[test]
    fn positive_hit_decrements_ttl() {
        let c = NativeCache::new(1024, 16, 0, 86400, 0, 60);
        let name = Name::from_str("example.com").unwrap();
        let request = Message::query(1, name.clone(), RecordType::A);
        c.put(
            &request,
            0,
            &[rec("example.com", 100)],
            &[],
            &[],
            false,
            None,
        );
        let (rcode, answers, _, _, _) = c
            .get(&Message::query(1, name.clone(), RecordType::A))
            .expect("적중");
        assert_eq!(rcode, 0);
        assert_eq!(answers.len(), 1);
        assert!(answers[0].ttl <= 100 && answers[0].ttl >= 1);
    }

    #[test]
    /// Exceeding it would use more memory than configured.
    fn shard_count_and_total_entries_never_exceed_configured_capacity() {
        fn fill(cache: &NativeCache, count: usize) {
            for index in 0..count {
                let name = format!("entry-{index}.capacity.test");
                let request =
                    Message::query(index as u16, Name::from_str(&name).unwrap(), RecordType::A);
                cache.put(&request, 0, &[rec(&name, 300)], &[], &[], false, None);
            }
        }

        let tiny = NativeCache::new(3, 16, 0, 86400, 0, 60);
        assert_eq!(tiny.shards.len(), 2, "shards must shrink below capacity");
        fill(&tiny, 1_000);
        assert!(
            tiny.len() <= 3,
            "actual entries exceeded configured capacity"
        );

        let uneven = NativeCache::new(17, 16, 0, 86400, 0, 60);
        assert_eq!(uneven.shards.len(), 16);
        fill(&uneven, 2_000);
        assert!(
            uneven.len() <= 17,
            "remainder distribution exceeded capacity"
        );
    }

    #[test]
    fn negative_cached() {
        let c = NativeCache::new(1024, 16, 0, 86400, 0, 60);
        let name = Name::from_str("nx.test").unwrap();
        let authority = vec![soa("nx.test", 60, 60)];
        let request = Message::query(1, name.clone(), RecordType::A);
        c.put(&request, 3, &[], &authority, &[], false, Some(60));
        let (rcode, answers, authorities, _, _) = c
            .get(&Message::query(1, name.clone(), RecordType::A))
            .expect("음성 적중");
        assert_eq!(rcode, 3);
        assert!(answers.is_empty());
        assert_eq!(authorities.len(), 1, "음성 SOA 보존");
    }

    #[test]
    fn authenticated_cache_is_capped_by_rrsig_expiration() {
        let cache = NativeCache::new(16, 1, 60, 86_400, 0, 60);
        let request = Message::query(
            1,
            Name::from_str("www.example.test").unwrap(),
            RecordType::A,
        );
        let answer = rec("www.example.test", 3600);

        cache.put(
            &request,
            ResponseCode::NoError.0,
            std::slice::from_ref(&answer),
            &[],
            &[],
            true,
            None,
        );
        assert!(
            cache.get(&request).is_none(),
            "서명 증거 없는 AD 응답은 캐시하지 않음"
        );

        let signature = rrsig("www.example.test", RecordType::A, 3600, 5);
        cache.put(
            &request,
            ResponseCode::NoError.0,
            &[answer, signature],
            &[],
            &[],
            true,
            None,
        );
        let (_, answers, _, _, authentic) = cache.get(&request).expect("서명 AD 응답 캐시");
        assert!(authentic);
        assert!(
            answers.iter().all(|record| record.ttl <= 5),
            "min_ttl도 RRSIG 만료를 연장하면 안 됨: {answers:?}"
        );
    }

    #[test]
    /// Without AD, the operator's TTL floor still does not extend past the RRSIG lifetime.
    fn unauthenticated_signed_cache_is_capped_by_rrsig_expiration() {
        let cache = NativeCache::new(16, 1, 120, 86_400, 0, 60);
        let request = Message::query(
            1,
            Name::from_str("www.example.test").unwrap(),
            RecordType::A,
        );
        let answer = rec("www.example.test", 3600);
        let signature = rrsig("www.example.test", RecordType::A, 3600, 5);

        cache.put(
            &request,
            ResponseCode::NoError.0,
            &[answer, signature],
            &[],
            &[],
            false,
            None,
        );

        let (_, answers, _, _, authentic) = cache.get(&request).expect("AD=0 서명 응답 캐시");
        assert!(!authentic);
        assert!(
            answers.iter().all(|record| record.ttl <= 5),
            "min_ttl이 AD=0 RRSIG 수명을 연장하면 안 됨: {answers:?}"
        );
    }

    #[test]
    /// The covered RRset is not in the envelope, so what the signature covers cannot be bound.
    /// Without AD it is stored under the RRSIG's own caps; with AD it is not stored, so a trimmed
    /// response cannot set the lifetime.
    fn direct_rrsig_query_is_cacheable_only_when_not_authenticated() {
        let cache = NativeCache::new(16, 1, 120, 86_400, 0, 60);
        let request = Message::query(
            1,
            Name::from_str("www.example.test").unwrap(),
            RecordType::RRSIG,
        );
        let signature = rrsig("www.example.test", RecordType::A, 3600, 5);

        cache.put(
            &request,
            ResponseCode::NoError.0,
            &[signature.clone()],
            &[],
            &[],
            false,
            None,
        );

        let (_, answers, _, _, _) = cache.get(&request).expect("직접 RRSIG 응답 캐시");
        assert_eq!(answers.len(), 1);
        assert!(answers[0].ttl <= 5, "RRSIG 자체 수명 상한: {answers:?}");

        cache.clear();
        cache.put(
            &request,
            ResponseCode::NoError.0,
            &[signature],
            &[],
            &[],
            true,
            None,
        );
        assert!(
            cache.get(&request).is_none(),
            "AD=1은 covered RRset이 없으면 담지 않습니다"
        );
    }

    #[test]
    fn authenticated_cache_requires_matching_received_ttl_bounds() {
        let answer = rec("www.example.test", 3600);
        let mut signature = rrsig("www.example.test", RecordType::A, 3600, 3600);
        signature.ttl = 2;

        assert_eq!(
            dnssec_ttl_cap(&[answer, signature], &[], &[]),
            Some(2),
            "RFC 4035의 수신 RRSIG TTL도 인증 캐시 수명을 제한해야 함"
        );

        let short_answer = rec("www.example.test", 1);
        let signature = rrsig("www.example.test", RecordType::A, 3600, 3600);
        assert_eq!(
            dnssec_ttl_cap(&[short_answer, signature], &[], &[]),
            Some(1),
            "수신한 covered RRset TTL도 인증 캐시 수명을 제한해야 함"
        );

        let answer = rec("www.example.test", 3600);
        let orphan_signature = rrsig("attacker.test", RecordType::A, 3600, 3600);
        assert_eq!(
            dnssec_ttl_cap(&[answer, orphan_signature], &[], &[]),
            None,
            "무관한 RRSIG로 AD 응답 캐시 수명을 만들면 안 됨"
        );
    }

    #[test]
    fn stale_wire_promotion_cannot_replace_a_newer_structured_answer() {
        let native = Arc::new(NativeCache::new(16, 1, 0, 86_400, 0, 60));
        let handle = CacheHandle {
            cache: native.clone(),
        };
        let request = Message::query(
            1,
            Name::from_str("race.example.test").unwrap(),
            RecordType::A,
        );
        let old = Record::new(
            request.questions[0].name.clone(),
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        );
        native.put(
            &request,
            ResponseCode::NoError.0,
            std::slice::from_ref(&old),
            &[],
            &[],
            false,
            None,
        );
        let request_wire = request.try_encode().unwrap();
        let scanned = crate::wirecache::scan_query(&request_wire).unwrap();
        let now = Instant::now();
        let candidate = handle
            .wire_candidate(scanned.key(), now)
            .expect("기존 구조화 응답");

        let new = Record::new(
            request.questions[0].name.clone(),
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 2)),
        );
        native.put(
            &request,
            ResponseCode::NoError.0,
            std::slice::from_ref(&new),
            &[],
            &[],
            false,
            None,
        );
        let mut old_response = request.clone();
        old_response.header.response = true;
        old_response.header.recursion_available = true;
        old_response.answers.push(old);
        let factory = crate::wirecache::WireEntryFactory::new(0, 86_400);
        let wire = factory
            .prepare(
                &old_response.try_encode().unwrap(),
                0,
                String::new(),
                now,
                candidate.lifetime_secs(),
            )
            .unwrap();

        assert!(!handle.promote_wire(handle.epoch(), scanned.key(), &candidate, wire));
        let (_, answers, _, _, _) = native.get(&request).unwrap();
        assert_eq!(answers[0].rdata, new.rdata);
    }

    #[test]
    /// Splitting it into two caches would store everything twice.
    fn wire_lookup_uses_filter_generation_without_a_second_lru() {
        let native = Arc::new(NativeCache::new(16, 1, 0, 86_400, 0, 60));
        let handle = CacheHandle {
            cache: native.clone(),
        };
        let request = Message::query(
            1,
            Name::from_str("generation.example.test").unwrap(),
            RecordType::A,
        );
        let answer = Record::new(
            request.questions[0].name.clone(),
            5,
            RData::A(Ipv4Addr::new(192, 0, 2, 3)),
        );
        native.put(
            &request,
            ResponseCode::NoError.0,
            std::slice::from_ref(&answer),
            &[],
            &[],
            false,
            None,
        );
        let request_wire = request.try_encode().unwrap();
        let scanned = crate::wirecache::scan_query(&request_wire).unwrap();
        let now = Instant::now();
        let candidate = handle.wire_candidate(scanned.key(), now).unwrap();
        let mut response = request.clone();
        response.header.response = true;
        response.header.recursion_available = true;
        response.answers.push(answer);
        let wire = crate::wirecache::WireEntryFactory::new(0, 86_400)
            .prepare(
                &response.try_encode().unwrap(),
                7,
                String::new(),
                now,
                candidate.lifetime_secs(),
            )
            .unwrap();
        assert!(handle.promote_wire(handle.epoch(), scanned.key(), &candidate, wire));

        assert!(handle.wire_get(scanned.key(), 7, now).is_some());
        assert!(handle.wire_get(scanned.key(), 8, now).is_none());
        assert!(
            native.get(&request).is_some(),
            "필터 세대 미스는 일반 응답 항목을 버리면 안 됩니다"
        );
        assert!(handle
            .wire_get(scanned.key(), 7, now + Duration::from_secs(5))
            .is_none());
        assert!(
            native.get(&request).is_none(),
            "만료 항목은 단일 LRU에서 제거"
        );
    }

    #[test]
    #[ignore = "microbenchmark: run with --release -- --ignored --nocapture"]
    fn bench_structured_entry_hit() {
        /// Layout with spare `Vec` capacity, for comparison.
        struct LegacyStructuredEntry {
            answers: Vec<Record>,
            authorities: Box<[Record]>,
            additionals: Box<[Record]>,
            inserted: Instant,
            lifetime_secs: u32,
        }

        fn legacy_hit(entry: &Arc<LegacyStructuredEntry>, now: Instant) -> usize {
            let entry = Arc::clone(std::hint::black_box(entry));
            let elapsed = now.saturating_duration_since(entry.inserted).as_secs();
            if elapsed >= u64::from(entry.lifetime_secs) {
                return 0;
            }
            let mut answers = entry.answers.clone();
            let mut authorities = entry.authorities.to_vec();
            let mut additionals = entry.additionals.to_vec();
            age_records(&mut answers, elapsed);
            age_records(&mut authorities, elapsed);
            age_records(&mut additionals, elapsed);
            std::hint::black_box(
                answers.len() + authorities.len() + additionals.len() + answers[0].ttl as usize,
            )
        }

        fn packed_hit(entry: &Arc<StructuredEntry>, now: Instant) -> usize {
            let entry = Arc::clone(std::hint::black_box(entry));
            let elapsed = entry.elapsed_secs(now);
            if entry.is_expired_at(elapsed) {
                return 0;
            }
            let mut answers = entry.answers.to_vec();
            let mut authorities = entry.authorities.to_vec();
            let mut additionals = entry.additionals.to_vec();
            age_records(&mut answers, u64::from(elapsed));
            age_records(&mut authorities, u64::from(elapsed));
            age_records(&mut additionals, u64::from(elapsed));
            std::hint::black_box(
                answers.len() + authorities.len() + additionals.len() + answers[0].ttl as usize,
            )
        }

        fn measure(mut hit: impl FnMut() -> usize, iterations: usize) -> (f64, usize) {
            let started = Instant::now();
            let mut sink = 0usize;
            for _ in 0..iterations {
                sink = sink.wrapping_add(hit());
            }
            (
                started.elapsed().as_nanos() as f64 / iterations as f64,
                sink,
            )
        }

        let answer = rec("structured-bench.example", 300);
        let inserted = Instant::now();
        let now = inserted + Duration::from_secs(10);
        let legacy = Arc::new(LegacyStructuredEntry {
            answers: vec![answer.clone()],
            authorities: Box::new([]),
            additionals: Box::new([]),
            inserted,
            lifetime_secs: 300,
        });
        let packed = Arc::new(StructuredEntry {
            answers: Box::new([answer]),
            authorities: Box::new([]),
            additionals: Box::new([]),
            inserted,
            lifetime_secs: 300,
            rcode: 0,
            authentic: false,
        });

        for _ in 0..10_000 {
            std::hint::black_box(legacy_hit(&legacy, now));
            std::hint::black_box(packed_hit(&packed, now));
        }
        const ITERATIONS: usize = 500_000;
        let (old_1, sink_1) = measure(|| legacy_hit(&legacy, now), ITERATIONS);
        let (new_1, sink_2) = measure(|| packed_hit(&packed, now), ITERATIONS);
        let (new_2, sink_3) = measure(|| packed_hit(&packed, now), ITERATIONS);
        let (old_2, sink_4) = measure(|| legacy_hit(&legacy, now), ITERATIONS);
        println!(
            "structured hit: old={old_1:.1}/{old_2:.1}ns packed={new_1:.1}/{new_2:.1}ns sink={}",
            sink_1 ^ sink_2 ^ sink_3 ^ sink_4
        );
    }

    #[test]
    #[ignore = "microbenchmark: run with --release -- --ignored --nocapture"]
    fn bench_dnssec_ttl_cap_typical_response() {
        let mut records = Vec::with_capacity(8);
        for name in [
            "a.example.test",
            "b.example.test",
            "c.example.test",
            "d.example.test",
        ] {
            records.push(rec(name, 3600));
            records.push(rrsig(name, RecordType::A, 3600, 3600));
        }

        const CALLS: u32 = 1_000_000;
        let started = Instant::now();
        for _ in 0..CALLS {
            std::hint::black_box(dnssec_ttl_cap(&records, &[], &[]));
        }
        let elapsed = started.elapsed();
        println!(
            "dnssec-ttl-cap-8-records: {:.1} ns/call ({CALLS} calls in {elapsed:?})",
            elapsed.as_nanos() as f64 / f64::from(CALLS)
        );
    }

    #[test]
    fn servfail_not_cached() {
        let c = NativeCache::new(1024, 16, 0, 86400, 0, 60);
        let name = Name::from_str("sf.test").unwrap();
        let request = Message::query(1, name.clone(), RecordType::A);
        c.put(&request, 2, &[rec("sf.test", 100)], &[], &[], false, None);
        assert!(c
            .get(&Message::query(1, name.clone(), RecordType::A))
            .is_none());
    }

    struct AlwaysFails {
        calls: Arc<AtomicUsize>,
    }

    impl Resolver for AlwaysFails {
        fn resolve(&self, _request: &Message) -> Option<Message> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    struct SlowAnswer {
        calls: Arc<AtomicUsize>,
    }

    impl Resolver for SlowAnswer {
        fn resolve(&self, request: &Message) -> Option<Message> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(150));
            let question = request.questions.first()?.clone();
            let mut response = Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.header.recursion_available = true;
            response.questions = request.questions.clone();
            response.answers.push(Record::new(
                question.name,
                60,
                RData::A(Ipv4Addr::new(203, 0, 113, 10)),
            ));
            Some(response)
        }
    }

    /// Answers at once with TTLs far above any configured cap.
    struct LongTtlAnswer;

    impl Resolver for LongTtlAnswer {
        fn resolve(&self, request: &Message) -> Option<Message> {
            let question = request.questions.first()?.clone();
            let mut response = Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.header.recursion_available = true;
            response.questions = request.questions.clone();
            response.answers.push(Record::new(
                question.name.clone(),
                86_400,
                RData::A(Ipv4Addr::new(203, 0, 113, 10)),
            ));
            response.authorities.push(rec("ns.long.example", 86_400));
            response.additionals.push(rec("glue.long.example", 86_400));
            Some(response)
        }
    }

    /// Empty answer section that is not negative.
    struct ReferralAnswer;

    impl Resolver for ReferralAnswer {
        fn resolve(&self, request: &Message) -> Option<Message> {
            let zone = Name::from_str("example").unwrap();
            let nameserver = Name::from_str("ns1.example").unwrap();
            let mut response = Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.header.recursion_available = true;
            response.questions = request.questions.clone();
            response
                .authorities
                .push(Record::new(zone, 86_400, RData::Ns(nameserver.clone())));
            response.additionals.push(Record::new(
                nameserver,
                86_400,
                RData::A(Ipv4Addr::new(192, 0, 2, 53)),
            ));
            Some(response)
        }
    }

    /// NODATA after a CNAME, with the SOA that proves it.
    struct CnameNodataAnswer;

    impl Resolver for CnameNodataAnswer {
        fn resolve(&self, request: &Message) -> Option<Message> {
            let question = request.questions.first()?;
            let mut response = Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.header.recursion_available = true;
            response.questions = request.questions.clone();
            response.answers.push(Record::new(
                question.name.clone(),
                86_400,
                RData::Cname(Name::from_str("target.example").unwrap()),
            ));
            response.authorities.push(soa("example", 86_400, 86_400));
            Some(response)
        }
    }

    #[test]
    /// A miss sends the upstream response as is; capping only the stored copy would give the first
    /// client a longer TTL than later ones, and that client is often a downstream cache.
    fn cache_miss_response_is_capped_like_the_stored_copy() {
        let layer = CacheLayer::new(Arc::new(LongTtlAnswer), 128, 1, 0, 120, 0, 60);
        let request = Message::query(9, Name::from_str("long.example").unwrap(), RecordType::A);

        let miss = layer.resolve(&request).expect("첫 응답");
        assert!(
            miss.answers.iter().all(|record| record.ttl <= 120),
            "미스 응답의 answer 수명이 상한을 넘었습니다: {:?}",
            miss.answers.iter().map(|r| r.ttl).collect::<Vec<_>>()
        );
        assert!(
            miss.authorities
                .iter()
                .chain(miss.additionals.iter())
                .all(|record| record.ttl <= 120),
            "미스 응답의 authority/additional 수명이 상한을 넘었습니다"
        );

        let hit = layer.resolve(&request).expect("두 번째 응답");
        assert!(
            hit.answers.iter().all(|record| record.ttl <= 120),
            "히트 응답의 수명이 상한을 넘었습니다"
        );
    }

    #[test]
    fn referral_uses_positive_ttl_cap_instead_of_negative_cap() {
        let layer = CacheLayer::new(Arc::new(ReferralAnswer), 128, 1, 0, 120, 0, 5);
        let request = Message::query(
            10,
            Name::from_str("www.delegated.example").unwrap(),
            RecordType::A,
        );

        let response = layer.resolve(&request).expect("위임 응답");
        assert!(response.answers.is_empty());
        assert_eq!(response.authorities[0].rtype, RecordType::NS);
        assert_eq!(response.authorities[0].ttl, 120);
        assert_eq!(response.additionals[0].ttl, 120);
    }

    #[test]
    /// Chosen by negative meaning, not by whether the answer section is empty.
    fn cname_to_nodata_uses_negative_ttl_cap_for_proof() {
        let layer = CacheLayer::new(Arc::new(CnameNodataAnswer), 128, 1, 0, 120, 0, 5);
        let request = Message::query(11, Name::from_str("alias.example").unwrap(), RecordType::A);

        let response = layer.resolve(&request).expect("CNAME 뒤 NODATA 응답");
        assert_eq!(response.answers[0].rtype, RecordType::CNAME);
        assert_eq!(response.answers[0].ttl, 120);
        assert_eq!(response.authorities[0].rtype, RecordType::SOA);
        assert_eq!(response.authorities[0].ttl, 5);
    }

    #[test]
    fn concurrent_identical_client_queries_share_one_resolution() {
        let calls = Arc::new(AtomicUsize::new(0));
        let layer = Arc::new(
            CacheLayer::new(
                Arc::new(SlowAnswer {
                    calls: calls.clone(),
                }),
                128,
                1,
                0,
                86400,
                0,
                60,
            )
            .with_positive_cache(false),
        );
        let start = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();

        for id in [0x1001, 0x1002] {
            let layer = layer.clone();
            let start = start.clone();
            handles.push(std::thread::spawn(move || {
                let request =
                    Message::query(id, Name::from_str("shared.example").unwrap(), RecordType::A);
                start.wait();
                layer.resolve(&request).expect("shared response")
            }));
        }

        start.wait();
        let responses: Vec<Message> = handles
            .into_iter()
            .map(|handle| handle.join().expect("client worker"))
            .collect();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(responses[0].header.id, 0x1001);
        assert_eq!(responses[1].header.id, 0x1002);
        assert_eq!(responses[0].answers.len(), 1);
        assert_eq!(responses[1].answers.len(), 1);
    }

    #[test]
    /// Waiting on itself would deadlock.
    fn same_thread_leader_flight_is_bypassed_not_joined() {
        let calls = Arc::new(AtomicUsize::new(0));
        let layer = CacheLayer::new(
            Arc::new(SlowAnswer {
                calls: calls.clone(),
            }),
            128,
            1,
            0,
            86_400,
            0,
            60,
        )
        .with_positive_cache(false);

        let request = Message::query(7, Name::from_str("nest.example").unwrap(), RecordType::A);
        let key = FlightKey::from_request(&request).unwrap();

        let leader_flight = Arc::new(ClientFlight::new());
        layer
            .flights
            .lock_recover()
            .insert(key, leader_flight.clone());

        let response = layer.resolve(&request).expect("bypassed resolution");
        assert_eq!(response.answers.len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            leader_flight
                .waiters
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[test]
    fn oversized_or_malformed_cache_keys_bypass_cache_but_still_resolve() {
        let calls = Arc::new(AtomicUsize::new(0));
        let layer = CacheLayer::new(
            Arc::new(SlowAnswer {
                calls: calls.clone(),
            }),
            128,
            1,
            0,
            86_400,
            0,
            60,
        );
        let mut oversized =
            Message::query(1, Name::from_str("large.example").unwrap(), RecordType::A);
        oversized.additionals.push(Record::new(
            Name::root(),
            0,
            RData::Unknown(65_000, vec![0; MAX_CACHED_REQUEST_WIRE + 1]),
        ));
        assert!(layer.resolve(&oversized).is_some());
        assert_eq!(layer.cache.len(), 0);
        assert!(layer.flights.lock_recover().is_empty());

        let mut malformed =
            Message::query(2, Name::from_str("bad.example").unwrap(), RecordType::A);
        malformed.header.rcode = 0x1000;
        assert!(FlightKey::from_request(&malformed).is_none());
        assert!(layer.resolve(&malformed).is_some());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    /// Normalizing more would give one query another's answer.
    fn flight_key_normalizes_only_id_case_and_edns_padding() {
        let mut first = Message::query(1, Name::from_str("WWW.Example").unwrap(), RecordType::A);
        let mut first_edns = onetdns_proto::Edns {
            dnssec_ok: true,
            options: vec![(8, vec![0, 1, 24, 0, 192, 0, 2]), (12, vec![0; 16])],
            ..Default::default()
        };
        first.additionals.push(first_edns.try_to_record().unwrap());

        let mut same = Message::query(
            65_535,
            Name::from_str("www.EXAMPLE").unwrap(),
            RecordType::A,
        );
        first_edns.options.pop();
        same.additionals.push(first_edns.try_to_record().unwrap());
        assert_eq!(
            FlightKey::from_request(&first),
            FlightKey::from_request(&same)
        );

        let mut different_ecs = same.clone();
        different_ecs.additionals.clear();
        first_edns.options[0].1[6] = 3;
        different_ecs
            .additionals
            .push(first_edns.try_to_record().unwrap());
        assert_ne!(
            FlightKey::from_request(&same),
            FlightKey::from_request(&different_ecs)
        );

        let mut different_flags = same.clone();
        different_flags.header.checking_disabled = true;
        assert_ne!(
            FlightKey::from_request(&same),
            FlightKey::from_request(&different_flags)
        );
    }

    #[test]
    fn normalized_request_key_uses_inline_storage_and_borrowed_lookup() {
        let short = Message::query(1, Name::from_str("short.example").unwrap(), RecordType::A);
        let long_name = format!(
            "{}.{}.{}.example",
            "a".repeat(40),
            "b".repeat(40),
            "c".repeat(40)
        );
        let long = Message::query(2, Name::from_str(&long_name).unwrap(), RecordType::AAAA);

        let short_key = NormalizedRequestKey::from_request(&short).unwrap();
        assert!(matches!(&short_key, NormalizedRequestKey::Inline { .. }));
        let long_key = NormalizedRequestKey::from_request(&long).unwrap();
        assert!(long_key.as_slice().len() > INLINE_REQUEST_KEY_CAPACITY);
        assert!(matches!(&long_key, NormalizedRequestKey::Heap(_)));

        for (request, normalized) in [(&short, short_key), (&long, long_key)] {
            let owned = FlightKey::from_request(request).unwrap();
            assert_eq!(owned.as_slice(), normalized.as_slice());
            let mut map = HashMap::new();
            map.insert(owned, 7);
            assert_eq!(map.get(normalized.as_slice()), Some(&7));
        }
    }

    #[test]
    fn flight_key_rejects_multiple_or_malformed_opt() {
        let mut multiple = Message::query(1, Name::from_str("opt.example").unwrap(), RecordType::A);
        multiple
            .additionals
            .push(onetdns_proto::Edns::default().try_to_record().unwrap());
        multiple
            .additionals
            .push(onetdns_proto::Edns::default().try_to_record().unwrap());
        assert!(FlightKey::from_request(&multiple).is_none());

        let mut malformed =
            Message::query(2, Name::from_str("opt.example").unwrap(), RecordType::A);
        malformed.additionals.push(Record::new(
            Name::root(),
            0,
            RData::Unknown(RecordType::OPT.0, vec![0, 8, 0, 4, 1]),
        ));
        assert!(FlightKey::from_request(&malformed).is_none());
    }

    #[test]
    fn non_query_envelopes_bypass_cache_state() {
        let calls = Arc::new(AtomicUsize::new(0));
        let layer = CacheLayer::new(
            Arc::new(SlowAnswer {
                calls: calls.clone(),
            }),
            128,
            1,
            0,
            86_400,
            0,
            60,
        );
        let mut request = Message::query(
            1,
            Name::from_str("envelope.example").unwrap(),
            RecordType::A,
        );
        request.answers.push(rec("injected.example", 60));

        assert!(FlightKey::from_request(&request).is_none());
        assert!(layer.resolve(&request).is_some());
        assert!(layer.resolve(&request).is_some());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(layer.cache.len(), 0);
        assert!(layer.flights.lock_recover().is_empty());
    }

    #[test]
    fn client_singleflight_table_is_bounded_and_overflow_bypasses_it() {
        let calls = Arc::new(AtomicUsize::new(0));
        let layer = CacheLayer::new(
            Arc::new(SlowAnswer {
                calls: calls.clone(),
            }),
            128,
            1,
            0,
            86_400,
            0,
            60,
        )
        .with_positive_cache(false);
        {
            let mut flights = layer.flights.lock_recover();
            for index in 0..MAX_CLIENT_FLIGHTS {
                flights.insert(
                    FlightKey::from_normalized_bytes(Box::new(index.to_be_bytes())),
                    Arc::new(ClientFlight::new()),
                );
            }
        }

        let request = Message::query(
            7,
            Name::from_str("overflow.example").unwrap(),
            RecordType::A,
        );
        assert!(layer.resolve(&request).is_some());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(layer.flights.lock_recover().len(), MAX_CLIENT_FLIGHTS);
    }

    #[test]
    fn waiting_follower_is_woken_and_late_caller_sees_result() {
        let flight = Arc::new(ClientFlight::new());
        let follower_flight = flight.clone();

        let follower = std::thread::spawn(move || {
            follower_flight
                .wait(Duration::from_secs(5))
                .expect("리더 완료로 깨어나야")
                .expect("응답이 실려야")
                .header
                .id
        });

        std::thread::sleep(Duration::from_millis(150));
        let mut answer = Message::default();
        answer.header.id = 0x3131;
        flight.complete(Ok(answer));
        assert_eq!(follower.join().expect("팔로워 스레드"), 0x3131);
        assert_eq!(
            flight.waiters.load(Ordering::SeqCst),
            0,
            "깨어나 돌아간 대기자가 수에 남음"
        );

        let quiet = ClientFlight::new();
        let mut late = Message::default();
        late.header.id = 0x6161;
        quiet.complete(Ok(late));
        assert_eq!(quiet.waiters.load(Ordering::SeqCst), 0);
        assert_eq!(
            quiet
                .wait(Duration::from_millis(50))
                .expect("즉시 관측")
                .expect("응답")
                .header
                .id,
            0x6161
        );
    }

    #[test]
    /// Silence would leave the client waiting until its deadline.
    fn transient_failure_cache_returns_servfail_instead_of_silence() {
        let calls = Arc::new(AtomicUsize::new(0));
        let layer = CacheLayer::new(
            Arc::new(AlwaysFails {
                calls: calls.clone(),
            }),
            128,
            1,
            0,
            86400,
            0,
            60,
        )
        .with_positive_cache(false);
        let request = Message::query(7, Name::from_str("failure.test").unwrap(), RecordType::A);

        assert!(
            matches!(
                layer.resolve_outcome(&request),
                ResolveOutcome::Failure(ResolveFailure::Permanent(None))
            ),
            "실패 종류가 상위로 전달돼야 한다"
        );

        let second = layer.resolve(&request).expect("캐시된 SERVFAIL 응답");
        assert_eq!(second.header.rcode, ResponseCode::ServFail.0);
        assert_eq!(calls.load(Ordering::Relaxed), 1, "실패도 한 번만 조회한다");

        let mut checking_disabled = request.clone();
        checking_disabled.header.checking_disabled = true;
        assert!(
            matches!(
                layer.resolve_outcome(&checking_disabled),
                ResolveOutcome::Failure(_)
            ),
            "CD별로 실패 캐시가 분리된다"
        );
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    /// Stub zones go through this layer; capping to its own limit would make every stub zone answer
    /// a 1-second one that barely stays in downstream caches.
    fn failure_guard_keeps_successful_answer_ttls() {
        let layer = CacheLayer::failure_guard(Arc::new(LongTtlAnswer), 64);
        let request = Message::query(
            11,
            Name::from_str("stub.long.example").unwrap(),
            RecordType::A,
        );
        let response = layer.resolve(&request).expect("답");
        assert_eq!(response.answers[0].ttl, 86_400);
    }

    #[test]
    fn repeated_failures_increase_backoff_after_expiry() {
        let layer = CacheLayer::failure_guard(
            Arc::new(AlwaysFails {
                calls: Arc::new(AtomicUsize::new(0)),
            }),
            64,
        );
        let request = Message::query(
            9,
            Name::from_str("backoff.failure.test").unwrap(),
            RecordType::A,
        );
        let key = FlightKey::from_request(&request).unwrap();
        let cache = &layer.cache;

        cache.remember_failure(cache.epoch(), key.clone());
        {
            let mut failures = cache.failures.lock_recover();
            let entry = failures.get_mut(&key).unwrap();
            assert_eq!(entry.attempts, 1);
            entry.expiry = Instant::now() - Duration::from_secs(1);
        }
        assert_eq!(cache.failure_hit(key.as_slice()), None);

        cache.remember_failure(cache.epoch(), key.clone());
        let mut failures = cache.failures.lock_recover();
        let entry = failures.get_mut(&key).unwrap();
        assert_eq!(entry.attempts, 2);
        assert!(entry.expiry > Instant::now() + FAILURE_CACHE_BASE_TTL);
    }

    /// Holds the first query until released, and fails every query.
    struct HeldFailure {
        entered: Mutex<Option<std::sync::mpsc::Sender<()>>>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
        calls: AtomicUsize,
    }

    impl Resolver for HeldFailure {
        fn resolve(&self, _request: &Message) -> Option<Message> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let entered = self.entered.lock_recover().take();
            if let Some(entered) = entered {
                entered.send(()).unwrap();
                self.release.lock_recover().recv().unwrap();
            }
            None
        }
    }

    #[test]
    /// Remembering it would answer SERVFAIL for that name for the whole period after the clear;
    /// when the clear came from enabling a local-only category, a name meant to be answered without
    /// upstream would stay failed.
    fn a_failure_in_flight_across_a_clear_is_not_remembered() {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let upstream = Arc::new(HeldFailure {
            entered: Mutex::new(Some(entered_tx)),
            release: Mutex::new(release_rx),
            calls: AtomicUsize::new(0),
        });
        let layer = Arc::new(CacheLayer::new(upstream.clone(), 64, 1, 0, 86_400, 0, 60));
        let handle = layer.handle();
        let request = Message::query(
            3,
            Name::from_str("held.failure.test").unwrap(),
            RecordType::A,
        );
        let in_flight = {
            let layer = layer.clone();
            let request = request.clone();
            std::thread::spawn(move || layer.resolve(&request))
        };

        entered_rx.recv().unwrap();
        handle.clear();
        release_tx.send(()).unwrap();
        assert!(in_flight.join().unwrap().is_none());

        assert!(layer.resolve(&request).is_none());
        assert_eq!(
            upstream.calls.load(Ordering::SeqCst),
            2,
            "비운 뒤에 도착한 실패가 기억돼 다시 묻지 않았습니다"
        );
    }

    #[test]
    /// Prefetch and lanes store after resolving, and wire promotion happens after the response is
    /// sent; an answer stored after a clear in between was built from the old config. The promotion
    /// candidate may itself be new after the clear, so an unchanged candidate does not block it.
    fn writes_that_started_before_a_clear_do_not_land_after_it() {
        let native = Arc::new(NativeCache::new(16, 1, 0, 86_400, 0, 60));
        let handle = CacheHandle {
            cache: native.clone(),
        };
        let request = Message::query(
            1,
            Name::from_str("epoch.example.test").unwrap(),
            RecordType::A,
        );
        let mut stale = request.clone();
        stale.header.response = true;
        stale.header.recursion_available = true;
        stale.answers.push(Record::new(
            request.questions[0].name.clone(),
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ));

        let before = handle.epoch();
        handle.clear();

        handle.store(before, &request, &stale);
        assert!(
            native.get(&request).is_none(),
            "비우기 전에 시작한 답이 담겼습니다"
        );
        handle.lane_remember_failure(before, &request);
        assert!(
            handle.lane_failure(&request).is_none(),
            "비우기 전에 시작한 실패가 기억됐습니다"
        );

        let fresh = Record::new(
            request.questions[0].name.clone(),
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 2)),
        );
        handle.store(
            handle.epoch(),
            &request,
            &Message {
                answers: vec![fresh.clone()],
                ..stale.clone()
            },
        );
        let request_wire = request.try_encode().unwrap();
        let scanned = crate::wirecache::scan_query(&request_wire).unwrap();
        let now = Instant::now();
        let candidate = handle
            .wire_candidate(scanned.key(), now)
            .expect("비운 뒤에 담긴 답");
        let wire = crate::wirecache::WireEntryFactory::new(0, 86_400)
            .prepare(
                &stale.try_encode().unwrap(),
                0,
                String::new(),
                now,
                candidate.lifetime_secs(),
            )
            .unwrap();
        assert!(
            !handle.promote_wire(before, scanned.key(), &candidate, wire),
            "비우기 전에 만든 바이트가 비운 뒤의 답을 덮었습니다"
        );
        let (_, answers, _, _, _) = native.get(&request).unwrap();
        assert_eq!(answers[0].rdata, fresh.rdata);

        handle.lane_remember_failure(handle.epoch(), &request);
        assert!(
            handle.lane_failure(&request).is_some(),
            "지금 세대로 시작한 실패는 기억돼야 합니다"
        );
    }

    #[test]
    fn min_ttl_clamp() {
        let c = NativeCache::new(1024, 16, 60, 86400, 0, 60);
        let name = Name::from_str("x.test").unwrap();
        let request = Message::query(1, name.clone(), RecordType::A);
        c.put(&request, 0, &[rec("x.test", 5)], &[], &[], false, None);
        let (_, answers, _, _, _) = c
            .get(&Message::query(1, name.clone(), RecordType::A))
            .unwrap();
        assert!(answers[0].ttl > 5, "min_ttl 클램프로 5보다 커야");
    }

    #[test]
    fn zero_max_ttl_disables_positive_and_negative_storage() {
        let cache = NativeCache::new(16, 1, 0, 0, 0, 0);
        let positive = Message::query(1, Name::from_str("positive.test").unwrap(), RecordType::A);
        cache.put(
            &positive,
            ResponseCode::NoError.0,
            &[rec("positive.test", 300)],
            &[],
            &[],
            false,
            None,
        );
        assert!(
            cache.get(&positive).is_none(),
            "max_ttl=0은 긍정 캐시를 꺼야 함"
        );

        let negative_name = Name::from_str("negative.test").unwrap();
        let negative = Message::query(2, negative_name.clone(), RecordType::A);
        let authority = soa("negative.test", 300, 300);
        cache.put(
            &negative,
            ResponseCode::NXDomain.0,
            &[],
            &[authority],
            &[],
            false,
            Some(300),
        );
        assert!(
            cache.get(&negative).is_none(),
            "neg_max_ttl=0은 부정 캐시를 꺼야 함"
        );
    }

    #[test]
    /// Extending them together would keep expired glue alive.
    fn cached_sections_age_independently_without_extending_glue() {
        let c = NativeCache::new(16, 1, 0, 86400, 0, 60);
        let name = Name::from_str("answer.ttl.test").unwrap();
        let request = Message::query(1, name.clone(), RecordType::A);
        let glue = rec("ns.ttl.test", 1);
        c.put(
            &request,
            ResponseCode::NoError.0,
            &[rec("answer.ttl.test", 100)],
            &[],
            &[glue],
            false,
            None,
        );

        let key = NativeCache::key(&request).unwrap();
        let index = c.idx(key.as_slice());
        let mut shard = c.shards[index].lock_recover();
        let Entry::Structured(entry) = shard.get_mut(&key).unwrap() else {
            panic!("직접 삽입한 응답은 구조화 항목이어야 합니다");
        };
        let entry = Arc::get_mut(entry).unwrap();
        entry.inserted = Instant::now() - Duration::from_secs(2);
        drop(shard);

        let (_, answers, _, additionals, _) = c.get(&request).unwrap();
        assert_eq!(answers.len(), 1);
        assert!(answers[0].ttl <= 98);
        assert!(additionals.is_empty(), "만료된 glue를 연장해서는 안 됨");
    }

    #[test]
    fn max_ttl_caps_every_cached_response_section() {
        let cache = NativeCache::new(16, 1, 0, 5, 0, 5);
        let name = Name::from_str("answer.ttl.test").unwrap();
        let request = Message::query(1, name, RecordType::A);
        cache.put(
            &request,
            ResponseCode::NoError.0,
            &[rec("answer.ttl.test", 300)],
            &[rec("authority.ttl.test", 300)],
            &[rec("additional.ttl.test", 300)],
            false,
            None,
        );

        let (_, answers, authorities, additionals, _) = cache.get(&request).unwrap();
        assert!(answers.iter().all(|record| record.ttl <= 5));
        assert!(authorities.iter().all(|record| record.ttl <= 5));
        assert!(additionals.iter().all(|record| record.ttl <= 5));
    }

    #[test]
    /// The wire path builds the key from bytes without parsing, the structured cache from the
    /// parsed message. If they differ, promotion never finds the slot, so queries of that shape
    /// never take the lane and do the work twice.
    fn wire_and_structured_cache_keys_agree() {
        let name = Name::from_str("key.parity.test").unwrap();
        let mut cases: Vec<(&str, Message)> = Vec::new();

        cases.push(("평문", Message::query(1, name.clone(), RecordType::A)));

        let mut plain_edns = Message::query(2, name.clone(), RecordType::A);
        plain_edns
            .additionals
            .push(onetdns_proto::Edns::default().try_to_record().unwrap());
        cases.push(("옵션 없는 EDNS", plain_edns));

        let mut do_edns = Message::query(3, name.clone(), RecordType::AAAA);
        let mut edns = onetdns_proto::Edns::default();
        edns.dnssec_ok = true;
        do_edns.additionals.push(edns.try_to_record().unwrap());
        cases.push(("DO를 켠 EDNS", do_edns));

        let mut big = Message::query(4, name.clone(), RecordType::A);
        let mut edns = onetdns_proto::Edns::default();
        edns.udp_payload = 4096;
        big.additionals.push(edns.try_to_record().unwrap());
        cases.push(("다른 UDP 크기", big));

        let mut padded = Message::query(5, name, RecordType::A);
        let mut edns = onetdns_proto::Edns::default();
        edns.options.push((onetdns_proto::EDNS_PADDING, vec![0; 8]));
        padded.additionals.push(edns.try_to_record().unwrap());
        cases.push(("패딩만 담긴 EDNS", padded));

        for (label, request) in cases {
            let packet = request.try_encode().unwrap();
            let scanned = crate::wirecache::scan_query(&packet)
                .unwrap_or_else(|| panic!("{label}: 무할당 경로가 이 질의를 읽지 못했습니다"));
            let structured = FlightKey::from_request(&request)
                .unwrap_or_else(|| panic!("{label}: 구조화 키를 만들지 못했습니다"));
            assert_eq!(
                scanned.key(),
                structured.as_slice(),
                "{label}: 두 키가 다릅니다"
            );
        }
    }

    #[test]
    /// Tries every combination of the two header flag bytes, and every value of each byte of the
    /// OPT UDP size and TTL. If the wire path accepts a query with no structured key, it serves a
    /// stored answer to a query the normal path does not cache; if the keys differ, two queries
    /// share one answer.
    fn wire_scanner_accepts_only_what_the_structured_key_accepts() {
        let name = Name::from_str("Scan.Parity.test").unwrap();
        let plain = Message::query(1, name.clone(), RecordType::A)
            .try_encode()
            .unwrap();
        let mut padded = Message::query(2, name, RecordType::AAAA);
        let mut edns = onetdns_proto::Edns::default();
        edns.options.push((onetdns_proto::EDNS_PADDING, vec![0; 4]));
        padded.additionals.push(edns.try_to_record().unwrap());
        let padded = padded.try_encode().unwrap();
        // OPT is the last record: root name 1, type 2, UDP size 2, TTL 4, RDLENGTH 2, options 8.
        let opt = padded.len() - (1 + 2 + 2 + 4 + 2 + 8);
        assert_eq!(
            &padded[opt..opt + 3],
            &[0, 0, 41],
            "대조군이 무효입니다: OPT 위치"
        );

        let mut accepted = 0usize;
        let mut rejected = 0usize;
        let mut check = |packet: &[u8]| {
            let Some(scanned) = crate::wirecache::scan_query(packet) else {
                rejected += 1;
                return;
            };
            accepted += 1;
            let request = Message::parse(packet).unwrap_or_else(|error| {
                panic!("무할당 경로가 받은 질의를 파서가 거부합니다({error:?}): {packet:02x?}")
            });
            let structured = FlightKey::from_request(&request).unwrap_or_else(|| {
                panic!("무할당 경로가 받은 질의로 구조화 키를 만들지 못합니다: {packet:02x?}")
            });
            assert_eq!(
                scanned.key(),
                structured.as_slice(),
                "두 키가 다릅니다: {packet:02x?}"
            );
        };
        for base in [&plain, &padded] {
            for flags in 0..=u16::MAX {
                let mut packet = base.clone();
                packet[2..4].copy_from_slice(&flags.to_be_bytes());
                check(&packet);
            }
        }
        for offset in opt + 3..opt + 9 {
            for value in 0..=u8::MAX {
                let mut packet = padded.clone();
                packet[offset] = value;
                check(&packet);
            }
        }
        assert!(
            accepted > 0 && rejected > 0,
            "대조군이 무효입니다: 받은 질의 {accepted}개, 거부한 질의 {rejected}개"
        );
    }

    #[test]
    fn qtype_separated() {
        let c = NativeCache::new(1024, 16, 0, 86400, 0, 60);
        let name = Name::from_str("a.test").unwrap();
        let request = Message::query(1, name.clone(), RecordType::A);
        c.put(&request, 0, &[rec("a.test", 100)], &[], &[], false, None);
        assert!(c
            .get(&Message::query(1, name.clone(), RecordType::A))
            .is_some());
        assert!(
            c.get(&Message::query(1, name.clone(), RecordType::AAAA))
                .is_none(),
            "qtype 분리"
        );
    }

    #[test]
    fn negative_ttl_clamped_to_neg_min() {
        let c = NativeCache::new(1024, 16, 0, 86400, 30, 3600);
        let name = Name::from_str("nx2.test").unwrap();
        let authority = vec![soa("nx2.test", 5, 5)];
        let request = Message::query(1, name.clone(), RecordType::A);
        c.put(&request, 3, &[], &authority, &[], false, Some(5));

        assert!(
            c.get(&Message::query(1, name.clone(), RecordType::A))
                .is_some(),
            "음성 캐시됨(neg_min으로 TTL 상향)"
        );
    }

    #[test]
    fn cname_only_partial_answer_is_not_cached_as_address() {
        let c = NativeCache::new(1024, 16, 0, 86400, 0, 60);
        let name = Name::from_str("alias.test").unwrap();
        let cname = Record::new(
            name.clone(),
            300,
            RData::Cname(Name::from_str("target.test").unwrap()),
        );
        let request = Message::query(1, name.clone(), RecordType::A);
        c.put(
            &request,
            ResponseCode::NoError.0,
            &[cname],
            &[],
            &[],
            false,
            None,
        );
        assert!(c
            .get(&Message::query(1, name.clone(), RecordType::A))
            .is_none());
    }

    #[test]
    fn unrelated_rrset_cannot_make_lame_response_cacheable() {
        let c = NativeCache::new(16, 1, 0, 86400, 0, 60);
        let request = Message::query(1, Name::from_str("victim.example").unwrap(), RecordType::A);
        c.put(
            &request,
            ResponseCode::NoError.0,
            &[rec("attacker.example", 300)],
            &[],
            &[],
            false,
            None,
        );
        assert!(c.get(&request).is_none());
    }

    #[test]
    fn mismatched_class_cannot_complete_or_pollute_cache_entry() {
        let c = NativeCache::new(16, 1, 0, 86400, 0, 60);
        let request = Message::query(1, Name::from_str("victim.example").unwrap(), RecordType::A);
        let mut wrong_class = rec("victim.example", 300);
        wrong_class.class = onetdns_proto::DnsClass(3);
        c.put(
            &request,
            ResponseCode::NoError.0,
            &[wrong_class.clone()],
            &[],
            &[],
            false,
            None,
        );
        assert!(c.get(&request).is_none());

        c.put(
            &request,
            ResponseCode::NoError.0,
            &[rec("victim.example", 300), wrong_class.clone()],
            &[wrong_class.clone()],
            &[wrong_class],
            false,
            None,
        );
        let (_, answers, authorities, additionals, _) = c.get(&request).unwrap();
        assert_eq!(answers.len(), 1);
        assert!(answers
            .iter()
            .chain(&authorities)
            .chain(&additionals)
            .all(|record| record.class == onetdns_proto::DnsClass::IN));
    }

    #[test]
    fn unrelated_soa_cannot_prove_negative_answer() {
        let c = NativeCache::new(16, 1, 0, 86400, 0, 60);
        let request = Message::query(1, Name::from_str("victim.example").unwrap(), RecordType::A);
        c.put(
            &request,
            ResponseCode::NXDomain.0,
            &[],
            &[soa("attacker.example", 300, 300)],
            &[],
            false,
            Some(300),
        );
        assert!(c.get(&request).is_none());
    }

    #[test]
    fn nxdomain_with_terminal_positive_rrset_is_not_cached() {
        let c = NativeCache::new(16, 1, 0, 86400, 0, 60);
        let request = Message::query(1, Name::from_str("victim.example").unwrap(), RecordType::A);
        c.put(
            &request,
            ResponseCode::NXDomain.0,
            &[rec("victim.example", 300)],
            &[soa("example", 300, 300)],
            &[],
            false,
            Some(300),
        );
        assert!(c.get(&request).is_none());
    }

    #[test]
    fn cname_terminal_rrset_remains_cacheable() {
        let c = NativeCache::new(16, 1, 0, 86400, 0, 60);
        let request = Message::query(1, Name::from_str("alias.example").unwrap(), RecordType::A);
        let cname = Record::new(
            Name::from_str("alias.example").unwrap(),
            300,
            RData::Cname(Name::from_str("target.example").unwrap()),
        );
        c.put(
            &request,
            ResponseCode::NoError.0,
            &[cname, rec("target.example", 300)],
            &[],
            &[],
            false,
            None,
        );
        assert!(c.get(&request).is_some());
    }

    #[test]
    fn conflicting_alias_rrsets_are_never_cached() {
        let cache = NativeCache::new(16, 1, 0, 86_400, 0, 60);
        let owner = Name::from_str("alias.example").unwrap();
        let request = Message::query(1, owner.clone(), RecordType::A);
        let cname = Record::new(
            owner.clone(),
            300,
            RData::Cname(Name::from_str("target.example").unwrap()),
        );
        cache.put(
            &request,
            ResponseCode::NoError.0,
            &[cname.clone(), rec("alias.example", 300)],
            &[],
            &[],
            false,
            None,
        );
        assert!(cache.get(&request).is_none());

        let conflicting = Record::new(
            owner,
            300,
            RData::Cname(Name::from_str("other.example").unwrap()),
        );
        cache.put(
            &request,
            ResponseCode::NoError.0,
            &[cname, conflicting, rec("target.example", 300)],
            &[],
            &[],
            false,
            None,
        );
        assert!(cache.get(&request).is_none());
    }

    #[test]
    fn unproven_empty_noerror_is_not_cached() {
        let c = NativeCache::new(1024, 16, 0, 86400, 0, 60);
        let name = Name::from_str("lame.test").unwrap();
        let request = Message::query(1, name.clone(), RecordType::A);
        c.put(
            &request,
            ResponseCode::NoError.0,
            &[],
            &[],
            &[],
            false,
            None,
        );
        assert!(c
            .get(&Message::query(1, name.clone(), RecordType::A))
            .is_none());
    }
}
