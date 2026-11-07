//! Iterative recursive resolution: walks delegations down from the root and decides itself which
//! servers to trust. Bailiwick is the core safety property: a referral is followed only when it
//! moves toward the query name and stays inside the current zone; a looser check would let any
//! server hijack another zone. Referrals, CNAMEs, DNAMEs and side queries each have a budget, so
//! one query cannot hold this server indefinitely.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use onetdns_core::{IpNet, LruMap, MutexExt};
use onetdns_proto::{
    ede_code, DnsClass, Edns, Header, Message, Name, Question, RData, Record, RecordType,
    ResponseCode,
};

/// Reads the environment variable once.
fn recurse_trace_enabled() -> bool {
    static E: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *E.get_or_init(|| std::env::var_os("ONETDNS_RECURSE_TRACE").is_some())
}
/// Trace lines carry names from remote servers, so control characters are escaped.
fn escaped_trace(args: std::fmt::Arguments<'_>) -> String {
    let mut line = String::new();
    let _ = std::fmt::Write::write_fmt(&mut onetdns_core::log::Escaped(&mut line), args);
    line
}
macro_rules! rtrace {
    ($($arg:tt)*) => {
        if recurse_trace_enabled() {
            eprintln!("[recurse] {}", escaped_trace(format_args!($($arg)*)));
        }
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecurseError {
    NoRoots,

    NoResponse,

    /// Referral budget spent; possibly a delegation loop.
    TooManyReferrals,

    TooManyCnames,

    TooManyDnames,

    /// Side queries resolving name server addresses exceeded their budget.
    TooManyQueries,

    /// Every delegated server failed to answer or was lame; passed on to the client as is.
    NoReachableNs,

    /// DNSSEC validation failed; the answer must not go out.
    Bogus,
}

impl std::fmt::Display for RecurseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            RecurseError::NoRoots => "No root server hints",
            RecurseError::NoResponse => "The queried server did not respond",
            RecurseError::TooManyReferrals => "Followed too many delegations",
            RecurseError::TooManyQueries => "Query needs too many upstream queries",
            RecurseError::TooManyCnames => "Followed too many CNAMEs",
            RecurseError::TooManyDnames => "Followed too many DNAMEs",
            RecurseError::NoReachableNs => "No reachable name server",
            RecurseError::Bogus => "DNSSEC validation failed",
        };
        write!(f, "{s}")
    }
}

impl std::error::Error for RecurseError {}

thread_local! {

    /// Per query: whether the client asked to skip validation.
    static HONOR_CD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Thread-local so the CD state does not have to be threaded through every call.
fn honor_cd_active() -> bool {
    HONOR_CD.with(|h| h.get())
}

/// Restores the previous CD state on drop, also when nested.
struct HonorCdScope {
    previous: bool,
}

impl HonorCdScope {
    fn enter(honor: bool) -> Self {
        Self {
            previous: HONOR_CD.with(|state| state.replace(honor)),
        }
    }
}

impl Drop for HonorCdScope {
    fn drop(&mut self) {
        HONOR_CD.with(|state| state.set(self.previous));
    }
}

fn with_honor_cd<T>(honor: bool, f: impl FnOnce() -> T) -> T {
    let _scope = HonorCdScope::enter(honor);
    f()
}

/// Shared across threads; every cache sits behind a mutex held briefly on the query path.
pub struct Recursor {
    roots: Vec<SocketAddr>,
    /// Deadline for the whole resolution, not each round trip.
    timeout: Duration,

    /// Not 53 only in tests.
    port: u16,
    max_referrals: usize,
    max_cnames: usize,
    max_dnames: usize,

    /// Without it, one delegation chain can multiply queries.
    max_ns_resolves: usize,

    /// Swapped atomically, since automatic updates change it from outside.
    trust_anchors: std::sync::Arc<onetdns_core::ArcSwap<Vec<onetdns_dnssec::Ds>>>,

    /// Treats every validation failure as Bogus.
    strict: bool,

    /// Reports validation failures but still answers. Diagnostic only, not for production.
    permissive: bool,

    /// 0x20 encoding: mixed-case query names make spoofing harder.
    caps_for_id: bool,

    /// Asks authorities over TCP only. Whether UDP 53 is intercepted is a property of the host
    /// network, so the flag is shared with whatever detects it and survives a rebuild on reload.
    authority_tcp: std::sync::Arc<std::sync::atomic::AtomicBool>,

    /// Improves cache hits; cannot be combined with 0x20.
    lowercase_outgoing: bool,

    /// Always validates, ignoring the client's CD bit.
    ignore_cd: bool,

    deny_servers: Vec<IpNet>,

    /// When non-empty, only these ranges are queried.
    allow_servers: Vec<IpNet>,

    do_ip4: bool,
    do_ip6: bool,
    prefer_ip6: bool,
    prefer_ip4: bool,

    /// Lenient mode falls back to the full name for servers that do not cope with minimization.
    qname_min_strict: bool,

    /// Accepts only name servers the upstream zone handed down.
    harden_referral_path: bool,

    /// Only domains the operator lists explicitly.
    domain_insecure: Vec<Name>,

    /// Lets outsiders check which anchor is in use.
    root_key_sentinel: bool,

    /// Zones above it are not validated.
    nsec3_max_iterations: u16,

    recursive_cache_ttl_max: u32,

    /// Failure history per server and zone, which orders the servers to ask. Timeouts and lame
    /// answers concern whether the server serves that zone, so they are kept per zone.
    infra: std::sync::Mutex<LruMap<InfraKey, InfraStat>>,

    /// Smoothed RTT per address. RTT depends on the path, not the zone; measuring per zone would
    /// treat a server known to be slow in one zone as new in its parent and ask it first.
    rtt: std::sync::Mutex<LruMap<IpAddr, u32>>,

    /// Saves most side queries.
    ns_addr_cache: std::sync::Mutex<LruMap<Vec<u8>, NsAddrEntry>>,

    /// Saves walking down from the root again.
    deleg_cache: std::sync::Mutex<LruMap<Vec<u8>, DelegationEntry>>,

    dnskey_cache: std::sync::Mutex<LruMap<Vec<u8>, DnskeyEntry>>,
    /// Saves walking the whole chain each time.
    validated_keys: std::sync::Mutex<LruMap<Vec<u8>, ValidatedKeyEntry>>,

    /// Queries finishing in the background, so one is never run twice.
    background: std::sync::Mutex<HashSet<(Vec<u8>, RecordType)>>,
}

/// More unfinished queries than this means the authorities' network is jammed; more threads would
/// spend queries without filling the cache.
const MAX_BACKGROUND_COMPLETIONS: usize = 16;

/// No server answered, or the resolution hit its deadline; past the deadline the keys for
/// validation may be missing, which can also end in SERVFAIL.
fn unfinished(result: &Result<(Message, NsContext), RecurseError>, deadline: Instant) -> bool {
    match result {
        Err(RecurseError::NoResponse) => true,
        Err(_) => Instant::now() >= deadline,
        Ok((message, _)) => {
            message.header.rcode == ResponseCode::ServFail.0 && Instant::now() >= deadline
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// One address answers differently per zone, so both form the key.
struct InfraKey {
    ip: IpAddr,
    zone: Vec<u8>,
}

impl InfraKey {
    fn new(ip: IpAddr, zone: &Name) -> Self {
        Self {
            ip,
            zone: zone.canonical_key(),
        }
    }
}

#[derive(Default)]
struct InfraStat {
    /// For backing off briefly.
    last_fail: Option<Instant>,

    /// Transport failures since the last success, which clears the record. Failures arriving while
    /// the server is down are not counted, so queries sent just before it went down do not push the
    /// back-off straight to the maximum.
    consecutive_failures: u8,

    /// An answer came but could not be used.
    last_protocol_error: Option<Instant>,
}

impl InfraStat {
    fn cooling(&self, now: Instant) -> bool {
        self.failed_within(INFRA_FAIL_COOLDOWN, now)
    }

    /// After `SERVER_DOWN_AFTER_FAILURES` failures in a row the server is skipped for
    /// `SERVER_DOWN_BASE`. A failed retry afterwards doubles the period, up to `SERVER_DOWN_MAX`.
    fn down(&self, now: Instant) -> bool {
        let Some(extra) = self
            .consecutive_failures
            .checked_sub(SERVER_DOWN_AFTER_FAILURES)
        else {
            return false;
        };
        let period = SERVER_DOWN_BASE
            .saturating_mul(1 << u32::from(extra).min(16))
            .min(SERVER_DOWN_MAX);
        self.failed_within(period, now)
    }

    fn failed_within(&self, period: Duration, now: Instant) -> bool {
        self.last_fail
            .is_some_and(|failed_at| now.saturating_duration_since(failed_at) < period)
    }
}

/// So a new server is not pushed to the back.
const DEFAULT_RTT_MS: u32 = 50;

/// Wait for a new server before also asking the next. Most authorities answer over UDP within
/// this; shorter doubles queries to every new server, longer wastes that much on a silent one.
const UNKNOWN_SERVER_PATIENCE: Duration = Duration::from_millis(400);

/// Two suffice to wait on a slow server while asking the next. More would widen what a worker
/// keeps in flight, which DNSBomb-style attacks use to make answers arrive at once.
const MAX_EXCHANGES_PER_QUERY: usize = 2;

/// Even a near server can exceed three times its RTT from scheduling delay alone; this keeps that
/// from sending every query twice.
const MIN_SERVER_PATIENCE: Duration = Duration::from_millis(100);

/// Afterwards the server returns to its normal rank.
const INFRA_FAIL_COOLDOWN: Duration = Duration::from_secs(30);

/// One failure may be a lost packet and only lowers the rank. Several in a row mean the server is
/// unreachable on this path, like one refusing TCP; asking it would spend the full timeout on each
/// query and keep the bin from reaching `fallback_upstreams`.
const SERVER_DOWN_AFTER_FAILURES: u8 = 3;

/// Equals the minimum time the bin remembers a failed answer.
const SERVER_DOWN_BASE: Duration = Duration::from_secs(5);

/// RFC 9520 has resolution failures remembered with exponential back-off, but no longer than five
/// minutes; longer would notice a recovered server late.
const SERVER_DOWN_MAX: Duration = Duration::from_secs(300);

/// Lowers the rank a lot without excluding the server.
const INFRA_FAIL_PENALTY_MS: u64 = 100_000;
/// Lighter than a timeout.
const INFRA_PROTOCOL_PENALTY_MS: u64 = 10_000;

const MAX_INFRA: usize = 50_000;
const MAX_NS_CACHE_CONFIGURED: usize = 1_000_000;

#[derive(Clone, Copy)]
/// In monotonic process milliseconds, so a system clock change does not skew expiry.
struct TtlLifetime {
    expires_at_millis: u64,
}

impl TtlLifetime {
    fn new(ttl_secs: u32) -> Self {
        Self {
            expires_at_millis: cache_now_millis()
                .saturating_add(u64::from(ttl_secs).saturating_mul(1_000)),
        }
    }

    #[cfg(test)]
    fn remaining(self, now_millis: u64) -> Option<Duration> {
        let millis = self.expires_at_millis.checked_sub(now_millis)?;
        (millis > 0).then(|| Duration::from_millis(millis))
    }

    /// Rounds up, so an answer never goes out with TTL 0.
    fn remaining_secs(self, now_millis: u64) -> Option<u32> {
        let millis = self.expires_at_millis.checked_sub(now_millis)?;
        (millis > 0).then(|| millis.div_ceil(1_000).min(u64::from(u32::MAX)) as u32)
    }

    fn is_live(self, now_millis: u64) -> bool {
        self.expires_at_millis > now_millis
    }

    #[cfg(test)]
    /// For tests of the expiry path.
    fn expired() -> Self {
        Self {
            expires_at_millis: 0,
        }
    }
}

/// Monotonic, unaffected by system clock changes.
fn cache_now_millis() -> u64 {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    EPOCH
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

struct NsAddrEntry {
    addrs: Vec<IpAddr>,
    lifetime: TtlLifetime,
}

const NS_ADDR_CACHE_MAX: usize = 4_096;

/// Keeps an answer packed with addresses from filling the cache.
const MAX_CACHED_NS_ADDRS: usize = 64;

struct DelegationEntry {
    servers: Vec<SocketAddr>,
    lifetime: TtlLifetime,
}

const DELEGATION_CACHE_MAX: usize = 4_096;

/// Not yet validated.
struct DnskeyEntry {
    records: Vec<Record>,
    signatures: Vec<onetdns_dnssec::Rrsig>,
    lifetime: TtlLifetime,
}

const DNSKEY_CACHE_MAX: usize = 4_096;

/// Holds the anchors used; once they change the entry is stale.
struct ValidatedKeyEntry {
    trust: ZoneTrust,
    anchors: std::sync::Arc<Vec<onetdns_dnssec::Ds>>,
    lifetime: TtlLifetime,
}

#[derive(Clone)]
/// Also records that a zone is unsigned; otherwise such zones could not start from a cached
/// delegation and every query would walk from the root.
enum ZoneTrust {
    Secure(std::sync::Arc<[onetdns_dnssec::Dnskey]>),
    /// The parent proved the DS absent with signatures, so signatures here are not validated.
    Insecure,
}

const VALIDATED_KEY_CACHE_MAX: usize = 4_096;

/// The shortest of the chain's record TTLs and its signatures' remaining lifetimes: using a result
/// past signature expiry would keep trusting a revoked key. Expiry uses serial arithmetic; an
/// expired signature gives 0.
fn chain_validity_ttl(links: &[onetdns_dnssec::ChainLink], now: u32) -> u32 {
    let remaining = |expiration: u32| {
        let left = expiration.wrapping_sub(now);
        if left < 0x8000_0000 {
            left
        } else {
            0
        }
    };
    let mut ttl = u32::MAX;
    for link in links {
        for record in link
            .dnskeys
            .iter()
            .chain(&link.ds_records)
            .chain(&link.ds_nsec_records)
            .chain(&link.ds_nsec3_records)
        {
            ttl = ttl.min(record.ttl);
        }
        for signature in link
            .dnskey_rrsigs
            .iter()
            .chain(&link.ds_rrsigs)
            .chain(&link.ds_nsec_rrsigs)
            .chain(&link.ds_nsec3_rrsigs)
        {
            ttl = ttl.min(remaining(signature.expiration));
        }
    }
    if ttl == u32::MAX {
        0
    } else {
        ttl
    }
}

/// The zone sets the iteration count and the validator must hash that often, so without a cap one
/// query forces arbitrary hashing (CVE-2023-50868, CVE-2026-1519). NSEC3 records above it are left
/// out of proofs and do not authenticate a denial.
const DEFAULT_NSEC3_MAX_ITERATIONS: u16 = onetdns_dnssec::MAX_NSEC3_ITERATIONS;

/// Total outgoing queries one client query may cause: an absolute counter against delegation
/// chasing and NS address resolution feeding each other (NXNSAttack), like BIND's
/// max-recursion-queries. The normal worst case is about half of it. Unlike `ns_resolves` it is
/// never refunded, or it would stop being a limit.
const MAX_TOTAL_QUERIES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Insecure and Bogus must stay apart: an insecure zone is answered, a bogus one gets SERVFAIL.
enum SecurityStatus {
    Secure,

    Insecure,

    /// Carries the EDE code for the client. Covers a signature that does not verify and also
    /// missing keys that leave the zone neither validated nor proven unsigned; both block the
    /// answer, for different reasons.
    Bogus(u16),
}

impl SecurityStatus {
    /// The worse status wins: one broken RRset makes the whole answer untrustworthy.
    fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bogus(code), _) => Self::Bogus(code),
            (_, Self::Bogus(code)) => Self::Bogus(code),
            (Self::Insecure, _) | (_, Self::Insecure) => Self::Insecure,
            _ => Self::Secure,
        }
    }
}

/// Resources one client query may use, passed as `&mut` into nested resolutions such as glueless
/// NS lookups so the whole tree shares it; a fresh one per level would void the limits. `queries`
/// only decreases.
struct Budget {
    /// One per NS name resolved. Refunded when an attempt from a cached delegation fails, to avoid
    /// a false SERVFAIL, so it is not an absolute limit; `queries` is.
    ns_resolves: usize,
    /// Never refunded.
    queries: usize,
    /// Shared by nested resolutions.
    deadline: Instant,
}

struct IterationState {
    zone: Name,

    servers: Vec<SocketAddr>,

    /// Labels settled so far: how far minimization has got.
    depth: usize,

    /// Turned off, falling back to the full name, when a server rejects minimization.
    minimize: bool,

    /// Steps from the root, the material for the DNSSEC chain.
    chain: Vec<ZoneStep>,

    /// Name servers of the current zone whose addresses are not resolved yet. Resolution stops once
    /// one address is usable; more are resolved one at a time only when those all fail to answer.
    unresolved_ns: Vec<Name>,
}

struct NextQuery {
    target: usize,
    is_final: bool,
    /// Only a suffix while minimizing.
    mname: Name,
    /// NS while minimizing.
    mtype: RecordType,
}

struct IterationContext<'a> {
    qname: &'a Name,
    qtype: RecordType,
    total: usize,
    /// Always true: clients asking with DO=1 need signatures even when this server does not
    /// validate, and a validating stub behind it would get nothing to check otherwise. Signatures
    /// are kept and stripped on the way to clients without DO.
    do_bit: bool,
    /// Only for building the chain of trust; without validation the per-delegation copies are
    /// skipped.
    collect_ds: bool,
}

/// A referral paused on a glueless delegation until the name server addresses are resolved.
struct PendingReferral {
    zone: Name,
    resp: Message,
    ns_names: Vec<Name>,

    addrs: Vec<SocketAddr>,
    /// For caching.
    address_ttl: Option<u32>,
    /// DS and its denial proof fetched from the parent, only for cuts revealed in an answer
    /// section. A referral carries DS evidence in its authority section, an authoritative answer
    /// does not; without it a signed zone would drop to Insecure unproven.
    ds_evidence: Option<Vec<Record>>,
    /// Moved to the iteration state after descending.
    unresolved: Vec<Name>,
}

enum StepOutcome {
    Done(Message),

    Continue,

    NeedNsAddrs {
        missing: Vec<Name>,
        pending: Box<PendingReferral>,
    },

    /// A cut revealed in an answer section; ask the parent for the DS first. Only when validating.
    NeedDs {
        /// No glue, so their addresses are unknown.
        missing: Vec<Name>,
        pending: Box<PendingReferral>,
    },

    Failed(RecurseError),
}

impl IterationState {
    /// Also creates the chain's first step.
    fn start(zone: Name, servers: Vec<SocketAddr>) -> Self {
        let depth = zone.num_labels();
        let chain = vec![ZoneStep {
            zone: zone.clone(),
            servers: servers.clone(),
            ns_names: vec![],
            ds_records: vec![],
            ds_rrsigs: vec![],
            ds_nsec_records: vec![],
            ds_nsec_rrsigs: vec![],
            ds_nsec3_records: vec![],
            ds_nsec3_rrsigs: vec![],
            ds: vec![],
        }];
        Self {
            zone,
            servers,
            depth,
            minimize: true,
            chain,
            unresolved_ns: Vec::new(),
        }
    }

    /// While minimizing, asks NS with one more label each time; sending the full name at once would
    /// tell every server on the path what the client is after.
    fn next_query(&self, ctx: &IterationContext<'_>) -> NextQuery {
        let target = if self.minimize {
            (self.depth + 1).min(ctx.total)
        } else {
            ctx.total
        };
        let is_final = target >= ctx.total;
        NextQuery {
            target,
            is_final,
            mname: ctx.qname.suffix(target),
            mtype: if is_final { ctx.qtype } else { RecordType::NS },
        }
    }
}

/// One step of the chain: a zone and its delegation evidence.
struct ZoneStep {
    zone: Name,
    servers: Vec<SocketAddr>,

    ns_names: Vec<Name>,
    ds_records: Vec<Record>,
    ds_rrsigs: Vec<onetdns_dnssec::Rrsig>,
    /// DS absence proven with NSEC.
    ds_nsec_records: Vec<Record>,
    ds_nsec_rrsigs: Vec<onetdns_dnssec::Rrsig>,
    /// DS absence proven with NSEC3.
    ds_nsec3_records: Vec<Record>,
    ds_nsec3_rrsigs: Vec<onetdns_dnssec::Rrsig>,
    /// Parsed DS, the trust basis for the next step.
    ds: Vec<onetdns_dnssec::Ds>,
}

#[derive(Debug, Default, Clone)]
/// Name servers involved in this resolution, passed upward with the answer.
pub struct NsContext {
    pub names: Vec<Name>,
    pub ips: Vec<std::net::IpAddr>,
}

impl NsContext {
    /// Deduplicated names and addresses from the whole chain.
    fn from_chain(chain: &[ZoneStep]) -> Self {
        let mut names: Vec<Name> = Vec::new();
        let mut ips: Vec<std::net::IpAddr> = Vec::new();
        for step in chain {
            for n in &step.ns_names {
                if !names.iter().any(|x| x.eq_ignore_case(n)) {
                    names.push(n.clone());
                }
            }
            for s in &step.servers {
                let ip = s.ip();
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
        NsContext { names, ips }
    }
}

impl Recursor {
    /// Other settings come from the `with_` methods.
    pub fn new(roots: Vec<SocketAddr>, timeout: Duration) -> Self {
        Self {
            roots,
            timeout,
            port: 53,
            max_referrals: 16,
            max_cnames: 8,
            max_dnames: 8,

            max_ns_resolves: 64,
            trust_anchors: std::sync::Arc::new(onetdns_core::ArcSwap::new(std::sync::Arc::new(
                Vec::new(),
            ))),
            strict: false,
            permissive: false,
            caps_for_id: true,
            authority_tcp: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            lowercase_outgoing: false,
            ignore_cd: true,
            deny_servers: Vec::new(),
            allow_servers: Vec::new(),
            do_ip4: true,
            do_ip6: true,
            prefer_ip6: false,
            prefer_ip4: false,
            qname_min_strict: false,
            harden_referral_path: false,
            domain_insecure: Vec::new(),
            root_key_sentinel: true,
            nsec3_max_iterations: DEFAULT_NSEC3_MAX_ITERATIONS,
            recursive_cache_ttl_max: u32::MAX,
            infra: std::sync::Mutex::new(LruMap::new(MAX_INFRA)),
            rtt: std::sync::Mutex::new(LruMap::new(MAX_INFRA)),
            ns_addr_cache: std::sync::Mutex::new(LruMap::new(NS_ADDR_CACHE_MAX)),
            deleg_cache: std::sync::Mutex::new(LruMap::new(DELEGATION_CACHE_MAX)),
            dnskey_cache: std::sync::Mutex::new(LruMap::new(DNSKEY_CACHE_MAX)),
            validated_keys: std::sync::Mutex::new(LruMap::new(VALIDATED_KEY_CACHE_MAX)),
            background: std::sync::Mutex::new(HashSet::new()),
        }
    }

    /// The caller owns and flips the flag.
    pub fn with_authority_tcp(
        mut self,
        switch: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        self.authority_tcp = switch;
        self
    }

    pub fn authority_over_tcp(&self) -> bool {
        self.authority_tcp
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Never above the hard cap of 150.
    pub fn with_nsec3_max_iterations(mut self, max: u16) -> Self {
        self.nsec3_max_iterations = max.min(onetdns_dnssec::MAX_NSEC3_ITERATIONS);
        self
    }

    /// Resizes every cache; 0 keeps the defaults.
    pub fn with_ns_cache_max(mut self, max: usize) -> Self {
        if max > 0 {
            let max = max.min(MAX_NS_CACHE_CONFIGURED);
            self.infra = std::sync::Mutex::new(LruMap::new(max));
            self.rtt = std::sync::Mutex::new(LruMap::new(max));
            self.ns_addr_cache = std::sync::Mutex::new(LruMap::new(max));
            self.deleg_cache = std::sync::Mutex::new(LruMap::new(max));
            self.dnskey_cache = std::sync::Mutex::new(LruMap::new(max));
            self.validated_keys = std::sync::Mutex::new(LruMap::new(max));
        }
        self
    }

    pub fn with_recursive_cache_ttl_max(mut self, max: u32) -> Self {
        self.recursive_cache_ttl_max = max;
        self
    }

    pub fn with_ns_side_query_limit(mut self, limit: usize) -> Self {
        if limit > 0 {
            self.max_ns_resolves = limit;
        }
        self
    }

    pub fn with_root_key_sentinel(mut self, on: bool) -> Self {
        self.root_key_sentinel = on;
        self
    }

    /// Whether the answer or SERVFAIL comes back depends on the label and on whether this server
    /// trusts that tag, so clients learn the anchor state from the difference. Applied to validated
    /// answers only; an unvalidated one signals nothing.
    fn apply_sentinel(&self, qname: &Name, qtype: RecordType, out: &mut Message) {
        if !self.root_key_sentinel || !out.header.authentic_data {
            return;
        }
        if qtype != RecordType::A && qtype != RecordType::AAAA {
            return;
        }
        let Some(first) = qname.labels().first() else {
            return;
        };
        let Some(sentinel) = onetdns_dnssec::RootKeySentinel::parse(first) else {
            return;
        };
        if sentinel.fails(&self.trust_anchors.load()) {
            out.answers.clear();
            out.authorities.clear();
            out.additionals.clear();
            out.header.rcode = ResponseCode::ServFail.0;
            out.header.authentic_data = false;
        }
    }

    pub fn with_ip_family(mut self, do_ip4: bool, do_ip6: bool, prefer: Option<bool>) -> Self {
        self.do_ip4 = do_ip4;
        self.do_ip6 = do_ip6;
        match prefer {
            Some(true) => self.prefer_ip6 = true,
            Some(false) => self.prefer_ip4 = true,
            None => {}
        }
        self
    }

    pub fn with_qname_min_strict(mut self, strict: bool) -> Self {
        self.qname_min_strict = strict;
        self
    }

    /// The synchronous path and the reactor lane both call this; if only one did, the setting would
    /// do nothing where the lane is enabled.
    pub(crate) fn apply_outgoing_case(&self, query: &mut Message) {
        for question in &mut query.questions {
            if self.caps_for_id {
                question.name = randomize_name_case(&question.name);
            } else if self.lowercase_outgoing {
                question.name = lowercase_name(&question.name);
            }
        }
    }

    pub fn with_harden_referral_path(mut self, on: bool) -> Self {
        self.harden_referral_path = on;
        self
    }

    /// Only domains the operator lists explicitly.
    pub fn with_domain_insecure(mut self, domains: Vec<Name>) -> Self {
        self.domain_insecure = domains;
        self
    }

    fn is_domain_insecure(&self, name: &Name) -> bool {
        self.domain_insecure.iter().any(|d| is_within(name, d))
    }

    fn family_allowed(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => self.do_ip4,
            IpAddr::V6(_) => self.do_ip6,
        }
    }

    /// 0 for the preferred family; the first sort key.
    fn family_rank(&self, ip: IpAddr) -> u8 {
        let is_v6 = ip.is_ipv6();
        if self.prefer_ip6 && is_v6 || self.prefer_ip4 && !is_v6 {
            0
        } else {
            1
        }
    }

    pub fn with_default_roots(timeout: Duration) -> Self {
        Self::new(default_roots(), timeout)
    }

    /// For tests.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    #[cfg(test)]
    /// Allows loopback upstreams; test only, never enabled in production.
    fn with_test_loopback(mut self) -> Self {
        self.allow_servers.push("127.0.0.0/8".parse().unwrap());
        self.allow_servers.push("::1/128".parse().unwrap());
        self
    }

    /// Enables validation.
    pub fn with_trust_anchors(self, anchors: Vec<onetdns_dnssec::Ds>) -> Self {
        self.trust_anchors.store(std::sync::Arc::new(anchors));
        self
    }

    /// Automatic anchor updates swap anchors through this.
    pub fn anchors_handle(&self) -> std::sync::Arc<onetdns_core::ArcSwap<Vec<onetdns_dnssec::Ds>>> {
        self.trust_anchors.clone()
    }

    /// For anchor updates.
    pub fn fetch_zone_dnskey(&self, zone: &Name) -> Result<Vec<Record>, RecurseError> {
        let mut budget = Budget {
            ns_resolves: self.max_ns_resolves,
            queries: MAX_TOTAL_QUERIES,
            deadline: self.query_deadline(),
        };
        let (resp, _) = self.iterate(zone, RecordType::DNSKEY, &mut budget, self.validating())?;
        Ok(resp.answers)
    }

    pub fn with_dnssec_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Diagnostic only, not for production.
    pub fn with_dnssec_permissive(mut self, permissive: bool) -> Self {
        self.permissive = permissive;
        self
    }

    pub fn with_caps_for_id(mut self, on: bool) -> Self {
        self.caps_for_id = on;
        self
    }

    pub fn with_lowercase_outgoing(mut self, on: bool) -> Self {
        self.lowercase_outgoing = on;
        self
    }

    pub fn with_server_acl(mut self, deny: Vec<IpNet>, allow: Vec<IpNet>) -> Self {
        self.deny_servers = deny;
        self.allow_servers = allow;
        self
    }

    /// Checks the family and the address ranges.
    fn server_eligible(&self, ip: IpAddr) -> bool {
        self.family_allowed(ip) && self.is_queryable(ip)
    }

    /// The allow list first, then the deny list, then global routability. By default only global
    /// addresses: querying internal ones would let a crafted delegation use this server to probe
    /// the internal network (SSRF).
    fn is_queryable(&self, ip: IpAddr) -> bool {
        if self.allow_servers.iter().any(|n| n.contains(&ip)) {
            return true;
        }
        if self.deny_servers.iter().any(|n| n.contains(&ip)) {
            return false;
        }
        is_globally_routable(ip)
    }

    pub fn with_dnssec(self) -> Self {
        self.with_trust_anchors(onetdns_dnssec::root_trust_anchors())
    }

    /// 0 is ignored.
    pub fn with_recursion_limit(mut self, limit: u8) -> Self {
        if limit > 0 {
            self.max_referrals = limit as usize;
        }
        self
    }

    /// 0 is ignored.
    pub fn with_cname_limit(mut self, limit: u8) -> Self {
        if limit > 0 {
            self.max_cnames = limit as usize;
        }
        self
    }

    /// 0 is ignored.
    pub fn with_dname_limit(mut self, limit: u8) -> Self {
        if limit > 0 {
            self.max_dnames = limit as usize;
        }
        self
    }

    /// With anchors set and CD not honoured.
    fn validating(&self) -> bool {
        !self.trust_anchors.load().is_empty()
    }

    #[cfg(any(unix, test))]
    pub fn is_validating(&self) -> bool {
        self.validating()
    }

    /// Shared by nested resolutions.
    fn query_deadline(&self) -> Instant {
        let now = Instant::now();
        now.checked_add(self.timeout).unwrap_or(now)
    }

    pub fn resolve(&self, qname: &Name, qtype: RecordType) -> Result<Message, RecurseError> {
        self.resolve_collect(qname, qtype).map(|(m, _)| m)
    }

    pub fn with_ignore_cd(mut self, ignore: bool) -> Self {
        self.ignore_cd = ignore;
        self
    }

    /// Unfinished resolutions continue in the background (`complete_in_background`), filling this
    /// recursor's cache so the client's retry needs only the remaining steps.
    pub fn resolve_with_ns_cd(
        self: &std::sync::Arc<Self>,
        qname: &Name,
        qtype: RecordType,
        cd: bool,
    ) -> Result<(Message, NsContext), RecurseError> {
        let deadline = self.query_deadline();
        let result = self.resolve_once_cd(qname, qtype, cd);
        if unfinished(&result, deadline) {
            self.complete_in_background(qname.clone(), qtype, cd);
        }
        result
    }

    /// Does not continue in the background.
    fn resolve_once_cd(
        &self,
        qname: &Name,
        qtype: RecordType,
        cd: bool,
    ) -> Result<(Message, NsContext), RecurseError> {
        let honor = cd && !self.ignore_cd;
        with_honor_cd(honor, || self.resolve_collect(qname, qtype))
    }

    /// The result is dropped; only the cache is kept. A query runs at most once at a time, at most
    /// `MAX_BACKGROUND_COMPLETIONS` run together, and a failed background run is not handed on
    /// again.
    pub fn complete_in_background(
        self: &std::sync::Arc<Self>,
        qname: Name,
        qtype: RecordType,
        cd: bool,
    ) {
        let key = (qname.canonical_key(), qtype);
        {
            let mut running = self.background.lock_recover();
            if running.len() >= MAX_BACKGROUND_COMPLETIONS || !running.insert(key.clone()) {
                return;
            }
        }
        let this = std::sync::Arc::clone(self);
        let task_key = key.clone();
        let spawned = std::thread::Builder::new()
            .name("recurse-complete".into())
            .spawn(move || {
                rtrace!(
                    "Finishing an unfinished recursion in the background: name={}, type={:?}",
                    qname.to_ascii_lower(),
                    qtype
                );
                let _ = this.resolve_once_cd(&qname, qtype, cd);
                this.background.lock_recover().remove(&task_key);
            });
        if spawned.is_err() {
            self.background.lock_recover().remove(&key);
        }
    }

    pub fn resolve_with_ns(
        &self,
        qname: &Name,
        qtype: RecordType,
    ) -> Result<(Message, NsContext), RecurseError> {
        self.resolve_collect(qname, qtype)
    }

    /// Takes a fresh budget and collects the chain.
    fn resolve_collect(
        &self,
        qname: &Name,
        qtype: RecordType,
    ) -> Result<(Message, NsContext), RecurseError> {
        let (mut out, ns) = self.iterate_to_answer(qname, qtype)?;

        out.header.authoritative = false;
        Ok((out, ns))
    }

    /// Ends in one of three cases: a DNAME result exceeding the name length, no alias, or an alias
    /// to follow; each validates and cleans up differently. The AD bit must be cleared before
    /// anything goes out: passing on the upstream's bit would mark an unvalidated answer as
    /// validated.
    fn iterate_to_answer(
        &self,
        qname: &Name,
        qtype: RecordType,
    ) -> Result<(Message, NsContext), RecurseError> {
        if self.roots.is_empty() {
            return Err(RecurseError::NoRoots);
        }
        let mut budget = Budget {
            ns_resolves: self.max_ns_resolves,
            queries: MAX_TOTAL_QUERIES,
            deadline: self.query_deadline(),
        };
        rtrace!(
            "Starting recursion: name={}, type={:?}, dnssec={}",
            qname.to_ascii_lower(),
            qtype,
            self.validating()
        );
        let (resp, chain) = self.iterate(qname, qtype, &mut budget, self.validating())?;

        let ns = NsContext::from_chain(&chain);

        if is_dname_yxdomain(&resp, qname) {
            let mut out = resp;
            out.header.authentic_data = false;
            out.answers.retain(|record| {
                record.class == DnsClass::IN
                    && (matches!(record.rdata, RData::Dname(_))
                        || onetdns_dnssec::Rrsig::from_record(record)
                            .is_some_and(|sig| sig.type_covered == RecordType::DNAME.0))
            });
            out.authorities.clear();
            out.additionals.clear();
            out.header.response = true;
            out.header.recursion_available = true;
            return Ok((out, ns));
        }

        let alias = alias_hop(&resp, qname, qtype);
        rtrace!(
            "Finished recursion: rcode={}, answers={}, cname_response={}, cname_target={:?}, delegation_steps={}",
            resp.header.rcode,
            resp.answers.len(),
            alias.is_some(),
            alias.as_ref().map(|hop| hop.target.to_ascii_lower()),
            chain.len()
        );

        if alias.is_none() {
            let mut out = resp;

            out.header.authentic_data = false;
            let positive = out.header.rcode == ResponseCode::NoError.0
                && has_direct_qtype_answer(&out, qname, qtype);
            if self.validating() {
                if positive {
                    let status =
                        self.validate_answer_status(qname, qtype, &out, &chain, budget.deadline);
                    rtrace!(
                        "DNSSEC response validation: name={}, status={:?}",
                        qname.to_ascii_lower(),
                        status
                    );
                    match status {
                        SecurityStatus::Secure => out.header.authentic_data = true,

                        SecurityStatus::Bogus(code) if !self.permissive && !honor_cd_active() => {
                            rtrace!(
                                "DNSSEC validation failed; returning SERVFAIL: name={}",
                                qname.to_ascii_lower()
                            );
                            out = bogus_servfail(&out, code)
                        }

                        _ => {}
                    }
                } else {
                    let (status, proof) =
                        self.validate_denial_status(qname, qtype, &out, &chain, budget.deadline);
                    if !proof.is_empty() {
                        out.authorities = proof;
                    }
                    rtrace!(
                        "DNSSEC denial proof validation: name={}, status={:?}",
                        qname.to_ascii_lower(),
                        status
                    );
                    match status {
                        SecurityStatus::Secure => out.header.authentic_data = true,

                        SecurityStatus::Bogus(code) if !self.permissive && !honor_cd_active() => {
                            rtrace!(
                                "DNSSEC denial proof failed; returning SERVFAIL: name={}",
                                qname.to_ascii_lower()
                            );
                            out = bogus_servfail(&out, code)
                        }

                        _ => {}
                    }
                }
            }
            sanitize_terminal_response(
                &mut out,
                qname,
                qtype,
                positive,
                chain.last().map(|step| &step.zone),
            );
            self.apply_sentinel(qname, qtype, &mut out);
            out.header.response = true;
            out.header.recursion_available = true;
            return Ok((out, ns));
        }

        let AliasHop {
            target,
            owner: alias_owner,
            atype: alias_type,
            records: mut merged,
        } = alias.expect("Returned in the alias.is_none() branch");
        let (cname_depth, dname_depth) = if alias_type == RecordType::DNAME {
            (0, 1)
        } else {
            (1, 0)
        };
        let alias_status = if self.validating() {
            self.validate_answer_status(&alias_owner, alias_type, &resp, &chain, budget.deadline)
        } else {
            SecurityStatus::Insecure
        };
        let (mut tail, tail_status) =
            self.resolve_inner(&target, qtype, cname_depth, dname_depth, &mut budget, true)?;
        merged.append(&mut tail.answers);
        tail.answers = merged;
        tail.questions = resp.questions.clone();

        let mut out = tail;

        out.header.authentic_data = false;
        let status = alias_status.combine(tail_status);
        if self.validating() {
            match status {
                SecurityStatus::Secure => out.header.authentic_data = true,
                SecurityStatus::Bogus(code) if !self.permissive && !honor_cd_active() => {
                    out = bogus_servfail(&out, code)
                }
                _ => {}
            }
        }
        out.header.response = true;
        out.header.recursion_available = true;
        Ok((out, ns))
    }

    /// Inherits the chain depth so the budget carries on; restarting the count would void the limit
    /// for aliases that chain to aliases. With `validate` false it neither collects DS nor
    /// validates and returns Insecure; only name server address lookups, whose result decides
    /// nothing, turn it off.
    fn resolve_inner(
        &self,
        qname: &Name,
        qtype: RecordType,
        cname_depth: usize,
        dname_depth: usize,
        budget: &mut Budget,
        validate: bool,
    ) -> Result<(Message, SecurityStatus), RecurseError> {
        if cname_depth > self.max_cnames {
            return Err(RecurseError::TooManyCnames);
        }
        if dname_depth > self.max_dnames {
            return Err(RecurseError::TooManyDnames);
        }
        let validate = validate && self.validating();
        let (mut resp, chain) = self.iterate(qname, qtype, budget, validate)?;

        if let Some((dname_record, target, synthetic_cname)) = dname_rewrite(&resp, qname) {
            let dname_status = if validate {
                self.validate_answer_status(
                    &dname_record.name,
                    RecordType::DNAME,
                    &resp,
                    &chain,
                    budget.deadline,
                )
            } else {
                SecurityStatus::Insecure
            };
            let (mut tail, tail_status) = self.resolve_inner(
                &target,
                qtype,
                cname_depth,
                dname_depth + 1,
                budget,
                validate,
            )?;
            let mut merged = alias_rrset_records(&resp, &dname_record.name, RecordType::DNAME);
            merged.push(synthetic_cname);
            merged.append(&mut tail.answers);
            tail.answers = merged;
            tail.questions = resp.questions.clone();
            return Ok((tail, dname_status.combine(tail_status)));
        }

        if has_direct_qtype_answer(&resp, qname, qtype) {
            let status = if validate {
                self.validate_answer_status(qname, qtype, &resp, &chain, budget.deadline)
            } else {
                SecurityStatus::Insecure
            };
            sanitize_terminal_response(&mut resp, qname, qtype, true, None);
            return Ok((resp, status));
        }
        if resp.header.rcode == ResponseCode::NXDomain.0 {
            let status = if validate {
                let (status, proof) =
                    self.validate_denial_status(qname, qtype, &resp, &chain, budget.deadline);
                if !proof.is_empty() {
                    resp.authorities = proof;
                }
                status
            } else {
                SecurityStatus::Insecure
            };
            sanitize_terminal_response(
                &mut resp,
                qname,
                qtype,
                false,
                chain.last().map(|step| &step.zone),
            );
            return Ok((resp, status));
        }
        if let Some(target) = cname_target(&resp, qname) {
            let cname_status = if validate {
                self.validate_answer_status(
                    qname,
                    RecordType::CNAME,
                    &resp,
                    &chain,
                    budget.deadline,
                )
            } else {
                SecurityStatus::Insecure
            };
            let (mut tail, tail_status) = self.resolve_inner(
                &target,
                qtype,
                cname_depth + 1,
                dname_depth,
                budget,
                validate,
            )?;
            let mut merged = alias_rrset_records(&resp, qname, RecordType::CNAME);
            merged.append(&mut tail.answers);
            tail.answers = merged;
            tail.questions = resp.questions.clone();
            return Ok((tail, cname_status.combine(tail_status)));
        }

        let status = if validate {
            let (status, proof) =
                self.validate_denial_status(qname, qtype, &resp, &chain, budget.deadline);
            if !proof.is_empty() {
                resp.authorities = proof;
            }
            status
        } else {
            SecurityStatus::Insecure
        };
        sanitize_terminal_response(
            &mut resp,
            qname,
            qtype,
            false,
            chain.last().map(|step| &step.zone),
        );
        Ok((resp, status))
    }

    /// Settles what needs no keys first, then validates the chain for keys and checks the answer
    /// RRsets with them.
    fn validate_answer_status(
        &self,
        qname: &Name,
        qtype: RecordType,
        answer_msg: &Message,
        chain: &[ZoneStep],
        deadline: Instant,
    ) -> SecurityStatus {
        if let Some(status) = self.answer_status_without_keys(qname, qtype) {
            return status;
        }
        let keys = match self.validated_chain_keys(chain, deadline) {
            Ok(keys) => keys,
            Err(status) => return status,
        };
        self.validate_answer_with_keys(qname, qtype, answer_msg, chain, &keys)
    }

    /// A query for RRSIG itself is Insecure, since signatures are not signed.
    fn answer_status_without_keys(
        &self,
        qname: &Name,
        qtype: RecordType,
    ) -> Option<SecurityStatus> {
        if self.is_domain_insecure(qname) {
            return Some(SecurityStatus::Insecure);
        }

        if qtype == RecordType::RRSIG {
            return Some(SecurityStatus::Insecure);
        }
        None
    }

    /// Accepts only the leaf zone as signer. Fewer RRSIG labels than the name means wildcard
    /// expansion, which must also be proven; without that proof a more specific name could be
    /// hidden behind the wildcard.
    fn validate_answer_with_keys(
        &self,
        qname: &Name,
        qtype: RecordType,
        answer_msg: &Message,
        chain: &[ZoneStep],
        keys: &[onetdns_dnssec::Dnskey],
    ) -> SecurityStatus {
        let now = now_secs();
        let rrset: Vec<Record> = answer_msg
            .answers
            .iter()
            .filter(|r| r.class == DnsClass::IN && r.rtype == qtype && r.name.eq_ignore_case(qname))
            .cloned()
            .collect();
        if rrset.is_empty() {
            return SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS);
        }
        let answer_rrsigs = extract_rrsigs(&answer_msg.answers, qtype.0, qname);
        if answer_rrsigs.is_empty() {
            return SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS);
        }

        let Some(apex) = chain.last().map(|step| &step.zone) else {
            return SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS);
        };
        let mut verification_budget = onetdns_dnssec::VerificationBudget::new();
        if onetdns_dnssec::validate_rrset_in_zone_with_budget_and(
            &rrset,
            &answer_rrsigs,
            keys,
            apex,
            now,
            &mut verification_budget,
            |signature, budget| {
                let labels = usize::from(signature.labels);
                labels == qname.num_labels()
                    || validated_wildcard_expansion(
                        answer_msg,
                        qname,
                        labels,
                        WildcardValidation {
                            keys,
                            apex,
                            now,
                            nsec3_max_iterations: self.nsec3_max_iterations,
                            verification_budget: budget,
                        },
                    )
            },
        )
        .is_ok()
        {
            return SecurityStatus::Secure;
        }
        SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS)
    }

    /// Each step's DNSKEY is fetched from that zone; its DS comes from the child step, where the
    /// parent's referral recorded it.
    fn build_chain_links(
        &self,
        chain: &[ZoneStep],
        deadline: Instant,
    ) -> Result<Vec<onetdns_dnssec::ChainLink>, RecurseError> {
        let mut links = Vec::with_capacity(chain.len());
        for (i, step) in chain.iter().enumerate() {
            let (dnskeys, dnskey_rrsigs) =
                self.fetch_dnskey(&step.zone, &step.servers, deadline)?;
            let (
                ds_records,
                ds_rrsigs,
                ds_nsec_records,
                ds_nsec_rrsigs,
                ds_nsec3_records,
                ds_nsec3_rrsigs,
                ds,
            ) = if i + 1 < chain.len() {
                (
                    chain[i + 1].ds_records.clone(),
                    chain[i + 1].ds_rrsigs.clone(),
                    chain[i + 1].ds_nsec_records.clone(),
                    chain[i + 1].ds_nsec_rrsigs.clone(),
                    chain[i + 1].ds_nsec3_records.clone(),
                    chain[i + 1].ds_nsec3_rrsigs.clone(),
                    chain[i + 1].ds.clone(),
                )
            } else {
                (vec![], vec![], vec![], vec![], vec![], vec![], vec![])
            };
            links.push(onetdns_dnssec::ChainLink {
                zone: step.zone.clone(),
                dnskeys,
                dnskey_rrsigs,
                ds_records,
                ds_rrsigs,
                ds_nsec_records,
                ds_nsec_rrsigs,
                ds_nsec3_records,
                ds_nsec3_rrsigs,
                ds,
            });
        }
        Ok(links)
    }

    /// Such a chain is not validated.
    fn chain_has_excessive_nsec3(&self, links: &[onetdns_dnssec::ChainLink]) -> bool {
        links.iter().any(|link| {
            onetdns_dnssec::nsec3_max_iterations(&link.ds_nsec3_records) > self.nsec3_max_iterations
        })
    }

    /// Returns the status and, when validation holds, the authority records to keep; otherwise they
    /// are empty and the caller keeps the original answer.
    fn validate_denial_status(
        &self,
        qname: &Name,
        qtype: RecordType,
        out: &Message,
        chain: &[ZoneStep],
        deadline: Instant,
    ) -> (SecurityStatus, Vec<Record>) {
        if self.is_domain_insecure(qname) {
            return (SecurityStatus::Insecure, Vec::new());
        }
        let keys = match self.validated_chain_keys(chain, deadline) {
            Ok(keys) => keys,
            Err(status) => return (status, Vec::new()),
        };
        self.validate_denial_with_keys(qname, qtype, out, chain, &keys)
    }

    /// Validates the SOA first, which decides the zone the answer came from, then proves the denial
    /// with NSEC or NSEC3. The minimal syntactic proof is selected first and only those RRsets are
    /// validated; the other order would let an answer padded with unrelated signatures force
    /// public-key operations. Returns the status and the authority records to keep: the apex SOA,
    /// the proof actually validated, and their signatures. The caller overwrites the authority
    /// section with them so no unvalidated NSEC remains.
    fn validate_denial_with_keys(
        &self,
        qname: &Name,
        qtype: RecordType,
        out: &Message,
        chain: &[ZoneStep],
        keys: &[onetdns_dnssec::Dnskey],
    ) -> (SecurityStatus, Vec<Record>) {
        let now = now_secs();
        let Some(apex) = chain.last().map(|step| &step.zone) else {
            return (SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS), Vec::new());
        };

        let soa: Vec<Record> = out
            .authorities
            .iter()
            .filter(|record| {
                record.class == DnsClass::IN
                    && record.rtype == RecordType::SOA
                    && record.name.eq_ignore_case(apex)
            })
            .cloned()
            .collect();
        if soa.len() != 1 {
            return (SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS), Vec::new());
        }
        let mut verification_budget = onetdns_dnssec::VerificationBudget::new();
        let soa_sigs = extract_rrsigs(&out.authorities, RecordType::SOA.0, apex);
        if onetdns_dnssec::validate_rrset_in_zone_with_budget(
            &soa,
            &soa_sigs,
            keys,
            apex,
            now,
            &mut verification_budget,
        )
        .is_err()
        {
            return (SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS), Vec::new());
        }

        let denial_records = |rtype| {
            out.authorities
                .iter()
                .filter(|record| record.class == DnsClass::IN && record.rtype == rtype)
                .cloned()
                .collect::<Vec<_>>()
        };
        let nsec = denial_records(RecordType::NSEC);
        let nsec3 = denial_records(RecordType::NSEC3);
        let nsec3_allowed =
            onetdns_dnssec::nsec3_max_iterations(&nsec3) <= self.nsec3_max_iterations;
        // With NSEC3 alone and too many iterations, the proof could not be examined. RFC 9276 gives
        // this case its own code.
        let excessive_nsec3_only = !nsec3_allowed && nsec.is_empty() && !nsec3.is_empty();
        let denial_bogus = if excessive_nsec3_only {
            SecurityStatus::Bogus(ede_code::UNSUPPORTED_NSEC3_ITERATIONS)
        } else {
            SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS)
        };

        if out.header.rcode == ResponseCode::NXDomain.0 {
            if let Some(proof) = onetdns_dnssec::nsec_name_nonexistent_proof(&nsec, qname) {
                if validate_denial_proof(
                    &proof,
                    &out.authorities,
                    keys,
                    apex,
                    now,
                    &mut verification_budget,
                ) {
                    let records = validated_denial_records(&soa, &proof, &out.authorities);
                    return (SecurityStatus::Secure, records);
                }
            }
            if nsec3_allowed {
                if let Some((proof, relies_on_opt_out)) =
                    onetdns_dnssec::nsec3_name_nonexistent_proof_status(&nsec3, qname)
                {
                    if validate_denial_proof(
                        &proof,
                        &out.authorities,
                        keys,
                        apex,
                        now,
                        &mut verification_budget,
                    ) {
                        let status = if relies_on_opt_out {
                            SecurityStatus::Insecure
                        } else {
                            SecurityStatus::Secure
                        };
                        let records = validated_denial_records(&soa, &proof, &out.authorities);
                        return (status, records);
                    }
                }
            }
            return (SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS), Vec::new());
        }

        if let Some(proof) = onetdns_dnssec::nsec_nodata_proof(&nsec, qname, qtype.0) {
            if validate_denial_proof(
                &proof,
                &out.authorities,
                keys,
                apex,
                now,
                &mut verification_budget,
            ) {
                let records = validated_denial_records(&soa, &proof, &out.authorities);
                return (SecurityStatus::Secure, records);
            }
        }
        if nsec3_allowed {
            if let Some(proof) = onetdns_dnssec::nsec3_nodata_proof(&nsec3, qname, qtype.0) {
                if validate_denial_proof(
                    &proof,
                    &out.authorities,
                    keys,
                    apex,
                    now,
                    &mut verification_budget,
                ) {
                    let records = validated_denial_records(&soa, &proof, &out.authorities);
                    return (SecurityStatus::Secure, records);
                }
            }
        }
        (denial_bogus, Vec::new())
    }

    /// Asks the zone's servers directly; walking from the root again would add a full resolution to
    /// every chain validation.
    fn fetch_dnskey(
        &self,
        zone: &Name,
        servers: &[SocketAddr],
        deadline: Instant,
    ) -> Result<(Vec<Record>, Vec<onetdns_dnssec::Rrsig>), RecurseError> {
        let key = zone.canonical_key();
        if let Some(cached) = self.dnskey_cached(&key) {
            return Ok(cached);
        }
        let resp = self.query_any(
            servers,
            &make_query(zone, RecordType::DNSKEY, true),
            zone,
            deadline,
        )?;
        Ok(self.absorb_dnskey_response(zone, &resp))
    }

    /// Cached for the shorter of the record TTL and the signatures' remaining lifetime; keeping
    /// expired signatures would keep trusting a revoked key.
    fn absorb_dnskey_response(
        &self,
        zone: &Name,
        resp: &Message,
    ) -> (Vec<Record>, Vec<onetdns_dnssec::Rrsig>) {
        let key = zone.canonical_key();
        let keys: Vec<Record> = resp
            .answers
            .iter()
            .filter(|r| {
                r.class == DnsClass::IN
                    && r.rtype == RecordType::DNSKEY
                    && r.name.eq_ignore_case(zone)
            })
            .cloned()
            .collect();
        let sigs = extract_rrsigs(&resp.answers, RecordType::DNSKEY.0, zone);
        let ttl = resp
            .answers
            .iter()
            .filter(|record| {
                record.class == DnsClass::IN
                    && record.name.eq_ignore_case(zone)
                    && (record.rtype == RecordType::DNSKEY
                        || record.rtype == RecordType::RRSIG
                            && onetdns_dnssec::Rrsig::from_record(record).is_some_and(
                                |signature| signature.type_covered == RecordType::DNSKEY.0,
                            ))
            })
            .map(|record| record.ttl)
            .min();
        if !keys.is_empty() && !sigs.is_empty() {
            if let Some(ttl) = ttl {
                let now = now_secs();
                let signature_ttl = sigs
                    .iter()
                    .map(|signature| {
                        let remaining = signature.expiration.wrapping_sub(now);
                        if remaining < 0x8000_0000 {
                            remaining
                        } else {
                            0
                        }
                    })
                    .min()
                    .unwrap_or(0);
                self.dnskey_store(key, keys.clone(), sigs.clone(), ttl.min(signature_ttl));
            }
        }
        (keys, sigs)
    }

    /// Lowers the TTLs to the remaining time, or clients would cache longer than they may.
    fn dnskey_cached(&self, key: &[u8]) -> Option<(Vec<Record>, Vec<onetdns_dnssec::Rrsig>)> {
        let mut cache = self.dnskey_cache.lock_recover();
        let now = cache_now_millis();
        match cache.get(key) {
            Some(entry) if entry.lifetime.is_live(now) => {
                let remaining = entry
                    .lifetime
                    .remaining_secs(now)
                    .expect("A live TTL must have time remaining");
                let mut records = entry.records.clone();
                for record in &mut records {
                    record.ttl = record.ttl.min(remaining);
                }
                Some((records, entry.signatures.clone()))
            }
            Some(_) => {
                cache.pop(key);
                None
            }
            None => None,
        }
    }

    /// Not stored once the TTL reaches 0.
    fn dnskey_store(
        &self,
        key: Vec<u8>,
        records: Vec<Record>,
        signatures: Vec<onetdns_dnssec::Rrsig>,
        ttl_secs: u32,
    ) {
        let ttl = ttl_secs.min(self.recursive_cache_ttl_max);
        if ttl == 0 {
            return;
        }
        self.dnskey_cache.lock_recover().put(
            key,
            DnskeyEntry {
                records,
                signatures,
                lifetime: TtlLifetime::new(ttl),
            },
        );
    }

    /// Used only when the stored anchors are the same object as the current ones; after an anchor
    /// change, an old result would validate with keys no longer trusted.
    fn validated_keys_cached(
        &self,
        zone_key: &[u8],
        anchors: &std::sync::Arc<Vec<onetdns_dnssec::Ds>>,
    ) -> Option<ZoneTrust> {
        let mut cache = self.validated_keys.lock_recover();
        let now = cache_now_millis();
        match cache.get(zone_key) {
            Some(entry)
                if entry.lifetime.is_live(now)
                    && std::sync::Arc::ptr_eq(&entry.anchors, anchors) =>
            {
                Some(entry.trust.clone())
            }
            Some(_) => {
                cache.pop(zone_key);
                None
            }
            None => None,
        }
    }

    fn validated_keys_store(
        &self,
        zone_key: Vec<u8>,
        trust: ZoneTrust,
        anchors: std::sync::Arc<Vec<onetdns_dnssec::Ds>>,
        ttl_secs: u32,
    ) {
        let ttl = ttl_secs.min(self.recursive_cache_ttl_max);
        if ttl == 0 {
            return;
        }
        self.validated_keys.lock_recover().put(
            zone_key,
            ValidatedKeyEntry {
                trust,
                anchors,
                lifetime: TtlLifetime::new(ttl),
            },
        );
    }

    fn cached_chain_trust(&self, chain: &[ZoneStep]) -> Option<ZoneTrust> {
        let leaf = chain.last()?;
        let anchors = self.trust_anchors.load();
        self.validated_keys_cached(&leaf.zone.canonical_key(), &anchors)
    }

    #[cfg(unix)]
    /// Decides which zone's DNSKEY to fetch first.
    fn first_chain_zone_missing_dnskey(
        &self,
        chain: &[ZoneStep],
        skip: &[Vec<u8>],
    ) -> Option<(Name, Vec<SocketAddr>)> {
        chain
            .iter()
            .map(|step| (step.zone.canonical_key(), step))
            .find(|(key, _)| !skip.contains(key) && self.dnskey_cached(key).is_none())
            .map(|(_, step)| (step.zone.clone(), step.servers.clone()))
    }

    #[cfg(unix)]
    /// For the event-driven path, which cannot issue synchronous queries here: decides only when
    /// everything is cached. `None` means the caller must fetch the missing DNSKEY first.
    fn validate_terminal_without_fetch(
        &self,
        qname: &Name,
        qtype: RecordType,
        msg: &Message,
        chain: &[ZoneStep],
        positive: bool,
    ) -> Option<(SecurityStatus, Vec<Record>)> {
        if positive {
            if let Some(status) = self.answer_status_without_keys(qname, qtype) {
                return Some((status, Vec::new()));
            }
        } else if self.is_domain_insecure(qname) {
            return Some((SecurityStatus::Insecure, Vec::new()));
        }
        if self.cached_chain_trust(chain).is_none() {
            if !chain.first().is_some_and(|step| step.zone.is_root()) {
                return None;
            }
            if self.first_chain_zone_missing_dnskey(chain, &[]).is_some() {
                return None;
            }
        }

        let keys = match self.validated_chain_keys(chain, Instant::now()) {
            Ok(keys) => keys,
            Err(status) => return Some((status, Vec::new())),
        };
        Some(if positive {
            (
                self.validate_answer_with_keys(qname, qtype, msg, chain, &keys),
                Vec::new(),
            )
        } else {
            self.validate_denial_with_keys(qname, qtype, msg, chain, &keys)
        })
    }

    /// Always true without validation. With it, the zone's keys must already be established, since
    /// starting midway skips the chain above.
    fn validated_start_ok(&self, zone: &Name) -> bool {
        !self.validating() || {
            let anchors = self.trust_anchors.load();
            self.validated_keys_cached(&zone.canonical_key(), &anchors)
                .is_some()
        }
    }

    /// Uses the cache when it can, otherwise fetches every step's DNSKEY and validates from the
    /// anchor. A chain not starting at the root is Bogus: the delegations above it were never
    /// checked.
    fn validated_chain_keys(
        &self,
        chain: &[ZoneStep],
        deadline: Instant,
    ) -> Result<std::sync::Arc<[onetdns_dnssec::Dnskey]>, SecurityStatus> {
        match self.cached_chain_trust(chain) {
            Some(ZoneTrust::Secure(keys)) => return Ok(keys),
            Some(ZoneTrust::Insecure) => return Err(SecurityStatus::Insecure),
            None => {}
        }
        let Some(leaf) = chain.last() else {
            return Err(SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS));
        };
        let zone_key = leaf.zone.canonical_key();
        let anchors = self.trust_anchors.load();

        if !chain.first().is_some_and(|step| step.zone.is_root()) {
            return Err(SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS));
        }
        let links = match self.build_chain_links(chain, deadline) {
            Ok(l) => l,

            Err(error) => {
                onetdns_core::debug!(event = "dnssec.chain_build_failed", zone = %leaf.zone.to_ascii_lower(), error = ?error, "Could not fetch the keys for the chain of trust; answering SERVFAIL");
                // The chain fails to build only when a DNSKEY could not be fetched. Whether a
                // signature is broken is unknown, and claiming so would send operators looking at
                // the wrong zone.
                return Err(SecurityStatus::Bogus(match error {
                    RecurseError::NoResponse | RecurseError::NoReachableNs => {
                        ede_code::NO_REACHABLE_AUTHORITY
                    }
                    _ => ede_code::DNSSEC_BOGUS,
                }));
            }
        };
        if self.chain_has_excessive_nsec3(&links) {
            onetdns_core::debug!(event = "dnssec.chain_nsec3_excessive", zone = %leaf.zone.to_ascii_lower(), "NSEC3 iterations exceed the budget; treating as bogus");
            // RFC 9276: this server refused the computation, the signature is not broken. A
            // distinct code tells operators to fix the zone parameters.
            return Err(SecurityStatus::Bogus(
                ede_code::UNSUPPORTED_NSEC3_ITERATIONS,
            ));
        }
        let now = now_secs();
        let keys = match onetdns_dnssec::validate_chain_status_with_options(
            &anchors,
            &links,
            now,
            self.strict,
        ) {
            onetdns_dnssec::ChainStatus::Secure(keys) => keys,
            onetdns_dnssec::ChainStatus::Insecure => {
                self.validated_keys_store(
                    zone_key,
                    ZoneTrust::Insecure,
                    anchors,
                    chain_validity_ttl(&links, now),
                );
                return Err(SecurityStatus::Insecure);
            }
            onetdns_dnssec::ChainStatus::Bogus => {
                return Err(SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS))
            }
        };
        let keys: std::sync::Arc<[onetdns_dnssec::Dnskey]> = keys.into();
        self.validated_keys_store(
            zone_key,
            ZoneTrust::Secure(keys.clone()),
            anchors,
            chain_validity_ttl(&links, now),
        );
        Ok(keys)
    }

    /// Starting from the root every time multiplies queries, so a cached delegation is tried first;
    /// if that fails, the path is evicted and the walk restarts at the root. The side query budget
    /// is refunded for the retry, or a merely stale cache would end in SERVFAIL. With `validate`
    /// false it collects no DS and does not require validated keys for a cached start.
    fn iterate(
        &self,
        qname: &Name,
        qtype: RecordType,
        budget: &mut Budget,
        validate: bool,
    ) -> Result<(Message, Vec<ZoneStep>), RecurseError> {
        let validated_start_ok = |zone: &Name| !validate || self.validated_start_ok(zone);
        {
            if let Some((zone, servers)) = self
                .deepest_cached_delegation(qname)
                .filter(|(zone, _)| validated_start_ok(zone))
            {
                rtrace!(
                    "Starting {} from cached delegation {} ({} servers)",
                    zone.to_ascii_lower(),
                    servers.len(),
                    qname.to_ascii_lower()
                );
                let saved = budget.ns_resolves;
                match self.iterate_from(qname, qtype, budget, zone.clone(), servers, validate) {
                    Ok(v) if validated_start_ok(v.1.last().map_or(&zone, |s| &s.zone)) => {
                        return Ok(v)
                    }
                    Ok(_) => {
                        rtrace!("No cached validated key for the partial chain leaf; walking again from the root");
                        budget.ns_resolves = saved;
                    }
                    Err(e) => {
                        rtrace!(
                            "Query from cached delegation {} failed ({:?}); dropping that path and retrying from the root",
                            zone.to_ascii_lower(),
                            e
                        );
                        self.deleg_evict_path(qname);
                        budget.ns_resolves = saved;
                    }
                }
            }
        }
        self.iterate_from(
            qname,
            qtype,
            budget,
            Name::root(),
            self.roots.clone(),
            validate,
        )
    }

    /// One query per turn, then a step down, an address lookup, or the end. The turn count is
    /// capped, so a referral loop stops. Minimization needs the referral budget plus the label
    /// count in turns, so followed delegations are counted separately against the referral budget.
    fn iterate_from(
        &self,
        qname: &Name,
        qtype: RecordType,
        budget: &mut Budget,
        start_zone: Name,
        start_servers: Vec<SocketAddr>,
        validate: bool,
    ) -> Result<(Message, Vec<ZoneStep>), RecurseError> {
        let ctx = IterationContext {
            qname,
            qtype,
            total: qname.num_labels(),
            do_bit: true,
            collect_ds: validate,
        };
        let mut state = IterationState::start(start_zone, start_servers);
        let mut referrals = 0usize;

        for _ in 0..(self.max_referrals + ctx.total + 2) {
            let plan = state.next_query(&ctx);
            let zone_depth = state.zone.num_labels();

            if budget.queries == 0 {
                rtrace!(
                    "Used up the total outgoing query budget: name={}",
                    qname.to_ascii_lower()
                );
                return Err(RecurseError::TooManyQueries);
            }
            budget.queries -= 1;

            let resp = loop {
                let error = match self.query_any_reserving(
                    &state.servers,
                    &make_query(&plan.mname, plan.mtype, ctx.do_bit),
                    &state.zone,
                    budget.deadline,
                    state.unresolved_ns.len(),
                ) {
                    Ok(r) => break r,
                    Err(e) => e,
                };
                // No server of this zone answered; ask again with the addresses of the name servers
                // left unresolved.
                if budget.queries > 0 && self.resolve_more_ns_addrs(&mut state, budget) {
                    budget.queries -= 1;
                    continue;
                }
                rtrace!(
                    "Recursive query failed: name={}, type={:?}, final_step={}, error={:?}, nameservers={}, zone={}",
                    plan.mname.to_ascii_lower(),
                    plan.mtype,
                    plan.is_final,
                    error,
                    state.servers.len(),
                    state.zone.to_ascii_lower()
                );
                return Err(error);
            };

            let mut outcome = self.advance(&mut state, resp, &plan, &ctx);

            if let StepOutcome::NeedDs { missing, pending } = outcome {
                let mut pending = *pending;
                pending.ds_evidence = Some(self.fetch_ds_evidence(
                    &pending.zone,
                    &state.zone,
                    &state.servers,
                    budget,
                )?);
                outcome = self.descend(&mut state, &ctx, pending, missing);
            }
            if let StepOutcome::NeedNsAddrs { missing, pending } = outcome {
                let mut pending = *pending;
                match self.resolve_ns_addrs(&missing, budget) {
                    Ok((extra, side_ttl, rest)) => {
                        pending.addrs.extend(extra);
                        pending.address_ttl = min_optional_ttl(pending.address_ttl, side_ttl);
                        pending.unresolved = rest;
                        outcome = self.finish_referral(&mut state, &ctx, pending);
                    }
                    Err(e) => {
                        rtrace!(
                            "  nameserver address lookup failed for zone {}: {:?}",
                            e,
                            pending.zone.to_ascii_lower()
                        );
                        return Err(e);
                    }
                }
            }
            match outcome {
                StepOutcome::Done(resp) => return Ok((resp, state.chain)),
                StepOutcome::Failed(e) => return Err(e),
                StepOutcome::Continue => {
                    if state.zone.num_labels() > zone_depth {
                        referrals += 1;
                        if referrals > self.max_referrals {
                            break;
                        }
                    }
                }

                StepOutcome::NeedNsAddrs { .. } | StepOutcome::NeedDs { .. } => unreachable!(),
            }
        }
        rtrace!("Delegation limit exceeded: name={}", qname.to_ascii_lower());
        Err(RecurseError::TooManyReferrals)
    }

    /// The order makes this safe. At the final step the answer must be for the question sent, and
    /// an NXDOMAIN must come from a server authoritative for the name. A referral is followed only
    /// when it is closer than the current zone and contains the query name: the bailiwick check,
    /// without which any server could lead this one into another zone. An NXDOMAIN during
    /// minimization is retried with the full name, as some servers answer empty non-terminals that
    /// way. An empty authoritative answer without a delegation means the name is inside the current
    /// zone, as for an empty non-terminal; referral hardening stops only when the path is suspect.
    fn advance(
        &self,
        state: &mut IterationState,
        mut resp: Message,
        plan: &NextQuery,
        ctx: &IterationContext<'_>,
    ) -> StepOutcome {
        rtrace!(
            "Got recursive response: name={}, type={:?}, final_step={}, rcode={}, answers={}, authority={}, additional={}, nameservers={}, zone={}",
            plan.mname.to_ascii_lower(),
            plan.mtype,
            plan.is_final,
            resp.header.rcode,
            resp.answers.len(),
            resp.authorities.len(),
            resp.additionals.len(),
            state.servers.len(),
            state.zone.to_ascii_lower()
        );

        if plan.is_final {
            strip_out_of_bailiwick_dnames(&mut resp, &state.zone);
            if is_relevant_positive(&resp, ctx.qname, ctx.qtype) {
                rtrace!("Got final response: name={}", ctx.qname.to_ascii_lower());
                return StepOutcome::Done(resp);
            }
        }

        if is_dname_yxdomain(&resp, ctx.qname) {
            return StepOutcome::Done(resp);
        }

        if resp.header.rcode == ResponseCode::NXDomain.0 {
            if !is_authoritative_negative(&resp, &plan.mname, &state.zone) {
                rtrace!(
                    "Rejected an NXDOMAIN that is unrelated to the current zone or not authoritative: zone={}",
                    state.zone.to_ascii_lower()
                );
                return StepOutcome::Failed(RecurseError::NoReachableNs);
            }
            if plan.is_final {
                return StepOutcome::Done(resp);
            }

            if self.qname_min_strict {
                return StepOutcome::Done(resp);
            }
            rtrace!(
                "Got NXDOMAIN during QNAME minimization; querying the full name: name={}",
                plan.mname.to_ascii_lower()
            );
            state.minimize = false;
            return StepOutcome::Continue;
        }

        if let Some(ns_names) = answer_zone_cut(&resp, plan, &state.zone) {
            rtrace!(
                "Found a zone cut in an authoritative NS answer: zone={}",
                plan.mname.to_ascii_lower()
            );
            let (addrs, missing, address_ttl) = self.glue_addrs(&resp, &ns_names, &state.zone);
            let pending = PendingReferral {
                zone: plan.mname.clone(),
                resp,
                ns_names,
                addrs,
                address_ttl,
                ds_evidence: None,
                unresolved: Vec::new(),
            };
            if ctx.collect_ds {
                return StepOutcome::NeedDs {
                    missing,
                    pending: Box::new(pending),
                };
            }
            return self.descend(state, ctx, pending, missing);
        }

        let (referral_zone, ns_names) = extract_referral(&resp, ctx.qname);
        rtrace!(
            "Checked delegation: zone={:?}, ns_names={}, closer_than_current={}, contains_qname={}",
            referral_zone.as_ref().map(|z| z.to_ascii_lower()),
            ns_names.len(),
            referral_zone
                .as_ref()
                .map(|nz| is_closer(nz, &state.zone))
                .unwrap_or(false),
            referral_zone
                .as_ref()
                .map(|nz| is_within(ctx.qname, nz))
                .unwrap_or(false)
        );
        match referral_zone {
            Some(nz) if is_closer(&nz, &state.zone) && is_within(ctx.qname, &nz) => {
                let (addrs, missing_ns, address_ttl) =
                    self.glue_addrs(&resp, &ns_names, &state.zone);
                let pending = PendingReferral {
                    zone: nz,
                    resp,
                    ns_names,
                    addrs,
                    address_ttl,
                    ds_evidence: None,
                    unresolved: Vec::new(),
                };
                self.descend(state, ctx, pending, missing_ns)
            }
            rejected_referral => {
                if plan.is_final {
                    if is_terminal_response(&resp, ctx.qname, &state.zone) {
                        rtrace!(
                            "Got a final response with no answers: name={}",
                            ctx.qname.to_ascii_lower()
                        );
                        return StepOutcome::Done(resp);
                    }

                    rtrace!(
                        "Final response is unusable; treating as unreachable nameservers: name={}",
                        ctx.qname.to_ascii_lower()
                    );
                    return StepOutcome::Failed(RecurseError::NoReachableNs);
                }
                if self.harden_referral_path
                    && (rejected_referral.is_some() || !resp.header.authoritative)
                {
                    rtrace!("Found no safe delegation path; treating as unreachable nameservers");
                    return StepOutcome::Failed(RecurseError::NoReachableNs);
                }
                rtrace!(
                    "No usable delegation; reducing QNAME minimization depth: depth={}",
                    plan.target
                );
                state.depth = plan.target;
                StepOutcome::Continue
            }
        }
    }

    /// Resolves addresses first when every name server lacks one; `missing` are the names without
    /// glue.
    fn descend(
        &self,
        state: &mut IterationState,
        ctx: &IterationContext<'_>,
        mut pending: PendingReferral,
        missing: Vec<Name>,
    ) -> StepOutcome {
        // Descend as soon as the parent gave one address. Resolving the remaining names first would
        // turn each into a resolution from the root and exhaust the budget.
        if !missing.is_empty() && pending.addrs.is_empty() {
            rtrace!(
                "Looking up addresses of nameservers without glue: need_address={}, have_address={}",
                missing.len(),
                pending.addrs.len()
            );

            return StepOutcome::NeedNsAddrs {
                missing,
                pending: Box::new(pending),
            };
        }
        if !missing.is_empty() {
            rtrace!(
                "Leaving {} glueless nameservers and descending with the {} addresses already known",
                missing.len(),
                pending.addrs.len()
            );
            pending.unresolved = missing;
        }
        self.finish_referral(state, ctx, pending)
    }

    /// The same server may serve the child zone, but DS is parent data, so it answers from the
    /// parent side. The chain validates the evidence by signature, as for a referral's authority
    /// section. Returns the answer and authority records as the step's DS evidence.
    fn fetch_ds_evidence(
        &self,
        zone: &Name,
        parent: &Name,
        servers: &[SocketAddr],
        budget: &mut Budget,
    ) -> Result<Vec<Record>, RecurseError> {
        if budget.queries == 0 {
            return Err(RecurseError::TooManyQueries);
        }
        budget.queries -= 1;
        let resp = self.query_any(
            servers,
            &make_query(zone, RecordType::DS, true),
            parent,
            budget.deadline,
        )?;
        Ok(resp.answers.into_iter().chain(resp.authorities).collect())
    }

    /// Sorts, deduplicates and caps the addresses; otherwise one delegation packed with addresses
    /// inflates both the cache and the attempts. Fails when no address is usable.
    fn finish_referral(
        &self,
        state: &mut IterationState,
        ctx: &IterationContext<'_>,
        pending: PendingReferral,
    ) -> StepOutcome {
        let PendingReferral {
            zone: nz,
            resp,
            ns_names,
            mut addrs,
            address_ttl,
            ds_evidence,
            unresolved,
        } = pending;
        addrs.sort_unstable();
        addrs.dedup();
        addrs.truncate(MAX_CACHED_NS_ADDRS);
        if addrs.is_empty() {
            rtrace!("  no reachable nameserver for {}", nz.to_ascii_lower());
            return StepOutcome::Failed(RecurseError::NoReachableNs);
        }
        rtrace!(
            "  following delegation {} ({} nameserver addresses)",
            nz.to_ascii_lower(),
            addrs.len()
        );
        state.servers = addrs;

        if let Some(ttl) = min_ns_ttl(&resp, &nz) {
            self.deleg_store(&nz, &state.servers, address_ttl.map_or(ttl, |a| a.min(ttl)));
        }

        let (
            ds_records,
            ds_rrsigs,
            ds_nsec_records,
            ds_nsec_rrsigs,
            ds_nsec3_records,
            ds_nsec3_rrsigs,
            ds,
        ) = if ctx.collect_ds {
            extract_ds(ds_evidence.as_deref().unwrap_or(&resp.authorities), &nz)
        } else {
            (vec![], vec![], vec![], vec![], vec![], vec![], vec![])
        };
        state.chain.push(ZoneStep {
            zone: nz.clone(),
            servers: state.servers.clone(),
            ns_names,
            ds_records,
            ds_rrsigs,
            ds_nsec_records,
            ds_nsec_rrsigs,
            ds_nsec3_records,
            ds_nsec3_rrsigs,
            ds,
        });
        state.depth = nz.num_labels();
        state.zone = nz;
        state.unresolved_ns = unresolved;
        StepOutcome::Continue
    }

    /// Glue comes from the parent and deserves less trust than child data, so only glue for names
    /// inside the current zone is accepted; out-of-bailiwick glue would let one delegation plant
    /// any address for any name. Returns the addresses, the names without one, and the minimum TTL.
    fn glue_addrs(
        &self,
        resp: &Message,
        ns_names: &[Name],
        zone: &Name,
    ) -> (Vec<SocketAddr>, Vec<Name>, Option<u32>) {
        let mut out = Vec::new();
        let mut covered = Vec::<Name>::new();
        let mut min_ttl = None;
        for r in &resp.additionals {
            if r.class != DnsClass::IN {
                continue;
            }
            let Some(ns_name) = ns_names.iter().find(|n| n.eq_ignore_case(&r.name)) else {
                continue;
            };
            if !is_within(&r.name, zone) {
                continue;
            }
            let addr = match &r.rdata {
                RData::A(ip) => Some(SocketAddr::new(IpAddr::V4(*ip), self.port)),
                RData::Aaaa(ip) => Some(SocketAddr::new(IpAddr::V6(*ip), self.port)),
                _ => None,
            };
            if let Some(addr) =
                addr.filter(|addr| self.family_allowed(addr.ip()) && self.is_queryable(addr.ip()))
            {
                out.push(addr);
                min_ttl = min_optional_ttl(min_ttl, Some(r.ttl));
                if !covered.iter().any(|name| name.eq_ignore_case(ns_name)) {
                    covered.push(ns_name.clone());
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        let missing = ns_names
            .iter()
            .filter(|name| !covered.iter().any(|covered| covered.eq_ignore_case(name)))
            .cloned()
            .collect();
        (out, missing, min_ttl)
    }

    /// Resolves in order and stops once an address is usable; the rest is returned and resolved
    /// only when those addresses all fail to answer. Resolving every name would let one slow server
    /// take the remaining time. The side resolution shares the budget and deadline, or one
    /// delegation chain would multiply queries. It is not validated: the address only picks a
    /// destination, and a forged one leads to a server whose answers validation rejects. Returns
    /// the addresses, their minimum TTL, and the names left.
    fn resolve_ns_addrs(
        &self,
        ns_names: &[Name],
        budget: &mut Budget,
    ) -> Result<(Vec<SocketAddr>, Option<u32>, Vec<Name>), RecurseError> {
        let mut all: Vec<SocketAddr> = Vec::new();
        let mut all_ttl = None;
        let mut rest = ns_names.iter();
        let ask_aaaa = self.do_ip6 && ipv6_route_available();
        for ns in rest.by_ref() {
            let key = ns.canonical_key();

            if let Some((addrs, ttl)) = self.ns_addr_cached_with_ttl(&key) {
                all.extend(addrs.into_iter().map(|ip| SocketAddr::new(ip, self.port)));
                all_ttl = min_optional_ttl(all_ttl, Some(ttl));
            } else {
                if budget.ns_resolves == 0 {
                    break;
                }
                budget.ns_resolves -= 1;
                let mut resolved: Vec<IpAddr> = Vec::new();
                let mut min_ttl = u32::MAX;
                let families = [(self.do_ip4, RecordType::A), (ask_aaaa, RecordType::AAAA)];
                for (wanted, rtype) in families {
                    if !wanted {
                        continue;
                    }
                    let Ok((m, _)) = self.resolve_inner(ns, rtype, 0, 0, budget, false) else {
                        continue;
                    };
                    for r in m.answers.iter().filter(|r| r.class == DnsClass::IN) {
                        let ip = match &r.rdata {
                            RData::A(ip) => IpAddr::V4(*ip),
                            RData::Aaaa(ip) => IpAddr::V6(*ip),
                            _ => continue,
                        };
                        resolved.push(ip);
                        min_ttl = min_ttl.min(r.ttl);
                    }
                }
                if !resolved.is_empty() {
                    resolved.sort_unstable();
                    resolved.dedup();
                    resolved.truncate(MAX_CACHED_NS_ADDRS);
                    self.ns_addr_store(key, resolved.clone(), min_ttl);
                    all_ttl = min_optional_ttl(all_ttl, Some(min_ttl));
                }
                all.extend(
                    resolved
                        .into_iter()
                        .map(|ip| SocketAddr::new(ip, self.port)),
                );
            }
            if all.iter().any(|s| self.usable_server(s.ip())) {
                break;
            }
        }
        all.retain(|s| self.server_eligible(s.ip()));
        all.sort_unstable();
        all.dedup();
        Ok((all, all_ttl, rest.cloned().collect()))
    }

    /// An IPv6 address on a host without an IPv6 route is unusable; stopping NS resolution with
    /// only such addresses would leave nowhere to send.
    fn usable_server(&self, ip: IpAddr) -> bool {
        self.server_eligible(ip) && (ip.is_ipv4() || ipv6_route_available())
    }

    /// True when a new address changed the server list.
    fn resolve_more_ns_addrs(&self, state: &mut IterationState, budget: &mut Budget) -> bool {
        while !state.unresolved_ns.is_empty() {
            let names = std::mem::take(&mut state.unresolved_ns);
            let Ok((addrs, _, rest)) = self.resolve_ns_addrs(&names, budget) else {
                return false;
            };
            state.unresolved_ns = rest;
            let fresh: Vec<SocketAddr> = addrs
                .into_iter()
                .filter(|addr| !state.servers.contains(addr))
                .collect();
            if fresh.is_empty() {
                continue;
            }
            rtrace!(
                "Nameservers of {} did not answer; resolved {} more addresses ({} names left)",
                state.zone.to_ascii_lower(),
                fresh.len(),
                state.unresolved_ns.len()
            );
            if let Some(step) = state.chain.last_mut() {
                step.servers.extend(fresh.iter().copied());
            }
            state.servers = fresh;
            return true;
        }
        false
    }

    #[cfg(test)]
    fn ns_addr_cached(&self, key: &[u8]) -> Option<Vec<IpAddr>> {
        self.ns_addr_cached_with_ttl(key).map(|(addrs, _)| addrs)
    }

    /// Drops an expired entry on the way out.
    fn ns_addr_cached_with_ttl(&self, key: &[u8]) -> Option<(Vec<IpAddr>, u32)> {
        let mut cache = self.ns_addr_cache.lock_recover();
        let now = cache_now_millis();
        match cache.get(key) {
            Some(entry) if entry.lifetime.is_live(now) => {
                let remaining = entry
                    .lifetime
                    .remaining_secs(now)
                    .expect("A live TTL must have time remaining");
                Some((entry.addrs.clone(), remaining))
            }
            Some(_) => {
                cache.pop(key);
                None
            }
            None => None,
        }
    }

    fn ns_addr_store(&self, key: Vec<u8>, addrs: Vec<IpAddr>, ttl_secs: u32) {
        let mut addrs = addrs;
        addrs.sort_unstable();
        addrs.dedup();
        addrs.truncate(MAX_CACHED_NS_ADDRS);
        let ttl = ttl_secs.min(self.recursive_cache_ttl_max);
        if ttl == 0 {
            return;
        }
        self.ns_addr_cache.lock_recover().put(
            key,
            NsAddrEntry {
                addrs,
                lifetime: TtlLifetime::new(ttl),
            },
        );
    }

    /// Deeper means fewer steps left.
    fn deepest_cached_delegation(&self, qname: &Name) -> Option<(Name, Vec<SocketAddr>)> {
        let total = qname.num_labels();
        let now = cache_now_millis();
        let mut key = [0u8; 255];
        let mut cache = self.deleg_cache.lock_recover();
        for k in (1..=total).rev() {
            let key = qname.canonical_suffix_key_into(k, &mut key)?;
            match cache.get(key) {
                Some(entry) if entry.lifetime.is_live(now) => {
                    return Some((qname.suffix(k), entry.servers.clone()));
                }
                Some(_) => {
                    cache.pop(key);
                }
                None => {}
            }
        }
        None
    }

    #[cfg(test)]
    /// Drops an expired entry on the way out.
    fn deleg_cached(&self, zone: &Name) -> Option<Vec<SocketAddr>> {
        let mut key = [0u8; 255];
        let key = zone.canonical_key_into(&mut key)?;
        let mut cache = self.deleg_cache.lock_recover();
        let now = cache_now_millis();
        match cache.get(key) {
            Some(entry) if entry.lifetime.is_live(now) => Some(entry.servers.clone()),
            Some(_) => {
                cache.pop(key);
                None
            }
            None => None,
        }
    }

    fn deleg_store(&self, zone: &Name, servers: &[SocketAddr], ttl_secs: u32) {
        if servers.is_empty() {
            return;
        }
        let mut servers = servers.to_vec();
        servers.sort_unstable();
        servers.dedup();
        servers.truncate(MAX_CACHED_NS_ADDRS);
        let ttl = ttl_secs.min(self.recursive_cache_ttl_max);
        if ttl == 0 {
            return;
        }
        let key = zone.canonical_key();
        self.deleg_cache.lock_recover().put(
            key,
            DelegationEntry {
                servers,
                lifetime: TtlLifetime::new(ttl),
            },
        );
    }

    /// Called when an attempt from a cached delegation fails. Which step is stale is unknown, so
    /// the whole path goes and the walk restarts at the root.
    fn deleg_evict_path(&self, qname: &Name) {
        let total = qname.num_labels();
        let mut cache = self.deleg_cache.lock_recover();
        let mut key = [0u8; 255];
        for k in 1..=total {
            if let Some(key) = qname.canonical_suffix_key_into(k, &mut key) {
                cache.pop(key);
            }
        }
    }

    /// Asks the most responsive servers first. An answer that does not match this server's query is
    /// skipped but kept as a last resort. With 0x20 on, the question must match case for case: that
    /// check is what rejects forged answers. Each server gets a share of the time, or the first
    /// could spend the whole deadline.
    fn query_any(
        &self,
        servers: &[SocketAddr],
        q: &Message,
        zone: &Name,
        deadline: Instant,
    ) -> Result<Message, RecurseError> {
        self.query_any_reserving(servers, q, zone, deadline, 0)
    }

    /// Like `query_any`, but reserves time for `reserve` name servers not yet resolved. After a
    /// server's patience it asks the next while still waiting, and uses whichever usable answer
    /// comes first: abandoning a slightly slow server would drop its answer just before it arrives,
    /// and waiting to the end would let one slow server take the rest. Name server resolution stops
    /// at the first usable address, so the list is short; dividing time among those few would let
    /// one dead server keep the remaining names from being tried.
    fn query_any_reserving(
        &self,
        servers: &[SocketAddr],
        q: &Message,
        zone: &Name,
        deadline: Instant,
        reserve: usize,
    ) -> Result<Message, RecurseError> {
        let mut fallback: Option<Message> = None;

        let mut sent = q.clone();
        self.apply_outgoing_case(&mut sent);

        let ordered = self.ask_order(servers, zone)?;

        let per_exchange_deadline = Instant::now().checked_add(self.timeout).unwrap_or(deadline);
        let deadline = deadline.min(per_exchange_deadline);
        let divisor = (ordered.len() + reserve).clamp(1, 4) as u32;
        let per_server = (self.timeout / divisor).max(Duration::from_millis(300));
        let request = std::sync::Arc::new(sent);
        let (tx, rx) = std::sync::mpsc::channel();
        let mut started: Vec<Option<Instant>> = vec![None; ordered.len()];
        let mut next = 0;
        let mut in_flight = 0usize;
        let mut ask_next_at = Instant::now();

        // Each exchange's timeout already falls inside the deadline, so this applies only when an
        // exchange overruns.
        let settled_by = deadline + per_server;
        loop {
            let now = Instant::now();
            let asking = now < deadline;
            if !asking && (in_flight == 0 || now >= settled_by) {
                if next < ordered.len() {
                    rtrace!(
                        "Ran out of time before asking some of the {} servers: name={}",
                        servers.len(),
                        request
                            .questions
                            .first()
                            .map(|q| q.name.to_ascii_lower())
                            .unwrap_or_default()
                    );
                }
                break;
            }
            if asking
                && next < ordered.len()
                && (in_flight == 0 || (now >= ask_next_at && in_flight < MAX_EXCHANGES_PER_QUERY))
            {
                let server = ordered[next];
                let attempt_timeout = per_server.min(deadline - now);
                self.spawn_attempt(server, &request, attempt_timeout, next, &tx);
                started[next] = Some(now);
                next += 1;
                in_flight += 1;
                ask_next_at = now + self.server_patience(server.ip()).min(per_server);
                continue;
            }
            if in_flight == 0 {
                break;
            }
            // Past the deadline, ask nothing new and wait only until the exchanges in flight report
            // back. Returning earlier would leave one in flight, and the next identical query would
            // join it and time out with it.
            let wake = if !asking {
                settled_by
            } else if next < ordered.len() && in_flight < MAX_EXCHANGES_PER_QUERY {
                ask_next_at.min(deadline)
            } else {
                deadline
            };
            let Ok((idx, result)) = rx.recv_timeout(wake.saturating_duration_since(now)) else {
                continue;
            };
            in_flight -= 1;
            let s = ordered[idx];
            let elapsed = started[idx]
                .take()
                .map_or(Duration::ZERO, |at| at.elapsed());
            match result {
                Ok(r) => {
                    if self.caps_for_id && !questions_case_exact(&r.questions, &request.questions) {
                        rtrace!(
                            "{} did not echo the query name case; dropping: sent={}, got={}",
                            s,
                            request
                                .questions
                                .first()
                                .map(|q| q.name.to_string())
                                .unwrap_or_default(),
                            r.questions
                                .first()
                                .map(|q| q.name.to_string())
                                .unwrap_or_default()
                        );
                        self.infra_fail(s.ip(), zone);
                        ask_next_at = Instant::now();
                        continue;
                    }
                    if response_usable_for_iteration(&r, &request, zone) {
                        self.infra_success(s.ip(), zone, elapsed);
                        self.record_unanswered(&ordered, &started);
                        return Ok(r);
                    }

                    self.infra_protocol_error(s.ip(), zone);
                    fallback = Some(r);
                    ask_next_at = Instant::now();
                }
                Err(error) => {
                    rtrace!(
                        "Asked {} but got no answer: name={}, type={:?}, error={:?}",
                        s,
                        request
                            .questions
                            .first()
                            .map(|q| q.name.to_ascii_lower())
                            .unwrap_or_default(),
                        request.questions.first().map(|q| q.qtype),
                        error
                    );
                    self.infra_fail(s.ip(), zone);
                    ask_next_at = Instant::now();
                }
            }
        }
        self.record_unanswered(&ordered, &started);
        fallback.ok_or(RecurseError::NoResponse)
    }

    /// Lets the caller ask other servers while this one runs. If the caller finishes first and
    /// drops the channel, the exchange still ends within its own timeout and the result is dropped.
    /// Without a thread it asks in place. The transport is chosen per exchange, since UDP 53
    /// interception may be detected mid-resolution and a UDP query after that gets no answer.
    fn spawn_attempt(
        &self,
        server: SocketAddr,
        request: &std::sync::Arc<Message>,
        timeout: Duration,
        idx: usize,
        tx: &std::sync::mpsc::Sender<(usize, Result<Message, onetdns_forward::ForwardError>)>,
    ) {
        let merge_case = self.caps_for_id;
        let transport = if self.authority_over_tcp() {
            onetdns_forward::AuthorityTransport::Tcp
        } else {
            onetdns_forward::AuthorityTransport::Udp
        };
        let attempt = {
            let request = request.clone();
            let tx = tx.clone();
            move || {
                let result = onetdns_forward::query_server_over(
                    server, &request, timeout, transport, merge_case,
                );
                let _ = tx.send((idx, result));
            }
        };
        if std::thread::Builder::new()
            .name("recurse-exchange".into())
            .spawn(attempt)
            .is_err()
        {
            let result =
                onetdns_forward::query_server_over(server, request, timeout, transport, merge_case);
            let _ = tx.send((idx, result));
        }
    }

    /// Records the RTT of servers abandoned before answering as at least the time waited.
    fn record_unanswered(&self, ordered: &[SocketAddr], started: &[Option<Instant>]) {
        for (server, at) in ordered.iter().zip(started) {
            if let Some(at) = at {
                self.record_rtt_at_least(server.ip(), at.elapsed());
            }
        }
    }

    /// Three times the measured RTT, the retransmission timeout RFC 6298 sets after the first
    /// measurement; normal jitter stays below it.
    fn server_patience(&self, ip: IpAddr) -> Duration {
        match self.srtt(ip) {
            Some(ms) => Duration::from_millis(u64::from(ms) * 3).max(MIN_SERVER_PATIENCE),
            None => UNKNOWN_SERVER_PATIENCE,
        }
    }

    /// Sorts by preferred family and score. Recently failed servers get a penalty but stay listed,
    /// since the query must still try them if the first ones do not answer. Only servers down after
    /// repeated failures are dropped, so the list is empty when all are down.
    fn order_by_infra(&self, servers: &[SocketAddr], zone: &Name) -> Vec<SocketAddr> {
        let infra = self.infra.lock_recover();
        let rtt = self.rtt.lock_recover();
        let now = Instant::now();

        let mut ranked: Vec<(u8, u64, SocketAddr)> = servers
            .iter()
            .copied()
            .filter(|server| self.family_allowed(server.ip()))
            .filter_map(|server| {
                let state = infra.peek(&InfraKey::new(server.ip(), zone));
                if state.is_some_and(|state| state.down(now)) {
                    return None;
                }
                Some((
                    self.family_rank(server.ip()),
                    infra_score(state, rtt.peek(&server.ip()).copied(), now),
                    server,
                ))
            })
            .collect();
        drop(rtt);
        drop(infra);
        ranked.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        ranked.into_iter().map(|(_, _, server)| server).collect()
    }

    /// `NoReachableNs` when policy or address family leaves no server to ask. `NoResponse` when
    /// every candidate is down after repeated failures: reported as a transport failure so the bin
    /// moves to `fallback_upstreams`.
    fn ask_order(
        &self,
        servers: &[SocketAddr],
        zone: &Name,
    ) -> Result<Vec<SocketAddr>, RecurseError> {
        let eligible: Vec<SocketAddr> = servers
            .iter()
            .copied()
            .filter(|server| self.server_eligible(server.ip()))
            .collect();
        if eligible.is_empty() {
            return Err(RecurseError::NoReachableNs);
        }
        let ordered = self.order_by_infra(&eligible, zone);
        if ordered.is_empty() {
            rtrace!(
                "Every nameserver of {} failed repeatedly; not asking until its backoff ends",
                zone.to_ascii_lower()
            );
            return Err(RecurseError::NoResponse);
        }
        Ok(ordered)
    }

    /// `None` for an address not measured yet.
    fn srtt(&self, ip: IpAddr) -> Option<u32> {
        self.rtt.lock_recover().peek(&ip).copied()
    }

    /// Exponential smoothing: a new sample counts one eighth, so one slow answer does not flip the
    /// order.
    fn record_rtt(&self, ip: IpAddr, sample: Duration) {
        let ms = sample.as_millis().min(u128::from(u32::MAX)) as u32;
        let mut rtt = self.rtt.lock_recover();
        let smoothed = match rtt.peek(&ip) {
            Some(&old) => ((u64::from(old) * 7 + u64::from(ms)) / 8) as u32,
            None => ms,
        };
        rtt.put(ip, smoothed);
    }

    /// Its RTT is at least the time waited; without this the server stays unmeasured and is asked
    /// first again next time.
    fn record_rtt_at_least(&self, ip: IpAddr, waited: Duration) {
        if self
            .srtt(ip)
            .is_none_or(|known| u128::from(known) < waited.as_millis())
        {
            self.record_rtt(ip, waited);
        }
    }

    /// Updates the RTT and clears the zone's failure record.
    fn infra_success(&self, ip: IpAddr, zone: &Name, rtt: Duration) {
        self.record_rtt(ip, rtt);
        self.infra.lock_recover().pop(&InfraKey::new(ip, zone));
    }

    /// An answer came, so it counts differently from a transport failure.
    fn infra_protocol_error(&self, ip: IpAddr, zone: &Name) {
        let key = InfraKey::new(ip, zone);
        let mut infra = self.infra.lock_recover();
        let mut state = infra.pop(&key).unwrap_or_default();
        state.last_protocol_error = Some(Instant::now());
        infra.put(key, state);
    }

    /// Lowers the rank; repeated failures stop queries to it for a while.
    fn infra_fail(&self, ip: IpAddr, zone: &Name) {
        let key = InfraKey::new(ip, zone);
        let now = Instant::now();
        let mut infra = self.infra.lock_recover();
        let mut state = infra.pop(&key).unwrap_or_default();
        if !state.down(now) {
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        }
        state.last_fail = Some(now);
        infra.put(key, state);
    }
}

/// Lower is tried first: RTT plus a failure penalty. The penalty is large enough to push failed
/// servers back without excluding them, so they return after `INFRA_FAIL_COOLDOWN`.
fn infra_score(state: Option<&InfraStat>, srtt_ms: Option<u32>, now: Instant) -> u64 {
    let base = u64::from(srtt_ms.unwrap_or(DEFAULT_RTT_MS));
    let Some(state) = state else {
        return base;
    };
    let recent = |at: Option<Instant>| {
        at.is_some_and(|at| now.saturating_duration_since(at) < INFRA_FAIL_COOLDOWN)
    };
    let transport_penalty = if state.cooling(now) {
        INFRA_FAIL_PENALTY_MS
    } else {
        0
    };
    let protocol_penalty = if recent(state.last_protocol_error) {
        INFRA_PROTOCOL_PENALTY_MS
    } else {
        0
    };
    base + transport_penalty + protocol_penalty
}

/// Filters loopback, private, link-local, documentation and IPv4-embedding IPv6 forms; missing the
/// embedded forms would let an internal IPv4 address slip through wrapped in IPv6. This is the core
/// SSRF defense: a crafted delegation naming an internal address would make this server probe the
/// internal network.
fn is_globally_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => !is_special_v4(address),
        IpAddr::V6(address) => {
            if let Some(mapped) = embedded_v4(address) {
                return !is_special_v4(mapped);
            }
            let octets = address.octets();
            let segments = address.segments();
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] & 0xffc0) == 0xfec0
                || (segments[0] & 0xfe00) == 0xfc00
                || (octets[0] == 0x20
                    && octets[1] == 0x01
                    && octets[2] == 0x0d
                    && octets[3] == 0xb8)
                || octets[..8] == [0x01, 0x00, 0, 0, 0, 0, 0, 0]
                || (octets[0] == 0x20
                    && octets[1] == 0x01
                    && octets[2] == 0x00
                    && octets[3] == 0x02)
                || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001))
        }
    }
}

/// Mapped, 6to4 and NAT64 forms.
fn embedded_v4(address: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return Some(mapped);
    }
    let segments = address.segments();
    let octets = address.octets();

    if segments[0] == 0x2002 {
        return Some(std::net::Ipv4Addr::new(
            octets[2], octets[3], octets[4], octets[5],
        ));
    }

    if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2..6] == [0, 0, 0, 0] {
        return Some(std::net::Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }

    if segments[..6] == [0, 0, 0, 0, 0, 0] {
        return Some(std::net::Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    None
}

fn is_special_v4(address: std::net::Ipv4Addr) -> bool {
    let value = u32::from(address);
    let in_net = |network: [u8; 4], prefix: u8| {
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        value & mask == u32::from(std::net::Ipv4Addr::from(network)) & mask
    };

    in_net([0, 0, 0, 0], 8)
        || in_net([10, 0, 0, 0], 8)
        || in_net([100, 64, 0, 0], 10)
        || in_net([127, 0, 0, 0], 8)
        || in_net([169, 254, 0, 0], 16)
        || in_net([172, 16, 0, 0], 12)
        || in_net([192, 0, 0, 0], 24)
        || in_net([192, 0, 2, 0], 24)
        || in_net([192, 88, 99, 0], 24)
        || in_net([192, 168, 0, 0], 16)
        || in_net([198, 18, 0, 0], 15)
        || in_net([198, 51, 100, 0], 24)
        || in_net([203, 0, 113, 0], 24)
        || in_net([224, 0, 0, 0], 4)
        || in_net([240, 0, 0, 0], 4)
}

/// Answers blocked as bogus, exported as a metric.
pub static VALIDATION_BOGUS_TOTAL: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
std::thread_local! {
    /// Observes only this thread's increments, so parallel tests do not interfere.
    static TEST_THREAD_VALIDATION_BOGUS_TOTAL: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
}

pub fn validation_bogus_total() -> u64 {
    VALIDATION_BOGUS_TOTAL.load(std::sync::atomic::Ordering::Relaxed)
}

fn record_validation_bogus() {
    VALIDATION_BOGUS_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    #[cfg(test)]
    TEST_THREAD_VALIDATION_BOGUS_TOTAL.with(|total| {
        total.set(total.get().saturating_add(1));
    });
}

#[cfg(test)]
fn test_thread_validation_bogus_total() -> u64 {
    TEST_THREAD_VALIDATION_BOGUS_TOTAL.with(std::cell::Cell::get)
}

/// Each code gets its own text so operators know what to fix: a broken signature and a refused
/// computation need different responses.
fn ede_text_for(code: u16) -> &'static str {
    match code {
        ede_code::UNSUPPORTED_NSEC3_ITERATIONS => "NSEC3 iterations above local limit",
        ede_code::NO_REACHABLE_AUTHORITY => "Could not fetch the DNSSEC keys from the authority",
        _ => "DNSSEC validation failed",
    }
}

/// Keeps only the question; any record left from a broken answer could be used by the client.
fn bogus_servfail(template: &Message, ede: u16) -> Message {
    // A missing key means the authorities were unreachable, not that validation failed. Counting it
    // as a validation failure would make a network outage look like a signature problem.
    if ede != ede_code::NO_REACHABLE_AUTHORITY {
        record_validation_bogus();
    }
    let mut sf = Message::default();
    sf.header.id = template.header.id;
    sf.header.rcode = ResponseCode::ServFail.0;
    sf.questions = template.questions.clone();
    let mut e = Edns::default();
    e.push_ede(ede, ede_text_for(ede));
    sf.additionals.push(e.try_to_record().unwrap());
    sf
}

/// RD is not set.
fn make_query(qname: &Name, qtype: RecordType, do_bit: bool) -> Message {
    let mut m = Message {
        header: Header {
            id: 0,
            recursion_desired: false,
            ..Default::default()
        },
        questions: vec![Question {
            name: qname.clone(),
            qtype,
            qclass: DnsClass::IN,
        }],
        ..Default::default()
    };
    m.additionals.push(
        Edns {
            udp_payload: 1232,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: do_bit,
            options: vec![],
        }
        .try_to_record()
        .unwrap(),
    );
    m
}

/// The answer echoes the case pattern, so a forger must also guess it besides the ID and port.
fn randomize_name_case(name: &Name) -> Name {
    let mut bits = onetdns_core::ephemeral_random_array::<32>();
    let mut idx = 0usize;
    let labels: Vec<Vec<u8>> = name
        .labels()
        .iter()
        .map(|l| {
            l.iter()
                .map(|&b| {
                    if b.is_ascii_alphabetic() {
                        if idx >= bits.len() * 8 {
                            bits = onetdns_core::ephemeral_random_array::<32>();
                            idx = 0;
                        }
                        let bit = (bits[idx / 8] >> (idx % 8)) & 1;
                        idx += 1;
                        if bit == 1 {
                            b.to_ascii_uppercase()
                        } else {
                            b.to_ascii_lowercase()
                        }
                    } else {
                        b
                    }
                })
                .collect()
        })
        .collect();
    Name::from_labels(labels).unwrap_or_else(|_| name.clone())
}

/// Improves upstream cache hits.
fn lowercase_name(name: &Name) -> Name {
    Name::from_labels(
        name.labels()
            .iter()
            .map(|l| l.to_ascii_lowercase())
            .collect(),
    )
    .unwrap_or_else(|_| name.clone())
}

/// The 0x20 check; ignoring case would remove the defense entirely.
fn questions_case_exact(resp: &[Question], sent: &[Question]) -> bool {
    if resp.len() != sent.len() {
        return false;
    }
    resp.iter().zip(sent).all(|(a, b)| {
        a.qtype == b.qtype
            && a.qclass == b.qclass
            && a.name.labels().len() == b.name.labels().len()
            && a.name
                .labels()
                .iter()
                .zip(b.name.labels())
                .all(|(x, y)| x == y)
    })
}

/// `records` is a referral's authority section or the answer to a separate DS query to the
/// parent.
fn extract_ds(
    records: &[Record],
    child_zone: &Name,
) -> (
    Vec<Record>,
    Vec<onetdns_dnssec::Rrsig>,
    Vec<Record>,
    Vec<onetdns_dnssec::Rrsig>,
    Vec<Record>,
    Vec<onetdns_dnssec::Rrsig>,
    Vec<onetdns_dnssec::Ds>,
) {
    let mut recs = Vec::new();
    let mut ds = Vec::new();
    let mut nsec = Vec::new();
    let mut nsec_sigs = Vec::new();
    let mut nsec3 = Vec::new();
    let mut nsec3_sigs = Vec::new();
    let mut ds_rrsig_ttl = None;
    let mut nsec_owners = HashSet::new();
    let mut nsec3_owners = HashSet::new();
    for r in records {
        if r.class != DnsClass::IN {
            continue;
        }
        if r.rtype == RecordType::DS && r.name.eq_ignore_case(child_zone) {
            recs.push(r.clone());
            if let Some(d) = onetdns_dnssec::Ds::from_record(r) {
                ds.push(d);
            }
        } else if r.rtype == RecordType::NSEC {
            nsec_owners.insert(r.name.canonical_key());
            nsec.push(r.clone());
        } else if r.rtype == RecordType::NSEC3 {
            nsec3_owners.insert(r.name.canonical_key());
            nsec3.push(r.clone());
        }
    }

    let mut sigs = Vec::new();
    for record in records {
        if record.class != DnsClass::IN || record.rtype != RecordType::RRSIG {
            continue;
        }
        let Some(signature) = onetdns_dnssec::Rrsig::from_record(record) else {
            continue;
        };
        match RecordType(signature.type_covered) {
            RecordType::DS if record.name.eq_ignore_case(child_zone) => {
                ds_rrsig_ttl = min_optional_ttl(ds_rrsig_ttl, Some(record.ttl));
                sigs.push(signature);
            }
            RecordType::NSEC if nsec_owners.contains(&record.name.canonical_key()) => {
                nsec_sigs.push(signature);
            }
            RecordType::NSEC3 if nsec3_owners.contains(&record.name.canonical_key()) => {
                nsec3_sigs.push(signature);
            }
            _ => {}
        }
    }

    if let Some(ttl) = ds_rrsig_ttl {
        for record in &mut recs {
            record.ttl = record.ttl.min(ttl);
        }
    }
    (recs, sigs, nsec, nsec_sigs, nsec3, nsec3_sigs, ds)
}

/// Connecting a UDP socket picks a route without sending, so it fails at once when there is
/// none; resolving AAAA on such a host only spends time on unusable addresses. The target is
/// a.root-servers.net's IPv6 address. The network can change, so the result is reused for 30
/// seconds only.
fn ipv6_route_available() -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    const RECHECK_SECS: u64 = 30;
    /// The last check time (Unix seconds) in the upper bits, the result in the lowest bit; 0 means
    /// not checked yet.
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let last = LAST.load(Ordering::Relaxed);
    if last != 0 && now.saturating_sub(last >> 1) < RECHECK_SECS {
        return last & 1 == 1;
    }
    let probe = SocketAddr::new(
        IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0x503, 0xba3e, 0, 0, 0, 2, 0x30,
        )),
        53,
    );
    let available = std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0))
        .and_then(|sock| sock.connect(probe))
        .is_ok();
    LAST.store((now << 1) | u64::from(available), Ordering::Relaxed);
    available
}

fn now_secs() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

fn extract_rrsigs(
    records: &[Record],
    type_covered: u16,
    owner: &Name,
) -> Vec<onetdns_dnssec::Rrsig> {
    records
        .iter()
        .filter(|r| {
            r.class == DnsClass::IN && r.rtype == RecordType::RRSIG && r.name.eq_ignore_case(owner)
        })
        .filter_map(onetdns_dnssec::Rrsig::from_record)
        .filter(|sig| sig.type_covered == type_covered)
        .collect()
}

/// A wildcard expansion needs a signed NSEC or NSEC3 proving the next closer absent; otherwise a
/// more specific name may be hidden.
struct WildcardValidation<'a> {
    keys: &'a [onetdns_dnssec::Dnskey],
    /// The signer must match this apex.
    apex: &'a Name,
    now: u32,
    nsec3_max_iterations: u16,
    /// The response-wide public-key budget, carried on from the answer RRsets.
    verification_budget: &'a mut onetdns_dnssec::VerificationBudget,
}

fn validated_wildcard_expansion(
    response: &Message,
    qname: &Name,
    closest_encloser_labels: usize,
    validation: WildcardValidation<'_>,
) -> bool {
    let denial_records = |rtype| {
        response
            .authorities
            .iter()
            .filter(|record| record.class == DnsClass::IN && record.rtype == rtype)
            .cloned()
            .collect::<Vec<_>>()
    };
    let nsecs = denial_records(RecordType::NSEC);
    if let Some(proof) =
        onetdns_dnssec::nsec_wildcard_expansion_proof(&nsecs, qname, closest_encloser_labels)
    {
        if validate_denial_proof(
            &proof,
            &response.authorities,
            validation.keys,
            validation.apex,
            validation.now,
            validation.verification_budget,
        ) {
            return true;
        }
    }
    let nsec3s = denial_records(RecordType::NSEC3);
    onetdns_dnssec::nsec3_max_iterations(&nsec3s) <= validation.nsec3_max_iterations
        && onetdns_dnssec::nsec3_wildcard_expansion_proof(&nsec3s, qname, closest_encloser_labels)
            .is_some_and(|proof| {
                validate_denial_proof(
                    &proof,
                    &response.authorities,
                    validation.keys,
                    validation.apex,
                    validation.now,
                    validation.verification_budget,
                )
            })
}

/// Validates the signatures of every RRset in the selected minimal NSEC or NSEC3 proof.
fn validate_denial_proof(
    proof: &[Record],
    response_records: &[Record],
    keys: &[onetdns_dnssec::Dnskey],
    apex: &Name,
    now: u32,
    verification_budget: &mut onetdns_dnssec::VerificationBudget,
) -> bool {
    !proof.is_empty()
        && proof.iter().all(|record| {
            let signatures = extract_rrsigs(response_records, record.rtype.0, &record.name);
            onetdns_dnssec::validate_rrset_in_zone_with_budget(
                std::slice::from_ref(record),
                &signatures,
                keys,
                apex,
                now,
                verification_budget,
            )
            .is_ok()
        })
}

/// Keeps the apex SOA, the selected proof records and their signatures. An AD answer carrying an
/// unvalidated NSEC would let the denial synthesis layer above trust it and deny unrelated names
/// in the zone.
fn validated_denial_records(
    soa: &[Record],
    proof: &[Record],
    authorities: &[Record],
) -> Vec<Record> {
    let mut kept: Vec<Record> = Vec::with_capacity(soa.len() + proof.len());
    kept.extend(soa.iter().cloned());
    kept.extend(proof.iter().cloned());
    let covered: Vec<(Vec<u8>, u16)> = kept
        .iter()
        .map(|record| (record.name.canonical_key(), record.rtype.0))
        .collect();
    let signatures: Vec<Record> = authorities
        .iter()
        .filter(|record| record.class == DnsClass::IN && record.rtype == RecordType::RRSIG)
        .filter(|record| {
            onetdns_dnssec::Rrsig::from_record(record).is_some_and(|signature| {
                let owner = record.name.canonical_key();
                covered
                    .iter()
                    .any(|(name, rtype)| *rtype == signature.type_covered && *name == owner)
            })
        })
        .cloned()
        .collect();
    kept.extend(signatures);
    kept
}

fn is_within(name: &Name, zone: &Name) -> bool {
    name.ends_with_ignore_case(zone)
}

/// Left in place, it could hijack names.
fn strip_out_of_bailiwick_dnames(resp: &mut Message, zone: &Name) {
    resp.answers
        .retain(|r| !matches!(r.rdata, RData::Dname(_)) || is_within(&r.name, zone));
}

/// One of the conditions for following a referral.
fn is_closer(cand: &Name, cur: &Name) -> bool {
    cand.num_labels() > cur.num_labels() && is_within(cand, cur)
}

fn min_optional_ttl(left: Option<u32>, right: Option<u32>) -> Option<u32> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(ttl), None) | (None, Some(ttl)) => Some(ttl),
        (None, None) => None,
    }
}

/// Becomes the delegation cache lifetime. In the authority section for a referral, in the answer
/// section for a cut revealed by an authoritative answer.
fn min_ns_ttl(resp: &Message, zone: &Name) -> Option<u32> {
    resp.authorities
        .iter()
        .chain(&resp.answers)
        .filter(|r| {
            r.class == DnsClass::IN && r.rtype == RecordType::NS && r.name.eq_ignore_case(zone)
        })
        .map(|r| r.ttl)
        .min()
}

/// Looks only at authority NS; answer NS is about the zone itself, not a delegation.
fn extract_referral(resp: &Message, qname: &Name) -> (Option<Name>, Vec<Name>) {
    if resp.header.rcode != ResponseCode::NoError.0
        || resp.header.authoritative
        || !resp.answers.is_empty()
    {
        return (None, vec![]);
    }
    let mut best: Option<Name> = None;
    for r in &resp.authorities {
        if r.class != DnsClass::IN {
            continue;
        }
        if let RData::Ns(_) = &r.rdata {
            if is_within(qname, &r.name)
                && best
                    .as_ref()
                    .is_none_or(|b| r.name.num_labels() > b.num_labels())
            {
                best = Some(r.name.clone());
            }
        }
    }
    let zone = match best {
        Some(z) => z,
        None => return (None, vec![]),
    };
    let ns: Vec<Name> = resp
        .authorities
        .iter()
        .filter_map(|r| match &r.rdata {
            RData::Ns(n) if r.class == DnsClass::IN && r.name.eq_ignore_case(&zone) => {
                Some(n.clone())
            }
            _ => None,
        })
        .collect();
    (Some(zone), ns)
}

/// When one server serves parent and child, it answers from the child, so the cut's NS comes in
/// the answer section rather than a referral's authority section; RFC 9156 treats that as a cut
/// too. Not following it would mistake the current zone for the parent and discard a negative
/// answer carrying the child's SOA as irrelevant. The name asked must be deeper than the current
/// zone; the zone's own apex NS is not a cut. Returns the cut's name server names.
fn answer_zone_cut(resp: &Message, plan: &NextQuery, zone: &Name) -> Option<Vec<Name>> {
    if plan.is_final
        || plan.mtype != RecordType::NS
        || resp.header.rcode != ResponseCode::NoError.0
        || !resp.header.authoritative
        || !is_closer(&plan.mname, zone)
    {
        return None;
    }
    let ns: Vec<Name> = resp
        .answers
        .iter()
        .filter_map(|record| match &record.rdata {
            RData::Ns(target)
                if record.class == DnsClass::IN && record.name.eq_ignore_case(&plan.mname) =>
            {
                Some(target.clone())
            }
            _ => None,
        })
        .collect();
    (!ns.is_empty()).then_some(ns)
}

fn has_direct_qtype_answer(resp: &Message, qname: &Name, qtype: RecordType) -> bool {
    resp.answers.iter().any(|record| {
        record.class == DnsClass::IN
            && record.name.eq_ignore_case(qname)
            && (qtype == RecordType::ANY || record.rtype == qtype)
    })
}

/// A DNAME result exceeding the name length gives YXDOMAIN, also a final answer.
fn is_dname_yxdomain(resp: &Message, qname: &Name) -> bool {
    resp.header.rcode == ResponseCode::YXDomain.0
        && resp.header.authoritative
        && resp.answers.iter().any(|record| {
            record.class == DnsClass::IN
                && matches!(record.rdata, RData::Dname(_))
                && record.name.num_labels() < qname.num_labels()
                && qname
                    .suffix(record.name.num_labels())
                    .eq_ignore_case(&record.name)
        })
}

/// The basis of a negative answer.
fn has_relevant_soa(resp: &Message, qname: &Name, zone: &Name) -> bool {
    is_within(qname, zone)
        && resp.authorities.iter().any(|record| {
            record.rtype == RecordType::SOA
                && record.class == DnsClass::IN
                && record.name.eq_ignore_case(zone)
        })
}

fn has_relevant_alias(resp: &Message, qname: &Name) -> bool {
    cname_target(resp, qname).is_some() || dname_rewrite(resp, qname).is_some()
}

fn is_relevant_positive(resp: &Message, qname: &Name, qtype: RecordType) -> bool {
    resp.header.rcode == ResponseCode::NoError.0
        && resp.header.authoritative
        && cname_owner_is_valid(resp, qname)
        && (has_direct_qtype_answer(resp, qname, qtype) || has_relevant_alias(resp, qname))
}

/// Requires the AA bit and zone relevance; accepting any server's NXDOMAIN would let anyone
/// delete arbitrary names.
fn is_authoritative_negative(resp: &Message, qname: &Name, zone: &Name) -> bool {
    resp.header.authoritative && has_relevant_soa(resp, qname, zone)
}

/// RFC 2308 lists this shape as a form of NODATA. Load-balancing authorities often give an alias
/// for A and answer other types this way; refusing it would make every server of the zone look
/// failed and end in SERVFAIL. Without an SOA there is no negative TTL, and the cache layer
/// declines to store it. In a signed zone the denial validation requires an SOA, so it is bogus.
fn is_bare_authoritative_nodata(resp: &Message, qname: &Name, zone: &Name) -> bool {
    resp.header.rcode == ResponseCode::NoError.0
        && resp.header.authoritative
        && is_within(qname, zone)
        && resp.answers.is_empty()
        && !resp
            .authorities
            .iter()
            .any(|record| matches!(record.rtype, RecordType::NS | RecordType::SOA))
}

fn retryable_rcode(rcode: u16) -> bool {
    matches!(
        rcode,
        code if code == ResponseCode::FormErr.0
            || code == ResponseCode::ServFail.0
            || code == ResponseCode::NotImp.0
            || code == ResponseCode::Refused.0
    )
}

/// The ID and question must match what this server sent, and the rcode must be usable; otherwise
/// the next server is tried.
fn response_usable_for_iteration(resp: &Message, query: &Message, zone: &Name) -> bool {
    let Some(question) = query.questions.first() else {
        return false;
    };
    if retryable_rcode(resp.header.rcode) {
        return false;
    }
    match resp.header.rcode {
        code if code == ResponseCode::NoError.0 => {
            is_relevant_positive(resp, &question.name, question.qtype)
                || is_authoritative_negative(resp, &question.name, zone)
                || is_bare_authoritative_nodata(resp, &question.name, zone)
                || extract_referral(resp, &question.name)
                    .0
                    .is_some_and(|child| is_closer(&child, zone))
        }
        code if code == ResponseCode::NXDomain.0 => {
            is_authoritative_negative(resp, &question.name, zone)
        }

        code if code == ResponseCode::YXDomain.0 => is_dname_yxdomain(resp, &question.name),
        _ => false,
    }
}

/// NODATA, for example.
fn is_terminal_response(resp: &Message, qname: &Name, zone: &Name) -> bool {
    resp.header.rcode == ResponseCode::NoError.0
        && (is_authoritative_negative(resp, qname, zone)
            || is_bare_authoritative_nodata(resp, qname, zone))
}

/// Keeps only records related to the query name and zone; passing on unrelated records an
/// upstream added would poison the cache.
fn sanitize_terminal_response(
    response: &mut Message,
    qname: &Name,
    qtype: RecordType,
    positive: bool,
    proof_zone: Option<&Name>,
) {
    if positive {
        response.answers.retain(|record| {
            if record.class != DnsClass::IN || !record.name.eq_ignore_case(qname) {
                return false;
            }

            qtype == RecordType::ANY
                || record.rtype == qtype
                || record.rtype == RecordType::RRSIG
                    && onetdns_dnssec::Rrsig::from_record(record)
                        .is_some_and(|signature| signature.type_covered == qtype.0)
        });
        response.authorities.clear();
    } else {
        response.answers.clear();
        response.authorities.retain(|record| {
            if record.class != DnsClass::IN {
                return false;
            }
            let Some(zone) = proof_zone else {
                return false;
            };
            if !is_within(&record.name, zone) {
                return false;
            }
            match record.rtype {
                RecordType::SOA => record.name.eq_ignore_case(zone),
                RecordType::NSEC | RecordType::NSEC3 => true,
                RecordType::RRSIG => {
                    onetdns_dnssec::Rrsig::from_record(record).is_some_and(|signature| {
                        let covered = RecordType(signature.type_covered);
                        matches!(covered, RecordType::NSEC | RecordType::NSEC3)
                            || covered == RecordType::SOA && record.name.eq_ignore_case(zone)
                    })
                }
                _ => false,
            }
        });
    }
    response
        .additionals
        .retain(|record| record.rtype == RecordType::OPT);
}

struct AliasHop {
    target: Name,
    owner: Name,
    atype: RecordType,

    records: Vec<Record>,
}

/// DNAME takes precedence over CNAME.
fn alias_hop(resp: &Message, qname: &Name, qtype: RecordType) -> Option<AliasHop> {
    if resp.header.rcode == ResponseCode::NXDomain.0 {
        return None;
    }
    if let Some((dname_record, target, synthetic_cname)) = dname_rewrite(resp, qname) {
        let owner = dname_record.name.clone();
        let mut records = alias_rrset_records(resp, &owner, RecordType::DNAME);
        records.push(synthetic_cname);
        return Some(AliasHop {
            target,
            owner,
            atype: RecordType::DNAME,
            records,
        });
    }
    if has_direct_qtype_answer(resp, qname, qtype) {
        return None;
    }
    let target = cname_target(resp, qname)?;
    Some(AliasHop {
        target,
        owner: qname.clone(),
        atype: RecordType::CNAME,
        records: alias_rrset_records(resp, qname, RecordType::CNAME),
    })
}

/// Validation needs both.
fn alias_rrset_records(response: &Message, owner: &Name, alias_type: RecordType) -> Vec<Record> {
    response
        .answers
        .iter()
        .filter(|record| {
            record.name.eq_ignore_case(owner)
                && record.class == DnsClass::IN
                && (record.rtype == alias_type
                    || record.rtype == RecordType::RRSIG
                        && onetdns_dnssec::Rrsig::from_record(record)
                            .is_some_and(|signature| signature.type_covered == alias_type.0))
        })
        .cloned()
        .collect()
}

/// Only when the owner is valid.
fn cname_target(resp: &Message, qname: &Name) -> Option<Name> {
    if !cname_owner_is_valid(resp, qname) {
        return None;
    }
    let mut target: Option<Name> = None;
    for record in &resp.answers {
        let RData::Cname(candidate) = &record.rdata else {
            continue;
        };
        if record.class != DnsClass::IN || !record.name.eq_ignore_case(qname) {
            continue;
        }
        if target
            .as_ref()
            .is_some_and(|current| !current.eq_ignore_case(candidate))
        {
            return None;
        }
        target = Some(candidate.clone());
    }
    target
}

/// Different CNAMEs at one owner are refused: which to follow would be undecided.
fn cname_owner_is_valid(resp: &Message, owner: &Name) -> bool {
    let has_cname = resp.answers.iter().any(|record| {
        record.class == DnsClass::IN
            && record.rtype == RecordType::CNAME
            && record.name.eq_ignore_case(owner)
    });
    if !has_cname {
        return true;
    }
    resp.answers.iter().all(|record| {
        record.class != DnsClass::IN
            || !record.name.eq_ignore_case(owner)
            || matches!(
                record.rtype,
                RecordType::CNAME | RecordType::RRSIG | RecordType::NSEC
            )
    })
}

/// The longest owner wins; a shorter one would skip a more specific rule.
fn dname_rewrite(resp: &Message, qname: &Name) -> Option<(Record, Name, Record)> {
    let mut best: Option<&Record> = None;
    for record in &resp.answers {
        if record.class != DnsClass::IN {
            continue;
        }
        let RData::Dname(_) = &record.rdata else {
            continue;
        };
        let owner_labels = record.name.num_labels();
        if qname.num_labels() <= owner_labels
            || !qname.suffix(owner_labels).eq_ignore_case(&record.name)
        {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|current| current.name.num_labels() < owner_labels)
        {
            best = Some(record);
        }
    }
    let record = best?;
    let RData::Dname(target_suffix) = &record.rdata else {
        return None;
    };
    if resp.answers.iter().any(|candidate| {
        candidate.class == DnsClass::IN
            && candidate.name.eq_ignore_case(&record.name)
            && matches!(
                &candidate.rdata,
                RData::Dname(other) if !other.eq_ignore_case(target_suffix)
            )
    }) {
        return None;
    }
    let prefix_len = qname.num_labels() - record.name.num_labels();
    let mut labels: Vec<Vec<u8>> = qname
        .labels()
        .take(prefix_len)
        .map(<[u8]>::to_vec)
        .collect();
    labels.extend(target_suffix.labels().map(<[u8]>::to_vec));
    let target = Name::from_labels(labels).ok()?;
    let synthetic = Record::new(qname.clone(), record.ttl, RData::Cname(target.clone()));
    Some((record.clone(), target, synthetic))
}

pub fn default_roots() -> Vec<SocketAddr> {
    [
        [198, 41, 0, 4],
        [199, 9, 14, 201],
        [192, 33, 4, 12],
        [199, 7, 91, 13],
        [192, 203, 230, 10],
        [192, 5, 5, 241],
        [192, 112, 36, 4],
        [198, 97, 190, 53],
        [192, 36, 148, 17],
        [192, 58, 128, 30],
        [193, 0, 14, 129],
        [199, 7, 83, 42],
        [202, 12, 27, 33],
    ]
    .into_iter()
    .map(|octets| SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)), 53))
    .collect()
}

#[cfg(unix)]
/// Event-driven resolution lane: the same decisions as the synchronous path without holding a
/// thread.
pub mod reactor;

#[cfg(all(test, unix))]
#[path = "reactor_probe.rs"]
/// Test-only probe measuring the lane's lifetime and resource use.
mod reactor_probe;

#[cfg(all(test, target_os = "linux", target_env = "musl"))]
#[global_allocator]
/// Swapped in test builds only, so the probe can observe allocations.
static PROBE_ALLOC: onetdns_core::talloc::ThreadCachedSystem =
    onetdns_core::talloc::ThreadCachedSystem;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, UdpSocket};
    use std::sync::{Arc, Mutex};

    fn name_key(name: &str) -> Vec<u8> {
        Name::from_str(name).unwrap().canonical_key()
    }

    #[test]
    fn trace_lines_escape_control_characters_from_remote_names() {
        let remote =
            Name::from_labels(vec![b"a\nforged\x1b[2J".to_vec(), b"test".to_vec()]).unwrap();
        let line = escaped_trace(format_args!("name={remote}"));
        assert_eq!(line, "name=a\\x0aforged\\x1b[2J.test.");
    }

    #[test]
    fn wildcard_expansion_requires_authenticated_denial_proof() {
        use onetdns_dnssec::sign::{pick_denial_nsecs, sign_zone, ZoneSigner};

        let apex = Name::from_str("example.test").unwrap();
        let wildcard = Name::from_str("*.wild.example.test").unwrap();
        let qname = Name::from_str("host.wild.example.test").unwrap();
        let signer = ZoneSigner::generate(apex.clone(), [44u8; 32]);
        let now = 1_700_000_000u64;
        let signed = sign_zone(
            &[Record::new(
                wildcard,
                300,
                RData::A(Ipv4Addr::new(192, 0, 2, 44)),
            )],
            &signer,
            now,
        );
        let nsecs: Vec<Record> = signed
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC)
            .cloned()
            .collect();
        let proof = pick_denial_nsecs(&nsecs, &qname, true);
        let mut response = Message::default();
        for nsec in proof {
            response.authorities.push(nsec.clone());
            response.authorities.extend(
                signed
                    .iter()
                    .filter(|record| {
                        record.rtype == RecordType::RRSIG
                            && record.name.eq_ignore_case(&nsec.name)
                            && onetdns_dnssec::Rrsig::from_record(record).is_some_and(|signature| {
                                signature.type_covered == RecordType::NSEC.0
                            })
                    })
                    .cloned(),
            );
        }

        let mut budget = onetdns_dnssec::VerificationBudget::new();
        assert!(validated_wildcard_expansion(
            &response,
            &qname,
            3,
            WildcardValidation {
                keys: &[signer.dnskey()],
                apex: &apex,
                now: now as u32,
                nsec3_max_iterations: 0,
                verification_budget: &mut budget,
            },
        ));

        let (signing_key, dnskey) = ecdsa_key(44);
        let proof_records: Vec<Record> = response
            .authorities
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC)
            .cloned()
            .collect();
        response
            .authorities
            .retain(|record| record.rtype != RecordType::RRSIG);
        for proof in proof_records {
            response.authorities.push(rrsig_rec(
                &signing_key,
                &dnskey,
                ".",
                RecordType::NSEC.0,
                std::slice::from_ref(&proof),
            ));
        }
        let mut budget = onetdns_dnssec::VerificationBudget::new();
        assert!(
            !validated_wildcard_expansion(
                &response,
                &qname,
                3,
                WildcardValidation {
                    keys: &[dnskey],
                    apex: &apex,
                    now: now as u32,
                    nsec3_max_iterations: 0,
                    verification_budget: &mut budget,
                },
            ),
            "유효한 키로 서명했어도 NSEC signer가 leaf apex와 다르면 거부"
        );

        response.authorities.clear();
        let mut budget = onetdns_dnssec::VerificationBudget::new();
        assert!(!validated_wildcard_expansion(
            &response,
            &qname,
            3,
            WildcardValidation {
                keys: &[signer.dnskey()],
                apex: &apex,
                now: now as u32,
                nsec3_max_iterations: 0,
                verification_budget: &mut budget,
            },
        ));
    }

    #[test]
    fn ns_addr_cache_reuses_until_expiry() {
        let rec = Recursor::new(vec![], Duration::from_secs(1));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));

        let active = name_key("ns1.azure-dns.net.");
        rec.ns_addr_store(active.clone(), vec![ip], 300);
        assert_eq!(rec.ns_addr_cached(&active), Some(vec![ip]));

        {
            let mut cache = rec.ns_addr_cache.lock_recover();
            cache.put(
                name_key("stale.azure-dns.net."),
                NsAddrEntry {
                    addrs: vec![ip],
                    lifetime: TtlLifetime::expired(),
                },
            );
        }
        let stale = name_key("stale.azure-dns.net.");
        assert_eq!(rec.ns_addr_cached(&stale), None);
        assert!(!rec.ns_addr_cache.lock_recover().contains_key(&stale));
    }

    #[test]
    fn recursive_cache_keys_preserve_raw_name_octets() {
        let first = Name::from_labels(vec![vec![0xff]]).unwrap();
        let second = Name::from_labels(vec![vec![0xfe]]).unwrap();
        assert_ne!(first.canonical_key(), second.canonical_key());
        assert_eq!(
            Name::from_str("WWW.example").unwrap().canonical_key(),
            Name::from_str("www.EXAMPLE").unwrap().canonical_key()
        );

        let rec = Recursor::new(vec![], Duration::from_secs(1));
        let first_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let second_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        rec.ns_addr_store(first.canonical_key(), vec![first_ip], 300);
        rec.ns_addr_store(second.canonical_key(), vec![second_ip], 300);
        assert_eq!(
            rec.ns_addr_cached(&first.canonical_key()),
            Some(vec![first_ip])
        );
        assert_eq!(
            rec.ns_addr_cached(&second.canonical_key()),
            Some(vec![second_ip])
        );

        rec.deleg_store(&first, &[SocketAddr::new(first_ip, 53)], 300);
        rec.deleg_store(&second, &[SocketAddr::new(second_ip, 53)], 300);
        assert_eq!(
            rec.deleg_cached(&first),
            Some(vec![SocketAddr::new(first_ip, 53)])
        );
        assert_eq!(
            rec.deleg_cached(&second),
            Some(vec![SocketAddr::new(second_ip, 53)])
        );
        assert_ne!(
            InfraKey::new(first_ip, &first),
            InfraKey::new(first_ip, &second)
        );
    }

    #[test]
    fn zero_ttl_ns_state_is_not_cached_and_large_entries_are_bounded() {
        let rec = Recursor::new(vec![], Duration::from_secs(1));
        let zone = Name::from_str("example").unwrap();
        let addresses: Vec<IpAddr> = (0..100)
            .map(|n| IpAddr::V4(Ipv4Addr::new(192, 0, 2, n)))
            .collect();
        let servers: Vec<SocketAddr> = addresses
            .iter()
            .map(|address| SocketAddr::new(*address, 53))
            .collect();

        let zero = name_key("ns.zero.example");
        rec.ns_addr_store(zero.clone(), addresses.clone(), 0);
        rec.deleg_store(&zone, &servers, 0);
        assert!(rec.ns_addr_cached(&zero).is_none());
        assert!(rec.deleg_cached(&zone).is_none());

        let large = name_key("ns.large.example");
        rec.ns_addr_store(large.clone(), addresses, 300);
        rec.deleg_store(&zone, &servers, 300);
        assert_eq!(
            rec.ns_addr_cached(&large).unwrap().len(),
            MAX_CACHED_NS_ADDRS
        );
        assert_eq!(rec.deleg_cached(&zone).unwrap().len(), MAX_CACHED_NS_ADDRS);
    }

    #[test]
    fn recursive_ns_state_never_outlives_authoritative_ttl() {
        assert_eq!(std::mem::size_of::<TtlLifetime>(), 8);
        let rec = Recursor::new(vec![], Duration::from_secs(1));
        let zone = Name::from_str("example").unwrap();
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let key = name_key("ns.short.example");

        rec.ns_addr_store(key.clone(), vec![address], 1);
        rec.deleg_store(&zone, &[SocketAddr::new(address, 53)], 1);

        let ns_remaining = rec
            .ns_addr_cache
            .lock_recover()
            .peek(&key)
            .unwrap()
            .lifetime
            .remaining(cache_now_millis())
            .unwrap();
        let deleg_remaining = rec
            .deleg_cache
            .lock_recover()
            .peek(&zone.canonical_key())
            .unwrap()
            .lifetime
            .remaining(cache_now_millis())
            .unwrap();
        assert!(ns_remaining <= Duration::from_secs(1), "{ns_remaining:?}");
        assert!(
            deleg_remaining <= Duration::from_secs(1),
            "{deleg_remaining:?}"
        );

        rec.ns_addr_store(key.clone(), vec![address], 86_400);
        rec.deleg_store(&zone, &[SocketAddr::new(address, 53)], 86_400);
        let ns_remaining = rec
            .ns_addr_cache
            .lock_recover()
            .peek(&key)
            .unwrap()
            .lifetime
            .remaining(cache_now_millis())
            .unwrap();
        let deleg_remaining = rec
            .deleg_cache
            .lock_recover()
            .peek(&zone.canonical_key())
            .unwrap()
            .lifetime
            .remaining(cache_now_millis())
            .unwrap();
        assert!(
            ns_remaining > Duration::from_secs(3_600)
                && ns_remaining <= Duration::from_secs(86_400),
            "{ns_remaining:?}"
        );
        assert!(
            deleg_remaining > Duration::from_secs(3_600)
                && deleg_remaining <= Duration::from_secs(86_400),
            "{deleg_remaining:?}"
        );

        rec.ns_addr_store(key.clone(), vec![address], u32::MAX);
        let full_dns_ttl = rec
            .ns_addr_cache
            .lock_recover()
            .peek(&key)
            .unwrap()
            .lifetime
            .remaining(cache_now_millis())
            .unwrap()
            .as_secs();
        assert!(
            full_dns_ttl >= u64::from(u32::MAX) - 1,
            "전체 u32 TTL 범위를 미래 Instant 덧셈 없이 보존해야 함: {full_dns_ttl}"
        );
    }

    #[test]
    fn configured_max_ttl_bounds_every_recursive_cache() {
        assert_eq!(
            Recursor::new(vec![], Duration::from_secs(1))
                .with_recursive_cache_ttl_max(0)
                .recursive_cache_ttl_max,
            0
        );
        assert_eq!(
            Recursor::new(vec![], Duration::from_secs(1))
                .with_recursive_cache_ttl_max(u32::MAX)
                .recursive_cache_ttl_max,
            u32::MAX
        );

        let rec = Recursor::new(vec![], Duration::from_secs(1)).with_recursive_cache_ttl_max(5);
        let zone = Name::from_str("example").unwrap();
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let key = name_key("ns.configured.example");

        rec.ns_addr_store(key.clone(), vec![address], 300);
        rec.deleg_store(&zone, &[SocketAddr::new(address, 53)], 300);
        rec.dnskey_store(key.clone(), vec![], vec![], 300);

        let now = cache_now_millis();
        let configured_max = Duration::from_secs(5);
        assert!(
            rec.ns_addr_cache
                .lock_recover()
                .peek(&key)
                .unwrap()
                .lifetime
                .remaining(now)
                .unwrap()
                <= configured_max
        );
        assert!(
            rec.deleg_cache
                .lock_recover()
                .peek(&zone.canonical_key())
                .unwrap()
                .lifetime
                .remaining(now)
                .unwrap()
                <= configured_max
        );
        assert!(
            rec.dnskey_cache
                .lock_recover()
                .peek(&key)
                .unwrap()
                .lifetime
                .remaining(now)
                .unwrap()
                <= configured_max
        );
    }

    #[test]
    fn validated_key_cache_expires_and_follows_anchor_rotation() {
        let rec = Recursor::new(vec![], Duration::from_secs(1));
        let key = name_key("example");
        let anchors = std::sync::Arc::new(Vec::new());

        rec.validated_keys_store(
            key.clone(),
            ZoneTrust::Secure(Vec::new().into()),
            anchors.clone(),
            0,
        );
        assert!(rec.validated_keys_cached(&key, &anchors).is_none());

        rec.validated_keys_store(
            key.clone(),
            ZoneTrust::Secure(Vec::new().into()),
            anchors.clone(),
            300,
        );
        assert!(rec.validated_keys_cached(&key, &anchors).is_some());

        let rotated = std::sync::Arc::new(Vec::new());
        assert!(rec.validated_keys_cached(&key, &rotated).is_none());

        assert!(rec.validated_keys_cached(&key, &anchors).is_none());
    }

    #[test]
    #[ignore = "microbenchmark: run with --release -- --ignored --nocapture"]
    fn bench_validated_key_cache_hit() {
        let rec = Recursor::new(vec![], Duration::from_secs(1));
        let zone_key = name_key("bench.example");
        let anchors = rec.trust_anchors.load();
        let keys: Vec<onetdns_dnssec::Dnskey> = (0..2)
            .map(|seed| onetdns_dnssec::Dnskey {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                public_key: vec![seed; 64],
            })
            .collect();
        rec.validated_keys_store(
            zone_key.clone(),
            ZoneTrust::Secure(keys.into()),
            anchors.clone(),
            300,
        );

        const HITS: u32 = 1_000_000;
        let started = Instant::now();
        for _ in 0..HITS {
            std::hint::black_box(
                rec.validated_keys_cached(&zone_key, &anchors)
                    .expect("cache hit"),
            );
        }
        let elapsed = started.elapsed();
        println!(
            "validated-key-cache-hit: {:.1} ns/hit ({HITS} hits in {elapsed:?})",
            elapsed.as_nanos() as f64 / f64::from(HITS)
        );
    }

    #[test]
    fn dnskey_cache_honors_zero_ttl_and_expiry() {
        let rec = Recursor::new(vec![], Duration::from_secs(1));
        let key = name_key("example");
        let records = vec![Record::new(
            Name::from_str("example").unwrap(),
            300,
            RData::Unknown(RecordType::DNSKEY.0, vec![1, 2, 3]),
        )];
        let signatures = vec![onetdns_dnssec::Rrsig {
            type_covered: RecordType::DNSKEY.0,
            algorithm: 13,
            labels: 1,
            original_ttl: 300,
            expiration: now_secs().wrapping_add(300),
            inception: now_secs().wrapping_sub(60),
            key_tag: 1,
            signer: Name::from_str("example").unwrap(),
            signature: vec![0; 64],
        }];

        rec.dnskey_store(key.clone(), records.clone(), signatures.clone(), 0);
        assert!(rec.dnskey_cached(&key).is_none());

        rec.dnskey_store(key.clone(), records, signatures, 300);
        assert!(rec.dnskey_cached(&key).is_some());
        rec.dnskey_cache.lock_recover().put(
            key.clone(),
            DnskeyEntry {
                records: vec![],
                signatures: vec![],
                lifetime: TtlLifetime::expired(),
            },
        );
        assert!(rec.dnskey_cached(&key).is_none());
    }

    #[test]
    fn ds_rrsig_ttl_bounds_validated_key_cache_lifetime() {
        let child = Name::from_str("child.example").unwrap();
        let ds = onetdns_dnssec::Ds {
            key_tag: 1234,
            algorithm: 13,
            digest_type: 2,
            digest: vec![7; 32],
        };
        let ds_record = Record::new(
            child.clone(),
            300,
            RData::Unknown(RecordType::DS.0, ds.rdata_bytes()),
        );
        let signature = onetdns_dnssec::Rrsig {
            type_covered: RecordType::DS.0,
            algorithm: 13,
            labels: child.num_labels() as u8,
            original_ttl: 300,
            expiration: now_secs().wrapping_add(300),
            inception: now_secs().wrapping_sub(1),
            key_tag: 5678,
            signer: Name::from_str("example").unwrap(),
            signature: vec![9; 64],
        };
        let signature_record = Record::new(
            child.clone(),
            7,
            RData::Unknown(RecordType::RRSIG.0, signature.rdata_bytes()),
        );
        let mut response = Message::default();
        response.authorities = vec![ds_record, signature_record];

        let (ds_records, ds_rrsigs, _, _, _, _, parsed_ds) =
            extract_ds(&response.authorities, &child);
        assert_eq!(ds_records[0].ttl, 7);
        assert_eq!(ds_rrsigs.len(), 1);
        assert_eq!(parsed_ds, vec![ds]);

        let link = onetdns_dnssec::ChainLink {
            zone: child,
            dnskeys: vec![],
            dnskey_rrsigs: vec![],
            ds_records,
            ds_rrsigs,
            ds_nsec_records: vec![],
            ds_nsec_rrsigs: vec![],
            ds_nsec3_records: vec![],
            ds_nsec3_rrsigs: vec![],
            ds: parsed_ds,
        };
        assert_eq!(chain_validity_ttl(&[link], now_secs()), 7);
    }

    #[test]
    fn extract_ds_parses_each_denial_signature_once() {
        let (signing_key, key) = ecdsa_key(93);
        let child = Name::from_str("child.example").unwrap();
        let nsec = nsec_rec(
            "child.example",
            "z.example",
            &[RecordType::NS.0, RecordType::RRSIG.0, RecordType::NSEC.0],
        );
        let signature = rrsig_rec(
            &signing_key,
            &key,
            "example",
            RecordType::NSEC.0,
            std::slice::from_ref(&nsec),
        );
        let mut response = Message::default();
        response.authorities = vec![nsec.clone(), nsec, signature];

        let (_, _, nsecs, nsec_sigs, _, _, _) = extract_ds(&response.authorities, &child);
        assert_eq!(nsecs.len(), 2, "입력 RR은 손실 없이 보존한다");
        assert_eq!(
            nsec_sigs.len(),
            1,
            "같은 owner의 NSEC가 중복돼도 RRSIG 한 개를 제곱 복제하면 안 된다"
        );
    }

    #[test]
    fn delegation_cache_deepest_evict_and_expiry() {
        let rec = Recursor::new(vec![], Duration::from_secs(1));
        let com = Name::from_str("com").unwrap();
        let ms = Name::from_str("microsoft.com").unwrap();
        let com_srv = vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 5, 6, 30)),
            53,
        )];
        let ms_srv = vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(13, 107, 222, 41)),
            53,
        )];
        rec.deleg_store(&com, &com_srv, 3600);
        rec.deleg_store(&ms, &ms_srv, 3600);

        let q = Name::from_str("eu-mobile.events.data.microsoft.com").unwrap();
        let (zone, servers) = rec
            .deepest_cached_delegation(&q)
            .expect("cached delegation");
        assert_eq!(zone.to_ascii_lower(), "microsoft.com");
        assert_eq!(servers, ms_srv);

        rec.deleg_evict_path(&q);
        assert!(rec.deepest_cached_delegation(&q).is_none());

        {
            let mut cache = rec.deleg_cache.lock_recover();
            cache.put(
                com.canonical_key(),
                DelegationEntry {
                    servers: com_srv.clone(),
                    lifetime: TtlLifetime::expired(),
                },
            );
        }
        assert!(rec.deleg_cached(&com).is_none());
    }

    #[test]
    fn recursive_state_caches_enforce_exact_lru_capacity() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let rec = Recursor::new(vec![], Duration::from_secs(1)).with_ns_cache_max(2);

        let ns1 = name_key("ns1.test");
        let ns2 = name_key("ns2.test");
        rec.ns_addr_store(ns1.clone(), vec![ip1], 300);
        rec.ns_addr_store(ns2.clone(), vec![ip2], 300);
        assert_eq!(rec.ns_addr_cached(&ns1), Some(vec![ip1]));
        rec.ns_addr_store(name_key("ns3.test"), vec![ip1], 300);
        assert!(rec.ns_addr_cached(&ns2).is_none());
        assert_eq!(rec.ns_addr_cache.lock_recover().len(), 2);

        let a = Name::from_str("a.test").unwrap();
        let b = Name::from_str("b.test").unwrap();
        let c = Name::from_str("c.test").unwrap();
        let server = [SocketAddr::new(ip1, 53)];
        rec.deleg_store(&a, &server, 300);
        rec.deleg_store(&b, &server, 300);
        assert!(rec.deleg_cached(&a).is_some());
        rec.deleg_store(&c, &server, 300);
        assert!(rec.deleg_cached(&b).is_none());
        assert_eq!(rec.deleg_cache.lock_recover().len(), 2);

        rec.infra_fail(ip1, &a);
        rec.infra_fail(ip1, &b);
        rec.infra_protocol_error(ip1, &a);
        rec.infra_fail(ip1, &c);
        let infra = rec.infra.lock_recover();
        assert!(infra.peek(&InfraKey::new(ip1, &a)).is_some());
        assert!(infra.peek(&InfraKey::new(ip1, &b)).is_none());
        assert!(infra.peek(&InfraKey::new(ip1, &c)).is_some());
        assert_eq!(infra.len(), 2);
        drop(infra);

        let ip3 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));
        rec.record_rtt(ip1, Duration::from_millis(10));
        rec.record_rtt(ip2, Duration::from_millis(10));
        rec.record_rtt(ip3, Duration::from_millis(10));
        assert!(rec.srtt(ip1).is_none());
        assert_eq!(rec.rtt.lock_recover().len(), 2);

        let key1 = name_key("key1.test");
        let key2 = name_key("key2.test");
        rec.dnskey_store(key1.clone(), vec![], vec![], 300);
        rec.dnskey_store(key2.clone(), vec![], vec![], 300);
        assert!(rec.dnskey_cached(&key1).is_some());
        rec.dnskey_store(name_key("key3.test"), vec![], vec![], 300);
        assert!(rec.dnskey_cached(&key2).is_none());
        assert_eq!(rec.dnskey_cache.lock_recover().len(), 2);

        let anchors = rec.trust_anchors.load();
        let validated1 = name_key("validated1.test");
        let validated2 = name_key("validated2.test");
        rec.validated_keys_store(
            validated1.clone(),
            ZoneTrust::Secure(Vec::new().into()),
            anchors.clone(),
            300,
        );
        rec.validated_keys_store(
            validated2.clone(),
            ZoneTrust::Secure(Vec::new().into()),
            anchors.clone(),
            300,
        );
        assert!(rec.validated_keys_cached(&validated1, &anchors).is_some());
        rec.validated_keys_store(
            name_key("validated3.test"),
            ZoneTrust::Secure(Vec::new().into()),
            anchors.clone(),
            300,
        );
        assert!(rec.validated_keys_cached(&validated2, &anchors).is_none());
        assert_eq!(rec.validated_keys.lock_recover().len(), 2);
    }

    #[test]
    fn non_in_records_cannot_drive_answers_referrals_or_glue() {
        let qname = Name::from_str("host.test").unwrap();
        let mut response = Message::query(1, qname.clone(), RecordType::A);
        response.header.response = true;
        response.header.authoritative = true;

        let mut answer = Record::new(qname.clone(), 300, RData::A(Ipv4Addr::new(192, 0, 2, 1)));
        answer.class = DnsClass(3);
        response.answers.push(answer);
        assert!(!has_direct_qtype_answer(&response, &qname, RecordType::A));

        response.answers.clear();
        response.header.authoritative = false;
        let zone = Name::from_str("test").unwrap();
        let ns = Name::from_str("ns.test").unwrap();
        let mut referral = Record::new(zone.clone(), 300, RData::Ns(ns.clone()));
        referral.class = DnsClass(3);
        response.authorities.push(referral);
        let mut glue = Record::new(ns.clone(), 300, RData::A(Ipv4Addr::new(192, 0, 2, 53)));
        glue.class = DnsClass(3);
        response.additionals.push(glue);
        assert!(extract_referral(&response, &qname).0.is_none());

        let rec = Recursor::new(vec![], Duration::from_secs(1));
        assert!(rec.glue_addrs(&response, &[ns], &zone).0.is_empty());
    }

    #[test]
    fn any_query_accepts_normal_rrset_response() {
        let qname = Name::from_str("host.test").unwrap();
        let zone = Name::from_str("test").unwrap();
        let mut resp = Message::query(1, qname.clone(), RecordType::ANY);
        resp.header.response = true;
        resp.header.authoritative = true;
        resp.answers.push(Record::new(
            qname.clone(),
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ));
        resp.answers.push(Record::new(
            qname.clone(),
            300,
            RData::Aaaa("2001:db8::1".parse().unwrap()),
        ));

        assert!(
            has_direct_qtype_answer(&resp, &qname, RecordType::ANY),
            "A/AAAA를 가진 ANY 응답은 직접 답변이어야 한다"
        );
        assert!(is_relevant_positive(&resp, &qname, RecordType::ANY));
        let req = Message::query(1, qname.clone(), RecordType::ANY);
        assert!(response_usable_for_iteration(&resp, &req, &zone));

        let mut out = resp.clone();
        sanitize_terminal_response(&mut out, &qname, RecordType::ANY, true, None);
        assert_eq!(
            out.answers.len(),
            2,
            "ANY 응답의 A·AAAA RRset이 유지되어야 한다"
        );
    }

    #[test]
    /// Otherwise the next server is tried, and a zone whose servers all answer this way gets
    /// SERVFAIL. No AA bit, a delegation, an out-of-zone name or mixed answers mean it is not
    /// NODATA.
    fn bare_authoritative_nodata_is_terminal_and_usable() {
        let qname = Name::from_str("host.gslb.test").unwrap();
        let zone = Name::from_str("gslb.test").unwrap();
        let query = Message::query(1, qname.clone(), RecordType::AAAA);
        let mut resp = query.clone();
        resp.header.response = true;
        resp.header.authoritative = true;

        assert!(response_usable_for_iteration(&resp, &query, &zone));
        assert!(is_terminal_response(&resp, &qname, &zone));

        let mut not_authoritative = resp.clone();
        not_authoritative.header.authoritative = false;
        assert!(!response_usable_for_iteration(
            &not_authoritative,
            &query,
            &zone
        ));
        assert!(!is_terminal_response(&not_authoritative, &qname, &zone));

        let mut delegation = resp.clone();
        delegation.authorities.push(Record::new(
            qname.clone(),
            300,
            RData::Ns(Name::from_str("ns.host.gslb.test").unwrap()),
        ));
        assert!(!is_bare_authoritative_nodata(&delegation, &qname, &zone));
        assert!(!is_terminal_response(&delegation, &qname, &zone));

        let other_zone = Name::from_str("other.test").unwrap();
        assert!(!is_bare_authoritative_nodata(&resp, &qname, &other_zone));
        assert!(!is_terminal_response(&resp, &qname, &other_zone));

        let mut unrelated_answer = resp.clone();
        unrelated_answer.answers.push(Record::new(
            Name::from_str("elsewhere.gslb.test").unwrap(),
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ));
        assert!(!is_terminal_response(&unrelated_answer, &qname, &zone));
    }

    #[test]
    fn dname_yxdomain_is_terminal_and_usable() {
        let owner = Name::from_str("sub.test").unwrap();
        let qname = Name::from_str("x.sub.test").unwrap();
        let zone = Name::from_str("test").unwrap();
        let mut resp = Message::query(1, qname.clone(), RecordType::A);
        resp.header.response = true;
        resp.header.authoritative = true;
        resp.header.rcode = ResponseCode::YXDomain.0;
        resp.answers.push(Record::new(
            owner.clone(),
            300,
            RData::Dname(Name::from_str("target.example").unwrap()),
        ));

        assert!(is_dname_yxdomain(&resp, &qname));
        let req = Message::query(1, qname.clone(), RecordType::A);
        assert!(
            response_usable_for_iteration(&resp, &req, &zone),
            "권한적 YXDOMAIN은 재시도 대상이 아니라 usable해야 한다"
        );

        assert!(!is_dname_yxdomain(&resp, &owner));
    }

    #[test]
    fn dname_covering_qname_wins_over_synthetic_cname() {
        let owner = Name::from_str("sub.test").unwrap();
        let qname = Name::from_str("a.sub.test").unwrap();
        let mut resp = Message::query(1, qname.clone(), RecordType::CNAME);
        resp.header.response = true;
        resp.header.authoritative = true;
        resp.answers.push(Record::new(
            owner.clone(),
            300,
            RData::Dname(Name::from_str("dst.example").unwrap()),
        ));
        resp.answers.push(Record::new(
            qname.clone(),
            300,
            RData::Cname(Name::from_str("a.dst.example").unwrap()),
        ));

        assert!(has_direct_qtype_answer(&resp, &qname, RecordType::CNAME));
        assert!(
            dname_rewrite(&resp, &qname).is_some(),
            "DNAME이 qname을 덮으면 별칭 경로(합성 CNAME보다 우선)를 타야 한다"
        );
    }

    #[test]
    fn rrsig_query_is_insecure_not_bogus() {
        let rec = Recursor::new(vec![], Duration::from_secs(1));
        let qname = Name::from_str("host.test").unwrap();
        let mut resp = Message::query(1, qname.clone(), RecordType::RRSIG);
        resp.header.response = true;
        let status = rec.validate_answer_status(
            &qname,
            RecordType::RRSIG,
            &resp,
            &[],
            Instant::now() + Duration::from_secs(1),
        );
        assert!(
            matches!(status, SecurityStatus::Insecure),
            "qtype=RRSIG는 Insecure여야 한다(Bogus 아님): {status:?}"
        );
    }

    #[test]
    fn nat64_local_use_prefix_is_not_globally_routable() {
        assert!(
            !is_globally_routable("64:ff9b:1::808:808".parse().unwrap()),
            "64:ff9b:1::/48은 비라우팅이어야 한다"
        );

        assert!(is_globally_routable("64:ff9b::808:808".parse().unwrap()));
        assert!(
            !is_globally_routable("64:ff9b::a9fe:a9fe".parse().unwrap()),
            "64:ff9b::169.254.169.254는 특수라 거부"
        );
    }

    #[test]
    fn dname_rewrite_uses_longest_matching_owner() {
        let qname = Name::from_str("www.deep.old.example").unwrap();
        let mut response = Message::default();
        response.answers.push(Record::new(
            Name::from_str("old.example").unwrap(),
            300,
            RData::Dname(Name::from_str("broad.example.net").unwrap()),
        ));
        response.answers.push(Record::new(
            Name::from_str("deep.old.example").unwrap(),
            120,
            RData::Dname(Name::from_str("specific.example.net").unwrap()),
        ));

        let (source, target, synthetic) = dname_rewrite(&response, &qname).expect("DNAME rewrite");
        assert_eq!(source.name.to_ascii_lower(), "deep.old.example");
        assert_eq!(target.to_ascii_lower(), "www.specific.example.net");
        assert_eq!(synthetic.ttl, 120);
        assert!(matches!(
            synthetic.rdata,
            RData::Cname(ref name) if name.to_ascii_lower() == "www.specific.example.net"
        ));
    }

    #[test]
    fn out_of_bailiwick_dname_is_stripped() {
        let zone = Name::from_str("sub.example.com").unwrap();
        let mut resp = Message::default();
        resp.answers.push(Record::new(
            Name::from_str("sub.example.com").unwrap(),
            300,
            RData::Dname(Name::from_str("ok.example.net").unwrap()),
        ));
        resp.answers.push(Record::new(
            Name::from_str("example.com").unwrap(),
            300,
            RData::Dname(Name::from_str("evil.example.net").unwrap()),
        ));
        resp.answers.push(Record::new(
            Name::from_str("host.sub.example.com").unwrap(),
            300,
            RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        ));

        strip_out_of_bailiwick_dnames(&mut resp, &zone);

        assert_eq!(resp.answers.len(), 2, "bailiwick 밖 DNAME 1건 제거");
        assert!(
            resp.answers
                .iter()
                .all(|r| !matches!(&r.rdata, RData::Dname(_)) || is_within(&r.name, &zone)),
            "남은 DNAME은 zone 이내여야 함"
        );
        assert!(
            resp.answers.iter().any(|r| matches!(&r.rdata, RData::A(_))),
            "비-DNAME 레코드는 유지"
        );
    }

    #[test]
    fn conflicting_alias_data_is_not_accepted_as_an_answer() {
        let qname = Name::from_str("www.example").unwrap();
        let zone = Name::from_str("example").unwrap();
        let query = Message::query(1, qname.clone(), RecordType::A);
        let mut response = query.clone();
        response.header.response = true;
        response.header.authoritative = true;
        response.answers.push(Record::new(
            qname.clone(),
            300,
            RData::Cname(Name::from_str("target.example").unwrap()),
        ));
        response.answers.push(Record::new(
            qname.clone(),
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ));

        assert!(cname_target(&response, &qname).is_none());
        assert!(!is_relevant_positive(&response, &qname, RecordType::A));
        assert!(!response_usable_for_iteration(&response, &query, &zone));

        response.answers.clear();
        let owner = Name::from_str("example").unwrap();
        response.answers.push(Record::new(
            owner.clone(),
            300,
            RData::Dname(Name::from_str("one.example.net").unwrap()),
        ));
        response.answers.push(Record::new(
            owner,
            300,
            RData::Dname(Name::from_str("two.example.net").unwrap()),
        ));
        assert!(dname_rewrite(&response, &qname).is_none());
    }

    #[test]
    fn infra_orders_fast_first_failed_last() {
        let r = Recursor::new(vec![], Duration::from_millis(100));
        let fast: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let slow: SocketAddr = "9.9.9.9:53".parse().unwrap();
        let dead: SocketAddr = "1.0.0.1:53".parse().unwrap();
        let zone = Name::from_str("example").unwrap();
        r.infra_success(fast.ip(), &zone, Duration::from_millis(5));
        r.infra_success(slow.ip(), &zone, Duration::from_millis(200));
        r.infra_fail(dead.ip(), &zone);

        assert_eq!(
            r.order_by_infra(&[dead, slow, fast], &zone),
            vec![fast, slow, dead]
        );
    }

    #[test]
    fn ip_family_filter_and_prefer() {
        let v4: SocketAddr = "1.2.3.4:53".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        let servers = [v4, v6];
        let zone = Name::from_str("example").unwrap();

        let r = Recursor::new(vec![], Duration::from_millis(50)).with_ip_family(true, false, None);
        assert_eq!(r.order_by_infra(&servers, &zone), vec![v4]);

        let r = Recursor::new(vec![], Duration::from_millis(50)).with_ip_family(false, true, None);
        assert_eq!(r.order_by_infra(&servers, &zone), vec![v6]);

        let r =
            Recursor::new(vec![], Duration::from_millis(50)).with_ip_family(true, true, Some(true));
        assert_eq!(r.order_by_infra(&servers, &zone).first(), Some(&v6));
    }

    #[test]
    fn root_key_sentinel_rfc8509() {
        let r = Recursor::with_default_roots(Duration::from_millis(50)).with_dnssec();
        let mk = |qname: &str| {
            let mut m = Message::query(1, Name::from_str(qname).unwrap(), RecordType::A);
            m.header.authentic_data = true;
            m.answers.push(Record::new(
                Name::from_str(qname).unwrap(),
                60,
                RData::A(Ipv4Addr::new(1, 2, 3, 4)),
            ));
            m
        };
        let apply = |q: &str| {
            let mut m = mk(q);
            r.apply_sentinel(&Name::from_str(q).unwrap(), RecordType::A, &mut m);
            m
        };

        let m = apply("root-key-sentinel-is-ta-20326.example.com");
        assert_eq!(m.header.rcode, ResponseCode::NoError.0);
        assert!(!m.answers.is_empty());

        assert_eq!(
            apply("root-key-sentinel-is-ta-00001.example.com")
                .header
                .rcode,
            ResponseCode::ServFail.0
        );

        assert_eq!(
            apply("root-key-sentinel-not-ta-20326.example.com")
                .header
                .rcode,
            ResponseCode::ServFail.0
        );

        assert_eq!(
            apply("root-key-sentinel-not-ta-00001.example.com")
                .header
                .rcode,
            ResponseCode::NoError.0
        );

        assert_eq!(
            apply("kskroll-sentinel-is-ta-00001.example.com")
                .header
                .rcode,
            ResponseCode::NoError.0,
            "초안의 라벨은 RFC 8509 센티널이 아니다"
        );
        assert_eq!(
            apply("root-key-sentinel-is-ta-1.example.com").header.rcode,
            ResponseCode::NoError.0,
            "key tag는 다섯 자리여야 한다"
        );

        let mut m = mk("root-key-sentinel-is-ta-00001.example.com");
        m.header.authentic_data = false;
        r.apply_sentinel(
            &Name::from_str("root-key-sentinel-is-ta-00001.example.com").unwrap(),
            RecordType::A,
            &mut m,
        );
        assert_eq!(m.header.rcode, ResponseCode::NoError.0);
    }

    #[test]
    fn domain_insecure_suffix_match() {
        let r = Recursor::new(vec![], Duration::from_millis(50))
            .with_domain_insecure(vec![Name::from_str("internal.example").unwrap()]);
        assert!(r.is_domain_insecure(&Name::from_str("host.internal.example").unwrap()));
        assert!(r.is_domain_insecure(&Name::from_str("internal.example").unwrap()));
        assert!(!r.is_domain_insecure(&Name::from_str("host.example").unwrap()));
    }

    #[test]
    fn infra_success_clears_fail_cooldown() {
        let r = Recursor::new(vec![], Duration::from_millis(100));
        let ip: IpAddr = "8.8.4.4".parse().unwrap();
        let zone = Name::from_str("example").unwrap();
        let key = InfraKey::new(ip, &zone);
        let score = |r: &Recursor| {
            infra_score(
                r.infra.lock_recover().peek(&key),
                r.srtt(ip),
                Instant::now(),
            )
        };
        r.infra_fail(ip, &zone);
        assert!(score(&r) >= INFRA_FAIL_PENALTY_MS, "실패는 큰 점수");

        r.infra_success(ip, &zone, Duration::from_millis(10));
        assert!(score(&r) < 100, "성공 후 작은 점수");
    }

    #[test]
    /// Pushed back but still listed, since the query must ask it when the first server does not
    /// answer.
    fn failed_servers_are_asked_last_until_cooldown_expires() {
        let r = Recursor::new(vec![], Duration::from_millis(100));
        let failed: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let healthy: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let zone = Name::from_str("example").unwrap();
        let key = InfraKey::new(failed.ip(), &zone);
        r.infra_fail(failed.ip(), &zone);
        assert_eq!(
            r.order_by_infra(&[failed, healthy], &zone),
            vec![healthy, failed]
        );

        {
            let mut infra = r.infra.lock_recover();
            infra.get_mut(&key).unwrap().last_fail =
                Instant::now().checked_sub(INFRA_FAIL_COOLDOWN + Duration::from_secs(1));
        }
        let ordered = r.order_by_infra(&[failed, healthy], &zone);
        assert!(ordered.contains(&failed) && ordered.contains(&healthy));
    }

    #[test]
    /// Dropping a once-failed server from the list would fail the query when the remaining server
    /// is silent, even though the dropped one has recovered.
    fn a_recently_failed_server_is_still_asked_when_the_preferred_one_is_silent() {
        const PORT: u16 = 5425;
        let recovered = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 94)), PORT);
        let silent_sock = UdpSocket::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 95)),
            PORT,
        ))
        .unwrap();
        let silent = silent_sock.local_addr().unwrap();
        spawn_server("127.0.0.94", PORT, |req| {
            a_answer(req, Ipv4Addr::new(192, 0, 2, 94))
        });

        let recursor = Recursor::new(vec![], Duration::from_secs(2))
            .with_port(PORT)
            .with_test_loopback();
        let zone = Name::from_str("recover.test").unwrap();
        recursor.infra_success(silent.ip(), &zone, Duration::from_millis(5));
        recursor.infra_fail(recovered.ip(), &zone);
        assert_eq!(
            recursor.order_by_infra(&[recovered, silent], &zone),
            vec![silent, recovered]
        );

        let query = make_query(
            &Name::from_str("a.recover.test").unwrap(),
            RecordType::A,
            false,
        );
        let answer = recursor
            .query_any(
                &[recovered, silent],
                &query,
                &zone,
                recursor.query_deadline(),
            )
            .expect("답하지 않는 서버 다음에 되살아난 서버에 묻지 않았습니다");
        assert_eq!(answer.answers.len(), 1);
        drop(silent_sock);
    }

    #[test]
    /// A server that failed once may have lost one packet and is still asked. Asking servers that
    /// failed repeatedly would spend the full timeout on each query, and ending in `NoReachableNs`
    /// would keep the bin from moving to the fallback.
    fn a_zone_whose_servers_all_failed_repeatedly_fails_fast() {
        let blackhole = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = blackhole.local_addr().unwrap();
        let recursor = Recursor::new(vec![], Duration::from_secs(2))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]);
        let zone = Name::from_str("down.test").unwrap();
        let query = make_query(
            &Name::from_str("a.down.test").unwrap(),
            RecordType::A,
            false,
        );

        for _ in 1..SERVER_DOWN_AFTER_FAILURES {
            recursor.infra_fail(server.ip(), &zone);
        }
        assert_eq!(
            recursor.order_by_infra(&[server], &zone),
            vec![server],
            "몇 번 실패했을 뿐인 서버는 여전히 물어야 합니다"
        );

        recursor.infra_fail(server.ip(), &zone);
        let started = Instant::now();
        assert!(matches!(
            recursor.query_any(&[server], &query, &zone, recursor.query_deadline()),
            Err(RecurseError::NoResponse)
        ));
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "내려간 서버에 다시 물었습니다: {:?}",
            started.elapsed()
        );
    }

    #[test]
    /// Failures while the server is down are not counted, so queries sent just before it went down
    /// do not push the back-off straight to the maximum.
    fn a_down_server_backs_off_exponentially() {
        let r = Recursor::new(vec![], Duration::from_millis(100));
        let ip: IpAddr = "192.0.2.53".parse().unwrap();
        let server = SocketAddr::new(ip, 53);
        let zone = Name::from_str("example").unwrap();
        let key = InfraKey::new(ip, &zone);
        let failed_ago = |r: &Recursor, ago: Duration| {
            r.infra.lock_recover().get_mut(&key).unwrap().last_fail =
                Instant::now().checked_sub(ago);
        };

        for _ in 0..SERVER_DOWN_AFTER_FAILURES + 3 {
            r.infra_fail(ip, &zone);
        }
        assert_eq!(
            r.infra
                .lock_recover()
                .peek(&key)
                .unwrap()
                .consecutive_failures,
            SERVER_DOWN_AFTER_FAILURES,
            "내려가 있는 동안의 실패를 셌습니다"
        );
        assert!(r.order_by_infra(&[server], &zone).is_empty());

        failed_ago(&r, SERVER_DOWN_BASE + Duration::from_secs(1));
        assert_eq!(r.order_by_infra(&[server], &zone), vec![server]);

        r.infra_fail(ip, &zone);
        failed_ago(&r, SERVER_DOWN_BASE + Duration::from_secs(1));
        assert!(
            r.order_by_infra(&[server], &zone).is_empty(),
            "다시 실패했는데 묻지 않는 기간이 늘지 않았습니다"
        );
        failed_ago(&r, SERVER_DOWN_BASE * 2 + Duration::from_secs(1));
        assert_eq!(r.order_by_infra(&[server], &zone), vec![server]);

        // Moves the check time forward rather than the failure time back: Instant counts from
        // around boot, so on a host up for less than the maximum the failure time cannot move that
        // far back.
        let mut infra = r.infra.lock_recover();
        let state = infra.get_mut(&key).unwrap();
        state.consecutive_failures = u8::MAX;
        let failed_at = state.last_fail.expect("마지막 실패 시각");
        assert!(state.down(failed_at + SERVER_DOWN_MAX - Duration::from_secs(1)));
        assert!(
            !state.down(failed_at + SERVER_DOWN_MAX + Duration::from_secs(1)),
            "묻지 않는 기간이 상한을 넘었습니다"
        );
    }

    #[test]
    fn recursion_policy_rejection_is_not_reported_as_transport_failure() {
        let recursor = Recursor::new(vec![], Duration::from_millis(10));
        let blocked: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let zone = Name::root();
        let query = make_query(&Name::from_str("example").unwrap(), RecordType::A, false);

        assert!(matches!(
            recursor.query_any(&[blocked], &query, &zone, recursor.query_deadline()),
            Err(RecurseError::NoReachableNs)
        ));
    }

    #[test]
    fn authority_exchange_obeys_the_shared_resolution_deadline() {
        let blackhole = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = blackhole.local_addr().unwrap();
        let recursor = Recursor::new(vec![], Duration::from_secs(2))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]);
        let zone = Name::root();
        let query = make_query(&Name::from_str("example").unwrap(), RecordType::A, false);
        let started = Instant::now();

        assert!(matches!(
            recursor.query_any(
                &[server],
                &query,
                &zone,
                Instant::now() + Duration::from_millis(80)
            ),
            Err(RecurseError::NoResponse)
        ));
        assert!(
            started.elapsed() < Duration::from_millis(750),
            "전체 해석 마감시각이 서버별 2초 timeout보다 우선해야 함"
        );
    }

    #[test]
    fn dns_protocol_error_does_not_open_transport_cooldown() {
        let recursor = Recursor::new(vec![], Duration::from_millis(100));
        let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let zone = Name::from_str("example").unwrap();

        recursor.infra_protocol_error(server.ip(), &zone);
        assert_eq!(
            recursor.order_by_infra(&[server], &zone),
            vec![server],
            "SERVFAIL/REFUSED/lame response must remain a DNS response, not transport outage"
        );
    }

    #[test]
    /// Parent and child zones often share servers; treating a server measured slow in the child as
    /// new in the parent would ask it first for the parent's DNSKEY.
    fn round_trip_time_is_shared_across_zones() {
        let recursor = Recursor::new(vec![], Duration::from_millis(100));
        let slow: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let fresh: SocketAddr = "9.9.9.9:53".parse().unwrap();
        let child = Name::from_str("ris.example").unwrap();
        let parent = Name::from_str("example").unwrap();

        recursor.infra_success(slow.ip(), &child, Duration::from_millis(800));
        assert_eq!(
            recursor.order_by_infra(&[slow, fresh], &parent),
            vec![fresh, slow]
        );
    }

    #[test]
    fn infra_failure_is_scoped_to_zone() {
        let recursor = Recursor::new(vec![], Duration::from_millis(100));
        let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let failed_zone = Name::from_str("example").unwrap();
        let other_zone = Name::from_str("net").unwrap();

        let healthy: SocketAddr = "1.1.1.1:53".parse().unwrap();
        recursor.infra_fail(server.ip(), &failed_zone);

        assert_eq!(
            recursor.order_by_infra(&[server, healthy], &failed_zone),
            vec![healthy, server]
        );

        let other = recursor.order_by_infra(&[server, healthy], &other_zone);
        assert!(other.contains(&server) && other.contains(&healthy));
    }

    #[test]
    fn with_dnssec_activates_validation() {
        let plain = Recursor::with_default_roots(Duration::from_secs(1));
        assert!(!plain.validating(), "기본은 검증 비활성");
        let secure = Recursor::with_default_roots(Duration::from_secs(1)).with_dnssec();
        assert!(secure.validating(), "with_dnssec → 루트 앵커로 검증 활성");
        assert_eq!(secure.trust_anchors.load()[0].key_tag, 20326);
    }

    #[test]
    fn ssrf_default_denies_internal_servers() {
        let r = Recursor::with_default_roots(Duration::from_secs(1));
        assert!(
            !r.is_queryable("169.254.169.254".parse().unwrap()),
            "클라우드 메타데이터 거부"
        );
        assert!(!r.is_queryable("127.0.0.1".parse().unwrap()), "루프백 거부");
        assert!(!r.is_queryable("10.0.0.5".parse().unwrap()), "사설 거부");
        assert!(!r.is_queryable("192.168.1.1".parse().unwrap()), "사설 거부");
        assert!(!r.is_queryable("::1".parse().unwrap()), "v6 루프백 거부");
        assert!(!r.is_queryable("fd00::1".parse().unwrap()), "v6 ULA 거부");

        assert!(
            !r.is_queryable("::ffff:127.0.0.1".parse().unwrap()),
            "IPv4-mapped 루프백 거부"
        );
        assert!(
            !r.is_queryable("64:ff9b::7f00:1".parse().unwrap()),
            "NAT64 well-known 루프백 거부"
        );
        assert!(
            !r.is_queryable("64:ff9b::a00:1".parse().unwrap()),
            "NAT64 사설 거부"
        );
        assert!(
            !r.is_queryable("64:ff9b:1::a9fe:a9fe".parse().unwrap()),
            "NAT64 local-use 메타데이터 거부"
        );
        assert!(
            !r.is_queryable("2002:7f00:1::".parse().unwrap()),
            "6to4 루프백 거부"
        );
        assert!(
            !r.is_queryable("2002:a00:1::".parse().unwrap()),
            "6to4 사설 거부"
        );
        assert!(
            !r.is_queryable("::127.0.0.1".parse().unwrap()),
            "IPv4-compatible 루프백 거부"
        );
        assert!(
            !r.is_queryable("fec0::1".parse().unwrap()),
            "deprecated site-local 거부"
        );

        assert!(
            r.is_queryable("64:ff9b::808:808".parse().unwrap()),
            "NAT64로 매핑된 전역 8.8.8.8 허용"
        );
        assert!(
            r.is_queryable("2002:808:808::".parse().unwrap()),
            "6to4로 매핑된 전역 8.8.8.8 허용"
        );

        let alternate_port = Recursor::with_default_roots(Duration::from_secs(1)).with_port(5353);
        assert!(
            !alternate_port.is_queryable("127.0.0.1".parse().unwrap()),
            "권한 포트 변경이 루프백/SSRF ACL을 암묵적으로 해제하면 안 됨"
        );

        assert!(r.is_queryable("8.8.8.8".parse().unwrap()), "전역 허용");
        assert!(
            r.is_queryable("2001:4860:4860::8888".parse().unwrap()),
            "전역 v6 허용"
        );

        let r2 = r.with_server_acl(vec![], vec!["10.0.0.0/8".parse().unwrap()]);
        assert!(
            r2.is_queryable("10.0.0.5".parse().unwrap()),
            "allow 명시 → 사설 허용"
        );

        let r3 = Recursor::with_default_roots(Duration::from_secs(1))
            .with_server_acl(vec!["8.8.8.0/24".parse().unwrap()], vec![]);
        assert!(
            !r3.is_queryable("8.8.8.8".parse().unwrap()),
            "deny 명시 → 전역도 거부"
        );
    }

    #[test]
    fn dnssec_strict_flag_plumbs() {
        let r = Recursor::with_default_roots(Duration::from_secs(1));
        assert!(!r.strict, "기본은 fail-closed 비활성(보수적)");
        let r = r.with_dnssec().with_dnssec_strict(true);
        assert!(r.strict && r.validating(), "strict + 검증 활성");
    }

    #[test]
    fn caps_for_id_randomizes_but_preserves_name() {
        let n = Name::from_str("www.Example.com").unwrap();

        for _ in 0..50 {
            let r = randomize_name_case(&n);
            assert!(r.eq_ignore_case(&n), "0x20: 대소문자 무시 시 동일 이름");
            assert_eq!(r.to_ascii_lower(), "www.example.com");
        }

        let differs = (0..50).any(|_| {
            randomize_name_case(&n)
                .labels()
                .iter()
                .zip(n.labels())
                .any(|(a, b)| a != b)
        });
        assert!(differs, "0x20: 랜덤화로 바이트가 바뀌어야 함");
    }

    #[test]
    fn caps_for_id_is_enabled_by_default_and_can_be_disabled() {
        assert!(Recursor::new(vec![], Duration::from_secs(1)).caps_for_id);
        assert!(
            !Recursor::new(vec![], Duration::from_secs(1))
                .with_caps_for_id(false)
                .caps_for_id
        );
    }

    #[test]
    fn honor_cd_scope_restores_after_request_isolation_unwind() {
        HONOR_CD.with(|state| state.set(false));
        let result = onetdns_core::isolation::catch_request(|| {
            with_honor_cd(true, || {
                assert!(honor_cd_active());
                panic!("injected request panic");
            });
        });
        assert!(result.is_err());
        assert!(!honor_cd_active());
    }

    #[test]
    fn honor_cd_scope_restores_nested_parent() {
        HONOR_CD.with(|state| state.set(false));
        with_honor_cd(true, || {
            assert!(honor_cd_active());
            with_honor_cd(false, || assert!(!honor_cd_active()));
            assert!(honor_cd_active());
        });
        assert!(!honor_cd_active());
    }

    #[test]
    fn lowercase_outgoing_normalizes_name() {
        let n = lowercase_name(&Name::from_str("WwW.Example.COM").unwrap());
        assert_eq!(n.to_ascii_lower(), "www.example.com");
        assert!(
            n.labels()
                .eq([b"www".as_slice(), b"example".as_slice(), b"com".as_slice()]),
            "라벨 바이트가 실제 소문자"
        );

        let mut query = make_query(
            &Name::from_str("WwW.Example.COM").unwrap(),
            RecordType::A,
            true,
        );
        Recursor::with_default_roots(Duration::from_secs(1))
            .with_caps_for_id(false)
            .with_lowercase_outgoing(true)
            .apply_outgoing_case(&mut query);
        assert!(
            query.questions[0].name.labels().eq([
                b"www".as_slice(),
                b"example".as_slice(),
                b"com".as_slice()
            ]),
            "리액터 레인도 쓰는 공통 경로가 설정을 따라야 한다"
        );
    }

    #[test]
    fn caps_for_id_exact_match_rejects_case_mismatch() {
        let q = |s: &str| {
            vec![Question {
                name: Name::from_str(s).unwrap(),
                qtype: RecordType::A,
                qclass: DnsClass::IN,
            }]
        };
        assert!(questions_case_exact(
            &q("WwW.eXample.com"),
            &q("WwW.eXample.com")
        ));

        assert!(!questions_case_exact(
            &q("www.example.com"),
            &q("WWW.example.com")
        ));
    }

    #[test]
    fn caps_for_id_rejects_wire_question_case_mismatch_end_to_end() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = socket.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let Ok((size, peer)) = socket.recv_from(&mut buf) else {
                return;
            };
            let Ok(request) = Message::parse(&buf[..size]) else {
                return;
            };
            let mut response = base(&request);
            let original_name = request.questions[0].name.clone();
            let mut labels: Vec<Vec<u8>> = original_name.labels().map(<[u8]>::to_vec).collect();
            'outer: for label in &mut labels {
                for byte in label {
                    if byte.is_ascii_alphabetic() {
                        *byte = if byte.is_ascii_lowercase() {
                            byte.to_ascii_uppercase()
                        } else {
                            byte.to_ascii_lowercase()
                        };
                        break 'outer;
                    }
                }
            }
            response.questions[0].name = Name::from_labels(labels).unwrap();
            response.answers.push(Record::new(
                original_name,
                60,
                RData::A(Ipv4Addr::new(192, 0, 2, 80)),
            ));
            let _ = socket.send_to(&response.try_encode().unwrap(), peer);
        });

        let recursor = Recursor::new(vec![], Duration::from_millis(500))
            .with_caps_for_id(true)
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]);
        let zone = Name::root();
        let request = Message::query(
            7,
            Name::from_str("manyletters.example").unwrap(),
            RecordType::A,
        );
        assert!(matches!(
            recursor.query_any(&[server], &request, &zone, recursor.query_deadline()),
            Err(RecurseError::NoResponse)
        ));
    }

    #[test]
    fn with_recursion_limit_overrides_default() {
        let r = Recursor::with_default_roots(Duration::from_secs(1));
        assert_eq!(r.max_referrals, 16, "기본 위임 추적 상한");
        let r = r.with_recursion_limit(4);
        assert_eq!(r.max_referrals, 4);

        let r = Recursor::with_default_roots(Duration::from_secs(1)).with_recursion_limit(0);
        assert_eq!(r.max_referrals, 16);
    }

    fn base(req: &Message) -> Message {
        Message {
            header: Header {
                id: req.header.id,
                response: true,
                recursion_desired: req.header.recursion_desired,
                ..Default::default()
            },
            questions: req.questions.clone(),
            ..Default::default()
        }
    }

    /// What real authorities do with large answers: without a TCP retry the delegation cannot be
    /// followed.
    fn spawn_truncating_server(
        bind_ip: &str,
        port: u16,
        respond: impl Fn(&Message) -> Message + Send + Sync + 'static,
    ) -> SocketAddr {
        let addr: SocketAddr = format!("{bind_ip}:{port}").parse().unwrap();

        let udp = UdpSocket::bind(addr).unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = udp.recv_from(&mut buf) {
                let Ok(req) = Message::parse(&buf[..n]) else {
                    continue;
                };
                let mut m = base(&req);
                m.header.truncated = true;
                if let Ok(wire) = m.try_encode() {
                    let _ = udp.send_to(&wire, from);
                }
            }
        });

        spawn_tcp_server(addr, respond)
    }

    fn spawn_tcp_server(
        addr: SocketAddr,
        respond: impl Fn(&Message) -> Message + Send + Sync + 'static,
    ) -> SocketAddr {
        use std::io::{Read, Write};
        let respond = std::sync::Arc::new(respond);
        let listener = std::net::TcpListener::bind(addr).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let respond = respond.clone();
                std::thread::spawn(move || {
                    let mut len = [0u8; 2];
                    while stream.read_exact(&mut len).is_ok() {
                        let want = u16::from_be_bytes(len) as usize;
                        let mut body = vec![0u8; want];
                        if stream.read_exact(&mut body).is_err() {
                            return;
                        }
                        let Ok(req) = Message::parse(&body) else {
                            return;
                        };
                        let Ok(wire) = respond(&req).try_encode() else {
                            return;
                        };
                        let framed = (wire.len() as u16).to_be_bytes();
                        if stream.write_all(&framed).is_err() || stream.write_all(&wire).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    fn spawn_server(
        bind_ip: &str,
        port: u16,
        respond: impl Fn(&Message) -> Message + Send + 'static,
    ) -> SocketAddr {
        let addr: SocketAddr = format!("{bind_ip}:{port}").parse().unwrap();
        let sock = UdpSocket::bind(addr).unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                if let Ok(req) = Message::parse(&buf[..n]) {
                    let _ = sock.send_to(&respond(&req).try_encode().unwrap(), from);
                }
            }
        });
        addr
    }

    #[test]
    fn endless_delegation_chain_is_bounded_by_total_query_budget() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let seen = Arc::new(AtomicUsize::new(0));
        let counter = seen.clone();

        const PORT: u16 = 15987;
        let addr = spawn_server("127.0.0.40", PORT, move |req| {
            let n = counter.fetch_add(1, Ordering::Relaxed);
            let mut m = base(req);
            m.header.authoritative = false;
            if let Some(q) = req.questions.first() {
                m.authorities.push(Record::new(
                    q.name.clone(),
                    172800,
                    RData::Ns(Name::from_str(&format!("ns{n}.chain.test.")).unwrap()),
                ));
            }
            m
        });

        let rec = Recursor::new(vec![addr], Duration::from_secs(5)).with_test_loopback();
        let name = Name::from_str("a.b.c.d.e.f.g.deep.test.").unwrap();

        let mut per_query = Vec::new();
        for _ in 0..3 {
            let before = seen.load(Ordering::Relaxed);
            assert!(
                rec.resolve(&name, RecordType::A).is_err(),
                "끝없는 위임이 성공으로 끝나면 안 된다"
            );
            per_query.push(seen.load(Ordering::Relaxed) - before);
        }
        let total = per_query.iter().copied().max().unwrap();

        assert!(total > 1, "공격 형태가 재현되지 않았다(발신 {total}회)");
        assert!(
            total <= MAX_TOTAL_QUERIES,
            "총 발신 질의 예산({MAX_TOTAL_QUERIES})을 넘겼다: {total}회"
        );
    }

    fn referral(req: &Message, zone: &str, ns: &str, glue: Ipv4Addr) -> Message {
        let mut m = base(req);
        m.header.authoritative = false;
        m.authorities.push(Record::new(
            Name::from_str(zone).unwrap(),
            172800,
            RData::Ns(Name::from_str(ns).unwrap()),
        ));
        m.additionals.push(Record::new(
            Name::from_str(ns).unwrap(),
            172800,
            RData::A(glue),
        ));
        m
    }

    fn a_answer(req: &Message, ip: Ipv4Addr) -> Message {
        let mut m = base(req);
        m.header.authoritative = true;
        if let Some(q) = req.questions.first() {
            m.answers
                .push(Record::new(q.name.clone(), 300, RData::A(ip)));
        }
        m
    }

    fn ecdsa_key(seed: u8) -> (p256::ecdsa::SigningKey, onetdns_dnssec::Dnskey) {
        let sk = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let point = sk.verifying_key().to_sec1_point(false);
        let dnskey = onetdns_dnssec::Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: point.as_bytes()[1..].to_vec(),
        };
        (sk, dnskey)
    }

    fn dnskey_rec(owner: &str, key: &onetdns_dnssec::Dnskey) -> Record {
        Record::new(
            Name::from_str(owner).unwrap(),
            3600,
            RData::Unknown(48, key.rdata_bytes()),
        )
    }

    fn nsec_rec(owner: &str, next: &str, types: &[u16]) -> Record {
        let mut rdata = Vec::new();
        for label in next.trim_end_matches('.').split('.') {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        let max = types.iter().copied().max().unwrap_or(0);
        let nbytes = (max / 8 + 1) as usize;
        let mut bm = vec![0u8; nbytes];
        for &t in types {
            bm[(t / 8) as usize] |= 0x80 >> (t % 8);
        }
        rdata.push(0);
        rdata.push(nbytes as u8);
        rdata.extend_from_slice(&bm);
        Record::new(
            Name::from_str(owner).unwrap(),
            3600,
            RData::Unknown(47, rdata),
        )
    }

    fn rrsig_rec(
        sk: &p256::ecdsa::SigningKey,
        key: &onetdns_dnssec::Dnskey,
        signer: &str,
        type_covered: u16,
        rrset: &[Record],
    ) -> Record {
        use p256::ecdsa::{signature::Signer, Signature};
        let owner = rrset[0].name.clone();
        let mut sig = onetdns_dnssec::Rrsig {
            type_covered,
            algorithm: 13,
            labels: owner.num_labels() as u8,
            original_ttl: 3600,
            expiration: 0x7FFF_FFFF,
            inception: 0,
            key_tag: key.key_tag(),
            signer: Name::from_str(signer).unwrap(),
            signature: vec![],
        };
        let s: Signature = sk.sign(&onetdns_dnssec::signed_data(&sig, rrset));
        sig.signature = s.to_bytes().to_vec();
        Record::new(owner, 3600, RData::Unknown(46, sig.rdata_bytes()))
    }

    #[test]
    fn terminal_denial_uses_chain_apex_not_descendant_soa() {
        let apex = Name::from_str("test").unwrap();
        let qname = Name::from_str("host.test").unwrap();
        let soa = onetdns_proto::Soa {
            mname: Name::from_str("ns.test").unwrap(),
            rname: Name::from_str("hostmaster.test").unwrap(),
            serial: 1,
            refresh: 3600,
            retry: 600,
            expire: 86_400,
            minimum: 300,
        };
        let mut response = Message::default();
        response.header.authoritative = true;
        response.header.rcode = ResponseCode::NXDomain.0;
        response
            .authorities
            .push(Record::new(qname.clone(), 3600, RData::soa(soa.clone())));

        assert!(
            !is_authoritative_negative(&response, &qname, &apex),
            "하위 owner의 SOA는 현재 zone의 최종 부재 응답이 아님"
        );

        let child = Name::from_str("sub.test").unwrap();
        let child_qname = Name::from_str("host.sub.test").unwrap();
        let mut lame = Message::default();
        lame.header.authoritative = true;
        lame.header.rcode = ResponseCode::NXDomain.0;
        lame.authorities
            .push(Record::new(apex.clone(), 3600, RData::soa(soa.clone())));
        assert!(
            !is_authoritative_negative(&lame, &child_qname, &child),
            "위임 지점보다 위의 SOA는 그 자식 zone의 부재 증명이 아님"
        );

        response
            .authorities
            .push(Record::new(apex.clone(), 3600, RData::soa(soa)));
        response
            .authorities
            .push(nsec_rec("host.test", "z.test", &[1, 46, 47]));
        sanitize_terminal_response(&mut response, &qname, RecordType::AAAA, false, Some(&apex));

        let retained_soa: Vec<&Record> = response
            .authorities
            .iter()
            .filter(|record| record.rtype == RecordType::SOA)
            .collect();
        assert_eq!(retained_soa.len(), 1);
        assert!(retained_soa[0].name.eq_ignore_case(&apex));
        assert!(response
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::NSEC));
    }

    #[test]
    fn terminal_denial_requires_leaf_apex_signatures() {
        let (signing_key, key) = ecdsa_key(63);
        let apex = Name::from_str("test").unwrap();
        let qname = Name::from_str("host.test").unwrap();
        let anchor = onetdns_dnssec::Ds::from_dnskey(&key, &apex, 2).unwrap();
        let rec = Recursor::new(vec![], Duration::from_secs(1)).with_trust_anchors(vec![anchor]);
        let anchors = rec.trust_anchors.load();
        rec.validated_keys_store(
            apex.canonical_key(),
            ZoneTrust::Secure(Arc::from(vec![key.clone()])),
            anchors,
            300,
        );
        let chain = [ZoneStep {
            zone: apex.clone(),
            servers: vec![],
            ns_names: vec![],
            ds_records: vec![],
            ds_rrsigs: vec![],
            ds_nsec_records: vec![],
            ds_nsec_rrsigs: vec![],
            ds_nsec3_records: vec![],
            ds_nsec3_rrsigs: vec![],
            ds: vec![],
        }];
        let soa = Record::new(
            apex,
            3600,
            RData::soa(onetdns_proto::Soa {
                mname: Name::from_str("ns.test").unwrap(),
                rname: Name::from_str("hostmaster.test").unwrap(),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 86_400,
                minimum: 300,
            }),
        );
        let soa_sig = rrsig_rec(
            &signing_key,
            &key,
            "test",
            RecordType::SOA.0,
            std::slice::from_ref(&soa),
        );
        let nsec = nsec_rec("host.test", "z.test", &[1, 46, 47]);
        let status = |signer: &str, soa_record: &Record, include_soa_sig: bool| {
            let mut response = Message::default();
            response.authorities.push(soa_record.clone());
            if include_soa_sig {
                response.authorities.push(soa_sig.clone());
            }
            response.authorities.push(nsec.clone());
            response.authorities.push(rrsig_rec(
                &signing_key,
                &key,
                signer,
                RecordType::NSEC.0,
                std::slice::from_ref(&nsec),
            ));
            rec.validate_denial_status(
                &qname,
                RecordType::AAAA,
                &response,
                &chain,
                Instant::now() + Duration::from_secs(1),
            )
            .0
        };

        assert_eq!(status("test", &soa, true), SecurityStatus::Secure);
        assert_eq!(
            status(".", &soa, true),
            SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS),
            "암호학적으로 유효해도 업스트림 zone signer의 최종 NSEC는 거부"
        );
        assert_eq!(
            status("test", &soa, false),
            SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS),
            "서명되지 않은 SOA를 포함한 부재 응답은 AD를 주장하면 안 됨"
        );
        let mut forged_soa = soa.clone();
        let RData::Soa(forged) = &mut forged_soa.rdata else {
            unreachable!()
        };
        forged.serial += 1;
        assert_eq!(
            status("test", &forged_soa, true),
            SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS),
            "유효한 SOA 서명에 변조된 SOA를 붙여도 거부"
        );
    }

    #[test]
    fn denial_validation_ignores_superfluous_signed_nsec_records() {
        let (signing_key, key) = ecdsa_key(64);
        let apex = Name::from_str("test").unwrap();
        let qname = Name::from_str("host.test").unwrap();
        let recursor = Recursor::new(vec![], Duration::from_secs(1));
        let chain = [ZoneStep {
            zone: apex.clone(),
            servers: vec![],
            ns_names: vec![],
            ds_records: vec![],
            ds_rrsigs: vec![],
            ds_nsec_records: vec![],
            ds_nsec_rrsigs: vec![],
            ds_nsec3_records: vec![],
            ds_nsec3_rrsigs: vec![],
            ds: vec![],
        }];
        let soa = Record::new(
            apex,
            3600,
            RData::soa(onetdns_proto::Soa {
                mname: Name::from_str("ns.test").unwrap(),
                rname: Name::from_str("hostmaster.test").unwrap(),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 86_400,
                minimum: 300,
            }),
        );
        let mut response = Message::default();
        response.authorities.push(soa.clone());
        response.authorities.push(rrsig_rec(
            &signing_key,
            &key,
            "test",
            RecordType::SOA.0,
            std::slice::from_ref(&soa),
        ));

        for i in 0..32 {
            let record = nsec_rec(
                &format!("a{i:02}.test"),
                &format!("a{i:02}z.test"),
                &[RecordType::A.0, RecordType::RRSIG.0, RecordType::NSEC.0],
            );
            response.authorities.push(record.clone());
            response.authorities.push(rrsig_rec(
                &signing_key,
                &key,
                "test",
                RecordType::NSEC.0,
                std::slice::from_ref(&record),
            ));
        }
        let needed = nsec_rec(
            "host.test",
            "z.test",
            &[RecordType::A.0, RecordType::RRSIG.0, RecordType::NSEC.0],
        );
        response.authorities.push(needed.clone());
        response.authorities.push(rrsig_rec(
            &signing_key,
            &key,
            "test",
            RecordType::NSEC.0,
            std::slice::from_ref(&needed),
        ));

        assert_eq!(
            recursor
                .validate_denial_with_keys(&qname, RecordType::AAAA, &response, &chain, &[key],)
                .0,
            SecurityStatus::Secure,
            "무관한 서명 RRset의 개수가 검증 순서나 판정을 좌우하면 안 된다"
        );
    }

    #[test]
    fn validated_denial_carries_only_the_proven_records() {
        let (signing_key, key) = ecdsa_key(81);
        let (attacker_key, attacker_pub) = ecdsa_key(82);
        let apex = Name::from_str("test").unwrap();
        let qname = Name::from_str("host.test").unwrap();
        let recursor = Recursor::new(vec![], Duration::from_secs(1));
        let chain = [ZoneStep {
            zone: apex.clone(),
            servers: vec![],
            ns_names: vec![],
            ds_records: vec![],
            ds_rrsigs: vec![],
            ds_nsec_records: vec![],
            ds_nsec_rrsigs: vec![],
            ds_nsec3_records: vec![],
            ds_nsec3_rrsigs: vec![],
            ds: vec![],
        }];
        let soa = Record::new(
            apex.clone(),
            3600,
            RData::soa(onetdns_proto::Soa {
                mname: Name::from_str("ns.test").unwrap(),
                rname: Name::from_str("hostmaster.test").unwrap(),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 86_400,
                minimum: 300,
            }),
        );
        let mut response = Message::default();
        response.authorities.push(soa.clone());
        response.authorities.push(rrsig_rec(
            &signing_key,
            &key,
            "test",
            RecordType::SOA.0,
            std::slice::from_ref(&soa),
        ));
        let proven = nsec_rec(
            "host.test",
            "hosta.test",
            &[RecordType::A.0, RecordType::RRSIG.0, RecordType::NSEC.0],
        );
        response.authorities.push(proven.clone());
        response.authorities.push(rrsig_rec(
            &signing_key,
            &key,
            "test",
            RecordType::NSEC.0,
            std::slice::from_ref(&proven),
        ));
        let forged = nsec_rec(
            "test",
            "host.test",
            &[
                RecordType::NS.0,
                RecordType::SOA.0,
                RecordType::RRSIG.0,
                RecordType::NSEC.0,
            ],
        );
        response.authorities.push(forged.clone());
        response.authorities.push(rrsig_rec(
            &attacker_key,
            &attacker_pub,
            "test",
            RecordType::NSEC.0,
            std::slice::from_ref(&forged),
        ));

        let (status, records) =
            recursor.validate_denial_with_keys(&qname, RecordType::AAAA, &response, &chain, &[key]);
        assert_eq!(
            status,
            SecurityStatus::Secure,
            "실제 증명은 유효하므로 Secure"
        );
        assert!(
            records.iter().any(
                |record| record.rtype == RecordType::NSEC && record.name.eq_ignore_case(&qname)
            ),
            "검증한 증명 NSEC은 남아야 합니다"
        );
        assert!(
            records.iter().any(|record| record.rtype == RecordType::SOA),
            "부정 수명의 근거인 SOA는 남아야 합니다"
        );
        assert!(
            !records
                .iter()
                .any(|record| record.rtype == RecordType::NSEC && record.name.eq_ignore_case(&apex)),
            "검증에 쓰이지 않은 끼워 넣은 NSEC은 남으면 안 됩니다"
        );
        assert!(
            !records.iter().any(|record| {
                record.rtype == RecordType::RRSIG
                    && record.name.eq_ignore_case(&apex)
                    && onetdns_dnssec::Rrsig::from_record(record)
                        .is_some_and(|signature| signature.type_covered == RecordType::NSEC.0)
            }),
            "끼워 넣은 NSEC의 서명도 남으면 안 됩니다"
        );
    }

    #[test]
    fn answer_rrsigs_share_one_verification_budget() {
        let (signing_key, key) = ecdsa_key(65);
        let apex = Name::from_str("test").unwrap();
        let qname = Name::from_str("host.test").unwrap();
        let chain = [ZoneStep {
            zone: apex,
            servers: vec![],
            ns_names: vec![],
            ds_records: vec![],
            ds_rrsigs: vec![],
            ds_nsec_records: vec![],
            ds_nsec_rrsigs: vec![],
            ds_nsec3_records: vec![],
            ds_nsec3_rrsigs: vec![],
            ds: vec![],
        }];
        let answer = Record::new(qname.clone(), 3600, RData::A(Ipv4Addr::new(192, 0, 2, 65)));
        let other = Record::new(qname.clone(), 3600, RData::A(Ipv4Addr::new(192, 0, 2, 66)));
        let invalid_for_answer = rrsig_rec(
            &signing_key,
            &key,
            "test",
            RecordType::A.0,
            std::slice::from_ref(&other),
        );
        let valid = rrsig_rec(
            &signing_key,
            &key,
            "test",
            RecordType::A.0,
            std::slice::from_ref(&answer),
        );
        let recursor = Recursor::new(vec![], Duration::from_secs(1));
        let verdict = |invalid_count| {
            let mut response = Message::default();
            response.answers.push(answer.clone());
            response.answers.extend(std::iter::repeat_n(
                invalid_for_answer.clone(),
                invalid_count,
            ));
            response.answers.push(valid.clone());
            recursor.validate_answer_with_keys(
                &qname,
                RecordType::A,
                &response,
                &chain,
                std::slice::from_ref(&key),
            )
        };

        assert_eq!(
            verdict(7),
            SecurityStatus::Secure,
            "8회째의 정상 서명은 검증해야 한다"
        );
        assert_eq!(
            verdict(8),
            SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS),
            "후보마다 예산을 초기화해 9회째를 검증하면 KeyTrap 상한이 무의미하다"
        );
    }

    #[test]
    fn denial_rrsets_share_one_response_verification_budget() {
        let (signing_key, key) = ecdsa_key(66);
        let apex = Name::from_str("test").unwrap();
        let qname = Name::from_str("host.test").unwrap();
        let chain = [ZoneStep {
            zone: apex.clone(),
            servers: vec![],
            ns_names: vec![],
            ds_records: vec![],
            ds_rrsigs: vec![],
            ds_nsec_records: vec![],
            ds_nsec_rrsigs: vec![],
            ds_nsec3_records: vec![],
            ds_nsec3_rrsigs: vec![],
            ds: vec![],
        }];
        let soa = Record::new(
            apex,
            3600,
            RData::soa(onetdns_proto::Soa {
                mname: Name::from_str("ns.test").unwrap(),
                rname: Name::from_str("hostmaster.test").unwrap(),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 86_400,
                minimum: 300,
            }),
        );
        let mut other_soa = soa.clone();
        let RData::Soa(other) = &mut other_soa.rdata else {
            unreachable!()
        };
        other.serial = 2;
        let invalid_soa_sig = rrsig_rec(
            &signing_key,
            &key,
            "test",
            RecordType::SOA.0,
            std::slice::from_ref(&other_soa),
        );
        let valid_soa_sig = rrsig_rec(
            &signing_key,
            &key,
            "test",
            RecordType::SOA.0,
            std::slice::from_ref(&soa),
        );
        let nsec = nsec_rec(
            "host.test",
            "z.test",
            &[RecordType::A.0, RecordType::RRSIG.0, RecordType::NSEC.0],
        );
        let nsec_sig = rrsig_rec(
            &signing_key,
            &key,
            "test",
            RecordType::NSEC.0,
            std::slice::from_ref(&nsec),
        );
        let recursor = Recursor::new(vec![], Duration::from_secs(1));
        let verdict = |invalid_count| {
            let mut response = Message::default();
            response.authorities.push(soa.clone());
            response
                .authorities
                .extend(std::iter::repeat_n(invalid_soa_sig.clone(), invalid_count));
            response.authorities.push(valid_soa_sig.clone());
            response.authorities.push(nsec.clone());
            response.authorities.push(nsec_sig.clone());
            recursor
                .validate_denial_with_keys(
                    &qname,
                    RecordType::AAAA,
                    &response,
                    &chain,
                    std::slice::from_ref(&key),
                )
                .0
        };

        assert_eq!(
            verdict(6),
            SecurityStatus::Secure,
            "SOA 7회와 NSEC 1회는 응답 예산 안에서 검증해야 한다"
        );
        assert_eq!(
            verdict(7),
            SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS),
            "SOA가 예산을 소진한 뒤 NSEC에서 새 예산을 만들면 응답 전체 상한이 아니다"
        );
    }

    #[cfg(unix)]
    fn spawn_signed_hierarchy(
        port: u16,
        root_ip: &str,
        child_ip: &str,
        forge_leaf_answer: bool,
    ) -> (SocketAddr, onetdns_dnssec::Ds) {
        let (sk_root, k_root) = ecdsa_key(21);
        let (sk_test, k_test) = ecdsa_key(22);
        let (sk_evil, k_evil) = ecdsa_key(23);

        let root_owner = Name::from_str(".").unwrap();
        let test_owner = Name::from_str("test").unwrap();
        let root_anchor = onetdns_dnssec::Ds::from_dnskey(&k_root, &root_owner, 2).unwrap();
        let test_ds = onetdns_dnssec::Ds::from_dnskey(&k_test, &test_owner, 2).unwrap();
        let test_ds_rec = Record::new(test_owner, 3600, RData::Unknown(43, test_ds.rdata_bytes()));

        let child_glue: Ipv4Addr = child_ip.parse().unwrap();
        {
            let (sk, k) = (sk_root.clone(), k_root.clone());
            let ds_rec = test_ds_rec.clone();
            spawn_server(root_ip, port, move |req| {
                let q = req.questions.first().unwrap().clone();
                let mut m = base(req);
                if q.qtype == RecordType::DNSKEY && q.name.is_root() {
                    m.header.authoritative = true;
                    let dk = dnskey_rec(".", &k);
                    let sig = rrsig_rec(&sk, &k, ".", RecordType::DNSKEY.0, &[dk.clone()]);
                    m.answers.push(dk);
                    m.answers.push(sig);
                } else {
                    m.authorities.push(Record::new(
                        Name::from_str("test").unwrap(),
                        3600,
                        RData::Ns(Name::from_str("ns.test").unwrap()),
                    ));
                    m.authorities.push(ds_rec.clone());
                    m.authorities.push(rrsig_rec(
                        &sk,
                        &k,
                        ".",
                        RecordType::DS.0,
                        &[ds_rec.clone()],
                    ));
                    m.additionals.push(Record::new(
                        Name::from_str("ns.test").unwrap(),
                        3600,
                        RData::A(child_glue),
                    ));
                }
                m
            });
        }
        {
            let (sk, k) = (sk_test.clone(), k_test.clone());
            let (sk_bad, k_bad) = (sk_evil.clone(), k_evil.clone());
            spawn_server(child_ip, port, move |req| {
                let q = req.questions.first().unwrap().clone();
                let mut m = base(req);
                m.header.authoritative = true;
                if q.qtype == RecordType::DNSKEY && q.name.to_ascii_lower() == "test" {
                    let dk = dnskey_rec("test", &k);
                    let sig = rrsig_rec(&sk, &k, "test", RecordType::DNSKEY.0, &[dk.clone()]);
                    m.answers.push(dk);
                    m.answers.push(sig);
                } else if q.name.to_ascii_lower() == "host.test" && q.qtype == RecordType::A {
                    let a = Record::new(
                        Name::from_str("host.test").unwrap(),
                        3600,
                        RData::A(Ipv4Addr::new(10, 0, 0, 9)),
                    );

                    let sig = if forge_leaf_answer {
                        rrsig_rec(&sk_bad, &k_bad, "test", RecordType::A.0, &[a.clone()])
                    } else {
                        rrsig_rec(&sk, &k, "test", RecordType::A.0, &[a.clone()])
                    };
                    m.answers.push(a);
                    m.answers.push(sig);
                }
                m
            });
        }
        let root_server = SocketAddr::new(IpAddr::V4(root_ip.parse().unwrap()), port);
        (root_server, root_anchor)
    }

    #[cfg(unix)]
    fn drive_lane(
        reactor: &mut crate::reactor::Reactor,
        rec: &Recursor,
    ) -> Option<crate::reactor::Completion> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let mut fds = Vec::new();
            let mut map = Vec::new();
            reactor.collect_pollfds(&mut fds, &mut map);
            if fds.is_empty() {
                return None;
            }
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
            let now = Instant::now();
            let mut out = Vec::new();
            if rc > 0 {
                reactor.pump(rec, &fds, 0, &map, now, &mut out);
            }
            reactor.on_tick(rec, now, &mut out);
            if let Some(first) = out.into_iter().next() {
                return Some(first);
            }
        }
        None
    }

    #[cfg(unix)]
    #[test]
    fn reactor_lane_validates_dnssec_without_blocking_fetch() {
        use crate::reactor::{Completion, Reactor, ReactorConfig, SubmitOutcome};

        let (root_server, anchor) = spawn_signed_hierarchy(5410, "127.0.0.40", "127.0.0.41", false);
        let rec = Recursor::new(vec![root_server], Duration::from_secs(2))
            .with_port(5410)
            .with_test_loopback()
            .with_trust_anchors(vec![anchor]);
        let qname = Name::from_str("host.test").unwrap();

        let mut cold = Reactor::new(ReactorConfig::default());
        assert!(matches!(
            cold.submit(&rec, qname.clone(), RecordType::A, 1, Instant::now(), false),
            SubmitOutcome::Accepted
        ));
        let Some(Completion::Answer(token, msg)) = drive_lane(&mut cold, &rec) else {
            panic!("레인이 DNSKEY를 스스로 모아 완결해야 한다");
        };
        assert_eq!(token, 1);
        assert_eq!(msg.header.rcode, ResponseCode::NoError.0);
        assert!(msg.header.authentic_data, "레인이 검증한 답은 AD=1");
        assert_eq!(
            msg.answers
                .iter()
                .filter(|r| r.rtype == RecordType::A)
                .count(),
            1
        );

        let sync = rec.resolve(&qname, RecordType::A).expect("동기 해석");
        assert_eq!(sync.header.authentic_data, msg.header.authentic_data);
        assert_eq!(sync.header.rcode, msg.header.rcode);
    }

    #[cfg(unix)]
    #[test]
    fn reactor_lane_servfails_forged_signature() {
        use crate::reactor::{Completion, Reactor, ReactorConfig, SubmitOutcome};

        let (root_server, anchor) = spawn_signed_hierarchy(5411, "127.0.0.42", "127.0.0.43", true);
        let rec = Recursor::new(vec![root_server], Duration::from_secs(2))
            .with_port(5411)
            .with_test_loopback()
            .with_trust_anchors(vec![anchor]);
        let qname = Name::from_str("host.test").unwrap();

        let sync = rec.resolve(&qname, RecordType::A).expect("동기 해석 시도");
        assert_eq!(
            sync.header.rcode,
            ResponseCode::ServFail.0,
            "동기 경로: 위조 서명은 SERVFAIL"
        );

        let mut warm = Reactor::new(ReactorConfig::default());
        assert!(matches!(
            warm.submit(&rec, qname, RecordType::A, 1, Instant::now(), false),
            SubmitOutcome::Accepted
        ));

        match drive_lane(&mut warm, &rec) {
            Some(Completion::Answer(_, msg)) => {
                assert_eq!(
                    msg.header.rcode,
                    ResponseCode::ServFail.0,
                    "레인이 위조 서명을 통과시켰다: AD={}, answers={}",
                    msg.header.authentic_data,
                    msg.answers.len()
                );
                assert!(!msg.header.authentic_data);
            }
            Some(Completion::Retry(_)) => {
                panic!("레인이 판정하지 않고 넘겼다. 이 테스트가 검증 경로를 지나지 않는다")
            }
            Some(Completion::Fail(..)) => panic!("해석 자체가 실패했다"),
            None => panic!("완료 통지가 없다"),
        }
    }

    #[test]
    /// Delegations with several name servers but glue for only some are common. Resolving the
    /// remaining names first would turn each into a resolution from the root and exhaust the
    /// budget. The glueless name servers point at a silent address, so resolving them first fails
    /// this test.
    fn a_referral_with_partial_glue_uses_what_it_has() {
        const PORT: u16 = 5406;
        /// Nothing listens here; a delegation to it spends the whole timeout.
        const BLACKHOLE: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 40);

        spawn_server("127.0.0.38", PORT, move |req| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            let name = q.name.to_ascii_lower();
            if name.ends_with("slow.test") {
                m.authorities.push(Record::new(
                    Name::from_str("slow.test").unwrap(),
                    3600,
                    RData::Ns(Name::from_str("ns.slow.test").unwrap()),
                ));
                m.additionals.push(Record::new(
                    Name::from_str("ns.slow.test").unwrap(),
                    3600,
                    RData::A(BLACKHOLE),
                ));
                return m;
            }
            for ns in ["ns1.partial", "ns2.slow.test", "ns3.slow.test"] {
                m.authorities.push(Record::new(
                    Name::from_str("partial").unwrap(),
                    3600,
                    RData::Ns(Name::from_str(ns).unwrap()),
                ));
            }
            m.additionals.push(Record::new(
                Name::from_str("ns1.partial").unwrap(),
                3600,
                RData::A(Ipv4Addr::new(127, 0, 0, 39)),
            ));
            m
        });

        spawn_server("127.0.0.39", PORT, move |req| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            m.header.authoritative = true;
            if q.name.to_ascii_lower() == "host.partial" && q.qtype == RecordType::A {
                m.answers.push(Record::new(
                    Name::from_str("host.partial").unwrap(),
                    3600,
                    RData::A(Ipv4Addr::new(10, 0, 0, 38)),
                ));
            }
            m
        });

        let root_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 38)), PORT);
        let rec = Recursor::new(vec![root_server], Duration::from_secs(2))
            .with_port(PORT)
            .with_test_loopback();
        let resp = rec
            .resolve(&Name::from_str("host.partial").unwrap(), RecordType::A)
            .expect("받은 글루로 내려갈 수 있어야 합니다");
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
        assert!(
            resp.answers.iter().any(
                |record| matches!(&record.rdata, RData::A(ip) if *ip == Ipv4Addr::new(10, 0, 0, 38))
            ),
            "글루를 쥐고도 답하지 않는 네임서버를 풀러 갔습니다"
        );
    }

    #[test]
    /// Minimization gets an empty answer without delegation at an empty non-terminal; treating it
    /// as a path failure would make such names SERVFAIL wherever hardening is on.
    fn harden_referral_path_allows_empty_non_terminals() {
        const PORT: u16 = 5408;

        spawn_server("127.0.0.83", PORT, |req| {
            let mut m = base(req);
            m.authorities.push(Record::new(
                Name::from_str("test").unwrap(),
                3600,
                RData::Ns(Name::from_str("ns.test").unwrap()),
            ));
            m.additionals.push(Record::new(
                Name::from_str("ns.test").unwrap(),
                3600,
                RData::A(Ipv4Addr::new(127, 0, 0, 84)),
            ));
            m
        });
        spawn_server("127.0.0.84", PORT, |req| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            let name = q.name.to_ascii_lower();
            m.header.authoritative = !name.ends_with("lame.test");
            if name == "host.ent.test" && q.qtype == RecordType::A {
                m.answers.push(Record::new(
                    q.name.clone(),
                    3600,
                    RData::A(Ipv4Addr::new(10, 0, 0, 84)),
                ));
            }
            m
        });

        let root_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 83)), PORT);
        let recursor = Recursor::new(vec![root_server], Duration::from_secs(2))
            .with_port(PORT)
            .with_test_loopback()
            .with_harden_referral_path(true);
        let resp = recursor
            .resolve(&Name::from_str("host.ent.test").unwrap(), RecordType::A)
            .expect("빈 비단말 아래 이름은 풀려야 한다");
        assert!(resp.answers.iter().any(
            |record| matches!(record.rdata, RData::A(ip) if ip == Ipv4Addr::new(10, 0, 0, 84))
        ));
        assert!(
            recursor
                .resolve(&Name::from_str("host.lame.test").unwrap(), RecordType::A)
                .is_err(),
            "권한 없는 빈 답으로는 내려가지 않는다"
        );
    }

    #[test]
    /// The turn cap adds the label count for minimization, so without counting delegations
    /// separately a limit of 1 would still resolve a name delegated twice.
    fn recursion_limit_bounds_followed_delegations() {
        const PORT: u16 = 5407;

        fn referral(req: &Message, zone: &str, ns: &str, ip: Ipv4Addr) -> Message {
            let mut m = base(req);
            m.authorities.push(Record::new(
                Name::from_str(zone).unwrap(),
                3600,
                RData::Ns(Name::from_str(ns).unwrap()),
            ));
            m.additionals
                .push(Record::new(Name::from_str(ns).unwrap(), 3600, RData::A(ip)));
            m
        }

        spawn_server("127.0.0.80", PORT, |req| {
            referral(req, "test", "ns.test", Ipv4Addr::new(127, 0, 0, 81))
        });
        spawn_server("127.0.0.81", PORT, |req| {
            referral(req, "a.test", "ns.a.test", Ipv4Addr::new(127, 0, 0, 82))
        });
        spawn_server("127.0.0.82", PORT, |req| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            m.header.authoritative = true;
            if q.name.to_ascii_lower() == "host.a.test" && q.qtype == RecordType::A {
                m.answers.push(Record::new(
                    q.name.clone(),
                    3600,
                    RData::A(Ipv4Addr::new(10, 0, 0, 80)),
                ));
            }
            m
        });

        let root_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 80)), PORT);
        let recursor = |limit| {
            Recursor::new(vec![root_server], Duration::from_secs(2))
                .with_port(PORT)
                .with_test_loopback()
                .with_recursion_limit(limit)
        };
        let name = Name::from_str("host.a.test").unwrap();
        assert!(
            recursor(2).resolve(&name, RecordType::A).is_ok(),
            "위임 두 번은 상한 2 안에 든다"
        );
        assert!(
            recursor(1).resolve(&name, RecordType::A).is_err(),
            "상한 1로는 두 번째 위임을 따라가지 않는다"
        );
    }

    #[test]
    /// An answer that does not fit one UDP datagram arrives truncated; without a TCP retry the
    /// delegation cannot be followed. The retry lives in the exchange layer below; this checks it
    /// through the recursive path. The UDP side is left empty on purpose, so only a TCP retry
    /// passes.
    fn a_truncated_referral_is_refetched_over_tcp() {
        const PORT: u16 = 5405;

        spawn_truncating_server("127.0.0.36", PORT, move |req| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            m.authorities.push(Record::new(
                Name::from_str("big").unwrap(),
                3600,
                RData::Ns(Name::from_str("ns.big").unwrap()),
            ));
            m.additionals.push(Record::new(
                Name::from_str("ns.big").unwrap(),
                3600,
                RData::A(Ipv4Addr::new(127, 0, 0, 37)),
            ));
            let _ = q;
            m
        });

        spawn_server("127.0.0.37", PORT, move |req| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            m.header.authoritative = true;
            if q.name.to_ascii_lower() == "host.big" && q.qtype == RecordType::A {
                m.answers.push(Record::new(
                    Name::from_str("host.big").unwrap(),
                    3600,
                    RData::A(Ipv4Addr::new(10, 0, 0, 36)),
                ));
            }
            m
        });

        let root_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 36)), PORT);
        let rec = Recursor::new(vec![root_server], Duration::from_secs(3))
            .with_port(PORT)
            .with_test_loopback();
        let resp = rec
            .resolve(&Name::from_str("host.big").unwrap(), RecordType::A)
            .expect("절단된 위임을 TCP로 다시 받아 따라갈 수 있어야 합니다");
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
        assert!(
            resp.answers.iter().any(
                |record| matches!(&record.rdata, RData::A(ip) if *ip == Ipv4Addr::new(10, 0, 0, 36))
            ),
            "최종 답을 얻지 못했습니다"
        );
    }

    #[test]
    fn authority_tcp_switch_bypasses_intercepted_udp() {
        const PORT: u16 = 5412;
        const FORGED: Ipv4Addr = Ipv4Addr::new(10, 9, 9, 9);
        const REAL: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 44);

        let answer = |req: &Message, ip: Ipv4Addr| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            m.header.authoritative = true;
            if q.qtype == RecordType::A {
                m.answers.push(Record::new(q.name, 300, RData::A(ip)));
            }
            m
        };
        let addr = spawn_server("127.0.0.44", PORT, move |req| answer(req, FORGED));
        spawn_tcp_server(addr, move |req| answer(req, REAL));

        let switch = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let rec = Recursor::new(vec![addr], Duration::from_secs(3))
            .with_port(PORT)
            .with_test_loopback()
            .with_authority_tcp(switch.clone());
        let resolve = |name: &str| {
            let resp = rec
                .resolve(&Name::from_str(name).unwrap(), RecordType::A)
                .expect("답을 받아야 합니다");
            resp.answers
                .iter()
                .find_map(|record| match record.rdata {
                    RData::A(ip) => Some(ip),
                    _ => None,
                })
                .expect("주소 답이 있어야 합니다")
        };

        assert_eq!(resolve("udp.intercept"), FORGED);
        switch.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(rec.authority_over_tcp());
        assert_eq!(
            resolve("tcp.intercept"),
            REAL,
            "판정을 켰는데도 UDP로 물어 가로챈 답을 받았습니다"
        );
    }

    #[test]
    /// The first two servers are silent. Without the cap the third would be asked as soon as its
    /// turn comes; with it, only after one of the first exchanges times out.
    fn a_query_waits_on_at_most_two_exchanges_at_once() {
        const PORT: u16 = 5423;
        let silent = |ip: &str| {
            let sock = UdpSocket::bind(format!("{ip}:{PORT}")).unwrap();
            let addr = sock.local_addr().unwrap();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while sock.recv_from(&mut buf).is_ok() {}
            });
            addr
        };
        let first = silent("127.0.0.90");
        let second = silent("127.0.0.91");
        let third_sock = UdpSocket::bind(format!("127.0.0.92:{PORT}")).unwrap();
        let third = third_sock.local_addr().unwrap();
        let asked_third = Arc::new(Mutex::new(None::<Instant>));
        let record = asked_third.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while third_sock.recv_from(&mut buf).is_ok() {
                record.lock().unwrap().get_or_insert_with(Instant::now);
            }
        });

        let timeout = Duration::from_secs(4);
        let rec = Recursor::new(vec![], timeout).with_test_loopback();
        let zone = Name::from_str("cap.test").unwrap();
        let query = make_query(
            &Name::from_str("host.cap.test").unwrap(),
            RecordType::A,
            false,
        );
        let started = Instant::now();
        assert!(rec
            .query_any(&[first, second, third], &query, &zone, rec.query_deadline())
            .is_err());

        let per_server = timeout / 3;
        let asked = asked_third
            .lock()
            .unwrap()
            .map(|at| at.duration_since(started))
            .expect("앞의 교환이 끝나면 셋째 서버에도 물어야 합니다");
        assert!(
            asked >= per_server,
            "앞의 두 교환이 답을 기다리는 동안 셋째 서버에도 물었습니다: {asked:?}"
        );
    }

    #[test]
    /// The flag turns on when the startup check ends, mid-resolution for anything started earlier.
    /// Choosing the transport once per server list would keep asking the remaining servers over the
    /// intercepted UDP.
    fn authority_tcp_switch_applies_to_servers_asked_after_it_turns_on() {
        const PORT: u16 = 5422;
        const FORGED: Ipv4Addr = Ipv4Addr::new(10, 9, 9, 88);
        const REAL: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 88);

        let switch = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let silent = UdpSocket::bind("127.0.0.88:5422").unwrap();
        let first = silent.local_addr().unwrap();
        let flip = switch.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while silent.recv_from(&mut buf).is_ok() {
                flip.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        });
        let answer = |req: &Message, ip: Ipv4Addr| {
            let mut m = base(req);
            m.header.authoritative = true;
            let q = req.questions.first().unwrap().clone();
            m.answers.push(Record::new(q.name, 300, RData::A(ip)));
            m
        };
        let second = spawn_server("127.0.0.89", PORT, move |req| answer(req, FORGED));
        spawn_tcp_server(second, move |req| answer(req, REAL));

        let rec = Recursor::new(vec![], Duration::from_secs(3))
            .with_test_loopback()
            .with_authority_tcp(switch);
        let zone = Name::from_str("switch.test").unwrap();
        let query = make_query(
            &Name::from_str("host.switch.test").unwrap(),
            RecordType::A,
            false,
        );
        let resp = rec
            .query_any(&[first, second], &query, &zone, rec.query_deadline())
            .expect("둘째 서버의 답을 받아야 합니다");
        assert!(
            matches!(resp.answers.first().map(|r| &r.rdata), Some(RData::A(ip)) if *ip == REAL),
            "판정이 켜진 뒤에도 UDP로 물어 가로챈 답을 받았습니다: {resp:?}"
        );
    }

    const COHOSTED_TARGET: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 50);

    /// The root delegates to parent.test. The zone server answers the child's NS authoritatively,
    /// answers the empty non-terminal myaddr.l.parent.test with NXDOMAIN, and answers DS queries
    /// with the parent's DS in the answer section, counting them. Returns the root address and the
    /// DS query count.
    fn spawn_cohosted_zones(
        root_ip: Ipv4Addr,
        zone_ip: Ipv4Addr,
        port: u16,
    ) -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        fn name(text: &str) -> Name {
            Name::from_str(text).unwrap()
        }
        fn soa(apex: &str) -> Record {
            Record::new(
                name(apex),
                300,
                RData::soa(onetdns_proto::Soa {
                    mname: name("ns.parent.test"),
                    rname: name("hostmaster.parent.test"),
                    serial: 1,
                    refresh: 3600,
                    retry: 600,
                    expire: 86_400,
                    minimum: 300,
                }),
            )
        }

        spawn_server(&root_ip.to_string(), port, move |req| {
            let mut m = base(req);
            m.authorities.push(Record::new(
                name("parent.test"),
                3600,
                RData::Ns(name("ns.parent.test")),
            ));
            m.additionals
                .push(Record::new(name("ns.parent.test"), 3600, RData::A(zone_ip)));
            m
        });
        let ds_queries = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = ds_queries.clone();
        spawn_server(&zone_ip.to_string(), port, move |req| {
            let q = req.questions.first().unwrap().clone();
            let asked = q.name.to_ascii_lower();
            let mut m = base(req);
            m.header.authoritative = true;
            match (asked.as_str(), q.qtype) {
                ("l.parent.test", RecordType::NS) => {
                    m.answers.push(Record::new(
                        name("l.parent.test"),
                        3600,
                        RData::Ns(name("ns.parent.test")),
                    ));
                    m.additionals.push(Record::new(
                        name("ns.parent.test"),
                        3600,
                        RData::A(zone_ip),
                    ));
                }
                ("l.parent.test", RecordType::DS) => {
                    seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let ds = onetdns_dnssec::Ds {
                        key_tag: 4321,
                        algorithm: 13,
                        digest_type: 2,
                        digest: vec![5; 32],
                    };
                    m.answers.push(Record::new(
                        name("l.parent.test"),
                        300,
                        RData::Unknown(RecordType::DS.0, ds.rdata_bytes()),
                    ));
                }
                ("myaddr.l.parent.test", _) => {
                    m.header.rcode = ResponseCode::NXDomain.0;
                    m.authorities.push(soa("l.parent.test"));
                }
                ("o-o.myaddr.l.parent.test", RecordType::A) => {
                    m.answers
                        .push(Record::new(q.name, 60, RData::A(COHOSTED_TARGET)));
                }
                (other, _) if other.ends_with("l.parent.test") => {
                    m.authorities.push(soa("l.parent.test"));
                }
                _ => m.authorities.push(soa("parent.test")),
            }
            m
        });
        (SocketAddr::new(IpAddr::V4(root_ip), port), ds_queries)
    }

    #[test]
    /// The server answers from the child zone, so NS for a minimized query comes as an
    /// authoritative answer, not a delegation. Missing the cut would take the current zone for the
    /// parent, discard the negative answer carrying the child's SOA as irrelevant and return
    /// SERVFAIL. Following it accepts the NXDOMAIN for the empty non-terminal and asks again with
    /// the full name.
    fn an_authoritative_ns_answer_is_followed_as_a_zone_cut() {
        const PORT: u16 = 5413;
        let (root, ds_queries) = spawn_cohosted_zones(
            Ipv4Addr::new(127, 0, 0, 50),
            Ipv4Addr::new(127, 0, 0, 51),
            PORT,
        );

        let rec = Recursor::new(vec![root], Duration::from_secs(3))
            .with_port(PORT)
            .with_test_loopback();
        let resp = rec
            .resolve(
                &Name::from_str("o-o.myaddr.l.parent.test").unwrap(),
                RecordType::A,
            )
            .expect("같은 서버가 맡은 자식 영역으로 내려가 답을 받아야 합니다");
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
        assert!(
            resp.answers
                .iter()
                .any(|record| matches!(&record.rdata, RData::A(ip) if *ip == COHOSTED_TARGET)),
            "최종 답을 얻지 못했습니다: {resp:?}"
        );
        assert_eq!(
            ds_queries.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "검증하지 않으면 DS를 따로 묻지 않는다"
        );
    }

    #[test]
    /// Unlike a referral, this cut comes without DS evidence; without it the signed child zone
    /// would drop to Insecure unproven and validation would be disabled.
    fn an_answer_zone_cut_fetches_its_ds_when_validating() {
        const PORT: u16 = 5414;
        let (root, ds_queries) = spawn_cohosted_zones(
            Ipv4Addr::new(127, 0, 0, 52),
            Ipv4Addr::new(127, 0, 0, 53),
            PORT,
        );

        let anchor = onetdns_dnssec::Ds {
            key_tag: 1,
            algorithm: 13,
            digest_type: 2,
            digest: vec![1; 32],
        };
        let rec = Recursor::new(vec![root], Duration::from_secs(3))
            .with_port(PORT)
            .with_test_loopback()
            .with_trust_anchors(vec![anchor]);
        let mut budget = Budget {
            ns_resolves: rec.max_ns_resolves,
            queries: MAX_TOTAL_QUERIES,
            deadline: rec.query_deadline(),
        };
        let qname = Name::from_str("o-o.myaddr.l.parent.test").unwrap();
        let (resp, chain) = rec
            .iterate_from(
                &qname,
                RecordType::A,
                &mut budget,
                Name::root(),
                vec![root],
                true,
            )
            .expect("검증을 켜도 경계를 따라 내려가야 합니다");
        assert!(resp
            .answers
            .iter()
            .any(|record| matches!(&record.rdata, RData::A(ip) if *ip == COHOSTED_TARGET)));
        assert_eq!(ds_queries.load(std::sync::atomic::Ordering::Relaxed), 1);
        let child = chain
            .iter()
            .find(|step| step.zone.to_ascii_lower() == "l.parent.test")
            .expect("자식 영역이 체인에 있어야 합니다");
        assert_eq!(
            child.ds.iter().map(|ds| ds.key_tag).collect::<Vec<_>>(),
            vec![4321],
            "부모에게 받은 DS가 체인에 기록돼야 합니다"
        );
    }

    /// Each zone has its own key. The child's NS is answered authoritatively and its DS, signed
    /// with the parent key, only to DS queries. `child_ds_seed` picks the key the DS is made from;
    /// a key other than the child's gives a forged DS. Returns the root address and the root trust
    /// anchor.
    fn spawn_signed_cohosted_zones(
        root_ip: Ipv4Addr,
        zone_ip: Ipv4Addr,
        port: u16,
        child_ds_seed: u8,
    ) -> (SocketAddr, onetdns_dnssec::Ds) {
        fn name(text: &str) -> Name {
            Name::from_str(text).unwrap()
        }
        fn ds_rec(owner: &str, key: &onetdns_dnssec::Dnskey) -> Record {
            let ds = onetdns_dnssec::Ds::from_dnskey(key, &name(owner), 2).unwrap();
            Record::new(
                name(owner),
                3600,
                RData::Unknown(RecordType::DS.0, ds.rdata_bytes()),
            )
        }

        let (root_sk, root_key) = ecdsa_key(71);
        let (parent_sk, parent_key) = ecdsa_key(72);
        let (child_sk, child_key) = ecdsa_key(73);
        let (_, ds_key) = ecdsa_key(child_ds_seed);
        let anchor = onetdns_dnssec::Ds::from_dnskey(&root_key, &Name::root(), 2).unwrap();

        let root_dnskey = vec![dnskey_rec(".", &root_key)];
        let root_dnskey_sig = rrsig_rec(&root_sk, &root_key, ".", 48, &root_dnskey);
        let parent_ds = vec![ds_rec("parent.test", &parent_key)];
        let parent_ds_sig = rrsig_rec(&root_sk, &root_key, ".", RecordType::DS.0, &parent_ds);
        spawn_server(&root_ip.to_string(), port, move |req| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            if q.qtype == RecordType::DNSKEY && q.name.is_root() {
                m.header.authoritative = true;
                m.answers.extend(root_dnskey.iter().cloned());
                m.answers.push(root_dnskey_sig.clone());
                return m;
            }
            m.authorities.push(Record::new(
                name("parent.test"),
                3600,
                RData::Ns(name("ns.parent.test")),
            ));
            m.authorities.extend(parent_ds.iter().cloned());
            m.authorities.push(parent_ds_sig.clone());
            m.additionals
                .push(Record::new(name("ns.parent.test"), 3600, RData::A(zone_ip)));
            m
        });

        let parent_dnskey = vec![dnskey_rec("parent.test", &parent_key)];
        let parent_dnskey_sig =
            rrsig_rec(&parent_sk, &parent_key, "parent.test", 48, &parent_dnskey);
        let child_dnskey = vec![dnskey_rec("l.parent.test", &child_key)];
        let child_dnskey_sig = rrsig_rec(&child_sk, &child_key, "l.parent.test", 48, &child_dnskey);
        let child_ns = vec![Record::new(
            name("l.parent.test"),
            3600,
            RData::Ns(name("ns.parent.test")),
        )];
        let child_ns_sig = rrsig_rec(
            &child_sk,
            &child_key,
            "l.parent.test",
            RecordType::NS.0,
            &child_ns,
        );
        let child_ds = vec![ds_rec("l.parent.test", &ds_key)];
        let child_ds_sig = rrsig_rec(
            &parent_sk,
            &parent_key,
            "parent.test",
            RecordType::DS.0,
            &child_ds,
        );
        let host = vec![Record::new(
            name("host.l.parent.test"),
            3600,
            RData::A(COHOSTED_TARGET),
        )];
        let host_sig = rrsig_rec(&child_sk, &child_key, "l.parent.test", 1, &host);
        spawn_server(&zone_ip.to_string(), port, move |req| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            m.header.authoritative = true;
            let (records, signature): (&[Record], &Record) =
                match (q.name.to_ascii_lower().as_str(), q.qtype) {
                    ("parent.test", RecordType::DNSKEY) => (&parent_dnskey, &parent_dnskey_sig),
                    ("l.parent.test", RecordType::DNSKEY) => (&child_dnskey, &child_dnskey_sig),
                    ("l.parent.test", RecordType::NS) => {
                        m.additionals.push(Record::new(
                            name("ns.parent.test"),
                            3600,
                            RData::A(zone_ip),
                        ));
                        (&child_ns, &child_ns_sig)
                    }
                    ("l.parent.test", RecordType::DS) => (&child_ds, &child_ds_sig),
                    ("host.l.parent.test", RecordType::A) => (&host, &host_sig),
                    _ => return m,
                };
            m.answers.extend(records.iter().cloned());
            m.answers.push(signature.clone());
            m
        });
        (SocketAddr::new(IpAddr::V4(root_ip), port), anchor)
    }

    #[test]
    /// The child key is trusted only through the DS fetched from the parent, and only then does the
    /// answer get AD; without the DS the child zone drops to Insecure and AD is not set.
    fn a_signed_answer_zone_cut_validates_through_the_fetched_ds() {
        const PORT: u16 = 5415;
        let (root, anchor) = spawn_signed_cohosted_zones(
            Ipv4Addr::new(127, 0, 0, 54),
            Ipv4Addr::new(127, 0, 0, 55),
            PORT,
            73,
        );
        let rec = Recursor::new(vec![root], Duration::from_secs(3))
            .with_port(PORT)
            .with_test_loopback()
            .with_trust_anchors(vec![anchor]);
        let resp = rec
            .resolve(
                &Name::from_str("host.l.parent.test").unwrap(),
                RecordType::A,
            )
            .expect("서명된 자식 영역의 답을 받아야 합니다");
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0, "{resp:?}");
        assert!(
            resp.answers
                .iter()
                .any(|record| matches!(&record.rdata, RData::A(ip) if *ip == COHOSTED_TARGET)),
            "최종 답을 얻지 못했습니다: {resp:?}"
        );
        assert!(
            resp.header.authentic_data,
            "부모에게 받은 DS로 자식 키를 확인해 Secure여야 합니다"
        );
    }

    #[test]
    /// The parent's signature is valid but the DS points at another key. The child's DNSKEY cannot
    /// be trusted: Bogus, never Insecure with the answer passed on.
    fn a_signed_answer_zone_cut_with_a_mismatched_ds_is_bogus() {
        const PORT: u16 = 5416;
        let (root, anchor) = spawn_signed_cohosted_zones(
            Ipv4Addr::new(127, 0, 0, 56),
            Ipv4Addr::new(127, 0, 0, 57),
            PORT,
            74,
        );
        let rec = Recursor::new(vec![root], Duration::from_secs(3))
            .with_port(PORT)
            .with_test_loopback()
            .with_trust_anchors(vec![anchor]);
        let resp = rec
            .resolve(
                &Name::from_str("host.l.parent.test").unwrap(),
                RecordType::A,
            )
            .expect("검증 실패도 응답으로 돌아와야 합니다");
        assert_eq!(resp.header.rcode, ResponseCode::ServFail.0, "{resp:?}");
        assert!(!resp.header.authentic_data);
    }

    const GLUELESS_TARGET: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 58);

    /// The root delegates target.test to ns1.a.test and ns2.b.test without glue, and each name
    /// answers its own address authoritatively: one silent server, one answering. The root logs the
    /// queries it receives by name and type. With `dead_first`, ns1.a.test is the silent one.
    fn spawn_glueless_delegation(
        ips: [Ipv4Addr; 3],
        port: u16,
        dead_first: bool,
    ) -> (
        SocketAddr,
        std::sync::Arc<std::sync::Mutex<Vec<(String, RecordType)>>>,
    ) {
        let [root_ip, dead_ip, good_ip] = ips;
        let (first, second) = if dead_first {
            (dead_ip, good_ip)
        } else {
            (good_ip, dead_ip)
        };
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        spawn_server(&root_ip.to_string(), port, move |req| {
            let q = req.questions.first().unwrap().clone();
            let asked = q.name.to_ascii_lower();
            log.lock().unwrap().push((asked.clone(), q.qtype));
            let mut m = base(req);
            if asked.ends_with("target.test") {
                for ns in ["ns1.a.test", "ns2.b.test"] {
                    m.authorities.push(Record::new(
                        Name::from_str("target.test").unwrap(),
                        3600,
                        RData::Ns(Name::from_str(ns).unwrap()),
                    ));
                }
                return m;
            }
            m.header.authoritative = true;
            let address = match (asked.as_str(), q.qtype) {
                ("ns1.a.test", RecordType::A) => Some(first),
                ("ns2.b.test", RecordType::A) => Some(second),
                _ => None,
            };
            if let Some(ip) = address {
                m.answers.push(Record::new(q.name, 3600, RData::A(ip)));
            }
            m
        });
        let silent = UdpSocket::bind(SocketAddr::new(IpAddr::V4(dead_ip), port)).unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while silent.recv_from(&mut buf).is_ok() {}
        });
        spawn_server(&good_ip.to_string(), port, move |req| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            m.header.authoritative = true;
            if q.name.to_ascii_lower() == "host.target.test" && q.qtype == RecordType::A {
                m.answers
                    .push(Record::new(q.name, 60, RData::A(GLUELESS_TARGET)));
            }
            m
        });
        (SocketAddr::new(IpAddr::V4(root_ip), port), seen)
    }

    fn has_glueless_target(resp: &Message) -> bool {
        resp.answers
            .iter()
            .any(|record| matches!(&record.rdata, RData::A(ip) if *ip == GLUELESS_TARGET))
    }

    #[test]
    /// Resolving every name would let one slow server take the remaining time. When the first name
    /// points at an answering server, the second must not be asked.
    fn glueless_nameserver_lookup_stops_at_the_first_usable_address() {
        const PORT: u16 = 5417;
        let (root, seen) = spawn_glueless_delegation(
            [
                Ipv4Addr::new(127, 0, 0, 58),
                Ipv4Addr::new(127, 0, 0, 59),
                Ipv4Addr::new(127, 0, 0, 61),
            ],
            PORT,
            false,
        );
        let rec = Recursor::new(vec![root], Duration::from_secs(3))
            .with_port(PORT)
            .with_test_loopback();
        let resp = rec
            .resolve(&Name::from_str("host.target.test").unwrap(), RecordType::A)
            .expect("첫 네임서버로 답을 받아야 합니다");
        assert!(has_glueless_target(&resp), "{resp:?}");
        assert!(
            !seen
                .lock()
                .unwrap()
                .iter()
                .any(|(name, _)| name == "ns2.b.test"),
            "쓸 수 있는 주소가 있는데 다음 네임서버 이름까지 풀었습니다"
        );
    }

    #[test]
    /// Time per server is divided including the names left; spending it all on the one address
    /// would leave no time for the second name.
    fn glueless_nameserver_lookup_resolves_the_next_name_when_the_first_is_dead() {
        const PORT: u16 = 5418;
        let (root, seen) = spawn_glueless_delegation(
            [
                Ipv4Addr::new(127, 0, 0, 68),
                Ipv4Addr::new(127, 0, 0, 69),
                Ipv4Addr::new(127, 0, 0, 72),
            ],
            PORT,
            true,
        );
        let rec = Recursor::new(vec![root], Duration::from_secs(3))
            .with_port(PORT)
            .with_test_loopback();
        let resp = rec
            .resolve(&Name::from_str("host.target.test").unwrap(), RecordType::A)
            .expect("둘째 네임서버로 넘어가 답을 받아야 합니다");
        assert!(has_glueless_target(&resp), "{resp:?}");
        assert_eq!(
            seen.lock()
                .unwrap()
                .iter()
                .filter(|(name, qtype)| name == "ns2.b.test" && *qtype == RecordType::A)
                .count(),
            1
        );
    }

    #[test]
    /// The address only picks a destination and the answer is validated through the chain, so
    /// validating this lookup would only spend time fetching DNSKEYs. The final answer is not
    /// validated here either, so a DNSKEY query at the root can only come from the address lookup.
    fn glueless_nameserver_lookup_does_not_validate() {
        const PORT: u16 = 5419;
        let (root, seen) = spawn_glueless_delegation(
            [
                Ipv4Addr::new(127, 0, 0, 75),
                Ipv4Addr::new(127, 0, 0, 76),
                Ipv4Addr::new(127, 0, 0, 77),
            ],
            PORT,
            false,
        );
        let anchor = onetdns_dnssec::Ds {
            key_tag: 1,
            algorithm: 13,
            digest_type: 2,
            digest: vec![1; 32],
        };
        let rec = Recursor::new(vec![root], Duration::from_secs(3))
            .with_port(PORT)
            .with_test_loopback()
            .with_trust_anchors(vec![anchor]);
        let mut budget = Budget {
            ns_resolves: rec.max_ns_resolves,
            queries: MAX_TOTAL_QUERIES,
            deadline: rec.query_deadline(),
        };
        let qname = Name::from_str("host.target.test").unwrap();
        let (resp, _) = rec
            .iterate_from(
                &qname,
                RecordType::A,
                &mut budget,
                Name::root(),
                vec![root],
                true,
            )
            .expect("주소를 풀어 내려가야 합니다");
        assert!(has_glueless_target(&resp), "{resp:?}");
        assert!(
            !seen
                .lock()
                .unwrap()
                .iter()
                .any(|(_, qtype)| matches!(*qtype, RecordType::DNSKEY | RecordType::DS)),
            "네임서버 주소를 푸는 해석이 검증하려고 키를 물었습니다: {:?}",
            seen.lock().unwrap()
        );
    }

    #[test]
    /// The first server is new, so after `UNKNOWN_SERVER_PATIENCE` the second is asked too. Waiting
    /// for the first delays by its lag; abandoning it loses an answer about to arrive. The late
    /// server gets an RTT of at least the time waited and goes last next time.
    fn a_slow_server_is_raced_by_the_next_one() {
        const PORT: u16 = 5420;
        /// Must be shorter than the per-server timeout.
        const SLOW_DELAY: Duration = Duration::from_millis(1500);
        let answer = |ip: Ipv4Addr| {
            move |req: &Message| {
                let mut m = base(req);
                m.header.authoritative = true;
                let q = req.questions.first().unwrap().clone();
                m.answers.push(Record::new(q.name, 60, RData::A(ip)));
                m
            }
        };
        let slow_ip = Ipv4Addr::new(127, 0, 0, 78);
        let fast_ip = Ipv4Addr::new(127, 0, 0, 79);
        let slow = spawn_server(&slow_ip.to_string(), PORT, {
            let respond = answer(slow_ip);
            move |req: &Message| {
                std::thread::sleep(SLOW_DELAY);
                respond(req)
            }
        });
        let fast = spawn_server(&fast_ip.to_string(), PORT, answer(fast_ip));

        let rec = Recursor::new(vec![], Duration::from_secs(4)).with_test_loopback();
        let zone = Name::from_str("race.test").unwrap();
        let query = make_query(
            &Name::from_str("host.race.test").unwrap(),
            RecordType::A,
            false,
        );
        let started = Instant::now();
        let resp = rec
            .query_any(&[slow, fast], &query, &zone, rec.query_deadline())
            .expect("둘째 서버의 답을 받아야 합니다");
        let elapsed = started.elapsed();

        assert!(
            matches!(resp.answers.first().map(|r| &r.rdata), Some(RData::A(ip)) if *ip == fast_ip),
            "{resp:?}"
        );
        assert!(
            elapsed >= UNKNOWN_SERVER_PATIENCE && elapsed < SLOW_DELAY,
            "둘째 서버에 물은 시점이 기대와 다릅니다: {elapsed:?}"
        );
        assert!(
            rec.srtt(slow.ip())
                .is_some_and(|ms| u128::from(ms) >= UNKNOWN_SERVER_PATIENCE.as_millis()),
            "답을 기다리다 만 서버의 왕복 시간이 기록되지 않았습니다"
        );
        assert_eq!(rec.order_by_infra(&[slow, fast], &zone), vec![fast, slow]);
    }

    #[test]
    /// The root ignores only the first query. The client gets a failure, but the background run
    /// caches the child delegation, so the next query does not walk from the root.
    fn an_unanswered_resolution_is_finished_in_the_background() {
        const PORT: u16 = 5421;
        let root_ip = Ipv4Addr::new(127, 0, 0, 86);
        let child_ip = Ipv4Addr::new(127, 0, 0, 87);
        let root_sock = UdpSocket::bind(SocketAddr::new(IpAddr::V4(root_ip), PORT)).unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut first = true;
            while let Ok((n, from)) = root_sock.recv_from(&mut buf) {
                let Ok(req) = Message::parse(&buf[..n]) else {
                    continue;
                };
                if std::mem::take(&mut first) {
                    continue;
                }
                let asked = req.questions.first().unwrap().name.to_ascii_lower();
                let resp = if asked.ends_with("bg.test") {
                    referral(&req, "bg.test", "ns.bg.test", child_ip)
                } else {
                    let mut m = base(&req);
                    m.header.authoritative = true;
                    m
                };
                let _ = root_sock.send_to(&resp.try_encode().unwrap(), from);
            }
        });
        spawn_server(&child_ip.to_string(), PORT, move |req| {
            a_answer(req, Ipv4Addr::new(192, 0, 2, 86))
        });

        let rec = Arc::new(
            Recursor::new(
                vec![SocketAddr::new(IpAddr::V4(root_ip), PORT)],
                Duration::from_millis(500),
            )
            .with_port(PORT)
            .with_test_loopback(),
        );
        let qname = Name::from_str("host.bg.test").unwrap();
        assert!(
            rec.resolve_with_ns_cd(&qname, RecordType::A, false)
                .is_err(),
            "루트가 첫 질의에 답하지 않았으니 이 해석은 실패해야 합니다"
        );

        let zone = Name::from_str("bg.test").unwrap();
        let until = Instant::now() + Duration::from_secs(3);
        while rec.deleg_cached(&zone).is_none() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            rec.deleg_cached(&zone).is_some(),
            "뒤에서 마저 돌린 해석이 위임을 캐시에 남기지 않았습니다"
        );
    }

    #[test]
    /// Without DO upstream the signatures never arrive, and a validating stub behind this server,
    /// or a forwarder validating through it, has nothing to check. The fake authority here adds
    /// signatures only when DO is set, so the test can tell whether this server sets it. The
    /// recursor has no trust anchor: it passes signatures on without validating.
    fn a_non_validating_recursor_still_carries_signatures_for_do_clients() {
        const PORT: u16 = 5404;
        let (sk_root, k_root) = ecdsa_key(21);
        let (sk_zone, k_zone) = ecdsa_key(22);

        let zone_owner = Name::from_str("signed").unwrap();
        let zone_ds = onetdns_dnssec::Ds::from_dnskey(&k_zone, &zone_owner, 2).unwrap();
        let zone_ds_rec = Record::new(zone_owner, 3600, RData::Unknown(43, zone_ds.rdata_bytes()));

        fn asked_for_dnssec(request: &Message) -> bool {
            request
                .opt()
                .and_then(Edns::from_record)
                .is_some_and(|edns| edns.dnssec_ok)
        }

        {
            let (sk, k) = (sk_root.clone(), k_root.clone());
            let ds_rec = zone_ds_rec.clone();
            spawn_server("127.0.0.34", PORT, move |req| {
                let q = req.questions.first().unwrap().clone();
                let signed = asked_for_dnssec(req);
                let mut m = base(req);
                if q.qtype == RecordType::DNSKEY && q.name.is_root() {
                    m.header.authoritative = true;
                    let dk = dnskey_rec(".", &k);
                    if signed {
                        let sig = rrsig_rec(&sk, &k, ".", RecordType::DNSKEY.0, &[dk.clone()]);
                        m.answers.push(dk);
                        m.answers.push(sig);
                    } else {
                        m.answers.push(dk);
                    }
                } else {
                    m.authorities.push(Record::new(
                        Name::from_str("signed").unwrap(),
                        3600,
                        RData::Ns(Name::from_str("ns.signed").unwrap()),
                    ));
                    if signed {
                        m.authorities.push(ds_rec.clone());
                        m.authorities.push(rrsig_rec(
                            &sk,
                            &k,
                            ".",
                            RecordType::DS.0,
                            &[ds_rec.clone()],
                        ));
                    }
                    m.additionals.push(Record::new(
                        Name::from_str("ns.signed").unwrap(),
                        3600,
                        RData::A(Ipv4Addr::new(127, 0, 0, 35)),
                    ));
                }
                m
            });
        }

        {
            let (sk, k) = (sk_zone.clone(), k_zone.clone());
            spawn_server("127.0.0.35", PORT, move |req| {
                let q = req.questions.first().unwrap().clone();
                let signed = asked_for_dnssec(req);
                let mut m = base(req);
                m.header.authoritative = true;
                if q.qtype == RecordType::DNSKEY && q.name.to_ascii_lower() == "signed" {
                    let dk = dnskey_rec("signed", &k);
                    if signed {
                        let sig = rrsig_rec(&sk, &k, "signed", RecordType::DNSKEY.0, &[dk.clone()]);
                        m.answers.push(dk);
                        m.answers.push(sig);
                    } else {
                        m.answers.push(dk);
                    }
                } else if q.name.to_ascii_lower() == "www.signed" && q.qtype == RecordType::A {
                    let a = Record::new(
                        Name::from_str("www.signed").unwrap(),
                        3600,
                        RData::A(Ipv4Addr::new(10, 0, 0, 21)),
                    );
                    if signed {
                        let sig = rrsig_rec(&sk, &k, "signed", RecordType::A.0, &[a.clone()]);
                        m.answers.push(a);
                        m.answers.push(sig);
                    } else {
                        m.answers.push(a);
                    }
                }
                m
            });
        }

        let root_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 34)), PORT);
        let rec = Recursor::new(vec![root_server], Duration::from_secs(2))
            .with_port(PORT)
            .with_test_loopback();
        assert!(
            !rec.is_validating(),
            "이 테스트는 검증하지 않는 리졸버를 전제로 합니다"
        );

        let resp = rec
            .resolve(&Name::from_str("www.signed").unwrap(), RecordType::A)
            .expect("해석 성공");
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
        assert!(
            resp.answers.iter().any(
                |record| matches!(&record.rdata, RData::A(ip) if *ip == Ipv4Addr::new(10, 0, 0, 21))
            ),
            "답 자체가 없습니다"
        );
        assert!(
            resp.answers
                .iter()
                .any(|record| record.rtype == RecordType::RRSIG),
            "검증하지 않는다는 이유로 업스트림에 DO를 설정하지 않아 서명을 받아 오지 못했습니다"
        );
        assert!(
            !resp.header.authentic_data,
            "검증하지 않았으므로 AD를 설정하면 안 됩니다"
        );
    }

    #[test]
    fn dnssec_secure_chain_sets_ad_and_bogus_servfails() {
        const PORT: u16 = 5400;
        let (sk_root, k_root) = ecdsa_key(11);
        let (sk_test, k_test) = ecdsa_key(12);

        let root_owner = Name::from_str(".").unwrap();
        let test_owner = Name::from_str("test").unwrap();
        let root_anchor = onetdns_dnssec::Ds::from_dnskey(&k_root, &root_owner, 2).unwrap();
        let test_ds = onetdns_dnssec::Ds::from_dnskey(&k_test, &test_owner, 2).unwrap();
        let test_ds_rec = Record::new(test_owner, 3600, RData::Unknown(43, test_ds.rdata_bytes()));

        {
            let (sk, k) = (sk_root.clone(), k_root.clone());
            let ds_rec = test_ds_rec.clone();
            spawn_server("127.0.0.30", PORT, move |req| {
                let q = req.questions.first().unwrap().clone();
                let mut m = base(req);
                if q.qtype == RecordType::DNSKEY && q.name.is_root() {
                    m.header.authoritative = true;
                    let dk = dnskey_rec(".", &k);
                    let sig = rrsig_rec(&sk, &k, ".", RecordType::DNSKEY.0, &[dk.clone()]);
                    m.answers.push(dk);
                    m.answers.push(sig);
                } else {
                    m.authorities.push(Record::new(
                        Name::from_str("test").unwrap(),
                        3600,
                        RData::Ns(Name::from_str("ns.test").unwrap()),
                    ));
                    m.authorities.push(ds_rec.clone());
                    m.authorities.push(rrsig_rec(
                        &sk,
                        &k,
                        ".",
                        RecordType::DS.0,
                        &[ds_rec.clone()],
                    ));
                    m.additionals.push(Record::new(
                        Name::from_str("ns.test").unwrap(),
                        3600,
                        RData::A(Ipv4Addr::new(127, 0, 0, 31)),
                    ));
                }
                m
            });
        }

        {
            let (sk, k) = (sk_test.clone(), k_test.clone());
            spawn_server("127.0.0.31", PORT, move |req| {
                let q = req.questions.first().unwrap().clone();
                let mut m = base(req);
                m.header.authoritative = true;
                if q.qtype == RecordType::DNSKEY && q.name.to_ascii_lower() == "test" {
                    let dk = dnskey_rec("test", &k);
                    let sig = rrsig_rec(&sk, &k, "test", RecordType::DNSKEY.0, &[dk.clone()]);
                    m.answers.push(dk);
                    m.answers.push(sig);
                } else if q.name.to_ascii_lower() == "host.test" && q.qtype == RecordType::A {
                    let a = Record::new(
                        Name::from_str("host.test").unwrap(),
                        3600,
                        RData::A(Ipv4Addr::new(10, 0, 0, 9)),
                    );
                    let sig = rrsig_rec(&sk, &k, "test", RecordType::A.0, &[a.clone()]);
                    m.answers.push(a);
                    m.answers.push(sig);
                } else if q.name.to_ascii_lower() == "alias.test" {
                    let cn = Record::new(
                        Name::from_str("alias.test").unwrap(),
                        3600,
                        RData::Cname(Name::from_str("host.test").unwrap()),
                    );
                    let sig = rrsig_rec(&sk, &k, "test", RecordType::CNAME.0, &[cn.clone()]);
                    m.answers.push(cn);
                    m.answers.push(sig);
                } else if q.name.to_ascii_lower() == "host.test" {
                    let soa = Record::new(
                        Name::from_str("test").unwrap(),
                        3600,
                        RData::soa(onetdns_proto::Soa {
                            mname: Name::from_str("ns.test").unwrap(),
                            rname: Name::from_str("hostmaster.test").unwrap(),
                            serial: 1,
                            refresh: 3600,
                            retry: 600,
                            expire: 86_400,
                            minimum: 300,
                        }),
                    );
                    let soa_sig = rrsig_rec(&sk, &k, "test", RecordType::SOA.0, &[soa.clone()]);
                    let ns = nsec_rec("host.test", "z.test", &[1, 46, 47]);
                    let sig = rrsig_rec(&sk, &k, "test", RecordType::NSEC.0, &[ns.clone()]);
                    m.authorities.push(soa);
                    m.authorities.push(soa_sig);
                    m.authorities.push(ns);
                    m.authorities.push(sig);
                }
                m
            });
        }

        let root_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 30)), PORT);

        let rec = Recursor::new(vec![root_server], Duration::from_secs(2))
            .with_port(PORT)
            .with_test_loopback()
            .with_trust_anchors(vec![root_anchor.clone()]);
        let resp = rec
            .resolve(&Name::from_str("host.test").unwrap(), RecordType::A)
            .expect("해석 성공");
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
        assert!(resp.header.authentic_data, "검증된 답은 AD=1");
        assert_eq!(
            resp.answers
                .iter()
                .filter(|r| r.rtype == RecordType::A)
                .count(),
            1
        );

        let nodata = rec
            .resolve(&Name::from_str("host.test").unwrap(), RecordType::AAAA)
            .expect("NODATA 해석");
        assert_eq!(nodata.header.rcode, ResponseCode::NoError.0);
        assert!(nodata.answers.is_empty());
        assert!(nodata.header.authentic_data, "보안 NODATA는 AD=1");

        let cname = rec
            .resolve(&Name::from_str("alias.test").unwrap(), RecordType::A)
            .expect("CNAME 체인 해석");
        assert_eq!(cname.header.rcode, ResponseCode::NoError.0);
        assert!(
            cname
                .answers
                .iter()
                .any(|r| matches!(r.rdata, RData::Cname(_))),
            "CNAME 레코드 포함"
        );
        assert!(
            cname
                .answers
                .iter()
                .any(|r| matches!(&r.rdata, RData::A(ip) if *ip == Ipv4Addr::new(10, 0, 0, 9))),
            "최종 A 레코드 포함"
        );
        assert!(
            cname.header.authentic_data,
            "전부 secure한 CNAME 체인은 AD=1"
        );
        assert!(cname.answers.iter().any(|record| {
            record
                .name
                .eq_ignore_case(&Name::from_str("alias.test").unwrap())
                && onetdns_dnssec::Rrsig::from_record(record)
                    .is_some_and(|signature| signature.type_covered == RecordType::CNAME.0)
        }));
        assert!(cname.answers.iter().any(|record| {
            record
                .name
                .eq_ignore_case(&Name::from_str("host.test").unwrap())
                && onetdns_dnssec::Rrsig::from_record(record)
                    .is_some_and(|signature| signature.type_covered == RecordType::A.0)
        }));

        let wrong_anchor =
            onetdns_dnssec::Ds::from_dnskey(&k_test, &Name::from_str(".").unwrap(), 2).unwrap();
        let rec_bad = Recursor::new(vec![root_server], Duration::from_secs(2))
            .with_port(PORT)
            .with_test_loopback()
            .with_trust_anchors(vec![wrong_anchor]);
        let resp2 = rec_bad
            .resolve(&Name::from_str("host.test").unwrap(), RecordType::A)
            .expect("해석 시도");
        assert_eq!(
            resp2.header.rcode,
            ResponseCode::ServFail.0,
            "bogus는 SERVFAIL"
        );
        assert!(!resp2.header.authentic_data);

        let opt = resp2.opt().expect("bogus 응답에 OPT");
        let (code, _) = Edns::from_record(opt).unwrap().ede().expect("EDE");
        assert_eq!(code, ede_code::DNSSEC_BOGUS);

        let bogus_nodata = rec_bad
            .resolve(&Name::from_str("host.test").unwrap(), RecordType::AAAA)
            .expect("bogus NODATA도 DNS 응답으로 반환");
        assert_eq!(
            bogus_nodata.header.rcode,
            ResponseCode::ServFail.0,
            "DNSSEC 음성 증명 실패도 strict 플래그와 무관하게 fail-closed"
        );
        assert!(!bogus_nodata.header.authentic_data);

        let bad_anchor2 =
            onetdns_dnssec::Ds::from_dnskey(&k_test, &Name::from_str(".").unwrap(), 2).unwrap();
        let rec_perm = Recursor::new(vec![root_server], Duration::from_secs(2))
            .with_port(PORT)
            .with_test_loopback()
            .with_trust_anchors(vec![bad_anchor2])
            .with_dnssec_permissive(true);
        let resp_perm = rec_perm
            .resolve(&Name::from_str("host.test").unwrap(), RecordType::A)
            .expect("permissive 해석");
        assert_eq!(
            resp_perm.header.rcode,
            ResponseCode::NoError.0,
            "permissive: bogus여도 SERVFAIL 아님"
        );
        assert!(!resp_perm.header.authentic_data, "permissive: AD=0");
        assert!(
            resp_perm
                .answers
                .iter()
                .any(|r| matches!(r.rdata, RData::A(_))),
            "permissive: 데이터 반환"
        );
        let permissive_nodata = rec_perm
            .resolve(&Name::from_str("host.test").unwrap(), RecordType::AAAA)
            .expect("permissive NODATA");
        assert_eq!(permissive_nodata.header.rcode, ResponseCode::NoError.0);
        assert!(!permissive_nodata.header.authentic_data);

        let bad3 =
            onetdns_dnssec::Ds::from_dnskey(&k_test, &Name::from_str(".").unwrap(), 2).unwrap();
        let rec_cd = Arc::new(
            Recursor::new(vec![root_server], Duration::from_secs(2))
                .with_port(PORT)
                .with_test_loopback()
                .with_trust_anchors(vec![bad3])
                .with_ignore_cd(false),
        );
        let n = Name::from_str("host.test").unwrap();

        let r_cd1 = rec_cd
            .resolve_with_ns_cd(&n, RecordType::A, true)
            .expect("cd 해석")
            .0;
        assert_eq!(
            r_cd1.header.rcode,
            ResponseCode::NoError.0,
            "CD honor: 데이터"
        );
        assert!(!r_cd1.header.authentic_data, "CD honor: AD=0");

        let r_cd0 = rec_cd
            .resolve_with_ns_cd(&n, RecordType::A, false)
            .expect("cd0 해석")
            .0;
        assert_eq!(
            r_cd0.header.rcode,
            ResponseCode::ServFail.0,
            "CD=0: bogus SERVFAIL"
        );

        let bad4 =
            onetdns_dnssec::Ds::from_dnskey(&k_test, &Name::from_str(".").unwrap(), 2).unwrap();
        let rec_ign = Arc::new(
            Recursor::new(vec![root_server], Duration::from_secs(2))
                .with_port(PORT)
                .with_test_loopback()
                .with_trust_anchors(vec![bad4]),
        );
        let r_ign = rec_ign
            .resolve_with_ns_cd(&n, RecordType::A, true)
            .expect("ign 해석")
            .0;
        assert_eq!(
            r_ign.header.rcode,
            ResponseCode::ServFail.0,
            "ignore_cd=true: CD 무시 SERVFAIL"
        );
    }

    #[test]
    /// That verdict must be cached; otherwise the zone's next query cannot start from the cached
    /// delegation and walks from the root again.
    fn unsigned_delegation_is_insecure_not_servfail() {
        const PORT: u16 = 5402;
        let (sk_root, k_root) = ecdsa_key(21);
        let root_owner = Name::from_str(".").unwrap();
        let root_anchor = onetdns_dnssec::Ds::from_dnskey(&k_root, &root_owner, 2).unwrap();
        let root_queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        {
            let (sk, k) = (sk_root.clone(), k_root.clone());
            let root_queries = root_queries.clone();
            spawn_server("127.0.0.40", PORT, move |req| {
                root_queries.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let q = req.questions.first().unwrap().clone();
                let mut m = base(req);
                if q.qtype == RecordType::DNSKEY && q.name.is_root() {
                    m.header.authoritative = true;
                    let dk = dnskey_rec(".", &k);
                    let sig = rrsig_rec(&sk, &k, ".", RecordType::DNSKEY.0, &[dk.clone()]);
                    m.answers.push(dk);
                    m.answers.push(sig);
                } else {
                    m.authorities.push(Record::new(
                        Name::from_str("insecure.test").unwrap(),
                        3600,
                        RData::Ns(Name::from_str("ns.insecure.test").unwrap()),
                    ));
                    m.additionals.push(Record::new(
                        Name::from_str("ns.insecure.test").unwrap(),
                        3600,
                        RData::A(Ipv4Addr::new(127, 0, 0, 41)),
                    ));
                }
                m
            });
        }

        spawn_server("127.0.0.41", PORT, move |req| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            m.header.authoritative = true;
            if q.name.to_ascii_lower() == "host.insecure.test" && q.qtype == RecordType::A {
                m.answers.push(Record::new(
                    Name::from_str("host.insecure.test").unwrap(),
                    3600,
                    RData::A(Ipv4Addr::new(203, 0, 113, 5)),
                ));
            } else {
                m.authorities.push(Record::new(
                    Name::from_str("insecure.test").unwrap(),
                    300,
                    RData::soa(onetdns_proto::Soa {
                        mname: Name::from_str("ns.insecure.test").unwrap(),
                        rname: Name::from_str("hostmaster.insecure.test").unwrap(),
                        serial: 1,
                        refresh: 300,
                        retry: 60,
                        expire: 3600,
                        minimum: 60,
                    }),
                ));
            }
            m
        });

        let root_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 40)), PORT);
        let rec = Recursor::new(vec![root_server], Duration::from_secs(2))
            .with_port(PORT)
            .with_test_loopback()
            .with_trust_anchors(vec![root_anchor.clone()]);
        let resp = rec
            .resolve(
                &Name::from_str("host.insecure.test").unwrap(),
                RecordType::A,
            )
            .expect("비서명 영역도 해석 성공해야 함");
        assert_eq!(
            resp.header.rcode,
            ResponseCode::NoError.0,
            "비서명 답은 SERVFAIL 아님"
        );
        assert!(!resp.header.authentic_data, "비서명 = AD=0");
        assert!(
            resp.answers
                .iter()
                .any(|r| matches!(&r.rdata, RData::A(ip) if *ip == Ipv4Addr::new(203, 0, 113, 5))),
            "비서명 A 답이 그대로 전달됨"
        );
        let insecure_zone = Name::from_str("insecure.test").unwrap();
        assert!(
            matches!(
                rec.validated_keys_cached(
                    &insecure_zone.canonical_key(),
                    &rec.trust_anchors.load()
                ),
                Some(ZoneTrust::Insecure)
            ),
            "서명 없는 영역이라는 판정이 캐시에 남아야 함"
        );
        assert!(rec.validated_start_ok(&insecure_zone));
        let root_before = root_queries.load(std::sync::atomic::Ordering::SeqCst);
        let nodata = rec
            .resolve(
                &Name::from_str("host.insecure.test").unwrap(),
                RecordType::AAAA,
            )
            .expect("비서명 영역의 NODATA도 허용");
        assert_eq!(nodata.header.rcode, ResponseCode::NoError.0);
        assert!(!nodata.header.authentic_data);
        assert_eq!(
            root_queries.load(std::sync::atomic::Ordering::SeqCst),
            root_before,
            "같은 비서명 영역의 다음 질의는 루트로 다시 가지 않아야 함"
        );

        let strict = Recursor::new(vec![root_server], Duration::from_secs(2))
            .with_port(PORT)
            .with_test_loopback()
            .with_trust_anchors(vec![root_anchor])
            .with_dnssec_strict(true);
        let stripped_ds = strict
            .resolve(
                &Name::from_str("host.insecure.test").unwrap(),
                RecordType::A,
            )
            .expect("DS 부재 증명 실패는 SERVFAIL 응답");
        assert_eq!(stripped_ds.header.rcode, ResponseCode::ServFail.0);
    }

    #[test]
    fn iterative_walk_root_tld_auth() {
        const PORT: u16 = 5388;
        let root_ip = Ipv4Addr::new(127, 0, 0, 1);
        let com_ip = Ipv4Addr::new(127, 0, 0, 2);
        let auth_ip = Ipv4Addr::new(127, 0, 0, 3);

        spawn_server("127.0.0.3", PORT, move |req| {
            a_answer(req, Ipv4Addr::new(93, 184, 216, 34))
        });

        spawn_server("127.0.0.2", PORT, move |req| {
            referral(req, "example.com", "ns.example.com", auth_ip)
        });

        spawn_server("127.0.0.1", PORT, move |req| {
            referral(req, "com", "ns.com", com_ip)
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(IpAddr::V4(root_ip), PORT)],
            Duration::from_secs(2),
        )
        .with_port(PORT)
        .with_test_loopback();

        let resp = rec
            .resolve(&Name::from_str("www.example.com").unwrap(), RecordType::A)
            .expect("해석 성공");
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].rdata {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(93, 184, 216, 34)),
            other => panic!("A 레코드를 예상했지만 실제 값은 {other:?}입니다"),
        }
    }

    #[test]
    fn non_validating_recursor_strips_upstream_ad_bit() {
        const PORT: u16 = 5399;
        let root_ip = Ipv4Addr::new(127, 0, 0, 1);
        let com_ip = Ipv4Addr::new(127, 0, 0, 2);
        let auth_ip = Ipv4Addr::new(127, 0, 0, 3);

        spawn_server("127.0.0.3", PORT, move |req| {
            let mut m = a_answer(req, Ipv4Addr::new(6, 6, 6, 6));
            m.header.authentic_data = true;
            m
        });
        spawn_server("127.0.0.2", PORT, move |req| {
            referral(req, "example.com", "ns.example.com", auth_ip)
        });
        spawn_server("127.0.0.1", PORT, move |req| {
            referral(req, "com", "ns.com", com_ip)
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(IpAddr::V4(root_ip), PORT)],
            Duration::from_secs(2),
        )
        .with_port(PORT)
        .with_test_loopback();

        let resp = rec
            .resolve(&Name::from_str("www.example.com").unwrap(), RecordType::A)
            .expect("해석 성공");
        assert_eq!(resp.answers.len(), 1);
        assert!(
            !resp.header.authentic_data,
            "비검증 recursor는 업스트림 AD=1을 제거해야 함"
        );
    }

    #[test]
    fn resolve_with_ns_collects_delegation() {
        const PORT: u16 = 5393;
        let root_ip = Ipv4Addr::new(127, 0, 0, 1);
        let com_ip = Ipv4Addr::new(127, 0, 0, 2);
        let auth_ip = Ipv4Addr::new(127, 0, 0, 3);
        spawn_server("127.0.0.3", PORT, move |req| {
            a_answer(req, Ipv4Addr::new(93, 184, 216, 34))
        });
        spawn_server("127.0.0.2", PORT, move |req| {
            referral(req, "example.com", "ns.example.com", auth_ip)
        });
        spawn_server("127.0.0.1", PORT, move |req| {
            referral(req, "com", "ns.com", com_ip)
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(IpAddr::V4(root_ip), PORT)],
            Duration::from_secs(2),
        )
        .with_port(PORT)
        .with_test_loopback();

        let (resp, ns) = rec
            .resolve_with_ns(&Name::from_str("www.example.com").unwrap(), RecordType::A)
            .expect("해석 성공");
        assert_eq!(resp.answers.len(), 1);
        let names: Vec<String> = ns.names.iter().map(|n| n.to_ascii_lower()).collect();
        assert!(
            names.iter().any(|n| n == "ns.com"),
            "NS 이름에 ns.com: {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "ns.example.com"),
            "NS 이름에 ns.example.com: {names:?}"
        );
        assert!(
            ns.ips.contains(&IpAddr::V4(com_ip)),
            "NS IP에 com 글루: {:?}",
            ns.ips
        );
        assert!(
            ns.ips.contains(&IpAddr::V4(auth_ip)),
            "NS IP에 auth 글루: {:?}",
            ns.ips
        );
    }

    #[test]
    fn follows_cname_chain() {
        const PORT: u16 = 5389;
        let auth_ip = Ipv4Addr::new(127, 0, 0, 5);

        spawn_server("127.0.0.5", PORT, move |req| {
            let mut m = base(req);
            m.header.authoritative = true;
            let q = req.questions.first().unwrap();
            let qn = q.name.to_ascii_lower();
            if qn == "alias.test" {
                m.answers.push(Record::new(
                    q.name.clone(),
                    300,
                    RData::Cname(Name::from_str("real.test").unwrap()),
                ));
            } else if qn == "real.test" {
                m.answers.push(Record::new(
                    q.name.clone(),
                    300,
                    RData::A(Ipv4Addr::new(10, 0, 0, 7)),
                ));
            }
            m
        });

        spawn_server("127.0.0.4", PORT, move |req| {
            referral(req, "test", "ns.test", auth_ip)
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)),
                PORT,
            )],
            Duration::from_secs(2),
        )
        .with_port(PORT)
        .with_test_loopback();

        let resp = rec
            .resolve(&Name::from_str("alias.test").unwrap(), RecordType::A)
            .expect("CNAME 추적 성공");

        assert!(resp
            .answers
            .iter()
            .any(|r| matches!(r.rdata, RData::Cname(_))));
        assert!(resp
            .answers
            .iter()
            .any(|r| matches!(&r.rdata, RData::A(ip) if *ip == Ipv4Addr::new(10, 0, 0, 7))));
    }

    #[test]
    fn qname_minimization_hides_full_name() {
        const PORT: u16 = 5391;
        let com_ip = Ipv4Addr::new(127, 0, 0, 21);
        let auth_ip = Ipv4Addr::new(127, 0, 0, 22);
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

        spawn_server("127.0.0.22", PORT, move |req| {
            a_answer(req, Ipv4Addr::new(5, 5, 5, 5))
        });

        spawn_server("127.0.0.21", PORT, move |req| {
            referral(req, "example.com", "ns.example.com", auth_ip)
        });

        let seen2 = seen.clone();
        spawn_server("127.0.0.20", PORT, move |req| {
            if let Some(q) = req.questions.first() {
                seen2.lock().unwrap().push(q.name.to_ascii_lower());
            }
            referral(req, "com", "ns.com", com_ip)
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 20)),
                PORT,
            )],
            Duration::from_secs(2),
        )
        .with_port(PORT)
        .with_test_loopback();

        let resp = rec
            .resolve(
                &Name::from_str("secret.www.example.com").unwrap(),
                RecordType::A,
            )
            .expect("해석 성공");
        assert_eq!(resp.answers.len(), 1);

        let seen = seen.lock().unwrap();
        assert!(!seen.is_empty(), "루트가 적어도 한 번 질의받아야");
        for name in seen.iter() {
            assert_eq!(name, "com", "루트가 최소화된 이름만 봐야: {name}");
        }
    }

    #[test]
    fn no_roots_errors() {
        let rec = Recursor::new(vec![], Duration::from_secs(1));
        assert!(matches!(
            rec.resolve(&Name::from_str("x.com").unwrap(), RecordType::A),
            Err(RecurseError::NoRoots)
        ));
    }

    #[test]
    fn parent_bailiwick_accepts_valid_sibling_glue() {
        const PORT: u16 = 5395;
        let root_ip = Ipv4Addr::new(127, 0, 0, 30);
        let com_ip = Ipv4Addr::new(127, 0, 0, 31);
        let auth_ip = Ipv4Addr::new(127, 0, 0, 32);

        spawn_server("127.0.0.32", PORT, move |req| {
            a_answer(req, Ipv4Addr::new(93, 184, 216, 34))
        });
        spawn_server("127.0.0.31", PORT, move |req| {
            referral(req, "example.com", "ns.example.com", auth_ip)
        });
        spawn_server("127.0.0.30", PORT, move |req| {
            referral(req, "com", "a.gtld.test", com_ip)
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(IpAddr::V4(root_ip), PORT)],
            Duration::from_secs(2),
        )
        .with_port(PORT)
        .with_test_loopback();
        let response = rec
            .resolve(&Name::from_str("www.example.com").unwrap(), RecordType::A)
            .expect("sibling glue를 사용해 해석 성공");
        assert!(response.answers.iter().any(
            |record| matches!(&record.rdata, RData::A(ip) if *ip == Ipv4Addr::new(93, 184, 216, 34))
        ));
    }

    #[test]
    fn bailiwick_rejects_out_of_zone_glue() {
        const PORT: u16 = 5390;
        let com_ip = Ipv4Addr::new(127, 0, 0, 11);

        spawn_server("127.0.0.11", PORT, move |req| {
            let mut m = base(req);
            m.authorities.push(Record::new(
                Name::from_str("victim.com").unwrap(),
                172800,
                RData::Ns(Name::from_str("ns.evil.org").unwrap()),
            ));
            m.additionals.push(Record::new(
                Name::from_str("ns.evil.org").unwrap(),
                172800,
                RData::A(Ipv4Addr::new(127, 0, 0, 99)),
            ));
            m
        });

        spawn_server("127.0.0.10", PORT, move |req| {
            referral(req, "com", "ns.com", com_ip)
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10)),
                PORT,
            )],
            Duration::from_millis(500),
        )
        .with_port(PORT)
        .with_test_loopback();

        let r = rec.resolve(&Name::from_str("www.victim.com").unwrap(), RecordType::A);
        assert!(
            matches!(r, Err(RecurseError::NoReachableNs)),
            "존 밖 글루 거부 → NoReachableNs, got {r:?}"
        );
    }

    #[test]
    fn ns_side_query_caches_only_reachable_answer_chain_addresses() {
        const PORT: u16 = 5403;
        let root_ip = Ipv4Addr::new(127, 0, 0, 70);
        let example_ip = Ipv4Addr::new(127, 0, 0, 71);
        let attacker_ip = Ipv4Addr::new(127, 0, 0, 73);
        let auth_ip = Ipv4Addr::new(127, 0, 0, 74);
        let attacker_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits = attacker_hits.clone();

        spawn_server("127.0.0.73", PORT, move |req| {
            hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            a_answer(req, Ipv4Addr::new(6, 6, 6, 6))
        });
        spawn_server("127.0.0.74", PORT, move |req| {
            a_answer(req, Ipv4Addr::new(1, 2, 3, 4))
        });
        spawn_server("127.0.0.71", PORT, move |req| {
            let question = req.questions.first().unwrap();
            let mut response = base(req);
            response.header.authoritative = true;
            if question
                .name
                .eq_ignore_case(&Name::from_str("ns.example").unwrap())
            {
                response.answers.push(Record::new(
                    question.name.clone(),
                    300,
                    RData::Cname(Name::from_str("real.example").unwrap()),
                ));
            } else {
                response
                    .answers
                    .push(Record::new(question.name.clone(), 300, RData::A(auth_ip)));
            }
            response.answers.push(Record::new(
                Name::from_str("attacker.invalid").unwrap(),
                3600,
                RData::A(attacker_ip),
            ));
            response
        });
        spawn_server("127.0.0.70", PORT, move |req| {
            let question = req.questions.first().unwrap();
            if question
                .name
                .eq_ignore_case(&Name::from_str("test").unwrap())
            {
                let mut response = base(req);
                response.header.authoritative = false;
                response.authorities.push(Record::new(
                    Name::from_str("test").unwrap(),
                    300,
                    RData::Ns(Name::from_str("ns.example").unwrap()),
                ));
                response
            } else {
                referral(req, "example", "ns.example", example_ip)
            }
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(IpAddr::V4(root_ip), PORT)],
            Duration::from_secs(1),
        )
        .with_port(PORT)
        .with_test_loopback();
        let response = rec
            .resolve(&Name::from_str("victim.test").unwrap(), RecordType::A)
            .expect("glue 없는 NS를 안전하게 side-resolve");
        assert!(response.answers.iter().any(
            |record| matches!(&record.rdata, RData::A(ip) if *ip == Ipv4Addr::new(1, 2, 3, 4))
        ));
        assert_eq!(
            rec.ns_addr_cached(&name_key("ns.example")),
            Some(vec![IpAddr::V4(auth_ip)])
        );
        assert_eq!(
            attacker_hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "NS side-query의 무관한 A로 연결하면 안 됨"
        );
    }

    #[test]
    fn unrelated_positive_answer_is_not_terminal() {
        const PORT: u16 = 5396;
        let root_ip = Ipv4Addr::new(127, 0, 0, 60);
        spawn_server("127.0.0.60", PORT, move |req| {
            let mut response = base(req);
            response.header.authoritative = true;
            response.answers.push(Record::new(
                Name::from_str("attacker.invalid").unwrap(),
                3600,
                RData::A(Ipv4Addr::new(127, 0, 0, 61)),
            ));
            response
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(IpAddr::V4(root_ip), PORT)],
            Duration::from_millis(300),
        )
        .with_port(PORT)
        .with_test_loopback();
        let result = rec.resolve(&Name::from_str("victim.test").unwrap(), RecordType::A);
        assert!(
            matches!(result, Err(RecurseError::NoReachableNs)),
            "무관한 A 레코드는 최종 답이 아니어야 함: {result:?}"
        );
    }

    #[test]
    fn terminal_response_strips_unrelated_sections() {
        const PORT: u16 = 5399;
        let root_ip = Ipv4Addr::new(127, 0, 0, 65);
        spawn_server("127.0.0.65", PORT, move |req| {
            let mut response = base(req);
            response.header.authoritative = true;
            response.answers.push(Record::new(
                req.questions[0].name.clone(),
                300,
                RData::A(Ipv4Addr::new(1, 2, 3, 4)),
            ));
            response.answers.push(Record::new(
                Name::from_str("attacker.invalid").unwrap(),
                3600,
                RData::A(Ipv4Addr::new(6, 6, 6, 6)),
            ));
            response.authorities.push(Record::new(
                Name::from_str("attacker.invalid").unwrap(),
                3600,
                RData::Ns(Name::from_str("ns.attacker.invalid").unwrap()),
            ));
            response.additionals.push(Record::new(
                Name::from_str("ns.attacker.invalid").unwrap(),
                3600,
                RData::A(Ipv4Addr::new(6, 6, 6, 6)),
            ));
            response
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(IpAddr::V4(root_ip), PORT)],
            Duration::from_millis(300),
        )
        .with_port(PORT)
        .with_test_loopback();
        let response = rec
            .resolve(&Name::from_str("victim").unwrap(), RecordType::A)
            .expect("관련 A는 반환되어야 함");
        assert_eq!(response.answers.len(), 1);
        assert!(response.answers[0]
            .name
            .eq_ignore_case(&Name::from_str("victim").unwrap()));
        assert!(response.authorities.is_empty());
        assert!(response.additionals.is_empty());
    }

    #[test]
    fn malformed_authority_response_fails_over_to_next_server() {
        const PORT: u16 = 5401;
        let bad_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let good_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let bad_count = bad_hits.clone();
        let good_count = good_hits.clone();
        let bad = spawn_server("127.0.0.66", PORT, move |req| {
            bad_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut response = base(req);
            response.header.authoritative = true;
            response.answers.push(Record::new(
                Name::from_str("attacker.invalid").unwrap(),
                300,
                RData::A(Ipv4Addr::new(6, 6, 6, 6)),
            ));
            response
        });
        let good = spawn_server("127.0.0.67", PORT, move |req| {
            good_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            a_answer(req, Ipv4Addr::new(1, 2, 3, 4))
        });

        let rec = Recursor::new(vec![bad, good], Duration::from_millis(600))
            .with_port(PORT)
            .with_test_loopback();
        let response = rec
            .resolve(&Name::from_str("victim").unwrap(), RecordType::A)
            .expect("두 번째 권한 서버로 failover");
        assert!(response.answers.iter().any(
            |record| matches!(&record.rdata, RData::A(ip) if *ip == Ipv4Addr::new(1, 2, 3, 4))
        ));
        assert_eq!(bad_hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(good_hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn unrelated_soa_cannot_prove_nxdomain() {
        const PORT: u16 = 5397;
        let root_ip = Ipv4Addr::new(127, 0, 0, 62);
        spawn_server("127.0.0.62", PORT, move |req| {
            let mut response = base(req);
            response.header.authoritative = true;
            response.header.rcode = ResponseCode::NXDomain.0;
            response.authorities.push(Record::new(
                Name::from_str("attacker.invalid").unwrap(),
                300,
                RData::soa(onetdns_proto::Soa {
                    mname: Name::from_str("ns.attacker.invalid").unwrap(),
                    rname: Name::from_str("hostmaster.attacker.invalid").unwrap(),
                    serial: 1,
                    refresh: 300,
                    retry: 60,
                    expire: 3600,
                    minimum: 60,
                }),
            ));
            response
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(IpAddr::V4(root_ip), PORT)],
            Duration::from_millis(300),
        )
        .with_port(PORT)
        .with_test_loopback();
        let result = rec.resolve(&Name::from_str("victim.test").unwrap(), RecordType::A);
        assert!(
            matches!(result, Err(RecurseError::NoReachableNs)),
            "무관한 SOA는 NXDOMAIN을 증명하지 못해야 함: {result:?}"
        );
    }

    #[test]
    fn servfail_authority_ns_cannot_seed_delegation_cache() {
        const PORT: u16 = 5398;
        let root_ip = Ipv4Addr::new(127, 0, 0, 63);
        let attacker_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits = attacker_hits.clone();
        spawn_server("127.0.0.64", PORT, move |req| {
            hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            a_answer(req, Ipv4Addr::new(6, 6, 6, 6))
        });
        spawn_server("127.0.0.63", PORT, move |req| {
            let mut response = referral(req, "test", "ns.test", Ipv4Addr::new(127, 0, 0, 64));
            response.header.rcode = ResponseCode::ServFail.0;
            response
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(IpAddr::V4(root_ip), PORT)],
            Duration::from_millis(300),
        )
        .with_port(PORT)
        .with_test_loopback();
        let result = rec.resolve(&Name::from_str("victim.test").unwrap(), RecordType::A);
        assert!(
            matches!(result, Err(RecurseError::NoReachableNs)),
            "SERVFAIL의 NS는 referral이 아니어야 함: {result:?}"
        );
        assert_eq!(
            attacker_hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "공격자 NS로 질의하면 안 됨"
        );
        assert!(
            rec.deleg_cached(&Name::from_str("test").unwrap()).is_none(),
            "SERVFAIL referral은 위임 캐시에 들어가면 안 됨"
        );
    }

    #[test]
    /// RFC 9276 asks for EDE 27 when many NSEC3 iterations lead to insecure or SERVFAIL. A broken
    /// signature (EDE 6) and a refused computation call for different action: the first is a broken
    /// zone, the second needs lower parameters. Both are SERVFAIL, so checking the rcode alone
    /// cannot tell them apart.
    fn excessive_nsec3_iterations_report_their_own_ede() {
        let plain = bogus_servfail(
            &make_query(
                &Name::from_str("bogus.example").unwrap(),
                RecordType::A,
                false,
            ),
            ede_code::DNSSEC_BOGUS,
        );
        let excessive = bogus_servfail(
            &make_query(
                &Name::from_str("bogus.example").unwrap(),
                RecordType::A,
                false,
            ),
            ede_code::UNSUPPORTED_NSEC3_ITERATIONS,
        );

        let ede_of = |msg: &Message| {
            Edns::from_record(msg.opt().expect("OPT"))
                .expect("EDNS")
                .ede()
                .expect("EDE")
        };
        assert_eq!(ede_of(&plain).0, ede_code::DNSSEC_BOGUS);
        assert_eq!(ede_of(&excessive).0, ede_code::UNSUPPORTED_NSEC3_ITERATIONS);
        assert_ne!(
            ede_of(&plain).1,
            ede_of(&excessive).1,
            "사유마다 다른 문구여야 운영자가 무엇을 고칠지 압니다"
        );
        assert_eq!(
            excessive.header.rcode,
            ResponseCode::ServFail.0,
            "rcode는 그대로 SERVFAIL입니다"
        );
    }

    #[test]
    /// The root answers address queries but not DNSKEY queries. With no proof of being unsigned the
    /// answer is still SERVFAIL, but the code must be EDE 22 and the bogus metric must not count
    /// it; EDE 6 would send operators to check sound signatures.
    fn unfetchable_keys_are_reported_as_an_unreachable_authority() {
        const PORT: u16 = 5424;
        let root = spawn_server("127.0.0.93", PORT, |req| {
            if req.questions.first().unwrap().qtype == RecordType::DNSKEY {
                // Mimics a silent server by answering with an ID this server discards.
                let mut m = base(req);
                m.header.id = req.header.id.wrapping_add(1);
                return m;
            }
            a_answer(req, Ipv4Addr::new(192, 0, 2, 93))
        });
        let anchor = onetdns_dnssec::Ds {
            key_tag: 1,
            algorithm: 13,
            digest_type: 2,
            digest: vec![1; 32],
        };
        let rec = Recursor::new(vec![root], Duration::from_millis(800))
            .with_port(PORT)
            .with_test_loopback()
            .with_trust_anchors(vec![anchor]);

        let before = test_thread_validation_bogus_total();
        let resp = rec
            .resolve(&Name::from_str("host.test").unwrap(), RecordType::A)
            .expect("SERVFAIL 응답이어야 합니다");
        assert_eq!(resp.header.rcode, ResponseCode::ServFail.0);
        let (code, _) = Edns::from_record(resp.opt().expect("OPT"))
            .expect("EDNS")
            .ede()
            .expect("EDE");
        assert_eq!(code, ede_code::NO_REACHABLE_AUTHORITY);
        assert_eq!(
            test_thread_validation_bogus_total(),
            before,
            "키를 받지 못한 것을 검증 실패로 셌습니다"
        );
    }

    #[test]
    fn bogus_servfail_increments_observability_counter() {
        let global_before = validation_bogus_total();
        let before = test_thread_validation_bogus_total();
        let template = make_query(
            &Name::from_str("bogus.example").unwrap(),
            RecordType::A,
            false,
        );
        let concurrent = template.clone();
        let noise = std::thread::spawn(move || {
            for _ in 0..32 {
                let _ = bogus_servfail(&concurrent, ede_code::DNSSEC_BOGUS);
            }
        });
        let sf = bogus_servfail(&template, ede_code::DNSSEC_BOGUS);
        noise.join().unwrap();
        assert_eq!(sf.header.rcode, ResponseCode::ServFail.0);
        assert!(
            validation_bogus_total() >= global_before.saturating_add(33),
            "동시 요청까지 전역 관측 카운터에 모두 기록되어야 함"
        );
        assert_eq!(
            test_thread_validation_bogus_total(),
            before + 1,
            "검증 실패 SERVFAIL은 이 요청의 관측 카운터를 한 번 올려야 함"
        );
    }
}
