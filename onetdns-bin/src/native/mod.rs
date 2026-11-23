//! State and resolution backends of the query handler every transport feeds into. `NativeServer`
//! holds the config, the feature swap, and the backend choice; the `query` module applies access
//! control, rate limits, cookies, policy, blocking, safe search, and client subnet before passing a
//! query down the chain.
//!
//! Blocking happens up here, so caches below cannot skip per-client policy. Fast paths send
//! cache-hit UDP queries without parsing and simple queries for this server's zones without
//! assembly; any feature that changes the response turns them off.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use onetdns_control::Recorder;
use onetdns_core::{
    AccessControl, ArcSwap, BlockResponse, ClientInfo, FilterVerdict, IpNet, LruMap, RateLimiter,
    RewriteTarget,
};
use onetdns_filter::SharedFilter;
use onetdns_forward::Forwarder;
use onetdns_proto::{
    Message, Name as ApName, RData as ApRData, Record as ApRecord, RecordType as ApRt,
};
use onetdns_recurse::Recursor;
use onetdns_security::CookieKeeper;

mod authority;
mod handler;
#[cfg(unix)]
mod lane;
mod observe;
mod query;
mod response;

use authority::AuthorityWirePath;
pub(crate) use authority::{NotifyKick, UpdateRule, ZoneJournal};
pub(crate) use query::RelayAdmission;
pub(crate) use response::{
    block_rcode, error_resp, local_only_negative_response, rcode_str, rdata_brief,
};
use response::{block_resp, records_resp};

const OPT_COOKIE: u16 = 10;

/// Advertised when the configured size is too small. The IPv6 minimum MTU minus headers, so the
/// path does not fragment.
const DEFAULT_EDNS_PAYLOAD: u16 = 1232;

/// Largest UDP response this server sends. A peer advertising less needs the truncation ladder, so
/// the fast path does not take it.
const SERVER_UDP_MAX: u16 = 1232;

/// Root name 1 + type 2 + class 2 + TTL 4 + length 2.
const EMPTY_OPT_WIRE_LEN: usize = 11;
const OPT_NSID: u16 = 3;

/// Lowercase.
const DDR_OWNER_WIRE: &[u8] = b"\x04_dns\x08resolver\x04arpa\x00";

/// Compares case-insensitively, without allocating.
#[cfg_attr(not(unix), allow(dead_code))]
fn ddr_owner(name: &ApName) -> bool {
    name.as_uncompressed_wire()
        .eq_ignore_ascii_case(DDR_OWNER_WIRE)
}

/// No legitimate query is this large.
const MAX_LARGE_QUERY_BYTES: usize = 1024;

#[derive(Clone, Default)]
pub struct CookiePolicy {
    /// Without a keeper, cookies are off.
    pub keeper: Option<Arc<CookieKeeper>>,
    /// Rejects queries with a missing or wrong cookie.
    pub strict: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct SchedWindow {
    /// Bitmask.
    pub days: u8,
    /// Minutes since midnight.
    pub start_min: u32,
    /// Minutes since midnight.
    pub end_min: u32,
}

#[derive(Debug, Default)]
/// Windows when service blocking pauses.
pub struct Schedule {
    pub windows: Vec<SchedWindow>,
}

impl Schedule {
    /// A window past midnight also counts under the previous day.
    pub fn is_active(&self, now: SystemTime) -> bool {
        if self.windows.is_empty() {
            return false;
        }
        let (dow, tod_min) = crate::localtime::local_weekday_minute(now);
        let tod_min = u32::from(tod_min);
        self.windows.iter().any(|w| {
            if w.start_min < w.end_min {
                (w.days & (1 << dow)) != 0 && tod_min >= w.start_min && tod_min < w.end_min
            } else {
                let previous_dow = (dow + 6) % 7;
                ((w.days & (1 << dow)) != 0 && tod_min >= w.start_min)
                    || ((w.days & (1 << previous_dow)) != 0 && tod_min < w.end_min)
            }
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Set by `evaluate_lane_gates` from the config and facts outside it.
pub(crate) struct LaneGates {
    /// Cache-hit UDP queries.
    pub(crate) wire: bool,
    /// Simple queries for this server's zones.
    pub(crate) authority: bool,
    /// Recursive cold misses, without holding a thread while waiting.
    pub(crate) reactor: bool,
}

impl Default for LaneGates {
    /// Opens all three; used by handlers not yet configured. A running server sets the result of
    /// `evaluate_lane_gates` at start and on every config swap.
    fn default() -> Self {
        LaneGates {
            wire: true,
            authority: true,
            reactor: true,
        }
    }
}

#[derive(Clone, Default)]
/// Response features decided by one config, swapped together on reload. State that carries over
/// between generations, such as the in-flight count, the recorder, and the safe search switch,
/// lives in `NativeServer` instead; kept here, it would have to be carried over on every config
/// change, and one missed would reset.
///
/// Fast paths read their gates, the chain generation, and the wire generation from this one value.
/// If a new chain generation were visible with the old gates, the new chain's cache would store
/// answers built under the old conditions and serve them for their whole TTL.
pub struct NativeFeatures {
    pub block_aaaa: bool,
    /// Synthesizes IPv6 answers from IPv4 ones.
    pub dns64_prefix: Option<[u8; 16]>,
    /// Synthesizes even when an IPv6 answer exists.
    pub dns64_synthall: bool,
    /// Blocks outside names that point to private addresses.
    pub rebind_protection: bool,
    pub rebind_allow: Vec<ApName>,
    /// Answers with these addresses become NXDOMAIN.
    pub bogus_nxdomain: Vec<IpNet>,
    pub recurse_deny_answers: Vec<IpNet>,
    pub recurse_allow_answers: Vec<IpNet>,
    pub rrset_roundrobin: bool,
    pub nsid: Option<Vec<u8>>,
    pub cookies: CookiePolicy,

    /// dnstap output.
    pub inflight_max: usize,

    /// Advertised UDP receive size.
    pub dnstap: Option<Arc<onetdns_control::DnstapWriter>>,

    pub edns_buffer: u16,

    pub hide_identity: bool,
    pub hide_version: bool,

    pub server_identity: Vec<u8>,
    /// Accepting it invites amplification through large answers.
    pub server_version: Vec<u8>,

    pub allow_any: bool,
    pub minimal_responses: bool,
    /// So the size does not reveal the content.
    pub padding_block: usize,
    /// None does not advertise it.
    pub tcp_keepalive_100ms: Option<u16>,
    /// ECS is in use, so responses echo the client's option.
    pub ecs_in_use: bool,
    pub harden_large_queries: bool,

    /// When on, `_dns.resolver.arpa` skips the fast paths so the DDR layer answers it.
    pub ddr_enabled: bool,

    /// Cache and recursive resolver of the current chain generation.
    pub(crate) lane_runtime: Option<Arc<LaneRuntime>>,
    pub(crate) lanes: LaneGates,
    /// Bumped whenever a setting that changes responses changes, so entries from an earlier
    /// generation carry another tag and do not go out again.
    pub(crate) wire_epoch: usize,
}

impl NativeFeatures {
    /// Equal only when both the block engine and the config generation match.
    pub(crate) fn wire_tag(&self, filter: &Arc<onetdns_filter::BlockEngine>) -> usize {
        (Arc::as_ptr(filter) as usize).rotate_left(17) ^ self.wire_epoch
    }

    /// Moves the fast paths to the new chain generation's cache and recursive resolver; `recursor`
    /// is None for a forward-only chain.
    pub(crate) fn adopt_chain(
        &mut self,
        factory: crate::wirecache::WireEntryFactory,
        cache: crate::cache::CacheHandle,
        recursor: Option<Arc<Recursor>>,
    ) {
        self.lane_runtime = Some(Arc::new(LaneRuntime {
            factory: Some(factory),
            cache,
            recursor,
        }));
    }
}

pub struct NativeFeatureSwap {
    swap: ArcSwap<NativeFeatures>,
    /// So tests can pin the number of snapshots per query.
    #[cfg(test)]
    test_loads: AtomicUsize,
}

impl NativeFeatureSwap {
    fn from_pointee(value: NativeFeatures) -> Self {
        Self {
            swap: ArcSwap::from_pointee(value),
            #[cfg(test)]
            test_loads: AtomicUsize::new(0),
        }
    }

    pub fn load(&self) -> Arc<NativeFeatures> {
        #[cfg(test)]
        self.test_loads.fetch_add(1, Ordering::Relaxed);
        self.swap.load()
    }

    /// Returns the count since the last call and resets it.
    #[cfg(test)]
    fn take_test_loads(&self) -> usize {
        self.test_loads.swap(0, Ordering::Relaxed)
    }

    pub fn store(&self, value: Arc<NativeFeatures>) {
        self.swap.store(value);
    }
}

/// Counts a query in flight until dropped.
struct InflightGuard<'a>(&'a AtomicUsize);
impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) fn is_single_label(name: &ApName) -> bool {
    name.num_labels() == 1
}

pub(crate) fn policy_transport(t: onetdns_core::Transport) -> onetdns_policy::QueryTransport {
    use onetdns_core::Transport as T;
    use onetdns_policy::QueryTransport as Q;
    match t {
        T::Do53Udp => Q::Do53Udp,
        T::Do53Tcp => Q::Do53Tcp,
        T::DoT => Q::Dot,
        T::DoH => Q::Doh,
        T::DoH3 => Q::Doh3,
        T::DoQ => Q::Doq,
        T::DnsCrypt => Q::DnsCrypt,
    }
}

/// None for invalid characters, which are not repaired.
pub(crate) fn normalized_text_name(name: &ApName) -> Option<String> {
    let mut out = String::new();
    for (index, label) in name.labels().iter().enumerate() {
        let label = std::str::from_utf8(label).ok()?;
        if index > 0 {
            out.push('.');
        }
        out.extend(label.chars().map(|c| c.to_ascii_lowercase()));
    }
    Some(out)
}

/// Reads a name under in-addr.arpa from the first octet, stopping at the first label that is not an
/// octet. None outside in-addr.arpa; otherwise the octets read and whether every label below was
/// one.
fn reverse_v4_octets(name: &ApName) -> Option<(Vec<u8>, bool)> {
    let mut labels = name.labels().rev();
    if !labels.next()?.eq_ignore_ascii_case(b"arpa")
        || !labels.next()?.eq_ignore_ascii_case(b"in-addr")
    {
        return None;
    }
    let mut octets = Vec::new();
    for label in labels {
        match std::str::from_utf8(label)
            .ok()
            .and_then(|text| text.parse::<u8>().ok())
        {
            Some(octet) => octets.push(octet),
            None => return Some((octets, false)),
        }
    }
    Some((octets, true))
}

/// False when octets are missing.
fn is_private_v4(octets: &[u8]) -> bool {
    matches!(
        octets,
        [10, ..] | [127, ..] | [192, 168, ..] | [169, 254, ..]
    ) || matches!(octets, [172, b, ..] if (16u8..=31).contains(b))
}

pub(crate) fn is_private_reverse(name: &ApName) -> bool {
    if let Some((octets, whole)) = reverse_v4_octets(name) {
        return whole && is_private_v4(&octets);
    }
    let labels: Vec<String> = name
        .labels()
        .iter()
        .map(|l| String::from_utf8_lossy(l).to_ascii_lowercase())
        .collect();
    let n = labels.len();
    if n < 3 {
        return false;
    }
    if labels[n - 2] == "ip6" && labels[n - 1] == "arpa" {
        let nibs = &labels[..n - 2];
        let hi = nibs.last().map(String::as_str);
        let hi2 = (nibs.len() >= 2).then(|| nibs[nibs.len() - 2].as_str());
        if hi == Some("f") {
            if matches!(hi2, Some("c") | Some("d")) {
                return true;
            }
            if hi2 == Some("e") && nibs.len() >= 3 {
                return matches!(nibs[nibs.len() - 3].as_str(), "8" | "9" | "a" | "b");
            }
        }
        return false;
    }
    false
}

/// Names that must not be asked upstream.
pub(crate) fn is_empty_zone(name: &ApName) -> bool {
    if let Some((octets, _)) = reverse_v4_octets(name) {
        // The zone is set by its top octets, and labels below them are inside it even when they are
        // not octets: DNS-SD asks names like lb._dns-sd._udp.0.1.168.192.in-addr.arpa per subnet.
        // 100.64.0.0/10 is the carrier-grade NAT shared space, which RFC 7793 splits into 64 zones.
        if is_private_v4(&octets)
            || matches!(octets.as_slice(), [100, b, ..] if (64u8..=127).contains(b))
        {
            return true;
        }
    } else if is_private_reverse(name) {
        return true;
    }
    let s = name.to_ascii_lower();
    let s = s.trim_end_matches('.');
    const ZONES: &[&str] = &[
        "home.arpa",
        "empty.as112.arpa",
        "0.in-addr.arpa",
        "255.in-addr.arpa",
        "2.0.192.in-addr.arpa",
        "100.51.198.in-addr.arpa",
        "113.0.203.in-addr.arpa",
        "8.e.f.ip6.arpa",
        "9.e.f.ip6.arpa",
        "a.e.f.ip6.arpa",
        "b.e.f.ip6.arpa",
        "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
        "8.b.d.0.1.0.0.2.ip6.arpa",
    ];
    ZONES
        .iter()
        .any(|z| s == *z || s.ends_with(&format!(".{z}")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Decides whether a fallback path is tried: only a transport failure is worth asking again, and
/// anything else would get the same result.
pub enum ResolveFailure {
    /// Worth asking another way.
    TransportExhausted,

    /// Asking again gives the same; carries the reason code for the client.
    Permanent(Option<u16>),
}

pub enum ResolveOutcome {
    Response(Message),
    Failure(ResolveFailure),
}

/// One slot in the resolution chain.
pub trait Resolver: Send + Sync {
    /// None when it cannot answer.
    fn resolve(&self, request: &Message) -> Option<Message>;

    /// By default, no answer counts as a permanent failure.
    fn resolve_outcome(&self, request: &Message) -> ResolveOutcome {
        match self.resolve(request) {
            Some(response) => ResolveOutcome::Response(response),
            None => ResolveOutcome::Failure(ResolveFailure::Permanent(None)),
        }
    }
}

/// Forward resolver not yet built. The slot exists even when the backend does not forward, so
/// switching the backend to forward or split replaces it without a restart.
pub struct UnbuiltForward;

impl Resolver for UnbuiltForward {
    fn resolve(&self, _request: &Message) -> Option<Message> {
        None
    }
}

#[derive(Clone)]
/// Swaps one resolver on reload without rebuilding the chain. Queries already holding the slot
/// finish on the previous one.
pub struct ResolverSlot {
    inner: Arc<RwLock<Arc<dyn Resolver>>>,
}

impl ResolverSlot {
    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(resolver)),
        }
    }

    pub fn load(&self) -> Arc<dyn Resolver> {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// The next query uses the new one.
    pub fn replace(&self, resolver: Arc<dyn Resolver>) {
        *self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = resolver;
    }
}

impl Resolver for ResolverSlot {
    fn resolve(&self, request: &Message) -> Option<Message> {
        self.load().resolve(request)
    }

    fn resolve_outcome(&self, request: &Message) -> ResolveOutcome {
        self.load().resolve_outcome(request)
    }
}

#[derive(Clone)]
/// Sends chosen clients to other upstreams. The route is wrapped in the same safety and cache
/// layers; otherwise matching a client alone would skip policy and this server's zones.
pub struct ClientUpstream {
    pub nets: Vec<IpNet>,
    pub ids: Vec<String>,
    pub resolver: Arc<dyn Resolver>,
    /// Separates this route's answers in the shared cache.
    upstreams: Vec<String>,
}

impl ClientUpstream {
    pub fn new(
        nets: Vec<IpNet>,
        ids: Vec<String>,
        upstreams: Vec<String>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        ClientUpstream {
            nets,
            ids,
            resolver,
            upstreams,
        }
    }

    /// The name separating this route's answers in the shared cache. The upstreams decide the
    /// answers, not the clients: keyed by client, servers with different upstreams for the same
    /// range would mix answers.
    pub fn namespace_key(&self) -> String {
        let mut upstreams = self.upstreams.clone();
        upstreams.sort_unstable();
        upstreams.dedup();
        upstreams.join(",")
    }

    fn matches(&self, client: &ClientInfo) -> bool {
        if self.nets.iter().any(|n| n.contains(&client.source_ip)) {
            return true;
        }
        if let Some(id) = &client.client_id {
            if self.ids.iter().any(|x| x == id) {
                return true;
            }
        }
        false
    }
}

/// Exported as a metric.
pub static DNSSEC_BOGUS_TOTAL: AtomicU64 = AtomicU64::new(0);

fn recurse_failure(error: onetdns_recurse::RecurseError, qname: &ApName) -> ResolveFailure {
    use onetdns_recurse::RecurseError as E;
    match error {
        E::NoResponse => ResolveFailure::TransportExhausted,
        E::NoRoots | E::NoReachableNs => {
            ResolveFailure::Permanent(Some(onetdns_proto::ede_code::NO_REACHABLE_AUTHORITY))
        }
        E::Bogus => {
            note_dnssec_bogus(qname);
            ResolveFailure::Permanent(Some(onetdns_proto::ede_code::DNSSEC_BOGUS))
        }

        E::TooManyReferrals | E::TooManyCnames | E::TooManyDnames | E::TooManyQueries => {
            ResolveFailure::Permanent(Some(onetdns_proto::ede_code::OTHER))
        }
    }
}

/// Reason code and text reported to the client.
pub(crate) fn failure_diagnosis(
    failure: &ResolveFailure,
) -> (&'static str, &'static str, Option<u16>) {
    match failure {
        ResolveFailure::TransportExhausted => (
            "RESOLVER_TRANSPORT_EXHAUSTED",
            "transport_exhausted",
            Some(onetdns_proto::ede_code::NETWORK_ERROR),
        ),
        ResolveFailure::Permanent(ede) => ("RESOLVER_PERMANENT_FAILURE", "permanent", *ede),
    }
}

fn note_dnssec_bogus(qname: &onetdns_proto::Name) {
    let count = DNSSEC_BOGUS_TOTAL
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    if count.is_power_of_two() {
        onetdns_core::warn!(
            event = "dnssec.validation_bogus",
            qname = %qname,
            count = count,
            "Blocked a response that failed DNSSEC validation"
        );
    }
}

pub enum NativeBackend {
    Forward(Forwarder),

    Recurse {
        recursor: Arc<Recursor>,
        ns_rpz: Option<Arc<SharedFilter>>,
        block_ttl: Arc<AtomicU32>,
        local_ttl: Arc<AtomicU32>,
    },
}

impl Resolver for NativeBackend {
    fn resolve(&self, request: &Message) -> Option<Message> {
        match self.resolve_outcome(request) {
            ResolveOutcome::Response(response) => Some(response),
            ResolveOutcome::Failure(_) => None,
        }
    }

    /// When forwarding, clears AD: this server must not pass on as validated what it did not
    /// validate. Clears AA too, since the upstream is the authority, not this server; the authority
    /// layer above sets it for this server's zones.
    fn resolve_outcome(&self, request: &Message) -> ResolveOutcome {
        match self {
            NativeBackend::Forward(forwarder) => match forwarder.resolve(request) {
                Ok(mut response) => {
                    response.header.authentic_data = false;
                    response.header.authoritative = false;
                    normalize_response_ttls(&mut response);
                    ResolveOutcome::Response(response)
                }
                Err(onetdns_forward::ForwardError::Timeout)
                | Err(onetdns_forward::ForwardError::Io(_))
                | Err(onetdns_forward::ForwardError::BadResponse) => {
                    ResolveOutcome::Failure(ResolveFailure::TransportExhausted)
                }
                Err(onetdns_forward::ForwardError::NoUpstream) => {
                    ResolveOutcome::Failure(ResolveFailure::Permanent(None))
                }
            },
            NativeBackend::Recurse {
                recursor,
                ns_rpz,
                block_ttl,
                local_ttl,
            } => {
                let Some(q) = request.questions.first() else {
                    return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
                };
                let (mut message, ns) = match recursor.resolve_with_ns_cd(
                    &q.name,
                    q.qtype,
                    request.header.checking_disabled,
                ) {
                    Ok(result) => result,
                    Err(error) => {
                        return ResolveOutcome::Failure(recurse_failure(error, &q.name));
                    }
                };

                if let Some(filter) = ns_rpz {
                    if let Some(verdict) = filter.load().rpz_ns_verdict(&ns.names, &ns.ips) {
                        match verdict {
                            FilterVerdict::Allow => {}
                            FilterVerdict::Block(block) => {
                                return ResolveOutcome::Response(block_resp(
                                    request,
                                    &q.name,
                                    q.qtype,
                                    block,
                                    block_ttl.load(Ordering::Acquire),
                                ));
                            }
                            FilterVerdict::Drop => {
                                // RPZ triggers never produce a drop: the chain cannot withhold a
                                // response, so such a verdict answers NXDOMAIN like rpz-drop.
                                return ResolveOutcome::Response(block_resp(
                                    request,
                                    &q.name,
                                    q.qtype,
                                    BlockResponse::NxDomain,
                                    block_ttl.load(Ordering::Acquire),
                                ));
                            }
                            FilterVerdict::Rewrite(target) => {
                                return ResolveOutcome::Response(ns_rpz_rewrite(
                                    request,
                                    &q.name,
                                    q.qtype,
                                    &target,
                                    local_ttl.load(Ordering::Acquire),
                                ));
                            }
                        }
                    }
                }
                message.header.id = request.header.id;
                message.questions = request.questions.clone();
                strip_dnssec_unless_requested(request, &mut message);
                normalize_response_ttls(&mut message);
                ResolveOutcome::Response(message)
            }
        }
    }
}

/// Normalizes TTLs per RFC 2181 before the response splits into the cache, the wire fast path, and
/// the client, so all of them use the same values. Doing it on output would miss the path that
/// sends prebuilt wire bytes.
fn normalize_response_ttls(response: &mut Message) {
    onetdns_proto::normalize_ttls(&mut response.answers);
    onetdns_proto::normalize_ttls(&mut response.authorities);
    onetdns_proto::normalize_ttls(&mut response.additionals);
}

const NSEC3PARAM: ApRt = ApRt(51);

/// DNSKEY and DS are not listed: clients ask for them directly, and stripping them would drop the
/// very answer asked for.
fn is_dnssec_only_type(rtype: ApRt) -> bool {
    matches!(rtype, ApRt::RRSIG | ApRt::NSEC | ApRt::NSEC3 | NSEC3PARAM)
}

/// Reads DO from the OPT TTL without parsing the options, since this runs on every query.
pub(crate) fn wants_dnssec(request: &Message) -> bool {
    request
        .additionals
        .iter()
        .any(|record| record.rtype == ApRt::OPT && (record.ttl & 0x0000_8000) != 0)
}

/// The recursive resolver always asks upstream with DO set, so it holds signatures for clients that
/// want them; clients that did not ask get none, since they would only grow the response toward
/// truncation.
pub(crate) fn strip_dnssec_unless_requested(request: &Message, response: &mut Message) {
    let carries_dnssec = |section: &[ApRecord]| {
        section
            .iter()
            .any(|record| is_dnssec_only_type(record.rtype))
    };
    if !carries_dnssec(&response.answers)
        && !carries_dnssec(&response.authorities)
        && !carries_dnssec(&response.additionals)
    {
        return;
    }
    if wants_dnssec(request) {
        return;
    }
    let keep = |record: &ApRecord| !is_dnssec_only_type(record.rtype);
    response.answers.retain(keep);
    response.authorities.retain(keep);
    response.additionals.retain(keep);
}

/// Rewrites the answer when a name server in it is blocked.
fn ns_rpz_rewrite(
    request: &Message,
    qname: &ApName,
    qtype: ApRt,
    target: &RewriteTarget,
    ttl: u32,
) -> Message {
    match target {
        RewriteTarget::Records(rdatas) => {
            let recs: Vec<ApRecord> = rdatas
                .iter()
                .filter(|rd| rd.record_type() == qtype)
                .map(|rd| ApRecord::new(qname.clone(), ttl, rd.clone()))
                .collect();
            records_resp(request, recs)
        }
        RewriteTarget::Cname(t) => {
            let cname = ApRecord::new(qname.clone(), ttl, ApRData::Cname(t.clone()));
            records_resp(request, vec![cname])
        }
    }
}

/// Whether the value does anything.
pub trait GatePresence {
    fn gate_present(&self) -> bool;
}

impl GatePresence for Vec<NativeView> {
    fn gate_present(&self) -> bool {
        !self.is_empty()
    }
}

impl GatePresence for onetdns_policy::PolicyEngine {
    fn gate_present(&self) -> bool {
        !self.is_empty()
    }
}

/// Swappable, and answers whether it is empty without cloning: checking the contents per query
/// would cost a clone, so emptiness is a separate atomic.
pub struct GatedSwap<T> {
    swap: ArcSwap<T>,
    present: AtomicBool,
}

impl<T: GatePresence> GatedSwap<T> {
    pub fn from_pointee(value: T) -> Self {
        let present = value.gate_present();
        GatedSwap {
            swap: ArcSwap::from_pointee(value),
            present: AtomicBool::new(present),
        }
    }

    /// From a value already shared.
    pub fn new(value: Arc<T>) -> Self {
        let present = value.gate_present();
        GatedSwap {
            swap: ArcSwap::new(value),
            present: AtomicBool::new(present),
        }
    }

    pub fn load(&self) -> Arc<T> {
        self.swap.load()
    }

    pub fn present(&self) -> bool {
        self.present.load(Ordering::Acquire)
    }

    /// Updates the emptiness flag together.
    pub fn store(&self, value: Arc<T>) {
        let present = value.gate_present();
        if present {
            self.present.store(true, Ordering::Release);
            self.swap.store(value);
        } else {
            self.swap.store(value);
            self.present.store(false, Ordering::Release);
        }
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
/// For the lane that does not hold a thread while recursion waits.
struct ReactorLaneShared {
    inflight: usize,

    /// Finishes what the lane could not.
    chain: Arc<dyn Resolver>,
}

/// Fast-path resources that must belong to the same chain generation.
pub(crate) struct LaneRuntime {
    /// Lifetime policy; None when wire entries cannot be made.
    factory: Option<crate::wirecache::WireEntryFactory>,
    /// Shared by the wire path and the reactor lane.
    cache: crate::cache::CacheHandle,
    /// None for a forward-only generation.
    recursor: Option<Arc<Recursor>>,
}

impl LaneRuntime {
    /// Stores a sent response for the fast path to reuse, when it can be stored.
    ///
    /// `epoch` is the cache generation taken before the resolution that built this response
    /// started.
    pub(crate) fn store_wire_response(
        &self,
        epoch: crate::cache::CacheEpoch,
        key: &[u8],
        response_wire: &[u8],
        filter_tag: usize,
        answers_summary: String,
        now: std::time::Instant,
    ) {
        let Some(factory) = self.factory.as_ref() else {
            return;
        };
        let Some(candidate) = self.cache.wire_candidate(key, now) else {
            return;
        };
        let entry = if candidate.has_fixed_local_ttl() {
            factory.prepare_fixed(response_wire, filter_tag, answers_summary, now)
        } else {
            factory.prepare(
                response_wire,
                filter_tag,
                answers_summary,
                now,
                candidate.lifetime_secs(),
            )
        };
        let Some(entry) = entry else {
            return;
        };
        self.cache.promote_wire(epoch, key, &candidate, entry);
    }
}

/// Handles one query from start to finish.
pub struct NativeServer {
    pub filter: Arc<SharedFilter>,
    pub acl: Arc<dyn AccessControl>,
    pub rate_limiters: Vec<Arc<dyn RateLimiter>>,

    pub backend: Arc<dyn Resolver>,

    pub client_upstreams: Vec<ClientUpstream>,

    /// None disables it.
    reactor_lane: Option<ReactorLaneShared>,
    pub block_ttl: Arc<AtomicU32>,
    pub local_ttl: Arc<AtomicU32>,
    pub features: Arc<NativeFeatureSwap>,
    recorder: Option<Recorder>,
    /// Changed by both the schedule task and config swaps.
    mac_cache: Option<Arc<crate::mac::NeighborCache>>,
    safe_search: Arc<AtomicBool>,
    /// Round-robin position.
    inflight: AtomicUsize,
    rotor: AtomicUsize,

    pub policy: Arc<GatedSwap<onetdns_policy::PolicyEngine>>,

    /// None disables zone transfers.
    pub xfr_store: Option<Arc<ArcSwap<onetdns_authority::ZoneStore>>>,

    /// Transfer, dynamic update, and signing settings, swapped together.
    pub authority: Arc<ArcSwap<AuthoritySettings>>,

    /// Signatures already seen, so a captured request cannot be replayed.
    tsig_replay: std::sync::Mutex<LruMap<Vec<u8>, u64>>,

    /// Called when a zone changes.
    pub update_notify: Option<Arc<dyn Fn(&ApName, u32) + Send + Sync>>,

    /// Zones the primary announced.
    pub notify_kick: Arc<NotifyKick>,

    /// Recent changes per zone.
    pub journal: Arc<std::sync::Mutex<std::collections::HashMap<Vec<u8>, ZoneJournal>>>,

    /// Per-client answer views.
    pub views: Arc<GatedSwap<Vec<NativeView>>>,

    /// None disables it.
    authority_wire_path: Option<AuthorityWirePath>,
}

#[derive(Clone)]
/// A zone accepting dynamic updates, bound to the file it saves to. A zone taking updates with
/// nowhere to save them would lose the changes on reload, so that state cannot be built. Zones from
/// sources other than files need their own write path and do not go here.
pub struct UpdateTarget {
    pub origin: ApName,
    pub file: std::path::PathBuf,
}

#[derive(Clone, Default)]
/// Authority settings swapped as one set: when the zone list changes, transfer ranges, signing
/// keys, updatable zones, and save paths change together, and swapping them one by one would serve
/// requests from a mismatched mix.
pub struct AuthoritySettings {
    pub xfr_allow: Vec<IpNet>,
    pub tsig_keys: Vec<onetdns_dnssec::tsig::TsigKey>,
    pub xfr_tsig_required: bool,
    pub update_allow: Vec<IpNet>,
    pub update_policy: Vec<UpdateRule>,
    pub update_tsig_required: bool,
    pub update_targets: Vec<UpdateTarget>,
    /// Zone, primary, and expected TSIG key.
    pub notify_secondaries: Vec<(ApName, IpAddr, Option<ApName>)>,
    /// Catalog primaries and expected TSIG keys. Member zones found through a catalog come and go
    /// at run time, so NOTIFY from these primaries is accepted without knowing the zone name in
    /// advance, and the refresh task drops zones it does not know.
    pub notify_catalog_primaries: Vec<(IpAddr, Option<ApName>)>,
    pub zone_signers: Vec<(ApName, crate::zone_signing::ZoneSigningCtx)>,
}

#[derive(Clone, Default)]
/// Names answered differently for chosen clients.
pub struct NativeView {
    pub nets: Vec<IpNet>,
    pub ids: Vec<String>,

    pub local_a: Vec<(Vec<u8>, Ipv4Addr)>,
    pub local_aaaa: Vec<(Vec<u8>, Ipv6Addr)>,
}

impl NativeView {
    fn matches(&self, client: &ClientInfo) -> bool {
        if self.nets.iter().any(|n| n.contains(&client.source_ip)) {
            return true;
        }
        client
            .client_id
            .as_ref()
            .is_some_and(|id| self.ids.iter().any(|x| x == id))
    }
}

impl NativeServer {
    pub fn new(
        filter: Arc<SharedFilter>,
        acl: Arc<dyn AccessControl>,
        rate_limiters: Vec<Arc<dyn RateLimiter>>,
        backend: Arc<dyn Resolver>,
        block_ttl: u32,
    ) -> Self {
        NativeServer {
            filter,
            acl,
            rate_limiters,
            backend,
            client_upstreams: Vec::new(),
            reactor_lane: None,
            block_ttl: Arc::new(AtomicU32::new(block_ttl)),
            local_ttl: Arc::new(AtomicU32::new(300)),
            features: Arc::new(NativeFeatureSwap::from_pointee(NativeFeatures::default())),
            recorder: None,
            mac_cache: None,
            safe_search: Arc::new(AtomicBool::new(false)),
            inflight: AtomicUsize::new(0),
            rotor: AtomicUsize::new(0),
            policy: Arc::new(GatedSwap::from_pointee(
                onetdns_policy::PolicyEngine::default(),
            )),
            xfr_store: None,
            authority: Arc::new(ArcSwap::from_pointee(AuthoritySettings::default())),
            tsig_replay: std::sync::Mutex::new(LruMap::new(4096)),
            update_notify: None,
            notify_kick: Arc::new(NotifyKick::default()),
            journal: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            views: Arc::new(GatedSwap::from_pointee(Vec::new())),
            authority_wire_path: None,
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn with_reactor_lane(
        self,
        recursor: Arc<Recursor>,
        cache: crate::cache::CacheHandle,
        inflight: usize,
    ) -> Self {
        self.with_reactor_lane_runtime(Some(recursor), cache, inflight)
    }

    /// Attaches the slot even to a generation without a recursive resolver, so the lane can be
    /// enabled later.
    pub fn with_reactor_lane_runtime(
        mut self,
        recursor: Option<Arc<Recursor>>,
        cache: crate::cache::CacheHandle,
        inflight: usize,
    ) -> Self {
        let mut features = (*self.features.load()).clone();
        let factory = features
            .lane_runtime
            .as_ref()
            .and_then(|runtime| runtime.factory);
        features.lane_runtime = Some(Arc::new(LaneRuntime {
            factory,
            cache,
            recursor,
        }));
        self.features.store(Arc::new(features));
        self.reactor_lane = Some(ReactorLaneShared {
            inflight,
            chain: self.backend.clone(),
        });
        self
    }

    pub fn with_ttl_sources(
        mut self,
        block_ttl: Arc<AtomicU32>,
        local_ttl: Arc<AtomicU32>,
    ) -> Self {
        self.block_ttl = block_ttl;
        self.local_ttl = local_ttl;
        self
    }

    pub fn with_wire_fast_path(
        self,
        fast_path: Option<(
            crate::wirecache::WireEntryFactory,
            crate::cache::CacheHandle,
        )>,
    ) -> Self {
        let mut features = (*self.features.load()).clone();
        let previous = features.lane_runtime.clone();
        features.lane_runtime = match fast_path {
            Some((factory, cache)) => Some(Arc::new(LaneRuntime {
                factory: Some(factory),
                cache,
                recursor: previous.and_then(|runtime| runtime.recursor.clone()),
            })),
            None => previous.map(|runtime| {
                Arc::new(LaneRuntime {
                    factory: None,
                    cache: runtime.cache.clone(),
                    recursor: runtime.recursor.clone(),
                })
            }),
        };
        self.features.store(Arc::new(features));
        self
    }

    pub fn with_authority_wire_path(
        mut self,
        store: Option<Arc<ArcSwap<onetdns_authority::ZoneStore>>>,
        recursion_available: bool,
    ) -> Self {
        self.authority_wire_path = store.map(|store| AuthorityWirePath {
            store,
            recursion_available,
        });
        self
    }

    pub fn with_views(mut self, views: Vec<NativeView>) -> Self {
        self.views = Arc::new(GatedSwap::from_pointee(views));
        self
    }

    pub fn with_journal(
        mut self,
        journal: Arc<std::sync::Mutex<std::collections::HashMap<Vec<u8>, ZoneJournal>>>,
    ) -> Self {
        self.journal = journal;
        self
    }

    pub fn with_notify_kick(mut self, kick: Arc<NotifyKick>) -> Self {
        self.notify_kick = kick;
        self
    }

    #[cfg(test)]
    pub fn with_notify_secondaries(
        mut self,
        secondaries: Vec<(ApName, IpAddr, Option<ApName>)>,
        kick: Arc<NotifyKick>,
    ) -> Self {
        self.edit_authority(|a| a.notify_secondaries = secondaries);
        self.notify_kick = kick;
        self
    }

    pub fn with_features(mut self, features: NativeFeatures) -> Self {
        self.features = Arc::new(NativeFeatureSwap::from_pointee(features));
        self
    }

    pub fn with_recorder(mut self, recorder: Option<Recorder>) -> Self {
        self.recorder = recorder;
        self
    }

    pub fn with_mac_cache(mut self, mac_cache: Option<Arc<crate::mac::NeighborCache>>) -> Self {
        self.mac_cache = mac_cache;
        self
    }

    /// Shared by the schedule task and config swaps.
    pub fn with_safe_search(mut self, safe_search: Arc<AtomicBool>) -> Self {
        self.safe_search = safe_search;
        self
    }

    /// None when nobody is watching, even with a recorder: building the name and reading the clock
    /// costs every query, so nothing is built to be thrown away.
    pub fn events(&self) -> Option<&Recorder> {
        self.recorder.as_ref().filter(|r| r.collecting())
    }

    pub fn with_client_upstreams(mut self, client_upstreams: Vec<ClientUpstream>) -> Self {
        self.client_upstreams = client_upstreams;
        self
    }

    /// The management API's simulation and explanation read the same slot; holding a copy would
    /// answer with the old policy after a config change.
    pub fn with_policy(mut self, policy: Arc<GatedSwap<onetdns_policy::PolicyEngine>>) -> Self {
        self.policy = policy;
        self
    }

    fn edit_authority(&self, edit: impl FnOnce(&mut AuthoritySettings)) {
        let mut next = (*self.authority.load()).clone();
        edit(&mut next);
        self.authority.store(Arc::new(next));
    }

    pub fn replace_authority(&self, settings: AuthoritySettings) {
        self.authority.store(Arc::new(settings));
    }

    pub fn with_xfr(
        mut self,
        store: Arc<ArcSwap<onetdns_authority::ZoneStore>>,
        allow: Vec<IpNet>,
    ) -> Self {
        self.xfr_store = Some(store);
        self.edit_authority(|a| a.xfr_allow = allow);
        self
    }

    #[cfg(test)]
    /// When required, unsigned requests are rejected.
    pub fn with_tsig(self, keys: Vec<onetdns_dnssec::tsig::TsigKey>, required: bool) -> Self {
        self.edit_authority(|a| {
            a.tsig_keys = keys;
            a.xfr_tsig_required = required;
        });
        self
    }

    #[cfg(test)]
    pub fn with_ddns(
        self,
        allow: Vec<IpNet>,
        tsig_required: bool,
        targets: Vec<UpdateTarget>,
    ) -> Self {
        self.edit_authority(|a| {
            a.update_allow = allow;
            a.update_tsig_required = tsig_required;
            a.update_targets = targets;
        });
        self
    }

    pub fn with_update_notify(mut self, notify: Arc<dyn Fn(&ApName, u32) + Send + Sync>) -> Self {
        self.update_notify = Some(notify);
        self
    }

    fn resolve_for(&self, request: &Message, client: &ClientInfo) -> ResolveOutcome {
        if let Some(route) = self.client_upstreams.iter().find(|r| r.matches(client)) {
            return route.resolver.resolve_outcome(request);
        }
        self.backend.resolve_outcome(request)
    }

    fn resolve_message_for(&self, request: &Message, client: &ClientInfo) -> Option<Message> {
        match self.resolve_for(request, client) {
            ResolveOutcome::Response(response) => Some(response),
            ResolveOutcome::Failure(_) => None,
        }
    }

    /// Recorded in the query log.
    fn resolver_mode(&self, client: &ClientInfo) -> &'static str {
        if self.client_upstreams.iter().any(|r| r.matches(client)) {
            "client_route"
        } else {
            "backend"
        }
    }
}

#[cfg(test)]
mod tests;
