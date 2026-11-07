//! Control-plane REST API and dashboard server, a hand-written HTTP/1.1 server. Non-blocking
//! admission hands only complete requests to connection threads. Routes before authentication
//! stay minimal, and state-changing requests are serialized.

use std::borrow::Cow;
use std::collections::hash_map::RandomState;
use std::collections::{HashMap, VecDeque};
use std::hash::BuildHasher;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use onetdns_core::json;
use onetdns_core::tcp::DeadlineTcp;
use onetdns_core::{ArcSwap, HttpsOrigin, IpNet, MutexExt, SecretString};
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::metrics::{now_ms, MetricsSnapshot, QueryEvent, Stats};

const MAX_CONTROL_CONNECTIONS: usize = 128;

/// Streaming connections stay open long, so they get a smaller limit of their own.
const MAX_CONTROL_STREAM_CONNECTIONS: usize = 64;
/// The connection thread applies config itself, including blocklist compilation and zone
/// parsing, whose frames are much larger in unoptimized builds; running out of stack kills the
/// process. Stacks are committed as used, so reserving one per connection costs no memory.
const CONTROL_CONNECTION_STACK_BYTES: usize = 1024 * 1024;
/// For the whole request, not each read.
const CONTROL_READ_TIMEOUT_SECS: u64 = 15;
/// For the whole response, not each write.
const CONTROL_WRITE_TIMEOUT_SECS: u64 = 30;

/// Request shapes whose failures are counted individually.
const MAX_REQUEST_FAILURE_COUNTS: usize = 256;

/// How long shutdown waits for open connections.
const CONTROL_DRAIN_GRACE_SECS: u64 = 5;

/// One TCP socket shared by the read, write and shutdown paths without duplicating the OS handle.
#[derive(Clone)]
struct SharedTcp(Arc<TcpStream>);

impl SharedTcp {
    fn new(stream: TcpStream) -> Self {
        Self(Arc::new(stream))
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.peer_addr()
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.local_addr()
    }

    /// Applies to every path reading this socket.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.0.set_read_timeout(timeout)
    }

    /// Non-blocking only during admission.
    fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }

    fn shutdown(&self, how: std::net::Shutdown) -> std::io::Result<()> {
        self.0.shutdown(how)
    }
}

impl Read for SharedTcp {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut stream = &*self.0;
        stream.read(buf)
    }
}

impl Write for SharedTcp {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut stream = &*self.0;
        stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut stream = &*self.0;
        stream.flush()
    }
}

/// A connection with the request bytes admission already read put in front. Deadlines and
/// shutdown are enforced by the wrapping `DeadlineTcp`.
struct AdmittedTcp {
    stream: SharedTcp,
    /// Request bytes admission already read.
    prefix: Vec<u8>,
    prefix_offset: usize,
    /// Returns the global admission byte budget when the prefix is dropped.
    _admission_bytes: Option<AdmissionBytesGuard>,
}

impl AdmittedTcp {
    fn new(
        stream: SharedTcp,
        prefix: Vec<u8>,
        admission_bytes: Option<AdmissionBytesGuard>,
    ) -> Self {
        Self {
            stream,
            prefix,
            prefix_offset: 0,
            _admission_bytes: admission_bytes,
        }
    }
}

impl Read for AdmittedTcp {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.prefix_offset < self.prefix.len() {
            let available = &self.prefix[self.prefix_offset..];
            let copied = available.len().min(buf.len());
            buf[..copied].copy_from_slice(&available[..copied]);
            self.prefix_offset += copied;
            return Ok(copied);
        }
        self.stream.read(buf)
    }
}

impl onetdns_core::tcp::SocketTimeouts for AdmittedTcp {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.stream.0.set_write_timeout(timeout)
    }
}

/// Gives the connection slot back on drop.
struct ActiveConnectionGuard(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// This connection's share of the global memory budget for unauthenticated request bytes.
struct AdmissionBytesGuard {
    /// Bytes reserved by every pending or active connection.
    total: Arc<std::sync::atomic::AtomicUsize>,
    held: usize,
}

impl AdmissionBytesGuard {
    fn new(total: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        Self { total, held: 0 }
    }

    /// Reserves as much as fits under the global limit, atomically.
    fn reserve(&mut self, wanted: usize) -> usize {
        use std::sync::atomic::Ordering;
        let mut current = self.total.load(Ordering::Acquire);
        loop {
            let granted = wanted.min(MAX_CONTROL_ADMISSION_BYTES.saturating_sub(current));
            if granted == 0 {
                return 0;
            }
            match self.total.compare_exchange_weak(
                current,
                current + granted,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.held += granted;
                    return granted;
                }
                Err(observed) => current = observed,
            }
        }
    }

    /// Returns reserved bytes that were not read.
    fn release(&mut self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        debug_assert!(bytes <= self.held);
        self.held -= bytes;
        self.total
            .fetch_sub(bytes, std::sync::atomic::Ordering::AcqRel);
    }
}

impl Drop for AdmissionBytesGuard {
    fn drop(&mut self) {
        self.release(self.held);
    }
}

/// Takes a slot atomically; `None` when all are taken.
fn acquire_connection_slot(
    active: &Arc<std::sync::atomic::AtomicUsize>,
) -> Option<ActiveConnectionGuard> {
    use std::sync::atomic::Ordering;
    active
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count < MAX_CONTROL_CONNECTIONS).then_some(count + 1)
        })
        .ok()
        .map(|_| ActiveConnectionGuard(active.clone()))
}

static ACTIVE_STREAM_CONNECTIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Gives the streaming slot back on drop.
struct StreamSlotGuard;

impl Drop for StreamSlotGuard {
    fn drop(&mut self) {
        ACTIVE_STREAM_CONNECTIONS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// `None` when all are taken.
fn acquire_stream_slot() -> Option<StreamSlotGuard> {
    use std::sync::atomic::Ordering;
    if ACTIVE_STREAM_CONNECTIONS.fetch_add(1, Ordering::AcqRel) >= MAX_CONTROL_STREAM_CONNECTIONS {
        ACTIVE_STREAM_CONNECTIONS.fetch_sub(1, Ordering::AcqRel);
        return None;
    }
    Some(StreamSlotGuard)
}

#[cfg(test)]
mod stream_slot_tests {
    use super::*;

    #[test]
    fn stream_slots_are_bounded_and_released() {
        let mut held = Vec::new();
        while let Some(g) = acquire_stream_slot() {
            held.push(g);
            assert!(
                held.len() <= MAX_CONTROL_STREAM_CONNECTIONS,
                "Concurrency limit reached; cannot acquire a slot"
            );
        }
        assert!(!held.is_empty());
        held.pop();
        assert!(
            acquire_stream_slot().is_some(),
            "A slot can be acquired again after release"
        );
    }

    #[test]
    fn control_connection_slots_are_bounded_balanced_and_released() {
        assert_eq!(
            MAX_CONTROL_CONNECTIONS,
            MAX_CONTROL_STREAM_CONNECTIONS * 2,
            "Streaming at capacity still leaves 64 regular and Raft connections"
        );
        assert_eq!(CONTROL_CONNECTION_STACK_BYTES, 1024 * 1024);

        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut held = Vec::new();
        while let Some(guard) = acquire_connection_slot(&active) {
            held.push(guard);
        }
        assert_eq!(held.len(), MAX_CONTROL_CONNECTIONS);
        assert_eq!(
            active.load(std::sync::atomic::Ordering::Acquire),
            MAX_CONTROL_CONNECTIONS,
            "A rejected acquire does not increase the active connection count"
        );
        held.pop();
        assert!(acquire_connection_slot(&active).is_some());
    }

    #[test]
    fn shared_tcp_clone_keeps_one_socket_owner() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let mut shared = SharedTcp::new(client);
        let clone = shared.clone();

        assert!(Arc::ptr_eq(&shared.0, &clone.0));
        shared.write_all(b"x").unwrap();
        let mut byte = [0u8; 1];
        server.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"x");
        clone.shutdown(std::net::Shutdown::Both).unwrap();
    }
}

/// Pending ACME HTTP-01 challenge responses by token.
static ACME_HTTP01: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
/// Transport errors per stage, for sampling their logs.
static CONTROL_ERROR_COUNTS: OnceLock<Mutex<HashMap<&'static str, u64>>> = OnceLock::new();
/// Serializes state-changing requests.
static CONTROL_MUTATION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn control_mutation_lock() -> &'static Mutex<()> {
    CONTROL_MUTATION_LOCK.get_or_init(|| Mutex::new(()))
}

/// Some POSTs, such as validation and dry runs, change nothing; locking them would make
/// read-only requests wait on each other.
fn is_state_changing_request(method: &str, path: &str) -> bool {
    match method {
        "PUT" | "PATCH" | "DELETE" => true,
        "POST" => !matches!(
            path,
            "/v1/config/validate"
                | "/v1/config/diff"
                | "/v1/config/set/diff"
                | "/v1/explain"
                | "/v1/resolve"
                | "/v1/policies/simulate"
                | "/v1/tls/validate"
                | "/v1/tls/revocation-check"
                | "/v1/upstreams/test"
        ),
        _ => false,
    }
}

/// Requests not locked here also skip cluster consensus. Cluster proposals are exempt because
/// consensus orders them itself, and locking would make proposals block each other. Self-update
/// is exempt: it changes no config and only starts a job on this node, and the updater runs
/// those one at a time.
fn requires_control_mutation_lock(method: &str, path: &str) -> bool {
    is_state_changing_request(method, path)
        && path != "/v1/cluster/propose"
        && !path.starts_with("/v1/system/update/")
}

/// Repeated request failures, by a bounded number of fingerprints.
static REQUEST_FAILURE_COUNTS: OnceLock<Mutex<RequestFailureCounts>> = OnceLock::new();

struct RequestFailureCounts {
    /// Keyed by request shape; the raw request is not kept.
    counts: HashMap<u64, u64>,
    /// Per-process seed, so attackers cannot pick colliding fingerprints.
    fingerprint_state: RandomState,
    /// New shapes seen after the tracking limit.
    overflow: u64,
}

impl Default for RequestFailureCounts {
    fn default() -> Self {
        Self {
            counts: HashMap::new(),
            fingerprint_state: RandomState::new(),
            overflow: 0,
        }
    }
}

impl RequestFailureCounts {
    fn fingerprint(&self, method: &str, path: &str, status: u16) -> u64 {
        self.fingerprint_state.hash_one((method, path, status))
    }

    /// Returns the new count.
    fn increment(&mut self, method: &str, path: &str, status: u16) -> u64 {
        let fingerprint = self.fingerprint(method, path, status);
        if let Some(count) = self.counts.get_mut(&fingerprint) {
            *count = count.saturating_add(1);
            return *count;
        }

        if self.counts.len() < MAX_REQUEST_FAILURE_COUNTS {
            self.counts.insert(fingerprint, 1);
            return 1;
        }

        self.overflow = self.overflow.saturating_add(1);
        self.overflow
    }

    #[cfg(test)]
    /// Count for a shape already tracked.
    fn count(&self, method: &str, path: &str, status: u16) -> u64 {
        self.counts
            .get(&self.fingerprint(method, path, status))
            .copied()
            .unwrap_or(0)
    }
}

/// Which failure of this shape this is, from 1. Peer addresses and raw paths are not kept;
/// shapes beyond the tracking limit share one saturating counter.
fn repeated_failure_count(method: &str, path: &str, status: u16) -> u64 {
    REQUEST_FAILURE_COUNTS
        .get_or_init(|| Mutex::new(RequestFailureCounts::default()))
        .lock_recover()
        .increment(method, path, status)
}

fn should_log_repeated_failure(count: u64) -> bool {
    count == 1 || count.is_power_of_two()
}

/// Counts transport errors and logs only the 1st, 2nd, 4th, ... one.
fn record_control_error(
    stage: &'static str,
    peer: Option<SocketAddr>,
    detail: impl std::fmt::Display,
) {
    let count = {
        let mut counts = CONTROL_ERROR_COUNTS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock_recover();
        let count = counts.entry(stage).or_insert(0);
        *count = count.saturating_add(1);
        *count
    };
    if count == 1 || count.is_power_of_two() {
        let peer = peer
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        onetdns_core::warn!(event = "control.transport_error",
            transport = "control",
            stage = stage,
            peer = %peer,
            count = count,
            error = %detail,
            "Error on a dashboard connection"
        );
    }
}

#[cfg(test)]
fn control_error_count(stage: &str) -> u64 {
    CONTROL_ERROR_COUNTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock_recover()
        .get(stage)
        .copied()
        .unwrap_or(0)
}

#[cfg(test)]
fn request_failure_count(method: &str, path: &str, status: u16) -> u64 {
    REQUEST_FAILURE_COUNTS
        .get_or_init(|| Mutex::new(RequestFailureCounts::default()))
        .lock_recover()
        .count(method, path, status)
}

fn acme_http01() -> &'static Mutex<HashMap<String, String>> {
    ACME_HTTP01.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn set_acme_http01(token: &str, key_authorization: &str) {
    acme_http01()
        .lock_recover()
        .insert(token.to_string(), key_authorization.to_string());
}

pub fn clear_acme_http01(token: &str) {
    acme_http01().lock_recover().remove(token);
}

/// Status line, content type and body.
pub type ApiResponse = (&'static str, &'static str, String);

/// Runs a state-changing request through cluster consensus.
pub type ClusterWrite =
    dyn Fn(&str, &str, &str, &mut dyn FnMut() -> ApiResponse) -> ApiResponse + Send + Sync;

/// Callbacks into the data path, so the control plane and the data path do not depend on each
/// other's types.
pub struct Controls {
    /// Rereads config and lists.
    pub reload: Box<dyn Fn() -> Result<ListCounts, String> + Send + Sync>,
    pub block_add: Box<dyn Fn(&str) -> Result<ListCounts, String> + Send + Sync>,
    pub allow_add: Box<dyn Fn(&str) -> Result<ListCounts, String> + Send + Sync>,

    /// Turns blocking of a service on or off.
    pub service_set: Box<dyn Fn(&str, bool) -> Result<ListCounts, String> + Send + Sync>,

    pub safesearch_set: Box<dyn Fn(bool) -> Result<(), String> + Send + Sync>,

    /// Current config and lists.
    pub export: Box<dyn Fn() -> String + Send + Sync>,

    pub import: Box<dyn Fn(&str) -> Result<ListCounts, String> + Send + Sync>,

    /// Checks a config without applying it.
    pub config_validate: Box<dyn Fn(&str) -> Result<(), String> + Send + Sync>,

    /// Difference between the given config and the current one.
    pub config_diff: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Applies a config by swapping it in or restarting.
    pub config_apply: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Changes a few config keys.
    pub config_set: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// What `config_set` would change and how it would be applied, without applying it.
    pub config_set_diff: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Config description the dashboard renders its forms from.
    pub config_schema: Box<dyn Fn() -> String + Send + Sync>,

    /// Checks that the upstream answers.
    pub upstream_test: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    pub cache_flush: Box<dyn Fn() -> String + Send + Sync>,

    pub rewrites_list: Box<dyn Fn() -> String + Send + Sync>,

    pub rewrite_add: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    pub rewrite_delete: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Services that can be blocked.
    pub services_catalog: Box<dyn Fn() -> String + Send + Sync>,

    pub access_list: Box<dyn Fn() -> String + Send + Sync>,

    pub tls_status: Box<dyn Fn() -> String + Send + Sync>,

    /// Checks that the current certificate can actually serve.
    pub tls_validate: Box<dyn Fn() -> Result<String, String> + Send + Sync>,

    /// Replaces the certificate and key.
    pub tls_configure: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    pub tls_revocation_check: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Starts certificate issuance.
    pub acme_issue: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Control tokens, without the token values.
    pub tokens_list: Box<dyn Fn() -> String + Send + Sync>,

    pub token_add: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    pub token_delete: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Restores the previous config.
    pub config_rollback: Box<dyn Fn() -> Result<String, String> + Send + Sync>,

    /// How a query would be decided, without resolving it.
    pub policy_simulate: Box<dyn Fn(&str) -> String + Send + Sync>,

    /// Authoritative zones.
    pub zones_list: Box<dyn Fn() -> String + Send + Sync>,

    /// Records of a zone.
    pub zone_get: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Replaces a whole zone.
    pub zone_put: Box<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>,

    pub zone_delete: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    pub zone_record_add: Box<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>,

    pub zone_record_delete: Box<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>,

    /// Whether a zone is signed, its keys, and the DS to give the parent.
    pub zone_dnssec: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Config as written in the file.
    pub config_desired: Box<dyn Fn() -> String + Send + Sync>,

    /// Config in effect.
    pub config_effective: Box<dyn Fn() -> String + Send + Sync>,

    /// Whether the file and the config in effect differ.
    pub config_status: Box<dyn Fn() -> String + Send + Sync>,

    /// Rereads the config file.
    pub config_reload: Box<dyn Fn() -> Result<String, String> + Send + Sync>,

    /// Metrics per policy plugin.
    pub plugins_metrics: Box<dyn Fn() -> String + Send + Sync>,

    /// Blocking summary.
    pub filter_report: Box<dyn Fn() -> String + Send + Sync>,

    /// Most-matched blocking rules.
    pub filter_top_rules: Box<dyn Fn() -> String + Send + Sync>,

    /// Blocking per list source.
    pub filter_sources: Box<dyn Fn() -> String + Send + Sync>,

    /// Subscribed blocklists.
    pub subscriptions_list: Box<dyn Fn() -> String + Send + Sync>,

    pub subscription_add: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    pub subscription_remove: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Changes a subscription's settings.
    pub subscription_update: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Downloads a subscribed list now.
    pub subscription_refresh: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Rules the user added.
    pub filter_rules_list: Box<dyn Fn() -> String + Send + Sync>,

    /// Adds or removes a user rule.
    pub filter_rule_mutate: Box<dyn Fn(&str, bool) -> Result<String, String> + Send + Sync>,

    pub clients_list: Box<dyn Fn() -> String + Send + Sync>,

    /// Upstream servers and their scores.
    pub upstreams_list: Box<dyn Fn() -> String + Send + Sync>,

    /// Long-running jobs.
    pub jobs_list: Box<dyn Fn() -> String + Send + Sync>,

    /// Progress of a job.
    pub job_get: Box<dyn Fn(u64) -> Result<String, String> + Send + Sync>,

    /// Starts a list refresh job.
    pub job_refresh: Box<dyn Fn() -> String + Send + Sync>,

    /// Active DHCP leases.
    pub dhcp_leases: Box<dyn Fn() -> String + Send + Sync>,

    /// Accepts a lease from another server.
    pub dhcp_lease_put: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// DHCP static assignments.
    pub dhcp_static_list: Box<dyn Fn() -> String + Send + Sync>,

    pub dhcp_static_add: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    pub dhcp_static_remove: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Adds a client group.
    pub client_add: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Removes a client group.
    pub client_remove: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Changes a client group.
    pub client_update: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Changes the dashboard sign-in password.
    pub password_change: Box<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>,

    /// Writes the first admin account to the config file when there is none.
    pub user_create: Box<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>,

    pub upstream_add: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    pub upstream_remove: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Explains why a query was decided as it was.
    pub explain: Box<dyn Fn(&str) -> String + Send + Sync>,

    pub cluster_status: Box<dyn Fn() -> String + Send + Sync>,

    /// Proposes a config change to the cluster.
    pub cluster_propose: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Runs a state-changing request through Raft. Compares the config before and after `dispatch`,
    /// which is called once, and proposes the change when cluster-shared config changed; an
    /// uncommitted change is rolled back and the request fails. Without Raft it just calls
    /// `dispatch`.
    pub cluster_write: Box<ClusterWrite>,

    /// Listeners currently open.
    pub listeners_status: Box<dyn Fn() -> String + Send + Sync>,

    /// System network adapters.
    pub net_adapters: Box<dyn Fn() -> Result<String, String> + Send + Sync>,

    /// Changes firewall rules.
    pub firewall_set: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Points the system DNS settings at this server.
    pub dns_client_set: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Restores the system DNS settings.
    pub dns_client_restore: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Sends a real query for one name to this server's listen address, so the answer passes
    /// access control, filters and cache. Diagnosis only explains the decision; this shows what the
    /// name actually resolves to.
    pub resolve_probe: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Boot service registration, and whether this OS supports it.
    pub boot_service_status: Box<dyn Fn() -> String + Send + Sync>,

    /// Registers or removes the boot service.
    pub boot_service_set: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Self-update state.
    pub update_status: Box<dyn Fn() -> String + Send + Sync>,

    /// Starts a job that checks for a new release; an error means it cannot start in the current
    /// state.
    pub update_check: Box<dyn Fn() -> Result<String, String> + Send + Sync>,

    /// Starts a job installing the version the last check found, refusing a `version` that differs
    /// from that result. An error means it cannot start in the current state.
    pub update_apply: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /// Starts a job rolling back a committed update; an error means it cannot start in the current
    /// state.
    pub update_rollback: Box<dyn Fn() -> Result<String, String> + Send + Sync>,

    /// Metrics the data path exports itself.
    pub metrics_extra: Box<dyn Fn() -> String + Send + Sync>,
}

impl Controls {
    /// Does nothing; for tests and running the dashboard alone.
    pub fn noop() -> Self {
        let counts = || Ok(ListCounts { block: 0, allow: 0 });
        Self {
            reload: Box::new(counts),
            block_add: Box::new(move |_| counts()),
            allow_add: Box::new(move |_| counts()),
            service_set: Box::new(move |_, _| counts()),
            safesearch_set: Box::new(|_| Ok(())),
            export: Box::new(|| "{\"version\":1}".to_string()),
            import: Box::new(move |_| counts()),
            config_validate: Box::new(|_| Ok(())),
            config_diff: Box::new(|_| {
                Ok("{\"added\":[],\"removed\":[],\"changed\":[]}".to_string())
            }),
            config_apply: Box::new(|_| Err("No config file path".to_string())),
            config_set: Box::new(|_| Err("No config file path".to_string())),
            config_set_diff: Box::new(|_| {
                Ok("{\"added\":[],\"removed\":[],\"changed\":[]}".to_string())
            }),
            config_schema: Box::new(|| "{\"keys\":[]}".to_string()),
            upstream_test: Box::new(|_| Err("The requested feature is not available".to_string())),
            cache_flush: Box::new(|| "{\"flushed\":0}".to_string()),
            rewrites_list: Box::new(|| "{\"rewrites\":[]}".to_string()),
            rewrite_add: Box::new(|_| Err("No config file path".to_string())),
            rewrite_delete: Box::new(|_| Err("No config file path".to_string())),
            services_catalog: Box::new(|| "{\"services\":[]}".to_string()),
            access_list: Box::new(|| {
                "{\"allowed\":[],\"blocked\":[],\"dropped\":[],\"unlisted\":\"allow\",\"refused_domains\":[]}"
                    .to_string()
            }),
            tls_status: Box::new(|| "{\"configured\":false}".to_string()),
            tls_validate: Box::new(|| Err("No TLS certificate is configured".to_string())),
            tls_configure: Box::new(|_| Err("No config file path".to_string())),
            tls_revocation_check: Box::new(|_| Err("Certificate chain not found".to_string())),
            acme_issue: Box::new(
                |_| Err("ACME certificate issuance is not configured".to_string()),
            ),
            tokens_list: Box::new(|| "{\"tokens\":[]}".to_string()),
            token_add: Box::new(|_| Err("No config file path".to_string())),
            token_delete: Box::new(|_| Err("No config file path".to_string())),
            config_rollback: Box::new(|| Err("No previous config to roll back to".to_string())),
            policy_simulate: Box::new(|_| "{\"action\":\"continue\"}".to_string()),
            zones_list: Box::new(|| "[]".to_string()),
            zone_get: Box::new(|_| Err("Authoritative DNS is not available".to_string())),
            zone_put: Box::new(|_, _| Err("Authoritative DNS is not available".to_string())),
            zone_delete: Box::new(|_| Err("Authoritative DNS is not available".to_string())),
            zone_record_add: Box::new(|_, _| Err("Authoritative DNS is not available".to_string())),
            zone_record_delete: Box::new(|_, _| {
                Err("Authoritative DNS is not available".to_string())
            }),
            zone_dnssec: Box::new(|_| Err("Authoritative DNS is not available".to_string())),
            config_desired: Box::new(|| "{}".to_string()),
            config_effective: Box::new(|| "{}".to_string()),
            config_status: Box::new(|| "{\"in_sync\":true,\"changed_keys\":[]}".to_string()),
            config_reload: Box::new(|| Ok("{\"accepted\":true}".to_string())),
            plugins_metrics: Box::new(|| "[]".to_string()),
            filter_report: Box::new(|| {
                "{\"rules_total\":0,\"rules_applied\":0,\"rules_skipped\":0}".to_string()
            }),
            filter_top_rules: Box::new(|| "{\"enabled\":false,\"top\":[]}".to_string()),
            filter_sources: Box::new(|| "{\"hits_enabled\":false,\"sources\":[]}".to_string()),
            subscriptions_list: Box::new(|| {
                "{\"urls\":[],\"count\":0,\"block_domains\":0}".to_string()
            }),
            subscription_add: Box::new(|_| {
                Err("Blocklist subscriptions are not available".to_string())
            }),
            subscription_remove: Box::new(|_| {
                Err("Blocklist subscriptions are not available".to_string())
            }),
            subscription_update: Box::new(|_| {
                Err("Blocklist subscriptions are not available".to_string())
            }),
            subscription_refresh: Box::new(|_| {
                Err("Blocklist subscriptions are not available".to_string())
            }),
            filter_rules_list: Box::new(|| {
                "{\"block\":[],\"allow\":[],\"refused_domains\":[]}".to_string()
            }),
            filter_rule_mutate: Box::new(|_, _| Err("Filtering is not available".to_string())),
            clients_list: Box::new(|| "[]".to_string()),
            upstreams_list: Box::new(|| "[]".to_string()),
            jobs_list: Box::new(|| "[]".to_string()),
            job_get: Box::new(|_| Err("Job not found".to_string())),
            job_refresh: Box::new(|| "{\"id\":0,\"status\":\"running\"}".to_string()),
            dhcp_leases: Box::new(|| "{\"v4\":[],\"v6\":[]}".to_string()),
            dhcp_lease_put: Box::new(|_| Err("DHCP is not configured".to_string())),
            dhcp_static_list: Box::new(|| "{\"available\":false,\"reservations\":[]}".to_string()),
            dhcp_static_add: Box::new(|_| Err("DHCP is not configured".to_string())),
            dhcp_static_remove: Box::new(|_| Err("DHCP is not configured".to_string())),
            client_add: Box::new(|_| Err("No config file path".to_string())),
            client_remove: Box::new(|_| Err("No config file path".to_string())),
            client_update: Box::new(|_| Err("No config file path".to_string())),
            password_change: Box::new(|_, _| Err("No config file path".to_string())),
            user_create: Box::new(|_, _| Err("No config file path".to_string())),
            upstream_add: Box::new(|_| Err("No config file path".to_string())),
            upstream_remove: Box::new(|_| Err("No config file path".to_string())),
            explain: Box::new(|_| "{\"decision\":\"continue\"}".to_string()),
            cluster_status: Box::new(|| {
                "{\"self\":{\"id\":null,\"role\":\"standalone\",\"backend\":\"unknown\",\"listeners\":0,\"leader\":null,\"term\":null,\"commit_index\":null,\"last_applied\":null,\"last_index\":null,\"snapshot_index\":null,\"retained_log_entries\":null,\"fatal\":null,\"healthy\":true,\"version\":null},\"peers\":[]}".to_string()
            }),
            cluster_propose: Box::new(|_| {
                Err("Raft high availability is not configured".to_string())
            }),
            cluster_write: Box::new(|_, _, _, dispatch| dispatch()),
            listeners_status: Box::new(|| "[]".to_string()),
            net_adapters: Box::new(|| {
                Err("Listing network adapters is not supported on this OS".to_string())
            }),
            firewall_set: Box::new(|_| {
                Err("Changing firewall settings is not supported on this OS".to_string())
            }),
            dns_client_set: Box::new(|_| {
                Err("Changing the system DNS server is not supported on this OS".to_string())
            }),
            dns_client_restore: Box::new(|_| {
                Err("Restoring system DNS settings is not supported on this OS".to_string())
            }),
            resolve_probe: Box::new(|_| Err("No DNS listen address".to_string())),
            boot_service_status: Box::new(|| {
                "{\"supported\":false,\"installed\":false,\"running\":false}".to_string()
            }),
            boot_service_set: Box::new(|_| {
                Err("Installing a boot service is not supported on this OS".to_string())
            }),
            update_status: Box::new(|| {
                "{\"participating\":false,\"reason\":\"Updates are not available\"}".to_string()
            }),
            update_check: Box::new(|| Err("Updates are not available".to_string())),
            update_apply: Box::new(|_| Err("Updates are not available".to_string())),
            update_rollback: Box::new(|| Err("Updates are not available".to_string())),
            metrics_extra: Box::new(String::new),
        }
    }
}

#[derive(Clone, Copy)]
/// Rule counts returned after a list change.
pub struct ListCounts {
    pub block: usize,
    pub allow: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Admin,
    ReadOnly,
}

impl Role {
    /// Name used in the audit log.
    fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::ReadOnly => "readonly",
        }
    }

    /// Read-only callers may send GET, diagnostic POSTs that change nothing, and their own password
    /// change. Blocking diagnostics would make operators reach for an admin token to investigate,
    /// which is worse. HEAD is not routed, so it is not allowed here either.
    fn allows(self, method: &str, path: &str) -> bool {
        self == Role::Admin
            || method == "GET"
            || (method == "POST"
                && matches!(
                    path,
                    "/v1/password" | "/v1/explain" | "/v1/resolve" | "/v1/policies/simulate"
                ))
    }
}

#[derive(Clone)]
/// A dashboard user. Only the password hash is kept.
pub struct UserCred {
    pub name: String,
    pub hash: SecretString,
    pub role: Role,
}

#[derive(Clone)]
struct Session {
    role: Role,
    name: String,
    /// Credential used to sign in; a password change ends the sessions made with the old one.
    credential_id: String,
    idle_expires_ms: u64,
    absolute_expires_ms: u64,
}

#[derive(Clone, Default)]
/// Survives config generations, so applying config does not sign anyone out.
pub struct SessionStore(Arc<Mutex<std::collections::HashMap<[u8; 32], Session>>>);

/// Copy of the store for rolling back a failed config apply.
pub struct SessionCheckpoint(std::collections::HashMap<[u8; 32], Session>);

impl SessionStore {
    pub fn checkpoint(&self) -> SessionCheckpoint {
        SessionCheckpoint(self.0.lock_recover().clone())
    }

    pub fn restore(&self, checkpoint: SessionCheckpoint) {
        *self.0.lock_recover() = checkpoint.0;
    }
}

const SESSION_IDLE_TTL_MS: u64 = 30 * 60 * 1000;
const SESSION_ABSOLUTE_TTL_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_SESSIONS: usize = 1024;
const MAX_USER_SESSIONS: usize = 8;
/// Window in which sign-in failures are counted.
const LOGIN_WINDOW_MS: u64 = 5 * 60 * 1000;
/// How long sign-in stays blocked once failures reach the limit.
const LOGIN_BLOCK_MS: u64 = 15 * 60 * 1000;
/// Failures allowed per source and user.
const MAX_LOGIN_FAILURES: u32 = 8;

/// Failures allowed per source, across user names.
const MAX_SOURCE_LOGIN_FAILURES: u32 = 40;

/// Sign-in failures through one reverse proxy accepted without pacing. Behind a proxy the source
/// comes from X-Forwarded-For, which other programs on the proxy host can forge, so failures are
/// also limited per proxy. Blocking would let one attacker lock out every admin behind the proxy,
/// so the proxy is only slowed down. Larger than the per-source limit, so one source using up its
/// limit does not slow the others.
const PROXY_LOGIN_FAILURE_BURST: u64 = 2 * MAX_SOURCE_LOGIN_FAILURES as u64;

/// Pace of further failures through a proxy once the burst is used up.
const PROXY_LOGIN_FAILURE_INTERVAL_MS: u64 = 1000;
/// Entries kept per sign-in failure table.
const MAX_LOGIN_ATTEMPT_KEYS: usize = 4096;
const MAX_REQUEST_LINE: usize = 8 * 1024;
const MAX_HEADER_LINE: usize = 16 * 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_HEADERS: usize = 100;
const MAX_REQUEST_BODY: usize = 1024 * 1024;
/// Bytes admission keeps while looking for the end of the headers.
const CONTROL_ADMISSION_HEADER_BYTES: usize = MAX_REQUEST_LINE + MAX_HEADER_BYTES + 4;
const CONTROL_ADMISSION_READ_BYTES: usize = 16 * 1024;
/// Interval for rechecking pending connections.
const CONTROL_ADMISSION_POLL_MS: u64 = 10;
/// Longest recheck interval for a pending connection that makes no progress.
const CONTROL_ADMISSION_MAX_BACKOFF_MS: u64 = 250;
/// Unauthenticated request bytes held across the whole process.
const MAX_CONTROL_ADMISSION_BYTES: usize = 8 * 1024 * 1024;

struct LoginAttempt {
    window_start_ms: u64,
    failures: u32,
    /// No attempt is accepted before this.
    blocked_until_ms: u64,
}

/// Keeps a wrong credential apart from an overloaded KDF; merging them would tell a valid user
/// their password is wrong because of someone else's load.
enum LoginResult {
    /// Session token, role and user name.
    Success(String, Role, String),
    Invalid,
    /// Too many password checks in progress.
    Busy,
}

#[derive(Default)]
/// Bearer tokens from config and sessions from sign-in, mapped onto the same roles.
pub struct Auth {
    /// Keyed digests of admin tokens; the tokens themselves are not kept.
    admin: Mutex<Vec<[u8; 32]>>,
    /// Keyed digests of read-only tokens.
    readonly: Mutex<Vec<[u8; 32]>>,
    users: Mutex<Vec<UserCred>>,
    sessions: SessionStore,
    /// Sign-in failures per source, and per source and user.
    login_attempts: Mutex<std::collections::HashMap<String, LoginAttempt>>,

    /// Per reverse proxy: the time, in ms, from which failures are accepted without pacing again.
    proxy_login_pace: Mutex<std::collections::HashMap<String, u64>>,

    /// One-time code required to create the first admin account; cleared once it exists.
    setup_code: Mutex<Option<SetupCode>>,
}

struct SetupCode {
    /// Keyed digest; the code itself is not kept.
    digest: [u8; 32],
    /// File the code was written to, shown on the setup screen.
    file: String,
}

impl Auth {
    pub fn single_admin(token: SecretString) -> Self {
        let admin = if token.is_empty() {
            vec![]
        } else {
            vec![credential_digest("token", &[token.as_str()])]
        };
        Auth {
            admin: Mutex::new(admin),
            ..Default::default()
        }
    }

    pub fn new(admin: Vec<SecretString>, readonly: Vec<SecretString>) -> Self {
        let f = |v: Vec<SecretString>| {
            v.into_iter()
                .filter(|token| !token.is_empty())
                .map(|token| credential_digest("token", &[token.as_str()]))
                .collect()
        };
        Auth {
            admin: Mutex::new(f(admin)),
            readonly: Mutex::new(f(readonly)),
            ..Default::default()
        }
    }

    pub fn with_users(mut self, users: Vec<UserCred>) -> Self {
        self.users = Mutex::new(users);
        self
    }

    /// Sessions opened with a removed token end at once; otherwise they would keep the access.
    pub fn replace_tokens(&self, admin: Vec<SecretString>, readonly: Vec<SecretString>) {
        let digest = |tokens: Vec<SecretString>| {
            tokens
                .into_iter()
                .filter(|token| !token.is_empty())
                .map(|token| credential_digest("token", &[token.as_str()]))
                .collect()
        };
        *self.admin.lock_recover() = digest(admin);
        *self.readonly.lock_recover() = digest(readonly);
        self.reconcile_sessions();
    }

    /// Syncs accounts with the config file. Accounts do not affect DNS, so changing them needs no
    /// DNS restart, and a file edited outside the server takes effect here without one. Sessions of
    /// removed accounts are dropped by `reconcile_sessions`.
    pub fn replace_users(&self, users: Vec<UserCred>) {
        *self.users.lock_recover() = users;
        self.reconcile_sessions();
    }

    /// Keeps sign-ins across a config apply.
    pub fn with_sessions(mut self, sessions: SessionStore) -> Self {
        self.sessions = sessions;
        self.reconcile_sessions();
        self
    }

    /// Drops sessions of users whose credential was removed or changed, which would otherwise keep
    /// access.
    fn reconcile_sessions(&self) {
        let now = now_ms();
        let users = self.users.lock_recover().clone();
        let mut valid = std::collections::HashMap::<String, Role>::new();
        for digest in self.admin.lock_recover().iter() {
            valid.insert(
                credential_fingerprint_from_digest("token", digest),
                Role::Admin,
            );
        }
        for digest in self.readonly.lock_recover().iter() {
            valid.insert(
                credential_fingerprint_from_digest("token", digest),
                Role::ReadOnly,
            );
        }
        for user in &users {
            valid.insert(user_credential_id(user), user.role);
        }
        self.sessions.0.lock_recover().retain(|_, session| {
            session.idle_expires_ms > now
                && session.absolute_expires_ms > now
                && valid.get(&session.credential_id) == Some(&session.role)
        });
    }

    pub fn has_users(&self) -> bool {
        !self.users.lock_recover().is_empty()
    }

    /// Being able to connect to loopback does not mean being allowed to edit the config file; on a
    /// shared machine other users' programs reach loopback too. So the first account needs a code
    /// that only someone who can read the file next to the config knows.
    pub fn set_setup_code(&self, code: &str, file: String) {
        *self.setup_code.lock_recover() = Some(SetupCode {
            digest: credential_digest("setup", &[code]),
            file,
        });
    }

    /// Called once the account exists or there is nowhere to put the code.
    pub fn clear_setup_code(&self) {
        *self.setup_code.lock_recover() = None;
    }

    /// Constant-time; always false without a code.
    fn setup_code_matches(&self, offered: &str) -> bool {
        let digest = credential_digest("setup", &[offered]);
        self.setup_code
            .lock_recover()
            .as_ref()
            .is_some_and(|code| ct_eq(&digest, &code.digest))
    }

    fn setup_code_file(&self) -> Option<String> {
        self.setup_code
            .lock_recover()
            .as_ref()
            .map(|code| code.file.clone())
    }

    /// Constant-time comparison.
    fn role_for(&self, token: &str) -> Option<Role> {
        if token.is_empty() {
            return None;
        }
        let digest = credential_digest("token", &[token]);
        if self
            .admin
            .lock_recover()
            .iter()
            .any(|value| ct_eq(&digest, value))
        {
            return Some(Role::Admin);
        }
        if self
            .readonly
            .lock_recover()
            .iter()
            .any(|value| ct_eq(&digest, value))
        {
            return Some(Role::ReadOnly);
        }
        None
    }

    /// A bearer token, when sent, decides alone; a wrong one is not rescued by a valid session.
    /// Falling back to the session would skip the CSRF check, which treats the request as bearer,
    /// while the authority came from the cookie.
    fn resolve(&self, bearer: &str, session: &str) -> Option<Role> {
        if bearer.is_empty() {
            self.role_for_session(session)
        } else {
            self.role_for(bearer)
        }
    }

    /// `None` once expired.
    fn role_for_session(&self, token: &str) -> Option<Role> {
        if token.is_empty() {
            return None;
        }
        let now = now_ms();
        let mut map = self.sessions.0.lock_recover();

        map.retain(|_, s| s.idle_expires_ms > now && s.absolute_expires_ms > now);
        let digest = credential_digest("session", &[token]);
        let s = map.get_mut(&digest)?;
        s.idle_expires_ms = now
            .saturating_add(SESSION_IDLE_TTL_MS)
            .min(s.absolute_expires_ms);
        Some(s.role)
    }

    /// Sessions are capped per user and in total; the oldest go first.
    fn issue_session(&self, role: Role, name: String, credential_id: String) -> String {
        let token = crate::password::new_session_token();
        let token_digest = credential_digest("session", &[&token]);
        let now = now_ms();
        let mut sessions = self.sessions.0.lock_recover();
        sessions.retain(|_, session| {
            session.idle_expires_ms > now && session.absolute_expires_ms > now
        });
        let mut own: Vec<([u8; 32], u64)> = sessions
            .iter()
            .filter(|(_, session)| session.name == name)
            .map(|(key, session)| (*key, session.absolute_expires_ms))
            .collect();
        own.sort_by_key(|(_, expires)| *expires);
        while own.len() >= MAX_USER_SESSIONS {
            if let Some((key, _)) = own.first().copied() {
                sessions.remove(&key);
                own.remove(0);
            } else {
                break;
            }
        }
        while sessions.len() >= MAX_SESSIONS {
            let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, session)| session.absolute_expires_ms)
                .map(|(key, _)| *key)
            else {
                break;
            };
            sessions.remove(&oldest);
        }
        sessions.insert(
            token_digest,
            Session {
                role,
                name,
                credential_id,
                idle_expires_ms: now.saturating_add(SESSION_IDLE_TTL_MS),
                absolute_expires_ms: now.saturating_add(SESSION_ABSOLUTE_TTL_MS),
            },
        );
        token
    }

    /// Runs one hash verification even for an unknown user, so timing does not reveal which names
    /// exist.
    fn login(&self, name: &str, password: &str) -> LoginResult {
        let user = {
            let users = self.users.lock_recover();
            users.iter().find(|u| u.name == name).cloned()
        };
        let verified = match &user {
            Some(u) => crate::password::verify_password_result(password, &u.hash),
            None => crate::password::verify_password_result(
                password,
                "pbkdf2-sha256$600000$00000000000000000000000000000000$\
                     0000000000000000000000000000000000000000000000000000000000000000",
            ),
        };
        match verified {
            crate::password::VerifyResult::Busy => return LoginResult::Busy,
            crate::password::VerifyResult::Mismatch => return LoginResult::Invalid,
            crate::password::VerifyResult::Match => {}
        }
        let Some(user) = user else {
            return LoginResult::Invalid;
        };
        let credential_id = user_credential_id(&user);
        let token = self.issue_session(user.role, user.name.clone(), credential_id);
        LoginResult::Success(token, user.role, user.name)
    }

    fn login_source_bucket(source: &str) -> String {
        format!("src\u{1f}{source}")
    }

    fn login_user_bucket(source: &str, user: &str) -> String {
        format!("user\u{1f}{source}\u{1f}{user}")
    }

    /// Seconds until this source and user may try again, or `None` if they may now. `proxy` is the
    /// reverse proxy the request came through.
    fn login_retry_after(&self, source: &str, proxy: Option<&str>, user: &str) -> Option<u64> {
        let now = now_ms();
        let mut attempts = self.login_attempts.lock_recover();
        attempts.retain(|_, attempt| {
            attempt.blocked_until_ms > now
                || now.saturating_sub(attempt.window_start_ms) <= LOGIN_WINDOW_MS
        });
        let blocked_until = [
            Self::login_source_bucket(source),
            Self::login_user_bucket(source, user),
        ]
        .iter()
        .filter_map(|key| attempts.get(key))
        .map(|attempt| attempt.blocked_until_ms)
        .max()
        .unwrap_or(0);
        drop(attempts);
        let paced_until = proxy.map_or(0, |proxy| {
            let next = self
                .proxy_login_pace
                .lock_recover()
                .get(proxy)
                .copied()
                .unwrap_or(0);
            next.saturating_sub((PROXY_LOGIN_FAILURE_BURST - 1) * PROXY_LOGIN_FAILURE_INTERVAL_MS)
        });
        let until = blocked_until.max(paced_until);
        (until > now).then(|| (until - now).div_ceil(1000))
    }

    #[cfg(test)]
    fn login_allowed(&self, source: &str, proxy: Option<&str>, user: &str) -> bool {
        self.login_retry_after(source, proxy, user).is_none()
    }

    /// Success clears only that user's failures. Source and proxy records stay; clearing them would
    /// let each sign-in to one's own account refill the guesses against other accounts.
    fn record_login_result(&self, source: &str, proxy: Option<&str>, user: &str, success: bool) {
        let mut attempts = self.login_attempts.lock_recover();
        if success {
            attempts.remove(&Self::login_user_bucket(source, user));
            return;
        }
        let now = now_ms();
        for (key, limit) in [
            (Self::login_user_bucket(source, user), MAX_LOGIN_FAILURES),
            (Self::login_source_bucket(source), MAX_SOURCE_LOGIN_FAILURES),
        ] {
            Self::record_login_failure(&mut attempts, key, limit, now);
        }
        drop(attempts);
        if let Some(proxy) = proxy {
            Self::pace_proxy_failure(&mut self.proxy_login_pace.lock_recover(), proxy, now);
        }
    }

    /// Pushes the proxy's next allowed time back one interval. Expired entries act like missing
    /// ones and are dropped. A wide trusted proxy range such as 127.0.0.0/8 lets a local program
    /// create entries endlessly, so the table is capped and the entry that frees up first is
    /// evicted.
    fn pace_proxy_failure(
        pace: &mut std::collections::HashMap<String, u64>,
        proxy: &str,
        now: u64,
    ) {
        pace.retain(|_, next| *next > now);
        if !pace.contains_key(proxy) && pace.len() >= MAX_LOGIN_ATTEMPT_KEYS {
            if let Some(soonest) = pace
                .iter()
                .min_by_key(|(_, next)| **next)
                .map(|(key, _)| key.clone())
            {
                pace.remove(&soonest);
            }
        }
        let next = pace.entry(proxy.to_string()).or_insert(0);
        *next = (*next).max(now) + PROXY_LOGIN_FAILURE_INTERVAL_MS;
    }

    /// Evicts the oldest entry when the table is full.
    fn record_login_failure(
        attempts: &mut std::collections::HashMap<String, LoginAttempt>,
        key: String,
        limit: u32,
        now: u64,
    ) {
        if !attempts.contains_key(&key) && attempts.len() >= MAX_LOGIN_ATTEMPT_KEYS {
            if let Some(oldest) = attempts
                .iter()
                .min_by_key(|(_, attempt)| attempt.window_start_ms)
                .map(|(key, _)| key.clone())
            {
                attempts.remove(&oldest);
            }
        }
        let attempt = attempts.entry(key).or_insert(LoginAttempt {
            window_start_ms: now,
            failures: 0,
            blocked_until_ms: 0,
        });
        if now.saturating_sub(attempt.window_start_ms) > LOGIN_WINDOW_MS {
            attempt.window_start_ms = now;
            attempt.failures = 0;
            attempt.blocked_until_ms = 0;
        }
        attempt.failures = attempt.failures.saturating_add(1);
        if attempt.failures >= limit {
            attempt.blocked_until_ms = now.saturating_add(LOGIN_BLOCK_MS);
        }
    }

    /// For the audit log.
    fn session_name(&self, token: &str) -> Option<String> {
        let digest = credential_digest("session", &[token]);
        self.sessions
            .0
            .lock_recover()
            .get(&digest)
            .map(|s| s.name.clone())
    }

    /// Distinguishes a busy KDF from a mismatch.
    fn verify_user(&self, name: &str, password: &str) -> crate::password::VerifyResult {
        let hash = {
            let users = self.users.lock_recover();
            users
                .iter()
                .find(|user| user.name == name)
                .map(|user| user.hash.clone())
        };
        hash.as_deref()
            .map(|stored| crate::password::verify_password_result(password, stored))
            .unwrap_or(crate::password::VerifyResult::Mismatch)
    }

    /// Opens a session for an account just created, without verifying the password again: this
    /// server stored it in the same request, and a busy KDF would fail a valid account. `None` if
    /// the account disappeared meanwhile.
    fn start_session_for(&self, name: &str) -> Option<(String, Role)> {
        let user = {
            let users = self.users.lock_recover();
            users.iter().find(|user| user.name == name).cloned()
        }?;
        let credential_id = user_credential_id(&user);
        let token = self.issue_session(user.role, user.name.clone(), credential_id);
        Some((token, user.role))
    }

    /// Adds the first admin only when there is no account. Checking and adding under one lock keeps
    /// two concurrent requests from creating two admins. Returns whether it added one.
    fn add_first_user(&self, name: String, hash: String) -> bool {
        let mut users = self.users.lock_recover();
        if !users.is_empty() {
            return false;
        }
        users.push(UserCred {
            name,
            hash: hash.into(),
            role: Role::Admin,
        });
        true
    }

    fn update_user_hash(&self, name: &str, hash: String) -> bool {
        let mut users = self.users.lock_recover();
        let Some(user) = users.iter_mut().find(|u| u.name == name) else {
            return false;
        };
        user.hash = hash.into();
        true
    }

    /// Called on password change.
    fn revoke_user_sessions(&self, name: &str) {
        self.sessions
            .0
            .lock_recover()
            .retain(|_, session| session.name != name);
    }

    fn logout(&self, token: &str) {
        if !token.is_empty() {
            let digest = credential_digest("session", &[token]);
            self.sessions.0.lock_recover().remove(&digest);
        }
    }
}

fn audit_action(method: &str) -> &'static str {
    match method {
        "POST" => "create_or_run",
        "PUT" => "replace",
        "PATCH" => "update",
        "DELETE" => "delete",
        _ => "read",
    }
}

/// `fallback` when empty.
fn audit_identity(value: &str, fallback: &str) -> String {
    let cleaned: String = value
        .chars()
        .filter(|character| !character.is_control())
        .take(80)
        .collect();
    if cleaned.trim().is_empty() {
        fallback.to_string()
    } else {
        cleaned
    }
}

/// Keyed digest of a credential, for the audit log; a leaked log must not grant access.
fn credential_digest(prefix: &str, parts: &[&str]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    /// Per-process key.
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    let key = KEY.get_or_init(onetdns_core::random_array::<32>);
    let mut hasher = HmacSha256::new_from_slice(key).expect("HMAC-SHA-256 key length is valid");
    hasher.update(prefix.as_bytes());
    for part in parts {
        hasher.update(&[0]);
        hasher.update(part.as_bytes());
    }
    hasher.finalize().into_bytes().into()
}

/// Short form of the digest for the audit log.
fn credential_fingerprint_from_digest(prefix: &str, digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut id = String::with_capacity(prefix.len() + 21);
    id.push_str(prefix);
    id.push('-');
    for byte in digest.iter().take(10) {
        id.push(HEX[(byte >> 4) as usize] as char);
        id.push(HEX[(byte & 0x0f) as usize] as char);
    }
    id
}

fn credential_fingerprint(prefix: &str, parts: &[&str]) -> String {
    credential_fingerprint_from_digest(prefix, &credential_digest(prefix, parts))
}

/// Changes when the password changes.
fn user_credential_id(user: &UserCred) -> String {
    credential_fingerprint(
        "user",
        &[&user.name, user.role.as_str(), user.hash.as_str()],
    )
}

fn bearer_actor(token: &str) -> String {
    credential_fingerprint("token", &[token])
}

fn audit_actor(auth: &Auth, bearer: &str, session: &str) -> String {
    if !bearer.is_empty() {
        return if auth.role_for(bearer).is_some() {
            bearer_actor(bearer)
        } else {
            "anonymous".to_string()
        };
    }
    match auth.session_name(session) {
        Some(name) if !session.is_empty() => audit_identity(&name, "authenticated-user"),
        _ => "anonymous".to_string(),
    }
}

/// The body may hold passwords or tokens, so it is filtered, not logged as is.
fn audit_request_detail(method: &str, path: &str, body: &str) -> String {
    if method == "GET" || body.trim().is_empty() {
        return String::new();
    }
    let mut parts = Vec::new();
    if let Ok(json::Json::Obj(fields)) = json::parse(body) {
        let mut keys: Vec<&str> = fields.iter().map(|(key, _)| key.as_str()).collect();
        keys.sort_unstable();
        keys.dedup();
        if !keys.is_empty() {
            // A diagnostic body is not a config change; logging it under the same name would make
            // an investigation read like a change.
            let label = if is_state_changing_request(method, path) {
                "changed_keys"
            } else {
                "request_keys"
            };
            parts.push(format!("{label}={}", keys.join(",")));
        }

        // Values are logged only for these keys; any other may hold a secret.
        const SAFE_TARGETS: [&str; 7] = ["name", "id", "service", "kind", "mac", "adapter", "port"];
        for target in SAFE_TARGETS {
            let Some(value) = fields
                .iter()
                .find(|(key, _)| key == target)
                .map(|(_, value)| value)
            else {
                continue;
            };
            let text = match value {
                json::Json::Str(value) => value.clone(),
                json::Json::Num(value) => value.to_string(),
                json::Json::Bool(value) => value.to_string(),
                _ => continue,
            };
            let shortened: String = text.chars().take(160).collect();
            parts.push(format!("{target}={shortened}"));
        }
    } else {
        parts.push(format!("body_bytes={}", body.len()));
    }
    if path.starts_with("/v1/config") && parts.is_empty() {
        parts.push(format!("body_bytes={}", body.len()));
    }
    parts.join(" ")
}

struct AuditEntry {
    ts_ms: u64,
    actor: String,
    role: &'static str,
    method: String,
    action: &'static str,
    path: String,
    peer: String,
    detail: String,
    status: u16,
}

struct AuditContext<'a> {
    role: &'static str,
    actor: &'a str,
    method: &'a str,
    path: &'a str,
    peer: &'a str,
    status: u16,
}

#[derive(Clone)]
/// Recent audit entries in a fixed-size ring buffer.
pub struct AuditLog {
    inner: Arc<Mutex<VecDeque<AuditEntry>>>,
    cap: usize,
}

impl AuditLog {
    pub fn new(cap: usize) -> Self {
        AuditLog {
            inner: Arc::new(Mutex::new(VecDeque::new())),
            cap: cap.max(1),
        }
    }
    fn record_actor(
        &self,
        role: &'static str,
        actor: &str,
        method: &str,
        path: &str,
        peer: &str,
        status: u16,
    ) {
        self.record_detail(
            AuditContext {
                role,
                actor,
                method,
                path,
                peer,
                status,
            },
            String::new(),
        );
    }

    fn record_request_actor(&self, context: AuditContext<'_>, body: &str) {
        let detail = audit_request_detail(context.method, context.path, body);
        self.record_detail(context, detail);
    }

    fn record_detail(&self, context: AuditContext<'_>, detail: String) {
        let AuditContext {
            role,
            actor,
            method,
            path,
            peer,
            status,
        } = context;
        let mut q = self.inner.lock_recover();
        if q.len() >= self.cap {
            q.pop_front();
        }
        q.push_back(AuditEntry {
            ts_ms: now_ms(),
            actor: actor.to_string(),
            role,
            method: method.to_string(),
            action: audit_action(method),
            path: path.to_string(),
            peer: peer.to_string(),
            detail: detail.clone(),
            status,
        });
        drop(q);

        // Diagnostic POSTs change nothing. Logging them as changes would add hundreds of lines per
        // investigation and bury the real changes; the audit log above already has them.
        if is_state_changing_request(method, path) || status >= 400 {
            let detail: Option<&str> = (!detail.is_empty()).then_some(detail.as_str());
            if status >= 400 {
                // Failures are logged on the 1st, 2nd, 4th, ... occurrence with the count, so one
                // client retrying a wrong token many times a second does not flood the log.
                let count = repeated_failure_count(method, path, status);
                if should_log_repeated_failure(count) {
                    match detail {
                        Some(detail) => onetdns_core::warn!(
                            event = "control.request_failed",
                            actor, role, method, path, peer, status, count, detail = %detail,
                            "Management API request failed"
                        ),
                        None => onetdns_core::warn!(
                            event = "control.request_failed",
                            actor,
                            role,
                            method,
                            path,
                            peer,
                            status,
                            count,
                            "Management API request failed"
                        ),
                    }
                }
            } else {
                match detail {
                    Some(detail) => onetdns_core::info!(
                        event = "control.mutation",
                        actor, role, method, path, peer, status, detail = %detail,
                        "Handled a management API change request"
                    ),
                    None => onetdns_core::info!(
                        event = "control.mutation",
                        actor,
                        role,
                        method,
                        path,
                        peer,
                        status,
                        "Handled a management API change request"
                    ),
                }
            }
        }
    }
    fn json(&self) -> String {
        let q = self.inner.lock_recover();
        let items: Vec<String> = q
            .iter()
            .map(|e| {
                format!(
                    "{{\"ts_ms\":{},\"actor\":{},\"role\":{},\"method\":{},\"action\":{},\"path\":{},\"peer\":{},\"detail\":{},\"status\":{}}}",
                    e.ts_ms,
                    json::escape(&e.actor),
                    json::escape(e.role),
                    json::escape(&e.method),
                    json::escape(e.action),
                    json::escape(&e.path),
                    json::escape(&e.peer),
                    json::escape(&e.detail),
                    e.status
                )
            })
            .collect();
        format!("{{\"entries\":[{}]}}", items.join(","))
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        AuditLog::new(1000)
    }
}

/// A control connection held without a thread until its request is complete.
struct PendingControlConnection {
    stream: SharedTcp,
    peer: SocketAddr,
    /// Counted from accept.
    deadline: Instant,
    /// Request bytes admission read so far.
    received: Vec<u8>,
    /// Earliest recheck of a connection that made no progress.
    next_probe: Instant,
    probe_delay: Duration,
    admission_bytes: AdmissionBytesGuard,
    /// Counts toward the connection limit while pending.
    guard: ActiveConnectionGuard,
}

enum ControlAdmissionState {
    Pending,
    /// Enough arrived for the parser to read without blocking.
    Ready,
    /// The peer closed before completing the request.
    Closed,
    /// The global unauthenticated byte budget is full.
    Overloaded,
}

/// Total bytes the parser will read for a request whose headers are complete. Admits nothing:
/// only a single valid Content-Length is waited for; duplicates, malformed values,
/// Transfer-Encoding and oversize bodies count as ready at the headers, so the parser rejects
/// them at once.
fn control_request_required_bytes(header: &[u8], header_end: usize) -> usize {
    let Ok(text) = std::str::from_utf8(&header[..header_end]) else {
        return header_end;
    };
    let mut content_length = None;
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, raw_value)) = line.split_once(':') else {
            return header_end;
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return header_end;
        }
        if !name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        if content_length.is_some() {
            return header_end;
        }
        let value = raw_value.trim_matches([' ', '\t']);
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return header_end;
        }
        let Ok(length) = value.parse::<usize>() else {
            return header_end;
        };
        if length > MAX_REQUEST_BODY {
            return header_end;
        }
        content_length = Some(length);
    }
    header_end
        .checked_add(content_length.unwrap_or(0))
        .unwrap_or(header_end)
}

/// Reads available bytes without blocking and reports whether the request is complete.
fn control_admission_state(
    pending: &mut PendingControlConnection,
    scratch: &mut [u8],
) -> std::io::Result<ControlAdmissionState> {
    loop {
        let required = if let Some(header_end) = pending
            .received
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
        {
            control_request_required_bytes(&pending.received, header_end)
        } else {
            CONTROL_ADMISSION_HEADER_BYTES
        };
        if pending.received.len() >= required {
            return Ok(ControlAdmissionState::Ready);
        }
        let read_len = (required - pending.received.len()).min(scratch.len());
        let reserved = pending.admission_bytes.reserve(read_len);
        if reserved == 0 {
            return Ok(ControlAdmissionState::Overloaded);
        }
        match pending.stream.read(&mut scratch[..reserved]) {
            Ok(0) => {
                pending.admission_bytes.release(reserved);
                return Ok(ControlAdmissionState::Closed);
            }
            Ok(read) => {
                pending.admission_bytes.release(reserved - read);
                pending.received.extend_from_slice(&scratch[..read]);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                pending.admission_bytes.release(reserved);
                return Ok(ControlAdmissionState::Pending);
            }
            Err(error) => {
                pending.admission_bytes.release(reserved);
                return Err(error);
            }
        }
    }
}

#[derive(Clone)]
/// Everything the control server needs to handle requests; shared by connection threads.
pub struct AppState {
    pub stats: Stats,
    pub auth: Arc<Auth>,
    pub audit: AuditLog,
    pub controls: Arc<Controls>,

    /// Until set, the server reports not ready.
    pub readiness: Arc<std::sync::atomic::AtomicBool>,

    /// Replaced whole on config reload.
    pub proxy: Arc<ArcSwap<ProxyPolicy>>,
}

#[derive(Default)]
/// Serving the dashboard behind a reverse proxy. Only connections from `trusted` may use an
/// `origins` Host, and only theirs have X-Forwarded-For read; others still need a loopback Host.
pub struct ProxyPolicy {
    /// Addresses the reverse proxy connects from.
    pub trusted: Vec<IpNet>,
    /// HTTPS origins the proxy serves the dashboard on.
    pub origins: Vec<HttpsOrigin>,
}

impl ProxyPolicy {
    fn trusts(&self, ip: IpAddr) -> bool {
        self.trusted.iter().any(|net| net.contains(&ip))
    }

    /// The first address from the right that is not a trusted proxy: clients can write anything on
    /// the left, and each proxy appends the address it saw. Stops at a non-address and returns
    /// `None`.
    fn forwarded_client(&self, forwarded_for: &str) -> Option<IpAddr> {
        for entry in forwarded_for.rsplit(',') {
            let ip = entry.trim().parse::<IpAddr>().ok()?;
            if !self.trusts(ip) {
                return Some(ip);
            }
        }
        None
    }
}

/// For direct loopback connections.
const SESSION_COOKIE: &str = "onetdns_session";

/// For connections through an HTTPS reverse proxy. Browsers accept a `__Host-` cookie only with
/// Secure, Path=/ and no Domain, so other subdomains cannot overwrite it.
const SECURE_SESSION_COOKIE: &str = "__Host-onetdns_session";

/// The sender of a request. Audit records, sign-in limits and the cookie form follow it.
struct Caller {
    /// The TCP peer; the proxy when the request came through one.
    peer: Option<SocketAddr>,
    /// Set when the request came through a trusted reverse proxy to a public origin.
    proxied: Option<Proxied>,
}

struct Proxied {
    /// From X-Forwarded-For; `None` when missing or malformed.
    client: Option<IpAddr>,
}

impl Caller {
    fn direct(peer: Option<SocketAddr>) -> Self {
        Self {
            peer,
            proxied: None,
        }
    }

    /// Source for audit records and logs, naming both client and proxy when proxied.
    fn label(&self) -> String {
        let peer = self.peer.map(|value| value.to_string()).unwrap_or_default();
        match &self.proxied {
            Some(proxied) => match proxied.client {
                Some(client) => format!("{client} via {peer}"),
                None => format!("unknown via {peer}"),
            },
            None => peer,
        }
    }

    /// Key for counting sign-in failures. Through a proxy it is the client's network, since
    /// counting the proxy would let one attacker block every admin behind it; the proxy's only
    /// when the client is unknown. An IPv6 client is counted by its /64, or it could change
    /// addresses within it to escape the limit. Direct requests all come from this machine and
    /// share one key; on Linux any address in 127.0.0.0/8 can connect, so per-address keys could be
    /// rotated.
    fn login_source(&self) -> String {
        match &self.proxied {
            Some(proxied) => proxied
                .client
                .or(self.peer.map(|peer| peer.ip()))
                .map_or_else(
                    || "unknown".to_string(),
                    |ip| onetdns_core::admission::client_network(ip).to_string(),
                ),
            None => "local".to_string(),
        }
    }

    /// The proxy address when proxied; the key for per-proxy sign-in pacing.
    fn login_proxy(&self) -> Option<String> {
        self.proxied.as_ref()?;
        Some(self.peer?.ip().to_string())
    }

    /// The Secure cookie when the request came through an HTTPS public origin.
    fn session_cookie(&self) -> &'static str {
        if self.proxied.is_some() {
            SECURE_SESSION_COOKIE
        } else {
            SESSION_COOKIE
        }
    }
}

/// Hands a completed request to a connection thread.
fn spawn_control_connection(
    pending: PendingControlConnection,
    state: &AppState,
    shutdown: &Arc<std::sync::atomic::AtomicBool>,
    connections: &mut Vec<(SharedTcp, std::thread::JoinHandle<()>)>,
) {
    let PendingControlConnection {
        stream,
        peer,
        deadline,
        received,
        next_probe: _,
        probe_delay: _,
        admission_bytes,
        guard,
    } = pending;
    if let Err(error) = stream.set_nonblocking(false) {
        record_control_error("socket_blocking", Some(peer), error);
        return;
    }
    let st = state.clone();
    let shutdown_stream = stream.clone();
    let connection_shutdown = shutdown.clone();
    match std::thread::Builder::new()
        .name("onetdns-control-client".to_string())
        .stack_size(CONTROL_CONNECTION_STACK_BYTES)
        .spawn(move || {
            let _guard = guard;
            if let Err(error) =
                handle_conn_until_shutdown(
                    stream,
                    &st,
                    connection_shutdown,
                    deadline,
                    received,
                    admission_bytes,
                )
            {
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::NotConnected
                ) {
                    onetdns_core::debug!(event = "control.connection_closed", transport = "control", peer = %peer, error = %error, "Closed dashboard connection");
                } else {
                    record_control_error("connection", Some(peer), error);
                }
            }
        })
    {
        Ok(thread) => connections.push((shutdown_stream, thread)),
        Err(error) => record_control_error("thread_spawn", Some(peer), error),
    }
}

/// Handles pending connections that completed, hit their deadline or closed.
fn promote_control_connections(
    pending: &mut Vec<PendingControlConnection>,
    state: &AppState,
    shutdown: &Arc<std::sync::atomic::AtomicBool>,
    connections: &mut Vec<(SharedTcp, std::thread::JoinHandle<()>)>,
    scratch: &mut [u8],
) {
    let mut index = 0;
    while index < pending.len() {
        let now = Instant::now();
        if now >= pending[index].deadline {
            let expired = pending.swap_remove(index);
            if expired.stream.set_nonblocking(false).is_ok() {
                let _ = write_simple(
                    expired.stream,
                    "408 Request Timeout",
                    "text/plain",
                    "",
                    "Management request was not received in time",
                );
            }
            continue;
        }
        if now < pending[index].next_probe {
            index += 1;
            continue;
        }
        let received_before = pending[index].received.len();
        let state_now = match control_admission_state(&mut pending[index], scratch) {
            Ok(state_now) => state_now,
            Err(error) => {
                let failed = pending.swap_remove(index);
                record_control_error("connection_admission", Some(failed.peer), error);
                continue;
            }
        };
        match state_now {
            ControlAdmissionState::Pending => {
                if pending[index].received.len() > received_before {
                    pending[index].probe_delay = Duration::from_millis(CONTROL_ADMISSION_POLL_MS);
                } else {
                    pending[index].probe_delay = (pending[index].probe_delay * 2)
                        .min(Duration::from_millis(CONTROL_ADMISSION_MAX_BACKOFF_MS));
                }
                pending[index].next_probe = now + pending[index].probe_delay;
                index += 1;
            }
            ControlAdmissionState::Closed => {
                pending.swap_remove(index);
            }
            ControlAdmissionState::Overloaded => {
                let overloaded = pending.swap_remove(index);
                if overloaded.stream.set_nonblocking(false).is_ok() {
                    let _ = write_simple(
                        overloaded.stream,
                        "503 Service Unavailable",
                        "text/plain",
                        "Retry-After: 1\r\n",
                        "Management request buffer limit reached",
                    );
                }
            }
            ControlAdmissionState::Ready => {
                let ready = pending.swap_remove(index);
                spawn_control_connection(ready, state, shutdown, connections);
            }
        }
    }
}

/// Config validation restricts the address to loopback.
pub fn serve(
    addr: SocketAddr,
    state: AppState,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    serve_listener(listener, state, shutdown)
}

/// Takes an open listener so a config reapply keeps the same socket and dashboard connections
/// survive. Only connections with a complete request get a thread; partial ones stay in
/// non-blocking admission.
pub fn serve_listener(
    listener: TcpListener,
    state: AppState,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<()> {
    use std::sync::atomic::Ordering;
    listener.set_nonblocking(true)?;
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let admission_bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut connections = Vec::new();
    let mut pending = Vec::new();
    let mut admission_scratch = [0u8; CONTROL_ADMISSION_READ_BYTES];
    while !shutdown.load(Ordering::Relaxed) {
        reap_control_connections(&mut connections);
        promote_control_connections(
            &mut pending,
            &state,
            &shutdown,
            &mut connections,
            &mut admission_scratch,
        );
        loop {
            match listener.accept() {
                Ok((s, peer)) => {
                    if let Err(error) = s
                        .set_read_timeout(Some(std::time::Duration::from_secs(
                            CONTROL_READ_TIMEOUT_SECS,
                        )))
                        .and_then(|()| {
                            s.set_write_timeout(Some(std::time::Duration::from_secs(
                                CONTROL_WRITE_TIMEOUT_SECS,
                            )))
                        })
                    {
                        record_control_error("socket_options", Some(peer), error);
                        continue;
                    }
                    let s = SharedTcp::new(s);
                    let Some(guard) = acquire_connection_slot(&active) else {
                        record_control_error(
                            "connection_limit",
                            Some(peer),
                            "Too many concurrent management connections",
                        );
                        let _ = write_simple(
                            s,
                            "503 Service Unavailable",
                            "text/plain",
                            "Retry-After: 1\r\n",
                            "Too many management requests. Try again shortly",
                        );
                        continue;
                    };
                    if let Err(error) = s.set_nonblocking(true) {
                        record_control_error("socket_nonblocking", Some(peer), error);
                        continue;
                    }
                    pending.push(PendingControlConnection {
                        stream: s,
                        peer,
                        deadline: Instant::now() + Duration::from_secs(CONTROL_READ_TIMEOUT_SECS),
                        received: Vec::new(),
                        next_probe: Instant::now(),
                        probe_delay: Duration::from_millis(CONTROL_ADMISSION_POLL_MS),
                        admission_bytes: AdmissionBytesGuard::new(admission_bytes.clone()),
                        guard,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    record_control_error("accept", None, error);
                    break;
                }
            }
        }
        promote_control_connections(
            &mut pending,
            &state,
            &shutdown,
            &mut connections,
            &mut admission_scratch,
        );
        std::thread::sleep(Duration::from_millis(CONTROL_ADMISSION_POLL_MS));
    }

    for pending in pending.drain(..) {
        let _ = pending.stream.shutdown(std::net::Shutdown::Both);
    }

    let drain_deadline = Instant::now() + Duration::from_secs(CONTROL_DRAIN_GRACE_SECS);
    loop {
        reap_control_connections(&mut connections);
        if connections.is_empty() || Instant::now() >= drain_deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    for (stream, _) in &connections {
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
    for (_, thread) in connections {
        let _ = thread.join();
    }
    Ok(())
}

/// Joins finished connection threads, whose handles would pile up otherwise.
fn reap_control_connections(connections: &mut Vec<(SharedTcp, std::thread::JoinHandle<()>)>) {
    let mut index = 0;
    while index < connections.len() {
        if connections[index].1.is_finished() {
            let (_, thread) = connections.swap_remove(index);
            let _ = thread.join();
        } else {
            index += 1;
        }
    }
}

/// Errors when the line exceeds the limit.
fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    out: &mut String,
    max: usize,
) -> std::io::Result<usize> {
    reader.take(max.saturating_add(1) as u64).read_line(out)
}

/// Strips the line ending; `None` when malformed.
fn http_line(value: &str) -> Option<&str> {
    let value = value.strip_suffix("\r\n")?;
    (!value.bytes().any(|byte| matches!(byte, b'\r' | b'\n'))).then_some(value)
}

fn http_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/// Control characters are refused; a line break in a value would smuggle in a new header.
fn http_field_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || (byte >= b' ' && byte != 0x7f))
}

/// Origin read from a loopback Host header; the host is normalized to a lowercase name or IP
/// string. A Host without a port means 80, which is how it is compared with Origin.
#[derive(Debug, PartialEq, Eq)]
struct LoopbackAuthority {
    host: String,
    port: Option<u16>,
}

impl LoopbackAuthority {
    /// The port, with HTTP's 80 filled in when omitted.
    fn effective_port(&self) -> u16 {
        self.port.unwrap_or(80)
    }
}

/// Whether the Host header names this server; a port, if given, must be this socket's. This is
/// the DNS rebinding defense: without it an attacker's page could point its name at loopback and
/// call the control API through the browser.
fn control_authority(value: &str, local_port: u16) -> Option<LoopbackAuthority> {
    let value = value.trim();
    if value.is_empty()
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
        || value.contains(['/', '\\', '@', '#', '?'])
    {
        return None;
    }
    let authority = parse_loopback_authority(value)?;
    authority
        .port
        .is_none_or(|port| port == local_port)
        .then_some(authority)
}

/// Parses host[:port] and returns it only for a loopback host.
fn parse_loopback_authority(value: &str) -> Option<LoopbackAuthority> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return address.ip().is_loopback().then(|| LoopbackAuthority {
            host: address.ip().to_string(),
            port: Some(address.port()),
        });
    }
    if let Some(inner) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
        let ip = inner.parse::<std::net::IpAddr>().ok()?;
        return ip.is_loopback().then(|| LoopbackAuthority {
            host: ip.to_string(),
            port: None,
        });
    }
    if let Ok(ip) = value.parse::<std::net::IpAddr>() {
        return ip.is_loopback().then(|| LoopbackAuthority {
            host: ip.to_string(),
            port: None,
        });
    }
    let (name, port) = match value.rsplit_once(':') {
        Some((name, port)) => (name, Some(port.parse::<u16>().ok()?)),
        None => (value, None),
    };
    name.eq_ignore_ascii_case("localhost")
        .then(|| LoopbackAuthority {
            host: "localhost".into(),
            port,
        })
}

/// Whether Origin is the same origin as the loopback Host: scheme http, since the socket serves
/// plain HTTP, and the same host and effective port. A value with a path is not an Origin.
/// Comparing hosts alone would let a page on another local port call the API and WebSocket;
/// browsers do not apply the same-origin policy to WebSocket, so this check is the only guard
/// against cross-site WebSocket hijacking.
fn same_loopback_origin(origin: &str, host: &LoopbackAuthority) -> bool {
    let Some(authority) = origin.strip_prefix("http://") else {
        return false;
    };
    if authority.is_empty() || authority.contains(['/', '\\', '@', '#', '?']) {
        return false;
    }
    parse_loopback_authority(authority).is_some_and(|origin| {
        origin.host == host.host && origin.effective_port() == host.effective_port()
    })
}

#[derive(Debug, PartialEq, Eq)]
enum HostRejection {
    /// Host is neither loopback nor a public origin reached through a trusted proxy.
    Misdirected,
    /// Origin differs from Host.
    CrossOrigin,
}

/// Decides from Host and Origin whether to accept the request, and if so who sent it. A loopback
/// Host needs a matching loopback Origin. Any other Host is accepted only from a trusted reverse
/// proxy and only when listed as a public origin, with Origin, if present, equal to it; only then
/// is X-Forwarded-For read. Opening public origins to non-proxy connections would let another
/// local program pose as the proxy and forge X-Forwarded-For to evade sign-in limits.
fn control_caller(
    policy: &ProxyPolicy,
    peer: Option<SocketAddr>,
    local_port: u16,
    host: &str,
    origin: Option<&str>,
    forwarded_for: &str,
) -> Result<Caller, HostRejection> {
    if let Some(authority) = control_authority(host, local_port) {
        if origin.is_some_and(|value| !same_loopback_origin(value, &authority)) {
            return Err(HostRejection::CrossOrigin);
        }
        return Ok(Caller::direct(peer));
    }
    let from_proxy = peer.is_some_and(|peer| policy.trusts(peer.ip()));
    let public = from_proxy
        .then(|| {
            policy
                .origins
                .iter()
                .find(|public| public.matches_host(host))
        })
        .flatten()
        .ok_or(HostRejection::Misdirected)?;
    if origin.is_some_and(|value| !public.matches_origin(value)) {
        return Err(HostRejection::CrossOrigin);
    }
    Ok(Caller {
        peer,
        proxied: Some(Proxied {
            client: policy.forwarded_client(forwarded_for),
        }),
    })
}

#[cfg(test)]
fn handle_conn(stream: TcpStream, st: &AppState) -> std::io::Result<()> {
    handle_conn_inner(
        SharedTcp::new(stream),
        st,
        None,
        Instant::now() + Duration::from_secs(CONTROL_READ_TIMEOUT_SECS),
        Vec::new(),
        None,
    )
}

fn handle_conn_until_shutdown(
    stream: SharedTcp,
    st: &AppState,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    request_deadline: Instant,
    prefix: Vec<u8>,
    admission_bytes: AdmissionBytesGuard,
) -> std::io::Result<()> {
    handle_conn_inner(
        stream,
        st,
        Some(shutdown),
        request_deadline,
        prefix,
        Some(admission_bytes),
    )
}

/// Reads the request line and headers within limits, checks Host and Origin, reads the body,
/// authenticates, then routes. State-changing requests take the mutation lock, or concurrent
/// config applies overwrite each other.
fn handle_conn_inner(
    mut stream: SharedTcp,
    st: &AppState,
    shutdown: Option<Arc<std::sync::atomic::AtomicBool>>,
    request_deadline: Instant,
    prefix: Vec<u8>,
    admission_bytes: Option<AdmissionBytesGuard>,
) -> std::io::Result<()> {
    let peer = stream.peer_addr().ok();
    let local_port = stream.local_addr()?.port();
    let mut deadline_stream = DeadlineTcp::new(
        AdmittedTcp::new(stream.clone(), prefix, admission_bytes),
        request_deadline,
    );
    if let Some(shutdown) = shutdown {
        deadline_stream = deadline_stream.stop_on(shutdown);
    }
    let mut reader = BufReader::new(deadline_stream);

    let mut line = String::new();
    if read_bounded_line(&mut reader, &mut line, MAX_REQUEST_LINE)? == 0 {
        return Ok(());
    }
    if line.len() > MAX_REQUEST_LINE {
        return write_simple(
            stream,
            "414 URI Too Long",
            "text/plain",
            "",
            "Request target is too long",
        );
    }
    let Some(line) = http_line(&line) else {
        return write_simple(
            stream,
            "400 Bad Request",
            "text/plain",
            "",
            "HTTP request line must end with CRLF",
        );
    };
    let mut it = line.split(' ');
    let method = it.next().unwrap_or("").to_string();
    let target = it.next().unwrap_or("").to_string();
    let version = it.next().unwrap_or("");

    if method.is_empty()
        || target.is_empty()
        || !http_token(&method)
        || !target.starts_with('/')
        || !target
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'#')
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || it.next().is_some()
    {
        return write_simple(
            stream,
            "400 Bad Request",
            "text/plain",
            "",
            "Malformed HTTP request line",
        );
    }
    // The query string is not part of the path; left on, `/?x=1` and `/healthz?src=lb` would 404
    // or 401. Only the path goes to the audit log.
    let path = match target.find('?') {
        Some(mark) => target[..mark].to_string(),
        None => target,
    };
    let mut content_length: Option<usize> = None;
    let mut content_type: Option<String> = None;
    let mut auth = String::new();
    let mut cookie = String::new();
    let mut csrf = String::new();
    let mut ws_upgrade = String::new();
    let mut ws_connection = String::new();
    let mut ws_key = String::new();
    let mut ws_version = String::new();
    let mut ws_protocols = String::new();
    let mut auth_seen = false;
    let mut csrf_seen = false;
    let mut host: Option<String> = None;
    let mut origin: Option<String> = None;
    let mut forwarded_for = String::new();
    let mut header_bytes = 0usize;
    let mut header_count = 0usize;
    let mut has_transfer_encoding = false;
    loop {
        let mut h = String::new();
        if read_bounded_line(&mut reader, &mut h, MAX_HEADER_LINE)? == 0 {
            return write_simple(
                stream,
                "400 Bad Request",
                "text/plain",
                "",
                "HTTP headers were not fully received",
            );
        }
        header_bytes = header_bytes.saturating_add(h.len());
        header_count = header_count.saturating_add(1);
        if h.len() > MAX_HEADER_LINE
            || header_bytes > MAX_HEADER_BYTES
            || header_count > MAX_HEADERS
        {
            return write_simple(
                stream,
                "431 Request Header Fields Too Large",
                "text/plain",
                "",
                "HTTP headers exceed the size or count limit",
            );
        }
        let Some(t) = http_line(&h) else {
            return write_simple(
                stream,
                "400 Bad Request",
                "text/plain",
                "",
                "HTTP header line must end with CRLF",
            );
        };
        if t.is_empty() {
            break;
        }
        if t.starts_with(' ') || t.starts_with('\t') {
            return write_simple(
                stream,
                "400 Bad Request",
                "text/plain",
                "",
                "Folded HTTP headers are not allowed",
            );
        }
        let Some((name, val)) = t.split_once(':') else {
            return write_simple(
                stream,
                "400 Bad Request",
                "text/plain",
                "",
                "Malformed HTTP header",
            );
        };
        if !http_token(name) || !http_field_value(val) {
            return write_simple(
                stream,
                "400 Bad Request",
                "text/plain",
                "",
                "HTTP header name or value contains a disallowed character",
            );
        }
        let val = val.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return write_simple(
                    stream,
                    "400 Bad Request",
                    "text/plain",
                    "",
                    "Content-Length header sent more than once",
                );
            }
            if val.is_empty() || !val.bytes().all(|byte| byte.is_ascii_digit()) {
                return write_simple(
                    stream,
                    "400 Bad Request",
                    "text/plain",
                    "",
                    "Invalid Content-Length header",
                );
            }
            content_length = Some(match val.parse::<usize>() {
                Ok(value) => value,
                Err(_) => {
                    return write_simple(
                        stream,
                        "400 Bad Request",
                        "text/plain",
                        "",
                        "Invalid Content-Length header",
                    )
                }
            });
        } else if name.eq_ignore_ascii_case("content-type") {
            if content_type.is_some() {
                return write_simple(
                    stream,
                    "400 Bad Request",
                    "text/plain",
                    "",
                    "Content-Type header sent more than once",
                );
            }
            content_type = Some(val.to_ascii_lowercase());
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            has_transfer_encoding = true;
        } else if name.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return write_simple(
                    stream,
                    "400 Bad Request",
                    "text/plain",
                    "",
                    "Host header sent more than once",
                );
            }
            host = Some(val.to_string());
        } else if name.eq_ignore_ascii_case("origin") {
            if origin.is_some() {
                return write_simple(
                    stream,
                    "400 Bad Request",
                    "text/plain",
                    "",
                    "Origin header sent more than once",
                );
            }
            origin = Some(val.to_string());
        } else if name.eq_ignore_ascii_case("x-forwarded-for") {
            if !forwarded_for.is_empty() {
                forwarded_for.push(',');
            }
            forwarded_for.push_str(val);
        } else if name.eq_ignore_ascii_case("authorization") {
            if auth_seen {
                return write_simple(
                    stream,
                    "400 Bad Request",
                    "text/plain",
                    "",
                    "Authorization header sent more than once",
                );
            }
            auth_seen = true;
            auth = val.to_string();
        } else if name.eq_ignore_ascii_case("cookie") {
            append_cookie_header(&mut cookie, val);
        } else if name.eq_ignore_ascii_case("x-onetdns-csrf") {
            if csrf_seen {
                return write_simple(
                    stream,
                    "400 Bad Request",
                    "text/plain",
                    "",
                    "CSRF header sent more than once",
                );
            }
            csrf_seen = true;
            csrf = val.to_string();
        } else if name.eq_ignore_ascii_case("upgrade") {
            ws_upgrade = val.to_string();
        } else if name.eq_ignore_ascii_case("connection") {
            ws_connection = val.to_string();
        } else if name.eq_ignore_ascii_case("sec-websocket-key") {
            ws_key = val.to_string();
        } else if name.eq_ignore_ascii_case("sec-websocket-version") {
            ws_version = val.to_string();
        } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
            if !ws_protocols.is_empty() {
                ws_protocols.push(',');
            }
            ws_protocols.push_str(val);
        }
    }
    let Some(host) = host else {
        return write_simple(
            stream,
            "400 Bad Request",
            "text/plain",
            "",
            "Missing Host header",
        );
    };
    // The CA sends the domain being issued as Host. This read-only GET returns only values meant
    // to be public, so rebinding gains nothing and the Host check is skipped.
    if method == "GET" && path.starts_with("/.well-known/acme-challenge/") {
        let (status, content_type, body) =
            route(&method, &path, "", "", "", &Caller::direct(peer), st);
        return write_simple(stream, status, content_type, "", &body);
    }
    let caller = match control_caller(
        &st.proxy.load(),
        peer,
        local_port,
        &host,
        origin.as_deref(),
        &forwarded_for,
    ) {
        Ok(caller) => caller,
        Err(HostRejection::Misdirected) => {
            record_control_error(
                "host_not_loopback",
                peer,
                "Management API called with a Host that is neither loopback nor a configured public address. This may be a DNS rebinding attempt",
            );
            return write_simple(
                stream,
                "421 Misdirected Request",
                "text/plain",
                "",
                "Management API Host must be localhost, a loopback address, or an address in control_public_origins reached through control_trusted_proxies",
            );
        }
        Err(HostRejection::CrossOrigin) => {
            record_control_error("cross_origin", peer, "Cross-origin management request");
            return write_simple(
                stream,
                "403 Forbidden",
                "text/plain",
                "",
                "Cross-origin management requests are not allowed",
            );
        }
    };
    if has_transfer_encoding {
        return write_simple(
            stream,
            "400 Bad Request",
            "text/plain",
            "",
            "Transfer-Encoding requests are not supported",
        );
    }
    let content_length = content_length.unwrap_or(0);
    if content_length > MAX_REQUEST_BODY {
        record_control_error("body_too_large", peer, content_length);
        return write_simple(
            stream,
            "413 Payload Too Large",
            "text/plain",
            "",
            "Request body is too large",
        );
    }
    let session_candidates = cookie_values(&cookie, caller.session_cookie());

    let session = select_session_cookie(&session_candidates, &st.auth);
    let bearer = auth.strip_prefix("Bearer ").unwrap_or("");
    let mutating = !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS");
    if mutating && path != "/v1/login" && !session.is_empty() && bearer.is_empty() && csrf != "1" {
        record_control_error(
            "csrf_check",
            peer,
            "Cookie-authenticated write request has no CSRF token",
        );
        return write_simple(
            stream,
            "403 Forbidden",
            "text/plain",
            "",
            "CSRF check failed",
        );
    }

    if content_length > 0 && !content_type_allowed(&method, &path, content_type.as_deref()) {
        record_control_error(
            "content_type",
            peer,
            "Content-Type is missing or unsupported",
        );
        return write_simple(
            stream,
            "415 Unsupported Media Type",
            "text/plain",
            "",
            "Content-Type header is missing or unsupported",
        );
    }
    let mut body = vec![0u8; content_length];
    if !body.is_empty() {
        reader.read_exact(&mut body)?;
    }
    let body = match String::from_utf8(body) {
        Ok(body) => body,
        Err(_) => {
            return write_simple(
                stream,
                "400 Bad Request",
                "text/plain",
                "",
                "Request body must be valid UTF-8",
            )
        }
    };

    if method == "POST" && path == "/v1/setup" {
        return handle_setup(stream, &body, &caller, st);
    }
    if method == "POST" && path == "/v1/login" {
        return handle_login(stream, &body, &caller, st);
    }
    if method == "POST" && path == "/v1/logout" {
        return handle_logout(stream, &session_candidates, &caller, st);
    }
    if method == "GET" && path == "/v1/auth" {
        return handle_auth(stream, &auth, &session, &caller, st);
    }

    if method == "GET" && path == "/v1/dashboard/ws" {
        return handle_dashboard_websocket(
            stream,
            &auth,
            &session,
            &ws_upgrade,
            &ws_connection,
            &ws_key,
            &ws_version,
            &ws_protocols,
            &caller,
            st,
        );
    }

    let (status, ctype, resp) = route(&method, &path, &auth, &session, &body, &caller, st);
    let ctype = with_charset(ctype);
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
        control_security_headers(),
        resp.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(resp.as_bytes())?;
    stream.flush()
}

/// Refusing content types a browser can send without a preflight is the CSRF defense.
fn content_type_allowed(method: &str, path: &str, value: Option<&str>) -> bool {
    if matches!(method, "GET" | "HEAD" | "OPTIONS") {
        return true;
    }
    let Some(raw) = value else {
        return false;
    };
    let media_type = raw.split(';').next().unwrap_or("").trim();
    if path.starts_with("/v1/zones/") {
        if path.ends_with("/records") {
            return match method {
                "POST" | "PUT" => {
                    matches!(media_type, "text/plain" | "application/dns-zone")
                }
                "DELETE" => media_type == "application/json",
                _ => false,
            };
        }
        return matches!(method, "POST" | "PUT")
            && matches!(media_type, "text/plain" | "application/dns-zone");
    }
    if path == "/v1/restore" || path == "/v1/config/set" {
        return media_type == "application/json";
    }
    if matches!(
        path,
        "/v1/config/validate" | "/v1/config/diff" | "/v1/config/apply"
    ) {
        return matches!(media_type, "text/plain" | "application/toml");
    }
    media_type == "application/json"
}

/// Joins repeated Cookie headers.
fn append_cookie_header(cookie: &mut String, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    if !cookie.is_empty() {
        cookie.push_str("; ");
    }
    cookie.push_str(value);
}

/// Every value with this name; names can repeat.
fn cookie_values(cookie: &str, key: &str) -> Vec<String> {
    let mut values: Vec<String> = Vec::new();
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == key {
                let value = v.trim();
                if !value.is_empty() && !values.iter().any(|item| item.as_str() == value) {
                    values.push(value.to_string());
                }
            }
        }
    }
    values
}

/// Picks the valid one among several session cookies. Browsers send same-named cookies with
/// different paths or domains, and taking only the first can make a stale value look like a
/// sign-out.
fn select_session_cookie(candidates: &[String], auth: &Auth) -> String {
    candidates
        .iter()
        .find(|token| auth.role_for_session(token.as_str()).is_some())
        .cloned()
        .or_else(|| candidates.first().cloned())
        .unwrap_or_default()
}

/// Same shape as the dashboard header mark.
#[cfg(feature = "dashboard")]
const FAVICON_SVG: &str = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 48 48\">\
<rect width=\"48\" height=\"48\" rx=\"10\" fill=\"#2f4a6b\"/>\
<g fill=\"none\" stroke=\"#f7f3e9\" stroke-width=\"4.6\" stroke-linecap=\"round\" \
stroke-linejoin=\"round\" transform=\"translate(5.28,5.28) scale(0.78)\">\
<path d=\"M38 14.4A17 17 0 1 0 38 33.6\"/>\
<path d=\"M31.5 24H39.5\"/>\
<path d=\"M9.5 24H17l3-7.5 4.5 15 3-7.5H33\"/>\
</g></svg>";

fn control_security_headers() -> &'static str {
    "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nPermissions-Policy: camera=(), microphone=(), geolocation=()\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'\r\n"
}

/// Without a charset, text responses may be read as ISO-8859-1 and Korean bodies break. JSON is
/// UTF-8 by spec, so it gets none.
fn with_charset(ctype: &str) -> Cow<'_, str> {
    if ctype.starts_with("text/") && !ctype.to_ascii_lowercase().contains("charset=") {
        Cow::Owned(format!("{ctype}; charset=utf-8"))
    } else {
        Cow::Borrowed(ctype)
    }
}

fn write_simple(
    mut stream: SharedTcp,
    status: &str,
    ctype: &str,
    extra: &str,
    body: &str,
) -> std::io::Result<()> {
    let ctype = with_charset(ctype);
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\n{}{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
        control_security_headers(),
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

/// A `max_age` of 0 deletes the cookie. Secure is set only for an HTTPS public origin; some
/// browsers do not store a Secure cookie over plain loopback HTTP.
fn session_cookie_header(caller: &Caller, token: &str, max_age: u64) -> String {
    let secure = if caller.proxied.is_some() {
        " Secure;"
    } else {
        ""
    };
    format!(
        "Set-Cookie: {}={token};{secure} HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}\r\n",
        caller.session_cookie()
    )
}

/// Creates the first admin account; open only while there is none, and closed for good after.
/// Signs the new account in so the first screen does not ask again. Two requests interleaving
/// between check and add would create two admins: the control-plane mutation lock guards the
/// config write and `add_first_user` the in-memory add.
fn handle_setup(
    stream: SharedTcp,
    body: &str,
    caller: &Caller,
    st: &AppState,
) -> std::io::Result<()> {
    let peer_s = caller.label();
    let refuse = |stream, status: &str, message: &str| {
        write_simple(
            stream,
            status,
            "application/json",
            "",
            &format!("{{\"ok\":false,\"error\":{}}}", json::escape(message)),
        )
    };

    // Only someone who can edit the config file may create the first account, and anyone on the
    // internet can send through the reverse proxy.
    if caller.proxied.is_some() {
        st.audit
            .record_actor("none", "anonymous", "POST", "/v1/setup", &peer_s, 403);
        return refuse(
            stream,
            "403 Forbidden",
            "Create the first account on the computer running OnetDNS, then sign in here",
        );
    }

    if st.auth.has_users() {
        st.audit
            .record_actor("none", "anonymous", "POST", "/v1/setup", &peer_s, 409);
        return refuse(
            stream,
            "409 Conflict",
            "An account already exists. Sign in, or change the password from the account page",
        );
    }

    let parsed = json::parse(body).ok();
    let field = |key: &str| {
        parsed
            .as_ref()
            .and_then(|value| value.get(key))
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string()
    };
    let name = field("user").trim().to_string();
    let password = field("password");

    // Hashing is expensive, so check the code first.
    if !st.auth.setup_code_matches(&field("code")) {
        st.audit
            .record_actor("none", "anonymous", "POST", "/v1/setup", &peer_s, 403);
        let message = match st.auth.setup_code_file() {
            Some(file) => format!("The setup code does not match. Copy it from {file}"),
            None => "OnetDNS has no setup code to check. Restart OnetDNS; it writes a new code next to its configuration file".to_string(),
        };
        return refuse(stream, "403 Forbidden", &message);
    }

    if name.is_empty() || name.chars().count() > 64 {
        return refuse(
            stream,
            "400 Bad Request",
            "Username must be 1 to 64 characters",
        );
    }
    if name
        .chars()
        .any(|c| c.is_control() || c == '"' || c == '\\' || c == '\'')
    {
        return refuse(
            stream,
            "400 Bad Request",
            "Username cannot contain quotes or control characters",
        );
    }
    let hash = match crate::password::hash_password(&password) {
        Ok(hash) => hash,
        Err(error) => {
            let status = match error {
                crate::password::PasswordError::Busy => "503 Service Unavailable",
                _ => "400 Bad Request",
            };
            return refuse(stream, status, &error.to_string());
        }
    };
    // Lock only the config write; holding it through the slow sign-in KDF would stall every other
    // control-plane change.
    {
        let _guard = control_mutation_lock().lock_recover();
        if st.auth.has_users() {
            return refuse(
                stream,
                "409 Conflict",
                "An account already exists. Sign in, or change the password from the account page",
            );
        }
        if let Err(error) = (st.controls.user_create)(&name, &hash) {
            st.audit
                .record_actor("none", "anonymous", "POST", "/v1/setup", &peer_s, 500);
            return refuse(stream, "500 Internal Server Error", &error);
        }
        // The config write may already have added the account through hot apply, so a false here is
        // not a failure; opening the session below checks the account exists.
        st.auth.add_first_user(name.clone(), hash);
        st.auth.clear_setup_code();
    }

    st.audit.record_actor(
        Role::Admin.as_str(),
        &audit_identity(&name, "authenticated-user"),
        "POST",
        "/v1/setup",
        &peer_s,
        200,
    );
    onetdns_core::warn!(
        event = "console.first_admin_created",
        user = %name,
        peer = %peer_s,
        "Created the first dashboard admin account; this setup path is now closed"
    );

    match st.auth.start_session_for(&name) {
        Some((token, role)) => {
            let cookie = session_cookie_header(caller, &token, SESSION_ABSOLUTE_TTL_MS / 1000);
            let resp = format!(
                "{{\"ok\":true,\"user\":{},\"role\":{}}}",
                json::escape(&name),
                json::escape(role.as_str())
            );
            write_simple(stream, "200 OK", "application/json", &cookie, &resp)
        }
        None => refuse(
            stream,
            "500 Internal Server Error",
            "The account was created but sign-in failed. Sign in again with the new account",
        ),
    }
}

/// Auth status, which decides what the sign-in screen shows.
fn handle_auth(
    stream: SharedTcp,
    auth: &str,
    session: &str,
    caller: &Caller,
    st: &AppState,
) -> std::io::Result<()> {
    let peer_s = caller.label();
    let bearer = auth
        .strip_prefix("Bearer ")
        .filter(|value| !value.is_empty())
        .unwrap_or("");
    if let Some(role) = bearer
        .is_empty()
        .then(|| st.auth.role_for_session(session))
        .flatten()
    {
        let user = st.auth.session_name(session).unwrap_or_default();
        st.audit.record_actor(
            role.as_str(),
            &audit_identity(&user, "authenticated-user"),
            "GET",
            "/v1/auth",
            &peer_s,
            200,
        );
        let body = auth_status_body(st, caller, true, role.as_str(), &user);
        return write_simple(stream, "200 OK", "application/json", "", &body);
    }

    // Control tokens are for the API: a valid token learns its role but gets no session cookie.
    // A cookie would turn a value no one memorizes into a browser credential, and one leaked token
    // would open the whole console.
    if let Some(role) = st.auth.role_for(bearer) {
        let actor = bearer_actor(bearer);
        st.audit
            .record_actor(role.as_str(), &actor, "GET", "/v1/auth", &peer_s, 200);
        let body = auth_status_body(st, caller, true, role.as_str(), &actor);
        return write_simple(stream, "200 OK", "application/json", "", &body);
    }

    // Unauthenticated status checks are not audited; anyone can send them, and they would push
    // real entries out of the fixed-size audit log.
    let body = auth_status_body(st, caller, false, "none", "");
    write_simple(stream, "200 OK", "application/json", "", &body)
}

/// Shared by `handle_auth` and direct `route()` calls so the two cannot drift.
fn auth_status_body(
    st: &AppState,
    caller: &Caller,
    authenticated: bool,
    role: &str,
    user: &str,
) -> String {
    // The path can contain an account name. The first account can only be created on this
    // machine, so proxied requests do not get it.
    let setup_code_file = if st.auth.has_users() || caller.proxied.is_some() {
        None
    } else {
        st.auth.setup_code_file()
    };
    format!(
        "{{\"login_enabled\":{},\"authenticated\":{},\"role\":{},\"user\":{},\"setup_code_file\":{}}}",
        st.auth.has_users(),
        authenticated,
        json::escape(role),
        json::escape(user),
        setup_code_file.map_or_else(|| "null".to_string(), |file| json::escape(&file))
    )
}

/// Failure reasons stay vague; telling a missing user from a wrong password would let callers
/// enumerate account names.
fn handle_login(
    stream: SharedTcp,
    body: &str,
    caller: &Caller,
    st: &AppState,
) -> std::io::Result<()> {
    let peer_s = caller.label();
    let j = json::parse(body).ok();
    let field = |k: &str| {
        j.as_ref()
            .and_then(|v| v.get(k))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let user = field("user");
    let password = field("password");
    let source_key = caller.login_source();
    let proxy_key = caller.login_proxy();
    let attempted_actor = audit_identity(&user, "anonymous");
    if let Some(retry_after) = st
        .auth
        .login_retry_after(&source_key, proxy_key.as_deref(), &user)
    {
        st.audit
            .record_actor("none", &attempted_actor, "POST", "/v1/login", &peer_s, 429);
        return write_simple(
            stream,
            "429 Too Many Requests",
            "application/json",
            &format!("Retry-After: {retry_after}\r\n"),
            "{\"ok\":false,\"error\":\"Too many sign-in attempts. Try again shortly\"}",
        );
    }
    match st.auth.login(&user, &password) {
        LoginResult::Success(token, role, name) => {
            st.auth
                .record_login_result(&source_key, proxy_key.as_deref(), &user, true);
            st.audit.record_actor(
                role.as_str(),
                &audit_identity(&name, "authenticated-user"),
                "POST",
                "/v1/login",
                &peer_s,
                200,
            );
            let cookie = session_cookie_header(caller, &token, SESSION_ABSOLUTE_TTL_MS / 1000);
            let resp = format!(
                "{{\"ok\":true,\"user\":{},\"role\":{}}}",
                json::escape(&name),
                json::escape(role.as_str())
            );
            write_simple(stream, "200 OK", "application/json", &cookie, &resp)
        }
        LoginResult::Invalid => {
            st.auth
                .record_login_result(&source_key, proxy_key.as_deref(), &user, false);
            st.audit
                .record_actor("none", &attempted_actor, "POST", "/v1/login", &peer_s, 401);
            write_simple(
                stream,
                "401 Unauthorized",
                "application/json",
                "",
                "{\"ok\":false,\"error\":\"Incorrect username or password\"}",
            )
        }
        LoginResult::Busy => {
            st.audit
                .record_actor("none", &attempted_actor, "POST", "/v1/login", &peer_s, 503);
            write_simple(
                stream,
                "503 Service Unavailable",
                "application/json",
                "Retry-After: 1\r\n",
                "{\"ok\":false,\"error\":\"Too many password checks. Try again shortly\"}",
            )
        }
    }
}

fn handle_logout(
    stream: SharedTcp,
    sessions: &[String],
    caller: &Caller,
    st: &AppState,
) -> std::io::Result<()> {
    for session in sessions {
        st.auth.logout(session);
    }
    let clear = session_cookie_header(caller, "", 0);
    write_simple(
        stream,
        "200 OK",
        "application/json",
        &clear,
        "{\"ok\":true}",
    )
}

const WEBSOCKET_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_WEBSOCKET_PAYLOAD: usize = 1024 * 1024;

/// Requests the dashboard sends over the WebSocket.
enum DashboardCommand {
    /// Records after this point.
    History(u64),
    Pong(Vec<u8>),
    Close,
}

#[allow(clippy::too_many_arguments)]
/// Pushes metrics and top lists periodically and query events as they come. These connections
/// stay open, so their slots are capped to keep a few tabs from taking the whole control plane.
fn handle_dashboard_websocket(
    mut stream: SharedTcp,
    auth: &str,
    session: &str,
    upgrade: &str,
    connection: &str,
    key: &str,
    version: &str,
    protocols: &str,
    caller: &Caller,
    st: &AppState,
) -> std::io::Result<()> {
    let offered = protocols
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let protocol_ok = offered.contains(&"onetdns.v1");
    let connection_upgrade = connection
        .split(',')
        .map(str::trim)
        .any(|value| value.eq_ignore_ascii_case("upgrade"));
    if !upgrade.eq_ignore_ascii_case("websocket")
        || !connection_upgrade
        || !websocket_key_valid(key)
        || version != "13"
        || !protocol_ok
    {
        return write_simple(
            stream,
            "400 Bad Request",
            "text/plain",
            "Sec-WebSocket-Version: 13\r\n",
            "WebSocket handshake failed",
        );
    }

    if offered.iter().any(|value| value.starts_with("bearer64.")) {
        return write_simple(
            stream,
            "400 Bad Request",
            "text/plain",
            "",
            "WebSocket subprotocol cannot carry credentials",
        );
    }
    let token = auth
        .strip_prefix("Bearer ")
        .filter(|value| !value.is_empty())
        .unwrap_or("");
    let resume = offered
        .iter()
        .find_map(|value| value.strip_prefix("resume."))
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0);
    let peer_s = caller.label();
    let Some(role) = st.auth.resolve(token, session) else {
        st.audit.record_actor(
            "none",
            &audit_actor(&st.auth, token, session),
            "GET",
            "/v1/dashboard/ws",
            &peer_s,
            401,
        );
        return write_simple(
            stream,
            "401 Unauthorized",
            "text/plain",
            "",
            "Authentication required",
        );
    };
    let actor = audit_actor(&st.auth, token, session);
    let Some(_stream_slot) = acquire_stream_slot() else {
        st.audit.record_actor(
            role.as_str(),
            &actor,
            "GET",
            "/v1/dashboard/ws",
            &peer_s,
            503,
        );
        record_control_error("stream_limit", caller.peer, "Too many live log connections");
        return write_simple(
            stream,
            "503 Service Unavailable",
            "text/plain",
            "Retry-After: 1\r\n",
            "Too many live log connections. Try again shortly",
        );
    };

    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WEBSOCKET_GUID);
    let accept = base64_standard(&hasher.finalize());
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: onetdns.v1\r\n\r\n"
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    st.audit.record_actor(
        role.as_str(),
        &actor,
        "GET",
        "/v1/dashboard/ws",
        &peer_s,
        101,
    );

    let subscription = st.stats.subscribe_after(resume);
    let hello = format!(
        "{{\"type\":\"hello\",\"replay_gap\":{}}}",
        if subscription.replay_gap {
            "true"
        } else {
            "false"
        }
    );
    ws_write_text(&mut stream, &hello)?;
    for event in subscription.replay {
        ws_write_text(
            &mut stream,
            &format!(
                "{{\"type\":\"query\",\"replay\":true,\"event\":{}}}",
                event_json(&event)
            ),
        )?;
    }
    ws_write_text(&mut stream, &dashboard_snapshot_json(st))?;
    ws_write_text(&mut stream, &dashboard_top_json(st))?;
    ws_write_text(&mut stream, &dashboard_jobs_json(st))?;

    let reader = DashboardReader::spawn(&stream)?;

    let mut history_range = 60u64;
    let now = std::time::Instant::now();
    let mut next_snapshot = now + std::time::Duration::from_secs(1);
    let mut next_top = now + std::time::Duration::from_secs(5);
    let mut next_jobs = now + std::time::Duration::from_secs(2);
    let mut next_history = now;
    let receiver = subscription.receiver;
    let mut closed = false;
    let mut auth_expired = false;
    while !closed {
        while let Ok(command) = reader.commands().try_recv() {
            match command {
                DashboardCommand::History(range) => {
                    history_range = range;
                    next_history = std::time::Instant::now();
                }
                DashboardCommand::Pong(payload) => ws_write_frame(&mut stream, 0xA, &payload)?,
                DashboardCommand::Close => closed = true,
            }
        }
        if closed {
            break;
        }
        if st.auth.resolve(token, session).is_none() {
            auth_expired = true;
            break;
        }

        let now = std::time::Instant::now();
        if now >= next_snapshot {
            ws_write_text(&mut stream, &dashboard_snapshot_json(st))?;
            next_snapshot = now + std::time::Duration::from_secs(1);
        }
        if now >= next_top {
            ws_write_text(&mut stream, &dashboard_top_json(st))?;
            next_top = now + std::time::Duration::from_secs(5);
        }
        if now >= next_jobs {
            ws_write_text(&mut stream, &dashboard_jobs_json(st))?;
            next_jobs = now + std::time::Duration::from_secs(2);
        }
        if history_range > 300 && now >= next_history {
            let history = stats_history_json(st, history_range);
            ws_write_text(
                &mut stream,
                &format!("{{\"type\":\"history\",\"data\":{history}}}"),
            )?;
            next_history = now + std::time::Duration::from_secs(5);
        }

        match receiver.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(event) => ws_write_text(
                &mut stream,
                &format!("{{\"type\":\"query\",\"event\":{}}}", event_json(&event)),
            )?,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let close_payload = if auth_expired { 1008u16 } else { 1000u16 }.to_be_bytes();
    let _ = ws_write_frame(&mut stream, 0x8, &close_payload);
    Ok(())
}

/// The thread reading browser frames on the dashboard WebSocket, and its cleanup. The thread
/// shares the socket and does not end while it is open, so every drop path signals stop, shuts
/// the socket down, drops the command receiver and joins, in that order; a handler leaving early
/// on a write error leaves no thread or socket behind. The receiver must go before the join: a
/// reader blocked sending Close into a full channel keeps the join waiting while it lives.
struct DashboardReader {
    stop: Arc<std::sync::atomic::AtomicBool>,
    stream: SharedTcp,
    commands: Option<std::sync::mpsc::Receiver<DashboardCommand>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl DashboardReader {
    /// On failure, leaves no thread or socket clone behind.
    fn spawn(stream: &SharedTcp) -> std::io::Result<Self> {
        let mut read_stream = stream.clone();
        read_stream.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_t = stop.clone();
        let (command_tx, commands) = std::sync::mpsc::sync_channel::<DashboardCommand>(64);
        let thread = std::thread::Builder::new()
            .name("onetdns-dashboard-ws-read".to_string())
            .stack_size(CONTROL_CONNECTION_STACK_BYTES)
            .spawn(move || loop {
                if stop_t.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                match ws_read_frame(&mut read_stream) {
                    Ok((0x1, payload)) => {
                        let Ok(text) = String::from_utf8(payload) else {
                            continue;
                        };
                        let Some(value) = json::parse(&text).ok() else {
                            continue;
                        };
                        if value.get("type").and_then(|value| value.as_str()) == Some("history") {
                            let range = value
                                .get("range")
                                .and_then(|value| value.as_u64())
                                .unwrap_or(60)
                                .clamp(60, 604_800);
                            let _ = command_tx.try_send(DashboardCommand::History(range));
                        }
                    }
                    Ok((0x8, _)) => {
                        let _ = command_tx.send(DashboardCommand::Close);
                        break;
                    }
                    Ok((0x9, payload)) => {
                        let _ = command_tx.try_send(DashboardCommand::Pong(payload));
                    }
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(_) => {
                        let _ = command_tx.send(DashboardCommand::Close);
                        break;
                    }
                }
            })?;
        Ok(Self {
            stop,
            stream: stream.clone(),
            commands: Some(commands),
            thread: Some(thread),
        })
    }

    fn commands(&self) -> &std::sync::mpsc::Receiver<DashboardCommand> {
        self.commands
            .as_ref()
            .expect("commands are released only in drop")
    }
}

impl Drop for DashboardReader {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        drop(self.commands.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn dashboard_snapshot_json(st: &AppState) -> String {
    format!(
        "{{\"type\":\"snapshot\",\"data\":{}}}",
        metrics_only_json(st)
    )
}

fn dashboard_top_json(st: &AppState) -> String {
    format!("{{\"type\":\"top\",\"data\":{}}}", top_json(st))
}

fn dashboard_jobs_json(st: &AppState) -> String {
    format!(
        "{{\"type\":\"jobs\",\"data\":{}}}",
        (st.controls.jobs_list)()
    )
}

/// Client frames must be masked; unmasked ones can be used to poison intermediaries.
fn ws_read_frame(stream: &mut SharedTcp) -> std::io::Result<(u8, Vec<u8>)> {
    let invalid =
        |message: &'static str| std::io::Error::new(std::io::ErrorKind::InvalidData, message);
    let mut header = [0u8; 2];
    stream.read_exact(&mut header)?;
    let fin = header[0] & 0x80 != 0;
    let rsv = header[0] & 0x70;
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    if !fin {
        return Err(invalid("Fragmented WebSocket messages are not supported"));
    }
    if rsv != 0 {
        return Err(invalid("Invalid WebSocket RSV bits"));
    }
    if !matches!(opcode, 0x1 | 0x8 | 0x9 | 0xA) {
        return Err(invalid("Unsupported WebSocket message type"));
    }
    if !masked {
        return Err(invalid("Rejected unmasked WebSocket frame"));
    }

    let length_code = header[1] & 0x7f;
    let mut length = length_code as u64;
    if length_code == 126 {
        let mut extended = [0u8; 2];
        stream.read_exact(&mut extended)?;
        length = u16::from_be_bytes(extended) as u64;
        if length < 126 {
            return Err(invalid("WebSocket frame length is not minimally encoded"));
        }
    } else if length_code == 127 {
        let mut extended = [0u8; 8];
        stream.read_exact(&mut extended)?;
        if extended[0] & 0x80 != 0 {
            return Err(invalid("Invalid WebSocket message length"));
        }
        length = u64::from_be_bytes(extended);
        if length <= u16::MAX as u64 {
            return Err(invalid("WebSocket frame length is not minimally encoded"));
        }
    }
    let control = matches!(opcode, 0x8..=0xA);
    if control && length > 125 {
        return Err(invalid("WebSocket control frame is too large"));
    }
    if length > MAX_WEBSOCKET_PAYLOAD as u64 {
        return Err(invalid("WebSocket frame is too large"));
    }

    let mut mask = [0u8; 4];
    stream.read_exact(&mut mask)?;
    let mut payload = vec![0u8; length as usize];
    stream.read_exact(&mut payload)?;
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    if opcode == 0x8 {
        if payload.len() == 1 {
            return Err(invalid("Invalid WebSocket close body"));
        }
        if payload.len() >= 2 {
            let code = u16::from_be_bytes([payload[0], payload[1]]);
            let valid_code = matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999);
            if !valid_code {
                return Err(invalid("Invalid WebSocket close code"));
            }
            if std::str::from_utf8(&payload[2..]).is_err() {
                return Err(invalid("WebSocket close reason is not valid UTF-8"));
            }
        }
    }
    if opcode == 0x1 && std::str::from_utf8(&payload).is_err() {
        return Err(invalid("WebSocket text message is not valid UTF-8"));
    }
    Ok((opcode, payload))
}

fn ws_write_text(stream: &mut SharedTcp, text: &str) -> std::io::Result<()> {
    ws_write_frame(stream, 0x1, text.as_bytes())
}

/// Server frames are not masked.
fn ws_write_frame(stream: &mut SharedTcp, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut header = Vec::with_capacity(10);
    header.push(0x80 | (opcode & 0x0f));
    match payload.len() {
        length @ 0..=125 => header.push(length as u8),
        length @ 126..=65_535 => {
            header.push(126);
            header.extend_from_slice(&(length as u16).to_be_bytes());
        }
        length => {
            header.push(127);
            header.extend_from_slice(&(length as u64).to_be_bytes());
        }
    }
    stream.write_all(&header)?;
    stream.write_all(payload)?;
    stream.flush()
}

/// Sec-WebSocket-Key must be 16 bytes in standard base64: 24 characters ending in `==`, with
/// the low 4 bits of the last data character zero. Without this check any string completes the
/// handshake.
fn websocket_key_valid(key: &str) -> bool {
    fn sextet(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = key.as_bytes();
    bytes.len() == 24
        && bytes.ends_with(b"==")
        && bytes[..22].iter().all(|&byte| sextet(byte).is_some())
        && sextet(bytes[21]).is_some_and(|last| last & 0x0f == 0)
}

/// For the WebSocket handshake response.
fn base64_standard(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        output.push(TABLE[(a >> 2) as usize] as char);
        output.push(TABLE[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[(((b & 0x0f) << 2) | (c >> 6)) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(TABLE[(c & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }
    output
}

#[cfg(test)]
/// Decodes the token carried in the WebSocket subprotocol.
fn base64_url_decode(value: &str) -> Option<Vec<u8>> {
    fn sextet(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let mut output = Vec::with_capacity(value.len() * 3 / 4);
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let remaining = bytes.len() - index;
        if remaining == 1 {
            return None;
        }
        let a = sextet(bytes[index])?;
        let b = sextet(bytes[index + 1])?;
        output.push((a << 2) | (b >> 4));
        if remaining > 2 {
            let c = sextet(bytes[index + 2])?;
            output.push((b << 4) | (c >> 2));
            if remaining > 3 {
                let d = sextet(bytes[index + 3])?;
                output.push((c << 6) | d);
            }
        }
        index += remaining.min(4);
    }
    Some(output)
}

fn event_json(e: &QueryEvent) -> String {
    e.to_json()
}

/// Static assets and health first, then authentication and the read-only filter, then the
/// final match maps each path to its callback. A new path must also go into the OpenAPI
/// document; a test enforces they match.
fn route(
    method: &str,
    path: &str,
    auth: &str,
    session: &str,
    body: &str,
    caller: &Caller,
    st: &AppState,
) -> (&'static str, &'static str, String) {
    let peer_s = caller.label();

    if method == "GET" {
        if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
            return match acme_http01().lock_recover().get(token) {
                Some(v) => ("200 OK", "text/plain", v.clone()),
                None => (
                    "404 Not Found",
                    "text/plain",
                    "Requested path not found".to_string(),
                ),
            };
        }
    }

    match (method, path) {
        ("GET", "/") => {
            #[cfg(feature = "dashboard")]
            let page = (
                "200 OK",
                "text/html; charset=utf-8",
                include_str!("../dashboard/index.html").to_string(),
            );
            #[cfg(not(feature = "dashboard"))]
            let page = (
                "200 OK",
                "text/plain",
                "OnetDNS management API is running. The web dashboard is disabled.".to_string(),
            );
            return page;
        }

        ("GET", "/support.js") => {
            #[cfg(feature = "dashboard")]
            return (
                "200 OK",
                "application/javascript; charset=utf-8",
                include_str!("../dashboard/support.js").to_string(),
            );
            #[cfg(not(feature = "dashboard"))]
            return (
                "404 Not Found",
                "text/plain",
                "Requested path not found".to_string(),
            );
        }

        ("GET", "/react.js") => {
            #[cfg(feature = "dashboard")]
            return (
                "200 OK",
                "application/javascript; charset=utf-8",
                include_str!("../dashboard/react.js").to_string(),
            );
            #[cfg(not(feature = "dashboard"))]
            return (
                "404 Not Found",
                "text/plain",
                "Requested path not found".to_string(),
            );
        }
        ("GET", "/react-dom.js") => {
            #[cfg(feature = "dashboard")]
            return (
                "200 OK",
                "application/javascript; charset=utf-8",
                include_str!("../dashboard/react-dom.js").to_string(),
            );
            #[cfg(not(feature = "dashboard"))]
            return (
                "404 Not Found",
                "text/plain",
                "Requested path not found".to_string(),
            );
        }
        // Linking the icon alone still leaves browsers, bookmarks and checkers requesting this
        // path, and blocking it before authentication fills the audit log with 401s that look like
        // break-in attempts.
        ("GET", "/favicon.ico") => {
            #[cfg(feature = "dashboard")]
            return ("200 OK", "image/svg+xml", FAVICON_SVG.to_string());
            #[cfg(not(feature = "dashboard"))]
            return (
                "404 Not Found",
                "text/plain",
                "Requested path not found".to_string(),
            );
        }

        ("GET", "/healthz") => return ("200 OK", "text/plain", "ok".to_string()),

        ("GET", "/readyz") => {
            return if st.readiness.load(std::sync::atomic::Ordering::Acquire) {
                ("200 OK", "text/plain", "ready".to_string())
            } else {
                (
                    "503 Service Unavailable",
                    "text/plain",
                    "not ready".to_string(),
                )
            }
        }
        ("GET", "/openapi.json") => return ("200 OK", "application/json", openapi_json()),

        ("GET", "/v1/auth") => {
            let token = auth.strip_prefix("Bearer ").unwrap_or("");
            let body = match st.auth.resolve(token, session) {
                Some(r) => {
                    let user = st
                        .auth
                        .session_name(session)
                        .unwrap_or_else(|| bearer_actor(token));
                    auth_status_body(st, caller, true, r.as_str(), &user)
                }
                None => auth_status_body(st, caller, false, "none", ""),
            };
            return ("200 OK", "application/json", body);
        }
        _ => {}
    }

    let token = auth.strip_prefix("Bearer ").unwrap_or("");
    let role = match st.auth.resolve(token, session) {
        Some(r) => r,
        None => {
            st.audit.record_actor(
                "none",
                &audit_actor(&st.auth, token, session),
                method,
                path,
                &peer_s,
                401,
            );
            return (
                "401 Unauthorized",
                "text/plain",
                "Authentication required".to_string(),
            );
        }
    };
    let actor = audit_actor(&st.auth, token, session);

    if !role.allows(method, path) {
        st.audit
            .record_actor(role.as_str(), &actor, method, path, &peer_s, 403);
        return (
            "403 Forbidden",
            "text/plain",
            "Read-only access cannot perform this action".to_string(),
        );
    }

    let state_changing = is_state_changing_request(method, path);

    if state_changing && !st.readiness.load(std::sync::atomic::Ordering::Acquire) {
        st.audit
            .record_actor(role.as_str(), &actor, method, path, &peer_s, 503);
        return (
            "503 Service Unavailable",
            "text/plain",
            "DNS service settings are being applied. Try again when they are ready".to_string(),
        );
    }

    let _mutation_guard = requires_control_mutation_lock(method, path)
        .then(|| control_mutation_lock().lock_recover());

    let mut dispatch = || route_dispatch(method, path, session, body, st);
    let out = if requires_control_mutation_lock(method, path) {
        (st.controls.cluster_write)(method, path, body, &mut dispatch)
    } else {
        dispatch()
    };

    let code = status_code(out.0);
    if method != "GET" || code >= 400 {
        st.audit.record_request_actor(
            AuditContext {
                role: role.as_str(),
                actor: &actor,
                method,
                path,
                peer: &peer_s,
                status: code,
            },
            body,
        );
    }
    out
}

/// Handles a request already authenticated and authorized. The caller writes the audit record,
/// since cluster consensus can turn the result into a failure and the record must show the
/// final response.
fn route_dispatch(
    method: &str,
    path: &str,
    session: &str,
    body: &str,
    st: &AppState,
) -> ApiResponse {
    if let Some(rest) = path.strip_prefix("/v1/zones/").filter(|o| !o.is_empty()) {
        if let Some(origin) = rest.strip_suffix("/dnssec").filter(|o| !o.is_empty()) {
            let out: (&'static str, &'static str, String) = match method {
                "GET" => match (st.controls.zone_dnssec)(origin) {
                    Ok(j) => ("200 OK", "application/json", j),
                    Err(e) => (
                        "404 Not Found",
                        "application/json",
                        format!("{{\"error\":\"{}\"}}", jesc(&e)),
                    ),
                },
                _ => (
                    "405 Method Not Allowed",
                    "text/plain",
                    "Method not allowed on this path".to_string(),
                ),
            };
            return out;
        }
        if let Some(origin) = rest.strip_suffix("/records").filter(|o| !o.is_empty()) {
            let out: (&'static str, &'static str, String) = match method {
                "POST" => match (st.controls.zone_record_add)(origin, body) {
                    Ok(j) => ("200 OK", "application/json", j),
                    Err(e) => (
                        "400 Bad Request",
                        "application/json",
                        format!("{{\"error\":\"{}\"}}", jesc(&e)),
                    ),
                },
                "DELETE" => match (st.controls.zone_record_delete)(origin, body) {
                    Ok(j) => ("200 OK", "application/json", j),
                    Err(e) => (
                        "404 Not Found",
                        "application/json",
                        format!("{{\"error\":\"{}\"}}", jesc(&e)),
                    ),
                },
                _ => (
                    "405 Method Not Allowed",
                    "text/plain",
                    "Method not allowed on this path".to_string(),
                ),
            };
            return out;
        }
        let origin = rest;
        let out: (&'static str, &'static str, String) = match method {
            "GET" => match (st.controls.zone_get)(origin) {
                Ok(j) => ("200 OK", "application/json", j),
                Err(e) => (
                    "404 Not Found",
                    "application/json",
                    format!("{{\"error\":\"{}\"}}", jesc(&e)),
                ),
            },
            "PUT" => match (st.controls.zone_put)(origin, body) {
                Ok(j) => ("200 OK", "application/json", j),
                Err(e) => (
                    "400 Bad Request",
                    "application/json",
                    format!("{{\"error\":\"{}\"}}", jesc(&e)),
                ),
            },
            "DELETE" => match (st.controls.zone_delete)(origin) {
                Ok(j) => ("200 OK", "application/json", j),
                Err(e) => (
                    "404 Not Found",
                    "application/json",
                    format!("{{\"error\":\"{}\"}}", jesc(&e)),
                ),
            },
            _ => (
                "405 Method Not Allowed",
                "text/plain",
                "Method not allowed on this path".to_string(),
            ),
        };
        return out;
    }

    if method == "GET" {
        if let Some(range) = path.strip_prefix("/v1/stats/history/") {
            let out: (&'static str, &'static str, String) = match range.parse::<u64>() {
                Ok(value) if matches!(value, 60 | 300 | 3_600 | 86_400 | 604_800) => {
                    ("200 OK", "application/json", stats_history_json(st, value))
                }
                _ => (
                    "400 Bad Request",
                    "application/json",
                    "{\"error\":\"Unsupported stats range\"}".to_string(),
                ),
            };
            return out;
        }
    }

    if let Some(id_s) = path
        .strip_prefix("/v1/jobs/")
        .filter(|s| !s.is_empty() && *s != "refresh")
    {
        if method == "GET" {
            let out: (&'static str, &'static str, String) = match id_s.parse::<u64>() {
                Ok(id) => match (st.controls.job_get)(id) {
                    Ok(j) => ("200 OK", "application/json", j),
                    Err(e) => (
                        "404 Not Found",
                        "application/json",
                        format!("{{\"error\":\"{}\"}}", jesc(&e)),
                    ),
                },
                Err(_) => (
                    "400 Bad Request",
                    "application/json",
                    "{\"error\":\"Invalid job ID\"}".to_string(),
                ),
            };
            return out;
        }
    }

    match (method, path) {
        ("GET", "/v1/stats") => ("200 OK", "application/json", stats_json(st)),
        ("GET", "/v1/metrics") => ("200 OK", "application/json", metrics_only_json(st)),
        ("GET", "/v1/queries") => ("200 OK", "application/json", recent_json(st)),
        ("GET", "/v1/top") => ("200 OK", "application/json", top_json(st)),
        ("GET", "/v1/audit") => ("200 OK", "application/json", st.audit.json()),
        ("GET", "/v1/backup") => ("200 OK", "application/json", (st.controls.export)()),
        ("GET", "/metrics") => ("200 OK", "text/plain; version=0.0.4", metrics_text(st)),
        ("POST", "/v1/reload") => counts_resp((st.controls.reload)()),
        ("POST", "/v1/block") => counts_resp((st.controls.block_add)(&body_str(body, "domain"))),
        ("POST", "/v1/allow") => counts_resp((st.controls.allow_add)(&body_str(body, "domain"))),
        ("POST", "/v1/restore") => counts_resp((st.controls.import)(body)),
        ("POST", "/v1/services") => {
            let svc = body_str(body, "service");
            let en = body_bool(body, "enable");
            counts_resp((st.controls.service_set)(&svc, en))
        }
        ("POST", "/v1/safesearch") => {
            let en = body_bool(body, "enable");
            match (st.controls.safesearch_set)(en) {
                Ok(()) => (
                    "200 OK",
                    "application/json",
                    format!("{{\"safe_search\":{en}}}"),
                ),
                Err(e) => (
                    "400 Bad Request",
                    "application/json",
                    format!("{{\"error\":{}}}", json::escape(&e)),
                ),
            }
        }
        ("POST", "/v1/password") => {
            let Some(name) = st.auth.session_name(session) else {
                return (
                    "400 Bad Request",
                    "application/json",
                    "{\"error\":\"Sign in with a user account to change the password\"}"
                        .to_string(),
                );
            };
            let current = body_str(body, "current_password");
            let next = body_str(body, "new_password");

            if let Err(error) = crate::password::check_new_password(&next) {
                return (
                    "400 Bad Request",
                    "application/json",
                    format!("{{\"error\":{}}}", json::escape(&error.to_string())),
                );
            }
            match st.auth.verify_user(&name, &current) {
                crate::password::VerifyResult::Match => {}
                crate::password::VerifyResult::Mismatch => {
                    return (
                        "403 Forbidden",
                        "application/json",
                        "{\"error\":\"Current password is incorrect\"}".to_string(),
                    );
                }
                crate::password::VerifyResult::Busy => {
                    return (
                        "503 Service Unavailable",
                        "application/json",
                        "{\"error\":\"Too many password checks. Try again shortly\"}".to_string(),
                    );
                }
            }
            let hash = match crate::password::hash_password(&next) {
                Ok(hash) => hash,
                Err(error) => {
                    let status = match error {
                        crate::password::PasswordError::Busy => "503 Service Unavailable",
                        _ => "400 Bad Request",
                    };
                    return (
                        status,
                        "application/json",
                        format!("{{\"error\":{}}}", json::escape(&error.to_string())),
                    );
                }
            };
            match (st.controls.password_change)(&name, &hash) {
                Ok(j) => {
                    if !st.auth.update_user_hash(&name, hash) {
                        return (
                            "409 Conflict",
                            "application/json",
                            "{\"error\":\"The user account was deleted while changing the password\"}"
                                .to_string(),
                        );
                    }
                    st.auth.revoke_user_sessions(&name);
                    ("200 OK", "application/json", j)
                }
                Err(e) => (
                    "400 Bad Request",
                    "application/json",
                    format!("{{\"error\":{}}}", json::escape(&e)),
                ),
            }
        }
        ("POST", "/v1/querylog/clear") => match st.stats.clear_recent() {
            Ok(()) => (
                "200 OK",
                "application/json",
                "{\"cleared\":true}".to_string(),
            ),
            Err(e) => (
                "500 Internal Server Error",
                "application/json",
                format!(
                    "{{\"cleared\":false,\"error\":{}}}",
                    json::escape(&e.to_string())
                ),
            ),
        },

        ("POST", "/v1/config/validate") => match (st.controls.config_validate)(body) {
            Ok(()) => ("200 OK", "application/json", "{\"valid\":true}".to_string()),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                format!("{{\"valid\":false,\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("POST", "/v1/config/diff") => match (st.controls.config_diff)(body) {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("POST", "/v1/config/apply") => match (st.controls.config_apply)(body) {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("POST", "/v1/config/set") => match (st.controls.config_set)(body) {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("POST", "/v1/config/set/diff") => match (st.controls.config_set_diff)(body) {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("GET", "/v1/config/schema") => {
            ("200 OK", "application/json", (st.controls.config_schema)())
        }
        ("POST", "/v1/upstreams/test") => match (st.controls.upstream_test)(body) {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("POST", "/v1/cache/flush") => ("200 OK", "application/json", (st.controls.cache_flush)()),
        ("GET", "/v1/tokens") => ("200 OK", "application/json", (st.controls.tokens_list)()),
        ("POST", "/v1/tokens") => match (st.controls.token_add)(body) {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("DELETE", "/v1/tokens") => match (st.controls.token_delete)(body) {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "404 Not Found",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("GET", "/v1/rewrites") => ("200 OK", "application/json", (st.controls.rewrites_list)()),
        ("POST", "/v1/rewrites") => match (st.controls.rewrite_add)(body) {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("DELETE", "/v1/rewrites") => match (st.controls.rewrite_delete)(body) {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "404 Not Found",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("GET", "/v1/services") => (
            "200 OK",
            "application/json",
            (st.controls.services_catalog)(),
        ),
        ("GET", "/v1/access") => ("200 OK", "application/json", (st.controls.access_list)()),
        ("GET", "/v1/tls") => ("200 OK", "application/json", (st.controls.tls_status)()),
        ("POST", "/v1/tls/validate") => match (st.controls.tls_validate)() {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("POST", "/v1/tls/configure") => result_resp((st.controls.tls_configure)(body)),
        ("POST", "/v1/tls/revocation-check") => {
            result_resp((st.controls.tls_revocation_check)(body))
        }
        ("POST", "/v1/acme/issue") => result_resp((st.controls.acme_issue)(body)),
        ("POST", "/v1/config/rollback") => conflict_resp((st.controls.config_rollback)()),
        ("POST", "/v1/policies/simulate") => (
            "200 OK",
            "application/json",
            (st.controls.policy_simulate)(body),
        ),

        ("POST", "/v1/explain") => ("200 OK", "application/json", (st.controls.explain)(body)),
        ("POST", "/v1/resolve") => result_resp((st.controls.resolve_probe)(body)),
        ("GET", "/v1/cluster/nodes") => {
            ("200 OK", "application/json", (st.controls.cluster_status)())
        }
        ("POST", "/v1/cluster/propose") => result_resp((st.controls.cluster_propose)(body)),

        ("GET", "/v1/listeners") => (
            "200 OK",
            "application/json",
            (st.controls.listeners_status)(),
        ),
        ("GET", "/v1/system/network-adapters") => result_resp((st.controls.net_adapters)()),
        ("POST", "/v1/system/firewall") => result_resp((st.controls.firewall_set)(body)),
        ("GET", "/v1/system/service") => (
            "200 OK",
            "application/json",
            (st.controls.boot_service_status)(),
        ),
        ("POST", "/v1/system/service") => result_resp((st.controls.boot_service_set)(body)),
        ("POST", "/v1/system/dns-client") => result_resp((st.controls.dns_client_set)(body)),
        ("POST", "/v1/system/dns-client/restore") => {
            result_resp((st.controls.dns_client_restore)(body))
        }
        ("GET", "/v1/system/update") => {
            ("200 OK", "application/json", (st.controls.update_status)())
        }
        ("POST", "/v1/system/update/check") => conflict_resp((st.controls.update_check)()),
        ("POST", "/v1/system/update/apply") => match update_version(body) {
            Ok(version) => conflict_resp((st.controls.update_apply)(&version)),
            Err(error) => result_resp(Err(error)),
        },
        ("POST", "/v1/system/update/rollback") => conflict_resp((st.controls.update_rollback)()),
        ("GET", "/v1/zones") => ("200 OK", "application/json", (st.controls.zones_list)()),
        ("GET", "/v1/config") => ("200 OK", "application/json", (st.controls.config_desired)()),
        ("GET", "/v1/config/effective") => (
            "200 OK",
            "application/json",
            (st.controls.config_effective)(),
        ),
        ("GET", "/v1/config/status") => {
            ("200 OK", "application/json", (st.controls.config_status)())
        }
        ("POST", "/v1/config/reload") => result_resp((st.controls.config_reload)()),
        ("GET", "/v1/plugins") => (
            "200 OK",
            "application/json",
            (st.controls.plugins_metrics)(),
        ),
        ("GET", "/v1/filter/report") => {
            ("200 OK", "application/json", (st.controls.filter_report)())
        }
        ("GET", "/v1/filter/top-rules") => (
            "200 OK",
            "application/json",
            (st.controls.filter_top_rules)(),
        ),
        ("GET", "/v1/filter/sources") => {
            ("200 OK", "application/json", (st.controls.filter_sources)())
        }

        ("GET", "/v1/filter/subscriptions") => (
            "200 OK",
            "application/json",
            (st.controls.subscriptions_list)(),
        ),
        ("POST", "/v1/filter/subscriptions") => match (st.controls.subscription_add)(body) {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("DELETE", "/v1/filter/subscriptions") => {
            match (st.controls.subscription_remove)(&body_str(body, "url")) {
                Ok(j) => ("200 OK", "application/json", j),
                Err(e) => (
                    "404 Not Found",
                    "application/json",
                    format!("{{\"error\":\"{}\"}}", jesc(&e)),
                ),
            }
        }
        ("PATCH", "/v1/filter/subscriptions") => {
            result_resp((st.controls.subscription_update)(body))
        }
        ("POST", "/v1/filter/subscriptions/refresh") => {
            result_resp((st.controls.subscription_refresh)(body))
        }
        ("GET", "/v1/filter/rules") => (
            "200 OK",
            "application/json",
            (st.controls.filter_rules_list)(),
        ),
        ("POST", "/v1/filter/rules") => result_resp((st.controls.filter_rule_mutate)(body, true)),
        ("DELETE", "/v1/filter/rules") => {
            result_resp((st.controls.filter_rule_mutate)(body, false))
        }
        ("GET", "/v1/clients") => ("200 OK", "application/json", (st.controls.clients_list)()),

        ("POST", "/v1/clients") => result_resp((st.controls.client_add)(body)),
        ("DELETE", "/v1/clients") => {
            result_resp((st.controls.client_remove)(&body_str(body, "name")))
        }
        ("PATCH", "/v1/clients") => result_resp((st.controls.client_update)(body)),
        ("GET", "/v1/upstreams") => ("200 OK", "application/json", (st.controls.upstreams_list)()),

        ("POST", "/v1/upstreams") => match upstream_field(body) {
            Ok(addr) => result_resp((st.controls.upstream_add)(&addr)),
            Err(error) => result_resp(Err(error)),
        },
        ("DELETE", "/v1/upstreams") => match upstream_field(body) {
            Ok(addr) => result_resp((st.controls.upstream_remove)(&addr)),
            Err(error) => result_resp(Err(error)),
        },
        ("GET", "/v1/jobs") => ("200 OK", "application/json", (st.controls.jobs_list)()),
        ("POST", "/v1/jobs/refresh") => ("200 OK", "application/json", (st.controls.job_refresh)()),
        ("GET", "/v1/dhcp/leases") => ("200 OK", "application/json", (st.controls.dhcp_leases)()),
        ("POST", "/v1/dhcp/leases") => result_resp((st.controls.dhcp_lease_put)(body)),
        ("GET", "/v1/dhcp/static") => (
            "200 OK",
            "application/json",
            (st.controls.dhcp_static_list)(),
        ),
        ("POST", "/v1/dhcp/static") => result_resp((st.controls.dhcp_static_add)(body)),
        ("DELETE", "/v1/dhcp/static") => {
            match (st.controls.dhcp_static_remove)(&body_str(body, "identity")) {
                Ok(j) => ("200 OK", "application/json", j),
                Err(e) => (
                    "404 Not Found",
                    "application/json",
                    format!("{{\"error\":\"{}\"}}", jesc(&e)),
                ),
            }
        }
        _ => (
            "404 Not Found",
            "text/plain",
            "Requested path not found".to_string(),
        ),
    }
}

fn jesc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn status_code(s: &str) -> u16 {
    s.split(|c: char| !c.is_ascii_digit())
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

fn counts_resp(r: Result<ListCounts, String>) -> (&'static str, &'static str, String) {
    match r {
        Ok(c) => (
            "200 OK",
            "application/json",
            format!("{{\"block\":{},\"allow\":{}}}", c.block, c.allow),
        ),
        Err(e) => ("400 Bad Request", "text/plain", e),
    }
}

fn result_resp(r: Result<String, String>) -> (&'static str, &'static str, String) {
    match r {
        Ok(j) => ("200 OK", "application/json", j),
        Err(e) => (
            "400 Bad Request",
            "application/json",
            format!("{{\"error\":\"{}\"}}", jesc(&e)),
        ),
    }
}

/// For a valid request the current state cannot carry out; failures are 409.
fn conflict_resp(r: Result<String, String>) -> ApiResponse {
    match r {
        Ok(j) => ("200 OK", "application/json", j),
        Err(e) => (
            "409 Conflict",
            "application/json",
            format!("{{\"error\":\"{}\"}}", jesc(&e)),
        ),
    }
}

/// The version the operator confirmed, from an update apply request.
fn update_version(body: &str) -> Result<String, String> {
    json::parse(body)
        .ok()
        .and_then(|json| {
            json.get("version")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .map(String::from)
        })
        .filter(|version| !version.is_empty())
        .ok_or_else(|| {
            "The request body must be an object with the version shown by the last check"
                .to_string()
        })
}

/// Reads and validates the upstream address in the body.
fn upstream_field(body: &str) -> Result<String, String> {
    let json =
        json::parse(body).map_err(|error| format!("Could not parse JSON request body: {error}"))?;
    let json::Json::Obj(fields) = json else {
        return Err("Upstream DNS request must be an object with a single addr string".into());
    };
    if fields.len() != 1 || fields[0].0 != "addr" {
        return Err("Upstream DNS request must contain only an addr string".into());
    }
    fields[0]
        .1
        .as_str()
        .map(str::trim)
        .filter(|addr| !addr.is_empty())
        .map(String::from)
        .ok_or_else(|| "addr must be a non-empty string".into())
}

fn body_str(body: &str, key: &str) -> String {
    json::parse(body)
        .ok()
        .and_then(|j| j.get(key).and_then(|v| v.as_str().map(String::from)))
        .unwrap_or_default()
}

fn body_bool(body: &str, key: &str) -> bool {
    json::parse(body)
        .ok()
        .and_then(|j| j.get(key).and_then(|v| v.as_bool()))
        .unwrap_or(false)
}

fn metrics_obj(m: &MetricsSnapshot) -> String {
    let by_t: Vec<String> = m
        .by_transport
        .iter()
        .map(|(t, c)| format!("{}:{}", json::escape(t), c))
        .collect();
    format!(
        "{{\"total\":{},\"resolved\":{},\"blocked\":{},\"rewritten\":{},\"denied\":{},\"refused\":{},\"throttled\":{},\"servfail\":{},\"by_transport\":{{{}}},\"avg_latency_ms\":{:.1},\"cache_hit_pct\":{:.1},\"dropped_log_events\":{},\"dropped_stat_events\":{},\"dropped_stream_events\":{},\"persist_failures\":{}}}",
        m.total, m.resolved, m.blocked, m.rewritten, m.denied, m.refused, m.throttled, m.servfail, by_t.join(","),
        m.avg_latency_ms, m.cache_hit_pct, m.dropped_log_events, m.dropped_stat_events, m.dropped_stream_events, m.persist_failures
    )
}

fn stats_json(st: &AppState) -> String {
    let m = st.stats.metrics.snapshot();
    let recent: Vec<String> = st.stats.recent(2_000).iter().map(event_json).collect();
    format!(
        "{{\"metrics\":{},\"recent\":[{}]}}",
        metrics_obj(&m),
        recent.join(",")
    )
}

fn metrics_only_json(st: &AppState) -> String {
    let m = st.stats.metrics.snapshot();
    format!("{{\"metrics\":{}}}", metrics_obj(&m))
}

fn recent_json(st: &AppState) -> String {
    let recent: Vec<String> = st.stats.recent(2_000).iter().map(event_json).collect();
    format!("{{\"recent\":[{}]}}", recent.join(","))
}

fn stats_history_json(st: &AppState, range_secs: u64) -> String {
    let points = st.stats.metrics.history(range_secs, 59);
    let items = points
        .iter()
        .map(|point| {
            format!(
                "{{\"ts_ms\":{},\"queries\":{},\"blocked\":{},\"avg_latency_ms\":{:.3},\"cache_hit_pct\":{:.3}}}",
                point.ts_ms,
                point.queries,
                point.blocked,
                point.avg_latency_ms,
                point.cache_hit_pct
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"range_secs\":{range_secs},\"points\":[{items}]}}")
}

fn top_json(st: &AppState) -> String {
    let t = st.stats.top(20);
    let pairs = |v: &[(String, u64)]| -> String {
        v.iter()
            .map(|(k, c)| format!("[{},{}]", json::escape(k), c))
            .collect::<Vec<_>>()
            .join(",")
    };
    format!(
        "{{\"domains\":[{}],\"blocked\":[{}],\"clients\":[{}]}}",
        pairs(&t.domains),
        pairs(&t.blocked),
        pairs(&t.clients)
    )
}

/// Prometheus text format.
fn metrics_text(st: &AppState) -> String {
    let m = st.stats.metrics.snapshot();
    let mut s = String::new();
    let line = |s: &mut String, name: &str, help: &str, val: u64| {
        s.push_str(&format!(
            "# TYPE {name} counter\n# HELP {name} {help}\n{name} {val}\n"
        ));
    };
    line(&mut s, "onetdns_queries_total", "Total queries", m.total);
    line(
        &mut s,
        "onetdns_resolved_total",
        "Resolved or rewritten responses",
        m.resolved,
    );
    line(
        &mut s,
        "onetdns_blocked_total",
        "Blocked DNS responses",
        m.blocked,
    );
    line(
        &mut s,
        "onetdns_rewritten_total",
        "Rewritten responses",
        m.rewritten,
    );
    line(
        &mut s,
        "onetdns_denied_total",
        "Requests refused by access control rules",
        m.denied,
    );
    line(
        &mut s,
        "onetdns_refused_total",
        "Requests answered with REFUSED",
        m.refused,
    );
    line(
        &mut s,
        "onetdns_throttled_total",
        "Requests rejected by rate limiting",
        m.throttled,
    );
    line(
        &mut s,
        "onetdns_servfail_total",
        "Server failure (SERVFAIL) responses",
        m.servfail,
    );
    line(
        &mut s,
        "onetdns_cache_hits_total",
        "Response cache hits",
        m.cache_hits,
    );
    line(
        &mut s,
        "onetdns_cache_lookups_total",
        "Response cache lookups",
        m.cache_lookups,
    );
    line(
        &mut s,
        "onetdns_query_latency_microseconds_total",
        "Total processing time. Divide by the count for the average",
        m.latency_sum_us,
    );
    line(
        &mut s,
        "onetdns_query_latency_measured_total",
        "Queries with measured processing time",
        m.latency_count,
    );
    line(
        &mut s,
        "onetdns_dropped_log_events_total",
        "Query events dropped because the processing queue was full",
        m.dropped_log_events,
    );
    line(
        &mut s,
        "onetdns_dropped_stat_events_total",
        "Events that lost top-list attribution because collection slots were full. Total query counts are unaffected",
        m.dropped_stat_events,
    );
    line(
        &mut s,
        "onetdns_dropped_stream_events_total",
        "Live events not sent because a subscriber was slow",
        m.dropped_stream_events,
    );
    line(
        &mut s,
        "onetdns_persist_failures_total",
        "Failures saving stats or the query log",
        m.persist_failures,
    );
    line(
        &mut s,
        "onetdns_request_panics_total",
        "Request handling faults isolated and recovered",
        onetdns_core::isolation::request_panic_count(),
    );
    let supervisor_restarts = std::env::var("ONETDNS_SUPERVISOR_RESTARTS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    line(
        &mut s,
        "onetdns_supervisor_restarts_total",
        "DNS worker processes restarted by the supervisor",
        supervisor_restarts,
    );
    s.push_str("# TYPE onetdns_queries_by_transport counter\n");
    for (t, c) in &m.by_transport {
        s.push_str(&format!(
            "onetdns_queries_by_transport{{transport=\"{t}\"}} {c}\n"
        ));
    }
    s.push_str(&(st.controls.metrics_extra)());
    s
}

/// Served without authentication.
fn openapi_json() -> String {
    // Adding a path means updating this and regenerating API.md at the repository root.
    const SPEC: &str = r##"{
  "openapi": "3.1.0",
  "info": {
    "title": "OnetDNS Management API",
    "version": "1",
    "description": "OnetDNS management API. Authenticate with a Bearer token or a cookie session. The admin role can change settings; the read-only role can only view and run diagnostics. Setting changes and authentication or authorization failures are recorded in /v1/audit."
  },
  "components": {
    "securitySchemes": {
      "bearer": { "type": "http", "scheme": "bearer" }
    }
  },
  "security": [ { "bearer": [] } ],
  "tags": [
    { "name": "Service", "description": "Liveness and readiness probes and this OpenAPI document. They need no authentication." },
    { "name": "Authentication", "description": "Sign-in sessions, the first admin account, passwords, and API tokens." },
    { "name": "Statistics and logs", "description": "Query statistics, recent queries, the dashboard stream, Prometheus metrics, and the audit log." },
    { "name": "Configuration", "description": "Read, validate, compare, and change the config file and the running config." },
    { "name": "Filtering", "description": "Block and allow rules, blocklist subscriptions, blocked services, safe search, rewrites, access lists, and filter reports." },
    { "name": "Clients", "description": "Per-client policies." },
    { "name": "Resolution", "description": "Listen addresses, upstream DNS servers, the response cache, and query diagnostics." },
    { "name": "TLS", "description": "Certificates for encrypted DNS: status, validation, replacement, revocation checks, and ACME issuance." },
    { "name": "Zones", "description": "Authoritative zones, their records, and their DNSSEC status." },
    { "name": "DHCP", "description": "DHCP leases and static assignments." },
    { "name": "Cluster", "description": "Cluster node status and Raft config proposals." },
    { "name": "Jobs", "description": "Background jobs. Requests that take long return a job ID to poll here." },
    { "name": "System", "description": "Changes to the host this server runs on: network adapters, firewall rules, the boot service, and the OS DNS client." },
    { "name": "Updates", "description": "Self-update of this node: release checks, installation, and rollback." }
  ],
  "paths": {
    "/healthz": { "get": { "tags": ["Service"], "summary": "Process liveness check", "security": [], "responses": { "200": { "description": "ok" } } } },
    "/openapi.json": { "get": { "tags": ["Service"], "summary": "This OpenAPI spec", "security": [], "responses": { "200": { "description": "OpenAPI 3.1 document" } } } },
    "/v1/auth": { "get": { "tags": ["Authentication"], "summary": "Current authentication state and role", "description": "The control token is for the API only and is never turned into a session cookie. Web console sessions are issued only by /v1/login.", "security": [], "responses": { "200": { "description": "{login_enabled,authenticated,role,user}" } } } },
    "/v1/setup": { "post": { "tags": ["Authentication"], "summary": "Create the first admin account", "description": "Available only while no account exists. Returns 409 once any account exists.", "security": [], "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "user": { "type": "string" }, "password": { "type": "string", "minLength": 12 }, "code": { "type": "string" } }, "required": ["user", "password", "code"] } } } }, "responses": { "200": { "description": "Session cookie and {ok,user,role}" }, "400": { "description": "Username or password does not meet the rules" }, "409": { "description": "An account already exists" } } } },
    "/v1/login": { "post": { "tags": ["Authentication"], "summary": "Sign in with username and password", "security": [], "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "user": { "type": "string" }, "password": { "type": "string" } }, "required": ["user", "password"] } } } }, "responses": { "200": { "description": "Session cookie and {authenticated,role,user}" }, "401": { "description": "Credentials do not match" } } } },
    "/v1/logout": { "post": { "tags": ["Authentication"], "summary": "End the current sign-in session", "security": [], "responses": { "200": { "description": "{ok:true}" } } } },
    "/v1/stats": { "get": { "tags": ["Statistics and logs"], "summary": "Stats and recent DNS queries", "responses": { "200": { "description": "Cumulative stats and recent queries" }, "401": { "description": "Not authenticated" } } } },
    "/v1/metrics": { "get": { "tags": ["Statistics and logs"], "summary": "Dashboard stats", "responses": { "200": { "description": "{metrics:{...}}" } } } },
    "/v1/queries": { "get": { "tags": ["Statistics and logs"], "summary": "Recent DNS queries", "responses": { "200": { "description": "{recent:[...]}" } } } },
    "/v1/stats/history/{range}": { "get": { "tags": ["Statistics and logs"], "summary": "Per-second time series of total and blocked queries", "parameters": [ { "name": "range", "in": "path", "required": true, "schema": { "type": "integer", "enum": [60,300,3600,86400,604800] } } ], "responses": { "200": { "description": "Time series points for the selected range" }, "400": { "description": "Unsupported range" } } } },
    "/v1/top": { "get": { "tags": ["Statistics and logs"], "summary": "Most queried domains, blocked entries, and clients", "responses": { "200": { "description": "Top entries by query count" } } } },
    "/v1/audit": { "get": { "tags": ["Statistics and logs"], "summary": "Management actions and access denials", "responses": { "200": { "description": "Recent management actions and access denials" } } } },
    "/v1/backup": { "get": { "tags": ["Filtering"], "summary": "Back up user filter data: block and allow rules, blocked services, refused domains, safe search", "responses": { "200": { "description": "{version,block,allow,services,refused_domains,safe_search}" } } } },
    "/v1/dashboard/ws": { "get": { "tags": ["Statistics and logs"], "summary": "Dashboard WebSocket", "description": "Sends query events, stats, top entries, and job status over one connection. Uses the onetdns.v1 subprotocol; pass resume.<event_id> to resume after reconnecting.", "responses": { "101": { "description": "WebSocket connection" } } } },
    "/metrics": { "get": { "tags": ["Statistics and logs"], "summary": "Prometheus exposition", "responses": { "200": { "description": "text/plain 0.0.4" } } } },
    "/v1/reload": { "post": { "tags": ["Filtering"], "summary": "Reload blocklists from the current settings", "responses": { "200": { "description": "{block,allow}" }, "403": { "description": "This action requires the admin role" } } } },
    "/v1/block": { "post": { "tags": ["Filtering"], "summary": "Add a blocked domain", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "domain": { "type": "string" } }, "required": ["domain"] } } } }, "responses": { "200": { "description": "{block,allow}" } } } },
    "/v1/allow": { "post": { "tags": ["Filtering"], "summary": "Add an allowed domain", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "domain": { "type": "string" } }, "required": ["domain"] } } } }, "responses": { "200": { "description": "{block,allow}" } } } },
    "/v1/restore": { "post": { "tags": ["Filtering"], "summary": "Restore a user filter data backup (replaces everything)", "requestBody": { "content": { "application/json": { "schema": { "type": "object" } } } }, "responses": { "200": { "description": "{block,allow}" }, "400": { "description": "Invalid input" } } } },
    "/v1/safesearch": { "post": { "tags": ["Filtering"], "summary": "Change the safe search setting", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "enable": { "type": "boolean" } }, "required": ["enable"] } } } }, "responses": { "200": { "description": "{safe_search}" }, "400": { "description": "Could not save the config file" } } } },
    "/v1/password": { "post": { "tags": ["Authentication"], "summary": "Change the signed-in user's password and revoke all of that user's sessions", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "current_password": { "type": "string" }, "new_password": { "type": "string", "minLength": 12 } }, "required": ["current_password","new_password"] } } } }, "responses": { "200": { "description": "{changed,reloading}" }, "403": { "description": "Current password does not match" } } } },
    "/v1/querylog/clear": { "post": { "tags": ["Statistics and logs"], "summary": "Clear the recent query log", "responses": { "200": { "description": "{cleared}" } } } },
    "/v1/config/validate": { "post": { "tags": ["Configuration"], "summary": "Check whether a TOML fragment is valid when merged into the current config. The actual config is not changed", "requestBody": { "content": { "text/plain": { "schema": { "type": "string" } } } }, "responses": { "200": { "description": "{valid:true}" }, "400": { "description": "{valid:false,error}" } } } },
    "/v1/config/diff": { "post": { "tags": ["Configuration"], "summary": "Compare a TOML fragment with the current config file and show which entries change and how they are applied", "requestBody": { "content": { "text/plain": { "schema": { "type": "string" } } } }, "responses": { "200": { "description": "{added[],removed[],changed[],effective_changed[],hot_reload[],service_restart[],restart_required}" }, "400": { "description": "Returns the error when the proposed config is invalid" } } } },
    "/v1/config/apply": { "post": { "tags": ["Configuration"], "summary": "Apply a config fragment (admin only): changes only the given top-level entries and keeps the rest. Filters, access control, rate limits, the query log, and upstream DNS server addresses apply without interrupting service", "requestBody": { "content": { "text/plain": { "schema": { "type": "string" } } } }, "responses": { "200": { "description": "{applied,mode,restart_required,reloading,changed}" }, "400": { "description": "Returns the error when the input is invalid or the config file cannot be used" } } } },
    "/v1/config/rollback": { "post": { "tags": ["Configuration"], "summary": "Roll back to the state before the last config apply (admin only)", "responses": { "200": { "description": "{rolled_back,restart_required}" }, "409": { "description": "Returns an error when there is no previous config" } } } },
    "/v1/policies/simulate": { "post": { "tags": ["Resolution"], "summary": "Preview the policy and filter result for a DNS query", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "client": { "type": "string" }, "qname": { "type": "string" }, "qtype": { "type": "string" } }, "required": ["qname"] } } } }, "responses": { "200": { "description": "{policy,filter,filter_stage,filter_matched,filter_list,decision}" } } } },
    "/v1/explain": { "post": { "tags": ["Resolution"], "summary": "Preview the decision for a DNS query: explains the policy, filter, response code, and handling without sending a real query or changing the cache", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "client": { "type": "string" }, "client_id": { "type": "string" }, "qname": { "type": "string" }, "qtype": { "type": "string" } }, "required": ["qname"] } } } }, "responses": { "200": { "description": "{decision,rcode,policy,filter,filter_stage,filter_matched,filter_list,matched,client_safe_search,backend,dnssec,resolution}" } } } },
    "/readyz": { "get": { "tags": ["Service"], "summary": "DNS service readiness check", "security": [], "responses": { "200": { "description": "ready" }, "503": { "description": "not ready" } } } },
    "/v1/cluster/nodes": { "get": { "tags": ["Cluster"], "summary": "Cluster node status. With consensus enabled, includes role, term, leader, and apply position", "responses": { "200": { "description": "{self:{id,role,backend,listeners,leader,term,commit_index,last_applied,last_index,snapshot_index,retained_log_entries,fatal,healthy,version},peers:[{id,url,healthy,role,rtt_ms,version}],identity:{node_id,public_key,peer_entry}}. identity.public_key is derived from the configured Raft signing key, and peer_entry is the entry to add as-is to cluster_raft_peers on other nodes. Both are null without a signing key. self.version is this node's OnetDNS version. peers[].version is the version in the last authenticated cluster message from that node, null until one arrives. Nodes ignore cluster messages from nodes that run a different version" } } } },
    "/v1/cluster/propose": { "post": { "tags": ["Cluster"], "summary": "Propose a config change to the Raft leader (admin only): replicates {patch:{key:value}} to every node and applies it. A null value removes the entry. Node-local settings are rejected. With Raft enabled, other config-changing management requests are also accepted only on the leader and replicated the same way; followers reject them with 409", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "patch": { "type": "object" } }, "required": ["patch"], "additionalProperties": false } } } }, "responses": { "200": { "description": "{committed,applied,index}" }, "400": { "description": "{error}" } } } },
    "/v1/listeners": { "get": { "tags": ["Resolution"], "summary": "Active DNS listen addresses and per-transport status", "responses": { "200": { "description": "{listeners:[...]}" } } } },
    "/v1/system/network-adapters": { "get": { "tags": ["System"], "summary": "List host network adapters", "responses": { "200": { "description": "Adapter JSON" }, "400": { "description": "Could not retrieve the information" } } } },
    "/v1/system/firewall": { "post": { "tags": ["System"], "summary": "Open a port in the host firewall for UDP, TCP, or both, or remove the rule for that port (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "port": { "type": "integer" }, "udp": { "type": "boolean" }, "tcp": { "type": "boolean" }, "action": { "type": "string", "enum": ["allow", "remove"] } }, "required": ["port"] } } } }, "responses": { "200": { "description": "Result" }, "400": { "description": "Could not apply the change" } } } },
    "/v1/resolve": { "post": { "tags": ["Resolution"], "summary": "Send one real query to this server", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "qname": { "type": "string" }, "qtype": { "type": "string" } }, "required": ["qname"] } } } }, "responses": { "200": { "description": "{rcode,elapsed_ms,server,answers[]}" }, "400": { "description": "Could not send the query" } } } },
    "/v1/system/service": { "get": { "tags": ["System"], "summary": "Boot service registration status", "responses": { "200": { "description": "{supported,installed,running}" } } }, "post": { "tags": ["System"], "summary": "Install or remove the boot service (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "action": { "type": "string", "enum": ["install", "uninstall"] } }, "required": ["action"] } } } }, "responses": { "200": { "description": "Result" }, "400": { "description": "Could not apply" } } } },
    "/v1/system/dns-client": { "post": { "tags": ["System"], "summary": "Change the OS DNS client settings (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "adapter": { "type": "string" }, "servers": { "type": "array", "items": { "type": "string" } } }, "required": ["adapter", "servers"] } } } }, "responses": { "200": { "description": "Result" }, "400": { "description": "Could not apply the change" } } } },
    "/v1/system/dns-client/restore": { "post": { "tags": ["System"], "summary": "Restore the OS DNS client settings (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "adapter": { "type": "string" } }, "required": ["adapter"] } } } }, "responses": { "200": { "description": "Restore result" }, "400": { "description": "Could not restore" } } } },
    "/v1/system/update": { "get": { "tags": ["Updates"], "summary": "Self-update status of this node: its version, whether this build updates itself and why not, how a new version is started, the last release check, the update record, and the version a rollback would reinstall", "responses": { "200": { "description": "{version,target,participating,reason,launch,release_check,task,checked_at,result,new_version,release_url,detail,record,rollback}" } } } },
    "/v1/system/update/check": { "post": { "tags": ["Updates"], "summary": "Start a job that checks GitHub for a newer release (admin only)", "responses": { "200": { "description": "{id,status}" }, "409": { "description": "{error}" } } } },
    "/v1/system/update/apply": { "post": { "tags": ["Updates"], "summary": "Start a job that installs the release found by the last check and starts it (admin only). version must be the version the last check found", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "version": { "type": "string" } }, "required": ["version"] } } } }, "responses": { "200": { "description": "{id,status}" }, "400": { "description": "{error}" }, "409": { "description": "{error}" } } } },
    "/v1/system/update/rollback": { "post": { "tags": ["Updates"], "summary": "Start a job that reinstalls the version replaced by the last committed update and starts it (admin only)", "responses": { "200": { "description": "{id,status}" }, "409": { "description": "{error}" } } } },
    "/v1/zones": { "get": { "tags": ["Zones"], "summary": "Authoritative zones", "responses": { "200": { "description": "[{origin,serial,records}]" } } } },
    "/v1/zones/{origin}": {
      "get": { "tags": ["Zones"], "summary": "Authoritative zone with structured records", "responses": { "200": { "description": "{origin,serial,record_count,records:[{name,type,ttl,value}]}" }, "404": { "description": "{error}" } } },
      "put": { "tags": ["Zones"], "summary": "Create or replace an authoritative DNS zone (admin only; body is an RFC 1035 zone file)", "requestBody": { "content": { "text/plain": { "schema": { "type": "string" } } } }, "responses": { "200": { "description": "{origin,serial,records,persisted}" }, "400": { "description": "{error}: invalid DNS zone data" }, "403": { "description": "This action requires the admin role" } } },
      "delete": { "tags": ["Zones"], "summary": "Delete an authoritative DNS zone (admin only)", "responses": { "200": { "description": "{deleted}" }, "404": { "description": "{error}" } } }
    },
    "/v1/zones/{origin}/dnssec": { "get": { "tags": ["Zones"], "summary": "Zone DNSSEC status (signed, DNSKEYs, DS for the parent)", "responses": { "200": { "description": "{signed,dnskeys:[{key_tag,flags,algorithm,role}],ds:{key_tag,algorithm,digest_type,digest}}" } } } },
    "/v1/zones/{origin}/records": {
      "post": { "tags": ["Zones"], "summary": "Add a DNS record (admin only): saves, re-signs with DNSSEC, and sends NOTIFY", "requestBody": { "content": { "text/plain": { "schema": { "type": "string" } } } }, "responses": { "200": { "description": "{origin,serial,records,persisted,signed}" }, "400": { "description": "{error}: invalid DNS record" } } },
      "delete": { "tags": ["Zones"], "summary": "Delete DNS records (admin only): with value, deletes only records whose value also matches", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "name": { "type": "string" }, "type": { "type": "string" }, "value": { "type": "string" } }, "required": ["name","type"] } } } }, "responses": { "200": { "description": "{deleted,origin,serial,persisted}" }, "404": { "description": "{error}: no matching entry" } } }
    },
    "/v1/config/effective": { "get": { "tags": ["Configuration"], "summary": "The config the server is actually running: defaults merged in, sensitive values masked. Direct edits to the config file are not included until applied", "responses": { "200": { "description": "Running config (JSON)" } } } },
    "/v1/config": { "get": { "tags": ["Configuration"], "summary": "Values saved in the config file, including changes not yet applied to the server. Returns error details when the file cannot be read or parsed", "responses": { "200": { "description": "Saved config values or a file error (JSON)" } } } },
    "/v1/config/status": { "get": { "tags": ["Configuration"], "summary": "Check whether the config file matches the running config and show entries not yet applied. service_restart lists the entries whose change restarts the DNS service when the file is applied; conditional_hot_reload_keys lists the settings that can restart it under the current configuration", "responses": { "200": { "description": "{in_sync,source,changed_keys[],service_restart[],restart_required,conditional_hot_reload_keys[],error?}" } } } },
    "/v1/config/reload": { "post": { "tags": ["Configuration"], "summary": "Validate config file changes and apply them to the running server (admin only)", "responses": { "200": { "description": "{accepted,mode,restart_required,changed}" }, "400": { "description": "{error}: config file is missing or invalid" } } } },
    "/v1/config/set": { "post": { "tags": ["Configuration"], "summary": "Change settings (admin only): merges the values into the TOML file, validates, and saves. Hot-reloadable entries apply without dropping connections; others restart the DNS service. Nested entries use their dedicated APIs", "requestBody": { "content": { "application/json": { "schema": { "type": "object" } } } }, "responses": { "200": { "description": "{applied,mode,restart_required,reloading,changed,keys}" }, "400": { "description": "{error}: unknown key or invalid value" } } } },
    "/v1/config/set/diff": { "post": { "tags": ["Configuration"], "summary": "Show which entries a /v1/config/set request with this body would change and how they would be applied, without changing anything (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object" } } } }, "responses": { "200": { "description": "{added[],removed[],changed[],effective_changed[],hot_reload[],service_restart[],restart_required}" }, "400": { "description": "{error}: unknown key or invalid value" } } } },
    "/v1/config/schema": { "get": { "tags": ["Configuration"], "summary": "Settings that /v1/config/set can change, with their types and descriptions", "responses": { "200": { "description": "{keys:[...],count}" } } } },
    "/v1/upstreams/test": { "post": { "tags": ["Resolution"], "summary": "Test an upstream DNS server (admin only): sends a test query and reports reachability, latency, and response code", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "addr": { "type": "string" } }, "required": ["addr"] } } } }, "responses": { "200": { "description": "{ok,latency_ms,rcode,addr}" }, "400": { "description": "{error}" } } } },
    "/v1/cache/flush": { "post": { "tags": ["Resolution"], "summary": "Flush the whole response cache (admin only). Returns the number of entries removed", "responses": { "200": { "description": "{flushed}" } } } },
    "/v1/tokens": { "get": { "tags": ["Authentication"], "summary": "Management API tokens. Token values are masked; only the role and a stable ID are returned", "responses": { "200": { "description": "{tokens:[{id,role,masked}]}" } } }, "post": { "tags": ["Authentication"], "summary": "Issue a management API token (admin only). The token is read-only unless role is admin. The full token value is returned only once, in this response", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "role": { "type": "string", "enum": ["admin", "readonly"] } } } } } }, "responses": { "200": { "description": "{created,role,token,id}" }, "400": { "description": "{error}" } } }, "delete": { "tags": ["Authentication"], "summary": "Revoke a management API token (admin only). The primary control token from the config file cannot be deleted", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "id": { "type": "string" } }, "required": ["id"] } } } }, "responses": { "200": { "description": "{removed}" }, "404": { "description": "{error}" } } } },
    "/v1/rewrites": { "get": { "tags": ["Filtering"], "summary": "DNS rewrite rules", "responses": { "200": { "description": "{rewrites:[{domain,answer}]}" } } }, "post": { "tags": ["Filtering"], "summary": "Add or replace a DNS rewrite rule (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "domain": { "type": "string" }, "answer": { "type": "string" } }, "required": ["domain", "answer"] } } } }, "responses": { "200": { "description": "{added,domain}" }, "400": { "description": "{error}" } } }, "delete": { "tags": ["Filtering"], "summary": "Delete a DNS rewrite rule (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "domain": { "type": "string" } }, "required": ["domain"] } } } }, "responses": { "200": { "description": "{removed,domain}" }, "404": { "description": "{error}" } } } },
    "/v1/services": {
      "get": { "tags": ["Filtering"], "summary": "Blockable services and whether each is blocked", "responses": { "200": { "description": "{count,services:[{id,name,blocked}]}" } } },
      "post": { "tags": ["Filtering"], "summary": "Change service blocking", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "service": { "type": "string" }, "enable": { "type": "boolean" } }, "required": ["service","enable"] } } } }, "responses": { "200": { "description": "{block,allow}" } } }
    },
    "/v1/access": { "get": { "tags": ["Filtering"], "summary": "Allowed, blocked, and silently dropped networks, what happens to clients that match no access rule (allow, deny, or drop), and domains answered with REFUSED. Use the config API to change them", "responses": { "200": { "description": "{allowed,blocked,dropped,unlisted,refused_domains}" } } } },
    "/v1/tls": { "get": { "tags": ["TLS"], "summary": "TLS certificate and private key paths, and encrypted DNS listener status", "responses": { "200": { "description": "{configured,cert,key,doh_listeners,dot_listeners}" } } } },
    "/v1/tls/validate": { "post": { "tags": ["TLS"], "summary": "Validate the configured certificate, private key, chain, and validity period (admin only). Trust path and hostname are not checked", "responses": { "200": { "description": "{material_valid,valid:false,trusted:false,hostname_checked:false,chain_len}" }, "400": { "description": "{error}" } } } },
    "/v1/tls/configure": { "post": { "tags": ["TLS"], "summary": "Replace the TLS certificate and private key (admin only): accepts PEM bodies or file paths, checks the format and that the key matches, saves them, and restarts the encrypted DNS listeners", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "certificate_chain": { "type": "string" }, "private_key": { "type": "string" }, "cert_path": { "type": "string" }, "key_path": { "type": "string" } }, "additionalProperties": false } } } }, "responses": { "200": { "description": "{configured,chain_len,reloading,cert,key}" }, "400": { "description": "{error}" } } } },
    "/v1/tls/revocation-check": { "post": { "tags": ["TLS"], "summary": "Check OCSP and CRL revocation status of a certificate chain (admin only). Fetches from the URLs in the certificate and verifies signatures", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "certificate_chain": { "type": "string" } }, "required": ["certificate_chain"] } } } }, "responses": { "200": { "description": "{ocsp,crl,ocsp_urls,crl_urls,revoked}" }, "400": { "description": "{error}" } } } },
    "/v1/acme/issue": { "post": { "tags": ["TLS"], "summary": "Issue an ACME certificate or register an account (admin only). Answers HTTP-01 and DNS-01 challenges automatically and saves the issued certificate and private key to the configured files", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "directory": { "type": "string" }, "domains": { "type": "array" }, "contact": { "type": "string" }, "challenge": { "type": "string" }, "account_only": { "type": "boolean" } } } } } }, "responses": { "200": { "description": "{account,issued,cert_file,key_file}" }, "400": { "description": "{error}" } } } },
    "/v1/plugins": { "get": { "tags": ["Filtering"], "summary": "WASM plugin metrics", "responses": { "200": { "description": "[{name,eval,error,block,latency_us}]" } } } },
    "/v1/filter/report": { "get": { "tags": ["Filtering"], "summary": "Filter rule load results and why rules were skipped", "responses": { "200": { "description": "{rules_total,rules_applied,rules_skipped,skip_reasons}" } } } },
    "/v1/filter/top-rules": { "get": { "tags": ["Filtering"], "summary": "Top N rules by hits (when track_rule_hits is enabled)", "responses": { "200": { "description": "{enabled,top:[{rule,hits}]}" } } } },
    "/v1/filter/sources": { "get": { "tags": ["Filtering"], "summary": "Rule count and cumulative hits per block or allow list", "responses": { "200": { "description": "{hits_enabled,sources:[{source,rules,hits}]}" } } } },
    "/v1/filter/subscriptions": {
      "get": { "tags": ["Filtering"], "summary": "Subscriptions with title, enabled state, and rule count. Built-in lists enabled by safe browsing and parental control are included with a preset value; they are turned on and off only by those settings and cannot be deleted or disabled here", "responses": { "200": { "description": "{lists:[{url,title,enabled,rules,updated_unix,preset?}],count,block_domains}. preset is safe_browsing or parental_control" } } },
      "post": { "tags": ["Filtering"], "summary": "Add a blocklist subscription (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "url": { "type": "string" }, "title": { "type": "string" }, "enabled": { "type": "boolean" } }, "required": ["url"] } } } }, "responses": { "200": { "description": "{added,subscriptions,block}" }, "400": { "description": "{error}" } } },
      "patch": { "tags": ["Filtering"], "summary": "Enable or disable a blocklist subscription (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "url": { "type": "string" }, "enabled": { "type": "boolean" } }, "required": ["url", "enabled"] } } } }, "responses": { "200": { "description": "{updated}" }, "400": { "description": "{error}" } } },
      "delete": { "tags": ["Filtering"], "summary": "Delete a blocklist subscription (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "url": { "type": "string" } }, "required": ["url"] } } } }, "responses": { "200": { "description": "{removed,subscriptions,block}" }, "404": { "description": "{error}" } } }
    },
    "/v1/filter/subscriptions/refresh": { "post": { "tags": ["Filtering"], "summary": "Refresh the given blocklist subscription (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "url": { "type": "string" } }, "required": ["url"] } } } }, "responses": { "200": { "description": "{refreshed:true}" }, "400": { "description": "{error}" } } } },
    "/v1/filter/rules": { "get": { "tags": ["Filtering"], "summary": "User block and allow rules, and domains answered with REFUSED", "responses": { "200": { "description": "{block,allow,refused_domains}" } } }, "post": { "tags": ["Filtering"], "summary": "Add a filter rule (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "kind": { "type": "string", "enum": ["block", "allow", "refused_domain"] }, "rule": { "type": "string" } }, "required": ["kind", "rule"] } } } }, "responses": { "200": { "description": "{updated:true}" } } }, "delete": { "tags": ["Filtering"], "summary": "Delete a filter rule (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "kind": { "type": "string", "enum": ["block", "allow", "refused_domain"] }, "rule": { "type": "string" } }, "required": ["kind", "rule"] } } } }, "responses": { "200": { "description": "{updated:true}" } } } },
    "/v1/clients": { "get": { "tags": ["Clients"], "summary": "Per-client policies", "responses": { "200": { "description": "[{name,nets,client_ids,tags,block_rules,disable_filtering}]" } } }, "post": { "tags": ["Clients"], "summary": "Add a client policy (admin only): ordinary block and allow policies apply without dropping connections; a dedicated upstream DNS server or a new MAC match restarts the DNS service", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "name": { "type": "string" }, "ids": { "type": "array", "items": { "type": "string" } }, "client_ids": { "type": "array", "items": { "type": "string" } }, "mac": { "type": "array", "items": { "type": "string" } }, "tags": { "type": "array", "items": { "type": "string" } }, "block": { "type": "array", "items": { "type": "string" } }, "allow": { "type": "array", "items": { "type": "string" } }, "blocked_services": { "type": "array", "items": { "type": "string" } }, "disable_filtering": { "type": "boolean" }, "safe_search": { "type": "boolean" } }, "required": ["name"] } } } }, "responses": { "200": { "description": "{added,reloading}" }, "400": { "description": "{error}" } } }, "patch": { "tags": ["Clients"], "summary": "Turn filtering on or off for a client (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "name": { "type": "string" }, "disable_filtering": { "type": "boolean" } }, "required": ["name", "disable_filtering"] } } } }, "responses": { "200": { "description": "{updated,disable_filtering,reloading}" } } }, "delete": { "tags": ["Clients"], "summary": "Delete a client policy (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "name": { "type": "string" } }, "required": ["name"] } } } }, "responses": { "200": { "description": "{removed,reloading}" }, "400": { "description": "{error}" } } } },
    "/v1/upstreams": { "get": { "tags": ["Resolution"], "summary": "Upstream DNS servers", "responses": { "200": { "description": "[{id,addr,queries?,ok?,fail?,ewma_ms?}]" } } }, "post": { "tags": ["Resolution"], "summary": "Add an upstream DNS server (admin only; applies without dropping connections)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "addr": { "type": "string" } }, "required": ["addr"], "additionalProperties": false } } } }, "responses": { "200": { "description": "{added,mode,restart_required}" }, "400": { "description": "{error}" } } }, "delete": { "tags": ["Resolution"], "summary": "Delete an upstream DNS server (admin only; applies without dropping connections)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "addr": { "type": "string" } }, "required": ["addr"], "additionalProperties": false } } } }, "responses": { "200": { "description": "{removed,mode,restart_required}" }, "400": { "description": "{error}" } } } },
    "/v1/jobs": { "get": { "tags": ["Jobs"], "summary": "Background jobs", "responses": { "200": { "description": "[{id,kind,status,created,finished,result}]" } } } },
    "/v1/jobs/refresh": { "post": { "tags": ["Jobs"], "summary": "Start a blocklist refresh job (admin only)", "responses": { "200": { "description": "{id,status}" } } } },
    "/v1/jobs/{id}": { "get": { "tags": ["Jobs"], "summary": "Status of one job (polling)", "responses": { "200": { "description": "{id,kind,status,...}" }, "404": { "description": "{error}" } } } },
    "/v1/dhcp/leases": { "get": { "tags": ["DHCP"], "summary": "Active DHCP leases. IPv4 entries include the binding identity, last MAC, and the vendor and hostname when known", "responses": { "200": { "description": "{v4:[{ip,identity,mac,vendor,hostname,expires,remaining}],v6:[{ip,duid,expires,remaining}]}" } } }, "post": { "tags": ["DHCP"], "summary": "Apply DHCP leases sent by the peer node in a high-availability setup (admin only). Accepts one object or a snapshot array with identity and last MAC; rejects the whole request if any entry is malformed", "requestBody": { "content": { "application/json": { "schema": { "oneOf": [{ "type": "object" }, { "type": "array", "items": { "type": "object" } }], "example": [{ "identity": "id:0102", "mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.100", "expiry": "1900000000", "hostname": "host1" }] } } } }, "responses": { "200": { "description": "{synced}" }, "400": { "description": "{error}" } } } },
    "/v1/dhcp/static": { "get": { "tags": ["DHCP"], "summary": "DHCP static assignments (fixed IP per mac:<hex> or id:<hex> identity)", "responses": { "200": { "description": "{available,reservations:[{identity,ip,hostname}]}. available is false when no DHCPv4 pool is running; adds and deletes are then rejected" } } }, "post": { "tags": ["DHCP"], "summary": "Add or change a DHCP static assignment (admin only). Applies to the pool immediately and saves to file", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "identity": { "type": "string" }, "ip": { "type": "string" }, "hostname": { "type": "string" } }, "required": ["identity", "ip"] } } } }, "responses": { "200": { "description": "{added,identity,ip}" }, "400": { "description": "{error}" } } }, "delete": { "tags": ["DHCP"], "summary": "Delete a DHCP static assignment (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "identity": { "type": "string" } }, "required": ["identity"] } } } }, "responses": { "200": { "description": "{removed,identity}" }, "404": { "description": "{error}" } } } }
  }
}"##;
    SPEC.to_string()
}

/// Constant time; an early return would let token bytes be guessed one at a time from timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// API.md at the repository root must match the OpenAPI document and role rules.
#[cfg(test)]
mod reference;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{channel, PersistOpts, RecorderOpts};
    use std::sync::Mutex;

    #[test]
    fn request_deadline_rejects_slow_drip_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for byte in b"GET / HTTP/1.1\r\n" {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(30));
            }
        });

        let started = Instant::now();
        let stream = TcpStream::connect(addr).unwrap();
        let mut reader = BufReader::new(DeadlineTcp::new(
            AdmittedTcp::new(SharedTcp::new(stream), Vec::new(), None),
            started + Duration::from_millis(120),
        ));
        let mut line = String::new();
        let error = reader.read_line(&mut line).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ));
        assert!(started.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
    }

    #[test]
    fn control_admission_waits_for_complete_request_and_replays_it() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, peer) = listener.accept().unwrap();
        let shared = SharedTcp::new(server);
        shared.set_nonblocking(true).unwrap();
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let admission_total = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut pending = PendingControlConnection {
            stream: shared,
            peer,
            deadline: Instant::now() + Duration::from_secs(1),
            received: Vec::new(),
            next_probe: Instant::now(),
            probe_delay: Duration::from_millis(CONTROL_ADMISSION_POLL_MS),
            admission_bytes: AdmissionBytesGuard::new(admission_total.clone()),
            guard: acquire_connection_slot(&active).unwrap(),
        };
        let request = b"POST /v1/config/validate HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 4\r\n\r\n{}{}";
        let body_tail = 2;
        client
            .write_all(&request[..request.len() - body_tail])
            .unwrap();
        let mut scratch = [0u8; CONTROL_ADMISSION_READ_BYTES];
        // `write_all` only fills the send buffer; when bytes reach the receiver is up to the
        // kernel. Checking once before the first part arrives proves nothing about Pending, so wait
        // for it.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(matches!(
                control_admission_state(&mut pending, &mut scratch).unwrap(),
                ControlAdmissionState::Pending
            ));
            if !pending.received.is_empty() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "요청 앞부분이 도착하지 않았습니다"
            );
            std::thread::sleep(Duration::from_millis(1));
        }

        client
            .write_all(&request[request.len() - body_tail..])
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if matches!(
                control_admission_state(&mut pending, &mut scratch).unwrap(),
                ControlAdmissionState::Ready
            ) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "요청 나머지가 도착하지 않았습니다"
            );
            std::thread::sleep(Duration::from_millis(1));
        }

        pending.stream.set_nonblocking(false).unwrap();
        let admission_bytes = std::mem::replace(
            &mut pending.admission_bytes,
            AdmissionBytesGuard::new(admission_total.clone()),
        );
        let mut reader = DeadlineTcp::new(
            AdmittedTcp::new(
                pending.stream.clone(),
                std::mem::take(&mut pending.received),
                Some(admission_bytes),
            ),
            pending.deadline,
        )
        .stop_on(Arc::new(std::sync::atomic::AtomicBool::new(false)));
        let mut received = vec![0u8; request.len()];
        reader.read_exact(&mut received).unwrap();
        assert_eq!(received, request, "기존 파서가 원래 요청을 그대로 봅니다");
    }

    #[test]
    fn control_admission_detects_close_after_partial_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, peer) = listener.accept().unwrap();
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let admission_total = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut pending = PendingControlConnection {
            stream: SharedTcp::new(server),
            peer,
            deadline: Instant::now() + Duration::from_secs(1),
            received: Vec::new(),
            next_probe: Instant::now(),
            probe_delay: Duration::from_millis(CONTROL_ADMISSION_POLL_MS),
            admission_bytes: AdmissionBytesGuard::new(admission_total),
            guard: acquire_connection_slot(&active).unwrap(),
        };
        pending.stream.set_nonblocking(true).unwrap();
        client.write_all(b"G").unwrap();
        drop(client);

        let mut scratch = [0u8; CONTROL_ADMISSION_READ_BYTES];
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if matches!(
                control_admission_state(&mut pending, &mut scratch).unwrap(),
                ControlAdmissionState::Closed
            ) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "부분 요청 뒤 FIN을 감지해야 합니다"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(pending.received, b"G");
    }

    #[test]
    fn admission_byte_budget_is_bounded_and_released() {
        use std::sync::atomic::Ordering;

        let total = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut first = AdmissionBytesGuard::new(total.clone());
        let mut second = AdmissionBytesGuard::new(total.clone());
        let mut denied = AdmissionBytesGuard::new(total.clone());
        assert_eq!(
            first.reserve(MAX_CONTROL_ADMISSION_BYTES - 1),
            MAX_CONTROL_ADMISSION_BYTES - 1
        );
        assert_eq!(second.reserve(2), 1);
        assert_eq!(denied.reserve(1), 0);
        assert_eq!(total.load(Ordering::Acquire), MAX_CONTROL_ADMISSION_BYTES);

        drop(second);
        assert_eq!(denied.reserve(1), 1);
        drop(first);
        drop(denied);
        assert_eq!(total.load(Ordering::Acquire), 0);
    }

    #[test]
    fn control_admission_reports_full_global_byte_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, peer) = listener.accept().unwrap();
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let admission_total = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut blocker = AdmissionBytesGuard::new(admission_total.clone());
        assert_eq!(
            blocker.reserve(MAX_CONTROL_ADMISSION_BYTES),
            MAX_CONTROL_ADMISSION_BYTES
        );
        let mut pending = PendingControlConnection {
            stream: SharedTcp::new(server),
            peer,
            deadline: Instant::now() + Duration::from_secs(1),
            received: Vec::new(),
            next_probe: Instant::now(),
            probe_delay: Duration::from_millis(CONTROL_ADMISSION_POLL_MS),
            admission_bytes: AdmissionBytesGuard::new(admission_total),
            guard: acquire_connection_slot(&active).unwrap(),
        };
        pending.stream.set_nonblocking(true).unwrap();
        client.write_all(b"G").unwrap();

        let mut scratch = [0u8; CONTROL_ADMISSION_READ_BYTES];
        assert!(matches!(
            control_admission_state(&mut pending, &mut scratch).unwrap(),
            ControlAdmissionState::Overloaded
        ));
        assert!(pending.received.is_empty());
        drop(blocker);
        // `write_all` only fills the send buffer; a single read may still find the socket empty.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(matches!(
                control_admission_state(&mut pending, &mut scratch).unwrap(),
                ControlAdmissionState::Pending
            ));
            if !pending.received.is_empty() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "보낸 바이트가 받는 쪽에 도착하지 않았습니다"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(pending.received, b"G");
    }

    #[test]
    fn control_admission_defers_malformed_framing_to_the_authoritative_parser() {
        for request in [
            b"POST / HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\n".as_slice(),
            b"POST / HTTP/1.1\r\nContent-Length: nope\r\n\r\n".as_slice(),
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
            b"POST / HTTP/1.1\r\nContent-Length: 1048577\r\n\r\n".as_slice(),
        ] {
            let header_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .unwrap()
                + 4;
            assert_eq!(
                control_request_required_bytes(request, header_end),
                header_end
            );
        }
    }

    #[test]
    fn serve_listener_promotes_a_request_only_after_its_header_is_complete() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_shutdown = shutdown.clone();
        let server = std::thread::spawn(move || {
            serve_listener(listener, test_state("adm", "ro"), server_shutdown).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        client.write_all(b"G").unwrap();
        let mut byte = [0u8; 1];
        let error = client.read(&mut byte).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));

        let rest = format!("ET /v1/auth HTTP/1.1\r\nHost: {addr}\r\n\r\n");
        client.write_all(rest.as_bytes()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

        shutdown.store(true, Ordering::Relaxed);
        server.join().unwrap();
    }

    fn test_state(admin: &str, readonly: &str) -> AppState {
        let (_rec, stats) = channel(8, 100, 0, RecorderOpts::default(), PersistOpts::default());
        let store: Arc<Mutex<(Vec<String>, Vec<String>)>> = Arc::new(Mutex::new((vec![], vec![])));
        let zones: Arc<Mutex<std::collections::HashMap<String, String>>> =
            Arc::new(Mutex::new(std::collections::HashMap::new()));
        let s1 = store.clone();
        let s2 = store.clone();
        let s3 = store.clone();
        let cnt = |st: &Mutex<(Vec<String>, Vec<String>)>| {
            let g = st.lock_recover();
            ListCounts {
                block: g.0.len(),
                allow: g.1.len(),
            }
        };
        let controls = Controls {
            reload: Box::new(move || Ok(cnt(&s1))),
            block_add: Box::new(move |d: &str| {
                s2.lock_recover().0.push(d.to_string());
                Ok(cnt(&s2))
            }),
            allow_add: Box::new(|_| Ok(ListCounts { block: 0, allow: 0 })),
            service_set: Box::new(|_, _| Ok(ListCounts { block: 0, allow: 0 })),
            safesearch_set: Box::new(|_| Ok(())),
            export: {
                let s = store.clone();
                Box::new(move || {
                    let g = s.lock_recover();
                    let arr = |v: &[String]| {
                        v.iter()
                            .map(|x| json::escape(x))
                            .collect::<Vec<_>>()
                            .join(",")
                    };
                    format!(
                        "{{\"version\":1,\"block\":[{}],\"allow\":[{}]}}",
                        arr(&g.0),
                        arr(&g.1)
                    )
                })
            },
            import: Box::new(move |body: &str| {
                let j = json::parse(body)?;
                let b: Vec<String> = j
                    .get("block")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                let mut g = s3.lock_recover();
                g.0 = b;
                Ok(ListCounts {
                    block: g.0.len(),
                    allow: g.1.len(),
                })
            }),

            config_validate: Box::new(|t| {
                if t.contains("bad") {
                    Err("입력 형식이 올바르지 않습니다".to_string())
                } else {
                    Ok(())
                }
            }),
            config_diff: Box::new(|_| {
                Ok("{\"added\":[],\"removed\":[],\"changed\":[]}".to_string())
            }),
            config_apply: Box::new(|t| {
                if t.contains("bad") {
                    Err("입력 형식이 올바르지 않습니다".to_string())
                } else {
                    Ok("{\"applied\":true,\"restart_required\":true}".to_string())
                }
            }),
            config_set: Box::new(|b| {
                if b.contains("\"bad\"") {
                    Err("알 수 없는 설정 키".to_string())
                } else {
                    Ok("{\"applied\":true,\"reloading\":true}".to_string())
                }
            }),
            config_set_diff: Box::new(|_| {
                Ok("{\"added\":[],\"removed\":[],\"changed\":[]}".to_string())
            }),
            config_schema: Box::new(|| "{\"keys\":[\"prefetch\",\"cache_size\"]}".to_string()),
            upstream_test: Box::new(|b| {
                if b.contains("addr") {
                    Ok("{\"ok\":true,\"latency_ms\":4}".to_string())
                } else {
                    Err("`addr` 항목을 입력해야 합니다".to_string())
                }
            }),
            cache_flush: Box::new(|| "{\"flushed\":42}".to_string()),
            rewrites_list: Box::new(|| {
                "{\"rewrites\":[{\"domain\":\"router.lan\",\"answer\":\"192.168.1.1\"}]}"
                    .to_string()
            }),
            rewrite_add: Box::new(|b| {
                if b.contains("domain") {
                    Ok("{\"added\":true}".to_string())
                } else {
                    Err("`domain` 항목을 입력해야 합니다".to_string())
                }
            }),
            rewrite_delete: Box::new(|_| Ok("{\"removed\":1}".to_string())),
            services_catalog: Box::new(|| {
                "{\"count\":1,\"services\":[{\"id\":\"youtube\",\"name\":\"YouTube\",\"group\":\"streaming\",\"rule_count\":5,\"blocked\":false}]}".to_string()
            }),
            access_list: Box::new(|| {
                "{\"allowed\":[\"10.0.0.0/8\"],\"blocked\":[],\"dropped\":[],\"unlisted\":\"deny\",\"refused_domains\":[]}"
                    .to_string()
            }),
            tls_status: Box::new(|| "{\"configured\":true,\"doh_listeners\":1}".to_string()),
            tls_validate: Box::new(|| Ok("{\"valid\":true,\"chain_len\":1}".to_string())),
            tls_configure: Box::new(|body| {
                if body.contains("private_key") || body.contains("key_path") {
                    Ok("{\"configured\":true,\"reloading\":true}".to_string())
                } else {
                    Err("인증서와 개인키를 모두 입력해야 합니다".to_string())
                }
            }),
            tls_revocation_check: Box::new(|body| {
                if body.contains("certificate_chain") {
                    Ok("{\"ocsp\":\"good\",\"crl\":\"unavailable\",\"revoked\":false}".to_string())
                } else {
                    Err("`certificate_chain` 항목을 입력해야 합니다".to_string())
                }
            }),
            acme_issue: Box::new(|body| {
                if body.contains("account_only") {
                    Ok("{\"account\":\"https://acme/acct/1\",\"issued\":false}".to_string())
                } else {
                    Err("ACME 디렉터리 주소를 입력해야 합니다".to_string())
                }
            }),
            tokens_list: Box::new(|| {
                "{\"tokens\":[{\"id\":\"ab12\",\"role\":\"admin\",\"masked\":\"abcdef…99\"}]}"
                    .to_string()
            }),
            token_add: Box::new(|b| {
                if b.contains("role") || b == "{}" {
                    Ok("{\"created\":true,\"role\":\"readonly\",\"token\":\"deadbeef\",\"id\":\"ab12\"}"
                        .to_string())
                } else {
                    Err("JSON 요청 본문을 해석할 수 없습니다".to_string())
                }
            }),
            token_delete: Box::new(|b| {
                if b.contains("\"id\"") {
                    Ok("{\"removed\":1}".to_string())
                } else {
                    Err("`id` 항목을 입력해야 합니다".to_string())
                }
            }),
            config_rollback: Box::new(|| Ok("{\"rolled_back\":true}".to_string())),
            policy_simulate: Box::new(|_| "{\"action\":\"continue\"}".to_string()),
            zones_list: Box::new(|| "[]".to_string()),

            zone_get: {
                let z = zones.clone();
                Box::new(move |origin: &str| {
                    z.lock()
                        .unwrap()
                        .get(origin)
                        .map(|t| {
                            format!("{{\"origin\":\"{origin}\",\"zone\":{}}}", json::escape(t))
                        })
                        .ok_or_else(|| format!("DNS 영역을 찾을 수 없습니다: {origin}"))
                })
            },
            zone_put: {
                let z = zones.clone();
                Box::new(move |origin: &str, text: &str| {
                    if text.contains("bad") {
                        return Err("DNS 영역 데이터 형식이 올바르지 않습니다".to_string());
                    }
                    z.lock()
                        .unwrap()
                        .insert(origin.to_string(), text.to_string());
                    Ok(format!("{{\"origin\":\"{origin}\",\"persisted\":false}}"))
                })
            },
            zone_delete: {
                let z = zones.clone();
                Box::new(move |origin: &str| {
                    z.lock()
                        .unwrap()
                        .remove(origin)
                        .map(|_| "{\"deleted\":true}".to_string())
                        .ok_or_else(|| format!("DNS 영역을 찾을 수 없습니다: {origin}"))
                })
            },
            zone_record_add: {
                let z = zones.clone();
                Box::new(move |origin: &str, body: &str| {
                    if body.trim().is_empty() {
                        return Err("빈 본문".to_string());
                    }
                    z.lock()
                        .unwrap()
                        .entry(origin.to_string())
                        .or_default()
                        .push_str(body);
                    Ok(format!("{{\"origin\":\"{origin}\",\"added\":true}}"))
                })
            },
            zone_record_delete: Box::new(|origin: &str, _: &str| {
                Ok(format!("{{\"origin\":\"{origin}\",\"deleted\":1}}"))
            }),
            zone_dnssec: Box::new(|origin: &str| {
                Ok(format!(
                    "{{\"origin\":\"{origin}\",\"signed\":true,\"dnskeys\":[],\"ds\":null}}"
                ))
            }),
            config_desired: Box::new(|| "{\"mode\":\"personal\"}".to_string()),
            config_effective: Box::new(|| "{\"mode\":\"personal\"}".to_string()),
            config_status: Box::new(|| "{\"in_sync\":true,\"changed_keys\":[]}".to_string()),
            config_reload: Box::new(|| Ok("{\"accepted\":true}".to_string())),
            plugins_metrics: Box::new(|| "[]".to_string()),
            filter_report: Box::new(|| {
                "{\"rules_total\":3,\"rules_applied\":2,\"rules_skipped\":1}".to_string()
            }),
            filter_top_rules: Box::new(|| {
                "{\"enabled\":true,\"top\":[{\"rule\":\"ads.example.com\",\"hits\":3}]}".to_string()
            }),
            filter_sources: Box::new(|| {
                "{\"hits_enabled\":true,\"sources\":[{\"source\":\"listA\",\"rules\":1,\"hits\":2}]}"
                    .to_string()
            }),
            subscriptions_list: Box::new(|| {
                "{\"urls\":[\"https://x/list.txt\"],\"count\":1,\"block_domains\":0}".to_string()
            }),
            subscription_add: Box::new(|url: &str| {
                if url.trim().is_empty() {
                    Err("URL을 입력해야 합니다".to_string())
                } else {
                    Ok("{\"added\":true}".to_string())
                }
            }),
            subscription_remove: Box::new(|_| Ok("{\"removed\":true}".to_string())),
            subscription_update: Box::new(|_| Ok("{\"updated\":true}".to_string())),
            subscription_refresh: Box::new(|_| Ok("{\"id\":1}".to_string())),
            filter_rules_list: Box::new(|| {
                "{\"block\":[],\"allow\":[],\"refused_domains\":[]}".to_string()
            }),
            filter_rule_mutate: Box::new(|_, _| Ok("{\"updated\":true}".to_string())),
            clients_list: Box::new(|| "[]".to_string()),
            upstreams_list: Box::new(|| "[]".to_string()),
            jobs_list: Box::new(|| "[{\"id\":1,\"status\":\"done\"}]".to_string()),
            job_get: Box::new(|id| {
                if id == 1 {
                    Ok("{\"id\":1,\"status\":\"done\"}".to_string())
                } else {
                    Err("작업을 찾을 수 없습니다".to_string())
                }
            }),
            job_refresh: Box::new(|| "{\"id\":2,\"status\":\"running\"}".to_string()),
            dhcp_leases: Box::new(|| {
                "{\"v4\":[{\"ip\":\"192.168.1.100\",\"identity\":\"id:0102\",\"mac\":\"aa:bb:cc:dd:ee:ff\",\"vendor\":null,\"hostname\":\"host1\",\"expires\":9999999999,\"remaining\":3600}],\"v6\":[]}".to_string()
            }),
            dhcp_lease_put: Box::new(|body| {
                if body.contains("\"identity\"")
                    && body.contains("\"mac\"")
                    && body.contains("\"ip\"")
                {
                    Ok("{\"synced\":1}".to_string())
                } else {
                    Err("`mac`과 `ip` 항목을 입력해야 합니다".to_string())
                }
            }),
            dhcp_static_list: Box::new(|| {
                "{\"available\":true,\"reservations\":[{\"identity\":\"mac:aabbccddeeff\",\"ip\":\"192.168.1.200\",\"hostname\":\"printer\"}]}".to_string()
            }),
            dhcp_static_add: Box::new(|body| {
                if body.contains("\"identity\"") && body.contains("\"ip\"") {
                    Ok("{\"added\":true}".to_string())
                } else {
                    Err("`mac`과 `ip` 항목을 입력해야 합니다".to_string())
                }
            }),
            dhcp_static_remove: Box::new(|identity| {
                if identity == "mac:aabbccddeeff" {
                    Ok("{\"removed\":true}".to_string())
                } else {
                    Err(format!("고정 할당 항목을 찾을 수 없습니다: {identity}"))
                }
            }),
            client_add: Box::new(|body| {
                if body.contains("\"name\"") {
                    Ok("{\"added\":true,\"reloading\":true}".to_string())
                } else {
                    Err("`name` 항목을 입력해야 합니다".to_string())
                }
            }),
            client_remove: Box::new(|name| {
                if name == "kid" {
                    Ok("{\"removed\":true,\"reloading\":true}".to_string())
                } else {
                    Err(format!("클라이언트를 찾을 수 없습니다: {name}"))
                }
            }),
            client_update: Box::new(|_| Ok("{\"updated\":true}".to_string())),
            password_change: Box::new(|_, _| Ok("{\"changed\":true}".to_string())),
            user_create: Box::new(|_, _| Ok("{\"created\":true}".to_string())),
            upstream_add: Box::new(|u| {
                if u.is_empty() {
                    Err("추가할 업스트림 DNS 서버 주소가 비어 있습니다".to_string())
                } else {
                    Ok("{\"added\":true,\"reloading\":true}".to_string())
                }
            }),
            upstream_remove: Box::new(|_| Ok("{\"removed\":true,\"reloading\":true}".to_string())),
            explain: Box::new(|body| {
                if body.contains("\"qname\"") {
                    "{\"decision\":\"block\",\"rcode\":\"NXDOMAIN\",\"filter_stage\":\"block\",\"backend\":\"forward\",\"dnssec\":false}".to_string()
                } else {
                    "{\"error\":\"qname is required\"}".to_string()
                }
            }),
            cluster_status: Box::new(|| {
                "{\"self\":{\"id\":null,\"role\":\"standalone\",\"backend\":\"unknown\",\"listeners\":0,\"leader\":null,\"term\":null,\"commit_index\":null,\"last_applied\":null,\"last_index\":null,\"snapshot_index\":null,\"retained_log_entries\":null,\"fatal\":null,\"healthy\":true,\"version\":null},\"peers\":[]}".to_string()
            }),
            cluster_propose: Box::new(|body| {
                if body.contains('{') {
                    Ok("{\"proposed\":true,\"index\":1}".to_string())
                } else {
                    Err("Raft 고가용성 기능이 설정되어 있지 않습니다".to_string())
                }
            }),
            cluster_write: Box::new(|_, _, _, dispatch| dispatch()),
            listeners_status: Box::new(|| "[]".to_string()),
            net_adapters: Box::new(|| Ok("{\"adapters\":[],\"platform\":\"test\"}".to_string())),
            firewall_set: Box::new(|_| Ok("{\"ok\":true}".to_string())),
            dns_client_set: Box::new(|_| Ok("{\"ok\":true}".to_string())),
            dns_client_restore: Box::new(|_| Ok("{\"ok\":true}".to_string())),
            // Mimics an unsupported OS, the same answer as the default callback.
            resolve_probe: Box::new(|_| Err("DNS 수신 주소가 없습니다".to_string())),
            boot_service_status: Box::new(|| {
                "{\"supported\":false,\"installed\":false,\"running\":false}".to_string()
            }),
            boot_service_set: Box::new(|_| {
                Err("부팅 서비스 등록은 Windows에서만 됩니다".to_string())
            }),
            update_status: Box::new(|| {
                "{\"participating\":true,\"result\":\"available\",\"new_version\":\"9.9.9\"}"
                    .to_string()
            }),
            update_check: Box::new(|| Ok("{\"id\":1,\"status\":\"running\"}".to_string())),
            update_apply: Box::new(|version| {
                if version == "9.9.9" {
                    Ok("{\"id\":2,\"status\":\"running\"}".to_string())
                } else {
                    Err(format!("The last check found version 9.9.9, not {version}"))
                }
            }),
            update_rollback: Box::new(|| {
                Err("There is no committed update to roll back".to_string())
            }),
            metrics_extra: Box::new(|| {
                "onetdns_transport_errors_total{transport=\"doh\",stage=\"accept\"} 3\n".to_string()
            }),
        };
        AppState {
            stats,
            auth: Arc::new(Auth::new(
                vec![admin.to_string().into()],
                vec![readonly.to_string().into()],
            )),
            audit: AuditLog::new(100),
            controls: Arc::new(controls),
            readiness: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            proxy: Arc::new(ArcSwap::from_pointee(ProxyPolicy::default())),
        }
    }

    const TEST_SETUP_CODE: &str = "test-setup-code";
    const TEST_SETUP_FILE: &str = "/etc/onetdns/setup-code.txt";

    /// Reproduces the first-run screen: no accounts and a setup code issued.
    fn state_without_accounts(
        user_create: Box<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>,
    ) -> AppState {
        let base = test_state("adm", "ro");
        let mut controls = Controls::noop();
        controls.user_create = user_create;
        let auth = Auth::new(vec![], vec![]);
        auth.set_setup_code(TEST_SETUP_CODE, TEST_SETUP_FILE.to_string());
        AppState {
            auth: Arc::new(auth),
            controls: Arc::new(controls),
            ..base
        }
    }

    fn setup_request(st: &AppState, body: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let request = format!(
            "POST /v1/setup HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = accept_before_deadline(&listener).expect("accept setup request");
                handle_conn(stream, st).unwrap();
            });
            let mut client = TcpStream::connect(addr).unwrap();
            client.write_all(request.as_bytes()).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            let mut response = String::new();
            std::io::Read::read_to_string(&mut client, &mut response).unwrap();
            response
        })
    }

    fn raw_control_request(request: &[u8]) -> String {
        let st = test_state("adm", "ro");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_conn(stream, &st).unwrap();
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(request).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        std::io::Read::read_to_string(&mut client, &mut response).unwrap();
        server.join().unwrap();
        response
    }

    #[test]
    /// Ambiguous body framing is what request smuggling exploits.
    fn ambiguous_http_syntax_is_rejected() {
        for request in [
            b"GET\t/v1/auth HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
            b"GET /v1/auth HTTP/1.1\nHost: localhost\n\n".as_slice(),
            b"GET /v1/auth HTTP/1.1\r\nHost: localhost\r\nX-Test\x01: ignored\r\n\r\n".as_slice(),
            b"GET /v1/auth HTTP/1.1\r\nHost: localhost\r\nContent-Length: +0\r\n\r\n".as_slice(),
        ] {
            let response = raw_control_request(request);
            assert!(
                response.starts_with("HTTP/1.1 400 Bad Request"),
                "ambiguous request was accepted: {response}"
            );
        }
    }

    #[test]
    /// Without stripping, one parameter on the console URL gives 404, and a health check calling
    /// with `?src=lb` gets 401 and reports the service dead.
    fn a_query_string_does_not_change_which_route_answers() {
        for (target, expected) in [
            ("/?utm_source=mail", "HTTP/1.1 200 OK"),
            ("/healthz?src=lb", "HTTP/1.1 200 OK"),
            ("/readyz?probe=1", "HTTP/1.1 200 OK"),
            ("/v1/auth?t=1", "HTTP/1.1 200 OK"),
            ("/nope?x=1", "HTTP/1.1 401 Unauthorized"),
        ] {
            let request = format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n");
            let response = raw_control_request(request.as_bytes());
            assert!(
                response.starts_with(expected),
                "{target} 응답이 {expected}가 아님: {}",
                response.lines().next().unwrap_or_default()
            );
        }
    }

    #[test]
    /// Left open after an account exists, anyone could add another admin.
    fn first_run_setup_creates_one_admin_and_then_closes() {
        let created = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(String, String)>::new()));
        let seen = created.clone();
        let st = state_without_accounts(Box::new(move |name, hash| {
            seen.lock_recover()
                .push((name.to_string(), hash.to_string()));
            Ok("{\"created\":true}".to_string())
        }));
        assert!(
            !st.auth.has_users(),
            "테스트는 계정이 없는 상태에서 시작한다"
        );

        let body =
            "{\"user\":\"owner\",\"password\":\"correct-horse-battery\",\"code\":\"test-setup-code\"}";
        let first = setup_request(&st, body);
        assert!(
            first.starts_with("HTTP/1.1 200 OK"),
            "첫 계정 만들기가 실패함: {}",
            first.lines().next().unwrap_or_default()
        );
        assert!(
            first.contains("Set-Cookie: onetdns_session="),
            "계정을 만들고 로그인되지 않음: {first}"
        );
        assert_eq!(
            created.lock_recover().len(),
            1,
            "설정 파일 기록이 한 번이 아님"
        );

        let second = setup_request(
            &st,
            "{\"user\":\"other\",\"password\":\"another-long-secret\"}",
        );
        assert!(
            second.starts_with("HTTP/1.1 409 Conflict"),
            "계정이 생긴 뒤에도 설정 경로가 열려 있음: {}",
            second.lines().next().unwrap_or_default()
        );
        assert_eq!(
            created.lock_recover().len(),
            1,
            "닫힌 뒤에도 설정 파일을 다시 고침"
        );
    }

    #[test]
    fn first_run_setup_rejects_weak_credentials() {
        let st =
            state_without_accounts(Box::new(|_, _| panic!("거부된 요청이 설정 파일에 닿았다")));
        for body in [
            "{\"user\":\"\",\"password\":\"correct-horse-battery\",\"code\":\"test-setup-code\"}",
            "{\"user\":\"owner\",\"password\":\"short\",\"code\":\"test-setup-code\"}",
            "{\"user\":\"ow\\\"ner\",\"password\":\"correct-horse-battery\",\"code\":\"test-setup-code\"}",
        ] {
            let response = setup_request(&st, body);
            assert!(
                response.starts_with("HTTP/1.1 400 Bad Request"),
                "{body} 가 거부되지 않음: {}",
                response.lines().next().unwrap_or_default()
            );
        }
    }

    #[test]
    /// Browsers request this path on their own; a 401 would make admins read their own browser's
    /// lines as break-in attempts.
    fn the_tab_icon_is_served_without_authentication() {
        let response = raw_control_request(b"GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "탭 아이콘이 인증을 요구함: {}",
            response.lines().next().unwrap_or_default()
        );
        assert!(
            response.contains("Content-Type: image/svg+xml"),
            "탭 아이콘 형식이 잘못됨: {response}"
        );
    }

    #[test]
    fn plain_text_answers_declare_utf8_on_the_routed_path() {
        let response = raw_control_request(b"GET /nope HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(
            response.contains("Content-Type: text/plain; charset=utf-8"),
            "라우팅 경로의 한국어 응답에 charset이 없음: {response}"
        );
    }

    #[test]
    fn generation_shutdown_lets_inflight_request_finish() {
        use std::io::{Read as _, Write as _};
        use std::sync::atomic::{AtomicBool, Ordering};

        let (_rec, stats) = channel(8, 100, 0, RecorderOpts::default(), PersistOpts::default());
        let mut controls = Controls::noop();
        controls.net_adapters = Box::new(|| {
            std::thread::sleep(Duration::from_millis(400));
            Ok("{\"platform\":\"test\",\"adapters\":[]}".to_string())
        });
        let state = AppState {
            stats,
            auth: Arc::new(Auth::single_admin("tok".into())),
            audit: AuditLog::new(100),
            controls: Arc::new(controls),
            readiness: Arc::new(AtomicBool::new(true)),
            proxy: Arc::new(ArcSwap::from_pointee(ProxyPolicy::default())),
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let sd = shutdown.clone();
        let server = std::thread::spawn(move || serve_listener(listener, state, sd).unwrap());

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let req = format!(
            "GET /v1/system/network-adapters HTTP/1.1\r\nHost: {addr}\r\n\
             Authorization: Bearer tok\r\nConnection: close\r\n\r\n"
        );
        client.write_all(req.as_bytes()).unwrap();

        std::thread::sleep(Duration::from_millis(120));
        shutdown.store(true, Ordering::Relaxed);

        let mut resp = Vec::new();
        client.read_to_end(&mut resp).unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(
            text.starts_with("HTTP/1.1 200"),
            "진행 중 요청이 리셋되지 않고 완료돼야 함: {:?}",
            &text[..text.len().min(60)]
        );
        assert!(text.contains("\"adapters\""), "어댑터 본문 포함돼야 함");

        server.join().unwrap();
    }

    fn call(st: &AppState, m: &str, p: &str, tok: &str, body: &str) -> (u16, String) {
        let auth = if tok.is_empty() {
            String::new()
        } else {
            format!("Bearer {tok}")
        };
        let (s, _ct, b) = route(m, p, &auth, "", body, &Caller::direct(None), st);
        (status_code(s), b)
    }

    fn call_session(st: &AppState, m: &str, p: &str, session: &str, body: &str) -> (u16, String) {
        let (s, _ct, b) = route(m, p, "", session, body, &Caller::direct(None), st);
        (status_code(s), b)
    }

    #[test]
    fn mutations_are_rejected_until_service_is_ready() {
        let st = test_state("adm", "ro");
        st.readiness
            .store(false, std::sync::atomic::Ordering::Release);
        let (status, body) = call(
            &st,
            "POST",
            "/v1/block",
            "adm",
            r#"{"domain":"example.com"}"#,
        );
        assert_eq!(status, 503);
        assert!(body.contains("settings are being applied"));
        assert_eq!(call(&st, "GET", "/v1/stats", "adm", "").0, 200);
    }

    #[test]
    fn shutdown_joins_idle_control_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server_shutdown = shutdown.clone();
        let server = std::thread::spawn(move || {
            serve_listener(listener, test_state("adm", "ro"), server_shutdown).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(b"G").unwrap();
        std::thread::sleep(Duration::from_millis(150));
        let started = Instant::now();
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        server.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn openapi_is_public() {
        let st = test_state("adm", "ro");
        let (code, body) = call(&st, "GET", "/openapi.json", "", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"openapi\""));
        assert!(body.contains("/v1/backup"));
    }

    #[test]
    fn prometheus_exposes_fault_recovery_counters() {
        let text = metrics_text(&test_state("adm", "ro"));
        assert!(text.contains("onetdns_request_panics_total"));
        assert!(text.contains("onetdns_supervisor_restarts_total"));
    }

    #[test]
    fn prometheus_appends_extra_metrics_from_controls() {
        let text = metrics_text(&test_state("adm", "ro"));
        assert!(
            text.contains("onetdns_transport_errors_total{transport=\"doh\",stage=\"accept\"} 3")
        );
    }

    #[test]
    fn prometheus_exposes_cache_and_overload_counters() {
        let text = metrics_text(&test_state("adm", "ro"));
        assert!(text.contains("onetdns_cache_hits_total"));
        assert!(text.contains("onetdns_cache_lookups_total"));
        assert!(text.contains("onetdns_dropped_log_events_total"));
        assert!(text.contains("onetdns_dropped_stream_events_total"));
        assert!(text.contains("onetdns_persist_failures_total"));
    }

    #[test]
    /// Derived from `Action::ALL`, so a new disposition must be exported; a fixed list here would
    /// keep passing.
    fn prometheus_exports_every_query_disposition() {
        let text = metrics_text(&test_state("adm", "ro"));
        for action in crate::metrics::Action::ALL {
            let metric = format!("onetdns_{}_total", action.name());
            assert!(
                text.contains(&metric),
                "{metric}이 /metrics에 없습니다. 처분이 빠지면 총 질의 수가 처분 합과 어긋납니다"
            );
        }
    }

    #[test]
    /// A mismatch would advertise APIs that do not exist.
    fn openapi_covers_all_control_routes() {
        use std::collections::BTreeSet;

        let mut implemented = BTreeSet::new();
        for line in include_str!("api.rs").lines() {
            for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
                let marker = format!("(\"{method}\", \"");
                let Some(start) = line.find(&marker) else {
                    continue;
                };
                let rest = &line[start + marker.len()..];
                let Some(end) = rest.find('"') else {
                    continue;
                };
                let path = &rest[..end];
                if path.starts_with('/')
                    && !matches!(
                        path,
                        "/" | "/react.js" | "/react-dom.js" | "/support.js" | "/favicon.ico"
                    )
                {
                    implemented.insert((method.to_ascii_lowercase(), path.to_string()));
                }
            }
        }
        for (method, path) in [
            ("post", "/v1/setup"),
            ("post", "/v1/login"),
            ("post", "/v1/logout"),
            ("get", "/v1/dashboard/ws"),
            ("get", "/v1/stats/history/{range}"),
            ("get", "/v1/jobs/{id}"),
            ("get", "/v1/zones/{origin}"),
            ("put", "/v1/zones/{origin}"),
            ("delete", "/v1/zones/{origin}"),
            ("get", "/v1/zones/{origin}/dnssec"),
            ("post", "/v1/zones/{origin}/records"),
            ("delete", "/v1/zones/{origin}/records"),
        ] {
            implemented.insert((method.to_string(), path.to_string()));
        }

        let parsed = json::parse(&openapi_json()).expect("OpenAPI JSON must parse");
        let paths = match parsed.get("paths") {
            Some(json::Json::Obj(paths)) => paths,
            _ => panic!("OpenAPI paths object missing"),
        };
        let mut documented = BTreeSet::new();
        for (path, item) in paths {
            let json::Json::Obj(methods) = item else {
                panic!("OpenAPI path item must be an object");
            };
            for (method, _) in methods {
                if matches!(method.as_str(), "get" | "post" | "put" | "patch" | "delete") {
                    documented.insert((method.clone(), path.clone()));
                }
            }
        }
        assert_eq!(implemented, documented);
    }

    #[test]
    fn removed_unversioned_api_namespace_is_not_routed() {
        let st = test_state("adm", "ro");
        for [method, path] in [
            ["GET", "/api/auth"],
            ["POST", "/api/login"],
            ["POST", "/api/logout"],
            ["GET", "/api/dashboard/ws"],
            ["GET", "/api/stats"],
            ["GET", "/api/stats/history/60"],
            ["GET", "/api/metrics"],
            ["GET", "/api/queries"],
            ["GET", "/api/top"],
            ["GET", "/api/audit"],
            ["GET", "/api/backup"],
            ["GET", "/api/plugins"],
            ["POST", "/api/reload"],
            ["POST", "/api/block"],
            ["POST", "/api/allow"],
            ["POST", "/api/restore"],
            ["POST", "/api/service"],
            ["POST", "/api/safesearch"],
            ["POST", "/api/password"],
            ["POST", "/api/querylog/clear"],
        ] {
            assert_eq!(call(&st, method, path, "adm", "{}").0, 404, "{path}");
        }
    }

    #[test]
    fn user_login_session_grants_role_and_logout_revokes() {
        let auth = Auth::new(vec!["adm".into()], vec![]).with_users(vec![UserCred {
            name: "alice".into(),
            hash: hash_eventually("s3cret-passphrase").into(),
            role: Role::Admin,
        }]);

        assert!(matches!(
            login_eventually(&auth, "alice", "nope"),
            LoginResult::Invalid
        ));
        assert!(matches!(
            login_eventually(&auth, "bob", "s3cret-passphrase"),
            LoginResult::Invalid
        ));

        let LoginResult::Success(token, role, name) =
            login_eventually(&auth, "alice", "s3cret-passphrase")
        else {
            panic!("login ok");
        };
        assert_eq!(role, Role::Admin);
        assert_eq!(name, "alice");
        assert_eq!(auth.role_for_session(&token), Some(Role::Admin));

        let st = AppState {
            stats: {
                let (_r, s) = channel(8, 100, 0, RecorderOpts::default(), PersistOpts::default());
                s
            },
            auth: Arc::new(auth),
            audit: AuditLog::new(100),
            controls: Arc::new(Controls::noop()),
            readiness: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            proxy: Arc::new(ArcSwap::from_pointee(ProxyPolicy::default())),
        };
        let LoginResult::Success(session, _, _) =
            login_eventually(st.auth.as_ref(), "alice", "s3cret-passphrase")
        else {
            panic!("login ok");
        };
        assert_eq!(call_session(&st, "GET", "/v1/stats", &session, "").0, 200);

        st.auth.logout(&session);
        assert_eq!(call_session(&st, "GET", "/v1/stats", &session, "").0, 401);
    }

    #[test]
    fn auth_and_session_stores_keep_only_keyed_digests() {
        let bearer = "admin-token-that-must-not-be-stored";
        let auth = Auth::single_admin(bearer.into());
        let expected_bearer = credential_digest("token", &[bearer]);
        assert_eq!(auth.admin.lock_recover().as_slice(), &[expected_bearer]);
        assert_eq!(auth.role_for(bearer), Some(Role::Admin));

        let store = auth.sessions.clone();
        let session = auth.issue_session(Role::Admin, "admin".into(), bearer_actor(bearer));
        let expected_session = credential_digest("session", &[&session]);
        assert!(store.0.lock_recover().contains_key(&expected_session));
        assert!(store.checkpoint().0.contains_key(&expected_session));
    }

    #[test]
    fn login_throttle_isolates_users_but_caps_rotation_per_source() {
        let auth = Auth::default();
        let source = "127.0.0.1";
        for _ in 0..MAX_LOGIN_FAILURES {
            auth.record_login_result(source, None, "alice", false);
        }
        assert!(
            !auth.login_allowed(source, None, "alice"),
            "실패가 누적된 사용자만 차단"
        );
        assert!(
            auth.login_allowed(source, None, "bob"),
            "다른 사용자의 로그인은 막지 않음"
        );

        for i in 0..MAX_SOURCE_LOGIN_FAILURES {
            auth.record_login_result(source, None, &format!("ghost{i}"), false);
        }
        assert!(
            !auth.login_allowed(source, None, "bob"),
            "사용자명 회전은 소스 집계로 차단"
        );
        assert!(
            auth.login_allowed("192.0.2.9", None, "bob"),
            "다른 소스는 영향 없음"
        );
    }

    #[test]
    fn shared_session_store_survives_auth_rebuild() {
        let store = SessionStore::default();
        let auth1 = Auth::single_admin("tok".into()).with_sessions(store.clone());
        let actor = bearer_actor("tok");
        let session = auth1.issue_session(Role::Admin, actor.clone(), actor);

        let auth2 = Auth::single_admin("tok".into()).with_sessions(store);
        assert_eq!(auth2.role_for_session(&session), Some(Role::Admin));

        auth2.logout(&session);
        assert_eq!(auth1.role_for_session(&session), None);
    }

    #[test]
    fn session_checkpoint_restores_sessions_after_failed_auth_rebuild() {
        let store = SessionStore::default();
        let auth1 = Auth::single_admin("old-token".into()).with_sessions(store.clone());
        let actor = bearer_actor("old-token");
        let session = auth1.issue_session(Role::Admin, actor.clone(), actor);
        let checkpoint = store.checkpoint();

        let auth2 = Auth::single_admin("new-token".into()).with_sessions(store.clone());
        assert_eq!(auth2.role_for_session(&session), None);
        store.restore(checkpoint);
        assert_eq!(auth1.role_for_session(&session), Some(Role::Admin));
    }

    #[test]
    fn shared_session_store_drops_removed_bearer_credentials() {
        let store = SessionStore::default();
        let auth1 = Auth::single_admin("old-token".into()).with_sessions(store.clone());
        let actor = bearer_actor("old-token");
        let session = auth1.issue_session(Role::Admin, actor.clone(), actor);

        let auth2 = Auth::single_admin("new-token".into()).with_sessions(store);
        assert_eq!(auth2.role_for_session(&session), None);
    }

    #[test]
    fn shared_session_store_drops_changed_user_credentials() {
        let store = SessionStore::default();
        let old_user = UserCred {
            name: "alice".into(),
            hash: "old-password-hash".into(),
            role: Role::Admin,
        };
        let auth1 = Auth::new(vec![], vec![])
            .with_users(vec![old_user.clone()])
            .with_sessions(store.clone());
        let session = auth1.issue_session(
            old_user.role,
            old_user.name.clone(),
            user_credential_id(&old_user),
        );

        let new_user = UserCred {
            name: "alice".into(),
            hash: "new-password-hash".into(),
            role: Role::ReadOnly,
        };
        let auth2 = Auth::new(vec![], vec![])
            .with_users(vec![new_user])
            .with_sessions(store);
        assert_eq!(auth2.role_for_session(&session), None);
    }

    /// If the test client dies on a failed assertion, no connection comes; without a deadline the
    /// test would hang instead of failing.
    fn accept_before_deadline(listener: &TcpListener) -> std::io::Result<(TcpStream, SocketAddr)> {
        let deadline = Instant::now() + Duration::from_secs(10);
        listener.set_nonblocking(true)?;
        loop {
            match listener.accept() {
                Ok(pair) => {
                    listener.set_nonblocking(false)?;
                    pair.0.set_nonblocking(false)?;
                    return Ok(pair);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        listener.set_nonblocking(false)?;
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "테스트 연결을 기다리다 데드라인을 넘겼습니다",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => {
                    listener.set_nonblocking(false)?;
                    return Err(error);
                }
            }
        }
    }

    #[test]
    /// Control tokens are API-only: they must not become browser credentials, yet API clients
    /// still need live subscriptions.
    fn a_control_token_authenticates_the_websocket_without_becoming_a_cookie() {
        let st = test_state("adm", "ro");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("test listener address");
        listener
            .set_nonblocking(false)
            .expect("blocking test listener");

        std::thread::scope(|scope| {
            let server = scope.spawn(|| {
                for _ in 0..2 {
                    let Ok((stream, _)) = accept_before_deadline(&listener) else {
                        return;
                    };
                    match handle_conn(stream, &st) {
                        Ok(()) => {}

                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::BrokenPipe
                                    | std::io::ErrorKind::ConnectionAborted
                            ) => {}
                        Err(e) => panic!("handle test request: {e:?}"),
                    }
                }
            });

            let mut auth_client = TcpStream::connect(addr).expect("connect auth client");
            let auth_request = concat!(
                "GET /v1/auth HTTP/1.1\r\n",
                "Host: localhost\r\n",
                "Authorization: Bearer adm\r\n",
                "Connection: close\r\n",
                "\r\n"
            );
            std::io::Write::write_all(&mut auth_client, auth_request.as_bytes())
                .expect("write auth request");
            let mut auth_response = String::new();
            std::io::Read::read_to_string(&mut auth_client, &mut auth_response)
                .expect("read auth response");
            assert!(
                auth_response.starts_with("HTTP/1.1 200 OK"),
                "{auth_response}"
            );
            assert!(
                auth_response.contains("\"authenticated\":true"),
                "API 호출자에게 역할은 알려 줍니다: {auth_response}"
            );
            assert!(
                !auth_response.contains("Set-Cookie:"),
                "제어 토큰은 브라우저 세션으로 바뀌면 안 됩니다: {auth_response}"
            );

            let mut ws_client = TcpStream::connect(addr).expect("connect websocket client");
            ws_client
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .expect("set websocket read timeout");
            let ws_request = concat!(
                "GET /v1/dashboard/ws HTTP/1.1\r\n",
                "Host: localhost\r\n",
                "Upgrade: websocket\r\n",
                "Connection: Upgrade\r\n",
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
                "Sec-WebSocket-Version: 13\r\n",
                "Sec-WebSocket-Protocol: onetdns.v1\r\n",
                "Authorization: Bearer adm\r\n",
                "\r\n"
            )
            .to_string();
            std::io::Write::write_all(&mut ws_client, ws_request.as_bytes())
                .expect("write websocket request");

            let mut header = Vec::new();
            let mut byte = [0u8; 1];
            while !header.ends_with(b"\r\n\r\n") {
                std::io::Read::read_exact(&mut ws_client, &mut byte)
                    .expect("read websocket response header");
                header.push(byte[0]);
                assert!(header.len() < 8192, "oversized websocket response header");
            }
            let header = String::from_utf8(header).expect("websocket header UTF-8");
            assert!(
                header.starts_with("HTTP/1.1 101 Switching Protocols"),
                "{header}"
            );
            assert!(
                header.contains("Sec-WebSocket-Protocol: onetdns.v1"),
                "{header}"
            );

            std::io::Write::write_all(
                &mut ws_client,
                &[0x88, 0x82, 0x01, 0x02, 0x03, 0x04, 0x02, 0xEA],
            )
            .expect("write websocket close frame");
            drop(ws_client);

            server.join().expect("join test server");
        });
    }

    #[test]
    fn diagnostic_post_requests_do_not_take_the_mutation_lock() {
        for path in [
            "/v1/config/validate",
            "/v1/config/diff",
            "/v1/config/set/diff",
            "/v1/explain",
            "/v1/policies/simulate",
            "/v1/tls/validate",
            "/v1/tls/revocation-check",
            "/v1/upstreams/test",
        ] {
            assert!(!is_state_changing_request("POST", path), "{path}");
        }
        assert!(is_state_changing_request("POST", "/v1/config/set"));
        assert!(is_state_changing_request("PATCH", "/v1/clients"));
        assert!(!is_state_changing_request("GET", "/v1/config"));
    }

    #[test]
    fn raft_proposals_use_log_ordering_instead_of_the_http_mutation_lock() {
        assert!(is_state_changing_request("POST", "/v1/cluster/propose"));
        assert!(!requires_control_mutation_lock(
            "POST",
            "/v1/cluster/propose"
        ));
        assert!(requires_control_mutation_lock("POST", "/v1/config/set"));
    }

    #[test]
    fn text_responses_declare_utf8() {
        assert_eq!(with_charset("text/plain"), "text/plain; charset=utf-8");
        assert_eq!(
            with_charset("text/plain; version=0.0.4"),
            "text/plain; version=0.0.4; charset=utf-8"
        );
        assert_eq!(
            with_charset("text/html; charset=utf-8"),
            "text/html; charset=utf-8",
            "이미 밝혔으면 덧붙이지 않습니다"
        );
        assert_eq!(
            with_charset("application/json"),
            "application/json",
            "JSON은 규격상 UTF-8이라 붙이지 않습니다"
        );
    }

    #[test]
    fn a_control_token_never_becomes_a_browser_session() {
        let st = test_state("adm", "ro");
        let (code, body) = call(&st, "GET", "/v1/auth", "adm", "");
        assert_eq!(code, 200);
        assert!(
            body.contains("\"authenticated\":true"),
            "API 호출자에게는 역할을 알려 줍니다: {body}"
        );
        assert!(
            st.auth.role_for_session("adm").is_none(),
            "토큰 값 자체가 세션으로 통해서는 안 됩니다"
        );
    }

    #[test]
    /// The sign-in screen checks this first.
    fn auth_status_endpoint_is_public() {
        let st = test_state("adm", "ro");
        let (code, body) = call(&st, "GET", "/v1/auth", "", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"login_enabled\":false"));
        assert!(body.contains("\"authenticated\":false"));
        for _ in 0..3 {
            call(&st, "GET", "/v1/auth", "", "");
        }
        let (_, audit) = call(&st, "GET", "/v1/audit", "adm", "");
        assert!(
            !audit.contains("\"actor\":\"anonymous\""),
            "인증 없는 상태 확인이 감사 기록을 채우면 안 됩니다: {audit}"
        );
    }

    #[test]
    fn rbac_unauthenticated_401() {
        let st = test_state("adm", "ro");
        assert_eq!(call(&st, "GET", "/v1/stats", "", "").0, 401);
        assert_eq!(call(&st, "GET", "/v1/stats", "wrong", "").0, 401);
    }

    #[test]
    fn repeated_failures_are_counted_and_diagnostics_are_not_mutations() {
        let st = test_state("adm", "ro");
        // The counter is process-wide, so a real path would mix in 401s from tests running in
        // parallel.
        let probe = "/v1/__repeated_failure_probe";
        let before = request_failure_count("POST", probe, 401);
        for _ in 0..20 {
            assert_eq!(call(&st, "POST", probe, "", "{}").0, 401);
        }
        assert_eq!(
            request_failure_count("POST", probe, 401),
            before + 20,
            "실패를 세지 않으면 억제할 기준이 없습니다"
        );

        for path in ["/v1/resolve", "/v1/explain", "/v1/policies/simulate"] {
            assert!(
                !is_state_changing_request("POST", path),
                "{path}는 아무것도 바꾸지 않습니다"
            );
        }
        // Control: a real change stays a change.
        assert!(is_state_changing_request("POST", "/v1/block"));
        assert!(is_state_changing_request("DELETE", "/v1/tokens"));
    }

    #[test]
    fn request_failure_tracking_has_a_fixed_cardinality() {
        let mut counts = RequestFailureCounts::default();
        let method = "GET";
        for index in 0..MAX_REQUEST_FAILURE_COUNTS {
            let path = format!("/__failure_cardinality_probe/{index}");
            assert_eq!(counts.increment(method, &path, 404), 1);
        }
        assert_eq!(counts.counts.len(), MAX_REQUEST_FAILURE_COUNTS);
        assert_eq!(
            counts.increment(method, "/__failure_cardinality_probe/0", 404),
            2,
            "상한에 닿아도 이미 추적 중인 실패의 개별 횟수는 유지해야 합니다"
        );

        let mut sampled = Vec::new();
        for index in 1..=64_u64 {
            let path = format!("/__failure_cardinality_overflow/{index}");
            let count = counts.increment(method, &path, 404);
            assert_eq!(
                count, index,
                "상한 밖 실패는 단일 포화 카운터로 묶어야 합니다"
            );
            if should_log_repeated_failure(count) {
                sampled.push(count);
            }
        }
        assert_eq!(counts.counts.len(), MAX_REQUEST_FAILURE_COUNTS);
        assert_eq!(sampled, [1, 2, 4, 8, 16, 32, 64]);
    }

    #[test]
    /// The default callback reports no listen address, so only the role check is tested.
    fn resolving_a_name_is_allowed_for_readonly_sessions() {
        let st = test_state("adm", "ro");
        assert_ne!(
            call(
                &st,
                "POST",
                "/v1/resolve",
                "ro",
                "{\"qname\":\"example.com\"}"
            )
            .0,
            403,
            "읽기 전용이 이름을 물어보지 못하면 안 됩니다"
        );
        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/resolve",
                "",
                "{\"qname\":\"example.com\"}"
            )
            .0,
            401,
            "인증 없이 물어봐서는 안 됩니다"
        );
    }

    #[test]
    /// Read-only callers see the status so the dashboard knows what to show; registering a service
    /// that starts on every boot is admin-only. The default callback reports unsupported.
    fn boot_service_is_admin_only_and_reports_unsupported_platforms() {
        let st = test_state("adm", "ro");

        let (code, body) = call(&st, "GET", "/v1/system/service", "ro", "");
        assert_eq!(code, 200, "상태 조회는 읽기 전용도 됩니다");
        assert!(
            body.contains("\"supported\":false"),
            "지원하지 않는 운영체제라고 알려야 합니다: {body}"
        );

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/system/service",
                "ro",
                "{\"action\":\"install\"}"
            )
            .0,
            403,
            "읽기 전용이 서비스를 등록해서는 안 됩니다"
        );
        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/system/service",
                "",
                "{\"action\":\"install\"}"
            )
            .0,
            401,
            "인증 없이 서비스를 등록해서는 안 됩니다"
        );
        assert_eq!(
            call(&st, "GET", "/v1/system/service", "", "").0,
            401,
            "인증 없이 상태를 봐서는 안 됩니다"
        );

        let (code, body) = call(
            &st,
            "POST",
            "/v1/system/service",
            "adm",
            "{\"action\":\"install\"}",
        );
        assert_eq!(code, 400, "지원하지 않는 곳에서는 실패로 답해야 합니다");
        assert!(
            body.contains("Windows"),
            "어디서 되는지 알려야 합니다: {body}"
        );
    }

    #[test]
    /// A missing version is 400; a version differing from the last check, or a job the current
    /// state cannot run, is 409.
    fn update_routes_check_roles_and_the_confirmed_version() {
        let st = test_state("adm", "ro");
        assert_eq!(call(&st, "GET", "/v1/system/update", "ro", "").0, 200);
        assert_eq!(call(&st, "GET", "/v1/system/update", "", "").0, 401);
        for path in [
            "/v1/system/update/check",
            "/v1/system/update/apply",
            "/v1/system/update/rollback",
        ] {
            let body = "{\"version\":\"9.9.9\"}";
            assert_eq!(call(&st, "POST", path, "ro", body).0, 403, "{path}");
            assert_eq!(call(&st, "POST", path, "", body).0, 401, "{path}");
        }

        assert_eq!(
            call(&st, "POST", "/v1/system/update/check", "adm", "").0,
            200
        );
        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/system/update/apply",
                "adm",
                "{\"version\":\"9.9.9\"}"
            )
            .0,
            200
        );
        for body in ["", "{}", "{\"version\":\"\"}", "{\"version\":9}"] {
            assert_eq!(
                call(&st, "POST", "/v1/system/update/apply", "adm", body).0,
                400,
                "{body}"
            );
        }
        let (code, body) = call(
            &st,
            "POST",
            "/v1/system/update/apply",
            "adm",
            "{\"version\":\"9.9.8\"}",
        );
        assert_eq!(code, 409);
        assert!(body.contains("9.9.9"), "{body}");
        assert_eq!(
            call(&st, "POST", "/v1/system/update/rollback", "adm", "").0,
            409
        );
    }

    #[test]
    /// A node-local job that changes no config; through consensus it would be refused on followers
    /// or fail while the config file is unreadable.
    fn update_routes_do_not_go_through_cluster_write() {
        let base = test_state("adm", "ro");
        let mut controls = Controls::noop();
        controls.cluster_write = Box::new(|_, _, _, _| {
            (
                "503 Service Unavailable",
                "application/json",
                "{\"error\":\"cluster\"}".to_string(),
            )
        });
        controls.update_check = Box::new(|| Ok("{\"id\":1,\"status\":\"running\"}".to_string()));
        controls.update_apply = Box::new(|_| Ok("{\"id\":2,\"status\":\"running\"}".to_string()));
        controls.update_rollback = Box::new(|| Ok("{\"id\":3,\"status\":\"running\"}".to_string()));
        let st = AppState {
            controls: Arc::new(controls),
            ..base
        };

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/block",
                "adm",
                "{\"domain\":\"example.com\"}"
            )
            .0,
            503,
            "설정을 바꾸는 요청은 합의를 거칩니다"
        );
        for (path, body) in [
            ("/v1/system/update/check", ""),
            ("/v1/system/update/apply", "{\"version\":\"9.9.9\"}"),
            ("/v1/system/update/rollback", ""),
        ] {
            assert_eq!(call(&st, "POST", path, "adm", body).0, 200, "{path}");
        }
    }

    #[test]
    fn rbac_readonly_can_get_but_not_mutate() {
        let st = test_state("adm", "ro");
        assert_eq!(
            call(&st, "GET", "/v1/stats", "ro", "").0,
            200,
            "readonly GET 허용"
        );
        let (code, _) = call(&st, "POST", "/v1/block", "ro", "{\"domain\":\"x.com\"}");
        assert_eq!(code, 403, "readonly POST 금지");
    }

    #[test]
    /// Values can hold secrets.
    fn audit_detail_lists_changed_keys_without_secret_values() {
        let detail = audit_request_detail(
            "POST",
            "/v1/config/set",
            r#"{"password":"do-not-log","safe_search":true,"port":53,"url":"https://user:secret@example.test/path?token=hidden"}"#,
        );
        assert!(detail.contains("changed_keys=password,port,safe_search,url"));
        assert!(detail.contains("port=53"));
        assert!(!detail.contains("do-not-log"));
        assert!(!detail.contains("secret"));
        assert!(!detail.contains("hidden"));
        assert!(!detail.contains("example.test"));
    }

    #[test]
    /// Recording a connection test or validation as changed keys would read as a config change.
    fn audit_detail_labels_diagnostic_request_fields_separately() {
        let detail = audit_request_detail("POST", "/v1/upstreams/test", r#"{"addr":"1.1.1.1"}"#);
        assert_eq!(detail, "request_keys=addr");
        let detail = audit_request_detail("POST", "/v1/upstreams", r#"{"addr":"1.1.1.1"}"#);
        assert_eq!(detail, "changed_keys=addr");
    }

    #[test]
    fn audit_detail_reports_non_json_body_size() {
        let detail = audit_request_detail("POST", "/v1/config/apply", "mode = \"public\"");
        assert!(detail.starts_with("body_bytes="));
    }

    #[test]
    fn rbac_admin_can_mutate_and_is_audited() {
        let st = test_state("adm", "ro");
        let (code, _) = call(&st, "POST", "/v1/block", "adm", "{\"domain\":\"ads.com\"}");
        assert_eq!(code, 200, "admin POST 허용");

        let (_, audit) = call(&st, "GET", "/v1/audit", "adm", "");
        assert!(audit.contains("\"path\":\"/v1/block\""));
        assert!(audit.contains("\"actor\":\"token-"));
        assert!(audit.contains("\"role\":\"admin\""));
        assert!(audit.contains("\"status\":200"));
    }

    #[test]
    fn audit_records_denials() {
        let st = test_state("adm", "ro");
        call(&st, "GET", "/v1/stats", "badtoken", "");
        call(&st, "POST", "/v1/block", "ro", "{\"domain\":\"x\"}");
        let (_, audit) = call(&st, "GET", "/v1/audit", "adm", "");
        assert!(audit.contains("\"status\":401"), "401 기록");
        assert!(audit.contains("\"role\":\"none\""));
        assert!(audit.contains("\"status\":403"), "403 기록");
    }

    #[test]
    fn backup_restore_roundtrip() {
        let st = test_state("adm", "ro");
        call(&st, "POST", "/v1/block", "adm", "{\"domain\":\"a.com\"}");
        call(&st, "POST", "/v1/block", "adm", "{\"domain\":\"b.com\"}");
        let (code, backup) = call(&st, "GET", "/v1/backup", "adm", "");
        assert_eq!(code, 200);
        assert!(backup.contains("a.com") && backup.contains("b.com"));

        let st2 = test_state("adm", "ro");
        let (code, resp) = call(&st2, "POST", "/v1/restore", "adm", &backup);
        assert_eq!(code, 200);
        assert!(resp.contains("\"block\":2"), "복원 후 block 2: {resp}");
    }

    #[test]
    fn zone_crud_roundtrip_and_rbac() {
        let st = test_state("adm", "ro");
        let zone_text = "$ORIGIN api.test.\n@ IN SOA ns1 admin 1 300 60 86400 60\n";

        let (code, body) = call(&st, "PUT", "/v1/zones/api.test", "adm", zone_text);
        assert_eq!(code, 200, "{body}");
        assert!(body.contains("\"origin\":\"api.test\""));

        let (code, body) = call(&st, "GET", "/v1/zones/api.test", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("api.test"));

        assert_eq!(
            call(&st, "PUT", "/v1/zones/api.test", "ro", zone_text).0,
            403
        );
        assert_eq!(call(&st, "DELETE", "/v1/zones/api.test", "ro", "").0, 403);

        assert_eq!(
            call(&st, "PUT", "/v1/zones/api.test", "adm", "bad zone").0,
            400
        );
        assert_eq!(
            call(&st, "POST", "/v1/zones/api.test", "adm", zone_text).0,
            405
        );

        assert_eq!(call(&st, "DELETE", "/v1/zones/api.test", "adm", "").0, 200);
        assert_eq!(call(&st, "GET", "/v1/zones/api.test", "adm", "").0, 404);

        let (_, audit) = call(&st, "GET", "/v1/audit", "adm", "");
        assert!(audit.contains("\"path\":\"/v1/zones/api.test\""));
    }

    #[test]
    fn effective_config_endpoint() {
        let st = test_state("adm", "ro");
        let (code, body) = call(&st, "GET", "/v1/config/effective", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"mode\""));

        assert_eq!(call(&st, "GET", "/v1/config/effective", "", "").0, 401);
    }

    #[test]
    fn readonly_can_read_backup_not_restore() {
        let st = test_state("adm", "ro");
        assert_eq!(call(&st, "GET", "/v1/backup", "ro", "").0, 200);
        assert_eq!(call(&st, "POST", "/v1/restore", "ro", "{}").0, 403);
    }

    #[test]
    fn jobs_endpoints() {
        let st = test_state("adm", "ro");

        let (code, body) = call(&st, "GET", "/v1/jobs", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"id\":1"));

        assert_eq!(call(&st, "GET", "/v1/jobs/1", "ro", "").0, 200);
        assert_eq!(call(&st, "GET", "/v1/jobs/999", "ro", "").0, 404);
        assert_eq!(call(&st, "GET", "/v1/jobs/abc", "ro", "").0, 400);

        assert_eq!(call(&st, "POST", "/v1/jobs/refresh", "adm", "").0, 200);
        assert_eq!(call(&st, "POST", "/v1/jobs/refresh", "ro", "").0, 403);
        assert_eq!(call(&st, "POST", "/v1/jobs/refresh", "", "").0, 401);
    }

    #[test]
    fn config_apply_rollback_endpoints() {
        let st = test_state("adm", "ro");

        assert_eq!(
            call(&st, "POST", "/v1/config/apply", "adm", "mode=\"personal\"").0,
            200
        );
        assert_eq!(call(&st, "POST", "/v1/config/apply", "adm", "bad").0, 400);

        assert_eq!(call(&st, "POST", "/v1/config/rollback", "adm", "").0, 200);

        assert_eq!(call(&st, "POST", "/v1/config/apply", "ro", "x").0, 403);
        assert_eq!(call(&st, "POST", "/v1/config/rollback", "", "").0, 401);
    }

    #[test]
    fn config_set_and_get_endpoints() {
        let st = test_state("adm", "ro");

        let (code, body) = call(&st, "POST", "/v1/config/set", "adm", "{\"prefetch\":true}");
        assert_eq!(code, 200);
        assert!(body.contains("\"applied\":true"));

        assert_eq!(
            call(&st, "POST", "/v1/config/set", "adm", "{\"bad\":1}").0,
            400
        );

        assert_eq!(
            call(&st, "POST", "/v1/config/set", "ro", "{\"prefetch\":true}").0,
            403
        );
        assert_eq!(
            call(&st, "POST", "/v1/config/set", "", "{\"prefetch\":true}").0,
            401
        );

        assert_eq!(call(&st, "GET", "/v1/config", "ro", "").0, 200);
    }

    #[test]
    fn schema_upstream_test_cache_flush_endpoints() {
        let st = test_state("adm", "ro");

        let (code, body) = call(&st, "GET", "/v1/config/schema", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"keys\""));

        let (c2, b2) = call(
            &st,
            "POST",
            "/v1/upstreams/test",
            "adm",
            "{\"addr\":\"1.1.1.1\"}",
        );
        assert_eq!(c2, 200);
        assert!(b2.contains("\"ok\""));
        assert_eq!(call(&st, "POST", "/v1/upstreams/test", "ro", "{}").0, 403);

        assert_eq!(call(&st, "POST", "/v1/cache/flush", "adm", "").0, 200);
        assert_eq!(call(&st, "POST", "/v1/cache/flush", "ro", "").0, 403);
    }

    #[test]
    fn token_crud_endpoints() {
        let st = test_state("adm", "ro");

        let (code, body) = call(&st, "GET", "/v1/tokens", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"tokens\""));
        assert!(body.contains("\"masked\""));

        let (c2, b2) = call(&st, "POST", "/v1/tokens", "adm", "{\"role\":\"readonly\"}");
        assert_eq!(c2, 200);
        assert!(b2.contains("\"token\""));
        assert!(b2.contains("\"id\""));

        assert_eq!(call(&st, "POST", "/v1/tokens", "ro", "{}").0, 403);

        let (c3, b3) = call(&st, "DELETE", "/v1/tokens", "adm", "{\"id\":\"ab12\"}");
        assert_eq!(c3, 200);
        assert!(b3.contains("\"removed\""));

        assert_eq!(
            call(&st, "DELETE", "/v1/tokens", "ro", "{\"id\":\"x\"}").0,
            403
        );
    }

    #[test]
    fn rewrites_services_access_tls_endpoints() {
        let st = test_state("adm", "ro");

        assert!(call(&st, "GET", "/v1/rewrites", "ro", "")
            .1
            .contains("router.lan"));
        let (c, b) = call(
            &st,
            "POST",
            "/v1/rewrites",
            "adm",
            "{\"domain\":\"x.lan\",\"answer\":\"10.0.0.9\"}",
        );
        assert_eq!(c, 200);
        assert!(b.contains("added"));
        assert_eq!(call(&st, "POST", "/v1/rewrites", "ro", "{}").0, 403);
        assert_eq!(
            call(
                &st,
                "DELETE",
                "/v1/rewrites",
                "adm",
                "{\"domain\":\"x.lan\"}"
            )
            .0,
            200
        );

        assert!(call(&st, "GET", "/v1/services", "ro", "")
            .1
            .contains("youtube"));
        assert!(call(&st, "GET", "/v1/access", "ro", "")
            .1
            .contains("allowed"));
        assert!(call(&st, "GET", "/v1/tls", "ro", "")
            .1
            .contains("configured"));
        assert_eq!(call(&st, "POST", "/v1/tls/validate", "adm", "").0, 200);
        assert_eq!(call(&st, "POST", "/v1/tls/validate", "ro", "").0, 403);

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/tls/configure",
                "adm",
                "{\"cert_path\":\"/c.pem\",\"key_path\":\"/k.pem\"}"
            )
            .0,
            200
        );
        assert_eq!(call(&st, "POST", "/v1/tls/configure", "adm", "{}").0, 400);
        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/tls/configure",
                "ro",
                "{\"key_path\":\"/k.pem\"}"
            )
            .0,
            403
        );

        let (code, body) = call(
            &st,
            "POST",
            "/v1/tls/revocation-check",
            "adm",
            "{\"certificate_chain\":\"-----BEGIN CERTIFICATE-----\"}",
        );
        assert_eq!(code, 200);
        assert!(body.contains("\"revoked\""));
        assert_eq!(
            call(&st, "POST", "/v1/tls/revocation-check", "adm", "{}").0,
            400
        );
        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/tls/revocation-check",
                "ro",
                "{\"certificate_chain\":\"x\"}"
            )
            .0,
            403
        );

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/acme/issue",
                "adm",
                "{\"account_only\":true}"
            )
            .0,
            200
        );
        assert_eq!(call(&st, "POST", "/v1/acme/issue", "adm", "{}").0, 400);
        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/acme/issue",
                "ro",
                "{\"account_only\":true}"
            )
            .0,
            403
        );
    }

    #[test]
    fn resource_endpoints() {
        let st = test_state("adm", "ro");

        let (code, body) = call(&st, "GET", "/v1/filter/subscriptions", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"urls\""));

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/filter/subscriptions",
                "adm",
                "{\"url\":\"https://x/y\"}"
            )
            .0,
            200
        );
        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/filter/subscriptions",
                "ro",
                "{\"url\":\"x\"}"
            )
            .0,
            403
        );
        assert_eq!(
            call(&st, "POST", "/v1/filter/subscriptions", "", "x").0,
            401
        );

        assert_eq!(
            call(
                &st,
                "DELETE",
                "/v1/filter/subscriptions",
                "adm",
                "{\"url\":\"x\"}"
            )
            .0,
            200
        );

        assert_eq!(call(&st, "GET", "/v1/clients", "ro", "").0, 200);
        assert_eq!(call(&st, "GET", "/v1/upstreams", "ro", "").0, 200);

        let (code, body) = call(&st, "GET", "/v1/dhcp/leases", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"v4\"") && body.contains("\"v6\""));
        let (code, body) = call(
            &st,
            "POST",
            "/v1/dhcp/leases",
            "adm",
            "{\"identity\":\"mac:aabbccddeeff\",\"mac\":\"aa:bb:cc:dd:ee:ff\",\"ip\":\"192.168.1.100\",\"expiry\":\"9999999999\"}",
        );
        assert_eq!(code, 200);
        assert!(body.contains("\"synced\""), "{body}");

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/dhcp/leases",
                "ro",
                "{\"identity\":\"mac:aabbccddeeff\",\"mac\":\"aa:bb:cc:dd:ee:ff\",\"ip\":\"192.168.1.100\",\"expiry\":\"9999999999\"}"
            )
            .0,
            403
        );
    }

    #[test]
    fn dhcp_static_reservation_crud() {
        let st = test_state("adm", "ro");

        let (code, body) = call(&st, "GET", "/v1/dhcp/static", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"reservations\""));

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/dhcp/static",
                "adm",
                "{\"identity\":\"mac:aabbccddeeff\",\"ip\":\"192.168.1.200\"}"
            )
            .0,
            200
        );

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/dhcp/static",
                "adm",
                "{\"ip\":\"192.168.1.200\"}"
            )
            .0,
            400
        );

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/dhcp/static",
                "ro",
                "{\"identity\":\"mac:aabbccddeeff\",\"ip\":\"192.168.1.200\"}"
            )
            .0,
            403
        );

        assert_eq!(
            call(
                &st,
                "DELETE",
                "/v1/dhcp/static",
                "adm",
                "{\"identity\":\"mac:aabbccddeeff\"}"
            )
            .0,
            200
        );
        assert_eq!(
            call(
                &st,
                "DELETE",
                "/v1/dhcp/static",
                "adm",
                "{\"identity\":\"mac:000000000000\"}"
            )
            .0,
            404
        );
    }

    #[test]
    fn clients_upstreams_crud() {
        let st = test_state("adm", "ro");

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/clients",
                "adm",
                "{\"name\":\"kid\",\"ids\":[\"192.168.1.5/32\"]}"
            )
            .0,
            200
        );
        assert_eq!(
            call(&st, "POST", "/v1/clients", "adm", "{\"ids\":[]}").0,
            400
        );
        assert_eq!(
            call(&st, "POST", "/v1/clients", "ro", "{\"name\":\"x\"}").0,
            403
        );
        assert_eq!(call(&st, "POST", "/v1/clients", "", "{}").0, 401);

        assert_eq!(
            call(&st, "DELETE", "/v1/clients", "adm", "{\"name\":\"kid\"}").0,
            200
        );
        assert_eq!(
            call(&st, "DELETE", "/v1/clients", "adm", "{\"name\":\"ghost\"}").0,
            400
        );

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/upstreams",
                "adm",
                "{\"addr\":\"9.9.9.9\"}"
            )
            .0,
            200
        );

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/upstreams",
                "adm",
                "{\"addr\":\"8.8.8.8\"}"
            )
            .0,
            200
        );
        assert_eq!(
            call(&st, "POST", "/v1/upstreams", "adm", "{\"addr\":\"\"}").0,
            400
        );
        assert_eq!(
            call(
                &st,
                "DELETE",
                "/v1/upstreams",
                "adm",
                "{\"addr\":\"9.9.9.9\"}"
            )
            .0,
            200
        );
        assert_eq!(
            call(&st, "POST", "/v1/upstreams", "ro", "{\"addr\":\"1.1.1.1\"}").0,
            403
        );
        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/upstreams",
                "adm",
                "{\"upstream\":\"1.1.1.1\"}"
            )
            .0,
            400
        );
        assert_eq!(call(&st, "POST", "/v1/upstreams", "adm", "1.1.1.1").0, 400);
    }

    #[test]
    fn explain_endpoint() {
        let st = test_state("adm", "ro");
        let (code, body) = call(
            &st,
            "POST",
            "/v1/explain",
            "adm",
            "{\"qname\":\"ads.example\",\"qtype\":\"A\"}",
        );
        assert_eq!(code, 200);
        assert!(body.contains("\"decision\"") && body.contains("\"rcode\""));
    }

    #[test]
    fn health_ready_cluster_endpoints() {
        let st = test_state("adm", "ro");

        assert_eq!(call(&st, "GET", "/healthz", "", "").0, 200);
        assert_eq!(call(&st, "GET", "/readyz", "", "").0, 200);

        let (code, body) = call(&st, "GET", "/v1/cluster/nodes", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"self\"") && body.contains("\"peers\""));

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/cluster/propose",
                "adm",
                "{\"patch\":{\"prefetch\":true}}"
            )
            .0,
            200
        );
        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/cluster/propose",
                "ro",
                "{\"patch\":{\"prefetch\":true}}"
            )
            .0,
            403
        );
    }

    #[test]
    fn zone_record_endpoints() {
        let st = test_state("adm", "ro");

        let (code, body) = call(
            &st,
            "POST",
            "/v1/zones/api.test/records",
            "adm",
            "www 300 IN A 1.2.3.4",
        );
        assert_eq!(code, 200);
        assert!(body.contains("\"added\""));

        let del = call(
            &st,
            "DELETE",
            "/v1/zones/api.test/records",
            "adm",
            "{\"name\":\"www\",\"type\":\"A\"}",
        );
        assert_eq!(del.0, 200);

        assert_eq!(
            call(&st, "POST", "/v1/zones/api.test/records", "ro", "x").0,
            403
        );
        assert_eq!(
            call(&st, "POST", "/v1/zones/api.test/records", "", "x").0,
            401
        );
        assert_eq!(
            call(&st, "GET", "/v1/zones/api.test/records", "adm", "").0,
            405
        );
        assert_eq!(
            call(
                &st,
                "PUT",
                "/v1/zones/api.test/records",
                "adm",
                "www 300 IN A 1.2.3.4"
            )
            .0,
            405
        );
    }

    #[test]
    fn zone_dnssec_endpoint() {
        let st = test_state("adm", "ro");
        let (code, body) = call(&st, "GET", "/v1/zones/api.test/dnssec", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"signed\""));
        assert!(body.contains("\"origin\":\"api.test\""));

        assert_eq!(call(&st, "GET", "/v1/zones/api.test/dnssec", "", "").0, 401);
        assert_eq!(
            call(&st, "POST", "/v1/zones/api.test/dnssec", "adm", "").0,
            405
        );
    }

    #[test]
    fn filter_report_endpoint() {
        let st = test_state("adm", "ro");
        let (code, body) = call(&st, "GET", "/v1/filter/report", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"rules_total\""));

        assert_eq!(call(&st, "GET", "/v1/filter/report", "", "").0, 401);
        assert_eq!(call(&st, "GET", "/v1/filter/compat", "ro", "").0, 404);
    }

    #[test]
    fn top_rules_endpoint() {
        let st = test_state("adm", "ro");
        let (code, body) = call(&st, "GET", "/v1/filter/top-rules", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"enabled\""));
        assert_eq!(call(&st, "GET", "/v1/filter/top-rules", "", "").0, 401);
    }

    #[test]
    fn repeated_cookie_header_fields_are_accepted_by_http_parser() {
        let st = test_state("adm", "ro");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("test listener address");

        std::thread::scope(|scope| {
            let server = scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accept test connection");
                handle_conn(stream, &st).expect("handle test request");
            });

            let mut client = TcpStream::connect(addr).expect("connect test client");
            let request = concat!(
                "GET /v1/auth HTTP/1.1\r\n",
                "Host: localhost\r\n",
                "Cookie: theme=dark\r\n",
                "Cookie: onetdns_session=stale\r\n",
                "Connection: close\r\n",
                "\r\n"
            );
            std::io::Write::write_all(&mut client, request.as_bytes()).expect("write test request");
            let mut response = String::new();
            std::io::Read::read_to_string(&mut client, &mut response).expect("read test response");
            assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
            assert!(
                response.contains("X-Content-Type-Options: nosniff"),
                "{response}"
            );
            assert!(response.contains("Content-Security-Policy:"), "{response}");
            assert!(response.contains("Cache-Control: no-store"), "{response}");

            server.join().expect("join test server");
        });
    }

    #[test]
    fn control_authority_rejects_dns_rebinding_and_cross_origin_requests() {
        let host = |value: &str| control_authority(value, 8080).map(|a| (a.host, a.port));
        assert_eq!(host("localhost"), Some(("localhost".into(), None)));
        assert_eq!(
            host("LOCALHOST:8080"),
            Some(("localhost".into(), Some(8080)))
        );
        assert_eq!(
            host("127.0.0.1:8080"),
            Some(("127.0.0.1".into(), Some(8080)))
        );
        assert_eq!(host("[::1]:8080"), Some(("::1".into(), Some(8080))));
        for rejected in [
            "evil.example",
            "evil.example:8080",
            "localhost:8081",
            "localhost:",
            "0.0.0.0:8080",
            "127.0.0.1@evil.example",
        ] {
            assert!(control_authority(rejected, 8080).is_none(), "{rejected}");
        }

        let same = |host: &str, origin: &str| {
            same_loopback_origin(origin, &control_authority(host, 8553).unwrap())
        };
        assert!(same("localhost:8553", "http://localhost:8553"));
        assert!(same("127.0.0.1:8553", "http://127.0.0.1:8553"));
        assert!(same("[::1]:8553", "http://[::1]:8553"));
        assert!(same("localhost", "http://localhost"));
        assert!(same("localhost", "http://localhost:80"));
        for (host, origin) in [
            ("localhost:8553", "http://localhost"),
            ("127.0.0.1:8553", "http://127.0.0.1"),
            ("127.0.0.1:8553", "http://127.0.0.1:9000"),
            ("127.0.0.1:8553", "https://127.0.0.1:8553"),
            ("127.0.0.1:8553", "http://localhost:8553"),
            ("127.0.0.1:8553", "http://127.0.0.1:8553/"),
            ("localhost:8553", "https://evil.example"),
            ("localhost:8553", "null"),
        ] {
            assert!(!same(host, origin), "{host} {origin}");
        }

        let rebinding = raw_control_request(b"GET /v1/auth HTTP/1.1\r\nHost: evil.example\r\n\r\n");
        assert!(rebinding.starts_with("HTTP/1.1 421 Misdirected Request"));
        let duplicate = raw_control_request(
            b"GET /v1/auth HTTP/1.1\r\nHost: localhost\r\nHost: localhost\r\n\r\n",
        );
        assert!(duplicate.starts_with("HTTP/1.1 400 Bad Request"));
        let cross_origin = raw_control_request(
            b"GET /v1/auth HTTP/1.1\r\nHost: localhost\r\nOrigin: https://evil.example\r\n\r\n",
        );
        assert!(cross_origin.starts_with("HTTP/1.1 403 Forbidden"));
    }

    #[test]
    /// Caught by the Host check, issuance would always fail behind a proxy; other paths must stay
    /// blocked for the same Host.
    fn acme_challenge_answers_any_host_but_other_paths_do_not() {
        set_acme_http01("hosttoken", "hosttoken.thumb");
        let answer = raw_control_request(
            b"GET /.well-known/acme-challenge/hosttoken HTTP/1.1\r\nHost: a1.example\r\n\r\n",
        );
        clear_acme_http01("hosttoken");
        assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer}");
        assert!(answer.ends_with("hosttoken.thumb"), "{answer}");
        let other = raw_control_request(b"GET /v1/auth HTTP/1.1\r\nHost: a1.example\r\n\r\n");
        assert!(
            other.starts_with("HTTP/1.1 421 Misdirected Request"),
            "{other}"
        );
    }

    #[test]
    /// These rejections happen before the audit path; uncounted, attacks would show in neither the
    /// log nor the dashboard.
    fn pre_auth_rejections_are_recorded() {
        let before_host = control_error_count("host_not_loopback");
        let before_origin = control_error_count("cross_origin");
        let before_body = control_error_count("body_too_large");
        let before_type = control_error_count("content_type");

        let _ = raw_control_request(b"GET /v1/auth HTTP/1.1\r\nHost: evil.example\r\n\r\n");
        let _ = raw_control_request(
            b"GET /v1/auth HTTP/1.1\r\nHost: localhost\r\nOrigin: https://evil.example\r\n\r\n",
        );
        let oversized = format!(
            "POST /v1/config/validate HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            MAX_REQUEST_BODY + 1
        );
        let _ = raw_control_request(oversized.as_bytes());
        let _ = raw_control_request(
            b"POST /v1/config/validate HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
        );

        assert!(
            control_error_count("host_not_loopback") > before_host,
            "리바인딩 거절이 기록되지 않았습니다"
        );
        assert!(
            control_error_count("cross_origin") > before_origin,
            "교차 출처 거절이 기록되지 않았습니다"
        );
        assert!(
            control_error_count("body_too_large") > before_body,
            "본문 크기 초과 거절이 기록되지 않았습니다"
        );
        assert!(
            control_error_count("content_type") > before_type,
            "Content-Type 거절이 기록되지 않았습니다"
        );
    }

    #[test]
    fn websocket_accept_matches_rfc_example() {
        let mut hasher = Sha1::new();
        hasher.update(b"dGhlIHNhbXBsZSBub25jZQ==");
        hasher.update(WEBSOCKET_GUID);
        assert_eq!(
            base64_standard(&hasher.finalize()),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn websocket_bearer_protocol_decodes_base64url() {
        assert_eq!(
            String::from_utf8(base64_url_decode("dG9rZW4tMTIz").unwrap()).unwrap(),
            "token-123"
        );
    }

    #[test]
    fn repeated_cookie_headers_are_combined() {
        let mut cookie = String::new();
        append_cookie_header(&mut cookie, "theme=dark");
        append_cookie_header(&mut cookie, "onetdns_session=token-a; lang=ko");

        assert_eq!(cookie, "theme=dark; onetdns_session=token-a; lang=ko");
        assert_eq!(
            cookie_values(&cookie, "onetdns_session"),
            vec!["token-a".to_string()]
        );
    }

    #[test]
    fn same_name_session_cookies_keep_distinct_values_without_duplicates() {
        let cookie = "onetdns_session=stale; onetdns_session=active; onetdns_session=active";
        assert_eq!(
            cookie_values(cookie, "onetdns_session"),
            vec!["stale".to_string(), "active".to_string()]
        );
    }

    #[test]
    fn valid_session_cookie_is_preferred_over_stale_duplicate() {
        let auth = Auth::new(vec![], vec![]).with_users(vec![UserCred {
            name: "alice".to_string(),
            hash: hash_eventually("s3cret-passphrase").into(),
            role: Role::Admin,
        }]);
        let LoginResult::Success(active, _, _) =
            login_eventually(&auth, "alice", "s3cret-passphrase")
        else {
            panic!("login");
        };
        let candidates = vec!["stale".to_string(), active.clone()];

        assert_eq!(select_session_cookie(&candidates, &auth), active);
    }

    /// Trusts 127.0.0.1 as the proxy and serves https://admin.example.com.
    fn proxied_policy() -> ProxyPolicy {
        ProxyPolicy {
            trusted: vec!["127.0.0.1/32".parse().unwrap()],
            origins: vec![HttpsOrigin::parse("https://admin.example.com").unwrap()],
        }
    }

    /// Over a real connection from 127.0.0.1.
    fn exchange(st: &AppState, request: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = accept_before_deadline(&listener).expect("accept request");
                handle_conn(stream, st).unwrap();
            });
            let mut client = TcpStream::connect(addr).unwrap();
            client.write_all(request.as_bytes()).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            let mut response = String::new();
            std::io::Read::read_to_string(&mut client, &mut response).unwrap();
            response
        })
    }

    #[test]
    fn a_public_origin_is_accepted_only_through_a_trusted_proxy() {
        let policy = proxied_policy();
        let proxy: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let other: SocketAddr = "127.0.0.2:40000".parse().unwrap();
        let host = "admin.example.com";
        let origin = Some("https://admin.example.com");

        let caller = control_caller(&policy, Some(proxy), 8553, host, origin, "198.51.100.7")
            .expect("프록시를 거친 공개 출처가 거절됨");
        assert!(caller.proxied.is_some());
        assert_eq!(caller.login_source(), "198.51.100.7");
        assert_eq!(caller.login_proxy().as_deref(), Some("127.0.0.1"));
        assert_eq!(caller.session_cookie(), SECURE_SESSION_COOKIE);

        assert_eq!(
            control_caller(&policy, Some(other), 8553, host, origin, "").err(),
            Some(HostRejection::Misdirected),
            "신뢰하지 않는 연결이 공개 출처로 들어옴"
        );
        assert_eq!(
            control_caller(&ProxyPolicy::default(), Some(proxy), 8553, host, origin, "").err(),
            Some(HostRejection::Misdirected),
            "설정이 없는데 공개 출처가 열림"
        );
        assert_eq!(
            control_caller(
                &policy,
                Some(proxy),
                8553,
                host,
                Some("https://evil.example"),
                ""
            )
            .err(),
            Some(HostRejection::CrossOrigin)
        );
        assert_eq!(
            control_caller(
                &policy,
                Some(proxy),
                8553,
                host,
                Some("http://admin.example.com"),
                ""
            )
            .err(),
            Some(HostRejection::CrossOrigin),
            "HTTPS가 아닌 출처를 받음"
        );

        let local = control_caller(
            &policy,
            Some(proxy),
            8553,
            "127.0.0.1:8553",
            None,
            "1.2.3.4",
        )
        .expect("루프백 Host가 거절됨");
        assert!(
            local.proxied.is_none(),
            "루프백 Host 요청에서 X-Forwarded-For를 읽음"
        );
        assert_eq!(local.session_cookie(), SESSION_COOKIE);
    }

    #[test]
    fn the_forwarded_client_is_the_rightmost_untrusted_address() {
        let policy = proxied_policy();
        let client = |value: &str| policy.forwarded_client(value);
        assert_eq!(
            client("203.0.113.1, 198.51.100.7"),
            Some("198.51.100.7".parse().unwrap())
        );
        assert_eq!(
            client("198.51.100.7, 127.0.0.1"),
            Some("198.51.100.7".parse().unwrap())
        );
        assert_eq!(client("127.0.0.1"), None);
        assert_eq!(client(""), None);
        assert_eq!(client("203.0.113.1, garbage"), None);
    }

    #[test]
    /// Without Secure, a session cookie received over HTTPS would also go out on plain requests.
    fn a_proxied_sign_in_gets_a_secure_host_cookie() {
        let mut st = test_state("adm", "ro");
        st.auth = Arc::new(Auth::new(vec![], vec![]).with_users(vec![UserCred {
            name: "alice".into(),
            hash: hash_eventually("s3cret-passphrase").into(),
            role: Role::Admin,
        }]));
        st.proxy = Arc::new(ArcSwap::from_pointee(proxied_policy()));
        let body = "{\"user\":\"alice\",\"password\":\"s3cret-passphrase\"}";
        let login = format!(
            "POST /v1/login HTTP/1.1\r\nHost: admin.example.com\r\nOrigin: https://admin.example.com\r\n\
             X-Forwarded-For: 198.51.100.7\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = loop {
            let response = exchange(&st, &login);
            if !response.starts_with("HTTP/1.1 503") {
                break response;
            }
        };
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let cookie = response
            .lines()
            .find_map(|line| line.strip_prefix("Set-Cookie: "))
            .expect("세션 쿠키가 없음");
        assert!(
            cookie.starts_with("__Host-onetdns_session=") && cookie.contains("Secure;"),
            "{cookie}"
        );
        let token = cookie
            .trim_start_matches("__Host-onetdns_session=")
            .split(';')
            .next()
            .unwrap();

        let auth_request = |cookie_name: &str| {
            format!(
                "GET /v1/auth HTTP/1.1\r\nHost: admin.example.com\r\nCookie: {cookie_name}={token}\r\n\r\n"
            )
        };
        assert!(exchange(&st, &auth_request("__Host-onetdns_session"))
            .contains("\"authenticated\":true"));
        assert!(
            exchange(&st, &auth_request("onetdns_session")).contains("\"authenticated\":false"),
            "HTTPS 출처에서 Secure가 아닌 쿠키 이름을 받음"
        );
    }

    #[test]
    fn first_account_setup_is_closed_through_the_proxy() {
        let mut st = state_without_accounts(Box::new(|_, _| Ok("{}".to_string())));
        st.proxy = Arc::new(ArcSwap::from_pointee(proxied_policy()));
        let body = "{\"user\":\"owner\",\"password\":\"correct-horse-battery\"}";
        let response = exchange(
            &st,
            &format!(
                "POST /v1/setup HTTP/1.1\r\nHost: admin.example.com\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(!st.auth.has_users());
    }

    #[test]
    fn proxy_login_pacing_keeps_a_bounded_table() {
        let mut pace: std::collections::HashMap<String, u64> = (0..MAX_LOGIN_ATTEMPT_KEYS)
            .map(|i| (format!("127.0.{}.{}", i / 256, i % 256), 2_000 + i as u64))
            .collect();
        Auth::pace_proxy_failure(&mut pace, "127.1.0.1", 1_000);
        assert_eq!(pace.len(), MAX_LOGIN_ATTEMPT_KEYS);
        assert!(
            !pace.contains_key("127.0.0.0"),
            "the soonest entry is evicted"
        );
        assert!(pace.contains_key("127.0.0.1"));

        Auth::pace_proxy_failure(&mut pace, "127.1.0.1", 1_000_000);
        assert_eq!(pace.len(), 1, "expired entries are dropped");
        assert_eq!(
            pace["127.1.0.1"],
            1_000_000 + PROXY_LOGIN_FAILURE_INTERVAL_MS
        );
    }

    #[test]
    /// Blocking per proxy lets one attacker lock out every admin; counting only per client lets a
    /// forged X-Forwarded-For try forever.
    fn proxied_sign_in_failures_are_counted_per_client_and_paced_per_proxy() {
        let auth = Auth::default();
        let proxy = Some("127.0.0.1");
        for i in 0..MAX_SOURCE_LOGIN_FAILURES {
            auth.record_login_result("198.51.100.7", proxy, &format!("ghost{i}"), false);
        }
        assert!(!auth.login_allowed("198.51.100.7", proxy, "alice"));
        assert!(
            auth.login_allowed("203.0.113.9", proxy, "alice"),
            "클라이언트 하나가 한도를 다 쓰자 다른 클라이언트까지 늦춰짐"
        );

        for i in u64::from(MAX_SOURCE_LOGIN_FAILURES)..PROXY_LOGIN_FAILURE_BURST {
            auth.record_login_result(&format!("client{i}"), proxy, "alice", false);
        }
        assert_eq!(
            auth.login_retry_after("203.0.113.9", proxy, "alice"),
            Some(1),
            "출발지를 바꿔 가며 프록시 한도를 넘겼는데 늦추지 않거나, 1초보다 오래 막음"
        );
        assert!(
            auth.login_allowed("local", None, "alice"),
            "프록시를 거치지 않은 로그인까지 늦춰짐"
        );
        std::thread::sleep(Duration::from_millis(1100));
        assert!(
            auth.login_allowed("203.0.113.9", proxy, "alice"),
            "간격이 지나도 프록시를 거친 로그인을 받지 않음"
        );
    }

    #[test]
    fn proxied_ipv6_sign_in_failures_are_counted_per_64() {
        let auth = Auth::default();
        let proxy: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let caller = |client: &str| Caller {
            peer: Some(proxy),
            proxied: Some(Proxied {
                client: Some(client.parse().unwrap()),
            }),
        };
        for i in 0..MAX_SOURCE_LOGIN_FAILURES {
            let source = caller(&format!("2001:db8:1:2::{:x}", i + 1)).login_source();
            auth.record_login_result(&source, Some("127.0.0.1"), &format!("ghost{i}"), false);
        }
        assert!(
            !auth.login_allowed(
                &caller("2001:db8:1:2:ffff::1").login_source(),
                Some("127.0.0.1"),
                "alice"
            ),
            "/64 안에서 주소를 바꿔 출발지 한도를 피함"
        );
        assert!(
            auth.login_allowed(
                &caller("2001:db8:1:3::1").login_source(),
                Some("127.0.0.1"),
                "alice"
            ),
            "다른 /64 의 클라이언트까지 막힘"
        );
    }

    #[test]
    fn direct_sign_in_failures_share_one_local_bucket() {
        let first = Caller::direct(Some("127.0.0.2:40000".parse().unwrap()));
        let second = Caller::direct(Some("127.0.0.3:40001".parse().unwrap()));
        assert_eq!(first.login_source(), second.login_source());
        assert_eq!(first.login_proxy(), None);
    }

    #[test]
    fn a_wrong_bearer_is_not_replaced_by_the_session_cookie() {
        let mut st = test_state("adm", "ro");
        st.auth = Arc::new(Auth::new(vec![], vec![]).with_users(vec![UserCred {
            name: "alice".into(),
            hash: hash_eventually("s3cret-passphrase").into(),
            role: Role::Admin,
        }]));
        let LoginResult::Success(session, _, _) =
            login_eventually(st.auth.as_ref(), "alice", "s3cret-passphrase")
        else {
            panic!("login ok");
        };
        assert_eq!(
            st.auth.resolve("garbage", &session),
            None,
            "틀린 베어러 뒤에서 세션으로 인증됨"
        );
        assert_eq!(st.auth.resolve("", &session), Some(Role::Admin));
        let (with_wrong_bearer, _, _) = route(
            "POST",
            "/v1/cache/flush",
            "Bearer garbage",
            &session,
            "",
            &Caller::direct(None),
            &st,
        );
        assert_eq!(status_code(with_wrong_bearer), 401);

        let request = format!(
            "POST /v1/cache/flush HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer garbage\r\n\
             Cookie: onetdns_session={session}\r\nContent-Length: 0\r\n\r\n"
        );
        let response = exchange(&st, &request);
        assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    }

    #[test]
    fn first_account_setup_requires_the_one_time_code() {
        let created = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let seen = created.clone();
        let st = state_without_accounts(Box::new(move |_, _| {
            *seen.lock_recover() += 1;
            Ok("{}".to_string())
        }));
        let body = |code: &str| {
            format!(
                "{{\"user\":\"owner\",\"password\":\"correct-horse-battery\",\"code\":\"{code}\"}}"
            )
        };
        for wrong in ["", "wrong-code"] {
            let response = setup_request(&st, &body(wrong));
            assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        }
        assert_eq!(*created.lock_recover(), 0, "틀린 코드로 계정을 만듦");

        let status = exchange(&st, "GET /v1/auth HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(
            status.contains(&format!(
                "\"setup_code_file\":{}",
                json::escape(TEST_SETUP_FILE)
            )),
            "설정 화면에 코드 파일 경로를 알려 주지 않음: {status}"
        );

        // A 503 comes while another test is hashing a password; the code is not consumed then.
        let response = loop {
            let response = setup_request(&st, &body(TEST_SETUP_CODE));
            if !response.starts_with("HTTP/1.1 503") {
                break response;
            }
        };
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert_eq!(*created.lock_recover(), 1);
        assert!(
            st.auth.setup_code_file().is_none(),
            "계정을 만든 뒤에도 설정 코드가 남음"
        );

        let without_code = state_without_accounts(Box::new(|_, _| panic!("코드 없이 계정을 만듦")));
        without_code.auth.clear_setup_code();
        let response = setup_request(&without_code, &body(TEST_SETUP_CODE));
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    }

    #[test]
    /// Fills the command channel and sends Close so the reader blocks in `send`; unless the guard
    /// drops the receiver before joining, the drop never ends.
    fn dropping_the_dashboard_reader_joins_a_blocked_reader() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let mut client =
            TcpStream::connect(listener.local_addr().unwrap()).expect("connect test client");
        let (server, _) = listener.accept().expect("accept test connection");
        let reader = DashboardReader::spawn(&SharedTcp::new(server)).expect("spawn reader");

        let mut frames = Vec::new();
        for _ in 0..80 {
            frames.extend_from_slice(&[0x89, 0x80, 1, 2, 3, 4]);
        }
        frames.extend_from_slice(&[0x88, 0x80, 1, 2, 3, 4]);
        std::io::Write::write_all(&mut client, &frames).expect("write frames");
        std::thread::sleep(Duration::from_millis(200));

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            drop(reader);
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("dropping the reader joins its thread");

        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut rest = Vec::new();
        assert_eq!(
            std::io::Read::read_to_end(&mut client, &mut rest).expect("socket is shut down"),
            0
        );
    }

    #[test]
    fn websocket_keys_must_encode_sixteen_bytes() {
        assert!(websocket_key_valid("dGhlIHNhbXBsZSBub25jZQ=="));
        for key in [
            "",
            "x",
            "dGhlIHNhbXBsZSBub25jZQ",
            "dGhlIHNhbXBsZSBub25jZR==",
            "dGhlIHNhbXBsZSBub25jZQ=x",
            "dGhlIHNhbXBsZSBub25j-Q==",
            "dGhlIHNhbXBsZSBub25jZSBh",
        ] {
            assert!(!websocket_key_valid(key), "{key}");
        }
    }

    fn login_eventually(auth: &Auth, name: &str, password: &str) -> LoginResult {
        loop {
            match auth.login(name, password) {
                LoginResult::Busy => std::thread::yield_now(),
                result => return result,
            }
        }
    }

    fn hash_eventually(password: &str) -> String {
        loop {
            match crate::password::hash_password(password) {
                Err(crate::password::PasswordError::Busy) => std::thread::yield_now(),
                result => return result.expect("A test password satisfies the length rule"),
            }
        }
    }
}
