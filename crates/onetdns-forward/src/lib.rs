//! Forwarding to upstreams over plain and encrypted transports. Each transport has its own module
//! (doh, dot, doq, doh3); this file handles upstream selection, single-flight, socket pools, and
//! stats.
//!
//! Never pass an upstream's AD bit through: that would vouch to clients for DNSSEC authenticity
//! this server did not check.

/// Binds the source address before connecting over TCP; std's connect cannot bind a local address
/// first. On a multihomed host with query_source set, TCP leaving by another route lets a firewall
/// pass UDP queries while blocking TCP retries after TC and encrypted upstreams.
mod bound_tcp;
mod dnscrypt;
mod doh;
mod doh3;
mod doq;
mod dot;
mod opportunistic;
mod quicdrive;
mod socks5;

pub use socks5::Socks5Proxy;

pub use opportunistic::{EncryptedRoute, Encryption, OpportunisticEncryption};

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

pub use onetdns_proto::Message;
use onetdns_proto::{Name, RData, RecordType, ResponseCode};
pub use onetdns_tls::TrustStore;

/// Source addresses for upstream sockets, from config.
static QUERY_SRC: RwLock<(Option<std::net::Ipv4Addr>, Option<std::net::Ipv6Addr>)> =
    RwLock::new((None, None));

/// Single-flight key: destination server, transport, and normalized query wire, with the
/// transaction ID cleared and, when configured, the question name's case folded. Otherwise the same
/// query would get a new key every time and single-flight would group nothing. The transport is
/// part of it so a plaintext retry does not wait on the encrypted exchange it falls back from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AuthorityQueryKey {
    server: SocketAddr,

    transport: AuthorityTransport,

    normalized_wire: Arc<[u8]>,
}

impl AuthorityQueryKey {
    /// `normalize_question_case` folds case for 0x20 encoding. None when the key material exceeds
    /// the limit; that query is not grouped.
    fn from_wire(
        server: SocketAddr,
        transport: AuthorityTransport,
        wire: &[u8],
        normalize_question_case: bool,
    ) -> Option<Self> {
        if wire.len() < 12 || wire.len() > MAX_AUTHORITY_FLIGHT_KEY_BYTES {
            return None;
        }
        if wire[4] != 0 || wire[5] != 1 {
            return None;
        }
        let mut normalized = wire.to_vec();
        normalized[0] = 0;
        normalized[1] = 0;
        if normalize_question_case {
            let mut i = 12;
            loop {
                let len = usize::from(*normalized.get(i)?);
                if len == 0 {
                    break;
                }

                if len & 0xC0 != 0 {
                    return None;
                }
                let end = i + 1 + len;
                for b in normalized.get_mut(i + 1..end)? {
                    b.make_ascii_lowercase();
                }
                i = end;
            }
        }
        Some(Self {
            server,
            transport,
            normalized_wire: normalized.into(),
        })
    }

    fn from_request(
        server: SocketAddr,
        transport: AuthorityTransport,
        request: &Message,
        normalize_question_case: bool,
    ) -> Option<Self> {
        request.questions.first()?;
        let mut normalized = request.clone();
        normalized.header.id = 0;
        if normalize_question_case {
            for question in &mut normalized.questions {
                let labels = question
                    .name
                    .labels()
                    .iter()
                    .map(|label| label.iter().map(u8::to_ascii_lowercase).collect())
                    .collect();
                question.name = Name::from_labels(labels).ok()?;
            }
        }
        let normalized_wire = normalized.try_encode().ok()?;
        if normalized_wire.len() > MAX_AUTHORITY_FLIGHT_KEY_BYTES {
            return None;
        }
        Some(Self {
            server,
            transport,
            normalized_wire: normalized_wire.into(),
        })
    }
}

/// One upstream exchange in progress; later requests for the same query wait on it. Sending each
/// concurrent request for a name upstream would pass this server's load straight to the upstream
/// when the cache is cold, so one goes out and the result is shared.
struct AuthorityFlight {
    result: Mutex<Option<Result<Message, ForwardError>>>,
    ready: Condvar,

    /// No notify when 0.
    waiters: AtomicUsize,

    /// So the leader never waits on itself.
    leader_thread: std::thread::ThreadId,
}

impl AuthorityFlight {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            ready: Condvar::new(),
            waiters: AtomicUsize::new(0),
            leader_thread: std::thread::current().id(),
        }
    }

    /// Gives up after `timeout`, so a stalled leader does not stall its followers.
    fn wait(&self, timeout: Duration) -> Result<Message, ForwardError> {
        let deadline = deadline_after(timeout);
        let mut result = self
            .result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            if let Some(completed) = result.as_ref() {
                return completed.clone();
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ForwardError::Timeout);
            }
            let (next, wait) = self
                .ready
                .wait_timeout(result, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            result = next;
            if wait.timed_out() && result.is_none() {
                return Err(ForwardError::Timeout);
            }
        }
    }

    fn complete(&self, result: Result<Message, ForwardError>) {
        *self
            .result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(result);

        if self.waiters.load(Ordering::SeqCst) > 0 {
            self.ready.notify_all();
        }
    }
}

static AUTHORITY_FLIGHTS: OnceLock<Mutex<HashMap<AuthorityQueryKey, Arc<AuthorityFlight>>>> =
    OnceLock::new();
/// Past this, new queries go out ungrouped.
const MAX_AUTHORITY_FLIGHTS: usize = 1024;

/// Keeps large queries from bloating the key map.
const MAX_AUTHORITY_FLIGHT_KEY_BYTES: usize = 4_096;

thread_local! {

    /// Reused per thread instead of allocated per query.
    static UDP_RECV_BUFFER: RefCell<Vec<u8>> = RefCell::new(vec![0; 65_535]);

    static UDP_SOCKET_POOL: RefCell<HashMap<SocketAddr, UdpSocketPool>> =
        RefCell::new(HashMap::new());
}

const UDP_SOCKET_POOL_SIZE: usize = 16;

/// Source port randomization is one leg of the cache poisoning defense. Reusing a socket
/// indefinitely exposes one port for long and weakens it, so sockets are reopened after this many
/// uses.
const UDP_SOCKET_POOL_MAX_USES: u32 = 16;

struct PooledUdpSocket {
    sock: UdpSocket,
    uses: u32,

    /// The receive timeout currently set.
    rcv_timeout: Option<Duration>,
}

/// Resetting the timeout each time costs a system call per socket; skip it when the cached value is
/// close to the time left.
fn rcv_timeout_reusable(cached: Option<Duration>, remaining: Duration) -> bool {
    match cached {
        Some(cached) => {
            cached <= remaining && remaining.saturating_sub(cached) <= Duration::from_millis(1)
        }
        None => false,
    }
}

#[derive(Default)]
/// Thread-local, so no locks.
struct UdpSocketPool {
    idle: Vec<PooledUdpSocket>,
    owned: usize,
}

/// Returns the socket, its use count, and its current receive timeout.
fn take_pooled_udp_socket(bind: SocketAddr) -> std::io::Result<(UdpSocket, u32, Option<Duration>)> {
    let reused = UDP_SOCKET_POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        let entry = pool.entry(bind).or_default();
        loop {
            if entry.owned < UDP_SOCKET_POOL_SIZE || entry.idle.is_empty() {
                return None;
            }
            let index = u64::from_le_bytes(onetdns_core::ephemeral_random_array::<8>()) as usize
                % entry.idle.len();
            let picked = entry.idle.swap_remove(index);
            if picked.uses < UDP_SOCKET_POOL_MAX_USES {
                return Some((picked.sock, picked.uses + 1, picked.rcv_timeout));
            }
            entry.owned -= 1;
        }
    });
    match reused {
        Some(entry) => Ok(entry),
        None => {
            let sock = onetdns_core::udp::bind(bind)?;
            UDP_SOCKET_POOL.with(|pool| {
                pool.borrow_mut().entry(bind).or_default().owned += 1;
            });
            Ok((sock, 1, None))
        }
    }
}

/// Drops it past the use limit.
fn return_pooled_udp_socket(
    bind: SocketAddr,
    sock: UdpSocket,
    uses: u32,
    rcv_timeout: Option<Duration>,
) {
    UDP_SOCKET_POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        let entry = pool.entry(bind).or_default();
        if entry.idle.len() < UDP_SOCKET_POOL_SIZE {
            entry.idle.push(PooledUdpSocket {
                sock,
                uses,
                rcv_timeout,
            });
        } else {
            entry.owned = entry.owned.saturating_sub(1);
        }
    });
}

/// Called on a suspected spoofed response: the attacker already knows that port, and reusing it
/// would send the next query from it too.
fn discard_pooled_udp_socket(bind: SocketAddr) {
    UDP_SOCKET_POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        let entry = pool.entry(bind).or_default();
        entry.owned = entry.owned.saturating_sub(1);
    });
}

fn authority_flights() -> &'static Mutex<HashMap<AuthorityQueryKey, Arc<AuthorityFlight>>> {
    AUTHORITY_FLIGHTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Returns whether this request leads; the leader sends upstream and fills the result, others wait.
fn acquire_authority_flight(
    flights: &mut HashMap<AuthorityQueryKey, Arc<AuthorityFlight>>,
    key: &AuthorityQueryKey,
) -> Option<(Arc<AuthorityFlight>, bool)> {
    if let Some(existing) = flights.get(key) {
        if existing.leader_thread == std::thread::current().id() {
            return None;
        }
        existing.waiters.fetch_add(1, Ordering::SeqCst);
        return Some((existing.clone(), false));
    }
    if flights.len() >= MAX_AUTHORITY_FLIGHTS {
        return None;
    }
    let flight = Arc::new(AuthorityFlight::new());
    flights.insert(key.clone(), flight.clone());
    Some((flight, true))
}

/// Pins the route on multihomed hosts.
pub fn set_query_source(v4: Option<std::net::Ipv4Addr>, v6: Option<std::net::Ipv6Addr>) {
    *QUERY_SRC
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = (v4, v6);
}

/// Matches the destination's family; port 0.
fn pick_bind(
    upstream: SocketAddr,
    v4: Option<std::net::Ipv4Addr>,
    v6: Option<std::net::Ipv6Addr>,
) -> SocketAddr {
    if upstream.is_ipv4() {
        (v4.unwrap_or(std::net::Ipv4Addr::UNSPECIFIED), 0).into()
    } else {
        (v6.unwrap_or(std::net::Ipv6Addr::UNSPECIFIED), 0).into()
    }
}

pub fn outgoing_bind(upstream: SocketAddr) -> SocketAddr {
    let (v4, v6) = *QUERY_SRC
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    pick_bind(upstream, v4, v6)
}

pub(crate) use onetdns_core::tcp::DeadlineTcp;

/// All TCP connections in this crate go through here: DeadlineTcp::connect picks no source address
/// and would ignore query_source.
pub(crate) fn connect_upstream(
    addr: SocketAddr,
    deadline: Instant,
) -> std::io::Result<DeadlineTcp> {
    let left = onetdns_core::tcp::time_left(deadline)?;
    let stream = bound_tcp::connect(outgoing_bind(addr), addr, left)?;
    // With Nagle on, a query written while the previous one is unacknowledged waits for the
    // server's delayed ACK.
    let _ = stream.set_nodelay(true);
    Ok(DeadlineTcp::new(stream, deadline))
}

/// The TCP connection a DoT or DoH upstream runs over.
pub(crate) fn connect_stream(
    endpoint: &Endpoint,
    deadline: Instant,
) -> Result<DeadlineTcp, ForwardError> {
    match endpoint {
        Endpoint::Direct(addr) => connect_upstream(*addr, deadline).map_err(io_err),
        Endpoint::Socks5 { proxy, host, port } => socks5::connect(proxy, host, *port, deadline),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Strategy {
    /// Tries in order, so the first upstream is effectively primary.
    #[default]
    Sequential,

    RoundRobin,

    /// Picks by observed latency and success rate.
    QueryStatistics,

    /// Sends to several at once and takes the fastest answer: lower latency, more upstream load.
    Parallel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    Udp,

    Tcp,

    Dot {
        server_name: String,
    },

    Doh {
        server_name: String,
        path: String,
    },

    Doq {
        server_name: String,
    },

    Doh3 {
        server_name: String,
        path: String,
    },

    /// Certificates are fetched as TXT records of `provider_name` and must be signed by
    /// `public_key`.
    Dnscrypt {
        provider_name: String,
        public_key: [u8; 32],
    },
}

/// Where an upstream's connections go.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Endpoint {
    Direct(SocketAddr),
    /// Through a SOCKS5 proxy, which opens the connection and resolves `host` when it is a name.
    /// Only DoT and DoH run over it; the proxy carries TCP only.
    Socks5 {
        proxy: Arc<Socks5Proxy>,
        host: String,
        port: u16,
    },
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endpoint::Direct(addr) => write!(f, "{addr}"),
            Endpoint::Socks5 { proxy, host, port } => {
                write!(f, "{} via {proxy}", socks5::host_port(host, *port))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub endpoint: Endpoint,
    pub transport: Transport,
}

impl Upstream {
    pub fn udp(addr: SocketAddr) -> Self {
        Upstream {
            endpoint: Endpoint::Direct(addr),
            transport: Transport::Udp,
        }
    }

    pub fn tcp(addr: SocketAddr) -> Self {
        Upstream {
            endpoint: Endpoint::Direct(addr),
            transport: Transport::Tcp,
        }
    }

    /// `server_name` is the name the certificate is checked against.
    pub fn dot(addr: SocketAddr, server_name: impl Into<String>) -> Self {
        Upstream {
            endpoint: Endpoint::Direct(addr),
            transport: Transport::Dot {
                server_name: server_name.into(),
            },
        }
    }

    /// DoT through `proxy`, which is given `host` as written.
    pub fn dot_via(
        proxy: Arc<Socks5Proxy>,
        host: impl Into<String>,
        port: u16,
        server_name: impl Into<String>,
    ) -> Self {
        Upstream {
            endpoint: Endpoint::Socks5 {
                proxy,
                host: host.into(),
                port,
            },
            transport: Transport::Dot {
                server_name: server_name.into(),
            },
        }
    }

    pub fn doh(addr: SocketAddr, server_name: impl Into<String>, path: impl Into<String>) -> Self {
        Upstream {
            endpoint: Endpoint::Direct(addr),
            transport: Transport::Doh {
                server_name: server_name.into(),
                path: path.into(),
            },
        }
    }

    /// DoH through `proxy`, which is given `host` as written.
    pub fn doh_via(
        proxy: Arc<Socks5Proxy>,
        host: impl Into<String>,
        port: u16,
        server_name: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Upstream {
            endpoint: Endpoint::Socks5 {
                proxy,
                host: host.into(),
                port,
            },
            transport: Transport::Doh {
                server_name: server_name.into(),
                path: path.into(),
            },
        }
    }

    pub fn doq(addr: SocketAddr, server_name: impl Into<String>) -> Self {
        Upstream {
            endpoint: Endpoint::Direct(addr),
            transport: Transport::Doq {
                server_name: server_name.into(),
            },
        }
    }

    /// Transport and address, for logs and stats.
    pub fn label(&self) -> String {
        match &self.transport {
            Transport::Udp => self.endpoint.to_string(),
            Transport::Tcp => format!("tcp://{}", self.endpoint),
            Transport::Dot { server_name } => format!("tls://{server_name}"),
            Transport::Doh { server_name, path } => format!("https://{server_name}{path}"),
            Transport::Doq { server_name } => format!("quic://{server_name}"),
            Transport::Doh3 { server_name, path } => format!("h3://{server_name}{path}"),
            Transport::Dnscrypt { provider_name, .. } => format!("dnscrypt://{provider_name}"),
        }
    }

    pub fn dnscrypt(
        addr: SocketAddr,
        provider_name: impl Into<String>,
        public_key: [u8; 32],
    ) -> Self {
        Upstream {
            endpoint: Endpoint::Direct(addr),
            transport: Transport::Dnscrypt {
                provider_name: provider_name.into(),
                public_key,
            },
        }
    }

    pub fn doh3(addr: SocketAddr, server_name: impl Into<String>, path: impl Into<String>) -> Self {
        Upstream {
            endpoint: Endpoint::Direct(addr),
            transport: Transport::Doh3 {
                server_name: server_name.into(),
                path: path.into(),
            },
        }
    }
}

/// Where the last response came from, for the query log.
enum ResponseSource {
    Label(std::borrow::Cow<'static, str>),
    /// Defers building the string.
    Addr(SocketAddr),
}

thread_local! {

    static LAST_SOURCE: std::cell::RefCell<Option<ResponseSource>> =
        const { std::cell::RefCell::new(None) };
}

/// The query log takes it after handling.
pub fn note_response_source(label: impl Into<std::borrow::Cow<'static, str>>) {
    LAST_SOURCE.with(|slot| *slot.borrow_mut() = Some(ResponseSource::Label(label.into())));
}

fn note_response_addr(addr: SocketAddr) {
    LAST_SOURCE.with(|slot| *slot.borrow_mut() = Some(ResponseSource::Addr(addr)));
}

/// Takes and clears it.
pub fn take_response_source() -> Option<std::borrow::Cow<'static, str>> {
    LAST_SOURCE
        .with(|slot| slot.borrow_mut().take())
        .map(|source| match source {
            ResponseSource::Label(label) => label,
            ResponseSource::Addr(addr) => addr.to_string().into(),
        })
}

/// So a previous query's source does not leak into the next log.
pub fn clear_response_source() {
    LAST_SOURCE.with(|slot| *slot.borrow_mut() = None);
}

/// Read once and shared by every TLS upstream.
fn system_trust() -> Arc<TrustStore> {
    static S: OnceLock<Arc<TrustStore>> = OnceLock::new();
    S.get_or_init(|| Arc::new(TrustStore::system())).clone()
}

type RevocationHook = Arc<dyn Fn(&[onetdns_tls::X509], &str) -> Result<(), String> + Send + Sync>;

/// Ties the connection cache to the trust store and revocation policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TlsCacheScope {
    /// Identifies the trust store contents.
    trust: [u8; 32],
    /// Bumped whenever the revocation hook changes.
    revocation_generation: u64,
}

struct RevocationPolicy {
    hook: Option<RevocationHook>,
    generation: u64,
}

static REVOCATION_POLICY: OnceLock<Mutex<RevocationPolicy>> = OnceLock::new();

fn revocation_policy() -> &'static Mutex<RevocationPolicy> {
    REVOCATION_POLICY.get_or_init(|| {
        Mutex::new(RevocationPolicy {
            hook: None,
            generation: 0,
        })
    })
}

fn tls_cache_scope(trust: &TrustStore) -> TlsCacheScope {
    let policy = revocation_policy()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    TlsCacheScope {
        trust: trust.cache_key(),
        revocation_generation: policy.hook.as_ref().map_or(0, |_| policy.generation),
    }
}

#[cfg(test)]
/// Serializes tests that change the global revocation hook against encrypted transport tests.
static REVOCATION_TEST_LOCK: RwLock<()> = RwLock::new(());

#[cfg(test)]
thread_local! {
    /// A test thread holding the write lock skips the read lock in its own exchanges.
    static REVOCATION_TEST_WRITER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn revocation_test_read_guard() -> Option<std::sync::RwLockReadGuard<'static, ()>> {
    if REVOCATION_TEST_WRITER.with(std::cell::Cell::get) {
        None
    } else {
        Some(
            REVOCATION_TEST_LOCK
                .read()
                .unwrap_or_else(|error| error.into_inner()),
        )
    }
}

#[cfg(test)]
struct RevocationTestWriteGuard {
    _guard: std::sync::RwLockWriteGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for RevocationTestWriteGuard {
    fn drop(&mut self) {
        REVOCATION_TEST_WRITER.with(|writer| writer.set(false));
    }
}

#[cfg(test)]
fn revocation_test_write_guard() -> RevocationTestWriteGuard {
    let guard = REVOCATION_TEST_LOCK
        .write()
        .unwrap_or_else(|error| error.into_inner());
    REVOCATION_TEST_WRITER.with(|writer| writer.set(true));
    RevocationTestWriteGuard { _guard: guard }
}

#[cfg(test)]
/// TLS-over-TCP upstream that reports its first read after the handshake, to see how the client
/// ended the connection: PeerAlert when it sent a fatal alert, another error when it closed without
/// one. Returns the server address, a trust store that trusts only the dns.test certificate, and a
/// receiver of each connection's first read.
fn tls_first_read_recorder(
    alpn: &[u8],
) -> (
    SocketAddr,
    Arc<onetdns_tls::TrustStore>,
    std::sync::mpsc::Receiver<Result<Vec<u8>, onetdns_tls::TlsError>>,
) {
    let ck = rcgen::generate_simple_self_signed(vec!["dns.test".to_string()]).unwrap();
    let cert_der = ck.cert.der().to_vec();
    let trust = Arc::new(onetdns_tls::TrustStore::from_ders([cert_der.as_slice()]));
    let (sign_scheme, sign) =
        onetdns_tls::signer_from_pkcs8_der(&ck.key_pair.serialize_der()).unwrap();
    let cfg = onetdns_tls::ServerConfig {
        cert_chain: vec![cert_der],
        sign_scheme,
        sign,
        alpn: vec![alpn.to_vec()],
        client_ca: None,
        resumption: None,
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (reads, received) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            let Ok(mut conn) = onetdns_tls::server_handshake(&mut stream, &cfg) else {
                continue;
            };
            if reads.send(conn.read_app(&mut stream)).is_err() {
                return;
            }
        }
    });
    (addr, trust, received)
}

/// Runs right after the TLS handshake, before a query is sent, so no query goes to an upstream with
/// a revoked certificate. The hook gets the verified chain, where the certificate after the leaf is
/// the leaf's issuer.
pub fn set_revocation_hook(
    f: Box<dyn Fn(&[onetdns_tls::X509], &str) -> Result<(), String> + Send + Sync>,
) {
    let mut policy = revocation_policy()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    policy.generation = policy
        .generation
        .checked_add(1)
        .expect("Revocation policy generations exhausted");
    policy.hook = Some(Arc::from(f));
}

pub fn clear_revocation_hook() {
    let mut policy = revocation_policy()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    policy.generation = policy
        .generation
        .checked_add(1)
        .expect("Revocation policy generations exhausted");
    policy.hook = None;
}

/// Passes when no hook is installed: revocation checking is optional and enforced only when on.
pub(crate) fn check_revocation(
    verified_chain: &[onetdns_tls::X509],
    host: &str,
) -> Result<(), ForwardError> {
    let hook = revocation_policy()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .hook
        .clone();
    if let Some(hook) = hook {
        hook(verified_chain, host)
            .map_err(|e| ForwardError::Io(format!("Certificate revocation check failed: {e}")))?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardError {
    /// No upstream left to try.
    NoUpstream,

    Timeout,

    Io(String),

    /// The response does not match the query, which may also mean spoofing.
    BadResponse,
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardError::NoUpstream => write!(f, "No upstream DNS server available"),
            ForwardError::Timeout => write!(f, "Upstream DNS server timed out"),
            ForwardError::Io(s) => write!(f, "I/O error talking to the upstream DNS server: {s}"),
            ForwardError::BadResponse => {
                write!(
                    f,
                    "Upstream DNS server sent a response that does not match the query"
                )
            }
        }
    }
}

impl std::error::Error for ForwardError {}

#[derive(Debug, Clone, Copy)]
struct UpstreamStat {
    /// Weighted toward recent samples, so a slowed upstream drops in rank at once.
    ewma_ms: f64,
    /// Consecutive; reset on success.
    failures: u32,
    samples: u64,

    ok: u64,
    fail: u64,
}

impl Default for UpstreamStat {
    fn default() -> Self {
        Self {
            ewma_ms: 0.0,
            failures: 0,
            samples: 0,
            ok: 0,
            fail: 0,
        }
    }
}

/// For the dashboard and persistence.
#[derive(Debug, Clone)]
pub struct UpstreamStatReport {
    pub label: String,
    pub queries: u64,
    pub ok: u64,
    pub fail: u64,
    pub ewma_ms: f64,
}

/// Shared between the forwarder and the control plane.
#[derive(Clone)]
pub struct ForwardStats {
    labels: Vec<String>,
    stats: Arc<Vec<Mutex<UpstreamStat>>>,
}

impl ForwardStats {
    /// Restores saved stats, so a restart does not lose what was learned. Fills only upstreams with
    /// no samples yet; existing observations are newer.
    pub fn seed(&self, reports: &[UpstreamStatReport]) {
        for (label, stat) in self.labels.iter().zip(self.stats.iter()) {
            let Some(r) = reports.iter().find(|r| &r.label == label) else {
                continue;
            };
            let mut s = stat.lock().unwrap_or_else(|error| error.into_inner());
            if s.samples == 0 {
                s.ewma_ms = r.ewma_ms;
                s.samples = r.queries;
                s.ok = r.ok;
                s.fail = r.fail;
            }
        }
    }

    /// Adds counts another process observed. The latency average stays this process's when it has
    /// samples of its own, as they are newer.
    pub fn add(&self, reports: &[UpstreamStatReport]) {
        for (label, stat) in self.labels.iter().zip(self.stats.iter()) {
            let Some(r) = reports.iter().find(|r| &r.label == label) else {
                continue;
            };
            let mut s = stat.lock().unwrap_or_else(|error| error.into_inner());
            if s.samples == 0 {
                s.ewma_ms = r.ewma_ms;
            }
            s.samples = s.samples.saturating_add(r.queries);
            s.ok = s.ok.saturating_add(r.ok);
            s.fail = s.fail.saturating_add(r.fail);
        }
    }

    pub fn snapshot(&self) -> Vec<UpstreamStatReport> {
        self.labels
            .iter()
            .zip(self.stats.iter())
            .map(|(label, stat)| {
                let s = *stat.lock().unwrap_or_else(|error| error.into_inner());
                UpstreamStatReport {
                    label: label.clone(),
                    queries: s.samples,
                    ok: s.ok,
                    fail: s.fail,
                    ewma_ms: s.ewma_ms,
                }
            })
            .collect()
    }
}

pub struct Forwarder {
    /// Per request.
    upstreams: Vec<Upstream>,
    timeout: Duration,
    strategy: Strategy,
    /// Upstreams tried at once under Parallel.
    rr: AtomicUsize,

    /// None uses the system store.
    parallel_limit: usize,

    trust: Option<Arc<TrustStore>>,
    stats: Arc<Vec<Mutex<UpstreamStat>>>,
}

impl Forwarder {
    /// Plain UDP upstreams.
    pub fn new(upstreams: Vec<SocketAddr>, timeout: Duration) -> Self {
        Self::with_upstreams(upstreams.into_iter().map(Upstream::udp).collect(), timeout)
    }

    pub fn with_upstreams(upstreams: Vec<Upstream>, timeout: Duration) -> Self {
        let stats = Arc::new(
            (0..upstreams.len())
                .map(|_| Mutex::new(UpstreamStat::default()))
                .collect::<Vec<_>>(),
        );
        Self {
            upstreams,
            timeout,
            strategy: Strategy::Sequential,
            rr: AtomicUsize::new(0),
            parallel_limit: 0,
            trust: None,
            stats,
        }
    }

    /// The control plane reads current stats through it.
    pub fn stats_handle(&self) -> ForwardStats {
        ForwardStats {
            labels: self.upstreams.iter().map(Upstream::label).collect(),
            stats: self.stats.clone(),
        }
    }

    pub fn with_strategy(mut self, s: Strategy) -> Self {
        self.strategy = s;
        self
    }

    /// Higher limits load upstreams more.
    pub fn with_parallel_limit(mut self, limit: usize) -> Self {
        self.parallel_limit = limit;
        self
    }

    /// Without one, the system store is used.
    pub fn with_trust(mut self, trust: Arc<TrustStore>) -> Self {
        self.trust = Some(trust);
        self
    }

    pub fn upstreams(&self) -> &[Upstream] {
        &self.upstreams
    }

    fn trust(&self) -> Arc<TrustStore> {
        self.trust.clone().unwrap_or_else(system_trust)
    }

    /// Picks a fresh outgoing transaction ID and restores the original on the response: reusing the
    /// client's ID upstream would make it predictable and spoofing easier. Clears AD: relaying an
    /// authenticity flag this server did not check would make clients take the answer as validated.
    pub fn resolve(&self, request: &Message) -> Result<Message, ForwardError> {
        let n = self.upstreams.len();
        if n == 0 {
            return Err(ForwardError::NoUpstream);
        }

        let mut wire = request
            .try_encode()
            .map_err(|_| ForwardError::BadResponse)?;
        let wire_id = next_id();
        wire[0..2].copy_from_slice(&wire_id.to_be_bytes());
        let deadline = deadline_after(self.timeout);

        if self.strategy == Strategy::Parallel {
            return self.resolve_parallel(request, &wire, wire_id, deadline);
        }
        if self.strategy == Strategy::QueryStatistics {
            return self.resolve_by_statistics(request, &wire, wire_id, deadline);
        }

        let start = match self.strategy {
            Strategy::RoundRobin => self.rr.fetch_add(1, Ordering::Relaxed) % n,
            _ => 0,
        };
        self.resolve_sequential(start, request, &wire, wire_id, deadline)
    }

    /// Orders upstreams by latency EWMA and consecutive failures. Failing upstreams sink but are
    /// never excluded, so they keep a chance to show recovery.
    fn resolve_by_statistics(
        &self,
        request: &Message,
        wire: &[u8],
        wire_id: u16,
        deadline: Instant,
    ) -> Result<Message, ForwardError> {
        let probe_start = self.rr.fetch_add(1, Ordering::Relaxed);
        let snapshot: Vec<UpstreamStat> = self
            .stats
            .iter()
            .map(|stat| *stat.lock().unwrap_or_else(|error| error.into_inner()))
            .collect();
        let mut order: Vec<usize> = (0..self.upstreams.len()).collect();
        order.sort_by(|&a, &b| {
            let sa = snapshot[a];
            let sb = snapshot[b];

            let score = |s: UpstreamStat, idx: usize| {
                if s.samples == 0 {
                    ((idx + self.upstreams.len() - (probe_start % self.upstreams.len()))
                        % self.upstreams.len()) as f64
                } else {
                    10_000.0 + s.ewma_ms + f64::from(s.failures.min(100)) * 250.0
                }
            };
            score(sa, a)
                .partial_cmp(&score(sb, b))
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut last = ForwardError::Timeout;
        let mut best: Option<(RespClass, Message)> = None;
        let trust = self.trust();
        let total = order.len();
        for (position, idx) in order.into_iter().enumerate() {
            let Some(remaining) = attempt_timeout(deadline, total - position) else {
                break;
            };
            let started = Instant::now();
            match exchange_one(
                &self.upstreams[idx],
                wire,
                wire_id,
                request,
                remaining,
                &trust,
            ) {
                Ok(mut resp) => {
                    resp.header.id = request.header.id;
                    let class = response_class(request, &resp);

                    self.record_upstream_result(idx, started.elapsed(), class == RespClass::Final);
                    match class {
                        RespClass::Final => {
                            note_response_source(self.upstreams[idx].label());
                            return Ok(resp);
                        }
                        cls => {
                            observe_non_final(&self.upstreams[idx], cls, request, &resp);
                            keep_best(&mut best, cls, resp);
                        }
                    }
                }
                Err(error) => {
                    self.record_upstream_result(idx, started.elapsed(), false);
                    last = error;
                }
            }
        }
        best.map(|(_, message)| message).ok_or(last)
    }

    /// Only final answers count as success. Counting referrals or empty answers would keep an
    /// upstream that cannot answer at the top.
    fn record_upstream_result(&self, index: usize, elapsed: Duration, success: bool) {
        let mut stat = self.stats[index]
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let ms = elapsed.as_secs_f64() * 1_000.0;
        stat.ewma_ms = if stat.samples == 0 {
            ms
        } else {
            stat.ewma_ms * 0.8 + ms * 0.2
        };
        stat.samples = stat.samples.saturating_add(1);
        if success {
            stat.failures = stat.failures.saturating_sub(1);
            stat.ok = stat.ok.saturating_add(1);
        } else {
            stat.failures = stat.failures.saturating_add(1);
            stat.fail = stat.fail.saturating_add(1);
        }
    }

    /// Splits the total deadline across the attempts left.
    fn resolve_sequential(
        &self,
        start: usize,
        request: &Message,
        wire: &[u8],
        wire_id: u16,
        deadline: Instant,
    ) -> Result<Message, ForwardError> {
        let n = self.upstreams.len();
        let mut last = ForwardError::Timeout;
        let mut best: Option<(RespClass, Message)> = None;
        let trust = self.trust();
        for k in 0..n {
            let Some(remaining) = attempt_timeout(deadline, n - k) else {
                break;
            };
            let idx = (start + k) % n;
            let up = &self.upstreams[idx];
            let started = Instant::now();
            match exchange_one(up, wire, wire_id, request, remaining, &trust) {
                Ok(mut resp) => {
                    resp.header.id = request.header.id;
                    let cls = response_class(request, &resp);
                    self.record_upstream_result(idx, started.elapsed(), cls == RespClass::Final);
                    match cls {
                        RespClass::Final => {
                            note_response_source(up.label());
                            return Ok(resp);
                        }

                        cls => {
                            observe_non_final(up, cls, request, &resp);
                            keep_best(&mut best, cls, resp);
                        }
                    }
                }
                Err(e) => {
                    self.record_upstream_result(idx, started.elapsed(), false);
                    last = e;
                }
            }
        }
        best.map(|(_, m)| m).ok_or(last)
    }

    /// Picks by response class, not arrival: a final answer beats a referral or empty answer even
    /// when it arrives later. A fast "don't know" must not become the answer.
    fn resolve_parallel(
        &self,
        request: &Message,
        wire: &[u8],
        wire_id: u16,
        deadline: Instant,
    ) -> Result<Message, ForwardError> {
        use std::sync::mpsc;

        let n = self.upstreams.len();
        let batch_size = if self.parallel_limit == 0 {
            n
        } else {
            self.parallel_limit.min(n).max(1)
        };
        let start = self.rr.fetch_add(batch_size, Ordering::Relaxed) % n;
        let mut attempted = 0usize;
        let mut last = ForwardError::Timeout;
        let mut best: Option<(RespClass, Message)> = None;
        let trust = self.trust();
        let shared_wire: Arc<[u8]> = Arc::from(wire);
        let shared_request = Arc::new(request.clone());

        while attempted < n {
            let batches_left = (n - attempted).div_ceil(batch_size);
            let Some(batch_timeout) = attempt_timeout(deadline, batches_left) else {
                break;
            };
            let batch_deadline = deadline_after(batch_timeout);
            let wanted = batch_size.min(n - attempted);
            let granted = acquire_parallel_slots(wanted);

            if granted == 0 {
                let idx = (start + attempted) % n;
                let upstream = &self.upstreams[idx];
                let Some(remaining) = attempt_timeout(deadline, n - attempted) else {
                    break;
                };
                attempted += 1;
                let started = Instant::now();
                match exchange_one(upstream, wire, wire_id, request, remaining, &trust) {
                    Ok(mut response) => {
                        response.header.id = request.header.id;
                        let class = response_class(request, &response);
                        self.record_upstream_result(
                            idx,
                            started.elapsed(),
                            class == RespClass::Final,
                        );
                        match class {
                            RespClass::Final => {
                                note_response_source(upstream.label());
                                return Ok(response);
                            }
                            class => {
                                observe_non_final(upstream, class, request, &response);
                                keep_best(&mut best, class, response);
                            }
                        }
                    }
                    Err(error) => {
                        self.record_upstream_result(idx, started.elapsed(), false);
                        last = error;
                    }
                }
                continue;
            }

            type JobResult = (usize, Duration, Upstream, Result<Message, ForwardError>);
            let (tx, rx) = mpsc::channel::<JobResult>();
            let mut submitted = 0usize;
            let mut synchronous = Vec::new();
            for offset in 0..granted {
                let index = (start + attempted + offset) % n;
                let upstream = self.upstreams[index].clone();
                let job_upstream = upstream.clone();
                let job_wire = shared_wire.clone();
                let job_request = shared_request.clone();
                let job_trust = trust.clone();
                let tx = tx.clone();
                if submit_parallel_job(move || {
                    let _guard = ParallelSlot;
                    let remaining = batch_deadline.saturating_duration_since(Instant::now());
                    let started = Instant::now();
                    let result = if remaining.is_zero() {
                        Err(ForwardError::Timeout)
                    } else {
                        exchange_one(
                            &job_upstream,
                            &job_wire,
                            wire_id,
                            &job_request,
                            remaining,
                            &job_trust,
                        )
                    };
                    let _ = tx.send((index, started.elapsed(), job_upstream, result));
                }) {
                    submitted += 1;
                } else {
                    release_parallel_slot();
                    let remaining = batch_deadline.saturating_duration_since(Instant::now());
                    let started = Instant::now();
                    let result = if remaining.is_zero() {
                        Err(ForwardError::Timeout)
                    } else {
                        exchange_one(&upstream, wire, wire_id, request, remaining, &trust)
                    };
                    synchronous.push((index, started.elapsed(), upstream, result));
                }
            }
            drop(tx);
            attempted += granted;

            let mut handle_result = |index: usize,
                                     elapsed: Duration,
                                     upstream: Upstream,
                                     result: Result<Message, ForwardError>|
             -> Option<Message> {
                match result {
                    Ok(mut response) => {
                        response.header.id = request.header.id;
                        let class = response_class(request, &response);
                        self.record_upstream_result(index, elapsed, class == RespClass::Final);
                        match class {
                            RespClass::Final => {
                                note_response_source(upstream.label());
                                return Some(response);
                            }
                            class => {
                                observe_non_final(&upstream, class, request, &response);
                                keep_best(&mut best, class, response);
                            }
                        }
                    }
                    Err(error) => {
                        self.record_upstream_result(index, elapsed, false);
                        last = error;
                    }
                }
                None
            };
            for (index, elapsed, upstream, result) in synchronous {
                if let Some(response) = handle_result(index, elapsed, upstream, result) {
                    return Ok(response);
                }
            }
            for _ in 0..submitted {
                let remaining = batch_deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match rx.recv_timeout(remaining) {
                    Ok((index, elapsed, upstream, result)) => {
                        if let Some(response) = handle_result(index, elapsed, upstream, result) {
                            return Ok(response);
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => break,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        }

        best.map(|(_, message)| message).ok_or(last)
    }
}

/// Splits the time left across the attempts left. None when no time is left or the share is 0,
/// ending the attempts.
fn attempt_timeout(deadline: Instant, attempts_left: usize) -> Option<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() || attempts_left == 0 {
        return None;
    }
    let divisor = u32::try_from(attempts_left).unwrap_or(u32::MAX);
    let timeout = remaining / divisor;
    (!timeout.is_zero()).then_some(timeout)
}

/// A huge configured timeout that would overflow the clock becomes an immediate expiry.
pub(crate) fn deadline_after(timeout: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(timeout).unwrap_or(now)
}

/// A reused connection may already be dead; cutting its first try short moves to a fresh connection
/// without spending the whole budget on it.
const FIRST_TRY_CAP_DEFAULT: Duration = Duration::from_millis(1500);

const TCP_IDLE_REUSE_MAX_DEFAULT: Duration = Duration::from_secs(120);

#[cfg(test)]
thread_local! {
    static REUSE_OVERRIDE: std::cell::Cell<Option<(Duration, Duration)>> =
        const { std::cell::Cell::new(None) };
}

/// Lets tests check expiry without waiting in real time.
#[cfg(test)]
pub(crate) fn set_reuse_caps_for_test(first_try: Duration, tcp_idle: Duration) {
    REUSE_OVERRIDE.with(|c| c.set(Some((first_try, tcp_idle))));
}

#[cfg(test)]
pub(crate) fn clear_reuse_caps_for_test() {
    REUSE_OVERRIDE.with(|c| c.set(None));
}

pub(crate) fn first_try_cap() -> Duration {
    #[cfg(test)]
    if let Some((f, _)) = REUSE_OVERRIDE.with(|c| c.get()) {
        return f;
    }
    FIRST_TRY_CAP_DEFAULT
}

pub(crate) fn tcp_idle_reuse_max() -> Duration {
    #[cfg(test)]
    if let Some((_, t)) = REUSE_OVERRIDE.with(|c| c.get()) {
        return t;
    }
    TCP_IDLE_REUSE_MAX_DEFAULT
}

/// The smaller of the fixed cap and two fifths of the budget left, so a short total budget is not
/// swallowed by the fixed value.
pub(crate) fn bounded_first_try(deadline: Instant) -> Instant {
    let now = Instant::now();
    let slice = deadline.saturating_duration_since(now);
    let cap = first_try_cap().min(slice * 2 / 5);
    now.checked_add(cap).unwrap_or(deadline).min(deadline)
}

/// Decides whether a response becomes the answer or other upstreams are tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RespClass {
    /// Actually answers the question; the only class counted as success.
    Final,

    Retryable,

    /// Formally successful but with no answer: NXDOMAIN without a proving SOA, NOERROR without
    /// records for the name asked. Taking it would cache a false "does not exist".
    Incomplete,
}

/// NXDOMAIN is final only with a proving SOA; a negative answer without one cannot be cached, so it
/// is Incomplete.
fn response_class(request: &Message, resp: &Message) -> RespClass {
    let rcode = resp.header.rcode;
    if rcode == ResponseCode::NXDomain.0 {
        return if !has_requested_answer(request, resp) && has_negative_soa(request, resp) {
            RespClass::Final
        } else {
            RespClass::Incomplete
        };
    }
    if rcode == ResponseCode::YXDomain.0 {
        return RespClass::Final;
    }
    if rcode != ResponseCode::NoError.0 {
        return RespClass::Retryable;
    }
    if has_requested_answer(request, resp) || has_negative_soa(request, resp) {
        RespClass::Final
    } else {
        RespClass::Incomplete
    }
}

static NON_FINAL_COUNTS: OnceLock<Mutex<HashMap<(Endpoint, RespClass), u64>>> = OnceLock::new();
/// Bounds memory however many servers send such responses.
const MAX_NON_FINAL_COUNTERS: usize = 1024;

fn increment_non_final_count(
    counts: &mut HashMap<(Endpoint, RespClass), u64>,
    key: (Endpoint, RespClass),
) -> u64 {
    if !counts.contains_key(&key) && counts.len() >= MAX_NON_FINAL_COUNTERS {
        if let Some(victim) = counts.keys().next().cloned() {
            counts.remove(&victim);
        }
    }
    let count = counts.entry(key).or_insert(0);
    *count = count.saturating_add(1);
    *count
}

/// Counters are bounded and logging is rate-limited, so an upstream that keeps sending incomplete
/// answers does not turn the log into load.
fn observe_non_final(upstream: &Upstream, class: RespClass, request: &Message, response: &Message) {
    let count = {
        let mut counts = NON_FINAL_COUNTS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        increment_non_final_count(&mut counts, (upstream.endpoint.clone(), class))
    };
    if count == 1 || count.is_power_of_two() {
        let (qname, qtype) = request
            .questions
            .first()
            .map(|question| {
                (
                    question.name.to_ascii_lower(),
                    format!("{:?}", question.qtype),
                )
            })
            .unwrap_or_else(|| ("-".to_string(), "-".to_string()));
        onetdns_core::warn!(event = "forward.upstream_response_anomaly",
            upstream = %upstream.endpoint,
            transport = ?upstream.transport,
            response_class = ?class,
            rcode = response.header.rcode,
            answers = response.answers.len(),
            authorities = response.authorities.len(),
            qname = %qname,
            qtype = %qtype,
            count = count,
            "Upstream DNS server returned a message that is not a final response"
        );
    }
}

fn keep_best(best: &mut Option<(RespClass, Message)>, cls: RespClass, resp: Message) {
    let replace = match best {
        None => true,
        Some((RespClass::Incomplete, _)) => cls == RespClass::Retryable,
        _ => false,
    };
    if replace {
        *best = Some((cls, resp));
    }
}

/// Whether the proving SOA comes from an ancestor zone of the query name. Without this check, a
/// response with any SOA attached would prove a name absent, letting an attacker plant negative
/// answers for arbitrary names in the cache.
fn has_negative_soa(request: &Message, resp: &Message) -> bool {
    let Some(question) = request.questions.first() else {
        return false;
    };
    let Some(terminal) = terminal_answer_name(question, &resp.answers) else {
        return false;
    };
    resp.authorities.iter().any(|record| {
        record.class == question.qclass
            && record.rtype == RecordType::SOA
            && record.name.num_labels() <= terminal.num_labels()
            && terminal
                .suffix(record.name.num_labels())
                .eq_ignore_case(&record.name)
    })
}

/// Follows the CNAME/DNAME chain and checks the final name has records; without following it,
/// normal alias answers would be judged incomplete.
fn has_requested_answer(req: &Message, resp: &Message) -> bool {
    let Some(question) = req.questions.first() else {
        return false;
    };
    if question.qtype == RecordType::ANY {
        return cname_target_at(&question.name, question.qclass, &resp.answers).is_ok()
            && resp.answers.iter().any(|record| {
                record.class == question.qclass && record.name.eq_ignore_case(&question.name)
            });
    }

    let mut current = question.name.clone();
    let mut seen = HashSet::<Vec<u8>>::new();
    for _ in 0..16 {
        let cname = match cname_target_at(&current, question.qclass, &resp.answers) {
            Ok(target) => target,
            Err(()) => return false,
        };
        if resp.answers.iter().any(|record| {
            record.class == question.qclass
                && record.name.eq_ignore_case(&current)
                && record.rtype == question.qtype
        }) {
            return true;
        }
        if !seen.insert(current.canonical_key()) {
            return false;
        }
        let target = cname.or_else(|| dname_target(&current, question.qclass, &resp.answers));
        let Some(target) = target else {
            return false;
        };
        current = target;
    }
    false
}

fn cname_target_at(
    owner: &Name,
    qclass: onetdns_proto::DnsClass,
    answers: &[onetdns_proto::Record],
) -> Result<Option<Name>, ()> {
    let mut target: Option<Name> = None;
    for record in answers {
        if record.class != qclass || !record.name.eq_ignore_case(owner) {
            continue;
        }
        if let RData::Cname(candidate) = &record.rdata {
            if target
                .as_ref()
                .is_some_and(|current| !current.eq_ignore_case(candidate))
            {
                return Err(());
            }
            target = Some(candidate.clone());
        }
    }
    if target.is_some()
        && answers.iter().any(|record| {
            record.class == qclass
                && record.name.eq_ignore_case(owner)
                && !matches!(
                    record.rtype,
                    RecordType::CNAME | RecordType::RRSIG | RecordType::NSEC
                )
        })
    {
        return Err(());
    }
    Ok(target)
}

fn dname_target(
    current: &Name,
    qclass: onetdns_proto::DnsClass,
    answers: &[onetdns_proto::Record],
) -> Option<Name> {
    let record = answers
        .iter()
        .filter(|record| {
            record.class == qclass
                && matches!(&record.rdata, RData::Dname(_))
                && current.num_labels() > record.name.num_labels()
                && current
                    .suffix(record.name.num_labels())
                    .eq_ignore_case(&record.name)
        })
        .max_by_key(|record| record.name.num_labels())?;
    let RData::Dname(target_suffix) = &record.rdata else {
        return None;
    };
    if answers.iter().any(|candidate| {
        candidate.class == qclass
            && candidate.name.eq_ignore_case(&record.name)
            && matches!(
                &candidate.rdata,
                RData::Dname(other) if !other.eq_ignore_case(target_suffix)
            )
    }) {
        return None;
    }
    let prefix_len = current.num_labels() - record.name.num_labels();
    let mut labels: Vec<Vec<u8>> = current
        .labels()
        .take(prefix_len)
        .map(<[u8]>::to_vec)
        .collect();
    labels.extend(target_suffix.labels().map(<[u8]>::to_vec));
    Name::from_labels(labels).ok()
}

/// The chain length is capped; two CNAMEs pointing at each other would loop forever.
fn terminal_answer_name(
    question: &onetdns_proto::Question,
    answers: &[onetdns_proto::Record],
) -> Option<Name> {
    let mut current = question.name.clone();
    let mut seen = HashSet::new();
    for _ in 0..16 {
        if !seen.insert(current.canonical_key()) {
            return None;
        }
        let next = match cname_target_at(&current, question.qclass, answers) {
            Ok(Some(target)) => Some(target),
            Ok(None) => dname_target(&current, question.qclass, answers),
            Err(()) => return None,
        };
        match next {
            Some(next) => current = next,
            None => return Some(current),
        }
    }
    None
}

fn exchange_one(
    up: &Upstream,
    wire: &[u8],
    wire_id: u16,
    request: &Message,
    timeout: Duration,
    trust: &TrustStore,
) -> Result<Message, ForwardError> {
    match (&up.transport, &up.endpoint) {
        (Transport::Dot { server_name }, endpoint) => dot::exchange(
            endpoint,
            server_name,
            wire,
            wire_id,
            request,
            timeout,
            trust,
        ),
        (Transport::Doh { server_name, path }, endpoint) => {
            doh::exchange(endpoint, server_name, path, wire, request, timeout, trust)
        }
        (Transport::Udp, Endpoint::Direct(addr)) => {
            udp_exchange(*addr, wire, wire_id, request, timeout, false)
        }
        (Transport::Tcp, Endpoint::Direct(addr)) => {
            tcp_exchange(*addr, wire, wire_id, request, timeout)
        }
        (Transport::Doq { server_name }, Endpoint::Direct(addr)) => {
            doq::exchange(*addr, server_name, wire, request, timeout, trust)
        }
        (Transport::Doh3 { server_name, path }, Endpoint::Direct(addr)) => {
            doh3::exchange(*addr, server_name, path, wire, request, timeout, trust)
        }
        (
            Transport::Dnscrypt {
                provider_name,
                public_key,
            },
            Endpoint::Direct(addr),
        ) => dnscrypt::exchange(
            dnscrypt::Server {
                addr: *addr,
                provider_name,
                public_key,
            },
            wire,
            wire_id,
            request,
            timeout,
        ),
        // Sending these directly would go around the proxy the operator chose.
        (_, Endpoint::Socks5 { .. }) => Err(ForwardError::Io(
            "Only DoT and DoH upstreams can go through a SOCKS5 proxy".into(),
        )),
    }
}

#[derive(Clone, Copy, PartialEq)]
/// Mixed case in queries makes spoofed answers harder to match, but the answer must echo the mix
/// exactly, so it works only with upstreams that do.
enum CasePolicy {
    Normalized,

    Exact,

    /// Compares ignoring case but returns the caller's form.
    MergedExact,
}

/// Queries a given server directly, as the recursive resolver does with authoritative servers.
/// Question case is merged in the response.
pub fn query_server(
    server: SocketAddr,
    request: &Message,
    timeout: Duration,
) -> Result<Message, ForwardError> {
    query_server_with_case_policy(
        server,
        request,
        timeout,
        CasePolicy::Normalized,
        AuthorityTransport::Udp,
    )
}

/// The answer's question case must match what was sent exactly: this is where 0x20 encoding is
/// checked, and a case pattern different from the random one sent is treated as spoofed and
/// dropped.
pub fn query_server_case_sensitive(
    server: SocketAddr,
    request: &Message,
    timeout: Duration,
) -> Result<Message, ForwardError> {
    query_server_with_case_policy(
        server,
        request,
        timeout,
        CasePolicy::Exact,
        AuthorityTransport::Udp,
    )
}

/// For when 0x20 encoding is off.
pub fn query_server_case_merged(
    server: SocketAddr,
    request: &Message,
    timeout: Duration,
) -> Result<Message, ForwardError> {
    query_server_with_case_policy(
        server,
        request,
        timeout,
        CasePolicy::MergedExact,
        AuthorityTransport::Udp,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthorityTransport {
    /// Falls back to TCP on a truncated answer.
    Udp,

    /// TCP from the start, for networks where a middlebox intercepts UDP 53 and answers itself;
    /// there, UDP answers do not come from the authoritative server.
    Tcp,

    /// Opportunistic encryption to the server's encrypted endpoint; see `OpportunisticEncryption`.
    Encrypted(Encryption),
}

/// `merge_case` compares ignoring case and returns the caller's form; otherwise names are
/// lowercased.
pub fn query_server_over(
    server: SocketAddr,
    request: &Message,
    timeout: Duration,
    transport: AuthorityTransport,
    merge_case: bool,
) -> Result<Message, ForwardError> {
    let policy = if merge_case {
        CasePolicy::MergedExact
    } else {
        CasePolicy::Normalized
    };
    query_server_with_case_policy(server, request, timeout, policy, transport)
}

fn query_server_with_case_policy(
    server: SocketAddr,
    request: &Message,
    timeout: Duration,
    policy: CasePolicy,
    transport: AuthorityTransport,
) -> Result<Message, ForwardError> {
    let normalize_key_case = policy != CasePolicy::Exact;
    let exact_wire_echo = policy != CasePolicy::Normalized;

    let wire = request
        .try_encode()
        .map_err(|_| ForwardError::BadResponse)?;
    let key =
        AuthorityQueryKey::from_wire(server, transport, &wire, normalize_key_case).or_else(|| {
            AuthorityQueryKey::from_request(server, transport, request, normalize_key_case)
        });
    let Some(key) = key else {
        return query_server_uncollapsed(
            server,
            request,
            timeout,
            exact_wire_echo,
            wire,
            transport,
        );
    };

    let acquired = {
        let mut flights = authority_flights()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        acquire_authority_flight(&mut flights, &key)
    };
    let Some((flight, leader)) = acquired else {
        return query_server_uncollapsed(
            server,
            request,
            timeout,
            exact_wire_echo,
            wire,
            transport,
        );
    };

    let mut result = if leader {
        let result =
            query_server_uncollapsed(server, request, timeout, exact_wire_echo, wire, transport);

        authority_flights()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&key);
        if flight.waiters.load(Ordering::SeqCst) > 0 {
            flight.complete(result.clone());
        }
        result
    } else {
        flight.wait(timeout)
    };

    if policy == CasePolicy::Exact
        && result
            .as_ref()
            .is_ok_and(|response| !questions_case_exact(&request.questions, &response.questions))
    {
        result = Err(ForwardError::BadResponse);
    }
    if let Ok(response) = &mut result {
        response.header.id = request.header.id;
        response.header.opcode = request.header.opcode;
        if policy != CasePolicy::Exact {
            response.questions = request.questions.clone();
        }
        note_response_addr(server);
    }
    result
}

/// Octet-for-octet comparison of question sections, the core of the 0x20 check.
fn questions_case_exact(
    sent: &[onetdns_proto::Question],
    received: &[onetdns_proto::Question],
) -> bool {
    sent.len() == received.len()
        && sent.iter().zip(received).all(|(left, right)| {
            left.qtype == right.qtype
                && left.qclass == right.qclass
                && left.name.labels().len() == right.name.labels().len()
                && left
                    .name
                    .labels()
                    .iter()
                    .zip(right.name.labels())
                    .all(|(left, right)| left == right)
        })
}

/// Exchanges directly, outside single-flight.
fn query_server_uncollapsed(
    server: SocketAddr,
    request: &Message,
    timeout: Duration,
    require_exact_question_case: bool,
    mut wire: Vec<u8>,
    transport: AuthorityTransport,
) -> Result<Message, ForwardError> {
    let wire_id = next_id();
    wire[0..2].copy_from_slice(&wire_id.to_be_bytes());
    let mut response = match transport {
        AuthorityTransport::Udp => udp_exchange(
            server,
            &wire,
            wire_id,
            request,
            timeout,
            require_exact_question_case,
        )?,
        AuthorityTransport::Tcp => tcp_exchange(server, &wire, wire_id, request, timeout)?,
        AuthorityTransport::Encrypted(encryption) => {
            opportunistic::exchange(server, encryption, &wire, wire_id, request, timeout)?
        }
    };
    response.header.id = request.header.id;
    Ok(response)
}

/// Connecting to an encrypted upstream needs its address, and that lookup cannot go through the
/// upstream itself, so a separate bootstrap server is used. Only addresses on the queried name's
/// CNAME chain are accepted; using addresses of other names in the response would let the bootstrap
/// server steer this server anywhere.
pub fn resolve_via_bootstrap(
    host: &str,
    bootstrap: &[std::net::IpAddr],
    timeout: Duration,
) -> Option<(std::net::IpAddr, u32)> {
    use onetdns_proto::{Name, RecordType};
    if bootstrap.is_empty() {
        return None;
    }
    let deadline = deadline_after(timeout);
    let mut current = Name::from_str(host).ok()?;
    let mut seen = HashSet::new();
    let mut chain_ttl: Option<u32> = None;
    for _ in 0..8 {
        if !seen.insert(current.canonical_key()) {
            return None;
        }
        let mut cname: Option<(Name, u32)> = None;
        for qtype in [RecordType::A, RecordType::AAAA] {
            let q = Message::query(0, current.clone(), qtype);
            for &bip in bootstrap {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return None;
                }
                let Ok(resp) = query_server(SocketAddr::new(bip, 53), &q, remaining) else {
                    continue;
                };
                let (address, next) = bootstrap_answer(&resp, &current, qtype);
                if let Some((address, ttl)) = address {
                    return Some((address, chain_ttl.map_or(ttl, |previous| previous.min(ttl))));
                }
                if let Some((next, ttl)) = next {
                    match &mut cname {
                        Some((existing, existing_ttl)) if existing.eq_ignore_case(&next) => {
                            *existing_ttl = (*existing_ttl).min(ttl);
                        }
                        Some(_) => return None,
                        None => cname = Some((next, ttl)),
                    }
                }
            }
        }
        let (next, ttl) = cname?;
        chain_ttl = Some(chain_ttl.map_or(ttl, |previous| previous.min(ttl)));
        current = next;
    }
    None
}

/// Collects addresses only for names on the alias chain; a response whose chains disagree is
/// discarded whole.
fn bootstrap_answer(
    response: &Message,
    start: &onetdns_proto::Name,
    qtype: onetdns_proto::RecordType,
) -> (
    Option<(std::net::IpAddr, u32)>,
    Option<(onetdns_proto::Name, u32)>,
) {
    use onetdns_proto::{RData, RecordType, ResponseCode};
    if response.header.rcode != ResponseCode::NoError.0 {
        return (None, None);
    }
    let mut current = start.clone();
    let mut seen = HashSet::new();
    let mut cname = None;
    let mut chain_ttl: Option<u32> = None;
    for _ in 0..8 {
        if !seen.insert(current.canonical_key()) {
            return (None, None);
        }
        let next = match cname_target_at(&current, onetdns_proto::DnsClass::IN, &response.answers) {
            Ok(next) => next,
            Err(()) => return (None, None),
        };
        if let Some((address, ttl)) = response.answers.iter().find_map(|answer| {
            if !answer.name.eq_ignore_case(&current) || answer.rtype != qtype {
                return None;
            }
            let address = match (&answer.rdata, qtype) {
                (RData::A(ip), RecordType::A) => std::net::IpAddr::V4(*ip),
                (RData::Aaaa(ip), RecordType::AAAA) => std::net::IpAddr::V6(*ip),
                _ => return None,
            };
            Some((address, answer.ttl))
        }) {
            return (
                Some((address, chain_ttl.map_or(ttl, |previous| previous.min(ttl)))),
                cname,
            );
        }
        let Some(next) = next else {
            break;
        };
        let Some(ttl) = response
            .answers
            .iter()
            .filter(|record| {
                record.class == onetdns_proto::DnsClass::IN
                    && record.name.eq_ignore_case(&current)
                    && matches!(&record.rdata, RData::Cname(candidate) if candidate.eq_ignore_case(&next))
            })
            .map(|record| record.ttl)
            .min()
        else {
            return (None, None);
        };
        let effective_ttl = chain_ttl.map_or(ttl, |previous| previous.min(ttl));
        chain_ttl = Some(effective_ttl);
        cname = Some((next.clone(), effective_ttl));
        current = next;
    }
    (None, cname)
}

/// Takes a socket from the pool.
fn udp_exchange(
    upstream: SocketAddr,
    wire: &[u8],
    wire_id: u16,
    request: &Message,
    timeout: Duration,
    require_exact_question_case: bool,
) -> Result<Message, ForwardError> {
    let bind = outgoing_bind(upstream);
    let (sock, uses, cached_timeout) = take_pooled_udp_socket(bind).map_err(io_err)?;
    let mut exchange = ExchangeSocket {
        sock: &sock,
        rcv_timeout: cached_timeout,
    };
    let result = udp_exchange_on(
        &mut exchange,
        upstream,
        wire,
        wire_id,
        request,
        timeout,
        require_exact_question_case,
    );
    let rcv_timeout = exchange.rcv_timeout;

    if result.is_ok() {
        return_pooled_udp_socket(bind, sock, uses, rcv_timeout);
    } else {
        drop(sock);
        discard_pooled_udp_socket(bind);
    }
    result
}

struct ExchangeSocket<'a> {
    sock: &'a UdpSocket,
    rcv_timeout: Option<Duration>,
}

/// Keeps receiving until the deadline, dropping answers whose ID or question does not match, so
/// spoofing attempts cannot take the real answer's place. The loop never runs past the deadline, so
/// flooding invalid answers cannot extend the query budget. Retries over TCP on TC.
fn udp_exchange_on(
    exchange: &mut ExchangeSocket<'_>,
    upstream: SocketAddr,
    wire: &[u8],
    wire_id: u16,
    request: &Message,
    timeout: Duration,
    require_exact_question_case: bool,
) -> Result<Message, ForwardError> {
    let sock = exchange.sock;
    let deadline = deadline_after(timeout);
    sock.send_to(wire, upstream).map_err(io_err)?;
    let mut saw_case_mismatch = false;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(if saw_case_mismatch {
                ForwardError::BadResponse
            } else {
                ForwardError::Timeout
            });
        }

        if !rcv_timeout_reusable(exchange.rcv_timeout, remaining) {
            sock.set_read_timeout(Some(remaining)).map_err(io_err)?;
            exchange.rcv_timeout = Some(remaining);
        }
        let received = UDP_RECV_BUFFER.with(|slot| {
            let mut buf = slot.borrow_mut();
            sock.recv_from(&mut buf).map(|(n, from)| {
                // Only datagrams from the upstream we queried are parsed; mismatched sources are
                // dropped below anyway, so filter before paying for the parse.
                if from == upstream {
                    (from, Message::parse_udp_reply(&buf[..n]))
                } else {
                    (from, None)
                }
            })
        });
        let (from, parsed) = match received {
            Ok(v) => v,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err(if saw_case_mismatch {
                    ForwardError::BadResponse
                } else {
                    ForwardError::Timeout
                });
            }
            Err(e) => return Err(io_err(e)),
        };

        if from != upstream {
            continue;
        }
        let Some(resp) = parsed else {
            continue;
        };
        if validate_response(request, &resp, Some(wire_id)).is_err() {
            continue;
        }
        if require_exact_question_case && !questions_case_exact(&request.questions, &resp.questions)
        {
            saw_case_mismatch = true;
            continue;
        }
        if resp.header.truncated {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ForwardError::Timeout);
            }
            return tcp_exchange(upstream, wire, wire_id, request, remaining);
        }
        return Ok(resp);
    }
}

struct Idle<C> {
    conn: C,
    last_used: Instant,
}

/// Connections between queries to authoritative servers. Shared by the process: per-thread pools
/// would keep the exchange threads recursion starts per server from using each other's
/// connections.
struct IdlePool<K, C> {
    idle: HashMap<K, Vec<Idle<C>>>,
    total: usize,
}

/// As many as concurrent queries to one server need.
const IDLE_PER_SERVER: usize = 2;

/// Recursion goes through hundreds of servers; without a cap idle connections would use up file
/// descriptors.
const IDLE_TOTAL: usize = 256;

impl<K: std::hash::Hash + Eq, C> IdlePool<K, C> {
    fn new() -> Self {
        Self {
            idle: HashMap::new(),
            total: 0,
        }
    }

    /// Drops connections idle too long. A connection the server has since closed can still come
    /// out; its first exchange fails at once, so it is not checked here.
    fn take(&mut self, key: &K) -> Option<C> {
        let conns = self.idle.get_mut(key)?;
        let mut found = None;
        while let Some(idle) = conns.pop() {
            self.total -= 1;
            if idle.last_used.elapsed() < tcp_idle_reuse_max() {
                found = Some(idle.conn);
                break;
            }
        }
        if conns.is_empty() {
            self.idle.remove(key);
        }
        found
    }

    /// Closes the connection past the caps.
    fn put(&mut self, key: K, conn: C) {
        if self.total >= IDLE_TOTAL {
            return;
        }
        let conns = self.idle.entry(key).or_default();
        if conns.len() >= IDLE_PER_SERVER {
            return;
        }
        conns.push(Idle {
            conn,
            last_used: Instant::now(),
        });
        self.total += 1;
    }
}

/// Keyed by bind address and server address.
fn tcp_idle_pool() -> &'static Mutex<IdlePool<(SocketAddr, SocketAddr), TcpStream>> {
    static POOL: OnceLock<Mutex<IdlePool<(SocketAddr, SocketAddr), TcpStream>>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(IdlePool::new()))
}

fn take_idle_tcp(bind: SocketAddr, upstream: SocketAddr) -> Option<TcpStream> {
    tcp_idle_pool()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take(&(bind, upstream))
}

/// Only connections whose answer was read in full.
fn return_idle_tcp(bind: SocketAddr, upstream: SocketAddr, stream: TcpStream) {
    tcp_idle_pool()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .put((bind, upstream), stream);
}

/// Plain TCP with 2-byte length framing. Asks over a kept connection to the server first: a new
/// connection costs another handshake round trip, hundreds of milliseconds per query for distant
/// servers. A kept connection may have died, so its first try is cut short and a failure retries on
/// a fresh connection.
fn tcp_exchange(
    upstream: SocketAddr,
    wire: &[u8],
    wire_id: u16,
    request: &Message,
    timeout: Duration,
) -> Result<Message, ForwardError> {
    let deadline = deadline_after(timeout);
    if wire.len() > 0xffff {
        return Err(ForwardError::BadResponse);
    }
    let mut framed = Vec::with_capacity(wire.len() + 2);
    framed.extend_from_slice(&(wire.len() as u16).to_be_bytes());
    framed.extend_from_slice(wire);
    let bind = outgoing_bind(upstream);

    if let Some(mut stream) = take_idle_tcp(bind, upstream) {
        match tcp_roundtrip(
            &mut stream,
            &framed,
            wire_id,
            request,
            bounded_first_try(deadline),
        ) {
            Ok(resp) => {
                return_idle_tcp(bind, upstream, stream);
                return Ok(resp);
            }
            Err(error) => {
                onetdns_core::debug!(event = "forward.conn_retry",
                    transport = "tcp",
                    addr = %upstream,
                    reason = ?error,
                    "Could not reuse the existing connection; retrying on a new one"
                );
            }
        }
    }

    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ForwardError::Timeout);
    }
    let mut stream = bound_tcp::connect(bind, upstream, remaining).map_err(io_err)?;
    let resp = tcp_roundtrip(&mut stream, &framed, wire_id, request, deadline)?;
    return_idle_tcp(bind, upstream, stream);
    Ok(resp)
}

fn tcp_roundtrip(
    stream: &mut TcpStream,
    framed: &[u8],
    wire_id: u16,
    request: &Message,
    deadline: Instant,
) -> Result<Message, ForwardError> {
    write_all_deadline(stream, framed, deadline)?;

    let mut lenb = [0u8; 2];
    read_exact_deadline(stream, &mut lenb, deadline)?;
    let rlen = u16::from_be_bytes(lenb) as usize;
    let mut rbuf = vec![0u8; rlen];
    read_exact_deadline(stream, &mut rbuf, deadline)?;

    let resp = Message::parse(&rbuf).map_err(|_| ForwardError::BadResponse)?;
    validate_response(request, &resp, Some(wire_id))?;
    Ok(resp)
}

/// Recomputes the time left after each partial write.
fn write_all_deadline(
    stream: &mut TcpStream,
    mut buf: &[u8],
    deadline: Instant,
) -> Result<(), ForwardError> {
    while !buf.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ForwardError::Timeout);
        }
        stream.set_write_timeout(Some(remaining)).map_err(io_err)?;
        match stream.write(buf) {
            Ok(0) => {
                return Err(ForwardError::Io(
                    "Could not write to the TCP connection (wrote 0 bytes)".into(),
                ))
            }
            Ok(written) => buf = &buf[written..],
            Err(error) => return Err(io_err(error)),
        }
    }
    Ok(())
}

/// Checks the absolute deadline after each partial read; socket timeouts alone would let a peer
/// sending one byte at a time stretch the budget forever.
fn read_exact_deadline(
    stream: &mut TcpStream,
    mut buf: &mut [u8],
    deadline: Instant,
) -> Result<(), ForwardError> {
    while !buf.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ForwardError::Timeout);
        }
        stream.set_read_timeout(Some(remaining)).map_err(io_err)?;
        match stream.read(buf) {
            Ok(0) => return Err(ForwardError::Io("TCP connection closed early".into())),
            Ok(read) => buf = &mut buf[read..],
            Err(error) => return Err(io_err(error)),
        }
    }
    Ok(())
}

pub(crate) fn question_matches(req: &Message, resp: &Message) -> bool {
    req.questions.len() == resp.questions.len()
        && req.questions.iter().zip(&resp.questions).all(|(a, b)| {
            a.qtype == b.qtype && a.qclass == b.qclass && a.name.eq_ignore_case(&b.name)
        })
}

/// Both ID and question must match; otherwise anyone's response would enter this server's cache.
pub(crate) fn validate_response(
    request: &Message,
    response: &Message,
    expected_id: Option<u16>,
) -> Result<(), ForwardError> {
    if !response.header.response
        || response.header.opcode != request.header.opcode
        || expected_id.is_some_and(|id| response.header.id != id)
        || !question_matches(request, response)
    {
        return Err(ForwardError::BadResponse);
    }
    Ok(())
}

pub(crate) fn io_err(e: std::io::Error) -> ForwardError {
    if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
        ForwardError::Timeout
    } else {
        ForwardError::Io(e.to_string())
    }
}

/// Logs why an encrypted upstream connection failed. The reason is folded into TransportExhausted
/// on the way up, and only here is it known whether the certificate expired, the CA is unknown, or
/// the server is unreachable, which covers most encrypted upstream failures. Logs only power-of-two
/// occurrences per transport, since a dead upstream fails every query.
pub(crate) fn note_upstream_connect_failure(
    transport: &'static str,
    addr: impl std::fmt::Display,
    server_name: &str,
    error: &impl std::fmt::Display,
) {
    use std::sync::atomic::{AtomicU64, Ordering};
    /// Per transport: dot, doh, doq, doh3, dnscrypt.
    static COUNTS: [AtomicU64; 5] = [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ];
    let slot = match transport {
        "dot" => 0,
        "doh" => 1,
        "doq" => 2,
        "dnscrypt" => 4,
        _ => 3,
    };
    let count = COUNTS[slot].fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::warn!(event = "forward.upstream_connect_failed", transport = transport, addr = %addr, server_name = server_name, count = count, %error, "Could not connect to the encrypted upstream DNS server");
    }
}

type ParallelJob = Box<dyn FnOnce() + Send + 'static>;

const MAX_PARALLEL_INFLIGHT: usize = 512;
/// How long an idle parallel worker stays.
const PARALLEL_WORKER_IDLE: Duration = Duration::from_secs(30);
static PARALLEL_INFLIGHT: AtomicUsize = AtomicUsize::new(0);
static PARALLEL_EXECUTOR: OnceLock<ParallelExecutor> = OnceLock::new();

struct ParallelQueue {
    jobs: VecDeque<ParallelJob>,
}

/// Grows with demand and empties when idle.
struct ParallelExecutorShared {
    queue: Mutex<ParallelQueue>,
    ready: Condvar,
    live: AtomicUsize,
    /// Workers free to take a job, including ones still starting.
    idle: AtomicUsize,
    next_worker: AtomicUsize,
}

/// Bounded dynamic worker pool for the Parallel strategy.
struct ParallelExecutor {
    shared: Arc<ParallelExecutorShared>,
    /// Queue length limit.
    capacity: usize,
    max_workers: usize,
    idle_timeout: Duration,
}

impl ParallelExecutor {
    /// No threads until the first job.
    fn new(max_workers: usize, capacity: usize, idle_timeout: Duration) -> Self {
        Self {
            shared: Arc::new(ParallelExecutorShared {
                queue: Mutex::new(ParallelQueue {
                    jobs: VecDeque::new(),
                }),
                ready: Condvar::new(),
                live: AtomicUsize::new(0),
                idle: AtomicUsize::new(0),
                next_worker: AtomicUsize::new(0),
            }),
            capacity: capacity.max(1),
            max_workers: max_workers.max(1),
            idle_timeout,
        }
    }

    /// The caller must hold the queue lock.
    fn spawn_worker_locked(&self) -> bool {
        let index = self.shared.next_worker.fetch_add(1, Ordering::Relaxed);
        self.shared.live.fetch_add(1, Ordering::Relaxed);
        self.shared.idle.fetch_add(1, Ordering::Relaxed);
        let shared = self.shared.clone();
        let idle_timeout = self.idle_timeout;
        match std::thread::Builder::new()
            .name(format!("onetdns-forward-parallel-{index}"))
            .spawn(move || parallel_worker_loop(shared, idle_timeout))
        {
            Ok(_) => true,
            Err(error) => {
                self.shared.live.fetch_sub(1, Ordering::Relaxed);
                self.shared.idle.fetch_sub(1, Ordering::Relaxed);
                /// Logs only samples, so repeated resource exhaustion does not exhaust the log too.
                static FAILURES: AtomicUsize = AtomicUsize::new(0);
                let count = FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
                if count.is_power_of_two() {
                    onetdns_core::warn!(event = "forward.parallel_worker_start_failed", index, count, %error, "Could not start parallel upstream query workers; handling those queries sequentially");
                }
                false
            }
        }
    }

    /// Adds workers only as far as the current backlog needs.
    fn try_submit(&self, job: ParallelJob) -> bool {
        let mut queue = self
            .shared
            .queue
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if queue.jobs.len() >= self.capacity {
            return false;
        }
        if self.shared.live.load(Ordering::Relaxed) == 0 && !self.spawn_worker_locked() {
            return false;
        }
        queue.jobs.push_back(job);
        let queued = queue.jobs.len();
        let idle = self.shared.idle.load(Ordering::Relaxed);
        let room = self
            .max_workers
            .saturating_sub(self.shared.live.load(Ordering::Relaxed));
        for _ in 0..queued.saturating_sub(idle).min(room) {
            if !self.spawn_worker_locked() {
                break;
            }
        }
        drop(queue);
        self.shared.ready.notify_one();
        true
    }
}

/// A job's panic is contained to that job; the worker takes the next one.
fn parallel_worker_loop(shared: Arc<ParallelExecutorShared>, idle_timeout: Duration) {
    loop {
        let job = {
            let mut queue = shared
                .queue
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            loop {
                if let Some(job) = queue.jobs.pop_front() {
                    shared.idle.fetch_sub(1, Ordering::Relaxed);
                    break job;
                }
                let (next, wait) = shared
                    .ready
                    .wait_timeout(queue, idle_timeout)
                    .unwrap_or_else(|error| error.into_inner());
                queue = next;
                if wait.timed_out() && queue.jobs.is_empty() {
                    shared.idle.fetch_sub(1, Ordering::Relaxed);
                    shared.live.fetch_sub(1, Ordering::Relaxed);
                    return;
                }
            }
        };
        let _ = onetdns_core::isolation::catch_request(job);
        shared.idle.fetch_add(1, Ordering::Relaxed);
    }
}

fn parallel_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().saturating_mul(4))
        .unwrap_or(32)
        .clamp(8, 128)
}

fn parallel_executor() -> &'static ParallelExecutor {
    PARALLEL_EXECUTOR.get_or_init(|| {
        ParallelExecutor::new(
            parallel_worker_count(),
            MAX_PARALLEL_INFLIGHT,
            PARALLEL_WORKER_IDLE,
        )
    })
}

/// False when the queue is full; the caller runs the job serially.
fn submit_parallel_job<F>(job: F) -> bool
where
    F: FnOnce() + Send + 'static,
{
    parallel_executor().try_submit(Box::new(job))
}

/// Returns how many were granted. The global cap keeps upstream load bounded however many queries
/// run at once.
fn acquire_parallel_slots(want: usize) -> usize {
    let mut granted = 0;
    for _ in 0..want {
        let prev = PARALLEL_INFLIGHT.fetch_add(1, Ordering::Relaxed);
        if prev >= MAX_PARALLEL_INFLIGHT {
            PARALLEL_INFLIGHT.fetch_sub(1, Ordering::Relaxed);
            break;
        }
        granted += 1;
    }
    granted
}

fn release_parallel_slot() {
    PARALLEL_INFLIGHT.fetch_sub(1, Ordering::Relaxed);
}

/// Releases itself on drop.
struct ParallelSlot;
impl Drop for ParallelSlot {
    fn drop(&mut self) {
        release_parallel_slot();
    }
}

/// Must be secure random: a sequential or predictable ID makes spoofed answers easy to match and
/// lowers the bar for cache poisoning.
fn next_id() -> u16 {
    u16::from_be_bytes(onetdns_core::ephemeral_random_array())
}

#[cfg(test)]
mod tests {
    use super::*;
    use onetdns_proto::{Name, RData, Record, RecordType, ResponseCode};
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};
    use std::sync::{Arc, Barrier};

    fn wait_until(timeout: Duration, condition: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if condition() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        condition()
    }

    #[test]
    fn upstream_connections_send_without_waiting_for_acks() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let stream = connect_upstream(
            listener.local_addr().unwrap(),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        assert!(stream.get_ref().nodelay().unwrap());
    }

    #[test]
    fn parallel_executor_scales_on_demand_and_retires_idle_workers() {
        let executor = ParallelExecutor::new(16, 32, Duration::from_millis(20));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(std::sync::atomic::AtomicBool::new(false));

        for _ in 0..4 {
            let active = active.clone();
            let peak = peak.clone();
            let completed = completed.clone();
            let release = release.clone();
            assert!(executor.try_submit(Box::new(move || {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                while !release.load(Ordering::SeqCst) {
                    std::thread::yield_now();
                }
                active.fetch_sub(1, Ordering::SeqCst);
                completed.fetch_add(1, Ordering::SeqCst);
            })));
        }

        assert!(wait_until(Duration::from_secs(1), || {
            active.load(Ordering::SeqCst) == 4
        }));
        assert_eq!(peak.load(Ordering::SeqCst), 4);
        assert_eq!(executor.shared.live.load(Ordering::SeqCst), 4);
        release.store(true, Ordering::SeqCst);
        assert!(wait_until(Duration::from_secs(1), || {
            completed.load(Ordering::SeqCst) == 4
        }));
        assert!(wait_until(Duration::from_secs(1), || {
            executor.shared.live.load(Ordering::SeqCst) == 0
        }));
        assert_eq!(executor.shared.idle.load(Ordering::SeqCst), 0);

        let restarted = Arc::new(AtomicUsize::new(0));
        let job_restarted = restarted.clone();
        assert!(executor.try_submit(Box::new(move || {
            job_restarted.fetch_add(1, Ordering::SeqCst);
        })));
        assert!(wait_until(Duration::from_secs(1), || {
            restarted.load(Ordering::SeqCst) == 1
        }));
        assert!(executor.shared.live.load(Ordering::SeqCst) <= 1);
    }

    #[test]
    fn parallel_executor_isolates_job_panics() {
        let executor = ParallelExecutor::new(1, 4, Duration::from_secs(1));
        let completed = Arc::new(AtomicUsize::new(0));
        assert!(executor.try_submit(Box::new(|| panic!("parallel job"))));
        let job_completed = completed.clone();
        assert!(executor.try_submit(Box::new(move || {
            job_completed.fetch_add(1, Ordering::SeqCst);
        })));
        assert!(wait_until(Duration::from_secs(1), || {
            completed.load(Ordering::SeqCst) == 1
        }));
        assert!(executor.shared.live.load(Ordering::SeqCst) <= 1);
    }

    #[test]
    fn authority_single_flight_state_is_bounded_without_breaking_existing_sharing() {
        let mut flights = HashMap::new();
        for index in 0..MAX_AUTHORITY_FLIGHTS {
            let key = AuthorityQueryKey {
                server: SocketAddr::from(([192, 0, 2, 1], 53)),
                transport: AuthorityTransport::Udp,
                normalized_wire: index.to_be_bytes().to_vec().into(),
            };
            assert!(acquire_authority_flight(&mut flights, &key).is_some());
        }

        let existing_key = flights.keys().next().unwrap().clone();
        let existing = flights.get(&existing_key).unwrap().clone();
        let shared = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let (shared, leader) =
                        acquire_authority_flight(&mut flights, &existing_key).unwrap();
                    assert!(!leader);
                    shared
                })
                .join()
                .unwrap()
        });
        assert!(Arc::ptr_eq(&existing, &shared));

        let overflow = AuthorityQueryKey {
            server: SocketAddr::from(([192, 0, 2, 2], 53)),
            transport: AuthorityTransport::Udp,
            normalized_wire: b"overflow".to_vec().into(),
        };
        assert!(acquire_authority_flight(&mut flights, &overflow).is_none());
        assert_eq!(flights.len(), MAX_AUTHORITY_FLIGHTS);
    }

    #[test]
    fn wire_key_matches_message_key_and_collapses_case() {
        let server = SocketAddr::from(([192, 0, 2, 7], 53));
        let upper = query("MiXeD.Example");
        let lower = query("mixed.example");
        let wire_upper = upper.try_encode().unwrap();
        let wire_lower = lower.try_encode().unwrap();

        let by_wire_upper =
            AuthorityQueryKey::from_wire(server, AuthorityTransport::Udp, &wire_upper, true)
                .unwrap();
        let by_wire_lower =
            AuthorityQueryKey::from_wire(server, AuthorityTransport::Udp, &wire_lower, true)
                .unwrap();
        let by_message =
            AuthorityQueryKey::from_request(server, AuthorityTransport::Udp, &upper, true).unwrap();
        assert_eq!(by_wire_upper, by_wire_lower);
        assert_eq!(by_wire_upper, by_message);

        let exact_upper =
            AuthorityQueryKey::from_wire(server, AuthorityTransport::Udp, &wire_upper, false)
                .unwrap();
        let exact_lower =
            AuthorityQueryKey::from_wire(server, AuthorityTransport::Udp, &wire_lower, false)
                .unwrap();
        assert_ne!(exact_upper, exact_lower);
        assert_eq!(
            exact_upper,
            AuthorityQueryKey::from_request(server, AuthorityTransport::Udp, &upper, false)
                .unwrap()
        );
    }

    #[test]
    /// Waiting on itself would hang.
    fn same_thread_leader_flight_is_bypassed_not_joined() {
        let server = SocketAddr::from(([192, 0, 2, 1], 53));
        let request = Message::query(1, Name::from_str("nest.example").unwrap(), RecordType::A);
        let key = AuthorityQueryKey::from_request(server, AuthorityTransport::Udp, &request, true)
            .unwrap();
        let mut flights = HashMap::new();

        let (leader_flight, leader) = acquire_authority_flight(&mut flights, &key).unwrap();
        assert!(leader);

        assert!(acquire_authority_flight(&mut flights, &key).is_none());
        assert_eq!(leader_flight.waiters.load(Ordering::SeqCst), 0);

        let other = std::thread::spawn(move || {
            let mut flights = HashMap::new();
            let request =
                Message::query(2, Name::from_str("cross.example").unwrap(), RecordType::A);
            let key =
                AuthorityQueryKey::from_request(server, AuthorityTransport::Udp, &request, true)
                    .unwrap();
            let _ = acquire_authority_flight(&mut flights, &key).unwrap();
            (flights, key)
        });
        let (mut flights, key) = other.join().unwrap();
        let (cross_flight, leader) = acquire_authority_flight(&mut flights, &key).unwrap();
        assert!(!leader);
        assert_eq!(cross_flight.waiters.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn oversized_authority_queries_bypass_global_single_flight_state() {
        let server = SocketAddr::from(([192, 0, 2, 1], 53));
        let mut request =
            Message::query(1, Name::from_str("large.example").unwrap(), RecordType::A);
        request.additionals.push(Record::new(
            Name::root(),
            0,
            RData::Unknown(65_000, vec![0; MAX_AUTHORITY_FLIGHT_KEY_BYTES + 1]),
        ));
        assert!(
            AuthorityQueryKey::from_request(server, AuthorityTransport::Udp, &request, true)
                .is_none()
        );
    }

    #[test]
    fn authority_single_flight_key_preserves_raw_qname_octets() {
        let server = SocketAddr::from(([192, 0, 2, 1], 53));
        let request = |id, label| {
            Message::query(
                id,
                Name::from_labels(vec![vec![label]]).unwrap(),
                RecordType::A,
            )
        };

        let first = AuthorityQueryKey::from_request(
            server,
            AuthorityTransport::Udp,
            &request(1, 0xff),
            true,
        )
        .unwrap();
        let second = AuthorityQueryKey::from_request(
            server,
            AuthorityTransport::Udp,
            &request(2, 0xfe),
            true,
        )
        .unwrap();
        assert_ne!(first, second);

        let upper = Message::query(3, Name::from_str("WWW.example").unwrap(), RecordType::A);
        let lower = Message::query(4, Name::from_str("www.EXAMPLE").unwrap(), RecordType::A);
        assert_eq!(
            AuthorityQueryKey::from_request(server, AuthorityTransport::Udp, &upper, true),
            AuthorityQueryKey::from_request(server, AuthorityTransport::Udp, &lower, true)
        );
    }

    #[test]
    fn extreme_timeout_cannot_overflow_instant_deadline() {
        let before = Instant::now();
        let deadline = deadline_after(Duration::MAX);
        assert!(deadline >= before);
        assert!(deadline <= Instant::now());
    }

    #[test]
    /// A single port makes spoofing easier to match.
    fn udp_socket_pool_grows_to_distinct_ports_before_reusing() {
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let mut ports = std::collections::HashSet::new();
        for _ in 0..UDP_SOCKET_POOL_SIZE {
            let (sock, uses, _) = take_pooled_udp_socket(bind).unwrap();
            assert_eq!(uses, 1, "상한 전에는 매번 새 소켓을 바인드한다");
            ports.insert(sock.local_addr().unwrap().port());
            return_pooled_udp_socket(bind, sock, uses, None);
        }
        assert_eq!(
            ports.len(),
            UDP_SOCKET_POOL_SIZE,
            "보유 포트가 서로 달라야 질의별 선택에 엔트로피가 생긴다"
        );

        let (sock, uses, _) = take_pooled_udp_socket(bind).unwrap();
        assert!(uses >= 2, "상한 후에는 보유 소켓을 재사용");
        assert!(ports.contains(&sock.local_addr().unwrap().port()));
        return_pooled_udp_socket(bind, sock, uses, None);
    }

    #[test]
    fn cached_receive_timeout_never_outlives_the_deadline() {
        let ms = Duration::from_millis;

        assert!(!rcv_timeout_reusable(None, ms(2000)));

        assert!(rcv_timeout_reusable(Some(ms(2000)), ms(2000)));
        assert!(rcv_timeout_reusable(
            Some(ms(2000)),
            ms(2000) + Duration::from_micros(900)
        ));

        assert!(!rcv_timeout_reusable(Some(ms(2000)), ms(1999)));

        assert!(!rcv_timeout_reusable(Some(ms(500)), ms(2000)));

        assert!(!rcv_timeout_reusable(
            Some(ms(2000)),
            Duration::from_micros(10)
        ));
    }

    #[test]
    fn udp_socket_pool_retires_by_use_count() {
        let bind: SocketAddr = "127.0.0.2:0".parse().unwrap();
        let (sock, _, _) = take_pooled_udp_socket(bind).unwrap();

        return_pooled_udp_socket(bind, sock, UDP_SOCKET_POOL_MAX_USES, None);
        let (next, uses, _) = take_pooled_udp_socket(bind).unwrap();
        assert_eq!(uses, 1, "수명 소진 후 새 소켓");
        drop(next);
    }

    #[test]
    fn failed_exchange_does_not_leak_pool_capacity() {
        let bind: SocketAddr = "127.0.0.3:0".parse().unwrap();

        for _ in 0..(UDP_SOCKET_POOL_SIZE * 2) {
            let (sock, uses, _) = take_pooled_udp_socket(bind).unwrap();
            assert_eq!(uses, 1, "실패가 반복되면 매번 새 포트");
            drop(sock);
            discard_pooled_udp_socket(bind);
        }
        let owned = UDP_SOCKET_POOL.with(|pool| pool.borrow().get(&bind).map_or(0, |e| e.owned));
        assert_eq!(owned, 0, "보유 수가 새지 않는다");
    }

    #[test]
    fn malformed_in_memory_query_is_never_sent_as_servfail_wire() {
        let server = SocketAddr::from(([127, 0, 0, 1], 9));
        let mut request = query("malformed.example");
        request.header.rcode = 0x1000;

        let forwarder = Forwarder::new(vec![server], Duration::from_millis(50));
        assert!(matches!(
            forwarder.resolve(&request),
            Err(ForwardError::BadResponse)
        ));
        assert!(matches!(
            query_server(server, &request, Duration::from_millis(50)),
            Err(ForwardError::BadResponse)
        ));
    }

    #[test]
    fn non_final_observation_counters_stay_bounded() {
        let mut counts = HashMap::new();
        for port in 1..=MAX_NON_FINAL_COUNTERS as u16 {
            increment_non_final_count(
                &mut counts,
                (
                    Endpoint::Direct(SocketAddr::from(([192, 0, 2, 1], port))),
                    RespClass::Retryable,
                ),
            );
        }
        assert_eq!(counts.len(), MAX_NON_FINAL_COUNTERS);
        let new_key = (
            Endpoint::Direct(SocketAddr::from(([192, 0, 2, 2], 53))),
            RespClass::Incomplete,
        );
        assert_eq!(increment_non_final_count(&mut counts, new_key.clone()), 1);
        assert_eq!(counts.len(), MAX_NON_FINAL_COUNTERS);
        assert_eq!(increment_non_final_count(&mut counts, new_key), 2);
    }

    #[test]
    /// Otherwise it would connect to an address someone slipped in.
    fn bootstrap_accepts_only_the_queried_cname_chain() {
        let start = Name::from_str("resolver.example").unwrap();
        let target = Name::from_str("edge.example").unwrap();
        let unrelated = Name::from_str("attacker.example").unwrap();
        let mut response = Message::default();
        response.header.response = true;
        response.answers.push(Record::new(
            unrelated,
            60,
            RData::A(Ipv4Addr::new(203, 0, 113, 66)),
        ));
        response
            .answers
            .push(Record::new(start.clone(), 7, RData::Cname(target.clone())));
        response.answers.push(Record::new(
            target,
            60,
            RData::A(Ipv4Addr::new(192, 0, 2, 53)),
        ));

        let (address, cname) = bootstrap_answer(&response, &start, RecordType::A);
        assert_eq!(address, Some(("192.0.2.53".parse().unwrap(), 7)));
        let (cname, ttl) = cname.unwrap();
        assert_eq!(cname.to_ascii_lower(), "edge.example");
        assert_eq!(ttl, 7);

        response.answers.remove(1);
        response.answers.remove(1);
        assert_eq!(
            bootstrap_answer(&response, &start, RecordType::A),
            (None, None)
        );
    }

    #[test]
    fn bootstrap_rejects_conflicting_alias_data() {
        let start = Name::from_str("resolver.example").unwrap();
        let first = Name::from_str("one.example").unwrap();
        let second = Name::from_str("two.example").unwrap();
        let mut response = Message::default();
        response.header.response = true;
        response
            .answers
            .push(Record::new(start.clone(), 60, RData::Cname(first)));
        response
            .answers
            .push(Record::new(start.clone(), 60, RData::Cname(second)));
        assert_eq!(
            bootstrap_answer(&response, &start, RecordType::A),
            (None, None)
        );

        response.answers.truncate(1);
        response.answers.push(Record::new(
            start.clone(),
            60,
            RData::A(Ipv4Addr::new(192, 0, 2, 53)),
        ));
        assert_eq!(
            bootstrap_answer(&response, &start, RecordType::A),
            (None, None)
        );
    }

    #[test]
    fn bootstrap_timeout_is_an_overall_deadline() {
        let started = Instant::now();
        assert!(resolve_via_bootstrap(
            "resolver.example",
            &["192.0.2.1".parse().unwrap()],
            Duration::ZERO,
        )
        .is_none());
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    /// TCP server answering each query with an empty response. With `close_after_answer` it closes
    /// after one answer. Returns the address and the number of connections accepted.
    fn spawn_tcp_answerer(close_after_answer: bool) -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().map_while(Result::ok) {
                counter.fetch_add(1, Ordering::SeqCst);
                std::thread::spawn(move || loop {
                    let mut len = [0u8; 2];
                    if stream.read_exact(&mut len).is_err() {
                        return;
                    }
                    let mut wire = vec![0; u16::from_be_bytes(len) as usize];
                    if stream.read_exact(&mut wire).is_err() {
                        return;
                    }
                    let request = Message::parse(&wire).unwrap();
                    let mut response = Message::default();
                    response.header.id = request.header.id;
                    response.header.response = true;
                    response.questions = request.questions.clone();
                    let wire = response.try_encode().unwrap();
                    let mut framed = (wire.len() as u16).to_be_bytes().to_vec();
                    framed.extend_from_slice(&wire);
                    if stream.write_all(&framed).is_err() || close_after_answer {
                        return;
                    }
                });
            }
        });
        (addr, accepted)
    }

    fn ask_over_tcp(addr: SocketAddr, id: u16) -> Result<Message, ForwardError> {
        let request = Message::query(id, Name::from_str("pool.example").unwrap(), RecordType::A);
        let wire = request.try_encode().unwrap();
        tcp_exchange(addr, &wire, id, &request, Duration::from_secs(2))
    }

    #[test]
    /// A new connection costs another handshake round trip, which every query pays on networks
    /// where UDP 53 is blocked and authoritative servers are asked over TCP.
    fn tcp_exchange_reuses_the_connection_to_the_same_server() {
        let (addr, accepted) = spawn_tcp_answerer(false);
        ask_over_tcp(addr, 0x7001).expect("첫 질의");
        ask_over_tcp(addr, 0x7002).expect("둘째 질의");
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
    }

    #[test]
    /// Authoritative servers may close idle connections within seconds; if a closed kept connection
    /// failed the query or waited for the timeout, reuse would do harm.
    fn tcp_exchange_retries_on_a_new_connection_when_the_kept_one_was_closed() {
        let (addr, accepted) = spawn_tcp_answerer(true);
        ask_over_tcp(addr, 0x7003).expect("첫 질의");
        std::thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        ask_over_tcp(addr, 0x7004).expect("둘째 질의");
        assert!(started.elapsed() < Duration::from_millis(300));
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn tcp_slow_drip_cannot_extend_query_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).unwrap();
            let mut wire = vec![0; u16::from_be_bytes(len) as usize];
            stream.read_exact(&mut wire).unwrap();
            let request = Message::parse(&wire).unwrap();
            let mut response = Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.questions = request.questions.clone();
            let wire = response.try_encode().unwrap();
            stream
                .write_all(&(wire.len() as u16).to_be_bytes())
                .unwrap();
            for byte in wire {
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(30));
            }
        });

        let request = Message::query(
            0x5151,
            Name::from_str("slow.example").unwrap(),
            RecordType::A,
        );
        let wire = request.try_encode().unwrap();
        let started = Instant::now();
        let result = tcp_exchange(
            addr,
            &wire,
            request.header.id,
            &request,
            Duration::from_millis(120),
        );
        assert!(matches!(result, Err(ForwardError::Timeout)));
        assert!(started.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
    }

    #[test]
    fn invalid_udp_flood_cannot_extend_query_deadline() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (len, client) = socket.recv_from(&mut buf).unwrap();
            let request = Message::parse(&buf[..len]).unwrap();
            let mut response = Message::default();
            response.header.id = request.header.id.wrapping_add(1);
            response.header.response = true;
            response.questions = request.questions.clone();
            let wire = response.try_encode().unwrap();
            let until = Instant::now() + Duration::from_millis(500);
            while Instant::now() < until {
                let _ = socket.send_to(&wire, client);
                std::thread::sleep(Duration::from_millis(5));
            }
        });

        let request = Message::query(
            0x6161,
            Name::from_str("flood.example").unwrap(),
            RecordType::A,
        );
        let started = Instant::now();
        let result = query_server(addr, &request, Duration::from_millis(120));
        assert!(matches!(result, Err(ForwardError::Timeout)));
        assert!(started.elapsed() < Duration::from_millis(350));
        server.join().unwrap();
    }

    #[test]
    fn failover_strategies_share_one_overall_deadline() {
        fn blackholes(count: usize) -> Vec<SocketAddr> {
            (0..count)
                .map(|_| {
                    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
                    let address = socket.local_addr().unwrap();
                    std::thread::spawn(move || {
                        let mut buf = [0u8; 512];
                        while socket.recv_from(&mut buf).is_ok() {}
                    });
                    address
                })
                .collect()
        }

        for strategy in [
            Strategy::Sequential,
            Strategy::RoundRobin,
            Strategy::QueryStatistics,
            Strategy::Parallel,
        ] {
            let mut forwarder =
                Forwarder::new(blackholes(3), Duration::from_millis(150)).with_strategy(strategy);
            if strategy == Strategy::Parallel {
                forwarder = forwarder.with_parallel_limit(1);
            }
            let started = Instant::now();
            let result = forwarder.resolve(&query("overall-deadline.example"));
            assert!(matches!(result, Err(ForwardError::Timeout)));
            assert!(
                started.elapsed() < Duration::from_millis(350),
                "{strategy:?} exceeded overall deadline: {:?}",
                started.elapsed()
            );
        }
    }

    #[test]
    fn query_source_bind_selection() {
        let v4srv: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let v6srv: SocketAddr = "[2001:4860:4860::8888]:53".parse().unwrap();

        assert_eq!(pick_bind(v4srv, None, None).ip(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(pick_bind(v6srv, None, None).ip(), Ipv6Addr::UNSPECIFIED);

        let s4 = Ipv4Addr::new(10, 1, 2, 3);
        assert_eq!(pick_bind(v4srv, Some(s4), None).ip(), s4);

        assert_eq!(pick_bind(v6srv, Some(s4), None).ip(), Ipv6Addr::UNSPECIFIED);

        assert_eq!(pick_bind(v4srv, Some(s4), None).port(), 0);
    }

    fn answer_for(req: &Message, ip: Ipv4Addr) -> Message {
        let mut m = Message::default();
        m.header.id = req.header.id;
        m.header.response = true;
        m.header.recursion_available = true;
        m.questions = req.questions.clone();
        if let Some(q) = req.questions.first() {
            m.answers
                .push(Record::new(q.name.clone(), 60, RData::A(ip)));
        }
        m
    }

    fn mock_udp(ip: Ipv4Addr) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                if let Ok(req) = Message::parse(&buf[..n]) {
                    let _ = sock.send_to(&answer_for(&req, ip).try_encode().unwrap(), from);
                }
            }
        });
        addr
    }

    fn mock_udp_empty(rcode: u16, delay: Duration) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                if let Ok(req) = Message::parse(&buf[..n]) {
                    if !delay.is_zero() {
                        std::thread::sleep(delay);
                    }
                    let mut response = Message::default();
                    response.header.id = req.header.id;
                    response.header.response = true;
                    response.header.recursion_available = true;
                    response.header.rcode = rcode;
                    response.questions = req.questions.clone();
                    let _ = sock.send_to(&response.try_encode().unwrap(), from);
                }
            }
        });
        addr
    }

    fn mock_udp_cname_only() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                if let Ok(req) = Message::parse(&buf[..n]) {
                    let mut response = Message::default();
                    response.header.id = req.header.id;
                    response.header.response = true;
                    response.header.recursion_available = true;
                    response.questions = req.questions.clone();
                    if let Some(question) = req.questions.first() {
                        response.answers.push(Record::new(
                            question.name.clone(),
                            60,
                            RData::Cname(Name::from_str("target.example").unwrap()),
                        ));
                    }
                    let _ = sock.send_to(&response.try_encode().unwrap(), from);
                }
            }
        });
        addr
    }

    fn query(name: &str) -> Message {
        Message::query(0xBEEF, Name::from_str(name).unwrap(), RecordType::A)
    }

    #[test]
    fn stats_recorded_for_all_strategies() {
        let good = mock_udp(Ipv4Addr::new(9, 9, 9, 9));
        for strategy in [
            Strategy::Sequential,
            Strategy::RoundRobin,
            Strategy::Parallel,
            Strategy::QueryStatistics,
        ] {
            let fwd = Forwarder::new(vec![good], Duration::from_secs(3)).with_strategy(strategy);
            let stats = fwd.stats_handle();
            fwd.resolve(&query("stat.test")).unwrap();
            fwd.resolve(&query("stat2.test")).unwrap();
            let snap = stats.snapshot();
            assert_eq!(snap.len(), 1);
            assert_eq!(snap[0].queries, 2, "{strategy:?} 질의 수 기록");
            assert_eq!(snap[0].ok, 2, "{strategy:?} 성공 기록");
            assert_eq!(snap[0].fail, 0);
            assert!(snap[0].ewma_ms >= 0.0);
            assert_eq!(snap[0].label, good.to_string());
        }
    }

    #[test]
    fn stats_seed_carries_over_by_label_without_clobbering_live() {
        let good: SocketAddr = "127.0.0.1:53001".parse().unwrap();
        let old = Forwarder::new(vec![good], Duration::from_secs(3));
        old.record_upstream_result(0, Duration::from_millis(10), true);
        let prev = old.stats_handle().snapshot();
        assert_eq!(prev[0].queries, 1);

        let fresh = Forwarder::new(vec![good], Duration::from_secs(3));
        fresh.stats_handle().seed(&prev);
        let snap = fresh.stats_handle().snapshot();
        assert_eq!(snap[0].queries, 1, "이전 통계 승계");
        assert_eq!(snap[0].ok, 1);

        let other: SocketAddr = "127.0.0.1:53002".parse().unwrap();
        let unrelated = Forwarder::new(vec![other], Duration::from_secs(3));
        unrelated.stats_handle().seed(&prev);
        assert_eq!(unrelated.stats_handle().snapshot()[0].queries, 0);

        let live = Forwarder::new(vec![good], Duration::from_secs(3));
        live.record_upstream_result(0, Duration::from_millis(20), true);
        live.record_upstream_result(0, Duration::from_millis(30), true);
        live.stats_handle().seed(&prev);
        assert_eq!(live.stats_handle().snapshot()[0].queries, 2, "라이브 우선");
    }

    #[test]
    fn added_counts_sum_and_the_latency_average_stays_with_own_samples() {
        let good: SocketAddr = "127.0.0.1:53001".parse().unwrap();
        let elsewhere = Forwarder::new(vec![good], Duration::from_secs(3));
        elsewhere.record_upstream_result(0, Duration::from_millis(100), true);
        elsewhere.record_upstream_result(0, Duration::from_millis(100), false);
        let observed = elsewhere.stats_handle().snapshot();

        let idle = Forwarder::new(vec![good], Duration::from_secs(3));
        idle.stats_handle().add(&observed);
        let snap = idle.stats_handle().snapshot();
        assert_eq!((snap[0].queries, snap[0].ok, snap[0].fail), (2, 1, 1));
        assert_eq!(snap[0].ewma_ms, observed[0].ewma_ms);

        let live = Forwarder::new(vec![good], Duration::from_secs(3));
        live.record_upstream_result(0, Duration::from_millis(10), true);
        let own = live.stats_handle().snapshot()[0].ewma_ms;
        live.stats_handle().add(&observed);
        let snap = live.stats_handle().snapshot();
        assert_eq!((snap[0].queries, snap[0].ok, snap[0].fail), (3, 2, 1));
        assert_eq!(snap[0].ewma_ms, own);
    }

    #[test]
    fn stats_record_failures_on_unreachable_upstream() {
        let blackhole = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = blackhole.local_addr().unwrap();
        let fwd = Forwarder::new(vec![addr], Duration::from_millis(80));
        let stats = fwd.stats_handle();
        assert!(fwd.resolve(&query("dead.test")).is_err());
        let snap = stats.snapshot();
        assert_eq!(snap[0].queries, 1);
        assert_eq!(snap[0].fail, 1);
        assert_eq!(snap[0].ok, 0);
    }

    #[test]
    fn forwards_udp() {
        let up = mock_udp(Ipv4Addr::new(5, 6, 7, 8));
        let fwd = Forwarder::new(vec![up], Duration::from_secs(2));
        let resp = fwd.resolve(&query("a.example.com")).unwrap();
        assert_eq!(resp.header.id, 0xBEEF);
        assert!(resp.header.response);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].rdata {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(5, 6, 7, 8)),
            other => panic!("A 레코드를 예상했지만 실제 값은 {other:?}입니다"),
        }
    }

    #[test]
    fn concurrent_identical_authority_queries_share_one_exchange() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = socket.local_addr().unwrap();
        let exchanges = Arc::new(AtomicUsize::new(0));
        let server_exchanges = exchanges.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = socket.recv_from(&mut buf) {
                let Ok(request) = Message::parse(&buf[..n]) else {
                    continue;
                };
                server_exchanges.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(150));
                let response = answer_for(&request, Ipv4Addr::new(198, 51, 100, 53));
                let _ = socket.send_to(&response.try_encode().unwrap(), from);
            }
        });

        let start = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for id in [0x2001, 0x2002] {
            let start = start.clone();
            handles.push(std::thread::spawn(move || {
                let request = Message::query(id, Name::from_str("com").unwrap(), RecordType::NS);
                start.wait();
                query_server(server, &request, Duration::from_secs(2)).unwrap()
            }));
        }

        start.wait();
        let responses: Vec<Message> = handles
            .into_iter()
            .map(|handle| handle.join().expect("authority worker"))
            .collect();

        assert_eq!(exchanges.load(Ordering::SeqCst), 1);
        assert_eq!(responses[0].header.id, 0x2001);
        assert_eq!(responses[1].header.id, 0x2002);
    }

    #[test]
    fn waiting_follower_is_still_woken_when_leader_completes() {
        let flight = Arc::new(AuthorityFlight::new());
        let follower_flight = flight.clone();

        flight.waiters.fetch_add(1, Ordering::SeqCst);

        let follower = std::thread::spawn(move || {
            follower_flight
                .wait(Duration::from_secs(5))
                .expect("리더 완료로 깨어나야")
                .header
                .id
        });

        std::thread::sleep(Duration::from_millis(150));
        let mut answer = Message::default();
        answer.header.id = 0x4242;
        flight.complete(Ok(answer));

        assert_eq!(follower.join().expect("팔로워 스레드"), 0x4242);
    }

    #[test]
    fn completion_without_waiters_is_still_observed_by_late_callers() {
        let flight = AuthorityFlight::new();
        let mut answer = Message::default();
        answer.header.id = 0x5151;
        flight.complete(Ok(answer));

        assert_eq!(flight.waiters.load(Ordering::SeqCst), 0);
        let seen = flight.wait(Duration::from_millis(50)).expect("즉시 관측");
        assert_eq!(seen.header.id, 0x5151);
    }

    #[test]
    /// Lowercasing would remove the spoofing defense.
    fn case_sensitive_authority_queries_do_not_collapse_or_rewrite_questions() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = socket.local_addr().unwrap();
        let exchanges = Arc::new(AtomicUsize::new(0));
        let server_exchanges = exchanges.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = socket.recv_from(&mut buf) {
                let Ok(request) = Message::parse(&buf[..n]) else {
                    continue;
                };
                server_exchanges.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(50));
                let response = answer_for(&request, Ipv4Addr::new(198, 51, 100, 54));
                let _ = socket.send_to(&response.try_encode().unwrap(), from);
            }
        });

        let start = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for (id, name) in [(0x3001, "MiXeD.Example"), (0x3002, "mIxEd.Example")] {
            let start = start.clone();
            handles.push(std::thread::spawn(move || {
                let request = query(name);
                let mut request = request;
                request.header.id = id;
                start.wait();
                (
                    request.clone(),
                    query_server_case_sensitive(server, &request, Duration::from_secs(2)).unwrap(),
                )
            }));
        }

        start.wait();
        let pairs = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(exchanges.load(Ordering::SeqCst), 2);
        for (request, response) in pairs {
            assert_eq!(
                request.questions[0].name.labels(),
                response.questions[0].name.labels()
            );
        }
    }

    #[test]
    fn case_sensitive_authority_query_rejects_case_mismatch() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = socket.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            if let Ok((n, from)) = socket.recv_from(&mut buf) {
                let request = Message::parse(&buf[..n]).unwrap();
                let mut response = answer_for(&request, Ipv4Addr::new(198, 51, 100, 55));
                response.questions[0].name =
                    Name::from_str(&response.questions[0].name.to_ascii_lower()).unwrap();
                let _ = socket.send_to(&response.try_encode().unwrap(), from);
                std::thread::sleep(Duration::from_millis(50));
            }
        });

        let request = query("MiXeD.Example");
        assert!(matches!(
            query_server_case_sensitive(server, &request, Duration::from_secs(1)),
            Err(ForwardError::BadResponse)
        ));
    }

    #[test]
    fn case_sensitive_authority_query_ignores_mismatch_before_valid_response() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = socket.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let (n, from) = socket.recv_from(&mut buf).unwrap();
            let request = Message::parse(&buf[..n]).unwrap();
            let mut mismatch = answer_for(&request, Ipv4Addr::new(198, 51, 100, 56));
            mismatch.questions[0].name =
                Name::from_str(&mismatch.questions[0].name.to_ascii_lower()).unwrap();
            socket
                .send_to(&mismatch.try_encode().unwrap(), from)
                .unwrap();
            std::thread::sleep(Duration::from_millis(10));
            socket
                .send_to(
                    &answer_for(&request, Ipv4Addr::new(198, 51, 100, 57))
                        .try_encode()
                        .unwrap(),
                    from,
                )
                .unwrap();
            std::thread::sleep(Duration::from_millis(50));
        });

        let request = query("MiXeD.Example");
        let response =
            query_server_case_sensitive(server, &request, Duration::from_secs(1)).unwrap();
        assert_eq!(
            response.questions[0].name.labels(),
            request.questions[0].name.labels()
        );
        assert!(matches!(
            &response.answers[0].rdata,
            RData::A(ip) if *ip == Ipv4Addr::new(198, 51, 100, 57)
        ));
        worker.join().unwrap();
    }

    #[test]
    fn case_merged_authority_queries_collapse_across_case_and_keep_caller_case() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = socket.local_addr().unwrap();
        let exchanges = Arc::new(AtomicUsize::new(0));
        let server_exchanges = exchanges.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = socket.recv_from(&mut buf) {
                let Ok(request) = Message::parse(&buf[..n]) else {
                    continue;
                };
                server_exchanges.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(150));
                let response = answer_for(&request, Ipv4Addr::new(198, 51, 100, 58));
                let _ = socket.send_to(&response.try_encode().unwrap(), from);
            }
        });

        let start = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for (id, name) in [(0x4001u16, "MiXeD.Example"), (0x4002, "mIxEd.Example")] {
            let start = start.clone();
            handles.push(std::thread::spawn(move || {
                let mut request = query(name);
                request.header.id = id;
                start.wait();
                (
                    request.clone(),
                    query_server_case_merged(server, &request, Duration::from_secs(2)).unwrap(),
                )
            }));
        }
        start.wait();
        let pairs: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert_eq!(exchanges.load(Ordering::SeqCst), 1);
        for (request, response) in pairs {
            assert_eq!(request.header.id, response.header.id);
            assert_eq!(
                request.questions[0].name.labels(),
                response.questions[0].name.labels()
            );
        }
    }

    #[test]
    fn case_merged_authority_query_ignores_forged_lowercase_echo() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = socket.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let (n, from) = socket.recv_from(&mut buf).unwrap();
            let request = Message::parse(&buf[..n]).unwrap();
            let mut forged = answer_for(&request, Ipv4Addr::new(198, 51, 100, 59));
            forged.questions[0].name =
                Name::from_str(&forged.questions[0].name.to_ascii_lower()).unwrap();
            socket.send_to(&forged.try_encode().unwrap(), from).unwrap();
            std::thread::sleep(Duration::from_millis(10));
            socket
                .send_to(
                    &answer_for(&request, Ipv4Addr::new(198, 51, 100, 60))
                        .try_encode()
                        .unwrap(),
                    from,
                )
                .unwrap();
            std::thread::sleep(Duration::from_millis(50));
        });

        let request = query("MiXeD.Example");
        let response = query_server_case_merged(server, &request, Duration::from_secs(1)).unwrap();

        assert!(matches!(
            &response.answers[0].rdata,
            RData::A(ip) if *ip == Ipv4Addr::new(198, 51, 100, 60)
        ));
        worker.join().unwrap();
    }

    #[test]
    fn udp_query_ignores_valid_looking_response_from_wrong_source() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = socket.local_addr().unwrap();
        let attacker = UdpSocket::bind("127.0.0.1:0").unwrap();
        let worker = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let (n, client) = socket.recv_from(&mut buf).unwrap();
            let request = Message::parse(&buf[..n]).unwrap();
            attacker
                .send_to(
                    &answer_for(&request, Ipv4Addr::new(203, 0, 113, 66))
                        .try_encode()
                        .unwrap(),
                    client,
                )
                .unwrap();
            std::thread::sleep(Duration::from_millis(10));
            socket
                .send_to(
                    &answer_for(&request, Ipv4Addr::new(203, 0, 113, 67))
                        .try_encode()
                        .unwrap(),
                    client,
                )
                .unwrap();
            std::thread::sleep(Duration::from_millis(50));
        });

        let response =
            query_server(server, &query("source.example"), Duration::from_secs(1)).unwrap();
        assert!(matches!(
            &response.answers[0].rdata,
            RData::A(ip) if *ip == Ipv4Addr::new(203, 0, 113, 67)
        ));
        worker.join().unwrap();
    }

    #[test]
    /// The last of four SAD DNS defenses. No answer means the port may have been observed;
    /// returning the socket to the pool would send the next query from the same port and extend the
    /// observation window. Socket reuse looks like a harmless saving of a bind call, so this pins
    /// it.
    fn unanswered_exchange_never_parks_its_socket_for_reuse() {
        let responder = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = responder.local_addr().unwrap();
        let bind = outgoing_bind(server);
        let idle_now =
            || UDP_SOCKET_POOL.with(|pool| pool.borrow().get(&bind).map_or(0, |e| e.idle.len()));

        let dead = {
            let closed = UdpSocket::bind("127.0.0.1:0").unwrap();
            let addr = closed.local_addr().unwrap();
            drop(closed);
            addr
        };
        let request = query("unanswered.example");
        let wire = request.try_encode().unwrap();

        let before = idle_now();
        for _ in 0..UDP_SOCKET_POOL_SIZE * 2 {
            let result = udp_exchange(
                dead,
                &wire,
                request.header.id,
                &request,
                Duration::from_millis(50),
                false,
            );
            assert!(result.is_err(), "죽은 업스트림에서 답이 오면 안 된다");
        }
        assert_eq!(
            idle_now(),
            before,
            "답을 못 받은 소켓이 풀에 들어갔습니다. 다음 질의가 관측된 포트로 나갑니다"
        );

        let worker = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let (n, client) = responder.recv_from(&mut buf).unwrap();
            let parsed = Message::parse(&buf[..n]).unwrap();
            responder
                .send_to(
                    &answer_for(&parsed, Ipv4Addr::new(203, 0, 113, 9))
                        .try_encode()
                        .unwrap(),
                    client,
                )
                .unwrap();
            std::thread::sleep(Duration::from_millis(50));
        });
        udp_exchange(
            server,
            &wire,
            request.header.id,
            &request,
            Duration::from_secs(1),
            false,
        )
        .expect("살아 있는 업스트림에는 답이 온다");
        worker.join().unwrap();
        assert!(
            idle_now() > before,
            "성공한 교환마저 풀에 안 들어가면 위 단언이 아무것도 지키지 않는다"
        );
    }

    /// Fake upstream answering over UDP and TCP on one port. A port free for TCP may still fail for
    /// UDP: on Windows, ranges reserved by Hyper-V give permission denied, and those ranges differ
    /// per protocol. Ephemeral ports come out in order, so the mismatched TCP sockets are held
    /// while walking past the range. `udp_reply` builds the UDP answer; TCP always gives a full
    /// answer with 9.9.9.9.
    fn spawn_udp_tcp_upstream(udp_reply: fn(&Message) -> Vec<u8>) -> SocketAddr {
        /// Enough to walk past a contiguous reserved range.
        const ATTEMPTS: usize = 512;

        let mut pair = None;
        let mut last_error = None;
        let mut taken = Vec::new();
        for _ in 0..ATTEMPTS {
            let tcp = TcpListener::bind("127.0.0.1:0").expect("TCP 바인딩");
            let addr = tcp.local_addr().expect("TCP 주소");
            match UdpSocket::bind(addr) {
                Ok(udp) => {
                    pair = Some((tcp, udp, addr));
                    break;
                }
                Err(error) => {
                    last_error = Some(error);
                    taken.push(tcp);
                }
            }
        }
        let (tcp, udp, addr) = pair.unwrap_or_else(|| {
            panic!("같은 포트 UDP/TCP 바인딩 {ATTEMPTS}회 실패: {last_error:?}")
        });
        drop(taken);

        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = udp.recv_from(&mut buf) {
                if let Ok(req) = Message::parse(&buf[..n]) {
                    let _ = udp.send_to(&udp_reply(&req), from);
                }
            }
        });
        std::thread::spawn(move || {
            for stream in tcp.incoming() {
                let mut s = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let mut lenb = [0u8; 2];
                if s.read_exact(&mut lenb).is_err() {
                    continue;
                }
                let len = u16::from_be_bytes(lenb) as usize;
                let mut mbuf = vec![0u8; len];
                if s.read_exact(&mut mbuf).is_err() {
                    continue;
                }
                let req = Message::parse(&mbuf).unwrap();
                let out = answer_for(&req, Ipv4Addr::new(9, 9, 9, 9))
                    .try_encode()
                    .unwrap();
                let _ = s.write_all(&(out.len() as u16).to_be_bytes());
                let _ = s.write_all(&out);
            }
        });
        addr
    }

    /// Checks the full TCP answer comes back and returns the time taken.
    fn resolve_through_tcp_fallback(addr: SocketAddr) -> Duration {
        let fwd = Forwarder::new(vec![addr], Duration::from_secs(20));
        let started = Instant::now();
        let resp = fwd.resolve(&query("trunc.example.com")).unwrap();
        let elapsed = started.elapsed();
        assert_eq!(resp.answers.len(), 1, "TCP 폴백으로 전체 응답");
        match &resp.answers[0].rdata {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(9, 9, 9, 9)),
            _ => panic!("A 기대"),
        }
        elapsed
    }

    #[test]
    fn tcp_fallback_on_truncation() {
        let addr = spawn_udp_tcp_upstream(|req| {
            let mut tc = Message::default();
            tc.header.id = req.header.id;
            tc.header.response = true;
            tc.header.truncated = true;
            tc.questions = req.questions.clone();
            tc.try_encode().unwrap()
        });
        resolve_through_tcp_fallback(addr);
    }

    #[test]
    /// A proxy intercepting UDP 53 cuts answers this way at 512 bytes; dropping and waiting would
    /// spend the whole query timeout and fail.
    fn tcp_fallback_on_reply_cut_without_tc() {
        let addr = spawn_udp_tcp_upstream(|req| {
            let full = answer_for(req, Ipv4Addr::new(9, 9, 9, 9))
                .try_encode()
                .unwrap();
            full[..full.len() - 3].to_vec()
        });
        let elapsed = resolve_through_tcp_fallback(addr);
        assert!(
            elapsed < Duration::from_secs(5),
            "잘린 응답을 버리고 제한 시간까지 기다렸다: {elapsed:?}"
        );
    }

    #[test]
    fn fails_over_to_second_upstream() {
        let blackhole = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead = blackhole.local_addr().unwrap();

        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while blackhole.recv_from(&mut buf).is_ok() {}
        });
        let alive = mock_udp(Ipv4Addr::new(1, 1, 1, 1));

        let fwd = Forwarder::new(vec![dead, alive], Duration::from_millis(300));
        let resp = fwd.resolve(&query("failover.example.com")).unwrap();
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].rdata {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(1, 1, 1, 1)),
            _ => panic!("A 기대"),
        }
    }

    #[test]
    fn fails_over_on_servfail_rcode() {
        let failing = mock_udp_empty(ResponseCode::ServFail.0, Duration::ZERO);
        let healthy = mock_udp(Ipv4Addr::new(4, 3, 2, 1));
        let fwd = Forwarder::new(vec![failing, healthy], Duration::from_secs(2));

        let response = fwd.resolve(&query("rcode-failover.example.com")).unwrap();
        assert_eq!(response.header.rcode, ResponseCode::NoError.0);
        match response.answers.first().map(|r| &r.rdata) {
            Some(RData::A(ip)) => assert_eq!(*ip, Ipv4Addr::new(4, 3, 2, 1)),
            other => panic!("두 번째 업스트림의 A 레코드를 예상했지만 실제 값은 {other:?}입니다"),
        }
    }

    #[test]
    fn query_statistics_penalizes_parseable_servfail() {
        let failing = mock_udp_empty(ResponseCode::ServFail.0, Duration::ZERO);
        let healthy = mock_udp(Ipv4Addr::new(203, 0, 113, 8));
        let forwarder = Forwarder::new(vec![failing, healthy], Duration::from_secs(2))
            .with_strategy(Strategy::QueryStatistics);

        let response = forwarder
            .resolve(&query("statistics-failover.example.com"))
            .unwrap();
        assert_eq!(response.header.rcode, ResponseCode::NoError.0);
        let failing_stat = *forwarder.stats[0]
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let healthy_stat = *forwarder.stats[1]
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(
            failing_stat.failures, 1,
            "SERVFAIL은 성공으로 집계하면 안 됨"
        );
        assert_eq!(healthy_stat.failures, 0);
        assert!(healthy_stat.samples >= 1);
    }

    #[test]
    fn fails_over_on_empty_noerror() {
        let lame = mock_udp_empty(ResponseCode::NoError.0, Duration::ZERO);
        let healthy = mock_udp(Ipv4Addr::new(6, 5, 4, 3));
        let fwd = Forwarder::new(vec![lame, healthy], Duration::from_secs(2));

        let response = fwd.resolve(&query("lame-failover.example.com")).unwrap();
        assert_eq!(response.header.rcode, ResponseCode::NoError.0);
        match response.answers.first().map(|r| &r.rdata) {
            Some(RData::A(ip)) => assert_eq!(*ip, Ipv4Addr::new(6, 5, 4, 3)),
            other => panic!("두 번째 업스트림의 A 레코드를 예상했지만 실제 값은 {other:?}입니다"),
        }
    }

    #[test]
    fn fails_over_on_cname_only() {
        let partial = mock_udp_cname_only();
        let healthy = mock_udp(Ipv4Addr::new(9, 8, 7, 6));
        let fwd = Forwarder::new(vec![partial, healthy], Duration::from_secs(2));

        let response = fwd.resolve(&query("alias.example.com")).unwrap();
        assert!(response
            .answers
            .iter()
            .any(|record| record.rdata == RData::A(Ipv4Addr::new(9, 8, 7, 6))));
    }

    #[test]
    fn all_upstreams_servfail_returns_servfail() {
        let a = mock_udp_empty(ResponseCode::ServFail.0, Duration::ZERO);
        let b = mock_udp_empty(ResponseCode::ServFail.0, Duration::ZERO);
        let fwd = Forwarder::new(vec![a, b], Duration::from_secs(2));

        let response = fwd.resolve(&query("allfail.example.com")).unwrap();
        assert_eq!(response.header.rcode, ResponseCode::ServFail.0);
    }

    #[test]
    fn unproven_nxdomain_fails_over() {
        let nx = mock_udp_empty(ResponseCode::NXDomain.0, Duration::ZERO);
        let healthy = mock_udp(Ipv4Addr::new(1, 2, 3, 4));
        let fwd = Forwarder::new(vec![nx, healthy], Duration::from_secs(2));

        let response = fwd.resolve(&query("nope.example.com")).unwrap();
        assert_eq!(response.header.rcode, ResponseCode::NoError.0);
        assert!(response
            .answers
            .iter()
            .any(|record| record.rdata == RData::A(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn final_response_requires_relevant_class_and_negative_soa() {
        let request = query("host.example");
        let question = request.questions[0].clone();
        let mut response = Message::default();
        response.header.response = true;
        response.questions = request.questions.clone();

        let mut wrong_class = Record::new(
            question.name.clone(),
            60,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        );
        wrong_class.class = onetdns_proto::DnsClass(3);
        response.answers.push(wrong_class);
        assert_eq!(response_class(&request, &response), RespClass::Incomplete);

        response.answers.clear();
        response.header.rcode = ResponseCode::NXDomain.0;
        assert_eq!(response_class(&request, &response), RespClass::Incomplete);

        response.authorities.push(Record::new(
            Name::from_str("attacker.invalid").unwrap(),
            60,
            RData::soa(onetdns_proto::Soa {
                mname: Name::from_str("ns.attacker.invalid").unwrap(),
                rname: Name::from_str("hostmaster.attacker.invalid").unwrap(),
                serial: 1,
                refresh: 60,
                retry: 60,
                expire: 3600,
                minimum: 60,
            }),
        ));
        assert_eq!(response_class(&request, &response), RespClass::Incomplete);

        response.authorities.clear();
        response.authorities.push(Record::new(
            Name::from_str("example").unwrap(),
            60,
            RData::soa(onetdns_proto::Soa {
                mname: Name::from_str("ns.example").unwrap(),
                rname: Name::from_str("hostmaster.example").unwrap(),
                serial: 1,
                refresh: 60,
                retry: 60,
                expire: 3600,
                minimum: 60,
            }),
        ));
        assert_eq!(response_class(&request, &response), RespClass::Final);

        response.answers.push(Record::new(
            question.name,
            60,
            RData::A(Ipv4Addr::new(192, 0, 2, 2)),
        ));
        assert_eq!(response_class(&request, &response), RespClass::Incomplete);
    }

    #[test]
    fn yxdomain_is_final_not_retryable() {
        let request = Message::query(1, Name::from_str("host.example").unwrap(), RecordType::A);
        let mut response = request.clone();
        response.header.response = true;
        response.header.rcode = ResponseCode::YXDomain.0;
        assert_eq!(response_class(&request, &response), RespClass::Final);
    }

    #[test]
    fn final_response_rejects_unrelated_any_and_conflicting_cname_data() {
        let mut any_request =
            Message::query(1, Name::from_str("host.example").unwrap(), RecordType::ANY);
        let mut response = any_request.clone();
        response.header.response = true;
        response.answers.push(Record::new(
            Name::from_str("attacker.invalid").unwrap(),
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ));
        assert_eq!(
            response_class(&any_request, &response),
            RespClass::Incomplete
        );

        response.answers.clear();
        response.answers.push(Record::new(
            any_request.questions[0].name.clone(),
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 2)),
        ));
        assert_eq!(response_class(&any_request, &response), RespClass::Final);

        any_request.questions[0].qtype = RecordType::A;
        response.questions = any_request.questions.clone();
        response.answers.push(Record::new(
            any_request.questions[0].name.clone(),
            300,
            RData::Cname(Name::from_str("target.example").unwrap()),
        ));
        assert_eq!(
            response_class(&any_request, &response),
            RespClass::Incomplete
        );
    }

    #[test]
    fn no_upstream_errors() {
        let fwd = Forwarder::new(vec![], Duration::from_secs(1));
        assert!(matches!(
            fwd.resolve(&query("x.com")),
            Err(ForwardError::NoUpstream)
        ));
    }

    fn mock_udp_slow(ip: Ipv4Addr, delay: Duration) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                if let Ok(req) = Message::parse(&buf[..n]) {
                    std::thread::sleep(delay);
                    let _ = sock.send_to(&answer_for(&req, ip).try_encode().unwrap(), from);
                }
            }
        });
        addr
    }

    #[test]
    fn parallel_picks_fastest() {
        let slow = mock_udp_slow(Ipv4Addr::new(2, 2, 2, 2), Duration::from_millis(600));
        let fast = mock_udp(Ipv4Addr::new(1, 1, 1, 1));
        let fwd = Forwarder::new(vec![slow, fast], Duration::from_secs(3))
            .with_strategy(Strategy::Parallel);

        let t0 = std::time::Instant::now();
        let resp = fwd.resolve(&query("race.example.com")).unwrap();
        let elapsed = t0.elapsed();
        match &resp.answers[0].rdata {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(1, 1, 1, 1), "빠른 업스트림 응답"),
            _ => panic!("A 기대"),
        }

        assert!(
            elapsed < Duration::from_millis(400),
            "느린 업스트림 대기 안 함: {elapsed:?}"
        );
    }

    #[test]
    /// Looking only at speed, the error would win.
    fn parallel_prefers_final_over_fast_servfail() {
        let failing = mock_udp_empty(ResponseCode::ServFail.0, Duration::ZERO);
        let healthy = mock_udp_slow(Ipv4Addr::new(3, 3, 3, 3), Duration::from_millis(80));
        let fwd = Forwarder::new(vec![failing, healthy], Duration::from_secs(2))
            .with_strategy(Strategy::Parallel);

        let response = fwd.resolve(&query("parallel-rcode.example.com")).unwrap();
        assert_eq!(response.header.rcode, ResponseCode::NoError.0);
        match response.answers.first().map(|r| &r.rdata) {
            Some(RData::A(ip)) => assert_eq!(*ip, Ipv4Addr::new(3, 3, 3, 3)),
            other => panic!("정상 A 레코드를 예상했지만 실제 값은 {other:?}입니다"),
        }
    }

    #[test]
    fn parallel_limit_is_concurrency_not_upstream_selection() {
        let failing = mock_udp_empty(ResponseCode::ServFail.0, Duration::ZERO);
        let healthy = mock_udp(Ipv4Addr::new(8, 8, 4, 4));
        let forwarder = Forwarder::new(vec![failing, healthy], Duration::from_secs(2))
            .with_strategy(Strategy::Parallel)
            .with_parallel_limit(1);

        let response = forwarder
            .resolve(&query("parallel-limit.example.com"))
            .unwrap();
        assert_eq!(response.header.rcode, ResponseCode::NoError.0);
        match response.answers.first().map(|record| &record.rdata) {
            Some(RData::A(ip)) => assert_eq!(*ip, Ipv4Addr::new(8, 8, 4, 4)),
            other => {
                panic!("두 번째 업스트림의 정상 A 레코드를 예상했지만 실제 값은 {other:?}입니다")
            }
        }
    }

    #[test]
    fn parallel_survives_dead_upstream() {
        let blackhole = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead = blackhole.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while blackhole.recv_from(&mut buf).is_ok() {}
        });
        let alive = mock_udp(Ipv4Addr::new(7, 7, 7, 7));

        let fwd = Forwarder::new(vec![dead, alive], Duration::from_secs(5))
            .with_strategy(Strategy::Parallel);
        let t0 = std::time::Instant::now();
        let resp = fwd.resolve(&query("survive.example.com")).unwrap();
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].rdata {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(7, 7, 7, 7)),
            _ => panic!("A 기대"),
        }

        assert!(
            t0.elapsed() < Duration::from_secs(1),
            "죽은 업스트림 대기 안 함"
        );
    }

    #[test]
    fn e2e_runtime_plus_forwarder() {
        use onetdns_runtime::{Handler, RequestCtx, Server, ServerConfig};

        let up = mock_udp(Ipv4Addr::new(2, 2, 2, 2));

        struct FwdHandler {
            fwd: Forwarder,
        }
        impl Handler for FwdHandler {
            fn handle(&self, request: &Message, _ctx: &RequestCtx) -> Option<Message> {
                self.fwd.resolve(request).ok()
            }
        }

        let handler = Arc::new(FwdHandler {
            fwd: Forwarder::new(vec![up], Duration::from_secs(2)),
        });
        let cfg = ServerConfig {
            pin_cores: false,
            tcp: false,
            poll_interval: Duration::from_millis(100),
            ..Default::default()
        };
        let server = Server::bind(([127, 0, 0, 1], 0).into(), handler, cfg).unwrap();
        let addr = server.udp_addr().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client
            .send_to(&query("e2e.example.com").try_encode().unwrap(), addr)
            .unwrap();
        let mut buf = [0u8; 4096];
        let (n, _) = client.recv_from(&mut buf).unwrap();
        let resp = Message::parse(&buf[..n]).unwrap();

        assert_eq!(resp.header.id, 0xBEEF);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].rdata {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(2, 2, 2, 2)),
            _ => panic!("A 기대"),
        }
        server.shutdown();
    }
}
