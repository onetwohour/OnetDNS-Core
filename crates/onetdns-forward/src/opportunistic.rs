//! Opportunistic encryption to authoritative servers (RFC 9539). A server is asked over DoT or DoQ
//! only after a probe got an answer that way; until then, and whenever encryption fails, it is asked
//! in plaintext. The certificate is not checked, so this hides queries from passive observers but
//! not from an attacker on the path.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use onetdns_core::LruMap;
use onetdns_proto::Message;
use onetdns_tls::{client_handshake, ClientConfig, InsecureVerifier, TlsSession};

use crate::doq::{self, DoqConn};
use crate::dot::{self, DotConn};
use crate::{AuthorityTransport, ForwardError, IdlePool};

/// How long an answer over encryption keeps a server on the encrypted path (RFC 9539 default).
const PERSISTENCE: Duration = Duration::from_secs(3 * 24 * 60 * 60);

/// How long a failure keeps a server off it (RFC 9539 default).
const DAMPING: Duration = Duration::from_secs(24 * 60 * 60);

/// The RFC 9539 default. A query's own exchange usually has less; a timeout there only drops a
/// success, so a probe with this timeout decides.
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);

/// Same bound as the recursor's per-server records.
const MAX_SERVERS: usize = 50_000;

/// Each probe is a thread holding a socket for up to `PROBE_TIMEOUT` per encryption it tries.
const MAX_PROBES: usize = 16;

/// Each new connection uses one; a server sends one or two per handshake.
const TICKETS_PER_SERVER: usize = 2;

/// Only servers that answer over DoQ have tickets, far fewer than `MAX_SERVERS`.
const MAX_TICKET_SERVERS: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Encryption {
    Dot,
    Doq,
}

impl Encryption {
    /// Tried in this order. DoQ comes first because a resumed DoQ connection carries the query in
    /// its first flight, so asking a server that closed the idle connection costs no extra round
    /// trip.
    const ALL: [Encryption; 2] = [Encryption::Doq, Encryption::Dot];

    /// TCP, TLS 1.3, and the query for DoT; the QUIC handshake and the query for DoQ without a
    /// ticket.
    pub fn round_trips_on_new_connection(self) -> u32 {
        match self {
            Encryption::Dot => 3,
            Encryption::Doq => 2,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Encryption::Dot => "dot",
            Encryption::Doq => "doq",
        }
    }

    fn alpn(self) -> &'static [u8] {
        match self {
            Encryption::Dot => b"dot",
            Encryption::Doq => b"doq",
        }
    }
}

/// Where to ask a server over encryption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptedRoute {
    pub endpoint: SocketAddr,
    pub encryption: Encryption,
}

impl EncryptedRoute {
    pub fn transport(self) -> AuthorityTransport {
        AuthorityTransport::Encrypted(self.encryption)
    }
}

/// What the process remembers about servers is shared by every holder, so it survives a rebuild on
/// reload; the ports only say where the encrypted endpoints are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpportunisticEncryption {
    dot_port: u16,
    doq_port: u16,
}

impl Default for OpportunisticEncryption {
    fn default() -> Self {
        Self::with_ports(853, 853)
    }
}

impl OpportunisticEncryption {
    /// Ports other than 853 only for tests.
    pub fn with_ports(dot_port: u16, doq_port: u16) -> Self {
        Self { dot_port, doq_port }
    }

    fn keys(self, server: IpAddr) -> [Key; 2] {
        Encryption::ALL.map(|encryption| {
            let port = match encryption {
                Encryption::Dot => self.dot_port,
                Encryption::Doq => self.doq_port,
            };
            (SocketAddr::new(server, port), encryption)
        })
    }

    /// Some while the server's last answer over DoT or DoQ is recent.
    pub fn route(self, server: IpAddr) -> Option<EncryptedRoute> {
        memory()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .route(self.keys(server), Instant::now())
            .map(|(endpoint, encryption)| EncryptedRoute {
                endpoint,
                encryption,
            })
    }

    /// Asks `server` the same request in the background over each encryption not known to fail,
    /// in order, until one answers, and returns at once. Does nothing while a route is known, a
    /// probe runs, or both failed within `DAMPING`.
    pub fn probe(self, server: IpAddr, request: &Message) {
        let Some(slot) = ProbeSlot::claim(self.keys(server)) else {
            return;
        };
        let request = request.clone();
        let _ = std::thread::Builder::new()
            .name("adot-probe".into())
            .spawn(move || slot.probe(&request));
    }
}

/// Servers whose last answer over encryption is recent, each with the protocol queries to it use.
pub fn encrypted_servers() -> Vec<(IpAddr, Encryption)> {
    let now = Instant::now();
    let mut servers: Vec<_> = memory()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .status
        .iter()
        .filter(|(_, status)| status.state(now) == State::Encrypted)
        .map(|(&(endpoint, encryption), _)| (endpoint.ip(), encryption))
        .collect();
    servers.sort_unstable_by_key(|&(server, encryption)| {
        let order = Encryption::ALL
            .iter()
            .position(|&tried| tried == encryption);
        (server, order)
    });
    servers.dedup_by_key(|(server, _)| *server);
    servers
}

type Key = (SocketAddr, Encryption);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Probing,

    /// When it last answered over encryption.
    Answered(Instant),

    Failed(Instant),
}

/// What a status decides now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Answered within `PERSISTENCE`: queries go this way.
    Encrypted,
    Probing,
    /// Failed within `DAMPING`: not tried again until then.
    Failed,
    Expired,
}

impl Status {
    fn state(self, now: Instant) -> State {
        match self {
            Status::Probing => State::Probing,
            Status::Answered(at) if now.saturating_duration_since(at) < PERSISTENCE => {
                State::Encrypted
            }
            Status::Failed(at) if now.saturating_duration_since(at) < DAMPING => State::Failed,
            Status::Answered(_) | Status::Failed(_) => State::Expired,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Answered,
    Failed,

    /// Timed out sooner than a probe would have; says nothing about the server.
    CutShort,
}

/// Per encrypted endpoint, the RFC 9539 state reduced to what changes a decision.
struct Memory {
    status: LruMap<Key, Status>,
}

impl Memory {
    fn new(capacity: usize) -> Self {
        Self {
            status: LruMap::new(capacity),
        }
    }

    fn route(&mut self, keys: [Key; 2], now: Instant) -> Option<Key> {
        keys.into_iter().find(|key| {
            self.status
                .get(key)
                .is_some_and(|status| status.state(now) == State::Encrypted)
        })
    }

    /// The endpoint to probe now, marked as probing. None while one answers, one is being probed,
    /// or all failed within `DAMPING`.
    fn claim_probe(&mut self, keys: [Key; 2], now: Instant) -> Option<Key> {
        if self.route(keys, now).is_some() {
            return None;
        }
        for key in keys {
            match self.status.get(&key).map(|status| status.state(now)) {
                Some(State::Probing) => return None,
                Some(State::Failed) => {}
                _ => {
                    self.status.put(key, Status::Probing);
                    return Some(key);
                }
            }
        }
        None
    }

    /// A short timeout drops a success but never erases a failure or a running probe.
    fn record(&mut self, key: Key, outcome: Outcome, now: Instant) {
        match outcome {
            Outcome::Answered => self.status.put(key, Status::Answered(now)),
            Outcome::Failed => self.status.put(key, Status::Failed(now)),
            Outcome::CutShort => {
                if matches!(self.status.peek(&key), Some(Status::Answered(_))) {
                    self.status.pop(&key);
                }
            }
        }
    }

    /// For a probe that ended without recording anything.
    fn release(&mut self, key: Key) {
        if self.status.peek(&key) == Some(&Status::Probing) {
            self.status.pop(&key);
        }
    }
}

fn memory() -> &'static Mutex<Memory> {
    static MEMORY: OnceLock<Mutex<Memory>> = OnceLock::new();
    MEMORY.get_or_init(|| Mutex::new(Memory::new(MAX_SERVERS)))
}

/// Holds one of `MAX_PROBES`; dropping it, on any path, frees the slot and the probing mark.
struct ProbeSlot {
    keys: [Key; 2],
    key: Key,
}

static PROBES: Mutex<usize> = Mutex::new(0);

impl ProbeSlot {
    fn claim(keys: [Key; 2]) -> Option<Self> {
        let mut probes = PROBES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *probes >= MAX_PROBES {
            return None;
        }
        let key = memory()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .claim_probe(keys, Instant::now())?;
        *probes += 1;
        Some(Self { keys, key })
    }

    /// Each exchange records its outcome, and a failure moves on to the next encryption; the
    /// slot is held until the last ends. Without moving on, a server offering only DoT would
    /// stay in plaintext until another plaintext answer started a probe.
    fn probe(mut self, request: &Message) {
        for _ in Encryption::ALL {
            let (endpoint, encryption) = self.key;
            let _ = crate::query_server_over(
                endpoint,
                request,
                PROBE_TIMEOUT,
                AuthorityTransport::Encrypted(encryption),
                true,
            );
            let next = memory()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .claim_probe(self.keys, Instant::now());
            match next {
                Some(next) => self.key = next,
                None => return,
            }
        }
    }
}

impl Drop for ProbeSlot {
    fn drop(&mut self) {
        memory()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .release(self.key);
        let mut probes = PROBES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *probes = probes.saturating_sub(1);
    }
}

enum EncryptedConn {
    Dot(Box<DotConn>),
    Doq(Box<DoqConn>),
}

/// Keyed by bind address, endpoint, and protocol.
type PoolKey = (SocketAddr, SocketAddr, Encryption);

fn pool() -> &'static Mutex<IdlePool<PoolKey, EncryptedConn>> {
    static POOL: OnceLock<Mutex<IdlePool<PoolKey, EncryptedConn>>> = OnceLock::new();
    crate::shared_idle_pool(&POOL, EncryptedConn::open)
}

/// Any certificate and no SNI: there is no name to check against. DoQ resumes with the query in
/// early data; DoT does not resume, since without early data that saves no round trip.
fn unauthenticated_config(endpoint: SocketAddr, encryption: Encryption) -> ClientConfig {
    let resumes = encryption == Encryption::Doq;
    ClientConfig {
        server_name: endpoint.ip().to_string(),
        verify_name: false,
        roots: None,
        insecure_verifier: Some(InsecureVerifier::dangerously_disable_certificate_verification()),
        alpn: vec![encryption.alpn().to_vec()],
        client_cert: None,
        session: if resumes { take_ticket(endpoint) } else { None },
        enable_early_data: resumes,
        send_key_share: true,
    }
}

/// Kept apart from the upstreams' tickets: resuming skips the certificate check, and these
/// handshakes checked none.
fn tickets() -> &'static Mutex<LruMap<SocketAddr, Vec<TlsSession>>> {
    static TICKETS: OnceLock<Mutex<LruMap<SocketAddr, Vec<TlsSession>>>> = OnceLock::new();
    TICKETS.get_or_init(|| Mutex::new(LruMap::new(MAX_TICKET_SERVERS)))
}

/// Each ticket is used once (RFC 9539), newest first.
fn take_ticket(endpoint: SocketAddr) -> Option<TlsSession> {
    let now = onetdns_tls::session::now_ms();
    let mut tickets = tickets()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let stack = tickets.get_mut(&endpoint)?;
    stack.retain(|ticket| ticket.is_fresh(now));
    let ticket = stack.pop();
    if stack.is_empty() {
        tickets.pop(&endpoint);
    }
    ticket
}

fn keep_tickets(endpoint: SocketAddr, new: Vec<TlsSession>) {
    if new.is_empty() {
        return;
    }
    let mut tickets = tickets()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut stack = tickets.pop(&endpoint).unwrap_or_default();
    stack.extend(new);
    let excess = stack.len().saturating_sub(TICKETS_PER_SERVER);
    stack.drain(..excess);
    tickets.put(endpoint, stack);
}

impl EncryptedConn {
    /// A DoQ connection the server closed is found by its first exchange.
    fn open(&self) -> bool {
        match self {
            EncryptedConn::Dot(conn) => conn.open(),
            EncryptedConn::Doq(_) => true,
        }
    }

    fn connect(
        bind: SocketAddr,
        endpoint: SocketAddr,
        encryption: Encryption,
        deadline: Instant,
    ) -> Result<Self, ForwardError> {
        let cfg = unauthenticated_config(endpoint, encryption);
        match encryption {
            Encryption::Dot => {
                let mut tcp = crate::connect_upstream(endpoint, deadline).map_err(crate::io_err)?;
                let tls = client_handshake(&mut tcp, &cfg).map_err(|error| {
                    if Instant::now() >= deadline {
                        ForwardError::Timeout
                    } else {
                        ForwardError::Io(format!("DoT handshake failed: {error}"))
                    }
                })?;
                Ok(EncryptedConn::Dot(Box::new(DotConn::new(tcp, tls))))
            }
            Encryption::Doq => {
                let timeout = deadline
                    .checked_duration_since(Instant::now())
                    .filter(|left| !left.is_zero())
                    .ok_or(ForwardError::Timeout)?;
                let created = Instant::now();
                let server_name = cfg.server_name.clone();
                let (sock, conn) =
                    crate::quicdrive::open_client_connection(endpoint, bind, cfg, timeout)?;
                DoqConn::establish(sock, conn, created, server_name, deadline)
                    .map(|conn| EncryptedConn::Doq(Box::new(conn)))
            }
        }
    }

    fn roundtrip(
        &mut self,
        wire: &[u8],
        wire_id: u16,
        request: &Message,
        deadline: Instant,
    ) -> Result<Message, ForwardError> {
        match self {
            EncryptedConn::Dot(conn) => dot::roundtrip(conn, wire, wire_id, request, deadline),
            EncryptedConn::Doq(conn) => doq::roundtrip(conn, wire, request, deadline),
        }
    }
}

/// Records the outcome for `route` and the next probe. A kept connection that fails is taken as
/// closed by the server, which is not a failure, and the query moves to a new one.
pub(crate) fn exchange(
    endpoint: SocketAddr,
    encryption: Encryption,
    wire: &[u8],
    wire_id: u16,
    request: &Message,
    timeout: Duration,
) -> Result<Message, ForwardError> {
    let deadline = crate::deadline_after(timeout);
    let result = ask(endpoint, encryption, wire, wire_id, request, deadline);
    let outcome = match &result {
        Ok(_) => Outcome::Answered,
        Err(ForwardError::Timeout) if timeout < PROBE_TIMEOUT => Outcome::CutShort,
        Err(_) => Outcome::Failed,
    };
    if outcome != Outcome::Answered {
        onetdns_core::debug!(event = "forward.opportunistic_failed",
            addr = %endpoint,
            encryption = ?encryption,
            reason = ?result.as_ref().err(),
            "Could not ask the authoritative server over encryption; it is asked in plaintext"
        );
    }
    memory()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .record((endpoint, encryption), outcome, Instant::now());
    result
}

fn ask(
    endpoint: SocketAddr,
    encryption: Encryption,
    wire: &[u8],
    wire_id: u16,
    request: &Message,
    deadline: Instant,
) -> Result<Message, ForwardError> {
    let bind = crate::outgoing_bind(endpoint);
    let key = (bind, endpoint, encryption);
    let kept = pool()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take(&key);
    if let Some(mut conn) = kept {
        match conn.roundtrip(wire, wire_id, request, crate::bounded_first_try(deadline)) {
            Ok(response) => {
                put_idle(key, conn);
                return Ok(response);
            }
            Err(error) => {
                if matches!(error, ForwardError::Timeout) {
                    pool()
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .stop_reusing(&key);
                }
                onetdns_core::debug!(event = "forward.conn_retry",
                    transport = "adot",
                    addr = %endpoint,
                    reason = ?error,
                    "Could not reuse the existing connection; retrying on a new one"
                );
            }
        }
    }
    let mut conn = EncryptedConn::connect(bind, endpoint, encryption, deadline)?;
    let response = conn.roundtrip(wire, wire_id, request, deadline)?;
    put_idle(key, conn);
    Ok(response)
}

/// Tickets arrive after the handshake, so any answered exchange may bring some.
fn put_idle(key: PoolKey, mut conn: EncryptedConn) {
    if let EncryptedConn::Doq(doq) = &mut conn {
        keep_tickets(key.1, doq.take_new_sessions());
    }
    pool()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .put(key, conn);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, TcpListener, UdpSocket};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    use onetdns_proto::{Name, RData, Record, RecordType};
    use onetdns_quic::params::TransportParams;
    use onetdns_quic::Connection;
    use onetdns_tls::conn::ServerResumption;
    use onetdns_tls::{server_handshake, signer_from_pkcs8_der, ServerConfig};

    use crate::quicdrive::random_cid;

    const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);

    fn query(name: &str) -> Message {
        Message::query(0x4242, Name::from_str(name).unwrap(), RecordType::A)
    }

    fn status(key: Key) -> Option<Status> {
        memory().lock().unwrap().status.peek(&key).copied()
    }

    fn wait_until(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
        let until = Instant::now() + limit;
        while Instant::now() < until {
            if done() {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        done()
    }

    /// Named for no address the client knows, so a handshake that completes proves nothing was
    /// checked.
    fn server_config(alpn: &[u8], resumption: Option<ServerResumption>) -> Arc<ServerConfig> {
        let ck = rcgen::generate_simple_self_signed(vec!["unrelated.test".to_string()]).unwrap();
        let (sign_scheme, sign) = signer_from_pkcs8_der(&ck.key_pair.serialize_der()).unwrap();
        Arc::new(ServerConfig {
            cert_chain: vec![ck.cert.der().to_vec()],
            sign_scheme,
            sign,
            alpn: vec![alpn.to_vec()],
            client_ca: None,
            resumption,
        })
    }

    fn answer(query: &[u8]) -> Vec<u8> {
        let request = Message::parse(query).unwrap();
        let mut response = Message::default();
        response.header.id = request.header.id;
        response.header.response = true;
        response.questions = request.questions.clone();
        if let Some(question) = request.questions.first() {
            response
                .answers
                .push(Record::new(question.name.clone(), 60, RData::A(ANSWER)));
        }
        response.try_encode().unwrap()
    }

    /// Counts connections.
    fn dot_server() -> (SocketAddr, Arc<AtomicUsize>) {
        let cfg = server_config(b"dot", None);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counted = accepts.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                counted.fetch_add(1, Ordering::SeqCst);
                let cfg = cfg.clone();
                thread::spawn(move || {
                    let Ok(mut tls) = server_handshake(&mut stream, &cfg) else {
                        return;
                    };
                    let mut buf = Vec::new();
                    loop {
                        let framed_len = |buf: &[u8]| {
                            (buf.len() >= 2)
                                .then(|| 2 + usize::from(u16::from_be_bytes([buf[0], buf[1]])))
                        };
                        while framed_len(&buf).is_none_or(|len| buf.len() < len) {
                            match tls.read_app(&mut stream) {
                                Ok(chunk) if !chunk.is_empty() => buf.extend_from_slice(&chunk),
                                _ => return,
                            }
                        }
                        let len = framed_len(&buf).unwrap();
                        let out = answer(&buf[2..len]);
                        buf.drain(..len);
                        let mut framed = (out.len() as u16).to_be_bytes().to_vec();
                        framed.extend_from_slice(&out);
                        if tls.write_app(&mut stream, &framed).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (addr, accepts)
    }

    /// Issues tickets and accepts early data. Counts peers, and the queries that came in accepted
    /// early data.
    fn doq_server() -> (SocketAddr, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let mut resumption = ServerResumption::secure_default();
        resumption.max_early_data = 0xffff_ffff;
        let cfg = server_config(b"doq", Some(resumption));
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let peers = Arc::new(AtomicUsize::new(0));
        let early = Arc::new(AtomicUsize::new(0));
        let (counted, counted_early) = (peers.clone(), early.clone());
        thread::spawn(move || {
            let mut conns: HashMap<SocketAddr, Connection> = HashMap::new();
            let mut buf = [0u8; onetdns_quic::MAX_RECV_UDP_PAYLOAD as usize];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                let conn = conns.entry(peer).or_insert_with(|| {
                    counted.fetch_add(1, Ordering::SeqCst);
                    Connection::new_server(
                        cfg.clone(),
                        random_cid(),
                        TransportParams::server_defaults(),
                    )
                });
                if conn.recv_datagram(&buf[..n]).is_err() {
                    conns.remove(&peer);
                    continue;
                }
                for (stream, query) in conn.take_stream_requests() {
                    if conn.early_data_accepted() {
                        counted_early.fetch_add(1, Ordering::SeqCst);
                    }
                    let _ = conn.send_dns_message(stream, &answer(&query));
                }
                while let Some(datagram) = conn.next_datagram() {
                    let _ = sock.send_to(&datagram, peer);
                }
            }
        });
        (addr, peers, early)
    }

    fn closed_tcp_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn closed_udp_port() -> u16 {
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn memory_keeps_answers_for_persistence_and_failures_for_damping() {
        let server = SocketAddr::from(([192, 0, 2, 1], 853));
        let doq = (server, Encryption::Doq);
        let dot = (server, Encryption::Dot);
        let keys = [doq, dot];
        let mut memory = Memory::new(8);
        let start = Instant::now();

        assert_eq!(memory.claim_probe(keys, start), Some(doq));
        assert_eq!(memory.claim_probe(keys, start), None, "one probe at a time");
        memory.record(doq, Outcome::Failed, start);
        assert_eq!(memory.route(keys, start), None);
        assert_eq!(memory.claim_probe(keys, start), Some(dot), "DoQ is damped");
        memory.record(dot, Outcome::Answered, start);
        assert_eq!(memory.route(keys, start), Some(dot));
        assert_eq!(
            memory.claim_probe(keys, start + DAMPING),
            None,
            "nothing is probed while DoT answers"
        );

        let later = start + PERSISTENCE;
        assert_eq!(memory.route(keys, later), None, "the answer is too old");
        assert_eq!(
            memory.claim_probe(keys, later),
            Some(doq),
            "DoQ is probed again"
        );
    }

    #[test]
    fn encrypted_servers_name_each_server_once() {
        let server = SocketAddr::from(([192, 0, 2, 5], 853));
        {
            let mut memory = memory().lock().unwrap();
            let now = Instant::now();
            memory.record((server, Encryption::Doq), Outcome::Answered, now);
            memory.record((server, Encryption::Dot), Outcome::Answered, now);
        }
        let listed: Vec<_> = encrypted_servers()
            .into_iter()
            .filter(|(ip, _)| *ip == server.ip())
            .collect();
        assert_eq!(
            listed,
            [(server.ip(), Encryption::Doq)],
            "queries go over DoQ when both answer"
        );
    }

    #[test]
    fn a_short_timeout_drops_a_success_but_not_a_failure_or_a_probe() {
        let dot = (SocketAddr::from(([192, 0, 2, 2], 853)), Encryption::Dot);
        let doq = (dot.0, Encryption::Doq);
        let mut memory = Memory::new(8);
        let now = Instant::now();

        memory.record(dot, Outcome::Answered, now);
        memory.record(dot, Outcome::CutShort, now);
        assert_eq!(memory.status.peek(&dot), None);

        memory.record(dot, Outcome::Failed, now);
        memory.record(dot, Outcome::CutShort, now);
        assert_eq!(memory.status.peek(&dot), Some(&Status::Failed(now)));

        assert_eq!(memory.claim_probe([dot, doq], now), Some(doq));
        memory.record(doq, Outcome::CutShort, now);
        assert_eq!(memory.status.peek(&doq), Some(&Status::Probing));
        memory.release(doq);
        assert_eq!(memory.status.peek(&doq), None);
    }

    #[test]
    fn a_server_offering_only_dot_is_asked_over_it_after_one_probe() {
        let (endpoint, accepts) = dot_server();
        let doq_port = closed_udp_port();
        let encryption = OpportunisticEncryption::with_ports(endpoint.port(), doq_port);
        let server = endpoint.ip();
        assert_eq!(encryption.route(server), None);

        encryption.probe(server, &query("probe.test"));
        assert!(wait_until(Duration::from_secs(5), || encryption
            .route(server)
            .is_some()));
        let route = encryption.route(server).unwrap();
        assert_eq!(
            route,
            EncryptedRoute {
                endpoint,
                encryption: Encryption::Dot
            }
        );
        assert!(matches!(
            status((SocketAddr::new(server, doq_port), Encryption::Doq)),
            Some(Status::Failed(_))
        ));

        let response = crate::query_server_over(
            route.endpoint,
            &query("next.test"),
            Duration::from_secs(2),
            route.transport(),
            true,
        )
        .unwrap();
        assert_eq!(response.answers[0].rdata, RData::A(ANSWER));
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            1,
            "the query reuses the probe's connection"
        );
    }

    #[test]
    fn a_server_offering_doq_is_asked_over_it_before_dot_is_tried() {
        let (endpoint, peers, _) = doq_server();
        let dot_port = closed_tcp_port();
        let encryption = OpportunisticEncryption::with_ports(dot_port, endpoint.port());
        let server = endpoint.ip();

        encryption.probe(server, &query("probe.test"));
        assert!(wait_until(Duration::from_secs(5), || encryption
            .route(server)
            .is_some()));
        let route = encryption.route(server).unwrap();
        assert_eq!(route.encryption, Encryption::Doq);
        assert_eq!(
            status((SocketAddr::new(server, dot_port), Encryption::Dot)),
            None
        );

        let response = crate::query_server_over(
            route.endpoint,
            &query("next.test"),
            Duration::from_secs(2),
            route.transport(),
            true,
        )
        .unwrap();
        assert_eq!(response.answers[0].rdata, RData::A(ANSWER));
        assert_eq!(peers.load(Ordering::SeqCst), 1);
    }

    #[test]
    /// The probe's handshake leaves a ticket; once its connection is gone, the next query resumes
    /// and goes out as early data the server accepts.
    fn a_new_doq_connection_resumes_with_the_query_in_early_data() {
        let (endpoint, peers, early) = doq_server();
        let encryption = OpportunisticEncryption::with_ports(closed_tcp_port(), endpoint.port());
        let server = endpoint.ip();
        encryption.probe(server, &query("probe.test"));
        assert!(wait_until(Duration::from_secs(5), || encryption
            .route(server)
            .is_some()));
        let route = encryption.route(server).unwrap();
        let pooled = (crate::outgoing_bind(endpoint), endpoint, Encryption::Doq);
        drop(pool().lock().unwrap().take(&pooled));

        let response = crate::query_server_over(
            route.endpoint,
            &query("resumed.test"),
            Duration::from_secs(2),
            route.transport(),
            true,
        )
        .unwrap();
        assert_eq!(response.answers[0].rdata, RData::A(ANSWER));
        assert_eq!(peers.load(Ordering::SeqCst), 2);
        assert_eq!(early.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_server_that_resets_is_not_probed_again_within_damping() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counted = accepts.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                counted.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        let doq_port = closed_udp_port();
        let encryption = OpportunisticEncryption::with_ports(endpoint.port(), doq_port);
        let server = endpoint.ip();
        let dot = (endpoint, Encryption::Dot);
        let doq = (SocketAddr::new(server, doq_port), Encryption::Doq);
        let failed = |key| matches!(status(key), Some(Status::Failed(_)));

        encryption.probe(server, &query("first.test"));
        assert!(wait_until(Duration::from_secs(6), || failed(doq) && failed(dot)));

        for _ in 0..3 {
            encryption.probe(server, &query("again.test"));
        }
        thread::sleep(Duration::from_millis(200));
        assert_eq!(accepts.load(Ordering::SeqCst), 1);
        assert!(failed(dot) && failed(doq));
        assert_eq!(encryption.route(server), None);
    }

    #[test]
    fn a_timeout_counts_as_failure_only_with_the_probe_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming() {
                held.push(stream);
            }
        });
        let key = (endpoint, Encryption::Dot);
        let request = query("silent.test");
        let wire = request.try_encode().unwrap();
        let ask = |timeout| {
            exchange(
                endpoint,
                Encryption::Dot,
                &wire,
                request.header.id,
                &request,
                timeout,
            )
        };

        memory()
            .lock()
            .unwrap()
            .record(key, Outcome::Answered, Instant::now());
        assert!(matches!(
            ask(Duration::from_millis(300)),
            Err(ForwardError::Timeout)
        ));
        assert_eq!(status(key), None);

        assert!(matches!(ask(PROBE_TIMEOUT), Err(ForwardError::Timeout)));
        assert!(matches!(status(key), Some(Status::Failed(_))));
    }
}
