//! The connection table and receive loop shared by the DoQ and DoH3 listeners. Admission,
//! Retry, path checks, timers, idle eviction, the memory budget and worker completions are
//! common; a `QuicService` decides how requests are dispatched and answers sent.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use onetdns_core::admission::{shrink_if_sparse, ClientCounts};
use onetdns_core::udp::RecvWait;
use onetdns_proto::Message;
use onetdns_quic::params::TransportParams;
use onetdns_quic::retry::{build_retry, parse_initial_header, RetryKey};
use onetdns_quic::{packet, ClosePeriod, Connection, H3Connection, QuicDiagnostic, QuicError};
use onetdns_tls::ServerConfig;

use crate::native::NativeServer;
use crate::quic_memory::{QuicMemoryBudget, QuicMemoryLease, QuicRunControl};
use crate::qworker::{self, QueryDone, QueryJob, WorkerPool, MAX_INFLIGHT_PER_CONN};
use crate::transport_observe;

const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONNECTIONS: usize = 2048;
const MAX_CONNECTIONS_PER_IP: usize = 64;
/// RFC 9000 minimum. Opening on smaller datagrams would let a small request draw a larger reply.
const MIN_INITIAL_DATAGRAM: usize = 1200;
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);
const TIMER_INTERVAL: Duration = Duration::from_millis(100);

/// DoQ uses the QUIC connection as is; DoH3 adds HTTP/3 on top.
pub(crate) trait ServerConn {
    fn from_quic(conn: Connection) -> Self;
    fn set_now(&mut self, now_ms: u64);
    fn on_timeout(&mut self, now_ms: u64);
    /// After an error the connection is unusable.
    fn recv_datagram(&mut self, datagram: &[u8]) -> Result<(), QuicError>;
    fn next_datagram(&mut self) -> Option<Vec<u8>>;
    fn is_closed(&self) -> bool;
    /// Keeps only the state the closing or draining period needs. `None` for an open connection or
    /// a period already over.
    fn into_close_period(self) -> Option<ClosePeriod>;
    /// What the connection holds against the global memory budget.
    fn retained_payload_bytes(&self) -> usize;
    /// For logging only.
    fn take_diagnostic(&mut self) -> Option<QuicDiagnostic>;
}

impl ServerConn for Connection {
    fn from_quic(conn: Connection) -> Self {
        conn
    }
    fn set_now(&mut self, now_ms: u64) {
        Connection::set_now(self, now_ms);
    }
    fn on_timeout(&mut self, now_ms: u64) {
        Connection::on_timeout(self, now_ms);
    }
    fn recv_datagram(&mut self, datagram: &[u8]) -> Result<(), QuicError> {
        Connection::recv_datagram(self, datagram)
    }
    fn next_datagram(&mut self) -> Option<Vec<u8>> {
        Connection::next_datagram(self)
    }
    fn is_closed(&self) -> bool {
        Connection::is_closed(self)
    }
    fn into_close_period(self) -> Option<ClosePeriod> {
        Connection::into_close_period(self)
    }
    fn retained_payload_bytes(&self) -> usize {
        Connection::retained_payload_bytes(self)
    }
    fn take_diagnostic(&mut self) -> Option<QuicDiagnostic> {
        Connection::take_diagnostic(self)
    }
}

impl ServerConn for H3Connection {
    fn from_quic(conn: Connection) -> Self {
        H3Connection::new(conn)
    }
    fn set_now(&mut self, now_ms: u64) {
        H3Connection::set_now(self, now_ms);
    }
    fn on_timeout(&mut self, now_ms: u64) {
        H3Connection::on_timeout(self, now_ms);
    }
    fn recv_datagram(&mut self, datagram: &[u8]) -> Result<(), QuicError> {
        H3Connection::recv_datagram(self, datagram)
    }
    fn next_datagram(&mut self) -> Option<Vec<u8>> {
        H3Connection::next_datagram(self)
    }
    fn is_closed(&self) -> bool {
        H3Connection::is_closed(self)
    }
    fn into_close_period(self) -> Option<ClosePeriod> {
        H3Connection::into_close_period(self)
    }
    fn retained_payload_bytes(&self) -> usize {
        H3Connection::retained_payload_bytes(self)
    }
    fn take_diagnostic(&mut self) -> Option<QuicDiagnostic> {
        self.conn_mut().take_diagnostic()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Why the listener closes a connection on its own; each transport maps it to its RFC error code.
pub(crate) enum Abandon {
    Shutdown,
    Internal,
    /// The memory budget or send buffer ran out.
    ExcessiveLoad,
}

/// What differs between DoQ and DoH3 listeners.
pub(crate) trait QuicService: Send + 'static {
    type Conn: ServerConn;
    const NAME: &'static str;
    /// Checks requests `recv_datagram` completed and hands them to workers or answers at once.
    /// Called on open connections only; a connection that becomes unusable is closed here, and the
    /// listener keeps it until its closing period ends.
    fn dispatch(&self, conn: &mut Self::Conn, intake: &mut Intake<'_>);
    /// Called on open connections only. `max_age` is ignored by transports without HTTP.
    fn send_answer(
        conn: &mut Self::Conn,
        stream_id: u64,
        wire: Vec<u8>,
        max_age: u32,
    ) -> Result<(), QuicError>;
    /// Keeps the first reason on a connection already closed. Dropping without notice would leave
    /// the peer waiting for its own idle timeout.
    fn abandon(conn: &mut Self::Conn, why: Abandon);
}

/// Whether the connection stays usable after a failed send, closing it if not. A stream the peer
/// stopped or that already ended loses only that answer; dropping the connection would lose the
/// other answers on it. A full send buffer means the peer sends queries without reading answers,
/// so it is reported as excessive load.
pub(crate) fn connection_survives<S: QuicService>(
    conn: &mut S::Conn,
    peer: SocketAddr,
    sent: Result<(), QuicError>,
) -> bool {
    let error = match sent {
        Ok(()) | Err(QuicError::StreamClosed) => return true,
        Err(error) => error,
    };
    let why = if error == QuicError::FlowControl {
        Abandon::ExcessiveLoad
    } else {
        Abandon::Internal
    };
    transport_observe::record_error(S::NAME, "send_response", Some(peer), &error);
    S::abandon(conn, why);
    false
}

/// Hands requests from one connection to workers, tagged with the connection key and epoch so a
/// late answer for a finished connection can be dropped.
pub(crate) struct Intake<'a> {
    key: &'a [u8],
    /// The validated peer address.
    peer: SocketAddr,
    epoch: u64,
    inflight: &'a mut usize,
    pool: &'a WorkerPool,
}

impl Intake<'_> {
    pub(crate) fn key(&self) -> &[u8] {
        self.key
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }

    pub(crate) fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Answers SERVFAIL at once when no worker takes the query. False when the connection can no
    /// longer be used.
    pub(crate) fn submit<S: QuicService>(
        &mut self,
        conn: &mut S::Conn,
        req: &Message,
        job: QueryJob,
    ) -> bool {
        let stream_id = job.stream_id;
        if *self.inflight >= MAX_INFLIGHT_PER_CONN {
            transport_observe::record_error(
                S::NAME,
                "inflight_limit",
                Some(self.peer),
                "connection has too many queries in flight",
            );
        } else if self.pool.submit(job).is_ok() {
            *self.inflight += 1;
            return true;
        } else {
            transport_observe::record_error(
                S::NAME,
                "worker_queue_full",
                Some(self.peer),
                "query worker queue is saturated",
            );
        }
        let sent = S::send_answer(conn, stream_id, qworker::servfail_wire(req), 0);
        connection_survives::<S>(conn, self.peer, sent)
    }
}

/// Stops and joins the receive loop on drop.
pub(crate) struct QuicListener {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl QuicListener {
    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for QuicListener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(crate) fn serve<S: QuicService>(
    service: S,
    addr: SocketAddr,
    tls: Arc<onetdns_core::ArcSwap<ServerConfig>>,
    handler: Arc<NativeServer>,
    shutdown: Arc<AtomicBool>,
    memory_budget: Arc<QuicMemoryBudget>,
) -> io::Result<QuicListener> {
    let socket = onetdns_core::udp::bind(addr)?;
    let bound = socket.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let listener_stop = stop.clone();
    let wait = RecvWait::new(TIMER_INTERVAL);
    wait.install(&socket)?;
    let workers = qworker::default_worker_count();
    let (done_notify, wake_source) = qworker::udp_completion_notifier(bound)?;
    let pool = WorkerPool::new(
        qworker::handler_resolver(handler.clone()),
        workers,
        workers * 64,
        Some(done_notify),
    )?;
    let thread = thread::Builder::new()
        .name(format!("{}-listener", S::NAME))
        .spawn(move || {
            Listener {
                service,
                socket,
                tls,
                pool,
                wake_source,
                drops: Box::new(move |source| handler.drops_source(source)),
                control: QuicRunControl::new(shutdown, listener_stop, memory_budget),
                table: ConnTable::new(),
                base_tp: TransportParams::server_defaults(),
                retry_key: RetryKey::generate(),
                next_epoch: 0,
                clock: Instant::now(),
            }
            .run(wait)
        })?;
    Ok(QuicListener {
        addr: bound,
        stop,
        thread: Some(thread),
    })
}

/// Must be unpredictable.
pub(crate) fn random_cid() -> Vec<u8> {
    let mut cid = [0u8; 8];
    onetdns_tls::sys::fill_random(&mut cid);
    cid.to_vec()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// The datagram must meet the RFC minimum and the total and per-client limits must have room.
fn initial_connection_allowed(datagram_len: usize, total: usize, client_has_room: bool) -> bool {
    datagram_len >= MIN_INITIAL_DATAGRAM && total < MAX_CONNECTIONS && client_has_room
}

/// Taking packets from another address would let a spoofed migration aim this server's traffic
/// at someone else.
fn same_validated_path(existing: SocketAddr, incoming: SocketAddr) -> bool {
    existing == incoming
}

/// A closed connection stays in the table until its closing or draining period ends, to answer
/// late packets with the close again and to keep its connection IDs known; RFC 9000 does not let a
/// server that keeps accepting cut the period short. Only the period's state is kept, so the
/// closed connection does not hold its memory budget meanwhile.
enum ConnState<C> {
    Open(C),
    Closing(ClosePeriod),
}

struct ConnEntry<C> {
    state: ConnState<C>,
    peer: SocketAddr,
    last: Instant,
    /// Tells late answers of a finished connection apart.
    epoch: u64,
    inflight: usize,
    /// This connection's share of the global QUIC memory budget.
    memory: QuicMemoryLease,
}

fn flush<C: ServerConn>(
    conn: &mut C,
    peer: SocketAddr,
    socket: &UdpSocket,
    name: &'static str,
    stage: &'static str,
) {
    while let Some(datagram) = conn.next_datagram() {
        if let Err(error) = socket.send_to(&datagram, peer) {
            transport_observe::record_error(name, stage, Some(peer), error);
        }
    }
}

impl<C: ServerConn> ConnEntry<C> {
    /// Sends the output of an open connection and resizes its memory lease, closing it with
    /// excessive load if the budget refuses. False when closed; the caller then retires it.
    fn settle<S: QuicService<Conn = C>>(
        &mut self,
        socket: &UdpSocket,
        stage: &'static str,
    ) -> bool {
        let ConnState::Open(conn) = &mut self.state else {
            return false;
        };
        flush(conn, self.peer, socket, S::NAME, stage);
        if !self.memory.refresh(conn.retained_payload_bytes()) {
            transport_observe::record_error(
                S::NAME,
                "memory_budget",
                Some(self.peer),
                "Total QUIC connection memory budget exceeded",
            );
            S::abandon(conn, Abandon::ExcessiveLoad);
            flush(conn, self.peer, socket, S::NAME, stage);
        }
        !conn.is_closed()
    }
}

/// The three maps are always updated together.
struct ConnTable<S: QuicService> {
    conns: HashMap<Vec<u8>, ConnEntry<S::Conn>>,
    /// Destination connection ID of a packet to the connection key.
    aliases: HashMap<Vec<u8>, Vec<u8>>,
    clients: ClientCounts,
}

impl<S: QuicService> ConnTable<S> {
    fn new() -> Self {
        Self {
            conns: HashMap::new(),
            aliases: HashMap::new(),
            clients: ClientCounts::new(MAX_CONNECTIONS_PER_IP, MAX_CONNECTIONS),
        }
    }

    fn key_for(&self, dcid: &[u8]) -> Vec<u8> {
        self.aliases
            .get(dcid)
            .cloned()
            .unwrap_or_else(|| dcid.to_vec())
    }

    fn insert(&mut self, dcid: Vec<u8>, key: Vec<u8>, entry: ConnEntry<S::Conn>) {
        self.clients.add(entry.peer.ip());
        self.conns.insert(key.clone(), entry);
        self.aliases.insert(dcid, key);
    }

    fn remove(&mut self, key: &[u8]) {
        if let Some(entry) = self.conns.remove(key) {
            self.clients.remove(entry.peer.ip());
        }
        self.aliases.retain(|_, primary| primary.as_slice() != key);
        self.shrink();
    }

    /// Keeps only the closing or draining state, or removes the connection once that is over too.
    /// The lease shrinks to match; if the close datagram needs more and the budget refuses, the
    /// current lease stays, which the base charge covers. Called on an open connection, it removes
    /// it.
    fn retire(&mut self, key: &[u8]) {
        let Some(mut entry) = self.conns.remove(key) else {
            return;
        };
        let period = match entry.state {
            ConnState::Open(conn) => conn.into_close_period(),
            ConnState::Closing(period) => Some(period),
        };
        let Some(period) = period else {
            self.clients.remove(entry.peer.ip());
            self.remove(key);
            return;
        };
        entry.memory.refresh(period.retained_bytes());
        entry.state = ConnState::Closing(period);
        self.conns.insert(key.to_vec(), entry);
    }

    /// Drops idle connections without notice, as RFC 9000 idle timeout does. Closing connections
    /// are dropped too once idle, so an inflated RTT cannot stretch their period and hold a slot.
    fn evict_idle(&mut self) {
        let now = Instant::now();
        self.conns
            .retain(|_, entry| now.duration_since(entry.last) < IDLE_TIMEOUT);
        let conns = &self.conns;
        self.aliases
            .retain(|_, primary| conns.contains_key(primary));
        self.clients.clear();
        for entry in self.conns.values() {
            self.clients.add(entry.peer.ip());
        }
        self.shrink();
    }

    /// Drops everything without notice. Used after a panic, when close frames built from the state
    /// could not be trusted.
    fn clear(&mut self) {
        self.conns.clear();
        self.aliases.clear();
        self.clients.clear();
    }

    fn shrink(&mut self) {
        shrink_if_sparse(&mut self.conns);
        shrink_if_sparse(&mut self.aliases);
        self.clients.shrink();
    }

    fn unique_cid(&self) -> Vec<u8> {
        loop {
            let cid = random_cid();
            if !self.conns.contains_key(&cid) {
                return cid;
            }
        }
    }

    /// `now_ms` is recorded as the send time; a stale value inflates RTT samples and fires PTO
    /// early.
    fn apply_completions(&mut self, socket: &UdpSocket, done: &mut Vec<QueryDone>, now_ms: u64) {
        let mut closed: Vec<Vec<u8>> = Vec::new();
        for d in done.drain(..) {
            let Some(entry) = self.conns.get_mut(&d.conn_key) else {
                continue;
            };
            if entry.epoch != d.epoch {
                continue;
            }
            entry.inflight = entry.inflight.saturating_sub(1);
            let Some(wire) = d.wire else {
                continue;
            };
            // A closed connection has nowhere to put an answer; trying would log a normal close as
            // a send failure.
            let ConnState::Open(conn) = &mut entry.state else {
                continue;
            };
            if conn.is_closed() {
                continue;
            }
            conn.set_now(now_ms);
            let sent = S::send_answer(conn, d.stream_id, wire, d.max_age);
            connection_survives::<S>(conn, entry.peer, sent);
            if !entry.settle::<S>(socket, "send_datagram") {
                closed.push(d.conn_key);
            }
        }
        for key in closed {
            self.retire(&key);
        }
    }

    /// Runs due retransmissions and drops connections whose closing period ended.
    fn drive_timeouts(&mut self, socket: &UdpSocket, now_ms: u64) {
        let mut closed = Vec::new();
        let mut ended = Vec::new();
        for (key, entry) in self.conns.iter_mut() {
            match &mut entry.state {
                ConnState::Open(conn) => {
                    conn.set_now(now_ms);
                    conn.on_timeout(now_ms);
                    if !entry.settle::<S>(socket, "timeout_send") {
                        closed.push(key.clone());
                    }
                }
                ConnState::Closing(period) => {
                    if period.is_over(now_ms) {
                        ended.push(key.clone());
                    }
                }
            }
        }
        for key in closed {
            self.retire(&key);
        }
        for key in ended {
            self.remove(&key);
        }
    }

    /// Sends a close on every open connection and drops them all. The socket closes too, so RFC
    /// 9000 lets the closing period be skipped; without the close, clients would wait for their
    /// idle timeout.
    fn close_all(&mut self, socket: &UdpSocket, now_ms: u64) {
        for entry in self.conns.values_mut() {
            if let ConnState::Open(conn) = &mut entry.state {
                conn.set_now(now_ms);
                S::abandon(conn, Abandon::Shutdown);
                flush(conn, entry.peer, socket, S::NAME, "shutdown_send");
            }
        }
        self.clear();
    }
}

struct Listener<S: QuicService> {
    service: S,
    socket: UdpSocket,
    tls: Arc<onetdns_core::ArcSwap<ServerConfig>>,
    pool: WorkerPool,
    /// Source of the datagram a worker sends to wake the loop.
    wake_source: SocketAddr,
    /// Datagrams from these addresses are dropped without any reply.
    drops: Box<dyn Fn(IpAddr) -> bool + Send>,
    control: QuicRunControl,
    table: ConnTable<S>,
    /// Transport parameters every new connection starts from.
    base_tp: TransportParams,
    retry_key: RetryKey,
    next_epoch: u64,
    /// Origin of the connection clock.
    clock: Instant,
}

impl<S: QuicService> Listener<S> {
    fn now_ms(&self) -> u64 {
        self.clock.elapsed().as_millis().min(u64::MAX as u128) as u64
    }

    fn run(mut self, wait: RecvWait) {
        let mut buf = [0u8; onetdns_quic::MAX_RECV_UDP_PAYLOAD as usize];
        let mut done: Vec<QueryDone> = Vec::new();
        let mut last_sweep = Instant::now();
        let mut last_timer = Instant::now();
        while !self.control.should_stop() {
            let maintenance = onetdns_core::isolation::catch_request(|| {
                self.pool.drain_done(&mut done);
                if !done.is_empty() {
                    let now_ms = self.now_ms();
                    self.table
                        .apply_completions(&self.socket, &mut done, now_ms);
                }
                if last_timer.elapsed() >= TIMER_INTERVAL {
                    let now_ms = self.now_ms();
                    self.table.drive_timeouts(&self.socket, now_ms);
                    last_timer = Instant::now();
                }
                if last_sweep.elapsed() >= SWEEP_INTERVAL {
                    self.table.evict_idle();
                    last_sweep = Instant::now();
                }
            });
            if maintenance.is_err() {
                self.table.clear();
                done.clear();
            }
            let (n, peer) = match wait.recv_from(&self.socket, &mut buf) {
                Ok(received) => received,
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(error) => {
                    transport_observe::record_error(S::NAME, "recv_datagram", None, error);
                    continue;
                }
            };
            let mut panic_key: Option<Vec<u8>> = None;
            let packet = onetdns_core::isolation::catch_request(|| {
                self.on_datagram(&buf[..n], peer, &mut panic_key)
            });
            if packet.is_err() {
                if let Some(key) = panic_key {
                    self.table.remove(&key);
                }
            }
        }
        let now_ms = self.now_ms();
        // Workers must stop even if sending the closes panics; remaining connections go with this
        // function.
        let _ = onetdns_core::isolation::catch_request(|| {
            self.table.close_all(&self.socket, now_ms);
        });
        self.pool.shutdown();
    }

    /// `panic_key` is set to the connection being handled, so a panic drops only that one.
    fn on_datagram(&mut self, bytes: &[u8], peer: SocketAddr, panic_key: &mut Option<Vec<u8>>) {
        if qworker::is_completion_wake(peer, self.wake_source, bytes) {
            return;
        }
        // No Retry and no ACK for a dropped address. A connection it opened before the drop rule
        // applied is removed too, which stops its retransmissions.
        if (self.drops)(peer.ip()) {
            if let Some(dcid) = packet::destination_connection_id(bytes, 8) {
                let key = self.table.key_for(dcid);
                if self
                    .table
                    .conns
                    .get(&key)
                    .is_some_and(|entry| same_validated_path(entry.peer, peer))
                {
                    self.table.remove(&key);
                }
            }
            return;
        }
        let Some(dcid) = packet::destination_connection_id(bytes, 8).map(<[u8]>::to_vec) else {
            transport_observe::record_error(
                S::NAME,
                "packet_header",
                Some(peer),
                "missing destination connection id",
            );
            return;
        };
        let now = Instant::now();
        let mut key = self.table.key_for(&dcid);
        *panic_key = Some(key.clone());
        if !self.table.conns.contains_key(&key) {
            let Some(accepted) = self.accept(bytes, peer, dcid, now, panic_key) else {
                return;
            };
            key = accepted;
        }

        let now_ms = self.now_ms();
        let Some(entry) = self.table.conns.get_mut(&key) else {
            return;
        };
        if !same_validated_path(entry.peer, peer) {
            transport_observe::record_error(
                S::NAME,
                "connection_migration",
                Some(peer),
                "connection migration requires path validation",
            );
            return;
        }
        entry.last = now;
        let conn = match &mut entry.state {
            ConnState::Open(conn) => conn,
            // A closing connection only repeats its close; its packets are not decoded, so requests
            // in them are not dispatched.
            ConnState::Closing(period) => {
                if let Some(datagram) = period.answer(bytes.len()) {
                    if let Err(error) = self.socket.send_to(&datagram, entry.peer) {
                        transport_observe::record_error(
                            S::NAME,
                            "send_datagram",
                            Some(entry.peer),
                            error,
                        );
                    }
                }
                return;
            }
        };
        conn.set_now(now_ms);
        let received = conn.recv_datagram(bytes);
        if let Some(diagnostic) = conn.take_diagnostic() {
            transport_observe::record_quic_diagnostic(S::NAME, Some(entry.peer), diagnostic);
        }
        match received {
            Err(error) => {
                transport_observe::record_error(
                    S::NAME,
                    "quic_connection",
                    Some(entry.peer),
                    error,
                );
            }
            // Closed: nothing can answer requests in this datagram.
            Ok(()) if conn.is_closed() => {}
            Ok(()) => {
                let mut intake = Intake {
                    key: &key,
                    peer: entry.peer,
                    epoch: entry.epoch,
                    inflight: &mut entry.inflight,
                    pool: &self.pool,
                };
                self.service.dispatch(conn, &mut intake);
            }
        }
        if !entry.settle::<S>(&self.socket, "send_datagram") {
            self.table.retire(&key);
        }
    }

    /// Answers a tokenless Initial with Retry to validate the address first, and creates state only
    /// for a valid token. Returns the new connection key.
    fn accept(
        &mut self,
        bytes: &[u8],
        peer: SocketAddr,
        dcid: Vec<u8>,
        now: Instant,
        panic_key: &mut Option<Vec<u8>>,
    ) -> Option<Vec<u8>> {
        if !packet::is_initial_packet(bytes) {
            transport_observe::record_error(
                S::NAME,
                "unknown_connection",
                Some(peer),
                "non-initial packet for unknown connection",
            );
            return None;
        }
        let client_has_room = self.table.clients.allows(peer.ip());
        if !initial_connection_allowed(bytes.len(), self.table.conns.len(), client_has_room) {
            transport_observe::record_error(
                S::NAME,
                "connection_limit",
                Some(peer),
                "initial datagram rejected by size or connection limit",
            );
            return None;
        }
        let header = parse_initial_header(bytes)?;
        if header.token.is_empty() {
            let retry_cid = self.table.unique_cid();
            let token = self
                .retry_key
                .issue(peer.ip(), header.dcid, &retry_cid, unix_now());
            let retry = build_retry(header.dcid, header.scid, &retry_cid, &token);
            if let Err(error) = self.socket.send_to(&retry, peer) {
                transport_observe::record_error(S::NAME, "send_retry", Some(peer), error);
            }
            return None;
        }
        let Some(original_dcid) =
            self.retry_key
                .validate(header.token, peer.ip(), header.dcid, unix_now())
        else {
            transport_observe::record_error(
                S::NAME,
                "retry_token",
                Some(peer),
                "invalid or expired retry token",
            );
            return None;
        };
        let local_cid = header.dcid.to_vec();
        *panic_key = Some(local_cid.clone());
        let Some(memory) = QuicMemoryLease::try_new(self.control.memory_budget().clone()) else {
            transport_observe::record_error(
                S::NAME,
                "memory_budget",
                Some(peer),
                format!(
                    "Total QUIC connection memory budget is full: {} / {} bytes",
                    self.control.memory_budget().used_bytes(),
                    self.control.memory_budget().limit_bytes()
                ),
            );
            return None;
        };
        let mut transport = self.base_tp.clone();
        transport.original_destination_connection_id = Some(original_dcid);
        transport.retry_source_connection_id = Some(local_cid.clone());
        let conn = Connection::new_server(self.tls.load(), local_cid.clone(), transport);
        self.table.insert(
            dcid,
            local_cid.clone(),
            ConnEntry {
                state: ConnState::Open(S::Conn::from_quic(conn)),
                peer,
                last: now,
                epoch: self.next_epoch,
                inflight: 0,
                memory,
            },
        );
        self.next_epoch = self.next_epoch.wrapping_add(1);
        Some(local_cid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use onetdns_proto::{Name, RecordType};
    use onetdns_tls::ClientConfig;

    use crate::doq::Doq;

    #[test]
    fn initial_admission_requires_rfc_size_and_preserves_fair_share() {
        assert!(!initial_connection_allowed(1199, 0, true));
        assert!(initial_connection_allowed(1200, 0, true));
        assert!(!initial_connection_allowed(1200, MAX_CONNECTIONS, true));
        assert!(!initial_connection_allowed(1200, 0, false));
        assert!(!same_validated_path(
            "127.0.0.1:1000".parse().unwrap(),
            "127.0.0.1:1001".parse().unwrap()
        ));
    }

    #[test]
    /// Sparse table slots must fit in the base charge.
    fn base_charge_covers_sparse_listener_table_slots() {
        let entry = std::mem::size_of::<ConnEntry<Connection>>()
            .max(std::mem::size_of::<ConnEntry<H3Connection>>());
        let connection_slot = std::mem::size_of::<Vec<u8>>()
            .saturating_add(entry)
            .saturating_add(1);
        let alias_slot = std::mem::size_of::<(Vec<u8>, Vec<u8>)>().saturating_add(1);
        let peer_slot = std::mem::size_of::<(IpAddr, usize)>()
            .saturating_add(std::mem::size_of::<(u64, usize)>())
            .saturating_add(2);
        let conservative = connection_slot
            .saturating_add(alias_slot)
            .saturating_add(peer_slot)
            .saturating_mul(4)
            .saturating_add(3 * 64);
        assert!(
            conservative <= crate::quic_memory::QUIC_CONNECTION_BASE_CHARGE,
            "sparse listener tables need {conservative}B per active connection"
        );
    }

    /// Also the destination connection ID the client picks.
    const SERVER_KEY: &[u8] = b"SERVERID";

    fn server_config(alpn: &[u8]) -> Arc<ServerConfig> {
        let (certs, key) = onetdns_transport::self_signed_material("dns.test").unwrap();
        let cfg = ServerConfig::from_pkcs8(certs[0].clone(), &key)
            .expect("ECDSA P-256 서명자")
            .with_alpn(vec![alpn.to_vec()]);
        Arc::new(cfg)
    }

    fn pump(client: &mut Connection, server: &mut Connection) {
        for _ in 0..20 {
            let mut moved = false;
            while let Some(datagram) = client.next_datagram() {
                server.recv_datagram(&datagram).unwrap();
                moved = true;
            }
            while let Some(datagram) = server.next_datagram() {
                client.recv_datagram(&datagram).unwrap();
                moved = true;
            }
            if !moved {
                break;
            }
        }
    }

    /// Skips certificate checks and has sent nothing yet.
    fn client_connection(alpn: &[u8]) -> Connection {
        let client_cfg = ClientConfig {
            server_name: "dns.test".into(),
            verify_name: false,
            roots: None,
            insecure_verifier: Some(
                onetdns_tls::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![alpn.to_vec()],
            ..Default::default()
        };
        Connection::new_client(
            client_cfg,
            SERVER_KEY.to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap()
    }

    fn handshaked_pair(alpn: &[u8]) -> (Connection, Connection) {
        let mut server = Connection::new_server(
            server_config(alpn),
            SERVER_KEY.to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = client_connection(alpn);
        pump(&mut client, &mut server);
        assert!(client.is_handshake_complete() && server.is_handshake_complete());
        (client, server)
    }

    #[derive(Default)]
    /// Answers and closes like DoQ and counts dispatch calls. Its own name keeps its errors out of
    /// the DoQ error counts other tests read.
    struct Probe {
        dispatched: std::cell::Cell<usize>,
    }

    impl QuicService for Probe {
        type Conn = Connection;
        const NAME: &'static str = "quic-probe";
        fn dispatch(&self, _conn: &mut Connection, _intake: &mut Intake<'_>) {
            self.dispatched.set(self.dispatched.get() + 1);
        }
        fn send_answer(
            conn: &mut Connection,
            stream_id: u64,
            wire: Vec<u8>,
            _max_age: u32,
        ) -> Result<(), QuicError> {
            conn.send_dns_message_owned(stream_id, wire)
        }
        fn abandon(conn: &mut Connection, why: Abandon) {
            Doq::abandon(conn, why);
        }
    }

    /// The connection's epoch is 7.
    fn conn_table<S: QuicService<Conn = Connection>>(
        server: Connection,
        peer: SocketAddr,
        budget: Arc<QuicMemoryBudget>,
        inflight: usize,
    ) -> ConnTable<S> {
        let mut table = ConnTable::<S>::new();
        table.insert(
            SERVER_KEY.to_vec(),
            SERVER_KEY.to_vec(),
            ConnEntry {
                state: ConnState::Open(server),
                peer,
                last: Instant::now(),
                epoch: 7,
                inflight,
                memory: QuicMemoryLease::try_new(budget).unwrap(),
            },
        );
        table
    }

    /// Workers never answer the queries they take.
    fn listener_with<S: QuicService>(service: S, table: ConnTable<S>) -> Listener<S> {
        Listener {
            service,
            socket: UdpSocket::bind("127.0.0.1:0").unwrap(),
            tls: Arc::new(onetdns_core::ArcSwap::new(server_config(b"doq"))),
            pool: WorkerPool::new(Arc::new(|_: &QueryJob| None), 1, 1, None).unwrap(),
            wake_source: "127.0.0.1:9".parse().unwrap(),
            drops: Box::new(|_| false),
            control: QuicRunControl::new(
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
                Arc::new(QuicMemoryBudget::default()),
            ),
            table,
            base_tp: TransportParams::server_defaults(),
            retry_key: RetryKey::generate(),
            next_epoch: 0,
            clock: Instant::now(),
        }
    }

    fn close_of(client: &Connection) -> Option<(u64, Option<u64>)> {
        client
            .peer_close()
            .map(|close| (close.error_code, close.frame_type))
    }

    fn delivered_close<C: ServerConn>(
        server: &mut C,
        client: &mut Connection,
    ) -> Option<(u64, Option<u64>)> {
        while let Some(datagram) = server.next_datagram() {
            let _ = client.recv_datagram(&datagram);
        }
        close_of(client)
    }

    fn received_close(socket: &UdpSocket, client: &mut Connection) -> Option<(u64, Option<u64>)> {
        let wait = RecvWait::new(Duration::from_millis(50));
        wait.install(socket).unwrap();
        let mut buf = [0u8; 2048];
        let deadline = Instant::now() + Duration::from_secs(5);
        while client.peer_close().is_none() && Instant::now() < deadline {
            if let Ok((n, _)) = wait.recv_from(socket, &mut buf) {
                let _ = client.recv_datagram(&buf[..n]);
            }
        }
        close_of(client)
    }

    #[test]
    /// Uses a stream that already answered to produce the same error STOP_SENDING causes; that
    /// STOP_SENDING produces it is tested in onetdns-quic.
    fn late_answer_to_a_closed_stream_keeps_the_connection() {
        let (mut client, mut server) = handshaked_pair(b"doq");
        let mut answer = Message::query(0, Name::from_str("late.test").unwrap(), RecordType::A);
        answer.header.response = true;
        let answer = answer.try_encode().unwrap();
        client.send_dns_message(0, &answer).unwrap();
        client.send_dns_message(4, &answer).unwrap();
        pump(&mut client, &mut server);
        assert_eq!(server.take_stream_requests().len(), 2);
        server.send_dns_message(0, &answer).unwrap();
        pump(&mut client, &mut server);
        assert_eq!(client.take_stream_requests().len(), 1);

        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut table = conn_table::<Doq>(
            server,
            client_socket.local_addr().unwrap(),
            Arc::new(QuicMemoryBudget::default()),
            2,
        );
        let mut done: Vec<QueryDone> = [0, 4]
            .into_iter()
            .map(|stream_id| QueryDone {
                conn_key: SERVER_KEY.to_vec(),
                epoch: 7,
                stream_id,
                wire: Some(answer.clone()),
                max_age: 0,
            })
            .collect();
        table.apply_completions(&socket, &mut done, 0);
        let entry = table
            .conns
            .get(SERVER_KEY)
            .expect("끝난 스트림에 실을 수 없는 답 하나 때문에 연결을 버렸습니다");
        assert_eq!(entry.inflight, 0);

        let wait = RecvWait::new(Duration::from_millis(50));
        wait.install(&client_socket).unwrap();
        let mut buf = [0u8; 2048];
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut answered = Vec::new();
        while answered.is_empty() && Instant::now() < deadline {
            if let Ok((n, _)) = wait.recv_from(&client_socket, &mut buf) {
                client.recv_datagram(&buf[..n]).unwrap();
            }
            answered = client.take_stream_requests();
        }
        assert_eq!(
            answered,
            vec![(4, answer)],
            "같은 연결에 실린 다른 질의의 답이 나가야 합니다"
        );
    }

    #[test]
    /// DoQ codes are from RFC 9250, DoH3 codes from RFC 9114; both are application closes, so no
    /// frame type.
    fn abandoned_connections_report_rfc_error_codes() {
        let cases = [
            (Abandon::Shutdown, 0x0, 0x100),
            (Abandon::Internal, 0x1, 0x102),
            (Abandon::ExcessiveLoad, 0x4, 0x107),
        ];
        for (why, doq_code, h3_code) in cases {
            let (mut client, mut server) = handshaked_pair(b"doq");
            Doq::abandon(&mut server, why);
            assert_eq!(
                delivered_close(&mut server, &mut client),
                Some((doq_code, None)),
                "{why:?} 에 맞는 DoQ 오류 코드가 아닙니다"
            );

            let (mut client, server) = handshaked_pair(b"h3");
            let mut server = H3Connection::new(server);
            crate::doh3::Doh3::abandon(&mut server, why);
            assert_eq!(
                delivered_close(&mut server, &mut client),
                Some((h3_code, None)),
                "{why:?} 에 맞는 HTTP/3 오류 코드가 아닙니다"
            );
        }
    }

    #[test]
    fn failed_answer_decides_whether_the_connection_survives() {
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let (_client, mut server) = handshaked_pair(b"doq");
        assert!(connection_survives::<Doq>(
            &mut server,
            peer,
            Err(QuicError::StreamClosed)
        ));
        assert!(
            !server.is_closed(),
            "끝난 스트림 하나 때문에 연결을 닫았습니다"
        );

        for (error, code) in [(QuicError::FlowControl, 0x4), (QuicError::StreamState, 0x1)] {
            let (mut client, mut server) = handshaked_pair(b"doq");
            assert!(!connection_survives::<Doq>(
                &mut server,
                peer,
                Err(error.clone())
            ));
            assert_eq!(
                delivered_close(&mut server, &mut client),
                Some((code, None)),
                "{error:?} 에 맞는 DoQ 오류 코드가 아닙니다"
            );
        }
    }

    #[test]
    fn closed_connection_stays_until_its_closing_period_ends() {
        let (_client, mut server) = handshaked_pair(b"doq");
        Doq::abandon(&mut server, Abandon::Internal);
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let budget = Arc::new(QuicMemoryBudget::default());
        let mut table = conn_table::<Doq>(
            server,
            client_socket.local_addr().unwrap(),
            budget.clone(),
            0,
        );

        table.drive_timeouts(&socket, 0);
        let entry = table
            .conns
            .get(SERVER_KEY)
            .expect("closing 기간이 끝나기 전에 연결을 버렸습니다");
        assert!(
            matches!(entry.state, ConnState::Closing(_)),
            "닫힌 연결의 키와 버퍼를 closing 기간에도 쥐고 있습니다"
        );
        assert!(
            budget.used_bytes()
                <= crate::quic_memory::QUIC_CONNECTION_BASE_CHARGE
                    + onetdns_quic::MAX_RECV_UDP_PAYLOAD as usize,
            "closing 기간의 연결이 종료 데이터그램보다 많은 몫을 쥐고 있습니다: {}",
            budget.used_bytes()
        );

        table.drive_timeouts(&socket, 60_000);
        assert!(
            table.conns.is_empty(),
            "closing 기간이 끝난 연결이 남았습니다"
        );
        assert!(table.aliases.is_empty() && table.clients.is_empty());
        assert_eq!(budget.used_bytes(), 0, "버린 연결의 메모리 몫이 남았습니다");
    }

    #[test]
    fn late_answer_to_a_closed_connection_keeps_its_closing_period() {
        let (_client, mut server) = handshaked_pair(b"doq");
        Doq::abandon(&mut server, Abandon::Internal);
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut table = conn_table::<Probe>(
            server,
            client_socket.local_addr().unwrap(),
            Arc::new(QuicMemoryBudget::default()),
            1,
        );
        let mut answer = Message::query(0, Name::from_str("late.test").unwrap(), RecordType::A);
        answer.header.response = true;
        let mut done = vec![QueryDone {
            conn_key: SERVER_KEY.to_vec(),
            epoch: 7,
            stream_id: 0,
            wire: Some(answer.try_encode().unwrap()),
            max_age: 0,
        }];
        table.apply_completions(&socket, &mut done, 0);
        let entry = table
            .conns
            .get(SERVER_KEY)
            .expect("늦은 응답 때문에 closing 기간이 끝나기 전에 연결을 버렸습니다");
        assert_eq!(entry.inflight, 0);
        assert_eq!(
            transport_observe::count(Probe::NAME, "send_response"),
            0,
            "닫힌 연결에 응답을 실으려 했습니다"
        );
    }

    #[test]
    /// A client that lost the first close learns of it only from this repeat.
    fn late_packet_to_a_closing_connection_gets_the_close_again() {
        let (mut client, mut server) = handshaked_pair(b"doq");
        Doq::abandon(&mut server, Abandon::Internal);
        while server.next_datagram().is_some() {}

        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = client_socket.local_addr().unwrap();
        let mut listener = listener_with(
            Probe::default(),
            conn_table(server, peer, Arc::new(QuicMemoryBudget::default()), 0),
        );
        let query = Message::query(0, Name::from_str("late.test").unwrap(), RecordType::A)
            .try_encode()
            .unwrap();
        client.send_dns_message(0, &query).unwrap();
        while let Some(datagram) = client.next_datagram() {
            listener.on_datagram(&datagram, peer, &mut None);
        }

        assert!(
            listener.table.conns.contains_key(SERVER_KEY),
            "closing 기간 중인 연결을 버렸습니다"
        );
        assert_eq!(
            listener.service.dispatched.get(),
            0,
            "닫힌 연결에 실려 온 질의를 서비스에 넘겼습니다"
        );
        assert_eq!(
            received_close(&client_socket, &mut client),
            Some((0x1, None)),
            "늦게 온 패킷에 종료를 다시 알리지 않았습니다"
        );
    }

    /// `None` after 5 s.
    fn next_datagram_on(socket: &UdpSocket) -> Option<Vec<u8>> {
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buf = [0u8; 2048];
        socket
            .recv_from(&mut buf)
            .ok()
            .map(|(n, _)| buf[..n].to_vec())
    }

    #[test]
    fn memory_budget_overrun_keeps_only_the_closing_period() {
        let (mut client, server) = handshaked_pair(b"doq");
        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = client_socket.local_addr().unwrap();
        let budget = Arc::new(QuicMemoryBudget::new(
            crate::quic_memory::QUIC_CONNECTION_BASE_CHARGE,
        ));
        let mut listener = listener_with(
            Probe::default(),
            conn_table(server, peer, budget.clone(), 0),
        );

        listener.table.drive_timeouts(&listener.socket, 0);
        let close = next_datagram_on(&client_socket).expect("과부하를 알리지 않았습니다");
        let _ = client.recv_datagram(&close);
        assert_eq!(
            close_of(&client),
            Some((0x4, None)),
            "과부하 코드가 아닙니다"
        );
        let entry = listener
            .table
            .conns
            .get(SERVER_KEY)
            .expect("closing 기간이 끝나기 전에 연결을 버렸습니다");
        assert!(
            matches!(entry.state, ConnState::Closing(_)),
            "예산이 거절한 버퍼를 closing 기간에도 쥐고 있습니다"
        );

        let mut late = vec![0x40];
        late.extend_from_slice(SERVER_KEY);
        late.resize(100, 0);
        listener.on_datagram(&late, peer, &mut None);
        assert_eq!(
            next_datagram_on(&client_socket),
            Some(close),
            "늦게 온 패킷에 종료를 다시 알리지 않았습니다"
        );

        listener.table.drive_timeouts(&listener.socket, 60_000);
        assert!(
            listener.table.conns.is_empty(),
            "closing 기간이 끝난 연결이 남았습니다"
        );
        assert_eq!(budget.used_bytes(), 0, "버린 연결의 메모리 몫이 남았습니다");
    }

    /// On loopback anything sent arrives at once.
    fn stays_silent(socket: &UdpSocket) -> bool {
        socket
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let mut buf = [0u8; 2048];
        socket.recv_from(&mut buf).is_err()
    }

    #[test]
    /// A Retry or ACK would reveal that a server is there.
    fn dropped_peer_gets_no_datagram_and_loses_its_connection() {
        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = client_socket.local_addr().unwrap();
        let initial = client_connection(b"doq")
            .next_datagram()
            .expect("클라이언트가 첫 패킷을 만들지 않았습니다");

        let mut listener = listener_with(Probe::default(), ConnTable::new());
        listener.on_datagram(&initial, peer, &mut None);
        assert!(
            next_datagram_on(&client_socket).is_some(),
            "대조군이 무효입니다. 버리지 않는 주소의 첫 패킷에 Retry 가 나가지 않았습니다"
        );
        listener.drops = Box::new(|source| source.is_loopback());
        listener.on_datagram(&initial, peer, &mut None);
        assert!(
            stays_silent(&client_socket),
            "버리는 주소의 첫 패킷에 답했습니다"
        );

        let (mut client, server) = handshaked_pair(b"doq");
        let mut listener = listener_with(
            Probe::default(),
            conn_table(server, peer, Arc::new(QuicMemoryBudget::default()), 0),
        );
        listener.drops = Box::new(|source| source.is_loopback());
        let query = Message::query(0, Name::from_str("drop.test").unwrap(), RecordType::A)
            .try_encode()
            .unwrap();
        client.send_dns_message(0, &query).unwrap();
        while let Some(datagram) = client.next_datagram() {
            listener.on_datagram(&datagram, peer, &mut None);
        }
        assert!(
            stays_silent(&client_socket),
            "버리는 주소의 열린 연결에 답했습니다"
        );
        assert_eq!(
            listener.service.dispatched.get(),
            0,
            "버리는 주소의 질의를 서비스에 넘겼습니다"
        );
        assert!(
            listener.table.conns.is_empty(),
            "버리는 주소에 열려 있던 연결이 남았습니다"
        );
    }

    #[test]
    fn an_ipv6_prefix_shares_one_connection_budget() {
        let budget = Arc::new(QuicMemoryBudget::default());
        let (_first_client, first) = handshaked_pair(b"doq");
        let mut table = conn_table::<Probe>(
            first,
            "[2001:db8::1]:4433".parse().unwrap(),
            budget.clone(),
            0,
        );
        let (_second_client, second) = handshaked_pair(b"doq");
        table.insert(
            b"second".to_vec(),
            b"second".to_vec(),
            ConnEntry {
                state: ConnState::Open(second),
                peer: "[2001:db8::2]:4433".parse().unwrap(),
                last: Instant::now(),
                epoch: 7,
                inflight: 0,
                memory: QuicMemoryLease::try_new(budget).unwrap(),
            },
        );
        table.clients = ClientCounts::new(1, 4);
        for entry in table.conns.values() {
            table.clients.add(entry.peer.ip());
        }
        assert!(
            !table.clients.allows("2001:db8::ffff:3".parse().unwrap()),
            "같은 /64 의 다른 주소로 절반을 넘겨 받으면 안 됩니다"
        );
        assert!(table.clients.allows("2001:db8:0:1::1".parse().unwrap()));
        table.remove(b"second");
        assert!(table.clients.allows("2001:db8::ffff:3".parse().unwrap()));
    }
}
