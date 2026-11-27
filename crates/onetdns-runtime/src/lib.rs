//! Thread-per-core Do53 server runtime without an async executor. Each worker owns its socket and
//! makes blocking system calls, so there is no work stealing or task scheduling; DNS queries are
//! short and uniform, and this fills the cores without executor overhead.
//!
//! On Linux each worker group opens its own socket with SO_REUSEPORT and the kernel spreads queries
//! across them; other platforms share one socket.

pub mod proxy;
mod sys;
mod tcp;
mod udp;

pub use udp::encode_limited;
pub use udp::encode_within;
pub use udp::recv_batch_counters;
pub use udp::NON_EDNS_UDP_MAX;

pub use sys::{bind_tcp, bind_udp};

use std::io;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use onetdns_core::IpNet;

pub use onetdns_proto::Message;

/// Minimal SERVFAIL for when the response cannot be encoded, used only at the transport boundary.
/// Staying silent would leave the client waiting for its timeout. It has no question section, so
/// encoding always succeeds.
fn encoding_failure_response(request: &Message) -> Message {
    let mut response = Message::default();
    response.header.id = request.header.id;
    response.header.response = true;
    response.header.opcode = request.header.opcode;
    response.header.recursion_desired = request.header.recursion_desired;
    response.header.checking_disabled = request.header.checking_disabled;
    response.header.rcode = onetdns_proto::ResponseCode::ServFail.0;
    response
}

/// Not the same type as `onetdns_core::client::Transport`, despite the name; neither re-exports the
/// other and callers convert at the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Do53Udp,
    Do53Tcp,
    DoT,
    DoH,
    DoH3,
    DoQ,
    DnsCrypt,
}

impl Transport {
    pub fn is_plain_do53(self) -> bool {
        matches!(self, Transport::Do53Udp | Transport::Do53Tcp)
    }

    pub fn is_encrypted(self) -> bool {
        !self.is_plain_do53()
    }

    /// Only stream transports: a transfer does not fit one UDP response, and DoH and DoQ framing
    /// assumes one response per query.
    pub fn supports_xfr(self) -> bool {
        matches!(self, Transport::Do53Tcp | Transport::DoT)
    }

    pub fn name(self) -> &'static str {
        match self {
            Transport::Do53Udp => "do53-udp",
            Transport::Do53Tcp => "do53-tcp",
            Transport::DoT => "dot",
            Transport::DoH => "doh",
            Transport::DoH3 => "doh3",
            Transport::DoQ => "doq",
            Transport::DnsCrypt => "dnscrypt",
        }
    }
}

/// Transport details a handler learned from its protocol, passed to the shared pipeline.
#[derive(Debug, Clone)]
pub struct RequestCtx<'a> {
    /// Replaced by the original client address after the PROXY protocol.
    pub src: SocketAddr,
    pub transport: Transport,

    /// The wire bytes before parsing, for paths that need them.
    pub raw: Option<&'a [u8]>,

    /// From a DoH path suffix and similar.
    pub client_id: Option<String>,

    pub authenticated: bool,

    /// Display name of the verified identity, such as a client certificate subject.
    pub auth_identity: Option<String>,
}

impl RequestCtx<'_> {
    pub fn new(src: SocketAddr, transport: Transport) -> Self {
        RequestCtx {
            src,
            transport,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireDisposition {
    /// Parse and take the normal path.
    Fallback,

    /// The output buffer holds a complete response.
    Respond,

    /// Send nothing: rate limiting or policy chose silence.
    Drop,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReactorDisposition {
    Respond,

    Drop,

    /// Handed upstream; the response comes from a later poll.
    Submitted,

    /// The reactor cannot handle it; take the synchronous path.
    Fallback,
}

/// Every default method means "this optimisation is not used", so an implementation only needs
/// `handle`; the fast path and reactor methods are optional overrides.
pub trait Handler: Send + Sync + 'static {
    /// `None` sends no response.
    fn handle(&self, request: &Message, ctx: &RequestCtx<'_>) -> Option<Message>;

    /// Tries to answer a UDP packet without parsing it: a cache hit goes out without parsing,
    /// response assembly or name compression, patching only the transaction ID, query name case and
    /// TTLs of the stored wire.
    fn handle_udp_wire(
        &self,
        _packet: &[u8],
        _ctx: &RequestCtx<'_>,
        _out: &mut onetdns_proto::Writer,
        _now: std::time::Instant,
    ) -> WireDisposition {
        WireDisposition::Fallback
    }

    fn handle_tcp_wire(
        &self,
        _packet: &[u8],
        _ctx: &RequestCtx<'_>,
        _out: &mut onetdns_proto::Writer,
        _now: std::time::Instant,
    ) -> WireDisposition {
        WireDisposition::Fallback
    }

    /// Used by zone transfers.
    fn handle_multi(&self, request: &Message, ctx: &RequestCtx<'_>) -> Option<Vec<Message>> {
        self.handle(request, ctx).map(|m| vec![m])
    }

    /// Dropping the packet leaves the client waiting until its deadline and retrying; RFC 8906 asks
    /// for a response code even to queries we do not understand. This runs before parsing, so the
    /// normal path's access control and rate limiting have not run; implementations must check
    /// both. `packet` has at least the 12-byte header and QR 0.
    fn handle_unparsable(&self, _packet: &[u8], _ctx: &RequestCtx<'_>) -> Option<Message> {
        None
    }

    /// A UDP worker calls this before it handles a round of datagrams and `end_round` once their
    /// responses are sent, so work the responses do not need, such as queuing query log entries,
    /// does not delay them.
    fn begin_round(&self) {}

    fn end_round(&self) {}

    /// UDP workers of a reactor server ask this on every loop and switch between the reactor and
    /// the synchronous loop when it changes. When it turns false the worker leaves the reactor loop
    /// and stops advancing its exchanges, so it must stay true while this thread still owns
    /// exchanges. The synchronous loop calls it on every receive, so keep it cheap.
    #[cfg(unix)]
    fn reactor_active(&self) -> bool {
        false
    }

    /// Unlike `handle_udp_wire`, a miss does not fall back to synchronous resolution: in the
    /// reactor a miss is submitted instead.
    #[cfg(unix)]
    fn handle_udp_wire_hit(
        &self,
        _packet: &[u8],
        _ctx: &RequestCtx<'_>,
        _out: &mut onetdns_proto::Writer,
        _now: std::time::Instant,
    ) -> WireDisposition {
        WireDisposition::Fallback
    }

    /// `Submitted` means the response comes from a later `reactor_pump`; `Fallback` when no slot is
    /// free.
    #[cfg(unix)]
    fn reactor_submit(
        &self,
        _packet: &[u8],
        _ctx: &RequestCtx<'_>,
        _out: &mut onetdns_proto::Writer,
        _now: std::time::Instant,
    ) -> ReactorDisposition {
        ReactorDisposition::Fallback
    }

    /// Adds the descriptors of exchanges in progress to the poll set; `map` records which exchange
    /// each descriptor belongs to.
    #[cfg(unix)]
    fn reactor_collect(&self, _fds: &mut Vec<libc::pollfd>, _map: &mut Vec<usize>) {}

    /// Collects completed responses from the poll results. `base` is where this handler's
    /// descriptors start in `fds`.
    #[cfg(unix)]
    fn reactor_pump(
        &self,
        _fds: &[libc::pollfd],
        _base: usize,
        _map: &[usize],
        _now: std::time::Instant,
        _out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) {
    }

    /// Retries and timeouts; called regardless of the poll results.
    #[cfg(unix)]
    fn reactor_tick(
        &self,
        _now: std::time::Instant,
        _out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) {
    }

    /// Derived from the earliest retry or timeout: too long misses it, too short wakes up for
    /// nothing.
    #[cfg(unix)]
    fn reactor_deadline_ms(&self, _now: std::time::Instant) -> i32 {
        50
    }

    #[cfg(unix)]
    fn reactor_has_capacity(&self) -> bool {
        false
    }

    /// Streams responses one at a time for stream transports. Stops as soon as `emit` returns
    /// false; returns true when every response went out.
    fn handle_stream(
        &self,
        request: &Message,
        ctx: &RequestCtx<'_>,
        emit: &mut dyn FnMut(&Message) -> bool,
    ) -> bool {
        let Some(responses) = self.handle_multi(request, ctx) else {
            return false;
        };
        if responses.is_empty() {
            return false;
        }
        responses.iter().all(emit)
    }

    /// Sends wire that is already encoded, such as a zone transfer, without re-encoding. `None`
    /// when this path is not used; the caller then takes the normal stream path.
    fn handle_preencoded_stream(
        &self,
        _request: &Message,
        _ctx: &RequestCtx<'_>,
        _out: &mut onetdns_proto::Writer,
        _emit: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Option<bool> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub udp: bool,

    pub tcp: bool,

    /// Zero derives the count from the cores.
    pub udp_workers: usize,

    /// Zero derives the count from the cores.
    pub tcp_acceptors: usize,

    /// Keeps cache locality but stops the scheduler from moving workers.
    pub pin_cores: bool,

    /// How often workers check for shutdown and reload: responsiveness against idle wake-ups.
    /// Windows UDP workers do not wake on it; see `onetdns_core::udp::shared_read_timeout`.
    pub poll_interval: Duration,

    /// Only meaningful on Unix.
    pub udp_reactor: bool,

    pub proxy_protocol: bool,

    /// With PROXY on and this empty, anyone can forge the source address and the ACL means nothing.
    pub trusted_proxies: Vec<IpNet>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            udp: true,
            tcp: true,
            udp_workers: 0,
            tcp_acceptors: 0,
            pin_cores: true,
            poll_interval: Duration::from_millis(500),
            udp_reactor: false,
            proxy_protocol: false,
            trusted_proxies: Vec::new(),
        }
    }
}

/// The distinct listening sockets of one address, without the per-worker duplicates: what
/// `bind_udp` and `bind_tcp` open, and what is handed to the process that replaces this one.
#[derive(Debug, Default)]
pub struct ServerSockets {
    pub udp: Vec<UdpSocket>,
    pub tcp: Vec<TcpListener>,
}

impl ServerSockets {
    /// Fails when a socket cannot be duplicated, which happens only when the process is out of
    /// descriptors.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            udp: self
                .udp
                .iter()
                .map(UdpSocket::try_clone)
                .collect::<io::Result<_>>()?,
            tcp: self
                .tcp
                .iter()
                .map(TcpListener::try_clone)
                .collect::<io::Result<_>>()?,
        })
    }
}

/// Stops and joins its workers when dropped.
pub struct Server {
    stop: tcp::ConnectionStop,
    workers: Workers,
    udp_addr: Option<SocketAddr>,
    tcp_addr: Option<SocketAddr>,
    /// Kept so `sockets` can hand them on; dropped after the workers have stopped.
    sockets: ServerSockets,
}

impl Server {
    /// Binds every socket before starting any thread: in the other order, a failure after partial
    /// success would leave started workers holding ports as ghost listeners. Sockets opened before
    /// a bind failure are closed.
    pub fn bind<H: Handler>(
        addr: SocketAddr,
        handler: Arc<H>,
        cfg: ServerConfig,
    ) -> io::Result<Server> {
        let sockets = ServerSockets {
            udp: if cfg.udp {
                sys::bind_udp(addr, sys::worker_count(cfg.udp_workers))?
            } else {
                Vec::new()
            },
            tcp: if cfg.tcp {
                sys::bind_tcp(addr, sys::worker_count(cfg.tcp_acceptors))?
            } else {
                Vec::new()
            },
        };
        Self::serve(sockets, handler, cfg)
    }

    /// Serves sockets that are already open, such as ones handed over by the process this one
    /// replaces. Each protocol is served when it has a socket, whatever `cfg.udp` and `cfg.tcp`
    /// say. On Linux, one reuseport group of TCP sockets gets one acceptor per socket.
    pub fn serve<H: Handler>(
        sockets: ServerSockets,
        handler: Arc<H>,
        mut cfg: ServerConfig,
    ) -> io::Result<Server> {
        let udp_workers = sys::worker_count(cfg.udp_workers);
        let tcp_acceptors = sys::worker_count(cfg.tcp_acceptors);
        cfg.poll_interval = sys::poll_interval(cfg.poll_interval);
        let stop = tcp::ConnectionStop::default();

        let udp_socks = if sockets.udp.is_empty() {
            None
        } else {
            Some(sys::fan_out_udp(&sockets.udp, udp_workers)?)
        };
        let tcp_listeners = if sockets.tcp.is_empty() {
            None
        } else {
            Some(sys::acceptor_sockets(&sockets.tcp, tcp_acceptors)?)
        };

        let mut workers = Workers::default();
        let mut udp_addr = None;
        let mut tcp_addr = None;
        if let Err(e) = Self::start_workers(
            &mut workers,
            &mut udp_addr,
            &mut tcp_addr,
            udp_socks,
            tcp_listeners,
            &handler,
            &cfg,
            &stop,
        ) {
            workers.stop(&stop, udp_addr);
            return Err(e);
        }

        Ok(Server {
            stop,
            workers,
            udp_addr,
            tcp_addr,
            sockets,
        })
    }

    /// If spawning fails midway, the caller signals shutdown and joins the threads started so far;
    /// no thread may survive a failure. Overlapped processing gets a larger stack, since every
    /// request in flight adds frames.
    ///
    /// TCP connection threads and the queue size follow the requested acceptor count, not the
    /// number of listening sockets, so platforms with a single listening socket such as Windows
    /// keep the same connection capacity.
    #[allow(clippy::too_many_arguments)]
    fn start_workers<H: Handler>(
        workers: &mut Workers,
        udp_addr: &mut Option<SocketAddr>,
        tcp_addr: &mut Option<SocketAddr>,
        udp_socks: Option<Vec<std::net::UdpSocket>>,
        tcp_listeners: Option<Vec<std::net::TcpListener>>,
        handler: &Arc<H>,
        cfg: &ServerConfig,
        stop: &tcp::ConnectionStop,
    ) -> io::Result<()> {
        if let Some(socks) = udp_socks {
            *udp_addr = Some(socks[0].local_addr()?);
            let batch_size = udp::worker_batch_size(socks.len());
            for (i, sock) in socks.into_iter().enumerate() {
                sock.set_read_timeout(onetdns_core::udp::shared_read_timeout(cfg.poll_interval))?;
                let h = handler.clone();
                let sd = stop.shutdown.clone();
                let pin = cfg.pin_cores;
                let reactor = cfg.udp_reactor;
                let builder = std::thread::Builder::new().name(format!("onetdns-udp-{i}"));
                workers.udp.push(builder.spawn(move || {
                    if pin {
                        sys::pin_to_core(i);
                    }
                    udp::worker(sock, h, sd, batch_size, reactor);
                })?);
            }
        }

        if let Some(listeners) = tcp_listeners {
            *tcp_addr = Some(listeners[0].local_addr()?);
            let acceptors = sys::worker_count(cfg.tcp_acceptors);
            let connection_workers = tcp::connection_worker_count(acceptors);
            let queue_capacity = tcp::connection_queue_capacity(acceptors);
            let limiter =
                tcp::connection_limiter(connection_workers, queue_capacity, cfg.proxy_protocol);
            let trusted_proxies = Arc::new(cfg.trusted_proxies.clone());
            let (connections, connection_handles) = tcp::spawn_connection_workers(
                handler.clone(),
                stop.clone(),
                tcp::ConnectionPoolConfig {
                    poll: cfg.poll_interval,
                    proxy_protocol: cfg.proxy_protocol,
                    trusted_proxies,
                    workers: connection_workers,
                    queue_capacity,
                    pin_cores: cfg.pin_cores,
                    pin_span: acceptors,
                },
            )?;
            workers.connections.extend(connection_handles);
            for (i, listener) in listeners.into_iter().enumerate() {
                let sd = stop.shutdown.clone();
                let pin = cfg.pin_cores;
                let poll = cfg.poll_interval;
                let limiter = limiter.clone();
                let connections = connections.clone();
                workers.acceptors.push(
                    std::thread::Builder::new()
                        .name(format!("onetdns-tcp-{i}"))
                        .spawn(move || {
                            if pin {
                                sys::pin_to_core(i);
                            }
                            tcp::accept_worker(listener, sd, poll, limiter, connections);
                        })?,
                );
            }
        }
        Ok(())
    }

    /// For finding the port when bound to port 0.
    pub fn udp_addr(&self) -> Option<SocketAddr> {
        self.udp_addr
    }

    pub fn tcp_addr(&self) -> Option<SocketAddr> {
        self.tcp_addr
    }

    /// Duplicates of the listening sockets. They stay open after this server stops, so another
    /// server, in this process or the next, can keep answering on them.
    pub fn sockets(&self) -> io::Result<ServerSockets> {
        self.sockets.try_clone()
    }

    /// Stops reading the listening sockets and closes this server's handles to them, returning
    /// once no worker reads them. TCP connections already accepted are served until the server is
    /// dropped.
    pub fn stop_reading(&mut self) {
        report_panicked(self.workers.stop_reading(&self.stop, self.udp_addr));
        self.sockets = ServerSockets::default();
    }

    /// Joining is required: otherwise a worker still alive holds the port when the next generation
    /// binds it.
    fn stop(&mut self) {
        report_panicked(self.workers.stop(&self.stop, self.udp_addr));
    }

    pub fn shutdown(mut self) {
        self.stop();
    }
}

fn report_panicked(workers: usize) {
    if workers > 0 {
        onetdns_core::error!(event = "server.worker_panicked", workers, "A query worker thread exited outside a request boundary; running with that many fewer threads meanwhile");
    }
}

#[derive(Default)]
struct Workers {
    udp: Vec<JoinHandle<()>>,
    acceptors: Vec<JoinHandle<()>>,
    connections: Vec<JoinHandle<()>>,
    /// When the listening sockets stopped being read.
    draining_since: Option<Instant>,
}

impl Workers {
    /// Joins the workers that read the listening sockets. Returns how many ended outside a request
    /// boundary.
    fn stop_reading(&mut self, stop: &tcp::ConnectionStop, udp_addr: Option<SocketAddr>) -> usize {
        stop.shutdown.store(true, Ordering::SeqCst);
        self.draining_since.get_or_insert_with(Instant::now);
        if onetdns_core::udp::shared_read_timeout(Duration::ZERO).is_none() {
            if let Some(addr) = udp_addr {
                wake_udp_workers(&self.udp, addr);
            }
        }
        joined_with_panic(self.udp.drain(..).chain(self.acceptors.drain(..)))
    }

    /// TCP connections already accepted, queued ones included, answer what they receive until
    /// idle, and are closed DRAIN_LIMIT after the listening sockets stopped being read.
    fn stop(&mut self, stop: &tcp::ConnectionStop, udp_addr: Option<SocketAddr>) -> usize {
        let panicked = self.stop_reading(stop, udp_addr);
        let deadline =
            self.draining_since.unwrap_or_else(Instant::now) + onetdns_core::tcp::DRAIN_LIMIT;
        while Instant::now() < deadline && self.connections.iter().any(|w| !w.is_finished()) {
            std::thread::sleep(Duration::from_millis(10));
        }
        stop.abort.store(true, Ordering::SeqCst);
        panicked + joined_with_panic(self.connections.drain(..))
    }
}

fn joined_with_panic(workers: impl Iterator<Item = JoinHandle<()>>) -> usize {
    workers.map(JoinHandle::join).filter(Result::is_err).count()
}

fn wake_udp_workers(handles: &[JoinHandle<()>], addr: SocketAddr) {
    let running = || {
        handles
            .iter()
            .filter(|handle| !handle.is_finished())
            .count()
    };
    if onetdns_core::udp::wake_readers(addr, running).is_err() {
        onetdns_core::error!(event = "server.udp_wake_failed", %addr, "Could not open the socket used to wake UDP workers; shutdown waits until each worker receives its next query");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use onetdns_proto::{Name, RData, Record, RecordType, ResponseCode, Writer};
    use std::collections::HashSet;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpStream, UdpSocket};
    use std::sync::atomic::AtomicUsize;
    use std::sync::{mpsc, Mutex};
    use std::time::Instant;

    struct EchoA {
        threads: Mutex<HashSet<std::thread::ThreadId>>,
    }

    impl EchoA {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                threads: Mutex::new(HashSet::new()),
            })
        }
    }

    impl Handler for EchoA {
        fn handle(&self, request: &Message, _ctx: &RequestCtx) -> Option<Message> {
            self.threads
                .lock()
                .unwrap()
                .insert(std::thread::current().id());
            let q = request.questions.first()?;
            let mut resp = Message::default();
            resp.header.id = request.header.id;
            resp.header.response = true;
            resp.header.recursion_desired = request.header.recursion_desired;
            resp.header.recursion_available = true;
            resp.header.rcode = ResponseCode::NoError.0;
            resp.questions = request.questions.clone();
            if q.qtype == RecordType::A {
                resp.answers.push(Record::new(
                    q.name.clone(),
                    300,
                    RData::A(Ipv4Addr::new(1, 2, 3, 4)),
                ));
            }
            Some(resp)
        }
    }

    struct TcpWireOnly {
        slow_calls: AtomicUsize,
    }

    impl Handler for TcpWireOnly {
        fn handle(&self, _request: &Message, _ctx: &RequestCtx) -> Option<Message> {
            self.slow_calls.fetch_add(1, Ordering::Relaxed);
            None
        }

        fn handle_tcp_wire(
            &self,
            packet: &[u8],
            ctx: &RequestCtx<'_>,
            out: &mut Writer,
            _now: Instant,
        ) -> WireDisposition {
            assert_eq!(ctx.transport, Transport::Do53Tcp);
            out.clear();
            out.push_bytes(packet);
            out.buf[2] |= 0x80;
            WireDisposition::Respond
        }
    }

    fn test_cfg() -> ServerConfig {
        ServerConfig {
            udp_workers: 1,
            tcp_acceptors: 1,
            pin_cores: false,
            poll_interval: Duration::from_millis(100),
            ..Default::default()
        }
    }

    fn local(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn query_bytes(id: u16, name: &str) -> Vec<u8> {
        Message::query(id, Name::from_str(name).unwrap(), RecordType::A)
            .try_encode()
            .unwrap()
    }

    struct WaitsForTheClientInEndRound {
        client_got_response: Mutex<mpsc::Receiver<()>>,
        first_round: Mutex<Option<bool>>,
    }

    impl Handler for WaitsForTheClientInEndRound {
        fn handle(&self, request: &Message, ctx: &RequestCtx) -> Option<Message> {
            EchoA::new().handle(request, ctx)
        }

        fn end_round(&self) {
            let mut first = self.first_round.lock().unwrap();
            if first.is_none() {
                let got = self
                    .client_got_response
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(2));
                *first = Some(got.is_ok());
            }
        }
    }

    #[test]
    fn udp_worker_sends_the_responses_before_ending_the_round() {
        let (got_response, client_got_response) = mpsc::channel();
        let handler = Arc::new(WaitsForTheClientInEndRound {
            client_got_response: Mutex::new(client_got_response),
            first_round: Mutex::new(None),
        });
        let server = Server::bind(local(0), handler.clone(), test_cfg()).unwrap();
        let client = UdpSocket::bind(local(0)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client
            .send_to(
                &query_bytes(0x5151, "a.example.com"),
                server.udp_addr().unwrap(),
            )
            .unwrap();
        let mut buf = [0u8; 512];
        client
            .recv_from(&mut buf)
            .expect("end_round ran before the response was sent");
        got_response.send(()).unwrap();

        let deadline = Instant::now() + Duration::from_secs(3);
        while handler.first_round.lock().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(*handler.first_round.lock().unwrap(), Some(true));
        server.shutdown();
    }

    #[test]
    fn udp_roundtrip() {
        let server = Server::bind(local(0), EchoA::new(), test_cfg()).unwrap();
        let addr = server.udp_addr().unwrap();

        let client = UdpSocket::bind(local(0)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client
            .send_to(&query_bytes(0x4242, "a.example.com"), addr)
            .unwrap();

        let mut buf = [0u8; 4096];
        let (n, _) = client.recv_from(&mut buf).unwrap();
        let resp = Message::parse(&buf[..n]).unwrap();

        assert_eq!(resp.header.id, 0x4242);
        assert!(resp.header.response);
        assert_eq!(resp.questions.len(), 1);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].rdata {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(1, 2, 3, 4)),
            other => panic!("A 레코드를 예상했지만 실제 값은 {other:?}입니다"),
        }
        server.shutdown();
    }

    #[test]
    /// Answering would make this server a reflection platform.
    fn udp_silently_drops_unsolicited_dns_responses() {
        let mut cfg = test_cfg();
        cfg.tcp = false;
        let handler = EchoA::new();
        let server = Server::bind(local(0), handler.clone(), cfg).unwrap();
        let addr = server.udp_addr().unwrap();

        let client = UdpSocket::bind(local(0)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        let mut unsolicited = Message::query(
            0x5151,
            Name::from_str("loop.example").unwrap(),
            RecordType::A,
        );
        unsolicited.header.response = true;
        client
            .send_to(&unsolicited.try_encode().unwrap(), addr)
            .unwrap();

        let error = client.recv_from(&mut [0u8; 512]).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
        assert!(handler.threads.lock().unwrap().is_empty());
        server.shutdown();
    }

    struct PanicOnFirstRequest {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl Handler for PanicOnFirstRequest {
        fn handle(&self, request: &Message, ctx: &RequestCtx) -> Option<Message> {
            if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
                panic!("simulated malicious request");
            }
            EchoA::new().handle(request, ctx)
        }
    }

    #[test]
    fn udp_worker_survives_panicking_request_and_serves_next_client() {
        let mut cfg = test_cfg();
        cfg.udp_workers = 1;
        cfg.tcp = false;
        let handler = Arc::new(PanicOnFirstRequest {
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let server = Server::bind(local(0), handler.clone(), cfg).unwrap();
        let address = server.udp_addr().unwrap();
        let faulting_client = UdpSocket::bind(local(0)).unwrap();
        faulting_client
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let healthy_client = UdpSocket::bind(local(0)).unwrap();
        healthy_client
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();

        faulting_client
            .send_to(&query_bytes(1, "panic.example"), address)
            .unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while handler.calls.load(Ordering::Acquire) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "패닉 요청이 처리되지 않았습니다"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(handler.calls.load(Ordering::Acquire), 1);
        let started = std::time::Instant::now();
        healthy_client
            .send_to(&query_bytes(2, "healthy.example"), address)
            .unwrap();
        let mut wire = [0u8; 512];
        let (length, _) = healthy_client.recv_from(&mut wire).unwrap();
        let response = Message::parse(&wire[..length]).unwrap();
        assert_eq!(response.header.id, 2);
        assert_eq!(response.answers.len(), 1);
        assert!(started.elapsed() < Duration::from_millis(250));

        let error = faulting_client.recv_from(&mut [0u8; 512]).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
        server.shutdown();
    }

    #[cfg(unix)]
    struct SwitchingReactor {
        active: std::sync::atomic::AtomicBool,
        asked: AtomicUsize,
        submitted: AtomicUsize,
        handled: AtomicUsize,
    }

    #[cfg(unix)]
    impl Handler for SwitchingReactor {
        fn handle(&self, request: &Message, _ctx: &RequestCtx) -> Option<Message> {
            self.handled.fetch_add(1, Ordering::SeqCst);
            let mut resp = Message::default();
            resp.header.id = request.header.id;
            resp.header.response = true;
            resp.questions = request.questions.clone();
            Some(resp)
        }

        fn reactor_active(&self) -> bool {
            self.asked.fetch_add(1, Ordering::SeqCst);
            self.active.load(Ordering::SeqCst)
        }

        fn reactor_has_capacity(&self) -> bool {
            true
        }

        fn reactor_submit(
            &self,
            packet: &[u8],
            _ctx: &RequestCtx<'_>,
            out: &mut Writer,
            _now: Instant,
        ) -> ReactorDisposition {
            self.submitted.fetch_add(1, Ordering::SeqCst);
            out.clear();
            out.push_bytes(packet);
            out.buf[2] |= 0x80;
            ReactorDisposition::Respond
        }
    }

    #[cfg(unix)]
    #[test]
    /// Reactor use changes when the config is replaced: reading it once at thread start would keep
    /// queries away from a reactor turned on later. Going back to the synchronous loop without
    /// making the socket blocking again would make receives spin.
    fn udp_worker_follows_the_reactor_switch_at_runtime() {
        let handler = Arc::new(SwitchingReactor {
            active: std::sync::atomic::AtomicBool::new(false),
            asked: AtomicUsize::new(0),
            submitted: AtomicUsize::new(0),
            handled: AtomicUsize::new(0),
        });
        let mut cfg = test_cfg();
        cfg.tcp = false;
        cfg.udp_reactor = true;
        let server = Server::bind(local(0), handler.clone(), cfg).unwrap();
        let addr = server.udp_addr().unwrap();
        let client = UdpSocket::bind(local(0)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        // A worker that switched loops takes effect from the next query, so keep sending until the
        // condition holds.
        let query_until = |failure: &str, done: &dyn Fn() -> bool| {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut id = 0u16;
            while !done() {
                assert!(Instant::now() < deadline, "{failure}");
                id = id.wrapping_add(1);
                client
                    .send_to(&query_bytes(id, "switch.example"), addr)
                    .unwrap();
                let _ = client.recv_from(&mut [0u8; 512]);
            }
        };

        query_until(
            "리액터를 끈 채로 띄운 워커가 동기 경로로 답하지 않았습니다",
            &|| handler.handled.load(Ordering::SeqCst) > 0,
        );
        assert_eq!(
            handler.submitted.load(Ordering::SeqCst),
            0,
            "리액터가 꺼져 있는데 질의를 리액터에 넘겼습니다"
        );

        handler.active.store(true, Ordering::SeqCst);
        query_until(
            "리액터를 켠 뒤에도 질의가 리액터로 가지 않았습니다",
            &|| handler.submitted.load(Ordering::SeqCst) > 0,
        );

        handler.active.store(false, Ordering::SeqCst);
        let handled = handler.handled.load(Ordering::SeqCst);
        query_until(
            "리액터를 끈 뒤에도 동기 경로로 돌아오지 않았습니다",
            &|| handler.handled.load(Ordering::SeqCst) > handled,
        );

        // The receive timeout is 100 ms, so a pause asks only a few times; spinning would ask tens
        // of thousands of times.
        let asked = handler.asked.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(500));
        let idle = handler.asked.load(Ordering::SeqCst) - asked;
        assert!(
            idle < 50,
            "쉬는 동안 리액터 사용 여부를 {idle}번 물었습니다. 수신이 기다리지 않고 헛돕니다"
        );
        server.shutdown();
    }

    #[test]
    fn tcp_roundtrip() {
        let server = Server::bind(local(0), EchoA::new(), test_cfg()).unwrap();
        let addr = server.tcp_addr().unwrap();

        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let q = query_bytes(0x0007, "b.example.com");
        stream.write_all(&(q.len() as u16).to_be_bytes()).unwrap();
        stream.write_all(&q).unwrap();

        let mut lenb = [0u8; 2];
        stream.read_exact(&mut lenb).unwrap();
        let len = u16::from_be_bytes(lenb) as usize;
        let mut rb = vec![0u8; len];
        stream.read_exact(&mut rb).unwrap();
        let resp = Message::parse(&rb).unwrap();

        assert_eq!(resp.header.id, 0x0007);
        assert_eq!(resp.answers.len(), 1);

        let q2 = query_bytes(0x0008, "c.example.com");
        stream.write_all(&(q2.len() as u16).to_be_bytes()).unwrap();
        stream.write_all(&q2).unwrap();
        stream.read_exact(&mut lenb).unwrap();
        let len = u16::from_be_bytes(lenb) as usize;
        let mut rb2 = vec![0u8; len];
        stream.read_exact(&mut rb2).unwrap();
        assert_eq!(Message::parse(&rb2).unwrap().header.id, 0x0008);

        drop(stream);
        server.shutdown();
    }

    #[test]
    fn tcp_wire_response_bypasses_message_parser_and_handler() {
        let mut cfg = test_cfg();
        cfg.udp = false;
        let handler = Arc::new(TcpWireOnly {
            slow_calls: AtomicUsize::new(0),
        });
        let server = Server::bind(local(0), handler.clone(), cfg).unwrap();
        let mut stream = TcpStream::connect(server.tcp_addr().unwrap()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let query = query_bytes(0x2929, "wire.example");
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .unwrap();
        stream.write_all(&query).unwrap();

        let mut length = [0u8; 2];
        stream.read_exact(&mut length).unwrap();
        let mut wire = vec![0; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut wire).unwrap();
        let response = Message::parse(&wire).unwrap();
        assert!(response.header.response);
        assert_eq!(response.header.id, 0x2929);
        assert_eq!(handler.slow_calls.load(Ordering::Relaxed), 0);
        server.shutdown();
    }

    #[test]
    fn tcp_closes_on_unsolicited_dns_response_without_calling_handler() {
        let mut cfg = test_cfg();
        cfg.udp = false;
        let handler = EchoA::new();
        let server = Server::bind(local(0), handler.clone(), cfg).unwrap();

        let mut stream = TcpStream::connect(server.tcp_addr().unwrap()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut unsolicited = Message::query(
            0x6161,
            Name::from_str("loop.example").unwrap(),
            RecordType::A,
        );
        unsolicited.header.response = true;
        let wire = unsolicited.try_encode().unwrap();
        stream
            .write_all(&(wire.len() as u16).to_be_bytes())
            .unwrap();
        stream.write_all(&wire).unwrap();

        assert_eq!(stream.read(&mut [0u8; 1]).unwrap(), 0);
        assert!(handler.threads.lock().unwrap().is_empty());
        server.shutdown();
    }

    #[test]
    fn slow_tcp_clients_cannot_starve_a_normal_client() {
        let mut cfg = test_cfg();
        cfg.udp = false;
        cfg.tcp_acceptors = 1;
        let server = Server::bind(local(0), EchoA::new(), cfg).unwrap();
        let address = server.tcp_addr().unwrap();

        let idle: Vec<_> = (0..4)
            .map(|_| TcpStream::connect(address).unwrap())
            .collect();
        std::thread::sleep(Duration::from_millis(150));

        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let query = query_bytes(0x7171, "fairness.example");
        client
            .write_all(&(query.len() as u16).to_be_bytes())
            .unwrap();
        client.write_all(&query).unwrap();
        let mut length = [0u8; 2];
        client.read_exact(&mut length).unwrap();
        let mut wire = vec![0; u16::from_be_bytes(length) as usize];
        client.read_exact(&mut wire).unwrap();
        assert_eq!(Message::parse(&wire).unwrap().header.id, 0x7171);

        drop((client, idle));
        server.shutdown();
    }

    struct LargeResponder;
    impl Handler for LargeResponder {
        fn handle(&self, request: &Message, _ctx: &RequestCtx) -> Option<Message> {
            let q = request.questions.first()?;
            let mut response = Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.questions = request.questions.clone();
            for octet in 1..=64 {
                response.answers.push(Record::new(
                    q.name.clone(),
                    300,
                    RData::A(Ipv4Addr::new(198, 51, 100, octet)),
                ));
            }
            Some(response)
        }
    }

    #[test]
    fn udp_truncation_retries_over_tcp_with_complete_answer() {
        let server = Server::bind(local(0), Arc::new(LargeResponder), test_cfg()).unwrap();
        let query = query_bytes(0x5151, "large.example.com");

        let udp = UdpSocket::bind(local(0)).unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        udp.send_to(&query, server.udp_addr().unwrap()).unwrap();
        let mut udp_buf = [0u8; 512];
        let (udp_len, _) = udp.recv_from(&mut udp_buf).unwrap();
        let truncated = Message::parse(&udp_buf[..udp_len]).unwrap();
        assert!(truncated.header.truncated);
        assert!(udp_len <= 512);

        let mut tcp = TcpStream::connect(server.tcp_addr().unwrap()).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        tcp.write_all(&(query.len() as u16).to_be_bytes()).unwrap();
        tcp.write_all(&query).unwrap();
        let mut len = [0u8; 2];
        tcp.read_exact(&mut len).unwrap();
        let mut wire = vec![0; u16::from_be_bytes(len) as usize];
        tcp.read_exact(&mut wire).unwrap();
        let complete = Message::parse(&wire).unwrap();
        assert!(!complete.header.truncated);
        assert_eq!(complete.answers.len(), 64);
        server.shutdown();
    }

    struct TripleResponder;
    impl Handler for TripleResponder {
        fn handle(&self, request: &Message, _ctx: &RequestCtx) -> Option<Message> {
            let mut m = Message::default();
            m.header.id = request.header.id;
            m.header.response = true;
            Some(m)
        }
        fn handle_multi(&self, request: &Message, _ctx: &RequestCtx) -> Option<Vec<Message>> {
            let q = request.questions.first()?;
            let out = (0..3u32)
                .map(|i| {
                    let mut m = Message::default();
                    m.header.id = request.header.id;
                    m.header.response = true;
                    m.answers.push(Record::new(
                        q.name.clone(),
                        i,
                        RData::A(Ipv4Addr::new(10, 0, 0, i as u8)),
                    ));
                    m
                })
                .collect();
            Some(out)
        }
    }

    #[test]
    fn tcp_multi_message_response() {
        let server = Server::bind(local(0), Arc::new(TripleResponder), test_cfg()).unwrap();
        let addr = server.tcp_addr().unwrap();

        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let q = query_bytes(0x00AA, "xfer.example.com");
        stream.write_all(&(q.len() as u16).to_be_bytes()).unwrap();
        stream.write_all(&q).unwrap();

        for expect_ttl in 0..3u32 {
            let mut lenb = [0u8; 2];
            stream.read_exact(&mut lenb).unwrap();
            let len = u16::from_be_bytes(lenb) as usize;
            let mut rb = vec![0u8; len];
            stream.read_exact(&mut rb).unwrap();
            let resp = Message::parse(&rb).unwrap();
            assert_eq!(resp.header.id, 0x00AA);
            assert_eq!(resp.answers[0].ttl, expect_ttl, "envelope 순서 보존");
        }
        drop(stream);
        server.shutdown();
    }

    #[test]
    fn concurrent_load() {
        let handler = EchoA::new();
        let server = Server::bind(local(0), handler.clone(), test_cfg()).unwrap();
        let addr = server.udp_addr().unwrap();

        let mut joins = vec![];
        for t in 0..8u16 {
            joins.push(std::thread::spawn(move || {
                let client = UdpSocket::bind(local(0)).unwrap();
                client
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut ok = 0;
                for i in 0..8u16 {
                    let id = t * 100 + i;
                    client
                        .send_to(&query_bytes(id, "load.example.com"), addr)
                        .unwrap();
                    let mut buf = [0u8; 4096];
                    if let Ok((n, _)) = client.recv_from(&mut buf) {
                        if let Ok(m) = Message::parse(&buf[..n]) {
                            if m.header.id == id && m.answers.len() == 1 {
                                ok += 1;
                            }
                        }
                    }
                }
                ok
            }));
        }
        let total: u32 = joins.into_iter().map(|j| j.join().unwrap()).sum();
        assert_eq!(total, 64, "동시 64질의 전부 응답");

        let used = handler.threads.lock().unwrap().len();
        assert!(used >= 1);
        server.shutdown();
    }

    #[test]
    /// A port left bound would prevent restarting.
    fn drop_stops_workers_and_releases_listener_ports() {
        let mut udp_cfg = test_cfg();
        udp_cfg.tcp = false;
        let udp_server = Server::bind(local(0), EchoA::new(), udp_cfg).unwrap();
        let udp_addr = udp_server.udp_addr().unwrap();
        drop(udp_server);
        let rebound_udp = UdpSocket::bind(udp_addr).expect("UDP port released on drop");
        drop(rebound_udp);

        let mut tcp_cfg = test_cfg();
        tcp_cfg.udp = false;
        let tcp_server = Server::bind(local(0), EchoA::new(), tcp_cfg).unwrap();
        let tcp_addr = tcp_server.tcp_addr().unwrap();
        drop(tcp_server);
        let rebound_tcp = std::net::TcpListener::bind(tcp_addr).expect("TCP port released on drop");
        drop(rebound_tcp);
    }

    #[test]
    /// A connection accepted before the stop is still answered, and closes once it goes idle.
    fn stopping_answers_open_connections_then_closes_them_when_idle() {
        fn ask(stream: &mut TcpStream, id: u16) -> Option<u16> {
            let q = query_bytes(id, "drain.example.com");
            stream.write_all(&(q.len() as u16).to_be_bytes()).ok()?;
            stream.write_all(&q).ok()?;
            let mut lenb = [0u8; 2];
            stream.read_exact(&mut lenb).ok()?;
            let mut rb = vec![0u8; u16::from_be_bytes(lenb) as usize];
            stream.read_exact(&mut rb).ok()?;
            Some(Message::parse(&rb).ok()?.header.id)
        }

        let mut cfg = test_cfg();
        cfg.udp = false;
        let server = Server::bind(local(0), EchoA::new(), cfg).unwrap();
        let mut stream = TcpStream::connect(server.tcp_addr().unwrap()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        assert_eq!(ask(&mut stream, 1), Some(1));

        let stopping = std::thread::spawn(move || {
            let started = Instant::now();
            server.shutdown();
            started.elapsed()
        });
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            ask(&mut stream, 2),
            Some(2),
            "멈추는 중에 받은 질의에 답하지 않았습니다"
        );
        assert_eq!(
            stream.read(&mut [0u8; 1]).ok(),
            Some(0),
            "조용해진 연결을 닫지 않았습니다"
        );
        assert!(stopping.join().unwrap() < onetdns_core::tcp::DRAIN_LIMIT);
    }

    #[test]
    /// Windows UDP workers wait without a timeout and must be woken over loopback at shutdown; a
    /// wrong wake-up address would never finish the join.
    fn unspecified_udp_listener_with_many_workers_stops() {
        let mut cfg = test_cfg();
        cfg.tcp = false;
        cfg.udp_workers = 32;
        let server = Server::bind(
            SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)),
            EchoA::new(),
            cfg,
        )
        .unwrap();
        let addr = server.udp_addr().unwrap();
        let started = std::time::Instant::now();
        drop(server);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        drop(UdpSocket::bind(addr).expect("UDP port released on drop"));
    }

    #[test]
    fn worker_count_logic() {
        assert_eq!(sys::worker_count(4), 4);
        assert_eq!(
            sys::worker_count(0),
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
                .min(sys::MAX_WORKERS)
        );
        assert_eq!(sys::worker_count(usize::MAX), sys::MAX_WORKERS);
    }

    #[test]
    fn poll_interval_is_bounded_for_public_runtime_callers() {
        assert_eq!(sys::poll_interval(Duration::ZERO), Duration::from_millis(1));
        assert_eq!(
            sys::poll_interval(Duration::from_millis(100)),
            Duration::from_millis(100)
        );
        assert_eq!(
            sys::poll_interval(Duration::from_secs(60)),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn only_multi_message_stream_transports_advertise_zone_transfer() {
        assert!(Transport::Do53Tcp.supports_xfr());
        assert!(Transport::DoT.supports_xfr());
        assert!(!Transport::DoQ.supports_xfr());
        assert!(!Transport::DoH.supports_xfr());
        assert!(!Transport::DoH3.supports_xfr());
    }
}
