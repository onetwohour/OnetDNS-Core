//! Do53 TCP listener and connection workers. Accepting only queues connections and workers
//! serve them, so a slow client cannot stop new connections from being accepted.

use std::io::{self, ErrorKind, IoSlice, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use onetdns_core::admission::ClientCounts;
use onetdns_core::IpNet;
use onetdns_proto::{Message, Writer};

use crate::{Handler, RequestCtx, Transport, WireDisposition};

const PROXY_HEADER_DEADLINE: Duration = Duration::from_secs(5);

/// Bounds how long a slow connection can hold a worker for one message.
const DNS_MESSAGE_DEADLINE: Duration = Duration::from_secs(10);

const MIN_CONNECTION_WORKERS: usize = 8;

const MAX_CONNECTION_WORKERS: usize = 64;

const MIN_CONNECTION_QUEUE: usize = 256;

/// Past this, new connections are refused instead of queued in memory.
const MAX_CONNECTION_QUEUE: usize = 4096;

/// Behind a proxy every connection comes from the proxy's address, so the per-client limit is
/// raised.
const MAX_PROXY_CONNECTIONS_PER_IP: usize = 64;

/// Sends the length prefix and body in one vectored write, so the prefix does not leave in a
/// packet of its own. A short write may stop inside the prefix, so the rest is resumed from there.
fn write_dns_frame<W: Write>(stream: &mut W, payload: &[u8]) -> io::Result<()> {
    let len = u16::try_from(payload.len()).map_err(|_| {
        io::Error::new(ErrorKind::InvalidInput, "DNS/TCP frame exceeds 65535 bytes")
    })?;
    let prefix = len.to_be_bytes();
    let slices = [IoSlice::new(&prefix), IoSlice::new(payload)];
    let written = loop {
        match stream.write_vectored(&slices) {
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            result => break result?,
        }
    };
    if written == 0 {
        return Err(io::Error::new(
            ErrorKind::WriteZero,
            "failed to write DNS/TCP frame",
        ));
    }
    if written < prefix.len() {
        stream.write_all(&prefix[written..])?;
        stream.write_all(payload)
    } else {
        stream.write_all(&payload[written - prefix.len()..])
    }
}

/// The stream, its peer, and the guard holding its slot.
pub(crate) type Accepted = (TcpStream, SocketAddr, ConnectionGuard);

pub(crate) struct ConnectionPoolConfig {
    pub poll: Duration,
    pub proxy_protocol: bool,
    pub trusted_proxies: Arc<Vec<IpNet>>,
    pub workers: usize,
    pub queue_capacity: usize,
    pub pin_cores: bool,
    /// Cores to pin to, shared with the accept threads.
    pub pin_span: usize,
}

/// Bounds concurrent connections in total and per client, so one client cannot starve the rest.
pub(crate) struct ConnectionLimiter {
    max_total: usize,
    state: Mutex<LimitState>,
}

struct LimitState {
    total: usize,
    clients: ClientCounts,
}

/// Returns the slot on drop, however the connection ends, panic included.
pub(crate) struct ConnectionGuard {
    limiter: Arc<ConnectionLimiter>,
    ip: IpAddr,
}

impl ConnectionLimiter {
    /// Both limits are raised to at least 1.
    fn new(max_total: usize, max_per_ip: usize) -> Arc<Self> {
        let max_total = max_total.max(1);
        Arc::new(Self {
            max_total,
            state: Mutex::new(LimitState {
                total: 0,
                clients: ClientCounts::new(max_per_ip.max(1), max_total),
            }),
        })
    }

    /// `None` when either limit is reached; the caller closes the connection.
    fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnectionGuard> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.total >= self.max_total || !state.clients.allows(ip) {
            return None;
        }
        state.total += 1;
        state.clients.add(ip);
        Some(ConnectionGuard {
            limiter: self.clone(),
            ip,
        })
    }
}

impl ConnectionGuard {
    /// Moves the slot to the client named in the PROXY header; otherwise the per-client limit would
    /// apply to the proxy only. False when that client is at its limit, and the connection must be
    /// refused.
    fn reassign_ip(&mut self, ip: IpAddr) -> bool {
        if self.ip == ip {
            return true;
        }
        let mut state = self
            .limiter
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.clients.remove(self.ip);
        if !state.clients.allows(ip) {
            state.clients.add(self.ip);
            return false;
        }
        state.clients.add(ip);
        self.ip = ip;
        true
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut state = self
            .limiter
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.total = state.total.saturating_sub(1);
        state.clients.remove(self.ip);
    }
}

/// More than the accept threads, so serving never blocks accepting.
pub(crate) fn connection_worker_count(acceptors: usize) -> usize {
    acceptors
        .max(1)
        .saturating_mul(2)
        .clamp(MIN_CONNECTION_WORKERS, MAX_CONNECTION_WORKERS)
}

pub(crate) fn connection_queue_capacity(acceptors: usize) -> usize {
    acceptors
        .max(1)
        .saturating_mul(64)
        .clamp(MIN_CONNECTION_QUEUE, MAX_CONNECTION_QUEUE)
}

/// The total is workers plus queue length: beyond that a connection can be neither served nor
/// queued.
pub(crate) fn connection_limiter(
    workers: usize,
    queue_capacity: usize,
    proxy_protocol: bool,
) -> Arc<ConnectionLimiter> {
    let max_per_ip = if proxy_protocol {
        MAX_PROXY_CONNECTIONS_PER_IP
    } else {
        workers.saturating_sub(2).clamp(4, 16)
    };
    ConnectionLimiter::new(workers.saturating_add(queue_capacity), max_per_ip)
}

/// Workers share one receiver, so a burst of connections cannot become a burst of threads.
/// Each connection is a fault isolation boundary. Fails only when no worker starts.
pub(crate) fn spawn_connection_workers<H: Handler>(
    handler: Arc<H>,
    shutdown: Arc<AtomicBool>,
    config: ConnectionPoolConfig,
) -> io::Result<(mpsc::SyncSender<Accepted>, Vec<std::thread::JoinHandle<()>>)> {
    let (tx, rx) = mpsc::sync_channel::<Accepted>(config.queue_capacity);
    let rx = Arc::new(Mutex::new(rx));
    let mut workers = Vec::with_capacity(config.workers);
    for idx in 0..config.workers {
        let rx = rx.clone();
        let handler = handler.clone();
        let shutdown = shutdown.clone();
        let trusted = config.trusted_proxies.clone();
        let poll = config.poll;
        let proxy_protocol = config.proxy_protocol;
        let pin_cores = config.pin_cores;
        let pin_span = config.pin_span;
        match std::thread::Builder::new()
            .name(format!("onetdns-tcp-conn-{idx}"))
            .spawn(move || {
                if pin_cores {
                    crate::sys::pin_to_core(idx % pin_span.max(1));
                }
                loop {
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    let next = {
                        let receiver = rx.lock().unwrap_or_else(|poisoned| {
                            onetdns_core::error!(
                                event = "tcp.accept_queue_poisoned",
                                worker = idx,
                                "Connection queue lock was poisoned; recovered and continuing"
                            );
                            poisoned.into_inner()
                        });
                        receiver.recv_timeout(poll)
                    };
                    match next {
                        Ok(accepted) => {
                            let _ = onetdns_core::isolation::catch_request(|| {
                                handle_conn(
                                    accepted,
                                    &handler,
                                    &shutdown,
                                    poll,
                                    proxy_protocol,
                                    &trusted,
                                )
                            });
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            }) {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                onetdns_core::error!(event = "tcp.worker_spawn_failed", %error, worker = idx, "Could not start the DNS/TCP connection thread");
                break;
            }
        }
    }
    if workers.is_empty() {
        return Err(io::Error::other(
            "Could not start the DNS/TCP connection thread",
        ));
    }
    Ok((tx, workers))
}

/// Waits up to `timeout` for a connection, so the non-blocking listener neither spins nor misses
/// shutdown.
#[cfg(unix)]
fn wait_for_incoming(listener: &TcpListener, timeout: Duration) -> io::Result<bool> {
    use std::os::fd::AsRawFd;

    let millis = timeout.as_millis().clamp(1, i32::MAX as u128) as i32;
    let mut descriptor = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let ready = unsafe { libc::poll(&mut descriptor, 1, millis) };
        if ready >= 0 {
            return Ok(ready > 0);
        }
        let error = io::Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Accepts at once; the caller sleeps briefly on WouldBlock.
#[cfg(not(unix))]
fn wait_for_incoming(_listener: &TcpListener, _timeout: Duration) -> io::Result<bool> {
    Ok(true)
}

/// Accepts and queues; requests are served elsewhere. A full queue closes the connection: waiting
/// here would stop accepting and push the backlog into the kernel.
pub(crate) fn accept_worker(
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    poll: Duration,
    limiter: Arc<ConnectionLimiter>,
    tx: mpsc::SyncSender<Accepted>,
) {
    while !shutdown.load(Ordering::Relaxed) {
        match wait_for_incoming(&listener, poll) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => {
                std::thread::sleep(poll.min(Duration::from_millis(10)));
                continue;
            }
        }
        match listener.accept() {
            Ok((stream, peer)) => {
                if let Some(guard) = limiter.try_acquire(peer.ip()) {
                    let _ = tx.try_send((stream, peer, guard));
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(poll.min(Duration::from_millis(10)));
            }
            Err(_) => std::thread::sleep(poll.min(Duration::from_millis(10))),
        }
    }
}

fn trusted_peer(peer: SocketAddr, trusted: &[IpNet]) -> bool {
    trusted.iter().any(|net| net.contains(&peer.ip()))
}

/// Serves every query on one connection. With PROXY on, an untrusted peer is closed before its
/// header is read; otherwise anyone could forge the source address. A message with the response
/// bit set closes the connection, since servers answering each other would loop.
fn handle_conn<H: Handler>(
    accepted: Accepted,
    handler: &Arc<H>,
    shutdown: &AtomicBool,
    poll: Duration,
    proxy_protocol: bool,
    trusted_proxies: &[IpNet],
) {
    let (mut stream, mut peer, mut guard) = accepted;
    if let Err(error) = stream
        .set_nonblocking(false)
        .and_then(|()| stream.set_read_timeout(Some(poll)))
        .and_then(|()| stream.set_write_timeout(Some(DNS_MESSAGE_DEADLINE)))
    {
        note_tcp_drop("socket_options", peer, &error.to_string());
        return;
    }
    let _ = stream.set_nodelay(true);

    if proxy_protocol {
        if !trusted_peer(peer, trusted_proxies) {
            note_tcp_drop(
                "untrusted_proxy",
                peer,
                "Connection from an address not in trusted_proxies",
            );
            return;
        }
        match read_proxy_header(&mut stream, shutdown) {
            Some(Some(real)) if guard.reassign_ip(real.ip()) => peer = real,
            Some(Some(_)) => {
                note_tcp_drop(
                    "client_connection_limit",
                    peer,
                    "Client named in the PROXY header is already at its connection limit",
                );
                return;
            }
            Some(None) => {}
            None => {
                note_tcp_drop("proxy_header", peer, "PROXY header is missing or malformed");
                return;
            }
        }
    }

    let mut writer = Writer::new();
    let mut body: Vec<u8> = Vec::with_capacity(512);

    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }

        let deadline = Instant::now() + DNS_MESSAGE_DEADLINE;
        let mut lenb = [0u8; 2];
        if !read_exact_until(&mut stream, &mut lenb, shutdown, deadline) {
            return;
        }
        let len = usize::from(u16::from_be_bytes(lenb));
        if len == 0 {
            return;
        }
        body.resize(len, 0);
        if !read_exact_until(&mut stream, &mut body, shutdown, deadline) {
            return;
        }
        let ctx = RequestCtx {
            src: peer,
            transport: Transport::Do53Tcp,
            raw: Some(body.as_slice()),
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };
        writer.clear();
        match handler.handle_tcp_wire(&body, &ctx, &mut writer, Instant::now()) {
            WireDisposition::Respond => {
                if write_dns_frame(&mut stream, &writer.buf).is_err() {
                    return;
                }
                continue;
            }
            WireDisposition::Drop => return,
            WireDisposition::Fallback => {}
        }

        let request = match Message::parse(&body) {
            Ok(m) => m,
            Err(_) => {
                // Answer and keep the connection: the length prefix still marks where the next
                // message starts.
                if body.len() >= 12 && body[2] & 0x80 == 0 {
                    if let Some(response) = handler.handle_unparsable(&body, &ctx) {
                        writer.clear();
                        if response.try_encode_into(&mut writer).is_ok()
                            && write_dns_frame(&mut stream, &writer.buf).is_err()
                        {
                            return;
                        }
                    }
                }
                continue;
            }
        };
        if request.header.response {
            return;
        }

        if let Some(completed) =
            handler.handle_preencoded_stream(&request, &ctx, &mut writer, &mut |wire| {
                write_dns_frame(&mut stream, wire).is_ok()
            })
        {
            if !completed {
                return;
            }
            continue;
        }

        let completed = handler.handle_stream(&request, &ctx, &mut |response| {
            writer.clear();
            if response.try_encode_into(&mut writer).is_err() {
                writer.clear();
                if crate::encoding_failure_response(&request)
                    .try_encode_into(&mut writer)
                    .is_err()
                {
                    return false;
                }
            }
            let l = writer.buf.len();
            if l > u16::MAX as usize {
                return false;
            }
            if write_dns_frame(&mut stream, &writer.buf).is_err() {
                return false;
            }
            true
        });
        if !completed {
            return;
        }
    }
}

/// The reason a connection was closed right after accept. A misconfigured front proxy drops every
/// connection here, so this is logged, sampled at powers of two.
fn note_tcp_drop(reason: &'static str, peer: SocketAddr, detail: &str) {
    use std::sync::atomic::AtomicU64;
    static COUNT: AtomicU64 = AtomicU64::new(0);
    let count = COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::warn!(event = "tcp.connection_dropped", reason = reason, peer = %peer, count = count, detail = detail, "Connection dropped right after accept");
    }
}

/// Reads a byte at a time so nothing past the header is consumed, within 256 bytes and a deadline.
/// `Some(Some(addr))` names the client, `Some(None)` is the proxy's own connection, and `None`
/// means close.
fn read_proxy_header(stream: &mut TcpStream, shutdown: &AtomicBool) -> Option<Option<SocketAddr>> {
    use crate::proxy::{parse, ProxyParse};
    let deadline = Instant::now() + PROXY_HEADER_DEADLINE;
    let mut buf: Vec<u8> = Vec::with_capacity(64);
    let mut one = [0u8; 1];
    loop {
        if Instant::now() >= deadline || buf.len() > 256 {
            return None;
        }
        match stream.read(&mut one) {
            Ok(0) => return None,
            Ok(_) => {
                if Instant::now() >= deadline {
                    return None;
                }
                buf.push(one[0]);
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                if shutdown.load(Ordering::Relaxed) {
                    return None;
                }
                continue;
            }
            Err(_) => return None,
        }
        match parse(&buf) {
            ProxyParse::Incomplete => continue,
            ProxyParse::Addr(a, _) => return Some(Some(a)),
            ProxyParse::Local(_) => return Some(None),
            ProxyParse::NotProxy => return None,
        }
    }
}

/// Fills `buf` by `deadline`. Each read timeout rechecks the deadline and shutdown, so a
/// connection sending a byte at a time is still cut off. False on deadline, shutdown, EOF or error.
fn read_exact_until(
    stream: &mut TcpStream,
    buf: &mut [u8],
    shutdown: &AtomicBool,
    deadline: Instant,
) -> bool {
    let mut got = 0;
    while got < buf.len() {
        if shutdown.load(Ordering::Relaxed) || Instant::now() >= deadline {
            return false;
        }
        match stream.read(&mut buf[got..]) {
            Ok(0) => return false,
            Ok(k) => {
                if Instant::now() >= deadline {
                    return false;
                }
                got += k;
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,
            Err(_) => return false,
        }
    }
    true
}

#[cfg(test)]
mod malformed_tests {
    use super::*;
    use onetdns_proto::{Name, RecordType};

    /// FORMERR for unparsable messages, NOERROR for the rest.
    struct TwoAnswerHandler;

    impl Handler for TwoAnswerHandler {
        fn handle(&self, request: &Message, _ctx: &RequestCtx<'_>) -> Option<Message> {
            let mut response = Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.questions = request.questions.clone();
            Some(response)
        }

        fn handle_unparsable(&self, packet: &[u8], _ctx: &RequestCtx<'_>) -> Option<Message> {
            let mut response = Message::default();
            response.header.id = u16::from_be_bytes([packet[0], packet[1]]);
            response.header.response = true;
            response.header.rcode = 1;
            Some(response)
        }
    }

    fn send_frame(stream: &mut TcpStream, payload: &[u8]) {
        let mut framed = (payload.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(payload);
        stream.write_all(&framed).expect("Could not send the frame");
    }

    fn recv_frame(stream: &mut TcpStream) -> Option<Message> {
        let mut length = [0u8; 2];
        if stream.read_exact(&mut length).is_err() {
            return None;
        }
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut body).ok()?;
        Message::parse(&body).ok()
    }

    #[test]
    /// Breaking the connection would make a client that pipelines queries lose all of them over one
    /// broken message.
    fn a_malformed_message_does_not_end_the_tcp_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Could not bind the listen address");
        let address = listener.local_addr().expect("Could not read the address");

        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).expect("Could not connect");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("Could not set the deadline");

            // The header claims two questions but carries one.
            let mut broken = vec![0u8; 12];
            broken[0..2].copy_from_slice(&0x4321u16.to_be_bytes());
            broken[4..6].copy_from_slice(&2u16.to_be_bytes());
            broken.extend_from_slice(&[2, b'n', b's', 0, 0, 1, 0, 1]);
            assert!(Message::parse(&broken).is_err(), "Control case is invalid");
            send_frame(&mut stream, &broken);
            let first = recv_frame(&mut stream);

            let good = Message::query(0x1234, Name::from_str("ok.test").unwrap(), RecordType::A)
                .try_encode()
                .expect("Could not build the query");
            send_frame(&mut stream, &good);
            let second = recv_frame(&mut stream);
            (first, second)
        });

        let (stream, peer) = listener.accept().expect("Did not receive");
        let limiter = ConnectionLimiter::new(4, 4);
        let guard = limiter
            .try_acquire(peer.ip())
            .expect("Could not take a slot");
        let shutdown = AtomicBool::new(false);
        handle_conn(
            (stream, peer, guard),
            &Arc::new(TwoAnswerHandler),
            &shutdown,
            Duration::from_millis(200),
            false,
            &[],
        );

        let (first, second) = client.join().expect("Client died");
        let first = first.expect("Did not answer an unreadable message");
        assert_eq!(first.header.rcode, 1);
        assert_eq!(first.header.id, 0x4321);
        let second = second.expect("Closed the connection on a single unreadable message");
        assert_eq!(second.header.rcode, 0);
        assert_eq!(second.header.id, 0x1234);
    }
}

#[cfg(test)]
mod limit_tests {
    use super::*;

    struct ShortVectoredWriter {
        bytes: Vec<u8>,
        first_limit: usize,
        vectored_calls: usize,
    }

    impl Write for ShortVectoredWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
            self.vectored_calls += 1;
            let mut remaining = self.first_limit;
            let mut written = 0;
            for buf in bufs {
                let take = remaining.min(buf.len());
                self.bytes.extend_from_slice(&buf[..take]);
                written += take;
                remaining -= take;
                if remaining == 0 {
                    break;
                }
            }
            Ok(written)
        }
    }

    #[test]
    fn dns_frame_vectored_write_handles_short_prefix_and_body() {
        for first_limit in [1, 4, usize::MAX] {
            let mut writer = ShortVectoredWriter {
                bytes: Vec::new(),
                first_limit,
                vectored_calls: 0,
            };
            write_dns_frame(&mut writer, b"abcdef").unwrap();
            assert_eq!(writer.bytes, b"\0\x06abcdef");
            assert_eq!(writer.vectored_calls, 1);
        }
    }

    #[test]
    fn dns_frame_rejects_oversized_payload() {
        let mut writer = Vec::new();
        let error = write_dns_frame(&mut writer, &vec![0; usize::from(u16::MAX) + 1])
            .expect_err("oversized DNS/TCP frame");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(writer.is_empty());
    }

    #[test]
    fn idle_acceptor_delivers_new_connection_without_poll_interval_delay() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let limiter = ConnectionLimiter::new(8, 8);
        let (tx, rx) = mpsc::sync_channel(1);
        let worker_shutdown = shutdown.clone();
        let worker_limiter = limiter.clone();
        let worker = std::thread::spawn(move || {
            accept_worker(
                listener,
                worker_shutdown,
                Duration::from_millis(500),
                worker_limiter,
                tx,
            )
        });

        std::thread::sleep(Duration::from_millis(20));
        let started = Instant::now();
        let client = TcpStream::connect(address).unwrap();
        let accepted = rx
            .recv_timeout(Duration::from_millis(400))
            .expect("500ms poll interval must not delay a ready TCP listener");
        assert!(started.elapsed() < Duration::from_millis(400));
        drop(accepted);
        drop(client);

        shutdown.store(true, Ordering::Relaxed);
        let _wake = TcpStream::connect(address);
        worker.join().unwrap();
    }

    #[test]
    fn length_and_body_share_one_absolute_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        // Only the ratios matter: the length arrives before the deadline and the body after it.
        // Scale every value together so a slow machine cannot reorder them.
        server
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let sender = std::thread::spawn(move || {
            client.write_all(&[0]).unwrap();
            std::thread::sleep(Duration::from_millis(200));
            client.write_all(&[1]).unwrap();
            std::thread::sleep(Duration::from_millis(400));
            let _ = client.write_all(&[0]);
        });
        let shutdown = AtomicBool::new(false);
        let started = Instant::now();
        let deadline = started + Duration::from_millis(450);
        let mut length = [0u8; 2];
        assert!(read_exact_until(
            &mut server,
            &mut length,
            &shutdown,
            deadline,
        ));
        assert_eq!(u16::from_be_bytes(length), 1);
        assert!(!read_exact_until(
            &mut server,
            &mut [0u8; 1],
            &shutdown,
            deadline,
        ));
        assert!(started.elapsed() < Duration::from_millis(800));
        sender.join().unwrap();
    }

    #[test]
    fn shared_limiter_caps_ip_and_reassigns_trusted_proxy_clients() {
        let limiter = ConnectionLimiter::new(512, 64);
        let ip = "192.0.2.1".parse().unwrap();
        let guards: Vec<_> = (0..64).map(|_| limiter.try_acquire(ip).unwrap()).collect();
        assert!(limiter.try_acquire(ip).is_none());

        let proxy_ip = "192.0.2.2".parse().unwrap();
        let mut proxy = limiter.try_acquire(proxy_ip).unwrap();
        assert!(!proxy.reassign_ip(ip));
        drop(guards);
        assert!(proxy.reassign_ip(ip));
        assert!(limiter.try_acquire(proxy_ip).is_some());
        drop(proxy);
    }

    #[test]
    fn a_proxied_ipv6_client_counts_against_its_prefix() {
        let limiter = ConnectionLimiter::new(8, 2);
        let held: Vec<_> = (1..=4)
            .map(|host| {
                limiter
                    .try_acquire(format!("2001:db8::{host}").parse().unwrap())
                    .unwrap()
            })
            .collect();
        assert!(limiter
            .try_acquire("2001:db8::ffff:5".parse().unwrap())
            .is_none());

        let mut proxied = limiter.try_acquire("192.0.2.2".parse().unwrap()).unwrap();
        assert!(
            !proxied.reassign_ip("2001:db8::6".parse().unwrap()),
            "PROXY 헤더로 알린 주소도 /64 한도를 지켜야 합니다"
        );
        assert!(
            limiter.try_acquire("192.0.2.2".parse().unwrap()).is_some(),
            "거절된 이전은 원래 주소의 몫을 그대로 둬야 합니다"
        );
        assert!(proxied.reassign_ip("2001:db8:0:1::1".parse().unwrap()));
        drop((held, proxied));
    }

    #[test]
    fn global_pool_bounds_threads_and_reserves_capacity_from_one_ip() {
        assert_eq!(connection_worker_count(1), 8);
        assert_eq!(connection_worker_count(16), 32);
        assert_eq!(connection_worker_count(usize::MAX), 64);
        assert_eq!(connection_queue_capacity(1), 256);
        assert_eq!(connection_queue_capacity(usize::MAX), 4096);

        let limiter = connection_limiter(8, 256, false);
        let ip = "192.0.2.10".parse().unwrap();
        let guards: Vec<_> = (0..6).map(|_| limiter.try_acquire(ip).unwrap()).collect();
        assert!(limiter.try_acquire(ip).is_none());
        assert!(limiter.try_acquire("192.0.2.11".parse().unwrap()).is_some());
        drop(guards);
    }
}
