//! Connection admission for encrypted TCP. Total and per-client counts are bounded together:
//! with only a total, one client could take every slot.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use onetdns_core::admission::ClientCounts;
use onetdns_core::tcp::{DeadlineTcp, DRAIN_IDLE, DRAIN_LIMIT};
use onetdns_core::MutexExt;

use crate::transport_observe;

pub(crate) const MAX_ENCRYPTED_TCP_CONNECTIONS: usize = 512;
/// Shared by every encrypted TCP transport.
pub(crate) const MAX_ENCRYPTED_TCP_CONNECTIONS_PER_IP: usize = 64;

/// Set explicitly so a connection does not reserve the OS default stack.
pub(crate) const CONNECTION_THREAD_STACK_BYTES: usize = 512 * 1024;
/// Accepts per round before pending input and shutdown are checked again.
pub(crate) const ENCRYPTED_ACCEPT_BATCH: usize = 64;

const MAX_DNSCRYPT_TCP_QUERY_BYTES: usize = 8192;
const ENCRYPTED_PREFIX_TIMEOUT: Duration = Duration::from_secs(30);
const MIN_PREFIX_POLL: Duration = Duration::from_millis(10);
const MAX_PREFIX_POLL: Duration = Duration::from_millis(250);

/// Framing that thread-less admission waits for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionProtocol {
    /// The first ClientHello, which may span TLS records.
    Tls,
    /// A DNSCrypt frame with a 2-byte length prefix.
    Dnscrypt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionState {
    Pending,
    Ready,
}

/// Replays the bytes admission already read, then reads the socket.
pub(crate) struct PrefixedTcp {
    stream: TcpStream,
    prefix: Box<[u8]>,
    offset: usize,
}

/// A connection collecting its first encrypted frame without a thread.
pub(crate) struct PendingEncryptedConnection {
    stream: TcpStream,
    peer: SocketAddr,
    prefix: Vec<u8>,
    /// Held while pending, so waiting connections count against the limits too.
    guard: ConnectionGuard,
    protocol: AdmissionProtocol,
    accepted: Instant,
    deadline: Instant,
    next_poll: Instant,
    poll_interval: Duration,
}

impl PrefixedTcp {
    pub(crate) fn new(stream: TcpStream, prefix: Vec<u8>) -> Self {
        Self {
            stream,
            prefix: prefix.into_boxed_slice(),
            offset: 0,
        }
    }

    pub(crate) fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.stream.set_nonblocking(nonblocking)
    }
}

impl onetdns_core::tcp::SocketTimeouts for PrefixedTcp {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_write_timeout(timeout)
    }
}

/// Checks each pending connection once and hands the complete ones to `ready`; `failed` sees
/// rejections, deadlines and socket errors.
pub(crate) fn poll_pending_encrypted_connections<F, E>(
    pending: &mut Vec<PendingEncryptedConnection>,
    mut ready: F,
    mut failed: E,
) where
    F: FnMut(PrefixedTcp, SocketAddr, ConnectionGuard),
    E: FnMut(SocketAddr, io::Error),
{
    let mut index = 0usize;
    while index < pending.len() {
        match pending[index].poll() {
            Ok(AdmissionState::Pending) => index += 1,
            Ok(AdmissionState::Ready) => {
                let connection = pending.swap_remove(index);
                let peer = connection.peer();
                match connection.into_ready() {
                    Ok((stream, peer, guard)) => ready(stream, peer, guard),
                    Err(error) => failed(peer, error),
                }
            }
            Err(error) => {
                let connection = pending.swap_remove(index);
                let peer = connection.peer();
                drop(connection);
                failed(peer, error);
            }
        }
    }
}

impl PendingEncryptedConnection {
    pub(crate) fn admit(
        stream: TcpStream,
        peer: SocketAddr,
        limiter: &Arc<ConnectionLimiter>,
        protocol: AdmissionProtocol,
    ) -> io::Result<Option<Self>> {
        let Some(guard) = limiter.try_acquire(peer.ip()) else {
            return Ok(None);
        };
        Self::new(stream, peer, guard, protocol).map(Some)
    }

    pub(crate) fn new(
        stream: TcpStream,
        peer: SocketAddr,
        guard: ConnectionGuard,
        protocol: AdmissionProtocol,
    ) -> io::Result<Self> {
        Self::with_deadline(
            stream,
            peer,
            guard,
            protocol,
            Instant::now() + ENCRYPTED_PREFIX_TIMEOUT,
        )
    }

    fn with_deadline(
        stream: TcpStream,
        peer: SocketAddr,
        guard: ConnectionGuard,
        protocol: AdmissionProtocol,
        deadline: Instant,
    ) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        // With Nagle on, each answer written in several TLS records waits for the client's
        // delayed ACK.
        let _ = stream.set_nodelay(true);
        let now = Instant::now();
        Ok(Self {
            stream,
            peer,
            prefix: Vec::new(),
            guard,
            protocol,
            accepted: now,
            deadline,
            next_poll: now,
            poll_interval: MIN_PREFIX_POLL,
        })
    }

    pub(crate) fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Nothing arrived within DRAIN_IDLE of being accepted; a draining listener closes it.
    fn drained(&self) -> bool {
        self.prefix.is_empty() && self.accepted.elapsed() >= DRAIN_IDLE
    }

    /// Reads what is available and reports whether the first frame is complete. Idle connections
    /// back off from 10 ms to 250 ms.
    pub(crate) fn poll(&mut self) -> io::Result<AdmissionState> {
        let now = Instant::now();
        if now >= self.deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if encrypted_prefix_state(&self.prefix, self.protocol)? == AdmissionState::Ready {
            return Ok(AdmissionState::Ready);
        }
        if now < self.next_poll {
            return Ok(AdmissionState::Pending);
        }

        let limit = match self.protocol {
            AdmissionProtocol::Tls => onetdns_tls::record::MAX_CLIENT_HELLO_PREFIX,
            AdmissionProtocol::Dnscrypt => MAX_DNSCRYPT_TCP_QUERY_BYTES + 2,
        };
        let mut scratch = [0u8; 2048];
        loop {
            let remaining = limit.saturating_sub(self.prefix.len());
            if remaining == 0 {
                return Err(invalid_admission(
                    "Frame did not end within the encrypted TCP prefix limit",
                ));
            }
            let read_limit = remaining.min(scratch.len());
            match self.stream.read(&mut scratch[..read_limit]) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(read) => {
                    self.prefix
                        .try_reserve_exact(read)
                        .map_err(|_| io::ErrorKind::OutOfMemory)?;
                    self.prefix.extend_from_slice(&scratch[..read]);
                    self.poll_interval = MIN_PREFIX_POLL;
                    if encrypted_prefix_state(&self.prefix, self.protocol)? == AdmissionState::Ready
                    {
                        return Ok(AdmissionState::Ready);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.next_poll = Instant::now() + self.poll_interval;
                    self.poll_interval = (self.poll_interval * 2).min(MAX_PREFIX_POLL);
                    return Ok(AdmissionState::Pending);
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn into_ready(self) -> io::Result<(PrefixedTcp, SocketAddr, ConnectionGuard)> {
        self.stream.set_nonblocking(false)?;
        Ok((
            PrefixedTcp::new(self.stream, self.prefix),
            self.peer,
            self.guard,
        ))
    }
}

impl Read for PrefixedTcp {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.offset < self.prefix.len() {
            let available = &self.prefix[self.offset..];
            let count = available.len().min(output.len());
            output[..count].copy_from_slice(&available[..count]);
            self.offset += count;
            return Ok(count);
        }
        self.stream.read(output)
    }
}

impl Write for PrefixedTcp {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.stream.write(input)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// Checks lengths only; the TLS or DNSCrypt parser still decides what the bytes mean.
pub(crate) fn encrypted_prefix_state(
    prefix: &[u8],
    protocol: AdmissionProtocol,
) -> io::Result<AdmissionState> {
    match protocol {
        AdmissionProtocol::Tls => match onetdns_tls::record::client_hello_complete(prefix) {
            Ok(true) => Ok(AdmissionState::Ready),
            Ok(false) => Ok(AdmissionState::Pending),
            Err(message) => Err(invalid_admission(message)),
        },
        AdmissionProtocol::Dnscrypt => dnscrypt_prefix_state(prefix),
    }
}

fn dnscrypt_prefix_state(prefix: &[u8]) -> io::Result<AdmissionState> {
    if prefix.len() < 2 {
        return Ok(AdmissionState::Pending);
    }
    let frame_len = u16::from_be_bytes([prefix[0], prefix[1]]) as usize;
    if frame_len == 0 || frame_len > MAX_DNSCRYPT_TCP_QUERY_BYTES {
        return Err(invalid_admission(
            "DNSCrypt TCP frame length is out of range",
        ));
    }
    if prefix.len() >= frame_len + 2 {
        Ok(AdmissionState::Ready)
    } else {
        Ok(AdmissionState::Pending)
    }
}

fn invalid_admission(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Starts a connection thread with the stack bound above.
pub(crate) fn spawn_bounded_connection_thread<F, T>(
    name: &'static str,
    body: F,
) -> std::io::Result<thread::JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    thread::Builder::new()
        .name(name.into())
        .stack_size(CONNECTION_THREAD_STACK_BYTES)
        .spawn(body)
}

pub struct ConnectionLimiter {
    max_total: usize,
    state: Mutex<State>,
}

struct State {
    total: usize,
    clients: ClientCounts,
}

/// A taken slot, returned on drop.
pub struct ConnectionGuard {
    limiter: Arc<ConnectionLimiter>,
    ip: IpAddr,
}

/// Tracks only the connections of one listener.
pub struct ConnectionTracker {
    active: Mutex<usize>,
    idle: Condvar,
}

/// Wakes the listener's shutdown wait on drop.
pub struct ConnectionActivity {
    tracker: Arc<ConnectionTracker>,
}

impl Default for ConnectionLimiter {
    /// The process-wide limits shared by every encrypted TCP transport.
    fn default() -> Self {
        Self::with_limits(
            MAX_ENCRYPTED_TCP_CONNECTIONS,
            MAX_ENCRYPTED_TCP_CONNECTIONS_PER_IP,
        )
    }
}

impl ConnectionLimiter {
    fn with_limits(max_total: usize, max_per_ip: usize) -> Self {
        let max_total = max_total.max(1);
        Self {
            max_total,
            state: Mutex::new(State {
                total: 0,
                clients: ClientCounts::new(max_per_ip.max(1), max_total),
            }),
        }
    }

    #[cfg(test)]
    pub fn new(max_total: usize, max_per_ip: usize) -> Arc<Self> {
        Arc::new(Self::with_limits(max_total, max_per_ip))
    }

    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnectionGuard> {
        let mut state = self.state.lock_recover();
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

impl ConnectionTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            active: Mutex::new(0),
            idle: Condvar::new(),
        })
    }

    pub fn track(self: &Arc<Self>) -> ConnectionActivity {
        let mut active = self.active.lock_recover();
        *active += 1;
        ConnectionActivity {
            tracker: self.clone(),
        }
    }

    /// Waits for this listener's connections only, not for other listeners sharing admission.
    pub fn wait_until_idle(&self) {
        let mut active = self.active.lock_recover();
        while *active != 0 {
            active = self
                .idle
                .wait(active)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    /// False when connections are still open after `timeout`.
    pub fn wait_until_idle_for(&self, timeout: Duration) -> bool {
        let active = self.active.lock_recover();
        let (active, _) = self
            .idle
            .wait_timeout_while(active, timeout, |active| *active != 0)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *active == 0
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut state = self.limiter.state.lock_recover();
        state.total = state.total.saturating_sub(1);
        state.clients.remove(self.ip);
    }
}

impl Drop for ConnectionActivity {
    fn drop(&mut self) {
        let mut active = self.tracker.active.lock_recover();
        *active -= 1;
        let idle = *active == 0;
        drop(active);
        if idle {
            self.tracker.idle.notify_all();
        }
    }
}

/// How long an idle accept loop waits before checking its stop signals again; stopping a listener
/// waits up to this long.
const ACCEPT_WAIT: Duration = Duration::from_millis(100);

/// What ends an admitted connection. `shutdown` and `stop` close it at once; once `drain` is set it
/// answers what it receives and closes when idle (`DeadlineTcp::drain_on`).
#[derive(Clone, Default)]
pub(crate) struct ConnectionSignals {
    /// The server's. Without it, connections end only with their listener.
    pub(crate) shutdown: Option<Arc<AtomicBool>>,
    /// Set by the listener DRAIN_LIMIT after it starts draining.
    pub(crate) stop: Arc<AtomicBool>,
    /// Set when the listener stops accepting.
    pub(crate) drain: Arc<AtomicBool>,
}

impl ConnectionSignals {
    pub(crate) fn watch<S>(&self, stream: DeadlineTcp<S>) -> DeadlineTcp<S> {
        let stream = stream
            .stop_on(self.stop.clone())
            .drain_on(self.drain.clone());
        match &self.shutdown {
            Some(shutdown) => stream.stop_on(shutdown.clone()),
            None => stream,
        }
    }

    /// Whether the server or the listener is stopping; a connection ended by that is not counted
    /// as an error.
    pub(crate) fn stopping(&self) -> bool {
        self.aborted() || self.drain.load(Ordering::Relaxed)
    }

    fn aborted(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
            || self
                .shutdown
                .as_ref()
                .is_some_and(|shutdown| shutdown.load(Ordering::Relaxed))
    }
}

/// A connection whose first frame has arrived. Keep `hold` for as long as the connection is
/// served: it holds the admission slot and makes dropping the listener wait for the connection.
pub(crate) struct AdmittedConnection {
    pub(crate) stream: PrefixedTcp,
    pub(crate) peer: SocketAddr,
    pub(crate) signals: ConnectionSignals,
    pub(crate) hold: ConnectionHold,
}

pub(crate) struct ConnectionHold {
    _guard: ConnectionGuard,
    _activity: ConnectionActivity,
}

/// One listening address of an encrypted TCP transport. Dropping it stops accepting and waits for
/// the connections it accepted to finish, closing those still open after DRAIN_LIMIT.
///
/// The loop waits with `poll` and never changes the listening socket's blocking mode or connects
/// to it, so the socket can be handed to another process that keeps accepting on it.
pub(crate) struct EncryptedTcpListener {
    addr: SocketAddr,
    signals: ConnectionSignals,
    thread: Option<thread::JoinHandle<()>>,
    /// Signalled once the accept loop no longer reads the listening socket.
    stopped_accepting: Option<mpsc::Receiver<()>>,
    /// Kept so `socket` can hand it on; closed when the listener stops reading.
    socket: Option<TcpListener>,
}

impl EncryptedTcpListener {
    /// `transport` names the transport in logs and in the thread name. `serve` gets each
    /// connection on the accept thread and must not block. Setting `shutdown` ends every
    /// connection at once; without it they end with the listener.
    pub(crate) fn spawn<D, F>(
        listener: TcpListener,
        transport: &'static str,
        protocol: AdmissionProtocol,
        admission: Arc<ConnectionLimiter>,
        drops_source: D,
        shutdown: Option<Arc<AtomicBool>>,
        serve: F,
    ) -> io::Result<Self>
    where
        D: Fn(IpAddr) -> bool + Send + 'static,
        F: FnMut(AdmittedConnection) + Send + 'static,
    {
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let socket = listener.try_clone()?;
        let signals = ConnectionSignals {
            shutdown,
            ..ConnectionSignals::default()
        };
        let accept = AcceptLoop {
            transport,
            protocol,
            admission,
            drops_source,
            signals: signals.clone(),
        };
        let (stopped, stopped_accepting) = mpsc::channel();
        let thread = thread::Builder::new()
            .name(format!("{transport}-listener"))
            .spawn(move || accept.run(listener, stopped, serve))?;
        Ok(Self {
            addr,
            signals,
            thread: Some(thread),
            stopped_accepting: Some(stopped_accepting),
            socket: Some(socket),
        })
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// A duplicate of the listening socket, which stays open after this listener stops.
    pub(crate) fn socket(&self) -> io::Result<TcpListener> {
        match &self.socket {
            Some(socket) => socket.try_clone(),
            None => Err(io::Error::other("the listener has stopped reading")),
        }
    }

    /// Stops accepting and closes this listener's handles to the socket, returning once nothing in
    /// it reads the socket. Connections already accepted are served until it is dropped.
    pub(crate) fn stop_reading(&mut self) {
        self.signals.drain.store(true, Ordering::Release);
        if let Some(stopped) = self.stopped_accepting.take() {
            let _ = stopped.recv();
        }
        self.socket = None;
    }
}

impl Drop for EncryptedTcpListener {
    fn drop(&mut self) {
        self.signals.drain.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct AcceptLoop<D> {
    transport: &'static str,
    protocol: AdmissionProtocol,
    admission: Arc<ConnectionLimiter>,
    drops_source: D,
    signals: ConnectionSignals,
}

impl<D: Fn(IpAddr) -> bool> AcceptLoop<D> {
    fn run(
        self,
        listener: TcpListener,
        stopped_accepting: mpsc::Sender<()>,
        mut serve: impl FnMut(AdmittedConnection),
    ) {
        let tracker = ConnectionTracker::new();
        let mut pending = Vec::new();
        while !self.signals.stopping() {
            let wait = if pending.is_empty() {
                ACCEPT_WAIT
            } else {
                MIN_PREFIX_POLL
            };
            match onetdns_core::poll::readable(&listener, wait) {
                Ok(true) => self.accept_batch(&listener, &mut pending),
                Ok(false) => {}
                Err(error) => {
                    transport_observe::record_error(self.transport, "accept", None, error);
                    thread::sleep(MIN_PREFIX_POLL);
                }
            }
            self.admit_ready(&mut pending, &tracker, &mut serve);
        }
        drop(listener);
        let _ = stopped_accepting.send(());

        let until = Instant::now() + DRAIN_LIMIT;
        while !pending.is_empty() && !self.signals.aborted() && Instant::now() < until {
            pending.retain(|connection| !connection.drained());
            thread::sleep(MIN_PREFIX_POLL);
            self.admit_ready(&mut pending, &tracker, &mut serve);
        }
        drop(pending);
        if !tracker.wait_until_idle_for(until.saturating_duration_since(Instant::now())) {
            self.signals.stop.store(true, Ordering::Release);
            tracker.wait_until_idle();
        }
    }

    fn admit_ready(
        &self,
        pending: &mut Vec<PendingEncryptedConnection>,
        tracker: &Arc<ConnectionTracker>,
        serve: &mut impl FnMut(AdmittedConnection),
    ) {
        let failed_stage = match self.protocol {
            AdmissionProtocol::Tls => "handshake_admission",
            AdmissionProtocol::Dnscrypt => "frame_admission",
        };
        poll_pending_encrypted_connections(
            pending,
            |stream, peer, guard| {
                serve(AdmittedConnection {
                    stream,
                    peer,
                    signals: self.signals.clone(),
                    hold: ConnectionHold {
                        _guard: guard,
                        _activity: tracker.track(),
                    },
                })
            },
            |peer, error| {
                transport_observe::record_error(self.transport, failed_stage, Some(peer), error)
            },
        );
    }

    fn accept_batch(&self, listener: &TcpListener, pending: &mut Vec<PendingEncryptedConnection>) {
        for _ in 0..ENCRYPTED_ACCEPT_BATCH {
            let (stream, peer) = match listener.accept() {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    transport_observe::record_error(self.transport, "accept", None, error);
                    return;
                }
            };
            if (self.drops_source)(peer.ip()) {
                continue;
            }
            match PendingEncryptedConnection::admit(stream, peer, &self.admission, self.protocol) {
                Ok(Some(connection)) => pending.push(connection),
                Ok(None) => transport_observe::record_error(
                    self.transport,
                    "connection_limit",
                    Some(peer),
                    "maximum concurrent connections reached",
                ),
                Err(error) => transport_observe::record_error(
                    self.transport,
                    "admission_start",
                    Some(peer),
                    error,
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// Answers every framed message on a connection with `tag`.
    fn tagging_listener(
        listener: TcpListener,
        tag: u8,
        limiter: Arc<ConnectionLimiter>,
    ) -> EncryptedTcpListener {
        EncryptedTcpListener::spawn(
            listener,
            "handover-test",
            AdmissionProtocol::Dnscrypt,
            limiter,
            |_| false,
            None,
            move |connection: AdmittedConnection| {
                thread::spawn(move || {
                    let AdmittedConnection {
                        stream,
                        signals,
                        hold: _hold,
                        ..
                    } = connection;
                    let wait = Duration::from_secs(5);
                    let mut stream = signals.watch(DeadlineTcp::new(stream, Instant::now() + wait));
                    loop {
                        let mut len = [0u8; 2];
                        if stream.read_exact(&mut len).is_err() {
                            return;
                        }
                        let mut body = vec![0u8; usize::from(u16::from_be_bytes(len))];
                        if stream.read_exact(&mut body).is_err()
                            || stream.write_all(&[tag]).is_err()
                        {
                            return;
                        }
                        stream.set_deadline(Instant::now() + wait);
                    }
                });
            },
        )
        .unwrap()
    }

    fn ask(addr: SocketAddr) -> Option<u8> {
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        stream.write_all(&[0, 4, b'p', b'i', b'n', b'g']).ok()?;
        let mut tag = [0u8; 1];
        stream.read_exact(&mut tag).ok()?;
        Some(tag[0])
    }

    #[test]
    /// Connections keep being answered while a listener hands its socket to the next: on Unix the
    /// next starts accepting before the first stops, on Windows after it stops reading. Either way
    /// the first answers what it accepted, and the next answers what waits on the socket.
    fn listener_hands_its_socket_over_without_dropping_connections() {
        let mut first = tagging_listener(
            TcpListener::bind("127.0.0.1:0").unwrap(),
            1,
            Arc::new(ConnectionLimiter::default()),
        );
        let addr = first.addr();
        let stop = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(AtomicUsize::new(0));
        let by_next = Arc::new(AtomicUsize::new(0));
        let clients: Vec<_> = (0..4)
            .map(|_| {
                let (stop, failed, by_next) = (stop.clone(), failed.clone(), by_next.clone());
                thread::spawn(move || {
                    while !stop.load(Ordering::Acquire) {
                        match ask(addr) {
                            Some(2) => {
                                by_next.fetch_add(1, Ordering::Relaxed);
                            }
                            Some(_) => {}
                            None => {
                                failed.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                })
            })
            .collect();

        thread::sleep(Duration::from_millis(300));
        let socket = first.socket().unwrap();
        if cfg!(windows) {
            first.stop_reading();
        }
        let next = tagging_listener(socket, 2, Arc::new(ConnectionLimiter::default()));
        drop(first);
        thread::sleep(Duration::from_millis(500));
        stop.store(true, Ordering::Release);
        for client in clients {
            client.join().unwrap();
        }
        drop(next);

        assert_eq!(
            failed.load(Ordering::Relaxed),
            0,
            "넘기는 동안 답을 받지 못한 연결이 있습니다"
        );
        assert!(
            by_next.load(Ordering::Relaxed) > 0,
            "넘겨받은 쪽이 답하지 않았습니다"
        );
    }

    #[test]
    fn enforces_total_and_per_ip_and_recovers_on_drop() {
        let limiter = ConnectionLimiter::new(3, 2);
        let ip1 = "192.0.2.1".parse().unwrap();
        let ip2 = "192.0.2.2".parse().unwrap();
        let a = limiter.try_acquire(ip1).unwrap();
        let b = limiter.try_acquire(ip1).unwrap();
        assert!(limiter.try_acquire(ip1).is_none(), "IP별 상한");
        let c = limiter.try_acquire(ip2).unwrap();
        assert!(limiter.try_acquire(ip2).is_none(), "전역 상한");

        drop(a);
        assert!(
            limiter.try_acquire(ip1).is_some(),
            "guard 해제 후 즉시 회복"
        );
        drop((b, c));
    }

    #[test]
    fn mapped_ipv4_cannot_take_a_second_per_ip_budget() {
        let limiter = ConnectionLimiter::new(2, 1);
        let plain = limiter.try_acquire("192.0.2.1".parse().unwrap()).unwrap();
        assert!(
            limiter
                .try_acquire("::ffff:192.0.2.1".parse().unwrap())
                .is_none(),
            "mapped 표현으로 동일 IP 상한을 우회하면 안 됩니다"
        );
        drop(plain);
    }

    #[test]
    fn one_ipv6_prefix_cannot_take_every_slot_by_changing_addresses() {
        let limiter = ConnectionLimiter::new(8, 2);
        let held: Vec<_> = (1..=4)
            .map(|host| {
                limiter
                    .try_acquire(format!("2001:db8::{host}").parse().unwrap())
                    .unwrap()
            })
            .collect();
        assert!(
            limiter
                .try_acquire("2001:db8::ffff:5".parse().unwrap())
                .is_none(),
            "같은 /64 의 다른 주소로 절반을 넘겨 받으면 안 됩니다"
        );
        assert!(limiter
            .try_acquire("2001:db8:0:1::1".parse().unwrap())
            .is_some());
        drop(held);
    }

    #[test]
    fn encrypted_connection_threads_have_an_explicit_stack_bound() {
        assert_eq!(CONNECTION_THREAD_STACK_BYTES, 512 * 1024);
        let thread = spawn_bounded_connection_thread("bounded-connection-test", || {
            std::thread::current().name() == Some("bounded-connection-test")
        })
        .unwrap();
        assert!(thread.join().unwrap());
    }

    #[test]
    fn detached_connection_threads_can_be_waited_without_retaining_handles() {
        let tracker = ConnectionTracker::new();
        let activity = tracker.track();
        let thread = spawn_bounded_connection_thread("detached-connection-test", move || {
            std::thread::sleep(Duration::from_millis(20));
            drop(activity);
        })
        .unwrap();
        drop(thread);

        tracker.wait_until_idle();
        let next = tracker.track();
        drop(next);
        tracker.wait_until_idle();
    }

    #[test]
    fn listener_lifetime_wait_is_local_to_its_tracker() {
        let first = ConnectionTracker::new();
        let second = ConnectionTracker::new();
        let first_activity = first.track();
        let second_activity = second.track();

        drop(first_activity);
        first.wait_until_idle();
        drop(second_activity);
        second.wait_until_idle();
    }

    #[test]
    fn default_admission_has_one_cross_transport_budget() {
        let limiter = Arc::new(ConnectionLimiter::default());
        let ip = "192.0.2.1".parse().unwrap();
        let mut connections = Vec::new();
        for _ in 0..MAX_ENCRYPTED_TCP_CONNECTIONS_PER_IP {
            connections.push(limiter.try_acquire(ip).unwrap());
        }
        assert!(
            limiter.try_acquire(ip).is_none(),
            "다른 전송 이름으로 들어와도 동일 IP 상한을 더 얻으면 안 됩니다"
        );
        for octet in 2..=8 {
            let ip = format!("192.0.2.{octet}").parse().unwrap();
            for _ in 0..MAX_ENCRYPTED_TCP_CONNECTIONS_PER_IP {
                connections.push(limiter.try_acquire(ip).unwrap());
            }
        }
        assert_eq!(connections.len(), MAX_ENCRYPTED_TCP_CONNECTIONS);
        assert!(
            limiter
                .try_acquire("198.51.100.1".parse().unwrap())
                .is_none(),
            "수신 주소나 전송이 달라도 프로세스 전체 상한을 넘으면 안 됩니다"
        );
    }

    fn tls_record(payload: &[u8]) -> Vec<u8> {
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    #[test]
    fn tls_admission_requires_a_complete_client_hello() {
        let hello = [1, 0, 0, 6, 3, 3, 0, 0, 0, 0];
        let first = tls_record(&hello[..2]);
        assert_eq!(
            encrypted_prefix_state(&first, AdmissionProtocol::Tls).unwrap(),
            AdmissionState::Pending
        );
        let mut complete = first;
        complete.extend_from_slice(&tls_record(&hello[2..]));
        assert_eq!(
            encrypted_prefix_state(&complete, AdmissionProtocol::Tls).unwrap(),
            AdmissionState::Ready
        );
    }

    #[test]
    fn tls_admission_rejects_oversized_lengths() {
        assert!(encrypted_prefix_state(&[22, 3, 1, 0x40, 0x01], AdmissionProtocol::Tls).is_err());
        let oversized_hello = tls_record(&[1, 1, 0, 1]);
        assert!(encrypted_prefix_state(&oversized_hello, AdmissionProtocol::Tls).is_err());
    }

    #[test]
    fn dnscrypt_admission_requires_the_complete_bounded_frame() {
        assert_eq!(
            encrypted_prefix_state(&[0, 3, 1, 2], AdmissionProtocol::Dnscrypt).unwrap(),
            AdmissionState::Pending
        );
        assert_eq!(
            encrypted_prefix_state(&[0, 3, 1, 2, 3], AdmissionProtocol::Dnscrypt).unwrap(),
            AdmissionState::Ready
        );
        assert!(
            encrypted_prefix_state(&[0x20, 0x01], AdmissionProtocol::Dnscrypt).is_err(),
            "8KiB를 넘는 선언은 본문을 기다리면 안 됩니다"
        );
    }

    #[test]
    fn prefixed_tcp_replays_admission_bytes_before_the_socket() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        client.write_all(b"tail").unwrap();

        let mut stream = PrefixedTcp::new(server, b"prefix-".to_vec());
        let mut bytes = [0u8; 11];
        stream.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"prefix-tail");
    }

    #[test]
    fn admitted_connections_send_without_waiting_for_acks() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, peer) = listener.accept().unwrap();
        assert!(
            !server.nodelay().unwrap(),
            "대조군: 받은 소켓은 Nagle 이 켜져 있습니다"
        );
        let limiter = ConnectionLimiter::new(1, 1);
        let guard = limiter.try_acquire(peer.ip()).unwrap();
        let pending =
            PendingEncryptedConnection::new(server, peer, guard, AdmissionProtocol::Tls).unwrap();
        assert!(pending.stream.nodelay().unwrap());
    }

    #[test]
    fn pending_connection_promotes_only_after_complete_frame() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, peer) = listener.accept().unwrap();
        let limiter = ConnectionLimiter::new(1, 1);
        let guard = limiter.try_acquire(peer.ip()).unwrap();
        let mut pending =
            PendingEncryptedConnection::new(server, peer, guard, AdmissionProtocol::Dnscrypt)
                .unwrap();

        client.write_all(&[0, 3, 1, 2]).unwrap();
        assert_eq!(pending.poll().unwrap(), AdmissionState::Pending);
        client.write_all(&[3]).unwrap();
        let ready_by = Instant::now() + Duration::from_secs(1);
        while pending.poll().unwrap() != AdmissionState::Ready {
            assert!(Instant::now() < ready_by);
            thread::sleep(Duration::from_millis(5));
        }

        let (mut stream, promoted_peer, _guard) = pending.into_ready().unwrap();
        assert_eq!(promoted_peer, peer);
        let mut frame = [0u8; 5];
        stream.read_exact(&mut frame).unwrap();
        assert_eq!(frame, [0, 3, 1, 2, 3]);
    }

    #[test]
    fn pending_connection_observes_absolute_deadline() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, peer) = listener.accept().unwrap();
        let limiter = ConnectionLimiter::new(1, 1);
        let guard = limiter.try_acquire(peer.ip()).unwrap();
        let mut pending = PendingEncryptedConnection::with_deadline(
            server,
            peer,
            guard,
            AdmissionProtocol::Tls,
            Instant::now(),
        )
        .unwrap();

        assert_eq!(pending.poll().unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    /// Holds one pending connection on a single-slot limiter while `misbehave` drives the client,
    /// polls until the connection fails, checks that the failure returned the slot, and returns
    /// the error.
    fn failed_admission(
        protocol: AdmissionProtocol,
        deadline: Duration,
        misbehave: impl FnOnce(&mut TcpStream) + Send + 'static,
    ) -> io::Error {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, peer) = listener.accept().unwrap();
        let limiter = ConnectionLimiter::new(1, 1);
        let guard = limiter.try_acquire(peer.ip()).unwrap();
        let connection = PendingEncryptedConnection::with_deadline(
            server,
            peer,
            guard,
            protocol,
            Instant::now() + deadline,
        )
        .unwrap();
        let mut pending = vec![connection];
        assert!(
            limiter.try_acquire(peer.ip()).is_none(),
            "대조군이 무효입니다. 기다리는 연결이 자리를 잡지 않았습니다"
        );

        let client = thread::spawn(move || {
            misbehave(&mut client);
            client
        });
        let give_up = Instant::now() + Duration::from_secs(5);
        let mut failure = None;
        while failure.is_none() {
            assert!(
                Instant::now() < give_up,
                "기다리는 연결이 실패하지 않았습니다"
            );
            thread::sleep(MIN_PREFIX_POLL);
            poll_pending_encrypted_connections(
                &mut pending,
                |_, _, _| panic!("받아들이면 안 되는 연결을 받아들였습니다"),
                |_, error| failure = Some(error),
            );
        }
        drop(client.join().unwrap());
        assert!(pending.is_empty());
        assert!(
            limiter.try_acquire(peer.ip()).is_some(),
            "실패한 연결이 자리를 돌려주지 않았습니다"
        );
        failure.unwrap()
    }

    #[test]
    fn failed_admission_returns_its_connection_slot() {
        let long = Duration::from_secs(30);

        let closed = failed_admission(AdmissionProtocol::Dnscrypt, long, |client| {
            client.write_all(&[0, 3, 1]).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
        });
        assert_eq!(closed.kind(), io::ErrorKind::UnexpectedEof);

        let oversized = failed_admission(AdmissionProtocol::Dnscrypt, long, |client| {
            client.write_all(&[0x20, 0x01]).unwrap();
        });
        assert_eq!(
            oversized.to_string(),
            "DNSCrypt TCP frame length is out of range"
        );

        // A ClientHello cut into one-byte records never completes within the prefix limit.
        let flood = failed_admission(AdmissionProtocol::Tls, long, |client| {
            let mut bytes = tls_record(&[1, 0, 0x75, 0x30]);
            while bytes.len() <= onetdns_tls::record::MAX_CLIENT_HELLO_PREFIX {
                bytes.extend_from_slice(&tls_record(&[0]));
            }
            let _ = client.write_all(&bytes);
        });
        assert_eq!(
            flood.to_string(),
            "Frame did not end within the encrypted TCP prefix limit"
        );

        let silent = failed_admission(AdmissionProtocol::Tls, Duration::from_millis(100), |_| {});
        assert_eq!(silent.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    /// A connection still waiting for its first frame holds its slot, so the listener refuses the
    /// next one; the slot comes back when the waiting peer leaves, and again when a served
    /// connection ends.
    fn listener_refuses_at_the_cap_and_recovers() {
        let listener = tagging_listener(
            TcpListener::bind("127.0.0.1:0").unwrap(),
            1,
            ConnectionLimiter::new(1, 1),
        );
        let addr = listener.addr();
        let ask_until_answered = || {
            let give_up = Instant::now() + Duration::from_secs(5);
            while ask(addr).is_none() {
                assert!(Instant::now() < give_up, "상한에서 풀려나지 않았습니다");
                thread::sleep(MIN_PREFIX_POLL);
            }
        };

        let waiting = TcpStream::connect(addr).unwrap();
        assert_eq!(
            ask(addr),
            None,
            "첫 프레임을 기다리는 연결이 자리를 차지하지 않았습니다"
        );
        drop(waiting);
        ask_until_answered();
        ask_until_answered();
        drop(listener);
    }
}
