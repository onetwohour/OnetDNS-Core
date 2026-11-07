//! Connection admission for encrypted TCP. Total and per-client counts are bounded together:
//! with only a total, one client could take every slot.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use onetdns_core::admission::ClientCounts;
use onetdns_core::MutexExt;

pub(crate) const MAX_ENCRYPTED_TCP_CONNECTIONS: usize = 512;
/// Shared by every encrypted TCP transport.
pub(crate) const MAX_ENCRYPTED_TCP_CONNECTIONS_PER_IP: usize = 64;

/// Set explicitly so a connection does not reserve the OS default stack.
pub(crate) const CONNECTION_THREAD_STACK_BYTES: usize = 512 * 1024;
/// Accepts per round before pending input and shutdown are checked again.
pub(crate) const ENCRYPTED_ACCEPT_BATCH: usize = 64;

const TLS_RECORD_HEADER_BYTES: usize = 5;
const MAX_TLS_PLAINTEXT_RECORD_BYTES: usize = 16 * 1024;
/// Bound on the buffered ClientHello before a connection gets a thread.
const MAX_TLS_CLIENT_HELLO_PREFIX_BYTES: usize = 64 * 1024;
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
        let now = Instant::now();
        Ok(Self {
            stream,
            peer,
            prefix: Vec::new(),
            guard,
            protocol,
            deadline,
            next_poll: now,
            poll_interval: MIN_PREFIX_POLL,
        })
    }

    pub(crate) fn peer(&self) -> SocketAddr {
        self.peer
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
            AdmissionProtocol::Tls => MAX_TLS_CLIENT_HELLO_PREFIX_BYTES,
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
        AdmissionProtocol::Tls => tls_client_hello_prefix_state(prefix),
        AdmissionProtocol::Dnscrypt => dnscrypt_prefix_state(prefix),
    }
}

fn tls_client_hello_prefix_state(prefix: &[u8]) -> io::Result<AdmissionState> {
    if prefix.len() > MAX_TLS_CLIENT_HELLO_PREFIX_BYTES {
        return Err(invalid_admission("TLS ClientHello prefix exceeds 64 KiB"));
    }

    let mut record_offset = 0usize;
    let mut handshake_header = [0u8; 4];
    let mut handshake_bytes = 0usize;
    let mut handshake_total = None;

    while record_offset < prefix.len() {
        if prefix.len() - record_offset < TLS_RECORD_HEADER_BYTES {
            return Ok(AdmissionState::Pending);
        }
        let header = &prefix[record_offset..record_offset + TLS_RECORD_HEADER_BYTES];
        if header[0] != 22 || header[1] != 3 {
            return Err(invalid_admission(
                "The first TLS message must be a handshake record",
            ));
        }
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if record_len == 0 || record_len > MAX_TLS_PLAINTEXT_RECORD_BYTES {
            return Err(invalid_admission("TLS record length is out of range"));
        }
        let record_end = record_offset + TLS_RECORD_HEADER_BYTES + record_len;
        if record_end > prefix.len() {
            return Ok(AdmissionState::Pending);
        }

        let payload = &prefix[record_offset + TLS_RECORD_HEADER_BYTES..record_end];
        if handshake_bytes < handshake_header.len() {
            let copy = (handshake_header.len() - handshake_bytes).min(payload.len());
            handshake_header[handshake_bytes..handshake_bytes + copy]
                .copy_from_slice(&payload[..copy]);
        }
        handshake_bytes = handshake_bytes.saturating_add(payload.len());

        if handshake_total.is_none() && handshake_bytes >= handshake_header.len() {
            if handshake_header[0] != 1 {
                return Err(invalid_admission(
                    "The first TLS handshake message must be a ClientHello",
                ));
            }
            let body_len = ((handshake_header[1] as usize) << 16)
                | ((handshake_header[2] as usize) << 8)
                | handshake_header[3] as usize;
            let total = handshake_header.len() + body_len;
            if total + TLS_RECORD_HEADER_BYTES > MAX_TLS_CLIENT_HELLO_PREFIX_BYTES {
                return Err(invalid_admission("TLS ClientHello length exceeds 64 KiB"));
            }
            handshake_total = Some(total);
        }
        if handshake_total.is_some_and(|total| handshake_bytes >= total) {
            return Ok(AdmissionState::Ready);
        }
        record_offset = record_end;
    }

    Ok(AdmissionState::Pending)
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

/// A blocked `accept` does not return on a flag; connecting once wakes it.
pub fn wake_tcp_listener(addr: SocketAddr) {
    let addr = match addr {
        SocketAddr::V4(addr) if addr.ip().is_unspecified() => {
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), addr.port())
        }
        SocketAddr::V6(addr) if addr.ip().is_unspecified() => {
            SocketAddr::new(Ipv6Addr::LOCALHOST.into(), addr.port())
        }
        addr => addr,
    };
    if let Err(e) = TcpStream::connect_timeout(&addr, Duration::from_millis(250)) {
        onetdns_core::debug!(event = "listener.wake_failed", addr = %addr, error = %e, "Could not wake the accept thread; shutdown is delayed until the pending accept returns");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn wake_connects_to_unspecified_listener() {
        let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = std::thread::spawn(move || listener.accept().is_ok());
        wake_tcp_listener(addr);
        assert!(accept.join().unwrap());
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
}
