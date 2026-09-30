/*!
 * @brief 연결 수 제한.
 *
 * @details 전체 수와 주소별 수를 함께 묶는다. 전체만 묶으면 한 주소가 슬롯을 다 차지해
 *          나머지를 굶긴다.
 */

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use onetdns_core::MutexExt;

/** @brief 프로세스 전체가 동시에 받을 암호화 TCP 연결 수. */
pub(crate) const MAX_ENCRYPTED_TCP_CONNECTIONS: usize = 512;
/** @brief 한 주소가 모든 암호화 TCP 전송에서 함께 차지할 수 있는 연결 수. */
pub(crate) const MAX_ENCRYPTED_TCP_CONNECTIONS_PER_IP: usize = 64;

/**
 * @brief 암호화 TCP 연결 하나가 예약하는 스레드 스택.
 * @details TLS·DNSCrypt 처리에는 컨트롤 플레인보다 여유를 두되 OS 기본 스택을 연결마다 예약하지
 *          않는다. 프로세스 전체 512개 연결 상한에서 명시적으로 요청하는 스택 합은 256 MiB다.
 */
pub(crate) const CONNECTION_THREAD_STACK_BYTES: usize = 512 * 1024;
/** @brief 한 번에 accept한 뒤 pending 입력과 종료를 다시 확인할 연결 수. */
pub(crate) const ENCRYPTED_ACCEPT_BATCH: usize = 64;

/** @brief TLS record 머리 크기. */
const TLS_RECORD_HEADER_BYTES: usize = 5;
/** @brief TLS 1.2/1.3 평문 record의 프로토콜 상한. */
const MAX_TLS_PLAINTEXT_RECORD_BYTES: usize = 16 * 1024;
/** @brief 스레드 승격 전에 보관할 ClientHello wire prefix의 절대 상한. */
const MAX_TLS_CLIENT_HELLO_PREFIX_BYTES: usize = 64 * 1024;
/** @brief DNSCrypt TCP 요청의 기존 프로토콜 상한. */
const MAX_DNSCRYPT_TCP_QUERY_BYTES: usize = 8192;
/** @brief 첫 frame을 기다리는 절대 데드라인. */
const ENCRYPTED_PREFIX_TIMEOUT: Duration = Duration::from_secs(30);
/** @brief 새 바이트가 없을 때 처음 다시 확인할 간격. */
const MIN_PREFIX_POLL: Duration = Duration::from_millis(10);
/** @brief 정지 연결의 syscall 빈도를 제한하는 최대 확인 간격. */
const MAX_PREFIX_POLL: Duration = Duration::from_millis(250);

/** @brief 스레드 없는 admission이 구분할 암호화 TCP framing. */
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionProtocol {
    /** @brief TLS record 안의 첫 ClientHello. */
    Tls,
    /** @brief 2바이트 길이 접두사의 DNSCrypt frame. */
    Dnscrypt,
}

/** @brief 현재 prefix만으로 처리 스레드를 시작해도 되는지. */
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionState {
    /** @brief 완전한 첫 frame이 아직 없다. */
    Pending,
    /** @brief 완전한 첫 frame이 있다. */
    Ready,
}

/**
 * @brief admission이 먼저 읽은 바이트를 기존 핸들러에 손실 없이 재생한다.
 * @details prefix를 모두 읽은 뒤에는 원래 TCP stream에 그대로 위임한다.
 */
pub(crate) struct PrefixedTcp {
    /** @brief 실제 연결. */
    stream: TcpStream,
    /** @brief admission이 먼저 읽은 바이트. */
    prefix: Box<[u8]>,
    /** @brief 핸들러에 이미 돌려준 prefix 길이. */
    offset: usize,
}

/** @brief 처리 스레드 없이 첫 암호화 frame을 모으는 연결. */
pub(crate) struct PendingEncryptedConnection {
    /** @brief 아직 nonblocking인 실제 연결. */
    stream: TcpStream,
    /** @brief 관측과 처리에 쓸 상대 주소. */
    peer: SocketAddr,
    /** @brief 기존 핸들러에 다시 돌려줄 입력 prefix. */
    prefix: Vec<u8>,
    /** @brief 대기 중에도 전역·주소별 연결 몫을 차지한다. */
    guard: ConnectionGuard,
    /** @brief 완결을 판별할 framing. */
    protocol: AdmissionProtocol,
    /** @brief 첫 frame 전체가 도착해야 하는 시각. */
    deadline: Instant,
    /** @brief 다음 nonblocking read를 시도할 시각. */
    next_poll: Instant,
    /** @brief 입력이 없는 연결에 적용할 적응형 확인 간격. */
    poll_interval: Duration,
}

impl PrefixedTcp {
    /** @brief 원래 연결 앞에 admission prefix를 붙인다. */
    pub(crate) fn new(stream: TcpStream, prefix: Vec<u8>) -> Self {
        Self {
            stream,
            prefix: prefix.into_boxed_slice(),
            offset: 0,
        }
    }

    /** @brief 읽기 제한시간을 실제 연결에 설정한다. */
    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }

    /** @brief 쓰기 제한시간을 실제 연결에 설정한다. */
    pub(crate) fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_write_timeout(timeout)
    }

    /** @brief 상대 주소를 실제 연결에서 읽는다. */
    pub(crate) fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }
}

/**
 * @brief pending 연결들을 한 번씩 확인하고 완결된 것만 기존 핸들러로 넘긴다.
 * @param ready blocking stream, 상대 주소, admission guard를 받을 콜백.
 * @param failed 거부·데드라인·소켓 오류를 관측할 콜백.
 */
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
    /** @brief 전역·주소별 몫을 잡고 첫 frame admission을 시작한다. */
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

    /** @brief 연결을 nonblocking admission에 넣는다. */
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

    /** @brief 지정한 절대 데드라인으로 admission 연결을 만든다. */
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

    /** @brief 이 연결의 상대 주소. */
    pub(crate) fn peer(&self) -> SocketAddr {
        self.peer
    }

    /**
     * @brief 지금 받을 수 있는 바이트만 모아 첫 frame 완결 여부를 돌려준다.
     * @details 입력 없는 연결은 확인 간격을 10ms에서 250ms까지 늘린다.
     */
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

    /** @brief 완결된 prefix를 보존한 blocking 처리 연결로 승격한다. */
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
    /** @brief prefix를 먼저, 실제 연결을 나중에 읽는다. */
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
    /** @brief 쓰기는 실제 연결에 바로 전달한다. */
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.stream.write(input)
    }

    /** @brief flush도 실제 연결에 전달한다. */
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/** @brief 첫 암호화 frame이 완결됐는지 길이만 검사한다. */
pub(crate) fn encrypted_prefix_state(
    prefix: &[u8],
    protocol: AdmissionProtocol,
) -> io::Result<AdmissionState> {
    match protocol {
        AdmissionProtocol::Tls => tls_client_hello_prefix_state(prefix),
        AdmissionProtocol::Dnscrypt => dnscrypt_prefix_state(prefix),
    }
}

/** @brief 여러 TLS handshake record에 걸친 첫 ClientHello 완결 여부를 센다. */
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

/** @brief DNSCrypt TCP 길이 접두사와 본문이 모두 도착했는지 검사한다. */
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

/** @brief admission framing 오류를 같은 종류로 만든다. */
fn invalid_admission(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/** @brief 명시적 스택 상한으로 암호화 연결 스레드를 시작한다. */
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

/** @brief 연결 수를 세고 슬롯을 나눠 주는 것. */
pub struct ConnectionLimiter {
    /** @brief 동시에 받을 연결 수. */
    max_total: usize,
    /** @brief 주소 하나가 차지할 수 있는 연결 수. */
    max_per_ip: usize,
    /** @brief 지금 세고 있는 것. */
    state: Mutex<State>,
}

#[derive(Default)]
/** @brief 지금 열려 있는 연결 수. */
struct State {
    /** @brief 지금 열려 있는 연결 수. */
    total: usize,
    /** @brief 주소별 연결 수. */
    per_ip: HashMap<IpAddr, usize>,
}

/** @brief 잡은 슬롯. 사라질 때 자동으로 돌려준다. */
pub struct ConnectionGuard {
    /** @brief 이 슬롯을 돌려줄 곳. */
    limiter: Arc<ConnectionLimiter>,
    /** @brief 이 연결의 상대 주소. */
    ip: IpAddr,
}

/** @brief 리스너 하나에 속한 연결 수명만 추적한다. */
pub struct ConnectionTracker {
    /** @brief 이 리스너에서 아직 끝나지 않은 연결 수. */
    active: Mutex<usize>,
    /** @brief 마지막 연결이 끝났음을 리스너 종료 경로에 알린다. */
    idle: Condvar,
}

/** @brief 추적 중인 연결 하나. 사라지면 리스너 종료 대기를 깨운다. */
pub struct ConnectionActivity {
    /** @brief 이 연결을 세는 리스너. */
    tracker: Arc<ConnectionTracker>,
}

impl Default for ConnectionLimiter {
    /** @brief 모든 암호화 TCP 전송이 공유할 프로세스 상한으로 만든다. */
    fn default() -> Self {
        Self::with_limits(
            MAX_ENCRYPTED_TCP_CONNECTIONS,
            MAX_ENCRYPTED_TCP_CONNECTIONS_PER_IP,
        )
    }
}

impl ConnectionLimiter {
    /** @brief 실제 상한을 가진 값을 만든다. */
    fn with_limits(max_total: usize, max_per_ip: usize) -> Self {
        Self {
            max_total: max_total.max(1),
            max_per_ip: max_per_ip.max(1),
            state: Mutex::new(State::default()),
        }
    }

    /** @brief 전체와 주소별 상한으로 만든다. */
    #[cfg(test)]
    pub fn new(max_total: usize, max_per_ip: usize) -> Arc<Self> {
        Arc::new(Self::with_limits(max_total, max_per_ip))
    }

    /** @brief 슬롯을 잡는다. 어느 한쪽 상한이라도 넘으면 잡지 않는다. */
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnectionGuard> {
        let ip = match ip {
            IpAddr::V6(value) => value
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(value)),
            value => value,
        };
        let mut state = self.state.lock_recover();
        let per_ip = state.per_ip.get(&ip).copied().unwrap_or(0);
        if state.total >= self.max_total || per_ip >= self.max_per_ip {
            return None;
        }
        state.total += 1;
        state.per_ip.insert(ip, per_ip + 1);
        Some(ConnectionGuard {
            limiter: self.clone(),
            ip,
        })
    }
}

impl ConnectionTracker {
    /** @brief 빈 리스너 추적기를 만든다. */
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            active: Mutex::new(0),
            idle: Condvar::new(),
        })
    }

    /** @brief 이 리스너에 연결 하나가 들어왔음을 기록한다. */
    pub fn track(self: &Arc<Self>) -> ConnectionActivity {
        let mut active = self.active.lock_recover();
        *active += 1;
        ConnectionActivity {
            tracker: self.clone(),
        }
    }

    /**
     * @brief 이 리스너가 이미 받은 연결이 모두 끝날 때까지 기다린다.
     * @details 전역 admission의 다른 리스너 연결은 기다리지 않는다.
     */
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
    /** @brief 슬롯을 돌려준다. */
    fn drop(&mut self) {
        let mut state = self.limiter.state.lock_recover();
        state.total = state.total.saturating_sub(1);
        if let Some(count) = state.per_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.per_ip.remove(&self.ip);
            }
        }
    }
}

impl Drop for ConnectionActivity {
    /** @brief 이 리스너의 연결 수명을 끝낸다. */
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

/**
 * @brief 리스너를 깨워 종료를 알아차리게 한다.
 * @details 대기 중인 accept는 신호만으로 풀리지 않는다. 스스로 한 번 접속해 깨운다.
 */
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
/** @brief 두 상한이 함께 걸리고 슬롯이 제대로 돌아오는지. */
mod tests {
    use super::*;

    #[test]
    /** @brief 전체와 주소별 상한이 함께 걸리고, 놓으면 다시 잡히는지. */
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
    /** @brief IPv4와 IPv4-mapped IPv6가 같은 주소별 몫을 쓰는지. */
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
    /** @brief 모든 주소에 묶인 리스너도 깨워지는지. */
    fn wake_connects_to_unspecified_listener() {
        let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = std::thread::spawn(move || listener.accept().is_ok());
        wake_tcp_listener(addr);
        assert!(accept.join().unwrap());
    }

    #[test]
    /** @brief 암호화 TCP 연결 스레드가 OS 기본값 대신 작은 명시적 스택을 쓰는지. */
    fn encrypted_connection_threads_have_an_explicit_stack_bound() {
        assert_eq!(CONNECTION_THREAD_STACK_BYTES, 512 * 1024);
        let thread = spawn_bounded_connection_thread("bounded-connection-test", || {
            std::thread::current().name() == Some("bounded-connection-test")
        })
        .unwrap();
        assert!(thread.join().unwrap());
    }

    #[test]
    /** @brief JoinHandle을 보관하지 않아도 종료 대기가 정확히 연결 수명과 함께 끝나는지. */
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
    /** @brief 한 리스너의 종료가 공유 admission을 쓰는 다른 리스너를 기다리지 않는지. */
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
    /** @brief 기본 admission이 전송별 인스턴스가 아니라 공유 프로세스 상한인지. */
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

    /** @brief 테스트용 TLS record를 만든다. */
    fn tls_record(payload: &[u8]) -> Vec<u8> {
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    #[test]
    /** @brief ClientHello가 record 사이에서 갈려도 완결 전에는 승격하지 않는지. */
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
    /** @brief TLS record와 ClientHello 길이가 admission 상한을 넘으면 즉시 거부하는지. */
    fn tls_admission_rejects_oversized_lengths() {
        assert!(encrypted_prefix_state(&[22, 3, 1, 0x40, 0x01], AdmissionProtocol::Tls).is_err());
        let oversized_hello = tls_record(&[1, 1, 0, 1]);
        assert!(encrypted_prefix_state(&oversized_hello, AdmissionProtocol::Tls).is_err());
    }

    #[test]
    /** @brief DNSCrypt도 길이 접두사의 전체 프레임이 오기 전에는 승격하지 않는지. */
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
    /** @brief admission이 먼저 읽은 바이트가 기존 핸들러에 한 번만 그대로 재생되는지. */
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
    /** @brief 부분 입력은 스레드 승격 없이 머물고, 완결 뒤 원문 전체를 돌려주는지. */
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
    /** @brief 첫 frame 데드라인이 지나면 대기 연결을 즉시 폐기할 수 있는지. */
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
