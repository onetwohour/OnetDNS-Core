/*!
 * @brief Do53 TCP 리스너와 연결 처리 워커.
 *
 * @details 수락과 처리를 분리한다. 수락 스레드는 연결을 받아 유계 큐에 넣기만 하고,
 *          처리 워커가 그 큐를 나눠 먹는다. 한 덩어리로 두면 느린 클라이언트 하나가
 *          수락 스레드를 붙들어 새 연결이 아예 받아지지 않는다.
 */

use std::collections::HashMap;
use std::io::{self, ErrorKind, IoSlice, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use onetdns_core::IpNet;
use onetdns_proto::{Message, Writer};

use crate::{Handler, RequestCtx, Transport, WireDisposition};

/** @brief PROXY 헤더가 다 도착할 때까지 기다릴 시간. */
const PROXY_HEADER_DEADLINE: Duration = Duration::from_secs(5);

/** @brief 메시지 하나를 다 읽을 때까지 기다릴 시간. 느린 연결이 워커를 붙들지 못하게 한다. */
const DNS_MESSAGE_DEADLINE: Duration = Duration::from_secs(10);

/** @brief 연결 처리 워커 수의 하한. */
const MIN_CONNECTION_WORKERS: usize = 8;

/** @brief 연결 처리 워커 수의 상한. */
const MAX_CONNECTION_WORKERS: usize = 64;

/** @brief 수락 큐 길이의 하한. */
const MIN_CONNECTION_QUEUE: usize = 256;

/**
 * @brief 수락 큐 길이의 상한.
 * @details 큐가 유계여야 한다. 무한 큐는 부하가 몰릴 때 메모리로 흘러들어가 결국
 *          응답 불가로 이어진다. 넘치면 새 연결을 거절하는 편이 낫다.
 */
const MAX_CONNECTION_QUEUE: usize = 4096;

/**
 * @brief PROXY 모드에서 한 출발지 IP가 열 수 있는 연결 수.
 * @details 이 모드에서는 모든 연결이 로드밸런서 주소 하나에서 오므로 한도를 크게 잡는다.
 *          평소 한도를 쓰면 프록시 뒤 전체가 그 한도를 나눠 쓰게 된다.
 */
const MAX_PROXY_CONNECTIONS_PER_IP: usize = 64;

/**
 * @brief 2바이트 길이 접두사를 붙여 메시지를 쓴다.
 * @details 접두사와 본문을 한 번의 벡터 쓰기로 보낸다. 나눠 쓰면 접두사만 담긴
 *          작은 패킷이 따로 나가 왕복이 늘어난다.
 * @note 부분 쓰기가 접두사 중간에서 끊길 수 있어, 남은 위치를 계산해 이어 쓴다.
 */
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

/** @brief 수락된 연결: 스트림, 상대 주소, 그리고 슬롯을 붙잡고 있는 가드. */
pub(crate) type Accepted = (TcpStream, SocketAddr, ConnectionGuard);

/** @brief 연결 처리 워커 풀 설정. */
pub(crate) struct ConnectionPoolConfig {
    /** @brief 새 연결을 확인하는 주기. */
    pub poll: Duration,
    /** @brief 앞단 프록시가 알려 주는 주소를 읽을지. */
    pub proxy_protocol: bool,
    /** @brief 그 알림을 믿어 줄 프록시 주소들. */
    pub trusted_proxies: Arc<Vec<IpNet>>,
    /** @brief 워커 수. */
    pub workers: usize,
    /** @brief 대기열 크기. */
    pub queue_capacity: usize,
    /** @brief 워커를 코어에 묶을지. */
    pub pin_cores: bool,
    /** @brief 고정할 코어 범위. 수락 스레드와 같은 코어들에 나눠 붙인다. */
    pub pin_span: usize,
}

/**
 * @brief 동시 연결 수를 전체와 IP별로 제한한다.
 * @details IP별 한도가 있어야 클라이언트 하나가 연결을 잔뜩 열어 다른 모두를 굶기지 못한다.
 */
pub(crate) struct ConnectionLimiter {
    /** @brief 동시에 받을 연결 수. */
    max_total: usize,
    /** @brief 주소 하나가 차지할 수 있는 연결 수. */
    max_per_ip: usize,
    /** @brief 지금 세고 있는 것. */
    state: Mutex<LimitState>,
}

/** @brief 제한기의 계수 상태. */
#[derive(Default)]
struct LimitState {
    /** @brief 지금 열려 있는 연결 수. */
    total: usize,
    /** @brief 주소별 연결 수. */
    per_ip: HashMap<IpAddr, usize>,
}

/**
 * @brief 연결 하나의 슬롯을 잡은 RAII 가드.
 * @details 드롭 시 계수를 되돌린다. 연결이 어떻게 끝나든: 정상 종료든 패닉이든:
 *          슬롯이 반드시 반납되어야 한다.
 */
pub(crate) struct ConnectionGuard {
    /** @brief 이 슬롯을 돌려줄 곳. */
    limiter: Arc<ConnectionLimiter>,
    /** @brief 이 연결의 상대 주소. */
    ip: IpAddr,
}

impl ConnectionLimiter {
    /** @brief 제한기를 만든다. 두 한도 모두 최소 1로 올린다. */
    fn new(max_total: usize, max_per_ip: usize) -> Arc<Self> {
        Arc::new(Self {
            max_total: max_total.max(1),
            max_per_ip: max_per_ip.max(1),
            state: Mutex::new(LimitState::default()),
        })
    }

    /**
     * @brief 슬롯을 하나 잡는다.
     * @return 전체나 IP별 한도에 걸리면 None. 호출자는 연결을 즉시 닫는다.
     */
    fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnectionGuard> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
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

impl ConnectionGuard {
    /**
     * @brief 이 연결의 계수를 다른 IP로 옮긴다.
     * @details PROXY 헤더를 읽어 원래 클라이언트 주소를 알게 된 뒤에 부른다. 옮기지
     *          않으면 IP별 한도가 프록시 주소에만 걸려 실제 클라이언트별 제한이 사라진다.
     * @return 새 IP가 이미 한도에 찼으면 false. 연결을 거절해야 한다.
     */
    fn reassign_ip(&mut self, ip: IpAddr) -> bool {
        if self.ip == ip {
            return true;
        }
        let mut state = self
            .limiter
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let next = state.per_ip.get(&ip).copied().unwrap_or(0);
        if next >= self.limiter.max_per_ip {
            return false;
        }
        if let Some(count) = state.per_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.per_ip.remove(&self.ip);
            }
        }
        state.per_ip.insert(ip, next + 1);
        self.ip = ip;
        true
    }
}

impl Drop for ConnectionGuard {
    /** @brief 슬롯을 반납한다. 계수가 0이 된 IP 항목은 지워 맵이 무한정 커지지 않게 한다. */
    fn drop(&mut self) {
        let mut state = self
            .limiter
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.total = state.total.saturating_sub(1);
        if let Some(count) = state.per_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.per_ip.remove(&self.ip);
            }
        }
    }
}

/** @brief 연결 처리 워커 수. 수락 스레드보다 많아야 처리가 수락을 막지 않는다. */
pub(crate) fn connection_worker_count(acceptors: usize) -> usize {
    acceptors
        .max(1)
        .saturating_mul(2)
        .clamp(MIN_CONNECTION_WORKERS, MAX_CONNECTION_WORKERS)
}

/** @brief 수락 큐 길이. 순간 몰림을 흡수하되 상한을 넘지 않는다. */
pub(crate) fn connection_queue_capacity(acceptors: usize) -> usize {
    acceptors
        .max(1)
        .saturating_mul(64)
        .clamp(MIN_CONNECTION_QUEUE, MAX_CONNECTION_QUEUE)
}

/**
 * @brief 워커 수와 큐 길이에 맞춘 연결 제한기를 만든다.
 * @details 전체 한도는 워커 수 + 큐 길이다. 그보다 많이 받아 봐야 처리도 대기도 못 한다.
 * @param proxy_protocol 켜져 있으면 IP별 한도를 크게 잡는다. 모든 연결이 프록시 주소
 *                       하나에서 오기 때문이다.
 */
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

/**
 * @brief 연결 처리 워커를 시작하고 수락 큐의 송신단을 돌려준다.
 *
 * @details 워커들이 하나의 수신단을 뮤텍스로 나눠 쓴다. 연결마다 스레드를 만들지 않으므로
 *          연결 폭주가 스레드 폭주로 번지지 않는다.
 * @note 연결마다 장애 격리 경계를 친다. TCP의 격리 단위는 패킷이 아니라 연결이다.
 * @return 워커를 하나도 시작하지 못하면 오류. 하나라도 뜨면 그만큼으로 진행한다.
 */
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

/**
 * @brief 새 연결이 올 때까지 제한 시간 안에서 기다린다.
 * @details 리스너가 논블로킹이라 그냥 accept를 돌리면 바쁜 대기가 된다. 폴링으로
 *          기다리되 시간을 끊어 종료 신호를 확인할 수 있게 한다.
 * @safety 폴링 구조체는 스택 변수 하나이고 개수를 1로 넘긴다.
 */
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

/**
 * @brief 유닉스가 아닌 플랫폼에서는 곧바로 accept를 시도한다.
 * @details WouldBlock을 받으면 호출자가 짧게 쉬고 재시도한다.
 */
#[cfg(not(unix))]
fn wait_for_incoming(_listener: &TcpListener, _timeout: Duration) -> io::Result<bool> {
    Ok(true)
}

/**
 * @brief 연결을 수락해 처리 큐에 넣는다. 요청 처리는 하지 않는다.
 * @note 큐가 가득 차면 try_send가 실패하고 연결은 그대로 닫힌다. 여기서 기다리면
 *       수락 자체가 멈춰 대기 큐가 커널 백로그로 밀려난다.
 */
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

/** @brief 이 상대에게서 온 PROXY 헤더를 믿어도 되는지. */
fn trusted_peer(peer: SocketAddr, trusted: &[IpNet]) -> bool {
    trusted.iter().any(|net| net.contains(&peer.ip()))
}

/**
 * @brief 연결 하나를 끝까지 처리한다. 같은 연결에서 여러 질의를 받는다.
 *
 * @details PROXY가 켜져 있으면 신뢰 목록에 없는 상대는 헤더를 읽지도 않고 끊는다.
 *          그러지 않으면 누구나 출발지를 위조할 수 있다.
 * @note 응답 비트가 선 메시지를 받으면 연결을 끊는다. 정상 클라이언트는 보내지 않는
 *       형태이고, 서버끼리 응답을 주고받는 무한 루프가 여기서 시작된다.
 * @note nodelay를 켠다. DNS 응답은 작고 하나로 끝나므로 지연 전송이 순수한 손해다.
 */
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
                // 파싱하지 못해도 답을 주고 연결은 이어 간다. 길이 프리픽스가 메시지 경계를
                // 이미 정하므로(RFC 1035) 내용이 깨져도 다음 메시지가 어디서 시작하는지
                // 안다. 하나가 깨졌다고 끊으면 질의를 이어 보내던 클라이언트가 연결을 잃는다.
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

/**
 * @brief PROXY 헤더를 읽는다.
 *
 * @details 한 바이트씩 읽어 파서가 확정할 때까지만 소비한다. 더 읽으면 뒤따르는 DNS
 *          데이터까지 삼켜 버린다.
 * @note 256바이트와 제한 시간 두 가지로 막는다. 헤더는 그보다 짧으므로, 끝없이 보내는
 *       상대가 버퍼나 워커를 붙들지 못한다.
 * @return Some(Some(addr))는 원래 클라이언트 주소, Some(None)은 프록시 자신의 연결,
 *         None은 헤더가 아니거나 실패라 연결을 끊어야 함을 뜻한다.
 */
/**
 * @brief 연결을 받자마자 끊은 사유를 남긴다.
 * @details 앞단 프록시 설정이 어긋나면 모든 연결이 여기서 조용히 끊긴다. 사유가 없으면
 *          "아무것도 안 된다"만 남는다. 계속 들어올 수 있어 2의 거듭제곱 번째만 기록한다.
 */
fn note_tcp_drop(reason: &'static str, peer: SocketAddr, detail: &str) {
    use std::sync::atomic::AtomicU64;
    /** @brief 누적 거절 수. */
    static COUNT: AtomicU64 = AtomicU64::new(0);
    let count = COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::warn!(event = "tcp.connection_dropped", reason = reason, peer = %peer, count = count, detail = detail, "Connection dropped right after accept");
    }
}

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

/**
 * @brief 데드라인 시각까지 버퍼를 정확히 채운다.
 * @details 읽기 타임아웃마다 데드라인과 종료 신호를 다시 본다. 한 바이트씩 아주 느리게 보내는
 *          연결도 총 데드라인에 걸려 끊긴다. 읽기 타임아웃만으로는 그런 연결을 못 막는다.
 * @return 다 채웠으면 true. 데드라인·종료·연결 종료·오류는 전부 false.
 */
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
/** @brief 읽지 못한 메시지 뒤에도 연결이 이어지는지. */
mod malformed_tests {
    use super::*;
    use onetdns_proto::{Name, RecordType};

    /** @brief 읽지 못한 것에는 FORMERR, 읽은 것에는 NOERROR 를 주는 테스트용 핸들러. */
    struct TwoAnswerHandler;

    impl Handler for TwoAnswerHandler {
        /** @brief 질문을 그대로 담은 NOERROR. */
        fn handle(&self, request: &Message, _ctx: &RequestCtx<'_>) -> Option<Message> {
            let mut response = Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.questions = request.questions.clone();
            Some(response)
        }

        /** @brief 헤더만 그대로 돌려준 FORMERR. */
        fn handle_unparsable(&self, packet: &[u8], _ctx: &RequestCtx<'_>) -> Option<Message> {
            let mut response = Message::default();
            response.header.id = u16::from_be_bytes([packet[0], packet[1]]);
            response.header.response = true;
            response.header.rcode = 1;
            Some(response)
        }
    }

    /** @brief 길이 프리픽스를 붙여 한 프레임 보낸다. */
    fn send_frame(stream: &mut TcpStream, payload: &[u8]) {
        let mut framed = (payload.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(payload);
        stream.write_all(&framed).expect("Could not send the frame");
    }

    /** @brief 한 프레임 받는다. 연결이 닫혔으면 없다. */
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
    /**
     * @brief 읽지 못한 메시지 하나에 답한 뒤에도 같은 연결로 다음 질의를 받는지.
     *
     * @details TCP 는 길이 프리픽스가 메시지 경계를 정하므로(RFC 1035) 내용이 깨져도
     *          다음 메시지가 어디서 시작하는지 안다. 끊어 버리면 질의를 이어 보내던
     *          클라이언트가 깨진 것 하나에 연결을 전부 잃고 다시 붙어야 한다.
     */
    fn a_malformed_message_does_not_end_the_tcp_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Could not bind the listen address");
        let address = listener.local_addr().expect("Could not read the address");

        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).expect("Could not connect");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("Could not set the deadline");

            // 질문 하나를 적고 둘이라고 말하는 헤더다.
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
/** @brief 길이 접두사 쓰기와 연결 수 상한. */
mod limit_tests {
    use super::*;

    /** @brief 한 번에 조금씩만 쓰는 테스트용 상대. */
    struct ShortVectoredWriter {
        /** @brief 지금까지 받은 바이트. */
        bytes: Vec<u8>,
        /** @brief 처음 한 번에 받아 줄 크기. */
        first_limit: usize,
        /** @brief 여러 조각으로 쓰기가 불린 횟수. */
        vectored_calls: usize,
    }

    impl Write for ShortVectoredWriter {
        /** @brief 조금만 쓴다. */
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        /** @brief 비운다. */
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }

        /** @brief 여러 조각을 조금만 쓴다. */
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
    /** @brief 길이와 본문이 나뉘어 써져도 이어지는지. */
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
    /** @brief 길이 접두사에 담을 수 없는 크기를 거부하는지. */
    fn dns_frame_rejects_oversized_payload() {
        let mut writer = Vec::new();
        let error = write_dns_frame(&mut writer, &vec![0; usize::from(u16::MAX) + 1])
            .expect_err("oversized DNS/TCP frame");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(writer.is_empty());
    }

    #[test]
    /** @brief 쉬고 있어도 새 연결이 곧바로 처리되는지. */
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
    /** @brief 길이와 본문에 하나의 데드라인이 걸리는지. 따로 걸면 조금씩 보내 무한히 붙잡는다. */
    fn length_and_body_share_one_absolute_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        /*
         * 아래 시간 값들은 비율만 의미가 있다. 길이 두 바이트는 데드라인 안에, 본문은 그
         * 뒤에 도착하도록 간격을 벌려 두었다. 부하가 걸린 기계에서 sleep 이 늘어져도 순서가
         * 뒤집히지 않도록, 값을 바꿀 때는 전부 같은 배수로 바꾼다.
         */
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
    /** @brief 주소별 상한이 걸리고, 프록시 뒤의 클라이언트는 원래 주소로 세는지. */
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
    /** @brief 전체 스레드 수에 상한이 걸리고 한 주소가 다 차지하지 못하는지. */
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
