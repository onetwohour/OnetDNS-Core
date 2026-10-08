/*!
 * @brief DoQ 와 DoH3 리스너가 함께 쓰는 연결 테이블과 수신 반복.
 *
 * @details 소켓 하나로 여러 QUIC 연결을 받는다. 연결 수락과 Retry, 경로 확인, 재전송
 *          타이머, 유휴 정리, 메모리 예산, 워커 완료 전달은 두 전송이 같다. 다 받은 요청을
 *          검사해 워커에 맡기는 일과 응답을 스트림에 싣는 일만 QuicService 구현이 정한다.
 * @warning 새 연결을 받는 조건이 증폭 방어다. 규격 크기를 채우지 않은 데이터그램으로
 *          연결을 열게 두면 작은 요청이 큰 응답을 끌어낸다.
 */

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

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

/** @brief 아무것도 오가지 않을 때 연결을 닫는 시간. */
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/** @brief 동시에 받을 연결 수. */
const MAX_CONNECTIONS: usize = 2048;
/** @brief 주소 하나가 차지할 수 있는 연결 수. */
const MAX_CONNECTIONS_PER_IP: usize = 64;
/**
 * @brief 첫 데이터그램의 최소 크기.
 * @warning 규격이 정한 값이다. 작은 패킷으로 연결을 열게 두면 작은 요청 하나가 큰 응답을
 *          끌어내는 증폭이 된다.
 */
const MIN_INITIAL_DATAGRAM: usize = 1200;
/** @brief 쉬는 연결을 걷어내는 주기. */
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);
/** @brief 재전송 데드라인을 확인하는 주기. */
const TIMER_INTERVAL: Duration = Duration::from_millis(100);

/**
 * @brief 리스너가 다루는 서버 쪽 연결.
 * @details DoQ 는 QUIC 연결을 그대로 쓰고, DoH3 는 그 위에 HTTP/3 를 얹은 연결을 쓴다.
 */
pub(crate) trait ServerConn {
    /** @brief 핸드셰이크 전의 QUIC 연결을 이 전송의 연결로 감싼다. */
    fn from_quic(conn: Connection) -> Self;
    /** @brief 연결 시계를 맞춘다. */
    fn set_now(&mut self, now_ms: u64);
    /** @brief 데드라인이 지난 재전송을 돌린다. */
    fn on_timeout(&mut self, now_ms: u64);
    /** @brief 데이터그램 하나를 받는다. 오류면 이 연결은 더 쓸 수 없다. */
    fn recv_datagram(&mut self, datagram: &[u8]) -> Result<(), QuicError>;
    /** @brief 내보낼 데이터그램을 꺼낸다. */
    fn next_datagram(&mut self) -> Option<Vec<u8>>;
    /** @brief 연결이 닫혔는지. */
    fn is_closed(&self) -> bool;
    /**
     * @brief 닫힌 연결에서 closing 이나 draining 기간에 쓸 상태만 남기고 나머지를 버린다.
     * @return 열린 연결이거나 기간이 이미 끝났으면 None.
     */
    fn into_close_period(self) -> Option<ClosePeriod>;
    /** @brief 전역 메모리 예산에 올릴 보유량. */
    fn retained_payload_bytes(&self) -> usize;
    /** @brief 기록에만 남기는 실패 진단. */
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
/**
 * @brief 리스너가 이쪽 사정으로 연결을 닫는 까닭.
 * @details 전송마다 RFC 가 정한 응용 오류 코드로 바꿔 상대에게 알린다.
 */
pub(crate) enum Abandon {
    /** @brief 리스너를 멈춘다. 알릴 오류는 없다. */
    Shutdown,
    /** @brief 이쪽 실패로 응답을 실을 수 없다. */
    Internal,
    /** @brief 메모리 예산이나 보낼 버퍼가 모자라다. */
    ExcessiveLoad,
}

/**
 * @brief 리스너에서 전송마다 다른 부분.
 * @details 다 받은 요청을 검사해 워커에 맡기는 방법, 응답을 스트림에 싣는 방법, 연결을 닫을 때
 *          알리는 오류 코드가 다르다.
 */
pub(crate) trait QuicService: Send + 'static {
    /** @brief 이 전송의 연결. */
    type Conn: ServerConn;
    /** @brief 기록과 스레드 이름에 쓰는 전송 이름. */
    const NAME: &'static str;
    /**
     * @brief recv_datagram 이 다 받은 요청을 검사해 워커에 맡기거나 그 자리에서 답한다.
     * @details 리스너는 열린 연결에만 부른다. 연결을 더 쓸 수 없게 되면 그 까닭으로 연결을 닫고
     *          돌아온다. 리스너는 닫힌 연결을 closing 기간이 끝날 때까지 붙들고 있다가 버린다.
     */
    fn dispatch(&self, conn: &mut Self::Conn, intake: &mut Intake<'_>);
    /**
     * @brief 응답 하나를 그 스트림에 싣는다. 리스너는 열린 연결에만 부른다.
     * @param max_age HTTP 캐시가 신선하다고 볼 시간. HTTP 를 쓰지 않는 전송은 무시한다.
     */
    fn send_answer(
        conn: &mut Self::Conn,
        stream_id: u64,
        wire: Vec<u8>,
        max_age: u32,
    ) -> Result<(), QuicError>;
    /**
     * @brief 이쪽 사정으로 연결을 닫고 그 까닭을 상대에게 알린다.
     * @details 이미 닫힌 연결은 처음 알린 사유를 그대로 둔다. 알리지 않고 버리면 상대는 자기
     *          유휴 데드라인까지 기다린다.
     */
    fn abandon(conn: &mut Self::Conn, why: Abandon);
}

/**
 * @brief 응답을 스트림에 실은 결과로 연결을 계속 쓸지 정하고, 못 쓰면 닫는다.
 * @details 상대가 STOP_SENDING 으로 답을 거절했거나 이미 끝난 스트림이면 그 답만 버린다.
 *          연결까지 버리면 같은 연결에 실린 다른 질의의 답을 잃는다. 다른 오류는 이 연결로
 *          더 답할 수 없다는 뜻이다. 보낼 버퍼가 찬 것은 상대가 답을 읽지 않으면서 질의를 계속
 *          보낸 결과라서 과부하로 알린다.
 * @return 연결을 계속 쓸 수 있으면 true.
 */
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

/**
 * @brief 연결 하나에서 받은 요청을 워커에 맡기는 창구.
 * @details 작업에 연결 키와 세대를 붙여야 끝난 연결에 늦게 온 응답을 가려 버릴 수 있다.
 */
pub(crate) struct Intake<'a> {
    /** @brief 이 연결의 키. */
    key: &'a [u8],
    /** @brief 확인된 상대 주소. */
    peer: SocketAddr,
    /** @brief 이 연결의 세대 번호. */
    epoch: u64,
    /** @brief 이 연결이 맡긴 질의 수. */
    inflight: &'a mut usize,
    /** @brief 질의를 맡을 워커들. */
    pool: &'a WorkerPool,
}

impl Intake<'_> {
    /** @brief 작업에 붙일 연결 키. */
    pub(crate) fn key(&self) -> &[u8] {
        self.key
    }

    /** @brief 작업에 붙일 세대 번호. */
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }

    /** @brief 요청을 보낸 주소. */
    pub(crate) fn peer(&self) -> SocketAddr {
        self.peer
    }

    /**
     * @brief 질의를 워커에 맡긴다. 맡길 수 없으면 SERVFAIL 로 바로 답한다.
     * @return 연결을 계속 쓸 수 있으면 true.
     */
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

/** @brief QUIC 리스너. 사라질 때 수신 반복을 끝내고 기다린다. */
pub(crate) struct QuicListener {
    /** @brief 이 리스너가 묶인 주소. */
    addr: SocketAddr,
    /** @brief 반복을 끝내라는 표시. */
    stop: Arc<AtomicBool>,
    /** @brief 반복을 실행하는 스레드. */
    thread: Option<thread::JoinHandle<()>>,
}

impl QuicListener {
    /** @brief 이 리스너가 묶인 주소. */
    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for QuicListener {
    /** @brief 종료를 알리고 반복이 끝나기를 기다린다. */
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/** @brief 리스너를 열고 연결을 받기 시작한다. */
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

/** @brief 새 연결 식별자. 예측할 수 없어야 한다. */
pub(crate) fn random_cid() -> Vec<u8> {
    let mut cid = [0u8; 8];
    onetdns_tls::sys::fill_random(&mut cid);
    cid.to_vec()
}

/** @brief 현재 Unix 초. */
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/**
 * @brief 새 연결을 받아들일지.
 * @details 데이터그램 크기가 규격을 채우고, 전체와 주소별 상한 안이어야 한다. 주소별
 *          상한이 있어야 한 곳이 슬롯을 다 차지하지 못한다.
 */
fn initial_connection_allowed(datagram_len: usize, total: usize, per_ip: usize) -> bool {
    datagram_len >= MIN_INITIAL_DATAGRAM
        && total < MAX_CONNECTIONS
        && per_ip < MAX_CONNECTIONS_PER_IP
}

/**
 * @brief 패킷이 확인된 경로에서 왔는지.
 * @warning 다른 주소에서 온 패킷을 그대로 받으면 출발지를 속인 이동으로 이 서버가 남에게
 *          트래픽을 쏟게 된다.
 */
fn same_validated_path(existing: SocketAddr, incoming: SocketAddr) -> bool {
    existing == incoming
}

/** @brief 높은 연결 수 뒤 남은 빈 bucket을 기하급수적으로만 줄여 메모리를 돌려준다. */
fn shrink_if_sparse<K: Eq + std::hash::Hash, V>(map: &mut HashMap<K, V>) {
    if map.is_empty() {
        map.shrink_to_fit();
        return;
    }
    let target = map.len().saturating_mul(2).saturating_add(1);
    if map.capacity() > target.saturating_mul(2) {
        map.shrink_to(target);
    }
}

/**
 * @brief 표에 든 연결의 상태.
 * @details 닫힌 연결도 closing 이나 draining 기간이 끝날 때까지 표에 남긴다. 그동안 늦게 온
 *          패킷에 종료를 다시 알려야 하고, 같은 연결 식별자로 오는 패킷을 모르는 연결로 다루지
 *          않아야 한다. RFC 9000 은 새 연결을 계속 받는 서버가 이 기간을 줄이지 않게 한다. 그
 *          일에는 키도 버퍼도 쓰지 않으므로 기간의 상태만 남겨, 닫힌 연결이 기간 내내 메모리
 *          예산을 쥐지 않게 한다.
 */
enum ConnState<C> {
    /** @brief 열린 연결의 상태 기계. */
    Open(C),
    /** @brief 닫힌 연결에 남은 기간. */
    Closing(ClosePeriod),
}

/** @brief 표에 든 연결 하나와 그 상태. */
struct ConnEntry<C> {
    /** @brief 열린 연결이거나 닫힌 연결의 남은 기간. */
    state: ConnState<C>,
    /** @brief 확인된 상대 주소. */
    peer: SocketAddr,
    /** @brief 마지막으로 무언가 오간 시각. */
    last: Instant,
    /** @brief 이 연결의 세대 번호. 끝난 연결의 늦은 응답을 구분한다. */
    epoch: u64,
    /** @brief 이 연결이 맡긴 질의 수. */
    inflight: usize,
    /** @brief 전역 QUIC 메모리 예산에서 이 연결이 빌린 몫. */
    memory: QuicMemoryLease,
}

/** @brief 연결에 쌓인 데이터그램을 모두 상대에게 보낸다. */
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
    /**
     * @brief 처리를 마친 열린 연결의 출력을 내보내고 메모리 몫을 지금 보유량에 맞춘다.
     * @details 예산이 늘려 주지 않으면 과부하를 알리고 닫는다.
     * @return 연결이 아직 열려 있으면 true. 닫혔으면 부른 쪽이 표의 retire 로 기간의 상태만
     *         남긴다.
     */
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

/** @brief 리스너가 붙든 연결과 그 색인. 세 표를 늘 함께 고친다. */
struct ConnTable<S: QuicService> {
    /** @brief 이쪽 연결 식별자별 연결. */
    conns: HashMap<Vec<u8>, ConnEntry<S::Conn>>,
    /** @brief 패킷의 목적지 연결 식별자에서 연결 키로. */
    aliases: HashMap<Vec<u8>, Vec<u8>>,
    /** @brief 주소별 연결 수. */
    peer_counts: HashMap<IpAddr, usize>,
}

impl<S: QuicService> ConnTable<S> {
    /** @brief 빈 테이블. */
    fn new() -> Self {
        Self {
            conns: HashMap::new(),
            aliases: HashMap::new(),
            peer_counts: HashMap::new(),
        }
    }

    /** @brief 패킷의 목적지 연결 식별자가 가리키는 연결 키. */
    fn key_for(&self, dcid: &[u8]) -> Vec<u8> {
        self.aliases
            .get(dcid)
            .cloned()
            .unwrap_or_else(|| dcid.to_vec())
    }

    /** @brief 새 연결을 넣는다. */
    fn insert(&mut self, dcid: Vec<u8>, key: Vec<u8>, entry: ConnEntry<S::Conn>) {
        *self.peer_counts.entry(entry.peer.ip()).or_default() += 1;
        self.conns.insert(key.clone(), entry);
        self.aliases.insert(dcid, key);
    }

    /** @brief 연결 하나를 지우고 별칭과 주소별 계수를 맞춘다. */
    fn remove(&mut self, key: &[u8]) {
        if let Some(entry) = self.conns.remove(key) {
            self.release_peer(entry.peer);
        }
        self.aliases.retain(|_, primary| primary.as_slice() != key);
        self.shrink();
    }

    /** @brief 표에서 뺀 연결 하나를 주소별 연결 수에서 뺀다. */
    fn release_peer(&mut self, peer: SocketAddr) {
        let ip = peer.ip();
        if let Some(count) = self.peer_counts.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.peer_counts.remove(&ip);
            }
        }
    }

    /**
     * @brief 닫힌 연결에서 closing 이나 draining 기간의 상태만 남긴다. 기간까지 끝났으면 지운다.
     * @details 메모리 몫도 남은 상태에 맞춰 줄인다. 예산을 넘겨 닫은 연결은 종료 데이터그램
     *          때문에 몫이 늘어야 할 수도 있는데, 예산이 거절하면 지금 몫을 그대로 둔다. 기본 몫이
     *          연결 구조 크기의 두 배 이상이라 종료 데이터그램 하나는 그 여유 안에 든다.
     * @note 열린 연결에는 남은 기간이 없으므로, 닫히지 않은 연결에 부르면 그 연결을 지운다.
     */
    fn retire(&mut self, key: &[u8]) {
        let Some(mut entry) = self.conns.remove(key) else {
            return;
        };
        let period = match entry.state {
            ConnState::Open(conn) => conn.into_close_period(),
            ConnState::Closing(period) => Some(period),
        };
        let Some(period) = period else {
            self.release_peer(entry.peer);
            self.remove(key);
            return;
        };
        entry.memory.refresh(period.retained_bytes());
        entry.state = ConnState::Closing(period);
        self.conns.insert(key.to_vec(), entry);
    }

    /**
     * @brief 쉬는 연결을 걷어낸다.
     * @details 알리지 않고 버린다. RFC 9000 의 유휴 종료가 그렇다. closing 기간 중인 연결도 마지막
     *          패킷 뒤 유휴 한도가 지나면 버려서, 왕복 시간이 부풀어 closing 기간이 길어진 연결이
     *          슬롯을 오래 잡지 못하게 한다.
     */
    fn evict_idle(&mut self) {
        let now = Instant::now();
        self.conns
            .retain(|_, entry| now.duration_since(entry.last) < IDLE_TIMEOUT);
        let conns = &self.conns;
        self.aliases
            .retain(|_, primary| conns.contains_key(primary));
        self.peer_counts.clear();
        for entry in self.conns.values() {
            *self.peer_counts.entry(entry.peer.ip()).or_default() += 1;
        }
        self.shrink();
    }

    /**
     * @brief 모든 연결을 버린다.
     * @details 반복 안에서 패닉이 나 상태를 믿을 수 없을 때는 종료를 알리지 않고 바로 부른다.
     *          그런 상태 기계로 만든 종료 프레임은 믿을 수 없다.
     */
    fn clear(&mut self) {
        self.conns.clear();
        self.aliases.clear();
        self.peer_counts.clear();
    }

    /** @brief 세 표의 high-water bucket을 활성 연결에 비례시킨다. */
    fn shrink(&mut self) {
        shrink_if_sparse(&mut self.conns);
        shrink_if_sparse(&mut self.aliases);
        shrink_if_sparse(&mut self.peer_counts);
    }

    /** @brief 지금 쓰이지 않는 연결 식별자를 만든다. */
    fn unique_cid(&self) -> Vec<u8> {
        loop {
            let cid = random_cid();
            if !self.conns.contains_key(&cid) {
                return cid;
            }
        }
    }

    /**
     * @brief 끝난 질의의 응답을 해당 연결로 보낸다.
     * @param now_ms 연결 시계의 지금 시각. 응답 패킷의 전송 시각으로 기록되므로, 낡은 값을
     *               넘기면 왕복 시간 표본이 실제보다 커지고 PTO 도 실제 전송보다 이르게 잡힌다.
     */
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
            /*
             * 닫힌 연결에는 답을 실을 곳이 없다. 실으려 하면 Closed 오류가 나서 정상적인 종료를
             * 응답 송신 실패로 기록하게 된다.
             */
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

    /** @brief 데드라인이 지난 연결의 재전송을 돌리고 closing 기간이 끝난 연결을 버린다. */
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

    /**
     * @brief 리스너를 멈추며 열린 연결마다 종료를 알리고 모두 버린다.
     * @details 소켓도 함께 닫으므로 closing 기간을 기다리지 않는다. 늦게 온 패킷이 닿을 곳이
     *          사라지므로 RFC 9000 이 기간을 줄이도록 허용하는 경우다. 알리지 않으면 클라이언트는
     *          자기 유휴 데드라인까지 기다린다.
     */
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

/** @brief 수신 스레드 하나가 소유하는 리스너 상태. */
struct Listener<S: QuicService> {
    /** @brief 전송마다 다른 부분. */
    service: S,
    /** @brief 모든 연결이 함께 쓰는 소켓. */
    socket: UdpSocket,
    /** @brief 새 연결에 쓸 TLS 설정. */
    tls: Arc<onetdns_core::ArcSwap<ServerConfig>>,
    /** @brief 질의를 맡는 워커들. */
    pool: WorkerPool,
    /** @brief 워커가 완료를 알리며 보내는 데이터그램의 출발지. */
    wake_source: SocketAddr,
    /** @brief 이 주소에서 온 데이터그램을 아무 응답 없이 버려야 하는지. */
    drops: Box<dyn Fn(IpAddr) -> bool + Send>,
    /** @brief 종료 신호와 전역 메모리 예산. */
    control: QuicRunControl,
    /** @brief 살아 있는 연결들. */
    table: ConnTable<S>,
    /** @brief 새 연결에 알릴 전송 매개변수의 바탕. */
    base_tp: TransportParams,
    /** @brief Retry 토큰을 만들고 확인하는 키. */
    retry_key: RetryKey,
    /** @brief 다음 연결에 줄 세대 번호. */
    next_epoch: u64,
    /** @brief 연결 시계의 기준 시각. */
    clock: Instant,
}

impl<S: QuicService> Listener<S> {
    /** @brief 연결 시계의 지금 시각. */
    fn now_ms(&self) -> u64 {
        self.clock.elapsed().as_millis().min(u64::MAX as u128) as u64
    }

    /** @brief 데이터그램을 받아 연결마다 넘기고 응답을 내보내는 반복. */
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
        /*
         * 종료를 알리다 패닉이 나도 워커는 멈춰야 한다. 남은 연결은 이 함수가 끝나며 함께 사라진다.
         */
        let _ = onetdns_core::isolation::catch_request(|| {
            self.table.close_all(&self.socket, now_ms);
        });
        self.pool.shutdown();
    }

    /**
     * @brief 데이터그램 하나를 그 연결에 넘긴다. 모르는 연결이면 새로 받을지 정한다.
     * @param panic_key 처리 도중 패닉이 나면 버릴 연결 키. 다룬 연결이 정해지는 대로 적는다.
     */
    fn on_datagram(&mut self, bytes: &[u8], peer: SocketAddr, panic_key: &mut Option<Vec<u8>>) {
        if qworker::is_completion_wake(peer, self.wake_source, bytes) {
            return;
        }
        /*
         * 버릴 주소에는 Retry 도 ACK 도 보내지 않는다. 버림이 정해지기 전에 그 주소에 열린
         * 연결이 있으면 상태도 지워 재전송까지 멈춘다.
         */
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
            /*
             * 닫힌 연결에 남은 일은 늦게 온 패킷에 종료를 다시 알리는 것뿐이다. 패킷을 풀지
             * 않으므로 실려 온 요청도 맡기지 않는다.
             */
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
            /*
             * 연결이 닫혔으면 같은 데이터그램에 요청이 실려 왔어도 답할 연결이 없으므로 워커에
             * 맡기지 않는다.
             */
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

    /**
     * @brief 모르는 연결에서 온 첫 패킷으로 새 연결을 열지 정한다.
     * @details 토큰 없는 Initial 에는 Retry 로 답해 주소를 먼저 확인한다. 토큰이 맞을 때만
     *          연결 상태를 만든다.
     * @return 새로 연 연결의 키. 열지 않았으면 None.
     */
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
        let per_ip = self.table.peer_counts.get(&peer.ip()).copied().unwrap_or(0);
        if !initial_connection_allowed(bytes.len(), self.table.conns.len(), per_ip) {
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
/** @brief 연결 수락 조건, 테이블 메모리, 그리고 답을 실을 수 없는 스트림의 처리. */
mod tests {
    use super::*;

    use onetdns_proto::{Name, RecordType};
    use onetdns_tls::ClientConfig;

    use crate::doq::Doq;

    #[test]
    /** @brief 작은 데이터그램을 거부하고 주소별 몫을 지키는지. 안 지키면 증폭과 독점이 된다. */
    fn initial_admission_requires_rfc_size_and_preserves_fair_share() {
        assert!(!initial_connection_allowed(1199, 0, 0));
        assert!(initial_connection_allowed(1200, 0, 0));
        assert!(!initial_connection_allowed(1200, MAX_CONNECTIONS, 0));
        assert!(!initial_connection_allowed(1200, 0, MAX_CONNECTIONS_PER_IP));
        assert!(!same_validated_path(
            "127.0.0.1:1000".parse().unwrap(),
            "127.0.0.1:1001".parse().unwrap()
        ));
    }

    #[test]
    /** @brief 연결 수가 줄면 high-water HashMap bucket을 남기지 않는지. */
    fn sparse_connection_table_releases_reserved_buckets() {
        let mut map = HashMap::new();
        for key in 0..1024 {
            map.insert(key, key);
        }
        let high_water = map.capacity();
        map.retain(|key, _| *key == 0);
        shrink_if_sparse(&mut map);
        assert_eq!(map.get(&0), Some(&0));
        assert!(map.capacity() < high_water);

        map.clear();
        shrink_if_sparse(&mut map);
        assert_eq!(map.capacity(), 0);
    }

    #[test]
    /** @brief 희소 listener table의 연결·별칭·IP bucket까지 기본 charge 안에 드는지. */
    fn base_charge_covers_sparse_listener_table_slots() {
        let entry = std::mem::size_of::<ConnEntry<Connection>>()
            .max(std::mem::size_of::<ConnEntry<H3Connection>>());
        let connection_slot = std::mem::size_of::<Vec<u8>>()
            .saturating_add(entry)
            .saturating_add(1);
        let alias_slot = std::mem::size_of::<(Vec<u8>, Vec<u8>)>().saturating_add(1);
        let peer_slot = std::mem::size_of::<(IpAddr, usize)>().saturating_add(1);
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

    /** @brief 시험의 서버 연결 키. 클라이언트가 고른 목적지 연결 식별자이기도 하다. */
    const SERVER_KEY: &[u8] = b"SERVERID";

    /** @brief 자체 서명 인증서를 쓰는 서버 설정. */
    fn server_config(alpn: &[u8]) -> Arc<ServerConfig> {
        let (certs, key) = onetdns_transport::self_signed_material("dns.test").unwrap();
        let cfg = ServerConfig::from_pkcs8(certs[0].clone(), &key)
            .expect("ECDSA P-256 서명자")
            .with_alpn(vec![alpn.to_vec()]);
        Arc::new(cfg)
    }

    /** @brief 데이터그램을 서로 건네며 두 연결을 진행시킨다. */
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

    /** @brief 서버 인증서를 확인하지 않는 클라이언트 연결. 아직 아무것도 보내지 않았다. */
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

    /** @brief 핸드셰이크를 마친 클라이언트와 서버 연결. */
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
    /**
     * @brief 리스너가 서비스를 언제 부르는지 지켜보는 시험용 서비스.
     * @details 응답과 종료는 DoQ 처럼 다루고 dispatch 를 부른 횟수를 센다. 이름이 따로라서 이
     *          서비스로 기록한 오류가 다른 시험의 DoQ 오류 수와 섞이지 않는다.
     */
    struct Probe {
        /** @brief dispatch 를 부른 횟수. */
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

    /** @brief 서버 연결 하나를 넣은 연결 표. 연결의 세대는 7 이다. */
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

    /** @brief 주어진 표로 데이터그램을 처리하는 리스너. 워커는 맡은 질의에 답하지 않는다. */
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

    /** @brief 클라이언트가 받은 종료 사유의 코드와 프레임 종류. */
    fn close_of(client: &Connection) -> Option<(u64, Option<u64>)> {
        client
            .peer_close()
            .map(|close| (close.error_code, close.frame_type))
    }

    /** @brief 서버 연결이 쌓아 둔 데이터그램을 클라이언트에 건네고 받은 종료 사유를 돌려준다. */
    fn delivered_close<C: ServerConn>(
        server: &mut C,
        client: &mut Connection,
    ) -> Option<(u64, Option<u64>)> {
        while let Some(datagram) = server.next_datagram() {
            let _ = client.recv_datagram(&datagram);
        }
        close_of(client)
    }

    /** @brief 소켓에 오는 데이터그램을 종료 사유가 올 때까지 클라이언트에 넣는다. */
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
    /**
     * @brief 답을 더 실을 수 없는 스트림의 늦은 응답이 연결을 끊지 않는지.
     * @details 클라이언트가 STOP_SENDING 으로 질의를 거두면 워커가 늦게 낸 답은 실을 곳이
     *          없다. 그 연결을 버리면 같은 연결의 다른 질의 답까지 잃는다. 여기서는 이미 답을
     *          낸 스트림으로 같은 오류를 만든다. STOP_SENDING 이 이 오류가 되는 것은
     *          onetdns-quic 의 시험이 확인한다.
     */
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
    /**
     * @brief 이쪽 사정으로 닫는 연결이 전송마다 RFC 가 정한 오류 코드를 알리는지.
     * @details DoQ 는 RFC 9250, DoH3 는 RFC 9114 의 값이다. 둘 다 응용 계층 종료라서 프레임
     *          종류가 없어야 한다.
     */
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
    /**
     * @brief 응답을 싣지 못한 까닭에 따라 연결을 남기거나 알맞은 코드로 닫는지.
     * @details 끝난 스트림이면 그 답만 버린다. 보낼 버퍼가 찬 것은 과부하로, 나머지는 내부
     *          오류로 알린다.
     */
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
    /**
     * @brief 닫힌 연결을 closing 기간 동안 표에 남겼다가 기간이 끝나면 버리는지.
     * @details 기간 중에 버리면 늦게 온 패킷에 종료를 다시 알릴 수 없고, 같은 연결 식별자로 온
     *          패킷을 모르는 연결의 것으로 다루게 된다.
     */
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
        assert!(table.aliases.is_empty() && table.peer_counts.is_empty());
        assert_eq!(budget.used_bytes(), 0, "버린 연결의 메모리 몫이 남았습니다");
    }

    #[test]
    /**
     * @brief 닫힌 연결에 늦게 온 워커 응답을 싣지 않고, 연결도 표에서 빼지 않는지.
     * @details 응답을 실을 곳은 없지만 closing 기간은 그대로 지켜야 한다. 실으려 하면 정상적인
     *          종료가 응답 송신 실패로 기록된다.
     */
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
    /**
     * @brief closing 기간에 늦게 온 패킷에 종료를 다시 알리고 실려 온 질의는 맡기지 않는지.
     * @details 첫 종료 패킷을 잃은 클라이언트는 이 재전송으로만 연결이 닫힌 것을 안다.
     */
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

    /** @brief 소켓에 오는 데이터그램 하나. 5초 안에 오지 않으면 None. */
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
    /**
     * @brief 메모리 예산을 넘긴 연결이 과부하를 알리고, 버퍼는 버린 채 closing 기간을 지키는지.
     * @details 기간을 지키지 않으면 종료 패킷을 잃은 클라이언트에 다시 알릴 수 없고, 같은 연결
     *          식별자로 오는 패킷을 모르는 연결의 것으로 다루게 된다. 버퍼를 쥔 채 남기면 예산이
     *          거절한 메모리를 기간 내내 쥐고 있게 된다.
     */
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

    /** @brief 소켓에 데이터그램이 오지 않는지. 보낸 것이 있다면 루프백이라 곧 도착한다. */
    fn stays_silent(socket: &UdpSocket) -> bool {
        socket
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let mut buf = [0u8; 2048];
        socket.recv_from(&mut buf).is_err()
    }

    #[test]
    /**
     * @brief 버리는 주소에는 Retry 도 ACK 도 보내지 않고, 그 주소에 열려 있던 연결은 지우는지.
     * @details 모르는 연결의 첫 패킷에 Retry 를, 열린 연결의 패킷에 ACK 를 보내면 서버가 있다는
     *          것이 드러난다. 버림이 정해지기 전에 열린 연결은 상태를 지워야 재전송도 멈춘다.
     */
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
}
