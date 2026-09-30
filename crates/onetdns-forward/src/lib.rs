/*!
 * @brief 업스트림 전달: 평문·암호화 전송으로 질의를 넘긴다.
 *
 * @details 전송마다 별도 모듈(doh/dot/doq/doh3)이 있고, 이 파일이 업스트림 선택,
 *          단일 비행(single-flight), 소켓 풀, 통계 관리를 맡는다.
 * @warning 업스트림 응답의 AD 비트는 절대 그대로 넘기지 않는다. 이 서버가 검증하지 않은
 *          DNSSEC 진정성을 클라이언트에게 보증하는 꼴이 되기 때문이다.
 */

/**
 * @brief 출발 주소를 묶은 뒤 업스트림에 TCP로 잇는다.
 * @details std의 연결 함수는 로컬 주소를 먼저 묶을 방법이 없다. query_source를 정한
 *          다중 홈 호스트에서 TCP만 다른 경로로 나가면, 방화벽이 UDP 질의는 통과시키고 TC 뒤
 *          TCP 재시도와 암호화 업스트림은 막는다.
 */
mod bound_tcp;
/** @brief HTTP/2 위 DoH 업스트림. */
mod doh;
/** @brief HTTP/3 위 DoH3 업스트림. */
mod doh3;
/** @brief QUIC 위 DoQ 업스트림. */
mod doq;
/** @brief TLS 위 DoT 업스트림. */
mod dot;
/** @brief QUIC 상태 기계에 데이터그램을 전달하는 것. */
mod quicdrive;

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

/** @brief 업스트림으로 나갈 때 바인딩할 출발 주소. 설정에서 지정한다. */
static QUERY_SRC: RwLock<(Option<std::net::Ipv4Addr>, Option<std::net::Ipv6Addr>)> =
    RwLock::new((None, None));

/**
 * @brief 단일 비행을 묶는 키: 목적지 서버와 정규화한 질의 와이어.
 * @note 트랜잭션 ID와 (설정에 따라) 질의 이름 대소문자를 지운 형태로 비교한다. 그러지
 *       않으면 같은 질의가 매번 다른 키가 되어 단일 비행이 아무것도 묶지 못한다.
 */
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AuthorityQueryKey {
    /** @brief 물어본 업스트림. */
    server: SocketAddr,

    /** @brief 정규화한 질의 바이트. */
    normalized_wire: Arc<[u8]>,
}

impl AuthorityQueryKey {
    /**
     * @brief 와이어에서 키를 만든다.
     * @param normalize_question_case 0x20 대소문자 인코딩을 쓰는 경우 대소문자를 지운다.
     * @return 키 재료가 상한을 넘으면 None: 그 질의는 단일 비행에 묶지 않는다.
     */
    fn from_wire(server: SocketAddr, wire: &[u8], normalize_question_case: bool) -> Option<Self> {
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

            normalized_wire: normalized.into(),
        })
    }

    /** @brief 파싱된 요청에서 키를 만든다. */
    fn from_request(
        server: SocketAddr,
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
            normalized_wire: normalized_wire.into(),
        })
    }
}

/**
 * @brief 진행 중인 업스트림 교환 하나. 같은 질의를 하는 후속 요청이 여기 붙어 기다린다.
 * @details 같은 이름을 동시에 묻는 요청이 업스트림으로 각각 나가면, 캐시가 비었을 때 업스트림에
 *          이 서버의 부하가 그대로 증폭돼 걸린다. 하나만 내보내고 결과를 나눠 갖는다.
 */
struct AuthorityFlight {
    /** @brief 다 되면 여기에 채운다. */
    result: Mutex<Option<Result<Message, ForwardError>>>,
    /** @brief 기다리는 쪽을 깨우는 곳. */
    ready: Condvar,

    /** @brief 지금 기다리는 수. 0이면 깨우지 않는다. */
    waiters: AtomicUsize,

    /** @brief 밖으로 내보낸 스레드. 자기 자신을 기다리지 않으려고 본다. */
    leader_thread: std::thread::ThreadId,
}

impl AuthorityFlight {
    /** @brief 비어 있는 비행을 만든다. */
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            ready: Condvar::new(),
            waiters: AtomicUsize::new(0),
            leader_thread: std::thread::current().id(),
        }
    }

    /**
     * @brief 앞선 요청의 결과를 기다린다.
     * @param timeout 이 시간을 넘기면 기다리지 않고 실패로 돌아간다. 선두 요청이 멎어도
     *                뒤따르는 요청이 함께 묶여 멎지 않게 한다.
     */
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

    /** @brief 결과를 채우고 기다리던 모두를 깨운다. */
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

/** @brief 지금 나가 있는 같은 질의들. 하나만 내보내고 결과를 나눈다. */
static AUTHORITY_FLIGHTS: OnceLock<Mutex<HashMap<AuthorityQueryKey, Arc<AuthorityFlight>>>> =
    OnceLock::new();
/** @brief 동시에 추적할 비행 수 상한. 넘으면 새 질의는 묶지 않고 그대로 내보낸다. */
const MAX_AUTHORITY_FLIGHTS: usize = 1024;

/** @brief 비행 키로 삼을 와이어 크기 상한. 큰 질의가 키 맵을 부풀리지 못하게 한다. */
const MAX_AUTHORITY_FLIGHT_KEY_BYTES: usize = 4_096;

thread_local! {

    /** @brief 이 스레드가 재사용하는 수신 버퍼. 질의마다 새로 잡지 않으려는 것이다. */
    static UDP_RECV_BUFFER: RefCell<Vec<u8>> = RefCell::new(vec![0; 65_535]);

    /** @brief 이 스레드가 목적지별로 보관 중인 소켓들. */
    static UDP_SOCKET_POOL: RefCell<HashMap<SocketAddr, UdpSocketPool>> =
        RefCell::new(HashMap::new());
}

/** @brief 목적지별로 보관할 UDP 소켓 수. */
const UDP_SOCKET_POOL_SIZE: usize = 16;

/**
 * @brief 소켓 하나를 재사용할 최대 횟수.
 * @warning 출발 포트 무작위화가 캐시 오염 방어의 한 축이다. 소켓을 무한정 재사용하면
 *          같은 포트가 오래 노출되어 그 방어가 약해지므로, 일정 횟수마다 새로 연다.
 */
const UDP_SOCKET_POOL_MAX_USES: u32 = 16;

/** @brief 재사용을 위해 보관 중인 소켓과 그 상태. */
struct PooledUdpSocket {
    /** @brief 보관 중인 소켓. */
    sock: UdpSocket,
    /** @brief 이 소켓을 쓴 횟수. 정해진 수를 넘으면 새로 연다. */
    uses: u32,

    /** @brief 이 소켓에 지금 걸린 수신 데드라인. */
    rcv_timeout: Option<Duration>,
}

/**
 * @brief 보관된 소켓의 수신 타임아웃을 그대로 써도 되는지.
 * @details 매번 타임아웃을 다시 설정하면 소켓 하나당 시스템 호출이 붙는다. 남은 시간과
 *          큰 차이가 없으면 재설정을 건너뛴다.
 */
fn rcv_timeout_reusable(cached: Option<Duration>, remaining: Duration) -> bool {
    match cached {
        Some(cached) => {
            cached <= remaining && remaining.saturating_sub(cached) <= Duration::from_millis(1)
        }
        None => false,
    }
}

#[derive(Default)]
/** @brief 바인드 주소별 소켓 풀. 스레드 지역이라 잠금이 없다. */
struct UdpSocketPool {
    /** @brief 쉬고 있는 소켓들. */
    idle: Vec<PooledUdpSocket>,
    /** @brief 이 목적지로 잡아 둔 소켓 수. */
    owned: usize,
}

/**
 * @brief 풀에서 소켓을 꺼내거나 새로 연다.
 * @return (소켓, 지금까지 쓴 횟수, 설정돼 있던 수신 타임아웃).
 */
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

/** @brief 소켓을 풀에 돌려준다. 사용 횟수 상한을 넘겼으면 버린다. */
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

/**
 * @brief 이 바인드 주소의 보관 소켓을 전부 버린다.
 * @details 위조 의심 응답을 받았을 때 부른다. 그 포트는 이미 상대에게 알려진 것이므로
 *          계속 쓰면 다음 질의도 같은 포트로 나간다.
 */
fn discard_pooled_udp_socket(bind: SocketAddr) {
    UDP_SOCKET_POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        let entry = pool.entry(bind).or_default();
        entry.owned = entry.owned.saturating_sub(1);
    });
}

/** @brief 진행 중인 비행 테이블. 처음 쓸 때 만든다. */
fn authority_flights() -> &'static Mutex<HashMap<AuthorityQueryKey, Arc<AuthorityFlight>>> {
    AUTHORITY_FLIGHTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/**
 * @brief 이 질의의 비행을 잡거나 기존 비행에 올라탄다.
 * @return 선두가 되었으면 이 서버가 업스트림에 내보내고 결과를 채운다. 아니면 기다린다.
 */
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

/** @brief 업스트림으로 나갈 때 쓸 출발 주소를 설정한다. 다중 홈 호스트에서 경로를 고정한다. */
pub fn set_query_source(v4: Option<std::net::Ipv4Addr>, v6: Option<std::net::Ipv6Addr>) {
    *QUERY_SRC
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = (v4, v6);
}

/** @brief 목적지 계열에 맞는 바인드 주소를 고른다. 포트는 0(임의)이다. */
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

/** @brief 이 업스트림으로 나갈 때 바인딩할 로컬 주소. */
pub fn outgoing_bind(upstream: SocketAddr) -> SocketAddr {
    let (v4, v6) = *QUERY_SRC
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    pick_bind(upstream, v4, v6)
}

/** @brief 절대 데드라인을 유지하는 TCP. */
pub(crate) struct DeadlineTcp {
    /** @brief 이어진 연결. */
    stream: TcpStream,
    /** @brief 요청 하나 전체의 데드라인. */
    deadline: Instant,
}

impl DeadlineTcp {
    /**
     * @brief 데드라인 시각까지 안에 TCP 연결을 맺는다.
     * @details 소켓 타임아웃이 아니라 절대 데드라인을 유지한다. 읽기·쓰기마다 남은 시간을
     *          다시 계산하므로, 조금씩 데이터를 보내는 상대가 총 예산을 넘기지 못한다.
     */
    fn connect(addr: SocketAddr, deadline: Instant) -> std::io::Result<Self> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                "Response timed out",
            ));
        }
        Ok(Self {
            stream: bound_tcp::connect(outgoing_bind(addr), addr, remaining)?,
            deadline,
        })
    }

    /** @brief 데드라인을 다시 잡는다. 살아 있음이 확인된 뒤 예산을 늘릴 때 쓴다. */
    fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = deadline;
    }

    /** @brief 데드라인까지 남은 시간. 이미 지났으면 타임아웃 오류다. */
    fn remaining(&self) -> std::io::Result<Duration> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(std::io::Error::new(
                ErrorKind::TimedOut,
                "Response timed out",
            ))
        } else {
            Ok(remaining)
        }
    }
}

impl Read for DeadlineTcp {
    /** @brief 남은 시간을 걸고 읽는다. */
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buf)
    }
}

impl Write for DeadlineTcp {
    /** @brief 남은 시간을 걸고 쓴다. */
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buf)
    }

    /** @brief 남은 시간을 걸고 비운다. */
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.flush()
    }
}

/** @brief 업스트림 여러 개를 어떻게 고를지. */
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Strategy {
    /** @brief 앞에서부터 순서대로 시도한다. 첫 업스트림이 사실상 주 서버가 된다. */
    #[default]
    Sequential,

    /** @brief 돌아가며 고른다. 부하가 고르게 퍼진다. */
    RoundRobin,

    /** @brief 관측된 응답 시간과 성공률로 고른다. */
    QueryStatistics,

    /** @brief 동시에 여러 곳에 보내고 가장 빠른 응답을 쓴다. 지연을 줄이되 업스트림 부하가 는다. */
    Parallel,
}

/** @brief 업스트림으로 가는 전송 방식. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /** @brief 평문 UDP. */
    Udp,

    /** @brief 평문 TCP. */
    Tcp,

    /** @brief TLS 위의 DNS. server_name으로 인증서를 검증한다. */
    Dot { server_name: String },

    /** @brief HTTP/2 위의 DNS. */
    Doh { server_name: String, path: String },

    /** @brief QUIC 위의 DNS. */
    Doq { server_name: String },

    /** @brief HTTP/3 위의 DNS. */
    Doh3 { server_name: String, path: String },
}

/** @brief 업스트림 하나: 주소와 전송 방식. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    /** @brief 이 업스트림의 주소. */
    pub addr: SocketAddr,
    /** @brief 어느 전송으로 물을지. */
    pub transport: Transport,
}

impl Upstream {
    /** @brief 평문 UDP 업스트림. */
    pub fn udp(addr: SocketAddr) -> Self {
        Upstream {
            addr,
            transport: Transport::Udp,
        }
    }

    /** @brief 평문 TCP 업스트림. */
    pub fn tcp(addr: SocketAddr) -> Self {
        Upstream {
            addr,
            transport: Transport::Tcp,
        }
    }

    /** @brief DoT 업스트림. server_name은 인증서 검증 대상 이름이다. */
    pub fn dot(addr: SocketAddr, server_name: impl Into<String>) -> Self {
        Upstream {
            addr,
            transport: Transport::Dot {
                server_name: server_name.into(),
            },
        }
    }

    /** @brief DoH 업스트림. */
    pub fn doh(addr: SocketAddr, server_name: impl Into<String>, path: impl Into<String>) -> Self {
        Upstream {
            addr,
            transport: Transport::Doh {
                server_name: server_name.into(),
                path: path.into(),
            },
        }
    }

    /** @brief DoQ 업스트림. */
    pub fn doq(addr: SocketAddr, server_name: impl Into<String>) -> Self {
        Upstream {
            addr,
            transport: Transport::Doq {
                server_name: server_name.into(),
            },
        }
    }

    /** @brief 로그·통계에 쓰는 업스트림 표시. 전송 종류와 주소가 함께 들어간다. */
    pub fn label(&self) -> String {
        match &self.transport {
            Transport::Udp => self.addr.to_string(),
            Transport::Tcp => format!("tcp://{}", self.addr),
            Transport::Dot { server_name } => format!("tls://{server_name}"),
            Transport::Doh { server_name, path } => format!("https://{server_name}{path}"),
            Transport::Doq { server_name } => format!("quic://{server_name}"),
            Transport::Doh3 { server_name, path } => format!("h3://{server_name}{path}"),
        }
    }

    /** @brief DoH3 업스트림. */
    pub fn doh3(addr: SocketAddr, server_name: impl Into<String>, path: impl Into<String>) -> Self {
        Upstream {
            addr,
            transport: Transport::Doh3 {
                server_name: server_name.into(),
                path: path.into(),
            },
        }
    }
}

/** @brief 마지막 응답이 어디서 왔는지. 질의 로그에 담긴다. */
enum ResponseSource {
    /** @brief 이름으로 적어 둔 출처. */
    Label(std::borrow::Cow<'static, str>),
    /** @brief 주소로 적어 둔 출처. 문자열 만들기를 늦춘다. */
    Addr(SocketAddr),
}

thread_local! {

    /** @brief 이 스레드가 마지막으로 답을 받은 곳. */
    static LAST_SOURCE: std::cell::RefCell<Option<ResponseSource>> =
        const { std::cell::RefCell::new(None) };
}

/** @brief 이 스레드의 응답 출처를 기록한다. 질의 처리 뒤 로그가 꺼내 쓴다. */
pub fn note_response_source(label: impl Into<std::borrow::Cow<'static, str>>) {
    LAST_SOURCE.with(|slot| *slot.borrow_mut() = Some(ResponseSource::Label(label.into())));
}

/** @brief 응답 출처를 주소로 기록한다. 문자열 조립을 늦추기 위한 형태다. */
fn note_response_addr(addr: SocketAddr) {
    LAST_SOURCE.with(|slot| *slot.borrow_mut() = Some(ResponseSource::Addr(addr)));
}

/** @brief 기록된 응답 출처를 꺼내며 지운다. */
pub fn take_response_source() -> Option<std::borrow::Cow<'static, str>> {
    LAST_SOURCE
        .with(|slot| slot.borrow_mut().take())
        .map(|source| match source {
            ResponseSource::Label(label) => label,
            ResponseSource::Addr(addr) => addr.to_string().into(),
        })
}

/** @brief 응답 출처를 지운다. 이전 질의의 값이 다음 로그에 새지 않게 한다. */
pub fn clear_response_source() {
    LAST_SOURCE.with(|slot| *slot.borrow_mut() = None);
}

/** @brief 시스템 신뢰 저장소. 한 번 읽어 모든 TLS 업스트림이 공유한다. */
fn system_trust() -> Arc<TrustStore> {
    /** @brief 한 번만 읽어 두는 신뢰 저장소. */
    static S: OnceLock<Arc<TrustStore>> = OnceLock::new();
    S.get_or_init(|| Arc::new(TrustStore::system())).clone()
}

/** @brief 폐기 확인 훅의 형식. */
type RevocationHook = Arc<dyn Fn(&[Vec<u8>], &str) -> Result<(), String> + Send + Sync>;

/** @brief 연결 캐시를 신뢰 저장소와 폐기 정책에 묶는 값. */
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TlsCacheScope {
    /** @brief 신뢰 저장소 내용 식별자. */
    trust: [u8; 32],
    /** @brief 폐기 훅이 바뀔 때마다 증가하는 세대. */
    revocation_generation: u64,
}

/** @brief 현재 폐기 정책과 캐시 무효화 세대. */
struct RevocationPolicy {
    /** @brief 설치된 폐기 확인 훅. */
    hook: Option<RevocationHook>,
    /** @brief 정책 변경 세대. */
    generation: u64,
}

/** @brief 설치된 폐기 정책. */
static REVOCATION_POLICY: OnceLock<Mutex<RevocationPolicy>> = OnceLock::new();

/** @brief 폐기 확인 훅 슬롯. */
fn revocation_policy() -> &'static Mutex<RevocationPolicy> {
    REVOCATION_POLICY.get_or_init(|| {
        Mutex::new(RevocationPolicy {
            hook: None,
            generation: 0,
        })
    })
}

/** @brief 현재 TLS 캐시의 보안 정책 범위를 얻는다. */
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
/** @brief 전역 폐기 훅을 바꾸는 테스트와 암호화 전송 테스트를 직렬화한다. */
static REVOCATION_TEST_LOCK: RwLock<()> = RwLock::new(());

#[cfg(test)]
thread_local! {
    /** @brief 쓰기 잠금을 든 테스트 스레드는 자신의 exchange에서 읽기 잠금을 건너뛴다. */
    static REVOCATION_TEST_WRITER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
/** @brief 보통 암호화 전송 테스트가 폐기 정책 변경과 겹치지 않게 한다. */
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
/** @brief 폐기 정책 변경 테스트가 가지고 있을 배타 잠금. */
struct RevocationTestWriteGuard {
    /** @brief 수명 동안 배타성을 유지한다. */
    _guard: std::sync::RwLockWriteGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for RevocationTestWriteGuard {
    fn drop(&mut self) {
        REVOCATION_TEST_WRITER.with(|writer| writer.set(false));
    }
}

#[cfg(test)]
/** @brief 폐기 정책을 바꾸는 테스트를 시작한다. */
fn revocation_test_write_guard() -> RevocationTestWriteGuard {
    let guard = REVOCATION_TEST_LOCK
        .write()
        .unwrap_or_else(|error| error.into_inner());
    REVOCATION_TEST_WRITER.with(|writer| writer.set(true));
    RevocationTestWriteGuard { _guard: guard }
}

/**
 * @brief 인증서 폐기 확인 훅을 설치한다.
 * @details TLS 핸드셰이크 직후, 질의를 보내기 전에 불린다. 폐기된 인증서를 쓰는
 *          업스트림으로 질의가 나가는 것을 막는 지점이다.
 */
pub fn set_revocation_hook(f: Box<dyn Fn(&[Vec<u8>], &str) -> Result<(), String> + Send + Sync>) {
    let mut policy = revocation_policy()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    policy.generation = policy
        .generation
        .checked_add(1)
        .expect("Revocation policy generations exhausted");
    policy.hook = Some(Arc::from(f));
}

/** @brief 폐기 확인 훅을 제거한다. */
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

/**
 * @brief 설치된 훅으로 상대 인증서 체인의 폐기 여부를 확인한다.
 * @details 훅이 없으면 통과다. 폐기 확인은 선택 기능이며, 켜져 있을 때만 강제된다.
 */
pub(crate) fn check_revocation(peer_chain: &[Vec<u8>], host: &str) -> Result<(), ForwardError> {
    let hook = revocation_policy()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .hook
        .clone();
    if let Some(hook) = hook {
        hook(peer_chain, host)
            .map_err(|e| ForwardError::Io(format!("Certificate revocation check failed: {e}")))?;
    }
    Ok(())
}

/** @brief 전달 실패 사유. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardError {
    /** @brief 시도할 업스트림이 남지 않았다. */
    NoUpstream,

    /** @brief 데드라인 안에 답이 오지 않았다. */
    Timeout,

    /** @brief 주고받는 중 오류가 났다. */
    Io(String),

    /** @brief 응답이 질의와 맞지 않는다. 위조 의심 신호이기도 하다. */
    BadResponse,
}

impl std::fmt::Display for ForwardError {
    /** @brief 사람이 읽을 문구. */
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

/**
 * @brief 업스트림 하나의 관측 통계.
 * @details ewma_ms는 지수 이동 평균 응답 시간이다. 최근 표본에 가중치를 두어, 느려진
 *          업스트림이 곧바로 순위에서 밀리게 한다.
 */
#[derive(Debug, Clone, Copy)]
struct UpstreamStat {
    /** @brief 부드럽게 다듬은 응답 시간. 최근 표본에 무게를 둔다. */
    ewma_ms: f64,
    /** @brief 연속 실패 수. 성공하면 0으로 되돌아간다. */
    failures: u32,
    /** @brief 지금까지의 표본 수. */
    samples: u64,

    /** @brief 성공한 수. */
    ok: u64,
    /** @brief 실패한 수. */
    fail: u64,
}

impl Default for UpstreamStat {
    /** @brief 표본이 없는 처음 상태. */
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

/** @brief 업스트림 통계를 밖으로 내보내는 형태. 대시보드와 저장에 쓴다. */
#[derive(Debug, Clone)]
pub struct UpstreamStatReport {
    /** @brief 이 업스트림을 가리키는 이름. */
    pub label: String,
    /** @brief 물어본 수. */
    pub queries: u64,
    /** @brief 성공한 수. */
    pub ok: u64,
    /** @brief 실패한 수. */
    pub fail: u64,
    /** @brief 부드럽게 다듬은 응답 시간. */
    pub ewma_ms: f64,
}

/** @brief 업스트림 통계를 담은 공유 핸들. 전달기와 컨트롤 플레인이 함께 본다. */
#[derive(Clone)]
pub struct ForwardStats {
    /** @brief 업스트림마다의 이름. */
    labels: Vec<String>,
    /** @brief 업스트림마다의 성적. */
    stats: Arc<Vec<Mutex<UpstreamStat>>>,
}

impl ForwardStats {
    /**
     * @brief 저장된 통계를 되살린다. 재시작 후 학습을 처음부터 다시 하지 않게 한다.
     * @note 아직 표본이 없는 업스트림만 채운다. 이미 관측이 쌓였다면 그쪽이 더 최신이다.
     */
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

    /** @brief 현재 통계를 읽어 보고 형태로 만든다. */
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

/** @brief 업스트림 전달기. 업스트림 목록·선택 전략·신뢰 저장소·통계를 함께 가지고 있다. */
pub struct Forwarder {
    /** @brief 쓸 업스트림들. */
    upstreams: Vec<Upstream>,
    /** @brief 요청 하나의 데드라인. */
    timeout: Duration,
    /** @brief 업스트림을 고르는 방식. */
    strategy: Strategy,
    /** @brief 라운드로빈 커서. */
    rr: AtomicUsize,

    /** @brief 병렬 전략에서 동시에 시도할 업스트림 수의 상한. */
    parallel_limit: usize,

    /** @brief 업스트림 인증서를 검증할 루트들. */
    trust: Option<Arc<TrustStore>>,
    /** @brief 업스트림마다의 성적. */
    stats: Arc<Vec<Mutex<UpstreamStat>>>,
}

impl Forwarder {
    /** @brief 평문 UDP 업스트림 목록으로 전달기를 만든다. */
    pub fn new(upstreams: Vec<SocketAddr>, timeout: Duration) -> Self {
        Self::with_upstreams(upstreams.into_iter().map(Upstream::udp).collect(), timeout)
    }

    /** @brief 전송 방식이 지정된 업스트림 목록으로 전달기를 만든다. */
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

    /** @brief 통계 핸들을 얻는다. 컨트롤 플레인이 이걸로 현황을 읽는다. */
    pub fn stats_handle(&self) -> ForwardStats {
        ForwardStats {
            labels: self.upstreams.iter().map(Upstream::label).collect(),
            stats: self.stats.clone(),
        }
    }

    /** @brief 업스트림 선택 전략을 지정한다. */
    pub fn with_strategy(mut self, s: Strategy) -> Self {
        self.strategy = s;
        self
    }

    /** @brief 병렬 전략의 동시 시도 수를 제한한다. 크게 잡을수록 업스트림 부하가 는다. */
    pub fn with_parallel_limit(mut self, limit: usize) -> Self {
        self.parallel_limit = limit;
        self
    }

    /** @brief 암호화 업스트림 검증에 쓸 신뢰 저장소를 지정한다. 없으면 시스템 저장소를 쓴다. */
    pub fn with_trust(mut self, trust: Arc<TrustStore>) -> Self {
        self.trust = Some(trust);
        self
    }

    /** @brief 설정된 업스트림 목록. */
    pub fn upstreams(&self) -> &[Upstream] {
        &self.upstreams
    }

    /** @brief 쓸 신뢰 저장소. 지정된 것이 없으면 시스템 저장소다. */
    fn trust(&self) -> Arc<TrustStore> {
        self.trust.clone().unwrap_or_else(system_trust)
    }

    /**
     * @brief 질의를 업스트림으로 전달한다.
     *
     * @details 나가는 트랜잭션 ID를 새로 뽑고, 돌아온 응답에는 원래 ID를 되돌려 놓는다.
     *          클라이언트가 고른 ID를 그대로 업스트림에 쓰면 예측 가능해져 위조가 쉬워진다.
     * @warning 응답의 AD 비트를 지운다. 이 서버가 검증하지 않은 진정성 표시를 그대로
     *          중계하면 클라이언트가 검증된 응답으로 착각한다.
     */
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

    /**
     * @brief 관측 통계로 업스트림 순서를 정해 시도한다.
     * @details 점수는 응답 시간 이동 평균과 연속 실패 수로 정한다. 실패가 쌓인 업스트림은
     *          뒤로 밀리되 완전히 배제되지는 않는다. 회복했는지 확인할 기회는 남긴다.
     */
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

    /**
     * @brief 시도 결과를 통계에 반영한다.
     * @note 성공으로 세는 것은 최종 응답뿐이다. 참조나 빈 응답까지 성공으로 치면
     *       실제로는 답을 못 주는 업스트림이 계속 1순위에 남는다.
     */
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

    /** @brief 주어진 순서대로 업스트림을 시도한다. 총 데드라인을 남은 시도 수로 나눠 배분한다. */
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

    /**
     * @brief 여러 업스트림에 동시에 보내고 가장 좋은 응답을 고른다.
     * @details 첫 응답이 아니라 응답 등급을 본다. 참조나 빈 응답보다 최종 답이 늦게
     *          와도 그쪽을 택한다. 빠른 "모르겠다"를 답으로 삼으면 안 된다.
     */
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

            /** @brief 병렬 시도 하나의 결과. */
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

/**
 * @brief 남은 데드라인을 남은 시도 수로 나눠 이번 시도의 제한 시간을 정한다.
 * @return 남은 시간이 없거나 나눈 몫이 0이면 None: 더 시도하지 않는다.
 */
fn attempt_timeout(deadline: Instant, attempts_left: usize) -> Option<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() || attempts_left == 0 {
        return None;
    }
    let divisor = u32::try_from(attempts_left).unwrap_or(u32::MAX);
    let timeout = remaining / divisor;
    (!timeout.is_zero()).then_some(timeout)
}

/**
 * @brief 지금부터 timeout 뒤의 데드라인 시각.
 * @note 극단적으로 큰 설정값이 시각 계산을 넘치게 하지 않도록 검사한다. 넘치면 즉시 만료로 바꾼다.
 */
pub(crate) fn deadline_after(timeout: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(timeout).unwrap_or(now)
}

/**
 * @brief 재사용 연결의 첫 시도에 허용할 시간 상한.
 * @details 재사용 연결은 이미 끊겼을 수 있다. 첫 시도를 짧게 끊어야 죽은 연결에 총 예산을
 *          다 쓰지 않고 새 연결로 넘어갈 수 있다.
 */
const FIRST_TRY_CAP_DEFAULT: Duration = Duration::from_millis(1500);

/** @brief 유휴 TCP 연결을 재사용할 수 있는 최대 시간. 넘으면 새로 연다. */
const TCP_IDLE_REUSE_MAX_DEFAULT: Duration = Duration::from_secs(120);

#[cfg(test)]
thread_local! {
    /** @brief 재사용 판정 시간을 테스트에서 바꿔 넣는 슬롯. */
    static REUSE_OVERRIDE: std::cell::Cell<Option<(Duration, Duration)>> =
        const { std::cell::Cell::new(None) };
}

/** @brief 테스트에서 재사용 상한을 바꾼다. 실시간을 기다리지 않고 만료를 확인하려는 용도다. */
#[cfg(test)]
pub(crate) fn set_reuse_caps_for_test(first_try: Duration, tcp_idle: Duration) {
    REUSE_OVERRIDE.with(|c| c.set(Some((first_try, tcp_idle))));
}

/** @brief 테스트용 재사용 상한 재정의를 해제한다. */
#[cfg(test)]
pub(crate) fn clear_reuse_caps_for_test() {
    REUSE_OVERRIDE.with(|c| c.set(None));
}

/** @brief 현재 적용할 첫 시도 상한. */
pub(crate) fn first_try_cap() -> Duration {
    #[cfg(test)]
    if let Some((f, _)) = REUSE_OVERRIDE.with(|c| c.get()) {
        return f;
    }
    FIRST_TRY_CAP_DEFAULT
}

/** @brief 현재 적용할 유휴 재사용 상한. */
pub(crate) fn tcp_idle_reuse_max() -> Duration {
    #[cfg(test)]
    if let Some((_, t)) = REUSE_OVERRIDE.with(|c| c.get()) {
        return t;
    }
    TCP_IDLE_REUSE_MAX_DEFAULT
}

/**
 * @brief 재사용 연결의 첫 시도 데드라인.
 * @details 고정 상한과 남은 예산의 5분의 2 중 작은 쪽이다. 비율을 함께 쓰는 이유는 총
 *          예산이 짧을 때 고정값이 예산 전부를 삼키지 않게 하려는 것이다.
 */
pub(crate) fn bounded_first_try(deadline: Instant) -> Instant {
    let now = Instant::now();
    let slice = deadline.saturating_duration_since(now);
    let cap = first_try_cap().min(slice * 2 / 5);
    now.checked_add(cap).unwrap_or(deadline).min(deadline)
}

/**
 * @brief 업스트림 응답의 등급.
 * @details 전달기가 "이 응답을 답으로 삼을지, 다른 업스트림을 더 볼지"를 정하는 기준이다.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RespClass {
    /** @brief 질문에 실제로 답한 응답. 통계에서 성공으로 세는 것도 이것뿐이다. */
    Final,

    /** @brief 오류라 다른 업스트림을 시도해 볼 만하다. */
    Retryable,

    /**
     * @brief 형식은 성공이지만 답이 없다.
     * @details 근거 SOA 없는 NXDOMAIN, 요청한 이름의 레코드가 없는 NOERROR 등이다.
     *          그대로 쓰면 "없다"는 잘못된 결론을 캐시에 남기게 된다.
     */
    Incomplete,
}

/**
 * @brief 응답을 등급으로 분류한다.
 * @details NXDOMAIN은 근거 SOA가 있어야 최종으로 인정한다. SOA 없는 부정 응답은 캐시할
 *          수 없으므로 미완성으로 본다.
 */
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

/** @brief 최종 답이 아닌 응답을 업스트림별로 센 것. */
static NON_FINAL_COUNTS: OnceLock<Mutex<HashMap<(SocketAddr, RespClass), u64>>> = OnceLock::new();
/** @brief 셀 수 있는 업스트림 수 상한. 없으면 업스트림을 지어내는 것만으로 메모리가 는다. */
const MAX_NON_FINAL_COUNTERS: usize = 1024;

/** @brief 최종이 아닌 응답의 누적 수를 센다. 진단 로그의 빈도를 정하는 데 쓴다. */
fn increment_non_final_count(
    counts: &mut HashMap<(SocketAddr, RespClass), u64>,
    key: (SocketAddr, RespClass),
) -> u64 {
    if !counts.contains_key(&key) && counts.len() >= MAX_NON_FINAL_COUNTERS {
        if let Some(victim) = counts.keys().next().copied() {
            counts.remove(&victim);
        }
    }
    let count = counts.entry(key).or_insert(0);
    *count = count.saturating_add(1);
    *count
}

/**
 * @brief 최종이 아닌 응답을 진단 로그로 남긴다.
 * @note 카운터가 유계이며 로그도 빈도를 줄여 남긴다. 업스트림이 계속 미완성 응답을 보내는
 *       상황에서 로그 자체가 부하가 되지 않게 한다.
 */
fn observe_non_final(upstream: &Upstream, class: RespClass, request: &Message, response: &Message) {
    let count = {
        let mut counts = NON_FINAL_COUNTS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        increment_non_final_count(&mut counts, (upstream.addr, class))
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
            upstream = %upstream.addr,
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

/** @brief 지금까지 본 것 중 더 좋은 등급의 응답을 남긴다. */
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

/**
 * @brief 부정 응답의 근거 SOA가 질의 이름의 조상 zone에서 왔는지.
 * @warning 소속을 확인하지 않으면 아무 SOA나 붙인 응답이 "이 이름은 없다"의 근거가 되어,
 *          공격자가 임의 이름에 대한 부정 응답을 캐시에 심을 수 있다.
 */
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

/**
 * @brief 응답이 실제로 질문한 것에 답했는지.
 * @details CNAME/DNAME 체인을 따라가 종착 이름의 레코드가 있는지 본다. 체인을 따라가지
 *          않으면 정상적인 별칭 응답을 미완성으로 잘못 판정한다.
 */
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

/** @brief 이 이름의 CNAME 대상을 찾는다. */
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

/** @brief DNAME 치환으로 만들어지는 대상 이름을 구한다. */
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

/**
 * @brief 별칭 체인을 따라가 최종 이름을 구한다.
 * @note 체인 길이에 상한이 있다. 없으면 서로를 가리키는 CNAME 쌍에서 무한히 돈다.
 */
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

/** @brief 업스트림 하나와 한 번 교환한다. 전송 방식에 맞는 모듈로 갈라진다. */
fn exchange_one(
    up: &Upstream,
    wire: &[u8],
    wire_id: u16,
    request: &Message,
    timeout: Duration,
    trust: &TrustStore,
) -> Result<Message, ForwardError> {
    match &up.transport {
        Transport::Udp => udp_exchange(up.addr, wire, wire_id, request, timeout, false),
        Transport::Tcp => tcp_exchange(up.addr, wire, wire_id, request, timeout),
        Transport::Dot { server_name } => {
            dot::exchange(up.addr, server_name, wire, wire_id, request, timeout, trust)
        }
        Transport::Doh { server_name, path } => {
            doh::exchange(up.addr, server_name, path, wire, request, timeout, trust)
        }
        Transport::Doq { server_name } => {
            doq::exchange(up.addr, server_name, wire, request, timeout, trust)
        }
        Transport::Doh3 { server_name, path } => {
            doh3::exchange(up.addr, server_name, path, wire, request, timeout, trust)
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
/**
 * @brief 질의 이름의 대소문자를 어떻게 다룰지.
 * @details 대소문자를 섞어 보내면 위조 응답을 맞히기가 어려워진다. 다만 그 섞은 형태를
 *          그대로 되받아야 하므로, 업스트림이 그러지 못하면 쓸 수 없다.
 */
enum CasePolicy {
    /** @brief 소문자로 맞춘다. */
    Normalized,

    /** @brief 섞은 형태를 그대로 되받아야 한다. */
    Exact,

    /** @brief 합칠 때는 대소문자를 무시하되 부른 쪽 형태로 돌려준다. */
    MergedExact,
}

/**
 * @brief 지정한 서버에 직접 질의한다. 재귀 리졸버가 권한 서버에 물을 때 쓴다.
 * @details 질의 이름 대소문자는 응답에서 합쳐 준다(대소문자 무시 비교).
 */
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

/**
 * @brief 응답의 질의 이름 대소문자가 보낸 것과 정확히 같아야 하는 질의.
 * @details 0x20 대소문자 인코딩의 검증 지점이다. 응답의 대소문자 패턴이 이 서버가 보낸
 *          무작위 패턴과 다르면 위조로 보고 버린다.
 */
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

/** @brief 대소문자를 합쳐 비교하는 질의. 0x20 인코딩을 쓰지 않을 때의 경로다. */
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/** @brief 권한 서버에 직접 질의할 때 쓰는 전송. */
pub enum AuthorityTransport {
    /** @brief UDP로 보내고, 잘린 응답이면 TCP로 다시 받는다. */
    Udp,

    /**
     * @brief 처음부터 TCP로 보낸다.
     * @details 중간 장비가 UDP 53번만 가로채 대신 답하는 망에서 쓴다. 그런 망에서는
     *          UDP 응답이 권한 서버가 보낸 것이 아니다.
     */
    Tcp,
}

/**
 * @brief 전송을 골라 권한 서버에 직접 질의한다.
 * @param merge_case 참이면 대소문자를 합쳐 비교하고 부른 쪽 형태로 돌려준다. 거짓이면
 *                   소문자로 맞춘다.
 */
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

/** @brief 대소문자 정책을 인자로 받는 직접 질의의 공통 구현. */
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
    let key = AuthorityQueryKey::from_wire(server, &wire, normalize_key_case)
        .or_else(|| AuthorityQueryKey::from_request(server, request, normalize_key_case));
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

/** @brief 응답의 질문 섹션이 보낸 것과 옥텟 단위로 같은지. 0x20 검증의 핵심 비교다. */
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

/** @brief 단일 비행에 묶지 않고 곧바로 업스트림과 교환한다. */
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
    };
    response.header.id = request.header.id;
    Ok(response)
}

/**
 * @brief DoH/DoT 서버 이름을 부트스트랩 리졸버로 푼다.
 *
 * @details 암호화 업스트림에 붙으려면 그 서버의 주소를 알아야 하는데, 그 조회 자체를 그
 *          업스트림으로 할 수는 없다. 그래서 별도의 부트스트랩 서버를 쓴다.
 * @warning 질의한 이름의 CNAME 체인 위에 있는 주소만 받아들인다. 응답에 딸려 온
 *          다른 이름의 주소를 그대로 쓰면, 부트스트랩 서버가 이 서버를 임의의 서버로
 *          유도할 수 있다.
 */
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

/**
 * @brief 부트스트랩 응답에서 주소를 추출한다.
 * @details 별칭 체인을 따라가며 그 체인에 속한 이름의 주소만 모은다. 체인이 서로 어긋나는
 *          응답은 전체를 버린다.
 */
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

/** @brief 평문 UDP로 한 번 교환한다. 소켓은 풀에서 꺼내 쓴다. */
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

/** @brief 주고받는 데 쓰는 소켓과 지금 걸린 데드라인. */
struct ExchangeSocket<'a> {
    /** @brief 쓰고 있는 소켓. */
    sock: &'a UdpSocket,
    /** @brief 그 소켓에 지금 걸린 수신 데드라인. */
    rcv_timeout: Option<Duration>,
}

/**
 * @brief 주어진 소켓으로 UDP 교환을 수행한다.
 *
 * @details 데드라인까지 응답을 계속 받아 본다. 트랜잭션 ID나 질문이 어긋난 응답은 버리고
 *          계속 기다린다. 위조 시도가 정상 응답의 슬롯을 뺏지 못하게 하려는 것이다.
 * @warning 다만 그 반복이 데드라인 안에서만 일어난다. 무효 응답을 쏟아붓는 공격자가 질의
 *          예산을 늘리지 못한다.
 * @note TC 비트가 선 응답을 받으면 TCP로 재시도한다.
 */
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
            sock.recv_from(&mut buf)
                .map(|(n, from)| (from, Message::parse_udp_reply(&buf[..n])))
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

/** @brief 보관 중인 유휴 평문 TCP 연결 하나. */
struct IdleTcp {
    /** @brief 이어진 연결. */
    stream: TcpStream,
    /** @brief 마지막으로 응답을 받은 시각. */
    last_used: Instant,
}

/** @brief 유휴 평문 TCP 연결을 보관하는 풀. 키는 (바인드 주소, 서버 주소)다. */
#[derive(Default)]
struct TcpIdlePool {
    /** @brief 서버별 유휴 연결. */
    idle: HashMap<(SocketAddr, SocketAddr), Vec<IdleTcp>>,
    /** @brief 모든 서버에 걸친 유휴 연결 수. */
    total: usize,
}

/** @brief 서버 하나에 보관할 유휴 연결 수 상한. 같은 서버에 동시에 묻는 질의 수만큼 필요하다. */
const TCP_IDLE_PER_SERVER: usize = 2;

/**
 * @brief 모든 서버에 걸쳐 보관할 유휴 연결 수 상한.
 * @note 재귀는 서버를 수백 곳 거친다. 상한이 없으면 유휴 연결이 파일 디스크립터를 다 쓴다.
 */
const TCP_IDLE_TOTAL: usize = 256;

/**
 * @brief 프로세스가 공유하는 유휴 평문 TCP 연결 풀.
 * @details 스레드마다 두면 재귀가 서버마다 따로 띄우는 교환 스레드가 서로의 연결을 쓰지 못한다.
 */
fn tcp_idle_pool() -> &'static Mutex<TcpIdlePool> {
    /** @brief 처음 쓸 때 만드는 풀. */
    static POOL: OnceLock<Mutex<TcpIdlePool>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(TcpIdlePool::default()))
}

/**
 * @brief 이 서버로 이어 둔 유휴 연결을 꺼낸다. 너무 오래 쉰 연결은 버린다.
 * @note 서버가 그사이 닫은 연결도 꺼내질 수 있다. 그런 연결은 질의를 보내면 곧바로 EOF가
 *       읽혀 새 연결로 넘어가므로 따로 확인하지 않는다.
 */
fn take_idle_tcp(bind: SocketAddr, upstream: SocketAddr) -> Option<TcpStream> {
    let mut pool = tcp_idle_pool()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let TcpIdlePool { idle, total } = &mut *pool;
    let conns = idle.get_mut(&(bind, upstream))?;
    let mut found = None;
    while let Some(conn) = conns.pop() {
        *total -= 1;
        if conn.last_used.elapsed() < tcp_idle_reuse_max() {
            found = Some(conn.stream);
            break;
        }
    }
    if conns.is_empty() {
        idle.remove(&(bind, upstream));
    }
    found
}

/** @brief 응답을 온전히 받은 연결을 풀에 돌려놓는다. 상한을 넘으면 닫는다. */
fn return_idle_tcp(bind: SocketAddr, upstream: SocketAddr, stream: TcpStream) {
    let mut pool = tcp_idle_pool()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if pool.total >= TCP_IDLE_TOTAL {
        return;
    }
    let conns = pool.idle.entry((bind, upstream)).or_default();
    if conns.len() >= TCP_IDLE_PER_SERVER {
        return;
    }
    conns.push(IdleTcp {
        stream,
        last_used: Instant::now(),
    });
    pool.total += 1;
}

/**
 * @brief 평문 TCP로 교환한다. 2바이트 길이 접두사 프레이밍을 쓴다.
 * @details 이 서버로 이어 둔 연결이 있으면 먼저 그것으로 묻는다. 새 연결은 핸드셰이크 왕복이
 *          한 번 더 들어, 멀리 있는 서버는 질의 하나에 수백 밀리초가 붙는다. 이어 둔 연결은
 *          그사이 끊겼을 수 있으므로 첫 시도를 짧게 끊고, 실패하면 새 연결로 다시 묻는다.
 */
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

/** @brief 이어진 연결로 길이 접두사가 붙은 질의 하나를 보내고 응답 하나를 읽는다. */
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

/** @brief 데드라인 안에서 전부 쓴다. 부분 쓰기마다 남은 시간을 다시 계산한다. */
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

/**
 * @brief 데드라인 안에서 버퍼를 정확히 채운다.
 * @warning 부분 읽기마다 절대 데드라인을 다시 본다. 소켓 타임아웃만 쓰면 한 바이트씩
 *          천천히 보내는 상대가 예산을 무한정 늘릴 수 있다.
 */
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

/** @brief 응답의 질문이 이 서버가 보낸 것과 같은지. */
pub(crate) fn question_matches(req: &Message, resp: &Message) -> bool {
    req.questions.len() == resp.questions.len()
        && req.questions.iter().zip(&resp.questions).all(|(a, b)| {
            a.qtype == b.qtype && a.qclass == b.qclass && a.name.eq_ignore_case(&b.name)
        })
}

/**
 * @brief 이 응답을 받아들여도 되는지.
 * @warning 번호와 질문이 모두 맞아야 한다. 확인하지 않으면 아무나 보낸 응답이 이 서버의
 *          캐시에 들어간다.
 */
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

/** @brief 입출력 오류를 전달 실패 사유로. */
pub(crate) fn io_err(e: std::io::Error) -> ForwardError {
    if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
        ForwardError::Timeout
    } else {
        ForwardError::Io(e.to_string())
    }
}

/**
 * @brief 암호화 업스트림에 연결하지 못한 사유를 남긴다.
 * @details 이 사유는 위로 올라가며 TransportExhausted로 접혀 사라진다. 인증서 만료인지
 *          미지 CA인지 그냥 닿지 않는 것인지는 여기서만 알 수 있고, 그것이 암호화 업스트림
 *          장애의 대부분이다.
 * @note 전송별로 2의 거듭제곱 번째만 남긴다. 업스트림이 죽으면 질의마다 실패하기 때문이다.
 */
pub(crate) fn note_upstream_connect_failure(
    transport: &'static str,
    addr: SocketAddr,
    server_name: &str,
    error: &impl std::fmt::Display,
) {
    use std::sync::atomic::{AtomicU64, Ordering};
    /** @brief 전송별 누적 실패 수. dot·doh·doq·doh3 순이다. */
    static COUNTS: [AtomicU64; 4] = [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ];
    let slot = match transport {
        "dot" => 0,
        "doh" => 1,
        "doq" => 2,
        _ => 3,
    };
    let count = COUNTS[slot].fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::warn!(event = "forward.upstream_connect_failed", transport = transport, addr = %addr, server_name = server_name, count = count, %error, "Could not connect to the encrypted upstream DNS server");
    }
}

/** @brief 병렬로 돌릴 일 하나. */
type ParallelJob = Box<dyn FnOnce() + Send + 'static>;

/** @brief 동시에 진행할 병렬 시도 수 상한. */
const MAX_PARALLEL_INFLIGHT: usize = 512;
/** @brief 병렬 워커가 일이 없을 때 남아 있을 시간. */
const PARALLEL_WORKER_IDLE: Duration = Duration::from_secs(30);
/** @brief 지금 진행 중인 병렬 시도 수. */
static PARALLEL_INFLIGHT: AtomicUsize = AtomicUsize::new(0);
/** @brief 병렬 시도를 돌리는 워커 풀. */
static PARALLEL_EXECUTOR: OnceLock<ParallelExecutor> = OnceLock::new();

/** @brief 아직 시작하지 않은 병렬 시도들. */
struct ParallelQueue {
    /** @brief 먼저 들어온 일을 먼저 꺼낸다. */
    jobs: VecDeque<ParallelJob>,
}

/** @brief 수요에 따라 커졌다가 유휴 시 비워지는 병렬 워커 공유 상태. */
struct ParallelExecutorShared {
    /** @brief 대기열. */
    queue: Mutex<ParallelQueue>,
    /** @brief 새 일이 들어왔음을 알린다. */
    ready: Condvar,
    /** @brief 현재 살아 있는 워커 수. */
    live: AtomicUsize,
    /** @brief 일을 맡을 수 있는 워커 수. 새로 시작하는 중인 워커도 포함한다. */
    idle: AtomicUsize,
    /** @brief 스레드 이름에 붙일 단조 번호. */
    next_worker: AtomicUsize,
}

/** @brief 병렬 전략의 bounded 동적 워커 풀. */
struct ParallelExecutor {
    /** @brief 워커들이 공유하는 상태. */
    shared: Arc<ParallelExecutorShared>,
    /** @brief 대기열 크기 상한. */
    capacity: usize,
    /** @brief 살아 있을 수 있는 워커 수 상한. */
    max_workers: usize,
    /** @brief 일이 없어진 워커를 회수할 때까지 기다릴 시간. */
    idle_timeout: Duration,
}

impl ParallelExecutor {
    /** @brief 빈 풀을 만든다. 첫 일이 오기 전에는 스레드가 없다. */
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

    /** @brief 워커 하나를 예약하고 시작한다. 호출자는 queue 잠금을 잡고 있어야 한다. */
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
                /** @brief 반복 자원 고갈이 로그 고갈로 번지지 않게 표본만 남긴다. */
                static FAILURES: AtomicUsize = AtomicUsize::new(0);
                let count = FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
                if count.is_power_of_two() {
                    onetdns_core::warn!(event = "forward.parallel_worker_start_failed", index, count, %error, "Could not start parallel upstream query workers; handling those queries sequentially");
                }
                false
            }
        }
    }

    /** @brief 일을 넣고, 지금 밀린 양을 받을 만큼만 워커를 늘린다. */
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

/** @brief 병렬 워커 하나의 반복. 작업 패닉은 이 일에만 가두고 다음 일을 받는다. */
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

/** @brief 병렬 전략이 쓸 실행 스레드 수. */
fn parallel_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().saturating_mul(4))
        .unwrap_or(32)
        .clamp(8, 128)
}

/** @brief 병렬 시도를 실행할 공용 동적 풀. */
fn parallel_executor() -> &'static ParallelExecutor {
    PARALLEL_EXECUTOR.get_or_init(|| {
        ParallelExecutor::new(
            parallel_worker_count(),
            MAX_PARALLEL_INFLIGHT,
            PARALLEL_WORKER_IDLE,
        )
    })
}

/** @brief 병렬 작업을 제출한다. 큐가 가득 차면 false: 호출자가 직렬로 처리한다. */
fn submit_parallel_job<F>(job: F) -> bool
where
    F: FnOnce() + Send + 'static,
{
    parallel_executor().try_submit(Box::new(job))
}

/**
 * @brief 병렬 시도 슬롯을 잡는다.
 * @return 실제로 확보한 수. 전역 상한이 있어 동시 질의가 많아도 업스트림 부하가 폭발하지 않는다.
 */
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

/** @brief 병렬 시도 슬롯을 반납한다. */
fn release_parallel_slot() {
    PARALLEL_INFLIGHT.fetch_sub(1, Ordering::Relaxed);
}

/** @brief 병렬 시도 슬롯 하나. 끝나면 스스로 반납한다. */
struct ParallelSlot;
impl Drop for ParallelSlot {
    /** @brief 슬롯을 반납한다. */
    fn drop(&mut self) {
        release_parallel_slot();
    }
}

/**
 * @brief 업스트림으로 나갈 트랜잭션 ID를 추출한다.
 * @warning 반드시 보안 난수여야 한다. 순차 증가나 예측 가능한 값이면 위조 응답을 맞히기가
 *          쉬워져 캐시 오염의 문턱이 크게 낮아진다.
 */
fn next_id() -> u16 {
    u16::from_be_bytes(onetdns_core::ephemeral_random_array())
}

#[cfg(test)]
/** @brief 응답 검증, 같은 질의 합치기, 데드라인이 늘어나지 않는지, 그리고 업스트림 고르기. */
mod tests {
    use super::*;
    use onetdns_proto::{Name, RData, Record, RecordType, ResponseCode};
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};
    use std::sync::{Arc, Barrier};

    /** @brief 짧은 동시성 테스트에서 조건이 될 때까지만 기다린다. */
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
    /** @brief 병렬 풀이 실제 수요만큼만 커지고, 쉰 뒤 0으로 줄었다가 다시 깨어나는지. */
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
    /** @brief 병렬 시도 하나의 패닉이 유일한 워커를 죽이지 않는지. */
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
    /** @brief 합치는 곳이 상한을 지키면서도 이미 합쳐진 것이 깨지지 않는지. */
    fn authority_single_flight_state_is_bounded_without_breaking_existing_sharing() {
        let mut flights = HashMap::new();
        for index in 0..MAX_AUTHORITY_FLIGHTS {
            let key = AuthorityQueryKey {
                server: SocketAddr::from(([192, 0, 2, 1], 53)),
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
            normalized_wire: b"overflow".to_vec().into(),
        };
        assert!(acquire_authority_flight(&mut flights, &overflow).is_none());
        assert_eq!(flights.len(), MAX_AUTHORITY_FLIGHTS);
    }

    #[test]
    /** @brief 바이트로 만든 키와 메시지로 만든 키가 같은지. */
    fn wire_key_matches_message_key_and_collapses_case() {
        let server = SocketAddr::from(([192, 0, 2, 7], 53));
        let upper = query("MiXeD.Example");
        let lower = query("mixed.example");
        let wire_upper = upper.try_encode().unwrap();
        let wire_lower = lower.try_encode().unwrap();

        let by_wire_upper = AuthorityQueryKey::from_wire(server, &wire_upper, true).unwrap();
        let by_wire_lower = AuthorityQueryKey::from_wire(server, &wire_lower, true).unwrap();
        let by_message = AuthorityQueryKey::from_request(server, &upper, true).unwrap();
        assert_eq!(by_wire_upper, by_wire_lower);
        assert_eq!(by_wire_upper, by_message);

        let exact_upper = AuthorityQueryKey::from_wire(server, &wire_upper, false).unwrap();
        let exact_lower = AuthorityQueryKey::from_wire(server, &wire_lower, false).unwrap();
        assert_ne!(exact_upper, exact_lower);
        assert_eq!(
            exact_upper,
            AuthorityQueryKey::from_request(server, &upper, false).unwrap()
        );
    }

    #[test]
    /** @brief 같은 스레드가 자기 자신을 기다리지 않는지. 기다리면 그대로 멈춘다. */
    fn same_thread_leader_flight_is_bypassed_not_joined() {
        let server = SocketAddr::from(([192, 0, 2, 1], 53));
        let request = Message::query(1, Name::from_str("nest.example").unwrap(), RecordType::A);
        let key = AuthorityQueryKey::from_request(server, &request, true).unwrap();
        let mut flights = HashMap::new();

        let (leader_flight, leader) = acquire_authority_flight(&mut flights, &key).unwrap();
        assert!(leader);

        assert!(acquire_authority_flight(&mut flights, &key).is_none());
        assert_eq!(leader_flight.waiters.load(Ordering::SeqCst), 0);

        let other = std::thread::spawn(move || {
            let mut flights = HashMap::new();
            let request =
                Message::query(2, Name::from_str("cross.example").unwrap(), RecordType::A);
            let key = AuthorityQueryKey::from_request(server, &request, true).unwrap();
            let _ = acquire_authority_flight(&mut flights, &key).unwrap();
            (flights, key)
        });
        let (mut flights, key) = other.join().unwrap();
        let (cross_flight, leader) = acquire_authority_flight(&mut flights, &key).unwrap();
        assert!(!leader);
        assert_eq!(cross_flight.waiters.load(Ordering::SeqCst), 1);
    }

    #[test]
    /** @brief 너무 큰 질의는 합치지 않고 그냥 나가는지. */
    fn oversized_authority_queries_bypass_global_single_flight_state() {
        let server = SocketAddr::from(([192, 0, 2, 1], 53));
        let mut request =
            Message::query(1, Name::from_str("large.example").unwrap(), RecordType::A);
        request.additionals.push(Record::new(
            Name::root(),
            0,
            RData::Unknown(65_000, vec![0; MAX_AUTHORITY_FLIGHT_KEY_BYTES + 1]),
        ));
        assert!(AuthorityQueryKey::from_request(server, &request, true).is_none());
    }

    #[test]
    /** @brief 키에서 이름의 원래 바이트가 바뀌지 않는지. */
    fn authority_single_flight_key_preserves_raw_qname_octets() {
        let server = SocketAddr::from(([192, 0, 2, 1], 53));
        let request = |id, label| {
            Message::query(
                id,
                Name::from_labels(vec![vec![label]]).unwrap(),
                RecordType::A,
            )
        };

        let first = AuthorityQueryKey::from_request(server, &request(1, 0xff), true).unwrap();
        let second = AuthorityQueryKey::from_request(server, &request(2, 0xfe), true).unwrap();
        assert_ne!(first, second);

        let upper = Message::query(3, Name::from_str("WWW.example").unwrap(), RecordType::A);
        let lower = Message::query(4, Name::from_str("www.EXAMPLE").unwrap(), RecordType::A);
        assert_eq!(
            AuthorityQueryKey::from_request(server, &upper, true),
            AuthorityQueryKey::from_request(server, &lower, true)
        );
    }

    #[test]
    /** @brief 아주 큰 데드라인 값이 시각 계산을 넘치게 하지 않는지. */
    fn extreme_timeout_cannot_overflow_instant_deadline() {
        let before = Instant::now();
        let deadline = deadline_after(Duration::MAX);
        assert!(deadline >= before);
        assert!(deadline <= Instant::now());
    }

    #[test]
    /** @brief 소켓을 여러 개 열어 출발 포트를 분산하는지. 한 포트만 쓰면 위조를 맞히기 쉬워진다. */
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
    /** @brief 보관한 소켓의 데드라인이 지금 데드라인을 넘지 않는지. */
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
    /** @brief 소켓을 정해진 횟수마다 새로 여는지. */
    fn udp_socket_pool_retires_by_use_count() {
        let bind: SocketAddr = "127.0.0.2:0".parse().unwrap();
        let (sock, _, _) = take_pooled_udp_socket(bind).unwrap();

        return_pooled_udp_socket(bind, sock, UDP_SOCKET_POOL_MAX_USES, None);
        let (next, uses, _) = take_pooled_udp_socket(bind).unwrap();
        assert_eq!(uses, 1, "수명 소진 후 새 소켓");
        drop(next);
    }

    #[test]
    /** @brief 실패해도 소켓 슬롯이 새 나가지 않는지. */
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
    /** @brief 인코딩하지 못한 질의를 오류 응답 바이트로 내보내지 않는지. */
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
    /** @brief 업스트림별 카운터가 상한을 지키는지. */
    fn non_final_observation_counters_stay_bounded() {
        let mut counts = HashMap::new();
        for port in 1..=MAX_NON_FINAL_COUNTERS as u16 {
            increment_non_final_count(
                &mut counts,
                (
                    SocketAddr::from(([192, 0, 2, 1], port)),
                    RespClass::Retryable,
                ),
            );
        }
        assert_eq!(counts.len(), MAX_NON_FINAL_COUNTERS);
        let new_key = (
            SocketAddr::from(([192, 0, 2, 2], 53)),
            RespClass::Incomplete,
        );
        assert_eq!(increment_non_final_count(&mut counts, new_key), 1);
        assert_eq!(counts.len(), MAX_NON_FINAL_COUNTERS);
        assert_eq!(increment_non_final_count(&mut counts, new_key), 2);
    }

    #[test]
    /** @brief 부트스트랩이 물어본 체인 위의 주소만 받아들이는지. 아니면 남이 끼워 넣은 주소로 접속한다. */
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
    /** @brief 서로 어긋나는 별칭이 든 답을 거부하는지. */
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
    /** @brief 부트스트랩 데드라인이 전체에 걸리는지. */
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

    /**
     * @brief 연결마다 질의를 받아 빈 응답을 돌려주는 TCP 서버를 띄운다.
     * @param close_after_answer 참이면 응답 하나를 보낸 뒤 연결을 닫는다.
     * @return 서버 주소와, 지금까지 받아들인 연결 수.
     */
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

    /** @brief 이 서버에 TCP로 한 번 묻는다. */
    fn ask_over_tcp(addr: SocketAddr, id: u16) -> Result<Message, ForwardError> {
        let request = Message::query(id, Name::from_str("pool.example").unwrap(), RecordType::A);
        let wire = request.try_encode().unwrap();
        tcp_exchange(addr, &wire, id, &request, Duration::from_secs(2))
    }

    #[test]
    /**
     * @brief 같은 서버에 잇따라 물으면 이어 둔 연결을 다시 쓰는지.
     * @details 새 연결은 핸드셰이크 왕복이 한 번 더 든다. UDP 53번이 막혀 권한 서버에 TCP로
     *          묻는 망에서는 질의마다 이 왕복이 붙는다.
     */
    fn tcp_exchange_reuses_the_connection_to_the_same_server() {
        let (addr, accepted) = spawn_tcp_answerer(false);
        ask_over_tcp(addr, 0x7001).expect("첫 질의");
        ask_over_tcp(addr, 0x7002).expect("둘째 질의");
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
    }

    #[test]
    /**
     * @brief 서버가 닫은 연결로 묻다 실패하면 곧바로 새 연결로 다시 묻는지.
     * @details 권한 서버는 유휴 연결을 몇 초 만에 닫기도 한다. 이어 둔 연결이 닫혔다고 질의가
     *          실패하거나 제한 시간까지 기다리면 재사용이 오히려 해가 된다.
     */
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
    /** @brief 한 바이트씩 흘려 보내는 업스트림이 데드라인을 늘리지 못하는지. */
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
    /** @brief 읽을 때마다 데드라인이 되살아나지 않는지. */
    fn deadline_tcp_slow_drip_cannot_reset_socket_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for byte in 0..10 {
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(30));
            }
        });

        let started = Instant::now();
        let mut stream = DeadlineTcp::connect(addr, started + Duration::from_millis(120)).unwrap();
        let mut bytes = [0u8; 10];
        let error = stream.read_exact(&mut bytes).unwrap_err();
        assert!(matches!(
            error.kind(),
            ErrorKind::WouldBlock | ErrorKind::TimedOut
        ));
        assert!(started.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
    }

    #[test]
    /** @brief 엉뚱한 응답을 쏟아부어도 데드라인이 늘지 않는지. */
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
    /** @brief 여러 업스트림을 차례로 시도하는 동안 데드라인이 하나로 유지되는지. */
    fn failover_strategies_share_one_overall_deadline() {
        /** @brief 답하지 않는 테스트용 주소들. */
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
    /** @brief 나갈 때 묶을 주소를 제대로 고르는지. */
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

    /** @brief 이 질의에 대한 테스트용 답. */
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

    /** @brief 고정 답을 내는 테스트용 업스트림. */
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

    /** @brief 빈 응답을 내는 테스트용 업스트림. */
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

    /** @brief 별칭만 답하는 테스트용 업스트림. */
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

    /** @brief 테스트용 질의. */
    fn query(name: &str) -> Message {
        Message::query(0xBEEF, Name::from_str(name).unwrap(), RecordType::A)
    }

    #[test]
    /** @brief 어느 방식으로 골라도 성적이 기록되는지. */
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
    /** @brief 저장해 둔 성적이 이어지되 지금 성적을 덮지 않는지. */
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
    /** @brief 닿지 않는 업스트림의 실패가 기록되는지. */
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
    /** @brief 평문으로 전달되는지. */
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
    /** @brief 같은 질의가 몰려도 밖으로는 하나만 나가는지. */
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
    /** @brief 기다리는 쪽이 깨어나는지. */
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
    /** @brief 늦게 온 쪽도 결과를 보는지. */
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
    /** @brief 대소문자를 섞어 보낼 때 그 형태가 유지되는지. 소문자로 바꾸면 위조 방어가 사라진다. */
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
    /** @brief 되받은 형태가 다르면 거부하는지. */
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
    /** @brief 어긋난 응답을 무시하고 맞는 응답을 계속 기다리는지. */
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
    /** @brief 합칠 때 대소문자를 무시하되 부른 쪽 형태로 돌려주는지. */
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
    /** @brief 임의로 만든 소문자 응답을 무시하는지. */
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
    /** @brief 다른 곳에서 온 그럴싸한 응답을 무시하는지. */
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
    /**
     * @brief 답을 못 받은 질의가 걸렸던 소켓을 다시 쓰지 않는지.
     *
     * @details SAD DNS 방어 네 겹 중 마지막이다. 답이 오지 않았다는 것은 그 포트가 이미
     *          관측됐을 수 있다는 뜻이므로, 소켓을 풀에 돌려주면 다음 질의가 같은 포트로
     *          나가 관측 구간이 이어진다. 소켓 재사용은 바인드 시스템 호출을 아끼는 그럴듯한
     *          최적화로 보이기 때문에 여기서 못 고정해 둔다.
     */
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

    /**
     * @brief 같은 포트에서 UDP 와 TCP 로 답하는 가짜 업스트림을 띄운다.
     * @param udp_reply UDP 질의에 돌려줄 바이트를 만든다. TCP 는 항상 9.9.9.9 를 담은 온전한 답이다.
     */
    fn spawn_udp_tcp_upstream(udp_reply: fn(&Message) -> Vec<u8>) -> SocketAddr {
        let mut pair = None;
        let mut last_error = None;
        let mut taken = Vec::new();
        for _ in 0..128 {
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
        let (tcp, udp, addr) =
            pair.unwrap_or_else(|| panic!("같은 포트 UDP/TCP 바인딩 128회 실패: {last_error:?}"));
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

    /** @brief 가짜 업스트림에 물어 TCP 로 받은 온전한 답이 나오는지 확인하고 걸린 시간을 돌려준다. */
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
    /** @brief 잘린 응답에 TCP로 다시 묻는지. */
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
    /**
     * @brief TC 없이 레코드 중간에서 끊긴 UDP 응답에 곧바로 TCP 로 다시 묻는지.
     * @details UDP 53 을 가로채는 프록시가 512바이트에서 이렇게 자른다. 버리고 기다리면
     *          질의 제한 시간을 다 쓰고 실패한다.
     */
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
    /** @brief 첫 업스트림이 안 되면 다음으로 넘어가는지. */
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
    /** @brief 오류 응답에 다음 업스트림으로 넘어가는지. */
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
    /** @brief 오류 응답이 성적에 반영되는지. */
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
    /** @brief 근거 없이 비어 온 응답에 다음 업스트림으로 넘어가는지. */
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
    /** @brief 별칭만 온 응답에 다음 업스트림으로 넘어가는지. */
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
    /** @brief 전부 실패하면 오류로 답하는지. */
    fn all_upstreams_servfail_returns_servfail() {
        let a = mock_udp_empty(ResponseCode::ServFail.0, Duration::ZERO);
        let b = mock_udp_empty(ResponseCode::ServFail.0, Duration::ZERO);
        let fwd = Forwarder::new(vec![a, b], Duration::from_secs(2));

        let response = fwd.resolve(&query("allfail.example.com")).unwrap();
        assert_eq!(response.header.rcode, ResponseCode::ServFail.0);
    }

    #[test]
    /** @brief 근거 없는 부정 응답에 다음 업스트림으로 넘어가는지. */
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
    /** @brief 최종 답으로 인정하려면 부류가 맞고 근거가 있어야 하는지. */
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
    /** @brief 다시 물어도 같은 오류는 최종으로 보는지. */
    fn yxdomain_is_final_not_retryable() {
        let request = Message::query(1, Name::from_str("host.example").unwrap(), RecordType::A);
        let mut response = request.clone();
        response.header.response = true;
        response.header.rcode = ResponseCode::YXDomain.0;
        assert_eq!(response_class(&request, &response), RespClass::Final);
    }

    #[test]
    /** @brief 무관하거나 서로 어긋나는 답을 최종으로 보지 않는지. */
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
    /** @brief 업스트림이 하나도 없으면 그 사유로 실패하는지. */
    fn no_upstream_errors() {
        let fwd = Forwarder::new(vec![], Duration::from_secs(1));
        assert!(matches!(
            fwd.resolve(&query("x.com")),
            Err(ForwardError::NoUpstream)
        ));
    }

    /** @brief 느리게 답하는 테스트용 업스트림. */
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
    /** @brief 동시에 물었을 때 가장 빠른 답을 쓰는지. */
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
    /** @brief 빠른 오류보다 늦은 최종 답을 고르는지. 빠른 것만 보면 오류가 이긴다. */
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
    /** @brief 동시 수 상한이 업스트림 선택을 줄이지 않는지. */
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
    /** @brief 죽은 업스트림이 섞여 있어도 답을 받는지. */
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
    /** @brief 서버와 전달을 이어 실제로 질의가 오가는지. */
    fn e2e_runtime_plus_forwarder() {
        use onetdns_runtime::{Handler, RequestCtx, Server, ServerConfig};

        let up = mock_udp(Ipv4Addr::new(2, 2, 2, 2));

        /** @brief 전달로 답하는 테스트용 핸들러. */
        struct FwdHandler {
            /** @brief 전달로 답하는 것. */
            fwd: Forwarder,
        }
        impl Handler for FwdHandler {
            /** @brief 전달해 답한다. */
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
