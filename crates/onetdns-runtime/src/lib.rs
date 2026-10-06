/*!
 * @brief 스레드당 코어 방식의 Do53 서버 런타임.
 *
 * @details 비동기 실행기를 쓰지 않는다. 워커마다 자기 소켓을 가지고 블로킹 시스템 호출로
 *          동작하는 구조라, 작업 훔치기도 태스크 스케줄링도 없다. DNS 질의는 짧고 균일해
 *          이 형태가 실행기 오버헤드 없이 코어를 채운다.
 * @note 리눅스에서는 SO_REUSEPORT로 워커마다 소켓을 따로 열어 커널이 질의를 워커에 분배하게 한다.
 *       다른 플랫폼은 소켓 하나를 공유한다.
 */

/** @brief 앞단 프록시가 알려 주는 원래 클라이언트 주소. */
pub mod proxy;
/** @brief 소켓과 CPU 묶기의 플랫폼별 부분. */
mod sys;
/** @brief TCP 워커. */
mod tcp;
/** @brief UDP 워커. */
mod udp;

pub use udp::encode_limited;
pub use udp::encode_within;
pub use udp::recv_batch_counters;
pub use udp::NON_EDNS_UDP_MAX;

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use onetdns_core::IpNet;

pub use onetdns_proto::Message;

/**
 * @brief 응답을 인코딩할 수 없을 때 내보낼 최소 SERVFAIL.
 * @details 전송 경계에서만 쓴다. 응답을 못 만들었다고 침묵하면 클라이언트가 타임아웃까지
 *          기다리므로, 실패를 명시적으로 알린다. 질문 섹션조차 넣지 않아 인코딩이 반드시 성공한다.
 */
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

/**
 * @brief 런타임이 보는 전송 종류.
 * @warning onetdns_core::client::Transport와 이름이 같지만 다른 타입이다. 서로
 *          재수출하지 않으며, 호출자가 경계에서 변환한다.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /** @brief 평문 UDP. */
    Do53Udp,
    /** @brief 평문 TCP. */
    Do53Tcp,
    /** @brief TLS 위. */
    DoT,
    /** @brief HTTP 위. */
    DoH,
    /** @brief HTTP/3 위. */
    DoH3,
    /** @brief QUIC 위. */
    DoQ,
    /** @brief DNSCrypt. */
    DnsCrypt,
}

impl Transport {
    /** @brief 평문 Do53인지. */
    pub fn is_plain_do53(self) -> bool {
        matches!(self, Transport::Do53Udp | Transport::Do53Tcp)
    }

    /** @brief 경로가 암호화되어 있는지. */
    pub fn is_encrypted(self) -> bool {
        !self.is_plain_do53()
    }

    /**
     * @brief 영역 전송(AXFR/IXFR)을 담을 수 있는 전송인지.
     * @details 스트림 전송만 가능하다. UDP는 응답 하나에 담기지 않고, DoH/DoQ는 질의당
     *          응답 하나를 전제하는 프레이밍이라 다중 응답을 담을 수 없다.
     */
    pub fn supports_xfr(self) -> bool {
        matches!(self, Transport::Do53Tcp | Transport::DoT)
    }

    /** @brief 로그·메트릭 레이블. */
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

/**
 * @brief 요청 하나에 딸린 전송 계층 정보.
 * @details 전송 핸들러가 자기 프로토콜에서 알아낸 것을 여기 담아 공통 파이프라인에 넘긴다.
 */
#[derive(Debug, Clone)]
pub struct RequestCtx<'a> {
    /** @brief 요청자 주소. PROXY 프로토콜을 거쳤다면 원래 클라이언트 주소로 대체돼 있다. */
    pub src: SocketAddr,
    /** @brief 이 요청이 온 전송. */
    pub transport: Transport,

    /** @brief 원본 와이어 바이트. 파싱하기 전 형태가 필요한 경로가 참조한다. */
    pub raw: Option<&'a [u8]>,

    /** @brief 클라이언트 식별자. DoH 경로 접미사 등에서 온다. */
    pub client_id: Option<String>,

    /** @brief 전송 계층에서 신원이 확인됐는지. */
    pub authenticated: bool,

    /** @brief 확인된 신원의 표시 이름. 클라이언트 인증서 주체 등이다. */
    pub auth_identity: Option<String>,
}

impl RequestCtx<'_> {
    /** @brief 인증 정보 없는 기본 문맥. */
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

/** @brief 와이어 고속 경로가 패킷을 어떻게 처리했는지. */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireDisposition {
    /** @brief 고속 경로가 처리하지 못했다. 파싱해서 일반 경로로 보낸다. */
    Fallback,

    /** @brief 출력 버퍼에 완성된 응답이 들어 있다. 그대로 보내면 된다. */
    Respond,

    /** @brief 응답하지 않는다. 속도 제한이나 정책이 침묵을 선택한 경우다. */
    Drop,
}

/** @brief 리액터 경로가 패킷을 어떻게 처리했는지. */
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReactorDisposition {
    /** @brief 완성된 응답이 출력 버퍼에 있다. */
    Respond,

    /** @brief 응답하지 않는다. */
    Drop,

    /** @brief 업스트림으로 넘겨 진행 중이다. 응답은 나중에 폴링에서 나온다. */
    Submitted,

    /** @brief 리액터가 다루지 못했다. 동기 경로로 보낸다. */
    Fallback,
}

/**
 * @brief 런타임이 요청을 위임하는 인터페이스.
 *
 * @details 기본 구현은 전부 "이 최적화를 쓰지 않는다"로 되어 있어, 구현체는 handle
 *          하나만 채워도 동작한다. 고속 경로·리액터는 선택적으로 재정의한다.
 */
pub trait Handler: Send + Sync + 'static {
    /**
     * @brief 파싱된 질의를 처리한다.
     * @return 응답. None이면 응답을 보내지 않는다.
     */
    fn handle(&self, request: &Message, ctx: &RequestCtx<'_>) -> Option<Message>;

    /**
     * @brief UDP 패킷을 파싱하지 않고 처리해 본다.
     * @details 캐시 히트를 파싱·응답 조립·이름 압축 없이 내보내는 경로다. 저장된 와이어의
     *          트랜잭션 ID·질의 이름 대소문자·TTL만 손본다.
     * @param out 응답 와이어를 쓸 버퍼.
     */
    fn handle_udp_wire(
        &self,
        _packet: &[u8],
        _ctx: &RequestCtx<'_>,
        _out: &mut onetdns_proto::Writer,
        _now: std::time::Instant,
    ) -> WireDisposition {
        WireDisposition::Fallback
    }

    /** @brief TCP 스트림에서 읽은 메시지에 대한 와이어 고속 경로. */
    fn handle_tcp_wire(
        &self,
        _packet: &[u8],
        _ctx: &RequestCtx<'_>,
        _out: &mut onetdns_proto::Writer,
        _now: std::time::Instant,
    ) -> WireDisposition {
        WireDisposition::Fallback
    }

    /** @brief 응답이 여럿일 수 있는 처리. 영역 전송이 이 경로를 쓴다. */
    fn handle_multi(&self, request: &Message, ctx: &RequestCtx<'_>) -> Option<Vec<Message>> {
        self.handle(request, ctx).map(|m| vec![m])
    }

    /**
     * @brief 파싱하지 못한 질의에 답한다.
     *
     * @details 버리면 클라이언트에게는 무응답이라 데드라인까지 기다렸다가 재시도한다. RFC 8906
     *          은 이해하지 못한 질의도 응답 코드로 답하라고 한다. 파싱 전이라 일반 경로의
     *          접근 제어와 속도 제한을 지나오지 못했으므로 구현이 그 둘을 다시 봐야 한다.
     * @param packet 파싱에 실패한 원본. 12바이트 헤더는 있고 QR은 0임이 보장된다.
     * @return 보낼 응답. 없으면 보내지 않는다.
     */
    fn handle_unparsable(&self, _packet: &[u8], _ctx: &RequestCtx<'_>) -> Option<Message> {
        None
    }

    /**
     * @brief 이 스레드가 리액터 루프를 돌아야 하는지.
     * @details 리액터를 쓰는 서버의 UDP 워커는 루프를 돌 때마다 이 값을 다시 묻고, 값이 바뀌면
     *          리액터 루프와 동기 루프를 오간다. 거짓이 되면 워커가 리액터 루프를 떠나 남은
     *          교환을 더 진행하지 않으므로, 이 스레드에 맡긴 교환이 남아 있는 동안에는 참이어야
     *          한다.
     * @note 동기 루프는 수신할 때마다 부르므로 가벼워야 한다.
     */
    #[cfg(unix)]
    fn reactor_active(&self) -> bool {
        false
    }

    /**
     * @brief 리액터 루프에서 쓰는 캐시 히트 전용 고속 경로.
     * @details 미스일 때 동기 해석으로 넘어가지 않는다는 점이 handle_udp_wire와 다르다.
     *          리액터에서는 미스가 제출(submit) 대상이기 때문이다.
     */
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

    /**
     * @brief 질의를 리액터에 제출해 비동기로 처리하게 한다.
     * @return Submitted면 응답이 이후 reactor_pump에서 나온다. 슬롯이 없으면 Fallback.
     */
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

    /**
     * @brief 진행 중인 교환의 디스크립터를 폴링 목록에 추가한다.
     * @param map 각 디스크립터를 어느 교환에 되돌릴지 나타내는 인덱스.
     */
    #[cfg(unix)]
    fn reactor_collect(&self, _fds: &mut Vec<libc::pollfd>, _map: &mut Vec<usize>) {}

    /**
     * @brief 폴링 결과를 처리해 완성된 응답을 모은다.
     * @param base fds 안에서 이 핸들러가 추가한 구간의 시작 위치.
     */
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

    /** @brief 시간에 따른 진행: 재시도와 타임아웃 처리. 폴링 결과와 무관하게 불린다. */
    #[cfg(unix)]
    fn reactor_tick(
        &self,
        _now: std::time::Instant,
        _out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) {
    }

    /**
     * @brief 다음 폴링 대기 시간(밀리초).
     * @details 가장 이른 재시도·타임아웃 시각에서 정한다. 너무 길면 그 시각을 놓치고,
     *          너무 짧으면 빈 깨어남이 잦아진다.
     */
    #[cfg(unix)]
    fn reactor_deadline_ms(&self, _now: std::time::Instant) -> i32 {
        50
    }

    /** @brief 리액터가 새 교환을 더 받을 수 있는지. 슬롯이 다 찼으면 false다. */
    #[cfg(unix)]
    fn reactor_has_capacity(&self) -> bool {
        false
    }

    /**
     * @brief 응답을 하나씩 흘려보내며 처리한다. 스트림 전송이 쓴다.
     * @param emit 응답 하나를 내보낸다. false를 돌려주면 즉시 중단한다.
     * @return 모든 응답을 내보냈으면 true.
     */
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

    /**
     * @brief 이미 인코딩된 와이어를 그대로 흘려보낸다.
     * @details 영역 전송처럼 미리 만들어 둔 바이트를 재인코딩 없이 내보내는 경로다.
     * @return 이 경로를 쓰지 않으면 None. 호출자는 일반 스트림 경로로 넘어간다.
     */
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

/** @brief 런타임 시작 설정. */
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /** @brief UDP 리스너를 열지. */
    pub udp: bool,

    /** @brief TCP 리스너를 열지. */
    pub tcp: bool,

    /** @brief UDP 워커 수. 0이면 코어 수에서 정한다. */
    pub udp_workers: usize,

    /** @brief TCP 수락 스레드 수. 0이면 코어 수에서 정한다. */
    pub tcp_acceptors: usize,

    /** @brief 워커를 코어에 고정할지. 캐시 지역성을 지키지만 스케줄러의 재배치를 막는다. */
    pub pin_cores: bool,

    /**
     * @brief 종료·재로드 신호를 확인하는 주기. 워커 응답성과 빈 깨어남의 절충이다.
     * @note 윈도우의 UDP 워커는 이 주기로 깨어나지 않는다. udp_read_timeout에 이유가 있다.
     */
    pub poll_interval: Duration,

    /** @brief UDP 리액터 경로를 쓸지. 유닉스에서만 의미가 있다. */
    pub udp_reactor: bool,

    /** @brief PROXY 프로토콜 헤더를 해석할지. */
    pub proxy_protocol: bool,

    /**
     * @brief PROXY 헤더를 신뢰할 출발지.
     * @warning 비워 두고 PROXY를 켜면 아무나 출발지 주소를 위조할 수 있어 ACL이 무력해진다.
     */
    pub trusted_proxies: Vec<IpNet>,
}

impl Default for ServerConfig {
    /** @brief 기본 설정. */
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

/**
 * @brief 실행 중인 서버. 드롭 시 워커를 멈추고 합류한다.
 */
pub struct Server {
    /** @brief 워커들에게 끝나라고 알릴 표시. */
    shutdown: Arc<AtomicBool>,
    /** @brief 실행 중인 워커들. */
    handles: Vec<JoinHandle<()>>,
    /** @brief UDP가 묶인 주소. */
    udp_addr: Option<SocketAddr>,
    /** @brief TCP가 묶인 주소. */
    tcp_addr: Option<SocketAddr>,
}

impl Server {
    /**
     * @brief 소켓을 열고 워커를 시작한다.
     *
     * @details 스레드를 하나라도 시작 전에 모든 소켓을 먼저 바인딩한다. 순서를
     *          바꾸면 일부만 성공한 상태에서 실패했을 때, 이미 뜬 워커가 포트를 잡은 채
     *          남는 유령 리스너가 생긴다.
     * @return 바인딩 실패는 오류다. 그 시점까지 연 소켓은 전부 닫힌다.
     */
    pub fn bind<H: Handler>(
        addr: SocketAddr,
        handler: Arc<H>,
        mut cfg: ServerConfig,
    ) -> io::Result<Server> {
        let udp_workers = sys::worker_count(cfg.udp_workers);
        let tcp_acceptors = sys::worker_count(cfg.tcp_acceptors);
        cfg.poll_interval = sys::poll_interval(cfg.poll_interval);
        let shutdown = Arc::new(AtomicBool::new(false));

        let udp_socks = if cfg.udp {
            Some(sys::bind_udp_workers(addr, udp_workers)?)
        } else {
            None
        };
        let tcp_listeners = if cfg.tcp {
            Some(sys::bind_tcp_workers(addr, tcp_acceptors)?)
        } else {
            None
        };

        let mut handles = Vec::with_capacity(udp_workers.saturating_add(tcp_acceptors));
        let mut udp_addr = None;
        let mut tcp_addr = None;
        if let Err(e) = Self::start_workers(
            &mut handles,
            &mut udp_addr,
            &mut tcp_addr,
            udp_socks,
            tcp_listeners,
            &handler,
            &cfg,
            &shutdown,
        ) {
            stop_workers(&shutdown, &mut handles, udp_addr);
            return Err(e);
        }

        Ok(Server {
            shutdown,
            handles,
            udp_addr,
            tcp_addr,
        })
    }

    /**
     * @brief 이미 바인딩된 소켓 위에 워커 스레드를 시작한다.
     * @details 스레드 생성이 중간에 실패하면 호출자가 종료 신호를 보내고 지금까지 뜬
     *          스레드를 합류시킨다. 실패 경로에서도 남는 스레드가 없어야 한다.
     * @note 겹침 처리를 켜면 스택을 키운다. 진행 중 요청마다 프레임이 쌓이기 때문이다.
     * @note TCP 연결 처리 스레드와 대기열 크기는 수신 소켓 수가 아니라 요청한 수락 수로
     *       정한다. 윈도우처럼 수신 소켓을 하나만 여는 플랫폼에서도 연결을 처리할 여력은
     *       줄지 않아야 한다.
     */
    #[allow(clippy::too_many_arguments)]
    fn start_workers<H: Handler>(
        handles: &mut Vec<JoinHandle<()>>,
        udp_addr: &mut Option<SocketAddr>,
        tcp_addr: &mut Option<SocketAddr>,
        udp_socks: Option<Vec<std::net::UdpSocket>>,
        tcp_listeners: Option<Vec<std::net::TcpListener>>,
        handler: &Arc<H>,
        cfg: &ServerConfig,
        shutdown: &Arc<AtomicBool>,
    ) -> io::Result<()> {
        if let Some(socks) = udp_socks {
            *udp_addr = Some(socks[0].local_addr()?);
            let batch_size = udp::worker_batch_size(socks.len());
            for (i, sock) in socks.into_iter().enumerate() {
                sock.set_read_timeout(udp_read_timeout(cfg.poll_interval))?;
                let h = handler.clone();
                let sd = shutdown.clone();
                let pin = cfg.pin_cores;
                let reactor = cfg.udp_reactor;
                let builder = std::thread::Builder::new().name(format!("onetdns-udp-{i}"));
                handles.push(builder.spawn(move || {
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
                shutdown.clone(),
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
            handles.extend(connection_handles);
            for (i, listener) in listeners.into_iter().enumerate() {
                let sd = shutdown.clone();
                let pin = cfg.pin_cores;
                let poll = cfg.poll_interval;
                let limiter = limiter.clone();
                let connections = connections.clone();
                handles.push(
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

    /** @brief 실제로 바인딩된 UDP 주소. 포트 0으로 열었을 때 확인용이다. */
    pub fn udp_addr(&self) -> Option<SocketAddr> {
        self.udp_addr
    }

    /** @brief 실제로 바인딩된 TCP 주소. */
    pub fn tcp_addr(&self) -> Option<SocketAddr> {
        self.tcp_addr
    }

    /**
     * @brief 종료를 알리고 모든 워커가 끝날 때까지 기다린다.
     * @details 합류가 필수다. 기다리지 않으면 다음 세대가 같은 포트를 열려 할 때 아직 살아
     *          있는 워커가 그 포트를 잡고 있어 바인딩이 실패한다.
     */
    fn stop(&mut self) {
        let panicked = stop_workers(&self.shutdown, &mut self.handles, self.udp_addr);
        if panicked > 0 {
            onetdns_core::error!(event = "server.worker_panicked", workers = panicked, "A query worker thread exited outside a request boundary; running with that many fewer threads meanwhile");
        }
    }

    /** @brief 서버를 소비하며 정지시킨다. */
    pub fn shutdown(mut self) {
        self.stop();
    }
}

/**
 * @brief UDP 워커의 수신 대기 한도.
 *
 * @details 윈도우에서 수신 대기가 한도에 걸려 끝나는 순간 도착한 데이터그램은 사라진다.
 *          워커 수십 개가 한 소켓을 나눠 읽으며 주기적으로 한도에 걸리면 질의가 드물게
 *          응답 없이 사라진다. 그래서 윈도우에서는 한도 없이 기다리고, 종료할 때는
 *          stop_workers가 깨우는 데이터그램을 보낸다.
 */
fn udp_read_timeout(poll: Duration) -> Option<Duration> {
    if cfg!(windows) {
        None
    } else {
        Some(poll)
    }
}

/**
 * @brief 종료를 알리고 워커가 모두 끝날 때까지 기다린다.
 * @return 요청 경계 밖에서 끝난 워커 수.
 */
fn stop_workers(
    shutdown: &AtomicBool,
    handles: &mut Vec<JoinHandle<()>>,
    udp_addr: Option<SocketAddr>,
) -> usize {
    shutdown.store(true, Ordering::SeqCst);
    if handles.is_empty() {
        return 0;
    }
    if udp_read_timeout(Duration::ZERO).is_none() {
        if let Some(addr) = udp_addr {
            wake_udp_workers(handles, addr);
        }
    }
    handles
        .drain(..)
        .map(JoinHandle::join)
        .filter(Result::is_err)
        .count()
}

/**
 * @brief 한도 없이 수신을 기다리는 UDP 워커를 깨운다.
 *
 * @details 질의가 될 수 없는 1바이트 데이터그램을 워커 소켓으로 보낸다. 받은 워커는 종료
 *          표시를 보고 끝난다. 아직 실행 중인 스레드가 있는 동안 계속 보낸다. 느린 질의를 처리하던
 *          워커는 그 질의를 마친 뒤에 깨우는 데이터그램을 받는다.
 */
fn wake_udp_workers(handles: &[JoinHandle<()>], addr: SocketAddr) {
    let target = if addr.ip().is_unspecified() {
        match addr {
            SocketAddr::V4(v4) => SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, v4.port())),
            SocketAddr::V6(v6) => SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, v6.port())),
        }
    } else {
        addr
    };
    let local: SocketAddr = if target.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let Ok(sender) = onetdns_core::udp::bind(local) else {
        onetdns_core::error!(event = "server.udp_wake_failed", %addr, "Could not open the socket used to wake UDP workers; shutdown waits until each worker receives its next query");
        return;
    };
    loop {
        let running = handles
            .iter()
            .filter(|handle| !handle.is_finished())
            .count();
        if running == 0 {
            return;
        }
        for _ in 0..running {
            let _ = sender.send_to(&[0], target);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

impl Drop for Server {
    /** @brief 드롭 시에도 반드시 정지·합류한다. 잊고 지나가도 유령 리스너가 남지 않는다. */
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
/** @brief 두 전송의 왕복, 잘림 처리, 그리고 느린 클라이언트가 남을 굶기지 않는지. */
mod tests {
    use super::*;
    use onetdns_proto::{Name, RData, Record, RecordType, ResponseCode, Writer};
    use std::collections::HashSet;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpStream, UdpSocket};
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;
    use std::time::Instant;

    /** @brief 고정 주소로 답하는 테스트용 핸들러. */
    struct EchoA {
        /** @brief 이 핸들러를 부른 스레드들. */
        threads: Mutex<HashSet<std::thread::ThreadId>>,
    }

    impl EchoA {
        /** @brief 만든다. */
        fn new() -> Arc<Self> {
            Arc::new(Self {
                threads: Mutex::new(HashSet::new()),
            })
        }
    }

    impl Handler for EchoA {
        /** @brief 고정 답을 돌려준다. */
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

    /** @brief 파싱 없이 바이트로만 답하는 테스트용 핸들러. */
    struct TcpWireOnly {
        /** @brief 느리게 답한 횟수. */
        slow_calls: AtomicUsize,
    }

    impl Handler for TcpWireOnly {
        /** @brief 보통 경로로는 답하지 않는다. */
        fn handle(&self, _request: &Message, _ctx: &RequestCtx) -> Option<Message> {
            self.slow_calls.fetch_add(1, Ordering::Relaxed);
            None
        }

        /** @brief 바이트로 곧장 답한다. */
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

    /** @brief 테스트용 설정. */
    fn test_cfg() -> ServerConfig {
        ServerConfig {
            udp_workers: 1,
            tcp_acceptors: 1,
            pin_cores: false,
            poll_interval: Duration::from_millis(100),
            ..Default::default()
        }
    }

    /** @brief 이 포트의 루프백 주소. */
    fn local(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /** @brief 테스트용 질의 바이트. */
    fn query_bytes(id: u16, name: &str) -> Vec<u8> {
        Message::query(id, Name::from_str(name).unwrap(), RecordType::A)
            .try_encode()
            .unwrap()
    }

    #[test]
    /** @brief UDP 왕복. */
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
    /** @brief 부르지 않은 응답을 조용히 버리는지. 답하면 이 서버가 반사 공격의 발판이 된다. */
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

    /** @brief 첫 질의에 패닉하는 테스트용 핸들러. */
    struct PanicOnFirstRequest {
        /** @brief 불린 횟수. */
        calls: std::sync::atomic::AtomicUsize,
    }

    impl Handler for PanicOnFirstRequest {
        /** @brief 첫 질의에 패닉한다. */
        fn handle(&self, request: &Message, ctx: &RequestCtx) -> Option<Message> {
            if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
                panic!("simulated malicious request");
            }
            EchoA::new().handle(request, ctx)
        }
    }

    #[test]
    /** @brief 질의 하나가 패닉해도 워커가 계속 도는지. */
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

    /** @brief 리액터 사용 여부를 실행 중에 바꿀 수 있는 테스트용 핸들러. */
    #[cfg(unix)]
    struct SwitchingReactor {
        /** @brief 리액터를 쓰라고 답할지. */
        active: AtomicBool,
        /** @brief 리액터 사용 여부를 물은 횟수. */
        asked: AtomicUsize,
        /** @brief 리액터에 넘어온 질의 수. */
        submitted: AtomicUsize,
        /** @brief 동기 경로로 답한 질의 수. */
        handled: AtomicUsize,
    }

    #[cfg(unix)]
    impl Handler for SwitchingReactor {
        /** @brief 답 없는 응답을 돌려준다. */
        fn handle(&self, request: &Message, _ctx: &RequestCtx) -> Option<Message> {
            self.handled.fetch_add(1, Ordering::SeqCst);
            let mut resp = Message::default();
            resp.header.id = request.header.id;
            resp.header.response = true;
            resp.questions = request.questions.clone();
            Some(resp)
        }

        /** @brief 정해 둔 값을 돌려주고 물은 횟수를 센다. */
        fn reactor_active(&self) -> bool {
            self.asked.fetch_add(1, Ordering::SeqCst);
            self.active.load(Ordering::SeqCst)
        }

        /** @brief 늘 더 받는다. */
        fn reactor_has_capacity(&self) -> bool {
            true
        }

        /** @brief 질의에 응답 비트만 세워 돌려준다. */
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
    /**
     * @brief UDP 워커가 실행 중에 바뀐 리액터 사용 여부를 따라가는지.
     * @details 리액터 사용 여부는 설정을 교체할 때 바뀐다. 스레드를 띄울 때 한 번만 보면 나중에
     *          켠 리액터로는 질의가 가지 않는다. 동기 루프로 돌아갈 때 소켓을 블로킹으로 되돌리지
     *          않으면 수신이 기다리지 않고 헛돈다.
     */
    fn udp_worker_follows_the_reactor_switch_at_runtime() {
        let handler = Arc::new(SwitchingReactor {
            active: AtomicBool::new(false),
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
        /* 루프를 바꾼 워커는 다음 질의부터 받으므로 조건이 설 때까지 질의를 계속 보낸다. */
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

        /* 수신 대기 한도가 100밀리초라 쉬는 동안에는 몇 번만 묻는다. 헛돌면 수만 번을 묻는다. */
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
    /** @brief TCP 왕복. */
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
    /** @brief 바이트 경로가 파싱을 건너뛰는지. */
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
    /** @brief 부르지 않은 응답에 연결을 끊는지. */
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
    /** @brief 느린 클라이언트들이 멀쩡한 클라이언트를 굶기지 못하는지. */
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

    /** @brief 큰 답을 내는 테스트용 핸들러. */
    struct LargeResponder;
    impl Handler for LargeResponder {
        /** @brief 큰 답을 돌려준다. */
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
    /** @brief 잘렸을 때 TCP로 다시 물어 온전한 답을 받는지. */
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

    /** @brief 응답 여럿을 내는 테스트용 핸들러. */
    struct TripleResponder;
    impl Handler for TripleResponder {
        /** @brief 하나만 돌려준다. */
        fn handle(&self, request: &Message, _ctx: &RequestCtx) -> Option<Message> {
            let mut m = Message::default();
            m.header.id = request.header.id;
            m.header.response = true;
            Some(m)
        }
        /** @brief 여럿을 돌려준다. */
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
    /** @brief 응답 여럿이 한 연결로 나가는지. */
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
    /** @brief 동시에 몰려도 모두 답을 받는지. */
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
    /** @brief 사라질 때 워커가 멈추고 포트가 풀리는지. 안 풀리면 재시작하지 못한다. */
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
    /**
     * @brief 모든 주소에 묶인 UDP 워커 여러 개가 멈추고 포트를 푸는지.
     * @details 윈도우의 UDP 워커는 한도 없이 기다리므로 종료할 때 루프백으로 깨워야 한다.
     *          깨우는 주소를 잘못 고르면 합류가 끝나지 않는다.
     */
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
    /** @brief 워커 수를 정하는 규칙. */
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
    /** @brief 기다리는 간격에 상한이 있는지. */
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
    /** @brief 여러 응답을 보낼 수 있는 전송만 영역 전송을 내세우는지. */
    fn only_multi_message_stream_transports_advertise_zone_transfer() {
        assert!(Transport::Do53Tcp.supports_xfr());
        assert!(Transport::DoT.supports_xfr());
        assert!(!Transport::DoQ.supports_xfr());
        assert!(!Transport::DoH.supports_xfr());
        assert!(!Transport::DoH3.supports_xfr());
    }
}
