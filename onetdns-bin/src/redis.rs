/*!
 * @brief 외부 공유 캐시 클라이언트.
 *
 * @details 여러 대가 캐시를 나눠 쓸 때 쓴다. 프로토콜은 이 서버가 쓰는 명령만 구현한다.
 *          연결은 여러 개를 두고 명령마다 하나를 빌려 쓴다. 잠금은 연결을 꺼내고 돌려놓을
 *          때와 회로 상태를 읽고 바꿀 때만 잡고, 접속과 왕복은 잠금 밖에서 한다.
 * @warning 이 캐시가 느리거나 죽어도 질의 처리가 멈추면 안 된다. 질의는 읽기 하나만 기다리고
 *          담기와 지우기는 워커에 맡긴다. 명령마다 데드라인이 짧고, 답이 느리면 실패로 보며,
 *          빌릴 연결이 없으면 기다리지 않고 건너뛰고, 실패하면 잠시 아예 건너뛴다.
 */

use std::io::{BufReader, Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use onetdns_core::tcp::DeadlineTcp;
use onetdns_core::{MutexExt, SecretString};
use onetdns_tls::{client_handshake, ClientConfig, TlsStream, TrustStore};
use zeroize::Zeroizing;

/** @brief 응답 한 줄의 길이 상한. */
const MAX_RESP_LINE: usize = 4 * 1024;
/**
 * @brief 값 하나의 크기 상한.
 * @details 이 서버가 담는 값은 DNS 메시지 하나와 그 봉투라 64KiB를 조금 넘을 뿐이다. 연결마다
 *          이만큼을 한 번에 잡으므로, 상한에 연결 수를 곱한 값이 응답 값을 담는 데 쓰는 메모리의
 *          최댓값이다.
 */
const MAX_BULK_REPLY: usize = 128 * 1024;
/**
 * @brief 명령 하나의 데드라인.
 * @details 접속, TLS, 인증, 쉬던 연결이 끊겨 새 연결로 다시 보내는 것까지 이 안에 끝내야 한다.
 */
const COMMAND_TIMEOUT: Duration = Duration::from_secs(1);
/**
 * @brief 맺어 둔 연결에서 명령을 보내고 답을 받기까지의 상한.
 * @details 넘기면 실패로 보고 회로를 연다. 답은 하지만 느린 캐시를 실패로 보지 않으면 회로가
 *          열리지 않아 질의마다 그만큼 기다린다. 공유 캐시는 업스트림에 다시 묻는 것보다 빨라야
 *          쓸모가 있으므로, 여러 번 오가야 하는 접속보다 훨씬 짧게 잡는다.
 */
const ROUNDTRIP_TIMEOUT: Duration = Duration::from_millis(100);
/** @brief 실패 뒤 건너뛸 기간. 죽은 캐시에 매 질의마다 접속을 시도하면 그것이 더 느리다. */
const FAILURE_COOLDOWN: Duration = Duration::from_secs(5);
/**
 * @brief 이 서버가 공유 캐시에 열어 두는 연결 수의 상한.
 * @details 연결이 모두 쓰이는 중이면 다음 명령은 기다리지 않고 건너뛴다. 기다리게 하면
 *          공유 캐시의 지연이 그대로 질의 처리의 지연이 된다. 상한은 서버마다 공유 캐시에
 *          여는 소켓 수를 묶는다.
 */
const MAX_CONNECTIONS: usize = 64;
/**
 * @brief 담기와 지우기를 보내는 워커 수.
 * @details 쓰기는 이만큼의 연결만 차지하므로, 나머지 연결은 질의가 기다리는 읽기에 남는다.
 */
const WRITE_WORKERS: usize = 8;
/**
 * @brief 쓰기 대기열 크기.
 * @details 워커가 모두 바쁠 때 몰린 쓰기를 받아 두고, 넘치면 버린다. 쓰기마다 응답 하나를 들고
 *          있으므로 상한이 없으면 공유 캐시가 밀릴 때 메모리가 끝없이 는다.
 */
const WRITE_QUEUE: usize = 64;
/** @brief 공유 캐시에 맡긴 쓰기 하나. */
type WriteJob = Box<dyn FnOnce() + Send + 'static>;
/** @brief 쓰기 워커 풀. 모든 클라이언트가 함께 쓴다. */
static WRITE_EXECUTOR: OnceLock<mpsc::SyncSender<WriteJob>> = OnceLock::new();

/** @brief 쓰기 워커 풀. 처음 쓸 때 시작한다. */
fn write_executor() -> &'static mpsc::SyncSender<WriteJob> {
    WRITE_EXECUTOR.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<WriteJob>(WRITE_QUEUE);
        let rx = Arc::new(Mutex::new(rx));
        for index in 0..WRITE_WORKERS {
            let rx = rx.clone();
            if let Err(error) = std::thread::Builder::new()
                .name(format!("onetdns-cachedb-write-{index}"))
                .spawn(move || loop {
                    let job = rx.lock_recover().recv();
                    match job {
                        Ok(job) => job(),
                        Err(_) => break,
                    }
                })
            {
                onetdns_core::warn!(event = "cachedb.write_worker_start_failed", %error, index, "Could not start a shared cache write thread; answers this server resolves may not reach the shared cache");
                break;
            }
        }
        tx
    })
}

/** @brief 공유 캐시와 맺은 연결 하나. */
enum Connection {
    /**
     * @brief 평문 TCP.
     * @details 응답의 줄은 한 바이트씩 읽으므로, 받은 바이트를 버퍼에 모아 두지 않으면 한 바이트마다
     *          소켓을 읽는다. TLS 연결은 복호화한 레코드를 버퍼에 두고 읽으므로 따로 두지 않는다.
     */
    Plain(BufReader<DeadlineTcp>),
    /** @brief TLS. */
    Tls(Box<TlsStream<DeadlineTcp>>),
}

impl Connection {
    /** @brief 이번 명령의 데드라인을 건다. */
    fn set_deadline(&mut self, deadline: Instant) {
        match self {
            Connection::Plain(tcp) => tcp.get_mut().set_deadline(deadline),
            Connection::Tls(tls) => tls.inner_mut().set_deadline(deadline),
        }
    }
}

impl Read for Connection {
    /** @brief 읽는다. */
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Connection::Plain(tcp) => tcp.read(buf),
            Connection::Tls(tls) => tls.read(buf),
        }
    }
}

impl Write for Connection {
    /** @brief 쓴다. */
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Connection::Plain(tcp) => tcp.get_mut().write(buf),
            Connection::Tls(tls) => tls.write(buf),
        }
    }

    /** @brief 비운다. */
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Connection::Plain(tcp) => tcp.get_mut().flush(),
            Connection::Tls(tls) => tls.flush(),
        }
    }
}

/** @brief 공유 캐시에 TLS로 붙을 때 확인할 것. */
pub struct RedisTls {
    /** @brief 인증서에 있어야 할 이름. 설정에 적은 Redis 호스트다. */
    pub server_name: String,
    /** @brief 인증서를 검증할 신뢰 저장소. */
    pub roots: TrustStore,
}

/** @brief 접속한 뒤 AUTH 명령으로 보낼 자격 증명. */
pub struct RedisAuth {
    /** @brief ACL 사용자 이름. 없으면 기본 사용자로 인증한다. */
    pub username: Option<String>,
    /** @brief 비밀번호. */
    pub password: SecretString,
}

/** @brief 공유 캐시에 붙는 방법. */
pub struct RedisOptions {
    /** @brief 붙을 주소. */
    pub addr: SocketAddr,
    /** @brief TLS 설정. 없으면 평문으로 붙는다. */
    pub tls: Option<RedisTls>,
    /** @brief 자격 증명. 없으면 인증하지 않는다. */
    pub auth: Option<RedisAuth>,
}

/**
 * @brief 공유 캐시로 명령을 보낼지 정하는 상태.
 * @details 실패하면 열리고, 쉬는 시간이 지나면 명령 하나만 보내 본다. 그 명령이 성공해야
 *          다시 닫힌다. 쉬는 시간이 지났을 때 모든 질의가 한꺼번에 접속을 시도하면 죽은
 *          캐시의 접속 대기 시간을 모든 질의가 함께 치른다.
 */
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Circuit {
    /** @brief 명령을 보낸다. */
    Closed,
    /** @brief 이 시각까지 건너뛴다. */
    Open(Instant),
    /** @brief 명령 하나가 다시 붙어 보는 중이다. 나머지는 건너뛴다. */
    Probing,
}

/** @brief 명령 하나가 받은 허가. */
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Admission {
    /** @brief 회로가 닫혀 있을 때 보낸 명령. */
    Normal,
    /** @brief 회로를 닫을지 정하는 명령. */
    Probe,
}

/** @brief 명령을 보내지 못한 까닭. */
enum Exchange {
    /** @brief 연결이 모두 쓰이는 중이라 보내지 않았다. 공유 캐시의 실패가 아니다. */
    Busy,
    /** @brief 보냈지만 실패했다. */
    Failed(std::io::Error),
}

/** @brief 연결 수 상한 안에서 잡은 자리 하나. 버리면 자리를 돌려준다. */
struct Slot(Arc<AtomicUsize>);

impl Slot {
    /** @brief 상한에 닿지 않았으면 자리를 잡는다. */
    fn acquire(open: &Arc<AtomicUsize>) -> Option<Slot> {
        open.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count < MAX_CONNECTIONS).then_some(count + 1)
        })
        .ok()?;
        Some(Slot(open.clone()))
    }
}

impl Drop for Slot {
    /** @brief 자리를 돌려준다. */
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/** @brief 연결과 그 연결이 차지한 자리. 함께 버려야 셈이 맞는다. */
struct Pooled {
    /** @brief 연결. */
    connection: Connection,
    /** @brief 차지한 자리. */
    _slot: Slot,
}

/** @brief 공유 캐시 클라이언트. */
pub struct RedisClient {
    /** @brief 붙을 주소. */
    addr: SocketAddr,
    /**
     * @brief TLS 핸드셰이크 설정. 없으면 평문으로 붙는다.
     * @note 한 번 만들어 두고 연결마다 빌려 쓴다. 신뢰 저장소를 연결마다 복제하거나 다시
     *       읽지 않기 위해서다.
     */
    tls: Option<ClientConfig>,
    /** @brief 자격 증명. 없으면 인증하지 않는다. */
    auth: Option<RedisAuth>,
    /** @brief 쉬고 있는 연결. */
    idle: Mutex<Vec<Pooled>>,
    /** @brief 열린 연결 수. 쉬는 것과 빌려 간 것을 모두 센다. */
    open: Arc<AtomicUsize>,
    /** @brief 명령을 보낼지 정하는 상태. */
    circuit: Mutex<Circuit>,
    /** @brief 서버가 오류로 답한 누적 횟수. 2의 거듭제곱 번째만 기록한다. */
    rejected: AtomicU64,
    /** @brief 대기열이 꽉 차 버린 쓰기의 누적 수. 2의 거듭제곱 번째만 기록한다. */
    dropped_writes: AtomicU64,
    #[cfg(test)]
    /** @brief 맡겨 두고 아직 끝나지 않은 쓰기 수. 테스트가 쓰기가 끝나기를 기다릴 때 본다. */
    pending_writes: AtomicUsize,
}

/**
 * @brief 명령 하나의 결과를 회로에 반영한다.
 * @warning 다시 붙어 보는 명령이 결과를 남기지 않고 사라지면 회로가 그 상태에 머물러 공유
 *          캐시를 영영 쓰지 않는다. 결과를 남기지 않고 버려지면 실패로 반영한다.
 */
struct Outcome<'a> {
    /** @brief 반영할 클라이언트. */
    client: &'a RedisClient,
    /** @brief 이 명령이 받은 허가. */
    admission: Admission,
    /** @brief 결과를 반영했는지. */
    settled: bool,
}

impl Outcome<'_> {
    /** @brief 성공을 반영한다. */
    fn succeeded(mut self) {
        self.settled = true;
        self.client.on_success(self.admission);
    }

    /** @brief 연결이 없어 보내지 못했음을 반영한다. */
    fn skipped(mut self) {
        self.settled = true;
        self.client.on_skip(self.admission);
    }

    /** @brief 실패를 반영한다. */
    fn failed(mut self, error: &std::io::Error) {
        self.settled = true;
        self.client.on_failure(self.admission, error);
    }
}

impl Drop for Outcome<'_> {
    /** @brief 반영하지 않은 결과를 실패로 반영한다. */
    fn drop(&mut self) {
        if !self.settled {
            self.client.on_failure(
                self.admission,
                &std::io::Error::other("The shared cache command did not finish"),
            );
        }
    }
}

impl RedisClient {
    /** @brief 붙는 방법으로 만든다. 접속은 처음 쓸 때 한다. */
    pub fn new(options: RedisOptions) -> Self {
        let RedisOptions { addr, tls, auth } = options;
        let tls = tls.map(|tls| ClientConfig {
            server_name: tls.server_name,
            verify_name: true,
            roots: Some(tls.roots),
            insecure_verifier: None,
            alpn: Vec::new(),
            client_cert: None,
            session: None,
            enable_early_data: false,
            send_key_share: true,
        });
        RedisClient {
            addr,
            tls,
            auth,
            idle: Mutex::new(Vec::new()),
            open: Arc::new(AtomicUsize::new(0)),
            circuit: Mutex::new(Circuit::Closed),
            rejected: AtomicU64::new(0),
            dropped_writes: AtomicU64::new(0),
            #[cfg(test)]
            pending_writes: AtomicUsize::new(0),
        }
    }

    /** @brief 붙을 주소. */
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /** @brief 이 명령을 보내도 되는지 정한다. 보내지 않으면 없음. */
    fn admit(&self) -> Option<Admission> {
        let mut circuit = self.circuit.lock_recover();
        match *circuit {
            Circuit::Closed => Some(Admission::Normal),
            Circuit::Open(until) if Instant::now() < until => None,
            Circuit::Open(_) => {
                *circuit = Circuit::Probing;
                Some(Admission::Probe)
            }
            Circuit::Probing => None,
        }
    }

    /** @brief 성공한 명령을 반영한다. 다시 붙어 본 명령이 성공했을 때만 회로를 닫는다. */
    fn on_success(&self, admission: Admission) {
        if admission != Admission::Probe {
            return;
        }
        *self.circuit.lock_recover() = Circuit::Closed;
        onetdns_core::info!(event = "cachedb.recovered", addr = %self.addr, "Shared cache is answering again; resumed using it");
    }

    /** @brief 보내지 못한 명령을 반영한다. 다시 붙어 보지 못했으면 다음 명령이 해 보게 한다. */
    fn on_skip(&self, admission: Admission) {
        if admission == Admission::Probe {
            *self.circuit.lock_recover() = Circuit::Open(Instant::now());
        }
    }

    /**
     * @brief 실패한 명령을 반영한다.
     * @details 회로가 닫혀 있을 때 실패한 명령만 회로를 연다. 이미 열린 뒤에 끝난 명령은 그 전에
     *          보낸 것이므로 다시 붙어 보는 일을 막지 않는다. 열 때 쉬는 연결도 버린다. 캐시가
     *          다시 뜨면 그 연결은 이미 끊겨 있다.
     */
    fn on_failure(&self, admission: Admission, error: &std::io::Error) {
        let opened = {
            let mut circuit = self.circuit.lock_recover();
            let opened = match (admission, *circuit) {
                (Admission::Probe, _) => false,
                (Admission::Normal, Circuit::Closed) => true,
                (Admission::Normal, _) => return,
            };
            *circuit = Circuit::Open(Instant::now() + FAILURE_COOLDOWN);
            opened
        };
        drop(std::mem::take(&mut *self.idle.lock_recover()));
        if opened {
            self.note_unavailable(error);
        }
    }

    /**
     * @brief 공유 캐시를 쓰지 못하게 됐음을 기록한다.
     * @details 회로가 열릴 때만 남긴다. 이 기록이 없으면 공유 캐시가 전부 죽어도 질의는 그대로
     *          처리돼 운영자가 알아챌 길이 없다.
     */
    fn note_unavailable(&self, error: &std::io::Error) {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            onetdns_core::warn!(event = "cachedb.credentials_rejected", addr = %self.addr, error = %error, cooldown_secs = FAILURE_COOLDOWN.as_secs(), "Shared cache rejected the configured user name or password; skipping it for now. Queries are still answered but the cache is not shared");
        } else {
            onetdns_core::warn!(event = "cachedb.unavailable", addr = %self.addr, error = %error, cooldown_secs = FAILURE_COOLDOWN.as_secs(), "Cannot reach the shared cache; skipping it for now. Queries are still answered but the cache is not shared");
        }
    }

    /** @brief 접속하고, TLS와 인증까지 마친다. */
    fn connect(&self, deadline: Instant) -> std::io::Result<Connection> {
        let mut tcp = DeadlineTcp::connect(self.addr, deadline)?;
        /* 명령은 작은 쓰기 하나 뒤에 응답을 기다리므로, Nagle 지연이 그대로 질의 지연이 된다. */
        let _ = tcp.get_ref().set_nodelay(true);
        let mut connection = match &self.tls {
            None => Connection::Plain(BufReader::new(tcp)),
            Some(config) => {
                let session = client_handshake(&mut tcp, config).map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("TLS handshake with the shared cache failed: {error}"),
                    )
                })?;
                Connection::Tls(Box::new(TlsStream::new(session, tcp)))
            }
        };
        if let Some(auth) = &self.auth {
            authenticate(&mut connection, auth)?;
        }
        Ok(connection)
    }

    /**
     * @brief 연결 하나를 빌린다.
     * @param fresh  참이면 쉬는 연결을 쓰지 않고 새로 붙는다.
     * @return 연결과, 그것이 쉬던 연결이었는지.
     */
    fn checkout(&self, deadline: Instant, fresh: bool) -> Result<(Pooled, bool), Exchange> {
        if !fresh {
            if let Some(pooled) = self.idle.lock_recover().pop() {
                return Ok((pooled, true));
            }
        }
        let slot = Slot::acquire(&self.open).ok_or(Exchange::Busy)?;
        let connection = self.connect(deadline).map_err(Exchange::Failed)?;
        Ok((
            Pooled {
                connection,
                _slot: slot,
            },
            false,
        ))
    }

    /**
     * @brief 연결을 빌려 명령 하나를 주고받는다.
     * @details 쉬던 연결이 실패하면 새 연결로 한 번 더 보낸다. 캐시가 다시 떴거나 쉬는 동안
     *          상대가 연결을 닫았으면 쉬던 연결은 이미 끊겨 있다. 세 명령 모두 다시 보내도
     *          결과가 같다.
     * @warning 실패한 연결은 돌려놓지 않는다. 어긋난 연결을 다시 쓰면 다음 명령의 답으로 앞
     *          명령의 답을 읽는다.
     */
    fn exchange(&self, args: &[&[u8]]) -> Result<RespValue, Exchange> {
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        let (mut pooled, reused) = self.checkout(deadline, false)?;
        match roundtrip(&mut pooled.connection, args, deadline) {
            Ok(value) => {
                self.idle.lock_recover().push(pooled);
                return Ok(value);
            }
            Err(error) if !reused => return Err(Exchange::Failed(error)),
            Err(_) => drop(pooled),
        }
        let (mut pooled, _) = self.checkout(deadline, true)?;
        let value = roundtrip(&mut pooled.connection, args, deadline).map_err(Exchange::Failed)?;
        self.idle.lock_recover().push(pooled);
        Ok(value)
    }

    /** @brief 명령 하나를 보내고 답을 받는다. 보내지 않았거나 실패하면 없음. */
    fn command(&self, args: &[&[u8]]) -> Option<RespValue> {
        let outcome = Outcome {
            client: self,
            admission: self.admit()?,
            settled: false,
        };
        match self.exchange(args) {
            Ok(value) => {
                outcome.succeeded();
                Some(value)
            }
            Err(Exchange::Busy) => {
                outcome.skipped();
                None
            }
            Err(Exchange::Failed(error)) => {
                outcome.failed(&error);
                None
            }
        }
    }

    /**
     * @brief 서버가 오류로 답했으면 기록한다.
     * @details 접속과 왕복은 성공했으므로 회로가 열리지 않는다. 메모리 부족처럼 공유 캐시가
     *          계속 아무 일도 하지 않는 상태가 여기서만 드러난다.
     */
    fn note_reply(&self, command: &str, value: &RespValue) {
        let RespValue::Error(message) = value else {
            return;
        };
        let count = self.rejected.fetch_add(1, Ordering::Relaxed) + 1;
        if count.is_power_of_two() {
            onetdns_core::warn!(event = "cachedb.command_rejected", addr = %self.addr, command = command, count = count, reply = %message, "Shared cache server rejected a command; the cache is not being shared");
        }
    }

    /** @brief 값을 읽는다. 실패하면 없는 것으로 본다. */
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let value = self.command(&[b"GET", key])?;
        self.note_reply("GET", &value);
        match value {
            RespValue::Bulk(b) => Some(b),
            _ => None,
        }
    }

    /** @brief 만료 시간과 함께 값을 넣도록 맡긴다. 답을 기다리지 않고, 실패는 무시한다. */
    pub fn setex(self: &Arc<Self>, key: Vec<u8>, secs: u64, value: Vec<u8>) {
        let secs = secs.max(1).to_string().into_bytes();
        self.write_later("SETEX", vec![b"SETEX".to_vec(), key, secs, value]);
    }

    /** @brief 값을 지우도록 맡긴다. 답을 기다리지 않고, 실패는 무시한다. */
    pub fn del(self: &Arc<Self>, key: Vec<u8>) {
        self.write_later("DEL", vec![b"DEL".to_vec(), key]);
    }

    /**
     * @brief 쓰기 명령을 워커에 맡긴다.
     * @details 질의의 답은 담기와 지우기의 결과에 기대지 않으므로 질의가 그 왕복을 기다릴 까닭이
     *          없다. 대기열이 꽉 차면 버린다.
     * @warning 맡긴 쓰기는 여러 워커가 나눠 보내므로 맡긴 순서대로 끝나지 않는다. 한 질의는 한
     *          키에 쓰기를 하나만 맡겨야 한다. 지우기와 담기를 함께 맡기면 새로 담은 값이 지워질
     *          수 있다.
     */
    fn write_later(self: &Arc<Self>, name: &'static str, args: Vec<Vec<u8>>) {
        #[cfg(test)]
        self.pending_writes.fetch_add(1, Ordering::AcqRel);
        let client = Arc::clone(self);
        let job: WriteJob = Box::new(move || {
            let args: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();
            if let Some(value) = client.command(&args) {
                client.note_reply(name, &value);
            }
            #[cfg(test)]
            client.pending_writes.fetch_sub(1, Ordering::AcqRel);
        });
        if write_executor().try_send(job).is_err() {
            #[cfg(test)]
            self.pending_writes.fetch_sub(1, Ordering::AcqRel);
            self.note_write_dropped();
        }
    }

    /**
     * @brief 대기열이 꽉 차 쓰기를 버렸음을 기록한다.
     * @details 공유 캐시가 받아 주는 속도보다 쓰기가 빨리 쌓인다는 뜻이다. 답은 그대로 나가지만
     *          다른 서버와 나누지 못한다.
     */
    fn note_write_dropped(&self) {
        let count = self.dropped_writes.fetch_add(1, Ordering::Relaxed) + 1;
        if count.is_power_of_two() {
            onetdns_core::warn!(event = "cachedb.write_dropped", addr = %self.addr, count = count, "Shared cache write queue is full, so an answer was not shared; the shared cache accepts writes more slowly than this server produces them");
        }
    }

    #[cfg(test)]
    /** @brief 맡긴 쓰기가 모두 끝나기를 기다린다. */
    pub(crate) fn wait_for_writes(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.pending_writes.load(Ordering::Acquire) > 0 {
            assert!(
                Instant::now() < deadline,
                "shared cache writes did not finish"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/**
 * @brief 새 연결에서 AUTH 명령으로 인증한다.
 * @return 서버가 오류로 답하면 PermissionDenied 종류의 실패.
 */
fn authenticate(connection: &mut Connection, auth: &RedisAuth) -> std::io::Result<()> {
    let password = auth.password.as_bytes();
    let reply = match &auth.username {
        Some(username) => write_and_read(connection, &[b"AUTH", username.as_bytes(), password]),
        None => write_and_read(connection, &[b"AUTH", password]),
    }?;
    match reply {
        RespValue::Simple(_) => Ok(()),
        RespValue::Error(message) => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("The shared cache rejected the credentials: {message}"),
        )),
        _ => Err(std::io::ErrorKind::InvalidData.into()),
    }
}

/** @brief 응답 값 하나. */
enum RespValue {
    /** @brief 짧은 문자열 응답. */
    Simple(#[allow(dead_code)] String),
    /** @brief 길이가 붙은 값. */
    Bulk(Vec<u8>),
    /** @brief 값이 없다. */
    Nil,
    /** @brief 수. */
    Int(#[allow(dead_code)] i64),
    /** @brief 오류. */
    Error(String),
}

/**
 * @brief 데드라인을 걸고 명령을 보내 답을 읽는다.
 * @param deadline 명령 전체의 데드라인. 왕복은 이보다 먼저 ROUNDTRIP_TIMEOUT 에 끊긴다.
 */
fn roundtrip(
    connection: &mut Connection,
    args: &[&[u8]],
    deadline: Instant,
) -> std::io::Result<RespValue> {
    connection.set_deadline(deadline.min(Instant::now() + ROUNDTRIP_TIMEOUT));
    write_and_read(connection, args)
}

/**
 * @brief 명령을 보내고 답을 읽는다.
 * @note 요청 버퍼를 쓰고 나서 지운다. AUTH 명령에는 비밀번호가 들어 있다. 버퍼가 자라며 다시
 *       잡히면 지우지 않은 이전 버퍼가 남으므로, 처음부터 전체 길이만큼 잡는다.
 */
fn write_and_read<S: Read + Write>(stream: &mut S, args: &[&[u8]]) -> std::io::Result<RespValue> {
    let capacity = 32 + args.iter().map(|a| a.len() + 32).sum::<usize>();
    let mut req = Zeroizing::new(Vec::with_capacity(capacity));
    req.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
    for a in args {
        req.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        req.extend_from_slice(a);
        req.extend_from_slice(b"\r\n");
    }
    stream.write_all(&req)?;
    stream.flush()?;
    read_reply(stream)
}

/** @brief 한 줄을 읽는다. 길이 상한이 걸린다. */
fn read_line<R: Read>(stream: &mut R) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    loop {
        if stream.read(&mut b)? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        if b[0] == b'\r' {
            stream.read_exact(&mut b)?;
            if b[0] != b'\n' {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            break;
        }
        out.push(b[0]);
        if out.len() > MAX_RESP_LINE {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
    }
    Ok(out)
}

/**
 * @brief 응답 하나를 읽는다.
 * @warning 배열 응답을 끝까지 소비해야 한다. 중간에 멈추면 남은 바이트가 다음 명령의
 *          답으로 읽혀 연결이 어긋난다.
 */
fn read_reply<R: Read>(stream: &mut R) -> std::io::Result<RespValue> {
    let line = read_line(stream)?;
    if line.is_empty() {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let rest = &line[1..];
    match line[0] {
        b'+' => Ok(RespValue::Simple(
            String::from_utf8_lossy(rest).into_owned(),
        )),
        b'-' => Ok(RespValue::Error(String::from_utf8_lossy(rest).into_owned())),
        b':' => Ok(RespValue::Int(parse_i64(rest)?)),
        b'$' => {
            let len = parse_i64(rest)?;
            if len == -1 {
                return Ok(RespValue::Nil);
            }
            if len < 0 {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            let len = usize::try_from(len).map_err(|_| std::io::ErrorKind::InvalidData)?;
            if len > MAX_BULK_REPLY {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf)?;
            let mut crlf = [0u8; 2];
            stream.read_exact(&mut crlf)?;
            if crlf != *b"\r\n" {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            Ok(RespValue::Bulk(buf))
        }
        b'*' => {
            let count = parse_i64(rest)?;
            if count == -1 {
                Ok(RespValue::Nil)
            } else {
                Err(std::io::ErrorKind::InvalidData.into())
            }
        }
        _ => Err(std::io::ErrorKind::InvalidData.into()),
    }
}

/** @brief 수를 읽는다. 형식이 어긋나면 오류다. */
fn parse_i64(b: &[u8]) -> std::io::Result<i64> {
    std::str::from_utf8(b)
        .map_err(|_| std::io::ErrorKind::InvalidData)?
        .parse()
        .map_err(|_| std::io::ErrorKind::InvalidData.into())
}

#[cfg(test)]
/** @brief 테스트가 띄우는 가짜 Redis. GET, SETEX, DEL, AUTH 만 처리한다. */
pub(crate) mod fake {
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use onetdns_core::MutexExt;

    /** @brief 가짜 Redis 가 답하는 방식. */
    #[derive(Clone, Default)]
    pub(crate) struct Behavior {
        /** @brief 명령마다 답하기 전에 기다릴 시간. */
        pub(crate) delay: Duration,
        /** @brief AUTH 로 받아야 할 사용자 이름과 비밀번호. 없으면 인증 없이 받는다. */
        pub(crate) credentials: Option<(Option<String>, String)>,
        /** @brief TLS 로 받을 때 쓸 서버 설정. */
        pub(crate) tls: Option<Arc<onetdns_tls::ServerConfig>>,
        /** @brief 참이면 답 하나를 보낸 뒤 연결을 닫는다. */
        pub(crate) close_after_reply: bool,
        /** @brief 있으면 이것이 참이 될 때까지 데이터 명령에 답하지 않는다. */
        pub(crate) hold: Option<Arc<AtomicBool>>,
    }

    /** @brief 띄운 가짜 Redis. 버리면 새 연결을 받지 않는다. */
    pub(crate) struct FakeRedis {
        /** @brief 받는 주소. */
        pub(crate) addr: SocketAddr,
        /** @brief 담긴 값. 테스트가 직접 넣고 꺼낸다. */
        pub(crate) store: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
        /** @brief 받은 연결 수. */
        pub(crate) connections: Arc<AtomicUsize>,
        /** @brief 처리한 데이터 명령 수. AUTH 는 세지 않는다. */
        pub(crate) commands: Arc<AtomicUsize>,
        /** @brief 멈출지. */
        stop: Arc<AtomicBool>,
    }

    impl FakeRedis {
        /** @brief 정한 방식으로 띄운다. */
        pub(crate) fn start(behavior: Behavior) -> FakeRedis {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let store = Arc::new(Mutex::new(HashMap::new()));
            let connections = Arc::new(AtomicUsize::new(0));
            let commands = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            {
                let store = store.clone();
                let connections = connections.clone();
                let commands = commands.clone();
                let stop = stop.clone();
                std::thread::spawn(move || {
                    for stream in listener.incoming() {
                        if stop.load(Ordering::Acquire) {
                            break;
                        }
                        let Ok(stream) = stream else {
                            continue;
                        };
                        connections.fetch_add(1, Ordering::AcqRel);
                        let store = store.clone();
                        let commands = commands.clone();
                        let behavior = behavior.clone();
                        std::thread::spawn(move || serve(stream, &store, &commands, &behavior));
                    }
                });
            }
            FakeRedis {
                addr,
                store,
                connections,
                commands,
                stop,
            }
        }

        /** @brief 담긴 값 하나. */
        pub(crate) fn value(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.store.lock_recover().get(key).cloned()
        }

        /** @brief 담긴 키 전부. */
        pub(crate) fn keys(&self) -> Vec<Vec<u8>> {
            self.store.lock_recover().keys().cloned().collect()
        }

        /** @brief 값을 직접 넣는다. Redis 에 쓸 수 있는 남이 하는 일이다. */
        pub(crate) fn insert(&self, key: Vec<u8>, value: Vec<u8>) {
            self.store.lock_recover().insert(key, value);
        }
    }

    impl Drop for FakeRedis {
        /** @brief 받기를 멈춘다. 막혀 있는 accept 를 깨우려고 한 번 붙는다. */
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            let _ = TcpStream::connect(self.addr);
        }
    }

    /** @brief 연결 하나를 처리한다. */
    fn serve(
        mut stream: TcpStream,
        store: &Mutex<HashMap<Vec<u8>, Vec<u8>>>,
        commands: &AtomicUsize,
        behavior: &Behavior,
    ) {
        match &behavior.tls {
            None => handle(&mut stream, store, commands, behavior),
            Some(config) => {
                let Ok(session) = onetdns_tls::server_handshake(&mut stream, config) else {
                    return;
                };
                let mut tls = onetdns_tls::TlsStream::new(session, stream);
                handle(&mut tls, store, commands, behavior);
            }
        }
    }

    /** @brief 명령을 읽고 답한다. */
    fn handle<S: Read + Write>(
        stream: &mut S,
        store: &Mutex<HashMap<Vec<u8>, Vec<u8>>>,
        commands: &AtomicUsize,
        behavior: &Behavior,
    ) {
        let mut authenticated = behavior.credentials.is_none();
        while let Some(args) = read_command(stream) {
            std::thread::sleep(behavior.delay);
            let name = args[0].to_ascii_uppercase();
            if let Some(release) = behavior.hold.as_ref().filter(|_| name != b"AUTH") {
                while !release.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            let reply = if name == b"AUTH" {
                let (username, password) = match args.as_slice() {
                    [_, password] => (None, password.clone()),
                    [_, username, password] => (Some(username.clone()), password.clone()),
                    _ => (None, Vec::new()),
                };
                let accepted = behavior.credentials.as_ref().is_some_and(|(user, pass)| {
                    user.as_ref().map(|user| user.as_bytes().to_vec()) == username
                        && pass.as_bytes() == password.as_slice()
                });
                authenticated |= accepted;
                if accepted {
                    b"+OK\r\n".to_vec()
                } else {
                    b"-WRONGPASS invalid username-password pair\r\n".to_vec()
                }
            } else if !authenticated {
                b"-NOAUTH Authentication required.\r\n".to_vec()
            } else {
                commands.fetch_add(1, Ordering::AcqRel);
                match (name.as_slice(), args.as_slice()) {
                    (b"GET", [_, key]) => match store.lock_recover().get(key) {
                        Some(value) => {
                            let mut reply = format!("${}\r\n", value.len()).into_bytes();
                            reply.extend_from_slice(value);
                            reply.extend_from_slice(b"\r\n");
                            reply
                        }
                        None => b"$-1\r\n".to_vec(),
                    },
                    (b"SETEX", [_, key, _, value]) => {
                        store.lock_recover().insert(key.clone(), value.clone());
                        b"+OK\r\n".to_vec()
                    }
                    (b"DEL", [_, key]) => {
                        let removed = store.lock_recover().remove(key).is_some();
                        format!(":{}\r\n", u8::from(removed)).into_bytes()
                    }
                    _ => b"-ERR unknown command\r\n".to_vec(),
                }
            };
            if stream.write_all(&reply).is_err() || behavior.close_after_reply {
                return;
            }
        }
    }

    /** @brief 요청 줄 하나를 읽는다. */
    fn read_line<S: Read>(stream: &mut S) -> Option<Vec<u8>> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            stream.read_exact(&mut byte).ok()?;
            if byte[0] == b'\n' && line.last() == Some(&b'\r') {
                line.pop();
                return Some(line);
            }
            line.push(byte[0]);
        }
    }

    /** @brief 명령 하나를 인자 목록으로 읽는다. */
    fn read_command<S: Read>(stream: &mut S) -> Option<Vec<Vec<u8>>> {
        let header = read_line(stream)?;
        let count: usize = std::str::from_utf8(header.strip_prefix(b"*")?)
            .ok()?
            .parse()
            .ok()?;
        let mut args = Vec::with_capacity(count);
        for _ in 0..count {
            let length = read_line(stream)?;
            let length: usize = std::str::from_utf8(length.strip_prefix(b"$")?)
                .ok()?
                .parse()
                .ok()?;
            let mut value = vec![0u8; length + 2];
            stream.read_exact(&mut value).ok()?;
            value.truncate(length);
            args.push(value);
        }
        (!args.is_empty()).then_some(args)
    }
}

#[cfg(test)]
/** @brief 데드라인, 연결 풀, 회로, 인증, TLS, 그리고 연결이 어긋나지 않는지. */
mod tests {
    use super::fake::{Behavior, FakeRedis};
    use super::*;
    use std::net::TcpListener;

    /** @brief 평문으로 붙는 클라이언트. */
    fn plain_client(addr: SocketAddr) -> Arc<RedisClient> {
        Arc::new(RedisClient::new(RedisOptions {
            addr,
            tls: None,
            auth: None,
        }))
    }

    #[test]
    /** @brief 실패 뒤 잠시 아예 건너뛰는지. */
    fn connection_failure_opens_fast_fail_circuit() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let client = plain_client(addr);

        assert!(client.get(b"missing").is_none());
        assert!(matches!(*client.circuit.lock_recover(), Circuit::Open(_)));

        let started = Instant::now();
        assert!(client.get(b"missing-again").is_none());
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    /**
     * @brief 느린 캐시에 동시에 보낸 명령이 줄을 서지 않는지.
     * @details 연결 하나를 잠금으로 나눠 쓰면 명령마다 앞 명령의 왕복을 기다려 지연이 쌓인다.
     *          실패가 아니므로 회로도 열리지 않아 질의마다 그 지연을 치른다.
     */
    fn slow_cache_does_not_serialize_concurrent_commands() {
        let delay = ROUNDTRIP_TIMEOUT / 4;
        let fake = FakeRedis::start(Behavior {
            delay,
            ..Behavior::default()
        });
        let client = plain_client(fake.addr);
        let started = Instant::now();
        let workers: Vec<_> = (0..8)
            .map(|index| {
                let client = client.clone();
                std::thread::spawn(move || client.get(format!("key-{index}").as_bytes()))
            })
            .collect();
        for worker in workers {
            assert!(worker.join().unwrap().is_none());
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < delay * 4,
            "commands waited for each other: {elapsed:?}"
        );
        assert_eq!(*client.circuit.lock_recover(), Circuit::Closed);
        assert_eq!(fake.commands.load(Ordering::Acquire), 8);
    }

    #[test]
    /**
     * @brief 연결이 모두 쓰이는 중이면 기다리지 않고 건너뛰며, 그것을 실패로 세지 않는지.
     * @details 연결 수 상한까지 자리를 붙들어 다른 명령이 연결을 모두 빌려 간 상태를 만든다.
     */
    fn exhausted_pool_skips_instead_of_waiting() {
        let fake = FakeRedis::start(Behavior::default());
        let client = plain_client(fake.addr);
        let held: Vec<Slot> = (0..MAX_CONNECTIONS)
            .map(|_| Slot::acquire(&client.open).unwrap())
            .collect();
        assert!(Slot::acquire(&client.open).is_none());

        let started = Instant::now();
        assert!(client.get(b"busy").is_none());
        assert!(started.elapsed() < Duration::from_millis(200));
        assert_eq!(*client.circuit.lock_recover(), Circuit::Closed);
        assert_eq!(fake.connections.load(Ordering::Acquire), 0);

        drop(held);
        assert_eq!(client.open.load(Ordering::Acquire), 0);
        client.setex(b"busy".to_vec(), 60, b"v".to_vec());
        client.wait_for_writes();
        assert_eq!(client.get(b"busy").as_deref(), Some(b"v".as_slice()));
        assert_eq!(client.open.load(Ordering::Acquire), 1);
    }

    #[test]
    /** @brief 쉬는 연결을 다시 쓰는지. */
    fn idle_connections_are_reused() {
        let fake = FakeRedis::start(Behavior::default());
        let client = plain_client(fake.addr);
        client.setex(b"k".to_vec(), 60, b"v".to_vec());
        client.wait_for_writes();
        for _ in 0..5 {
            assert_eq!(client.get(b"k").as_deref(), Some(b"v".as_slice()));
        }
        assert_eq!(fake.connections.load(Ordering::Acquire), 1);
    }

    #[test]
    /** @brief 상대가 닫은 쉬는 연결을 만나면 새 연결로 한 번 더 보내고, 회로는 열지 않는지. */
    fn closed_idle_connection_is_replaced_without_opening_the_circuit() {
        let fake = FakeRedis::start(Behavior {
            close_after_reply: true,
            ..Behavior::default()
        });
        let client = plain_client(fake.addr);
        client.setex(b"k".to_vec(), 60, b"v".to_vec());
        client.wait_for_writes();
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(client.get(b"k").as_deref(), Some(b"v".as_slice()));
        assert_eq!(*client.circuit.lock_recover(), Circuit::Closed);
        assert_eq!(fake.connections.load(Ordering::Acquire), 2);
    }

    #[test]
    /**
     * @brief 답은 하지만 느린 캐시를 실패로 보고 건너뛰는지.
     * @details 명령 데드라인 안에서만 느리면 실패가 아니어서 회로가 열리지 않고, 질의마다 그만큼
     *          기다린다.
     */
    fn slow_replies_open_the_circuit() {
        let fake = FakeRedis::start(Behavior {
            delay: ROUNDTRIP_TIMEOUT * 5,
            ..Behavior::default()
        });
        let client = plain_client(fake.addr);
        let started = Instant::now();
        assert!(client.get(b"k").is_none());
        let waited = started.elapsed();
        assert!(
            waited < ROUNDTRIP_TIMEOUT * 3,
            "the lookup waited for the slow reply: {waited:?}"
        );
        assert!(matches!(*client.circuit.lock_recover(), Circuit::Open(_)));

        let started = Instant::now();
        assert!(client.get(b"k").is_none());
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    /**
     * @brief 담기와 지우기가 답을 기다리지 않는지.
     * @details 가짜 Redis는 테스트가 풀어 줄 때까지 답하지 않는다. 쓰기가 답을 기다리면 테스트가
     *          풀어 주기 전에 데드라인이 지나 쓰기가 실패하고 값이 담기지 않는다.
     */
    fn writes_do_not_wait_for_the_reply() {
        let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fake = FakeRedis::start(Behavior {
            hold: Some(release.clone()),
            ..Behavior::default()
        });
        let client = plain_client(fake.addr);
        client.setex(b"k".to_vec(), 60, b"v".to_vec());
        client.del(b"gone".to_vec());
        release.store(true, Ordering::Release);
        client.wait_for_writes();
        assert_eq!(fake.value(b"k").as_deref(), Some(b"v".as_slice()));
        assert_eq!(*client.circuit.lock_recover(), Circuit::Closed);
        assert_eq!(fake.commands.load(Ordering::Acquire), 2);
    }

    #[test]
    /**
     * @brief 쉬는 시간이 지나면 명령 하나만 다시 붙어 보고, 그 결과로만 회로가 바뀌는지.
     * @details 다시 붙어 보는 명령이 결과 없이 사라지면 회로를 실패로 연다. 그러지 않으면 다시
     *          붙어 보는 상태에 머물러 공유 캐시를 영영 쓰지 않는다.
     */
    fn only_one_command_probes_and_only_it_closes_the_circuit() {
        let client = plain_client(SocketAddr::from(([127, 0, 0, 1], 1)));
        *client.circuit.lock_recover() = Circuit::Open(Instant::now());

        assert_eq!(client.admit(), Some(Admission::Probe));
        assert_eq!(client.admit(), None, "a second command must not probe too");

        drop(Outcome {
            client: &client,
            admission: Admission::Probe,
            settled: false,
        });
        assert!(
            matches!(*client.circuit.lock_recover(), Circuit::Open(until) if until > Instant::now())
        );

        *client.circuit.lock_recover() = Circuit::Open(Instant::now());
        assert_eq!(client.admit(), Some(Admission::Probe));
        client.on_success(Admission::Normal);
        assert_eq!(*client.circuit.lock_recover(), Circuit::Probing);
        client.on_success(Admission::Probe);
        assert_eq!(*client.circuit.lock_recover(), Circuit::Closed);
        assert_eq!(client.admit(), Some(Admission::Normal));
    }

    #[test]
    /** @brief 회로가 열린 뒤에 끝난 이전 명령의 실패가 쉬는 시간을 늘리지 않는지. */
    fn late_failure_of_an_earlier_command_leaves_the_open_circuit_alone() {
        let client = plain_client(SocketAddr::from(([127, 0, 0, 1], 1)));
        let error = std::io::Error::from(std::io::ErrorKind::TimedOut);
        client.on_failure(Admission::Normal, &error);
        let Circuit::Open(first) = *client.circuit.lock_recover() else {
            panic!("the first failure must open the circuit");
        };
        std::thread::sleep(Duration::from_millis(20));
        client.on_failure(Admission::Normal, &error);
        assert_eq!(*client.circuit.lock_recover(), Circuit::Open(first));
    }

    #[test]
    /** @brief 새 연결마다 AUTH 로 인증하고, 사용자 이름이 없으면 기본 사용자로 인증하는지. */
    fn every_new_connection_authenticates() {
        for username in [Some("dns".to_string()), None] {
            let fake = FakeRedis::start(Behavior {
                credentials: Some((username.clone(), "correct-password".into())),
                ..Behavior::default()
            });
            let client = Arc::new(RedisClient::new(RedisOptions {
                addr: fake.addr,
                tls: None,
                auth: Some(RedisAuth {
                    username,
                    password: "correct-password".into(),
                }),
            }));
            client.setex(b"k".to_vec(), 60, b"v".to_vec());
            client.wait_for_writes();
            assert_eq!(client.get(b"k").as_deref(), Some(b"v".as_slice()));
            assert_eq!(*client.circuit.lock_recover(), Circuit::Closed);
        }
    }

    #[test]
    /** @brief 자격 증명을 거부당하면 명령을 보내지 않고 회로를 여는지. */
    fn rejected_credentials_open_the_circuit_before_any_command() {
        let fake = FakeRedis::start(Behavior {
            credentials: Some((Some("dns".into()), "correct-password".into())),
            ..Behavior::default()
        });
        fake.insert(b"k".to_vec(), b"v".to_vec());
        let client = RedisClient::new(RedisOptions {
            addr: fake.addr,
            tls: None,
            auth: Some(RedisAuth {
                username: Some("dns".into()),
                password: "wrong-password".into(),
            }),
        });
        assert!(client.get(b"k").is_none());
        assert!(matches!(*client.circuit.lock_recover(), Circuit::Open(_)));
        assert_eq!(fake.commands.load(Ordering::Acquire), 0);
    }

    #[test]
    /** @brief TLS 로 붙고, 인증서 이름이 설정한 호스트와 다르면 거부하는지. */
    fn tls_connection_checks_the_certificate_name() {
        let (certs, key) = onetdns_transport::self_signed_material("redis.test").unwrap();
        let roots = TrustStore::from_ders([certs[0].as_slice()]);
        let server =
            Arc::new(onetdns_tls::ServerConfig::from_pkcs8(certs[0].clone(), &key).unwrap());
        let fake = FakeRedis::start(Behavior {
            tls: Some(server),
            ..Behavior::default()
        });
        let tls_client = |server_name: &str| {
            Arc::new(RedisClient::new(RedisOptions {
                addr: fake.addr,
                tls: Some(RedisTls {
                    server_name: server_name.to_string(),
                    roots: roots.clone(),
                }),
                auth: None,
            }))
        };

        let client = tls_client("redis.test");
        client.setex(b"k".to_vec(), 60, b"v".to_vec());
        client.wait_for_writes();
        assert_eq!(client.get(b"k").as_deref(), Some(b"v".as_slice()));

        let impostor = tls_client("other.test");
        assert!(impostor.get(b"k").is_none());
        assert!(matches!(*impostor.circuit.lock_recover(), Circuit::Open(_)));
    }

    #[test]
    /**
     * @brief 읽기 버퍼보다 큰 값을 읽은 뒤에도 같은 연결에서 다음 답을 제대로 읽는지.
     * @details 큰 값은 앞부분이 버퍼에 담기고 나머지는 소켓에서 바로 읽힌다. 그 경계에서 바이트를
     *          잃거나 겹쳐 읽으면 다음 명령이 앞 명령의 답을 읽는다.
     */
    fn large_reply_keeps_the_pooled_connection_in_step() {
        let fake = FakeRedis::start(Behavior::default());
        let client = plain_client(fake.addr);
        let large: Vec<u8> = (0..=u8::MAX).cycle().take(MAX_BULK_REPLY).collect();
        fake.insert(b"large".to_vec(), large.clone());
        fake.insert(b"small".to_vec(), b"v".to_vec());
        for _ in 0..3 {
            assert_eq!(client.get(b"large").as_deref(), Some(large.as_slice()));
            assert_eq!(client.get(b"small").as_deref(), Some(b"v".as_slice()));
            assert!(client.get(b"missing").is_none());
        }
        assert_eq!(fake.connections.load(Ordering::Acquire), 1);
    }

    #[test]
    /** @brief 수 형식을 엄격히 보고, 배열 응답이 연결을 어긋나게 하지 않는지. */
    fn resp_numeric_fields_are_strict_and_arrays_cannot_desync_connection() {
        assert!(parse_i64(b"12").is_ok());
        assert!(parse_i64(b"").is_err());
        assert!(parse_i64(b"12x").is_err());

        let read = |reply: &[u8]| read_reply(&mut &reply[..]);
        assert!(read(b"$wat\r\n").is_err());
        assert!(read(b"$-2\r\n").is_err());
        assert!(read(b"*1\r\n$3\r\nfoo\r\n").is_err());
        assert!(matches!(read(b"$-1\r\n"), Ok(RespValue::Nil)));
        assert!(matches!(read(b"$3\r\nfoo\r\n"), Ok(RespValue::Bulk(value)) if value == b"foo"));
    }

    #[test]
    /** @brief 변형한 응답 바이트를 읽어도 패닉하지 않는지. */
    fn resp_reader_survives_mutated_replies() {
        use crate::fuzzutil::{havoc, Rng};
        let seeds: [&[u8]; 5] = [
            b"+OK\r\n",
            b"-ERR wrong\r\n",
            b":42\r\n",
            b"$5\r\nhello\r\n",
            b"*-1\r\n",
        ];
        let mut rng = Rng::new(0x5245_4449_535f_5245);
        for round in 0..20_000 {
            let input = if round % 3 == 0 {
                rng.rand_bytes(64)
            } else {
                havoc(&mut rng, seeds[round % seeds.len()])
            };
            let _ = read_reply(&mut input.as_slice());
        }
    }
}
