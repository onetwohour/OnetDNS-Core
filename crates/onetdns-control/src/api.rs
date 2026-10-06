/*!
 * @brief 컨트롤 플레인 REST API와 대시보드 서빙.
 *
 * @details 손으로 쓴 HTTP/1.1 서버다. 비차단 admission이 완성한 요청만 연결 스레드로
 *          넘기고, 라우팅은 메서드와 경로의 match 두 겹으로 한다. 첫 겹이 정적 자산과
 *          헬스, 둘째 겹이 인증을 거친 뒤의 API다.
 * @warning 이 서버는 관리 권한을 다룬다. 인증 이전 경로는 최소로 유지하고, 상태를
 *          바꾸는 요청은 직렬화해 서로 겹치지 않게 한다.
 * @note 대시보드는 서버 템플릿 없이 전부 내려보내는 클라이언트 앱이다. 새 필드를
 *       보이려면 여기 JSON 생성기와 대시보드 쪽 바인딩을 함께 고쳐야 한다.
 */

use std::borrow::Cow;
use std::collections::hash_map::RandomState;
use std::collections::{HashMap, VecDeque};
use std::hash::BuildHasher;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use onetdns_core::json;
use onetdns_core::tcp::DeadlineTcp;
use onetdns_core::{ArcSwap, HttpsOrigin, IpNet, MutexExt, SecretString};
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::metrics::{now_ms, MetricsSnapshot, QueryEvent, Stats};

/** @brief 동시에 받을 제어 연결 수. */
const MAX_CONTROL_CONNECTIONS: usize = 128;

/** @brief 동시에 받을 스트리밍 연결 수. 오래 붙어 있으므로 따로 더 좁게 잡는다. */
const MAX_CONTROL_STREAM_CONNECTIONS: usize = 64;
/**
 * @brief 제어 연결 스레드 스택 크기.
 * @details 요청을 받은 스레드가 설정 반영까지 그대로 실행한다. 반영에는 차단 엔진 컴파일과
 *          영역 파일 파싱이 들어가고, 최적화하지 않은 빌드는 그 프레임이 훨씬 크다. 스택이
 *          모자라면 설정 하나를 바꾸다 프로세스 전체가 죽는다. 스택은 쓰는 만큼만 커밋되므로
 *          연결 수만큼 예약해도 실제 메모리는 늘지 않는다.
 */
const CONTROL_CONNECTION_STACK_BYTES: usize = 1024 * 1024;
/** @brief 요청을 다 받기까지의 데드라인. */
const CONTROL_READ_TIMEOUT_SECS: u64 = 15;
/** @brief 응답을 다 보내기까지의 데드라인. */
const CONTROL_WRITE_TIMEOUT_SECS: u64 = 30;

/** @brief 개별 모양으로 추적할 관리 API 실패 수의 상한. */
const MAX_REQUEST_FAILURE_COUNTS: usize = 256;

/** @brief 종료 시 남은 연결을 기다려 줄 시간. */
const CONTROL_DRAIN_GRACE_SECS: u64 = 5;

/** @brief 한 TCP 소켓을 OS 핸들 복제 없이 읽기·쓰기·종료 경로가 함께 가진다. */
#[derive(Clone)]
struct SharedTcp(Arc<TcpStream>);

impl SharedTcp {
    /** @brief 유일한 OS 소켓 소유권을 공유 참조로 감싼다. */
    fn new(stream: TcpStream) -> Self {
        Self(Arc::new(stream))
    }

    /** @brief 상대 주소. */
    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.peer_addr()
    }

    /** @brief 로컬 주소. */
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.local_addr()
    }

    /** @brief 읽기 타임아웃. 같은 소켓을 읽는 경로 모두에 적용된다. */
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.0.set_read_timeout(timeout)
    }

    /** @brief 블로킹 모드를 바꾼다. admission 동안만 비차단으로 둔다. */
    fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }

    /** @brief 공유 소켓의 입출력을 함께 끊는다. */
    fn shutdown(&self, how: std::net::Shutdown) -> std::io::Result<()> {
        self.0.shutdown(how)
    }
}

impl Read for SharedTcp {
    /** @brief TcpStream의 공유 읽기 구현으로 전달한다. */
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut stream = &*self.0;
        stream.read(buf)
    }
}

impl Write for SharedTcp {
    /** @brief TcpStream의 공유 쓰기 구현으로 전달한다. */
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut stream = &*self.0;
        stream.write(buf)
    }

    /** @brief TcpStream의 flush 구현으로 전달한다. */
    fn flush(&mut self) -> std::io::Result<()> {
        let mut stream = &*self.0;
        stream.flush()
    }
}

/**
 * @brief admission 이 먼저 읽어 둔 요청 바이트를 앞에 붙인 연결.
 * @details 앞 바이트를 다 돌려준 뒤에는 소켓을 그대로 읽는다. 데드라인과 종료 신호는 이 연결을
 *          감싼 DeadlineTcp 가 지킨다.
 */
struct AdmittedTcp {
    /** @brief 실제 소켓. */
    stream: SharedTcp,
    /** @brief admission이 먼저 읽어 둔 요청 바이트. */
    prefix: Vec<u8>,
    /** @brief prefix에서 다음에 읽을 곳. */
    prefix_offset: usize,
    /** @brief prefix가 사라질 때 전역 admission 원문 예산을 돌려준다. */
    _admission_bytes: Option<AdmissionBytesGuard>,
}

impl AdmittedTcp {
    /** @brief 소켓 앞에 admission이 읽어 둔 바이트를 붙인다. */
    fn new(
        stream: SharedTcp,
        prefix: Vec<u8>,
        admission_bytes: Option<AdmissionBytesGuard>,
    ) -> Self {
        Self {
            stream,
            prefix,
            prefix_offset: 0,
            _admission_bytes: admission_bytes,
        }
    }
}

impl Read for AdmittedTcp {
    /** @brief prefix를 먼저, 소켓을 나중에 읽는다. */
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.prefix_offset < self.prefix.len() {
            let available = &self.prefix[self.prefix_offset..];
            let copied = available.len().min(buf.len());
            buf[..copied].copy_from_slice(&available[..copied]);
            self.prefix_offset += copied;
            return Ok(copied);
        }
        self.stream.read(buf)
    }
}

impl onetdns_core::tcp::SocketTimeouts for AdmittedTcp {
    /** @brief 소켓에 건다. */
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }

    /** @brief 소켓에 건다. */
    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.stream.0.set_write_timeout(timeout)
    }
}

/** @brief 연결 수를 세는 보호자. 사라질 때 자동으로 되돌린다. */
struct ActiveConnectionGuard(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for ActiveConnectionGuard {
    /** @brief 세었던 슬롯을 돌려준다. */
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/** @brief 인증 전 요청 원문이 쓸 수 있는 전역 메모리 예산의 연결별 지분. */
struct AdmissionBytesGuard {
    /** @brief 모든 보류·처리 연결이 예약한 원문 바이트 합계. */
    total: Arc<std::sync::atomic::AtomicUsize>,
    /** @brief 이 연결이 예약한 바이트. */
    held: usize,
}

impl AdmissionBytesGuard {
    /** @brief 아직 지분이 없는 보호자를 만든다. */
    fn new(total: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        Self { total, held: 0 }
    }

    /** @brief 전역 상한 안에서 가능한 만큼 원자적으로 예약한다. */
    fn reserve(&mut self, wanted: usize) -> usize {
        use std::sync::atomic::Ordering;
        let mut current = self.total.load(Ordering::Acquire);
        loop {
            let granted = wanted.min(MAX_CONTROL_ADMISSION_BYTES.saturating_sub(current));
            if granted == 0 {
                return 0;
            }
            match self.total.compare_exchange_weak(
                current,
                current + granted,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.held += granted;
                    return granted;
                }
                Err(observed) => current = observed,
            }
        }
    }

    /** @brief 실제로 읽지 않은 예약분을 즉시 돌려준다. */
    fn release(&mut self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        debug_assert!(bytes <= self.held);
        self.held -= bytes;
        self.total
            .fetch_sub(bytes, std::sync::atomic::Ordering::AcqRel);
    }
}

impl Drop for AdmissionBytesGuard {
    /** @brief 연결 또는 파서가 원문을 버릴 때 남은 지분을 전부 돌려준다. */
    fn drop(&mut self) {
        self.release(self.held);
    }
}

/** @brief 전체 제어 연결 슬롯을 원자적으로 잡는다. 꽉 찼으면 잡지 않는다. */
fn acquire_connection_slot(
    active: &Arc<std::sync::atomic::AtomicUsize>,
) -> Option<ActiveConnectionGuard> {
    use std::sync::atomic::Ordering;
    active
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count < MAX_CONTROL_CONNECTIONS).then_some(count + 1)
        })
        .ok()
        .map(|_| ActiveConnectionGuard(active.clone()))
}

/** @brief 지금 열려 있는 스트리밍 연결 수. */
static ACTIVE_STREAM_CONNECTIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/** @brief 스트리밍 슬롯을 잡았다 놓는 보호자. */
struct StreamSlotGuard;

impl Drop for StreamSlotGuard {
    /** @brief 세었던 슬롯을 돌려준다. */
    fn drop(&mut self) {
        ACTIVE_STREAM_CONNECTIONS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/** @brief 스트리밍 슬롯을 잡는다. 꽉 찼으면 잡지 않는다. */
fn acquire_stream_slot() -> Option<StreamSlotGuard> {
    use std::sync::atomic::Ordering;
    if ACTIVE_STREAM_CONNECTIONS.fetch_add(1, Ordering::AcqRel) >= MAX_CONTROL_STREAM_CONNECTIONS {
        ACTIVE_STREAM_CONNECTIONS.fetch_sub(1, Ordering::AcqRel);
        return None;
    }
    Some(StreamSlotGuard)
}

#[cfg(test)]
/** @brief 스트리밍 곳 수가 상한을 지키고 제대로 돌아오는지. */
mod stream_slot_tests {
    use super::*;

    #[test]
    /** @brief 곳이 상한에서 막히고, 놓으면 다시 잡히는지. */
    fn stream_slots_are_bounded_and_released() {
        let mut held = Vec::new();
        while let Some(g) = acquire_stream_slot() {
            held.push(g);
            assert!(
                held.len() <= MAX_CONTROL_STREAM_CONNECTIONS,
                "Concurrency limit reached; cannot acquire a slot"
            );
        }
        assert!(!held.is_empty());
        held.pop();
        assert!(
            acquire_stream_slot().is_some(),
            "A slot can be acquired again after release"
        );
    }

    #[test]
    /** @brief 전체 연결 위치가 상한에서 막히고 놓은 뒤 다시 잡히는지. */
    fn control_connection_slots_are_bounded_balanced_and_released() {
        assert_eq!(
            MAX_CONTROL_CONNECTIONS,
            MAX_CONTROL_STREAM_CONNECTIONS * 2,
            "Streaming at capacity still leaves 64 regular and Raft connections"
        );
        assert_eq!(CONTROL_CONNECTION_STACK_BYTES, 1024 * 1024);

        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut held = Vec::new();
        while let Some(guard) = acquire_connection_slot(&active) {
            held.push(guard);
        }
        assert_eq!(held.len(), MAX_CONTROL_CONNECTIONS);
        assert_eq!(
            active.load(std::sync::atomic::Ordering::Acquire),
            MAX_CONTROL_CONNECTIONS,
            "A rejected acquire does not increase the active connection count"
        );
        held.pop();
        assert!(acquire_connection_slot(&active).is_some());
    }

    #[test]
    /** @brief 공유 TCP 복제가 OS 소켓이 아니라 같은 Arc 소유권만 늘리는지. */
    fn shared_tcp_clone_keeps_one_socket_owner() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let mut shared = SharedTcp::new(client);
        let clone = shared.clone();

        assert!(Arc::ptr_eq(&shared.0, &clone.0));
        shared.write_all(b"x").unwrap();
        let mut byte = [0u8; 1];
        server.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"x");
        clone.shutdown(std::net::Shutdown::Both).unwrap();
    }
}

/** @brief ACME 인증서 발급용 임시 응답값. */
static ACME_HTTP01: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
/** @brief 단계별 전송 오류 횟수. 로그를 지수적으로 줄이는 데 쓴다. */
static CONTROL_ERROR_COUNTS: OnceLock<Mutex<HashMap<&'static str, u64>>> = OnceLock::new();
/** @brief 상태 변경 요청을 직렬화하는 잠금. */
static CONTROL_MUTATION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/** @brief 상태 변경 잠금. 처음 쓸 때 만든다. */
fn control_mutation_lock() -> &'static Mutex<()> {
    CONTROL_MUTATION_LOCK.get_or_init(|| Mutex::new(()))
}

/**
 * @brief 이 요청이 서버 상태를 바꾸는지.
 * @note POST 중에도 검증이나 모의 실행처럼 바꾸지 않는 것이 있다. 그것까지 잠그면
 *       읽기 성격의 요청이 서로를 기다린다.
 */
fn is_state_changing_request(method: &str, path: &str) -> bool {
    match method {
        "PUT" | "PATCH" | "DELETE" => true,
        "POST" => !matches!(
            path,
            "/v1/config/validate"
                | "/v1/config/diff"
                | "/v1/config/set/diff"
                | "/v1/explain"
                | "/v1/resolve"
                | "/v1/policies/simulate"
                | "/v1/tls/validate"
                | "/v1/tls/revocation-check"
                | "/v1/upstreams/test"
        ),
        _ => false,
    }
}

/**
 * @brief 이 요청에 변경 잠금이 필요한지. 잠그지 않는 요청은 클러스터 합의도 거치지 않는다.
 * @details 클러스터 제안은 예외다. 그것은 합의 계층이 자체 순서를 정하므로, 여기서 또
 *          잠그면 제안 처리가 서로를 막는다. 자체 업데이트 요청도 예외다. 설정을 바꾸지 않고
 *          이 노드에서 작업만 시작하며, 업데이트 작업끼리는 업데이트 쪽이 하나씩 돌린다.
 */
fn requires_control_mutation_lock(method: &str, path: &str) -> bool {
    is_state_changing_request(method, path)
        && path != "/v1/cluster/propose"
        && !path.starts_with("/v1/system/update/")
}

/** @brief 되풀이되는 요청 실패를 제한된 수의 지문으로 세는 곳. */
static REQUEST_FAILURE_COUNTS: OnceLock<Mutex<RequestFailureCounts>> = OnceLock::new();

/** @brief 관리 API 실패 로그의 제한된 반복 카운터. */
struct RequestFailureCounts {
    /** @brief 원문을 보관하지 않는 요청 모양별 횟수. */
    counts: HashMap<u64, u64>,
    /** @brief 공격자가 지문 충돌을 고르지 못하게 하는 프로세스별 상태. */
    fingerprint_state: RandomState,
    /** @brief 개별 추적 상한 뒤 처음 본 요청 모양의 합계. */
    overflow: u64,
}

impl Default for RequestFailureCounts {
    /** @brief 빈 실패 카운터를 만든다. */
    fn default() -> Self {
        Self {
            counts: HashMap::new(),
            fingerprint_state: RandomState::new(),
            overflow: 0,
        }
    }
}

impl RequestFailureCounts {
    /** @brief 요청 모양을 프로세스별 무작위 지문으로 줄인다. */
    fn fingerprint(&self, method: &str, path: &str, status: u16) -> u64 {
        self.fingerprint_state.hash_one((method, path, status))
    }

    /** @brief 요청 모양의 횟수를 올리고 새 값을 돌려준다. */
    fn increment(&mut self, method: &str, path: &str, status: u16) -> u64 {
        let fingerprint = self.fingerprint(method, path, status);
        if let Some(count) = self.counts.get_mut(&fingerprint) {
            *count = count.saturating_add(1);
            return *count;
        }

        if self.counts.len() < MAX_REQUEST_FAILURE_COUNTS {
            self.counts.insert(fingerprint, 1);
            return 1;
        }

        self.overflow = self.overflow.saturating_add(1);
        self.overflow
    }

    #[cfg(test)]
    /** @brief 이미 개별 추적 중인 요청 모양의 횟수. */
    fn count(&self, method: &str, path: &str, status: u16) -> u64 {
        self.counts
            .get(&self.fingerprint(method, path, status))
            .copied()
            .unwrap_or(0)
    }
}

/**
 * @brief 같은 모양의 요청 실패가 지금까지 몇 번째인지.
 *
 * @details 상대 주소와 원문 경로를 보관하지 않는다. 프로세스별 무작위 지문은 정해진 수만
 *          개별 추적하고, 그 뒤 처음 본 모양은 단일 포화 카운터로 합친다.
 * @return 이 모양의 실패가 몇 번째인지. 1부터 센다.
 */
fn repeated_failure_count(method: &str, path: &str, status: u16) -> u64 {
    REQUEST_FAILURE_COUNTS
        .get_or_init(|| Mutex::new(RequestFailureCounts::default()))
        .lock_recover()
        .increment(method, path, status)
}

/** @brief 반복 실패를 이번 횟수에 로그로 남길지. */
fn should_log_repeated_failure(count: u64) -> bool {
    count == 1 || count.is_power_of_two()
}

/**
 * @brief 전송 오류를 세고 가끔만 로그로 남긴다.
 * @details 처음과 2의 거듭제곱 번째만 남긴다. 오류가 쏟아질 때 로그가 그것보다 더 큰
 *          문제가 되는 것을 막는다.
 */
fn record_control_error(
    stage: &'static str,
    peer: Option<SocketAddr>,
    detail: impl std::fmt::Display,
) {
    let count = {
        let mut counts = CONTROL_ERROR_COUNTS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock_recover();
        let count = counts.entry(stage).or_insert(0);
        *count = count.saturating_add(1);
        *count
    };
    if count == 1 || count.is_power_of_two() {
        let peer = peer
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        onetdns_core::warn!(event = "control.transport_error",
            transport = "control",
            stage = stage,
            peer = %peer,
            count = count,
            error = %detail,
            "Error on a dashboard connection"
        );
    }
}

#[cfg(test)]
/** @brief 이 단계에서 지금까지 센 오류 수. 거절이 기록되는지 테스트가 확인한다. */
fn control_error_count(stage: &str) -> u64 {
    CONTROL_ERROR_COUNTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock_recover()
        .get(stage)
        .copied()
        .unwrap_or(0)
}

#[cfg(test)]
/** @brief 이 모양의 요청 실패가 지금까지 몇 번 있었는지. 되풀이 억제를 테스트가 확인한다. */
fn request_failure_count(method: &str, path: &str, status: u16) -> u64 {
    REQUEST_FAILURE_COUNTS
        .get_or_init(|| Mutex::new(RequestFailureCounts::default()))
        .lock_recover()
        .count(method, path, status)
}

/** @brief ACME 응답값 저장소. */
fn acme_http01() -> &'static Mutex<HashMap<String, String>> {
    ACME_HTTP01.get_or_init(|| Mutex::new(HashMap::new()))
}

/** @brief ACME 인증에 쓸 응답값을 등록한다. */
pub fn set_acme_http01(token: &str, key_authorization: &str) {
    acme_http01()
        .lock_recover()
        .insert(token.to_string(), key_authorization.to_string());
}

/** @brief 등록한 ACME 응답값을 지운다. */
pub fn clear_acme_http01(token: &str) {
    acme_http01().lock_recover().remove(token);
}

/** @brief 관리 API 응답. 상태 줄, 콘텐츠 형식, 본문. */
pub type ApiResponse = (&'static str, &'static str, String);

/** @brief 상태를 바꾸는 요청을 클러스터 합의와 묶는 함수의 모양. */
pub type ClusterWrite =
    dyn Fn(&str, &str, &str, &mut dyn FnMut() -> ApiResponse) -> ApiResponse + Send + Sync;

/**
 * @brief 데이터 경로로 들어가는 콜백 테이블.
 * @details 컨트롤 플레인은 데이터 경로를 직접 알지 못한다. 필요한 동작을 전부 이 상자 안의
 *          클로저로 받아, 두 계층이 서로의 타입에 얽히지 않게 한다.
 */
pub struct Controls {
    /** @brief 설정과 목록을 다시 읽는다. */
    pub reload: Box<dyn Fn() -> Result<ListCounts, String> + Send + Sync>,
    /** @brief 차단 목록에 항목을 더한다. */
    pub block_add: Box<dyn Fn(&str) -> Result<ListCounts, String> + Send + Sync>,
    /** @brief 허용 목록에 항목을 더한다. */
    pub allow_add: Box<dyn Fn(&str) -> Result<ListCounts, String> + Send + Sync>,

    /** @brief 서비스 차단을 켜고 끈다. */
    pub service_set: Box<dyn Fn(&str, bool) -> Result<ListCounts, String> + Send + Sync>,

    /** @brief 안전 검색을 켜고 끈다. */
    pub safesearch_set: Box<dyn Fn(bool) -> Result<(), String> + Send + Sync>,

    /** @brief 지금 설정과 목록을 내보낸다. */
    pub export: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 내보낸 설정을 되읽는다. */
    pub import: Box<dyn Fn(&str) -> Result<ListCounts, String> + Send + Sync>,

    /** @brief 설정 문자열이 유효한지 검사한다. 적용하지는 않는다. */
    pub config_validate: Box<dyn Fn(&str) -> Result<(), String> + Send + Sync>,

    /** @brief 보낸 설정과 지금 설정의 차이. */
    pub config_diff: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 설정을 반영한다. 교체하거나 재시작한다. */
    pub config_apply: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 설정 항목 몇 개만 고친다. */
    pub config_set: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief config_set 에 보낼 항목들이 무엇을 바꾸고 어떻게 반영되는지. 적용하지는 않는다. */
    pub config_set_diff: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 대시보드가 화면을 그릴 설정 명세. */
    pub config_schema: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 이 업스트림에 실제로 닿는지 확인한다. */
    pub upstream_test: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 담아 둔 응답을 모두 비운다. */
    pub cache_flush: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 재작성 규칙 목록. */
    pub rewrites_list: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 재작성 규칙을 넣는다. */
    pub rewrite_add: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 재작성 규칙을 지운다. */
    pub rewrite_delete: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 차단할 수 있는 서비스 목록. */
    pub services_catalog: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 접근 제어 목록. */
    pub access_list: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 지금 인증서 상태. */
    pub tls_status: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 지금 인증서로 실제로 서빙할 수 있는지 확인한다. */
    pub tls_validate: Box<dyn Fn() -> Result<String, String> + Send + Sync>,

    /** @brief 인증서와 키를 바꾼다. */
    pub tls_configure: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 이 인증서가 폐기됐는지 확인한다. */
    pub tls_revocation_check: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 인증서 발급을 시작한다. */
    pub acme_issue: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 제어 토큰 목록. 토큰 자체는 드러내지 않는다. */
    pub tokens_list: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 제어 토큰을 만든다. */
    pub token_add: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 제어 토큰을 지운다. */
    pub token_delete: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 직전 설정으로 되돌린다. */
    pub config_rollback: Box<dyn Fn() -> Result<String, String> + Send + Sync>,

    /** @brief 이 질의가 어떻게 판정될지 실제로 묻지 않고 보여 준다. */
    pub policy_simulate: Box<dyn Fn(&str) -> String + Send + Sync>,

    /** @brief 권한 영역 목록. */
    pub zones_list: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 이 영역의 기록들. */
    pub zone_get: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 이 영역을 전부 바꾼다. */
    pub zone_put: Box<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>,

    /** @brief 이 영역을 지운다. */
    pub zone_delete: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 이 영역에 기록을 넣는다. */
    pub zone_record_add: Box<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>,

    /** @brief 이 영역에서 기록을 지운다. */
    pub zone_record_delete: Box<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>,

    /** @brief 이 영역의 서명 여부와 서명 키, 부모 영역에 올릴 DS. */
    pub zone_dnssec: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 파일에 적힌 설정. */
    pub config_desired: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 지금 적용 중인 설정. */
    pub config_effective: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 파일과 적용 중인 설정이 어긋나는지. */
    pub config_status: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 설정을 다시 읽게 한다. */
    pub config_reload: Box<dyn Fn() -> Result<String, String> + Send + Sync>,

    /** @brief 정책 플러그인별 지표. */
    pub plugins_metrics: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 차단 현황 요약. */
    pub filter_report: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 많이 걸린 차단 규칙. */
    pub filter_top_rules: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 차단 목록 출처별 현황. */
    pub filter_sources: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 구독 중인 차단 목록. */
    pub subscriptions_list: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 차단 목록 구독을 넣는다. */
    pub subscription_add: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 차단 목록 구독을 뺀다. */
    pub subscription_remove: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 구독의 설정을 바꾼다. */
    pub subscription_update: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 구독한 목록을 지금 다시 내려받는다. */
    pub subscription_refresh: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 사용자가 넣은 규칙 목록. */
    pub filter_rules_list: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 사용자 규칙을 넣거나 뺀다. */
    pub filter_rule_mutate: Box<dyn Fn(&str, bool) -> Result<String, String> + Send + Sync>,

    /** @brief 클라이언트 목록. */
    pub clients_list: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 업스트림 서버 목록과 그 성적. */
    pub upstreams_list: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 오래 걸리는 작업 목록. */
    pub jobs_list: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 이 작업의 진행 상황. */
    pub job_get: Box<dyn Fn(u64) -> Result<String, String> + Send + Sync>,

    /** @brief 목록 갱신 작업을 시작한다. */
    pub job_refresh: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 지금 나가 있는 DHCP 임대. */
    pub dhcp_leases: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 다른 서버에서 온 임대를 받아들인다. */
    pub dhcp_lease_put: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief DHCP 고정 할당 목록. */
    pub dhcp_static_list: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief DHCP 고정 할당을 넣는다. */
    pub dhcp_static_add: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief DHCP 고정 할당을 뺀다. */
    pub dhcp_static_remove: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 클라이언트 그룹을 넣는다. */
    pub client_add: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 클라이언트 그룹을 뺀다. */
    pub client_remove: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 클라이언트 그룹을 고친다. */
    pub client_update: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 대시보드 로그인 암호를 바꾼다. */
    pub password_change: Box<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>,

    /** @brief 계정이 하나도 없을 때 첫 관리자 계정을 설정 파일에 적는다. */
    pub user_create: Box<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>,

    /** @brief 업스트림 서버를 넣는다. */
    pub upstream_add: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 업스트림 서버를 뺀다. */
    pub upstream_remove: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 이 질의가 왜 그렇게 판정됐는지 설명한다. */
    pub explain: Box<dyn Fn(&str) -> String + Send + Sync>,

    /** @brief 클러스터 상태. */
    pub cluster_status: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 클러스터에 설정 변경을 제안한다. */
    pub cluster_propose: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /**
     * @brief 상태를 바꾸는 요청 하나를 Raft 합의를 거쳐 처리한다.
     * @details 요청 처리 함수를 받아 처리 전후의 설정을 비교하고, 클러스터 공유 설정이
     *          바뀌었으면 Raft 에 제안한다. 커밋되지 않은 변경은 되돌리고 실패로 응답한다.
     *          Raft 를 쓰지 않으면 요청 처리 함수를 그대로 호출한다.
     * @param method 요청 방식.
     * @param path 요청 경로.
     * @param body 요청 본문.
     * @param dispatch 실제 요청 처리. 한 번만 부른다.
     */
    pub cluster_write: Box<ClusterWrite>,

    /** @brief 지금 열려 있는 리스너 상태. */
    pub listeners_status: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 시스템 네트워크 어댑터 목록. */
    pub net_adapters: Box<dyn Fn() -> Result<String, String> + Send + Sync>,

    /** @brief 방화벽 규칙을 바꾼다. */
    pub firewall_set: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 시스템 DNS 설정을 이 서버로 돌린다. */
    pub dns_client_set: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 시스템 DNS 설정을 원래대로 되돌린다. */
    pub dns_client_restore: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /**
     * @brief 이름 하나를 이 서버에 실제로 물어본다.
     *
     * @details 진단은 「어떻게 처분될지」를 설명할 뿐이고, 운영자가 정작 알고 싶은 것은
     *          「그래서 무엇으로 풀리는지」다. 이 서버의 수신 주소로 진짜 질의를 보내므로
     *          접근 제한·필터·캐시를 모두 거친 답이 나온다.
     */
    pub resolve_probe: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 부팅 서비스 등록 상태. 이 운영체제가 지원하는지도 함께 알린다. */
    pub boot_service_status: Box<dyn Fn() -> String + Send + Sync>,

    /** @brief 부팅 서비스를 등록하거나 제거한다. */
    pub boot_service_set: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /** @brief 자체 업데이트 상태. */
    pub update_status: Box<dyn Fn() -> String + Send + Sync>,

    /**
     * @brief 새 릴리스를 확인하는 작업을 시작한다.
     * @return 시작한 작업. 실패는 지금 상태로는 시작할 수 없다는 뜻이다.
     */
    pub update_check: Box<dyn Fn() -> Result<String, String> + Send + Sync>,

    /**
     * @brief 마지막 확인에서 찾은 버전을 설치하는 작업을 시작한다.
     * @param version 운영자가 확인한 버전. 마지막 확인 결과와 다르면 시작하지 않는다.
     * @return 시작한 작업. 실패는 지금 상태로는 시작할 수 없다는 뜻이다.
     */
    pub update_apply: Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>,

    /**
     * @brief 확정된 업데이트를 되돌리는 작업을 시작한다.
     * @return 시작한 작업. 실패는 지금 상태로는 시작할 수 없다는 뜻이다.
     */
    pub update_rollback: Box<dyn Fn() -> Result<String, String> + Send + Sync>,

    /** @brief 데이터 경로가 따로 내보내는 지표. */
    pub metrics_extra: Box<dyn Fn() -> String + Send + Sync>,
}

impl Controls {
    /** @brief 아무것도 하지 않는 콜백 테이블. 테스트와 대시보드 단독 실행에 쓴다. */
    pub fn noop() -> Self {
        let counts = || Ok(ListCounts { block: 0, allow: 0 });
        Self {
            reload: Box::new(counts),
            block_add: Box::new(move |_| counts()),
            allow_add: Box::new(move |_| counts()),
            service_set: Box::new(move |_, _| counts()),
            safesearch_set: Box::new(|_| Ok(())),
            export: Box::new(|| "{\"version\":1}".to_string()),
            import: Box::new(move |_| counts()),
            config_validate: Box::new(|_| Ok(())),
            config_diff: Box::new(|_| {
                Ok("{\"added\":[],\"removed\":[],\"changed\":[]}".to_string())
            }),
            config_apply: Box::new(|_| Err("No config file path".to_string())),
            config_set: Box::new(|_| Err("No config file path".to_string())),
            config_set_diff: Box::new(|_| {
                Ok("{\"added\":[],\"removed\":[],\"changed\":[]}".to_string())
            }),
            config_schema: Box::new(|| "{\"keys\":[]}".to_string()),
            upstream_test: Box::new(|_| Err("The requested feature is not available".to_string())),
            cache_flush: Box::new(|| "{\"flushed\":0}".to_string()),
            rewrites_list: Box::new(|| "{\"rewrites\":[]}".to_string()),
            rewrite_add: Box::new(|_| Err("No config file path".to_string())),
            rewrite_delete: Box::new(|_| Err("No config file path".to_string())),
            services_catalog: Box::new(|| "{\"services\":[]}".to_string()),
            access_list: Box::new(|| {
                "{\"allowed\":[],\"blocked\":[],\"refused_domains\":[]}".to_string()
            }),
            tls_status: Box::new(|| "{\"configured\":false}".to_string()),
            tls_validate: Box::new(|| Err("No TLS certificate is configured".to_string())),
            tls_configure: Box::new(|_| Err("No config file path".to_string())),
            tls_revocation_check: Box::new(|_| Err("Certificate chain not found".to_string())),
            acme_issue: Box::new(
                |_| Err("ACME certificate issuance is not configured".to_string()),
            ),
            tokens_list: Box::new(|| "{\"tokens\":[]}".to_string()),
            token_add: Box::new(|_| Err("No config file path".to_string())),
            token_delete: Box::new(|_| Err("No config file path".to_string())),
            config_rollback: Box::new(|| Err("No previous config to roll back to".to_string())),
            policy_simulate: Box::new(|_| "{\"action\":\"continue\"}".to_string()),
            zones_list: Box::new(|| "[]".to_string()),
            zone_get: Box::new(|_| Err("Authoritative DNS is not available".to_string())),
            zone_put: Box::new(|_, _| Err("Authoritative DNS is not available".to_string())),
            zone_delete: Box::new(|_| Err("Authoritative DNS is not available".to_string())),
            zone_record_add: Box::new(|_, _| Err("Authoritative DNS is not available".to_string())),
            zone_record_delete: Box::new(|_, _| {
                Err("Authoritative DNS is not available".to_string())
            }),
            zone_dnssec: Box::new(|_| Err("Authoritative DNS is not available".to_string())),
            config_desired: Box::new(|| "{}".to_string()),
            config_effective: Box::new(|| "{}".to_string()),
            config_status: Box::new(|| "{\"in_sync\":true,\"changed_keys\":[]}".to_string()),
            config_reload: Box::new(|| Ok("{\"accepted\":true}".to_string())),
            plugins_metrics: Box::new(|| "[]".to_string()),
            filter_report: Box::new(|| {
                "{\"rules_total\":0,\"rules_applied\":0,\"rules_skipped\":0}".to_string()
            }),
            filter_top_rules: Box::new(|| "{\"enabled\":false,\"top\":[]}".to_string()),
            filter_sources: Box::new(|| "{\"hits_enabled\":false,\"sources\":[]}".to_string()),
            subscriptions_list: Box::new(|| {
                "{\"urls\":[],\"count\":0,\"block_domains\":0}".to_string()
            }),
            subscription_add: Box::new(|_| {
                Err("Blocklist subscriptions are not available".to_string())
            }),
            subscription_remove: Box::new(|_| {
                Err("Blocklist subscriptions are not available".to_string())
            }),
            subscription_update: Box::new(|_| {
                Err("Blocklist subscriptions are not available".to_string())
            }),
            subscription_refresh: Box::new(|_| {
                Err("Blocklist subscriptions are not available".to_string())
            }),
            filter_rules_list: Box::new(|| {
                "{\"block\":[],\"allow\":[],\"refused_domains\":[]}".to_string()
            }),
            filter_rule_mutate: Box::new(|_, _| Err("Filtering is not available".to_string())),
            clients_list: Box::new(|| "[]".to_string()),
            upstreams_list: Box::new(|| "[]".to_string()),
            jobs_list: Box::new(|| "[]".to_string()),
            job_get: Box::new(|_| Err("Job not found".to_string())),
            job_refresh: Box::new(|| "{\"id\":0,\"status\":\"running\"}".to_string()),
            dhcp_leases: Box::new(|| "{\"v4\":[],\"v6\":[]}".to_string()),
            dhcp_lease_put: Box::new(|_| Err("DHCP is not configured".to_string())),
            dhcp_static_list: Box::new(|| "{\"available\":false,\"reservations\":[]}".to_string()),
            dhcp_static_add: Box::new(|_| Err("DHCP is not configured".to_string())),
            dhcp_static_remove: Box::new(|_| Err("DHCP is not configured".to_string())),
            client_add: Box::new(|_| Err("No config file path".to_string())),
            client_remove: Box::new(|_| Err("No config file path".to_string())),
            client_update: Box::new(|_| Err("No config file path".to_string())),
            password_change: Box::new(|_, _| Err("No config file path".to_string())),
            user_create: Box::new(|_, _| Err("No config file path".to_string())),
            upstream_add: Box::new(|_| Err("No config file path".to_string())),
            upstream_remove: Box::new(|_| Err("No config file path".to_string())),
            explain: Box::new(|_| "{\"decision\":\"continue\"}".to_string()),
            cluster_status: Box::new(|| {
                "{\"self\":{\"id\":null,\"role\":\"standalone\",\"backend\":\"unknown\",\"listeners\":0,\"leader\":null,\"term\":null,\"commit_index\":null,\"last_applied\":null,\"last_index\":null,\"snapshot_index\":null,\"retained_log_entries\":null,\"fatal\":null,\"healthy\":true,\"version\":null},\"peers\":[]}".to_string()
            }),
            cluster_propose: Box::new(|_| {
                Err("Raft high availability is not configured".to_string())
            }),
            cluster_write: Box::new(|_, _, _, dispatch| dispatch()),
            listeners_status: Box::new(|| "[]".to_string()),
            net_adapters: Box::new(|| {
                Err("Listing network adapters is not supported on this OS".to_string())
            }),
            firewall_set: Box::new(|_| {
                Err("Changing firewall settings is not supported on this OS".to_string())
            }),
            dns_client_set: Box::new(|_| {
                Err("Changing the system DNS server is not supported on this OS".to_string())
            }),
            dns_client_restore: Box::new(|_| {
                Err("Restoring system DNS settings is not supported on this OS".to_string())
            }),
            resolve_probe: Box::new(|_| Err("No DNS listen address".to_string())),
            boot_service_status: Box::new(|| {
                "{\"supported\":false,\"installed\":false,\"running\":false}".to_string()
            }),
            boot_service_set: Box::new(|_| {
                Err("Installing a boot service is not supported on this OS".to_string())
            }),
            update_status: Box::new(|| {
                "{\"participating\":false,\"reason\":\"Updates are not available\"}".to_string()
            }),
            update_check: Box::new(|| Err("Updates are not available".to_string())),
            update_apply: Box::new(|_| Err("Updates are not available".to_string())),
            update_rollback: Box::new(|| Err("Updates are not available".to_string())),
            metrics_extra: Box::new(String::new),
        }
    }
}

#[derive(Clone, Copy)]
/** @brief 차단·허용 목록의 항목 수. 변경 결과로 돌려준다. */
pub struct ListCounts {
    /** @brief 차단 규칙 수. */
    pub block: usize,
    /** @brief 허용 규칙 수. */
    pub allow: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
/** @brief 접근 권한 등급. */
pub enum Role {
    /** @brief 무엇이든 할 수 있다. */
    Admin,
    /** @brief 보기만 할 수 있다. */
    ReadOnly,
}

impl Role {
    /** @brief 감사 로그에 쓸 이름. */
    fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::ReadOnly => "readonly",
        }
    }

    /**
     * @brief 이 등급이 그 메서드를 쓸 수 있는지.
     * @note 읽기 전용은 GET만 된다. 라우팅이 HEAD를 처리하지 않으므로 여기서도 열지 않는다.
     */
    fn allows(self, method: &str) -> bool {
        self == Role::Admin || method == "GET"
    }
}

#[derive(Clone)]
/** @brief 대시보드 사용자 하나. 비밀번호는 해시로만 갖고 있다. */
pub struct UserCred {
    /** @brief 로그인 이름. */
    pub name: String,
    /** @brief 암호 해시. */
    pub hash: SecretString,
    /** @brief 권한. */
    pub role: Role,
}

#[derive(Clone)]
/** @brief 로그인 세션 하나. */
struct Session {
    /** @brief 이 로그인의 권한. */
    role: Role,
    /** @brief 로그인 이름. */
    name: String,
    /** @brief 이 로그인에 쓴 자격 증명. 암호를 바꾸면 이 로그인만 끊는다. */
    credential_id: String,
    /** @brief 가만히 두면 이때 끊긴다. */
    idle_expires_ms: u64,
    /** @brief 쓰고 있어도 이때는 끊긴다. */
    absolute_expires_ms: u64,
}

#[derive(Clone, Default)]
/** @brief 세션 저장소. 세대가 바뀌어도 살아남아 로그인이 풀리지 않는다. */
pub struct SessionStore(Arc<Mutex<std::collections::HashMap<[u8; 32], Session>>>);

/** @brief 세션 저장소의 사본. 설정 적용이 실패했을 때 되돌리는 데 쓴다. */
pub struct SessionCheckpoint(std::collections::HashMap<[u8; 32], Session>);

impl SessionStore {
    /** @brief 지금 세션 상태를 떠 둔다. */
    pub fn checkpoint(&self) -> SessionCheckpoint {
        SessionCheckpoint(self.0.lock_recover().clone())
    }

    /** @brief 떠 둔 상태로 되돌린다. */
    pub fn restore(&self, checkpoint: SessionCheckpoint) {
        *self.0.lock_recover() = checkpoint.0;
    }
}

/** @brief 아무 활동이 없을 때 세션이 만료되는 시간. */
const SESSION_IDLE_TTL_MS: u64 = 30 * 60 * 1000;
/** @brief 활동이 있어도 세션이 반드시 만료되는 시간. */
const SESSION_ABSOLUTE_TTL_MS: u64 = 24 * 60 * 60 * 1000;
/** @brief 전체 세션 수 상한. */
const MAX_SESSIONS: usize = 1024;
/** @brief 사용자 한 명이 가질 수 있는 세션 수. */
const MAX_USER_SESSIONS: usize = 8;
/** @brief 로그인 실패를 세는 구간. */
const LOGIN_WINDOW_MS: u64 = 5 * 60 * 1000;
/** @brief 실패가 쌓였을 때 막아 두는 시간. */
const LOGIN_BLOCK_MS: u64 = 15 * 60 * 1000;
/** @brief 사용자별 실패 허용 횟수. */
const MAX_LOGIN_FAILURES: u32 = 8;

/** @brief 출발지별 실패 허용 횟수. 사용자 이름을 바꿔 가며 시도하는 것을 막는다. */
const MAX_SOURCE_LOGIN_FAILURES: u32 = 40;

/**
 * @brief 리버스 프록시 하나를 거친 로그인 실패를 쉬지 않고 받는 횟수.
 * @details 프록시 뒤의 출발지는 X-Forwarded-For가 알려 준다. 프록시와 같은 컴퓨터의 다른
 *          프로그램도 이 헤더를 꾸며 보낼 수 있으므로 프록시 단위로도 제한한다. 다만 오래
 *          막으면 공격자 하나가 프록시 뒤의 모든 관리자를 막으므로, 막지 않고 속도만 늦춘다.
 *          출발지 하나의 한도보다 커서, 출발지 하나가 한도를 다 써도 다른 관리자는 늦춰지지
 *          않는다.
 */
const PROXY_LOGIN_FAILURE_BURST: u64 = 2 * MAX_SOURCE_LOGIN_FAILURES as u64;

/** @brief 몰아서 받는 횟수를 다 쓴 뒤 프록시를 거친 로그인 실패를 하나 더 받기까지의 간격. */
const PROXY_LOGIN_FAILURE_INTERVAL_MS: u64 = 1000;
/** @brief 실패 기록을 담을 항목 수 상한. */
const MAX_LOGIN_ATTEMPT_KEYS: usize = 4096;
/** @brief 요청 첫 줄의 길이 상한. */
const MAX_REQUEST_LINE: usize = 8 * 1024;
/** @brief 헤더 한 줄의 길이 상한. */
const MAX_HEADER_LINE: usize = 16 * 1024;
/** @brief 헤더 전체의 길이 상한. */
const MAX_HEADER_BYTES: usize = 64 * 1024;
/** @brief 헤더 줄 수 상한. */
const MAX_HEADERS: usize = 100;
/** @brief 본문 길이 상한. */
const MAX_REQUEST_BODY: usize = 1024 * 1024;
/** @brief admission이 헤더 종결을 찾을 때 보관하는 최대 바이트. */
const CONTROL_ADMISSION_HEADER_BYTES: usize = MAX_REQUEST_LINE + MAX_HEADER_BYTES + 4;
/** @brief admission이 한 번에 읽는 임시 버퍼 크기. */
const CONTROL_ADMISSION_READ_BYTES: usize = 16 * 1024;
/** @brief 보류 연결을 다시 확인하는 간격. */
const CONTROL_ADMISSION_POLL_MS: u64 = 10;
/** @brief 진전 없는 보류 연결을 다시 확인하는 최대 간격. */
const CONTROL_ADMISSION_MAX_BACKOFF_MS: u64 = 250;
/** @brief 인증 전 요청 원문이 프로세스 전체에서 차지할 수 있는 최대치. */
const MAX_CONTROL_ADMISSION_BYTES: usize = 8 * 1024 * 1024;

/** @brief 로그인 실패 기록 하나. */
struct LoginAttempt {
    /** @brief 지금 세고 있는 구간이 시작한 시각. */
    window_start_ms: u64,
    /** @brief 이 구간에서 틀린 횟수. */
    failures: u32,
    /** @brief 이 시각까지는 아예 받지 않는다. */
    blocked_until_ms: u64,
}

/**
 * @brief 로그인 시도 결과.
 * @note 자격증명 불일치와 처리 포화를 구분한다. 합치면 정상 사용자가 남의 부하 때문에
 *       비밀번호가 틀렸다는 답을 받는다.
 */
enum LoginResult {
    /** @brief 맞았다. 로그인 이름, 권한, 자격 증명. */
    Success(String, Role, String),
    /** @brief 틀렸다. */
    Invalid,
    /** @brief 너무 자주 틀려 잠시 받지 않는다. */
    Busy,
}

#[derive(Default)]
/**
 * @brief 인증 상태. 토큰과 세션 두 가지를 함께 다룬다.
 * @details 토큰은 설정에 적힌 고정값이고, 세션은 로그인으로 발급된다. 어느 쪽이든
 *          같은 등급 체계로 수렴한다.
 */
pub struct Auth {
    /** @brief 무엇이든 할 수 있는 토큰들의 키드 지문. 원문은 보관하지 않는다. */
    admin: Mutex<Vec<[u8; 32]>>,
    /** @brief 보기만 할 수 있는 토큰들의 키드 지문. 원문은 보관하지 않는다. */
    readonly: Mutex<Vec<[u8; 32]>>,
    /** @brief 로그인할 수 있는 사용자들. */
    users: Mutex<Vec<UserCred>>,
    /** @brief 지금 열린 로그인들. */
    sessions: SessionStore,
    /** @brief 주소별 로그인 실패 기록. */
    login_attempts: Mutex<std::collections::HashMap<String, LoginAttempt>>,

    /**
     * @brief 리버스 프록시별 로그인 실패 속도 기록. 값은 다음 실패를 쉬지 않고 받을 수 있게
     *        되는 시각(밀리초)이다.
     */
    proxy_login_pace: Mutex<std::collections::HashMap<String, u64>>,

    /** @brief 첫 관리자 계정을 만들 때 요구하는 일회용 설정 코드. 계정을 만들면 지운다. */
    setup_code: Mutex<Option<SetupCode>>,
}

/** @brief 일회용 설정 코드. */
struct SetupCode {
    /** @brief 코드의 키드 지문. 원문은 보관하지 않는다. */
    digest: [u8; 32],
    /** @brief 코드를 적어 둔 파일 경로. 설정 화면에 보여 준다. */
    file: String,
}

impl Auth {
    /** @brief 관리자 토큰 하나로 만든다. */
    pub fn single_admin(token: SecretString) -> Self {
        let admin = if token.is_empty() {
            vec![]
        } else {
            vec![credential_digest("token", &[token.as_str()])]
        };
        Auth {
            admin: Mutex::new(admin),
            ..Default::default()
        }
    }

    /** @brief 관리자와 읽기 전용 토큰 목록으로 만든다. */
    pub fn new(admin: Vec<SecretString>, readonly: Vec<SecretString>) -> Self {
        let f = |v: Vec<SecretString>| {
            v.into_iter()
                .filter(|token| !token.is_empty())
                .map(|token| credential_digest("token", &[token.as_str()]))
                .collect()
        };
        Auth {
            admin: Mutex::new(f(admin)),
            readonly: Mutex::new(f(readonly)),
            ..Default::default()
        }
    }

    /** @brief 대시보드 사용자를 등록한다. */
    pub fn with_users(mut self, users: Vec<UserCred>) -> Self {
        self.users = Mutex::new(users);
        self
    }

    /**
     * @brief 등록된 계정 목록을 설정 파일 내용으로 맞춘다.
     *
     * @details 계정은 DNS 처리와 아무 관계가 없으므로 계정만 바뀌었을 때 DNS를 다시
     *          시작할 이유가 없다. 설정 파일이 밖에서 바뀐 경우에도 이 자리에서 맞춰야
     *          새 계정이 재시작 없이 곧바로 로그인할 수 있다.
     * @note 사라진 계정의 세션은 세션 정합 검사가 걷어 간다.
     */
    /**
     * @brief 제어 토큰 목록을 교체한다.
     *
     * @details 지운 토큰으로 열려 있던 세션은 곧바로 끊긴다. 이것이 없으면 토큰을 지워도
     *          그 토큰으로 만든 세션이 남아 계속 들어온다.
     */
    pub fn replace_tokens(&self, admin: Vec<SecretString>, readonly: Vec<SecretString>) {
        let digest = |tokens: Vec<SecretString>| {
            tokens
                .into_iter()
                .filter(|token| !token.is_empty())
                .map(|token| credential_digest("token", &[token.as_str()]))
                .collect()
        };
        *self.admin.lock_recover() = digest(admin);
        *self.readonly.lock_recover() = digest(readonly);
        self.reconcile_sessions();
    }

    /** @brief 대시보드 사용자 목록을 교체한다. */
    pub fn replace_users(&self, users: Vec<UserCred>) {
        *self.users.lock_recover() = users;
        self.reconcile_sessions();
    }

    /** @brief 기존 세션 저장소를 물려받는다. 재적용에도 로그인이 유지된다. */
    pub fn with_sessions(mut self, sessions: SessionStore) -> Self {
        self.sessions = sessions;
        self.reconcile_sessions();
        self
    }

    /**
     * @brief 설정이 바뀐 뒤 세션을 정리한다.
     * @details 자격증명이 사라졌거나 바뀐 사용자의 세션은 버린다. 남겨 두면 지운 계정으로
     *          계속 접근할 수 있다.
     */
    fn reconcile_sessions(&self) {
        let now = now_ms();
        let users = self.users.lock_recover().clone();
        let mut valid = std::collections::HashMap::<String, Role>::new();
        for digest in self.admin.lock_recover().iter() {
            valid.insert(
                credential_fingerprint_from_digest("token", digest),
                Role::Admin,
            );
        }
        for digest in self.readonly.lock_recover().iter() {
            valid.insert(
                credential_fingerprint_from_digest("token", digest),
                Role::ReadOnly,
            );
        }
        for user in &users {
            valid.insert(user_credential_id(user), user.role);
        }
        self.sessions.0.lock_recover().retain(|_, session| {
            session.idle_expires_ms > now
                && session.absolute_expires_ms > now
                && valid.get(&session.credential_id) == Some(&session.role)
        });
    }

    /** @brief 대시보드 사용자가 등록돼 있는지. */
    pub fn has_users(&self) -> bool {
        !self.users.lock_recover().is_empty()
    }

    /**
     * @brief 첫 관리자 계정을 만들 때 요구할 일회용 설정 코드를 정한다.
     * @details 루프백에 접속할 수 있다고 해서 설정 파일을 고칠 권한이 있는 것은 아니다. 여러
     *          사람이 쓰는 컴퓨터에서는 다른 사용자의 프로그램도 루프백에 접속한다. 그래서 설정
     *          파일 옆의 파일을 읽을 수 있는 사람만 아는 코드를 요구한다.
     * @param file 코드를 적어 둔 파일 경로.
     */
    pub fn set_setup_code(&self, code: &str, file: String) {
        *self.setup_code.lock_recover() = Some(SetupCode {
            digest: credential_digest("setup", &[code]),
            file,
        });
    }

    /** @brief 설정 코드를 지운다. 계정을 만들었거나 코드를 둘 곳이 없을 때 부른다. */
    pub fn clear_setup_code(&self) {
        *self.setup_code.lock_recover() = None;
    }

    /** @brief 설정 코드가 맞는지. 비교는 상수 시간이다. 코드가 없으면 언제나 틀리다. */
    fn setup_code_matches(&self, offered: &str) -> bool {
        let digest = credential_digest("setup", &[offered]);
        self.setup_code
            .lock_recover()
            .as_ref()
            .is_some_and(|code| ct_eq(&digest, &code.digest))
    }

    /** @brief 설정 코드를 적어 둔 파일 경로. 코드가 없으면 없다. */
    fn setup_code_file(&self) -> Option<String> {
        self.setup_code
            .lock_recover()
            .as_ref()
            .map(|code| code.file.clone())
    }

    /** @brief 이 토큰의 등급. 비교는 상수 시간이다. */
    fn role_for(&self, token: &str) -> Option<Role> {
        if token.is_empty() {
            return None;
        }
        let digest = credential_digest("token", &[token]);
        if self
            .admin
            .lock_recover()
            .iter()
            .any(|value| ct_eq(&digest, value))
        {
            return Some(Role::Admin);
        }
        if self
            .readonly
            .lock_recover()
            .iter()
            .any(|value| ct_eq(&digest, value))
        {
            return Some(Role::ReadOnly);
        }
        None
    }

    /**
     * @brief 토큰이나 세션에서 등급을 정한다.
     * @details 베어러 토큰을 보냈으면 그 토큰으로만 판정하고, 틀리면 세션이 맞아도 인증되지
     *          않는다. 세션으로 넘어가면 CSRF 검사는 베어러 요청으로 보고 건너뛰는데 실제
     *          권한은 쿠키에서 나온다.
     */
    fn resolve(&self, bearer: &str, session: &str) -> Option<Role> {
        if bearer.is_empty() {
            self.role_for_session(session)
        } else {
            self.role_for(bearer)
        }
    }

    /** @brief 세션 토큰의 등급. 만료됐으면 없다. */
    fn role_for_session(&self, token: &str) -> Option<Role> {
        if token.is_empty() {
            return None;
        }
        let now = now_ms();
        let mut map = self.sessions.0.lock_recover();

        map.retain(|_, s| s.idle_expires_ms > now && s.absolute_expires_ms > now);
        let digest = credential_digest("session", &[token]);
        let s = map.get_mut(&digest)?;
        s.idle_expires_ms = now
            .saturating_add(SESSION_IDLE_TTL_MS)
            .min(s.absolute_expires_ms);
        Some(s.role)
    }

    /**
     * @brief 새 세션을 발급한다.
     * @note 사용자별 세션 수와 전체 수에 상한이 있다. 넘으면 오래된 것부터 버린다.
     */
    fn issue_session(&self, role: Role, name: String, credential_id: String) -> String {
        let token = crate::password::new_session_token();
        let token_digest = credential_digest("session", &[&token]);
        let now = now_ms();
        let mut sessions = self.sessions.0.lock_recover();
        sessions.retain(|_, session| {
            session.idle_expires_ms > now && session.absolute_expires_ms > now
        });
        let mut own: Vec<([u8; 32], u64)> = sessions
            .iter()
            .filter(|(_, session)| session.name == name)
            .map(|(key, session)| (*key, session.absolute_expires_ms))
            .collect();
        own.sort_by_key(|(_, expires)| *expires);
        while own.len() >= MAX_USER_SESSIONS {
            if let Some((key, _)) = own.first().copied() {
                sessions.remove(&key);
                own.remove(0);
            } else {
                break;
            }
        }
        while sessions.len() >= MAX_SESSIONS {
            let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, session)| session.absolute_expires_ms)
                .map(|(key, _)| *key)
            else {
                break;
            };
            sessions.remove(&oldest);
        }
        sessions.insert(
            token_digest,
            Session {
                role,
                name,
                credential_id,
                idle_expires_ms: now.saturating_add(SESSION_IDLE_TTL_MS),
                absolute_expires_ms: now.saturating_add(SESSION_ABSOLUTE_TTL_MS),
            },
        );
        token
    }

    /**
     * @brief 사용자 이름과 비밀번호로 로그인한다.
     * @warning 사용자가 없을 때도 해시 검증을 한 번 돌린다. 그러지 않으면 걸린 시간으로
     *          존재하는 계정 이름을 알아낼 수 있다.
     */
    fn login(&self, name: &str, password: &str) -> LoginResult {
        let user = {
            let users = self.users.lock_recover();
            users.iter().find(|u| u.name == name).cloned()
        };
        let verified = match &user {
            Some(u) => crate::password::verify_password_result(password, &u.hash),
            None => crate::password::verify_password_result(
                password,
                "pbkdf2-sha256$600000$00000000000000000000000000000000$\
                     0000000000000000000000000000000000000000000000000000000000000000",
            ),
        };
        match verified {
            crate::password::VerifyResult::Busy => return LoginResult::Busy,
            crate::password::VerifyResult::Mismatch => return LoginResult::Invalid,
            crate::password::VerifyResult::Match => {}
        }
        let Some(user) = user else {
            return LoginResult::Invalid;
        };
        let credential_id = user_credential_id(&user);
        let token = self.issue_session(user.role, user.name.clone(), credential_id);
        LoginResult::Success(token, user.role, user.name)
    }

    /** @brief 출발지별 실패 기록의 키. */
    fn login_source_bucket(source: &str) -> String {
        format!("src\u{1f}{source}")
    }

    /** @brief 출발지와 사용자를 묶은 실패 기록의 키. */
    fn login_user_bucket(source: &str, user: &str) -> String {
        format!("user\u{1f}{source}\u{1f}{user}")
    }

    /**
     * @brief 지금 이 출발지와 사용자가 시도할 수 없으면, 다시 시도할 수 있을 때까지의 초.
     * @param proxy 리버스 프록시를 거쳐 왔으면 그 프록시의 주소.
     */
    fn login_retry_after(&self, source: &str, proxy: Option<&str>, user: &str) -> Option<u64> {
        let now = now_ms();
        let mut attempts = self.login_attempts.lock_recover();
        attempts.retain(|_, attempt| {
            attempt.blocked_until_ms > now
                || now.saturating_sub(attempt.window_start_ms) <= LOGIN_WINDOW_MS
        });
        let blocked_until = [
            Self::login_source_bucket(source),
            Self::login_user_bucket(source, user),
        ]
        .iter()
        .filter_map(|key| attempts.get(key))
        .map(|attempt| attempt.blocked_until_ms)
        .max()
        .unwrap_or(0);
        drop(attempts);
        let paced_until = proxy.map_or(0, |proxy| {
            let next = self
                .proxy_login_pace
                .lock_recover()
                .get(proxy)
                .copied()
                .unwrap_or(0);
            next.saturating_sub((PROXY_LOGIN_FAILURE_BURST - 1) * PROXY_LOGIN_FAILURE_INTERVAL_MS)
        });
        let until = blocked_until.max(paced_until);
        (until > now).then(|| (until - now).div_ceil(1000))
    }

    #[cfg(test)]
    /** @brief 지금 이 출발지와 사용자가 시도할 수 있는지. */
    fn login_allowed(&self, source: &str, proxy: Option<&str>, user: &str) -> bool {
        self.login_retry_after(source, proxy, user).is_none()
    }

    /**
     * @brief 시도 결과를 기록한다. 성공하면 그 사용자의 실패 기록만 지운다.
     * @note 출발지와 프록시 단위의 기록은 성공해도 지우지 않는다. 지우면 자기 계정으로 한 번
     *       로그인할 때마다 다른 계정을 추측할 횟수가 다시 채워진다.
     */
    fn record_login_result(&self, source: &str, proxy: Option<&str>, user: &str, success: bool) {
        let mut attempts = self.login_attempts.lock_recover();
        if success {
            attempts.remove(&Self::login_user_bucket(source, user));
            return;
        }
        let now = now_ms();
        for (key, limit) in [
            (Self::login_user_bucket(source, user), MAX_LOGIN_FAILURES),
            (Self::login_source_bucket(source), MAX_SOURCE_LOGIN_FAILURES),
        ] {
            Self::record_login_failure(&mut attempts, key, limit, now);
        }
        drop(attempts);
        if let Some(proxy) = proxy {
            Self::pace_proxy_failure(&mut self.proxy_login_pace.lock_recover(), proxy, now);
        }
    }

    /**
     * @brief 프록시 하나의 다음 허용 시각을 한 간격 뒤로 민다.
     * @details 다음 허용 시각이 이미 지난 항목은 없는 항목과 같게 동작하므로 지운다. 신뢰하는
     *          프록시 대역이 127.0.0.0/8처럼 넓으면 같은 컴퓨터의 프로그램이 출발 주소를 바꿔
     *          항목을 끝없이 만들 수 있어서 항목 수에도 상한을 두고, 넘치면 가장 먼저 풀리는
     *          항목을 버린다.
     */
    fn pace_proxy_failure(
        pace: &mut std::collections::HashMap<String, u64>,
        proxy: &str,
        now: u64,
    ) {
        pace.retain(|_, next| *next > now);
        if !pace.contains_key(proxy) && pace.len() >= MAX_LOGIN_ATTEMPT_KEYS {
            if let Some(soonest) = pace
                .iter()
                .min_by_key(|(_, next)| **next)
                .map(|(key, _)| key.clone())
            {
                pace.remove(&soonest);
            }
        }
        let next = pace.entry(proxy.to_string()).or_insert(0);
        *next = (*next).max(now) + PROXY_LOGIN_FAILURE_INTERVAL_MS;
    }

    /** @brief 실패를 기록한다. 항목 수가 상한을 넘으면 오래된 것부터 버린다. */
    fn record_login_failure(
        attempts: &mut std::collections::HashMap<String, LoginAttempt>,
        key: String,
        limit: u32,
        now: u64,
    ) {
        if !attempts.contains_key(&key) && attempts.len() >= MAX_LOGIN_ATTEMPT_KEYS {
            if let Some(oldest) = attempts
                .iter()
                .min_by_key(|(_, attempt)| attempt.window_start_ms)
                .map(|(key, _)| key.clone())
            {
                attempts.remove(&oldest);
            }
        }
        let attempt = attempts.entry(key).or_insert(LoginAttempt {
            window_start_ms: now,
            failures: 0,
            blocked_until_ms: 0,
        });
        if now.saturating_sub(attempt.window_start_ms) > LOGIN_WINDOW_MS {
            attempt.window_start_ms = now;
            attempt.failures = 0;
            attempt.blocked_until_ms = 0;
        }
        attempt.failures = attempt.failures.saturating_add(1);
        if attempt.failures >= limit {
            attempt.blocked_until_ms = now.saturating_add(LOGIN_BLOCK_MS);
        }
    }

    /** @brief 세션 주인의 이름. 감사 로그에 쓴다. */
    fn session_name(&self, token: &str) -> Option<String> {
        let digest = credential_digest("session", &[token]);
        self.sessions
            .0
            .lock_recover()
            .get(&digest)
            .map(|s| s.name.clone())
    }

    /** @brief 비밀번호를 검증한다. 포화 여부까지 구분해 돌려준다. */
    fn verify_user(&self, name: &str, password: &str) -> crate::password::VerifyResult {
        let hash = {
            let users = self.users.lock_recover();
            users
                .iter()
                .find(|user| user.name == name)
                .map(|user| user.hash.clone())
        };
        hash.as_deref()
            .map(|stored| crate::password::verify_password_result(password, stored))
            .unwrap_or(crate::password::VerifyResult::Mismatch)
    }

    /**
     * @brief 방금 만든 계정의 세션을 연다.
     *
     * @details 비밀번호를 다시 검증하지 않는다. 같은 요청에서 이 서버가 저장한 값이라 확인할
     *          것이 없고, 키 파생 곳이 차 있으면 멀쩡한 계정으로도 로그인이 실패한다.
     * @return 세션 토큰과 권한. 그 사이 계정이 사라졌으면 None.
     */
    fn start_session_for(&self, name: &str) -> Option<(String, Role)> {
        let user = {
            let users = self.users.lock_recover();
            users.iter().find(|user| user.name == name).cloned()
        }?;
        let credential_id = user_credential_id(&user);
        let token = self.issue_session(user.role, user.name.clone(), credential_id);
        Some((token, user.role))
    }

    /**
     * @brief 계정이 하나도 없을 때만 첫 관리자를 등록한다.
     *
     * @details 검사와 등록을 같은 잠금 안에서 해야 두 요청이 동시에 들어와도 관리자가
     *          둘 생기지 않는다.
     * @return 등록했으면 true. 이미 계정이 있으면 false.
     */
    fn add_first_user(&self, name: String, hash: String) -> bool {
        let mut users = self.users.lock_recover();
        if !users.is_empty() {
            return false;
        }
        users.push(UserCred {
            name,
            hash: hash.into(),
            role: Role::Admin,
        });
        true
    }

    /** @brief 사용자의 비밀번호 해시를 교체한다. */
    fn update_user_hash(&self, name: &str, hash: String) -> bool {
        let mut users = self.users.lock_recover();
        let Some(user) = users.iter_mut().find(|u| u.name == name) else {
            return false;
        };
        user.hash = hash.into();
        true
    }

    /** @brief 이 사용자의 세션을 전부 버린다. 비밀번호를 바꾸면 부른다. */
    fn revoke_user_sessions(&self, name: &str) {
        self.sessions
            .0
            .lock_recover()
            .retain(|_, session| session.name != name);
    }

    /** @brief 세션 하나를 버린다. */
    fn logout(&self, token: &str) {
        if !token.is_empty() {
            let digest = credential_digest("session", &[token]);
            self.sessions.0.lock_recover().remove(&digest);
        }
    }
}

/** @brief 메서드에서 감사 로그의 동작 이름을 정한다. */
fn audit_action(method: &str) -> &'static str {
    match method {
        "POST" => "create_or_run",
        "PUT" => "replace",
        "PATCH" => "update",
        "DELETE" => "delete",
        _ => "read",
    }
}

/** @brief 감사 로그에 남길 신원. 비어 있으면 대체 값을 쓴다. */
fn audit_identity(value: &str, fallback: &str) -> String {
    let cleaned: String = value
        .chars()
        .filter(|character| !character.is_control())
        .take(80)
        .collect();
    if cleaned.trim().is_empty() {
        fallback.to_string()
    } else {
        cleaned
    }
}

/**
 * @brief 자격증명의 지문. 감사 로그에 남긴다.
 * @warning 원본을 남기지 않는다. 로그가 새면 그것으로 바로 접근할 수 있게 된다.
 */
fn credential_digest(prefix: &str, parts: &[&str]) -> [u8; 32] {
    /** @brief 서명에 쓰는 요약 함수. */
    type HmacSha256 = Hmac<Sha256>;
    /** @brief 이 프로세스의 서명 키. */
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    let key = KEY.get_or_init(onetdns_core::random_array::<32>);
    let mut hasher = HmacSha256::new_from_slice(key).expect("HMAC-SHA-256 key length is valid");
    hasher.update(prefix.as_bytes());
    for part in parts {
        hasher.update(&[0]);
        hasher.update(part.as_bytes());
    }
    hasher.finalize().into_bytes().into()
}

/** @brief 자격증명 지문을 감사 로그용 짧은 문자열로 바꾼다. */
fn credential_fingerprint_from_digest(prefix: &str, digest: &[u8; 32]) -> String {
    /** @brief 16진 문자표. */
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut id = String::with_capacity(prefix.len() + 21);
    id.push_str(prefix);
    id.push('-');
    for byte in digest.iter().take(10) {
        id.push(HEX[(byte >> 4) as usize] as char);
        id.push(HEX[(byte & 0x0f) as usize] as char);
    }
    id
}

/** @brief 자격증명을 키드 지문으로 만든 뒤 감사 로그용으로 줄인다. */
fn credential_fingerprint(prefix: &str, parts: &[&str]) -> String {
    credential_fingerprint_from_digest(prefix, &credential_digest(prefix, parts))
}

/** @brief 사용자 자격증명의 식별자. 비밀번호가 바뀌면 달라진다. */
fn user_credential_id(user: &UserCred) -> String {
    credential_fingerprint(
        "user",
        &[&user.name, user.role.as_str(), user.hash.as_str()],
    )
}

/** @brief 토큰 사용자의 감사 로그 표기. */
fn bearer_actor(token: &str) -> String {
    credential_fingerprint("token", &[token])
}

/** @brief 이 요청을 누가 보냈는지 감사 로그용으로 정리한다. */
fn audit_actor(auth: &Auth, bearer: &str, session: &str) -> String {
    if !bearer.is_empty() {
        return if auth.role_for(bearer).is_some() {
            bearer_actor(bearer)
        } else {
            "anonymous".to_string()
        };
    }
    match auth.session_name(session) {
        Some(name) if !session.is_empty() => audit_identity(&name, "authenticated-user"),
        _ => "anonymous".to_string(),
    }
}

/**
 * @brief 감사 로그에 남길 요청 요약.
 * @warning 본문에 비밀번호나 토큰이 들어 있을 수 있다. 그대로 남기지 않고 걸러 낸다.
 */
fn audit_request_detail(method: &str, path: &str, body: &str) -> String {
    if method == "GET" || body.trim().is_empty() {
        return String::new();
    }
    let mut parts = Vec::new();
    if let Ok(json::Json::Obj(fields)) = json::parse(body) {
        let mut keys: Vec<&str> = fields.iter().map(|(key, _)| key.as_str()).collect();
        keys.sort_unstable();
        keys.dedup();
        if !keys.is_empty() {
            /* 진단 요청의 본문은 바꾼 설정이 아니다. 같은 이름으로 남기면 조사 기록이 변경 기록처럼 읽힌다. */
            let label = if is_state_changing_request(method, path) {
                "changed_keys"
            } else {
                "request_keys"
            };
            parts.push(format!("{label}={}", keys.join(",")));
        }

        /** @brief 이 이름들만 대상으로 받는다. 아무 항목이나 받으면 남의 설정을 건드리게 된다. */
        const SAFE_TARGETS: [&str; 7] = ["name", "id", "service", "kind", "mac", "adapter", "port"];
        for target in SAFE_TARGETS {
            let Some(value) = fields
                .iter()
                .find(|(key, _)| key == target)
                .map(|(_, value)| value)
            else {
                continue;
            };
            let text = match value {
                json::Json::Str(value) => value.clone(),
                json::Json::Num(value) => value.to_string(),
                json::Json::Bool(value) => value.to_string(),
                _ => continue,
            };
            let shortened: String = text.chars().take(160).collect();
            parts.push(format!("{target}={shortened}"));
        }
    } else {
        parts.push(format!("body_bytes={}", body.len()));
    }
    if path.starts_with("/v1/config") && parts.is_empty() {
        parts.push(format!("body_bytes={}", body.len()));
    }
    parts.join(" ")
}

/** @brief 감사 기록 하나. */
struct AuditEntry {
    /** @brief 이 일이 일어난 시각. */
    ts_ms: u64,
    /** @brief 누가 했는지. */
    actor: String,
    /** @brief 그 권한. */
    role: &'static str,
    /** @brief 요청 방식. */
    method: String,
    /** @brief 무엇을 했는지. */
    action: &'static str,
    /** @brief 요청한 경로. */
    path: String,
    /** @brief 어디서 왔는지. */
    peer: String,
    /** @brief 덧붙일 내용. */
    detail: String,
    /** @brief 응답 상태. */
    status: u16,
}

/** @brief 감사 기록을 만들 때 필요한 문맥. */
struct AuditContext<'a> {
    /** @brief 이 요청의 권한. */
    role: &'static str,
    /** @brief 누가 했는지. */
    actor: &'a str,
    /** @brief 요청 방식. */
    method: &'a str,
    /** @brief 요청한 경로. */
    path: &'a str,
    /** @brief 어디서 왔는지. */
    peer: &'a str,
    /** @brief 응답 상태. */
    status: u16,
}

#[derive(Clone)]
/** @brief 최근 감사 기록. 크기가 정해진 링 버퍼다. */
pub struct AuditLog {
    /** @brief 남겨 둔 기록들. */
    inner: Arc<Mutex<VecDeque<AuditEntry>>>,
    /** @brief 남겨 둘 기록 수. */
    cap: usize,
}

impl AuditLog {
    /** @brief 정해진 크기로 만든다. */
    pub fn new(cap: usize) -> Self {
        AuditLog {
            inner: Arc::new(Mutex::new(VecDeque::new())),
            cap: cap.max(1),
        }
    }
    /** @brief 행위자와 함께 감사 기록을 남긴다. */
    fn record_actor(
        &self,
        role: &'static str,
        actor: &str,
        method: &str,
        path: &str,
        peer: &str,
        status: u16,
    ) {
        self.record_detail(
            AuditContext {
                role,
                actor,
                method,
                path,
                peer,
                status,
            },
            String::new(),
        );
    }

    /** @brief 요청 하나를 감사 기록으로 남긴다. */
    fn record_request_actor(&self, context: AuditContext<'_>, body: &str) {
        let detail = audit_request_detail(context.method, context.path, body);
        self.record_detail(context, detail);
    }

    /** @brief 상세 설명을 붙여 감사 기록을 남긴다. */
    fn record_detail(&self, context: AuditContext<'_>, detail: String) {
        let AuditContext {
            role,
            actor,
            method,
            path,
            peer,
            status,
        } = context;
        let mut q = self.inner.lock_recover();
        if q.len() >= self.cap {
            q.pop_front();
        }
        q.push_back(AuditEntry {
            ts_ms: now_ms(),
            actor: actor.to_string(),
            role,
            method: method.to_string(),
            action: audit_action(method),
            path: path.to_string(),
            peer: peer.to_string(),
            detail: detail.clone(),
            status,
        });
        drop(q);

        // 진단용 POST는 아무것도 바꾸지 않는다. 그것까지 「변경 요청」으로 남기면 조사 한 번에
        // 로그가 수백 줄씩 늘어 정작 진짜 변경이 묻힌다. 감사 기록에는 위에서 이미 담았다.
        if is_state_changing_request(method, path) || status >= 400 {
            // 빈 detail 을 그대로 실으면 읽는 사람이 건너뛰어야 할 빈 칸이 된다.
            let detail: Option<&str> = (!detail.is_empty()).then_some(detail.as_str());
            if status >= 400 {
                // 실패는 요청마다 남기지 않는다. 토큰이 틀린 클라이언트 하나가 초당 수십 번
                // 두드리면 그 로그가 원래 문제보다 더 큰 문제가 된다. 처음과 2의 거듭제곱
                // 번째만 남기고, 몇 번째인지 함께 적어 얼마나 쏟아지는지 알 수 있게 한다.
                let count = repeated_failure_count(method, path, status);
                if should_log_repeated_failure(count) {
                    match detail {
                        Some(detail) => onetdns_core::warn!(
                            event = "control.request_failed",
                            actor, role, method, path, peer, status, count, detail = %detail,
                            "Management API request failed"
                        ),
                        None => onetdns_core::warn!(
                            event = "control.request_failed",
                            actor,
                            role,
                            method,
                            path,
                            peer,
                            status,
                            count,
                            "Management API request failed"
                        ),
                    }
                }
            } else {
                match detail {
                    Some(detail) => onetdns_core::info!(
                        event = "control.mutation",
                        actor, role, method, path, peer, status, detail = %detail,
                        "Handled a management API change request"
                    ),
                    None => onetdns_core::info!(
                        event = "control.mutation",
                        actor,
                        role,
                        method,
                        path,
                        peer,
                        status,
                        "Handled a management API change request"
                    ),
                }
            }
        }
    }
    /** @brief 감사 기록을 JSON으로. */
    fn json(&self) -> String {
        let q = self.inner.lock_recover();
        let items: Vec<String> = q
            .iter()
            .map(|e| {
                format!(
                    "{{\"ts_ms\":{},\"actor\":{},\"role\":{},\"method\":{},\"action\":{},\"path\":{},\"peer\":{},\"detail\":{},\"status\":{}}}",
                    e.ts_ms,
                    json::escape(&e.actor),
                    json::escape(e.role),
                    json::escape(&e.method),
                    json::escape(e.action),
                    json::escape(&e.path),
                    json::escape(&e.peer),
                    json::escape(&e.detail),
                    e.status
                )
            })
            .collect();
        format!("{{\"entries\":[{}]}}", items.join(","))
    }
}

impl Default for AuditLog {
    /** @brief 기본값. */
    fn default() -> Self {
        AuditLog::new(1000)
    }
}

/** @brief 요청이 완성되기 전까지 스레드 없이 보류하는 제어 연결. */
struct PendingControlConnection {
    /** @brief OS 핸들 하나를 공유하는 소켓. */
    stream: SharedTcp,
    /** @brief 로그에 쓸 상대 주소. */
    peer: SocketAddr,
    /** @brief accept 시점부터 계산한 요청 데드라인. */
    deadline: Instant,
    /** @brief admission이 비차단으로 먼저 읽어 둔 요청 바이트. */
    received: Vec<u8>,
    /** @brief 진전 없는 연결을 다시 확인할 가장 이른 시각. */
    next_probe: Instant,
    /** @brief 진전 없는 연결의 재확인 간격. */
    probe_delay: Duration,
    /** @brief 이 연결의 prefix가 예약한 전역 원문 예산. */
    admission_bytes: AdmissionBytesGuard,
    /** @brief 보류 중에도 전체 연결 상한에 포함한다. */
    guard: ActiveConnectionGuard,
}

/** @brief 비차단 admission에서 본 요청 상태. */
enum ControlAdmissionState {
    /** @brief 아직 요청 전체가 도착하지 않았다. */
    Pending,
    /** @brief 기존 파서가 블로킹 없이 읽을 만큼 도착했다. */
    Ready,
    /** @brief 상대가 요청을 완성하지 않고 연결을 닫았다. */
    Closed,
    /** @brief 전역 인증 전 원문 예산이 가득 찼다. */
    Overloaded,
}

/**
 * @brief 완성된 헤더에서 기존 파서가 읽어야 할 총 바이트 수를 구한다.
 * @details 이 함수는 요청을 승인하지 않는다. 단일 정상 Content-Length만 기다리고,
 *          중복·형식 오류·Transfer-Encoding·크기 초과는 헤더까지만 준비됐다고 보아
 *          기존 권위 파서가 즉시 거절하게 한다.
 */
fn control_request_required_bytes(header: &[u8], header_end: usize) -> usize {
    let Ok(text) = std::str::from_utf8(&header[..header_end]) else {
        return header_end;
    };
    let mut content_length = None;
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, raw_value)) = line.split_once(':') else {
            return header_end;
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return header_end;
        }
        if !name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        if content_length.is_some() {
            return header_end;
        }
        let value = raw_value.trim_matches([' ', '\t']);
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return header_end;
        }
        let Ok(length) = value.parse::<usize>() else {
            return header_end;
        };
        if length > MAX_REQUEST_BODY {
            return header_end;
        }
        content_length = Some(length);
    }
    header_end
        .checked_add(content_length.unwrap_or(0))
        .unwrap_or(header_end)
}

/** @brief 소켓 바이트를 비차단으로 받아 요청이 완성됐는지 본다. */
fn control_admission_state(
    pending: &mut PendingControlConnection,
    scratch: &mut [u8],
) -> std::io::Result<ControlAdmissionState> {
    loop {
        let required = if let Some(header_end) = pending
            .received
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
        {
            control_request_required_bytes(&pending.received, header_end)
        } else {
            CONTROL_ADMISSION_HEADER_BYTES
        };
        if pending.received.len() >= required {
            return Ok(ControlAdmissionState::Ready);
        }
        let read_len = (required - pending.received.len()).min(scratch.len());
        let reserved = pending.admission_bytes.reserve(read_len);
        if reserved == 0 {
            return Ok(ControlAdmissionState::Overloaded);
        }
        match pending.stream.read(&mut scratch[..reserved]) {
            Ok(0) => {
                pending.admission_bytes.release(reserved);
                return Ok(ControlAdmissionState::Closed);
            }
            Ok(read) => {
                pending.admission_bytes.release(reserved - read);
                pending.received.extend_from_slice(&scratch[..read]);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                pending.admission_bytes.release(reserved);
                return Ok(ControlAdmissionState::Pending);
            }
            Err(error) => {
                pending.admission_bytes.release(reserved);
                return Err(error);
            }
        }
    }
}

#[derive(Clone)]
/** @brief 컨트롤 플레인 서버가 요청 처리에 쓰는 것 전부. 연결 스레드가 공유한다. */
pub struct AppState {
    /** @brief 지표 저장소. */
    pub stats: Stats,
    /** @brief 인증. */
    pub auth: Arc<Auth>,
    /** @brief 감사 기록. */
    pub audit: AuditLog,
    /** @brief 데이터 평면으로 들어가는 훅들. */
    pub controls: Arc<Controls>,

    /** @brief 서버가 다 떴는지. 그 전에는 준비되지 않았다고 답한다. */
    pub readiness: Arc<std::sync::atomic::AtomicBool>,

    /** @brief 관리 화면 앞의 리버스 프록시 정책. 설정을 다시 읽으면 통째로 바뀐다. */
    pub proxy: Arc<ArcSwap<ProxyPolicy>>,
}

#[derive(Default)]
/**
 * @brief 관리 화면을 리버스 프록시 뒤에서 내보일 때의 정책.
 * @details trusted 대역에서 접속한 요청만 origins의 Host로 들어올 수 있고, 그런 요청에서만
 *          X-Forwarded-For를 읽는다. 그 밖의 요청은 전처럼 루프백 Host만 받는다.
 */
pub struct ProxyPolicy {
    /** @brief 리버스 프록시가 접속해 오는 주소 대역. */
    pub trusted: Vec<IpNet>,
    /** @brief 리버스 프록시가 관리 화면을 내보이는 HTTPS 출처. */
    pub origins: Vec<HttpsOrigin>,
}

impl ProxyPolicy {
    /** @brief 이 주소가 신뢰하는 리버스 프록시인지. */
    fn trusts(&self, ip: IpAddr) -> bool {
        self.trusted.iter().any(|net| net.contains(&ip))
    }

    /**
     * @brief X-Forwarded-For에서 실제 클라이언트 주소를 고른다.
     * @details 오른쪽부터 읽으며 신뢰하는 프록시 주소를 건너뛴 첫 주소다. 왼쪽 항목은
     *          클라이언트가 마음대로 적어 보낼 수 있고, 프록시는 자기가 본 주소를 오른쪽 끝에
     *          붙이기 때문이다. 주소가 아닌 값을 만나면 거기서 멈추고 모른다고 답한다.
     */
    fn forwarded_client(&self, forwarded_for: &str) -> Option<IpAddr> {
        for entry in forwarded_for.rsplit(',') {
            let ip = entry.trim().parse::<IpAddr>().ok()?;
            if !self.trusts(ip) {
                return Some(ip);
            }
        }
        None
    }
}

/** @brief 로그인 세션 쿠키 이름. 루프백으로 직접 접속할 때 쓴다. */
const SESSION_COOKIE: &str = "onetdns_session";

/**
 * @brief HTTPS 리버스 프록시를 거쳐 접속할 때의 세션 쿠키 이름.
 * @details __Host- 접두사가 붙은 쿠키는 브라우저가 Secure, Path=/, Domain 없음일 때만
 *          받는다. 같은 도메인의 다른 하위 도메인이 이 쿠키를 덮어쓸 수 없게 된다.
 */
const SECURE_SESSION_COOKIE: &str = "__Host-onetdns_session";

/** @brief 요청을 보낸 쪽. 감사 기록, 로그인 제한, 쿠키 형식이 이것을 따른다. */
struct Caller {
    /** @brief TCP 연결의 상대 주소. 프록시를 거쳤으면 프록시다. */
    peer: Option<SocketAddr>,
    /** @brief 신뢰하는 리버스 프록시를 거쳐 공개 출처로 들어왔을 때 그 내용. */
    proxied: Option<Proxied>,
}

/** @brief 리버스 프록시를 거쳐 들어온 요청의 정보. */
struct Proxied {
    /** @brief X-Forwarded-For가 알려 준 실제 클라이언트 주소. 헤더가 없거나 깨졌으면 없다. */
    client: Option<IpAddr>,
}

impl Caller {
    /** @brief 프록시를 거치지 않은 요청. */
    fn direct(peer: Option<SocketAddr>) -> Self {
        Self {
            peer,
            proxied: None,
        }
    }

    /** @brief 감사 기록과 로그에 남길 출발지. 프록시를 거쳤으면 실제 클라이언트와 프록시를 함께 적는다. */
    fn label(&self) -> String {
        let peer = self.peer.map(|value| value.to_string()).unwrap_or_default();
        match &self.proxied {
            Some(proxied) => match proxied.client {
                Some(client) => format!("{client} via {peer}"),
                None => format!("unknown via {peer}"),
            },
            None => peer,
        }
    }

    /**
     * @brief 로그인 실패를 셀 출발지.
     * @details 프록시를 거쳤으면 실제 클라이언트 주소다. 프록시 주소로 세면 공격자 하나가
     *          프록시 뒤의 모든 관리자를 함께 막는다. 클라이언트 주소를 모르면 프록시 주소로 센다.
     *          직접 들어온 요청은 모두 이 컴퓨터 안에서 온 것이라 하나로 센다. 주소로 나누면
     *          Linux에서는 127.0.0.0/8의 아무 주소에서나 접속할 수 있어 출발지를 바꿔 가며
     *          제한을 피한다.
     */
    fn login_source(&self) -> String {
        match &self.proxied {
            Some(proxied) => proxied
                .client
                .or(self.peer.map(|peer| peer.ip()))
                .map_or_else(|| "unknown".to_string(), |ip| ip.to_string()),
            None => "local".to_string(),
        }
    }

    /** @brief 프록시를 거쳤으면 그 프록시 주소. 프록시 단위 로그인 제한의 키다. */
    fn login_proxy(&self) -> Option<String> {
        self.proxied.as_ref()?;
        Some(self.peer?.ip().to_string())
    }

    /** @brief 이 요청이 쓰는 세션 쿠키 이름. HTTPS 공개 출처로 들어왔으면 Secure 쿠키다. */
    fn session_cookie(&self) -> &'static str {
        if self.proxied.is_some() {
            SECURE_SESSION_COOKIE
        } else {
            SESSION_COOKIE
        }
    }
}

/** @brief 완성된 요청을 기존 연결 처리 스레드로 승격한다. */
fn spawn_control_connection(
    pending: PendingControlConnection,
    state: &AppState,
    shutdown: &Arc<std::sync::atomic::AtomicBool>,
    connections: &mut Vec<(SharedTcp, std::thread::JoinHandle<()>)>,
) {
    let PendingControlConnection {
        stream,
        peer,
        deadline,
        received,
        next_probe: _,
        probe_delay: _,
        admission_bytes,
        guard,
    } = pending;
    if let Err(error) = stream.set_nonblocking(false) {
        record_control_error("socket_blocking", Some(peer), error);
        return;
    }
    let st = state.clone();
    let shutdown_stream = stream.clone();
    let connection_shutdown = shutdown.clone();
    match std::thread::Builder::new()
        .name("onetdns-control-client".to_string())
        .stack_size(CONTROL_CONNECTION_STACK_BYTES)
        .spawn(move || {
            let _guard = guard;
            if let Err(error) =
                handle_conn_until_shutdown(
                    stream,
                    &st,
                    connection_shutdown,
                    deadline,
                    received,
                    admission_bytes,
                )
            {
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::NotConnected
                ) {
                    onetdns_core::debug!(event = "control.connection_closed", transport = "control", peer = %peer, error = %error, "Closed dashboard connection");
                } else {
                    record_control_error("connection", Some(peer), error);
                }
            }
        })
    {
        Ok(thread) => connections.push((shutdown_stream, thread)),
        Err(error) => record_control_error("thread_spawn", Some(peer), error),
    }
}

/** @brief 완성·데드라인·종료된 보류 연결을 처리한다. */
fn promote_control_connections(
    pending: &mut Vec<PendingControlConnection>,
    state: &AppState,
    shutdown: &Arc<std::sync::atomic::AtomicBool>,
    connections: &mut Vec<(SharedTcp, std::thread::JoinHandle<()>)>,
    scratch: &mut [u8],
) {
    let mut index = 0;
    while index < pending.len() {
        let now = Instant::now();
        if now >= pending[index].deadline {
            let expired = pending.swap_remove(index);
            if expired.stream.set_nonblocking(false).is_ok() {
                let _ = write_simple(
                    expired.stream,
                    "408 Request Timeout",
                    "text/plain",
                    "",
                    "Management request was not received in time",
                );
            }
            continue;
        }
        if now < pending[index].next_probe {
            index += 1;
            continue;
        }
        let received_before = pending[index].received.len();
        let state_now = match control_admission_state(&mut pending[index], scratch) {
            Ok(state_now) => state_now,
            Err(error) => {
                let failed = pending.swap_remove(index);
                record_control_error("connection_admission", Some(failed.peer), error);
                continue;
            }
        };
        match state_now {
            ControlAdmissionState::Pending => {
                if pending[index].received.len() > received_before {
                    pending[index].probe_delay = Duration::from_millis(CONTROL_ADMISSION_POLL_MS);
                } else {
                    pending[index].probe_delay = (pending[index].probe_delay * 2)
                        .min(Duration::from_millis(CONTROL_ADMISSION_MAX_BACKOFF_MS));
                }
                pending[index].next_probe = now + pending[index].probe_delay;
                index += 1;
            }
            ControlAdmissionState::Closed => {
                pending.swap_remove(index);
            }
            ControlAdmissionState::Overloaded => {
                let overloaded = pending.swap_remove(index);
                if overloaded.stream.set_nonblocking(false).is_ok() {
                    let _ = write_simple(
                        overloaded.stream,
                        "503 Service Unavailable",
                        "text/plain",
                        "Retry-After: 1\r\n",
                        "Management request buffer limit reached",
                    );
                }
            }
            ControlAdmissionState::Ready => {
                let ready = pending.swap_remove(index);
                spawn_control_connection(ready, state, shutdown, connections);
            }
        }
    }
}

/**
 * @brief 주소에 묶고 컨트롤 플레인을 서빙한다.
 * @warning 이 서버는 관리 권한을 다룬다. 설정 검증이 루프백 주소만 허용하도록 강제한다.
 */
pub fn serve(
    addr: SocketAddr,
    state: AppState,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    serve_listener(listener, state, shutdown)
}

/**
 * @brief 이미 열린 리스너로 서빙한다.
 * @details 리스너를 밖에서 받는 이유는 설정 재적용 때문이다. 세대가 바뀌어도 같은 소켓을
 *          유지해야 대시보드 연결이 끊기지 않는다.
 * @note 요청이 완성된 연결만 스레드로 승격한다. 부분 요청은 비차단 admission에 둔다.
 */
pub fn serve_listener(
    listener: TcpListener,
    state: AppState,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<()> {
    use std::sync::atomic::Ordering;
    listener.set_nonblocking(true)?;
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let admission_bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut connections = Vec::new();
    let mut pending = Vec::new();
    let mut admission_scratch = [0u8; CONTROL_ADMISSION_READ_BYTES];
    while !shutdown.load(Ordering::Relaxed) {
        reap_control_connections(&mut connections);
        promote_control_connections(
            &mut pending,
            &state,
            &shutdown,
            &mut connections,
            &mut admission_scratch,
        );
        loop {
            match listener.accept() {
                Ok((s, peer)) => {
                    if let Err(error) = s
                        .set_read_timeout(Some(std::time::Duration::from_secs(
                            CONTROL_READ_TIMEOUT_SECS,
                        )))
                        .and_then(|()| {
                            s.set_write_timeout(Some(std::time::Duration::from_secs(
                                CONTROL_WRITE_TIMEOUT_SECS,
                            )))
                        })
                    {
                        record_control_error("socket_options", Some(peer), error);
                        continue;
                    }
                    let s = SharedTcp::new(s);
                    let Some(guard) = acquire_connection_slot(&active) else {
                        record_control_error(
                            "connection_limit",
                            Some(peer),
                            "Too many concurrent management connections",
                        );
                        let _ = write_simple(
                            s,
                            "503 Service Unavailable",
                            "text/plain",
                            "Retry-After: 1\r\n",
                            "Too many management requests. Try again shortly",
                        );
                        continue;
                    };
                    if let Err(error) = s.set_nonblocking(true) {
                        record_control_error("socket_nonblocking", Some(peer), error);
                        continue;
                    }
                    pending.push(PendingControlConnection {
                        stream: s,
                        peer,
                        deadline: Instant::now() + Duration::from_secs(CONTROL_READ_TIMEOUT_SECS),
                        received: Vec::new(),
                        next_probe: Instant::now(),
                        probe_delay: Duration::from_millis(CONTROL_ADMISSION_POLL_MS),
                        admission_bytes: AdmissionBytesGuard::new(admission_bytes.clone()),
                        guard,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    record_control_error("accept", None, error);
                    break;
                }
            }
        }
        promote_control_connections(
            &mut pending,
            &state,
            &shutdown,
            &mut connections,
            &mut admission_scratch,
        );
        std::thread::sleep(Duration::from_millis(CONTROL_ADMISSION_POLL_MS));
    }

    for pending in pending.drain(..) {
        let _ = pending.stream.shutdown(std::net::Shutdown::Both);
    }

    let drain_deadline = Instant::now() + Duration::from_secs(CONTROL_DRAIN_GRACE_SECS);
    loop {
        reap_control_connections(&mut connections);
        if connections.is_empty() || Instant::now() >= drain_deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    for (stream, _) in &connections {
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
    for (_, thread) in connections {
        let _ = thread.join();
    }
    Ok(())
}

/** @brief 끝난 연결 스레드를 정리한다. 쌓이면 핸들이 계속 는다. */
fn reap_control_connections(connections: &mut Vec<(SharedTcp, std::thread::JoinHandle<()>)>) {
    let mut index = 0;
    while index < connections.len() {
        if connections[index].1.is_finished() {
            let (_, thread) = connections.swap_remove(index);
            let _ = thread.join();
        } else {
            index += 1;
        }
    }
}

/** @brief 길이 상한을 지키며 한 줄을 읽는다. 넘으면 오류다. */
fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    out: &mut String,
    max: usize,
) -> std::io::Result<usize> {
    reader.take(max.saturating_add(1) as u64).read_line(out)
}

/** @brief 줄 끝의 개행을 떼어 낸다. 형식이 어긋나면 None. */
fn http_line(value: &str) -> Option<&str> {
    let value = value.strip_suffix("\r\n")?;
    (!value.bytes().any(|byte| matches!(byte, b'\r' | b'\n'))).then_some(value)
}

/** @brief 문자열이 HTTP 토큰 규칙을 지키는지. */
fn http_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/**
 * @brief 헤더 값에 허용되지 않는 문자가 없는지.
 * @warning 제어문자를 허용하면 값에 든 줄바꿈이 헤더를 새로 만들어 내는 밀반입이 성립한다.
 */
fn http_field_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || (byte >= b' ' && byte != 0x7f))
}

/**
 * @brief 루프백 Host 헤더에서 읽은 출처. 호스트는 소문자 이름이나 IP 문자열로 정규화한다.
 * @details 포트가 없는 Host는 HTTP 기본 포트 80을 뜻한다. Origin과 비교할 때 이 규칙으로
 *          양쪽의 실제 포트를 맞춘다.
 */
#[derive(Debug, PartialEq, Eq)]
struct LoopbackAuthority {
    host: String,
    port: Option<u16>,
}

impl LoopbackAuthority {
    /** @brief 포트를 생략했을 때 HTTP가 쓰는 포트까지 채운 실제 포트. */
    fn effective_port(&self) -> u16 {
        self.port.unwrap_or(80)
    }
}

/**
 * @brief Host 헤더가 자기 자신을 가리키는지 확인한다.
 * @details 포트가 있으면 이 제어 소켓의 포트와 같아야 한다.
 * @warning DNS 리바인딩 방어의 핵심이다. 확인하지 않으면 공격자 페이지가 이름을 이 서버의
 *          루프백으로 돌려 브라우저를 통해 관리 API를 부를 수 있다.
 */
fn control_authority(value: &str, local_port: u16) -> Option<LoopbackAuthority> {
    let value = value.trim();
    if value.is_empty()
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
        || value.contains(['/', '\\', '@', '#', '?'])
    {
        return None;
    }
    let authority = parse_loopback_authority(value)?;
    authority
        .port
        .is_none_or(|port| port == local_port)
        .then_some(authority)
}

/** @brief host[:port] 형태를 읽고 호스트가 루프백일 때만 돌려준다. */
fn parse_loopback_authority(value: &str) -> Option<LoopbackAuthority> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return address.ip().is_loopback().then(|| LoopbackAuthority {
            host: address.ip().to_string(),
            port: Some(address.port()),
        });
    }
    if let Some(inner) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
        let ip = inner.parse::<std::net::IpAddr>().ok()?;
        return ip.is_loopback().then(|| LoopbackAuthority {
            host: ip.to_string(),
            port: None,
        });
    }
    if let Ok(ip) = value.parse::<std::net::IpAddr>() {
        return ip.is_loopback().then(|| LoopbackAuthority {
            host: ip.to_string(),
            port: None,
        });
    }
    let (name, port) = match value.rsplit_once(':') {
        Some((name, port)) => (name, Some(port.parse::<u16>().ok()?)),
        None => (value, None),
    };
    name.eq_ignore_ascii_case("localhost")
        .then(|| LoopbackAuthority {
            host: "localhost".into(),
            port,
        })
}

/**
 * @brief Origin이 루프백 Host와 같은 출처인지 확인한다.
 * @details 출처는 스킴, 호스트, 포트의 조합이다. 제어 소켓은 평문 HTTP만 받으므로 스킴은
 *          http여야 하고, 호스트와 실제 포트가 모두 Host와 같아야 한다. 경로가 붙은 값은
 *          Origin 형식이 아니므로 거절한다.
 * @warning 호스트만 비교하면 같은 컴퓨터의 다른 포트에서 뜬 페이지가 관리 API와 웹소켓을
 *          호출할 수 있다. 브라우저는 웹소켓에 동일 출처 정책을 적용하지 않으므로 이 검사가
 *          교차 출처 웹소켓 가로채기를 막는 유일한 장치다.
 */
fn same_loopback_origin(origin: &str, host: &LoopbackAuthority) -> bool {
    let Some(authority) = origin.strip_prefix("http://") else {
        return false;
    };
    if authority.is_empty() || authority.contains(['/', '\\', '@', '#', '?']) {
        return false;
    }
    parse_loopback_authority(authority).is_some_and(|origin| {
        origin.host == host.host && origin.effective_port() == host.effective_port()
    })
}

/** @brief Host와 Origin 검사에서 요청을 거절하는 이유. */
#[derive(Debug, PartialEq, Eq)]
enum HostRejection {
    /** @brief Host가 루프백도 아니고, 신뢰하는 프록시를 거친 공개 출처도 아니다. */
    Misdirected,
    /** @brief Origin이 Host와 다른 출처다. */
    CrossOrigin,
}

/**
 * @brief Host와 Origin으로 요청을 받을지 정하고, 받는다면 보낸 쪽을 알아낸다.
 * @details 루프백 Host는 전처럼 받고 Origin도 같은 루프백 출처여야 한다. 그 밖의 Host는
 *          신뢰하는 리버스 프록시에서 접속했고 공개 출처 목록의 Host일 때만 받으며, Origin이
 *          있으면 그 출처와 정확히 같아야 한다. 이때만 X-Forwarded-For를 읽는다.
 * @warning DNS 리바인딩 방어가 여기 있다. 공개 출처를 프록시가 아닌 연결에도 열면, 이름을
 *          루프백으로 돌린 공격자 페이지는 막히지만 같은 컴퓨터의 다른 프로그램이 프록시인
 *          척 X-Forwarded-For를 꾸며 로그인 제한을 피할 수 있다.
 */
fn control_caller(
    policy: &ProxyPolicy,
    peer: Option<SocketAddr>,
    local_port: u16,
    host: &str,
    origin: Option<&str>,
    forwarded_for: &str,
) -> Result<Caller, HostRejection> {
    if let Some(authority) = control_authority(host, local_port) {
        if origin.is_some_and(|value| !same_loopback_origin(value, &authority)) {
            return Err(HostRejection::CrossOrigin);
        }
        return Ok(Caller::direct(peer));
    }
    let from_proxy = peer.is_some_and(|peer| policy.trusts(peer.ip()));
    let public = from_proxy
        .then(|| {
            policy
                .origins
                .iter()
                .find(|public| public.matches_host(host))
        })
        .flatten()
        .ok_or(HostRejection::Misdirected)?;
    if origin.is_some_and(|value| !public.matches_origin(value)) {
        return Err(HostRejection::CrossOrigin);
    }
    Ok(Caller {
        peer,
        proxied: Some(Proxied {
            client: policy.forwarded_client(forwarded_for),
        }),
    })
}

#[cfg(test)]
/** @brief 연결 하나를 처리한다. */
fn handle_conn(stream: TcpStream, st: &AppState) -> std::io::Result<()> {
    handle_conn_inner(
        SharedTcp::new(stream),
        st,
        None,
        Instant::now() + Duration::from_secs(CONTROL_READ_TIMEOUT_SECS),
        Vec::new(),
        None,
    )
}

/** @brief 종료 신호가 설 때까지 연결 하나를 처리한다. */
fn handle_conn_until_shutdown(
    stream: SharedTcp,
    st: &AppState,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    request_deadline: Instant,
    prefix: Vec<u8>,
    admission_bytes: AdmissionBytesGuard,
) -> std::io::Result<()> {
    handle_conn_inner(
        stream,
        st,
        Some(shutdown),
        request_deadline,
        prefix,
        Some(admission_bytes),
    )
}

/**
 * @brief 요청을 읽고 라우팅해 응답한다. 서버의 본체다.
 *
 * @details 순서가 정해져 있다. 요청 줄과 헤더를 상한 안에서 읽고, Host와 Origin을
 *          확인하고, 본문을 받고, 인증을 거친 뒤 라우팅한다.
 * @warning 상태를 바꾸는 요청은 변경 잠금을 잡는다. 겹치면 설정 적용이 서로를 덮어쓴다.
 */
fn handle_conn_inner(
    mut stream: SharedTcp,
    st: &AppState,
    shutdown: Option<Arc<std::sync::atomic::AtomicBool>>,
    request_deadline: Instant,
    prefix: Vec<u8>,
    admission_bytes: Option<AdmissionBytesGuard>,
) -> std::io::Result<()> {
    let peer = stream.peer_addr().ok();
    let local_port = stream.local_addr()?.port();
    let mut deadline_stream = DeadlineTcp::new(
        AdmittedTcp::new(stream.clone(), prefix, admission_bytes),
        request_deadline,
    );
    if let Some(shutdown) = shutdown {
        deadline_stream = deadline_stream.stop_on(shutdown);
    }
    let mut reader = BufReader::new(deadline_stream);

    let mut line = String::new();
    if read_bounded_line(&mut reader, &mut line, MAX_REQUEST_LINE)? == 0 {
        return Ok(());
    }
    if line.len() > MAX_REQUEST_LINE {
        return write_simple(
            stream,
            "414 URI Too Long",
            "text/plain",
            "",
            "Request target is too long",
        );
    }
    let Some(line) = http_line(&line) else {
        return write_simple(
            stream,
            "400 Bad Request",
            "text/plain",
            "",
            "HTTP request line must end with CRLF",
        );
    };
    let mut it = line.split(' ');
    let method = it.next().unwrap_or("").to_string();
    let target = it.next().unwrap_or("").to_string();
    let version = it.next().unwrap_or("");

    if method.is_empty()
        || target.is_empty()
        || !http_token(&method)
        || !target.starts_with('/')
        || !target
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'#')
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || it.next().is_some()
    {
        return write_simple(
            stream,
            "400 Bad Request",
            "text/plain",
            "",
            "Malformed HTTP request line",
        );
    }
    // 질의 문자열은 경로가 아니다. 이것을 떼지 않으면 /?x=1도 /healthz?src=lb도
    // 등록되지 않은 경로가 되어 404·401이 된다. 감사 기록에도 경로만 남긴다.
    let path = match target.find('?') {
        Some(mark) => target[..mark].to_string(),
        None => target,
    };
    let mut content_length: Option<usize> = None;
    let mut content_type: Option<String> = None;
    let mut auth = String::new();
    let mut cookie = String::new();
    let mut csrf = String::new();
    let mut ws_upgrade = String::new();
    let mut ws_connection = String::new();
    let mut ws_key = String::new();
    let mut ws_version = String::new();
    let mut ws_protocols = String::new();
    let mut auth_seen = false;
    let mut csrf_seen = false;
    let mut host: Option<String> = None;
    let mut origin: Option<String> = None;
    let mut forwarded_for = String::new();
    let mut header_bytes = 0usize;
    let mut header_count = 0usize;
    let mut has_transfer_encoding = false;
    loop {
        let mut h = String::new();
        if read_bounded_line(&mut reader, &mut h, MAX_HEADER_LINE)? == 0 {
            return write_simple(
                stream,
                "400 Bad Request",
                "text/plain",
                "",
                "HTTP headers were not fully received",
            );
        }
        header_bytes = header_bytes.saturating_add(h.len());
        header_count = header_count.saturating_add(1);
        if h.len() > MAX_HEADER_LINE
            || header_bytes > MAX_HEADER_BYTES
            || header_count > MAX_HEADERS
        {
            return write_simple(
                stream,
                "431 Request Header Fields Too Large",
                "text/plain",
                "",
                "HTTP headers exceed the size or count limit",
            );
        }
        let Some(t) = http_line(&h) else {
            return write_simple(
                stream,
                "400 Bad Request",
                "text/plain",
                "",
                "HTTP header line must end with CRLF",
            );
        };
        if t.is_empty() {
            break;
        }
        if t.starts_with(' ') || t.starts_with('\t') {
            return write_simple(
                stream,
                "400 Bad Request",
                "text/plain",
                "",
                "Folded HTTP headers are not allowed",
            );
        }
        let Some((name, val)) = t.split_once(':') else {
            return write_simple(
                stream,
                "400 Bad Request",
                "text/plain",
                "",
                "Malformed HTTP header",
            );
        };
        if !http_token(name) || !http_field_value(val) {
            return write_simple(
                stream,
                "400 Bad Request",
                "text/plain",
                "",
                "HTTP header name or value contains a disallowed character",
            );
        }
        let val = val.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return write_simple(
                    stream,
                    "400 Bad Request",
                    "text/plain",
                    "",
                    "Content-Length header sent more than once",
                );
            }
            if val.is_empty() || !val.bytes().all(|byte| byte.is_ascii_digit()) {
                return write_simple(
                    stream,
                    "400 Bad Request",
                    "text/plain",
                    "",
                    "Invalid Content-Length header",
                );
            }
            content_length = Some(match val.parse::<usize>() {
                Ok(value) => value,
                Err(_) => {
                    return write_simple(
                        stream,
                        "400 Bad Request",
                        "text/plain",
                        "",
                        "Invalid Content-Length header",
                    )
                }
            });
        } else if name.eq_ignore_ascii_case("content-type") {
            if content_type.is_some() {
                return write_simple(
                    stream,
                    "400 Bad Request",
                    "text/plain",
                    "",
                    "Content-Type header sent more than once",
                );
            }
            content_type = Some(val.to_ascii_lowercase());
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            has_transfer_encoding = true;
        } else if name.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return write_simple(
                    stream,
                    "400 Bad Request",
                    "text/plain",
                    "",
                    "Host header sent more than once",
                );
            }
            host = Some(val.to_string());
        } else if name.eq_ignore_ascii_case("origin") {
            if origin.is_some() {
                return write_simple(
                    stream,
                    "400 Bad Request",
                    "text/plain",
                    "",
                    "Origin header sent more than once",
                );
            }
            origin = Some(val.to_string());
        } else if name.eq_ignore_ascii_case("x-forwarded-for") {
            if !forwarded_for.is_empty() {
                forwarded_for.push(',');
            }
            forwarded_for.push_str(val);
        } else if name.eq_ignore_ascii_case("authorization") {
            if auth_seen {
                return write_simple(
                    stream,
                    "400 Bad Request",
                    "text/plain",
                    "",
                    "Authorization header sent more than once",
                );
            }
            auth_seen = true;
            auth = val.to_string();
        } else if name.eq_ignore_ascii_case("cookie") {
            append_cookie_header(&mut cookie, val);
        } else if name.eq_ignore_ascii_case("x-onetdns-csrf") {
            if csrf_seen {
                return write_simple(
                    stream,
                    "400 Bad Request",
                    "text/plain",
                    "",
                    "CSRF header sent more than once",
                );
            }
            csrf_seen = true;
            csrf = val.to_string();
        } else if name.eq_ignore_ascii_case("upgrade") {
            ws_upgrade = val.to_string();
        } else if name.eq_ignore_ascii_case("connection") {
            ws_connection = val.to_string();
        } else if name.eq_ignore_ascii_case("sec-websocket-key") {
            ws_key = val.to_string();
        } else if name.eq_ignore_ascii_case("sec-websocket-version") {
            ws_version = val.to_string();
        } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
            if !ws_protocols.is_empty() {
                ws_protocols.push(',');
            }
            ws_protocols.push_str(val);
        }
    }
    let Some(host) = host else {
        return write_simple(
            stream,
            "400 Bad Request",
            "text/plain",
            "",
            "Missing Host header",
        );
    };
    /*
     * CA는 Host에 발급 대상 도메인을 담아 보낸다. 이 경로는 인증 없이 공개할 값만 돌려주는
     * 읽기 전용 GET이라 리바인딩으로 얻을 것이 없으므로 Host 검사를 거치지 않는다.
     */
    if method == "GET" && path.starts_with("/.well-known/acme-challenge/") {
        let (status, content_type, body) =
            route(&method, &path, "", "", "", &Caller::direct(peer), st);
        return write_simple(stream, status, content_type, "", &body);
    }
    let caller = match control_caller(
        &st.proxy.load(),
        peer,
        local_port,
        &host,
        origin.as_deref(),
        &forwarded_for,
    ) {
        Ok(caller) => caller,
        Err(HostRejection::Misdirected) => {
            record_control_error(
                "host_not_loopback",
                peer,
                "Management API called with a Host that is neither loopback nor a configured public address. This may be a DNS rebinding attempt",
            );
            return write_simple(
                stream,
                "421 Misdirected Request",
                "text/plain",
                "",
                "Management API Host must be localhost, a loopback address, or an address in control_public_origins reached through control_trusted_proxies",
            );
        }
        Err(HostRejection::CrossOrigin) => {
            record_control_error("cross_origin", peer, "Cross-origin management request");
            return write_simple(
                stream,
                "403 Forbidden",
                "text/plain",
                "",
                "Cross-origin management requests are not allowed",
            );
        }
    };
    if has_transfer_encoding {
        return write_simple(
            stream,
            "400 Bad Request",
            "text/plain",
            "",
            "Transfer-Encoding requests are not supported",
        );
    }
    let content_length = content_length.unwrap_or(0);
    if content_length > MAX_REQUEST_BODY {
        record_control_error("body_too_large", peer, content_length);
        return write_simple(
            stream,
            "413 Payload Too Large",
            "text/plain",
            "",
            "Request body is too large",
        );
    }
    let session_candidates = cookie_values(&cookie, caller.session_cookie());

    let session = select_session_cookie(&session_candidates, &st.auth);
    let bearer = auth.strip_prefix("Bearer ").unwrap_or("");
    let mutating = !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS");
    if mutating && path != "/v1/login" && !session.is_empty() && bearer.is_empty() && csrf != "1" {
        record_control_error(
            "csrf_check",
            peer,
            "Cookie-authenticated write request has no CSRF token",
        );
        return write_simple(
            stream,
            "403 Forbidden",
            "text/plain",
            "",
            "CSRF check failed",
        );
    }

    if content_length > 0 && !content_type_allowed(&method, &path, content_type.as_deref()) {
        record_control_error(
            "content_type",
            peer,
            "Content-Type is missing or unsupported",
        );
        return write_simple(
            stream,
            "415 Unsupported Media Type",
            "text/plain",
            "",
            "Content-Type header is missing or unsupported",
        );
    }
    let mut body = vec![0u8; content_length];
    if !body.is_empty() {
        reader.read_exact(&mut body)?;
    }
    let body = match String::from_utf8(body) {
        Ok(body) => body,
        Err(_) => {
            return write_simple(
                stream,
                "400 Bad Request",
                "text/plain",
                "",
                "Request body must be valid UTF-8",
            )
        }
    };

    if method == "POST" && path == "/v1/setup" {
        return handle_setup(stream, &body, &caller, st);
    }
    if method == "POST" && path == "/v1/login" {
        return handle_login(stream, &body, &caller, st);
    }
    if method == "POST" && path == "/v1/logout" {
        return handle_logout(stream, &session_candidates, &caller, st);
    }
    if method == "GET" && path == "/v1/auth" {
        return handle_auth(stream, &auth, &session, &caller, st);
    }

    if method == "GET" && path == "/v1/dashboard/ws" {
        return handle_dashboard_websocket(
            stream,
            &auth,
            &session,
            &ws_upgrade,
            &ws_connection,
            &ws_key,
            &ws_version,
            &ws_protocols,
            &caller,
            st,
        );
    }

    let (status, ctype, resp) = route(&method, &path, &auth, &session, &body, &caller, st);
    let ctype = with_charset(ctype);
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
        control_security_headers(),
        resp.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(resp.as_bytes())?;
    stream.flush()
}

/**
 * @brief 이 요청의 내용 형식이 허용되는지.
 * @warning 브라우저가 사전 요청 없이 보낼 수 있는 형식을 막는 것이 교차 출처 위조 방어다.
 */
fn content_type_allowed(method: &str, path: &str, value: Option<&str>) -> bool {
    if matches!(method, "GET" | "HEAD" | "OPTIONS") {
        return true;
    }
    let Some(raw) = value else {
        return false;
    };
    let media_type = raw.split(';').next().unwrap_or("").trim();
    if path.starts_with("/v1/zones/") {
        if path.ends_with("/records") {
            return match method {
                "POST" | "PUT" => {
                    matches!(media_type, "text/plain" | "application/dns-zone")
                }
                "DELETE" => media_type == "application/json",
                _ => false,
            };
        }
        return matches!(method, "POST" | "PUT")
            && matches!(media_type, "text/plain" | "application/dns-zone");
    }
    if path == "/v1/restore" || path == "/v1/config/set" {
        return media_type == "application/json";
    }
    if matches!(
        path,
        "/v1/config/validate" | "/v1/config/diff" | "/v1/config/apply"
    ) {
        return matches!(media_type, "text/plain" | "application/toml");
    }
    media_type == "application/json"
}

/** @brief 여러 번 온 쿠키 헤더를 하나로 잇는다. */
fn append_cookie_header(cookie: &mut String, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    if !cookie.is_empty() {
        cookie.push_str("; ");
    }
    cookie.push_str(value);
}

/** @brief 쿠키에서 같은 이름의 값들을 모두 추출한다. 이름이 겹칠 수 있다. */
fn cookie_values(cookie: &str, key: &str) -> Vec<String> {
    let mut values: Vec<String> = Vec::new();
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == key {
                let value = v.trim();
                if !value.is_empty() && !values.iter().any(|item| item.as_str() == value) {
                    values.push(value.to_string());
                }
            }
        }
    }
    values
}

/**
 * @brief 여러 세션 쿠키 중 실제로 유효한 것을 고른다.
 * @details 브라우저는 경로나 도메인이 다르면 같은 이름의 쿠키를 여럿 보낸다. 첫 번째만
 *          보면 오래된 값 때문에 로그인이 풀린 것처럼 보인다.
 */
fn select_session_cookie(candidates: &[String], auth: &Auth) -> String {
    candidates
        .iter()
        .find(|token| auth.role_for_session(token.as_str()).is_some())
        .cloned()
        .or_else(|| candidates.first().cloned())
        .unwrap_or_default()
}

/** @brief 콘솔 탭 아이콘. 대시보드 헤더의 표식과 같은 도형이다. */
#[cfg(feature = "dashboard")]
const FAVICON_SVG: &str = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 48 48\">\
<rect width=\"48\" height=\"48\" rx=\"10\" fill=\"#2f4a6b\"/>\
<g fill=\"none\" stroke=\"#f7f3e9\" stroke-width=\"4.6\" stroke-linecap=\"round\" \
stroke-linejoin=\"round\" transform=\"translate(5.28,5.28) scale(0.78)\">\
<path d=\"M38 14.4A17 17 0 1 0 38 33.6\"/>\
<path d=\"M31.5 24H39.5\"/>\
<path d=\"M9.5 24H17l3-7.5 4.5 15 3-7.5H33\"/>\
</g></svg>";

/** @brief 모든 응답에 붙이는 보안 헤더. */
fn control_security_headers() -> &'static str {
    "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nPermissions-Policy: camera=(), microphone=(), geolocation=()\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'\r\n"
}

/** @brief 간단한 응답 하나를 쓴다. */
/**
 * @brief 내용 형식에 문자 인코딩을 붙인다.
 * @details text 계열 응답에 charset이 없으면 클라이언트가 ISO-8859-1로 읽어도 규격
 *          위반이 아니다. 본문이 한국어라 그렇게 읽히면 그대로 깨진다. JSON은 규격상
 *          UTF-8이라 붙이지 않는다.
 */
fn with_charset(ctype: &str) -> Cow<'_, str> {
    if ctype.starts_with("text/") && !ctype.to_ascii_lowercase().contains("charset=") {
        Cow::Owned(format!("{ctype}; charset=utf-8"))
    } else {
        Cow::Borrowed(ctype)
    }
}

fn write_simple(
    mut stream: SharedTcp,
    status: &str,
    ctype: &str,
    extra: &str,
    body: &str,
) -> std::io::Result<()> {
    let ctype = with_charset(ctype);
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\n{}{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
        control_security_headers(),
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

/**
 * @brief 세션 쿠키를 설정하는 헤더. max_age가 0이면 쿠키를 지운다.
 * @note HTTPS 공개 출처로 들어왔을 때만 Secure를 붙인다. 루프백 평문 접속에 붙이면 브라우저에
 *       따라 쿠키를 저장하지 않는다.
 */
fn session_cookie_header(caller: &Caller, token: &str, max_age: u64) -> String {
    let secure = if caller.proxied.is_some() {
        " Secure;"
    } else {
        ""
    };
    format!(
        "Set-Cookie: {}={token};{secure} HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}\r\n",
        caller.session_cookie()
    )
}

/**
 * @brief 첫 관리자 계정을 만든다. 계정이 하나도 없을 때만 열린다.
 *
 * @details 컨트롤 플레인은 설정 검증에서 루프백 주소만 허용하므로, 이 경로에 닿을 수 있는
 *          사람은 설정 파일을 직접 고칠 수 있는 사람과 같은 범위다. 계정이 하나라도
 *          생기면 이 경로는 영구히 닫힌다. 만든 뒤 바로 로그인시켜 첫 화면에서
 *          로그인을 다시 하게 만들지 않는다.
 * @warning 검사와 등록 사이에 다른 요청이 끼어들면 관리자가 둘 생긴다. 설정 파일
 *          기록은 컨트롤 플레인 변경 잠금으로, 메모리 등록은 add_first_user 안에서 막는다.
 */
fn handle_setup(
    stream: SharedTcp,
    body: &str,
    caller: &Caller,
    st: &AppState,
) -> std::io::Result<()> {
    let peer_s = caller.label();
    let refuse = |stream, status: &str, message: &str| {
        write_simple(
            stream,
            status,
            "application/json",
            "",
            &format!("{{\"ok\":false,\"error\":{}}}", json::escape(message)),
        )
    };

    // 첫 계정은 설정 파일을 고칠 수 있는 사람만 만들어야 한다. 리버스 프록시를 거친 요청은
    // 인터넷의 누구든 보낼 수 있다.
    if caller.proxied.is_some() {
        st.audit
            .record_actor("none", "anonymous", "POST", "/v1/setup", &peer_s, 403);
        return refuse(
            stream,
            "403 Forbidden",
            "Create the first account on the computer running OnetDNS, then sign in here",
        );
    }

    if st.auth.has_users() {
        st.audit
            .record_actor("none", "anonymous", "POST", "/v1/setup", &peer_s, 409);
        return refuse(
            stream,
            "409 Conflict",
            "An account already exists. Sign in, or change the password from the account page",
        );
    }

    let parsed = json::parse(body).ok();
    let field = |key: &str| {
        parsed
            .as_ref()
            .and_then(|value| value.get(key))
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string()
    };
    let name = field("user").trim().to_string();
    let password = field("password");

    // 비밀번호 해시는 비싸므로 코드부터 본다.
    if !st.auth.setup_code_matches(&field("code")) {
        st.audit
            .record_actor("none", "anonymous", "POST", "/v1/setup", &peer_s, 403);
        let message = match st.auth.setup_code_file() {
            Some(file) => format!("The setup code does not match. Copy it from {file}"),
            None => "OnetDNS has no setup code to check. Restart OnetDNS; it writes a new code next to its configuration file".to_string(),
        };
        return refuse(stream, "403 Forbidden", &message);
    }

    if name.is_empty() || name.chars().count() > 64 {
        return refuse(
            stream,
            "400 Bad Request",
            "Username must be 1 to 64 characters",
        );
    }
    if name
        .chars()
        .any(|c| c.is_control() || c == '"' || c == '\\' || c == '\'')
    {
        return refuse(
            stream,
            "400 Bad Request",
            "Username cannot contain quotes or control characters",
        );
    }
    let hash = match crate::password::hash_password(&password) {
        Ok(hash) => hash,
        Err(error) => {
            let status = match error {
                crate::password::PasswordError::Busy => "503 Service Unavailable",
                _ => "400 Bad Request",
            };
            return refuse(stream, status, &error.to_string());
        }
    };
    // 잠금은 설정 파일 기록 구간에만 건다. 뒤따르는 로그인 검증까지 안고 있으면 느린
    // 키 파생이 다른 모든 컨트롤 플레인 변경을 함께 멈춘다.
    {
        let _guard = control_mutation_lock().lock_recover();
        if st.auth.has_users() {
            return refuse(
                stream,
                "409 Conflict",
                "An account already exists. Sign in, or change the password from the account page",
            );
        }
        if let Err(error) = (st.controls.user_create)(&name, &hash) {
            st.audit
                .record_actor("none", "anonymous", "POST", "/v1/setup", &peer_s, 500);
            return refuse(stream, "500 Internal Server Error", &error);
        }
        // 설정 파일 기록이 무중단 적용을 거치며 목록을 이미 채웠을 수 있다. 그때는 여기서
        // 더 넣을 것이 없으므로 실패로 보지 않는다. 계정이 정말 생겼는지는 바로 아래에서
        // 세션을 열어 보며 확인한다.
        st.auth.add_first_user(name.clone(), hash);
        st.auth.clear_setup_code();
    }

    st.audit.record_actor(
        Role::Admin.as_str(),
        &audit_identity(&name, "authenticated-user"),
        "POST",
        "/v1/setup",
        &peer_s,
        200,
    );
    onetdns_core::warn!(
        event = "console.first_admin_created",
        user = %name,
        peer = %peer_s,
        "Created the first dashboard admin account; this setup path is now closed"
    );

    match st.auth.start_session_for(&name) {
        Some((token, role)) => {
            let cookie = session_cookie_header(caller, &token, SESSION_ABSOLUTE_TTL_MS / 1000);
            let resp = format!(
                "{{\"ok\":true,\"user\":{},\"role\":{}}}",
                json::escape(&name),
                json::escape(role.as_str())
            );
            write_simple(stream, "200 OK", "application/json", &cookie, &resp)
        }
        None => refuse(
            stream,
            "500 Internal Server Error",
            "The account was created but sign-in failed. Sign in again with the new account",
        ),
    }
}

/** @brief 인증 상태를 알려 주는 응답. 로그인 화면이 무엇을 보일지 정한다. */
fn handle_auth(
    stream: SharedTcp,
    auth: &str,
    session: &str,
    caller: &Caller,
    st: &AppState,
) -> std::io::Result<()> {
    let peer_s = caller.label();
    let bearer = auth
        .strip_prefix("Bearer ")
        .filter(|value| !value.is_empty())
        .unwrap_or("");
    if let Some(role) = bearer
        .is_empty()
        .then(|| st.auth.role_for_session(session))
        .flatten()
    {
        let user = st.auth.session_name(session).unwrap_or_default();
        st.audit.record_actor(
            role.as_str(),
            &audit_identity(&user, "authenticated-user"),
            "GET",
            "/v1/auth",
            &peer_s,
            200,
        );
        let body = auth_status_body(st, caller, true, role.as_str(), &user);
        return write_simple(stream, "200 OK", "application/json", "", &body);
    }

    // 제어 토큰은 API 전용이다. 유효한 토큰에게 역할은 알려 주되 세션 쿠키는 발급하지
    // 않는다. 쿠키로 바꿔 주면 사람이 외워 넣을 수 없는 값이 브라우저 자격증명이 되고
    // 토큰 하나가 새면 콘솔 전체가 함께 열린다.
    if let Some(role) = st.auth.role_for(bearer) {
        let actor = bearer_actor(bearer);
        st.audit
            .record_actor(role.as_str(), &actor, "GET", "/v1/auth", &peer_s, 200);
        let body = auth_status_body(st, caller, true, role.as_str(), &actor);
        return write_simple(stream, "200 OK", "application/json", "", &body);
    }

    /* 로그인하지 않은 상태 확인은 남기지 않는다. 인증 없이 누구나 보낼 수 있어서, 남기면 크기가 정해진 감사 기록에서 진짜 기록을 밀어낼 수 있다. */
    let body = auth_status_body(st, caller, false, "none", "");
    write_simple(stream, "200 OK", "application/json", "", &body)
}

/**
 * @brief 인증 상태 응답 본문을 만든다.
 * @details 실제 접속이 지나는 handle_auth와 route()의 직접 호출 경로가 같은 본문을 쓰게
 *          하여 두 구현이 서로 어긋나지 않게 한다.
 */
fn auth_status_body(
    st: &AppState,
    caller: &Caller,
    authenticated: bool,
    role: &str,
    user: &str,
) -> String {
    // 경로에는 계정 이름 같은 것이 들어 있다. 첫 계정은 이 컴퓨터에서만 만들 수 있으므로
    // 프록시를 거친 요청에는 알려 주지 않는다.
    let setup_code_file = if st.auth.has_users() || caller.proxied.is_some() {
        None
    } else {
        st.auth.setup_code_file()
    };
    format!(
        "{{\"login_enabled\":{},\"authenticated\":{},\"role\":{},\"user\":{},\"setup_code_file\":{}}}",
        st.auth.has_users(),
        authenticated,
        json::escape(role),
        json::escape(user),
        setup_code_file.map_or_else(|| "null".to_string(), |file| json::escape(&file))
    )
}

/**
 * @brief 로그인 요청을 처리하고 세션 쿠키를 설정한다.
 * @note 실패 사유를 자세히 알리지 않는다. 사용자가 없는 것과 비밀번호가 틀린 것을
 *       구분해 주면 계정 이름을 헤아릴 수 있다.
 */
fn handle_login(
    stream: SharedTcp,
    body: &str,
    caller: &Caller,
    st: &AppState,
) -> std::io::Result<()> {
    let peer_s = caller.label();
    let j = json::parse(body).ok();
    let field = |k: &str| {
        j.as_ref()
            .and_then(|v| v.get(k))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let user = field("user");
    let password = field("password");
    let source_key = caller.login_source();
    let proxy_key = caller.login_proxy();
    let attempted_actor = audit_identity(&user, "anonymous");
    if let Some(retry_after) = st
        .auth
        .login_retry_after(&source_key, proxy_key.as_deref(), &user)
    {
        st.audit
            .record_actor("none", &attempted_actor, "POST", "/v1/login", &peer_s, 429);
        return write_simple(
            stream,
            "429 Too Many Requests",
            "application/json",
            &format!("Retry-After: {retry_after}\r\n"),
            "{\"ok\":false,\"error\":\"Too many sign-in attempts. Try again shortly\"}",
        );
    }
    match st.auth.login(&user, &password) {
        LoginResult::Success(token, role, name) => {
            st.auth
                .record_login_result(&source_key, proxy_key.as_deref(), &user, true);
            st.audit.record_actor(
                role.as_str(),
                &audit_identity(&name, "authenticated-user"),
                "POST",
                "/v1/login",
                &peer_s,
                200,
            );
            let cookie = session_cookie_header(caller, &token, SESSION_ABSOLUTE_TTL_MS / 1000);
            let resp = format!(
                "{{\"ok\":true,\"user\":{},\"role\":{}}}",
                json::escape(&name),
                json::escape(role.as_str())
            );
            write_simple(stream, "200 OK", "application/json", &cookie, &resp)
        }
        LoginResult::Invalid => {
            st.auth
                .record_login_result(&source_key, proxy_key.as_deref(), &user, false);
            st.audit
                .record_actor("none", &attempted_actor, "POST", "/v1/login", &peer_s, 401);
            write_simple(
                stream,
                "401 Unauthorized",
                "application/json",
                "",
                "{\"ok\":false,\"error\":\"Incorrect username or password\"}",
            )
        }
        LoginResult::Busy => {
            st.audit
                .record_actor("none", &attempted_actor, "POST", "/v1/login", &peer_s, 503);
            write_simple(
                stream,
                "503 Service Unavailable",
                "application/json",
                "Retry-After: 1\r\n",
                "{\"ok\":false,\"error\":\"Too many password checks. Try again shortly\"}",
            )
        }
    }
}

/** @brief 세션을 버리고 쿠키를 지운다. */
fn handle_logout(
    stream: SharedTcp,
    sessions: &[String],
    caller: &Caller,
    st: &AppState,
) -> std::io::Result<()> {
    for session in sessions {
        st.auth.logout(session);
    }
    let clear = session_cookie_header(caller, "", 0);
    write_simple(
        stream,
        "200 OK",
        "application/json",
        &clear,
        "{\"ok\":true}",
    )
}

/** @brief 웹소켓 핸드셰이크에 쓰는 고정 문자열. */
const WEBSOCKET_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/** @brief 웹소켓 프레임 본문 크기 상한. */
const MAX_WEBSOCKET_PAYLOAD: usize = 1024 * 1024;

/** @brief 대시보드가 웹소켓으로 보내는 요청. */
enum DashboardCommand {
    /** @brief 이 시점 이후의 기록을 달라. */
    History(u64),
    /** @brief 살아 있는지 확인하는 답. */
    Pong(Vec<u8>),
    /** @brief 연결을 닫는다. */
    Close,
}

#[allow(clippy::too_many_arguments)]
/**
 * @brief 대시보드 실시간 연결을 처리한다.
 * @details 지표와 상위 목록을 주기적으로 밀어내고, 질의 이벤트는 오는 대로 보낸다.
 * @warning 이 연결은 오래 붙어 있다. 곳 수에 상한이 있어야 몇 개의 탭이 컨트롤 플레인 전체를
 *          점유하지 못한다.
 */
fn handle_dashboard_websocket(
    mut stream: SharedTcp,
    auth: &str,
    session: &str,
    upgrade: &str,
    connection: &str,
    key: &str,
    version: &str,
    protocols: &str,
    caller: &Caller,
    st: &AppState,
) -> std::io::Result<()> {
    let offered = protocols
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let protocol_ok = offered.contains(&"onetdns.v1");
    let connection_upgrade = connection
        .split(',')
        .map(str::trim)
        .any(|value| value.eq_ignore_ascii_case("upgrade"));
    if !upgrade.eq_ignore_ascii_case("websocket")
        || !connection_upgrade
        || !websocket_key_valid(key)
        || version != "13"
        || !protocol_ok
    {
        return write_simple(
            stream,
            "400 Bad Request",
            "text/plain",
            "Sec-WebSocket-Version: 13\r\n",
            "WebSocket handshake failed",
        );
    }

    if offered.iter().any(|value| value.starts_with("bearer64.")) {
        return write_simple(
            stream,
            "400 Bad Request",
            "text/plain",
            "",
            "WebSocket subprotocol cannot carry credentials",
        );
    }
    let token = auth
        .strip_prefix("Bearer ")
        .filter(|value| !value.is_empty())
        .unwrap_or("");
    let resume = offered
        .iter()
        .find_map(|value| value.strip_prefix("resume."))
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0);
    let peer_s = caller.label();
    let Some(role) = st.auth.resolve(token, session) else {
        st.audit.record_actor(
            "none",
            &audit_actor(&st.auth, token, session),
            "GET",
            "/v1/dashboard/ws",
            &peer_s,
            401,
        );
        return write_simple(
            stream,
            "401 Unauthorized",
            "text/plain",
            "",
            "Authentication required",
        );
    };
    let actor = audit_actor(&st.auth, token, session);
    let Some(_stream_slot) = acquire_stream_slot() else {
        st.audit.record_actor(
            role.as_str(),
            &actor,
            "GET",
            "/v1/dashboard/ws",
            &peer_s,
            503,
        );
        record_control_error("stream_limit", caller.peer, "Too many live log connections");
        return write_simple(
            stream,
            "503 Service Unavailable",
            "text/plain",
            "Retry-After: 1\r\n",
            "Too many live log connections. Try again shortly",
        );
    };

    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WEBSOCKET_GUID);
    let accept = base64_standard(&hasher.finalize());
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: onetdns.v1\r\n\r\n"
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    st.audit.record_actor(
        role.as_str(),
        &actor,
        "GET",
        "/v1/dashboard/ws",
        &peer_s,
        101,
    );

    let subscription = st.stats.subscribe_after(resume);
    let hello = format!(
        "{{\"type\":\"hello\",\"replay_gap\":{}}}",
        if subscription.replay_gap {
            "true"
        } else {
            "false"
        }
    );
    ws_write_text(&mut stream, &hello)?;
    for event in subscription.replay {
        ws_write_text(
            &mut stream,
            &format!(
                "{{\"type\":\"query\",\"replay\":true,\"event\":{}}}",
                event_json(&event)
            ),
        )?;
    }
    ws_write_text(&mut stream, &dashboard_snapshot_json(st))?;
    ws_write_text(&mut stream, &dashboard_top_json(st))?;
    ws_write_text(&mut stream, &dashboard_jobs_json(st))?;

    let reader = DashboardReader::spawn(&stream)?;

    let mut history_range = 60u64;
    let now = std::time::Instant::now();
    let mut next_snapshot = now + std::time::Duration::from_secs(1);
    let mut next_top = now + std::time::Duration::from_secs(5);
    let mut next_jobs = now + std::time::Duration::from_secs(2);
    let mut next_history = now;
    let receiver = subscription.receiver;
    let mut closed = false;
    let mut auth_expired = false;
    while !closed {
        while let Ok(command) = reader.commands().try_recv() {
            match command {
                DashboardCommand::History(range) => {
                    history_range = range;
                    next_history = std::time::Instant::now();
                }
                DashboardCommand::Pong(payload) => ws_write_frame(&mut stream, 0xA, &payload)?,
                DashboardCommand::Close => closed = true,
            }
        }
        if closed {
            break;
        }
        if st.auth.resolve(token, session).is_none() {
            auth_expired = true;
            break;
        }

        let now = std::time::Instant::now();
        if now >= next_snapshot {
            ws_write_text(&mut stream, &dashboard_snapshot_json(st))?;
            next_snapshot = now + std::time::Duration::from_secs(1);
        }
        if now >= next_top {
            ws_write_text(&mut stream, &dashboard_top_json(st))?;
            next_top = now + std::time::Duration::from_secs(5);
        }
        if now >= next_jobs {
            ws_write_text(&mut stream, &dashboard_jobs_json(st))?;
            next_jobs = now + std::time::Duration::from_secs(2);
        }
        if history_range > 300 && now >= next_history {
            let history = stats_history_json(st, history_range);
            ws_write_text(
                &mut stream,
                &format!("{{\"type\":\"history\",\"data\":{history}}}"),
            )?;
            next_history = now + std::time::Duration::from_secs(5);
        }

        match receiver.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(event) => ws_write_text(
                &mut stream,
                &format!("{{\"type\":\"query\",\"event\":{}}}", event_json(&event)),
            )?,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let close_payload = if auth_expired { 1008u16 } else { 1000u16 }.to_be_bytes();
    let _ = ws_write_frame(&mut stream, 0x8, &close_payload);
    Ok(())
}

/**
 * @brief 대시보드 웹소켓에서 브라우저가 보낸 프레임을 읽는 스레드와 그 정리 책임.
 * @details 읽기 스레드는 같은 소켓을 공유하므로 소켓이 열려 있는 한 끝나지 않는다. 그래서
 *          값이 사라지는 모든 경로에서 멈춤 신호, 소켓 종료, 명령 수신 쪽 해제, join을 이
 *          순서대로 수행한다. 쓰기 실패로 핸들러가 중간에 빠져나가도 스레드와 소켓이 남지 않는다.
 * @invariant 수신 쪽을 join보다 먼저 놓는다. 가득 찬 채널에 Close를 보내려고 막힌 읽기
 *            스레드가 있으면, 수신 쪽이 살아 있는 동안 join은 끝나지 않는다.
 */
struct DashboardReader {
    stop: Arc<std::sync::atomic::AtomicBool>,
    stream: SharedTcp,
    commands: Option<std::sync::mpsc::Receiver<DashboardCommand>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl DashboardReader {
    /** @brief 읽기 스레드를 띄운다. 실패하면 스레드도 소켓 복제도 남지 않는다. */
    fn spawn(stream: &SharedTcp) -> std::io::Result<Self> {
        let mut read_stream = stream.clone();
        read_stream.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_t = stop.clone();
        let (command_tx, commands) = std::sync::mpsc::sync_channel::<DashboardCommand>(64);
        let thread = std::thread::Builder::new()
            .name("onetdns-dashboard-ws-read".to_string())
            .stack_size(CONTROL_CONNECTION_STACK_BYTES)
            .spawn(move || loop {
                if stop_t.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                match ws_read_frame(&mut read_stream) {
                    Ok((0x1, payload)) => {
                        let Ok(text) = String::from_utf8(payload) else {
                            continue;
                        };
                        let Some(value) = json::parse(&text).ok() else {
                            continue;
                        };
                        if value.get("type").and_then(|value| value.as_str()) == Some("history") {
                            let range = value
                                .get("range")
                                .and_then(|value| value.as_u64())
                                .unwrap_or(60)
                                .clamp(60, 604_800);
                            let _ = command_tx.try_send(DashboardCommand::History(range));
                        }
                    }
                    Ok((0x8, _)) => {
                        let _ = command_tx.send(DashboardCommand::Close);
                        break;
                    }
                    Ok((0x9, payload)) => {
                        let _ = command_tx.try_send(DashboardCommand::Pong(payload));
                    }
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(_) => {
                        let _ = command_tx.send(DashboardCommand::Close);
                        break;
                    }
                }
            })?;
        Ok(Self {
            stop,
            stream: stream.clone(),
            commands: Some(commands),
            thread: Some(thread),
        })
    }

    /** @brief 읽기 스레드가 넘긴 명령을 받는 쪽. */
    fn commands(&self) -> &std::sync::mpsc::Receiver<DashboardCommand> {
        self.commands
            .as_ref()
            .expect("commands are released only in drop")
    }
}

impl Drop for DashboardReader {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        drop(self.commands.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/** @brief 대시보드에 보낼 지표 모음 JSON. */
fn dashboard_snapshot_json(st: &AppState) -> String {
    format!(
        "{{\"type\":\"snapshot\",\"data\":{}}}",
        metrics_only_json(st)
    )
}

/** @brief 대시보드에 보낼 상위 목록 JSON. */
fn dashboard_top_json(st: &AppState) -> String {
    format!("{{\"type\":\"top\",\"data\":{}}}", top_json(st))
}

/** @brief 대시보드에 보낼 작업 상태 JSON. */
fn dashboard_jobs_json(st: &AppState) -> String {
    format!(
        "{{\"type\":\"jobs\",\"data\":{}}}",
        (st.controls.jobs_list)()
    )
}

/**
 * @brief 웹소켓 프레임 하나를 읽는다.
 * @warning 클라이언트 프레임은 반드시 가려져 있어야 한다. 가려지지 않은 프레임을 받으면
 *          중간 장비를 속이는 공격에 쓰일 수 있다.
 */
fn ws_read_frame(stream: &mut SharedTcp) -> std::io::Result<(u8, Vec<u8>)> {
    let invalid =
        |message: &'static str| std::io::Error::new(std::io::ErrorKind::InvalidData, message);
    let mut header = [0u8; 2];
    stream.read_exact(&mut header)?;
    let fin = header[0] & 0x80 != 0;
    let rsv = header[0] & 0x70;
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    if !fin {
        return Err(invalid("Fragmented WebSocket messages are not supported"));
    }
    if rsv != 0 {
        return Err(invalid("Invalid WebSocket RSV bits"));
    }
    if !matches!(opcode, 0x1 | 0x8 | 0x9 | 0xA) {
        return Err(invalid("Unsupported WebSocket message type"));
    }
    if !masked {
        return Err(invalid("Rejected unmasked WebSocket frame"));
    }

    let length_code = header[1] & 0x7f;
    let mut length = length_code as u64;
    if length_code == 126 {
        let mut extended = [0u8; 2];
        stream.read_exact(&mut extended)?;
        length = u16::from_be_bytes(extended) as u64;
        if length < 126 {
            return Err(invalid("WebSocket frame length is not minimally encoded"));
        }
    } else if length_code == 127 {
        let mut extended = [0u8; 8];
        stream.read_exact(&mut extended)?;
        if extended[0] & 0x80 != 0 {
            return Err(invalid("Invalid WebSocket message length"));
        }
        length = u64::from_be_bytes(extended);
        if length <= u16::MAX as u64 {
            return Err(invalid("WebSocket frame length is not minimally encoded"));
        }
    }
    let control = matches!(opcode, 0x8..=0xA);
    if control && length > 125 {
        return Err(invalid("WebSocket control frame is too large"));
    }
    if length > MAX_WEBSOCKET_PAYLOAD as u64 {
        return Err(invalid("WebSocket frame is too large"));
    }

    let mut mask = [0u8; 4];
    stream.read_exact(&mut mask)?;
    let mut payload = vec![0u8; length as usize];
    stream.read_exact(&mut payload)?;
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    if opcode == 0x8 {
        if payload.len() == 1 {
            return Err(invalid("Invalid WebSocket close body"));
        }
        if payload.len() >= 2 {
            let code = u16::from_be_bytes([payload[0], payload[1]]);
            let valid_code = matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999);
            if !valid_code {
                return Err(invalid("Invalid WebSocket close code"));
            }
            if std::str::from_utf8(&payload[2..]).is_err() {
                return Err(invalid("WebSocket close reason is not valid UTF-8"));
            }
        }
    }
    if opcode == 0x1 && std::str::from_utf8(&payload).is_err() {
        return Err(invalid("WebSocket text message is not valid UTF-8"));
    }
    Ok((opcode, payload))
}

/** @brief 텍스트 프레임을 보낸다. */
fn ws_write_text(stream: &mut SharedTcp, text: &str) -> std::io::Result<()> {
    ws_write_frame(stream, 0x1, text.as_bytes())
}

/** @brief 프레임 하나를 보낸다. 서버 프레임은 가리지 않는다. */
fn ws_write_frame(stream: &mut SharedTcp, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut header = Vec::with_capacity(10);
    header.push(0x80 | (opcode & 0x0f));
    match payload.len() {
        length @ 0..=125 => header.push(length as u8),
        length @ 126..=65_535 => {
            header.push(126);
            header.extend_from_slice(&(length as u16).to_be_bytes());
        }
        length => {
            header.push(127);
            header.extend_from_slice(&(length as u64).to_be_bytes());
        }
    }
    stream.write_all(&header)?;
    stream.write_all(payload)?;
    stream.flush()
}

/**
 * @brief Sec-WebSocket-Key가 RFC 6455의 형식인지. 16바이트를 표준 base64로 적은 값이어야 한다.
 * @details 16바이트는 base64로 22글자에 == 가 붙은 24글자이고, 마지막 글자의 아래 4비트는
 *          0이다. 이것을 확인하지 않으면 아무 문자열에나 핸드셰이크를 마쳐 준다.
 */
fn websocket_key_valid(key: &str) -> bool {
    /** @brief 표준 base64 글자 하나의 6비트 값. */
    fn sextet(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = key.as_bytes();
    bytes.len() == 24
        && bytes.ends_with(b"==")
        && bytes[..22].iter().all(|&byte| sextet(byte).is_some())
        && sextet(bytes[21]).is_some_and(|last| last & 0x0f == 0)
}

/** @brief 표준 base64 인코딩. 웹소켓 핸드셰이크 응답에 쓴다. */
fn base64_standard(bytes: &[u8]) -> String {
    /** @brief base64 문자표. */
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        output.push(TABLE[(a >> 2) as usize] as char);
        output.push(TABLE[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[(((b & 0x0f) << 2) | (c >> 6)) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(TABLE[(c & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }
    output
}

#[cfg(test)]
/** @brief base64url 디코딩. 웹소켓 하위 프로토콜에 담긴 토큰을 푼다. */
fn base64_url_decode(value: &str) -> Option<Vec<u8>> {
    /** @brief 문자 하나를 6비트 값으로. */
    fn sextet(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let mut output = Vec::with_capacity(value.len() * 3 / 4);
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let remaining = bytes.len() - index;
        if remaining == 1 {
            return None;
        }
        let a = sextet(bytes[index])?;
        let b = sextet(bytes[index + 1])?;
        output.push((a << 2) | (b >> 4));
        if remaining > 2 {
            let c = sextet(bytes[index + 2])?;
            output.push((b << 4) | (c >> 2));
            if remaining > 3 {
                let d = sextet(bytes[index + 3])?;
                output.push((c << 6) | d);
            }
        }
        index += remaining.min(4);
    }
    Some(output)
}

/** @brief 질의 이벤트를 JSON으로. */
fn event_json(e: &QueryEvent) -> String {
    e.to_json()
}

/**
 * @brief 인증을 거친 요청을 실제 처리로 보낸다.
 *
 * @details 정적 자산과 헬스를 먼저 처리하고, 그다음 인증을 확인하고, 읽기 전용 등급을
 *          거른 뒤, 마지막 match가 각 경로를 콜백에 연결한다.
 * @note 새 경로를 더하면 OpenAPI 문서에도 함께 넣어야 한다. 테스트가 둘의 일치를 강제한다.
 */
fn route(
    method: &str,
    path: &str,
    auth: &str,
    session: &str,
    body: &str,
    caller: &Caller,
    st: &AppState,
) -> (&'static str, &'static str, String) {
    let peer_s = caller.label();

    if method == "GET" {
        if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
            return match acme_http01().lock_recover().get(token) {
                Some(v) => ("200 OK", "text/plain", v.clone()),
                None => (
                    "404 Not Found",
                    "text/plain",
                    "Requested path not found".to_string(),
                ),
            };
        }
    }

    match (method, path) {
        ("GET", "/") => {
            #[cfg(feature = "dashboard")]
            let page = (
                "200 OK",
                "text/html; charset=utf-8",
                include_str!("../dashboard/index.html").to_string(),
            );
            #[cfg(not(feature = "dashboard"))]
            let page = (
                "200 OK",
                "text/plain",
                "OnetDNS management API is running. The web dashboard is disabled.".to_string(),
            );
            return page;
        }

        ("GET", "/support.js") => {
            #[cfg(feature = "dashboard")]
            return (
                "200 OK",
                "application/javascript; charset=utf-8",
                include_str!("../dashboard/support.js").to_string(),
            );
            #[cfg(not(feature = "dashboard"))]
            return (
                "404 Not Found",
                "text/plain",
                "Requested path not found".to_string(),
            );
        }

        ("GET", "/react.js") => {
            #[cfg(feature = "dashboard")]
            return (
                "200 OK",
                "application/javascript; charset=utf-8",
                include_str!("../dashboard/react.js").to_string(),
            );
            #[cfg(not(feature = "dashboard"))]
            return (
                "404 Not Found",
                "text/plain",
                "Requested path not found".to_string(),
            );
        }
        ("GET", "/react-dom.js") => {
            #[cfg(feature = "dashboard")]
            return (
                "200 OK",
                "application/javascript; charset=utf-8",
                include_str!("../dashboard/react-dom.js").to_string(),
            );
            #[cfg(not(feature = "dashboard"))]
            return (
                "404 Not Found",
                "text/plain",
                "Requested path not found".to_string(),
            );
        }
        // 아이콘을 링크로만 주면 브라우저와 북마크·점검 도구가 여전히 이 주소를 부르고,
        // 인증 앞에서 막혀 감사 기록이 침입 시도처럼 보이는 401로 채워진다.
        ("GET", "/favicon.ico") => {
            #[cfg(feature = "dashboard")]
            return ("200 OK", "image/svg+xml", FAVICON_SVG.to_string());
            #[cfg(not(feature = "dashboard"))]
            return (
                "404 Not Found",
                "text/plain",
                "Requested path not found".to_string(),
            );
        }

        ("GET", "/healthz") => return ("200 OK", "text/plain", "ok".to_string()),

        ("GET", "/readyz") => {
            return if st.readiness.load(std::sync::atomic::Ordering::Acquire) {
                ("200 OK", "text/plain", "ready".to_string())
            } else {
                (
                    "503 Service Unavailable",
                    "text/plain",
                    "not ready".to_string(),
                )
            }
        }
        ("GET", "/openapi.json") => return ("200 OK", "application/json", openapi_json()),

        ("GET", "/v1/auth") => {
            let token = auth.strip_prefix("Bearer ").unwrap_or("");
            let body = match st.auth.resolve(token, session) {
                Some(r) => {
                    let user = st
                        .auth
                        .session_name(session)
                        .unwrap_or_else(|| bearer_actor(token));
                    auth_status_body(st, caller, true, r.as_str(), &user)
                }
                None => auth_status_body(st, caller, false, "none", ""),
            };
            return ("200 OK", "application/json", body);
        }
        _ => {}
    }

    let token = auth.strip_prefix("Bearer ").unwrap_or("");
    let role = match st.auth.resolve(token, session) {
        Some(r) => r,
        None => {
            st.audit.record_actor(
                "none",
                &audit_actor(&st.auth, token, session),
                method,
                path,
                &peer_s,
                401,
            );
            return (
                "401 Unauthorized",
                "text/plain",
                "Authentication required".to_string(),
            );
        }
    };
    let actor = audit_actor(&st.auth, token, session);

    // 읽기 전용 세션이 부를 수 있는 POST. 진단은 조사에 쓰라고 있는 것이라, 이것을 막으면
    // 조사할 때마다 관리자 토큰을 꺼내게 되고 그쪽이 더 위험하다.
    let readonly_safe_post = method == "POST"
        && matches!(
            path,
            "/v1/password" | "/v1/explain" | "/v1/resolve" | "/v1/policies/simulate"
        );
    if !role.allows(method) && !readonly_safe_post {
        st.audit
            .record_actor(role.as_str(), &actor, method, path, &peer_s, 403);
        return (
            "403 Forbidden",
            "text/plain",
            "Read-only access cannot perform this action".to_string(),
        );
    }

    let state_changing = is_state_changing_request(method, path);

    if state_changing && !st.readiness.load(std::sync::atomic::Ordering::Acquire) {
        st.audit
            .record_actor(role.as_str(), &actor, method, path, &peer_s, 503);
        return (
            "503 Service Unavailable",
            "text/plain",
            "DNS service settings are being applied. Try again when they are ready".to_string(),
        );
    }

    let _mutation_guard = requires_control_mutation_lock(method, path)
        .then(|| control_mutation_lock().lock_recover());

    let mut dispatch = || route_dispatch(method, path, session, body, st);
    let out = if requires_control_mutation_lock(method, path) {
        (st.controls.cluster_write)(method, path, body, &mut dispatch)
    } else {
        dispatch()
    };

    let code = status_code(out.0);
    if method != "GET" || code >= 400 {
        st.audit.record_request_actor(
            AuditContext {
                role: role.as_str(),
                actor: &actor,
                method,
                path,
                peer: &peer_s,
                status: code,
            },
            body,
        );
    }
    out
}

/**
 * @brief 인증과 권한 확인을 마친 요청을 처리한다.
 * @details 감사 기록은 호출하는 쪽이 남긴다. 클러스터 합의가 요청 결과를 실패로 바꿀 수 있어서,
 *          기록은 합의까지 끝난 최종 응답으로 남겨야 한다.
 */
fn route_dispatch(
    method: &str,
    path: &str,
    session: &str,
    body: &str,
    st: &AppState,
) -> ApiResponse {
    if let Some(rest) = path.strip_prefix("/v1/zones/").filter(|o| !o.is_empty()) {
        if let Some(origin) = rest.strip_suffix("/dnssec").filter(|o| !o.is_empty()) {
            let out: (&'static str, &'static str, String) = match method {
                "GET" => match (st.controls.zone_dnssec)(origin) {
                    Ok(j) => ("200 OK", "application/json", j),
                    Err(e) => (
                        "404 Not Found",
                        "application/json",
                        format!("{{\"error\":\"{}\"}}", jesc(&e)),
                    ),
                },
                _ => (
                    "405 Method Not Allowed",
                    "text/plain",
                    "Method not allowed on this path".to_string(),
                ),
            };
            return out;
        }
        if let Some(origin) = rest.strip_suffix("/records").filter(|o| !o.is_empty()) {
            let out: (&'static str, &'static str, String) = match method {
                "POST" => match (st.controls.zone_record_add)(origin, body) {
                    Ok(j) => ("200 OK", "application/json", j),
                    Err(e) => (
                        "400 Bad Request",
                        "application/json",
                        format!("{{\"error\":\"{}\"}}", jesc(&e)),
                    ),
                },
                "DELETE" => match (st.controls.zone_record_delete)(origin, body) {
                    Ok(j) => ("200 OK", "application/json", j),
                    Err(e) => (
                        "404 Not Found",
                        "application/json",
                        format!("{{\"error\":\"{}\"}}", jesc(&e)),
                    ),
                },
                _ => (
                    "405 Method Not Allowed",
                    "text/plain",
                    "Method not allowed on this path".to_string(),
                ),
            };
            return out;
        }
        let origin = rest;
        let out: (&'static str, &'static str, String) = match method {
            "GET" => match (st.controls.zone_get)(origin) {
                Ok(j) => ("200 OK", "application/json", j),
                Err(e) => (
                    "404 Not Found",
                    "application/json",
                    format!("{{\"error\":\"{}\"}}", jesc(&e)),
                ),
            },
            "PUT" => match (st.controls.zone_put)(origin, body) {
                Ok(j) => ("200 OK", "application/json", j),
                Err(e) => (
                    "400 Bad Request",
                    "application/json",
                    format!("{{\"error\":\"{}\"}}", jesc(&e)),
                ),
            },
            "DELETE" => match (st.controls.zone_delete)(origin) {
                Ok(j) => ("200 OK", "application/json", j),
                Err(e) => (
                    "404 Not Found",
                    "application/json",
                    format!("{{\"error\":\"{}\"}}", jesc(&e)),
                ),
            },
            _ => (
                "405 Method Not Allowed",
                "text/plain",
                "Method not allowed on this path".to_string(),
            ),
        };
        return out;
    }

    if method == "GET" {
        if let Some(range) = path.strip_prefix("/v1/stats/history/") {
            let out: (&'static str, &'static str, String) = match range.parse::<u64>() {
                Ok(value) if matches!(value, 60 | 300 | 3_600 | 86_400 | 604_800) => {
                    ("200 OK", "application/json", stats_history_json(st, value))
                }
                _ => (
                    "400 Bad Request",
                    "application/json",
                    "{\"error\":\"Unsupported stats range\"}".to_string(),
                ),
            };
            return out;
        }
    }

    if let Some(id_s) = path
        .strip_prefix("/v1/jobs/")
        .filter(|s| !s.is_empty() && *s != "refresh")
    {
        if method == "GET" {
            let out: (&'static str, &'static str, String) = match id_s.parse::<u64>() {
                Ok(id) => match (st.controls.job_get)(id) {
                    Ok(j) => ("200 OK", "application/json", j),
                    Err(e) => (
                        "404 Not Found",
                        "application/json",
                        format!("{{\"error\":\"{}\"}}", jesc(&e)),
                    ),
                },
                Err(_) => (
                    "400 Bad Request",
                    "application/json",
                    "{\"error\":\"Invalid job ID\"}".to_string(),
                ),
            };
            return out;
        }
    }

    match (method, path) {
        ("GET", "/v1/stats") => ("200 OK", "application/json", stats_json(st)),
        ("GET", "/v1/metrics") => ("200 OK", "application/json", metrics_only_json(st)),
        ("GET", "/v1/queries") => ("200 OK", "application/json", recent_json(st)),
        ("GET", "/v1/top") => ("200 OK", "application/json", top_json(st)),
        ("GET", "/v1/audit") => ("200 OK", "application/json", st.audit.json()),
        ("GET", "/v1/backup") => ("200 OK", "application/json", (st.controls.export)()),
        ("GET", "/metrics") => ("200 OK", "text/plain; version=0.0.4", metrics_text(st)),
        ("POST", "/v1/reload") => counts_resp((st.controls.reload)()),
        ("POST", "/v1/block") => counts_resp((st.controls.block_add)(&body_str(body, "domain"))),
        ("POST", "/v1/allow") => counts_resp((st.controls.allow_add)(&body_str(body, "domain"))),
        ("POST", "/v1/restore") => counts_resp((st.controls.import)(body)),
        ("POST", "/v1/services") => {
            let svc = body_str(body, "service");
            let en = body_bool(body, "enable");
            counts_resp((st.controls.service_set)(&svc, en))
        }
        ("POST", "/v1/safesearch") => {
            let en = body_bool(body, "enable");
            match (st.controls.safesearch_set)(en) {
                Ok(()) => (
                    "200 OK",
                    "application/json",
                    format!("{{\"safe_search\":{en}}}"),
                ),
                Err(e) => (
                    "400 Bad Request",
                    "application/json",
                    format!("{{\"error\":{}}}", json::escape(&e)),
                ),
            }
        }
        ("POST", "/v1/password") => {
            let Some(name) = st.auth.session_name(session) else {
                return (
                    "400 Bad Request",
                    "application/json",
                    "{\"error\":\"Sign in with a user account to change the password\"}"
                        .to_string(),
                );
            };
            let current = body_str(body, "current_password");
            let next = body_str(body, "new_password");

            if let Err(error) = crate::password::check_new_password(&next) {
                return (
                    "400 Bad Request",
                    "application/json",
                    format!("{{\"error\":{}}}", json::escape(&error.to_string())),
                );
            }
            match st.auth.verify_user(&name, &current) {
                crate::password::VerifyResult::Match => {}
                crate::password::VerifyResult::Mismatch => {
                    return (
                        "403 Forbidden",
                        "application/json",
                        "{\"error\":\"Current password is incorrect\"}".to_string(),
                    );
                }
                crate::password::VerifyResult::Busy => {
                    return (
                        "503 Service Unavailable",
                        "application/json",
                        "{\"error\":\"Too many password checks. Try again shortly\"}".to_string(),
                    );
                }
            }
            let hash = match crate::password::hash_password(&next) {
                Ok(hash) => hash,
                Err(error) => {
                    let status = match error {
                        crate::password::PasswordError::Busy => "503 Service Unavailable",
                        _ => "400 Bad Request",
                    };
                    return (
                        status,
                        "application/json",
                        format!("{{\"error\":{}}}", json::escape(&error.to_string())),
                    );
                }
            };
            match (st.controls.password_change)(&name, &hash) {
                Ok(j) => {
                    if !st.auth.update_user_hash(&name, hash) {
                        return (
                            "409 Conflict",
                            "application/json",
                            "{\"error\":\"The user account was deleted while changing the password\"}"
                                .to_string(),
                        );
                    }
                    st.auth.revoke_user_sessions(&name);
                    ("200 OK", "application/json", j)
                }
                Err(e) => (
                    "400 Bad Request",
                    "application/json",
                    format!("{{\"error\":{}}}", json::escape(&e)),
                ),
            }
        }
        ("POST", "/v1/querylog/clear") => match st.stats.clear_recent() {
            Ok(()) => (
                "200 OK",
                "application/json",
                "{\"cleared\":true}".to_string(),
            ),
            Err(e) => (
                "500 Internal Server Error",
                "application/json",
                format!(
                    "{{\"cleared\":false,\"error\":{}}}",
                    json::escape(&e.to_string())
                ),
            ),
        },

        ("POST", "/v1/config/validate") => match (st.controls.config_validate)(body) {
            Ok(()) => ("200 OK", "application/json", "{\"valid\":true}".to_string()),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                format!("{{\"valid\":false,\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("POST", "/v1/config/diff") => match (st.controls.config_diff)(body) {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("POST", "/v1/config/apply") => match (st.controls.config_apply)(body) {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("POST", "/v1/config/set") => match (st.controls.config_set)(body) {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("POST", "/v1/config/set/diff") => match (st.controls.config_set_diff)(body) {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("GET", "/v1/config/schema") => {
            ("200 OK", "application/json", (st.controls.config_schema)())
        }
        ("POST", "/v1/upstreams/test") => match (st.controls.upstream_test)(body) {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("POST", "/v1/cache/flush") => ("200 OK", "application/json", (st.controls.cache_flush)()),
        ("GET", "/v1/tokens") => ("200 OK", "application/json", (st.controls.tokens_list)()),
        ("POST", "/v1/tokens") => match (st.controls.token_add)(body) {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("DELETE", "/v1/tokens") => match (st.controls.token_delete)(body) {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "404 Not Found",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("GET", "/v1/rewrites") => ("200 OK", "application/json", (st.controls.rewrites_list)()),
        ("POST", "/v1/rewrites") => match (st.controls.rewrite_add)(body) {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("DELETE", "/v1/rewrites") => match (st.controls.rewrite_delete)(body) {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "404 Not Found",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("GET", "/v1/services") => (
            "200 OK",
            "application/json",
            (st.controls.services_catalog)(),
        ),
        ("GET", "/v1/access") => ("200 OK", "application/json", (st.controls.access_list)()),
        ("GET", "/v1/tls") => ("200 OK", "application/json", (st.controls.tls_status)()),
        ("POST", "/v1/tls/validate") => match (st.controls.tls_validate)() {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("POST", "/v1/tls/configure") => result_resp((st.controls.tls_configure)(body)),
        ("POST", "/v1/tls/revocation-check") => {
            result_resp((st.controls.tls_revocation_check)(body))
        }
        ("POST", "/v1/acme/issue") => result_resp((st.controls.acme_issue)(body)),
        ("POST", "/v1/config/rollback") => conflict_resp((st.controls.config_rollback)()),
        ("POST", "/v1/policies/simulate") => (
            "200 OK",
            "application/json",
            (st.controls.policy_simulate)(body),
        ),

        ("POST", "/v1/explain") => ("200 OK", "application/json", (st.controls.explain)(body)),
        ("POST", "/v1/resolve") => result_resp((st.controls.resolve_probe)(body)),
        ("GET", "/v1/cluster/nodes") => {
            ("200 OK", "application/json", (st.controls.cluster_status)())
        }
        ("POST", "/v1/cluster/propose") => result_resp((st.controls.cluster_propose)(body)),

        ("GET", "/v1/listeners") => (
            "200 OK",
            "application/json",
            (st.controls.listeners_status)(),
        ),
        ("GET", "/v1/system/network-adapters") => result_resp((st.controls.net_adapters)()),
        ("POST", "/v1/system/firewall") => result_resp((st.controls.firewall_set)(body)),
        ("GET", "/v1/system/service") => (
            "200 OK",
            "application/json",
            (st.controls.boot_service_status)(),
        ),
        ("POST", "/v1/system/service") => result_resp((st.controls.boot_service_set)(body)),
        ("POST", "/v1/system/dns-client") => result_resp((st.controls.dns_client_set)(body)),
        ("POST", "/v1/system/dns-client/restore") => {
            result_resp((st.controls.dns_client_restore)(body))
        }
        ("GET", "/v1/system/update") => {
            ("200 OK", "application/json", (st.controls.update_status)())
        }
        ("POST", "/v1/system/update/check") => conflict_resp((st.controls.update_check)()),
        ("POST", "/v1/system/update/apply") => match update_version(body) {
            Ok(version) => conflict_resp((st.controls.update_apply)(&version)),
            Err(error) => result_resp(Err(error)),
        },
        ("POST", "/v1/system/update/rollback") => conflict_resp((st.controls.update_rollback)()),
        ("GET", "/v1/zones") => ("200 OK", "application/json", (st.controls.zones_list)()),
        ("GET", "/v1/config") => ("200 OK", "application/json", (st.controls.config_desired)()),
        ("GET", "/v1/config/effective") => (
            "200 OK",
            "application/json",
            (st.controls.config_effective)(),
        ),
        ("GET", "/v1/config/status") => {
            ("200 OK", "application/json", (st.controls.config_status)())
        }
        ("POST", "/v1/config/reload") => result_resp((st.controls.config_reload)()),
        ("GET", "/v1/plugins") => (
            "200 OK",
            "application/json",
            (st.controls.plugins_metrics)(),
        ),
        ("GET", "/v1/filter/report") => {
            ("200 OK", "application/json", (st.controls.filter_report)())
        }
        ("GET", "/v1/filter/top-rules") => (
            "200 OK",
            "application/json",
            (st.controls.filter_top_rules)(),
        ),
        ("GET", "/v1/filter/sources") => {
            ("200 OK", "application/json", (st.controls.filter_sources)())
        }

        ("GET", "/v1/filter/subscriptions") => (
            "200 OK",
            "application/json",
            (st.controls.subscriptions_list)(),
        ),
        ("POST", "/v1/filter/subscriptions") => match (st.controls.subscription_add)(body) {
            Ok(j) => ("200 OK", "application/json", j),
            Err(e) => (
                "400 Bad Request",
                "application/json",
                format!("{{\"error\":\"{}\"}}", jesc(&e)),
            ),
        },
        ("DELETE", "/v1/filter/subscriptions") => {
            match (st.controls.subscription_remove)(&body_str(body, "url")) {
                Ok(j) => ("200 OK", "application/json", j),
                Err(e) => (
                    "404 Not Found",
                    "application/json",
                    format!("{{\"error\":\"{}\"}}", jesc(&e)),
                ),
            }
        }
        ("PATCH", "/v1/filter/subscriptions") => {
            result_resp((st.controls.subscription_update)(body))
        }
        ("POST", "/v1/filter/subscriptions/refresh") => {
            result_resp((st.controls.subscription_refresh)(body))
        }
        ("GET", "/v1/filter/rules") => (
            "200 OK",
            "application/json",
            (st.controls.filter_rules_list)(),
        ),
        ("POST", "/v1/filter/rules") => result_resp((st.controls.filter_rule_mutate)(body, true)),
        ("DELETE", "/v1/filter/rules") => {
            result_resp((st.controls.filter_rule_mutate)(body, false))
        }
        ("GET", "/v1/clients") => ("200 OK", "application/json", (st.controls.clients_list)()),

        ("POST", "/v1/clients") => result_resp((st.controls.client_add)(body)),
        ("DELETE", "/v1/clients") => {
            result_resp((st.controls.client_remove)(&body_str(body, "name")))
        }
        ("PATCH", "/v1/clients") => result_resp((st.controls.client_update)(body)),
        ("GET", "/v1/upstreams") => ("200 OK", "application/json", (st.controls.upstreams_list)()),

        ("POST", "/v1/upstreams") => match upstream_field(body) {
            Ok(addr) => result_resp((st.controls.upstream_add)(&addr)),
            Err(error) => result_resp(Err(error)),
        },
        ("DELETE", "/v1/upstreams") => match upstream_field(body) {
            Ok(addr) => result_resp((st.controls.upstream_remove)(&addr)),
            Err(error) => result_resp(Err(error)),
        },
        ("GET", "/v1/jobs") => ("200 OK", "application/json", (st.controls.jobs_list)()),
        ("POST", "/v1/jobs/refresh") => ("200 OK", "application/json", (st.controls.job_refresh)()),
        ("GET", "/v1/dhcp/leases") => ("200 OK", "application/json", (st.controls.dhcp_leases)()),
        ("POST", "/v1/dhcp/leases") => result_resp((st.controls.dhcp_lease_put)(body)),
        ("GET", "/v1/dhcp/static") => (
            "200 OK",
            "application/json",
            (st.controls.dhcp_static_list)(),
        ),
        ("POST", "/v1/dhcp/static") => result_resp((st.controls.dhcp_static_add)(body)),
        ("DELETE", "/v1/dhcp/static") => {
            match (st.controls.dhcp_static_remove)(&body_str(body, "identity")) {
                Ok(j) => ("200 OK", "application/json", j),
                Err(e) => (
                    "404 Not Found",
                    "application/json",
                    format!("{{\"error\":\"{}\"}}", jesc(&e)),
                ),
            }
        }
        _ => (
            "404 Not Found",
            "text/plain",
            "Requested path not found".to_string(),
        ),
    }
}

/** @brief 문자열을 JSON 문자열 값으로 이스케이프한다. */
fn jesc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/** @brief 상태 줄에서 숫자 코드를 추출한다. */
fn status_code(s: &str) -> u16 {
    s.split(|c: char| !c.is_ascii_digit())
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

/** @brief 목록 변경 결과를 응답으로 만든다. */
fn counts_resp(r: Result<ListCounts, String>) -> (&'static str, &'static str, String) {
    match r {
        Ok(c) => (
            "200 OK",
            "application/json",
            format!("{{\"block\":{},\"allow\":{}}}", c.block, c.allow),
        ),
        Err(e) => ("400 Bad Request", "text/plain", e),
    }
}

/** @brief 문자열 결과를 응답으로 만든다. */
fn result_resp(r: Result<String, String>) -> (&'static str, &'static str, String) {
    match r {
        Ok(j) => ("200 OK", "application/json", j),
        Err(e) => (
            "400 Bad Request",
            "application/json",
            format!("{{\"error\":\"{}\"}}", jesc(&e)),
        ),
    }
}

/** @brief 요청은 맞지만 지금 상태로는 할 수 없는 동작의 결과를 응답으로 만든다. 실패는 409 다. */
fn conflict_resp(r: Result<String, String>) -> ApiResponse {
    match r {
        Ok(j) => ("200 OK", "application/json", j),
        Err(e) => (
            "409 Conflict",
            "application/json",
            format!("{{\"error\":\"{}\"}}", jesc(&e)),
        ),
    }
}

/** @brief 업데이트 적용 요청에서 운영자가 확인한 버전을 읽는다. */
fn update_version(body: &str) -> Result<String, String> {
    json::parse(body)
        .ok()
        .and_then(|json| {
            json.get("version")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .map(String::from)
        })
        .filter(|version| !version.is_empty())
        .ok_or_else(|| {
            "The request body must be an object with the version shown by the last check"
                .to_string()
        })
}

/** @brief 요청 본문에서 업스트림 주소를 추출해 검증한다. */
fn upstream_field(body: &str) -> Result<String, String> {
    let json =
        json::parse(body).map_err(|error| format!("Could not parse JSON request body: {error}"))?;
    let json::Json::Obj(fields) = json else {
        return Err("Upstream DNS request must be an object with a single addr string".into());
    };
    if fields.len() != 1 || fields[0].0 != "addr" {
        return Err("Upstream DNS request must contain only an addr string".into());
    }
    fields[0]
        .1
        .as_str()
        .map(str::trim)
        .filter(|addr| !addr.is_empty())
        .map(String::from)
        .ok_or_else(|| "addr must be a non-empty string".into())
}

/** @brief 본문 JSON에서 문자열 필드를 읽는다. */
fn body_str(body: &str, key: &str) -> String {
    json::parse(body)
        .ok()
        .and_then(|j| j.get(key).and_then(|v| v.as_str().map(String::from)))
        .unwrap_or_default()
}

/** @brief 본문 JSON에서 참거짓 필드를 읽는다. */
fn body_bool(body: &str, key: &str) -> bool {
    json::parse(body)
        .ok()
        .and_then(|j| j.get(key).and_then(|v| v.as_bool()))
        .unwrap_or(false)
}

/** @brief 지표를 JSON 객체로. */
fn metrics_obj(m: &MetricsSnapshot) -> String {
    let by_t: Vec<String> = m
        .by_transport
        .iter()
        .map(|(t, c)| format!("{}:{}", json::escape(t), c))
        .collect();
    format!(
        "{{\"total\":{},\"resolved\":{},\"blocked\":{},\"rewritten\":{},\"denied\":{},\"refused\":{},\"throttled\":{},\"servfail\":{},\"by_transport\":{{{}}},\"avg_latency_ms\":{:.1},\"cache_hit_pct\":{:.1},\"dropped_log_events\":{},\"dropped_stat_events\":{},\"dropped_stream_events\":{},\"persist_failures\":{}}}",
        m.total, m.resolved, m.blocked, m.rewritten, m.denied, m.refused, m.throttled, m.servfail, by_t.join(","),
        m.avg_latency_ms, m.cache_hit_pct, m.dropped_log_events, m.dropped_stat_events, m.dropped_stream_events, m.persist_failures
    )
}

/** @brief 통계 응답 JSON. */
fn stats_json(st: &AppState) -> String {
    let m = st.stats.metrics.snapshot();
    let recent: Vec<String> = st.stats.recent(2_000).iter().map(event_json).collect();
    format!(
        "{{\"metrics\":{},\"recent\":[{}]}}",
        metrics_obj(&m),
        recent.join(",")
    )
}

/** @brief 지표만 담은 JSON. */
fn metrics_only_json(st: &AppState) -> String {
    let m = st.stats.metrics.snapshot();
    format!("{{\"metrics\":{}}}", metrics_obj(&m))
}

/** @brief 최근 질의 기록 JSON. */
fn recent_json(st: &AppState) -> String {
    let recent: Vec<String> = st.stats.recent(2_000).iter().map(event_json).collect();
    format!("{{\"recent\":[{}]}}", recent.join(","))
}

/** @brief 그래프용 이력 JSON. */
fn stats_history_json(st: &AppState, range_secs: u64) -> String {
    let points = st.stats.metrics.history(range_secs, 59);
    let items = points
        .iter()
        .map(|point| {
            format!(
                "{{\"ts_ms\":{},\"queries\":{},\"blocked\":{},\"avg_latency_ms\":{:.3},\"cache_hit_pct\":{:.3}}}",
                point.ts_ms,
                point.queries,
                point.blocked,
                point.avg_latency_ms,
                point.cache_hit_pct
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"range_secs\":{range_secs},\"points\":[{items}]}}")
}

/** @brief 상위 목록 JSON. */
fn top_json(st: &AppState) -> String {
    let t = st.stats.top(20);
    let pairs = |v: &[(String, u64)]| -> String {
        v.iter()
            .map(|(k, c)| format!("[{},{}]", json::escape(k), c))
            .collect::<Vec<_>>()
            .join(",")
    };
    format!(
        "{{\"domains\":[{}],\"blocked\":[{}],\"clients\":[{}]}}",
        pairs(&t.domains),
        pairs(&t.blocked),
        pairs(&t.clients)
    )
}

/** @brief Prometheus 형식 지표. 외부 수집기가 읽는다. */
fn metrics_text(st: &AppState) -> String {
    let m = st.stats.metrics.snapshot();
    let mut s = String::new();
    let line = |s: &mut String, name: &str, help: &str, val: u64| {
        s.push_str(&format!(
            "# TYPE {name} counter\n# HELP {name} {help}\n{name} {val}\n"
        ));
    };
    line(&mut s, "onetdns_queries_total", "Total queries", m.total);
    line(
        &mut s,
        "onetdns_resolved_total",
        "Resolved or rewritten responses",
        m.resolved,
    );
    line(
        &mut s,
        "onetdns_blocked_total",
        "Blocked DNS responses",
        m.blocked,
    );
    line(
        &mut s,
        "onetdns_rewritten_total",
        "Rewritten responses",
        m.rewritten,
    );
    line(
        &mut s,
        "onetdns_denied_total",
        "Requests refused by access control rules",
        m.denied,
    );
    line(
        &mut s,
        "onetdns_refused_total",
        "Requests answered with REFUSED",
        m.refused,
    );
    line(
        &mut s,
        "onetdns_throttled_total",
        "Requests rejected by rate limiting",
        m.throttled,
    );
    line(
        &mut s,
        "onetdns_servfail_total",
        "Server failure (SERVFAIL) responses",
        m.servfail,
    );
    line(
        &mut s,
        "onetdns_cache_hits_total",
        "Response cache hits",
        m.cache_hits,
    );
    line(
        &mut s,
        "onetdns_cache_lookups_total",
        "Response cache lookups",
        m.cache_lookups,
    );
    line(
        &mut s,
        "onetdns_query_latency_microseconds_total",
        "Total processing time. Divide by the count for the average",
        m.latency_sum_us,
    );
    line(
        &mut s,
        "onetdns_query_latency_measured_total",
        "Queries with measured processing time",
        m.latency_count,
    );
    line(
        &mut s,
        "onetdns_dropped_log_events_total",
        "Query events dropped because the processing queue was full",
        m.dropped_log_events,
    );
    line(
        &mut s,
        "onetdns_dropped_stat_events_total",
        "Events that lost top-list attribution because collection slots were full. Total query counts are unaffected",
        m.dropped_stat_events,
    );
    line(
        &mut s,
        "onetdns_dropped_stream_events_total",
        "Live events not sent because a subscriber was slow",
        m.dropped_stream_events,
    );
    line(
        &mut s,
        "onetdns_persist_failures_total",
        "Failures saving stats or the query log",
        m.persist_failures,
    );
    line(
        &mut s,
        "onetdns_request_panics_total",
        "Request handling faults isolated and recovered",
        onetdns_core::isolation::request_panic_count(),
    );
    let supervisor_restarts = std::env::var("ONETDNS_SUPERVISOR_RESTARTS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    line(
        &mut s,
        "onetdns_supervisor_restarts_total",
        "DNS worker processes restarted by the supervisor",
        supervisor_restarts,
    );
    s.push_str("# TYPE onetdns_queries_by_transport counter\n");
    for (t, c) in &m.by_transport {
        s.push_str(&format!(
            "onetdns_queries_by_transport{{transport=\"{t}\"}} {c}\n"
        ));
    }
    s.push_str(&(st.controls.metrics_extra)());
    s
}

/** @brief OpenAPI 문서. 인증 없이 볼 수 있다. */
fn openapi_json() -> String {
    /** @brief 문서 본문. 경로를 더하면 여기도 함께 고쳐야 한다. */
    const SPEC: &str = r##"{
  "openapi": "3.1.0",
  "info": {
    "title": "OnetDNS Management API",
    "version": "1",
    "description": "OnetDNS management API. Authenticate with a Bearer token or a cookie session. The admin role can change settings; the read-only role can only view and run diagnostics. Setting changes and authentication or authorization failures are recorded in /v1/audit."
  },
  "components": {
    "securitySchemes": {
      "bearer": { "type": "http", "scheme": "bearer" }
    }
  },
  "security": [ { "bearer": [] } ],
  "paths": {
    "/healthz": { "get": { "summary": "Process liveness check", "security": [], "responses": { "200": { "description": "ok" } } } },
    "/openapi.json": { "get": { "summary": "This OpenAPI spec", "security": [], "responses": { "200": { "description": "OpenAPI 3.1 document" } } } },
    "/v1/auth": { "get": { "summary": "Current authentication state and role", "description": "The control token is for the API only and is never turned into a session cookie. Web console sessions are issued only by /v1/login.", "security": [], "responses": { "200": { "description": "{login_enabled,authenticated,role,user}" } } } },
    "/v1/setup": { "post": { "summary": "Create the first admin account", "description": "Available only while no account exists. Returns 409 once any account exists.", "security": [], "responses": { "200": { "description": "Session cookie and {ok,user,role}" }, "400": { "description": "Username or password does not meet the rules" }, "409": { "description": "An account already exists" } } } },
    "/v1/login": { "post": { "summary": "Sign in with username and password", "security": [], "responses": { "200": { "description": "Session cookie and {authenticated,role,user}" }, "401": { "description": "Credentials do not match" } } } },
    "/v1/logout": { "post": { "summary": "End the current sign-in session", "responses": { "200": { "description": "{logged_out:true}" } } } },
    "/v1/stats": { "get": { "summary": "Stats and recent DNS queries", "responses": { "200": { "description": "Cumulative stats and recent queries" }, "401": { "description": "Not authenticated" } } } },
    "/v1/metrics": { "get": { "summary": "Dashboard stats", "responses": { "200": { "description": "{metrics:{...}}" } } } },
    "/v1/queries": { "get": { "summary": "Recent DNS queries", "responses": { "200": { "description": "{recent:[...]}" } } } },
    "/v1/stats/history/{range}": { "get": { "summary": "Per-second time series of total and blocked queries", "parameters": [ { "name": "range", "in": "path", "required": true, "schema": { "type": "integer", "enum": [60,300,3600,86400,604800] } } ], "responses": { "200": { "description": "Time series points for the selected range" }, "400": { "description": "Unsupported range" } } } },
    "/v1/top": { "get": { "summary": "Most queried domains, blocked entries, and clients", "responses": { "200": { "description": "Top entries by query count" } } } },
    "/v1/audit": { "get": { "summary": "Management actions and access denials", "responses": { "200": { "description": "Recent management actions and access denials" } } } },
    "/v1/backup": { "get": { "summary": "Back up user filter data: block and allow rules, blocked services, refused domains, safe search", "responses": { "200": { "description": "{version,block,allow,services,refused_domains,safe_search}" } } } },
    "/v1/dashboard/ws": { "get": { "summary": "Dashboard WebSocket", "description": "Sends query events, stats, top entries, and job status over one connection. Uses the onetdns.v1 subprotocol; pass resume.<event_id> to resume after reconnecting.", "responses": { "101": { "description": "WebSocket connection" } } } },
    "/metrics": { "get": { "summary": "Prometheus exposition", "responses": { "200": { "description": "text/plain 0.0.4" } } } },
    "/v1/reload": { "post": { "summary": "Reload blocklists from the current settings", "responses": { "200": { "description": "{block,allow}" }, "403": { "description": "This action requires the admin role" } } } },
    "/v1/block": { "post": { "summary": "Add a blocked domain", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "domain": { "type": "string" } }, "required": ["domain"] } } } }, "responses": { "200": { "description": "{block,allow}" } } } },
    "/v1/allow": { "post": { "summary": "Add an allowed domain", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "domain": { "type": "string" } }, "required": ["domain"] } } } }, "responses": { "200": { "description": "{block,allow}" } } } },
    "/v1/restore": { "post": { "summary": "Restore a user filter data backup (replaces everything)", "requestBody": { "content": { "application/json": { "schema": { "type": "object" } } } }, "responses": { "200": { "description": "{block,allow}" }, "400": { "description": "Invalid input" } } } },
    "/v1/safesearch": { "post": { "summary": "Change the safe search setting", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "enable": { "type": "boolean" } }, "required": ["enable"] } } } }, "responses": { "200": { "description": "{safe_search}" }, "400": { "description": "Could not save the config file" } } } },
    "/v1/password": { "post": { "summary": "Change the signed-in user's password and revoke all of that user's sessions", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "current_password": { "type": "string" }, "new_password": { "type": "string", "minLength": 12 } }, "required": ["current_password","new_password"] } } } }, "responses": { "200": { "description": "{changed,reloading}" }, "403": { "description": "Current password does not match" } } } },
    "/v1/querylog/clear": { "post": { "summary": "Clear the recent query log", "responses": { "200": { "description": "{cleared}" } } } },
    "/v1/config/validate": { "post": { "summary": "Check whether a TOML fragment is valid when merged into the current config. The actual config is not changed", "requestBody": { "content": { "text/plain": { "schema": { "type": "string" } } } }, "responses": { "200": { "description": "{valid:true}" }, "400": { "description": "{valid:false,error}" } } } },
    "/v1/config/diff": { "post": { "summary": "Compare a TOML fragment with the current config file and show which entries change and how they are applied", "requestBody": { "content": { "text/plain": { "schema": { "type": "string" } } } }, "responses": { "200": { "description": "{added[],removed[],changed[],effective_changed[],hot_reload[],service_restart[],restart_required}" }, "400": { "description": "Returns the error when the proposed config is invalid" } } } },
    "/v1/config/apply": { "post": { "summary": "Apply a config fragment (admin only): changes only the given top-level entries and keeps the rest. Filters, access control, rate limits, the query log, and upstream DNS server addresses apply without interrupting service", "requestBody": { "content": { "text/plain": { "schema": { "type": "string" } } } }, "responses": { "200": { "description": "{applied,mode,restart_required,reloading,changed}" }, "400": { "description": "Returns the error when the input is invalid or the config file cannot be used" } } } },
    "/v1/config/rollback": { "post": { "summary": "Roll back to the state before the last config apply (admin only)", "responses": { "200": { "description": "{rolled_back,restart_required}" }, "409": { "description": "Returns an error when there is no previous config" } } } },
    "/v1/policies/simulate": { "post": { "summary": "Preview the policy and filter result for a DNS query", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "client": { "type": "string" }, "qname": { "type": "string" }, "qtype": { "type": "string" } }, "required": ["qname"] } } } }, "responses": { "200": { "description": "{policy,filter,filter_stage,filter_matched,filter_list,decision}" } } } },
    "/v1/explain": { "post": { "summary": "Preview the decision for a DNS query: explains the policy, filter, response code, and handling without sending a real query or changing the cache", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "client": { "type": "string" }, "client_id": { "type": "string" }, "qname": { "type": "string" }, "qtype": { "type": "string" } }, "required": ["qname"] } } } }, "responses": { "200": { "description": "{decision,rcode,policy,filter,filter_stage,filter_matched,filter_list,matched,client_safe_search,backend,dnssec,resolution}" } } } },
    "/readyz": { "get": { "summary": "DNS service readiness check", "security": [], "responses": { "200": { "description": "ready" }, "503": { "description": "not ready" } } } },
    "/v1/cluster/nodes": { "get": { "summary": "Cluster node status. With consensus enabled, includes role, term, leader, and apply position", "responses": { "200": { "description": "{self:{id,role,backend,listeners,leader,term,commit_index,last_applied,last_index,snapshot_index,retained_log_entries,fatal,healthy,version},peers:[{id,url,healthy,role,rtt_ms,version}],identity:{node_id,public_key,peer_entry}}. identity.public_key is derived from the configured Raft signing key, and peer_entry is the entry to add as-is to cluster_raft_peers on other nodes. Both are null without a signing key. self.version is this node's OnetDNS version. peers[].version is the version in the last authenticated cluster message from that node, null until one arrives. Nodes ignore cluster messages from nodes that run a different version" } } } },
    "/v1/cluster/propose": { "post": { "summary": "Propose a config change to the Raft leader (admin only): replicates {patch:{key:value}} to every node and applies it. A null value removes the entry. Node-local settings are rejected. With Raft enabled, other config-changing management requests are also accepted only on the leader and replicated the same way; followers reject them with 409", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "patch": { "type": "object" } }, "required": ["patch"], "additionalProperties": false } } } }, "responses": { "200": { "description": "{committed,applied,index}" }, "400": { "description": "{error}" } } } },
    "/v1/listeners": { "get": { "summary": "Active DNS listen addresses and per-transport status", "responses": { "200": { "description": "{listeners:[...]}" } } } },
    "/v1/system/network-adapters": { "get": { "summary": "List host network adapters", "responses": { "200": { "description": "Adapter JSON" }, "400": { "description": "Could not retrieve the information" } } } },
    "/v1/system/firewall": { "post": { "summary": "Apply the firewall rules the DNS listen addresses need (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object" } } } }, "responses": { "200": { "description": "Result" }, "400": { "description": "Could not apply the change" } } } },
    "/v1/resolve": { "post": { "summary": "Send one real query to this server", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "qname": { "type": "string" }, "qtype": { "type": "string" } }, "required": ["qname"] } } } }, "responses": { "200": { "description": "{rcode,elapsed_ms,server,answers[]}" }, "400": { "description": "Could not send the query" } } } },
    "/v1/system/service": { "get": { "summary": "Boot service registration status", "responses": { "200": { "description": "{supported,installed,running}" } } }, "post": { "summary": "Install or remove the boot service (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "action": { "type": "string", "enum": ["install", "uninstall"] } }, "required": ["action"] } } } }, "responses": { "200": { "description": "Result" }, "400": { "description": "Could not apply" } } } },
    "/v1/system/dns-client": { "post": { "summary": "Change the OS DNS client settings (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object" } } } }, "responses": { "200": { "description": "Result" }, "400": { "description": "Could not apply the change" } } } },
    "/v1/system/dns-client/restore": { "post": { "summary": "Restore the OS DNS client settings (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object" } } } }, "responses": { "200": { "description": "Restore result" }, "400": { "description": "Could not restore" } } } },
    "/v1/system/update": { "get": { "summary": "Self-update status of this node: its version, whether this build updates itself and why not, how a new version is started, the last release check, the update record, and the version a rollback would reinstall", "responses": { "200": { "description": "{version,target,participating,reason,launch,release_check,task,checked_at,result,new_version,release_url,detail,record,rollback}" } } } },
    "/v1/system/update/check": { "post": { "summary": "Start a job that checks GitHub for a newer release (admin only)", "responses": { "200": { "description": "{id,status}" }, "409": { "description": "{error}" } } } },
    "/v1/system/update/apply": { "post": { "summary": "Start a job that installs the release found by the last check and starts it (admin only). version must be the version the last check found", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "version": { "type": "string" } }, "required": ["version"] } } } }, "responses": { "200": { "description": "{id,status}" }, "400": { "description": "{error}" }, "409": { "description": "{error}" } } } },
    "/v1/system/update/rollback": { "post": { "summary": "Start a job that reinstalls the version replaced by the last committed update and starts it (admin only)", "responses": { "200": { "description": "{id,status}" }, "409": { "description": "{error}" } } } },
    "/v1/zones": { "get": { "summary": "Authoritative zones", "responses": { "200": { "description": "[{origin,serial,records}]" } } } },
    "/v1/zones/{origin}": {
      "get": { "summary": "Authoritative zone with structured records", "responses": { "200": { "description": "{origin,serial,record_count,records:[{name,type,ttl,value}]}" }, "404": { "description": "{error}" } } },
      "put": { "summary": "Create or replace an authoritative DNS zone (admin only; body is an RFC 1035 zone file)", "requestBody": { "content": { "text/plain": { "schema": { "type": "string" } } } }, "responses": { "200": { "description": "{origin,serial,records,persisted}" }, "400": { "description": "{error}: invalid DNS zone data" }, "403": { "description": "This action requires the admin role" } } },
      "delete": { "summary": "Delete an authoritative DNS zone (admin only)", "responses": { "200": { "description": "{deleted}" }, "404": { "description": "{error}" } } }
    },
    "/v1/zones/{origin}/dnssec": { "get": { "summary": "Zone DNSSEC status (signed, DNSKEYs, DS for the parent)", "responses": { "200": { "description": "{signed,dnskeys:[{key_tag,flags,algorithm,role}],ds:{key_tag,algorithm,digest_type,digest}}" } } } },
    "/v1/zones/{origin}/records": {
      "post": { "summary": "Add a DNS record (admin only): saves, re-signs with DNSSEC, and sends NOTIFY", "requestBody": { "content": { "text/plain": { "schema": { "type": "string" } } } }, "responses": { "200": { "description": "{origin,serial,records,persisted,signed}" }, "400": { "description": "{error}: invalid DNS record" } } },
      "delete": { "summary": "Delete DNS records (admin only): with value, deletes only records whose value also matches", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "name": { "type": "string" }, "type": { "type": "string" }, "value": { "type": "string" } }, "required": ["name","type"] } } } }, "responses": { "200": { "description": "{deleted,origin,serial,persisted}" }, "404": { "description": "{error}: no matching entry" } } }
    },
    "/v1/config/effective": { "get": { "summary": "The config the server is actually running: defaults merged in, sensitive values masked. Direct edits to the config file are not included until applied", "responses": { "200": { "description": "Running config (JSON)" } } } },
    "/v1/config": { "get": { "summary": "Values saved in the config file, including changes not yet applied to the server. Returns error details when the file cannot be read or parsed", "responses": { "200": { "description": "Saved config values or a file error (JSON)" } } } },
    "/v1/config/status": { "get": { "summary": "Check whether the config file matches the running config and show entries not yet applied. service_restart lists the entries whose change restarts the DNS service when the file is applied; conditional_hot_reload_keys lists the settings that can restart it under the current configuration", "responses": { "200": { "description": "{in_sync,source,changed_keys[],service_restart[],restart_required,conditional_hot_reload_keys[],error?}" } } } },
    "/v1/config/reload": { "post": { "summary": "Validate config file changes and apply them to the running server (admin only)", "responses": { "200": { "description": "{accepted,mode,restart_required,changed}" }, "400": { "description": "{error}: config file is missing or invalid" } } } },
    "/v1/config/set": { "post": { "summary": "Change settings (admin only): merges the values into the TOML file, validates, and saves. Hot-reloadable entries apply without dropping connections; others restart the DNS service. Nested entries use their dedicated APIs", "requestBody": { "content": { "application/json": { "schema": { "type": "object" } } } }, "responses": { "200": { "description": "{applied,mode,restart_required,reloading,changed,keys}" }, "400": { "description": "{error}: unknown key or invalid value" } } } },
    "/v1/config/set/diff": { "post": { "summary": "Show which entries a /v1/config/set request with this body would change and how they would be applied, without changing anything (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object" } } } }, "responses": { "200": { "description": "{added[],removed[],changed[],effective_changed[],hot_reload[],service_restart[],restart_required}" }, "400": { "description": "{error}: unknown key or invalid value" } } } },
    "/v1/config/schema": { "get": { "summary": "Settings that /v1/config/set can change, with their types and descriptions", "responses": { "200": { "description": "{keys:[...],count}" } } } },
    "/v1/upstreams/test": { "post": { "summary": "Test an upstream DNS server (admin only): sends a test query and reports reachability, latency, and response code", "requestBody": { "content": { "application/json": { "schema": { "type": "object" } } } }, "responses": { "200": { "description": "{ok,latency_ms,rcode,addr}" }, "400": { "description": "{error}" } } } },
    "/v1/cache/flush": { "post": { "summary": "Flush the whole response cache (admin only). Returns the number of entries removed", "responses": { "200": { "description": "{flushed}" } } } },
    "/v1/tokens": { "get": { "summary": "Management API tokens. Token values are masked; only the role and a stable ID are returned", "responses": { "200": { "description": "{tokens:[{id,role,masked}]}" } } }, "post": { "summary": "Issue a management API token (admin only). The full token value is returned only once, in this response", "responses": { "200": { "description": "{created,role,token,id}" }, "400": { "description": "{error}" } } }, "delete": { "summary": "Revoke a management API token (admin only). The primary control token from the config file cannot be deleted", "responses": { "200": { "description": "{removed}" }, "404": { "description": "{error}" } } } },
    "/v1/rewrites": { "get": { "summary": "DNS rewrite rules", "responses": { "200": { "description": "{rewrites:[{domain,answer}]}" } } }, "post": { "summary": "Add or replace a DNS rewrite rule (admin only)", "responses": { "200": { "description": "{added,domain}" }, "400": { "description": "{error}" } } }, "delete": { "summary": "Delete a DNS rewrite rule (admin only)", "responses": { "200": { "description": "{removed,domain}" }, "404": { "description": "{error}" } } } },
    "/v1/services": {
      "get": { "summary": "Blockable services and whether each is blocked", "responses": { "200": { "description": "{count,services:[{id,name,blocked}]}" } } },
      "post": { "summary": "Change service blocking", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "service": { "type": "string" }, "enable": { "type": "boolean" } }, "required": ["service","enable"] } } } }, "responses": { "200": { "description": "{block,allow}" } } }
    },
    "/v1/access": { "get": { "summary": "Allowed and blocked networks, and domains answered with REFUSED. Use the config API to change them", "responses": { "200": { "description": "{allowed,blocked,refused_domains}" } } } },
    "/v1/tls": { "get": { "summary": "TLS certificate and private key paths, and encrypted DNS listener status", "responses": { "200": { "description": "{configured,cert,key,doh_listeners,dot_listeners}" } } } },
    "/v1/tls/validate": { "post": { "summary": "Validate the configured certificate, private key, chain, and validity period (admin only). Trust path and hostname are not checked", "responses": { "200": { "description": "{material_valid,valid:false,trusted:false,hostname_checked:false,chain_len}" }, "400": { "description": "{error}" } } } },
    "/v1/tls/configure": { "post": { "summary": "Replace the TLS certificate and private key (admin only): accepts PEM bodies or file paths, checks the format and that the key matches, saves them, and restarts the encrypted DNS listeners", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "certificate_chain": { "type": "string" }, "private_key": { "type": "string" }, "cert_path": { "type": "string" }, "key_path": { "type": "string" } }, "additionalProperties": false } } } }, "responses": { "200": { "description": "{configured,chain_len,reloading,cert,key}" }, "400": { "description": "{error}" } } } },
    "/v1/tls/revocation-check": { "post": { "summary": "Check OCSP and CRL revocation status of a certificate chain (admin only). Fetches from the URLs in the certificate and verifies signatures", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "certificate_chain": { "type": "string" } }, "required": ["certificate_chain"] } } } }, "responses": { "200": { "description": "{ocsp,crl,ocsp_urls,crl_urls,revoked}" }, "400": { "description": "{error}" } } } },
    "/v1/acme/issue": { "post": { "summary": "Issue an ACME certificate or register an account (admin only). Answers HTTP-01 and DNS-01 challenges automatically and saves the issued certificate and private key to the configured files", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "directory": { "type": "string" }, "domains": { "type": "array" }, "contact": { "type": "string" }, "challenge": { "type": "string" }, "account_only": { "type": "boolean" } } } } } }, "responses": { "200": { "description": "{account,issued,cert_file,key_file}" }, "400": { "description": "{error}" } } } },
    "/v1/plugins": { "get": { "summary": "WASM plugin metrics", "responses": { "200": { "description": "[{name,eval,error,block,latency_us}]" } } } },
    "/v1/filter/report": { "get": { "summary": "Filter rule load results and why rules were skipped", "responses": { "200": { "description": "{rules_total,rules_applied,rules_skipped,skip_reasons}" } } } },
    "/v1/filter/top-rules": { "get": { "summary": "Top N rules by hits (when track_rule_hits is enabled)", "responses": { "200": { "description": "{enabled,top:[{rule,hits}]}" } } } },
    "/v1/filter/sources": { "get": { "summary": "Rule count and cumulative hits per block or allow list", "responses": { "200": { "description": "{hits_enabled,sources:[{source,rules,hits}]}" } } } },
    "/v1/filter/subscriptions": {
      "get": { "summary": "Subscriptions with title, enabled state, and rule count. Built-in lists enabled by safe browsing and parental control are included with a preset value; they are turned on and off only by those settings and cannot be deleted or disabled here", "responses": { "200": { "description": "{lists:[{url,title,enabled,rules,updated_unix,preset?}],count,block_domains}. preset is safe_browsing or parental_control" } } },
      "post": { "summary": "Add a blocklist subscription (admin only)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "url": { "type": "string" }, "title": { "type": "string" }, "enabled": { "type": "boolean" } }, "required": ["url"] } } } }, "responses": { "200": { "description": "{added,subscriptions,block}" }, "400": { "description": "{error}" } } },
      "patch": { "summary": "Rename or enable/disable a blocklist subscription (admin only)", "responses": { "200": { "description": "{updated}" }, "400": { "description": "{error}" } } },
      "delete": { "summary": "Delete a blocklist subscription (admin only)", "responses": { "200": { "description": "{removed,subscriptions,block}" }, "404": { "description": "{error}" } } }
    },
    "/v1/filter/subscriptions/refresh": { "post": { "summary": "Refresh the given blocklist subscription (admin only)", "responses": { "200": { "description": "{refreshed:true}" }, "400": { "description": "{error}" } } } },
    "/v1/filter/rules": { "get": { "summary": "User block and allow rules, and domains answered with REFUSED", "responses": { "200": { "description": "{block,allow,refused_domains}" } } }, "post": { "summary": "Add a filter rule (admin only)", "responses": { "200": { "description": "{updated:true}" } } }, "delete": { "summary": "Delete a filter rule (admin only)", "responses": { "200": { "description": "{updated:true}" } } } },
    "/v1/clients": { "get": { "summary": "Per-client policies", "responses": { "200": { "description": "[{name,nets,client_ids,tags,block_rules,disable_filtering}]" } } }, "post": { "summary": "Add a client policy (admin only): ordinary block and allow policies apply without dropping connections; a dedicated upstream DNS server or a new MAC match restarts the DNS service", "responses": { "200": { "description": "{added,reloading}" }, "400": { "description": "{error}" } } }, "patch": { "summary": "Turn filtering on or off for a client (admin only)", "responses": { "200": { "description": "{updated,disable_filtering,reloading}" } } }, "delete": { "summary": "Delete a client policy (admin only)", "responses": { "200": { "description": "{removed,reloading}" }, "400": { "description": "{error}" } } } },
    "/v1/upstreams": { "get": { "summary": "Upstream DNS servers", "responses": { "200": { "description": "[{id,addr,queries?,ok?,fail?,ewma_ms?}]" } } }, "post": { "summary": "Add an upstream DNS server (admin only; applies without dropping connections)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "addr": { "type": "string" } }, "required": ["addr"], "additionalProperties": false } } } }, "responses": { "200": { "description": "{added,mode,restart_required}" }, "400": { "description": "{error}" } } }, "delete": { "summary": "Delete an upstream DNS server (admin only; applies without dropping connections)", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "addr": { "type": "string" } }, "required": ["addr"], "additionalProperties": false } } } }, "responses": { "200": { "description": "{removed,mode,restart_required}" }, "400": { "description": "{error}" } } } },
    "/v1/jobs": { "get": { "summary": "Background jobs", "responses": { "200": { "description": "[{id,kind,status,created,finished,result}]" } } } },
    "/v1/jobs/refresh": { "post": { "summary": "Start a blocklist refresh job (admin only)", "responses": { "200": { "description": "{id,status}" } } } },
    "/v1/jobs/{id}": { "get": { "summary": "Status of one job (polling)", "responses": { "200": { "description": "{id,kind,status,...}" }, "404": { "description": "{error}" } } } },
    "/v1/dhcp/leases": { "get": { "summary": "Active DHCP leases. IPv4 entries include the binding identity, last MAC, and the vendor and hostname when known", "responses": { "200": { "description": "{v4:[{ip,identity,mac,vendor,hostname,expires,remaining}],v6:[{ip,duid,expires,remaining}]}" } } }, "post": { "summary": "Apply DHCP leases sent by the peer node in a high-availability setup (admin only). Accepts one object or a snapshot array with identity and last MAC; rejects the whole request if any entry is malformed", "requestBody": { "content": { "application/json": { "schema": { "oneOf": [{ "type": "object" }, { "type": "array", "items": { "type": "object" } }], "example": [{ "identity": "id:0102", "mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.100", "expiry": "1900000000", "hostname": "host1" }] } } } }, "responses": { "200": { "description": "{synced}" }, "400": { "description": "{error}" } } } },
    "/v1/dhcp/static": { "get": { "summary": "DHCP static assignments (fixed IP per mac:<hex> or id:<hex> identity)", "responses": { "200": { "description": "{available,reservations:[{identity,ip,hostname}]}. available is false when no DHCPv4 pool is running; adds and deletes are then rejected" } } }, "post": { "summary": "Add or change a DHCP static assignment (admin only). Applies to the pool immediately and saves to file", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "identity": { "type": "string" }, "ip": { "type": "string" }, "hostname": { "type": "string" } }, "required": ["identity", "ip"] } } } }, "responses": { "200": { "description": "{added,identity,ip}" }, "400": { "description": "{error}" } } }, "delete": { "summary": "Delete a DHCP static assignment (admin only)", "responses": { "200": { "description": "{removed,identity}" }, "404": { "description": "{error}" } } } }
  }
}"##;
    SPEC.to_string()
}

/**
 * @brief 상수 시간 비교.
 * @warning 토큰 비교에 쓴다. 조기 반환을 넣으면 걸린 시간으로 토큰을 한 바이트씩 알아낼 수 있다.
 */
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
/** @brief 인증과 등급, 요청 스머글링 거부, 리바인딩 방어, 세션 수명, 그리고 문서와 경로의 일치. */
mod tests {
    use super::*;
    use crate::metrics::{channel, PersistOpts, RecorderOpts};
    use std::sync::Mutex;

    #[test]
    /** @brief 헤더를 한 바이트씩 흘려 보내는 상대가 연결을 붙잡지 못하는지. */
    fn request_deadline_rejects_slow_drip_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for byte in b"GET / HTTP/1.1\r\n" {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(30));
            }
        });

        let started = Instant::now();
        let stream = TcpStream::connect(addr).unwrap();
        let mut reader = BufReader::new(DeadlineTcp::new(
            AdmittedTcp::new(SharedTcp::new(stream), Vec::new(), None),
            started + Duration::from_millis(120),
        ));
        let mut line = String::new();
        let error = reader.read_line(&mut line).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ));
        assert!(started.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
    }

    #[test]
    /** @brief admission이 완성 요청을 기다리고 먼저 읽은 바이트를 파서에 그대로 재생하는지. */
    fn control_admission_waits_for_complete_request_and_replays_it() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, peer) = listener.accept().unwrap();
        let shared = SharedTcp::new(server);
        shared.set_nonblocking(true).unwrap();
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let admission_total = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut pending = PendingControlConnection {
            stream: shared,
            peer,
            deadline: Instant::now() + Duration::from_secs(1),
            received: Vec::new(),
            next_probe: Instant::now(),
            probe_delay: Duration::from_millis(CONTROL_ADMISSION_POLL_MS),
            admission_bytes: AdmissionBytesGuard::new(admission_total.clone()),
            guard: acquire_connection_slot(&active).unwrap(),
        };
        let request = b"POST /v1/config/validate HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 4\r\n\r\n{}{}";
        let body_tail = 2;
        client
            .write_all(&request[..request.len() - body_tail])
            .unwrap();
        let mut scratch = [0u8; CONTROL_ADMISSION_READ_BYTES];
        /*
         * write_all 은 보내는 쪽 버퍼에 넣은 것까지만 보장하고, 받는 쪽에 언제 올라올지는
         * 커널에 달려 있다. 앞부분이 도착하기 전에 한 번만 보면 Pending 단언이 아무것도
         * 증명하지 못하므로, 도착한 것을 확인한 뒤에 판정한다.
         */
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(matches!(
                control_admission_state(&mut pending, &mut scratch).unwrap(),
                ControlAdmissionState::Pending
            ));
            if !pending.received.is_empty() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "요청 앞부분이 도착하지 않았습니다"
            );
            std::thread::sleep(Duration::from_millis(1));
        }

        client
            .write_all(&request[request.len() - body_tail..])
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if matches!(
                control_admission_state(&mut pending, &mut scratch).unwrap(),
                ControlAdmissionState::Ready
            ) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "요청 나머지가 도착하지 않았습니다"
            );
            std::thread::sleep(Duration::from_millis(1));
        }

        pending.stream.set_nonblocking(false).unwrap();
        let admission_bytes = std::mem::replace(
            &mut pending.admission_bytes,
            AdmissionBytesGuard::new(admission_total.clone()),
        );
        let mut reader = DeadlineTcp::new(
            AdmittedTcp::new(
                pending.stream.clone(),
                std::mem::take(&mut pending.received),
                Some(admission_bytes),
            ),
            pending.deadline,
        )
        .stop_on(Arc::new(std::sync::atomic::AtomicBool::new(false)));
        let mut received = vec![0u8; request.len()];
        reader.read_exact(&mut received).unwrap();
        assert_eq!(received, request, "기존 파서가 원래 요청을 그대로 봅니다");
    }

    #[test]
    /** @brief 부분 요청 뒤 연결을 닫으면 admission이 즉시 곳을 회수할 수 있는지. */
    fn control_admission_detects_close_after_partial_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, peer) = listener.accept().unwrap();
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let admission_total = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut pending = PendingControlConnection {
            stream: SharedTcp::new(server),
            peer,
            deadline: Instant::now() + Duration::from_secs(1),
            received: Vec::new(),
            next_probe: Instant::now(),
            probe_delay: Duration::from_millis(CONTROL_ADMISSION_POLL_MS),
            admission_bytes: AdmissionBytesGuard::new(admission_total),
            guard: acquire_connection_slot(&active).unwrap(),
        };
        pending.stream.set_nonblocking(true).unwrap();
        client.write_all(b"G").unwrap();
        drop(client);

        let mut scratch = [0u8; CONTROL_ADMISSION_READ_BYTES];
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if matches!(
                control_admission_state(&mut pending, &mut scratch).unwrap(),
                ControlAdmissionState::Closed
            ) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "부분 요청 뒤 FIN을 감지해야 합니다"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(pending.received, b"G");
    }

    #[test]
    /** @brief 전역 admission 원문 예산이 경쟁 중에도 상한을 넘지 않고 drop 때 반환되는지. */
    fn admission_byte_budget_is_bounded_and_released() {
        use std::sync::atomic::Ordering;

        let total = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut first = AdmissionBytesGuard::new(total.clone());
        let mut second = AdmissionBytesGuard::new(total.clone());
        let mut denied = AdmissionBytesGuard::new(total.clone());
        assert_eq!(
            first.reserve(MAX_CONTROL_ADMISSION_BYTES - 1),
            MAX_CONTROL_ADMISSION_BYTES - 1
        );
        assert_eq!(second.reserve(2), 1);
        assert_eq!(denied.reserve(1), 0);
        assert_eq!(total.load(Ordering::Acquire), MAX_CONTROL_ADMISSION_BYTES);

        drop(second);
        assert_eq!(denied.reserve(1), 1);
        drop(first);
        drop(denied);
        assert_eq!(total.load(Ordering::Acquire), 0);
    }

    #[test]
    /** @brief 전역 원문 예산이 가득 차면 새 요청이 바이트를 소비하지 않고 거절되는지. */
    fn control_admission_reports_full_global_byte_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, peer) = listener.accept().unwrap();
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let admission_total = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut blocker = AdmissionBytesGuard::new(admission_total.clone());
        assert_eq!(
            blocker.reserve(MAX_CONTROL_ADMISSION_BYTES),
            MAX_CONTROL_ADMISSION_BYTES
        );
        let mut pending = PendingControlConnection {
            stream: SharedTcp::new(server),
            peer,
            deadline: Instant::now() + Duration::from_secs(1),
            received: Vec::new(),
            next_probe: Instant::now(),
            probe_delay: Duration::from_millis(CONTROL_ADMISSION_POLL_MS),
            admission_bytes: AdmissionBytesGuard::new(admission_total),
            guard: acquire_connection_slot(&active).unwrap(),
        };
        pending.stream.set_nonblocking(true).unwrap();
        client.write_all(b"G").unwrap();

        let mut scratch = [0u8; CONTROL_ADMISSION_READ_BYTES];
        assert!(matches!(
            control_admission_state(&mut pending, &mut scratch).unwrap(),
            ControlAdmissionState::Overloaded
        ));
        assert!(pending.received.is_empty());
        drop(blocker);
        /*
         * write_all 은 보내는 쪽 버퍼에 넣은 것까지만 보장한다. 받는 쪽 소켓에 바이트가
         * 올라오는 시점은 커널에 달려 있어, 한 번만 읽으면 아직 빈 채로 볼 수 있다.
         */
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(matches!(
                control_admission_state(&mut pending, &mut scratch).unwrap(),
                ControlAdmissionState::Pending
            ));
            if !pending.received.is_empty() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "보낸 바이트가 받는 쪽에 도착하지 않았습니다"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(pending.received, b"G");
    }

    #[test]
    /** @brief 기존 파서가 헤더만 보고 거절할 모양은 admission이 본문을 기다리지 않는지. */
    fn control_admission_defers_malformed_framing_to_the_authoritative_parser() {
        for request in [
            b"POST / HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\n".as_slice(),
            b"POST / HTTP/1.1\r\nContent-Length: nope\r\n\r\n".as_slice(),
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
            b"POST / HTTP/1.1\r\nContent-Length: 1048577\r\n\r\n".as_slice(),
        ] {
            let header_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .unwrap()
                + 4;
            assert_eq!(
                control_request_required_bytes(request, header_end),
                header_end
            );
        }
    }

    #[test]
    /** @brief 실제 리스너가 부분 요청을 보류했다가 완성 뒤 정상 응답하는지. */
    fn serve_listener_promotes_a_request_only_after_its_header_is_complete() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_shutdown = shutdown.clone();
        let server = std::thread::spawn(move || {
            serve_listener(listener, test_state("adm", "ro"), server_shutdown).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        client.write_all(b"G").unwrap();
        let mut byte = [0u8; 1];
        let error = client.read(&mut byte).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));

        let rest = format!("ET /v1/auth HTTP/1.1\r\nHost: {addr}\r\n\r\n");
        client.write_all(rest.as_bytes()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

        shutdown.store(true, Ordering::Relaxed);
        server.join().unwrap();
    }

    /** @brief 테스트용 컨트롤 플레인 상태. 관리자와 읽기 전용 토큰을 지정해 만든다. */
    fn test_state(admin: &str, readonly: &str) -> AppState {
        let (_rec, stats) = channel(8, 100, 0, RecorderOpts::default(), PersistOpts::default());
        let store: Arc<Mutex<(Vec<String>, Vec<String>)>> = Arc::new(Mutex::new((vec![], vec![])));
        let zones: Arc<Mutex<std::collections::HashMap<String, String>>> =
            Arc::new(Mutex::new(std::collections::HashMap::new()));
        let s1 = store.clone();
        let s2 = store.clone();
        let s3 = store.clone();
        let cnt = |st: &Mutex<(Vec<String>, Vec<String>)>| {
            let g = st.lock_recover();
            ListCounts {
                block: g.0.len(),
                allow: g.1.len(),
            }
        };
        let controls = Controls {
            reload: Box::new(move || Ok(cnt(&s1))),
            block_add: Box::new(move |d: &str| {
                s2.lock_recover().0.push(d.to_string());
                Ok(cnt(&s2))
            }),
            allow_add: Box::new(|_| Ok(ListCounts { block: 0, allow: 0 })),
            service_set: Box::new(|_, _| Ok(ListCounts { block: 0, allow: 0 })),
            safesearch_set: Box::new(|_| Ok(())),
            export: {
                let s = store.clone();
                Box::new(move || {
                    let g = s.lock_recover();
                    let arr = |v: &[String]| {
                        v.iter()
                            .map(|x| json::escape(x))
                            .collect::<Vec<_>>()
                            .join(",")
                    };
                    format!(
                        "{{\"version\":1,\"block\":[{}],\"allow\":[{}]}}",
                        arr(&g.0),
                        arr(&g.1)
                    )
                })
            },
            import: Box::new(move |body: &str| {
                let j = json::parse(body)?;
                let b: Vec<String> = j
                    .get("block")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                let mut g = s3.lock_recover();
                g.0 = b;
                Ok(ListCounts {
                    block: g.0.len(),
                    allow: g.1.len(),
                })
            }),

            config_validate: Box::new(|t| {
                if t.contains("bad") {
                    Err("입력 형식이 올바르지 않습니다".to_string())
                } else {
                    Ok(())
                }
            }),
            config_diff: Box::new(|_| {
                Ok("{\"added\":[],\"removed\":[],\"changed\":[]}".to_string())
            }),
            config_apply: Box::new(|t| {
                if t.contains("bad") {
                    Err("입력 형식이 올바르지 않습니다".to_string())
                } else {
                    Ok("{\"applied\":true,\"restart_required\":true}".to_string())
                }
            }),
            config_set: Box::new(|b| {
                if b.contains("\"bad\"") {
                    Err("알 수 없는 설정 키".to_string())
                } else {
                    Ok("{\"applied\":true,\"reloading\":true}".to_string())
                }
            }),
            config_set_diff: Box::new(|_| {
                Ok("{\"added\":[],\"removed\":[],\"changed\":[]}".to_string())
            }),
            config_schema: Box::new(|| "{\"keys\":[\"prefetch\",\"cache_size\"]}".to_string()),
            upstream_test: Box::new(|b| {
                if b.contains("addr") {
                    Ok("{\"ok\":true,\"latency_ms\":4}".to_string())
                } else {
                    Err("`addr` 항목을 입력해야 합니다".to_string())
                }
            }),
            cache_flush: Box::new(|| "{\"flushed\":42}".to_string()),
            rewrites_list: Box::new(|| {
                "{\"rewrites\":[{\"domain\":\"router.lan\",\"answer\":\"192.168.1.1\"}]}"
                    .to_string()
            }),
            rewrite_add: Box::new(|b| {
                if b.contains("domain") {
                    Ok("{\"added\":true}".to_string())
                } else {
                    Err("`domain` 항목을 입력해야 합니다".to_string())
                }
            }),
            rewrite_delete: Box::new(|_| Ok("{\"removed\":1}".to_string())),
            services_catalog: Box::new(|| {
                "{\"count\":1,\"services\":[{\"id\":\"youtube\",\"name\":\"YouTube\",\"group\":\"streaming\",\"rule_count\":5,\"blocked\":false}]}".to_string()
            }),
            access_list: Box::new(|| {
                "{\"allowed\":[\"10.0.0.0/8\"],\"blocked\":[],\"refused_domains\":[]}".to_string()
            }),
            tls_status: Box::new(|| "{\"configured\":true,\"doh_listeners\":1}".to_string()),
            tls_validate: Box::new(|| Ok("{\"valid\":true,\"chain_len\":1}".to_string())),
            tls_configure: Box::new(|body| {
                if body.contains("private_key") || body.contains("key_path") {
                    Ok("{\"configured\":true,\"reloading\":true}".to_string())
                } else {
                    Err("인증서와 개인키를 모두 입력해야 합니다".to_string())
                }
            }),
            tls_revocation_check: Box::new(|body| {
                if body.contains("certificate_chain") {
                    Ok("{\"ocsp\":\"good\",\"crl\":\"unavailable\",\"revoked\":false}".to_string())
                } else {
                    Err("`certificate_chain` 항목을 입력해야 합니다".to_string())
                }
            }),
            acme_issue: Box::new(|body| {
                if body.contains("account_only") {
                    Ok("{\"account\":\"https://acme/acct/1\",\"issued\":false}".to_string())
                } else {
                    Err("ACME 디렉터리 주소를 입력해야 합니다".to_string())
                }
            }),
            tokens_list: Box::new(|| {
                "{\"tokens\":[{\"id\":\"ab12\",\"role\":\"admin\",\"masked\":\"abcdef…99\"}]}"
                    .to_string()
            }),
            token_add: Box::new(|b| {
                if b.contains("role") || b == "{}" {
                    Ok("{\"created\":true,\"role\":\"readonly\",\"token\":\"deadbeef\",\"id\":\"ab12\"}"
                        .to_string())
                } else {
                    Err("JSON 요청 본문을 해석할 수 없습니다".to_string())
                }
            }),
            token_delete: Box::new(|b| {
                if b.contains("\"id\"") {
                    Ok("{\"removed\":1}".to_string())
                } else {
                    Err("`id` 항목을 입력해야 합니다".to_string())
                }
            }),
            config_rollback: Box::new(|| Ok("{\"rolled_back\":true}".to_string())),
            policy_simulate: Box::new(|_| "{\"action\":\"continue\"}".to_string()),
            zones_list: Box::new(|| "[]".to_string()),

            zone_get: {
                let z = zones.clone();
                Box::new(move |origin: &str| {
                    z.lock()
                        .unwrap()
                        .get(origin)
                        .map(|t| {
                            format!("{{\"origin\":\"{origin}\",\"zone\":{}}}", json::escape(t))
                        })
                        .ok_or_else(|| format!("DNS 영역을 찾을 수 없습니다: {origin}"))
                })
            },
            zone_put: {
                let z = zones.clone();
                Box::new(move |origin: &str, text: &str| {
                    if text.contains("bad") {
                        return Err("DNS 영역 데이터 형식이 올바르지 않습니다".to_string());
                    }
                    z.lock()
                        .unwrap()
                        .insert(origin.to_string(), text.to_string());
                    Ok(format!("{{\"origin\":\"{origin}\",\"persisted\":false}}"))
                })
            },
            zone_delete: {
                let z = zones.clone();
                Box::new(move |origin: &str| {
                    z.lock()
                        .unwrap()
                        .remove(origin)
                        .map(|_| "{\"deleted\":true}".to_string())
                        .ok_or_else(|| format!("DNS 영역을 찾을 수 없습니다: {origin}"))
                })
            },
            zone_record_add: {
                let z = zones.clone();
                Box::new(move |origin: &str, body: &str| {
                    if body.trim().is_empty() {
                        return Err("빈 본문".to_string());
                    }
                    z.lock()
                        .unwrap()
                        .entry(origin.to_string())
                        .or_default()
                        .push_str(body);
                    Ok(format!("{{\"origin\":\"{origin}\",\"added\":true}}"))
                })
            },
            zone_record_delete: Box::new(|origin: &str, _: &str| {
                Ok(format!("{{\"origin\":\"{origin}\",\"deleted\":1}}"))
            }),
            zone_dnssec: Box::new(|origin: &str| {
                Ok(format!(
                    "{{\"origin\":\"{origin}\",\"signed\":true,\"dnskeys\":[],\"ds\":null}}"
                ))
            }),
            config_desired: Box::new(|| "{\"mode\":\"personal\"}".to_string()),
            config_effective: Box::new(|| "{\"mode\":\"personal\"}".to_string()),
            config_status: Box::new(|| "{\"in_sync\":true,\"changed_keys\":[]}".to_string()),
            config_reload: Box::new(|| Ok("{\"accepted\":true}".to_string())),
            plugins_metrics: Box::new(|| "[]".to_string()),
            filter_report: Box::new(|| {
                "{\"rules_total\":3,\"rules_applied\":2,\"rules_skipped\":1}".to_string()
            }),
            filter_top_rules: Box::new(|| {
                "{\"enabled\":true,\"top\":[{\"rule\":\"ads.example.com\",\"hits\":3}]}".to_string()
            }),
            filter_sources: Box::new(|| {
                "{\"hits_enabled\":true,\"sources\":[{\"source\":\"listA\",\"rules\":1,\"hits\":2}]}"
                    .to_string()
            }),
            subscriptions_list: Box::new(|| {
                "{\"urls\":[\"https://x/list.txt\"],\"count\":1,\"block_domains\":0}".to_string()
            }),
            subscription_add: Box::new(|url: &str| {
                if url.trim().is_empty() {
                    Err("URL을 입력해야 합니다".to_string())
                } else {
                    Ok("{\"added\":true}".to_string())
                }
            }),
            subscription_remove: Box::new(|_| Ok("{\"removed\":true}".to_string())),
            subscription_update: Box::new(|_| Ok("{\"updated\":true}".to_string())),
            subscription_refresh: Box::new(|_| Ok("{\"id\":1}".to_string())),
            filter_rules_list: Box::new(|| {
                "{\"block\":[],\"allow\":[],\"refused_domains\":[]}".to_string()
            }),
            filter_rule_mutate: Box::new(|_, _| Ok("{\"updated\":true}".to_string())),
            clients_list: Box::new(|| "[]".to_string()),
            upstreams_list: Box::new(|| "[]".to_string()),
            jobs_list: Box::new(|| "[{\"id\":1,\"status\":\"done\"}]".to_string()),
            job_get: Box::new(|id| {
                if id == 1 {
                    Ok("{\"id\":1,\"status\":\"done\"}".to_string())
                } else {
                    Err("작업을 찾을 수 없습니다".to_string())
                }
            }),
            job_refresh: Box::new(|| "{\"id\":2,\"status\":\"running\"}".to_string()),
            dhcp_leases: Box::new(|| {
                "{\"v4\":[{\"ip\":\"192.168.1.100\",\"identity\":\"id:0102\",\"mac\":\"aa:bb:cc:dd:ee:ff\",\"vendor\":null,\"hostname\":\"host1\",\"expires\":9999999999,\"remaining\":3600}],\"v6\":[]}".to_string()
            }),
            dhcp_lease_put: Box::new(|body| {
                if body.contains("\"identity\"")
                    && body.contains("\"mac\"")
                    && body.contains("\"ip\"")
                {
                    Ok("{\"synced\":1}".to_string())
                } else {
                    Err("`mac`과 `ip` 항목을 입력해야 합니다".to_string())
                }
            }),
            dhcp_static_list: Box::new(|| {
                "{\"available\":true,\"reservations\":[{\"identity\":\"mac:aabbccddeeff\",\"ip\":\"192.168.1.200\",\"hostname\":\"printer\"}]}".to_string()
            }),
            dhcp_static_add: Box::new(|body| {
                if body.contains("\"identity\"") && body.contains("\"ip\"") {
                    Ok("{\"added\":true}".to_string())
                } else {
                    Err("`mac`과 `ip` 항목을 입력해야 합니다".to_string())
                }
            }),
            dhcp_static_remove: Box::new(|identity| {
                if identity == "mac:aabbccddeeff" {
                    Ok("{\"removed\":true}".to_string())
                } else {
                    Err(format!("고정 할당 항목을 찾을 수 없습니다: {identity}"))
                }
            }),
            client_add: Box::new(|body| {
                if body.contains("\"name\"") {
                    Ok("{\"added\":true,\"reloading\":true}".to_string())
                } else {
                    Err("`name` 항목을 입력해야 합니다".to_string())
                }
            }),
            client_remove: Box::new(|name| {
                if name == "kid" {
                    Ok("{\"removed\":true,\"reloading\":true}".to_string())
                } else {
                    Err(format!("클라이언트를 찾을 수 없습니다: {name}"))
                }
            }),
            client_update: Box::new(|_| Ok("{\"updated\":true}".to_string())),
            password_change: Box::new(|_, _| Ok("{\"changed\":true}".to_string())),
            user_create: Box::new(|_, _| Ok("{\"created\":true}".to_string())),
            upstream_add: Box::new(|u| {
                if u.is_empty() {
                    Err("추가할 업스트림 DNS 서버 주소가 비어 있습니다".to_string())
                } else {
                    Ok("{\"added\":true,\"reloading\":true}".to_string())
                }
            }),
            upstream_remove: Box::new(|_| Ok("{\"removed\":true,\"reloading\":true}".to_string())),
            explain: Box::new(|body| {
                if body.contains("\"qname\"") {
                    "{\"decision\":\"block\",\"rcode\":\"NXDOMAIN\",\"filter_stage\":\"block\",\"backend\":\"forward\",\"dnssec\":false}".to_string()
                } else {
                    "{\"error\":\"qname is required\"}".to_string()
                }
            }),
            cluster_status: Box::new(|| {
                "{\"self\":{\"id\":null,\"role\":\"standalone\",\"backend\":\"unknown\",\"listeners\":0,\"leader\":null,\"term\":null,\"commit_index\":null,\"last_applied\":null,\"last_index\":null,\"snapshot_index\":null,\"retained_log_entries\":null,\"fatal\":null,\"healthy\":true,\"version\":null},\"peers\":[]}".to_string()
            }),
            cluster_propose: Box::new(|body| {
                if body.contains('{') {
                    Ok("{\"proposed\":true,\"index\":1}".to_string())
                } else {
                    Err("Raft 고가용성 기능이 설정되어 있지 않습니다".to_string())
                }
            }),
            cluster_write: Box::new(|_, _, _, dispatch| dispatch()),
            listeners_status: Box::new(|| "[]".to_string()),
            net_adapters: Box::new(|| Ok("{\"adapters\":[],\"platform\":\"test\"}".to_string())),
            firewall_set: Box::new(|_| Ok("{\"ok\":true}".to_string())),
            dns_client_set: Box::new(|_| Ok("{\"ok\":true}".to_string())),
            dns_client_restore: Box::new(|_| Ok("{\"ok\":true}".to_string())),
            // 이 테스트 모듈은 지원하지 않는 운영체제를 흉내 낸다. 기본 콜백과 같은 답이다.
            resolve_probe: Box::new(|_| Err("DNS 수신 주소가 없습니다".to_string())),
            boot_service_status: Box::new(|| {
                "{\"supported\":false,\"installed\":false,\"running\":false}".to_string()
            }),
            boot_service_set: Box::new(|_| {
                Err("부팅 서비스 등록은 Windows에서만 됩니다".to_string())
            }),
            update_status: Box::new(|| {
                "{\"participating\":true,\"result\":\"available\",\"new_version\":\"9.9.9\"}"
                    .to_string()
            }),
            update_check: Box::new(|| Ok("{\"id\":1,\"status\":\"running\"}".to_string())),
            update_apply: Box::new(|version| {
                if version == "9.9.9" {
                    Ok("{\"id\":2,\"status\":\"running\"}".to_string())
                } else {
                    Err(format!("The last check found version 9.9.9, not {version}"))
                }
            }),
            update_rollback: Box::new(|| {
                Err("There is no committed update to roll back".to_string())
            }),
            metrics_extra: Box::new(|| {
                "onetdns_transport_errors_total{transport=\"doh\",stage=\"accept\"} 3\n".to_string()
            }),
        };
        AppState {
            stats,
            auth: Arc::new(Auth::new(
                vec![admin.to_string().into()],
                vec![readonly.to_string().into()],
            )),
            audit: AuditLog::new(100),
            controls: Arc::new(controls),
            readiness: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            proxy: Arc::new(ArcSwap::from_pointee(ProxyPolicy::default())),
        }
    }

    /** @brief 날 바이트를 그대로 보내고 응답을 받는다. 파서 자체를 테스트할 때 쓴다. */
    /** @brief 테스트용 일회용 설정 코드. */
    const TEST_SETUP_CODE: &str = "test-setup-code";
    /** @brief 테스트용 설정 코드 파일 경로. */
    const TEST_SETUP_FILE: &str = "/etc/onetdns/setup-code.txt";

    /** @brief 계정이 하나도 없고 설정 코드가 발급된 컨트롤 플레인 상태. 첫 실행 화면을 재현한다. */
    fn state_without_accounts(
        user_create: Box<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>,
    ) -> AppState {
        let base = test_state("adm", "ro");
        let mut controls = Controls::noop();
        controls.user_create = user_create;
        let auth = Auth::new(vec![], vec![]);
        auth.set_setup_code(TEST_SETUP_CODE, TEST_SETUP_FILE.to_string());
        AppState {
            auth: Arc::new(auth),
            controls: Arc::new(controls),
            ..base
        }
    }

    /** @brief 주어진 상태에 첫 계정 만들기 요청 하나를 보낸다. */
    fn setup_request(st: &AppState, body: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let request = format!(
            "POST /v1/setup HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = accept_before_deadline(&listener).expect("accept setup request");
                handle_conn(stream, st).unwrap();
            });
            let mut client = TcpStream::connect(addr).unwrap();
            client.write_all(request.as_bytes()).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            let mut response = String::new();
            std::io::Read::read_to_string(&mut client, &mut response).unwrap();
            response
        })
    }

    fn raw_control_request(request: &[u8]) -> String {
        let st = test_state("adm", "ro");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_conn(stream, &st).unwrap();
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(request).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        std::io::Read::read_to_string(&mut client, &mut response).unwrap();
        server.join().unwrap();
        response
    }

    #[test]
    /** @brief 본문 경계가 애매한 요청을 거부하는지. 이 어긋남이 요청 스머글링이다. */
    fn ambiguous_http_syntax_is_rejected() {
        for request in [
            b"GET\t/v1/auth HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
            b"GET /v1/auth HTTP/1.1\nHost: localhost\n\n".as_slice(),
            b"GET /v1/auth HTTP/1.1\r\nHost: localhost\r\nX-Test\x01: ignored\r\n\r\n".as_slice(),
            b"GET /v1/auth HTTP/1.1\r\nHost: localhost\r\nContent-Length: +0\r\n\r\n".as_slice(),
        ] {
            let response = raw_control_request(request);
            assert!(
                response.starts_with("HTTP/1.1 400 Bad Request"),
                "ambiguous request was accepted: {response}"
            );
        }
    }

    #[test]
    /**
     * @brief 질의 문자열이 붙어도 같은 경로로 라우팅되는지.
     * @details 떼지 않으면 콘솔 주소에 파라미터 하나만 붙어도 404가 되고, ?src=lb를
     *          붙여 부르는 상태 점검은 401을 받아 서비스가 죽은 것으로 보인다.
     */
    fn a_query_string_does_not_change_which_route_answers() {
        for (target, expected) in [
            ("/?utm_source=mail", "HTTP/1.1 200 OK"),
            ("/healthz?src=lb", "HTTP/1.1 200 OK"),
            ("/readyz?probe=1", "HTTP/1.1 200 OK"),
            ("/v1/auth?t=1", "HTTP/1.1 200 OK"),
            ("/nope?x=1", "HTTP/1.1 401 Unauthorized"),
        ] {
            let request = format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n");
            let response = raw_control_request(request.as_bytes());
            assert!(
                response.starts_with(expected),
                "{target} 응답이 {expected}가 아님: {}",
                response.lines().next().unwrap_or_default()
            );
        }
    }

    #[test]
    /**
     * @brief 첫 관리자 계정을 만들고 그대로 로그인되는지, 그 뒤로는 닫히는지.
     * @details 이 경로가 계정이 생긴 뒤에도 열려 있으면 누구나 관리자를 하나 더 만든다.
     */
    fn first_run_setup_creates_one_admin_and_then_closes() {
        let created = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(String, String)>::new()));
        let seen = created.clone();
        let st = state_without_accounts(Box::new(move |name, hash| {
            seen.lock_recover()
                .push((name.to_string(), hash.to_string()));
            Ok("{\"created\":true}".to_string())
        }));
        assert!(
            !st.auth.has_users(),
            "테스트는 계정이 없는 상태에서 시작한다"
        );

        let body =
            "{\"user\":\"owner\",\"password\":\"correct-horse-battery\",\"code\":\"test-setup-code\"}";
        let first = setup_request(&st, body);
        assert!(
            first.starts_with("HTTP/1.1 200 OK"),
            "첫 계정 만들기가 실패함: {}",
            first.lines().next().unwrap_or_default()
        );
        assert!(
            first.contains("Set-Cookie: onetdns_session="),
            "계정을 만들고 로그인되지 않음: {first}"
        );
        assert_eq!(
            created.lock_recover().len(),
            1,
            "설정 파일 기록이 한 번이 아님"
        );

        let second = setup_request(
            &st,
            "{\"user\":\"other\",\"password\":\"another-long-secret\"}",
        );
        assert!(
            second.starts_with("HTTP/1.1 409 Conflict"),
            "계정이 생긴 뒤에도 설정 경로가 열려 있음: {}",
            second.lines().next().unwrap_or_default()
        );
        assert_eq!(
            created.lock_recover().len(),
            1,
            "닫힌 뒤에도 설정 파일을 다시 고침"
        );
    }

    #[test]
    /** @brief 약한 비밀번호나 빈 아이디로는 첫 계정을 만들 수 없는지. */
    fn first_run_setup_rejects_weak_credentials() {
        let st =
            state_without_accounts(Box::new(|_, _| panic!("거부된 요청이 설정 파일에 닿았다")));
        for body in [
            "{\"user\":\"\",\"password\":\"correct-horse-battery\",\"code\":\"test-setup-code\"}",
            "{\"user\":\"owner\",\"password\":\"short\",\"code\":\"test-setup-code\"}",
            "{\"user\":\"ow\\\"ner\",\"password\":\"correct-horse-battery\",\"code\":\"test-setup-code\"}",
        ] {
            let response = setup_request(&st, body);
            assert!(
                response.starts_with("HTTP/1.1 400 Bad Request"),
                "{body} 가 거부되지 않음: {}",
                response.lines().next().unwrap_or_default()
            );
        }
    }

    #[test]
    /**
     * @brief 탭 아이콘 요청이 인증 앞에서 막혀 감사 기록을 더럽히지 않는지.
     * @details 브라우저는 이 주소를 스스로 부른다. 401로 돌려보내면 관리자가 자기
     *          브라우저가 남긴 줄을 침입 시도로 읽게 된다.
     */
    fn the_tab_icon_is_served_without_authentication() {
        let response = raw_control_request(b"GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "탭 아이콘이 인증을 요구함: {}",
            response.lines().next().unwrap_or_default()
        );
        assert!(
            response.contains("Content-Type: image/svg+xml"),
            "탭 아이콘 형식이 잘못됨: {response}"
        );
    }

    #[test]
    /** @brief 한국어 본문을 주는 응답이 문자 인코딩을 밝히는지. */
    fn plain_text_answers_declare_utf8_on_the_routed_path() {
        let response = raw_control_request(b"GET /nope HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(
            response.contains("Content-Type: text/plain; charset=utf-8"),
            "라우팅 경로의 한국어 응답에 charset이 없음: {response}"
        );
    }

    #[test]
    /** @brief 재적용 중이라도 처리 중이던 요청은 끝나는지. */
    fn generation_shutdown_lets_inflight_request_finish() {
        use std::io::{Read as _, Write as _};
        use std::sync::atomic::{AtomicBool, Ordering};

        let (_rec, stats) = channel(8, 100, 0, RecorderOpts::default(), PersistOpts::default());
        let mut controls = Controls::noop();
        controls.net_adapters = Box::new(|| {
            std::thread::sleep(Duration::from_millis(400));
            Ok("{\"platform\":\"test\",\"adapters\":[]}".to_string())
        });
        let state = AppState {
            stats,
            auth: Arc::new(Auth::single_admin("tok".into())),
            audit: AuditLog::new(100),
            controls: Arc::new(controls),
            readiness: Arc::new(AtomicBool::new(true)),
            proxy: Arc::new(ArcSwap::from_pointee(ProxyPolicy::default())),
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let sd = shutdown.clone();
        let server = std::thread::spawn(move || serve_listener(listener, state, sd).unwrap());

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let req = format!(
            "GET /v1/system/network-adapters HTTP/1.1\r\nHost: {addr}\r\n\
             Authorization: Bearer tok\r\nConnection: close\r\n\r\n"
        );
        client.write_all(req.as_bytes()).unwrap();

        std::thread::sleep(Duration::from_millis(120));
        shutdown.store(true, Ordering::Relaxed);

        let mut resp = Vec::new();
        client.read_to_end(&mut resp).unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(
            text.starts_with("HTTP/1.1 200"),
            "진행 중 요청이 리셋되지 않고 완료돼야 함: {:?}",
            &text[..text.len().min(60)]
        );
        assert!(text.contains("\"adapters\""), "어댑터 본문 포함돼야 함");

        server.join().unwrap();
    }

    /** @brief 토큰으로 요청 하나를 보내고 상태와 본문을 받는다. */
    fn call(st: &AppState, m: &str, p: &str, tok: &str, body: &str) -> (u16, String) {
        let auth = if tok.is_empty() {
            String::new()
        } else {
            format!("Bearer {tok}")
        };
        let (s, _ct, b) = route(m, p, &auth, "", body, &Caller::direct(None), st);
        (status_code(s), b)
    }

    /** @brief 세션 쿠키로 요청 하나를 보낸다. */
    fn call_session(st: &AppState, m: &str, p: &str, session: &str, body: &str) -> (u16, String) {
        let (s, _ct, b) = route(m, p, "", session, body, &Caller::direct(None), st);
        (status_code(s), b)
    }

    #[test]
    /** @brief 준비되기 전에는 상태 변경을 거부하는지. */
    fn mutations_are_rejected_until_service_is_ready() {
        let st = test_state("adm", "ro");
        st.readiness
            .store(false, std::sync::atomic::Ordering::Release);
        let (status, body) = call(
            &st,
            "POST",
            "/v1/block",
            "adm",
            r#"{"domain":"example.com"}"#,
        );
        assert_eq!(status, 503);
        assert!(body.contains("settings are being applied"));
        assert_eq!(call(&st, "GET", "/v1/stats", "adm", "").0, 200);
    }

    #[test]
    /** @brief 쉬고 있는 연결도 종료 때 정리되는지. */
    fn shutdown_joins_idle_control_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server_shutdown = shutdown.clone();
        let server = std::thread::spawn(move || {
            serve_listener(listener, test_state("adm", "ro"), server_shutdown).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(b"G").unwrap();
        std::thread::sleep(Duration::from_millis(150));
        let started = Instant::now();
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        server.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    /** @brief 문서가 인증 없이 열리는지. */
    fn openapi_is_public() {
        let st = test_state("adm", "ro");
        let (code, body) = call(&st, "GET", "/openapi.json", "", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"openapi\""));
        assert!(body.contains("/v1/backup"));
    }

    #[test]
    /** @brief 패닉과 재시작 카운터가 지표로 나오는지. */
    fn prometheus_exposes_fault_recovery_counters() {
        let text = metrics_text(&test_state("adm", "ro"));
        assert!(text.contains("onetdns_request_panics_total"));
        assert!(text.contains("onetdns_supervisor_restarts_total"));
    }

    #[test]
    /** @brief 데이터 경로가 따로 내는 지표가 함께 담기는지. */
    fn prometheus_appends_extra_metrics_from_controls() {
        let text = metrics_text(&test_state("adm", "ro"));
        assert!(
            text.contains("onetdns_transport_errors_total{transport=\"doh\",stage=\"accept\"} 3")
        );
    }

    #[test]
    /** @brief 캐시와 과부하 카운터가 지표로 나오는지. */
    fn prometheus_exposes_cache_and_overload_counters() {
        let text = metrics_text(&test_state("adm", "ro"));
        assert!(text.contains("onetdns_cache_hits_total"));
        assert!(text.contains("onetdns_cache_lookups_total"));
        assert!(text.contains("onetdns_dropped_log_events_total"));
        assert!(text.contains("onetdns_dropped_stream_events_total"));
        assert!(text.contains("onetdns_persist_failures_total"));
    }

    #[test]
    /**
     * @brief 처분 카운터가 하나도 빠짐없이 지표로 나오는지.
     *
     * @details 목록을 여기 고정해 두면 처분이 늘었을 때 이 테스트도 같이 통과해 버린다.
     *          Action::ALL에서 파생해야 새 처분이 내보내기를 강제한다.
     */
    fn prometheus_exports_every_query_disposition() {
        let text = metrics_text(&test_state("adm", "ro"));
        for action in crate::metrics::Action::ALL {
            let metric = format!("onetdns_{}_total", action.name());
            assert!(
                text.contains(&metric),
                "{metric}이 /metrics에 없습니다. 처분이 빠지면 총 질의 수가 처분 합과 어긋납니다"
            );
        }
    }

    #[test]
    /** @brief 문서가 실제 경로를 전부 덮는지. 어긋나면 없는 API를 쓰라고 알리게 된다. */
    fn openapi_covers_all_control_routes() {
        use std::collections::BTreeSet;

        let mut implemented = BTreeSet::new();
        for line in include_str!("api.rs").lines() {
            for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
                let marker = format!("(\"{method}\", \"");
                let Some(start) = line.find(&marker) else {
                    continue;
                };
                let rest = &line[start + marker.len()..];
                let Some(end) = rest.find('"') else {
                    continue;
                };
                let path = &rest[..end];
                if path.starts_with('/')
                    && !matches!(
                        path,
                        "/" | "/react.js" | "/react-dom.js" | "/support.js" | "/favicon.ico"
                    )
                {
                    implemented.insert((method.to_ascii_lowercase(), path.to_string()));
                }
            }
        }
        for (method, path) in [
            ("post", "/v1/setup"),
            ("post", "/v1/login"),
            ("post", "/v1/logout"),
            ("get", "/v1/dashboard/ws"),
            ("get", "/v1/stats/history/{range}"),
            ("get", "/v1/jobs/{id}"),
            ("get", "/v1/zones/{origin}"),
            ("put", "/v1/zones/{origin}"),
            ("delete", "/v1/zones/{origin}"),
            ("get", "/v1/zones/{origin}/dnssec"),
            ("post", "/v1/zones/{origin}/records"),
            ("delete", "/v1/zones/{origin}/records"),
        ] {
            implemented.insert((method.to_string(), path.to_string()));
        }

        let parsed = json::parse(&openapi_json()).expect("OpenAPI JSON must parse");
        let paths = match parsed.get("paths") {
            Some(json::Json::Obj(paths)) => paths,
            _ => panic!("OpenAPI paths object missing"),
        };
        let mut documented = BTreeSet::new();
        for (path, item) in paths {
            let json::Json::Obj(methods) = item else {
                panic!("OpenAPI path item must be an object");
            };
            for (method, _) in methods {
                if matches!(method.as_str(), "get" | "post" | "put" | "patch" | "delete") {
                    documented.insert((method.clone(), path.clone()));
                }
            }
        }
        assert_eq!(implemented, documented);
    }

    #[test]
    /** @brief 없앤 이전 경로가 살아 있지 않은지. */
    fn removed_unversioned_api_namespace_is_not_routed() {
        let st = test_state("adm", "ro");
        for [method, path] in [
            ["GET", "/api/auth"],
            ["POST", "/api/login"],
            ["POST", "/api/logout"],
            ["GET", "/api/dashboard/ws"],
            ["GET", "/api/stats"],
            ["GET", "/api/stats/history/60"],
            ["GET", "/api/metrics"],
            ["GET", "/api/queries"],
            ["GET", "/api/top"],
            ["GET", "/api/audit"],
            ["GET", "/api/backup"],
            ["GET", "/api/plugins"],
            ["POST", "/api/reload"],
            ["POST", "/api/block"],
            ["POST", "/api/allow"],
            ["POST", "/api/restore"],
            ["POST", "/api/service"],
            ["POST", "/api/safesearch"],
            ["POST", "/api/password"],
            ["POST", "/api/querylog/clear"],
        ] {
            assert_eq!(call(&st, method, path, "adm", "{}").0, 404, "{path}");
        }
    }

    #[test]
    /** @brief 로그인이 등급을 주고 로그아웃이 즉시 거두는지. */
    fn user_login_session_grants_role_and_logout_revokes() {
        let auth = Auth::new(vec!["adm".into()], vec![]).with_users(vec![UserCred {
            name: "alice".into(),
            hash: hash_eventually("s3cret-passphrase").into(),
            role: Role::Admin,
        }]);

        assert!(matches!(
            login_eventually(&auth, "alice", "nope"),
            LoginResult::Invalid
        ));
        assert!(matches!(
            login_eventually(&auth, "bob", "s3cret-passphrase"),
            LoginResult::Invalid
        ));

        let LoginResult::Success(token, role, name) =
            login_eventually(&auth, "alice", "s3cret-passphrase")
        else {
            panic!("login ok");
        };
        assert_eq!(role, Role::Admin);
        assert_eq!(name, "alice");
        assert_eq!(auth.role_for_session(&token), Some(Role::Admin));

        let st = AppState {
            stats: {
                let (_r, s) = channel(8, 100, 0, RecorderOpts::default(), PersistOpts::default());
                s
            },
            auth: Arc::new(auth),
            audit: AuditLog::new(100),
            controls: Arc::new(Controls::noop()),
            readiness: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            proxy: Arc::new(ArcSwap::from_pointee(ProxyPolicy::default())),
        };
        let LoginResult::Success(session, _, _) =
            login_eventually(st.auth.as_ref(), "alice", "s3cret-passphrase")
        else {
            panic!("login ok");
        };
        assert_eq!(call_session(&st, "GET", "/v1/stats", &session, "").0, 200);

        st.auth.logout(&session);
        assert_eq!(call_session(&st, "GET", "/v1/stats", &session, "").0, 401);
    }

    #[test]
    /** @brief 고정 토큰과 세션 토큰 원문이 인증 상태와 체크포인트에 남지 않는지. */
    fn auth_and_session_stores_keep_only_keyed_digests() {
        let bearer = "admin-token-that-must-not-be-stored";
        let auth = Auth::single_admin(bearer.into());
        let expected_bearer = credential_digest("token", &[bearer]);
        assert_eq!(auth.admin.lock_recover().as_slice(), &[expected_bearer]);
        assert_eq!(auth.role_for(bearer), Some(Role::Admin));

        let store = auth.sessions.clone();
        let session = auth.issue_session(Role::Admin, "admin".into(), bearer_actor(bearer));
        let expected_session = credential_digest("session", &[&session]);
        assert!(store.0.lock_recover().contains_key(&expected_session));
        assert!(store.checkpoint().0.contains_key(&expected_session));
    }

    #[test]
    /** @brief 사용자별로 따로 세되, 이름을 바꿔 가며 시도하는 것도 출발지 단위로 막는지. */
    fn login_throttle_isolates_users_but_caps_rotation_per_source() {
        let auth = Auth::default();
        let source = "127.0.0.1";
        for _ in 0..MAX_LOGIN_FAILURES {
            auth.record_login_result(source, None, "alice", false);
        }
        assert!(
            !auth.login_allowed(source, None, "alice"),
            "실패가 누적된 사용자만 차단"
        );
        assert!(
            auth.login_allowed(source, None, "bob"),
            "다른 사용자의 로그인은 막지 않음"
        );

        for i in 0..MAX_SOURCE_LOGIN_FAILURES {
            auth.record_login_result(source, None, &format!("ghost{i}"), false);
        }
        assert!(
            !auth.login_allowed(source, None, "bob"),
            "사용자명 회전은 소스 집계로 차단"
        );
        assert!(
            auth.login_allowed("192.0.2.9", None, "bob"),
            "다른 소스는 영향 없음"
        );
    }

    #[test]
    /** @brief 설정을 다시 적용해도 로그인이 유지되는지. */
    fn shared_session_store_survives_auth_rebuild() {
        let store = SessionStore::default();
        let auth1 = Auth::single_admin("tok".into()).with_sessions(store.clone());
        let actor = bearer_actor("tok");
        let session = auth1.issue_session(Role::Admin, actor.clone(), actor);

        let auth2 = Auth::single_admin("tok".into()).with_sessions(store);
        assert_eq!(auth2.role_for_session(&session), Some(Role::Admin));

        auth2.logout(&session);
        assert_eq!(auth1.role_for_session(&session), None);
    }

    #[test]
    /** @brief 적용이 실패하면 세션도 되돌아오는지. */
    fn session_checkpoint_restores_sessions_after_failed_auth_rebuild() {
        let store = SessionStore::default();
        let auth1 = Auth::single_admin("old-token".into()).with_sessions(store.clone());
        let actor = bearer_actor("old-token");
        let session = auth1.issue_session(Role::Admin, actor.clone(), actor);
        let checkpoint = store.checkpoint();

        let auth2 = Auth::single_admin("new-token".into()).with_sessions(store.clone());
        assert_eq!(auth2.role_for_session(&session), None);
        store.restore(checkpoint);
        assert_eq!(auth1.role_for_session(&session), Some(Role::Admin));
    }

    #[test]
    /** @brief 없앤 토큰의 세션이 버려지는지. 남으면 지운 자격증명으로 계속 접근한다. */
    fn shared_session_store_drops_removed_bearer_credentials() {
        let store = SessionStore::default();
        let auth1 = Auth::single_admin("old-token".into()).with_sessions(store.clone());
        let actor = bearer_actor("old-token");
        let session = auth1.issue_session(Role::Admin, actor.clone(), actor);

        let auth2 = Auth::single_admin("new-token".into()).with_sessions(store);
        assert_eq!(auth2.role_for_session(&session), None);
    }

    #[test]
    /** @brief 비밀번호가 바뀐 사용자의 세션이 버려지는지. */
    fn shared_session_store_drops_changed_user_credentials() {
        let store = SessionStore::default();
        let old_user = UserCred {
            name: "alice".into(),
            hash: "old-password-hash".into(),
            role: Role::Admin,
        };
        let auth1 = Auth::new(vec![], vec![])
            .with_users(vec![old_user.clone()])
            .with_sessions(store.clone());
        let session = auth1.issue_session(
            old_user.role,
            old_user.name.clone(),
            user_credential_id(&old_user),
        );

        let new_user = UserCred {
            name: "alice".into(),
            hash: "new-password-hash".into(),
            role: Role::ReadOnly,
        };
        let auth2 = Auth::new(vec![], vec![])
            .with_users(vec![new_user])
            .with_sessions(store);
        assert_eq!(auth2.role_for_session(&session), None);
    }

    /**
     * @brief 데드라인을 두고 연결을 받는다.
     * @details 테스트 클라이언트가 단언 실패로 죽으면 다음 연결은 오지 않는다. 데드라인이 없으면
     *          테스트가 실패로 끝나지 못하고 멈춰 버린다.
     * @return 받은 연결. 데드라인까지 오지 않으면 오류.
     */
    fn accept_before_deadline(listener: &TcpListener) -> std::io::Result<(TcpStream, SocketAddr)> {
        let deadline = Instant::now() + Duration::from_secs(10);
        listener.set_nonblocking(true)?;
        loop {
            match listener.accept() {
                Ok(pair) => {
                    listener.set_nonblocking(false)?;
                    pair.0.set_nonblocking(false)?;
                    return Ok(pair);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        listener.set_nonblocking(false)?;
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "테스트 연결을 기다리다 데드라인을 넘겼습니다",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => {
                    listener.set_nonblocking(false)?;
                    return Err(error);
                }
            }
        }
    }

    #[test]
    /**
     * @brief 토큰이 쿠키가 되지 않고도 API 클라이언트가 웹소켓을 쓸 수 있는지.
     * @details 제어 토큰은 API 전용이다. 브라우저 자격증명으로 바뀌지 않아야 하고,
     *          그렇다고 API 클라이언트의 실시간 구독이 막혀서도 안 된다.
     */
    fn a_control_token_authenticates_the_websocket_without_becoming_a_cookie() {
        let st = test_state("adm", "ro");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("test listener address");
        // 클라이언트 쪽 단언이 깨지면 두 번째 연결이 오지 않는다. 데드라인이 없으면 accept가
        // 영원히 붙들려 테스트가 실패 대신 멈춘다. 무엇이 틀렸는지 볼 수 없게 된다.
        listener
            .set_nonblocking(false)
            .expect("blocking test listener");

        std::thread::scope(|scope| {
            let server = scope.spawn(|| {
                for _ in 0..2 {
                    let Ok((stream, _)) = accept_before_deadline(&listener) else {
                        return;
                    };
                    match handle_conn(stream, &st) {
                        Ok(()) => {}

                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::BrokenPipe
                                    | std::io::ErrorKind::ConnectionAborted
                            ) => {}
                        Err(e) => panic!("handle test request: {e:?}"),
                    }
                }
            });

            let mut auth_client = TcpStream::connect(addr).expect("connect auth client");
            let auth_request = concat!(
                "GET /v1/auth HTTP/1.1\r\n",
                "Host: localhost\r\n",
                "Authorization: Bearer adm\r\n",
                "Connection: close\r\n",
                "\r\n"
            );
            std::io::Write::write_all(&mut auth_client, auth_request.as_bytes())
                .expect("write auth request");
            let mut auth_response = String::new();
            std::io::Read::read_to_string(&mut auth_client, &mut auth_response)
                .expect("read auth response");
            assert!(
                auth_response.starts_with("HTTP/1.1 200 OK"),
                "{auth_response}"
            );
            assert!(
                auth_response.contains("\"authenticated\":true"),
                "API 호출자에게 역할은 알려 줍니다: {auth_response}"
            );
            assert!(
                !auth_response.contains("Set-Cookie:"),
                "제어 토큰은 브라우저 세션으로 바뀌면 안 됩니다: {auth_response}"
            );

            let mut ws_client = TcpStream::connect(addr).expect("connect websocket client");
            ws_client
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .expect("set websocket read timeout");
            let ws_request = concat!(
                "GET /v1/dashboard/ws HTTP/1.1\r\n",
                "Host: localhost\r\n",
                "Upgrade: websocket\r\n",
                "Connection: Upgrade\r\n",
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
                "Sec-WebSocket-Version: 13\r\n",
                "Sec-WebSocket-Protocol: onetdns.v1\r\n",
                "Authorization: Bearer adm\r\n",
                "\r\n"
            )
            .to_string();
            std::io::Write::write_all(&mut ws_client, ws_request.as_bytes())
                .expect("write websocket request");

            let mut header = Vec::new();
            let mut byte = [0u8; 1];
            while !header.ends_with(b"\r\n\r\n") {
                std::io::Read::read_exact(&mut ws_client, &mut byte)
                    .expect("read websocket response header");
                header.push(byte[0]);
                assert!(header.len() < 8192, "oversized websocket response header");
            }
            let header = String::from_utf8(header).expect("websocket header UTF-8");
            assert!(
                header.starts_with("HTTP/1.1 101 Switching Protocols"),
                "{header}"
            );
            assert!(
                header.contains("Sec-WebSocket-Protocol: onetdns.v1"),
                "{header}"
            );

            std::io::Write::write_all(
                &mut ws_client,
                &[0x88, 0x82, 0x01, 0x02, 0x03, 0x04, 0x02, 0xEA],
            )
            .expect("write websocket close frame");
            drop(ws_client);

            server.join().expect("join test server");
        });
    }

    #[test]
    /** @brief 검증과 모의 실행이 변경 잠금을 잡지 않는지. 잡으면 읽기 성격 요청이 서로를 기다린다. */
    fn diagnostic_post_requests_do_not_take_the_mutation_lock() {
        for path in [
            "/v1/config/validate",
            "/v1/config/diff",
            "/v1/config/set/diff",
            "/v1/explain",
            "/v1/policies/simulate",
            "/v1/tls/validate",
            "/v1/tls/revocation-check",
            "/v1/upstreams/test",
        ] {
            assert!(!is_state_changing_request("POST", path), "{path}");
        }
        assert!(is_state_changing_request("POST", "/v1/config/set"));
        assert!(is_state_changing_request("PATCH", "/v1/clients"));
        assert!(!is_state_changing_request("GET", "/v1/config"));
    }

    #[test]
    /** @brief 클러스터 제안이 합의 순서를 쓰는지. 여기서 또 잠그면 제안끼리 막힌다. */
    fn raft_proposals_use_log_ordering_instead_of_the_http_mutation_lock() {
        assert!(is_state_changing_request("POST", "/v1/cluster/propose"));
        assert!(!requires_control_mutation_lock(
            "POST",
            "/v1/cluster/propose"
        ));
        assert!(requires_control_mutation_lock("POST", "/v1/config/set"));
    }

    #[test]
    /**
     * @brief 한국어 본문을 보내는 text 응답이 문자 인코딩을 밝히는지.
     * @details charset이 없으면 클라이언트가 ISO-8859-1로 읽어도 규격 위반이 아니라서
     *          오류 문구와 /metrics의 HELP가 그대로 깨진다.
     */
    fn text_responses_declare_utf8() {
        assert_eq!(with_charset("text/plain"), "text/plain; charset=utf-8");
        assert_eq!(
            with_charset("text/plain; version=0.0.4"),
            "text/plain; version=0.0.4; charset=utf-8"
        );
        assert_eq!(
            with_charset("text/html; charset=utf-8"),
            "text/html; charset=utf-8",
            "이미 밝혔으면 덧붙이지 않습니다"
        );
        assert_eq!(
            with_charset("application/json"),
            "application/json",
            "JSON은 규격상 UTF-8이라 붙이지 않습니다"
        );
    }

    #[test]
    /**
     * @brief 제어 토큰이 브라우저 세션으로 바뀌지 않는지.
     * @details 토큰은 API 전용이다. 세션 쿠키로 바꿔 주면 사람이 외워 넣을 수 없는 값이
     *          브라우저 자격증명이 되고, 토큰 하나가 새면 콘솔 전체가 함께 열린다.
     */
    fn a_control_token_never_becomes_a_browser_session() {
        let st = test_state("adm", "ro");
        let (code, body) = call(&st, "GET", "/v1/auth", "adm", "");
        assert_eq!(code, 200);
        assert!(
            body.contains("\"authenticated\":true"),
            "API 호출자에게는 역할을 알려 줍니다: {body}"
        );
        assert!(
            st.auth.role_for_session("adm").is_none(),
            "토큰 값 자체가 세션으로 통해서는 안 됩니다"
        );
    }

    #[test]
    /** @brief 인증 상태 조회가 인증 없이 열리는지. 로그인 화면이 이것을 먼저 본다. */
    fn auth_status_endpoint_is_public() {
        let st = test_state("adm", "ro");
        let (code, body) = call(&st, "GET", "/v1/auth", "", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"login_enabled\":false"));
        assert!(body.contains("\"authenticated\":false"));
        for _ in 0..3 {
            call(&st, "GET", "/v1/auth", "", "");
        }
        let (_, audit) = call(&st, "GET", "/v1/audit", "adm", "");
        assert!(
            !audit.contains("\"actor\":\"anonymous\""),
            "인증 없는 상태 확인이 감사 기록을 채우면 안 됩니다: {audit}"
        );
    }

    #[test]
    /** @brief 인증 없는 요청이 막히는지. */
    fn rbac_unauthenticated_401() {
        let st = test_state("adm", "ro");
        assert_eq!(call(&st, "GET", "/v1/stats", "", "").0, 401);
        assert_eq!(call(&st, "GET", "/v1/stats", "wrong", "").0, 401);
    }

    #[test]
    /**
     * @brief 되풀이되는 요청 실패가 로그를 덮지 않는지, 진단이 변경으로 기록되지 않는지.
     *
     * @details 토큰이 틀린 클라이언트 하나가 초당 수십 번 두드리면 실패마다 한 줄씩 남던
     *          때는 그 로그가 원래 문제보다 커졌다. 처음과 2의 거듭제곱 번째만 남긴다.
     * @note 아무것도 바꾸지 않는 진단 POST를 「변경 요청」으로 남기면 조사 한 번에 수백 줄이
     *       쌓여 정작 진짜 변경이 묻힌다.
     */
    fn repeated_failures_are_counted_and_diagnostics_are_not_mutations() {
        let st = test_state("adm", "ro");
        // 카운터는 프로세스 전역이라 실제 경로를 쓰면 병렬로 실행되는 다른 테스트의 401이 섞인다.
        let probe = "/v1/__repeated_failure_probe";
        let before = request_failure_count("POST", probe, 401);
        for _ in 0..20 {
            assert_eq!(call(&st, "POST", probe, "", "{}").0, 401);
        }
        assert_eq!(
            request_failure_count("POST", probe, 401),
            before + 20,
            "실패를 세지 않으면 억제할 기준이 없습니다"
        );

        // 진단 POST는 아무것도 바꾸지 않는다. 변경으로 분류되면 안 된다.
        for path in ["/v1/resolve", "/v1/explain", "/v1/policies/simulate"] {
            assert!(
                !is_state_changing_request("POST", path),
                "{path}는 아무것도 바꾸지 않습니다"
            );
        }
        // 대조군. 진짜 변경은 그대로 변경이어야 한다.
        assert!(is_state_changing_request("POST", "/v1/block"));
        assert!(is_state_changing_request("DELETE", "/v1/tokens"));
    }

    #[test]
    /** @brief 서로 다른 실패 경로가 진단 카운터 메모리를 무한히 늘리지 않는지. */
    fn request_failure_tracking_has_a_fixed_cardinality() {
        let mut counts = RequestFailureCounts::default();
        let method = "GET";
        for index in 0..MAX_REQUEST_FAILURE_COUNTS {
            let path = format!("/__failure_cardinality_probe/{index}");
            assert_eq!(counts.increment(method, &path, 404), 1);
        }
        assert_eq!(counts.counts.len(), MAX_REQUEST_FAILURE_COUNTS);
        assert_eq!(
            counts.increment(method, "/__failure_cardinality_probe/0", 404),
            2,
            "상한에 닿아도 이미 추적 중인 실패의 개별 횟수는 유지해야 합니다"
        );

        let mut sampled = Vec::new();
        for index in 1..=64_u64 {
            let path = format!("/__failure_cardinality_overflow/{index}");
            let count = counts.increment(method, &path, 404);
            assert_eq!(
                count, index,
                "상한 밖 실패는 단일 포화 카운터로 묶어야 합니다"
            );
            if should_log_repeated_failure(count) {
                sampled.push(count);
            }
        }
        assert_eq!(counts.counts.len(), MAX_REQUEST_FAILURE_COUNTS);
        assert_eq!(sampled, [1, 2, 4, 8, 16, 32, 64]);
    }

    #[test]
    /**
     * @brief 이름을 실제로 물어보는 곳을 읽기 전용도 쓸 수 있는지.
     *
     * @details 무엇으로 풀리는지 보는 것은 진단이지 변경이 아니다. 읽기 전용 세션이
     *          이것을 못 쓰면 조사할 때마다 관리자 토큰을 꺼내게 되고, 그것이 더 위험하다.
     * @note 이 테스트 모듈의 기본 콜백은 수신 주소가 없다고 답한다. 권한 판정만 본다.
     */
    fn resolving_a_name_is_allowed_for_readonly_sessions() {
        let st = test_state("adm", "ro");
        assert_ne!(
            call(
                &st,
                "POST",
                "/v1/resolve",
                "ro",
                "{\"qname\":\"example.com\"}"
            )
            .0,
            403,
            "읽기 전용이 이름을 물어보지 못하면 안 됩니다"
        );
        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/resolve",
                "",
                "{\"qname\":\"example.com\"}"
            )
            .0,
            401,
            "인증 없이 물어봐서는 안 됩니다"
        );
    }

    #[test]
    /**
     * @brief 부팅 서비스 곳이 권한과 미지원 운영체제를 옳게 다루는지.
     *
     * @details 상태 조회는 읽기 전용도 볼 수 있어야 대시보드가 무엇을 보여 줄지 정할 수
     *          있고, 등록과 제거는 관리자만 해야 한다. 부팅마다 뜨는 서비스를 만드는 일이다.
     * @note 기본 콜백은 지원하지 않는다고 답한다. 대시보드는 그 값을 보고 이 항목을 감춘다.
     */
    fn boot_service_is_admin_only_and_reports_unsupported_platforms() {
        let st = test_state("adm", "ro");

        let (code, body) = call(&st, "GET", "/v1/system/service", "ro", "");
        assert_eq!(code, 200, "상태 조회는 읽기 전용도 됩니다");
        assert!(
            body.contains("\"supported\":false"),
            "지원하지 않는 운영체제라고 알려야 합니다: {body}"
        );

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/system/service",
                "ro",
                "{\"action\":\"install\"}"
            )
            .0,
            403,
            "읽기 전용이 서비스를 등록해서는 안 됩니다"
        );
        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/system/service",
                "",
                "{\"action\":\"install\"}"
            )
            .0,
            401,
            "인증 없이 서비스를 등록해서는 안 됩니다"
        );
        assert_eq!(
            call(&st, "GET", "/v1/system/service", "", "").0,
            401,
            "인증 없이 상태를 봐서는 안 됩니다"
        );

        let (code, body) = call(
            &st,
            "POST",
            "/v1/system/service",
            "adm",
            "{\"action\":\"install\"}",
        );
        assert_eq!(code, 400, "지원하지 않는 곳에서는 실패로 답해야 합니다");
        assert!(
            body.contains("Windows"),
            "어디서 되는지 알려야 합니다: {body}"
        );
    }

    #[test]
    /**
     * @brief 업데이트 경로의 권한과 응답 코드.
     * @details 상태는 읽기 전용도 보고 작업은 관리자만 시작한다. 적용 요청에 버전이 없으면 400,
     *          마지막 확인 결과와 다르면 409 다. 지금 상태로 할 수 없는 작업도 409 다.
     */
    fn update_routes_check_roles_and_the_confirmed_version() {
        let st = test_state("adm", "ro");
        assert_eq!(call(&st, "GET", "/v1/system/update", "ro", "").0, 200);
        assert_eq!(call(&st, "GET", "/v1/system/update", "", "").0, 401);
        for path in [
            "/v1/system/update/check",
            "/v1/system/update/apply",
            "/v1/system/update/rollback",
        ] {
            let body = "{\"version\":\"9.9.9\"}";
            assert_eq!(call(&st, "POST", path, "ro", body).0, 403, "{path}");
            assert_eq!(call(&st, "POST", path, "", body).0, 401, "{path}");
        }

        assert_eq!(
            call(&st, "POST", "/v1/system/update/check", "adm", "").0,
            200
        );
        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/system/update/apply",
                "adm",
                "{\"version\":\"9.9.9\"}"
            )
            .0,
            200
        );
        for body in ["", "{}", "{\"version\":\"\"}", "{\"version\":9}"] {
            assert_eq!(
                call(&st, "POST", "/v1/system/update/apply", "adm", body).0,
                400,
                "{body}"
            );
        }
        let (code, body) = call(
            &st,
            "POST",
            "/v1/system/update/apply",
            "adm",
            "{\"version\":\"9.9.8\"}",
        );
        assert_eq!(code, 409);
        assert!(body.contains("9.9.9"), "{body}");
        assert_eq!(
            call(&st, "POST", "/v1/system/update/rollback", "adm", "").0,
            409
        );
    }

    #[test]
    /**
     * @brief 업데이트 요청이 변경 잠금과 클러스터 합의를 거치지 않는지.
     * @details 설정을 바꾸지 않는 노드 로컬 작업이다. 합의를 거치면 팔로워에서 거절되거나, 설정
     *          파일을 읽지 못하는 동안 실패한다.
     */
    fn update_routes_do_not_go_through_cluster_write() {
        let base = test_state("adm", "ro");
        let mut controls = Controls::noop();
        controls.cluster_write = Box::new(|_, _, _, _| {
            (
                "503 Service Unavailable",
                "application/json",
                "{\"error\":\"cluster\"}".to_string(),
            )
        });
        controls.update_check = Box::new(|| Ok("{\"id\":1,\"status\":\"running\"}".to_string()));
        controls.update_apply = Box::new(|_| Ok("{\"id\":2,\"status\":\"running\"}".to_string()));
        controls.update_rollback = Box::new(|| Ok("{\"id\":3,\"status\":\"running\"}".to_string()));
        let st = AppState {
            controls: Arc::new(controls),
            ..base
        };

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/block",
                "adm",
                "{\"domain\":\"example.com\"}"
            )
            .0,
            503,
            "설정을 바꾸는 요청은 합의를 거칩니다"
        );
        for (path, body) in [
            ("/v1/system/update/check", ""),
            ("/v1/system/update/apply", "{\"version\":\"9.9.9\"}"),
            ("/v1/system/update/rollback", ""),
        ] {
            assert_eq!(call(&st, "POST", path, "adm", body).0, 200, "{path}");
        }
    }

    #[test]
    /** @brief 읽기 전용이 조회만 되고 변경은 막히는지. */
    fn rbac_readonly_can_get_but_not_mutate() {
        let st = test_state("adm", "ro");
        assert_eq!(
            call(&st, "GET", "/v1/stats", "ro", "").0,
            200,
            "readonly GET 허용"
        );
        let (code, _) = call(&st, "POST", "/v1/block", "ro", "{\"domain\":\"x.com\"}");
        assert_eq!(code, 403, "readonly POST 금지");
    }

    #[test]
    /** @brief 감사 기록이 바뀐 키만 남기고 값은 남기지 않는지. 값에는 비밀이 들어 있다. */
    fn audit_detail_lists_changed_keys_without_secret_values() {
        let detail = audit_request_detail(
            "POST",
            "/v1/config/set",
            r#"{"password":"do-not-log","safe_search":true,"port":53,"url":"https://user:secret@example.test/path?token=hidden"}"#,
        );
        assert!(detail.contains("changed_keys=password,port,safe_search,url"));
        assert!(detail.contains("port=53"));
        assert!(!detail.contains("do-not-log"));
        assert!(!detail.contains("secret"));
        assert!(!detail.contains("hidden"));
        assert!(!detail.contains("example.test"));
    }

    #[test]
    /**
     * @brief 설정을 바꾸지 않는 진단 요청의 본문을 변경 항목으로 적지 않는지.
     * @details 연결 테스트나 설정 검증이 변경 항목으로 남으면 감사 기록을 읽는 사람이 바뀌지 않은
     *          설정을 바뀐 것으로 읽는다.
     */
    fn audit_detail_labels_diagnostic_request_fields_separately() {
        let detail = audit_request_detail("POST", "/v1/upstreams/test", r#"{"addr":"1.1.1.1"}"#);
        assert_eq!(detail, "request_keys=addr");
        let detail = audit_request_detail("POST", "/v1/upstreams", r#"{"addr":"1.1.1.1"}"#);
        assert_eq!(detail, "changed_keys=addr");
    }

    #[test]
    /** @brief JSON이 아닌 본문은 크기만 남기는지. */
    fn audit_detail_reports_non_json_body_size() {
        let detail = audit_request_detail("POST", "/v1/config/apply", "mode = \"public\"");
        assert!(detail.starts_with("body_bytes="));
    }

    #[test]
    /** @brief 관리자의 변경이 되고 감사에 남는지. */
    fn rbac_admin_can_mutate_and_is_audited() {
        let st = test_state("adm", "ro");
        let (code, _) = call(&st, "POST", "/v1/block", "adm", "{\"domain\":\"ads.com\"}");
        assert_eq!(code, 200, "admin POST 허용");

        let (_, audit) = call(&st, "GET", "/v1/audit", "adm", "");
        assert!(audit.contains("\"path\":\"/v1/block\""));
        assert!(audit.contains("\"actor\":\"token-"));
        assert!(audit.contains("\"role\":\"admin\""));
        assert!(audit.contains("\"status\":200"));
    }

    #[test]
    /** @brief 거부된 시도도 감사에 남는지. */
    fn audit_records_denials() {
        let st = test_state("adm", "ro");
        call(&st, "GET", "/v1/stats", "badtoken", "");
        call(&st, "POST", "/v1/block", "ro", "{\"domain\":\"x\"}");
        let (_, audit) = call(&st, "GET", "/v1/audit", "adm", "");
        assert!(audit.contains("\"status\":401"), "401 기록");
        assert!(audit.contains("\"role\":\"none\""));
        assert!(audit.contains("\"status\":403"), "403 기록");
    }

    #[test]
    /** @brief 내보내고 되읽는 왕복. */
    fn backup_restore_roundtrip() {
        let st = test_state("adm", "ro");
        call(&st, "POST", "/v1/block", "adm", "{\"domain\":\"a.com\"}");
        call(&st, "POST", "/v1/block", "adm", "{\"domain\":\"b.com\"}");
        let (code, backup) = call(&st, "GET", "/v1/backup", "adm", "");
        assert_eq!(code, 200);
        assert!(backup.contains("a.com") && backup.contains("b.com"));

        let st2 = test_state("adm", "ro");
        let (code, resp) = call(&st2, "POST", "/v1/restore", "adm", &backup);
        assert_eq!(code, 200);
        assert!(resp.contains("\"block\":2"), "복원 후 block 2: {resp}");
    }

    #[test]
    /** @brief 권한 zone 편집 왕복과 등급 제한. */
    fn zone_crud_roundtrip_and_rbac() {
        let st = test_state("adm", "ro");
        let zone_text = "$ORIGIN api.test.\n@ IN SOA ns1 admin 1 300 60 86400 60\n";

        let (code, body) = call(&st, "PUT", "/v1/zones/api.test", "adm", zone_text);
        assert_eq!(code, 200, "{body}");
        assert!(body.contains("\"origin\":\"api.test\""));

        let (code, body) = call(&st, "GET", "/v1/zones/api.test", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("api.test"));

        assert_eq!(
            call(&st, "PUT", "/v1/zones/api.test", "ro", zone_text).0,
            403
        );
        assert_eq!(call(&st, "DELETE", "/v1/zones/api.test", "ro", "").0, 403);

        assert_eq!(
            call(&st, "PUT", "/v1/zones/api.test", "adm", "bad zone").0,
            400
        );
        assert_eq!(
            call(&st, "POST", "/v1/zones/api.test", "adm", zone_text).0,
            405
        );

        assert_eq!(call(&st, "DELETE", "/v1/zones/api.test", "adm", "").0, 200);
        assert_eq!(call(&st, "GET", "/v1/zones/api.test", "adm", "").0, 404);

        let (_, audit) = call(&st, "GET", "/v1/audit", "adm", "");
        assert!(audit.contains("\"path\":\"/v1/zones/api.test\""));
    }

    #[test]
    /** @brief 실제 적용 중인 설정 조회. */
    fn effective_config_endpoint() {
        let st = test_state("adm", "ro");
        let (code, body) = call(&st, "GET", "/v1/config/effective", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"mode\""));

        assert_eq!(call(&st, "GET", "/v1/config/effective", "", "").0, 401);
    }

    #[test]
    /** @brief 읽기 전용이 내보내기는 되고 되읽기는 막히는지. */
    fn readonly_can_read_backup_not_restore() {
        let st = test_state("adm", "ro");
        assert_eq!(call(&st, "GET", "/v1/backup", "ro", "").0, 200);
        assert_eq!(call(&st, "POST", "/v1/restore", "ro", "{}").0, 403);
    }

    #[test]
    /** @brief 작업 상태 조회. */
    fn jobs_endpoints() {
        let st = test_state("adm", "ro");

        let (code, body) = call(&st, "GET", "/v1/jobs", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"id\":1"));

        assert_eq!(call(&st, "GET", "/v1/jobs/1", "ro", "").0, 200);
        assert_eq!(call(&st, "GET", "/v1/jobs/999", "ro", "").0, 404);
        assert_eq!(call(&st, "GET", "/v1/jobs/abc", "ro", "").0, 400);

        assert_eq!(call(&st, "POST", "/v1/jobs/refresh", "adm", "").0, 200);
        assert_eq!(call(&st, "POST", "/v1/jobs/refresh", "ro", "").0, 403);
        assert_eq!(call(&st, "POST", "/v1/jobs/refresh", "", "").0, 401);
    }

    #[test]
    /** @brief 설정 적용과 되돌리기. */
    fn config_apply_rollback_endpoints() {
        let st = test_state("adm", "ro");

        assert_eq!(
            call(&st, "POST", "/v1/config/apply", "adm", "mode=\"personal\"").0,
            200
        );
        assert_eq!(call(&st, "POST", "/v1/config/apply", "adm", "bad").0, 400);

        assert_eq!(call(&st, "POST", "/v1/config/rollback", "adm", "").0, 200);

        assert_eq!(call(&st, "POST", "/v1/config/apply", "ro", "x").0, 403);
        assert_eq!(call(&st, "POST", "/v1/config/rollback", "", "").0, 401);
    }

    #[test]
    /** @brief 설정 개별 항목 읽기와 쓰기. */
    fn config_set_and_get_endpoints() {
        let st = test_state("adm", "ro");

        let (code, body) = call(&st, "POST", "/v1/config/set", "adm", "{\"prefetch\":true}");
        assert_eq!(code, 200);
        assert!(body.contains("\"applied\":true"));

        assert_eq!(
            call(&st, "POST", "/v1/config/set", "adm", "{\"bad\":1}").0,
            400
        );

        assert_eq!(
            call(&st, "POST", "/v1/config/set", "ro", "{\"prefetch\":true}").0,
            403
        );
        assert_eq!(
            call(&st, "POST", "/v1/config/set", "", "{\"prefetch\":true}").0,
            401
        );

        assert_eq!(call(&st, "GET", "/v1/config", "ro", "").0, 200);
    }

    #[test]
    /** @brief 스키마 조회, 업스트림 테스트, 캐시 비우기. */
    fn schema_upstream_test_cache_flush_endpoints() {
        let st = test_state("adm", "ro");

        let (code, body) = call(&st, "GET", "/v1/config/schema", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"keys\""));

        let (c2, b2) = call(
            &st,
            "POST",
            "/v1/upstreams/test",
            "adm",
            "{\"addr\":\"1.1.1.1\"}",
        );
        assert_eq!(c2, 200);
        assert!(b2.contains("\"ok\""));
        assert_eq!(call(&st, "POST", "/v1/upstreams/test", "ro", "{}").0, 403);

        assert_eq!(call(&st, "POST", "/v1/cache/flush", "adm", "").0, 200);
        assert_eq!(call(&st, "POST", "/v1/cache/flush", "ro", "").0, 403);
    }

    #[test]
    /** @brief 토큰 관리. */
    fn token_crud_endpoints() {
        let st = test_state("adm", "ro");

        let (code, body) = call(&st, "GET", "/v1/tokens", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"tokens\""));
        assert!(body.contains("\"masked\""));

        let (c2, b2) = call(&st, "POST", "/v1/tokens", "adm", "{\"role\":\"readonly\"}");
        assert_eq!(c2, 200);
        assert!(b2.contains("\"token\""));
        assert!(b2.contains("\"id\""));

        assert_eq!(call(&st, "POST", "/v1/tokens", "ro", "{}").0, 403);

        let (c3, b3) = call(&st, "DELETE", "/v1/tokens", "adm", "{\"id\":\"ab12\"}");
        assert_eq!(c3, 200);
        assert!(b3.contains("\"removed\""));

        assert_eq!(
            call(&st, "DELETE", "/v1/tokens", "ro", "{\"id\":\"x\"}").0,
            403
        );
    }

    #[test]
    /** @brief 재작성, 서비스 차단, 접근 제어, TLS 설정. */
    fn rewrites_services_access_tls_endpoints() {
        let st = test_state("adm", "ro");

        assert!(call(&st, "GET", "/v1/rewrites", "ro", "")
            .1
            .contains("router.lan"));
        let (c, b) = call(
            &st,
            "POST",
            "/v1/rewrites",
            "adm",
            "{\"domain\":\"x.lan\",\"answer\":\"10.0.0.9\"}",
        );
        assert_eq!(c, 200);
        assert!(b.contains("added"));
        assert_eq!(call(&st, "POST", "/v1/rewrites", "ro", "{}").0, 403);
        assert_eq!(
            call(
                &st,
                "DELETE",
                "/v1/rewrites",
                "adm",
                "{\"domain\":\"x.lan\"}"
            )
            .0,
            200
        );

        assert!(call(&st, "GET", "/v1/services", "ro", "")
            .1
            .contains("youtube"));
        assert!(call(&st, "GET", "/v1/access", "ro", "")
            .1
            .contains("allowed"));
        assert!(call(&st, "GET", "/v1/tls", "ro", "")
            .1
            .contains("configured"));
        assert_eq!(call(&st, "POST", "/v1/tls/validate", "adm", "").0, 200);
        assert_eq!(call(&st, "POST", "/v1/tls/validate", "ro", "").0, 403);

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/tls/configure",
                "adm",
                "{\"cert_path\":\"/c.pem\",\"key_path\":\"/k.pem\"}"
            )
            .0,
            200
        );
        assert_eq!(call(&st, "POST", "/v1/tls/configure", "adm", "{}").0, 400);
        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/tls/configure",
                "ro",
                "{\"key_path\":\"/k.pem\"}"
            )
            .0,
            403
        );

        let (code, body) = call(
            &st,
            "POST",
            "/v1/tls/revocation-check",
            "adm",
            "{\"certificate_chain\":\"-----BEGIN CERTIFICATE-----\"}",
        );
        assert_eq!(code, 200);
        assert!(body.contains("\"revoked\""));
        assert_eq!(
            call(&st, "POST", "/v1/tls/revocation-check", "adm", "{}").0,
            400
        );
        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/tls/revocation-check",
                "ro",
                "{\"certificate_chain\":\"x\"}"
            )
            .0,
            403
        );

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/acme/issue",
                "adm",
                "{\"account_only\":true}"
            )
            .0,
            200
        );
        assert_eq!(call(&st, "POST", "/v1/acme/issue", "adm", "{}").0, 400);
        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/acme/issue",
                "ro",
                "{\"account_only\":true}"
            )
            .0,
            403
        );
    }

    #[test]
    /** @brief 자원 사용량 조회. */
    fn resource_endpoints() {
        let st = test_state("adm", "ro");

        let (code, body) = call(&st, "GET", "/v1/filter/subscriptions", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"urls\""));

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/filter/subscriptions",
                "adm",
                "{\"url\":\"https://x/y\"}"
            )
            .0,
            200
        );
        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/filter/subscriptions",
                "ro",
                "{\"url\":\"x\"}"
            )
            .0,
            403
        );
        assert_eq!(
            call(&st, "POST", "/v1/filter/subscriptions", "", "x").0,
            401
        );

        assert_eq!(
            call(
                &st,
                "DELETE",
                "/v1/filter/subscriptions",
                "adm",
                "{\"url\":\"x\"}"
            )
            .0,
            200
        );

        assert_eq!(call(&st, "GET", "/v1/clients", "ro", "").0, 200);
        assert_eq!(call(&st, "GET", "/v1/upstreams", "ro", "").0, 200);

        let (code, body) = call(&st, "GET", "/v1/dhcp/leases", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"v4\"") && body.contains("\"v6\""));
        let (code, body) = call(
            &st,
            "POST",
            "/v1/dhcp/leases",
            "adm",
            "{\"identity\":\"mac:aabbccddeeff\",\"mac\":\"aa:bb:cc:dd:ee:ff\",\"ip\":\"192.168.1.100\",\"expiry\":\"9999999999\"}",
        );
        assert_eq!(code, 200);
        assert!(body.contains("\"synced\""), "{body}");

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/dhcp/leases",
                "ro",
                "{\"identity\":\"mac:aabbccddeeff\",\"mac\":\"aa:bb:cc:dd:ee:ff\",\"ip\":\"192.168.1.100\",\"expiry\":\"9999999999\"}"
            )
            .0,
            403
        );
    }

    #[test]
    /** @brief DHCP 고정 할당 관리. */
    fn dhcp_static_reservation_crud() {
        let st = test_state("adm", "ro");

        let (code, body) = call(&st, "GET", "/v1/dhcp/static", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"reservations\""));

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/dhcp/static",
                "adm",
                "{\"identity\":\"mac:aabbccddeeff\",\"ip\":\"192.168.1.200\"}"
            )
            .0,
            200
        );

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/dhcp/static",
                "adm",
                "{\"ip\":\"192.168.1.200\"}"
            )
            .0,
            400
        );

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/dhcp/static",
                "ro",
                "{\"identity\":\"mac:aabbccddeeff\",\"ip\":\"192.168.1.200\"}"
            )
            .0,
            403
        );

        assert_eq!(
            call(
                &st,
                "DELETE",
                "/v1/dhcp/static",
                "adm",
                "{\"identity\":\"mac:aabbccddeeff\"}"
            )
            .0,
            200
        );
        assert_eq!(
            call(
                &st,
                "DELETE",
                "/v1/dhcp/static",
                "adm",
                "{\"identity\":\"mac:000000000000\"}"
            )
            .0,
            404
        );
    }

    #[test]
    /** @brief 클라이언트별 업스트림 관리. */
    fn clients_upstreams_crud() {
        let st = test_state("adm", "ro");

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/clients",
                "adm",
                "{\"name\":\"kid\",\"ids\":[\"192.168.1.5/32\"]}"
            )
            .0,
            200
        );
        assert_eq!(
            call(&st, "POST", "/v1/clients", "adm", "{\"ids\":[]}").0,
            400
        );
        assert_eq!(
            call(&st, "POST", "/v1/clients", "ro", "{\"name\":\"x\"}").0,
            403
        );
        assert_eq!(call(&st, "POST", "/v1/clients", "", "{}").0, 401);

        assert_eq!(
            call(&st, "DELETE", "/v1/clients", "adm", "{\"name\":\"kid\"}").0,
            200
        );
        assert_eq!(
            call(&st, "DELETE", "/v1/clients", "adm", "{\"name\":\"ghost\"}").0,
            400
        );

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/upstreams",
                "adm",
                "{\"addr\":\"9.9.9.9\"}"
            )
            .0,
            200
        );

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/upstreams",
                "adm",
                "{\"addr\":\"8.8.8.8\"}"
            )
            .0,
            200
        );
        assert_eq!(
            call(&st, "POST", "/v1/upstreams", "adm", "{\"addr\":\"\"}").0,
            400
        );
        assert_eq!(
            call(
                &st,
                "DELETE",
                "/v1/upstreams",
                "adm",
                "{\"addr\":\"9.9.9.9\"}"
            )
            .0,
            200
        );
        assert_eq!(
            call(&st, "POST", "/v1/upstreams", "ro", "{\"addr\":\"1.1.1.1\"}").0,
            403
        );
        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/upstreams",
                "adm",
                "{\"upstream\":\"1.1.1.1\"}"
            )
            .0,
            400
        );
        assert_eq!(call(&st, "POST", "/v1/upstreams", "adm", "1.1.1.1").0, 400);
    }

    #[test]
    /** @brief 질의 하나가 왜 그렇게 처리되는지 설명. */
    fn explain_endpoint() {
        let st = test_state("adm", "ro");
        let (code, body) = call(
            &st,
            "POST",
            "/v1/explain",
            "adm",
            "{\"qname\":\"ads.example\",\"qtype\":\"A\"}",
        );
        assert_eq!(code, 200);
        assert!(body.contains("\"decision\"") && body.contains("\"rcode\""));
    }

    #[test]
    /** @brief 헬스, 준비 상태, 클러스터 조회. */
    fn health_ready_cluster_endpoints() {
        let st = test_state("adm", "ro");

        assert_eq!(call(&st, "GET", "/healthz", "", "").0, 200);
        assert_eq!(call(&st, "GET", "/readyz", "", "").0, 200);

        let (code, body) = call(&st, "GET", "/v1/cluster/nodes", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"self\"") && body.contains("\"peers\""));

        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/cluster/propose",
                "adm",
                "{\"patch\":{\"prefetch\":true}}"
            )
            .0,
            200
        );
        assert_eq!(
            call(
                &st,
                "POST",
                "/v1/cluster/propose",
                "ro",
                "{\"patch\":{\"prefetch\":true}}"
            )
            .0,
            403
        );
    }

    #[test]
    /** @brief 권한 zone의 레코드 편집. */
    fn zone_record_endpoints() {
        let st = test_state("adm", "ro");

        let (code, body) = call(
            &st,
            "POST",
            "/v1/zones/api.test/records",
            "adm",
            "www 300 IN A 1.2.3.4",
        );
        assert_eq!(code, 200);
        assert!(body.contains("\"added\""));

        let del = call(
            &st,
            "DELETE",
            "/v1/zones/api.test/records",
            "adm",
            "{\"name\":\"www\",\"type\":\"A\"}",
        );
        assert_eq!(del.0, 200);

        assert_eq!(
            call(&st, "POST", "/v1/zones/api.test/records", "ro", "x").0,
            403
        );
        assert_eq!(
            call(&st, "POST", "/v1/zones/api.test/records", "", "x").0,
            401
        );
        assert_eq!(
            call(&st, "GET", "/v1/zones/api.test/records", "adm", "").0,
            405
        );
        assert_eq!(
            call(
                &st,
                "PUT",
                "/v1/zones/api.test/records",
                "adm",
                "www 300 IN A 1.2.3.4"
            )
            .0,
            405
        );
    }

    #[test]
    /** @brief zone 서명 상태 조회. */
    fn zone_dnssec_endpoint() {
        let st = test_state("adm", "ro");
        let (code, body) = call(&st, "GET", "/v1/zones/api.test/dnssec", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"signed\""));
        assert!(body.contains("\"origin\":\"api.test\""));

        assert_eq!(call(&st, "GET", "/v1/zones/api.test/dnssec", "", "").0, 401);
        assert_eq!(
            call(&st, "POST", "/v1/zones/api.test/dnssec", "adm", "").0,
            405
        );
    }

    #[test]
    /** @brief 필터 적용 결과 보고. */
    fn filter_report_endpoint() {
        let st = test_state("adm", "ro");
        let (code, body) = call(&st, "GET", "/v1/filter/report", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"rules_total\""));

        assert_eq!(call(&st, "GET", "/v1/filter/report", "", "").0, 401);
        assert_eq!(call(&st, "GET", "/v1/filter/compat", "ro", "").0, 404);
    }

    #[test]
    /** @brief 가장 많이 걸린 규칙 목록. */
    fn top_rules_endpoint() {
        let st = test_state("adm", "ro");
        let (code, body) = call(&st, "GET", "/v1/filter/top-rules", "ro", "");
        assert_eq!(code, 200);
        assert!(body.contains("\"enabled\""));
        assert_eq!(call(&st, "GET", "/v1/filter/top-rules", "", "").0, 401);
    }

    #[test]
    /** @brief 쿠키 헤더가 여러 번 와도 파서가 받아들이는지. */
    fn repeated_cookie_header_fields_are_accepted_by_http_parser() {
        let st = test_state("adm", "ro");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("test listener address");

        std::thread::scope(|scope| {
            let server = scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accept test connection");
                handle_conn(stream, &st).expect("handle test request");
            });

            let mut client = TcpStream::connect(addr).expect("connect test client");
            let request = concat!(
                "GET /v1/auth HTTP/1.1\r\n",
                "Host: localhost\r\n",
                "Cookie: theme=dark\r\n",
                "Cookie: onetdns_session=stale\r\n",
                "Connection: close\r\n",
                "\r\n"
            );
            std::io::Write::write_all(&mut client, request.as_bytes()).expect("write test request");
            let mut response = String::new();
            std::io::Read::read_to_string(&mut client, &mut response).expect("read test response");
            assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
            assert!(
                response.contains("X-Content-Type-Options: nosniff"),
                "{response}"
            );
            assert!(response.contains("Content-Security-Policy:"), "{response}");
            assert!(response.contains("Cache-Control: no-store"), "{response}");

            server.join().expect("join test server");
        });
    }

    #[test]
    /** @brief 리바인딩과 교차 출처 요청을 막는지. 브라우저를 통한 관리 API 호출을 차단하는 방어다. */
    fn control_authority_rejects_dns_rebinding_and_cross_origin_requests() {
        let host = |value: &str| control_authority(value, 8080).map(|a| (a.host, a.port));
        assert_eq!(host("localhost"), Some(("localhost".into(), None)));
        assert_eq!(
            host("LOCALHOST:8080"),
            Some(("localhost".into(), Some(8080)))
        );
        assert_eq!(
            host("127.0.0.1:8080"),
            Some(("127.0.0.1".into(), Some(8080)))
        );
        assert_eq!(host("[::1]:8080"), Some(("::1".into(), Some(8080))));
        for rejected in [
            "evil.example",
            "evil.example:8080",
            "localhost:8081",
            "localhost:",
            "0.0.0.0:8080",
            "127.0.0.1@evil.example",
        ] {
            assert!(control_authority(rejected, 8080).is_none(), "{rejected}");
        }

        let same = |host: &str, origin: &str| {
            same_loopback_origin(origin, &control_authority(host, 8553).unwrap())
        };
        assert!(same("localhost:8553", "http://localhost:8553"));
        assert!(same("127.0.0.1:8553", "http://127.0.0.1:8553"));
        assert!(same("[::1]:8553", "http://[::1]:8553"));
        assert!(same("localhost", "http://localhost"));
        assert!(same("localhost", "http://localhost:80"));
        for (host, origin) in [
            ("localhost:8553", "http://localhost"),
            ("127.0.0.1:8553", "http://127.0.0.1"),
            ("127.0.0.1:8553", "http://127.0.0.1:9000"),
            ("127.0.0.1:8553", "https://127.0.0.1:8553"),
            ("127.0.0.1:8553", "http://localhost:8553"),
            ("127.0.0.1:8553", "http://127.0.0.1:8553/"),
            ("localhost:8553", "https://evil.example"),
            ("localhost:8553", "null"),
        ] {
            assert!(!same(host, origin), "{host} {origin}");
        }

        let rebinding = raw_control_request(b"GET /v1/auth HTTP/1.1\r\nHost: evil.example\r\n\r\n");
        assert!(rebinding.starts_with("HTTP/1.1 421 Misdirected Request"));
        let duplicate = raw_control_request(
            b"GET /v1/auth HTTP/1.1\r\nHost: localhost\r\nHost: localhost\r\n\r\n",
        );
        assert!(duplicate.starts_with("HTTP/1.1 400 Bad Request"));
        let cross_origin = raw_control_request(
            b"GET /v1/auth HTTP/1.1\r\nHost: localhost\r\nOrigin: https://evil.example\r\n\r\n",
        );
        assert!(cross_origin.starts_with("HTTP/1.1 403 Forbidden"));
    }

    #[test]
    /**
     * @brief CA가 도메인을 Host로 담아 와도 http-01 응답을 받는지.
     * @details 이 경로가 Host 검사에 걸리면 앞단 프록시로 넘겨도 발급이 늘 실패한다. 다른
     *          경로는 같은 Host로 여전히 막혀야 한다.
     */
    fn acme_challenge_answers_any_host_but_other_paths_do_not() {
        set_acme_http01("hosttoken", "hosttoken.thumb");
        let answer = raw_control_request(
            b"GET /.well-known/acme-challenge/hosttoken HTTP/1.1\r\nHost: a1.example\r\n\r\n",
        );
        clear_acme_http01("hosttoken");
        assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer}");
        assert!(answer.ends_with("hosttoken.thumb"), "{answer}");
        let other = raw_control_request(b"GET /v1/auth HTTP/1.1\r\nHost: a1.example\r\n\r\n");
        assert!(
            other.starts_with("HTTP/1.1 421 Misdirected Request"),
            "{other}"
        );
    }

    #[test]
    /**
     * @brief 인증 앞에서 끊는 거절이 기록에 남는지.
     * @details 이 거절들은 감사 기록 경로보다 앞에 있어, 세지 않으면 공격 시도가 로그에도
     *          대시보드에도 남지 않는다. 방어가 조용히 동작하는 것이 문제였다.
     */
    fn pre_auth_rejections_are_recorded() {
        let before_host = control_error_count("host_not_loopback");
        let before_origin = control_error_count("cross_origin");
        let before_body = control_error_count("body_too_large");
        let before_type = control_error_count("content_type");

        let _ = raw_control_request(b"GET /v1/auth HTTP/1.1\r\nHost: evil.example\r\n\r\n");
        let _ = raw_control_request(
            b"GET /v1/auth HTTP/1.1\r\nHost: localhost\r\nOrigin: https://evil.example\r\n\r\n",
        );
        let oversized = format!(
            "POST /v1/config/validate HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            MAX_REQUEST_BODY + 1
        );
        let _ = raw_control_request(oversized.as_bytes());
        let _ = raw_control_request(
            b"POST /v1/config/validate HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
        );

        assert!(
            control_error_count("host_not_loopback") > before_host,
            "리바인딩 거절이 기록되지 않았습니다"
        );
        assert!(
            control_error_count("cross_origin") > before_origin,
            "교차 출처 거절이 기록되지 않았습니다"
        );
        assert!(
            control_error_count("body_too_large") > before_body,
            "본문 크기 초과 거절이 기록되지 않았습니다"
        );
        assert!(
            control_error_count("content_type") > before_type,
            "Content-Type 거절이 기록되지 않았습니다"
        );
    }

    #[test]
    /** @brief 웹소켓 핸드셰이크 응답이 규격 예제와 맞는지. */
    fn websocket_accept_matches_rfc_example() {
        let mut hasher = Sha1::new();
        hasher.update(b"dGhlIHNhbXBsZSBub25jZQ==");
        hasher.update(WEBSOCKET_GUID);
        assert_eq!(
            base64_standard(&hasher.finalize()),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    /** @brief 하위 프로토콜에 담긴 토큰을 제대로 푸는지. */
    fn websocket_bearer_protocol_decodes_base64url() {
        assert_eq!(
            String::from_utf8(base64_url_decode("dG9rZW4tMTIz").unwrap()).unwrap(),
            "token-123"
        );
    }

    #[test]
    /** @brief 여러 번 온 쿠키가 하나로 합쳐지는지. */
    fn repeated_cookie_headers_are_combined() {
        let mut cookie = String::new();
        append_cookie_header(&mut cookie, "theme=dark");
        append_cookie_header(&mut cookie, "onetdns_session=token-a; lang=ko");

        assert_eq!(cookie, "theme=dark; onetdns_session=token-a; lang=ko");
        assert_eq!(
            cookie_values(&cookie, "onetdns_session"),
            vec!["token-a".to_string()]
        );
    }

    #[test]
    /** @brief 같은 이름의 쿠키가 여럿이어도 값이 각각 보존되는지. */
    fn same_name_session_cookies_keep_distinct_values_without_duplicates() {
        let cookie = "onetdns_session=stale; onetdns_session=active; onetdns_session=active";
        assert_eq!(
            cookie_values(cookie, "onetdns_session"),
            vec!["stale".to_string(), "active".to_string()]
        );
    }

    #[test]
    /** @brief 유효한 쿠키가 오래된 것보다 우선하는지. 첫 번째만 보면 로그인이 풀린 것처럼 보인다. */
    fn valid_session_cookie_is_preferred_over_stale_duplicate() {
        let auth = Auth::new(vec![], vec![]).with_users(vec![UserCred {
            name: "alice".to_string(),
            hash: hash_eventually("s3cret-passphrase").into(),
            role: Role::Admin,
        }]);
        let LoginResult::Success(active, _, _) =
            login_eventually(&auth, "alice", "s3cret-passphrase")
        else {
            panic!("login");
        };
        let candidates = vec!["stale".to_string(), active.clone()];

        assert_eq!(select_session_cookie(&candidates, &auth), active);
    }

    /** @brief 포화로 실패하면 잠시 뒤 다시 시도해 실제 판정을 얻는다. */
    /** @brief 127.0.0.1을 프록시로 믿고 https://admin.example.com을 내보이는 정책. */
    fn proxied_policy() -> ProxyPolicy {
        ProxyPolicy {
            trusted: vec!["127.0.0.1/32".parse().unwrap()],
            origins: vec![HttpsOrigin::parse("https://admin.example.com").unwrap()],
        }
    }

    /** @brief 요청 하나를 실제 연결로 보내고 응답 전체를 받는다. 연결은 127.0.0.1에서 온다. */
    fn exchange(st: &AppState, request: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = accept_before_deadline(&listener).expect("accept request");
                handle_conn(stream, st).unwrap();
            });
            let mut client = TcpStream::connect(addr).unwrap();
            client.write_all(request.as_bytes()).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            let mut response = String::new();
            std::io::Read::read_to_string(&mut client, &mut response).unwrap();
            response
        })
    }

    #[test]
    /**
     * @brief 공개 출처 Host는 신뢰하는 프록시에서 온 연결에만 열리는지.
     * @details 프록시가 아닌 연결에 열면 같은 컴퓨터의 다른 프로그램이 X-Forwarded-For를 꾸며
     *          로그인 제한을 피한다. Origin은 그 공개 출처와 정확히 같아야 한다.
     */
    fn a_public_origin_is_accepted_only_through_a_trusted_proxy() {
        let policy = proxied_policy();
        let proxy: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let other: SocketAddr = "127.0.0.2:40000".parse().unwrap();
        let host = "admin.example.com";
        let origin = Some("https://admin.example.com");

        let caller = control_caller(&policy, Some(proxy), 8553, host, origin, "198.51.100.7")
            .expect("프록시를 거친 공개 출처가 거절됨");
        assert!(caller.proxied.is_some());
        assert_eq!(caller.login_source(), "198.51.100.7");
        assert_eq!(caller.login_proxy().as_deref(), Some("127.0.0.1"));
        assert_eq!(caller.session_cookie(), SECURE_SESSION_COOKIE);

        assert_eq!(
            control_caller(&policy, Some(other), 8553, host, origin, "").err(),
            Some(HostRejection::Misdirected),
            "신뢰하지 않는 연결이 공개 출처로 들어옴"
        );
        assert_eq!(
            control_caller(&ProxyPolicy::default(), Some(proxy), 8553, host, origin, "").err(),
            Some(HostRejection::Misdirected),
            "설정이 없는데 공개 출처가 열림"
        );
        assert_eq!(
            control_caller(
                &policy,
                Some(proxy),
                8553,
                host,
                Some("https://evil.example"),
                ""
            )
            .err(),
            Some(HostRejection::CrossOrigin)
        );
        assert_eq!(
            control_caller(
                &policy,
                Some(proxy),
                8553,
                host,
                Some("http://admin.example.com"),
                ""
            )
            .err(),
            Some(HostRejection::CrossOrigin),
            "HTTPS가 아닌 출처를 받음"
        );

        let local = control_caller(
            &policy,
            Some(proxy),
            8553,
            "127.0.0.1:8553",
            None,
            "1.2.3.4",
        )
        .expect("루프백 Host가 거절됨");
        assert!(
            local.proxied.is_none(),
            "루프백 Host 요청에서 X-Forwarded-For를 읽음"
        );
        assert_eq!(local.session_cookie(), SESSION_COOKIE);
    }

    #[test]
    /**
     * @brief X-Forwarded-For에서 프록시가 붙인 오른쪽 주소를 고르는지.
     * @details 왼쪽 항목은 클라이언트가 마음대로 적어 보낼 수 있다.
     */
    fn the_forwarded_client_is_the_rightmost_untrusted_address() {
        let policy = proxied_policy();
        let client = |value: &str| policy.forwarded_client(value);
        assert_eq!(
            client("203.0.113.1, 198.51.100.7"),
            Some("198.51.100.7".parse().unwrap())
        );
        assert_eq!(
            client("198.51.100.7, 127.0.0.1"),
            Some("198.51.100.7".parse().unwrap())
        );
        assert_eq!(client("127.0.0.1"), None);
        assert_eq!(client(""), None);
        assert_eq!(client("203.0.113.1, garbage"), None);
    }

    #[test]
    /**
     * @brief 프록시를 거친 로그인이 Secure가 붙은 __Host- 쿠키를 받고, 그 쿠키로 인증되는지.
     * @details Secure가 빠지면 HTTPS로 받은 세션 쿠키가 평문 요청에도 실려 나간다.
     */
    fn a_proxied_sign_in_gets_a_secure_host_cookie() {
        let mut st = test_state("adm", "ro");
        st.auth = Arc::new(Auth::new(vec![], vec![]).with_users(vec![UserCred {
            name: "alice".into(),
            hash: hash_eventually("s3cret-passphrase").into(),
            role: Role::Admin,
        }]));
        st.proxy = Arc::new(ArcSwap::from_pointee(proxied_policy()));
        let body = "{\"user\":\"alice\",\"password\":\"s3cret-passphrase\"}";
        let login = format!(
            "POST /v1/login HTTP/1.1\r\nHost: admin.example.com\r\nOrigin: https://admin.example.com\r\n\
             X-Forwarded-For: 198.51.100.7\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = loop {
            let response = exchange(&st, &login);
            if !response.starts_with("HTTP/1.1 503") {
                break response;
            }
        };
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let cookie = response
            .lines()
            .find_map(|line| line.strip_prefix("Set-Cookie: "))
            .expect("세션 쿠키가 없음");
        assert!(
            cookie.starts_with("__Host-onetdns_session=") && cookie.contains("Secure;"),
            "{cookie}"
        );
        let token = cookie
            .trim_start_matches("__Host-onetdns_session=")
            .split(';')
            .next()
            .unwrap();

        let auth_request = |cookie_name: &str| {
            format!(
                "GET /v1/auth HTTP/1.1\r\nHost: admin.example.com\r\nCookie: {cookie_name}={token}\r\n\r\n"
            )
        };
        assert!(exchange(&st, &auth_request("__Host-onetdns_session"))
            .contains("\"authenticated\":true"));
        assert!(
            exchange(&st, &auth_request("onetdns_session")).contains("\"authenticated\":false"),
            "HTTPS 출처에서 Secure가 아닌 쿠키 이름을 받음"
        );
    }

    #[test]
    /** @brief 첫 계정 만들기는 프록시를 거친 요청에 열리지 않는지. 인터넷의 누구든 관리자가 된다. */
    fn first_account_setup_is_closed_through_the_proxy() {
        let mut st = state_without_accounts(Box::new(|_, _| Ok("{}".to_string())));
        st.proxy = Arc::new(ArcSwap::from_pointee(proxied_policy()));
        let body = "{\"user\":\"owner\",\"password\":\"correct-horse-battery\"}";
        let response = exchange(
            &st,
            &format!(
                "POST /v1/setup HTTP/1.1\r\nHost: admin.example.com\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(!st.auth.has_users());
    }

    #[test]
    /** @brief 프록시별 속도 제한 표가 풀린 항목을 지우고 항목 수 상한을 지키는지. */
    fn proxy_login_pacing_keeps_a_bounded_table() {
        let mut pace: std::collections::HashMap<String, u64> = (0..MAX_LOGIN_ATTEMPT_KEYS)
            .map(|i| (format!("127.0.{}.{}", i / 256, i % 256), 2_000 + i as u64))
            .collect();
        Auth::pace_proxy_failure(&mut pace, "127.1.0.1", 1_000);
        assert_eq!(pace.len(), MAX_LOGIN_ATTEMPT_KEYS);
        assert!(
            !pace.contains_key("127.0.0.0"),
            "the soonest entry is evicted"
        );
        assert!(pace.contains_key("127.0.0.1"));

        Auth::pace_proxy_failure(&mut pace, "127.1.0.1", 1_000_000);
        assert_eq!(pace.len(), 1, "expired entries are dropped");
        assert_eq!(
            pace["127.1.0.1"],
            1_000_000 + PROXY_LOGIN_FAILURE_INTERVAL_MS
        );
    }

    #[test]
    /**
     * @brief 프록시 뒤의 로그인 실패를 실제 클라이언트마다 세고, 프록시 전체는 막지 않고 늦추는지.
     * @details 프록시 주소로 막으면 공격자 하나가 모든 관리자를 막는다. 클라이언트 주소로만
     *          세면 X-Forwarded-For를 꾸며 무한히 시도할 수 있다.
     */
    fn proxied_sign_in_failures_are_counted_per_client_and_paced_per_proxy() {
        let auth = Auth::default();
        let proxy = Some("127.0.0.1");
        for i in 0..MAX_SOURCE_LOGIN_FAILURES {
            auth.record_login_result("198.51.100.7", proxy, &format!("ghost{i}"), false);
        }
        assert!(!auth.login_allowed("198.51.100.7", proxy, "alice"));
        assert!(
            auth.login_allowed("203.0.113.9", proxy, "alice"),
            "클라이언트 하나가 한도를 다 쓰자 다른 클라이언트까지 늦춰짐"
        );

        for i in u64::from(MAX_SOURCE_LOGIN_FAILURES)..PROXY_LOGIN_FAILURE_BURST {
            auth.record_login_result(&format!("client{i}"), proxy, "alice", false);
        }
        assert_eq!(
            auth.login_retry_after("203.0.113.9", proxy, "alice"),
            Some(1),
            "출발지를 바꿔 가며 프록시 한도를 넘겼는데 늦추지 않거나, 1초보다 오래 막음"
        );
        assert!(
            auth.login_allowed("local", None, "alice"),
            "프록시를 거치지 않은 로그인까지 늦춰짐"
        );
        std::thread::sleep(Duration::from_millis(1100));
        assert!(
            auth.login_allowed("203.0.113.9", proxy, "alice"),
            "간격이 지나도 프록시를 거친 로그인을 받지 않음"
        );
    }

    #[test]
    /**
     * @brief 루프백으로 직접 들어온 요청의 로그인 실패를 주소와 상관없이 하나로 세는지.
     * @details Linux에서는 127.0.0.0/8의 아무 주소에서나 접속할 수 있다. 주소로 나누면 주소를
     *          바꿔 가며 제한을 피한다.
     */
    fn direct_sign_in_failures_share_one_local_bucket() {
        let first = Caller::direct(Some("127.0.0.2:40000".parse().unwrap()));
        let second = Caller::direct(Some("127.0.0.3:40001".parse().unwrap()));
        assert_eq!(first.login_source(), second.login_source());
        assert_eq!(first.login_proxy(), None);
    }

    #[test]
    /**
     * @brief 틀린 베어러 토큰을 보낸 요청이 세션 쿠키로 넘어가 인증되지 않는지.
     * @details CSRF 검사는 베어러가 있으면 건너뛴다. 틀린 베어러 뒤에서 세션으로 넘어가면
     *          CSRF 헤더 없는 쿠키 요청이 세션 권한으로 실행된다.
     */
    fn a_wrong_bearer_is_not_replaced_by_the_session_cookie() {
        let mut st = test_state("adm", "ro");
        st.auth = Arc::new(Auth::new(vec![], vec![]).with_users(vec![UserCred {
            name: "alice".into(),
            hash: hash_eventually("s3cret-passphrase").into(),
            role: Role::Admin,
        }]));
        let LoginResult::Success(session, _, _) =
            login_eventually(st.auth.as_ref(), "alice", "s3cret-passphrase")
        else {
            panic!("login ok");
        };
        assert_eq!(
            st.auth.resolve("garbage", &session),
            None,
            "틀린 베어러 뒤에서 세션으로 인증됨"
        );
        assert_eq!(st.auth.resolve("", &session), Some(Role::Admin));
        let (with_wrong_bearer, _, _) = route(
            "POST",
            "/v1/cache/flush",
            "Bearer garbage",
            &session,
            "",
            &Caller::direct(None),
            &st,
        );
        assert_eq!(status_code(with_wrong_bearer), 401);

        let request = format!(
            "POST /v1/cache/flush HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer garbage\r\n\
             Cookie: onetdns_session={session}\r\nContent-Length: 0\r\n\r\n"
        );
        let response = exchange(&st, &request);
        assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    }

    #[test]
    /**
     * @brief 첫 계정 만들기가 일회용 설정 코드를 요구하고, 만든 뒤에는 코드를 지우는지.
     * @details 루프백에 접속할 수 있다는 것만으로는 설정 파일을 고칠 권한이 있다고 볼 수 없다.
     *          같은 컴퓨터의 다른 사용자가 먼저 관리자가 될 수 있다.
     */
    fn first_account_setup_requires_the_one_time_code() {
        let created = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let seen = created.clone();
        let st = state_without_accounts(Box::new(move |_, _| {
            *seen.lock_recover() += 1;
            Ok("{}".to_string())
        }));
        let body = |code: &str| {
            format!(
                "{{\"user\":\"owner\",\"password\":\"correct-horse-battery\",\"code\":\"{code}\"}}"
            )
        };
        for wrong in ["", "wrong-code"] {
            let response = setup_request(&st, &body(wrong));
            assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        }
        assert_eq!(*created.lock_recover(), 0, "틀린 코드로 계정을 만듦");

        let status = exchange(&st, "GET /v1/auth HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(
            status.contains(&format!(
                "\"setup_code_file\":{}",
                json::escape(TEST_SETUP_FILE)
            )),
            "설정 화면에 코드 파일 경로를 알려 주지 않음: {status}"
        );

        // 다른 테스트가 비밀번호를 해시하는 중이면 503이 온다. 코드는 그때 쓰이지 않는다.
        let response = loop {
            let response = setup_request(&st, &body(TEST_SETUP_CODE));
            if !response.starts_with("HTTP/1.1 503") {
                break response;
            }
        };
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert_eq!(*created.lock_recover(), 1);
        assert!(
            st.auth.setup_code_file().is_none(),
            "계정을 만든 뒤에도 설정 코드가 남음"
        );

        let without_code = state_without_accounts(Box::new(|_, _| panic!("코드 없이 계정을 만듦")));
        without_code.auth.clear_setup_code();
        let response = setup_request(&without_code, &body(TEST_SETUP_CODE));
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    }

    #[test]
    /**
     * @brief 웹소켓 읽기 가드를 놓으면 읽기 스레드가 끝나고 소켓이 닫히는지.
     * @details 명령 채널을 가득 채운 뒤 Close 프레임을 보내 읽기 스레드를 블로킹 send에
     *          묶어 둔다. 가드가 수신 쪽을 join보다 먼저 놓지 않으면 drop이 끝나지 않는다.
     */
    fn dropping_the_dashboard_reader_joins_a_blocked_reader() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let mut client =
            TcpStream::connect(listener.local_addr().unwrap()).expect("connect test client");
        let (server, _) = listener.accept().expect("accept test connection");
        let reader = DashboardReader::spawn(&SharedTcp::new(server)).expect("spawn reader");

        let mut frames = Vec::new();
        for _ in 0..80 {
            frames.extend_from_slice(&[0x89, 0x80, 1, 2, 3, 4]);
        }
        frames.extend_from_slice(&[0x88, 0x80, 1, 2, 3, 4]);
        std::io::Write::write_all(&mut client, &frames).expect("write frames");
        std::thread::sleep(Duration::from_millis(200));

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            drop(reader);
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("dropping the reader joins its thread");

        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut rest = Vec::new();
        assert_eq!(
            std::io::Read::read_to_end(&mut client, &mut rest).expect("socket is shut down"),
            0
        );
    }

    #[test]
    /** @brief Sec-WebSocket-Key가 16바이트의 표준 base64가 아니면 거부하는지. */
    fn websocket_keys_must_encode_sixteen_bytes() {
        assert!(websocket_key_valid("dGhlIHNhbXBsZSBub25jZQ=="));
        for key in [
            "",
            "x",
            "dGhlIHNhbXBsZSBub25jZQ",
            "dGhlIHNhbXBsZSBub25jZR==",
            "dGhlIHNhbXBsZSBub25jZQ=x",
            "dGhlIHNhbXBsZSBub25j-Q==",
            "dGhlIHNhbXBsZSBub25jZSBh",
        ] {
            assert!(!websocket_key_valid(key), "{key}");
        }
    }

    fn login_eventually(auth: &Auth, name: &str, password: &str) -> LoginResult {
        loop {
            match auth.login(name, password) {
                LoginResult::Busy => std::thread::yield_now(),
                result => return result,
            }
        }
    }

    /** @brief 포화로 실패하면 잠시 뒤 다시 시도해 해시를 얻는다. */
    fn hash_eventually(password: &str) -> String {
        loop {
            match crate::password::hash_password(password) {
                Err(crate::password::PasswordError::Busy) => std::thread::yield_now(),
                result => return result.expect("A test password satisfies the length rule"),
            }
        }
    }
}
