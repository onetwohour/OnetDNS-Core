/*!
 * @brief 질의 처리 워커 풀.
 *
 * @details 느린 질의 하나가 뒤의 빠른 질의를 막지 않게 한다. 받는 쪽은 큐에 넣기만 하고,
 *          워커들이 꺼내 처리한 뒤 완료를 알린다.
 * @warning 작업 중 패닉해도 그 질의만 실패해야 한다. 잡아서 최소한의 실패 응답으로 바꾸고
 *          워커는 다음 일을 이어 간다.
 */

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

use onetdns_proto::{Message, ResponseCode};
use onetdns_runtime::{Handler, RequestCtx, Transport as RtTransport};

use crate::native::NativeServer;

/** @brief 연결 하나가 동시에 맡길 수 있는 질의 수. */
pub const MAX_INFLIGHT_PER_CONN: usize = 256;

#[derive(Debug)]
/** @brief 처리할 질의 하나. */
pub struct QueryJob {
    /** @brief 이 질의가 온 연결. */
    pub conn_key: Vec<u8>,
    /** @brief 그 연결의 세대 번호. 끝난 연결의 늦은 응답을 구분한다. */
    pub epoch: u64,
    /** @brief 그 연결 안의 스트림. */
    pub stream_id: u64,
    /** @brief 받은 그대로의 질의 바이트. */
    pub query: Vec<u8>,
    /** @brief 질의를 보낸 곳. */
    pub peer: SocketAddr,
    /** @brief 어느 전송으로 왔는지. */
    pub transport: RtTransport,
    /** @brief 경로나 인증서에서 알아낸 클라이언트 식별자. */
    pub client_id: Option<String>,
    /** @brief 인증된 연결로 왔는지. */
    pub authenticated: bool,
    /** @brief 인증서에 적힌 신원. */
    pub auth_identity: Option<String>,
}

#[derive(Debug)]
/** @brief 처리가 끝난 질의와 그 응답. */
pub struct QueryDone {
    /** @brief 이 응답이 갈 연결. */
    pub conn_key: Vec<u8>,
    /** @brief 그 연결의 세대 번호. */
    pub epoch: u64,
    /** @brief 그 연결 안의 스트림. */
    pub stream_id: u64,
    /** @brief 내보낼 응답 바이트. 없으면 답하지 못했다. */
    pub wire: Option<Vec<u8>>,
    /** @brief HTTP 캐시가 신선하다고 볼 시간. DoH3만 쓰고 DoQ는 무시한다. */
    pub max_age: u32,
}

/**
 * @brief 워커가 만들어 낸 응답 바이트와 그 수명.
 * @details 수명은 HTTP 전송만 쓴다. 응답을 만든 곳에만 Message가 있어서 여기서 담아 전달한다.
 */
pub struct ResolvedAnswer {
    /** @brief 내보낼 응답 바이트. */
    pub wire: Vec<u8>,
    /** @brief HTTP 캐시가 신선하다고 볼 시간. */
    pub max_age: u32,
}

/** @brief 질의를 실제로 푸는 함수. */
pub type ResolveFn = Arc<dyn Fn(&QueryJob) -> Option<ResolvedAnswer> + Send + Sync>;
/** @brief 완료를 알리는 함수. */
pub type DoneNotify = Arc<dyn Fn() + Send + Sync>;

/** @brief 리스너를 깨우는 데 쓰는 바이트. */
const COMPLETION_WAKE: &[u8] = b"\0";

/**
 * @brief 완료를 알려 UDP 리스너를 깨우는 방법을 만든다.
 * @details 리스너는 소켓에서 자고 있다. 완료됐다고 알리려면 그 소켓에 무언가 보내야 한다.
 */
pub fn udp_completion_notifier(bound: SocketAddr) -> io::Result<(DoneNotify, SocketAddr)> {
    let bind_ip = match bound.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => Ipv4Addr::LOCALHOST.into(),
        IpAddr::V6(ip) if ip.is_unspecified() => Ipv6Addr::LOCALHOST.into(),
        ip => ip,
    };
    let bind = SocketAddr::new(bind_ip, 0);
    let target = match bound {
        SocketAddr::V4(addr) if addr.ip().is_unspecified() => {
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), addr.port())
        }
        SocketAddr::V6(addr) if addr.ip().is_unspecified() => {
            SocketAddr::new(Ipv6Addr::LOCALHOST.into(), addr.port())
        }
        addr => addr,
    };
    let socket = UdpSocket::bind(bind)?;
    socket.set_nonblocking(true)?;
    let source = socket.local_addr()?;
    let failures = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let notify: DoneNotify = Arc::new(move || {
        if let Err(e) = socket.send_to(COMPLETION_WAKE, target) {
            let count = failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if count.is_power_of_two() {
                onetdns_core::warn!(event = "worker.wake_failed", target = %target, count = count, error = %e, "Could not send the completion notice; the finished response waits until the next packet arrives");
            }
        }
    });
    Ok((notify, source))
}

/**
 * @brief 받은 패킷이 이 서버가 보낸 깨움 신호인지.
 * @warning 출발지가 자기 자신이고 내용도 맞아야 한다. 확인하지 않으면 밖에서 보낸
 *          패킷이 깨움으로 오인된다.
 */
pub fn is_completion_wake(source: SocketAddr, expected: SocketAddr, packet: &[u8]) -> bool {
    source == expected && packet == COMPLETION_WAKE
}

/** @brief 대기 중인 일과 끝난 일. */
struct Queue {
    /** @brief 아직 맡지 않은 일들. */
    jobs: VecDeque<QueryJob>,
    /** @brief 더 받지 않는다는 표시. */
    closed: bool,
}

/** @brief 워커들이 나눠 쓰는 상태. */
struct Shared {
    /** @brief 일 대기열. */
    queue: Mutex<Queue>,
    /** @brief 일이 들어왔음을 알리는 곳. */
    not_empty: Condvar,
    /** @brief 대기열 크기 상한. */
    capacity: usize,
    /** @brief 끝난 일들. */
    done: Mutex<VecDeque<QueryDone>>,
    /** @brief 끝났음을 리스너에 알리는 방법. */
    done_notify: Option<DoneNotify>,
}

/** @brief 워커 풀. */
pub struct WorkerPool {
    /** @brief 워커들이 나눠 쓰는 상태. */
    shared: Arc<Shared>,
    /** @brief 실행 중인 워커들. */
    workers: Vec<JoinHandle<()>>,
}

impl WorkerPool {
    /** @brief 워커들을 시작한다. */
    pub fn new(
        resolve: ResolveFn,
        workers: usize,
        capacity: usize,
        done_notify: Option<DoneNotify>,
    ) -> io::Result<Self> {
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue {
                jobs: VecDeque::new(),
                closed: false,
            }),
            not_empty: Condvar::new(),
            capacity: capacity.max(1),
            done: Mutex::new(VecDeque::new()),
            done_notify,
        });
        let mut handles: Vec<JoinHandle<()>> = Vec::new();
        for i in 0..workers.max(1) {
            let worker_shared = shared.clone();
            let worker_resolve = resolve.clone();
            let handle = match std::thread::Builder::new()
                .name(format!("qworker-{i}"))
                .spawn(move || worker_loop(&worker_shared, &worker_resolve))
            {
                Ok(handle) => handle,
                Err(error) => {
                    let mut queue = shared.queue.lock().unwrap_or_else(|e| e.into_inner());
                    queue.closed = true;
                    drop(queue);
                    shared.not_empty.notify_all();
                    for handle in handles {
                        let _ = handle.join();
                    }
                    return Err(error);
                }
            };
            handles.push(handle);
        }
        Ok(WorkerPool {
            shared,
            workers: handles,
        })
    }

    /** @brief 일을 맡긴다. 큐가 꽉 찼으면 되돌려준다. */
    pub fn submit(&self, job: QueryJob) -> Result<(), Box<QueryJob>> {
        let mut q = self.shared.queue.lock().unwrap_or_else(|e| e.into_inner());
        if q.closed || q.jobs.len() >= self.shared.capacity {
            return Err(Box::new(job));
        }
        q.jobs.push_back(job);
        drop(q);
        self.shared.not_empty.notify_one();
        Ok(())
    }

    /** @brief 끝난 일들을 가져간다. */
    pub fn drain_done(&self, out: &mut Vec<QueryDone>) {
        let mut done = self.shared.done.lock().unwrap_or_else(|e| e.into_inner());
        out.extend(done.drain(..));
    }

    /** @brief 워커들에게 멈추라고 알린다. */
    fn stop(&mut self) {
        {
            let mut q = self.shared.queue.lock().unwrap_or_else(|e| e.into_inner());
            q.closed = true;
            q.jobs.clear();
        }
        self.shared.not_empty.notify_all();
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }

    /** @brief 워커들을 멈추고 기다린다. */
    pub fn shutdown(mut self) {
        self.stop();
    }
}

impl Drop for WorkerPool {
    /** @brief 워커들을 정리한다. */
    fn drop(&mut self) {
        self.stop();
    }
}

/**
 * @brief 워커 하나의 반복.
 * @warning 처리 중 패닉을 잡는다. 잡지 않으면 질의 하나 때문에 워커가 죽고, 그만큼
 *          처리 능력이 줄어든다.
 */
fn worker_loop(shared: &Arc<Shared>, resolve: &ResolveFn) {
    loop {
        let job = {
            let mut q = shared.queue.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if let Some(job) = q.jobs.pop_front() {
                    break job;
                }
                if q.closed {
                    return;
                }
                q = shared.not_empty.wait(q).unwrap_or_else(|e| e.into_inner());
            }
        };
        let answer = match onetdns_core::isolation::catch_request(|| resolve(&job)) {
            Ok(answer) => answer,
            Err(_) => {
                servfail_wire_from_raw(&job.query).map(|wire| ResolvedAnswer { wire, max_age: 0 })
            }
        };
        let (wire, max_age) = match answer {
            Some(answer) => (Some(answer.wire), answer.max_age),
            None => (None, 0),
        };
        let should_notify = {
            let mut done = shared.done.lock().unwrap_or_else(|e| e.into_inner());
            let was_empty = done.is_empty();
            done.push_back(QueryDone {
                conn_key: job.conn_key,
                epoch: job.epoch,
                stream_id: job.stream_id,
                wire,
                max_age,
            });
            was_empty
        };
        if should_notify {
            if let Some(notify) = &shared.done_notify {
                notify();
            }
        }
    }
}

/** @brief 질의 핸들러를 푸는 함수로 감싼다. */
pub fn handler_resolver(handler: Arc<NativeServer>) -> ResolveFn {
    Arc::new(move |job: &QueryJob| {
        let req = Message::parse(&job.query).ok()?;
        if req.header.response {
            return None;
        }
        let ctx = RequestCtx {
            src: job.peer,
            transport: job.transport,
            raw: Some(job.query.as_slice()),
            client_id: job.client_id.clone(),
            authenticated: job.authenticated,
            auth_identity: job.auth_identity.clone(),
        };
        let response = handler.handle(&req, &ctx)?;
        let max_age = crate::doh::http_freshness_secs(&response);
        Some(ResolvedAnswer {
            wire: response.try_encode().ok()?,
            max_age,
        })
    })
}

/** @brief 이 질의에 대한 실패 응답 바이트. */
pub fn servfail_wire(req: &Message) -> Vec<u8> {
    let mut m = Message::default();
    m.header.id = req.header.id;
    m.header.response = true;
    m.header.opcode = req.header.opcode;
    m.header.recursion_desired = req.header.recursion_desired;
    m.header.recursion_available = true;
    m.header.rcode = ResponseCode::ServFail.0;
    m.questions = req.questions.clone();
    m.try_encode()
        .expect("A minimal SERVFAIL built from a parsed request can always be encoded")
}

/**
 * @brief 파싱하지 않고 실패 응답을 만든다.
 * @details 패닉이 파싱에서 났을 수 있다. 다시 파싱하면 같은 위치에서 또 패닉한다.
 *          그래서 헤더만 손봐서 최소한의 응답을 낸다.
 */
fn servfail_wire_from_raw(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 || query[2] & 0x80 != 0 {
        return None;
    }
    let request_flags = u16::from_be_bytes([query[2], query[3]]);
    let response_flags =
        0x8000 | (request_flags & (0x7800 | 0x0100 | 0x0010)) | 0x0080 | ResponseCode::ServFail.0;
    let mut wire = vec![0u8; 12];
    wire[..2].copy_from_slice(&query[..2]);
    wire[2..4].copy_from_slice(&response_flags.to_be_bytes());
    Some(wire)
}

/** @brief 기본 워커 수. */
pub fn default_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(2, 16)
}

#[cfg(test)]
/** @brief 느린 일이 빠른 일을 막지 않는지, 그리고 패닉이 그 질의에만 머무는지. */
mod tests {
    use super::*;

    /** @brief 테스트용 질의 하나. */
    fn job(id: u8) -> QueryJob {
        QueryJob {
            conn_key: vec![id],
            epoch: 1,
            stream_id: id as u64,
            query: vec![id, id, id],
            peer: "127.0.0.1:0".parse().unwrap(),
            transport: RtTransport::DoQ,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        }
    }

    /** @brief 끝난 일이 이만큼 모일 때까지 가져간다. */
    fn collect_done(pool: &WorkerPool, expected: usize) -> Vec<QueryDone> {
        let mut out = Vec::new();
        for _ in 0..500 {
            pool.drain_done(&mut out);
            if out.len() >= expected {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        out
    }

    #[test]
    /** @brief 맡긴 일이 처리되고 완료가 돌아오는지. */
    fn pool_resolves_and_returns_completions() {
        let resolve: ResolveFn = Arc::new(|j: &QueryJob| {
            Some(ResolvedAnswer {
                wire: j.query.clone(),
                max_age: 0,
            })
        });
        let pool = WorkerPool::new(resolve, 3, 16, None).unwrap();
        for i in 0..8 {
            pool.submit(job(i)).expect("submit");
        }
        let done = collect_done(&pool, 8);
        assert_eq!(done.len(), 8);
        for d in &done {
            assert_eq!(d.wire.as_deref(), Some([d.conn_key[0]; 3].as_slice()));
        }
        pool.shutdown();
    }

    #[test]
    /** @brief 느린 일 하나가 뒤를 막지 않는지. */
    fn slow_job_does_not_stall_fast_jobs() {
        let resolve: ResolveFn = Arc::new(|j: &QueryJob| {
            if j.conn_key == [0xFF] {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Some(ResolvedAnswer {
                wire: j.query.clone(),
                max_age: 0,
            })
        });
        let pool = WorkerPool::new(resolve, 2, 32, None).unwrap();
        pool.submit(QueryJob {
            conn_key: vec![0xFF],
            ..job(1)
        })
        .expect("submit slow");
        for i in 2..6 {
            pool.submit(job(i)).expect("submit fast");
        }
        let start = std::time::Instant::now();
        let mut fast = 0;
        while fast < 4 && start.elapsed() < std::time::Duration::from_millis(150) {
            let mut out = Vec::new();
            pool.drain_done(&mut out);
            for d in out {
                if d.conn_key != [0xFF] {
                    fast += 1;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert_eq!(
            fast, 4,
            "빠른 job은 느린 job(200ms)에 막히지 않고 150ms 내 완료되어야"
        );
        pool.shutdown();
    }

    #[test]
    /** @brief 큐가 꽉 차면 되돌려주는지. */
    fn pool_rejects_when_full() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let g = gate.clone();
        let resolve: ResolveFn = Arc::new(move |j: &QueryJob| {
            let (lock, cv) = &*g;
            let mut open = lock.lock().unwrap_or_else(|e| e.into_inner());
            while !*open {
                open = cv.wait(open).unwrap_or_else(|e| e.into_inner());
            }
            Some(ResolvedAnswer {
                wire: j.query.clone(),
                max_age: 0,
            })
        });
        let pool = WorkerPool::new(resolve, 1, 2, None).unwrap();

        let mut accepted = 0;
        let mut rejected = 0;
        for i in 0..10 {
            match pool.submit(job(i)) {
                Ok(()) => accepted += 1,
                Err(_) => rejected += 1,
            }
        }
        assert!(rejected > 0, "포화 시 일부는 반려되어야");
        assert!(accepted >= 1);

        {
            let (lock, cv) = &*gate;
            *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
            cv.notify_all();
        }
        pool.shutdown();
    }

    #[test]
    /** @brief 실패 응답이 질의 번호와 질문을 되비추는지. */
    fn servfail_echoes_id_and_question() {
        let req = Message::query(
            0xBEEF,
            onetdns_proto::Name::from_str("x.test").unwrap(),
            onetdns_proto::RecordType::A,
        );
        let wire = servfail_wire(&req);
        let parsed = Message::parse(&wire).unwrap();
        assert_eq!(parsed.header.id, 0xBEEF);
        assert!(parsed.header.response);
        assert_eq!(parsed.header.rcode, ResponseCode::ServFail.0);
        assert_eq!(parsed.questions.len(), 1);
    }

    #[test]
    /** @brief 패닉 뒤 응답을 만들 때 다시 파싱하지 않는지. 파싱에서 난 패닉이면 또 터진다. */
    fn raw_panic_fallback_never_reparses_and_emits_minimal_servfail() {
        assert!(servfail_wire_from_raw(&[0; 11]).is_none());
        let mut response = [0u8; 12];
        response[2] = 0x80;
        assert!(servfail_wire_from_raw(&response).is_none());

        let mut query = [0u8; 12];
        query[..2].copy_from_slice(&0xCAFEu16.to_be_bytes());
        query[2..4].copy_from_slice(&0x0110u16.to_be_bytes());
        let wire = servfail_wire_from_raw(&query).unwrap();
        let parsed = Message::parse(&wire).unwrap();
        assert_eq!(parsed.header.id, 0xCAFE);
        assert!(parsed.header.response);
        assert!(parsed.header.recursion_desired);
        assert!(parsed.header.checking_disabled);
        assert_eq!(parsed.header.rcode, ResponseCode::ServFail.0);
        assert!(parsed.questions.is_empty());
    }

    #[test]
    /** @brief 완료 알림이 리스너를 깨우는지. */
    fn completion_notifier_wakes_udp_listener_once_work_is_ready() {
        let listener = UdpSocket::bind("0.0.0.0:0").unwrap();
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let (notify, wake_source) =
            udp_completion_notifier(listener.local_addr().unwrap()).unwrap();
        let resolve: ResolveFn = Arc::new(|j: &QueryJob| {
            Some(ResolvedAnswer {
                wire: j.query.clone(),
                max_age: 0,
            })
        });
        let pool = WorkerPool::new(resolve, 1, 4, Some(notify)).unwrap();
        pool.submit(job(7)).unwrap();

        let mut packet = [0u8; 8];
        let (n, source) = listener.recv_from(&mut packet).unwrap();
        assert!(is_completion_wake(source, wake_source, &packet[..n]));
        let mut done = Vec::new();
        pool.drain_done(&mut done);
        assert_eq!(done.len(), 1);
        pool.shutdown();
    }

    #[test]
    /** @brief 패닉한 일이 실패 응답이 되고 워커가 계속 도는지. */
    fn panicking_job_returns_servfail_and_worker_processes_next_job() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let worker_calls = calls.clone();
        let resolve: ResolveFn = Arc::new(move |job: &QueryJob| {
            if worker_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
                panic!("simulated resolver panic");
            }
            Some(ResolvedAnswer {
                wire: job.query.clone(),
                max_age: 0,
            })
        });
        let pool = WorkerPool::new(resolve, 1, 4, None).unwrap();
        let request1 = Message::query(
            0x1111,
            onetdns_proto::Name::from_str("panic.example").unwrap(),
            onetdns_proto::RecordType::A,
        );
        let request2 = Message::query(
            0x2222,
            onetdns_proto::Name::from_str("healthy.example").unwrap(),
            onetdns_proto::RecordType::A,
        );
        let mut first = job(1);
        first.query = request1.try_encode().unwrap();
        let mut second = job(2);
        second.query = request2.try_encode().unwrap();
        pool.submit(first).unwrap();
        pool.submit(second).unwrap();

        let done = collect_done(&pool, 2);
        assert_eq!(done.len(), 2);
        let failed = Message::parse(done[0].wire.as_deref().unwrap()).unwrap();
        assert_eq!(failed.header.id, 0x1111);
        assert_eq!(failed.header.rcode, ResponseCode::ServFail.0);
        let healthy = Message::parse(done[1].wire.as_deref().unwrap()).unwrap();
        assert_eq!(healthy.header.id, 0x2222);
        assert!(!healthy.header.response);
        pool.shutdown();
    }
}
