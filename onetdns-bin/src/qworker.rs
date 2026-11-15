//! Query worker pool, so one slow query does not hold up the fast ones behind it. The receiver only
//! queues; workers resolve and report completion.
//!
//! A panic fails only its own query: it is caught and turned into a minimal failure response, and
//! the worker moves on.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

use onetdns_proto::{Message, ResponseCode};
use onetdns_runtime::{Handler, RequestCtx, Transport as RtTransport};

use crate::native::NativeServer;

pub const MAX_INFLIGHT_PER_CONN: usize = 256;

#[derive(Debug)]
pub struct QueryJob {
    pub conn_key: Vec<u8>,
    /// Tells late answers for a finished connection apart.
    pub epoch: u64,
    pub stream_id: u64,
    /// As received.
    pub query: Vec<u8>,
    pub peer: SocketAddr,
    pub transport: RtTransport,
    /// From the path or the certificate.
    pub client_id: Option<String>,
    pub authenticated: bool,
    /// Identity named in the certificate.
    pub auth_identity: Option<String>,
}

#[derive(Debug)]
pub struct QueryDone {
    pub conn_key: Vec<u8>,
    pub epoch: u64,
    pub stream_id: u64,
    /// None when no answer could be made.
    pub wire: Option<Vec<u8>>,
    /// HTTP cache freshness lifetime; DoH3 uses it, DoQ ignores it.
    pub max_age: u32,
}

/// Only the code that built the response has the Message, so the lifetime, which only HTTP
/// transports use, travels with the bytes.
pub struct ResolvedAnswer {
    pub wire: Vec<u8>,
    pub max_age: u32,
}

pub type ResolveFn = Arc<dyn Fn(&QueryJob) -> Option<ResolvedAnswer> + Send + Sync>;
pub type DoneNotify = Arc<dyn Fn() + Send + Sync>;

const COMPLETION_WAKE: &[u8] = b"\0";

/// The listener sleeps in a socket receive, so completion is signaled by sending that socket a
/// packet. Also returns the sender's address, for `is_completion_wake`.
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

/// Both the source and the payload must match; otherwise a packet from outside could pass as a
/// wake.
pub fn is_completion_wake(source: SocketAddr, expected: SocketAddr, packet: &[u8]) -> bool {
    source == expected && packet == COMPLETION_WAKE
}

struct Queue {
    jobs: VecDeque<QueryJob>,
    closed: bool,
}

struct Shared {
    queue: Mutex<Queue>,
    not_empty: Condvar,
    capacity: usize,
    done: Mutex<VecDeque<QueryDone>>,
    done_notify: Option<DoneNotify>,
}

pub struct WorkerPool {
    shared: Arc<Shared>,
    workers: Vec<JoinHandle<()>>,
}

impl WorkerPool {
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

    /// Returns the job when the queue is full or closed.
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

    pub fn drain_done(&self, out: &mut Vec<QueryDone>) {
        let mut done = self.shared.done.lock().unwrap_or_else(|e| e.into_inner());
        out.extend(done.drain(..));
    }

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

    /// Stops the workers and joins them.
    pub fn shutdown(mut self) {
        self.stop();
    }
}

impl Drop for WorkerPool {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Catches panics: an uncaught one would kill the worker over a single query and shrink the pool.
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

/// The panic may have come from parsing, and parsing again would panic at the same place, so only
/// the header is patched.
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

pub fn default_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(2, 16)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    /// Reparsing would hit a parser panic again.
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
