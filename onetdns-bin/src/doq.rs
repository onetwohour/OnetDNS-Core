/*!
 * @brief DoQ 리스너.
 *
 * @details QUIC 스트림 하나에 질의 하나가 오간다. 소켓 하나로 여러 연결을 받고, 상태
 *          기계는 sans-IO라 여기서 데이터그램만 전달한다.
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
use onetdns_quic::{packet, Connection};
use onetdns_runtime::Transport as RtTransport;
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

/** @brief DoQ 리스너. 사라질 때 반복을 정리한다. */
pub struct DoqListener {
    /** @brief 이 리스너가 묶인 주소. */
    addr: SocketAddr,
    /** @brief 반복을 끝내라는 표시. */
    stop: Arc<AtomicBool>,
    /** @brief 루프를 실행하는 스레드. */
    thread: Option<std::thread::JoinHandle<()>>,
}

impl DoqListener {
    /** @brief 이 리스너가 묶인 주소. */
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for DoqListener {
    /** @brief 종료를 알리고 반복이 끝나기를 기다린다. */
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/** @brief 리스너를 열고 연결을 받는다. */
pub fn serve_doq(
    addr: SocketAddr,
    tls: Arc<onetdns_core::ArcSwap<ServerConfig>>,
    handler: Arc<NativeServer>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    memory_budget: Arc<QuicMemoryBudget>,
) -> io::Result<DoqListener> {
    let socket = onetdns_core::udp::bind(addr)?;
    let bound = socket.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let listener_stop = stop.clone();
    let wait = RecvWait::new(TIMER_INTERVAL);
    wait.install(&socket)?;
    let workers = qworker::default_worker_count();
    let (done_notify, wake_source) = qworker::udp_completion_notifier(bound)?;
    let pool = WorkerPool::new(
        qworker::handler_resolver(handler),
        workers,
        workers * 64,
        Some(done_notify),
    )?;
    let thread = thread::Builder::new()
        .name("doq-listener".into())
        .spawn(move || {
            let control = QuicRunControl::new(shutdown, listener_stop, memory_budget);
            run_loop(socket, wait, tls, pool, wake_source, control)
        })?;
    Ok(DoqListener {
        addr: bound,
        stop,
        thread: Some(thread),
    })
}

/** @brief 새 연결 식별자. 예측할 수 없어야 한다. */
fn random_cid() -> Vec<u8> {
    let mut cid = [0u8; 8];
    onetdns_tls::sys::fill_random(&mut cid);
    cid.to_vec()
}

/** @brief 살아 있는 연결 하나와 그 상태. */
struct ConnEntry {
    /** @brief 이 연결의 상태 기계. */
    conn: Connection,
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

impl ConnEntry {
    /** @brief 현재 QUIC 보유량으로 전역 charge를 맞춘다. */
    fn refresh_memory(&mut self) -> bool {
        self.memory.refresh(self.conn.retained_payload_bytes())
    }
}

/**
 * @brief 이 질의가 DoQ에서 연결을 끊어야 하는 프로토콜 오류인지.
 *
 * @details RFC 9250은 QUIC 위의 DNS Message ID를 0으로 규정한다. 질의와 응답은
 *          스트림으로 짝지어지므로 ID 필드가 필요 없기 때문이다. 4.3.3은 0이 아닌 ID와
 *          edns-tcp-keepalive 옵션을 각각 치명적 오류로 열거한다. 후자는 TCP 전용이라
 *          QUIC 연결 관리와 뜻이 겹치고 어긋난다.
 * @return 끊어야 하면 그 까닭, 정상이면 None.
 */
fn doq_protocol_error(req: &Message) -> Option<&'static str> {
    if req.header.id != 0 {
        return Some("DNS message ID over QUIC must be zero");
    }
    let carries_keepalive = req
        .opt()
        .and_then(onetdns_proto::Edns::from_record)
        .is_some_and(|edns| edns.has_option(onetdns_proto::EDNS_TCP_KEEPALIVE));
    if carries_keepalive {
        return Some("edns-tcp-keepalive is not allowed over QUIC");
    }
    None
}

/**
 * @brief RFC 9250 의 DoQ 오류 코드 중 규격 위반에 쓰는 값.
 * @details 4.3.3 은 이런 오류를 치명적으로 보고 CONNECTION_CLOSE 로 알리게 한다.
 *          알리지 않으면 상대는 자기 유휴 데드라인까지 기다린다.
 */
const DOQ_PROTOCOL_ERROR: u64 = 0x2;

/**
 * @brief 끝난 질의의 응답을 해당 연결로 보낸다.
 * @param now_ms 연결 시계의 지금 시각. 응답 패킷의 전송 시각으로 기록되므로, 낡은 값을
 *               넘기면 왕복 시간 표본이 실제보다 커지고 PTO 도 실제 전송보다 이르게 잡힌다.
 */
fn apply_completions(
    socket: &UdpSocket,
    conns: &mut HashMap<Vec<u8>, ConnEntry>,
    aliases: &mut HashMap<Vec<u8>, Vec<u8>>,
    counts: &mut HashMap<IpAddr, usize>,
    done: &mut Vec<QueryDone>,
    now_ms: u64,
) {
    let mut to_remove: Vec<Vec<u8>> = Vec::new();
    for d in done.drain(..) {
        let Some(entry) = conns.get_mut(&d.conn_key) else {
            continue;
        };
        if entry.epoch != d.epoch {
            continue;
        }
        entry.inflight = entry.inflight.saturating_sub(1);
        let Some(mut wire) = d.wire else {
            continue;
        };
        /*
         * RFC 9250 에서 QUIC 위로 나가는 DNS 메시지의 ID 는 0 이어야 한다. 받는 쪽에서 0 이 아닌
         * 질의를 이미 끊지만, 내보내는 곳에서도 강제해 어떤 경로로도 새지 않게 한다.
         */
        if let Some(id) = wire.get_mut(..2) {
            id.fill(0);
        }
        entry.conn.set_now(now_ms);
        if let Err(error) = entry.conn.send_dns_message_owned(d.stream_id, wire) {
            transport_observe::record_error("doq", "send_response", Some(entry.peer), error);
            to_remove.push(d.conn_key);
            continue;
        }
        while let Some(dg) = entry.conn.next_datagram() {
            if let Err(error) = socket.send_to(&dg, entry.peer) {
                transport_observe::record_error("doq", "send_datagram", Some(entry.peer), error);
            }
        }
        if !entry.refresh_memory() {
            transport_observe::record_error(
                "doq",
                "memory_budget",
                Some(entry.peer),
                "Total QUIC connection memory budget exceeded",
            );
            to_remove.push(d.conn_key);
            continue;
        }
        if entry.conn.is_closed() {
            to_remove.push(d.conn_key);
        }
    }
    for key in to_remove {
        remove_connection(&key, conns, aliases, counts);
    }
}

/** @brief 주소별 연결 수를 다시 센다. */
fn rebuild_peer_counts(conns: &HashMap<Vec<u8>, ConnEntry>, counts: &mut HashMap<IpAddr, usize>) {
    counts.clear();
    for entry in conns.values() {
        *counts.entry(entry.peer.ip()).or_default() += 1;
    }
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

/** @brief 연결·별칭·주소 계수의 high-water bucket을 활성 연결에 비례시킨다. */
fn shrink_connection_tables(
    conns: &mut HashMap<Vec<u8>, ConnEntry>,
    aliases: &mut HashMap<Vec<u8>, Vec<u8>>,
    counts: &mut HashMap<IpAddr, usize>,
) {
    shrink_if_sparse(conns);
    shrink_if_sparse(aliases);
    shrink_if_sparse(counts);
}

/** @brief 쉬는 연결을 걷어낸다. */
fn evict_idle(
    conns: &mut HashMap<Vec<u8>, ConnEntry>,
    aliases: &mut HashMap<Vec<u8>, Vec<u8>>,
    counts: &mut HashMap<IpAddr, usize>,
) {
    let now = Instant::now();
    conns.retain(|_, entry| {
        !entry.conn.is_closed() && now.duration_since(entry.last) < IDLE_TIMEOUT
    });
    aliases.retain(|_, primary| conns.contains_key(primary));
    rebuild_peer_counts(conns, counts);
    shrink_connection_tables(conns, aliases, counts);
}

/** @brief 연결 하나를 지우고 카운터를 맞춘다. */
fn remove_connection(
    key: &[u8],
    conns: &mut HashMap<Vec<u8>, ConnEntry>,
    aliases: &mut HashMap<Vec<u8>, Vec<u8>>,
    counts: &mut HashMap<IpAddr, usize>,
) {
    if let Some(entry) = conns.remove(key) {
        let ip = entry.peer.ip();
        if let Some(count) = counts.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&ip);
            }
        }
    }
    aliases.retain(|_, primary| primary.as_slice() != key);
    shrink_connection_tables(conns, aliases, counts);
}

/** @brief 데드라인이 지난 연결의 재전송을 돌린다. */
fn drive_timeouts(
    socket: &UdpSocket,
    conns: &mut HashMap<Vec<u8>, ConnEntry>,
    aliases: &mut HashMap<Vec<u8>, Vec<u8>>,
    counts: &mut HashMap<IpAddr, usize>,
    now_ms: u64,
) {
    let mut closed = Vec::new();
    for (key, entry) in conns.iter_mut() {
        entry.conn.set_now(now_ms);
        entry.conn.on_timeout(now_ms);
        while let Some(datagram) = entry.conn.next_datagram() {
            if let Err(error) = socket.send_to(&datagram, entry.peer) {
                transport_observe::record_error("doq", "timeout_send", Some(entry.peer), error);
            }
        }
        if !entry.refresh_memory() {
            transport_observe::record_error(
                "doq",
                "memory_budget",
                Some(entry.peer),
                "Total QUIC connection memory budget exceeded",
            );
            closed.push(key.clone());
        } else if entry.conn.is_closed() {
            closed.push(key.clone());
        }
    }
    for key in closed {
        remove_connection(&key, conns, aliases, counts);
    }
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

/** @brief 지금 쓰이지 않는 연결 식별자를 만든다. */
fn unique_cid(conns: &HashMap<Vec<u8>, ConnEntry>) -> Vec<u8> {
    loop {
        let cid = random_cid();
        if !conns.contains_key(&cid) {
            return cid;
        }
    }
}

/** @brief 데이터그램을 받아 연결마다 넘기고 응답을 내보내는 반복. */
fn run_loop(
    socket: UdpSocket,
    wait: RecvWait,
    tls: Arc<onetdns_core::ArcSwap<ServerConfig>>,
    pool: WorkerPool,
    wake_source: SocketAddr,
    control: QuicRunControl,
) {
    let mut conns: HashMap<Vec<u8>, ConnEntry> = HashMap::new();
    let mut aliases: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    let mut peer_counts: HashMap<IpAddr, usize> = HashMap::new();
    let base_tp = TransportParams::server_defaults();
    let retry_key = RetryKey::generate();
    let mut last_sweep = Instant::now();
    let clock = Instant::now();
    let mut last_timer = Instant::now();
    let mut buf = [0u8; onetdns_quic::MAX_RECV_UDP_PAYLOAD as usize];
    let mut next_epoch: u64 = 0;
    let mut done_buf: Vec<QueryDone> = Vec::new();
    while !control.should_stop() {
        let maintenance = onetdns_core::isolation::catch_request(|| {
            pool.drain_done(&mut done_buf);
            if !done_buf.is_empty() {
                apply_completions(
                    &socket,
                    &mut conns,
                    &mut aliases,
                    &mut peer_counts,
                    &mut done_buf,
                    clock.elapsed().as_millis().min(u64::MAX as u128) as u64,
                );
            }
            if last_timer.elapsed() >= TIMER_INTERVAL {
                drive_timeouts(
                    &socket,
                    &mut conns,
                    &mut aliases,
                    &mut peer_counts,
                    clock.elapsed().as_millis().min(u64::MAX as u128) as u64,
                );
                last_timer = Instant::now();
            }
            if last_sweep.elapsed() >= SWEEP_INTERVAL {
                evict_idle(&mut conns, &mut aliases, &mut peer_counts);
                last_sweep = Instant::now();
            }
        });
        if maintenance.is_err() {
            conns.clear();
            aliases.clear();
            peer_counts.clear();
            done_buf.clear();
        }
        let (n, peer) = match wait.recv_from(&socket, &mut buf) {
            Ok(x) => x,
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) => {
                transport_observe::record_error("doq", "recv_datagram", None, error);
                continue;
            }
        };
        let packet_bytes = &buf[..n];
        let mut panic_key: Option<Vec<u8>> = None;
        let packet_result = onetdns_core::isolation::catch_request(|| {
            if qworker::is_completion_wake(peer, wake_source, packet_bytes) {
                return;
            }
            let Some(dcid) = packet::destination_connection_id(packet_bytes, 8).map(|v| v.to_vec())
            else {
                transport_observe::record_error(
                    "doq",
                    "packet_header",
                    Some(peer),
                    "missing destination connection id",
                );
                return;
            };
            let now = Instant::now();

            let mut key = aliases.get(&dcid).cloned().unwrap_or_else(|| dcid.clone());
            panic_key = Some(key.clone());
            if !conns.contains_key(&key) {
                if !packet::is_initial_packet(packet_bytes) {
                    transport_observe::record_error(
                        "doq",
                        "unknown_connection",
                        Some(peer),
                        "non-initial packet for unknown connection",
                    );
                    return;
                }
                let per_ip = peer_counts.get(&peer.ip()).copied().unwrap_or(0);
                if !initial_connection_allowed(packet_bytes.len(), conns.len(), per_ip) {
                    transport_observe::record_error(
                        "doq",
                        "connection_limit",
                        Some(peer),
                        "initial datagram rejected by size or connection limit",
                    );
                    return;
                }
                let Some(header) = parse_initial_header(packet_bytes) else {
                    return;
                };
                if header.token.is_empty() {
                    let retry_cid = unique_cid(&conns);
                    let token = retry_key.issue(peer.ip(), header.dcid, &retry_cid, unix_now());
                    let retry = build_retry(header.dcid, header.scid, &retry_cid, &token);
                    if let Err(error) = socket.send_to(&retry, peer) {
                        transport_observe::record_error("doq", "send_retry", Some(peer), error);
                    }
                    return;
                }
                let Some(original_dcid) =
                    retry_key.validate(header.token, peer.ip(), header.dcid, unix_now())
                else {
                    transport_observe::record_error(
                        "doq",
                        "retry_token",
                        Some(peer),
                        "invalid or expired retry token",
                    );
                    return;
                };
                let local_cid = header.dcid.to_vec();
                panic_key = Some(local_cid.clone());
                let Some(memory) = QuicMemoryLease::try_new(control.memory_budget().clone()) else {
                    transport_observe::record_error(
                        "doq",
                        "memory_budget",
                        Some(peer),
                        format!(
                            "Total QUIC connection memory budget is full: {} / {} bytes",
                            control.memory_budget().used_bytes(),
                            control.memory_budget().limit_bytes()
                        ),
                    );
                    return;
                };
                let mut transport = base_tp.clone();
                transport.original_destination_connection_id = Some(original_dcid);
                transport.retry_source_connection_id = Some(local_cid.clone());
                conns.insert(
                    local_cid.clone(),
                    ConnEntry {
                        conn: Connection::new_server(tls.load(), local_cid.clone(), transport),
                        peer,
                        last: now,
                        epoch: next_epoch,
                        inflight: 0,
                        memory,
                    },
                );
                next_epoch = next_epoch.wrapping_add(1);
                aliases.insert(dcid, local_cid.clone());
                *peer_counts.entry(peer.ip()).or_default() += 1;
                key = local_cid;
            }

            let mut remove = false;
            if let Some(entry) = conns.get_mut(&key) {
                if !same_validated_path(entry.peer, peer) {
                    transport_observe::record_error(
                        "doq",
                        "connection_migration",
                        Some(peer),
                        "connection migration requires path validation",
                    );
                    return;
                }
                entry.last = now;
                let conn = &mut entry.conn;
                conn.set_now(clock.elapsed().as_millis().min(u64::MAX as u128) as u64);
                let recv_result = conn.recv_datagram(packet_bytes);
                if let Some(diagnostic) = conn.take_diagnostic() {
                    transport_observe::record_quic_diagnostic("doq", Some(entry.peer), diagnostic);
                }
                if let Err(error) = recv_result {
                    transport_observe::record_error(
                        "doq",
                        "quic_connection",
                        Some(entry.peer),
                        error,
                    );
                    remove = true;
                } else {
                    let _ = conn.take_resets();
                    for (sid, q) in conn.take_stream_requests() {
                        match Message::parse(&q) {
                            Ok(req) if !req.header.response => {
                                if let Some(reason) = doq_protocol_error(&req) {
                                    transport_observe::record_error(
                                        "doq",
                                        "doq_protocol_error",
                                        Some(entry.peer),
                                        reason,
                                    );
                                    conn.close(DOQ_PROTOCOL_ERROR, reason);
                                    remove = true;
                                    break;
                                }
                                if entry.inflight >= MAX_INFLIGHT_PER_CONN {
                                    transport_observe::record_error(
                                        "doq",
                                        "inflight_limit",
                                        Some(entry.peer),
                                        "connection has too many queries in flight",
                                    );
                                    let wire = qworker::servfail_wire(&req);
                                    if let Err(error) = conn.send_dns_message_owned(sid, wire) {
                                        transport_observe::record_error(
                                            "doq",
                                            "send_response",
                                            Some(entry.peer),
                                            error,
                                        );
                                    }
                                    continue;
                                }
                                let auth_identity =
                                    conn.client_auth_identity().map(|value| value.to_string());
                                let job = QueryJob {
                                    conn_key: key.clone(),
                                    epoch: entry.epoch,
                                    stream_id: sid,
                                    query: q,
                                    peer: entry.peer,
                                    transport: RtTransport::DoQ,
                                    client_id: auth_identity.clone(),
                                    authenticated: conn.client_authenticated(),
                                    auth_identity,
                                };
                                match pool.submit(job) {
                                    Ok(()) => entry.inflight += 1,
                                    Err(job) => {
                                        transport_observe::record_error(
                                            "doq",
                                            "worker_queue_full",
                                            Some(entry.peer),
                                            "query worker queue is saturated",
                                        );
                                        let wire = qworker::servfail_wire(&req);
                                        if let Err(error) =
                                            conn.send_dns_message_owned(job.stream_id, wire)
                                        {
                                            transport_observe::record_error(
                                                "doq",
                                                "send_response",
                                                Some(entry.peer),
                                                error,
                                            );
                                        }
                                    }
                                }
                            }
                            Ok(_) => {
                                transport_observe::record_error(
                                    "doq",
                                    "dns_response_as_query",
                                    Some(entry.peer),
                                    "unsolicited DNS response",
                                );
                                conn.close(DOQ_PROTOCOL_ERROR, "unsolicited DNS response");
                                remove = true;
                                break;
                            }
                            Err(error) => {
                                transport_observe::record_error(
                                    "doq",
                                    "dns_parse",
                                    Some(entry.peer),
                                    error,
                                );
                                conn.close(DOQ_PROTOCOL_ERROR, "malformed DNS message");
                                remove = true;
                                break;
                            }
                        }
                    }
                    while let Some(dg) = conn.next_datagram() {
                        if let Err(error) = socket.send_to(&dg, entry.peer) {
                            transport_observe::record_error(
                                "doq",
                                "send_datagram",
                                Some(entry.peer),
                                error,
                            );
                        }
                    }
                    remove |= conn.is_closed();
                }
                if !remove && !entry.refresh_memory() {
                    transport_observe::record_error(
                        "doq",
                        "memory_budget",
                        Some(entry.peer),
                        "Total QUIC connection memory budget exceeded",
                    );
                    remove = true;
                }
            }
            if remove {
                remove_connection(&key, &mut conns, &mut aliases, &mut peer_counts);
            }
        });
        if packet_result.is_err() {
            if let Some(key) = panic_key {
                remove_connection(&key, &mut conns, &mut aliases, &mut peer_counts);
            }
        }
    }
    pool.shutdown();
}

/** @brief 현재 Unix 초. */
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
/** @brief 연결 수락 조건, 종료, 재전송, 그리고 실제 QUIC 위 질의 왕복. */
mod tests {
    use super::*;
    use std::net::UdpSocket;

    use onetdns_core::BlockResponse;
    use onetdns_filter::{build_from_str, SharedFilter};
    use onetdns_forward::Forwarder;
    use onetdns_proto::{Name as ApName, RData as ApRData, RecordType};
    use onetdns_security::IpAcl;
    use onetdns_tls::ClientConfig;

    use crate::native::NativeBackend;

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

    /** @brief 고정 응답을 내는 테스트용 업스트림. */
    fn mock_upstream() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        thread::spawn(move || {
            let mut b = [0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut b) {
                if let Ok(req) = Message::parse(&b[..n]) {
                    let mut m = Message::default();
                    m.header.id = req.header.id;
                    m.header.response = true;
                    m.header.recursion_available = true;
                    m.questions = req.questions.clone();
                    if let Some(q) = req.questions.first() {
                        m.answers.push(onetdns_proto::Record::new(
                            q.name.clone(),
                            60,
                            ApRData::A(std::net::Ipv4Addr::new(9, 9, 9, 9)),
                        ));
                    }
                    let _ = sock.send_to(&m.try_encode().unwrap(), from);
                }
            }
        });
        addr
    }

    /** @brief 테스트용 질의 핸들러. */
    fn native_handler() -> Arc<NativeServer> {
        let engine = build_from_str("||blocked.test^\n", "", BlockResponse::NxDomain);
        Arc::new(NativeServer::new(
            Arc::new(SharedFilter::from_pointee(engine)),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(NativeBackend::Forward(Forwarder::new(
                vec![mock_upstream()],
                Duration::from_secs(2),
            ))),
            60,
        ))
    }

    /** @brief 테스트용 자체 서명 설정. */
    fn self_signed_doq() -> Arc<ServerConfig> {
        let (certs, key) = onetdns_transport::self_signed_material("dns.test").unwrap();
        let cert_der = certs[0].clone();
        let key_der = key.clone();
        let cfg = ServerConfig::from_pkcs8(cert_der, &key_der)
            .expect("ECDSA P-256 서명자")
            .with_alpn(vec![b"doq".to_vec()]);
        Arc::new(cfg)
    }

    /** @brief 테스트 하나가 쓰는 독립 QUIC 전역 예산. */
    fn memory_budget() -> Arc<QuicMemoryBudget> {
        Arc::new(QuicMemoryBudget::default())
    }

    #[test]
    /** @brief 종료 때 반복이 정리되는지. */
    fn dropping_doq_listener_joins_event_loop() {
        let listener = serve_doq(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(self_signed_doq())),
            native_handler(),
            Arc::new(AtomicBool::new(false)),
            memory_budget(),
        )
        .unwrap();
        let started = Instant::now();
        drop(listener);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /** @brief QUIC로 질의를 보내고 답을 받는다. */
    fn doq_query(server: SocketAddr, name: &str, qtype: RecordType) -> Message {
        doq_query_with_blackout(server, name, qtype, Duration::ZERO, random_cid())
    }

    /**
     * @brief 패킷이 잠시 끊기는 상황을 만들어 질의를 보낸다.
     * @param client_cid 클라이언트가 쓸 연결 식별자. 길이 0이어도 된다.
     */
    fn doq_query_with_blackout(
        server: SocketAddr,
        name: &str,
        qtype: RecordType,
        blackout: Duration,
        client_cid: Vec<u8>,
    ) -> Message {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        /*
         * 블랙아웃 시험은 질의 뒤 클라이언트 타이머를 멈추므로 잃은 데이터그램을 되찾지 못한다.
         * 소켓 수신 한도에 기대면 윈도우에서 한도에 걸리는 순간 도착한 응답이 사라져 서버
         * 재전송과 무관하게 실패한다.
         */
        let wait = RecvWait::new(Duration::from_millis(50));
        wait.install(&sock).unwrap();
        let cfg = ClientConfig {
            server_name: "dns.test".into(),
            verify_name: false,
            roots: None,
            insecure_verifier: Some(
                onetdns_tls::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![b"doq".to_vec()],
            ..Default::default()
        };
        let mut client = Connection::new_client(
            cfg,
            random_cid(),
            client_cid,
            TransportParams::server_defaults(),
        )
        .unwrap();

        let query = Message::query(0, ApName::from_str(name).unwrap(), qtype)
            .try_encode()
            .unwrap();
        let mut asked = false;
        let mut blackout_started = None;
        let mut b = [0u8; 2048];
        /*
         * 반복 횟수가 아니라 시각으로 끝낸다. 한 바퀴마다 데이터그램 하나를 받거나 50밀리초를
         * 기다리므로, 횟수로 세면 전체 시험을 병렬로 돌리는 CI 러너에서 서버 스레드가 몇 초
         * 밀렸을 때 응답보다 한도가 먼저 끝난다. 이 한도는 응답이 아예 오지 않는 경우를
         * 잡으려는 것이지 지연 요구가 아니다.
         */
        let clock = Instant::now();
        let deadline = clock + Duration::from_secs(15);
        while Instant::now() < deadline {
            /*
             * 연결 상태 기계는 시계를 직접 읽지 않으므로 시각을 넘기고 재전송 타이머를 돌린다.
             * 돌리지 않으면 클라이언트가 보낸 데이터그램 하나가 사라졌을 때 다시 보내지 않아
             * 응답을 끝내 받지 못한다. 블랙아웃 시험은 질의를 보낸 뒤 타이머를 멈춘다.
             * 클라이언트가 프로브를 계속 보내면 서버가 그 ACK 로 응답 손실을 알아채 다시
             * 보낼 수 있어, 서버가 스스로 재전송하는지 증명하지 못한다.
             */
            let now_ms = clock.elapsed().as_millis() as u64;
            client.set_now(now_ms);
            if blackout.is_zero() || !asked {
                client.on_timeout(now_ms);
            }
            while let Some(dg) = client.next_datagram() {
                sock.send_to(&dg, server).unwrap();
            }
            if client.is_handshake_complete() && !asked {
                client.send_dns_message(0, &query).unwrap();
                asked = true;
                blackout_started = Some(Instant::now());
                while let Some(dg) = client.next_datagram() {
                    sock.send_to(&dg, server).unwrap();
                }
            }
            if asked {
                if let Some((_, resp)) = client.take_stream_requests().into_iter().next() {
                    return Message::parse(&resp).unwrap();
                }
            }
            match wait.recv_from(&sock, &mut b) {
                Ok((n, _)) => {
                    if blackout_started.is_some_and(|started| started.elapsed() < blackout) {
                        continue;
                    }
                    client.recv_datagram(&b[..n]).unwrap();
                }
                Err(_) => {}
            }
        }
        panic!("DoQ 응답 없음");
    }

    #[test]
    /** @brief 허용된 이름이 해석되는지. */
    fn doq_allowed_query_resolves_over_self_quic() {
        let l = serve_doq(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(self_signed_doq())),
            native_handler(),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            memory_budget(),
        )
        .unwrap();
        let resp = doq_query(l.addr(), "allowed.test", RecordType::A);
        assert_eq!(resp.header.id, 0, "RFC 9250 4.2.1: QUIC 위 메시지 ID는 0");
        assert_eq!(resp.answers.len(), 1, "A 레코드 1개");
        match &resp.answers[0].rdata {
            ApRData::A(ip) => assert_eq!(*ip, std::net::Ipv4Addr::new(9, 9, 9, 9)),
            other => panic!("A 레코드를 예상했지만 실제 값은 {other:?}입니다"),
        }
    }

    #[test]
    /**
     * @brief RFC 9250이 열거한 두 프로토콜 오류를 가려내는지.
     * @details 0이 아닌 ID와 edns-tcp-keepalive다. 둘 다 연결을 끊어야 하므로 답이 없다.
     */
    fn doq_protocol_errors_are_recognized() {
        let ok = Message::query(0, ApName::from_str("allowed.test").unwrap(), RecordType::A);
        assert!(doq_protocol_error(&ok).is_none(), "정상 질의는 통과한다");

        let bad_id = Message::query(
            0x4242,
            ApName::from_str("allowed.test").unwrap(),
            RecordType::A,
        );
        assert!(
            doq_protocol_error(&bad_id).is_some(),
            "QUIC 위 메시지 ID는 0이어야 한다"
        );

        let mut keepalive = ok.clone();
        keepalive.set_tcp_keepalive(100).unwrap();
        assert!(
            doq_protocol_error(&keepalive).is_some(),
            "edns-tcp-keepalive는 TCP 전용이라 QUIC에서는 오류다"
        );
    }

    #[test]
    /** @brief 차단된 이름이 막히는지. */
    fn doq_blocked_query_returns_nxdomain_over_self_quic() {
        let l = serve_doq(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(self_signed_doq())),
            native_handler(),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            memory_budget(),
        )
        .unwrap();
        let resp = doq_query(l.addr(), "blocked.test", RecordType::A);
        assert_eq!(resp.header.rcode, onetdns_proto::ResponseCode::NXDomain.0);
        assert!(resp.answers.is_empty());
    }

    #[test]
    /** @brief 클라이언트가 조용해도 서버가 스스로 재전송하는지. 안 하면 잃은 응답이 영영 안 간다. */
    fn doq_server_pto_retransmits_without_new_client_packets() {
        let l = serve_doq(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(self_signed_doq())),
            native_handler(),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            memory_budget(),
        )
        .unwrap();
        let resp = doq_query_with_blackout(
            l.addr(),
            "pto.test",
            RecordType::A,
            Duration::from_millis(400),
            random_cid(),
        );
        assert_eq!(resp.header.id, 0, "RFC 9250 4.2.1: QUIC 위 메시지 ID는 0");
        assert_eq!(resp.answers.len(), 1);
    }

    #[test]
    /**
     * @brief 길이 0인 연결 식별자를 쓰는 클라이언트의 질의에 답하는지.
     * @details msquic 을 쓰는 클라이언트가 이렇게 연결한다. 리스너가 그 Initial 을 받아들이지
     *          않으면 핸드셰이크가 시간 초과로 끝난다.
     */
    fn doq_answers_client_with_zero_length_connection_id() {
        let l = serve_doq(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(self_signed_doq())),
            native_handler(),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            memory_budget(),
        )
        .unwrap();
        let resp = doq_query_with_blackout(
            l.addr(),
            "allowed.test",
            RecordType::A,
            Duration::ZERO,
            Vec::new(),
        );
        assert_eq!(resp.answers.len(), 1);
    }
}
