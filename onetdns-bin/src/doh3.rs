/*!
 * @brief DoH3 리스너.
 *
 * @details QUIC 위 HTTP/3로 DNS 메시지를 주고받는다. 소켓 하나로 여러 연결을 받고,
 *          상태 기계는 sans-IO라 여기서 데이터그램만 전달한다.
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
use onetdns_quic::{packet, Connection, H3Connection};
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

/** @brief DoH3 리스너. 사라질 때 반복을 정리한다. */
pub struct Doh3Listener {
    /** @brief 이 리스너가 묶인 주소. */
    addr: SocketAddr,
    /** @brief 반복을 끝내라는 표시. */
    stop: Arc<AtomicBool>,
    /** @brief 루프를 실행하는 스레드. */
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Doh3Listener {
    /** @brief 이 리스너가 묶인 주소. */
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Doh3Listener {
    /** @brief 종료를 알리고 반복이 끝나기를 기다린다. */
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/** @brief 리스너를 열고 연결을 받는다. */
pub fn serve_doh3(
    addr: SocketAddr,
    tls: Arc<onetdns_core::ArcSwap<ServerConfig>>,
    handler: Arc<NativeServer>,
    doh_path: String,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    memory_budget: Arc<QuicMemoryBudget>,
) -> io::Result<Doh3Listener> {
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
        .name("doh3-listener".into())
        .spawn(move || {
            let control = QuicRunControl::new(shutdown, listener_stop, memory_budget);
            run_loop(socket, wait, tls, doh_path, pool, wake_source, control)
        })?;
    Ok(Doh3Listener {
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
    conn: H3Connection,
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
    /** @brief 현재 HTTP/3+QUIC 보유량으로 전역 charge를 맞춘다. */
    fn refresh_memory(&mut self) -> bool {
        self.memory.refresh(self.conn.retained_payload_bytes())
    }
}

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
        let Some(wire) = d.wire else {
            continue;
        };
        entry.conn.set_now(now_ms);
        if let Err(error) = entry.conn.send_response_owned(d.stream_id, wire, d.max_age) {
            transport_observe::record_error("doh3", "send_response", Some(entry.peer), error);
            to_remove.push(d.conn_key);
            continue;
        }
        while let Some(dg) = entry.conn.next_datagram() {
            if let Err(error) = socket.send_to(&dg, entry.peer) {
                transport_observe::record_error("doh3", "send_datagram", Some(entry.peer), error);
            }
        }
        if !entry.refresh_memory() {
            transport_observe::record_error(
                "doh3",
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
                transport_observe::record_error("doh3", "timeout_send", Some(entry.peer), error);
            }
        }
        if !entry.refresh_memory() {
            transport_observe::record_error(
                "doh3",
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

/** @brief 요청 경로가 이 서버가 서빙하는 것인지. */
fn match_doh_path(path: &[u8], expected: &str) -> bool {
    let path_only = path.split(|&b| b == b'?').next().unwrap_or(path);
    if path_only == expected.as_bytes() {
        return true;
    }
    let mut prefix = expected.as_bytes().to_vec();
    prefix.push(b'/');
    path_only
        .strip_prefix(prefix.as_slice())
        .is_some_and(|rest| !rest.is_empty() && !rest.contains(&b'/'))
}

/** @brief 데이터그램을 받아 연결마다 넘기고 응답을 내보내는 반복. */
fn run_loop(
    socket: UdpSocket,
    wait: RecvWait,
    tls: Arc<onetdns_core::ArcSwap<ServerConfig>>,
    doh_path: String,
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
                transport_observe::record_error("doh3", "recv_datagram", None, error);
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
                    "doh3",
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
                        "doh3",
                        "unknown_connection",
                        Some(peer),
                        "non-initial packet for unknown connection",
                    );
                    return;
                }
                let per_ip = peer_counts.get(&peer.ip()).copied().unwrap_or(0);
                if !initial_connection_allowed(packet_bytes.len(), conns.len(), per_ip) {
                    transport_observe::record_error(
                        "doh3",
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
                        transport_observe::record_error("doh3", "send_retry", Some(peer), error);
                    }
                    return;
                }
                let Some(original_dcid) =
                    retry_key.validate(header.token, peer.ip(), header.dcid, unix_now())
                else {
                    transport_observe::record_error(
                        "doh3",
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
                        "doh3",
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
                let conn = Connection::new_server(tls.load(), local_cid.clone(), transport);
                conns.insert(
                    local_cid.clone(),
                    ConnEntry {
                        conn: H3Connection::new(conn),
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
                        "doh3",
                        "connection_migration",
                        Some(peer),
                        "connection migration requires path validation",
                    );
                    return;
                }
                entry.last = now;
                let h3 = &mut entry.conn;
                h3.set_now(clock.elapsed().as_millis().min(u64::MAX as u128) as u64);
                let recv_result = h3.recv_datagram(packet_bytes);
                if let Some(diagnostic) = h3.conn_mut().take_diagnostic() {
                    transport_observe::record_quic_diagnostic("doh3", Some(entry.peer), diagnostic);
                }
                if let Err(error) = recv_result {
                    transport_observe::record_error(
                        "doh3",
                        "quic_connection",
                        Some(entry.peer),
                        error,
                    );
                    remove = true;
                } else {
                    'requests: for r in h3.take_requests_meta() {
                        if !match_doh_path(&r.path, &doh_path) {
                            if let Err(error) = h3.send_status(r.stream_id, b"404") {
                                transport_observe::record_error(
                                    "doh3",
                                    "send_response",
                                    Some(entry.peer),
                                    error,
                                );
                                remove = true;
                                break;
                            }
                            continue;
                        }
                        match Message::parse(&r.wire) {
                            Ok(req) if !req.header.response => {
                                let authenticated = h3.client_authenticated();
                                let auth_identity =
                                    h3.client_auth_identity().map(|value| value.to_string());

                                let client_id = match crate::doh::authenticated_path_identity(
                                    r.client_id.as_deref(),
                                    authenticated,
                                    auth_identity.as_deref(),
                                ) {
                                    Ok(id) => id,
                                    Err(()) => {
                                        onetdns_core::warn!(event = "doh3.client_id_mismatch",
                                            peer = %entry.peer,
                                            path_identity = %r.client_id.as_deref().unwrap_or(""),
                                            auth_identity = %auth_identity.as_deref().unwrap_or(""),
                                            "Client ID in the DoH3 URL does not match the client ID in the mTLS certificate"
                                        );
                                        if let Err(error) = h3.send_status(r.stream_id, b"403") {
                                            transport_observe::record_error(
                                                "doh3",
                                                "send_response",
                                                Some(entry.peer),
                                                error,
                                            );
                                            remove = true;
                                            break 'requests;
                                        }
                                        continue;
                                    }
                                };

                                if entry.inflight >= MAX_INFLIGHT_PER_CONN {
                                    transport_observe::record_error(
                                        "doh3",
                                        "inflight_limit",
                                        Some(entry.peer),
                                        "connection has too many queries in flight",
                                    );
                                    let wire = qworker::servfail_wire(&req);
                                    if let Err(error) = h3.send_response_owned(r.stream_id, wire, 0)
                                    {
                                        transport_observe::record_error(
                                            "doh3",
                                            "send_response",
                                            Some(entry.peer),
                                            error,
                                        );
                                        remove = true;
                                        break;
                                    }
                                    continue;
                                }
                                let job = QueryJob {
                                    conn_key: key.clone(),
                                    epoch: entry.epoch,
                                    stream_id: r.stream_id,
                                    query: r.wire,
                                    peer: entry.peer,
                                    transport: RtTransport::DoH3,
                                    client_id,
                                    authenticated,
                                    auth_identity,
                                };
                                match pool.submit(job) {
                                    Ok(()) => entry.inflight += 1,
                                    Err(job) => {
                                        transport_observe::record_error(
                                            "doh3",
                                            "worker_queue_full",
                                            Some(entry.peer),
                                            "query worker queue is saturated",
                                        );
                                        let wire = qworker::servfail_wire(&req);
                                        if let Err(error) =
                                            h3.send_response_owned(job.stream_id, wire, 0)
                                        {
                                            transport_observe::record_error(
                                                "doh3",
                                                "send_response",
                                                Some(entry.peer),
                                                error,
                                            );
                                            remove = true;
                                            break;
                                        }
                                    }
                                }
                            }
                            Ok(_) => {
                                transport_observe::record_error(
                                    "doh3",
                                    "dns_response_as_query",
                                    Some(entry.peer),
                                    "unsolicited DNS response",
                                );
                                if let Err(error) = h3.send_status(r.stream_id, b"400") {
                                    transport_observe::record_error(
                                        "doh3",
                                        "send_response",
                                        Some(entry.peer),
                                        error,
                                    );
                                    remove = true;
                                    break 'requests;
                                }
                            }
                            Err(error) => {
                                // 읽지 못한 본문은 요청 잘못이다. 아무것도 보내지 않으면
                                // 스트림이 매달린 채로 클라이언트가 자기 데드라인까지 기다린다.
                                // 바로 위 분기(응답을 질의로 보낸 경우)와 같은 상태로 답한다.
                                transport_observe::record_error(
                                    "doh3",
                                    "dns_parse",
                                    Some(entry.peer),
                                    error,
                                );
                                if let Err(error) = h3.send_status(r.stream_id, b"400") {
                                    transport_observe::record_error(
                                        "doh3",
                                        "send_response",
                                        Some(entry.peer),
                                        error,
                                    );
                                    remove = true;
                                    break 'requests;
                                }
                            }
                        }
                    }
                    while let Some(dg) = h3.next_datagram() {
                        if let Err(error) = socket.send_to(&dg, entry.peer) {
                            transport_observe::record_error(
                                "doh3",
                                "send_datagram",
                                Some(entry.peer),
                                error,
                            );
                        }
                    }
                    remove |= h3.is_closed();
                }
                if !remove && !entry.refresh_memory() {
                    transport_observe::record_error(
                        "doh3",
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
/** @brief 연결 수락 조건, 종료, 그리고 실제 HTTP/3 위 질의 왕복. */
mod tests {
    use super::*;
    use std::net::UdpSocket;

    use onetdns_core::BlockResponse;
    use onetdns_filter::{build_from_str, SharedFilter};
    use onetdns_forward::Forwarder;
    use onetdns_proto::{Name as ApName, RData as ApRData, RecordType};
    use onetdns_quic::{h3, qpack};
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

    #[test]
    /** @brief 희소 listener table의 연결·별칭·IP bucket까지 기본 charge 안에 드는지. */
    fn base_charge_covers_sparse_listener_table_slots() {
        let connection_slot = std::mem::size_of::<Vec<u8>>()
            .saturating_add(std::mem::size_of::<ConnEntry>())
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
    fn self_signed_h3() -> Arc<ServerConfig> {
        let (certs, key) = onetdns_transport::self_signed_material("dns.test").unwrap();
        let cert_der = certs[0].clone();
        let key_der = key.clone();
        Arc::new(
            ServerConfig::from_pkcs8(cert_der, &key_der)
                .expect("ECDSA P-256")
                .with_alpn(vec![b"h3".to_vec()]),
        )
    }

    /** @brief 테스트 하나가 쓰는 독립 QUIC 전역 예산. */
    fn memory_budget() -> Arc<QuicMemoryBudget> {
        Arc::new(QuicMemoryBudget::default())
    }

    #[test]
    /** @brief 종료 때 반복이 정리되는지. */
    fn dropping_doh3_listener_joins_event_loop() {
        let listener = serve_doh3(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(self_signed_h3())),
            native_handler(),
            "/dns-query".to_string(),
            Arc::new(AtomicBool::new(false)),
            memory_budget(),
        )
        .unwrap();
        let started = Instant::now();
        drop(listener);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /** @brief HTTP/3로 질의를 보내고 답을 받는다. */
    fn doh3_query(server: SocketAddr, name: &str, qtype: RecordType) -> Message {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let cfg = ClientConfig {
            server_name: "dns.test".into(),
            verify_name: false,
            roots: None,
            insecure_verifier: Some(
                onetdns_tls::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![b"h3".to_vec()],
            ..Default::default()
        };
        let mut client = Connection::new_client(
            cfg,
            random_cid(),
            random_cid(),
            TransportParams::server_defaults(),
        )
        .unwrap();

        let query = Message::query(0x4242, ApName::from_str(name).unwrap(), qtype)
            .try_encode()
            .unwrap();
        let mut sent = false;
        let mut stream0: Vec<u8> = Vec::new();
        let mut b = [0u8; 2048];
        /*
         * 한도는 반복 횟수가 아니라 시각으로 둔다. 연결 상태 기계는 시계를 직접 읽지 않으므로
         * 시각을 넘기고 재전송 타이머를 돌린다. 돌리지 않으면 클라이언트가 보낸 데이터그램
         * 하나가 사라졌을 때 다시 보내지 않아 응답을 끝내 받지 못한다.
         */
        let clock = Instant::now();
        let deadline = clock + Duration::from_secs(15);
        while Instant::now() < deadline {
            let now_ms = clock.elapsed().as_millis() as u64;
            client.set_now(now_ms);
            client.on_timeout(now_ms);
            while let Some(dg) = client.next_datagram() {
                sock.send_to(&dg, server).unwrap();
            }
            if client.is_handshake_complete() && !sent {
                let mut payload = Vec::new();
                h3::encode_frame(
                    &mut payload,
                    h3::FRAME_HEADERS,
                    &qpack::doh_post_request_headers("dns.test", "/dns-query", query.len()),
                );
                h3::encode_frame(&mut payload, h3::FRAME_DATA, &query);
                client.send_stream(0, &payload, true).unwrap();
                sent = true;
                while let Some(dg) = client.next_datagram() {
                    sock.send_to(&dg, server).unwrap();
                }
            }
            for (id, data, _fin) in client.take_readable() {
                if id == 0 {
                    stream0.extend_from_slice(&data);
                }
            }
            if let Some(frames) = h3::parse_frames(&stream0) {
                for (t, p) in &frames {
                    if *t == h3::FRAME_DATA && !p.is_empty() {
                        return Message::parse(p).unwrap();
                    }
                }
            }
            if let Ok((n, _)) = sock.recv_from(&mut b) {
                client.recv_datagram(&b[..n]).unwrap();
            }
        }
        panic!("DoH3 응답 없음");
    }

    #[test]
    /** @brief 허용된 이름이 해석되는지. */
    fn doh3_allowed_query_resolves_over_self_h3() {
        let l = serve_doh3(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(self_signed_h3())),
            native_handler(),
            "/dns-query".into(),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            memory_budget(),
        )
        .unwrap();
        let resp = doh3_query(l.addr(), "allowed.test", RecordType::A);
        assert_eq!(resp.header.id, 0x4242);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].rdata {
            ApRData::A(ip) => assert_eq!(*ip, std::net::Ipv4Addr::new(9, 9, 9, 9)),
            other => panic!("A 레코드를 예상했지만 실제 값은 {other:?}입니다"),
        }
    }

    #[test]
    /** @brief 차단된 이름이 막히는지. */
    fn doh3_blocked_query_returns_nxdomain_over_self_h3() {
        let l = serve_doh3(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(self_signed_h3())),
            native_handler(),
            "/dns-query".into(),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            memory_budget(),
        )
        .unwrap();
        let resp = doh3_query(l.addr(), "blocked.test", RecordType::A);
        assert_eq!(resp.header.rcode, onetdns_proto::ResponseCode::NXDomain.0);
        assert!(resp.answers.is_empty());
    }
}
