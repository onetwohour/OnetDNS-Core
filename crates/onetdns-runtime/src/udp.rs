/*!
 * @brief Do53 UDP 워커.
 *
 * @details 리눅스에서는 recvmmsg/sendmmsg로 여러 데이터그램을 한 번의 시스템 호출로
 *          주고받는다. 다른 플랫폼은 단일 수신 루프다. 두 경로 모두 process_datagram을
 *          공유하므로 파싱 전 고속 경로 시도 순서가 어긋나지 않는다.
 */

#[cfg(not(target_os = "linux"))]
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use onetdns_proto::{Edns, Message, Writer};

use crate::{Handler, RequestCtx, Transport};

/** @brief 전송 실패 누적 수. 로그 폭주를 막으려 표본만 기록하고 총계는 여기 쌓는다. */
static SEND_ERRORS: AtomicU64 = AtomicU64::new(0);

/** @brief recvmmsg 호출 횟수. 배치 하나마다 하나씩 는다. */
static RECV_BATCHES: AtomicU64 = AtomicU64::new(0);

/** @brief 그 호출들이 실제로 가져온 데이터그램 수. */
static RECV_DATAGRAMS: AtomicU64 = AtomicU64::new(0);

/**
 * @brief 배치 한 번이 실제로 몇 개를 가져왔는지 센다.
 * @details MSG_WAITFORONE은 하나만 도착해도 깨어난다. 부하가 몰릴 때 배치가 실제로
 *          커지는지는 재 봐야만 알 수 있고, 평균이 1에 가까우면 배치화가 시스템 호출을
 *          전혀 줄이지 못하고 있다는 뜻이다.
 * @note 데이터그램마다가 아니라 배치마다 두 번 더한다. 핫패스 비용은 무시할 수준이다.
 */
#[cfg(target_os = "linux")]
fn note_recv_batch(datagrams: u64) {
    RECV_BATCHES.fetch_add(1, Ordering::Relaxed);
    RECV_DATAGRAMS.fetch_add(datagrams, Ordering::Relaxed);
}

/** @brief recvmmsg 호출 수와 그것이 가져온 데이터그램 수. 지표 노출용이다. */
pub fn recv_batch_counters() -> (u64, u64) {
    (
        RECV_BATCHES.load(Ordering::Relaxed),
        RECV_DATAGRAMS.load(Ordering::Relaxed),
    )
}

/** @brief UDP 응답 크기 상한. 경로 단편화를 피하는 값이며 EDNS 협상값보다 우선한다. */
const SERVER_UDP_MAX: usize = 1232;

/**
 * @brief EDNS 를 쓰지 않은 UDP 질의에 답할 수 있는 크기.
 * @details RFC 1035가 정한 값이다. 넘으면 잘라서 TC 를 설정해야 하며, 이 상한을
 *          모르는 경로가 생기면 클라이언트가 받지 못하는 크기가 그대로 나간다.
 */
pub const NON_EDNS_UDP_MAX: usize = 512;

/** @brief 받아들일 UDP 질의 크기 상한. 이보다 큰 데이터그램은 파싱하지 않고 버린다. */
const MAX_UDP_REQUEST: usize = 4096;

/** @brief 워커가 소켓을 독점할 때의 배치 크기. */
const FULL_UDP_BATCH: usize = 32;

/** @brief 여러 워커가 소켓을 나눠 읽을 때의 배치 크기. */
const SHARED_UDP_BATCH: usize = 16;

/**
 * @brief 배치 크기를 정한다.
 * @details 소켓을 공유할 때 배치를 줄인다. 한 워커가 크게 퍼 가면 같은 소켓을 읽는 다른
 *          워커가 굶고, 그만큼 처리 지연이 한쪽에 몰린다.
 */
fn batch_size_for(workers: usize, cpus: usize) -> usize {
    if workers > cpus.max(1) {
        SHARED_UDP_BATCH
    } else {
        FULL_UDP_BATCH
    }
}

/** @brief 이 호스트의 코어 수를 반영한 배치 크기. */
pub(crate) fn worker_batch_size(workers: usize) -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    batch_size_for(workers, cpus)
}

/** @brief UDP 워커 진입점. 플랫폼에 맞는 루프로 갈라진다. */
pub fn worker<H: Handler>(
    sock: UdpSocket,
    handler: Arc<H>,
    shutdown: Arc<AtomicBool>,
    batch_size: usize,
) {
    #[cfg(target_os = "linux")]
    batch::worker(sock, handler, shutdown, batch_size);
    #[cfg(not(target_os = "linux"))]
    single_worker(sock, handler, shutdown, batch_size);
}

/**
 * @brief 데이터그램을 하나씩 처리하는 워커 루프.
 * @details 수신이 끝날 때마다 종료 표시를 본다. 유닉스는 수신 대기 한도로 주기적으로
 *          깨어나고, 윈도우는 종료할 때 서버가 보내는 데이터그램으로 깨어난다.
 */
#[cfg(not(target_os = "linux"))]
fn single_worker<H: Handler>(
    sock: UdpSocket,
    handler: Arc<H>,
    shutdown: Arc<AtomicBool>,
    _batch_size: usize,
) {
    let mut recv = [0u8; MAX_UDP_REQUEST + 1];
    let mut writer = Writer::with_limit(SERVER_UDP_MAX);

    while !shutdown.load(Ordering::Relaxed) {
        let (n, src) = match sock.recv_from(&mut recv) {
            Ok(v) => v,

            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,

            Err(error) => {
                record_recv_error(&error);
                continue;
            }
        };
        if n > MAX_UDP_REQUEST {
            continue;
        }

        if !process_datagram(
            handler.as_ref(),
            &recv[..n],
            src,
            Instant::now(),
            &mut writer,
        ) {
            continue;
        }

        if let Err(error) = sock.send_to(&writer.buf, src) {
            record_send_error(src, writer.buf.len(), &error);
        }
    }
}

/**
 * @brief 데이터그램 하나를 응답 와이어로 바꾼다. 두 워커 구현이 공유한다.
 *
 * @details 순서가 중요하다. 파싱하기 전에 와이어 고속 경로를 먼저 시도한다. 캐시
 *          히트를 파싱 비용 없이 내보내는 것이 이 경로의 존재 이유다.
 * @note 응답 비트가 선 패킷은 즉시 버린다. 그러지 않으면 두 서버가 서로의 응답에
 *       응답하며 무한히 주고받는 반사 루프가 만들어진다.
 * @note 패킷마다 장애 격리 경계를 둔다. 조작된 입력의 패닉이 워커를 죽이지 않는다.
 * @return 보낼 응답이 writer에 담겼으면 true.
 */
fn process_datagram<H: Handler>(
    handler: &H,
    packet: &[u8],
    src: std::net::SocketAddr,
    now: Instant,
    writer: &mut Writer,
) -> bool {
    writer.clear();
    if packet.len() > MAX_UDP_REQUEST {
        return false;
    }
    let handled = onetdns_core::isolation::catch_request(|| {
        if packet.len() < 12 || packet[2] & 0x80 != 0 {
            return false;
        }

        let ctx = RequestCtx {
            src,
            transport: Transport::Do53Udp,
            raw: Some(packet),
            client_id: None,

            authenticated: false,
            auth_identity: None,
        };

        match handler.handle_udp_wire(packet, &ctx, writer, now) {
            crate::WireDisposition::Respond => return !writer.buf.is_empty(),
            crate::WireDisposition::Drop => return false,
            crate::WireDisposition::Fallback => {}
        }

        let request = match Message::parse(packet) {
            Ok(m) => m,
            Err(_) => {
                let Some(response) = handler.handle_unparsable(packet, &ctx) else {
                    return false;
                };
                return response.try_encode_into(writer).is_ok() && !writer.buf.is_empty();
            }
        };
        let response = match handler.handle(&request, &ctx) {
            Some(response) => response,
            None => return false,
        };
        encode_limited(&request, &response, writer);
        true
    });
    handled == Ok(true)
}

/** @brief 종료 시 진행 중인 교환을 마무리하며 기다릴 최대 시간. */
#[cfg(unix)]
const REACTOR_DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_millis(1000);

/**
 * @brief 이벤트 구동 UDP 워커.
 *
 * @details 한 루프에서 리스너와 진행 중인 업스트림 교환들을 함께 폴링한다. 새 질의는 캐시
 *          히트면 즉시 응답하고, 아니면 리액터에 제출해 응답 없이 다음으로 넘어간다.
 *          블로킹 워커와 달리 업스트림을 기다리는 동안 스레드가 멈추지 않는다.
 * @note 한 번에 받아들이는 질의를 64개로 끊는다. 무한정 받으면 이미 제출된 교환의
 *       폴링이 계속 밀려 응답이 늦어진다. 리액터에 슬롯이 없어도 즉시 멈춘다.
 */
#[cfg(unix)]
pub(crate) fn reactor_worker<H: Handler>(
    sock: UdpSocket,
    handler: Arc<H>,
    shutdown: Arc<AtomicBool>,
) {
    use std::os::fd::AsRawFd;
    if let Err(error) = sock.set_nonblocking(true) {
        onetdns_core::error!(event = "dns.reactor_nonblocking_failed", %error, "Could not make the receive socket non-blocking; the reactor may stall on a single query");
    }
    let listener_fd = sock.as_raw_fd();
    let mut recv = [0u8; MAX_UDP_REQUEST + 1];
    let mut writer = Writer::with_limit(SERVER_UDP_MAX);
    let mut fds: Vec<libc::pollfd> = Vec::new();
    let mut map: Vec<usize> = Vec::new();
    let mut outq: Vec<(std::net::SocketAddr, Vec<u8>)> = Vec::new();

    while !shutdown.load(Ordering::Relaxed) {
        fds.clear();
        map.clear();
        fds.push(libc::pollfd {
            fd: listener_fd,
            events: libc::POLLIN,
            revents: 0,
        });
        handler.reactor_collect(&mut fds, &mut map);

        let now = Instant::now();

        let timeout = handler.reactor_deadline_ms(now).clamp(1, 500);
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        let now = Instant::now();

        if rc > 0 && fds[0].revents & libc::POLLIN != 0 {
            for _ in 0..64 {
                if !handler.reactor_has_capacity() {
                    break;
                }
                let (n, src) = match sock.recv_from(&mut recv) {
                    Ok(v) => v,
                    Err(error) => {
                        record_recv_error(&error);
                        break;
                    }
                };
                if n > MAX_UDP_REQUEST {
                    continue;
                }
                let packet = &recv[..n];

                if packet.len() < 12 || packet[2] & 0x80 != 0 {
                    continue;
                }
                let ctx = RequestCtx {
                    src,
                    transport: Transport::Do53Udp,
                    raw: Some(packet),
                    client_id: None,
                    authenticated: false,
                    auth_identity: None,
                };
                writer.clear();

                match handler.handle_udp_wire_hit(packet, &ctx, &mut writer, now) {
                    crate::WireDisposition::Respond => {
                        if !writer.buf.is_empty() {
                            send_or_record(&sock, &writer.buf, src);
                        }
                        continue;
                    }
                    crate::WireDisposition::Drop => continue,
                    crate::WireDisposition::Fallback => {}
                }
                writer.clear();
                match handler.reactor_submit(packet, &ctx, &mut writer, now) {
                    crate::ReactorDisposition::Respond => {
                        if !writer.buf.is_empty() {
                            send_or_record(&sock, &writer.buf, src);
                        }
                    }
                    crate::ReactorDisposition::Drop | crate::ReactorDisposition::Submitted => {}
                    crate::ReactorDisposition::Fallback => {
                        if process_datagram(handler.as_ref(), packet, src, now, &mut writer) {
                            send_or_record(&sock, &writer.buf, src);
                        }
                    }
                }
            }
        }

        if rc > 0 {
            handler.reactor_pump(&fds, 1, &map, now, &mut outq);
        }
        handler.reactor_tick(now, &mut outq);
        for (dst, wire) in outq.drain(..) {
            send_or_record(&sock, &wire, dst);
        }
    }

    let drain_until = Instant::now() + REACTOR_DRAIN_BUDGET;

    let mut idle_passes = 0u32;
    while Instant::now() < drain_until {
        fds.clear();
        map.clear();
        handler.reactor_collect(&mut fds, &mut map);
        let now = Instant::now();
        let remaining = (drain_until - now).as_millis() as i32;
        if fds.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(1));
        } else {
            let timeout = handler
                .reactor_deadline_ms(now)
                .clamp(1, 50)
                .min(remaining.max(1));
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
            if rc > 0 {
                handler.reactor_pump(&fds, 0, &map, Instant::now(), &mut outq);
            }
        }
        handler.reactor_tick(Instant::now(), &mut outq);
        let produced = !outq.is_empty();
        for (dst, wire) in outq.drain(..) {
            send_or_record(&sock, &wire, dst);
        }
        if fds.is_empty() && !produced {
            idle_passes += 1;
            if idle_passes >= 50 {
                break;
            }
        } else {
            idle_passes = 0;
        }
    }
}

/**
 * @brief 커널이 채운 주소 저장소를 Rust 주소 타입으로 바꾼다.
 * @safety ss_family를 먼저 확인한 뒤 그 계열의 구조체로만 재해석한다. 아는 계열이
 *         아니면 None을 돌려주고 아무것도 읽지 않는다.
 * @note 부르는 곳은 recvmmsg 와 sendmmsg 를 쓰는 batch 모듈뿐이고 그 모듈은 리눅스
 *       전용이다. unix 로 열어 두면 리눅스가 아닌 unix 에서 죽은 코드가 된다.
 */
#[cfg(target_os = "linux")]
fn decode_sockaddr(storage: &libc::sockaddr_storage) -> Option<std::net::SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    match libc::c_int::from(storage.ss_family) {
        libc::AF_INET => {
            let v4 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr))),
                u16::from_be(v4.sin_port),
            ))
        }
        libc::AF_INET6 => {
            let v6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                Ipv6Addr::from(v6.sin6_addr.s6_addr),
                u16::from_be(v6.sin6_port),
                v6.sin6_flowinfo,
                v6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/**
 * @brief 응답 전송 실패를 기록한다.
 * @note 2의 거듭제곱 번째에만 로그를 남긴다. 도달 불가 클라이언트가 대량으로 질의하면
 *       실패마다 로그를 쓰는 것 자체가 부하가 되기 때문이다.
 */
fn record_send_error(src: std::net::SocketAddr, bytes: usize, error: &std::io::Error) {
    let count = SEND_ERRORS.fetch_add(1, Ordering::Relaxed) + 1;

    if count.is_power_of_two() {
        onetdns_core::warn!(
            event = "dns.udp_response_send_failed",
            client = %src,
            bytes,
            %error,
            count,
            "Could not send UDP DNS response"
        );
    }
}

#[cfg(unix)]
/** @brief 응답을 보내고 실패는 표본만 기록한다. 리액터 경로도 같은 카운터를 쓰게 하려는 것이다. */
fn send_or_record(sock: &UdpSocket, wire: &[u8], dst: std::net::SocketAddr) {
    if let Err(error) = sock.send_to(wire, dst) {
        record_send_error(dst, wire.len(), &error);
    }
}

/**
 * @brief 수신 실패를 기록한다.
 * @note 소켓이 영영 망가지면 이 루프가 계속 헛돌기만 한다. 2의 거듭제곱 번째만 남겨
 *       그 상태를 알리되 로그가 부하가 되지 않게 한다.
 */
fn record_recv_error(error: &std::io::Error) {
    use std::io::ErrorKind;
    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
        return;
    }
    /** @brief 수신 실패 누적 수. */
    static RECV_ERRORS: AtomicU64 = AtomicU64::new(0);
    let count = RECV_ERRORS.fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::warn!(event = "dns.udp_recv_failed", %error, count, "Failed to receive UDP query");
    }
}

/**
 * @brief 리눅스 배치 입출력 워커.
 *
 * @details recvmmsg/sendmmsg로 데이터그램 여러 개를 시스템 호출 한 번에 처리한다.
 *          질의당 시스템 호출 수가 처리량의 지배 요인이라, 부하가 높을수록 이득이 커진다.
 * @note 버퍼·헤더 배열은 루프 밖에서 한 번만 잡고 계속 재사용한다. 배치마다 다시 만들면
 *       배치 이득을 할당 비용으로 되돌려준다.
 */
#[cfg(target_os = "linux")]
mod batch {
    use super::*;
    use std::net::UdpSocket;
    use std::os::unix::io::AsRawFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /** @brief 슬롯 하나의 수신 버퍼 크기. */
    const RECV_BUF: usize = MAX_UDP_REQUEST;

    /**
     * @brief 배치 수신·처리·전송 루프.
     * @note MSG_WAITFORONE으로 대기한다. 하나만 와도 깨어나므로 한산할 때 지연이 늘지
     *       않으면서, 몰릴 때는 배치가 자연히 커진다.
     * @safety 헤더가 가리키는 버퍼와 주소 저장소는 루프 전체에 살아 있고, 커널에 넘기는
     *         슬롯 수는 배열 길이를 넘지 않는다.
     */
    pub(super) fn worker<H: Handler>(
        sock: UdpSocket,
        handler: Arc<H>,
        shutdown: Arc<AtomicBool>,
        batch_size: usize,
    ) {
        debug_assert!(matches!(batch_size, SHARED_UDP_BATCH | FULL_UDP_BATCH));
        let fd = sock.as_raw_fd();
        let mut recv_bufs: Vec<Vec<u8>> = (0..batch_size).map(|_| vec![0u8; RECV_BUF]).collect();
        let mut names: Vec<libc::sockaddr_storage> = (0..batch_size)
            .map(|_| unsafe { std::mem::zeroed() })
            .collect();
        let mut recv_iovs: Vec<libc::iovec> = recv_bufs
            .iter_mut()
            .map(|buf| libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            })
            .collect();
        let mut recv_hdrs: Vec<libc::mmsghdr> = (0..batch_size)
            .map(|slot| {
                let mut hdr: libc::mmsghdr = unsafe { std::mem::zeroed() };
                hdr.msg_hdr.msg_name = (&mut names[slot] as *mut libc::sockaddr_storage).cast();
                hdr.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
                hdr.msg_hdr.msg_iov = &mut recv_iovs[slot];
                hdr.msg_hdr.msg_iovlen = 1;
                hdr
            })
            .collect();
        let mut writers: Vec<Writer> = (0..batch_size)
            .map(|_| Writer::with_limit(SERVER_UDP_MAX))
            .collect();
        let mut send_iovs: Vec<libc::iovec> = (0..batch_size)
            .map(|_| libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            })
            .collect();
        let mut send_hdrs: Vec<libc::mmsghdr> = (0..batch_size)
            .map(|_| unsafe { std::mem::zeroed() })
            .collect();
        while !shutdown.load(Ordering::Relaxed) {
            for hdr in &mut recv_hdrs {
                hdr.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
                hdr.msg_hdr.msg_flags = 0;
            }
            let received = unsafe {
                libc::recvmmsg(
                    fd,
                    recv_hdrs.as_mut_ptr(),
                    batch_size as libc::c_uint,
                    libc::MSG_WAITFORONE as _,
                    std::ptr::null_mut(),
                )
            };
            if received <= 0 {
                continue;
            }
            super::note_recv_batch(received as u64);

            let mut out = 0usize;

            let batch_now = Instant::now();
            for slot in 0..received as usize {
                if received_message_is_truncated(recv_hdrs[slot].msg_hdr.msg_flags) {
                    continue;
                }
                let len = (recv_hdrs[slot].msg_len as usize).min(RECV_BUF);
                let Some(src) = decode_sockaddr(&names[slot]) else {
                    continue;
                };
                let writer = &mut writers[out];
                if !process_datagram(
                    handler.as_ref(),
                    &recv_bufs[slot][..len],
                    src,
                    batch_now,
                    writer,
                ) {
                    continue;
                }
                send_iovs[out].iov_base = writer.buf.as_mut_ptr().cast();
                send_iovs[out].iov_len = writer.buf.len();
                send_hdrs[out].msg_hdr.msg_name =
                    (&mut names[slot] as *mut libc::sockaddr_storage).cast();
                send_hdrs[out].msg_hdr.msg_namelen = recv_hdrs[slot].msg_hdr.msg_namelen;
                send_hdrs[out].msg_hdr.msg_iov = &mut send_iovs[out];
                send_hdrs[out].msg_hdr.msg_iovlen = 1;
                out += 1;
            }

            let mut sent = 0usize;
            while sent < out {
                let r = unsafe {
                    libc::sendmmsg(
                        fd,
                        send_hdrs[sent..].as_mut_ptr(),
                        (out - sent) as libc::c_uint,
                        0,
                    )
                };
                if r > 0 {
                    sent += r as usize;
                    continue;
                }
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }

                let storage = unsafe {
                    &*(send_hdrs[sent].msg_hdr.msg_name as *const libc::sockaddr_storage)
                };
                if let Some(dst) = decode_sockaddr(storage) {
                    record_send_error(dst, send_iovs[sent].iov_len, &error);
                }
                sent += 1;
            }
        }
    }

    /**
     * @brief 수신 중 잘린 메시지인지.
     * @warning 잘린 질의에 답하면 안 된다. 뒷부분이 사라진 채로 해석되어 클라이언트가
     *          보내지 않은 질의에 응답하는 꼴이 된다.
     */
    pub(super) fn received_message_is_truncated(flags: libc::c_int) -> bool {
        flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
    }
}

/**
 * @brief 응답을 협상된 UDP 크기 안에 들어가도록 인코딩한다.
 *
 * @details 사다리를 순서대로 내려간다. 전체 → TC 비트를 설정한 축약 → 부가 섹션 제거 →
 *          질문까지 제거. 마지막 수단은 최소 SERVFAIL이라 인코딩이 반드시 성공한다.
 * @note pub인 이유는 wire 고속 경로가 같은 사다리를 재사용하기 때문이다. 두 경로가
 *       다른 축약 규칙을 쓰면 같은 질의가 경로에 따라 다른 크기의 응답을 받는다.
 * @invariant 이 함수를 마치면 writer.buf는 언제나 협상 한도 이하다.
 */
pub fn encode_limited(request: &Message, response: &Message, writer: &mut Writer) {
    encode_within(request, response, writer, max_udp(request));
}

/**
 * @brief 응답을 주어진 한도 안에 들어가도록 인코딩한다.
 *
 * @details encode_limited 와 같은 사다리를 쓰되 한도를 밖에서 받는다. DNSCrypt 는 협상된
 *          EDNS 크기가 아니라 질의 패킷 길이가 한도라, 그쪽에서 계산한 값을 넘겨 준다.
 * @param limit 인코딩 결과가 넘지 않아야 할 바이트 수.
 * @invariant 이 함수를 마치면 writer.buf는 언제나 limit 이하다.
 */
pub fn encode_within(request: &Message, response: &Message, writer: &mut Writer, limit: usize) {
    if encode_response(response, writer) && writer.buf.len() <= limit {
        return;
    }

    let mut response = truncated(request, response);
    if encode_response(&response, writer) && writer.buf.len() <= limit {
        return;
    }

    response.additionals.clear();
    if encode_response(&response, writer) && writer.buf.len() <= limit {
        return;
    }

    response.questions.clear();
    if !encode_response(&response, writer) {
        let fallback = crate::encoding_failure_response(request);
        let encoded = encode_response(&fallback, writer);
        debug_assert!(encoded, "The fixed minimal SERVFAIL must always encode");
    }
    debug_assert!(writer.buf.len() <= limit);
}

/** @brief 버퍼를 비우고 응답을 인코딩한다. 성공 여부만 돌려준다. */
fn encode_response(response: &Message, writer: &mut Writer) -> bool {
    writer.clear();
    response.try_encode_into(writer).is_ok()
}

/**
 * @brief 이 질의에 허용되는 UDP 응답 크기.
 * @details EDNS가 없으면 512다. 클라이언트가 더 큰 값을 광고해도 서버 상한으로 자른다.
 *          큰 응답은 경로에서 조각나 유실되기 쉽고 증폭 계수도 커진다.
 */
fn max_udp(req: &Message) -> usize {
    req.opt()
        .and_then(Edns::from_record)
        .map(|e| usize::from(e.udp_payload.max(NON_EDNS_UDP_MAX as u16)).min(SERVER_UDP_MAX))
        .unwrap_or(NON_EDNS_UDP_MAX)
}

/**
 * @brief TC 비트를 설정한 축약 응답을 만든다. 클라이언트가 TCP로 재시도하게 하는 신호다.
 * @details 헤더 플래그와 rcode는 원래 응답에서 그대로 가져온다. 축약은 크기 문제일 뿐
 *          판정이 바뀐 것이 아니므로, 재시도한 클라이언트가 다른 결론을 보면 안 된다.
 */
fn truncated(req: &Message, original: &Message) -> Message {
    let mut m = Message::default();
    m.header.id = req.header.id;
    m.header.response = true;
    m.header.opcode = req.header.opcode;
    m.header.authoritative = original.header.authoritative;
    m.header.recursion_desired = req.header.recursion_desired;
    m.header.recursion_available = original.header.recursion_available;
    m.header.authentic_data = original.header.authentic_data;
    m.header.checking_disabled = req.header.checking_disabled;
    m.header.rcode = original.header.rcode;
    m.header.truncated = true;
    m.questions = req.questions.clone();
    if let Some(opt) = original.opt() {
        m.additionals.push(opt.clone());
    }
    m
}

#[cfg(test)]
/** @brief 잘림 처리와 크기 상한, 그리고 빈 응답을 내보내지 않는지. */
mod tests {
    use super::*;
    use onetdns_proto::{Edns, Name, Question, RecordType};

    /** @brief 바이트 경로 호출 수를 세는 테스트용 핸들러. */
    struct CountingWireHandler(AtomicU64);

    impl Handler for CountingWireHandler {
        /** @brief 보통 경로로는 답하지 않는다. */
        fn handle(&self, _request: &Message, _ctx: &RequestCtx<'_>) -> Option<Message> {
            None
        }

        /** @brief 호출 횟수를 세고 그대로 반환한다. */
        fn handle_udp_wire(
            &self,
            _packet: &[u8],
            _ctx: &RequestCtx<'_>,
            _out: &mut Writer,
            _now: Instant,
        ) -> crate::WireDisposition {
            self.0.fetch_add(1, Ordering::Relaxed);
            crate::WireDisposition::Drop
        }
    }

    /** @brief 읽지 못한 질의에 FORMERR로 답하는 테스트용 핸들러. */
    struct FormErrHandler;

    impl Handler for FormErrHandler {
        /** @brief 보통 경로는 쓰지 않는다. */
        fn handle(&self, _request: &Message, _ctx: &RequestCtx<'_>) -> Option<Message> {
            None
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

    #[test]
    /**
     * @brief 파싱에 실패한 데이터그램을 조용히 버리지 않고 핸들러에 넘기는지.
     * @details 넘기지 않으면 클라이언트에게는 무응답이고, RFC 8906 이 지목한 그 실패다.
     *          핸들러 단위 테스트는 이 배선을 보지 못하므로 워커 쪽에서 따로 확인한다.
     */
    fn an_unparsable_datagram_reaches_the_handler_instead_of_being_dropped() {
        // 질문 하나를 적고 둘이라고 말하는 헤더다.
        let mut packet = vec![0u8; 12];
        packet[0..2].copy_from_slice(&0x0abcu16.to_be_bytes());
        packet[4..6].copy_from_slice(&2u16.to_be_bytes());
        packet.extend_from_slice(&[2, b'n', b's', 0, 0, 1, 0, 1]);
        assert!(Message::parse(&packet).is_err(), "대조군이 무효입니다");

        let mut writer = Writer::with_limit(SERVER_UDP_MAX);
        assert!(process_datagram(
            &FormErrHandler,
            &packet,
            "192.0.2.1:53000".parse().unwrap(),
            Instant::now(),
            &mut writer,
        ));
        let response = Message::parse(&writer.buf).expect("응답을 읽지 못했습니다");
        assert_eq!(response.header.id, 0x0abc);
        assert_eq!(response.header.rcode, 1);
    }

    #[test]
    /** @brief 워커가 코어보다 많을 때만 배치를 줄이는지. */
    fn udp_batch_shrinks_only_when_workers_outnumber_cpus() {
        assert_eq!(batch_size_for(1, 1), FULL_UDP_BATCH);
        assert_eq!(batch_size_for(4, 4), FULL_UDP_BATCH);
        assert_eq!(batch_size_for(5, 4), SHARED_UDP_BATCH);
        assert_eq!(batch_size_for(112, 28), SHARED_UDP_BATCH);
        assert_eq!(batch_size_for(1, 0), FULL_UDP_BATCH);
    }

    #[test]
    /** @brief 지나치게 큰 데이터그램을 처리 전에 버리는지. */
    fn oversized_udp_payload_is_dropped_before_the_wire_handler() {
        let handler = CountingWireHandler(AtomicU64::new(0));
        let packet = vec![0u8; MAX_UDP_REQUEST + 1];
        let mut writer = Writer::with_limit(SERVER_UDP_MAX);

        assert!(!process_datagram(
            &handler,
            &packet,
            "192.0.2.1:53000".parse().unwrap(),
            Instant::now(),
            &mut writer,
        ));
        assert_eq!(handler.0.load(Ordering::Relaxed), 0);

        let max_sized_packet = vec![0u8; MAX_UDP_REQUEST];
        assert!(!process_datagram(
            &handler,
            &max_sized_packet,
            "192.0.2.1:53000".parse().unwrap(),
            Instant::now(),
            &mut writer,
        ));
        assert_eq!(handler.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    /** @brief 잘라 낸 응답이 약속한 크기를 넘지 않는지. 넘으면 상대가 받지 못한다. */
    fn truncated_response_never_exceeds_negotiated_udp_limit() {
        let mut request = Message::default();
        request.header.id = 7;
        for index in 0..40 {
            request.questions.push(Question {
                name: Name::from_str(&format!(
                    "question-{index:02}-aaaaaaaaaaaaaaaa.unique-{index:02}-bbbbbbbbbbbbbbbb"
                ))
                .unwrap(),
                qtype: RecordType::A,
                qclass: onetdns_proto::DnsClass::IN,
            });
        }
        let mut response = request.clone();
        response.header.response = true;
        response.answers = Vec::new();
        let mut writer = Writer::with_limit(SERVER_UDP_MAX);
        encode_limited(&request, &response, &mut writer);

        assert!(writer.buf.len() <= 512);
        let parsed = Message::parse(&writer.buf).unwrap();
        assert!(parsed.header.truncated);
        assert!(parsed.questions.is_empty(), "과대 question section 제거");
    }

    #[test]
    /** @brief 잘라 내도 작은 확장 기록은 남기는지. */
    fn truncated_response_preserves_small_opt() {
        let mut request =
            Message::query(9, Name::from_str("large.example").unwrap(), RecordType::A);
        request.additionals.push(
            Edns {
                udp_payload: 1232,
                dnssec_ok: true,
                ..Default::default()
            }
            .try_to_record()
            .unwrap(),
        );
        let mut response = request.clone();
        response.header.response = true;
        response.header.truncated = false;
        response.additionals.push(onetdns_proto::Record::new(
            Name::root(),
            0,
            onetdns_proto::RData::Unknown(16, vec![0; 2000]),
        ));
        let mut writer = Writer::with_limit(SERVER_UDP_MAX);
        encode_limited(&request, &response, &mut writer);

        assert!(writer.buf.len() <= 1232);
        let parsed = Message::parse(&writer.buf).unwrap();
        assert!(parsed.header.truncated);
        assert!(parsed.opt().is_some(), "작은 OPT 협상 정보 유지");
    }

    #[test]
    /** @brief 적을 수 없는 응답에 빈 데이터그램을 보내지 않는지. */
    fn invalid_internal_response_never_emits_an_empty_datagram() {
        let request = Message::query(
            11,
            Name::from_str("invalid.example").unwrap(),
            RecordType::A,
        );
        let mut response = request.clone();
        response.header.response = true;
        response.header.rcode = 0x1fff;
        let mut writer = Writer::with_limit(SERVER_UDP_MAX);

        encode_limited(&request, &response, &mut writer);

        let parsed = Message::parse(&writer.buf).unwrap();
        assert!(parsed.header.response);
        assert_eq!(parsed.header.rcode, onetdns_proto::ResponseCode::ServFail.0);
        assert!(writer.buf.len() <= 512);
    }

    #[cfg(target_os = "linux")]
    #[test]
    /** @brief 묶어 받을 때 잘린 것을 걸러 내는지. */
    fn linux_batch_receiver_rejects_truncated_payload_or_control_data() {
        assert!(!batch::received_message_is_truncated(0));
        assert!(batch::received_message_is_truncated(libc::MSG_TRUNC));
        assert!(batch::received_message_is_truncated(libc::MSG_CTRUNC));
        assert!(batch::received_message_is_truncated(
            libc::MSG_TRUNC | libc::MSG_CTRUNC
        ));
    }
}
