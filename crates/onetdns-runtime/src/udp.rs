//! Do53 UDP workers. On Linux recvmmsg and sendmmsg move several datagrams per system call; other
//! platforms use a single-datagram loop. Both share `process_datagram`, so the order of the
//! pre-parse fast paths cannot drift between them.

#[cfg(not(target_os = "linux"))]
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use onetdns_proto::{Edns, Message, Writer};

use crate::{Handler, RequestCtx, Transport};

/// Only samples are logged to avoid log floods; the total accumulates here.
static SEND_ERRORS: AtomicU64 = AtomicU64::new(0);

static RECV_BATCHES: AtomicU64 = AtomicU64::new(0);

static RECV_DATAGRAMS: AtomicU64 = AtomicU64::new(0);

/// MSG_WAITFORONE wakes on a single datagram, so whether batches actually grow under load can only
/// be measured; an average near 1 means batching saves no system calls. Two additions per batch,
/// not per datagram, cost nothing on the hot path.
#[cfg(target_os = "linux")]
fn note_recv_batch(datagrams: u64) {
    RECV_BATCHES.fetch_add(1, Ordering::Relaxed);
    RECV_DATAGRAMS.fetch_add(datagrams, Ordering::Relaxed);
}

pub fn recv_batch_counters() -> (u64, u64) {
    (
        RECV_BATCHES.load(Ordering::Relaxed),
        RECV_DATAGRAMS.load(Ordering::Relaxed),
    )
}

/// Avoids fragmentation on the path and takes precedence over the EDNS size the client offers.
const SERVER_UDP_MAX: usize = 1232;

/// RFC 1035 limit for queries without EDNS. A larger answer must be truncated with TC set; a path
/// that ignores this sends answers the client cannot receive.
pub const NON_EDNS_UDP_MAX: usize = 512;

/// Larger datagrams are dropped unparsed.
const MAX_UDP_REQUEST: usize = 4096;

const FULL_UDP_BATCH: usize = 32;

const SHARED_UDP_BATCH: usize = 16;

/// Smaller batches when workers share a socket: one worker grabbing a big batch starves the others
/// reading it and piles latency on one side.
fn batch_size_for(workers: usize, cpus: usize) -> usize {
    if workers > cpus.max(1) {
        SHARED_UDP_BATCH
    } else {
        FULL_UDP_BATCH
    }
}

pub(crate) fn worker_batch_size(workers: usize) -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    batch_size_for(workers, cpus)
}

/// In a reactor server the worker switches between the reactor loop and the synchronous loop
/// whenever the handler's answer changes. That answer changes when the config is replaced, so
/// reading it once at thread start would keep queries away from a reactor enabled later. `reactor`
/// is ignored outside Unix.
pub fn worker<H: Handler>(
    sock: UdpSocket,
    handler: Arc<H>,
    shutdown: Arc<AtomicBool>,
    batch_size: usize,
    reactor: bool,
) {
    #[cfg(unix)]
    if reactor {
        while !shutdown.load(Ordering::Relaxed) {
            if handler.reactor_active() {
                reactor_worker(&sock, handler.as_ref(), &shutdown);
            } else {
                blocking_worker(&sock, handler.as_ref(), &shutdown, batch_size, || {
                    handler.reactor_active()
                });
            }
        }
        return;
    }
    #[cfg(not(unix))]
    let _ = reactor;
    blocking_worker(&sock, handler.as_ref(), &shutdown, batch_size, || false);
}

/// Returns when `leave` returns true.
fn blocking_worker<H: Handler>(
    sock: &UdpSocket,
    handler: &H,
    shutdown: &AtomicBool,
    batch_size: usize,
    leave: impl Fn() -> bool,
) {
    #[cfg(target_os = "linux")]
    batch::worker(sock, handler, shutdown, batch_size, leave);
    #[cfg(not(target_os = "linux"))]
    single_worker(sock, handler, shutdown, batch_size, leave);
}

/// Checks the shutdown flag and `leave` after every receive. Unix wakes up on the receive timeout;
/// Windows wakes on the datagram the server sends at shutdown.
#[cfg(not(target_os = "linux"))]
fn single_worker<H: Handler>(
    sock: &UdpSocket,
    handler: &H,
    shutdown: &AtomicBool,
    _batch_size: usize,
    leave: impl Fn() -> bool,
) {
    let mut recv = [0u8; MAX_UDP_REQUEST + 1];
    let mut writer = Writer::with_limit(SERVER_UDP_MAX);

    while !shutdown.load(Ordering::Relaxed) && !leave() {
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

        handler.begin_round();
        if process_datagram(handler, &recv[..n], src, Instant::now(), &mut writer) {
            if let Err(error) = sock.send_to(&writer.buf, src) {
                record_send_error(src, writer.buf.len(), &error);
            }
        }
        handler.end_round();
    }
}

/// The wire fast path runs before parsing: sending cache hits without parsing is why it exists.
/// Packets with the response bit set are dropped at once, or two servers could answer each other's
/// responses forever. Each packet runs inside a fault isolation boundary, so a panic from crafted
/// input does not kill the worker. Returns true when `writer` holds a response to send.
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

/// Longest wait at shutdown for exchanges in progress to finish.
#[cfg(unix)]
const REACTOR_DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_millis(1000);

/// Polls the listener and the upstream exchanges in progress in one loop. A new query is answered
/// at once on a cache hit and otherwise submitted, and the loop moves on; unlike the blocking
/// worker, the thread never stalls on upstream. When the handler turns the reactor off, the socket
/// goes back to blocking and the function returns.
///
/// At most 64 queries are accepted per round, or polling of submitted exchanges would keep
/// slipping; it also stops at once when the reactor has no free slot.
///
/// Receives and sends do not block, but the socket itself stays blocking: its mode is shared by
/// every handle to it, including the synchronous workers and a process the socket was handed to.
#[cfg(unix)]
fn reactor_worker<H: Handler>(sock: &UdpSocket, handler: &H, shutdown: &AtomicBool) {
    use std::os::fd::AsRawFd;
    let listener_fd = sock.as_raw_fd();
    let mut recv = [0u8; MAX_UDP_REQUEST + 1];
    let mut writer = Writer::with_limit(SERVER_UDP_MAX);
    let mut fds: Vec<libc::pollfd> = Vec::new();
    let mut map: Vec<usize> = Vec::new();
    let mut outq: Vec<(std::net::SocketAddr, Vec<u8>)> = Vec::new();

    while !shutdown.load(Ordering::Relaxed) {
        if !handler.reactor_active() {
            return;
        }
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

        handler.begin_round();
        if rc > 0 && fds[0].revents & libc::POLLIN != 0 {
            for _ in 0..64 {
                if !handler.reactor_has_capacity() {
                    break;
                }
                let (n, src) = match recv_from_now(sock, &mut recv) {
                    Ok(v) => v,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
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
                            send_or_record(sock, &writer.buf, src);
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
                            send_or_record(sock, &writer.buf, src);
                        }
                    }
                    crate::ReactorDisposition::Drop | crate::ReactorDisposition::Submitted => {}
                    crate::ReactorDisposition::Fallback => {
                        if process_datagram(handler, packet, src, now, &mut writer) {
                            send_or_record(sock, &writer.buf, src);
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
            send_or_record(sock, &wire, dst);
        }
        handler.end_round();
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
            send_or_record(sock, &wire, dst);
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

#[cfg(unix)]
fn decode_sockaddr(storage: &libc::sockaddr_storage) -> Option<std::net::SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    match libc::c_int::from(storage.ss_family) {
        libc::AF_INET => {
            // SAFETY: ss_family says the storage holds a sockaddr_in.
            let v4 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr))),
                u16::from_be(v4.sin_port),
            ))
        }
        libc::AF_INET6 => {
            // SAFETY: ss_family says the storage holds a sockaddr_in6.
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

/// Logs only every power-of-two failure: an unreachable client sending many queries would otherwise
/// turn logging into load.
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
/// So the reactor path shares the same counters.
fn send_or_record(sock: &UdpSocket, wire: &[u8], dst: std::net::SocketAddr) {
    if let Err(error) = send_to_now(sock, wire, dst) {
        record_send_error(dst, wire.len(), &error);
    }
}

/// `recv_from` that fails with `WouldBlock` instead of waiting, without making the socket
/// non-blocking.
#[cfg(unix)]
fn recv_from_now(
    sock: &UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr)> {
    use std::os::fd::AsRawFd;
    // SAFETY: all-zero bytes are a valid sockaddr_storage.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: `buf` and `storage` outlive the call and their sizes are passed with them.
    let n = unsafe {
        libc::recvfrom(
            sock.as_raw_fd(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            libc::MSG_DONTWAIT,
            (&mut storage as *mut libc::sockaddr_storage).cast(),
            &mut len,
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let src = decode_sockaddr(&storage)
        .ok_or_else(|| std::io::Error::other("datagram from an address that is not IP"))?;
    Ok((n as usize, src))
}

/// `send_to` that fails with `WouldBlock` instead of waiting, without making the socket
/// non-blocking.
#[cfg(unix)]
fn send_to_now(sock: &UdpSocket, wire: &[u8], dst: std::net::SocketAddr) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let (storage, len) = encode_sockaddr(dst);
    // SAFETY: `wire` and `storage` outlive the call and their sizes are passed with them.
    let n = unsafe {
        libc::sendto(
            sock.as_raw_fd(),
            wire.as_ptr().cast(),
            wire.len(),
            libc::MSG_DONTWAIT,
            (&storage as *const libc::sockaddr_storage).cast(),
            len,
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn encode_sockaddr(addr: std::net::SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: all-zero bytes are a valid sockaddr_storage.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        std::net::SocketAddr::V4(v4) => {
            // SAFETY: sockaddr_storage is large enough and aligned for any socket address.
            let sin = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr = libc::in_addr {
                s_addr: u32::from(*v4.ip()).to_be(),
            };
            let len = std::mem::size_of::<libc::sockaddr_in>();
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            {
                sin.sin_len = len as u8;
            }
            (storage, len as libc::socklen_t)
        }
        std::net::SocketAddr::V6(v6) => {
            // SAFETY: sockaddr_storage is large enough and aligned for any socket address.
            let sin6 = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_flowinfo = v6.flowinfo();
            sin6.sin6_addr = libc::in6_addr {
                s6_addr: v6.ip().octets(),
            };
            sin6.sin6_scope_id = v6.scope_id();
            let len = std::mem::size_of::<libc::sockaddr_in6>();
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            {
                sin6.sin6_len = len as u8;
            }
            (storage, len as libc::socklen_t)
        }
    }
}

/// A socket broken for good would leave this loop spinning; logging every power-of-two failure
/// reports that without the log becoming load.
fn record_recv_error(error: &std::io::Error) {
    use std::io::ErrorKind;
    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
        return;
    }
    static RECV_ERRORS: AtomicU64 = AtomicU64::new(0);
    let count = RECV_ERRORS.fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::warn!(event = "dns.udp_recv_failed", %error, count, "Failed to receive UDP query");
    }
}

/// recvmmsg and sendmmsg handle several datagrams per system call. System calls per query dominate
/// throughput, so the gain grows with load. Buffers and header arrays are allocated once outside
/// the loop and reused; rebuilding them per batch would spend the gain on allocation.
#[cfg(target_os = "linux")]
mod batch {
    use super::*;
    use std::net::UdpSocket;
    use std::os::unix::io::AsRawFd;
    use std::sync::atomic::{AtomicBool, Ordering};

    const RECV_BUF: usize = MAX_UDP_REQUEST;

    /// Checks the shutdown flag and `leave` after every batch is sent. MSG_WAITFORONE wakes on a
    /// single datagram, so latency does not grow when idle while batches grow under load.
    pub(super) fn worker<H: Handler>(
        sock: &UdpSocket,
        handler: &H,
        shutdown: &AtomicBool,
        batch_size: usize,
        leave: impl Fn() -> bool,
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
        while !shutdown.load(Ordering::Relaxed) && !leave() {
            for hdr in &mut recv_hdrs {
                hdr.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
                hdr.msg_hdr.msg_flags = 0;
            }
            // SAFETY: the headers point at buffers and address storage that live for the whole
            // loop, and the slot count never exceeds the array length.
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

            handler.begin_round();
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
                if !process_datagram(handler, &recv_bufs[slot][..len], src, batch_now, writer) {
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
                // SAFETY: the first `out` headers point at live writer buffers and names.
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

                // SAFETY: msg_name was set to a live entry of `names` above.
                let storage = unsafe {
                    &*(send_hdrs[sent].msg_hdr.msg_name as *const libc::sockaddr_storage)
                };
                if let Some(dst) = decode_sockaddr(storage) {
                    record_send_error(dst, send_iovs[sent].iov_len, &error);
                }
                sent += 1;
            }
            handler.end_round();
        }
    }

    /// A truncated query must not be answered: parsed without its tail, it would be a query the
    /// client never sent.
    pub(super) fn received_message_is_truncated(flags: libc::c_int) -> bool {
        flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
    }
}

/// Steps down a ladder: full, truncated with TC, without the additional section, without the
/// question. The last resort is a minimal SERVFAIL, so encoding always succeeds. Public because the
/// wire fast path reuses the same ladder; different truncation rules would give the same query
/// different response sizes by path. `writer.buf` never exceeds the negotiated limit afterwards.
pub fn encode_limited(request: &Message, response: &Message, writer: &mut Writer) {
    encode_within(request, response, writer, max_udp(request));
}

/// The same ladder with the limit given by the caller: DNSCrypt limits by the query packet length,
/// not the negotiated EDNS size. `writer.buf` never exceeds `limit` afterwards.
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

fn encode_response(response: &Message, writer: &mut Writer) -> bool {
    writer.clear();
    response.try_encode_into(writer).is_ok()
}

/// 512 without EDNS. A larger size the client advertises is capped at the server limit: large
/// responses fragment and get lost on the path, and raise the amplification factor.
fn max_udp(req: &Message) -> usize {
    req.opt()
        .and_then(Edns::from_record)
        .map(|e| usize::from(e.udp_payload.max(NON_EDNS_UDP_MAX as u16)).min(SERVER_UDP_MAX))
        .unwrap_or(NON_EDNS_UDP_MAX)
}

/// Sets TC so the client retries over TCP. Header flags and rcode come from the original response:
/// truncation is a size issue, not a different verdict, so the retry must not see another outcome.
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
mod tests {
    use super::*;
    use onetdns_proto::{Edns, Name, Question, RecordType};

    struct CountingWireHandler(AtomicU64);

    impl Handler for CountingWireHandler {
        fn handle(&self, _request: &Message, _ctx: &RequestCtx<'_>) -> Option<Message> {
            None
        }

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

    struct FormErrHandler;

    impl Handler for FormErrHandler {
        fn handle(&self, _request: &Message, _ctx: &RequestCtx<'_>) -> Option<Message> {
            None
        }

        fn handle_unparsable(&self, packet: &[u8], _ctx: &RequestCtx<'_>) -> Option<Message> {
            let mut response = Message::default();
            response.header.id = u16::from_be_bytes([packet[0], packet[1]]);
            response.header.response = true;
            response.header.rcode = 1;
            Some(response)
        }
    }

    #[test]
    /// Without this the client gets no response, the failure RFC 8906 points out. Handler unit
    /// tests cannot see this wiring, so the worker side is checked here.
    fn an_unparsable_datagram_reaches_the_handler_instead_of_being_dropped() {
        // A header that announces two questions but carries one.
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
    fn udp_batch_shrinks_only_when_workers_outnumber_cpus() {
        assert_eq!(batch_size_for(1, 1), FULL_UDP_BATCH);
        assert_eq!(batch_size_for(4, 4), FULL_UDP_BATCH);
        assert_eq!(batch_size_for(5, 4), SHARED_UDP_BATCH);
        assert_eq!(batch_size_for(112, 28), SHARED_UDP_BATCH);
        assert_eq!(batch_size_for(1, 0), FULL_UDP_BATCH);
    }

    #[test]
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
    fn linux_batch_receiver_rejects_truncated_payload_or_control_data() {
        assert!(!batch::received_message_is_truncated(0));
        assert!(batch::received_message_is_truncated(libc::MSG_TRUNC));
        assert!(batch::received_message_is_truncated(libc::MSG_CTRUNC));
        assert!(batch::received_message_is_truncated(
            libc::MSG_TRUNC | libc::MSG_CTRUNC
        ));
    }
}
