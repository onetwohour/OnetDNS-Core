//! Winsock calls std does not expose, through the ws2_32 that std already links. Each takes a socket
//! handle the caller owns.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

pub(crate) const SOCK_STREAM: i32 = 1;
pub(crate) const SOCK_DGRAM: i32 = 2;
pub(crate) const IPPROTO_TCP: i32 = 6;
pub(crate) const IPPROTO_UDP: i32 = 17;
pub(crate) const IPPROTO_IPV6: i32 = 41;
pub(crate) const IPV6_V6ONLY: i32 = 27;
pub(crate) const SOL_SOCKET: i32 = 0xffff;
pub(crate) const SO_RANDOMIZE_PORT: i32 = 0x3005;

const AF_INET: i32 = 2;
const AF_INET6: i32 = 23;
const INVALID_SOCKET: usize = usize::MAX;
const WSA_FLAG_OVERLAPPED: u32 = 0x01;
const WSA_FLAG_NO_HANDLE_INHERIT: u32 = 0x80;
const WSANOTINITIALISED: i32 = 10_093;
/// The backlog std's `TcpListener::bind` uses.
const LISTEN_BACKLOG: i32 = 128;

/// Room for a `SOCKADDR_IN6`, the larger of the two.
#[repr(C, align(8))]
struct RawSockAddr([u8; 28]);

#[link(name = "ws2_32")]
unsafe extern "system" {
    fn WSASocketW(
        af: i32,
        kind: i32,
        protocol: i32,
        protocol_info: *mut core::ffi::c_void,
        group: u32,
        flags: u32,
    ) -> usize;
    fn setsockopt(socket: usize, level: i32, name: i32, value: *const u8, len: i32) -> i32;
    #[link_name = "bind"]
    fn bind_socket(socket: usize, name: *const u8, len: i32) -> i32;
    #[link_name = "listen"]
    fn listen_socket(socket: usize, backlog: i32) -> i32;
    fn WSAIoctl(
        socket: usize,
        code: u32,
        input: *const core::ffi::c_void,
        input_len: u32,
        output: *mut core::ffi::c_void,
        output_len: u32,
        returned: *mut u32,
        overlapped: *mut core::ffi::c_void,
        completion: *mut core::ffi::c_void,
    ) -> i32;
}

/// Opens a socket for `addr`'s family the way std does: overlapped and not inherited by child
/// processes. The caller owns the handle.
pub(crate) fn open(addr: &SocketAddr, kind: i32, protocol: i32) -> io::Result<usize> {
    let family = if addr.is_ipv4() { AF_INET } else { AF_INET6 };
    let open = || {
        // SAFETY: every argument is a plain value or null.
        unsafe {
            WSASocketW(
                family,
                kind,
                protocol,
                core::ptr::null_mut(),
                0,
                WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
            )
        }
    };
    let mut handle = open();
    if handle == INVALID_SOCKET
        && io::Error::last_os_error().raw_os_error() == Some(WSANOTINITIALISED)
    {
        // std starts Winsock when it opens its first socket.
        drop(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)));
        handle = open();
    }
    if handle == INVALID_SOCKET {
        return Err(io::Error::last_os_error());
    }
    Ok(handle)
}

pub(crate) fn set_option(socket: usize, level: i32, name: i32, value: u32) -> io::Result<()> {
    // SAFETY: a live socket and a 4-byte option value that outlives the call.
    let rc = unsafe {
        setsockopt(
            socket,
            level,
            name,
            (&value as *const u32).cast(),
            std::mem::size_of::<u32>() as i32,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn bind(socket: usize, addr: SocketAddr) -> io::Result<()> {
    let mut raw = RawSockAddr([0; 28]);
    let len = match addr {
        SocketAddr::V4(v4) => {
            raw.0[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
            raw.0[2..4].copy_from_slice(&v4.port().to_be_bytes());
            raw.0[4..8].copy_from_slice(&v4.ip().octets());
            16
        }
        SocketAddr::V6(v6) => {
            raw.0[0..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
            raw.0[2..4].copy_from_slice(&v6.port().to_be_bytes());
            raw.0[4..8].copy_from_slice(&v6.flowinfo().to_ne_bytes());
            raw.0[8..24].copy_from_slice(&v6.ip().octets());
            raw.0[24..28].copy_from_slice(&v6.scope_id().to_ne_bytes());
            28
        }
    };
    // SAFETY: `raw` holds `len` bytes of a valid socket address for this family.
    if unsafe { bind_socket(socket, raw.0.as_ptr(), len) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn listen(socket: usize) -> io::Result<()> {
    // SAFETY: a live, bound socket.
    if unsafe { listen_socket(socket, LISTEN_BACKLOG) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// For control codes that take a 4-byte input and return nothing.
pub(crate) fn ioctl(socket: usize, code: u32, value: u32) -> io::Result<()> {
    let mut returned: u32 = 0;
    // SAFETY: a live socket, a 4-byte input and a length slot that outlive the call, and no
    // overlapped I/O.
    let rc = unsafe {
        WSAIoctl(
            socket,
            code,
            (&value as *const u32).cast(),
            std::mem::size_of::<u32>() as u32,
            core::ptr::null_mut(),
            0,
            &mut returned,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
