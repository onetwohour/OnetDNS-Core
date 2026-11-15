//! Non-blocking TCP connect. A std connect, even with a timeout, holds the thread for the
//! handshake; this opens the socket non-blocking and only starts the connect, and the caller
//! watches for completion.
//!
//! Sockets are not inherited by child processes; otherwise a restarted child would hold the old
//! connection and the port would stay taken.

use std::io;
use std::net::{SocketAddr, TcpStream};

#[cfg(unix)]
/// Starts the connect and returns without waiting; fails only when the socket cannot be opened.
///
/// The socket stays non-blocking. The caller checks completion with take_error and peer_addr and
/// handles WouldBlock on reads and writes.
pub(crate) fn connect(address: SocketAddr) -> io::Result<TcpStream> {
    use std::os::fd::FromRawFd;

    let domain = if address.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM, libc::IPPROTO_TCP) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let fail = |error| {
        unsafe {
            libc::close(fd);
        }
        Err(error)
    };
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return fail(io::Error::last_os_error());
    }
    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if descriptor_flags < 0
        || unsafe { libc::fcntl(fd, libc::F_SETFD, descriptor_flags | libc::FD_CLOEXEC) } < 0
    {
        return fail(io::Error::last_os_error());
    }

    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let length = match address {
        SocketAddr::V4(address) => {
            let raw = (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>();
            unsafe {
                (*raw).sin_family = libc::AF_INET as _;
                (*raw).sin_port = address.port().to_be();
                (*raw).sin_addr = libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                };
                #[cfg(any(
                    target_os = "dragonfly",
                    target_os = "freebsd",
                    target_os = "ios",
                    target_os = "macos",
                    target_os = "netbsd",
                    target_os = "openbsd",
                    target_os = "tvos",
                    target_os = "visionos",
                    target_os = "watchos"
                ))]
                {
                    (*raw).sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
                }
            }
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(address) => {
            let raw = (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>();
            unsafe {
                (*raw).sin6_family = libc::AF_INET6 as _;
                (*raw).sin6_port = address.port().to_be();
                (*raw).sin6_flowinfo = address.flowinfo();
                (*raw).sin6_addr = libc::in6_addr {
                    s6_addr: address.ip().octets(),
                };
                (*raw).sin6_scope_id = address.scope_id();
                #[cfg(any(
                    target_os = "dragonfly",
                    target_os = "freebsd",
                    target_os = "ios",
                    target_os = "macos",
                    target_os = "netbsd",
                    target_os = "openbsd",
                    target_os = "tvos",
                    target_os = "visionos",
                    target_os = "watchos"
                ))]
                {
                    (*raw).sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
                }
            }
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    };
    let result = unsafe {
        libc::connect(
            fd,
            (&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr>(),
            length,
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::EINPROGRESS) | Some(libc::EWOULDBLOCK) | Some(libc::EALREADY)
        ) {
            return fail(error);
        }
    }

    Ok(unsafe { TcpStream::from_raw_fd(fd) })
}

#[cfg(windows)]
/// Starts the connect and returns without waiting; fails only when the socket cannot be opened.
///
/// The socket stays non-blocking. The caller checks completion with take_error and peer_addr and
/// handles WouldBlock on reads and writes.
pub(crate) fn connect(address: SocketAddr) -> io::Result<TcpStream> {
    use std::os::windows::io::{FromRawSocket, RawSocket};
    use std::sync::OnceLock;

    type WinSocket = usize;
    const AF_INET: i32 = 2;
    const AF_INET6: i32 = 23;
    const SOCK_STREAM: i32 = 1;
    const IPPROTO_TCP: i32 = 6;
    const INVALID_SOCKET: WinSocket = !0;
    const SOCKET_ERROR: i32 = -1;
    const FIONBIO: i32 = 0x8004_667eu32 as i32;
    const WSAEWOULDBLOCK: i32 = 10_035;
    const WSAEINPROGRESS: i32 = 10_036;
    const WSAEALREADY: i32 = 10_037;
    const WSA_FLAG_OVERLAPPED: u32 = 0x01;
    const WSA_FLAG_NO_HANDLE_INHERIT: u32 = 0x80;

    #[repr(C, align(8))]
    /// Large enough for any address family.
    struct RawSockAddr([u8; 32]);

    #[link(name = "Ws2_32")]
    extern "system" {
        fn WSASocketW(
            af: i32,
            kind: i32,
            protocol: i32,
            protocol_info: *mut std::ffi::c_void,
            group: u32,
            flags: u32,
        ) -> WinSocket;
        fn ioctlsocket(socket: WinSocket, command: i32, argument: *mut u32) -> i32;
        fn connect(socket: WinSocket, address: *const u8, address_length: i32) -> i32;
        fn closesocket(socket: WinSocket) -> i32;
        fn WSAGetLastError() -> i32;
    }

    /// WSAStartup runs once; its failure is returned on every later call.
    static WINSOCK_ERROR: OnceLock<Option<i32>> = OnceLock::new();
    if let Some(code) = *WINSOCK_ERROR.get_or_init(|| {
        std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .err()
            .map(|error| error.raw_os_error().unwrap_or(10_091))
    }) {
        return Err(io::Error::from_raw_os_error(code));
    }

    let domain = if address.is_ipv4() { AF_INET } else { AF_INET6 };
    let socket_handle = unsafe {
        WSASocketW(
            domain,
            SOCK_STREAM,
            IPPROTO_TCP,
            std::ptr::null_mut(),
            0,
            WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    if socket_handle == INVALID_SOCKET {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    let fail = |error| {
        unsafe {
            closesocket(socket_handle);
        }
        Err(error)
    };
    let mut enabled = 1u32;
    if unsafe { ioctlsocket(socket_handle, FIONBIO, &mut enabled) } == SOCKET_ERROR {
        return fail(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }

    let mut raw = RawSockAddr([0; 32]);
    let (family, length) = if address.is_ipv4() {
        (AF_INET, 16)
    } else {
        (AF_INET6, 28)
    };
    raw.0[0..2].copy_from_slice(&(family as u16).to_ne_bytes());
    raw.0[2..4].copy_from_slice(&address.port().to_be_bytes());
    match address {
        SocketAddr::V4(address) => raw.0[4..8].copy_from_slice(&address.ip().octets()),
        SocketAddr::V6(address) => {
            raw.0[4..8].copy_from_slice(&address.flowinfo().to_ne_bytes());
            raw.0[8..24].copy_from_slice(&address.ip().octets());
            raw.0[24..28].copy_from_slice(&address.scope_id().to_ne_bytes());
        }
    }
    if unsafe { connect(socket_handle, raw.0.as_ptr(), length) } == SOCKET_ERROR {
        let code = unsafe { WSAGetLastError() };
        if !matches!(code, WSAEWOULDBLOCK | WSAEINPROGRESS | WSAEALREADY) {
            return fail(io::Error::from_raw_os_error(code));
        }
    }

    Ok(unsafe { TcpStream::from_raw_socket(socket_handle as RawSocket) })
}

#[cfg(not(any(unix, windows)))]
compile_error!("Non-blocking TCP connections need the Unix or Windows socket API");

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    fn assert_connects(listener: TcpListener) {
        let started = Instant::now();
        let stream = connect(listener.local_addr().unwrap()).unwrap();
        assert!(started.elapsed() < Duration::from_millis(100));

        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(error) = stream.take_error().unwrap() {
                panic!("nonblocking connect failed: {error}");
            }
            match stream.peer_addr() {
                Ok(_) => break,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::NotConnected
                    ) => {}
                Err(error) => panic!("unexpected connect state: {error}"),
            }
            assert!(Instant::now() < deadline, "nonblocking connect timed out");
            std::thread::yield_now();
        }
        listener.set_nonblocking(true).unwrap();
        // peer_addr succeeding on the client only means the client side finished the handshake. The
        // kernel processes the final ACK and queues the connection for accept separately, so a
        // single try can get WouldBlock in between.
        let accept_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < accept_deadline,
                        "연결이 수락 대기열에 오르지 않았습니다"
                    );
                    std::thread::yield_now();
                }
                Err(error) => panic!("accept 실패: {error}"),
            }
        }
    }

    #[test]
    fn ipv4_connect_completes_without_blocking_the_caller() {
        assert_connects(TcpListener::bind("127.0.0.1:0").unwrap());
    }

    #[test]
    fn ipv6_connect_completes_without_blocking_the_caller() {
        let Ok(listener) = TcpListener::bind("[::1]:0") else {
            return;
        };
        assert_connects(listener);
    }

    #[cfg(unix)]
    #[test]
    /// Otherwise the port stays taken after a restart.
    fn connected_socket_is_not_inherited_by_children() {
        use std::os::fd::AsRawFd;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = connect(listener.local_addr().unwrap()).unwrap();
        let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0, "fcntl(F_GETFD) 실패");
        assert_ne!(
            flags & libc::FD_CLOEXEC,
            0,
            "XFR 소켓이 exec 시 자식에게 상속됩니다"
        );
    }

    #[cfg(windows)]
    #[test]
    /// Otherwise the port stays taken after a restart.
    fn connected_socket_is_not_inherited_by_children() {
        use std::os::windows::io::AsRawSocket;

        const HANDLE_FLAG_INHERIT: u32 = 0x01;
        #[link(name = "kernel32")]
        extern "system" {
            fn GetHandleInformation(handle: usize, flags: *mut u32) -> i32;
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = connect(listener.local_addr().unwrap()).unwrap();
        let mut flags = 0u32;
        let ok = unsafe { GetHandleInformation(stream.as_raw_socket() as usize, &mut flags) };
        assert_ne!(ok, 0, "GetHandleInformation 실패");
        assert_eq!(
            flags & HANDLE_FLAG_INHERIT,
            0,
            "XFR 소켓이 CreateProcess로 자식에게 상속됩니다"
        );
    }
}
