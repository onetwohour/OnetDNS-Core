/*!
 * @brief 비차단 TCP 접속 걸기.
 *
 * @details 표준 접속은 데드라인을 걸어도 초기 왕복에서 스레드를 붙잡는다. 여기서는 소켓을
 *          비차단으로 열고 접속을 걸어 두기만 한다. 언제 이어졌는지는 호출하는 쪽이 본다.
 * @note 자식 프로세스에 물려주지 않도록 만든다. 물려주면 재시작한 자식이 이전 연결을
 *       잡고 있어 포트가 풀리지 않는다.
 */

use std::io;
use std::net::{SocketAddr, TcpStream};

#[cfg(unix)]
/**
 * @brief 접속을 걸고 곧바로 돌려준다. 이어지기를 기다리지 않는다.
 *
 * @param address 붙을 곳.
 * @return 아직 이어지는 중일 수 있는 소켓. 열지 못했을 때만 오류다.
 * @warning 돌려준 소켓은 비차단 상태로 남는다. 호출하는 쪽이 take_error와 peer_addr로
 *          이어졌는지 보고, 읽고 쓸 때 WouldBlock을 다뤄야 한다.
 */
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
/**
 * @brief 접속을 걸고 곧바로 돌려준다. 이어지기를 기다리지 않는다.
 *
 * @param address 붙을 곳.
 * @return 아직 이어지는 중일 수 있는 소켓. 열지 못했을 때만 오류다.
 * @warning 돌려준 소켓은 비차단 상태로 남는다. 호출하는 쪽이 take_error와 peer_addr로
 *          이어졌는지 보고, 읽고 쓸 때 WouldBlock을 다뤄야 한다.
 */
pub(crate) fn connect(address: SocketAddr) -> io::Result<TcpStream> {
    use std::os::windows::io::{FromRawSocket, RawSocket};
    use std::sync::OnceLock;

    /** @brief 소켓 핸들. */
    type WinSocket = usize;
    /** @brief IPv4 주소 계열. */
    const AF_INET: i32 = 2;
    /** @brief IPv6 주소 계열. */
    const AF_INET6: i32 = 23;
    /** @brief 스트림 소켓. */
    const SOCK_STREAM: i32 = 1;
    /** @brief TCP. */
    const IPPROTO_TCP: i32 = 6;
    /** @brief 잘못된 소켓 값. */
    const INVALID_SOCKET: WinSocket = !0;
    /** @brief 소켓 호출 실패 값. */
    const SOCKET_ERROR: i32 = -1;
    /** @brief 비차단 모드 설정 요청. */
    const FIONBIO: i32 = 0x8004_667eu32 as i32;
    /** @brief 지금은 안 되니 나중에 다시. */
    const WSAEWOULDBLOCK: i32 = 10_035;
    /** @brief 접속이 진행 중. */
    const WSAEINPROGRESS: i32 = 10_036;
    /** @brief 이미 진행 중인 접속이 있음. */
    const WSAEALREADY: i32 = 10_037;
    /** @brief 겹침 입출력을 쓸 수 있는 소켓. */
    const WSA_FLAG_OVERLAPPED: u32 = 0x01;
    /** @brief 자식에게 물려주지 않는다. 물려주면 포트가 풀리지 않는다. */
    const WSA_FLAG_NO_HANDLE_INHERIT: u32 = 0x80;

    #[repr(C, align(8))]
    /** @brief 어느 주소 계열이든 담을 수 있는 크기의 소켓 주소. */
    struct RawSockAddr([u8; 32]);

    #[link(name = "Ws2_32")]
    extern "system" {
        /** @brief 소켓을 연다. 물려주기 여부를 지정할 수 있다. */
        fn WSASocketW(
            af: i32,
            kind: i32,
            protocol: i32,
            protocol_info: *mut std::ffi::c_void,
            group: u32,
            flags: u32,
        ) -> WinSocket;
        /** @brief 소켓 동작 방식을 바꾼다. */
        fn ioctlsocket(socket: WinSocket, command: i32, argument: *mut u32) -> i32;
        /** @brief 접속을 건다. */
        fn connect(socket: WinSocket, address: *const u8, address_length: i32) -> i32;
        /** @brief 소켓을 닫는다. */
        fn closesocket(socket: WinSocket) -> i32;
        /** @brief 마지막 소켓 오류. */
        fn WSAGetLastError() -> i32;
    }

    /** @brief 소켓 계층 초기화 결과. 한 번만 하고 실패했으면 그 사유를 그대로 쓴다. */
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
/** @brief 접속이 스레드를 붙잡지 않고, 소켓이 자식에게 새지 않는지. */
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    /** @brief 이 리스너에 접속이 되는지 확인한다. */
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
        /*
         * 클라이언트에서 peer_addr 가 성공했다는 것은 핸드셰이크가 클라이언트 쪽에서
         * 끝났다는 뜻일 뿐이다. 마지막 ACK 를 처리해 수락 대기열에 올리는 일은 커널이 따로
         * 하므로, 한 번만 시도하면 그 사이에 WouldBlock 을 받고 실패한다.
         */
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
    /** @brief IPv4 접속이 스레드를 붙잡지 않는지. */
    fn ipv4_connect_completes_without_blocking_the_caller() {
        assert_connects(TcpListener::bind("127.0.0.1:0").unwrap());
    }

    #[test]
    /** @brief IPv6 접속이 스레드를 붙잡지 않는지. */
    fn ipv6_connect_completes_without_blocking_the_caller() {
        let Ok(listener) = TcpListener::bind("[::1]:0") else {
            return;
        };
        assert_connects(listener);
    }

    #[cfg(unix)]
    #[test]
    /** @brief 소켓이 자식에게 물려지지 않는지. 물려지면 재시작 뒤에도 포트가 잡혀 있다. */
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
    /** @brief 소켓이 자식에게 물려지지 않는지. 물려지면 재시작 뒤에도 포트가 잡혀 있다. */
    fn connected_socket_is_not_inherited_by_children() {
        use std::os::windows::io::AsRawSocket;

        /** @brief 자식에게 물려주는 손잡이임을 나타내는 표시. */
        const HANDLE_FLAG_INHERIT: u32 = 0x01;
        #[link(name = "kernel32")]
        extern "system" {
            /** @brief 핸들의 속성을 읽는다. */
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
