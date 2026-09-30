use std::io;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/**
 * @brief bind 주소에서 addr로 데드라인 안에 TCP 연결을 맺는다.
 * @param bind 묶을 로컬 주소. 주소가 지정되지 않았으면 std 연결을 그대로 쓴다.
 * @param addr 이을 업스트림.
 * @param timeout 연결을 기다릴 상한.
 */
pub(crate) fn connect(
    bind: SocketAddr,
    addr: SocketAddr,
    timeout: Duration,
) -> io::Result<TcpStream> {
    if bind.ip().is_unspecified() {
        return TcpStream::connect_timeout(&addr, timeout);
    }
    if timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Connect timeout is zero",
        ));
    }
    let stream = sys::bound_socket(bind, addr)?;
    stream.set_nonblocking(true)?;
    sys::start_connect(&stream, addr)?;
    sys::wait_writable(&stream, timeout)?;
    if let Some(error) = stream.take_error()? {
        return Err(error);
    }
    stream.peer_addr()?;
    stream.set_nonblocking(false)?;
    Ok(stream)
}

/** @brief 연결을 기다릴 밀리초. poll 계열 함수의 인자 범위에 맞춘다. */
fn timeout_millis(timeout: Duration) -> i32 {
    i32::try_from(timeout.as_millis().max(1)).unwrap_or(i32::MAX)
}

#[cfg(unix)]
/** @brief libc 소켓 호출. */
mod sys {
    use std::io;
    use std::net::{SocketAddr, TcpStream};
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::time::Duration;

    /**
     * @brief 소켓 주소를 커널 형식으로 바꾼다.
     * @return 주소 저장 공간과 그 가운데 쓴 길이.
     */
    fn raw_addr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
        /* @safety sockaddr_storage는 모든 바이트가 0이어도 올바른 값이다. */
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let len = match addr {
            /* BSD 계열은 구조체에 sa_len 필드가 더 있다. 구조체 리터럴로 만들면 그
             * 플랫폼에서만 필드가 모자라 컴파일이 깨지므로, 0으로 채운 뒤 필드를 하나씩
             * 넣고 sa_len 은 해당 플랫폼에서만 적는다. */
            SocketAddr::V4(v4) => {
                /* @safety sockaddr_storage는 sockaddr_in보다 크고 정렬도 넉넉하다. */
                let raw = (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>();
                unsafe {
                    (*raw).sin_family = libc::AF_INET as libc::sa_family_t;
                    (*raw).sin_port = v4.port().to_be();
                    (*raw).sin_addr = libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.ip().octets()),
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
                std::mem::size_of::<libc::sockaddr_in>()
            }
            SocketAddr::V6(v6) => {
                /* @safety sockaddr_storage는 sockaddr_in6보다 크고 정렬도 넉넉하다. */
                let raw =
                    (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>();
                unsafe {
                    (*raw).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                    (*raw).sin6_port = v6.port().to_be();
                    (*raw).sin6_flowinfo = v6.flowinfo();
                    (*raw).sin6_addr = libc::in6_addr {
                        s6_addr: v6.ip().octets(),
                    };
                    (*raw).sin6_scope_id = v6.scope_id();
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
                std::mem::size_of::<libc::sockaddr_in6>()
            }
        };
        (storage, len as libc::socklen_t)
    }

    /** @brief 계열에 맞는 TCP 소켓을 열고 bind 주소에 묶는다. */
    pub(super) fn bound_socket(bind: SocketAddr, addr: SocketAddr) -> io::Result<TcpStream> {
        let family = if addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        /* @safety 인자가 모두 값이다. */
        let fd = unsafe { libc::socket(family, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        /* @safety 방금 연 소켓이라 다른 소유자가 없다. 이후 닫기는 TcpStream이 맡는다. */
        let stream = unsafe { TcpStream::from_raw_fd(fd) };
        /* @safety 이 서버가 가진 소켓의 플래그만 바꾼다. 자식 프로세스에 새지 않게 한다. */
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (raw, len) = raw_addr(bind);
        /* @safety raw는 len 바이트까지 올바른 주소를 담고 있다. */
        if unsafe { libc::bind(fd, (&raw as *const libc::sockaddr_storage).cast(), len) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(stream)
    }

    /** @brief 논블로킹 연결을 건다. 진행 중이면 성공으로 본다. */
    pub(super) fn start_connect(stream: &TcpStream, addr: SocketAddr) -> io::Result<()> {
        let (raw, len) = raw_addr(addr);
        /* @safety raw는 len 바이트까지 올바른 주소를 담고 있다. */
        let rc = unsafe {
            libc::connect(
                stream.as_raw_fd(),
                (&raw as *const libc::sockaddr_storage).cast(),
                len,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINPROGRESS) {
            Ok(())
        } else {
            Err(error)
        }
    }

    /** @brief 연결이 끝나 쓸 수 있게 될 때까지 기다린다. */
    pub(super) fn wait_writable(stream: &TcpStream, timeout: Duration) -> io::Result<()> {
        let mut pfd = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        loop {
            /* @safety pfd 하나를 가리키고 개수도 1이다. */
            let rc = unsafe { libc::poll(&mut pfd, 1, super::timeout_millis(timeout)) };
            match rc {
                0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Upstream connection timed out",
                    ))
                }
                n if n > 0 => return Ok(()),
                _ => {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                }
            }
        }
    }
}

#[cfg(windows)]
/** @brief winsock 소켓 호출. std가 링크하는 ws2_32를 쓴다. */
mod sys {
    use std::io;
    use std::net::{SocketAddr, TcpStream};
    use std::os::windows::io::{AsRawSocket, FromRawSocket, RawSocket};
    use std::time::Duration;

    /** @brief 잘못된 소켓 값. */
    const INVALID_SOCKET: usize = usize::MAX;
    /** @brief IPv4 계열. */
    const AF_INET: i32 = 2;
    /** @brief IPv6 계열. */
    const AF_INET6: i32 = 23;
    /** @brief 스트림 소켓. */
    const SOCK_STREAM: i32 = 1;
    /** @brief TCP. */
    const IPPROTO_TCP: i32 = 6;
    /** @brief 논블로킹 연결이 진행 중이라는 오류. */
    const WSAEWOULDBLOCK: i32 = 10035;
    /** @brief 아직 winsock을 초기화하지 않았다는 오류. */
    const WSANOTINITIALISED: i32 = 10093;
    /** @brief 쓸 수 있음을 기다린다. */
    const POLLWRNORM: i16 = 0x0010;

    #[repr(C)]
    /** @brief WSAPoll에 넘기는 소켓 하나. */
    struct WsaPollFd {
        /** @brief 소켓. */
        fd: usize,
        /** @brief 기다릴 이벤트. */
        events: i16,
        /** @brief 일어난 이벤트. */
        revents: i16,
    }

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn socket(af: i32, kind: i32, protocol: i32) -> usize;
        fn bind(s: usize, name: *const u8, namelen: i32) -> i32;
        fn connect(s: usize, name: *const u8, namelen: i32) -> i32;
        fn closesocket(s: usize) -> i32;
        fn WSAPoll(fds: *mut WsaPollFd, nfds: u32, timeout: i32) -> i32;
        fn WSAGetLastError() -> i32;
    }

    /** @brief 소켓 주소를 winsock 형식 바이트로 바꾼다. */
    fn raw_addr(addr: SocketAddr) -> Vec<u8> {
        match addr {
            SocketAddr::V4(v4) => {
                let mut raw = vec![0u8; 16];
                raw[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
                raw[2..4].copy_from_slice(&v4.port().to_be_bytes());
                raw[4..8].copy_from_slice(&v4.ip().octets());
                raw
            }
            SocketAddr::V6(v6) => {
                let mut raw = vec![0u8; 28];
                raw[0..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
                raw[2..4].copy_from_slice(&v6.port().to_be_bytes());
                raw[4..8].copy_from_slice(&v6.flowinfo().to_ne_bytes());
                raw[8..24].copy_from_slice(&v6.ip().octets());
                raw[24..28].copy_from_slice(&v6.scope_id().to_ne_bytes());
                raw
            }
        }
    }

    /** @brief 마지막 winsock 오류. */
    fn last_error() -> io::Error {
        /* @safety 인자가 없다. */
        io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
    }

    /** @brief 계열에 맞는 TCP 소켓을 열고 bind 주소에 묶는다. */
    pub(super) fn bound_socket(bind_to: SocketAddr, addr: SocketAddr) -> io::Result<TcpStream> {
        let family = if addr.is_ipv4() { AF_INET } else { AF_INET6 };
        /* @safety 인자가 모두 값이다. */
        let mut s = unsafe { socket(family, SOCK_STREAM, IPPROTO_TCP) };
        if s == INVALID_SOCKET && unsafe { WSAGetLastError() } == WSANOTINITIALISED {
            /* std는 소켓을 처음 만들 때 winsock을 초기화한다. */
            drop(std::net::UdpSocket::bind(("127.0.0.1", 0)));
            /* @safety 인자가 모두 값이다. */
            s = unsafe { socket(family, SOCK_STREAM, IPPROTO_TCP) };
        }
        if s == INVALID_SOCKET {
            return Err(last_error());
        }
        let raw = raw_addr(bind_to);
        /* @safety raw는 raw.len() 바이트의 올바른 주소다. */
        if unsafe { bind(s, raw.as_ptr(), raw.len() as i32) } != 0 {
            let error = last_error();
            /* @safety 방금 연 소켓을 닫는다. */
            unsafe { closesocket(s) };
            return Err(error);
        }
        /* @safety 방금 연 소켓이라 다른 소유자가 없다. 이후 닫기는 TcpStream이 맡는다. */
        Ok(unsafe { TcpStream::from_raw_socket(s as RawSocket) })
    }

    /** @brief 논블로킹 연결을 건다. 진행 중이면 성공으로 본다. */
    pub(super) fn start_connect(stream: &TcpStream, addr: SocketAddr) -> io::Result<()> {
        let raw = raw_addr(addr);
        /* @safety raw는 raw.len() 바이트의 올바른 주소다. */
        if unsafe {
            connect(
                stream.as_raw_socket() as usize,
                raw.as_ptr(),
                raw.len() as i32,
            )
        } == 0
        {
            return Ok(());
        }
        let error = last_error();
        if error.raw_os_error() == Some(WSAEWOULDBLOCK) {
            Ok(())
        } else {
            Err(error)
        }
    }

    /** @brief 연결이 끝나 쓸 수 있게 되거나 실패할 때까지 기다린다. */
    pub(super) fn wait_writable(stream: &TcpStream, timeout: Duration) -> io::Result<()> {
        let mut pfd = WsaPollFd {
            fd: stream.as_raw_socket() as usize,
            events: POLLWRNORM,
            revents: 0,
        };
        /* @safety pfd 하나를 가리키고 개수도 1이다. */
        match unsafe { WSAPoll(&mut pfd, 1, super::timeout_millis(timeout)) } {
            0 => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Upstream connection timed out",
            )),
            n if n > 0 => Ok(()),
            _ => Err(last_error()),
        }
    }
}

#[cfg(test)]
/** @brief 출발 주소가 실제 연결에 쓰이는지. */
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};

    #[test]
    /** @brief 묶은 출발 주소가 상대에게 보이고, 지정하지 않으면 운영체제가 고르는지. */
    fn connect_uses_the_configured_source_address() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target = listener.local_addr().unwrap();
        let bind: SocketAddr = (Ipv4Addr::new(127, 0, 0, 2), 0).into();
        let stream = connect(bind, target, Duration::from_secs(3)).unwrap();
        let (_, peer) = listener.accept().unwrap();
        assert_eq!(peer.ip(), Ipv4Addr::new(127, 0, 0, 2));
        assert_eq!(
            stream.local_addr().unwrap().ip(),
            Ipv4Addr::new(127, 0, 0, 2)
        );

        let any: SocketAddr = (Ipv4Addr::UNSPECIFIED, 0).into();
        connect(any, target, Duration::from_secs(3)).unwrap();
        let (_, peer) = listener.accept().unwrap();
        assert_eq!(peer.ip(), Ipv4Addr::LOCALHOST);
    }

    #[test]
    /** @brief 아무도 받지 않는 포트면 데드라인 안에 오류로 끝나는지. */
    fn connect_to_a_closed_port_fails() {
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let bind: SocketAddr = (Ipv4Addr::new(127, 0, 0, 2), 0).into();
        let started = std::time::Instant::now();
        assert!(connect(
            bind,
            (Ipv4Addr::LOCALHOST, port).into(),
            Duration::from_secs(3)
        )
        .is_err());
        assert!(started.elapsed() < Duration::from_secs(3) + Duration::from_millis(500));
    }
}
