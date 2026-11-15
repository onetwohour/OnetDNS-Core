use std::io;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// With an unspecified `bind` address, std's connect is used as is.
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

/// Fits poll's argument range.
fn timeout_millis(timeout: Duration) -> i32 {
    i32::try_from(timeout.as_millis().max(1)).unwrap_or(i32::MAX)
}

#[cfg(unix)]
mod sys {
    use std::io;
    use std::net::{SocketAddr, TcpStream};
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::time::Duration;

    /// Returns the storage and the length used.
    fn raw_addr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
        // SAFETY: sockaddr_storage is valid when all bytes are zero.
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let len = match addr {
            // BSD systems have an extra sa_len field. A struct literal would fail to compile there
            // for the missing field, so the storage is zeroed, fields are set one by one, and
            // sa_len is written only on those platforms.
            SocketAddr::V4(v4) => {
                // SAFETY: sockaddr_storage is larger than sockaddr_in and at least as aligned.
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
                // SAFETY: sockaddr_storage is larger than sockaddr_in6 and at least as aligned.
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

    pub(super) fn bound_socket(bind: SocketAddr, addr: SocketAddr) -> io::Result<TcpStream> {
        let family = if addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        // SAFETY: all arguments are plain values.
        let fd = unsafe { libc::socket(family, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the socket was just opened, so nothing else owns it; TcpStream closes it from
        // here on.
        let stream = unsafe { TcpStream::from_raw_fd(fd) };
        // SAFETY: fd is a socket this server owns.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (raw, len) = raw_addr(bind);
        // SAFETY: raw holds a valid address in its first len bytes.
        if unsafe { libc::bind(fd, (&raw as *const libc::sockaddr_storage).cast(), len) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(stream)
    }

    /// Non-blocking; in progress counts as success.
    pub(super) fn start_connect(stream: &TcpStream, addr: SocketAddr) -> io::Result<()> {
        let (raw, len) = raw_addr(addr);
        // SAFETY: raw holds a valid address in its first len bytes.
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

    pub(super) fn wait_writable(stream: &TcpStream, timeout: Duration) -> io::Result<()> {
        let mut pfd = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        loop {
            // SAFETY: points to one pollfd, and the count is 1.
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
/// Winsock calls, through the ws2_32 that std already links.
mod sys {
    use std::io;
    use std::net::{SocketAddr, TcpStream};
    use std::os::windows::io::{AsRawSocket, FromRawSocket, RawSocket};
    use std::time::Duration;

    const INVALID_SOCKET: usize = usize::MAX;
    const AF_INET: i32 = 2;
    const AF_INET6: i32 = 23;
    const SOCK_STREAM: i32 = 1;
    const IPPROTO_TCP: i32 = 6;
    const WSAEWOULDBLOCK: i32 = 10035;
    const WSANOTINITIALISED: i32 = 10093;
    const POLLWRNORM: i16 = 0x0010;

    #[repr(C)]
    struct WsaPollFd {
        fd: usize,
        events: i16,
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

    fn last_error() -> io::Error {
        // SAFETY: takes no arguments.
        io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
    }

    pub(super) fn bound_socket(bind_to: SocketAddr, addr: SocketAddr) -> io::Result<TcpStream> {
        let family = if addr.is_ipv4() { AF_INET } else { AF_INET6 };
        // SAFETY: all arguments are plain values.
        let mut s = unsafe { socket(family, SOCK_STREAM, IPPROTO_TCP) };
        if s == INVALID_SOCKET && unsafe { WSAGetLastError() } == WSANOTINITIALISED {
            // std initializes winsock when it first creates a socket.
            drop(std::net::UdpSocket::bind(("127.0.0.1", 0)));
            // SAFETY: all arguments are plain values.
            s = unsafe { socket(family, SOCK_STREAM, IPPROTO_TCP) };
        }
        if s == INVALID_SOCKET {
            return Err(last_error());
        }
        let raw = raw_addr(bind_to);
        // SAFETY: raw is a valid address of raw.len() bytes.
        if unsafe { bind(s, raw.as_ptr(), raw.len() as i32) } != 0 {
            let error = last_error();
            // SAFETY: closes the socket just opened.
            unsafe { closesocket(s) };
            return Err(error);
        }
        // SAFETY: the socket was just opened, so nothing else owns it; TcpStream closes it from
        // here on.
        Ok(unsafe { TcpStream::from_raw_socket(s as RawSocket) })
    }

    /// Non-blocking; in progress counts as success.
    pub(super) fn start_connect(stream: &TcpStream, addr: SocketAddr) -> io::Result<()> {
        let raw = raw_addr(addr);
        // SAFETY: raw is a valid address of raw.len() bytes.
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

    pub(super) fn wait_writable(stream: &TcpStream, timeout: Duration) -> io::Result<()> {
        let mut pfd = WsaPollFd {
            fd: stream.as_raw_socket() as usize,
            events: POLLWRNORM,
            revents: 0,
        };
        // SAFETY: points to one pollfd, and the count is 1.
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
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};

    #[test]
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
