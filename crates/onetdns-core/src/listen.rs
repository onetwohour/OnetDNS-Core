//! Listening sockets. The unspecified IPv6 address takes IPv4 as well on every platform, as the
//! listen address conflict check in onetdns-config assumes. std leaves `IPV6_V6ONLY` at the OS
//! default, which is on in Windows and in Linux with `net.ipv6.bindv6only=1`.

use std::io;
use std::net::{SocketAddr, TcpListener, UdpSocket};

/// Whether a listener on `addr` also takes IPv4.
pub fn is_dual_stack(addr: SocketAddr) -> bool {
    matches!(addr, SocketAddr::V6(v6) if v6.ip().is_unspecified())
}

pub fn tcp(addr: SocketAddr) -> io::Result<TcpListener> {
    if is_dual_stack(addr) {
        sys::dual_stack_tcp(addr)
    } else {
        TcpListener::bind(addr)
    }
}

/// Opened like `crate::udp::bind`.
pub fn udp(addr: SocketAddr) -> io::Result<UdpSocket> {
    crate::udp::open(addr, is_dual_stack(addr))
}

#[cfg(unix)]
pub(crate) use sys::dual_stack_udp;

#[cfg(unix)]
mod sys {
    use std::io;
    use std::mem::size_of;
    use std::net::{SocketAddr, TcpListener, UdpSocket};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    /// What std's `TcpListener::bind` uses.
    const LISTEN_BACKLOG: libc::c_int = 128;

    fn check(rc: libc::c_int) -> io::Result<()> {
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn set(
        fd: &OwnedFd,
        level: libc::c_int,
        name: libc::c_int,
        value: libc::c_int,
    ) -> io::Result<()> {
        // SAFETY: a live socket and an int option value that outlives the call.
        check(unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                level,
                name,
                (&value as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        })
    }

    /// An IPv6 socket bound to `addr` with `IPV6_V6ONLY` off. Closes on exec like std's sockets, or
    /// the executable an update starts would inherit the listener.
    fn bound(addr: SocketAddr, kind: libc::c_int) -> io::Result<OwnedFd> {
        let SocketAddr::V6(addr) = addr else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let kind = kind | libc::SOCK_CLOEXEC;
        // SAFETY: every argument is a plain value.
        let raw = unsafe { libc::socket(libc::AF_INET6, kind, 0) };
        check(raw)?;
        // SAFETY: the socket was just opened and nothing else owns it; `fd` closes it.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        // SAFETY: a live socket.
        check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) })?;
        #[cfg(target_vendor = "apple")]
        set(&fd, libc::SOL_SOCKET, libc::SO_NOSIGPIPE, 1)?;
        set(&fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 0)?;
        if kind & libc::SOCK_STREAM == libc::SOCK_STREAM {
            // std sets it on Unix listeners so a restart can rebind at once.
            set(&fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
        }

        // SAFETY: all-zero bytes are a valid sockaddr_in6; the fields are set one by one because
        // BSD systems have an extra sin6_len field.
        let mut raw: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        raw.sin6_port = addr.port().to_be();
        raw.sin6_flowinfo = addr.flowinfo();
        raw.sin6_addr = libc::in6_addr {
            s6_addr: addr.ip().octets(),
        };
        raw.sin6_scope_id = addr.scope_id();
        #[cfg(any(
            target_vendor = "apple",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        {
            raw.sin6_len = size_of::<libc::sockaddr_in6>() as u8;
        }
        // SAFETY: `raw` is a complete sockaddr_in6 that outlives the call.
        check(unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw as *const libc::sockaddr_in6).cast(),
                size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        })?;
        Ok(fd)
    }

    pub(crate) fn dual_stack_tcp(addr: SocketAddr) -> io::Result<TcpListener> {
        let fd = bound(addr, libc::SOCK_STREAM)?;
        // SAFETY: a live, bound socket.
        check(unsafe { libc::listen(fd.as_raw_fd(), LISTEN_BACKLOG) })?;
        Ok(TcpListener::from(fd))
    }

    pub(crate) fn dual_stack_udp(addr: SocketAddr) -> io::Result<UdpSocket> {
        Ok(UdpSocket::from(bound(addr, libc::SOCK_DGRAM)?))
    }
}

#[cfg(windows)]
mod sys {
    use std::io;
    use std::net::{SocketAddr, TcpListener};
    use std::os::windows::io::{FromRawSocket, RawSocket};

    use crate::winsock;

    pub(crate) fn dual_stack_tcp(addr: SocketAddr) -> io::Result<TcpListener> {
        let handle = winsock::open(&addr, winsock::SOCK_STREAM, winsock::IPPROTO_TCP)?;
        // SAFETY: the socket was just opened and has no other owner; `listener` closes it.
        let listener = unsafe { TcpListener::from_raw_socket(handle as RawSocket) };
        winsock::set_option(handle, winsock::IPPROTO_IPV6, winsock::IPV6_V6ONLY, 0)?;
        winsock::bind(handle, addr)?;
        winsock::listen(handle)?;
        Ok(listener)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpStream};
    use std::time::Duration;

    /// Hosts without IPv6 cannot open the listener at all.
    fn ipv6_available() -> bool {
        TcpListener::bind("[::1]:0").is_ok()
    }

    #[test]
    fn unspecified_ipv6_tcp_listener_accepts_ipv4() {
        if !ipv6_available() {
            return;
        }
        let listener = tcp("[::]:0".parse().unwrap()).unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        let (mut accepted, peer) = listener.accept().unwrap();
        assert_eq!(
            peer.ip().to_canonical(),
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        client.write_all(b"x").unwrap();
        let mut byte = [0u8; 1];
        accepted.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"x");
        assert!(
            TcpStream::connect(("::1", port)).is_ok(),
            "IPv6 still works"
        );
    }

    #[test]
    fn unspecified_ipv6_udp_listener_receives_ipv4() {
        if !ipv6_available() {
            return;
        }
        let server = udp("[::]:0".parse().unwrap()).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let port = server.local_addr().unwrap().port();
        let client = crate::udp::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        client.send_to(b"q", (Ipv4Addr::LOCALHOST, port)).unwrap();
        let mut buf = [0u8; 8];
        let (n, from) = server.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"q");
        server.send_to(b"a", from).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let n = client.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"a");
    }

    #[test]
    fn specific_addresses_keep_their_family() {
        assert!(!is_dual_stack("[::1]:53".parse().unwrap()));
        assert!(!is_dual_stack("0.0.0.0:53".parse().unwrap()));
        assert!(is_dual_stack("[::]:53".parse().unwrap()));
    }
}
