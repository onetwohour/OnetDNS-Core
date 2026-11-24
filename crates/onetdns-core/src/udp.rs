//! UDP sockets that behave the same on Windows and Unix. Open every UDP socket with `bind`, and a
//! listening one with `crate::listen::udp`.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// Opens a UDP socket. On Windows, ICMP errors no longer fail later receives, and port 0 gets a
/// random port instead of the next one in sequence.
pub fn bind(addr: impl Into<SocketAddr>) -> io::Result<UdpSocket> {
    open(addr.into(), false)
}

/// `dual_stack` is for the unspecified IPv6 address only; see `crate::listen`.
pub(crate) fn open(addr: SocketAddr, dual_stack: bool) -> io::Result<UdpSocket> {
    #[cfg(windows)]
    {
        let socket = if addr.port() == 0 || dual_stack {
            windows::bind_raw(addr, dual_stack)?
        } else {
            UdpSocket::bind(addr)?
        };
        windows::ignore_icmp_errors(&socket)?;
        Ok(socket)
    }
    #[cfg(not(windows))]
    {
        if dual_stack {
            crate::listen::dual_stack_udp(addr)
        } else {
            UdpSocket::bind(addr)
        }
    }
}

/// The receive timeout for a socket several threads read. A Windows receive that ends on its
/// timeout drops the datagram arriving at that moment, and with many threads timing out
/// periodically, queries occasionally vanish. So on Windows those threads wait without a timeout and
/// are woken with `wake_readers` when they must stop.
pub fn shared_read_timeout(poll: Duration) -> Option<Duration> {
    if cfg!(windows) {
        None
    } else {
        Some(poll)
    }
}

/// Sends one-byte datagrams, which no listener answers, to the socket bound to `addr` until
/// `running` reports no reader left. Each reader answers what it already received and checks its
/// stop flag before the next receive; one busy with a slow request gets its wake-up after finishing
/// it.
pub fn wake_readers(addr: SocketAddr, running: impl Fn() -> usize) -> io::Result<()> {
    let target = if addr.ip().is_unspecified() {
        match addr {
            SocketAddr::V4(v4) => SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, v4.port())),
            SocketAddr::V6(v6) => SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, v6.port())),
        }
    } else {
        addr
    };
    let local: SocketAddr = if target.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let sender = bind(local)?;
    loop {
        let running = running();
        if running == 0 {
            return Ok(());
        }
        for _ in 0..running {
            let _ = sender.send_to(&[0], target);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Waits at most `timeout` for one datagram.
///
/// A Windows receive that ends on the socket timeout drops the datagram arriving at that moment,
/// so on Windows the socket gets no timeout and `WSAPoll` does the waiting. Use it only on a
/// socket one thread reads: if another thread takes the datagram after the poll, the receive
/// blocks without a limit.
#[derive(Debug, Clone, Copy)]
pub struct RecvWait {
    timeout: Duration,
}

impl RecvWait {
    /// Call `install` on the socket before receiving.
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    pub fn install(self, socket: &UdpSocket) -> io::Result<()> {
        if cfg!(windows) {
            socket.set_read_timeout(None)
        } else {
            socket.set_read_timeout(Some(self.timeout))
        }
    }

    /// Fails with `WouldBlock` or `TimedOut` when nothing arrives in time.
    pub fn recv_from(self, socket: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.wait(socket)?;
        socket.recv_from(buf)
    }

    /// Fails with `WouldBlock` or `TimedOut` when nothing arrives in time.
    pub fn recv(self, socket: &UdpSocket, buf: &mut [u8]) -> io::Result<usize> {
        self.wait(socket)?;
        socket.recv(buf)
    }

    fn wait(self, socket: &UdpSocket) -> io::Result<()> {
        #[cfg(windows)]
        if !crate::poll::readable(socket, self.timeout)? {
            return Err(io::ErrorKind::TimedOut.into());
        }
        #[cfg(not(windows))]
        let _ = socket;
        Ok(())
    }
}

#[cfg(windows)]
mod windows {
    use std::io;
    use std::net::{SocketAddr, UdpSocket};
    use std::os::windows::io::{AsRawSocket, FromRawSocket, RawSocket};

    use crate::winsock;

    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;
    const SIO_UDP_NETRESET: u32 = 0x9800_000F;
    const WSAENOBUFS: i32 = 10_055;
    /// A random port that lands among taken ones can fail the bind with WSAENOBUFS while other
    /// ports are free; the next pick almost always succeeds.
    const RANDOM_PORT_BINDS: usize = 4;

    /// Binds through Winsock to set options that std's `UdpSocket::bind` gives no chance to set
    /// before `bind`: `SO_RANDOMIZE_PORT` on port 0, so Windows picks a random free port rather
    /// than the next one, and dual-stack.
    pub(super) fn bind_raw(addr: SocketAddr, dual_stack: bool) -> io::Result<UdpSocket> {
        let handle = winsock::open(&addr, winsock::SOCK_DGRAM, winsock::IPPROTO_UDP)?;
        // SAFETY: the socket was just opened and has no other owner; `socket` closes it.
        let socket = unsafe { UdpSocket::from_raw_socket(handle as RawSocket) };
        if addr.port() == 0 {
            winsock::set_option(handle, winsock::SOL_SOCKET, winsock::SO_RANDOMIZE_PORT, 1)?;
        }
        if dual_stack {
            winsock::set_option(handle, winsock::IPPROTO_IPV6, winsock::IPV6_V6ONLY, 0)?;
        }
        let mut binds = if addr.port() == 0 {
            RANDOM_PORT_BINDS
        } else {
            1
        };
        loop {
            binds -= 1;
            match winsock::bind(handle, addr) {
                Err(error) if binds > 0 && error.raw_os_error() == Some(WSAENOBUFS) => {}
                result => return result.map(|()| socket),
            }
        }
    }

    /// Stops ICMP port-unreachable and TTL-expired errors from failing the next receive.
    pub(super) fn ignore_icmp_errors(socket: &UdpSocket) -> io::Result<()> {
        for code in [SIO_UDP_CONNRESET, SIO_UDP_NETRESET] {
            winsock::ioctl(socket.as_raw_socket() as usize, code, 0)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::Duration;

    fn ports_in_sequence(ip: IpAddr) -> usize {
        let sockets: Vec<UdpSocket> = (0..16).map(|_| bind((ip, 0)).expect("bind")).collect();
        let ports: Vec<u16> = sockets
            .iter()
            .map(|socket| {
                let local = socket.local_addr().unwrap();
                assert_eq!(local.ip(), ip);
                local.port()
            })
            .collect();
        ports
            .windows(2)
            .filter(|pair| pair[1] == pair[0].wrapping_add(1))
            .count()
    }

    #[test]
    fn port_zero_gets_an_unpredictable_port() {
        assert!(ports_in_sequence(IpAddr::from([127, 0, 0, 1])) < 4);
    }

    #[test]
    fn port_zero_gets_an_unpredictable_port_over_ipv6() {
        if UdpSocket::bind("[::1]:0").is_err() {
            return;
        }
        assert!(ports_in_sequence("::1".parse().unwrap()) < 4);
    }

    #[test]
    fn a_fixed_port_is_kept() {
        let port = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let socket = bind(([127, 0, 0, 1], port)).expect("bind");
        assert_eq!(socket.local_addr().unwrap().port(), port);
    }

    /// Windows would fail the first receive with a connection reset.
    #[test]
    fn datagram_after_icmp_unreachable_is_received() {
        let server = bind(([127, 0, 0, 1], 0)).expect("bind");
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let closed = UdpSocket::bind("127.0.0.1:0").unwrap();
        let closed_addr = closed.local_addr().unwrap();
        drop(closed);
        for _ in 0..3 {
            server.send_to(b"late reply", closed_addr).unwrap();
        }
        std::thread::sleep(Duration::from_millis(100));

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .send_to(b"query", server.local_addr().unwrap())
            .unwrap();
        let mut buf = [0u8; 16];
        let (n, from) = server.recv_from(&mut buf).expect("질의를 받아야 합니다");
        assert_eq!(&buf[..n], b"query");
        assert_eq!(from, client.local_addr().unwrap());
    }

    /// The datagram loss only shows under CPU load, so this checks what was installed.
    #[test]
    fn recv_wait_keeps_windows_sockets_free_of_receive_timeouts() {
        let socket = bind(([127, 0, 0, 1], 0)).expect("bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(9)))
            .unwrap();
        RecvWait::new(Duration::from_millis(40))
            .install(&socket)
            .unwrap();
        let expected = if cfg!(windows) {
            None
        } else {
            Some(Duration::from_millis(40))
        };
        assert_eq!(socket.read_timeout().unwrap(), expected);
    }

    #[test]
    fn recv_wait_returns_datagram_or_times_out() {
        let socket = bind(([127, 0, 0, 1], 0)).expect("bind");
        let wait = RecvWait::new(Duration::from_millis(50));
        wait.install(&socket).unwrap();
        let mut buf = [0u8; 16];

        let started = std::time::Instant::now();
        let error = wait
            .recv_from(&socket, &mut buf)
            .expect_err("보낸 것이 없으면 한도 뒤에 끝나야 합니다");
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        assert!(started.elapsed() >= Duration::from_millis(40));

        let target = socket.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let late = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            sender.send_to(b"late", target).unwrap();
        });
        let wait = RecvWait::new(Duration::from_secs(5));
        wait.install(&socket).unwrap();
        let (n, _) = wait
            .recv_from(&socket, &mut buf)
            .expect("기다리는 동안 온 데이터그램을 받아야 합니다");
        assert_eq!(&buf[..n], b"late");
        late.join().unwrap();
    }
}
