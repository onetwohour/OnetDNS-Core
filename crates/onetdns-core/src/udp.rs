//! UDP sockets that behave the same on Windows and Unix. Open every UDP socket with `bind`.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// Opens a UDP socket. On Windows, ICMP errors no longer fail later receives, and port 0 gets a
/// random port instead of the next one in sequence.
pub fn bind(addr: impl Into<SocketAddr>) -> io::Result<UdpSocket> {
    let addr = addr.into();
    #[cfg(windows)]
    {
        let socket = if addr.port() == 0 {
            windows::bind_random_port(addr)?
        } else {
            UdpSocket::bind(addr)?
        };
        windows::ignore_icmp_errors(&socket)?;
        Ok(socket)
    }
    #[cfg(not(windows))]
    UdpSocket::bind(addr)
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
        if !windows::wait_readable(socket, self.timeout)? {
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
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
    use std::os::windows::io::{AsRawSocket, FromRawSocket, RawSocket};
    use std::time::Duration;

    const AF_INET: i32 = 2;
    const AF_INET6: i32 = 23;
    const SOCK_DGRAM: i32 = 2;
    const IPPROTO_UDP: i32 = 17;
    const INVALID_SOCKET: usize = usize::MAX;
    const WSA_FLAG_OVERLAPPED: u32 = 0x01;
    const WSA_FLAG_NO_HANDLE_INHERIT: u32 = 0x80;
    const WSANOTINITIALISED: i32 = 10_093;
    const SOL_SOCKET: i32 = 0xffff;
    const SO_RANDOMIZE_PORT: i32 = 0x3005;
    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;
    const SIO_UDP_NETRESET: u32 = 0x9800_000F;
    const POLLRDNORM: i16 = 0x0100;

    #[repr(C)]
    struct PollFd {
        fd: usize,
        events: i16,
        revents: i16,
    }

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
        fn WSAPoll(fds: *mut PollFd, count: u32, timeout_ms: i32) -> i32;
    }

    /// Opens a socket the way std does: overlapped and not inherited by child processes.
    fn open(family: i32) -> usize {
        // SAFETY: every argument is a plain value or null.
        unsafe {
            WSASocketW(
                family,
                SOCK_DGRAM,
                IPPROTO_UDP,
                core::ptr::null_mut(),
                0,
                WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
            )
        }
    }

    fn raw_addr(addr: SocketAddr) -> (RawSockAddr, i32) {
        let mut raw = RawSockAddr([0; 28]);
        match addr {
            SocketAddr::V4(v4) => {
                raw.0[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
                raw.0[2..4].copy_from_slice(&v4.port().to_be_bytes());
                raw.0[4..8].copy_from_slice(&v4.ip().octets());
                (raw, 16)
            }
            SocketAddr::V6(v6) => {
                raw.0[0..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
                raw.0[2..4].copy_from_slice(&v6.port().to_be_bytes());
                raw.0[4..8].copy_from_slice(&v6.flowinfo().to_ne_bytes());
                raw.0[8..24].copy_from_slice(&v6.ip().octets());
                raw.0[24..28].copy_from_slice(&v6.scope_id().to_ne_bytes());
                (raw, 28)
            }
        }
    }

    /// Binds `addr` (port 0) with `SO_RANDOMIZE_PORT`, so Windows picks a random free port
    /// rather than the next one; std's `UdpSocket::bind` gives no chance to set it before `bind`.
    pub(super) fn bind_random_port(addr: SocketAddr) -> io::Result<UdpSocket> {
        let family = if addr.is_ipv4() { AF_INET } else { AF_INET6 };
        let mut handle = open(family);
        if handle == INVALID_SOCKET
            && io::Error::last_os_error().raw_os_error() == Some(WSANOTINITIALISED)
        {
            // std starts Winsock when it opens its first socket.
            drop(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)));
            handle = open(family);
        }
        if handle == INVALID_SOCKET {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the socket was just opened and has no other owner; `socket` closes it.
        let socket = unsafe { UdpSocket::from_raw_socket(handle as RawSocket) };
        let on: u32 = 1;
        // SAFETY: a live socket and a 4-byte option value that outlives the call.
        let rc = unsafe {
            setsockopt(
                handle,
                SOL_SOCKET,
                SO_RANDOMIZE_PORT,
                (&on as *const u32).cast(),
                std::mem::size_of::<u32>() as i32,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let (raw, len) = raw_addr(addr);
        // SAFETY: `raw` holds `len` bytes of a valid socket address for this family.
        if unsafe { bind_socket(handle, raw.0.as_ptr(), len) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(socket)
    }

    /// Returns true when the socket became readable in time. An error state counts as readable;
    /// the receive that follows reports it.
    pub(super) fn wait_readable(socket: &UdpSocket, timeout: Duration) -> io::Result<bool> {
        let timeout_ms = i32::try_from(timeout.as_nanos().div_ceil(1_000_000)).unwrap_or(i32::MAX);
        let mut entry = PollFd {
            fd: socket.as_raw_socket() as usize,
            events: POLLRDNORM,
            revents: 0,
        };
        // SAFETY: one entry holding a live socket, borrowed for the whole call.
        let ready = unsafe { WSAPoll(&mut entry, 1, timeout_ms) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ready > 0)
    }

    /// Stops ICMP port-unreachable and TTL-expired errors from failing the next receive.
    pub(super) fn ignore_icmp_errors(socket: &UdpSocket) -> io::Result<()> {
        for code in [SIO_UDP_CONNRESET, SIO_UDP_NETRESET] {
            let off: u32 = 0;
            let mut returned: u32 = 0;
            // SAFETY: a live socket, a 4-byte input and a length slot that outlive the call,
            // and no overlapped I/O.
            let rc = unsafe {
                WSAIoctl(
                    socket.as_raw_socket() as usize,
                    code,
                    (&off as *const u32).cast(),
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
