//! Platform-specific socket binding and CPU placement. SO_REUSEPORT is used only on Linux; other
//! platforms duplicate one socket and let the kernel spread work among the workers, except that the
//! Windows TCP listening socket is never duplicated. CPU placement is hard affinity on Linux, an
//! ideal processor on Windows, and nothing elsewhere.

use std::io;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::time::Duration;

/// Keeps a config typo from exploding into threads.
pub(crate) const MAX_WORKERS: usize = 256;

/// Shorter wakes up for nothing and burns CPU.
const MIN_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Longer makes shutdown and reload visibly slow.
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Zero derives the count from the available parallelism.
pub fn worker_count(requested: usize) -> usize {
    if requested != 0 {
        return requested.min(MAX_WORKERS);
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(MAX_WORKERS)
}

pub fn poll_interval(requested: Duration) -> Duration {
    requested.clamp(MIN_POLL_INTERVAL, MAX_POLL_INTERVAL)
}

/// Does not use the worker index as the CPU number: under containers or taskset the allowed CPUs
/// are a sparse subset, and using indexes directly would target forbidden CPUs, so pinning fails or
/// some allowed cores sit idle. `None` when the set is empty.
#[cfg(any(target_os = "linux", windows, test))]
fn allowed_cpu(mask: &[u64], worker: usize) -> Option<usize> {
    let count: usize = mask.iter().map(|word| word.count_ones() as usize).sum();
    if count == 0 {
        return None;
    }
    let mut target = worker % count;
    for (word_index, &word) in mask.iter().enumerate() {
        let mut remaining = word;
        while remaining != 0 {
            let bit = remaining.trailing_zeros() as usize;
            if target == 0 {
                return Some(word_index * 64 + bit);
            }
            target -= 1;
            remaining &= remaining - 1;
        }
    }
    None
}

/// Not one socket per worker: reuseport distribution hashes the 4-tuple, so a client with a fixed
/// source always lands on the same socket. With as many sockets as workers, that client's load is
/// tied to one worker while the rest idle; grouping sockets by CPU count and letting several
/// workers read each socket loosens that.
#[cfg(any(target_os = "linux", test))]
fn udp_socket_groups(n: usize) -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    n.min(cpus).max(1)
}

#[cfg(any(target_os = "linux", test))]
fn fan_out_udp(groups: Vec<UdpSocket>, n: usize) -> io::Result<Vec<UdpSocket>> {
    let mut socks = Vec::with_capacity(n);
    for idx in 0..n {
        socks.push(groups[idx % groups.len()].try_clone()?);
    }
    Ok(socks)
}

/// Port 0 does not use reuseport: each socket would get a different port. Without reuseport, one
/// socket is duplicated.
pub fn bind_udp_workers(addr: SocketAddr, n: usize) -> io::Result<Vec<UdpSocket>> {
    #[cfg(target_os = "linux")]
    {
        if addr.port() != 0 {
            if let Ok(socks) = linux::reuseport_udp(addr, udp_socket_groups(n)) {
                return fan_out_udp(socks, n);
            }
        }
    }
    let base = onetdns_core::udp::bind(addr)?;
    let mut socks = Vec::with_capacity(n);
    for _ in 0..n {
        socks.push(base.try_clone()?);
    }
    Ok(socks)
}

/// TCP has a different 4-tuple per connection, so one listener per worker has no UDP-style pinning
/// problem.
///
/// On Windows only one listening socket is returned: accepting concurrently on duplicated handles
/// can leave a non-blocking handle asleep inside accept until a connection arrives, so that
/// acceptor never sees shutdown and the side stopping the server waits forever on the join. Windows
/// has no kernel distribution across handles anyway, so nothing is lost.
pub fn bind_tcp_workers(addr: SocketAddr, n: usize) -> io::Result<Vec<TcpListener>> {
    #[cfg(target_os = "linux")]
    {
        if addr.port() != 0 {
            if let Ok(ls) = linux::reuseport_tcp(addr, n) {
                return Ok(ls);
            }
        }
    }
    let base = TcpListener::bind(addr)?;
    base.set_nonblocking(true)?;
    #[cfg(windows)]
    let n = n.min(1);
    let mut listeners = Vec::with_capacity(n);
    for _ in 0..n {
        let l = base.try_clone()?;
        l.set_nonblocking(true)?;
        listeners.push(l);
    }
    Ok(listeners)
}

/// Does nothing where unsupported. Linux pins with hard affinity and Windows only states a
/// preference; the schedulers differ, so they are not forced to the same strength.
#[allow(unused_variables)]
pub fn pin_to_core(idx: usize) {
    #[cfg(target_os = "linux")]
    linux::pin_to_core(idx);
    #[cfg(windows)]
    let _ = windows::pin_to_core(idx);
}

/// Declares only the needed system calls instead of using libc; the constants are Linux ABI values.
#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::net::{SocketAddr, TcpListener, UdpSocket};
    use std::os::raw::{c_int, c_void};
    use std::os::unix::io::FromRawFd;

    const AF_INET: c_int = 2;
    const AF_INET6: c_int = 10;
    const SOCK_STREAM: c_int = 1;
    const SOCK_DGRAM: c_int = 2;
    /// Sockets close on exec. Otherwise child processes and the new executable an update execs
    /// inherit the listening sockets; the old socket, read by no one, stays in the SO_REUSEPORT
    /// group after the new binary binds the same address, and queries the kernel sends to it
    /// vanish. Setting it at creation keeps it from leaking to a child another thread spawns in
    /// between.
    const SOCK_CLOEXEC: c_int = 0o2_000_000;
    const SOL_SOCKET: c_int = 1;
    const SO_REUSEADDR: c_int = 2;
    const SO_REUSEPORT: c_int = 15;
    const SOMAXCONN: c_int = 128;

    extern "C" {
        fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
        fn setsockopt(
            fd: c_int,
            level: c_int,
            optname: c_int,
            optval: *const c_void,
            optlen: u32,
        ) -> c_int;
        fn bind(fd: c_int, addr: *const c_void, len: u32) -> c_int;
        fn listen(fd: c_int, backlog: c_int) -> c_int;
        fn close(fd: c_int) -> c_int;
        fn sched_getaffinity(pid: c_int, cpusetsize: usize, mask: *mut u64) -> c_int;
        fn sched_setaffinity(pid: c_int, cpusetsize: usize, mask: *const u64) -> c_int;
    }

    /// The family is in host byte order and the port in network byte order; mixing them binds the
    /// wrong port.
    fn sockaddr(addr: &SocketAddr) -> (Vec<u8>, c_int) {
        match addr {
            SocketAddr::V4(a) => {
                let mut b = vec![0u8; 16];
                b[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
                b[2..4].copy_from_slice(&a.port().to_be_bytes());
                b[4..8].copy_from_slice(&a.ip().octets());
                (b, AF_INET)
            }
            SocketAddr::V6(a) => {
                let mut b = vec![0u8; 28];
                b[0..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
                b[2..4].copy_from_slice(&a.port().to_be_bytes());
                b[4..8].copy_from_slice(&a.flowinfo().to_ne_bytes());
                b[8..24].copy_from_slice(&a.ip().octets());
                b[24..28].copy_from_slice(&a.scope_id().to_ne_bytes());
                (b, AF_INET6)
            }
        }
    }

    /// Closes the fd on every failure path, or repeated reloads would leak descriptors. The caller
    /// takes ownership of the returned fd.
    fn make_reuse_fd(addr: &SocketAddr, ty: c_int) -> io::Result<c_int> {
        let (sa, domain) = sockaddr(addr);
        unsafe {
            let fd = socket(domain, ty | SOCK_CLOEXEC, 0);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let on: c_int = 1;
            let onp = (&on as *const c_int) as *const c_void;
            let sz = std::mem::size_of::<c_int>() as u32;

            if setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, onp, sz) < 0
                || setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, onp, sz) < 0
                || bind(fd, sa.as_ptr() as *const c_void, sa.len() as u32) < 0
            {
                let e = io::Error::last_os_error();
                close(fd);
                return Err(e);
            }
            Ok(fd)
        }
    }

    /// Checks the bound port afterwards: if it differs from the requested one, reuseport did not
    /// take effect and a random port was assigned, and some workers would listen on the wrong port.
    pub fn reuseport_udp(addr: SocketAddr, n: usize) -> io::Result<Vec<UdpSocket>> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let fd = make_reuse_fd(&addr, SOCK_DGRAM)?;
            // SAFETY: make_reuse_fd just created fd and nothing else owns it.
            let sock = unsafe { UdpSocket::from_raw_fd(fd) };

            if sock.local_addr().ok().map(|la| la.port()) != Some(addr.port()) {
                return Err(io::Error::other("reuseport port does not match"));
            }
            out.push(sock);
        }
        Ok(out)
    }

    /// On a listen failure the fd is closed before returning the error; only fds that succeeded are
    /// owned by Rust types.
    pub fn reuseport_tcp(addr: SocketAddr, n: usize) -> io::Result<Vec<TcpListener>> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let fd = make_reuse_fd(&addr, SOCK_STREAM)?;
            if unsafe { listen(fd, SOMAXCONN) } < 0 {
                let e = io::Error::last_os_error();
                unsafe { close(fd) };
                return Err(e);
            }
            // SAFETY: make_reuse_fd just created fd and nothing else owns it.
            let l = unsafe { TcpListener::from_raw_fd(fd) };
            if l.local_addr().ok().map(|la| la.port()) != Some(addr.port()) {
                return Err(io::Error::other("reuseport port does not match"));
            }
            l.set_nonblocking(true)?;
            out.push(l);
        }
        Ok(out)
    }

    /// Reads the inherited affinity first and picks only within it. Failures are ignored: pinning
    /// is an optimisation and the server must work without it.
    pub fn pin_to_core(idx: usize) {
        let mut allowed = [0u64; 16];
        let size = std::mem::size_of_val(&allowed);
        // SAFETY: the mask is a stack array and its size is passed with it.
        if unsafe { sched_getaffinity(0, size, allowed.as_mut_ptr()) } < 0 {
            return;
        }
        let Some(cpu) = super::allowed_cpu(&allowed, idx) else {
            return;
        };
        let mut mask = [0u64; 16];
        mask[cpu / 64] = 1u64 << (cpu % 64);
        // SAFETY: the mask is a stack array and its size is passed with it.
        unsafe {
            sched_setaffinity(0, size, mask.as_ptr());
        }
    }
}

/// Declares only the calls needed instead of pulling in a crate, like the service control bindings.
#[cfg(windows)]
mod windows {
    type Handle = isize;

    pub(super) const NO_IDEAL_PROCESSOR: u32 = u32::MAX;

    unsafe extern "system" {
        fn GetCurrentThread() -> Handle;
        fn GetCurrentProcess() -> Handle;
        fn GetProcessAffinityMask(
            process: Handle,
            process_mask: *mut usize,
            system_mask: *mut usize,
        ) -> i32;
        fn SetThreadIdealProcessor(thread: Handle, ideal: u32) -> u32;
    }

    /// Returns the previous ideal processor, or `NO_IDEAL_PROCESSOR` on failure.
    pub(super) fn set_ideal_processor(ideal: u32) -> u32 {
        // SAFETY: every argument is passed by value; the call touches none of our memory.
        unsafe { SetThreadIdealProcessor(GetCurrentThread(), ideal) }
    }

    /// Picks a core within the inherited affinity and states it as a preference. Failures are
    /// ignored: this is an optimisation.
    ///
    /// Unlike Linux it does not pin hard: on machines mixing performance and efficiency cores, a
    /// worker pinned to an efficiency core could not even move and would get slower; a preference
    /// keeps cache locality and leaves the decision to the scheduler. Ideal processor numbers mean
    /// something only within the thread's processor group, so on multi-group machines only CPUs of
    /// the default group are picked. Returns the previous ideal processor; `NO_IDEAL_PROCESSOR`
    /// means nothing changed.
    pub(super) fn pin_to_core(idx: usize) -> u32 {
        let mut allowed_mask: usize = 0;
        let mut system_mask: usize = 0;
        // SAFETY: both out-parameters are stack variables; the kernel writes one word to each.
        let read = unsafe {
            GetProcessAffinityMask(GetCurrentProcess(), &mut allowed_mask, &mut system_mask)
        };
        if read == 0 {
            return NO_IDEAL_PROCESSOR;
        }
        let allowed = [allowed_mask as u64];
        let Some(cpu) = super::allowed_cpu(&allowed, idx) else {
            return NO_IDEAL_PROCESSOR;
        };
        let Ok(cpu) = u32::try_from(cpu) else {
            return NO_IDEAL_PROCESSOR;
        };
        set_ideal_processor(cpu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    /// Accepting concurrently on duplicated handles can leave an acceptor asleep inside accept so
    /// the server never stops. That shows up only by chance, so the configuration that causes it is
    /// prevented.
    fn windows_tcp_listener_is_never_duplicated() {
        let listeners = bind_tcp_workers("127.0.0.1:0".parse().unwrap(), 22).unwrap();
        assert_eq!(listeners.len(), 1);
    }

    #[test]
    fn udp_sockets_are_grouped_so_workers_can_share_one_client() {
        let cpus = std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1);
        assert_eq!(udp_socket_groups(0), 1);
        assert_eq!(udp_socket_groups(1), 1);
        assert_eq!(udp_socket_groups(cpus), cpus);
        assert_eq!(udp_socket_groups(cpus * 4), cpus);
        assert_eq!(udp_socket_groups(MAX_WORKERS), cpus.min(MAX_WORKERS));
    }

    #[test]
    fn fan_out_gives_every_worker_a_socket_round_robin() {
        let groups: Vec<UdpSocket> = (0..2)
            .map(|_| UdpSocket::bind("127.0.0.1:0").expect("bind"))
            .collect();
        let ports: Vec<u16> = groups
            .iter()
            .map(|s| s.local_addr().expect("addr").port())
            .collect();
        let socks = fan_out_udp(groups, 5).expect("fan out");
        assert_eq!(socks.len(), 5);
        for (idx, sock) in socks.iter().enumerate() {
            assert_eq!(
                sock.local_addr().expect("addr").port(),
                ports[idx % ports.len()],
                "워커 {idx}가 라운드로빈 순서를 벗어났습니다"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn listening_sockets_close_on_exec() {
        use std::os::unix::io::AsRawFd;

        const O_CLOEXEC: u32 = 0o2_000_000;
        let flags = |fd: i32| {
            let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).expect("fdinfo");
            let value = info
                .lines()
                .find_map(|line| line.strip_prefix("flags:"))
                .expect("flags 줄");
            u32::from_str_radix(value.trim(), 8).expect("8진수 플래그")
        };
        let udp = UdpSocket::bind("127.0.0.1:0")
            .and_then(|socket| socket.local_addr())
            .expect("빈 UDP 포트");
        for socket in linux::reuseport_udp(udp, 2).expect("UDP 수신 소켓") {
            assert_ne!(flags(socket.as_raw_fd()) & O_CLOEXEC, 0, "UDP 수신 소켓");
        }
        let tcp = TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("빈 TCP 포트");
        for listener in linux::reuseport_tcp(tcp, 2).expect("TCP 수신 소켓") {
            assert_ne!(flags(listener.as_raw_fd()) & O_CLOEXEC, 0, "TCP 수신 소켓");
        }
    }

    #[test]
    /// A thread pinned outside the set never runs at all.
    fn worker_affinity_uses_only_the_inherited_cpu_set() {
        let allowed = [0b1010u64, 0b10];
        assert_eq!(allowed_cpu(&allowed, 0), Some(1));
        assert_eq!(allowed_cpu(&allowed, 1), Some(3));
        assert_eq!(allowed_cpu(&allowed, 2), Some(65));
        assert_eq!(allowed_cpu(&allowed, 3), Some(1));
        assert_eq!(allowed_cpu(&[0], 0), None);
    }

    #[cfg(windows)]
    #[test]
    /// A silently failing call is the same as no optimisation.
    fn windows_worker_ideal_processor_is_actually_applied() {
        let previous = windows::pin_to_core(0);
        assert_ne!(
            previous,
            windows::NO_IDEAL_PROCESSOR,
            "선호 코어 지정이 실패했습니다"
        );
        // The test harness may reuse this thread, so restore the original value.
        assert_ne!(
            windows::set_ideal_processor(previous),
            windows::NO_IDEAL_PROCESSOR,
            "원래 선호 코어로 되돌리지 못했습니다"
        );
    }
}
