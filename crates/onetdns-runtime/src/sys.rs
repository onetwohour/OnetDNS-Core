/*!
 * @brief 플랫폼별 소켓 바인딩과 CPU 배치.
 *
 * @details SO_REUSEPORT는 리눅스에서만 쓴다. 다른 플랫폼은 소켓 하나를 복제해
 *          공유하며, 커널이 워커 사이의 분배를 맡는다. 윈도우의 TCP 수신 소켓만은
 *          복제하지 않는다. CPU 배치는 리눅스가 하드 친화도, 윈도우가 선호 코어
 *          지정이고 그 밖에서는 하지 않는다.
 */

use std::io;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::time::Duration;

/** @brief 워커 수 상한. 설정 오타가 스레드 폭증으로 이어지지 않게 막는다. */
pub(crate) const MAX_WORKERS: usize = 256;

/** @brief 폴링 주기 하한. 더 짧게 잡으면 빈 깨어남이 CPU를 갉아먹는다. */
const MIN_POLL_INTERVAL: Duration = Duration::from_millis(1);

/** @brief 폴링 주기 상한. 더 길면 종료·재로드 반응이 눈에 띄게 느려진다. */
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(1);

/** @brief 워커 수를 정한다. 0이면 사용 가능한 병렬도에서 끌어온다. */
pub fn worker_count(requested: usize) -> usize {
    if requested != 0 {
        return requested.min(MAX_WORKERS);
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(MAX_WORKERS)
}

/** @brief 폴링 주기를 허용 범위로 자른다. */
pub fn poll_interval(requested: Duration) -> Duration {
    requested.clamp(MIN_POLL_INTERVAL, MAX_POLL_INTERVAL)
}

/**
 * @brief 상속받은 CPU 집합 안에서 워커에게 배정할 CPU를 고른다.
 *
 * @details 워커 번호를 그대로 CPU 번호로 쓰지 않는다. 컨테이너나 taskset 아래에서는
 *          허용된 CPU가 듬성듬성한 부분집합이라, 번호를 직접 쓰면 금지된 CPU를 지정해
 *          고정이 실패하거나 허용된 코어 일부가 놀게 된다.
 * @return 허용 집합 안의 CPU 번호. 집합이 비어 있으면 None.
 */
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

/**
 * @brief 실제로 열 SO_REUSEPORT 소켓 수.
 *
 * @details 워커마다 소켓을 하나씩 열지 않는다. 커널의 reuseport 분배는 4-튜플 해시라,
 *          출발지가 고정된 클라이언트 하나는 언제나 같은 소켓으로만 간다. 소켓 수가
 *          워커 수와 같으면 그 클라이언트의 부하가 워커 하나에 묶여 나머지가 논다.
 *          소켓을 CPU 수로 묶고 여러 워커가 같은 소켓을 나눠 읽게 해서 그 고착을 푼다.
 */
#[cfg(any(target_os = "linux", test))]
fn udp_socket_groups(n: usize) -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    n.min(cpus).max(1)
}

/** @brief 소켓 그룹을 워커 수만큼 라운드로빈으로 복제해 나눠 준다. */
#[cfg(any(target_os = "linux", test))]
fn fan_out_udp(groups: Vec<UdpSocket>, n: usize) -> io::Result<Vec<UdpSocket>> {
    let mut socks = Vec::with_capacity(n);
    for idx in 0..n {
        socks.push(groups[idx % groups.len()].try_clone()?);
    }
    Ok(socks)
}

/**
 * @brief 워커용 UDP 소켓을 연다.
 * @note 포트 0(임의 포트)에서는 reuseport를 쓰지 않는다. 소켓마다 다른 포트가 배정되어
 *       같은 주소를 공유한다는 전제가 깨지기 때문이다.
 * @return reuseport가 안 되는 환경에서는 소켓 하나를 복제해 돌려준다.
 */
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

/**
 * @brief 워커용 TCP 리스너를 연다.
 * @details TCP는 연결마다 4-튜플이 달라 UDP 같은 고착이 없으므로 워커 수만큼 그대로 연다.
 * @warning 윈도우에서는 수신 소켓 하나만 돌려준다. 같은 소켓을 복제한 핸들 여러 개로
 *          동시에 accept 하면, 논블로킹으로 둔 핸들 하나가 연결이 올 때까지 accept 안에서
 *          잠드는 일이 생긴다. 그 수락 스레드는 종료 신호를 보지 못하고, 서버를 내리는
 *          쪽은 합류를 기다리며 함께 멈춘다. 윈도우에는 커널이 연결을 나눠 주는 장치가
 *          없어 복제 핸들을 늘려도 accept 는 같은 소켓에서 차례로 처리되므로 잃는 것도 없다.
 */
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

/**
 * @brief 현재 스레드가 쓸 코어를 정한다. 지원하지 않는 곳에서는 아무 일도 하지 않는다.
 * @note 리눅스는 하드 친화도로 못 박고 윈도우는 선호로만 알린다. 플랫폼마다 스케줄러가
 *       다르므로 같은 세기로 맞추지 않는다.
 */
#[allow(unused_variables)]
pub fn pin_to_core(idx: usize) {
    #[cfg(target_os = "linux")]
    linux::pin_to_core(idx);
    #[cfg(windows)]
    let _ = windows::pin_to_core(idx);
}

/**
 * @brief 리눅스 전용 소켓·스케줄러 바인딩.
 * @details libc를 쓰지 않고 필요한 시스템 호출만 직접 선언한다. 상수는 리눅스 ABI 값이다.
 */
#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::net::{SocketAddr, TcpListener, UdpSocket};
    use std::os::raw::{c_int, c_void};
    use std::os::unix::io::FromRawFd;

    /** @brief IPv4 주소 계열. */
    const AF_INET: c_int = 2;
    /** @brief IPv6 주소 계열. */
    const AF_INET6: c_int = 10;
    /** @brief 스트림 소켓. */
    const SOCK_STREAM: c_int = 1;
    /** @brief 데이터그램 소켓. */
    const SOCK_DGRAM: c_int = 2;
    /** @brief 소켓 공통 옵션 계층. */
    const SOL_SOCKET: c_int = 1;
    /** @brief 방금 닫은 주소에 다시 묶는다. */
    const SO_REUSEADDR: c_int = 2;
    /** @brief 여러 소켓이 같은 포트에 묶인다. 워커마다 소켓을 두어 커널이 나눠 주게 하려는 것이다. */
    const SO_REUSEPORT: c_int = 15;
    /** @brief 대기 줄 길이. */
    const SOMAXCONN: c_int = 128;

    extern "C" {
        /** @brief 소켓을 연다. */
        fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
        /** @brief 소켓 옵션을 건다. */
        fn setsockopt(
            fd: c_int,
            level: c_int,
            optname: c_int,
            optval: *const c_void,
            optlen: u32,
        ) -> c_int;
        /** @brief 주소에 묶는다. */
        fn bind(fd: c_int, addr: *const c_void, len: u32) -> c_int;
        /** @brief 연결을 받기 시작한다. */
        fn listen(fd: c_int, backlog: c_int) -> c_int;
        /** @brief 소켓을 닫는다. */
        fn close(fd: c_int) -> c_int;
        /** @brief 이 프로세스가 쓸 수 있는 코어 집합. */
        fn sched_getaffinity(pid: c_int, cpusetsize: usize, mask: *mut u64) -> c_int;
        /** @brief 이 스레드를 특정 코어에 묶는다. */
        fn sched_setaffinity(pid: c_int, cpusetsize: usize, mask: *const u64) -> c_int;
    }

    /**
     * @brief 소켓 주소를 커널이 기대하는 바이트 배치로 만든다.
     * @note 계열은 호스트 바이트 순서, 포트는 네트워크 바이트 순서다. 둘을 섞으면
     *       엉뚱한 포트에 바인딩된다.
     */
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

    /**
     * @brief SO_REUSEPORT가 켜진 소켓을 만들어 바인딩한다.
     * @safety 실패 경로마다 fd를 닫는다. 닫지 않으면 재로드를 반복할수록 fd가 샌다.
     * @return 성공한 fd. 호출자가 소유권을 가져가 Rust 타입으로 감싼다.
     */
    fn make_reuse_fd(addr: &SocketAddr, ty: c_int) -> io::Result<c_int> {
        let (sa, domain) = sockaddr(addr);
        unsafe {
            let fd = socket(domain, ty, 0);
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

    /**
     * @brief 같은 주소에 SO_REUSEPORT UDP 소켓 n개를 연다.
     * @warning 바인딩 후 실제 포트를 다시 확인한다. 요청 포트와 다르면 reuseport가 듣지
     *          않고 임의 포트가 배정된 것이며, 그대로 두면 일부 워커가 엉뚱한 포트를 듣는다.
     * @safety from_raw_fd는 make_reuse_fd가 방금 만든, 다른 소유자가 없는 fd만 받는다.
     */
    pub fn reuseport_udp(addr: SocketAddr, n: usize) -> io::Result<Vec<UdpSocket>> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let fd = make_reuse_fd(&addr, SOCK_DGRAM)?;
            let sock = unsafe { UdpSocket::from_raw_fd(fd) };

            if sock.local_addr().ok().map(|la| la.port()) != Some(addr.port()) {
                return Err(io::Error::other("reuseport port does not match"));
            }
            out.push(sock);
        }
        Ok(out)
    }

    /**
     * @brief 같은 주소에 SO_REUSEPORT TCP 리스너 n개를 연다.
     * @safety listen 실패 시 fd를 닫은 뒤 오류를 낸다. 성공한 fd만 Rust 타입이 소유한다.
     */
    pub fn reuseport_tcp(addr: SocketAddr, n: usize) -> io::Result<Vec<TcpListener>> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let fd = make_reuse_fd(&addr, SOCK_STREAM)?;
            if unsafe { listen(fd, SOMAXCONN) } < 0 {
                let e = io::Error::last_os_error();
                unsafe { close(fd) };
                return Err(e);
            }
            let l = unsafe { TcpListener::from_raw_fd(fd) };
            if l.local_addr().ok().map(|la| la.port()) != Some(addr.port()) {
                return Err(io::Error::other("reuseport port does not match"));
            }
            l.set_nonblocking(true)?;
            out.push(l);
        }
        Ok(out)
    }

    /**
     * @brief 현재 스레드를 CPU 하나에 고정한다.
     * @details 먼저 상속받은 친화도를 읽어 그 안에서만 고른다. 실패는 조용히 넘긴다.
     *          고정은 최적화일 뿐이라 안 되더라도 서버는 정상 동작해야 한다.
     * @safety 마스크 배열은 스택에 있고 크기를 함께 넘기므로 커널이 범위를 넘겨 쓰지 않는다.
     */
    pub fn pin_to_core(idx: usize) {
        let mut allowed = [0u64; 16];
        let size = std::mem::size_of_val(&allowed);
        if unsafe { sched_getaffinity(0, size, allowed.as_mut_ptr()) } < 0 {
            return;
        }
        let Some(cpu) = super::allowed_cpu(&allowed, idx) else {
            return;
        };
        let mut mask = [0u64; 16];
        mask[cpu / 64] = 1u64 << (cpu % 64);
        unsafe {
            sched_setaffinity(0, size, mask.as_ptr());
        }
    }
}

/**
 * @brief 윈도우 전용 스레드 친화도 지정.
 * @details 외부 크레이트를 쓰지 않으려고 필요한 호출만 직접 선언한다. 서비스 제어
 *          바인딩과 같은 방식이다.
 */
#[cfg(windows)]
mod windows {
    /** @brief 커널 개체 핸들. */
    type Handle = isize;

    /** @brief 선호 코어를 못 정했다는 뜻의 반환값. */
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

    /**
     * @brief 현재 스레드의 선호 코어를 바꾼다.
     * @param ideal 선호할 CPU 번호.
     * @return 바꾸기 전 선호 코어. NO_IDEAL_PROCESSOR면 실패다.
     * @safety 인자가 모두 값이라 커널이 이 서버의 메모리를 건드리지 않는다.
     */
    pub(super) fn set_ideal_processor(ideal: u32) -> u32 {
        unsafe { SetThreadIdealProcessor(GetCurrentThread(), ideal) }
    }

    /**
     * @brief 현재 스레드가 쓸 코어를 고르고 스케줄러에 선호로 알린다.
     *
     * @details 먼저 상속받은 친화도를 읽어 그 안에서만 고른다. 실패는 조용히 넘긴다.
     *          이건 최적화일 뿐이라 안 되더라도 서버는 정상 동작해야 한다.
     * @warning 리눅스처럼 하드 친화도로 못 박지 않는다. 성능 코어와 효율 코어가 섞인
     *          기계에서 워커를 효율 코어에 묶으면 이동조차 못 해 더 느려진다. 선호는
     *          같은 코어를 이어 쓰게 해 캐시 지역성은 얻으면서 스케줄러의 판단을 남긴다.
     * @note 선호 코어 번호는 스레드가 속한 프로세서 그룹 안에서만 뜻이 있다. 그룹이
     *       여럿인 기계에서는 기본 그룹의 CPU만 고른다.
     * @return 바꾸기 전 선호 코어. NO_IDEAL_PROCESSOR면 아무것도 하지 않았다.
     * @safety 두 출력 인자는 스택 변수의 주소이고 커널은 각각 한 워드만 쓴다.
     */
    pub(super) fn pin_to_core(idx: usize) -> u32 {
        let mut allowed_mask: usize = 0;
        let mut system_mask: usize = 0;
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
/** @brief 소켓을 워커에 나누는 방식과 코어 묶기. */
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    /**
     * @brief 윈도우에서 TCP 수신 소켓을 복제하지 않는지.
     * @details 복제 핸들로 동시에 accept 하면 수락 스레드 하나가 accept 안에서 잠들어 서버를
     *          내리지 못한다. 그 현상은 확률적으로만 드러나므로 원인이 되는 구성을 막는다.
     */
    fn windows_tcp_listener_is_never_duplicated() {
        let listeners = bind_tcp_workers("127.0.0.1:0".parse().unwrap(), 22).unwrap();
        assert_eq!(listeners.len(), 1);
    }

    #[test]
    /** @brief 소켓 수를 코어 수로 묶어 클라이언트 하나가 워커 하나에 고착되지 않는지. */
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
    /** @brief 워커마다 소켓이 돌아가는지. */
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

    #[test]
    /** @brief 물려받은 코어 집합 밖으로 묶지 않는지. 밖으로 묶으면 그 스레드가 아예 돌지 않는다. */
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
    /** @brief 윈도우에서도 실제로 지정되는지. 호출이 조용히 실패하면 최적화가 없는 것과 같다. */
    fn windows_worker_ideal_processor_is_actually_applied() {
        let previous = windows::pin_to_core(0);
        assert_ne!(
            previous,
            windows::NO_IDEAL_PROCESSOR,
            "선호 코어 지정이 실패했습니다"
        );
        // 이 스레드는 테스트 하네스가 재사용할 수 있으므로 원래 값으로 되돌린다.
        assert_ne!(
            windows::set_ideal_processor(previous),
            windows::NO_IDEAL_PROCESSOR,
            "원래 선호 코어로 되돌리지 못했습니다"
        );
    }
}
