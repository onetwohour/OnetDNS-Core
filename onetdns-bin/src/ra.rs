/*!
 * @brief IPv6 라우터 광고.
 *
 * @details 이 서버가 DNS 서버라고 알리려면 라우터 광고에 접두사를 담아 주기적으로 뿌려야
 *          한다. 원시 소켓이 필요해 리눅스에서만 돈다.
 * @warning 받은 요청을 검사하는 조건이 안전의 전부다. 홉 한계, 출발지 범위, 검사합을
 *          확인하지 않으면 망 밖에서 보낸 패킷에 이 서버가 응답한다.
 */

use std::net::Ipv6Addr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/** @brief 라우터 광고 메시지 종류. */
const ICMP6_RA: u8 = 134;
/** @brief 라우터 요청 메시지 종류. */
const ICMP6_RS: u8 = 133;

#[derive(Debug, Clone)]
/** @brief 광고에 담을 값들. */
pub struct RaConfig {
    /** @brief 알릴 주소 접두사. */
    pub prefix: Ipv6Addr,
    /** @brief 접두사 길이. */
    pub prefix_len: u8,

    /** @brief 주소를 DHCP로 받으라고 알린다. */
    pub managed: bool,

    /** @brief 주소 말고 다른 설정을 DHCP로 받으라고 알린다. */
    pub other: bool,
    /** @brief 이 서버를 기본 경로로 쓸 기간. 0이면 기본 경로가 아니다. */
    pub router_lifetime: u16,
    /** @brief 이 접두사가 유효한 기간. */
    pub valid_lifetime: u32,
    /** @brief 이 접두사를 새 연결에 쓸 기간. */
    pub preferred_lifetime: u32,
    /** @brief 함께 알릴 최대 전송 크기. */
    pub mtu: Option<u32>,

    /** @brief 함께 알릴 이 서버의 하드웨어 주소. */
    pub source_mac: Option<[u8; 6]>,

    /** @brief 주기적으로 뿌릴 간격. 0이면 루트지 않는다. */
    pub interval: u64,

    /** @brief 내보낼 인터페이스 번호. */
    pub interface_index: u32,
}

impl Default for RaConfig {
    /** @brief 접두사가 없으면 광고하지 않는다. */
    fn default() -> Self {
        RaConfig {
            prefix: Ipv6Addr::UNSPECIFIED,
            prefix_len: 64,
            managed: false,
            other: false,
            router_lifetime: 1800,
            valid_lifetime: 86_400,
            preferred_lifetime: 14_400,
            mtu: None,
            source_mac: None,
            interval: 600,
            interface_index: 0,
        }
    }
}

/** @brief 광고 패킷을 만든다. 설정에 없는 항목은 담지 않는다. */
pub fn build_ra(cfg: &RaConfig) -> Vec<u8> {
    let mut m = Vec::with_capacity(64);
    m.push(ICMP6_RA);
    m.push(0);
    m.extend_from_slice(&0u16.to_be_bytes());
    m.push(64);
    let flags = (u8::from(cfg.managed) << 7) | (u8::from(cfg.other) << 6);
    m.push(flags);
    m.extend_from_slice(&cfg.router_lifetime.to_be_bytes());
    m.extend_from_slice(&0u32.to_be_bytes());
    m.extend_from_slice(&0u32.to_be_bytes());

    if let Some(mac) = cfg.source_mac {
        m.push(1);
        m.push(1);
        m.extend_from_slice(&mac);
    }

    if let Some(mtu) = cfg.mtu {
        m.push(5);
        m.push(1);
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&mtu.to_be_bytes());
    }

    if !cfg.prefix.is_unspecified() {
        m.push(3);
        m.push(4);
        m.push(cfg.prefix_len);

        m.push(0b1100_0000);
        m.extend_from_slice(&cfg.valid_lifetime.to_be_bytes());
        m.extend_from_slice(&cfg.preferred_lifetime.to_be_bytes());
        m.extend_from_slice(&0u32.to_be_bytes());
        m.extend_from_slice(&cfg.prefix.octets());
    }
    m
}

#[cfg_attr(not(test), allow(dead_code))]
/** @brief ICMPv6 검사합. 가짜 헤더를 포함해 계산한다. */
pub fn icmpv6_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, payload: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut add = |bytes: &[u8]| {
        let mut i = 0;
        while i + 1 < bytes.len() {
            sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
            i += 2;
        }
        if i < bytes.len() {
            sum += (bytes[i] as u32) << 8;
        }
    };
    add(&src.octets());
    add(&dst.octets());
    add(&(payload.len() as u32).to_be_bytes());
    add(&[0, 0, 0, 58]);
    add(payload);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
/**
 * @brief 이 바이트열이 라우터 요청인지.
 * @details 옵션 길이를 끝까지 따라가며 전부 들어맞아야 참이다. 길이가 0이거나 남는
 *          바이트가 있으면 거짓이다.
 */
pub fn is_router_solicitation(icmp: &[u8]) -> bool {
    if icmp.len() < 8 || icmp[0] != ICMP6_RS || icmp[1] != 0 || icmp[4..8] != [0, 0, 0, 0] {
        return false;
    }
    let mut offset = 8usize;
    while offset < icmp.len() {
        if offset + 2 > icmp.len() {
            return false;
        }
        let units = icmp[offset + 1] as usize;
        if units == 0 {
            return false;
        }
        let option_len = units.saturating_mul(8);
        if offset.saturating_add(option_len) > icmp.len() {
            return false;
        }
        offset += option_len;
    }
    offset == icmp.len()
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/**
 * @brief 이 요청에 응답해도 되는 맥락인지.
 * @warning 홉 한계 255는 이 패킷이 라우터를 거치지 않았다는 유일한 증거다. 이것과
 *          출발지 범위, 검사합을 함께 보지 않으면 망 밖에서 이 서버를 부릴 수 있다.
 * @note 출발지가 미지정이면 링크 계층 주소 옵션이 있으면 안 된다. 규격이 금지한다.
 */
fn valid_router_solicitation_context(
    icmp: &[u8],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    hop_limit: i32,
    received_ifindex: u32,
    expected_ifindex: u32,
) -> bool {
    if !is_router_solicitation(icmp)
        || hop_limit != 255
        || (expected_ifindex != 0 && received_ifindex != expected_ifindex)
        || !(source.is_unspecified() || source.is_unicast_link_local())
        || icmpv6_checksum(&source, &destination, icmp) != 0
    {
        return false;
    }

    if source.is_unspecified() {
        let mut offset = 8usize;
        while offset < icmp.len() {
            if icmp[offset] == 1 {
                return false;
            }
            offset += (icmp[offset + 1] as usize) * 8;
        }
    }
    true
}

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
/**
 * @brief sysfs 표기의 링크 계층 주소를 6바이트로 바꾼다.
 *
 * @details 광고 옵션 1은 이더넷 6바이트만 담을 수 있으므로 길이가 다른 장치는 여기서
 *          걸러진다. 전부 0인 주소는 링크 계층 주소가 없다는 뜻이라 담지 않는다.
 * @param text 콜론으로 나뉜 16진 표기.
 * @return 6바이트 주소. 자릿수나 그룹 수가 다르거나 전부 0이면 None.
 */
fn parse_link_layer_address(text: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut groups = text.trim().split(':');
    for slot in out.iter_mut() {
        let group = groups.next()?;
        if group.len() != 2 || !group.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        *slot = u8::from_str_radix(group, 16).ok()?;
    }
    if groups.next().is_some() || out == [0u8; 6] {
        return None;
    }
    Some(out)
}

#[cfg(target_os = "linux")]
/** @brief 크기 상한을 걸어 sysfs 항목 하나를 읽는다. */
fn read_sysfs_entry(path: &std::path::Path) -> Option<String> {
    use std::io::Read;

    /** @brief 인터페이스 번호도 주소 표기도 이보다 길지 않다. */
    const MAX_SYSFS_ENTRY: u64 = 128;

    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_SYSFS_ENTRY + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_SYSFS_ENTRY {
        return None;
    }
    String::from_utf8(bytes).ok()
}

#[cfg(target_os = "linux")]
/**
 * @brief 인터페이스 번호에 걸린 하드웨어 주소를 찾는다.
 *
 * @details sysfs를 읽는다. ioctl로 받으려면 요청 번호와 구조체 오프셋을 손으로 고정해야
 *          하고 그 값은 대상 아키텍처를 탄다.
 * @param interface_index 광고를 내보낼 인터페이스 번호. 0은 어느 장치인지 정하지 않았다는 뜻이다.
 * @return 이더넷 6바이트 주소. 장치를 못 찾거나 주소를 못 읽으면 None.
 */
fn interface_mac(interface_index: u32) -> Option<[u8; 6]> {
    if interface_index == 0 {
        return None;
    }
    for entry in std::fs::read_dir("/sys/class/net").ok()?.flatten() {
        let dir = entry.path();
        let matches = read_sysfs_entry(&dir.join("ifindex"))
            .and_then(|text| text.trim().parse::<u32>().ok())
            .is_some_and(|index| index == interface_index);
        if matches {
            return parse_link_layer_address(&read_sysfs_entry(&dir.join("address"))?);
        }
    }
    None
}

/** @brief 광고 스레드를 시작한다. 주기나 접두사가 없으면 시작하지 않는다. */
pub fn spawn_ra(
    cfg: RaConfig,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<Option<std::thread::JoinHandle<()>>> {
    if cfg.interval == 0 || cfg.prefix.is_unspecified() {
        return Ok(None);
    }

    /* 하드웨어 주소를 실으면 호스트가 이웃 요청 왕복 없이 기본 경로를 쓴다. */
    #[cfg(target_os = "linux")]
    let cfg = RaConfig {
        source_mac: cfg
            .source_mac
            .or_else(|| interface_mac(cfg.interface_index)),
        ..cfg
    };

    let pkt = build_ra(&cfg);
    onetdns_core::info!(
        event = "ra.packet_built",
        bytes = pkt.len(),
        ifindex = cfg.interface_index,
        interval = cfg.interval,
        "Built the IPv6 router advertisement packet"
    );
    #[cfg(target_os = "linux")]
    {
        std::thread::Builder::new()
            .name("ra".into())
            .spawn(move || linux::run(cfg, shutdown))
            .map(Some)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (cfg, shutdown);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Router advertisements need a raw ICMPv6 socket and are available only on Linux",
        ))
    }
}

#[cfg(target_os = "linux")]
/** @brief 원시 ICMPv6 소켓을 쓰는 리눅스 구현. */
mod linux {
    use super::{build_ra, valid_router_solicitation_context, RaConfig};
    use std::net::Ipv6Addr;
    use std::os::raw::{c_int, c_void};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /**
     * @brief 광고를 보내지 못한 누적 수.
     * @details 요청 광고는 링크 위 아무나 유발할 수 있어 실패도 그만큼 잦아진다. 2의
     *          거듭제곱 번째만 기록해 로그 자체가 부하가 되지 않게 한다.
     */
    static SEND_FAILURES: AtomicU64 = AtomicU64::new(0);

    /** @brief IPv6 주소 계열. */
    const AF_INET6: c_int = 10;
    /** @brief 원시 소켓. */
    const SOCK_RAW: c_int = 3;
    /** @brief ICMPv6. */
    const IPPROTO_ICMPV6: c_int = 58;
    /** @brief IPv6 소켓 옵션 계층. */
    const IPPROTO_IPV6: c_int = 41;
    /** @brief 다중 전송 홉 한계 설정. */
    const IPV6_MULTICAST_HOPS: c_int = 18;
    /** @brief 다중 전송을 내보낼 인터페이스 설정. */
    const IPV6_MULTICAST_IF: c_int = 17;
    /** @brief 다중 전송 그룹 가입. */
    const IPV6_ADD_MEMBERSHIP: c_int = 20;
    /** @brief 받은 패킷의 목적지와 인터페이스를 함께 달라는 요청. */
    const IPV6_RECVPKTINFO: c_int = 49;
    /** @brief 목적지와 인터페이스가 담긴 부가 정보 종류. */
    const IPV6_PKTINFO: c_int = 50;
    /** @brief 받은 패킷의 홉 한계를 함께 달라는 요청. */
    const IPV6_RECVHOPLIMIT: c_int = 51;
    /** @brief 홉 한계가 담긴 부가 정보 종류. */
    const IPV6_HOPLIMIT: c_int = 52;
    /** @brief 소켓 공통 옵션 계층. */
    const SOL_SOCKET: c_int = 1;
    /** @brief 수신 데드라인. 종료 신호를 확인하려면 수신이 깨어나야 한다. */
    const SO_RCVTIMEO: c_int = 20;

    #[repr(C)]
    /** @brief 읽고 쓸 버퍼 하나. */
    struct Iovec {
        /** @brief 버퍼가 시작하는 위치. */
        iov_base: *mut c_void,
        /** @brief 버퍼 길이. */
        iov_len: usize,
    }

    #[repr(C)]
    /** @brief 부가 정보까지 함께 주고받는 메시지 헤더. */
    struct Msghdr {
        /** @brief 상대 주소를 담을 곳. */
        msg_name: *mut c_void,
        /** @brief 그 주소의 크기. */
        msg_namelen: u32,
        /** @brief 읽고 쓸 버퍼들. */
        msg_iov: *mut Iovec,
        /** @brief 버퍼 개수. */
        msg_iovlen: usize,
        /** @brief 부가 정보를 담을 곳. */
        msg_control: *mut c_void,
        /** @brief 부가 정보의 크기. */
        msg_controllen: usize,
        /** @brief 잘림 같은 결과 표시. */
        msg_flags: c_int,
    }

    #[repr(C)]
    /** @brief 부가 정보 한 조각의 헤더. */
    struct Cmsghdr {
        /** @brief 이 조각 전체의 길이. */
        cmsg_len: usize,
        /** @brief 이 조각의 계층. */
        cmsg_level: c_int,
        /** @brief 이 조각의 종류. */
        cmsg_type: c_int,
    }

    #[repr(C)]
    /** @brief 가입할 다중 전송 그룹과 인터페이스. */
    struct Ipv6Mreq {
        /** @brief 그룹 주소. */
        multiaddr: [u8; 16],
        /** @brief 가입할 인터페이스 번호. 0이면 커널이 고른다. */
        interface: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    /** @brief IPv6 소켓 주소. */
    struct SockaddrIn6 {
        /** @brief 주소 계열. */
        sin6_family: u16,
        /** @brief 포트. */
        sin6_port: u16,
        /** @brief 흐름 정보. */
        sin6_flowinfo: u32,
        /** @brief 주소. */
        sin6_addr: [u8; 16],
        /** @brief 링크 지역 주소를 구분하는 번호. */
        sin6_scope_id: u32,
    }

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
        /** @brief 지정한 대상으로 보낸다. */
        fn sendto(
            fd: c_int,
            buf: *const c_void,
            len: usize,
            flags: c_int,
            addr: *const c_void,
            addrlen: u32,
        ) -> isize;
        /** @brief 부가 정보까지 함께 받는다. */
        fn recvmsg(fd: c_int, msg: *mut Msghdr, flags: c_int) -> isize;
        /** @brief 소켓을 닫는다. */
        fn close(fd: c_int) -> c_int;
    }

    /** @brief 부가 정보 조각의 정렬 크기. */
    fn cmsg_align(length: usize) -> usize {
        let align = std::mem::size_of::<usize>();
        (length + align - 1) & !(align - 1)
    }

    /** @brief 링크의 모든 노드를 가리키는 주소. 광고는 여기로 뿌린다. */
    fn all_nodes(ifindex: u32) -> [u8; 28] {
        let mut b = [0u8; 28];
        b[0..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
        let mut addr = [0u8; 16];
        addr[0] = 0xff;
        addr[1] = 0x02;
        addr[15] = 0x01;
        b[8..24].copy_from_slice(&addr);
        b[24..28].copy_from_slice(&ifindex.to_ne_bytes());
        b
    }

    /**
     * @brief 라우터 요청을 하나 받아 응답해도 되는지까지 판단한다.
     * @warning 잘린 메시지나 잘린 부가 정보는 버린다. 잘린 것을 그대로 믿으면 홉 한계나
     *          목적지가 빠진 채로 검사를 통과한다.
     */
    fn recv_rs(fd: c_int, cfg: &RaConfig, buf: &mut [u8]) -> bool {
        let mut source = SockaddrIn6::default();
        let mut control = [0u8; 128];
        let mut iov = Iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut msg = Msghdr {
            msg_name: (&mut source as *mut SockaddrIn6).cast(),
            msg_namelen: std::mem::size_of::<SockaddrIn6>() as u32,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: control.as_mut_ptr().cast(),
            msg_controllen: control.len(),
            msg_flags: 0,
        };
        let n = unsafe { recvmsg(fd, &mut msg, 0) };
        if n <= 0
            || msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || source.sin6_family != AF_INET6 as u16
        {
            return false;
        }

        let mut hop_limit: Option<i32> = None;
        let mut destination: Option<Ipv6Addr> = None;
        let mut ifindex: Option<u32> = None;
        let header_len = cmsg_align(std::mem::size_of::<Cmsghdr>());
        let mut offset = 0usize;
        while offset + std::mem::size_of::<Cmsghdr>() <= msg.msg_controllen {
            let header =
                unsafe { std::ptr::read_unaligned(control.as_ptr().add(offset).cast::<Cmsghdr>()) };
            if header.cmsg_len < header_len || offset + header.cmsg_len > msg.msg_controllen {
                return false;
            }
            let data = unsafe { control.as_ptr().add(offset + header_len) };
            let data_len = header.cmsg_len - header_len;
            if header.cmsg_level == IPPROTO_IPV6
                && header.cmsg_type == IPV6_HOPLIMIT
                && data_len >= std::mem::size_of::<c_int>()
            {
                hop_limit = Some(unsafe { std::ptr::read_unaligned(data.cast::<c_int>()) });
            } else if header.cmsg_level == IPPROTO_IPV6
                && header.cmsg_type == IPV6_PKTINFO
                && data_len >= 20
            {
                let mut address = [0u8; 16];
                unsafe { std::ptr::copy_nonoverlapping(data, address.as_mut_ptr(), 16) };
                destination = Some(Ipv6Addr::from(address));
                ifindex = Some(unsafe { std::ptr::read_unaligned(data.add(16).cast::<u32>()) });
            }
            let step = cmsg_align(header.cmsg_len);
            if step == 0 {
                return false;
            }
            offset = offset.saturating_add(step);
        }

        let source_ip = Ipv6Addr::from(source.sin6_addr);
        let Some((hop_limit, destination, ifindex)) = hop_limit
            .zip(destination)
            .zip(ifindex)
            .map(|((h, d), i)| (h, d, i))
        else {
            return false;
        };
        valid_router_solicitation_context(
            &buf[..n as usize],
            source_ip,
            destination,
            hop_limit,
            ifindex,
            cfg.interface_index,
        )
    }

    /**
     * @brief 광고 반복을 돌린다.
     * @details 주기마다 루트고, 사이에 들어온 요청에도 응답한다. 필요한 옵션을 걸지
     *          못했으면 요청 응답은 접고 주기 광고만 한다.
     */
    pub fn run(cfg: RaConfig, shutdown: Arc<AtomicBool>) {
        let fd = unsafe { socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6) };
        if fd < 0 {
            onetdns_core::error!(event = "ra.socket_failed",
                "Could not open a raw ICMPv6 socket; router advertisements are disabled (requires CAP_NET_RAW)"
            );
            return;
        }
        let mut ancillary_ready = true;
        unsafe {
            let hops: c_int = 255;
            if setsockopt(
                fd,
                IPPROTO_IPV6,
                IPV6_MULTICAST_HOPS,
                (&hops as *const c_int).cast(),
                std::mem::size_of::<c_int>() as u32,
            ) != 0
            {
                ancillary_ready = false;
            }
            let enabled: c_int = 1;
            if setsockopt(
                fd,
                IPPROTO_IPV6,
                IPV6_RECVHOPLIMIT,
                (&enabled as *const c_int).cast(),
                std::mem::size_of::<c_int>() as u32,
            ) != 0
                || setsockopt(
                    fd,
                    IPPROTO_IPV6,
                    IPV6_RECVPKTINFO,
                    (&enabled as *const c_int).cast(),
                    std::mem::size_of::<c_int>() as u32,
                ) != 0
            {
                ancillary_ready = false;
            }
            /* 라우터 요청은 ff02::2로 온다. 포워딩이 꺼진 호스트는 이 그룹에 가입하지 않는다. */
            let all_routers = Ipv6Mreq {
                multiaddr: [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02],
                interface: cfg.interface_index,
            };
            if setsockopt(
                fd,
                IPPROTO_IPV6,
                IPV6_ADD_MEMBERSHIP,
                (&all_routers as *const Ipv6Mreq).cast(),
                std::mem::size_of::<Ipv6Mreq>() as u32,
            ) != 0
            {
                ancillary_ready = false;
            }
            if cfg.interface_index != 0 {
                let idx = cfg.interface_index;
                if setsockopt(
                    fd,
                    IPPROTO_IPV6,
                    IPV6_MULTICAST_IF,
                    (&idx as *const u32).cast(),
                    std::mem::size_of::<u32>() as u32,
                ) != 0
                {
                    ancillary_ready = false;
                }
            }
            let tv = libc::timeval {
                tv_sec: 1,
                tv_usec: 0,
            };
            if setsockopt(
                fd,
                SOL_SOCKET,
                SO_RCVTIMEO,
                (&tv as *const libc::timeval).cast(),
                std::mem::size_of_val(&tv) as u32,
            ) != 0
            {
                ancillary_ready = false;
            }
        }
        if !ancillary_ready {
            onetdns_core::warn!(event = "ra.ifindex_check_failed",
                "Could not set up receive-interface checks for IPv6 router advertisements; sending periodic advertisements only, not solicited ones"
            );
        }

        let dst = all_nodes(cfg.interface_index);
        let send = |fd: c_int| {
            let pkt = build_ra(&cfg);
            let n = unsafe {
                sendto(
                    fd,
                    pkt.as_ptr().cast(),
                    pkt.len(),
                    0,
                    dst.as_ptr().cast(),
                    dst.len() as u32,
                )
            };
            if n < 0 {
                let error = std::io::Error::last_os_error();
                let count = SEND_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
                if count.is_power_of_two() {
                    onetdns_core::warn!(event = "ra.send_failed", interface = cfg.interface_index, count = count, %error, "Failed to send IPv6 router advertisement; devices on this link will not learn this server as their DNS");
                }
            }
        };

        send(fd);
        let mut last = Instant::now();
        let mut buf = [0u8; 1500];
        while !shutdown.load(Ordering::Relaxed) {
            if ancillary_ready && recv_rs(fd, &cfg, &mut buf) {
                send(fd);
            } else if !ancillary_ready {
                std::thread::sleep(Duration::from_millis(250));
            }
            if last.elapsed() >= Duration::from_secs(cfg.interval) {
                send(fd);
                last = Instant::now();
            }
        }
        unsafe {
            close(fd);
        }
    }
}

#[cfg(test)]
/** @brief 광고 패킷의 각 항목과, 요청 판별이 규격대로인지. */
mod tests {
    use super::*;

    /** @brief 테스트용 설정. */
    fn cfg() -> RaConfig {
        RaConfig {
            prefix: "2001:db8:1::".parse().unwrap(),
            prefix_len: 64,
            managed: false,
            other: true,
            router_lifetime: 1800,
            valid_lifetime: 86_400,
            preferred_lifetime: 14_400,
            mtu: Some(1500),
            source_mac: Some([0x02, 0, 0, 0, 0, 0x01]),
            interval: 600,
            interface_index: 2,
        }
    }

    #[test]
    /** @brief 헤더 항목들이 설정대로 담기는지. */
    fn ra_header_fields() {
        let m = build_ra(&cfg());
        assert_eq!(m[0], 134, "type=RA");
        assert_eq!(m[1], 0, "code=0");
        assert_eq!(&m[2..4], &[0, 0], "checksum 0(커널 계산)");
        assert_eq!(m[4], 64, "cur hop limit");
        assert_eq!(m[5], 0b0100_0000, "O 플래그만(M=0,O=1)");
        assert_eq!(u16::from_be_bytes([m[6], m[7]]), 1800, "router lifetime");
    }

    #[test]
    /** @brief 주소 배정 방식 표시가 담기는지. */
    fn ra_managed_flag() {
        let mut c = cfg();
        c.managed = true;
        c.other = false;
        let m = build_ra(&c);
        assert_eq!(m[5], 0b1000_0000, "M=1,O=0");
    }

    #[test]
    /** @brief 설정한 옵션들이 담기는지. */
    fn ra_options_present() {
        let m = build_ra(&cfg());

        assert_eq!(m.len(), 64);

        assert_eq!(m[16], 1, "SLLA type");
        assert_eq!(m[17], 1, "SLLA len(8바이트)");
        assert_eq!(&m[18..24], &[0x02, 0, 0, 0, 0, 0x01]);

        assert_eq!(m[24], 5, "MTU type");
        assert_eq!(m[25], 1, "MTU len");
        assert_eq!(u32::from_be_bytes([m[28], m[29], m[30], m[31]]), 1500);

        assert_eq!(m[32], 3, "PIO type");
        assert_eq!(m[33], 4, "PIO len(32바이트)");
        assert_eq!(m[34], 64, "prefix len");
        assert_eq!(m[35], 0b1100_0000, "L+A 플래그");
        assert_eq!(
            u32::from_be_bytes([m[36], m[37], m[38], m[39]]),
            86_400,
            "valid lifetime"
        );
        assert_eq!(
            &m[48..64],
            &"2001:db8:1::".parse::<Ipv6Addr>().unwrap().octets()
        );
    }

    #[test]
    /** @brief 설정하지 않은 옵션은 빠지는지. */
    fn ra_omits_optional_options() {
        let mut c = cfg();
        c.mtu = None;
        c.source_mac = None;
        let m = build_ra(&c);

        assert_eq!(m.len(), 48);
        assert_eq!(m[16], 3, "PIO가 헤더 바로 뒤");
    }

    #[test]
    /** @brief sysfs 표기를 읽어 옵션에 담을 수 있는지. */
    fn link_layer_address_parses_sysfs_form() {
        assert_eq!(
            parse_link_layer_address("00:15:5d:a3:27:58\n"),
            Some([0x00, 0x15, 0x5d, 0xa3, 0x27, 0x58])
        );
        assert_eq!(
            parse_link_layer_address("AA:BB:CC:DD:EE:FF"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
    }

    #[test]
    /** @brief 6바이트로 담을 수 없는 주소는 걸러지는지. */
    fn link_layer_address_rejects_unusable_forms() {
        /* 링크 계층 주소가 없는 장치는 전부 0으로 나온다. 그대로 광고하면 안 된다. */
        assert_eq!(parse_link_layer_address("00:00:00:00:00:00"), None);
        /* 터널은 4바이트, 인피니밴드는 20바이트로 옵션에 담을 수 없다. */
        assert_eq!(parse_link_layer_address("00:00:00:00"), None);
        assert_eq!(
            parse_link_layer_address("00:00:00:00:fe:80:00:00:00:00:00:00:00:00:00:00:00:00:00:00"),
            None
        );
        assert_eq!(parse_link_layer_address("0:15:5d:a3:27:58"), None);
        assert_eq!(parse_link_layer_address("00:15:5d:a3:27:5g"), None);
        assert_eq!(parse_link_layer_address("00:15:5d:a3:27:+8"), None);
        assert_eq!(parse_link_layer_address(""), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    /** @brief 인터페이스를 정하지 않았으면 주소를 지어내지 않는지. */
    fn interface_mac_needs_an_explicit_index() {
        assert_eq!(interface_mac(0), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    /**
     * @brief 실제 인터페이스의 주소를 sysfs에서 읽어 오는지.
     *
     * @details 이 호스트에 있는 이더넷 장치를 직접 찾아 번호와 주소를 읽고, 같은 번호로
     *          조회한 결과가 일치하는지 본다. 장치가 없는 환경에서는 건너뛴다.
     */
    fn interface_mac_reads_a_real_device() {
        let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
            return;
        };
        for entry in entries.flatten() {
            let dir = entry.path();
            let Some(index) = read_sysfs_entry(&dir.join("ifindex"))
                .and_then(|text| text.trim().parse::<u32>().ok())
            else {
                continue;
            };
            let Some(expected) =
                read_sysfs_entry(&dir.join("address")).and_then(|t| parse_link_layer_address(&t))
            else {
                continue;
            };
            assert_eq!(
                interface_mac(index),
                Some(expected),
                "{} 의 주소를 번호 {index}로 찾지 못했습니다",
                dir.display()
            );
            return;
        }
    }

    #[test]
    /** @brief 검사합이 규격대로인지. */
    fn checksum_matches_rfc_internet_checksum() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "ff02::1".parse().unwrap();
        let mut pkt = build_ra(&cfg());
        let ck = icmpv6_checksum(&src, &dst, &pkt);
        pkt[2..4].copy_from_slice(&ck.to_be_bytes());
        assert_eq!(
            icmpv6_checksum(&src, &dst, &pkt),
            0,
            "체크섬 채운 뒤 재계산은 0"
        );
    }

    #[test]
    /** @brief 요청을 알아보고 어긋난 것을 거르는지. */
    fn detects_router_solicitation() {
        assert!(is_router_solicitation(&[133, 0, 0, 0, 0, 0, 0, 0]));
        assert!(!is_router_solicitation(&[134, 0, 0, 0]));
        assert!(!is_router_solicitation(&[]));
    }
}

#[cfg(test)]
/** @brief 망가진 바이트열에도 파서가 패닉하지 않는지. */
mod fuzz_tests {
    use super::*;

    #[test]
    /** @brief 어떤 바이트열이 와도 판별이 오류로 끝날 뿐 패닉하지 않는지. */
    fn router_solicitation_parsing_never_panics_on_malformed_bytes() {
        use crate::fuzzutil::{havoc, Rng};

        let seed = [
            133u8, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let source: Ipv6Addr = "fe80::1".parse().expect("링크로컬 주소");
        let dest: Ipv6Addr = "ff02::2".parse().expect("라우터 멀티캐스트");
        let mut rng = Rng::new(0x5A17_C0DE_1234_9876);
        for index in 0..20_000u32 {
            let bytes = if index % 3 == 0 {
                rng.rand_bytes(120)
            } else {
                havoc(&mut rng, &seed)
            };
            let _ = is_router_solicitation(&bytes);
            let _ = icmpv6_checksum(&source, &dest, &bytes);
        }
    }
}
