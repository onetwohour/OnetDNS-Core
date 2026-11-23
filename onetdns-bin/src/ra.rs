//! IPv6 router advertisements carrying a prefix, sent periodically and in answer to router
//! solicitations. Needs a raw socket, so it runs only on Linux.
//!
//! Checking received solicitations is the whole of its safety: without the hop limit, source scope,
//! and checksum checks, packets from off-link would get answers.

use std::net::Ipv6Addr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

const ICMP6_RA: u8 = 134;
const ICMP6_RS: u8 = 133;

#[derive(Debug, Clone)]
pub struct RaConfig {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,

    /// M flag: get addresses from DHCPv6.
    pub managed: bool,

    /// O flag: get other settings from DHCPv6.
    pub other: bool,
    /// 0 means not a default router.
    pub router_lifetime: u16,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub mtu: Option<u32>,

    /// Sent as the RDNSS option (RFC 8106); empty leaves it out.
    pub dns: Vec<Ipv6Addr>,

    /// Sent as the source link-layer address option.
    pub source_mac: Option<[u8; 6]>,

    /// Seconds between advertisements; 0 turns advertising off.
    pub interval: u64,

    pub interface_index: u32,
}

impl Default for RaConfig {
    /// No prefix means no advertisements.
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
            dns: Vec::new(),
            source_mac: None,
            interval: 600,
            interface_index: 0,
        }
    }
}

/// Options not configured are left out.
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

    // The length byte counts 8-byte units, so one option holds 127 addresses at most; the config
    // allows fewer.
    if !cfg.dns.is_empty() {
        let servers = &cfg.dns[..cfg.dns.len().min(127)];
        m.push(25);
        m.push(1 + 2 * servers.len() as u8);
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&rdnss_lifetime(cfg.interval).to_be_bytes());
        for server in servers {
            m.extend_from_slice(&server.octets());
        }
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

/// RFC 8106 asks for at least three advertisement intervals, so one lost advertisement does not
/// expire the servers.
fn rdnss_lifetime(interval: u64) -> u32 {
    u32::try_from(interval.saturating_mul(3)).unwrap_or(u32::MAX)
}

#[cfg_attr(not(test), allow(dead_code))]
/// Includes the pseudo-header.
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
/// Every option length must walk exactly to the end; a zero length or leftover bytes fail it.
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
/// Hop limit 255 is the only proof the packet crossed no router; without it, the source scope, and
/// the checksum, off-link senders could drive this server.
///
/// An unspecified source must not carry a link-layer address option, which the spec forbids.
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
/// Option 1 holds only a 6-byte Ethernet address, so devices with other lengths are filtered here.
/// An all-zero address means none and is left out.
///
/// `text` is colon-separated hex. None on a wrong digit or group count, or all zeros.
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
/// With a size cap.
fn read_sysfs_entry(path: &std::path::Path) -> Option<String> {
    use std::io::Read;

    /// Neither an interface index nor an address is longer.
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
/// Reads sysfs: an ioctl would need the request number and struct offsets pinned by hand, and those
/// vary by architecture. `interface_index` 0 means no device was chosen. None when the device or
/// its address cannot be found.
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

/// Does not start without an interval or a prefix.
pub fn spawn_ra(
    cfg: RaConfig,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<Option<std::thread::JoinHandle<()>>> {
    if cfg.interval == 0 || cfg.prefix.is_unspecified() {
        return Ok(None);
    }

    // With the link-layer address, hosts use the default route without a neighbor solicitation
    // round trip.
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
mod linux {
    use super::{build_ra, valid_router_solicitation_context, RaConfig};
    use std::net::Ipv6Addr;
    use std::os::raw::{c_int, c_void};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// Anyone on the link can trigger solicited advertisements, so failures can be just as
    /// frequent; only powers of two are logged, so logging adds no load.
    static SEND_FAILURES: AtomicU64 = AtomicU64::new(0);

    const AF_INET6: c_int = 10;
    const SOCK_RAW: c_int = 3;
    const IPPROTO_ICMPV6: c_int = 58;
    const IPPROTO_IPV6: c_int = 41;
    const IPV6_MULTICAST_HOPS: c_int = 18;
    const IPV6_MULTICAST_IF: c_int = 17;
    const IPV6_ADD_MEMBERSHIP: c_int = 20;
    const IPV6_RECVPKTINFO: c_int = 49;
    const IPV6_PKTINFO: c_int = 50;
    const IPV6_RECVHOPLIMIT: c_int = 51;
    const IPV6_HOPLIMIT: c_int = 52;
    const SOL_SOCKET: c_int = 1;
    /// Wakes the receive so the shutdown signal is checked.
    const SO_RCVTIMEO: c_int = 20;

    #[repr(C)]
    struct Iovec {
        iov_base: *mut c_void,
        iov_len: usize,
    }

    #[repr(C)]
    struct Msghdr {
        msg_name: *mut c_void,
        msg_namelen: u32,
        msg_iov: *mut Iovec,
        msg_iovlen: usize,
        msg_control: *mut c_void,
        msg_controllen: usize,
        msg_flags: c_int,
    }

    #[repr(C)]
    struct Cmsghdr {
        cmsg_len: usize,
        cmsg_level: c_int,
        cmsg_type: c_int,
    }

    #[repr(C)]
    struct Ipv6Mreq {
        /// 0 lets the kernel choose.
        multiaddr: [u8; 16],
        interface: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct SockaddrIn6 {
        sin6_family: u16,
        sin6_port: u16,
        sin6_flowinfo: u32,
        sin6_addr: [u8; 16],
        sin6_scope_id: u32,
    }

    extern "C" {
        fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
        fn setsockopt(
            fd: c_int,
            level: c_int,
            optname: c_int,
            optval: *const c_void,
            optlen: u32,
        ) -> c_int;
        fn sendto(
            fd: c_int,
            buf: *const c_void,
            len: usize,
            flags: c_int,
            addr: *const c_void,
            addrlen: u32,
        ) -> isize;
        fn recvmsg(fd: c_int, msg: *mut Msghdr, flags: c_int) -> isize;
        fn close(fd: c_int) -> c_int;
    }

    fn cmsg_align(length: usize) -> usize {
        let align = std::mem::size_of::<usize>();
        (length + align - 1) & !(align - 1)
    }

    /// ff02::1 on this interface; advertisements go here.
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

    /// Receives one router solicitation and decides whether to answer it. Truncated messages or
    /// control data are dropped: trusting them would pass the checks with the hop limit or
    /// destination missing.
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

    /// Advertises every interval and answers solicitations in between. When the options it needs
    /// cannot be set, it stops answering solicitations and only advertises periodically.
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
            // Router solicitations go to ff02::2, which hosts with forwarding off do not join.
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
mod tests {
    use super::*;

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
            dns: Vec::new(),
            source_mac: Some([0x02, 0, 0, 0, 0, 0x01]),
            interval: 600,
            interface_index: 2,
        }
    }

    /// The option of `kind` after the 16-byte RA header.
    fn option(m: &[u8], kind: u8) -> Option<&[u8]> {
        let mut rest = &m[16..];
        while rest.len() >= 2 {
            let len = usize::from(rest[1]) * 8;
            assert!(len > 0 && len <= rest.len(), "option walks to the end");
            if rest[0] == kind {
                return Some(&rest[..len]);
            }
            rest = &rest[len..];
        }
        None
    }

    #[test]
    /// Without it, hosts that do not use DHCPv6 learn no DNS server from this router.
    fn rdnss_carries_the_servers_for_three_intervals() {
        assert!(option(&build_ra(&cfg()), 25).is_none());

        let mut c = cfg();
        c.dns = vec!["2001:db8::53".parse().unwrap(), "fd00::53".parse().unwrap()];
        let m = build_ra(&c);
        let rdnss = option(&m, 25).expect("RDNSS");
        assert_eq!(rdnss.len(), 40);
        assert_eq!(rdnss[1], 5);
        assert_eq!(&rdnss[2..4], &[0, 0]);
        assert_eq!(u32::from_be_bytes(rdnss[4..8].try_into().unwrap()), 1_800);
        assert_eq!(&rdnss[8..24], &c.dns[0].octets());
        assert_eq!(&rdnss[24..40], &c.dns[1].octets());
        assert!(option(&m, 3).is_some(), "the prefix still follows");
    }

    #[test]
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
    fn ra_managed_flag() {
        let mut c = cfg();
        c.managed = true;
        c.other = false;
        let m = build_ra(&c);
        assert_eq!(m[5], 0b1000_0000, "M=1,O=0");
    }

    #[test]
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
    fn ra_omits_optional_options() {
        let mut c = cfg();
        c.mtu = None;
        c.source_mac = None;
        let m = build_ra(&c);

        assert_eq!(m.len(), 48);
        assert_eq!(m[16], 3, "PIO가 헤더 바로 뒤");
    }

    #[test]
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
    fn link_layer_address_rejects_unusable_forms() {
        // Devices without a link-layer address read as all zeros; advertising that would be wrong.
        assert_eq!(parse_link_layer_address("00:00:00:00:00:00"), None);
        // Tunnels have 4 bytes and InfiniBand 20, which the option cannot hold.
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
    fn interface_mac_needs_an_explicit_index() {
        assert_eq!(interface_mac(0), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    /// Finds an Ethernet device on this host, reads its index and address, and checks that the
    /// lookup by that index matches. Skipped where there is no such device.
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
    fn detects_router_solicitation() {
        assert!(is_router_solicitation(&[133, 0, 0, 0, 0, 0, 0, 0]));
        assert!(!is_router_solicitation(&[134, 0, 0, 0]));
        assert!(!is_router_solicitation(&[]));
    }
}

#[cfg(test)]
mod fuzz_tests {
    use super::*;

    #[test]
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
