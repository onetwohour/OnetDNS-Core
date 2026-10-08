/*!
 * @brief 주소를 아직 설정하지 않은 DHCPv4 클라이언트에 chaddr로 직접 답한다.
 *
 * @details Linux는 Ethernet/IP/UDP 프레임을 직접 내보내 커널 이웃표를 건드리지 않는다.
 *          Windows는 raw Ethernet 송신 API가 없으므로 IP Helper로 대상 ARP 항목을
 *          전송 동안만 고정한다.
 */

use std::io;
use std::net::{Ipv4Addr, UdpSocket};

/** @brief 초기 클라이언트에 IP unicast와 Ethernet chaddr 조합으로 DHCP 응답을 보낸다. */
pub fn send_initial_unicast(
    socket: &UdpSocket,
    server_ip: Ipv4Addr,
    server_port: u16,
    target_ip: Ipv4Addr,
    target_mac: [u8; 6],
    payload: &[u8],
) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let _ = socket;
        linux::send(server_ip, server_port, target_ip, target_mac, payload)
    }
    #[cfg(windows)]
    {
        let _ = server_port;
        windows::send(socket, server_ip, target_ip, target_mac, payload)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (
            socket,
            server_ip,
            server_port,
            target_ip,
            target_mac,
            payload,
        );
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "This operating system has no DHCPv4 L2 unicast sender",
        ))
    }
}

/**
 * @brief DHCP 요청을 받을 소켓을 연다.
 *
 * @details 0.0.0.0에 묶은 소켓은 모든 인터페이스의 방송을 받으므로, 그대로 두면 이 서버가
 *          맡지 않은 망의 기기에까지 답한다. 그 망의 주소는 이 서버의 범위 밖이라 NAK로
 *          끝나고, NAK를 받은 기기는 쓰던 주소를 버린다. Windows는 서버 주소에 묶은 소켓이
 *          그 인터페이스로 들어온 방송을 받으므로 서버 주소에 묶는다. Linux는 서버 주소에
 *          묶으면 방송을 받지 못하므로 0.0.0.0에 묶고, 받을 때 들어온 인터페이스를 함께 읽는다.
 */
pub fn bind_server_socket(server_ip: Ipv4Addr, port: u16) -> io::Result<UdpSocket> {
    #[cfg(windows)]
    let socket = onetdns_core::udp::bind((server_ip, port))?;
    #[cfg(not(windows))]
    let socket = onetdns_core::udp::bind((Ipv4Addr::UNSPECIFIED, port))?;
    #[cfg(target_os = "linux")]
    linux::report_arrival_interface(&socket)?;
    #[cfg(not(windows))]
    let _ = server_ip;
    Ok(socket)
}

/**
 * @brief 요청 하나와 그 요청이 들어온 인터페이스 번호를 받는다.
 * @return 들어온 인터페이스를 알 수 없는 플랫폼이면 번호는 없다.
 * @retval Err 한도 안에 오지 않았으면 종류가 WouldBlock 이나 TimedOut 인 오류.
 */
pub fn recv_request(
    socket: &UdpSocket,
    wait: onetdns_core::udp::RecvWait,
    buf: &mut [u8],
) -> io::Result<(usize, Option<u32>)> {
    #[cfg(target_os = "linux")]
    {
        let _ = wait;
        linux::recv_with_interface(socket, buf)
    }
    #[cfg(not(target_os = "linux"))]
    {
        wait.recv_from(socket, buf).map(|(n, _)| (n, None))
    }
}

/** @brief 서버 주소가 붙은 인터페이스 번호. 알 수 없는 플랫폼이면 없다. */
pub fn served_interface(server_ip: Ipv4Addr) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        linux::interface_index(server_ip).ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = server_ip;
        None
    }
}

/**
 * @brief 서버 주소가 붙은 인터페이스로 DHCP 방송을 보낸다.
 * @details 0.0.0.0에 묶인 소켓으로 255.255.255.255에 보내면 커널이 라우팅 표로 나갈 곳을
 *          고른다. 기본 경로가 없는 LAN 전용 장비에서는 전송이 실패하고, WAN과 LAN을 함께
 *          가진 장비에서는 OFFER가 클라이언트가 없는 기본 경로 쪽으로 나간다. Linux는 서버
 *          주소의 인터페이스를 찾아 그리로 내보낸다. Windows는 소켓을 서버 주소에 묶으므로
 *          그 주소의 인터페이스로 나간다. 서버 주소가 로컬에 없거나, 그 인터페이스가 방송을
 *          실어 나르지 못하거나, 다른 운영체제면 커널의 선택에 맡긴다.
 */
pub fn send_broadcast(
    socket: &UdpSocket,
    server_ip: Ipv4Addr,
    port: u16,
    payload: &[u8],
) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    if let Ok(index) = linux::interface_index(server_ip) {
        if linux::send_on_interface(socket, index, server_ip, port, payload).is_ok() {
            return Ok(());
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = server_ip;
    socket
        .send_to(payload, (Ipv4Addr::BROADCAST, port))
        .map(|_| ())
}

#[cfg(any(target_os = "linux", test))]
/** @brief 16비트 1의 보수 체크섬. IPv4 헤더와 UDP pseudo-header에 함께 쓴다. */
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    let mut high = None;
    for part in parts {
        for &byte in *part {
            if let Some(first) = high.take() {
                sum = sum.wrapping_add(u32::from(u16::from_be_bytes([first, byte])));
            } else {
                high = Some(byte);
            }
        }
    }
    if let Some(first) = high {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([first, 0])));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).expect("The checksum fits in 16 bits after the carry fold")
}

#[cfg(any(target_os = "linux", test))]
/** @brief Ethernet II + IPv4 + UDP 프레임을 만든다. */
fn build_frame(
    source_mac: [u8; 6],
    target_mac: [u8; 6],
    server_ip: Ipv4Addr,
    server_port: u16,
    target_ip: Ipv4Addr,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    const ETHERNET_LEN: usize = 14;
    const IPV4_LEN: usize = 20;
    const UDP_LEN: usize = 8;
    let udp_len = UDP_LEN
        .checked_add(payload.len())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "DHCP UDP reply is too large")
        })?;
    let ip_len = u16::try_from(IPV4_LEN + usize::from(udp_len))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DHCP IPv4 reply is too large"))?;
    let mut frame = vec![0u8; ETHERNET_LEN + usize::from(ip_len)];

    frame[..6].copy_from_slice(&target_mac);
    frame[6..12].copy_from_slice(&source_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    let ip = &mut frame[ETHERNET_LEN..ETHERNET_LEN + IPV4_LEN];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&ip_len.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&server_ip.octets());
    ip[16..20].copy_from_slice(&target_ip.octets());
    let ip_checksum = checksum(&[ip]);
    ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp_start = ETHERNET_LEN + IPV4_LEN;
    let udp = &mut frame[udp_start..];
    udp[..2].copy_from_slice(&server_port.to_be_bytes());
    udp[2..4].copy_from_slice(&68u16.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[UDP_LEN..].copy_from_slice(payload);
    let source_octets = server_ip.octets();
    let target_octets = target_ip.octets();
    let udp_len_bytes = udp_len.to_be_bytes();
    let udp_checksum = checksum(&[
        &source_octets,
        &target_octets,
        &[0, 17],
        &udp_len_bytes,
        udp,
    ]);
    udp[6..8].copy_from_slice(
        &if udp_checksum == 0 {
            0xffffu16
        } else {
            udp_checksum
        }
        .to_be_bytes(),
    );
    Ok(frame)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::CStr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    /** @brief 설정한 서버 주소가 속한 인터페이스 번호. */
    pub(super) fn interface_index(server_ip: Ipv4Addr) -> io::Result<u32> {
        interface_name(&Addrs::load()?, server_ip).map(|(_, index)| index)
    }

    /** @brief 받는 데이터그램마다 들어온 인터페이스를 함께 알려 달라고 한다. */
    pub(super) fn report_arrival_interface(socket: &UdpSocket) -> io::Result<()> {
        let on: libc::c_int = 1;
        /* @safety on은 호출 동안 살아 있는 int이고 길이를 정확히 넘긴다. */
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                (&raw const on).cast(),
                libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
                    .expect("The size of int fits in socklen_t"),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /**
     * @brief 데이터그램 하나와 들어온 인터페이스 번호를 받는다.
     * @details 소켓 수신 한도에 걸리면 WouldBlock 이나 TimedOut 으로 끝난다.
     */
    pub(super) fn recv_with_interface(
        socket: &UdpSocket,
        buf: &mut [u8],
    ) -> io::Result<(usize, Option<u32>)> {
        let info_len = u32::try_from(std::mem::size_of::<libc::in_pktinfo>())
            .expect("The size of in_pktinfo fits in u32");
        /* @safety CMSG_SPACE는 길이만 계산한다. */
        let space = unsafe { libc::CMSG_SPACE(info_len) } as usize;
        let mut control = vec![0u8; space];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        /* @safety 모든 0 비트가 msghdr의 유효한 초기 상태다. */
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &raw mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = space as _;
        /* @safety message가 가리키는 버퍼와 제어 자료는 호출 동안 모두 살아 있다. */
        let received = unsafe { libc::recvmsg(socket.as_raw_fd(), &raw mut message, 0) };
        let len = usize::try_from(received).map_err(|_| io::Error::last_os_error())?;
        let mut interface = None;
        /* @safety 커널이 채운 제어 자료를 CMSG 매크로로만 따라가며 msg_controllen 안에서 읽는다. */
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&raw const message);
            while !header.is_null() {
                if (*header).cmsg_level == libc::IPPROTO_IP
                    && (*header).cmsg_type == libc::IP_PKTINFO
                {
                    let info = std::ptr::read_unaligned(
                        libc::CMSG_DATA(header).cast::<libc::in_pktinfo>(),
                    );
                    interface = u32::try_from(info.ipi_ifindex).ok();
                }
                header = libc::CMSG_NXTHDR(&raw const message, header);
            }
        }
        Ok((len, interface))
    }

    /**
     * @brief 지정한 인터페이스로 방송을 보낸다.
     * @details IP_PKTINFO의 인터페이스 번호가 나갈 곳을 정하므로 라우팅 표에 방송 경로가
     *          없어도 된다. 원본 주소는 서버 주소로 둔다.
     */
    pub(super) fn send_on_interface(
        socket: &UdpSocket,
        index: u32,
        server_ip: Ipv4Addr,
        port: u16,
        payload: &[u8],
    ) -> io::Result<()> {
        /* @safety 모든 0 비트가 sockaddr_in의 유효한 초기 상태다. */
        let mut destination: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        destination.sin_family = libc::AF_INET as libc::sa_family_t;
        destination.sin_port = port.to_be();
        destination.sin_addr.s_addr = u32::from_ne_bytes(Ipv4Addr::BROADCAST.octets());
        let info = libc::in_pktinfo {
            ipi_ifindex: i32::try_from(index).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "Interface index is too large")
            })?,
            ipi_spec_dst: libc::in_addr {
                s_addr: u32::from_ne_bytes(server_ip.octets()),
            },
            ipi_addr: libc::in_addr { s_addr: 0 },
        };
        let info_len = u32::try_from(std::mem::size_of::<libc::in_pktinfo>())
            .expect("The size of in_pktinfo fits in u32");
        /* @safety CMSG_SPACE는 길이만 계산한다. */
        let space = unsafe { libc::CMSG_SPACE(info_len) } as usize;
        let mut control = vec![0u8; space];
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        /* @safety 모든 0 비트가 msghdr의 유효한 초기 상태다. */
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_name = (&raw mut destination).cast();
        message.msg_namelen = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_in>())
            .expect("The size of sockaddr_in fits in socklen_t");
        message.msg_iov = &raw mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = space as _;
        /* @safety control은 CMSG_SPACE 크기로 잡았으므로 첫 헤더와 자료가 그 안에 들어간다. */
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&raw const message);
            (*header).cmsg_level = libc::IPPROTO_IP;
            (*header).cmsg_type = libc::IP_PKTINFO;
            (*header).cmsg_len = libc::CMSG_LEN(info_len) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<libc::in_pktinfo>(), info);
        }
        /* @safety message가 가리키는 주소, 버퍼, 제어 자료는 호출 동안 모두 살아 있다. */
        let sent = unsafe { libc::sendmsg(socket.as_raw_fd(), &raw const message, 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if usize::try_from(sent).ok() != Some(payload.len()) {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "DHCP broadcast was only partly sent",
            ));
        }
        Ok(())
    }

    /** @brief getifaddrs가 넘긴 목록. 떨어질 때 한 번 해제한다. */
    struct Addrs(*mut libc::ifaddrs);

    impl Addrs {
        /** @brief 지금 인터페이스 주소 목록을 읽는다. */
        fn load() -> io::Result<Self> {
            let mut head = std::ptr::null_mut();
            /* @safety head는 libc가 채우는 출력 포인터이며 성공 뒤 Drop이 한 번 해제한다. */
            if unsafe { libc::getifaddrs(&mut head) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(head))
        }

        /** @brief 목록의 노드들. 목록이 살아 있는 동안만 유효하다. */
        fn iter(&self) -> impl Iterator<Item = &libc::ifaddrs> + '_ {
            let mut cursor = self.0;
            std::iter::from_fn(move || {
                if cursor.is_null() {
                    return None;
                }
                /* @safety getifaddrs 목록의 노드는 free 전까지 유효하다. */
                let item = unsafe { &*cursor };
                cursor = item.ifa_next;
                Some(item)
            })
        }
    }

    impl Drop for Addrs {
        fn drop(&mut self) {
            /* @safety getifaddrs가 성공해 소유한 목록을 정확히 한 번 해제한다. */
            unsafe { libc::freeifaddrs(self.0) };
        }
    }

    /** @brief 설정한 서버 주소가 붙은 인터페이스의 이름과 번호. */
    fn interface_name(addrs: &Addrs, server_ip: Ipv4Addr) -> io::Result<(std::ffi::CString, u32)> {
        let name = addrs
            .iter()
            .find(|item| {
                !item.ifa_addr.is_null()
                    /* @safety ifa_addr의 family 필드는 모든 sockaddr 변형의 공통 헤더다. */
                    && unsafe { (*item.ifa_addr).sa_family } == libc::AF_INET as libc::sa_family_t
                    /* @safety family가 AF_INET임을 확인했다. */
                    && unsafe { (*item.ifa_addr.cast::<libc::sockaddr_in>()).sin_addr.s_addr }
                        .to_ne_bytes()
                        == server_ip.octets()
            })
            /* @safety ifa_name은 getifaddrs 계약상 NUL 종료 문자열이다. */
            .map(|item| unsafe { CStr::from_ptr(item.ifa_name) }.to_owned())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("DHCP server address {server_ip} is not on any local interface"),
                )
            })?;
        /* @safety name은 NUL 종료 문자열이며 libc는 읽기만 한다. */
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((name, index))
    }

    /** @brief 설정한 서버 주소가 속한 Ethernet 인터페이스의 번호·MAC을 찾는다. */
    fn interface(server_ip: Ipv4Addr) -> io::Result<(u32, [u8; 6])> {
        let addrs = Addrs::load()?;
        let (name, index) = interface_name(&addrs, server_ip)?;
        for item in addrs.iter() {
            if !item.ifa_addr.is_null()
                /* @safety sockaddr 공통 헤더만 읽는다. */
                && unsafe { (*item.ifa_addr).sa_family } == libc::AF_PACKET as libc::sa_family_t
                /* @safety 양쪽 포인터 모두 유효한 NUL 종료 인터페이스 이름이다. */
                && unsafe { libc::strcmp(item.ifa_name, name.as_ptr()) } == 0
            {
                /* @safety family가 AF_PACKET임을 확인했다. */
                let link = unsafe { &*item.ifa_addr.cast::<libc::sockaddr_ll>() };
                if link.sll_halen >= 6 {
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&link.sll_addr[..6]);
                    if mac != [0; 6] && mac[0] & 1 == 0 {
                        return Ok((index, mac));
                    }
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!(
                "Could not find the Ethernet MAC of DHCP interface {}",
                name.to_string_lossy()
            ),
        ))
    }

    pub(super) fn send(
        server_ip: Ipv4Addr,
        server_port: u16,
        target_ip: Ipv4Addr,
        target_mac: [u8; 6],
        payload: &[u8],
    ) -> io::Result<()> {
        const ETH_P_IP: u16 = 0x0800;
        let (interface_index, source_mac) = interface(server_ip)?;
        let frame = build_frame(
            source_mac,
            target_mac,
            server_ip,
            server_port,
            target_ip,
            payload,
        )?;
        /* @safety 인자는 Linux AF_PACKET socket 계약의 정수 값이다. */
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                i32::from(ETH_P_IP.to_be()),
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        /* @safety 성공한 socket 호출이 넘긴 fd의 단독 소유권을 받는다. */
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        /* @safety 모든 0 비트가 sockaddr_ll의 유효한 초기 상태다. */
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = libc::AF_PACKET as u16;
        address.sll_protocol = ETH_P_IP.to_be();
        address.sll_ifindex = i32::try_from(interface_index).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "Interface index is too large")
        })?;
        address.sll_halen = 6;
        address.sll_addr[..6].copy_from_slice(&target_mac);
        /* @safety frame과 sockaddr_ll은 호출 동안 살아 있고 길이는 각각의 실제 크기다. */
        let sent = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                frame.as_ptr().cast(),
                frame.len(),
                0,
                (&raw const address).cast::<libc::sockaddr>(),
                libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_ll>())
                    .expect("The size of sockaddr_ll fits in socklen_t"),
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if usize::try_from(sent).ok() != Some(frame.len()) {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "DHCP Ethernet frame was only partly sent",
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::os::windows::io::{AsRawSocket, RawSocket};

    const NO_ERROR: u32 = 0;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const ERROR_NO_DATA: u32 = 232;
    const MIB_IPNET_TYPE_STATIC: u32 = 4;
    const IPPROTO_IP: i32 = 0;
    const IP_UNICAST_IF: i32 = 31;
    const SOCKET_ERROR: i32 = -1;

    #[repr(C)]
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct MibIpNetRow {
        index: u32,
        physical_length: u32,
        physical: [u8; 8],
        address: u32,
        kind: u32,
    }

    #[repr(C)]
    struct MibIpNetTable {
        count: u32,
        rows: [MibIpNetRow; 1],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MibIpAddrRow {
        address: u32,
        index: u32,
        mask: u32,
        broadcast: u32,
        reassembly_size: u32,
        unused: u16,
        kind: u16,
    }

    #[repr(C)]
    struct MibIpAddrTable {
        count: u32,
        rows: [MibIpAddrRow; 1],
    }

    #[link(name = "iphlpapi")]
    #[allow(non_snake_case)]
    unsafe extern "system" {
        fn GetIpNetTable(table: *mut MibIpNetTable, size: *mut u32, ordered: i32) -> u32;
        fn GetIpAddrTable(table: *mut MibIpAddrTable, size: *mut u32, ordered: i32) -> u32;
        fn CreateIpNetEntry(row: *const MibIpNetRow) -> u32;
        fn SetIpNetEntry(row: *const MibIpNetRow) -> u32;
        fn DeleteIpNetEntry(row: *const MibIpNetRow) -> u32;
    }

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn getsockopt(
            socket: RawSocket,
            level: i32,
            option: i32,
            value: *mut i8,
            length: *mut i32,
        ) -> i32;
        fn setsockopt(
            socket: RawSocket,
            level: i32,
            option: i32,
            value: *const i8,
            length: i32,
        ) -> i32;
        fn WSAGetLastError() -> i32;
    }

    fn error(code: u32) -> io::Error {
        io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX))
    }

    fn socket_error() -> io::Error {
        /* @safety WSAGetLastError는 호출 스레드의 정수 오류 코드만 반환한다. */
        io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
    }

    /** @brief IP Helper의 count+가변 행 테이블을 경계 검사해 소유 벡터로 옮긴다. */
    fn table_rows<Row: Copy>(
        mut read: impl FnMut(*mut std::ffi::c_void, *mut u32) -> u32,
    ) -> io::Result<Vec<Row>> {
        let mut size = 0u32;
        let first = read(std::ptr::null_mut(), &mut size);
        if first == ERROR_NO_DATA {
            return Ok(Vec::new());
        }
        if first != ERROR_INSUFFICIENT_BUFFER && first != NO_ERROR {
            return Err(error(first));
        }
        let row_offset = std::mem::size_of::<u32>().div_ceil(std::mem::align_of::<Row>())
            * std::mem::align_of::<Row>();
        for _ in 0..3 {
            let bytes = usize::try_from(size)
                .ok()
                .filter(|value| *value >= row_offset)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Windows IP Helper table size is invalid",
                    )
                })?;
            let words = bytes.div_ceil(std::mem::size_of::<usize>());
            let mut storage = vec![0usize; words];
            let table = storage.as_mut_ptr().cast::<std::ffi::c_void>();
            let mut actual = size;
            let result = read(table, &mut actual);
            if result == ERROR_NO_DATA {
                return Ok(Vec::new());
            }
            if result == ERROR_INSUFFICIENT_BUFFER {
                size = actual;
                continue;
            }
            if result != NO_ERROR {
                return Err(error(result));
            }
            /* @safety API 성공 뒤 최소 4바이트 count가 초기화됐다. */
            let count = unsafe { *table.cast::<u32>() as usize };
            let required = count
                .checked_mul(std::mem::size_of::<Row>())
                .and_then(|value| value.checked_add(row_offset))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Windows IP Helper table has too many entries",
                    )
                })?;
            if required > usize::try_from(actual).unwrap_or(0)
                || required > storage.len() * std::mem::size_of::<usize>()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Windows IP Helper table is truncated",
                ));
            }
            let rows = (table as *const u8).wrapping_add(row_offset).cast::<Row>();
            let mut output = Vec::with_capacity(count);
            for item in 0..count {
                /* @safety 위의 checked 범위 검사가 count개 행 전체를 보장한다. */
                output.push(unsafe { *rows.add(item) });
            }
            return Ok(output);
        }
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "Windows IP Helper table kept growing while being read",
        ))
    }

    fn existing(index: u32, address: u32) -> io::Result<Option<MibIpNetRow>> {
        table_rows::<MibIpNetRow>(|table, size| {
            /* @safety table_rows가 버퍼와 크기의 수명·범위를 보장한다. */
            unsafe { GetIpNetTable(table.cast(), size, 0) }
        })
        .map(|rows| {
            rows.into_iter()
                .find(|row| row.index == index && row.address == address)
        })
    }

    fn interface_for(server_ip: Ipv4Addr) -> io::Result<u32> {
        let address = u32::from_ne_bytes(server_ip.octets());
        table_rows::<MibIpAddrRow>(|table, size| {
            /* @safety table_rows가 버퍼와 크기의 수명·범위를 보장한다. */
            unsafe { GetIpAddrTable(table.cast(), size, 0) }
        })?
        .into_iter()
        .find(|row| row.address == address)
        .map(|row| row.index)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("DHCP server address {server_ip} is not on any local interface"),
            )
        })
    }

    struct NeighborGuard {
        temporary: MibIpNetRow,
        previous: Option<MibIpNetRow>,
    }

    impl Drop for NeighborGuard {
        fn drop(&mut self) {
            let current = match existing(self.temporary.index, self.temporary.address) {
                Ok(current) => current,
                Err(error) => {
                    onetdns_core::warn!(
                        event = "dhcp4.neighbor_restore_check_failed",
                        ip = %Ipv4Addr::from(self.temporary.address.to_ne_bytes()),
                        interface = self.temporary.index,
                        %error,
                        "Could not check who owns the Windows ARP entry after an initial DHCP unicast; leaving it alone"
                    );
                    return;
                }
            };
            if !current.is_some_and(|row| {
                let length = usize::try_from(row.physical_length).unwrap_or(usize::MAX);
                row.index == self.temporary.index
                    && row.address == self.temporary.address
                    && row.kind == self.temporary.kind
                    && row.physical_length == self.temporary.physical_length
                    && length <= row.physical.len()
                    && row.physical[..length] == self.temporary.physical[..length]
            }) {
                return;
            }
            /* @safety 두 함수 모두 완전히 초기화된 MIB_IPNETROW를 읽기만 한다. */
            let result = unsafe {
                match self.previous {
                    Some(previous) => SetIpNetEntry(&raw const previous),
                    None => DeleteIpNetEntry(&raw const self.temporary),
                }
            };
            if result != NO_ERROR {
                onetdns_core::warn!(
                    event = "dhcp4.neighbor_restore_failed",
                    ip = %Ipv4Addr::from(self.temporary.address.to_ne_bytes()),
                    interface = self.temporary.index,
                    error = %error(result),
                    "Could not restore the Windows ARP entry after an initial DHCP unicast"
                );
            }
        }
    }

    struct InterfaceGuard {
        socket: RawSocket,
        previous: u32,
    }

    impl Drop for InterfaceGuard {
        fn drop(&mut self) {
            let previous = self.previous.to_be();
            /* @safety socket은 UdpSocket보다 짧게 살고 option은 4바이트 DWORD다. */
            if unsafe {
                setsockopt(
                    self.socket,
                    IPPROTO_IP,
                    IP_UNICAST_IF,
                    (&raw const previous).cast(),
                    i32::try_from(std::mem::size_of::<u32>())
                        .expect("The size of DWORD fits in i32"),
                )
            } == SOCKET_ERROR
            {
                onetdns_core::warn!(
                    event = "dhcp4.interface_restore_failed",
                    interface = self.previous,
                    error = %socket_error(),
                    "Could not restore the Windows outgoing interface after an initial DHCP unicast"
                );
            }
        }
    }

    fn current_interface(socket: RawSocket) -> io::Result<u32> {
        let mut previous = 0u32;
        let mut length =
            i32::try_from(std::mem::size_of::<u32>()).expect("The size of DWORD fits in i32");
        /* @safety previous와 length는 4바이트 socket option의 유효한 출력 버퍼다. */
        if unsafe {
            getsockopt(
                socket,
                IPPROTO_IP,
                IP_UNICAST_IF,
                (&raw mut previous).cast(),
                &mut length,
            )
        } == SOCKET_ERROR
        {
            return Err(socket_error());
        }
        if length
            != i32::try_from(std::mem::size_of::<u32>()).expect("The size of DWORD fits in i32")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows IP_UNICAST_IF value has an invalid size",
            ));
        }
        Ok(previous)
    }

    fn select_interface(socket: &UdpSocket, index: u32) -> io::Result<InterfaceGuard> {
        if index == 0 || index > 0x00ff_ffff {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows IPv4 interface index does not fit in 24 bits",
            ));
        }
        let socket = socket.as_raw_socket();
        let previous = current_interface(socket)?;
        let network_index = index.to_be();
        /* @safety network_index는 Microsoft가 요구하는 network-byte-order DWORD다. */
        if unsafe {
            setsockopt(
                socket,
                IPPROTO_IP,
                IP_UNICAST_IF,
                (&raw const network_index).cast(),
                i32::try_from(std::mem::size_of::<u32>()).expect("The size of DWORD fits in i32"),
            )
        } == SOCKET_ERROR
        {
            return Err(socket_error());
        }
        Ok(InterfaceGuard { socket, previous })
    }

    fn pin(index: u32, target_ip: Ipv4Addr, target_mac: [u8; 6]) -> io::Result<NeighborGuard> {
        let address = u32::from_ne_bytes(target_ip.octets());
        let previous = existing(index, address)?;
        let mut physical = [0u8; 8];
        physical[..6].copy_from_slice(&target_mac);
        let temporary = MibIpNetRow {
            index,
            physical_length: 6,
            physical,
            address,
            kind: MIB_IPNET_TYPE_STATIC,
        };
        /* @safety temporary는 API가 요구하는 모든 필드를 채운 MIB_IPNETROW다. */
        let result = unsafe {
            if previous.is_some() {
                SetIpNetEntry(&raw const temporary)
            } else {
                CreateIpNetEntry(&raw const temporary)
            }
        };
        if result != NO_ERROR {
            return Err(error(result));
        }
        Ok(NeighborGuard {
            temporary,
            previous,
        })
    }

    pub(super) fn send(
        socket: &UdpSocket,
        server_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        target_mac: [u8; 6],
        payload: &[u8],
    ) -> io::Result<()> {
        let interface = interface_for(server_ip)?;
        let _neighbor = pin(interface, target_ip, target_mac)?;
        let _interface = select_interface(socket, interface)?;
        let sent = socket.send_to(payload, (target_ip, 68))?;
        if sent != payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "DHCP UDP reply was only partly sent",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn windows_arp_row_abi_matches_ip_helper() {
            assert_eq!(std::mem::size_of::<MibIpNetRow>(), 24);
            assert_eq!(std::mem::align_of::<MibIpNetRow>(), 4);
            assert_eq!(std::mem::size_of::<MibIpAddrRow>(), 24);
            assert_eq!(std::mem::align_of::<MibIpAddrRow>(), 4);
            assert_eq!(std::mem::offset_of!(MibIpNetTable, rows), 4);
            assert_eq!(std::mem::offset_of!(MibIpAddrTable, rows), 4);
        }

        #[test]
        fn windows_server_interface_selection_roundtrips_socket_option() {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let raw = socket.as_raw_socket();
            let before = current_interface(raw).unwrap();
            let interface = interface_for(Ipv4Addr::LOCALHOST).unwrap();
            {
                let _guard = select_interface(&socket, interface).unwrap();
                assert_eq!(current_interface(raw).unwrap(), interface);
            }
            assert_eq!(current_interface(raw).unwrap(), before);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    /**
     * @brief 방송을 내보낼 인터페이스를 서버 주소로 찾는지.
     * @details 이 번호가 틀리면 OFFER가 클라이언트가 없는 쪽으로 나가거나, 기본 경로가 없는
     *          장비에서 전송 자체가 실패한다.
     */
    fn broadcast_interface_is_the_one_holding_the_server_address() {
        /* @safety 리터럴은 NUL 종료 문자열이다. */
        let loopback = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
        assert_ne!(loopback, 0);
        assert_eq!(
            linux::interface_index(Ipv4Addr::LOCALHOST).unwrap(),
            loopback
        );
        assert_eq!(
            linux::interface_index(Ipv4Addr::new(192, 0, 2, 254))
                .unwrap_err()
                .kind(),
            io::ErrorKind::AddrNotAvailable
        );
    }

    #[test]
    fn ethernet_ipv4_udp_frame_has_valid_headers_and_checksums() {
        let source_mac = [0x02, 1, 2, 3, 4, 5];
        let target_mac = [0x02, 6, 7, 8, 9, 10];
        let server_ip = Ipv4Addr::new(192, 0, 2, 1);
        let target_ip = Ipv4Addr::new(192, 0, 2, 100);
        let payload = [1, 2, 3, 4, 5];
        let frame =
            build_frame(source_mac, target_mac, server_ip, 67, target_ip, &payload).unwrap();

        assert_eq!(&frame[..6], &target_mac);
        assert_eq!(&frame[6..12], &source_mac);
        assert_eq!(&frame[12..14], &0x0800u16.to_be_bytes());
        let ip = &frame[14..34];
        assert_eq!(ip[0], 0x45);
        assert_eq!(checksum(&[ip]), 0);
        assert_eq!(&ip[12..16], &server_ip.octets());
        assert_eq!(&ip[16..20], &target_ip.octets());
        let udp = &frame[34..];
        assert_eq!(&udp[..2], &67u16.to_be_bytes());
        assert_eq!(&udp[2..4], &68u16.to_be_bytes());
        assert_eq!(&udp[8..], &payload);
        let source_octets = server_ip.octets();
        let target_octets = target_ip.octets();
        let udp_len = u16::try_from(udp.len()).unwrap();
        let udp_len_bytes = udp_len.to_be_bytes();
        assert_eq!(
            checksum(&[
                &source_octets,
                &target_octets,
                &[0, 17],
                &udp_len_bytes,
                udp,
            ]),
            0
        );
    }
}
