//! Answers DHCPv4 clients that have no address yet, straight to their chaddr. Linux sends the
//! Ethernet, IP, and UDP frame itself and never touches the kernel neighbor table. Windows has no
//! raw Ethernet send API, so IP Helper pins the target's ARP entry for the duration of the send.

use std::io;
use std::net::{Ipv4Addr, UdpSocket};

/// IP unicast to the client's chaddr, before it has an address.
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

/// A socket bound to 0.0.0.0 receives broadcasts from every interface, and answering them would
/// reach devices on networks this server does not serve. Their addresses are outside its range, so
/// they get a NAK and drop the address they were using.
///
/// On Windows, a socket bound to the server address receives broadcasts arriving on that interface,
/// so it binds there. On Linux, a socket bound to the server address misses broadcasts, so it binds
/// to 0.0.0.0 and reads the arrival interface with each request.
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

/// The interface index is None where the platform cannot tell. Fails with WouldBlock or TimedOut
/// when nothing arrives in time.
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

/// Index of the interface holding the server address; None where the platform cannot tell.
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

/// Sent to 255.255.255.255 from a socket bound to 0.0.0.0, the kernel picks the way out from the
/// routing table: a LAN-only device without a default route fails the send, and a device with both
/// WAN and LAN sends the OFFER out the default route, away from the client.
///
/// Linux sends it out the interface holding the server address. Windows binds the socket to the
/// server address, so it leaves through that interface. When the address is not local, the
/// interface cannot carry broadcasts, or on other systems, the kernel chooses.
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
/// Ones' complement checksum, for the IPv4 header and the UDP pseudo-header.
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
/// Ethernet II, IPv4, and UDP.
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

    pub(super) fn interface_index(server_ip: Ipv4Addr) -> io::Result<u32> {
        interface_name(&Addrs::load()?, server_ip).map(|(_, index)| index)
    }

    /// Makes each received datagram report its arrival interface.
    pub(super) fn report_arrival_interface(socket: &UdpSocket) -> io::Result<()> {
        let on: libc::c_int = 1;
        // SAFETY: `on` is an int alive for the call, and its exact length is passed.
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

    /// Ends with WouldBlock or TimedOut at the socket receive timeout.
    pub(super) fn recv_with_interface(
        socket: &UdpSocket,
        buf: &mut [u8],
    ) -> io::Result<(usize, Option<u32>)> {
        let info_len = u32::try_from(std::mem::size_of::<libc::in_pktinfo>())
            .expect("The size of in_pktinfo fits in u32");
        // SAFETY: CMSG_SPACE only computes a length.
        let space = unsafe { libc::CMSG_SPACE(info_len) } as usize;
        let mut control = vec![0u8; space];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: All-zero bits are a valid initial msghdr.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &raw mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = space as _;
        // SAFETY: The buffers and control data `message` points to live for the whole call.
        let received = unsafe { libc::recvmsg(socket.as_raw_fd(), &raw mut message, 0) };
        let len = usize::try_from(received).map_err(|_| io::Error::last_os_error())?;
        let mut interface = None;
        // SAFETY: Kernel-filled control data is walked only with the CMSG macros, within
        // msg_controllen.
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

    /// The IP_PKTINFO interface index picks the way out, so no broadcast route is needed. The
    /// source address is the server address.
    pub(super) fn send_on_interface(
        socket: &UdpSocket,
        index: u32,
        server_ip: Ipv4Addr,
        port: u16,
        payload: &[u8],
    ) -> io::Result<()> {
        // SAFETY: All-zero bits are a valid initial sockaddr_in.
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
        // SAFETY: CMSG_SPACE only computes a length.
        let space = unsafe { libc::CMSG_SPACE(info_len) } as usize;
        let mut control = vec![0u8; space];
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        // SAFETY: All-zero bits are a valid initial msghdr.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_name = (&raw mut destination).cast();
        message.msg_namelen = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_in>())
            .expect("The size of sockaddr_in fits in socklen_t");
        message.msg_iov = &raw mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = space as _;
        // SAFETY: `control` was sized with CMSG_SPACE, so the first header and its data fit.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&raw const message);
            (*header).cmsg_level = libc::IPPROTO_IP;
            (*header).cmsg_type = libc::IP_PKTINFO;
            (*header).cmsg_len = libc::CMSG_LEN(info_len) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<libc::in_pktinfo>(), info);
        }
        // SAFETY: The address, buffer, and control data `message` points to live for the whole
        // call.
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

    /// The list from getifaddrs, freed once on drop.
    struct Addrs(*mut libc::ifaddrs);

    impl Addrs {
        fn load() -> io::Result<Self> {
            let mut head = std::ptr::null_mut();
            // SAFETY: `head` is an out pointer libc fills; on success, Drop frees it once.
            if unsafe { libc::getifaddrs(&mut head) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(head))
        }

        /// Nodes are valid only while the list lives.
        fn iter(&self) -> impl Iterator<Item = &libc::ifaddrs> + '_ {
            let mut cursor = self.0;
            std::iter::from_fn(move || {
                if cursor.is_null() {
                    return None;
                }
                // SAFETY: getifaddrs nodes stay valid until the list is freed.
                let item = unsafe { &*cursor };
                cursor = item.ifa_next;
                Some(item)
            })
        }
    }

    impl Drop for Addrs {
        fn drop(&mut self) {
            // SAFETY: Frees the list a successful getifaddrs returned, exactly once.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }

    fn interface_name(addrs: &Addrs, server_ip: Ipv4Addr) -> io::Result<(std::ffi::CString, u32)> {
        let name = addrs
            .iter()
            .find(|item| {
                !item.ifa_addr.is_null()
                    // SAFETY: sa_family is in the header every sockaddr variant shares.
                    && unsafe { (*item.ifa_addr).sa_family } == libc::AF_INET as libc::sa_family_t
                    // SAFETY: The family was checked to be AF_INET.
                    && unsafe { (*item.ifa_addr.cast::<libc::sockaddr_in>()).sin_addr.s_addr }
                        .to_ne_bytes()
                        == server_ip.octets()
            })
            // SAFETY: ifa_name is NUL-terminated per the getifaddrs contract.
            .map(|item| unsafe { CStr::from_ptr(item.ifa_name) }.to_owned())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("DHCP server address {server_ip} is not on any local interface"),
                )
            })?;
        // SAFETY: `name` is NUL-terminated, and libc only reads it.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((name, index))
    }

    /// Index and MAC of the Ethernet interface holding the server address.
    fn interface(server_ip: Ipv4Addr) -> io::Result<(u32, [u8; 6])> {
        let addrs = Addrs::load()?;
        let (name, index) = interface_name(&addrs, server_ip)?;
        for item in addrs.iter() {
            if !item.ifa_addr.is_null()
                // SAFETY: Reads only the common sockaddr header.
                && unsafe { (*item.ifa_addr).sa_family } == libc::AF_PACKET as libc::sa_family_t
                // SAFETY: Both pointers are valid NUL-terminated interface names.
                && unsafe { libc::strcmp(item.ifa_name, name.as_ptr()) } == 0
            {
                // SAFETY: The family was checked to be AF_PACKET.
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
        // SAFETY: The arguments are the integer values the Linux AF_PACKET socket call takes.
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
        // SAFETY: Takes sole ownership of the fd a successful socket call returned.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: All-zero bits are a valid initial sockaddr_ll.
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = libc::AF_PACKET as u16;
        address.sll_protocol = ETH_P_IP.to_be();
        address.sll_ifindex = i32::try_from(interface_index).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "Interface index is too large")
        })?;
        address.sll_halen = 6;
        address.sll_addr[..6].copy_from_slice(&target_mac);
        // SAFETY: `frame` and the sockaddr_ll live for the call, and each length is its real size.
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
        // SAFETY: WSAGetLastError only returns the calling thread's error code.
        io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
    }

    /// Copies an IP Helper count-plus-rows table into an owned vector, with bounds checks.
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
            // SAFETY: After the API succeeds, at least the 4-byte count is initialized.
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
                // SAFETY: The checked range above covers all `count` rows.
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
            // SAFETY: table_rows guarantees the buffer's lifetime and size.
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
            // SAFETY: table_rows guarantees the buffer's lifetime and size.
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
            // SAFETY: Both functions only read a fully initialized MIB_IPNETROW.
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
            // SAFETY: The raw socket does not outlive the UdpSocket, and the option is a 4-byte
            // DWORD.
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
        // SAFETY: `previous` and `length` are valid output buffers for a 4-byte socket option.
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
        // SAFETY: `network_index` is the network-byte-order DWORD the API requires.
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
        // SAFETY: `temporary` is a MIB_IPNETROW with every field the API requires filled in.
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
    /// A wrong index sends the OFFER away from the client, or fails the send on a device without a
    /// default route.
    fn broadcast_interface_is_the_one_holding_the_server_address() {
        // SAFETY: The literal is NUL-terminated.
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
