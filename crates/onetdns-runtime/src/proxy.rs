//! PROXY protocol v1 and v2 header parser that restores the original client address behind a load
//! balancer.
//!
//! Accept the header only from trusted sources: allowed from anyone, it lets anyone forge the
//! source address and bypass the ACL and rate limiting. The caller (the TCP worker) decides trust;
//! this parser checks only the format.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Designed not to overlap with DNS, so these 12 bytes settle whether the header is v2.
const V2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

pub enum ProxyParse {
    /// Original client address and the header length.
    Addr(SocketAddr, usize),

    /// The proxy's own connection, such as a health check: skip the header and keep the address.
    Local(usize),

    /// Read more and call again.
    Incomplete,

    /// Treat everything as DNS data.
    NotProxy,
}

/// Returns `Incomplete` when the buffer is too short to tell either signature; calling that
/// `NotProxy` would read the header as DNS data.
pub fn parse(buf: &[u8]) -> ProxyParse {
    if buf.len() >= 12 && buf[..12] == V2_SIG {
        return parse_v2(buf);
    }
    if buf.starts_with(b"PROXY ") {
        return parse_v1(buf);
    }

    if buf.len() < 6 && b"PROXY ".starts_with(buf) {
        return ProxyParse::Incomplete;
    }

    if buf.len() < 12 && V2_SIG.starts_with(buf) {
        return ProxyParse::Incomplete;
    }
    ProxyParse::NotProxy
}

/// At most 107 bytes by the specification; without a CRLF inside that, it is not a header.
/// Otherwise a connection that never sends the terminator would grow the buffer without bound. A
/// protocol and address family that disagree are rejected: accepting IPv6 in a TCP4 header leaves
/// address parsing to differ by implementation.
fn parse_v1(buf: &[u8]) -> ProxyParse {
    let end = match buf.windows(2).position(|w| w == b"\r\n") {
        Some(p) => p,
        None => {
            return if buf.len() > 107 {
                ProxyParse::NotProxy
            } else {
                ProxyParse::Incomplete
            }
        }
    };
    let consumed = end + 2;
    let line = match std::str::from_utf8(&buf[..end]) {
        Ok(s) => s,
        Err(_) => return ProxyParse::NotProxy,
    };
    let fields: Vec<&str> = line.split_ascii_whitespace().collect();
    if fields.first().copied() != Some("PROXY") {
        return ProxyParse::NotProxy;
    }
    if fields.get(1).copied() == Some("UNKNOWN") {
        return if fields.len() == 2 {
            ProxyParse::Local(consumed)
        } else {
            ProxyParse::NotProxy
        };
    }
    if fields.len() != 6 {
        return ProxyParse::NotProxy;
    }
    let proto = fields[1];
    let (Ok(src), Ok(dst), Ok(sport), Ok(_dport)) = (
        fields[2].parse::<IpAddr>(),
        fields[3].parse::<IpAddr>(),
        fields[4].parse::<u16>(),
        fields[5].parse::<u16>(),
    ) else {
        return ProxyParse::NotProxy;
    };
    let family_ok = matches!(
        (proto, src, dst),
        ("TCP4", IpAddr::V4(_), IpAddr::V4(_)) | ("TCP6", IpAddr::V6(_), IpAddr::V6(_))
    );
    if !family_ok || sport == 0 {
        return ProxyParse::NotProxy;
    }
    ProxyParse::Addr(SocketAddr::new(src, sport), consumed)
}

/// The length field gives the size of the address block; until that much has arrived it is
/// `Incomplete`. Only TCP over IPv4 (0x11) and IPv6 (0x21) are accepted; this server never receives
/// UDP or Unix socket families over PROXY.
fn parse_v2(buf: &[u8]) -> ProxyParse {
    if buf.len() < 16 {
        return ProxyParse::Incomplete;
    }
    let ver_cmd = buf[12];
    if ver_cmd >> 4 != 0x2 {
        return ProxyParse::NotProxy;
    }
    let cmd = ver_cmd & 0x0f;
    if cmd > 1 {
        return ProxyParse::NotProxy;
    }
    let fam_proto = buf[13];
    let len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let Some(total) = 16usize.checked_add(len) else {
        return ProxyParse::NotProxy;
    };
    if buf.len() < total {
        return ProxyParse::Incomplete;
    }
    if cmd == 0 {
        return ProxyParse::Local(total);
    }
    let addr = &buf[16..total];
    match fam_proto {
        0x11 if addr.len() >= 12 => {
            let ip = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
            let port = u16::from_be_bytes([addr[8], addr[9]]);
            if port == 0 {
                ProxyParse::NotProxy
            } else {
                ProxyParse::Addr(SocketAddr::new(IpAddr::V4(ip), port), total)
            }
        }
        0x21 if addr.len() >= 36 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&addr[..16]);
            let ip = Ipv6Addr::from(o);
            let port = u16::from_be_bytes([addr[32], addr[33]]);
            if port == 0 {
                ProxyParse::NotProxy
            } else {
                ProxyParse::Addr(SocketAddr::new(IpAddr::V6(ip), port), total)
            }
        }
        _ => ProxyParse::NotProxy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(p: ProxyParse) -> (SocketAddr, usize) {
        match p {
            ProxyParse::Addr(a, n) => (a, n),
            _ => panic!("Addr 기대"),
        }
    }

    #[test]
    fn v1_tcp4() {
        let line = b"PROXY TCP4 192.168.0.1 10.0.0.1 56324 443\r\nDNSDATA";
        let (a, n) = addr(parse(line));
        assert_eq!(a, "192.168.0.1:56324".parse().unwrap());
        assert_eq!(n, line.len() - "DNSDATA".len());
    }

    #[test]
    fn v1_tcp6_and_unknown() {
        let line = b"PROXY TCP6 2001:db8::1 2001:db8::2 1234 53\r\n";
        let (a, _) = addr(parse(line));
        assert_eq!(a, "[2001:db8::1]:1234".parse().unwrap());

        match parse(b"PROXY UNKNOWN\r\n") {
            ProxyParse::Local(n) => assert_eq!(n, 15),
            _ => panic!("Local 기대"),
        }
    }

    #[test]
    fn v1_incomplete_then_complete() {
        assert!(matches!(parse(b"PRO"), ProxyParse::Incomplete));
        assert!(matches!(
            parse(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2"),
            ProxyParse::Incomplete
        ));
    }

    #[test]
    fn v2_ipv4() {
        let mut h = V2_SIG.to_vec();
        h.push(0x21);
        h.push(0x11);
        h.extend_from_slice(&12u16.to_be_bytes());
        h.extend_from_slice(&[203, 0, 113, 7]);
        h.extend_from_slice(&[10, 0, 0, 1]);
        h.extend_from_slice(&0xd903u16.to_be_bytes());
        h.extend_from_slice(&53u16.to_be_bytes());
        h.extend_from_slice(b"DNS");
        let (a, n) = addr(parse(&h));
        assert_eq!(a, "203.0.113.7:55555".parse().unwrap());
        assert_eq!(n, h.len() - 3);
    }

    #[test]
    fn v2_local_command() {
        let mut h = V2_SIG.to_vec();
        h.push(0x20);
        h.push(0x00);
        h.extend_from_slice(&0u16.to_be_bytes());
        match parse(&h) {
            ProxyParse::Local(n) => assert_eq!(n, 16),
            _ => panic!("Local 기대"),
        }
    }

    #[test]
    /// Misreading it would eat the start of the query.
    fn not_proxy_plain_dns() {
        assert!(matches!(
            parse(&[0x00, 0x1d, 0xab, 0xcd]),
            ProxyParse::NotProxy
        ));
    }
}
