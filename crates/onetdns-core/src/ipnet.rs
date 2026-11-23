//! CIDR IP networks, for ACLs, RPZ client-IP rules, and ECS, and which addresses the public
//! internet routes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Host bits are cleared at parse time, so Eq and Hash see 10.0.0.1/8 and 10.0.0.0/8 as one network
/// and it is not registered twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpNet {
    network: IpAddr,

    prefix: u8,
}

impl IpNet {
    pub fn prefix_len(&self) -> u8 {
        self.prefix
    }

    pub fn network(&self) -> IpAddr {
        self.network
    }

    /// IPv4 and IPv6 never match each other: 0.0.0.0/0 does not contain IPv6 addresses, so opening
    /// both families takes a rule for each.
    pub fn contains(&self, addr: &IpAddr) -> bool {
        match (self.network, addr) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let m = v4_mask(self.prefix);
                (u32::from(net) & m) == (u32::from(*ip) & m)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let m = v6_mask(self.prefix);
                (u128::from(net) & m) == (u128::from(*ip) & m)
            }
            _ => false,
        }
    }
}

/// 0 and 32 or more are handled apart, since shifting a u32 by 32 overflows.
fn v4_mask(prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        p if p >= 32 => u32::MAX,
        p => u32::MAX << (32 - p),
    }
}

/// Same edge handling as v4_mask.
fn v6_mask(prefix: u8) -> u128 {
    match prefix {
        0 => 0,
        p if p >= 128 => u128::MAX,
        p => u128::MAX << (128 - p),
    }
}

/// Holds the input text, so config errors show which entry failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseIpNetError(String);

impl std::fmt::Display for ParseIpNetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid CIDR: {}", self.0)
    }
}

impl std::error::Error for ParseIpNetError {}

impl FromStr for IpNet {
    type Err = ParseIpNetError;

    /// Accepts addr/prefix or a bare address, which becomes a host route (/32 or /128). Rejects a
    /// prefix past the family's maximum; clamping it would open a wider range than intended.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_str, prefix_str) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr_str
            .parse()
            .map_err(|_| ParseIpNetError(s.to_string()))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_str {
            Some(p) => p
                .parse::<u8>()
                .map_err(|_| ParseIpNetError(s.to_string()))?,
            None => max,
        };
        if prefix > max {
            return Err(ParseIpNetError(s.to_string()));
        }
        let network = mask_addr(addr, prefix);
        Ok(IpNet { network, prefix })
    }
}

fn mask_addr(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(u32::from(v4) & v4_mask(prefix))),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & v6_mask(prefix))),
    }
}

impl std::fmt::Display for IpNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// False for loopback, private, link-local, documentation and other special-use addresses,
/// including IPv4 ones wrapped in IPv6, which would otherwise slip through. An address someone
/// else named (a delegation, a relay target) must pass this before this server sends to it, or
/// they could make it probe the internal network.
pub fn is_globally_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => !is_special_v4(address),
        IpAddr::V6(address) => {
            if let Some(mapped) = embedded_v4(address) {
                return !is_special_v4(mapped);
            }
            let octets = address.octets();
            let segments = address.segments();
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] & 0xffc0) == 0xfec0
                || (segments[0] & 0xfe00) == 0xfc00
                || (octets[0] == 0x20
                    && octets[1] == 0x01
                    && octets[2] == 0x0d
                    && octets[3] == 0xb8)
                || octets[..8] == [0x01, 0x00, 0, 0, 0, 0, 0, 0]
                || (octets[0] == 0x20
                    && octets[1] == 0x01
                    && octets[2] == 0x00
                    && octets[3] == 0x02)
                || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001))
        }
    }
}

/// Mapped, 6to4 and NAT64 forms.
fn embedded_v4(address: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return Some(mapped);
    }
    let segments = address.segments();
    let octets = address.octets();

    if segments[0] == 0x2002 {
        return Some(Ipv4Addr::new(octets[2], octets[3], octets[4], octets[5]));
    }

    if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2..6] == [0, 0, 0, 0] {
        return Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }

    if segments[..6] == [0, 0, 0, 0, 0, 0] {
        return Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    None
}

fn is_special_v4(address: Ipv4Addr) -> bool {
    let value = u32::from(address);
    let in_net = |network: [u8; 4], prefix: u8| {
        let mask = v4_mask(prefix);
        value & mask == u32::from(Ipv4Addr::from(network)) & mask
    };

    in_net([0, 0, 0, 0], 8)
        || in_net([10, 0, 0, 0], 8)
        || in_net([100, 64, 0, 0], 10)
        || in_net([127, 0, 0, 0], 8)
        || in_net([169, 254, 0, 0], 16)
        || in_net([172, 16, 0, 0], 12)
        || in_net([192, 0, 0, 0], 24)
        || in_net([192, 0, 2, 0], 24)
        || in_net([192, 88, 99, 0], 24)
        || in_net([192, 168, 0, 0], 16)
        || in_net([198, 18, 0, 0], 15)
        || in_net([198, 51, 100, 0], 24)
        || in_net([203, 0, 113, 0], 24)
        || in_net([224, 0, 0, 0], 4)
        || in_net([240, 0, 0, 0], 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat64_local_use_prefix_is_not_globally_routable() {
        assert!(
            !is_globally_routable("64:ff9b:1::808:808".parse().unwrap()),
            "64:ff9b:1::/48은 비라우팅이어야 한다"
        );

        assert!(is_globally_routable("64:ff9b::808:808".parse().unwrap()));
        assert!(
            !is_globally_routable("64:ff9b::a9fe:a9fe".parse().unwrap()),
            "64:ff9b::169.254.169.254는 특수라 거부"
        );
    }

    #[test]
    fn internal_addresses_wrapped_in_ipv6_are_not_globally_routable() {
        for internal in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.1",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "2002:7f00:1::",
            "64:ff9b::7f00:1",
        ] {
            assert!(!is_globally_routable(ip(internal)), "{internal}");
        }
        for public in ["8.8.8.8", "::ffff:8.8.8.8", "2606:4700:4700::1111"] {
            assert!(is_globally_routable(ip(public)), "{public}");
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parse_and_contains_v4() {
        let net: IpNet = "10.0.0.0/8".parse().unwrap();
        assert_eq!(net.prefix_len(), 8);
        assert!(net.contains(&ip("10.1.2.3")));
        assert!(net.contains(&ip("10.255.255.255")));
        assert!(!net.contains(&ip("11.0.0.0")));
        assert!(!net.contains(&ip("9.255.255.255")));
    }

    #[test]
    /// Left set, one range would compare unequal to itself.
    fn host_bits_are_masked() {
        let net: IpNet = "127.0.0.1/8".parse().unwrap();
        assert_eq!(net.network(), ip("127.0.0.0"));
        assert!(net.contains(&ip("127.5.5.5")));
    }

    #[test]
    fn slash_zero_matches_all_same_family() {
        let net: IpNet = "0.0.0.0/0".parse().unwrap();
        assert!(net.contains(&ip("8.8.8.8")));
        assert!(net.contains(&ip("0.0.0.0")));

        assert!(!net.contains(&ip("::1")));
    }

    #[test]
    fn slash_32_is_single_host() {
        let net: IpNet = "192.168.1.1/32".parse().unwrap();
        assert!(net.contains(&ip("192.168.1.1")));
        assert!(!net.contains(&ip("192.168.1.2")));
    }

    #[test]
    fn bare_ip_is_host_route() {
        let v4: IpNet = "192.168.1.1".parse().unwrap();
        assert_eq!(v4.prefix_len(), 32);
        assert!(v4.contains(&ip("192.168.1.1")));
        assert!(!v4.contains(&ip("192.168.1.2")));

        let v6: IpNet = "2001:db8::1".parse().unwrap();
        assert_eq!(v6.prefix_len(), 128);
        assert!(v6.contains(&ip("2001:db8::1")));
    }

    #[test]
    fn parse_and_contains_v6() {
        let net: IpNet = "2001:db8::/32".parse().unwrap();
        assert!(net.contains(&ip("2001:db8::1")));
        assert!(net.contains(&ip("2001:db8:ffff::1")));
        assert!(!net.contains(&ip("2001:db9::1")));

        assert!(!net.contains(&ip("10.0.0.1")));
    }

    #[test]
    fn rejects_bad_input() {
        assert!("not-an-ip/8".parse::<IpNet>().is_err());
        assert!("10.0.0.0/33".parse::<IpNet>().is_err());
        assert!("::1/129".parse::<IpNet>().is_err());
        assert!("10.0.0.0/x".parse::<IpNet>().is_err());
    }

    #[test]
    fn display_roundtrip() {
        let net: IpNet = "10.1.2.3/16".parse().unwrap();
        assert_eq!(net.to_string(), "10.1.0.0/16");

        let reparsed: IpNet = net.to_string().parse().unwrap();
        assert_eq!(net, reparsed);
    }
}
