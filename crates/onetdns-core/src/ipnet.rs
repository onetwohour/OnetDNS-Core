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

/// Longest-prefix lookup over a fixed list of networks, for lists too long to scan per query.
/// Among equal networks the later one wins, as `max_by_key` over the list would pick.
#[derive(Debug, Default)]
pub struct NetIndex {
    /// Per prefix length, longest first: each network with its list position, sorted by network.
    v4: Vec<(u8, Vec<(u32, u32)>)>,
    v6: Vec<(u8, Vec<(u128, u32)>)>,
}

impl NetIndex {
    pub fn new<'a>(nets: impl IntoIterator<Item = &'a IpNet>) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for (position, net) in nets.into_iter().enumerate() {
            let position = u32::try_from(position).expect("network lists stay under 2^32 entries");
            match net.network {
                IpAddr::V4(address) => bucket(&mut v4, net.prefix)
                    .push((u32::from(address) & v4_mask(net.prefix), position)),
                IpAddr::V6(address) => bucket(&mut v6, net.prefix)
                    .push((u128::from(address) & v6_mask(net.prefix), position)),
            }
        }
        Self {
            v4: sorted(v4),
            v6: sorted(v6),
        }
    }

    /// The list position of the longest network holding `addr`, with its prefix length.
    pub fn longest(&self, addr: &IpAddr) -> Option<(u8, usize)> {
        match addr {
            IpAddr::V4(address) => longest_in(&self.v4, u32::from(*address), v4_mask),
            IpAddr::V6(address) => longest_in(&self.v6, u128::from(*address), v6_mask),
        }
    }
}

fn bucket<T>(buckets: &mut Vec<(u8, Vec<T>)>, prefix: u8) -> &mut Vec<T> {
    let at = match buckets.iter().position(|(length, _)| *length == prefix) {
        Some(at) => at,
        None => {
            buckets.push((prefix, Vec::new()));
            buckets.len() - 1
        }
    };
    &mut buckets[at].1
}

fn sorted<T: Ord>(mut buckets: Vec<(u8, Vec<(T, u32)>)>) -> Vec<(u8, Vec<(T, u32)>)> {
    buckets.sort_unstable_by(|a, b| b.0.cmp(&a.0));
    for (_, nets) in &mut buckets {
        nets.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
        nets.dedup_by(|later, kept| later.0 == kept.0);
        nets.shrink_to_fit();
    }
    buckets
}

fn longest_in<T: Ord + Copy + std::ops::BitAnd<Output = T>>(
    buckets: &[(u8, Vec<(T, u32)>)],
    address: T,
    mask: fn(u8) -> T,
) -> Option<(u8, usize)> {
    buckets.iter().find_map(|(prefix, nets)| {
        let network = address & mask(*prefix);
        nets.binary_search_by(|(candidate, _)| candidate.cmp(&network))
            .ok()
            .map(|at| (*prefix, nets[at].1 as usize))
    })
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
    fn net_index_picks_what_a_scan_for_the_longest_network_picks() {
        let nets: Vec<IpNet> = [
            "10.0.0.0/8",
            "10.1.0.0/16",
            "0.0.0.0/0",
            "10.1.2.3/32",
            "10.1.9.9/16",
            "2001:db8::/32",
            "::/0",
            "2001:db8:1::/48",
        ]
        .iter()
        .map(|net| net.parse().unwrap())
        .collect();
        let index = NetIndex::new(&nets);
        for address in [
            "10.1.2.3",
            "10.1.2.4",
            "10.2.0.1",
            "192.0.2.1",
            "2001:db8:1::5",
            "2001:db8:2::5",
            "2001:db9::1",
            "::ffff:10.1.2.3",
        ] {
            let address: IpAddr = address.parse().unwrap();
            let scanned = nets
                .iter()
                .enumerate()
                .filter(|(_, net)| net.contains(&address))
                .max_by_key(|(_, net)| net.prefix_len())
                .map(|(position, net)| (net.prefix_len(), position));
            assert_eq!(index.longest(&address), scanned, "{address}");
        }
        assert_eq!(index.longest(&"10.1.7.7".parse().unwrap()), Some((16, 4)));
        assert_eq!(
            NetIndex::new(&[]).longest(&"10.0.0.1".parse().unwrap()),
            None
        );
    }

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
