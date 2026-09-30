/*!
 * @brief CIDR 표기 IP 네트워크. ACL·RPZ 클라이언트 IP 규칙·ECS가 쓴다.
 */

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/**
 * @brief 접두사 길이가 붙은 IP 네트워크.
 * @invariant network의 호스트 비트는 파싱 시점에 0으로 지워진다. 덕분에 Eq/Hash가
 *            같은 네트워크를 항상 같게 보아 10.0.0.1/8과 10.0.0.0/8이 중복 등록되지 않는다.
 */
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpNet {
    /** @brief 대역의 시작 주소. 대역 밖 비트는 지워 둔다. */
    network: IpAddr,

    /** @brief 대역 길이. */
    prefix: u8,
}

impl IpNet {
    /** @brief 접두사 길이(비트). */
    pub fn prefix_len(&self) -> u8 {
        self.prefix
    }

    /** @brief 호스트 비트를 지운 네트워크 주소. */
    pub fn network(&self) -> IpAddr {
        self.network
    }

    /**
     * @brief 주소가 이 네트워크에 속하는지.
     * @note IPv4와 IPv6는 서로 절대 맞지 않는다. 0.0.0.0/0도 IPv6 주소를 포함하지 않으므로,
     *       두 계열을 모두 열려면 규칙을 각각 써야 한다.
     */
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

/**
 * @brief IPv4 접두사 마스크.
 * @note 0과 32 이상을 따로 처리한다. u32::MAX << 32는 시프트 폭 초과로 정의되지 않는다.
 */
fn v4_mask(prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        p if p >= 32 => u32::MAX,
        p => u32::MAX << (32 - p),
    }
}

/** @brief IPv6 접두사 마스크. 경계 처리 이유는 v4_mask와 같다. */
fn v6_mask(prefix: u8) -> u128 {
    match prefix {
        0 => 0,
        p if p >= 128 => u128::MAX,
        p => u128::MAX << (128 - p),
    }
}

/** @brief CIDR 파싱 실패. 원문을 담아 설정 오류 메시지에서 어느 줄인지 알려 준다. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseIpNetError(String);

impl std::fmt::Display for ParseIpNetError {
    /** @brief 사람이 읽을 문구. */
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid CIDR: {}", self.0)
    }
}

impl std::error::Error for ParseIpNetError {}

impl FromStr for IpNet {
    /** @brief 읽기에 실패한 까닭. */
    type Err = ParseIpNetError;

    /**
     * @brief 주소/접두사 또는 맨 주소를 파싱한다.
     * @details 접두사가 없으면 호스트 경로로 본다(IPv4 /32, IPv6 /128). 계열별 최대 길이를
     *          넘으면 거부한다. 넘긴 값을 잘라 받으면 의도보다 넓은 대역이 열린다.
     */
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

/** @brief 주소의 호스트 비트를 지워 네트워크 주소로 만든다. */
fn mask_addr(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(u32::from(v4) & v4_mask(prefix))),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & v6_mask(prefix))),
    }
}

impl std::fmt::Display for IpNet {
    /** @brief 사람이 읽을 표기. */
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

#[cfg(test)]
/** @brief 표기 읽기와 포함 판정, 그리고 어긋난 입력의 거부. */
mod tests {
    use super::*;

    /** @brief 테스트용 주소. */
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    /** @brief IPv4 대역 표기와 포함 판정. */
    fn parse_and_contains_v4() {
        let net: IpNet = "10.0.0.0/8".parse().unwrap();
        assert_eq!(net.prefix_len(), 8);
        assert!(net.contains(&ip("10.1.2.3")));
        assert!(net.contains(&ip("10.255.255.255")));
        assert!(!net.contains(&ip("11.0.0.0")));
        assert!(!net.contains(&ip("9.255.255.255")));
    }

    #[test]
    /** @brief 대역 밖 비트가 지워지는지. 남으면 같은 대역이 다르게 보인다. */
    fn host_bits_are_masked() {
        let net: IpNet = "127.0.0.1/8".parse().unwrap();
        assert_eq!(net.network(), ip("127.0.0.0"));
        assert!(net.contains(&ip("127.5.5.5")));
    }

    #[test]
    /** @brief 전체 대역이 같은 계열을 모두 포함하는지. */
    fn slash_zero_matches_all_same_family() {
        let net: IpNet = "0.0.0.0/0".parse().unwrap();
        assert!(net.contains(&ip("8.8.8.8")));
        assert!(net.contains(&ip("0.0.0.0")));

        assert!(!net.contains(&ip("::1")));
    }

    #[test]
    /** @brief 가장 좁은 대역이 주소 하나만 포함하는지. */
    fn slash_32_is_single_host() {
        let net: IpNet = "192.168.1.1/32".parse().unwrap();
        assert!(net.contains(&ip("192.168.1.1")));
        assert!(!net.contains(&ip("192.168.1.2")));
    }

    #[test]
    /** @brief 대역 표기 없이 적으면 주소 하나로 보는지. */
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
    /** @brief IPv6 대역 표기와 포함 판정. */
    fn parse_and_contains_v6() {
        let net: IpNet = "2001:db8::/32".parse().unwrap();
        assert!(net.contains(&ip("2001:db8::1")));
        assert!(net.contains(&ip("2001:db8:ffff::1")));
        assert!(!net.contains(&ip("2001:db9::1")));

        assert!(!net.contains(&ip("10.0.0.1")));
    }

    #[test]
    /** @brief 어긋난 표기를 거절하는지. */
    fn rejects_bad_input() {
        assert!("not-an-ip/8".parse::<IpNet>().is_err());
        assert!("10.0.0.0/33".parse::<IpNet>().is_err());
        assert!("::1/129".parse::<IpNet>().is_err());
        assert!("10.0.0.0/x".parse::<IpNet>().is_err());
    }

    #[test]
    /** @brief 적었다 읽으면 같은지. */
    fn display_roundtrip() {
        let net: IpNet = "10.1.2.3/16".parse().unwrap();
        assert_eq!(net.to_string(), "10.1.0.0/16");

        let reparsed: IpNet = net.to_string().parse().unwrap();
        assert_eq!(net, reparsed);
    }
}
