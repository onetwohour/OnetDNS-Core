use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use onetdns_core::{ClientInfo, IpNet, RateDecision, RateLimiter};

use crate::bucket::TokenBucket;

/// Per-address limits are useless against IPv6: a single /64 gives an attacker practically
/// unlimited sources. Keying by prefix makes them share one budget.
pub struct SubnetRateLimiter {
    inner: TokenBucket<IpAddr>,
    v4_prefix: u8,
    v6_prefix: u8,
    allow: Vec<IpNet>,
}

impl SubnetRateLimiter {
    /// `v4_prefix` is clamped to the family's maximum. IPv6 usually uses /56 or /64.
    pub fn new(per_second: u32, burst: u32, v4_prefix: u8, v6_prefix: u8) -> Option<Self> {
        Some(Self {
            inner: TokenBucket::new(per_second, burst)?,
            v4_prefix: v4_prefix.min(32),
            v6_prefix: v6_prefix.min(128),
            allow: vec![],
        })
    }

    pub fn with_allow(mut self, allow: Vec<IpNet>) -> Self {
        self.allow = allow;
        self
    }

    /// Prefix 0 is handled apart: a shift by the full width is undefined.
    fn key(&self, ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4);
                let mask = if self.v4_prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.v4_prefix)
                };
                IpAddr::V4(Ipv4Addr::from(bits & mask))
            }
            IpAddr::V6(v6) => {
                let bits = u128::from(v6);
                let mask = if self.v6_prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.v6_prefix)
                };
                IpAddr::V6(Ipv6Addr::from(bits & mask))
            }
        }
    }
}

impl RateLimiter for SubnetRateLimiter {
    /// Exemptions are checked against the original address: after truncation an exempt range and
    /// its neighbours share a key, and the exemption would spread to them.
    fn check(&self, client: &ClientInfo) -> RateDecision {
        if self.allow.iter().any(|n| n.contains(&client.source_ip)) {
            return RateDecision::Permit;
        }
        if self.inner.check(&self.key(client.source_ip)) {
            RateDecision::Permit
        } else {
            RateDecision::Throttle
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use onetdns_core::Transport;

    fn client(ip: &str) -> ClientInfo {
        ClientInfo {
            source_ip: ip.parse().unwrap(),
            client_id: None,
            transport: Transport::Do53Udp,
            authenticated: false,
        }
    }

    #[test]
    fn same_subnet_shares_budget() {
        let rl = SubnetRateLimiter::new(1, 2, 24, 56).unwrap();

        assert_eq!(rl.check(&client("203.0.113.1")), RateDecision::Permit);
        assert_eq!(rl.check(&client("203.0.113.99")), RateDecision::Permit);
        assert_eq!(rl.check(&client("203.0.113.250")), RateDecision::Throttle);

        assert_eq!(rl.check(&client("198.51.100.1")), RateDecision::Permit);
    }
}
