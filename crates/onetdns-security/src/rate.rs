use std::net::IpAddr;

use onetdns_core::{ClientInfo, IpNet, RateDecision, RateLimiter};

use crate::bucket::TokenBucket;

/// One budget per source address. Unsuitable for many clients behind NAT; use the subnet limiter
/// there.
pub struct KeyedRateLimiter {
    inner: TokenBucket<IpAddr>,

    allow: Vec<IpNet>,
}

impl KeyedRateLimiter {
    /// Rate 0 returns `None`, meaning no limit.
    pub fn new(per_second: u32, burst: u32) -> Option<Self> {
        Some(Self {
            inner: TokenBucket::new(per_second, burst)?,
            allow: vec![],
        })
    }

    /// For trusted sources such as internal monitoring.
    pub fn with_allow(mut self, allow: Vec<IpNet>) -> Self {
        self.allow = allow;
        self
    }
}

impl RateLimiter for KeyedRateLimiter {
    fn check(&self, client: &ClientInfo) -> RateDecision {
        if self.allow.iter().any(|n| n.contains(&client.source_ip)) {
            return RateDecision::Permit;
        }
        if self.inner.check(&client.source_ip) {
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
    fn throttles_after_burst() {
        let rl = KeyedRateLimiter::new(1, 2).unwrap();
        let c = client("198.51.100.7");
        assert_eq!(rl.check(&c), RateDecision::Permit);
        assert_eq!(rl.check(&c), RateDecision::Permit);

        assert_eq!(rl.check(&c), RateDecision::Throttle);

        assert_eq!(rl.check(&client("198.51.100.8")), RateDecision::Permit);
    }

    #[test]
    fn disabled_when_zero() {
        assert!(KeyedRateLimiter::new(0, 0).is_none());
    }

    #[test]
    fn allowlist_bypasses_limit() {
        let rl = KeyedRateLimiter::new(1, 1)
            .unwrap()
            .with_allow(vec!["10.0.0.0/8".parse().unwrap()]);
        let c = client("10.1.2.3");

        for _ in 0..5 {
            assert_eq!(rl.check(&c), RateDecision::Permit);
        }
    }
}
