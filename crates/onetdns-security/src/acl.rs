use std::net::IpAddr;

use onetdns_core::{AccessControl, AclDecision, ClientInfo, DropReason, IpNet};

/// Drop beats deny and deny beats allow, whatever order the rules were added in. Without this,
/// adding a rule could open or weaken an existing block. Dropping unlisted requests only touches
/// requests no rule matched, so it leaves that order alone.
pub struct IpAcl {
    allow: Vec<IpNet>,
    deny: Vec<IpNet>,
    drop: Vec<IpNet>,

    allow_ids: Vec<String>,
    deny_ids: Vec<String>,
    default_allow: bool,
    /// Drop rather than refuse requests no rule matched. Has no effect when `default_allow` is set.
    drop_unlisted: bool,
}

impl IpAcl {
    /// `default_allow` decides whether requests that match no list are accepted; when they are not,
    /// `with_unlisted_drop` decides between refusing and dropping them.
    pub fn new(allow: Vec<IpNet>, deny: Vec<IpNet>, default_allow: bool) -> Self {
        Self {
            allow,
            deny,
            drop: vec![],
            allow_ids: vec![],
            deny_ids: vec![],
            default_allow,
            drop_unlisted: false,
        }
    }

    /// Client IDs come only from encrypted transports (DoH path suffix, DNSCrypt name and so on).
    /// Plain Do53 has no ID, so only address rules apply to it.
    pub fn with_ids(mut self, allow_ids: Vec<String>, deny_ids: Vec<String>) -> Self {
        self.allow_ids = allow_ids;
        self.deny_ids = deny_ids;
        self
    }

    /// Decided by address only: a client ID is known only after the handshake, too late for a
    /// decision that must come before it.
    pub fn with_drop(mut self, drop: Vec<IpNet>) -> Self {
        self.drop = drop;
        self
    }

    /// Addresses and IDs on the deny list are still refused, since that is the response the
    /// operator chose for them. Has no effect when the default is allow.
    pub fn with_unlisted_drop(mut self, on: bool) -> Self {
        self.drop_unlisted = on;
        self
    }

    /// The default in Public mode.
    pub fn allow_all() -> Self {
        Self::new(vec![], vec![], true)
    }

    fn contained(nets: &[IpNet], ip: IpAddr) -> bool {
        nets.iter().any(|n| n.contains(&ip))
    }

    /// With any client ID rule, clients from one address may be allowed or refused depending on
    /// their ID, so nothing can be dropped before the ID is known; dropping before the handshake
    /// would shut out clients with an allowed ID.
    fn drops_unlisted(&self, ip: IpAddr) -> bool {
        self.drop_unlisted
            && !self.default_allow
            && self.allow_ids.is_empty()
            && self.deny_ids.is_empty()
            && !Self::contained(&self.deny, ip)
            && !Self::contained(&self.allow, ip)
    }
}

impl AccessControl for IpAcl {
    /// Order: drop, deny, allow, default. Every deny check finishes before any allow check, or a
    /// broad allow rule would hide a narrow deny rule.
    fn check(&self, client: &ClientInfo) -> AclDecision {
        let ip = client.source_ip;
        let id = client.client_id.as_deref();

        if let Some(reason) = self.drops(ip) {
            return AclDecision::Drop(reason);
        }
        if Self::contained(&self.deny, ip) {
            return AclDecision::Deny;
        }
        if let Some(id) = id {
            if self.deny_ids.iter().any(|x| x == id) {
                return AclDecision::Deny;
            }
        }

        if Self::contained(&self.allow, ip) {
            return AclDecision::Allow;
        }
        if let Some(id) = id {
            if self.allow_ids.iter().any(|x| x == id) {
                return AclDecision::Allow;
            }
        }
        if self.default_allow {
            AclDecision::Allow
        } else if self.drop_unlisted {
            AclDecision::Drop(DropReason::Unlisted)
        } else {
            AclDecision::Deny
        }
    }

    fn drops(&self, ip: IpAddr) -> Option<DropReason> {
        if Self::contained(&self.drop, ip) {
            Some(DropReason::DropList)
        } else if self.drops_unlisted(ip) {
            Some(DropReason::Unlisted)
        } else {
            None
        }
    }

    /// Allow lists do not matter: with a default of allow, unmatched requests pass anyway. The only
    /// condition is that every blocking list is empty. Getting this wrong lets the wire fast path
    /// skip the ACL and bypass blocks.
    fn is_trivially_allow(&self) -> bool {
        self.default_allow
            && self.deny.is_empty()
            && self.deny_ids.is_empty()
            && self.drop.is_empty()
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
    fn deny_unlisted_when_closed() {
        let acl = IpAcl::new(vec!["192.168.0.0/16".parse().unwrap()], vec![], false);
        assert_eq!(acl.check(&client("192.168.1.5")), AclDecision::Allow);
        assert_eq!(acl.check(&client("8.8.8.8")), AclDecision::Deny);
    }

    #[test]
    fn deny_takes_precedence() {
        let acl = IpAcl::new(
            vec!["10.0.0.0/8".parse().unwrap()],
            vec!["10.6.6.0/24".parse().unwrap()],
            true,
        );
        assert_eq!(acl.check(&client("10.1.2.3")), AclDecision::Allow);
        assert_eq!(acl.check(&client("10.6.6.9")), AclDecision::Deny);
    }

    #[test]
    /// An allowed client ID must not escape a drop either: drops apply before the ID is known, so
    /// escaping one would make the result depend on the transport.
    fn drop_takes_precedence_over_deny_and_allow() {
        let acl = IpAcl::new(
            vec!["10.0.0.0/8".parse().unwrap()],
            vec!["10.6.6.0/24".parse().unwrap()],
            true,
        )
        .with_ids(vec!["vip".into()], vec![])
        .with_drop(vec![
            "10.6.6.0/28".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ]);
        let dropped = AclDecision::Drop(DropReason::DropList);
        assert_eq!(acl.check(&client("10.6.6.1")), dropped);
        assert_eq!(acl.check(&client("10.6.6.20")), AclDecision::Deny);
        assert_eq!(acl.check(&client("10.1.2.3")), AclDecision::Allow);
        assert_eq!(acl.check(&client("2001:db8::1")), dropped);
        assert_eq!(
            acl.check(&client_id("10.6.6.1", "vip")),
            dropped,
            "허용된 ID 가 버림을 풀었습니다"
        );
    }

    #[test]
    /// If the address alone says drop, every ID must be dropped for the same reason, because
    /// transports act on it before the handshake. Without ID rules both decisions must match.
    fn drops_agrees_with_check() {
        let closed = || {
            IpAcl::new(
                vec!["192.168.0.0/16".parse().unwrap()],
                vec!["198.51.100.0/24".parse().unwrap()],
                false,
            )
            .with_drop(vec!["192.168.7.0/24".parse().unwrap()])
        };
        let acls = [
            closed(),
            closed().with_unlisted_drop(true),
            closed()
                .with_unlisted_drop(true)
                .with_ids(vec!["vip".into()], vec!["banned".into()]),
            IpAcl::allow_all()
                .with_unlisted_drop(true)
                .with_drop(vec!["192.168.7.0/24".parse().unwrap()]),
        ];
        let ips = [
            "192.168.7.9",
            "192.168.8.9",
            "198.51.100.9",
            "203.0.113.1",
            "::1",
        ];
        for (n, acl) in acls.iter().enumerate() {
            let no_ids = acl.allow_ids.is_empty() && acl.deny_ids.is_empty();
            for ip in ips {
                let drops = acl.drops(ip.parse().unwrap());
                if let Some(reason) = drops {
                    for id in ["vip", "banned", "other"] {
                        assert_eq!(
                            acl.check(&client_id(ip, id)),
                            AclDecision::Drop(reason),
                            "{n}번 ACL 이 {ip} 를 주소만 보고 버렸지만 ID {id} 로는 버리지 않습니다"
                        );
                    }
                }
                if no_ids {
                    let checked = match acl.check(&client(ip)) {
                        AclDecision::Drop(reason) => Some(reason),
                        _ => None,
                    };
                    assert_eq!(drops, checked, "{n}번 ACL 의 두 판정이 {ip} 에서 다릅니다");
                }
            }
        }
    }

    #[test]
    fn unlisted_drop_spares_listed_addresses() {
        let acl = IpAcl::new(
            vec!["192.168.0.0/16".parse().unwrap()],
            vec!["198.51.100.0/24".parse().unwrap()],
            false,
        )
        .with_drop(vec!["192.168.7.0/24".parse().unwrap()])
        .with_unlisted_drop(true);
        let unlisted = AclDecision::Drop(DropReason::Unlisted);
        assert_eq!(acl.check(&client("192.168.1.5")), AclDecision::Allow);
        assert_eq!(acl.check(&client("198.51.100.5")), AclDecision::Deny);
        assert_eq!(
            acl.check(&client("192.168.7.5")),
            AclDecision::Drop(DropReason::DropList)
        );
        assert_eq!(acl.check(&client("203.0.113.1")), unlisted);
        assert_eq!(acl.check(&client("2001:db8::1")), unlisted);
        assert_eq!(
            acl.drops("203.0.113.1".parse().unwrap()),
            Some(DropReason::Unlisted)
        );
        assert!(!acl.is_trivially_allow());

        let refusing = IpAcl::new(vec!["192.168.0.0/16".parse().unwrap()], vec![], false);
        assert_eq!(
            refusing.check(&client("203.0.113.1")),
            AclDecision::Deny,
            "대조군이 무효입니다: 끄면 목록 밖을 거부해야 합니다"
        );
        assert_eq!(refusing.drops("203.0.113.1".parse().unwrap()), None);
    }

    #[test]
    fn unlisted_drop_waits_for_client_id() {
        let acl = IpAcl::new(vec![], vec![], false)
            .with_ids(vec!["vip".into()], vec!["banned".into()])
            .with_unlisted_drop(true);
        let ip = "203.0.113.1";
        assert_eq!(
            acl.drops(ip.parse().unwrap()),
            None,
            "ID 를 보기 전에 버렸습니다"
        );
        assert_eq!(acl.check(&client_id(ip, "vip")), AclDecision::Allow);
        assert_eq!(acl.check(&client_id(ip, "banned")), AclDecision::Deny);
        let unlisted = AclDecision::Drop(DropReason::Unlisted);
        assert_eq!(acl.check(&client_id(ip, "other")), unlisted);
        assert_eq!(acl.check(&client(ip)), unlisted);
    }

    #[test]
    fn unlisted_drop_is_inert_when_open() {
        let acl = IpAcl::allow_all().with_unlisted_drop(true);
        assert_eq!(acl.check(&client("203.0.113.1")), AclDecision::Allow);
        assert_eq!(acl.drops("203.0.113.1".parse().unwrap()), None);
        assert!(
            acl.is_trivially_allow(),
            "아무것도 막지 않는데 빠른 경로를 닫았습니다"
        );
    }

    #[test]
    fn default_allow_when_open() {
        let acl = IpAcl::allow_all();
        assert!(acl.is_trivially_allow());
        assert_eq!(acl.check(&client("203.0.113.1")), AclDecision::Allow);
    }

    #[test]
    /// The fast path trusts this answer.
    fn only_unconditional_acl_reports_trivial_allow() {
        assert!(!IpAcl::new(vec![], vec![], false).is_trivially_allow());
        assert!(
            IpAcl::new(vec!["192.0.2.0/24".parse().unwrap()], vec![], true,).is_trivially_allow()
        );
        assert!(
            !IpAcl::new(vec![], vec!["192.0.2.0/24".parse().unwrap()], true,).is_trivially_allow()
        );
        assert!(!IpAcl::allow_all()
            .with_drop(vec!["192.0.2.0/24".parse().unwrap()])
            .is_trivially_allow());
    }

    fn client_id(ip: &str, id: &str) -> ClientInfo {
        ClientInfo {
            source_ip: ip.parse().unwrap(),
            client_id: Some(id.to_string()),
            transport: Transport::DoT,
            authenticated: true,
        }
    }

    #[test]
    fn clientid_allow_and_deny() {
        let acl =
            IpAcl::new(vec![], vec![], false).with_ids(vec!["vip".into()], vec!["banned".into()]);
        assert_eq!(acl.check(&client_id("8.8.8.8", "vip")), AclDecision::Allow);
        assert_eq!(acl.check(&client_id("8.8.8.8", "other")), AclDecision::Deny);

        let acl2 = IpAcl::new(vec![], vec![], true).with_ids(vec![], vec!["banned".into()]);
        assert_eq!(
            acl2.check(&client_id("8.8.8.8", "banned")),
            AclDecision::Deny
        );
    }
}
