/*!
 * @brief 주소·클라이언트 ID 기반 접근 제어 목록.
 */

use std::net::IpAddr;

use onetdns_core::{AccessControl, AclDecision, ClientInfo, DropReason, IpNet};

/**
 * @brief CIDR과 클라이언트 ID로 판정하는 ACL.
 *
 * @invariant 버림이 거부를, 거부가 허용을 항상 이긴다. 어떤 순서로 넣든 버림 목록에 걸린
 *            요청은 버려지고, 거부 목록에 걸린 요청은 허용 목록에도 있든 없든 거부된다. 이
 *            성질이 없으면 규칙을 추가하는 것만으로 기존 차단이 뚫리거나 약해질 수 있다. 목록
 *            밖 버림은 어느 규칙에도 걸리지 않은 요청에만 닿으므로 이 순서를 바꾸지 않는다.
 */
pub struct IpAcl {
    /** @brief 허용할 대역들. */
    allow: Vec<IpNet>,
    /** @brief 막을 대역들. 허용보다 먼저 본다. */
    deny: Vec<IpNet>,
    /** @brief 응답 없이 버릴 대역들. 거부보다도 먼저 본다. */
    drop: Vec<IpNet>,

    /** @brief 허용할 클라이언트 식별자들. */
    allow_ids: Vec<String>,
    /** @brief 막을 클라이언트 식별자들. */
    deny_ids: Vec<String>,
    /** @brief 허용 목록이 비었을 때 다 받을지. */
    default_allow: bool,
    /** @brief 어느 규칙에도 걸리지 않은 요청을 거부 대신 버릴지. 기본이 허용이면 뜻이 없다. */
    drop_unlisted: bool,
}

impl IpAcl {
    /**
     * @brief 주소 규칙만 가진 ACL을 만든다.
     * @param default_allow 어느 목록에도 걸리지 않은 요청을 받을지. 거짓이면 막고, 거부할지
     *                      버릴지는 with_unlisted_drop 이 정한다.
     */
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

    /**
     * @brief 클라이언트 ID 규칙을 덧붙인다.
     * @details ID는 암호화 전송에서만 나온다. DoH 경로 접미사, DNSCrypt 이름 등. 평문
     *          Do53에는 ID가 없으므로 주소 규칙만 적용된다.
     */
    pub fn with_ids(mut self, allow_ids: Vec<String>, deny_ids: Vec<String>) -> Self {
        self.allow_ids = allow_ids;
        self.deny_ids = deny_ids;
        self
    }

    /**
     * @brief 응답 없이 버릴 대역을 덧붙인다.
     * @details 주소로만 정한다. 클라이언트 ID는 핸드셰이크가 끝나야 알 수 있어서, 그 전에
     *          버려야 하는 판정의 근거가 될 수 없다.
     */
    pub fn with_drop(mut self, drop: Vec<IpNet>) -> Self {
        self.drop = drop;
        self
    }

    /**
     * @brief 어느 규칙에도 걸리지 않은 요청을 거부하지 않고 버리게 한다.
     * @details 기본이 허용이면 그런 요청은 받아들여지므로 뜻이 없다. 거부 목록에 든 주소와 ID 는
     *          계속 거부로 답한다. 운영자가 그 대상에 고른 처분이기 때문이다.
     */
    pub fn with_unlisted_drop(mut self, on: bool) -> Self {
        self.drop_unlisted = on;
        self
    }

    /** @brief 규칙이 없는 전면 허용 ACL. Public 모드의 기본 상태다. */
    pub fn allow_all() -> Self {
        Self::new(vec![], vec![], true)
    }

    /** @brief 주소가 목록 중 하나에 속하는지. */
    fn contained(nets: &[IpNet], ip: IpAddr) -> bool {
        nets.iter().any(|n| n.contains(&ip))
    }

    /**
     * @brief 주소만 보고도 목록 밖이라 버릴 수 있는지.
     * @details ID 규칙이 하나라도 있으면 같은 주소에서 온 클라이언트도 가져온 ID 에 따라 허용되거나
     *          거부된다. 그래서 ID 를 보기 전에는 버릴 수 없다. 핸드셰이크 전에 버리면 허용된 ID 를
     *          가진 클라이언트도 들어오지 못한다.
     */
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
    /**
     * @brief 판정한다. 버림 → 거부 → 허용 → 기본값 순서다.
     * @note 거부 검사를 먼저, 그것도 전부 끝낸 뒤에 허용을 본다. 순서를 섞으면 넓은 허용
     *       규칙이 좁은 거부 규칙을 가려 버린다.
     */
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

    /** @brief 주소만으로 버림이 정해지는지와 그 까닭. */
    fn drops(&self, ip: IpAddr) -> Option<DropReason> {
        if Self::contained(&self.drop, ip) {
            Some(DropReason::DropList)
        } else if self.drops_unlisted(ip) {
            Some(DropReason::Unlisted)
        } else {
            None
        }
    }

    /**
     * @brief 어떤 요청도 막지 않는 ACL인지.
     * @details 허용 목록은 봐도 상관없다. 기본이 허용이면 거기 걸리지 않아도 통과하기
     *          때문이다. 막는 목록이 모두 비어 있는지가 유일한 조건이며, 이걸 잘못 판정하면
     *          wire 고속 경로가 ACL 재검사를 건너뛰어 차단이 우회된다.
     */
    fn is_trivially_allow(&self) -> bool {
        self.default_allow
            && self.deny.is_empty()
            && self.deny_ids.is_empty()
            && self.drop.is_empty()
    }
}

#[cfg(test)]
/** @brief 거부가 허용을 이기는지, 그리고 아무것도 막지 않는 설정의 판정. */
mod tests {
    use super::*;
    use onetdns_core::Transport;

    /** @brief 테스트용 클라이언트. */
    fn client(ip: &str) -> ClientInfo {
        ClientInfo {
            source_ip: ip.parse().unwrap(),
            client_id: None,
            transport: Transport::Do53Udp,
            authenticated: false,
        }
    }

    #[test]
    /** @brief 허용 목록이 있으면 그 밖을 막는지. */
    fn deny_unlisted_when_closed() {
        let acl = IpAcl::new(vec!["192.168.0.0/16".parse().unwrap()], vec![], false);
        assert_eq!(acl.check(&client("192.168.1.5")), AclDecision::Allow);
        assert_eq!(acl.check(&client("8.8.8.8")), AclDecision::Deny);
    }

    #[test]
    /** @brief 거부가 허용을 이기는지. */
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
    /**
     * @brief 버림이 거부와 허용을 모두 이기는지.
     * @details 허용된 클라이언트 ID 로도 버림을 피하지 못해야 한다. 버림은 ID 를 알기 전에
     *          적용되므로, 피할 수 있으면 전송마다 결과가 달라진다.
     */
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
    /**
     * @brief 주소만 보는 판정이 전체 판정과 어긋나지 않는지.
     * @details 주소만 보고 버린다고 했으면 어떤 ID 를 가져와도 같은 까닭으로 버려야 한다. 전송이
     *          그 판정으로 핸드셰이크 전에 끊기 때문이다. ID 규칙이 없으면 두 판정은 같아야 한다.
     */
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
    /**
     * @brief 목록 밖 버림이 어느 규칙에도 걸리지 않은 주소만 버리는지.
     * @details 거부 목록에 든 주소는 운영자가 거부를 고른 대상이므로 계속 거부로 답해야 한다.
     */
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
    /**
     * @brief ID 규칙이 있으면 목록 밖 버림을 ID 를 본 뒤로 미루는지.
     * @details 주소만 보고 버리면 허용된 ID 를 가져올 클라이언트까지 핸드셰이크 전에 끊긴다.
     */
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
    /** @brief 기본이 허용이면 목록 밖 버림이 아무것도 버리지 않는지. */
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
    /** @brief 허용 목록이 없으면 다 받는지. */
    fn default_allow_when_open() {
        let acl = IpAcl::allow_all();
        assert!(acl.is_trivially_allow());
        assert_eq!(acl.check(&client("203.0.113.1")), AclDecision::Allow);
    }

    #[test]
    /** @brief 정말 아무것도 막지 않을 때만 그렇다고 답하는지. 빠른 경로가 이 판정을 믿는다. */
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

    /** @brief 식별자가 붙은 테스트용 클라이언트. */
    fn client_id(ip: &str, id: &str) -> ClientInfo {
        ClientInfo {
            source_ip: ip.parse().unwrap(),
            client_id: Some(id.to_string()),
            transport: Transport::DoT,
            authenticated: true,
        }
    }

    #[test]
    /** @brief 식별자 기준 허용과 거부. */
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
