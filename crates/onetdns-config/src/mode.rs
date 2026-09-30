/*!
 * @brief 동작 모드.
 *
 * @details 개인용과 공개용은 기본 허용 대역이 다르다. 개인용은 사설 대역만 받고, 공개용은
 *          모든 클라이언트를 받는다. 공개용에 속도 제한이 없으면 시작할 때마다 경고를 남긴다.
 */

use onetdns_core::IpNet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/** @brief 이 서버가 누구를 위한 것인지. */
pub enum Mode {
    #[default]
    /** @brief 내부망용. 기본 제한이 걸린다. */
    Personal,
    /** @brief 공개용. 모든 클라이언트를 받는다. */
    Public,
}

impl Mode {
    /**
     * @brief 이 모드의 기본 허용 대역.
     * @note 공개용은 비워 둔다. 넓은 클라이언트를 받는 것이 공개용의 목적이고, 그
     *       위험은 속도 제한으로 막는다.
     */
    pub fn preset_acl_allow(self) -> Vec<IpNet> {
        let cidrs: &[&str] = match self {
            Mode::Personal => &[
                "127.0.0.0/8",
                "10.0.0.0/8",
                "100.64.0.0/10",
                "169.254.0.0/16",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "::1/128",
                "fe80::/10",
                "fc00::/7",
            ],
            Mode::Public => &["0.0.0.0/0", "::/0"],
        };
        cidrs
            .iter()
            .map(|cidr| {
                cidr.parse()
                    .expect("The default access control ranges must be valid CIDRs")
            })
            .collect()
    }
}
