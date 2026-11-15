//! Operating mode. Personal accepts only private ranges by default and Public accepts every client;
//! Public without a rate limit logs a warning at every start.

use onetdns_core::IpNet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Personal,
    Public,
}

impl Mode {
    /// Empty for Public: serving many clients is its purpose, and rate limiting covers that risk.
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
