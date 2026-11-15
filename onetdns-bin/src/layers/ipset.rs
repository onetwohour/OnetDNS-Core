//! Adds answered addresses to Linux ipsets, so firewall or routing rules can follow names.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use onetdns_core::MutexExt;
use onetdns_proto::{Message, Name, RData};

use super::outcome_to_option;
use crate::native::{ResolveOutcome, Resolver};

pub struct IpsetLayer {
    inner: Arc<dyn Resolver>,
    set_v4: Option<String>,
    set_v6: Option<String>,
    domains: Vec<Name>,
    /// Avoids adding the same address again and again.
    recent: Mutex<HashSet<IpAddr>>,
}

impl IpsetLayer {
    pub fn new(
        inner: Arc<dyn Resolver>,
        set_v4: Option<String>,
        set_v6: Option<String>,
        domains: &[String],
    ) -> Result<Self, String> {
        let domains = domains
            .iter()
            .map(|domain| {
                Name::from_str(domain.trim())
                    .map_err(|_| format!("Invalid DNS name to track in ipset: {domain}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(IpsetLayer {
            inner,
            set_v4,
            set_v6,
            domains,
            recent: Mutex::new(HashSet::new()),
        })
    }

    fn tracked(&self, name: &Name) -> bool {
        self.domains
            .iter()
            .any(|domain| name.ends_with_ignore_case(domain))
    }

    fn add_ip(&self, ip: IpAddr) {
        let set = match ip {
            IpAddr::V4(_) => &self.set_v4,
            IpAddr::V6(_) => &self.set_v6,
        };
        let Some(set) = set else {
            return;
        };
        {
            let mut recent = self.recent.lock_recover();
            if !recent.insert(ip) {
                return;
            }
            if recent.len() > 100_000 {
                recent.clear();
                recent.insert(ip);
            }
        }
        if !ipset_add(set, ip) {
            self.recent.lock_recover().remove(&ip);
        }
    }
}

#[cfg(target_os = "linux")]
fn ipset_add(set: &str, ip: IpAddr) -> bool {
    let Some(exe) = crate::osnet::resolve_tool("ipset") else {
        onetdns_core::warn!(event = "ipset.binary_missing", set, %ip, "Could not find the ipset executable in a trusted path");
        return false;
    };
    let mut command = std::process::Command::new(exe);
    command.args(["add", set, &ip.to_string(), "-exist"]);
    crate::osnet::harden_child_env(&mut command);
    match command.output() {
        Ok(output) if output.status.success() => true,
        Ok(output) => {
            onetdns_core::warn!(event = "ipset.update_failed",
                set,
                %ip,
                status = ?output.status.code(),
                stderr = %String::from_utf8_lossy(&output.stderr),
                "Could not apply addresses to ipset"
            );
            false
        }
        Err(error) => {
            onetdns_core::warn!(event = "ipset.command_failed", set, %ip, %error, "ipset command failed");
            false
        }
    }
}
#[cfg(not(target_os = "linux"))]
fn ipset_add(_set: &str, _ip: IpAddr) -> bool {
    false
}

impl Resolver for IpsetLayer {
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        let resp = match self.inner.resolve_outcome(req) {
            ResolveOutcome::Response(resp) => resp,

            failure => return failure,
        };
        if let Some(q) = req.questions.first() {
            if self.tracked(&q.name) {
                for r in &resp.answers {
                    match &r.rdata {
                        RData::A(ip) => self.add_ip(IpAddr::V4(*ip)),
                        RData::Aaaa(ip) => self.add_ip(IpAddr::V6(*ip)),
                        _ => {}
                    }
                }
            }
        }
        ResolveOutcome::Response(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use std::sync::Arc;

    use onetdns_proto::{Name, RecordType};

    use crate::native::Resolver;

    #[test]
    fn ipset_tracks_configured_suffixes() {
        let inner = Mock::new(1, 0);
        let layer = IpsetLayer::new(
            inner as Arc<dyn Resolver>,
            Some("v4set".into()),
            None,
            &["ads.example".to_string()],
        )
        .unwrap();
        assert!(layer.tracked(&Name::from_str("ads.example").unwrap()));
        assert!(layer.tracked(&Name::from_str("x.ads.example").unwrap()));
        assert!(!layer.tracked(&Name::from_str("notads.example").unwrap()));
        assert!(!layer.tracked(&Name::from_str("other.com").unwrap()));

        let r = layer.resolve(&query("ads.example", RecordType::A)).unwrap();
        assert!(!r.answers.is_empty());

        let unicode = IpsetLayer::new(
            Mock::new(1, 0),
            Some("v4set".into()),
            None,
            &["�".to_string()],
        )
        .unwrap();
        let raw = Name::from_labels(vec![vec![0xff]]).unwrap();
        assert!(unicode.tracked(&Name::from_str("�").unwrap()));
        assert!(!unicode.tracked(&raw));
    }
}
