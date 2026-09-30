/*!
 * @brief 응답 주소로 리눅스 ipset을 채우는 계층.
 */

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use onetdns_core::MutexExt;
use onetdns_proto::{Message, Name, RData};

use super::outcome_to_option;
use crate::native::{ResolveOutcome, Resolver};

/**
 * @brief 답한 주소를 커널 주소 집합에 넣는 계층.
 * @details 방화벽이나 경로 규칙을 이름 기준으로 걸 수 있게 하려는 것이다.
 */
pub struct IpsetLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief IPv4 주소를 넣을 집합. 없으면 넣지 않는다. */
    set_v4: Option<String>,
    /** @brief IPv6 주소를 넣을 집합. 없으면 넣지 않는다. */
    set_v6: Option<String>,
    /** @brief 지켜볼 이름들. */
    domains: Vec<Name>,
    /** @brief 최근에 넣은 주소들. 같은 주소를 거듭 넣지 않으려는 것이다. */
    recent: Mutex<HashSet<IpAddr>>,
}

impl IpsetLayer {
    /** @brief 지켜볼 접미사와 집합 이름으로 만든다. */
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
                    .map_err(|_| format!("ipset 추적 DNS 이름이 올바르지 않습니다: {domain}"))
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

    /** @brief 이 이름을 지켜보는지. */
    fn tracked(&self, name: &Name) -> bool {
        self.domains
            .iter()
            .any(|domain| name.ends_with_ignore_case(domain))
    }

    /** @brief 주소를 집합에 넣는다. */
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
/** @brief 커널 주소 집합에 넣는다. */
fn ipset_add(set: &str, ip: IpAddr) -> bool {
    let Some(exe) = crate::osnet::resolve_tool("ipset") else {
        onetdns_core::warn!(event = "ipset.binary_missing", set, %ip, "신뢰할 수 있는 경로에서 ipset 실행 파일을 찾지 못했습니다");
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
                "ipset에 주소를 반영하지 못했습니다"
            );
            false
        }
        Err(error) => {
            onetdns_core::warn!(event = "ipset.command_failed", set, %ip, %error, "ipset 명령 실행에 실패했습니다");
            false
        }
    }
}
#[cfg(not(target_os = "linux"))]
/** @brief 이 플랫폼에는 주소 집합이 없다. */
fn ipset_add(_set: &str, _ip: IpAddr) -> bool {
    false
}

impl Resolver for IpsetLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 답한 주소를 집합에 넣고 그대로 돌려준다. */
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
/** @brief 설정한 접미사의 응답만 ipset 대상이 되는지. */
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use std::sync::Arc;

    use onetdns_proto::{Name, RecordType};

    use crate::native::Resolver;

    #[test]
    /** @brief 지켜보기로 한 이름의 주소만 집합에 넣는지. */
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
