//! Oblivious DoH on the DoH listener. As a target it opens queries a proxy relays, resolves them as
//! DoH queries from the proxy, and seals the answers. As a proxy it relays sealed messages to the
//! targets the config allows, and to no others.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use onetdns_config::Config;
use onetdns_core::{ArcSwap, MutexExt};
use onetdns_forward::odoh::{OdohError, Relay, RelayError, Relayed, TargetKey};
use onetdns_http2::{Oblivious, ObliviousReply};
use onetdns_tls::hpke::PrivateKey;

use crate::native::RelayAdmission;
use crate::transport_observe;
use crate::upstream::{parse_upstream_url, split_authority, BOOTSTRAP_TIMEOUT};

/// How long a relay waits for a target. Fixed rather than `query_timeout_secs`, so changing that
/// key does not reopen the DoH listener.
const RELAY_TIMEOUT: Duration = Duration::from_secs(10);

/// A target address from the bootstrap servers is kept at least this long, whatever its TTL, and
/// a failed lookup keeps the old address this long before trying again.
const MIN_TARGET_ADDR_LIFETIME: Duration = Duration::from_secs(60);

/// What a DoH listener serves of Oblivious DoH.
pub(crate) struct ObliviousDoh {
    pub(crate) target: Option<Arc<OdohTarget>>,
    pub(crate) proxy: Option<OdohProxy>,
}

pub(crate) struct OdohTarget {
    key: TargetKey,
    configs: Vec<u8>,
}

impl OdohTarget {
    pub(crate) fn new(secret: PrivateKey) -> Self {
        let key = TargetKey::new(secret);
        let configs = key.configs();
        Self { key, configs }
    }

    pub(crate) fn public_key(&self) -> [u8; 32] {
        self.key.public_key()
    }
}

/// The targets an ODoH proxy relays to. Connections to them are shared by every client.
pub(crate) struct OdohProxy {
    targets: Vec<ProxyTarget>,
    /// The running config. Its `bootstrap` changes without reopening the DoH listener.
    runtime_cfg: Arc<ArcSwap<Config>>,
    relay: Relay,
}

struct ProxyTarget {
    /// Lowercase; an IPv6 address without brackets.
    host: String,
    port: u16,
    path: String,
    server_name: String,
    /// With when it expires; an IP literal never does.
    addr: Mutex<Option<(SocketAddr, Option<Instant>)>>,
}

impl OdohProxy {
    /// `targets` are URLs config validation accepted. Hostnames are looked up through the running
    /// config's `bootstrap` on first use.
    pub(crate) fn new(targets: &[String], runtime_cfg: Arc<ArcSwap<Config>>, relay: Relay) -> Self {
        let targets = targets
            .iter()
            .filter_map(|url| {
                let parsed = parse_upstream_url(url)?;
                let port = parsed.port.unwrap_or(443);
                let fixed = parsed
                    .host
                    .parse::<IpAddr>()
                    .ok()
                    .map(|ip| (SocketAddr::new(ip, port), None));
                Some(ProxyTarget {
                    host: parsed.host.to_ascii_lowercase(),
                    port,
                    path: parsed.path.clone()?,
                    server_name: parsed.server_name(),
                    addr: Mutex::new(fixed),
                })
            })
            .collect();
        Self {
            targets,
            runtime_cfg,
            relay,
        }
    }

    fn relay(&self, target_host: &str, target_path: &str, message: &[u8]) -> ObliviousReply {
        let Some(target) = self.find(target_host, target_path) else {
            return denied();
        };
        let Some(addr) = self.address(target) else {
            return ObliviousReply::ProxyError {
                status: "502",
                error: "dns_error",
            };
        };
        match self.relay.send(
            addr,
            &target.server_name,
            &target.path,
            message,
            RELAY_TIMEOUT,
        ) {
            Ok(Relayed::Message(message)) => ObliviousReply::Message(message),
            Ok(Relayed::Status(status)) => ObliviousReply::TargetStatus(status),
            Err(error) => {
                transport_observe::record_error("odoh", "relay", Some(addr), error);
                let status = match error {
                    RelayError::ConnectionTimeout | RelayError::HttpResponseTimeout => "504",
                    _ => "502",
                };
                ObliviousReply::ProxyError {
                    status,
                    error: error.proxy_status(),
                }
            }
        }
    }

    /// `targethost` may carry the port; 443 may be left out.
    fn find(&self, target_host: &str, target_path: &str) -> Option<&ProxyTarget> {
        let (host, port) = split_authority(target_host)?;
        let port = port.unwrap_or(443);
        self.targets.iter().find(|target| {
            target.port == port
                && target.host.eq_ignore_ascii_case(host)
                && target.path == target_path
        })
    }

    fn address(&self, target: &ProxyTarget) -> Option<SocketAddr> {
        let cached = *target.addr.lock_recover();
        if let Some((addr, expires)) = cached {
            if expires.is_none_or(|at| Instant::now() < at) {
                return Some(addr);
            }
        }
        let resolved = onetdns_forward::resolve_via_bootstrap(
            &target.host,
            &self.runtime_cfg.load().bootstrap,
            BOOTSTRAP_TIMEOUT,
        )
        .map(|(ip, ttl)| {
            let lifetime = Duration::from_secs(ttl.into()).max(MIN_TARGET_ADDR_LIFETIME);
            (SocketAddr::new(ip, target.port), lifetime)
        });
        let (addr, lifetime) = match (resolved, cached) {
            (Some(fresh), _) => fresh,
            (None, stale) => {
                transport_observe::record_error(
                    "odoh",
                    "target_lookup",
                    None,
                    format_args!("{} through the bootstrap servers", target.host),
                );
                (stale?.0, MIN_TARGET_ADDR_LIFETIME)
            }
        };
        *target.addr.lock_recover() = Some((addr, Instant::now().checked_add(lifetime)));
        Some(addr)
    }
}

fn denied() -> ObliviousReply {
    ObliviousReply::ProxyError {
        status: "403",
        error: "http_request_denied",
    }
}

/// Oblivious DoH on one DoH connection, whose peer is a proxy when this server is the target, and
/// a client when it is the proxy. `resolve` answers a DNS query as the listener answers DoH from
/// that peer; `admit_relay` is the ACL and rate limit check for a relay.
pub(crate) struct ObliviousConn<'a, R, A> {
    pub(crate) service: &'a ObliviousDoh,
    pub(crate) peer: SocketAddr,
    pub(crate) resolve: R,
    pub(crate) admit_relay: A,
}

impl<R, A> Oblivious for ObliviousConn<'_, R, A>
where
    R: Fn(&[u8]) -> Result<Option<Vec<u8>>, &'static str>,
    A: Fn() -> RelayAdmission,
{
    fn configs(&self) -> Option<Vec<u8>> {
        self.service
            .target
            .as_ref()
            .map(|target| target.configs.clone())
    }

    fn target(&self, message: &[u8]) -> ObliviousReply {
        let Some(target) = &self.service.target else {
            // Only a proxy here, and the request did not say where to relay.
            return ObliviousReply::ProxyError {
                status: "400",
                error: "http_request_error",
            };
        };
        let opened = match target.key.open_query(message) {
            Ok(opened) => opened,
            Err(error) => {
                transport_observe::record_error("odoh", "open_query", Some(self.peer), error);
                // A client holding an old config learns from 401 to fetch the current one.
                return ObliviousReply::Status(if error == OdohError::UnknownKey {
                    "401"
                } else {
                    "400"
                });
            }
        };
        let response = match refused_unless_query(opened.dns()) {
            Some(refused) => refused,
            None => match (self.resolve)(opened.dns()) {
                Ok(Some(response)) => response,
                Ok(None) => return ObliviousReply::Unanswered,
                Err(status) => return ObliviousReply::Status(status),
            },
        };
        match opened.seal_response(&response) {
            Ok(sealed) => ObliviousReply::Message(sealed),
            Err(error) => {
                transport_observe::record_error("odoh", "seal_response", Some(self.peer), error);
                ObliviousReply::Status("502")
            }
        }
    }

    fn proxy(&self, target_host: &str, target_path: &str, message: &[u8]) -> ObliviousReply {
        let Some(proxy) = &self.service.proxy else {
            return denied();
        };
        match (self.admit_relay)() {
            RelayAdmission::Allow => proxy.relay(target_host, target_path, message),
            RelayAdmission::Drop => ObliviousReply::Drop,
            RelayAdmission::Deny => denied(),
            RelayAdmission::Throttle => ObliviousReply::Status("429"),
        }
    }
}

/// The proxy's address stands for every client behind it, so a request authorized by source
/// address, such as UPDATE, NOTIFY or a zone transfer, is refused rather than granted to all of
/// them.
fn refused_unless_query(dns: &[u8]) -> Option<Vec<u8>> {
    const IXFR: u16 = 251;
    const AXFR: u16 = 252;
    let request = onetdns_proto::Message::parse(dns).ok()?;
    let transfer = request
        .questions
        .iter()
        .any(|question| matches!(question.qtype.0, IXFR | AXFR));
    if request.header.response || (request.header.opcode == 0 && !transfer) {
        return None;
    }
    crate::native::error_resp(&request, onetdns_proto::ResponseCode::Refused)
        .try_encode()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_standard_queries_reach_the_resolver() {
        let name = onetdns_proto::Name::from_str("zone.test").unwrap();
        let query = onetdns_proto::Message::query(7, name.clone(), onetdns_proto::RecordType::SOA);
        assert_eq!(refused_unless_query(&query.try_encode().unwrap()), None);
        let mut update = query.clone();
        update.header.opcode = 5;
        let mut notify = query.clone();
        notify.header.opcode = 4;
        let axfr = onetdns_proto::Message::query(7, name.clone(), onetdns_proto::RecordType(252));
        let ixfr = onetdns_proto::Message::query(7, name, onetdns_proto::RecordType(251));
        for (label, other) in [
            ("UPDATE", update),
            ("NOTIFY", notify),
            ("AXFR", axfr),
            ("IXFR", ixfr),
        ] {
            let refused = refused_unless_query(&other.try_encode().unwrap()).expect(label);
            let refused = onetdns_proto::Message::parse(&refused).unwrap();
            assert_eq!(refused.header.id, 7);
            assert_eq!(
                refused.header.rcode,
                onetdns_proto::ResponseCode::Refused.0,
                "{label}"
            );
        }
    }

    fn proxy(targets: &[&str]) -> OdohProxy {
        let targets: Vec<String> = targets.iter().map(|target| target.to_string()).collect();
        OdohProxy::new(
            &targets,
            Arc::new(ArcSwap::from_pointee(Config::default())),
            Relay::default(),
        )
    }

    #[test]
    fn proxy_targets_match_by_host_port_and_exact_path() {
        let proxy = proxy(&[
            "https://Odoh.Example/dns-query",
            "https://192.0.2.1:8443/q#odoh.example",
            "https://[2001:db8::1]/q",
        ]);
        let found = |host: &str, path: &str| {
            proxy.find(host, path).map(|target| {
                (
                    target.host.as_str(),
                    target.port,
                    target.server_name.as_str(),
                )
            })
        };
        assert_eq!(
            found("odoh.example", "/dns-query"),
            Some(("odoh.example", 443, "Odoh.Example"))
        );
        assert!(found("ODOH.EXAMPLE:443", "/dns-query").is_some());
        assert!(found("odoh.example:8443", "/dns-query").is_none());
        assert!(found("odoh.example", "/dns-query/").is_none());
        assert!(found("odoh.example", "/DNS-QUERY").is_none());
        assert!(found("other.example", "/dns-query").is_none());
        assert_eq!(
            found("192.0.2.1:8443", "/q"),
            Some(("192.0.2.1", 8443, "odoh.example"))
        );
        assert!(found("192.0.2.1", "/q").is_none());
        assert!(found("[2001:db8::1]", "/q").is_some());
        assert!(found("[2001:db8::1]:443", "/q").is_some());
        assert!(found("[2001:db8::1", "/q").is_none());
        assert!(found("odoh.example:0", "/dns-query").is_none());
    }

    #[test]
    /// An address literal needs no bootstrap servers; a hostname without them has no address.
    fn proxy_target_addresses_come_from_the_url_or_the_bootstrap_servers() {
        let proxy = proxy(&["https://192.0.2.1:8443/q", "https://odoh.example/q"]);
        let literal = proxy.find("192.0.2.1:8443", "/q").unwrap();
        assert_eq!(
            proxy.address(literal),
            Some("192.0.2.1:8443".parse().unwrap())
        );
        let named = proxy.find("odoh.example", "/q").unwrap();
        assert_eq!(proxy.address(named), None);
        assert!(matches!(
            proxy.relay("odoh.example", "/q", b"sealed"),
            ObliviousReply::ProxyError {
                status: "502",
                error: "dns_error"
            }
        ));
    }

    #[test]
    fn relays_pass_admission_before_anything_is_sent() {
        let service = ObliviousDoh {
            target: None,
            proxy: Some(proxy(&["https://odoh.example/q"])),
        };
        let conn = |admission: RelayAdmission| ObliviousConn {
            service: &service,
            peer: "192.0.2.9:4000".parse().unwrap(),
            resolve: |_: &[u8]| Ok(None),
            admit_relay: move || admission,
        };
        let reply = |admission| conn(admission).proxy("odoh.example", "/q", b"sealed");
        assert!(matches!(reply(RelayAdmission::Drop), ObliviousReply::Drop));
        assert!(matches!(
            reply(RelayAdmission::Deny),
            ObliviousReply::ProxyError {
                status: "403",
                error: "http_request_denied"
            }
        ));
        assert!(matches!(
            reply(RelayAdmission::Throttle),
            ObliviousReply::Status("429")
        ));
        assert!(matches!(
            conn(RelayAdmission::Allow).proxy("elsewhere.example", "/q", b"sealed"),
            ObliviousReply::ProxyError {
                status: "403",
                error: "http_request_denied"
            }
        ));
        assert!(matches!(
            conn(RelayAdmission::Allow).target(b"sealed"),
            ObliviousReply::ProxyError {
                status: "400",
                error: "http_request_error"
            }
        ));
        assert!(conn(RelayAdmission::Allow).configs().is_none());
    }
}
