//! Oblivious HTTP (RFC 9458) on the DoH listener. The gateway decapsulates the Binary HTTP requests
//! a relay forwards, answers those for the DoH path as DoH queries from the relay, and encapsulates
//! the responses. The relay resources pass clients' requests to the gateway each one names.

use std::net::SocketAddr;
use std::sync::Arc;

use onetdns_config::Config;
use onetdns_core::ArcSwap;
use onetdns_forward::odoh::Relay;
use onetdns_forward::ohttp::{GatewayError, GatewayKey};
use onetdns_http2::{
    bhttp, DohAnswer, GatewayReply, ObliviousHttp, ObliviousMedia, ObliviousReply,
};

use crate::native::RelayAdmission;
use crate::odoh::{admitted, refused_unless_query, Destination, Forwarder};
use crate::transport_observe;

/// The relay resources of a DoH listener, each passing requests to its one gateway.
pub(crate) struct OhttpRelays {
    resources: Vec<(String, Destination)>,
    forwarder: Forwarder,
}

impl OhttpRelays {
    /// `resources` are ones config validation accepted. Gateway hostnames are looked up through
    /// the running config's `bootstrap` on first use.
    pub(crate) fn new(
        resources: &[onetdns_config::OhttpRelay],
        runtime_cfg: Arc<ArcSwap<Config>>,
        relay: Relay,
    ) -> Self {
        let resources = resources
            .iter()
            .filter_map(|resource| {
                Some((resource.path.clone(), Destination::new(&resource.gateway)?))
            })
            .collect();
        Self {
            resources,
            forwarder: Forwarder { runtime_cfg, relay },
        }
    }

    fn gateway(&self, path: &[u8]) -> Option<&Destination> {
        self.resources
            .iter()
            .find(|(resource, _)| resource.as_bytes() == path)
            .map(|(_, gateway)| gateway)
    }
}

/// Oblivious HTTP on one DoH connection: the gateway, whose peer is a relay, and the relay
/// resources, whose peer is a client. `resolve` answers a DNS query as the listener answers DoH
/// from that peer; `admit_relay` is the ACL and rate limit check for relaying.
pub(crate) struct OhttpConn<'a, R, A> {
    pub(crate) gateway: Option<&'a GatewayKey>,
    pub(crate) relays: Option<&'a OhttpRelays>,
    pub(crate) peer: SocketAddr,
    pub(crate) doh_path: &'a str,
    pub(crate) resolve: R,
    pub(crate) admit_relay: A,
}

impl<R, A> OhttpConn<'_, R, A>
where
    R: Fn(&[u8]) -> Result<Option<DohAnswer>, &'static str>,
{
    fn answer_with(&self, key: &GatewayKey, encapsulated: &[u8]) -> GatewayReply {
        let opened = match key.open_request(encapsulated) {
            Ok(opened) => opened,
            Err(error) => {
                transport_observe::record_error("ohttp", "open_request", Some(self.peer), error);
                // RFC 9458 leaves the 4xx to the gateway; 422 tells a stale or wrong key apart
                // from a malformed request.
                return GatewayReply::Status(if error == GatewayError::Malformed {
                    "400"
                } else {
                    "422"
                });
            }
        };
        let answer = match bhttp::doh_query(opened.request(), self.doh_path) {
            Ok(query) => match refused_unless_query(&query) {
                Some(refused) => Ok(DohAnswer {
                    body: refused,
                    max_age: 0,
                }),
                None => match (self.resolve)(&query) {
                    Ok(Some(answer)) => Ok(answer),
                    Ok(None) => return GatewayReply::Unanswered,
                    Err(status) => Err(status),
                },
            },
            Err(status) => Err(status),
        };
        match opened.seal_response(&bhttp::doh_response(answer)) {
            Ok(sealed) => GatewayReply::Response(sealed),
            Err(error) => {
                transport_observe::record_error("ohttp", "seal_response", Some(self.peer), error);
                GatewayReply::Status("502")
            }
        }
    }
}

impl<R, A> ObliviousHttp for OhttpConn<'_, R, A>
where
    R: Fn(&[u8]) -> Result<Option<DohAnswer>, &'static str>,
    A: Fn() -> RelayAdmission,
{
    fn keys(&self) -> Option<Vec<u8>> {
        self.gateway.map(|key| key.keys().to_vec())
    }

    fn answer(&self, encapsulated: &[u8]) -> Option<GatewayReply> {
        self.gateway.map(|key| self.answer_with(key, encapsulated))
    }

    fn relays(&self, path: &[u8]) -> bool {
        self.relays
            .is_some_and(|relays| relays.gateway(path).is_some())
    }

    fn relay(&self, path: &[u8], encapsulated: &[u8]) -> ObliviousReply {
        let Some((forwarder, gateway)) = self
            .relays
            .and_then(|relays| Some((&relays.forwarder, relays.gateway(path)?)))
        else {
            return ObliviousReply::Status("404");
        };
        admitted((self.admit_relay)(), || {
            forwarder.send(gateway, encapsulated, ObliviousMedia::Ohttp)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use onetdns_forward::ohttp::KeyConfig;
    use onetdns_tls::hpke::PrivateKey;

    #[test]
    /// A query the resolver leaves unanswered resets the stream; a status it gives, or a request
    /// it never sees, still travels encapsulated.
    fn the_gateway_keeps_the_resolvers_decisions() {
        use onetdns_http2::bhttp::{Control, Message as Bhttp};

        let key = GatewayKey::new(PrivateKey::generate());
        let name = onetdns_proto::Name::from_str("zone.test").unwrap();
        let query = onetdns_proto::Message::query(7, name, onetdns_proto::RecordType::SOA);
        let mut update = query.clone();
        update.header.opcode = 5;
        let request = |dns: &onetdns_proto::Message| {
            Bhttp {
                control: Control::Request {
                    method: b"POST".to_vec(),
                    scheme: b"https".to_vec(),
                    authority: Vec::new(),
                    path: b"/dns-query".to_vec(),
                },
                fields: vec![(
                    b"content-type".to_vec(),
                    b"application/dns-message".to_vec(),
                )],
                content: dns.try_encode().unwrap(),
            }
            .encode()
        };
        let answer = |dns: &onetdns_proto::Message, status: Option<&'static str>| {
            let conn = OhttpConn {
                gateway: Some(&key),
                relays: None,
                peer: "192.0.2.9:4000".parse().unwrap(),
                doh_path: "/dns-query",
                resolve: move |_: &[u8]| match status {
                    Some(status) => Err(status),
                    None => Ok(None),
                },
                admit_relay: || RelayAdmission::Allow,
            };
            let (encapsulated, pending) = KeyConfig::from_keys(key.keys())
                .unwrap()
                .encapsulate(&request(dns))
                .unwrap();
            match conn.answer_with(&key, &encapsulated) {
                GatewayReply::Response(sealed) => {
                    Some(Bhttp::decode(&pending.open_response(&sealed).unwrap()).unwrap())
                }
                GatewayReply::Unanswered => None,
                GatewayReply::Status(status) => panic!("unencapsulated {status}"),
            }
        };
        assert!(answer(&query, None).is_none());
        assert_eq!(
            answer(&query, Some("429")).unwrap().control,
            Control::Response(429)
        );
        let refused = answer(&update, None).expect("UPDATE never reaches the resolver");
        assert_eq!(
            onetdns_proto::Message::parse(&refused.content)
                .unwrap()
                .header
                .rcode,
            onetdns_proto::ResponseCode::Refused.0
        );
    }
}
