//! RFC 9462 DDR: announces the encrypted listeners in _dns.resolver.arpa SVCB records.

use std::sync::Arc;

use onetdns_proto::{DnsClass, Message, Name, RData, Record, RecordType};

use super::{answer_message, outcome_to_option};
use crate::native::{ResolveOutcome, Resolver};

/// Short, so clients do not hold on to stale endpoints.
const DDR_TTL: u32 = 300;

/// SvcParamKey alpn, RFC 9460.
const SVCB_KEY_ALPN: u16 = 1;

/// SvcParamKey port, RFC 9460.
const SVCB_KEY_PORT: u16 = 3;

/// SvcParamKey dohpath, RFC 9461.
const SVCB_KEY_DOHPATH: u16 = 7;

/// One encrypted transport to announce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DdrEndpoint {
    /// Lower is tried first.
    pub priority: u16,
    /// h2 or h3 for DoH.
    pub alpn: &'static [&'static str],
    pub port: u16,
    /// URI template; DoH only.
    pub dohpath: Option<String>,
}

impl DdrEndpoint {
    /// In ascending key order, as SVCB records and DNR options both require.
    pub fn svc_params(&self) -> Result<Vec<(u16, Box<[u8]>)>, String> {
        let mut params: Vec<(u16, Box<[u8]>)> = Vec::with_capacity(3);
        let mut alpn = Vec::new();
        for id in self.alpn {
            let bytes = id.as_bytes();
            if bytes.is_empty() || bytes.len() > u8::MAX as usize {
                return Err(format!("DDR ALPN identifier '{id}' has an invalid length"));
            }
            alpn.push(bytes.len() as u8);
            alpn.extend_from_slice(bytes);
        }
        params.push((SVCB_KEY_ALPN, alpn.into_boxed_slice()));
        params.push((SVCB_KEY_PORT, Box::from(self.port.to_be_bytes().as_slice())));
        if let Some(path) = &self.dohpath {
            params.push((SVCB_KEY_DOHPATH, Box::from(path.as_bytes())));
        }
        Ok(params)
    }
}

/// Lets clients that ask over Do53 upgrade to DoH, DoT, or DoQ. The answer depends on neither the
/// client nor the time, so it is built once and cloned per query.
pub struct DdrLayer {
    inner: Arc<dyn Resolver>,
    owner: Name,
    records: Vec<Record>,
    /// For NODATA to other types. An empty NOERROR needs a SOA (RFC 2308); without one, the outer
    /// response check treats it as broken and turns it into SERVFAIL.
    negative_soa: Record,
}

impl DdrLayer {
    /// `name` is the authentication name clients check the TLS certificate against. Fails on an
    /// invalid name; None without endpoints.
    pub fn new(
        inner: Arc<dyn Resolver>,
        name: &str,
        endpoints: &[DdrEndpoint],
    ) -> Result<Option<Self>, String> {
        if endpoints.is_empty() {
            return Ok(None);
        }
        let owner = Name::from_str("_dns.resolver.arpa")
            .map_err(|error| format!("Could not build the DDR name: {error}"))?;
        let target = Name::from_str(name).map_err(|error| {
            format!("Could not turn ddr_name '{name}' into a DNS name: {error}")
        })?;
        let mut records = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            records.push(Record::new(
                owner.clone(),
                DDR_TTL,
                RData::Svcb {
                    priority: endpoint.priority,
                    target: target.clone(),
                    params: endpoint.svc_params()?.into_boxed_slice(),
                },
            ));
        }
        // The SOA owner is the zone apex. resolver.arpa is special-use, so this server answers it
        // locally.
        let apex = Name::from_str("resolver.arpa")
            .map_err(|error| format!("Could not build the resolver.arpa name: {error}"))?;
        let negative_soa = Record::new(
            apex.clone(),
            DDR_TTL,
            RData::soa(onetdns_proto::Soa {
                mname: apex.clone(),
                rname: apex,
                serial: 1,
                refresh: DDR_TTL,
                retry: DDR_TTL,
                expire: DDR_TTL.saturating_mul(24).max(DDR_TTL),
                minimum: DDR_TTL,
            }),
        );
        Ok(Some(DdrLayer {
            inner,
            owner,
            records,
            negative_soa,
        }))
    }
}

impl Resolver for DdrLayer {
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /// Other types at this name get NODATA: resolver.arpa is special-use and must not leak
    /// upstream.
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        if let Some(q) = req.questions.first() {
            if q.qclass == DnsClass::IN && q.name.eq_ignore_case(&self.owner) {
                let answers = if q.qtype == RecordType::SVCB {
                    self.records
                        .iter()
                        .map(|record| {
                            let mut record = record.clone();
                            record.name = q.name.clone();
                            record
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                let mut response = answer_message(req.header.id, q.name.clone(), q.qtype, answers);
                response.header.authoritative = true;
                if response.answers.is_empty() {
                    response.authorities.push(self.negative_soa.clone());
                }
                return ResolveOutcome::Response(response);
            }
        }
        self.inner.resolve_outcome(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use onetdns_proto::{Message, Name, RData, RecordType, ResponseCode};

    use crate::native::Resolver;

    fn ddr_layer(backend: Arc<dyn Resolver>) -> DdrLayer {
        DdrLayer::new(
            backend,
            "dns.example.net",
            &[
                DdrEndpoint {
                    priority: 1,
                    alpn: &["h2"],
                    port: 443,
                    dohpath: Some("/dns-query{?dns}".to_string()),
                },
                DdrEndpoint {
                    priority: 3,
                    alpn: &["dot"],
                    port: 853,
                    dohpath: None,
                },
            ],
        )
        .expect("DDR 계층 생성")
        .expect("알릴 전송이 있으면 계층이 생김")
    }

    #[test]
    fn ddr_layer_answers_resolver_arpa_with_encrypted_endpoints() {
        let backend = Mock::new(9, 2);
        let layer = ddr_layer(backend.clone() as Arc<dyn Resolver>);
        let q = Message::query(
            0x1234,
            Name::from_str("_dns.resolver.arpa").unwrap(),
            RecordType::SVCB,
        );
        let resp = layer.resolve(&q).expect("DDR 응답");
        assert_eq!(resp.header.id, 0x1234);
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
        assert!(resp.header.authoritative);
        assert_eq!(
            backend.calls.load(Ordering::SeqCst),
            0,
            "resolver.arpa는 업스트림으로 새지 않아야 합니다"
        );
        assert_eq!(resp.answers.len(), 2);

        let target = Name::from_str("dns.example.net").unwrap();
        let doh = match &resp.answers[0].rdata {
            RData::Svcb {
                priority,
                target: t,
                params,
            } => {
                assert_eq!(*priority, 1);
                assert!(t.eq_ignore_case(&target));
                params.clone()
            }
            other => panic!("SVCB가 아님: {other:?}"),
        };
        // alpn (1) is a length-prefixed list, port (3) a big-endian u16, dohpath (7) a template.
        assert_eq!(doh[0], (1, Box::from(&b"\x02h2"[..])));
        assert_eq!(doh[1], (3, Box::from(&443u16.to_be_bytes()[..])));
        assert_eq!(doh[2], (7, Box::from(&b"/dns-query{?dns}"[..])));
        assert!(
            doh.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "SVCB 매개변수 키는 오름차순이어야 합니다"
        );

        // Encoding fails on a wrong parameter order.
        let wire = resp.try_encode().expect("DDR 응답 인코딩");
        let parsed = Message::parse(&wire).expect("DDR 응답 재파싱");
        assert_eq!(parsed.answers.len(), 2);
    }

    #[test]
    fn ddr_layer_closes_other_types_on_resolver_arpa() {
        let backend = Mock::new(9, 2);
        let layer = ddr_layer(backend.clone() as Arc<dyn Resolver>);
        let apex = Name::from_str("resolver.arpa").unwrap();
        for qtype in [RecordType::A, RecordType::AAAA, RecordType::TXT] {
            let q = Message::query(1, Name::from_str("_DNS.Resolver.ARPA").unwrap(), qtype);
            let resp = layer.resolve(&q).expect("NODATA 응답");
            assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
            assert!(resp.answers.is_empty(), "{qtype:?}에는 답이 없어야 합니다");
            assert!(
                resp.authorities.iter().any(|record| {
                    matches!(&record.rdata, RData::Soa(_)) && record.name.eq_ignore_case(&apex)
                }),
                "{qtype:?} 부정 응답에 영역 꼭대기 SOA가 있어야 합니다"
            );
        }
        assert_eq!(
            backend.calls.load(Ordering::SeqCst),
            0,
            "특수 용도 이름은 업스트림으로 새지 않아야 합니다"
        );
    }

    #[test]
    fn ddr_layer_passes_other_names_through() {
        let backend = Mock::new(9, ResponseCode::NoError.0);
        let layer = ddr_layer(backend.clone() as Arc<dyn Resolver>);
        let q = Message::query(1, Name::from_str("example.com").unwrap(), RecordType::SVCB);
        layer.resolve(&q).expect("안쪽 응답");
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ddr_layer_is_absent_without_encrypted_listeners() {
        let backend = Mock::new(9, 2) as Arc<dyn Resolver>;
        assert!(DdrLayer::new(backend, "dns.example.net", &[])
            .expect("빈 목록은 오류가 아님")
            .is_none());
    }
}
