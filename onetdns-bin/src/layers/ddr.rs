/*!
 * @brief RFC 9462 DDR. _dns.resolver.arpa SVCB로 암호화 리스너를 알리는 계층.
 */

use std::sync::Arc;

use onetdns_proto::{DnsClass, Message, Name, RData, Record, RecordType};

use super::{answer_message, outcome_to_option};
use crate::native::{ResolveOutcome, Resolver};

/** @brief DDR 답의 수명. 클라이언트가 승격 정보를 오래 붙들지 않게 짧게 둔다. */
const DDR_TTL: u32 = 300;

/** @brief SVCB alpn 매개변수 키(RFC 9460). */
const SVCB_KEY_ALPN: u16 = 1;

/** @brief SVCB port 매개변수 키(RFC 9460). */
const SVCB_KEY_PORT: u16 = 3;

/** @brief SVCB dohpath 매개변수 키(RFC 9461). */
const SVCB_KEY_DOHPATH: u16 = 7;

/**
 * @brief 암호화 전송 하나를 DDR로 알리기 위한 재료.
 * @details 우선순위는 이 리졸버가 권하는 순서다. 값이 작을수록 먼저 시도된다.
 */
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DdrEndpoint {
    /** @brief 권하는 순서. */
    pub priority: u16,
    /** @brief 이 전송의 ALPN 표식들. DoH는 h2 또는 h3다. */
    pub alpn: &'static [&'static str],
    /** @brief 이 전송이 듣고 있는 포트. */
    pub port: u16,
    /** @brief DoH 계열에만 있는 질의 template. */
    pub dohpath: Option<String>,
}

/**
 * @brief _dns.resolver.arpa SVCB 질의에 암호화 전송을 알리는 계층(RFC 9462).
 *
 * @details 클라이언트가 Do53으로 물어 온 곳에서 DoH·DoT·DoQ로 스스로 올라오게 하는 것이
 *          목적이다. 답은 클라이언트와 무관하게 같고 설정이 바뀌면 세대가 바뀌므로 시간에
 *          따라 달라지지도 않는다.
 * @warning 답은 미리 만들어 두고 질의마다 복제만 한다. 이름과 매개변수가 질의에 따라
 *          달라지지 않기 때문이다.
 */
pub struct DdrLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 이 서버가 답하는 이름. _dns.resolver.arpa다. */
    owner: Name,
    /** @brief 미리 만들어 둔 SVCB 답들. */
    records: Vec<Record>,
    /**
     * @brief 다른 타입에 돌려줄 부정 응답의 권한 기록.
     * @note 빈 NOERROR는 부정 SOA가 있어야 한다(RFC 2308). 없으면 바깥의 응답 검증이
     *       망가진 답으로 보고 SERVFAIL로 바꾼다.
     */
    negative_soa: Record,
}

impl DdrLayer {
    /**
     * @brief 알릴 전송 목록으로 계층을 만든다.
     *
     * @param name 이 리졸버의 인증 이름. 클라이언트가 TLS 인증서를 이 이름으로 검증한다.
     * @param endpoints 알릴 전송들. 비어 있으면 알릴 것이 없다는 뜻이다.
     * @return 이름이 올바르지 않으면 오류. 알릴 전송이 없으면 None.
     */
    pub fn new(
        inner: Arc<dyn Resolver>,
        name: &str,
        endpoints: &[DdrEndpoint],
    ) -> Result<Option<Self>, String> {
        if endpoints.is_empty() {
            return Ok(None);
        }
        let owner = Name::from_str("_dns.resolver.arpa")
            .map_err(|error| format!("DDR 이름을 만들지 못했습니다: {error}"))?;
        let target = Name::from_str(name)
            .map_err(|error| format!("ddr_name '{name}'을 이름으로 만들지 못했습니다: {error}"))?;
        let mut records = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            // 매개변수는 키 오름차순이어야 한다. 인코더가 그것을 검사한다.
            let mut params: Vec<(u16, Box<[u8]>)> = Vec::with_capacity(3);
            let mut alpn = Vec::new();
            for id in endpoint.alpn {
                let bytes = id.as_bytes();
                if bytes.is_empty() || bytes.len() > u8::MAX as usize {
                    return Err(format!("DDR ALPN 표식 '{id}'의 길이가 올바르지 않습니다"));
                }
                alpn.push(bytes.len() as u8);
                alpn.extend_from_slice(bytes);
            }
            params.push((SVCB_KEY_ALPN, alpn.into_boxed_slice()));
            params.push((
                SVCB_KEY_PORT,
                Box::from(endpoint.port.to_be_bytes().as_slice()),
            ));
            if let Some(path) = &endpoint.dohpath {
                params.push((SVCB_KEY_DOHPATH, Box::from(path.as_bytes())));
            }
            records.push(Record::new(
                owner.clone(),
                DDR_TTL,
                RData::Svcb {
                    priority: endpoint.priority,
                    target: target.clone(),
                    params: params.into_boxed_slice(),
                },
            ));
        }
        // 부정 응답의 SOA 소유자는 영역 꼭대기다. resolver.arpa는 특수 용도 이름이라
        // 이 서버가 로컬에서 맡는다.
        let apex = Name::from_str("resolver.arpa")
            .map_err(|error| format!("resolver.arpa 이름을 만들지 못했습니다: {error}"))?;
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
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /**
     * @brief 승격 안내를 묻는 이름이면 답하고, 아니면 지나간다.
     * @note 같은 이름의 다른 타입은 NODATA로 닫는다. resolver.arpa는 특수 용도 이름이라
     *       업스트림으로 새어 나가면 안 된다.
     */
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
/** @brief DDR 응답 형식과 다른 이름·유형의 처리. */
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use onetdns_proto::{Message, Name, RData, RecordType, ResponseCode};

    use crate::native::Resolver;

    /** @brief 테스트용 DDR 계층 하나. DoH·DoT 둘을 알린다. */
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
    /** @brief 승격 안내가 SVCB로 나가고 인코딩까지 통과하는지. */
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
        // alpn(1)은 길이 앞붙임 목록, port(3)는 big-endian u16, dohpath(7)는 template이다.
        assert_eq!(doh[0], (1, Box::from(&b"\x02h2"[..])));
        assert_eq!(doh[1], (3, Box::from(&443u16.to_be_bytes()[..])));
        assert_eq!(doh[2], (7, Box::from(&b"/dns-query{?dns}"[..])));
        assert!(
            doh.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "SVCB 매개변수 키는 오름차순이어야 합니다"
        );

        // 실제로 와이어에 담기는지까지 본다. 매개변수 순서가 틀리면 여기서 걸린다.
        let wire = resp.try_encode().expect("DDR 응답 인코딩");
        let parsed = Message::parse(&wire).expect("DDR 응답 재파싱");
        assert_eq!(parsed.answers.len(), 2);
    }

    #[test]
    /** @brief 같은 이름의 다른 타입을 업스트림으로 흘리지 않는지. */
    fn ddr_layer_closes_other_types_on_resolver_arpa() {
        let backend = Mock::new(9, 2);
        let layer = ddr_layer(backend.clone() as Arc<dyn Resolver>);
        let apex = Name::from_str("resolver.arpa").unwrap();
        for qtype in [RecordType::A, RecordType::AAAA, RecordType::TXT] {
            let q = Message::query(1, Name::from_str("_DNS.Resolver.ARPA").unwrap(), qtype);
            let resp = layer.resolve(&q).expect("NODATA 응답");
            assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
            assert!(resp.answers.is_empty(), "{qtype:?}에는 답이 없어야 합니다");
            // 부정 SOA가 없으면 빈 NOERROR가 되어 바깥 응답 검증이 SERVFAIL로 바꾼다.
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
    /** @brief 다른 이름은 그대로 지나가는지. */
    fn ddr_layer_passes_other_names_through() {
        let backend = Mock::new(9, ResponseCode::NoError.0);
        let layer = ddr_layer(backend.clone() as Arc<dyn Resolver>);
        let q = Message::query(1, Name::from_str("example.com").unwrap(), RecordType::SVCB);
        layer.resolve(&q).expect("안쪽 응답");
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    /** @brief 알릴 전송이 없으면 계층을 만들지 않는지. */
    fn ddr_layer_is_absent_without_encrypted_listeners() {
        let backend = Mock::new(9, 2) as Arc<dyn Resolver>;
        assert!(DdrLayer::new(backend, "dns.example.net", &[])
            .expect("빈 목록은 오류가 아님")
            .is_none());
    }
}
