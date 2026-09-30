/*!
 * @brief 해석 체인을 이루는 계층들.
 *
 * @details 각 계층은 안쪽 리졸버를 하나 잡고, 자기 차례에 답할 수 있으면 답하고 아니면
 *          안으로 넘긴다. 쌓는 순서가 곧 우선순위다.
 * @warning 순서를 바꾸면 동작이 바뀐다. 순서는 테스트로 고정돼 있다.
 * @note 응답을 요청·클라이언트·시각에 따라 달라지게 하는 계층은 UDP 고속 경로 조건에
 *       스스로를 넣어야 한다. 넣지 않으면 그 계층이 없는 것처럼 캐시된 답이 나간다.
 */

mod acme_challenge;
mod aggressive_nsec;
mod authority;
mod below_nxdomain;
mod cache_db;
mod ddr;
mod dhcp_dns;
mod dynamic_record;
mod ecs;
mod fallback;
mod ipset;
mod local_address;
mod local_only;
mod name_rate_limit;
mod prefetch;
mod serve_stale;
mod split;
mod stub;
#[cfg(test)]
mod test_support;

pub use acme_challenge::AcmeChallengeLayer;
pub use aggressive_nsec::AggressiveNsecLayer;
pub use authority::AuthorityLayer;
pub use below_nxdomain::BelowNxdomainLayer;
pub use cache_db::CacheDbLayer;
pub use ddr::{DdrEndpoint, DdrLayer};
pub use dhcp_dns::DhcpDnsLayer;
pub use dynamic_record::DynamicRecordLayer;
pub use ecs::EcsLayer;
pub use fallback::FallbackLayer;
pub use ipset::IpsetLayer;
pub use local_address::{LocalAddressLayer, LocalAddressTable};
pub use local_only::{LocalOnlyLayer, LocalOnlyNames};
pub use name_rate_limit::NameRateLimitLayer;
pub use prefetch::{PrefetchLayer, PrefetchRefresher};
pub use serve_stale::ServeStaleLayer;
pub use split::{Route, SplitResolver};
pub use stub::StubLayer;

use onetdns_proto::{DnsClass, Edns, Message, Name, Question, Record, RecordType};

use crate::native::ResolveOutcome;

/** @brief 의미 키로 삼을 요청 바이트의 길이 상한. */
const MAX_SEMANTIC_KEY_WIRE: usize = 4_096;

/** @brief 설정에 적힌 이름을 비교용 키로. 형식이 틀리면 없다. */
fn configured_name_key(name: &str) -> Option<Vec<u8>> {
    Name::from_str(name.trim())
        .ok()
        .map(|name| name.canonical_key())
}

/**
 * @brief 응답을 달라지게 하지 않는 것만 지운 요청 바이트.
 * @details 질의 번호와 이름 대소문자, 내용 없는 채우기 옵션을 지운다. 같은 뜻의 질의가
 *          같은 키를 갖게 하려는 것이다.
 * @return 키. 캐시할 수 없는 모양이거나 너무 길면 없다.
 */
fn semantic_request_key(request: &Message) -> Option<Vec<u8>> {
    if request.header.response
        || request.header.opcode != 0
        || request.header.authoritative
        || request.header.truncated
        || request.header.recursion_available
        || request.header.rcode != 0
        || request.questions.len() != 1
        || !request.answers.is_empty()
        || !request.authorities.is_empty()
        || request
            .additionals
            .iter()
            .any(|record| record.rtype != RecordType::OPT)
    {
        return None;
    }
    let mut normalized = request.clone();
    normalized.header.id = 0;
    for question in &mut normalized.questions {
        let labels = question
            .name
            .labels()
            .iter()
            .map(|label| label.iter().map(u8::to_ascii_lowercase).collect())
            .collect();
        question.name = Name::from_labels(labels).ok()?;
    }
    for record in &mut normalized.additionals {
        if record.rtype == RecordType::OPT {
            if let Some(mut edns) = Edns::from_record(record) {
                edns.options
                    .retain(|(code, _)| *code != onetdns_proto::EDNS_PADDING);
                *record = edns.try_to_record().ok()?;
            }
        }
    }
    let wire = normalized.try_encode().ok()?;
    (wire.len() <= MAX_SEMANTIC_KEY_WIRE).then_some(wire)
}

/** @brief 담아 둔 응답을 이 요청에 맞춰 고친다. 번호와 질문을 되비추지 않으면 자기 답으로 알아보지 못한다. */
fn retarget_message(mut response: Message, request: &Message) -> Message {
    response.header.id = request.header.id;
    response.header.opcode = request.header.opcode;
    response.header.recursion_desired = request.header.recursion_desired;
    response.header.checking_disabled = request.header.checking_disabled;
    response.questions = request.questions.clone();
    response
}

/** @brief 모든 구간의 수명에 상한을 건다. */
fn cap_message_ttls(message: &mut Message, cap: u32) {
    for record in message
        .answers
        .iter_mut()
        .chain(message.authorities.iter_mut())
        .chain(message.additionals.iter_mut())
    {
        if record.rtype != RecordType::OPT {
            record.ttl = record.ttl.min(cap);
        }
    }
}

/** @brief 답 기록들로 응답을 만든다. */
fn answer_message(id: u16, name: Name, qtype: RecordType, answers: Vec<Record>) -> Message {
    let mut m = Message::default();
    m.header.id = id;
    m.header.response = true;
    m.header.recursion_available = true;
    m.questions = vec![Question {
        name,
        qtype,
        qclass: DnsClass::IN,
    }];
    m.answers = answers;
    m
}

/** @brief 이 영역이 그 이름을 덮는지. */
fn is_zone_ancestor(zone: &Name, qname: &Name) -> bool {
    zone.num_labels() <= qname.num_labels() && qname.suffix(zone.num_labels()).eq_ignore_case(zone)
}

/** @brief 증명이 일부 이름을 비워 두는 방식인지. 그렇다면 없다고 단정할 수 없다. */
fn nsec3_has_optout(records: &[Record]) -> bool {
    records
        .iter()
        .filter_map(onetdns_dnssec::Nsec3::from_record)
        .any(|n| n.flags & 1 != 0)
}

/**
 * @brief 부재 증명을 배우는 계층이 아래로 물을 요청. DO를 설정한다.
 * @details 해석 백엔드는 DO를 설정하지 않은 요청의 답에서 NSEC과 RRSIG를 걷어낸다. 그대로 물으면
 *          DO 없이 묻는 대부분의 클라이언트에게서는 증명을 하나도 배우지 못한다. 배운 뒤에는
 *          원래 요청대로 다시 걷어낸다.
 */
fn with_dnssec_records(req: &Message) -> std::borrow::Cow<'_, Message> {
    if crate::native::wants_dnssec(req) {
        return std::borrow::Cow::Borrowed(req);
    }
    let mut asked = req.clone();
    crate::dnssecfwd::set_dnssec_ok(&mut asked);
    std::borrow::Cow::Owned(asked)
}

/** @brief 현재 Unix 초. */
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/** @brief 결과를 있음·없음으로 바꾼다. */
pub(crate) fn outcome_to_option(outcome: ResolveOutcome) -> Option<Message> {
    match outcome {
        ResolveOutcome::Response(response) => Some(response),
        ResolveOutcome::Failure(_) => None,
    }
}

#[cfg(test)]
/** @brief 경로 이름을 받는 계층들이 설정 이름을 같은 규칙으로 다루는지. */
mod tests {
    use crate::layers::test_support::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::AtomicU32;
    use std::sync::Arc;

    use onetdns_proto::{Message, Name, RData, RecordType, ResponseCode};

    use crate::layers::ipset::IpsetLayer;
    use crate::layers::local_address::{LocalAddressLayer, LocalAddressTable};
    use crate::layers::split::{Route, SplitResolver};
    use crate::layers::stub::StubLayer;
    use crate::native::Resolver;

    #[test]
    /** @brief 설정한 이름이 조용히 사라지거나 겹치지 않는지. */
    fn configured_route_names_cannot_disappear_or_conflict() {
        let forward = Mock::new(1, ResponseCode::NoError.0) as Arc<dyn Resolver>;
        let recurse = Mock::new(2, ResponseCode::NoError.0) as Arc<dyn Resolver>;

        assert!(StubLayer::new(
            forward.clone(),
            vec![("bad..stub".to_string(), recurse.clone())],
        )
        .is_err());
        assert!(SplitResolver::new(
            forward.clone(),
            recurse.clone(),
            Route::Forward,
            &["bad..recurse".to_string()],
            &[],
        )
        .is_err());
        assert!(SplitResolver::new(
            forward.clone(),
            recurse.clone(),
            Route::Forward,
            &["same.example".to_string()],
            &["same.example.".to_string()],
        )
        .is_err());
        assert!(LocalAddressTable::new(
            &[("bad..local".to_string(), Ipv4Addr::new(192, 0, 2, 1))],
            &[],
            Arc::new(AtomicU32::new(300)),
        )
        .is_err());
        assert!(IpsetLayer::new(
            forward,
            Some("v4set".to_string()),
            None,
            &["bad..ipset".to_string()],
        )
        .is_err());
    }

    #[test]
    /** @brief 분기 판정에서 이름의 원래 바이트가 바뀌지 않는지. */
    fn stub_and_split_routing_preserve_raw_name_octets() {
        let inner = Mock::new(1, ResponseCode::NoError.0);
        let routed = Mock::new(9, ResponseCode::NoError.0);
        let replacement = "�".to_string();
        let valid = Name::from_str(&replacement).unwrap();
        let invalid = Name::from_labels(vec![vec![0xff]]).unwrap();

        let stub = StubLayer::new(
            inner.clone(),
            vec![(replacement.clone(), routed.clone() as Arc<dyn Resolver>)],
        )
        .unwrap();
        let request = |name| Message::query(1, name, RecordType::A);
        assert_eq!(
            stub.resolve(&request(valid.clone())).unwrap().answers[0].ttl,
            9
        );
        assert_eq!(
            stub.resolve(&request(invalid.clone())).unwrap().answers[0].ttl,
            1
        );

        let split = SplitResolver::new(
            inner,
            routed,
            Route::Forward,
            std::slice::from_ref(&replacement),
            &[],
        )
        .unwrap();
        let addresses = Arc::new(
            LocalAddressTable::new(
                &[(replacement.clone(), Ipv4Addr::new(192, 0, 2, 1))],
                &[],
                Arc::new(AtomicU32::new(300)),
            )
            .unwrap(),
        );
        let split = LocalAddressLayer::new(Arc::new(split), addresses, None);
        assert!(matches!(
            split.resolve(&request(valid)).unwrap().answers[0].rdata,
            RData::A(ip) if ip == Ipv4Addr::new(192, 0, 2, 1)
        ));
        assert_eq!(
            split.resolve(&request(invalid)).unwrap().answers[0].ttl,
            1,
            "invalid UTF-8 label must not collide with configured U+FFFD"
        );
    }
}
