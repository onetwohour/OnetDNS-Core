//! Layers of the resolver chain. Each holds an inner resolver and answers when it can, otherwise
//! passes the query on. Stacking order is priority, and tests pin it.
//!
//! A layer that makes responses depend on the request, the client, or the time must add itself to
//! the UDP fast path conditions; otherwise cached answers go out as if the layer were absent.

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
pub use cache_db::{CacheDbLayer, CacheDbScope};
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

const MAX_SEMANTIC_KEY_WIRE: usize = 4_096;

/// None when malformed.
fn configured_name_key(name: &str) -> Option<Vec<u8>> {
    Name::from_str(name.trim())
        .ok()
        .map(|name| name.canonical_key())
}

/// Request bytes with what does not change the response removed: the ID, name case, and empty
/// padding, so equivalent queries share a key. None for an uncacheable shape or when too long.
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

/// Without the ID and question echoed back, the client would not recognize its answer.
fn retarget_message(mut response: Message, request: &Message) -> Message {
    response.header.id = request.header.id;
    response.header.opcode = request.header.opcode;
    response.header.recursion_desired = request.header.recursion_desired;
    response.header.checking_disabled = request.header.checking_disabled;
    response.questions = request.questions.clone();
    response
}

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

fn is_zone_ancestor(zone: &Name, qname: &Name) -> bool {
    zone.num_labels() <= qname.num_labels() && qname.suffix(zone.num_labels()).eq_ignore_case(zone)
}

/// With opt-out, nonexistence cannot be concluded.
fn nsec3_has_optout(records: &[Record]) -> bool {
    records
        .iter()
        .filter_map(onetdns_dnssec::Nsec3::from_record)
        .any(|n| n.flags & 1 != 0)
}

/// Sets DO on the request a proof-learning layer sends down. Backends strip NSEC and RRSIG from
/// answers to requests without DO, and most clients do not set it, so asking as is would learn no
/// proofs. After learning, the response is stripped again to match the original request.
fn with_dnssec_records(req: &Message) -> std::borrow::Cow<'_, Message> {
    if crate::native::wants_dnssec(req) {
        return std::borrow::Cow::Borrowed(req);
    }
    let mut asked = req.clone();
    crate::dnssecfwd::set_dnssec_ok(&mut asked);
    std::borrow::Cow::Owned(asked)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn outcome_to_option(outcome: ResolveOutcome) -> Option<Message> {
    match outcome {
        ResolveOutcome::Response(response) => Some(response),
        ResolveOutcome::Failure(_) => None,
    }
}

#[cfg(test)]
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
