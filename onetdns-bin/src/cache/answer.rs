//! Answer checks and response shaping on the way into and out of the cache. The question must
//! actually be answered, and authority records covering a negative answer must cover the queried
//! name. Responses are built from cached content, and a shared result gets this request's ID and
//! question.

use std::collections::HashSet;

use onetdns_proto::{Message, Name, RData, Record, RecordType};

/// Subtracts the elapsed time and drops expired records.
pub(crate) fn age_records(records: &mut Vec<Record>, elapsed_secs: u64) {
    records.retain_mut(|record| {
        let remaining = u64::from(record.ttl).saturating_sub(elapsed_secs);
        if remaining == 0 {
            false
        } else {
            record.ttl = remaining as u32;
            true
        }
    });
}

/// Follows aliases; false on a loop, or when an alias and other records share a name. Caching a
/// response for which this is false as a positive answer would let a peer that sent only unrelated
/// records occupy the cache.
pub(crate) fn has_requested_answer(request: &Message, answers: &[Record]) -> bool {
    let Some(question) = request.questions.first() else {
        return false;
    };
    let mut current = question.name.clone();
    let mut seen = HashSet::new();
    for _ in 0..16 {
        let alias = match next_alias(&current, question.qclass, answers) {
            Ok(alias) => alias,
            Err(()) => return false,
        };
        let at_current = |record: &Record| record.name.eq_ignore_case(&current);
        if question.qtype == RecordType::ANY {
            if answers
                .iter()
                .any(|record| record.class == question.qclass && at_current(record))
            {
                return true;
            }
        } else if answers.iter().any(|record| {
            record.class == question.qclass
                && record.name.eq_ignore_case(&current)
                && record.rtype == question.qtype
        }) {
            return true;
        }
        if !seen.insert(current.canonical_key()) {
            return false;
        }
        let Some(next) = alias else {
            return false;
        };
        current = next;
    }
    false
}

pub(crate) fn terminal_answer_name(request: &Message, answers: &[Record]) -> Option<Name> {
    let question = request.questions.first()?;
    let mut current = question.name.clone();
    let mut seen = HashSet::new();
    for _ in 0..16 {
        if !seen.insert(current.canonical_key()) {
            return None;
        }
        match next_alias(&current, question.qclass, answers) {
            Ok(Some(next)) => current = next,
            Ok(None) => return Some(current),
            Err(()) => return None,
        }
    }
    None
}

/// Different aliases for one name, or an alias alongside other records, is an error: accepting it
/// would make the answer depend on which one is followed.
fn next_alias(
    current: &Name,
    qclass: onetdns_proto::DnsClass,
    answers: &[Record],
) -> Result<Option<Name>, ()> {
    let mut cname: Option<Name> = None;
    for record in answers {
        if record.class != qclass || !record.name.eq_ignore_case(current) {
            continue;
        }
        if let RData::Cname(target) = &record.rdata {
            if cname
                .as_ref()
                .is_some_and(|existing| !existing.eq_ignore_case(target))
            {
                return Err(());
            }
            cname = Some(target.clone());
        }
    }
    if cname.is_some()
        && answers.iter().any(|record| {
            record.class == qclass
                && record.name.eq_ignore_case(current)
                && !matches!(
                    record.rtype,
                    RecordType::CNAME | RecordType::RRSIG | RecordType::NSEC
                )
        })
    {
        return Err(());
    }
    if cname.is_some() {
        return Ok(cname);
    }

    let Some(record) = answers
        .iter()
        .filter(|record| {
            record.class == qclass
                && matches!(&record.rdata, RData::Dname(_))
                && current.num_labels() > record.name.num_labels()
                && current
                    .suffix(record.name.num_labels())
                    .eq_ignore_case(&record.name)
        })
        .max_by_key(|record| record.name.num_labels())
    else {
        return Ok(None);
    };
    let RData::Dname(target) = &record.rdata else {
        return Ok(None);
    };
    if answers.iter().any(|candidate| {
        candidate.class == qclass
            && candidate.name.eq_ignore_case(&record.name)
            && matches!(
                &candidate.rdata,
                RData::Dname(other) if !other.eq_ignore_case(target)
            )
    }) {
        return Err(());
    }
    let prefix_len = current.num_labels() - record.name.num_labels();
    let mut labels: Vec<Vec<u8>> = current
        .labels()
        .take(prefix_len)
        .map(<[u8]>::to_vec)
        .collect();
    labels.extend(target.labels().map(<[u8]>::to_vec));
    Ok(Name::from_labels(labels).ok())
}

/// Only authority records covering the queried name count; accepting unrelated ones would let
/// anyone plant a nonexistence answer in this cache.
pub(crate) fn relevant_negative_soa_minimum(
    request: &Message,
    answers: &[Record],
    authorities: &[Record],
) -> Option<u32> {
    let qclass = request.questions.first()?.qclass;
    let terminal = terminal_answer_name(request, answers)?;
    authorities
        .iter()
        .filter_map(|record| match &record.rdata {
            RData::Soa(soa)
                if record.class == qclass
                    && record.name.num_labels() <= terminal.num_labels()
                    && terminal
                        .suffix(record.name.num_labels())
                        .eq_ignore_case(&record.name) =>
            {
                Some(soa.minimum.min(record.ttl))
            }
            _ => None,
        })
        .min()
}

pub(crate) fn neg_soa_minimum(request: &Message, msg: &Message) -> Option<u32> {
    relevant_negative_soa_minimum(request, &msg.answers, &msg.authorities)
}

/// Without this request's ID and question, the client would not recognize the answer as its own.
pub(crate) fn retarget_response(mut response: Message, request: &Message) -> Message {
    response.header.id = request.header.id;
    response.header.opcode = request.header.opcode;
    response.header.recursion_desired = request.header.recursion_desired;
    response.header.checking_disabled = request.header.checking_disabled;
    response.questions = request.questions.clone();
    response
}

pub(crate) fn cached_message(
    req: &Message,
    rcode: u16,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
    authentic: bool,
) -> Message {
    let mut m = Message::default();
    m.header.id = req.header.id;
    m.header.response = true;
    m.header.opcode = req.header.opcode;
    m.header.recursion_desired = req.header.recursion_desired;
    m.header.recursion_available = true;
    m.header.checking_disabled = req.header.checking_disabled;
    m.header.rcode = rcode;
    m.header.authentic_data = authentic;
    m.questions = req.questions.clone();
    m.answers = answers;
    m.authorities = authorities;
    m.additionals = additionals;
    m
}
