/*!
 * @brief 캐시가 응답을 받아들이고 돌려줄 때 거치는 답 검증과 응답 가공.
 *
 * @details 질문한 것이 실제로 답에 들어 있는지, 부정 응답을 덮는 권한 기록이 질문한 이름을
 *          가리키는지 본다. 담아 둔 내용으로 이 요청에 대한 응답을 짓고, 남의 결과를 나눠
 *          줄 때 질의 번호와 질문을 이 요청에 맞게 되비춘다.
 */

use std::collections::HashSet;

use onetdns_proto::{Message, Name, RData, Record, RecordType};

/** @brief 흐른 만큼 수명을 깎고, 다한 것은 뺀다. */
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

/**
 * @brief 질문한 것이 실제로 답에 들어 있는지.
 * @details 별칭을 따라가며 본다. 순환이 생기거나 별칭과 다른 기록이 같은 이름에 함께
 *          오면 거짓이다.
 * @warning 이것이 거짓인 응답을 긍정 답으로 담으면, 질문과 무관한 기록만 담아 보낸
 *          상대가 캐시를 차지한다.
 */
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

/** @brief 별칭을 다 따라간 끝의 이름. */
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

/**
 * @brief 이 이름의 다음 별칭.
 * @warning 같은 이름에 서로 다른 별칭이 오거나 별칭과 다른 기록이 함께 오면 오류다.
 *          그런 응답을 받아들이면 어느 쪽을 따르느냐에 따라 답이 갈린다.
 */
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

/**
 * @brief 이 부정 응답을 덮는 권한 기록의 최소 수명.
 * @warning 질문한 이름을 덮는 것만 본다. 무관한 권한 기록을 받아들이면 남이 이 서버의 캐시에
 *          없다는 답을 심을 수 있다.
 */
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

/** @brief 이 응답의 부정 수명 근거. */
pub(crate) fn neg_soa_minimum(request: &Message, msg: &Message) -> Option<u32> {
    relevant_negative_soa_minimum(request, &msg.answers, &msg.authorities)
}

/**
 * @brief 남의 결과를 나눠 받을 때 이 요청에 맞게 고친다.
 * @warning 질의 번호와 질문을 되비추지 않으면 클라이언트가 자기 질의의 답으로 알아보지
 *          못한다.
 */
pub(crate) fn retarget_response(mut response: Message, request: &Message) -> Message {
    response.header.id = request.header.id;
    response.header.opcode = request.header.opcode;
    response.header.recursion_desired = request.header.recursion_desired;
    response.header.checking_disabled = request.header.checking_disabled;
    response.questions = request.questions.clone();
    response
}

/** @brief 담아 둔 내용으로 이 요청에 대한 응답을 만든다. */
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
