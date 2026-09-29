/*!
 * @brief 해석 체인을 이루는 계층들.
 *
 * @details 각 계층은 안쪽 리졸버를 하나 잡고, 자기 차례에 답할 수 있으면 답하고 아니면
 *          안으로 넘긴다. 쌓는 순서가 곧 우선순위다.
 * @warning 순서를 바꾸면 동작이 바뀐다. 순서는 테스트로 고정돼 있다.
 * @note 응답을 요청·클라이언트·시각에 따라 달라지게 하는 계층은 UDP 고속 경로 조건에
 *       스스로를 넣어야 한다. 넣지 않으면 그 계층이 없는 것처럼 캐시된 답이 나간다.
 */

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use onetdns_core::{LruMap, MutexExt};
use onetdns_proto::{
    ede_code, DnsClass, Edns, Message, Name, Question, RData, Record, RecordType, ResponseCode,
};

use crate::native::{ResolveFailure, ResolveOutcome, Resolver};

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

/**
 * @brief 이 서버가 권한을 가진 영역을 먼저 답하는 계층.
 * @details 여기서 답이 나오면 재귀로 내려가지 않는다.
 */
pub struct AuthorityLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 서빙할 권한 영역들. 한꺼번에 교체한다. */
    store: Arc<onetdns_core::ArcSwap<onetdns_authority::ZoneStore>>,

    /** @brief 응답에 재귀 가능 표시를 담을지. */
    recursion_offered: bool,
}

impl AuthorityLayer {
    /** @brief 영역 저장소를 잡은 계층을 만든다. */
    pub fn new(
        inner: Arc<dyn Resolver>,
        store: Arc<onetdns_core::ArcSwap<onetdns_authority::ZoneStore>>,
    ) -> Self {
        AuthorityLayer {
            inner,
            store,
            recursion_offered: true,
        }
    }

    /** @brief 응답에 재귀 가능 표시를 담을지. */
    pub fn with_recursion_offered(mut self, offered: bool) -> Self {
        self.recursion_offered = offered;
        self
    }
}

impl Resolver for AuthorityLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 이 서버의 영역이면 답하고, 아니면 안으로 넘긴다. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        let Some(q) = req.questions.first() else {
            return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
        };
        let store = self.store.load();
        match store.query(&q.name, q.qtype) {
            Some(resp) => {
                let mut m = authority_message(req, resp);
                m.header.recursion_available = self.recursion_offered;

                let dnssec_ok = req
                    .opt()
                    .and_then(Edns::from_record)
                    .map(|e| e.dnssec_ok)
                    .unwrap_or(false);
                if dnssec_ok {
                    if let Some(zone) = store.zone_for(&q.name) {
                        attach_dnssec(&mut m, zone, &q.name);
                    }
                }
                ResolveOutcome::Response(m)
            }
            None => self.inner.resolve_outcome(req),
        }
    }
}

/**
 * @brief 응답에 서명과 부재 증명을 붙인다.
 * @details 클라이언트가 요구했을 때만 붙인다. 있는 답에는 그 서명을, 없는 답에는 없다는
 *          증명을 붙여야 검증하는 쪽이 이 서버의 답을 믿을 수 있다.
 */
fn attach_dnssec(m: &mut Message, zone: &onetdns_authority::Zone, qname: &Name) {
    let rrsig_t = RecordType(46);
    let nsec_t = RecordType(47);
    // 서명을 붙인 뒤에는 RRSIG가 별칭과 같은 owner의 다른 타입처럼 보여 terminal 추적을
    // 방해한다. 원래 answer만 있을 때 최종 이름과 요청 RRset 존재 여부를 확정한다.
    let terminal = crate::cache::terminal_answer_name(m, &m.answers);
    let has_requested_answer = crate::cache::has_requested_answer(m, &m.answers);

    let sigs_for = |owner: &Name, covered: u16| -> Vec<Record> {
        zone.query(owner, rrsig_t)
            .answers
            .into_iter()
            .filter(|r| {
                r.name.eq_ignore_case(owner)
                    && onetdns_dnssec::Rrsig::from_record(r)
                        .is_some_and(|s| s.type_covered == covered)
            })
            .collect()
    };

    let pairs = unique_rrsets(&m.answers, &[rrsig_t]);

    let mut wildcard_expanded = false;
    for (owner, t) in pairs {
        let sigs = sigs_for(&owner, t);
        for s in &sigs {
            if onetdns_dnssec::Rrsig::from_record(s)
                .is_some_and(|sig| (sig.labels as usize) < owner.num_labels())
            {
                wildcard_expanded = true;
            }
        }
        m.answers.extend(sigs);
    }

    if wildcard_expanded {
        let nsec3_t = RecordType(50);
        if zone.has_denial_records(nsec3_t) {
            for n in indexed_nsec3_proof(zone, qname, true) {
                let sigs = sigs_for(&n.name, nsec3_t.0);
                m.authorities.push(n);
                m.authorities.extend(sigs);
            }
        } else {
            for n in indexed_nsec_proof(zone, qname, true) {
                let sigs = sigs_for(&n.name, nsec_t.0);
                m.authorities.push(n);
                m.authorities.extend(sigs);
            }
        }
    }

    let auth_pairs = unique_rrsets(&m.authorities, &[rrsig_t, nsec_t]);
    for (owner, t) in auth_pairs {
        m.authorities.extend(sigs_for(&owner, t));
    }

    let additional_pairs = unique_rrsets(&m.additionals, &[rrsig_t, RecordType::OPT]);
    for (owner, rtype) in additional_pairs {
        m.additionals.extend(sigs_for(&owner, rtype));
    }

    let nxdomain = m.header.authoritative
        && m.header.rcode == ResponseCode::NXDomain.0
        && !has_requested_answer;
    let nodata = m.header.authoritative
        && m.header.rcode == ResponseCode::NoError.0
        && !has_requested_answer;
    let insecure_delegation = (!m.header.authoritative
        && m.header.rcode == ResponseCode::NoError.0
        && m.answers.is_empty())
    .then(|| {
        m.authorities
            .iter()
            .filter(|record| record.rtype == RecordType::NS)
            .max_by_key(|record| record.name.num_labels())
            .map(|record| record.name.clone())
    })
    .flatten()
    .filter(|delegation| {
        !m.authorities
            .iter()
            .any(|record| record.rtype == RecordType::DS && record.name.eq_ignore_case(delegation))
    });
    let denial_target = if nxdomain {
        terminal.as_ref().map(|target| (target, true))
    } else if nodata {
        terminal.as_ref().map(|target| (target, false))
    } else {
        insecure_delegation.as_ref().map(|name| (name, false))
    };
    if let Some((target, target_is_nxdomain)) = denial_target {
        let nsec3_t = RecordType(50);
        if zone.has_denial_records(nsec3_t) {
            for n in indexed_nsec3_proof(zone, target, target_is_nxdomain) {
                let sigs = sigs_for(&n.name, nsec3_t.0);
                m.authorities.push(n);
                m.authorities.extend(sigs);
            }
        } else {
            for n in indexed_nsec_proof(zone, target, target_is_nxdomain) {
                let sigs = sigs_for(&n.name, nsec_t.0);
                m.authorities.push(n);
                m.authorities.extend(sigs);
            }
        }
    }
}

/** @brief 증명 기록을 겹치지 않게 넣는다. */
fn push_unique_proof(out: &mut Vec<Record>, record: &Record) {
    if !out.iter().any(|existing| {
        existing.rtype == record.rtype && existing.name.eq_ignore_case(&record.name)
    }) {
        out.push(record.clone());
    }
}

/** @brief 이 이름이 없다는 증명 기록을 찾는다. */
fn indexed_nsec_proof(zone: &onetdns_authority::Zone, qname: &Name, nxdomain: bool) -> Vec<Record> {
    let rtype = RecordType::NSEC;
    if !nxdomain {
        if let Some(record) = zone.exact_denial_record(rtype, qname) {
            return vec![record.clone()];
        }
    }

    let closest_encloser = (0..qname.num_labels()).rev().find_map(|labels| {
        let candidate = qname.suffix(labels);
        zone.exact_denial_record(rtype, &candidate)
            .map(|_| candidate)
    });
    let mut proof = Vec::new();
    if let Some(closest_encloser) = closest_encloser {
        if let Some(record) = zone.exact_denial_record(rtype, &closest_encloser) {
            push_unique_proof(&mut proof, record);
        }
        let next_closer = qname.suffix(closest_encloser.num_labels() + 1);
        if let Some(record) = zone.preceding_denial_record(rtype, &next_closer) {
            if onetdns_dnssec::Nsec::from_record(record).is_some_and(|nsec| {
                onetdns_dnssec::nsec_covers(&record.name, &nsec.next, &next_closer)
            }) {
                push_unique_proof(&mut proof, record);
            }
        }
        let mut labels = vec![b"*".to_vec()];
        labels.extend(closest_encloser.labels().map(<[u8]>::to_vec));
        if let Ok(wildcard) = Name::from_labels(labels) {
            let record = if nxdomain {
                zone.preceding_denial_record(rtype, &wildcard)
                    .filter(|record| {
                        onetdns_dnssec::Nsec::from_record(record).is_some_and(|nsec| {
                            onetdns_dnssec::nsec_covers(&record.name, &nsec.next, &wildcard)
                        })
                    })
            } else {
                zone.exact_denial_record(rtype, &wildcard)
            };
            if let Some(record) = record {
                push_unique_proof(&mut proof, record);
            }
        }
    }
    proof
}

/** @brief 이름을 감춘 형태의 부재 증명 기록을 찾는다. */
fn indexed_nsec3_proof(
    zone: &onetdns_authority::Zone,
    qname: &Name,
    nxdomain: bool,
) -> Vec<Record> {
    let rtype = RecordType::NSEC3;
    let Some(first_record) = zone.first_denial_record(rtype) else {
        return Vec::new();
    };
    let Some(first_nsec3) = onetdns_dnssec::Nsec3::from_record(first_record) else {
        return Vec::new();
    };
    if first_record.name.is_root()
        || first_nsec3.hash_alg != 1
        || first_nsec3.iterations != 0
        || first_nsec3.flags & !1 != 0
    {
        return Vec::new();
    }
    let apex = first_record.name.suffix(first_record.name.num_labels() - 1);
    let salt = first_nsec3.salt;
    let iterations = first_nsec3.iterations;
    let hashed_owner = |name: &Name| -> Option<(Name, Vec<u8>)> {
        let hash = onetdns_dnssec::nsec3_hash(name, &salt, iterations);
        let mut labels = vec![onetdns_dnssec::base32hex_encode(&hash).into_bytes()];
        labels.extend(apex.labels().map(<[u8]>::to_vec));
        Some((Name::from_labels(labels).ok()?, hash))
    };
    let exact = |name: &Name| -> Option<&Record> {
        let (owner, _) = hashed_owner(name)?;
        zone.exact_denial_record(rtype, &owner)
    };
    let covering = |name: &Name| -> Option<&Record> {
        let (owner, hash) = hashed_owner(name)?;
        let record = zone.preceding_denial_record(rtype, &owner)?;
        let owner_hash = record
            .name
            .labels()
            .first()
            .and_then(onetdns_dnssec::base32hex_decode_pub)?;
        let nsec3 = onetdns_dnssec::Nsec3::from_record(record)?;
        onetdns_dnssec::hash_covers_pub(&owner_hash, &nsec3.next_hashed, &hash).then_some(record)
    };

    if !nxdomain {
        if let Some(record) = exact(qname) {
            return vec![record.clone()];
        }
    }

    let mut closest_encloser = None;
    for labels in (0..=qname.num_labels()).rev() {
        let candidate = qname.suffix(labels);
        if exact(&candidate).is_some() {
            closest_encloser = Some(candidate);
            break;
        }
    }

    let mut proof = Vec::new();
    if let Some(closest_encloser) = closest_encloser {
        if let Some(record) = exact(&closest_encloser) {
            push_unique_proof(&mut proof, record);
        }
        if qname.num_labels() > closest_encloser.num_labels() {
            let next_closer = qname.suffix(closest_encloser.num_labels() + 1);
            if let Some(record) = covering(&next_closer) {
                push_unique_proof(&mut proof, record);
            }
        }
        let mut labels = vec![b"*".to_vec()];
        labels.extend(closest_encloser.labels().map(<[u8]>::to_vec));
        if let Ok(wildcard) = Name::from_labels(labels) {
            let record = if nxdomain {
                covering(&wildcard)
            } else {
                exact(&wildcard)
            };
            if let Some(record) = record {
                push_unique_proof(&mut proof, record);
            }
        }
    }
    proof
}

/** @brief 서명해야 할 RRset 목록. 같은 것은 한 번만. */
fn unique_rrsets(records: &[Record], excluded: &[RecordType]) -> Vec<(Name, u16)> {
    let mut seen = std::collections::HashSet::with_capacity(records.len());
    let mut pairs = Vec::new();
    for record in records {
        if excluded.contains(&record.rtype) {
            continue;
        }
        let key = (record.name.canonical_key(), record.rtype.0);
        if seen.insert(key) {
            pairs.push((record.name.clone(), record.rtype.0));
        }
    }
    pairs
}

/** @brief 영역 조회 결과로 응답을 만든다. */
fn authority_message(req: &Message, resp: onetdns_authority::Response) -> Message {
    let mut m = Message::default();
    m.header.id = req.header.id;
    m.header.response = true;
    m.header.opcode = req.header.opcode;
    m.header.recursion_desired = req.header.recursion_desired;
    m.header.recursion_available = true;
    m.header.authoritative = resp.authoritative;
    m.header.rcode = resp.rcode as u16;
    m.questions = req.questions.clone();
    m.answers = resp.answers;
    m.authorities = resp.authority;
    m.additionals = resp.additional;
    m
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 이 질의를 어디로 보낼지. */
pub enum Route {
    /** @brief 전달로 보낸다. */
    Forward,
    /** @brief 재귀로 보낸다. */
    Recurse,
}

/**
 * @brief 이 응답을 담아 두면 안 되는지.
 * @warning 질문과 어긋나거나 잘렸거나 질문한 것이 답에 없으면 담지 않는다. 담으면 남이
 *          끼워 넣은 엉뚱한 답이 눌러앉는다.
 */
fn response_not_cacheable(req: &Message, resp: &Message) -> bool {
    resp.header.rcode != ResponseCode::NoError.0
        || !resp.header.response
        || resp.header.truncated
        || resp.header.opcode != req.header.opcode
        || req.questions.len() != resp.questions.len()
        || !req
            .questions
            .iter()
            .zip(&resp.questions)
            .all(|(request, response)| {
                request.qtype == response.qtype
                    && request.qclass == response.qclass
                    && request.name.eq_ignore_case(&response.name)
            })
        || !crate::cache::has_requested_answer(req, &resp.answers)
}

/**
 * @brief 주 경로가 닿지 못했을 때 다른 경로로 다시 묻는 계층.
 * @warning 전송이 끊긴 실패만 넘긴다. 설정이 틀렸거나 검증에 실패한 것은 다시 물어도
 *          같고, 넘기면 검증 실패를 우회하는 길이 된다.
 */
pub struct FallbackLayer {
    /** @brief 먼저 물어볼 곳. */
    primary: Arc<dyn Resolver>,
    /** @brief 주 경로가 닿지 못했을 때 물어볼 곳. */
    fallback: Arc<dyn Resolver>,
}

impl FallbackLayer {
    /** @brief 주 경로와 보조 경로로 만든다. */
    pub fn new(primary: Arc<dyn Resolver>, fallback: Arc<dyn Resolver>) -> Self {
        FallbackLayer { primary, fallback }
    }
}

impl Resolver for FallbackLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /**
     * @brief 주 경로가 닿지 못했을 때만 보조 경로로 다시 묻는다.
     * @note 다시 물을 때 요청을 처음 상태로 되돌린다. 주 경로가 채워 넣은 표시를 그대로
     *       전달하면 보조 경로가 그것을 이 서버의 판단으로 오해한다.
     */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        match self.primary.resolve_outcome(req) {
            ResolveOutcome::Response(response) => ResolveOutcome::Response(response),

            failure @ ResolveOutcome::Failure(ResolveFailure::Permanent(_)) => failure,
            ResolveOutcome::Failure(ResolveFailure::TransportExhausted) => {
                let mut fallback_req = req.clone();
                fallback_req.header.response = false;
                fallback_req.header.authoritative = false;
                fallback_req.header.truncated = false;
                fallback_req.header.recursion_desired = true;
                fallback_req.header.recursion_available = false;
                fallback_req.header.authentic_data = false;
                fallback_req.header.rcode = ResponseCode::NoError.0;
                fallback_req.answers.clear();
                fallback_req.authorities.clear();

                fallback_req
                    .additionals
                    .retain(|record| record.rtype == RecordType::OPT);

                match self.fallback.resolve(&fallback_req) {
                    Some(mut response) => {
                        response.header.id = req.header.id;
                        response.header.opcode = req.header.opcode;
                        response.header.recursion_desired = req.header.recursion_desired;
                        response.questions = req.questions.clone();
                        ResolveOutcome::Response(response)
                    }

                    None => ResolveOutcome::Failure(ResolveFailure::TransportExhausted),
                }
            }
        }
    }
}

/** @brief 특정 접미사를 지정한 서버로 보내는 계층. */
pub struct StubLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 접미사와 그 접미사를 보낼 곳. */
    stubs: Vec<(Vec<u8>, Arc<dyn Resolver>)>,
}

impl StubLayer {
    /** @brief 접미사 목록으로 만든다. 이름이 틀리거나 겹치면 실패다. */
    pub fn new(
        inner: Arc<dyn Resolver>,
        stubs: Vec<(String, Arc<dyn Resolver>)>,
    ) -> Result<Self, String> {
        let mut parsed = Vec::with_capacity(stubs.len());
        for (suffix, backend) in stubs {
            let key = configured_name_key(&suffix)
                .ok_or_else(|| format!("스텁 영역 이름이 올바르지 않습니다: {suffix}"))?;
            if parsed.iter().any(|(existing, _)| existing == &key) {
                return Err(format!("스텁 영역 이름이 중복되었습니다: {suffix}"));
            }
            parsed.push((key, backend));
        }
        Ok(StubLayer {
            inner,
            stubs: parsed,
        })
    }

    /** @brief 이 이름에 맞는 서버. 가장 긴 접미사가 이긴다. */
    fn match_stub(&self, name: &Name) -> Option<&Arc<dyn Resolver>> {
        let mut key = [0u8; 255];
        for labels in (0..=name.num_labels()).rev() {
            let key = name.canonical_suffix_key_into(labels, &mut key)?;
            if let Some((_, b)) = self
                .stubs
                .iter()
                .find(|(suffix, _)| suffix.as_slice() == key)
            {
                return Some(b);
            }
        }
        None
    }
}

impl Resolver for StubLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 맞는 접미사가 있으면 그리로, 없으면 안으로. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        let Some(q) = req.questions.first() else {
            return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
        };
        match self.match_stub(&q.name) {
            Some(b) => b.resolve_outcome(req),
            None => self.inner.resolve_outcome(req),
        }
    }
}

/** @brief 접미사에 따라 전달과 재귀를 갈라 보내는 것. */
pub struct SplitResolver {
    /** @brief 전달 경로. */
    forward: Arc<dyn Resolver>,
    /** @brief 재귀 경로. */
    recurse: Arc<dyn Resolver>,
    /** @brief 어느 목록에도 없을 때 갈 곳. */
    default: Route,
    /** @brief 재귀로 보낼 접미사들. */
    recurse_suffixes: HashSet<Vec<u8>>,
    /** @brief 전달로 보낼 접미사들. */
    forward_suffixes: HashSet<Vec<u8>>,
}

impl SplitResolver {
    /** @brief 두 경로와 분기 규칙으로 만든다. */
    pub fn new(
        forward: Arc<dyn Resolver>,
        recurse: Arc<dyn Resolver>,
        default: Route,
        recurse_suffixes: &[String],
        forward_suffixes: &[String],
    ) -> Result<Self, String> {
        let recurse_suffixes = recurse_suffixes
            .iter()
            .map(|suffix| {
                configured_name_key(suffix)
                    .ok_or_else(|| format!("재귀 분할 DNS 이름이 올바르지 않습니다: {suffix}"))
            })
            .collect::<Result<HashSet<_>, _>>()?;
        let forward_suffixes = forward_suffixes
            .iter()
            .map(|suffix| {
                configured_name_key(suffix)
                    .ok_or_else(|| format!("전달 분할 DNS 이름이 올바르지 않습니다: {suffix}"))
            })
            .collect::<Result<HashSet<_>, _>>()?;
        if recurse_suffixes
            .intersection(&forward_suffixes)
            .next()
            .is_some()
        {
            return Err(
                "같은 DNS 이름을 재귀와 전달 분할 경로에 동시에 지정할 수 없습니다".to_string(),
            );
        }
        Ok(SplitResolver {
            forward,
            recurse,
            default,
            recurse_suffixes,
            forward_suffixes,
        })
    }

    /** @brief 이 이름을 어디로 보낼지. */
    fn route_for(&self, name: &Name) -> Route {
        let mut key = [0u8; 255];
        for labels in (0..=name.num_labels()).rev() {
            let Some(key) = name.canonical_suffix_key_into(labels, &mut key) else {
                return self.default;
            };
            if self.recurse_suffixes.contains(key) {
                return Route::Recurse;
            }
            if self.forward_suffixes.contains(key) {
                return Route::Forward;
            }
        }
        self.default
    }
}

impl Resolver for SplitResolver {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        match self.resolve_outcome(req) {
            ResolveOutcome::Response(response) => Some(response),
            ResolveOutcome::Failure(_) => None,
        }
    }

    /** @brief 분기 규칙대로 보낸다. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        let Some(q) = req.questions.first() else {
            return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
        };
        match self.route_for(&q.name) {
            Route::Recurse => self.recurse.resolve_outcome(req),
            Route::Forward => self.forward.resolve_outcome(req),
        }
    }
}

/**
 * @brief 설정에 고정해 둔 이름별 주소.
 * @note 수명을 원자 값으로 잡는다. 설정을 다시 읽었을 때 다음 질의부터 곧바로 반영되게
 *       하려는 것이다.
 */
pub struct LocalAddressTable {
    /** @brief 이름별로 고정해 둔 주소. */
    addresses: HashMap<Vec<u8>, LocalAddresses>,
    /** @brief 답에 담을 수명. 설정을 다시 읽으면 곧바로 반영되도록 따로 둔다. */
    local_ttl: Arc<std::sync::atomic::AtomicU32>,
}

#[derive(Default)]
/** @brief 이름 하나에 걸린 주소들. */
struct LocalAddresses {
    /** @brief 이 이름의 IPv4 주소. */
    a: Option<Ipv4Addr>,
    /** @brief 이 이름의 IPv6 주소. */
    aaaa: Option<Ipv6Addr>,
}

impl LocalAddressTable {
    /** @brief 설정 목록으로 만든다. 이름이 틀리거나 겹치면 실패다. */
    pub fn new(
        local_a: &[(String, Ipv4Addr)],
        local_aaaa: &[(String, Ipv6Addr)],
        local_ttl: Arc<std::sync::atomic::AtomicU32>,
    ) -> Result<Self, String> {
        let mut addresses = HashMap::<Vec<u8>, LocalAddresses>::with_capacity(
            local_a.len().saturating_add(local_aaaa.len()),
        );
        for (name, ip) in local_a {
            let key = configured_name_key(name)
                .ok_or_else(|| format!("로컬 A 레코드 이름이 올바르지 않습니다: {name}"))?;
            if addresses.entry(key).or_default().a.replace(*ip).is_some() {
                return Err(format!("로컬 A 레코드 이름이 중복되었습니다: {name}"));
            }
        }
        for (name, ip) in local_aaaa {
            let key = configured_name_key(name)
                .ok_or_else(|| format!("로컬 AAAA 레코드 이름이 올바르지 않습니다: {name}"))?;
            if addresses
                .entry(key)
                .or_default()
                .aaaa
                .replace(*ip)
                .is_some()
            {
                return Err(format!("로컬 AAAA 레코드 이름이 중복되었습니다: {name}"));
            }
        }
        Ok(Self {
            addresses,
            local_ttl,
        })
    }

    /** @brief 이 이름에 고정해 둔 답. */
    fn local_answer(&self, name: &Name, qtype: RecordType) -> Option<(Vec<Record>, u32)> {
        let mut key = [0u8; 255];
        let key = name.canonical_key_into(&mut key)?;
        let addresses = self.addresses.get(key)?;
        let ttl = self.local_ttl.load(std::sync::atomic::Ordering::Acquire);
        let answers = match qtype {
            RecordType::A => addresses
                .a
                .map(|ip| vec![Record::new(name.clone(), ttl, RData::A(ip))])
                .unwrap_or_default(),
            RecordType::AAAA => addresses
                .aaaa
                .map(|ip| vec![Record::new(name.clone(), ttl, RData::Aaaa(ip))])
                .unwrap_or_default(),
            _ => vec![],
        };
        Some((answers, ttl))
    }
}

/**
 * @brief 고정해 둔 주소를 답하는 계층.
 * @warning 답할 때 그곳에 표시를 남긴다. 남기지 않으면 나중에 바깥 계층의 답을 이
 *          계층의 답으로 오해해 고정 수명 항목으로 승격시킨다.
 */
pub struct LocalAddressLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 고정해 둔 주소표. */
    addresses: Arc<LocalAddressTable>,
    /** @brief 답했음을 표시해 둘 캐시. 승격할 때 남의 답과 구분하려는 것이다. */
    wire_cache: Option<Arc<OnceLock<crate::cache::CacheHandle>>>,
}

impl LocalAddressLayer {
    /** @brief 주소표를 잡은 계층을 만든다. */
    pub fn new(
        inner: Arc<dyn Resolver>,
        addresses: Arc<LocalAddressTable>,
        wire_cache: Option<Arc<OnceLock<crate::cache::CacheHandle>>>,
    ) -> Self {
        Self {
            inner,
            addresses,
            wire_cache,
        }
    }
}

impl Resolver for LocalAddressLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 고정해 둔 이름이면 답하고, 아니면 안으로 넘긴다. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        let Some(q) = req.questions.first() else {
            return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
        };
        if let Some((answers, ttl)) = self.addresses.local_answer(&q.name, q.qtype) {
            if let Some(cache) = self.wire_cache.as_ref().and_then(|slot| slot.get()) {
                cache.ensure_local_wire_candidate(req);
            }
            let mut response = answer_message(req.header.id, q.name.clone(), q.qtype, answers);
            if response.answers.is_empty() {
                response.authorities.push(Record::new(
                    q.name.clone(),
                    ttl,
                    RData::Soa(Box::new(onetdns_proto::Soa {
                        mname: Name::root(),
                        rname: Name::root(),
                        serial: 1,
                        refresh: 3_600,
                        retry: 600,
                        expire: 86_400,
                        minimum: ttl,
                    })),
                ));
            }
            return ResolveOutcome::Response(response);
        }
        self.inner.resolve_outcome(req)
    }
}

/** @brief 인증서 발급 도전에 답하는 계층. */
pub struct AcmeChallengeLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
}

impl AcmeChallengeLayer {
    /** @brief 안쪽 리졸버를 잡은 계층을 만든다. */
    pub fn new(inner: Arc<dyn Resolver>) -> Self {
        AcmeChallengeLayer { inner }
    }
}

impl Resolver for AcmeChallengeLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 도전이 걸린 이름이면 그 값을 답한다. 발급이 끝나면 걸린 것이 없어 그냥 지나간다. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        if let Some(q) = req.questions.first() {
            if q.qtype == RecordType::TXT {
                let name = q.name.to_string();
                if name.to_ascii_lowercase().starts_with("_acme-challenge.") {
                    if let Some(txt) = crate::acme::dns01_txt(&name) {
                        let rec =
                            Record::new(q.name.clone(), 0, RData::Txt(vec![txt.into_bytes()]));
                        return ResolveOutcome::Response(answer_message(
                            req.header.id,
                            q.name.clone(),
                            RecordType::TXT,
                            vec![rec],
                        ));
                    }
                }
            }
        }
        self.inner.resolve_outcome(req)
    }
}

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

#[derive(Clone, Copy, PartialEq, Eq)]
/** @brief 여러 주소 중 무엇을 답할지 고르는 방식. */
enum DynMode {
    /** @brief 무작위로 하나 고른다. */
    Random,
    /** @brief 몫에 비례해 고른다. */
    Weighted,
    /** @brief 돌아가며 고른다. */
    RoundRobin,
    /** @brief 살아 있는 것만 답한다. */
    Failover,
}

/** @brief 상태를 보고 답을 고르는 기록 하나. */
struct DynRec {
    /** @brief 이 기록의 종류. */
    qtype: RecordType,
    /** @brief 고르는 방식. */
    mode: DynMode,
    /** @brief 후보 주소와 그 몫. */
    values: Vec<(IpAddr, u32)>,
    /** @brief 답에 담을 수명. */
    ttl: u32,
    /** @brief 살아 있는지 확인할 포트. 0이면 확인하지 않는다. */
    probe_port: u16,
    /** @brief 돌아가며 고를 때의 지금 위치. */
    rr: std::sync::atomic::AtomicUsize,
    /** @brief 주소별로 마지막에 확인한 결과와 시각. */
    health: Arc<Mutex<HashMap<IpAddr, (bool, Instant)>>>,
    /** @brief 지금 확인 중인 주소들. 같은 주소를 겹쳐 확인하지 않으려는 것이다. */
    probing: Arc<Mutex<HashSet<IpAddr>>>,
}

impl DynRec {
    /**
     * @brief 이번에 답할 주소를 고른다.
     * @details 살아 있는 것만 답하려면 확인해야 한다. 확인은 질의 처리를 붙잡지 않도록
     *          제한된 워커에게 맡기고, 지금 아는 상태로 답한다.
     * @warning 아는 것이 하나도 없으면 첫 주소를 답한다. 아무것도 답하지 않으면 확인이
     *          한 번 실패한 것만으로 그 이름이 전부 죽는다.
     */
    fn select(&self) -> Vec<IpAddr> {
        if self.values.is_empty() {
            return Vec::new();
        }
        match self.mode {
            DynMode::Random => {
                let i = rand_usize() % self.values.len();
                vec![self.values[i].0]
            }
            DynMode::Weighted => {
                let total: u64 = self.values.iter().map(|(_, w)| u64::from(*w)).sum();
                if total == 0 {
                    return vec![self.values[0].0];
                }
                let mut random = [0u8; 8];
                onetdns_core::fill_random(&mut random);
                let mut r = u64::from_le_bytes(random) % total;
                for (ip, w) in &self.values {
                    let weight = u64::from(*w);
                    if r < weight {
                        return vec![*ip];
                    }
                    r -= weight;
                }
                vec![self.values[0].0]
            }
            DynMode::RoundRobin => {
                let i =
                    self.rr.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % self.values.len();
                vec![self.values[i].0]
            }
            DynMode::Failover => {
                let port = self.probe_port;
                if port == 0 {
                    return self.values.iter().map(|(ip, _)| *ip).collect();
                }
                let now = Instant::now();
                let mut known_up = Vec::new();
                let should_probe = {
                    let health = self.health.lock_recover();
                    let mut stale = Vec::new();
                    for (ip, _) in &self.values {
                        match health.get(ip) {
                            Some((up, checked)) => {
                                let age = now.saturating_duration_since(*checked);
                                if *up && age <= Duration::from_secs(10) {
                                    known_up.push(*ip);
                                }
                                if age > Duration::from_secs(5) {
                                    stale.push(*ip);
                                }
                            }
                            None => {
                                stale.push(*ip);
                            }
                        }
                    }
                    stale
                };
                let should_probe = {
                    let mut probing = self.probing.lock_recover();
                    should_probe
                        .into_iter()
                        .filter(|ip| probing.insert(*ip))
                        .collect::<Vec<_>>()
                };
                for ip in should_probe {
                    let health = self.health.clone();
                    let probing = self.probing.clone();
                    if !submit_health_probe(move || {
                        let up = tcp_reachable(ip, port);
                        let previous = health
                            .lock_recover()
                            .insert(ip, (up, Instant::now()))
                            .map(|state| state.0);
                        match (previous, up) {
                            (Some(false), true) => onetdns_core::info!(
                                event = "upstream.health_recovered",
                                address = %ip,
                                port,
                                "업스트림 DNS 서버가 다시 응답합니다"
                            ),
                            (None | Some(true), false) => onetdns_core::warn!(
                                event = "upstream.health_failed",
                                address = %ip,
                                port,
                                "업스트림 DNS 서버의 연결 확인에 실패했습니다"
                            ),
                            _ => {}
                        }
                        probing.lock_recover().remove(&ip);
                    }) {
                        self.probing.lock_recover().remove(&ip);
                        onetdns_core::debug!(
                            event = "upstream.health_probe_queue_full",
                            address = %ip,
                            port,
                            "업스트림 DNS 서버 상태 확인 대기열이 가득 차 이번 확인을 건너뜁니다"
                        );
                    }
                }
                if known_up.is_empty() {
                    vec![self.values[0].0]
                } else {
                    known_up
                }
            }
        }
    }
}

/** @brief 무작위 수 하나. */
fn rand_usize() -> usize {
    let mut b = [0u8; std::mem::size_of::<usize>()];
    onetdns_core::fill_random(&mut b);
    usize::from_le_bytes(b)
}

/** @brief 이 주소의 이 포트에 닿는지. */
fn tcp_reachable(ip: IpAddr, port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::new(ip, port),
        Duration::from_millis(400),
    )
    .is_ok()
}

/** @brief 상태 확인 일 하나. */
type HealthProbeJob = Box<dyn FnOnce() + Send + 'static>;

/** @brief 상태 확인 워커 수. */
const HEALTH_PROBE_WORKERS: usize = 8;
/** @brief 상태 확인 대기열 크기. 상한이 없으면 확인이 밀릴 때 스레드가 끝없이 늘어난다. */
const HEALTH_PROBE_QUEUE: usize = 256;
/** @brief 상태 확인 워커 풀. */
static HEALTH_PROBE_EXECUTOR: OnceLock<mpsc::SyncSender<HealthProbeJob>> = OnceLock::new();
#[cfg(test)]
/** @brief 지금 실행 중인 확인 수. 테스트용. */
static HEALTH_PROBE_ACTIVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
/** @brief 동시에 돈 확인의 최대치. 테스트용. */
static HEALTH_PROBE_PEAK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
/** @brief 동시 확인 수를 세는 것. 테스트용. */
struct HealthProbeActivity;

#[cfg(test)]
impl HealthProbeActivity {
    /** @brief 확인 하나를 세기 시작한다. */
    fn enter() -> Self {
        use std::sync::atomic::Ordering;
        let active = HEALTH_PROBE_ACTIVE.fetch_add(1, Ordering::SeqCst) + 1;
        HEALTH_PROBE_PEAK.fetch_max(active, Ordering::SeqCst);
        Self
    }
}

#[cfg(test)]
impl Drop for HealthProbeActivity {
    /** @brief 확인 하나를 뺀다. */
    fn drop(&mut self) {
        HEALTH_PROBE_ACTIVE.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/** @brief 상태 확인 워커 풀. 처음 쓸 때 시작한다. */
fn health_probe_executor() -> &'static mpsc::SyncSender<HealthProbeJob> {
    HEALTH_PROBE_EXECUTOR.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<HealthProbeJob>(HEALTH_PROBE_QUEUE);
        let rx = Arc::new(Mutex::new(rx));
        for index in 0..HEALTH_PROBE_WORKERS {
            let rx = rx.clone();
            if let Err(error) = std::thread::Builder::new()
                .name(format!("onetdns-health-probe-{index}"))
                .spawn(move || loop {
                    let job = rx.lock_recover().recv();
                    match job {
                        Ok(job) => {
                            #[cfg(test)]
                            let _activity = HealthProbeActivity::enter();
                            job();
                        }
                        Err(_) => break,
                    }
                })
            {
                onetdns_core::warn!(event = "upstream.health_worker_start_failed", %error, index, "업스트림 DNS 서버 상태 확인 스레드를 시작하지 못해 해당 기능을 일부 비활성화합니다");
                break;
            }
        }
        tx
    })
}

/** @brief 확인을 맡긴다. 대기열이 꽉 차면 이번 확인을 건너뛴다. */
fn submit_health_probe(job: impl FnOnce() + Send + 'static) -> bool {
    health_probe_executor().try_send(Box::new(job)).is_ok()
}

/** @brief 상태를 보고 답을 고르는 기록들을 답하는 계층. */
pub struct DynamicRecordLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 이름별로 걸린 기록들. */
    records: HashMap<Vec<u8>, Vec<DynRec>>,
}

impl DynamicRecordLayer {
    /** @brief 설정한 기록들로 만든다. */
    pub fn new(
        inner: Arc<dyn Resolver>,
        cfg: &[onetdns_config::DynamicRecord],
    ) -> Result<Self, String> {
        let mut records: HashMap<Vec<u8>, Vec<DynRec>> = HashMap::new();
        for (index, r) in cfg.iter().enumerate() {
            let qtype = match r.qtype.as_str() {
                "A" => RecordType::A,
                "AAAA" => RecordType::AAAA,
                other => {
                    return Err(format!(
                        "dynamic_records[{index}].qtype에 허용되지 않은 값이 있습니다: '{other}'"
                    ));
                }
            };
            let mode = match r.mode.as_str() {
                "random" => DynMode::Random,
                "weighted" => DynMode::Weighted,
                "round_robin" => DynMode::RoundRobin,
                "failover" => DynMode::Failover,
                other => {
                    return Err(format!(
                        "dynamic_records[{index}].mode에 허용되지 않은 값이 있습니다: '{other}'"
                    ));
                }
            };
            let mut values = Vec::new();
            for (item, v) in r.values.iter().enumerate() {
                let (ip_s, weight) = match v.split_once('|') {
                    Some((a, w)) => (
                        a.trim(),
                        w.trim().parse::<u32>().map_err(|_| {
                            format!(
                                "dynamic_records[{index}].values[{item}]의 weight가 올바르지 않습니다"
                            )
                        })?,
                    ),
                    None => (v.trim(), 1),
                };
                let ip = ip_s.parse::<IpAddr>().map_err(|_| {
                    format!("dynamic_records[{index}].values[{item}]의 IP 주소가 올바르지 않습니다")
                })?;
                let family_ok = (qtype == RecordType::A && ip.is_ipv4())
                    || (qtype == RecordType::AAAA && ip.is_ipv6());
                if !family_ok {
                    return Err(format!(
                        "dynamic_records[{index}].values[{item}]의 IP 주소 계열이 qtype과 다릅니다"
                    ));
                }
                values.push((ip, weight));
            }
            if values.is_empty() {
                return Err(format!(
                    "dynamic_records[{index}].values에 한 개 이상의 IP 주소가 필요합니다"
                ));
            }
            let name_key = configured_name_key(&r.name).ok_or_else(|| {
                format!("dynamic_records[{index}].name의 DNS 이름이 올바르지 않습니다")
            })?;
            let record = DynRec {
                qtype,
                mode,
                values,
                ttl: r.ttl,
                probe_port: r.probe_port,
                rr: std::sync::atomic::AtomicUsize::new(0),
                health: Arc::new(Mutex::new(HashMap::new())),
                probing: Arc::new(Mutex::new(HashSet::new())),
            };
            let records_for_name = records.entry(name_key).or_default();
            if records_for_name
                .iter_mut()
                .any(|existing| existing.qtype == qtype)
            {
                return Err(format!(
                    "dynamic_records[{index}]가 같은 name과 qtype을 중복 정의합니다"
                ));
            }
            records_for_name.push(record);
        }
        Ok(DynamicRecordLayer { inner, records })
    }

    /** @brief 답할 기록이 하나도 없는지. */
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl Resolver for DynamicRecordLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 설정한 이름이면 골라 답하고, 아니면 안으로 넘긴다. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        if let Some(q) = req.questions.first() {
            let mut key = [0u8; 255];
            let rec = q
                .name
                .canonical_key_into(&mut key)
                .and_then(|key| self.records.get(key))
                .and_then(|records| records.iter().find(|record| record.qtype == q.qtype));
            if let Some(rec) = rec {
                let ips = rec.select();
                if !ips.is_empty() {
                    let answers: Vec<Record> = ips
                        .iter()
                        .map(|ip| {
                            let rd = match ip {
                                IpAddr::V4(a) => RData::A(*a),
                                IpAddr::V6(a) => RData::Aaaa(*a),
                            };
                            Record::new(q.name.clone(), rec.ttl, rd)
                        })
                        .collect();
                    return ResolveOutcome::Response(answer_message(
                        req.header.id,
                        q.name.clone(),
                        rec.qtype,
                        answers,
                    ));
                }

                if rec.mode == DynMode::Failover {
                    return ResolveOutcome::Response(answer_message(
                        req.header.id,
                        q.name.clone(),
                        rec.qtype,
                        vec![],
                    ));
                }
            }
        }
        self.inner.resolve_outcome(req)
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

/** @brief domain_needed가 막는 범주. */
pub const LOCAL_ONLY_DOMAIN_NEEDED: u8 = 1;
/** @brief bogus_priv가 막는 범주. */
pub const LOCAL_ONLY_BOGUS_PRIV: u8 = 2;
/** @brief empty_zones가 막는 범주. */
pub const LOCAL_ONLY_EMPTY_ZONES: u8 = 4;

/**
 * @brief 밖으로 내보내면 안 되는 이름의 범주를 담아 두는 곳.
 * @details 세 설정은 실행 중에 바뀔 수 있으므로 계층이 값을 복사해 두면 안 된다. 한 번의
 *          Relaxed 로드로 세 범주를 모두 읽도록 비트로 담는다.
 */
pub struct LocalOnlyNames {
    /** @brief 켜진 범주의 비트합. */
    bits: std::sync::atomic::AtomicU8,
}

impl LocalOnlyNames {
    /** @brief 세 설정에서 비트합을 만든다. */
    pub fn new(domain_needed: bool, bogus_priv: bool, empty_zones: bool) -> Self {
        let value = Self {
            bits: std::sync::atomic::AtomicU8::new(0),
        };
        value.set(domain_needed, bogus_priv, empty_zones);
        value
    }

    /** @brief 켜진 범주를 교체한다. */
    pub fn set(&self, domain_needed: bool, bogus_priv: bool, empty_zones: bool) {
        let mut bits = 0u8;
        if domain_needed {
            bits |= LOCAL_ONLY_DOMAIN_NEEDED;
        }
        if bogus_priv {
            bits |= LOCAL_ONLY_BOGUS_PRIV;
        }
        if empty_zones {
            bits |= LOCAL_ONLY_EMPTY_ZONES;
        }
        self.bits.store(bits, std::sync::atomic::Ordering::Relaxed);
    }

    /** @brief 지금 켜진 범주. */
    fn bits(&self) -> u8 {
        self.bits.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/**
 * @brief 밖에 물어보면 안 되는 이름을 업스트림 질의 직전에 끊는 계층.
 *
 * @details domain_needed, bogus_priv, empty_zones가 막으려는 것은 이 이름들이 업스트림 DNS
 *          서버로 새 나가는 것이다. 로컬 권한 영역, DHCP 임대, 스텁 위임, 로컬 주소가
 *          답할 수 있으면 그 답이 먼저 나가야 하므로 이 계층은 그것들보다 안쪽, 상위
 *          질의 바로 앞에 놓인다.
 * @warning 바깥으로 옮기면 자기 설정으로 만든 home.arpa 영역이나 사설 대역 역방향
 *          영역을 자기가 NXDOMAIN으로 덮는다.
 */
pub struct LocalOnlyLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 막을 범주. */
    names: Arc<LocalOnlyNames>,
    /** @brief 막은 답의 수명. */
    block_ttl: Arc<std::sync::atomic::AtomicU32>,
}

impl LocalOnlyLayer {
    /** @brief 로컬 전용 이름 목록을 가진 계층을 만든다. */
    pub fn new(
        inner: Arc<dyn Resolver>,
        names: Arc<LocalOnlyNames>,
        block_ttl: Arc<std::sync::atomic::AtomicU32>,
    ) -> Self {
        LocalOnlyLayer {
            inner,
            names,
            block_ttl,
        }
    }

    /** @brief 이 이름을 밖에 물어보면 안 되는지. */
    fn blocked(&self, name: &Name, qtype: RecordType) -> bool {
        let bits = self.names.bits();
        if bits == 0 {
            return false;
        }
        (bits & LOCAL_ONLY_DOMAIN_NEEDED != 0 && crate::native::is_single_label(name))
            || (bits & LOCAL_ONLY_BOGUS_PRIV != 0
                && qtype == RecordType::PTR
                && crate::native::is_private_reverse(name))
            || (bits & LOCAL_ONLY_EMPTY_ZONES != 0 && crate::native::is_empty_zone(name))
    }
}

impl Resolver for LocalOnlyLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 밖에 물어보면 안 되는 이름이면 NXDOMAIN으로 끊고, 아니면 안으로 넘긴다. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        if let Some(q) = req.questions.first() {
            if self.blocked(&q.name, q.qtype) {
                let ttl = self.block_ttl.load(std::sync::atomic::Ordering::Acquire);
                return ResolveOutcome::Response(crate::native::local_only_negative_response(
                    req, &q.name, ttl,
                ));
            }
        }
        self.inner.resolve_outcome(req)
    }
}

/** @brief 이 서버가 나눠 준 주소를 이름으로도 답하는 계층. */
pub struct DhcpDnsLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 임대 기록. */
    pool: Arc<Mutex<crate::dhcp::LeasePool>>,
    /** @brief 임대에 붙일 도메인 접미사. 없으면 이름으로 답하지 않는다. */
    domain: Option<Name>,
    /** @brief 답에 담을 수명 상한. */
    local_ttl: Arc<std::sync::atomic::AtomicU32>,
}

impl DhcpDnsLayer {
    /** @brief 임대 기록을 잡은 계층을 만든다. */
    pub fn new(
        inner: Arc<dyn Resolver>,
        pool: Arc<Mutex<crate::dhcp::LeasePool>>,
        domain: &str,
        local_ttl: Arc<std::sync::atomic::AtomicU32>,
    ) -> Self {
        DhcpDnsLayer {
            inner,
            pool,
            domain: Name::from_str(domain.trim().trim_end_matches('.'))
                .ok()
                .filter(|name| !name.is_root()),
            local_ttl,
        }
    }

    /** @brief 이 임대가 끝날 때까지 남은 수명. 임대보다 길게 답하면 안 된다. */
    fn lease_ttl(&self, expiry_unix: u64) -> Option<u32> {
        let remaining = expiry_unix
            .saturating_sub(crate::unix_now())
            .min(u64::from(u32::MAX)) as u32;
        (remaining > 0).then(|| {
            self.local_ttl
                .load(std::sync::atomic::Ordering::Acquire)
                .min(remaining)
        })
    }

    /** @brief 이 이름에 임대된 주소. */
    fn forward_lookup(&self, name: &Name) -> Option<(Ipv4Addr, u32)> {
        let domain = self.domain.as_ref()?;
        if name.num_labels() != domain.num_labels() + 1 || !name.ends_with_ignore_case(domain) {
            return None;
        }
        let host = name.labels().first()?;
        let pool = self.pool.lock_recover();
        pool.snapshot().into_iter().find_map(|l| {
            l.hostname
                .as_deref()
                .filter(|h| h.as_bytes().eq_ignore_ascii_case(host))
                .and_then(|_| self.lease_ttl(l.expiry_unix).map(|ttl| (l.ip, ttl)))
        })
    }

    /** @brief 이 주소를 잡은 클라이언트의 이름. */
    fn reverse_lookup(&self, name: &Name) -> Option<(Name, u32)> {
        let domain = self.domain.as_ref()?;
        let ip = ptr_to_ipv4(name)?;
        let pool = self.pool.lock_recover();
        let lease = pool
            .snapshot()
            .into_iter()
            .find(|l| l.ip == ip)
            .filter(|lease| lease.hostname.is_some())?;
        let ttl = self.lease_ttl(lease.expiry_unix)?;
        let mut labels = Vec::with_capacity(domain.labels().len() + 1);
        labels.push(lease.hostname?.into_bytes());
        labels.extend(domain.labels().map(<[u8]>::to_vec));
        Some((Name::from_labels(labels).ok()?, ttl))
    }
}

/** @brief 거꾸로 적힌 이름에서 주소를 읽는다. */
fn ptr_to_ipv4(name: &Name) -> Option<Ipv4Addr> {
    let mut labels = name.labels();
    if labels.len() != 6 {
        return None;
    }
    let labels = [
        labels.next()?,
        labels.next()?,
        labels.next()?,
        labels.next()?,
        labels.next()?,
        labels.next()?,
    ];
    let lab = |i: usize| std::str::from_utf8(labels[i]).ok();
    if !lab(4)?.eq_ignore_ascii_case("in-addr") || !lab(5)?.eq_ignore_ascii_case("arpa") {
        return None;
    }
    let oct = |i: usize| -> Option<u8> { lab(i)?.parse().ok() };
    Some(Ipv4Addr::new(oct(3)?, oct(2)?, oct(1)?, oct(0)?))
}

impl Resolver for DhcpDnsLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 임대 기록에 있으면 답하고, 아니면 안으로 넘긴다. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        if let Some(q) = req.questions.first() {
            match q.qtype {
                RecordType::A => {
                    if let Some((ip, ttl)) = self.forward_lookup(&q.name) {
                        return ResolveOutcome::Response(answer_message(
                            req.header.id,
                            q.name.clone(),
                            q.qtype,
                            vec![Record::new(q.name.clone(), ttl, RData::A(ip))],
                        ));
                    }
                }
                RecordType::AAAA if self.forward_lookup(&q.name).is_some() => {
                    return ResolveOutcome::Response(answer_message(
                        req.header.id,
                        q.name.clone(),
                        q.qtype,
                        vec![],
                    ));
                }
                RecordType::PTR => {
                    if let Some((target, ttl)) = self.reverse_lookup(&q.name) {
                        return ResolveOutcome::Response(answer_message(
                            req.header.id,
                            q.name.clone(),
                            q.qtype,
                            vec![Record::new(q.name.clone(), ttl, RData::Ptr(target))],
                        ));
                    }
                }
                _ => {}
            }
        }
        self.inner.resolve_outcome(req)
    }
}

/**
 * @brief 클라이언트 대역 정보를 붙이거나 떼는 계층.
 * @warning 붙이면 업스트림이 클라이언트 위치에 따라 다른 답을 준다. 그래서 이 계층이 켜지면
 *          UDP 고속 경로를 쓸 수 없다.
 */
pub struct EcsLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 붙일 옵션. 없으면 붙어 온 것을 뗀다. */
    option: Option<(u16, Vec<u8>)>,
}

impl EcsLayer {
    /** @brief 지정한 대역을 붙이는 계층. */
    pub fn new(inner: Arc<dyn Resolver>, custom_ip: IpAddr) -> Self {
        let (family, addr, prefix): (u16, Vec<u8>, u8) = match custom_ip {
            IpAddr::V4(v4) => (1, v4.octets().to_vec(), 24),
            IpAddr::V6(v6) => (2, v6.octets().to_vec(), 56),
        };
        let nbytes = (prefix as usize).div_ceil(8);
        let mut data = Vec::new();
        data.extend_from_slice(&family.to_be_bytes());
        data.push(prefix);
        data.push(0);
        data.extend_from_slice(&addr[..nbytes.min(addr.len())]);
        EcsLayer {
            inner,
            option: Some((8, data)),
        }
    }

    /** @brief 붙어 온 대역 정보를 떼는 계층. 이 서버의 클라이언트 위치를 업스트림에 흘리지 않으려는 것이다. */
    pub fn strip(inner: Arc<dyn Resolver>) -> Self {
        EcsLayer {
            inner,
            option: None,
        }
    }
}

/**
 * @brief EDNS 레코드를 다시 짜지 못해 질의를 접었음을 알린다.
 * @details 질의마다 호출되는 경로라 2의 거듭제곱 번째만 남긴다. 이 실패는 클라이언트에게
 *          SERVFAIL로 보이므로 기록이 없으면 원인을 찾을 수 없다.
 */
fn ecs_encode_failed(error: &impl std::fmt::Display) {
    /** @brief 누적 실패 수. */
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::error!(event = "ecs.edns_encode_failed", count = count, %error, "클라이언트 대역 정보를 붙인 EDNS 레코드를 만들지 못해 질의를 실패로 접었습니다");
    }
}

impl Resolver for EcsLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 대역 정보를 붙이거나 떼고 안으로 넘긴다. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        let mut r = req.clone();
        let opt_index = r
            .additionals
            .iter()
            .position(|record| record.rtype == RecordType::OPT);
        let mut edns = opt_index
            .and_then(|index| Edns::from_record(&r.additionals[index]))
            .unwrap_or_default();
        edns.options.retain(|(code, _)| *code != 8);
        if let Some(option) = &self.option {
            edns.options.push(option.clone());
        }
        match (opt_index, self.option.is_some()) {
            (Some(index), _) => match edns.try_to_record() {
                Ok(record) => r.additionals[index] = record,

                Err(error) => {
                    ecs_encode_failed(&error);
                    return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
                }
            },
            (None, true) => match edns.try_to_record() {
                Ok(record) => r.additionals.push(record),
                Err(error) => {
                    ecs_encode_failed(&error);
                    return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
                }
            },
            (None, false) => {}
        }
        self.inner.resolve_outcome(&r)
    }
}

#[derive(Clone)]
/** @brief 담아 둔 응답 하나와 그 신선·유예 기한. */
struct StaleEntry {
    /** @brief 담아 둔 응답. */
    response: Message,
    /** @brief 담은 시각. */
    inserted: Instant,
    /** @brief 이때까지는 그냥 신선한 답으로 내보낸다. */
    fresh_until: Instant,
    /** @brief 이때까지는 업스트림이 죽었을 때만 내보낸다. */
    stale_until: Instant,
    /** @brief 담을 때의 원래 수명. */
    original_ttl: Duration,
}

/** @brief 담아 둘 때 쓰는 키. */
type StaleKey = Vec<u8>;
/** @brief 담아 둔 응답들. */
type StaleStore = Arc<Mutex<LruMap<StaleKey, StaleEntry>>>;
/** @brief 동시에 돌릴 갱신 수. */
const MAX_STALE_REFRESHES: usize = 32;
/** @brief 갱신 일 하나. */
type StaleRefreshJob = Box<dyn FnOnce() + Send + 'static>;
/** @brief 갱신 워커 수. */
const STALE_REFRESH_WORKERS: usize = 8;
/** @brief 갱신 워커 풀. */
static STALE_REFRESH_EXECUTOR: OnceLock<mpsc::SyncSender<StaleRefreshJob>> = OnceLock::new();
/** @brief 실행 중인 갱신 수와 그것이 0이 되기를 기다리는 곳. */
type StaleJobs = Arc<(Mutex<usize>, Condvar)>;

/** @brief 갱신이 끝나면 진행 표시를 지우고 기다리는 쪽을 깨우는 것. */
struct StaleRefreshGuard {
    /** @brief 지금 갱신 중인 이름들. */
    inflight: Arc<Mutex<HashSet<StaleKey>>>,
    /** @brief 이 갱신이 맡은 이름. */
    key: StaleKey,
    /** @brief 실행 중인 갱신 수와 그것이 0이 되기를 기다리는 곳. */
    jobs: StaleJobs,
}

impl Drop for StaleRefreshGuard {
    /** @brief 진행 표시를 지우고 깨운다. 지우지 않으면 그 이름은 다시 갱신되지 않는다. */
    fn drop(&mut self) {
        self.inflight.lock_recover().remove(&self.key);
        let (count, wake) = &*self.jobs;
        let mut count = count.lock_recover();
        *count = count.saturating_sub(1);
        wake.notify_all();
    }
}

/** @brief 갱신 워커 풀. 처음 쓸 때 시작한다. */
fn stale_refresh_executor() -> &'static mpsc::SyncSender<StaleRefreshJob> {
    STALE_REFRESH_EXECUTOR.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<StaleRefreshJob>(MAX_STALE_REFRESHES);
        let rx = Arc::new(Mutex::new(rx));
        for index in 0..STALE_REFRESH_WORKERS {
            let rx = rx.clone();
            if let Err(error) = std::thread::Builder::new()
                .name(format!("onetdns-stale-refresh-{index}"))
                .spawn(move || loop {
                    let job = rx.lock_recover().recv();
                    match job {
                        Ok(job) => job(),
                        Err(_) => break,
                    }
                })
            {
                onetdns_core::warn!(event = "cache.stale_refresh_worker_start_failed", %error, index, "만료 응답 갱신 스레드를 시작하지 못해 해당 기능을 일부 비활성화합니다");
                break;
            }
        }
        tx
    })
}

/** @brief 갱신을 맡긴다. 대기열이 꽉 차면 이번 갱신을 건너뛴다. */
fn submit_stale_refresh(job: impl FnOnce() + Send + 'static) -> bool {
    stale_refresh_executor().try_send(Box::new(job)).is_ok()
}

/**
 * @brief 갱신을 맡기지 못했음을 알린다.
 * @details 계속 실패하면 만료 응답이 갱신되지 않은 채 유예 기간 내내 나간다. 질의마다
 *          호출되는 경로라 2의 거듭제곱 번째만 남긴다.
 */
fn stale_refresh_not_submitted() {
    /** @brief 누적 실패 수. */
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::warn!(event = "cache.stale_refresh_dropped", count = count, "갱신 대기열이 꽉 차 만료 응답을 새로 받아 오지 못했습니다. 유예 기간 동안 낡은 답이 그대로 나갑니다");
    }
}

/** @brief 흐른 만큼 수명을 깎고 다한 것은 뺀다. EDNS 유사 레코드는 수명이 아니므로 건드리지 않는다. */
fn age_fresh_records(records: &mut Vec<Record>, elapsed_secs: u64) {
    records.retain_mut(|record| {
        if record.rtype == RecordType::OPT {
            return true;
        }
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
 * @brief 업스트림이 답하지 못할 때 만료된 답이라도 내보내는 계층.
 * @details 아무 답도 못 주는 것보다 조금 지난 답이 낫다는 판단이다. 유예 기간과 다시
 *          물을 시점은 설정으로 정한다.
 */
pub struct ServeStaleLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 담아 둔 응답들. */
    store: StaleStore,
    /** @brief 만료 뒤에도 내보낼 수 있는 기간. */
    max_stale: Duration,
    /** @brief 담을 때 걸 수명 하한. */
    min_ttl: u32,
    /** @brief 담을 때 걸 수명 상한. */
    max_ttl: u32,
    /** @brief 지난 답을 내보낼 때 담을 수명. */
    reply_ttl: u32,
    /** @brief 다시 물어 성공하면 유예 기한을 처음부터 다시 잡는지. */
    ttl_reset: bool,
    /** @brief 이만큼 지나면 지난 답부터 내보낸다. 없으면 끝까지 기다린다. */
    client_timeout: Option<Duration>,
    /** @brief 만료된 답을 기다림 없이 먼저 내보내고 뒤에서 다시 묻는지. */
    stale_first: bool,
    /** @brief 지금 갱신 중인 이름들. */
    inflight: Arc<Mutex<HashSet<StaleKey>>>,
    /** @brief 이 계층이 사라지고 있다는 표시. */
    stop: Arc<std::sync::atomic::AtomicBool>,
    /** @brief 서버 전체가 끝나고 있다는 표시. */
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    /** @brief 실행 중인 갱신 수와 그것이 0이 되기를 기다리는 곳. */
    jobs: StaleJobs,
}

impl ServeStaleLayer {
    #[allow(clippy::too_many_arguments)]
    /** @brief 유예 기간과 수명 상하한으로 만든다. */
    pub fn new(
        inner: Arc<dyn Resolver>,
        max_stale: Duration,
        cap: usize,
        min_ttl: u32,
        max_ttl: u32,
        reply_ttl: u32,
        ttl_reset: bool,
        client_timeout: Option<Duration>,
        stale_first: bool,
    ) -> Self {
        let cap = cap.max(1);
        ServeStaleLayer {
            inner,
            store: Arc::new(Mutex::new(LruMap::new(cap))),
            max_stale,
            min_ttl,
            max_ttl,
            // RFC 8767은 만료된 레코드의 수명을 0보다 크게 실으라고 정한다. 0으로 내보내면
            // 받은 쪽이 담아 두지 못해 같은 이름을 곧바로 다시 물어, 업스트림이 죽어 있는 동안
            // 질의가 몰린다. 이 기능이 막으려던 상황을 그대로 만든다.
            reply_ttl: reply_ttl.max(1),
            ttl_reset,
            client_timeout: client_timeout.filter(|d| !d.is_zero()),
            stale_first,
            inflight: Arc::new(Mutex::new(HashSet::new())),
            stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            jobs: Arc::new((Mutex::new(0), Condvar::new())),
        }
    }

    /** @brief 종료 신호를 붙인다. 갱신이 종료를 막지 않게 하려는 것이다. */
    pub fn with_shutdown(mut self, shutdown: Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.shutdown = shutdown;
        self
    }

    /**
     * @brief 응답을 담아 둔다.
     * @warning 담을 자격을 확인한다. 질문한 것이 답에 없는 응답을 담으면, 나중에 업스트림이
     *          죽었을 때 그 엉뚱한 답을 내보낸다.
     */
    fn store_answer_shared(
        store: &StaleStore,
        max_stale: Duration,
        min_ttl: u32,
        max_ttl: u32,
        request: &Message,
        key: StaleKey,
        answer: &Message,
    ) {
        if answer.header.rcode != ResponseCode::NoError.0
            || !crate::cache::has_requested_answer(request, &answer.answers)
        {
            return;
        }
        let mut ttl = answer
            .answers
            .iter()
            .filter(|record| record.rtype != RecordType::OPT)
            .map(|record| record.ttl)
            .min()
            .unwrap_or(0)
            .clamp(min_ttl, max_ttl);
        let mut stored = answer.clone();
        for record in &mut stored.answers {
            if record.rtype != RecordType::OPT {
                record.ttl = record.ttl.clamp(min_ttl, max_ttl);
            }
        }
        for record in stored
            .authorities
            .iter_mut()
            .chain(stored.additionals.iter_mut())
        {
            if record.rtype != RecordType::OPT {
                record.ttl = record.ttl.min(max_ttl);
            }
        }
        let Some(dnssec_cap) = crate::cache::cache_dnssec_ttl_cap(
            answer.header.authentic_data,
            &answer.answers,
            &answer.authorities,
            &answer.additionals,
        ) else {
            return;
        };
        ttl = ttl.min(dnssec_cap);
        cap_message_ttls(&mut stored, dnssec_cap);
        if ttl == 0 {
            return;
        }
        let now = Instant::now();
        let fresh_until = now + Duration::from_secs(u64::from(ttl));
        let stale_until = fresh_until + max_stale;
        store.lock_recover().put(
            key,
            StaleEntry {
                response: stored,
                inserted: now,
                fresh_until,
                stale_until,
                original_ttl: Duration::from_secs(u64::from(ttl)),
            },
        );
    }

    /** @brief 응답을 담아 둔다. */
    fn store_answer(&self, request: &Message, key: StaleKey, answer: &Message) {
        Self::store_answer_shared(
            &self.store,
            self.max_stale,
            self.min_ttl,
            self.max_ttl,
            request,
            key,
            answer,
        );
    }

    /** @brief 담아 둔 것을 꺼낸다. 유예 기한까지 지났으면 지운다. */
    fn cached(&self, key: &StaleKey) -> Option<StaleEntry> {
        let now = Instant::now();
        let mut store = self.store.lock_recover();
        let entry = store.get_mut(key)?;
        if entry.stale_until <= now {
            store.pop(key);
            return None;
        }
        Some(entry.clone())
    }

    /** @brief 아직 신선한 답을 흐른 만큼 깎아 낸다. */
    fn build_fresh(&self, request: &Message, entry: &StaleEntry) -> Message {
        let elapsed = Instant::now()
            .saturating_duration_since(entry.inserted)
            .as_secs();
        let mut response = retarget_message(entry.response.clone(), request);
        age_fresh_records(&mut response.answers, elapsed);
        age_fresh_records(&mut response.authorities, elapsed);
        age_fresh_records(&mut response.additionals, elapsed);
        response
    }

    /**
     * @brief 만료된 답을 내보낼 형태로 만든다.
     * @note 설정한 짧은 수명으로 바꿔 단다. 원래 수명 그대로 보내면 클라이언트가 오래
     *       담아 두어 지난 답이 더 오래 산다.
     */
    fn build_stale(&self, request: &Message, entry: &StaleEntry) -> Message {
        let mut response = retarget_message(entry.response.clone(), request);

        response.header.authentic_data = false;
        let now = Instant::now();
        let keep_stale = |records: &mut Vec<Record>| {
            records.retain_mut(|record| {
                if record.rtype == RecordType::OPT {
                    return true;
                }
                let record_ttl = Duration::from_secs(u64::from(record.ttl));
                let record_stale_until = if record_ttl >= entry.original_ttl {
                    entry
                        .stale_until
                        .checked_add(record_ttl - entry.original_ttl)
                } else {
                    entry
                        .stale_until
                        .checked_sub(entry.original_ttl - record_ttl)
                };
                let still_eligible =
                    record_stale_until.is_some_and(|stale_until| stale_until > now);
                if !still_eligible {
                    return false;
                }
                record.ttl = self.reply_ttl;
                true
            });
        };
        keep_stale(&mut response.answers);
        keep_stale(&mut response.authorities);
        keep_stale(&mut response.additionals);
        let mut edns = request
            .opt()
            .and_then(Edns::from_record)
            .unwrap_or_default();
        edns.extended_rcode = 0;
        edns.version = 0;
        edns.options
            .retain(|(code, _)| *code != onetdns_proto::EDE_OPTION);
        edns.push_ede(ede_code::STALE_ANSWER, "stale answer");
        response.additionals.retain(|r| r.rtype != RecordType::OPT);
        response.additionals.push(
            edns.try_to_record()
                .expect("기존 EDNS 옵션을 줄이고 고정 EDE를 추가한 레코드는 인코딩 가능"),
        );
        response
    }

    /** @brief 설정에 따라 유예 기한을 늘린다. */
    fn extend_stale_if_configured(&self, key: &StaleKey) {
        if !self.ttl_reset {
            return;
        }
        if let Some(entry) = self.store.lock_recover().get_mut(key) {
            entry.stale_until = Instant::now() + self.max_stale;
        }
    }

    /** @brief 이 이름의 갱신을 시작한다. 이미 돌고 있으면 시작하지 않는다. */
    fn begin_refresh(&self, key: &StaleKey) -> bool {
        if self.stop.load(std::sync::atomic::Ordering::Relaxed)
            || self.shutdown.load(std::sync::atomic::Ordering::Relaxed)
        {
            return false;
        }
        let mut inflight = self.inflight.lock_recover();
        if inflight.len() >= MAX_STALE_REFRESHES || !inflight.insert(key.clone()) {
            return false;
        }
        let (count, _) = &*self.jobs;
        let mut count = count.lock_recover();
        *count = count.saturating_add(1);
        true
    }

    /** @brief 뒤에서 다시 묻게 맡긴다. */
    fn spawn_refresh(&self, request: Message, key: StaleKey) {
        if !self.begin_refresh(&key) {
            return;
        }
        let inner = self.inner.clone();
        let store = self.store.clone();
        let inflight = self.inflight.clone();
        let jobs = self.jobs.clone();
        let stop = self.stop.clone();
        let shutdown = self.shutdown.clone();
        let max_stale = self.max_stale;
        let min_ttl = self.min_ttl;
        let max_ttl = self.max_ttl;
        let guard = StaleRefreshGuard {
            inflight,
            key: key.clone(),
            jobs,
        };
        let submitted = submit_stale_refresh(move || {
            let _guard = guard;
            if stop.load(std::sync::atomic::Ordering::Relaxed)
                || shutdown.load(std::sync::atomic::Ordering::Relaxed)
            {
                return;
            }
            if let Some(answer) = inner.resolve(&request) {
                if !stop.load(std::sync::atomic::Ordering::Relaxed)
                    && !shutdown.load(std::sync::atomic::Ordering::Relaxed)
                {
                    Self::store_answer_shared(
                        &store,
                        max_stale,
                        min_ttl,
                        max_ttl,
                        &request,
                        key.clone(),
                        &answer,
                    );
                }
            }
        });
        if !submitted {
            stale_refresh_not_submitted();
        }
    }

    /** @brief 데드라인을 걸어 안으로 묻는다. 데드라인을 넘기면 담아 둔 답을 먼저 내보내려는 것이다. */
    fn resolve_with_timeout(
        &self,
        request: &Message,
        key: &StaleKey,
        timeout: Duration,
    ) -> Option<Option<Message>> {
        if !self.begin_refresh(key) {
            return None;
        }
        let (tx, rx) = mpsc::sync_channel(1);
        let inner = self.inner.clone();
        let request_owned = request.clone();
        let store = self.store.clone();
        let inflight = self.inflight.clone();
        let jobs = self.jobs.clone();
        let stop = self.stop.clone();
        let shutdown = self.shutdown.clone();
        let key_owned = key.clone();
        let max_stale = self.max_stale;
        let min_ttl = self.min_ttl;
        let max_ttl = self.max_ttl;
        let guard = StaleRefreshGuard {
            inflight,
            key: key_owned.clone(),
            jobs,
        };
        if !submit_stale_refresh(move || {
            let _guard = guard;
            if stop.load(std::sync::atomic::Ordering::Relaxed)
                || shutdown.load(std::sync::atomic::Ordering::Relaxed)
            {
                return;
            }
            let result = inner.resolve(&request_owned);
            if !stop.load(std::sync::atomic::Ordering::Relaxed)
                && !shutdown.load(std::sync::atomic::Ordering::Relaxed)
            {
                if let Some(answer) = &result {
                    Self::store_answer_shared(
                        &store,
                        max_stale,
                        min_ttl,
                        max_ttl,
                        &request_owned,
                        key_owned.clone(),
                        answer,
                    );
                }
            }
            let _ = tx.send(result);
        }) {
            stale_refresh_not_submitted();
            return Some(None);
        }
        match rx.recv_timeout(timeout) {
            Ok(result) => Some(result),
            Err(mpsc::RecvTimeoutError::Timeout) => Some(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Some(None),
        }
    }
}

impl Drop for ServeStaleLayer {
    /**
     * @brief 실행 중인 갱신이 끝나기를 기다린다.
     * @warning 기다리지 않으면 갱신이 이미 사라진 것을 건드린다.
     */
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let (count, wake) = &*self.jobs;
        let mut count = count.lock_recover();
        while *count != 0 {
            count = wake.wait(count).unwrap_or_else(|error| error.into_inner());
        }
    }
}

impl Resolver for ServeStaleLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, request: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(request))
    }

    /** @brief 신선하면 그대로, 만료됐으면 갱신을 걸고 지난 답을 내보낸다. */
    fn resolve_outcome(&self, request: &Message) -> ResolveOutcome {
        let Some(key) = semantic_request_key(request) else {
            return self.inner.resolve_outcome(request);
        };
        let now = Instant::now();
        let cached = self.cached(&key);

        if let Some(entry) = &cached {
            if entry.fresh_until > now {
                return ResolveOutcome::Response(self.build_fresh(request, entry));
            }
            if self.stale_first && entry.stale_until > now {
                self.spawn_refresh(request.clone(), key.clone());
                return ResolveOutcome::Response(self.build_stale(request, entry));
            }
        }

        if let (Some(entry), Some(timeout)) = (&cached, self.client_timeout) {
            if entry.stale_until > now {
                match self.resolve_with_timeout(request, &key, timeout) {
                    Some(Some(answer)) => return ResolveOutcome::Response(answer),
                    Some(None) | None => {
                        self.extend_stale_if_configured(&key);
                        return ResolveOutcome::Response(self.build_stale(request, entry));
                    }
                }
            }
        }

        match self.inner.resolve_outcome(request) {
            ResolveOutcome::Response(answer) if answer.header.rcode == ResponseCode::ServFail.0 => {
                if let Some(entry) = cached.filter(|entry| entry.stale_until > Instant::now()) {
                    self.extend_stale_if_configured(&key);
                    ResolveOutcome::Response(self.build_stale(request, &entry))
                } else {
                    ResolveOutcome::Response(answer)
                }
            }
            ResolveOutcome::Response(answer) => {
                self.store_answer(request, key, &answer);
                ResolveOutcome::Response(answer)
            }

            failure => match cached.filter(|entry| entry.stale_until > Instant::now()) {
                Some(entry) => {
                    self.extend_stale_if_configured(&key);
                    ResolveOutcome::Response(self.build_stale(request, &entry))
                }
                None => failure,
            },
        }
    }
}

/** @brief 기록 하나를 가리키는 키. */
type RecKey = (Vec<u8>, u16, Vec<u8>);

/** @brief 기록에서 키를 만든다. */
fn rec_key(record: &Record) -> RecKey {
    let mut writer = onetdns_proto::Writer::new();
    record.rdata.encode(&mut writer);
    (record.name.canonical_key(), record.rtype.0, writer.buf)
}

/** @brief 이 영역이 그 이름을 덮는지. */
fn is_zone_ancestor(zone: &Name, qname: &Name) -> bool {
    zone.num_labels() <= qname.num_labels() && qname.suffix(zone.num_labels()).eq_ignore_case(zone)
}

/**
 * @brief 영역 하나에서 모은 부재 증명 기록과 그 인덱스.
 * @details 정렬된 인덱스를 두고 이진 탐색한다. 인덱스가 없으면 증명 하나를 찾는 데 영역
 *          전체를 훑는다.
 */
struct NsecZoneEntry {
    /** @brief 이 영역에서 모은 기록과 담은 시각. */
    records: HashMap<RecKey, (Record, Instant)>,
    /** @brief 이름 순으로 정렬한 증명 인덱스. */
    nsec_index: Vec<RecKey>,
    /** @brief 요약값 순으로 정렬한 감춘 형태 증명 인덱스. */
    nsec3_index: Vec<(Vec<u8>, RecKey)>,
    /** @brief 이름과 종류별로 그것을 덮는 서명들. */
    signatures: HashMap<(Vec<u8>, u16), Vec<RecKey>>,
    /** @brief 이 영역의 권한 기록. 부정 수명의 근거다. */
    soa: Option<RecKey>,
}

impl NsecZoneEntry {
    /** @brief 빈 항목. */
    fn new() -> Self {
        Self {
            records: HashMap::new(),
            nsec_index: Vec::new(),
            nsec3_index: Vec::new(),
            signatures: HashMap::new(),
            soa: None,
        }
    }

    /** @brief 인덱스를 다시 만든다. 기록이 바뀌면 반드시 불러야 한다. */
    fn rebuild_indexes(&mut self) {
        let mut nsec_index = Vec::new();
        let mut nsec3_index = Vec::new();
        let mut signatures: HashMap<(Vec<u8>, u16), Vec<RecKey>> = HashMap::new();
        let mut soa = None;
        for (key, (record, _)) in &self.records {
            match record.rtype {
                RecordType::SOA => soa = Some(key.clone()),
                RecordType::NSEC => nsec_index.push(key.clone()),
                RecordType::NSEC3 => {
                    if let Some(hash) = record
                        .name
                        .labels()
                        .first()
                        .and_then(onetdns_dnssec::base32hex_decode_pub)
                    {
                        nsec3_index.push((hash, key.clone()));
                    }
                }
                RecordType::RRSIG => {
                    if let Some(signature) = onetdns_dnssec::Rrsig::from_record(record) {
                        signatures
                            .entry((record.name.canonical_key(), signature.type_covered))
                            .or_default()
                            .push(key.clone());
                    }
                }
                _ => {}
            }
        }
        nsec_index.sort_unstable_by(|left, right| {
            let left = &self.records.get(left).expect("indexed NSEC").0.name;
            let right = &self.records.get(right).expect("indexed NSEC").0.name;
            onetdns_dnssec::canonical_name_cmp(left, right)
        });
        nsec3_index.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        self.nsec_index = nsec_index;
        self.nsec3_index = nsec3_index;
        self.signatures = signatures;
        self.soa = soa;
    }

    /** @brief 흐른 만큼 수명을 깎은 기록. 다했으면 없다. */
    fn aged_record(&self, key: &RecKey, now: Instant) -> Option<Record> {
        let (record, expiry) = self.records.get(key)?;
        let mut record = record.clone();
        record.ttl = expiry.saturating_duration_since(now).as_secs() as u32;
        Some(record)
    }

    /** @brief 이 이름의 증명 기록. */
    fn nsec_exact(&self, name: &Name) -> Option<&RecKey> {
        self.nsec_index
            .binary_search_by(|key| {
                let owner = &self.records.get(key).expect("indexed NSEC").0.name;
                onetdns_dnssec::canonical_name_cmp(owner, name)
            })
            .ok()
            .map(|index| &self.nsec_index[index])
    }

    /** @brief 이 이름이 그 사이에 없음을 덮는 증명 기록. */
    fn nsec_covering(&self, name: &Name) -> Option<&RecKey> {
        let len = self.nsec_index.len();
        if len == 0 {
            return None;
        }
        let insertion = self
            .nsec_index
            .binary_search_by(|key| {
                let owner = &self.records.get(key).expect("indexed NSEC").0.name;
                onetdns_dnssec::canonical_name_cmp(owner, name)
            })
            .unwrap_or_else(|index| index);
        let predecessor = if insertion == 0 {
            len - 1
        } else {
            insertion - 1
        };
        let key = &self.nsec_index[predecessor];
        let record = &self.records.get(key).expect("indexed NSEC").0;
        let nsec = onetdns_dnssec::Nsec::from_record(record)?;
        onetdns_dnssec::nsec_covers(&record.name, &nsec.next, name).then_some(key)
    }

    /** @brief 이 요약값의 증명 기록. */
    fn nsec3_exact(&self, hash: &[u8]) -> Option<&RecKey> {
        self.nsec3_index
            .binary_search_by(|(owner, _)| owner.as_slice().cmp(hash))
            .ok()
            .map(|index| &self.nsec3_index[index].1)
    }

    /** @brief 이 요약값이 그 사이에 없음을 덮는 증명 기록. */
    fn nsec3_covering(&self, hash: &[u8]) -> Option<&RecKey> {
        let len = self.nsec3_index.len();
        if len == 0 {
            return None;
        }
        let insertion = self
            .nsec3_index
            .binary_search_by(|(owner, _)| owner.as_slice().cmp(hash))
            .unwrap_or_else(|index| index);
        let predecessor = if insertion == 0 {
            len - 1
        } else {
            insertion - 1
        };
        let (owner, key) = &self.nsec3_index[predecessor];
        let record = &self.records.get(key).expect("indexed NSEC3").0;
        let nsec3 = onetdns_dnssec::Nsec3::from_record(record)?;
        onetdns_dnssec::hash_covers_pub(owner, &nsec3.next_hashed, hash).then_some(key)
    }

    /** @brief 이 기록을 덮는 서명들. */
    fn signatures_for(&self, covered: &Record, now: Instant) -> Vec<Record> {
        self.signatures
            .get(&(covered.name.canonical_key(), covered.rtype.0))
            .into_iter()
            .flatten()
            .filter_map(|key| self.aged_record(key, now))
            .collect()
    }

    /** @brief 이 이름이 없음을 보이는 데 쓸 증명과 서명. 서명 없이 내보내면 검증하는 쪽이 거부한다. */
    fn denial_candidates(&self, qname: &Name, now: Instant) -> (Vec<Record>, Vec<Record>) {
        let mut nsec_keys = Vec::with_capacity(5);
        Self::push_key(&mut nsec_keys, self.nsec_exact(qname));
        if let Some((closest, key)) = (0..qname.num_labels()).rev().find_map(|labels| {
            let candidate = qname.suffix(labels);
            self.nsec_exact(&candidate).map(|key| (candidate, key))
        }) {
            Self::push_key(&mut nsec_keys, Some(key));
            let next_closer = qname.suffix(closest.num_labels() + 1);
            Self::push_key(&mut nsec_keys, self.nsec_covering(&next_closer));
            if let Some(wildcard) = wildcard_name(&closest) {
                Self::push_key(&mut nsec_keys, self.nsec_exact(&wildcard));
                Self::push_key(&mut nsec_keys, self.nsec_covering(&wildcard));
            }
        }
        let nsecs = nsec_keys
            .iter()
            .filter_map(|key| self.aged_record(key, now))
            .collect();

        let mut nsec3_keys = Vec::with_capacity(5);
        let parameters = self.nsec3_index.first().and_then(|(_, key)| {
            let record = &self.records.get(key)?.0;
            let nsec3 = onetdns_dnssec::Nsec3::from_record(record)?;
            Some((nsec3.salt, nsec3.iterations))
        });
        if let Some((salt, iterations)) =
            parameters.filter(|(_, iterations)| *iterations <= onetdns_dnssec::MAX_NSEC3_ITERATIONS)
        {
            let mut hash_budget = onetdns_dnssec::Nsec3HashBudget::default();
            let Some(qhash) = hash_budget.hash(qname, &salt, iterations) else {
                return (nsecs, Vec::new());
            };
            Self::push_key(&mut nsec3_keys, self.nsec3_exact(&qhash));
            let mut closest_match = None;
            for labels in (0..qname.num_labels()).rev() {
                let candidate = qname.suffix(labels);
                let Some(hash) = hash_budget.hash(&candidate, &salt, iterations) else {
                    return (nsecs, Vec::new());
                };
                if let Some(key) = self.nsec3_exact(&hash) {
                    closest_match = Some((candidate, key));
                    break;
                }
            }
            if let Some((closest, key)) = closest_match {
                Self::push_key(&mut nsec3_keys, Some(key));
                let next_closer = qname.suffix(closest.num_labels() + 1);
                let Some(next_hash) = hash_budget.hash(&next_closer, &salt, iterations) else {
                    return (nsecs, Vec::new());
                };
                Self::push_key(&mut nsec3_keys, self.nsec3_covering(&next_hash));
                if let Some(wildcard) = wildcard_name(&closest) {
                    let Some(wildcard_hash) = hash_budget.hash(&wildcard, &salt, iterations) else {
                        return (nsecs, Vec::new());
                    };
                    Self::push_key(&mut nsec3_keys, self.nsec3_exact(&wildcard_hash));
                    Self::push_key(&mut nsec3_keys, self.nsec3_covering(&wildcard_hash));
                }
            }
        }
        let nsec3s = nsec3_keys
            .iter()
            .filter_map(|key| self.aged_record(key, now))
            .collect();
        (nsecs, nsec3s)
    }

    /** @brief 키를 겹치지 않게 넣는다. */
    fn push_key(keys: &mut Vec<RecKey>, key: Option<&RecKey>) {
        if let Some(key) = key {
            if !keys.contains(key) {
                keys.push(key.clone());
            }
        }
    }
}

/** @brief 이 이름 바로 아래의 와일드카드 이름. */
fn wildcard_name(encloser: &Name) -> Option<Name> {
    let mut labels = Vec::with_capacity(encloser.labels().len() + 1);
    labels.push(b"*".to_vec());
    labels.extend(encloser.labels().map(<[u8]>::to_vec));
    Name::from_labels(labels).ok()
}

/** @brief 영역 하나를 가리키는 키. */
type NsecZoneKey = (Vec<u8>, u16);

/** @brief 영역별 증명 기록 저장소. */
struct NsecStore {
    /** @brief 영역별 증명 기록. 가득 차면 영역 단위로 밀어낸다. */
    zones: LruMap<NsecZoneKey, NsecZoneEntry>,
    /** @brief 담아 둔 기록 수. 상한을 세기 위해 따로 둔다. */
    records: usize,
}

/**
 * @brief 담아 둔 부재 증명으로 없다는 답을 직접 만드는 계층.
 * @details 한 번 받은 증명이 이름 구간 전체를 덮으므로, 그 구간의 다른 이름도 밖에
 *          묻지 않고 답할 수 있다.
 * @warning 검증된 증명만 담는다. 검증되지 않은 것으로 답을 지어내면 남이 이 서버에게
 *          "없다"고 심어 둔 것을 이 서버가 퍼뜨린다.
 */
pub struct AggressiveNsecLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 담아 둔 증명들. */
    store: Mutex<NsecStore>,

    /** @brief 전체 기록 수 상한. */
    cap: usize,
    /** @brief 영역 하나가 차지할 수 있는 기록 수. */
    per_zone: usize,
    /** @brief 임의로 만든 답에 담을 수명 하한. */
    neg_min_ttl: u32,
    /** @brief 임의로 만든 답에 담을 수명 상한. */
    neg_max_ttl: u32,
}

impl AggressiveNsecLayer {
    /** @brief 용량과 수명 상하한으로 만든다. */
    pub fn new(inner: Arc<dyn Resolver>, cap: usize, neg_min_ttl: u32, neg_max_ttl: u32) -> Self {
        let cap = cap.max(1);
        Self {
            inner,
            store: Mutex::new(NsecStore {
                zones: LruMap::new(cap),
                records: 0,
            }),
            cap,
            per_zone: cap.min(4096),
            neg_min_ttl,
            neg_max_ttl,
        }
    }

    /**
     * @brief 검증된 부재 증명을 담아 둔다.
     * @warning 수명이 0인 기록은 담지 않는다. 담으면 이미 만료된 증명으로 답을 임의로 만든다.
     */
    fn maybe_cache(&self, response: &Message) {
        if !response.header.authentic_data {
            return;
        }
        let rcode = response.header.rcode;
        let negative = rcode == ResponseCode::NXDomain.0
            || (rcode == ResponseCode::NoError.0
                && !crate::cache::has_requested_answer(response, &response.answers));
        if !negative {
            return;
        }
        let Some(signature_ttl) = crate::cache::dnssec_ttl_cap(
            &response.answers,
            &response.authorities,
            &response.additionals,
        ) else {
            return;
        };
        if signature_ttl == 0 {
            return;
        }
        let Some(qclass) = response.questions.first().map(|question| question.qclass) else {
            return;
        };
        let mut soa_records = response
            .authorities
            .iter()
            .filter(|record| record.class == qclass && record.rtype == RecordType::SOA);
        let Some(soa_record) = soa_records.next() else {
            return;
        };
        if soa_records.next().is_some() {
            return;
        }
        let RData::Soa(soa) = &soa_record.rdata else {
            return;
        };
        let negative_ttl = soa_record
            .ttl
            .min(soa.minimum)
            .clamp(self.neg_min_ttl, self.neg_max_ttl)
            .min(signature_ttl);
        if negative_ttl == 0 {
            return;
        }
        let eligible: Vec<Record> = response
            .authorities
            .iter()
            .filter(|record| {
                record.class == qclass
                    && is_zone_ancestor(&soa_record.name, &record.name)
                    && match record.rtype {
                        RecordType::SOA => record.name.eq_ignore_case(&soa_record.name),
                        RecordType::NSEC | RecordType::NSEC3 => true,
                        RecordType::RRSIG => onetdns_dnssec::Rrsig::from_record(record)
                            .is_some_and(|signature| {
                                matches!(
                                    RecordType(signature.type_covered),
                                    RecordType::SOA | RecordType::NSEC | RecordType::NSEC3
                                )
                            }),
                        _ => false,
                    }
            })
            .cloned()
            .map(|mut record| {
                record.ttl = record
                    .ttl
                    .clamp(self.neg_min_ttl, self.neg_max_ttl)
                    .min(negative_ttl);
                record
            })
            .collect();
        let now_secs = now_secs() as u32;
        let signed_data_is_complete = eligible
            .iter()
            .filter(|record| {
                matches!(
                    record.rtype,
                    RecordType::SOA | RecordType::NSEC | RecordType::NSEC3
                )
            })
            .all(|covered| {
                eligible.iter().any(|signature_record| {
                    signature_record.class == covered.class
                        && signature_record.name.eq_ignore_case(&covered.name)
                        && onetdns_dnssec::Rrsig::from_record(signature_record).is_some_and(
                            |signature| {
                                signature.type_covered == covered.rtype.0
                                    && onetdns_dnssec::rrsig_time_valid(&signature, now_secs)
                            },
                        )
                })
            });
        let Some(denied_name) = crate::cache::terminal_answer_name(response, &response.answers)
        else {
            return;
        };
        let nsec: Vec<Record> = eligible
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC)
            .cloned()
            .collect();
        let nsec3: Vec<Record> = eligible
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC3)
            .cloned()
            .collect();
        let nsec3_parameters = nsec3
            .first()
            .and_then(onetdns_dnssec::Nsec3::from_record)
            .map(|record| (record.hash_alg, record.iterations, record.salt));
        let denial_is_replayable = if rcode == ResponseCode::NXDomain.0 {
            onetdns_dnssec::prove_name_nonexistent(&nsec, &denied_name)
                || !nsec3_has_optout(&nsec3)
                    && onetdns_dnssec::prove_name_nonexistent_nsec3(&nsec3, &denied_name)
        } else {
            onetdns_dnssec::prove_nodata(&nsec, &denied_name, response.questions[0].qtype.0)
                || onetdns_dnssec::prove_nodata_nsec3(
                    &nsec3,
                    &denied_name,
                    response.questions[0].qtype.0,
                )
        };
        if eligible.is_empty()
            || eligible.len() > self.per_zone
            || eligible.iter().any(|record| record.ttl == 0)
            || !signed_data_is_complete
            || !denial_is_replayable
        {
            return;
        }
        let zone_name = (soa_record.name.canonical_key(), qclass.0);
        let now = Instant::now();
        let replaced_rrsets: HashSet<(Vec<u8>, u16)> = eligible
            .iter()
            .filter(|record| {
                matches!(
                    record.rtype,
                    RecordType::SOA | RecordType::NSEC | RecordType::NSEC3
                )
            })
            .map(|record| (record.name.canonical_key(), record.rtype.0))
            .collect();
        let mut store = self.store.lock_recover();
        let mut zone = store
            .zones
            .pop(&zone_name)
            .unwrap_or_else(NsecZoneEntry::new);
        store.records = store.records.saturating_sub(zone.records.len());
        zone.records.retain(|_, (_, expiry)| *expiry > now);
        if let Some(parameters) = nsec3_parameters {
            let rollover = zone.records.values().any(|(record, _)| {
                record.rtype == RecordType::NSEC3
                    && onetdns_dnssec::Nsec3::from_record(record).is_some_and(|cached| {
                        (cached.hash_alg, cached.iterations, cached.salt) != parameters
                    })
            });
            if rollover {
                zone.records.retain(|_, (record, _)| {
                    record.rtype != RecordType::NSEC3
                        && onetdns_dnssec::Rrsig::from_record(record)
                            .is_none_or(|signature| signature.type_covered != RecordType::NSEC3.0)
                });
            }
        }
        zone.records.retain(|(owner, rtype, _), (record, _)| {
            let covered_type = if *rtype == RecordType::RRSIG.0 {
                onetdns_dnssec::Rrsig::from_record(record)
                    .map(|signature| signature.type_covered)
                    .unwrap_or(*rtype)
            } else {
                *rtype
            };
            !replaced_rrsets.contains(&(owner.clone(), covered_type))
        });
        for record in eligible {
            let expiry = now + Duration::from_secs(u64::from(record.ttl));
            zone.records.insert(rec_key(&record), (record, expiry));
        }
        if zone.records.len() > self.per_zone {
            return;
        }
        zone.rebuild_indexes();
        while store.records.saturating_add(zone.records.len()) > self.cap {
            let Some((_, evicted)) = store.zones.pop_lru() else {
                return;
            };
            store.records = store.records.saturating_sub(evicted.records.len());
        }
        store.records += zone.records.len();
        store.zones.put(zone_name, zone);
    }

    /** @brief 담아 둔 증명으로 이 질의에 답을 임의로 만든다. 덮는 증명이 없으면 만들지 않는다. */
    fn try_synthesize(&self, request: &Message) -> Option<Message> {
        let question = request.questions.first()?;
        let qname = &question.name;
        let qtype = question.qtype;
        let now = Instant::now();
        let mut store = self.store.lock_recover();
        let (zone_key, removed) = (0..=qname.num_labels()).rev().find_map(|labels| {
            let key = (qname.suffix(labels).canonical_key(), question.qclass.0);
            if let Some(zone) = store.zones.get_mut(&key) {
                let before = zone.records.len();
                zone.records.retain(|_, (_, expiry)| *expiry > now);
                if zone.records.len() != before {
                    zone.rebuild_indexes();
                }
                Some((key, before - zone.records.len()))
            } else {
                None
            }
        })?;
        store.records = store.records.saturating_sub(removed);
        let zone = store.zones.get_mut(&zone_key)?;
        let (nsecs, nsec3s) = zone.denial_candidates(qname, now);
        let soa = zone.aged_record(zone.soa.as_ref()?, now)?;
        let (rcode, denial) = onetdns_dnssec::nsec_name_nonexistent_proof(&nsecs, qname)
            .map(|proof| (ResponseCode::NXDomain.0, proof))
            .or_else(|| {
                onetdns_dnssec::nsec_nodata_proof(&nsecs, qname, qtype.0)
                    .map(|proof| (ResponseCode::NoError.0, proof))
            })
            .or_else(|| {
                onetdns_dnssec::nsec3_nodata_proof(&nsec3s, qname, qtype.0)
                    .map(|proof| (ResponseCode::NoError.0, proof))
            })
            .or_else(|| {
                let (proof, relies_on_opt_out) =
                    onetdns_dnssec::nsec3_name_nonexistent_proof_status(&nsec3s, qname)?;
                (!relies_on_opt_out).then_some((ResponseCode::NXDomain.0, proof))
            })?;
        let mut proof = Vec::with_capacity(1 + denial.len());
        proof.push(soa);
        proof.extend(denial);
        let mut signatures = Vec::with_capacity(proof.len());
        for covered in &proof {
            let mut covered_signatures = zone.signatures_for(covered, now);
            if covered_signatures.is_empty() {
                return None;
            }
            signatures.append(&mut covered_signatures);
        }
        drop(store);
        let dnssec_ok = request
            .opt()
            .and_then(Edns::from_record)
            .is_some_and(|edns| edns.dnssec_ok);
        if dnssec_ok {
            proof.extend(signatures);
        } else {
            proof.truncate(1);
        }
        let mut message = answer_message(request.header.id, qname.clone(), qtype, vec![]);
        message.header.rcode = rcode;
        message.header.authentic_data = true;
        message.authorities = proof;
        Some(retarget_message(message, request))
    }
}

/** @brief 증명이 일부 이름을 비워 두는 방식인지. 그렇다면 없다고 단정할 수 없다. */
fn nsec3_has_optout(records: &[Record]) -> bool {
    records
        .iter()
        .filter_map(onetdns_dnssec::Nsec3::from_record)
        .any(|n| n.flags & 1 != 0)
}

impl Resolver for AggressiveNsecLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 지어낼 수 있으면 짓고, 아니면 물어보고 그 증명을 담는다. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        if req.questions.is_empty() {
            return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
        }
        if let Some(synth) = self.try_synthesize(req) {
            return ResolveOutcome::Response(synth);
        }
        let mut resp = match self.inner.resolve_outcome(&with_dnssec_records(req)) {
            ResolveOutcome::Response(resp) => resp,

            failure => return failure,
        };
        self.maybe_cache(&resp);
        crate::native::strip_dnssec_unless_requested(req, &mut resp);
        ResolveOutcome::Response(resp)
    }
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

/** @brief 수명의 이 비율이 지난 시점. 만료 전에 미리 다시 물으려는 것이다. */
fn refresh_at_pct(now: Instant, ttl: u32, pct: u32) -> Instant {
    let pct = pct.clamp(10, 99) as u64;
    now + Duration::from_secs(((ttl as u64) * pct / 100).max(1))
}

/** @brief 현재 Unix 초. */
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/**
 * @brief 이름별로 질의 수를 제한하는 계층.
 * @details 무작위로 임의로 만든 하위 이름을 퍼붓는 공격은 이름의 윗부분이 같다. 그 윗부분을
 *          키로 세면 막을 수 있다.
 * @warning 캐시가 맞은 것도 센다. 세지 않으면 캐시에 담긴 이름으로는 얼마든지 퍼부을 수 있다.
 */
pub struct NameRateLimitLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 키 하나가 1초에 쓸 수 있는 몫. */
    per_sec: u32,
    /** @brief 이름 뒤에서 이만큼만 잘라 키로 삼는다. */
    labels: usize,
    /** @brief 키별 남은 몫. */
    buckets: Mutex<NameRateBuckets>,
    /** @brief 셀 수 있는 키 수 상한. */
    cap: usize,
}

#[derive(Default)]
/** @brief 키별 남은 몫. */
struct NameRateBuckets {
    /** @brief 지금 세고 있는 1초 구간. */
    window: u64,
    /** @brief 이 구간에서 키별로 쓴 몫. */
    counts: HashMap<Vec<u8>, u32>,
}

impl NameRateLimitLayer {
    /** @brief 초당 허용치와 셀 조각 수로 만든다. */
    pub fn new(inner: Arc<dyn Resolver>, per_sec: u32, labels: usize) -> Self {
        NameRateLimitLayer {
            inner,
            per_sec: per_sec.max(1),
            labels: labels.max(1),
            buckets: Mutex::new(NameRateBuckets::default()),
            cap: 200_000,
        }
    }

    /** @brief 이 이름을 셀 때 쓸 키. 정해진 조각 수만큼 뒤에서 자른다. */
    fn key(&self, name: &Name) -> Vec<u8> {
        let mut key = [0u8; 255];
        name.canonical_suffix_key_into(self.labels, &mut key)
            .unwrap_or_default()
            .to_vec()
    }

    /** @brief 이번 질의를 받아 줄지. */
    fn allow(&self, name: &Name) -> bool {
        let now = now_secs();
        let key = self.key(name);
        let mut b = self.buckets.lock_recover();
        if b.window != now {
            b.window = now;
            b.counts.clear();
        }
        if b.counts.len() >= self.cap && !b.counts.contains_key(&key) {
            return false;
        }
        let count = b.counts.entry(key).or_default();
        *count = count.saturating_add(1);
        *count <= self.per_sec
    }
}

impl Resolver for NameRateLimitLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 몫이 남았으면 넘기고, 없으면 거절한다. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        if let Some(q) = req.questions.first() {
            if !self.allow(&q.name) {
                let mut m = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
                m.header.rcode = ResponseCode::ServFail.0;
                return ResolveOutcome::Response(m);
            }
        }
        self.inner.resolve_outcome(req)
    }
}

#[derive(Clone)]
/** @brief 없다고 확인된 이름 하나와 그 증명. */
struct BelowNxEntry {
    /** @brief 이 판정이 만료되는 시각. */
    expiry: Instant,
    /** @brief 임의로 만든 답에 그대로 담을 증명. */
    proof: Arc<[Record]>,
}

/** @brief 없다고 확인된 이름을 가리키는 키. */
type BelowNxKey = (Vec<u8>, u16);

/**
 * @brief 없는 이름 아래는 전부 없다고 답하는 계층.
 * @details 어떤 이름이 없으면 그 아래 이름도 있을 수 없다. 그래서 한 번 확인한 것으로
 *          그 아래 질의를 밖에 묻지 않고 답한다.
 */
pub struct BelowNxdomainLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 없다고 확인된 이름들. */
    nx: Mutex<LruMap<BelowNxKey, BelowNxEntry>>,
    /** @brief 임의로 만든 답에 담을 수명 하한. */
    neg_min_ttl: u32,
    /** @brief 임의로 만든 답에 담을 수명 상한. */
    neg_max_ttl: u32,
}

/** @brief 함께 담아 둘 증명 기록 수 상한. */
const MAX_BELOW_NX_PROOF_RECORDS: usize = 16;

impl BelowNxdomainLayer {
    /** @brief 용량과 수명 상하한으로 만든다. */
    pub fn new(inner: Arc<dyn Resolver>, cap: usize, neg_min_ttl: u32, neg_max_ttl: u32) -> Self {
        BelowNxdomainLayer {
            inner,
            nx: Mutex::new(LruMap::new(cap.max(1))),
            neg_min_ttl,
            neg_max_ttl,
        }
    }

    /** @brief 담아 둘 때 쓰는 키. */
    fn cache_key(name: &Name, qclass: DnsClass) -> BelowNxKey {
        (name.canonical_key(), qclass.0)
    }

    /** @brief 이 이름을 덮는, 없다고 확인된 윗 이름. */
    fn ancestor_nx(&self, qname: &Name, qclass: DnsClass) -> Option<BelowNxEntry> {
        let now = Instant::now();
        let mut nx = self.nx.lock_recover();
        for labels in (1..qname.num_labels()).rev() {
            let candidate = Self::cache_key(&qname.suffix(labels), qclass);
            match nx.get_mut(&candidate) {
                Some(entry) if entry.expiry > now => return Some(entry.clone()),
                Some(_) => {
                    nx.pop(&candidate);
                }
                None => {}
            }
        }
        None
    }

    /**
     * @brief 임의로 만든 답에 그대로 담을 수 있는 증명을 고른다.
     * @warning 검증하는 클라이언트가 이 서버의 답을 받아들이려면 증명이 그 이름에도 들어맞아야
     *          한다. 들어맞지 않는 증명을 실으면 그 클라이언트는 이 서버의 답을 거부한다.
     */
    fn authenticated_proof(
        response: &Message,
        denied_name: &Name,
        qclass: DnsClass,
    ) -> Option<Vec<Record>> {
        let mut relevant_soa = response.authorities.iter().filter(|record| {
            record.class == qclass
                && record.rtype == RecordType::SOA
                && is_zone_ancestor(&record.name, denied_name)
        });
        let soa = relevant_soa.next()?;
        if relevant_soa.next().is_some() {
            return None;
        }
        let apex = &soa.name;
        let mut proof: Vec<Record> = response
            .authorities
            .iter()
            .filter(|record| {
                record.class == qclass
                    && match record.rtype {
                        RecordType::SOA => record.name.eq_ignore_case(apex),
                        RecordType::NSEC | RecordType::NSEC3 => {
                            is_zone_ancestor(apex, &record.name)
                        }
                        _ => false,
                    }
            })
            .cloned()
            .collect();
        let data_len = proof.len();
        if !(2..=MAX_BELOW_NX_PROOF_RECORDS).contains(&data_len) {
            return None;
        }
        let now = now_secs() as u32;
        let signatures: Vec<Record> = response
            .authorities
            .iter()
            .filter(|record| {
                if record.class != qclass || record.rtype != RecordType::RRSIG {
                    return false;
                }
                let Some(signature) = onetdns_dnssec::Rrsig::from_record(record) else {
                    return false;
                };
                onetdns_dnssec::rrsig_time_valid(&signature, now)
                    && proof[..data_len].iter().any(|covered| {
                        covered.name.eq_ignore_case(&record.name)
                            && covered.rtype.0 == signature.type_covered
                    })
            })
            .cloned()
            .collect();
        proof.extend(signatures);
        if proof.len() > MAX_BELOW_NX_PROOF_RECORDS
            || proof[..data_len].iter().any(|covered| {
                !proof[data_len..].iter().any(|signature_record| {
                    onetdns_dnssec::Rrsig::from_record(signature_record).is_some_and(|signature| {
                        covered.name.eq_ignore_case(&signature_record.name)
                            && covered.rtype.0 == signature.type_covered
                    })
                })
            })
        {
            return None;
        }
        let nsec: Vec<Record> = proof[..data_len]
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC)
            .cloned()
            .collect();
        let nsec3: Vec<Record> = proof[..data_len]
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC3)
            .cloned()
            .collect();
        if !onetdns_dnssec::prove_name_nonexistent(&nsec, denied_name)
            && (nsec3_has_optout(&nsec3)
                || !onetdns_dnssec::prove_name_nonexistent_nsec3(&nsec3, denied_name))
        {
            return None;
        }
        Some(proof)
    }
}

impl Resolver for BelowNxdomainLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 윗 이름이 없다고 확인됐으면 그대로 답한다. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        let Some(q) = req.questions.first() else {
            return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
        };
        if let Some(entry) = self.ancestor_nx(&q.name, q.qclass) {
            let mut m = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
            m.header.rcode = ResponseCode::NXDomain.0;
            m.header.authentic_data = true;
            let ttl = entry
                .expiry
                .saturating_duration_since(Instant::now())
                .as_secs() as u32;
            let dnssec_ok = req
                .opt()
                .and_then(Edns::from_record)
                .is_some_and(|edns| edns.dnssec_ok);
            m.authorities = entry
                .proof
                .iter()
                .filter(|record| dnssec_ok || record.rtype == RecordType::SOA)
                .cloned()
                .map(|mut record| {
                    record.ttl = record.ttl.min(ttl);
                    record
                })
                .collect();
            return ResolveOutcome::Response(retarget_message(m, req));
        }
        let mut resp = match self.inner.resolve_outcome(&with_dnssec_records(req)) {
            ResolveOutcome::Response(resp) => resp,

            failure => return failure,
        };
        self.remember(req, q.qclass, &resp);
        crate::native::strip_dnssec_unless_requested(req, &mut resp);
        ResolveOutcome::Response(resp)
    }
}

impl BelowNxdomainLayer {
    /** @brief 서명으로 확인된 NXDOMAIN이면 그 증명을 담아 둔다. */
    fn remember(&self, req: &Message, qclass: DnsClass, resp: &Message) {
        if resp.header.rcode == ResponseCode::NXDomain.0 && resp.header.authentic_data {
            let signature_ttl =
                crate::cache::dnssec_ttl_cap(&resp.answers, &resp.authorities, &resp.additionals);
            let denied_name = crate::cache::terminal_answer_name(req, &resp.answers);
            if let (Some(signature_ttl), Some(denied_name)) = (signature_ttl, denied_name) {
                let Some(mut proof) = Self::authenticated_proof(resp, &denied_name, qclass) else {
                    return;
                };
                let Some((soa_ttl, soa_minimum)) = proof.iter().find_map(|record| {
                    let RData::Soa(soa) = &record.rdata else {
                        return None;
                    };
                    Some((record.ttl, soa.minimum))
                }) else {
                    return;
                };
                let ttl = soa_ttl
                    .min(soa_minimum)
                    .clamp(self.neg_min_ttl, self.neg_max_ttl)
                    .min(signature_ttl);
                if ttl == 0 {
                    return;
                }
                for record in &mut proof {
                    record.ttl = ttl;
                }
                let now = Instant::now();
                let mut nx = self.nx.lock_recover();
                nx.put(
                    Self::cache_key(&denied_name, qclass),
                    BelowNxEntry {
                        expiry: now + Duration::from_secs(u64::from(ttl)),
                        proof: proof.into(),
                    },
                );
            }
        }
    }
}

/**
 * @brief 여러 대가 나눠 쓰는 외부 캐시 계층.
 * @warning 담고 꺼낼 때 키에 해석 맥락을 넣는다. 넣지 않으면 다른 설정으로 실행 중인 서버가
 *          담은 답을 이 서버가 그대로 쓴다.
 */
pub struct CacheDbLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 외부 캐시 클라이언트. */
    redis: Arc<crate::redis::RedisClient>,
    /** @brief 외부 캐시에 담아 둘 기간. */
    expire_secs: u64,
    /** @brief 담을 때 걸 수명 하한. */
    min_ttl: u32,
    /** @brief 담을 때 걸 수명 상한. */
    max_ttl: u32,
    /** @brief 키 앞에 붙일 이름. 다른 설정의 답과 섞이지 않게 한다. */
    namespace: String,
}

impl CacheDbLayer {
    /** @brief 외부 캐시 클라이언트를 잡은 계층을 만든다. */
    pub fn new(
        inner: Arc<dyn Resolver>,
        redis: Arc<crate::redis::RedisClient>,
        expire_secs: u64,
        min_ttl: u32,
        max_ttl: u32,
        namespace: String,
    ) -> Self {
        CacheDbLayer {
            inner,
            redis,
            expire_secs,
            min_ttl,
            max_ttl,
            namespace,
        }
    }

    /** @brief 이 요청의 외부 캐시 키. */
    fn key(&self, request: &Message) -> Option<Vec<u8>> {
        let mut key = format!("onetdns:v2:{}:", self.namespace).into_bytes();
        key.extend_from_slice(&semantic_request_key(request)?);
        Some(key)
    }

    /** @brief 담을 바이트로. */
    fn encode_value(response: &Message) -> Option<Vec<u8>> {
        let stored_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .ok()?;
        let mut value = stored_at.to_be_bytes().to_vec();
        value.extend_from_slice(&response.try_encode().ok()?);
        Some(value)
    }

    /** @brief 담아 둔 바이트를 응답으로. 시각이 앞날이면 거부한다. 남이 담은 것으로 수명을 늘릴 수 있다. */
    fn decode_value(value: &[u8], max_ttl: u32) -> Option<(Message, u64)> {
        let timestamp: [u8; 8] = value.get(..8)?.try_into().ok()?;
        let stored_at = u64::from_be_bytes(timestamp);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let elapsed = now.checked_sub(stored_at)?;
        let remaining_cap = u64::from(max_ttl).checked_sub(elapsed)?;
        if remaining_cap == 0 {
            return None;
        }
        let mut message = Message::parse(value.get(8..)?).ok()?;
        let elapsed = elapsed.min(u64::from(u32::MAX)) as u32;
        let age_section = |records: &mut Vec<onetdns_proto::Record>| {
            records.retain_mut(|record| {
                if record.rtype == RecordType::OPT {
                    return true;
                }
                record.ttl = record.ttl.saturating_sub(elapsed);
                record.ttl > 0
            });
        };
        age_section(&mut message.answers);
        age_section(&mut message.authorities);
        age_section(&mut message.additionals);
        cap_message_ttls(&mut message, remaining_cap as u32);
        let any_live = message
            .answers
            .iter()
            .chain(message.authorities.iter())
            .chain(message.additionals.iter())
            .any(|record| record.rtype != RecordType::OPT);
        any_live.then_some((message, u64::from(elapsed)))
    }
}

impl Resolver for CacheDbLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 외부 캐시를 보고, 없으면 물어 담는다. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        if req.questions.is_empty() {
            return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
        }
        let Some(key) = self.key(req) else {
            return self.inner.resolve_outcome(req);
        };
        if let Some(bytes) = self.redis.get(&key) {
            if let Some((mut m, _elapsed)) = Self::decode_value(&bytes, self.max_ttl) {
                let ttl_fresh = m
                    .answers
                    .iter()
                    .chain(m.authorities.iter())
                    .chain(m.additionals.iter())
                    .any(|record| record.rtype != RecordType::OPT && record.ttl > 0);
                let dnssec_fresh = crate::cache::cache_dnssec_ttl_cap(
                    m.header.authentic_data,
                    &m.answers,
                    &m.authorities,
                    &m.additionals,
                )
                .is_some();
                if ttl_fresh && dnssec_fresh && !response_not_cacheable(req, &m) {
                    m.header.id = req.header.id;
                    m.header.opcode = req.header.opcode;
                    m.header.recursion_desired = req.header.recursion_desired;
                    m.header.checking_disabled = req.header.checking_disabled;
                    m.questions = req.questions.clone();
                    onetdns_forward::note_response_source("외부 캐시");
                    return ResolveOutcome::Response(m);
                }
            }

            self.redis.del(&key);
        }
        let resp = match self.inner.resolve_outcome(req) {
            ResolveOutcome::Response(resp) => resp,

            failure => return failure,
        };
        if resp.header.rcode == ResponseCode::NoError.0
            && !resp.answers.is_empty()
            && !response_not_cacheable(req, &resp)
        {
            let mut stored = resp.clone();
            for record in &mut stored.answers {
                if record.rtype != RecordType::OPT {
                    record.ttl = record.ttl.clamp(self.min_ttl, self.max_ttl);
                }
            }
            for record in stored
                .authorities
                .iter_mut()
                .chain(stored.additionals.iter_mut())
            {
                if record.rtype != RecordType::OPT {
                    record.ttl = record.ttl.min(self.max_ttl);
                }
            }
            let Some(dnssec_cap) = crate::cache::cache_dnssec_ttl_cap(
                resp.header.authentic_data,
                &resp.answers,
                &resp.authorities,
                &resp.additionals,
            ) else {
                return ResolveOutcome::Response(resp);
            };
            cap_message_ttls(&mut stored, dnssec_cap);
            let mut rr_ttl = stored
                .answers
                .iter()
                .filter(|record| record.rtype != RecordType::OPT)
                .map(|record| u64::from(record.ttl))
                .min()
                .unwrap_or(0);
            rr_ttl = rr_ttl.min(u64::from(dnssec_cap));
            let ttl = if self.expire_secs > 0 {
                self.expire_secs.min(rr_ttl)
            } else {
                rr_ttl
            };
            if ttl > 0 {
                if let Some(value) = Self::encode_value(&stored) {
                    self.redis.setex(&key, ttl, &value);
                }
            }
        }
        ResolveOutcome::Response(resp)
    }
}

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

/** @brief 결과를 있음·없음으로 바꾼다. */
pub(crate) fn outcome_to_option(outcome: ResolveOutcome) -> Option<Message> {
    match outcome {
        ResolveOutcome::Response(response) => Some(response),
        ResolveOutcome::Failure(_) => None,
    }
}

#[derive(Clone)]
/** @brief 미리 다시 물을 이름 하나와 그 시점. */
struct PrefetchEntry {
    /** @brief 이 시각이 지나면 미리 다시 묻는다. */
    refresh_at: Instant,
    /** @brief 이 이름을 물은 횟수. 자주 묻는지 구분한다. */
    hits: u32,
    /** @brief 다시 물을 때 쓸 요청. */
    request: Message,
}

/** @brief 한 번에 미리 물을 이름 수. 한꺼번에 다 물면 그때마다 부하가 튄다. */
const MAX_PREFETCH_REFRESH_BATCH: usize = 64;

/**
 * @brief 자주 묻는 이름을 만료 전에 미리 다시 묻는 계층.
 * @details 만료 직후 처음 묻는 클라이언트가 업스트림 왕복을 기다리지 않게 하려는 것이다.
 * @warning 자주 묻는 것만 대상으로 삼는다. 전부 미리 물으면 이 서버가 업스트림에 부하를 만든다.
 */
pub struct PrefetchLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 미리 물을 이름들. */
    tracked: Arc<Mutex<HashMap<Vec<u8>, PrefetchEntry>>>,
    /** @brief 지켜볼 이름 수 상한. */
    cap: usize,
    /** @brief 수명의 이 비율이 지나면 미리 다시 묻는다. */
    ttl_pct: u32,
    /** @brief 뒤에서 실행 중인 것을 끝내라는 표시. */
    stop: Arc<std::sync::atomic::AtomicBool>,
    /** @brief 미리 묻기를 실행하는 스레드. */
    worker: Option<std::thread::JoinHandle<()>>,
}

/** @brief 미리 물을 때 부를 함수. */
pub type PrefetchRefresher = Arc<dyn Fn(&Message) -> Option<Message> + Send + Sync>;

impl PrefetchLayer {
    /** @brief 대상 판단 기준과 갱신 시점으로 만든다. */
    pub fn with_policy(
        inner: Arc<dyn Resolver>,
        refresh: PrefetchRefresher,
        tick: Duration,
        cap: usize,
        min_hits: u32,
        ttl_pct: u32,
        shutdown: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        let ttl_pct = ttl_pct.clamp(10, 99);
        let tick = tick.max(Duration::from_millis(100));
        let tracked: Arc<Mutex<HashMap<Vec<u8>, PrefetchEntry>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let refresh_bg = refresh;
        let tracked_bg = tracked.clone();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_bg = stop.clone();
        let worker = match std::thread::Builder::new()
            .name("onetdns-prefetch".into())
            .spawn(move || loop {
                std::thread::park_timeout(tick);
                if shutdown.load(std::sync::atomic::Ordering::Relaxed)
                    || stop_bg.load(std::sync::atomic::Ordering::Relaxed)
                {
                    break;
                }
                let now = Instant::now();

                let due: Vec<(Vec<u8>, Message)> = {
                    let mut tracked = tracked_bg.lock_recover();
                    tracked.retain(|_, entry| entry.refresh_at > now || entry.hits >= min_hits);
                    tracked
                        .iter()
                        .filter(|(_, entry)| entry.refresh_at <= now)
                        .take(MAX_PREFETCH_REFRESH_BATCH)
                        .map(|(key, entry)| (key.clone(), entry.request.clone()))
                        .collect()
                };
                for (key, request) in due {
                    if stop_bg.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    match refresh_bg(&request) {
                        Some(answer) if !answer.answers.is_empty() => {
                            let ttl = answer
                                .answers
                                .iter()
                                .map(|record| record.ttl)
                                .min()
                                .unwrap_or(0);
                            let mut tracked = tracked_bg.lock_recover();
                            if ttl == 0 {
                                tracked.remove(&key);
                            } else if let Some(entry) = tracked.get_mut(&key) {
                                entry.refresh_at = refresh_at_pct(Instant::now(), ttl, ttl_pct);
                                entry.hits = 0;
                            }
                        }
                        _ => {
                            tracked_bg.lock_recover().remove(&key);
                        }
                    }
                }
            }) {
            Ok(handle) => Some(handle),
            Err(error) => {
                onetdns_core::warn!(event = "cache.prefetch_worker_start_failed", %error, "만료 전 사전 갱신 스레드를 시작하지 못해 해당 기능을 비활성화합니다");
                None
            }
        };
        PrefetchLayer {
            inner,
            tracked,
            cap: cap.max(1),
            ttl_pct,
            stop,
            worker,
        }
    }
}

impl Drop for PrefetchLayer {
    /** @brief 뒤에서 실행 중인 갱신을 깨워 끝낸다. */
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
    }
}

impl Resolver for PrefetchLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 답을 넘기면서 자주 묻는 이름이면 갱신 대상으로 올린다. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        let resp = match self.inner.resolve_outcome(req) {
            ResolveOutcome::Response(resp) => resp,
            failure => return failure,
        };
        if resp.header.rcode == ResponseCode::NoError.0
            && !resp.answers.is_empty()
            && !req.questions.is_empty()
        {
            let ttl = resp.answers.iter().map(|r| r.ttl).min().unwrap_or(0);
            let Some(key) = semantic_request_key(req) else {
                return ResolveOutcome::Response(resp);
            };
            let mut t = self.tracked.lock_recover();
            if ttl == 0 {
                t.remove(&key);
                return ResolveOutcome::Response(resp);
            }
            let n = t.len();
            match t.get_mut(&key) {
                Some(e) => {
                    e.hits = e.hits.saturating_add(1);
                    e.refresh_at = refresh_at_pct(Instant::now(), ttl, self.ttl_pct);
                }
                None if n < self.cap => {
                    t.insert(
                        key,
                        PrefetchEntry {
                            refresh_at: refresh_at_pct(Instant::now(), ttl, self.ttl_pct),
                            hits: 1,
                            request: {
                                let mut request = req.clone();
                                request.header.id = 0;
                                request
                            },
                        },
                    );
                }
                None => {}
            }
        }
        ResolveOutcome::Response(resp)
    }
}

#[cfg(test)]
/** @brief 계층별 판정, 순서, 그리고 담을 자격과 증명 요구가 실제로 막는지. */
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    /** @brief 이 서버의 영역이 답할 수 있으면 안쪽으로 내려가지 않는지. */
    fn authority_layer_refers_below_root_delegation_without_hitting_backend() {
        let root_text = "$TTL 3600\n. IN SOA ns.root. host.root. 1 3600 900 604800 3600\n. IN NS ns.root.\nns.root. IN A 127.0.1.1\ntest. IN NS ns.test.\nns.test. IN A 127.0.2.1\n";
        let zone = onetdns_authority::parse_zone(root_text, ".").unwrap();
        let mut zs = onetdns_authority::ZoneStore::new();
        zs.add(zone);
        let store = Arc::new(onetdns_core::ArcSwap::new(Arc::new(zs)));
        let backend = Mock::new(9, 2);
        let layer = AuthorityLayer::new(backend.clone() as Arc<dyn Resolver>, store);

        let q = Message::query(7, Name::from_str("a00.z0007.test").unwrap(), RecordType::A);
        let resp = layer.resolve(&q).expect("리퍼럴 응답");
        assert_eq!(
            resp.header.rcode,
            ResponseCode::NoError.0,
            "SERVFAIL이 아님"
        );
        assert!(!resp.header.authoritative);
        assert!(resp.answers.is_empty());
        assert!(resp
            .authorities
            .iter()
            .any(|a| matches!(&a.rdata, RData::Ns(t) if t.eq_ignore_case(&Name::from_str("ns.test").unwrap()))));
        assert_eq!(
            backend.calls.load(Ordering::SeqCst),
            0,
            "위임은 백엔드로 넘기지 않고 권한 리퍼럴로 응답"
        );
    }

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

    /** @brief 정해진 응답을 내는 테스트용 리졸버. */
    struct Mock {
        /** @brief 이 리졸버를 가리키는 표식. 어느 쪽이 답했는지 본다. */
        tag: u8,
        /** @brief 돌려줄 응답 코드. */
        rcode: u16,
        /** @brief 불린 횟수. */
        calls: AtomicU32,
    }
    impl Mock {
        /** @brief 표식과 응답 코드를 정해 만든다. */
        fn new(tag: u8, rcode: u16) -> Arc<Self> {
            Arc::new(Mock {
                tag,
                rcode,
                calls: AtomicU32::new(0),
            })
        }
    }
    impl Resolver for Mock {
        /** @brief 미리 정해 둔 응답을 돌려준다. */
        fn resolve(&self, req: &Message) -> Option<Message> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let q = req.questions.first().unwrap();
            let mut m = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
            m.header.rcode = self.rcode;

            m.answers.push(Record::new(
                q.name.clone(),
                self.tag as u32,
                RData::A(Ipv4Addr::new(self.tag, self.tag, self.tag, self.tag)),
            ));
            Some(m)
        }
    }

    /** @brief 재귀 요구 표시를 그대로 되비추는 테스트용 리졸버. */
    struct RecursionDesiredMock {
        /** @brief 재귀 요구 표시가 실려 왔는지. */
        seen: std::sync::atomic::AtomicBool,
    }

    impl RecursionDesiredMock {
        /** @brief 만든다. */
        fn new() -> Arc<Self> {
            Arc::new(Self {
                seen: std::sync::atomic::AtomicBool::new(false),
            })
        }
    }

    impl Resolver for RecursionDesiredMock {
        /** @brief 미리 정해 둔 응답을 돌려준다. */
        fn resolve(&self, req: &Message) -> Option<Message> {
            self.seen
                .store(req.header.recursion_desired, Ordering::SeqCst);
            let q = req.questions.first()?;
            Some(answer_message(
                req.header.id,
                q.name.clone(),
                q.qtype,
                vec![Record::new(
                    q.name.clone(),
                    60,
                    RData::A(Ipv4Addr::new(2, 2, 2, 2)),
                )],
            ))
        }
    }

    /** @brief 빈 응답을 내는 테스트용 리졸버. */
    struct EmptyMock {
        /** @brief 권한 기록을 담을지. */
        with_soa: bool,
        /** @brief 불린 횟수. */
        calls: AtomicU32,
    }

    impl EmptyMock {
        /** @brief 권한 기록을 담을지 정해 만든다. */
        fn new(with_soa: bool) -> Arc<Self> {
            Arc::new(Self {
                with_soa,
                calls: AtomicU32::new(0),
            })
        }
    }

    impl Resolver for EmptyMock {
        /** @brief 미리 정해 둔 응답을 돌려준다. */
        fn resolve(&self, req: &Message) -> Option<Message> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let q = req.questions.first()?;
            let mut response = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
            if self.with_soa {
                response.authorities.push(Record::new(
                    q.name.clone(),
                    60,
                    RData::soa(onetdns_proto::Soa {
                        mname: Name::from_str("ns1.test").unwrap(),
                        rname: Name::from_str("hostmaster.test").unwrap(),
                        serial: 1,
                        refresh: 3600,
                        retry: 600,
                        expire: 86400,
                        minimum: 60,
                    }),
                ));
            }
            Some(response)
        }
    }

    /** @brief 전송이 끊긴 실패를 내는 테스트용 리졸버. */
    struct TransportFailureMock {
        /** @brief 불린 횟수. */
        calls: AtomicU32,
    }

    impl TransportFailureMock {
        /** @brief 만든다. */
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicU32::new(0),
            })
        }
    }

    impl Resolver for TransportFailureMock {
        /** @brief 언제나 답하지 않는다. */
        fn resolve(&self, _req: &Message) -> Option<Message> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            None
        }

        /** @brief 전송이 끊겼다고 알린다. */
        fn resolve_outcome(&self, _req: &Message) -> ResolveOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ResolveOutcome::Failure(ResolveFailure::TransportExhausted)
        }
    }

    /** @brief 다시 물어도 같은 실패를 내는 테스트용 리졸버. */
    struct PermanentFailureMock {
        /** @brief 불린 횟수. */
        calls: AtomicU32,
    }

    impl PermanentFailureMock {
        /** @brief 만든다. */
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicU32::new(0),
            })
        }
    }

    impl Resolver for PermanentFailureMock {
        /** @brief 언제나 답하지 않는다. */
        fn resolve(&self, _req: &Message) -> Option<Message> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            None
        }

        /** @brief 되돌릴 수 없는 실패라고 알린다. */
        fn resolve_outcome(&self, _req: &Message) -> ResolveOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ResolveOutcome::Failure(ResolveFailure::Permanent(None))
        }
    }

    /** @brief 테스트용 질의. */
    fn query(name: &str, qtype: RecordType) -> Message {
        Message::query(1, Name::from_str(name).unwrap(), qtype)
    }

    /** @brief 테스트용 동적 기록 설정. */
    fn dynrec(mode: &str, values: &[&str]) -> onetdns_config::DynamicRecord {
        onetdns_config::DynamicRecord {
            name: "dyn.test".into(),
            qtype: "A".into(),
            mode: mode.into(),
            values: values.iter().map(|s| s.to_string()).collect(),
            ttl: 30,
            probe_port: 0,
        }
    }

    /** @brief 응답의 첫 주소. */
    fn first_a(m: &Message) -> Ipv4Addr {
        for r in &m.answers {
            if let RData::A(ip) = r.rdata {
                return ip;
            }
        }
        Ipv4Addr::UNSPECIFIED
    }

    #[test]
    /** @brief 무작위 방식이 설정한 값 중에서만 고르는지. */
    fn dynamic_random_picks_configured_value() {
        let mock = Mock::new(9, 0);
        let layer =
            DynamicRecordLayer::new(mock.clone(), &[dynrec("random", &["10.0.0.1", "10.0.0.2"])])
                .unwrap();
        let resp = layer.resolve(&query("dyn.test", RecordType::A)).unwrap();
        let ip = first_a(&resp);
        assert!(
            ip == Ipv4Addr::new(10, 0, 0, 1) || ip == Ipv4Addr::new(10, 0, 0, 2),
            "구성된 값 중 하나"
        );
        assert_eq!(
            mock.calls.load(Ordering::SeqCst),
            0,
            "동적 레코드가 가로채 inner 미호출"
        );
    }

    #[test]
    /** @brief 몫이 0인 값을 고르지 않는지. */
    fn dynamic_weighted_respects_weight_zero() {
        let mock = Mock::new(9, 0);

        let layer =
            DynamicRecordLayer::new(mock, &[dynrec("weighted", &["10.0.0.1|0", "10.0.0.2|10"])])
                .unwrap();
        for _ in 0..20 {
            let resp = layer.resolve(&query("dyn.test", RecordType::A)).unwrap();
            assert_eq!(first_a(&resp), Ipv4Addr::new(10, 0, 0, 2));
        }
    }

    #[test]
    /** @brief 돌아가며 고르는지. */
    fn dynamic_round_robin_rotates() {
        let mock = Mock::new(9, 0);
        let layer =
            DynamicRecordLayer::new(mock, &[dynrec("round_robin", &["10.0.0.1", "10.0.0.2"])])
                .unwrap();
        let a = first_a(&layer.resolve(&query("dyn.test", RecordType::A)).unwrap());
        let b = first_a(&layer.resolve(&query("dyn.test", RecordType::A)).unwrap());
        let c = first_a(&layer.resolve(&query("dyn.test", RecordType::A)).unwrap());
        assert_ne!(a, b, "연속 호출은 회전");
        assert_eq!(a, c, "2개 값 → 한 바퀴 후 복귀");
    }

    #[test]
    /** @brief 상태 확인이 제한된 워커 안에서만 도는지. 안 그러면 스레드가 끝없이 는다. */
    fn dynamic_failover_health_checks_use_bounded_executor() {
        let values = (1..=64)
            .map(|last| format!("192.0.2.{last}"))
            .collect::<Vec<_>>();
        let record = onetdns_config::DynamicRecord {
            name: "dyn.test".into(),
            qtype: "A".into(),
            mode: "failover".into(),
            values,
            ttl: 30,
            probe_port: 9,
        };
        let layer = DynamicRecordLayer::new(Mock::new(9, 0), &[record]).unwrap();
        let started = Instant::now();
        let response = layer.resolve(&query("dyn.test", RecordType::A)).unwrap();
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(first_a(&response), Ipv4Addr::new(192, 0, 2, 1));

        std::thread::sleep(Duration::from_millis(20));
        let peak = HEALTH_PROBE_PEAK.load(std::sync::atomic::Ordering::SeqCst);
        assert!(peak > 0 && peak <= HEALTH_PROBE_WORKERS, "peak={peak}");
    }

    #[test]
    /** @brief 설정하지 않은 이름은 그냥 지나가는지. */
    fn dynamic_passthrough_for_other_names() {
        let mock = Mock::new(7, 0);
        let layer =
            DynamicRecordLayer::new(mock.clone(), &[dynrec("random", &["10.0.0.1"])]).unwrap();
        let resp = layer.resolve(&query("other.test", RecordType::A)).unwrap();
        assert_eq!(first_a(&resp), Ipv4Addr::new(7, 7, 7, 7), "inner로 통과");
        assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    /** @brief 이름의 원래 바이트가 키에서 바뀌지 않는지. 바뀌면 다른 이름이 같은 답을 받는다. */
    fn dynamic_record_key_preserves_raw_name_octets() {
        let mock = Mock::new(7, 0);
        let mut record = dynrec("random", &["10.0.0.1"]);
        record.name = "�".into();
        let layer = DynamicRecordLayer::new(mock.clone(), &[record]).unwrap();

        let configured = Message::query(1, Name::from_str("�").unwrap(), RecordType::A);
        assert_eq!(
            first_a(&layer.resolve(&configured).unwrap()),
            Ipv4Addr::new(10, 0, 0, 1)
        );

        let raw = Message::query(
            2,
            Name::from_labels(vec![vec![0xff]]).unwrap(),
            RecordType::A,
        );
        assert_eq!(
            first_a(&layer.resolve(&raw).unwrap()),
            Ipv4Addr::new(7, 7, 7, 7),
            "invalid UTF-8 wire label must not collide with configured U+FFFD"
        );
        assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    /** @brief 잘못된 설정이 조용히 무시되지 않는지. 무시되면 운영자는 걸린 줄 안다. */
    fn invalid_dynamic_record_cannot_disappear_silently() {
        let mut record = dynrec("random", &["10.0.0.1"]);
        record.name = "bad..name".to_string();
        assert!(DynamicRecordLayer::new(Mock::new(7, 0), &[record]).is_err());
    }

    /** @brief 테스트용 부재 증명 기록. */
    fn nsec_record(owner: &str, next: &str, types: &[u16]) -> Record {
        let mut rdata = Vec::new();
        for label in next.trim_end_matches('.').split('.') {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        let max = types.iter().copied().max().unwrap_or(0);
        let nbytes = (max / 8 + 1) as usize;
        let mut bm = vec![0u8; nbytes];
        for &t in types {
            bm[(t / 8) as usize] |= 0x80 >> (t % 8);
        }
        rdata.push(0);
        rdata.push(nbytes as u8);
        rdata.extend_from_slice(&bm);
        Record::new(
            Name::from_str(owner).unwrap(),
            3600,
            RData::Unknown(47, rdata),
        )
    }

    /** @brief 테스트용 권한 기록. */
    fn soa_record(zone: &str) -> Record {
        Record::new(
            Name::from_str(zone).unwrap(),
            3600,
            RData::soa(onetdns_proto::Soa {
                mname: Name::from_str(&format!("ns.{zone}")).unwrap(),
                rname: Name::from_str(&format!("admin.{zone}")).unwrap(),
                serial: 1,
                refresh: 7200,
                retry: 3600,
                expire: 1_209_600,
                minimum: 3600,
            }),
        )
    }

    #[test]
    /** @brief 큰 영역에서도 증명 조회가 훑기로 떨어지지 않는지. */
    fn indexed_denial_lookup_handles_ten_thousand_node_chain() {
        /** @brief 테스트에 쓸 이름 수. */
        const NODES: usize = 10_000;
        let unsigned = onetdns_authority::parse_zone(
            "$ORIGIN sec.test.\n@ 60 IN SOA ns.sec.test. hostmaster.sec.test. 1 60 60 3600 60\n@ 60 IN NS ns.sec.test.\nns 60 IN A 192.0.2.1\n",
            "sec.test",
        )
        .unwrap();
        let mut records = unsigned.axfr_records();
        records.pop();

        let owners: Vec<String> = std::iter::once("sec.test".to_string())
            .chain((0..NODES).map(|index| format!("n{index:05}.sec.test")))
            .collect();
        for index in 0..owners.len() {
            records.push(nsec_record(
                &owners[index],
                &owners[(index + 1) % owners.len()],
                &[RecordType::NSEC.0],
            ));
        }
        let zone = onetdns_authority::Zone::from_records(records).unwrap();

        let missing = Name::from_str("n05000a.sec.test").unwrap();
        let proof = indexed_nsec_proof(&zone, &missing, true);
        assert!(proof.iter().any(|record| {
            record
                .name
                .eq_ignore_case(&Name::from_str("n05000.sec.test").unwrap())
        }));
        assert!(proof.len() <= missing.num_labels(), "proof={}", proof.len());

        let existing = Name::from_str("n05000.sec.test").unwrap();
        let nodata = indexed_nsec_proof(&zone, &existing, false);
        assert_eq!(nodata.len(), 1);
        assert!(nodata[0].name.eq_ignore_case(&existing));
    }

    /** @brief 남은 기간을 지정한 테스트용 서명. */
    fn rrsig_record_with_lifetime(record: &Record, lifetime: u32) -> Record {
        let now = now_secs() as u32;
        let signature = onetdns_dnssec::Rrsig {
            type_covered: record.rtype.0,
            algorithm: 13,
            labels: record.name.num_labels() as u8,
            original_ttl: record.ttl,
            expiration: now.wrapping_add(lifetime),
            inception: now.wrapping_sub(60),
            key_tag: 1,
            signer: record.name.clone(),
            signature: vec![0; 64],
        };
        Record::new(
            record.name.clone(),
            record.ttl,
            RData::Unknown(RecordType::RRSIG.0, signature.rdata_bytes()),
        )
    }

    /** @brief 테스트용 서명. */
    fn rrsig_record(record: &Record) -> Record {
        rrsig_record_with_lifetime(record, 3600)
    }

    /** @brief 기록마다 서명을 붙인다. */
    fn with_rrsigs(mut records: Vec<Record>) -> Vec<Record> {
        let signatures = records.iter().map(rrsig_record).collect::<Vec<_>>();
        records.extend(signatures);
        records
    }

    /** @brief 이름을 감춘 형태의 테스트용 부재 증명. */
    fn nsec3_nodata_record(name: &str, zone: &str, salt: &[u8]) -> Record {
        let qname = Name::from_str(name).unwrap();
        let hash = onetdns_dnssec::nsec3_hash(&qname, salt, 0);
        let owner = Name::from_str(&format!(
            "{}.{}",
            onetdns_dnssec::base32hex_encode(&hash),
            zone
        ))
        .unwrap();
        let mut rdata = vec![1, 0, 0, 0, salt.len() as u8];
        rdata.extend_from_slice(salt);
        rdata.push(20);
        rdata.extend_from_slice(&[0; 20]);
        rdata.extend_from_slice(&[0, 6, 0x40, 0, 0, 0, 0, 0x02]);
        Record::new(owner, 3600, RData::Unknown(RecordType::NSEC3.0, rdata))
    }

    /** @brief 증명이 담긴 부정 응답을 내는 테스트용 리졸버. */
    struct NsecNx {
        /** @brief 검증됐다고 표시할지. */
        ad: bool,
        /** @brief 불린 횟수. */
        calls: AtomicU32,
    }
    impl Resolver for NsecNx {
        /** @brief 미리 정해 둔 응답을 돌려준다. */
        fn resolve(&self, req: &Message) -> Option<Message> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let q = req.questions.first()?;
            let mut m = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
            m.header.rcode = ResponseCode::NXDomain.0;
            m.header.authentic_data = self.ad;
            m.authorities = with_rrsigs(vec![
                soa_record("example.com"),
                nsec_record("example.com", "a.example.com", &[6, 47]),
                nsec_record("a.example.com", "c.example.com", &[1, 47]),
            ]);
            Some(m)
        }
    }

    #[test]
    /** @brief 담아 둔 증명으로 없다는 답을 만드는지. */
    fn aggressive_nsec_synthesizes_nxdomain() {
        let inner = Arc::new(NsecNx {
            ad: true,
            calls: AtomicU32::new(0),
        });
        let layer = AggressiveNsecLayer::new(inner.clone(), 16, 0, 86_400);

        let r1 = layer
            .resolve(&query("b.example.com", RecordType::A))
            .unwrap();
        assert_eq!(r1.header.rcode, ResponseCode::NXDomain.0);
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);

        let r2 = layer
            .resolve(&query("b2.example.com", RecordType::A))
            .unwrap();
        assert_eq!(r2.header.rcode, ResponseCode::NXDomain.0, "합성 NXDOMAIN");
        assert!(r2.header.authentic_data, "합성도 AD=1");
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            1,
            "두 번째는 inner 미호출(합성)"
        );
        assert_eq!(r2.authorities.len(), 1, "DO=0이면 SOA만 반환");
        assert_eq!(r2.authorities[0].rtype, RecordType::SOA);

        let mut dnssec_query = query("b3.example.com", RecordType::AAAA);
        dnssec_query.additionals.push(
            Edns {
                dnssec_ok: true,
                ..Default::default()
            }
            .try_to_record()
            .unwrap(),
        );
        let r3 = layer.resolve(&dnssec_query).unwrap();
        assert!(r3
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::NSEC));
        assert!(r3
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::RRSIG));
        assert_eq!(r3.questions.len(), 1);
        assert!(r3.questions[0]
            .name
            .eq_ignore_case(&dnssec_query.questions[0].name));
        assert_eq!(r3.questions[0].qtype, dnssec_query.questions[0].qtype);
        assert_eq!(r3.questions[0].qclass, dnssec_query.questions[0].qclass);
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);

        let mut other_class = query("b4.example.com", RecordType::A);
        other_class.questions[0].qclass = DnsClass(3);
        layer.resolve(&other_class).unwrap();
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            2,
            "IN denial proof를 다른 QCLASS에 재사용하면 안 됨"
        );
    }

    #[test]
    /** @brief 검증되지 않은 증명으로는 만들지 않는지. 만들면 남이 심은 것을 이 서버가 퍼뜨린다. */
    fn aggressive_nsec_skips_unvalidated() {
        let inner = Arc::new(NsecNx {
            ad: false,
            calls: AtomicU32::new(0),
        });
        let layer = AggressiveNsecLayer::new(inner.clone(), 16, 0, 86_400);
        layer.resolve(&query("b.example.com", RecordType::A));
        layer.resolve(&query("b2.example.com", RecordType::A));
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            2,
            "AD=0은 캐시 안 함 → 매번 inner"
        );
    }

    #[test]
    /** @brief 권한 기록이 정한 부정 수명을 지키는지. */
    fn aggressive_nsec_respects_soa_negative_ttl() {
        let layer = AggressiveNsecLayer::new(Mock::new(1, 0), 16, 0, 86_400);
        let mut soa = soa_record("example.com");
        let RData::Soa(soa_data) = &mut soa.rdata else {
            panic!("SOA fixture");
        };
        soa_data.minimum = 2;
        let mut response = answer_message(
            1,
            Name::from_str("b.example.com").unwrap(),
            RecordType::A,
            vec![],
        );
        response.header.rcode = ResponseCode::NXDomain.0;
        response.header.authentic_data = true;
        response.authorities = with_rrsigs(vec![
            soa,
            nsec_record("example.com", "a.example.com", &[6, 47]),
            nsec_record("a.example.com", "c.example.com", &[1, 47]),
        ]);
        layer.maybe_cache(&response);

        let synthesized = layer
            .try_synthesize(&query("b2.example.com", RecordType::A))
            .expect("검증된 NSEC 합성");
        assert!(
            synthesized.authorities.iter().all(|record| record.ttl <= 2),
            "부정 증명은 SOA MINIMUM을 넘기면 안 됨: {:?}",
            synthesized.authorities
        );
    }

    #[test]
    /** @brief 설정한 수명 상하한을 지키는지. */
    fn aggressive_nsec_honors_configured_negative_ttl_bounds() {
        let layer = AggressiveNsecLayer::new(Mock::new(1, 0), 16, 5, 5);
        let mut soa = soa_record("example.com");
        let RData::Soa(soa_data) = &mut soa.rdata else {
            panic!("SOA fixture");
        };
        soa_data.minimum = 2;
        let mut response = answer_message(
            1,
            Name::from_str("b.example.com").unwrap(),
            RecordType::A,
            vec![],
        );
        response.header.rcode = ResponseCode::NXDomain.0;
        response.header.authentic_data = true;
        response.authorities = with_rrsigs(vec![
            soa,
            nsec_record("example.com", "a.example.com", &[6, 47]),
            nsec_record("a.example.com", "c.example.com", &[1, 47]),
        ]);
        layer.maybe_cache(&response);

        let synthesized = layer
            .try_synthesize(&query("b2.example.com", RecordType::A))
            .expect("설정 범위로 저장한 NSEC 합성");
        assert!(
            synthesized
                .authorities
                .iter()
                .all(|record| (3..=5).contains(&record.ttl)),
            "neg_min_ttl/neg_max_ttl 범위를 적용해야 함: {:?}",
            synthesized.authorities
        );
    }

    #[test]
    /** @brief CNAME 뒤 NODATA에서 검증된 terminal proof도 부정 TTL 정책으로 재사용하는지. */
    fn aggressive_nsec_learns_proof_from_cname_to_nodata() {
        let layer = AggressiveNsecLayer::new(Mock::new(1, 0), 16, 0, 7);
        let alias = Name::from_str("alias.example.com").unwrap();
        let target = Name::from_str("target.example.com").unwrap();
        let mut response = answer_message(
            1,
            alias.clone(),
            RecordType::A,
            vec![Record::new(alias, 3_600, RData::Cname(target.clone()))],
        );
        response.header.authentic_data = true;
        response.authorities = with_rrsigs(vec![
            soa_record("example.com"),
            nsec_record("target.example.com", "z.example.com", &[28, 47]),
        ]);

        layer.maybe_cache(&response);

        let synthesized = layer
            .try_synthesize(&query("target.example.com", RecordType::A))
            .expect("CNAME terminal의 검증된 NODATA proof 재사용");
        assert_eq!(synthesized.header.rcode, ResponseCode::NoError.0);
        assert!(synthesized.answers.is_empty());
        assert!(synthesized.authorities.iter().all(|record| record.ttl <= 7));
    }

    #[test]
    /** @brief 서명 만료가 설정한 하한보다 짧으면 그쪽을 따르는지. */
    fn aggressive_nsec_dnssec_cap_overrides_configured_minimum() {
        let layer = AggressiveNsecLayer::new(Mock::new(1, 0), 16, 120, 120);
        let mut response = answer_message(
            1,
            Name::from_str("b.example.com").unwrap(),
            RecordType::A,
            vec![],
        );
        response.header.rcode = ResponseCode::NXDomain.0;
        response.header.authentic_data = true;
        let records = vec![
            soa_record("example.com"),
            nsec_record("example.com", "a.example.com", &[6, 47]),
            nsec_record("a.example.com", "c.example.com", &[1, 47]),
        ];
        response.authorities = records.clone();
        response.authorities.extend(
            records
                .iter()
                .map(|record| rrsig_record_with_lifetime(record, 60)),
        );
        layer.maybe_cache(&response);

        let synthesized = layer
            .try_synthesize(&query("b2.example.com", RecordType::A))
            .expect("configured minimum must not suppress a valid DNSSEC proof");
        assert!(
            synthesized
                .authorities
                .iter()
                .all(|record| record.ttl <= 60),
            "cryptographic lifetime must override neg_min_ttl: {:?}",
            synthesized.authorities
        );
    }

    #[test]
    /** @brief 수명이 0인 증명을 담지 않는지. 담으면 만료된 것으로 답을 만든다. */
    fn aggressive_nsec_never_caches_zero_ttl_proof_records() {
        let layer = AggressiveNsecLayer::new(Mock::new(1, 0), 16, 0, 86_400);
        let mut nsec = nsec_record("example.com", "a.example.com", &[6, 47]);
        nsec.ttl = 0;
        let mut response = answer_message(
            1,
            Name::from_str("missing.example.com").unwrap(),
            RecordType::A,
            vec![],
        );
        response.header.rcode = ResponseCode::NXDomain.0;
        response.header.authentic_data = true;
        response.authorities = with_rrsigs(vec![soa_record("example.com"), nsec]);

        layer.maybe_cache(&response);

        let store = layer.store.lock_recover();
        assert_eq!(store.records, 0);
        assert!(store.zones.is_empty());
    }

    #[test]
    /** @brief 담는 양이 상한을 지키고, 밀어낼 때 영역 단위로 밀어내는지. */
    fn aggressive_nsec_store_keeps_exact_record_cap_and_evicts_whole_lru_zone() {
        let layer = AggressiveNsecLayer::new(Mock::new(1, 0), 6, 0, 86_400);
        let response = |zone: &str| {
            let mut message = answer_message(
                1,
                Name::from_str(&format!("missing.{zone}")).unwrap(),
                RecordType::A,
                vec![],
            );
            message.header.rcode = ResponseCode::NXDomain.0;
            message.header.authentic_data = true;
            message.authorities = with_rrsigs(vec![
                soa_record(zone),
                nsec_record(zone, &format!("a.{zone}"), &[6, 47]),
                nsec_record(&format!("a.{zone}"), &format!("z.{zone}"), &[1, 47]),
            ]);
            message
        };

        layer.maybe_cache(&response("first.test"));
        layer.maybe_cache(&response("second.test"));

        let mut store = layer.store.lock_recover();
        assert_eq!(store.records, 6);
        assert_eq!(store.zones.len(), 1);
        assert!(store
            .zones
            .get(&(
                Name::from_str("first.test").unwrap().canonical_key(),
                DnsClass::IN.0,
            ))
            .is_none());
        assert!(store
            .zones
            .get(&(
                Name::from_str("second.test").unwrap().canonical_key(),
                DnsClass::IN.0,
            ))
            .is_some());
    }

    #[test]
    /** @brief 즉시 predecessor가 덮지 않으면 더 오래된 넓은 proof로 후퇴하지 않는지. */
    fn aggressive_denial_covering_never_skips_a_closer_owner() {
        let expiry = Instant::now() + Duration::from_secs(60);

        let mut nsec_zone = NsecZoneEntry::new();
        for record in [
            nsec_record("a.example", "z.example", &[47]),
            nsec_record("l.example", "l1.example", &[47]),
        ] {
            nsec_zone.records.insert(rec_key(&record), (record, expiry));
        }
        nsec_zone.rebuild_indexes();
        assert!(
            nsec_zone
                .nsec_covering(&Name::from_str("m.example").unwrap())
                .is_none(),
            "정렬상 더 가까운 l.example을 건너뛰고 a.example의 겹친 구간을 쓰면 안 된다"
        );

        let nsec3_record = |owner: [u8; 20], next: [u8; 20]| {
            let mut rdata = vec![1, 0, 0, 0, 0, 20];
            rdata.extend_from_slice(&next);
            Record::new(
                Name::from_str(&format!(
                    "{}.example",
                    onetdns_dnssec::base32hex_encode(&owner)
                ))
                .unwrap(),
                60,
                RData::Unknown(RecordType::NSEC3.0, rdata),
            )
        };
        let mut nsec3_zone = NsecZoneEntry::new();
        for record in [
            nsec3_record([0x10; 20], [0xf0; 20]),
            nsec3_record([0x70; 20], [0x75; 20]),
        ] {
            nsec3_zone
                .records
                .insert(rec_key(&record), (record, expiry));
        }
        nsec3_zone.rebuild_indexes();
        assert!(
            nsec3_zone.nsec3_covering(&[0x80; 20]).is_none(),
            "정렬상 더 가까운 0x70 owner를 건너뛰고 0x10의 겹친 구간을 쓰면 안 된다"
        );
    }

    #[test]
    /** @brief aggressive NSEC3 후보 탐색도 깊이×반복 총 SHA 예산을 공유하는지. */
    fn aggressive_nsec3_candidate_lookup_has_a_total_hash_budget() {
        let qname = Name::from_labels((0..127).map(|_| vec![b'a']).collect()).unwrap();
        let root = Name::from_labels(Vec::new()).unwrap();
        let expiry = Instant::now() + Duration::from_secs(60);
        let build_zone = |iterations: u16| {
            let nsec3_record = |owner: [u8; 20], next: [u8; 20]| {
                let mut rdata = vec![1, 0];
                rdata.extend_from_slice(&iterations.to_be_bytes());
                rdata.extend_from_slice(&[0, 20]);
                rdata.extend_from_slice(&next);
                Record::new(
                    Name::from_str(&format!("{}.", onetdns_dnssec::base32hex_encode(&owner)))
                        .unwrap(),
                    60,
                    RData::Unknown(RecordType::NSEC3.0, rdata),
                )
            };
            let root_hash: [u8; 20] = onetdns_dnssec::nsec3_hash(&root, &[], iterations)
                .try_into()
                .unwrap();
            let mut zone = NsecZoneEntry::new();
            for record in [
                nsec3_record(root_hash, [0xff; 20]),
                nsec3_record([0; 20], [0xff; 20]),
            ] {
                zone.records.insert(rec_key(&record), (record, expiry));
            }
            zone.rebuild_indexes();
            zone
        };

        let within_budget = build_zone(62);
        assert!(
            !within_budget
                .denial_candidates(&qname, Instant::now())
                .1
                .is_empty(),
            "130×63=8,190 SHA 라운드는 후보를 반환해야 한다"
        );

        let over_budget = build_zone(63);
        assert!(
            over_budget
                .denial_candidates(&qname, Instant::now())
                .1
                .is_empty(),
            "후보 탐색도 8,192 SHA 라운드 뒤 다음 이름 해시 전에 닫혀야 한다"
        );
    }

    #[test]
    /** @brief 큰 영역에서도 맞는 증명을 고르는지. */
    fn aggressive_nsec_selects_proof_from_large_zone_cache() {
        let layer = AggressiveNsecLayer::new(Mock::new(1, 0), 64, 0, 86_400);
        let mut response = answer_message(
            1,
            Name::from_str("b.example.com").unwrap(),
            RecordType::A,
            vec![],
        );
        response.header.rcode = ResponseCode::NXDomain.0;
        response.header.authentic_data = true;
        let mut denial = vec![
            soa_record("example.com"),
            nsec_record("example.com", "a.example.com", &[6, 47]),
            nsec_record("a.example.com", "c.example.com", &[1, 47]),
        ];
        for index in 0..6 {
            denial.push(nsec_record(
                &format!("x{index}.example.com"),
                &format!("x{index}z.example.com"),
                &[1, 47],
            ));
        }
        response.authorities = with_rrsigs(denial);
        layer.maybe_cache(&response);

        {
            let store = layer.store.lock_recover();
            assert!(
                store.records > 16,
                "fixture must cross the former synthesis cliff"
            );
        }

        let mut request = query("b2.example.com", RecordType::A);
        request.additionals.push(
            Edns {
                dnssec_ok: true,
                ..Default::default()
            }
            .try_to_record()
            .unwrap(),
        );
        let synthesized = layer
            .try_synthesize(&request)
            .expect("large zone cache must still synthesize from a minimal proof");
        assert_eq!(synthesized.header.rcode, ResponseCode::NXDomain.0);
        assert!(synthesized.authorities.len() <= 6);
        assert!(synthesized
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::SOA));
        assert!(synthesized
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::NSEC));
        assert!(synthesized
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::RRSIG));
    }

    #[test]
    #[ignore = "microbenchmark: run with --release -- --ignored --nocapture"]
    /** @brief 큰 영역에서 답을 만드는 비용. */
    fn bench_aggressive_nsec_large_zone_synthesis() {
        let layer = AggressiveNsecLayer::new(Mock::new(1, 0), 4096, 0, 86_400);
        let mut response = answer_message(
            1,
            Name::from_str("b.example.com").unwrap(),
            RecordType::A,
            vec![],
        );
        response.header.rcode = ResponseCode::NXDomain.0;
        response.header.authentic_data = true;
        let mut denial = vec![
            soa_record("example.com"),
            nsec_record("example.com", "a.example.com", &[6, 47]),
            nsec_record("a.example.com", "c.example.com", &[1, 47]),
        ];
        for index in 0..1000 {
            denial.push(nsec_record(
                &format!("x{index:04}.example.com"),
                &format!("x{index:04}z.example.com"),
                &[1, 47],
            ));
        }
        response.authorities = with_rrsigs(denial);
        layer.maybe_cache(&response);
        let request = query("b2.example.com", RecordType::A);
        assert!(layer.try_synthesize(&request).is_some());

        /** @brief 호출 횟수. */
        const CALLS: u32 = 1000;
        let started = Instant::now();
        for _ in 0..CALLS {
            std::hint::black_box(layer.try_synthesize(std::hint::black_box(&request)));
        }
        let elapsed = started.elapsed();
        println!(
            "aggressive-nsec-2006-cached-records: {:.1} us/call ({CALLS} calls in {elapsed:?})",
            elapsed.as_secs_f64() * 1_000_000.0 / f64::from(CALLS)
        );
    }

    #[test]
    /** @brief 증명이 바뀌면 한꺼번에 교체하는지. 섞이면 이전 증명과 새 증명이 함께 담긴다. */
    fn aggressive_nsec_replaces_changed_rrset_atomically() {
        let layer = AggressiveNsecLayer::new(Mock::new(1, 0), 16, 0, 86_400);
        let response = |next: &str| {
            let mut message = answer_message(
                1,
                Name::from_str("b.example.com").unwrap(),
                RecordType::A,
                vec![],
            );
            message.header.rcode = ResponseCode::NXDomain.0;
            message.header.authentic_data = true;
            message.authorities = with_rrsigs(vec![
                soa_record("example.com"),
                nsec_record("example.com", "a.example.com", &[6, 47]),
                nsec_record("a.example.com", next, &[1, 47]),
            ]);
            message
        };

        layer.maybe_cache(&response("c.example.com"));
        layer.maybe_cache(&response("d.example.com"));

        let mut store = layer.store.lock_recover();
        let zone = store
            .zones
            .get(&(
                Name::from_str("example.com").unwrap().canonical_key(),
                DnsClass::IN.0,
            ))
            .unwrap();
        let owner = Name::from_str("a.example.com").unwrap();
        let cached: Vec<&Record> = zone
            .records
            .values()
            .map(|(record, _)| record)
            .filter(|record| record.rtype == RecordType::NSEC && record.name.eq_ignore_case(&owner))
            .collect();
        assert_eq!(cached.len(), 1, "old and new NSEC RRsets must not be mixed");
        assert_eq!(
            onetdns_dnssec::Nsec::from_record(cached[0]).unwrap().next,
            Name::from_str("d.example.com").unwrap()
        );
        assert_eq!(store.records, 6);
    }

    #[test]
    /** @brief 전송이 끊겼을 때 보조 경로로 넘어가는지. */
    fn fallback_on_transport_exhaustion() {
        let primary = TransportFailureMock::new();
        let fallback = Mock::new(2, ResponseCode::NoError.0);
        let layer = FallbackLayer::new(primary.clone(), fallback.clone());
        let response = layer.resolve(&query("x.test", RecordType::A)).unwrap();
        assert_eq!(
            response.answers[0].ttl, 2,
            "transport failure uses fallback"
        );
        assert_eq!(primary.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    /** @brief 보조 경로에 재귀를 요구해 묻는지. */
    fn fallback_forces_recursion_desired() {
        let primary = TransportFailureMock::new();
        let fallback = RecursionDesiredMock::new();
        let layer = FallbackLayer::new(primary, fallback.clone());
        let mut req = query("www.example.com", RecordType::A);
        req.header.recursion_desired = false;

        let response = layer.resolve(&req).unwrap();
        assert_eq!(response.header.rcode, ResponseCode::NoError.0);
        assert!(
            fallback.seen.load(Ordering::SeqCst),
            "configured recursive fallback must receive RD=1"
        );
        let got = response.questions.first().expect("fallback question");
        let expected = req.questions.first().expect("original question");
        assert!(got.name.eq_ignore_case(&expected.name));
        assert_eq!(got.qtype, expected.qtype);
        assert_eq!(got.qclass, expected.qclass);
    }

    #[test]
    /** @brief 되돌릴 수 없는 실패는 넘기지 않는지. 넘기면 검증 실패를 우회하는 길이 된다. */
    fn no_fallback_on_permanent_backend_failure() {
        let primary = PermanentFailureMock::new();
        let fallback = Mock::new(2, ResponseCode::NoError.0);
        let layer = FallbackLayer::new(primary.clone(), fallback.clone());

        assert!(
            matches!(
                layer.resolve_outcome(&query("x.test", RecordType::A)),
                ResolveOutcome::Failure(ResolveFailure::Permanent(_))
            ),
            "영구 실패가 대체 경로에 가려지거나 다른 실패와 합쳐지면 안 된다"
        );
        assert_eq!(primary.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    /** @brief 오류 응답을 받은 것은 실패로 보지 않는지. */
    fn no_fallback_on_servfail_response() {
        let primary = Mock::new(1, ResponseCode::ServFail.0);
        let fallback = Mock::new(2, ResponseCode::NoError.0);
        let layer = FallbackLayer::new(primary.clone(), fallback.clone());
        let response = layer.resolve(&query("x.test", RecordType::A)).unwrap();
        assert_eq!(response.header.rcode, ResponseCode::ServFail.0);
        assert_eq!(primary.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    /** @brief 거절 응답을 받은 것은 실패로 보지 않는지. */
    fn no_fallback_on_refused_response() {
        let primary = Mock::new(1, ResponseCode::Refused.0);
        let fallback = Mock::new(2, ResponseCode::NoError.0);
        let layer = FallbackLayer::new(primary, fallback.clone());
        let response = layer.resolve(&query("x.test", RecordType::A)).unwrap();
        assert_eq!(response.header.rcode, ResponseCode::Refused.0);
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    /** @brief 정상 응답에는 다시 묻지 않는지. */
    fn no_fallback_on_noerror() {
        let primary = Mock::new(1, ResponseCode::NoError.0);
        let fallback = Mock::new(2, ResponseCode::NoError.0);
        let layer = FallbackLayer::new(primary.clone(), fallback.clone());
        let response = layer.resolve(&query("x.test", RecordType::A)).unwrap();
        assert_eq!(response.answers[0].ttl, 1, "primary response is final");
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    /** @brief 근거 없이 비어 온 응답에도 다시 묻지 않는지. */
    fn no_fallback_on_unproven_empty_noerror_packet() {
        let primary = EmptyMock::new(false);
        let fallback = Mock::new(8, ResponseCode::NoError.0);
        let layer = FallbackLayer::new(primary.clone(), fallback.clone());

        let response = layer.resolve(&query("empty.test", RecordType::A)).unwrap();
        assert_eq!(response.header.rcode, ResponseCode::NoError.0);
        assert!(response.answers.is_empty());
        assert_eq!(primary.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    /** @brief 근거가 담긴 빈 응답에 다시 묻지 않는지. */
    fn no_fallback_on_proven_nodata() {
        let primary = EmptyMock::new(true);
        let fallback = Mock::new(8, ResponseCode::NoError.0);
        let layer = FallbackLayer::new(primary.clone(), fallback.clone());

        let response = layer.resolve(&query("nodata.test", RecordType::A)).unwrap();
        assert!(response.answers.is_empty());
        assert_eq!(response.authorities.len(), 1);
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    /** @brief 접미사가 맞는 질의가 지정한 서버로 가는지. */
    fn stub_routes_matching_suffix() {
        let inner = Mock::new(1, ResponseCode::NoError.0);
        let stub = Mock::new(9, ResponseCode::NoError.0);
        let layer = StubLayer::new(
            inner.clone(),
            vec![(
                "corp.internal".to_string(),
                stub.clone() as Arc<dyn Resolver>,
            )],
        )
        .unwrap();

        let r1 = layer
            .resolve(&query("host.corp.internal", RecordType::A))
            .unwrap();
        assert_eq!(r1.answers[0].ttl, 9);

        let r2 = layer.resolve(&query("example.com", RecordType::A)).unwrap();
        assert_eq!(r2.answers[0].ttl, 1);
    }

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

    /** @brief 처음 한 번만 답하고 이후 실패하는 테스트용 리졸버. */
    struct FailAfterFirst {
        /** @brief 지금까지 답한 횟수. */
        n: AtomicU32,
    }
    impl Resolver for FailAfterFirst {
        /** @brief 미리 정해 둔 응답을 돌려준다. */
        fn resolve(&self, req: &Message) -> Option<Message> {
            let c = self.n.fetch_add(1, Ordering::SeqCst);
            if c == 0 {
                let q = req.questions.first().unwrap();
                let mut m = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
                m.answers.push(Record::new(
                    q.name.clone(),
                    1,
                    RData::A(Ipv4Addr::new(5, 6, 7, 8)),
                ));
                Some(m)
            } else {
                None
            }
        }
    }

    #[test]
    /** @brief 업스트림이 죽었을 때 담아 둔 답을 내보내는지. */
    fn serve_stale_on_failure() {
        let inner = Arc::new(FailAfterFirst {
            n: AtomicU32::new(0),
        });
        let layer = ServeStaleLayer::new(
            inner,
            Duration::from_secs(3600),
            1024,
            0,
            86_400,
            30,
            false,
            None,
            false,
        );

        let r1 = layer.resolve(&query("x.test", RecordType::A)).unwrap();
        assert_eq!(r1.answers.len(), 1);

        std::thread::sleep(Duration::from_millis(1100));

        let r2 = layer.resolve(&query("x.test", RecordType::A)).unwrap();
        assert_eq!(r2.answers.len(), 1);
        match &r2.answers[0].rdata {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(5, 6, 7, 8)),
            _ => panic!("stale A 기대"),
        }
        assert_eq!(r2.answers[0].ttl, 30, "stale은 짧은 TTL");

        let opt = r2.opt().expect("stale 응답에 OPT");
        let (code, _) = Edns::from_record(opt).unwrap().ede().expect("EDE");
        assert_eq!(code, ede_code::STALE_ANSWER);
    }

    #[test]
    /**
     * @brief 응답 수명을 0으로 설정해도 0으로 나가지 않는지.
     *
     * @details RFC 8767은 만료된 레코드의 수명을 0보다 크게 실으라고 정한다. 0이면 받은
     *          쪽이 담아 두지 못해 같은 이름을 곧바로 다시 묻고, 업스트림이 죽어 있는 동안
     *          질의가 몰린다. 이 기능이 막으려던 상황을 그대로 만든다.
     */
    fn serve_stale_reply_ttl_is_never_zero() {
        let layer = ServeStaleLayer::new(
            Mock::new(1, ResponseCode::ServFail.0),
            Duration::from_secs(60),
            16,
            0,
            86_400,
            0,
            false,
            None,
            false,
        );
        let request = query("stale.example", RecordType::A);
        let entry = StaleEntry {
            response: answer_message(
                1,
                Name::from_str("stale.example").unwrap(),
                RecordType::A,
                vec![Record::new(
                    Name::from_str("stale.example").unwrap(),
                    300,
                    RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                )],
            ),
            inserted: Instant::now(),
            fresh_until: Instant::now(),
            stale_until: Instant::now() + Duration::from_secs(60),
            original_ttl: Duration::from_secs(300),
        };

        let response = layer.build_stale(&request, &entry);
        assert_eq!(
            response.answers[0].ttl, 1,
            "0으로 설정해도 1 아래로는 내려가지 않습니다"
        );
    }

    #[test]
    /** @brief 지난 답을 먼저 내보내고 뒤에서 다시 묻는지. */
    fn serve_stale_refresh_serves_stale_then_refreshes() {
        /** @brief 두 번째부터 느리게 답하는 테스트용 리졸버. */
        struct SlowAfterFirst {
            /** @brief 불린 횟수. */
            calls: AtomicU32,
        }
        impl Resolver for SlowAfterFirst {
            /** @brief 미리 정해 둔 응답을 돌려준다. */
            fn resolve(&self, req: &Message) -> Option<Message> {
                let c = self.calls.fetch_add(1, Ordering::SeqCst);
                if c > 0 {
                    std::thread::sleep(Duration::from_millis(80));
                }
                let q = req.questions.first().unwrap();
                let mut m = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
                m.answers.push(Record::new(
                    q.name.clone(),
                    1,
                    RData::A(Ipv4Addr::new(7, 7, 7, 7)),
                ));
                Some(m)
            }
        }
        let inner = Arc::new(SlowAfterFirst {
            calls: AtomicU32::new(0),
        });
        let layer = ServeStaleLayer::new(
            inner.clone(),
            Duration::from_secs(3600),
            1024,
            0,
            86_400,
            11,
            false,
            Some(Duration::from_millis(5)),
            false,
        );

        let r1 = layer.resolve(&query("x.test", RecordType::A)).unwrap();
        assert!(r1.opt().is_none(), "첫 응답은 stale 아님");
        let c1 = inner.calls.load(Ordering::SeqCst);

        std::thread::sleep(Duration::from_millis(1100));

        let r2 = layer.resolve(&query("x.test", RecordType::A)).unwrap();
        assert_eq!(r2.answers[0].ttl, 11, "serve-stale reply TTL");
        let opt = r2.opt().expect("stale 응답 OPT");
        let (code, _) = Edns::from_record(opt).unwrap().ede().expect("EDE");
        assert_eq!(
            code,
            ede_code::STALE_ANSWER,
            "client_timeout 초과 시 즉시 stale 제공"
        );
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            inner.calls.load(Ordering::SeqCst) > c1,
            "백그라운드 갱신이 inner 재호출"
        );
    }

    #[test]
    /** @brief 만료 응답 먼저 보내기를 켜면 기다림 없이 지난 답을 내고 뒤에서 다시 묻는지. */
    fn stale_first_answers_without_waiting_for_upstream() {
        /** @brief 첫 번째 뒤로는 오래 걸리는 테스트용 리졸버. */
        struct SlowAfterFirst {
            /** @brief 불린 횟수. */
            calls: AtomicU32,
        }
        impl Resolver for SlowAfterFirst {
            /** @brief 수명 1초짜리 답을 돌려준다. */
            fn resolve(&self, req: &Message) -> Option<Message> {
                if self.calls.fetch_add(1, Ordering::SeqCst) > 0 {
                    std::thread::sleep(Duration::from_millis(500));
                }
                let q = req.questions.first().unwrap();
                let mut m = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
                m.answers.push(Record::new(
                    q.name.clone(),
                    1,
                    RData::A(Ipv4Addr::new(7, 7, 7, 7)),
                ));
                Some(m)
            }
        }
        let inner = Arc::new(SlowAfterFirst {
            calls: AtomicU32::new(0),
        });
        let layer = ServeStaleLayer::new(
            inner.clone(),
            Duration::from_secs(3600),
            1024,
            0,
            86_400,
            5,
            false,
            None,
            true,
        );
        layer.resolve(&query("y.test", RecordType::A)).unwrap();
        std::thread::sleep(Duration::from_millis(1100));

        let started = Instant::now();
        let stale = layer.resolve(&query("y.test", RecordType::A)).unwrap();
        assert!(started.elapsed() < Duration::from_millis(300));
        assert_eq!(stale.answers[0].ttl, 5);
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    /** @brief 실행 중인 갱신이 끝나기를 기다리고 사라지는지. 안 기다리면 사라진 것을 건드린다. */
    fn dropping_serve_stale_waits_for_active_refresh() {
        /** @brief 신호를 줄 때까지 답하지 않는 테스트용 리졸버. */
        struct BlockingRefresh {
            /** @brief 들어왔음을 알릴 곳. */
            entered: Mutex<Option<std::sync::mpsc::Sender<()>>>,
            /** @brief 놓아 줄 때까지 기다리는 곳. */
            release: Arc<(Mutex<bool>, Condvar)>,
        }
        impl Resolver for BlockingRefresh {
            /** @brief 신호가 올 때까지 멈춰 있는다. */
            fn resolve(&self, _req: &Message) -> Option<Message> {
                if let Some(entered) = self.entered.lock_recover().take() {
                    let _ = entered.send(());
                }
                let (released, wake) = &*self.release;
                let mut released = released.lock_recover();
                while !*released {
                    released = wake
                        .wait(released)
                        .unwrap_or_else(|error| error.into_inner());
                }
                None
            }
        }

        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let layer = ServeStaleLayer::new(
            Arc::new(BlockingRefresh {
                entered: Mutex::new(Some(entered_tx)),
                release: release.clone(),
            }),
            Duration::from_secs(60),
            8,
            0,
            86_400,
            30,
            false,
            None,
            false,
        );
        let request = query("drop-stale.test", RecordType::A);
        let key = semantic_request_key(&request).unwrap();
        layer.spawn_refresh(request, key);
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let (dropped_tx, dropped_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            drop(layer);
            let _ = dropped_tx.send(());
        });
        assert!(dropped_rx.recv_timeout(Duration::from_millis(50)).is_err());
        let (released, wake) = &*release;
        *released.lock_recover() = true;
        wake.notify_all();
        dropped_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[test]
    /** @brief 담는 양이 상한을 지키고 오래된 것부터 밀리는지. */
    fn serve_stale_store_honors_capacity_and_lru_recency() {
        let layer = ServeStaleLayer::new(
            Mock::new(1, ResponseCode::NoError.0),
            Duration::from_secs(3600),
            2,
            0,
            86_400,
            30,
            false,
            None,
            false,
        );
        let a = query("a.test", RecordType::A);
        let b = query("b.test", RecordType::A);
        let c = query("c.test", RecordType::A);
        let a_key = semantic_request_key(&a).unwrap();
        let b_key = semantic_request_key(&b).unwrap();
        let c_key = semantic_request_key(&c).unwrap();

        layer.resolve(&a).unwrap();
        layer.resolve(&b).unwrap();
        layer.resolve(&a).unwrap();
        layer.resolve(&c).unwrap();

        assert!(layer.cached(&a_key).is_some());
        assert!(layer.cached(&b_key).is_none(), "가장 오래 안 쓴 b가 퇴출");
        assert!(layer.cached(&c_key).is_some());
        assert_eq!(layer.store.lock_recover().len(), 2);
    }

    #[test]
    /** @brief 신선 구간이 설정한 수명 상하한을 지키는지. */
    fn serve_stale_fresh_cache_honors_configured_ttl_bounds() {
        let layer = ServeStaleLayer::new(
            Mock::new(1, ResponseCode::NoError.0),
            Duration::from_secs(3600),
            2,
            5,
            5,
            30,
            false,
            None,
            false,
        );
        let request = query("bounded.example", RecordType::A);
        let key = semantic_request_key(&request).unwrap();
        let answer = answer_message(
            1,
            Name::from_str("bounded.example").unwrap(),
            RecordType::A,
            vec![Record::new(
                Name::from_str("bounded.example").unwrap(),
                300,
                RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            )],
        );

        layer.store_answer(&request, key.clone(), &answer);

        let mut store = layer.store.lock_recover();
        let entry = store.get(&key).expect("serve-stale 캐시 저장");
        assert_eq!(entry.original_ttl, Duration::from_secs(5));
        assert_eq!(entry.response.answers[0].ttl, 5);
        assert!(entry.fresh_until <= Instant::now() + Duration::from_secs(5));
    }

    #[test]
    /** @brief 신선 구간이 서명 만료를 넘지 않는지. */
    fn serve_stale_fresh_window_is_capped_by_rrsig_expiration() {
        let layer = ServeStaleLayer::new(
            Mock::new(1, ResponseCode::NoError.0),
            Duration::from_secs(3600),
            2,
            0,
            86_400,
            30,
            false,
            None,
            false,
        );
        let request = query("signed.example", RecordType::A);
        let key = semantic_request_key(&request).unwrap();
        let answer = Record::new(
            Name::from_str("signed.example").unwrap(),
            3600,
            RData::A(Ipv4Addr::new(192, 0, 2, 10)),
        );
        let mut response = answer_message(1, answer.name.clone(), RecordType::A, vec![answer]);
        response.header.authentic_data = true;

        layer.store_answer(&request, key.clone(), &response);
        assert!(
            layer.store.lock_recover().is_empty(),
            "RRSIG 없는 AD 응답은 stale/fresh 캐시에 넣지 않음"
        );

        let signature = rrsig_record_with_lifetime(&response.answers[0], 5);
        response.answers.push(signature);
        layer.store_answer(&request, key.clone(), &response);
        let entry = layer.cached(&key).expect("서명 응답 저장");
        assert!(entry.original_ttl <= Duration::from_secs(5));
        assert!(
            entry.response.answers.iter().all(|record| record.ttl <= 5),
            "캐시 레코드 TTL도 서명 수명 이하여야 함"
        );

        response.header.authentic_data = false;
        layer.store.lock_recover().clear();
        layer.store_answer(&request, key.clone(), &response);
        let entry = layer.cached(&key).expect("AD=0 서명 응답 저장");
        assert!(entry.original_ttl <= Duration::from_secs(5));
        assert!(
            entry.response.answers.iter().all(|record| record.ttl <= 5),
            "AD=0이어도 stale 캐시가 RRSIG 수명을 연장하면 안 됨"
        );
    }

    #[test]
    /** @brief 질문과 무관한 답을 담지 않는지. 담으면 업스트림이 죽었을 때 그것이 나간다. */
    fn serve_stale_rejects_unrelated_lame_answer() {
        /** @brief 질문과 무관한 답을 내는 테스트용 리졸버. */
        struct UnrelatedAnswer {
            /** @brief 불린 횟수. */
            calls: AtomicU32,
        }
        impl Resolver for UnrelatedAnswer {
            /** @brief 무관한 답을 돌려준다. */
            fn resolve(&self, req: &Message) -> Option<Message> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let q = req.questions.first()?;
                let mut response = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
                response.answers.push(Record::new(
                    Name::from_str("attacker.example").unwrap(),
                    300,
                    RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                ));
                Some(response)
            }
        }

        let inner = Arc::new(UnrelatedAnswer {
            calls: AtomicU32::new(0),
        });
        let layer = ServeStaleLayer::new(
            inner.clone(),
            Duration::from_secs(3600),
            16,
            0,
            86_400,
            30,
            false,
            None,
            false,
        );
        let request = query("victim.example", RecordType::A);

        layer.resolve(&request).unwrap();
        layer.resolve(&request).unwrap();
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
        assert!(layer.store.lock_recover().is_empty());
    }

    #[test]
    /** @brief 딸려 온 기록도 제 수명대로 늙어 빠지는지. */
    fn serve_stale_fresh_hit_ages_and_expires_each_additional_rr() {
        /** @brief 딸린 기록의 수명이 짧은 답을 내는 테스트용 리졸버. */
        struct ShortAdditional;
        impl Resolver for ShortAdditional {
            /** @brief 딸린 기록의 수명이 짧은 답을 돌려준다. */
            fn resolve(&self, req: &Message) -> Option<Message> {
                let q = req.questions.first()?;
                let mut response = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
                response.answers.push(Record::new(
                    q.name.clone(),
                    100,
                    RData::A(Ipv4Addr::new(192, 0, 2, 10)),
                ));
                response.additionals.push(Record::new(
                    Name::from_str("ns.victim.example").unwrap(),
                    5,
                    RData::A(Ipv4Addr::new(192, 0, 2, 53)),
                ));
                Some(response)
            }
        }

        let layer = ServeStaleLayer::new(
            Arc::new(ShortAdditional),
            Duration::from_secs(3600),
            16,
            0,
            86_400,
            30,
            false,
            None,
            false,
        );
        let request = query("victim.example", RecordType::A);
        let key = semantic_request_key(&request).unwrap();
        layer.resolve(&request).unwrap();

        layer.store.lock_recover().get_mut(&key).unwrap().inserted =
            Instant::now() - Duration::from_secs(2);
        let aged = layer.resolve(&request).unwrap();
        assert_eq!(aged.additionals[0].ttl, 3);
        assert!(aged.answers[0].ttl <= 98);

        layer.store.lock_recover().get_mut(&key).unwrap().inserted =
            Instant::now() - Duration::from_secs(6);
        let expired = layer.resolve(&request).unwrap();
        assert!(expired.additionals.is_empty());
        assert!(expired.answers[0].ttl <= 94);
    }

    #[test]
    /** @brief 짧은 딸림 레코드가 자기 stale 구간을 넘긴 뒤 다시 살아나지 않는지. */
    fn serve_stale_does_not_resurrect_expired_additional_records() {
        let layer = ServeStaleLayer::new(
            Mock::new(1, ResponseCode::ServFail.0),
            Duration::from_secs(60),
            16,
            0,
            86_400,
            30,
            false,
            None,
            false,
        );
        let request = query("victim.example", RecordType::A);
        let mut response = answer_message(
            request.header.id,
            request.questions[0].name.clone(),
            RecordType::A,
            vec![Record::new(
                request.questions[0].name.clone(),
                100,
                RData::A(Ipv4Addr::new(192, 0, 2, 10)),
            )],
        );
        response.additionals.push(Record::new(
            Name::from_str("ns.victim.example").unwrap(),
            1,
            RData::A(Ipv4Addr::new(192, 0, 2, 53)),
        ));
        let entry = StaleEntry {
            response,
            inserted: Instant::now() - Duration::from_secs(62),
            fresh_until: Instant::now(),
            stale_until: Instant::now() + Duration::from_secs(60),
            original_ttl: Duration::from_secs(100),
        };

        let stale = layer.build_stale(&request, &entry);
        assert_eq!(stale.answers[0].ttl, 30);
        assert!(
            !stale.additionals.iter().any(|record| {
                record.rtype == RecordType::A
                    && record
                        .name
                        .eq_ignore_case(&Name::from_str("ns.victim.example").unwrap())
            }),
            "개별 TTL 1초와 stale 구간 60초를 모두 지난 glue는 되살리면 안 됩니다"
        );
    }

    #[test]
    /** @brief stale 구간 재설정이 주 답만 살리고 훨씬 짧은 딸림 레코드는 되살리지 않는지. */
    fn serve_stale_ttl_reset_preserves_per_record_ttl_offsets() {
        let layer = ServeStaleLayer::new(
            Mock::new(1, ResponseCode::ServFail.0),
            Duration::from_secs(60),
            16,
            0,
            86_400,
            30,
            true,
            None,
            false,
        );
        let request = query("reset.example", RecordType::A);
        let mut response = answer_message(
            request.header.id,
            request.questions[0].name.clone(),
            RecordType::A,
            vec![Record::new(
                request.questions[0].name.clone(),
                100,
                RData::A(Ipv4Addr::new(192, 0, 2, 10)),
            )],
        );
        response.additionals.push(Record::new(
            Name::from_str("ns.reset.example").unwrap(),
            1,
            RData::A(Ipv4Addr::new(192, 0, 2, 53)),
        ));
        let entry = StaleEntry {
            response,
            inserted: Instant::now() - Duration::from_secs(200),
            fresh_until: Instant::now() - Duration::from_secs(100),
            stale_until: Instant::now() + Duration::from_secs(60),
            original_ttl: Duration::from_secs(100),
        };

        let stale = layer.build_stale(&request, &entry);
        assert_eq!(stale.answers.len(), 1, "재설정한 주 답의 stale 구간은 유지");
        assert!(
            !stale
                .additionals
                .iter()
                .any(|record| record.rtype == RecordType::A),
            "주 답보다 99초 짧은 glue까지 전역 창으로 되살리면 안 됩니다"
        );
    }

    #[test]
    /** @brief 별칭 끝에 답이 있으면 담는지. */
    fn serve_stale_accepts_cname_chain_with_terminal_rrset() {
        /** @brief 별칭 체인이 담긴 답을 내는 테스트용 리졸버. */
        struct AliasAnswer {
            /** @brief 불린 횟수. */
            calls: AtomicU32,
        }
        impl Resolver for AliasAnswer {
            /** @brief 별칭 체인이 담긴 답을 돌려준다. */
            fn resolve(&self, req: &Message) -> Option<Message> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let q = req.questions.first()?;
                let target = Name::from_str("target.example").unwrap();
                let mut response = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
                response.answers.push(Record::new(
                    q.name.clone(),
                    100,
                    RData::Cname(target.clone()),
                ));
                response.answers.push(Record::new(
                    target,
                    100,
                    RData::A(Ipv4Addr::new(192, 0, 2, 20)),
                ));
                Some(response)
            }
        }

        let inner = Arc::new(AliasAnswer {
            calls: AtomicU32::new(0),
        });
        let layer = ServeStaleLayer::new(
            inner.clone(),
            Duration::from_secs(3600),
            16,
            0,
            86_400,
            30,
            false,
            None,
            false,
        );
        let request = query("alias.example", RecordType::A);

        assert_eq!(layer.resolve(&request).unwrap().answers.len(), 2);
        assert_eq!(layer.resolve(&request).unwrap().answers.len(), 2);
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    /** @brief 키로 삼기엔 너무 큰 질의도 답은 받는지. */
    fn oversized_semantic_key_bypasses_stale_state_without_dropping_query() {
        let inner = Mock::new(60, ResponseCode::NoError.0);
        let layer = ServeStaleLayer::new(
            inner.clone(),
            Duration::from_secs(3600),
            16,
            0,
            86_400,
            30,
            false,
            None,
            false,
        );
        let mut request = query("large.example", RecordType::A);
        request.additionals.push(Record::new(
            Name::root(),
            0,
            RData::Unknown(65_000, vec![0; MAX_SEMANTIC_KEY_WIRE + 1]),
        ));

        assert!(semantic_request_key(&request).is_none());
        assert!(layer.resolve(&request).is_some());
        assert!(layer.resolve(&request).is_some());
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
        assert!(layer.store.lock_recover().is_empty());
    }

    #[test]
    /** @brief 질의가 아닌 것이 담아 둔 상태를 건드리지 않는지. */
    fn non_query_envelope_bypasses_semantic_state() {
        let inner = Mock::new(60, ResponseCode::NoError.0);
        let layer = ServeStaleLayer::new(
            inner.clone(),
            Duration::from_secs(3600),
            16,
            0,
            86_400,
            30,
            false,
            None,
            false,
        );
        let mut request = query("envelope.example", RecordType::A);
        request.authorities.push(soa_record("example"));

        assert!(semantic_request_key(&request).is_none());
        assert!(layer.resolve(&request).is_some());
        assert!(layer.resolve(&request).is_some());
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
        assert!(layer.store.lock_recover().is_empty());
    }

    /** @brief 그대로 넘기는 테스트용 갱신 함수. */
    fn passthrough_refresher(inner: Arc<dyn Resolver>) -> PrefetchRefresher {
        Arc::new(move |req: &Message| inner.resolve(req))
    }

    #[test]
    /** @brief 자주 묻는 이름만 미리 묻는 대상이 되는지. */
    fn prefetch_popularity_gate() {
        let inner = Mock::new(1, ResponseCode::NoError.0);
        let layer = PrefetchLayer::with_policy(
            inner.clone(),
            passthrough_refresher(inner.clone()),
            Duration::from_millis(40),
            1024,
            2,
            10,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );

        layer.resolve(&query("rare.test", RecordType::A));
        assert_eq!(layer.tracked.lock_recover().len(), 1, "질의 직후 추적됨");
        std::thread::sleep(Duration::from_millis(1300));
        let tracked = layer.tracked.lock_recover().len();
        assert_eq!(
            tracked, 0,
            "인기 미달(hits<min_hits) 항목은 만기 시 추적 해제"
        );
    }

    #[test]
    /** @brief 수명이 0인 답을 미리 묻는 대상으로 삼지 않는지. */
    fn prefetch_never_tracks_zero_ttl_answers() {
        /** @brief 수명이 0인 답을 내는 테스트용 리졸버. */
        struct ZeroTtlAnswer;
        impl Resolver for ZeroTtlAnswer {
            /** @brief 수명이 0인 답을 돌려준다. */
            fn resolve(&self, req: &Message) -> Option<Message> {
                let question = req.questions.first()?;
                Some(answer_message(
                    req.header.id,
                    question.name.clone(),
                    question.qtype,
                    vec![Record::new(
                        question.name.clone(),
                        0,
                        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                    )],
                ))
            }
        }

        let backend: Arc<dyn Resolver> = Arc::new(ZeroTtlAnswer);
        let layer = PrefetchLayer::with_policy(
            backend.clone(),
            passthrough_refresher(backend),
            Duration::from_secs(3600),
            16,
            1,
            50,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );

        layer.resolve(&query("zero.example", RecordType::A));

        assert!(
            layer.tracked.lock_recover().is_empty(),
            "캐시할 수 없는 TTL=0 응답을 prefetch가 추적하면 안 됨"
        );
    }

    #[test]
    /** @brief 한 번에 미리 묻는 양이 상한을 지키는지. 안 지키면 그때마다 부하가 튄다. */
    fn prefetch_refresh_work_is_bounded_per_cycle() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let refresh_calls = calls.clone();
        let refresher: PrefetchRefresher = Arc::new(move |_| {
            refresh_calls.fetch_add(1, Ordering::SeqCst);
            None
        });
        let layer = PrefetchLayer::with_policy(
            Mock::new(60, ResponseCode::NoError.0),
            refresher,
            Duration::from_secs(3600),
            MAX_PREFETCH_REFRESH_BATCH + 1,
            1,
            50,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );
        {
            let mut tracked = layer.tracked.lock_recover();
            for index in 0..=MAX_PREFETCH_REFRESH_BATCH {
                let request = query(&format!("due-{index}.example"), RecordType::A);
                tracked.insert(
                    semantic_request_key(&request).unwrap(),
                    PrefetchEntry {
                        refresh_at: Instant::now(),
                        hits: 1,
                        request,
                    },
                );
            }
        }

        layer.worker.as_ref().unwrap().thread().unpark();
        for _ in 0..100 {
            if calls.load(Ordering::SeqCst) >= MAX_PREFETCH_REFRESH_BATCH {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(20));

        assert_eq!(
            calls.load(Ordering::SeqCst),
            MAX_PREFETCH_REFRESH_BATCH,
            "한 prefetch 주기가 캐시 전체를 한꺼번에 갱신하면 안 됨"
        );
        assert_eq!(layer.tracked.lock_recover().len(), 1);
    }

    #[test]
    /** @brief 수명이 0이 된 항목을 대상에서 빼는지. */
    fn prefetch_refresh_drops_entry_when_ttl_becomes_zero() {
        let refresher: PrefetchRefresher = Arc::new(|request| {
            let question = request.questions.first()?;
            Some(answer_message(
                request.header.id,
                question.name.clone(),
                question.qtype,
                vec![Record::new(
                    question.name.clone(),
                    0,
                    RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                )],
            ))
        });
        let layer = PrefetchLayer::with_policy(
            Mock::new(60, ResponseCode::NoError.0),
            refresher,
            Duration::from_secs(3600),
            1,
            1,
            50,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );
        let request = query("expires-now.example", RecordType::A);
        layer.tracked.lock_recover().insert(
            semantic_request_key(&request).unwrap(),
            PrefetchEntry {
                refresh_at: Instant::now(),
                hits: 1,
                request,
            },
        );

        layer.worker.as_ref().unwrap().thread().unpark();
        for _ in 0..100 {
            if layer.tracked.lock_recover().is_empty() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("TTL=0으로 바뀐 prefetch 항목이 제거되지 않았습니다");
    }

    #[test]
    /** @brief 만료 전에 미리 다시 물어 담아 두는지. */
    fn prefetch_rewarms_cache_before_expiry() {
        let backend = Mock::new(2, ResponseCode::NoError.0);
        let cache = Arc::new(
            crate::cache::CacheLayer::new(backend.clone(), 1024, 1, 0, 10, 0, 10)
                .with_positive_cache(true),
        );
        let handle = cache.handle();
        let refresher: PrefetchRefresher = {
            let backend = backend.clone();
            Arc::new(move |req: &Message| {
                let resp = backend.resolve(req)?;
                handle.store(req, &resp);
                Some(resp)
            })
        };
        let layer = PrefetchLayer::with_policy(
            cache,
            refresher,
            Duration::from_millis(100),
            1024,
            1,
            50,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );
        layer.resolve(&query("hot.test", RecordType::A));
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1, "최초 미스 1회");

        std::thread::sleep(Duration::from_millis(1300));
        assert_eq!(
            backend.calls.load(Ordering::SeqCst),
            2,
            "만료(2s) 전 프리패치가 캐시를 우회해 재해석"
        );
    }

    #[test]
    /** @brief 사라질 때 뒤에서 실행 중인 것이 깨어나 끝나는지. */
    fn dropping_prefetch_layer_wakes_and_releases_background_state() {
        let inner = Mock::new(60, ResponseCode::NoError.0);
        let layer = PrefetchLayer::with_policy(
            inner.clone(),
            passthrough_refresher(inner),
            Duration::from_secs(3600),
            16,
            1,
            50,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );
        let tracked = Arc::downgrade(&layer.tracked);
        drop(layer);

        for _ in 0..100 {
            if tracked.upgrade().is_none() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("prefetch layer drop 후 background worker가 상태를 계속 보유함");
    }

    #[test]
    /** @brief 대역 정보가 붙는지. */
    fn ecs_option_attached() {
        let inner = Mock::new(1, ResponseCode::NoError.0);
        let layer = EcsLayer::new(inner, "203.0.113.5".parse().unwrap());

        let option = layer.option.as_ref().expect("ECS 옵션이 부착되어야 함");
        assert_eq!(option.0, 8);
        assert_eq!(option.1, vec![0x00, 0x01, 24, 0, 203, 0, 113]);

        let resp = layer.resolve(&query("x.test", RecordType::A));
        assert!(resp.is_some());
    }

    #[test]
    /** @brief 분기 규칙과 고정해 둔 주소가 함께 동작하는지. */
    fn split_local_and_routing() {
        let fwd = Mock::new(3, ResponseCode::NoError.0);
        let rec = Mock::new(4, ResponseCode::NoError.0);
        let local_ttl = Arc::new(AtomicU32::new(17));
        let split = SplitResolver::new(
            fwd.clone(),
            rec.clone(),
            Route::Forward,
            &["corp.internal".to_string()],
            &[],
        )
        .unwrap();
        let cached = crate::cache::CacheLayer::new(Arc::new(split), 8, 1, 0, 3_600, 0, 3_600);
        let addresses = Arc::new(
            LocalAddressTable::new(
                &[("router.lan".to_string(), Ipv4Addr::new(192, 168, 0, 1))],
                &[],
                local_ttl.clone(),
            )
            .unwrap(),
        );
        let split = LocalAddressLayer::new(Arc::new(cached), addresses, None);

        let r0 = split.resolve(&query("router.lan", RecordType::A)).unwrap();
        match &r0.answers[0].rdata {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(192, 168, 0, 1)),
            _ => panic!("로컬 A 기대"),
        }
        assert_eq!(r0.answers[0].ttl, 17, "설정한 로컬 TTL");
        local_ttl.store(23, Ordering::Release);
        assert_eq!(
            split
                .resolve(&query("router.lan", RecordType::A))
                .unwrap()
                .answers[0]
                .ttl,
            23,
            "응답 캐시가 있어도 핫 적용한 로컬 TTL"
        );
        local_ttl.store(0, Ordering::Release);
        assert_eq!(
            split
                .resolve(&query("router.lan", RecordType::A))
                .unwrap()
                .answers[0]
                .ttl,
            0,
            "TTL 0을 숨은 하한 없이 보존"
        );
        local_ttl.store(u32::MAX, Ordering::Release);
        assert_eq!(
            split
                .resolve(&query("router.lan", RecordType::A))
                .unwrap()
                .answers[0]
                .ttl,
            u32::MAX,
            "TTL 상한값을 잘라내지 않음"
        );
        let nodata = split
            .resolve(&query("router.lan", RecordType::TXT))
            .unwrap();
        assert!(nodata.answers.is_empty());
        assert!(
            matches!(
                nodata.authorities.as_slice(),
                [Record {
                    ttl: u32::MAX,
                    rdata: RData::Soa(soa),
                    ..
                }] if soa.minimum == u32::MAX
            ),
            "등록된 로컬 이름의 다른 타입은 SOA가 증명하는 NODATA"
        );

        let r1 = split
            .resolve(&query("host.corp.internal", RecordType::A))
            .unwrap();
        assert_eq!(r1.answers[0].ttl, 4, "recurse로 라우팅");

        let r2 = split.resolve(&query("example.com", RecordType::A)).unwrap();
        assert_eq!(r2.answers[0].ttl, 3, "기본 forward");
    }

    #[test]
    /** @brief 이 서버가 서명해 낸 답을 남이 실제로 검증할 수 있는지. */
    fn signed_authority_serves_validatable_dnssec() {
        use onetdns_dnssec::sign::{sign_zone, ZoneSigner};

        let zone_text = "$ORIGIN sec.test.\n$TTL 300\n@ IN SOA ns1 admin 1 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\nwww IN A 10.0.0.2\nweb IN HTTPS 0 svc.sec.test.\nsvc IN HTTPS 1 . port=443\nsvc IN A 10.0.0.3\nold IN DNAME target.sec.test.\nwww.target IN A 10.0.0.4\nalias-nodata IN CNAME target-nodata\ntarget-nodata IN AAAA 2001:db8::1\nalias-nx IN CNAME missing\n";
        let unsigned = onetdns_authority::parse_zone(zone_text, "sec.test").unwrap();
        let signer = ZoneSigner::generate(Name::from_str("sec.test").unwrap(), [9u8; 32]);
        let now = 1_700_000_000u64;
        let mut recs = unsigned.axfr_records();
        recs.pop();
        let signed = onetdns_authority::Zone::from_records(sign_zone(&recs, &signer, now)).unwrap();
        let mut zs = onetdns_authority::ZoneStore::new();
        zs.add(signed);
        let store = Arc::new(onetdns_core::ArcSwap::new(Arc::new(zs)));
        let layer = AuthorityLayer::new(Mock::new(9, 0) as Arc<dyn Resolver>, store);

        let do_query = |name: &str, qtype: RecordType| -> Message {
            let mut q = Message::query(7, Name::from_str(name).unwrap(), qtype);
            q.additionals.push(
                Edns {
                    dnssec_ok: true,
                    ..Default::default()
                }
                .try_to_record()
                .unwrap(),
            );
            q
        };

        let resp = layer
            .resolve(&do_query("www.sec.test", RecordType::A))
            .unwrap();
        let rrset: Vec<Record> = resp
            .answers
            .iter()
            .filter(|r| r.rtype == RecordType::A)
            .cloned()
            .collect();
        let sigs: Vec<onetdns_dnssec::Rrsig> = resp
            .answers
            .iter()
            .filter(|r| r.rtype.0 == 46)
            .filter_map(onetdns_dnssec::Rrsig::from_record)
            .collect();
        assert!(!rrset.is_empty() && !sigs.is_empty(), "A+RRSIG 부착");
        onetdns_dnssec::validate_rrset(&rrset, &sigs, &[signer.dnskey()], now as u32)
            .expect("서빙된 양성 응답 검증");

        let binding = layer
            .resolve(&do_query("web.sec.test", RecordType::HTTPS))
            .unwrap();
        for covered in [RecordType::HTTPS, RecordType::A] {
            let rrset: Vec<Record> = binding
                .additionals
                .iter()
                .filter(|record| {
                    record
                        .name
                        .eq_ignore_case(&Name::from_str("svc.sec.test").unwrap())
                        && record.rtype == covered
                })
                .cloned()
                .collect();
            let signatures: Vec<onetdns_dnssec::Rrsig> = binding
                .additionals
                .iter()
                .filter_map(onetdns_dnssec::Rrsig::from_record)
                .filter(|signature| signature.type_covered == covered.0)
                .collect();
            assert!(!rrset.is_empty() && !signatures.is_empty());
            onetdns_dnssec::validate_rrset(&rrset, &signatures, &[signer.dnskey()], now as u32)
                .expect("Additional service-binding RRset RRSIG 검증");
        }

        let dname = layer
            .resolve(&do_query("www.old.sec.test", RecordType::A))
            .unwrap();
        assert!(dname
            .answers
            .iter()
            .any(|record| record.rtype == RecordType::DNAME));
        assert!(dname.answers.iter().any(|record| {
            record
                .name
                .eq_ignore_case(&Name::from_str("www.target.sec.test").unwrap())
                && record.rtype == RecordType::A
        }));
        assert!(dname.answers.iter().any(|record| {
            record
                .name
                .eq_ignore_case(&Name::from_str("old.sec.test").unwrap())
                && onetdns_dnssec::Rrsig::from_record(record)
                    .is_some_and(|signature| signature.type_covered == RecordType::DNAME.0)
        }));
        assert!(dname.answers.iter().any(|record| {
            record
                .name
                .eq_ignore_case(&Name::from_str("www.target.sec.test").unwrap())
                && onetdns_dnssec::Rrsig::from_record(record)
                    .is_some_and(|signature| signature.type_covered == RecordType::A.0)
        }));
        assert!(!dname.answers.iter().any(|record| {
            record
                .name
                .eq_ignore_case(&Name::from_str("www.old.sec.test").unwrap())
                && onetdns_dnssec::Rrsig::from_record(record)
                    .is_some_and(|signature| signature.type_covered == RecordType::CNAME.0)
        }));

        let cname_nodata = layer
            .resolve(&do_query("alias-nodata.sec.test", RecordType::A))
            .unwrap();
        assert_eq!(cname_nodata.header.rcode, ResponseCode::NoError.0);
        let cname_nodata_proof: Vec<Record> = cname_nodata
            .authorities
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC)
            .cloned()
            .collect();
        assert!(
            onetdns_dnssec::prove_nodata(
                &cname_nodata_proof,
                &Name::from_str("target-nodata.sec.test").unwrap(),
                RecordType::A.0,
            ),
            "CNAME terminal NODATA를 증명하는 NSEC가 필요합니다"
        );

        let cname_nxdomain = layer
            .resolve(&do_query("alias-nx.sec.test", RecordType::A))
            .unwrap();
        assert_eq!(cname_nxdomain.header.rcode, ResponseCode::NXDomain.0);
        let cname_nxdomain_proof: Vec<Record> = cname_nxdomain
            .authorities
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC)
            .cloned()
            .collect();
        assert!(
            onetdns_dnssec::prove_name_nonexistent(
                &cname_nxdomain_proof,
                &Name::from_str("missing.sec.test").unwrap(),
            ),
            "CNAME terminal NXDOMAIN은 최종 대상의 부재를 증명해야 합니다"
        );

        let resp = layer
            .resolve(&do_query("nope.sec.test", RecordType::A))
            .unwrap();
        assert_eq!(resp.header.rcode, ResponseCode::NXDomain.0);
        let nsecs: Vec<Record> = resp
            .authorities
            .iter()
            .filter(|r| r.rtype.0 == 47)
            .cloned()
            .collect();
        assert!(!nsecs.is_empty(), "NSEC 부착");
        assert!(
            onetdns_dnssec::prove_name_nonexistent(
                &nsecs,
                &Name::from_str("nope.sec.test").unwrap()
            ),
            "서빙된 NXDOMAIN 부재증명 검증"
        );

        let nsec_sigs: Vec<onetdns_dnssec::Rrsig> = resp
            .authorities
            .iter()
            .filter(|r| r.rtype.0 == 46)
            .filter_map(onetdns_dnssec::Rrsig::from_record)
            .filter(|s| s.type_covered == 47)
            .collect();
        assert!(!nsec_sigs.is_empty(), "RRSIG(NSEC) 부착");
        let one_nsec: Vec<Record> = nsecs
            .iter()
            .filter(|r| r.name.eq_ignore_case(&nsecs[0].name))
            .cloned()
            .collect();
        onetdns_dnssec::validate_rrset(&one_nsec, &nsec_sigs, &[signer.dnskey()], now as u32)
            .expect("NSEC RRSIG 검증");

        let resp = layer
            .resolve(&Message::query(
                8,
                Name::from_str("www.sec.test").unwrap(),
                RecordType::A,
            ))
            .unwrap();
        assert!(
            resp.answers.iter().all(|r| r.rtype.0 != 46),
            "DO=0 → RRSIG 없음"
        );
    }

    #[test]
    /** @brief 와일드카드 이름과 빈 중간 이름의 답에 증명이 붙는지. */
    fn signed_authority_proves_wildcard_and_empty_nonterminal_answers() {
        use onetdns_dnssec::sign::{sign_zone_with, DenialMode, Nsec3Params, ZoneSigner};

        let zone_text = "$ORIGIN sec.test.\n$TTL 300\n@ IN SOA ns1 admin 1 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\n*.wild IN A 10.0.0.2\nleaf.empty IN A 10.0.0.3\nalias-nodata IN CNAME target-nodata\ntarget-nodata IN AAAA 2001:db8::1\nalias-nx IN CNAME missing\n";
        let unsigned = onetdns_authority::parse_zone(zone_text, "sec.test").unwrap();
        let signer = ZoneSigner::generate(Name::from_str("sec.test").unwrap(), [19u8; 32]);
        let now = 1_700_000_000u64;

        for mode in [
            DenialMode::Nsec,
            DenialMode::Nsec3(Nsec3Params {
                iterations: 0,
                salt: vec![0xab, 0xcd],
            }),
        ] {
            let mut records = unsigned.axfr_records();
            records.pop();
            let signed_records = sign_zone_with(&records, &signer, now, &mode);
            let signed = onetdns_authority::Zone::from_records(signed_records).unwrap();
            let mut zones = onetdns_authority::ZoneStore::new();
            zones.add(signed);
            let layer = AuthorityLayer::new(
                Mock::new(9, 0) as Arc<dyn Resolver>,
                Arc::new(onetdns_core::ArcSwap::new(Arc::new(zones))),
            );
            let query = |name: &str, qtype: RecordType| {
                let mut message = Message::query(7, Name::from_str(name).unwrap(), qtype);
                message.additionals.push(
                    Edns {
                        dnssec_ok: true,
                        ..Default::default()
                    }
                    .try_to_record()
                    .unwrap(),
                );
                message
            };
            let denial = |response: &Message| {
                response
                    .authorities
                    .iter()
                    .filter(|record| {
                        record.rtype
                            == if matches!(&mode, DenialMode::Nsec) {
                                RecordType::NSEC
                            } else {
                                RecordType::NSEC3
                            }
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            };

            let wildcard_name = Name::from_str("host.wild.sec.test").unwrap();
            let positive = layer
                .resolve(&query("host.wild.sec.test", RecordType::A))
                .unwrap();
            assert!(positive
                .answers
                .iter()
                .any(|record| record.rtype == RecordType::A));
            assert!(positive
                .answers
                .iter()
                .any(|record| record.rtype == RecordType::RRSIG));
            let positive_denial = denial(&positive);
            assert!(!positive_denial.is_empty());
            assert!(match &mode {
                DenialMode::Nsec =>
                    onetdns_dnssec::prove_wildcard_expansion(&positive_denial, &wildcard_name, 3,),
                DenialMode::Nsec3(_) => onetdns_dnssec::prove_wildcard_expansion_nsec3(
                    &positive_denial,
                    &wildcard_name,
                    3,
                ),
            });

            let wildcard_nodata = layer
                .resolve(&query("host.wild.sec.test", RecordType::AAAA))
                .unwrap();
            let wildcard_proof = denial(&wildcard_nodata);
            assert!(match &mode {
                DenialMode::Nsec => onetdns_dnssec::prove_nodata(
                    &wildcard_proof,
                    &wildcard_name,
                    RecordType::AAAA.0,
                ),
                DenialMode::Nsec3(_) => onetdns_dnssec::prove_nodata_nsec3(
                    &wildcard_proof,
                    &wildcard_name,
                    RecordType::AAAA.0,
                ),
            });

            let empty_name = Name::from_str("empty.sec.test").unwrap();
            let empty_nodata = layer
                .resolve(&query("empty.sec.test", RecordType::AAAA))
                .unwrap();
            let empty_proof = denial(&empty_nodata);
            assert!(match &mode {
                DenialMode::Nsec =>
                    onetdns_dnssec::prove_nodata(&empty_proof, &empty_name, RecordType::AAAA.0,),
                DenialMode::Nsec3(_) => onetdns_dnssec::prove_nodata_nsec3(
                    &empty_proof,
                    &empty_name,
                    RecordType::AAAA.0,
                ),
            });

            let terminal_nodata_name = Name::from_str("target-nodata.sec.test").unwrap();
            let terminal_nodata = layer
                .resolve(&query("alias-nodata.sec.test", RecordType::A))
                .unwrap();
            let terminal_nodata_proof = denial(&terminal_nodata);
            assert!(match &mode {
                DenialMode::Nsec => onetdns_dnssec::prove_nodata(
                    &terminal_nodata_proof,
                    &terminal_nodata_name,
                    RecordType::A.0,
                ),
                DenialMode::Nsec3(_) => onetdns_dnssec::prove_nodata_nsec3(
                    &terminal_nodata_proof,
                    &terminal_nodata_name,
                    RecordType::A.0,
                ),
            });

            let missing_name = Name::from_str("missing.sec.test").unwrap();
            let terminal_nxdomain = layer
                .resolve(&query("alias-nx.sec.test", RecordType::A))
                .unwrap();
            let terminal_nxdomain_proof = denial(&terminal_nxdomain);
            assert!(match &mode {
                DenialMode::Nsec =>
                    onetdns_dnssec::prove_name_nonexistent(&terminal_nxdomain_proof, &missing_name,),
                DenialMode::Nsec3(_) => onetdns_dnssec::prove_name_nonexistent_nsec3(
                    &terminal_nxdomain_proof,
                    &missing_name,
                ),
            });
        }
    }

    #[test]
    /** @brief 위임 지점에서 다음 영역의 키와 그 서명을 주는지. */
    fn signed_delegation_serves_ds_and_its_signature() {
        use onetdns_dnssec::sign::{sign_zone, ZoneSigner};

        let zone_text = "$ORIGIN sec.test.\n$TTL 300\n@ IN SOA ns1 admin 1 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\nchild IN NS ns.child\nchild IN NS ns2.child\nns.child IN A 10.0.0.2\nns2.child IN A 10.0.0.3\nchild IN TYPE43 \\# 4 000d0200\nplain IN NS ns.plain\nns.plain IN A 10.0.0.4\n";
        let unsigned = onetdns_authority::parse_zone(zone_text, "sec.test").unwrap();
        let signer = ZoneSigner::generate(Name::from_str("sec.test").unwrap(), [12u8; 32]);
        let now = 1_700_000_000u64;
        let mut records = unsigned.axfr_records();
        records.pop();
        let signed =
            onetdns_authority::Zone::from_records(sign_zone(&records, &signer, now)).unwrap();
        let mut zones = onetdns_authority::ZoneStore::new();
        zones.add(signed);
        let layer = AuthorityLayer::new(
            Mock::new(9, 0) as Arc<dyn Resolver>,
            Arc::new(onetdns_core::ArcSwap::new(Arc::new(zones))),
        );

        let mut query = Message::query(
            7,
            Name::from_str("host.child.sec.test").unwrap(),
            RecordType::A,
        );
        query.additionals.push(
            Edns {
                dnssec_ok: true,
                ..Default::default()
            }
            .try_to_record()
            .unwrap(),
        );
        let referral = layer.resolve(&query).unwrap();
        assert!(!referral.header.authoritative);
        let ds: Vec<Record> = referral
            .authorities
            .iter()
            .filter(|record| record.rtype == RecordType::DS)
            .cloned()
            .collect();
        let signatures: Vec<onetdns_dnssec::Rrsig> = referral
            .authorities
            .iter()
            .filter_map(onetdns_dnssec::Rrsig::from_record)
            .filter(|signature| signature.type_covered == RecordType::DS.0)
            .collect();
        assert_eq!(ds.len(), 1);
        assert!(!signatures.is_empty());
        onetdns_dnssec::validate_rrset(&ds, &signatures, &[signer.dnskey()], now as u32)
            .expect("referral DS 서명 검증");
        assert_eq!(
            referral
                .authorities
                .iter()
                .filter_map(onetdns_dnssec::Rrsig::from_record)
                .filter(|signature| signature.type_covered == RecordType::NS.0)
                .count(),
            0,
            "부모 zone의 delegation NS RRset은 서명하지 않음"
        );
        assert!(!referral
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::NSEC));

        query.questions[0].name = Name::from_str("host.plain.sec.test").unwrap();
        query.questions[0].qtype = RecordType::A;
        let insecure_referral = layer.resolve(&query).unwrap();
        assert!(!insecure_referral.header.authoritative);
        assert!(!insecure_referral
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::DS));
        let denial: Vec<Record> = insecure_referral
            .authorities
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC)
            .cloned()
            .collect();
        assert_eq!(denial.len(), 1, "위임점 DS 부재증명만 첨부");
        assert!(onetdns_dnssec::prove_nodata(
            &denial,
            &Name::from_str("plain.sec.test").unwrap(),
            RecordType::DS.0,
        ));
        let denial_signatures: Vec<onetdns_dnssec::Rrsig> = insecure_referral
            .authorities
            .iter()
            .filter_map(onetdns_dnssec::Rrsig::from_record)
            .filter(|signature| signature.type_covered == RecordType::NSEC.0)
            .collect();
        onetdns_dnssec::validate_rrset(&denial, &denial_signatures, &[signer.dnskey()], now as u32)
            .expect("insecure delegation NSEC 검증");

        query.questions[0].name = Name::from_str("child.sec.test").unwrap();
        query.questions[0].qtype = RecordType::DS;
        let direct = layer.resolve(&query).unwrap();
        assert!(direct.header.authoritative);
        assert!(direct
            .answers
            .iter()
            .any(|record| record.rtype == RecordType::DS));
        assert!(direct
            .answers
            .iter()
            .filter_map(onetdns_dnssec::Rrsig::from_record)
            .any(|signature| signature.type_covered == RecordType::DS.0));
    }

    #[test]
    /** @brief 와일드카드 이름으로 만든 답의 서명이 원래 임자 이름을 유지하는지. 바꾸면 검증이 깨진다. */
    fn wildcard_answer_carries_reowned_rrsig() {
        use onetdns_dnssec::sign::{sign_zone, ZoneSigner};

        let zone_text = "$ORIGIN sec.test.\n$TTL 300\n@ IN SOA ns1 admin 1 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\n*.w IN A 10.0.0.77\n";
        let unsigned = onetdns_authority::parse_zone(zone_text, "sec.test").unwrap();
        let signer = ZoneSigner::generate(Name::from_str("sec.test").unwrap(), [11u8; 32]);
        let now = 1_700_000_000u64;
        let mut recs = unsigned.axfr_records();
        recs.pop();
        let signed = onetdns_authority::Zone::from_records(sign_zone(&recs, &signer, now)).unwrap();
        let mut zs = onetdns_authority::ZoneStore::new();
        zs.add(signed);
        let store = Arc::new(onetdns_core::ArcSwap::new(Arc::new(zs)));
        let layer = AuthorityLayer::new(Mock::new(9, 0) as Arc<dyn Resolver>, store);

        let mut q = Message::query(7, Name::from_str("abc.w.sec.test").unwrap(), RecordType::A);
        q.additionals.push(
            Edns {
                dnssec_ok: true,
                ..Default::default()
            }
            .try_to_record()
            .unwrap(),
        );
        let resp = layer.resolve(&q).unwrap();

        let rrset: Vec<Record> = resp
            .answers
            .iter()
            .filter(|r| r.rtype == RecordType::A)
            .cloned()
            .collect();
        assert!(!rrset.is_empty(), "합성 A 답");
        let sigs: Vec<onetdns_dnssec::Rrsig> = resp
            .answers
            .iter()
            .filter(|r| r.rtype.0 == 46 && r.name.eq_ignore_case(&rrset[0].name))
            .filter_map(onetdns_dnssec::Rrsig::from_record)
            .collect();
        assert!(!sigs.is_empty(), "와일드카드 RRSIG 재부착");
        assert!(sigs[0].labels < 4, "labels 필드 < qname 라벨 수(확장 신호)");
        onetdns_dnssec::validate_rrset(&rrset, &sigs, &[signer.dnskey()], now as u32)
            .expect("와일드카드 합성 답 검증(검증기의 owner_for_signing 재구성)");

        assert!(
            resp.authorities.iter().any(|r| r.rtype.0 == 47),
            "qname 부재 NSEC 부착"
        );
    }

    #[test]
    /** @brief 감춘 형태의 증명으로 빈 답을 만드는지. */
    fn aggressive_nsec3_synthesizes_nodata_from_cache() {
        /** @brief 요약값을 이름에 쓰는 표기로. */
        fn b32hex(data: &[u8]) -> String {
            /** @brief 표기에 쓰는 문자표. */
            const A: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
            let (mut acc, mut bits, mut out) = (0u64, 0u32, String::new());
            for &b in data {
                acc = (acc << 8) | b as u64;
                bits += 8;
                while bits >= 5 {
                    bits -= 5;
                    out.push(A[((acc >> bits) & 0x1f) as usize] as char);
                }
            }
            if bits > 0 {
                out.push(A[((acc << (5 - bits)) & 0x1f) as usize] as char);
            }
            out
        }

        /** @brief 정해진 응답을 내는 테스트용 리졸버. */
        struct Fixed {
            /** @brief 돌려줄 응답. */
            resp: Message,
            /** @brief 불린 횟수. */
            calls: AtomicU32,
        }
        impl Resolver for Fixed {
            /** @brief 정해진 응답을 돌려준다. */
            fn resolve(&self, req: &Message) -> Option<Message> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let mut m = self.resp.clone();
                m.header.id = req.header.id;
                Some(m)
            }
        }

        let qname = Name::from_str("x.example").unwrap();
        let h = onetdns_dnssec::nsec3_hash(&qname, b"", 0);
        let owner = Name::from_str(&format!("{}.example", b32hex(&h))).unwrap();
        let mut rd = vec![1u8, 0u8];
        rd.extend_from_slice(&0u16.to_be_bytes());
        rd.push(0);
        rd.push(20);
        rd.extend_from_slice(&[0u8; 20]);
        rd.extend_from_slice(&[0u8, 6, 0x40, 0, 0, 0, 0, 0x02]);
        let nsec3 = Record::new(owner, 3600, RData::Unknown(50, rd));
        assert_eq!(nsec3.rtype, RecordType::NSEC3);

        let mut resp = answer_message(1, qname.clone(), RecordType::AAAA, vec![]);
        resp.header.rcode = ResponseCode::NoError.0;
        resp.header.authentic_data = true;
        resp.authorities = with_rrsigs(vec![soa_record("example"), nsec3]);

        let inner = Arc::new(Fixed {
            resp,
            calls: AtomicU32::new(0),
        });
        let layer = AggressiveNsecLayer::new(inner.clone() as Arc<dyn Resolver>, 16, 0, 86_400);

        let q = query("x.example", RecordType::AAAA);
        let r1 = layer.resolve(&q).unwrap();
        assert_eq!(r1.header.rcode, ResponseCode::NoError.0);
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            1,
            "첫 질의는 업스트림 해석"
        );

        let mut dnssec_query = q.clone();
        dnssec_query.additionals.push(
            Edns {
                dnssec_ok: true,
                ..Default::default()
            }
            .try_to_record()
            .unwrap(),
        );
        let r2 = layer.resolve(&dnssec_query).unwrap();
        assert_eq!(r2.header.rcode, ResponseCode::NoError.0);
        assert!(r2.header.authentic_data, "합성 응답 AD=1");
        assert!(
            r2.authorities.iter().any(|r| r.rtype == RecordType::NSEC3),
            "합성 응답에 NSEC3 부재증명"
        );
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            1,
            "NSEC3 aggressive 합성 → 업스트림 미호출"
        );
    }

    #[test]
    /** @brief 감추기 설정이 바뀌면 이전 증명을 버리는지. 섞이면 없는 것을 있다고 하거나 그 반대가 된다. */
    fn aggressive_nsec3_rollover_discards_previous_parameters() {
        let layer = AggressiveNsecLayer::new(Mock::new(1, 0), 16, 0, 86_400);
        let response = |salt: &[u8]| {
            let mut message = answer_message(
                1,
                Name::from_str("x.example").unwrap(),
                RecordType::AAAA,
                vec![],
            );
            message.header.rcode = ResponseCode::NoError.0;
            message.header.authentic_data = true;
            message.authorities = with_rrsigs(vec![
                soa_record("example"),
                nsec3_nodata_record("x.example", "example", salt),
            ]);
            message
        };

        layer.maybe_cache(&response(&[]));
        layer.maybe_cache(&response(&[1]));

        {
            let mut store = layer.store.lock_recover();
            let zone = store
                .zones
                .get(&(
                    Name::from_str("example").unwrap().canonical_key(),
                    DnsClass::IN.0,
                ))
                .unwrap();
            let nsec3: Vec<onetdns_dnssec::Nsec3> = zone
                .records
                .values()
                .filter_map(|(record, _)| onetdns_dnssec::Nsec3::from_record(record))
                .collect();
            assert_eq!(nsec3.len(), 1);
            assert_eq!(nsec3[0].salt, vec![1]);
            assert_eq!(store.records, 4);
        }

        let synthesized = layer
            .try_synthesize(&query("x.example", RecordType::AAAA))
            .expect("current NSEC3 generation remains synthesizable");
        assert_eq!(synthesized.header.rcode, ResponseCode::NoError.0);
    }

    #[test]
    /** @brief 감춘 형태의 증명으로 없다는 답을 만드는지. */
    fn aggressive_nsec3_synthesizes_nxdomain_from_cache() {
        /** @brief 요약값을 이름에 쓰는 표기로. */
        fn b32hex(data: &[u8]) -> String {
            /** @brief 표기에 쓰는 문자표. */
            const A: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
            let (mut acc, mut bits, mut out) = (0u64, 0u32, String::new());
            for &b in data {
                acc = (acc << 8) | b as u64;
                bits += 8;
                while bits >= 5 {
                    bits -= 5;
                    out.push(A[((acc >> bits) & 0x1f) as usize] as char);
                }
            }
            if bits > 0 {
                out.push(A[((acc << (5 - bits)) & 0x1f) as usize] as char);
            }
            out
        }

        /** @brief 감춘 형태의 테스트용 증명 기록. */
        fn nsec3(owner_hash: &[u8], next: [u8; 20]) -> Record {
            let owner = Name::from_str(&format!("{}.example", b32hex(owner_hash))).unwrap();
            let mut rd = vec![1u8, 0u8];
            rd.extend_from_slice(&0u16.to_be_bytes());
            rd.push(0);
            rd.push(20);
            rd.extend_from_slice(&next);

            Record::new(owner, 3600, RData::Unknown(50, rd))
        }

        /** @brief 정해진 응답을 내는 테스트용 리졸버. */
        struct Fixed {
            /** @brief 돌려줄 응답. */
            resp: Message,
            /** @brief 불린 횟수. */
            calls: AtomicU32,
        }
        impl Resolver for Fixed {
            /** @brief 정해진 응답을 돌려준다. */
            fn resolve(&self, req: &Message) -> Option<Message> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let mut m = self.resp.clone();
                m.header.id = req.header.id;
                Some(m)
            }
        }

        let h_ce = onetdns_dnssec::nsec3_hash(&Name::from_str("example").unwrap(), b"", 0);
        let ce = nsec3(&h_ce, [0xff; 20]);
        let wide = nsec3(&[0u8; 20], [0xff; 20]);
        let mut denial = vec![soa_record("example"), ce, wide];
        for index in 1..=6 {
            denial.push(nsec3(&[index; 20], [index + 1; 20]));
        }

        let qname = Name::from_str("nx.example").unwrap();
        let mut resp = answer_message(1, qname.clone(), RecordType::A, vec![]);
        resp.header.rcode = ResponseCode::NXDomain.0;
        resp.header.authentic_data = true;
        resp.authorities = with_rrsigs(denial);

        let inner = Arc::new(Fixed {
            resp,
            calls: AtomicU32::new(0),
        });
        let layer = AggressiveNsecLayer::new(inner.clone() as Arc<dyn Resolver>, 64, 0, 86_400);

        let q = query("nx.example", RecordType::A);
        let r1 = layer.resolve(&q).unwrap();
        assert_eq!(r1.header.rcode, ResponseCode::NXDomain.0);
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            1,
            "첫 질의는 업스트림 해석"
        );
        assert!(
            layer.store.lock_recover().records > 16,
            "fixture must cross the former synthesis cliff"
        );

        let mut dnssec_query = q.clone();
        dnssec_query.additionals.push(
            Edns {
                dnssec_ok: true,
                ..Default::default()
            }
            .try_to_record()
            .unwrap(),
        );
        let r2 = layer.resolve(&dnssec_query).unwrap();
        assert_eq!(
            r2.header.rcode,
            ResponseCode::NXDomain.0,
            "캐시 NSEC3로 NXDOMAIN 합성"
        );
        assert!(r2.header.authentic_data, "합성 응답 AD=1");
        assert!(r2
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::NSEC3));
        assert!(r2
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::RRSIG));
        assert!(
            r2.authorities.len() <= 6,
            "관련 없는 NSEC3를 합성 응답에 복사하면 안 됨: {}",
            r2.authorities.len()
        );
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            1,
            "NSEC3 NXDOMAIN 합성 → 업스트림 미호출"
        );
    }

    #[test]
    /** @brief 이름별 질의 수가 상한을 넘지 못하는지. */
    fn name_ratelimit_caps_cache_miss_per_name() {
        let inner = Mock::new(7, 0);

        let layer = NameRateLimitLayer::new(inner.clone() as Arc<dyn Resolver>, 3, 2);
        let mut ok = 0;
        let mut limited = 0;
        for i in 0..10 {
            let name = format!("r{i}.victim.com");
            let r = layer.resolve(&query(&name, RecordType::A)).unwrap();
            if r.header.rcode == ResponseCode::ServFail.0 {
                limited += 1;
            } else {
                ok += 1;
            }
        }
        assert_eq!(ok, 3, "한도 3개만 통과");
        assert_eq!(limited, 7, "초과분은 SERVFAIL");
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            3,
            "초과분은 업스트림 미호출"
        );

        let r = layer.resolve(&query("a.other.com", RecordType::A)).unwrap();
        assert_ne!(r.header.rcode, ResponseCode::ServFail.0);
    }

    #[test]
    /** @brief 캐시가 맞은 것도 세는지. 세지 않으면 담긴 이름으로는 얼마든지 퍼부을 수 있다. */
    fn name_ratelimit_includes_response_cache_hits() {
        let inner = Mock::new(7, 0);
        let cache = crate::cache::CacheLayer::new(
            inner.clone() as Arc<dyn Resolver>,
            8,
            1,
            0,
            3_600,
            0,
            3_600,
        );
        let layer = NameRateLimitLayer::new(Arc::new(cache), 1, 2);
        let mut limited = 0;
        for _ in 0..4 {
            let response = layer
                .resolve(&query("hot.victim.example", RecordType::A))
                .unwrap();
            limited += usize::from(response.header.rcode == ResponseCode::ServFail.0);
        }
        assert!(
            limited >= 2,
            "초 경계가 한 번 끼어도 캐시 히트가 이름 제한을 우회하면 안 됨"
        );
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            1,
            "허용된 후속 질의는 응답 캐시에서 처리"
        );
    }

    #[test]
    /** @brief 슬롯이 다 차도 이미 세고 있던 이름이 밀려나지 않는지. */
    fn name_ratelimit_full_window_rejects_new_keys_without_dropping_existing_keys() {
        let inner = Mock::new(1, ResponseCode::NoError.0);
        let mut layer = NameRateLimitLayer::new(inner, 2, 2);
        layer.cap = 2;
        let a = Name::from_str("a.example").unwrap();
        let b = Name::from_str("b.example").unwrap();
        let c = Name::from_str("c.example").unwrap();

        assert!(layer.allow(&a));
        assert!(layer.allow(&b));
        assert!(!layer.allow(&c), "포화된 현재 구간의 새 키는 즉시 거부");
        assert!(layer.allow(&a), "이미 추적 중인 키의 남은 예산은 유지");
        assert_eq!(layer.buckets.lock_recover().counts.len(), 2);
    }

    #[test]
    /** @brief 담아 둘 때 이름의 원래 바이트가 바뀌지 않는지. */
    fn below_nxdomain_cache_preserves_raw_name_octets() {
        let layer = BelowNxdomainLayer::new(Mock::new(1, ResponseCode::NoError.0), 16, 0, 86_400);
        let first = Name::from_labels(vec![vec![0xff]]).unwrap();
        let second = Name::from_labels(vec![vec![0xfe]]).unwrap();
        layer.nx.lock_recover().put(
            BelowNxdomainLayer::cache_key(&first, DnsClass::IN),
            BelowNxEntry {
                expiry: Instant::now() + Duration::from_secs(60),
                proof: Arc::from(vec![soa_record("example")]),
            },
        );

        let first_child = Name::from_labels(vec![b"child".to_vec(), vec![0xff]]).unwrap();
        let second_child = Name::from_labels(vec![b"child".to_vec(), vec![0xfe]]).unwrap();
        assert!(layer.ancestor_nx(&first_child, DnsClass::IN).is_some());
        assert!(layer.ancestor_nx(&first_child, DnsClass(3)).is_none());
        assert!(layer.ancestor_nx(&second_child, DnsClass::IN).is_none());
        assert_ne!(first.canonical_key(), second.canonical_key());
    }

    #[test]
    /** @brief 없는 이름 아래를 밖에 묻지 않고 답하는지. */
    fn below_nxdomain_synthesizes_descendants() {
        /** @brief 없다고 답하며 호출 수를 세는 테스트용 리졸버. */
        struct NxThenCount {
            /** @brief 불린 횟수. */
            calls: AtomicU32,
        }
        impl Resolver for NxThenCount {
            /** @brief 없다고 답하고 호출을 센다. */
            fn resolve(&self, req: &Message) -> Option<Message> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let q = req.questions.first().unwrap();
                let mut m = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);

                let qn = q.name.to_ascii_lower();
                if qn == "gone.example" || qn.ends_with(".gone.example") {
                    m.header.rcode = ResponseCode::NXDomain.0;

                    m.header.authentic_data = true;
                    m.authorities = with_rrsigs(vec![
                        soa_record("example"),
                        nsec_record("example", "a.example", &[6, 46, 47]),
                        nsec_record("a.example", "z.example", &[6, 46, 47]),
                    ]);
                }
                Some(m)
            }
        }
        let inner = Arc::new(NxThenCount {
            calls: AtomicU32::new(0),
        });
        let layer = BelowNxdomainLayer::new(inner.clone() as Arc<dyn Resolver>, 1024, 0, 86_400);

        let r = layer
            .resolve(&query("gone.example", RecordType::A))
            .unwrap();
        assert_eq!(r.header.rcode, ResponseCode::NXDomain.0);
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);

        let mut descendant = query("deep.sub.gone.example", RecordType::AAAA);
        descendant.additionals.push(
            Edns {
                dnssec_ok: true,
                ..Default::default()
            }
            .try_to_record()
            .unwrap(),
        );
        let r = layer.resolve(&descendant).unwrap();
        assert_eq!(r.header.rcode, ResponseCode::NXDomain.0);
        assert!(
            r.authorities
                .iter()
                .any(|record| record.rtype == RecordType::NSEC),
            "DO=1인 below-NXDOMAIN 응답은 원래 NSEC proof를 반환해야 함"
        );
        assert!(
            r.authorities
                .iter()
                .any(|record| record.rtype == RecordType::RRSIG),
            "DO=1인 below-NXDOMAIN 응답은 proof 서명도 반환해야 함"
        );
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            1,
            "하위 질의는 업스트림 미호출"
        );

        let r = layer
            .resolve(&query("other.gone.example", RecordType::A))
            .unwrap();
        assert_eq!(r.header.rcode, ResponseCode::NXDomain.0);
        assert_eq!(r.authorities.len(), 1, "DO=0이면 SOA만 반환");
        assert_eq!(r.authorities[0].rtype, RecordType::SOA);
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);

        let r = layer
            .resolve(&query("live.example", RecordType::A))
            .unwrap();
        assert_eq!(r.header.rcode, ResponseCode::NoError.0);
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    /**
     * @brief DO 없이 묻는 클라이언트에게서도 부재 증명을 배우는지.
     * @details 해석 백엔드는 DO가 없는 요청의 답에서 NSEC과 RRSIG를 걷어낸다. 계층이 받은 요청
     *          그대로 물으면 대부분의 클라이언트에게서는 배울 증명이 없다.
     */
    fn below_nxdomain_learns_from_clients_without_do() {
        /** @brief 백엔드처럼 DO가 없는 요청의 답에서 DNSSEC 레코드를 걷어내는 리졸버. */
        struct StrippingBackend {
            /** @brief 불린 횟수. */
            calls: AtomicU32,
        }
        impl Resolver for StrippingBackend {
            /** @brief 서명된 NXDOMAIN을 만들고 요청대로 걷어낸다. */
            fn resolve(&self, req: &Message) -> Option<Message> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let q = req.questions.first().unwrap();
                let mut m = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
                m.header.rcode = ResponseCode::NXDomain.0;
                m.header.authentic_data = true;
                m.authorities = with_rrsigs(vec![
                    soa_record("example"),
                    nsec_record("example", "a.example", &[6, 46, 47]),
                    nsec_record("a.example", "z.example", &[6, 46, 47]),
                ]);
                crate::native::strip_dnssec_unless_requested(req, &mut m);
                Some(m)
            }
        }
        let inner = Arc::new(StrippingBackend {
            calls: AtomicU32::new(0),
        });
        let layer = BelowNxdomainLayer::new(inner.clone() as Arc<dyn Resolver>, 1024, 0, 86_400);

        let r = layer
            .resolve(&query("gone.example", RecordType::A))
            .unwrap();
        assert!(
            r.authorities
                .iter()
                .all(|record| record.rtype == RecordType::SOA),
            "DO가 없던 클라이언트에게는 증명을 내보내지 않는다"
        );
        layer
            .resolve(&query("deep.gone.example", RecordType::A))
            .unwrap();
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            1,
            "DO 없는 첫 질의에서 배운 증명으로 하위 이름에 답해야 한다"
        );
    }

    #[test]
    /** @brief 별칭 끝의 이름을 기준으로 담는지. */
    fn below_nxdomain_caches_the_terminal_alias_target() {
        /** @brief 별칭 뒤에 없다고 답하는 테스트용 리졸버. */
        struct AliasNx {
            /** @brief 불린 횟수. */
            calls: AtomicU32,
        }
        impl Resolver for AliasNx {
            /** @brief 별칭 체인 끝에서 없다고 답한다. */
            fn resolve(&self, req: &Message) -> Option<Message> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let q = req.questions.first()?;
                let mut response = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
                if q.name
                    .eq_ignore_case(&Name::from_str("alias.example").unwrap())
                {
                    response.header.rcode = ResponseCode::NXDomain.0;
                    response.header.authentic_data = true;
                    response.answers = with_rrsigs(vec![Record::new(
                        q.name.clone(),
                        3600,
                        RData::Cname(Name::from_str("missing.example").unwrap()),
                    )]);
                    response.authorities = with_rrsigs(vec![
                        soa_record("example"),
                        nsec_record("example", "a.example", &[6, 46, 47]),
                        nsec_record("a.example", "z.example", &[6, 46, 47]),
                    ]);
                }
                Some(response)
            }
        }

        let inner = Arc::new(AliasNx {
            calls: AtomicU32::new(0),
        });
        let layer = BelowNxdomainLayer::new(inner.clone(), 16, 0, 86_400);
        assert_eq!(
            layer
                .resolve(&query("alias.example", RecordType::A))
                .unwrap()
                .header
                .rcode,
            ResponseCode::NXDomain.0
        );

        assert_eq!(
            layer
                .resolve(&query("child.alias.example", RecordType::A))
                .unwrap()
                .header
                .rcode,
            ResponseCode::NoError.0,
            "CNAME owner가 아니라 alias chain의 마지막 denied name에 cut을 저장해야 함"
        );
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);

        assert_eq!(
            layer
                .resolve(&query("child.missing.example", RecordType::AAAA))
                .unwrap()
                .header
                .rcode,
            ResponseCode::NXDomain.0
        );
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            2,
            "denied alias target의 하위 이름은 캐시에서 응답"
        );
    }

    #[test]
    /** @brief 설정한 부정 수명 상하한을 지키는지. */
    fn below_nxdomain_honors_configured_negative_ttl_bounds() {
        /** @brief 수명이 짧은 부정 응답을 내는 테스트용 리졸버. */
        struct ShortNx;
        impl Resolver for ShortNx {
            /** @brief 수명이 짧은 부정 응답을 돌려준다. */
            fn resolve(&self, req: &Message) -> Option<Message> {
                let q = req.questions.first()?;
                let mut message = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
                message.header.rcode = ResponseCode::NXDomain.0;
                message.header.authentic_data = true;
                let mut soa = soa_record("example");
                let RData::Soa(data) = &mut soa.rdata else {
                    unreachable!();
                };
                data.minimum = 2;
                message.authorities = with_rrsigs(vec![
                    soa,
                    nsec_record("example", "a.example", &[6, 46, 47]),
                    nsec_record("a.example", "z.example", &[6, 46, 47]),
                ]);
                Some(message)
            }
        }

        let layer = BelowNxdomainLayer::new(Arc::new(ShortNx), 16, 5, 5);
        layer.resolve(&query("gone.example", RecordType::A));

        let mut cache = layer.nx.lock_recover();
        let entry = cache
            .get(&BelowNxdomainLayer::cache_key(
                &Name::from_str("gone.example").unwrap(),
                DnsClass::IN,
            ))
            .expect("below-NXDOMAIN 저장");
        assert_eq!(
            entry
                .proof
                .iter()
                .find(|record| record.rtype == RecordType::SOA)
                .unwrap()
                .ttl,
            5
        );
        assert!(entry.expiry <= Instant::now() + Duration::from_secs(5));
    }

    #[test]
    /** @brief 수명이 0인 권한 기록을 담지 않는지. */
    fn below_nxdomain_never_caches_zero_ttl_soa() {
        /** @brief 수명이 0인 부정 응답을 내는 테스트용 리졸버. */
        struct ZeroTtlNx {
            /** @brief 불린 횟수. */
            calls: AtomicU32,
        }
        impl Resolver for ZeroTtlNx {
            /** @brief 수명이 0인 부정 응답을 돌려준다. */
            fn resolve(&self, req: &Message) -> Option<Message> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let q = req.questions.first().unwrap();
                let mut message = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
                message.header.rcode = ResponseCode::NXDomain.0;
                message.header.authentic_data = true;
                let mut soa = soa_record("example");
                soa.ttl = 0;
                message.authorities = with_rrsigs(vec![
                    soa,
                    nsec_record("example", "a.example", &[6, 46, 47]),
                    nsec_record("a.example", "z.example", &[6, 46, 47]),
                ]);
                Some(message)
            }
        }

        let inner = Arc::new(ZeroTtlNx {
            calls: AtomicU32::new(0),
        });
        let layer = BelowNxdomainLayer::new(inner.clone() as Arc<dyn Resolver>, 16, 0, 86_400);
        layer.resolve(&query("gone.example", RecordType::A));
        layer.resolve(&query("child.gone.example", RecordType::AAAA));

        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
        assert!(layer.nx.lock_recover().is_empty());
    }

    #[test]
    /** @brief 임의로 만든 답에 그대로 담을 수 있는 증명만 쓰는지. 아니면 검증하는 클라이언트가 거부한다. */
    fn below_nxdomain_requires_replayable_signed_proof() {
        let denied_name = Name::from_str("gone.example").unwrap();
        let mut response = answer_message(1, denied_name.clone(), RecordType::A, vec![]);
        response.header.rcode = ResponseCode::NXDomain.0;
        response.header.authentic_data = true;
        response.authorities = with_rrsigs(vec![soa_record("example")]);

        assert!(
            BelowNxdomainLayer::authenticated_proof(&response, &denied_name, DnsClass::IN)
                .is_none()
        );
    }

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

    /** @brief 이름 공간을 지정한 테스트용 외부 캐시 계층. */
    fn cachedb_with_namespace(namespace: &str) -> CacheDbLayer {
        CacheDbLayer::new(
            EmptyMock::new(false) as Arc<dyn Resolver>,
            Arc::new(crate::redis::RedisClient::new(std::net::SocketAddr::from(
                ([127, 0, 0, 1], 1),
            ))),
            60,
            0,
            3600,
            namespace.to_string(),
        )
    }

    #[test]
    /** @brief 같은 뜻의 질의가 같은 키를 갖는지. */
    fn cachedb_key_normalizes() {
        let layer = cachedb_with_namespace("ns");
        let upper = layer.key(&query("Example.COM", RecordType::A)).unwrap();
        let lower = layer.key(&query("example.com", RecordType::A)).unwrap();
        assert_eq!(upper, lower, "0x20 대소문자는 동일 키로 정규화되어야 함");
        assert!(upper.starts_with(b"onetdns:v2:ns:"));
        let aaaa = layer.key(&query("example.com", RecordType::AAAA)).unwrap();
        assert_ne!(lower, aaaa, "qtype가 다르면 키가 분리되어야 함");
    }

    #[test]
    /** @brief 해석 맥락이 다르면 키도 다른지. 같으면 다른 설정의 답을 이 서버가 쓴다. */
    fn cachedb_key_separates_resolution_contexts() {
        let request = query("example.com", RecordType::A);
        let default_chain = cachedb_with_namespace("recurse-dnssec")
            .key(&request)
            .unwrap();
        let route_chain = cachedb_with_namespace("route-work").key(&request).unwrap();
        let plain_forward = cachedb_with_namespace("forward").key(&request).unwrap();
        assert_ne!(default_chain, route_chain, "클라이언트 라우트는 분리");
        assert_ne!(default_chain, plain_forward, "백엔드·검증 정책은 분리");
    }

    #[test]
    /** @brief 질문과 맞고 온전한 긍정 응답만 받아들이는지. */
    fn cachedb_accepts_only_matching_complete_positive_envelopes() {
        let request = query("cache.example", RecordType::A);
        let q = request.questions[0].clone();
        let mut response = answer_message(
            request.header.id,
            q.name.clone(),
            q.qtype,
            vec![Record::new(
                q.name.clone(),
                300,
                RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            )],
        );
        assert!(!response_not_cacheable(&request, &response));

        response.header.response = false;
        assert!(response_not_cacheable(&request, &response));
        response.header.response = true;
        response.header.truncated = true;
        assert!(response_not_cacheable(&request, &response));
        response.header.truncated = false;
        response.header.rcode = ResponseCode::NXDomain.0;
        assert!(response_not_cacheable(&request, &response));
        response.header.rcode = ResponseCode::NoError.0;
        response.questions[0].qtype = RecordType::AAAA;
        assert!(response_not_cacheable(&request, &response));
        response.questions[0] = q;
        response.answers[0].name = Name::from_str("attacker.example").unwrap();
        assert!(response_not_cacheable(&request, &response));
    }

    #[test]
    /** @brief 앞날로 적힌 시각을 거부하고 구간마다 늙히는지. 안 그러면 남이 수명을 늘릴 수 있다. */
    fn cachedb_rejects_future_timestamp_and_ages_each_section() {
        let request = query("cache.example", RecordType::A);
        let q = request.questions[0].clone();
        let mut response = answer_message(
            request.header.id,
            q.name.clone(),
            q.qtype,
            vec![Record::new(
                q.name,
                100,
                RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            )],
        );
        response.additionals.push(Record::new(
            Name::from_str("ns.cache.example").unwrap(),
            1,
            RData::A(Ipv4Addr::new(192, 0, 2, 53)),
        ));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let wire = response.try_encode().unwrap();

        let mut future = (now + 60).to_be_bytes().to_vec();
        future.extend_from_slice(&wire);
        assert!(CacheDbLayer::decode_value(&future, u32::MAX).is_none());

        let mut aged = now.saturating_sub(2).to_be_bytes().to_vec();
        aged.extend_from_slice(&wire);
        let (decoded, elapsed) = CacheDbLayer::decode_value(&aged, u32::MAX).unwrap();
        assert!(elapsed >= 2);
        assert!(decoded.answers[0].ttl <= 98);
        assert!(decoded.additionals.is_empty());
    }

    #[test]
    /** @brief 현재 최대 TTL이 조회 시점부터 다시 시작되지 않고 삽입 시점부터 적용되는지. */
    fn cachedb_max_ttl_is_an_absolute_age_cap() {
        let request = query("cache.example", RecordType::A);
        let q = request.questions[0].clone();
        let response = answer_message(
            request.header.id,
            q.name.clone(),
            q.qtype,
            vec![Record::new(
                q.name,
                300,
                RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            )],
        );
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut value = now.saturating_sub(2).to_be_bytes().to_vec();
        value.extend_from_slice(&response.try_encode().unwrap());

        let (decoded, elapsed) = CacheDbLayer::decode_value(&value, 5).unwrap();
        let remaining_cap = 5u64.saturating_sub(elapsed) as u32;
        assert!(
            decoded.answers[0].ttl <= remaining_cap,
            "max_ttl은 삽입 뒤 경과 시간만큼 줄어야 합니다: elapsed={elapsed}, ttl={}",
            decoded.answers[0].ttl
        );
    }

    #[test]
    /** @brief 담기엔 너무 큰 응답을 오류로 바꿔 담지 않는지. */
    fn cachedb_does_not_encode_servfail_fallback_for_oversized_value() {
        let request = query("large.cache.example", RecordType::A);
        let q = request.questions[0].clone();
        let response = answer_message(
            request.header.id,
            q.name.clone(),
            q.qtype,
            vec![Record::new(
                q.name,
                300,
                RData::Unknown(65280, vec![0; 65_500]),
            )],
        );
        assert!(CacheDbLayer::encode_value(&response).is_none());
    }

    #[test]
    /** @brief 임대 기록으로 이름과 주소를 서로 답하고, 없으면 넘기는지. */
    fn dhcp_dns_forward_reverse_and_delegate() {
        use crate::dhcp::{ClientIdentity, DhcpConfig, LeasePool};
        let dc = DhcpConfig {
            server_ip: Ipv4Addr::new(192, 168, 1, 1),
            range_start: Ipv4Addr::new(192, 168, 1, 100),
            range_end: Ipv4Addr::new(192, 168, 1, 200),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            router: Ipv4Addr::new(192, 168, 1, 1),
            dns: vec![Ipv4Addr::new(192, 168, 1, 1)],
            lease_secs: 3600,
            tftp_server: None,
            boot_file: None,
            domain_name: None,
            lease_file: None,
            static_file: None,
        };
        let mut pool = LeasePool::new(&dc);
        let first_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        pool.commit(
            &ClientIdentity::Hardware(first_mac),
            first_mac,
            u32::from(Ipv4Addr::new(192, 168, 1, 123)),
            Some("myhost".to_string()),
        );
        let second_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xfe];
        pool.commit(
            &ClientIdentity::Hardware(second_mac),
            second_mac,
            u32::from(Ipv4Addr::new(192, 168, 1, 124)),
            Some("�".to_string()),
        );
        let pool = Arc::new(Mutex::new(pool));
        let inner = Mock::new(9, 0);
        let local_ttl = Arc::new(AtomicU32::new(17));
        let layer = DhcpDnsLayer::new(
            inner.clone() as Arc<dyn Resolver>,
            pool,
            "lan",
            local_ttl.clone(),
        );

        let r = layer.resolve(&query("MyHost.LAN", RecordType::A)).unwrap();
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.answers[0].ttl, 17);
        match &r.answers[0].rdata {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(192, 168, 1, 123)),
            other => panic!("A 레코드를 예상했지만 실제 값은 {other:?}입니다"),
        }

        let raw_name = Name::from_labels(vec![vec![0xff], b"lan".to_vec()]).unwrap();
        let raw_query = Message::query(2, raw_name, RecordType::A);
        let raw_response = layer.resolve(&raw_query).unwrap();
        assert_eq!(first_a(&raw_response), Ipv4Addr::new(9, 9, 9, 9));

        let before = inner.calls.load(Ordering::SeqCst);
        let r = layer
            .resolve(&query("myhost.lan", RecordType::AAAA))
            .unwrap();
        assert!(r.answers.is_empty());
        assert_eq!(inner.calls.load(Ordering::SeqCst), before, "AAAA 미위임");

        let r = layer
            .resolve(&query("123.1.168.192.in-addr.arpa", RecordType::PTR))
            .unwrap();
        assert_eq!(r.answers.len(), 1);
        match &r.answers[0].rdata {
            RData::Ptr(n) => assert_eq!(n.to_ascii_lower().trim_end_matches('.'), "myhost.lan"),
            other => panic!("PTR 기대, got {other:?}"),
        }
        assert_eq!(r.answers[0].ttl, 17);
        local_ttl.store(23, Ordering::Release);
        assert_eq!(
            layer
                .resolve(&query("myhost.lan", RecordType::A))
                .unwrap()
                .answers[0]
                .ttl,
            23,
            "DHCP DNS도 로컬 TTL 핫 변경을 공유"
        );
        local_ttl.store(u32::MAX, Ordering::Release);
        let lease_bounded = layer
            .resolve(&query("myhost.lan", RecordType::A))
            .unwrap()
            .answers[0]
            .ttl;
        assert!(
            (1..=3_600).contains(&lease_bounded),
            "DNS TTL이 남은 DHCP 임대를 넘으면 안 됨: {lease_bounded}"
        );
        local_ttl.store(0, Ordering::Release);
        assert_eq!(
            layer
                .resolve(&query("myhost.lan", RecordType::A))
                .unwrap()
                .answers[0]
                .ttl,
            0,
            "명시한 TTL 0은 현재 응답 전용으로 보존"
        );

        let before = inner.calls.load(Ordering::SeqCst);
        let _ = layer.resolve(&query("other.lan", RecordType::A));
        let _ = layer.resolve(&query("example.com", RecordType::A));
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            before + 2,
            "미지 이름은 위임"
        );
    }
}
