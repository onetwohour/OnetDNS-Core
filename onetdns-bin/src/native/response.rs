/*!
 * @brief 응답 조립과 후처리. EDNS와 EDE를 붙이고, DNS64 합성, 사설 주소 제거, 차단 응답을 만든다.
 */

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use onetdns_control::Action;
use onetdns_core::{BlockResponse, ClientInfo, FilterEngine, FilterVerdict, IpNet, RewriteTarget};
use onetdns_filter::BlockEngine;
use onetdns_proto::{
    DnsClass, Edns, Message, Name as ApName, ProtoError, RData as ApRData, Record as ApRecord,
    RecordType as ApRt, ResponseCode,
};
use onetdns_runtime::{RequestCtx, Transport as RtTransport};

use crate::native::query::{base_edns, RuleMatch};
use crate::native::{NativeFeatures, NativeServer};

impl NativeServer {
    /** @brief 답을 바꾼 것을 기록에 남긴다. */
    pub(crate) fn rec_rewrite_response<'r>(
        &self,
        client: &ClientInfo,
        name: &ApName,
        qtype: ApRt,
        response: &Message,
        rule: impl Into<RuleMatch<'r>>,
    ) {
        let rcode = ResponseCode(response.header.rcode);
        if rcode == ResponseCode::ServFail {
            self.rec_failure(
                client,
                Some(name),
                Some(qtype),
                "REWRITE_TARGET_RESOLUTION_FAILED",
                "rewrite",
                "Resolving the rewrite target did not produce a valid response",
            );
        } else if rcode == ResponseCode::Refused {
            self.rec_rc(client, Action::Refused, Some(name), Some(qtype), rcode);
        } else {
            let answers = answers_summary(&response.answers);
            self.rec_rc_diag(
                client,
                Action::Rewritten,
                Some(name),
                Some(qtype),
                rcode,
                &answers,
                "",
                rule,
            );
        }
    }

    /** @brief 별칭 체인에 차단 대상이 숨어 있는지 본다. 끝만 보면 별칭 뒤에 숨겨 지나갈 수 있다. */
    pub(crate) fn cname_uncloak(
        engine: &BlockEngine,
        answers: &[ApRecord],
        client: &ClientInfo,
    ) -> Option<BlockResponse> {
        for rec in answers {
            if let ApRData::Cname(cn) = &rec.rdata {
                if let FilterVerdict::Block(br) = engine.verdict(cn, ApRt::CNAME, client) {
                    return Some(br);
                }
            }
        }
        None
    }

    /** @brief 답에 담긴 주소가 차단 대상인지 본다. */
    pub(crate) fn rpz_ip_check(
        engine: &BlockEngine,
        answers: &[ApRecord],
    ) -> Option<FilterVerdict> {
        if !engine.has_rpz_ip() {
            return None;
        }
        for rec in answers {
            let ip = match &rec.rdata {
                ApRData::A(a) => IpAddr::V4(*a),
                ApRData::Aaaa(a) => IpAddr::V6(*a),
                _ => continue,
            };
            if let Some(v) = engine.rpz_ip_verdict(ip) {
                return Some(v.clone());
            }
        }
        None
    }

    /** @brief 차단·재작성 판정대로 응답을 바꾼다. */
    pub(crate) fn rewrite_resp(
        &self,
        request: &Message,
        qname: &ApName,
        qtype: ApRt,
        target: RewriteTarget,
        client: &ClientInfo,
    ) -> Message {
        let ttl = self.local_ttl.load(Ordering::Acquire);
        match target {
            RewriteTarget::Records(rdatas) => {
                let recs: Vec<ApRecord> = rdatas
                    .into_iter()
                    .filter(|rd| rd.record_type() == qtype)
                    .map(|rd| ApRecord::new(qname.clone(), ttl, rd))
                    .collect();
                records_resp(request, recs)
            }
            RewriteTarget::Cname(target_name) => {
                let cname = ApRecord::new(qname.clone(), ttl, ApRData::Cname(target_name.clone()));
                let mut recs = vec![cname];
                if qtype != ApRt::CNAME {
                    let mut sub = request.clone();
                    if let Some(question) = sub.questions.first_mut() {
                        question.name = target_name.clone();
                        question.qtype = qtype;
                    }
                    let Some(ans) = self.resolve_message_for(&sub, client) else {
                        return error_resp(request, ResponseCode::ServFail);
                    };
                    if ans.header.rcode != ResponseCode::NoError.0
                        || !response_has_requested_answer(&sub, &ans)
                    {
                        return error_resp(request, ResponseCode::ServFail);
                    }
                    recs.extend(ans.answers);
                }
                records_resp(request, recs)
            }
        }
    }
}

/**
 * @brief 클라이언트가 보낸 ECS 옵션을 응답에 그대로 돌려줄 형태로 만든다.
 *
 * @details RFC 7871은 FAMILY, SOURCE PREFIX-LENGTH, ADDRESS 를 질의의 것과 같게
 *          하라고 한다. SCOPE 는 0 으로 둔다. 이 서버는 설정된 고정 대역으로 업스트림에 묻기
 *          때문에 어느 클라이언트에게나 같은 답이 나가고, 0 이 아닌 값을 적으면 하류가
 *          그 대역 전용 답으로 잘못 담는다.
 * @param raw 질의에 실려 온 옵션 바이트.
 * @return 그대로 돌려줄 바이트. 앞 4바이트가 없거나 주소가 SOURCE 를 덮지 못하면 없음.
 */
fn echoed_client_subnet(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() < 4 {
        return None;
    }
    let source = raw[2];
    if usize::from(source).div_ceil(8) != raw.len() - 4 {
        return None;
    }
    let mut echo = raw.to_vec();
    echo[3] = 0;
    Some(echo)
}

/** @brief 내보내기 전에 응답을 다듬는다. */
pub(crate) fn postprocess(
    f: &NativeFeatures,
    msg: &mut Message,
    request: &Message,
    ctx: &RequestCtx,
) -> Result<(), ProtoError> {
    if f.minimal_responses && msg.header.rcode == ResponseCode::NoError.0 && !msg.answers.is_empty()
    {
        msg.authorities.clear();
        msg.additionals
            .retain(|r| r.rtype == onetdns_proto::RecordType::OPT);
    }
    if let Some(to) = f.tcp_keepalive_100ms {
        let tcp = matches!(ctx.transport, RtTransport::Do53Tcp | RtTransport::DoT);
        let asked = request
            .opt()
            .and_then(Edns::from_record)
            .map(|e| e.has_option(onetdns_proto::EDNS_TCP_KEEPALIVE))
            .unwrap_or(false);
        if tcp && asked {
            msg.set_tcp_keepalive(to)?;
        }
    }

    // RFC 7871: 대역 정보를 쓰는 서버는 클라이언트가 그 옵션을 보냈을 때만, 그러나
    // 보냈으면 반드시 응답에도 담아야 한다. 하류가 전달 리졸버면 이 값으로 자기 캐시의
    // 범위를 정하므로, 없으면 대역별 답을 모두에게 주는 캐시가 된다.
    if f.ecs_in_use {
        if let Some(echo) = request
            .opt()
            .and_then(Edns::from_record)
            .and_then(|e| e.client_subnet().map(<[u8]>::to_vec))
            .and_then(|raw| echoed_client_subnet(&raw))
        {
            msg.set_client_subnet(echo)?;
        }
    }

    if f.padding_block > 0 && request.requested_padding() {
        msg.pad_to(f.padding_block)?;
    }
    Ok(())
}

/** @brief 옵션을 붙여 응답을 마무리한다. */
pub(crate) fn finalize(mut msg: Message, edns: Option<Edns>) -> Message {
    // 요청에 OPT가 없으면 응답에도 없어야 한다. RFC 6891이 그렇게 정한다. 업스트림이나
    // 재귀가 담아 온 OPT를 그대로 흘리면 이 서버가 광고한 적 없는 버퍼 크기와 남의 DO 비트가
    // 클라이언트에 나간다.
    msg.additionals
        .retain(|r| r.rtype != onetdns_proto::RecordType::OPT);
    if let Some(e) = edns {
        msg.additionals.push(
            e.try_to_record()
                .expect("Response EDNS limited internally can always be encoded"),
        );
    }
    msg
}

/** @brief 사유 코드의 문구. */
pub(crate) fn ede_text(code: u16) -> &'static str {
    use onetdns_proto::ede_code as ec;
    match code {
        ec::OTHER => "recursion limit exceeded",
        ec::DNSSEC_BOGUS => "DNSSEC validation failed",
        ec::NO_REACHABLE_AUTHORITY => "no reachable authority",
        ec::NETWORK_ERROR => "network error",
        _ => "",
    }
}

/** @brief 응답에 사유를 붙인다. */
pub(crate) fn with_ede(
    edns: Option<Edns>,
    request: &Message,
    buf: u16,
    code: u16,
    text: &str,
) -> Option<Edns> {
    let mut e = match edns {
        Some(e) => e,
        None if request.opt().is_some() => base_edns(request, buf),
        None => return None,
    };
    e.push_ede(code, text);
    Some(e)
}

/** @brief 기록에 담긴 주소. */
pub(crate) fn rdata_ip(rd: &ApRData) -> Option<IpAddr> {
    match rd {
        ApRData::A(a) => Some(IpAddr::V4(*a)),
        ApRData::Aaaa(a) => Some(IpAddr::V6(*a)),
        _ => None,
    }
}

/** @brief 기록의 주소가 이 대역들에 드는지. */
pub(crate) fn rdata_in_nets(rd: &ApRData, nets: &[IpNet]) -> bool {
    rdata_ip(rd).is_some_and(|ip| nets.iter().any(|n| n.contains(&ip)))
}

/** @brief 지어낼 답에 쓸 부정 수명. */
pub(crate) fn dns64_negative_ttl(response: &Message) -> Option<u32> {
    response.authorities.iter().find_map(|record| {
        if let ApRData::Soa(soa) = &record.rdata {
            Some(record.ttl.min(soa.minimum))
        } else {
            None
        }
    })
}

/** @brief IPv4 주소로 IPv6 주소를 임의로 만든다. IPv6만 되는 망에서 IPv4만 있는 곳에 닿게 하려는 것이다. */
pub(crate) fn synthesize_dns64(
    answers: &[ApRecord],
    prefix: &[u8; 16],
    ttl_cap: Option<u32>,
) -> Vec<ApRecord> {
    answers
        .iter()
        .filter_map(|record| {
            if let ApRData::A(address) = &record.rdata {
                let mut v6 = *prefix;
                v6[12..16].copy_from_slice(&address.octets());
                let ttl = ttl_cap.map_or(record.ttl, |cap| record.ttl.min(cap));
                Some(ApRecord::new(
                    record.name.clone(),
                    ttl,
                    ApRData::Aaaa(Ipv6Addr::from(v6)),
                ))
            } else {
                None
            }
        })
        .collect()
}

/** @brief 기록에 내부망 주소가 담겼는지. */
fn is_private_rdata(rd: &ApRData) -> bool {
    match rd {
        ApRData::A(address) => is_private_v4(*address),
        ApRData::Aaaa(address) => is_private_v6(*address),
        ApRData::Svcb { params, .. } | ApRData::Https { params, .. } => {
            params.iter().any(|(key, value)| match *key {
                4 => {
                    value.len() % 4 != 0
                        || value.chunks_exact(4).any(|bytes| {
                            is_private_v4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
                        })
                }
                6 => {
                    value.len() % 16 != 0
                        || value.chunks_exact(16).any(|bytes| {
                            let mut octets = [0u8; 16];
                            octets.copy_from_slice(bytes);
                            is_private_v6(Ipv6Addr::from(octets))
                        })
                }
                _ => false,
            })
        }
        _ => false,
    }
}

/**
 * @brief 답에서 내부망 주소를 뺀다.
 * @warning 밖의 이름이 이 서버의 내부 주소를 가리키면 브라우저가 그 이름의 권한으로 내부망에
 *          접근한다. 그것을 막는 것이다.
 */
pub(crate) fn strip_private_records(message: &mut Message) -> bool {
    let before = message.answers.len() + message.authorities.len() + message.additionals.len();
    message
        .answers
        .retain(|record| !is_private_rdata(&record.rdata));
    message
        .authorities
        .retain(|record| !is_private_rdata(&record.rdata));
    message
        .additionals
        .retain(|record| !is_private_rdata(&record.rdata));
    before != message.answers.len() + message.authorities.len() + message.additionals.len()
}

/** @brief 밖에 있을 수 없는 IPv4 주소인지. */
fn is_private_v4(ip: Ipv4Addr) -> bool {
    let value = u32::from(ip);
    let in_net = |network: [u8; 4], prefix: u8| {
        let mask = u32::MAX << (32 - prefix);
        value & mask == u32::from(Ipv4Addr::from(network)) & mask
    };
    in_net([0, 0, 0, 0], 8)
        || in_net([10, 0, 0, 0], 8)
        || in_net([100, 64, 0, 0], 10)
        || in_net([127, 0, 0, 0], 8)
        || in_net([169, 254, 0, 0], 16)
        || in_net([172, 16, 0, 0], 12)
        || in_net([192, 0, 0, 0], 24)
        || in_net([192, 0, 2, 0], 24)
        || in_net([192, 88, 99, 0], 24)
        || in_net([192, 168, 0, 0], 16)
        || in_net([198, 18, 0, 0], 15)
        || in_net([198, 51, 100, 0], 24)
        || in_net([203, 0, 113, 0], 24)
        || in_net([224, 0, 0, 0], 4)
        || in_net([240, 0, 0, 0], 4)
}

/** @brief 밖에 있을 수 없는 IPv6 주소인지. */
fn is_private_v6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_private_v4(mapped);
    }
    let octets = ip.octets();
    let seg0 = ip.segments()[0];
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (seg0 & 0xfe00) == 0xfc00
        || (seg0 & 0xffc0) == 0xfe80
        || octets[..4] == [0x20, 0x01, 0x0d, 0xb8]
        || octets[..8] == [0x01, 0x00, 0, 0, 0, 0, 0, 0]
        || octets[..4] == [0x20, 0x01, 0x00, 0x02]
}

/** @brief 재귀로 받은 응답을 클라이언트에 낼 형태로 맞춘다. */
pub(crate) fn normalize_recursive_response(response: &mut Message, request: &Message) {
    response.header.id = request.header.id;
    response.header.response = true;
    response.header.opcode = request.header.opcode;
    response.header.recursion_desired = request.header.recursion_desired;
    response.header.recursion_available = true;
    response.header.checking_disabled = request.header.checking_disabled;
    let same_questions = response.questions.len() == request.questions.len()
        && response
            .questions
            .iter()
            .zip(&request.questions)
            .all(|(response, request)| {
                response.name == request.name
                    && response.qtype == request.qtype
                    && response.qclass == request.qclass
            });
    if !same_questions {
        response.questions.clone_from(&request.questions);
    }
}

/** @brief 없다는 것을 뒷받침하는 권한 기록이 실렸는지. */
pub(crate) fn has_negative_soa(response: &Message) -> bool {
    response
        .authorities
        .iter()
        .any(|record| record.rtype == ApRt::SOA)
}

/** @brief 답에 별칭이 실렸는지. */
pub(crate) fn has_alias_answer(response: &Message) -> bool {
    response
        .answers
        .iter()
        .any(|record| matches!(&record.rdata, ApRData::Cname(_) | ApRData::Dname(_)))
}

/** @brief 다른 서버로 가라는 응답인지. */
pub(crate) fn is_delegation_referral(response: &Message) -> bool {
    !response.header.authoritative
        && response.answers.is_empty()
        && response
            .authorities
            .iter()
            .any(|record| record.rtype == ApRt::NS)
}

/** @brief 기록에 남길 답 요약. */
pub(crate) fn answers_summary(answers: &[ApRecord]) -> String {
    /** @brief 요약에 담을 항목 수. */
    const MAX: usize = 5;
    let mut parts: Vec<String> = answers
        .iter()
        .take(MAX)
        .map(|record| {
            let value = rdata_brief(&record.rdata);
            if value.is_empty() {
                record.rtype.name().to_string()
            } else {
                format!("{} {value}", record.rtype.name())
            }
        })
        .collect();
    if answers.len() > MAX {
        parts.push(format!("+{} more", answers.len() - MAX));
    }
    parts.join(" · ")
}

/** @brief 기록 하나를 짧은 문자열로. */
pub(crate) fn rdata_brief(rdata: &ApRData) -> String {
    match rdata {
        ApRData::A(ip) => ip.to_string(),
        ApRData::Aaaa(ip) => ip.to_string(),
        ApRData::Cname(n) | ApRData::Ns(n) | ApRData::Ptr(n) | ApRData::Dname(n) => {
            n.to_ascii_lower()
        }
        ApRData::Mx {
            preference,
            exchange,
        } => format!("{preference} {}", exchange.to_ascii_lower()),
        ApRData::Txt(parts) => {
            let text = parts
                .first()
                .map(|p| String::from_utf8_lossy(p).to_string())
                .unwrap_or_default();
            if text.chars().count() > 60 {
                let head: String = text.chars().take(60).collect();
                format!("{head}…")
            } else {
                text
            }
        }
        ApRData::Soa(s) => s.mname.to_ascii_lower(),
        ApRData::Srv {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {}", target.to_ascii_lower()),
        _ => String::new(),
    }
}

/** @brief 질문한 것이 실제로 답에 들어 있는지. 별칭을 따라가며 본다. */
pub(crate) fn response_has_requested_answer(request: &Message, response: &Message) -> bool {
    let Some(question) = request.questions.first() else {
        return !response.answers.is_empty();
    };
    if question.qtype == ApRt::ANY {
        return !response.answers.is_empty();
    }

    let mut current = question.name.clone();
    let mut seen = HashSet::<Vec<u8>>::new();
    for _ in 0..16 {
        if response
            .answers
            .iter()
            .any(|record| record.name.eq_ignore_case(&current) && record.rtype == question.qtype)
        {
            return true;
        }
        if !seen.insert(current.canonical_key()) {
            return false;
        }
        let target = response
            .answers
            .iter()
            .find_map(|record| {
                if record.name.eq_ignore_case(&current) {
                    if let ApRData::Cname(target) = &record.rdata {
                        return Some(target.clone());
                    }
                }
                None
            })
            .or_else(|| dname_answer_target(&current, &response.answers));
        let Some(target) = target else {
            return false;
        };
        current = target;
    }
    false
}

/** @brief 통째 옮김 기록이 가리키는 이름. */
fn dname_answer_target(current: &ApName, answers: &[ApRecord]) -> Option<ApName> {
    let record = answers
        .iter()
        .filter(|record| {
            matches!(&record.rdata, ApRData::Dname(_))
                && current.num_labels() > record.name.num_labels()
                && current
                    .suffix(record.name.num_labels())
                    .eq_ignore_case(&record.name)
        })
        .max_by_key(|record| record.name.num_labels())?;
    let ApRData::Dname(target_suffix) = &record.rdata else {
        return None;
    };
    let prefix_len = current.num_labels() - record.name.num_labels();
    let mut labels: Vec<Vec<u8>> = current
        .labels()
        .take(prefix_len)
        .map(<[u8]>::to_vec)
        .collect();
    labels.extend(target_suffix.labels().map(<[u8]>::to_vec));
    ApName::from_labels(labels).ok()
}

/** @brief 이 요청에 대한 빈 응답 뼈대. */
pub(crate) fn base_response(request: &Message) -> Message {
    let mut m = Message::default();
    m.header.id = request.header.id;
    m.header.response = true;
    m.header.opcode = request.header.opcode;
    m.header.recursion_desired = request.header.recursion_desired;
    m.header.recursion_available = true;
    m.questions = request.questions.clone();
    m
}

/** @brief 현재 Unix 초. */
pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/** @brief 이 코드의 오류 응답. */
pub(crate) fn error_resp(request: &Message, code: ResponseCode) -> Message {
    let mut m = base_response(request);
    m.header.rcode = code.0;
    m
}

/**
 * @brief 요청이 담은 OPT를 그대로 돌려주는 오류 응답.
 *
 * @details RFC 6891은 요청에 OPT가 있으면 응답에도 넣게 한다. 빼면 상대는 이 서버가
 *          EDNS를 모르는 것으로 보고 512바이트로 전환하므로, 형식 오류 하나가 그 뒤 모든
 *          질의의 버퍼 크기를 깎는다. 요청에 OPT가 없으면 응답에도 넣지 않는다.
 * @param udp_payload 이 서버가 광고할 버퍼 크기.
 */
pub(crate) fn edns_error_resp(request: &Message, code: ResponseCode, udp_payload: u16) -> Message {
    let edns = request.opt().map(|_| base_edns(request, udp_payload));
    finalize(error_resp(request, code), edns)
}

/** @brief 이 기록들을 답으로 담은 응답. */
/**
 * @brief ANY를 온전히 답하지 않을 때 대신 내보내는 합성 HINFO.
 *
 * @details RFC 8482가 정한 모양이다. CPU 필드에 RFC8482, OS 필드에 빈 문자열을 넣는다.
 *          질의자는 이것을 보고 이 응답이 온전한 ANY가 아님을 안다. 절단 비트는 설정하지
 *          않는다. 잘린 것이 아니라 이것이 답이기 때문이다.
 * @note HINFO(13)는 이 서버의 codec이 구조로 다루지 않는 종류라 wire 바이트로 만든다. 두
 *       character-string이 길이 프리픽스를 달고 이어지는 형식이다.
 */
pub(crate) fn rfc8482_hinfo(qname: &ApName) -> ApRecord {
    /** @brief 합성 HINFO의 수명. 질의자가 오래 붙들 이유가 없는 값이다. */
    const TTL: u32 = 3600;
    let mut wire = Vec::with_capacity(9);
    wire.push(b"RFC8482".len() as u8);
    wire.extend_from_slice(b"RFC8482");
    wire.push(0);
    ApRecord {
        name: qname.clone(),
        rtype: ApRt(13),
        class: DnsClass::IN,
        ttl: TTL,
        rdata: ApRData::Unknown(13, wire),
    }
}

pub(crate) fn records_resp(request: &Message, answers: Vec<ApRecord>) -> Message {
    let mut m = base_response(request);
    m.header.rcode = ResponseCode::NoError.0;
    m.answers = answers;
    m
}

/**
 * @brief 밖에 물어보면 안 되는 이름에 돌려줄 부정 응답.
 * @details 로컬에서 아무도 답하지 못했을 때만 쓰인다. 정책이 막았을 때와 같은 모양이다.
 */
pub(crate) fn local_only_negative_response(request: &Message, qname: &ApName, ttl: u32) -> Message {
    policy_negative_resp(request, qname, ResponseCode::NXDomain, ttl)
}

/** @brief 정책이 막았을 때의 응답. */
pub(crate) fn policy_negative_resp(
    request: &Message,
    qname: &ApName,
    code: ResponseCode,
    ttl: u32,
) -> Message {
    let mut response = error_resp(request, code);
    let mname = ApName::from_str("blocked.invalid").unwrap_or_else(|_| ApName::root());
    let rname = ApName::from_str("hostmaster.blocked.invalid").unwrap_or_else(|_| ApName::root());
    response.authorities.push(ApRecord::new(
        qname.clone(),
        ttl,
        ApRData::soa(onetdns_proto::Soa {
            mname,
            rname,
            serial: 1,
            refresh: ttl,
            retry: ttl,
            expire: ttl.saturating_mul(24).max(ttl),
            minimum: ttl,
        }),
    ));
    response
}

/**
 * @brief 응답 코드의 이름.
 * @note 아는 코드는 정적 문자열을 그대로 빌려 준다. 질의마다 실행되는 경로라 이름 하나를
 *       힙에 옮겨 담지 않는다.
 */
pub(crate) fn rcode_str(code: ResponseCode) -> std::borrow::Cow<'static, str> {
    let name = match code.0 {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        16 => "BADVERS_OR_BADSIG",
        17 => "BADKEY",
        18 => "BADTIME",
        19 => "BADMODE",
        20 => "BADNAME",
        21 => "BADALG",
        22 => "BADTRUNC",
        23 => "BADCOOKIE",
        _ => return std::borrow::Cow::Owned(format!("UNKNOWN({})", code.0)),
    };
    std::borrow::Cow::Borrowed(name)
}

/** @brief 차단 방식과 질의 종류에 맞는 응답 코드. */
pub(crate) fn block_rcode(br: &BlockResponse, qtype: ApRt) -> ResponseCode {
    match br {
        BlockResponse::NxDomain => ResponseCode::NXDomain,
        BlockResponse::Refused => ResponseCode::Refused,
        BlockResponse::NoData | BlockResponse::ZeroIp => ResponseCode::NoError,
        BlockResponse::Custom { v4, v6 } => {
            let has = match qtype {
                ApRt::A => v4.is_some(),
                ApRt::AAAA => v6.is_some(),
                _ => false,
            };
            if has {
                ResponseCode::NoError
            } else {
                ResponseCode::NXDomain
            }
        }
    }
}

/** @brief 차단 응답을 만든다. */
pub(crate) fn block_resp(
    request: &Message,
    qname: &ApName,
    qtype: ApRt,
    br: BlockResponse,
    block_ttl: u32,
) -> Message {
    match br {
        BlockResponse::NxDomain => {
            policy_negative_resp(request, qname, ResponseCode::NXDomain, block_ttl)
        }
        BlockResponse::Refused => error_resp(request, ResponseCode::Refused),
        BlockResponse::NoData => {
            policy_negative_resp(request, qname, ResponseCode::NoError, block_ttl)
        }
        BlockResponse::ZeroIp => {
            let recs = custom_ip_records(
                qname,
                qtype,
                Some(Ipv4Addr::UNSPECIFIED),
                Some(Ipv6Addr::UNSPECIFIED),
                block_ttl,
            );
            records_resp(request, recs)
        }
        BlockResponse::Custom { v4, v6 } => {
            let recs = custom_ip_records(qname, qtype, v4, v6, block_ttl);
            if recs.is_empty() {
                policy_negative_resp(request, qname, ResponseCode::NXDomain, block_ttl)
            } else {
                records_resp(request, recs)
            }
        }
    }
}

/** @brief 지정한 주소를 답으로 담은 기록들. */
fn custom_ip_records(
    qname: &ApName,
    qtype: ApRt,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    block_ttl: u32,
) -> Vec<ApRecord> {
    match qtype {
        ApRt::A => v4
            .map(|a| vec![ApRecord::new(qname.clone(), block_ttl, ApRData::A(a))])
            .unwrap_or_default(),
        ApRt::AAAA => v6
            .map(|a| vec![ApRecord::new(qname.clone(), block_ttl, ApRData::Aaaa(a))])
            .unwrap_or_default(),
        _ => vec![],
    }
}

#[cfg(test)]
/** @brief 응답 조립과 후처리. */
mod tests {
    use super::*;
    use crate::native::tests::{big_zone_store, ctx, negative_soa_ttl, q, server, shared_filter};
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use onetdns_core::{ArcSwap, BlockResponse};
    use onetdns_proto::{
        DnsClass, Edns, Message, Name as ApName, RData as ApRData, Record as ApRecord, RecordType,
        RecordType as ApRt, ResponseCode,
    };
    use onetdns_runtime::{Handler, RequestCtx, Transport as RtTransport};
    use onetdns_security::IpAcl;

    use crate::native::{NativeFeatures, NativeServer, Resolver};

    #[test]
    /** @brief 차단 방식에 맞는 응답 코드가 나가는지. */
    fn block_rcode_reflects_actual_response() {
        assert_eq!(
            block_rcode(&BlockResponse::Refused, ApRt::A),
            ResponseCode::Refused
        );
        assert_eq!(
            block_rcode(&BlockResponse::NoData, ApRt::A),
            ResponseCode::NoError
        );
        assert_eq!(
            block_rcode(&BlockResponse::ZeroIp, ApRt::A),
            ResponseCode::NoError
        );
        assert_eq!(
            block_rcode(&BlockResponse::NxDomain, ApRt::A),
            ResponseCode::NXDomain
        );

        let custom = BlockResponse::Custom {
            v4: Some(Ipv4Addr::new(10, 0, 0, 1)),
            v6: None,
        };
        assert_eq!(block_rcode(&custom, ApRt::A), ResponseCode::NoError);
        assert_eq!(block_rcode(&custom, ApRt::AAAA), ResponseCode::NXDomain);
        assert_eq!(block_rcode(&custom, ApRt::MX), ResponseCode::NXDomain);
    }

    #[test]
    /** @brief 차단 수명을 0으로 두면 그대로 0으로 나가는지. */
    fn zero_block_ttl_is_preserved_in_synthesized_responses() {
        let request = Message::query(1, ApName::from_str("blocked.example").unwrap(), ApRt::A);
        let qname = request.questions[0].name.clone();

        let address = block_resp(&request, &qname, ApRt::A, BlockResponse::ZeroIp, 0);
        assert_eq!(address.answers[0].ttl, 0);

        let negative = policy_negative_resp(&request, &qname, ResponseCode::NXDomain, 0);
        assert_eq!(negative.authorities[0].ttl, 0);

        let missing_family = block_resp(
            &request,
            &qname,
            ApRt::AAAA,
            BlockResponse::Custom {
                v4: Some(Ipv4Addr::new(192, 0, 2, 1)),
                v6: None,
            },
            0,
        );
        assert_eq!(missing_family.header.rcode, ResponseCode::NXDomain.0);
        assert_eq!(negative_soa_ttl(&missing_family), 0);
    }

    #[test]
    /** @brief 응답 코드 이름. */
    fn rcode_str_labels() {
        assert_eq!(rcode_str(ResponseCode::NoError), "NOERROR");
        assert_eq!(rcode_str(ResponseCode::ServFail), "SERVFAIL");
        assert_eq!(rcode_str(ResponseCode::NXDomain), "NXDOMAIN");
        assert_eq!(rcode_str(ResponseCode::Refused), "REFUSED");
        assert_eq!(rcode_str(ResponseCode(9)), "NOTAUTH");
        assert_eq!(rcode_str(ResponseCode(4095)), "UNKNOWN(4095)");
    }

    #[test]
    #[ignore = "마이크로벤치: cargo test -p onetdns --release -- --ignored --nocapture"]
    /** @brief 답 요약을 만드는 비용. */
    fn bench_answers_summary_cost() {
        use std::time::Instant;
        let name = ApName::from_str("www.example.com").unwrap();
        let ip = |b: u8| ApRData::A(Ipv4Addr::new(93, 184, 216, b));
        let answers = vec![
            ApRecord::new(name.clone(), 300, ip(34)),
            ApRecord::new(name.clone(), 300, ip(35)),
        ];
        for _ in 0..50_000 {
            let _ = answers_summary(&answers);
        }
        let iters = 1_000_000u128;
        let mut sink = 0usize;
        let t = Instant::now();
        for _ in 0..iters {
            sink = sink.wrapping_add(answers_summary(&answers).len());
        }
        let ns = t.elapsed().as_nanos() as f64 / iters as f64;
        println!(
            "answers_summary(2xA): {ns:.1} ns/call saved per store when no recorder (sink={sink})"
        );
    }

    #[test]
    /** @brief 서명한 영역 전송이 오가고, 요구 설정이 서명 없는 것을 막는지. */
    fn axfr_tsig_signed_roundtrip_and_required_mode() {
        use onetdns_dnssec::tsig;
        let zone_text = "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 admin 1 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\n";
        let zone = onetdns_authority::parse_zone(zone_text, "example.com").unwrap();
        let mut zs = onetdns_authority::ZoneStore::new();
        zs.add(zone);
        let store = Arc::new(ArcSwap::new(Arc::new(zs)));
        let key = tsig::TsigKey::new(
            ApName::from_str("xfer-key").unwrap(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let srv = server("")
            .with_xfr(store, vec!["127.0.0.0/8".parse().unwrap()])
            .with_tsig(vec![key.clone()], true);
        let tcp = RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Tcp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };

        let unsigned = Message::query(7, ApName::from_str("example.com").unwrap(), ApRt(252));
        let resp = srv.handle(&unsigned, &tcp).unwrap();
        assert_eq!(resp.header.rcode, ResponseCode::Refused.0, "비서명 거부");

        let mut signed = Message::query(8, ApName::from_str("example.com").unwrap(), ApRt(252));
        let req_mac = tsig::sign_message(&mut signed, &key, now_unix(), None).unwrap();
        let signed_wire = signed.try_encode().unwrap();
        let tcp_raw = RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Tcp,
            raw: Some(signed_wire.as_slice()),
            client_id: None,

            authenticated: false,
            auth_identity: None,
        };
        let resp = srv.handle(&signed, &tcp_raw).unwrap();
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
        assert!(
            resp.answers.iter().any(|r| r.rtype == RecordType::SOA),
            "SOA 포함"
        );
        tsig::verify_message(&resp, &key, now_unix(), Some(&req_mac)).expect("응답 TSIG 검증");

        let mut ordinary = q("ordinary.example");
        let ordinary_mac = tsig::sign_message(&mut ordinary, &key, now_unix(), None).unwrap();
        let ordinary_wire = ordinary.try_encode().unwrap();
        let ordinary_ctx = RequestCtx {
            raw: Some(&ordinary_wire),
            ..tcp_raw
        };
        let ordinary_resp = srv.handle(&ordinary, &ordinary_ctx).unwrap();
        tsig::verify_message(&ordinary_resp, &key, now_unix(), Some(&ordinary_mac))
            .expect("일반 DNS 응답도 요청 TSIG에 연쇄 서명");

        let bad = tsig::TsigKey::new(key.name.clone(), b"wrong-wrong-wrong!".to_vec()).unwrap();
        let mut forged = Message::query(9, ApName::from_str("example.com").unwrap(), ApRt(252));
        tsig::sign_message(&mut forged, &bad, now_unix(), None).unwrap();
        let forged_wire = forged.try_encode().unwrap();
        let forged_ctx = RequestCtx {
            raw: Some(&forged_wire),
            ..tcp.clone()
        };
        let resp = srv.handle(&forged, &forged_ctx).unwrap();
        assert_eq!(resp.header.rcode, 9, "BADSIG → NOTAUTH");
        assert_eq!(
            resp.additionals.last().map(|record| record.rtype),
            Some(ApRt(250)),
            "BADSIG 응답은 빈 MAC의 TSIG 오류 레코드를 포함해야 합니다"
        );
        let error = tsig::response_data(&resp).expect("BADSIG TSIG");
        assert_eq!(error.error(), tsig::TSIG_ERROR_BADSIG);
        assert!(error.mac().is_empty(), "BADSIG 오류는 서명하면 안 됩니다");
        assert!(error.other().is_empty());

        let unknown = tsig::TsigKey::new(
            ApName::from_str("unknown-key").unwrap(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let mut unknown_request =
            Message::query(10, ApName::from_str("example.com").unwrap(), ApRt(252));
        tsig::sign_message(&mut unknown_request, &unknown, now_unix(), None).unwrap();
        let unknown_wire = unknown_request.try_encode().unwrap();
        let unknown_ctx = RequestCtx {
            raw: Some(&unknown_wire),
            ..tcp.clone()
        };
        let resp = srv.handle(&unknown_request, &unknown_ctx).unwrap();
        assert_eq!(resp.header.rcode, 9, "BADKEY → NOTAUTH");
        assert_eq!(
            resp.additionals.last().map(|record| record.rtype),
            Some(ApRt(250)),
            "BADKEY 응답은 빈 MAC의 TSIG 오류 레코드를 포함해야 합니다"
        );
        let error = tsig::response_data(&resp).expect("BADKEY TSIG");
        assert_eq!(error.error(), tsig::TSIG_ERROR_BADKEY);
        assert_eq!(error.key_name(), &unknown.name);
        assert!(error.mac().is_empty(), "BADKEY 오류는 서명하면 안 됩니다");
        assert!(error.other().is_empty());

        let mut unsupported =
            Message::query(11, ApName::from_str("example.com").unwrap(), ApRt(252));
        tsig::sign_message(&mut unsupported, &key, now_unix(), None).unwrap();
        let raw = match &mut unsupported.additionals.last_mut().unwrap().rdata {
            ApRData::Unknown(250, raw) => raw,
            _ => panic!("TSIG RDATA가 아닙니다"),
        };
        let algorithm = raw
            .windows(b"hmac-sha256".len())
            .position(|window| window == b"hmac-sha256")
            .expect("알고리즘 이름");
        raw[algorithm..algorithm + b"hmac-sha512".len()].copy_from_slice(b"hmac-sha512");
        let unsupported_wire = unsupported.try_encode().unwrap();
        let unsupported_ctx = RequestCtx {
            raw: Some(&unsupported_wire),
            ..tcp.clone()
        };
        let resp = srv.handle(&unsupported, &unsupported_ctx).unwrap();
        let error = tsig::response_data(&resp).expect("unsupported algorithm BADKEY TSIG");
        assert_eq!(error.error(), tsig::TSIG_ERROR_BADKEY);
        assert_eq!(error.algorithm().to_ascii_lower(), "hmac-sha512");
        assert!(error.mac().is_empty());

        let client_time = now_unix().saturating_sub(301);
        let mut expired = Message::query(12, ApName::from_str("example.com").unwrap(), ApRt(252));
        let expired_mac = tsig::sign_message(&mut expired, &key, client_time, None).unwrap();
        let expired_wire = expired.try_encode().unwrap();
        let expired_ctx = RequestCtx {
            raw: Some(&expired_wire),
            ..tcp.clone()
        };
        let resp = srv.handle(&expired, &expired_ctx).unwrap();
        assert_eq!(resp.header.rcode, 9, "BADTIME → NOTAUTH");
        assert_eq!(
            resp.additionals.last().map(|record| record.rtype),
            Some(ApRt(250)),
            "BADTIME 응답은 서명된 TSIG 오류 레코드를 포함해야 합니다"
        );
        let error = tsig::response_data(&resp).expect("BADTIME TSIG");
        assert_eq!(error.error(), tsig::TSIG_ERROR_BADTIME);
        assert_eq!(error.time_signed(), client_time);
        assert_eq!(error.fudge(), 300);
        assert_eq!(error.other().len(), 6);
        assert_eq!(error.mac().len(), 32, "BADTIME 오류는 서명해야 합니다");
        let server_time = error
            .other()
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
        assert!(now_unix().abs_diff(server_time) <= 1);
        tsig::verify_message(&resp, &key, client_time, Some(&expired_mac))
            .expect("BADTIME 응답 MAC 검증");

        let stale_bad =
            tsig::TsigKey::new(key.name.clone(), b"wrong-wrong-wrong!".to_vec()).unwrap();
        let mut stale_forged =
            Message::query(13, ApName::from_str("example.com").unwrap(), ApRt(252));
        tsig::sign_message(&mut stale_forged, &stale_bad, client_time, None).unwrap();
        let stale_forged_wire = stale_forged.try_encode().unwrap();
        let stale_forged_ctx = RequestCtx {
            raw: Some(&stale_forged_wire),
            ..tcp.clone()
        };
        let resp = srv.handle(&stale_forged, &stale_forged_ctx).unwrap();
        let error = tsig::response_data(&resp).expect("stale BADSIG TSIG");
        assert_eq!(
            error.error(),
            tsig::TSIG_ERROR_BADSIG,
            "시간보다 MAC을 먼저 검증해야 합니다"
        );
        assert!(error.mac().is_empty());

        let mut unsigned_ixfr =
            Message::query(14, ApName::from_str("example.com").unwrap(), ApRt(251));
        unsigned_ixfr.authorities.push(ApRecord {
            name: ApName::from_str("example.com").unwrap(),
            rtype: ApRt::SOA,
            class: DnsClass::IN,
            ttl: 300,
            rdata: ApRData::soa(onetdns_proto::Soa {
                mname: ApName::from_str("ns1.example.com").unwrap(),
                rname: ApName::from_str("admin.example.com").unwrap(),
                serial: 1,
                refresh: 300,
                retry: 60,
                expire: 86400,
                minimum: 60,
            }),
        });
        let udp = RequestCtx {
            transport: RtTransport::Do53Udp,
            ..tcp
        };
        let resp = srv.handle(&unsigned_ixfr, &udp).unwrap();
        assert_eq!(
            resp.header.rcode,
            ResponseCode::Refused.0,
            "UDP IXFR도 필수 TSIG를 우회할 수 없습니다"
        );
    }

    #[test]
    /** @brief 서명이 망가진 요청이 서명 없는 전송으로 넘어가지 않는지. 넘어가면 검증을 우회한다. */
    fn malformed_tsig_layout_cannot_fall_back_to_unsigned_axfr() {
        use onetdns_dnssec::tsig;
        let zone_text = "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 admin 1 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\n";
        let zone = onetdns_authority::parse_zone(zone_text, "example.com").unwrap();
        let mut zones = onetdns_authority::ZoneStore::new();
        zones.add(zone);
        let store = Arc::new(ArcSwap::new(Arc::new(zones)));
        let key = tsig::TsigKey::new(
            ApName::from_str("xfer-key").unwrap(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let srv = server("")
            .with_xfr(store, vec!["127.0.0.0/8".parse().unwrap()])
            .with_tsig(vec![key.clone()], false);

        let mut request = Message::query(8, ApName::from_str("example.com").unwrap(), ApRt(252));
        tsig::sign_message(&mut request, &key, now_unix(), None).unwrap();
        request.additionals.push(ApRecord {
            name: ApName::from_str("padding.example.com").unwrap(),
            rtype: ApRt(65_000),
            class: DnsClass::IN,
            ttl: 0,
            rdata: ApRData::Unknown(65_000, Vec::new()),
        });
        let raw = request.try_encode().unwrap();
        let tcp = RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Tcp,
            raw: Some(&raw),
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };

        let response = srv.handle(&request, &tcp).unwrap();
        assert_eq!(
            response.header.rcode,
            ResponseCode::FormErr.0,
            "마지막 RR이 아닌 TSIG는 unsigned AXFR로 강등하지 않습니다"
        );
    }

    #[test]
    /** @brief 여러 청크의 서명이 체인으로 이어져 검증되는지. */
    fn axfr_multi_envelope_tsig_chain_verifies() {
        use onetdns_dnssec::tsig;
        let store = big_zone_store(2000);
        let key = tsig::TsigKey::new(
            ApName::from_str("xfer-key").unwrap(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let srv = server("")
            .with_xfr(store, vec!["127.0.0.0/8".parse().unwrap()])
            .with_tsig(vec![key.clone()], true);

        let mut signed = Message::query(8, ApName::from_str("big.test").unwrap(), ApRt(252));
        let req_mac = tsig::sign_message(&mut signed, &key, now_unix(), None).unwrap();
        let wire = signed.try_encode().unwrap();
        let tcp_raw = RequestCtx {
            src: "127.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Tcp,
            raw: Some(wire.as_slice()),
            client_id: None,

            authenticated: false,
            auth_identity: None,
        };
        let msgs = srv.handle_multi(&signed, &tcp_raw).expect("AXFR 응답");
        assert!(msgs.len() > 1, "다중 envelope: {}", msgs.len());

        let mut prev = req_mac.clone();
        for (i, m) in msgs.iter().enumerate() {
            let w = m.try_encode().unwrap();
            let res = if i == 0 {
                tsig::verify_wire(&w, &key, now_unix(), Some(&prev))
            } else {
                tsig::verify_wire_subsequent(&w, &key, now_unix(), &prev)
            };
            let (_, mac) = res.unwrap_or_else(|e| {
                panic!("{i}번째 전송 메시지의 TSIG 검증에 실패했습니다: {e:?}")
            });
            prev = mac;
        }

        let mut writer = onetdns_proto::Writer::new();
        let mut wires = Vec::new();
        assert_eq!(
            srv.handle_preencoded_stream(&signed, &tcp_raw, &mut writer, &mut |wire| {
                wires.push(wire.to_vec());
                true
            }),
            Some(true),
            "TSIG AXFR도 캐시된 wire template을 사용합니다"
        );
        assert_eq!(wires.len(), msgs.len());
        let mut prev = req_mac;
        for (index, wire) in wires.iter().enumerate() {
            let (stripped, mac) = if index == 0 {
                tsig::verify_wire(wire, &key, now_unix(), Some(&prev))
            } else {
                tsig::verify_wire_subsequent(wire, &key, now_unix(), &prev)
            }
            .unwrap_or_else(|error| panic!("{index}번째 fast TSIG envelope: {error:?}"));
            let message = Message::parse(&stripped).unwrap();
            assert_eq!(message.questions.len(), usize::from(index == 0));
            prev = mac;
        }
    }

    #[test]
    /** @brief 최소 응답과 채우기가 설정대로 적용되는지. */
    fn postprocess_minimal_responses_and_padding() {
        let mut f = NativeFeatures {
            minimal_responses: true,
            padding_block: 128,
            ..NativeFeatures::default()
        };

        let mut msg = Message::query(9, ApName::from_str("x.test").unwrap(), RecordType::A);
        msg.header.response = true;
        msg.answers.push(ApRecord::new(
            ApName::from_str("x.test").unwrap(),
            60,
            ApRData::A(Ipv4Addr::new(1, 2, 3, 4)),
        ));
        msg.authorities.push(ApRecord::new(
            ApName::from_str("ns.test").unwrap(),
            60,
            ApRData::A(Ipv4Addr::new(9, 9, 9, 9)),
        ));
        msg.additionals
            .push(Edns::default().try_to_record().unwrap());

        let mut req = Message::query(9, ApName::from_str("x.test").unwrap(), RecordType::A);
        let mut e = Edns::default();
        e.options.push((onetdns_proto::EDNS_PADDING, vec![]));
        req.additionals.push(e.try_to_record().unwrap());

        postprocess(&f, &mut msg, &req, &ctx()).unwrap();
        assert!(
            msg.authorities.is_empty(),
            "minimal-responses가 권한 섹션 제거"
        );
        assert_eq!(
            msg.try_encode().unwrap().len() % 128,
            0,
            "padding으로 block 배수 정렬"
        );

        let mut msg2 = Message::query(9, ApName::from_str("x.test").unwrap(), RecordType::A);
        msg2.header.response = true;
        msg2.additionals
            .push(Edns::default().try_to_record().unwrap());
        let plain = Message::query(9, ApName::from_str("x.test").unwrap(), RecordType::A);
        f.minimal_responses = false;
        let before = msg2.try_encode().unwrap().len();
        postprocess(&f, &mut msg2, &plain, &ctx()).unwrap();
        assert_eq!(
            msg2.try_encode().unwrap().len(),
            before,
            "padding 미요청 시 변화 없음"
        );
    }

    #[test]
    /** @brief 임의로 만든 답의 수명이 근거보다 길지 않은지. */
    fn dns64_synthesis_caps_ttl_with_negative_soa() {
        let owner = ApName::from_str("v4only.test").unwrap();
        let answers = vec![ApRecord::new(
            owner.clone(),
            300,
            ApRData::A(Ipv4Addr::new(192, 0, 2, 10)),
        )];
        let mut prefix = [0u8; 16];
        prefix[..4].copy_from_slice(&[0x00, 0x64, 0xff, 0x9b]);
        let synthesized = synthesize_dns64(&answers, &prefix, Some(45));
        assert_eq!(synthesized.len(), 1);
        assert_eq!(synthesized[0].ttl, 45);
        assert!(matches!(&synthesized[0].rdata, ApRData::Aaaa(_)));
    }

    #[test]
    /** @brief 클라이언트마다 달라지는 차단이 담긴 바이트로 새 나가지 않는지. */
    fn wire_store_does_not_leak_client_specific_cname_block() {
        use onetdns_runtime::WireDisposition;

        /** @brief 별칭 뒤에 차단 대상을 숨긴 답을 내는 테스트용 체인. */
        struct CloakedAnswer;
        impl Resolver for CloakedAnswer {
            /** @brief 별칭 뒤에 차단 대상을 숨긴 답을 돌려준다. */
            fn resolve(&self, request: &Message) -> Option<Message> {
                let mut response = base_response(request);
                let name = request.questions.first().unwrap().name.clone();
                let tracker = ApName::from_str("tracker.evil.example").unwrap();
                response
                    .answers
                    .push(ApRecord::new(name, 300, ApRData::Cname(tracker.clone())));
                response.answers.push(ApRecord::new(
                    tracker,
                    300,
                    ApRData::A(Ipv4Addr::new(203, 0, 113, 9)),
                ));
                Some(response)
            }
        }

        let engine =
            onetdns_filter::build_from_str("", "", BlockResponse::ZeroIp).with_clients(vec![
                onetdns_filter::ClientPolicy::with_options(
                    vec!["10.0.0.0/8".parse().unwrap()],
                    vec![],
                    vec![],
                    &["tracker.evil.example".to_string()],
                    &[],
                    false,
                    None,
                ),
            ]);
        let layer =
            crate::cache::CacheLayer::new(Arc::new(CloakedAnswer), 64, 1, 0, 86_400, 0, 86_400);
        let cache = layer.handle();
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(engine)),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(layer),
            60,
        )
        .with_wire_fast_path(Some((
            crate::wirecache::WireEntryFactory::new(0, 86_400),
            cache,
        )));

        let packet = Message::query(
            0x21,
            ApName::from_str("cdn.publisher.example").unwrap(),
            ApRt::A,
        )
        .try_encode()
        .unwrap();
        let blocked_ctx = RequestCtx {
            src: "10.0.0.1:5555".parse().unwrap(),
            transport: RtTransport::Do53Udp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };

        let mut out = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&packet, &blocked_ctx, &mut out, std::time::Instant::now()),
            WireDisposition::Fallback,
            "클라이언트별 규칙이 있으면 공유 wire 표현을 만들지 않는다"
        );

        let mut out2 = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&packet, &ctx(), &mut out2, std::time::Instant::now()),
            WireDisposition::Fallback
        );

        let request = Message::parse(&packet).unwrap();
        let blocked = server
            .handle(&request, &blocked_ctx)
            .expect("동기 경로 응답");
        assert!(
            blocked
                .answers
                .iter()
                .any(|r| matches!(&r.rdata, ApRData::A(ip) if ip.is_unspecified())),
            "차단 대상 클라이언트는 동기 경로에서 0.0.0.0을 받는다"
        );
        assert!(
            server
                .handle(&request, &ctx())
                .expect("동기 경로 응답")
                .answers
                .iter()
                .any(
                    |r| matches!(&r.rdata, ApRData::A(ip) if *ip == Ipv4Addr::new(203, 0, 113, 9))
                ),
            "차단 대상이 아닌 클라이언트는 참 응답을 받는다"
        );

        let plain_layer =
            crate::cache::CacheLayer::new(Arc::new(CloakedAnswer), 64, 1, 0, 86_400, 0, 86_400);
        let plain_cache = plain_layer.handle();
        let plain = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::build_from_str(
                "",
                "",
                BlockResponse::ZeroIp,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(plain_layer),
            60,
        )
        .with_wire_fast_path(Some((
            crate::wirecache::WireEntryFactory::new(0, 86_400),
            plain_cache,
        )));
        let mut out3 = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            plain.handle_udp_wire(&packet, &ctx(), &mut out3, std::time::Instant::now()),
            WireDisposition::Respond,
            "클라이언트별 규칙이 없으면 기존대로 wire 경로가 동작한다"
        );
    }

    #[test]
    /** @brief 밖에 있을 수 없는 주소를 표기와 무관하게 모두 거르는지. */
    fn rebind_address_classification_blocks_all_non_public_forms() {
        for address in [
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            assert!(is_private_rdata(&ApRData::A(address)), "{address}");
        }
        assert!(!is_private_rdata(&ApRData::A(Ipv4Addr::new(8, 8, 8, 8))));

        let mapped_loopback = "::ffff:127.0.0.1".parse().unwrap();
        let documentation = "2001:db8::1".parse().unwrap();
        let public = "2606:4700:4700::1111".parse().unwrap();
        assert!(is_private_rdata(&ApRData::Aaaa(mapped_loopback)));
        assert!(is_private_rdata(&ApRData::Aaaa(documentation)));
        assert!(!is_private_rdata(&ApRData::Aaaa(public)));

        let mapped_hint = ApRData::Https {
            priority: 1,
            target: ApName::root(),
            params: vec![(6, Box::from(mapped_loopback.octets()))].into_boxed_slice(),
        };
        assert!(is_private_rdata(&mapped_hint));
    }

    #[test]
    /** @brief 내부망 주소가 어느 구간에 실려도 빠지는지. */
    fn rebind_filter_removes_private_data_from_every_dns_section() {
        let owner = ApName::from_str("mail.example").unwrap();
        let mut response = Message::default();
        response.answers.push(ApRecord::new(
            owner.clone(),
            60,
            ApRData::Mx {
                preference: 10,
                exchange: owner.clone(),
            },
        ));
        response.authorities.push(ApRecord::new(
            owner.clone(),
            60,
            ApRData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ));
        response.additionals.push(ApRecord::new(
            owner,
            60,
            ApRData::Aaaa("::ffff:127.0.0.1".parse().unwrap()),
        ));
        response
            .additionals
            .push(onetdns_proto::Edns::default().try_to_record().unwrap());

        assert!(strip_private_records(&mut response));
        assert_eq!(response.answers.len(), 1, "공개 MX 의미는 유지");
        assert!(response.authorities.is_empty());
        assert_eq!(response.additionals.len(), 1, "OPT는 유지");
        assert_eq!(response.additionals[0].rtype, ApRt::OPT);
    }
}
