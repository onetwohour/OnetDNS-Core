/*!
 * @brief RFC 1035 zone 파일 파서.
 *
 * @details 모든 zone 공급자가 결국 이 함수를 거친다. 파일, 디렉터리, DB 백엔드가 각자
 *          형식을 해석하지 않고 여기로 모이므로, 입력 검증이 한곳에 모인다.
 * @warning 신뢰할 수 없는 입력이 닿는다. 컨트롤 플레인으로 zone 텍스트를 올릴 수 있고, DB 행도
 *          이 서버가 만든 것이 아닐 수 있다. 어떤 입력에도 패닉하지 않아야 하며, 패닉 스윕의
 *          진입점 중 하나다.
 */

use std::net::{Ipv4Addr, Ipv6Addr};

use onetdns_proto::{Name, RData, Record, RecordType, Soa};

use crate::{Zone, MAX_ZONE_RECORDS};

/**
 * @brief zone 텍스트를 파싱해 Zone을 만든다.
 *
 * @details 상태를 이어 가며 줄 단위로 읽는다. origin과 기본 TTL은 지시자가 바꾸고,
 *          공백으로 시작하는 줄은 직전 소유자 이름을 물려받는다. 클래스와 TTL은 순서가
 *          자유로워서 타입이 나올 때까지 앞에서 걷어 낸다.
 * @param text           zone 파일 내용. 앞의 BOM은 떼어 낸다.
 * @param default_origin 파일에 지시자가 없을 때 쓸 origin.
 * @return 파싱된 Zone.
 * @retval Err SOA가 없거나 둘 이상일 때, 레코드 수가 상한을 넘을 때, 그리고 각 줄의
 *             형식이 어긋날 때.
 * @invariant SOA는 정확히 하나여야 한다. 둘이면 어느 것이 zone의 직렬번호인지 정해지지
 *            않아 전송과 갱신이 어긋난다.
 */
pub fn parse_zone(text: &str, default_origin: &str) -> Result<Zone, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut origin = Name::from_str(default_origin).map_err(|_| "Invalid origin".to_string())?;
    let mut default_ttl: u32 = 3600;
    let mut last_owner: Option<Name> = Some(origin.clone());
    let mut soa: Option<(Name, u32, Soa)> = None;
    let mut soa_count = 0usize;
    let estimated_records = text
        .lines()
        .filter(|line| {
            let line = line.trim_start();
            !line.is_empty() && !line.starts_with(';') && !line.starts_with('$')
        })
        .count()
        .min(MAX_ZONE_RECORDS);
    let mut records = Vec::with_capacity(estimated_records);

    for_each_logical_line(text, |started_ws, content| {
        let toks = tokenize(content);
        if toks.is_empty() {
            return Ok(());
        }

        if toks[0].eq_ignore_ascii_case("$ORIGIN") {
            origin = parse_name(
                toks.get(1).ok_or("$ORIGIN directive has no value")?,
                &origin,
            )?;
            return Ok(());
        }
        if toks[0].eq_ignore_ascii_case("$TTL") {
            default_ttl = parse_ttl(toks.get(1).ok_or("$TTL directive has no value")?)?;
            return Ok(());
        }

        let mut i = 0usize;
        let owner = if started_ws {
            last_owner
                .clone()
                .ok_or("Missing owner (the first line starts with whitespace)")?
        } else {
            let o = parse_name(&toks[0], &origin)?;
            i = 1;
            o
        };
        last_owner = Some(owner.clone());

        let mut ttl = default_ttl;
        loop {
            let t = toks
                .get(i)
                .ok_or("The record is incomplete because its type is missing")?;
            if t.eq_ignore_ascii_case("IN") {
                i += 1;
                continue;
            }
            if let Ok(n) = parse_ttl(t) {
                ttl = n;
                i += 1;
                continue;
            }
            break;
        }

        let rtype = toks[i].clone();
        i += 1;
        let rdata = parse_rdata(&rtype, &toks[i..], &origin)?;
        if let RData::Soa(s) = &rdata {
            soa_count += 1;
            if soa_count > 1 {
                return Err("A zone must have exactly one apex SOA".to_string());
            }
            soa = Some((owner.clone(), ttl, s.as_ref().clone()));
        }
        if records.len() >= MAX_ZONE_RECORDS {
            return Err(format!(
                "The zone has more records than allowed ({MAX_ZONE_RECORDS})"
            ));
        }
        records.push(Record::new(owner.clone(), ttl, rdata));
        Ok(())
    })?;

    let (soa_owner, soa_ttl, soa_rec) = soa.ok_or("The zone has no SOA".to_string())?;
    Zone::from_flat_records(soa_owner, soa_rec, soa_ttl, records)
}

/**
 * @brief ZONEMD 다이제스트의 최소 길이.
 * @details RFC 8976은 이보다 짧은 다이제스트를 허용하지 않는다. 짧은 값은 영역이 온전한지
 *          가리는 근거가 되지 못한다.
 */
const ZONEMD_MIN_DIGEST: usize = 12;

/**
 * @brief 타입 이름과 토큰들로 RDATA를 만든다.
 * @details 아는 타입은 구조화해서 담고, 모르는 타입은 형식으로 받아 미해석 바이트로 둔다.
 *          마지막에 반드시 validate를 거친다. 파싱만 되고 규격에 어긋나는 값이 zone에
 *          들어가면 응답 인코딩 시점에야 문제가 드러난다.
 */
fn parse_rdata(rtype: &str, toks: &[String], origin: &Name) -> Result<RData, String> {
    let need = |n: usize| -> Result<(), String> {
        if toks.len() < n {
            Err(format!("{rtype} RDATA is incomplete"))
        } else {
            Ok(())
        }
    };
    let rd = match rtype.to_ascii_uppercase().as_str() {
        "A" => {
            need(1)?;
            RData::A(
                toks[0]
                    .parse::<Ipv4Addr>()
                    .map_err(|_| "Invalid IPv4 address in A record")?,
            )
        }
        "AAAA" => {
            need(1)?;
            RData::Aaaa(
                toks[0]
                    .parse::<Ipv6Addr>()
                    .map_err(|_| "Invalid IPv6 address in AAAA record")?,
            )
        }
        "NS" => {
            need(1)?;
            RData::Ns(parse_name(&toks[0], origin)?)
        }
        "CNAME" => {
            need(1)?;
            RData::Cname(parse_name(&toks[0], origin)?)
        }
        "DNAME" => {
            need(1)?;
            RData::Dname(parse_name(&toks[0], origin)?)
        }
        "PTR" => {
            need(1)?;
            RData::Ptr(parse_name(&toks[0], origin)?)
        }
        "MX" => {
            need(2)?;
            RData::Mx {
                preference: toks[0].parse().map_err(|_| "Invalid MX preference")?,
                exchange: parse_name(&toks[1], origin)?,
            }
        }
        "TXT" => RData::Txt(toks.iter().map(|t| unescape_char_string(t)).collect()),
        "CAA" => {
            need(3)?;
            let flags: u8 = toks[0].parse().map_err(|_| "Invalid CAA flags")?;
            let tag = unescape_char_string(&toks[1]);

            let value = unescape_char_string(&toks[2..].join(" "));
            RData::Caa {
                flags,
                tag: tag.into_boxed_slice(),
                value: value.into_boxed_slice(),
            }
        }
        "SRV" => {
            need(4)?;
            RData::Srv {
                priority: toks[0].parse().map_err(|_| "Invalid SRV priority")?,
                weight: toks[1].parse().map_err(|_| "Invalid SRV weight")?,
                port: toks[2].parse().map_err(|_| "Invalid SRV port")?,
                target: parse_name(&toks[3], origin)?,
            }
        }
        "SOA" => {
            need(7)?;
            RData::soa(Soa {
                mname: parse_name(&toks[0], origin)?,
                rname: parse_name(&toks[1], origin)?,
                serial: toks[2].parse().map_err(|_| "Invalid SOA serial")?,
                refresh: parse_ttl(&toks[3])?,
                retry: parse_ttl(&toks[4])?,
                expire: parse_ttl(&toks[5])?,
                minimum: parse_ttl(&toks[6])?,
            })
        }
        "TLSA" => {
            need(4)?;
            RData::Tlsa {
                usage: toks[0].parse().map_err(|_| "Invalid TLSA usage")?,
                selector: toks[1].parse().map_err(|_| "Invalid TLSA selector")?,
                matching: toks[2].parse().map_err(|_| "Invalid TLSA matching type")?,
                data: hex_decode(&toks[3..].join("")).ok_or("Invalid TLSA hex data")?,
            }
        }
        "SSHFP" => {
            need(3)?;
            RData::Sshfp {
                algorithm: toks[0].parse().map_err(|_| "Invalid SSHFP algorithm")?,
                fp_type: toks[1]
                    .parse()
                    .map_err(|_| "Invalid SSHFP fingerprint type")?,
                fingerprint: hex_decode(&toks[2..].join(""))
                    .ok_or("Invalid SSHFP hex fingerprint")?,
            }
        }

        "DNSKEY" | "CDNSKEY" => {
            need(4)?;
            let flags: u16 = toks[0]
                .parse()
                .map_err(|_| format!("Invalid {rtype} flags"))?;
            let protocol: u8 = toks[1]
                .parse()
                .map_err(|_| format!("Invalid {rtype} protocol"))?;
            let algorithm: u8 = toks[2]
                .parse()
                .map_err(|_| format!("Invalid {rtype} algorithm"))?;
            let key = base64_decode(&toks[3..].join(""))
                .ok_or_else(|| format!("{rtype} public key is not valid base64"))?;
            let mut wire = Vec::with_capacity(4 + key.len());
            wire.extend_from_slice(&flags.to_be_bytes());
            wire.push(protocol);
            wire.push(algorithm);
            wire.extend_from_slice(&key);
            RData::Unknown(
                if rtype.eq_ignore_ascii_case("DNSKEY") {
                    48
                } else {
                    60
                },
                wire,
            )
        }
        "RRSIG" => {
            need(9)?;
            let covered = rrsig_covered_type(&toks[0])?;
            let algorithm: u8 = toks[1].parse().map_err(|_| "Invalid RRSIG algorithm")?;
            let labels: u8 = toks[2].parse().map_err(|_| "Invalid RRSIG label count")?;
            let original_ttl = parse_ttl(&toks[3])?;
            let expiration = parse_dnssec_time(&toks[4])?;
            let inception = parse_dnssec_time(&toks[5])?;
            let key_tag: u16 = toks[6].parse().map_err(|_| "Invalid RRSIG key tag")?;
            let signer = parse_name(&toks[7], origin)?;
            let signature =
                base64_decode(&toks[8..].join("")).ok_or("RRSIG signature is not valid base64")?;
            let mut wire = Vec::with_capacity(18 + signature.len());
            wire.extend_from_slice(&covered.to_be_bytes());
            wire.push(algorithm);
            wire.push(labels);
            wire.extend_from_slice(&original_ttl.to_be_bytes());
            wire.extend_from_slice(&expiration.to_be_bytes());
            wire.extend_from_slice(&inception.to_be_bytes());
            wire.extend_from_slice(&key_tag.to_be_bytes());
            wire.extend_from_slice(signer.as_uncompressed_wire());
            wire.extend_from_slice(&signature);
            RData::Unknown(46, wire)
        }
        "NSEC" => {
            need(1)?;
            let next = parse_name(&toks[0], origin)?;
            let mut wire = next.as_uncompressed_wire().to_vec();
            wire.extend_from_slice(&type_bitmap(&toks[1..])?);
            RData::Unknown(47, wire)
        }
        "NSEC3PARAM" => {
            need(4)?;
            let mut wire = nsec3_head(&toks[0], &toks[1], &toks[2], &toks[3], "NSEC3PARAM")?;
            wire.shrink_to_fit();
            RData::Unknown(51, wire)
        }
        "NSEC3" => {
            need(6)?;
            let mut wire = nsec3_head(&toks[0], &toks[1], &toks[2], &toks[3], "NSEC3")?;
            let next =
                base32hex_decode(&toks[4]).ok_or("NSEC3 next hash is not valid base32hex")?;
            let len =
                u8::try_from(next.len()).map_err(|_| "NSEC3 next hash is too long".to_string())?;
            wire.push(len);
            wire.extend_from_slice(&next);
            wire.extend_from_slice(&type_bitmap(&toks[5..])?);
            RData::Unknown(50, wire)
        }
        "DS" | "CDS" => {
            need(4)?;
            let key_tag: u16 = toks[0].parse().map_err(|_| "Invalid DS key tag")?;
            let algorithm: u8 = toks[1].parse().map_err(|_| "Invalid DS algorithm")?;
            let digest_type: u8 = toks[2].parse().map_err(|_| "Invalid DS digest type")?;
            let digest = hex_decode(&toks[3..].join("")).ok_or("Invalid DS hex digest")?;
            let mut wire = Vec::with_capacity(4 + digest.len());
            wire.extend_from_slice(&key_tag.to_be_bytes());
            wire.push(algorithm);
            wire.push(digest_type);
            wire.extend_from_slice(&digest);
            RData::Unknown(
                if rtype.eq_ignore_ascii_case("DS") {
                    43
                } else {
                    59
                },
                wire,
            )
        }
        "ZONEMD" => {
            need(4)?;
            let serial: u32 = toks[0].parse().map_err(|_| "Invalid ZONEMD serial")?;
            let scheme: u8 = toks[1].parse().map_err(|_| "Invalid ZONEMD scheme")?;
            let hash_alg: u8 = toks[2]
                .parse()
                .map_err(|_| "Invalid ZONEMD hash algorithm")?;
            let digest = hex_decode(&toks[3..].join("")).ok_or("Invalid ZONEMD hex digest")?;
            if digest.len() < ZONEMD_MIN_DIGEST {
                return Err(format!(
                    "ZONEMD digest must be at least {ZONEMD_MIN_DIGEST} bytes"
                ));
            }
            let mut wire = Vec::with_capacity(6 + digest.len());
            wire.extend_from_slice(&serial.to_be_bytes());
            wire.push(scheme);
            wire.push(hash_alg);
            wire.extend_from_slice(&digest);
            RData::Unknown(63, wire)
        }
        "NAPTR" => {
            need(6)?;
            RData::Naptr(Box::new(onetdns_proto::Naptr {
                order: toks[0].parse().map_err(|_| "Invalid NAPTR order")?,
                preference: toks[1].parse().map_err(|_| "Invalid NAPTR preference")?,
                flags: unescape_char_string(&toks[2]),
                services: unescape_char_string(&toks[3]),
                regexp: unescape_char_string(&toks[4]),
                replacement: parse_name(&toks[5], origin)?,
            }))
        }
        "URI" => {
            need(3)?;
            RData::Uri {
                priority: toks[0].parse().map_err(|_| "Invalid URI priority")?,
                weight: toks[1].parse().map_err(|_| "Invalid URI weight")?,
                target: unescape_char_string(&toks[2..].join(" ")),
            }
        }
        "SVCB" | "HTTPS" => {
            need(2)?;
            let priority: u16 = toks[0].parse().map_err(|_| "Invalid SVCB priority")?;
            let target = parse_name(&toks[1], origin)?;
            let mut params = Vec::new();
            for t in &toks[2..] {
                let (name, value) = match t.split_once('=') {
                    Some((name, value)) => (name, Some(value)),
                    None => (t.as_str(), None),
                };
                let (key, wire) = svcb_param(name, value)?;
                params.push((key, wire.into_boxed_slice()));
            }
            params.sort_unstable_by_key(|(key, _)| *key);
            if rtype.eq_ignore_ascii_case("SVCB") {
                RData::Svcb {
                    priority,
                    target,
                    params: params.into_boxed_slice(),
                }
            } else {
                RData::Https {
                    priority,
                    target,
                    params: params.into_boxed_slice(),
                }
            }
        }
        other => {
            if let Some(num) = other
                .strip_prefix("TYPE")
                .and_then(|n| n.parse::<u16>().ok())
            {
                if toks.first().map(|t| t.as_str()) == Some("\\#") {
                    need(2)?;
                    let len: usize = toks[1]
                        .parse()
                        .map_err(|_| "Invalid \\# length".to_string())?;
                    let hex: String = toks[2..].concat();
                    let bytes = hex_decode(&hex).ok_or("Invalid RFC 3597 hex data")?;
                    if bytes.len() != len {
                        return Err(format!(
                            "\\# length mismatch: declared {len}, actual {}",
                            bytes.len()
                        ));
                    }
                    RData::Unknown(num, bytes)
                } else {
                    return Err(format!(
                        "TYPE{num} records must use the RFC 3597 \\# format"
                    ));
                }
            } else {
                return Err(format!("Unsupported record type: {other}"));
            }
        }
    };
    let _ = RecordType::A;
    rd.validate()
        .map_err(|error| format!("Invalid {rtype} RDATA: {error}"))?;
    Ok(rd)
}

/**
 * @brief 16진 문자열을 바이트로.
 * @note 바이트 단위로 다루므로 다중바이트 문자가 섞여도 인덱스가 문자 경계를 벗어나지
 *       않는다. to_digit이 걸러 내니 별도 검사는 필요 없다.
 * @return 길이가 홀수이거나 16진수가 아닌 문자가 있으면 None.
 */
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    (0..b.len() / 2)
        .map(|i| {
            let hi = (b[2 * i] as char).to_digit(16)?;
            let lo = (b[2 * i + 1] as char).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

/**
 * @brief 토큰을 이름으로. 상대 이름은 origin을 붙여 절대 이름으로 만든다.
 * @details 골뱅이는 origin 자신이고, 점으로 끝나면 이미 절대 이름이다. 그 밖에는 origin을
 *          이어 붙인다. 이 규칙을 어기면 같은 zone 파일이 origin에 따라 다른 이름을 만든다.
 */
fn parse_name(tok: &str, origin: &Name) -> Result<Name, String> {
    if tok == "@" {
        return Ok(origin.clone());
    }
    if tok.ends_with('.') && !tok.ends_with(r"\.") {
        return Name::from_str(tok).map_err(|_| format!("Invalid name: {tok}"));
    }
    /*
     * origin은 라벨로 이어 붙인다. 표시 문자열로 합치면 이스케이프가 필요한 바이트가
     * 그대로 섞여 들어가 다시 읽을 때 라벨 경계가 달라진다.
     */
    let relative = Name::from_str(tok).map_err(|_| format!("Invalid name: {tok}"))?;
    let mut labels: Vec<Vec<u8>> = relative.labels().map(<[u8]>::to_vec).collect();
    labels.extend(origin.labels().map(<[u8]>::to_vec));
    Name::from_labels(labels).map_err(|_| format!("Invalid name: {tok}"))
}

/**
 * @brief TTL을 읽는다. 순수한 숫자와 접미사 형식(1h30m 등)을 모두 받는다.
 * @note 누적은 포화 연산으로 하고 마지막에 32비트로 자른다. 큰 값을 적어도 넘치지 않고
 *       상한에 머무른다.
 * @return 숫자가 하나도 없거나 모르는 접미사가 있으면 오류.
 */
fn parse_ttl(s: &str) -> Result<u32, String> {
    if let Ok(n) = s.parse::<u32>() {
        return Ok(n);
    }

    let mut total: u64 = 0;
    let mut num: u64 = 0;
    let mut saw = false;
    for c in s.chars() {
        if c.is_ascii_digit() {
            num = num.saturating_mul(10).saturating_add(c as u64 - '0' as u64);
            saw = true;
        } else {
            let mult = match c.to_ascii_lowercase() {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 86_400,
                'w' => 604_800,
                _ => return Err(format!("Invalid TTL: {s}")),
            };
            total = total.saturating_add(num.saturating_mul(mult));
            num = 0;
        }
    }
    if !saw {
        return Err(format!("Invalid TTL: {s}"));
    }
    total = total.saturating_add(num);
    Ok(total.min(u32::MAX as u64) as u32)
}

/**
 * @brief 괄호로 이어진 여러 물리 줄을 논리 줄 하나로 묶어 넘긴다.
 *
 * @details SOA처럼 긴 레코드는 괄호로 줄을 나눠 쓴다. 괄호 깊이를 세되 따옴표 안의
 *          괄호는 세지 않는다. 텍스트가 괄호를 닫지 않고 끝나도 마지막 조각을 그대로
 *          넘긴다. 삼키면 잘린 파일이 조용히 통과한다.
 * @param emit 첫 인자는 그 논리 줄이 공백으로 시작했는지다. 소유자 이름을 물려받을지가
 *             여기서 갈리므로 내용과 함께 전달해야 한다.
 */
fn for_each_logical_line(
    text: &str,
    mut emit: impl FnMut(bool, &str) -> Result<(), String>,
) -> Result<(), String> {
    let mut cur = String::new();
    let mut line = String::new();
    let mut cur_ws = false;
    let mut paren: i32 = 0;
    let mut in_logical = false;
    for raw in text.lines() {
        strip_comment_into(raw, &mut line);
        if !in_logical {
            if line.trim().is_empty() {
                continue;
            }
            cur.clear();
            cur_ws = line.starts_with([' ', '\t']);
            in_logical = true;
        } else {
            cur.push(' ');
        }
        cur.push_str(line.trim());
        paren += count_unquoted(&line, '(') - count_unquoted(&line, ')');
        if paren <= 0 {
            paren = 0;
            cur.retain(|c| c != '(' && c != ')');
            emit(cur_ws, &cur)?;
            in_logical = false;
        }
    }
    if in_logical {
        cur.retain(|c| c != '(' && c != ')');
        emit(cur_ws, &cur)?;
    }
    Ok(())
}

/**
 * @brief 주석을 떼어 낸다. 따옴표 안과 역슬래시 뒤의 세미콜론은 주석이 아니다.
 * @note 버퍼를 재사용해 줄마다 할당이 붙지 않게 한다.
 */
fn strip_comment_into(line: &str, out: &mut String) {
    out.clear();
    let mut in_q = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                out.push(c);
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            }
            '"' => {
                in_q = !in_q;
                out.push(c);
            }
            ';' if !in_q => break,
            _ => out.push(c),
        }
    }
}

/** @brief 따옴표 밖에 있는 특정 문자 수를 센다. 역슬래시 다음 문자는 건너뛴다. */
fn count_unquoted(s: &str, target: char) -> i32 {
    let mut n = 0;
    let mut in_q = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '"' => in_q = !in_q,
            _ if c == target && !in_q => n += 1,
            _ => {}
        }
    }
    n
}

/**
 * @brief 논리 줄을 토큰으로 나눈다.
 * @details 따옴표 안의 공백은 나누지 않고, 역슬래시 이스케이프는 그대로 남긴다. 해석은
 *          타입별 파서가 한다. 빈 따옴표쌍도 토큰 하나로 친다. TXT의 빈 문자열이다.
 */
fn tokenize(s: &str) -> Vec<String> {
    let mut toks = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    let mut quoted = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                cur.push('\\');
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            '"' => {
                in_q = !in_q;
                quoted = true;
            }
            _ if in_q => cur.push(c),
            _ if c.is_whitespace() => {
                if !cur.is_empty() || quoted {
                    toks.push(std::mem::take(&mut cur));
                    quoted = false;
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() || quoted {
        toks.push(cur);
    }
    toks
}

/**
 * @brief RRSIG가 덮는 종류 이름을 번호로.
 * @details 이름을 아는 종류는 약칭으로, 그 밖은 TYPEnnn으로 적힌다.
 */
fn rrsig_covered_type(tok: &str) -> Result<u16, String> {
    type_number(tok).ok_or_else(|| format!("Unknown type covered by RRSIG: {tok}"))
}

/**
 * @brief 종류 이름을 번호로. 이름을 모르면 TYPEnnn 형식만 받는다.
 * @details RecordType::name이 번호에서 이름으로 가는 유일한 테이블이라, 여기서 그 테이블을 되짚는다.
 */
fn type_number(tok: &str) -> Option<u16> {
    if let Some(digits) = tok
        .strip_prefix("TYPE")
        .or_else(|| tok.strip_prefix("type"))
    {
        return digits.parse().ok();
    }
    (1u16..=260).find(|n| {
        let name = RecordType(*n).name();
        name != "UNKNOWN" && name.eq_ignore_ascii_case(tok)
    })
}

/**
 * @brief NSEC과 NSEC3의 종류 비트맵을 만든다.
 *
 * @details RFC 4034가 정한 형식이다. 종류 번호의 상위 바이트로 윈도를 나누고, 윈도마다
 *          실제로 쓰인 마지막 바이트까지만 적는다. 윈도를 길이대로 자르지 않으면 검증기가
 *          비트맵을 다르게 읽어 부재 증명이 어긋난다.
 */
fn type_bitmap(toks: &[String]) -> Result<Vec<u8>, String> {
    let mut windows: std::collections::BTreeMap<u8, [u8; 32]> = std::collections::BTreeMap::new();
    for tok in toks {
        let number = type_number(tok).ok_or_else(|| format!("Unknown type: {tok}"))?;
        let window = (number >> 8) as u8;
        let bit = (number & 0xff) as usize;
        let bytes = windows.entry(window).or_insert([0u8; 32]);
        bytes[bit / 8] |= 0x80 >> (bit % 8);
    }
    let mut out = Vec::new();
    for (window, bytes) in windows {
        let len = bytes.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
        if len == 0 {
            continue;
        }
        out.push(window);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    Ok(out)
}

/**
 * @brief NSEC3와 NSEC3PARAM이 함께 쓰는 앞부분을 만든다.
 * @details 해시 알고리즘, 플래그, 반복 횟수, 소금이다. 소금 없음은 -로 적는다.
 */
fn nsec3_head(
    hash: &str,
    flags: &str,
    iterations: &str,
    salt: &str,
    rtype: &str,
) -> Result<Vec<u8>, String> {
    let hash: u8 = hash
        .parse()
        .map_err(|_| format!("Invalid {rtype} hash algorithm"))?;
    let flags: u8 = flags
        .parse()
        .map_err(|_| format!("Invalid {rtype} flags"))?;
    let iterations: u16 = iterations
        .parse()
        .map_err(|_| format!("Invalid {rtype} iteration count"))?;
    let salt = if salt == "-" {
        Vec::new()
    } else {
        hex_decode(salt).ok_or_else(|| format!("{rtype} salt is not hex"))?
    };
    let salt_len = u8::try_from(salt.len()).map_err(|_| format!("{rtype} salt is too long"))?;
    let mut wire = Vec::with_capacity(5 + salt.len());
    wire.push(hash);
    wire.push(flags);
    wire.extend_from_slice(&iterations.to_be_bytes());
    wire.push(salt_len);
    wire.extend_from_slice(&salt);
    Ok(wire)
}

/** @brief NSEC3의 해시 이름이 쓰는 base32hex를 푼다. 패딩은 받지 않는다. */
fn base32hex_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc = 0u64;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'A'..=b'V' => c - b'A' + 10,
            b'a'..=b'v' => c - b'a' + 10,
            b'=' => continue,
            _ => return None,
        };
        acc = (acc << 5) | u64::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/**
 * @brief RRSIG의 시각을 읽는다.
 * @details YYYYMMDDHHmmSS 형식과 초 단위 정수 둘 다 규격이 허용한다.
 * @return 1970년부터의 초.
 */
fn parse_dnssec_time(tok: &str) -> Result<u32, String> {
    if tok.len() != 14 || !tok.bytes().all(|b| b.is_ascii_digit()) {
        return tok
            .parse::<u32>()
            .map_err(|_| format!("Invalid RRSIG time: {tok}"));
    }
    let field = |range: std::ops::Range<usize>| -> u64 { tok[range].parse().unwrap_or(0) };
    let (year, month, day) = (field(0..4), field(4..6), field(6..8));
    let (hour, minute, second) = (field(8..10), field(10..12), field(12..14));
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(format!("Invalid RRSIG time: {tok}"));
    }
    /* 1970-01-01부터의 일수. 3월을 한 해의 시작으로 옮겨 윤년 보정을 한 줄로 만든다. */
    let shifted_year = if month <= 2 { year - 1 } else { year };
    let era = shifted_year / 400;
    let year_of_era = shifted_year - era * 400;
    let month_shift = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_shift + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = (era * 146_097 + day_of_era) as i64 - 719_468;
    let seconds = days * 86_400 + (hour * 3600 + minute * 60 + second) as i64;
    u32::try_from(seconds).map_err(|_| format!("RRSIG time is out of range: {tok}"))
}

/**
 * @brief zone 파일에 적힌 base64를 푼다.
 * @details DNSKEY와 RRSIG와 ech가 이 형식을 쓴다. 여러 토큰으로 나뉘어 오는 경우가 흔해
 *          공백은 건너뛴다.
 * @return 알파벳 밖 문자가 있으면 None.
 */
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    /** @brief 문자 하나를 6비트 값으로. */
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        if c.is_ascii_whitespace() {
            continue;
        }
        acc = (acc << 6) | u32::from(val(c)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/**
 * @brief 등록된 SvcParamKey 이름을 번호로.
 * @details RFC 9460의 등록부다. 이름이 아닌 keyNNNNN 형태는 호출자가 다룬다.
 */
fn svcb_key_number(name: &str) -> Option<u16> {
    Some(match name {
        "mandatory" => 0,
        "alpn" => 1,
        "no-default-alpn" => 2,
        "port" => 3,
        "ipv4hint" => 4,
        "ech" => 5,
        "ipv6hint" => 6,
        _ => return None,
    })
}

/**
 * @brief SvcParamKey 이름 또는 keyNNNNN을 번호로.
 * @details mandatory 값도 키 이름 목록이라 같은 규칙으로 푼다.
 */
fn svcb_key_of(name: &str) -> Result<u16, String> {
    if let Some(key) = svcb_key_number(name) {
        return Ok(key);
    }
    name.strip_prefix("key")
        .and_then(|digits| digits.parse::<u16>().ok())
        .ok_or_else(|| format!("Invalid SVCB parameter key: {name}"))
}

/**
 * @brief 쉼표로 나뉜 목록을 구분한다.
 *
 * @details RFC 9460 부록 A.1이 정한 규칙이다. 항목 안의 쉼표는 역슬래시로 막고, 역슬래시
 *          자신도 역슬래시로 막는다. 이스케이프를 먼저 풀면 막아 둔 쉼표와 구분자가
 *          같아져 잘못 갈라진다.
 */
fn split_escaped_list(value: &[u8]) -> Vec<Vec<u8>> {
    let mut items = vec![Vec::new()];
    let mut i = 0;
    while i < value.len() {
        match value[i] {
            b'\\' if i + 1 < value.len() => {
                items
                    .last_mut()
                    .expect("There is always at least one item")
                    .push(value[i + 1]);
                i += 2;
            }
            b',' => {
                items.push(Vec::new());
                i += 1;
            }
            byte => {
                items
                    .last_mut()
                    .expect("There is always at least one item")
                    .push(byte);
                i += 1;
            }
        }
    }
    items
}

/**
 * @brief SvcParam 하나를 번호와 wire 바이트로 옮긴다.
 *
 * @details RFC 9460은 값의 표시 형식을 키마다 따로 정한다. 등록된 키를 모르면 그
 *          영역을 아예 담지 못하므로, 실제로 쓰이는 일곱을 모두 다룬다. 등록부에 없는
 *          keyNNNNN은 같은 항이 정한 대로 character-string을 풀어 그대로 wire로 쓴다.
 * @param name 키 이름 또는 keyNNNNN.
 * @param value = 뒤의 토큰. 없으면 None.
 * @return 키 번호와 wire 바이트.
 */
fn svcb_param(name: &str, value: Option<&str>) -> Result<(u16, Vec<u8>), String> {
    let key = svcb_key_of(name)?;
    let raw = value.map(unescape_char_string).unwrap_or_default();
    let missing = |what: &str| format!("SVCB {what} has no value");

    let wire = match key {
        0 => {
            if raw.is_empty() {
                return Err(missing("mandatory"));
            }
            let mut keys = Vec::new();
            for item in split_escaped_list(&raw) {
                let item = String::from_utf8(item)
                    .map_err(|_| "Invalid SVCB mandatory value".to_string())?;
                keys.push(svcb_key_of(&item)?);
            }
            keys.sort_unstable();
            keys.dedup();
            keys.iter().flat_map(|k| k.to_be_bytes()).collect()
        }
        1 => {
            if raw.is_empty() {
                return Err(missing("alpn"));
            }
            let mut out = Vec::new();
            for id in split_escaped_list(&raw) {
                if id.is_empty() || id.len() > 255 {
                    return Err("Invalid SVCB alpn entry length".to_string());
                }
                out.push(id.len() as u8);
                out.extend_from_slice(&id);
            }
            out
        }
        2 => {
            if !raw.is_empty() {
                return Err("SVCB no-default-alpn takes no value".to_string());
            }
            Vec::new()
        }
        3 => {
            let text = String::from_utf8(raw).map_err(|_| missing("port"))?;
            let port: u16 = text.parse().map_err(|_| "Invalid SVCB port".to_string())?;
            port.to_be_bytes().to_vec()
        }
        4 | 6 => {
            if raw.is_empty() {
                return Err(missing(if key == 4 { "ipv4hint" } else { "ipv6hint" }));
            }
            let mut out = Vec::new();
            for item in split_escaped_list(&raw) {
                let text =
                    String::from_utf8(item).map_err(|_| "Invalid SVCB address hint".to_string())?;
                if key == 4 {
                    let ip: std::net::Ipv4Addr = text
                        .parse()
                        .map_err(|_| format!("Invalid SVCB ipv4hint address: {text}"))?;
                    out.extend_from_slice(&ip.octets());
                } else {
                    let ip: std::net::Ipv6Addr = text
                        .parse()
                        .map_err(|_| format!("Invalid SVCB ipv6hint address: {text}"))?;
                    out.extend_from_slice(&ip.octets());
                }
            }
            out
        }
        5 => {
            let text = String::from_utf8(raw).map_err(|_| missing("ech"))?;
            base64_decode(&text).ok_or("SVCB ech value is not valid base64")?
        }
        _ => raw,
    };
    Ok((key, wire))
}

/**
 * @brief 문자열 토큰의 역슬래시 이스케이프를 푼다.
 * @details 역슬래시 뒤 세 자리 십진수는 그 값의 바이트 하나가 된다. 255를 넘거나 자릿수가
 *          모자라면 이스케이프가 아니라 다음 문자 그대로다.
 * @note 바이트 단위로 다루므로 다중바이트 문자가 끼어도 인덱스가 어긋나지 않는다.
 */
pub(crate) fn unescape_char_string(tok: &str) -> Vec<u8> {
    let b = tok.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            if b[i + 1].is_ascii_digit()
                && i + 3 < b.len()
                && b[i + 2].is_ascii_digit()
                && b[i + 3].is_ascii_digit()
            {
                let d = (b[i + 1] - b'0') as u16 * 100
                    + (b[i + 2] - b'0') as u16 * 10
                    + (b[i + 3] - b'0') as u16;
                if d <= 255 {
                    out.push(d as u8);
                    i += 4;
                    continue;
                }
            }
            out.push(b[i + 1]);
            i += 2;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/** @brief 파서의 형식 처리와, 어떤 쓰레기 입력에도 패닉하지 않음. */
#[cfg(test)]
mod tests {
    use super::*;

    /** @brief 편집기가 붙인 BOM이 첫 레코드를 삼키지 않는지. */
    #[test]
    fn utf8_bom_prefixed_zone_parses() {
        let body = "$ORIGIN bom.test.\n@ IN SOA ns admin 1 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\nwww IN A 192.0.2.2\n";
        let with_bom = format!("\u{feff}{body}");
        let plain = parse_zone(body, "bom.test").unwrap();
        let bommed = parse_zone(&with_bom, "bom.test").unwrap();
        assert_eq!(bommed.soa().serial, plain.soa().serial);
        assert_eq!(
            bommed.axfr_records().len(),
            plain.axfr_records().len(),
            "BOM이 첫 레코드를 삼키면 안 된다"
        );
    }

    /** @brief 숫자와 접미사 조합이 모두 같은 초로 풀리는지. */
    #[test]
    fn parse_ttl_suffixes() {
        assert_eq!(parse_ttl("3600").unwrap(), 3600);
        assert_eq!(parse_ttl("1h").unwrap(), 3600);
        assert_eq!(parse_ttl("1d").unwrap(), 86_400);
        assert_eq!(parse_ttl("1h30m").unwrap(), 5400);
        assert!(parse_ttl("xx").is_err());
    }

    /** @brief 따옴표 안의 공백이 토큰을 나누지 않는지. */
    #[test]
    fn tokenize_quoted_txt() {
        let t = tokenize(r#"@ IN TXT "hello world" "more""#);
        assert_eq!(t, vec!["@", "IN", "TXT", "hello world", "more"]);
    }

    /** @brief 다중바이트 문자가 섞여도 인덱스가 문자 경계를 벗어나지 않는지. */
    #[test]
    fn hex_decode_no_panic_on_multibyte() {
        assert!(hex_decode("€a").is_none());
        assert!(hex_decode("€€").is_none());
        assert_eq!(hex_decode("ff00").unwrap(), vec![0xff, 0x00]);
        assert!(hex_decode("fff").is_none());
    }

    /** @brief 십진 이스케이프와 문자 이스케이프가 각각 옳은 바이트로 풀리는지. */
    #[test]
    fn unescape_roundtrips_decimal_and_char_escapes() {
        assert_eq!(unescape_char_string(r"a\010b"), vec![b'a', 10, b'b']);
        assert_eq!(unescape_char_string(r#"\"\\"#), vec![b'"', b'\\']);
        assert_eq!(unescape_char_string(r"\255"), vec![0xff]);
        assert_eq!(unescape_char_string("plain"), b"plain".to_vec());
    }

    /**
     * @brief 영역 파일의 ZONEMD 표기를 읽는지.
     * @details ZONEMD를 붙여 공표한 영역 파일을 읽지 못하면 영역 전체를 담지 못하고, 영역
     *          요약 검사도 쓸 수 없다.
     */
    #[test]
    fn zonemd_presentation_parses_to_wire() {
        let origin = Name::from_str("example").unwrap();
        let digest = "c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c";
        let line = format!("ZONEMD 2018031900 1 1 {} {}", &digest[..48], &digest[48..]);
        let RData::Unknown(63, wire) =
            parse_rdata("ZONEMD", &tokenize(&line)[1..], &origin).unwrap()
        else {
            panic!("ZONEMD는 타입 번호와 원래 바이트로 담긴다");
        };
        assert_eq!(&wire[..4], &2018031900u32.to_be_bytes());
        assert_eq!(&wire[4..6], &[1, 1]);
        assert_eq!(wire.len(), 6 + 48);
        assert!(parse_rdata("ZONEMD", &tokenize("ZONEMD 1 1 1 00ff")[1..], &origin).is_err());

        let text = format!(
            "$ORIGIN example.\n@ 86400 IN SOA ns1 admin 2018031900 1800 900 604800 86400\n@ 86400 IN NS ns1\nns1 3600 IN A 203.0.113.63\n@ 86400 IN ZONEMD 2018031900 1 1 (\n {}\n {} )\n",
            &digest[..48],
            &digest[48..]
        );
        parse_zone(&text, "example").expect("괄호로 나눈 ZONEMD가 든 영역");
    }

    /** @brief 미해석 RDATA의 16진 토큰에 다중바이트가 들어와도 패닉하지 않는지. */
    #[test]
    fn hex_rdata_multibyte_token_does_not_panic() {
        let origin = Name::from_str("example.com").unwrap();
        for line in ["TLSA 3 1 1 €a", "SSHFP 4 2 €a", "TYPE99 \\# 2 €a"] {
            let toks = tokenize(line);
            let _ = parse_rdata(line.split(' ').next().unwrap(), &toks[1..], &origin);
        }
    }

    /** @brief 타입별 RDATA가 제대로 구조화되는지. 각 타입의 토큰 배치를 한데 고정한다. */
    #[test]
    fn typed_rdata_zone_parse() {
        let origin = Name::from_str("example.com").unwrap();
        let pr = |line: &str| {
            parse_rdata(
                line.split(' ').next().unwrap(),
                &tokenize(line)[1..],
                &origin,
            )
        };

        assert!(matches!(
            pr("TLSA 3 1 1 abcdef").unwrap(),
            RData::Tlsa {
                usage: 3,
                selector: 1,
                matching: 1,
                ..
            }
        ));

        assert!(matches!(
            pr("SSHFP 4 2 001122").unwrap(),
            RData::Sshfp {
                algorithm: 4,
                fp_type: 2,
                ..
            }
        ));

        let n = pr(r#"NAPTR 100 10 "U" "E2U+sip" "!regexp!" _sip.example.com"#).unwrap();
        assert!(matches!(
            n,
            RData::Naptr(ref naptr) if naptr.order == 100 && naptr.preference == 10
        ));

        assert!(matches!(
            pr(r#"URI 10 1 "https://ex.com/""#).unwrap(),
            RData::Uri {
                priority: 10,
                weight: 1,
                ..
            }
        ));

        let s = pr("SVCB 1 svc.example.net port=443").unwrap();
        match s {
            RData::Svcb {
                priority, params, ..
            } => {
                assert_eq!(priority, 1);
                assert_eq!(params[0].0, 3);
                assert_eq!(params[0].1.as_ref(), [0x01, 0xbb]);
            }
            _ => panic!("SVCB 기대"),
        }
        assert!(matches!(
            pr("HTTPS 0 svc.example.net").unwrap(),
            RData::Https { priority: 0, .. }
        ));

        let reordered = pr("SVCB 1 svc.example.net port=443 alpn=h2").unwrap();
        assert!(matches!(
            reordered,
            RData::Svcb {
                params,
                ..
            } if params.iter().map(|(key, _)| *key).collect::<Vec<_>>() == vec![1, 3]
        ));
        assert!(pr("SVCB 1 svc.example.net port=443 port=444").is_err());
        assert!(pr("SVCB 1 svc.example.net key2").is_err());

        /* RFC 9460이 정한 등록 키와 그 값 형식. 셋 다 wire 바이트까지 확인한다. */
        let full = pr("HTTPS 1 svc.example.net alpn=h2,h3 port=8443 ipv4hint=192.0.2.1,192.0.2.2")
            .expect("등록된 키를 읽어야 합니다");
        match full {
            RData::Https { params, .. } => {
                let by_key = |k: u16| {
                    params
                        .iter()
                        .find(|(key, _)| *key == k)
                        .map(|(_, v)| v.to_vec())
                        .unwrap_or_default()
                };
                assert_eq!(by_key(1), b"h2h3", "alpn은 길이 프리픽스가 붙는다");
                assert_eq!(by_key(3), vec![0x20, 0xfb], "port는 2바이트 정수다");
                assert_eq!(by_key(4), vec![192, 0, 2, 1, 192, 0, 2, 2]);
            }
            other => panic!("HTTPS 기대: {other:?}"),
        }

        /* 항목 안의 쉼표는 역슬래시로 막는다. 먼저 이스케이프를 풀면 구분자와 섞인다. */
        match pr(r"SVCB 1 . alpn=one\\,two").expect("막은 쉼표") {
            RData::Svcb { params, .. } => {
                assert_eq!(params[0].1.as_ref(), b"one,two");
            }
            other => panic!("SVCB 기대: {other:?}"),
        }

        /* 등록부에 없는 키의 값은 16진수가 아니라 character-string이다. */
        match pr("SVCB 1 . key65000=hello").expect("미등록 키") {
            RData::Svcb { params, .. } => assert_eq!(params[0].1.as_ref(), b"hello"),
            other => panic!("SVCB 기대: {other:?}"),
        }

        assert!(pr("SVCB 1 . port=notanumber").is_err());
        assert!(pr("SVCB 1 . ipv4hint=2001:db8::1").is_err());

        /*
         * RFC 4034가 정한 DNSSEC 표시 형식. 미리 서명된 zone을 담지 못하면 온라인 서명
         * 말고는 길이 없다. wire 바이트까지 확인한다. BIND와 대조해 얻은 값이다.
         */
        match pr("DNSKEY 256 3 13 AQIDBA==").expect("DNSKEY") {
            RData::Unknown(48, wire) => {
                assert_eq!(wire, vec![0x01, 0x00, 3, 13, 1, 2, 3, 4]);
            }
            other => panic!("DNSKEY 기대: {other:?}"),
        }
        match pr("CDNSKEY 257 3 13 AQIDBA==").expect("CDNSKEY") {
            RData::Unknown(60, wire) => assert_eq!(wire[..4], [0x01, 0x01, 3, 13]),
            other => panic!("CDNSKEY 기대: {other:?}"),
        }
        match pr("CDS 12345 13 2 0123").expect("CDS") {
            RData::Unknown(59, wire) => assert_eq!(wire, vec![0x30, 0x39, 13, 2, 0x01, 0x23]),
            other => panic!("CDS 기대: {other:?}"),
        }
        match pr("RRSIG A 13 3 3600 20260901000000 20260801000000 12345 sec.test. AQIDBA==")
            .expect("RRSIG")
        {
            RData::Unknown(46, wire) => {
                assert_eq!(wire[..2], [0, 1], "덮는 종류는 A(1)");
                assert_eq!(wire[2..4], [13, 3], "알고리즘과 라벨 수");
                assert_eq!(wire[4..8], 3600u32.to_be_bytes(), "원래 수명");
                assert_eq!(
                    u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]),
                    1_788_220_800,
                    "20260901000000은 1970년 기준 1788220800초"
                );
                assert_eq!(wire[16..18], [0x30, 0x39], "키 태그");
            }
            other => panic!("RRSIG 기대: {other:?}"),
        }
        match pr("NSEC next.sec.test. A AAAA RRSIG NSEC").expect("NSEC") {
            RData::Unknown(47, wire) => {
                /* 이름 뒤가 비트맵이다. 윈도 0, 길이 6, A(1) AAAA(28) RRSIG(46) NSEC(47). */
                let bitmap = &wire[wire.len() - 8..];
                assert_eq!(bitmap, [0x00, 0x06, 0x40, 0x00, 0x00, 0x08, 0x00, 0x03]);
            }
            other => panic!("NSEC 기대: {other:?}"),
        }
        match pr("NSEC3PARAM 1 0 0 aabbcc").expect("NSEC3PARAM") {
            RData::Unknown(51, wire) => {
                assert_eq!(wire, vec![1, 0, 0, 0, 3, 0xaa, 0xbb, 0xcc]);
            }
            other => panic!("NSEC3PARAM 기대: {other:?}"),
        }
        match pr("NSEC3PARAM 1 0 0 -").expect("소금 없음") {
            RData::Unknown(51, wire) => assert_eq!(wire, vec![1, 0, 0, 0, 0]),
            other => panic!("NSEC3PARAM 기대: {other:?}"),
        }
        match pr("NSEC3 1 1 0 aabbcc CPNMU0BE4E8O6PJ9RGCSNJ4EJ6A6AL5T A RRSIG").expect("NSEC3") {
            RData::Unknown(50, wire) => {
                assert_eq!(wire[..5], [1, 1, 0, 0, 3], "해시·플래그·반복·소금 길이");
                assert_eq!(wire[8], 20, "SHA-1 해시는 20바이트");
                assert_eq!(wire[9..11], [0x66, 0x6f], "base32hex를 푼 앞 두 바이트");
                assert_eq!(wire[wire.len() - 8..], [0, 6, 0x40, 0, 0, 0, 0, 2]);
            }
            other => panic!("NSEC3 기대: {other:?}"),
        }
        /* 이름을 모르는 종류는 TYPEnnn으로 비트맵에 넣을 수 있어야 한다. */
        assert!(pr("NSEC next.sec.test. A TYPE300").is_ok());
        assert!(pr("DNSKEY 256 3 13 !!!not-base64!!!").is_err());
        assert!(pr("RRSIG A 13 3 3600 20261301000000 20260801000000 1 . AQ==").is_err());

        match pr("DS 3643 13 2 20e3e957e3b70393").unwrap() {
            RData::Unknown(43, wire) => {
                assert_eq!(&wire[0..2], &3643u16.to_be_bytes());
                assert_eq!(wire[2], 13);
                assert_eq!(wire[3], 2);
                assert_eq!(
                    &wire[4..],
                    &[0x20, 0xe3, 0xe9, 0x57, 0xe3, 0xb7, 0x03, 0x93]
                );
            }
            other => panic!("DS를 TYPE43 opaque로 기대: {other:?}"),
        }
        assert!(pr("DS 3643 13 2").is_err(), "다이제스트 누락 거부");
        assert!(pr("DS 3643 13 2 zz").is_err(), "16진수 오류 거부");
    }

    /**
     * @brief 아무 입력이 와도 오류로 끝날 뿐 패닉하지 않는다.
     * @details 컨트롤 플레인으로 zone 텍스트를 올릴 수 있으므로 이 파서는 신뢰 경계에 있다.
     */
    #[test]
    fn parser_no_panic_on_garbage() {
        let mut seed: u32 = 0x2545_f491;
        let mut rng = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        /** @brief 망가뜨릴 때 끼워 넣을 글자들. */
        const CH: &[u8] = b"abcXYZ0123 .@\t\n\";()$ORIGIN TTLINSOAANSAAA*";
        for _ in 0..3000 {
            let len = (rng() % 160) as usize;
            let s: String = (0..len)
                .map(|_| CH[(rng() as usize) % CH.len()] as char)
                .collect();
            let _ = parse_zone(&s, "example.com");
        }

        for t in [
            "",
            "@ IN",
            "$ORIGIN",
            "$TTL",
            "x IN A",
            "@ IN SOA",
            "( ( (",
            "\"unterminated",
            "@ IN A 999.999.999.999",
            "@ 99999999999999999999 IN A 1.2.3.4",
        ] {
            let _ = parse_zone(t, "example.com");
        }
    }
}
