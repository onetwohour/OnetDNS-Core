/*!
 * @brief 차단 목록 형식 파서.
 *
 * @details AdGuard, ABP, hosts, RPZ를 모두 읽는다. 어느 형식이든 결국 도메인 집합과
 *          규칙 목록으로 수렴한다.
 * @warning 파일을 읽지 못하면 실패로 끝난다. 조용히 넘어가면 필터가 전부 사라진 채
 *          정상 시작한 것처럼 보인다. 파일 하나가 어긋나면 그 파일의 규칙을 하나도
 *          적용하지 않는다. 절반만 걸린 필터는 없느니만 못하다.
 */

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::Path;

/** @brief 읽어 들일 목록 파일 크기 상한. */
const MAX_LOCAL_LIST_FILE: u64 = 128 * 1024 * 1024;
/** @brief 목록 한 줄의 길이 상한. */
const MAX_LOCAL_LIST_LINE: u64 = 1024 * 1024;

/** @brief 상한 초과 오류를 만든다. */
fn list_too_large() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "Filter list exceeds the 128 MiB size limit",
    )
}

/** @brief 상한을 지키며 한 줄을 읽는다. */
fn read_list_line(reader: &mut impl BufRead, line: &mut String) -> std::io::Result<usize> {
    let mut bounded = reader.take(MAX_LOCAL_LIST_LINE + 1);
    let read = bounded.read_line(line)?;
    if read as u64 > MAX_LOCAL_LIST_LINE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Filter rule line exceeds the 1 MiB size limit",
        ));
    }
    Ok(read)
}

/** @brief 목록 파일을 열고 크기와 형식을 확인한다. */
fn open_validated_list_file(path: &Path) -> std::io::Result<File> {
    let mut file = File::open(path)?;
    {
        let mut reader = BufReader::new((&mut file).take(MAX_LOCAL_LIST_FILE + 1));
        let mut line = String::new();
        let mut total = 0u64;
        loop {
            line.clear();
            let read = read_list_line(&mut reader, &mut line)?;
            if read == 0 {
                break;
            }
            total = total.saturating_add(read as u64);
            if total > MAX_LOCAL_LIST_FILE {
                return Err(list_too_large());
            }
        }
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

/**
 * @brief 파일의 모든 줄을 넘겨준다.
 * @warning 도중에 실패하면 전부 오류다. 호출자는 그 파일의 규칙을 하나도 적용하지 않는다.
 */
fn parse_validated_list_file(file: File, mut on_line: impl FnMut(&str)) -> std::io::Result<()> {
    let mut reader = BufReader::new(file.take(MAX_LOCAL_LIST_FILE + 1));
    let mut line = String::new();
    let mut total = 0u64;
    loop {
        line.clear();
        let read = read_list_line(&mut reader, &mut line)?;
        if read == 0 {
            return Ok(());
        }
        total = total.saturating_add(read as u64);
        if total > MAX_LOCAL_LIST_FILE {
            return Err(list_too_large());
        }
        on_line(&line);
    }
}

use crate::regex::Regex;
use onetdns_core::{BlockResponse, FilterVerdict, IpNet, RewriteTarget};
use onetdns_proto::{Name, RecordType};

use crate::engine::{BlockEngine, DomainSet, EngineParts, RpzIpRule, RpzNameRule};

#[derive(Default)]
/** @brief 목록을 읽는 동안 쌓이는 것들. 규칙, 집합, 보고가 여기 모인다. */
struct Accum {
    /** @brief 만드는 중인 엔진 부품. */
    parts: EngineParts,

    /** @brief 무효로 만들 규칙들. 나중에 걷어 낸다. */
    badfilter: Vec<String>,
    /** @brief 무효로 만들 정규식 규칙들. */
    badfilter_regex: Vec<String>,

    /** @brief 지금 읽고 있는 목록 번호. */
    cur_source: u32,
}

impl Accum {
    /** @brief 빈 상태. */
    fn new() -> Self {
        Accum {
            cur_source: crate::engine::NO_SOURCE,
            ..Default::default()
        }
    }

    /** @brief 목록 하나를 출처로 등록하고 번호를 받는다. */
    fn register_source(&mut self, name: String) {
        self.cur_source = self.parts.sources.len() as u32;
        self.parts.sources.push(name);
    }
}

/** @brief 규칙 본문과 수식어를 구분한다. */
fn split_mods(s: &str) -> (&str, Vec<&str>) {
    match s.find('$') {
        Some(i) => (&s[..i], s[i + 1..].split(',').collect()),
        None => (s, vec![]),
    }
}

/** @brief 해석한 수식어들. */
struct RuleMods<'a> {
    /** @brief 무엇보다 먼저 보라는 표시. */
    important: bool,
    /** @brief 다른 규칙을 무효로 만드는 규칙인지. */
    badfilter: bool,
    /** @brief 이 종류에만 건다. */
    dnstypes: Vec<RecordType>,
    /** @brief 이 종류는 빼고 건다. */
    dnstype_excluded: Vec<RecordType>,
    /** @brief 다른 답으로 바꾸라는 지시. */
    dnsrewrite: Option<&'a str>,
    /** @brief 이 클라이언트들에만 건다. */
    client_conds: Vec<crate::engine::ClientCond>,
    /** @brief 이 태그에만 건다. */
    ctags: Vec<(bool, String)>,
    /** @brief 이 이름들은 뺀다. */
    denyallow: Vec<String>,
}

/**
 * @brief 수식어 목록을 해석한다.
 * @note 이 서버와 무관한 브라우저 전용 수식어는 오류가 아니라 적용 대상 아님으로 분류한다.
 *       오류로 세면 보고가 실제 문제를 가린다.
 */
fn parse_mods<'a>(mods: &[&'a str], acc: &mut Accum, line: &str) -> Option<RuleMods<'a>> {
    let mut out = RuleMods {
        important: false,
        badfilter: false,
        dnstypes: vec![],
        dnstype_excluded: vec![],
        dnsrewrite: None,
        client_conds: vec![],
        ctags: vec![],
        denyallow: vec![],
    };
    let mut dnstype_present = false;
    for m in mods {
        let m = m.trim();
        if m.is_empty() {
            continue;
        } else if m == "important" {
            out.important = true;
        } else if m == "badfilter" {
            out.badfilter = true;
        } else if let Some(v) = m.strip_prefix("dnstype=") {
            dnstype_present = true;
            for t in v.split('|') {
                let t = t.trim();

                if let Some(rest) = t.strip_prefix('~') {
                    if let Some(rt) = parse_rtype(rest) {
                        out.dnstype_excluded.push(rt);
                    }
                } else if let Some(rt) = parse_rtype(t) {
                    out.dnstypes.push(rt);
                }
            }
        } else if let Some(v) = m.strip_prefix("dnsrewrite=") {
            out.dnsrewrite = Some(v);
        } else if let Some(v) = m.strip_prefix("client=") {
            for part in v.split('|') {
                let (negated, val) = match part.strip_prefix('~') {
                    Some(r) => (true, r.trim()),
                    None => (false, part.trim()),
                };
                if val.is_empty() {
                    continue;
                }

                match val.parse::<onetdns_core::IpNet>() {
                    Ok(net) => out
                        .client_conds
                        .push(crate::engine::ClientCond::Net { negated, net }),
                    Err(_) => out.client_conds.push(crate::engine::ClientCond::Id {
                        negated,
                        id: val.to_string(),
                    }),
                }
            }
        } else if let Some(v) = m.strip_prefix("ctag=") {
            for part in v.split('|') {
                let (negated, val) = match part.strip_prefix('~') {
                    Some(r) => (true, r.trim()),
                    None => (false, part.trim()),
                };
                if !val.is_empty() {
                    out.ctags.push((negated, val.to_ascii_lowercase()));
                }
            }
        } else if let Some(v) = m.strip_prefix("denyallow=") {
            for part in v.split('|') {
                let d = part.trim().trim_start_matches("*.").to_ascii_lowercase();
                if !d.is_empty() {
                    out.denyallow.push(d);
                }
            }
        } else {
            onetdns_core::trace!(modifier = m, "Excluded a rule with an unsupported modifier");
            let key = m.split('=').next().unwrap_or(m).trim_start_matches('~');
            acc.parts.report.rules_skipped += 1;
            if is_network_modifier(key) {
                acc.parts.report.not_applicable += 1;
            } else {
                *acc.parts
                    .report
                    .unsupported_modifier
                    .entry(key.to_string())
                    .or_default() += 1;
            }
            return None;
        }
    }

    if dnstype_present && out.dnstypes.is_empty() && out.dnstype_excluded.is_empty() {
        onetdns_core::debug!(
            event = "filter.dnstype_rule_invalid",
            rule = line,
            "Excluded a rule whose dnstype modifier has no valid record type"
        );
        acc.parts.report.rules_skipped += 1;
        acc.parts.report.invalid_pattern += 1;
        return None;
    }
    Some(out)
}

/** @brief 정규식 규칙에서 패턴과 수식어를 구분한다. */
fn split_regex_rule(body: &str) -> Option<(&str, Vec<&str>)> {
    let rest = body.strip_prefix('/')?;
    let bytes = rest.as_bytes();
    let mut close = None;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'/' && (i + 1 == bytes.len() || bytes[i + 1] == b'$') {
            close = Some(i);
        }
    }
    let close = close?;
    let pat = &rest[..close];
    if pat.is_empty() {
        return None;
    }
    let mods = match rest[close + 1..].strip_prefix('$') {
        Some(tail) => tail.split(',').collect(),
        None => vec![],
    };
    Some((pat, mods))
}

/** @brief 정규식 규칙을 수식어에 따라 알맞은 집합으로 보낸다. */
fn route_regex_rule(pat: &str, m: RuleMods, allow: bool, acc: &mut Accum) {
    let RuleMods {
        important,
        badfilter,
        dnstypes,
        mut dnstype_excluded,
        dnsrewrite,
        client_conds,
        ctags,
        denyallow,
    } = m;

    if !client_conds.is_empty() || !ctags.is_empty() || !denyallow.is_empty() {
        acc.parts.client_rules.push(crate::engine::ClientRule {
            domain: String::new(),
            regex: Some(pat.to_string()),
            allow,
            clients: client_conds,
            ctags,
            denyallow,
        });
        return;
    }

    if let Some(v) = dnsrewrite {
        if !apply_regex_dnsrewrite(pat, v, &mut acc.parts) {
            skip_invalid_pattern(acc);
        }
        return;
    }

    if badfilter {
        acc.badfilter_regex.push(pat.to_string());
        return;
    }

    if !dnstype_excluded.is_empty() && !allow {
        dnstype_excluded.sort_by_key(|t| t.0);
        dnstype_excluded.dedup();
        acc.parts
            .regex_typed_block_except
            .push((dnstype_excluded, pat.to_string()));
        return;
    }

    if !dnstypes.is_empty() && !allow {
        for t in dnstypes {
            acc.parts.regex_typed_block.push((t, pat.to_string()));
        }
        return;
    }

    let list = match (allow, important) {
        (true, true) => &mut acc.parts.regex_allow_important,
        (true, false) => &mut acc.parts.regex_allow,
        (false, true) => &mut acc.parts.regex_block_important,
        (false, false) => &mut acc.parts.regex_block,
    };
    list.push(pat.to_string());
}

/**
 * @brief 규칙 한 줄을 읽어 알맞은 집합에 넣는다.
 * @details 형식이 여럿이라 접두 문자로 구분된다. 두 세로줄은 도메인, 골뱅이 둘은 허용,
 *          빗금은 정규식, 그 밖에는 hosts 형식이나 평범한 도메인이다.
 */
fn parse_line(line: &str, acc: &mut Accum, into_allow: bool) {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
        return;
    }

    acc.parts.report.rules_total += 1;
    let src = acc.cur_source;

    let (body, force_allow) = match line.strip_prefix("@@") {
        Some(r) => (r, true),
        None => (line, false),
    };
    let allow = into_allow || force_allow;

    if body.starts_with('/') {
        let Some((pat, mods)) = split_regex_rule(body) else {
            acc.parts.report.rules_skipped += 1;
            acc.parts.report.invalid_regex += 1;
            return;
        };
        if let Err(error) = Regex::new(pat) {
            onetdns_core::debug!(event = "filter.regex_rule_invalid", pat, %error, "Could not compile a regex rule; excluded it");
            acc.parts.report.rules_skipped += 1;
            acc.parts.report.invalid_regex += 1;
            return;
        }
        let Some(m) = parse_mods(&mods, acc, line) else {
            return;
        };
        route_regex_rule(pat, m, allow, acc);
        return;
    }

    let (pattern, mods) = split_mods(body);
    let Some(m) = parse_mods(&mods, acc, line) else {
        return;
    };
    let RuleMods {
        important,
        badfilter,
        dnstypes,
        mut dnstype_excluded,
        dnsrewrite,
        client_conds,
        ctags,
        denyallow,
    } = m;

    if !client_conds.is_empty() || !ctags.is_empty() || !denyallow.is_empty() {
        let domain = if pattern.trim().is_empty() || pattern.trim() == "*" {
            String::new()
        } else {
            match extract_domain(pattern) {
                Some(d) => crate::engine::normalize_str(&d),
                None => {
                    skip_invalid_pattern(acc);
                    return;
                }
            }
        };
        acc.parts.client_rules.push(crate::engine::ClientRule {
            domain,
            regex: None,
            allow,
            clients: client_conds,
            ctags,
            denyallow,
        });
        return;
    }

    if let Some(v) = dnsrewrite {
        match extract_domain(pattern) {
            Some(dom) => {
                if !apply_dnsrewrite(&dom, v, &mut acc.parts, src) {
                    skip_invalid_pattern(acc);
                }
            }
            None => skip_invalid_pattern(acc),
        }
        return;
    }

    let mut toks = pattern.split_whitespace();
    if let Some(first) = toks.clone().next() {
        if let Ok(ip) = first.parse::<IpAddr>() {
            toks.next();
            for host in toks {
                let host = host.trim();
                if host.is_empty() || host.eq_ignore_ascii_case("localhost") {
                    continue;
                }
                if is_unspecified_or_loopback(&ip) {
                    target_set(&mut acc.parts, allow, important, false).add_exact_src(host, src);
                } else {
                    acc.parts.rewrites.add_exact(host, RewriteTarget::ip(ip));
                }
            }
            return;
        }
    }

    let dom = match extract_domain(pattern) {
        Some(d) => d,
        None => {
            skip_invalid_pattern(acc);
            return;
        }
    };

    if badfilter {
        acc.badfilter.push(dom);
        return;
    }

    if allow && (!dnstypes.is_empty() || !dnstype_excluded.is_empty()) {
        acc.parts.report.rules_skipped += 1;
        *acc.parts
            .report
            .unsupported_modifier
            .entry("dnstype(allow)".to_string())
            .or_default() += 1;
        return;
    }

    if !dnstype_excluded.is_empty() && !allow {
        dnstype_excluded.sort_by_key(|t| t.0);
        dnstype_excluded.dedup();
        typed_except_set(&mut acc.parts, &dnstype_excluded).add_suffix_src(&dom, src);
        return;
    }

    if !dnstypes.is_empty() && !allow {
        for t in dnstypes {
            typed_set(&mut acc.parts, t).add_suffix_src(&dom, src);
        }
        return;
    }

    target_set(&mut acc.parts, allow, important, false).add_suffix_src(&dom, src);
}

/** @brief 잘못된 패턴을 건너뛴 것으로 센다. */
fn skip_invalid_pattern(acc: &mut Accum) {
    acc.parts.report.rules_skipped += 1;
    acc.parts.report.invalid_pattern += 1;
}

/** @brief 이 수식어가 브라우저 전용인지. DNS 서버에는 적용 대상이 아니다. */
fn is_network_modifier(key: &str) -> bool {
    matches!(
        key,
        "third-party"
            | "3p"
            | "first-party"
            | "1p"
            | "document"
            | "doc"
            | "script"
            | "image"
            | "stylesheet"
            | "css"
            | "object"
            | "xmlhttprequest"
            | "xhr"
            | "subdocument"
            | "ping"
            | "websocket"
            | "webrtc"
            | "font"
            | "media"
            | "other"
            | "popup"
            | "object-subrequest"
            | "elemhide"
            | "ehide"
            | "generichide"
            | "ghide"
            | "specifichide"
            | "shide"
            | "content"
            | "jsinject"
            | "urlblock"
            | "genericblock"
            | "extension"
            | "removeparam"
            | "redirect"
            | "redirect-rule"
            | "csp"
            | "replace"
            | "cookie"
            | "header"
            | "method"
            | "removeheader"
            | "domain"
            | "match-case"
            | "all"
    )
}

/** @brief 수식어에 맞는 대상 집합을 고른다. */
fn target_set(
    parts: &mut EngineParts,
    allow: bool,
    important: bool,
    refuse: bool,
) -> &mut DomainSet {
    if refuse {
        &mut parts.refuse
    } else {
        match (allow, important) {
            (true, true) => &mut parts.allow_important,
            (true, false) => &mut parts.allow,
            (false, true) => &mut parts.block_important,
            (false, false) => &mut parts.block,
        }
    }
}

/** @brief 이 타입 전용 집합. */
fn typed_set(parts: &mut EngineParts, t: RecordType) -> &mut DomainSet {
    if let Some(idx) = parts.typed_block.iter().position(|(rt, _)| *rt == t) {
        &mut parts.typed_block[idx].1
    } else {
        let idx = parts.typed_block.len();
        parts.typed_block.push((t, DomainSet::default()));
        &mut parts.typed_block[idx].1
    }
}

/** @brief 나열한 타입을 뺀 나머지에 걸리는 집합. */
fn typed_except_set<'a>(parts: &'a mut EngineParts, excluded: &[RecordType]) -> &'a mut DomainSet {
    if let Some(idx) = parts
        .typed_block_except
        .iter()
        .position(|(e, _)| e == excluded)
    {
        &mut parts.typed_block_except[idx].1
    } else {
        let idx = parts.typed_block_except.len();
        parts
            .typed_block_except
            .push((excluded.to_vec(), DomainSet::default()));
        &mut parts.typed_block_except[idx].1
    }
}

/** @brief 재작성 규칙을 적용한다. 주소, 이름, 응답 코드를 지정할 수 있다. */
fn apply_dnsrewrite(dom: &str, value: &str, parts: &mut EngineParts, src: u32) -> bool {
    let segs: Vec<&str> = value.split(';').collect();
    let val = if segs.len() == 3 { segs[2] } else { segs[0] };
    let upper = val.trim().to_ascii_uppercase();

    match upper.as_str() {
        "NXDOMAIN" => {
            parts.block.add_suffix_src(dom, src);
            return true;
        }
        "REFUSED" => {
            parts.refuse.add_suffix_src(dom, src);
            return true;
        }
        "" | "NODATA" | "NOERROR" => {
            parts.nodata.add_suffix_src(dom, src);
            return true;
        }
        "NORESPONSE" => {
            parts.no_response.add_suffix_src(dom, src);
            return true;
        }
        _ => {}
    }

    if let Ok(ip) = val.parse::<IpAddr>() {
        parts.rewrites.add_suffix(dom, RewriteTarget::ip(ip));
        return true;
    }
    if looks_like_domain(val) {
        if let Ok(name) = Name::from_str(val) {
            parts.rewrites.add_suffix(dom, RewriteTarget::Cname(name));
            return true;
        }
    }
    false
}

/** @brief 정규식 규칙의 재작성을 적용한다. */
fn apply_regex_dnsrewrite(pat: &str, value: &str, parts: &mut EngineParts) -> bool {
    let segs: Vec<&str> = value.split(';').collect();
    let val = if segs.len() == 3 { segs[2] } else { segs[0] };
    let upper = val.trim().to_ascii_uppercase();

    match upper.as_str() {
        "NXDOMAIN" => {
            parts.regex_block.push(pat.to_string());
            return true;
        }
        "REFUSED" => {
            parts.regex_refuse.push(pat.to_string());
            return true;
        }
        "" | "NODATA" | "NOERROR" => {
            parts.regex_nodata.push(pat.to_string());
            return true;
        }
        "NORESPONSE" => {
            parts.regex_no_response.push(pat.to_string());
            return true;
        }
        _ => {}
    }

    if let Ok(ip) = val.parse::<IpAddr>() {
        parts
            .regex_rewrites
            .push((pat.to_string(), RewriteTarget::ip(ip)));
        return true;
    }
    if looks_like_domain(val) {
        if let Ok(name) = Name::from_str(val) {
            parts
                .regex_rewrites
                .push((pat.to_string(), RewriteTarget::Cname(name)));
            return true;
        }
    }
    false
}

/** @brief 패턴에서 도메인 부분을 추출한다. 도메인 형태가 아니면 없다. */
fn extract_domain(pattern: &str) -> Option<String> {
    let p = pattern.trim();
    let p = p.strip_prefix("||").unwrap_or(p);
    let p = p.strip_prefix('|').unwrap_or(p);
    let end = p.find(['^', '/', '*', '|']).unwrap_or(p.len());
    let dom = &p[..end];
    if looks_like_domain(dom) {
        Some(dom.to_string())
    } else {
        None
    }
}

/** @brief 타입 이름을 번호로. */
fn parse_rtype(s: &str) -> Option<RecordType> {
    Some(match s.trim().to_ascii_uppercase().as_str() {
        "A" => RecordType::A,
        "AAAA" => RecordType::AAAA,
        "CNAME" => RecordType::CNAME,
        "DNAME" => RecordType::DNAME,
        "MX" => RecordType::MX,
        "TXT" => RecordType::TXT,
        "NS" => RecordType::NS,
        "SOA" => RecordType::SOA,
        "SRV" => RecordType::SRV,
        "PTR" => RecordType::PTR,
        "HTTPS" => RecordType::HTTPS,
        "SVCB" => RecordType::SVCB,
        "CAA" => RecordType::CAA,
        "ANY" => RecordType::ANY,
        _ => return None,
    })
}

/** @brief 이 문자열이 도메인처럼 생겼는지. */
fn looks_like_domain(s: &str) -> bool {
    !s.is_empty()
        && s.contains('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

/** @brief 이 주소가 hosts 형식에서 차단을 뜻하는 값인지. */
fn is_unspecified_or_loopback(ip: &IpAddr) -> bool {
    ip.is_unspecified() || ip.is_loopback()
}

/** @brief 취소 규칙들을 적용해 대상 규칙을 꺼 준다. 모든 규칙을 읽은 뒤에 한다. */
fn apply_badfilter(acc: &mut Accum) {
    for d in &acc.badfilter {
        acc.parts.block.remove(d);
        acc.parts.block_important.remove(d);
        acc.parts.allow.remove(d);
        acc.parts.allow_important.remove(d);
        acc.parts.refuse.remove(d);
        acc.parts.nodata.remove(d);
        acc.parts.no_response.remove(d);
        for (_, s) in &mut acc.parts.typed_block {
            s.remove(d);
        }
        for (_, s) in &mut acc.parts.typed_block_except {
            s.remove(d);
        }
    }

    for p in &acc.badfilter_regex {
        let parts = &mut acc.parts;
        for list in [
            &mut parts.regex_block,
            &mut parts.regex_allow,
            &mut parts.regex_block_important,
            &mut parts.regex_allow_important,
            &mut parts.regex_refuse,
            &mut parts.regex_nodata,
            &mut parts.regex_no_response,
        ] {
            list.retain(|x| x != p);
        }
        parts.regex_rewrites.retain(|(x, _)| x != p);
        parts.regex_typed_block.retain(|(_, x)| x != p);
        parts.regex_typed_block_except.retain(|(_, x)| x != p);
    }
}

/** @brief 규칙 한 줄이 유효한지 검사하고 사유를 알려 준다. 대시보드가 쓴다. */
pub fn validate_rule(line: &str) -> Result<(), String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
        return Err("Empty rule or comment".to_string());
    }

    let body = trimmed.strip_prefix("@@").unwrap_or(trimmed);
    if body.starts_with('/') {
        let Some((pat, _)) = split_regex_rule(body) else {
            return Err("Regex rule is missing its closing slash".to_string());
        };
        if let Err(error) = Regex::new(pat) {
            return Err(error.to_string());
        }
    }

    let mut acc = Accum::new();
    parse_line(trimmed, &mut acc, false);
    let report = &acc.parts.report;
    if report.rules_skipped == 0 {
        return Ok(());
    }
    if let Some(name) = report.unsupported_modifier.keys().next() {
        return Err(format!("Unsupported modifier: ${name}"));
    }
    if report.not_applicable > 0 {
        return Err("Modifier does not apply to DNS filtering".to_string());
    }
    if report.invalid_regex > 0 {
        return Err("Invalid regex rule".to_string());
    }
    Err("Not a valid domain or rule pattern".to_string())
}

/**
 * @brief RPZ zone 텍스트를 읽는다.
 * @note 이 서버가 지원하는 부분집합만 다룬다. 이름 기반 규칙과 주소 기반 규칙이다.
 */
pub fn parse_rpz_text(text: &str, parts: &mut EngineParts) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with(';')
            || line.starts_with('$')
            || line.starts_with("@")
        {
            continue;
        }
        let mut toks = line.split_whitespace();
        let owner = match toks.next() {
            Some(o) => o.trim_end_matches('.'),
            None => continue,
        };

        let rest: Vec<&str> = toks.collect();
        let (rtype, rdata) = match find_type(&rest) {
            Some(x) => x,
            None => continue,
        };

        let verdict = match rpz_action_verdict(rtype, rdata) {
            Some(v) => v,
            None => continue,
        };

        if let Some(enc) = rpz_ip_owner(owner, "rpz-client-ip") {
            if let Some(net) = rpz_ip_to_net(enc) {
                parts.rpz_client_ip.push(RpzIpRule::new(net, verdict));
            }
            continue;
        }
        if let Some(enc) = rpz_ip_owner(owner, "rpz-ip") {
            if let Some(net) = rpz_ip_to_net(enc) {
                parts.rpz_ip.push(RpzIpRule::new(net, verdict));
            }
            continue;
        }

        if let Some(enc) = rpz_ip_owner(owner, "rpz-nsip") {
            if let Some(net) = rpz_ip_to_net(enc) {
                parts.rpz_nsip.push(RpzIpRule::new(net, verdict));
            }
            continue;
        }

        if let Some(nsd) = rpz_ip_owner(owner, "rpz-nsdname") {
            let dom = nsd.trim_start_matches("*.");
            if looks_like_domain(dom) {
                if let Some(rule) = RpzNameRule::new(dom, verdict) {
                    parts.rpz_nsdname.push(rule);
                }
            }
            continue;
        }

        if owner.starts_with("rpz-") || owner.is_empty() {
            continue;
        }
        let (dom, subdomains) = match owner.strip_prefix("*.") {
            Some(parent) => (parent, true),
            None => (owner, false),
        };
        if !looks_like_domain(dom) {
            continue;
        }
        apply_rpz_verdict_qname(parts, dom, subdomains, verdict);
    }
}

/**
 * @brief RPZ 레코드에서 처분을 정한다.
 * @note rpz-drop 은 원래 답하지 않으라는 뜻이지만 설정한 차단 응답으로 답한다. 받아 온 영역의
 *       규칙대로 침묵하면 클라이언트는 차단을 장애로 보고 시간이 다 될 때까지 기다리며 재시도한다.
 *       침묵은 운영자가 NORESPONSE 로 직접 고른 이름에만 쓴다. rpz-tcp-only 는 지원하지 않아
 *       규칙을 건너뛴다. 어느 쪽이든 그 이름을 CNAME 대상으로 삼지 않는다.
 */
fn rpz_action_verdict(rtype: &str, rdata: &[&str]) -> Option<FilterVerdict> {
    match rtype.to_ascii_uppercase().as_str() {
        "CNAME" => {
            let target = rdata.first().copied().unwrap_or(".");
            Some(match target.to_ascii_lowercase().as_str() {
                "." => FilterVerdict::Block(BlockResponse::NxDomain),
                "*." => FilterVerdict::Block(BlockResponse::NoData),
                "rpz-passthru." | "rpz-passthru" => FilterVerdict::Allow,
                "rpz-drop." | "rpz-drop" => FilterVerdict::Block(BlockResponse::NxDomain),
                "rpz-tcp-only." | "rpz-tcp-only" => return None,
                t => FilterVerdict::Rewrite(RewriteTarget::Cname(
                    Name::from_str(t.trim_end_matches('.')).ok()?,
                )),
            })
        }
        "A" | "AAAA" => {
            let ip: IpAddr = rdata.first()?.parse().ok()?;
            if is_unspecified_or_loopback(&ip) {
                Some(FilterVerdict::Block(BlockResponse::NxDomain))
            } else {
                Some(FilterVerdict::Rewrite(RewriteTarget::ip(ip)))
            }
        }
        _ => None,
    }
}

/**
 * @brief 이름 기반 RPZ 규칙을 적용한다.
 * @details RPZ 의 소유자 이름은 그 이름 하나만 가리킨다. 하위 도메인은 *. 로 시작하는 소유자가
 *          따로 가리킨다.
 * @warning 엔진의 접미사 규칙은 부모 이름 자체도 덮으므로 *.example 규칙은 example 에도 걸린다.
 *          하위 도메인만 덮는 규칙이 엔진에 없어서다.
 */
fn apply_rpz_verdict_qname(
    parts: &mut EngineParts,
    dom: &str,
    subdomains: bool,
    verdict: FilterVerdict,
) {
    let set = match verdict {
        FilterVerdict::Allow => &mut parts.allow,
        FilterVerdict::Block(BlockResponse::NoData) => &mut parts.nodata,
        FilterVerdict::Block(BlockResponse::Refused) => &mut parts.refuse,
        FilterVerdict::Block(_) => &mut parts.block,
        FilterVerdict::Drop => &mut parts.no_response,
        FilterVerdict::Rewrite(target) => {
            if subdomains {
                parts.rewrites.add_suffix(dom, target);
            } else {
                parts.rewrites.add_exact(dom, target);
            }
            return;
        }
    };
    if subdomains {
        set.add_suffix(dom);
    } else {
        set.add_exact(dom);
    }
}

/** @brief RPZ 소유자 이름에서 주소 부분을 추출한다. */
fn rpz_ip_owner<'a>(owner: &'a str, marker: &str) -> Option<&'a str> {
    let pat = format!(".{marker}");
    let idx = owner.find(&pat)?;
    let enc = &owner[..idx];
    (!enc.is_empty()).then_some(enc)
}

/** @brief RPZ의 뒤집힌 주소 표기를 대역으로 바꾼다. */
fn rpz_ip_to_net(enc: &str) -> Option<IpNet> {
    let labels: Vec<&str> = enc.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    let prefix: u8 = labels[0].parse().ok()?;
    let rev = &labels[1..];

    if rev.len() == 4
        && rev
            .iter()
            .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()))
    {
        let o: Vec<u8> = rev.iter().filter_map(|l| l.parse::<u8>().ok()).collect();
        if o.len() == 4 && prefix <= 32 {
            return format!("{}.{}.{}.{}/{}", o[3], o[2], o[1], o[0], prefix)
                .parse()
                .ok();
        }
        return None;
    }

    if prefix > 128 {
        return None;
    }
    let mut net_order: Vec<&str> = rev.to_vec();
    net_order.reverse();
    let zz = net_order.iter().filter(|g| **g == "zz").count();
    if zz > 1 {
        return None;
    }
    let non_zz = net_order.len() - zz;
    let mut groups: Vec<String> = Vec::with_capacity(8);
    for g in &net_order {
        if *g == "zz" {
            let zeros = 8usize.checked_sub(non_zz)?;
            if zeros == 0 {
                return None;
            }
            for _ in 0..zeros {
                groups.push("0".to_string());
            }
        } else {
            let v = u16::from_str_radix(g, 16).ok()?;
            groups.push(format!("{v:x}"));
        }
    }
    if groups.len() != 8 {
        return None;
    }
    format!("{}/{}", groups.join(":"), prefix).parse().ok()
}

/** @brief 레코드 줄에서 타입과 그 뒤를 찾는다. */
fn find_type<'a>(rest: &'a [&'a str]) -> Option<(&'a str, &'a [&'a str])> {
    for (i, t) in rest.iter().enumerate() {
        let up = t.to_ascii_uppercase();
        if matches!(up.as_str(), "CNAME" | "A" | "AAAA" | "PTR" | "TXT") {
            return Some((rest[i], &rest[i + 1..]));
        }
    }
    None
}

/** @brief 설정된 목록들을 읽어 엔진 구성을 만든다. */
pub fn load_parts(
    blocklists: &[impl AsRef<Path>],
    allowlists: &[impl AsRef<Path>],
    extra_block: &[&str],
    extra_allow: &[&str],
) -> std::io::Result<EngineParts> {
    load_parts_with_subscriptions(blocklists, allowlists, &[], extra_block, extra_allow)
}

/** @brief 구독한 차단 목록 하나의 규칙이 어디에 있는지. */
pub enum SubscriptionRules<'a> {
    /** @brief 내려받아 디스크에 둔 캐시 파일. */
    File(&'a Path),
    /** @brief 메모리에 있는 줄들. 캐시 디렉터리를 쓰지 않을 때다. */
    Lines(&'a [String]),
}

/**
 * @brief 구독한 차단 목록 하나.
 * @details 이름은 그 목록의 출처로 등록된다. 질의 기록이 어느 목록 때문에 막혔는지를
 *          목록 단위로 보여 주는 값이며, 규칙 원문은 따로 보존하지 않는다.
 */
pub struct SubscriptionSource<'a> {
    /** @brief 출처 이름. 구독 주소를 쓴다. */
    pub name: &'a str,
    /** @brief 규칙이 있는 곳. */
    pub rules: SubscriptionRules<'a>,
}

/** @brief 구독 목록까지 포함해 엔진 구성을 만든다. */
pub fn load_parts_with_subscriptions(
    blocklists: &[impl AsRef<Path>],
    allowlists: &[impl AsRef<Path>],
    subscriptions: &[SubscriptionSource<'_>],
    extra_block: &[&str],
    extra_allow: &[&str],
) -> std::io::Result<EngineParts> {
    let mut acc = Accum::new();
    for path in blocklists {
        let file = open_validated_list_file(path.as_ref()).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!(
                    "Could not read or validate blocklist '{}': {error}",
                    path.as_ref().display()
                ),
            )
        })?;
        acc.register_source(path.as_ref().display().to_string());
        parse_validated_list_file(file, |line| parse_line(line, &mut acc, false)).map_err(
            |error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "Could not read blocklist '{}': {error}",
                        path.as_ref().display()
                    ),
                )
            },
        )?;
    }
    for path in allowlists {
        let file = open_validated_list_file(path.as_ref()).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!(
                    "Could not read or validate allowlist '{}': {error}",
                    path.as_ref().display()
                ),
            )
        })?;
        acc.register_source(path.as_ref().display().to_string());
        parse_validated_list_file(file, |line| parse_line(line, &mut acc, true)).map_err(
            |error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "Could not read allowlist '{}': {error}",
                        path.as_ref().display()
                    ),
                )
            },
        )?;
    }
    for subscription in subscriptions {
        acc.register_source(subscription.name.to_string());
        match subscription.rules {
            SubscriptionRules::File(path) => {
                let file = open_validated_list_file(path).map_err(|error| {
                    std::io::Error::new(
                        error.kind(),
                        format!(
                            "Could not read or validate subscription blocklist cache '{}': {error}",
                            path.display()
                        ),
                    )
                })?;
                parse_validated_list_file(file, |line| parse_line(line, &mut acc, false)).map_err(
                    |error| {
                        std::io::Error::new(
                            error.kind(),
                            format!(
                                "Could not read subscription blocklist cache '{}': {error}",
                                path.display()
                            ),
                        )
                    },
                )?;
            }
            SubscriptionRules::Lines(lines) => {
                for line in lines {
                    parse_line(line, &mut acc, false);
                }
            }
        }
    }
    acc.cur_source = crate::engine::NO_SOURCE;
    for d in extra_block {
        parse_line(d, &mut acc, false);
    }
    for d in extra_allow {
        parse_line(d, &mut acc, true);
    }
    apply_badfilter(&mut acc);
    Ok(acc.parts)
}

/** @brief 목록들을 읽어 엔진을 만든다. */
pub fn load_lists(
    blocklists: &[impl AsRef<Path>],
    allowlists: &[impl AsRef<Path>],
    default_block: BlockResponse,
) -> std::io::Result<BlockEngine> {
    load_lists_with(blocklists, allowlists, &[], &[], default_block)
}

/** @brief 추가 목록까지 포함해 엔진을 만든다. */
pub fn load_lists_with(
    blocklists: &[impl AsRef<Path>],
    allowlists: &[impl AsRef<Path>],
    extra_block: &[&str],
    extra_allow: &[&str],
    default_block: BlockResponse,
) -> std::io::Result<BlockEngine> {
    let parts = load_parts(blocklists, allowlists, extra_block, extra_allow)?;
    Ok(BlockEngine::new(parts, default_block))
}

/** @brief 문자열 하나에서 엔진을 만든다. 테스트와 검증에 쓴다. */
pub fn build_from_str(
    block_text: &str,
    allow_text: &str,
    default_block: BlockResponse,
) -> BlockEngine {
    let mut acc = Accum::new();
    for line in block_text.lines() {
        parse_line(line, &mut acc, false);
    }
    for line in allow_text.lines() {
        parse_line(line, &mut acc, true);
    }
    apply_badfilter(&mut acc);
    BlockEngine::new(acc.parts, default_block)
}

/** @brief 이름 붙은 문자열들에서 엔진을 만든다. 출처가 보존된다. */
pub fn build_from_named(
    sources: &[(String, String)],
    extra_allow: &str,
    default_block: BlockResponse,
) -> BlockEngine {
    let mut acc = Accum::new();
    for (name, text) in sources {
        acc.register_source(name.clone());
        for line in text.lines() {
            parse_line(line, &mut acc, false);
        }
    }
    acc.cur_source = crate::engine::NO_SOURCE;
    for line in extra_allow.lines() {
        parse_line(line, &mut acc, true);
    }
    apply_badfilter(&mut acc);
    BlockEngine::new(acc.parts, default_block)
}

#[cfg(test)]
/** @brief 형식별 파싱, 수식어 우선순위, 그리고 실패 시 열리지 않는지. */
mod tests {
    use super::*;
    use onetdns_core::{ClientInfo, FilterEngine, FilterVerdict, Transport};

    /** @brief 엔진에 이름 하나를 물어 판정을 얻는다. */
    fn verdict(engine: &BlockEngine, q: &str) -> FilterVerdict {
        let client = ClientInfo {
            source_ip: "127.0.0.1".parse().unwrap(),
            client_id: None,
            transport: Transport::Do53Udp,
            authenticated: false,
        };
        engine.verdict(&Name::from_str(q).unwrap(), RecordType::A, &client)
    }

    #[test]
    /** @brief 이 서버와 무관한 브라우저 전용 수식어를 적용 대상 아님으로 분류하는지. 오류로 세면 보고가 쓸모없어진다. */
    fn network_modifiers_classified_not_applicable() {
        let text = "\
||ads.example.com^$third-party
||cdn.example.com^$script,image
||x.example.com^$domain=foo.com
||real.example.com^$app=org.example
||good.example.com^
";
        let eng = build_from_str(text, "", BlockResponse::NxDomain);
        let r = eng.load_report();
        assert_eq!(r.rules_total, 5);
        assert_eq!(r.not_applicable, 3, "third-party·script,image·domain은 N/A");

        assert_eq!(r.unsupported_modifier.get("app"), Some(&1));
        assert_eq!(r.rules_applied(), 1, "good.example.com만 적용");
        assert!(r.to_json().contains("\"not_applicable\":3"));
    }

    #[test]
    /** @brief 규칙이 어느 목록에서 왔는지 추적되는지. 어떤 목록 때문에 막혔는지 알려면 필요하다. */
    fn per_list_source_tracking() {
        let eng = build_from_named(
            &[
                ("listA".to_string(), "||ads.example.com^\n".to_string()),
                (
                    "listB".to_string(),
                    "||tracker.net^\n||beacon.io^\n".to_string(),
                ),
            ],
            "",
            BlockResponse::NxDomain,
        )
        .with_hit_tracking(true);

        for _ in 0..2 {
            eng.verdict(
                &Name::from_str("x.ads.example.com.").unwrap(),
                RecordType::A,
                &ClientInfo {
                    source_ip: "127.0.0.1".parse().unwrap(),
                    client_id: None,
                    transport: Transport::Do53Udp,
                    authenticated: false,
                },
            );
        }

        let stats = eng.source_stats();
        let a = stats.iter().find(|s| s.source == "listA").unwrap();
        assert_eq!(a.rules, 1);
        assert_eq!(a.hits, 2);
        let b = stats.iter().find(|s| s.source == "listB").unwrap();
        assert_eq!(b.rules, 2);
        assert_eq!(b.hits, 0);
    }

    #[test]
    /** @brief 타입 부정이 나열한 것만 빼고 막는지. */
    fn dnstype_negation_blocks_except_listed() {
        let eng = build_from_str("||tracker.test^$dnstype=~A\n", "", BlockResponse::NxDomain);
        let q = |name: &str, qt: RecordType| {
            let client = ClientInfo {
                source_ip: "127.0.0.1".parse().unwrap(),
                client_id: None,
                transport: Transport::Do53Udp,
                authenticated: false,
            };
            eng.verdict(&Name::from_str(name).unwrap(), qt, &client)
        };
        assert!(
            matches!(q("tracker.test.", RecordType::A), FilterVerdict::Allow),
            "A 제외→통과"
        );
        assert!(
            matches!(
                q("tracker.test.", RecordType::AAAA),
                FilterVerdict::Block(_)
            ),
            "AAAA 차단"
        );
        assert!(
            matches!(q("tracker.test.", RecordType(15)), FilterVerdict::Block(_)),
            "MX 차단"
        );
        assert!(
            matches!(q("clean.test.", RecordType::AAAA), FilterVerdict::Allow),
            "무관 도메인 통과"
        );
    }

    #[test]
    /** @brief 여러 형식이 섞인 목록을 읽는지. */
    fn parses_mixed_formats() {
        let block = "\
# comment
0.0.0.0 ads.example.com
127.0.0.1 tracking.test localhost
||doubleclick.net^
analytics.bad
";
        let allow = "@@||ads.example.com^\n";
        let eng = build_from_str(block, allow, BlockResponse::NxDomain);

        assert!(matches!(
            verdict(&eng, "ads.example.com."),
            FilterVerdict::Allow
        ));
        assert!(matches!(
            verdict(&eng, "tracking.test."),
            FilterVerdict::Block(_)
        ));
        assert!(matches!(
            verdict(&eng, "x.doubleclick.net."),
            FilterVerdict::Block(_)
        ));
        assert!(matches!(
            verdict(&eng, "analytics.bad."),
            FilterVerdict::Block(_)
        ));
        assert!(matches!(verdict(&eng, "safe.org."), FilterVerdict::Allow));
    }

    #[test]
    /** @brief 중요 표시가 허용 규칙을 이기는지. */
    fn important_modifier() {
        let eng = build_from_str(
            "||ads.example.com^$important\n",
            "@@||example.com^\n",
            BlockResponse::NxDomain,
        );
        assert!(matches!(
            verdict(&eng, "ads.example.com."),
            FilterVerdict::Block(_)
        ));
        assert!(matches!(
            verdict(&eng, "www.example.com."),
            FilterVerdict::Allow
        ));
    }

    #[test]
    /** @brief 취소 규칙이 대상 규칙을 꺼 주는지. */
    fn badfilter_disables_rule() {
        let eng = build_from_str(
            "||example.com^\n||example.com^$badfilter\n",
            "",
            BlockResponse::NxDomain,
        );
        assert!(matches!(
            verdict(&eng, "example.com."),
            FilterVerdict::Allow
        ));
    }

    #[test]
    /** @brief 재작성 규칙이 주소를 지정하는지. */
    fn dnsrewrite_to_ip() {
        let eng = build_from_str(
            "||rw.example.com^$dnsrewrite=1.2.3.4\n",
            "",
            BlockResponse::NxDomain,
        );
        assert!(matches!(
            verdict(&eng, "rw.example.com."),
            FilterVerdict::Rewrite(_)
        ));
    }

    #[test]
    /** @brief 정규식 규칙의 재작성. */
    fn regex_dnsrewrite_to_ip() {
        let eng = build_from_str(
            "/^[a-z0-9]{32}\\.t\\.e\\.s\\.t\\.onetwohour\\.com$/$dnsrewrite=158.247.221.46\n",
            "",
            BlockResponse::NxDomain,
        );
        match verdict(
            &eng,
            "0123456789abcdef0123456789abcdef.t.e.s.t.onetwohour.com.",
        ) {
            FilterVerdict::Rewrite(RewriteTarget::Records(rs)) => {
                assert_eq!(
                    rs,
                    vec![onetdns_proto::RData::A("158.247.221.46".parse().unwrap())]
                )
            }
            o => panic!("Rewrite 기대, {o:?}"),
        }
        assert!(
            matches!(
                verdict(&eng, "short.t.e.s.t.onetwohour.com."),
                FilterVerdict::Allow
            ),
            "패턴이 일치하지 않으면 통과"
        );
    }

    #[test]
    /** @brief 정규식 재작성의 응답 코드 지정. */
    fn regex_dnsrewrite_status_values() {
        let eng = build_from_str(
            "/^rf\\./$dnsrewrite=REFUSED\n/^nd\\./$dnsrewrite=NODATA\n/^nx\\./$dnsrewrite=NXDOMAIN\n",
            "",
            BlockResponse::NxDomain,
        );
        assert!(matches!(
            verdict(&eng, "rf.example.com."),
            FilterVerdict::Block(BlockResponse::Refused)
        ));
        assert!(matches!(
            verdict(&eng, "nd.example.com."),
            FilterVerdict::Block(BlockResponse::NoData)
        ));
        assert!(matches!(
            verdict(&eng, "nx.example.com."),
            FilterVerdict::Block(_)
        ));
    }

    #[test]
    /** @brief 정규식 허용 규칙. */
    fn regex_allow_rule_with_at_at() {
        let eng = build_from_str(
            "||metrics.example.com^\n",
            "@@/^metrics\\.example\\.com$/\n",
            BlockResponse::NxDomain,
        );
        assert!(matches!(
            verdict(&eng, "metrics.example.com."),
            FilterVerdict::Allow
        ));

        let eng = build_from_str(
            "||metrics.example.com^\n@@/^metrics\\.example\\.com$/\n",
            "",
            BlockResponse::NxDomain,
        );
        assert!(matches!(
            verdict(&eng, "metrics.example.com."),
            FilterVerdict::Allow
        ));
    }

    #[test]
    /** @brief 정규식 중요 표시가 일반 허용을 이기는지. */
    fn regex_important_beats_plain_allow() {
        let eng = build_from_str(
            "/banner\\./$important\n",
            "@@||banner.example.com^\n",
            BlockResponse::NxDomain,
        );
        assert!(matches!(
            verdict(&eng, "banner.example.com."),
            FilterVerdict::Block(_)
        ));
    }

    #[test]
    /** @brief 정규식 규칙의 타입 제한이 나열한 것만 막는지. */
    fn regex_dnstype_blocks_only_listed() {
        let eng = build_from_str("/^svc\\./$dnstype=HTTPS\n", "", BlockResponse::NxDomain);
        let client = ClientInfo {
            source_ip: "127.0.0.1".parse().unwrap(),
            client_id: None,
            transport: Transport::Do53Udp,
            authenticated: false,
        };
        let q =
            |qt: RecordType| eng.verdict(&Name::from_str("svc.example.com.").unwrap(), qt, &client);
        assert!(matches!(q(RecordType::HTTPS), FilterVerdict::Block(_)));
        assert!(matches!(q(RecordType::A), FilterVerdict::Allow));
    }

    #[test]
    /** @brief 정규식 규칙의 타입 부정. */
    fn regex_dnstype_negation() {
        let eng = build_from_str("/^svc\\./$dnstype=~A\n", "", BlockResponse::NxDomain);
        let client = ClientInfo {
            source_ip: "127.0.0.1".parse().unwrap(),
            client_id: None,
            transport: Transport::Do53Udp,
            authenticated: false,
        };
        let q =
            |qt: RecordType| eng.verdict(&Name::from_str("svc.example.com.").unwrap(), qt, &client);
        assert!(matches!(q(RecordType::A), FilterVerdict::Allow));
        assert!(matches!(q(RecordType::AAAA), FilterVerdict::Block(_)));
    }

    #[test]
    /** @brief 대역 표기가 든 클라이언트 수식어가 정규식과 섞여도 갈리는지. */
    fn regex_client_modifier_with_cidr_slash() {
        let eng = build_from_str("/^cam\\./$client=10.0.0.0/8\n", "", BlockResponse::NxDomain);
        let q = |ip: &str| {
            let client = ClientInfo {
                source_ip: ip.parse().unwrap(),
                client_id: None,
                transport: Transport::Do53Udp,
                authenticated: false,
            };
            eng.verdict(
                &Name::from_str("cam.example.com.").unwrap(),
                RecordType::A,
                &client,
            )
        };
        assert!(matches!(q("10.1.2.3"), FilterVerdict::Block(_)));
        assert!(matches!(q("192.168.1.1"), FilterVerdict::Allow));
    }

    #[test]
    /** @brief 정규식 규칙의 취소. */
    fn regex_badfilter_cancels_rule() {
        let eng = build_from_str(
            "/^ads\\./\n/^ads\\./$badfilter\n",
            "",
            BlockResponse::NxDomain,
        );
        assert!(matches!(
            verdict(&eng, "ads.example.com."),
            FilterVerdict::Allow
        ));
    }

    #[test]
    /** @brief 지원하지 않는 수식어가 보고에 남는지. */
    fn regex_unsupported_modifier_reported() {
        let eng = build_from_str("/^x\\./$removeparam=id\n", "", BlockResponse::NxDomain);
        let r = eng.load_report();
        assert_eq!(r.rules_skipped, 1);
        assert_eq!(r.not_applicable, 1, "웹 필터 수식어는 N/A로 집계");
        assert!(matches!(
            verdict(&eng, "x.example.com."),
            FilterVerdict::Allow
        ));
    }

    #[test]
    /** @brief 규칙 검증이 사유를 알려 주는지. 대시보드가 이것을 보여 준다. */
    fn validate_rule_reports_reasons() {
        assert!(validate_rule("||ads.example.com^").is_ok());
        assert!(validate_rule("@@||example.com^$important").is_ok());
        assert!(validate_rule(
            "/^[a-z0-9]{32}\\.t\\.e\\.s\\.t\\.onetwohour\\.com$/$dnsrewrite=158.247.221.46"
        )
        .is_ok());
        assert!(validate_rule("0.0.0.0 ads.example.com").is_ok());

        assert!(validate_rule("").is_err(), "빈 규칙");
        assert!(validate_rule("! comment").is_err(), "주석");
        assert!(validate_rule("/unclosed").is_err(), "닫는 슬래시 없음");
        assert!(validate_rule("/(*bad/").is_err(), "정규식 컴파일 실패");
        let e = validate_rule("||x.example.com^$app=org.example").unwrap_err();
        assert!(e.contains("app"), "지원하지 않는 수식어 이름 포함: {e}");
        assert!(
            validate_rule("||x.example.com^$third-party").is_err(),
            "웹 필터 수식어"
        );
        assert!(validate_rule("not a domain !!").is_err(), "잘못된 패턴");
        assert!(
            validate_rule("||rw.example.com^$dnsrewrite=???").is_err(),
            "해석 불가 dnsrewrite 값"
        );
    }

    #[test]
    /**
     * @brief 구독 목록의 규칙이 그 목록 이름을 출처로 남기는지.
     * @details 캐시 파일에서 읽든 메모리의 줄에서 읽든 같아야 하고, 목록에 속하지 않는
     *          추가 규칙은 출처가 없어야 한다. 그래야 질의 기록이 목록을 잘못 지목하지 않는다.
     */
    fn subscription_rules_keep_their_list_as_source() {
        let path =
            std::env::temp_dir().join(format!("onetdns-filter-extra-{}.list", std::process::id()));
        std::fs::write(&path, "# cache header\n||disk.example^\n").unwrap();
        let lines = vec!["||memory.example^".to_string()];
        let parts = load_parts_with_subscriptions(
            &[] as &[std::path::PathBuf],
            &[] as &[std::path::PathBuf],
            &[
                SubscriptionSource {
                    name: "https://lists.example/disk.txt",
                    rules: SubscriptionRules::File(&path),
                },
                SubscriptionSource {
                    name: "https://lists.example/memory.txt",
                    rules: SubscriptionRules::Lines(&lines),
                },
            ],
            &["||inline.example^"],
            &[],
        )
        .unwrap();
        let _ = std::fs::remove_file(&path);

        let source_name = |key: &str| {
            parts
                .block
                .source_of(key)
                .and_then(|id| parts.sources.get(id as usize))
                .cloned()
        };
        assert_eq!(
            source_name("deep.disk.example").as_deref(),
            Some("https://lists.example/disk.txt")
        );
        assert_eq!(
            source_name("memory.example").as_deref(),
            Some("https://lists.example/memory.txt")
        );
        assert_eq!(source_name("inline.example"), None);
    }

    #[test]
    /** @brief UTF-8이 아닌 파일이 규칙을 하나도 적용하기 전에 거부되는지. 절반만 적용되면 안 된다. */
    fn invalid_utf8_file_is_rejected_before_any_rule_is_applied() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-filter-invalid-utf8-{}.list",
            std::process::id()
        ));
        std::fs::write(&path, b"||partial.example^\n\xff\n").unwrap();
        let result = load_parts(
            std::slice::from_ref(&path),
            &[] as &[std::path::PathBuf],
            &[],
            &[],
        );
        let _ = std::fs::remove_file(&path);

        assert!(result.is_err());
    }

    #[test]
    /** @brief 지나치게 긴 줄이 있으면 그 파일 전체를 적용하지 않는지. */
    fn oversized_rule_line_is_rejected_before_any_rule_is_applied() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-filter-oversized-line-{}.list",
            std::process::id()
        ));
        let mut contents = b"||partial.example^\n".to_vec();
        contents.resize(contents.len() + MAX_LOCAL_LIST_LINE as usize + 1, b'a');
        std::fs::write(&path, contents).unwrap();
        let result = load_parts(
            std::slice::from_ref(&path),
            &[] as &[std::path::PathBuf],
            &[],
            &[],
        );
        let _ = std::fs::remove_file(&path);

        assert!(result.is_err());
    }

    #[test]
    /** @brief 설정된 파일을 읽지 못하면 차단이 열리지 않고 실패하는지. 열리면 필터가 조용히 사라진다. */
    fn configured_filter_files_cannot_fail_open() {
        let missing = std::env::temp_dir().join(format!(
            "onetdns-filter-missing-{}-{}.list",
            std::process::id(),
            line!()
        ));
        let empty = &[] as &[std::path::PathBuf];

        assert!(load_parts(std::slice::from_ref(&missing), empty, &[], &[]).is_err());
        assert!(load_parts(empty, std::slice::from_ref(&missing), &[], &[]).is_err());
        assert!(load_parts_with_subscriptions(
            empty,
            empty,
            &[SubscriptionSource {
                name: "https://lists.example/missing.txt",
                rules: SubscriptionRules::File(&missing),
            }],
            &[],
            &[]
        )
        .is_err());
    }

    #[test]
    /** @brief 재작성의 데이터 없음이 빈 정상 응답이 되는지. */
    fn dnsrewrite_nodata_is_empty_noerror() {
        for rule in [
            "$dnsrewrite=NODATA",
            "$dnsrewrite=NOERROR",
            "$dnsrewrite=NODATA;A;",
        ] {
            let eng = build_from_str(
                &format!("||nd.example.com^{rule}\n"),
                "",
                BlockResponse::NxDomain,
            );
            assert!(
                matches!(
                    verdict(&eng, "nd.example.com."),
                    FilterVerdict::Block(BlockResponse::NoData)
                ),
                "{rule} → NODATA 기대"
            );
        }
    }

    #[test]
    /**
     * @brief NORESPONSE 재작성이 이름 규칙과 정규식 규칙 모두에서 무응답 판정이 되는지.
     * @details 값은 다른 응답 코드처럼 대소문자를 가리지 않는다. 규칙 검증이 거절하면
     *          대시보드에서 이 규칙을 넣을 수 없고, badfilter 가 빼지 못하면 구독 목록에 든
     *          규칙을 끌 방법이 없다.
     */
    fn dnsrewrite_noresponse_drops_names_and_patterns() {
        let rules = "\
||quiet.example^$dnsrewrite=NORESPONSE
/^scan[0-9]+\\.example$/$dnsrewrite=noresponse
||gone.example^$dnsrewrite=NORESPONSE
||gone.example^$badfilter
";
        let eng = build_from_str(rules, "", BlockResponse::NxDomain);
        for name in ["quiet.example.", "www.quiet.example.", "scan42.example."] {
            assert!(
                matches!(verdict(&eng, name), FilterVerdict::Drop),
                "{name} 이 무응답 판정을 받지 않았습니다"
            );
        }
        assert!(
            matches!(verdict(&eng, "gone.example."), FilterVerdict::Allow),
            "badfilter 가 무응답 규칙을 빼지 못했습니다"
        );
        assert!(
            matches!(verdict(&eng, "scan.example."), FilterVerdict::Allow),
            "대조군이 무효입니다: 규칙에 없는 이름이 막혔습니다"
        );
        assert!(validate_rule("||quiet.example^$dnsrewrite=NORESPONSE").is_ok());
        assert!(validate_rule("/^scan[0-9]+\\.example$/$dnsrewrite=NORESPONSE").is_ok());
    }

    #[test]
    /** @brief 로드 보고가 적용과 건너뜀을 모아 주는지. */
    fn load_report_aggregates_applied_and_skipped() {
        let text = "\
# comment ignored
||good.example.com^
||typed.example.com^$dnstype=A
||unsup.example.com^$app=org.example
||stealthy.example.com^$stealth
/valid.*pat/
/unclosed
||rw.example.com^$dnsrewrite=1.2.3.4
$dnsrewrite=NXDOMAIN
";
        let eng = build_from_str(text, "", BlockResponse::NxDomain);
        let r = eng.load_report();
        assert_eq!(r.rules_total, 8, "비주석 규칙 8줄");
        assert_eq!(r.rules_skipped, 4);
        assert_eq!(r.rules_applied(), 4);
        assert_eq!(r.invalid_regex, 1, "닫는 슬래시 없는 정규식");
        assert_eq!(r.invalid_pattern, 1, "빈 도메인 dnsrewrite");
        assert_eq!(r.unsupported_modifier.get("app"), Some(&1));
        assert_eq!(r.unsupported_modifier.get("stealth"), Some(&1));

        let j = r.to_json();
        assert!(j.contains("\"rules_total\":8"));
        assert!(j.contains("\"rules_applied\":4"));
        assert!(j.contains("\"app\":1"));
    }

    #[test]
    /** @brief RPZ 주소 표기를 두 계열 모두 읽는지. */
    fn rpz_ip_decoder_v4_and_v6() {
        let n = rpz_ip_to_net("32.3.2.1.10").unwrap();
        assert!(n.contains(&"10.1.2.3".parse().unwrap()));
        assert!(!n.contains(&"10.1.2.4".parse().unwrap()));

        let n = rpz_ip_to_net("24.0.0.0.10").unwrap();
        assert!(n.contains(&"10.0.0.5".parse().unwrap()));
        assert!(!n.contains(&"10.0.1.5".parse().unwrap()));

        let n = rpz_ip_to_net("128.1.zz.db8.2001").unwrap();
        assert!(n.contains(&"2001:db8::1".parse().unwrap()));
        assert!(!n.contains(&"2001:db8::2".parse().unwrap()));

        assert!(rpz_ip_to_net("33.3.2.1.10").is_none());
        assert!(rpz_ip_to_net("64").is_none());
        assert!(rpz_ip_to_net("128.zz.1.zz.2001").is_none());
    }

    #[test]
    /** @brief RPZ 주소 규칙이 실제로 걸리는지. */
    fn rpz_ip_triggers_parsed() {
        let mut parts = EngineParts::default();
        parse_rpz_text(
            "32.3.2.1.10.rpz-ip CNAME .\n\
             24.0.0.0.192.rpz-client-ip CNAME rpz-passthru.\n\
             32.1.0.0.127.rpz-nsip CNAME .\n\
             ns.evil.example.rpz-nsdname CNAME .\n",
            &mut parts,
        );
        assert_eq!(parts.rpz_ip.len(), 1, "rpz-ip 트리거 1건");
        assert_eq!(parts.rpz_client_ip.len(), 1, "rpz-client-ip 트리거 1건");

        assert_eq!(parts.rpz_nsip.len(), 1, "rpz-nsip 트리거 1건");
        assert!(parts.rpz_nsip[0]
            .net
            .contains(&"127.0.0.1".parse().unwrap()));
        assert_eq!(parts.rpz_nsdname.len(), 1, "rpz-nsdname 트리거 1건");
        assert!(
            parts.rpz_nsdname[0].matches(&Name::from_str("ns.evil.example").unwrap()),
            "정확 NS 매칭"
        );
        assert!(
            parts.rpz_nsdname[0].matches(&Name::from_str("a.ns.evil.example").unwrap()),
            "하위 도메인 NS 매칭"
        );
        assert!(
            !parts.rpz_nsdname[0].matches(&Name::from_str("evil.example").unwrap()),
            "상위는 불매칭"
        );
        assert!(
            parts.block.is_empty(),
            "NS 트리거가 qname 차단으로 새지 않음"
        );
        assert!(parts.rpz_ip[0].net.contains(&"10.1.2.3".parse().unwrap()));
        assert!(matches!(parts.rpz_ip[0].verdict, FilterVerdict::Block(_)));
        assert!(parts.rpz_client_ip[0]
            .net
            .contains(&"192.0.0.5".parse().unwrap()));
        assert!(matches!(
            parts.rpz_client_ip[0].verdict,
            FilterVerdict::Allow
        ));
    }

    #[test]
    /** @brief RPZ의 별표 별칭이 데이터 없음으로 해석되는지. */
    fn rpz_wildcard_cname_is_nodata() {
        let mut parts = EngineParts::default();
        parse_rpz_text("nd.example.com CNAME *.\n", &mut parts);
        let eng = BlockEngine::new(parts, BlockResponse::NxDomain);
        assert!(matches!(
            verdict(&eng, "nd.example.com."),
            FilterVerdict::Block(BlockResponse::NoData)
        ));
    }

    #[test]
    /** @brief 클라이언트 수식어가 없는 질의에서는 그 규칙이 걸리지 않는지. */
    fn client_modifier_skipped() {
        let eng = build_from_str(
            "||x.example.com^$client=10.0.0.0/8\n",
            "",
            BlockResponse::NxDomain,
        );
        assert!(matches!(
            verdict(&eng, "x.example.com."),
            FilterVerdict::Allow
        ));
    }

    /** @brief 주어진 클라이언트 정보로 판정한다. */
    fn verdict_from(engine: &BlockEngine, q: &str, ip: &str, id: Option<&str>) -> FilterVerdict {
        let client = ClientInfo {
            source_ip: ip.parse().unwrap(),
            client_id: id.map(String::from),
            transport: Transport::Do53Udp,
            authenticated: false,
        };
        engine.verdict(&Name::from_str(q).unwrap(), RecordType::A, &client)
    }

    #[test]
    /** @brief 클라이언트 수식어가 맞는 클라이언트에만 걸리는지. */
    fn client_modifier_targets_matching_client() {
        let eng = build_from_str(
            "||ads.example.com^$client=10.0.0.0/8\n||t.example.com^$client=~10.1.1.1\n",
            "",
            BlockResponse::NxDomain,
        );
        assert!(matches!(
            verdict_from(&eng, "ads.example.com.", "10.2.3.4", None),
            FilterVerdict::Block(_)
        ));
        assert!(matches!(
            verdict_from(&eng, "ads.example.com.", "192.168.1.5", None),
            FilterVerdict::Allow
        ));

        assert!(matches!(
            verdict_from(&eng, "t.example.com.", "10.1.1.1", None),
            FilterVerdict::Allow
        ));
        assert!(matches!(
            verdict_from(&eng, "t.example.com.", "10.1.1.2", None),
            FilterVerdict::Block(_)
        ));
    }

    #[test]
    /** @brief 클라이언트 식별자로도 걸리는지. */
    fn client_modifier_matches_client_id() {
        let eng = build_from_str(
            "||g.example.com^$client=kids-tablet\n",
            "",
            BlockResponse::NxDomain,
        );
        assert!(matches!(
            verdict_from(&eng, "g.example.com.", "10.0.0.1", Some("kids-tablet")),
            FilterVerdict::Block(_)
        ));
        assert!(matches!(
            verdict_from(&eng, "g.example.com.", "10.0.0.1", None),
            FilterVerdict::Allow
        ));
    }

    #[test]
    /** @brief 예외 수식어가 나열한 도메인을 빼 주는지. */
    fn denyallow_modifier_excepts_domains() {
        let eng = build_from_str(
            "||example.org^$denyallow=safe.example.org\n",
            "",
            BlockResponse::NxDomain,
        );
        assert!(matches!(
            verdict(&eng, "ads.example.org."),
            FilterVerdict::Block(_)
        ));
        assert!(matches!(
            verdict(&eng, "safe.example.org."),
            FilterVerdict::Allow
        ));
        assert!(matches!(
            verdict(&eng, "www.safe.example.org."),
            FilterVerdict::Allow
        ));
    }

    #[test]
    /** @brief 클라이언트 태그로 걸리는지. */
    fn ctag_modifier_matches_client_tags() {
        let eng = build_from_str(
            "||game.example.com^$ctag=kids\n",
            "",
            BlockResponse::NxDomain,
        )
        .with_clients(vec![crate::engine::ClientPolicy::with_options(
            vec!["10.0.0.5/32".parse().unwrap()],
            vec![],
            vec!["kids".to_string()],
            &[],
            &[],
            false,
            None,
        )]);
        assert!(
            matches!(
                verdict_from(&eng, "game.example.com.", "10.0.0.5", None),
                FilterVerdict::Block(_)
            ),
            "kids 태그 클라 차단"
        );
        assert!(
            matches!(
                verdict_from(&eng, "game.example.com.", "10.0.0.9", None),
                FilterVerdict::Allow
            ),
            "태그 없는 클라 통과"
        );
    }

    #[test]
    /** @brief 클라이언트 예외가 일반 차단을 이기는지. */
    fn client_rule_exception_wins() {
        let eng = build_from_str(
            "||news.example.com^\n@@||news.example.com^$client=10.0.0.5\n",
            "",
            BlockResponse::NxDomain,
        );
        assert!(matches!(
            verdict_from(&eng, "news.example.com.", "10.0.0.5", None),
            FilterVerdict::Allow
        ));
        assert!(matches!(
            verdict_from(&eng, "news.example.com.", "10.0.0.6", None),
            FilterVerdict::Block(_)
        ));
    }

    #[test]
    /**
     * @brief RPZ 소유자 이름의 범위와 특수 대상을 규격대로 읽는지.
     * @details 정확한 소유자가 하위 도메인까지 덮으면 허용 규칙 하나가 영역 전체를 풀고,
     *          rpz-drop 을 CNAME 으로 읽으면 차단해야 할 이름이 그 이름으로 해석된다.
     */
    fn rpz_owner_scope_and_special_targets() {
        let mut parts = EngineParts::default();
        let rpz = "\
exact.example.com CNAME .
*.wild.example.com CNAME .
drop.example.com CNAME rpz-drop.
tcp.example.com CNAME rpz-tcp-only.
";
        parse_rpz_text(rpz, &mut parts);
        let eng = BlockEngine::new(parts, BlockResponse::NxDomain);
        assert!(matches!(
            verdict(&eng, "exact.example.com."),
            FilterVerdict::Block(_)
        ));
        assert!(matches!(
            verdict(&eng, "sub.exact.example.com."),
            FilterVerdict::Allow
        ));
        assert!(matches!(
            verdict(&eng, "a.wild.example.com."),
            FilterVerdict::Block(_)
        ));
        assert!(matches!(
            verdict(&eng, "drop.example.com."),
            FilterVerdict::Block(_)
        ));
        assert!(matches!(
            verdict(&eng, "tcp.example.com."),
            FilterVerdict::Allow
        ));
    }

    #[test]
    /**
     * @brief rpz-drop 이 침묵하지 않고 운영자가 고른 차단 응답으로 답하는지.
     * @details 받아 온 영역이 침묵을 고르게 두면 차단이 장애처럼 보인다. 고정된 응답을 쓰면 같은
     *          차단인데도 목록 형식에 따라 클라이언트가 받는 답이 달라진다.
     */
    fn rpz_drop_answers_with_the_configured_block_response() {
        let mut parts = EngineParts::default();
        parse_rpz_text("drop.example.com CNAME rpz-drop.\n", &mut parts);
        let eng = BlockEngine::new(parts, BlockResponse::ZeroIp);
        assert!(matches!(
            verdict(&eng, "drop.example.com."),
            FilterVerdict::Block(BlockResponse::ZeroIp)
        ));
    }

    #[test]
    /** @brief 이 서버가 지원하는 RPZ 부분집합이 동작하는지. */
    fn rpz_subset() {
        let mut parts = EngineParts::default();
        let rpz = "\
; comment
bad.example.com CNAME .
rw.example.com A 9.9.9.9
ok.example.com CNAME rpz-passthru.
";
        parse_rpz_text(rpz, &mut parts);
        let eng = BlockEngine::new(parts, BlockResponse::NxDomain);
        assert!(matches!(
            verdict(&eng, "bad.example.com."),
            FilterVerdict::Block(_)
        ));
        assert!(matches!(
            verdict(&eng, "rw.example.com."),
            FilterVerdict::Rewrite(_)
        ));
        assert!(matches!(
            verdict(&eng, "ok.example.com."),
            FilterVerdict::Allow
        ));
    }
}
