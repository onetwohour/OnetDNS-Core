//! Blocklist parsers for AdGuard, ABP, hosts, and RPZ formats; every format ends up as domain sets
//! and rule lists.
//!
//! A file that cannot be read is an error: skipping it would start normally with the filter gone. A
//! file that fails partway applies none of its rules, since a half-loaded filter is worse than
//! none.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::Path;

const MAX_LOCAL_LIST_FILE: u64 = 128 * 1024 * 1024;
const MAX_LOCAL_LIST_LINE: u64 = 1024 * 1024;

fn list_too_large() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "Filter list exceeds the 128 MiB size limit",
    )
}

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

/// With `digest`, also feeds it every line on the way.
fn open_validated_list_file(
    path: &Path,
    mut digest: Option<&mut RulesDigest>,
) -> std::io::Result<File> {
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
            if let Some(digest) = digest.as_deref_mut() {
                digest.line(&line);
            }
        }
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

/// Identifies what parsing a list depends on: its trimmed rule lines in order, and whether they
/// are read as allow rules. Comments are left out, so a list that changed only its header keeps
/// its parsed form.
struct RulesDigest(sha2::Sha256);

impl RulesDigest {
    fn new(allow: bool) -> Self {
        use sha2::Digest;
        Self(sha2::Sha256::new_with_prefix([u8::from(allow)]))
    }

    fn line(&mut self, line: &str) {
        use sha2::Digest;
        let line = line.trim();
        if is_rule_line(line) {
            self.0.update(line.as_bytes());
            self.0.update(b"\n");
        }
    }

    fn finish(self) -> [u8; 32] {
        use sha2::Digest;
        self.0.finalize().into()
    }
}

/// A failure partway makes the whole file an error; the caller applies none of its rules.
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

use crate::compact::{reverse_cmp, CompactDomainMap, SourceTable, SourceTableBuilder};
use crate::engine::{BlockEngine, DomainSet, EngineParts, RpzIpRule, RpzNameRule};
use crate::table::{DomainTable, KeyRun};
use std::collections::{BinaryHeap, HashSet};

#[derive(Default)]
struct Accum {
    parts: EngineParts,

    /// Placements of `$badfilter` rules, removed once every rule has been read.
    cancels: Vec<Placement>,

    cur_source: u32,

    /// Set while one list is parsed for a [`ParsedList`]: only domain entries are placed, and a
    /// line with any other rule sets `deferred_line` so its text is kept instead.
    defer_others: bool,
    deferred_line: bool,
}

impl Accum {
    fn new() -> Self {
        Accum {
            cur_source: crate::engine::NO_SOURCE,
            ..Default::default()
        }
    }

    fn register_source(&mut self, name: String) {
        self.cur_source = self.parts.sources.len() as u32;
        self.parts.sources.push(name);
    }

    fn emit(&mut self, placement: Placement, badfilter: bool) {
        if self.defer_others && (badfilter || !matches!(placement, Placement::Domain { .. })) {
            self.deferred_line = true;
        } else if badfilter {
            self.cancels.push(placement);
        } else {
            place(&mut self.parts, placement, self.cur_source);
        }
    }
}

/// The plain sets, each kept once for domain rules and once for regex rules.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Kind {
    Block,
    BlockImportant,
    Allow,
    AllowImportant,
    Refuse,
    Nodata,
    NoResponse,
}

impl Kind {
    pub(crate) const ALL: [Kind; 7] = [
        Kind::Block,
        Kind::BlockImportant,
        Kind::Allow,
        Kind::AllowImportant,
        Kind::Refuse,
        Kind::Nodata,
        Kind::NoResponse,
    ];

    fn of(allow: bool, important: bool) -> Self {
        match (allow, important) {
            (true, true) => Kind::AllowImportant,
            (true, false) => Kind::Allow,
            (false, true) => Kind::BlockImportant,
            (false, false) => Kind::Block,
        }
    }
}

#[derive(Clone, PartialEq)]
pub(crate) enum Slot {
    Plain(Kind),
    Typed(RecordType),
    /// Every type except these, sorted and deduplicated.
    TypedExcept(Vec<RecordType>),
}

/// Where one rule lands. A `$badfilter` rule computes its placement the same way and removes it,
/// so it cancels only the rule written the same way without `$badfilter`.
enum Placement {
    Domain {
        slot: Slot,
        domain: String,
        exact: bool,
    },
    Rewrite {
        domain: String,
        exact: bool,
        target: RewriteTarget,
    },
    Regex {
        slot: Slot,
        pattern: String,
    },
    RegexRewrite {
        pattern: String,
        target: RewriteTarget,
    },
    Client(crate::engine::ClientRule),
}

fn split_mods(s: &str) -> (&str, Vec<&str>) {
    match s.find('$') {
        Some(i) => (&s[..i], s[i + 1..].split(',').collect()),
        None => (s, vec![]),
    }
}

struct RuleMods<'a> {
    important: bool,
    badfilter: bool,
    dnstypes: Vec<RecordType>,
    dnstype_excluded: Vec<RecordType>,
    dnsrewrite: Option<&'a str>,
    client_conds: Vec<crate::engine::ClientCond>,
    ctags: Vec<(bool, String)>,
    denyallow: Vec<String>,
}

/// Browser-only modifiers that mean nothing to a DNS server are counted as not applicable, not as
/// errors; counting them as errors would bury real problems in the report.
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
        let rule = crate::engine::ClientRule {
            domain: String::new(),
            regex: Some(pat.to_string()),
            allow,
            clients: client_conds,
            ctags,
            denyallow,
        };
        acc.emit(Placement::Client(rule), badfilter);
        return;
    }

    let pattern = pat.to_string();
    if let Some(v) = dnsrewrite {
        match parse_dnsrewrite(v) {
            Some(DnsRewrite::Code(kind)) => acc.emit(
                Placement::Regex {
                    slot: Slot::Plain(kind),
                    pattern,
                },
                badfilter,
            ),
            Some(DnsRewrite::Target(target)) => {
                acc.emit(Placement::RegexRewrite { pattern, target }, badfilter)
            }
            None => skip_invalid_pattern(acc),
        }
        return;
    }

    if !dnstype_excluded.is_empty() && !allow {
        dnstype_excluded.sort_by_key(|t| t.0);
        dnstype_excluded.dedup();
        let slot = Slot::TypedExcept(dnstype_excluded);
        acc.emit(Placement::Regex { slot, pattern }, badfilter);
        return;
    }

    if !dnstypes.is_empty() && !allow {
        for t in dnstypes {
            let pattern = pattern.clone();
            acc.emit(
                Placement::Regex {
                    slot: Slot::Typed(t),
                    pattern,
                },
                badfilter,
            );
        }
        return;
    }

    let slot = Slot::Plain(Kind::of(allow, important));
    acc.emit(Placement::Regex { slot, pattern }, badfilter);
}

/// Formats are told apart by prefix: `||` is a domain, `@@` an allow rule, `/` a regex, anything
/// else a hosts line or a bare domain.
fn parse_line(line: &str, acc: &mut Accum, into_allow: bool) {
    let line = line.trim();
    if !is_rule_line(line) {
        return;
    }

    acc.parts.report.rules_total += 1;

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
        let rule = crate::engine::ClientRule {
            domain,
            regex: None,
            allow,
            clients: client_conds,
            ctags,
            denyallow,
        };
        acc.emit(Placement::Client(rule), badfilter);
        return;
    }

    if let Some(v) = dnsrewrite {
        let placement = extract_domain(pattern).and_then(|domain| {
            Some(match parse_dnsrewrite(v)? {
                DnsRewrite::Code(kind) => Placement::Domain {
                    slot: Slot::Plain(kind),
                    domain,
                    exact: false,
                },
                DnsRewrite::Target(target) => Placement::Rewrite {
                    domain,
                    exact: false,
                    target,
                },
            })
        });
        match placement {
            Some(placement) => acc.emit(placement, badfilter),
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
                let domain = host.to_string();
                let placement = if is_unspecified_or_loopback(&ip) {
                    Placement::Domain {
                        slot: Slot::Plain(Kind::of(allow, important)),
                        domain,
                        exact: true,
                    }
                } else {
                    Placement::Rewrite {
                        domain,
                        exact: true,
                        target: RewriteTarget::ip(ip),
                    }
                };
                acc.emit(placement, badfilter);
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

    if allow && (!dnstypes.is_empty() || !dnstype_excluded.is_empty()) {
        acc.parts.report.rules_skipped += 1;
        *acc.parts
            .report
            .unsupported_modifier
            .entry("dnstype(allow)".to_string())
            .or_default() += 1;
        return;
    }

    if !dnstype_excluded.is_empty() {
        dnstype_excluded.sort_by_key(|t| t.0);
        dnstype_excluded.dedup();
        let placement = Placement::Domain {
            slot: Slot::TypedExcept(dnstype_excluded),
            domain: dom,
            exact: false,
        };
        acc.emit(placement, badfilter);
        return;
    }

    if !dnstypes.is_empty() {
        for t in dnstypes {
            let placement = Placement::Domain {
                slot: Slot::Typed(t),
                domain: dom.clone(),
                exact: false,
            };
            acc.emit(placement, badfilter);
        }
        return;
    }

    let placement = Placement::Domain {
        slot: Slot::Plain(Kind::of(allow, important)),
        domain: dom,
        exact: false,
    };
    acc.emit(placement, badfilter);
}

/// Takes a trimmed line. Anything else is a blank line or a comment and does not change the filter.
fn is_rule_line(line: &str) -> bool {
    !(line.is_empty() || line.starts_with('#') || line.starts_with('!'))
}

fn skip_invalid_pattern(acc: &mut Accum) {
    acc.parts.report.rules_skipped += 1;
    acc.parts.report.invalid_pattern += 1;
}

/// Browser-only modifiers, which do not apply to a DNS server.
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

fn plain_set(parts: &mut EngineParts, kind: Kind) -> &mut DomainSet {
    match kind {
        Kind::Block => &mut parts.block,
        Kind::BlockImportant => &mut parts.block_important,
        Kind::Allow => &mut parts.allow,
        Kind::AllowImportant => &mut parts.allow_important,
        Kind::Refuse => &mut parts.refuse,
        Kind::Nodata => &mut parts.nodata,
        Kind::NoResponse => &mut parts.no_response,
    }
}

fn regex_list(parts: &mut EngineParts, kind: Kind) -> &mut Vec<String> {
    match kind {
        Kind::Block => &mut parts.regex_block,
        Kind::BlockImportant => &mut parts.regex_block_important,
        Kind::Allow => &mut parts.regex_allow,
        Kind::AllowImportant => &mut parts.regex_allow_important,
        Kind::Refuse => &mut parts.regex_refuse,
        Kind::Nodata => &mut parts.regex_nodata,
        Kind::NoResponse => &mut parts.regex_no_response,
    }
}

fn domain_set(parts: &mut EngineParts, slot: Slot) -> &mut DomainSet {
    match slot {
        Slot::Plain(kind) => plain_set(parts, kind),
        Slot::Typed(t) => {
            let idx = match parts.typed_block.iter().position(|(rt, _)| *rt == t) {
                Some(idx) => idx,
                None => {
                    parts.typed_block.push((t, DomainSet::default()));
                    parts.typed_block.len() - 1
                }
            };
            &mut parts.typed_block[idx].1
        }
        Slot::TypedExcept(excluded) => {
            let sets = &mut parts.typed_block_except;
            let idx = match sets.iter().position(|(e, _)| *e == excluded) {
                Some(idx) => idx,
                None => {
                    sets.push((excluded, DomainSet::default()));
                    sets.len() - 1
                }
            };
            &mut sets[idx].1
        }
    }
}

/// Unlike `domain_set`, does not create a typed set that no rule has used.
fn existing_domain_set<'a>(parts: &'a mut EngineParts, slot: &Slot) -> Option<&'a mut DomainSet> {
    match slot {
        Slot::Plain(kind) => Some(plain_set(parts, *kind)),
        Slot::Typed(t) => parts
            .typed_block
            .iter_mut()
            .find(|(rt, _)| rt == t)
            .map(|(_, set)| set),
        Slot::TypedExcept(excluded) => parts
            .typed_block_except
            .iter_mut()
            .find(|(e, _)| e == excluded)
            .map(|(_, set)| set),
    }
}

fn place(parts: &mut EngineParts, placement: Placement, src: u32) {
    match placement {
        Placement::Domain {
            slot,
            domain,
            exact,
        } => {
            let set = domain_set(parts, slot);
            if exact {
                set.add_exact_src(&domain, src);
            } else {
                set.add_suffix_src(&domain, src);
            }
        }
        Placement::Rewrite {
            domain,
            exact,
            target,
        } => {
            if exact {
                parts.rewrites.add_exact(&domain, target);
            } else {
                parts.rewrites.add_suffix(&domain, target);
            }
        }
        Placement::Regex { slot, pattern } => match slot {
            Slot::Plain(kind) => regex_list(parts, kind).push(pattern),
            Slot::Typed(t) => parts.regex_typed_block.push((t, pattern)),
            Slot::TypedExcept(excluded) => parts.regex_typed_block_except.push((excluded, pattern)),
        },
        Placement::RegexRewrite { pattern, target } => {
            parts.regex_rewrites.push((pattern, target));
        }
        Placement::Client(rule) => parts.client_rules.push(rule),
    }
}

fn cancel(parts: &mut EngineParts, placement: &Placement) {
    match placement {
        Placement::Domain {
            slot,
            domain,
            exact,
        } => {
            if let Some(set) = existing_domain_set(parts, slot) {
                if *exact {
                    set.remove_exact(domain);
                } else {
                    set.remove_suffix(domain);
                }
            }
        }
        Placement::Rewrite {
            domain,
            exact,
            target,
        } => parts.rewrites.remove(domain, *exact, target),
        Placement::Regex { slot, pattern } => match slot {
            Slot::Plain(kind) => regex_list(parts, *kind).retain(|p| p != pattern),
            Slot::Typed(t) => parts
                .regex_typed_block
                .retain(|(rt, p)| !(rt == t && p == pattern)),
            Slot::TypedExcept(excluded) => parts
                .regex_typed_block_except
                .retain(|(e, p)| !(e == excluded && p == pattern)),
        },
        Placement::RegexRewrite { pattern, target } => parts
            .regex_rewrites
            .retain(|(p, t)| !(p == pattern && t == target)),
        Placement::Client(rule) => parts.client_rules.retain(|r| r != rule),
    }
}

/// What a `$dnsrewrite` value asks for.
enum DnsRewrite {
    /// A response code, answered from the matching set.
    Code(Kind),
    /// An address or a name.
    Target(RewriteTarget),
}

fn parse_dnsrewrite(value: &str) -> Option<DnsRewrite> {
    let segs: Vec<&str> = value.split(';').collect();
    let val = if segs.len() == 3 { segs[2] } else { segs[0] };
    let upper = val.trim().to_ascii_uppercase();

    let kind = match upper.as_str() {
        "NXDOMAIN" => Some(Kind::Block),
        "REFUSED" => Some(Kind::Refuse),
        "" | "NODATA" | "NOERROR" => Some(Kind::Nodata),
        "NORESPONSE" => Some(Kind::NoResponse),
        _ => None,
    };
    if let Some(kind) = kind {
        return Some(DnsRewrite::Code(kind));
    }

    if let Ok(ip) = val.parse::<IpAddr>() {
        return Some(DnsRewrite::Target(RewriteTarget::ip(ip)));
    }
    if looks_like_domain(val) {
        if let Ok(name) = Name::from_str(val) {
            return Some(DnsRewrite::Target(RewriteTarget::Cname(name)));
        }
    }
    None
}

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

fn looks_like_domain(s: &str) -> bool {
    !s.is_empty()
        && s.contains('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

/// The addresses that mean blocked in hosts format.
fn is_unspecified_or_loopback(ip: &IpAddr) -> bool {
    ip.is_unspecified() || ip.is_loopback()
}

/// Runs after every rule has been read, so a `$badfilter` rule cancels its rule wherever it is.
fn apply_badfilter(acc: &mut Accum) {
    for placement in std::mem::take(&mut acc.cancels) {
        cancel(&mut acc.parts, &placement);
    }
}

/// The dashboard shows the reason.
pub fn validate_rule(line: &str) -> Result<(), String> {
    let trimmed = line.trim();
    if !is_rule_line(trimmed) {
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

/// Handles the subset this server supports: name-based and address-based rules.
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

/// rpz-drop means no answer, but it is answered with the configured block response: silence from a
/// fetched zone makes clients treat the block as an outage and retry until they time out. Silence
/// is used only for names the operator chose with NORESPONSE. rpz-tcp-only is not supported and the
/// rule is skipped. Neither is taken as a CNAME target.
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

/// An RPZ owner name covers only that name; subdomains are covered by a separate owner starting
/// with `*.`. The engine's suffix rules also cover the parent name itself, so a `*.example` rule
/// matches example too: the engine has no rule that covers subdomains only.
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

fn rpz_ip_owner<'a>(owner: &'a str, marker: &str) -> Option<&'a str> {
    let pat = format!(".{marker}");
    let idx = owner.find(&pat)?;
    let enc = &owner[..idx];
    (!enc.is_empty()).then_some(enc)
}

/// Decodes RPZ's reversed address notation into a network.
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

fn find_type<'a>(rest: &'a [&'a str]) -> Option<(&'a str, &'a [&'a str])> {
    for (i, t) in rest.iter().enumerate() {
        let up = t.to_ascii_uppercase();
        if matches!(up.as_str(), "CNAME" | "A" | "AAAA" | "PTR" | "TXT") {
            return Some((rest[i], &rest[i + 1..]));
        }
    }
    None
}

pub fn load_parts(
    blocklists: &[impl AsRef<Path>],
    allowlists: &[impl AsRef<Path>],
    extra_block: &[&str],
    extra_allow: &[&str],
) -> std::io::Result<EngineParts> {
    load_parts_with_subscriptions(blocklists, allowlists, &[], extra_block, extra_allow)
}

pub enum SubscriptionRules<'a> {
    File(&'a Path),
    /// In memory, when no cache directory is used.
    Lines(&'a [String]),
}

/// One subscribed blocklist. Its name is registered as the source of its rules, which is how the
/// query log shows which list blocked a name; the rule text itself is not kept.
pub struct SubscriptionSource<'a> {
    pub name: &'a str,
    pub rules: SubscriptionRules<'a>,
}

pub fn load_parts_with_subscriptions(
    blocklists: &[impl AsRef<Path>],
    allowlists: &[impl AsRef<Path>],
    subscriptions: &[SubscriptionSource<'_>],
    extra_block: &[&str],
    extra_allow: &[&str],
) -> std::io::Result<EngineParts> {
    load_parts_with_store(
        blocklists,
        allowlists,
        subscriptions,
        extra_block,
        extra_allow,
        None,
        |_| Ok(()),
    )
}

/// Like [`load_parts_with_subscriptions`], but a list file whose rules `store` already holds is
/// not parsed again. `tail` then adds rules after every list and user rule, where `$badfilter`
/// does not reach them; the domain sets it sees hold only the user rules. The domain sets come
/// back frozen.
pub fn load_parts_with_store(
    blocklists: &[impl AsRef<Path>],
    allowlists: &[impl AsRef<Path>],
    subscriptions: &[SubscriptionSource<'_>],
    extra_block: &[&str],
    extra_allow: &[&str],
    mut store: Option<&mut dyn ParsedListStore>,
    tail: impl FnOnce(&mut EngineParts) -> std::io::Result<()>,
) -> std::io::Result<EngineParts> {
    let mut lists = Vec::new();
    for path in blocklists {
        let path = path.as_ref();
        let rules = SubscriptionRules::File(path);
        let list = load_list(&rules, false, "blocklist", &mut store)?;
        lists.push((path.display().to_string(), false, list));
    }
    for path in allowlists {
        let path = path.as_ref();
        let rules = SubscriptionRules::File(path);
        let list = load_list(&rules, true, "allowlist", &mut store)?;
        lists.push((path.display().to_string(), true, list));
    }
    for subscription in subscriptions {
        let list = load_list(
            &subscription.rules,
            false,
            "subscription blocklist cache",
            &mut store,
        )?;
        lists.push((subscription.name.to_string(), false, list));
    }
    combine(lists, extra_block, extra_allow, tail)
}

/// Keeps parsed lists between builds. `rules` digests a list's trimmed rule lines and whether they
/// were read as allow rules, so comment-only changes keep the same entry.
pub trait ParsedListStore {
    fn load(&mut self, rules: &[u8; 32]) -> Option<ParsedList>;

    /// A list that is not kept is parsed again next time.
    fn save(&mut self, rules: &[u8; 32], list: &ParsedList);
}

/// One list parsed on its own. Domain entries are kept sorted for the automaton. Every other rule
/// is kept as its line and parsed again when lists are combined, because `$badfilter` and rewrites
/// act across lists.
pub struct ParsedList {
    /// In first-use order, which decides the order of typed sets.
    pub(crate) sets: Vec<(Slot, ListSet)>,
    pub(crate) other_lines: Vec<String>,
    pub(crate) report: crate::engine::FilterLoadReport,
}

pub(crate) struct ListSet {
    pub(crate) exact: KeyRun,
    pub(crate) suffix: KeyRun,
}

impl ListSet {
    fn take(set: &mut DomainSet) -> Self {
        let (exact, suffix) = set.take_tables();
        Self {
            exact: KeyRun::Parsed(exact.into_sorted(reverse_cmp)),
            suffix: KeyRun::Parsed(suffix.into_sorted(reverse_cmp)),
        }
    }
}

impl ParsedList {
    pub(crate) fn parse(
        allow: bool,
        read: impl FnOnce(&mut dyn FnMut(&str)) -> std::io::Result<()>,
    ) -> std::io::Result<Self> {
        let mut acc = Accum {
            defer_others: true,
            ..Accum::new()
        };
        let mut other_lines = Vec::new();
        read(&mut |line| {
            parse_line(line, &mut acc, allow);
            if std::mem::take(&mut acc.deferred_line) {
                other_lines.push(line.trim().to_string());
            }
        })?;
        let mut parts = acc.parts;
        let mut sets = Vec::new();
        for kind in Kind::ALL {
            let set = plain_set(&mut parts, kind);
            if !set.is_empty() {
                sets.push((Slot::Plain(kind), ListSet::take(set)));
            }
        }
        for (rtype, mut set) in parts.typed_block {
            sets.push((Slot::Typed(rtype), ListSet::take(&mut set)));
        }
        for (types, mut set) in parts.typed_block_except {
            sets.push((Slot::TypedExcept(types), ListSet::take(&mut set)));
        }
        Ok(Self {
            sets,
            other_lines,
            report: parts.report,
        })
    }
}

/// `label` names the kind of list in errors.
fn load_list(
    rules: &SubscriptionRules<'_>,
    allow: bool,
    label: &str,
    store: &mut Option<&mut dyn ParsedListStore>,
) -> std::io::Result<ParsedList> {
    let path = match rules {
        SubscriptionRules::File(path) => *path,
        SubscriptionRules::Lines(lines) => {
            return ParsedList::parse(allow, |on_line| {
                lines.iter().for_each(|line| on_line(line));
                Ok(())
            });
        }
    };
    let mut digest = store.is_some().then(|| RulesDigest::new(allow));
    let file = open_validated_list_file(path, digest.as_mut()).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "Could not read or validate {label} '{}': {error}",
                path.display()
            ),
        )
    })?;
    let digest = digest.map(RulesDigest::finish);
    if let (Some(store), Some(digest)) = (store.as_deref_mut(), &digest) {
        if let Some(list) = store.load(digest) {
            return Ok(list);
        }
    }
    let list = ParsedList::parse(allow, |on_line| parse_validated_list_file(file, on_line))
        .map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("Could not read {label} '{}': {error}", path.display()),
            )
        })?;
    if let (Some(store), Some(digest)) = (store.as_deref_mut(), &digest) {
        store.save(digest, &list);
    }
    Ok(list)
}

/// Puts parsed lists together in order. A name in several lists keeps the earliest as its source,
/// user rules come after every list, and `$badfilter` rules act across all of them, as if
/// everything had been parsed in one pass.
fn combine(
    lists: Vec<(String, bool, ParsedList)>,
    extra_block: &[&str],
    extra_allow: &[&str],
    tail: impl FnOnce(&mut EngineParts) -> std::io::Result<()>,
) -> std::io::Result<EngineParts> {
    let mut acc = Accum::new();
    let mut slots: Vec<(Slot, Vec<(u32, ListSet)>)> = Vec::new();
    for (name, allow, list) in lists {
        acc.register_source(name);
        let ParsedList {
            sets,
            other_lines,
            report,
        } = list;
        // The list's report already counts these lines.
        let counted = std::mem::take(&mut acc.parts.report);
        for line in &other_lines {
            parse_line(line, &mut acc, allow);
        }
        acc.parts.report = counted;
        acc.parts.report.absorb(report);
        for (slot, set) in sets {
            let source = acc.cur_source;
            match slots.iter_mut().find(|(known, _)| *known == slot) {
                Some((_, runs)) => runs.push((source, set)),
                None => slots.push((slot, vec![(source, set)])),
            }
        }
    }
    acc.cur_source = crate::engine::NO_SOURCE;
    for rule in extra_block {
        parse_line(rule, &mut acc, false);
    }
    for rule in extra_allow {
        parse_line(rule, &mut acc, true);
    }
    let cancelled: Vec<(Slot, bool, String)> = acc
        .cancels
        .iter()
        .filter_map(|placement| match placement {
            Placement::Domain {
                slot,
                domain,
                exact,
            } => Some((slot.clone(), *exact, crate::engine::normalize_str(domain))),
            _ => None,
        })
        .collect();
    apply_badfilter(&mut acc);
    let mut parts = acc.parts;
    tail(&mut parts)?;

    // The sets still in `parts` hold the user rules and the tail, which rank after every list.
    for kind in Kind::ALL {
        let slot = Slot::Plain(kind);
        let runs = match slots.iter().position(|(known, _)| *known == slot) {
            Some(index) => slots.remove(index).1,
            None => Vec::new(),
        };
        build_set(plain_set(&mut parts, kind), runs, &slot, &cancelled);
    }
    let mut own_typed = std::mem::take(&mut parts.typed_block);
    let mut own_typed_except = std::mem::take(&mut parts.typed_block_except);
    for (slot, runs) in slots {
        let mut set = DomainSet::default();
        match &slot {
            Slot::Typed(rtype) => {
                if let Some(index) = own_typed.iter().position(|(known, _)| known == rtype) {
                    set = own_typed.remove(index).1;
                }
                build_set(&mut set, runs, &slot, &cancelled);
                parts.typed_block.push((*rtype, set));
            }
            Slot::TypedExcept(types) => {
                if let Some(index) = own_typed_except
                    .iter()
                    .position(|(known, _)| known == types)
                {
                    set = own_typed_except.remove(index).1;
                }
                build_set(&mut set, runs, &slot, &cancelled);
                parts.typed_block_except.push((types.clone(), set));
            }
            Slot::Plain(_) => {}
        }
    }
    for (rtype, mut set) in own_typed {
        build_set(&mut set, Vec::new(), &Slot::Typed(rtype), &cancelled);
        parts.typed_block.push((rtype, set));
    }
    for (types, mut set) in own_typed_except {
        let slot = Slot::TypedExcept(types.clone());
        build_set(&mut set, Vec::new(), &slot, &cancelled);
        parts.typed_block_except.push((types, set));
    }
    Ok(parts)
}

/// Replaces `set`, which holds the rules ranked after every list, with the frozen merge of the
/// lists' entries and its own. `cancelled` removes entries from the lists only.
fn build_set(
    set: &mut DomainSet,
    lists: Vec<(u32, ListSet)>,
    slot: &Slot,
    cancelled: &[(Slot, bool, String)],
) {
    let (own_exact, own_suffix) = set.take_tables();
    let mut exact_runs = Vec::with_capacity(lists.len());
    let mut suffix_runs = Vec::with_capacity(lists.len());
    for (source, ListSet { exact, suffix }) in lists {
        exact_runs.push((source, exact));
        suffix_runs.push((source, suffix));
    }
    let cancelled_in = |exact: bool| -> HashSet<&str> {
        cancelled
            .iter()
            .filter(|(known, known_exact, _)| known == slot && *known_exact == exact)
            .map(|(_, _, name)| name.as_str())
            .collect()
    };
    *set = DomainSet::from_built(
        merge_runs(exact_runs, own_exact, &cancelled_in(true)),
        merge_runs(suffix_runs, own_suffix, &cancelled_in(false)),
    );
}

fn merge_runs(
    lists: Vec<(u32, KeyRun)>,
    own: DomainTable,
    cancelled: &HashSet<&str>,
) -> Result<CompactDomainMap, DomainTable> {
    let mut lists: Vec<(u32, KeyRun)> = lists
        .into_iter()
        .filter(|(_, run)| !run.is_empty())
        .collect();
    let own = (!own.is_empty()).then(|| own.into_sorted(reverse_cmp));
    if lists.is_empty() {
        return match own {
            Some(own) => CompactDomainMap::try_from_sorted(own),
            None => Ok(CompactDomainMap::default()),
        };
    }
    if lists.len() == 1 && own.is_none() && cancelled.is_empty() {
        if let Some((source, run)) = lists.pop() {
            return match run {
                KeyRun::Parsed(mut sorted) => {
                    sorted.set_source(source);
                    CompactDomainMap::try_from_sorted(sorted)
                }
                KeyRun::Stored { names, offsets } => {
                    let sources = SourceTable::uniform(source, offsets.len() - 1);
                    CompactDomainMap::try_from_staged(names, offsets, sources)
                }
            };
        }
    }

    let mut inputs: Vec<Box<dyn Iterator<Item = (&str, u32)> + '_>> = lists
        .iter()
        .map(|(source, run)| {
            let source = *source;
            Box::new(run.names().map(move |name| (name, source))) as Box<dyn Iterator<Item = _>>
        })
        .collect();
    // `$badfilter` was already applied to the user rules and the tail, the last input.
    let own_input = inputs.len();
    if let Some(own) = &own {
        inputs.push(Box::new(own.iter()));
    }
    let mut heap = BinaryHeap::with_capacity(inputs.len());
    for (input, entries) in inputs.iter_mut().enumerate() {
        if let Some((name, source)) = entries.next() {
            heap.push(MergeHead {
                name,
                input,
                source,
            });
        }
    }
    let most_names = lists.iter().map(|(_, run)| run.len()).sum::<usize>()
        + own.as_ref().map_or(0, |own| own.len());
    let most_bytes = lists.iter().map(|(_, run)| run.text_len()).sum::<usize>()
        + own.as_ref().map_or(0, |own| own.text_len());
    let mut names = String::with_capacity(most_bytes.min(u32::MAX as usize));
    let mut offsets = Vec::with_capacity(most_names + 1);
    offsets.push(0u32);
    let mut sources = SourceTableBuilder::with_capacity(most_names);
    let mut overflowed = false;
    while let Some(first) = heap.pop() {
        let name = first.name;
        let dropped = cancelled.contains(name);
        let mut winner = None;
        let mut current = Some(first);
        while let Some(head) = current {
            if winner.is_none() && (!dropped || head.input >= own_input) {
                winner = Some(head.source);
            }
            if let Some((next, source)) = inputs[head.input].next() {
                heap.push(MergeHead {
                    name: next,
                    input: head.input,
                    source,
                });
            }
            current = if heap.peek().is_some_and(|next| next.name == name) {
                heap.pop()
            } else {
                None
            };
        }
        let Some(source) = winner else {
            continue;
        };
        if names.len() + name.len() >= u32::MAX as usize {
            if !overflowed {
                overflowed = true;
                onetdns_core::warn!(
                    event = "filter.rule_table_overflow",
                    "Blocklist exceeds the 32-bit index limit; later rules were not added"
                );
            }
            continue;
        }
        names.push_str(name);
        offsets.push(names.len() as u32);
        sources.push(source);
    }
    // Free the inputs before the automaton is built.
    drop(inputs);
    drop(lists);
    drop(own);
    CompactDomainMap::try_from_staged(names, offsets, sources.finish())
}

/// Orders the heap so the smallest name pops first, and among equal names the earliest input.
struct MergeHead<'a> {
    name: &'a str,
    input: usize,
    source: u32,
}

impl Ord for MergeHead<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        reverse_cmp(other.name, self.name).then_with(|| other.input.cmp(&self.input))
    }
}

impl PartialOrd for MergeHead<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for MergeHead<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for MergeHead<'_> {}

pub fn load_lists(
    blocklists: &[impl AsRef<Path>],
    allowlists: &[impl AsRef<Path>],
    default_block: BlockResponse,
) -> std::io::Result<BlockEngine> {
    load_lists_with(blocklists, allowlists, &[], &[], default_block)
}

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

/// For tests and validation.
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

/// Keeps each source's name.
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
mod tests {
    use super::*;
    use onetdns_core::{ClientInfo, FilterEngine, FilterVerdict, Transport};

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
    /// Counting them as errors would make the report useless.
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
    /// Needed to show which list blocked a name.
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
    /// A badfilter rule names one rule by its text; removing every rule for the name took out
    /// important, typed, and allow rules that the list author meant to keep.
    fn badfilter_cancels_only_the_rule_written_the_same_way() {
        let rules = "\
||imp.example^$important
||imp.example^$badfilter
||typed.example^$dnstype=AAAA
||typed.example^$badfilter
||gone-typed.example^$dnstype=AAAA
||gone-typed.example^$dnstype=AAAA,badfilter
/^re\\./$important
/^re\\./$badfilter
||both.example^
@@||both.example^
@@||both.example^$badfilter
||cl.example^$client=10.0.0.0/8
||cl.example^$client=10.0.0.0/8,badfilter
||only-bad.example^$dnsrewrite=192.0.2.1,badfilter
";
        let eng = build_from_str(rules, "", BlockResponse::NxDomain);
        let ask = |name: &str, qtype: RecordType, source: &str| {
            let client = ClientInfo {
                source_ip: source.parse().unwrap(),
                client_id: None,
                transport: Transport::Do53Udp,
                authenticated: false,
            };
            eng.verdict(&Name::from_str(name).unwrap(), qtype, &client)
        };
        let local = "127.0.0.1";
        let blocked = |v: FilterVerdict| matches!(v, FilterVerdict::Block(_));
        let allowed = |v: FilterVerdict| matches!(v, FilterVerdict::Allow);

        assert!(blocked(ask("imp.example.", RecordType::A, local)));
        assert!(blocked(ask("typed.example.", RecordType::AAAA, local)));
        assert!(allowed(ask("gone-typed.example.", RecordType::AAAA, local)));
        assert!(blocked(ask("re.example.", RecordType::A, local)));
        assert!(
            blocked(ask("both.example.", RecordType::A, local)),
            "the allow rule was cancelled, so the block rule applies"
        );
        assert!(allowed(ask("cl.example.", RecordType::A, "10.1.2.3")));
        assert!(
            allowed(ask("only-bad.example.", RecordType::A, local)),
            "a badfilter rule must not add a rule of its own"
        );
    }

    #[test]
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
    /// Whether read from a cache file or from lines in memory; extra rules outside any list have no
    /// source. Otherwise the query log would name the wrong list.
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
    /// A half-applied file must not happen.
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
    /// Otherwise the filter would silently disappear.
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
    /// The value is case-insensitive like the other response codes. If rule validation rejected it,
    /// the dashboard could not add the rule; if badfilter could not remove it, a rule in a
    /// subscribed list could not be turned off.
    fn dnsrewrite_noresponse_drops_names_and_patterns() {
        let rules = "\
||quiet.example^$dnsrewrite=NORESPONSE
/^scan[0-9]+\\.example$/$dnsrewrite=noresponse
||gone.example^$dnsrewrite=NORESPONSE
||gone.example^$dnsrewrite=NORESPONSE,badfilter
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
    /// A `$client` rule does not block other clients.
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
    /// If an exact owner covered subdomains, one allow rule would open the whole zone; if rpz-drop
    /// were read as a CNAME, a name meant to be blocked would resolve to that name.
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
    /// Silence chosen by a fetched zone makes a block look like an outage. A fixed response would
    /// give clients different answers for the same block depending on the list format.
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

    const LIST_A: &str = "\
! Title: list a
||ads.example^
||shared.example^
0.0.0.0 hosts-block.example other-host.example
0.0.0.0 .
192.0.2.7 rewrite-host.example
||typed.example^$dnstype=AAAA
||except.example^$dnstype=~A|~MX
||important.example^$important
/^regex[0-9]+\\.example$/
||rewrite.example^$dnsrewrite=192.0.2.9
||refused.example^$dnsrewrite=REFUSED
||client.example^$client=192.168.1.0/24
||cancel-me.example^
||cross-cancel.example^
@@||allowed-in-block.example^
||Mixed.Case.Example^
||weird.example^$app=org.example
";

    const LIST_B: &str = "\
||shared.example^
||b-only.example^
||cancel-me.example^$badfilter
||typed.example^$dnstype=AAAA
||mx.example^$dnstype=MX
||cross-cancel.example^
||except.example^$dnstype=~MX|~A
/^regex[0-9]+\\.example$/$badfilter
";

    const LIST_B_CHANGED: &str = "\
||shared.example^
||b-new.example^
||cancel-me.example^$badfilter
||typed.example^$dnstype=AAAA
||mx.example^$dnstype=MX
||cross-cancel.example^
||txt-from-b.example^$dnstype=TXT
";

    const LIST_C: &str = "\
||allowed.example^
||ads.example^
||allowed.example^$important
";

    const LIST_D: &str = "\
# onetdns-fetched: 1
||sub.example^
||cross-cancel.example^$badfilter
||user-cancelled.example^$badfilter
||nodata.example^$dnsrewrite=NODATA
||drop.example^$dnsrewrite=NORESPONSE
";

    const EXTRA_BLOCK: &[&str] = &[
        "||user.example^",
        "||shared.example^",
        "||user-cancelled.example^",
        "||ads.example^$dnstype=TXT",
        "||mx.example^$dnstype=MX",
    ];
    const EXTRA_ALLOW: &[&str] = &["||user-allow.example^", "||b-only.example^"];

    /// What the bin adds after the lists: a cancelled name added back and a name a list already has.
    fn tail(parts: &mut EngineParts) -> std::io::Result<()> {
        parts.refuse.add_suffix("cross-cancel.example");
        parts.block.add_suffix("cross-cancel.example");
        parts.block.add_suffix("tail.example");
        parts.block.add_suffix("ads.example");
        parts.nodata.add_exact("user-cancelled.example");
        Ok(())
    }

    /// Every list in one pass, as loading worked before lists were parsed one at a time.
    fn load_in_one_pass(lists: &[(&str, bool, &str)]) -> EngineParts {
        let mut acc = Accum::new();
        for (name, allow, text) in lists {
            acc.register_source(name.to_string());
            for line in text.lines() {
                parse_line(line, &mut acc, *allow);
            }
        }
        acc.cur_source = crate::engine::NO_SOURCE;
        for rule in EXTRA_BLOCK {
            parse_line(rule, &mut acc, false);
        }
        for rule in EXTRA_ALLOW {
            parse_line(rule, &mut acc, true);
        }
        apply_badfilter(&mut acc);
        let mut parts = acc.parts;
        tail(&mut parts).unwrap();
        parts
    }

    #[derive(Default)]
    struct MemoryStore {
        files: std::collections::HashMap<[u8; 32], Vec<u8>>,
        hits: usize,
        saves: usize,
    }

    impl ParsedListStore for MemoryStore {
        fn load(&mut self, rules: &[u8; 32]) -> Option<ParsedList> {
            let list = crate::cache::decode_parsed_list(self.files.get(rules)?, *rules).ok()?;
            self.hits += 1;
            Some(list)
        }

        fn save(&mut self, rules: &[u8; 32], list: &ParsedList) {
            let mut file = std::io::Cursor::new(Vec::new());
            crate::cache::write_parsed_list(list, *rules, &mut file).unwrap();
            self.files.insert(*rules, file.into_inner());
            self.saves += 1;
        }
    }

    struct ListFiles {
        dir: std::path::PathBuf,
    }

    impl ListFiles {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "onetdns-filter-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }

        fn write(&self, name: &str, text: &str) -> std::path::PathBuf {
            let path = self.dir.join(name);
            std::fs::write(&path, text).unwrap();
            path
        }
    }

    impl Drop for ListFiles {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Loads block files `a` and `b`, allow file `c`, and subscription `d` from a file, the way the
    /// bin does.
    fn load_from_files(
        files: &ListFiles,
        b_text: &str,
        store: Option<&mut dyn ParsedListStore>,
    ) -> EngineParts {
        let a = files.write("a.txt", LIST_A);
        let b = files.write("b.txt", b_text);
        let c = files.write("c.txt", LIST_C);
        let d = files.write("d.list", LIST_D);
        load_parts_with_store(
            &[a, b],
            &[c],
            &[SubscriptionSource {
                name: "https://lists.example/d.txt",
                rules: SubscriptionRules::File(&d),
            }],
            EXTRA_BLOCK,
            EXTRA_ALLOW,
            store,
            tail,
        )
        .unwrap()
    }

    fn reference(files: &ListFiles, b_text: &str) -> EngineParts {
        let path = |name: &str| files.dir.join(name).display().to_string();
        load_in_one_pass(&[
            (&path("a.txt"), false, LIST_A),
            (&path("b.txt"), false, b_text),
            (&path("c.txt"), true, LIST_C),
            ("https://lists.example/d.txt", false, LIST_D),
        ])
    }

    /// Every rule with its list, and the verdict, explanation, and counts for each probe.
    fn describe(parts: EngineParts) -> Vec<String> {
        let source = |id: u32| parts.sources.get(id as usize).cloned();
        let set = |label: String, set: &DomainSet| {
            let entries: Vec<_> = set
                .entries()
                .into_iter()
                .map(|(exact, key, id)| (exact, key, source(id)))
                .collect();
            format!("{label}: {entries:?}")
        };
        let mut out = vec![
            set("block".into(), &parts.block),
            set("allow".into(), &parts.allow),
            set("block_important".into(), &parts.block_important),
            set("allow_important".into(), &parts.allow_important),
            set("refuse".into(), &parts.refuse),
            set("nodata".into(), &parts.nodata),
            set("no_response".into(), &parts.no_response),
        ];
        for (rtype, typed) in &parts.typed_block {
            out.push(set(format!("typed {rtype:?}"), typed));
        }
        for (types, typed) in &parts.typed_block_except {
            out.push(set(format!("typed except {types:?}"), typed));
        }
        let mut rewrites: Vec<_> = parts
            .rewrites
            .exact
            .iter()
            .map(|(name, target)| format!("= {name} {target:?}"))
            .chain(
                parts
                    .rewrites
                    .suffix
                    .iter()
                    .map(|(name, target)| format!("* {name} {target:?}")),
            )
            .collect();
        rewrites.sort();
        out.push(format!("rewrites: {rewrites:?}"));
        out.push(format!(
            "regex: {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
            parts.regex_block,
            parts.regex_allow,
            parts.regex_block_important,
            parts.regex_allow_important,
            parts.regex_refuse,
            parts.regex_nodata,
            parts.regex_no_response,
            parts.regex_rewrites,
            parts.regex_typed_block,
            parts.regex_typed_block_except,
        ));
        out.push(format!("clients: {:?}", parts.client_rules));
        out.push(format!("sources: {:?}", parts.sources));

        let probes: Vec<String> = [LIST_A, LIST_B, LIST_B_CHANGED, LIST_C, LIST_D]
            .iter()
            .flat_map(|text| {
                text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
            })
            .chain(EXTRA_BLOCK.iter().copied())
            .chain(EXTRA_ALLOW.iter().copied())
            .chain(["tail.example", "regex12.example", "nothing.example"])
            .map(|token| token.trim_matches(|c: char| !c.is_ascii_alphanumeric()))
            .filter(|token| token.contains('.') && token.parse::<IpAddr>().is_err())
            .flat_map(|token| [token.to_string(), format!("deep.{token}")])
            .collect();
        let engine = BlockEngine::new(parts, BlockResponse::NxDomain);
        out.push(format!("report: {}", engine.load_report().to_json()));
        out.push(format!(
            "counts: {} {} {:?}",
            engine.block_count(),
            engine.allow_count(),
            engine.source_stats()
        ));
        for address in ["127.0.0.1", "192.168.1.5"] {
            let client = ClientInfo {
                source_ip: address.parse().unwrap(),
                client_id: None,
                transport: Transport::Do53Udp,
                authenticated: false,
            };
            for probe in &probes {
                let Ok(name) = Name::from_str(probe) else {
                    continue;
                };
                for rtype in [
                    RecordType::A,
                    RecordType::AAAA,
                    RecordType::MX,
                    RecordType::TXT,
                    RecordType::HTTPS,
                ] {
                    out.push(format!(
                        "{address} {probe} {rtype:?}: {:?} {:?}",
                        engine.verdict(&name, rtype, &client),
                        engine.explain(&name, rtype, &client)
                    ));
                }
            }
        }
        out
    }

    fn assert_same(actual: EngineParts, expected: EngineParts) {
        let (actual, expected) = (describe(actual), describe(expected));
        assert_eq!(actual.len(), expected.len());
        for (actual, expected) in actual.iter().zip(&expected) {
            assert_eq!(actual, expected);
        }
    }

    #[test]
    /// Each list is parsed on its own and merged; the result must be what one pass over every list
    /// gives, down to which list each rule is credited to.
    fn lists_parsed_one_by_one_match_a_single_pass() {
        let files = ListFiles::new("merge");
        let parts = load_from_files(&files, LIST_B, None);
        assert_same(parts, reference(&files, LIST_B));
    }

    #[test]
    fn stored_lists_build_the_same_engine_as_parsing_them() {
        let files = ListFiles::new("stored");
        let mut store = MemoryStore::default();
        let cold = load_from_files(&files, LIST_B, Some(&mut store));
        assert_eq!((store.hits, store.saves), (0, 4));
        assert_same(cold, reference(&files, LIST_B));

        let warm = load_from_files(&files, LIST_B, Some(&mut store));
        assert_eq!((store.hits, store.saves), (4, 4));
        assert_same(warm, reference(&files, LIST_B));
    }

    #[test]
    /// Only the changed list is parsed again, and the engine matches a full rebuild.
    fn changing_one_list_reparses_only_that_list() {
        let files = ListFiles::new("one-changed");
        let mut store = MemoryStore::default();
        load_from_files(&files, LIST_B, Some(&mut store));
        assert_eq!((store.hits, store.saves), (0, 4));

        let parts = load_from_files(&files, LIST_B_CHANGED, Some(&mut store));
        assert_eq!((store.hits, store.saves), (3, 5));
        assert_same(parts, reference(&files, LIST_B_CHANGED));
    }

    #[test]
    fn comment_changes_keep_the_stored_list() {
        let files = ListFiles::new("comments");
        let mut store = MemoryStore::default();
        load_from_files(&files, LIST_B, Some(&mut store));
        let commented = format!("! Updated: today\n{LIST_B}\n# trailing note\n   \n");
        load_from_files(&files, &commented, Some(&mut store));
        assert_eq!((store.hits, store.saves), (4, 4));

        let reordered: String = LIST_B
            .lines()
            .rev()
            .map(|line| format!("{line}\n"))
            .collect();
        load_from_files(&files, &reordered, Some(&mut store));
        assert_eq!((store.hits, store.saves), (7, 5));
    }

    #[test]
    fn the_same_rules_as_block_and_allow_are_stored_apart() {
        let files = ListFiles::new("allow-flag");
        let mut store = MemoryStore::default();
        let path = files.write("same.txt", "||same.example^\n");
        let empty = &[] as &[std::path::PathBuf];
        let parts = load_parts_with_store(
            std::slice::from_ref(&path),
            std::slice::from_ref(&path),
            &[],
            &[],
            &[],
            Some(&mut store),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!((store.hits, store.saves), (0, 2));
        assert_eq!(parts.block.len(), 1);
        assert_eq!(parts.allow.len(), 1);
        load_parts_with_store(
            empty,
            std::slice::from_ref(&path),
            &[],
            &[],
            &[],
            Some(&mut store),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(store.hits, 1);
    }

    #[test]
    /// A damaged entry is not used; the list is parsed again and the entry replaced.
    fn corrupted_stored_list_falls_back_to_parsing() {
        let files = ListFiles::new("corrupt");
        let mut store = MemoryStore::default();
        load_from_files(&files, LIST_B, Some(&mut store));
        for file in store.files.values_mut() {
            let middle = file.len() / 2;
            file[middle] ^= 0x40;
        }
        let parts = load_from_files(&files, LIST_B, Some(&mut store));
        assert_eq!((store.hits, store.saves), (0, 8));
        assert_same(parts, reference(&files, LIST_B));

        load_from_files(&files, LIST_B, Some(&mut store));
        assert_eq!(store.hits, 4);
    }
}
