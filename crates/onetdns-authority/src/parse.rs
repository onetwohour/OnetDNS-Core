//! RFC 1035 zone file parser. File, directory, and database sources all hand their text here
//! instead of interpreting formats themselves, so input validation lives in one place.
//!
//! Input is untrusted: zone text can be uploaded through the control plane, and database rows may
//! not come from this server. It must not panic on any input, and it is one of the panic sweep's
//! entry points.

use std::net::{Ipv4Addr, Ipv6Addr};

use onetdns_proto::{Name, RData, Record, RecordType, Soa};

use crate::{Zone, MAX_ZONE_RECORDS};

/// Reads line by line with carried state: directives change the origin and default TTL, and a line
/// starting with whitespace inherits the previous owner. Class and TTL may come in either order, so
/// they are taken off the front until the type appears. A leading BOM is dropped; `default_origin`
/// applies when the file has no directive.
///
/// Fails when there is no SOA or more than one, when the record count exceeds the limit, or when a
/// line is malformed. Exactly one SOA: with two, the zone's serial is undefined and transfers and
/// updates disagree.
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

/// RFC 8976 allows nothing shorter; a shorter value proves nothing about zone integrity.
const ZONEMD_MIN_DIGEST: usize = 12;

/// Known types are parsed into structure; unknown types are taken in generic form as uninterpreted
/// bytes. Everything goes through validate at the end: a value that parses but violates the spec
/// would otherwise surface only when encoding a response.
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

/// Works on bytes, so multibyte characters cannot push an index off a character boundary; to_digit
/// rejects them. None for odd length or non-hex characters.
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

/// @ is the origin, a trailing dot means absolute, and anything else gets the origin appended.
/// Breaking this rule would make one zone file produce different names depending on the origin.
fn parse_name(tok: &str, origin: &Name) -> Result<Name, String> {
    if tok == "@" {
        return Ok(origin.clone());
    }
    if tok.ends_with('.') && !tok.ends_with(r"\.") {
        return Name::from_str(tok).map_err(|_| format!("Invalid name: {tok}"));
    }
    // The origin is appended as labels; joining presentation strings would mix in bytes that need
    // escaping and move label boundaries when read back.
    let relative = Name::from_str(tok).map_err(|_| format!("Invalid name: {tok}"))?;
    let mut labels: Vec<Vec<u8>> = relative.labels().map(<[u8]>::to_vec).collect();
    labels.extend(origin.labels().map(<[u8]>::to_vec));
    Name::from_labels(labels).map_err(|_| format!("Invalid name: {tok}"))
}

/// Accepts plain numbers and suffixed forms such as 1h30m. Sums saturate and are clamped to 32 bits
/// at the end, so large values stop at the limit instead of overflowing. Errors on no digits or an
/// unknown suffix.
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

/// Joins physical lines continued with parentheses, as long records like SOA use. Counts
/// parenthesis depth outside quotes. If the text ends with a parenthesis still open, the last piece
/// is passed on anyway; swallowing it would let a truncated file pass silently. `emit` also gets
/// whether the logical line started with whitespace, which decides whether the owner is inherited.
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

/// Semicolons inside quotes or after a backslash are not comments. Reuses the buffer, so lines do
/// not allocate.
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

/// Skips the character after a backslash.
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

/// Spaces inside quotes do not split, and backslash escapes are left for each type's parser. An
/// empty quoted pair is one token: TXT's empty string.
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

/// Known types by mnemonic, others as TYPEnnn.
fn rrsig_covered_type(tok: &str) -> Result<u16, String> {
    type_number(tok).ok_or_else(|| format!("Unknown type covered by RRSIG: {tok}"))
}

/// Unknown names only in TYPEnnn form. RecordType::name is the only number-to-name table, so this
/// walks it in reverse.
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

/// RFC 4034 type bitmap for NSEC and NSEC3: windows by the type's high byte, each written only up
/// to its last used byte. Untrimmed windows make validators read the bitmap differently and break
/// denial proofs.
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

/// Shared prefix of NSEC3 and NSEC3PARAM: hash algorithm, flags, iterations, salt. No salt is
/// written as -.
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

/// For NSEC3 hashed names; no padding.
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

/// The spec allows both YYYYMMDDHHmmSS and plain seconds. Returns seconds since 1970.
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
    // Days since 1970-01-01. Starting the year in March puts the leap day last, so the leap year
    // correction is one line.
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

/// For DNSKEY, RRSIG, and ech values. These often span several tokens, so whitespace is skipped.
/// None on characters outside the alphabet.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
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

/// The RFC 9460 registry. keyNNNNN is the caller's job.
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

/// mandatory lists key names too, so it uses the same rule.
fn svcb_key_of(name: &str) -> Result<u16, String> {
    if let Some(key) = svcb_key_number(name) {
        return Ok(key);
    }
    name.strip_prefix("key")
        .and_then(|digits| digits.parse::<u16>().ok())
        .ok_or_else(|| format!("Invalid SVCB parameter key: {name}"))
}

/// Comma-separated list per RFC 9460: a comma inside an item is escaped with a backslash, as is the
/// backslash itself. Unescaping first would make escaped commas look like separators.
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

/// RFC 9460 defines the presentation format per key. Missing a registered key would make a zone
/// unloadable, so all seven in use are handled. Unregistered keyNNNNN values are character-strings
/// decoded straight to wire. `value` is the token after =, if any.
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

/// A backslash followed by three decimal digits becomes that byte; above 255 or with too few digits
/// it is not an escape, and the next character is taken literally. Works on bytes, so multibyte
/// characters do not shift indexes.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// An editor's BOM must not swallow the first record.
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

    #[test]
    fn parse_ttl_suffixes() {
        assert_eq!(parse_ttl("3600").unwrap(), 3600);
        assert_eq!(parse_ttl("1h").unwrap(), 3600);
        assert_eq!(parse_ttl("1d").unwrap(), 86_400);
        assert_eq!(parse_ttl("1h30m").unwrap(), 5400);
        assert!(parse_ttl("xx").is_err());
    }

    #[test]
    fn tokenize_quoted_txt() {
        let t = tokenize(r#"@ IN TXT "hello world" "more""#);
        assert_eq!(t, vec!["@", "IN", "TXT", "hello world", "more"]);
    }

    #[test]
    fn hex_decode_no_panic_on_multibyte() {
        assert!(hex_decode("€a").is_none());
        assert!(hex_decode("€€").is_none());
        assert_eq!(hex_decode("ff00").unwrap(), vec![0xff, 0x00]);
        assert!(hex_decode("fff").is_none());
    }

    #[test]
    fn unescape_roundtrips_decimal_and_char_escapes() {
        assert_eq!(unescape_char_string(r"a\010b"), vec![b'a', 10, b'b']);
        assert_eq!(unescape_char_string(r#"\"\\"#), vec![b'"', b'\\']);
        assert_eq!(unescape_char_string(r"\255"), vec![0xff]);
        assert_eq!(unescape_char_string("plain"), b"plain".to_vec());
    }

    /// Unable to read ZONEMD, a zone published with it could not be loaded at all, and digest
    /// checks would be unusable.
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

    #[test]
    fn hex_rdata_multibyte_token_does_not_panic() {
        let origin = Name::from_str("example.com").unwrap();
        for line in ["TLSA 3 1 1 €a", "SSHFP 4 2 €a", "TYPE99 \\# 2 €a"] {
            let toks = tokenize(line);
            let _ = parse_rdata(line.split(' ').next().unwrap(), &toks[1..], &origin);
        }
    }

    /// Pins each type's token layout in one place.
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

        // Registered keys and their value formats from RFC 9460, each checked down to wire bytes.
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

        // A comma inside an item is escaped; unescaping first would mix it with separators.
        match pr(r"SVCB 1 . alpn=one\\,two").expect("막은 쉼표") {
            RData::Svcb { params, .. } => {
                assert_eq!(params[0].1.as_ref(), b"one,two");
            }
            other => panic!("SVCB 기대: {other:?}"),
        }

        // Values of unregistered keys are character-strings, not hex.
        match pr("SVCB 1 . key65000=hello").expect("미등록 키") {
            RData::Svcb { params, .. } => assert_eq!(params[0].1.as_ref(), b"hello"),
            other => panic!("SVCB 기대: {other:?}"),
        }

        assert!(pr("SVCB 1 . port=notanumber").is_err());
        assert!(pr("SVCB 1 . ipv4hint=2001:db8::1").is_err());

        // RFC 4034 DNSSEC presentation formats. Without them presigned zones cannot load, leaving
        // online signing as the only option. Wire bytes are checked against BIND.
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
                // The bitmap follows the name: window 0, length 6, A(1) AAAA(28) RRSIG(46)
                // NSEC(47).
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
        // Unknown types must go into the bitmap as TYPEnnn.
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

    /// Zone text can be uploaded through the control plane, so this parser sits on a trust
    /// boundary.
    #[test]
    fn parser_no_panic_on_garbage() {
        let mut seed: u32 = 0x2545_f491;
        let mut rng = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
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
