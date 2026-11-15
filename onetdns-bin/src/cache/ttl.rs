//! DNSSEC lifetime caps for the cache. Signature expiry and the received TTL of the covered RRset
//! together keep a signature that will expire from being cached as a validated answer.

use std::time::{SystemTime, UNIX_EPOCH};

use onetdns_proto::{Record, RecordType};

/// Caching past signature expiry would serve expired signatures as validated.
pub(crate) fn dnssec_ttl_cap(
    answers: &[Record],
    authorities: &[Record],
    additionals: &[Record],
) -> Option<u32> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as u32;
    answers
        .iter()
        .chain(authorities)
        .chain(additionals)
        .filter(|record| record.rtype == RecordType::RRSIG)
        .filter_map(|record| {
            let signature = onetdns_dnssec::Rrsig::from_record(record)?;
            if !onetdns_dnssec::rrsig_time_valid(&signature, now) {
                return None;
            }
            let covered_ttl = answers
                .iter()
                .chain(authorities)
                .chain(additionals)
                .filter(|covered| {
                    covered.class == record.class
                        && covered.rtype.0 == signature.type_covered
                        && covered.name.eq_ignore_case(&record.name)
                })
                .map(|covered| covered.ttl)
                .min()?;
            Some((record.ttl, covered_ttl, signature))
        })
        .map(|(rrsig_ttl, covered_ttl, signature)| {
            rrsig_ttl
                .min(covered_ttl)
                .min(signature.original_ttl)
                .min(signature.expiration.wrapping_sub(now))
        })
        .min()
}

/// A cap from the RRSIG records alone, without the covered RRset.
fn rrsig_record_ttl_cap(
    answers: &[Record],
    authorities: &[Record],
    additionals: &[Record],
) -> (bool, Option<u32>) {
    let mut has_rrsig = false;
    let mut cap: Option<u32> = None;
    let mut observed_now: Option<Option<u32>> = None;
    for record in answers.iter().chain(authorities).chain(additionals) {
        if record.rtype != RecordType::RRSIG {
            continue;
        }
        has_rrsig = true;
        let Some(now) = *observed_now.get_or_insert_with(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|duration| duration.as_secs() as u32)
        }) else {
            continue;
        };
        let Some(signature) = onetdns_dnssec::Rrsig::from_record(record) else {
            continue;
        };
        if !onetdns_dnssec::rrsig_time_valid(&signature, now) {
            continue;
        }
        let ttl = record
            .ttl
            .min(signature.original_ttl)
            .min(signature.expiration.wrapping_sub(now));
        cap = Some(cap.map_or(ttl, |current| current.min(ttl)));
    }
    (has_rrsig, cap)
}

/// Some(u32::MAX) for an unsigned AD=0 response. With AD set or any RRSIG present, the received
/// TTL, the Original TTL and the signature expiry are all checked: CD queries and paths without
/// validation can return signed answers with AD=0, so AD alone cannot decide.
///
/// None when no valid RRSIG cap is found.
pub(crate) fn cache_dnssec_ttl_cap(
    authentic: bool,
    answers: &[Record],
    authorities: &[Record],
    additionals: &[Record],
) -> Option<u32> {
    let (has_rrsig, signature_cap) = rrsig_record_ttl_cap(answers, authorities, additionals);
    if !has_rrsig {
        return (!authentic).then_some(u32::MAX);
    }
    let signature_cap = signature_cap?;
    if !authentic {
        return Some(
            signature_cap
                .min(dnssec_ttl_cap(answers, authorities, additionals).unwrap_or(u32::MAX)),
        )
        .filter(|ttl| *ttl > 0);
    }
    let authenticated_cap = dnssec_ttl_cap(answers, authorities, additionals)?;
    let cap = signature_cap.min(authenticated_cap);
    if cap == 0 {
        None
    } else {
        Some(cap)
    }
}
