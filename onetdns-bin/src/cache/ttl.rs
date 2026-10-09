/*!
 * @brief 캐시가 지켜야 할 DNSSEC 수명 상한 계산.
 *
 * @details 서명 만료와 covered RRset 의 수신 TTL 을 함께 보아, 이미 만료될 서명을 검증된
 *          답이라며 담아 두지 않게 한다.
 */

use std::time::{SystemTime, UNIX_EPOCH};

use onetdns_proto::{Record, RecordType};

/**
 * @brief 검증된 응답을 담아 둘 수 있는 최대 기간.
 * @warning 서명 만료를 넘겨 담아 두면 안 된다. 넘기면 이미 만료된 서명을 검증된 답이라며
 *          내보낸다.
 */
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

/** @brief RRSIG 존재 여부와 covered RRset 없이도 알 수 있는 자체 수명 상한. */
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

/**
 * @brief 캐시가 지켜야 할 DNSSEC 수명 상한.
 * @details 서명이 없는 AD=0 응답은 별도 상한이 없어 u32::MAX다. AD가 켜졌거나 RRSIG가
 *          하나라도 있으면 수신 TTL·Original TTL·서명 만료를 모두 확인한다. CD 질의나
 *          검증 비활성 경로는 서명 응답이어도 AD=0일 수 있으므로 AD만 보고 건너뛰면 안 된다.
 * @return 유효한 RRSIG 수명 상한을 하나라도 얻으면 그 최솟값, 얻지 못하면 없음.
 */
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
