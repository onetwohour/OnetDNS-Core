/*!
 * @brief RFC 8198. 캐시한 NSEC, NSEC3 증명으로 부정 응답을 합성하는 계층.
 */

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use onetdns_core::{LruMap, MutexExt};
use onetdns_proto::{Edns, Message, Name, RData, Record, RecordType, ResponseCode};

use super::{
    answer_message, is_zone_ancestor, now_secs, nsec3_has_optout, outcome_to_option,
    retarget_message, with_dnssec_records,
};
use crate::native::{ResolveFailure, ResolveOutcome, Resolver};

/** @brief 기록 하나를 가리키는 키. */
type RecKey = (Vec<u8>, u16, Vec<u8>);

/** @brief 기록에서 키를 만든다. */
fn rec_key(record: &Record) -> RecKey {
    let mut writer = onetdns_proto::Writer::new();
    record.rdata.encode(&mut writer);
    (record.name.canonical_key(), record.rtype.0, writer.buf)
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

#[cfg(test)]
/** @brief 캐시한 증명으로 합성한 부정 응답과 그 증명 저장소. */
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use onetdns_core::MutexExt;
    use onetdns_proto::{DnsClass, Edns, Message, Name, RData, Record, RecordType, ResponseCode};

    use crate::layers::answer_message;
    use crate::native::Resolver;

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
}
