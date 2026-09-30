/*!
 * @brief RFC 8020. NXDOMAIN인 이름 아래를 합성으로 답하는 계층.
 */

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use onetdns_core::{LruMap, MutexExt};
use onetdns_proto::{DnsClass, Edns, Message, Name, RData, Record, RecordType, ResponseCode};

use super::{
    answer_message, is_zone_ancestor, now_secs, nsec3_has_optout, outcome_to_option,
    retarget_message, with_dnssec_records,
};
use crate::native::{ResolveFailure, ResolveOutcome, Resolver};

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

#[cfg(test)]
/** @brief NXDOMAIN 아래 합성과 증명 요구, TTL 한도. */
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
}
