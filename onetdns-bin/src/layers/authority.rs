/*!
 * @brief 이 서버가 권한을 가진 영역을 재귀보다 먼저 답하는 계층과 그 DNSSEC 증명 조립.
 */

use std::sync::Arc;

use onetdns_proto::{Edns, Message, Name, Record, RecordType, ResponseCode};

use super::outcome_to_option;
use crate::native::{ResolveFailure, ResolveOutcome, Resolver};

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
    /*
     * 서명을 붙인 뒤에는 RRSIG가 별칭과 같은 owner의 다른 타입처럼 보여 terminal 추적을
     * 방해한다. 원래 answer만 있을 때 최종 이름과 요청 RRset 존재 여부를 확정한다.
     */
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

#[cfg(test)]
/** @brief 권한 영역 응답과 서명 증명이 검증 가능한 형태로 나가는지. */
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use onetdns_proto::{Edns, Message, Name, RData, Record, RecordType, ResponseCode};

    use crate::native::Resolver;

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
}
