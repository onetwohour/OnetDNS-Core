/*!
 * @brief 계층 테스트가 함께 쓰는 가짜 리졸버와 레코드 생성기.
 */

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use onetdns_proto::{Message, Name, RData, Record, RecordType};

use crate::layers::{answer_message, now_secs};
use crate::native::Resolver;

/** @brief 정해진 응답을 내는 테스트용 리졸버. */
pub(super) struct Mock {
    /** @brief 이 리졸버를 가리키는 표식. 어느 쪽이 답했는지 본다. */
    tag: u8,
    /** @brief 돌려줄 응답 코드. */
    rcode: u16,
    /** @brief 불린 횟수. */
    pub(super) calls: AtomicU32,
}
impl Mock {
    /** @brief 표식과 응답 코드를 정해 만든다. */
    pub(super) fn new(tag: u8, rcode: u16) -> Arc<Self> {
        Arc::new(Mock {
            tag,
            rcode,
            calls: AtomicU32::new(0),
        })
    }
}
impl Resolver for Mock {
    /** @brief 미리 정해 둔 응답을 돌려준다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let q = req.questions.first().unwrap();
        let mut m = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
        m.header.rcode = self.rcode;

        m.answers.push(Record::new(
            q.name.clone(),
            self.tag as u32,
            RData::A(Ipv4Addr::new(self.tag, self.tag, self.tag, self.tag)),
        ));
        Some(m)
    }
}

/** @brief 빈 응답을 내는 테스트용 리졸버. */
pub(super) struct EmptyMock {
    /** @brief 권한 기록을 담을지. */
    with_soa: bool,
    /** @brief 불린 횟수. */
    pub(super) calls: AtomicU32,
}

impl EmptyMock {
    /** @brief 권한 기록을 담을지 정해 만든다. */
    pub(super) fn new(with_soa: bool) -> Arc<Self> {
        Arc::new(Self {
            with_soa,
            calls: AtomicU32::new(0),
        })
    }
}

impl Resolver for EmptyMock {
    /** @brief 미리 정해 둔 응답을 돌려준다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let q = req.questions.first()?;
        let mut response = answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
        if self.with_soa {
            response.authorities.push(Record::new(
                q.name.clone(),
                60,
                RData::soa(onetdns_proto::Soa {
                    mname: Name::from_str("ns1.test").unwrap(),
                    rname: Name::from_str("hostmaster.test").unwrap(),
                    serial: 1,
                    refresh: 3600,
                    retry: 600,
                    expire: 86400,
                    minimum: 60,
                }),
            ));
        }
        Some(response)
    }
}

/** @brief 테스트용 질의. */
pub(super) fn query(name: &str, qtype: RecordType) -> Message {
    Message::query(1, Name::from_str(name).unwrap(), qtype)
}

/** @brief 응답의 첫 주소. */
pub(super) fn first_a(m: &Message) -> Ipv4Addr {
    for r in &m.answers {
        if let RData::A(ip) = r.rdata {
            return ip;
        }
    }
    Ipv4Addr::UNSPECIFIED
}

/** @brief 테스트용 부재 증명 기록. */
pub(super) fn nsec_record(owner: &str, next: &str, types: &[u16]) -> Record {
    let mut rdata = Vec::new();
    for label in next.trim_end_matches('.').split('.') {
        rdata.push(label.len() as u8);
        rdata.extend_from_slice(label.as_bytes());
    }
    rdata.push(0);
    let max = types.iter().copied().max().unwrap_or(0);
    let nbytes = (max / 8 + 1) as usize;
    let mut bm = vec![0u8; nbytes];
    for &t in types {
        bm[(t / 8) as usize] |= 0x80 >> (t % 8);
    }
    rdata.push(0);
    rdata.push(nbytes as u8);
    rdata.extend_from_slice(&bm);
    Record::new(
        Name::from_str(owner).unwrap(),
        3600,
        RData::Unknown(47, rdata),
    )
}

/** @brief 테스트용 권한 기록. */
pub(super) fn soa_record(zone: &str) -> Record {
    Record::new(
        Name::from_str(zone).unwrap(),
        3600,
        RData::soa(onetdns_proto::Soa {
            mname: Name::from_str(&format!("ns.{zone}")).unwrap(),
            rname: Name::from_str(&format!("admin.{zone}")).unwrap(),
            serial: 1,
            refresh: 7200,
            retry: 3600,
            expire: 1_209_600,
            minimum: 3600,
        }),
    )
}

/** @brief 남은 기간을 지정한 테스트용 서명. */
pub(super) fn rrsig_record_with_lifetime(record: &Record, lifetime: u32) -> Record {
    let now = now_secs() as u32;
    let signature = onetdns_dnssec::Rrsig {
        type_covered: record.rtype.0,
        algorithm: 13,
        labels: record.name.num_labels() as u8,
        original_ttl: record.ttl,
        expiration: now.wrapping_add(lifetime),
        inception: now.wrapping_sub(60),
        key_tag: 1,
        signer: record.name.clone(),
        signature: vec![0; 64],
    };
    Record::new(
        record.name.clone(),
        record.ttl,
        RData::Unknown(RecordType::RRSIG.0, signature.rdata_bytes()),
    )
}

/** @brief 테스트용 서명. */
pub(super) fn rrsig_record(record: &Record) -> Record {
    rrsig_record_with_lifetime(record, 3600)
}

/** @brief 기록마다 서명을 붙인다. */
pub(super) fn with_rrsigs(mut records: Vec<Record>) -> Vec<Record> {
    let signatures = records.iter().map(rrsig_record).collect::<Vec<_>>();
    records.extend(signatures);
    records
}
