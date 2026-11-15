//! Fake resolvers and record builders shared by layer tests.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use onetdns_proto::{Message, Name, RData, Record, RecordType};

use crate::layers::{answer_message, now_secs};
use crate::native::Resolver;

/// Answers with a fixed rcode; `tag` shows which resolver answered.
pub(super) struct Mock {
    tag: u8,
    rcode: u16,
    pub(super) calls: AtomicU32,
}
impl Mock {
    pub(super) fn new(tag: u8, rcode: u16) -> Arc<Self> {
        Arc::new(Mock {
            tag,
            rcode,
            calls: AtomicU32::new(0),
        })
    }
}
impl Resolver for Mock {
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

/// Answers with no records, with or without a SOA in authority.
pub(super) struct EmptyMock {
    with_soa: bool,
    pub(super) calls: AtomicU32,
}

impl EmptyMock {
    pub(super) fn new(with_soa: bool) -> Arc<Self> {
        Arc::new(Self {
            with_soa,
            calls: AtomicU32::new(0),
        })
    }
}

impl Resolver for EmptyMock {
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

pub(super) fn query(name: &str, qtype: RecordType) -> Message {
    Message::query(1, Name::from_str(name).unwrap(), qtype)
}

pub(super) fn first_a(m: &Message) -> Ipv4Addr {
    for r in &m.answers {
        if let RData::A(ip) = r.rdata {
            return ip;
        }
    }
    Ipv4Addr::UNSPECIFIED
}

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

pub(super) fn rrsig_record(record: &Record) -> Record {
    rrsig_record_with_lifetime(record, 3600)
}

pub(super) fn with_rrsigs(mut records: Vec<Record>) -> Vec<Record> {
    let signatures = records.iter().map(rrsig_record).collect::<Vec<_>>();
    records.extend(signatures);
    records
}
