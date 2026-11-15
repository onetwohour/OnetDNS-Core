//! DNS wire format codec, the bottom of this workspace's dependencies: it has no runtime
//! dependencies, and every other crate builds on these types. Parsing is consistently fail-closed
//! and turns ambiguous input into an error. Untrusted network bytes reach this crate first, and
//! what passes here is trusted as is by the layers above.
//!
//! No path here panics because of input bytes; all indexing goes through get or checked_*.

pub mod message;
pub mod name;
pub mod rdata;
pub mod wire;

pub use message::{
    ede_code, Edns, Header, Message, Question, ResponseCode, EDE_OPTION, EDNS_CLIENT_SUBNET,
    EDNS_PADDING, EDNS_TCP_KEEPALIVE,
};
pub use name::Name;
pub use rdata::{normalize_ttls, DnsClass, Naptr, RData, Record, RecordType, Soa, MAX_TTL};
pub use wire::{Reader, Writer};

/// Callers usually map all of these to FORMERR; they stay distinct so logs and tests show which
/// layer refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// Read past the remaining bytes; the normal end of a truncated message.
    Eof,

    /// Name syntax: label length, total length, compression pointer rules.
    Name(String),

    /// Message level: section counts, OPT placement, trailing bytes.
    Message(String),
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtoError::Eof => write!(f, "Read past the end of the message"),
            ProtoError::Name(s) => write!(f, "Name parse error: {s}"),
            ProtoError::Message(s) => write!(f, "DNS message error: {s}"),
        }
    }
}

impl std::error::Error for ProtoError {}

#[cfg(test)]
/// Cross-checks against hickory: our encoder and parser agreeing with each other proves nothing if
/// the spec was misread.
mod xval {

    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn our_query_parsed_by_hickory() {
        let msg = Message::query(
            0x1234,
            Name::from_str("www.example.com").unwrap(),
            RecordType::A,
        );
        let bytes = msg.try_encode().unwrap();

        let h = hickory_proto::op::Message::from_vec(&bytes)
            .expect("Reference DNS implementation must parse the message");
        assert_eq!(h.metadata.id, 0x1234);
        assert_eq!(h.queries.len(), 1);
        assert_eq!(h.queries[0].name().to_ascii(), "www.example.com.");
        assert_eq!(h.queries[0].query_type(), hickory_proto::rr::RecordType::A);
    }

    #[test]
    fn hickory_response_parsed_by_us() {
        use hickory_proto::op::{Message as HMsg, MessageType};
        use hickory_proto::rr::{
            rdata, Name as HName, RData as HRData, Record as HRec, RecordType as HRt,
        };
        use std::str::FromStr;

        let mut m = HMsg::query();
        m.metadata.id = 0xABCD;
        m.metadata.message_type = MessageType::Response;
        m.add_query(hickory_proto::op::Query::query(
            HName::from_str("a.example.com.").unwrap(),
            HRt::A,
        ));
        m.answers.push(HRec::from_rdata(
            HName::from_str("a.example.com.").unwrap(),
            300,
            HRData::CNAME(rdata::CNAME(HName::from_str("b.example.com.").unwrap())),
        ));
        m.answers.push(HRec::from_rdata(
            HName::from_str("b.example.com.").unwrap(),
            300,
            HRData::A(rdata::A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        let bytes = m.to_vec().unwrap();

        let ours = Message::parse(&bytes).expect("This DNS implementation must parse the message");
        assert_eq!(ours.header.id, 0xABCD);
        assert!(ours.header.response);
        assert_eq!(ours.questions.len(), 1);
        assert_eq!(ours.questions[0].name.to_ascii_lower(), "a.example.com");
        assert_eq!(ours.answers.len(), 2);

        match &ours.answers[0].rdata {
            RData::Cname(n) => assert_eq!(n.to_ascii_lower(), "b.example.com"),
            other => panic!("Expected a CNAME record, got {other:?}"),
        }

        match &ours.answers[1].rdata {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(1, 2, 3, 4)),
            other => panic!("Expected an A record, got {other:?}"),
        }
    }

    #[test]
    fn our_roundtrip_mixed() {
        let mut msg = Message {
            header: Header {
                id: 7,
                response: true,
                recursion_available: true,
                rcode: ResponseCode::NoError.0,
                ..Default::default()
            },
            questions: vec![Question {
                name: Name::from_str("mail.test.org").unwrap(),
                qtype: RecordType::MX,
                qclass: DnsClass::IN,
            }],
            ..Default::default()
        };
        msg.answers.push(Record::new(
            Name::from_str("mail.test.org").unwrap(),
            3600,
            RData::Mx {
                preference: 10,
                exchange: Name::from_str("mx1.test.org").unwrap(),
            },
        ));
        msg.answers.push(Record::new(
            Name::from_str("test.org").unwrap(),
            3600,
            RData::Txt(vec![b"hello world".to_vec()]),
        ));
        let bytes = msg.try_encode().unwrap();
        let back = Message::parse(&bytes).unwrap();
        assert_eq!(back.answers.len(), 2);
        match &back.answers[0].rdata {
            RData::Mx {
                preference,
                exchange,
            } => {
                assert_eq!(*preference, 10);
                assert_eq!(exchange.to_ascii_lower(), "mx1.test.org");
            }
            _ => panic!("Expected an MX record"),
        }

        let h = hickory_proto::op::Message::from_vec(&bytes).unwrap();
        assert_eq!(h.answers.len(), 2);
    }

    #[test]
    fn caa_roundtrip() {
        let mut msg = Message {
            header: Header {
                id: 9,
                response: true,
                rcode: ResponseCode::NoError.0,
                ..Default::default()
            },
            questions: vec![Question {
                name: Name::from_str("example.com").unwrap(),
                qtype: RecordType::CAA,
                qclass: DnsClass::IN,
            }],
            ..Default::default()
        };
        msg.answers.push(Record::new(
            Name::from_str("example.com").unwrap(),
            3600,
            RData::Caa {
                flags: 0,
                tag: Box::from(*b"issue"),
                value: Box::from(*b"letsencrypt.org"),
            },
        ));
        let bytes = msg.try_encode().unwrap();
        let back = Message::parse(&bytes).unwrap();
        match &back.answers[0].rdata {
            RData::Caa { flags, tag, value } => {
                assert_eq!(*flags, 0);
                assert_eq!(&**tag, b"issue");
                assert_eq!(&**value, b"letsencrypt.org");
            }
            other => panic!("Expected a CAA record, got {other:?}"),
        }

        let h = hickory_proto::op::Message::from_vec(&bytes).unwrap();
        assert_eq!(h.answers.len(), 1);
        assert_eq!(
            h.answers[0].record_type(),
            hickory_proto::rr::RecordType::CAA
        );
    }

    #[test]
    fn ede_roundtrip() {
        let mut msg = Message::query(1, Name::from_str("blocked.test").unwrap(), RecordType::A);
        let mut edns = Edns::default();
        edns.push_ede(ede_code::BLOCKED, "blocked by filter");
        msg.additionals.push(edns.try_to_record().unwrap());
        let bytes = msg.try_encode().unwrap();
        let back = Message::parse(&bytes).unwrap();
        let opt = back.opt().expect("Has OPT");
        let (code, text) = Edns::from_record(opt).unwrap().ede().expect("EDE option");
        assert_eq!(code, 15);
        assert_eq!(text, "blocked by filter");

        let _ = hickory_proto::op::Message::from_vec(&bytes).unwrap();
    }

    #[test]
    fn edns_opt_roundtrip() {
        let mut msg = Message::query(1, Name::from_str("x.com").unwrap(), RecordType::A);
        let edns = Edns {
            udp_payload: 1232,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: true,
            options: vec![(10, vec![1, 2, 3, 4])],
        };
        msg.additionals.push(edns.try_to_record().unwrap());
        let bytes = msg.try_encode().unwrap();
        let back = Message::parse(&bytes).unwrap();
        let opt = back.opt().expect("Has OPT");
        let e = Edns::from_record(opt).unwrap();
        assert_eq!(e.udp_payload, 1232);
        assert!(e.dnssec_ok);
        assert_eq!(e.options[0], (10, vec![1, 2, 3, 4]));
    }
}
