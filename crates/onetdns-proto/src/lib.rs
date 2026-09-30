/*!
 * @brief DNS 와이어 포맷 코덱. 이 워크스페이스의 의존성 바닥이다.
 *
 * @details 외부 크레이트를 전혀 쓰지 않으며, 상위 크레이트는 모두 이 타입들 위에 쌓인다.
 *          파싱은 일관되게 fail-closed다. 애매한 입력은 받아 주지 않고 오류로 돌린다.
 *          신뢰할 수 없는 네트워크 바이트가 최초로 닿는 지점이므로, 여기서 통과시킨 것은
 *          상위 계층이 그대로 믿는다.
 * @invariant 이 크레이트의 어떤 경로도 입력 바이트 때문에 패닉하지 않는다. 인덱싱은
 *            전부 get/checked_*를 거친다.
 */

/** @brief 메시지 전체의 읽기와 적기. */
pub mod message;
/** @brief 도메인 이름. */
pub mod name;
/** @brief 기록 종류별 내용. */
pub mod rdata;
/** @brief 바이트를 읽고 쓰는 기본 도구. */
pub mod wire;

pub use message::{
    ede_code, Edns, Header, Message, Question, ResponseCode, EDE_OPTION, EDNS_CLIENT_SUBNET,
    EDNS_PADDING, EDNS_TCP_KEEPALIVE,
};
pub use name::Name;
pub use rdata::{normalize_ttls, DnsClass, Naptr, RData, Record, RecordType, Soa, MAX_TTL};
pub use wire::{Reader, Writer};

/**
 * @brief 와이어 코덱이 낼 수 있는 오류.
 *
 * @details 호출자는 이 셋을 구분하지 않고 대개 FORMERR로 바꾼다. 구분을 남겨 두는 이유는
 *          로그와 테스트에서 어느 층에서 거부됐는지 보기 위해서다.
 */
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /** @brief 남은 바이트보다 많이 읽으려 했다. 잘린 메시지의 정상 결말이다. */
    Eof,

    /** @brief 이름 문법 위반: 라벨 길이, 전체 길이, 압축 포인터 규칙 등. */
    Name(String),

    /** @brief 메시지 수준 위반: 섹션 개수, OPT 배치, 잔여 바이트 등. */
    Message(String),
}

impl std::fmt::Display for ProtoError {
    /** @brief 사람이 읽을 문구. */
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
/**
 * @brief 다른 구현과 서로 읽히는지 대조한다.
 * @details 자체 구현끼리만 맞으면 규격을 잘못 읽었어도 알 수 없다. 널리 쓰이는 구현과
 *          주고받아 본다.
 */
mod xval {

    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    /** @brief 이 서버가 만든 질의를 남이 읽을 수 있는지. */
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
    /** @brief 남이 만든 응답을 이 서버가 읽을 수 있는지. */
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
    /** @brief 여러 기록이 섞인 메시지의 왕복. */
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
    /** @brief 인증 기관 제한 기록의 왕복. */
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
    /** @brief 확장 오류 사유의 왕복. */
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
    /** @brief 확장 옵션의 왕복. */
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
