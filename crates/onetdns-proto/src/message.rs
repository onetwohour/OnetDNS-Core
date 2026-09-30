/*!
 * @brief DNS 메시지. 헤더, 섹션, EDNS(0) OPT 처리.
 *
 * @details 파싱은 의도적으로 엄격하다. 예약 비트, 중복 OPT, 잔여 바이트, 불가능한 섹션
 *          개수를 전부 거부한다. 관대하게 받아들이면 같은 바이트열을 이 서버와 상위 리졸버가
 *          다르게 읽어 캐시 오염과 필터 우회의 경로가 된다.
 */

use crate::name::Name;
use crate::rdata::{DnsClass, Record, RecordType};
use crate::wire::{Reader, Writer, MAX_DNS_WIRE_LEN};
use crate::ProtoError;

/**
 * @brief DNS 응답 코드. 확장 rcode를 담기 위해 12비트를 쓴다.
 *
 * @details 열거형이 아니라 newtype인 이유는 미지의 코드도 그대로 담아 보내야 하기 때문이다.
 *          하위 4비트는 헤더에, 상위 8비트는 OPT의 TTL 필드에 나뉘어 들어간다.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseCode(pub u16);

#[allow(non_upper_case_globals)]
impl ResponseCode {
    /** @brief 성공. 레코드가 없는 NODATA도 이 코드다. */
    pub const NoError: ResponseCode = ResponseCode(0);
    /** @brief 질의 형식이 잘못됨. 파서가 거부한 입력에 돌려준다. */
    pub const FormErr: ResponseCode = ResponseCode(1);
    /** @brief 서버 내부 실패. DNSSEC bogus 판정도 여기로 합쳐진다. */
    pub const ServFail: ResponseCode = ResponseCode(2);
    /** @brief 이름이 존재하지 않음. */
    pub const NXDomain: ResponseCode = ResponseCode(3);
    /** @brief 지원하지 않는 요청. 미구현 opcode와 XFR 거부에 쓴다. */
    pub const NotImp: ResponseCode = ResponseCode(4);
    /** @brief 정책상 거부. ACL 차단이 이 코드로 나간다. */
    pub const Refused: ResponseCode = ResponseCode(5);
    /** @brief UPDATE 선결 조건 위반: 없어야 할 이름이 있다. */
    pub const YXDomain: ResponseCode = ResponseCode(6);
    /** @brief 지원하지 않는 EDNS 버전. 확장 rcode라 OPT가 있어야 전달된다. */
    pub const BadVers: ResponseCode = ResponseCode(16);
    /** @brief DNS 쿠키가 틀림. 클라이언트가 올바른 쿠키로 재시도하게 만든다. */
    pub const BadCookie: ResponseCode = ResponseCode(23);
}

/**
 * @brief 12바이트 DNS 헤더를 풀어 놓은 형태.
 *
 * @details rcode는 12비트다. OPT에서 합친 확장 rcode가 여기 들어온다. 인코딩할 때
 *          상위 비트가 있는데 OPT가 없으면 코덱이 OPT를 하나 만들어 붙인다. 그러지 않으면
 *          상위 8비트가 조용히 사라진다.
 */
#[derive(Debug, Clone, Default)]
pub struct Header {
    /** @brief 질의 번호. 요청과 응답을 짝짓는다. */
    pub id: u16,
    /** @brief 응답인지. */
    pub response: bool,
    /** @brief 질의 종류를 넘어선 동작 코드. */
    pub opcode: u8,
    /** @brief 이 답이 권한 있는 것인지. */
    pub authoritative: bool,
    /** @brief 크기가 모자라 잘렸는지. */
    pub truncated: bool,
    /** @brief 재귀해 달라는 요구. */
    pub recursion_desired: bool,
    /** @brief 재귀할 수 있다는 알림. */
    pub recursion_available: bool,
    /** @brief 검증됐다는 표시. */
    pub authentic_data: bool,
    /** @brief 검증하지 말라는 요구. */
    pub checking_disabled: bool,
    /** @brief 응답 코드. */
    pub rcode: u16,
}

impl Header {
    /**
     * @brief 플래그 필드를 와이어 16비트로 다시 합친다.
     * @note Z 비트는 항상 0으로 남는다. 헤더가 그 비트를 담지 않으므로 받은 질의가 설정해
     *       두었더라도 그대로 돌려주지 않는다. RFC 1035가 요구하는 것이 그것이다.
     */
    fn flags(&self) -> u16 {
        let mut f = 0u16;
        if self.response {
            f |= 0x8000;
        }
        f |= ((self.opcode as u16) & 0xF) << 11;
        if self.authoritative {
            f |= 0x0400;
        }
        if self.truncated {
            f |= 0x0200;
        }
        if self.recursion_desired {
            f |= 0x0100;
        }
        if self.recursion_available {
            f |= 0x0080;
        }
        if self.authentic_data {
            f |= 0x0020;
        }
        if self.checking_disabled {
            f |= 0x0010;
        }
        f |= self.rcode & 0xF;
        f
    }

    /** @brief 와이어 플래그 16비트를 풀어 헤더를 만든다. rcode는 하위 4비트만 담긴다. */
    fn from_flags(id: u16, f: u16) -> Self {
        Self {
            id,
            response: f & 0x8000 != 0,
            opcode: ((f >> 11) & 0xF) as u8,
            authoritative: f & 0x0400 != 0,
            truncated: f & 0x0200 != 0,
            recursion_desired: f & 0x0100 != 0,
            recursion_available: f & 0x0080 != 0,
            authentic_data: f & 0x0020 != 0,
            checking_disabled: f & 0x0010 != 0,
            rcode: f & 0xF,
        }
    }
}

/** @brief 질문 섹션 항목: 이름, 타입, 클래스. */
#[derive(Debug, Clone)]
pub struct Question {
    /** @brief 물어본 이름. */
    pub name: Name,
    /** @brief 질의 종류. */
    pub qtype: RecordType,
    /** @brief 질의 부류. */
    pub qclass: DnsClass,
}

/**
 * @brief 파싱된 DNS 메시지. 모든 전송이 이 형태로 수렴한다.
 *
 * @details OPT는 별도 필드가 아니라 additionals 안에 레코드로 남는다. 확장 rcode만
 *          파싱 시 header.rcode로 합쳐진다. 호출자가 두 곳을 보지 않게 하려는 것이다.
 */
#[derive(Debug, Clone, Default)]
pub struct Message {
    /** @brief 헤더. */
    pub header: Header,
    /** @brief 물어본 것들. */
    pub questions: Vec<Question>,
    /** @brief 답. */
    pub answers: Vec<Record>,
    /** @brief 권한 기록. */
    pub authorities: Vec<Record>,
    /** @brief 딸린 기록. */
    pub additionals: Vec<Record>,
}

impl Message {
    /**
     * @brief 와이어 바이트를 메시지로 해석한다. 신뢰 경계의 최전선이다.
     *
     * @details 관대함을 거부하는 지점들: OPT는 Additional에 최대 하나, OPT owner는 루트,
     *          끝에 남는 바이트가 있으면 거부. 섹션 개수는 남은 바이트로 나눈 하한(질문
     *          5바이트·레코드 11바이트)과 대조해, 헤더가 선언한 수만큼 미리 할당하지
     *          못하게 막는다.
     * @note 예약된 Z 비트는 거부하지 않고 버린다. 헤더에 담지 않으므로 그대로 돌려줄 수도 없다.
     *       거부하면 응답이 아니라 무응답이 되는데, RFC 8906은 그 질의에도
     *       NOERROR 로 답할 것을 요구한다.
     * @return 위 규칙 중 하나라도 어기면 오류. 부분 파싱 결과는 절대 돌려주지 않는다.
     */
    pub fn parse(buf: &[u8]) -> Result<Message, ProtoError> {
        if buf.len() > MAX_DNS_WIRE_LEN {
            return Err(ProtoError::Message(
                "DNS message exceeds the 65,535-byte wire limit".into(),
            ));
        }
        let mut r = Reader::new(buf);
        let id = r.u16()?;
        let flags = r.u16()?;
        let qd = r.u16()? as usize;
        let an = r.u16()? as usize;
        let ns = r.u16()? as usize;
        let ar = r.u16()? as usize;
        let mut header = Header::from_flags(id, flags);

        /** @brief 구간 하나에 담을 항목 수 상한. 없으면 개수만 크게 적은 짧은 패킷으로 메모리를 잡게 만든다. */
        const MAX_SECTION_ITEMS: usize = 4096;
        let remaining = r.remaining();
        if qd > MAX_SECTION_ITEMS
            || an > MAX_SECTION_ITEMS
            || ns > MAX_SECTION_ITEMS
            || ar > MAX_SECTION_ITEMS
            || qd.saturating_mul(5) > remaining
            || an.saturating_add(ns).saturating_add(ar).saturating_mul(11) > remaining
        {
            return Err(ProtoError::Message(
                "Impossible or excessive DNS section count".into(),
            ));
        }

        let mut questions = Vec::with_capacity(qd.min(64));
        for _ in 0..qd {
            let name = Name::parse(&mut r)?;
            let qtype = RecordType(r.u16()?);
            let qclass = DnsClass(r.u16()?);
            questions.push(Question {
                name,
                qtype,
                qclass,
            });
        }
        let read_n =
            |r: &mut Reader, n: usize, update_section: u8| -> Result<Vec<Record>, ProtoError> {
                let mut v = Vec::with_capacity(n.min(64));
                for _ in 0..n {
                    v.push(match update_section {
                        1 => Record::parse_update_empty(r)?,
                        2 => Record::parse_update_operation(r)?,
                        _ => Record::parse(r)?,
                    });
                }
                Ok(v)
            };
        let is_update = header.opcode == 5 && !header.response;
        let answers = read_n(&mut r, an, u8::from(is_update))?;
        let authorities = read_n(&mut r, ns, if is_update { 2 } else { 0 })?;
        if answers
            .iter()
            .chain(&authorities)
            .any(|record| record.rtype == RecordType::OPT)
        {
            return Err(ProtoError::Message(
                "OPT record is only allowed in the Additional section".into(),
            ));
        }
        let additionals = read_n(&mut r, ar, 0)?;
        if r.remaining() != 0 {
            return Err(ProtoError::Message(
                "Unparsed bytes after the DNS message".into(),
            ));
        }

        let mut opts = additionals
            .iter()
            .filter(|record| record.rtype == RecordType::OPT);
        if let Some(opt) = opts.next() {
            if opts.next().is_some() {
                return Err(ProtoError::Message(
                    "A DNS message can have only one OPT record".into(),
                ));
            }
            let extended_rcode = Edns::validate_record(opt)?;
            header.rcode |= u16::from(extended_rcode) << 4;
        }

        Ok(Message {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    /**
     * @brief UDP 로 받은 응답을 해석한다. 바이트가 모자라 끝난 응답은 잘린 응답으로 읽는다.
     *
     * @details UDP 53 을 가로채 대신 답하는 ISP 프록시 가운데는 512바이트를 넘는 응답을 TC 비트
     *          없이 512바이트에서 잘라 보내는 것이 있다. 그런 응답은 레코드 중간에서 끊겨 parse 가
     *          거부하고, 버린 채 기다려도 온전한 응답은 오지 않으므로 질의가 데드라인까지 묶인다.
     *          헤더가 응답이고 질문 구간까지 온전하면 TC 가 켜진 빈 응답으로 돌려주어, 호출자가
     *          원래의 TC 처리대로 TCP 로 다시 묻게 한다. 바이트가 모자란 것이 아닌 형식 위반은
     *          잘림으로 보지 않고 버린다.
     * @warning 잘린 응답에는 질문 뒤의 레코드를 하나도 담지 않는다. 잘린 나머지를 답으로 쓰면
     *          안 된다. 호출자는 이 결과에도 보통 응답과 같은 ID 와 질문 검사를 해야 한다.
     * @return 해석할 수 없으면 없다.
     */
    pub fn parse_udp_reply(buf: &[u8]) -> Option<Message> {
        match Message::parse(buf) {
            Ok(message) => Some(message),
            Err(ProtoError::Eof) => Message::cut_reply(buf),
            Err(_) => None,
        }
    }

    /** @brief 잘린 응답의 헤더와 질문만으로 TC 가 켜진 빈 응답을 만든다. */
    fn cut_reply(buf: &[u8]) -> Option<Message> {
        let mut r = Reader::new(buf);
        let id = r.u16().ok()?;
        let flags = r.u16().ok()?;
        let qd = r.u16().ok()? as usize;
        for _ in 0..3 {
            r.u16().ok()?;
        }
        let mut header = Header::from_flags(id, flags);
        if !header.response || qd == 0 || qd.saturating_mul(5) > r.remaining() {
            return None;
        }
        let mut questions = Vec::with_capacity(qd);
        for _ in 0..qd {
            let name = Name::parse(&mut r).ok()?;
            let qtype = RecordType(r.u16().ok()?);
            let qclass = DnsClass(r.u16().ok()?);
            questions.push(Question {
                name,
                qtype,
                qclass,
            });
        }
        header.truncated = true;
        Some(Message {
            header,
            questions,
            ..Message::default()
        })
    }

    /**
     * @brief 메시지를 새 버퍼에 인코딩한다.
     * @return 표현 불가능한 메시지는 오류다. 잘린 결과를 성공으로 돌려주지 않는다.
     */
    pub fn try_encode(&self) -> Result<Vec<u8>, ProtoError> {
        let mut w = Writer::new();
        self.encode_checked_into(&mut w)?;
        w.finish()
    }

    /**
     * @brief 재사용 중인 버퍼에 인코딩한다. 응답 경로의 할당을 없애는 경로다.
     * @param w 반드시 비어 있고 실패 표시가 없어야 한다. 남은 압축 오프셋이 있으면
     *          새 메시지가 이전 메시지 위치를 가리키는 포인터를 쓰게 되므로 거부한다.
     */
    pub fn try_encode_into(&self, w: &mut Writer) -> Result<(), ProtoError> {
        if !w.buf.is_empty() || !w.names.is_empty() || w.is_failed() {
            return Err(ProtoError::Message(
                "Encoding a DNS message in place needs an empty output buffer".into(),
            ));
        }
        self.encode_checked_into(w)
    }

    /**
     * @brief 인코딩 전 구조 검사와 실제 쓰기를 수행하는 공통 구현.
     *
     * @details 파서가 거부하는 것은 인코더도 만들지 않는다는 대칭을 지킨다. OPT 중복·위치,
     *          TYPE과 RDATA 종류 불일치, 섹션 개수 초과가 검사 대상이다. 불일치를 허용하면
     *          이 서버가 만든 응답을 이 서버의 파서가 되읽지 못하는 상태가 생긴다.
     * @note 확장 rcode가 있는데 OPT가 없으면 여기서 OPT를 합성한다. 그러지 않으면 상위
     *       8비트가 와이어에서 사라져 클라이언트가 잘못된 코드를 본다.
     */
    fn encode_checked_into(&self, w: &mut Writer) -> Result<(), ProtoError> {
        if self.header.opcode > 0x0f {
            return Err(ProtoError::Message(
                "DNS opcode does not fit in 4 bits".into(),
            ));
        }
        if self.header.rcode > 0x0fff {
            return Err(ProtoError::Message(
                "DNS rcode does not fit in 12 bits".into(),
            ));
        }
        let qd = u16::try_from(self.questions.len())
            .map_err(|_| ProtoError::Message("More than 65,535 DNS questions".into()))?;
        let an = u16::try_from(self.answers.len())
            .map_err(|_| ProtoError::Message("More than 65,535 DNS answer records".into()))?;
        let ns = u16::try_from(self.authorities.len())
            .map_err(|_| ProtoError::Message("More than 65,535 DNS authority records".into()))?;
        let opt_count = self
            .additionals
            .iter()
            .filter(|record| record.rtype == RecordType::OPT)
            .count();
        if opt_count > 1 {
            return Err(ProtoError::Message(
                "A DNS message can have only one OPT record".into(),
            ));
        }
        if self
            .answers
            .iter()
            .chain(&self.authorities)
            .any(|record| record.rtype == RecordType::OPT)
        {
            return Err(ProtoError::Message(
                "OPT record is only allowed in the Additional section".into(),
            ));
        }
        for record in self
            .answers
            .iter()
            .chain(&self.authorities)
            .chain(&self.additionals)
        {
            if record.rtype != record.rdata.record_type() {
                return Err(ProtoError::Message(format!(
                    "DNS record TYPE {} does not match RDATA TYPE {}",
                    record.rtype.0,
                    record.rdata.record_type().0
                )));
            }
            record.rdata.validate()?;
        }
        if let Some(opt) = self
            .additionals
            .iter()
            .find(|record| record.rtype == RecordType::OPT)
        {
            if !opt.name.is_root() {
                return Err(ProtoError::Message("OPT owner must be root".into()));
            }
            Edns::try_from_record(opt)?;
        }
        let needs_synthetic_opt = self.header.rcode > 0x0f && opt_count == 0;
        let ar_len = self
            .additionals
            .len()
            .checked_add(usize::from(needs_synthetic_opt))
            .ok_or_else(|| ProtoError::Message("Additional count overflowed".into()))?;
        let ar = u16::try_from(ar_len)
            .map_err(|_| ProtoError::Message("More than 65,535 DNS additional records".into()))?;

        w.push_u16(self.header.id);
        w.push_u16(self.header.flags());
        w.push_u16(qd);
        w.push_u16(an);
        w.push_u16(ns);
        w.push_u16(ar);
        Self::stop_on_writer_error(w)?;
        for q in &self.questions {
            q.name.encode(w);
            w.push_u16(q.qtype.0);
            w.push_u16(q.qclass.0);
            Self::stop_on_writer_error(w)?;
        }
        for record in &self.answers {
            record.encode(w);
            Self::stop_on_writer_error(w)?;
        }
        for record in &self.authorities {
            record.encode(w);
            Self::stop_on_writer_error(w)?;
        }
        for record in &self.additionals {
            if record.rtype == RecordType::OPT {
                let ttl = (record.ttl & 0x00ff_ffff)
                    | (u32::from(((self.header.rcode >> 4) & 0xff) as u8) << 24);
                record.encode_with_ttl(w, ttl);
            } else {
                record.encode(w);
            }
            Self::stop_on_writer_error(w)?;
        }
        if needs_synthetic_opt {
            let mut edns = Edns::default();
            edns.extended_rcode = ((self.header.rcode >> 4) & 0xff) as u8;
            edns.try_to_record()?.encode(w);
            Self::stop_on_writer_error(w)?;
        }
        Ok(())
    }

    /**
     * @brief 버퍼가 실패 상태면 즉시 오류로 빠져나온다.
     * @details 한 번 실패한 버퍼는 이후 쓰기를 전부 버리므로, 매 항목 뒤에 확인해야 잘린
     *          결과가 성공으로 흘러나가지 않는다.
     */
    fn stop_on_writer_error(w: &Writer) -> Result<(), ProtoError> {
        match w.error() {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    /** @brief 재귀 요청 비트가 선 IN 클래스 질의 하나를 만든다. */
    pub fn query(id: u16, name: Name, qtype: RecordType) -> Message {
        Message {
            header: Header {
                id,
                recursion_desired: true,
                ..Default::default()
            },
            questions: vec![Question {
                name,
                qtype,
                qclass: DnsClass::IN,
            }],
            ..Default::default()
        }
    }

    /** @brief OPT 레코드를 찾는다. 파서가 중복을 막으므로 최대 하나다. */
    pub fn opt(&self) -> Option<&Record> {
        self.additionals.iter().find(|r| r.rtype == RecordType::OPT)
    }

    /** @brief 클라이언트가 EDNS 패딩을 요청했는지. 암호화 전송에서 크기 노출을 줄이는 신호다. */
    pub fn requested_padding(&self) -> bool {
        self.opt()
            .and_then(Edns::from_record)
            .map(|e| e.has_option(EDNS_PADDING))
            .unwrap_or(false)
    }

    /**
     * @brief 와이어 크기를 block 배수로 맞추는 EDNS 패딩을 넣는다.
     *
     * @details 기존 패딩을 먼저 걷어내고 그 상태의 크기를 재야 정확한 패딩 길이가 나온다.
     *          +4는 패딩 옵션 자체의 헤더(코드 2 + 길이 2)이다.
     * @param block 0이거나 OPT가 없으면 아무것도 하지 않는다.
     */
    pub fn pad_to(&mut self, block: usize) -> Result<(), ProtoError> {
        if block == 0 {
            return Ok(());
        }
        let Some(idx) = self
            .additionals
            .iter()
            .position(|r| r.rtype == RecordType::OPT)
        else {
            return Ok(());
        };
        let mut edns = Edns::try_from_record(&self.additionals[idx])?;

        edns.options.retain(|(c, _)| *c != EDNS_PADDING);
        self.additionals[idx] = edns.try_to_record()?;
        let base = self.try_encode()?.len();

        let pad_len = (block - ((base + 4) % block)) % block;
        edns.options.push((EDNS_PADDING, vec![0u8; pad_len]));
        self.additionals[idx] = edns.try_to_record()?;
        Ok(())
    }

    /**
     * @brief edns-tcp-keepalive 옵션을 설정한다. OPT가 없으면 만들어 붙인다.
     * @param timeout_100ms 유휴 유지 시간, 100밀리초 단위(RFC 7828).
     */
    pub fn set_tcp_keepalive(&mut self, timeout_100ms: u16) -> Result<(), ProtoError> {
        match self
            .additionals
            .iter()
            .position(|r| r.rtype == RecordType::OPT)
        {
            Some(idx) => {
                let mut edns = Edns::try_from_record(&self.additionals[idx])?;
                edns.set_tcp_keepalive(timeout_100ms);
                self.additionals[idx] = edns.try_to_record()?;
            }
            None => {
                let mut edns = Edns::default();
                edns.set_tcp_keepalive(timeout_100ms);
                self.additionals.push(edns.try_to_record()?);
            }
        }
        Ok(())
    }

    /**
     * @brief edns-client-subnet 옵션을 설정한다. OPT가 없으면 만들어 붙인다.
     * @param option FAMILY, SOURCE PREFIX-LENGTH, SCOPE PREFIX-LENGTH, ADDRESS 를 담은 원시 바이트.
     */
    pub fn set_client_subnet(&mut self, option: Vec<u8>) -> Result<(), ProtoError> {
        match self
            .additionals
            .iter()
            .position(|r| r.rtype == RecordType::OPT)
        {
            Some(idx) => {
                let mut edns = Edns::try_from_record(&self.additionals[idx])?;
                edns.set_client_subnet(option);
                self.additionals[idx] = edns.try_to_record()?;
            }
            None => {
                let mut edns = Edns::default();
                edns.set_client_subnet(option);
                self.additionals.push(edns.try_to_record()?);
            }
        }
        Ok(())
    }
}

/** @brief Extended DNS Error 옵션 코드(RFC 8914). 실패 사유를 기계가 읽게 해 준다. */
pub const EDE_OPTION: u16 = 15;

/** @brief edns-tcp-keepalive 옵션 코드(RFC 7828). */
pub const EDNS_TCP_KEEPALIVE: u16 = 11;

/** @brief edns-client-subnet 옵션 코드(RFC 7871). */
pub const EDNS_CLIENT_SUBNET: u16 = 8;

/** @brief EDNS 패딩 옵션 코드(RFC 7830). 암호화 전송의 크기 노출을 줄인다. */
pub const EDNS_PADDING: u16 = 12;

/**
 * @brief 이 서버가 내보내는 Extended DNS Error 정보 코드.
 *
 * @details 전부가 아니라 실제로 쓰는 것만 정의한다. rcode 하나로는 "왜"가 전달되지 않아
 *          클라이언트가 차단과 장애를 구분하지 못하기 때문에 붙인다.
 */
pub mod ede_code {

    /** @brief 분류되지 않은 사유. 텍스트에 설명이 담긴다. */
    pub const OTHER: u16 = 0;

    /** @brief 만료된 캐시 응답을 냈다(RFC 8767 serve-stale). */
    pub const STALE_ANSWER: u16 = 3;

    /** @brief DNSSEC 검증이 bogus로 끝났다. 서명이 데이터와 맞지 않는다. */
    pub const DNSSEC_BOGUS: u16 = 6;

    /** @brief RRSIG 유효 기간이 지났다. bogus의 흔한 원인이라 따로 구분한다. */
    pub const SIGNATURE_EXPIRED: u16 = 7;

    /** @brief 운영자 정책으로 차단됨. 이 서버의 블록리스트 판정. */
    pub const BLOCKED: u16 = 15;

    /** @brief 외부 요구로 차단됨. */
    pub const CENSORED: u16 = 16;

    /** @brief 클라이언트가 스스로 요청한 필터링. */
    pub const FILTERED: u16 = 17;

    /** @brief 이 클라이언트에게 허용되지 않는 질의: ACL 거부. */
    pub const PROHIBITED: u16 = 18;

    /** @brief 권한 서버 어디에도 닿지 못했다. */
    pub const NO_REACHABLE_AUTHORITY: u16 = 22;

    /** @brief 업스트림으로 가는 길에서 네트워크 오류가 났다. */
    pub const NETWORK_ERROR: u16 = 23;
    /** @brief NSEC3 반복 횟수가 검증기가 받아들이는 상한을 넘음(RFC 9276). */
    pub const UNSUPPORTED_NSEC3_ITERATIONS: u16 = 27;
}

/**
 * @brief OPT 레코드를 풀어 놓은 EDNS(0) 상태.
 *
 * @details OPT는 필드를 엉뚱한 곳에 숨겨 둔다. 클래스가 UDP 페이로드 크기, TTL이
 *          확장 rcode·버전·DO 비트다. 이 타입이 그 변환을 한곳에 모은다.
 */
#[derive(Debug, Clone)]
pub struct Edns {
    /** @brief 받아들일 UDP 크기. */
    pub udp_payload: u16,
    /** @brief 응답 코드의 윗자리. */
    pub extended_rcode: u8,
    /** @brief 확장 버전. */
    pub version: u8,
    /** @brief 서명을 함께 달라는 요구. */
    pub dnssec_ok: bool,
    /** @brief 담긴 옵션들. */
    pub options: Vec<(u16, Vec<u8>)>,
}

impl Default for Edns {
    /**
     * @brief 기본 EDNS 상태.
     * @note 페이로드 1232는 IPv6 최소 MTU에서 헤더를 뺀 값으로, 경로 단편화를 피하는
     *       널리 쓰이는 안전값이다. 이보다 키우면 응답이 조각나 유실 위험이 커진다.
     */
    fn default() -> Self {
        Self {
            udp_payload: 1232,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            options: vec![],
        }
    }
}

impl Edns {
    /**
     * @brief OPT 레코드에서 TTL과 원시 옵션 바이트를 꺼낸다.
     * @return OPT가 아니거나 owner가 루트가 아니면 오류. RDATA는 미해석 형태여야 한다.
     */
    fn record_parts(rec: &Record) -> Result<(u32, &[u8]), ProtoError> {
        if rec.rtype != RecordType::OPT {
            return Err(ProtoError::Message("Not an OPT record".into()));
        }
        if !rec.name.is_root() {
            return Err(ProtoError::Message("OPT owner must be root".into()));
        }
        match &rec.rdata {
            crate::rdata::RData::Unknown(_, raw) => Ok((rec.ttl, raw)),
            _ => Err(ProtoError::Message("Invalid OPT RDATA".into())),
        }
    }

    /**
     * @brief 옵션 목록을 훑으며 각 (코드, 데이터)에 콜백을 부른다.
     *
     * @details 검사와 수집 두 용도를 한 구현으로 묶는다. 검사 전용 경로가 따로 있으면
     *          둘의 엄격함이 어긋나 검사에서 통과한 것이 수집에서 깨지는 일이 생긴다.
     * @return 옵션 헤더가 끊겼거나 길이가 남은 바이트를 넘으면 오류.
     */
    fn visit_options(raw: &[u8], mut visit: impl FnMut(u16, &[u8])) -> Result<(), ProtoError> {
        let mut i = 0usize;
        while i < raw.len() {
            if raw.len() - i < 4 {
                return Err(ProtoError::Message(
                    "EDNS option header is truncated".into(),
                ));
            }
            let code = u16::from_be_bytes([raw[i], raw[i + 1]]);
            let len = u16::from_be_bytes([raw[i + 2], raw[i + 3]]) as usize;
            i += 4;
            let end = i
                .checked_add(len)
                .ok_or_else(|| ProtoError::Message("EDNS option length overflowed".into()))?;
            if end > raw.len() {
                return Err(ProtoError::Message("EDNS option data is truncated".into()));
            }
            visit(code, &raw[i..end]);
            i = end;
        }
        Ok(())
    }

    /**
     * @brief OPT를 검사만 하고 확장 rcode를 추출한다. 옵션을 복사하지 않는다.
     * @return 확장 rcode 상위 8비트. 헤더 rcode와 합쳐 12비트가 된다.
     */
    fn validate_record(rec: &Record) -> Result<u8, ProtoError> {
        let (ttl, raw) = Self::record_parts(rec)?;
        Self::visit_options(raw, |_, _| {})?;
        Ok(((ttl >> 24) & 0xff) as u8)
    }

    /** @brief OPT 레코드를 완전히 풀어 옵션까지 복사한다. */
    pub fn try_from_record(rec: &Record) -> Result<Edns, ProtoError> {
        let (ttl, raw) = Self::record_parts(rec)?;
        let mut options = vec![];
        Self::visit_options(raw, |code, data| options.push((code, data.to_vec())))?;
        Ok(Edns {
            udp_payload: rec.class.0,
            extended_rcode: ((ttl >> 24) & 0xff) as u8,
            version: ((ttl >> 16) & 0xff) as u8,
            dnssec_ok: (ttl & 0x0000_8000) != 0,
            options,
        })
    }

    /** @brief 사유가 필요 없을 때 쓰는 try_from_record의 Option 버전. */
    pub fn from_record(rec: &Record) -> Option<Edns> {
        Self::try_from_record(rec).ok()
    }

    /**
     * @brief Extended DNS Error를 덧붙인다.
     * @param info_code ede_code의 값 중 하나.
     * @param extra_text 사람이 읽을 보충 설명. 와이어에서 길이 종결이라 종단 널을 넣지 않는다.
     */
    pub fn push_ede(&mut self, info_code: u16, extra_text: &str) {
        let mut data = info_code.to_be_bytes().to_vec();
        data.extend_from_slice(extra_text.as_bytes());
        self.options.push((EDE_OPTION, data));
    }

    /** @brief 해당 코드의 옵션이 있는지. */
    pub fn has_option(&self, code: u16) -> bool {
        self.options.iter().any(|(c, _)| *c == code)
    }

    /** @brief keepalive 옵션을 설정한다. 기존 값은 덮어쓰지 않고 지운 뒤 다시 넣는다. */
    pub fn set_tcp_keepalive(&mut self, timeout_100ms: u16) {
        self.options.retain(|(c, _)| *c != EDNS_TCP_KEEPALIVE);
        self.options
            .push((EDNS_TCP_KEEPALIVE, timeout_100ms.to_be_bytes().to_vec()));
    }

    /** @brief ECS 옵션을 설정한다. 기존 값은 지운 뒤 다시 넣는다. */
    pub fn set_client_subnet(&mut self, option: Vec<u8>) {
        self.options.retain(|(c, _)| *c != EDNS_CLIENT_SUBNET);
        self.options.push((EDNS_CLIENT_SUBNET, option));
    }

    /** @brief ECS 옵션의 원시 바이트. */
    pub fn client_subnet(&self) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|(c, _)| *c == EDNS_CLIENT_SUBNET)
            .map(|(_, data)| data.as_slice())
    }

    /**
     * @brief 첫 EDE 옵션의 코드와 설명 문자열.
     * @note 데이터가 2바이트 미만이면 코드 0으로 바꾼다. 잘린 옵션 하나 때문에 응답 전체를
     *       버리는 것보다 낫다. 이건 진단 정보일 뿐이다.
     */
    pub fn ede(&self) -> Option<(u16, String)> {
        self.options
            .iter()
            .find(|(c, _)| *c == EDE_OPTION)
            .map(|(_, d)| {
                let code = if d.len() >= 2 {
                    u16::from_be_bytes([d[0], d[1]])
                } else {
                    0
                };
                let text = String::from_utf8_lossy(d.get(2..).unwrap_or(&[])).into_owned();
                (code, text)
            })
    }

    /**
     * @brief 이 상태를 OPT 레코드로 되돌린다.
     * @return 옵션 하나 또는 전체가 16비트 길이를 넘으면 오류. 잘라 내지 않는다.
     */
    pub fn try_to_record(&self) -> Result<Record, ProtoError> {
        let mut raw = Vec::new();
        for (code, data) in &self.options {
            let len = u16::try_from(data.len()).map_err(|_| {
                ProtoError::Message(format!("EDNS option {code} exceeds 65,535 bytes"))
            })?;
            let next = raw
                .len()
                .checked_add(4)
                .and_then(|value| value.checked_add(data.len()))
                .ok_or_else(|| ProtoError::Message("EDNS option length overflowed".into()))?;
            if next > u16::MAX as usize {
                return Err(ProtoError::Message(
                    "EDNS options exceed 65,535 bytes in total".into(),
                ));
            }
            raw.extend_from_slice(&code.to_be_bytes());
            raw.extend_from_slice(&len.to_be_bytes());
            raw.extend_from_slice(data);
        }
        let ttl = (u32::from(self.extended_rcode) << 24)
            | ((self.version as u32) << 16)
            | if self.dnssec_ok { 0x0000_8000 } else { 0 };
        Ok(Record {
            name: Name::root(),
            rtype: RecordType::OPT,
            class: DnsClass(self.udp_payload),
            ttl,
            rdata: crate::rdata::RData::Unknown(RecordType::OPT.0, raw),
        })
    }
}

#[cfg(test)]
/** @brief 아무 바이트열에도 파서가 패닉하지 않는지. */
mod robustness_tests {
    use super::Message;

    #[test]
    /** @brief 쓰레기 바이트열에 패닉하지 않는지. */
    fn parse_no_panic_on_garbage() {
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut rng = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..5000 {
            let len = (rng() % 300) as usize;
            let bytes: Vec<u8> = (0..len).map(|_| (rng() & 0xff) as u8).collect();
            if let Ok(m) = Message::parse(&bytes) {
                let _ = m.try_encode();
            }
        }

        for b in [&b""[..], &[0u8][..], &[0u8; 11][..], &[0xff; 12][..]] {
            let _ = Message::parse(b);
        }
    }
}

#[cfg(test)]
/** @brief UDP 응답이 도중에 끊겼을 때만 잘린 응답으로 읽는지. */
mod udp_reply_tests {
    use super::*;
    use crate::rdata::RData;
    use std::net::Ipv4Addr;

    /** @brief A 레코드 여러 개를 담은 응답의 와이어. */
    fn reply_wire() -> Vec<u8> {
        let name = Name::from_str("cut.example").unwrap();
        let mut m = Message::query(7, name.clone(), RecordType::A);
        m.header.response = true;
        for i in 0..4 {
            m.answers.push(Record::new(
                name.clone(),
                60,
                RData::A(Ipv4Addr::new(192, 0, 2, i)),
            ));
        }
        m.try_encode().unwrap()
    }

    #[test]
    /** @brief 온전한 응답은 그대로 해석하는지. */
    fn whole_reply_is_parsed_as_is() {
        let m = Message::parse_udp_reply(&reply_wire()).unwrap();
        assert!(!m.header.truncated);
        assert_eq!(m.answers.len(), 4);
    }

    #[test]
    /** @brief 레코드 중간에서 끊긴 응답을 레코드 없는 TC 응답으로 읽는지. */
    fn reply_cut_mid_record_reads_as_truncated() {
        let wire = reply_wire();
        let m = Message::parse_udp_reply(&wire[..wire.len() - 3]).unwrap();
        assert!(m.header.truncated);
        assert_eq!(m.header.id, 7);
        assert_eq!(m.questions.len(), 1);
        assert!(m.answers.is_empty() && m.authorities.is_empty() && m.additionals.is_empty());
    }

    #[test]
    /** @brief 질문이 끊겼거나 질의이거나 형식 위반이면 잘림으로 보지 않는지. */
    fn only_a_cut_reply_with_a_whole_question_counts() {
        let wire = reply_wire();
        assert!(Message::parse_udp_reply(&wire[..14]).is_none());

        let mut query = wire.clone();
        query[2] &= 0x7f;
        assert!(Message::parse_udp_reply(&query[..wire.len() - 3]).is_none());

        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(Message::parse_udp_reply(&trailing).is_none());
    }
}

#[cfg(test)]
/** @brief 확장 옵션을 붙이고 읽는 동작. */
mod edns_option_tests {
    use super::*;

    /** @brief 확장 옵션이 붙은 테스트용 응답. */
    fn resp_with_opt() -> Message {
        let mut m = Message::query(1, Name::from_str("example.com").unwrap(), RecordType::A);
        m.header.response = true;
        m.additionals.push(Edns::default().try_to_record().unwrap());
        m
    }

    #[test]
    /** @brief 채우기가 크기를 정해진 단위로 맞추는지. */
    fn pad_to_rounds_wire_size_to_block() {
        let mut m = resp_with_opt();
        m.pad_to(128).unwrap();
        let size = m.try_encode().unwrap().len();
        assert_eq!(
            size % 128,
            0,
            "Padded wire size is a multiple of the block size"
        );

        let edns = Edns::from_record(m.opt().unwrap()).unwrap();
        assert!(edns.has_option(EDNS_PADDING));

        m.pad_to(468).unwrap();
        assert_eq!(m.try_encode().unwrap().len() % 468, 0);
    }

    #[test]
    /** @brief 확장 옵션이 없으면 채우지 않는지. */
    fn pad_to_noop_without_opt() {
        let mut m = Message::query(1, Name::from_str("x.test").unwrap(), RecordType::A);
        m.header.response = true;
        let before = m.try_encode().unwrap().len();
        m.pad_to(468).unwrap();
        assert_eq!(
            m.try_encode().unwrap().len(),
            before,
            "No padding without OPT"
        );
    }

    #[test]
    /** @brief 상대가 채우기를 요청했는지 알아보는지. */
    fn requested_padding_detects_query_option() {
        let mut q = Message::query(1, Name::from_str("x.test").unwrap(), RecordType::A);
        let mut e = Edns::default();
        e.options.push((EDNS_PADDING, vec![0u8; 4]));
        q.additionals.push(e.try_to_record().unwrap());
        assert!(q.requested_padding());

        let q2 = Message::query(1, Name::from_str("x.test").unwrap(), RecordType::A);
        assert!(!q2.requested_padding());
    }

    #[test]
    /** @brief 연결 유지 옵션이 붙는지. */
    fn tcp_keepalive_attaches_option() {
        let mut m = Message::query(1, Name::from_str("x.test").unwrap(), RecordType::A);
        m.set_tcp_keepalive(100).unwrap();
        let edns = Edns::from_record(m.opt().unwrap()).unwrap();
        let kv = edns
            .options
            .iter()
            .find(|(c, _)| *c == EDNS_TCP_KEEPALIVE)
            .unwrap();
        assert_eq!(kv.1, vec![0x00, 0x64]);
    }
}

#[cfg(test)]
/** @brief 어긋난 메시지를 받아들이지 않는지. */
mod hardening_tests {
    use super::*;

    #[test]
    /** @brief 개수만 크게 적은 짧은 패킷을 거부하는지. 받아들이면 그것만으로 메모리가 동난다. */
    fn rejects_count_allocation_bomb() {
        let mut wire = vec![0u8; 12];
        wire[4..12].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert!(Message::parse(&wire).is_err());
    }

    #[test]
    /**
     * @brief 예약된 Z 비트를 설정한 질의를 버리지 않고, 답에는 그대로 돌려주지 않는지.
     * @details 거부하면 응답이 아니라 무응답이 된다. RFC 8906은 그 질의에도
     *          NOERROR 로 답하고 그 비트는 응답에 없을 것을 요구한다.
     */
    fn reserved_header_z_bit_is_ignored_not_rejected() {
        let mut query = Message::query(
            0x1234,
            Name::from_str("example.com").unwrap(),
            RecordType::A,
        );
        query.header.recursion_desired = true;
        let mut wire = query.try_encode().expect("Could not build the query");
        let flags = u16::from_be_bytes([wire[2], wire[3]]) | 0x0040;
        wire[2..4].copy_from_slice(&flags.to_be_bytes());

        let parsed = Message::parse(&wire).expect("Dropped a query with the Z bit set");
        assert_eq!(parsed.questions.len(), 1);
        assert!(parsed.header.recursion_desired);

        let again = parsed.try_encode().expect("Could not rebuild");
        assert_eq!(
            u16::from_be_bytes([again[2], again[3]]) & 0x0040,
            0,
            "Echoed reserved bits"
        );
    }

    #[test]
    /** @brief 빈 내용을 허용하는 곳을 규격대로 구분하는지. */
    fn update_accepts_empty_rdata_only_for_rfc2136_classes() {
        let mut update = Message::default();
        update.header.opcode = 5;
        update.questions.push(Question {
            name: Name::from_str("example.com").unwrap(),
            qtype: RecordType::SOA,
            qclass: DnsClass::IN,
        });
        update.answers.push(Record {
            name: Name::from_str("host.example.com").unwrap(),
            rtype: RecordType::A,
            class: DnsClass(255),
            ttl: 0,
            rdata: crate::RData::Unknown(RecordType::A.0, Vec::new()),
        });
        let parsed = Message::parse(&update.try_encode().unwrap())
            .expect("Empty RDATA in an ANY prerequisite");
        assert!(matches!(
            &parsed.answers[0].rdata,
            crate::RData::Unknown(1, bytes) if bytes.is_empty()
        ));

        update.answers[0].class = DnsClass::IN;
        assert!(Message::parse(&update.try_encode().unwrap()).is_err());
    }

    #[test]
    /** @brief 확장 응답 코드의 왕복. */
    fn extended_rcode_roundtrip() {
        let mut m = Message::query(7, Name::from_str("cookie.test").unwrap(), RecordType::A);
        m.header.response = true;
        m.header.rcode = ResponseCode::BadCookie.0;
        m.additionals.push(Edns::default().try_to_record().unwrap());
        let wire = m.try_encode().unwrap();
        let parsed = Message::parse(&wire).unwrap();
        assert_eq!(parsed.header.rcode, ResponseCode::BadCookie.0);
    }

    #[test]
    /** @brief 확장 기록이 여럿이거나 어긋나면 거부하는지. 둘이면 어느 쪽을 믿느냐가 갈린다. */
    fn rejects_multiple_or_malformed_opt() {
        let mut multiple = vec![0u8; 12];
        multiple[10..12].copy_from_slice(&2u16.to_be_bytes());
        for _ in 0..2 {
            multiple.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        }
        assert!(Message::parse(&multiple).is_err());

        let mut malformed = vec![0u8; 12];
        malformed[10..12].copy_from_slice(&1u16.to_be_bytes());
        malformed.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 5, 0, 1, 0, 5, 1]);
        assert!(Message::parse(&malformed).is_err());

        let mut generated = Message::query(1, Name::from_str("x.test").unwrap(), RecordType::A);
        generated
            .additionals
            .push(Edns::default().try_to_record().unwrap());
        generated
            .additionals
            .push(Edns::default().try_to_record().unwrap());
        assert!(generated.try_encode().is_err());
    }

    #[test]
    /** @brief 적을 수 없는 상태를 모두 오류로 알리는지. */
    fn strict_encoder_reports_every_invalid_state() {
        let message = Message::query(0x1234, Name::from_str("x.test").unwrap(), RecordType::A);
        let mut edns = Edns::default();
        edns.options.push((65001, vec![0u8; u16::MAX as usize + 1]));
        assert!(edns.try_to_record().is_err());

        let mut invalid = message.clone();
        invalid.header.rcode = 0x1000;
        assert!(invalid.try_encode().is_err());
    }

    #[test]
    /** @brief 바로 적는 경로가 같은 바이트를 내고 버퍼를 다시 쓰는지. */
    fn direct_encoder_matches_wire_and_reuses_writer_capacity() {
        let message = Message::query(
            0x5151,
            Name::from_str("direct.example").unwrap(),
            RecordType::A,
        );
        let expected = message.try_encode().unwrap();
        let mut writer = Writer::new();
        writer.buf.reserve(512);

        message.try_encode_into(&mut writer).unwrap();
        assert_eq!(writer.buf, expected);
        let allocation = writer.buf.as_ptr();

        writer.clear();
        message.try_encode_into(&mut writer).unwrap();
        assert_eq!(writer.buf.as_ptr(), allocation);
        assert!(message.try_encode_into(&mut writer).is_err());
    }

    #[test]
    /** @brief 크기를 넘길 것 같으면 잡기 전에 멈추는지. */
    fn bounded_writer_stops_before_allocating_an_oversized_wire() {
        let mut message = Message::query(
            0x5252,
            Name::from_str("bounded.example").unwrap(),
            RecordType::A,
        );
        message.header.response = true;
        for octet in 0..=255 {
            message.answers.push(Record::new(
                Name::from_str(&format!("owner-{octet}.bounded.example")).unwrap(),
                60,
                crate::RData::Unknown(16, vec![octet; 128]),
            ));
        }

        let mut writer = Writer::with_limit(512);
        assert!(message.try_encode_into(&mut writer).is_err());
        assert!(writer.buf.len() <= 512);
        assert!(
            writer.buf.capacity() < 4096,
            "Remaining RRsets were not fully expanded"
        );
    }

    #[test]
    /** @brief 메시지 뒤에 남는 바이트를 거부하는지. */
    fn parser_rejects_trailing_bytes() {
        let mut wire = Message::query(1, Name::from_str("x.test").unwrap(), RecordType::A)
            .try_encode()
            .unwrap();
        wire.push(0);
        assert!(Message::parse(&wire).is_err());
    }

    #[test]
    /** @brief 크기 상한을 읽기 전에 거는지. */
    fn parser_enforces_the_dns_wire_size_limit_before_decoding() {
        let wire = vec![0u8; crate::wire::MAX_DNS_WIRE_LEN + 1];
        let error = Message::parse(&wire).unwrap_err();
        assert!(error.to_string().contains("65,535"), "{error}");
    }

    #[test]
    /** @brief 확장 기록이 정해진 구간 밖에 있으면 거부하는지. */
    fn opt_is_rejected_outside_the_additional_section() {
        let mut wire = vec![0u8; 12];
        wire[6..8].copy_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        assert!(Message::parse(&wire).is_err());

        let mut message = Message::default();
        message
            .answers
            .push(Edns::default().try_to_record().unwrap());
        assert!(message.try_encode().is_err());
    }

    #[test]
    /** @brief 범위를 벗어난 동작 코드를 거부하는지. */
    fn strict_encoder_rejects_out_of_range_opcode() {
        let mut message = Message::default();
        message.header.opcode = 16;
        assert!(message.try_encode().is_err());
    }

    #[test]
    /** @brief 기록 종류와 내용이 어긋나면 거부하는지. 적어 내보내면 상대가 다르게 읽는다. */
    fn strict_encoder_rejects_record_type_and_rdata_mismatch() {
        let mut message = Message::default();
        message.answers.push(Record {
            name: Name::root(),
            rtype: RecordType::A,
            class: DnsClass::IN,
            ttl: 0,
            rdata: crate::RData::Unknown(RecordType::TXT.0, vec![0]),
        });
        assert!(message.try_encode().is_err());
    }
}
