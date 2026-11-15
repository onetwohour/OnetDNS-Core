//! DNS messages: header, sections, and EDNS(0) OPT. Parsing is deliberately strict and refuses
//! duplicate OPT, trailing bytes, and impossible section counts. Leniency would let this server and
//! an upstream resolver read the same bytes differently, a path to cache poisoning and filter
//! bypass.

use crate::name::Name;
use crate::rdata::{DnsClass, Record, RecordType};
use crate::wire::{Reader, Writer, MAX_DNS_WIRE_LEN};
use crate::ProtoError;

/// Stops a short packet with huge counts from preallocating what the header declares. Module-level
/// so the normal and cut-reply parsers share it.
const MAX_SECTION_ITEMS: usize = 4096;

/// 12 bits, to hold extended rcodes: the low 4 go in the header, the high 8 in the OPT TTL field. A
/// newtype rather than an enum, so unknown codes pass through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseCode(pub u16);

#[allow(non_upper_case_globals)]
impl ResponseCode {
    /// Also NODATA, with no records.
    pub const NoError: ResponseCode = ResponseCode(0);
    /// Returned for input the parser refused.
    pub const FormErr: ResponseCode = ResponseCode(1);
    /// DNSSEC bogus also maps here.
    pub const ServFail: ResponseCode = ResponseCode(2);
    pub const NXDomain: ResponseCode = ResponseCode(3);
    /// Unimplemented opcodes and refused XFR.
    pub const NotImp: ResponseCode = ResponseCode(4);
    /// ACL blocks go out with this code.
    pub const Refused: ResponseCode = ResponseCode(5);
    /// UPDATE prerequisite failed: a name that should not exist does.
    pub const YXDomain: ResponseCode = ResponseCode(6);
    /// Extended rcode, so it needs an OPT to be sent.
    pub const BadVers: ResponseCode = ResponseCode(16);
    /// Makes the client retry with the right cookie.
    pub const BadCookie: ResponseCode = ResponseCode(23);
}

/// The 12-byte header, unpacked. `rcode` is 12 bits and includes the extended rcode merged from
/// OPT; when high bits are set and there is no OPT, the codec adds one, or the high 8 bits would
/// vanish.
#[derive(Debug, Clone, Default)]
pub struct Header {
    pub id: u16,
    pub response: bool,
    pub opcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub authentic_data: bool,
    pub checking_disabled: bool,
    pub rcode: u16,
}

impl Header {
    /// The Z bit is always 0: the header does not store it, so a query that set it does not get it
    /// back, as RFC 1035 requires.
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

    /// `rcode` gets only the low 4 bits.
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

#[derive(Debug, Clone)]
pub struct Question {
    pub name: Name,
    pub qtype: RecordType,
    pub qclass: DnsClass,
}

/// Every transport converges on this. OPT stays a record in `additionals`; only the extended rcode
/// is merged into `header.rcode` at parse time, so callers do not look in two places.
#[derive(Debug, Clone, Default)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
}

impl Message {
    /// The front line of the trust boundary. Refuses more than one OPT, an OPT outside Additional
    /// or with a non-root owner, and trailing bytes. Section counts are checked against the bytes
    /// left (5 per question, 11 per record), so a header cannot make the parser preallocate what it
    /// declares.
    ///
    /// The reserved Z bit is dropped, not refused: the header does not store it, so it cannot be
    /// echoed either. Refusing would mean no answer, and RFC 8906 requires a NOERROR answer to such
    /// a query.
    ///
    /// Any violation is an error; a partial parse is never returned.
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

    /// Parses a reply received over UDP, reading one that runs out of bytes as truncated. Some ISP
    /// proxies that intercept UDP 53 cut replies over 512 bytes at 512 without setting TC. Such a
    /// reply breaks mid-record, parse refuses it, and waiting brings no complete reply, so the
    /// query stalls until its deadline. If the header says response and the question section is
    /// whole, it becomes an empty reply with TC set, and the caller retries over TCP as for any TC.
    /// Format violations other than running out of bytes are not truncation and are dropped.
    ///
    /// A truncated result carries no records after the question; the cut remainder must not be used
    /// as an answer. Callers still check its ID and question like any reply.
    pub fn parse_udp_reply(buf: &[u8]) -> Option<Message> {
        match Message::parse(buf) {
            Ok(message) => Some(message),
            Err(ProtoError::Eof) => Message::cut_reply(buf),
            Err(_) => None,
        }
    }

    /// An empty TC reply built from the header and question of a cut reply.
    fn cut_reply(buf: &[u8]) -> Option<Message> {
        let mut r = Reader::new(buf);
        let id = r.u16().ok()?;
        let flags = r.u16().ok()?;
        let qd = r.u16().ok()? as usize;
        for _ in 0..3 {
            r.u16().ok()?;
        }
        let mut header = Header::from_flags(id, flags);
        if !header.response
            || qd == 0
            || qd > MAX_SECTION_ITEMS
            || qd.saturating_mul(5) > r.remaining()
        {
            return None;
        }
        let mut questions = Vec::with_capacity(qd.min(64));
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

    /// A message that cannot be represented is an error; a truncated result is never returned as
    /// success.
    pub fn try_encode(&self) -> Result<Vec<u8>, ProtoError> {
        let mut w = Writer::new();
        self.encode_checked_into(&mut w)?;
        w.finish()
    }

    /// Encodes into a reused buffer, so the response path does not allocate. `w` must be empty and
    /// not failed: leftover compression offsets would make the new message point into the old one.
    pub fn try_encode_into(&self, w: &mut Writer) -> Result<(), ProtoError> {
        if !w.buf.is_empty() || !w.names.is_empty() || w.is_failed() {
            return Err(ProtoError::Message(
                "Encoding a DNS message in place needs an empty output buffer".into(),
            ));
        }
        self.encode_checked_into(w)
    }

    /// Checks structure before writing: what the parser refuses, the encoder never produces.
    /// Checked are OPT duplicates and placement, TYPE and RDATA mismatches, and section counts;
    /// allowing a mismatch would produce responses this server's own parser cannot read back.
    ///
    /// An extended rcode without an OPT gets one synthesized here, or its high 8 bits would vanish
    /// on the wire and the client would see the wrong code.
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

    /// A failed writer drops every later write, so checking after each item keeps a truncated
    /// result from passing as success.
    fn stop_on_writer_error(w: &Writer) -> Result<(), ProtoError> {
        match w.error() {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    /// An IN-class query with RD set.
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

    /// At most one; the parser refuses duplicates.
    pub fn opt(&self) -> Option<&Record> {
        self.additionals.iter().find(|r| r.rtype == RecordType::OPT)
    }

    pub fn requested_padding(&self) -> bool {
        self.opt()
            .and_then(Edns::from_record)
            .map(|e| e.has_option(EDNS_PADDING))
            .unwrap_or(false)
    }

    /// Pads the wire size to a multiple of `block`. Existing padding is removed first and the size
    /// measured without it, to get the right padding length; the 4 is the padding option's own
    /// header (code 2, length 2). Does nothing when `block` is 0 or there is no OPT.
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

    /// Adds an OPT if there is none. `timeout_100ms` is the idle timeout in units of 100 ms (RFC
    /// 7828).
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

    /// Adds an OPT if there is none. `option` holds FAMILY, SOURCE PREFIX-LENGTH, SCOPE
    /// PREFIX-LENGTH, and ADDRESS, raw.
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

/// Extended DNS Error option (RFC 8914).
pub const EDE_OPTION: u16 = 15;

/// RFC 7828.
pub const EDNS_TCP_KEEPALIVE: u16 = 11;

/// RFC 7871.
pub const EDNS_CLIENT_SUBNET: u16 = 8;

/// RFC 7830.
pub const EDNS_PADDING: u16 = 12;

/// Extended DNS Error info codes this server sends; only those in use. An rcode alone does not say
/// why, so clients could not tell a block from an outage.
pub mod ede_code {

    /// Unclassified; the text explains.
    pub const OTHER: u16 = 0;

    /// Served a stale cache entry (RFC 8767).
    pub const STALE_ANSWER: u16 = 3;

    pub const DNSSEC_BOGUS: u16 = 6;

    /// Split out because it is a common cause of bogus.
    pub const SIGNATURE_EXPIRED: u16 = 7;

    /// This server's blocklist verdict.
    pub const BLOCKED: u16 = 15;

    pub const CENSORED: u16 = 16;

    /// Filtering the client asked for.
    pub const FILTERED: u16 = 17;

    /// ACL refusal.
    pub const PROHIBITED: u16 = 18;

    pub const NO_REACHABLE_AUTHORITY: u16 = 22;

    pub const NETWORK_ERROR: u16 = 23;
    /// RFC 9276.
    pub const UNSUPPORTED_NSEC3_ITERATIONS: u16 = 27;
}

/// EDNS(0) state unpacked from an OPT record. OPT hides fields in odd places: CLASS is the UDP
/// payload size and TTL holds extended rcode, version, and DO. This type keeps that conversion in
/// one place.
#[derive(Debug, Clone)]
pub struct Edns {
    pub udp_payload: u16,
    /// High 8 bits of the rcode.
    pub extended_rcode: u8,
    pub version: u8,
    pub dnssec_ok: bool,
    pub options: Vec<(u16, Vec<u8>)>,
}

impl Default for Edns {
    /// 1232 is the IPv6 minimum MTU minus headers, the common safe value that avoids fragmentation;
    /// larger replies risk fragments and loss.
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
    /// TTL and raw option bytes of an OPT record. Errors when it is not OPT, the owner is not the
    /// root, or the RDATA is not raw.
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

    /// Calls `visit` for each (code, data). Validation and collection share this, so they cannot
    /// disagree on strictness. Errors on a cut option header or a length past the remaining bytes.
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

    /// Validates without copying options and returns the extended rcode's high 8 bits, which
    /// combine with the header rcode into 12.
    fn validate_record(rec: &Record) -> Result<u8, ProtoError> {
        let (ttl, raw) = Self::record_parts(rec)?;
        Self::visit_options(raw, |_, _| {})?;
        Ok(((ttl >> 24) & 0xff) as u8)
    }

    /// Copies the options too.
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

    pub fn from_record(rec: &Record) -> Option<Edns> {
        Self::try_from_record(rec).ok()
    }

    /// `info_code` is one of `ede_code`. `extra_text` is human-readable and length-delimited on the
    /// wire, so it has no terminating NUL.
    pub fn push_ede(&mut self, info_code: u16, extra_text: &str) {
        let mut data = info_code.to_be_bytes().to_vec();
        data.extend_from_slice(extra_text.as_bytes());
        self.options.push((EDE_OPTION, data));
    }

    pub fn has_option(&self, code: u16) -> bool {
        self.options.iter().any(|(c, _)| *c == code)
    }

    /// Replaces any existing value.
    pub fn set_tcp_keepalive(&mut self, timeout_100ms: u16) {
        self.options.retain(|(c, _)| *c != EDNS_TCP_KEEPALIVE);
        self.options
            .push((EDNS_TCP_KEEPALIVE, timeout_100ms.to_be_bytes().to_vec()));
    }

    /// Replaces any existing value.
    pub fn set_client_subnet(&mut self, option: Vec<u8>) {
        self.options.retain(|(c, _)| *c != EDNS_CLIENT_SUBNET);
        self.options.push((EDNS_CLIENT_SUBNET, option));
    }

    pub fn client_subnet(&self) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|(c, _)| *c == EDNS_CLIENT_SUBNET)
            .map(|(_, data)| data.as_slice())
    }

    /// Code and text of the first EDE option. Data shorter than 2 bytes becomes code 0: it is only
    /// diagnostics, not worth dropping the whole response over.
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

    /// Errors when one option or the total exceeds a 16-bit length, instead of truncating.
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
mod robustness_tests {
    use super::Message;

    #[test]
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
mod udp_reply_tests {
    use super::*;
    use crate::rdata::RData;
    use std::net::Ipv4Addr;

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
    fn whole_reply_is_parsed_as_is() {
        let m = Message::parse_udp_reply(&reply_wire()).unwrap();
        assert!(!m.header.truncated);
        assert_eq!(m.answers.len(), 4);
    }

    #[test]
    fn reply_cut_mid_record_reads_as_truncated() {
        let wire = reply_wire();
        let m = Message::parse_udp_reply(&wire[..wire.len() - 3]).unwrap();
        assert!(m.header.truncated);
        assert_eq!(m.header.id, 7);
        assert_eq!(m.questions.len(), 1);
        assert!(m.answers.is_empty() && m.authorities.is_empty() && m.additionals.is_empty());
    }

    #[test]
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

    #[test]
    /// The cut-reply parser applies the same section count limit as the normal parser itself,
    /// without assuming the caller filtered first. Over the limit the reply is refused even with
    /// enough bytes; within it, it reads as truncated.
    fn cut_reply_enforces_the_section_item_limit() {
        let over = 4097usize;
        let mut too_many = vec![0u8; 12 + over * 5];
        too_many[2] = 0x80;
        too_many[4..6].copy_from_slice(&(over as u16).to_be_bytes());
        assert!(Message::cut_reply(&too_many).is_none());

        let ok = 1usize;
        let mut one = vec![0u8; 12 + ok * 5];
        one[2] = 0x80;
        one[4..6].copy_from_slice(&(ok as u16).to_be_bytes());
        assert!(Message::cut_reply(&one).is_some());
    }
}

#[cfg(test)]
mod edns_option_tests {
    use super::*;

    fn resp_with_opt() -> Message {
        let mut m = Message::query(1, Name::from_str("example.com").unwrap(), RecordType::A);
        m.header.response = true;
        m.additionals.push(Edns::default().try_to_record().unwrap());
        m
    }

    #[test]
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
mod hardening_tests {
    use super::*;

    #[test]
    /// Accepting it would exhaust memory on its own.
    fn rejects_count_allocation_bomb() {
        let mut wire = vec![0u8; 12];
        wire[4..12].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert!(Message::parse(&wire).is_err());
    }

    #[test]
    /// Refusing would mean no answer. RFC 8906 requires a NOERROR answer that does not carry the
    /// bit.
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
    /// With two, which one to trust is ambiguous.
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
    fn parser_rejects_trailing_bytes() {
        let mut wire = Message::query(1, Name::from_str("x.test").unwrap(), RecordType::A)
            .try_encode()
            .unwrap();
        wire.push(0);
        assert!(Message::parse(&wire).is_err());
    }

    #[test]
    fn parser_enforces_the_dns_wire_size_limit_before_decoding() {
        let wire = vec![0u8; crate::wire::MAX_DNS_WIRE_LEN + 1];
        let error = Message::parse(&wire).unwrap_err();
        assert!(error.to_string().contains("65,535"), "{error}");
    }

    #[test]
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
    fn strict_encoder_rejects_out_of_range_opcode() {
        let mut message = Message::default();
        message.header.opcode = 16;
        assert!(message.try_encode().is_err());
    }

    #[test]
    /// Sent out, the peer would read it differently.
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
