//! Binary HTTP messages (RFC 9292), the plaintext of Oblivious HTTP, and the DoH requests and
//! responses an Oblivious HTTP gateway carries in them. Decoding takes both framings and rejects
//! whatever RFC 9292 calls invalid; encoding writes the known-length framing.

use crate::server::{
    get_dns_param, DohAnswer, Media, ALLOWED_METHODS, MAX_H2_RESPONSE, STATUS_BAD_GATEWAY,
    STATUS_BAD_REQUEST, STATUS_METHOD_NOT_ALLOWED, STATUS_UNSUPPORTED_MEDIA_TYPE,
};
use crate::{token_byte, valid_field_value};

/// Field lines one message may carry, counting informational responses and trailers. DoH needs a
/// few; the cap bounds what decoding one message allocates.
const MAX_FIELD_LINES: usize = 64;

/// RFC 8467's block for DNS responses. Padding the whole response to it hides the answer's size
/// from anyone who sees only the encapsulated response.
const RESPONSE_PADDING_BLOCK: usize = 468;

/// RFC 9458 requires an error for a 100-continue expectation; the encapsulation cannot carry an
/// interim response.
const STATUS_EXPECTATION_FAILED: &str = "417";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    Request {
        method: Vec<u8>,
        scheme: Vec<u8>,
        /// Empty when the request had none.
        authority: Vec<u8>,
        path: Vec<u8>,
    },
    /// The final status. Informational responses before it are checked and dropped.
    Response(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub control: Control,
    /// The header section, names in the case they were sent. Trailers are checked and dropped:
    /// DoH has no use for them.
    pub fields: Vec<(Vec<u8>, Vec<u8>)>,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed;

impl Message {
    pub fn decode(bytes: &[u8]) -> Result<Self, Malformed> {
        let mut reader = Reader::new(bytes);
        let framing = reader.varint()?;
        if framing > 3 {
            return Err(Malformed);
        }
        let known_length = framing < 2;
        let control = if framing % 2 == 0 {
            Control::Request {
                method: reader.prefixed()?.to_vec(),
                scheme: reader.prefixed()?.to_vec(),
                authority: reader.prefixed()?.to_vec(),
                path: reader.prefixed()?.to_vec(),
            }
        } else {
            loop {
                match reader.varint()? {
                    100..=199 => {
                        reader.section(known_length, false)?;
                    }
                    status @ 200..=599 => break Control::Response(status as u16),
                    _ => return Err(Malformed),
                }
            }
        };
        let fields = reader.section(known_length, false)?;
        let content = reader.content(known_length)?;
        reader.section(known_length, true)?;
        if reader.rest.iter().any(|&byte| byte != 0) {
            return Err(Malformed);
        }
        Ok(Self {
            control,
            fields,
            content,
        })
    }

    /// Known-length framing with an empty trailer section and no padding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.content.len() + 64);
        match &self.control {
            Control::Request {
                method,
                scheme,
                authority,
                path,
            } => {
                put_varint(&mut out, 0);
                for part in [method, scheme, authority, path] {
                    put_prefixed(&mut out, part);
                }
            }
            Control::Response(status) => {
                put_varint(&mut out, 1);
                put_varint(&mut out, u64::from(*status));
            }
        }
        let mut section = Vec::new();
        for (name, value) in &self.fields {
            put_prefixed(&mut section, name);
            put_prefixed(&mut section, value);
        }
        put_prefixed(&mut out, &section);
        put_prefixed(&mut out, &self.content);
        put_varint(&mut out, 0);
        out
    }
}

/// The DNS query a Binary HTTP request for DoH at `doh_path` or `/` carries, read as the DoH listener
/// reads one. `Err` is the status to answer with. The authority is not checked: the gateway only
/// ever answers for this server's own DoH path.
pub fn doh_query(request: &[u8], doh_path: &str) -> Result<Vec<u8>, &'static str> {
    let Ok(Message {
        control:
            Control::Request {
                method,
                scheme,
                path,
                ..
            },
        fields,
        content,
    }) = Message::decode(request)
    else {
        return Err(STATUS_BAD_REQUEST);
    };
    if scheme != b"https" {
        return Err(STATUS_BAD_REQUEST);
    }
    let mut content_type = None;
    for (name, value) in &fields {
        if name.eq_ignore_ascii_case(b"expect") {
            return Err(STATUS_EXPECTATION_FAILED);
        }
        if name.eq_ignore_ascii_case(b"content-type")
            && content_type.replace(Media::of(value)).is_some()
        {
            return Err(STATUS_BAD_REQUEST);
        }
        if name.eq_ignore_ascii_case(b"content-length")
            && std::str::from_utf8(value)
                .ok()
                .filter(|text| text.bytes().all(|byte| byte.is_ascii_digit()))
                .and_then(|text| text.parse::<usize>().ok())
                != Some(content.len())
        {
            return Err(STATUS_BAD_REQUEST);
        }
    }
    let path_only = path.split(|&byte| byte == b'?').next().unwrap_or(b"");
    if path_only != doh_path.as_bytes() && path_only != b"/" {
        return Err("404");
    }
    let query = match method.as_slice() {
        b"POST" if content_type != Some(Media::Dns) => return Err(STATUS_UNSUPPORTED_MEDIA_TYPE),
        b"POST" => content,
        b"GET" if !content.is_empty() => return Err(STATUS_BAD_REQUEST),
        b"GET" => get_dns_param(&path).ok_or(STATUS_BAD_REQUEST)?,
        _ => return Err(STATUS_METHOD_NOT_ALLOWED),
    };
    if query.is_empty() {
        return Err(STATUS_BAD_REQUEST);
    }
    Ok(query)
}

/// The Binary HTTP response carrying a DoH answer, or a status in its place, padded to a multiple
/// of RFC 8467's response block.
pub fn doh_response(answer: Result<DohAnswer, &'static str>) -> Vec<u8> {
    let message = match answer {
        Ok(answer) if answer.body.len() <= MAX_H2_RESPONSE => Message {
            control: Control::Response(200),
            fields: vec![
                (
                    b"content-type".to_vec(),
                    b"application/dns-message".to_vec(),
                ),
                (
                    b"cache-control".to_vec(),
                    format!("max-age={}", answer.max_age).into_bytes(),
                ),
            ],
            content: answer.body,
        },
        // An answer that cannot be sent is a server problem, as on the DoH path.
        Ok(_) => status_message(STATUS_BAD_GATEWAY),
        Err(status) => status_message(status),
    };
    let mut bytes = message.encode();
    bytes.resize(bytes.len().next_multiple_of(RESPONSE_PADDING_BLOCK), 0);
    bytes
}

fn status_message(status: &str) -> Message {
    // A 405 must list the accepted methods, or the client cannot know what to retry with.
    let fields = if status == STATUS_METHOD_NOT_ALLOWED {
        vec![(b"allow".to_vec(), ALLOWED_METHODS.as_bytes().to_vec())]
    } else {
        Vec::new()
    };
    Message {
        control: Control::Response(status.parse().unwrap_or(500)),
        fields,
        content: Vec::new(),
    }
}

struct Reader<'a> {
    rest: &'a [u8],
    field_lines: usize,
}

impl<'a> Reader<'a> {
    fn new(rest: &'a [u8]) -> Self {
        Self {
            rest,
            field_lines: 0,
        }
    }

    /// Checks the length against what is left before slicing, so no length field sizes anything.
    fn take(&mut self, len: u64) -> Result<&'a [u8], Malformed> {
        let len = usize::try_from(len).map_err(|_| Malformed)?;
        if len > self.rest.len() {
            return Err(Malformed);
        }
        let (head, rest) = self.rest.split_at(len);
        self.rest = rest;
        Ok(head)
    }

    /// A QUIC variable-length integer.
    fn varint(&mut self) -> Result<u64, Malformed> {
        let first = *self.rest.first().ok_or(Malformed)?;
        let bytes = self.take(1 << (first >> 6))?;
        Ok(bytes[1..]
            .iter()
            .fold(u64::from(first & 0x3f), |value, &byte| {
                (value << 8) | u64::from(byte)
            }))
    }

    fn prefixed(&mut self) -> Result<&'a [u8], Malformed> {
        let len = self.varint()?;
        self.take(len)
    }

    /// A field section. A message may end where a section would start, which stands for an empty
    /// one; ending anywhere inside a section is invalid.
    fn section(
        &mut self,
        known_length: bool,
        trailers: bool,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Malformed> {
        let mut lines = Vec::new();
        if self.rest.is_empty() {
            return Ok(lines);
        }
        if known_length {
            let mut section = Reader::new(self.prefixed()?);
            while !section.rest.is_empty() {
                let name = section.prefixed()?;
                let value = section.prefixed()?;
                self.push_line(&mut lines, name, value, trailers)?;
            }
        } else {
            loop {
                let name = self.prefixed()?;
                if name.is_empty() {
                    break;
                }
                let value = self.prefixed()?;
                self.push_line(&mut lines, name, value, trailers)?;
            }
        }
        Ok(lines)
    }

    fn push_line(
        &mut self,
        lines: &mut Vec<(Vec<u8>, Vec<u8>)>,
        name: &[u8],
        value: &[u8],
        trailers: bool,
    ) -> Result<(), Malformed> {
        self.field_lines += 1;
        if self.field_lines > MAX_FIELD_LINES {
            return Err(Malformed);
        }
        let token = match name.strip_prefix(b":") {
            // Control data carries these five. Other pseudo-fields come before the regular ones
            // and never in trailers.
            Some(_)
                if trailers
                    || matches!(
                        name,
                        b":method" | b":scheme" | b":authority" | b":path" | b":status"
                    )
                    || lines.iter().any(|(seen, _)| !seen.starts_with(b":")) =>
            {
                return Err(Malformed);
            }
            Some(pseudo) => pseudo,
            None => name,
        };
        if token.is_empty() || !token.iter().all(|&byte| token_byte(byte)) {
            return Err(Malformed);
        }
        if !valid_field_value(value) {
            return Err(Malformed);
        }
        lines.push((name.to_vec(), value.to_vec()));
        Ok(())
    }

    fn content(&mut self, known_length: bool) -> Result<Vec<u8>, Malformed> {
        if self.rest.is_empty() {
            return Ok(Vec::new());
        }
        if known_length {
            return Ok(self.prefixed()?.to_vec());
        }
        let mut content = Vec::new();
        loop {
            let chunk = self.prefixed()?;
            if chunk.is_empty() {
                return Ok(content);
            }
            content.extend_from_slice(chunk);
        }
    }
}

/// Callers pass in-memory lengths and status codes, all far below the 2^62 limit.
fn put_varint(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=0x3f => out.push(value as u8),
        0x40..=0x3fff => out.extend_from_slice(&(0x4000 | value as u16).to_be_bytes()),
        0x4000..=0x3fff_ffff => out.extend_from_slice(&(0x8000_0000 | value as u32).to_be_bytes()),
        _ => out.extend_from_slice(&(0xc000_0000_0000_0000 | value).to_be_bytes()),
    }
}

fn put_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let text: String = text.split_whitespace().collect();
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn field(name: &str, value: &str) -> (Vec<u8>, Vec<u8>) {
        (name.as_bytes().to_vec(), value.as_bytes().to_vec())
    }

    // RFC 9292 figure 8: a known-length request.
    const KNOWN_LENGTH_REQUEST: &str = "
        00034745 54056874 74707300 0a2f6865 6c6c6f2e 74787440 6c0a7573 65722d61
        67656e74 34637572 6c2f372e 31362e33 206c6962 6375726c 2f372e31 362e3320
        4f70656e 53534c2f 302e392e 376c207a 6c69622f 312e322e 3304686f 73740f77
        77772e65 78616d70 6c652e63 6f6d0f61 63636570 742d6c61 6e677561 67650665
        6e2c206d 690000";

    // RFC 9292 figure 9: the same request, indeterminate-length with 10 bytes of padding.
    const INDETERMINATE_REQUEST: &str = "
        02034745 54056874 74707300 0a2f6865 6c6c6f2e 7478740a 75736572 2d616765
        6e743463 75726c2f 372e3136 2e33206c 69626375 726c2f37 2e31362e 33204f70
        656e5353 4c2f302e 392e376c 207a6c69 622f312e 322e3304 686f7374 0f777777
        2e657861 6d706c65 2e636f6d 0f616363 6570742d 6c616e67 75616765 06656e2c
        206d6900 00000000 00000000 00000000";

    // RFC 9292 figure 11: an indeterminate-length response with two informational responses.
    const INFORMATIONAL_RESPONSE: &str = "
        03406607 72756e6e 696e670a 22736c65 65702031 35220040 67046c69 6e6b233c
        2f737479 6c652e63 73733e3b 2072656c 3d707265 6c6f6164 3b206173 3d737479
        6c65046c 696e6b24 3c2f7363 72697074 2e6a733e 3b207265 6c3d7072 656c6f61
        643b2061 733d7363 72697074 0040c804 64617465 1d4d6f6e 2c203237 204a756c
        20323030 39203132 3a32383a 35332047 4d540673 65727665 72064170 61636865
        0d6c6173 742d6d6f 64696669 65641d57 65642c20 3232204a 756c2032 30303920
        31393a31 353a3536 20474d54 04657461 67142233 34616133 38372d64 2d313536
        38656230 30220d61 63636570 742d7261 6e676573 05627974 65730e63 6f6e7465
        6e742d6c 656e6774 68023531 04766172 790f4163 63657074 2d456e63 6f64696e
        670c636f 6e74656e 742d7479 70650a74 6578742f 706c6169 6e003348 656c6c6f
        20576f72 6c642120 4d792063 6f6e7465 6e742069 6e636c75 64657320 61207472
        61696c69 6e672043 524c462e 0d0a0000";

    // RFC 9292 figure 13: a known-length response with a trailer.
    const TRAILER_RESPONSE: &str = "
        0140c800 1d546869 7320636f 6e74656e 7420636f 6e746169 6e732043 524c462e
        0d0a0d07 74726169 6c657204 74657874";

    fn hello_request() -> Message {
        Message {
            control: Control::Request {
                method: b"GET".to_vec(),
                scheme: b"https".to_vec(),
                authority: Vec::new(),
                path: b"/hello.txt".to_vec(),
            },
            fields: vec![
                field(
                    "user-agent",
                    "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3",
                ),
                field("host", "www.example.com"),
                field("accept-language", "en, mi"),
            ],
            content: Vec::new(),
        }
    }

    #[test]
    fn requests_decode_from_both_framings_of_the_rfc_example() {
        let known = hex(KNOWN_LENGTH_REQUEST);
        assert_eq!(Message::decode(&known), Ok(hello_request()));
        assert_eq!(
            hello_request().encode(),
            known,
            "the encoder writes figure 8 byte for byte"
        );
        assert_eq!(
            Message::decode(&known[..known.len() - 2]),
            Ok(hello_request()),
            "empty content and trailers may be truncated"
        );
        assert_eq!(
            Message::decode(&hex(INDETERMINATE_REQUEST)),
            Ok(hello_request())
        );
    }

    #[test]
    fn responses_decode_past_informational_responses_and_trailers() {
        let response = Message::decode(&hex(INFORMATIONAL_RESPONSE)).unwrap();
        assert_eq!(response.control, Control::Response(200));
        assert_eq!(response.fields.len(), 8);
        assert_eq!(
            response.fields[0],
            field("date", "Mon, 27 Jul 2009 12:28:53 GMT")
        );
        assert_eq!(response.fields[7], field("content-type", "text/plain"));
        assert_eq!(
            response.content,
            b"Hello World! My content includes a trailing CRLF.\r\n"
        );

        let response = Message::decode(&hex(TRAILER_RESPONSE)).unwrap();
        assert_eq!(response.control, Control::Response(200));
        assert!(response.fields.is_empty());
        assert_eq!(response.content, b"This content contains CRLF.\r\n");
    }

    #[test]
    /// RFC 9458's example request ends right after its control data.
    fn a_message_may_end_after_its_control_data() {
        let request =
            Message::decode(&hex("00034745540568747470730b6578616d706c652e636f6d012f")).unwrap();
        assert_eq!(
            request.control,
            Control::Request {
                method: b"GET".to_vec(),
                scheme: b"https".to_vec(),
                authority: b"example.com".to_vec(),
                path: b"/".to_vec(),
            }
        );
        assert!(request.fields.is_empty() && request.content.is_empty());
        assert_eq!(
            Message::decode(&hex("0140c8")).unwrap().control,
            Control::Response(200)
        );
    }

    #[test]
    fn invalid_messages_are_rejected() {
        let known = hex(KNOWN_LENGTH_REQUEST);
        let with = |tail: &[u8]| [known.as_slice(), tail].concat();
        let request_with_fields = |section: &[u8]| {
            let mut out = hex("00 03474554 056874747073 00 012f");
            put_prefixed(&mut out, section);
            out
        };
        let response_with_trailers = |section: &[u8]| {
            let mut out = hex("01 40c8 00 00");
            put_prefixed(&mut out, section);
            out
        };
        for (label, bytes) in [
            ("framing indicator 4", hex("04")),
            ("truncated control data", hex("000347")),
            ("nonzero padding", with(&[0, 1])),
            (
                "content longer than the message",
                hex("00 00 00 00 00 00 05 01"),
            ),
            (
                "a length near 2^62",
                hex("00 00 00 00 00 00 ffffffffffffffff 00"),
            ),
            ("empty field name", request_with_fields(&hex("00 00"))),
            (
                "space in a field name",
                request_with_fields(b"\x03a b\x01x"),
            ),
            ("CR in a field value", request_with_fields(b"\x01a\x03x\ry")),
            (
                "leading space in a value",
                request_with_fields(b"\x01a\x02 y"),
            ),
            (
                "control data as a field",
                request_with_fields(b"\x05:path\x01/"),
            ),
            (
                "pseudo-field after a regular one",
                request_with_fields(b"\x01a\x01b\x09:protocol\x01x"),
            ),
            (
                "pseudo-field in trailers",
                response_with_trailers(b"\x09:protocol\x01x"),
            ),
            (
                "unterminated indeterminate section",
                hex("02 03474554 056874747073 00 012f 04686f7374 0161"),
            ),
            ("only an informational response", hex("01 4066")),
            ("status 99", hex("01 4063")),
            ("status 600", hex("01 4258")),
            (
                "field section shorter than its lines",
                request_with_fields(b"\x04host"),
            ),
        ] {
            assert_eq!(Message::decode(&bytes), Err(Malformed), "{label}");
        }
    }

    #[test]
    fn extension_pseudo_fields_and_uppercase_names_are_valid() {
        let mut out = hex("00 03474554 056874747073 00 012f");
        put_prefixed(&mut out, b"\x09:protocol\x01x\x04Host\x01y");
        let message = Message::decode(&out).unwrap();
        assert_eq!(
            message.fields,
            vec![field(":protocol", "x"), field("Host", "y")]
        );
    }

    #[test]
    fn field_lines_are_capped_per_message() {
        let section = |count: usize| b"\x01a\x01b".repeat(count);
        let request = |count: usize| {
            let mut out = hex("00 03474554 056874747073 00 012f");
            put_prefixed(&mut out, &section(count));
            out
        };
        assert_eq!(
            Message::decode(&request(MAX_FIELD_LINES))
                .unwrap()
                .fields
                .len(),
            MAX_FIELD_LINES
        );
        assert_eq!(
            Message::decode(&request(MAX_FIELD_LINES + 1)),
            Err(Malformed)
        );
        let mut with_trailers = request(MAX_FIELD_LINES);
        with_trailers.push(0);
        put_prefixed(&mut with_trailers, &section(1));
        assert_eq!(
            Message::decode(&with_trailers),
            Err(Malformed),
            "trailers count toward the cap"
        );
    }

    #[test]
    fn varints_take_every_length_the_format_allows() {
        for value in [0, 63, 64, 16_383, 16_384, 1 << 29, (1 << 30) - 1, 1 << 30] {
            let mut out = Vec::new();
            put_varint(&mut out, value);
            let mut reader = Reader::new(&out);
            assert_eq!(reader.varint(), Ok(value));
            assert!(reader.rest.is_empty());
        }
        assert_eq!(
            Reader::new(&hex("4025")).varint(),
            Ok(37),
            "a value need not use the shortest encoding"
        );
    }

    fn doh_request(method: &str, path: &str, fields: &[(&str, &str)], content: &[u8]) -> Vec<u8> {
        Message {
            control: Control::Request {
                method: method.as_bytes().to_vec(),
                scheme: b"https".to_vec(),
                authority: b"dns.test".to_vec(),
                path: path.as_bytes().to_vec(),
            },
            fields: fields
                .iter()
                .map(|(name, value)| field(name, value))
                .collect(),
            content: content.to_vec(),
        }
        .encode()
    }

    const DNS: (&str, &str) = ("content-type", "application/dns-message");

    #[test]
    fn doh_requests_carry_their_query_by_post_or_get() {
        assert_eq!(
            doh_query(
                &doh_request("POST", "/dns-query", &[DNS], b"query"),
                "/dns-query"
            ),
            Ok(b"query".to_vec())
        );
        assert_eq!(
            doh_query(
                &doh_request(
                    "POST",
                    "/dns-query",
                    &[DNS, ("Content-Length", "5")],
                    b"query"
                ),
                "/dns-query"
            ),
            Ok(b"query".to_vec())
        );
        assert_eq!(
            doh_query(
                &doh_request("GET", "/dns-query?dns=AAAB", &[], b""),
                "/dns-query"
            ),
            Ok(vec![0, 0, 1])
        );
    }

    #[test]
    fn doh_requests_get_the_status_the_doh_listener_would_give() {
        let query = |method: &str, path: &str, fields: &[(&str, &str)], content: &[u8]| {
            doh_query(&doh_request(method, path, fields, content), "/dns-query")
        };
        assert_eq!(query("POST", "/dns-query/laptop", &[DNS], b"q"), Err("404"));
        assert_eq!(query("POST", "/other", &[DNS], b"q"), Err("404"));
        assert_eq!(
            query(
                "POST",
                "/dns-query",
                &[("content-type", "text/plain")],
                b"q"
            ),
            Err("415")
        );
        assert_eq!(query("POST", "/dns-query", &[], b"q"), Err("415"));
        assert_eq!(query("PUT", "/dns-query", &[DNS], b"q"), Err("405"));
        assert_eq!(
            query(
                "POST",
                "/dns-query",
                &[DNS, ("expect", "100-continue")],
                b"q"
            ),
            Err("417")
        );
        assert_eq!(query("POST", "/dns-query", &[DNS, DNS], b"q"), Err("400"));
        assert_eq!(
            query("POST", "/dns-query", &[DNS, ("content-length", "4")], b"q"),
            Err("400")
        );
        assert_eq!(query("POST", "/dns-query", &[DNS], b""), Err("400"));
        assert_eq!(query("GET", "/dns-query?dns=AAAB", &[], b"q"), Err("400"));
        assert_eq!(query("GET", "/dns-query", &[], b""), Err("400"));

        let mut http = Message::decode(&doh_request("POST", "/dns-query", &[DNS], b"q")).unwrap();
        if let Control::Request { scheme, .. } = &mut http.control {
            *scheme = b"http".to_vec();
        }
        assert_eq!(doh_query(&http.encode(), "/dns-query"), Err("400"));
        assert_eq!(doh_query(b"\x04", "/dns-query"), Err("400"));
        assert_eq!(doh_query(&hex("0140c8"), "/dns-query"), Err("400"));
    }

    #[test]
    fn doh_responses_are_padded_binary_http() {
        let bytes = doh_response(Ok(DohAnswer {
            body: b"answer".to_vec(),
            max_age: 60,
        }));
        assert_eq!(bytes.len(), RESPONSE_PADDING_BLOCK);
        let response = Message::decode(&bytes).unwrap();
        assert_eq!(response.control, Control::Response(200));
        assert_eq!(
            response.fields,
            vec![DNS, ("cache-control", "max-age=60")]
                .into_iter()
                .map(|(name, value)| field(name, value))
                .collect::<Vec<_>>()
        );
        assert_eq!(response.content, b"answer");

        let long = doh_response(Ok(DohAnswer {
            body: vec![1; 1000],
            max_age: 0,
        }));
        assert_eq!(long.len() % RESPONSE_PADDING_BLOCK, 0);

        let refused = Message::decode(&doh_response(Err("405"))).unwrap();
        assert_eq!(refused.control, Control::Response(405));
        assert_eq!(refused.fields, vec![field("allow", ALLOWED_METHODS)]);
        let too_long = doh_response(Ok(DohAnswer {
            body: vec![0; MAX_H2_RESPONSE + 1],
            max_age: 0,
        }));
        assert_eq!(
            Message::decode(&too_long).unwrap().control,
            Control::Response(502)
        );
    }
}
