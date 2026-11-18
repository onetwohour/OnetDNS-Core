//! TLS record framing: the byte stream is split into records, each tagged with a type and a length.
//!
//! Lengths are capped; otherwise one length field could hold this side's memory.

use crate::TlsError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentType(pub u8);

#[allow(non_upper_case_globals)]
impl ContentType {
    /// A dummy in TLS 1.3, kept for compatibility.
    pub const ChangeCipherSpec: ContentType = ContentType(20);
    pub const Alert: ContentType = ContentType(21);
    pub const Handshake: ContentType = ContentType(22);
    /// In TLS 1.3 everything encrypted is disguised as this type.
    pub const ApplicationData: ContentType = ContentType(23);
}

pub const MAX_FRAGMENT: usize = 1 << 14;
/// Leaves room for the tag and expansion.
pub const MAX_CIPHERTEXT: usize = MAX_FRAGMENT + 256;

/// TLS 1.3 uses it too, for compatibility.
pub const LEGACY_VERSION: u16 = 0x0303;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsRecord {
    pub content_type: ContentType,
    pub version: u16,
    pub fragment: Vec<u8>,
}

impl TlsRecord {
    pub fn new(content_type: ContentType, fragment: Vec<u8>) -> Self {
        Self {
            content_type,
            version: LEGACY_VERSION,
            fragment,
        }
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.content_type.0);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&(self.fragment.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.fragment);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(5 + self.fragment.len());
        self.encode_into(&mut v);
        v
    }

    /// None when the record is incomplete; that means wait, not an error.
    pub fn parse(buf: &[u8]) -> Result<Option<(TlsRecord, usize)>, TlsError> {
        if buf.len() < 5 {
            return Ok(None);
        }
        let content_type = ContentType(buf[0]);
        let version = u16::from_be_bytes([buf[1], buf[2]]);
        let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if len > MAX_CIPHERTEXT {
            return Err(TlsError::RecordOverflow);
        }
        if buf.len() < 5 + len {
            return Ok(None);
        }
        Ok(Some((
            TlsRecord {
                content_type,
                version,
                fragment: buf[5..5 + len].to_vec(),
            },
            5 + len,
        )))
    }
}

/// Bound on a buffered first ClientHello, which may span records.
pub const MAX_CLIENT_HELLO_PREFIX: usize = 64 * 1024;

/// Whether `prefix` holds the whole first ClientHello, so a server can hold a new connection
/// without a thread until the handshake can run without waiting. Checks lengths and types only;
/// the handshake still parses the message. The error says what is wrong with the prefix.
pub fn client_hello_complete(prefix: &[u8]) -> Result<bool, &'static str> {
    if prefix.len() > MAX_CLIENT_HELLO_PREFIX {
        return Err("TLS ClientHello prefix exceeds 64 KiB");
    }

    let mut record_offset = 0usize;
    let mut handshake_header = [0u8; 4];
    let mut handshake_bytes = 0usize;
    let mut handshake_total = None;

    while record_offset < prefix.len() {
        if prefix.len() - record_offset < 5 {
            return Ok(false);
        }
        let header = &prefix[record_offset..record_offset + 5];
        if header[0] != 22 || header[1] != 3 {
            return Err("The first TLS message must be a handshake record");
        }
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if record_len == 0 || record_len > MAX_FRAGMENT {
            return Err("TLS record length is out of range");
        }
        let record_end = record_offset + 5 + record_len;
        if record_end > prefix.len() {
            return Ok(false);
        }

        let payload = &prefix[record_offset + 5..record_end];
        if handshake_bytes < handshake_header.len() {
            let copy = (handshake_header.len() - handshake_bytes).min(payload.len());
            handshake_header[handshake_bytes..handshake_bytes + copy]
                .copy_from_slice(&payload[..copy]);
        }
        handshake_bytes = handshake_bytes.saturating_add(payload.len());

        if handshake_total.is_none() && handshake_bytes >= handshake_header.len() {
            if handshake_header[0] != 1 {
                return Err("The first TLS handshake message must be a ClientHello");
            }
            let body_len = ((handshake_header[1] as usize) << 16)
                | ((handshake_header[2] as usize) << 8)
                | handshake_header[3] as usize;
            let total = handshake_header.len() + body_len;
            if total + 5 > MAX_CLIENT_HELLO_PREFIX {
                return Err("TLS ClientHello length exceeds 64 KiB");
            }
            handshake_total = Some(total);
        }
        if handshake_total.is_some_and(|total| handshake_bytes >= total) {
            return Ok(true);
        }
        record_offset = record_end;
    }

    Ok(false)
}

#[derive(Default)]
pub struct RecordReader {
    buf: Vec<u8>,
}

impl RecordReader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn next_record(&mut self) -> Result<Option<TlsRecord>, TlsError> {
        match TlsRecord::parse(&self.buf)? {
            Some((rec, consumed)) => {
                self.buf.drain(..consumed);
                Ok(Some(rec))
            }
            None => Ok(None),
        }
    }
}
