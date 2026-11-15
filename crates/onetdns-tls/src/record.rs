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
