//! Byte cursor and writer with name compression state. The only byte access path the message, name,
//! and rdata codecs share; keeping bounds checks here keeps those parsers from indexing slices
//! directly.

use crate::name::NameMap;
use crate::ProtoError;

/// The largest DNS message a 2-byte TCP length prefix can express.
pub const MAX_DNS_WIRE_LEN: usize = u16::MAX as usize;

/// Bounds-checked byte cursor. `pos` can be rewound freely, which following compression pointers
/// needs. `limit` is narrowed while reading an RDATA so a record cannot read past its own length.
///
/// `pos <= limit <= buf.len()`; every read checks this first.
pub struct Reader<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
    pub(crate) limit: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            limit: buf.len(),
        }
    }

    pub fn u8(&mut self) -> Result<u8, ProtoError> {
        if self.pos >= self.limit {
            return Err(ProtoError::Eof);
        }
        let b = *self.buf.get(self.pos).ok_or(ProtoError::Eof)?;
        self.pos += 1;
        Ok(b)
    }

    /// Big-endian.
    pub fn u16(&mut self) -> Result<u16, ProtoError> {
        let hi = self.u8()? as u16;
        let lo = self.u8()? as u16;
        Ok((hi << 8) | lo)
    }

    /// Big-endian.
    pub fn u32(&mut self) -> Result<u32, ProtoError> {
        let a = self.u16()? as u32;
        let b = self.u16()? as u32;
        Ok((a << 16) | b)
    }

    /// Borrows `n` bytes without copying. `n` comes from untrusted input, so the addition is
    /// checked for overflow first.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        let end = self.pos.checked_add(n).ok_or(ProtoError::Eof)?;
        if end > self.limit {
            return Err(ProtoError::Eof);
        }
        let s = self.buf.get(self.pos..end).ok_or(ProtoError::Eof)?;
        self.pos = end;
        Ok(s)
    }

    pub fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.pos)
    }
}

/// Encoding buffer with name compression that stays failed after the first error: it records the
/// error and drops every later write. The encoding path need not check each push, but callers must
/// check error() or finish(), or a truncated message passes as success.
///
/// `buf.len() <= limit`; a write that would exceed it fails instead.
pub struct Writer {
    pub buf: Vec<u8>,
    pub(crate) names: NameMap,
    error: Option<ProtoError>,
    limit: usize,
}

impl Default for Writer {
    fn default() -> Self {
        Self {
            buf: Vec::new(),
            names: NameMap::default(),
            error: None,
            limit: MAX_DNS_WIRE_LEN,
        }
    }
}

impl Writer {
    /// Up to the absolute wire limit (64 KiB).
    pub fn new() -> Self {
        Self::default()
    }

    /// For fitting a UDP response to the negotiated size. A `limit` above the absolute wire limit
    /// is clamped to it.
    pub fn with_limit(limit: usize) -> Self {
        Self {
            limit: limit.min(MAX_DNS_WIRE_LEN),
            ..Self::default()
        }
    }

    /// Keeps the allocation. Compression offsets are valid for one message only, so `names` is
    /// cleared too; otherwise the next message would carry pointers into the previous one.
    pub fn clear(&mut self) {
        self.buf.clear();
        self.names.clear();
        self.error = None;
    }

    /// Only the first error is kept.
    pub fn fail(&mut self, message: impl Into<String>) {
        if self.error.is_none() {
            self.error = Some(ProtoError::Message(message.into()));
        }
    }

    /// Lets long encoding loops stop early.
    pub fn is_failed(&self) -> bool {
        self.error.is_some()
    }

    pub fn error(&self) -> Option<&ProtoError> {
        self.error.as_ref()
    }

    /// Whether `additional` more bytes may be appended; false when the writer already failed or
    /// just failed now.
    fn reserve_append(&mut self, additional: usize) -> bool {
        if self.error.is_some() {
            return false;
        }
        let Some(total) = self.buf.len().checked_add(additional) else {
            self.fail("DNS message length arithmetic overflowed");
            return false;
        };
        if total > self.limit {
            self.fail(format!("DNS message exceeds the {}-byte limit", self.limit));
            return false;
        }
        true
    }

    /// Past the limit the byte is dropped and the writer marked failed.
    pub fn push_u8(&mut self, v: u8) {
        if self.reserve_append(1) {
            self.buf.push(v);
        }
    }

    /// Big-endian.
    pub fn push_u16(&mut self, v: u16) {
        if self.reserve_append(2) {
            self.buf.extend_from_slice(&v.to_be_bytes());
        }
    }

    /// Big-endian.
    pub fn push_u32(&mut self, v: u32) {
        if self.reserve_append(4) {
            self.buf.extend_from_slice(&v.to_be_bytes());
        }
    }

    pub fn push_bytes(&mut self, b: &[u8]) {
        if self.reserve_append(b.len()) {
            self.buf.extend_from_slice(b);
        }
    }

    /// Reserves space for many same-shaped records at once. A push_bytes per record means a limit
    /// check, a capacity check, and a small run-time-length memcpy per record; writing fixed-size
    /// records into one reserved block removes those calls. Returns the zeroed block, or `None`
    /// without touching the buffer when the limit is exceeded or the writer already failed.
    pub fn reserve_block(&mut self, additional: usize) -> Option<&mut [u8]> {
        if !self.reserve_append(additional) {
            return None;
        }
        let start = self.buf.len();
        self.buf.resize(start + additional, 0);
        Some(&mut self.buf[start..])
    }

    /// Reserves a 16-bit length slot to fill later; pass the returned position to backpatch_len.
    pub fn placeholder_u16(&mut self) -> usize {
        let at = self.buf.len();
        self.push_u16(0);
        at
    }

    /// Writes the byte count since `at` (from placeholder_u16) into its slot. RDLENGTH is 16 bits,
    /// so an RDATA over 65,535 bytes fails instead of being truncated.
    pub fn backpatch_len(&mut self, at: usize) {
        if self.error.is_some() {
            return;
        }
        let Some(start) = at.checked_add(2) else {
            self.fail("DNS length placeholder overflowed");
            return;
        };
        let Some(slice) = self.buf.get(at..start) else {
            self.fail("Invalid DNS length placeholder range");
            return;
        };
        let _ = slice;
        let Some(len) = self.buf.len().checked_sub(start) else {
            self.fail("Invalid DNS RDATA length range");
            return;
        };
        let Ok(len) = u16::try_from(len) else {
            self.fail("DNS record data exceeds 65,535 bytes");
            return;
        };
        self.buf[at..start].copy_from_slice(&len.to_be_bytes());
    }

    /// The first error from encoding, if any; otherwise the bytes.
    pub fn finish(self) -> Result<Vec<u8>, ProtoError> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(self.buf),
        }
    }
}
