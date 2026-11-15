//! Length-prefixed reads and writes; most TLS messages are sequences of values with 1-, 2-, or
//! 3-byte length prefixes.
//!
//! Every read is bounds-checked: this is where untrusted bytes first arrive.

use crate::TlsError;

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn u8(&mut self) -> Result<u8, TlsError> {
        let b = *self.buf.get(self.pos).ok_or(TlsError::Decode)?;
        self.pos += 1;
        Ok(b)
    }

    pub fn u16(&mut self) -> Result<u16, TlsError> {
        Ok(((self.u8()? as u16) << 8) | self.u8()? as u16)
    }

    /// Handshake message lengths use this form.
    pub fn u24(&mut self) -> Result<u32, TlsError> {
        Ok(((self.u8()? as u32) << 16) | ((self.u8()? as u32) << 8) | self.u8()? as u32)
    }

    pub fn u32(&mut self) -> Result<u32, TlsError> {
        Ok(((self.u16()? as u32) << 16) | self.u16()? as u32)
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], TlsError> {
        let s = self
            .buf
            .get(self.pos..self.pos + n)
            .ok_or(TlsError::Decode)?;
        self.pos += n;
        Ok(s)
    }

    pub fn vec8(&mut self) -> Result<&'a [u8], TlsError> {
        let n = self.u8()? as usize;
        self.take(n)
    }

    pub fn vec16(&mut self) -> Result<&'a [u8], TlsError> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    pub fn vec24(&mut self) -> Result<&'a [u8], TlsError> {
        let n = self.u24()? as usize;
        self.take(n)
    }
}

#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u24(&mut self, v: u32) {
        self.buf
            .extend_from_slice(&[(v >> 16) as u8, (v >> 8) as u8, v as u8]);
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// Leaves the length field empty, fills the body, then goes back to write the length, so nested
    /// structures need no precomputed lengths.
    pub fn vec8(&mut self, f: impl FnOnce(&mut Writer)) {
        let at = self.buf.len();
        self.buf.push(0);
        f(self);
        let len = (self.buf.len() - at - 1) as u8;
        self.buf[at] = len;
    }

    pub fn vec16(&mut self, f: impl FnOnce(&mut Writer)) {
        let at = self.buf.len();
        self.buf.extend_from_slice(&[0, 0]);
        f(self);
        let len = (self.buf.len() - at - 2) as u16;
        self.buf[at..at + 2].copy_from_slice(&len.to_be_bytes());
    }

    pub fn vec24(&mut self, f: impl FnOnce(&mut Writer)) {
        let at = self.buf.len();
        self.buf.extend_from_slice(&[0, 0, 0]);
        f(self);
        let len = (self.buf.len() - at - 3) as u32;
        self.buf[at..at + 3].copy_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    }
}
