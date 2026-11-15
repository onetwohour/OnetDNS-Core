//! DER parser, the format certificates use. Lengths come in a short and a long form; the long form
//! gives the length of the length first.
//!
//! Nonminimal length encodings are rejected: if one value could be written several ways, the bytes
//! that were signed and the value read here could differ.

use crate::TlsError;

pub const BOOLEAN: u8 = 0x01;
pub const INTEGER: u8 = 0x02;
/// Prefixed with the count of unused bits.
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const OID: u8 = 0x06;
pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;

/// Context-specific tag, for optional fields whose meaning depends on position.
pub const fn context(n: u8) -> u8 {
    0xA0 | n
}

#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn der(&self) -> Der<'a> {
        Der::new(self.value)
    }
}

pub struct Der<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn byte(&mut self) -> Result<u8, TlsError> {
        let b = *self.buf.get(self.pos).ok_or(TlsError::BadCert)?;
        self.pos += 1;
        Ok(b)
    }

    /// Rejects nonminimal lengths. Accepting them lets implementations read the same certificate
    /// differently, and that difference is a bypass.
    pub fn next(&mut self) -> Result<Tlv<'a>, TlsError> {
        let tag = self.byte()?;
        let first = self.byte()?;
        let len = if first < 0x80 {
            first as usize
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 {
                return Err(TlsError::BadCert);
            }
            let mut l = 0usize;
            for i in 0..n {
                let b = self.byte()?;

                if i == 0 && b == 0 {
                    return Err(TlsError::BadCert);
                }
                l = (l << 8) | b as usize;
            }

            if l < 0x80 {
                return Err(TlsError::BadCert);
            }
            l
        };

        let end = self.pos.checked_add(len).ok_or(TlsError::BadCert)?;
        let value = self.buf.get(self.pos..end).ok_or(TlsError::BadCert)?;
        self.pos = end;
        Ok(Tlv { tag, value })
    }

    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8], TlsError> {
        let tlv = self.next()?;
        if tlv.tag != tag {
            return Err(TlsError::BadCert);
        }
        Ok(tlv.value)
    }

    /// Also returns the raw bytes, which are what signatures cover.
    pub fn next_raw(&mut self) -> Result<(&'a [u8], Tlv<'a>), TlsError> {
        let start = self.pos;
        let tlv = self.next()?;
        Ok((&self.buf[start..self.pos], tlv))
    }
}

/// DER writes true only as the single byte 0xFF and false only as 0x00. Accepting another length or
/// value would read the same certificate differently from other verifiers.
pub fn boolean_value(value: &[u8]) -> Result<bool, TlsError> {
    match value {
        [0xFF] => Ok(true),
        [0x00] => Ok(false),
        _ => Err(TlsError::BadCert),
    }
}

/// Rejects empty values, negatives (top bit set), and needless leading 0x00 bytes; read as
/// unsigned, -1 would become a large limit like 255. Values past u32 are rejected too.
pub fn uint_value(value: &[u8]) -> Result<u32, TlsError> {
    match value {
        [] => return Err(TlsError::BadCert),
        [first, ..] if first & 0x80 != 0 => return Err(TlsError::BadCert),
        [0x00, second, ..] if second & 0x80 == 0 => return Err(TlsError::BadCert),
        _ => {}
    }
    let mut n: u32 = 0;
    for &b in value {
        n = n
            .checked_mul(256)
            .and_then(|n| n.checked_add(u32::from(b)))
            .ok_or(TlsError::BadCert)?;
    }
    Ok(n)
}

/// Rejects nonzero unused bits.
pub fn bit_string_bytes(value: &[u8]) -> Result<&[u8], TlsError> {
    let (&unused, rest) = value.split_first().ok_or(TlsError::BadCert)?;

    if unused > 7 || (rest.is_empty() && unused != 0) {
        return Err(TlsError::BadCert);
    }
    if unused != 0 {
        if let Some(&last) = rest.last() {
            if last & ((1u8 << unused) - 1) != 0 {
                return Err(TlsError::BadCert);
            }
        }
    }
    Ok(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sequence_of_primitives() {
        let oid = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
        let mut inner = Vec::new();
        inner.extend_from_slice(&[INTEGER, 0x01, 0x05]);
        inner.push(OID);
        inner.push(oid.len() as u8);
        inner.extend_from_slice(&oid);
        inner.extend_from_slice(&[BIT_STRING, 0x03, 0x00, 0xAB, 0xCD]);
        let mut der = Vec::new();
        der.push(SEQUENCE);
        der.push(inner.len() as u8);
        der.extend_from_slice(&inner);

        let mut top = Der::new(&der);
        let seq = top.expect(SEQUENCE).unwrap();
        let mut r = Der::new(seq);
        assert_eq!(r.expect(INTEGER).unwrap(), &[0x05]);
        assert_eq!(r.expect(OID).unwrap(), &oid);
        let bs = r.expect(BIT_STRING).unwrap();
        assert_eq!(bit_string_bytes(bs).unwrap(), &[0xAB, 0xCD]);
        assert!(r.is_empty());
    }

    #[test]
    fn long_form_length() {
        let body = vec![0x77u8; 200];
        let mut der = vec![OCTET_STRING, 0x81, 0xC8];
        der.extend_from_slice(&body);
        let mut r = Der::new(&der);
        let v = r.expect(OCTET_STRING).unwrap();
        assert_eq!(v.len(), 200);
        assert_eq!(v, &body[..]);
    }

    #[test]
    fn nested_and_raw() {
        let der = [SEQUENCE, 0x05, SEQUENCE, 0x03, INTEGER, 0x01, 0x01];
        let mut top = Der::new(&der);
        let (raw, tlv) = top.next_raw().unwrap();
        assert_eq!(raw, &der[..]);
        assert_eq!(tlv.tag, SEQUENCE);
        let mut inner = tlv.der();
        let inner_seq = inner.expect(SEQUENCE).unwrap();
        assert_eq!(Der::new(inner_seq).expect(INTEGER).unwrap(), &[0x01]);
    }

    #[test]
    fn oversize_long_form_length_never_panics() {
        let mut r = Der::new(&[OCTET_STRING, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        assert!(matches!(r.next(), Err(TlsError::BadCert)));
    }

    #[test]
    fn non_minimal_length_rejected() {
        let mut r = Der::new(&[OCTET_STRING, 0x81, 0x05, 1, 2, 3, 4, 5]);
        assert!(r.next().is_err());

        let mut body = vec![OCTET_STRING, 0x82, 0x00, 0xC8];
        body.extend_from_slice(&[0u8; 200]);
        let mut r2 = Der::new(&body);
        assert!(r2.next().is_err());
    }

    #[test]
    fn bit_string_validation() {
        assert_eq!(
            bit_string_bytes(&[0x00, 0xAB, 0xCD]).unwrap(),
            &[0xAB, 0xCD]
        );

        assert!(bit_string_bytes(&[0x08, 0xAB]).is_err());

        assert!(bit_string_bytes(&[0x03]).is_err());

        assert!(bit_string_bytes(&[0x03, 0x05]).is_err());

        assert_eq!(bit_string_bytes(&[0x03, 0xF8]).unwrap(), &[0xF8]);
    }

    #[test]
    fn context_tag_and_errors() {
        assert_eq!(context(0), 0xA0);
        assert_eq!(context(3), 0xA3);

        let mut r = Der::new(&[SEQUENCE, 0x05, 0x01]);
        assert!(r.next().is_err());

        let mut r2 = Der::new(&[INTEGER, 0x01, 0x05]);
        assert!(r2.expect(SEQUENCE).is_err());
    }
}
