/*!
 * @brief DER 파서.
 *
 * @details 인증서가 이 형식이다. 길이는 짧은 형태와 긴 형태가 있고, 긴 형태는 길이의
 *          길이를 먼저 적는다.
 * @warning 비최소 길이 인코딩을 거부한다. 같은 값을 여러 형태로 쓸 수 있으면 서명한
 *          바이트와 이쪽이 읽은 값이 달라질 수 있다.
 */

use crate::TlsError;

/** @brief 참거짓. */
pub const BOOLEAN: u8 = 0x01;
/** @brief 정수. */
pub const INTEGER: u8 = 0x02;
/** @brief 비트열. 앞에 남는 비트 수가 붙는다. */
pub const BIT_STRING: u8 = 0x03;
/** @brief 바이트열. */
pub const OCTET_STRING: u8 = 0x04;
/** @brief 객체 식별자. */
pub const OID: u8 = 0x06;
/** @brief SEQUENCE. */
pub const SEQUENCE: u8 = 0x30;
/** @brief SET. */
pub const SET: u8 = 0x31;

/** @brief 문맥 의존 태그. 위치마다 뜻이 달라지는 선택 항목에 쓴다. */
pub const fn context(n: u8) -> u8 {
    0xA0 | n
}

#[derive(Debug, Clone, Copy)]
/** @brief 태그, 길이, 값 하나. */
pub struct Tlv<'a> {
    /** @brief 이 조각의 태그. */
    pub tag: u8,
    /** @brief 이 조각의 내용. */
    pub value: &'a [u8],
}

impl<'a> Tlv<'a> {
    /** @brief 이 값의 내용을 다시 파싱할 커서. */
    pub fn der(&self) -> Der<'a> {
        Der::new(self.value)
    }
}

/** @brief DER 바이트를 읽는 커서. */
pub struct Der<'a> {
    /** @brief 읽어 들일 바이트. */
    buf: &'a [u8],
    /** @brief 지금 위치. */
    pos: usize,
}

impl<'a> Der<'a> {
    /** @brief 바이트열로 커서를 만든다. */
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /** @brief 다 읽었는지. */
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /** @brief 한 바이트를 읽는다. */
    fn byte(&mut self) -> Result<u8, TlsError> {
        let b = *self.buf.get(self.pos).ok_or(TlsError::BadCert)?;
        self.pos += 1;
        Ok(b)
    }

    /**
     * @brief 다음 값을 읽는다.
     * @warning 길이를 비최소로 적은 것을 거부한다. 허용하면 같은 인증서를 다르게 읽는
     *          구현 차이가 생기고, 그 차이가 곧 우회 경로다.
     */
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

    /** @brief 기대한 태그의 값을 읽는다. 다르면 오류다. */
    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8], TlsError> {
        let tlv = self.next()?;
        if tlv.tag != tag {
            return Err(TlsError::BadCert);
        }
        Ok(tlv.value)
    }

    /** @brief 값과 함께 그 원본 바이트도 준다. 서명 대상이 원본이라 필요하다. */
    pub fn next_raw(&mut self) -> Result<(&'a [u8], Tlv<'a>), TlsError> {
        let start = self.pos;
        let tlv = self.next()?;
        Ok((&self.buf[start..self.pos], tlv))
    }
}

/**
 * @brief BOOLEAN 값의 내용을 읽는다.
 * @details DER 은 참을 0xFF 한 바이트, 거짓을 0x00 한 바이트로만 적는다. 다른 길이나 값을 받으면
 *          같은 인증서를 다른 검증기와 다르게 읽게 된다.
 */
pub fn boolean_value(value: &[u8]) -> Result<bool, TlsError> {
    match value {
        [0xFF] => Ok(true),
        [0x00] => Ok(false),
        _ => Err(TlsError::BadCert),
    }
}

/**
 * @brief 음이 아닌 INTEGER 값의 내용을 u32 로 읽는다.
 * @details 빈 값, 음수(첫 비트가 1), 불필요한 앞자리 0x00 을 거부한다. 음수를 부호 없는 값으로
 *          읽으면 -1 이 255 처럼 큰 제한으로 바뀐다. u32 를 넘는 값도 거부한다.
 */
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

/** @brief 비트열에서 실제 바이트를 꺼낸다. 남는 비트가 0이 아니면 거부한다. */
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
/** @brief 길이 형태별 파싱과 비최소 인코딩 거부. */
mod tests {
    use super::*;

    #[test]
    /** @brief 기본 값들의 파싱. */
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
    /** @brief 긴 형태 길이. */
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
    /** @brief 중첩 구조와 원본 바이트. */
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
    /** @brief 지나치게 큰 길이에도 패닉하지 않는지. */
    fn oversize_long_form_length_never_panics() {
        let mut r = Der::new(&[OCTET_STRING, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        assert!(matches!(r.next(), Err(TlsError::BadCert)));
    }

    #[test]
    /** @brief 비최소 길이를 거부하는지. */
    fn non_minimal_length_rejected() {
        let mut r = Der::new(&[OCTET_STRING, 0x81, 0x05, 1, 2, 3, 4, 5]);
        assert!(r.next().is_err());

        let mut body = vec![OCTET_STRING, 0x82, 0x00, 0xC8];
        body.extend_from_slice(&[0u8; 200]);
        let mut r2 = Der::new(&body);
        assert!(r2.next().is_err());
    }

    #[test]
    /** @brief 비트열의 남는 비트 검사. */
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
    /** @brief 문맥 태그와 오류 경로. */
    fn context_tag_and_errors() {
        assert_eq!(context(0), 0xA0);
        assert_eq!(context(3), 0xA3);

        let mut r = Der::new(&[SEQUENCE, 0x05, 0x01]);
        assert!(r.next().is_err());

        let mut r2 = Der::new(&[INTEGER, 0x01, 0x05]);
        assert!(r2.expect(SEQUENCE).is_err());
    }
}
