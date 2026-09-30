/*!
 * @brief RSA 검증. 서명은 하지 않는다.
 *
 * @details 허용 목록에 RSA 크레이트가 없어서 직접 만들었다. DNSSEC 알고리즘 8/10과 TLS
 *          인증서 서명 검증이 여기에 기댄다. 서명 생성은 테스트용을 빼면 제공하지 않는다.
 * @note 의도적으로 비상수시간이다. 검증은 공개 데이터만 다루므로 타이밍으로 새어 나갈
 *       비밀이 없다. 개인키 연산이 필요해지면 이 코드를 재사용하면 안 된다.
 * @invariant 키 제약은 ring의 RSA_*_2048_8192_*를 따르되 지수와 모듈러스 하한만 낮다.
 *            n은 선행 0이 없고 홀수, e는 3..=2^33-1의 홀수, 서명 길이는 모듈러스 길이와
 *            정확히 같다. 지수 3을 받는 것은 아직 널리 쓰이는 이전 루트 인증서 때문이고,
 *            그 안전은 verify_pkcs1 의 EM 전체 비교가 받친다.
 */

use std::cmp::Ordering;

/** @brief 받아들일 모듈러스 최대 비트. 림 배열 상한과 같다. */
pub const MAX_MODULUS_BITS: u32 = 8192;

/**
 * @brief 기본 모듈러스 하한. TLS 인증서 서명이 이것을 쓴다.
 *
 * @details 오늘의 공개 CA는 2048비트 미만을 발급하지 않는다.
 */
pub const MIN_MODULUS_BITS: u32 = 2048;

/**
 * @brief DNSSEC 검증에서 받아들일 모듈러스 하한.
 *
 * @details 지금도 org, nl을 비롯한 여러 영역이 1024비트 ZSK로 서명한다. 하한을 2048로
 *          두면 그 영역들의 서명이 전부 맞지 않는 것으로 나와, 정상 영역을 전부
 *          Bogus로 막는다. 검증기가 서명을 확인하지 못하는 것과 서명이 위조된 것은
 *          다른 일이므로, 여기서는 실제로 쓰이는 하한까지 받아들인다.
 * @warning 이 값을 올리면 그 크기로 서명하는 모든 영역이 해석되지 않는다. 서명 생성에는
 *          해당하지 않는다. 이 구현은 알고리즘 13으로만 서명한다.
 */
pub const MIN_MODULUS_BITS_DNSSEC: u32 = 1024;

/** @brief 서명에 쓰인 해시. DNSSEC/TLS가 실제로 쓰는 세 가지만 지원한다. */
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaHash {
    /** @brief SHA-256. */
    Sha256,
    /** @brief SHA-384. */
    Sha384,
    /** @brief SHA-512. */
    Sha512,
}

impl RsaHash {
    /** @brief 해시 출력 길이(바이트). */
    pub fn digest_len(self) -> usize {
        match self {
            RsaHash::Sha256 => 32,
            RsaHash::Sha384 => 48,
            RsaHash::Sha512 => 64,
        }
    }

    /** @brief 여러 조각을 이어 해싱한다. 중간 버퍼를 만들지 않으려는 형태다. */
    fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        use sha2::Digest as _;
        match self {
            RsaHash::Sha256 => {
                let mut h = sha2::Sha256::new();
                parts.iter().for_each(|p| h.update(p));
                h.finalize().to_vec()
            }
            RsaHash::Sha384 => {
                let mut h = sha2::Sha384::new();
                parts.iter().for_each(|p| h.update(p));
                h.finalize().to_vec()
            }
            RsaHash::Sha512 => {
                let mut h = sha2::Sha512::new();
                parts.iter().for_each(|p| h.update(p));
                h.finalize().to_vec()
            }
        }
    }

    /**
     * @brief 해시별 DigestInfo DER 접두사(PKCS#1 v1.5).
     * @details 미리 계산된 상수로 둔다. 검증 시 이 접두사로 기대값을 조립해 비교하고,
     *          서명에서 꺼낸 DER을 파싱하지 않는다. 파싱하면 같은 해시를 여러 인코딩으로
     *          표현하는 위조 여지가 생긴다.
     */
    fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            RsaHash::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            RsaHash::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            RsaHash::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }
}

/** @brief 검증 실패 사유. 키가 규격을 벗어난 것과 서명이 맞지 않는 것을 구분한다. */
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaError {
    /** @brief 키가 제약에 맞지 않는다. */
    BadKey,
    /** @brief 서명이 맞지 않는다. */
    BadSignature,
}

/**
 * @brief RSASSA-PKCS1-v1_5 서명을 검증한다.
 *
 * @details 서명을 공개 지수로 거듭제곱해 얻은 블록을, 기대 인코딩을 처음부터 조립한 것과
 *          전부 비교한다. DER을 되파싱하지 않는 것이 이 구현의 안전 핵심이다.
 * @param n 모듈러스 빅엔디언. 선행 0이 없어야 한다.
 * @param e 공개 지수 빅엔디언.
 * @return 일치하면 Ok. 어긋나면 BadSignature, 키가 규격 밖이면 BadKey.
 */
pub fn verify_pkcs1(
    hash: RsaHash,
    n: &[u8],
    e: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), RsaError> {
    verify_pkcs1_min_bits(hash, n, e, msg, sig, MIN_MODULUS_BITS)
}

/**
 * @brief 모듈러스 하한을 지정해 RSASSA-PKCS1-v1_5 서명을 검증한다.
 *
 * @param min_bits 받아들일 모듈러스 최소 비트. 기본 하한은 MIN_MODULUS_BITS이고,
 *                 DNSSEC 검증은 MIN_MODULUS_BITS_DNSSEC를 쓴다.
 */
pub fn verify_pkcs1_min_bits(
    hash: RsaHash,
    n: &[u8],
    e: &[u8],
    msg: &[u8],
    sig: &[u8],
    min_bits: u32,
) -> Result<(), RsaError> {
    let modulus = Modulus::parse(n, min_bits)?;
    let exponent = parse_exponent(e)?;
    let em = modulus.pow(sig, &exponent)?;
    let expected = emsa_pkcs1(hash, msg, modulus.bytes)?;
    if em == expected {
        Ok(())
    } else {
        Err(RsaError::BadSignature)
    }
}

/**
 * @brief RSASSA-PSS 서명을 검증한다(RFC 8017).
 *
 * @details 검사 순서: 선행 패딩이 0인지, 끝이 0xbc인지, 미사용 상위 비트가 0인지,
 *          MGF1로 마스크를 벗긴 뒤 0x00…0x01 구분자가 제자리인지, 마지막으로 salt로
 *          다시 만든 해시가 서명 안의 해시와 같은지.
 * @warning 중간 검사 하나라도 건너뛰면 위조 서명이 통과한다. 특히 미사용 비트 검사를
 *          빼면 같은 서명을 여러 형태로 표현할 수 있게 된다.
 */
pub fn verify_pss(
    hash: RsaHash,
    n: &[u8],
    e: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), RsaError> {
    let modulus = Modulus::parse(n, MIN_MODULUS_BITS)?;
    let exponent = parse_exponent(e)?;
    let em_full = modulus.pow(sig, &exponent)?;

    let hlen = hash.digest_len();
    let em_bits = modulus.bits as usize - 1;
    let em_len = em_bits.div_ceil(8);

    let skip = em_full.len() - em_len;
    if em_full[..skip].iter().any(|&b| b != 0) {
        return Err(RsaError::BadSignature);
    }
    let em = &em_full[skip..];
    if em_len < 2 * hlen + 2 || em[em_len - 1] != 0xbc {
        return Err(RsaError::BadSignature);
    }
    let db_len = em_len - hlen - 1;
    let (masked_db, rest) = em.split_at(db_len);
    let h = &rest[..hlen];
    let unused_bits = 8 * em_len - em_bits;
    if unused_bits > 0 && masked_db[0] >> (8 - unused_bits) != 0 {
        return Err(RsaError::BadSignature);
    }

    let db_mask = mgf1(hash, h, db_len);
    let mut db: Vec<u8> = masked_db
        .iter()
        .zip(db_mask.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    db[0] &= 0xff >> unused_bits;

    let ps_len = em_len - 2 * hlen - 2;
    if db[..ps_len].iter().any(|&b| b != 0) || db[ps_len] != 0x01 {
        return Err(RsaError::BadSignature);
    }
    let salt = &db[ps_len + 1..];
    let mhash = hash.digest(&[msg]);
    let expected_h = hash.digest(&[&[0u8; 8], &mhash, salt]);
    if expected_h == h {
        Ok(())
    } else {
        Err(RsaError::BadSignature)
    }
}

/**
 * @brief PKCS#1 v1.5 기대 인코딩 블록을 조립한다.
 * @details 0x00 0x01 0xff… 0x00 DigestInfo Hash 형태다. 패딩이 최소 8바이트는 되어야
 *          하므로 모듈러스가 t_len + 11보다 짧으면 거부한다.
 * @param k 모듈러스 길이(바이트). 결과 블록의 길이가 된다.
 */
fn emsa_pkcs1(hash: RsaHash, msg: &[u8], k: usize) -> Result<Vec<u8>, RsaError> {
    let prefix = hash.digest_info_prefix();
    let t_len = prefix.len() + hash.digest_len();
    if k < t_len + 11 {
        return Err(RsaError::BadSignature);
    }
    let mut em = vec![0xff; k];
    em[0] = 0x00;
    em[1] = 0x01;
    em[k - t_len - 1] = 0x00;
    em[k - t_len..k - hash.digest_len()].copy_from_slice(prefix);
    em[k - hash.digest_len()..].copy_from_slice(&hash.digest(&[msg]));
    Ok(em)
}

/** @brief MGF1 마스크 생성 함수(RFC 8017 B.2.1). 시드에 카운터를 붙여 해시를 이어 붙인다. */
fn mgf1(hash: RsaHash, seed: &[u8], mask_len: usize) -> Vec<u8> {
    let mut mask = Vec::with_capacity(mask_len + hash.digest_len());
    let mut counter = 0u32;
    while mask.len() < mask_len {
        mask.extend_from_slice(&hash.digest(&[seed, &counter.to_be_bytes()]));
        counter += 1;
    }
    mask.truncate(mask_len);
    mask
}

/**
 * @brief 공개 지수를 검사한다.
 * @details 3 이상 2^33-1 이하의 홀수만 받는다. 짝수는 유효한 RSA 지수가 아니고, 1은
 *          서명이 곧 원문이라 아무것도 증명하지 못한다.
 * @note 3 같은 작은 지수는 채우기를 느슨하게 보는 검증기에서 위조가 쉬워진다. 여기서는
 *       verify_pkcs1 이 EM을 최대 길이 채우기로 다시 만들어 전부 비교하므로, 채우기를
 *       줄이고 뒤에 값을 채워 넣는 그 경로가 없다.
 */
fn parse_exponent(e: &[u8]) -> Result<Vec<u8>, RsaError> {
    if e.is_empty() || e[0] == 0 || e.len() > 5 {
        return Err(RsaError::BadKey);
    }
    let value = e
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    if !(3..=(1u64 << 33) - 1).contains(&value) || value & 1 == 0 {
        return Err(RsaError::BadKey);
    }
    Ok(e.to_vec())
}

/**
 * @brief 림 배열의 고정 길이. 8192비트 = 128 × 64비트가 상한이다.
 * @note 고정 크기라 힙 할당이 없고, 키 크기 상한이 타입 자체에 고정된다.
 */
const MAX_LIMBS: usize = 128;

/**
 * @brief 몽고메리 연산에 필요한 형태로 전처리된 모듈러스.
 * @invariant n은 홀수이며 상위 k개 림만 유효하다. n0inv는 2^64 기준 -n^-1이다.
 */
struct Modulus {
    /** @brief 계수. */
    n: [u64; MAX_LIMBS],

    /** @brief 몽고메리 곱셈에 쓰는 값. */
    n0inv: u64,

    /** @brief 계수가 차지하는 자릿수. */
    k: usize,

    /** @brief 계수의 비트 수. */
    bits: u32,

    /** @brief 계수의 바이트 수. 서명 길이가 이것과 같아야 한다. */
    bytes: usize,
}

impl Modulus {
    /**
     * @brief 빅엔디언 모듈러스를 검사하고 전처리한다.
     * @details 선행 0 바이트를 거부한다. 같은 키를 여러 길이로 표현할 수 있으면 서명 길이
     *          검사가 무력해진다. 짝수 모듈러스는 몽고메리 역원이 존재하지 않아 거부한다.
     */
    fn parse(n: &[u8], min_bits: u32) -> Result<Self, RsaError> {
        let Some(&first) = n.first() else {
            return Err(RsaError::BadKey);
        };
        if first == 0 || n.last().is_none_or(|byte| byte & 1 == 0) {
            return Err(RsaError::BadKey);
        }
        let bits = (n.len() as u32 - 1) * 8 + (8 - first.leading_zeros());
        if !(min_bits..=MAX_MODULUS_BITS).contains(&bits) {
            return Err(RsaError::BadKey);
        }
        let k = n.len().div_ceil(8);
        let limbs = be_to_limbs(n);

        Ok(Modulus {
            n: limbs,
            n0inv: neg_inv64(limbs[0]),
            k,
            bits,
            bytes: n.len(),
        })
    }

    /**
     * @brief 모듈러 거듭제곱. 서명을 공개 지수로 올려 인코딩 블록을 되찾는다.
     *
     * @details 앞의 배가 반복이 밑을 몽고메리 영역으로 옮기고(2^(64k)를 곱하는 것과 같다),
     *          마지막에 1과 곱해 원래 영역으로 되돌린다. 지수 비트를 최상위부터 훑는
     *          제곱·곱셈 방식이다.
     * @warning 서명 길이가 모듈러스 길이와 다르거나 값이 모듈러스 이상이면 거부한다.
     *          이 검사를 빼면 같은 서명을 여러 표현으로 만들 수 있다.
     */
    fn pow(&self, base: &[u8], exp: &[u8]) -> Result<Vec<u8>, RsaError> {
        if base.len() != self.bytes {
            return Err(RsaError::BadSignature);
        }
        let mut base_m = be_to_limbs(base);
        if cmp(&base_m[..self.k], &self.n[..self.k]) != Ordering::Less {
            return Err(RsaError::BadSignature);
        }

        for _ in 0..(64 * self.k) {
            double_mod(&mut base_m[..self.k], &self.n[..self.k]);
        }

        let mut acc: Option<[u64; MAX_LIMBS]> = None;
        for &byte in exp {
            for shift in (0..8).rev() {
                let bit = byte >> shift & 1 == 1;
                acc = match acc {
                    Some(a) => {
                        let sq = self.mont_mul(&a, &a);
                        Some(if bit { self.mont_mul(&sq, &base_m) } else { sq })
                    }
                    None if bit => Some(base_m),
                    None => None,
                };
            }
        }
        let mut one = [0u64; MAX_LIMBS];
        one[0] = 1;
        let result = match acc {
            Some(a) => self.mont_mul(&a, &one),
            None => one,
        };
        let mut out = vec![0u8; self.bytes];
        limbs_to_be(&result, &mut out);
        Ok(out)
    }

    /**
     * @brief CIOS 방식 몽고메리 곱셈. a·b·R^-1 mod n을 구한다.
     * @details 곱셈과 약분을 한 바깥 루프에 엮어(Coarsely Integrated Operand Scanning)
     *          중간 결과를 두 배 길이로 가지고 있지 않는다.
     * @note 마지막의 조건부 뺄셈이 결과를 모듈러스 미만으로 되돌린다. 이 분기가 비상수시간
     *       요소지만, 검증은 공개 데이터만 다루므로 문제가 되지 않는다.
     */
    fn mont_mul(&self, a: &[u64; MAX_LIMBS], b: &[u64; MAX_LIMBS]) -> [u64; MAX_LIMBS] {
        let k = self.k;
        let n = &self.n;
        let mut t = [0u64; MAX_LIMBS + 2];
        for &a_limb in a.iter().take(k) {
            let ai = a_limb as u128;
            let mut carry = 0u128;
            for j in 0..k {
                let v = t[j] as u128 + ai * b[j] as u128 + carry;
                t[j] = v as u64;
                carry = v >> 64;
            }
            let v = t[k] as u128 + carry;
            t[k] = v as u64;
            t[k + 1] = (v >> 64) as u64;

            let m = t[0].wrapping_mul(self.n0inv) as u128;
            let mut carry = (t[0] as u128 + m * n[0] as u128) >> 64;
            for j in 1..k {
                let v = t[j] as u128 + m * n[j] as u128 + carry;
                t[j - 1] = v as u64;
                carry = v >> 64;
            }
            let v = t[k] as u128 + carry;
            t[k - 1] = v as u64;
            t[k] = t[k + 1] + ((v >> 64) as u64);
        }
        let mut out = [0u64; MAX_LIMBS];
        out[..k].copy_from_slice(&t[..k]);
        if t[k] != 0 || cmp(&out[..k], &n[..k]) != Ordering::Less {
            sub_in_place(&mut out[..k], &n[..k]);
        }
        out
    }
}

/** @brief 빅엔디언 바이트열을 리틀엔디언 64비트 림 배열로 옮긴다. */
fn be_to_limbs(bytes: &[u8]) -> [u64; MAX_LIMBS] {
    let mut limbs = [0u64; MAX_LIMBS];
    for (i, &byte) in bytes.iter().rev().enumerate() {
        limbs[i / 8] |= u64::from(byte) << (8 * (i % 8));
    }
    limbs
}

/** @brief 림 배열을 빅엔디언 바이트열로 되돌린다. out 길이만큼만 쓴다. */
fn limbs_to_be(limbs: &[u64; MAX_LIMBS], out: &mut [u8]) {
    let len = out.len();
    for i in 0..len {
        out[len - 1 - i] = (limbs[i / 8] >> (8 * (i % 8))) as u8;
    }
}

/** @brief 같은 길이의 두 다중정밀 수를 비교한다. 최상위 림부터 본다. */
fn cmp(a: &[u64], b: &[u64]) -> Ordering {
    for i in (0..a.len()).rev() {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

/** @brief a -= b. 빌림을 전파하며 위치별로 뺀다. a >= b를 전제한다. */
fn sub_in_place(a: &mut [u64], b: &[u64]) {
    let mut borrow = 0u64;
    for (x, &y) in a.iter_mut().zip(b.iter()) {
        let (d1, b1) = x.overflowing_sub(y);
        let (d2, b2) = d1.overflowing_sub(borrow);
        *x = d2;
        borrow = u64::from(b1 | b2);
    }
}

/**
 * @brief t = 2t mod n. 밑을 몽고메리 영역으로 옮길 때 반복 호출한다.
 * @details 최상위에서 넘친 비트도 함께 본다. 그것을 무시하면 2n에 근접한 값에서 결과가 틀어진다.
 */
fn double_mod(t: &mut [u64], n: &[u64]) {
    let mut carry = 0u64;
    for limb in t.iter_mut() {
        let next = *limb >> 63;
        *limb = (*limb << 1) | carry;
        carry = next;
    }
    if carry != 0 || cmp(t, n) != Ordering::Less {
        sub_in_place(t, n);
    }
}

/**
 * @brief 2^64를 법으로 하는 -n0^-1. 몽고메리 약분의 계수다.
 * @details 뉴턴 반복이 매 회 정확 비트 수를 배로 늘린다. 홀수의 역원은 1비트에서 시작하므로
 *          5회면 64비트를 넘긴다. n0이 홀수라는 전제에 기댄다.
 */
fn neg_inv64(n0: u64) -> u64 {
    let mut x = n0;
    for _ in 0..5 {
        x = x.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(x)));
    }
    x.wrapping_neg()
}

/**
 * @brief 테스트 전용 RSA 서명기.
 *
 * @warning 비상수시간이며 개인키를 다룬다. 운영 경로에서 절대 쓰지 않는다.
 *          DNSSEC/TLS 테스트가 검증할 서명을 만들려면 서명 쪽 구현이 필요해서 두었을 뿐이며,
 *          rsa-test-sign 기능으로만 노출된다.
 */
#[cfg(any(test, feature = "rsa-test-sign"))]
pub mod testsign {
    use super::{emsa_pkcs1, mgf1, Modulus, RsaHash, MIN_MODULUS_BITS};

    /** @brief 테스트용 RSA 키 쌍. */
    pub struct TestRsaKey {
        /** @brief 계수. */
        pub n: Vec<u8>,
        /** @brief 공개 지수. */
        pub e: Vec<u8>,
        /** @brief 비밀 지수. 테스트에서만 쓴다. */
        d: Vec<u8>,
    }

    impl TestRsaKey {
        /** @brief 모듈러스·공개 지수·개인 지수로 키를 만든다. */
        pub fn from_components(n: Vec<u8>, e: Vec<u8>, d: Vec<u8>) -> Self {
            TestRsaKey { n, e, d }
        }

        /**
         * @brief PKCS#8 DER에서 키를 읽는다.
         * @note 테스트 픽스처만 읽으므로 검사가 최소한이다. 신뢰할 수 없는 입력에 쓰지 않는다.
         */
        pub fn from_pkcs8(der: &[u8]) -> Option<Self> {
            let (body, rest) = read_tlv(der, 0x30)?;
            if !rest.is_empty() {
                return None;
            }
            let (version, body) = read_tlv(body, 0x02)?;
            if version != [0] {
                return None;
            }
            let (_alg, body) = read_tlv(body, 0x30)?;
            let (keys, _) = read_tlv(body, 0x04)?;
            let (rsa, rest) = read_tlv(keys, 0x30)?;
            if !rest.is_empty() {
                return None;
            }
            let (version, rsa) = read_tlv(rsa, 0x02)?;
            if version != [0] {
                return None;
            }
            let (n, rsa) = read_tlv(rsa, 0x02)?;
            let (e, rsa) = read_tlv(rsa, 0x02)?;
            let (d, _) = read_tlv(rsa, 0x02)?;
            Some(TestRsaKey {
                n: strip_leading_zero(n).to_vec(),
                e: strip_leading_zero(e).to_vec(),
                d: strip_leading_zero(d).to_vec(),
            })
        }

        /** @brief 모듈러스 길이(바이트). 서명 길이와 같다. */
        pub fn modulus_len(&self) -> usize {
            self.n.len()
        }

        /** @brief RSAPublicKey DER. 검증 쪽에 넘길 공개키를 만든다. */
        pub fn public_key_der(&self) -> Vec<u8> {
            let mut body = der_integer(&self.n);
            body.extend_from_slice(&der_integer(&self.e));
            let mut out = vec![0x30];
            out.extend_from_slice(&der_len(body.len()));
            out.extend_from_slice(&body);
            out
        }

        /** @brief PKCS#1 v1.5 서명을 만든다. 테스트 전용이다. */
        pub fn sign_pkcs1(&self, hash: RsaHash, msg: &[u8]) -> Vec<u8> {
            let em = emsa_pkcs1(hash, msg, self.n.len())
                .expect("RSA public key modulus is shorter than the minimum size");
            self.raw_sign(&em)
        }

        /**
         * @brief PSS 서명을 만든다. 테스트 전용이다.
         * @param salt 해시와 같은 길이여야 한다. 검증 쪽이 이 길이를 전제로 복원한다.
         */
        pub fn sign_pss(&self, hash: RsaHash, msg: &[u8], salt: &[u8]) -> Vec<u8> {
            let hlen = hash.digest_len();
            assert_eq!(salt.len(), hlen, "PSS salt must match the hash length");
            let modulus = Modulus::parse(&self.n, MIN_MODULUS_BITS).expect("Invalid test key");
            let em_bits = modulus.bits as usize - 1;
            let em_len = em_bits.div_ceil(8);
            assert!(
                em_len >= 2 * hlen + 2,
                "RSA public key modulus is shorter than the minimum size"
            );

            let mhash = hash.digest(&[msg]);
            let h = hash.digest(&[&[0u8; 8], &mhash, salt]);
            let ps_len = em_len - 2 * hlen - 2;
            let mut db = vec![0u8; ps_len];
            db.push(0x01);
            db.extend_from_slice(salt);
            let mask = mgf1(hash, &h, db.len());
            for (b, m) in db.iter_mut().zip(mask.iter()) {
                *b ^= m;
            }
            db[0] &= 0xff >> (8 * em_len - em_bits);

            let mut em = vec![0u8; self.n.len() - em_len];
            em.extend_from_slice(&db);
            em.extend_from_slice(&h);
            em.push(0xbc);
            self.raw_sign(&em)
        }

        /** @brief 인코딩 블록을 개인 지수로 올린다. 상수시간이 아니다. */
        fn raw_sign(&self, em: &[u8]) -> Vec<u8> {
            let modulus = Modulus::parse(&self.n, MIN_MODULUS_BITS).expect("Invalid test key");
            modulus
                .pow(em, &self.d)
                .expect("EM is outside the modulus range")
        }
    }

    /** @brief 기대한 태그의 DER TLV 하나를 읽는다. 내용과 나머지를 돌려준다. */
    fn read_tlv(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
        let (&t, rest) = input.split_first()?;
        if t != tag {
            return None;
        }
        let (&l, rest) = rest.split_first()?;
        let (len, rest) = match l {
            0x81 => {
                let (&l1, rest) = rest.split_first()?;
                (usize::from(l1), rest)
            }
            0x82 => {
                let (l2, rest) = rest.split_at_checked(2)?;
                (usize::from(u16::from_be_bytes([l2[0], l2[1]])), rest)
            }
            short if short < 0x80 => (usize::from(short), rest),
            _ => return None,
        };
        let (value, rest) = rest.split_at_checked(len)?;
        Some((value, rest))
    }

    /** @brief DER INTEGER의 부호용 선행 0을 떼어 낸다. RSA 값은 언제나 양수다. */
    fn strip_leading_zero(v: &[u8]) -> &[u8] {
        v.strip_prefix(&[0]).unwrap_or(v)
    }

    /** @brief 값을 DER INTEGER로 감싼다. 최상위 비트가 서면 음수로 읽히지 않게 0을 덧댄다. */
    fn der_integer(v: &[u8]) -> Vec<u8> {
        let sign_pad = usize::from(v.first().is_some_and(|&b| b & 0x80 != 0));
        let mut out = vec![0x02];
        out.extend_from_slice(&der_len(v.len() + sign_pad));
        if sign_pad == 1 {
            out.push(0x00);
        }
        out.extend_from_slice(v);
        out
    }

    /** @brief DER 길이 필드를 인코딩한다. 짧은 형식과 1·2바이트 긴 형식만 다룬다. */
    fn der_len(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else if len < 0x100 {
            vec![0x81, len as u8]
        } else {
            vec![0x82, (len >> 8) as u8, len as u8]
        }
    }
}

#[cfg(test)]
/** @brief 알려진 답과 맞는지, 그리고 키와 서명의 제약을 실제로 거절하는지. */
mod tests {
    use super::testsign::TestRsaKey;
    use super::*;

    /** @brief 16진 문자열을 바이트열로. */
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /** @brief base64 디코딩. */
    fn b64_decode(input: &str) -> Vec<u8> {
        /** @brief base64 문자표. */
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        let mut acc = 0u32;
        let mut bits = 0u32;
        for &c in input.as_bytes() {
            if c == b'=' || c.is_ascii_whitespace() {
                continue;
            }
            let v = ALPHABET.iter().position(|&a| a == c).unwrap() as u32;
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        out
    }

    /** @brief 테스트용 2048비트 키. */
    fn test_key_2048() -> TestRsaKey {
        let der = b64_decode(include_str!(
            "../../../testdata/rsa_test_private_key_2048.pk8.b64"
        ));
        TestRsaKey::from_pkcs8(&der).unwrap()
    }

    /** @brief 알려진 답 테스트에 쓰는 메시지. */
    const KAT_MSG: &[u8] = b"onetdns rsa kat v1";
    /** @brief 알려진 답 테스트의 계수. */
    const KAT_N: &str = "c8a78500a5a250db8ed36c85b8dcf83c4be1953114faaac7616e0ea24922fa6b7ab01f85582c815cc3bdeb5ed46762bc536accaa8b72705b00cef316b2ec508fb9697241b9e34238419cccf7339eeb8b062147af4f5932f613d9bc0ae70bf6d56d4432e83e13767587531bfa9dd56531741244be75e8bc9226b9fa44b4b8a101358d7e8bb75d0c724a4f11ece77776263faefe79612eb1d71646e77e8982866be1400eafc3580d3139b41aaa7380187372f22e35bd55b288496165c881ed154d5811245c52d56cc09d4916d4f2a50bcf5ae0a2637f4cfa6bf9daafc113dba8383b6dd7da6dd8db22d8510a8d3115983308909a1a0332517aa55e896e154249b3";
    /** @brief 알려진 답 테스트의 공개 지수. */
    const KAT_E: &str = "010001";
    /** @brief 알려진 답: 이전 채우기, SHA-256. */
    const KAT_PKCS1_SHA256: &str = "2c623f434952f0f4d0cbd9fb7d44d2c487e485d0caa0b2cd34eeb2de1b0e8f961651724da18bb0dae8c873f302a913322f57c86033a0ff00a1ae2664e1129a2f4a10757f068d26d8baeca83bd6fd9631a19b80756c168843b451026f8833a84a0cc0a3cdaf81b1888fb5a45909e8d4382fb7bb25e797bbe6f6273502bdfd560cdce7bc4a357c0068478275366db58315654cf4e1ac7a7733b3725a46c580586fa14f42a13253c554447087f584014e3869b638a826b1daa69083217071090b10cd15478b622a51b31c01b39ffdcde5ca1664cec0e9126d6c0f7c318c449a204b92dd06dd0232c56c5a8063dc20be3fe8dc34ef829bb5b36d173610b344f13a8b";
    /** @brief 알려진 답: 이전 채우기, SHA-384. */
    const KAT_PKCS1_SHA384: &str = "950067c5828987d69463d4315ed59130e6784a69076fc75b280a61ca4500a6f905d15cae1ed012f4b47121cd8a0a4b1d3f9dd328e2624972fc29158e98ccad81a01f8e20014b8a1dc6df8bd24f7900f75fc2f5ebef83ec53a386b0653f1b244f4853226804440edc4605087a5009935aa46552a3e175e9af8605d6dfc57e6cc0242af64735c29503ed7935b8b09d9edb2ce28ba821c473bd731989a0bd46429d4bba7d3b88ee2de717e62a734fda8d8e62cb5acb28b518b19ce756f0808d9ede19b2a99d80595fc3c562a5b1c86d42037fca2198b47fd7a9f7ba68c5e82d46592cb2bb023950c36dc41bded73b0fdc761f33bd8f548f98e39727a7d08e2ab6ac";
    /** @brief 알려진 답: 이전 채우기, SHA-512. */
    const KAT_PKCS1_SHA512: &str = "2ed35b506b5be94a68ea78c110e733152750ce2e6424c673132b274d0fc362476ed068aa33569cb58838f9d3527ad36ada0bdb9c1493108c1cf10648247ceeaaaf0d78e9f290cfb03fde8e8f4726522c3293690fa97ee4c4d0622fc4fb046a5caeae60d473df9b632d2efc7a540471aa98af503eb1ec3ac1d82c8524eb088f9ac316746df12493eaa898f00b117b5045d2c7aac2551df8fa410125f2fb8a2a3c78dc38480358aa686bf5bd02050a8bb36f6e52a73fe10e4d378215cd709907ed82a939d972a97a9d36525b5c50b1c070fd177dee8e3b07e84242c0922a43572ae0a79c1e82e869b97d51ed601b259ce2b3fc253db16b8416c57d8afdecd317c9";
    /** @brief 알려진 답: 무작위 채우기, SHA-256. */
    const KAT_PSS_SHA256: &str = "54c04293bee87677b93e4068a8bdeaea8d2abddd8bb22f84da17542e3b9670795bdecce05644c903bacf4cf08b765fe3474d02073811f83aa0c800184ee0de6290bcc3250080a45b29973b99d93cd754e8859cea14d59d155416a18c6432006a972280c62bebf6d5a2e257acacd66740d7361c45cce51590c57949160f9e32d1e3bae7cee9158913959e43ae2dd3866e40d0517d0584a79e09126334686dc0ff0d6b91812e75cf89a1ff607bad189d676fa42019e411c3df81456ce1d4cd4e301b38dd47835b96922ecb9fdee8c668ba3a61fff6c789cd6b3f664919af62863f1ae37a6c2da06e632c2499a43559a466caa0251e31a9de88888d709fbf5944d1";
    /** @brief 알려진 답: 무작위 채우기, SHA-384. */
    const KAT_PSS_SHA384: &str = "765f1af9fd1877d06b444ddd422d5ec004d224b25d290db8cfd980c0b09064d9bd215a26448cfbc47a22f93dbcf5c723bed9a7dbd7c3da2c805a413cb9855b94b31ba527b67d5033b988986a4731036acfaedd3f05dba43c7ab69f0c1438b0bed913240f4466aadc5135b9eb91a1f2c82c3a0b80bcb12656962fed2aedca2db54da3d0ef5af78e1fe03a5182d427af6ffe6afc394000b3920c6615d29fbb184505f1f61eaa6b7895c2e5183f4625ec43160b975672b2103b9378395e04fd975a8b1e2f034b513f0af07592df12da89498d90a619e08e1368ac80bbda74858ad41b3d3ed998673f9765002aac57c07f33d92777561e4830a318941d62bf5dec36";
    /** @brief 알려진 답: 무작위 채우기, SHA-512. */
    const KAT_PSS_SHA512: &str = "a1c907448bdf48924d866349df473086c921557892b0e4178ce29be171d090cf4af2c08e56b95c9236aed0486c109b1b95a4f47c6fde1aaf52ade79649158b55f534fa4f9a296aed5e0c1adb70da6040e5142fc9000945d14574c3e68063a46d1b1b4aead64f7063141fd2b5cbaf4be96bbfa5a0b47f78104b17c75accd76d92c7a9b4514ca60615ae87053bf21ef5772a193b1d81a76967f638b8ef4bf73262853a93f04721c11e5f4c147fa39a7793514ea82649907df0aa029d13f33b3861479d043beb20cc3046da86d2525bccc575ca37c062bb00c1719f607cee9fcd020eb3b838ba1ae74ca5e2b4eb76595f5acad3a7ca3841860c01ab732d63d6e3b1";

    #[test]
    /** @brief 이전 채우기 방식이 알려진 답과 맞는지. */
    fn ring_kat_pkcs1() {
        let n = unhex(KAT_N);
        let e = unhex(KAT_E);
        let cases = [
            (RsaHash::Sha256, KAT_PKCS1_SHA256),
            (RsaHash::Sha384, KAT_PKCS1_SHA384),
            (RsaHash::Sha512, KAT_PKCS1_SHA512),
        ];
        for (hash, sig_hex) in cases {
            let mut sig = unhex(sig_hex);
            assert_eq!(
                verify_pkcs1(hash, &n, &e, KAT_MSG, &sig),
                Ok(()),
                "{hash:?}"
            );
            sig[0] ^= 0xff;
            assert_eq!(
                verify_pkcs1(hash, &n, &e, KAT_MSG, &sig),
                Err(RsaError::BadSignature),
                "{hash:?} tamper"
            );
            sig[0] ^= 0xff;
            assert_eq!(
                verify_pkcs1(hash, &n, &e, b"other message", &sig),
                Err(RsaError::BadSignature),
                "{hash:?} wrong msg"
            );
        }
    }

    #[test]
    /** @brief 무작위 채우기 방식이 알려진 답과 맞는지. */
    fn ring_kat_pss() {
        let n = unhex(KAT_N);
        let e = unhex(KAT_E);
        let cases = [
            (RsaHash::Sha256, KAT_PSS_SHA256),
            (RsaHash::Sha384, KAT_PSS_SHA384),
            (RsaHash::Sha512, KAT_PSS_SHA512),
        ];
        for (hash, sig_hex) in cases {
            let mut sig = unhex(sig_hex);
            assert_eq!(verify_pss(hash, &n, &e, KAT_MSG, &sig), Ok(()), "{hash:?}");
            let last = sig.len() - 1;
            sig[last] ^= 0xff;
            assert_eq!(
                verify_pss(hash, &n, &e, KAT_MSG, &sig),
                Err(RsaError::BadSignature),
                "{hash:?} tamper"
            );
            sig[last] ^= 0xff;
            assert_eq!(
                verify_pss(hash, &n, &e, b"other message", &sig),
                Err(RsaError::BadSignature),
                "{hash:?} wrong msg"
            );
        }
    }

    #[test]
    /** @brief 요약 방식이나 채우기가 다르면 거절하는지. 받아들이면 서명을 교체할 수 있다. */
    fn wrong_hash_and_wrong_padding_rejected() {
        let n = unhex(KAT_N);
        let e = unhex(KAT_E);
        let sig = unhex(KAT_PKCS1_SHA256);
        assert_eq!(
            verify_pkcs1(RsaHash::Sha384, &n, &e, KAT_MSG, &sig),
            Err(RsaError::BadSignature)
        );
        assert_eq!(
            verify_pss(RsaHash::Sha256, &n, &e, KAT_MSG, &sig),
            Err(RsaError::BadSignature)
        );
        let pss = unhex(KAT_PSS_SHA256);
        assert_eq!(
            verify_pkcs1(RsaHash::Sha256, &n, &e, KAT_MSG, &pss),
            Err(RsaError::BadSignature)
        );
    }

    /** @brief 지수 3 테스트 벡터가 덮는 원문. */
    const E3_MSG: &[u8] = b"onetdns e3 vector";
    /** @brief 지수 3 테스트 벡터의 계수. */
    const E3_N: &str = "b7d295f19268575d17d1f92b6c4df32054ffd157ea9a19177ea2e98627b12aa13771910be1ee59becc448dc4adcd727b81a48498e748d45808d88200f0a6014301465b16d3816dc2e978d3a0f4277c32b4038a1f3bc9d72d00a10e127ad99f2546fb61df302737c06b99029c5cbbb0ba7a1d622d38e3641a60428e33262ebbcb3343aa176d69bdfe2be51be415c278c2304cce8b369c4c8fc58883eb646e6ee11cbcde330c978d9d6f8844e500f64cd7d84a5cdf3b5b569c121c6233197978992ff584e546c388819f562e61afb3b6d0e0d61f39cdd04fcdb0612db579f241bfd2b9f8f54058abc0cc33947aa4a9b178b36d401b9ece84093824a16efe9aeb6b";
    /** @brief 그 키로 제대로 만든 이전 채우기 SHA-256 서명. */
    const E3_SIG: &str = "0f4738b29e1f4f5ad4cb33483567b3067d9a01ef2285ef58f2ce75367810d2cd99f9906a72b4a11217c543dc62a6ea9cb93b0489f681164899aa83b1d978e1275a85a32a1ad5e71ba5c94250d87a1cf5e85b01a3383901dbf732601fa616e96d9670a19664ed97368e1a1d598a9a1d55e999c960e265e88b8336a217125e89a2a5e472ce0b0cae3a275f3305f27a4b919f61f30aa32a20ed9866eafff41500514d39d39b5e1eb200ad1fcf56ab50b68a715ffde4ce638a96a62c21e6a51e1be43e135715c75bbe337439a156a8c142ad59397861896fc2948353742cf15ce9f7dc5c32923d8e7b14005994f7448afba77cea7db31f2388b269ec3107eca0b93f";
    /** @brief 채우기를 여덟 바이트로 줄이고 뒤를 값으로 채운 EM의 세제곱근. 개인키 없이 만든다. */
    const E3_FORGED: &str = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000032cbfd4a7adc7905583d767520f51640759176d37826f2ef63ae3dc7a7d1bdf411de33ccbee7a5eaa0a2d7274fc50fc0a2fcd1cb50711c4748a1961c0be8a1436a98f1dc47abdf4a9dac502c659be511bbc4559a9b";

    #[test]
    /**
     * @brief 지수 3 키를 받되 작은 지수 위조는 막는지.
     *
     * @details 위조 서명을 세제곱하면 00 01 FF..FF 00 DigestInfo 까지는 규격 모양이고 그
     *          뒤가 값으로 채워져 있다. 채우기 길이를 보지 않거나 DigestInfo 만 떼어 보는
     *          검증기는 이것을 통과시킨다. 이 구현은 EM 전체를 다시 만들어 비교하므로 걸린다.
     * @warning 이 테스트가 지수 하한을 3으로 내린 근거다. 지수 검사를 손대면 여기부터 본다.
     */
    fn exponent_three_accepted_but_small_exponent_forgery_rejected() {
        let n = unhex(E3_N);
        let e = [3u8];

        // 이 벡터가 진짜 위조 시도인지부터 확인한다. 세제곱한 값이 규격 앞부분과
        // DigestInfo 를 그대로 담고 있어야 느슨한 검증기가 통과시킬 서명이 된다.
        let forged_em = Modulus::parse(&n, MIN_MODULUS_BITS)
            .unwrap()
            .pow(&unhex(E3_FORGED), &e)
            .unwrap();
        assert_eq!(
            &forged_em[..11],
            &[0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00]
        );
        assert!(forged_em[11..].starts_with(&unhex("3031300d060960864801650304020105000420")));
        assert!(forged_em[11 + 19..].starts_with(&RsaHash::Sha256.digest(&[E3_MSG])));

        assert_eq!(
            verify_pkcs1(RsaHash::Sha256, &n, &e, E3_MSG, &unhex(E3_SIG)),
            Ok(())
        );
        assert_eq!(
            verify_pkcs1(RsaHash::Sha256, &n, &e, E3_MSG, &unhex(E3_FORGED)),
            Err(RsaError::BadSignature)
        );
    }

    #[test]
    /** @brief 너무 작거나 형태가 어긋난 키를 거절하는지. */
    fn key_constraints_enforced() {
        let n = unhex(KAT_N);
        let e = unhex(KAT_E);
        let sig = unhex(KAT_PKCS1_SHA256);

        let verify = |n: &[u8], e: &[u8], sig: &[u8]| {
            let pkcs1 = verify_pkcs1(RsaHash::Sha256, n, e, KAT_MSG, sig);
            let pss = verify_pss(RsaHash::Sha256, n, e, KAT_MSG, sig);
            assert_eq!(pkcs1, pss, "두 검증 경로의 키 판정이 갈렸습니다");
            pkcs1
        };

        // 지수 3은 키로는 받는다. 이 서명은 다른 지수로 만든 것이라 서명에서 걸린다.
        assert_eq!(verify(&n, &[3], &sig), Err(RsaError::BadSignature));
        assert_eq!(verify(&n, &[1], &sig), Err(RsaError::BadKey));
        assert_eq!(verify(&n, &[1, 0, 0], &sig), Err(RsaError::BadKey));
        assert_eq!(verify(&n, &[0, 1, 0, 1], &sig), Err(RsaError::BadKey));
        assert_eq!(verify(&n, &[2, 0, 0, 0, 0, 1], &sig), Err(RsaError::BadKey));
        assert_eq!(verify(&n, &[], &sig), Err(RsaError::BadKey));

        let mut padded = vec![0u8];
        padded.extend_from_slice(&n);
        assert_eq!(verify(&padded, &e, &sig), Err(RsaError::BadKey));
        let mut even = n.clone();
        *even.last_mut().unwrap() &= 0xfe;
        assert_eq!(verify(&even, &e, &sig), Err(RsaError::BadKey));
        let mut short = vec![0xffu8; 255];
        *short.last_mut().unwrap() |= 1;
        assert_eq!(verify(&short, &e, &sig), Err(RsaError::BadKey));
        let mut huge = vec![0xffu8; 1025];
        *huge.last_mut().unwrap() |= 1;
        assert_eq!(verify(&huge, &e, &sig), Err(RsaError::BadKey));
    }

    #[test]
    /** @brief 서명 길이가 계수와 같아야 하는지. 다르면 받아들이지 않는다. */
    fn signature_range_enforced() {
        let n = unhex(KAT_N);
        let e = unhex(KAT_E);
        let sig = unhex(KAT_PKCS1_SHA256);

        let verify = |sig: &[u8]| {
            let pkcs1 = verify_pkcs1(RsaHash::Sha256, &n, &e, KAT_MSG, sig);
            let pss = verify_pss(RsaHash::Sha256, &n, &e, KAT_MSG, sig);
            assert_eq!(pkcs1, pss, "두 검증 경로의 서명 범위 판정이 갈렸습니다");
            pkcs1
        };

        assert_eq!(verify(&sig[..255]), Err(RsaError::BadSignature));
        let mut long = sig.clone();
        long.push(0);
        assert_eq!(verify(&long), Err(RsaError::BadSignature));

        assert_eq!(verify(&n), Err(RsaError::BadSignature));
        assert_eq!(verify(&vec![0xffu8; 256]), Err(RsaError::BadSignature));
    }

    #[test]
    /** @brief 테스트용 서명기로 서명한 것을 검증할 수 있는지. */
    fn testsign_roundtrip_2048() {
        let key = test_key_2048();
        assert_eq!(key.n, unhex(KAT_N));
        assert_eq!(key.e, unhex(KAT_E));

        let msg = b"roundtrip message";
        for hash in [RsaHash::Sha256, RsaHash::Sha384, RsaHash::Sha512] {
            let sig = key.sign_pkcs1(hash, msg);
            assert_eq!(
                verify_pkcs1(hash, &key.n, &key.e, msg, &sig),
                Ok(()),
                "{hash:?}"
            );

            let salt: Vec<u8> = (0..hash.digest_len() as u8).collect();
            let sig = key.sign_pss(hash, msg, &salt);
            assert_eq!(
                verify_pss(hash, &key.n, &key.e, msg, &sig),
                Ok(()),
                "{hash:?} pss"
            );
        }
    }

    /** @brief 다른 구현으로 만든 테스트 자료의 계수. */
    const DOTNET_N: &str = "d5fe562f4d7ffcc2e4cb587780ffb55d9930e78bf2b86791a849ee939a464c23b85f1f27d8f2b0f64245150a32a3e5303c107aecd6d3a0e69e20c27e20280466020c18eb54dc0e15d311b8588d0b55cb167e534202dcecf8dec60545c7b08b363546b724f9c0eda50cffa85521f0297586f08e68987745c23336ad692a066e0f0677e2240b2d169f42894e6bc393e3d1f6fbc881928d677352288de86cdf0ace92bed555bb6ba5f861cf82417fc214c8111ca10c4d3326ba03b6965406d11306b6d3d030774cd209ddc165054fcaacfa12c36e27a3313fe49ef63d73c603bbd2e51a368d9984194deecb04af8a2024ea854138ed6c093f6029c6fd785924b5a0eeb38eecb08341ba30dd90a23d028144087789bf2b6da75831c23e472ae7e3eaed77dda4122ce4920abfbb3c463b8b0fbdd02070d16e5b76d69fed28d408eab02599548a6206068d538924273513374f1986c7401409f5cce40f50f7657fc766ba205a40f58886a4978d5aad34b43eecf5b6b4126c7680b0a4523f5765f2c5ea8211398e94ac123d17acc9b4d61d8620a3a49d06ddfbef49671feac8088a396ca2094238cd466ebd6852353e25ce8c5b8d1236db247bfc87c9eec1f462aecb232cedf85e0b5b3e2666ebf19426f466bad2ff4895d5a062f3580b2ed6a74ed87314dfeaeebde2dd57227aaf2b204d1c732be85fd6bc56b5b4cc8b2b5b932b1d4d";
    /** @brief 다른 구현으로 만든 테스트 자료의 비밀 지수. */
    const DOTNET_D: &str = "0d69dfe51f2a82a184cdea41b36853ea060c36b76303841a713e1122576d48a0849211d5e19774d83ad731b66dee301391f046844a0301f6f2ba82f67cf585310fb7ca6815eda54460f29f678d8fc454f298008806bdea6cbf2a1272894ddbac0e32dc9008c7bb1db96edd12590a40cf0922530ae363b68fb1be1fa893e5cb484dd37ded5c75fb11088eaac7be7eaaad229a2dbb51806397aaf2b7d275e09540d599f8ad630e205d2d646079d2944bd12ea168c6e89fe83188c20d323f2b23d22beba30526b53e05384d4313ce289a2722bdf54daec10b8c3d1a9a4783860063fbd064d30368705d9e364398ed438e8cd4c57dd80409a05b5ac30a685cce1c4458d71f55bd2bebf246aca7475b4b5ed9681f2ec3ea4635224e300b13b214d34d48421cfc5f34a10f6d6957a06b1000f14b7c04cda9c8045edba1a7d978dddbe65929ab599d3b1488a6401d03001378856ad4c77bac228eea644672bb08f86420ef64a28f99ffd76b643257cd12d8075f64e70e230dc741c26500109552fe7320ce4745917841079f5ff7508112d2e59c0b85bbd40cfe8f4c8e5b736148213e200faed4bed7417d3ee074bb41c0988b03a14c1f1612f4984fdac28bfd739b92eb1336d8cbe264ee9e6e6bdf3b0a4a97abbb59324f2ce3e507604d2b50c9b9e866749b3d682d798d9e5c706473eceb04d5f7d1fb66b7e4c261914f9aa016eba7d1";
    /** @brief 다른 구현이 만든 서명: 이전 채우기. */
    const DOTNET_PKCS1_SHA256: &str = "112b264f61c49b9edd6a26710cd2f2fce6c050597378cb4d4c8d6ba730ea467c7c32de672876caa539272a89fa55b67bf951725be07ecbb5de97a2ad6b128adfd0580e926e4affb5bf74c82338e26301eef2f5e5fea06c76e2a09523a48cd34e7afdc7280c0aadc1ddbc82b2453940914c6cf05907c94a34ea1a90d17c6569901e4e5e3bc8c9e73f475118241b9172b042f18f7b86a71861fbe4e1349c4d0230faf8bcb8cedddab6e5cbe34cdf35e7fa4ed3cb7b46adbe2a9e206ee93fc396e82691f661c9e554764fd298cfcec035c3ac008c3b11aeb8653dece2a74912beaee47a16fc56dad42f1adca177bf4c4f5724faa94c28dd1a3b84564c66c24405519d1a026ab5e4b20afe6ea9c4d2ba8ac020dffa1cb9cec4d63cbb62a1f53b2540d34f9923e103ab0eff38042e52aaeac5b83d1e22c0ade4368e1dc45bf36957f921aab49d502a492929ce466e5d9c9ba32244e1c9dda1c97cfc2884fc05b9c0b167261bdacc1f95409f58757ca44d621bd6814d574ec2c9004a753c00e0881c08ec203d01214c29ecd029dc8a957f4a5111c9f8a0ab2864dc26d967dfe3578a89bf439a3616294163a14b082cd1cdf6736406370c92af00ee86ce24aaba2c16172770ee82a2b7e5f6686d08fcb2abc79507442c9a874597506904b7dd711ad108cf9251e099bc845be7bab69b9395043948fe30654b8659701fc4af2c53b69db4";
    /** @brief 다른 구현이 만든 서명: 무작위 채우기. */
    const DOTNET_PSS_SHA512: &str = "55d2ccdc5f5e3582ed29ec7d71ce416fb92f081a49c704f9e94c0cbc90eaf2246d5f190ea29411f6f579655c1c6ef3160cd52e6ba30332fe75434f0b29df00e29d11ffae58659a632bded89da0559301787b12c49308778d26829803f9abd7675e6d0b6690c92ed8f89fc647afb0e1c8fe7dacf5992b07a585621f6ce540bdb9aee231b80b59edacb1aed89aa33cbceffcee6fbefadf19a274d7b4774f9bc6fc651e8eea07564a0a2c905806637c4c83c30012d46fc91391cb2974d942b25d87347dc66c64ba3d66587974c9bdffa1c97175a4073ac6131e980fc8ba31bdb69c46737a6cf6c778bd44a58d8e178a88970d5249e5a9b27e8a2730488c2615fcbd333aedfc58d87924b73fa51bebce5a59581bcd3b0bf959a70a0b9ea495ec2b61c9f7204fbe2c3658caf43b75481d14e684f6514027781f19d099f349db235792205f7f7a96e3fcf8b9a1638e7298ae6f3521fb2e78b076a303fd062cccfc01285145ce77a481ecf7430adbb843a1c688a09b59f1a7e3a5bfbaa3c1e7b74cb25cacb7ba43b89dd523a66af3f27e351b8b730e6e77334f9219329b58ea9be89d74366f6b094ce2d4d0a02fd1ae15e84585083781bd78f82f582622f061ce60f05a16138c3897fcabb6c7d217e3ec6dce14d724ed83cc00b6e9355402002a2bddae57de13c600f04236c09bea626a017c9b041076a245927778d4bf22fcefcdedfe";

    #[test]
    /** @brief 다른 구현이 만든 서명을 이 구현이 검증할 수 있는지. 자체 구현끼리만 맞으면 틀린 줄 모른다. */
    fn dotnet_cross_validation_4096() {
        let n = unhex(DOTNET_N);
        let e = unhex(KAT_E);

        let key = TestRsaKey::from_components(n.clone(), e.clone(), unhex(DOTNET_D));
        assert_eq!(
            key.sign_pkcs1(RsaHash::Sha256, KAT_MSG),
            unhex(DOTNET_PKCS1_SHA256)
        );
        assert_eq!(
            verify_pkcs1(
                RsaHash::Sha256,
                &n,
                &e,
                KAT_MSG,
                &unhex(DOTNET_PKCS1_SHA256)
            ),
            Ok(())
        );
        assert_eq!(
            verify_pss(RsaHash::Sha512, &n, &e, KAT_MSG, &unhex(DOTNET_PSS_SHA512)),
            Ok(())
        );
        assert_eq!(
            verify_pss(
                RsaHash::Sha512,
                &n,
                &e,
                b"other message",
                &unhex(DOTNET_PSS_SHA512)
            ),
            Err(RsaError::BadSignature)
        );
    }
}
