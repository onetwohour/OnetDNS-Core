//! RSA signature verification, built in-tree because the dependency allowlist has no RSA crate.
//! DNSSEC algorithms 8 and 10 and TLS certificate signatures use it. There is no signing outside
//! tests.
//!
//! Deliberately not constant-time: verification handles only public data, so timing leaks no
//! secret. Do not reuse this code for private-key operations.
//!
//! Key constraints follow ring's RSA_*_2048_8192_* with lower floors for exponent and modulus: n
//! odd with no leading zero, e odd in 3..=2^33-1, signature length equal to the modulus length.
//! Exponent 3 is accepted for older root certificates still in wide use; its safety rests on
//! verify_pkcs1 comparing the whole EM.

use std::cmp::Ordering;

/// Matches MAX_LIMBS.
pub const MAX_MODULUS_BITS: u32 = 8192;

/// Default floor, used for TLS certificate signatures. Public CAs no longer issue keys below 2048
/// bits.
pub const MIN_MODULUS_BITS: u32 = 2048;

/// Floor for DNSSEC verification. Many zones, org and nl among them, still sign with 1024-bit ZSKs;
/// a 2048 floor would make all of them Bogus. Signing is unaffected: this implementation signs only
/// with algorithm 13.
pub const MIN_MODULUS_BITS_DNSSEC: u32 = 1024;

/// Only the three hashes DNSSEC and TLS use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaHash {
    Sha256,
    Sha384,
    Sha512,
}

impl RsaHash {
    pub fn digest_len(self) -> usize {
        match self {
            RsaHash::Sha256 => 32,
            RsaHash::Sha384 => 48,
            RsaHash::Sha512 => 64,
        }
    }

    /// Hashes the parts in sequence without joining them into one buffer.
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

    /// DigestInfo DER prefix for PKCS#1 v1.5. Verification builds the expected encoding from it
    /// instead of parsing the DER in the signature; parsing would admit several encodings of the
    /// same hash.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaError {
    BadKey,
    BadSignature,
}

/// Verifies an RSASSA-PKCS1-v1_5 signature. The block from raising the signature to the public
/// exponent is compared in full against the expected encoding built from scratch; never parsing the
/// DER back is what keeps this safe. `n` and `e` are big-endian, and `n` must have no leading zero.
pub fn verify_pkcs1(
    hash: RsaHash,
    n: &[u8],
    e: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), RsaError> {
    verify_pkcs1_min_bits(hash, n, e, msg, sig, MIN_MODULUS_BITS)
}

/// verify_pkcs1 with an explicit modulus floor; DNSSEC passes MIN_MODULUS_BITS_DNSSEC.
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

/// Verifies an RSASSA-PSS signature (RFC 8017). Checks, in order: zero leading padding, trailing
/// 0xbc, zero unused top bits, the 0x00…0x01 separator in place after MGF1 unmasking, and the hash
/// rebuilt from the salt matching the one in the signature. Skipping any check lets a forgery
/// through; without the unused-bit check one signature has several encodings.
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

/// Builds the expected `k`-byte PKCS#1 v1.5 block: 0x00 0x01 0xff… 0x00 DigestInfo hash. Padding
/// must be at least 8 bytes, so a modulus shorter than t_len + 11 is rejected.
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

/// MGF1 from RFC 8017.
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

/// Accepts only odd exponents in 3..=2^33-1. Even values are not valid RSA exponents, and 1 makes
/// the signature the message itself.
///
/// Small exponents such as 3 make forgery easy against verifiers that check padding loosely.
/// verify_pkcs1 rebuilds the full-length EM and compares all of it, so that forgery has no path
/// here.
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

/// 8192 bits in 64-bit limbs. A fixed size means no heap allocation and puts the key size bound in
/// the type.
const MAX_LIMBS: usize = 128;

/// Modulus preprocessed for Montgomery arithmetic. n is odd and only the low k limbs are used;
/// n0inv is -n^-1 mod 2^64.
struct Modulus {
    n: [u64; MAX_LIMBS],

    n0inv: u64,

    k: usize,

    bits: u32,

    /// The signature length must equal this.
    bytes: usize,
}

impl Modulus {
    /// Rejects a leading zero byte: if one key had several lengths, the signature length check
    /// would mean nothing. Rejects an even modulus, which has no Montgomery inverse.
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

    /// Raises the signature to the public exponent to recover the encoded block, with left-to-right
    /// square-and-multiply. The leading doublings move the base into Montgomery form (multiplying
    /// by 2^(64k)); multiplying by 1 at the end moves it back.
    ///
    /// Rejects a signature whose length differs from the modulus or whose value is not below it;
    /// otherwise one signature would have several representations.
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

    /// CIOS Montgomery multiplication: a·b·R^-1 mod n. Multiply and reduce share one outer loop, so
    /// there is no double-length intermediate. The final conditional subtraction is not
    /// constant-time, which is fine for public data.
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

/// Big-endian bytes to little-endian 64-bit limbs.
fn be_to_limbs(bytes: &[u8]) -> [u64; MAX_LIMBS] {
    let mut limbs = [0u64; MAX_LIMBS];
    for (i, &byte) in bytes.iter().rev().enumerate() {
        limbs[i / 8] |= u64::from(byte) << (8 * (i % 8));
    }
    limbs
}

/// Writes only out.len() bytes.
fn limbs_to_be(limbs: &[u64; MAX_LIMBS], out: &mut [u8]) {
    let len = out.len();
    for i in 0..len {
        out[len - 1 - i] = (limbs[i / 8] >> (8 * (i % 8))) as u8;
    }
}

fn cmp(a: &[u64], b: &[u64]) -> Ordering {
    for i in (0..a.len()).rev() {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

/// a -= b; requires a >= b.
fn sub_in_place(a: &mut [u64], b: &[u64]) {
    let mut borrow = 0u64;
    for (x, &y) in a.iter_mut().zip(b.iter()) {
        let (d1, b1) = x.overflowing_sub(y);
        let (d2, b2) = d1.overflowing_sub(borrow);
        *x = d2;
        borrow = u64::from(b1 | b2);
    }
}

/// t = 2t mod n, used to move the base into Montgomery form. Counts the bit carried out of the top
/// limb; ignoring it breaks values near 2n.
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

/// -n0^-1 mod 2^64, the Montgomery reduction factor. For odd n0, x = n0 is already its own inverse
/// to 3 bits, and each Newton step doubles the correct bits, so 5 steps pass 64.
fn neg_inv64(n0: u64) -> u64 {
    let mut x = n0;
    for _ in 0..5 {
        x = x.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(x)));
    }
    x.wrapping_neg()
}

/// Test-only RSA signer, exposed only through the rsa-test-sign feature. Not constant-time and
/// handles private keys: never use it in a production path.
#[cfg(any(test, feature = "rsa-test-sign"))]
pub mod testsign {
    use super::{emsa_pkcs1, mgf1, Modulus, RsaHash, MIN_MODULUS_BITS};

    pub struct TestRsaKey {
        pub n: Vec<u8>,
        pub e: Vec<u8>,
        d: Vec<u8>,
    }

    impl TestRsaKey {
        pub fn from_components(n: Vec<u8>, e: Vec<u8>, d: Vec<u8>) -> Self {
            TestRsaKey { n, e, d }
        }

        /// Minimal checks: reads test fixtures only, never untrusted input.
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

        /// Equals the signature length.
        pub fn modulus_len(&self) -> usize {
            self.n.len()
        }

        /// RSAPublicKey DER.
        pub fn public_key_der(&self) -> Vec<u8> {
            let mut body = der_integer(&self.n);
            body.extend_from_slice(&der_integer(&self.e));
            let mut out = vec![0x30];
            out.extend_from_slice(&der_len(body.len()));
            out.extend_from_slice(&body);
            out
        }

        pub fn sign_pkcs1(&self, hash: RsaHash, msg: &[u8]) -> Vec<u8> {
            let em = emsa_pkcs1(hash, msg, self.n.len())
                .expect("RSA public key modulus is shorter than the minimum size");
            self.raw_sign(&em)
        }

        /// `salt` must be the hash length; verification assumes it.
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

        fn raw_sign(&self, em: &[u8]) -> Vec<u8> {
            let modulus = Modulus::parse(&self.n, MIN_MODULUS_BITS).expect("Invalid test key");
            modulus
                .pow(em, &self.d)
                .expect("EM is outside the modulus range")
        }
    }

    /// Reads one DER TLV with the expected tag; returns its contents and the rest.
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

    /// Drops the sign byte of a DER INTEGER; RSA values are positive.
    fn strip_leading_zero(v: &[u8]) -> &[u8] {
        v.strip_prefix(&[0]).unwrap_or(v)
    }

    /// Prepends 0 when the top bit is set, so the value does not read as negative.
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

    /// Short form and 1- or 2-byte long forms only.
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
mod tests {
    use super::testsign::TestRsaKey;
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn b64_decode(input: &str) -> Vec<u8> {
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

    fn test_key_2048() -> TestRsaKey {
        let der = b64_decode(include_str!(
            "../../../testdata/rsa_test_private_key_2048.pk8.b64"
        ));
        TestRsaKey::from_pkcs8(&der).unwrap()
    }

    const KAT_MSG: &[u8] = b"onetdns rsa kat v1";
    const KAT_N: &str = "c8a78500a5a250db8ed36c85b8dcf83c4be1953114faaac7616e0ea24922fa6b7ab01f85582c815cc3bdeb5ed46762bc536accaa8b72705b00cef316b2ec508fb9697241b9e34238419cccf7339eeb8b062147af4f5932f613d9bc0ae70bf6d56d4432e83e13767587531bfa9dd56531741244be75e8bc9226b9fa44b4b8a101358d7e8bb75d0c724a4f11ece77776263faefe79612eb1d71646e77e8982866be1400eafc3580d3139b41aaa7380187372f22e35bd55b288496165c881ed154d5811245c52d56cc09d4916d4f2a50bcf5ae0a2637f4cfa6bf9daafc113dba8383b6dd7da6dd8db22d8510a8d3115983308909a1a0332517aa55e896e154249b3";
    const KAT_E: &str = "010001";
    const KAT_PKCS1_SHA256: &str = "2c623f434952f0f4d0cbd9fb7d44d2c487e485d0caa0b2cd34eeb2de1b0e8f961651724da18bb0dae8c873f302a913322f57c86033a0ff00a1ae2664e1129a2f4a10757f068d26d8baeca83bd6fd9631a19b80756c168843b451026f8833a84a0cc0a3cdaf81b1888fb5a45909e8d4382fb7bb25e797bbe6f6273502bdfd560cdce7bc4a357c0068478275366db58315654cf4e1ac7a7733b3725a46c580586fa14f42a13253c554447087f584014e3869b638a826b1daa69083217071090b10cd15478b622a51b31c01b39ffdcde5ca1664cec0e9126d6c0f7c318c449a204b92dd06dd0232c56c5a8063dc20be3fe8dc34ef829bb5b36d173610b344f13a8b";
    const KAT_PKCS1_SHA384: &str = "950067c5828987d69463d4315ed59130e6784a69076fc75b280a61ca4500a6f905d15cae1ed012f4b47121cd8a0a4b1d3f9dd328e2624972fc29158e98ccad81a01f8e20014b8a1dc6df8bd24f7900f75fc2f5ebef83ec53a386b0653f1b244f4853226804440edc4605087a5009935aa46552a3e175e9af8605d6dfc57e6cc0242af64735c29503ed7935b8b09d9edb2ce28ba821c473bd731989a0bd46429d4bba7d3b88ee2de717e62a734fda8d8e62cb5acb28b518b19ce756f0808d9ede19b2a99d80595fc3c562a5b1c86d42037fca2198b47fd7a9f7ba68c5e82d46592cb2bb023950c36dc41bded73b0fdc761f33bd8f548f98e39727a7d08e2ab6ac";
    const KAT_PKCS1_SHA512: &str = "2ed35b506b5be94a68ea78c110e733152750ce2e6424c673132b274d0fc362476ed068aa33569cb58838f9d3527ad36ada0bdb9c1493108c1cf10648247ceeaaaf0d78e9f290cfb03fde8e8f4726522c3293690fa97ee4c4d0622fc4fb046a5caeae60d473df9b632d2efc7a540471aa98af503eb1ec3ac1d82c8524eb088f9ac316746df12493eaa898f00b117b5045d2c7aac2551df8fa410125f2fb8a2a3c78dc38480358aa686bf5bd02050a8bb36f6e52a73fe10e4d378215cd709907ed82a939d972a97a9d36525b5c50b1c070fd177dee8e3b07e84242c0922a43572ae0a79c1e82e869b97d51ed601b259ce2b3fc253db16b8416c57d8afdecd317c9";
    const KAT_PSS_SHA256: &str = "54c04293bee87677b93e4068a8bdeaea8d2abddd8bb22f84da17542e3b9670795bdecce05644c903bacf4cf08b765fe3474d02073811f83aa0c800184ee0de6290bcc3250080a45b29973b99d93cd754e8859cea14d59d155416a18c6432006a972280c62bebf6d5a2e257acacd66740d7361c45cce51590c57949160f9e32d1e3bae7cee9158913959e43ae2dd3866e40d0517d0584a79e09126334686dc0ff0d6b91812e75cf89a1ff607bad189d676fa42019e411c3df81456ce1d4cd4e301b38dd47835b96922ecb9fdee8c668ba3a61fff6c789cd6b3f664919af62863f1ae37a6c2da06e632c2499a43559a466caa0251e31a9de88888d709fbf5944d1";
    const KAT_PSS_SHA384: &str = "765f1af9fd1877d06b444ddd422d5ec004d224b25d290db8cfd980c0b09064d9bd215a26448cfbc47a22f93dbcf5c723bed9a7dbd7c3da2c805a413cb9855b94b31ba527b67d5033b988986a4731036acfaedd3f05dba43c7ab69f0c1438b0bed913240f4466aadc5135b9eb91a1f2c82c3a0b80bcb12656962fed2aedca2db54da3d0ef5af78e1fe03a5182d427af6ffe6afc394000b3920c6615d29fbb184505f1f61eaa6b7895c2e5183f4625ec43160b975672b2103b9378395e04fd975a8b1e2f034b513f0af07592df12da89498d90a619e08e1368ac80bbda74858ad41b3d3ed998673f9765002aac57c07f33d92777561e4830a318941d62bf5dec36";
    const KAT_PSS_SHA512: &str = "a1c907448bdf48924d866349df473086c921557892b0e4178ce29be171d090cf4af2c08e56b95c9236aed0486c109b1b95a4f47c6fde1aaf52ade79649158b55f534fa4f9a296aed5e0c1adb70da6040e5142fc9000945d14574c3e68063a46d1b1b4aead64f7063141fd2b5cbaf4be96bbfa5a0b47f78104b17c75accd76d92c7a9b4514ca60615ae87053bf21ef5772a193b1d81a76967f638b8ef4bf73262853a93f04721c11e5f4c147fa39a7793514ea82649907df0aa029d13f33b3861479d043beb20cc3046da86d2525bccc575ca37c062bb00c1719f607cee9fcd020eb3b838ba1ae74ca5e2b4eb76595f5acad3a7ca3841860c01ab732d63d6e3b1";

    #[test]
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
    /// Accepting another hash or padding would let a signature be swapped.
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

    const E3_MSG: &[u8] = b"onetdns e3 vector";
    const E3_N: &str = "b7d295f19268575d17d1f92b6c4df32054ffd157ea9a19177ea2e98627b12aa13771910be1ee59becc448dc4adcd727b81a48498e748d45808d88200f0a6014301465b16d3816dc2e978d3a0f4277c32b4038a1f3bc9d72d00a10e127ad99f2546fb61df302737c06b99029c5cbbb0ba7a1d622d38e3641a60428e33262ebbcb3343aa176d69bdfe2be51be415c278c2304cce8b369c4c8fc58883eb646e6ee11cbcde330c978d9d6f8844e500f64cd7d84a5cdf3b5b569c121c6233197978992ff584e546c388819f562e61afb3b6d0e0d61f39cdd04fcdb0612db579f241bfd2b9f8f54058abc0cc33947aa4a9b178b36d401b9ece84093824a16efe9aeb6b";
    const E3_SIG: &str = "0f4738b29e1f4f5ad4cb33483567b3067d9a01ef2285ef58f2ce75367810d2cd99f9906a72b4a11217c543dc62a6ea9cb93b0489f681164899aa83b1d978e1275a85a32a1ad5e71ba5c94250d87a1cf5e85b01a3383901dbf732601fa616e96d9670a19664ed97368e1a1d598a9a1d55e999c960e265e88b8336a217125e89a2a5e472ce0b0cae3a275f3305f27a4b919f61f30aa32a20ed9866eafff41500514d39d39b5e1eb200ad1fcf56ab50b68a715ffde4ce638a96a62c21e6a51e1be43e135715c75bbe337439a156a8c142ad59397861896fc2948353742cf15ce9f7dc5c32923d8e7b14005994f7448afba77cea7db31f2388b269ec3107eca0b93f";
    /// Cube root of an EM whose padding is cut to 8 bytes and whose tail is filled, made without
    /// the private key.
    const E3_FORGED: &str = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000032cbfd4a7adc7905583d767520f51640759176d37826f2ef63ae3dc7a7d1bdf411de33ccbee7a5eaa0a2d7274fc50fc0a2fcd1cb50711c4748a1961c0be8a1436a98f1dc47abdf4a9dac502c659be511bbc4559a9b";

    #[test]
    /// Cubing the forged signature gives 00 01 FF..FF 00 DigestInfo in the expected shape, followed
    /// by filler. A verifier that ignores padding length or extracts only DigestInfo accepts it;
    /// this one rebuilds the whole EM and rejects it.
    ///
    /// This test is why the exponent floor is 3; start here before touching the exponent check.
    fn exponent_three_accepted_but_small_exponent_forgery_rejected() {
        let n = unhex(E3_N);
        let e = [3u8];

        // First check the vector is a real forgery attempt: the cube must hold the expected prefix
        // and DigestInfo, or a loose verifier would not accept it either.
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

        // Exponent 3 is a valid key; this signature was made with another exponent, so it fails as
        // a signature.
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
    /// The signature must be exactly the modulus length.
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

    const DOTNET_N: &str = "d5fe562f4d7ffcc2e4cb587780ffb55d9930e78bf2b86791a849ee939a464c23b85f1f27d8f2b0f64245150a32a3e5303c107aecd6d3a0e69e20c27e20280466020c18eb54dc0e15d311b8588d0b55cb167e534202dcecf8dec60545c7b08b363546b724f9c0eda50cffa85521f0297586f08e68987745c23336ad692a066e0f0677e2240b2d169f42894e6bc393e3d1f6fbc881928d677352288de86cdf0ace92bed555bb6ba5f861cf82417fc214c8111ca10c4d3326ba03b6965406d11306b6d3d030774cd209ddc165054fcaacfa12c36e27a3313fe49ef63d73c603bbd2e51a368d9984194deecb04af8a2024ea854138ed6c093f6029c6fd785924b5a0eeb38eecb08341ba30dd90a23d028144087789bf2b6da75831c23e472ae7e3eaed77dda4122ce4920abfbb3c463b8b0fbdd02070d16e5b76d69fed28d408eab02599548a6206068d538924273513374f1986c7401409f5cce40f50f7657fc766ba205a40f58886a4978d5aad34b43eecf5b6b4126c7680b0a4523f5765f2c5ea8211398e94ac123d17acc9b4d61d8620a3a49d06ddfbef49671feac8088a396ca2094238cd466ebd6852353e25ce8c5b8d1236db247bfc87c9eec1f462aecb232cedf85e0b5b3e2666ebf19426f466bad2ff4895d5a062f3580b2ed6a74ed87314dfeaeebde2dd57227aaf2b204d1c732be85fd6bc56b5b4cc8b2b5b932b1d4d";
    const DOTNET_D: &str = "0d69dfe51f2a82a184cdea41b36853ea060c36b76303841a713e1122576d48a0849211d5e19774d83ad731b66dee301391f046844a0301f6f2ba82f67cf585310fb7ca6815eda54460f29f678d8fc454f298008806bdea6cbf2a1272894ddbac0e32dc9008c7bb1db96edd12590a40cf0922530ae363b68fb1be1fa893e5cb484dd37ded5c75fb11088eaac7be7eaaad229a2dbb51806397aaf2b7d275e09540d599f8ad630e205d2d646079d2944bd12ea168c6e89fe83188c20d323f2b23d22beba30526b53e05384d4313ce289a2722bdf54daec10b8c3d1a9a4783860063fbd064d30368705d9e364398ed438e8cd4c57dd80409a05b5ac30a685cce1c4458d71f55bd2bebf246aca7475b4b5ed9681f2ec3ea4635224e300b13b214d34d48421cfc5f34a10f6d6957a06b1000f14b7c04cda9c8045edba1a7d978dddbe65929ab599d3b1488a6401d03001378856ad4c77bac228eea644672bb08f86420ef64a28f99ffd76b643257cd12d8075f64e70e230dc741c26500109552fe7320ce4745917841079f5ff7508112d2e59c0b85bbd40cfe8f4c8e5b736148213e200faed4bed7417d3ee074bb41c0988b03a14c1f1612f4984fdac28bfd739b92eb1336d8cbe264ee9e6e6bdf3b0a4a97abbb59324f2ce3e507604d2b50c9b9e866749b3d682d798d9e5c706473eceb04d5f7d1fb66b7e4c261914f9aa016eba7d1";
    const DOTNET_PKCS1_SHA256: &str = "112b264f61c49b9edd6a26710cd2f2fce6c050597378cb4d4c8d6ba730ea467c7c32de672876caa539272a89fa55b67bf951725be07ecbb5de97a2ad6b128adfd0580e926e4affb5bf74c82338e26301eef2f5e5fea06c76e2a09523a48cd34e7afdc7280c0aadc1ddbc82b2453940914c6cf05907c94a34ea1a90d17c6569901e4e5e3bc8c9e73f475118241b9172b042f18f7b86a71861fbe4e1349c4d0230faf8bcb8cedddab6e5cbe34cdf35e7fa4ed3cb7b46adbe2a9e206ee93fc396e82691f661c9e554764fd298cfcec035c3ac008c3b11aeb8653dece2a74912beaee47a16fc56dad42f1adca177bf4c4f5724faa94c28dd1a3b84564c66c24405519d1a026ab5e4b20afe6ea9c4d2ba8ac020dffa1cb9cec4d63cbb62a1f53b2540d34f9923e103ab0eff38042e52aaeac5b83d1e22c0ade4368e1dc45bf36957f921aab49d502a492929ce466e5d9c9ba32244e1c9dda1c97cfc2884fc05b9c0b167261bdacc1f95409f58757ca44d621bd6814d574ec2c9004a753c00e0881c08ec203d01214c29ecd029dc8a957f4a5111c9f8a0ab2864dc26d967dfe3578a89bf439a3616294163a14b082cd1cdf6736406370c92af00ee86ce24aaba2c16172770ee82a2b7e5f6686d08fcb2abc79507442c9a874597506904b7dd711ad108cf9251e099bc845be7bab69b9395043948fe30654b8659701fc4af2c53b69db4";
    const DOTNET_PSS_SHA512: &str = "55d2ccdc5f5e3582ed29ec7d71ce416fb92f081a49c704f9e94c0cbc90eaf2246d5f190ea29411f6f579655c1c6ef3160cd52e6ba30332fe75434f0b29df00e29d11ffae58659a632bded89da0559301787b12c49308778d26829803f9abd7675e6d0b6690c92ed8f89fc647afb0e1c8fe7dacf5992b07a585621f6ce540bdb9aee231b80b59edacb1aed89aa33cbceffcee6fbefadf19a274d7b4774f9bc6fc651e8eea07564a0a2c905806637c4c83c30012d46fc91391cb2974d942b25d87347dc66c64ba3d66587974c9bdffa1c97175a4073ac6131e980fc8ba31bdb69c46737a6cf6c778bd44a58d8e178a88970d5249e5a9b27e8a2730488c2615fcbd333aedfc58d87924b73fa51bebce5a59581bcd3b0bf959a70a0b9ea495ec2b61c9f7204fbe2c3658caf43b75481d14e684f6514027781f19d099f349db235792205f7f7a96e3fcf8b9a1638e7298ae6f3521fb2e78b076a303fd062cccfc01285145ce77a481ecf7430adbb843a1c688a09b59f1a7e3a5bfbaa3c1e7b74cb25cacb7ba43b89dd523a66af3f27e351b8b730e6e77334f9219329b58ea9be89d74366f6b094ce2d4d0a02fd1ae15e84585083781bd78f82f582622f061ce60f05a16138c3897fcabb6c7d217e3ec6dce14d724ed83cc00b6e9355402002a2bddae57de13c600f04236c09bea626a017c9b041076a245927778d4bf22fcefcdedfe";

    #[test]
    /// Agreeing only with our own signer would not catch a shared mistake.
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
