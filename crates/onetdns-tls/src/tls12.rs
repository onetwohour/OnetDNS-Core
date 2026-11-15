//! TLS 1.2 support. Key derivation, record protection, and handshake messages all differ from TLS
//! 1.3; it stays for peers that still use it.
//!
//! Suites without forward secrecy are left out entirely, so they cannot be negotiated.

use hmac::Mac;
use zeroize::Zeroizing;

use crate::aead::{aead_open, aead_seal, Aead};
use crate::keyschedule::Hash;
use crate::msg::consts::{SECP256R1, X25519};
use crate::record::{ContentType, TlsRecord, LEGACY_VERSION};
use crate::wire::{Reader, Writer};
use crate::TlsError;

pub mod suites {
    pub const ECDHE_ECDSA_AES128_GCM_SHA256: u16 = 0xC02B;
    pub const ECDHE_ECDSA_AES256_GCM_SHA384: u16 = 0xC02C;
    pub const ECDHE_RSA_AES128_GCM_SHA256: u16 = 0xC02F;
    pub const ECDHE_RSA_AES256_GCM_SHA384: u16 = 0xC030;
    pub const ECDHE_ECDSA_CHACHA20_SHA256: u16 = 0xCCA9;
    pub const ECDHE_RSA_CHACHA20_SHA256: u16 = 0xCCA8;
}

/// Only the uncompressed format is used.
pub const EXT_EC_POINT_FORMATS: u16 = 11;
pub const EC_POINT_FORMAT_UNCOMPRESSED: u8 = 0;
/// Binds the transcript into key derivation, which stops session confusion attacks.
pub const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
/// Sent empty; this side never renegotiates.
pub const EXT_RENEGOTIATION_INFO: u16 = 0xff01;
/// RFC 5746 treats it as an empty renegotiation_info extension.
pub const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: u16 = 0x00ff;
pub const CERT_TYPE_RSA_SIGN: u8 = 1;
/// RFC 8422 puts ECDSA and EdDSA keys here.
pub const CERT_TYPE_ECDSA_SIGN: u8 = 64;

const VERIFY_DATA_LEN: usize = 12;

#[derive(Debug, Clone, Copy)]
pub struct Suite12 {
    pub aead: Aead,
    pub hash: Hash,
    pub key_len: usize,
    pub ecdsa: bool,
}

pub fn suite_info(suite: u16) -> Option<Suite12> {
    use suites::*;
    Some(match suite {
        ECDHE_ECDSA_AES128_GCM_SHA256 => Suite12 {
            aead: Aead::Aes128Gcm,
            hash: Hash::Sha256,
            key_len: 16,
            ecdsa: true,
        },
        ECDHE_RSA_AES128_GCM_SHA256 => Suite12 {
            aead: Aead::Aes128Gcm,
            hash: Hash::Sha256,
            key_len: 16,
            ecdsa: false,
        },
        ECDHE_ECDSA_AES256_GCM_SHA384 => Suite12 {
            aead: Aead::Aes256Gcm,
            hash: Hash::Sha384,
            key_len: 32,
            ecdsa: true,
        },
        ECDHE_RSA_AES256_GCM_SHA384 => Suite12 {
            aead: Aead::Aes256Gcm,
            hash: Hash::Sha384,
            key_len: 32,
            ecdsa: false,
        },
        ECDHE_ECDSA_CHACHA20_SHA256 => Suite12 {
            aead: Aead::ChaCha20Poly1305,
            hash: Hash::Sha256,
            key_len: 32,
            ecdsa: true,
        },
        ECDHE_RSA_CHACHA20_SHA256 => Suite12 {
            aead: Aead::ChaCha20Poly1305,
            hash: Hash::Sha256,
            key_len: 32,
            ecdsa: false,
        },
        _ => return None,
    })
}

pub fn client_suites() -> [u16; 6] {
    use suites::*;
    [
        ECDHE_ECDSA_AES128_GCM_SHA256,
        ECDHE_RSA_AES128_GCM_SHA256,
        ECDHE_ECDSA_CHACHA20_SHA256,
        ECDHE_RSA_CHACHA20_SHA256,
        ECDHE_ECDSA_AES256_GCM_SHA384,
        ECDHE_RSA_AES256_GCM_SHA384,
    ]
}

/// Picks an offered suite the local certificate can serve.
pub fn choose_server_suite(offered: &[u16], server_ecdsa: bool) -> Option<u16> {
    use suites::*;
    let pref = if server_ecdsa {
        [
            ECDHE_ECDSA_AES128_GCM_SHA256,
            ECDHE_ECDSA_CHACHA20_SHA256,
            ECDHE_ECDSA_AES256_GCM_SHA384,
        ]
    } else {
        [
            ECDHE_RSA_AES128_GCM_SHA256,
            ECDHE_RSA_CHACHA20_SHA256,
            ECDHE_RSA_AES256_GCM_SHA384,
        ]
    };
    pref.into_iter().find(|s| offered.contains(s))
}

pub fn supported_groups() -> [u16; 2] {
    [X25519, SECP256R1]
}

pub fn group_supported(g: u16) -> bool {
    g == X25519 || g == SECP256R1
}

fn hmac(hash: Hash, key: &[u8], data: &[u8]) -> Vec<u8> {
    match hash {
        Hash::Sha256 => {
            let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
                .expect("HMAC key length must match the algorithm");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
        Hash::Sha384 => {
            let mut m = hmac::Hmac::<sha2::Sha384>::new_from_slice(key)
                .expect("HMAC key length must match the algorithm");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
    }
}

fn p_hash(hash: Hash, secret: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut a = Zeroizing::new(hmac(hash, secret, seed));
    while out.len() < out_len {
        let mut input = Zeroizing::new(a.to_vec());
        input.extend_from_slice(seed);
        let block = Zeroizing::new(hmac(hash, secret, &input));
        out.extend_from_slice(&block);
        a = Zeroizing::new(hmac(hash, secret, &a));
    }
    out.truncate(out_len);
    out
}

pub fn prf(hash: Hash, secret: &[u8], label: &str, seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut ls = label.as_bytes().to_vec();
    ls.extend_from_slice(seed);
    p_hash(hash, secret, &ls, out_len)
}

pub fn master_secret(
    hash: Hash,
    pms: &[u8],
    client_random: &[u8],
    server_random: &[u8],
) -> Vec<u8> {
    let mut seed = client_random.to_vec();
    seed.extend_from_slice(server_random);
    prf(hash, pms, "master secret", &seed, 48)
}

/// Use this one: the original derivation uses only the randoms, so different handshakes can reach
/// the same secret, which allows session confusion attacks.
pub fn extended_master_secret(hash: Hash, pms: &[u8], session_hash: &[u8]) -> Vec<u8> {
    prf(hash, pms, "extended master secret", session_hash, 48)
}

pub struct KeyMaterial {
    pub client_key: Vec<u8>,
    pub server_key: Vec<u8>,
    /// Fixed part of the nonce; `fixed_iv_len` sets its length.
    pub client_iv: Vec<u8>,
    pub server_iv: Vec<u8>,
}

/// Whether records carry the 8-byte explicit nonce part. AES-GCM does, per RFC 5288;
/// ChaCha20-Poly1305 does not, per RFC 7905, and XORs the sequence number into the fixed part
/// instead.
fn explicit_nonce(aead: Aead) -> bool {
    !matches!(aead, Aead::ChaCha20Poly1305)
}

fn fixed_iv_len(aead: Aead) -> usize {
    if explicit_nonce(aead) {
        4
    } else {
        12
    }
}

/// The fixed nonce length follows the suite's cipher.
pub fn key_material(
    suite: &Suite12,
    master: &[u8],
    client_random: &[u8],
    server_random: &[u8],
) -> KeyMaterial {
    let mut seed = server_random.to_vec();
    seed.extend_from_slice(client_random);
    let key_len = suite.key_len;
    let iv_len = fixed_iv_len(suite.aead);
    let need = 2 * key_len + 2 * iv_len;
    let kb = Zeroizing::new(prf(suite.hash, master, "key expansion", &seed, need));
    let (client_key, rest) = kb.split_at(key_len);
    let (server_key, rest) = rest.split_at(key_len);
    let (client_iv, server_iv) = rest.split_at(iv_len);
    KeyMaterial {
        client_key: client_key.to_vec(),
        server_key: server_key.to_vec(),
        client_iv: client_iv.to_vec(),
        server_iv: server_iv.to_vec(),
    }
}

pub fn finished_verify_data(hash: Hash, master: &[u8], label: &str, transcript: &[u8]) -> Vec<u8> {
    let session_hash = hash.digest(transcript);
    prf(hash, master, label, &session_hash, VERIFY_DATA_LEN)
}

/// The nonce layout differs by cipher; see `explicit_nonce`.
pub struct Tls12RecordCrypto {
    aead: Aead,
    key: Vec<u8>,
    iv: Vec<u8>,
    seq: u64,
}

impl Drop for Tls12RecordCrypto {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl Tls12RecordCrypto {
    /// Internal when the fixed part's length does not fit the cipher.
    pub fn new(aead: Aead, key: Vec<u8>, iv: Vec<u8>) -> Result<Self, TlsError> {
        if iv.len() != fixed_iv_len(aead) {
            return Err(TlsError::Internal);
        }
        Ok(Self {
            aead,
            key,
            iv,
            seq: 0,
        })
    }

    /// The sequence number and the record header.
    fn aad(seq: u64, ct: ContentType, plaintext_len: usize) -> [u8; 13] {
        let s = seq.to_be_bytes();
        [
            s[0],
            s[1],
            s[2],
            s[3],
            s[4],
            s[5],
            s[6],
            s[7],
            ct.0,
            (LEGACY_VERSION >> 8) as u8,
            LEGACY_VERSION as u8,
            (plaintext_len >> 8) as u8,
            plaintext_len as u8,
        ]
    }

    /// `explicit` is the part carried in the record for AES-GCM, or the sequence number for
    /// ChaCha20-Poly1305.
    fn nonce(&self, explicit: &[u8; 8]) -> [u8; 12] {
        let mut n = [0u8; 12];
        if explicit_nonce(self.aead) {
            n[..4].copy_from_slice(&self.iv);
            n[4..].copy_from_slice(explicit);
        } else {
            n.copy_from_slice(&self.iv);
            for (byte, seq) in n[4..].iter_mut().zip(explicit) {
                *byte ^= seq;
            }
        }
        n
    }

    fn explicit_len(&self) -> usize {
        if explicit_nonce(self.aead) {
            8
        } else {
            0
        }
    }

    /// Fails when the sequence number would overflow; wrapping would repeat the nonce. Internal
    /// when the plaintext exceeds the record limit: the caller failed to split it, so the peer must
    /// not be told record_overflow.
    pub fn encrypt(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
    ) -> Result<TlsRecord, TlsError> {
        if plaintext.len() > crate::record::MAX_FRAGMENT {
            return Err(TlsError::Internal);
        }
        if self.seq >= self.aead.encryption_limit() {
            return Err(TlsError::SeqExhausted);
        }
        let explicit = self.seq.to_be_bytes();
        let nonce = self.nonce(&explicit);
        let aad = Self::aad(self.seq, content_type, plaintext.len());
        let sealed = aead_seal(self.aead, &self.key, &nonce, &aad, plaintext);
        let mut fragment = Vec::with_capacity(self.explicit_len() + sealed.len());
        fragment.extend_from_slice(&explicit[..self.explicit_len()]);
        fragment.extend_from_slice(&sealed);

        self.seq = self.seq.checked_add(1).ok_or(TlsError::SeqExhausted)?;
        Ok(TlsRecord::new(content_type, fragment))
    }

    /// Fails on a sequence mismatch. RecordOverflow when the plaintext exceeds 2^14 bytes; without
    /// compression, the plaintext limit RFC 5246 sets applies directly.
    pub fn decrypt(&mut self, record: &TlsRecord) -> Result<Vec<u8>, TlsError> {
        let explicit_len = self.explicit_len();
        if record.fragment.len() < explicit_len + 16 {
            return Err(TlsError::Decrypt);
        }
        let explicit: [u8; 8] = if explicit_len == 0 {
            self.seq.to_be_bytes()
        } else {
            record.fragment[..8]
                .try_into()
                .map_err(|_| TlsError::Decrypt)?
        };
        let ct = &record.fragment[explicit_len..];
        let plaintext_len = ct.len() - 16;
        if plaintext_len > crate::record::MAX_FRAGMENT {
            return Err(TlsError::RecordOverflow);
        }
        let nonce = self.nonce(&explicit);
        let aad = Self::aad(self.seq, record.content_type, plaintext_len);
        let plain = aead_open(self.aead, &self.key, &nonce, &aad, ct)?;
        self.seq = self.seq.checked_add(1).ok_or(TlsError::SeqExhausted)?;
        Ok(plain)
    }
}

pub fn ecdh_params(group: u16, public: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(3);
    w.u16(group);
    w.vec8(|w| w.bytes(public));
    w.buf
}

pub fn server_key_exchange(params: &[u8], sig_scheme: u16, signature: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(params);
    w.u16(sig_scheme);
    w.vec16(|w| w.bytes(signature));
    w.buf
}

#[allow(clippy::type_complexity)]
pub fn parse_server_key_exchange(
    body: &[u8],
) -> Result<(u16, Vec<u8>, Vec<u8>, u16, Vec<u8>), TlsError> {
    let mut r = Reader::new(body);
    let curve_type = r.u8()?;
    if curve_type != 3 {
        return Err(TlsError::IllegalParameter);
    }
    let group = r.u16()?;
    let public = r.vec8()?.to_vec();

    let params_len = 1 + 2 + 1 + public.len();
    let params_bytes = body.get(..params_len).ok_or(TlsError::Decode)?.to_vec();
    let sig_scheme = r.u16()?;
    let signature = r.vec16()?.to_vec();
    if public.is_empty() || signature.is_empty() || !r.is_empty() {
        return Err(TlsError::Decode);
    }
    Ok((group, public, params_bytes, sig_scheme, signature))
}

pub fn client_key_exchange(public: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.vec8(|w| w.bytes(public));
    w.buf
}

pub fn parse_client_key_exchange(body: &[u8]) -> Result<Vec<u8>, TlsError> {
    let mut r = Reader::new(body);
    let public = r.vec8()?.to_vec();
    if public.is_empty() || !r.is_empty() {
        return Err(TlsError::Decode);
    }
    Ok(public)
}

pub fn certificate(chain: &[Vec<u8>]) -> Vec<u8> {
    let mut w = Writer::new();
    w.vec24(|w| {
        for cert in chain {
            w.vec24(|w| w.bytes(cert));
        }
    });
    w.buf
}

/// Decode on malformed input or an empty certificate; BadCert when there are more certificates than
/// this side will verify.
pub fn parse_certificate(body: &[u8]) -> Result<Vec<Vec<u8>>, TlsError> {
    let mut r = Reader::new(body);
    let list = r.vec24()?;
    if !r.is_empty() {
        return Err(TlsError::Decode);
    }
    let mut lr = Reader::new(list);
    let mut out = Vec::new();
    while !lr.is_empty() {
        let certificate = lr.vec24()?;
        if certificate.is_empty() {
            return Err(TlsError::Decode);
        }
        if out.len() >= crate::cert::MAX_CERTIFICATE_ENTRIES {
            return Err(TlsError::BadCert);
        }
        out.push(certificate.to_vec());
    }
    Ok(out)
}

/// The parts of a TLS 1.2 CertificateRequest this side uses.
pub struct CertificateRequest12 {
    pub certificate_types: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
}

impl CertificateRequest12 {
    /// Whether a signature with this scheme, and a certificate holding its key, is acceptable. The
    /// certificate type follows the key type; RFC 8422 puts Ed25519 keys under ecdsa_sign too.
    pub fn accepts(&self, scheme: u16) -> bool {
        use crate::msg::consts::*;
        let certificate_type = match scheme {
            ED25519 | ECDSA_SECP256R1_SHA256 | ECDSA_SECP384R1_SHA384 => CERT_TYPE_ECDSA_SIGN,
            RSA_PKCS1_SHA256 | RSA_PKCS1_SHA384 | RSA_PKCS1_SHA512 | RSA_PSS_RSAE_SHA256
            | RSA_PSS_RSAE_SHA384 | RSA_PSS_RSAE_SHA512 => CERT_TYPE_RSA_SIGN,
            _ => return false,
        };
        self.certificate_types.contains(&certificate_type)
            && self.signature_algorithms.contains(&scheme)
    }
}

/// The CA list is not used, so only its format is checked. Decode on malformed input or on an empty
/// list that must not be empty.
pub fn parse_certificate_request(body: &[u8]) -> Result<CertificateRequest12, TlsError> {
    let mut r = Reader::new(body);
    let certificate_types = r.vec8()?.to_vec();
    let algorithms = r.vec16()?;
    let authorities = r.vec16()?;
    if certificate_types.is_empty()
        || algorithms.is_empty()
        || algorithms.len() % 2 != 0
        || !r.is_empty()
    {
        return Err(TlsError::Decode);
    }
    let mut names = Reader::new(authorities);
    while !names.is_empty() {
        if names.vec16()?.is_empty() {
            return Err(TlsError::Decode);
        }
    }
    let signature_algorithms = algorithms
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    Ok(CertificateRequest12 {
        certificate_types,
        signature_algorithms,
    })
}

/// Both randoms followed by the parameters. The randoms keep the signature from being reused in
/// another handshake.
pub fn ske_signed_content(
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    params: &[u8],
) -> Vec<u8> {
    let mut c = Vec::with_capacity(64 + params.len());
    c.extend_from_slice(client_random);
    c.extend_from_slice(server_random);
    c.extend_from_slice(params);
    c
}

pub fn ext_ec_point_formats() -> crate::msg::Extension {
    let mut w = Writer::new();
    w.vec8(|w| w.u8(EC_POINT_FORMAT_UNCOMPRESSED));
    crate::msg::Extension::new(EXT_EC_POINT_FORMATS, w.buf)
}

pub fn ext_extended_master_secret() -> crate::msg::Extension {
    crate::msg::Extension::new(EXT_EXTENDED_MASTER_SECRET, Vec::new())
}

pub fn ext_renegotiation_info() -> crate::msg::Extension {
    let mut w = Writer::new();
    w.vec8(|_w| {});
    crate::msg::Extension::new(EXT_RENEGOTIATION_INFO, w.buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prf_deterministic_and_length() {
        let out = prf(Hash::Sha256, b"secret", "label", b"seed", 100);
        assert_eq!(out.len(), 100);

        assert_eq!(out, prf(Hash::Sha256, b"secret", "label", b"seed", 100));

        assert_eq!(
            &prf(Hash::Sha256, b"secret", "label", b"seed", 40),
            &out[..40]
        );

        assert_ne!(
            prf(Hash::Sha384, b"secret", "label", b"seed", 48),
            out[..48]
        );
    }

    #[test]
    fn master_and_keyblock_symmetry() {
        let pms = [7u8; 32];
        let cr = [1u8; 32];
        let sr = [2u8; 32];
        let ms = master_secret(Hash::Sha256, &pms, &cr, &sr);
        assert_eq!(ms.len(), 48);
        let gcm = suite_info(suites::ECDHE_ECDSA_AES128_GCM_SHA256).unwrap();
        let km = key_material(&gcm, &ms, &cr, &sr);
        assert_eq!(km.client_key.len(), 16);
        assert_eq!(km.server_key.len(), 16);
        assert_eq!(km.client_iv.len(), 4);
        assert_ne!(km.client_key, km.server_key);
        assert_ne!(km.client_iv, km.server_iv);

        let chacha = suite_info(suites::ECDHE_ECDSA_CHACHA20_SHA256).unwrap();
        let km = key_material(&chacha, &ms, &cr, &sr);
        assert_eq!(km.client_key.len(), 32);
        assert_eq!(
            km.client_iv.len(),
            12,
            "RFC 7905 는 키 블록에서 12 바이트 고정 nonce 를 가져오게 합니다"
        );
        assert_eq!(km.server_iv.len(), 12);
    }

    #[test]
    /// No explicit nonce: only ciphertext and tag are carried, and the nonce is the fixed part
    /// XORed with the sequence number.
    fn chacha20_record_follows_rfc7905() {
        let key = vec![0x5au8; 32];
        let iv: Vec<u8> = (0u8..12).collect();
        let mut enc =
            Tls12RecordCrypto::new(Aead::ChaCha20Poly1305, key.clone(), iv.clone()).unwrap();
        let mut dec =
            Tls12RecordCrypto::new(Aead::ChaCha20Poly1305, key.clone(), iv.clone()).unwrap();

        let first = enc.encrypt(ContentType::Handshake, b"finished").unwrap();
        let second = enc.encrypt(ContentType::ApplicationData, b"query").unwrap();
        assert_eq!(
            first.fragment.len(),
            8 + 16,
            "명시 nonce 를 싣지 않아야 합니다"
        );

        let mut nonce: [u8; 12] = iv.clone().try_into().unwrap();
        nonce[11] ^= 1;
        let aad = Tls12RecordCrypto::aad(1, ContentType::ApplicationData, 5);
        let expected = aead_seal(Aead::ChaCha20Poly1305, &key, &nonce, &aad, b"query");
        assert_eq!(
            second.fragment, expected,
            "nonce 는 고정 부분과 일련번호의 XOR 입니다"
        );

        assert_eq!(dec.decrypt(&first).unwrap(), b"finished");
        assert_eq!(dec.decrypt(&second).unwrap(), b"query");
    }

    #[test]
    fn record_crypto_rejects_wrong_iv_length() {
        assert!(Tls12RecordCrypto::new(Aead::ChaCha20Poly1305, vec![0; 32], vec![0; 4]).is_err());
        assert!(Tls12RecordCrypto::new(Aead::Aes128Gcm, vec![0; 16], vec![0; 12]).is_err());
    }

    #[test]
    /// Rejected before decrypting.
    fn oversized_ciphertext_is_record_overflow() {
        for (aead, key, iv, explicit) in [
            (Aead::Aes128Gcm, vec![0x11; 16], vec![0; 4], 8),
            (Aead::ChaCha20Poly1305, vec![0x11; 32], vec![0; 12], 0),
        ] {
            let mut dec = Tls12RecordCrypto::new(aead, key, iv).unwrap();
            let fragment = vec![0; explicit + crate::record::MAX_FRAGMENT + 1 + 16];
            let record = TlsRecord::new(ContentType::ApplicationData, fragment);
            assert_eq!(dec.decrypt(&record), Err(TlsError::RecordOverflow));
        }
    }

    #[test]
    fn record_crypto_roundtrip() {
        let key = vec![0x33u8; 16];
        let salt = vec![0xAB, 0xCD, 0xEF, 0x12];
        let mut enc = Tls12RecordCrypto::new(Aead::Aes128Gcm, key.clone(), salt.clone()).unwrap();
        let mut dec = Tls12RecordCrypto::new(Aead::Aes128Gcm, key, salt).unwrap();

        let r1 = enc
            .encrypt(ContentType::ApplicationData, b"hello dns over tls 1.2")
            .unwrap();
        assert_eq!(r1.content_type, ContentType::ApplicationData);

        assert_eq!(r1.fragment.len(), 8 + 22 + 16);
        assert_eq!(dec.decrypt(&r1).unwrap(), b"hello dns over tls 1.2");

        let r2 = enc
            .encrypt(ContentType::ApplicationData, b"hello dns over tls 1.2")
            .unwrap();
        assert_ne!(r1.fragment, r2.fragment);
        assert_eq!(dec.decrypt(&r2).unwrap(), b"hello dns over tls 1.2");
    }

    #[test]
    fn record_crypto_tamper_and_reorder_rejected() {
        let key = vec![0x44u8; 32];
        let salt = vec![0u8; 4];
        let mut enc = Tls12RecordCrypto::new(Aead::Aes256Gcm, key.clone(), salt.clone()).unwrap();
        let mut dec = Tls12RecordCrypto::new(Aead::Aes256Gcm, key, salt).unwrap();
        let mut r = enc
            .encrypt(ContentType::ApplicationData, b"secret")
            .unwrap();
        r.fragment[10] ^= 0xFF;
        assert!(dec.decrypt(&r).is_err());

        let good = enc
            .encrypt(ContentType::ApplicationData, b"secret")
            .unwrap();
        assert!(dec.decrypt(&good).is_err());
    }

    #[test]
    fn seq_exhaustion_fails_closed() {
        let key = vec![0x33u8; 32];
        let mut enc = Tls12RecordCrypto::new(Aead::ChaCha20Poly1305, key, vec![0xAB; 12]).unwrap();
        enc.seq = u64::MAX;
        assert_eq!(
            enc.encrypt(ContentType::ApplicationData, b"x"),
            Err(TlsError::SeqExhausted)
        );
    }

    #[test]
    fn aes_gcm_key_usage_limit_fails_closed() {
        for (aead, key) in [
            (Aead::Aes128Gcm, vec![0x11; 16]),
            (Aead::Aes256Gcm, vec![0x22; 32]),
        ] {
            let mut enc = Tls12RecordCrypto::new(aead, key, vec![0; 4]).unwrap();
            enc.seq = 1 << 24;
            assert_eq!(
                enc.encrypt(ContentType::ApplicationData, b"x"),
                Err(TlsError::SeqExhausted)
            );
        }
    }

    #[test]
    /// A local fault, not the peer's.
    fn oversized_plaintext_is_rejected_before_encryption() {
        let mut crypto =
            Tls12RecordCrypto::new(Aead::Aes128Gcm, vec![0x11; 16], vec![0; 4]).unwrap();
        assert_eq!(
            crypto.encrypt(
                ContentType::ApplicationData,
                &vec![0; crate::record::MAX_FRAGMENT + 1]
            ),
            Err(TlsError::Internal)
        );
        assert_eq!(crypto.seq, 0);
    }

    #[test]
    fn ske_roundtrip() {
        let params = ecdh_params(X25519, &[9u8; 32]);
        let body = server_key_exchange(&params, 0x0403, &[0xAAu8; 70]);
        let (g, pubk, pbytes, scheme, sig) = parse_server_key_exchange(&body).unwrap();
        assert_eq!(g, X25519);
        assert_eq!(pubk, vec![9u8; 32]);
        assert_eq!(pbytes, params);
        assert_eq!(scheme, 0x0403);
        assert_eq!(sig, vec![0xAAu8; 70]);
    }

    #[test]
    fn certificate_roundtrip() {
        let chain = vec![vec![1u8, 2, 3], vec![4u8, 5]];
        let body = certificate(&chain);
        assert_eq!(parse_certificate(&body).unwrap(), chain);
    }

    #[test]
    fn certificate_parser_rejects_trailing_and_excessive_entries() {
        let mut trailing = certificate(&[vec![1]]);
        trailing.push(0);
        assert!(parse_certificate(&trailing).is_err());

        let excessive = vec![vec![1]; crate::cert::MAX_CERTIFICATE_ENTRIES + 1];
        assert!(parse_certificate(&certificate(&excessive)).is_err());
    }

    #[test]
    fn certificate_request_parsing_and_acceptance() {
        let encode = |types: &[u8], algorithms: &[u16], names: &[&[u8]]| {
            let mut w = Writer::new();
            w.vec8(|w| w.bytes(types));
            w.vec16(|w| algorithms.iter().for_each(|scheme| w.u16(*scheme)));
            w.vec16(|w| names.iter().for_each(|name| w.vec16(|w| w.bytes(name))));
            w.buf
        };
        let request = parse_certificate_request(&encode(
            &[CERT_TYPE_ECDSA_SIGN],
            &[0x0403, 0x0804],
            &[b"dn"],
        ))
        .unwrap();
        assert!(request.accepts(0x0403));
        assert!(
            !request.accepts(0x0804),
            "RSA 키는 rsa_sign 종류가 있어야 받아 줍니다"
        );
        assert!(
            !request.accepts(0x0503),
            "알리지 않은 서명 방식은 받아 주지 않습니다"
        );

        assert!(parse_certificate_request(&encode(&[], &[0x0403], &[])).is_err());
        assert!(parse_certificate_request(&encode(&[64], &[], &[])).is_err());
        assert!(parse_certificate_request(&encode(&[64], &[0x0403], &[b""])).is_err());
        let mut trailing = encode(&[64], &[0x0403], &[]);
        trailing.push(0);
        assert!(parse_certificate_request(&trailing).is_err());
    }

    #[test]
    fn cke_roundtrip() {
        let body = client_key_exchange(&[0x04u8; 65]);
        assert_eq!(parse_client_key_exchange(&body).unwrap(), vec![0x04u8; 65]);
        let mut trailing = body;
        trailing.push(0);
        assert!(parse_client_key_exchange(&trailing).is_err());
        assert!(parse_client_key_exchange(&[0]).is_err());
    }
}
