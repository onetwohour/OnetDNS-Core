/*!
 * @brief TLS 1.2 전용 부분.
 *
 * @details 1.3과 키 유도, 레코드 보호, 핸드셰이크 메시지가 모두 다르다. 앞선 방식을 쓰는
 *          상대와 통해야 해서 남겨 둔 것이다.
 * @note 전방 비밀성이 없는 스위트는 아예 넣지 않았다. 목록에 없으면 협상될 수 없다.
 */

use hmac::Mac;
use zeroize::Zeroizing;

use crate::aead::{aead_open, aead_seal, Aead};
use crate::keyschedule::Hash;
use crate::msg::consts::{SECP256R1, X25519};
use crate::record::{ContentType, TlsRecord, LEGACY_VERSION};
use crate::wire::{Reader, Writer};
use crate::TlsError;

/** @brief 이쪽이 지원하는 암호 스위트. */
pub mod suites {
    /** @brief ECDSA 인증에 AES-128-GCM. */
    pub const ECDHE_ECDSA_AES128_GCM_SHA256: u16 = 0xC02B;
    /** @brief ECDSA 인증에 AES-256-GCM. */
    pub const ECDHE_ECDSA_AES256_GCM_SHA384: u16 = 0xC02C;
    /** @brief RSA 인증에 AES-128-GCM. */
    pub const ECDHE_RSA_AES128_GCM_SHA256: u16 = 0xC02F;
    /** @brief RSA 인증에 AES-256-GCM. */
    pub const ECDHE_RSA_AES256_GCM_SHA384: u16 = 0xC030;
    /** @brief ECDSA 인증에 ChaCha20. */
    pub const ECDHE_ECDSA_CHACHA20_SHA256: u16 = 0xCCA9;
    /** @brief RSA 인증에 ChaCha20. */
    pub const ECDHE_RSA_CHACHA20_SHA256: u16 = 0xCCA8;
}

/** @brief 점 형식 확장. 압축하지 않은 형식만 쓴다. */
pub const EXT_EC_POINT_FORMATS: u16 = 11;
/** @brief 확장 마스터 비밀. 핸드셰이크 기록을 키 유도에 묶어 세션 혼동 공격을 막는다. */
pub const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
/** @brief 재협상 정보. 이쪽은 재협상하지 않으므로 빈 값을 보낸다. */
pub const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/** @brief 핸드셰이크 확인 값 길이. */
const VERIFY_DATA_LEN: usize = 12;

#[derive(Debug, Clone, Copy)]
/** @brief 스위트 하나의 매개변수. */
pub struct Suite12 {
    /** @brief 쓰는 암호 방식. */
    pub aead: Aead,
    /** @brief 쓰는 요약 방식. */
    pub hash: Hash,
    /** @brief 키 길이. */
    pub key_len: usize,
    /** @brief 타원곡선 서명을 쓰는지. */
    pub ecdsa: bool,
}

/** @brief 스위트 번호에서 매개변수를 얻는다. */
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

/** @brief 클라이언트로서 제안할 스위트들. */
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

/** @brief 상대가 제안한 것 중 이쪽 인증서로 쓸 수 있는 것을 고른다. */
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

/** @brief 지원하는 곡선들. */
pub fn supported_groups() -> [u16; 2] {
    [X25519, SECP256R1]
}

/** @brief 이 곡선을 지원하는지. */
pub fn group_supported(g: u16) -> bool {
    g == X25519 || g == SECP256R1
}

/** @brief HMAC. */
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

/** @brief 1.2의 확장 함수. 필요한 길이만큼 반복해 늘린다. */
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

/** @brief 1.2의 의사난수 함수. 레이블과 시드로 키 재료를 만든다. */
pub fn prf(hash: Hash, secret: &[u8], label: &str, seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut ls = label.as_bytes().to_vec();
    ls.extend_from_slice(seed);
    p_hash(hash, secret, &ls, out_len)
}

/** @brief 키 교환 결과에서 마스터 비밀을 만든다. */
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

/**
 * @brief 핸드셰이크 기록을 넣어 마스터 비밀을 만든다.
 * @warning 이쪽을 써야 세션 혼동 공격을 막는다. 원래 방식은 무작위 값만 쓰므로 서로 다른
 *          핸드셰이크가 같은 비밀에 이를 수 있다.
 */
pub fn extended_master_secret(hash: Hash, pms: &[u8], session_hash: &[u8]) -> Vec<u8> {
    prf(hash, pms, "extended master secret", session_hash, 48)
}

/** @brief 양방향 키와 논스 기준값. */
pub struct KeyMaterial {
    /** @brief 클라이언트가 보낼 때 쓰는 키. */
    pub client_key: Vec<u8>,
    /** @brief 서버가 보낼 때 쓰는 키. */
    pub server_key: Vec<u8>,
    /** @brief 클라이언트 쪽 nonce의 고정 부분. */
    pub client_iv: [u8; 4],
    /** @brief 서버 쪽 nonce의 고정 부분. */
    pub server_iv: [u8; 4],
}

/** @brief 마스터 비밀에서 실제 키들을 갈라낸다. */
pub fn key_material(
    hash: Hash,
    master: &[u8],
    client_random: &[u8],
    server_random: &[u8],
    key_len: usize,
) -> KeyMaterial {
    let mut seed = server_random.to_vec();
    seed.extend_from_slice(client_random);
    let need = 2 * key_len + 2 * 4;
    let kb = Zeroizing::new(prf(hash, master, "key expansion", &seed, need));
    let client_key = kb[..key_len].to_vec();
    let server_key = kb[key_len..2 * key_len].to_vec();
    let mut client_iv = [0u8; 4];
    let mut server_iv = [0u8; 4];
    client_iv.copy_from_slice(&kb[2 * key_len..2 * key_len + 4]);
    server_iv.copy_from_slice(&kb[2 * key_len + 4..2 * key_len + 8]);
    KeyMaterial {
        client_key,
        server_key,
        client_iv,
        server_iv,
    }
}

/** @brief 핸드셰이크 기록을 확인하는 값. */
pub fn finished_verify_data(hash: Hash, master: &[u8], label: &str, transcript: &[u8]) -> Vec<u8> {
    let session_hash = hash.digest(transcript);
    prf(hash, master, label, &session_hash, VERIFY_DATA_LEN)
}

/** @brief 1.2 레코드 보호. 논스에 명시 부분이 실려 온다. */
pub struct Tls12RecordCrypto {
    /** @brief 쓰는 암호 방식. */
    aead: Aead,
    /** @brief 암호화하고 복호화하는 키. */
    key: Vec<u8>,
    /** @brief nonce의 고정 부분. */
    salt: [u8; 4],
    /** @brief 레코드 일련번호. */
    seq: u64,
}

impl Drop for Tls12RecordCrypto {
    /** @brief 키 바이트를 지운다. */
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
        self.salt.zeroize();
    }
}

impl Tls12RecordCrypto {
    /** @brief 키와 논스 앞부분으로 만든다. */
    pub fn new(aead: Aead, key: Vec<u8>, salt: [u8; 4]) -> Self {
        Self {
            aead,
            key,
            salt,
            seq: 0,
        }
    }

    /** @brief 추가 인증 데이터. 순서 번호와 레코드 헤더가 들어간다. */
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

    /** @brief 고정 앞부분과 명시 뒷부분을 이어 논스를 만든다. */
    fn nonce(&self, explicit: &[u8; 8]) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(&self.salt);
        n[4..].copy_from_slice(explicit);
        n
    }

    /**
     * @brief 레코드를 암호화한다.
     * @warning 순서 번호가 넘칠 지경이면 실패한다. 되감기면 논스가 되풀이돼 보호가 무너진다.
     */
    pub fn encrypt(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
    ) -> Result<TlsRecord, TlsError> {
        if plaintext.len() > crate::record::MAX_FRAGMENT {
            return Err(TlsError::RecordOverflow);
        }
        if self.seq >= self.aead.encryption_limit() {
            return Err(TlsError::SeqExhausted);
        }
        let explicit = self.seq.to_be_bytes();
        let nonce = self.nonce(&explicit);
        let aad = Self::aad(self.seq, content_type, plaintext.len());
        let sealed = aead_seal(self.aead, &self.key, &nonce, &aad, plaintext);
        let mut fragment = Vec::with_capacity(8 + sealed.len());
        fragment.extend_from_slice(&explicit);
        fragment.extend_from_slice(&sealed);

        self.seq = self.seq.checked_add(1).ok_or(TlsError::SeqExhausted)?;
        Ok(TlsRecord::new(content_type, fragment))
    }

    /** @brief 레코드를 복호화한다. 순서 번호가 어긋나면 실패다. */
    pub fn decrypt(&mut self, record: &TlsRecord) -> Result<Vec<u8>, TlsError> {
        if record.fragment.len() < 8 + 16 {
            return Err(TlsError::Decrypt);
        }
        let mut explicit = [0u8; 8];
        explicit.copy_from_slice(&record.fragment[..8]);
        let ct = &record.fragment[8..];
        let plaintext_len = ct.len() - 16;
        let nonce = self.nonce(&explicit);
        let aad = Self::aad(self.seq, record.content_type, plaintext_len);
        let plain = aead_open(self.aead, &self.key, &nonce, &aad, ct)?;
        self.seq = self.seq.checked_add(1).ok_or(TlsError::SeqExhausted)?;
        Ok(plain)
    }
}

/** @brief 키 교환 매개변수를 쓴다. 곡선과 공개값이 들어간다. */
pub fn ecdh_params(group: u16, public: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(3);
    w.u16(group);
    w.vec8(|w| w.bytes(public));
    w.buf
}

/** @brief 서버 키 교환 메시지를 만든다. 매개변수에 서명이 붙는다. */
pub fn server_key_exchange(params: &[u8], sig_scheme: u16, signature: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(params);
    w.u16(sig_scheme);
    w.vec16(|w| w.bytes(signature));
    w.buf
}

#[allow(clippy::type_complexity)]
/** @brief 서버 키 교환 메시지를 읽는다. */
pub fn parse_server_key_exchange(
    body: &[u8],
) -> Result<(u16, Vec<u8>, Vec<u8>, u16, Vec<u8>), TlsError> {
    let mut r = Reader::new(body);
    let curve_type = r.u8()?;
    if curve_type != 3 {
        return Err(TlsError::Protocol);
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

/** @brief 클라이언트 키 교환 메시지를 만든다. */
pub fn client_key_exchange(public: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.vec8(|w| w.bytes(public));
    w.buf
}

/** @brief 클라이언트 키 교환 메시지를 읽는다. */
pub fn parse_client_key_exchange(body: &[u8]) -> Result<Vec<u8>, TlsError> {
    let mut r = Reader::new(body);
    let public = r.vec8()?.to_vec();
    if public.is_empty() || !r.is_empty() {
        return Err(TlsError::Decode);
    }
    Ok(public)
}

/** @brief 인증서 메시지를 만든다. */
pub fn certificate(chain: &[Vec<u8>]) -> Vec<u8> {
    let mut w = Writer::new();
    w.vec24(|w| {
        for cert in chain {
            w.vec24(|w| w.bytes(cert));
        }
    });
    w.buf
}

/** @brief 인증서 메시지를 읽는다. */
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
        if certificate.is_empty() || out.len() >= crate::cert::MAX_CERTIFICATE_ENTRIES {
            return Err(TlsError::RecordOverflow);
        }
        out.push(certificate.to_vec());
    }
    Ok(out)
}

/**
 * @brief 서버 키 교환 서명의 대상 바이트.
 * @details 양쪽 무작위 값과 매개변수를 잇는다. 무작위 값이 들어가야 서명을 다른 핸드셰이크에
 *          되쓸 수 없다.
 */
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

/** @brief 점 형식 확장을 만든다. */
pub fn ext_ec_point_formats() -> crate::msg::Extension {
    let mut w = Writer::new();
    w.vec8(|w| w.u8(0));
    crate::msg::Extension::new(EXT_EC_POINT_FORMATS, w.buf)
}

/** @brief 확장 마스터 비밀 확장을 만든다. */
pub fn ext_extended_master_secret() -> crate::msg::Extension {
    crate::msg::Extension::new(EXT_EXTENDED_MASTER_SECRET, Vec::new())
}

/** @brief 재협상 정보 확장을 만든다. 빈 값이다. */
pub fn ext_renegotiation_info() -> crate::msg::Extension {
    let mut w = Writer::new();
    w.vec8(|_w| {});
    crate::msg::Extension::new(EXT_RENEGOTIATION_INFO, w.buf)
}

#[cfg(test)]
/** @brief 키 유도의 결정성, 레코드 왕복, 그리고 메시지 왕복. */
mod tests {
    use super::*;

    #[test]
    /** @brief 확장 함수가 결정적이고 요청한 길이를 내는지. */
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
    /** @brief 양쪽이 같은 키를 얻는지. */
    fn master_and_keyblock_symmetry() {
        let pms = [7u8; 32];
        let cr = [1u8; 32];
        let sr = [2u8; 32];
        let ms = master_secret(Hash::Sha256, &pms, &cr, &sr);
        assert_eq!(ms.len(), 48);
        let km = key_material(Hash::Sha256, &ms, &cr, &sr, 16);
        assert_eq!(km.client_key.len(), 16);
        assert_eq!(km.server_key.len(), 16);
        assert_ne!(km.client_key, km.server_key);
        assert_ne!(km.client_iv, km.server_iv);
    }

    #[test]
    /** @brief 레코드 왕복. */
    fn record_crypto_roundtrip() {
        let key = vec![0x33u8; 16];
        let salt = [0xAB, 0xCD, 0xEF, 0x12];
        let mut enc = Tls12RecordCrypto::new(Aead::Aes128Gcm, key.clone(), salt);
        let mut dec = Tls12RecordCrypto::new(Aead::Aes128Gcm, key, salt);

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
    /** @brief 변조와 순서 뒤바뀜을 거부하는지. */
    fn record_crypto_tamper_and_reorder_rejected() {
        let key = vec![0x44u8; 32];
        let salt = [0u8; 4];
        let mut enc = Tls12RecordCrypto::new(Aead::Aes256Gcm, key.clone(), salt);
        let mut dec = Tls12RecordCrypto::new(Aead::Aes256Gcm, key, salt);
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
    /** @brief 순서 번호가 다하면 되감지 않고 실패하는지. */
    fn seq_exhaustion_fails_closed() {
        let key = vec![0x33u8; 32];
        let salt = [0xAB, 0xCD, 0xEF, 0x12];
        let mut enc = Tls12RecordCrypto::new(Aead::ChaCha20Poly1305, key, salt);
        enc.seq = u64::MAX;
        assert_eq!(
            enc.encrypt(ContentType::ApplicationData, b"x"),
            Err(TlsError::SeqExhausted)
        );
    }

    #[test]
    /** @brief TLS 1.2 AES-GCM도 키 안전 사용량을 넘지 않는지. */
    fn aes_gcm_key_usage_limit_fails_closed() {
        for (aead, key) in [
            (Aead::Aes128Gcm, vec![0x11; 16]),
            (Aead::Aes256Gcm, vec![0x22; 32]),
        ] {
            let mut enc = Tls12RecordCrypto::new(aead, key, [0; 4]);
            enc.seq = 1 << 24;
            assert_eq!(
                enc.encrypt(ContentType::ApplicationData, b"x"),
                Err(TlsError::SeqExhausted)
            );
        }
    }

    #[test]
    /** @brief TLS 1.2도 평문 상한을 넘는 레코드를 만들지 않는지. */
    fn oversized_plaintext_is_rejected_before_encryption() {
        let mut crypto = Tls12RecordCrypto::new(Aead::Aes128Gcm, vec![0x11; 16], [0; 4]);
        assert_eq!(
            crypto.encrypt(
                ContentType::ApplicationData,
                &vec![0; crate::record::MAX_FRAGMENT + 1]
            ),
            Err(TlsError::RecordOverflow)
        );
        assert_eq!(crypto.seq, 0);
    }

    #[test]
    /** @brief 서버 키 교환 메시지 왕복. */
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
    /** @brief 인증서 메시지 왕복. */
    fn certificate_roundtrip() {
        let chain = vec![vec![1u8, 2, 3], vec![4u8, 5]];
        let body = certificate(&chain);
        assert_eq!(parse_certificate(&body).unwrap(), chain);
    }

    #[test]
    /** @brief 뒤에 남는 바이트와 지나친 항목 수를 거부하는지. */
    fn certificate_parser_rejects_trailing_and_excessive_entries() {
        let mut trailing = certificate(&[vec![1]]);
        trailing.push(0);
        assert!(parse_certificate(&trailing).is_err());

        let excessive = vec![vec![1]; crate::cert::MAX_CERTIFICATE_ENTRIES + 1];
        assert!(parse_certificate(&certificate(&excessive)).is_err());
    }

    #[test]
    /** @brief 클라이언트 키 교환 메시지 왕복. */
    fn cke_roundtrip() {
        let body = client_key_exchange(&[0x04u8; 65]);
        assert_eq!(parse_client_key_exchange(&body).unwrap(), vec![0x04u8; 65]);
        let mut trailing = body;
        trailing.push(0);
        assert!(parse_client_key_exchange(&trailing).is_err());
        assert!(parse_client_key_exchange(&[0]).is_err());
    }
}
