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
/** @brief 압축하지 않은 점 형식. 이쪽이 읽고 쓰는 유일한 형식이다. */
pub const EC_POINT_FORMAT_UNCOMPRESSED: u8 = 0;
/** @brief 확장 마스터 비밀. 핸드셰이크 기록을 키 유도에 묶어 세션 혼동 공격을 막는다. */
pub const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
/** @brief 재협상 정보. 이쪽은 재협상하지 않으므로 빈 값을 보낸다. */
pub const EXT_RENEGOTIATION_INFO: u16 = 0xff01;
/**
 * @brief 스위트 목록에 넣는 재협상 정보 표시. RFC 5746 은 빈 renegotiation_info 확장과 같은
 *        뜻으로 본다.
 */
pub const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: u16 = 0x00ff;
/** @brief CertificateRequest 의 인증서 종류 값. RSA 서명 키를 담은 인증서. */
pub const CERT_TYPE_RSA_SIGN: u8 = 1;
/** @brief CertificateRequest 의 인증서 종류 값. RFC 8422 는 ECDSA 와 EdDSA 키를 여기에 넣는다. */
pub const CERT_TYPE_ECDSA_SIGN: u8 = 64;

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

/** @brief 양방향 키와 nonce 고정 부분. */
pub struct KeyMaterial {
    /** @brief 클라이언트가 보낼 때 쓰는 키. */
    pub client_key: Vec<u8>,
    /** @brief 서버가 보낼 때 쓰는 키. */
    pub server_key: Vec<u8>,
    /** @brief 클라이언트 쪽 nonce 의 고정 부분. 길이는 fixed_iv_len 이 정한다. */
    pub client_iv: Vec<u8>,
    /** @brief 서버 쪽 nonce 의 고정 부분. */
    pub server_iv: Vec<u8>,
}

/**
 * @brief 이 암호 방식이 레코드마다 nonce 의 명시 부분 8 바이트를 싣는지.
 * @details AES-GCM 은 RFC 5288 대로 싣는다. ChaCha20-Poly1305 는 RFC 7905 대로 싣지 않고
 *          일련번호를 고정 부분과 XOR 해 nonce 를 만든다.
 */
fn explicit_nonce(aead: Aead) -> bool {
    !matches!(aead, Aead::ChaCha20Poly1305)
}

/** @brief 키 블록에서 가져오는 nonce 고정 부분의 길이. */
fn fixed_iv_len(aead: Aead) -> usize {
    if explicit_nonce(aead) {
        4
    } else {
        12
    }
}

/** @brief 마스터 비밀에서 실제 키들을 갈라낸다. 고정 nonce 길이는 스위트의 암호 방식을 따른다. */
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

/** @brief 핸드셰이크 기록을 확인하는 값. */
pub fn finished_verify_data(hash: Hash, master: &[u8], label: &str, transcript: &[u8]) -> Vec<u8> {
    let session_hash = hash.digest(transcript);
    prf(hash, master, label, &session_hash, VERIFY_DATA_LEN)
}

/** @brief 1.2 레코드 보호. nonce 구성은 암호 방식마다 다르다. explicit_nonce 를 본다. */
pub struct Tls12RecordCrypto {
    /** @brief 쓰는 암호 방식. */
    aead: Aead,
    /** @brief 암호화하고 복호화하는 키. */
    key: Vec<u8>,
    /** @brief nonce 의 고정 부분. 길이가 fixed_iv_len 과 같다. */
    iv: Vec<u8>,
    /** @brief 레코드 일련번호. */
    seq: u64,
}

impl Drop for Tls12RecordCrypto {
    /** @brief 키 바이트를 지운다. */
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl Tls12RecordCrypto {
    /**
     * @brief 키와 nonce 고정 부분으로 만든다.
     * @retval TlsError::Internal 고정 부분 길이가 암호 방식에 맞지 않는다.
     */
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

    /**
     * @brief nonce 를 만든다.
     * @param explicit AES-GCM 이면 레코드에 실린 명시 부분, ChaCha20-Poly1305 면 일련번호.
     */
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

    /** @brief 레코드 앞에 싣는 명시 nonce 의 길이. */
    fn explicit_len(&self) -> usize {
        if explicit_nonce(self.aead) {
            8
        } else {
            0
        }
    }

    /**
     * @brief 레코드를 암호화한다.
     * @warning 순서 번호가 넘칠 지경이면 실패한다. 되감기면 논스가 되풀이돼 보호가 무너진다.
     * @retval TlsError::Internal 평문이 레코드 상한을 넘는다. 나눠 보내지 않은 호출자의
     *         잘못이므로 상대에게 record_overflow 를 알리면 안 된다.
     */
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

    /**
     * @brief 레코드를 복호화한다. 순서 번호가 어긋나면 실패다.
     * @retval TlsError::RecordOverflow 평문이 2^14 바이트를 넘는다. 이쪽은 압축을 쓰지 않으므로
     *         RFC 5246 이 평문에 정한 상한이 그대로 걸린다.
     */
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

/**
 * @brief 인증서 메시지를 읽는다.
 * @retval TlsError::Decode 형식이 깨졌거나 빈 인증서가 있다.
 * @retval TlsError::BadCert 인증서가 이쪽이 검증할 개수 상한보다 많다.
 */
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

/** @brief 1.2 서버가 보낸 인증서 요청 가운데 이쪽이 쓰는 부분. */
pub struct CertificateRequest12 {
    /** @brief 받아 주는 인증서 종류. */
    pub certificate_types: Vec<u8>,
    /** @brief 받아 주는 서명 방식. */
    pub signature_algorithms: Vec<u16>,
}

impl CertificateRequest12 {
    /**
     * @brief 이 서명 방식으로 만든 서명과 그 키를 담은 인증서를 받아 주는지.
     * @details 인증서 종류는 키 종류로 정한다. RFC 8422 는 Ed25519 키도 ecdsa_sign 에 넣는다.
     */
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

/**
 * @brief 1.2 CertificateRequest 를 읽는다. 인증 기관 목록은 쓰지 않으므로 형식만 확인한다.
 * @retval TlsError::Decode 형식이 깨졌거나, 비어 있으면 안 되는 목록이 비었다.
 */
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
    w.vec8(|w| w.u8(EC_POINT_FORMAT_UNCOMPRESSED));
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
    /**
     * @brief ChaCha20-Poly1305 레코드가 RFC 7905 형식인지.
     * @details 명시 nonce 없이 암호문과 태그만 싣고, nonce 는 고정 부분과 일련번호의 XOR 이다.
     */
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
    /** @brief 고정 nonce 길이가 암호 방식에 맞지 않으면 만들지 않는지. */
    fn record_crypto_rejects_wrong_iv_length() {
        assert!(Tls12RecordCrypto::new(Aead::ChaCha20Poly1305, vec![0; 32], vec![0; 4]).is_err());
        assert!(Tls12RecordCrypto::new(Aead::Aes128Gcm, vec![0; 16], vec![0; 12]).is_err());
    }

    #[test]
    /** @brief 2^14 바이트를 넘는 평문이 든 레코드를 풀기 전에 record_overflow 로 거부하는지. */
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
    /** @brief 레코드 왕복. */
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
    /** @brief 변조와 순서 뒤바뀜을 거부하는지. */
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
    /** @brief 순서 번호가 다하면 되감지 않고 실패하는지. */
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
    /** @brief TLS 1.2 AES-GCM도 키 안전 사용량을 넘지 않는지. */
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
    /** @brief TLS 1.2도 평문 상한을 넘는 레코드를 만들지 않고, 이쪽 잘못으로 보는지. */
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
    /** @brief 1.2 CertificateRequest 를 읽고, 인증서 종류와 서명 방식이 함께 맞아야 받아 주는지. */
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
