/*!
 * @brief 레코드 보호.
 *
 * @details 논스는 기준값과 순서 번호를 XOR해 만든다. 순서 번호는 레코드마다 하나씩 는다.
 * @warning 같은 키로 같은 논스를 두 번 쓰면 AEAD가 전부 무너진다. 순서 번호가 넘칠
 *          지경이면 이어 가지 않고 실패한다.
 */

use crate::msg::consts;
use crate::record::{ContentType, TlsRecord, LEGACY_VERSION, MAX_FRAGMENT};
use crate::TlsError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 쓸 수 있는 알고리즘. */
pub enum Aead {
    /** @brief AES-128 GCM. */
    Aes128Gcm,
    /** @brief AES-256 GCM. */
    Aes256Gcm,
    /** @brief ChaCha20-Poly1305. */
    ChaCha20Poly1305,
}

/** @brief AES-GCM 키 하나로 보낼 레코드 상한. RFC 9846보다 보수적이다. */
const AES_GCM_MAX_ENCRYPTED_RECORDS: u64 = 1 << 24;

impl Aead {
    /** @brief 키 갱신 없이 보낼 수 있는 레코드 수. */
    pub(crate) fn encryption_limit(self) -> u64 {
        match self {
            Aead::Aes128Gcm | Aead::Aes256Gcm => AES_GCM_MAX_ENCRYPTED_RECORDS,
            Aead::ChaCha20Poly1305 => u64::MAX,
        }
    }
}

/** @brief 암호 스위트에 맞는 알고리즘. 모르는 스위트면 없다. */
pub fn aead_for_suite(suite: u16) -> Option<Aead> {
    match suite {
        consts::TLS_AES_128_GCM_SHA256 => Some(Aead::Aes128Gcm),
        consts::TLS_AES_256_GCM_SHA384 => Some(Aead::Aes256Gcm),
        consts::TLS_CHACHA20_POLY1305_SHA256 => Some(Aead::ChaCha20Poly1305),
        _ => None,
    }
}

/** @brief 인증 태그 길이. */
const TAG_LEN: usize = 16;

/** @brief 한 방향의 레코드 보호 상태. 키와 순서 번호를 가지고 있다. */
pub struct RecordCrypto {
    /** @brief 쓰는 암호 방식. */
    aead: Aead,
    /** @brief 암호화하고 복호화하는 키. */
    key: Vec<u8>,
    /** @brief nonce의 고정 부분. */
    iv: [u8; 12],
    /** @brief 레코드 일련번호. nonce의 나머지를 이룬다. */
    seq: u64,
}

impl Drop for RecordCrypto {
    /** @brief 키 바이트를 지운다. 메모리에 남기지 않는다. */
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl RecordCrypto {
    /** @brief 키와 기준 논스로 만든다. */
    pub fn new(aead: Aead, key: Vec<u8>, iv: [u8; 12]) -> Self {
        Self {
            aead,
            key,
            iv,
            seq: 0,
        }
    }

    /** @brief 지금 순서 번호로 논스를 만든다. */
    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        let seq = self.seq.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= seq[i];
        }
        n
    }

    /** @brief 추가 인증 데이터. 레코드 헤더가 그대로 들어간다. */
    fn aad(ct_len: usize) -> [u8; 5] {
        [
            ContentType::ApplicationData.0,
            (LEGACY_VERSION >> 8) as u8,
            LEGACY_VERSION as u8,
            (ct_len >> 8) as u8,
            ct_len as u8,
        ]
    }

    /**
     * @brief 레코드 하나를 암호화한다.
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
        let mut inner = Vec::with_capacity(plaintext.len() + 1);
        inner.extend_from_slice(plaintext);
        inner.push(content_type.0);
        let nonce = self.nonce();
        let ct_len = inner.len() + TAG_LEN;
        let aad = Self::aad(ct_len);
        let fragment = aead_seal(self.aead, &self.key, &nonce, &aad, &inner);

        self.seq = self.seq.checked_add(1).ok_or(TlsError::SeqExhausted)?;
        Ok(TlsRecord::new(ContentType::ApplicationData, fragment))
    }

    /** @brief 다음 응용 레코드 전에 키를 바꿔야 하는지. 갱신 메시지 하나는 남긴다. */
    pub(crate) fn needs_key_update(&self) -> bool {
        self.seq >= self.aead.encryption_limit().saturating_sub(1)
    }

    #[cfg(test)]
    /** @brief 키 갱신 경계 테스트를 위해 마지막 허용 sequence로 옮긴다. */
    pub(crate) fn move_to_last_encryption_for_test(&mut self) {
        self.seq = self.aead.encryption_limit().saturating_sub(1);
    }

    /**
     * @brief 레코드 하나를 복호화한다. 인증이 맞지 않으면 실패다.
     * @details 바깥 버전이 다르면 인증 데이터가 달라져 어차피 풀리지 않으므로, 풀어 보기 전에
     *          같은 사유인 Decrypt 로 거부한다. 채움을 걷어 낸 뒤 내용 종류가 남지 않으면
     *          RFC 8446 이 정한 대로 unexpected_message 다.
     * @retval TlsError::RecordOverflow 내용 종류와 채움을 더한 평문이 2^14 + 1 바이트를 넘는다.
     *         바깥 레코드의 여유분 256 바이트는 태그와 확장 몫이고 평문 몫이 아니다.
     */
    pub fn decrypt(&mut self, record: &TlsRecord) -> Result<(ContentType, Vec<u8>), TlsError> {
        if record.content_type != ContentType::ApplicationData {
            return Err(TlsError::UnexpectedMessage);
        }
        if record.version != LEGACY_VERSION {
            return Err(TlsError::Decrypt);
        }
        let nonce = self.nonce();
        let aad = Self::aad(record.fragment.len());
        let mut plain = aead_open(self.aead, &self.key, &nonce, &aad, &record.fragment)?;
        self.seq = self.seq.checked_add(1).ok_or(TlsError::SeqExhausted)?;
        if plain.len() > MAX_FRAGMENT + 1 {
            return Err(TlsError::RecordOverflow);
        }

        while plain.last() == Some(&0) {
            plain.pop();
        }
        let ct = plain.pop().ok_or(TlsError::UnexpectedMessage)?;
        Ok((ContentType(ct), plain))
    }
}

/** @brief 알고리즘을 골라 봉인한다. */
pub(crate) fn aead_seal(
    aead: Aead,
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    msg: &[u8],
) -> Vec<u8> {
    use aes_gcm::aead::{Aead as _, KeyInit, Payload};
    match aead {
        Aead::Aes128Gcm => {
            let c = aes_gcm::Aes128Gcm::new_from_slice(key)
                .expect("Cipher key length must match the algorithm");
            c.encrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg, aad })
                .expect("seal")
        }
        Aead::Aes256Gcm => {
            let c = aes_gcm::Aes256Gcm::new_from_slice(key)
                .expect("Cipher key length must match the algorithm");
            c.encrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg, aad })
                .expect("seal")
        }
        Aead::ChaCha20Poly1305 => {
            use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload as CPayload};
            let c = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
                .expect("Cipher key length must match the algorithm");
            c.encrypt(
                chacha20poly1305::Nonce::from_slice(nonce),
                CPayload { msg, aad },
            )
            .expect("seal")
        }
    }
}

/**
 * @brief 알고리즘을 골라 푼다.
 * @retval TlsError::Internal 키 길이가 알고리즘과 맞지 않는다. 상대와 무관한 이쪽 잘못이다.
 * @retval TlsError::Decrypt 인증이 맞지 않는다.
 */
pub(crate) fn aead_open(
    aead: Aead,
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, TlsError> {
    use aes_gcm::aead::{Aead as _, KeyInit, Payload};
    let r = match aead {
        Aead::Aes128Gcm => {
            let c = aes_gcm::Aes128Gcm::new_from_slice(key).map_err(|_| TlsError::Internal)?;
            c.decrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg: ct, aad })
        }
        Aead::Aes256Gcm => {
            let c = aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| TlsError::Internal)?;
            c.decrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg: ct, aad })
        }
        Aead::ChaCha20Poly1305 => {
            use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload as CPayload};
            let c = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| TlsError::Internal)?;
            c.decrypt(
                chacha20poly1305::Nonce::from_slice(nonce),
                CPayload { msg: ct, aad },
            )
        }
    };
    r.map_err(|_| TlsError::Decrypt)
}

#[cfg(test)]
/** @brief 알고리즘별 왕복과, 변조·잘못된 키·순서 번호 소진에서의 실패. */
mod tests {
    use super::*;

    /** @brief 암호화하고 디코딩해 같은지 확인한다. */
    fn roundtrip(aead: Aead, key: Vec<u8>) {
        let iv = [0x24u8; 12];
        let mut enc = RecordCrypto::new(aead, key.clone(), iv);
        let mut dec = RecordCrypto::new(aead, key, iv);

        let rec = enc
            .encrypt(ContentType::Handshake, b"finished-data")
            .unwrap();
        assert_eq!(rec.content_type, ContentType::ApplicationData);
        let (ct, pt) = dec.decrypt(&rec).unwrap();
        assert_eq!(ct, ContentType::Handshake);
        assert_eq!(pt, b"finished-data");

        let rec2 = enc
            .encrypt(ContentType::ApplicationData, b"finished-data")
            .unwrap();
        assert_ne!(rec.fragment, rec2.fragment);
        let (ct2, pt2) = dec.decrypt(&rec2).unwrap();
        assert_eq!(ct2, ContentType::ApplicationData);
        assert_eq!(pt2, b"finished-data");
    }

    #[test]
    /** @brief AES-128-GCM 왕복. */
    fn aes128gcm_roundtrip() {
        roundtrip(Aead::Aes128Gcm, vec![0x11; 16]);
    }
    #[test]
    /** @brief AES-256-GCM 왕복. */
    fn aes256gcm_roundtrip() {
        roundtrip(Aead::Aes256Gcm, vec![0x22; 32]);
    }
    #[test]
    /** @brief ChaCha20-Poly1305 왕복. */
    fn chacha20poly1305_roundtrip() {
        roundtrip(Aead::ChaCha20Poly1305, vec![0x33; 32]);
    }

    #[test]
    /** @brief 한 바이트만 바꿔도 인증이 실패하는지. */
    fn tamper_detected() {
        let key = vec![0x11; 16];
        let iv = [0u8; 12];
        let mut enc = RecordCrypto::new(Aead::Aes128Gcm, key.clone(), iv);
        let mut dec = RecordCrypto::new(Aead::Aes128Gcm, key, iv);
        let mut rec = enc
            .encrypt(ContentType::ApplicationData, b"secret")
            .unwrap();
        rec.fragment[0] ^= 0xFF;
        assert_eq!(dec.decrypt(&rec), Err(TlsError::Decrypt));
    }

    #[test]
    /** @brief 다른 키로는 풀리지 않는지. */
    fn wrong_key_fails() {
        let iv = [0u8; 12];
        let mut enc = RecordCrypto::new(Aead::ChaCha20Poly1305, vec![0xAA; 32], iv);
        let mut dec = RecordCrypto::new(Aead::ChaCha20Poly1305, vec![0xBB; 32], iv);
        let rec = enc
            .encrypt(ContentType::ApplicationData, b"secret")
            .unwrap();
        assert!(dec.decrypt(&rec).is_err());
    }

    #[test]
    /** @brief TLS 1.3 보호 레코드의 외부 type·version 변조를 복호화 전에 거부하는지. */
    fn protected_record_header_is_canonical() {
        let key = vec![0x11; 16];
        let iv = [0x22; 12];
        let mut sender = RecordCrypto::new(Aead::Aes128Gcm, key.clone(), iv);
        let record = sender
            .encrypt(ContentType::ApplicationData, b"dns")
            .unwrap();

        let mut wrong_type = record.clone();
        wrong_type.content_type = ContentType::Handshake;
        let mut receiver = RecordCrypto::new(Aead::Aes128Gcm, key.clone(), iv);
        assert_eq!(
            receiver.decrypt(&wrong_type),
            Err(TlsError::UnexpectedMessage)
        );
        assert_eq!(
            receiver.decrypt(&record),
            Ok((ContentType::ApplicationData, b"dns".to_vec()))
        );

        let mut wrong_version = record;
        wrong_version.version = 0x0302;
        let mut receiver = RecordCrypto::new(Aead::Aes128Gcm, key, iv);
        assert_eq!(receiver.decrypt(&wrong_version), Err(TlsError::Decrypt));
    }

    #[test]
    /** @brief 채움만 있고 내용 종류가 없는 평문을 unexpected_message 사유로 거부하는지. */
    fn all_zero_inner_plaintext_is_unexpected() {
        let key = vec![0x11; 16];
        let iv = [0x22; 12];
        let nonce = {
            let sender = RecordCrypto::new(Aead::Aes128Gcm, key.clone(), iv);
            sender.nonce()
        };
        let inner = [0u8; 4];
        let aad = RecordCrypto::aad(inner.len() + TAG_LEN);
        let fragment = aead_seal(Aead::Aes128Gcm, &key, &nonce, &aad, &inner);
        let record = TlsRecord::new(ContentType::ApplicationData, fragment);
        let mut receiver = RecordCrypto::new(Aead::Aes128Gcm, key, iv);
        assert_eq!(receiver.decrypt(&record), Err(TlsError::UnexpectedMessage));
    }

    #[test]
    /**
     * @brief 채움까지 더한 평문이 2^14 + 1 바이트를 넘으면 record_overflow 인지.
     * @details 채움을 걷어 낸 내용은 한도 안이어도 RFC 8446 은 내용 종류와 채움을 더한 평문
     *          전체에 한도를 건다.
     */
    fn padded_inner_plaintext_over_the_limit_is_record_overflow() {
        let key = vec![0x11; 16];
        let iv = [0x22; 12];
        let nonce = RecordCrypto::new(Aead::Aes128Gcm, key.clone(), iv).nonce();
        let open = |inner: &[u8]| {
            let aad = RecordCrypto::aad(inner.len() + TAG_LEN);
            let fragment = aead_seal(Aead::Aes128Gcm, &key, &nonce, &aad, inner);
            RecordCrypto::new(Aead::Aes128Gcm, key.clone(), iv)
                .decrypt(&TlsRecord::new(ContentType::ApplicationData, fragment))
                .map(|(_, plaintext)| plaintext.len())
        };
        let mut inner = vec![0x7a; MAX_FRAGMENT];
        inner.push(ContentType::ApplicationData.0);
        assert_eq!(open(&inner), Ok(MAX_FRAGMENT));
        inner.push(0);
        assert_eq!(open(&inner), Err(TlsError::RecordOverflow));
    }

    #[test]
    /** @brief 순서 번호가 다하면 되감지 않고 실패하는지. 되감기면 논스가 되풀이된다. */
    fn seq_exhaustion_fails_closed() {
        let key = vec![0x11; 32];
        let iv = [0u8; 12];
        let mut enc = RecordCrypto::new(Aead::ChaCha20Poly1305, key, iv);
        enc.seq = u64::MAX;

        assert_eq!(
            enc.encrypt(ContentType::ApplicationData, b"x"),
            Err(TlsError::SeqExhausted)
        );
    }

    #[test]
    /** @brief AES-GCM이 안전 사용량을 넘어 암복호하지 않는지. */
    fn aes_gcm_key_usage_limit_fails_closed() {
        for (aead, key) in [
            (Aead::Aes128Gcm, vec![0x11; 16]),
            (Aead::Aes256Gcm, vec![0x22; 32]),
        ] {
            let mut enc = RecordCrypto::new(aead, key, [0; 12]);
            enc.seq = 1 << 24;
            assert_eq!(
                enc.encrypt(ContentType::ApplicationData, b"x"),
                Err(TlsError::SeqExhausted)
            );
        }
    }

    #[test]
    /** @brief 평문 상한을 넘는 레코드를 만들지 않고, 이쪽 잘못으로 보는지. */
    fn oversized_plaintext_is_rejected_before_encryption() {
        let mut crypto = RecordCrypto::new(Aead::Aes128Gcm, vec![0x11; 16], [0; 12]);
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
    /** @brief 스위트에서 알고리즘이 제대로 골라지는지. */
    fn suite_to_aead() {
        assert_eq!(
            aead_for_suite(consts::TLS_AES_128_GCM_SHA256),
            Some(Aead::Aes128Gcm)
        );
        assert_eq!(
            aead_for_suite(consts::TLS_AES_256_GCM_SHA384),
            Some(Aead::Aes256Gcm)
        );
        assert_eq!(
            aead_for_suite(consts::TLS_CHACHA20_POLY1305_SHA256),
            Some(Aead::ChaCha20Poly1305)
        );
        assert_eq!(aead_for_suite(0), None);
    }
}
