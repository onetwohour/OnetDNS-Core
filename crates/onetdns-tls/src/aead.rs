//! Record protection. The nonce is the base IV XORed with the sequence number, which grows by one
//! per record.
//!
//! Reusing a nonce with the same key breaks AEAD completely, so when the sequence number would
//! overflow this fails instead of continuing.

use crate::msg::consts;
use crate::record::{ContentType, TlsRecord, LEGACY_VERSION, MAX_FRAGMENT};
use crate::TlsError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aead {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// Records per AES-GCM key; more conservative than RFC 9846.
const AES_GCM_MAX_ENCRYPTED_RECORDS: u64 = 1 << 24;

impl Aead {
    pub(crate) fn encryption_limit(self) -> u64 {
        match self {
            Aead::Aes128Gcm | Aead::Aes256Gcm => AES_GCM_MAX_ENCRYPTED_RECORDS,
            Aead::ChaCha20Poly1305 => u64::MAX,
        }
    }
}

pub fn aead_for_suite(suite: u16) -> Option<Aead> {
    match suite {
        consts::TLS_AES_128_GCM_SHA256 => Some(Aead::Aes128Gcm),
        consts::TLS_AES_256_GCM_SHA384 => Some(Aead::Aes256Gcm),
        consts::TLS_CHACHA20_POLY1305_SHA256 => Some(Aead::ChaCha20Poly1305),
        _ => None,
    }
}

const TAG_LEN: usize = 16;

pub struct RecordCrypto {
    aead: Aead,
    key: Vec<u8>,
    iv: [u8; 12],
    seq: u64,
}

impl Drop for RecordCrypto {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl RecordCrypto {
    pub fn new(aead: Aead, key: Vec<u8>, iv: [u8; 12]) -> Self {
        Self {
            aead,
            key,
            iv,
            seq: 0,
        }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        let seq = self.seq.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= seq[i];
        }
        n
    }

    /// The record header as is.
    fn aad(ct_len: usize) -> [u8; 5] {
        [
            ContentType::ApplicationData.0,
            (LEGACY_VERSION >> 8) as u8,
            LEGACY_VERSION as u8,
            (ct_len >> 8) as u8,
            ct_len as u8,
        ]
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

    /// Leaves room for the update message itself.
    pub(crate) fn needs_key_update(&self) -> bool {
        self.seq >= self.aead.encryption_limit().saturating_sub(1)
    }

    #[cfg(test)]
    pub(crate) fn move_to_last_encryption_for_test(&mut self) {
        self.seq = self.aead.encryption_limit().saturating_sub(1);
    }

    /// Fails when authentication fails. A different outer version changes the authenticated data so
    /// the record would not open anyway; it is rejected before trying, with the same Decrypt
    /// reason. If no content type is left after stripping padding, it is unexpected_message, as RFC
    /// 8446 requires. RecordOverflow when the plaintext with content type and padding exceeds 2^14
    /// + 1 bytes; the outer record's extra 256 bytes are for the tag and expansion, not plaintext.
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

/// Internal when the key length does not fit the algorithm, a local fault unrelated to the peer;
/// Decrypt when authentication fails.
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
mod tests {
    use super::*;

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
    fn aes128gcm_roundtrip() {
        roundtrip(Aead::Aes128Gcm, vec![0x11; 16]);
    }
    #[test]
    fn aes256gcm_roundtrip() {
        roundtrip(Aead::Aes256Gcm, vec![0x22; 32]);
    }
    #[test]
    fn chacha20poly1305_roundtrip() {
        roundtrip(Aead::ChaCha20Poly1305, vec![0x33; 32]);
    }

    #[test]
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
    /// Rejects tampering with the outer type and version before decrypting.
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
    /// The limit covers the whole plaintext with content type and padding, as RFC 8446 sets it,
    /// even when the content left after stripping padding fits.
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
    /// Wrapping would repeat the nonce.
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
    /// A local fault, not the peer's.
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
