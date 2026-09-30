/*!
 * @brief 패킷 본문 암호화와 헤더 보호.
 *
 * @details 두 겹이다. 본문은 AEAD로 감싸고, 헤더의 일부 비트와 패킷 번호는 별도 키로
 *          만든 마스크와 XOR해 가린다. 헤더 보호가 있어야 경로상 장비가 연결을
 *          추적하거나 간섭하기 어려워진다.
 */

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use aes_gcm::aead::{Aead as GcmAead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 쓸 수 있는 AEAD 알고리즘. */
pub enum Aead {
    /** @brief AES-128 GCM. */
    Aes128Gcm,
    /** @brief AES-256 GCM. */
    Aes256Gcm,
    /** @brief ChaCha20-Poly1305. */
    ChaCha20Poly1305,
}

impl Aead {
    /** @brief 이 알고리즘의 키 길이. */
    pub fn key_len(&self) -> usize {
        match self {
            Aead::Aes128Gcm => 16,
            Aead::Aes256Gcm => 32,
            Aead::ChaCha20Poly1305 => 32,
        }
    }

    /**
     * @brief 패킷 번호로 논스를 만든다. 기준값과 XOR한다.
     * @warning 같은 키로 같은 논스를 두 번 쓰면 AEAD가 전부 무너진다. 패킷 번호가
     *          중복되지 않는 것이 그 보장의 근거다.
     */
    fn nonce(iv: &[u8], pn: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&iv[..12]);
        let pnb = pn.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= pnb[i];
        }
        nonce
    }

    /** @brief 본문을 암호화한다. 헤더가 추가 인증 데이터로 들어간다. */
    pub fn seal(&self, key: &[u8], iv: &[u8], pn: u64, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let nonce = Self::nonce(iv, pn);
        let pl = Payload {
            msg: plaintext,
            aad,
        };
        match self {
            Aead::Aes128Gcm => Aes128Gcm::new(key.into())
                .encrypt(aes_gcm::Nonce::from_slice(&nonce), pl)
                .expect("AES-128-GCM key and nonce must have the correct length"),
            Aead::Aes256Gcm => Aes256Gcm::new(key.into())
                .encrypt(aes_gcm::Nonce::from_slice(&nonce), pl)
                .expect("AES-256-GCM key and nonce must have the correct length"),
            Aead::ChaCha20Poly1305 => {
                let c = ChaCha20Poly1305::new_from_slice(key)
                    .expect("ChaCha20-Poly1305 key must be 32 bytes");
                c.encrypt(chacha20poly1305::Nonce::from_slice(&nonce), pl)
                    .expect("ChaCha20-Poly1305 key and nonce must have the correct length")
            }
        }
    }

    /** @brief 본문을 복호화한다. 인증이 맞지 않으면 실패다. */
    pub fn open(
        &self,
        key: &[u8],
        iv: &[u8],
        pn: u64,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        let nonce = Self::nonce(iv, pn);
        let pl = Payload {
            msg: ciphertext,
            aad,
        };
        match self {
            Aead::Aes128Gcm => Aes128Gcm::new(key.into())
                .decrypt(aes_gcm::Nonce::from_slice(&nonce), pl)
                .ok(),
            Aead::Aes256Gcm => Aes256Gcm::new(key.into())
                .decrypt(aes_gcm::Nonce::from_slice(&nonce), pl)
                .ok(),
            Aead::ChaCha20Poly1305 => {
                let c = ChaCha20Poly1305::new_from_slice(key)
                    .expect("ChaCha20-Poly1305 key must be 32 bytes");
                c.decrypt(chacha20poly1305::Nonce::from_slice(&nonce), pl)
                    .ok()
            }
        }
    }

    /**
     * @brief 헤더 보호에 쓸 마스크를 만든다.
     * @details 암호문에서 추출한 표본으로 블록 연산을 한 번 돌린다. 표본이 패킷마다 다르므로
     *          마스크도 매번 달라진다.
     */
    pub fn header_mask(&self, hp_key: &[u8], sample: &[u8; 16]) -> [u8; 5] {
        match self {
            Aead::Aes128Gcm | Aead::Aes256Gcm => {
                let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(sample);
                match self {
                    Aead::Aes128Gcm => Aes128::new(hp_key.into()).encrypt_block(&mut block),
                    Aead::Aes256Gcm => Aes256::new(hp_key.into()).encrypt_block(&mut block),
                    _ => unreachable!(),
                }
                let mut mask = [0u8; 5];
                mask.copy_from_slice(&block[..5]);
                mask
            }
            Aead::ChaCha20Poly1305 => {
                use chacha20::cipher::{
                    generic_array::GenericArray, KeyIvInit, StreamCipher, StreamCipherSeek,
                };
                let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
                let key = GenericArray::from_slice(hp_key);
                let nonce = GenericArray::from_slice(&sample[4..16]);
                let mut cipher = chacha20::ChaCha20::new(key, nonce);
                cipher.seek(counter as u64 * 64);
                let mut mask = [0u8; 5];
                cipher.apply_keystream(&mut mask);
                mask
            }
        }
    }
}

/**
 * @brief 헤더 보호를 씌우거나 벗긴다. 같은 연산이라 양방향이 하나다.
 * @note 첫 바이트에서 가리는 비트 수가 긴 헤더와 짧은 헤더에서 다르다. 긴 쪽은
 *       하위 4비트, 짧은 쪽은 5비트다.
 */
pub fn apply_header_protection(
    first: &mut u8,
    pn_bytes: &mut [u8],
    mask: &[u8; 5],
    long_header: bool,
) {
    let low = if long_header { 0x0f } else { 0x1f };
    *first ^= mask[0] & low;
    for (i, b) in pn_bytes.iter_mut().enumerate().take(4) {
        *b ^= mask[1 + i];
    }
}

#[cfg(test)]
/** @brief 블록 연산과 마스크를 공표된 벡터에 대조하고, 왕복이 성립하는지 본다. */
mod tests {
    use super::*;

    /** @brief 16진 문자열을 바이트로. */
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    /** @brief AES 블록 연산을 표준 벡터와 비교한다. */
    fn fips197_aes128_block() {
        let key = hex("000102030405060708090a0b0c0d0e0f");
        let sample: [u8; 16] = hex("00112233445566778899aabbccddeeff").try_into().unwrap();

        let mask = Aead::Aes128Gcm.header_mask(&key, &sample);
        let full = hex("69c4e0d86a7b0430d8cdb78070b4c55a");
        assert_eq!(&mask[..], &full[..5]);
    }

    #[test]
    /** @brief ChaCha20 헤더 마스크를 규격 벡터와 비교한다. */
    fn rfc9001_a5_chacha20_header_mask() {
        let hp = hex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
        let sample: [u8; 16] = hex("5e5cd55c41f69080575d7999c25a5bfb").try_into().unwrap();
        let mask = Aead::ChaCha20Poly1305.header_mask(&hp, &sample);
        assert_eq!(&mask[..], &hex("aefefe7d03")[..]);
    }

    #[test]
    /** @brief ChaCha20 AEAD 왕복. */
    fn chacha20_aead_roundtrip_with_pn_nonce() {
        let key = hex("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8");
        let iv = hex("e0459b3474bdd0e44a41c809");
        let aad = b"\x42header";
        let pt = b"DNS-over-QUIC chacha payload";
        let ct = Aead::ChaCha20Poly1305.seal(&key, &iv, 7, aad, pt);
        assert_eq!(ct.len(), pt.len() + 16);
        assert_eq!(
            Aead::ChaCha20Poly1305.open(&key, &iv, 7, aad, &ct).unwrap(),
            pt
        );
        assert!(Aead::ChaCha20Poly1305
            .open(&key, &iv, 8, aad, &ct)
            .is_none());
        assert!(Aead::ChaCha20Poly1305
            .open(&key, &iv, 7, b"\x42HEADER", &ct)
            .is_none());
        assert_eq!(Aead::ChaCha20Poly1305.key_len(), 32);
    }

    #[test]
    /** @brief AES-GCM AEAD 왕복. */
    fn aead_roundtrip_with_pn_nonce() {
        let key = hex("1f369613dd76d5467730efcbe3b1a22d");
        let iv = hex("fa044b2f42a3fd3b46fb255c");
        let aad = b"\xc3header";
        let pt = b"DNS-over-QUIC payload";
        let ct = Aead::Aes128Gcm.seal(&key, &iv, 2, aad, pt);
        assert_eq!(ct.len(), pt.len() + 16);

        assert_eq!(Aead::Aes128Gcm.open(&key, &iv, 2, aad, &ct).unwrap(), pt);

        assert!(Aead::Aes128Gcm.open(&key, &iv, 3, aad, &ct).is_none());

        assert!(Aead::Aes128Gcm
            .open(&key, &iv, 2, b"\xc3HEADER", &ct)
            .is_none());
    }

    #[test]
    /** @brief 같은 연산을 두 번 하면 원래대로 돌아오는지. */
    fn header_protection_is_symmetric() {
        let mask = [0xab, 0xcd, 0xef, 0x12, 0x34];
        let mut first = 0xc3u8;
        let mut pn = vec![0x00u8, 0x01];
        let (orig_first, orig_pn) = (first, pn.clone());
        apply_header_protection(&mut first, &mut pn, &mask, true);
        assert_ne!(first, orig_first);

        apply_header_protection(&mut first, &mut pn, &mask, true);
        assert_eq!(first, orig_first);
        assert_eq!(pn, orig_pn);
    }

    #[test]
    /** @brief 긴 헤더에서 가리는 비트 수가 맞는지. 틀리면 패킷 유형이 새거나 깨진다. */
    fn long_header_masks_low_4_bits_only() {
        let mask = [0xff, 0, 0, 0, 0];
        let mut first = 0xc3u8;
        let mut pn = vec![];
        apply_header_protection(&mut first, &mut pn, &mask, true);
        assert_eq!(first, 0xc3 ^ 0x0f);
    }
}
