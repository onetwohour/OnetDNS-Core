/*!
 * @brief 키 교환.
 *
 * @details X25519와 P-256을 지원한다. 개인키는 시드에서 만들고, 공유 비밀은 상대의
 *          공개값과 합쳐 나온다.
 * @warning 상대 공개값을 검사해야 한다. 낮은 위수 점을 받으면 공유 비밀이 예측 가능한
 *          값으로 고정된다.
 */

use crate::msg::consts::{SECP256R1, X25519};
use zeroize::Zeroize;

/** @brief 키 교환 한 번에 쓰는 개인키. */
pub struct KeyExchange {
    /** @brief 실제로 쓰는 곡선. */
    inner: Inner,
}

/** @brief 곡선별 개인키. */
enum Inner {
    /** @brief X25519. */
    X25519(x25519_dalek::StaticSecret),
    /** @brief P-256. */
    P256(p256::SecretKey),
}

impl KeyExchange {
    /** @brief 시드에서 개인키를 만든다. 모르는 곡선이면 없다. */
    pub fn from_seed(group: u16, seed: &[u8]) -> Option<KeyExchange> {
        match group {
            X25519 => {
                let mut s: [u8; 32] = seed.get(..32)?.try_into().ok()?;
                let secret = x25519_dalek::StaticSecret::from(s);
                s.zeroize();
                Some(KeyExchange {
                    inner: Inner::X25519(secret),
                })
            }
            SECP256R1 => {
                let sk = p256::SecretKey::from_slice(seed).ok()?;
                Some(KeyExchange {
                    inner: Inner::P256(sk),
                })
            }
            _ => None,
        }
    }

    /** @brief 이 키의 곡선 번호. */
    pub fn group(&self) -> u16 {
        match self.inner {
            Inner::X25519(_) => X25519,
            Inner::P256(_) => SECP256R1,
        }
    }

    /** @brief 상대에게 보낼 공개값. */
    pub fn public_bytes(&self) -> Vec<u8> {
        match &self.inner {
            Inner::X25519(s) => x25519_dalek::PublicKey::from(s).to_bytes().to_vec(),
            Inner::P256(s) => {
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                s.public_key().to_encoded_point(false).as_bytes().to_vec()
            }
        }
    }

    /**
     * @brief 상대 공개값과 합쳐 공유 비밀을 만든다.
     * @warning 낮은 위수 점을 거부한다. 받아들이면 공유 비밀이 고정값이 되어 암호화가
     *          무의미해진다.
     * @details P-256 공개값은 압축하지 않은 65 바이트 형식만 받는다. RFC 8446 은 이 형식만
     *          정의하고, 1.2 에서도 이쪽이 알린 점 형식은 압축하지 않은 형식뿐이다.
     */
    pub fn shared_secret(&self, peer: &[u8]) -> Option<Vec<u8>> {
        match &self.inner {
            Inner::X25519(s) => {
                let p: [u8; 32] = peer.try_into().ok()?;
                let shared = s.diffie_hellman(&x25519_dalek::PublicKey::from(p));

                if shared.as_bytes().iter().all(|&b| b == 0) {
                    return None;
                }
                Some(shared.as_bytes().to_vec())
            }
            Inner::P256(s) => {
                if peer.len() != 65 || peer[0] != 0x04 {
                    return None;
                }
                let pp = p256::PublicKey::from_sec1_bytes(peer).ok()?;
                let shared = p256::ecdh::diffie_hellman(s.to_nonzero_scalar(), pp.as_affine());
                Some(shared.raw_secret_bytes().to_vec())
            }
        }
    }
}

#[cfg(test)]
/** @brief 두 곡선의 교환과 낮은 위수 점 거부. */
mod tests {
    use super::*;

    /** @brief 양쪽이 같은 공유 비밀을 얻는지 확인한다. */
    fn ecdh_roundtrip(group: u16, sa: &[u8], sb: &[u8]) {
        let a = KeyExchange::from_seed(group, sa).unwrap();
        let b = KeyExchange::from_seed(group, sb).unwrap();
        let s1 = a.shared_secret(&b.public_bytes()).unwrap();
        let s2 = b.shared_secret(&a.public_bytes()).unwrap();
        assert_eq!(s1, s2, "양방향 공유 비밀 일치");
        assert_eq!(s1.len(), 32);
        assert_eq!(a.group(), group);
    }

    #[test]
    /** @brief 낮은 위수 점을 거부하는지. 받으면 비밀이 고정된다. */
    fn x25519_rejects_low_order_points() {
        let a = KeyExchange::from_seed(X25519, &[7u8; 32]).unwrap();

        let all_zero = [0u8; 32];
        let one = {
            let mut p = [0u8; 32];
            p[0] = 1;
            p
        };
        assert!(a.shared_secret(&all_zero).is_none(), "0 point 거부");
        assert!(a.shared_secret(&one).is_none(), "order-1 point 거부");
    }

    #[test]
    /** @brief X25519 교환. */
    fn x25519_ecdh() {
        ecdh_roundtrip(X25519, &[1u8; 32], &[2u8; 32]);

        assert_eq!(
            KeyExchange::from_seed(X25519, &[3u8; 32])
                .unwrap()
                .public_bytes()
                .len(),
            32
        );
    }

    #[test]
    /** @brief P-256 교환. */
    fn p256_ecdh() {
        ecdh_roundtrip(SECP256R1, &[0x42u8; 32], &[0x37u8; 32]);

        let pk = KeyExchange::from_seed(SECP256R1, &[5u8; 32])
            .unwrap()
            .public_bytes();
        assert_eq!(pk.len(), 65);
        assert_eq!(pk[0], 0x04);
    }

    #[test]
    /** @brief 모르는 곡선이면 만들지 않는지. */
    fn unknown_group_none() {
        assert!(KeyExchange::from_seed(0x9999, &[0u8; 32]).is_none());
    }

    #[test]
    /** @brief 압축한 P-256 공개값은 곡선 위의 점이어도 거부하는지. */
    fn p256_rejects_compressed_points() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let a = KeyExchange::from_seed(SECP256R1, &[0x42u8; 32]).unwrap();
        let b = p256::SecretKey::from_slice(&[0x37u8; 32]).unwrap();
        let compressed = b.public_key().to_encoded_point(true);
        assert_eq!(compressed.as_bytes().len(), 33);
        assert!(
            a.shared_secret(compressed.as_bytes()).is_none(),
            "압축한 점은 받지 않아야 합니다"
        );
        let uncompressed = b.public_key().to_encoded_point(false);
        assert!(a.shared_secret(uncompressed.as_bytes()).is_some());
    }
}
