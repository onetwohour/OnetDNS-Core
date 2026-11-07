//! TLS key exchange over X25519 and P-256.

use crate::msg::consts::{SECP256R1, X25519};
use zeroize::Zeroize;

pub struct KeyExchange {
    inner: Inner,
}

enum Inner {
    X25519(x25519_dalek::StaticSecret),
    P256(p256::SecretKey),
}

impl KeyExchange {
    /// Returns `None` for an unknown group.
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

    pub fn group(&self) -> u16 {
        match self.inner {
            Inner::X25519(_) => X25519,
            Inner::P256(_) => SECP256R1,
        }
    }

    pub fn public_bytes(&self) -> Vec<u8> {
        match &self.inner {
            Inner::X25519(s) => x25519_dalek::PublicKey::from(s).to_bytes().to_vec(),
            Inner::P256(s) => {
                use p256::elliptic_curve::sec1::ToSec1Point;
                s.public_key().to_sec1_point(false).as_bytes().to_vec()
            }
        }
    }

    /// Rejects a low-order X25519 point, which would fix the shared secret. A P-256 value must be
    /// the uncompressed 65-byte form: RFC 8446 defines only that form, and it is the only point
    /// format this side advertises in TLS 1.2.
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
mod tests {
    use super::*;

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
    fn p256_ecdh() {
        ecdh_roundtrip(SECP256R1, &[0x42u8; 32], &[0x37u8; 32]);

        let pk = KeyExchange::from_seed(SECP256R1, &[5u8; 32])
            .unwrap()
            .public_bytes();
        assert_eq!(pk.len(), 65);
        assert_eq!(pk[0], 0x04);
    }

    #[test]
    fn unknown_group_none() {
        assert!(KeyExchange::from_seed(0x9999, &[0u8; 32]).is_none());
    }

    #[test]
    fn p256_rejects_compressed_points() {
        use p256::elliptic_curve::sec1::ToSec1Point;
        let a = KeyExchange::from_seed(SECP256R1, &[0x42u8; 32]).unwrap();
        let b = p256::SecretKey::from_slice(&[0x37u8; 32]).unwrap();
        let compressed = b.public_key().to_sec1_point(true);
        assert_eq!(compressed.as_bytes().len(), 33);
        assert!(
            a.shared_secret(compressed.as_bytes()).is_none(),
            "압축한 점은 받지 않아야 합니다"
        );
        let uncompressed = b.public_key().to_sec1_point(false);
        assert!(a.shared_secret(uncompressed.as_bytes()).is_some());
    }
}
