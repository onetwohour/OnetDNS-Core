//! TLS key exchange over X25519, P-256, and the X25519MLKEM768 hybrid (RFC 10024).

use crate::msg::consts::{SECP256R1, X25519, X25519MLKEM768};
use ml_kem::ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{Decapsulate, Key, KeyExport, B32};
use zeroize::Zeroize;

/// Seed length that covers every group; X25519MLKEM768 uses all of it.
pub const SEED_LEN: usize = 96;

const MLKEM768_EK_LEN: usize = 1184;
const MLKEM768_CT_LEN: usize = 1088;

pub struct KeyExchange {
    inner: Inner,
}

enum Inner {
    X25519(x25519_dalek::StaticSecret),
    P256(p256::SecretKey),
    X25519MlKem768(Box<DecapsulationKey>, x25519_dalek::StaticSecret),
}

fn x25519_secret(seed: &[u8]) -> Option<x25519_dalek::StaticSecret> {
    let mut s: [u8; 32] = seed.get(..32)?.try_into().ok()?;
    let secret = x25519_dalek::StaticSecret::from(s);
    s.zeroize();
    Some(secret)
}

/// Rejects a low-order point, which would fix the shared secret.
fn x25519_agree(secret: &x25519_dalek::StaticSecret, peer: &[u8]) -> Option<Vec<u8>> {
    let p: [u8; 32] = peer.try_into().ok()?;
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(p));
    if !shared.was_contributory() {
        return None;
    }
    Some(shared.as_bytes().to_vec())
}

impl KeyExchange {
    /// Returns `None` for an unknown group or a seed shorter than the group needs.
    pub fn from_seed(group: u16, seed: &[u8]) -> Option<KeyExchange> {
        let inner = match group {
            X25519 => Inner::X25519(x25519_secret(seed)?),
            SECP256R1 => Inner::P256(p256::SecretKey::from_slice(seed.get(..32)?).ok()?),
            X25519MLKEM768 => {
                let kem_seed = ml_kem::Seed::try_from(seed.get(..64)?).ok()?;
                Inner::X25519MlKem768(
                    Box::new(DecapsulationKey::from_seed(kem_seed)),
                    x25519_secret(seed.get(64..)?)?,
                )
            }
            _ => return None,
        };
        Some(KeyExchange { inner })
    }

    /// The server's key share and the shared secret for the client's share. A key encapsulation
    /// has no key pair on this side, so this replaces `from_seed` followed by `shared_secret`.
    pub fn respond(group: u16, peer: &[u8], seed: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        if group != X25519MLKEM768 {
            let kx = KeyExchange::from_seed(group, seed)?;
            let secret = kx.shared_secret(peer)?;
            return Some((kx.public_bytes(), secret));
        }
        if peer.len() != MLKEM768_EK_LEN + 32 {
            return None;
        }
        let (ek, x_peer) = peer.split_at(MLKEM768_EK_LEN);
        let ek = EncapsulationKey::new(&Key::<EncapsulationKey>::try_from(ek).ok()?).ok()?;
        let x = x25519_secret(seed.get(32..)?)?;
        let ecdh = x25519_agree(&x, x_peer)?;
        let (ct, kem) = ek.encapsulate_deterministic(&B32::try_from(seed.get(..32)?).ok()?);
        let mut share = ct.to_vec();
        share.extend_from_slice(x25519_dalek::PublicKey::from(&x).as_bytes());
        let mut secret = kem.to_vec();
        secret.extend_from_slice(&ecdh);
        Some((share, secret))
    }

    pub fn group(&self) -> u16 {
        match self.inner {
            Inner::X25519(_) => X25519,
            Inner::P256(_) => SECP256R1,
            Inner::X25519MlKem768(..) => X25519MLKEM768,
        }
    }

    pub fn public_bytes(&self) -> Vec<u8> {
        match &self.inner {
            Inner::X25519(s) => x25519_dalek::PublicKey::from(s).to_bytes().to_vec(),
            Inner::P256(s) => {
                use p256::elliptic_curve::sec1::ToSec1Point;
                s.public_key().to_sec1_point(false).as_bytes().to_vec()
            }
            Inner::X25519MlKem768(dk, x) => {
                let mut share = dk.encapsulation_key().to_bytes().to_vec();
                share.extend_from_slice(x25519_dalek::PublicKey::from(x).as_bytes());
                share
            }
        }
    }

    /// Rejects a low-order X25519 point, which would fix the shared secret. A P-256 value must be
    /// the uncompressed 65-byte form: RFC 8446 defines only that form, and it is the only point
    /// format this side advertises in TLS 1.2.
    pub fn shared_secret(&self, peer: &[u8]) -> Option<Vec<u8>> {
        match &self.inner {
            Inner::X25519(s) => x25519_agree(s, peer),
            Inner::P256(s) => {
                if peer.len() != 65 || peer[0] != 0x04 {
                    return None;
                }
                let pp = p256::PublicKey::from_sec1_bytes(peer).ok()?;
                let shared = p256::ecdh::diffie_hellman(s.to_nonzero_scalar(), pp.as_affine());
                Some(shared.raw_secret_bytes().to_vec())
            }
            Inner::X25519MlKem768(dk, x) => {
                if peer.len() != MLKEM768_CT_LEN + 32 {
                    return None;
                }
                let (ct, x_peer) = peer.split_at(MLKEM768_CT_LEN);
                let ecdh = x25519_agree(x, x_peer)?;
                let mut secret = dk.decapsulate(&Ciphertext::try_from(ct).ok()?).to_vec();
                secret.extend_from_slice(&ecdh);
                Some(secret)
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
    /// RFC 10024 puts the ML-KEM part first in each share and in the secret.
    fn hybrid_agrees_and_orders_ml_kem_first() {
        let client = KeyExchange::from_seed(X25519MLKEM768, &[0x11; SEED_LEN]).unwrap();
        let share = client.public_bytes();
        assert_eq!(share.len(), MLKEM768_EK_LEN + 32);
        let (reply, secret) =
            KeyExchange::respond(X25519MLKEM768, &share, &[0x22; SEED_LEN]).unwrap();
        assert_eq!(reply.len(), MLKEM768_CT_LEN + 32);
        assert_eq!(secret.len(), 64);
        assert_eq!(client.shared_secret(&reply).as_ref(), Some(&secret));

        let x_client = KeyExchange::from_seed(X25519, &[0x11; 32]).unwrap();
        assert_eq!(&share[MLKEM768_EK_LEN..], x_client.public_bytes());
        assert_eq!(
            x_client.shared_secret(&reply[MLKEM768_CT_LEN..]).unwrap(),
            secret[32..]
        );
    }

    #[test]
    fn hybrid_rejects_malformed_shares() {
        let client = KeyExchange::from_seed(X25519MLKEM768, &[0x11; SEED_LEN]).unwrap();
        let share = client.public_bytes();
        let seed = [0x22; SEED_LEN];
        assert!(KeyExchange::respond(X25519MLKEM768, &share[1..], &seed).is_none());

        let mut low_order = share.clone();
        low_order[MLKEM768_EK_LEN..].fill(0);
        assert!(KeyExchange::respond(X25519MLKEM768, &low_order, &seed).is_none());

        let mut unreduced = share.clone();
        unreduced[..MLKEM768_EK_LEN - 32].fill(0xff);
        assert!(
            KeyExchange::respond(X25519MLKEM768, &unreduced, &seed).is_none(),
            "q 이상인 계수가 든 캡슐화 키는 거부해야 합니다"
        );

        let (reply, _) = KeyExchange::respond(X25519MLKEM768, &share, &seed).unwrap();
        assert!(client.shared_secret(&reply[1..]).is_none());
        let mut reply_low_order = reply.clone();
        reply_low_order[MLKEM768_CT_LEN..].fill(0);
        assert!(client.shared_secret(&reply_low_order).is_none());
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
