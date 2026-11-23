//! HPKE (RFC 9180) base mode with one suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
//! AES-128-GCM, the suite Oblivious DoH requires. Oblivious DoH and Oblivious HTTP also seal their
//! responses with the suite's KDF and AEAD directly, so those are exported as well.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::aead::{aead_open, aead_seal, Aead};

pub const KEM_ID: u16 = 0x0020;
pub const KDF_ID: u16 = 0x0001;
pub const AEAD_ID: u16 = 0x0001;

/// Encapsulated key length.
pub const N_ENC: usize = 32;
pub const N_PK: usize = 32;
pub const N_SK: usize = 32;
/// AEAD key length.
pub const N_K: usize = 16;
/// AEAD nonce length.
pub const N_N: usize = 12;
/// KDF output length.
pub const N_H: usize = 32;
/// AEAD tag length.
pub const N_T: usize = 16;

const MODE_BASE: u8 = 0x00;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeError {
    /// A public key of the wrong length, or one that gives the all-zero shared secret.
    InvalidKey,
    /// Authentication failed.
    Open,
    /// The next sequence number would repeat a nonce.
    MessageLimit,
    /// More than the KDF can expand: 255 * N_H bytes, or 65535 with a label.
    TooLong,
}

impl std::fmt::Display for HpkeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            HpkeError::InvalidKey => "invalid HPKE public key",
            HpkeError::Open => "HPKE message authentication failed",
            HpkeError::MessageLimit => "HPKE context sequence number exhausted",
            HpkeError::TooLong => "requested HPKE key material is too long",
        })
    }
}

impl std::error::Error for HpkeError {}

/// An X25519 private key. Wiped on drop.
pub struct PrivateKey {
    secret: x25519_dalek::StaticSecret,
}

impl PrivateKey {
    /// Panics when the OS cannot supply randomness.
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; N_SK]);
        onetdns_core::rng::fill_random(&mut *bytes);
        Self::from_bytes(&bytes)
    }

    /// DeriveKeyPair: the same input keying material always gives the same key.
    pub fn derive(ikm: &[u8]) -> Self {
        let prk = labeled_extract(&kem_suite_id(), b"", b"dkp_prk", ikm);
        let mut sk = Zeroizing::new([0u8; N_SK]);
        labeled_expand(&kem_suite_id(), &prk, b"sk", b"", &mut *sk)
            .expect("N_SK is within the HKDF limit");
        Self::from_bytes(&sk)
    }

    pub fn from_bytes(bytes: &[u8; N_SK]) -> Self {
        Self {
            secret: x25519_dalek::StaticSecret::from(*bytes),
        }
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; N_SK]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    pub fn public_key(&self) -> [u8; N_PK] {
        x25519_dalek::PublicKey::from(&self.secret).to_bytes()
    }

    /// Rejects a low-order point, which would fix the shared secret whatever this key is.
    fn dh(&self, peer: &[u8]) -> Result<Zeroizing<[u8; 32]>, HpkeError> {
        let peer: [u8; N_PK] = peer.try_into().map_err(|_| HpkeError::InvalidKey)?;
        let shared = self
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        if shared.as_bytes().iter().all(|&byte| byte == 0) {
            return Err(HpkeError::InvalidKey);
        }
        Ok(Zeroizing::new(*shared.as_bytes()))
    }
}

/// Encapsulates to `pk_r` with a fresh ephemeral key. Returns `enc`, which the receiver needs, and
/// the context that seals to it.
pub fn setup_sender(pk_r: &[u8], info: &[u8]) -> Result<([u8; N_ENC], SenderContext), HpkeError> {
    setup_sender_with(pk_r, info, &PrivateKey::generate())
}

fn setup_sender_with(
    pk_r: &[u8],
    info: &[u8],
    sk_e: &PrivateKey,
) -> Result<([u8; N_ENC], SenderContext), HpkeError> {
    let dh = sk_e.dh(pk_r)?;
    let enc = sk_e.public_key();
    let shared = extract_and_expand(&dh, &enc, pk_r);
    Ok((enc, SenderContext(KeySchedule::new(&shared, info))))
}

pub fn setup_receiver(
    enc: &[u8],
    sk_r: &PrivateKey,
    info: &[u8],
) -> Result<ReceiverContext, HpkeError> {
    let dh = sk_r.dh(enc)?;
    let shared = extract_and_expand(&dh, enc, &sk_r.public_key());
    Ok(ReceiverContext(KeySchedule::new(&shared, info)))
}

/// Seals messages in order. Separate from `ReceiverContext` so one context never both seals and
/// opens: the two directions share a key, and sealing on the receiving side would reuse the
/// sender's nonces.
pub struct SenderContext(KeySchedule);

impl SenderContext {
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let nonce = self.0.nonce();
        let next = self.0.seq.checked_add(1).ok_or(HpkeError::MessageLimit)?;
        let sealed = aead_seal(Aead::Aes128Gcm, &*self.0.key, &nonce, aad, plaintext);
        self.0.seq = next;
        Ok(sealed)
    }

    pub fn export(&self, context: &[u8], out: &mut [u8]) -> Result<(), HpkeError> {
        self.0.export(context, out)
    }
}

/// Opens messages in the order they were sealed. A failed open does not advance the sequence.
pub struct ReceiverContext(KeySchedule);

impl ReceiverContext {
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let nonce = self.0.nonce();
        let next = self.0.seq.checked_add(1).ok_or(HpkeError::MessageLimit)?;
        let plaintext = aead_open(Aead::Aes128Gcm, &*self.0.key, &nonce, aad, ciphertext)
            .map_err(|_| HpkeError::Open)?;
        self.0.seq = next;
        Ok(plaintext)
    }

    pub fn export(&self, context: &[u8], out: &mut [u8]) -> Result<(), HpkeError> {
        self.0.export(context, out)
    }
}

struct KeySchedule {
    key: Zeroizing<[u8; N_K]>,
    base_nonce: Zeroizing<[u8; N_N]>,
    exporter_secret: Zeroizing<[u8; N_H]>,
    seq: u64,
}

impl KeySchedule {
    fn new(shared_secret: &[u8; 32], info: &[u8]) -> Self {
        let suite = hpke_suite_id();
        let psk_id_hash = labeled_extract(&suite, b"", b"psk_id_hash", b"");
        let info_hash = labeled_extract(&suite, b"", b"info_hash", info);
        let mut context = Vec::with_capacity(1 + 2 * N_H);
        context.push(MODE_BASE);
        context.extend_from_slice(&*psk_id_hash);
        context.extend_from_slice(&*info_hash);

        let secret = labeled_extract(&suite, shared_secret, b"secret", b"");
        let mut schedule = KeySchedule {
            key: Zeroizing::new([0; N_K]),
            base_nonce: Zeroizing::new([0; N_N]),
            exporter_secret: Zeroizing::new([0; N_H]),
            seq: 0,
        };
        for (label, out) in [
            (&b"key"[..], &mut schedule.key[..]),
            (b"base_nonce", &mut schedule.base_nonce[..]),
            (b"exp", &mut schedule.exporter_secret[..]),
        ] {
            labeled_expand(&suite, &secret, label, &context, out)
                .expect("Key schedule outputs are within the HKDF limit");
        }
        schedule
    }

    fn nonce(&self) -> [u8; N_N] {
        let mut nonce = *self.base_nonce;
        for (byte, seq) in nonce[N_N - 8..].iter_mut().zip(self.seq.to_be_bytes()) {
            *byte ^= seq;
        }
        nonce
    }

    fn export(&self, context: &[u8], out: &mut [u8]) -> Result<(), HpkeError> {
        labeled_expand(
            &hpke_suite_id(),
            &self.exporter_secret,
            b"sec",
            context,
            out,
        )
    }
}

/// The suite's KDF Extract, unlabeled.
pub fn extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; N_H]> {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = Zeroizing::new([0u8; N_H]);
    out.copy_from_slice(&prk);
    out
}

/// The suite's KDF Expand, unlabeled.
pub fn expand(prk: &[u8; N_H], info: &[u8], out: &mut [u8]) -> Result<(), HpkeError> {
    Hkdf::<Sha256>::from_prk(prk)
        .expect("N_H is the SHA-256 PRK length")
        .expand(info, out)
        .map_err(|_| HpkeError::TooLong)
}

/// The suite's AEAD with a caller-supplied key and nonce. The caller must never reuse a nonce with
/// the same key.
pub fn seal(key: &[u8; N_K], nonce: &[u8; N_N], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    aead_seal(Aead::Aes128Gcm, key, nonce, aad, plaintext)
}

pub fn open(
    key: &[u8; N_K],
    nonce: &[u8; N_N],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, HpkeError> {
    aead_open(Aead::Aes128Gcm, key, nonce, aad, ciphertext).map_err(|_| HpkeError::Open)
}

/// DHKEM's ExtractAndExpand: binds the shared secret to both public keys.
fn extract_and_expand(dh: &[u8; 32], enc: &[u8], pk_r: &[u8]) -> Zeroizing<[u8; 32]> {
    let suite = kem_suite_id();
    let prk = labeled_extract(&suite, b"", b"eae_prk", dh);
    let mut kem_context = Vec::with_capacity(N_ENC + N_PK);
    kem_context.extend_from_slice(enc);
    kem_context.extend_from_slice(pk_r);
    let mut shared = Zeroizing::new([0u8; 32]);
    labeled_expand(&suite, &prk, b"shared_secret", &kem_context, &mut *shared)
        .expect("The shared secret is within the HKDF limit");
    shared
}

fn kem_suite_id() -> [u8; 5] {
    let [high, low] = KEM_ID.to_be_bytes();
    [b'K', b'E', b'M', high, low]
}

fn hpke_suite_id() -> [u8; 10] {
    let mut id = [0u8; 10];
    id[..4].copy_from_slice(b"HPKE");
    id[4..6].copy_from_slice(&KEM_ID.to_be_bytes());
    id[6..8].copy_from_slice(&KDF_ID.to_be_bytes());
    id[8..].copy_from_slice(&AEAD_ID.to_be_bytes());
    id
}

fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<[u8; N_H]> {
    let mut labeled = Zeroizing::new(Vec::with_capacity(
        7 + suite_id.len() + label.len() + ikm.len(),
    ));
    labeled.extend_from_slice(b"HPKE-v1");
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(ikm);
    extract(salt, &labeled)
}

fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8; N_H],
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), HpkeError> {
    let length = u16::try_from(out.len()).map_err(|_| HpkeError::TooLong)?;
    let mut labeled = Vec::with_capacity(2 + 7 + suite_id.len() + label.len() + info.len());
    labeled.extend_from_slice(&length.to_be_bytes());
    labeled.extend_from_slice(b"HPKE-v1");
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(info);
    let result = expand(prk, &labeled, out);
    labeled.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let text: String = text.split_whitespace().collect();
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn array<const N: usize>(text: &str) -> [u8; N] {
        hex(text).try_into().unwrap()
    }

    // RFC 9180 test vectors, appendix A.1.1: base mode of this suite.
    const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
    const IKM_E: &str = "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234";
    const PK_EM: &str = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
    const SK_EM: &str = "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736";
    const IKM_R: &str = "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037";
    const PK_RM: &str = "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d";
    const SK_RM: &str = "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8";
    const SHARED_SECRET: &str = "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc";
    const KEY: &str = "4531685d41d65f03dc48f6b8302c05b0";
    const BASE_NONCE: &str = "56d890e5accaaf011cff4b7d";
    const EXPORTER_SECRET: &str =
        "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8";
    const PT: &str = "4265617574792069732074727574682c20747275746820626561757479";
    const ENCRYPTIONS: [(u64, &str); 6] = [
        (
            0,
            "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9\
             6d8770ac83d07bea87e13c512a",
        ),
        (
            1,
            "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab25\
             1c03d0c22a56b8ca42c2063b84",
        ),
        (
            2,
            "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb7251649158\
             8d96a19ad4a683518973dcc180",
        ),
        (
            4,
            "583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a\
             09fc0012bc69fccaa251c0246d",
        ),
        (
            255,
            "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505b\
             f106deefec4a49ac38d71c9e0a",
        ),
        (
            256,
            "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3\
             fbeda97d2e0e1aba483a2df9f2",
        ),
    ];
    const EXPORTS: [(&str, &str); 3] = [
        (
            "",
            "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee",
        ),
        (
            "00",
            "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5",
        ),
        (
            "54657374436f6e74657874",
            "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931",
        ),
    ];

    fn vector_contexts() -> ([u8; N_ENC], SenderContext, ReceiverContext) {
        let sk_e = PrivateKey::derive(&hex(IKM_E));
        let sk_r = PrivateKey::derive(&hex(IKM_R));
        let (enc, sender) = setup_sender_with(&hex(PK_RM), &hex(INFO), &sk_e).unwrap();
        let receiver = setup_receiver(&enc, &sk_r, &hex(INFO)).unwrap();
        (enc, sender, receiver)
    }

    #[test]
    fn derived_key_pairs_match_the_rfc_vectors() {
        let sk_e = PrivateKey::derive(&hex(IKM_E));
        assert_eq!(*sk_e.to_bytes(), array::<32>(SK_EM));
        assert_eq!(sk_e.public_key(), array::<32>(PK_EM));
        let sk_r = PrivateKey::derive(&hex(IKM_R));
        assert_eq!(*sk_r.to_bytes(), array::<32>(SK_RM));
        assert_eq!(sk_r.public_key(), array::<32>(PK_RM));
    }

    #[test]
    fn both_sides_reach_the_rfc_key_schedule() {
        let sk_e = PrivateKey::derive(&hex(IKM_E));
        let sk_r = PrivateKey::derive(&hex(IKM_R));
        let sent = sk_e.dh(&hex(PK_RM)).unwrap();
        let received = sk_r.dh(&hex(PK_EM)).unwrap();
        for dh in [sent, received] {
            assert_eq!(
                *extract_and_expand(&dh, &hex(PK_EM), &hex(PK_RM)),
                array::<32>(SHARED_SECRET)
            );
        }

        let (enc, sender, receiver) = vector_contexts();
        assert_eq!(enc, array::<32>(PK_EM));
        for schedule in [&sender.0, &receiver.0] {
            assert_eq!(*schedule.key, array::<16>(KEY));
            assert_eq!(*schedule.base_nonce, array::<12>(BASE_NONCE));
            assert_eq!(*schedule.exporter_secret, array::<32>(EXPORTER_SECRET));
        }
    }

    #[test]
    fn sealing_in_sequence_matches_the_rfc_ciphertexts() {
        let (_, mut sender, mut receiver) = vector_contexts();
        let pt = hex(PT);
        for seq in 0..=256u64 {
            let aad = format!("Count-{seq}");
            let ct = sender.seal(aad.as_bytes(), &pt).unwrap();
            if let Some((_, want)) = ENCRYPTIONS.iter().find(|(at, _)| *at == seq) {
                assert_eq!(ct, hex(want), "sequence {seq}");
            }
            assert_eq!(receiver.open(aad.as_bytes(), &ct).unwrap(), pt);
        }
    }

    #[test]
    fn exports_match_the_rfc_values() {
        let (_, sender, receiver) = vector_contexts();
        for (context, want) in EXPORTS {
            for exported in [
                {
                    let mut out = [0u8; 32];
                    sender.export(&hex(context), &mut out).unwrap();
                    out
                },
                {
                    let mut out = [0u8; 32];
                    receiver.export(&hex(context), &mut out).unwrap();
                    out
                },
            ] {
                assert_eq!(exported, array::<32>(want), "context {context:?}");
            }
        }
    }

    #[test]
    fn a_failed_open_leaves_the_sequence_where_it_was() {
        let (_, mut sender, mut receiver) = vector_contexts();
        let first = sender.seal(b"", b"first").unwrap();
        let mut tampered = first.clone();
        tampered[0] ^= 1;
        assert_eq!(receiver.open(b"", &tampered), Err(HpkeError::Open));
        assert_eq!(receiver.open(b"other aad", &first), Err(HpkeError::Open));
        assert_eq!(receiver.open(b"", &first).unwrap(), b"first");
    }

    #[test]
    fn low_order_and_malformed_public_keys_are_refused() {
        // The all-zero point is of low order: any private key gives the all-zero shared secret.
        assert_eq!(
            setup_sender(&[0u8; 32], b"").err(),
            Some(HpkeError::InvalidKey)
        );
        assert_eq!(
            setup_sender(&[9u8; 31], b"").err(),
            Some(HpkeError::InvalidKey)
        );
        let sk_r = PrivateKey::generate();
        assert!(matches!(
            setup_receiver(&[0u8; 32], &sk_r, b""),
            Err(HpkeError::InvalidKey)
        ));
    }

    #[test]
    fn fresh_ephemeral_keys_still_reach_the_receiver() {
        let sk_r = PrivateKey::generate();
        let (enc, mut sender) = setup_sender(&sk_r.public_key(), b"info").unwrap();
        let (other_enc, _) = setup_sender(&sk_r.public_key(), b"info").unwrap();
        assert_ne!(enc, other_enc, "each setup draws a new ephemeral key");
        let mut receiver = setup_receiver(&enc, &sk_r, b"info").unwrap();
        let ct = sender.seal(b"aad", b"message").unwrap();
        assert_eq!(receiver.open(b"aad", &ct).unwrap(), b"message");

        let mut wrong_info = setup_receiver(&enc, &sk_r, b"other").unwrap();
        assert_eq!(wrong_info.open(b"aad", &ct), Err(HpkeError::Open));
    }

    #[test]
    fn export_length_is_bounded_by_the_kdf() {
        let (_, sender, _) = vector_contexts();
        let mut at_limit = vec![0u8; 255 * N_H];
        assert!(sender.export(b"", &mut at_limit).is_ok());
        let mut over = vec![0u8; 255 * N_H + 1];
        assert_eq!(sender.export(b"", &mut over), Err(HpkeError::TooLong));
    }
}
