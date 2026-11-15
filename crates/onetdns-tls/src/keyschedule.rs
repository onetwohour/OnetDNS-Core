//! TLS 1.3 key schedule. One secret advances through the early, handshake, and application stages,
//! and each stage splits off keys per direction.
//!
//! Every derivation mixes in a label and the transcript hash, so the same key exchange gives
//! different keys when the handshake content differs.

use hmac::Mac;

use crate::msg::consts;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha256,
    Sha384,
}

impl Hash {
    pub fn len(&self) -> usize {
        match self {
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
        }
    }

    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        match self {
            Hash::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Hash::Sha384 => sha2::Sha384::digest(data).to_vec(),
        }
    }
}

pub fn suite_params(suite: u16) -> Option<(Hash, usize)> {
    match suite {
        consts::TLS_AES_128_GCM_SHA256 => Some((Hash::Sha256, 16)),
        consts::TLS_AES_256_GCM_SHA384 => Some((Hash::Sha384, 32)),
        consts::TLS_CHACHA20_POLY1305_SHA256 => Some((Hash::Sha256, 32)),
        _ => None,
    }
}

pub fn hkdf_extract(hash: Hash, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    match hash {
        Hash::Sha256 => hkdf::Hkdf::<sha2::Sha256>::extract(Some(salt), ikm)
            .0
            .to_vec(),
        Hash::Sha384 => hkdf::Hkdf::<sha2::Sha384>::extract(Some(salt), ikm)
            .0
            .to_vec(),
    }
}

pub fn hkdf_expand(hash: Hash, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut okm = vec![0u8; len];
    match hash {
        Hash::Sha256 => {
            hkdf::Hkdf::<sha2::Sha256>::from_prk(prk)
                .expect("PRK length")
                .expand(info, &mut okm)
                .expect("OKM length");
        }
        Hash::Sha384 => {
            hkdf::Hkdf::<sha2::Sha384>::from_prk(prk)
                .expect("PRK length")
                .expand(info, &mut okm)
                .expect("OKM length");
        }
    }
    okm
}

/// A fixed prefix on the label makes keys for different uses come out of the same secret
/// differently.
pub fn hkdf_expand_label(
    hash: Hash,
    secret: &[u8],
    label: &str,
    context: &[u8],
    len: usize,
) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(&(len as u16).to_be_bytes());
    let full = format!("tls13 {label}");
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(hash, secret, &info, len)
}

pub fn derive_secret(hash: Hash, secret: &[u8], label: &str, transcript_hash: &[u8]) -> Vec<u8> {
    hkdf_expand_label(hash, secret, label, transcript_hash, hash.len())
}

pub fn traffic_keys(hash: Hash, secret: &[u8], key_len: usize) -> (Vec<u8>, Vec<u8>) {
    let key = hkdf_expand_label(hash, secret, "key", &[], key_len);
    let iv = hkdf_expand_label(hash, secret, "iv", &[], 12);
    (key, iv)
}

pub fn traffic_update(hash: Hash, secret: &[u8]) -> Vec<u8> {
    hkdf_expand_label(hash, secret, "traffic upd", &[], hash.len())
}

pub fn finished_key(hash: Hash, base_key: &[u8]) -> Vec<u8> {
    hkdf_expand_label(hash, base_key, "finished", &[], hash.len())
}

pub fn resumption_psk(hash: Hash, res_master: &[u8], nonce: &[u8]) -> Vec<u8> {
    hkdf_expand_label(hash, res_master, "resumption", nonce, hash.len())
}

/// Used for Finished comparisons; leaking timing would let the right value be guessed byte by byte.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

/// The last check against a forged handshake: if a man in the middle changed any message, this does
/// not match.
pub fn finished_verify_data(hash: Hash, finished_key: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    match hash {
        Hash::Sha256 => {
            let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(finished_key).expect("key");
            m.update(transcript_hash);
            m.finalize().into_bytes().to_vec()
        }
        Hash::Sha384 => {
            let mut m = hmac::Hmac::<sha2::Sha384>::new_from_slice(finished_key).expect("key");
            m.update(transcript_hash);
            m.finalize().into_bytes().to_vec()
        }
    }
}

pub struct Transcript {
    hash: Hash,
    data: Vec<u8>,
}

impl Transcript {
    pub fn new(hash: Hash) -> Self {
        Self {
            hash,
            data: Vec::new(),
        }
    }

    pub(crate) fn retained_payload_bytes(&self) -> usize {
        self.data.capacity()
    }

    /// Wire bytes as is.
    pub fn update(&mut self, msg_wire: &[u8]) {
        self.data.extend_from_slice(msg_wire);
    }

    pub fn hash(&self) -> Vec<u8> {
        self.hash.digest(&self.data)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Required when the server sends HelloRetryRequest; keeping the original would split the two
    /// sides' transcripts.
    pub fn replace_with_message_hash(&mut self) {
        let ch_hash = self.hash.digest(&self.data);
        let mut synthetic = vec![254u8, 0x00, 0x00, ch_hash.len() as u8];
        synthetic.extend_from_slice(&ch_hash);
        self.data = synthetic;
    }
}

pub struct KeySchedule {
    hash: Hash,
    secret: Vec<u8>,
}

impl Drop for KeySchedule {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

impl KeySchedule {
    /// Without a PSK.
    pub fn new(hash: Hash) -> Self {
        let zeros = vec![0u8; hash.len()];
        let early = hkdf_extract(hash, &zeros, &zeros);
        Self {
            hash,
            secret: early,
        }
    }

    pub(crate) fn retained_payload_bytes(&self) -> usize {
        self.secret.capacity()
    }

    /// With a PSK, for resumption.
    pub fn new_with_psk(hash: Hash, psk: &[u8]) -> Self {
        let zeros = vec![0u8; hash.len()];
        let early = hkdf_extract(hash, &zeros, psk);
        Self {
            hash,
            secret: early,
        }
    }

    /// Binds the resumption offer to the transcript; the intermediate secret is zeroed before
    /// returning.
    pub fn psk_binder(&self, truncated_ch_hash: &[u8]) -> Vec<u8> {
        use zeroize::Zeroizing;
        let binder_key = Zeroizing::new(derive_secret(
            self.hash,
            &self.secret,
            "res binder",
            &self.empty_hash(),
        ));
        let finished = Zeroizing::new(finished_key(self.hash, &binder_key));
        finished_verify_data(self.hash, &finished, truncated_ch_hash)
    }

    pub fn client_early_traffic_secret(&self, ch_transcript_hash: &[u8]) -> Vec<u8> {
        derive_secret(self.hash, &self.secret, "c e traffic", ch_transcript_hash)
    }

    pub fn resumption_master_secret(&self, transcript_hash: &[u8]) -> Vec<u8> {
        derive_secret(self.hash, &self.secret, "res master", transcript_hash)
    }

    pub fn hash(&self) -> Hash {
        self.hash
    }

    pub fn current_secret(&self) -> &[u8] {
        &self.secret
    }

    pub fn enter_handshake(&mut self, ecdhe: &[u8]) {
        use zeroize::Zeroize;
        let mut derived = derive_secret(self.hash, &self.secret, "derived", &self.empty_hash());
        let next = hkdf_extract(self.hash, &derived, ecdhe);
        derived.zeroize();
        self.secret.zeroize();
        self.secret = next;
    }

    pub fn enter_master(&mut self) {
        use zeroize::Zeroize;
        let mut derived = derive_secret(self.hash, &self.secret, "derived", &self.empty_hash());
        let zeros = vec![0u8; self.hash.len()];
        let next = hkdf_extract(self.hash, &derived, &zeros);
        derived.zeroize();
        self.secret.zeroize();
        self.secret = next;
    }

    pub fn client_handshake_traffic_secret(&self, transcript_hash: &[u8]) -> Vec<u8> {
        derive_secret(self.hash, &self.secret, "c hs traffic", transcript_hash)
    }
    pub fn server_handshake_traffic_secret(&self, transcript_hash: &[u8]) -> Vec<u8> {
        derive_secret(self.hash, &self.secret, "s hs traffic", transcript_hash)
    }
    pub fn client_application_traffic_secret(&self, transcript_hash: &[u8]) -> Vec<u8> {
        derive_secret(self.hash, &self.secret, "c ap traffic", transcript_hash)
    }
    pub fn server_application_traffic_secret(&self, transcript_hash: &[u8]) -> Vec<u8> {
        derive_secret(self.hash, &self.secret, "s ap traffic", transcript_hash)
    }

    /// Used in derivations between stages.
    fn empty_hash(&self) -> Vec<u8> {
        self.hash.digest(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc5869_hkdf_sha256_vector() {
        let ikm = vec![0x0b; 22];
        let salt = hx("000102030405060708090a0b0c");
        let info = hx("f0f1f2f3f4f5f6f7f8f9");
        let prk = hkdf_extract(Hash::Sha256, &salt, &ikm);
        assert_eq!(
            prk,
            hx("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );
        let okm = hkdf_expand(Hash::Sha256, &prk, &info, 42);
        assert_eq!(
            okm,
            hx("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        );
    }

    #[test]
    fn expand_label_info_layout() {
        let secret = vec![0xABu8; 32];
        let got = hkdf_expand_label(Hash::Sha256, &secret, "key", &[], 4);
        let mut info = Vec::new();
        info.extend_from_slice(&4u16.to_be_bytes());
        let full = b"tls13 key";
        info.push(full.len() as u8);
        info.extend_from_slice(full);
        info.push(0);
        let expect = hkdf_expand(Hash::Sha256, &secret, &info, 4);
        assert_eq!(got, expect);
        assert_eq!(got.len(), 4);
    }

    #[test]
    fn key_schedule_progression_deterministic() {
        let hash = Hash::Sha256;
        let mut ks = KeySchedule::new(hash);
        let early = ks.current_secret().to_vec();
        assert_eq!(early.len(), 32);

        ks.enter_handshake(&[0x07; 32]);
        let hs_secret = ks.current_secret().to_vec();
        assert_ne!(hs_secret, early);

        let th = hash.digest(b"transcript-up-to-serverhello");
        let chs = ks.client_handshake_traffic_secret(&th);
        let shs = ks.server_handshake_traffic_secret(&th);
        assert_eq!(chs.len(), 32);
        assert_ne!(chs, shs);

        let (key, iv) = traffic_keys(hash, &chs, 16);
        assert_eq!(key.len(), 16);
        assert_eq!(iv.len(), 12);

        let fk = finished_key(hash, &shs);
        let vd1 = finished_verify_data(hash, &fk, &th);
        let vd2 = finished_verify_data(hash, &fk, &th);
        assert_eq!(vd1, vd2);
        assert_eq!(vd1.len(), 32);

        let vd3 = finished_verify_data(hash, &fk, &hash.digest(b"other"));
        assert_ne!(vd1, vd3);

        ks.enter_master();
        let cap = ks.client_application_traffic_secret(&th);
        assert_eq!(cap.len(), 32);
        assert_ne!(cap, chs);
    }

    #[test]
    fn suite_params_lookup() {
        assert_eq!(
            suite_params(consts::TLS_AES_128_GCM_SHA256),
            Some((Hash::Sha256, 16))
        );
        assert_eq!(
            suite_params(consts::TLS_AES_256_GCM_SHA384),
            Some((Hash::Sha384, 32))
        );
        assert_eq!(
            suite_params(consts::TLS_CHACHA20_POLY1305_SHA256),
            Some((Hash::Sha256, 32))
        );
        assert_eq!(suite_params(0x0000), None);
    }
}
