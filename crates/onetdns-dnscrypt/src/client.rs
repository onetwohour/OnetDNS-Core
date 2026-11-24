//! The client side: checking a provider's certificates and sealing queries to the resolver key the
//! chosen one carries.

use ed25519_dalek::{Signature, VerifyingKey};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    box_beforenm, secretbox_open, secretbox_seal, unpad_checked, CERT_MAGIC, CLIENT_MAGIC_LEN,
    CLIENT_NONCE_LEN, ES_VERSION_XCHACHA, PUBKEY_LEN, RESOLVER_MAGIC,
};

const CERT_LEN: usize = 124;

/// Client magic, client public key and client nonce.
const QUERY_HEADER_LEN: usize = CLIENT_MAGIC_LEN + PUBKEY_LEN + CLIENT_NONCE_LEN;

const TAG_LEN: usize = 16;

/// What a sealed query adds to its padded plaintext.
pub const QUERY_OVERHEAD: usize = QUERY_HEADER_LEN + TAG_LEN;

/// Resolver magic and the full nonce.
const RESPONSE_HEADER_LEN: usize = RESOLVER_MAGIC.len() + 24;

const PAD_BLOCK: usize = 64;

/// A certificate whose signature, es-version and validity window checked out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub resolver_pk: [u8; 32],
    pub client_magic: [u8; CLIENT_MAGIC_LEN],
    pub serial: u32,
    pub ts_start: u32,
    pub ts_end: u32,
}

impl Certificate {
    /// The signature covers everything after it, extensions included. The window includes both
    /// ends. A client magic of all 0xff or seven leading zeros is refused: a relay could not tell
    /// such a query from an anonymized one or from QUIC.
    pub fn verify(bytes: &[u8], provider_pk: &[u8; 32], now: u32) -> Option<Self> {
        if bytes.len() < CERT_LEN
            || bytes[..4] != CERT_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != ES_VERSION_XCHACHA
        {
            return None;
        }
        let key = VerifyingKey::from_bytes(provider_pk).ok()?;
        let signature = Signature::from_slice(&bytes[8..72]).ok()?;
        key.verify_strict(&bytes[72..], &signature).ok()?;

        let field = |at: usize| {
            u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        let mut resolver_pk = [0u8; 32];
        resolver_pk.copy_from_slice(&bytes[72..104]);
        let mut client_magic = [0u8; CLIENT_MAGIC_LEN];
        client_magic.copy_from_slice(&bytes[104..112]);
        let cert = Certificate {
            resolver_pk,
            client_magic,
            serial: field(112),
            ts_start: field(116),
            ts_end: field(120),
        };
        let usable_magic = client_magic != [0xff; CLIENT_MAGIC_LEN] && client_magic[..7] != [0; 7];
        (usable_magic
            && cert.ts_start < cert.ts_end
            && (cert.ts_start..=cert.ts_end).contains(&now))
        .then_some(cert)
    }
}

/// The valid certificate with the highest serial; invalid ones are skipped, not fatal.
pub fn best_certificate<'a>(
    candidates: impl IntoIterator<Item = &'a [u8]>,
    provider_pk: &[u8; 32],
    now: u32,
) -> Option<Certificate> {
    candidates
        .into_iter()
        .filter_map(|bytes| Certificate::verify(bytes, provider_pk, now))
        .max_by_key(|cert| cert.serial)
}

/// A client key pair and the key it shares with one certificate's resolver key.
pub struct Session {
    client_magic: [u8; CLIENT_MAGIC_LEN],
    client_pk: [u8; PUBKEY_LEN],
    shared: Zeroizing<[u8; 32]>,
}

impl Session {
    /// A new client key pair for `cert`. None when the resolver key is a low-order point, which
    /// would make the shared key known to anyone.
    pub fn new(cert: &Certificate) -> Option<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        onetdns_core::fill_random(&mut *seed);
        let secret = StaticSecret::from(*seed);
        let raw = secret.diffie_hellman(&PublicKey::from(cert.resolver_pk));
        if !raw.was_contributory() {
            return None;
        }
        Some(Session {
            client_magic: cert.client_magic,
            client_pk: PublicKey::from(&secret).to_bytes(),
            shared: Zeroizing::new(box_beforenm(raw.as_bytes())),
        })
    }

    /// Seals `query` into a packet of at least `min_len` bytes, padded to a multiple of 64, so a
    /// `min_len` that is one is the packet's size whenever the query fits. Returns the packet and
    /// the nonce its response must echo. Every call draws a new nonce, as each sealed query must
    /// have its own.
    pub fn seal(&self, query: &[u8], min_len: usize) -> (Vec<u8>, [u8; CLIENT_NONCE_LEN]) {
        let nonce = onetdns_core::random_array::<CLIENT_NONCE_LEN>();
        let mut full_nonce = [0u8; 24];
        full_nonce[..CLIENT_NONCE_LEN].copy_from_slice(&nonce);

        let packet_len = min_len
            .max(QUERY_OVERHEAD + query.len() + 1)
            .next_multiple_of(PAD_BLOCK);
        let mut padded = Vec::with_capacity(packet_len - QUERY_OVERHEAD);
        padded.extend_from_slice(query);
        padded.push(0x80);
        padded.resize(packet_len - QUERY_OVERHEAD, 0);

        let sealed = secretbox_seal(&self.shared, &full_nonce, &padded);
        let mut packet = Vec::with_capacity(QUERY_HEADER_LEN + sealed.len());
        packet.extend_from_slice(&self.client_magic);
        packet.extend_from_slice(&self.client_pk);
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&sealed);
        (packet, nonce)
    }

    /// The DNS message in a response to the query sealed with `nonce`; None for anything else,
    /// including a response to another query.
    pub fn open(&self, packet: &[u8], nonce: &[u8; CLIENT_NONCE_LEN]) -> Option<Vec<u8>> {
        if packet.len() < RESPONSE_HEADER_LEN + TAG_LEN
            || packet[..RESOLVER_MAGIC.len()] != RESOLVER_MAGIC
            || packet[RESOLVER_MAGIC.len()..RESOLVER_MAGIC.len() + CLIENT_NONCE_LEN] != nonce[..]
        {
            return None;
        }
        let mut full_nonce = [0u8; 24];
        full_nonce.copy_from_slice(&packet[RESOLVER_MAGIC.len()..RESPONSE_HEADER_LEN]);
        let plain = secretbox_open(&self.shared, &full_nonce, &packet[RESPONSE_HEADER_LEN..])?;
        unpad_checked(&plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Provider;

    fn now() -> u32 {
        crate::unix_now()
    }

    #[test]
    fn a_certificate_verifies_only_under_its_provider_key_and_window() {
        let provider = Provider::generate("2.dnscrypt-cert.test", 3_600);
        let cert = provider.cert_bytes();
        let pk = provider.provider_public_key();
        let parsed = Certificate::verify(&cert, &pk, now()).expect("유효한 인증서");
        assert_eq!(parsed.resolver_pk, provider.resolver_pk);
        assert_eq!(parsed.client_magic, provider.client_magic);

        let other = Provider::generate("2.dnscrypt-cert.test", 3_600).provider_public_key();
        assert!(
            Certificate::verify(&cert, &other, now()).is_none(),
            "다른 제공자 키"
        );
        assert!(
            Certificate::verify(&cert, &pk, parsed.ts_end + 1).is_none(),
            "만료"
        );
        assert!(
            Certificate::verify(&cert, &pk, parsed.ts_start - 1).is_none(),
            "시작 전"
        );

        let mut tampered = cert.clone();
        tampered[100] ^= 1;
        assert!(
            Certificate::verify(&tampered, &pk, now()).is_none(),
            "서명 밖 변조"
        );
        let mut version = cert.clone();
        version[5] = 1;
        assert!(
            Certificate::verify(&version, &pk, now()).is_none(),
            "es-version 1"
        );
        assert!(
            Certificate::verify(&cert[..123], &pk, now()).is_none(),
            "짧은 인증서"
        );
    }

    /// A certificate from `provider` with the given serial and window.
    fn signed(provider: &Provider, serial: u32, ts_start: u32, ts_end: u32) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let mut signed = provider.resolver_pk.to_vec();
        signed.extend_from_slice(&provider.client_magic);
        for field in [serial, ts_start, ts_end] {
            signed.extend_from_slice(&field.to_be_bytes());
        }
        let mut cert = CERT_MAGIC.to_vec();
        cert.extend_from_slice(&ES_VERSION_XCHACHA.to_be_bytes());
        cert.extend_from_slice(&[0, 0]);
        cert.extend_from_slice(&provider.signing.sign(&signed).to_bytes());
        cert.extend_from_slice(&signed);
        cert
    }

    #[test]
    fn the_highest_valid_serial_wins_and_invalid_ones_are_skipped() {
        let provider = Provider::generate("2.dnscrypt-cert.test", 3_600);
        let pk = provider.provider_public_key();
        let at = now();
        let older = signed(&provider, 7, at - 10, at + 3_600);
        let newer = signed(&provider, 8, at - 10, at + 3_600);
        let expired_but_newest = signed(&provider, 9, at - 100, at - 1);
        let backwards = signed(&provider, 10, at + 10, at - 10);
        let garbage = vec![0u8; 124];
        let best = best_certificate(
            [
                older.as_slice(),
                garbage.as_slice(),
                expired_but_newest.as_slice(),
                newer.as_slice(),
                backwards.as_slice(),
            ],
            &pk,
            at,
        )
        .unwrap();
        assert_eq!(best.serial, 8);
        let edge = signed(&provider, 1, at, at + 1);
        assert!(
            Certificate::verify(&edge, &pk, at).is_some(),
            "시작 시각 포함"
        );
        assert!(
            Certificate::verify(&edge, &pk, at + 1).is_some(),
            "끝 시각 포함"
        );
        assert!(best_certificate([garbage.as_slice()], &pk, at).is_none());
    }

    #[test]
    /// The server side of this crate opens what the client seals and the client opens the answer;
    /// a response to another nonce is refused.
    fn a_sealed_query_round_trips_through_the_server_path() {
        let provider = Provider::generate("2.dnscrypt-cert.test", 3_600);
        let cert = Certificate::verify(
            &provider.cert_bytes(),
            &provider.provider_public_key(),
            now(),
        )
        .unwrap();
        let session = Session::new(&cert).unwrap();
        let query: &[u8] =
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x04test\x00\x00\x01\x00\x01";
        let (packet, nonce) = session.seal(query, 256);
        assert_eq!(packet.len(), 256);
        assert_eq!(session.seal(query, 300).0.len(), 320);
        assert_eq!(
            session.seal(&[0; 200], 256).0.len(),
            320,
            "질의가 크면 늘어남"
        );

        let answer: &[u8] =
            b"\x12\x34\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x04test\x00\x00\x01\x00\x01";
        let reply = crate::server::respond(
            &provider,
            &packet,
            "127.0.0.1:5353".parse().unwrap(),
            true,
            &|received: Vec<u8>, _src, _budget| {
                assert_eq!(received, query);
                Some(answer.to_vec())
            },
            &|_src| true,
        )
        .unwrap();
        assert_eq!(session.open(&reply, &nonce).as_deref(), Some(answer));
        let (_, other_nonce) = session.seal(query, 256);
        assert_ne!(other_nonce, nonce);
        assert!(session.open(&reply, &other_nonce).is_none());
    }
}
