//! DNSCrypt v2: certificates and query encryption. A client fetches the signed certificate over TXT
//! to learn the resolver key, then seals queries with XChaCha20-Poly1305 under an X25519 shared
//! key. The signing key is the long-term trust anchor; the resolver key can change because clients
//! learn it from the certificate.

pub mod server;

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20Legacy;
use ed25519_dalek::{Signer, SigningKey};
use poly1305::universal_hash::KeyInit as _;
use poly1305::Poly1305;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

pub const CERT_MAGIC: [u8; 4] = *b"DNSC";

/// The only es-version this implementation supports.
pub const ES_VERSION_XCHACHA: u16 = 0x0002;

pub const RESOLVER_MAGIC: [u8; 8] = [0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38];

/// Taken from the start of the resolver public key.
pub const CLIENT_MAGIC_LEN: usize = 8;

/// The client's half of the 24-byte nonce.
pub const CLIENT_NONCE_LEN: usize = 12;

pub const PUBKEY_LEN: usize = 32;

/// Only the certificate is behind a mutex: it is the only part that changes, so the query path
/// reads the keys without locking.
#[derive(Clone)]
pub struct Provider {
    signing: SigningKey,

    resolver_sk: StaticSecret,

    pub resolver_pk: [u8; 32],

    pub client_magic: [u8; CLIENT_MAGIC_LEN],

    cert: Arc<Mutex<Vec<u8>>>,
    pub provider_name: String,
}

/// Signs the resolver public key, client magic, serial and validity window, so only the holder of
/// the signing key can substitute a resolver key.
fn build_cert(
    signing: &SigningKey,
    resolver_pk: &[u8; 32],
    client_magic: &[u8; CLIENT_MAGIC_LEN],
    valid_secs: u32,
) -> Vec<u8> {
    let now = unix_now();

    let serial: u32 = now;
    let ts_start = now;
    let ts_end = now.saturating_add(valid_secs);

    let mut signed = Vec::with_capacity(52);
    signed.extend_from_slice(resolver_pk);
    signed.extend_from_slice(client_magic);
    signed.extend_from_slice(&serial.to_be_bytes());
    signed.extend_from_slice(&ts_start.to_be_bytes());
    signed.extend_from_slice(&ts_end.to_be_bytes());
    let sig = signing.sign(&signed).to_bytes();

    let mut cert = Vec::with_capacity(124);
    cert.extend_from_slice(&CERT_MAGIC);
    cert.extend_from_slice(&ES_VERSION_XCHACHA.to_be_bytes());
    cert.extend_from_slice(&0u16.to_be_bytes());
    cert.extend_from_slice(&sig);
    cert.extend_from_slice(&signed);
    cert
}

impl Provider {
    pub fn generate(provider_name: &str, valid_secs: u32) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        onetdns_core::fill_random(&mut *seed);
        Self::with_signing_seed(&seed, provider_name, valid_secs)
    }

    /// Restores a provider from a stored signing seed, so clients keep trusting it across restarts.
    /// The resolver key is new every time; clients learn it from the certificate.
    pub fn with_signing_seed(seed: &[u8; 32], provider_name: &str, valid_secs: u32) -> Self {
        let signing = SigningKey::from_bytes(seed);

        let mut rsk = [0u8; 32];
        onetdns_core::fill_random(&mut rsk);
        let resolver_sk = StaticSecret::from(rsk);
        rsk.zeroize();
        let resolver_pk = PublicKey::from(&resolver_sk).to_bytes();

        let mut client_magic = [0u8; CLIENT_MAGIC_LEN];
        client_magic.copy_from_slice(&resolver_pk[..CLIENT_MAGIC_LEN]);

        let cert = build_cert(&signing, &resolver_pk, &client_magic, valid_secs);

        Self {
            signing,
            resolver_sk,
            resolver_pk,
            client_magic,
            cert: Arc::new(Mutex::new(cert)),
            provider_name: provider_name.to_string(),
        }
    }

    /// The long-term private key: whoever holds it can forge a certificate for any resolver key.
    /// Use it only to persist the provider across restarts.
    pub fn signing_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /// Re-signs with a new validity window; the keys stay the same.
    pub fn reissue_cert(&self, valid_secs: u32) {
        let fresh = build_cert(
            &self.signing,
            &self.resolver_pk,
            &self.client_magic,
            valid_secs,
        );
        *self.cert.lock().unwrap_or_else(|p| p.into_inner()) = fresh;
    }

    pub fn cert_bytes(&self) -> Vec<u8> {
        self.cert.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Clients must know this key in advance to verify the certificate.
    pub fn provider_public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// X25519 followed by HChaCha20, which is how DNSCrypt es-version 2 defines the key exchange
    /// (libsodium's crypto_box_beforenm). Without that step no standard client derives the same
    /// key.
    pub fn shared_key(&self, client_pk: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        let raw = Zeroizing::new(
            self.resolver_sk
                .diffie_hellman(&PublicKey::from(*client_pk))
                .to_bytes(),
        );
        Zeroizing::new(box_beforenm(&raw))
    }

    /// Compares the query name with the provider name as raw octets: converting to a string would
    /// map distinct non-UTF-8 names to the same text. Returns `None` for anything but this server's
    /// certificate query, which then takes the normal DNS path.
    pub fn cert_txt_response(&self, packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < 12 {
            return None;
        }
        if u16::from_be_bytes([packet[4], packet[5]]) < 1 {
            return None;
        }
        let (name, after_name) = read_qname(packet, 12)?;
        if after_name + 4 > packet.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([packet[after_name], packet[after_name + 1]]);
        if qtype != 16 {
            return None;
        }
        if name != configured_qname_key(&self.provider_name)? {
            return None;
        }

        let cert = self.cert_bytes();
        let question_end = after_name + 4;
        let mut resp = Vec::with_capacity(question_end + 16 + cert.len());
        resp.extend_from_slice(&packet[0..2]);
        resp.extend_from_slice(&[0x81, 0x80]);
        resp.extend_from_slice(&[0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        resp.extend_from_slice(&packet[12..question_end]);
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&[0x00, 0x10]);
        resp.extend_from_slice(&[0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]);
        let rdlen = (cert.len() + 1) as u16;
        resp.extend_from_slice(&rdlen.to_be_bytes());
        resp.push(cert.len() as u8);
        resp.extend_from_slice(&cert);
        Some(resp)
    }
}

/// Does not follow compression pointers: the first name in the question section cannot be
/// compressed.
fn read_qname(buf: &[u8], mut i: usize) -> Option<(Vec<u8>, usize)> {
    let mut name = Vec::new();
    loop {
        let len = *buf.get(i)? as usize;
        if len == 0 {
            i += 1;
            name.push(0);
            break;
        }
        if len > 63 || name.len().checked_add(len + 1)? >= 255 {
            return None;
        }
        i += 1;
        let label = buf.get(i..i + len)?;
        name.push(len as u8);
        name.extend(label.iter().map(u8::to_ascii_lowercase));
        i += len;
    }
    Some((name, i))
}

fn configured_qname_key(name: &str) -> Option<Vec<u8>> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        return Some(vec![0]);
    }
    let mut key = Vec::new();
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || key.len().checked_add(label.len() + 1)? >= 255 {
            return None;
        }
        key.push(label.len() as u8);
        key.extend(label.as_bytes().iter().map(u8::to_ascii_lowercase));
    }
    key.push(0);
    Some(key)
}

/// The client fills only the first 12 nonce bytes and the rest are zero; in the query direction the
/// client nonce alone is unique. Returns `None` on an authentication or padding failure, without
/// telling which.
pub fn decrypt_query(
    key: &[u8; 32],
    client_nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    let mut nonce = [0u8; 24];
    nonce[..12].copy_from_slice(client_nonce);
    let pt = secretbox_open(key, &nonce, ciphertext)?;
    unpad_checked(&pt)
}

fn box_beforenm(raw_shared: &[u8; 32]) -> [u8; 32] {
    let zero = chacha20::cipher::generic_array::GenericArray::from([0u8; 16]);
    chacha20::hchacha::<chacha20::cipher::consts::U10>(
        chacha20::cipher::generic_array::GenericArray::from_slice(raw_shared),
        &zero,
    )
    .into()
}

/// Poly1305 key and keystream of crypto_secretbox_xchacha20poly1305. The first 16 nonce bytes
/// derive the subkey and the last 8 are the ChaCha20 nonce. The first 32 bytes of block 0 are the
/// Poly1305 key, the first 32 message bytes use the rest of block 0, and the remainder starts at
/// block 1. Unlike the AEAD construction there is no length block and no AAD.
///
/// Starting the message at block 1 still round-trips between our own seal and open but fails
/// against libsodium and dnscrypt-proxy, so the tests check known answers from an external
/// implementation.
struct SecretboxStream {
    head: Zeroizing<[u8; 32]>,
    cipher: ChaCha20Legacy,
}

impl SecretboxStream {
    /// Sealing and opening are the same XOR.
    fn apply(mut self, data: &mut [u8]) {
        let split = data.len().min(self.head.len());
        let (front, rest) = data.split_at_mut(split);
        for (byte, key) in front.iter_mut().zip(self.head.iter()) {
            *byte ^= key;
        }
        self.cipher.apply_keystream(rest);
    }
}

fn secretbox_parts(key: &[u8; 32], nonce: &[u8; 24]) -> (Poly1305, SecretboxStream) {
    let subkey = chacha20::hchacha::<chacha20::cipher::consts::U10>(
        chacha20::cipher::generic_array::GenericArray::from_slice(key),
        chacha20::cipher::generic_array::GenericArray::from_slice(&nonce[..16]),
    );
    let mut cipher = ChaCha20Legacy::new(&subkey, nonce[16..].into());
    let mut block0 = [0u8; 64];
    cipher.apply_keystream(&mut block0);
    let mac = Poly1305::new(poly1305::Key::from_slice(&block0[..32]));
    let mut head = Zeroizing::new([0u8; 32]);
    head.copy_from_slice(&block0[32..]);
    block0.zeroize();
    (mac, SecretboxStream { head, cipher })
}

/// The 16-byte MAC comes before the ciphertext.
fn secretbox_seal(key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8]) -> Vec<u8> {
    let (mac, stream) = secretbox_parts(key, nonce);
    let mut body = plaintext.to_vec();
    stream.apply(&mut body);
    let tag = mac.compute_unpadded(&body);
    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&body);
    out
}

fn secretbox_open(key: &[u8; 32], nonce: &[u8; 24], boxed: &[u8]) -> Option<Vec<u8>> {
    if boxed.len() < 16 {
        return None;
    }
    let (tag, body) = boxed.split_at(16);
    let (mac, stream) = secretbox_parts(key, nonce);
    if !ct_eq(&mac.compute_unpadded(body), tag) {
        return None;
    }
    let mut out = body.to_vec();
    stream.apply(&mut out);
    Some(out)
}

/// Constant time: an early exit would let an attacker guess the MAC byte by byte.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The server fills the last 12 nonce bytes at random, so several responses to one query nonce
/// never reuse a nonce. Returns the full nonce, which the response carries, and the ciphertext.
pub fn encrypt_response(
    key: &[u8; 32],
    client_nonce: &[u8; 12],
    dns_response: &[u8],
) -> ([u8; 24], Vec<u8>) {
    let mut server_nonce = [0u8; 12];
    onetdns_core::fill_random(&mut server_nonce);
    let mut nonce = [0u8; 24];
    nonce[..12].copy_from_slice(client_nonce);
    nonce[12..].copy_from_slice(&server_nonce);

    let padded = pad(dns_response, 64);
    (nonce, secretbox_seal(key, &nonce, &padded))
}

/// ISO/IEC 7816-4 padding: 0x80, then zeros up to a multiple of `block`.
pub fn pad(msg: &[u8], block: usize) -> Vec<u8> {
    let block = block.max(1);
    let mut v = msg.to_vec();
    v.push(0x80);
    while v.len() % block != 0 {
        v.push(0x00);
    }
    v
}

pub fn unpad(padded: &[u8]) -> Vec<u8> {
    unpad_checked(padded).unwrap_or_default()
}

/// Returns `None` when no 0x80 precedes the zeros or everything is zero; accepting bad padding
/// would let a tampered plaintext length through.
fn unpad_checked(padded: &[u8]) -> Option<Vec<u8>> {
    let mut i = padded.len();
    while i > 0 && padded[i - 1] == 0x00 {
        i -= 1;
    }
    if i == 0 || padded[i - 1] != 0x80 {
        return None;
    }
    Some(padded[..i - 1].to_vec())
}

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    fn txt_query(label: &[u8]) -> Vec<u8> {
        let mut packet = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        packet.push(label.len() as u8);
        packet.extend_from_slice(label);
        packet.extend_from_slice(&[0, 0, 16, 0, 1]);
        packet
    }

    #[test]
    fn provider_name_preserves_raw_query_octets() {
        let provider = Provider::generate("�", 86400);
        assert!(provider
            .cert_txt_response(&txt_query("�".as_bytes()))
            .is_some());
        assert!(provider.cert_txt_response(&txt_query(&[0xff])).is_none());
    }

    fn client_parse_cert(cert: &[u8], provider_pub: &[u8; 32]) -> ([u8; 32], [u8; 8]) {
        assert_eq!(&cert[0..4], &CERT_MAGIC);
        assert_eq!(u16::from_be_bytes([cert[4], cert[5]]), ES_VERSION_XCHACHA);
        let sig = Signature::from_slice(&cert[8..72]).unwrap();
        let signed = &cert[72..124];
        let vk = VerifyingKey::from_bytes(provider_pub).unwrap();
        vk.verify(signed, &sig).expect("cert 서명 검증");
        let mut rpk = [0u8; 32];
        rpk.copy_from_slice(&signed[0..32]);
        let mut cm = [0u8; 8];
        cm.copy_from_slice(&signed[32..40]);
        (rpk, cm)
    }

    #[test]
    fn persisted_signing_seed_keeps_provider_pubkey_stable() {
        let a = Provider::generate("2.dnscrypt-cert.onetdns", 86400);
        let seed = a.signing_seed();
        let b = Provider::with_signing_seed(&seed, "2.dnscrypt-cert.onetdns", 86400);
        assert_eq!(a.provider_public_key(), b.provider_public_key());
    }

    #[test]
    /// Expected values come from implementations independent of this crate: HChaCha20 from the
    /// XChaCha draft's public vectors, the message layout from libsodium's crypto_secretbox. The
    /// message is longer than 32 bytes so it spans the end of block 0 and block 1. A round-trip
    /// test alone passes when both sides are wrong the same way.
    fn secretbox_matches_libsodium_layout() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 24] = core::array::from_fn(|i| 100 + i as u8);
        let msg = b"OnetDNS DNSCrypt secretbox known answer, longer than one half block.";
        let expected = "a1fcfe60564f2a1ecdf820a26ad00cac009a7ff9d75c488b3932a1d50f363073\
                        a341f062e01d631d6d0441e05f6959575c1297c3884bfbaea75cf251c10acfe9\
                        2fd3331fc443a4d5ac3d05cb4d7e1a7cc4652850";
        let sealed = secretbox_seal(&key, &nonce, msg);
        let hex: String = sealed.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);
        assert_eq!(
            secretbox_open(&key, &nonce, &sealed).as_deref(),
            Some(&msg[..])
        );
    }

    #[test]
    fn malformed_padding_is_rejected() {
        assert_eq!(unpad(&[]), Vec::<u8>::new());
        assert_eq!(unpad(&[1, 2, 0, 0]), Vec::<u8>::new());
        assert_eq!(unpad(&[1, 2, 0x80, 0]), vec![1, 2]);

        let key = [7u8; 32];
        let client_nonce = [3u8; 12];
        let mut nonce = [0u8; 24];
        nonce[..12].copy_from_slice(&client_nonce);
        let ciphertext = secretbox_seal(&key, &nonce, &[1, 2, 0, 0]);
        assert_eq!(decrypt_query(&key, &client_nonce, &ciphertext), None);
    }

    #[test]
    fn reissue_cert_keeps_keys_and_refreshes_window() {
        let p = Provider::generate("2.dnscrypt-cert.onetdns", 86400);
        let before = p.cert_bytes();
        let pk_before = p.resolver_pk;
        let magic_before = p.client_magic;
        p.reissue_cert(86400);
        let after = p.cert_bytes();
        assert_eq!(p.resolver_pk, pk_before);
        assert_eq!(p.client_magic, magic_before);

        assert_eq!(before.len(), after.len());
        let (rpk, _) = client_parse_cert(&after, &p.provider_public_key());
        assert_eq!(rpk, p.resolver_pk);
    }

    #[test]
    fn full_dnscrypt_roundtrip() {
        let provider = Provider::generate("2.dnscrypt-cert.onetdns", 86400);

        let (resolver_pk, client_magic) =
            client_parse_cert(&provider.cert_bytes(), &provider.provider_public_key());
        assert_eq!(client_magic, provider.client_magic);

        let mut csk = [0u8; 32];
        onetdns_core::fill_random(&mut csk);
        let client_sk = StaticSecret::from(csk);
        let client_pk = PublicKey::from(&client_sk).to_bytes();
        let raw_x25519 = client_sk
            .diffie_hellman(&PublicKey::from(resolver_pk))
            .to_bytes();
        let client_shared = box_beforenm(&raw_x25519);
        let server_shared = provider.shared_key(&client_pk);
        assert_eq!(
            client_shared.as_slice(),
            server_shared.as_slice(),
            "공유 키 일치"
        );
        assert_ne!(
            client_shared.as_slice(),
            raw_x25519.as_slice(),
            "X25519 결과를 그대로 쓰면 표준 클라이언트와 키가 어긋납니다"
        );

        let dns_query: &[u8] = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        let mut client_nonce = [0u8; 12];
        onetdns_core::fill_random(&mut client_nonce);
        let mut qnonce = [0u8; 24];
        qnonce[..12].copy_from_slice(&client_nonce);
        let padded = pad(dns_query, 64);
        let qct = secretbox_seal(&client_shared, &qnonce, &padded);
        assert_eq!(
            qct.len(),
            padded.len() + 16,
            "MAC 16바이트가 암호문에 더해집니다"
        );
        assert_ne!(
            &qct[..16],
            &qct[qct.len() - 16..],
            "MAC 곳을 가리는 우연이 아닌지 확인합니다"
        );

        let decrypted = decrypt_query(&server_shared, &client_nonce, &qct).expect("서버 복호화");
        assert_eq!(decrypted, dns_query, "복호화된 질의 = 원본");

        // A MAC moved to the end must be rejected; this pins it to the front.
        let mut tag_appended = qct[16..].to_vec();
        tag_appended.extend_from_slice(&qct[..16]);
        assert_eq!(
            decrypt_query(&server_shared, &client_nonce, &tag_appended),
            None,
            "MAC 은 암호문 앞에 옵니다"
        );

        let dns_response: &[u8] = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00fake-response";
        let (rnonce, rct) = encrypt_response(&server_shared, &client_nonce, dns_response);
        let rpt = secretbox_open(&client_shared, &rnonce, &rct).expect("클라이언트 복호화");
        assert_eq!(unpad(&rpt), dns_response, "복호화된 응답 = 원본");
    }

    #[test]
    /// Runs the real listener loop: correct crypto with a wrong wire layout would still lock out
    /// every client.
    fn dnscrypt_listener_answers_over_a_real_socket() {
        use std::net::UdpSocket;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let provider = Provider::generate("2.dnscrypt-cert.onetdns", 86400);
        let provider_pub = provider.provider_public_key();
        let server_socket = UdpSocket::bind("127.0.0.1:0").expect("서버 소켓");
        let server_addr = server_socket.local_addr().expect("서버 주소");
        let shutdown = Arc::new(AtomicBool::new(false));

        let answer: &[u8] = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        let listener_shutdown = shutdown.clone();
        let listener = std::thread::spawn(move || {
            crate::server::serve(
                provider,
                server_socket,
                |query: Vec<u8>, _src, _budget| {
                    assert_eq!(&query[12..], b"\x07example\x03com\x00\x00\x01\x00\x01");
                    Some(answer.to_vec())
                },
                |_src| true,
                &listener_shutdown,
            )
        });

        let client = UdpSocket::bind("127.0.0.1:0").expect("클라이언트 소켓");
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("수신 제한 시간");
        let mut buf = [0u8; 4096];

        let mut question = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in "2.dnscrypt-cert.onetdns".split('.') {
            question.push(label.len() as u8);
            question.extend_from_slice(label.as_bytes());
        }
        question.extend_from_slice(&[0, 0, 16, 0, 1]);
        client.send_to(&question, server_addr).expect("인증서 조회");
        let (n, _) = client.recv_from(&mut buf).expect("인증서 응답");
        // The answer echoes the question; a compression pointer (2), type (2), class (2), TTL (4),
        // length (2) and string length (1) precede the certificate.
        let cert_start = question.len() + 13;
        let (resolver_pk, client_magic) = client_parse_cert(&buf[cert_start..n], &provider_pub);

        let mut client_secret = [0u8; 32];
        onetdns_core::fill_random(&mut client_secret);
        let client_sk = StaticSecret::from(client_secret);
        let client_pk = PublicKey::from(&client_sk).to_bytes();
        let shared = box_beforenm(
            &client_sk
                .diffie_hellman(&PublicKey::from(resolver_pk))
                .to_bytes(),
        );

        let dns_query: &[u8] = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        let mut client_nonce = [0u8; 12];
        onetdns_core::fill_random(&mut client_nonce);
        let mut nonce = [0u8; 24];
        nonce[..12].copy_from_slice(&client_nonce);
        let mut packet = Vec::new();
        packet.extend_from_slice(&client_magic);
        packet.extend_from_slice(&client_pk);
        packet.extend_from_slice(&client_nonce);
        packet.extend_from_slice(&secretbox_seal(&shared, &nonce, &pad(dns_query, 256)));
        client.send_to(&packet, server_addr).expect("암호화 질의");

        let (n, from) = client.recv_from(&mut buf).expect("암호화 응답");
        assert_eq!(from, server_addr, "응답은 질의를 보낸 주소에서 옵니다");
        assert_eq!(&buf[..8], &RESOLVER_MAGIC, "응답 매직");
        assert!(
            n <= packet.len(),
            "UDP 응답이 질의보다 길면 증폭이 됩니다: 응답={n} 질의={}",
            packet.len()
        );
        let mut response_nonce = [0u8; 24];
        response_nonce.copy_from_slice(&buf[8..32]);
        assert_eq!(
            &response_nonce[..12],
            &client_nonce,
            "논스 앞절반은 클라이언트 것"
        );
        let plain = secretbox_open(&shared, &response_nonce, &buf[32..n]).expect("응답 복호화");
        assert_eq!(
            unpad(&plain),
            answer,
            "와이어로 받은 응답 = 서버가 만든 응답"
        );

        shutdown.store(true, Ordering::Release);
        listener
            .join()
            .expect("리스너 스레드")
            .expect("리스너 종료");
    }
}
