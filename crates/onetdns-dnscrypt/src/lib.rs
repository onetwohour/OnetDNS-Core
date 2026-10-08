/*!
 * @brief DNSCrypt v2: 인증서 발급과 질의 암복호화.
 *
 * @details 클라이언트는 TXT 질의로 서명된 인증서를 받아 리졸버 공개키를 얻고, 그 뒤
 *          X25519 공유키로 질의를 XChaCha20-Poly1305 암호화해 보낸다. 서명 키가 장기
 *          신뢰 근거이고, 리졸버 키는 인증서를 재발급하며 교체할 수 있다.
 */

/** @brief DNSCrypt 수신 쪽. */
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

/** @brief 인증서 시작 표식. */
pub const CERT_MAGIC: [u8; 4] = *b"DNSC";

/** @brief XChaCha20-Poly1305 암호 스위트 버전. 이 구현이 지원하는 유일한 값이다. */
pub const ES_VERSION_XCHACHA: u16 = 0x0002;

/** @brief 암호화된 응답 앞에 붙는 고정 표식. 클라이언트가 응답을 알아보는 근거다. */
pub const RESOLVER_MAGIC: [u8; 8] = [0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38];

/** @brief 클라이언트 매직 길이. 리졸버 공개키 앞부분에서 따온다. */
pub const CLIENT_MAGIC_LEN: usize = 8;

/** @brief 클라이언트가 제공하는 논스 절반의 길이. */
pub const CLIENT_NONCE_LEN: usize = 12;

/** @brief X25519 공개키 길이. */
pub const PUBKEY_LEN: usize = 32;

/**
 * @brief DNSCrypt 제공자 상태: 서명 키, 리졸버 키 쌍, 현재 인증서.
 *
 * @details 인증서만 Mutex 뒤에 둔다. 갱신되는 것은 인증서뿐이고 키는 수명 동안 고정이라,
 *          질의 처리 경로의 키 접근에 잠금이 걸리지 않는다.
 */
#[derive(Clone)]
pub struct Provider {
    /** @brief 인증서에 서명하는 키. */
    signing: SigningKey,

    /** @brief 질의를 푸는 비밀 키. */
    resolver_sk: StaticSecret,

    /** @brief 그 짝이 되는 공개 키. */
    pub resolver_pk: [u8; 32],

    /** @brief 클라이언트가 질의 앞에 붙일 값. */
    pub client_magic: [u8; CLIENT_MAGIC_LEN],

    /** @brief 지금 내주는 인증서. */
    cert: Arc<Mutex<Vec<u8>>>,
    /** @brief 이 서버를 가리키는 이름. */
    pub provider_name: String,
}

/**
 * @brief 서명된 인증서 바이트열을 만든다.
 * @details 서명 대상은 리졸버 공개키·클라이언트 매직·일련번호·유효 구간이다. 서명 키를
 *          가진 쪽만 리졸버 키를 바꿔 넣을 수 있게 하는 구조다.
 * @param valid_secs 유효 기간(초). 짧을수록 키 노출 구간이 좁아지지만 재발급이 잦아진다.
 */
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
    /** @brief 새 서명 키로 제공자를 만든다. 기존 클라이언트는 인증서를 다시 받아야 한다. */
    pub fn generate(provider_name: &str, valid_secs: u32) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        onetdns_core::fill_random(&mut *seed);
        Self::with_signing_seed(&seed, provider_name, valid_secs)
    }

    /**
     * @brief 기존 서명 시드로 제공자를 복원한다. 재시작 후에도 같은 신뢰를 유지한다.
     * @note 리졸버 키는 매번 새로 만든다. 그건 인증서로 배포되므로 바뀌어도 무방하고,
     *       주기적 교체가 오히려 바람직하다.
     */
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

    /**
     * @brief 서명 시드를 꺼낸다. 재시작 간 신원 유지를 위해 저장할 때만 쓴다.
     * @warning 장기 개인키다. 노출되면 임의의 리졸버 키를 담은 인증서를 위조할 수 있다.
     */
    pub fn signing_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /** @brief 유효 구간을 새로 잡아 인증서를 다시 서명한다. 키는 그대로다. */
    pub fn reissue_cert(&self, valid_secs: u32) {
        let fresh = build_cert(
            &self.signing,
            &self.resolver_pk,
            &self.client_magic,
            valid_secs,
        );
        *self.cert.lock().unwrap_or_else(|p| p.into_inner()) = fresh;
    }

    /** @brief 현재 인증서 사본. 포이즌된 락을 복구해 잠근다. */
    pub fn cert_bytes(&self) -> Vec<u8> {
        self.cert.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /** @brief 인증서 검증에 쓰이는 공개 서명 키. 클라이언트가 미리 알아야 하는 값이다. */
    pub fn provider_public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /**
     * @brief 클라이언트 공개키와의 공유 비밀. 질의 복호화 키가 된다.
     * @details X25519 결과를 그대로 쓰지 않고 hchacha20 을 한 번 더 건다. DNSCrypt v2 가
     *          es-version 2 의 키 교환을 그렇게 정의하며, libsodium 의 crypto_box 계열이
     *          beforenm 단계에서 하는 일과 같다. 이 단계를 빼면 어떤 표준 클라이언트도
     *          같은 키에 이르지 못한다.
     */
    pub fn shared_key(&self, client_pk: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        let raw = Zeroizing::new(
            self.resolver_sk
                .diffie_hellman(&PublicKey::from(*client_pk))
                .to_bytes(),
        );
        Zeroizing::new(box_beforenm(&raw))
    }

    /**
     * @brief 인증서 TXT 질의에 응답을 만든다.
     *
     * @details 질의 이름을 설정된 제공자 이름과 원시 옥텟으로 대조한다. 문자열로
     *          변환해 비교하면 UTF-8이 아닌 이름이 손실 변환되어 서로 다른 이름이 같아진다.
     * @return 이 서버의 인증서 질의가 아니면 None. 일반 DNS 경로로 넘어간다.
     */
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

/**
 * @brief 압축 없는 QNAME을 소문자 정규 형태로 읽는다.
 * @details 인증서 질의는 이 서버가 직접 해석한다. 압축 포인터는 따라가지 않는다. 질문
 *          섹션의 첫 이름은 압축될 수 없기 때문이다.
 */
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

/** @brief 설정된 제공자 이름을 질의와 대조할 정규 키로 바꾼다. */
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

/**
 * @brief 암호화된 질의를 복호화하고 패딩을 벗긴다.
 * @details 논스 24바이트 중 앞 12바이트만 클라이언트가 정한다. 나머지는 0이다. 질의
 *          방향에서는 클라이언트 논스만으로 유일성이 보장된다.
 * @return 인증 실패나 패딩 이상이면 None. 두 경우를 구분하지 않는다.
 */
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

/** @brief libsodium crypto_box 의 beforenm: X25519 결과에 hchacha20 을 건다. */
fn box_beforenm(raw_shared: &[u8; 32]) -> [u8; 32] {
    let zero = chacha20::cipher::generic_array::GenericArray::from([0u8; 16]);
    chacha20::hchacha::<chacha20::cipher::consts::U10>(
        chacha20::cipher::generic_array::GenericArray::from_slice(raw_shared),
        &zero,
    )
    .into()
}

/**
 * @brief crypto_secretbox_xchacha20poly1305 의 Poly1305 키와 본문용 키 스트림.
 * @details 논스 앞 16바이트로 서브키를 만들고, 뒤 8바이트를 ChaCha20 논스로 쓴다. 블록 0
 *          의 앞 32바이트가 Poly1305 키이고, 본문의 앞 32바이트는 블록 0 의 뒤 32바이트로,
 *          나머지는 블록 1부터 암호화한다. AEAD 버전과 달리 길이 블록도 AAD 도 섞지 않는다.
 * @warning 본문을 블록 1부터 흘리면 자체 구현끼리는 봉인과 열기가 맞아도 libsodium 과
 *          dnscrypt-proxy 같은 표준 클라이언트와는 한 바이트도 통하지 않는다. 자체 왕복
 *          테스트로는 이 차이가 드러나지 않으므로 외부 구현에서 추출한 기지 답으로 검사한다.
 */
struct SecretboxStream {
    /** @brief 블록 0 의 뒤 32바이트. 본문의 앞 32바이트에 쓴다. */
    head: Zeroizing<[u8; 32]>,
    /** @brief 블록 1부터 이어지는 키 스트림. */
    cipher: ChaCha20Legacy,
}

impl SecretboxStream {
    /** @brief 본문에 키 스트림을 XOR 한다. 봉인과 열기가 같은 동작이다. */
    fn apply(mut self, data: &mut [u8]) {
        let split = data.len().min(self.head.len());
        let (front, rest) = data.split_at_mut(split);
        for (byte, key) in front.iter_mut().zip(self.head.iter()) {
            *byte ^= key;
        }
        self.cipher.apply_keystream(rest);
    }
}

/** @brief 서브키로 Poly1305 키와 본문용 키 스트림을 만든다. */
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

/**
 * @brief 봉인한다. MAC 16바이트가 암호문 앞에 온다.
 * @return MAC 뒤에 암호문을 이은 바이트열.
 */
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

/**
 * @brief 봉인을 푼다.
 * @return 인증이 어긋나면 없음. 성공하면 평문.
 */
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

/**
 * @brief 상수시간 바이트 비교.
 * @warning 조기 종료하면 시간 차이로 MAC 을 한 바이트씩 맞춰 나갈 수 있다.
 */
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

/**
 * @brief 응답을 패딩해 암호화한다.
 * @details 논스 뒷 12바이트를 서버가 무작위로 채운다. 같은 질의 논스에 여러 응답을 보내도
 *          논스가 재사용되지 않게 하는 장치다. AEAD에서 논스 재사용은 치명적이다.
 * @return (전체 논스, 암호문). 논스는 그대로 응답에 담긴다.
 */
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

/** @brief ISO/IEC 7816-4 패딩: 0x80 뒤에 0을 채워 블록 배수로 맞춘다. */
pub fn pad(msg: &[u8], block: usize) -> Vec<u8> {
    let block = block.max(1);
    let mut v = msg.to_vec();
    v.push(0x80);
    while v.len() % block != 0 {
        v.push(0x00);
    }
    v
}

/** @brief 패딩을 벗긴다. 형식이 틀리면 빈 결과가 된다. */
pub fn unpad(padded: &[u8]) -> Vec<u8> {
    unpad_checked(padded).unwrap_or_default()
}

/**
 * @brief 패딩을 검사하며 벗긴다.
 * @return 0을 걷어낸 곳에 0x80이 없거나 전부 0이면 None. 잘못된 패딩을 조용히
 *         받아들이면 조작된 평문 길이가 통과한다.
 */
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

/** @brief 현재 유닉스 시각(초). 시계가 epoch 이전이면 0으로 바꾼다. */
fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

#[cfg(test)]
/** @brief 인증서 발급과 왕복, 그리고 어긋난 채우기의 거부. */
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    /** @brief 인증서를 묻는 테스트용 질의. */
    fn txt_query(label: &[u8]) -> Vec<u8> {
        let mut packet = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        packet.push(label.len() as u8);
        packet.extend_from_slice(label);
        packet.extend_from_slice(&[0, 0, 16, 0, 1]);
        packet
    }

    #[test]
    /** @brief 제공자 이름의 원래 바이트가 바뀌지 않는지. */
    fn provider_name_preserves_raw_query_octets() {
        let provider = Provider::generate("�", 86400);
        assert!(provider
            .cert_txt_response(&txt_query("�".as_bytes()))
            .is_some());
        assert!(provider.cert_txt_response(&txt_query(&[0xff])).is_none());
    }

    /** @brief 받은 인증서를 클라이언트처럼 읽는다. */
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
    /** @brief 저장한 시드로 공개 키가 그대로인지. 바뀌면 클라이언트가 이 서버를 못 알아본다. */
    fn persisted_signing_seed_keeps_provider_pubkey_stable() {
        let a = Provider::generate("2.dnscrypt-cert.onetdns", 86400);
        let seed = a.signing_seed();
        let b = Provider::with_signing_seed(&seed, "2.dnscrypt-cert.onetdns", 86400);
        assert_eq!(a.provider_public_key(), b.provider_public_key());
    }

    #[test]
    /**
     * @brief 봉인 결과가 외부 구현이 낸 기지 답과 같은지.
     *
     * @details 기대값은 이 크레이트와 무관한 구현에서 뽑았다. HChaCha20 은 XChaCha 초안의
     *          공개 벡터로, 본문 배치는 libsodium 의 crypto_secretbox 결과로 먼저 맞춘 뒤
     *          같은 배치로 계산했다. 본문을 32바이트보다 길게 잡아 블록 0 의 뒤쪽과 블록 1
     *          이후를 모두 지나게 했다. 자체 왕복 테스트만 있으면 양쪽이 똑같이 틀려도 통과한다.
     */
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
    /** @brief 어긋난 채우기를 거부하는지. */
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
    /** @brief 인증서를 다시 낼 때 키는 두고 기간만 미는지. */
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
    /** @brief 암호화된 질의의 전체 왕복. */
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

        /* MAC 을 뒤로 옮기면 거부되어야 한다. 앞에 붙는다는 것을 이렇게 못 고정한다. */
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
    /**
     * @brief 실제 UDP 소켓 위에서 인증서 조회와 암호화 질의가 오가는지.
     *
     * @details 암호 계층만 맞아도 와이어 배치가 어긋나면 어떤 클라이언트도 붙지 못한다.
     *          리스너 루프를 그대로 돌려 인증서 TXT 응답에서 리졸버 키를 꺼내고, 그 키로
     *          봉인한 질의를 보내고, 리졸버 매직이 붙은 응답을 풀어 본다.
     */
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
        /* 응답은 질문을 되울린 뒤 압축 포인터 2, 유형 2, 클래스 2, TTL 4, 길이 2, 문자열 길이 1 다음이 인증서다. */
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
