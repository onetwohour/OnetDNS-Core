/*!
 * @brief 차단 방식 TLS 연결. DoT와 TCP 위 DoH가 쓴다.
 *
 * @details 소켓을 직접 읽고 쓴다. 1.3을 먼저 시도하고, 상대가 1.2만 알면 그쪽으로 간다.
 * @note engine의 sans-IO 구현과 별개다. 둘이 와이어 원시 요소만 나눠 쓰고 상태 기계는
 *       각자 갖는다.
 */

use std::io::{Read, Write};
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::aead::{aead_for_suite, Aead, RecordCrypto};
use crate::cert::{
    certificate_chain_is_valid, certificate_verify_content, CertEntry, CertificateMsg,
    CertificateVerify,
};
use crate::handshake::{HandshakeMsg, HandshakeReader, HandshakeType};
use crate::keyschedule::{
    finished_key, finished_verify_data, suite_params, traffic_keys, traffic_update, Hash,
    KeySchedule, Transcript,
};
use crate::kx::KeyExchange;
use crate::msg::consts::*;
use crate::msg::{ClientHello, Extension, ServerHello};
use crate::record::{ContentType, TlsRecord, MAX_CIPHERTEXT, MAX_FRAGMENT};
use crate::sys::{fill_random, random_32};
use crate::tls12::{self, Tls12RecordCrypto};
use crate::wire::Writer;
use crate::x509::X509;
use crate::TlsError;

/** @brief 응용 데이터 사이에 허용할 연속 빈 레코드. */
const MAX_CONSECUTIVE_EMPTY_APPLICATION_RECORDS: usize = 32;

/** @brief 한 연결에서 보낼 수 있는 TLS 1.3 키 세대 수. */
const MAX_TLS13_KEY_UPDATES: u64 = (1u64 << 48) - 1;

/** @brief 경고 레코드를 오류로 옮긴다. 정상 종료 통지는 오류와 구분한다. */
fn alert_error(payload: &[u8]) -> TlsError {
    if payload.len() < 2 || payload.len() % 2 != 0 {
        return TlsError::Protocol;
    }
    for alert in payload.chunks_exact(2) {
        let level = alert[0];
        let description = alert[1];
        if description != 0 {
            return TlsError::PeerAlert { level, description };
        }
    }
    TlsError::CloseNotify
}

/** @brief 지금 쓰는 레코드 보호. 판마다 방식이 다르다. */
enum RecordLayer {
    /** @brief 1.3 방식. */
    Tls13(RecordCrypto),
    /** @brief 1.2 방식. */
    Tls12(Tls12RecordCrypto),
}

impl RecordLayer {
    /** @brief 레코드를 암호화한다. */
    fn encrypt(&mut self, ct: ContentType, pt: &[u8]) -> Result<TlsRecord, TlsError> {
        match self {
            RecordLayer::Tls13(c) => c.encrypt(ct, pt),
            RecordLayer::Tls12(c) => c.encrypt(ct, pt),
        }
    }

    /** @brief 레코드를 복호화한다. */
    fn decrypt(&mut self, rec: &TlsRecord) -> Result<(ContentType, Vec<u8>), TlsError> {
        if rec.version != crate::record::LEGACY_VERSION {
            return Err(TlsError::Protocol);
        }

        let (content_type, plaintext, limit) = match self {
            RecordLayer::Tls13(c) => {
                let (content_type, plaintext) = c.decrypt(rec)?;
                (content_type, plaintext, MAX_FRAGMENT)
            }
            RecordLayer::Tls12(c) => (rec.content_type, c.decrypt(rec)?, MAX_FRAGMENT),
        };
        if plaintext.len() > limit {
            return Err(TlsError::RecordOverflow);
        }
        Ok((content_type, plaintext))
    }
}

#[derive(Clone)]
/** @brief 서버 설정. 인증서와 키, 프로토콜 목록을 담는다. */
pub struct ServerConfig {
    /** @brief 보낼 인증서 체인. */
    pub cert_chain: Vec<Vec<u8>>,
    /** @brief 서명에 쓸 방식. */
    pub sign_scheme: u16,
    /** @brief 실제로 서명하는 것. 키를 직접 잡지 않는다. */
    pub sign: Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>,

    /** @brief 이쪽이 받아들일 ALPN 목록. */
    pub alpn: Vec<Vec<u8>>,

    /** @brief 클라이언트 인증서를 검증할 루트들. 없으면 요구하지 않는다. */
    pub client_ca: Option<crate::trust::TrustStore>,

    /** @brief 다시 붙기를 허용할 설정. 없으면 매번 처음부터 핸드셰이크한다. */
    pub resumption: Option<ServerResumption>,
}

#[derive(Clone)]
/** @brief 세션 재개 설정. */
pub struct ServerResumption {
    /** @brief 티켓을 암호화하고 복호화하는 것. */
    pub ticketer: Arc<crate::session::Ticketer>,

    /** @brief 티켓이 유효한 기간. */
    pub lifetime_secs: u32,

    /** @brief 왕복 없이 받아들일 자료 크기. 0이면 받지 않는다. */
    pub max_early_data: u32,
}

impl ServerResumption {
    /**
     * @brief 암호화 DNS 전송에 쓸 안전한 기본 재개 설정.
     *
     * @warning max_early_data를 0이 아니게 두지 말 것. 이 크레이트에는 안티리플레이가
     *          없다. 일회용 티켓도, ClientHello 기록도, freshness 구간도 구현돼 있지 않다.
     *          RFC 8446은 0-RTT를 받는 서버가 그중 하나를 반드시 갖추라고 요구한다.
     *          지금 서버가 0-RTT를 아예 받지 않는 이유가 이 값 하나이므로, 올리려면
     *          안티리플레이를 먼저 만들어야 한다. 0-RTT 자료는 전방 비밀성도 없다.
     */
    pub fn secure_default() -> Self {
        ServerResumption {
            ticketer: Arc::new(crate::session::Ticketer::new()),
            lifetime_secs: 7200,

            max_early_data: 0,
        }
    }
}

impl ServerConfig {
    /** @brief 인증서 하나와 키로 설정을 만든다. */
    pub fn from_pkcs8(cert_der: Vec<u8>, key_pkcs8_der: &[u8]) -> Option<Self> {
        Self::from_chain_pkcs8(vec![cert_der], key_pkcs8_der)
    }

    /** @brief 체인과 키로 설정을 만든다. */
    pub fn from_chain_pkcs8(cert_chain: Vec<Vec<u8>>, key_pkcs8_der: &[u8]) -> Option<Self> {
        if !certificate_chain_is_valid(&cert_chain, false) {
            return None;
        }
        let (sign_scheme, sign) = signer_from_pkcs8_der(key_pkcs8_der)?;

        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::pkcs8::DecodePrivateKey;
        let secret = p256::SecretKey::from_pkcs8_der(key_pkcs8_der).ok()?;
        let leaf = X509::parse(&cert_chain[0]).ok()?;
        if leaf.public_key != secret.public_key().to_encoded_point(false).as_bytes() {
            return None;
        }
        Some(ServerConfig {
            cert_chain,
            sign_scheme,
            sign,
            alpn: Vec::new(),
            client_ca: None,
            resumption: None,
        })
    }

    /** @brief 협상할 응용 프로토콜을 정한다. */
    pub fn with_alpn(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn = protocols;
        self
    }

    /** @brief 클라이언트 인증을 켠다. 이 저장소로 체인을 검증한다. */
    pub fn with_client_ca(mut self, store: crate::trust::TrustStore) -> Self {
        self.client_ca = Some(store);
        self
    }

    /** @brief 세션 재개를 켠다. */
    pub fn with_resumption(mut self, r: ServerResumption) -> Self {
        self.resumption = Some(r);
        self
    }
}

#[derive(Clone)]
/** @brief 클라이언트 인증서와 서명 키. */
pub struct ClientCert {
    /** @brief 보낼 인증서 체인. */
    pub chain: Vec<Vec<u8>>,
    /** @brief 서명에 쓸 방식. */
    pub sign_scheme: u16,
    /** @brief 실제로 서명하는 것. */
    pub sign: Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>,
}

impl ClientCert {
    /** @brief 체인과 키로 만든다. */
    pub fn from_pkcs8(chain: Vec<Vec<u8>>, key_pkcs8_der: &[u8]) -> Option<Self> {
        if !certificate_chain_is_valid(&chain, false) {
            return None;
        }
        let (sign_scheme, sign) = signer_from_pkcs8_der(key_pkcs8_der)?;
        Some(ClientCert {
            chain,
            sign_scheme,
            sign,
        })
    }
}

/** @brief 키 바이트에서 서명자를 만든다. 키 종류를 알아서 가린다. */
pub fn signer_from_pkcs8_der(
    der: &[u8],
) -> Option<(u16, Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>)> {
    use p256::pkcs8::DecodePrivateKey;
    if let Ok(secret) = p256::SecretKey::from_pkcs8_der(der) {
        let signing = p256::ecdsa::SigningKey::from(secret);
        let f = move |content: &[u8]| -> Vec<u8> {
            use p256::ecdsa::{signature::Signer, Signature};
            let sig: Signature = signing.sign(content);
            sig.to_der().as_bytes().to_vec()
        };
        return Some((ECDSA_SECP256R1_SHA256, Arc::new(f)));
    }
    None
}

#[derive(Debug, Clone, Copy)]
/**
 * @brief 인증서 검증을 끄는 표시.
 * @warning 이름 자체가 경고다. 테스트와 명시적으로 위험을 감수한 설정에만 쓴다.
 */
pub struct InsecureVerifier(());

impl InsecureVerifier {
    /** @brief 검증을 끈다. 이 이름이 곧 문서다. */
    pub fn dangerously_disable_certificate_verification() -> Self {
        Self(())
    }
}

/** @brief 클라이언트 설정. */
pub struct ClientConfig {
    /** @brief 붙을 서버 이름. */
    pub server_name: String,

    /** @brief 인증서의 이름이 맞는지 볼지. */
    pub verify_name: bool,

    /** @brief 인증서를 검증할 루트들. */
    pub roots: Option<crate::trust::TrustStore>,

    /** @brief 검증을 대신할 것. 테스트 말고는 쓰지 않는다. */
    pub insecure_verifier: Option<InsecureVerifier>,

    /** @brief 이쪽이 쓰고 싶은 ALPN 목록. */
    pub alpn: Vec<Vec<u8>>,

    /** @brief 이쪽이 낼 인증서. 서버가 요구할 때 쓴다. */
    pub client_cert: Option<ClientCert>,

    /** @brief 다시 붙을 때 쓸 앞선 세션. */
    pub session: Option<crate::session::TlsSession>,

    /** @brief 왕복 없이 자료를 보낼지. */
    pub enable_early_data: bool,

    /** @brief 첫 메시지에 키 조각을 담을지. */
    pub send_key_share: bool,
}

/** @brief 프로토콜 이름들이 와이어에 담길 수 있는 형태인지. */
pub(crate) fn alpn_protocols_are_valid(protocols: &[Vec<u8>]) -> bool {
    let mut total = 0usize;
    let mut seen = std::collections::HashSet::new();
    for protocol in protocols {
        if protocol.is_empty() || protocol.len() > u8::MAX as usize || !seen.insert(protocol) {
            return false;
        }
        let Some(next) = total.checked_add(1 + protocol.len()) else {
            return false;
        };
        total = next;
    }
    total <= u16::MAX as usize
}

/** @brief 이 설정으로 만든 인사말이 와이어에 담기는지. 핸드셰이크 전에 확인한다. */
pub(crate) fn client_config_wire_is_valid(cfg: &ClientConfig) -> bool {
    let server_name = cfg.server_name.as_bytes();
    if server_name.is_empty()
        || server_name.len() > 253
        || !server_name.is_ascii()
        || server_name.contains(&0)
        || !alpn_protocols_are_valid(&cfg.alpn)
    {
        return false;
    }
    if cfg
        .client_cert
        .as_ref()
        .is_some_and(|certificate| !certificate_chain_is_valid(&certificate.chain, false))
    {
        return false;
    }
    cfg.session.as_ref().is_none_or(|session| {
        session.server_name == cfg.server_name
            && suite_params(session.suite).is_some_and(|(hash, _)| session.psk.len() == hash.len())
            && !session.ticket.is_empty()
            && session.ticket.len() <= u16::MAX as usize
            && session.server_transport_params.len() <= u16::MAX as usize
            && session.alpn.as_ref().is_none_or(|protocol| {
                !protocol.is_empty()
                    && protocol.len() <= u8::MAX as usize
                    && cfg.alpn.contains(protocol)
            })
    })
}

/** @brief 서버 설정이 와이어에 담기는지. */
pub(crate) fn server_config_wire_is_valid(cfg: &ServerConfig) -> bool {
    certificate_chain_is_valid(&cfg.cert_chain, false)
        && alpn_protocols_are_valid(&cfg.alpn)
        && cfg.resumption.as_ref().is_none_or(|resumption| {
            resumption.lifetime_secs <= crate::session::MAX_TICKET_LIFETIME_SECS
        })
}

impl Default for ClientConfig {
    /** @brief 기본 설정. */
    fn default() -> Self {
        ClientConfig {
            server_name: String::new(),
            verify_name: true,
            roots: Some(crate::trust::TrustStore::system()),
            insecure_verifier: None,
            alpn: Vec::new(),
            client_cert: None,
            session: None,
            enable_early_data: false,
            send_key_share: true,
        }
    }
}

/** @brief 진단 로그에 쓸 짧은 16진 표기. */
fn short_hex(bytes: &[u8]) -> String {
    /** @brief 16진 문자표. */
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().min(32) * 2);
    for &b in bytes.iter().take(32) {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/** @brief 핸드셰이크를 마친 연결. 응용 데이터를 주고받는다. */
pub struct TlsConnection {
    /** @brief 받는 쪽 암호 상태. */
    read: RecordLayer,
    /** @brief 보내는 쪽 암호 상태. */
    write: RecordLayer,

    /** @brief 협상한 버전. */
    version: u16,

    /** @brief 협상한 ALPN. */
    alpn: Option<Vec<u8>>,

    /** @brief 상대가 인증서로 자신을 증명했는지. */
    client_authenticated: bool,

    /** @brief 그 인증서에 적힌 신원. */
    client_auth_identity: Option<String>,

    /** @brief 상대가 보낸 인증서 체인. */
    peer_chain: Vec<Vec<u8>>,

    /** @brief 이 연결이 클라이언트 쪽인지. 핸드셰이크 뒤 메시지 방향을 검사한다. */
    is_client: bool,

    /** @brief 레코드 경계에 걸친 핸드셰이크 뒤 메시지 조각. */
    post_handshake: HandshakeReader,

    /** @brief TLS 1.3 방향별 응용 비밀. 키 갱신 때만 필요하다. */
    traffic: Option<Tls13Traffic>,

    /** @brief 이 연결이 PSK로 재개됐는지. */
    resumed: bool,

    /** @brief 서버가 보낼 다음 티켓의 PSK를 만드는 비밀. */
    resumption: Option<ClientResumption>,

    /** @brief 핸드셰이크 뒤 받아 외부가 아직 가져가지 않은 세션. */
    new_sessions: Vec<crate::session::TlsSession>,
}

/** @brief TLS 1.3 응용 키를 다음 세대로 바꾸는 데 필요한 최소 상태. */
struct Tls13Traffic {
    /** @brief 레코드 보호 알고리즘. */
    aead: Aead,
    /** @brief 비밀을 늘리는 해시. */
    hash: Hash,
    /** @brief 파생할 AEAD 키 길이. */
    key_len: usize,
    /** @brief 상대가 보내는 방향의 현재 비밀. */
    read_secret: Vec<u8>,
    /** @brief 이쪽이 보내는 방향의 현재 비밀. */
    write_secret: Vec<u8>,
    /** @brief 이쪽이 이미 보낸 키 갱신 횟수. */
    write_updates: u64,
}

impl Drop for Tls13Traffic {
    /** @brief 응용 traffic secret을 연결 종료 때 지운다. */
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.read_secret.zeroize();
        self.write_secret.zeroize();
    }
}

/** @brief 클라이언트가 NewSessionTicket을 실제 재개 세션으로 바꾸는 상태. */
struct ClientResumption {
    /** @brief 티켓을 받을 때 결속할 서버 이름. */
    server_name: String,
    /** @brief 티켓 nonce를 PSK로 늘리는 해시. */
    hash: Hash,
    /** @brief 재접속 때 제안할 암호 스위트. */
    suite: u16,
    /** @brief 서버 Finished까지 묶인 재개 기준 비밀. */
    master: Vec<u8>,
}

impl Drop for ClientResumption {
    /** @brief 연결 종료 때 재개 기준 비밀을 지운다. */
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.master.zeroize();
    }
}

impl TlsConnection {
    /** @brief 합의된 응용 프로토콜. */
    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /** @brief 상대가 보낸 인증서 체인. */
    pub fn peer_chain(&self) -> &[Vec<u8>] {
        &self.peer_chain
    }

    /** @brief 합의된 버전. */
    pub fn version(&self) -> u16 {
        self.version
    }

    /** @brief 클라이언트 인증서를 확인했는지. */
    pub fn client_authenticated(&self) -> bool {
        self.client_authenticated
    }

    /** @brief 확인된 클라이언트 신원. */
    pub fn client_auth_identity(&self) -> Option<&str> {
        self.client_auth_identity.as_deref()
    }

    /** @brief 이 연결이 PSK-DHE로 재개됐는지. */
    pub fn is_resumed(&self) -> bool {
        self.resumed
    }

    /** @brief 새로 받은 재개 세션을 소유권과 함께 꺼낸다. */
    pub fn take_sessions(&mut self) -> Vec<crate::session::TlsSession> {
        std::mem::take(&mut self.new_sessions)
    }

    /** @brief 받는 TLS 1.3 응용 키를 다음 세대로 원자 교체한다. */
    fn update_read_key(&mut self) -> Result<(), TlsError> {
        let traffic = self.traffic.as_mut().ok_or(TlsError::Protocol)?;
        let secret = traffic_update(traffic.hash, &traffic.read_secret);
        let (key, iv) = traffic_keys(traffic.hash, &secret, traffic.key_len);
        use zeroize::Zeroize;
        traffic.read_secret.zeroize();
        traffic.read_secret = secret;
        self.read = RecordLayer::Tls13(RecordCrypto::new(traffic.aead, key, iv12(iv)));
        Ok(())
    }

    /** @brief 보내는 TLS 1.3 응용 키를 다음 세대로 원자 교체한다. */
    fn update_write_key(&mut self) -> Result<(), TlsError> {
        let traffic = self.traffic.as_mut().ok_or(TlsError::Protocol)?;
        if traffic.write_updates >= MAX_TLS13_KEY_UPDATES {
            return Err(TlsError::SeqExhausted);
        }
        let secret = traffic_update(traffic.hash, &traffic.write_secret);
        let (key, iv) = traffic_keys(traffic.hash, &secret, traffic.key_len);
        use zeroize::Zeroize;
        traffic.write_secret.zeroize();
        traffic.write_secret = secret;
        traffic.write_updates += 1;
        self.write = RecordLayer::Tls13(RecordCrypto::new(traffic.aead, key, iv12(iv)));
        Ok(())
    }

    /** @brief 송신 키 세대를 한 번 더 올릴 수 있는지. */
    fn can_update_write_key(&self) -> bool {
        self.traffic
            .as_ref()
            .is_some_and(|traffic| traffic.write_updates < MAX_TLS13_KEY_UPDATES)
    }

    /** @brief 현재 보내는 키로 KeyUpdate를 보낸 뒤 새 키로 넘어간다. */
    fn send_key_update<S: Write>(
        &mut self,
        s: &mut S,
        request_peer_update: bool,
    ) -> Result<(), TlsError> {
        if !self.can_update_write_key() {
            return Err(TlsError::SeqExhausted);
        }
        let encoded = HandshakeMsg::new(
            HandshakeType::KeyUpdate,
            vec![u8::from(request_peer_update)],
        )
        .encode();
        let record = match &mut self.write {
            RecordLayer::Tls13(crypto) => crypto.encrypt(ContentType::Handshake, &encoded)?,
            RecordLayer::Tls12(_) => return Err(TlsError::Protocol),
        };
        write_record(s, &record)?;
        self.update_write_key()
    }

    /** @brief AES-GCM·sequence 한계의 마지막 한 건을 KeyUpdate에 쓰도록 보장한다. */
    fn ensure_write_key_capacity<S: Write>(&mut self, s: &mut S) -> Result<(), TlsError> {
        let update = match &self.write {
            RecordLayer::Tls13(crypto) => crypto.needs_key_update(),
            RecordLayer::Tls12(_) => false,
        };
        if update && self.traffic.is_some() {
            self.send_key_update(s, false)?;
        }
        Ok(())
    }

    /**
     * @brief 응용 데이터를 보낸다.
     * @note 평문 크기 상한에 맞춰 나눈다. 넘기면 상대가 레코드를 거부한다.
     */
    pub fn write_app<S: Write>(&mut self, s: &mut S, data: &[u8]) -> Result<(), TlsError> {
        /** @brief 한 번에 보낼 응용 자료 크기. 조각 상한을 넘지 않게 잡는다. */
        const APP_CHUNK: usize = MAX_FRAGMENT;
        if data.is_empty() {
            self.ensure_write_key_capacity(s)?;
            let rec = self.write.encrypt(ContentType::ApplicationData, data)?;
            return write_record(s, &rec);
        }
        for chunk in data.chunks(APP_CHUNK) {
            self.ensure_write_key_capacity(s)?;
            let rec = self.write.encrypt(ContentType::ApplicationData, chunk)?;
            write_record(s, &rec)?;
        }
        Ok(())
    }

    /**
     * @brief 더 보낼 것이 없음을 알린다.
     * @details RFC 8446이 쓰기 쪽을 닫기 전에 close_notify를 보내라고 정한다. 알리지 않고
     *          연결만 끊으면 상대는 중간에서 잘린 것과 구분하지 못한다.
     */
    pub fn send_close_notify<S: Write>(&mut self, s: &mut S) -> Result<(), TlsError> {
        /** @brief warning 수준 close_notify. */
        const CLOSE_NOTIFY: [u8; 2] = [1, 0];
        let rec = self.write.encrypt(ContentType::Alert, &CLOSE_NOTIFY)?;
        write_record(s, &rec)
    }

    /** @brief 응용 데이터를 받는다. 핸드셰이크 뒤 메시지도 여기서 처리한다. */
    pub fn read_app<S: Read + Write>(&mut self, s: &mut S) -> Result<Vec<u8>, TlsError> {
        let mut ignored_records = 0usize;
        let mut post_handshake_messages = 0usize;
        let mut answered_key_update = false;
        loop {
            let rec = read_record(s)?;
            if rec.content_type == ContentType::ChangeCipherSpec {
                return Err(TlsError::Protocol);
            }
            let (ct, pt) = self.read.decrypt(&rec)?;
            match ct {
                ContentType::ApplicationData if pt.is_empty() => {
                    ignored_records += 1;
                    if ignored_records > MAX_CONSECUTIVE_EMPTY_APPLICATION_RECORDS {
                        return Err(TlsError::Protocol);
                    }
                }
                ContentType::ApplicationData => {
                    if self.post_handshake.has_pending() {
                        return Err(TlsError::Protocol);
                    }
                    return Ok(pt);
                }
                ContentType::Handshake if pt.is_empty() => return Err(TlsError::Protocol),
                ContentType::Handshake => {
                    ignored_records += 1;
                    if ignored_records > MAX_CONSECUTIVE_EMPTY_APPLICATION_RECORDS
                        || self.version != TLS13
                    {
                        return Err(TlsError::Protocol);
                    }
                    let had_pending = self.post_handshake.has_pending();
                    self.post_handshake.feed(&pt);
                    while let Some(msg) = self.post_handshake.next_message()? {
                        post_handshake_messages += 1;
                        if post_handshake_messages > MAX_CONSECUTIVE_EMPTY_APPLICATION_RECORDS {
                            return Err(TlsError::Protocol);
                        }
                        match msg.msg_type {
                            HandshakeType::NewSessionTicket if self.is_client => {
                                let ticket = crate::msg::NewSessionTicket::parse(&msg.body)?;
                                if ticket.lifetime_secs > 0 {
                                    let Some(resumption) = &self.resumption else {
                                        continue;
                                    };
                                    let max_early_data = ticket.max_early_data();
                                    let psk = crate::keyschedule::resumption_psk(
                                        resumption.hash,
                                        &resumption.master,
                                        &ticket.nonce,
                                    );
                                    self.new_sessions.push(crate::session::TlsSession {
                                        server_name: resumption.server_name.clone(),
                                        suite: resumption.suite,
                                        psk,
                                        ticket: ticket.ticket,
                                        lifetime_secs: ticket
                                            .lifetime_secs
                                            .min(crate::session::MAX_TICKET_LIFETIME_SECS),
                                        age_add: ticket.age_add,
                                        max_early_data,
                                        alpn: self.alpn.clone(),
                                        server_transport_params: Vec::new(),
                                        obtained_at_ms: crate::session::now_ms(),
                                    });
                                }
                            }
                            HandshakeType::KeyUpdate
                                if !had_pending
                                    && pt.len() == 5
                                    && msg.body.len() == 1
                                    && msg.body[0] <= 1 =>
                            {
                                self.update_read_key()?;
                                if msg.body[0] == 1
                                    && !answered_key_update
                                    && self.can_update_write_key()
                                {
                                    self.send_key_update(s, false)?;
                                    answered_key_update = true;
                                }
                            }
                            _ => return Err(TlsError::Protocol),
                        }
                    }
                }
                ContentType::Alert if self.version == TLS13 && pt.len() != 2 => {
                    return Err(TlsError::Protocol);
                }
                ContentType::Alert => return Err(alert_error(&pt)),
                _ => return Err(TlsError::Protocol),
            }
        }
    }
}

/** @brief 연결을 읽기와 쓰기로 감싼 것. 평범한 스트림처럼 쓸 수 있다. */
pub struct TlsStream<S> {
    /** @brief 이 연결의 암호 상태. */
    conn: TlsConnection,
    /** @brief 하위 전송 스트림. */
    inner: S,
    /** @brief 풀어 놓았지만 아직 위로 넘기지 않은 자료. */
    rbuf: Vec<u8>,
    /** @brief 그 자료를 어디까지 넘겼는지. */
    rpos: usize,
}

impl<S: Read + Write> TlsStream<S> {
    /** @brief 연결과 소켓을 묶는다. */
    pub fn new(conn: TlsConnection, inner: S) -> Self {
        TlsStream {
            conn,
            inner,
            rbuf: Vec::new(),
            rpos: 0,
        }
    }

    /** @brief 협상한 ALPN. */
    pub fn alpn(&self) -> Option<&[u8]> {
        self.conn.alpn()
    }

    /** @brief 클라이언트가 인증서로 자신을 증명했는지. */
    pub fn client_authenticated(&self) -> bool {
        self.conn.client_authenticated()
    }

    /** @brief 그 인증서에 적힌 신원. */
    pub fn client_auth_identity(&self) -> Option<&str> {
        self.conn.client_auth_identity()
    }

    /** @brief 상대가 보낸 인증서 체인. */
    pub fn peer_chain(&self) -> &[Vec<u8>] {
        self.conn.peer_chain()
    }

    /** @brief 이 스트림이 PSK-DHE로 재개됐는지. */
    pub fn is_resumed(&self) -> bool {
        self.conn.is_resumed()
    }

    /** @brief 새로 받은 재개 세션을 꺼낸다. */
    pub fn take_sessions(&mut self) -> Vec<crate::session::TlsSession> {
        self.conn.take_sessions()
    }

    /** @brief 밑에 깔린 소켓. */
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: Read + Write> Read for TlsStream<S> {
    /** @brief 응용 데이터를 읽는다. */
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.rpos >= self.rbuf.len() {
            match self.conn.read_app(&mut self.inner) {
                Ok(data) if !data.is_empty() => {
                    self.rbuf = data;
                    self.rpos = 0;
                }
                Ok(_) => continue,
                Err(TlsError::CloseNotify) => return Ok(0),
                Err(TlsError::Eof) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        TlsError::Eof.to_string(),
                    ))
                }
                Err(error) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        error.to_string(),
                    ))
                }
            }
        }
        let n = (self.rbuf.len() - self.rpos).min(out.len());
        out[..n].copy_from_slice(&self.rbuf[self.rpos..self.rpos + n]);
        self.rpos += n;
        Ok(n)
    }
}

impl<S: Read + Write> Write for TlsStream<S> {
    /** @brief 응용 데이터를 쓴다. */
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        self.conn
            .write_app(&mut self.inner, data)
            .map_err(|_| std::io::Error::other("Could not write TLS data"))?;
        Ok(data.len())
    }
    /** @brief 밑에 깔린 소켓을 비운다. */
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/**
 * @brief 레코드 하나를 읽는다.
 * @retval TlsError::Eof 첫 바이트를 읽기 전에 연결이 닫혔다.
 */
fn read_record<S: Read>(s: &mut S) -> Result<TlsRecord, TlsError> {
    let mut hdr = [0u8; 5];
    let first = loop {
        match s.read(&mut hdr) {
            Ok(0) => return Err(TlsError::Eof),
            Ok(n) => break n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(TlsError::Io),
        }
    };
    s.read_exact(&mut hdr[first..]).map_err(|_| TlsError::Io)?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len > MAX_CIPHERTEXT {
        return Err(TlsError::RecordOverflow);
    }
    let mut frag = vec![0u8; len];
    s.read_exact(&mut frag).map_err(|_| TlsError::Io)?;
    Ok(TlsRecord {
        content_type: ContentType(hdr[0]),
        version: u16::from_be_bytes([hdr[1], hdr[2]]),
        fragment: frag,
    })
}

/** @brief 레코드 하나를 쓴다. */
fn write_record<S: Write>(s: &mut S, rec: &TlsRecord) -> Result<(), TlsError> {
    if rec.fragment.len() > MAX_CIPHERTEXT {
        return Err(TlsError::RecordOverflow);
    }
    s.write_all(&rec.encode()).map_err(|_| TlsError::Io)
}

/** @brief 큰 평문 핸드셰이크 메시지를 레코드 상한에 맞춰 보낸다. */
fn write_plain_handshake<S: Write>(s: &mut S, encoded: &[u8]) -> Result<(), TlsError> {
    for chunk in encoded.chunks(MAX_FRAGMENT) {
        write_record(s, &TlsRecord::new(ContentType::Handshake, chunk.to_vec()))?;
    }
    Ok(())
}

/** @brief 암호화되지 않은 핸드셰이크 메시지를 읽는다. 핸드셰이크 초반에 쓴다. */
fn read_plaintext_handshake<S: Read>(s: &mut S) -> Result<HandshakeMsg, TlsError> {
    let mut reader = HandshakeReader::new();
    loop {
        if let Some(msg) = reader.next_message()? {
            return Ok(msg);
        }
        let rec = read_record(s)?;
        match rec.content_type {
            ContentType::ChangeCipherSpec if valid_ccs_record(&rec) => continue,
            ContentType::ChangeCipherSpec => return Err(TlsError::Protocol),
            ContentType::Handshake => reader.feed(&rec.fragment),
            ContentType::Alert => return Err(alert_error(&rec.fragment)),
            _ => return Err(TlsError::Protocol),
        }
    }
}

/** @brief 암호화된 핸드셰이크 메시지를 읽는 것. */
struct EncReader {
    /** @brief 암호를 푼 핸드셰이크 바이트를 모으는 곳. */
    hr: HandshakeReader,
}

impl EncReader {
    /** @brief 빈 상태. */
    fn new() -> Self {
        Self {
            hr: HandshakeReader::new(),
        }
    }

    /** @brief 다음 핸드셰이크 메시지를 읽는다. */
    fn next<S: Read>(&mut self, s: &mut S, c: &mut RecordCrypto) -> Result<HandshakeMsg, TlsError> {
        loop {
            if let Some(m) = self.hr.next_message()? {
                return Ok(m);
            }
            let rec = read_record(s)?;
            if rec.content_type == ContentType::ChangeCipherSpec {
                if valid_ccs_record(&rec) {
                    continue;
                }
                return Err(TlsError::Protocol);
            }
            let (ct, pt) = c.decrypt(&rec)?;
            match ct {
                ContentType::Handshake if pt.is_empty() => return Err(TlsError::Protocol),
                ContentType::Handshake => self.hr.feed(&pt),
                ContentType::Alert if pt.len() == 2 => return Err(alert_error(&pt)),
                _ => return Err(TlsError::Protocol),
            }
        }
    }
}

/** @brief 핸드셰이크 메시지를 암호화해 보낸다. */
fn send_hs_enc<S: Write>(
    s: &mut S,
    c: &mut RecordCrypto,
    msg: &HandshakeMsg,
) -> Result<(), TlsError> {
    let encoded = msg.encode();
    for chunk in encoded.chunks(MAX_FRAGMENT) {
        let rec = c.encrypt(ContentType::Handshake, chunk)?;
        write_record(s, &rec)?;
    }
    Ok(())
}

/** @brief 논스 기준값을 고정 길이 배열로. */
fn iv12(v: Vec<u8>) -> [u8; 12] {
    let mut a = [0u8; 12];
    a.copy_from_slice(&v[..12]);
    a
}

/** @brief 상대가 제안한 것 중 쓸 스위트를 고른다. */
fn choose_suite(offered: &[u16]) -> Option<u16> {
    [
        TLS_AES_128_GCM_SHA256,
        TLS_CHACHA20_POLY1305_SHA256,
        TLS_AES_256_GCM_SHA384,
    ]
    .into_iter()
    .find(|&s| offered.contains(&s))
}

/** @brief 지금 blocking TLS 재접속에 제안할 수 있는 세션. */
fn fresh_client_session(cfg: &ClientConfig) -> Option<&crate::session::TlsSession> {
    cfg.session.as_ref().filter(|session| {
        session.server_name == cfg.server_name
            && session.is_fresh(crate::session::now_ms())
            && suite_params(session.suite).is_some()
            && session
                .alpn
                .as_ref()
                .is_none_or(|alpn| cfg.alpn.contains(alpn))
    })
}

/** @brief placeholder가 든 ClientHello의 PSK binder를 실제 값으로 바꾼다. */
fn encode_client_hello(
    hello: &ClientHello,
    session: Option<&crate::session::TlsSession>,
    binder_prefix: &[u8],
) -> Result<Vec<u8>, TlsError> {
    let mut wire = hello.to_handshake().encode();
    let Some(session) = session else {
        return Ok(wire);
    };
    let (hash, _) = suite_params(session.suite).ok_or(TlsError::Protocol)?;
    let binders_len = 2 + 1 + hash.len();
    if wire.len() <= binders_len {
        return Err(TlsError::Protocol);
    }
    let mut binder_transcript = Transcript::new(hash);
    binder_transcript.update(binder_prefix);
    binder_transcript.update(&wire[..wire.len() - binders_len]);
    let truncated_hash = binder_transcript.hash();
    let schedule = KeySchedule::new_with_psk(hash, &session.psk);
    let binder = schedule.psk_binder(&truncated_hash);
    let offset = wire.len() - binder.len();
    wire[offset..].copy_from_slice(&binder);
    Ok(wire)
}

/** @brief 서버가 blocking TLS ClientHello의 첫 PSK 제안을 검증한다. */
fn accept_client_psk(
    cfg: &ServerConfig,
    hello: &ClientHello,
    message: &HandshakeMsg,
    negotiated_alpn: &Option<Vec<u8>>,
    binder_prefix: &[u8],
) -> Result<Option<crate::session::ResumptionState>, TlsError> {
    let Some(resumption) = &cfg.resumption else {
        return Ok(None);
    };
    if cfg.client_ca.is_some()
        || !hello
            .ext(EXT_PSK_KEY_EXCHANGE_MODES)
            .and_then(Extension::as_psk_modes)
            .is_some_and(|modes| modes.contains(&PSK_DHE_KE))
    {
        return Ok(None);
    }
    let Some((identities, binders)) = hello
        .ext(EXT_PRE_SHARED_KEY)
        .and_then(Extension::as_pre_shared_key_client)
    else {
        return Ok(None);
    };
    let (Some((identity, obfuscated_age)), Some(binder)) = (identities.first(), binders.first())
    else {
        return Ok(None);
    };
    let Some(state) = resumption.ticketer.open(identity) else {
        return Ok(None);
    };
    let offered_server_name = hello
        .ext(EXT_SERVER_NAME)
        .and_then(Extension::as_server_name);
    if state.server_name != offered_server_name
        || state.alpn != *negotiated_alpn
        || !hello.cipher_suites.contains(&state.suite)
    {
        return Ok(None);
    }
    let Some((hash, _)) = suite_params(state.suite) else {
        return Ok(None);
    };

    let wire = message.encode();
    let binders_len = 2 + binders.iter().map(|value| 1 + value.len()).sum::<usize>();
    if wire.len() <= binders_len {
        return Ok(None);
    }
    let mut binder_transcript = Transcript::new(hash);
    binder_transcript.update(binder_prefix);
    binder_transcript.update(&wire[..wire.len() - binders_len]);
    let truncated_hash = binder_transcript.hash();
    let schedule = KeySchedule::new_with_psk(hash, &state.psk);
    let expected = schedule.psk_binder(&truncated_hash);
    if !crate::keyschedule::ct_eq(&expected, binder) {
        return Err(TlsError::BadSignature);
    }

    let now = crate::session::now_ms();
    let server_age = now.saturating_sub(state.issued_ms);
    let client_age = obfuscated_age.wrapping_sub(state.age_add) as u64;
    if server_age > state.lifetime_secs as u64 * 1000 || client_age.abs_diff(server_age) > 10_000 {
        return Ok(None);
    }
    Ok(Some(state))
}

/** @brief 서버 인사말에서 X25519 공개값을 꺼낸다. */
fn x25519_server_share(sh: &ServerHello) -> Option<Vec<u8>> {
    let (g, key) = sh.ext(EXT_KEY_SHARE)?.as_key_share_server()?;
    (g == X25519).then_some(key)
}

/** @brief 클라이언트 인사말에서 X25519 공개값을 꺼낸다. */
fn x25519_client_share(ch: &ClientHello) -> Option<Vec<u8>> {
    let entries = ch.ext(EXT_KEY_SHARE)?.as_key_share_client()?;
    entries
        .into_iter()
        .find(|(g, _)| *g == X25519)
        .map(|(_, k)| k)
}

/** @brief 암호화되지 않은 핸드셰이크 메시지를 읽는 것. */
struct PlainHsReader {
    /** @brief 평문 핸드셰이크 바이트를 모으는 곳. */
    hr: HandshakeReader,
}

impl PlainHsReader {
    /** @brief 빈 상태. */
    fn new() -> Self {
        Self {
            hr: HandshakeReader::new(),
        }
    }

    /** @brief 핸드셰이크 메시지 하나를 읽는다. 나뉘어 와도 이어 붙인다. */
    fn next<S: Read>(&mut self, s: &mut S) -> Result<HandshakeMsg, TlsError> {
        loop {
            if let Some(m) = self.hr.next_message()? {
                return Ok(m);
            }
            let rec = read_record(s)?;
            match rec.content_type {
                ContentType::Handshake => self.hr.feed(&rec.fragment),
                ContentType::ChangeCipherSpec if valid_ccs_record(&rec) => {}
                ContentType::ChangeCipherSpec => return Err(TlsError::Protocol),
                ContentType::Alert => return Err(alert_error(&rec.fragment)),
                _ => return Err(TlsError::Protocol),
            }
        }
    }
}

/** @brief 호환용 더미 레코드를 받는다. 1.3에서는 뜻이 없지만 오기는 한다. */
fn expect_ccs<S: Read>(s: &mut S) -> Result<(), TlsError> {
    let rec = read_record(s)?;
    if !valid_ccs_record(&rec) {
        return Err(TlsError::Protocol);
    }
    Ok(())
}

/** @brief 더미 레코드가 규격 형태인지. 아무 바이트나 받으면 그것이 경로가 된다. */
fn valid_ccs_record(record: &TlsRecord) -> bool {
    record.content_type == ContentType::ChangeCipherSpec
        && record.version == crate::record::LEGACY_VERSION
        && record.fragment == [1]
}

/** @brief 바이트열이 정확히 핸드셰이크 메시지 하나인지. 뒤에 바이트가 남으면 거부한다. */
fn parse_exact_handshake(bytes: &[u8]) -> Result<HandshakeMsg, TlsError> {
    let (message, used) = HandshakeMsg::parse(bytes)?.ok_or(TlsError::Protocol)?;
    if used != bytes.len() {
        return Err(TlsError::Protocol);
    }
    Ok(message)
}

/** @brief 호환용 더미 레코드를 만든다. */
fn ccs_record() -> TlsRecord {
    TlsRecord::new(ContentType::ChangeCipherSpec, vec![1])
}

/** @brief 이 서명 방식이 ECDSA인지. */
fn scheme_is_ecdsa(scheme: u16) -> bool {
    scheme == ECDSA_SECP256R1_SHA256 || scheme == ECDSA_SECP384R1_SHA384
}

/**
 * @brief 1.2 클라이언트 인사말이 이쪽이 답할 수 있는 형태인지.
 * @warning 이쪽 인증서로 쓸 수 있는 서명 방식을 제안했는지 확인한다.
 */
fn validate_tls12_client_hello(ch: &ClientHello, sign_scheme: u16) -> Result<(), TlsError> {
    if ch.legacy_version != TLS12
        || ch.compression_methods != [0]
        || !ch
            .ext(tls12::EXT_EXTENDED_MASTER_SECRET)
            .is_some_and(|extension| extension.data.is_empty())
        || ch
            .ext(tls12::EXT_RENEGOTIATION_INFO)
            .is_none_or(|extension| extension.data != [0])
        || !ch
            .ext(EXT_SIGNATURE_ALGORITHMS)
            .and_then(Extension::as_signature_algorithms)
            .is_some_and(|algorithms| algorithms.contains(&sign_scheme))
    {
        return Err(TlsError::Protocol);
    }
    Ok(())
}

/**
 * @brief 1.2 서버 인사말이 이쪽 제안 안에 있는지.
 * @details 서버 이름을 보냈으면 서버는 빈 server_name 확장으로 그 이름을 썼다고 알릴 수 있다.
 *          RFC 6066 이 허용하는 응답이고, 많은 부하 분산기가 이렇게 답한다.
 * @warning 이쪽이 제안하지 않은 스위트나 확장을 받아들이면 다운그레이드이 성립한다.
 */
fn validate_tls12_server_hello(
    cfg: &ClientConfig,
    ch: &ClientHello,
    sh: &ServerHello,
) -> Result<Option<Vec<u8>>, TlsError> {
    if sh.legacy_version != TLS12
        || sh.ext(EXT_SUPPORTED_VERSIONS).is_some()
        || !ch.cipher_suites.contains(&sh.cipher_suite)
        || !tls12::client_suites().contains(&sh.cipher_suite)
        || !sh
            .ext(tls12::EXT_EXTENDED_MASTER_SECRET)
            .is_some_and(|extension| extension.data.is_empty())
        || sh
            .ext(tls12::EXT_RENEGOTIATION_INFO)
            .is_none_or(|extension| extension.data != [0])
        || !sh
            .extensions
            .iter()
            .all(|extension| match extension.ext_type {
                tls12::EXT_EXTENDED_MASTER_SECRET
                | tls12::EXT_RENEGOTIATION_INFO
                | tls12::EXT_EC_POINT_FORMATS
                | EXT_ALPN => true,
                EXT_SERVER_NAME => extension.data.is_empty() && ch.ext(EXT_SERVER_NAME).is_some(),
                _ => false,
            })
        || sh
            .ext(tls12::EXT_EC_POINT_FORMATS)
            .is_some_and(|extension| extension.data != [1, 0])
    {
        return Err(TlsError::Protocol);
    }
    match sh.ext(EXT_ALPN) {
        Some(extension) => {
            let protocols = extension.as_alpn().ok_or(TlsError::Protocol)?;
            if protocols.len() != 1 || !cfg.alpn.contains(&protocols[0]) {
                return Err(TlsError::Protocol);
            }
            Ok(Some(protocols[0].clone()))
        }
        None => Ok(None),
    }
}

/** @brief 서버로서 핸드셰이크를 마친다. 버전에 따라 갈린다. */
pub fn server_handshake<S: Read + Write>(
    s: &mut S,
    cfg: &ServerConfig,
) -> Result<TlsConnection, TlsError> {
    if !server_config_wire_is_valid(cfg) {
        return Err(TlsError::RecordOverflow);
    }
    let mut ch_msg = read_plaintext_handshake(s)?;
    let mut ch = ClientHello::from_handshake(&ch_msg)?;

    let offers_13 = ch
        .ext(EXT_SUPPORTED_VERSIONS)
        .and_then(|e| e.as_supported_versions_client())
        .map(|vs| vs.contains(&TLS13))
        .unwrap_or(false);
    if offers_13 && !ch.is_valid_tls13() {
        return Err(TlsError::Protocol);
    }
    if offers_13 && ch.ext(EXT_COOKIE).is_some() {
        return Err(TlsError::Protocol);
    }
    if !(offers_13 && choose_suite(&ch.cipher_suites).is_some()) {
        if cfg.client_ca.is_some() {
            return Err(TlsError::Protocol);
        }
        return server_handshake_tls12(s, cfg, ch_msg, ch);
    }

    let suite = choose_suite(&ch.cipher_suites).ok_or(TlsError::Protocol)?;
    let (hash, key_len) = suite_params(suite).ok_or(TlsError::Protocol)?;
    let aead = aead_for_suite(suite).ok_or(TlsError::Protocol)?;

    let mut transcript = Transcript::new(hash);
    let mut psk_binder_prefix = Vec::new();
    let hrr_used = x25519_client_share(&ch).is_none();
    if hrr_used {
        let first_ch = ch.clone();
        let supports_x25519 = ch
            .ext(EXT_SUPPORTED_GROUPS)
            .and_then(|e| e.as_supported_groups())
            .map(|gs| gs.contains(&X25519))
            .unwrap_or(false);
        if !supports_x25519 {
            return Err(TlsError::Protocol);
        }

        transcript.update(&ch_msg.encode());
        transcript.replace_with_message_hash();
        let cookie: Vec<u8> = random_32().to_vec();
        let hrr = ServerHello {
            legacy_version: TLS12,
            random: crate::msg::HRR_RANDOM,
            session_id_echo: ch.session_id.clone(),
            cipher_suite: suite,
            extensions: vec![
                Extension::supported_versions_server(TLS13),
                Extension::key_share_hrr(X25519),
                Extension::cookie(&cookie),
            ],
        };
        let hrr_msg = hrr.to_handshake();
        write_plain_handshake(s, &hrr_msg.encode())?;
        transcript.update(&hrr_msg.encode());

        ch_msg = read_plaintext_handshake(s)?;
        ch = ClientHello::from_handshake(&ch_msg)?;
        if !ch.is_valid_tls13() || !ch.is_valid_retry_of(&first_ch) {
            return Err(TlsError::Protocol);
        }
        let echoed = ch
            .ext(crate::msg::consts::EXT_COOKIE)
            .and_then(|e| e.as_cookie());
        if echoed.as_deref() != Some(cookie.as_slice()) {
            return Err(TlsError::Protocol);
        }
        let retry_shares = ch
            .ext(EXT_KEY_SHARE)
            .and_then(Extension::as_key_share_client)
            .ok_or(TlsError::Protocol)?;
        if retry_shares.len() != 1 || retry_shares[0].0 != X25519 || retry_shares[0].1.len() != 32 {
            return Err(TlsError::Protocol);
        }
        psk_binder_prefix.extend_from_slice(transcript.as_bytes());
        transcript.update(&ch_msg.encode());
    } else {
        transcript.update(&ch_msg.encode());
    }
    let client_pub = x25519_client_share(&ch).ok_or(TlsError::Protocol)?;

    let client_alpn = ch
        .ext(EXT_ALPN)
        .and_then(|e| e.as_alpn())
        .unwrap_or_default();
    let negotiated_alpn: Option<Vec<u8>> = cfg
        .alpn
        .iter()
        .find(|sp| client_alpn.iter().any(|cp| cp == *sp))
        .cloned();
    let psk = accept_client_psk(cfg, &ch, &ch_msg, &negotiated_alpn, &psk_binder_prefix)?
        .filter(|state| state.suite == suite);
    let resumed = psk.is_some();
    let client_allows_resumption = ch
        .ext(EXT_PSK_KEY_EXCHANGE_MODES)
        .and_then(Extension::as_psk_modes)
        .is_some_and(|modes| modes.contains(&PSK_DHE_KE));

    let mut seed = Zeroizing::new([0u8; 32]);
    fill_random(&mut *seed);
    let kx = KeyExchange::from_seed(X25519, &*seed).ok_or(TlsError::Protocol)?;
    let shared = Zeroizing::new(kx.shared_secret(&client_pub).ok_or(TlsError::Protocol)?);

    let mut sh_extensions = vec![
        Extension::supported_versions_server(TLS13),
        Extension::key_share_server(X25519, &kx.public_bytes()),
    ];
    if resumed {
        sh_extensions.push(Extension::pre_shared_key_server(0));
    }
    let sh = ServerHello {
        legacy_version: TLS12,
        random: random_32(),
        session_id_echo: ch.session_id.clone(),
        cipher_suite: suite,
        extensions: sh_extensions,
    };
    let sh_msg = sh.to_handshake();
    write_plain_handshake(s, &sh_msg.encode())?;
    transcript.update(&sh_msg.encode());

    let mut ks = match &psk {
        Some(state) => KeySchedule::new_with_psk(hash, &state.psk),
        None => KeySchedule::new(hash),
    };
    ks.enter_handshake(&shared);
    let th = transcript.hash();
    let chs = Zeroizing::new(ks.client_handshake_traffic_secret(&th));
    let shs = Zeroizing::new(ks.server_handshake_traffic_secret(&th));
    let (ck, civ) = traffic_keys(hash, &chs, key_len);
    let (sk, siv) = traffic_keys(hash, &shs, key_len);
    let mut write_c = RecordCrypto::new(aead, sk, iv12(siv));
    let mut read_c = RecordCrypto::new(aead, ck, iv12(civ));

    let ee = HandshakeMsg::new(
        HandshakeType::EncryptedExtensions,
        encrypted_extensions(negotiated_alpn.as_deref()),
    );
    send_hs_enc(s, &mut write_c, &ee)?;
    transcript.update(&ee.encode());

    let want_client_cert = cfg.client_ca.is_some() && !resumed;
    if want_client_cert {
        let cr = HandshakeMsg::new(
            HandshakeType::CertificateRequest,
            crate::cert::CertificateRequestMsg::standard().encode(),
        );
        send_hs_enc(s, &mut write_c, &cr)?;
        transcript.update(&cr.encode());
    }

    if !resumed {
        let cert = CertificateMsg {
            request_context: vec![],
            entries: cfg
                .cert_chain
                .iter()
                .map(|der| CertEntry {
                    cert_data: der.clone(),
                    extensions: vec![],
                })
                .collect(),
        };
        let cert_msg = HandshakeMsg::new(HandshakeType::Certificate, cert.encode());
        send_hs_enc(s, &mut write_c, &cert_msg)?;
        transcript.update(&cert_msg.encode());

        let cv_content = certificate_verify_content(&transcript.hash(), true);
        let cv = CertificateVerify {
            algorithm: cfg.sign_scheme,
            signature: (cfg.sign)(&cv_content),
        };
        let cv_msg = HandshakeMsg::new(HandshakeType::CertificateVerify, cv.encode());
        send_hs_enc(s, &mut write_c, &cv_msg)?;
        transcript.update(&cv_msg.encode());
    }

    let sfk = Zeroizing::new(finished_key(hash, &shs));
    let sfin = finished_verify_data(hash, &sfk, &transcript.hash());
    let fin_msg = HandshakeMsg::new(HandshakeType::Finished, sfin);
    send_hs_enc(s, &mut write_c, &fin_msg)?;
    transcript.update(&fin_msg.encode());

    ks.enter_master();
    let th_after = transcript.hash();
    let cap = ks.client_application_traffic_secret(&th_after);
    let sap = ks.server_application_traffic_secret(&th_after);

    let mut er = EncReader::new();
    let mut th_for_client_fin = th_after.clone();
    let mut client_auth_identity: Option<String> = None;
    if want_client_cert {
        let cert_m = er.next(s, &mut read_c)?;
        if cert_m.msg_type != HandshakeType::Certificate {
            return Err(TlsError::Protocol);
        }
        let ccert = CertificateMsg::parse(&cert_m.body)?;

        if ccert.entries.is_empty() {
            return Err(TlsError::BadCert);
        }
        let chain: Vec<X509> = ccert
            .entries
            .iter()
            .map(|e| X509::parse(&e.cert_data))
            .collect::<Result<_, _>>()?;
        let store = cfg.client_ca.as_ref().ok_or(TlsError::Protocol)?;
        crate::trust::verify_client_chain(&chain, store, now_epoch())?;
        let client_certificate = chain.first().ok_or(TlsError::BadCert)?;
        client_auth_identity = Some(format!(
            "mtls:{}",
            short_hex(&client_certificate.public_key)
        ));
        transcript.update(&cert_m.encode());

        let th_before_cv = transcript.hash();
        let cv_m = er.next(s, &mut read_c)?;
        if cv_m.msg_type != HandshakeType::CertificateVerify {
            return Err(TlsError::Protocol);
        }
        let cv = CertificateVerify::parse(&cv_m.body)?;
        let cv_content = certificate_verify_content(&th_before_cv, false);
        client_certificate.verify_tls_signature(cv.algorithm, &cv_content, &cv.signature)?;
        transcript.update(&cv_m.encode());
        th_for_client_fin = transcript.hash();
    }
    let cfin = er.next(s, &mut read_c)?;
    let cfk = Zeroizing::new(finished_key(hash, &chs));
    let expected = finished_verify_data(hash, &cfk, &th_for_client_fin);
    if cfin.msg_type != HandshakeType::Finished || !crate::keyschedule::ct_eq(&cfin.body, &expected)
    {
        return Err(TlsError::BadSignature);
    }
    transcript.update(&cfin.encode());

    let (cak, caiv) = traffic_keys(hash, &cap, key_len);
    let (sak, saiv) = traffic_keys(hash, &sap, key_len);
    let mut application_write = RecordCrypto::new(aead, sak, iv12(saiv));
    if let Some(resumption) = &cfg.resumption {
        if cfg.client_ca.is_none() && client_allows_resumption && resumption.lifetime_secs > 0 {
            let master = Zeroizing::new(ks.resumption_master_secret(&transcript.hash()));
            let mut nonce = [0u8; 8];
            fill_random(&mut nonce);
            let session_psk = crate::keyschedule::resumption_psk(hash, &master, &nonce);
            let mut age = [0u8; 4];
            fill_random(&mut age);
            let age_add = u32::from_be_bytes(age);
            let state = crate::session::ResumptionState {
                server_name: ch.ext(EXT_SERVER_NAME).and_then(Extension::as_server_name),
                suite,
                psk: session_psk,
                alpn: negotiated_alpn.clone(),
                issued_ms: crate::session::now_ms(),
                age_add,
                lifetime_secs: resumption.lifetime_secs,
                max_early_data: 0,
            };
            let ticket = resumption
                .ticketer
                .seal(&state)
                .ok_or(TlsError::RecordOverflow)?;
            let message = HandshakeMsg::new(
                HandshakeType::NewSessionTicket,
                crate::msg::NewSessionTicket {
                    lifetime_secs: resumption.lifetime_secs,
                    age_add,
                    nonce: nonce.to_vec(),
                    ticket,
                    extensions: Vec::new(),
                }
                .encode(),
            );
            send_hs_enc(s, &mut application_write, &message)?;
        }
    }
    Ok(TlsConnection {
        read: RecordLayer::Tls13(RecordCrypto::new(aead, cak, iv12(caiv))),
        write: RecordLayer::Tls13(application_write),
        version: TLS13,
        alpn: negotiated_alpn,
        client_authenticated: client_auth_identity.is_some(),
        client_auth_identity,
        peer_chain: Vec::new(),
        is_client: false,
        post_handshake: HandshakeReader::new(),
        traffic: Some(Tls13Traffic {
            aead,
            hash,
            key_len,
            read_secret: cap,
            write_secret: sap,
            write_updates: 0,
        }),
        resumed,
        resumption: None,
        new_sessions: Vec::new(),
    })
}

/** @brief 클라이언트 인사말을 만든다. */
fn build_client_hello(
    cfg: &ClientConfig,
    kx: &KeyExchange,
    send_key_share: bool,
    cookie: Option<&[u8]>,
    session: Option<&crate::session::TlsSession>,
) -> ClientHello {
    let key_shares: Vec<(u16, Vec<u8>)> = if send_key_share {
        vec![(X25519, kx.public_bytes())]
    } else {
        vec![]
    };
    let mut extensions = vec![
        Extension::supported_versions_client(&[TLS13, TLS12]),
        Extension::supported_groups(&[X25519, SECP256R1]),
        Extension::signature_algorithms(&[
            ED25519,
            ECDSA_SECP256R1_SHA256,
            ECDSA_SECP384R1_SHA384,
            RSA_PSS_RSAE_SHA256,
            RSA_PSS_RSAE_SHA384,
            RSA_PKCS1_SHA256,
        ]),
        Extension::key_share_client(&key_shares),
        Extension::server_name(&cfg.server_name),
    ];
    if let Some(c) = cookie {
        extensions.push(Extension::cookie(c));
    }
    if !cfg.alpn.is_empty() {
        let protos: Vec<&[u8]> = cfg.alpn.iter().map(|v| v.as_slice()).collect();
        extensions.push(Extension::alpn(&protos));
    }

    extensions.push(tls12::ext_extended_master_secret());
    extensions.push(tls12::ext_ec_point_formats());
    extensions.push(tls12::ext_renegotiation_info());
    extensions.push(Extension::psk_key_exchange_modes(&[PSK_DHE_KE]));

    if let Some(session) = session {
        let (hash, _) = suite_params(session.suite).expect("Validated TLS 1.3 session suite");
        extensions.push(Extension::pre_shared_key_client(
            &session.ticket,
            session.obfuscated_age(crate::session::now_ms()),
            hash.len(),
        ));
    }

    let mut cipher_suites = vec![
        TLS_AES_128_GCM_SHA256,
        TLS_CHACHA20_POLY1305_SHA256,
        TLS_AES_256_GCM_SHA384,
    ];
    if let Some(session) = session {
        cipher_suites.retain(|suite| *suite != session.suite);
        cipher_suites.insert(0, session.suite);
    }
    cipher_suites.extend_from_slice(&tls12::client_suites());

    ClientHello {
        legacy_version: TLS12,
        random: random_32(),
        session_id: random_32().to_vec(),
        cipher_suites,
        compression_methods: vec![0],
        extensions,
    }
}

/** @brief 클라이언트로서 핸드셰이크를 마친다. */
pub fn client_handshake<S: Read + Write>(
    s: &mut S,
    cfg: &ClientConfig,
) -> Result<TlsConnection, TlsError> {
    if !client_config_wire_is_valid(cfg) {
        return Err(TlsError::RecordOverflow);
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    fill_random(&mut *seed);
    let kx = KeyExchange::from_seed(X25519, &*seed).ok_or(TlsError::Protocol)?;

    let mut offered_session = fresh_client_session(cfg);
    let ch = build_client_hello(cfg, &kx, cfg.send_key_share, None, offered_session);
    let mut ch_bytes = encode_client_hello(&ch, offered_session, &[])?;
    write_plain_handshake(s, &ch_bytes)?;

    let mut server_hs = PlainHsReader::new();
    let mut sh_msg = server_hs.next(s)?;
    let mut sh = ServerHello::from_handshake(&sh_msg)?;

    let server_chose_13 = sh
        .ext(EXT_SUPPORTED_VERSIONS)
        .and_then(|e| e.as_supported_versions_server())
        == Some(TLS13);
    if sh.random != crate::msg::HRR_RANDOM && !server_chose_13 {
        /** @brief 규격이 정한 표시. 상대가 이것을 실었는데 이쪽이 더 높은 버전을 지원하면 중간에서 끌어내린 것이다. */
        const DOWNGRADE_12: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01];
        /** @brief 더 낮은 판으로 끌어내렸음을 나타내는 표시. */
        const DOWNGRADE_11: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00];
        if sh.random[24..32] == DOWNGRADE_12 || sh.random[24..32] == DOWNGRADE_11 {
            return Err(TlsError::Protocol);
        }
        return client_handshake_tls12(s, cfg, ch, ch_bytes, sh, sh_msg, server_hs);
    }

    let mut hrr_transcript: Option<Transcript> = None;
    let mut hrr_suite = None;
    if sh.random == crate::msg::HRR_RANDOM {
        if !sh.is_valid_tls13(&ch.session_id, true) || x25519_client_share(&ch).is_some() {
            return Err(TlsError::Protocol);
        }
        let selected = sh.ext(EXT_KEY_SHARE).and_then(|e| e.as_key_share_hrr());
        if selected != Some(X25519) {
            return Err(TlsError::Protocol);
        }
        let cookie = match sh.ext(EXT_COOKIE) {
            Some(extension) => Some(extension.as_cookie().ok_or(TlsError::Protocol)?),
            None => None,
        };
        let (hash, _) = suite_params(sh.cipher_suite).ok_or(TlsError::Protocol)?;
        if !ch.cipher_suites.contains(&sh.cipher_suite) {
            return Err(TlsError::Protocol);
        }
        hrr_suite = Some(sh.cipher_suite);

        let mut t = Transcript::new(hash);
        t.update(&ch_bytes);
        t.replace_with_message_hash();
        t.update(&sh_msg.encode());

        if offered_session.is_some_and(|session| session.suite != sh.cipher_suite) {
            offered_session = None;
        }
        let mut ch2 = build_client_hello(cfg, &kx, true, cookie.as_deref(), offered_session);
        ch2.random = ch.random;
        ch2.session_id.clone_from(&ch.session_id);
        ch2.cipher_suites.clone_from(&ch.cipher_suites);
        ch_bytes = encode_client_hello(&ch2, offered_session, t.as_bytes())?;
        write_plain_handshake(s, &ch_bytes)?;
        t.update(&ch_bytes);
        hrr_transcript = Some(t);

        sh_msg = read_plaintext_handshake(s)?;
        sh = ServerHello::from_handshake(&sh_msg)?;
        if sh.random == crate::msg::HRR_RANDOM {
            return Err(TlsError::Protocol);
        }
    }
    if !sh.is_valid_tls13(&ch.session_id, false) {
        return Err(TlsError::Protocol);
    }
    let suite = sh.cipher_suite;
    if hrr_suite.is_some_and(|selected| selected != suite) {
        return Err(TlsError::Protocol);
    }
    let (hash, key_len) = suite_params(suite).ok_or(TlsError::Protocol)?;
    let aead = aead_for_suite(suite).ok_or(TlsError::Protocol)?;
    let server_pub = x25519_server_share(&sh).ok_or(TlsError::Protocol)?;
    let shared = Zeroizing::new(kx.shared_secret(&server_pub).ok_or(TlsError::Protocol)?);
    let psk_accepted = match sh
        .ext(EXT_PRE_SHARED_KEY)
        .and_then(Extension::as_pre_shared_key_server)
    {
        Some(0) if offered_session.is_some_and(|session| session.suite == suite) => true,
        Some(_) => return Err(TlsError::Protocol),
        None => false,
    };

    let mut transcript = match hrr_transcript {
        Some(t) => t,
        None => {
            let mut t = Transcript::new(hash);
            t.update(&ch_bytes);
            t
        }
    };
    transcript.update(&sh_msg.encode());

    let mut ks = match offered_session.filter(|_| psk_accepted) {
        Some(session) => KeySchedule::new_with_psk(hash, &session.psk),
        None => KeySchedule::new(hash),
    };
    ks.enter_handshake(&shared);
    let th = transcript.hash();
    let chs = Zeroizing::new(ks.client_handshake_traffic_secret(&th));
    let shs = Zeroizing::new(ks.server_handshake_traffic_secret(&th));
    let (ck, civ) = traffic_keys(hash, &chs, key_len);
    let (sk, siv) = traffic_keys(hash, &shs, key_len);
    let mut read_c = RecordCrypto::new(aead, sk, iv12(siv));
    let mut write_c = RecordCrypto::new(aead, ck, iv12(civ));

    let mut er = EncReader::new();
    let ee = er.next(s, &mut read_c)?;
    if ee.msg_type != HandshakeType::EncryptedExtensions {
        return Err(TlsError::Protocol);
    }

    let ee_extensions = Extension::parse_vector(&ee.body)?;
    if !ee_extensions
        .iter()
        .all(|extension| match extension.ext_type {
            EXT_ALPN => true,
            EXT_SERVER_NAME => extension.data.is_empty(),
            EXT_SUPPORTED_GROUPS => extension.as_supported_groups().is_some(),
            _ => false,
        })
    {
        return Err(TlsError::Protocol);
    }
    let negotiated_alpn = match Extension::find(&ee_extensions, EXT_ALPN) {
        Some(extension) => {
            let protocols = extension.as_alpn().ok_or(TlsError::Protocol)?;
            if protocols.len() != 1 || !cfg.alpn.contains(&protocols[0]) {
                return Err(TlsError::Protocol);
            }
            Some(protocols[0].clone())
        }
        None => None,
    };
    if psk_accepted && offered_session.is_none_or(|session| session.alpn != negotiated_alpn) {
        return Err(TlsError::Protocol);
    }
    transcript.update(&ee.encode());

    if psk_accepted {
        let fin_m = er.next(s, &mut read_c)?;
        if fin_m.msg_type != HandshakeType::Finished {
            return Err(TlsError::Protocol);
        }
        let sfk = Zeroizing::new(finished_key(hash, &shs));
        let expected = finished_verify_data(hash, &sfk, &transcript.hash());
        if !crate::keyschedule::ct_eq(&fin_m.body, &expected) {
            return Err(TlsError::BadSignature);
        }
        transcript.update(&fin_m.encode());
        let application_transcript = transcript.hash();

        let cfk = Zeroizing::new(finished_key(hash, &chs));
        let cfin_msg = HandshakeMsg::new(
            HandshakeType::Finished,
            finished_verify_data(hash, &cfk, &application_transcript),
        );
        send_hs_enc(s, &mut write_c, &cfin_msg)?;
        transcript.update(&cfin_msg.encode());

        ks.enter_master();
        let cap = ks.client_application_traffic_secret(&application_transcript);
        let sap = ks.server_application_traffic_secret(&application_transcript);
        let master = ks.resumption_master_secret(&transcript.hash());
        let (cak, caiv) = traffic_keys(hash, &cap, key_len);
        let (sak, saiv) = traffic_keys(hash, &sap, key_len);
        return Ok(TlsConnection {
            read: RecordLayer::Tls13(RecordCrypto::new(aead, sak, iv12(saiv))),
            write: RecordLayer::Tls13(RecordCrypto::new(aead, cak, iv12(caiv))),
            version: TLS13,
            alpn: negotiated_alpn,
            client_authenticated: false,
            client_auth_identity: None,
            peer_chain: Vec::new(),
            is_client: true,
            post_handshake: HandshakeReader::new(),
            traffic: Some(Tls13Traffic {
                aead,
                hash,
                key_len,
                read_secret: sap,
                write_secret: cap,
                write_updates: 0,
            }),
            resumed: true,
            resumption: Some(ClientResumption {
                server_name: cfg.server_name.clone(),
                hash,
                suite,
                master,
            }),
            new_sessions: Vec::new(),
        });
    }

    let mut next_m = er.next(s, &mut read_c)?;
    let mut cert_requested = false;
    if next_m.msg_type == HandshakeType::CertificateRequest {
        crate::cert::CertificateRequestMsg::parse(&next_m.body)?;
        cert_requested = true;
        transcript.update(&next_m.encode());
        next_m = er.next(s, &mut read_c)?;
    }
    let cert_m = next_m;
    if cert_m.msg_type != HandshakeType::Certificate {
        return Err(TlsError::Protocol);
    }
    let cert = CertificateMsg::parse(&cert_m.body)?;
    let leaf = cert.leaf().ok_or(TlsError::BadCert)?;
    let x = X509::parse(leaf)?;
    let peer_chain: Vec<Vec<u8>> = cert.entries.iter().map(|e| e.cert_data.clone()).collect();
    match &cfg.roots {
        Some(store) => {
            let chain: Vec<X509> = cert
                .entries
                .iter()
                .map(|e| X509::parse(&e.cert_data))
                .collect::<Result<_, _>>()?;
            crate::trust::verify_chain(&chain, store, &cfg.server_name, now_epoch())?;
        }

        None => {
            if cfg.insecure_verifier.is_none() {
                return Err(TlsError::BadCert);
            }
            if cfg.verify_name && !x.matches_hostname(&cfg.server_name) {
                return Err(TlsError::BadCert);
            }
        }
    }
    transcript.update(&cert_m.encode());

    let th_before_cv = transcript.hash();
    let cv_m = er.next(s, &mut read_c)?;
    if cv_m.msg_type != HandshakeType::CertificateVerify {
        return Err(TlsError::Protocol);
    }
    let cv = CertificateVerify::parse(&cv_m.body)?;
    let cv_content = certificate_verify_content(&th_before_cv, true);
    x.verify_tls_signature(cv.algorithm, &cv_content, &cv.signature)?;
    transcript.update(&cv_m.encode());

    let th_before_fin = transcript.hash();
    let fin_m = er.next(s, &mut read_c)?;
    if fin_m.msg_type != HandshakeType::Finished {
        return Err(TlsError::Protocol);
    }
    let sfk = Zeroizing::new(finished_key(hash, &shs));
    let expected_sfin = finished_verify_data(hash, &sfk, &th_before_fin);
    if !crate::keyschedule::ct_eq(&fin_m.body, &expected_sfin) {
        return Err(TlsError::BadSignature);
    }
    transcript.update(&fin_m.encode());
    let th_after = transcript.hash();

    let mut th_for_fin = th_after.clone();
    if cert_requested {
        let entries: Vec<CertEntry> = cfg
            .client_cert
            .as_ref()
            .map(|cc| {
                cc.chain
                    .iter()
                    .map(|c| CertEntry {
                        cert_data: c.clone(),
                        extensions: vec![],
                    })
                    .collect()
            })
            .unwrap_or_default();
        let has_cert = !entries.is_empty();
        let cmsg = CertificateMsg {
            request_context: vec![],
            entries,
        };
        let cert_hs = HandshakeMsg::new(HandshakeType::Certificate, cmsg.encode());
        send_hs_enc(s, &mut write_c, &cert_hs)?;
        transcript.update(&cert_hs.encode());
        if has_cert {
            let cc = cfg.client_cert.as_ref().ok_or(TlsError::Protocol)?;
            let content = certificate_verify_content(&transcript.hash(), false);
            let cv = CertificateVerify {
                algorithm: cc.sign_scheme,
                signature: (cc.sign)(&content),
            };
            let cv_hs = HandshakeMsg::new(HandshakeType::CertificateVerify, cv.encode());
            send_hs_enc(s, &mut write_c, &cv_hs)?;
            transcript.update(&cv_hs.encode());
        }
        th_for_fin = transcript.hash();
    }
    let cfk = Zeroizing::new(finished_key(hash, &chs));
    let cfin = finished_verify_data(hash, &cfk, &th_for_fin);
    let cfin_msg = HandshakeMsg::new(HandshakeType::Finished, cfin);
    send_hs_enc(s, &mut write_c, &cfin_msg)?;
    transcript.update(&cfin_msg.encode());

    ks.enter_master();
    let cap = ks.client_application_traffic_secret(&th_after);
    let sap = ks.server_application_traffic_secret(&th_after);
    let resumption_master = ks.resumption_master_secret(&transcript.hash());
    let (cak, caiv) = traffic_keys(hash, &cap, key_len);
    let (sak, saiv) = traffic_keys(hash, &sap, key_len);
    Ok(TlsConnection {
        read: RecordLayer::Tls13(RecordCrypto::new(aead, sak, iv12(saiv))),
        write: RecordLayer::Tls13(RecordCrypto::new(aead, cak, iv12(caiv))),
        version: TLS13,
        alpn: negotiated_alpn,
        client_authenticated: false,
        client_auth_identity: None,
        peer_chain,
        is_client: true,
        post_handshake: HandshakeReader::new(),
        traffic: Some(Tls13Traffic {
            aead,
            hash,
            key_len,
            read_secret: sap,
            write_secret: cap,
            write_updates: 0,
        }),
        resumed: false,
        resumption: Some(ClientResumption {
            server_name: cfg.server_name.clone(),
            hash,
            suite,
            master: resumption_master,
        }),
        new_sessions: Vec::new(),
    })
}

/** @brief 1.2 서버 핸드셰이크. */
fn server_handshake_tls12<S: Read + Write>(
    s: &mut S,
    cfg: &ServerConfig,
    ch_msg: HandshakeMsg,
    ch: ClientHello,
) -> Result<TlsConnection, TlsError> {
    validate_tls12_client_hello(&ch, cfg.sign_scheme)?;
    let server_ecdsa = scheme_is_ecdsa(cfg.sign_scheme);
    let suite =
        tls12::choose_server_suite(&ch.cipher_suites, server_ecdsa).ok_or(TlsError::Protocol)?;
    let info = tls12::suite_info(suite).ok_or(TlsError::Protocol)?;

    let client_groups = ch
        .ext(EXT_SUPPORTED_GROUPS)
        .and_then(|e| e.as_supported_groups())
        .unwrap_or_default();
    let group = tls12::supported_groups()
        .into_iter()
        .find(|g| client_groups.contains(g))
        .ok_or(TlsError::Protocol)?;

    let use_ems = ch.ext(tls12::EXT_EXTENDED_MASTER_SECRET).is_some();
    let client_random = ch.random;

    let client_alpn = ch
        .ext(EXT_ALPN)
        .and_then(|e| e.as_alpn())
        .unwrap_or_default();
    let negotiated_alpn: Option<Vec<u8>> = cfg
        .alpn
        .iter()
        .find(|sp| client_alpn.iter().any(|cp| cp == *sp))
        .cloned();

    let mut transcript = ch_msg.encode();

    let server_random = random_32();
    let mut sh_exts = Vec::new();
    if use_ems {
        sh_exts.push(tls12::ext_extended_master_secret());
    }
    sh_exts.push(tls12::ext_renegotiation_info());
    sh_exts.push(tls12::ext_ec_point_formats());
    if let Some(a) = &negotiated_alpn {
        sh_exts.push(Extension::alpn(&[a]));
    }
    let sh = ServerHello {
        legacy_version: TLS12,
        random: server_random,
        session_id_echo: Vec::new(),
        cipher_suite: suite,
        extensions: sh_exts,
    };
    let sh_msg = sh.to_handshake();
    write_plain_handshake(s, &sh_msg.encode())?;
    transcript.extend_from_slice(&sh_msg.encode());

    let cert_msg = HandshakeMsg::new(
        HandshakeType::Certificate,
        tls12::certificate(&cfg.cert_chain),
    );
    write_plain_handshake(s, &cert_msg.encode())?;
    transcript.extend_from_slice(&cert_msg.encode());

    let mut seed = Zeroizing::new([0u8; 32]);
    fill_random(&mut *seed);
    let kx = KeyExchange::from_seed(group, &*seed).ok_or(TlsError::Protocol)?;
    let params = tls12::ecdh_params(group, &kx.public_bytes());
    let signed = tls12::ske_signed_content(&client_random, &server_random, &params);
    let signature = (cfg.sign)(&signed);
    let ske_msg = HandshakeMsg::new(
        HandshakeType::ServerKeyExchange,
        tls12::server_key_exchange(&params, cfg.sign_scheme, &signature),
    );
    write_plain_handshake(s, &ske_msg.encode())?;
    transcript.extend_from_slice(&ske_msg.encode());

    let shd_msg = HandshakeMsg::new(HandshakeType::ServerHelloDone, Vec::new());
    write_plain_handshake(s, &shd_msg.encode())?;
    transcript.extend_from_slice(&shd_msg.encode());

    let mut phr = PlainHsReader::new();
    let cke = phr.next(s)?;
    if cke.msg_type != HandshakeType::ClientKeyExchange {
        return Err(TlsError::Protocol);
    }
    let client_pub = tls12::parse_client_key_exchange(&cke.body)?;
    transcript.extend_from_slice(&cke.encode());
    let shared = Zeroizing::new(kx.shared_secret(&client_pub).ok_or(TlsError::Protocol)?);

    let master = Zeroizing::new(if use_ems {
        tls12::extended_master_secret(info.hash, &shared, &info.hash.digest(&transcript))
    } else {
        tls12::master_secret(info.hash, &shared, &client_random, &server_random)
    });
    let km = tls12::key_material(
        info.hash,
        &master,
        &client_random,
        &server_random,
        info.key_len,
    );
    let mut read_c = Tls12RecordCrypto::new(info.aead, km.client_key, km.client_iv);
    let mut write_c = Tls12RecordCrypto::new(info.aead, km.server_key, km.server_iv);

    expect_ccs(s)?;
    let cfin_rec = read_record(s)?;
    if cfin_rec.content_type != ContentType::Handshake
        || cfin_rec.version != crate::record::LEGACY_VERSION
    {
        return Err(TlsError::Protocol);
    }
    let cfin_plain = read_c.decrypt(&cfin_rec)?;
    let cfin = parse_exact_handshake(&cfin_plain)?;
    let expected = tls12::finished_verify_data(info.hash, &master, "client finished", &transcript);
    if cfin.msg_type != HandshakeType::Finished || !crate::keyschedule::ct_eq(&cfin.body, &expected)
    {
        return Err(TlsError::BadSignature);
    }
    transcript.extend_from_slice(&cfin.encode());

    write_record(s, &ccs_record())?;
    let sfin = tls12::finished_verify_data(info.hash, &master, "server finished", &transcript);
    let sfin_msg = HandshakeMsg::new(HandshakeType::Finished, sfin);
    write_record(
        s,
        &write_c.encrypt(ContentType::Handshake, &sfin_msg.encode())?,
    )?;

    Ok(TlsConnection {
        read: RecordLayer::Tls12(read_c),
        write: RecordLayer::Tls12(write_c),
        version: TLS12,
        alpn: negotiated_alpn,
        client_authenticated: false,
        client_auth_identity: None,
        peer_chain: Vec::new(),
        is_client: false,
        post_handshake: HandshakeReader::new(),
        traffic: None,
        resumed: false,
        resumption: None,
        new_sessions: Vec::new(),
    })
}

/** @brief 1.2 클라이언트 핸드셰이크. */
fn client_handshake_tls12<S: Read + Write>(
    s: &mut S,
    cfg: &ClientConfig,
    ch: ClientHello,
    ch_bytes: Vec<u8>,
    sh: ServerHello,
    sh_msg: HandshakeMsg,
    mut phr: PlainHsReader,
) -> Result<TlsConnection, TlsError> {
    let client_random = ch.random;
    let negotiated_alpn = validate_tls12_server_hello(cfg, &ch, &sh)?;
    let suite = sh.cipher_suite;
    let info = tls12::suite_info(suite).ok_or(TlsError::Protocol)?;
    let server_random = sh.random;

    let mut transcript = ch_bytes;
    transcript.extend_from_slice(&sh_msg.encode());

    let cert_message = phr.next(s)?;
    if cert_message.msg_type != HandshakeType::Certificate {
        return Err(TlsError::Protocol);
    }
    let cert_chain = tls12::parse_certificate(&cert_message.body)?;
    transcript.extend_from_slice(&cert_message.encode());

    let ske_message = phr.next(s)?;
    if ske_message.msg_type != HandshakeType::ServerKeyExchange {
        return Err(TlsError::Protocol);
    }
    let (group, server_pub, params_bytes, sig_scheme, signature) =
        tls12::parse_server_key_exchange(&ske_message.body)?;
    transcript.extend_from_slice(&ske_message.encode());

    let next = phr.next(s)?;
    if next.msg_type == HandshakeType::CertificateRequest {
        return Err(TlsError::Protocol);
    }
    if next.msg_type != HandshakeType::ServerHelloDone || !next.body.is_empty() {
        return Err(TlsError::Protocol);
    }
    transcript.extend_from_slice(&next.encode());
    if !tls12::group_supported(group) {
        return Err(TlsError::Protocol);
    }
    if !ch
        .ext(EXT_SUPPORTED_GROUPS)
        .and_then(Extension::as_supported_groups)
        .is_some_and(|groups| groups.contains(&group))
        || info.ecdsa != scheme_is_ecdsa(sig_scheme)
    {
        return Err(TlsError::Protocol);
    }
    if !ch
        .ext(EXT_SIGNATURE_ALGORITHMS)
        .and_then(Extension::as_signature_algorithms)
        .is_some_and(|algorithms| algorithms.contains(&sig_scheme))
    {
        return Err(TlsError::Protocol);
    }

    let leaf = cert_chain.first().ok_or(TlsError::BadCert)?;
    let x = X509::parse(leaf)?;
    let peer_chain: Vec<Vec<u8>> = cert_chain.clone();
    match &cfg.roots {
        Some(store) => {
            let chain: Vec<X509> = cert_chain
                .iter()
                .map(|d| X509::parse(d))
                .collect::<Result<_, _>>()?;
            crate::trust::verify_chain(&chain, store, &cfg.server_name, now_epoch())?;
        }
        None => {
            if cfg.insecure_verifier.is_none() {
                return Err(TlsError::BadCert);
            }
            if cfg.verify_name && !x.matches_hostname(&cfg.server_name) {
                return Err(TlsError::BadCert);
            }
        }
    }

    let signed = tls12::ske_signed_content(&client_random, &server_random, &params_bytes);
    x.verify_tls_signature(sig_scheme, &signed, &signature)?;

    let mut seed = Zeroizing::new([0u8; 32]);
    fill_random(&mut *seed);
    let kx = KeyExchange::from_seed(group, &*seed).ok_or(TlsError::Protocol)?;
    let shared = Zeroizing::new(kx.shared_secret(&server_pub).ok_or(TlsError::Protocol)?);

    let cke_msg = HandshakeMsg::new(
        HandshakeType::ClientKeyExchange,
        tls12::client_key_exchange(&kx.public_bytes()),
    );
    write_plain_handshake(s, &cke_msg.encode())?;
    transcript.extend_from_slice(&cke_msg.encode());

    let master = Zeroizing::new(tls12::extended_master_secret(
        info.hash,
        &shared,
        &info.hash.digest(&transcript),
    ));
    let km = tls12::key_material(
        info.hash,
        &master,
        &client_random,
        &server_random,
        info.key_len,
    );
    let mut write_c = Tls12RecordCrypto::new(info.aead, km.client_key, km.client_iv);
    let mut read_c = Tls12RecordCrypto::new(info.aead, km.server_key, km.server_iv);

    write_record(s, &ccs_record())?;
    let cfin = tls12::finished_verify_data(info.hash, &master, "client finished", &transcript);
    let cfin_msg = HandshakeMsg::new(HandshakeType::Finished, cfin);
    write_record(
        s,
        &write_c.encrypt(ContentType::Handshake, &cfin_msg.encode())?,
    )?;
    transcript.extend_from_slice(&cfin_msg.encode());

    expect_ccs(s)?;
    let sfin_rec = read_record(s)?;
    if sfin_rec.content_type != ContentType::Handshake
        || sfin_rec.version != crate::record::LEGACY_VERSION
    {
        return Err(TlsError::Protocol);
    }
    let sfin_plain = read_c.decrypt(&sfin_rec)?;
    let sfin = parse_exact_handshake(&sfin_plain)?;
    let expected = tls12::finished_verify_data(info.hash, &master, "server finished", &transcript);
    if sfin.msg_type != HandshakeType::Finished || !crate::keyschedule::ct_eq(&sfin.body, &expected)
    {
        return Err(TlsError::BadSignature);
    }

    Ok(TlsConnection {
        read: RecordLayer::Tls12(read_c),
        write: RecordLayer::Tls12(write_c),
        version: TLS12,
        alpn: negotiated_alpn,
        client_authenticated: false,
        client_auth_identity: None,
        peer_chain,
        is_client: true,
        post_handshake: HandshakeReader::new(),
        traffic: None,
        resumed: false,
        resumption: None,
        new_sessions: Vec::new(),
    })
}

/** @brief 현재 Unix 초. */
fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/** @brief 암호화된 확장 메시지를 만든다. */
fn encrypted_extensions(alpn: Option<&[u8]>) -> Vec<u8> {
    let mut w = Writer::new();
    w.vec16(|w| {
        if let Some(proto) = alpn {
            Extension::alpn(&[proto]).encode_into(w);
        }
    });
    w.buf
}

#[cfg(test)]
/** @brief 두 버전의 핸드셰이크, 인증서 검증, 클라이언트 인증, 그리고 다운그레이드 거부. */
mod tests {
    use super::*;
    use p256::pkcs8::DecodePrivateKey;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[test]
    /**
     * @brief 레코드 경계의 종료와 레코드 중간의 종료를 구분하는지.
     * @details 위층은 경계의 종료만 정상 종료로 볼 수 있다. 중간에서 끊긴 것까지 같게 보면
     *          잘린 레코드를 알아차리지 못한다.
     */
    fn read_record_separates_boundary_eof_from_truncation() {
        assert_eq!(read_record(&mut &[][..]).unwrap_err(), TlsError::Eof);
        assert_eq!(
            read_record(&mut &[23u8, 3, 3][..]).unwrap_err(),
            TlsError::Io
        );
        assert_eq!(
            read_record(&mut &[23u8, 3, 3, 0, 4, 1, 2][..]).unwrap_err(),
            TlsError::Io
        );
        let record = read_record(&mut &[23u8, 3, 3, 0, 2, 7, 8][..]).unwrap();
        assert_eq!(record.fragment, vec![7, 8]);
    }

    /** @brief TLS 1.3 응용 레코드 테스트용 연결. */
    fn test_tls13_connection() -> TlsConnection {
        let secret = vec![0x42; Hash::Sha256.len()];
        let (key, iv) = traffic_keys(Hash::Sha256, &secret, 16);
        TlsConnection {
            read: RecordLayer::Tls13(RecordCrypto::new(
                Aead::Aes128Gcm,
                key.clone(),
                iv12(iv.clone()),
            )),
            write: RecordLayer::Tls13(RecordCrypto::new(Aead::Aes128Gcm, key, iv12(iv))),
            version: TLS13,
            alpn: None,
            client_authenticated: false,
            client_auth_identity: None,
            peer_chain: Vec::new(),
            is_client: true,
            post_handshake: HandshakeReader::new(),
            traffic: Some(Tls13Traffic {
                aead: Aead::Aes128Gcm,
                hash: Hash::Sha256,
                key_len: 16,
                read_secret: secret.clone(),
                write_secret: secret,
                write_updates: 0,
            }),
            resumed: false,
            resumption: None,
            new_sessions: Vec::new(),
        }
    }

    /** @brief 입출력이 불리면 즉시 실패하는 테스트용 스트림. */
    struct NoIo;

    impl Read for NoIo {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("빈 버퍼 읽기가 하위 스트림에 도달했습니다")
        }
    }

    impl Write for NoIo {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            panic!("빈 버퍼 쓰기가 하위 스트림에 도달했습니다")
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /** @brief 보호된 레코드를 테스트 연결이 읽을 바이트로 만든다. */
    fn encrypted_records(records: &[(ContentType, &[u8])]) -> std::io::Cursor<Vec<u8>> {
        let secret = vec![0x42; Hash::Sha256.len()];
        let (key, iv) = traffic_keys(Hash::Sha256, &secret, 16);
        let mut crypto = RecordCrypto::new(Aead::Aes128Gcm, key, iv12(iv));
        let mut wire = Vec::new();
        for &(content_type, plaintext) in records {
            crypto
                .encrypt(content_type, plaintext)
                .unwrap()
                .encode_into(&mut wire);
        }
        std::io::Cursor::new(wire)
    }

    #[test]
    /** @brief 정상 종료와 치명적 오류를 구분하는지. 합치면 정상 종료가 오류로 보인다. */
    fn close_notify_is_distinct_from_fatal_alerts() {
        assert_eq!(alert_error(&[1, 0]), TlsError::CloseNotify);
        assert_eq!(
            alert_error(&[2, 40]),
            TlsError::PeerAlert {
                level: 2,
                description: 40,
            }
        );
        assert_eq!(alert_error(&[1, 0, 1, 0]), TlsError::CloseNotify);
        assert_eq!(
            alert_error(&[1, 0, 2, 40]),
            TlsError::PeerAlert {
                level: 2,
                description: 40,
            }
        );
        assert_eq!(alert_error(&[2]), TlsError::Protocol);
    }

    #[test]
    /**
     * @brief 안전한 기본 재개 설정이 0-RTT를 받지 않는지.
     * @details 이 크레이트에는 안티리플레이가 없으므로 0이 정책이 아니라 정확성 조건이다.
     *          올리려면 일회용 티켓이나 freshness 구간을 먼저 만들어야 한다.
     */
    fn secure_resumption_default_refuses_early_data() {
        assert_eq!(
            ServerResumption::secure_default().max_early_data,
            0,
            "안티리플레이 없이 0-RTT를 받으면 재생된 질의를 그대로 처리한다"
        );
    }

    #[test]
    /** @brief 빈 응용 버퍼가 네트워크 I/O를 일으키지 않는지. */
    fn tls_stream_empty_io_is_side_effect_free() {
        let mut stream = TlsStream::new(test_tls13_connection(), NoIo);
        assert_eq!(stream.read(&mut []).unwrap(), 0);
        assert_eq!(stream.write(&[]).unwrap(), 0);
    }

    #[test]
    /** @brief 빈 application record 홍수를 제한하되 경계 안의 데이터는 받는지. */
    fn consecutive_empty_application_records_are_bounded() {
        let mut allowed = vec![(ContentType::ApplicationData, &[][..]); 32];
        allowed.push((ContentType::ApplicationData, b"dns"));
        assert_eq!(
            test_tls13_connection().read_app(&mut encrypted_records(&allowed)),
            Ok(b"dns".to_vec())
        );

        let denied = vec![(ContentType::ApplicationData, &[][..]); 33];
        assert_eq!(
            test_tls13_connection().read_app(&mut encrypted_records(&denied)),
            Err(TlsError::Protocol)
        );
    }

    #[test]
    /** @brief 알 수 없는 보호 content type과 빈 handshake를 무시하지 않는지. */
    fn invalid_protected_content_types_fail_closed() {
        assert_eq!(
            test_tls13_connection().read_app(&mut encrypted_records(&[(ContentType(0xff), b"x")])),
            Err(TlsError::Protocol)
        );
        assert_eq!(
            test_tls13_connection()
                .read_app(&mut encrypted_records(&[(ContentType::Handshake, b"")])),
            Err(TlsError::Protocol)
        );
        assert_eq!(
            test_tls13_connection().read_app(&mut encrypted_records(&[(
                ContentType::Alert,
                &[1, 0, 1, 0]
            )])),
            Err(TlsError::Protocol)
        );
    }

    #[test]
    /** @brief 재개를 쓰지 않는 클라이언트가 올바른 티켓만 경계와 무관하게 무시하는지. */
    fn post_handshake_ticket_is_validated_across_records() {
        let ticket = crate::msg::NewSessionTicket {
            lifetime_secs: 60,
            age_add: 7,
            nonce: vec![1],
            ticket: vec![2, 3],
            extensions: vec![],
        };
        let encoded = HandshakeMsg::new(HandshakeType::NewSessionTicket, ticket.encode()).encode();
        assert_eq!(
            test_tls13_connection().read_app(&mut encrypted_records(&[
                (ContentType::Handshake, &encoded[..3]),
                (ContentType::Handshake, &encoded[3..]),
                (ContentType::ApplicationData, b"dns"),
            ])),
            Ok(b"dns".to_vec())
        );

        let key_update = HandshakeMsg::new(HandshakeType::KeyUpdate, vec![2]).encode();
        assert_eq!(
            test_tls13_connection().read_app(&mut encrypted_records(&[(
                ContentType::Handshake,
                &key_update
            )])),
            Err(TlsError::Protocol)
        );

        assert_eq!(
            test_tls13_connection().read_app(&mut encrypted_records(&[
                (
                    ContentType::Handshake,
                    &[HandshakeType::NewSessionTicket.0, 0, 0]
                ),
                (ContentType::ApplicationData, b"dns"),
            ])),
            Err(TlsError::Protocol)
        );

        let valid_key_update = HandshakeMsg::new(HandshakeType::KeyUpdate, vec![0]).encode();
        assert_eq!(
            test_tls13_connection().read_app(&mut encrypted_records(&[
                (ContentType::Handshake, &valid_key_update[..2]),
                (ContentType::Handshake, &valid_key_update[2..]),
            ])),
            Err(TlsError::Protocol)
        );
        let mut coalesced = valid_key_update.clone();
        coalesced.extend_from_slice(&valid_key_update);
        assert_eq!(
            test_tls13_connection().read_app(&mut encrypted_records(&[(
                ContentType::Handshake,
                &coalesced
            )])),
            Err(TlsError::Protocol)
        );
    }

    #[test]
    /** @brief 핸드셰이크 중 예상 밖의 보호 레코드를 조용히 버리지 않는지. */
    fn encrypted_handshake_reader_rejects_unexpected_records() {
        for (content_type, plaintext) in [
            (ContentType::ApplicationData, &b"x"[..]),
            (ContentType::Handshake, &b""[..]),
            (ContentType::Alert, &[1, 0, 1, 0][..]),
        ] {
            let mut reader = EncReader::new();
            let secret = vec![0x42; Hash::Sha256.len()];
            let (key, iv) = traffic_keys(Hash::Sha256, &secret, 16);
            let mut crypto = RecordCrypto::new(Aead::Aes128Gcm, key, iv12(iv));
            assert_eq!(
                reader.next(
                    &mut encrypted_records(&[(content_type, plaintext)]),
                    &mut crypto
                ),
                Err(TlsError::Protocol)
            );
        }
    }

    #[test]
    /** @brief 와이어에 담기지 않는 설정을 핸드셰이크 전에 거부하는지. */
    fn invalid_wire_configuration_is_rejected_before_handshake() {
        let mut cfg = ClientConfig {
            server_name: "dns.example".to_string(),
            alpn: vec![b"h2".to_vec()],
            ..Default::default()
        };
        assert!(client_config_wire_is_valid(&cfg));

        cfg.alpn.push(b"h2".to_vec());
        assert!(!client_config_wire_is_valid(&cfg));
        cfg.alpn.pop();

        cfg.session = Some(crate::session::TlsSession {
            server_name: "dns.example".to_string(),
            suite: TLS_AES_128_GCM_SHA256,
            psk: vec![0; 31],
            ticket: vec![1],
            lifetime_secs: 60,
            age_add: 0,
            max_early_data: 0,
            alpn: Some(b"h2".to_vec()),
            server_transport_params: Vec::new(),
            obtained_at_ms: 0,
        });
        assert!(!client_config_wire_is_valid(&cfg));
        cfg.session.as_mut().unwrap().psk.push(0);
        assert!(client_config_wire_is_valid(&cfg));
        cfg.session.as_mut().unwrap().alpn = Some(b"h3".to_vec());
        assert!(!client_config_wire_is_valid(&cfg));

        let mut server = ServerConfig {
            cert_chain: vec![vec![1]],
            sign_scheme: ECDSA_SECP256R1_SHA256,
            sign: Arc::new(|_| Vec::new()),
            alpn: Vec::new(),
            client_ca: None,
            resumption: Some(ServerResumption {
                ticketer: Arc::new(crate::session::Ticketer::from_key([1; 32])),
                lifetime_secs: crate::session::MAX_TICKET_LIFETIME_SECS,
                max_early_data: 0,
            }),
        };
        assert!(server_config_wire_is_valid(&server));
        server.resumption.as_mut().unwrap().lifetime_secs += 1;
        assert!(!server_config_wire_is_valid(&server));
    }

    /** @brief 테스트용 1.2 인사말 짝. */
    fn valid_tls12_hellos() -> (ClientConfig, ClientHello, ServerHello) {
        let cfg = ClientConfig {
            server_name: "dns.example".to_string(),
            alpn: vec![b"dot".to_vec()],
            ..Default::default()
        };
        let ch = ClientHello {
            legacy_version: TLS12,
            random: [1; 32],
            session_id: vec![2; 32],
            cipher_suites: tls12::client_suites().to_vec(),
            compression_methods: vec![0],
            extensions: vec![
                Extension::signature_algorithms(&[ECDSA_SECP256R1_SHA256]),
                tls12::ext_extended_master_secret(),
                tls12::ext_renegotiation_info(),
                tls12::ext_ec_point_formats(),
                Extension::alpn(&[b"dot"]),
            ],
        };
        let sh = ServerHello {
            legacy_version: TLS12,
            random: [3; 32],
            session_id_echo: Vec::new(),
            cipher_suite: tls12::suites::ECDHE_ECDSA_AES128_GCM_SHA256,
            extensions: vec![
                tls12::ext_extended_master_secret(),
                tls12::ext_renegotiation_info(),
                tls12::ext_ec_point_formats(),
                Extension::alpn(&[b"dot"]),
            ],
        };
        (cfg, ch, sh)
    }

    #[test]
    /** @brief 다운그레이드과 제안하지 않은 값을 거부하는지. */
    fn tls12_hello_validation_rejects_downgrade_and_unsolicited_values() {
        let (cfg, mut ch, mut sh) = valid_tls12_hellos();
        assert!(validate_tls12_client_hello(&ch, ECDSA_SECP256R1_SHA256).is_ok());
        assert_eq!(
            validate_tls12_server_hello(&cfg, &ch, &sh).unwrap(),
            Some(b"dot".to_vec())
        );

        sh.extensions
            .retain(|extension| extension.ext_type != tls12::EXT_EXTENDED_MASTER_SECRET);
        assert_eq!(
            validate_tls12_server_hello(&cfg, &ch, &sh),
            Err(TlsError::Protocol)
        );
        sh.extensions.push(tls12::ext_extended_master_secret());
        sh.extensions.push(Extension::new(0x1234, Vec::new()));
        assert_eq!(
            validate_tls12_server_hello(&cfg, &ch, &sh),
            Err(TlsError::Protocol)
        );
        sh.extensions.pop();
        ch.extensions.push(Extension::server_name("dns.example"));
        sh.extensions
            .push(Extension::new(EXT_SERVER_NAME, Vec::new()));
        assert!(
            validate_tls12_server_hello(&cfg, &ch, &sh).is_ok(),
            "보낸 서버 이름을 썼다는 빈 응답은 받아들인다"
        );
        ch.extensions
            .retain(|extension| extension.ext_type != EXT_SERVER_NAME);
        assert_eq!(
            validate_tls12_server_hello(&cfg, &ch, &sh),
            Err(TlsError::Protocol),
            "보내지 않은 서버 이름에 대한 응답은 거부한다"
        );
        sh.extensions.pop();
        *sh.extensions
            .iter_mut()
            .find(|extension| extension.ext_type == EXT_ALPN)
            .unwrap() = Extension::alpn(&[b"h2"]);
        assert_eq!(
            validate_tls12_server_hello(&cfg, &ch, &sh),
            Err(TlsError::Protocol)
        );

        ch.compression_methods = vec![1];
        assert_eq!(
            validate_tls12_client_hello(&ch, ECDSA_SECP256R1_SHA256),
            Err(TlsError::Protocol)
        );
    }

    #[test]
    /** @brief 비정규 더미 레코드와 어긋난 순서를 거부하는지. */
    fn tls12_rejects_noncanonical_ccs_finished_and_server_flight_order() {
        let valid_finished = HandshakeMsg::new(HandshakeType::Finished, vec![1; 12]).encode();
        assert!(parse_exact_handshake(&valid_finished).is_ok());
        let mut trailing = valid_finished;
        trailing.push(0);
        assert_eq!(parse_exact_handshake(&trailing), Err(TlsError::Protocol));

        let valid_ccs = TlsRecord::new(ContentType::ChangeCipherSpec, vec![1]).encode();
        assert!(expect_ccs(&mut std::io::Cursor::new(valid_ccs)).is_ok());
        let invalid_ccs = TlsRecord::new(ContentType::ChangeCipherSpec, vec![1, 0]).encode();
        assert_eq!(
            expect_ccs(&mut std::io::Cursor::new(invalid_ccs)),
            Err(TlsError::Protocol)
        );

        let (cfg, ch, sh) = valid_tls12_hellos();
        let ch_bytes = ch.to_handshake().encode();
        let sh_msg = sh.to_handshake();
        let wrong_first = HandshakeMsg::new(
            HandshakeType::ServerKeyExchange,
            tls12::server_key_exchange(
                &tls12::ecdh_params(X25519, &[1; 32]),
                ECDSA_SECP256R1_SHA256,
                &[1],
            ),
        );
        let input = TlsRecord::new(ContentType::Handshake, wrong_first.encode()).encode();
        assert_eq!(
            client_handshake_tls12(
                &mut std::io::Cursor::new(input),
                &cfg,
                ch,
                ch_bytes,
                sh,
                sh_msg,
                PlainHsReader::new(),
            )
            .map(|_| ()),
            Err(TlsError::Protocol)
        );
    }

    #[test]
    /** @brief 큰 쓰기가 평문 상한에 맞춰 나뉘는지. */
    fn application_writes_are_fragmented_to_tls_plaintext_limits() {
        let key = vec![0x33; 16];
        let iv = [0x44; 12];
        let mut connection = TlsConnection {
            read: RecordLayer::Tls13(RecordCrypto::new(crate::Aead::Aes128Gcm, key.clone(), iv)),
            write: RecordLayer::Tls13(RecordCrypto::new(crate::Aead::Aes128Gcm, key.clone(), iv)),
            version: TLS13,
            alpn: None,
            client_authenticated: false,
            client_auth_identity: None,
            peer_chain: Vec::new(),
            is_client: false,
            post_handshake: HandshakeReader::new(),
            traffic: None,
            resumed: false,
            resumption: None,
            new_sessions: Vec::new(),
        };
        let plaintext = vec![0x5a; MAX_FRAGMENT * 2 + 17];
        let mut wire = Vec::new();
        connection.write_app(&mut wire, &plaintext).unwrap();

        let mut receiver = RecordCrypto::new(crate::Aead::Aes128Gcm, key, iv);
        let mut decoded = Vec::new();
        let mut records = 0;
        while !wire.is_empty() {
            let (record, consumed) = TlsRecord::parse(&wire).unwrap().unwrap();
            let (content_type, fragment) = receiver.decrypt(&record).unwrap();
            assert_eq!(content_type, ContentType::ApplicationData);
            assert!(fragment.len() <= MAX_FRAGMENT);
            decoded.extend_from_slice(&fragment);
            wire.drain(..consumed);
            records += 1;
        }
        assert_eq!(decoded, plaintext);
        assert_eq!(records, 3);
    }

    #[test]
    /** @brief 큰 평문 handshake를 여러 레코드로 나누는지. */
    fn plaintext_handshake_is_fragmented_at_the_record_limit() {
        let payload = vec![0x5a; MAX_FRAGMENT + 17];
        let mut wire = Vec::new();
        write_plain_handshake(&mut wire, &payload).unwrap();

        let mut decoded = Vec::new();
        let mut records = 0;
        while !wire.is_empty() {
            let (record, consumed) = TlsRecord::parse(&wire).unwrap().unwrap();
            assert_eq!(record.content_type, ContentType::Handshake);
            assert!(record.fragment.len() <= MAX_FRAGMENT);
            decoded.extend_from_slice(&record.fragment);
            wire.drain(..consumed);
            records += 1;
        }
        assert_eq!(decoded, payload);
        assert_eq!(records, 2);
    }

    #[test]
    /** @brief 큰 보호 handshake도 암호화 전에 레코드 경계로 나누는지. */
    fn encrypted_handshake_is_fragmented_at_the_record_limit() {
        let key = vec![0x33; 16];
        let iv = [0x44; 12];
        let message = HandshakeMsg::new(HandshakeType::Certificate, vec![0x5a; MAX_FRAGMENT + 17]);
        let expected = message.encode();
        let mut sender = RecordCrypto::new(Aead::Aes128Gcm, key.clone(), iv);
        let mut wire = Vec::new();
        send_hs_enc(&mut wire, &mut sender, &message).unwrap();

        let mut receiver = RecordCrypto::new(Aead::Aes128Gcm, key, iv);
        let mut decoded = Vec::new();
        let mut records = 0;
        while !wire.is_empty() {
            let (record, consumed) = TlsRecord::parse(&wire).unwrap().unwrap();
            let (content_type, fragment) = receiver.decrypt(&record).unwrap();
            assert_eq!(content_type, ContentType::Handshake);
            assert!(fragment.len() <= MAX_FRAGMENT);
            decoded.extend_from_slice(&fragment);
            wire.drain(..consumed);
            records += 1;
        }
        assert_eq!(decoded, expected);
        assert_eq!(records, 2);
    }

    #[test]
    /** @brief 상한과 정확히 같은 크기를 받아들이는지. */
    fn full_size_tls13_plaintext_is_accepted() {
        let key = vec![0x55; 16];
        let iv = [0x66; 12];
        let mut sender = RecordCrypto::new(crate::Aead::Aes128Gcm, key.clone(), iv);
        let record = sender
            .encrypt(ContentType::ApplicationData, &vec![0x7a; MAX_FRAGMENT])
            .unwrap();
        let mut receiver = RecordLayer::Tls13(RecordCrypto::new(crate::Aead::Aes128Gcm, key, iv));
        let (content_type, plaintext) = receiver.decrypt(&record).unwrap();
        assert_eq!(content_type, ContentType::ApplicationData);
        assert_eq!(plaintext.len(), MAX_FRAGMENT);
    }

    #[test]
    /** @brief 인증됐어도 상한을 넘는 평문을 거부하는지. */
    fn authenticated_oversized_tls13_plaintext_is_rejected() {
        let key = vec![0x55; 16];
        let iv = [0x66; 12];
        let mut inner = vec![0x7a; MAX_FRAGMENT + 1];
        inner.push(ContentType::ApplicationData.0);
        let ciphertext_len = inner.len() + 16;
        let aad = [
            ContentType::ApplicationData.0,
            (crate::record::LEGACY_VERSION >> 8) as u8,
            crate::record::LEGACY_VERSION as u8,
            (ciphertext_len >> 8) as u8,
            ciphertext_len as u8,
        ];
        let fragment = crate::aead::aead_seal(crate::Aead::Aes128Gcm, &key, &iv, &aad, &inner);
        let record = TlsRecord::new(ContentType::ApplicationData, fragment);
        let mut receiver = RecordLayer::Tls13(RecordCrypto::new(crate::Aead::Aes128Gcm, key, iv));
        assert!(matches!(
            receiver.decrypt(&record),
            Err(TlsError::RecordOverflow)
        ));
    }

    #[test]
    /** @brief 실제 소켓 위에서 1.3 핸드셰이크가 끝나는지. */
    fn full_tls13_handshake_over_tcp() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = ck.cert.der().as_ref().to_vec();
        let key_der = ck.key_pair.serialize_der();
        let secret = p256::SecretKey::from_pkcs8_der(&key_der).unwrap();
        let signing = p256::ecdsa::SigningKey::from(secret);

        let server_cfg = ServerConfig {
            cert_chain: vec![cert_der],
            sign_scheme: ECDSA_SECP256R1_SHA256,
            sign: Arc::new(move |content| {
                use p256::ecdsa::{signature::Signer, Signature};
                let sig: Signature = signing.sign(content);
                sig.to_der().as_bytes().to_vec()
            }),
            alpn: vec![],
            client_ca: None,
            resumption: None,
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut conn = server_handshake(&mut s, &server_cfg).expect("서버 핸드셰이크");
            let req = conn.read_app(&mut s).expect("요청 수신");
            assert_eq!(req, b"ping");
            conn.write_app(&mut s, b"pong").expect("응답 송신");
        });

        let mut c = TcpStream::connect(addr).unwrap();
        let client_cfg = ClientConfig {
            server_name: "localhost".to_string(),
            verify_name: true,
            roots: None,
            insecure_verifier: Some(
                InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![],
            ..Default::default()
        };
        let mut conn = client_handshake(&mut c, &client_cfg).expect("클라 핸드셰이크");
        conn.write_app(&mut c, b"ping").unwrap();
        let resp = conn.read_app(&mut c).unwrap();
        assert_eq!(resp, b"pong");

        server.join().unwrap();
    }

    #[test]
    /** @brief 요청형·사용량 경계 KeyUpdate 뒤 양방향 새 키가 실제 TCP에서 맞는지. */
    fn tls13_key_update_rotates_both_directions() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let server_cfg = ServerConfig::from_pkcs8(
            ck.cert.der().as_ref().to_vec(),
            &ck.key_pair.serialize_der(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut conn = server_handshake(&mut socket, &server_cfg).unwrap();
            conn.send_key_update(&mut socket, true).unwrap();
            conn.write_app(&mut socket, b"generation-one").unwrap();
            assert_eq!(conn.read_app(&mut socket).unwrap(), b"client-new-key");

            match &mut conn.write {
                RecordLayer::Tls13(crypto) => crypto.move_to_last_encryption_for_test(),
                RecordLayer::Tls12(_) => panic!("TLS 1.3을 협상해야 합니다"),
            }
            conn.write_app(&mut socket, b"generation-two").unwrap();
        });

        let mut socket = TcpStream::connect(addr).unwrap();
        let client_cfg = ClientConfig {
            server_name: "localhost".to_string(),
            verify_name: true,
            roots: None,
            insecure_verifier: Some(
                InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            ..Default::default()
        };
        let mut conn = client_handshake(&mut socket, &client_cfg).unwrap();
        assert_eq!(conn.read_app(&mut socket).unwrap(), b"generation-one");
        conn.write_app(&mut socket, b"client-new-key").unwrap();
        match &mut conn.read {
            RecordLayer::Tls13(crypto) => crypto.move_to_last_encryption_for_test(),
            RecordLayer::Tls12(_) => panic!("TLS 1.3을 협상해야 합니다"),
        }
        assert_eq!(conn.read_app(&mut socket).unwrap(), b"generation-two");
        server.join().unwrap();
    }

    #[test]
    /** @brief HRR 뒤 정상 티켓 재접속도 인증서 서명 없이 PSK-DHE로 끝나는지. */
    fn blocking_tls13_hrr_resumption_skips_certificate_flight() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let key_der = ck.key_pair.serialize_der();
        let signing =
            p256::ecdsa::SigningKey::from(p256::SecretKey::from_pkcs8_der(&key_der).unwrap());
        let signatures = Arc::new(AtomicUsize::new(0));
        let sign_counter = Arc::clone(&signatures);
        let ticketer = Arc::new(crate::session::Ticketer::from_key([0x5a; 32]));
        let now = crate::session::now_ms();
        let psk = vec![0x33; Hash::Sha256.len()];
        let age_add = 0x1020_3040;
        let lifetime_secs = 60;
        let ticket = ticketer
            .seal(&crate::session::ResumptionState {
                server_name: Some("localhost".to_string()),
                suite: TLS_AES_128_GCM_SHA256,
                psk: psk.clone(),
                alpn: None,
                issued_ms: now,
                age_add,
                lifetime_secs,
                max_early_data: 0,
            })
            .unwrap();
        let server_cfg = ServerConfig {
            cert_chain: vec![ck.cert.der().as_ref().to_vec()],
            sign_scheme: ECDSA_SECP256R1_SHA256,
            sign: Arc::new(move |content| {
                use p256::ecdsa::{signature::Signer, Signature};
                sign_counter.fetch_add(1, Ordering::Relaxed);
                let signature: Signature = signing.sign(content);
                signature.to_der().as_bytes().to_vec()
            }),
            alpn: vec![],
            client_ca: None,
            resumption: Some(ServerResumption {
                ticketer,
                lifetime_secs,
                max_early_data: 0,
            }),
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut conn = server_handshake(&mut socket, &server_cfg).unwrap();
            assert_eq!(conn.read_app(&mut socket).unwrap(), b"resume");
            conn.write_app(&mut socket, b"ok").unwrap();
        });

        let mut socket = TcpStream::connect(addr).unwrap();
        let client_cfg = ClientConfig {
            server_name: "localhost".to_string(),
            verify_name: true,
            roots: None,
            insecure_verifier: Some(
                InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            session: Some(crate::session::TlsSession {
                server_name: "localhost".to_string(),
                suite: TLS_AES_128_GCM_SHA256,
                psk,
                ticket,
                lifetime_secs,
                age_add,
                max_early_data: 0,
                alpn: None,
                server_transport_params: vec![],
                obtained_at_ms: now,
            }),
            send_key_share: false,
            ..Default::default()
        };
        let mut conn = client_handshake(&mut socket, &client_cfg).unwrap();
        conn.write_app(&mut socket, b"resume").unwrap();
        assert_eq!(conn.read_app(&mut socket).unwrap(), b"ok");
        server.join().unwrap();
        assert_eq!(signatures.load(Ordering::Relaxed), 0);
    }

    #[test]
    /** @brief 첫 연결이 발급한 티켓으로 두 번째 blocking TLS 연결이 재개되는지. */
    fn blocking_tls13_ticket_issue_and_resume_roundtrip() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let mut server_cfg = ServerConfig::from_pkcs8(
            ck.cert.der().as_ref().to_vec(),
            &ck.key_pair.serialize_der(),
        )
        .unwrap();
        server_cfg.resumption = Some(ServerResumption {
            ticketer: Arc::new(crate::session::Ticketer::from_key([0x6b; 32])),
            lifetime_secs: 120,
            max_early_data: 0,
        });

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for (expected_resumed, request, response) in [
                (false, &b"first"[..], &b"one"[..]),
                (true, &b"second"[..], &b"two"[..]),
            ] {
                let (mut socket, _) = listener.accept().unwrap();
                let mut conn = server_handshake(&mut socket, &server_cfg).unwrap();
                assert_eq!(conn.is_resumed(), expected_resumed);
                assert_eq!(conn.read_app(&mut socket).unwrap(), request);
                conn.write_app(&mut socket, response).unwrap();
            }
        });

        let base_client = || ClientConfig {
            server_name: "localhost".to_string(),
            verify_name: true,
            roots: None,
            insecure_verifier: Some(
                InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            ..Default::default()
        };

        let mut first_socket = TcpStream::connect(addr).unwrap();
        let mut first = client_handshake(&mut first_socket, &base_client()).unwrap();
        assert!(!first.is_resumed());
        first.write_app(&mut first_socket, b"first").unwrap();
        assert_eq!(first.read_app(&mut first_socket).unwrap(), b"one");
        let mut sessions = first.take_sessions();
        assert_eq!(sessions.len(), 1);

        let mut second_cfg = base_client();
        second_cfg.session = sessions.pop();
        let mut second_socket = TcpStream::connect(addr).unwrap();
        let mut second = client_handshake(&mut second_socket, &second_cfg).unwrap();
        assert!(second.is_resumed());
        second.write_app(&mut second_socket, b"second").unwrap();
        assert_eq!(second.read_app(&mut second_socket).unwrap(), b"two");
        assert_eq!(second.take_sessions().len(), 1);
        server.join().unwrap();
    }

    #[test]
    /** @brief 다른 SNI에서 발급한 정상 인증 티켓도 재개에 쓰지 않는지. */
    fn blocking_tls13_ticket_is_bound_to_server_name() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let ticketer = Arc::new(crate::session::Ticketer::from_key([0x7c; 32]));
        let now = crate::session::now_ms();
        let psk = vec![0x44; Hash::Sha256.len()];
        let ticket = ticketer
            .seal(&crate::session::ResumptionState {
                server_name: Some("other.example".to_string()),
                suite: TLS_AES_128_GCM_SHA256,
                psk: psk.clone(),
                alpn: None,
                issued_ms: now,
                age_add: 9,
                lifetime_secs: 60,
                max_early_data: 0,
            })
            .unwrap();
        let server_cfg = ServerConfig::from_pkcs8(
            ck.cert.der().as_ref().to_vec(),
            &ck.key_pair.serialize_der(),
        )
        .unwrap()
        .with_resumption(ServerResumption {
            ticketer,
            lifetime_secs: 60,
            max_early_data: 0,
        });
        let client_cfg = ClientConfig {
            server_name: "localhost".to_string(),
            roots: None,
            insecure_verifier: Some(
                InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            session: Some(crate::session::TlsSession {
                server_name: "localhost".to_string(),
                suite: TLS_AES_128_GCM_SHA256,
                psk,
                ticket,
                lifetime_secs: 60,
                age_add: 9,
                max_early_data: 0,
                alpn: None,
                server_transport_params: Vec::new(),
                obtained_at_ms: now,
            }),
            ..Default::default()
        };
        let kx = KeyExchange::from_seed(X25519, &[0x21; 32]).unwrap();
        let session = fresh_client_session(&client_cfg);
        let hello = build_client_hello(&client_cfg, &kx, true, None, session);
        let wire = encode_client_hello(&hello, session, &[]).unwrap();
        let message = parse_exact_handshake(&wire).unwrap();
        let parsed = ClientHello::from_handshake(&message).unwrap();
        assert!(
            accept_client_psk(&server_cfg, &parsed, &message, &None, &[])
                .unwrap()
                .is_none()
        );

        let correct_psk = vec![0x55; Hash::Sha256.len()];
        let matching_ticket = server_cfg
            .resumption
            .as_ref()
            .unwrap()
            .ticketer
            .seal(&crate::session::ResumptionState {
                server_name: Some("localhost".to_string()),
                suite: TLS_AES_128_GCM_SHA256,
                psk: correct_psk,
                alpn: None,
                issued_ms: now,
                age_add: 10,
                lifetime_secs: 60,
                max_early_data: 0,
            })
            .unwrap();
        let mut forged_cfg = client_cfg;
        forged_cfg.session = Some(crate::session::TlsSession {
            server_name: "localhost".to_string(),
            suite: TLS_AES_128_GCM_SHA256,
            psk: vec![0x56; Hash::Sha256.len()],
            ticket: matching_ticket,
            lifetime_secs: 60,
            age_add: 10,
            max_early_data: 0,
            alpn: None,
            server_transport_params: Vec::new(),
            obtained_at_ms: now,
        });
        let session = fresh_client_session(&forged_cfg);
        let hello = build_client_hello(&forged_cfg, &kx, true, None, session);
        let wire = encode_client_hello(&hello, session, &[]).unwrap();
        let message = parse_exact_handshake(&wire).unwrap();
        let parsed = ClientHello::from_handshake(&message).unwrap();
        assert!(matches!(
            accept_client_psk(&server_cfg, &parsed, &message, &None, &[]),
            Err(TlsError::BadSignature)
        ));
    }

    #[test]
    /** @brief 16KiB보다 큰 실제 인증서 메시지가 레코드 경계를 넘어 핸드셰이크되는지. */
    fn large_certificate_handshake_spans_tls13_records() {
        use rcgen::{CertificateParams, CustomExtension, KeyPair};

        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 55_555, 1],
                vec![0xa5; MAX_FRAGMENT],
            ));
        let cert = params.self_signed(&key).unwrap();
        let cert_der = cert.der().to_vec();
        assert!(cert_der.len() > MAX_FRAGMENT);
        let server_cfg = ServerConfig::from_pkcs8(cert_der, &key.serialize_der()).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            server_handshake(&mut socket, &server_cfg).expect("큰 인증서 서버 핸드셰이크");
        });

        let mut socket = TcpStream::connect(addr).unwrap();
        let client_cfg = ClientConfig {
            server_name: "localhost".to_string(),
            verify_name: true,
            roots: None,
            insecure_verifier: Some(
                InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            ..Default::default()
        };
        client_handshake(&mut socket, &client_cfg).expect("큰 인증서 클라이언트 핸드셰이크");
        server.join().unwrap();
    }

    #[test]
    /** @brief 이름이 다르면 거부하는지. */
    fn wrong_hostname_rejected() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = ck.cert.der().as_ref().to_vec();
        let key_der = ck.key_pair.serialize_der();
        let signing =
            p256::ecdsa::SigningKey::from(p256::SecretKey::from_pkcs8_der(&key_der).unwrap());
        let server_cfg = ServerConfig {
            cert_chain: vec![cert_der],
            sign_scheme: ECDSA_SECP256R1_SHA256,
            sign: Arc::new(move |content| {
                use p256::ecdsa::{signature::Signer, Signature};
                let sig: Signature = signing.sign(content);
                sig.to_der().as_bytes().to_vec()
            }),
            alpn: vec![],
            client_ca: None,
            resumption: None,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let _ = server_handshake(&mut s, &server_cfg);
            }
        });
        let mut c = TcpStream::connect(addr).unwrap();
        let client_cfg = ClientConfig {
            server_name: "evil.example".to_string(),
            verify_name: true,
            roots: None,
            insecure_verifier: Some(
                InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![],
            ..Default::default()
        };

        assert!(matches!(
            client_handshake(&mut c, &client_cfg),
            Err(TlsError::BadCert)
        ));
        drop(c);
        let _ = server.join();
    }

    #[test]
    /** @brief 체인이 이쪽 저장소까지 이어지는지 확인하는지. */
    fn handshake_verifies_chain_to_trust_store() {
        use crate::trust::TrustStore;
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_der = ca_cert.der().to_vec();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(vec!["dns.example".to_string()]).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
        let leaf_der = leaf_cert.der().to_vec();
        let leaf_key_der = leaf_key.serialize_der();

        let make_server = || {
            let (scheme, sign) = signer_from_pkcs8_der(&leaf_key_der).unwrap();
            ServerConfig {
                cert_chain: vec![leaf_der.clone()],
                sign_scheme: scheme,
                sign,
                alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                client_ca: None,
                resumption: None,
            }
        };

        {
            let server_cfg = make_server();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                if let Ok((mut s, _)) = listener.accept() {
                    if let Ok(mut conn) = server_handshake(&mut s, &server_cfg) {
                        if let Ok(req) = conn.read_app(&mut s) {
                            assert_eq!(req, b"hi");
                            let _ = conn.write_app(&mut s, b"ok");
                        }
                    }
                }
            });
            let mut c = TcpStream::connect(addr).unwrap();
            let cfg = ClientConfig {
                server_name: "dns.example".into(),
                verify_name: true,
                roots: Some(TrustStore::from_ders([ca_der.as_slice()])),
                alpn: vec![b"h2".to_vec()],
                ..Default::default()
            };
            let mut conn = client_handshake(&mut c, &cfg).expect("체인 검증 성공해야");

            assert_eq!(conn.alpn(), Some(b"h2".as_slice()));
            conn.write_app(&mut c, b"hi").unwrap();
            assert_eq!(conn.read_app(&mut c).unwrap(), b"ok");
            server.join().unwrap();
        }

        {
            let server_cfg = make_server();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                if let Ok((mut s, _)) = listener.accept() {
                    let _ = server_handshake(&mut s, &server_cfg);
                }
            });

            let other_key = KeyPair::generate().unwrap();
            let mut other_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            other_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let other_ca = other_params.self_signed(&other_key).unwrap();

            let mut c = TcpStream::connect(addr).unwrap();
            let cfg = ClientConfig {
                server_name: "dns.example".into(),
                verify_name: true,
                roots: Some(TrustStore::from_ders([other_ca.der().as_ref()])),
                alpn: vec![],
                ..Default::default()
            };
            assert!(matches!(
                client_handshake(&mut c, &cfg),
                Err(TlsError::BadCert)
            ));
            drop(c);
            let _ = server.join();
        }
    }

    /** @brief 클라이언트 인증 테스트용 CA와 리프. */
    fn mtls_ca_and_leaf(cn: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(vec![cn.to_string()]).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
        (
            ca_cert.der().to_vec(),
            leaf_cert.der().to_vec(),
            leaf_key.serialize_der(),
        )
    }

    /** @brief 검증을 끈 테스트용 클라이언트. */
    fn insecure_test_client(server_name: &str) -> ClientConfig {
        ClientConfig {
            server_name: server_name.to_string(),
            roots: None,
            insecure_verifier: Some(
                InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            ..Default::default()
        }
    }

    /** @brief 클라이언트 인증을 켠 테스트용 서버 설정. */
    fn mtls_server_cfg(client_ca: Option<crate::trust::TrustStore>) -> ServerConfig {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = ck.cert.der().as_ref().to_vec();
        let key_der = ck.key_pair.serialize_der();
        let mut cfg = ServerConfig::from_pkcs8(cert_der, &key_der).unwrap();
        cfg.client_ca = client_ca;
        cfg
    }

    #[test]
    /** @brief 클라이언트 인증이 되는지. */
    fn mtls_handshake_with_client_cert() {
        use crate::trust::TrustStore;
        let (ca_der, leaf_der, leaf_key) = mtls_ca_and_leaf("client.example");
        let server_cfg = mtls_server_cfg(Some(TrustStore::from_ders([ca_der.as_slice()])));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut conn = server_handshake(&mut s, &server_cfg).expect("mTLS 서버 핸드셰이크");
            let req = conn.read_app(&mut s).expect("요청");
            assert_eq!(req, b"auth-ping");
            conn.write_app(&mut s, b"auth-pong").unwrap();
        });

        let mut c = TcpStream::connect(addr).unwrap();
        let mut client_cfg = insecure_test_client("localhost");
        client_cfg.client_cert = Some(ClientCert::from_pkcs8(vec![leaf_der], &leaf_key).unwrap());
        let mut conn = client_handshake(&mut c, &client_cfg).expect("mTLS 클라 핸드셰이크");
        conn.write_app(&mut c, b"auth-ping").unwrap();
        assert_eq!(conn.read_app(&mut c).unwrap(), b"auth-pong");
        server.join().unwrap();
    }

    #[test]
    /** @brief 인증서 없는 클라이언트를 거부하는지. */
    fn mtls_rejects_client_without_cert() {
        use crate::trust::TrustStore;
        let (ca_der, _, _) = mtls_ca_and_leaf("client.example");
        let server_cfg = mtls_server_cfg(Some(TrustStore::from_ders([ca_der.as_slice()])));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();

            assert!(matches!(
                server_handshake(&mut s, &server_cfg),
                Err(TlsError::BadCert)
            ));
        });

        let mut c = TcpStream::connect(addr).unwrap();
        let client_cfg = insecure_test_client("localhost");

        let _ = client_handshake(&mut c, &client_cfg);
        server.join().unwrap();
    }

    #[test]
    /** @brief 모르는 CA가 발급한 클라이언트 인증서를 거부하는지. */
    fn mtls_rejects_untrusted_client_cert() {
        use crate::trust::TrustStore;
        let (trusted_ca, _, _) = mtls_ca_and_leaf("good.example");

        let (_other_ca, evil_leaf, evil_key) = mtls_ca_and_leaf("evil.example");
        let server_cfg = mtls_server_cfg(Some(TrustStore::from_ders([trusted_ca.as_slice()])));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            assert!(matches!(
                server_handshake(&mut s, &server_cfg),
                Err(TlsError::BadCert)
            ));
        });

        let mut c = TcpStream::connect(addr).unwrap();
        let mut client_cfg = insecure_test_client("localhost");
        client_cfg.client_cert = Some(ClientCert::from_pkcs8(vec![evil_leaf], &evil_key).unwrap());
        let _ = client_handshake(&mut c, &client_cfg);
        server.join().unwrap();
    }

    #[test]
    /** @brief 키 공유가 없으면 다시 시도를 거쳐 끝나는지. */
    fn hrr_round_trip_when_client_omits_key_share() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = ck.cert.der().as_ref().to_vec();
        let key_der = ck.key_pair.serialize_der();
        let server_cfg = ServerConfig::from_pkcs8(cert_der, &key_der).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut conn = server_handshake(&mut s, &server_cfg).expect("HRR 서버 핸드셰이크");
            let req = conn.read_app(&mut s).expect("요청");
            assert_eq!(req, b"hrr-ping");
            conn.write_app(&mut s, b"hrr-pong").unwrap();
        });

        let mut c = TcpStream::connect(addr).unwrap();
        let mut client_cfg = insecure_test_client("localhost");
        client_cfg.send_key_share = false;
        let mut conn = client_handshake(&mut c, &client_cfg).expect("HRR 클라 핸드셰이크");
        conn.write_app(&mut c, b"hrr-ping").unwrap();
        assert_eq!(conn.read_app(&mut c).unwrap(), b"hrr-pong");
        server.join().unwrap();
    }

    #[test]
    /** @brief 키 공유가 있으면 왕복 하나로 끝나는지. */
    fn normal_handshake_no_hrr_when_key_share_present() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = ck.cert.der().as_ref().to_vec();
        let key_der = ck.key_pair.serialize_der();
        let server_cfg = ServerConfig::from_pkcs8(cert_der, &key_der).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut conn = server_handshake(&mut s, &server_cfg).unwrap();
            let req = conn.read_app(&mut s).unwrap();
            conn.write_app(&mut s, &req).unwrap();
        });
        let mut c = TcpStream::connect(addr).unwrap();
        let cfg = insecure_test_client("localhost");
        let mut conn = client_handshake(&mut c, &cfg).unwrap();
        conn.write_app(&mut c, b"hello").unwrap();
        assert_eq!(conn.read_app(&mut c).unwrap(), b"hello");
        server.join().unwrap();
    }

    /** @brief 1.2만 제안하는 테스트용 클라이언트 핸드셰이크. */
    fn client_handshake_force_tls12<S: Read + Write>(
        s: &mut S,
        cfg: &ClientConfig,
    ) -> Result<TlsConnection, TlsError> {
        let mut exts = vec![
            Extension::supported_groups(&[X25519, SECP256R1]),
            Extension::signature_algorithms(&[
                ECDSA_SECP256R1_SHA256,
                RSA_PSS_RSAE_SHA256,
                RSA_PKCS1_SHA256,
            ]),
            Extension::server_name(&cfg.server_name),
            tls12::ext_extended_master_secret(),
            tls12::ext_ec_point_formats(),
            tls12::ext_renegotiation_info(),
        ];
        if !cfg.alpn.is_empty() {
            let protos: Vec<&[u8]> = cfg.alpn.iter().map(|v| v.as_slice()).collect();
            exts.push(Extension::alpn(&protos));
        }
        let ch = ClientHello {
            legacy_version: TLS12,
            random: random_32(),
            session_id: random_32().to_vec(),
            cipher_suites: tls12::client_suites().to_vec(),
            compression_methods: vec![0],
            extensions: exts,
        };
        let ch_bytes = ch.to_handshake().encode();
        write_plain_handshake(s, &ch_bytes)?;
        let mut phr = PlainHsReader::new();
        let sh_msg = phr.next(s)?;
        let sh = ServerHello::from_handshake(&sh_msg)?;
        client_handshake_tls12(s, cfg, ch, ch_bytes, sh, sh_msg, phr)
    }

    #[test]
    /** @brief 실제 소켓 위에서 1.2 핸드셰이크가 끝나는지. */
    fn full_tls12_handshake_over_tcp() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let server_cfg = ServerConfig::from_pkcs8(
            ck.cert.der().as_ref().to_vec(),
            &ck.key_pair.serialize_der(),
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();

            let mut conn = server_handshake(&mut s, &server_cfg).expect("서버 1.2 핸드셰이크");
            assert_eq!(conn.version(), TLS12);
            let req = conn.read_app(&mut s).expect("요청");
            assert_eq!(req, b"tls12-ping");
            conn.write_app(&mut s, b"tls12-pong").unwrap();
        });

        let mut c = TcpStream::connect(addr).unwrap();
        let cfg = insecure_test_client("localhost");
        let mut conn = client_handshake_force_tls12(&mut c, &cfg).expect("클라 1.2 핸드셰이크");
        assert_eq!(conn.version(), TLS12);
        conn.write_app(&mut c, b"tls12-ping").unwrap();
        assert_eq!(conn.read_app(&mut c).unwrap(), b"tls12-pong");
        server.join().unwrap();
    }

    #[test]
    /** @brief 1.2에서도 체인 검증과 프로토콜 협상이 되는지. */
    fn tls12_chain_verification_and_alpn() {
        use crate::trust::TrustStore;
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_der = ca_cert.der().to_vec();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(vec!["dns.example".to_string()]).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
        let leaf_der = leaf_cert.der().to_vec();
        let leaf_key_der = leaf_key.serialize_der();

        let (scheme, sign) = signer_from_pkcs8_der(&leaf_key_der).unwrap();
        let server_cfg = ServerConfig {
            cert_chain: vec![leaf_der],
            sign_scheme: scheme,
            sign,
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            client_ca: None,
            resumption: None,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut conn = server_handshake(&mut s, &server_cfg).expect("서버 1.2");
            let req = conn.read_app(&mut s).unwrap();
            conn.write_app(&mut s, &req).unwrap();
        });
        let mut c = TcpStream::connect(addr).unwrap();
        let cfg = ClientConfig {
            server_name: "dns.example".into(),
            verify_name: true,
            roots: Some(TrustStore::from_ders([ca_der.as_slice()])),
            alpn: vec![b"h2".to_vec()],
            ..Default::default()
        };
        let mut conn = client_handshake_force_tls12(&mut c, &cfg).expect("체인 검증 1.2");
        assert_eq!(conn.version(), TLS12);

        assert_eq!(conn.alpn(), Some(b"h2".as_slice()));
        conn.write_app(&mut c, b"hi-1.2").unwrap();
        assert_eq!(conn.read_app(&mut c).unwrap(), b"hi-1.2");
        server.join().unwrap();
    }

    #[test]
    /** @brief 1.2에서도 이름이 다르면 거부하는지. */
    fn tls12_wrong_hostname_rejected() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let server_cfg = ServerConfig::from_pkcs8(
            ck.cert.der().as_ref().to_vec(),
            &ck.key_pair.serialize_der(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let _ = server_handshake(&mut s, &server_cfg);
            }
        });
        let mut c = TcpStream::connect(addr).unwrap();
        let cfg = ClientConfig {
            server_name: "evil.example".into(),
            verify_name: true,
            ..Default::default()
        };

        assert!(matches!(
            client_handshake_force_tls12(&mut c, &cfg),
            Err(TlsError::BadCert)
        ));
        drop(c);
        let _ = server.join();
    }

    #[test]
    /** @brief 보통 클라이언트가 여전히 1.3을 먼저 시도하는지. */
    fn normal_client_still_prefers_tls13() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let server_cfg = ServerConfig::from_pkcs8(
            ck.cert.der().as_ref().to_vec(),
            &ck.key_pair.serialize_der(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut conn = server_handshake(&mut s, &server_cfg).unwrap();
            assert_eq!(conn.version(), TLS13);
            let req = conn.read_app(&mut s).unwrap();
            conn.write_app(&mut s, &req).unwrap();
        });
        let mut c = TcpStream::connect(addr).unwrap();
        let cfg = insecure_test_client("localhost");
        let mut conn = client_handshake(&mut c, &cfg).unwrap();
        assert_eq!(conn.version(), TLS13);
        conn.write_app(&mut c, b"x").unwrap();
        assert_eq!(conn.read_app(&mut c).unwrap(), b"x");
        server.join().unwrap();
    }
}
