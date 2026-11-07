//! Blocking TLS over a socket, for DoT and DoH over TCP. Tries TLS 1.3 first and falls back to
//! 1.2. Separate from the sans-IO engine: the two share wire primitives but keep their own state
//! machines.

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
use crate::wire::{Reader, Writer};
use crate::x509::X509;
use crate::TlsError;

/// Consecutive records that carry nothing upward: empty application data, compatibility
/// ChangeCipherSpec, user_canceled. A peer can send them for free, so without a cap a read never
/// ends.
const MAX_CONSECUTIVE_IGNORED_RECORDS: usize = 32;

const MAX_TLS13_KEY_UPDATES: u64 = (1u64 << 48) - 1;

const ALERT_LEVEL_FATAL: u8 = 2;

const ALERT_LEVEL_WARNING: u8 = 1;

const ALERT_CLOSE_NOTIFY: u8 = 0;

const ALERT_USER_CANCELED: u8 = 90;

/// RFC 8446 requires a 1.3-capable server negotiating 1.2 to put this at the end of server
/// random, so a 1.3 client can detect a downgrade.
const DOWNGRADE_TLS12: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01];

const DOWNGRADE_TLS11: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00];

/// Keeps close_notify apart from errors. A warning-level user_canceled is not an error: RFC 8446
/// counts it as a closure alert and the sender follows it with close_notify, which is read next. A
/// fatal alert in 1.2 ends the connection at once (RFC 5246). `None` when the record holds only a
/// warning-level user_canceled; the caller reads the next record.
fn alert_error(payload: &[u8]) -> Option<TlsError> {
    if payload.len() < 2 || payload.len() % 2 != 0 {
        return Some(TlsError::Decode);
    }
    let mut close_notify = false;
    for alert in payload.chunks_exact(2) {
        match (alert[0], alert[1]) {
            (_, ALERT_CLOSE_NOTIFY) => close_notify = true,
            (ALERT_LEVEL_WARNING, ALERT_USER_CANCELED) => {}
            (level, description) => return Some(TlsError::PeerAlert { level, description }),
        }
    }
    close_notify.then_some(TlsError::CloseNotify)
}

/// TLS 1.3 puts exactly one alert per record and ignores the level, so user_canceled is a closure
/// alert at any level. An empty record is not an alert, and a wrong length means the alert could
/// not be read. Returns as `alert_error` does.
fn tls13_alert_error(payload: &[u8]) -> Option<TlsError> {
    match payload {
        [] => Some(TlsError::UnexpectedMessage),
        [_, ALERT_USER_CANCELED] => None,
        [_, _] => alert_error(payload),
        _ => Some(TlsError::Decode),
    }
}

enum RecordLayer {
    Tls13(RecordCrypto),
    Tls12(Tls12RecordCrypto),
}

impl RecordLayer {
    fn encrypt(&mut self, ct: ContentType, pt: &[u8]) -> Result<TlsRecord, TlsError> {
        match self {
            RecordLayer::Tls13(c) => c.encrypt(ct, pt),
            RecordLayer::Tls12(c) => c.encrypt(ct, pt),
        }
    }

    /// Sending may fail; the connection has already failed and the caller returns the original
    /// error.
    fn send_fatal_alert<S: Write>(&mut self, s: &mut S, description: u8) {
        if let Ok(record) = self.encrypt(ContentType::Alert, &[ALERT_LEVEL_FATAL, description]) {
            let _ = write_record(s, &record);
        }
    }

    /// The decrypting side checks the plaintext limit. A changed record version is `Decrypt`: the
    /// version is AEAD additional data, so it fails authentication.
    fn decrypt(&mut self, rec: &TlsRecord) -> Result<(ContentType, Vec<u8>), TlsError> {
        if rec.version != crate::record::LEGACY_VERSION {
            return Err(TlsError::Decrypt);
        }
        match self {
            RecordLayer::Tls13(c) => c.decrypt(rec),
            RecordLayer::Tls12(c) => Ok((rec.content_type, c.decrypt(rec)?)),
        }
    }
}

/// The write protection during the handshake. Handshake messages and fatal alerts both go
/// through it, as RFC 8446 sends alerts under the current write protection; since it alone holds
/// the write key and sequence number, an alert at a failure never reuses a nonce.
enum HandshakeWrite {
    /// Nothing sent yet; a failure here sends no alert.
    Silent,
    Plain,
    Protected(RecordLayer),
}

impl HandshakeWrite {
    /// On failure, reports the reason under the current write protection.
    fn run<S: Write>(
        mut self,
        s: &mut S,
        handshake: impl FnOnce(&mut S, &mut HandshakeWrite) -> Result<TlsConnection, TlsError>,
    ) -> Result<TlsConnection, TlsError> {
        let result = handshake(s, &mut self);
        if let Err(error) = &result {
            self.send_alert(s, error);
        }
        result
    }

    /// Fragments to the record limit.
    fn send<S: Write>(&mut self, s: &mut S, encoded: &[u8]) -> Result<(), TlsError> {
        match self {
            HandshakeWrite::Protected(layer) => {
                for chunk in encoded.chunks(MAX_FRAGMENT) {
                    let record = layer.encrypt(ContentType::Handshake, chunk)?;
                    write_record(s, &record)?;
                }
                Ok(())
            }
            HandshakeWrite::Silent | HandshakeWrite::Plain => {
                *self = HandshakeWrite::Plain;
                write_plain_handshake(s, encoded)
            }
        }
    }

    fn protect(&mut self, layer: RecordLayer) {
        *self = HandshakeWrite::Protected(layer);
    }

    fn take_layer(&mut self) -> Result<RecordLayer, TlsError> {
        match std::mem::replace(self, HandshakeWrite::Silent) {
            HandshakeWrite::Protected(layer) => Ok(layer),
            _ => Err(TlsError::Internal),
        }
    }

    fn send_alert<S: Write>(&mut self, s: &mut S, error: &TlsError) {
        let Some(description) = error.alert() else {
            return;
        };
        match self {
            HandshakeWrite::Silent => {}
            HandshakeWrite::Plain => {
                let alert = vec![ALERT_LEVEL_FATAL, description];
                let _ = write_record(s, &TlsRecord::new(ContentType::Alert, alert));
            }
            HandshakeWrite::Protected(layer) => layer.send_fatal_alert(s, description),
        }
    }
}

#[derive(Clone)]
pub struct ServerConfig {
    pub cert_chain: Vec<Vec<u8>>,
    pub sign_scheme: u16,
    /// Signs without holding the key directly.
    pub sign: Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>,

    pub alpn: Vec<Vec<u8>>,

    /// Client certificates are required only when set.
    pub client_ca: Option<crate::trust::TrustStore>,

    /// Without it every connection does a full handshake.
    pub resumption: Option<ServerResumption>,
}

#[derive(Clone)]
pub struct ServerResumption {
    pub ticketer: Arc<crate::session::Ticketer>,

    pub lifetime_secs: u32,

    /// 0 refuses early data.
    pub max_early_data: u32,
}

impl ServerResumption {
    /// Keep `max_early_data` at 0. This crate has no anti-replay: no single-use tickets, no
    /// ClientHello recording, no freshness window, and RFC 8446 requires one of them before a
    /// server accepts 0-RTT. 0-RTT data also lacks forward secrecy.
    pub fn secure_default() -> Self {
        ServerResumption {
            ticketer: Arc::new(crate::session::Ticketer::new()),
            lifetime_secs: 7200,

            max_early_data: 0,
        }
    }
}

impl ServerConfig {
    pub fn from_pkcs8(cert_der: Vec<u8>, key_pkcs8_der: &[u8]) -> Option<Self> {
        Self::from_chain_pkcs8(vec![cert_der], key_pkcs8_der)
    }

    pub fn from_chain_pkcs8(cert_chain: Vec<Vec<u8>>, key_pkcs8_der: &[u8]) -> Option<Self> {
        if !certificate_chain_is_valid(&cert_chain, false) {
            return None;
        }
        let (sign_scheme, sign) = signer_from_pkcs8_der(key_pkcs8_der)?;

        use p256::elliptic_curve::sec1::ToSec1Point;
        use p256::pkcs8::DecodePrivateKey;
        let secret = p256::SecretKey::from_pkcs8_der(key_pkcs8_der).ok()?;
        let leaf = X509::parse(&cert_chain[0]).ok()?;
        if leaf.public_key != secret.public_key().to_sec1_point(false).as_bytes() {
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

    pub fn with_alpn(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn = protocols;
        self
    }

    pub fn with_client_ca(mut self, store: crate::trust::TrustStore) -> Self {
        self.client_ca = Some(store);
        self
    }

    pub fn with_resumption(mut self, r: ServerResumption) -> Self {
        self.resumption = Some(r);
        self
    }
}

#[derive(Clone)]
pub struct ClientCert {
    pub chain: Vec<Vec<u8>>,
    pub sign_scheme: u16,
    pub sign: Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>,
}

impl ClientCert {
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

/// Picks the signer from the key type.
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
/// Disables certificate verification. Only for tests and settings that accept the risk
/// explicitly.
pub struct InsecureVerifier(());

impl InsecureVerifier {
    pub fn dangerously_disable_certificate_verification() -> Self {
        Self(())
    }
}

pub struct ClientConfig {
    pub server_name: String,

    pub verify_name: bool,

    pub roots: Option<crate::trust::TrustStore>,

    /// For tests only.
    pub insecure_verifier: Option<InsecureVerifier>,

    pub alpn: Vec<Vec<u8>>,

    pub client_cert: Option<ClientCert>,

    pub session: Option<crate::session::TlsSession>,

    pub enable_early_data: bool,

    pub send_key_share: bool,
}

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

/// Checked before the handshake.
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

pub(crate) fn server_config_wire_is_valid(cfg: &ServerConfig) -> bool {
    certificate_chain_is_valid(&cfg.cert_chain, false)
        && alpn_protocols_are_valid(&cfg.alpn)
        && cfg.resumption.as_ref().is_none_or(|resumption| {
            resumption.lifetime_secs <= crate::session::MAX_TICKET_LIFETIME_SECS
        })
}

impl Default for ClientConfig {
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

impl ClientConfig {
    /// RFC 6066 forbids IP addresses in SNI and wants names without the trailing dot. When
    /// connecting by address no SNI is sent, the certificate is checked by IP SAN, and a
    /// server_name extension in the reply is refused.
    pub(crate) fn sni(&self) -> Option<&str> {
        match crate::x509::peer_host(&self.server_name) {
            crate::x509::PeerHost::Name(name) if !name.is_empty() => Some(name),
            _ => None,
        }
    }
}

/// Short hex for diagnostic logs.
fn short_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().min(32) * 2);
    for &b in bytes.iter().take(32) {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub struct TlsConnection {
    read: RecordLayer,
    write: RecordLayer,

    version: u16,

    alpn: Option<Vec<u8>>,

    client_authenticated: bool,

    client_auth_identity: Option<String>,

    verified_chain: Vec<X509>,

    /// Checks the direction of post-handshake messages.
    is_client: bool,

    /// Post-handshake message fragments spanning records.
    post_handshake: HandshakeReader,

    /// TLS 1.3 per-direction application secrets, needed only for KeyUpdate.
    traffic: Option<Tls13Traffic>,

    resumed: bool,

    /// Derives the PSK of the next ticket the server sends.
    resumption: Option<ClientResumption>,

    /// Sessions received after the handshake and not yet taken.
    new_sessions: Vec<crate::session::TlsSession>,

    /// Set after a fatal alert was sent or received, or a record was only partly written. RFC 8446
    /// allows nothing more on such a connection, and after a partial record the peer cannot parse
    /// anything, so reads, writes and close_notify all fail with this reason.
    failed: Option<TlsError>,
}

struct Tls13Traffic {
    aead: Aead,
    hash: Hash,
    key_len: usize,
    read_secret: Vec<u8>,
    write_secret: Vec<u8>,
    write_updates: u64,
}

impl Drop for Tls13Traffic {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.read_secret.zeroize();
        self.write_secret.zeroize();
    }
}

struct ClientResumption {
    server_name: String,
    hash: Hash,
    suite: u16,
    /// Covers the handshake through the server Finished.
    master: Vec<u8>,
}

impl Drop for ClientResumption {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.master.zeroize();
    }
}

impl TlsConnection {
    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// From the leaf to a root in this side's store; empty for a resumed or unverified connection.
    /// Take the leaf's issuer from here, not from the chain the peer sent.
    pub fn verified_chain(&self) -> &[X509] {
        &self.verified_chain
    }

    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn client_authenticated(&self) -> bool {
        self.client_authenticated
    }

    pub fn client_auth_identity(&self) -> Option<&str> {
        self.client_auth_identity.as_deref()
    }

    pub fn is_resumed(&self) -> bool {
        self.resumed
    }

    pub fn take_sessions(&mut self) -> Vec<crate::session::TlsSession> {
        std::mem::take(&mut self.new_sessions)
    }

    fn update_read_key(&mut self) -> Result<(), TlsError> {
        let traffic = self.traffic.as_mut().ok_or(TlsError::Internal)?;
        let secret = traffic_update(traffic.hash, &traffic.read_secret);
        let (key, iv) = traffic_keys(traffic.hash, &secret, traffic.key_len);
        use zeroize::Zeroize;
        traffic.read_secret.zeroize();
        traffic.read_secret = secret;
        self.read = RecordLayer::Tls13(RecordCrypto::new(traffic.aead, key, iv12(iv)));
        Ok(())
    }

    fn update_write_key(&mut self) -> Result<(), TlsError> {
        let traffic = self.traffic.as_mut().ok_or(TlsError::Internal)?;
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

    fn can_update_write_key(&self) -> bool {
        self.traffic
            .as_ref()
            .is_some_and(|traffic| traffic.write_updates < MAX_TLS13_KEY_UPDATES)
    }

    /// A failed send may have written part of the record; the peer would read the next record as
    /// its rest and fail authentication, so the connection is marked failed.
    fn send_record<S: Write>(&mut self, s: &mut S, record: &TlsRecord) -> Result<(), TlsError> {
        write_record(s, record).inspect_err(|error| self.failed = Some(error.clone()))
    }

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
            RecordLayer::Tls12(_) => return Err(TlsError::Internal),
        };
        self.send_record(s, &record)?;
        self.update_write_key()
    }

    /// Keeps the last record before the AES-GCM and sequence limits for the KeyUpdate.
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

    /// Fragments to the plaintext limit, which the peer enforces.
    pub fn write_app<S: Write>(&mut self, s: &mut S, data: &[u8]) -> Result<(), TlsError> {
        const APP_CHUNK: usize = MAX_FRAGMENT;
        if let Some(error) = &self.failed {
            return Err(error.clone());
        }
        if data.is_empty() {
            self.ensure_write_key_capacity(s)?;
            let rec = self.write.encrypt(ContentType::ApplicationData, data)?;
            return self.send_record(s, &rec);
        }
        for chunk in data.chunks(APP_CHUNK) {
            self.ensure_write_key_capacity(s)?;
            let rec = self.write.encrypt(ContentType::ApplicationData, chunk)?;
            self.send_record(s, &rec)?;
        }
        Ok(())
    }

    /// RFC 8446 requires close_notify before closing the write side; otherwise the peer cannot tell
    /// the end from a truncation.
    pub fn send_close_notify<S: Write>(&mut self, s: &mut S) -> Result<(), TlsError> {
        const CLOSE_NOTIFY: [u8; 2] = [1, 0];
        if let Some(error) = &self.failed {
            return Err(error.clone());
        }
        let rec = self.write.encrypt(ContentType::Alert, &CLOSE_NOTIFY)?;
        self.send_record(s, &rec)
    }

    /// For policy outside TLS verification, such as revocation. Sends certificate_unknown as a
    /// rejection inside the handshake would; closing TCP alone looks like a truncation to the peer.
    /// Later reads and writes fail with this reason.
    pub fn reject_peer_certificate<S: Write>(&mut self, s: &mut S) {
        if self.failed.is_some() {
            return;
        }
        let error = TlsError::CertificateUnknown;
        if let Some(description) = error.alert() {
            self.write.send_fatal_alert(s, description);
        }
        self.failed = Some(error);
    }

    /// Also handles post-handshake messages. A failure caused by a received record sends a fatal
    /// alert and marks the connection failed; a fatal alert from the peer marks it failed without a
    /// reply.
    pub fn read_app<S: Read + Write>(&mut self, s: &mut S) -> Result<Vec<u8>, TlsError> {
        if let Some(error) = &self.failed {
            return Err(error.clone());
        }
        let result = self.read_application_data(s);
        if let Err(error) = &result {
            if let Some(description) = error.alert() {
                self.write.send_fatal_alert(s, description);
                self.failed = Some(error.clone());
            } else if matches!(error, TlsError::PeerAlert { .. }) {
                self.failed = Some(error.clone());
            }
        }
        result
    }

    fn read_application_data<S: Read + Write>(&mut self, s: &mut S) -> Result<Vec<u8>, TlsError> {
        let mut ignored_records = 0usize;
        let mut post_handshake_messages = 0usize;
        let mut answered_key_update = false;
        loop {
            let rec = read_record(s)?;
            if rec.content_type == ContentType::ChangeCipherSpec {
                return Err(TlsError::UnexpectedMessage);
            }
            let (ct, pt) = self.read.decrypt(&rec)?;
            match ct {
                ContentType::ApplicationData if pt.is_empty() => {
                    ignored_records += 1;
                    if ignored_records > MAX_CONSECUTIVE_IGNORED_RECORDS
                        || self.post_handshake.has_pending()
                    {
                        return Err(TlsError::UnexpectedMessage);
                    }
                }
                ContentType::ApplicationData => {
                    if self.post_handshake.has_pending() {
                        return Err(TlsError::UnexpectedMessage);
                    }
                    return Ok(pt);
                }
                ContentType::Handshake if pt.is_empty() => return Err(TlsError::UnexpectedMessage),
                ContentType::Handshake => {
                    ignored_records += 1;
                    if ignored_records > MAX_CONSECUTIVE_IGNORED_RECORDS || self.version != TLS13 {
                        return Err(TlsError::UnexpectedMessage);
                    }
                    let had_pending = self.post_handshake.has_pending();
                    self.post_handshake.feed(&pt);
                    while let Some(msg) = self.post_handshake.next_message()? {
                        post_handshake_messages += 1;
                        if post_handshake_messages > MAX_CONSECUTIVE_IGNORED_RECORDS {
                            return Err(TlsError::UnexpectedMessage);
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
                            HandshakeType::KeyUpdate => {
                                if msg.body.len() != 1 {
                                    return Err(TlsError::Decode);
                                }
                                if msg.body[0] > 1 {
                                    return Err(TlsError::IllegalParameter);
                                }
                                if had_pending || pt.len() != 5 {
                                    return Err(TlsError::UnexpectedMessage);
                                }
                                self.update_read_key()?;
                                if msg.body[0] == 1
                                    && !answered_key_update
                                    && self.can_update_write_key()
                                {
                                    self.send_key_update(s, false)?;
                                    answered_key_update = true;
                                }
                            }
                            _ => return Err(TlsError::UnexpectedMessage),
                        }
                    }
                }
                ContentType::Alert => {
                    let error = if self.version == TLS13 {
                        tls13_alert_error(&pt)
                    } else {
                        alert_error(&pt)
                    };
                    if let Some(error) = error {
                        return Err(error);
                    }
                    ignored_records += 1;
                    if ignored_records > MAX_CONSECUTIVE_IGNORED_RECORDS
                        || self.post_handshake.has_pending()
                    {
                        return Err(TlsError::UnexpectedMessage);
                    }
                }
                _ => return Err(TlsError::UnexpectedMessage),
            }
        }
    }
}

pub struct TlsStream<S> {
    conn: TlsConnection,
    inner: S,
    /// Read position in `rbuf`.
    rbuf: Vec<u8>,
    rpos: usize,
}

impl<S: Read + Write> TlsStream<S> {
    pub fn new(conn: TlsConnection, inner: S) -> Self {
        TlsStream {
            conn,
            inner,
            rbuf: Vec::new(),
            rpos: 0,
        }
    }

    pub fn alpn(&self) -> Option<&[u8]> {
        self.conn.alpn()
    }

    pub fn client_authenticated(&self) -> bool {
        self.conn.client_authenticated()
    }

    pub fn client_auth_identity(&self) -> Option<&str> {
        self.conn.client_auth_identity()
    }

    pub fn verified_chain(&self) -> &[X509] {
        self.conn.verified_chain()
    }

    pub fn is_resumed(&self) -> bool {
        self.conn.is_resumed()
    }

    pub fn take_sessions(&mut self) -> Vec<crate::session::TlsSession> {
        self.conn.take_sessions()
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: Read + Write> Read for TlsStream<S> {
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
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        self.conn
            .write_app(&mut self.inner, data)
            .map_err(|_| std::io::Error::other("Could not write TLS data"))?;
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// `Eof` when the connection closes before the first byte.
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

/// `Internal` when the record exceeds the limit: this side built it, so record_overflow is not
/// the peer's to hear.
fn write_record<S: Write>(s: &mut S, rec: &TlsRecord) -> Result<(), TlsError> {
    if rec.fragment.len() > MAX_CIPHERTEXT {
        return Err(TlsError::Internal);
    }
    s.write_all(&rec.encode()).map_err(|_| TlsError::Io)
}

fn write_plain_handshake<S: Write>(s: &mut S, encoded: &[u8]) -> Result<(), TlsError> {
    for chunk in encoded.chunks(MAX_FRAGMENT) {
        write_record(s, &TlsRecord::new(ContentType::Handshake, chunk.to_vec()))?;
    }
    Ok(())
}

/// Past the cap of consecutive ignored records, unexpected_message.
fn skip_ignored_record(ignored: &mut usize) -> Result<(), TlsError> {
    *ignored += 1;
    if *ignored > MAX_CONSECUTIVE_IGNORED_RECORDS {
        return Err(TlsError::UnexpectedMessage);
    }
    Ok(())
}

/// Enforces the plaintext record rules: at most 2^14 bytes, no empty handshake record.
/// Compatibility ChangeCipherSpec is allowed only after the first ClientHello (RFC 8446), so only
/// readers created after it drop one; TLS 1.2 never allows it here.
struct PlainHsReader {
    hr: HandshakeReader,
    /// When false, a ChangeCipherSpec is unexpected_message.
    drop_ccs: bool,
    ignored: usize,
}

impl PlainHsReader {
    fn new(drop_ccs: bool) -> Self {
        Self {
            hr: HandshakeReader::new(),
            drop_ccs,
            ignored: 0,
        }
    }

    fn next<S: Read>(&mut self, s: &mut S) -> Result<HandshakeMsg, TlsError> {
        loop {
            if let Some(m) = self.hr.next_message()? {
                return Ok(m);
            }
            let rec = read_record(s)?;
            if rec.fragment.len() > MAX_FRAGMENT {
                return Err(TlsError::RecordOverflow);
            }
            match rec.content_type {
                ContentType::Handshake if rec.fragment.is_empty() => {
                    return Err(TlsError::UnexpectedMessage)
                }
                ContentType::Handshake => {
                    self.ignored = 0;
                    self.hr.feed(&rec.fragment);
                }
                ContentType::ChangeCipherSpec if self.drop_ccs && valid_ccs_record(&rec) => {
                    skip_ignored_record(&mut self.ignored)?
                }
                ContentType::Alert => match alert_error(&rec.fragment) {
                    Some(error) => return Err(error),
                    None => skip_ignored_record(&mut self.ignored)?,
                },
                _ => return Err(TlsError::UnexpectedMessage),
            }
        }
    }

    /// Reads the last message before a key change. Leftover bytes are unexpected_message: RFC 8446
    /// forbids a handshake message spanning a key change, and those bytes are unreadable under the
    /// new key.
    fn next_at_boundary<S: Read>(&mut self, s: &mut S) -> Result<HandshakeMsg, TlsError> {
        let message = self.next(s)?;
        self.ensure_boundary()?;
        Ok(message)
    }

    fn ensure_boundary(&self) -> Result<(), TlsError> {
        if self.hr.has_pending() {
            return Err(TlsError::UnexpectedMessage);
        }
        Ok(())
    }
}

struct EncReader {
    hr: HandshakeReader,
    ignored: usize,
}

impl EncReader {
    fn new() -> Self {
        Self {
            hr: HandshakeReader::new(),
            ignored: 0,
        }
    }

    /// Accepts plaintext alerts too: a peer failing on this side's ServerHello has no handshake
    /// keys yet. A compatibility ChangeCipherSpec may come any time before the peer's Finished.
    fn next<S: Read>(&mut self, s: &mut S, c: &mut RecordCrypto) -> Result<HandshakeMsg, TlsError> {
        loop {
            if let Some(m) = self.hr.next_message()? {
                return Ok(m);
            }
            let rec = read_record(s)?;
            match rec.content_type {
                ContentType::ChangeCipherSpec if valid_ccs_record(&rec) => {
                    skip_ignored_record(&mut self.ignored)?;
                    continue;
                }
                ContentType::ChangeCipherSpec => return Err(TlsError::UnexpectedMessage),
                ContentType::Alert if rec.fragment.len() > MAX_FRAGMENT => {
                    return Err(TlsError::RecordOverflow)
                }
                ContentType::Alert => match alert_error(&rec.fragment) {
                    Some(error) => return Err(error),
                    None => {
                        skip_ignored_record(&mut self.ignored)?;
                        continue;
                    }
                },
                _ => {}
            }
            let (ct, pt) = c.decrypt(&rec)?;
            match ct {
                ContentType::Handshake if pt.is_empty() => return Err(TlsError::UnexpectedMessage),
                ContentType::Handshake => {
                    self.ignored = 0;
                    self.hr.feed(&pt);
                }
                ContentType::Alert => match tls13_alert_error(&pt) {
                    Some(error) => return Err(error),
                    None => skip_ignored_record(&mut self.ignored)?,
                },
                _ => return Err(TlsError::UnexpectedMessage),
            }
        }
    }

    /// Leftover bytes after the message are unexpected_message.
    fn next_at_boundary<S: Read>(
        &mut self,
        s: &mut S,
        c: &mut RecordCrypto,
    ) -> Result<HandshakeMsg, TlsError> {
        let message = self.next(s, c)?;
        if self.hr.has_pending() {
            return Err(TlsError::UnexpectedMessage);
        }
        Ok(message)
    }
}

fn iv12(v: Vec<u8>) -> [u8; 12] {
    let mut a = [0u8; 12];
    a.copy_from_slice(&v[..12]);
    a
}

fn choose_suite(offered: &[u16]) -> Option<u16> {
    [
        TLS_AES_128_GCM_SHA256,
        TLS_CHACHA20_POLY1305_SHA256,
        TLS_AES_256_GCM_SHA384,
    ]
    .into_iter()
    .find(|&s| offered.contains(&s))
}

pub(crate) fn new_key_exchange(group: u16) -> Result<KeyExchange, TlsError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    fill_random(&mut *seed);
    KeyExchange::from_seed(group, &*seed).ok_or(TlsError::Internal)
}

/// A session the blocking client can offer now.
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

/// Replaces the PSK binder placeholder with the real value.
fn encode_client_hello(
    hello: &ClientHello,
    session: Option<&crate::session::TlsSession>,
    binder_prefix: &[u8],
) -> Result<Vec<u8>, TlsError> {
    let mut wire = hello.to_handshake().encode();
    let Some(session) = session else {
        return Ok(wire);
    };
    let (hash, _) = suite_params(session.suite).ok_or(TlsError::Internal)?;
    let binders_len = 2 + 1 + hash.len();
    if wire.len() <= binders_len {
        return Err(TlsError::Internal);
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

/// `hash` belongs to the chosen suite; RFC 8446 allows a PSK with any suite of the same hash,
/// not only the ticket's.
fn accept_client_psk(
    cfg: &ServerConfig,
    hello: &ClientHello,
    message: &HandshakeMsg,
    hash: Hash,
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
        || state.hash() != Some(hash)
    {
        return Ok(None);
    }

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

/// In preference order. RFC 8446 makes secp256r1 mandatory.
const SERVER_TLS13_GROUPS: [u16; 2] = [X25519, SECP256R1];

#[derive(Debug, PartialEq)]
pub(crate) enum ServerKeyShare {
    Offered { group: u16, public: Vec<u8> },
    Retry(u16),
}

/// Shared by the TCP server and the QUIC engine. Picks the client's key share in this side's
/// preference order, else asks for a retry with a supported group the client lists.
/// `HandshakeFailure` when there is no common group.
pub(crate) fn choose_server_key_share(ch: &ClientHello) -> Result<ServerKeyShare, TlsError> {
    let shares = ch
        .ext(EXT_KEY_SHARE)
        .and_then(Extension::as_key_share_client)
        .unwrap_or_default();
    for group in SERVER_TLS13_GROUPS {
        if let Some((_, public)) = shares.iter().find(|(offered, _)| *offered == group) {
            return Ok(ServerKeyShare::Offered {
                group,
                public: public.clone(),
            });
        }
    }
    let supported = ch
        .ext(EXT_SUPPORTED_GROUPS)
        .and_then(Extension::as_supported_groups)
        .unwrap_or_default();
    SERVER_TLS13_GROUPS
        .into_iter()
        .find(|group| supported.contains(group))
        .map(ServerKeyShare::Retry)
        .ok_or(TlsError::HandshakeFailure)
}

/// RFC 8446 requires the retried hello to carry exactly one share, for the requested group;
/// otherwise `IllegalParameter`. The public value is checked during key agreement.
pub(crate) fn retry_key_share(ch: &ClientHello, group: u16) -> Result<Vec<u8>, TlsError> {
    let shares = ch
        .ext(EXT_KEY_SHARE)
        .ok_or(TlsError::MissingExtension)?
        .as_key_share_client()
        .ok_or(TlsError::Decode)?;
    match shares.as_slice() {
        [(offered, public)] if *offered == group => Ok(public.clone()),
        _ => Err(TlsError::IllegalParameter),
    }
}

/// An alert in its place is the peer's failure.
fn expect_ccs<S: Read>(s: &mut S) -> Result<(), TlsError> {
    let mut ignored = 0;
    loop {
        let rec = read_record(s)?;
        if rec.fragment.len() > MAX_FRAGMENT {
            return Err(TlsError::RecordOverflow);
        }
        if valid_ccs_record(&rec) {
            return Ok(());
        }
        if rec.content_type != ContentType::Alert {
            return Err(TlsError::UnexpectedMessage);
        }
        match alert_error(&rec.fragment) {
            Some(error) => return Err(error),
            None => skip_ignored_record(&mut ignored)?,
        }
    }
}

/// The peer has switched keys, so every record here is protected, alerts included.
fn read_tls12_finished<S: Read>(
    s: &mut S,
    read_c: &mut Tls12RecordCrypto,
) -> Result<HandshakeMsg, TlsError> {
    let mut ignored = 0;
    loop {
        let record = read_record(s)?;
        if record.version != crate::record::LEGACY_VERSION {
            return Err(TlsError::Decrypt);
        }
        match record.content_type {
            ContentType::Handshake => return parse_exact_handshake(&read_c.decrypt(&record)?),
            ContentType::Alert => match alert_error(&read_c.decrypt(&record)?) {
                Some(error) => return Err(error),
                None => skip_ignored_record(&mut ignored)?,
            },
            _ => return Err(TlsError::UnexpectedMessage),
        }
    }
}

/// Accepting arbitrary bytes would open a path through.
fn valid_ccs_record(record: &TlsRecord) -> bool {
    record.content_type == ContentType::ChangeCipherSpec
        && record.version == crate::record::LEGACY_VERSION
        && record.fragment == [1]
}

/// `Decode` when incomplete. Leftover bytes are `UnexpectedMessage`: at a key change the message
/// must end at the record boundary.
fn parse_exact_handshake(bytes: &[u8]) -> Result<HandshakeMsg, TlsError> {
    let (message, used) = HandshakeMsg::parse(bytes)?.ok_or(TlsError::Decode)?;
    if used != bytes.len() {
        return Err(TlsError::UnexpectedMessage);
    }
    Ok(message)
}

fn ccs_record() -> TlsRecord {
    TlsRecord::new(ContentType::ChangeCipherSpec, vec![1])
}

fn scheme_is_ecdsa(scheme: u16) -> bool {
    scheme == ECDSA_SECP256R1_SHA256 || scheme == ECDSA_SECP384R1_SHA384
}

/// The compression list need only contain null, which RFC 5246 requires and the server picks.
/// Renegotiation info on a first connection may come as an empty extension or the SCSV (RFC 5746).
/// A point format list without uncompressed is refused, as RFC 8422 requires. Without extended
/// master secret or renegotiation info nothing here is acceptable. The client must offer a scheme
/// this side's certificate can sign with.
fn validate_tls12_client_hello(ch: &ClientHello, sign_scheme: u16) -> Result<(), TlsError> {
    if !ch.compression_methods.contains(&0) {
        return Err(TlsError::IllegalParameter);
    }
    let secure_renegotiation = match ch.ext(tls12::EXT_RENEGOTIATION_INFO) {
        Some(extension) => {
            let mut reader = Reader::new(&extension.data);
            let renegotiated_connection = reader.vec8()?;
            if !reader.is_empty() {
                return Err(TlsError::Decode);
            }
            if !renegotiated_connection.is_empty() {
                return Err(TlsError::HandshakeFailure);
            }
            true
        }
        None => ch
            .cipher_suites
            .contains(&tls12::TLS_EMPTY_RENEGOTIATION_INFO_SCSV),
    };
    if !secure_renegotiation
        || !ch
            .ext(tls12::EXT_EXTENDED_MASTER_SECRET)
            .is_some_and(|extension| extension.data.is_empty())
    {
        return Err(TlsError::HandshakeFailure);
    }
    if ch
        .ext(tls12::EXT_EC_POINT_FORMATS)
        .and_then(Extension::as_ec_point_formats)
        .is_some_and(|formats| !formats.contains(&tls12::EC_POINT_FORMAT_UNCOMPRESSED))
    {
        return Err(TlsError::IllegalParameter);
    }
    if !ch.offers_signature_scheme(sign_scheme) {
        return Err(TlsError::HandshakeFailure);
    }
    Ok(())
}

/// A server may confirm the sent name with an empty server_name extension (RFC 6066), as many
/// load balancers do. A point format list is fine if it contains uncompressed. An offered extension
/// that cannot appear in a 1.2 ServerHello is `IllegalParameter`. Accepting a suite or extension
/// this side did not offer would allow a downgrade. Returns the server's ALPN choice.
fn validate_tls12_server_hello(
    cfg: &ClientConfig,
    ch: &ClientHello,
    sh: &ServerHello,
) -> Result<Option<Vec<u8>>, TlsError> {
    if sh.legacy_version != TLS12 {
        return Err(TlsError::ProtocolVersion);
    }
    if !ch.cipher_suites.contains(&sh.cipher_suite)
        || !tls12::client_suites().contains(&sh.cipher_suite)
    {
        return Err(TlsError::IllegalParameter);
    }
    for extension in &sh.extensions {
        if ch.ext(extension.ext_type).is_none() {
            return Err(TlsError::UnsupportedExtension);
        }
        match extension.ext_type {
            tls12::EXT_EXTENDED_MASTER_SECRET | EXT_SERVER_NAME => {
                if !extension.data.is_empty() {
                    return Err(TlsError::Decode);
                }
            }
            tls12::EXT_RENEGOTIATION_INFO => {
                let mut reader = Reader::new(&extension.data);
                let renegotiated_connection = reader.vec8()?;
                if !reader.is_empty() {
                    return Err(TlsError::Decode);
                }
                if !renegotiated_connection.is_empty() {
                    return Err(TlsError::HandshakeFailure);
                }
            }
            tls12::EXT_EC_POINT_FORMATS => {
                let formats = extension.as_ec_point_formats().ok_or(TlsError::Decode)?;
                if !formats.contains(&tls12::EC_POINT_FORMAT_UNCOMPRESSED) {
                    return Err(TlsError::IllegalParameter);
                }
            }
            EXT_ALPN => {}
            _ => return Err(TlsError::IllegalParameter),
        }
    }
    if sh.ext(tls12::EXT_EXTENDED_MASTER_SECRET).is_none()
        || sh.ext(tls12::EXT_RENEGOTIATION_INFO).is_none()
    {
        return Err(TlsError::HandshakeFailure);
    }
    sh.ext(EXT_ALPN)
        .map(|extension| extension.selected_alpn(&cfg.alpn))
        .transpose()
}

/// A failure sends a fatal alert under the current write protection. A retry is requested only
/// when the retried hello can finish the handshake; since it cannot change the supported groups, a
/// hello without X25519 is refused at once. In 1.3 the handshake proceeds with this side's chain
/// even if the client did not list its scheme, as RFC 8446 suggests; the client decides.
/// `Internal` when the configuration does not fit the wire, and then nothing is sent.
pub fn server_handshake<S: Read + Write>(
    s: &mut S,
    cfg: &ServerConfig,
) -> Result<TlsConnection, TlsError> {
    if !server_config_wire_is_valid(cfg) {
        return Err(TlsError::Internal);
    }
    HandshakeWrite::Plain.run(s, |s, w| run_server_handshake(s, cfg, w))
}

/// Everything sent goes through `w`.
fn run_server_handshake<S: Read + Write>(
    s: &mut S,
    cfg: &ServerConfig,
    w: &mut HandshakeWrite,
) -> Result<TlsConnection, TlsError> {
    let mut ch_msg = PlainHsReader::new(false).next_at_boundary(s)?;
    let mut ch = ClientHello::from_handshake(&ch_msg)?;

    let offers_13 = ch.offers_version(TLS13)?;
    if offers_13 {
        ch.validate_tls13()?;
        if ch.ext(EXT_COOKIE).is_some() {
            return Err(TlsError::IllegalParameter);
        }
    }
    if !(offers_13 && choose_suite(&ch.cipher_suites).is_some()) {
        if cfg.client_ca.is_some() || !ch.offers_version(TLS12)? {
            return Err(if offers_13 {
                TlsError::HandshakeFailure
            } else {
                TlsError::ProtocolVersion
            });
        }
        return server_handshake_tls12(s, cfg, ch_msg, ch, w);
    }
    let negotiated_alpn = ch.select_alpn(&cfg.alpn)?;

    let suite = choose_suite(&ch.cipher_suites).ok_or(TlsError::Internal)?;
    let (hash, key_len) = suite_params(suite).ok_or(TlsError::Internal)?;
    let aead = aead_for_suite(suite).ok_or(TlsError::Internal)?;

    let mut transcript = Transcript::new(hash);
    let mut psk_binder_prefix = Vec::new();
    let (group, client_pub) = match choose_server_key_share(&ch)? {
        ServerKeyShare::Offered { group, public } => {
            transcript.update(&ch_msg.encode());
            (group, public)
        }
        ServerKeyShare::Retry(group) => {
            let first_ch = ch.clone();
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
                    Extension::key_share_hrr(group),
                    Extension::cookie(&cookie),
                ],
            };
            let hrr_msg = hrr.to_handshake();
            w.send(s, &hrr_msg.encode())?;
            transcript.update(&hrr_msg.encode());

            ch_msg = PlainHsReader::new(true).next_at_boundary(s)?;
            ch = ClientHello::from_handshake(&ch_msg)?;
            ch.validate_tls13()?;
            if !ch.is_valid_retry_of(&first_ch) {
                return Err(TlsError::IllegalParameter);
            }
            let echoed = ch
                .ext(EXT_COOKIE)
                .ok_or(TlsError::MissingExtension)?
                .as_cookie()
                .ok_or(TlsError::Decode)?;
            if echoed != cookie {
                return Err(TlsError::IllegalParameter);
            }
            let public = retry_key_share(&ch, group)?;
            psk_binder_prefix.extend_from_slice(transcript.as_bytes());
            transcript.update(&ch_msg.encode());
            (group, public)
        }
    };

    let psk = accept_client_psk(
        cfg,
        &ch,
        &ch_msg,
        hash,
        &negotiated_alpn,
        &psk_binder_prefix,
    )?;
    let resumed = psk.is_some();
    if !resumed && ch.ext(EXT_SIGNATURE_ALGORITHMS).is_none() {
        return Err(TlsError::MissingExtension);
    }
    let client_allows_resumption = ch
        .ext(EXT_PSK_KEY_EXCHANGE_MODES)
        .and_then(Extension::as_psk_modes)
        .is_some_and(|modes| modes.contains(&PSK_DHE_KE));

    let kx = new_key_exchange(group)?;
    let shared = Zeroizing::new(
        kx.shared_secret(&client_pub)
            .ok_or(TlsError::IllegalParameter)?,
    );

    let mut sh_extensions = vec![
        Extension::supported_versions_server(TLS13),
        Extension::key_share_server(group, &kx.public_bytes()),
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
    w.send(s, &sh_msg.encode())?;
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
    w.protect(RecordLayer::Tls13(RecordCrypto::new(aead, sk, iv12(siv))));
    let mut read_c = RecordCrypto::new(aead, ck, iv12(civ));

    let ee = HandshakeMsg::new(
        HandshakeType::EncryptedExtensions,
        encrypted_extensions(negotiated_alpn.as_deref()),
    );
    w.send(s, &ee.encode())?;
    transcript.update(&ee.encode());

    let want_client_cert = cfg.client_ca.is_some() && !resumed;
    if want_client_cert {
        let cr = HandshakeMsg::new(
            HandshakeType::CertificateRequest,
            crate::cert::CertificateRequestMsg::standard().encode(),
        );
        w.send(s, &cr.encode())?;
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
        w.send(s, &cert_msg.encode())?;
        transcript.update(&cert_msg.encode());

        let cv_content = certificate_verify_content(&transcript.hash(), true);
        let cv = CertificateVerify {
            algorithm: cfg.sign_scheme,
            signature: (cfg.sign)(&cv_content),
        };
        let cv_msg = HandshakeMsg::new(HandshakeType::CertificateVerify, cv.encode());
        w.send(s, &cv_msg.encode())?;
        transcript.update(&cv_msg.encode());
    }

    let sfk = Zeroizing::new(finished_key(hash, &shs));
    let sfin = finished_verify_data(hash, &sfk, &transcript.hash());
    let fin_msg = HandshakeMsg::new(HandshakeType::Finished, sfin);
    w.send(s, &fin_msg.encode())?;
    transcript.update(&fin_msg.encode());

    // After this side's Finished the server writes with application keys, and alerts rejecting the
    // client's certificate or Finished must use them for the client to read.
    ks.enter_master();
    let th_after = transcript.hash();
    let cap = ks.client_application_traffic_secret(&th_after);
    let sap = ks.server_application_traffic_secret(&th_after);
    let (sak, saiv) = traffic_keys(hash, &sap, key_len);
    w.protect(RecordLayer::Tls13(RecordCrypto::new(aead, sak, iv12(saiv))));

    let mut er = EncReader::new();
    let mut th_for_client_fin = th_after.clone();
    let mut client_auth_identity: Option<String> = None;
    if want_client_cert {
        let cert_m = er.next(s, &mut read_c)?;
        if cert_m.msg_type != HandshakeType::Certificate {
            return Err(TlsError::UnexpectedMessage);
        }
        let ccert = CertificateMsg::parse(&cert_m.body)?;

        if ccert.entries.is_empty() {
            return Err(TlsError::CertificateRequired);
        }
        let chain: Vec<X509> = ccert
            .entries
            .iter()
            .map(|e| X509::parse(&e.cert_data))
            .collect::<Result<_, _>>()?;
        let store = cfg.client_ca.as_ref().ok_or(TlsError::Internal)?;
        crate::trust::verify_client_chain(&chain, store, now_epoch())?;
        let client_certificate = chain.first().ok_or(TlsError::Internal)?;
        client_auth_identity = Some(format!(
            "mtls:{}",
            short_hex(&client_certificate.public_key)
        ));
        transcript.update(&cert_m.encode());

        let th_before_cv = transcript.hash();
        let cv_m = er.next(s, &mut read_c)?;
        if cv_m.msg_type != HandshakeType::CertificateVerify {
            return Err(TlsError::UnexpectedMessage);
        }
        let cv = CertificateVerify::parse(&cv_m.body)?;
        let cv_content = certificate_verify_content(&th_before_cv, false);
        cv.verify_tls13(
            client_certificate,
            &crate::cert::REQUESTED_SIGNATURE_SCHEMES,
            &cv_content,
        )?;
        transcript.update(&cv_m.encode());
        th_for_client_fin = transcript.hash();
    }
    let cfin = er.next_at_boundary(s, &mut read_c)?;
    let cfk = Zeroizing::new(finished_key(hash, &chs));
    cfin.verify_finished(&finished_verify_data(hash, &cfk, &th_for_client_fin))?;
    transcript.update(&cfin.encode());

    let (cak, caiv) = traffic_keys(hash, &cap, key_len);
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
            let ticket = resumption.ticketer.seal(&state).ok_or(TlsError::Internal)?;
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
            w.send(s, &message.encode())?;
        }
    }
    Ok(TlsConnection {
        read: RecordLayer::Tls13(RecordCrypto::new(aead, cak, iv12(caiv))),
        write: w.take_layer()?,
        version: TLS13,
        alpn: negotiated_alpn,
        client_authenticated: client_auth_identity.is_some(),
        client_auth_identity,
        verified_chain: Vec::new(),
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
        failed: None,
    })
}

fn build_client_hello(
    cfg: &ClientConfig,
    kx: &KeyExchange,
    send_key_share: bool,
    cookie: Option<&[u8]>,
    session: Option<&crate::session::TlsSession>,
) -> ClientHello {
    let key_shares: Vec<(u16, Vec<u8>)> = if send_key_share {
        vec![(kx.group(), kx.public_bytes())]
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
    ];
    if let Some(host) = cfg.sni() {
        extensions.push(Extension::server_name(host));
    }
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

/// A failure sends a fatal alert under the current write protection. After the ServerHello that
/// is the client handshake key; this side sends no early data, so the server reads with it.
/// `Internal` when the configuration does not fit the wire, and then nothing is sent.
pub fn client_handshake<S: Read + Write>(
    s: &mut S,
    cfg: &ClientConfig,
) -> Result<TlsConnection, TlsError> {
    if !client_config_wire_is_valid(cfg) {
        return Err(TlsError::Internal);
    }
    HandshakeWrite::Silent.run(s, |s, w| run_client_handshake(s, cfg, w))
}

/// Everything sent goes through `w`.
fn run_client_handshake<S: Read + Write>(
    s: &mut S,
    cfg: &ClientConfig,
    w: &mut HandshakeWrite,
) -> Result<TlsConnection, TlsError> {
    let mut kx = new_key_exchange(X25519)?;
    let mut share_group = cfg.send_key_share.then(|| kx.group());

    let mut offered_session = fresh_client_session(cfg);
    let ch = build_client_hello(cfg, &kx, cfg.send_key_share, None, offered_session);
    let mut ch_bytes = encode_client_hello(&ch, offered_session, &[])?;
    w.send(s, &ch_bytes)?;

    let mut server_hs = PlainHsReader::new(true);
    let mut sh_msg = server_hs.next(s)?;
    let mut sh = ServerHello::from_handshake(&sh_msg)?;

    let server_chose_13 = sh
        .ext(EXT_SUPPORTED_VERSIONS)
        .and_then(|e| e.as_supported_versions_server())
        == Some(TLS13);
    if sh.random != crate::msg::HRR_RANDOM && !server_chose_13 {
        if sh.random[24..32] == DOWNGRADE_TLS12 || sh.random[24..32] == DOWNGRADE_TLS11 {
            return Err(TlsError::IllegalParameter);
        }
        return client_handshake_tls12(s, cfg, ch, ch_bytes, sh, sh_msg, server_hs, w);
    }
    server_hs.ensure_boundary()?;

    let mut hrr_transcript: Option<Transcript> = None;
    let mut hrr_suite = None;
    let mut retry_hello: Option<ClientHello> = None;
    if sh.random == crate::msg::HRR_RANDOM {
        let retry_group = sh.validate_retry_request(&ch)?;
        let cookie = match sh.ext(EXT_COOKIE) {
            Some(extension) => Some(extension.as_cookie().ok_or(TlsError::Decode)?),
            None => None,
        };
        let (hash, _) = suite_params(sh.cipher_suite).ok_or(TlsError::IllegalParameter)?;
        if !ch.cipher_suites.contains(&sh.cipher_suite) {
            return Err(TlsError::IllegalParameter);
        }
        hrr_suite = Some(sh.cipher_suite);

        let mut t = Transcript::new(hash);
        t.update(&ch_bytes);
        t.replace_with_message_hash();
        t.update(&sh_msg.encode());

        if offered_session.is_some_and(|session| session.hash() != Some(hash)) {
            offered_session = None;
        }
        if let Some(group) = retry_group {
            kx = new_key_exchange(group)?;
            share_group = Some(group);
        }
        let mut ch2 = build_client_hello(
            cfg,
            &kx,
            share_group.is_some(),
            cookie.as_deref(),
            offered_session,
        );
        ch2.random = ch.random;
        ch2.session_id.clone_from(&ch.session_id);
        ch2.cipher_suites.clone_from(&ch.cipher_suites);
        ch_bytes = encode_client_hello(&ch2, offered_session, t.as_bytes())?;
        w.send(s, &ch_bytes)?;
        t.update(&ch_bytes);
        hrr_transcript = Some(t);
        retry_hello = Some(ch2);

        sh_msg = PlainHsReader::new(true).next_at_boundary(s)?;
        sh = ServerHello::from_handshake(&sh_msg)?;
        if sh.random == crate::msg::HRR_RANDOM {
            return Err(TlsError::UnexpectedMessage);
        }
    }
    let hello = retry_hello.as_ref().unwrap_or(&ch);
    sh.validate_tls13(hello, false)?;
    let suite = sh.cipher_suite;
    if hrr_suite.is_some_and(|selected| selected != suite) {
        return Err(TlsError::IllegalParameter);
    }
    let (hash, key_len) = suite_params(suite).ok_or(TlsError::IllegalParameter)?;
    let aead = aead_for_suite(suite).ok_or(TlsError::Internal)?;
    let server_pub = sh.key_share(share_group)?;
    let shared = Zeroizing::new(
        kx.shared_secret(&server_pub)
            .ok_or(TlsError::IllegalParameter)?,
    );
    let psk_accepted = match sh.ext(EXT_PRE_SHARED_KEY) {
        None => false,
        Some(extension) => {
            let selected = extension
                .as_pre_shared_key_server()
                .ok_or(TlsError::Decode)?;
            let Some(session) = offered_session else {
                return Err(TlsError::UnsupportedExtension);
            };
            if selected != 0 || session.hash() != Some(hash) {
                return Err(TlsError::IllegalParameter);
            }
            true
        }
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
    w.protect(RecordLayer::Tls13(RecordCrypto::new(aead, ck, iv12(civ))));

    let mut er = EncReader::new();
    let ee = er.next(s, &mut read_c)?;
    if ee.msg_type != HandshakeType::EncryptedExtensions {
        return Err(TlsError::UnexpectedMessage);
    }

    let mut negotiated_alpn = None;
    for extension in Extension::parse_vector(&ee.body)? {
        match extension.ext_type {
            EXT_ALPN => negotiated_alpn = Some(extension.selected_alpn(&cfg.alpn)?),
            EXT_SERVER_NAME => {
                if hello.ext(EXT_SERVER_NAME).is_none() {
                    return Err(TlsError::UnsupportedExtension);
                }
                if !extension.data.is_empty() {
                    return Err(TlsError::Decode);
                }
            }
            EXT_SUPPORTED_GROUPS => {
                extension.as_supported_groups().ok_or(TlsError::Decode)?;
            }
            other if hello.ext(other).is_some() => return Err(TlsError::IllegalParameter),
            _ => return Err(TlsError::UnsupportedExtension),
        }
    }
    if psk_accepted && offered_session.is_none_or(|session| session.alpn != negotiated_alpn) {
        return Err(TlsError::IllegalParameter);
    }
    transcript.update(&ee.encode());

    if psk_accepted {
        let fin_m = er.next_at_boundary(s, &mut read_c)?;
        let sfk = Zeroizing::new(finished_key(hash, &shs));
        fin_m.verify_finished(&finished_verify_data(hash, &sfk, &transcript.hash()))?;
        transcript.update(&fin_m.encode());
        let application_transcript = transcript.hash();

        let cfk = Zeroizing::new(finished_key(hash, &chs));
        let cfin_msg = HandshakeMsg::new(
            HandshakeType::Finished,
            finished_verify_data(hash, &cfk, &application_transcript),
        );
        w.send(s, &cfin_msg.encode())?;
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
            verified_chain: Vec::new(),
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
            failed: None,
        });
    }

    let mut next_m = er.next(s, &mut read_c)?;
    let mut requested_schemes = None;
    if next_m.msg_type == HandshakeType::CertificateRequest {
        let request = crate::cert::CertificateRequestMsg::parse(&next_m.body)?;
        requested_schemes = Some(request.handshake_signature_algorithms()?);
        transcript.update(&next_m.encode());
        next_m = er.next(s, &mut read_c)?;
    }
    let cert_m = next_m;
    if cert_m.msg_type != HandshakeType::Certificate {
        return Err(TlsError::UnexpectedMessage);
    }
    let cert = CertificateMsg::parse(&cert_m.body)?;
    let leaf = cert.leaf().ok_or(TlsError::Decode)?;
    let x = X509::parse(leaf)?;
    let verified_chain = match &cfg.roots {
        Some(store) => {
            let chain: Vec<X509> = cert
                .entries
                .iter()
                .map(|e| X509::parse(&e.cert_data))
                .collect::<Result<_, _>>()?;
            crate::trust::verify_chain(&chain, store, &cfg.server_name, now_epoch())?
        }

        None => {
            if cfg.insecure_verifier.is_none() {
                return Err(TlsError::BadCert);
            }
            if cfg.verify_name && !x.matches_hostname(&cfg.server_name) {
                return Err(TlsError::BadCert);
            }
            Vec::new()
        }
    };
    transcript.update(&cert_m.encode());

    let th_before_cv = transcript.hash();
    let cv_m = er.next(s, &mut read_c)?;
    if cv_m.msg_type != HandshakeType::CertificateVerify {
        return Err(TlsError::UnexpectedMessage);
    }
    let cv = CertificateVerify::parse(&cv_m.body)?;
    let cv_content = certificate_verify_content(&th_before_cv, true);
    cv.verify_tls13(&x, &hello.signature_algorithms(), &cv_content)?;
    transcript.update(&cv_m.encode());

    let th_before_fin = transcript.hash();
    let fin_m = er.next_at_boundary(s, &mut read_c)?;
    let sfk = Zeroizing::new(finished_key(hash, &shs));
    fin_m.verify_finished(&finished_verify_data(hash, &sfk, &th_before_fin))?;
    transcript.update(&fin_m.encode());
    let th_after = transcript.hash();

    let mut th_for_fin = th_after.clone();
    if let Some(requested) = &requested_schemes {
        // With a key the server does not accept, send an empty Certificate; RFC 8446 has the server
        // decide whether to continue.
        let client_cert = cfg
            .client_cert
            .as_ref()
            .filter(|cc| crate::cert::tls13_signature_scheme_allowed(cc.sign_scheme, requested));
        let entries: Vec<CertEntry> = client_cert
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
        let cmsg = CertificateMsg {
            request_context: vec![],
            entries,
        };
        let cert_hs = HandshakeMsg::new(HandshakeType::Certificate, cmsg.encode());
        w.send(s, &cert_hs.encode())?;
        transcript.update(&cert_hs.encode());
        if let Some(cc) = client_cert {
            let content = certificate_verify_content(&transcript.hash(), false);
            let cv = CertificateVerify {
                algorithm: cc.sign_scheme,
                signature: (cc.sign)(&content),
            };
            let cv_hs = HandshakeMsg::new(HandshakeType::CertificateVerify, cv.encode());
            w.send(s, &cv_hs.encode())?;
            transcript.update(&cv_hs.encode());
        }
        th_for_fin = transcript.hash();
    }
    let cfk = Zeroizing::new(finished_key(hash, &chs));
    let cfin = finished_verify_data(hash, &cfk, &th_for_fin);
    let cfin_msg = HandshakeMsg::new(HandshakeType::Finished, cfin);
    w.send(s, &cfin_msg.encode())?;
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
        verified_chain,
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
        failed: None,
    })
}

/// Alerts go out in plaintext until this side's ChangeCipherSpec, which switches the write key
/// in 1.2.
fn server_handshake_tls12<S: Read + Write>(
    s: &mut S,
    cfg: &ServerConfig,
    ch_msg: HandshakeMsg,
    ch: ClientHello,
    w: &mut HandshakeWrite,
) -> Result<TlsConnection, TlsError> {
    validate_tls12_client_hello(&ch, cfg.sign_scheme)?;
    let server_ecdsa = scheme_is_ecdsa(cfg.sign_scheme);
    let suite = tls12::choose_server_suite(&ch.cipher_suites, server_ecdsa)
        .ok_or(TlsError::HandshakeFailure)?;
    let info = tls12::suite_info(suite).ok_or(TlsError::Internal)?;

    let client_groups = ch
        .ext(EXT_SUPPORTED_GROUPS)
        .and_then(|e| e.as_supported_groups())
        .unwrap_or_default();
    let group = tls12::supported_groups()
        .into_iter()
        .find(|g| client_groups.contains(g))
        .ok_or(TlsError::HandshakeFailure)?;

    let use_ems = ch.ext(tls12::EXT_EXTENDED_MASTER_SECRET).is_some();
    let client_random = ch.random;
    let negotiated_alpn = ch.select_alpn(&cfg.alpn)?;

    let mut transcript = ch_msg.encode();

    let mut server_random = random_32();
    server_random[24..].copy_from_slice(&DOWNGRADE_TLS12);
    let mut sh_exts = Vec::new();
    if use_ems {
        sh_exts.push(tls12::ext_extended_master_secret());
    }
    sh_exts.push(tls12::ext_renegotiation_info());
    if ch.ext(tls12::EXT_EC_POINT_FORMATS).is_some() {
        sh_exts.push(tls12::ext_ec_point_formats());
    }
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
    w.send(s, &sh_msg.encode())?;
    transcript.extend_from_slice(&sh_msg.encode());

    let cert_msg = HandshakeMsg::new(
        HandshakeType::Certificate,
        tls12::certificate(&cfg.cert_chain),
    );
    w.send(s, &cert_msg.encode())?;
    transcript.extend_from_slice(&cert_msg.encode());

    let kx = new_key_exchange(group)?;
    let params = tls12::ecdh_params(group, &kx.public_bytes());
    let signed = tls12::ske_signed_content(&client_random, &server_random, &params);
    let signature = (cfg.sign)(&signed);
    let ske_msg = HandshakeMsg::new(
        HandshakeType::ServerKeyExchange,
        tls12::server_key_exchange(&params, cfg.sign_scheme, &signature),
    );
    w.send(s, &ske_msg.encode())?;
    transcript.extend_from_slice(&ske_msg.encode());

    let shd_msg = HandshakeMsg::new(HandshakeType::ServerHelloDone, Vec::new());
    w.send(s, &shd_msg.encode())?;
    transcript.extend_from_slice(&shd_msg.encode());

    let cke = PlainHsReader::new(false).next_at_boundary(s)?;
    if cke.msg_type != HandshakeType::ClientKeyExchange {
        return Err(TlsError::UnexpectedMessage);
    }
    let client_pub = tls12::parse_client_key_exchange(&cke.body)?;
    transcript.extend_from_slice(&cke.encode());
    let shared = Zeroizing::new(
        kx.shared_secret(&client_pub)
            .ok_or(TlsError::IllegalParameter)?,
    );

    let master = Zeroizing::new(if use_ems {
        tls12::extended_master_secret(info.hash, &shared, &info.hash.digest(&transcript))
    } else {
        tls12::master_secret(info.hash, &shared, &client_random, &server_random)
    });
    let km = tls12::key_material(&info, &master, &client_random, &server_random);
    let mut read_c = Tls12RecordCrypto::new(info.aead, km.client_key, km.client_iv)?;
    let write_c = Tls12RecordCrypto::new(info.aead, km.server_key, km.server_iv)?;

    expect_ccs(s)?;
    let cfin = read_tls12_finished(s, &mut read_c)?;
    cfin.verify_finished(&tls12::finished_verify_data(
        info.hash,
        &master,
        "client finished",
        &transcript,
    ))?;
    transcript.extend_from_slice(&cfin.encode());

    write_record(s, &ccs_record())?;
    w.protect(RecordLayer::Tls12(write_c));
    let sfin = tls12::finished_verify_data(info.hash, &master, "server finished", &transcript);
    w.send(
        s,
        &HandshakeMsg::new(HandshakeType::Finished, sfin).encode(),
    )?;

    Ok(TlsConnection {
        read: RecordLayer::Tls12(read_c),
        write: w.take_layer()?,
        version: TLS12,
        alpn: negotiated_alpn,
        client_authenticated: false,
        client_auth_identity: None,
        verified_chain: Vec::new(),
        is_client: false,
        post_handshake: HandshakeReader::new(),
        traffic: None,
        resumed: false,
        resumption: None,
        new_sessions: Vec::new(),
        failed: None,
    })
}

#[allow(clippy::too_many_arguments)]
/// Alerts go out in plaintext until this side's ChangeCipherSpec, which switches the write key
/// in 1.2. A certificate is sent only when one matches the requested type and scheme; otherwise
/// an empty Certificate, as RFC 5246 says.
fn client_handshake_tls12<S: Read + Write>(
    s: &mut S,
    cfg: &ClientConfig,
    ch: ClientHello,
    ch_bytes: Vec<u8>,
    sh: ServerHello,
    sh_msg: HandshakeMsg,
    mut phr: PlainHsReader,
    w: &mut HandshakeWrite,
) -> Result<TlsConnection, TlsError> {
    let client_random = ch.random;
    let negotiated_alpn = validate_tls12_server_hello(cfg, &ch, &sh)?;
    let suite = sh.cipher_suite;
    let info = tls12::suite_info(suite).ok_or(TlsError::Internal)?;
    let server_random = sh.random;

    let mut transcript = ch_bytes;
    transcript.extend_from_slice(&sh_msg.encode());
    phr.drop_ccs = false;

    let cert_message = phr.next(s)?;
    if cert_message.msg_type != HandshakeType::Certificate {
        return Err(TlsError::UnexpectedMessage);
    }
    let cert_chain = tls12::parse_certificate(&cert_message.body)?;
    transcript.extend_from_slice(&cert_message.encode());

    let ske_message = phr.next(s)?;
    if ske_message.msg_type != HandshakeType::ServerKeyExchange {
        return Err(TlsError::UnexpectedMessage);
    }
    let (group, server_pub, params_bytes, sig_scheme, signature) =
        tls12::parse_server_key_exchange(&ske_message.body)?;
    transcript.extend_from_slice(&ske_message.encode());

    let mut next = phr.next(s)?;
    let mut certificate_request = None;
    if next.msg_type == HandshakeType::CertificateRequest {
        certificate_request = Some(tls12::parse_certificate_request(&next.body)?);
        transcript.extend_from_slice(&next.encode());
        next = phr.next(s)?;
    }
    if next.msg_type != HandshakeType::ServerHelloDone {
        return Err(TlsError::UnexpectedMessage);
    }
    if !next.body.is_empty() {
        return Err(TlsError::Decode);
    }
    phr.ensure_boundary()?;
    transcript.extend_from_slice(&next.encode());
    if !tls12::group_supported(group)
        || !ch
            .ext(EXT_SUPPORTED_GROUPS)
            .and_then(Extension::as_supported_groups)
            .is_some_and(|groups| groups.contains(&group))
        || info.ecdsa != scheme_is_ecdsa(sig_scheme)
        || !ch
            .ext(EXT_SIGNATURE_ALGORITHMS)
            .and_then(Extension::as_signature_algorithms)
            .is_some_and(|algorithms| algorithms.contains(&sig_scheme))
    {
        return Err(TlsError::IllegalParameter);
    }

    let leaf = cert_chain.first().ok_or(TlsError::Decode)?;
    let x = X509::parse(leaf)?;
    let verified_chain = match &cfg.roots {
        Some(store) => {
            let chain: Vec<X509> = cert_chain
                .iter()
                .map(|d| X509::parse(d))
                .collect::<Result<_, _>>()?;
            crate::trust::verify_chain(&chain, store, &cfg.server_name, now_epoch())?
        }
        None => {
            if cfg.insecure_verifier.is_none() {
                return Err(TlsError::BadCert);
            }
            if cfg.verify_name && !x.matches_hostname(&cfg.server_name) {
                return Err(TlsError::BadCert);
            }
            Vec::new()
        }
    };

    let signed = tls12::ske_signed_content(&client_random, &server_random, &params_bytes);
    x.verify_tls_signature(sig_scheme, &signed, &signature)?;

    let kx = new_key_exchange(group)?;
    let shared = Zeroizing::new(
        kx.shared_secret(&server_pub)
            .ok_or(TlsError::IllegalParameter)?,
    );

    let client_cert = certificate_request.as_ref().map(|request| {
        cfg.client_cert
            .as_ref()
            .filter(|cc| request.accepts(cc.sign_scheme))
    });
    if let Some(client_cert) = client_cert {
        let chain = client_cert.map_or(&[][..], |cc| cc.chain.as_slice());
        let cert_msg = HandshakeMsg::new(HandshakeType::Certificate, tls12::certificate(chain));
        w.send(s, &cert_msg.encode())?;
        transcript.extend_from_slice(&cert_msg.encode());
    }

    let cke_msg = HandshakeMsg::new(
        HandshakeType::ClientKeyExchange,
        tls12::client_key_exchange(&kx.public_bytes()),
    );
    w.send(s, &cke_msg.encode())?;
    transcript.extend_from_slice(&cke_msg.encode());

    // The RFC 7627 session hash ends at ClientKeyExchange. CertificateVerify comes after it and
    // signs every handshake message before it.
    let master = Zeroizing::new(tls12::extended_master_secret(
        info.hash,
        &shared,
        &info.hash.digest(&transcript),
    ));
    if let Some(Some(cc)) = client_cert {
        let cv = CertificateVerify {
            algorithm: cc.sign_scheme,
            signature: (cc.sign)(&transcript),
        };
        let cv_msg = HandshakeMsg::new(HandshakeType::CertificateVerify, cv.encode());
        w.send(s, &cv_msg.encode())?;
        transcript.extend_from_slice(&cv_msg.encode());
    }
    let km = tls12::key_material(&info, &master, &client_random, &server_random);
    let write_c = Tls12RecordCrypto::new(info.aead, km.client_key, km.client_iv)?;
    let mut read_c = Tls12RecordCrypto::new(info.aead, km.server_key, km.server_iv)?;

    write_record(s, &ccs_record())?;
    w.protect(RecordLayer::Tls12(write_c));
    let cfin = tls12::finished_verify_data(info.hash, &master, "client finished", &transcript);
    let cfin_msg = HandshakeMsg::new(HandshakeType::Finished, cfin);
    w.send(s, &cfin_msg.encode())?;
    transcript.extend_from_slice(&cfin_msg.encode());

    expect_ccs(s)?;
    let sfin = read_tls12_finished(s, &mut read_c)?;
    sfin.verify_finished(&tls12::finished_verify_data(
        info.hash,
        &master,
        "server finished",
        &transcript,
    ))?;

    Ok(TlsConnection {
        read: RecordLayer::Tls12(read_c),
        write: w.take_layer()?,
        version: TLS12,
        alpn: negotiated_alpn,
        client_authenticated: false,
        client_auth_identity: None,
        verified_chain,
        is_client: true,
        post_handshake: HandshakeReader::new(),
        traffic: None,
        resumed: false,
        resumption: None,
        new_sessions: Vec::new(),
        failed: None,
    })
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

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
mod tests {
    use super::*;
    use p256::pkcs8::DecodePrivateKey;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[test]
    /// Upper layers may treat only an EOF at a record boundary as a clean close; treating a
    /// mid-record EOF the same would miss a truncation.
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
            verified_chain: Vec::new(),
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
            failed: None,
        }
    }

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
    /// A warning-level user_canceled is a closure alert, not an error; a record holding only that
    /// yields nothing so the following close_notify is read. In 1.3 the level is ignored.
    fn close_notify_is_distinct_from_fatal_alerts() {
        let handshake_failure = TlsError::PeerAlert {
            level: 2,
            description: 40,
        };
        assert_eq!(alert_error(&[1, 0]), Some(TlsError::CloseNotify));
        assert_eq!(alert_error(&[2, 40]), Some(handshake_failure.clone()));
        assert_eq!(alert_error(&[1, 0, 1, 0]), Some(TlsError::CloseNotify));
        assert_eq!(alert_error(&[1, 0, 2, 40]), Some(handshake_failure));
        assert_eq!(alert_error(&[2]), Some(TlsError::Decode));
        assert_eq!(alert_error(&[1, ALERT_USER_CANCELED]), None);
        assert_eq!(
            alert_error(&[1, ALERT_USER_CANCELED, 1, 0]),
            Some(TlsError::CloseNotify)
        );
        assert_eq!(
            alert_error(&[2, ALERT_USER_CANCELED]),
            Some(TlsError::PeerAlert {
                level: 2,
                description: ALERT_USER_CANCELED,
            })
        );
        assert_eq!(tls13_alert_error(&[1, ALERT_USER_CANCELED]), None);
        assert_eq!(tls13_alert_error(&[2, ALERT_USER_CANCELED]), None);
        assert_eq!(tls13_alert_error(&[]), Some(TlsError::UnexpectedMessage));
        assert_eq!(tls13_alert_error(&[1, 0, 1, 0]), Some(TlsError::Decode));
    }

    #[test]
    fn user_canceled_does_not_end_the_read() {
        let canceled = (ContentType::Alert, &[1, ALERT_USER_CANCELED][..]);
        assert_eq!(
            test_tls13_connection().read_app(&mut encrypted_records(&[
                canceled,
                (ContentType::Alert, &[1, 0]),
            ])),
            Err(TlsError::CloseNotify)
        );
        assert_eq!(
            test_tls13_connection().read_app(&mut encrypted_records(&[
                canceled,
                (ContentType::ApplicationData, b"dns"),
            ])),
            Ok(b"dns".to_vec())
        );

        let finished = HandshakeMsg::new(HandshakeType::Finished, vec![1; 32]).encode();
        assert_eq!(
            EncReader::new()
                .next(
                    &mut encrypted_records(&[canceled, (ContentType::Handshake, &finished)]),
                    &mut test_peer_crypto(),
                )
                .map(|message| message.msg_type == HandshakeType::Finished),
            Ok(true)
        );

        let plaintext = [
            TlsRecord::new(ContentType::Alert, vec![1, ALERT_USER_CANCELED]).encode(),
            TlsRecord::new(ContentType::Alert, vec![1, 0]).encode(),
        ]
        .concat();
        assert_eq!(
            PlainHsReader::new(false)
                .next(&mut std::io::Cursor::new(plaintext))
                .err(),
            Some(TlsError::CloseNotify)
        );

        let endless = vec![canceled; MAX_CONSECUTIVE_IGNORED_RECORDS + 1];
        assert_eq!(
            test_tls13_connection().read_app(&mut encrypted_records(&endless)),
            Err(TlsError::UnexpectedMessage),
            "무시하는 레코드는 무한히 받지 않는다"
        );
    }

    #[test]
    /// Without anti-replay, 0 is a correctness condition, not a policy.
    fn secure_resumption_default_refuses_early_data() {
        assert_eq!(
            ServerResumption::secure_default().max_early_data,
            0,
            "안티리플레이 없이 0-RTT를 받으면 재생된 질의를 그대로 처리한다"
        );
    }

    #[test]
    fn tls_stream_empty_io_is_side_effect_free() {
        let mut stream = TlsStream::new(test_tls13_connection(), NoIo);
        assert_eq!(stream.read(&mut []).unwrap(), 0);
        assert_eq!(stream.write(&[]).unwrap(), 0);
    }

    #[test]
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
            Err(TlsError::UnexpectedMessage)
        );
    }

    #[test]
    fn invalid_protected_content_types_fail_closed() {
        assert_eq!(
            test_tls13_connection().read_app(&mut encrypted_records(&[(ContentType(0xff), b"x")])),
            Err(TlsError::UnexpectedMessage)
        );
        assert_eq!(
            test_tls13_connection()
                .read_app(&mut encrypted_records(&[(ContentType::Handshake, b"")])),
            Err(TlsError::UnexpectedMessage)
        );
        assert_eq!(
            test_tls13_connection().read_app(&mut encrypted_records(&[(
                ContentType::Alert,
                &[1, 0, 1, 0]
            )])),
            Err(TlsError::Decode)
        );
        assert_eq!(
            test_tls13_connection().read_app(&mut encrypted_records(&[(ContentType::Alert, &[])])),
            Err(TlsError::UnexpectedMessage)
        );
    }

    #[test]
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
            Err(TlsError::IllegalParameter)
        );
        let long_key_update = HandshakeMsg::new(HandshakeType::KeyUpdate, vec![0, 0]).encode();
        assert_eq!(
            test_tls13_connection().read_app(&mut encrypted_records(&[(
                ContentType::Handshake,
                &long_key_update
            )])),
            Err(TlsError::Decode)
        );

        assert_eq!(
            test_tls13_connection().read_app(&mut encrypted_records(&[
                (
                    ContentType::Handshake,
                    &[HandshakeType::NewSessionTicket.0, 0, 0]
                ),
                (ContentType::ApplicationData, b"dns"),
            ])),
            Err(TlsError::UnexpectedMessage)
        );

        let valid_key_update = HandshakeMsg::new(HandshakeType::KeyUpdate, vec![0]).encode();
        assert_eq!(
            test_tls13_connection().read_app(&mut encrypted_records(&[
                (ContentType::Handshake, &valid_key_update[..2]),
                (ContentType::Handshake, &valid_key_update[2..]),
            ])),
            Err(TlsError::UnexpectedMessage)
        );
        let mut coalesced = valid_key_update.clone();
        coalesced.extend_from_slice(&valid_key_update);
        assert_eq!(
            test_tls13_connection().read_app(&mut encrypted_records(&[(
                ContentType::Handshake,
                &coalesced
            )])),
            Err(TlsError::UnexpectedMessage)
        );
    }

    #[test]
    fn encrypted_handshake_reader_rejects_unexpected_records() {
        for (content_type, plaintext, expected) in [
            (
                ContentType::ApplicationData,
                &b"x"[..],
                TlsError::UnexpectedMessage,
            ),
            (
                ContentType::Handshake,
                &b""[..],
                TlsError::UnexpectedMessage,
            ),
            (ContentType::Alert, &[1, 0, 1, 0][..], TlsError::Decode),
            (
                ContentType::Alert,
                &[2, 42][..],
                TlsError::PeerAlert {
                    level: 2,
                    description: 42,
                },
            ),
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
                Err(expected)
            );
        }
    }

    fn test_peer_crypto() -> RecordCrypto {
        let secret = vec![0x42; Hash::Sha256.len()];
        let (key, iv) = traffic_keys(Hash::Sha256, &secret, 16);
        RecordCrypto::new(Aead::Aes128Gcm, key, iv12(iv))
    }

    #[test]
    /// Before anything is sent the peer does not know the connection, so nothing is sent. I/O
    /// failures and peer alerts get no reply.
    fn handshake_failure_alert_follows_the_write_protection() {
        let fail = |error: TlsError| {
            move |_: &mut Vec<u8>, _: &mut HandshakeWrite| -> Result<TlsConnection, TlsError> {
                Err(error)
            }
        };

        let mut silent = Vec::new();
        assert_eq!(
            HandshakeWrite::Silent
                .run(&mut silent, fail(TlsError::Decode))
                .err(),
            Some(TlsError::Decode)
        );
        assert!(silent.is_empty(), "아무것도 보내기 전에 경고를 보냈습니다");

        let mut plain = Vec::new();
        assert!(HandshakeWrite::Plain
            .run(&mut plain, fail(TlsError::Decode))
            .is_err());
        assert_eq!(plain, [21, 3, 3, 0, 2, 2, 50]);

        for error in [
            TlsError::Io,
            TlsError::Eof,
            TlsError::PeerAlert {
                level: 2,
                description: 40,
            },
        ] {
            let mut quiet = Vec::new();
            assert!(HandshakeWrite::Plain
                .run(&mut quiet, fail(error.clone()))
                .is_err());
            assert!(quiet.is_empty(), "{error:?} 에 경고로 답했습니다");
        }

        let protected = HandshakeWrite::Protected(RecordLayer::Tls13(test_peer_crypto()));
        let mut sealed = Vec::new();
        assert!(protected.run(&mut sealed, fail(TlsError::BadCert)).is_err());
        let record = read_record(&mut sealed.as_slice()).unwrap();
        assert_eq!(
            record.content_type,
            ContentType::ApplicationData,
            "키를 바꾼 뒤의 경고를 평문으로 보냈습니다"
        );
        assert_eq!(
            test_peer_crypto().decrypt(&record),
            Ok((ContentType::Alert, vec![2, 42]))
        );
    }

    #[test]
    /// A fatal alert from the peer gets no reply, and a dropped connection is not marked failed.
    fn fatal_alert_ends_the_connection() {
        let mut conn = test_tls13_connection();
        let mut wire = encrypted_records(&[(ContentType(0xff), b"x")]);
        let received = wire.get_ref().len();
        assert_eq!(conn.read_app(&mut wire), Err(TlsError::UnexpectedMessage));
        let alert = read_record(&mut &wire.get_ref()[received..]).unwrap();
        assert_eq!(
            test_peer_crypto().decrypt(&alert),
            Ok((ContentType::Alert, vec![2, 10]))
        );
        assert_eq!(
            conn.write_app(&mut NoIo, b"dns"),
            Err(TlsError::UnexpectedMessage)
        );
        assert_eq!(
            conn.send_close_notify(&mut NoIo),
            Err(TlsError::UnexpectedMessage)
        );
        assert_eq!(conn.read_app(&mut NoIo), Err(TlsError::UnexpectedMessage));

        let mut conn = test_tls13_connection();
        let mut wire = encrypted_records(&[(ContentType::Alert, &[2, 40])]);
        let received = wire.get_ref().len();
        let peer_alert = TlsError::PeerAlert {
            level: 2,
            description: 40,
        };
        assert_eq!(conn.read_app(&mut wire), Err(peer_alert.clone()));
        assert_eq!(
            wire.get_ref().len(),
            received,
            "받은 치명 경고에 경고로 답했습니다"
        );
        assert_eq!(conn.write_app(&mut NoIo, b"dns"), Err(peer_alert));

        let mut conn = test_tls13_connection();
        assert_eq!(
            conn.read_app(&mut std::io::Cursor::new(Vec::new())),
            Err(TlsError::Eof)
        );
        let mut after = Vec::new();
        assert_eq!(conn.send_close_notify(&mut after), Ok(()));
        assert!(!after.is_empty(), "끊긴 연결을 실패 상태로 두었습니다");
    }

    #[test]
    fn rejected_peer_certificate_sends_certificate_unknown() {
        let mut conn = test_tls13_connection();
        let mut wire = Vec::new();
        conn.reject_peer_certificate(&mut wire);
        let alert = read_record(&mut wire.as_slice()).unwrap();
        assert_eq!(
            test_peer_crypto().decrypt(&alert),
            Ok((ContentType::Alert, vec![2, 46]))
        );
        assert_eq!(
            conn.write_app(&mut NoIo, b"dns"),
            Err(TlsError::CertificateUnknown)
        );
        let mut again = Vec::new();
        conn.reject_peer_certificate(&mut again);
        assert!(again.is_empty(), "끝난 연결에 경고를 다시 보냈습니다");
    }

    #[test]
    /// After a partial record, the peer would read the next record as its rest; a trailing
    /// close_notify would show up as an authentication failure instead of a clean close.
    fn unfinished_record_write_stops_later_writes() {
        /// Accepts a fixed number of bytes, then blocks.
        struct SendBuffer(usize);

        impl Write for SendBuffer {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                if self.0 == 0 {
                    return Err(std::io::ErrorKind::WouldBlock.into());
                }
                let taken = data.len().min(self.0);
                self.0 -= taken;
                Ok(taken)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut conn = test_tls13_connection();
        assert_eq!(
            conn.write_app(&mut SendBuffer(10), b"dns answer"),
            Err(TlsError::Io)
        );
        assert_eq!(conn.send_close_notify(&mut NoIo), Err(TlsError::Io));
        assert_eq!(conn.write_app(&mut NoIo, b"dns"), Err(TlsError::Io));

        let mut conn = test_tls13_connection();
        assert_eq!(
            conn.send_close_notify(&mut SendBuffer(3)),
            Err(TlsError::Io)
        );
        assert_eq!(conn.write_app(&mut NoIo, b"dns"), Err(TlsError::Io));
    }

    #[test]
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
            Err(TlsError::HandshakeFailure)
        );
        sh.extensions.push(tls12::ext_extended_master_secret());
        sh.extensions.push(Extension::new(0x1234, Vec::new()));
        assert_eq!(
            validate_tls12_server_hello(&cfg, &ch, &sh),
            Err(TlsError::UnsupportedExtension)
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
            Err(TlsError::UnsupportedExtension),
            "보내지 않은 서버 이름에 대한 응답은 거부한다"
        );
        sh.extensions.pop();
        *sh.extensions
            .iter_mut()
            .find(|extension| extension.ext_type == EXT_ALPN)
            .unwrap() = Extension::alpn(&[b"h2"]);
        assert_eq!(
            validate_tls12_server_hello(&cfg, &ch, &sh),
            Err(TlsError::IllegalParameter)
        );

        ch.compression_methods = vec![1];
        assert_eq!(
            validate_tls12_client_hello(&ch, ECDSA_SECP256R1_SHA256),
            Err(TlsError::IllegalParameter)
        );
    }

    #[test]
    /// A point format list containing uncompressed is accepted in any order and count; no alert
    /// fits refusing a well-formed list.
    fn tls12_server_hello_rejections_name_the_matching_alert() {
        let (cfg, ch, sh) = valid_tls12_hellos();
        let with = |ext_type: u16, data: Vec<u8>| {
            let mut changed = sh.clone();
            changed
                .extensions
                .retain(|extension| extension.ext_type != ext_type);
            changed.extensions.push(Extension::new(ext_type, data));
            validate_tls12_server_hello(&cfg, &ch, &changed)
        };
        assert!(
            with(tls12::EXT_EC_POINT_FORMATS, vec![3, 2, 0, 1]).is_ok(),
            "압축하지 않은 형식이 든 목록은 받아들여야 한다"
        );
        assert_eq!(
            with(tls12::EXT_EC_POINT_FORMATS, vec![2, 1, 2]),
            Err(TlsError::IllegalParameter)
        );
        assert_eq!(
            with(tls12::EXT_EC_POINT_FORMATS, vec![2, 0]),
            Err(TlsError::Decode)
        );
        assert_eq!(
            with(tls12::EXT_RENEGOTIATION_INFO, vec![1, 7]),
            Err(TlsError::HandshakeFailure)
        );
        assert_eq!(
            with(tls12::EXT_RENEGOTIATION_INFO, vec![2, 7]),
            Err(TlsError::Decode)
        );
        assert_eq!(
            with(tls12::EXT_EXTENDED_MASTER_SECRET, vec![0]),
            Err(TlsError::Decode)
        );
        assert_eq!(
            with(EXT_SIGNATURE_ALGORITHMS, Vec::new()),
            Err(TlsError::IllegalParameter),
            "제안했어도 서버 인사말에 올 수 없는 확장은 IllegalParameter 여야 한다"
        );

        let mut old_version = sh.clone();
        old_version.legacy_version = 0x0301;
        assert_eq!(
            validate_tls12_server_hello(&cfg, &ch, &old_version),
            Err(TlsError::ProtocolVersion)
        );
        let mut unoffered_suite = sh;
        unoffered_suite.cipher_suite = TLS_AES_128_GCM_SHA256;
        assert_eq!(
            validate_tls12_server_hello(&cfg, &ch, &unoffered_suite),
            Err(TlsError::IllegalParameter)
        );
    }

    #[test]
    fn tls12_server_answers_point_formats_only_when_offered() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cfg = ServerConfig::from_pkcs8(
            ck.cert.der().as_ref().to_vec(),
            &ck.key_pair.serialize_der(),
        )
        .unwrap();
        let (_, mut hello, _) = valid_tls12_hellos();
        hello
            .extensions
            .push(Extension::supported_groups(&[X25519]));
        let answer = |hello: &ClientHello| first_server_hello(&cfg, hello.to_handshake().encode());

        let reply = answer(&hello).expect("정상 1.2 인사말에는 답해야 한다");
        assert_eq!(
            reply.ext(tls12::EXT_EC_POINT_FORMATS),
            Some(&tls12::ext_ec_point_formats()),
            "보낸 점 형식 확장에는 압축하지 않은 형식으로 답해야 한다"
        );

        let mut omitted = hello.clone();
        omitted
            .extensions
            .retain(|extension| extension.ext_type != tls12::EXT_EC_POINT_FORMATS);
        let reply = answer(&omitted).expect("점 형식 확장이 없어도 답해야 한다");
        assert_eq!(
            reply.ext(tls12::EXT_EC_POINT_FORMATS),
            None,
            "보내지 않은 확장으로 답하면 안 된다"
        );

        let mut compressed_only = hello;
        *compressed_only
            .extensions
            .iter_mut()
            .find(|extension| extension.ext_type == tls12::EXT_EC_POINT_FORMATS)
            .unwrap() = Extension::new(tls12::EXT_EC_POINT_FORMATS, vec![1, 1]);
        assert!(
            answer(&compressed_only).is_none(),
            "압축하지 않은 형식이 빠진 목록에는 답하지 않아야 한다"
        );
    }

    #[test]
    /// supported_versions absent with legacy_version above 1.2 negotiates 1.2. legacy_version of
    /// SSL 3.0 or lower is refused with protocol_version whatever else is offered.
    fn tls12_server_marks_downgrade_and_accepts_rfc_variants() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cfg = ServerConfig::from_pkcs8(
            ck.cert.der().as_ref().to_vec(),
            &ck.key_pair.serialize_der(),
        )
        .unwrap();
        let (_, mut hello, _) = valid_tls12_hellos();
        hello
            .extensions
            .push(Extension::supported_groups(&[X25519]));
        let answer = |hello: &ClientHello| first_server_hello(&cfg, hello.to_handshake().encode());
        let failure = |hello: &ClientHello| {
            let mut stream = Scripted {
                input: std::io::Cursor::new(
                    TlsRecord::new(ContentType::Handshake, hello.to_handshake().encode()).encode(),
                ),
                output: Vec::new(),
            };
            server_handshake(&mut stream, &cfg).err()
        };

        let reply = answer(&hello).expect("정상 1.2 인사말에는 답해야 한다");
        assert_eq!(
            reply.random[24..],
            DOWNGRADE_TLS12,
            "1.2 로 답하면 다운그레이드 표식을 넣어야 한다"
        );

        let mut newer_legacy = hello.clone();
        newer_legacy.legacy_version = TLS13;
        assert!(
            answer(&newer_legacy).is_some(),
            "supported_versions 가 없으면 legacy_version 이 높아도 1.2 로 답해야 한다"
        );
        let mut compression = hello.clone();
        compression.compression_methods = vec![1, 0];
        assert!(
            answer(&compression).is_some(),
            "무압축이 들어 있는 압축 방식 목록은 받아들여야 한다"
        );
        let mut scsv = hello.clone();
        scsv.extensions
            .retain(|extension| extension.ext_type != tls12::EXT_RENEGOTIATION_INFO);
        scsv.cipher_suites
            .push(tls12::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        assert!(
            answer(&scsv).is_some(),
            "SCSV 도 첫 연결의 재협상 정보로 받아들여야 한다"
        );

        let mut no_renegotiation_info = scsv;
        no_renegotiation_info
            .cipher_suites
            .retain(|suite| *suite != tls12::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        let mut renegotiating = hello.clone();
        *renegotiating
            .extensions
            .iter_mut()
            .find(|extension| extension.ext_type == tls12::EXT_RENEGOTIATION_INFO)
            .unwrap() = Extension::new(tls12::EXT_RENEGOTIATION_INFO, vec![1, 7]);
        let mut ssl3 = hello.clone();
        ssl3.legacy_version = 0x0300;
        ssl3.extensions
            .push(Extension::supported_versions_client(&[TLS12]));
        let mut tls11_only = hello;
        tls11_only
            .extensions
            .push(Extension::supported_versions_client(&[0x0302]));
        for (case, rejected, expected) in [
            (
                "재협상 정보 없음",
                no_renegotiation_info,
                TlsError::HandshakeFailure,
            ),
            ("재협상 요청", renegotiating, TlsError::HandshakeFailure),
            (
                "1.2 를 제안해도 legacy_version 이 SSL 3.0",
                ssl3,
                TlsError::ProtocolVersion,
            ),
            ("1.1 만 제안", tls11_only, TlsError::ProtocolVersion),
        ] {
            assert_eq!(failure(&rejected), Some(expected), "{case}");
        }
    }

    #[test]
    fn tls12_rejects_noncanonical_ccs_finished_and_server_flight_order() {
        let valid_finished = HandshakeMsg::new(HandshakeType::Finished, vec![1; 12]).encode();
        assert!(parse_exact_handshake(&valid_finished).is_ok());
        assert_eq!(
            parse_exact_handshake(&valid_finished[..valid_finished.len() - 1]),
            Err(TlsError::Decode)
        );
        let mut trailing = valid_finished;
        trailing.push(0);
        assert_eq!(
            parse_exact_handshake(&trailing),
            Err(TlsError::UnexpectedMessage)
        );

        let valid_ccs = TlsRecord::new(ContentType::ChangeCipherSpec, vec![1]).encode();
        assert!(expect_ccs(&mut std::io::Cursor::new(valid_ccs)).is_ok());
        let invalid_ccs = TlsRecord::new(ContentType::ChangeCipherSpec, vec![1, 0]).encode();
        assert_eq!(
            expect_ccs(&mut std::io::Cursor::new(invalid_ccs)),
            Err(TlsError::UnexpectedMessage)
        );
        let alert_instead = TlsRecord::new(ContentType::Alert, vec![2, 40]).encode();
        assert_eq!(
            expect_ccs(&mut std::io::Cursor::new(alert_instead)),
            Err(TlsError::PeerAlert {
                level: 2,
                description: 40,
            })
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
                PlainHsReader::new(false),
                &mut HandshakeWrite::Plain,
            )
            .map(|_| ()),
            Err(TlsError::UnexpectedMessage)
        );
    }

    #[test]
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
            verified_chain: Vec::new(),
            is_client: false,
            post_handshake: HandshakeReader::new(),
            traffic: None,
            resumed: false,
            resumption: None,
            new_sessions: Vec::new(),
            failed: None,
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
    fn encrypted_handshake_is_fragmented_at_the_record_limit() {
        let key = vec![0x33; 16];
        let iv = [0x44; 12];
        let message = HandshakeMsg::new(HandshakeType::Certificate, vec![0x5a; MAX_FRAGMENT + 17]);
        let expected = message.encode();
        let mut sender = HandshakeWrite::Protected(RecordLayer::Tls13(RecordCrypto::new(
            Aead::Aes128Gcm,
            key.clone(),
            iv,
        )));
        let mut wire = Vec::new();
        sender.send(&mut wire, &expected).unwrap();

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
            accept_client_psk(&server_cfg, &parsed, &message, Hash::Sha256, &None, &[])
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
            accept_client_psk(&server_cfg, &parsed, &message, Hash::Sha256, &None, &[]),
            Err(TlsError::BadSignature)
        ));
    }

    #[test]
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
    /// The client has handshake keys after the ServerHello, so its alert is protected with them and
    /// the server must decrypt it to read bad_certificate.
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
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            server_handshake(&mut s, &server_cfg).err()
        });
        let mut c = Recorded {
            inner: TcpStream::connect(addr).unwrap(),
            written: Vec::new(),
        };
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

        assert_eq!(
            client_handshake(&mut c, &client_cfg).err(),
            Some(TlsError::BadCert)
        );
        assert_eq!(
            last_written_record(&c.written).content_type,
            ContentType::ApplicationData,
            "ServerHello 를 처리한 뒤의 경고를 평문으로 보냈습니다"
        );
        // Closing with unread server data sends RST, which can drop the connection before the
        // server reads the alert; close after the server ends.
        assert_eq!(
            server.join().unwrap(),
            Some(TlsError::PeerAlert {
                level: 2,
                description: 42,
            })
        );
        drop(c);
    }

    #[test]
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
            other_params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "Other Test Root");
            let other_ca = other_params.self_signed(&other_key).unwrap();

            let mut c = TcpStream::connect(addr).unwrap();
            let cfg = ClientConfig {
                server_name: "dns.example".into(),
                verify_name: true,
                roots: Some(TrustStore::from_ders([other_ca.der().as_ref()])),
                alpn: vec![],
                ..Default::default()
            };
            assert_eq!(
                client_handshake(&mut c, &cfg).err(),
                Some(TlsError::UnknownCa),
                "모르는 CA 가 발급한 체인은 unknown_ca 로 거부해야 한다"
            );
            drop(c);
            let _ = server.join();
        }
    }

    #[test]
    /// A leaf issued by the root, followed by a fake root with the same name, still yields a
    /// verified path ending at the stored root, in 1.3 and 1.2.
    fn verified_chain_ends_at_the_stored_root_not_a_presented_impostor() {
        use crate::trust::TrustStore;
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_der = ca_cert.der().to_vec();

        let impostor_key = KeyPair::generate().unwrap();
        let mut impostor_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        impostor_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let impostor_der = impostor_params
            .self_signed(&impostor_key)
            .unwrap()
            .der()
            .to_vec();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(vec!["dns.example".to_string()]).unwrap();
        let leaf_der = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .unwrap()
            .der()
            .to_vec();
        let leaf_key_der = leaf_key.serialize_der();

        let ca = X509::parse(&ca_der).unwrap();
        let impostor = X509::parse(&impostor_der).unwrap();
        assert_eq!(
            impostor.subject_raw, ca.subject_raw,
            "가짜 루트는 진짜 루트와 이름이 같아야 시험이 성립한다"
        );
        let expected = vec![X509::parse(&leaf_der).unwrap().cert_sha256, ca.cert_sha256];

        for force_tls12 in [false, true] {
            let (scheme, sign) = signer_from_pkcs8_der(&leaf_key_der).unwrap();
            let server_cfg = ServerConfig {
                cert_chain: vec![leaf_der.clone(), impostor_der.clone()],
                sign_scheme: scheme,
                sign,
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
            let cfg = ClientConfig {
                server_name: "dns.example".into(),
                verify_name: true,
                roots: Some(TrustStore::from_ders([ca_der.as_slice()])),
                alpn: vec![],
                ..Default::default()
            };
            let conn = if force_tls12 {
                client_handshake_force_tls12(&mut c, &cfg)
            } else {
                client_handshake(&mut c, &cfg)
            }
            .expect("리프가 진짜 루트에 바로 닿으므로 핸드셰이크는 성공해야 한다");

            let path: Vec<[u8; 32]> = conn
                .verified_chain()
                .iter()
                .map(|cert| cert.cert_sha256)
                .collect();
            assert_eq!(
                path, expected,
                "1.2 강제 여부 {force_tls12}: 발급자 자리에는 이쪽 저장소의 루트가 와야 한다"
            );
            drop(c);
            let _ = server.join();
        }
    }

    fn mtls_ca_and_leaf(cn: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, format!("{cn} CA"));
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

    /// Keeps the bytes this side wrote.
    struct Recorded<S> {
        inner: S,
        written: Vec<u8>,
    }

    impl<S: Read> Read for Recorded<S> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read(buf)
        }
    }

    impl<S: Write> Write for Recorded<S> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = self.inner.write(buf)?;
            self.written.extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    fn last_written_record(mut wire: &[u8]) -> TlsRecord {
        let mut last = None;
        while !wire.is_empty() {
            last = Some(read_record(&mut wire).unwrap());
        }
        last.expect("쓴 레코드가 없습니다")
    }

    fn mtls_server_cfg(client_ca: Option<crate::trust::TrustStore>) -> ServerConfig {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = ck.cert.der().as_ref().to_vec();
        let key_der = ck.key_pair.serialize_der();
        let mut cfg = ServerConfig::from_pkcs8(cert_der, &key_der).unwrap();
        cfg.client_ca = client_ca;
        cfg
    }

    #[test]
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
                Err(TlsError::CertificateRequired)
            ));
            let _ = s.read_to_end(&mut Vec::new());
        });

        let mut c = TcpStream::connect(addr).unwrap();
        // Without an alert the client waits for a reply and the server for the close; the timeout
        // makes the test fail instead of hanging.
        c.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let client_cfg = insecure_test_client("localhost");

        let mut conn = client_handshake(&mut c, &client_cfg)
            .expect("클라이언트는 서버 Finished 까지 확인하고 핸드셰이크를 마친다");
        assert_eq!(
            conn.read_app(&mut c),
            Err(TlsError::PeerAlert {
                level: 2,
                description: 116,
            }),
            "서버가 응용 키로 보낸 certificate_required 를 읽어야 한다"
        );
        drop(c);
        server.join().unwrap();
    }

    #[test]
    fn mtls_rejects_untrusted_client_cert() {
        use crate::trust::TrustStore;
        let (trusted_ca, _, _) = mtls_ca_and_leaf("good.example");

        let (_other_ca, evil_leaf, evil_key) = mtls_ca_and_leaf("evil.example");
        let server_cfg = mtls_server_cfg(Some(TrustStore::from_ders([trusted_ca.as_slice()])));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            assert_eq!(
                server_handshake(&mut s, &server_cfg).err(),
                Some(TlsError::UnknownCa)
            );
        });

        let mut c = TcpStream::connect(addr).unwrap();
        let mut client_cfg = insecure_test_client("localhost");
        client_cfg.client_cert = Some(ClientCert::from_pkcs8(vec![evil_leaf], &evil_key).unwrap());
        let _ = client_handshake(&mut c, &client_cfg);
        server.join().unwrap();
    }

    #[test]
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

    #[test]
    /// Servers that enforce RFC 6066 strictly drop the handshake on an address in SNI.
    fn client_hello_names_only_host_names() {
        let kx = KeyExchange::from_seed(X25519, &[0x31; 32]).unwrap();
        let sni = |server_name: &str| {
            build_client_hello(&insecure_test_client(server_name), &kx, true, None, None)
                .ext(EXT_SERVER_NAME)
                .and_then(Extension::as_server_name)
        };
        assert_eq!(sni("192.0.2.1"), None);
        assert_eq!(sni("2001:db8::1"), None);
        assert_eq!(sni("[2001:db8::1]"), None);
        assert_eq!(sni("dns.example"), Some("dns.example".to_string()));
        assert_eq!(sni("dns.example."), Some("dns.example".to_string()));
    }

    struct Scripted {
        /// Reaching the end reads as a closed connection.
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Scripted {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A HelloRetryRequest has the same format, so it counts. The handshake then fails for lack of
    /// input, but the first record is already out.
    fn first_server_hello(cfg: &ServerConfig, client_hello: Vec<u8>) -> Option<ServerHello> {
        let mut stream = Scripted {
            input: std::io::Cursor::new(
                TlsRecord::new(ContentType::Handshake, client_hello).encode(),
            ),
            output: Vec::new(),
        };
        let _ = server_handshake(&mut stream, cfg);
        let (record, _) = TlsRecord::parse(&stream.output).ok()??;
        if record.content_type != ContentType::Handshake {
            return None;
        }
        let (message, _) = HandshakeMsg::parse(&record.fragment).ok()??;
        ServerHello::from_handshake(&message).ok()
    }

    fn withdraw_signature_scheme(hello: &mut ClientHello, scheme: u16) {
        let extension = hello
            .extensions
            .iter_mut()
            .find(|extension| extension.ext_type == EXT_SIGNATURE_ALGORITHMS)
            .expect("서명 방식 확장이 있어야 한다");
        let offered: Vec<u16> = extension
            .as_signature_algorithms()
            .unwrap()
            .into_iter()
            .filter(|offered| *offered != scheme)
            .collect();
        *extension = Extension::signature_algorithms(&offered);
    }

    #[test]
    /// Extensions this side does not parse are answered whatever they contain.
    fn server_answers_only_acceptable_client_hellos() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cfg = ServerConfig::from_pkcs8(
            ck.cert.der().as_ref().to_vec(),
            &ck.key_pair.serialize_der(),
        )
        .unwrap();
        let kx = KeyExchange::from_seed(X25519, &[0x31; 32]).unwrap();
        let client_cfg = ClientConfig {
            alpn: vec![b"dot".to_vec()],
            ..insecure_test_client("localhost")
        };
        let hello = build_client_hello(&client_cfg, &kx, true, None, None);
        let answer = |hello: &ClientHello| first_server_hello(&cfg, hello.to_handshake().encode());
        let reply = answer(&hello).expect("정상 인사말에는 답해야 한다");
        assert_ne!(
            reply.random,
            crate::msg::HRR_RANDOM,
            "키 공유가 맞으므로 다시 시도 요청이 아니어야 한다"
        );

        let mut unknown = hello.clone();
        unknown
            .extensions
            .push(Extension::new(0xfe0d, vec![0xff; 5]));
        assert!(
            answer(&unknown).is_some(),
            "해석하지 않는 확장은 내용을 보지 않아야 한다"
        );

        for extension in &hello.extensions {
            if extension.client_hello_syntax_ok().is_none() {
                continue;
            }
            let mut broken = hello.clone();
            broken
                .extensions
                .iter_mut()
                .find(|candidate| candidate.ext_type == extension.ext_type)
                .unwrap()
                .data
                .push(0);
            assert!(
                answer(&broken).is_none(),
                "확장 {}: 형식이 깨진 인사말에는 답하지 않아야 한다",
                extension.ext_type
            );
        }

        let without = |ext_type: u16| {
            let mut changed = hello.clone();
            changed
                .extensions
                .retain(|extension| extension.ext_type != ext_type);
            changed
        };
        assert!(
            answer(&without(EXT_SIGNATURE_ALGORITHMS)).is_none(),
            "재개 제안 없이 서명 방식이 빠지면 답하지 않아야 한다"
        );
        assert!(
            answer(&without(EXT_KEY_SHARE)).is_none(),
            "지원 곡선만 있고 키 공유가 빠지면 다시 시도 요청도 보내지 않아야 한다"
        );
        let mut psk_without_modes = without(EXT_PSK_KEY_EXCHANGE_MODES);
        psk_without_modes
            .extensions
            .push(Extension::pre_shared_key_client(b"ticket", 0, 32));
        assert!(
            answer(&psk_without_modes).is_none(),
            "재개 방식 없이 재개를 제안하면 답하지 않아야 한다"
        );

        let mut other_schemes = hello.clone();
        withdraw_signature_scheme(&mut other_schemes, cfg.sign_scheme);
        assert!(
            answer(&other_schemes).is_some_and(|reply| reply.random != crate::msg::HRR_RANDOM),
            "이쪽 서명 방식이 목록에 없어도 RFC 8446 대로 가진 인증서로 답해야 한다"
        );

        let mut empty_shares = hello;
        empty_shares
            .extensions
            .iter_mut()
            .find(|extension| extension.ext_type == EXT_KEY_SHARE)
            .unwrap()
            .data = vec![0, 0];
        let retry = answer(&empty_shares).expect("키 공유가 비었으면 다시 시도를 요청해야 한다");
        assert_eq!(retry.random, crate::msg::HRR_RANDOM);
        withdraw_signature_scheme(&mut empty_shares, cfg.sign_scheme);
        assert_eq!(
            answer(&empty_shares).map(|reply| reply.random),
            Some(crate::msg::HRR_RANDOM),
            "서명 방식 목록과 무관하게 다시 시도를 요청해야 한다"
        );
    }

    #[test]
    /// With shares for both groups X25519 is chosen; the retried hello must carry one share for the
    /// requested group.
    fn tls13_server_negotiates_p256_key_exchange() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cfg = ServerConfig::from_pkcs8(
            ck.cert.der().as_ref().to_vec(),
            &ck.key_pair.serialize_der(),
        )
        .unwrap();
        let x25519 = KeyExchange::from_seed(X25519, &[0x31; 32]).unwrap();
        let p256 = KeyExchange::from_seed(SECP256R1, &[0x32; 32]).unwrap();
        let share = |kx: &KeyExchange| (kx.group(), kx.public_bytes());
        let hello = |shares: Vec<(u16, Vec<u8>)>, groups: &[u16]| {
            let client_cfg = insecure_test_client("localhost");
            let mut hello = build_client_hello(&client_cfg, &x25519, true, None, None);
            for extension in &mut hello.extensions {
                match extension.ext_type {
                    EXT_KEY_SHARE => *extension = Extension::key_share_client(&shares),
                    EXT_SUPPORTED_GROUPS => *extension = Extension::supported_groups(groups),
                    _ => {}
                }
            }
            hello
        };
        let answer = |hello: &ClientHello| first_server_hello(&cfg, hello.to_handshake().encode());
        let agreed = |hello: &ClientHello, kx: &KeyExchange| {
            let reply = answer(hello).expect("ServerHello 로 답해야 한다");
            let (group, public) = reply
                .ext(EXT_KEY_SHARE)
                .and_then(Extension::as_key_share_server)
                .expect("ServerHello 의 키 조각이 있어야 한다");
            reply.random != crate::msg::HRR_RANDOM
                && group == kx.group()
                && kx.shared_secret(&public).is_some()
        };
        assert!(
            agreed(&hello(vec![share(&p256)], &[SECP256R1]), &p256),
            "P-256 조각만 보낸 인사말에는 P-256 으로 답해야 한다"
        );
        assert!(
            agreed(
                &hello(vec![share(&p256), share(&x25519)], &[SECP256R1, X25519]),
                &x25519
            ),
            "두 곡선의 조각이 모두 있으면 X25519 를 골라야 한다"
        );

        let retry = answer(&hello(Vec::new(), &[SECP256R1])).expect("다시 시도를 요청해야 한다");
        assert_eq!(retry.random, crate::msg::HRR_RANDOM);
        assert_eq!(
            retry
                .ext(EXT_KEY_SHARE)
                .and_then(Extension::as_key_share_hrr),
            Some(SECP256R1)
        );
        assert!(
            answer(&hello(Vec::new(), &[SECP384R1])).is_none(),
            "공통 곡선이 없으면 답하지 않아야 한다"
        );

        let retried = |shares| hello(shares, &[SECP256R1]);
        assert_eq!(
            retry_key_share(&retried(vec![share(&p256)]), SECP256R1),
            Ok(p256.public_bytes())
        );
        for (case, shares) in [
            ("다른 곡선", vec![share(&x25519)]),
            ("조각 둘", vec![share(&p256), share(&x25519)]),
            ("조각 없음", Vec::new()),
        ] {
            assert_eq!(
                retry_key_share(&retried(shares), SECP256R1),
                Err(TlsError::IllegalParameter),
                "재시도 인사말의 {case}"
            );
        }
    }

    #[test]
    /// Before the ServerHello neither side has handshake keys.
    fn rejected_client_hello_is_answered_with_a_plaintext_alert() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cfg = ServerConfig {
            alpn: vec![b"dot".to_vec()],
            ..ServerConfig::from_pkcs8(
                ck.cert.der().as_ref().to_vec(),
                &ck.key_pair.serialize_der(),
            )
            .unwrap()
        };
        let kx = KeyExchange::from_seed(X25519, &[0x31; 32]).unwrap();
        let hello = build_client_hello(&insecure_test_client("localhost"), &kx, true, None, None);

        let mut broken = hello.clone();
        broken
            .extensions
            .iter_mut()
            .find(|extension| extension.ext_type == EXT_KEY_SHARE)
            .unwrap()
            .data
            .push(0);
        let other_protocol = build_client_hello(
            &ClientConfig {
                alpn: vec![b"h2".to_vec()],
                ..insecure_test_client("localhost")
            },
            &kx,
            true,
            None,
            None,
        );
        let mut no_common_group = hello;
        for extension in &mut no_common_group.extensions {
            match extension.ext_type {
                EXT_SUPPORTED_GROUPS => *extension = Extension::supported_groups(&[SECP384R1]),
                EXT_KEY_SHARE => *extension = Extension::key_share_client(&[]),
                _ => {}
            }
        }

        for (hello, expected) in [
            (broken, TlsError::Decode),
            (other_protocol, TlsError::NoApplicationProtocol),
            (no_common_group, TlsError::HandshakeFailure),
        ] {
            let mut stream = Scripted {
                input: std::io::Cursor::new(
                    TlsRecord::new(ContentType::Handshake, hello.to_handshake().encode()).encode(),
                ),
                output: Vec::new(),
            };
            assert_eq!(
                server_handshake(&mut stream, &cfg).err(),
                Some(expected.clone())
            );
            let description = expected.alert().unwrap();
            assert_eq!(stream.output, [21, 3, 3, 0, 2, 2, description]);
        }
    }

    #[test]
    /// A ChangeCipherSpec before the first ClientHello and an empty handshake record are
    /// unexpected_message, plaintext over 2^14 bytes is record_overflow, and leftover bytes after
    /// the ClientHello are unexpected_message because keys change there.
    fn server_reads_plaintext_handshake_records_within_rfc_8446_limits() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cfg = ServerConfig::from_pkcs8(
            ck.cert.der().as_ref().to_vec(),
            &ck.key_pair.serialize_der(),
        )
        .unwrap();
        let kx = KeyExchange::from_seed(X25519, &[0x31; 32]).unwrap();
        let hello = build_client_hello(&insecure_test_client("localhost"), &kx, true, None, None)
            .to_handshake()
            .encode();
        let handshake =
            |fragment: Vec<u8>| TlsRecord::new(ContentType::Handshake, fragment).encode();
        for (case, input, expected) in [
            (
                "ClientHello 앞의 ChangeCipherSpec",
                [ccs_record().encode(), handshake(hello.clone())].concat(),
                TlsError::UnexpectedMessage,
            ),
            (
                "빈 핸드셰이크 레코드",
                handshake(Vec::new()),
                TlsError::UnexpectedMessage,
            ),
            (
                "2^14 바이트를 넘는 평문",
                handshake(vec![0; MAX_FRAGMENT + 1]),
                TlsError::RecordOverflow,
            ),
            (
                "ClientHello 뒤에 남은 바이트",
                handshake([hello.clone(), vec![1, 0]].concat()),
                TlsError::UnexpectedMessage,
            ),
        ] {
            let mut stream = Scripted {
                input: std::io::Cursor::new(input),
                output: Vec::new(),
            };
            assert_eq!(
                server_handshake(&mut stream, &cfg).err(),
                Some(expected.clone()),
                "{case}"
            );
            let description = expected.alert().unwrap();
            assert_eq!(stream.output, [21, 3, 3, 0, 2, 2, description], "{case}");
        }
    }

    #[test]
    /// The client checks after ServerHello and HelloRetryRequest, both sides after the peer's
    /// Finished.
    fn handshake_messages_before_a_key_change_end_at_a_record_boundary() {
        let finished = HandshakeMsg::new(HandshakeType::Finished, vec![7; 32]).encode();
        let secret = vec![0x42; Hash::Sha256.len()];
        let (key, iv) = traffic_keys(Hash::Sha256, &secret, 16);
        let read = |wire: &mut std::io::Cursor<Vec<u8>>| {
            let mut crypto = RecordCrypto::new(Aead::Aes128Gcm, key.clone(), iv12(iv.clone()));
            EncReader::new()
                .next_at_boundary(wire, &mut crypto)
                .map(|message| message.msg_type)
        };
        assert_eq!(
            read(&mut encrypted_records(&[(
                ContentType::Handshake,
                &finished
            )])),
            Ok(HandshakeType::Finished)
        );
        let trailing = [finished.as_slice(), &[20, 0]].concat();
        assert_eq!(
            read(&mut encrypted_records(&[(
                ContentType::Handshake,
                &trailing
            )])),
            Err(TlsError::UnexpectedMessage),
            "Finished 뒤에 남은 바이트"
        );

        let server_hello = |random: [u8; 32], key_share: Extension| ServerHello {
            legacy_version: TLS12,
            random,
            session_id_echo: Vec::new(),
            cipher_suite: TLS_AES_128_GCM_SHA256,
            extensions: vec![Extension::supported_versions_server(TLS13), key_share],
        };
        for (case, reply) in [
            (
                "ServerHello",
                server_hello([5; 32], Extension::key_share_server(X25519, &[9; 32])),
            ),
            (
                "다시 시도 요청",
                server_hello(crate::msg::HRR_RANDOM, Extension::key_share_hrr(SECP256R1)),
            ),
        ] {
            let fragment = [reply.to_handshake().encode(), vec![20, 0]].concat();
            let mut stream = Scripted {
                input: std::io::Cursor::new(
                    TlsRecord::new(ContentType::Handshake, fragment).encode(),
                ),
                output: Vec::new(),
            };
            assert_eq!(
                client_handshake(&mut stream, &insecure_test_client("localhost")).err(),
                Some(TlsError::UnexpectedMessage),
                "{case} 뒤에 남은 바이트"
            );
        }
    }

    #[test]
    /// A dropped connection has nowhere to send, and nothing more goes out after a fatal alert.
    fn handshake_does_not_answer_eof_io_or_peer_alerts() {
        let cfg = insecure_test_client("localhost");
        for (input, expected) in [
            (Vec::new(), TlsError::Eof),
            (vec![22, 3, 3, 0, 10, 2], TlsError::Io),
            (
                vec![21, 3, 3, 0, 2, 2, 40],
                TlsError::PeerAlert {
                    level: 2,
                    description: 40,
                },
            ),
        ] {
            let mut stream = Scripted {
                input: std::io::Cursor::new(input),
                output: Vec::new(),
            };
            assert_eq!(
                client_handshake(&mut stream, &cfg).err(),
                Some(expected.clone())
            );
            let mut written = stream.output.as_slice();
            assert!(!written.is_empty(), "ClientHello 를 보내지 않았습니다");
            while !written.is_empty() {
                let record = read_record(&mut written).unwrap();
                assert_eq!(
                    record.content_type,
                    ContentType::Handshake,
                    "{expected:?} 에 경고로 답했습니다"
                );
            }
        }
    }

    #[test]
    /// A resumption does not sign with the certificate. An empty key share can still finish as a
    /// resumption, so a retry must be requested.
    fn resumption_does_not_need_the_certificate_signature_scheme() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let ticketer = Arc::new(crate::session::Ticketer::from_key([0x5b; 32]));
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
        let mut cfg = ServerConfig::from_pkcs8(
            ck.cert.der().as_ref().to_vec(),
            &ck.key_pair.serialize_der(),
        )
        .unwrap();
        cfg.resumption = Some(ServerResumption {
            ticketer,
            lifetime_secs,
            max_early_data: 0,
        });
        let session = crate::session::TlsSession {
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
        };
        let kx = KeyExchange::from_seed(X25519, &[0x32; 32]).unwrap();
        let mut hello = build_client_hello(
            &insecure_test_client("localhost"),
            &kx,
            true,
            None,
            Some(&session),
        );
        withdraw_signature_scheme(&mut hello, cfg.sign_scheme);
        let wire = encode_client_hello(&hello, Some(&session), &[]).unwrap();
        let reply = first_server_hello(&cfg, wire).expect("재개 인사말에는 답해야 한다");
        assert!(
            reply.ext(EXT_PRE_SHARED_KEY).is_some(),
            "티켓을 받아들여 재개로 답해야 한다"
        );

        hello
            .extensions
            .iter_mut()
            .find(|extension| extension.ext_type == EXT_KEY_SHARE)
            .unwrap()
            .data = vec![0, 0];
        let wire = encode_client_hello(&hello, Some(&session), &[]).unwrap();
        let retry =
            first_server_hello(&cfg, wire).expect("재개를 제안했으면 다시 시도를 요청해야 한다");
        assert_eq!(retry.random, crate::msg::HRR_RANDOM);
    }

    #[test]
    /// The server picks its preferred suite, so a ChaCha20 ticket resumes as AES-128.
    fn tcp_resumption_needs_only_the_same_hash() {
        for (ticket_suite, resumed) in [
            (TLS_CHACHA20_POLY1305_SHA256, true),
            (TLS_AES_256_GCM_SHA384, false),
        ] {
            let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
            let ticketer = Arc::new(crate::session::Ticketer::from_key([0x5b; 32]));
            let now = crate::session::now_ms();
            let (hash, _) = suite_params(ticket_suite).unwrap();
            let psk = vec![0x33; hash.len()];
            let age_add = 0x1020_3040;
            let lifetime_secs = 60;
            let ticket = ticketer
                .seal(&crate::session::ResumptionState {
                    server_name: Some("localhost".to_string()),
                    suite: ticket_suite,
                    psk: psk.clone(),
                    alpn: None,
                    issued_ms: now,
                    age_add,
                    lifetime_secs,
                    max_early_data: 0,
                })
                .unwrap();
            let server_cfg = ServerConfig {
                resumption: Some(ServerResumption {
                    ticketer,
                    lifetime_secs,
                    max_early_data: 0,
                }),
                ..ServerConfig::from_pkcs8(
                    ck.cert.der().as_ref().to_vec(),
                    &ck.key_pair.serialize_der(),
                )
                .unwrap()
            };
            let client_cfg = ClientConfig {
                session: Some(crate::session::TlsSession {
                    server_name: "localhost".to_string(),
                    suite: ticket_suite,
                    psk,
                    ticket,
                    lifetime_secs,
                    age_add,
                    max_early_data: 0,
                    alpn: None,
                    server_transport_params: vec![],
                    obtained_at_ms: now,
                }),
                ..insecure_test_client("localhost")
            };
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                server_handshake(&mut s, &server_cfg).unwrap().is_resumed()
            });
            let mut c = TcpStream::connect(addr).unwrap();
            let conn = client_handshake(&mut c, &client_cfg).unwrap();
            assert_eq!(
                conn.is_resumed(),
                resumed,
                "클라이언트, 티켓 {ticket_suite:#06x}"
            );
            assert_eq!(
                server.join().unwrap(),
                resumed,
                "서버, 티켓 {ticket_suite:#06x}"
            );
        }
    }

    #[test]
    /// Every signature is valid and the key type matches, so only the scheme check refuses them.
    fn tcp_client_accepts_only_certificate_verify_schemes_rfc_8446_allows() {
        let (certificate, key) = crate::cert::rsa_test_certificate("localhost");
        for (scheme, expected) in [
            (RSA_PSS_RSAE_SHA256, None),
            (RSA_PKCS1_SHA256, Some(TlsError::IllegalParameter)),
            (RSA_PSS_RSAE_SHA512, Some(TlsError::IllegalParameter)),
        ] {
            let server_cfg = ServerConfig {
                cert_chain: vec![certificate.clone()],
                sign_scheme: scheme,
                sign: crate::cert::rsa_test_signer(key.clone(), scheme),
                alpn: Vec::new(),
                client_ca: None,
                resumption: None,
            };
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
                    .unwrap();
                server_handshake(&mut s, &server_cfg).err()
            });
            let mut c = TcpStream::connect(addr).unwrap();
            assert_eq!(
                client_handshake(&mut c, &insecure_test_client("localhost")).err(),
                expected,
                "서명 방식 {scheme:#06x}"
            );
            let peer_alert = expected.map(|_| TlsError::PeerAlert {
                level: 2,
                description: 47,
            });
            // The client fails before reading the server Finished; closing now would send RST
            // before the server reads the alert, so close after the server ends.
            assert_eq!(
                server.join().unwrap(),
                peer_alert,
                "서명 방식 {scheme:#06x}"
            );
            drop(c);
        }
    }

    #[test]
    /// Another group means one share for that group; a cookie alone keeps the first share and adds
    /// the cookie. The server closes after the second hello.
    fn tcp_client_follows_retry_requests_for_another_group_or_a_cookie() {
        for retry in [
            Extension::key_share_hrr(SECP256R1),
            Extension::cookie(b"retry-cookie"),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let request = retry.clone();
            let server = thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                let first = PlainHsReader::new(false).next_at_boundary(&mut s).unwrap();
                let first = ClientHello::from_handshake(&first).unwrap();
                let hrr = ServerHello {
                    legacy_version: TLS12,
                    random: crate::msg::HRR_RANDOM,
                    session_id_echo: first.session_id.clone(),
                    cipher_suite: TLS_AES_128_GCM_SHA256,
                    extensions: vec![Extension::supported_versions_server(TLS13), request],
                };
                write_record(
                    &mut s,
                    &TlsRecord::new(ContentType::Handshake, hrr.to_handshake().encode()),
                )
                .unwrap();
                let second = PlainHsReader::new(true).next_at_boundary(&mut s).unwrap();
                (first, ClientHello::from_handshake(&second).unwrap())
            });
            let mut c = TcpStream::connect(addr).unwrap();
            let result = client_handshake(&mut c, &insecure_test_client("localhost"));
            let (first, second) = server.join().unwrap();
            assert!(result.is_err(), "서버가 두 번째 인사말 뒤에 닫았다");
            assert!(second.is_valid_retry_of(&first));

            let shares = |hello: &ClientHello| {
                hello
                    .ext(EXT_KEY_SHARE)
                    .and_then(Extension::as_key_share_client)
                    .unwrap()
            };
            let cookie = second.ext(EXT_COOKIE).and_then(Extension::as_cookie);
            if retry.ext_type == EXT_KEY_SHARE {
                let [(group, public)] = shares(&second).try_into().unwrap();
                assert_eq!(group, SECP256R1);
                assert_eq!(
                    (public.len(), public[0]),
                    (65, 4),
                    "P-256 키 조각은 압축하지 않은 점이다"
                );
                assert_eq!(cookie, None);
            } else {
                assert_eq!(
                    shares(&second),
                    shares(&first),
                    "쿠키만 담은 요청에는 첫 키 조각을 그대로 보낸다"
                );
                assert_eq!(cookie, Some(b"retry-cookie".to_vec()));
            }
        }
    }

    #[test]
    fn handshake_by_address_completes_without_sni() {
        let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
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
            let req = conn.read_app(&mut s).unwrap();
            conn.write_app(&mut s, &req).unwrap();
        });
        let mut c = TcpStream::connect(addr).unwrap();
        let mut conn = client_handshake(&mut c, &insecure_test_client("127.0.0.1")).unwrap();
        conn.write_app(&mut c, b"by address").unwrap();
        assert_eq!(conn.read_app(&mut c).unwrap(), b"by address");
        server.join().unwrap();
    }

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
        HandshakeWrite::Silent.run(s, |s, w| {
            let ch_bytes = ch.to_handshake().encode();
            w.send(s, &ch_bytes)?;
            let mut phr = PlainHsReader::new(true);
            let sh_msg = phr.next(s)?;
            let sh = ServerHello::from_handshake(&sh_msg)?;
            client_handshake_tls12(s, cfg, ch, ch_bytes, sh, sh_msg, phr, w)
        })
    }

    #[test]
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
    /// A 1.2 client sends plaintext until its ChangeCipherSpec; a protected alert would be
    /// unreadable to the server.
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
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            server_handshake(&mut s, &server_cfg).err()
        });
        let mut c = Recorded {
            inner: TcpStream::connect(addr).unwrap(),
            written: Vec::new(),
        };
        let cfg = ClientConfig {
            server_name: "evil.example".into(),
            verify_name: true,
            ..Default::default()
        };

        assert_eq!(
            client_handshake_force_tls12(&mut c, &cfg).err(),
            Some(TlsError::BadCert)
        );
        let alert = last_written_record(&c.written);
        assert_eq!(alert.content_type, ContentType::Alert);
        assert_eq!(alert.fragment, [2, 42]);
        // Closing with unread server data sends RST, which can drop the connection before the
        // server reads the alert; close after the server ends.
        assert_eq!(
            server.join().unwrap(),
            Some(TlsError::PeerAlert {
                level: 2,
                description: 42,
            })
        );
        drop(c);
    }

    #[test]
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
