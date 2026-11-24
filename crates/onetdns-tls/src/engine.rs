//! Sans-IO handshake engine for QUIC: it never touches a socket. Handshake data goes in, the state
//! advances, and outgoing data and derived secrets come out.
//!
//! Separate from the blocking implementation in conn; the two share only wire primitives and keep
//! their own state machines.

use crate::cert::{
    certificate_verify_content, tls13_signature_scheme_allowed, CertEntry, CertificateMsg,
    CertificateVerify, REQUESTED_SIGNATURE_SCHEMES,
};
use crate::conn::{
    choose_server_key_share, client_config_wire_is_valid, client_key_shares, client_shared_secret,
    new_key_exchange, respond_key_exchange, retry_key_share, server_config_wire_is_valid,
    ClientConfig, ServerConfig, ServerKeyShare,
};
use crate::handshake::{HandshakeMsg, HandshakeReader, HandshakeType};
use crate::keyschedule::{
    finished_key, finished_verify_data, suite_params, Hash, KeySchedule, Transcript,
};
use crate::kx::KeyExchange;
use crate::msg::consts::*;
use crate::msg::{ClientHello, Extension, ServerHello};
use crate::sys::{fill_random, random_32};
use crate::wire::Writer;
use crate::x509::X509;
use crate::TlsError;
use std::sync::Arc;
use zeroize::Zeroizing;

pub const EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
/// Which keys protect the handshake data.
pub enum Level {
    Initial,
    Handshake,
    Application,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secret {
    pub suite: u16,
    pub secret: Vec<u8>,
}

impl Drop for Secret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretPair {
    pub level: Level,
    pub client: Secret,
    pub server: Secret,
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn choose_suite_quic(offered: &[u16]) -> Option<u16> {
    [
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    ]
    .into_iter()
    .find(|&s| offered.contains(&s))
}

/// For diagnostic logs.
fn short_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().min(32) * 2);
    for &b in bytes.iter().take(32) {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Carries the transport parameters.
fn encrypted_extensions_quic_full(
    alpn: Option<&[u8]>,
    transport_params: &[u8],
    early_data: bool,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.vec16(|w| {
        if let Some(proto) = alpn {
            Extension::alpn(&[proto]).encode_into(w);
        }
        if early_data {
            Extension::early_data().encode_into(w);
        }
        Extension::new(EXT_QUIC_TRANSPORT_PARAMETERS, transport_params.to_vec()).encode_into(w);
    });
    w.buf
}

/// Rejects duplicates and non-canonical forms.
fn parse_ee_extensions(body: &[u8]) -> Result<Vec<Extension>, TlsError> {
    Extension::parse_vector(body)
}

#[derive(PartialEq, Eq)]
enum SState {
    ExpectClientHello,
    ExpectClientCertificate,
    ExpectClientCertVerify,
    ExpectClientFinished,
    Done,
}

pub struct ServerHandshake {
    /// Shared, so certificates and trust stores are not copied per connection.
    cfg: Arc<ServerConfig>,
    local_tp: Vec<u8>,
    hr: HandshakeReader,
    /// Bytes of the previous level were left when the receive level changed; they cannot be read at
    /// the new level.
    stranded_input: bool,
    state: SState,

    hash: Hash,
    suite: u16,
    client_hs_secret: Vec<u8>,

    transcript: Option<Transcript>,

    ks: Option<KeySchedule>,

    client_cert: Option<X509>,

    resumed: bool,

    early_accepted: bool,

    early_secret_out: Option<Secret>,

    /// Sent with HelloRetryRequest, so the server need not keep state.
    hrr_cookie: Option<Vec<u8>>,
    /// Transcript prefix up to the retry.
    hrr_prefix: Option<Vec<u8>>,
    hrr_suite: Option<u16>,
    hrr_group: Option<u16>,
    hrr_client_hello: Option<ClientHello>,

    out_initial: Vec<u8>,
    out_handshake: Vec<u8>,

    out_application: Vec<u8>,
    pending_secrets: Vec<SecretPair>,
    peer_tp: Option<Vec<u8>>,
    alpn: Option<Vec<u8>>,
    /// Client SNI bound into tickets.
    server_name: Option<String>,
    client_allows_resumption: bool,
}

impl Drop for ServerHandshake {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.client_hs_secret.zeroize();
    }
}

impl ServerHandshake {
    pub fn new(cfg: Arc<ServerConfig>, local_transport_params: Vec<u8>) -> Self {
        Self {
            cfg,
            local_tp: local_transport_params,
            hr: HandshakeReader::new(),
            stranded_input: false,
            state: SState::ExpectClientHello,
            hash: Hash::Sha256,
            suite: 0,
            client_hs_secret: Vec::new(),
            transcript: None,
            ks: None,
            client_cert: None,
            resumed: false,
            early_accepted: false,
            early_secret_out: None,
            hrr_cookie: None,
            hrr_prefix: None,
            hrr_suite: None,
            hrr_group: None,
            hrr_client_hello: None,
            out_initial: Vec::new(),
            out_handshake: Vec::new(),
            out_application: Vec::new(),
            pending_secrets: Vec::new(),
            peer_tp: None,
            alpn: None,
            server_name: None,
            client_allows_resumption: false,
        }
    }

    /// Mutable handshake payload bytes this connection holds. The QUIC listener's global memory
    /// budget uses it to stop input amplification across connections. The shared ServerConfig is
    /// one per generation, so it is not counted here.
    pub fn retained_payload_bytes(&self) -> usize {
        let mut total = self
            .local_tp
            .capacity()
            .saturating_add(self.hr.retained_payload_bytes())
            .saturating_add(self.client_hs_secret.capacity())
            .saturating_add(
                self.transcript
                    .as_ref()
                    .map_or(0, Transcript::retained_payload_bytes),
            )
            .saturating_add(
                self.ks
                    .as_ref()
                    .map_or(0, KeySchedule::retained_payload_bytes),
            )
            .saturating_add(
                self.client_cert
                    .as_ref()
                    .map_or(0, X509::retained_payload_bytes),
            )
            .saturating_add(self.hrr_cookie.as_ref().map_or(0, Vec::capacity))
            .saturating_add(self.hrr_prefix.as_ref().map_or(0, Vec::capacity))
            .saturating_add(
                self.hrr_client_hello
                    .as_ref()
                    .map_or(0, ClientHello::retained_payload_bytes),
            )
            .saturating_add(self.out_initial.capacity())
            .saturating_add(self.out_handshake.capacity())
            .saturating_add(self.out_application.capacity())
            .saturating_add(
                self.pending_secrets
                    .capacity()
                    .saturating_mul(std::mem::size_of::<SecretPair>()),
            )
            .saturating_add(self.peer_tp.as_ref().map_or(0, Vec::capacity))
            .saturating_add(self.alpn.as_ref().map_or(0, Vec::capacity))
            .saturating_add(self.server_name.as_ref().map_or(0, String::capacity));
        if let Some(secret) = &self.early_secret_out {
            total = total.saturating_add(secret.secret.capacity());
        }
        for pair in &self.pending_secrets {
            total = total
                .saturating_add(pair.client.secret.capacity())
                .saturating_add(pair.server.secret.capacity());
        }
        total
    }

    /// `level` is the encryption level the data arrived at. Bytes of the same level left after a
    /// message that changes the receive level are kept unprocessed; RFC 9001 makes that a
    /// PROTOCOL_VIOLATION connection error, so the caller checks `has_unconsumed_input` and closes.
    /// Calling again in that state is refused.
    ///
    /// UnexpectedMessage for data not at the current receive level, or when bytes of the previous
    /// level remain.
    pub fn provide(&mut self, level: Level, data: &[u8]) -> Result<(), TlsError> {
        if !server_config_wire_is_valid(&self.cfg) || self.local_tp.len() > u16::MAX as usize {
            return Err(TlsError::Internal);
        }
        if self.stranded_input || level != self.receive_level() {
            return Err(TlsError::UnexpectedMessage);
        }
        self.hr.feed(data);
        while let Some(msg) = self.hr.next_message()? {
            match self.state {
                SState::ExpectClientHello => self.on_client_hello(&msg)?,
                SState::ExpectClientCertificate => self.on_client_certificate(&msg)?,
                SState::ExpectClientCertVerify => self.on_client_cert_verify(&msg)?,
                SState::ExpectClientFinished => self.on_client_finished(&msg)?,
                SState::Done => return Err(TlsError::UnexpectedMessage),
            }
            if self.receive_level() != level {
                self.stranded_input = self.hr.has_pending();
                break;
            }
        }
        Ok(())
    }

    pub fn receive_level(&self) -> Level {
        match self.state {
            SState::ExpectClientHello => Level::Initial,
            SState::ExpectClientCertificate
            | SState::ExpectClientCertVerify
            | SState::ExpectClientFinished => Level::Handshake,
            SState::Done => Level::Application,
        }
    }

    pub fn has_unconsumed_input(&self) -> bool {
        self.hr.has_pending()
    }

    /// `suite` is the suite chosen now. RFC 8446 lets suites with the same hash share a PSK, but
    /// early data is accepted only with the ticket's own suite. Returns the accepted ticket and
    /// whether early data can be accepted.
    ///
    /// The binder is verified; without that, mimicking a ticket would resume someone else's
    /// session.
    fn try_accept_psk(
        &self,
        ch: &ClientHello,
        ch_msg: &HandshakeMsg,
        suite: u16,
        negotiated_alpn: &Option<Vec<u8>>,
        binder_prefix: &[u8],
    ) -> Result<Option<(crate::session::ResumptionState, bool)>, TlsError> {
        let Some(res) = &self.cfg.resumption else {
            return Ok(None);
        };
        let (hash, _) = suite_params(suite).ok_or(TlsError::Internal)?;
        if self.cfg.client_ca.is_some() {
            return Ok(None);
        }

        let modes_ok = ch
            .ext(EXT_PSK_KEY_EXCHANGE_MODES)
            .and_then(|e| e.as_psk_modes())
            .is_some_and(|m| m.contains(&PSK_DHE_KE));
        let Some(ext) = ch.ext(EXT_PRE_SHARED_KEY) else {
            return Ok(None);
        };
        if !modes_ok {
            return Ok(None);
        }
        let Some((ids, binders)) = ext.as_pre_shared_key_client() else {
            return Ok(None);
        };
        let (Some((identity, obf_age)), Some(binder)) = (ids.first(), binders.first()) else {
            return Ok(None);
        };

        let Some(state) = res.ticketer.open(identity) else {
            return Ok(None);
        };
        if state.server_name != ch.ext(EXT_SERVER_NAME).and_then(Extension::as_server_name)
            || state.alpn != *negotiated_alpn
            || state.hash() != Some(hash)
        {
            return Ok(None);
        }

        let full = ch_msg.encode();
        let binders_len = 2 + binders.iter().map(|b| 1 + b.len()).sum::<usize>();
        if full.len() <= binders_len {
            return Ok(None);
        }
        let truncated = &full[..full.len() - binders_len];
        let mut binder_transcript = Transcript::new(hash);
        binder_transcript.update(binder_prefix);
        binder_transcript.update(truncated);
        let ks_early = KeySchedule::new_with_psk(hash, &state.psk);
        let expect = ks_early.psk_binder(&binder_transcript.hash());
        if !crate::keyschedule::ct_eq(&expect, binder) {
            return Err(TlsError::BadSignature);
        }

        let now = crate::session::now_ms();
        let server_age = now.saturating_sub(state.issued_ms);
        let client_age = obf_age.wrapping_sub(state.age_add) as u64;
        if server_age > state.lifetime_secs as u64 * 1000
            || client_age.abs_diff(server_age) > 10_000
        {
            return Ok(None);
        }

        let early_ok = ch.ext(EXT_EARLY_DATA).is_some()
            && res.max_early_data > 0
            && state.max_early_data > 0
            && state.suite == suite;
        Ok(Some((state, early_ok)))
    }

    /// Sends HelloRetryRequest only when the retried hello can finish the handshake. A retried
    /// hello cannot change supported groups or ALPN, so a hello with no common group or with
    /// mismatched ALPN is refused at the first hello. When the client's signature algorithms omit
    /// this side's scheme, the handshake continues with the certificate at hand, as RFC 8446
    /// allows.
    ///
    /// NoApplicationProtocol when this side uses ALPN and nothing was agreed; RFC 9001 makes ALPN
    /// mandatory for QUIC.
    fn on_client_hello(&mut self, ch_msg: &HandshakeMsg) -> Result<(), TlsError> {
        let ch = ClientHello::from_handshake(ch_msg)?;
        ch.validate_tls13()?;
        if ch.ext(EXT_QUIC_TRANSPORT_PARAMETERS).is_none() {
            return Err(TlsError::MissingExtension);
        }
        let server_name = ch.ext(EXT_SERVER_NAME).and_then(Extension::as_server_name);
        if self
            .server_name
            .as_ref()
            .is_some_and(|expected| Some(expected) != server_name.as_ref())
        {
            return Err(TlsError::IllegalParameter);
        }
        self.server_name = server_name;
        if let Some(first) = self.hrr_client_hello.take() {
            if !ch.is_valid_retry_of(&first) {
                return Err(TlsError::IllegalParameter);
            }
        } else if ch.ext(EXT_COOKIE).is_some() {
            return Err(TlsError::IllegalParameter);
        }
        self.peer_tp = ch
            .ext(EXT_QUIC_TRANSPORT_PARAMETERS)
            .map(|e| e.data.clone());
        let negotiated_alpn = ch.select_alpn(&self.cfg.alpn)?;
        if !self.cfg.alpn.is_empty() && negotiated_alpn.is_none() {
            return Err(TlsError::NoApplicationProtocol);
        }

        let (group, client_pub) = match self.hrr_group.take() {
            Some(group) => {
                let echoed = ch
                    .ext(EXT_COOKIE)
                    .ok_or(TlsError::MissingExtension)?
                    .as_cookie()
                    .ok_or(TlsError::Decode)?;
                if self.hrr_cookie.as_deref() != Some(&echoed[..]) {
                    return Err(TlsError::IllegalParameter);
                }
                (group, retry_key_share(&ch, group)?)
            }
            None => match choose_server_key_share(&ch)? {
                ServerKeyShare::Offered { group, public } => (group, public),
                ServerKeyShare::Retry(group) => {
                    let suite =
                        choose_suite_quic(&ch.cipher_suites).ok_or(TlsError::HandshakeFailure)?;
                    let (hash, _) = suite_params(suite).ok_or(TlsError::Internal)?;
                    let cookie = random_32().to_vec();
                    let mut t = Transcript::new(hash);
                    t.update(&ch_msg.encode());
                    t.replace_with_message_hash();
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
                    self.out_initial.extend_from_slice(&hrr_msg.encode());
                    t.update(&hrr_msg.encode());
                    self.hrr_prefix = Some(t.as_bytes().to_vec());
                    self.hrr_suite = Some(suite);
                    self.hrr_group = Some(group);
                    self.hrr_cookie = Some(cookie);
                    self.hrr_client_hello = Some(ch);
                    return Ok(());
                }
            },
        };

        self.alpn = negotiated_alpn.clone();
        self.client_allows_resumption = ch
            .ext(EXT_PSK_KEY_EXCHANGE_MODES)
            .and_then(Extension::as_psk_modes)
            .is_some_and(|modes| modes.contains(&PSK_DHE_KE));

        let suite = self
            .hrr_suite
            .or_else(|| choose_suite_quic(&ch.cipher_suites))
            .ok_or(TlsError::HandshakeFailure)?;
        let (hash, _key_len) = suite_params(suite).ok_or(TlsError::Internal)?;
        let psk = self.try_accept_psk(
            &ch,
            ch_msg,
            suite,
            &negotiated_alpn,
            self.hrr_prefix.as_deref().unwrap_or_default(),
        )?;
        let resumed = psk.is_some();
        if !resumed && ch.ext(EXT_SIGNATURE_ALGORITHMS).is_none() {
            return Err(TlsError::MissingExtension);
        }

        let mut transcript = Transcript::new(hash);
        if let Some(prefix) = self.hrr_prefix.take() {
            transcript.update(&prefix);
        }
        transcript.update(&ch_msg.encode());

        if let Some((state, early_ok)) = &psk {
            if *early_ok {
                let ks_early = KeySchedule::new_with_psk(hash, &state.psk);
                let cets = ks_early.client_early_traffic_secret(&transcript.hash());
                self.early_secret_out = Some(Secret {
                    suite,
                    secret: cets,
                });
                self.early_accepted = true;
            }
        }

        let (server_share, shared) = respond_key_exchange(group, &client_pub)?;
        let mut sh_extensions = vec![
            Extension::supported_versions_server(TLS13),
            Extension::key_share_server(group, &server_share),
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
        self.out_initial.extend_from_slice(&sh_msg.encode());
        transcript.update(&sh_msg.encode());

        let mut ks = match &psk {
            Some((state, _)) => KeySchedule::new_with_psk(hash, &state.psk),
            None => KeySchedule::new(hash),
        };
        ks.enter_handshake(&shared);
        let th = transcript.hash();
        let chs = ks.client_handshake_traffic_secret(&th);
        let shs = Zeroizing::new(ks.server_handshake_traffic_secret(&th));
        self.pending_secrets.push(SecretPair {
            level: Level::Handshake,
            client: Secret {
                suite,
                secret: chs.clone(),
            },
            server: Secret {
                suite,
                secret: shs.to_vec(),
            },
        });

        let ee = HandshakeMsg::new(
            HandshakeType::EncryptedExtensions,
            encrypted_extensions_quic_full(
                negotiated_alpn.as_deref(),
                &self.local_tp,
                self.early_accepted,
            ),
        );
        self.out_handshake.extend_from_slice(&ee.encode());
        transcript.update(&ee.encode());

        if !resumed {
            if self.cfg.client_ca.is_some() {
                let cr = HandshakeMsg::new(
                    HandshakeType::CertificateRequest,
                    crate::cert::CertificateRequestMsg::standard().encode(),
                );
                self.out_handshake.extend_from_slice(&cr.encode());
                transcript.update(&cr.encode());
            }

            let cert = CertificateMsg {
                request_context: vec![],
                entries: self
                    .cfg
                    .cert_chain
                    .iter()
                    .map(|der| CertEntry {
                        cert_data: der.clone(),
                        extensions: vec![],
                    })
                    .collect(),
            };
            let cert_msg = HandshakeMsg::new(HandshakeType::Certificate, cert.encode());
            self.out_handshake.extend_from_slice(&cert_msg.encode());
            transcript.update(&cert_msg.encode());

            let cv_content = certificate_verify_content(&transcript.hash(), true);
            let cv = CertificateVerify {
                algorithm: self.cfg.sign_scheme,
                signature: (self.cfg.sign)(&cv_content),
            };
            let cv_msg = HandshakeMsg::new(HandshakeType::CertificateVerify, cv.encode());
            self.out_handshake.extend_from_slice(&cv_msg.encode());
            transcript.update(&cv_msg.encode());
        }

        let sfk = Zeroizing::new(finished_key(hash, &shs));
        let sfin = finished_verify_data(hash, &sfk, &transcript.hash());
        let fin_msg = HandshakeMsg::new(HandshakeType::Finished, sfin);
        self.out_handshake.extend_from_slice(&fin_msg.encode());
        transcript.update(&fin_msg.encode());

        ks.enter_master();
        let th_after = transcript.hash();
        let cap = ks.client_application_traffic_secret(&th_after);
        let sap = ks.server_application_traffic_secret(&th_after);
        self.pending_secrets.push(SecretPair {
            level: Level::Application,
            client: Secret { suite, secret: cap },
            server: Secret { suite, secret: sap },
        });

        self.hash = hash;
        self.suite = suite;
        self.resumed = resumed;
        self.client_hs_secret = chs;
        self.transcript = Some(transcript);
        self.ks = Some(ks);
        self.state = if !resumed && self.cfg.client_ca.is_some() {
            SState::ExpectClientCertificate
        } else {
            SState::ExpectClientFinished
        };
        Ok(())
    }

    fn on_client_certificate(&mut self, msg: &HandshakeMsg) -> Result<(), TlsError> {
        if msg.msg_type != HandshakeType::Certificate {
            return Err(TlsError::UnexpectedMessage);
        }
        let ccert = CertificateMsg::parse(&msg.body)?;

        if ccert.entries.is_empty() {
            return Err(TlsError::CertificateRequired);
        }
        let chain: Vec<X509> = ccert
            .entries
            .iter()
            .map(|e| X509::parse(&e.cert_data))
            .collect::<Result<_, _>>()?;
        let store = self.cfg.client_ca.as_ref().ok_or(TlsError::Internal)?;
        crate::trust::verify_client_chain(&chain, store, now_epoch())?;
        self.client_cert = Some(chain.first().ok_or(TlsError::Internal)?.clone());
        let transcript = self.transcript.as_mut().ok_or(TlsError::Internal)?;
        transcript.update(&msg.encode());
        self.state = SState::ExpectClientCertVerify;
        Ok(())
    }

    fn on_client_cert_verify(&mut self, msg: &HandshakeMsg) -> Result<(), TlsError> {
        if msg.msg_type != HandshakeType::CertificateVerify {
            return Err(TlsError::UnexpectedMessage);
        }
        let transcript = self.transcript.as_mut().ok_or(TlsError::Internal)?;
        let th_before_cv = transcript.hash();
        let cv = CertificateVerify::parse(&msg.body)?;
        let certificate = self.client_cert.as_ref().ok_or(TlsError::Internal)?;
        let cv_content = certificate_verify_content(&th_before_cv, false);
        cv.verify_tls13(certificate, &REQUESTED_SIGNATURE_SCHEMES, &cv_content)?;
        transcript.update(&msg.encode());
        self.state = SState::ExpectClientFinished;
        Ok(())
    }

    /// The last check against a forged handshake; compared in constant time.
    fn on_client_finished(&mut self, fin_msg: &HandshakeMsg) -> Result<(), TlsError> {
        let transcript = self.transcript.as_mut().ok_or(TlsError::Internal)?;
        let cfk = Zeroizing::new(finished_key(self.hash, &self.client_hs_secret));
        fin_msg.verify_finished(&finished_verify_data(self.hash, &cfk, &transcript.hash()))?;
        transcript.update(&fin_msg.encode());
        self.state = SState::Done;

        if let Some(res) = self.cfg.resumption.clone() {
            if self.cfg.client_ca.is_none()
                && self.client_allows_resumption
                && res.lifetime_secs > 0
            {
                let th_fin = self.transcript.as_ref().ok_or(TlsError::Internal)?.hash();
                let ks = self.ks.as_ref().ok_or(TlsError::Internal)?;
                let res_master = Zeroizing::new(ks.resumption_master_secret(&th_fin));
                let mut nonce = [0u8; 8];
                fill_random(&mut nonce);
                let psk = crate::keyschedule::resumption_psk(self.hash, &res_master, &nonce);
                let mut age4 = [0u8; 4];
                fill_random(&mut age4);
                let age_add = u32::from_be_bytes(age4);
                let state = crate::session::ResumptionState {
                    server_name: self.server_name.clone(),
                    suite: self.suite,
                    psk,
                    alpn: self.alpn.clone(),
                    issued_ms: crate::session::now_ms(),
                    age_add,
                    lifetime_secs: res.lifetime_secs,
                    max_early_data: res.max_early_data,
                };
                let ticket = res.ticketer.seal(&state).ok_or(TlsError::Internal)?;
                let mut extensions = Vec::new();
                if res.max_early_data > 0 {
                    extensions.push(Extension::early_data_nst(res.max_early_data));
                }
                let nst = crate::msg::NewSessionTicket {
                    lifetime_secs: res.lifetime_secs,
                    age_add,
                    nonce: nonce.to_vec(),
                    ticket,
                    extensions,
                };
                let msg = HandshakeMsg::new(HandshakeType::NewSessionTicket, nst.encode());
                self.out_application.extend_from_slice(&msg.encode());
            }
        }
        Ok(())
    }

    pub fn take_crypto(&mut self) -> Vec<(Level, Vec<u8>)> {
        let mut out = Vec::new();
        if !self.out_initial.is_empty() {
            out.push((Level::Initial, std::mem::take(&mut self.out_initial)));
        }
        if !self.out_handshake.is_empty() {
            out.push((Level::Handshake, std::mem::take(&mut self.out_handshake)));
        }
        if !self.out_application.is_empty() {
            out.push((
                Level::Application,
                std::mem::take(&mut self.out_application),
            ));
        }
        out
    }

    pub fn take_secrets(&mut self) -> Vec<SecretPair> {
        std::mem::take(&mut self.pending_secrets)
    }

    pub fn take_early_secret(&mut self) -> Option<Secret> {
        self.early_secret_out.take()
    }

    pub fn is_resumed(&self) -> bool {
        self.resumed
    }

    pub fn early_data_accepted(&self) -> bool {
        self.early_accepted
    }

    pub fn peer_transport_params(&self) -> Option<&[u8]> {
        self.peer_tp.as_deref()
    }

    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    pub fn client_authenticated(&self) -> bool {
        self.state == SState::Done && self.cfg.client_ca.is_some() && self.client_cert.is_some()
    }

    pub fn client_auth_identity(&self) -> Option<String> {
        self.client_cert
            .as_ref()
            .map(|certificate| format!("mtls:{}", short_hex(&certificate.public_key)))
    }

    pub fn is_complete(&self) -> bool {
        self.state == SState::Done
    }
}

#[derive(PartialEq, Eq)]
enum CState {
    ExpectServerHello,
    ExpectFlight,
    Done,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CFlightState {
    EncryptedExtensions,
    CertificateOrRequest,
    Certificate,
    CertificateVerify,
    Finished,
}

pub struct ClientHandshake {
    cfg: ClientConfig,
    /// The key shares the last hello sent.
    shares: Vec<KeyExchange>,
    /// The transcript up to the ServerHello. After a HelloRetryRequest it holds the first hello's
    /// hash, the request, and the second hello.
    ch_wire: Vec<u8>,
    /// The last hello sent; the server's reply is checked against it.
    hello: ClientHello,
    hr: HandshakeReader,
    /// Bytes of the previous level were left when the receive level changed; they cannot be read at
    /// the new level.
    stranded_input: bool,
    state: CState,
    flight_state: CFlightState,
    transcript: Option<Transcript>,
    ks: Option<KeySchedule>,
    hash: Hash,
    suite: u16,
    client_hs_secret: Vec<u8>,
    server_hs_secret: Vec<u8>,
    leaf_cert: Option<X509>,

    /// Schemes the server accepts when it asks for a client certificate; None when it did not ask.
    requested_schemes: Option<Vec<u16>>,

    seen_cert_verify: bool,

    psk_session: Option<crate::session::TlsSession>,
    psk_accepted: bool,
    early_offered: bool,
    early_accepted: bool,

    early_secret_out: Option<Secret>,

    res_master: Vec<u8>,

    new_sessions: Vec<crate::session::TlsSession>,

    /// A second HelloRetryRequest would loop forever.
    hrr_done: bool,
    out_initial: Vec<u8>,
    out_handshake: Vec<u8>,
    pending_secrets: Vec<SecretPair>,
    peer_tp: Option<Vec<u8>>,
    alpn: Option<Vec<u8>>,
    verified_chain: Vec<X509>,
}

impl Drop for ClientHandshake {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.client_hs_secret.zeroize();
        self.server_hs_secret.zeroize();
        self.res_master.zeroize();
    }
}

impl ClientHandshake {
    pub fn new(cfg: ClientConfig, local_transport_params: Vec<u8>) -> Result<Self, TlsError> {
        if !client_config_wire_is_valid(&cfg) || local_transport_params.len() > u16::MAX as usize {
            return Err(TlsError::Internal);
        }
        let shares = client_key_shares(cfg.send_key_share)?;
        let session = cfg
            .session
            .clone()
            .filter(|s| s.is_fresh(crate::session::now_ms()) && suite_params(s.suite).is_some());

        let key_shares: Vec<(u16, Vec<u8>)> = shares
            .iter()
            .map(|kx| (kx.group(), kx.public_bytes()))
            .collect();
        let mut extensions = vec![
            Extension::supported_versions_client(&[TLS13]),
            Extension::supported_groups(&[X25519MLKEM768, X25519]),
            Extension::signature_algorithms(&[
                ED25519,
                ECDSA_SECP256R1_SHA256,
                MLDSA44,
                RSA_PSS_RSAE_SHA256,
                RSA_PKCS1_SHA256,
            ]),
            Extension::key_share_client(&key_shares),
        ];
        if let Some(host) = cfg.sni() {
            extensions.push(Extension::server_name(host));
        }
        extensions.push(Extension::new(
            EXT_QUIC_TRANSPORT_PARAMETERS,
            local_transport_params,
        ));
        extensions.push(Extension::psk_key_exchange_modes(&[PSK_DHE_KE]));
        if !cfg.alpn.is_empty() {
            let protos: Vec<&[u8]> = cfg.alpn.iter().map(|v| v.as_slice()).collect();
            extensions.push(Extension::alpn(&protos));
        }

        let mut early_offered = false;
        if let Some(s) = &session {
            let alpn_same = s.alpn.is_none() || cfg.alpn.first() == s.alpn.as_ref();
            if cfg.enable_early_data && s.max_early_data > 0 && alpn_same {
                extensions.push(Extension::early_data());
                early_offered = true;
            }
            let (h, _) = suite_params(s.suite).ok_or(TlsError::Internal)?;
            extensions.push(Extension::pre_shared_key_client(
                &s.ticket,
                s.obfuscated_age(crate::session::now_ms()),
                h.len(),
            ));
        }

        let mut cipher_suites = vec![
            TLS_AES_128_GCM_SHA256,
            TLS_AES_256_GCM_SHA384,
            TLS_CHACHA20_POLY1305_SHA256,
        ];
        if let Some(s) = &session {
            cipher_suites.retain(|cs| *cs != s.suite);
            cipher_suites.insert(0, s.suite);
        }
        let ch = ClientHello {
            legacy_version: TLS12,
            random: random_32(),

            session_id: Vec::new(),

            cipher_suites,
            compression_methods: vec![0],
            extensions,
        };
        let mut ch_wire = ch.to_handshake().encode();

        let mut early_secret_out = None;
        if let Some(s) = &session {
            let (h, _) = suite_params(s.suite).ok_or(TlsError::Internal)?;
            let binders_len = 2 + 1 + h.len();
            if ch_wire.len() <= binders_len {
                return Err(TlsError::Internal);
            }
            let truncated_hash = h.digest(&ch_wire[..ch_wire.len() - binders_len]);
            let ks_early = KeySchedule::new_with_psk(h, &s.psk);
            let binder = ks_early.psk_binder(&truncated_hash);
            let at = ch_wire.len() - h.len();
            ch_wire[at..].copy_from_slice(&binder);

            if early_offered {
                let cets = ks_early.client_early_traffic_secret(&h.digest(&ch_wire));
                early_secret_out = Some(Secret {
                    suite: s.suite,
                    secret: cets,
                });
            }
        }

        Ok(Self {
            cfg,
            shares,
            out_initial: ch_wire.clone(),
            ch_wire,
            hello: ch,
            hr: HandshakeReader::new(),
            stranded_input: false,
            state: CState::ExpectServerHello,
            flight_state: CFlightState::EncryptedExtensions,
            transcript: None,
            ks: None,
            hash: Hash::Sha256,
            suite: 0,
            client_hs_secret: Vec::new(),
            server_hs_secret: Vec::new(),
            leaf_cert: None,
            requested_schemes: None,
            seen_cert_verify: false,
            psk_session: session,
            psk_accepted: false,
            early_offered,
            early_accepted: false,
            early_secret_out,
            res_master: Vec::new(),
            new_sessions: Vec::new(),
            hrr_done: false,
            out_handshake: Vec::new(),
            pending_secrets: Vec::new(),
            peer_tp: None,
            alpn: None,
            verified_chain: Vec::new(),
        })
    }

    /// Same rules as the server's `provide`: bytes left after a message that changes the receive
    /// level stay unprocessed, and the caller checks `has_unconsumed_input` and closes.
    ///
    /// UnexpectedMessage for data not at the current receive level, or when bytes of the previous
    /// level remain.
    pub fn provide(&mut self, level: Level, data: &[u8]) -> Result<(), TlsError> {
        if self.stranded_input || level != self.receive_level() {
            return Err(TlsError::UnexpectedMessage);
        }
        self.hr.feed(data);
        while let Some(msg) = self.hr.next_message()? {
            match self.state {
                CState::ExpectServerHello => self.on_server_hello(&msg)?,
                CState::ExpectFlight => self.on_flight_msg(&msg)?,
                CState::Done => self.on_post_handshake(&msg)?,
            }
            if self.receive_level() != level {
                self.stranded_input = self.hr.has_pending();
                break;
            }
        }
        Ok(())
    }

    pub fn receive_level(&self) -> Level {
        match self.state {
            CState::ExpectServerHello => Level::Initial,
            CState::ExpectFlight => Level::Handshake,
            CState::Done => Level::Application,
        }
    }

    pub fn has_unconsumed_input(&self) -> bool {
        self.hr.has_pending()
    }

    /// A request naming a group gets a new key share for it; a cookie-only request keeps the
    /// earlier key shares and adds the cookie. PSK offers whose hash differs from the chosen suite
    /// are dropped.
    ///
    /// Accepted only once; a second one is rejected, so a server cannot make the client retry
    /// forever. The transcript is replaced with its hash as the spec requires.
    fn on_hello_retry(&mut self, hrr: &HandshakeMsg, sh: &ServerHello) -> Result<(), TlsError> {
        if self.hrr_done {
            return Err(TlsError::UnexpectedMessage);
        }
        let retry_group = sh.validate_retry_request(&self.hello)?;
        let cookie = match sh.ext(EXT_COOKIE) {
            Some(extension) => Some(extension.as_cookie().ok_or(TlsError::Decode)?),
            None => None,
        };
        let (hash, _) = suite_params(sh.cipher_suite).ok_or(TlsError::IllegalParameter)?;
        let first_ch = &self.hello;
        if !first_ch.cipher_suites.contains(&sh.cipher_suite) {
            return Err(TlsError::IllegalParameter);
        }

        let mut t = Transcript::new(hash);
        t.update(&self.ch_wire);
        t.replace_with_message_hash();
        t.update(&hrr.encode());

        if self
            .psk_session
            .as_ref()
            .is_some_and(|session| session.hash() != Some(hash))
        {
            self.psk_session = None;
        }
        if let Some(group) = retry_group {
            self.shares = vec![new_key_exchange(group)?];
        }
        let key_shares: Vec<(u16, Vec<u8>)> = self
            .shares
            .iter()
            .map(|kx| (kx.group(), kx.public_bytes()))
            .collect();
        let mut extensions = Vec::with_capacity(first_ch.extensions.len() + 1);
        for extension in &first_ch.extensions {
            match extension.ext_type {
                EXT_KEY_SHARE => extensions.push(Extension::key_share_client(&key_shares)),
                EXT_EARLY_DATA | EXT_COOKIE | EXT_PRE_SHARED_KEY => {}
                _ => extensions.push(extension.clone()),
            }
        }
        if let Some(c) = &cookie {
            extensions.push(Extension::cookie(c));
        }
        if let Some(session) = &self.psk_session {
            extensions.push(Extension::pre_shared_key_client(
                &session.ticket,
                session.obfuscated_age(crate::session::now_ms()),
                hash.len(),
            ));
        }
        let ch2 = ClientHello {
            legacy_version: first_ch.legacy_version,
            random: first_ch.random,
            session_id: first_ch.session_id.clone(),
            cipher_suites: first_ch.cipher_suites.clone(),
            compression_methods: first_ch.compression_methods.clone(),
            extensions,
        };
        let mut ch2_wire = ch2.to_handshake().encode();
        if let Some(session) = &self.psk_session {
            let binders_len = 2 + 1 + hash.len();
            if ch2_wire.len() <= binders_len {
                return Err(TlsError::Internal);
            }
            let mut binder_transcript = Transcript::new(hash);
            binder_transcript.update(t.as_bytes());
            binder_transcript.update(&ch2_wire[..ch2_wire.len() - binders_len]);
            let schedule = KeySchedule::new_with_psk(hash, &session.psk);
            let binder = schedule.psk_binder(&binder_transcript.hash());
            let at = ch2_wire.len() - hash.len();
            ch2_wire[at..].copy_from_slice(&binder);
        }
        t.update(&ch2_wire);

        self.ch_wire = t.as_bytes().to_vec();
        self.out_initial.extend_from_slice(&ch2_wire);
        self.hello = ch2;

        self.early_offered = false;
        self.early_secret_out = None;
        self.hrr_done = true;
        self.suite = sh.cipher_suite;
        Ok(())
    }

    fn on_server_hello(&mut self, sh_msg: &HandshakeMsg) -> Result<(), TlsError> {
        let sh = ServerHello::from_handshake(sh_msg)?;

        if sh.random == crate::msg::HRR_RANDOM {
            return self.on_hello_retry(sh_msg, &sh);
        }
        sh.validate_tls13(&self.hello, false)?;
        let suite = sh.cipher_suite;
        if self.hrr_done && self.suite != suite {
            return Err(TlsError::IllegalParameter);
        }
        let (hash, _key_len) = suite_params(suite).ok_or(TlsError::IllegalParameter)?;
        let shared = client_shared_secret(&self.shares, &sh)?;

        let psk_accepted = match sh.ext(EXT_PRE_SHARED_KEY) {
            None => false,
            Some(extension) => {
                let selected = extension
                    .as_pre_shared_key_server()
                    .ok_or(TlsError::Decode)?;
                let session = self
                    .psk_session
                    .as_ref()
                    .ok_or(TlsError::UnsupportedExtension)?;
                if selected != 0 || session.hash() != Some(hash) {
                    return Err(TlsError::IllegalParameter);
                }
                true
            }
        };

        let mut transcript = Transcript::new(hash);
        transcript.update(&self.ch_wire);
        transcript.update(&sh_msg.encode());

        let mut ks = if psk_accepted {
            let psk = &self.psk_session.as_ref().ok_or(TlsError::Internal)?.psk;
            KeySchedule::new_with_psk(hash, psk)
        } else {
            KeySchedule::new(hash)
        };
        ks.enter_handshake(&shared);
        let th = transcript.hash();
        let chs = ks.client_handshake_traffic_secret(&th);
        let shs = ks.server_handshake_traffic_secret(&th);
        self.pending_secrets.push(SecretPair {
            level: Level::Handshake,
            client: Secret {
                suite,
                secret: chs.clone(),
            },
            server: Secret {
                suite,
                secret: shs.clone(),
            },
        });

        self.hash = hash;
        self.suite = suite;
        self.psk_accepted = psk_accepted;
        self.client_hs_secret = chs;
        self.server_hs_secret = shs;
        self.transcript = Some(transcript);
        self.ks = Some(ks);
        self.state = CState::ExpectFlight;
        Ok(())
    }

    fn on_flight_msg(&mut self, msg: &HandshakeMsg) -> Result<(), TlsError> {
        let transcript = self.transcript.as_mut().ok_or(TlsError::Internal)?;
        match msg.msg_type {
            HandshakeType::EncryptedExtensions => {
                if self.flight_state != CFlightState::EncryptedExtensions {
                    return Err(TlsError::UnexpectedMessage);
                }
                let mut peer_tp = None;
                for extension in parse_ee_extensions(&msg.body)? {
                    match extension.ext_type {
                        EXT_QUIC_TRANSPORT_PARAMETERS => peer_tp = Some(extension.data),
                        EXT_ALPN => self.alpn = Some(extension.selected_alpn(&self.cfg.alpn)?),
                        EXT_EARLY_DATA => {
                            if !self.early_offered {
                                return Err(TlsError::UnsupportedExtension);
                            }
                            if !extension.data.is_empty() {
                                return Err(TlsError::Decode);
                            }
                            self.early_accepted = true;
                        }
                        EXT_SERVER_NAME => {
                            if self.hello.ext(EXT_SERVER_NAME).is_none() {
                                return Err(TlsError::UnsupportedExtension);
                            }
                            if !extension.data.is_empty() {
                                return Err(TlsError::Decode);
                            }
                        }
                        EXT_SUPPORTED_GROUPS => {
                            extension.as_supported_groups().ok_or(TlsError::Decode)?;
                        }
                        other if self.hello.ext(other).is_some() => {
                            return Err(TlsError::IllegalParameter)
                        }
                        _ => return Err(TlsError::UnsupportedExtension),
                    }
                }
                if !self.cfg.alpn.is_empty() && self.alpn.is_none() {
                    return Err(TlsError::NoApplicationProtocol);
                }
                // A resumed session must use the same application protocol as when it was first
                // made. Early data can be accepted only when resuming with the ticket's own suite,
                // as RFC 8446 requires.
                let session = self.psk_session.as_ref().filter(|_| self.psk_accepted);
                if session.is_some_and(|session| session.alpn != self.alpn)
                    || (self.early_accepted
                        && session.is_none_or(|session| session.suite != self.suite))
                {
                    return Err(TlsError::IllegalParameter);
                }
                self.peer_tp = Some(peer_tp.ok_or(TlsError::MissingExtension)?);
                self.flight_state = if self.psk_accepted {
                    CFlightState::Finished
                } else {
                    CFlightState::CertificateOrRequest
                };
                transcript.update(&msg.encode());
                Ok(())
            }
            HandshakeType::CertificateRequest => {
                if self.flight_state != CFlightState::CertificateOrRequest {
                    return Err(TlsError::UnexpectedMessage);
                }
                let request = crate::cert::CertificateRequestMsg::parse(&msg.body)?;
                self.requested_schemes = Some(request.handshake_signature_algorithms()?);
                self.flight_state = CFlightState::Certificate;
                transcript.update(&msg.encode());
                Ok(())
            }
            HandshakeType::Certificate => {
                if !matches!(
                    self.flight_state,
                    CFlightState::CertificateOrRequest | CFlightState::Certificate
                ) {
                    return Err(TlsError::UnexpectedMessage);
                }
                let cert = CertificateMsg::parse(&msg.body)?;
                let leaf = cert.leaf().ok_or(TlsError::Decode)?;
                let x = X509::parse(leaf)?;

                self.verified_chain = match &self.cfg.roots {
                    Some(store) => {
                        let chain: Vec<X509> = cert
                            .entries
                            .iter()
                            .map(|e| X509::parse(&e.cert_data))
                            .collect::<Result<_, _>>()?;
                        crate::trust::verify_chain(
                            &chain,
                            store,
                            &self.cfg.server_name,
                            now_epoch(),
                        )?
                    }
                    None => {
                        if self.cfg.insecure_verifier.is_none() {
                            return Err(TlsError::BadCert);
                        }
                        if self.cfg.verify_name && !x.matches_hostname(&self.cfg.server_name) {
                            return Err(TlsError::BadCert);
                        }
                        Vec::new()
                    }
                };
                self.leaf_cert = Some(x);
                self.flight_state = CFlightState::CertificateVerify;
                transcript.update(&msg.encode());
                Ok(())
            }
            HandshakeType::CertificateVerify => {
                if self.flight_state != CFlightState::CertificateVerify {
                    return Err(TlsError::UnexpectedMessage);
                }
                let th_before_cv = transcript.hash();
                let cv = CertificateVerify::parse(&msg.body)?;
                let certificate = self.leaf_cert.as_ref().ok_or(TlsError::Internal)?;
                let cv_content = certificate_verify_content(&th_before_cv, true);
                cv.verify_tls13(certificate, &self.hello.signature_algorithms(), &cv_content)?;
                self.seen_cert_verify = true;
                self.flight_state = CFlightState::Finished;
                transcript.update(&msg.encode());
                Ok(())
            }
            HandshakeType::Finished => {
                if self.flight_state != CFlightState::Finished
                    || (!self.psk_accepted && !self.seen_cert_verify)
                {
                    return Err(TlsError::UnexpectedMessage);
                }
                let sfk = Zeroizing::new(finished_key(self.hash, &self.server_hs_secret));
                msg.verify_finished(&finished_verify_data(self.hash, &sfk, &transcript.hash()))?;
                transcript.update(&msg.encode());
                let th_after = transcript.hash();

                if let Some(requested) = &self.requested_schemes {
                    // If the key's scheme is one the server does not accept, reply with an empty
                    // Certificate instead. RFC 8446 has clients without a suitable certificate do
                    // this, and the server decides whether to continue.
                    let client_cert = self
                        .cfg
                        .client_cert
                        .as_ref()
                        .filter(|cc| tls13_signature_scheme_allowed(cc.sign_scheme, requested));
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
                    self.out_handshake.extend_from_slice(&cert_hs.encode());
                    transcript.update(&cert_hs.encode());
                    if let Some(cc) = client_cert {
                        let content = certificate_verify_content(&transcript.hash(), false);
                        let cv = CertificateVerify {
                            algorithm: cc.sign_scheme,
                            signature: (cc.sign)(&content),
                        };
                        let cv_hs =
                            HandshakeMsg::new(HandshakeType::CertificateVerify, cv.encode());
                        self.out_handshake.extend_from_slice(&cv_hs.encode());
                        transcript.update(&cv_hs.encode());
                    }
                }

                let cfk = Zeroizing::new(finished_key(self.hash, &self.client_hs_secret));
                let cfin = finished_verify_data(self.hash, &cfk, &transcript.hash());
                let fin_msg = HandshakeMsg::new(HandshakeType::Finished, cfin);
                self.out_handshake.extend_from_slice(&fin_msg.encode());
                transcript.update(&fin_msg.encode());
                let th_client_fin = transcript.hash();

                let ks = self.ks.as_mut().ok_or(TlsError::Internal)?;
                ks.enter_master();
                let cap = ks.client_application_traffic_secret(&th_after);
                let sap = ks.server_application_traffic_secret(&th_after);

                self.res_master = ks.resumption_master_secret(&th_client_fin);
                self.pending_secrets.push(SecretPair {
                    level: Level::Application,
                    client: Secret {
                        suite: self.suite,
                        secret: cap,
                    },
                    server: Secret {
                        suite: self.suite,
                        secret: sap,
                    },
                });
                self.state = CState::Done;
                Ok(())
            }
            _ => Err(TlsError::UnexpectedMessage),
        }
    }

    /// Session tickets arrive here.
    fn on_post_handshake(&mut self, msg: &HandshakeMsg) -> Result<(), TlsError> {
        match msg.msg_type {
            HandshakeType::NewSessionTicket => {
                let nst = crate::msg::NewSessionTicket::parse(&msg.body)?;
                if self.res_master.is_empty() || nst.lifetime_secs == 0 {
                    return Ok(());
                }
                let psk =
                    crate::keyschedule::resumption_psk(self.hash, &self.res_master, &nst.nonce);
                self.new_sessions.push(crate::session::TlsSession {
                    server_name: self.cfg.server_name.clone(),
                    suite: self.suite,
                    psk,
                    ticket: nst.ticket.clone(),
                    lifetime_secs: nst
                        .lifetime_secs
                        .min(crate::session::MAX_TICKET_LIFETIME_SECS),
                    age_add: nst.age_add,
                    max_early_data: nst.max_early_data(),
                    alpn: self.alpn.clone(),
                    server_transport_params: self.peer_tp.clone().unwrap_or_default(),
                    obtained_at_ms: crate::session::now_ms(),
                });
                Ok(())
            }
            _ => Err(TlsError::UnexpectedMessage),
        }
    }

    pub fn take_crypto(&mut self) -> Vec<(Level, Vec<u8>)> {
        let mut out = Vec::new();
        if !self.out_initial.is_empty() {
            out.push((Level::Initial, std::mem::take(&mut self.out_initial)));
        }
        if !self.out_handshake.is_empty() {
            out.push((Level::Handshake, std::mem::take(&mut self.out_handshake)));
        }
        out
    }

    pub fn take_secrets(&mut self) -> Vec<SecretPair> {
        std::mem::take(&mut self.pending_secrets)
    }

    pub fn take_early_secret(&mut self) -> Option<Secret> {
        self.early_secret_out.take()
    }

    pub fn is_resumed(&self) -> bool {
        self.psk_accepted
    }

    pub fn early_data_accepted(&self) -> bool {
        self.early_accepted
    }

    pub fn take_sessions(&mut self) -> Vec<crate::session::TlsSession> {
        std::mem::take(&mut self.new_sessions)
    }

    pub fn peer_transport_params(&self) -> Option<&[u8]> {
        self.peer_tp.as_deref()
    }

    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// From the leaf to this side's stored root. Empty for resumed connections and when the
    /// certificate was not verified. Take the leaf's issuer from this path, not from the chain the
    /// server sent.
    pub fn verified_chain(&self) -> &[X509] {
        &self.verified_chain
    }

    pub fn is_complete(&self) -> bool {
        self.state == CState::Done
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdig_gnutls_client_hello_produces_server_hello() {
        fn unhex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        let ch_wire = unhex("01000152030373c67427c6b2c1c098088176799beb520c0fe6eacadb08e91a61293356a5cdd90000081302130313011304010001210039003c0f1401fe406eefb89ce19ac3f4e60e199bf31a56fed90508ffffffffffffffff0408ffffffffffffffff0b0243e80102538811080000000100000001002d000302010000170000000500050100000000002b0003020304ff01000100001c00024001000b00020100000a000a0008001d001700180019000d00220020040108090804040308070501080a0805050308080601080b08060603020102030033006b0069001d0020715352b8da70c372eaad650b085d39b492052afcc8cd1210fb700d301e73110c0017004104f94eccac641524772d8d098b30afda56d38a6a7d043824537d906b3c5ccdd66895c057ce35c1016cce7f6351714017c375b8a93e0a90f9cb2c9b8eedc53431f0002300000016000000100006000403646f71");

        let mut server = ServerHandshake::new(
            Arc::new(make_server_cfg(vec![b"doq".to_vec()])),
            b"stp".to_vec(),
        );
        server
            .provide(Level::Initial, &ch_wire)
            .expect("kdig CH 수용");
        let flight = server.take_crypto();
        assert!(
            !flight.is_empty(),
            "kdig CH에 서버가 아무 crypto도 내지 않았다. DoQ 무응답의 근본 원인"
        );

        let initial: Vec<u8> = flight
            .iter()
            .filter(|(l, _)| *l == Level::Initial)
            .flat_map(|(_, d)| d.clone())
            .collect();
        assert!(
            !initial.is_empty(),
            "Initial 레벨 출력 없음(ServerHello 미생성)"
        );
        assert_eq!(
            initial[0], 0x02,
            "첫 핸드셰이크 메시지가 ServerHello(0x02)가 아님"
        );
    }

    #[test]
    fn encrypted_extensions_are_canonical_and_first() {
        let valid = encrypted_extensions_quic_full(Some(b"doq"), b"tp", false);
        assert!(parse_ee_extensions(&valid).is_ok());
        let mut trailing = valid;
        trailing.push(0);
        assert!(parse_ee_extensions(&trailing).is_err());

        let mut server = ServerHandshake::new(
            Arc::new(make_server_cfg(vec![b"doq".to_vec()])),
            b"stp".to_vec(),
        );
        let client_cfg = ClientConfig {
            server_name: "localhost".to_string(),
            alpn: vec![b"doq".to_vec()],
            ..insecure_test_client()
        };
        let mut client = ClientHandshake::new(client_cfg, b"ctp".to_vec()).unwrap();
        for (level, data) in client.take_crypto() {
            server.provide(level, &data).unwrap();
        }
        let flight = server.take_crypto();
        client.provide(flight[0].0, &flight[0].1).unwrap();
        let mut reader = HandshakeReader::new();
        reader.feed(&flight[1].1);
        let mut certificate_message = None;
        while let Some(message) = reader.next_message().unwrap() {
            if message.msg_type == HandshakeType::Certificate {
                certificate_message = Some(message);
                break;
            }
        }
        let certificate_message = certificate_message.unwrap().encode();
        assert_eq!(
            client.provide(Level::Handshake, &certificate_message),
            Err(TlsError::UnexpectedMessage),
            "암호화된 확장보다 먼저 온 인증서는 unexpected_message 다"
        );
    }

    #[test]
    /// No SNI is sent when connecting by address, and RFC 8446 requires aborting on a reply to an
    /// extension that was not sent.
    fn server_name_reply_requires_an_offered_name() {
        for (server_name, offered) in [("localhost", true), ("127.0.0.1", false)] {
            let mut server = ServerHandshake::new(
                Arc::new(make_server_cfg(vec![b"doq".to_vec()])),
                b"stp".to_vec(),
            );
            let client_cfg = ClientConfig {
                server_name: server_name.to_string(),
                alpn: vec![b"doq".to_vec()],
                ..insecure_test_client()
            };
            let mut client = ClientHandshake::new(client_cfg, b"ctp".to_vec()).unwrap();
            let initial = client.take_crypto();
            let mut reader = HandshakeReader::new();
            reader.feed(&initial[0].1);
            let hello = ClientHello::parse(&reader.next_message().unwrap().unwrap().body).unwrap();
            assert_eq!(
                hello.ext(EXT_SERVER_NAME).is_some(),
                offered,
                "{server_name}"
            );
            for (level, data) in initial {
                server.provide(level, &data).unwrap();
            }
            let flight = server.take_crypto();
            client.provide(flight[0].0, &flight[0].1).unwrap();

            let mut reader = HandshakeReader::new();
            reader.feed(&flight[1].1);
            let ee = reader.next_message().unwrap().unwrap();
            assert_eq!(ee.msg_type, HandshakeType::EncryptedExtensions);
            let mut extensions = parse_ee_extensions(&ee.body).unwrap();
            extensions.push(Extension::new(EXT_SERVER_NAME, Vec::new()));
            let mut body = Writer::new();
            body.vec16(|w| {
                extensions
                    .iter()
                    .for_each(|extension| extension.encode_into(w))
            });
            let reply = HandshakeMsg::new(HandshakeType::EncryptedExtensions, body.buf).encode();
            assert_eq!(
                client.provide(Level::Handshake, &reply),
                if offered {
                    Ok(())
                } else {
                    Err(TlsError::UnsupportedExtension)
                },
                "{server_name}"
            );
        }
    }

    #[test]
    /// illegal_parameter when an offered extension appears where it cannot, unsupported_extension
    /// when it was not offered, missing_extension when transport parameters are absent.
    fn encrypted_extensions_rejections_name_the_matching_alert() {
        let cfg = Arc::new(make_server_cfg(vec![b"doq".to_vec()]));
        let reply = |edit: &dyn Fn(&mut Vec<Extension>)| {
            let mut server = ServerHandshake::new(Arc::clone(&cfg), b"stp".to_vec());
            let client_cfg = ClientConfig {
                server_name: "localhost".to_string(),
                alpn: vec![b"doq".to_vec()],
                ..insecure_test_client()
            };
            let mut client = ClientHandshake::new(client_cfg, b"ctp".to_vec()).unwrap();
            for (level, data) in client.take_crypto() {
                server.provide(level, &data).unwrap();
            }
            let flight = server.take_crypto();
            client.provide(flight[0].0, &flight[0].1).unwrap();
            let mut reader = HandshakeReader::new();
            reader.feed(&flight[1].1);
            let ee = reader.next_message().unwrap().unwrap();
            let mut extensions = parse_ee_extensions(&ee.body).unwrap();
            edit(&mut extensions);
            let mut body = Writer::new();
            body.vec16(|w| {
                extensions
                    .iter()
                    .for_each(|extension| extension.encode_into(w))
            });
            let ee = HandshakeMsg::new(HandshakeType::EncryptedExtensions, body.buf);
            client.provide(Level::Handshake, &ee.encode())
        };

        assert_eq!(reply(&|_| {}), Ok(()), "고치지 않은 확장은 받아들여야 한다");
        assert_eq!(
            reply(&|extensions| {
                extensions.retain(|extension| extension.ext_type != EXT_QUIC_TRANSPORT_PARAMETERS)
            }),
            Err(TlsError::MissingExtension),
            "전송 매개변수가 빠지면 missing_extension 이다"
        );
        assert_eq!(
            reply(&|extensions| extensions.push(Extension::early_data())),
            Err(TlsError::UnsupportedExtension),
            "제안하지 않은 조기 데이터 수락은 unsupported_extension 이다"
        );
        assert_eq!(
            reply(&|extensions| extensions.push(Extension::key_share_server(X25519, &[7; 32]))),
            Err(TlsError::IllegalParameter),
            "인사말에 보낸 키 공유가 암호화된 확장에 오면 illegal_parameter 다"
        );
        assert_eq!(
            reply(&|extensions| extensions.push(Extension::new(0x1234, Vec::new()))),
            Err(TlsError::UnsupportedExtension),
            "제안하지 않은 확장은 unsupported_extension 이다"
        );
        assert_eq!(
            reply(&|extensions| extensions.push(Extension::new(EXT_SUPPORTED_GROUPS, vec![0, 1]))),
            Err(TlsError::Decode),
            "형식이 깨진 지원 곡선은 decode_error 다"
        );
        assert_eq!(
            reply(&|extensions| {
                for extension in extensions.iter_mut() {
                    if extension.ext_type == EXT_ALPN {
                        *extension = Extension::alpn(&[b"h3".as_slice()]);
                    }
                }
            }),
            Err(TlsError::IllegalParameter),
            "제안하지 않은 프로토콜을 고르면 illegal_parameter 다"
        );
    }

    #[test]
    /// A hello whose signature algorithms omit this side's scheme is answered with the certificate
    /// at hand, as RFC 8446 allows.
    fn quic_server_answers_only_acceptable_client_hellos() {
        let client_cfg = ClientConfig {
            server_name: "localhost".to_string(),
            alpn: vec![b"doq".to_vec()],
            ..insecure_test_client()
        };
        let mut client = ClientHandshake::new(client_cfg, b"ctp".to_vec()).unwrap();
        let initial = client.take_crypto();
        let mut reader = HandshakeReader::new();
        reader.feed(&initial[0].1);
        let hello = ClientHello::parse(&reader.next_message().unwrap().unwrap().body).unwrap();

        let cfg = Arc::new(make_server_cfg(vec![b"doq".to_vec()]));
        let answer = |hello: &ClientHello| {
            let mut server = ServerHandshake::new(Arc::clone(&cfg), b"stp".to_vec());
            let accepted = server
                .provide(Level::Initial, &hello.to_handshake().encode())
                .is_ok();
            (accepted, !server.take_crypto().is_empty())
        };
        assert_eq!(answer(&hello), (true, true), "정상 인사말에는 답해야 한다");

        let mut broken_share = hello.clone();
        broken_share
            .extensions
            .iter_mut()
            .find(|extension| extension.ext_type == EXT_KEY_SHARE)
            .unwrap()
            .data
            .push(0);
        assert_eq!(
            answer(&broken_share),
            (false, false),
            "키 공유가 깨진 인사말에는 다시 시도 요청도 보내지 않아야 한다"
        );

        let other_schemes = |hello: &ClientHello| {
            let mut changed = hello.clone();
            let signature_algorithms = changed
                .extensions
                .iter_mut()
                .find(|extension| extension.ext_type == EXT_SIGNATURE_ALGORITHMS)
                .unwrap();
            let offered: Vec<u16> = signature_algorithms
                .as_signature_algorithms()
                .unwrap()
                .into_iter()
                .filter(|scheme| *scheme != cfg.sign_scheme)
                .collect();
            *signature_algorithms = Extension::signature_algorithms(&offered);
            changed
        };
        assert_eq!(
            answer(&other_schemes(&hello)),
            (true, true),
            "이쪽 서명 방식이 목록에 없어도 가진 인증서로 답해야 한다"
        );

        let mut empty_shares = hello;
        empty_shares
            .extensions
            .iter_mut()
            .find(|extension| extension.ext_type == EXT_KEY_SHARE)
            .unwrap()
            .data = vec![0, 0];
        assert_eq!(
            answer(&empty_shares),
            (true, true),
            "키 공유가 비었으면 다시 시도를 요청해야 한다"
        );
        assert_eq!(
            answer(&other_schemes(&empty_shares)),
            (true, true),
            "서명 방식 목록과 무관하게 다시 시도를 요청해야 한다"
        );
    }

    fn test_hrr(suite: u16) -> HandshakeMsg {
        ServerHello {
            legacy_version: TLS12,
            random: crate::msg::HRR_RANDOM,
            session_id_echo: Vec::new(),
            cipher_suite: suite,
            extensions: vec![
                Extension::supported_versions_server(TLS13),
                Extension::key_share_hrr(X25519),
            ],
        }
        .to_handshake()
    }

    #[test]
    /// Each with the alert RFC 8446 sets.
    fn quic_client_rejects_redundant_hrr_and_suite_change() {
        let normal_cfg = ClientConfig {
            server_name: "localhost".to_string(),
            ..insecure_test_client()
        };
        let mut normal = ClientHandshake::new(normal_cfg, b"tp".to_vec()).unwrap();
        assert_eq!(
            normal.provide(Level::Initial, &test_hrr(TLS_AES_128_GCM_SHA256).encode()),
            Err(TlsError::IllegalParameter),
            "이미 키 조각을 보낸 곡선을 고른 요청은 illegal_parameter 다"
        );

        let retried = || {
            let retry_cfg = ClientConfig {
                server_name: "localhost".to_string(),
                send_key_share: false,
                ..insecure_test_client()
            };
            let mut retry = ClientHandshake::new(retry_cfg, b"tp".to_vec()).unwrap();
            retry
                .provide(Level::Initial, &test_hrr(TLS_AES_128_GCM_SHA256).encode())
                .unwrap();
            let _ = retry.take_crypto();
            retry
        };
        assert_eq!(
            retried().provide(Level::Initial, &test_hrr(TLS_AES_128_GCM_SHA256).encode()),
            Err(TlsError::UnexpectedMessage),
            "두 번째 다시 시도 요청은 unexpected_message 다"
        );

        let mut retry = retried();
        let changed = ServerHello {
            legacy_version: TLS12,
            random: [9; 32],
            session_id_echo: Vec::new(),
            cipher_suite: TLS_AES_256_GCM_SHA384,
            extensions: vec![
                Extension::supported_versions_server(TLS13),
                Extension::key_share_server(X25519, &[7; 32]),
            ],
        }
        .to_handshake();
        assert_eq!(
            retry.provide(Level::Initial, &changed.encode()),
            Err(TlsError::IllegalParameter),
            "다시 시도 요청과 다른 스위트를 고른 서버 인사말은 illegal_parameter 다"
        );
    }
    use p256::pkcs8::DecodePrivateKey;
    use std::sync::Arc;

    fn make_server_cfg(alpn: Vec<Vec<u8>>) -> ServerConfig {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = ck.cert.der().as_ref().to_vec();
        let key_der = ck.key_pair.serialize_der();
        let signing =
            p256::ecdsa::SigningKey::from(p256::SecretKey::from_pkcs8_der(&key_der).unwrap());
        ServerConfig {
            cert_chain: vec![cert_der],
            sign_scheme: ECDSA_SECP256R1_SHA256,
            sign: Arc::new(move |content| {
                use p256::ecdsa::{signature::Signer, Signature};
                let sig: Signature = signing.sign(content);
                sig.to_der().as_bytes().to_vec()
            }),
            alpn,
            client_ca: None,
            resumption: None,
        }
    }

    #[test]
    fn server_handshake_retains_shared_server_config() {
        let config = Arc::new(make_server_cfg(vec![b"doq".to_vec()]));
        let certificate = config.cert_chain[0].as_ptr();
        let handshake = ServerHandshake::new(config.clone(), b"transport".to_vec());

        assert!(Arc::ptr_eq(&handshake.cfg, &config));
        assert_eq!(handshake.cfg.cert_chain[0].as_ptr(), certificate);
        assert_eq!(Arc::strong_count(&config), 2);
    }

    /// Test only; not on any production path.
    fn insecure_test_client() -> ClientConfig {
        ClientConfig {
            roots: None,
            insecure_verifier: Some(
                crate::conn::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            ..Default::default()
        }
    }

    fn pump(from: &mut Vec<(Level, Vec<u8>)>, to_provide: &mut dyn FnMut(Level, &[u8])) {
        for (lvl, data) in from.drain(..) {
            to_provide(lvl, &data);
        }
    }

    #[test]
    fn quic_engine_full_handshake_matches_secrets() {
        let server_tp = b"\x01\x02SERVER-TRANSPORT-PARAMS".to_vec();
        let client_tp = b"\x03\x04client-transport-params".to_vec();

        let mut server = ServerHandshake::new(
            Arc::new(make_server_cfg(vec![b"doq".to_vec()])),
            server_tp.clone(),
        );
        let client_cfg = ClientConfig {
            server_name: "localhost".to_string(),
            verify_name: true,
            roots: None,
            insecure_verifier: Some(
                crate::conn::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![b"doq".to_vec()],
            ..Default::default()
        };
        let mut client = ClientHandshake::new(client_cfg, client_tp.clone()).unwrap();

        let mut server_secrets: Vec<SecretPair> = Vec::new();
        let mut client_secrets: Vec<SecretPair> = Vec::new();

        let mut c_out = client.take_crypto();
        assert_eq!(c_out.len(), 1);
        assert_eq!(c_out[0].0, Level::Initial);
        {
            let mut f = |lvl: Level, d: &[u8]| server.provide(lvl, d).expect("server provide CH");
            pump(&mut c_out, &mut f);
        }
        server_secrets.extend(server.take_secrets());

        let mut s_out = server.take_crypto();
        assert_eq!(s_out.len(), 2);
        assert_eq!(s_out[0].0, Level::Initial);
        assert_eq!(s_out[1].0, Level::Handshake);
        {
            let mut f =
                |lvl: Level, d: &[u8]| client.provide(lvl, d).expect("client provide flight");
            pump(&mut s_out, &mut f);
        }
        client_secrets.extend(client.take_secrets());

        let mut c_out2 = client.take_crypto();
        assert_eq!(c_out2.len(), 1);
        assert_eq!(c_out2[0].0, Level::Handshake);
        {
            let mut f = |lvl: Level, d: &[u8]| server.provide(lvl, d).expect("server provide fin");
            pump(&mut c_out2, &mut f);
        }

        assert!(server.is_complete(), "서버 핸드셰이크 완료");
        assert!(client.is_complete(), "클라 핸드셰이크 완료");

        assert_eq!(server.peer_transport_params(), Some(client_tp.as_slice()));
        assert_eq!(client.peer_transport_params(), Some(server_tp.as_slice()));

        assert_eq!(server.alpn(), Some(b"doq".as_slice()));
        assert_eq!(client.alpn(), Some(b"doq".as_slice()));

        let s_app = server_secrets
            .iter()
            .find(|p| p.level == Level::Application)
            .unwrap();
        let c_app = client_secrets
            .iter()
            .find(|p| p.level == Level::Application)
            .unwrap();
        assert_eq!(s_app, c_app, "application 트래픽 시크릿 일치");

        let s_hs = server_secrets
            .iter()
            .find(|p| p.level == Level::Handshake)
            .unwrap();
        let c_hs = client_secrets
            .iter()
            .find(|p| p.level == Level::Handshake)
            .unwrap();
        assert_eq!(s_hs, c_hs, "handshake 트래픽 시크릿 일치");

        assert_eq!(s_app.client.suite, TLS_AES_128_GCM_SHA256);
    }

    #[test]
    fn quic_engine_rejects_wrong_hostname() {
        let mut server = ServerHandshake::new(Arc::new(make_server_cfg(vec![])), b"tp".to_vec());
        let client_cfg = ClientConfig {
            server_name: "evil.example".to_string(),
            verify_name: true,
            roots: None,
            insecure_verifier: Some(
                crate::conn::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![],
            ..Default::default()
        };
        let mut client = ClientHandshake::new(client_cfg, b"tp".to_vec()).unwrap();

        let mut c_out = client.take_crypto();
        for (lvl, d) in c_out.drain(..) {
            server.provide(lvl, &d).unwrap();
        }

        let mut s_out = server.take_crypto();
        let mut err = None;
        for (lvl, d) in s_out.drain(..) {
            if let Err(e) = client.provide(lvl, &d) {
                err = Some(e);
            }
        }
        assert_eq!(err, Some(TlsError::BadCert));
        assert!(!client.is_complete());
    }

    #[test]
    /// RFC 9001 makes ALPN mandatory for QUIC. The server ends it when there is no overlap or the
    /// client sent no ALPN; the client ends it when the server picked none.
    fn quic_engine_alpn_mismatch_is_no_application_protocol() {
        let client_hello = |alpn: Vec<Vec<u8>>| {
            let cfg = ClientConfig {
                server_name: "localhost".to_string(),
                alpn,
                ..insecure_test_client()
            };
            let mut client = ClientHandshake::new(cfg, b"c".to_vec()).unwrap();
            let (level, hello) = client.take_crypto().remove(0);
            assert_eq!(level, Level::Initial);
            (client, hello)
        };
        let server = |alpn: Vec<Vec<u8>>| {
            ServerHandshake::new(Arc::new(make_server_cfg(alpn)), b"s".to_vec())
        };

        let (_, hello) = client_hello(vec![b"doq".to_vec()]);
        assert_eq!(
            server(vec![b"h3".to_vec()]).provide(Level::Initial, &hello),
            Err(TlsError::NoApplicationProtocol),
            "겹치는 프로토콜이 없다"
        );
        let (_, hello) = client_hello(Vec::new());
        assert_eq!(
            server(vec![b"doq".to_vec()]).provide(Level::Initial, &hello),
            Err(TlsError::NoApplicationProtocol),
            "클라이언트가 ALPN 을 보내지 않았다"
        );

        let (mut client, hello) = client_hello(vec![b"doq".to_vec()]);
        let mut silent_server = server(Vec::new());
        silent_server.provide(Level::Initial, &hello).unwrap();
        let result = silent_server
            .take_crypto()
            .into_iter()
            .try_for_each(|(level, data)| client.provide(level, &data));
        assert_eq!(
            result,
            Err(TlsError::NoApplicationProtocol),
            "서버가 프로토콜을 고르지 않았다"
        );
    }

    #[test]
    fn quic_engine_mtls_client_auth() {
        use crate::conn::ClientCert;
        use crate::trust::TrustStore;
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(vec!["client.example".to_string()]).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

        let mut scfg = make_server_cfg(vec![b"doq".to_vec()]);
        scfg.client_ca = Some(TrustStore::from_ders([ca_cert.der().as_ref()]));
        let mut server = ServerHandshake::new(Arc::new(scfg), b"stp".to_vec());

        let client_cfg = ClientConfig {
            server_name: "localhost".to_string(),
            verify_name: true,
            roots: None,
            insecure_verifier: Some(
                crate::conn::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![b"doq".to_vec()],
            client_cert: Some(
                ClientCert::from_pkcs8(vec![leaf_cert.der().to_vec()], &leaf_key.serialize_der())
                    .unwrap(),
            ),
            ..Default::default()
        };
        let mut client = ClientHandshake::new(client_cfg, b"ctp".to_vec()).unwrap();

        for (lvl, d) in client.take_crypto().drain(..) {
            server.provide(lvl, &d).unwrap();
        }
        let server_secrets = server.take_secrets();

        for (lvl, d) in server.take_crypto().drain(..) {
            client.provide(lvl, &d).unwrap();
        }
        let client_secrets = client.take_secrets();

        for (lvl, d) in client.take_crypto().drain(..) {
            server.provide(lvl, &d).unwrap();
        }
        assert!(server.is_complete(), "mTLS 서버 완료");
        assert!(client.is_complete(), "mTLS 클라 완료");
        let s_app = server_secrets
            .iter()
            .find(|p| p.level == Level::Application)
            .unwrap();
        let c_app = client_secrets
            .iter()
            .find(|p| p.level == Level::Application)
            .unwrap();
        assert_eq!(s_app, c_app, "mTLS에서도 app 시크릿 일치");
    }

    #[test]
    /// Even when the peer appends a fake root with the same name after a leaf the root issued
    /// directly.
    fn quic_engine_verified_chain_ends_at_the_stored_root() {
        use crate::trust::TrustStore;
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

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

        let (sign_scheme, sign) =
            crate::conn::signer_from_pkcs8_der(&leaf_key.serialize_der()).unwrap();
        let scfg = ServerConfig {
            cert_chain: vec![leaf_der.clone(), impostor_der],
            sign_scheme,
            sign,
            alpn: vec![b"doq".to_vec()],
            client_ca: None,
            resumption: None,
        };
        let mut server = ServerHandshake::new(Arc::new(scfg), b"stp".to_vec());
        let client_cfg = ClientConfig {
            server_name: "dns.example".to_string(),
            verify_name: true,
            roots: Some(TrustStore::from_ders([ca_cert.der().as_ref()])),
            alpn: vec![b"doq".to_vec()],
            ..Default::default()
        };
        let mut client = ClientHandshake::new(client_cfg, b"ctp".to_vec()).unwrap();
        run_handshake(&mut server, &mut client);
        assert!(
            client.is_complete(),
            "리프가 진짜 루트에 바로 닿으므로 완료해야 한다"
        );

        let path: Vec<[u8; 32]> = client
            .verified_chain()
            .iter()
            .map(|cert| cert.cert_sha256)
            .collect();
        let expected = vec![
            X509::parse(&leaf_der).unwrap().cert_sha256,
            X509::parse(ca_cert.der()).unwrap().cert_sha256,
        ];
        assert_eq!(
            path, expected,
            "발급자 자리에는 이쪽 저장소의 루트가 와야 한다"
        );
    }

    #[test]
    fn quic_engine_mtls_rejects_missing_cert() {
        use crate::trust::TrustStore;
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let mut scfg = make_server_cfg(vec![]);
        scfg.client_ca = Some(TrustStore::from_ders([ca_cert.der().as_ref()]));
        let mut server = ServerHandshake::new(Arc::new(scfg), b"stp".to_vec());

        let client_cfg = ClientConfig {
            server_name: "localhost".to_string(),
            verify_name: true,
            roots: None,
            insecure_verifier: Some(
                crate::conn::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![],
            ..Default::default()
        };
        let mut client = ClientHandshake::new(client_cfg, b"ctp".to_vec()).unwrap();

        for (lvl, d) in client.take_crypto().drain(..) {
            server.provide(lvl, &d).unwrap();
        }
        for (lvl, d) in server.take_crypto().drain(..) {
            client.provide(lvl, &d).unwrap();
        }

        let mut err = None;
        for (lvl, d) in client.take_crypto().drain(..) {
            if let Err(e) = server.provide(lvl, &d) {
                err = Some(e);
                break;
            }
        }
        assert_eq!(err, Some(TlsError::CertificateRequired));
        assert!(!server.is_complete());
    }

    fn run_handshake(
        server: &mut ServerHandshake,
        client: &mut ClientHandshake,
    ) -> (Vec<SecretPair>, Vec<SecretPair>, Vec<(Level, Vec<u8>)>) {
        for (lvl, d) in client.take_crypto().drain(..) {
            server.provide(lvl, &d).unwrap();
        }
        let s_secrets = server.take_secrets();
        for (lvl, d) in server.take_crypto().drain(..) {
            client.provide(lvl, &d).unwrap();
        }
        let c_secrets = client.take_secrets();
        for (lvl, d) in client.take_crypto().drain(..) {
            server.provide(lvl, &d).unwrap();
        }

        let post = server.take_crypto();
        (s_secrets, c_secrets, post)
    }

    #[test]
    fn quic_engine_psk_resumption_and_zero_rtt() {
        use crate::conn::ServerResumption;

        let mut res = ServerResumption::secure_default();
        res.max_early_data = 0xffff_ffff;
        let make = || make_server_cfg(vec![b"doq".to_vec()]).with_resumption(res.clone());

        let mut server = ServerHandshake::new(Arc::new(make()), b"stp".to_vec());
        let client_cfg = ClientConfig {
            server_name: "localhost".to_string(),
            verify_name: true,
            alpn: vec![b"doq".to_vec()],
            ..insecure_test_client()
        };
        let mut client = ClientHandshake::new(client_cfg, b"ctp".to_vec()).unwrap();
        let (_, _, post) = run_handshake(&mut server, &mut client);
        assert!(server.is_complete() && client.is_complete());
        assert!(!server.is_resumed(), "1차는 전체 핸드셰이크");

        assert!(
            post.iter().any(|(l, _)| *l == Level::Application),
            "서버가 NewSessionTicket을 발급해야"
        );
        for (lvl, d) in post {
            client.provide(lvl, &d).unwrap();
        }
        let sessions = client.take_sessions();
        assert_eq!(sessions.len(), 1, "세션 1개 보관");
        let session = sessions.into_iter().next().unwrap();
        assert_eq!(session.max_early_data, 0xffff_ffff);
        assert_eq!(session.alpn.as_deref(), Some(b"doq".as_slice()));

        let mut server2 = ServerHandshake::new(Arc::new(make()), b"stp".to_vec());
        let client_cfg2 = ClientConfig {
            server_name: "localhost".to_string(),
            verify_name: true,
            alpn: vec![b"doq".to_vec()],
            session: Some(session),
            enable_early_data: true,
            ..insecure_test_client()
        };
        let mut client2 = ClientHandshake::new(client_cfg2, b"ctp".to_vec()).unwrap();

        let c_early = client2.take_early_secret().expect("클라 0-RTT 시크릿");

        let (s_sec, c_sec, _) = run_handshake(&mut server2, &mut client2);
        assert!(server2.is_complete() && client2.is_complete());
        assert!(server2.is_resumed(), "PSK 재개 수락");
        assert!(client2.is_resumed());
        assert!(server2.early_data_accepted(), "0-RTT 수락");
        assert!(client2.early_data_accepted());

        let s_early = server2.take_early_secret().expect("서버 0-RTT 시크릿");
        assert_eq!(c_early, s_early, "0-RTT 트래픽 시크릿 일치");

        let s_app = s_sec
            .iter()
            .find(|p| p.level == Level::Application)
            .unwrap();
        let c_app = c_sec
            .iter()
            .find(|p| p.level == Level::Application)
            .unwrap();
        assert_eq!(s_app, c_app);
    }

    #[test]
    /// The binder is recomputed after the retry, and a tampered second binder is rejected.
    fn quic_engine_psk_resumption_survives_hello_retry_request() {
        use crate::conn::ServerResumption;

        let resumption = ServerResumption::secure_default();
        let make = || make_server_cfg(vec![b"doq".to_vec()]).with_resumption(resumption.clone());

        let mut first_server = ServerHandshake::new(Arc::new(make()), b"stp".to_vec());
        let mut first_client = ClientHandshake::new(
            ClientConfig {
                server_name: "localhost".to_string(),
                verify_name: true,
                alpn: vec![b"doq".to_vec()],
                ..insecure_test_client()
            },
            b"ctp".to_vec(),
        )
        .unwrap();
        let (_, _, tickets) = run_handshake(&mut first_server, &mut first_client);
        for (level, data) in tickets {
            first_client.provide(level, &data).unwrap();
        }
        let session = first_client.take_sessions().pop().unwrap();

        let retry_flight = |session| {
            let mut server = ServerHandshake::new(Arc::new(make()), b"stp".to_vec());
            let mut client = ClientHandshake::new(
                ClientConfig {
                    server_name: "localhost".to_string(),
                    verify_name: true,
                    alpn: vec![b"doq".to_vec()],
                    session: Some(session),
                    send_key_share: false,
                    ..insecure_test_client()
                },
                b"ctp".to_vec(),
            )
            .unwrap();
            for (level, data) in client.take_crypto() {
                server.provide(level, &data).unwrap();
            }
            for (level, data) in server.take_crypto() {
                client.provide(level, &data).unwrap();
            }
            let retry = client.take_crypto();
            (server, client, retry)
        };

        let (mut forged_server, _forged_client, mut forged_retry) = retry_flight(session.clone());
        *forged_retry[0].1.last_mut().unwrap() ^= 1;
        assert_eq!(
            forged_server.provide(forged_retry[0].0, &forged_retry[0].1),
            Err(TlsError::BadSignature),
            "ClientHello2 binder 변조는 HRR transcript 검증에서 걸려야"
        );

        let (mut server, mut client, retry) = retry_flight(session);
        let retry_hello = HandshakeMsg::parse(&retry[0].1).unwrap().unwrap().0;
        let retry_hello = ClientHello::from_handshake(&retry_hello).unwrap();
        assert!(retry_hello.ext(EXT_PRE_SHARED_KEY).is_some());
        assert!(retry_hello.ext(EXT_EARLY_DATA).is_none());
        for (level, data) in retry {
            server.provide(level, &data).unwrap();
        }
        let server_secrets = server.take_secrets();
        for (level, data) in server.take_crypto() {
            client.provide(level, &data).unwrap();
        }
        let client_secrets = client.take_secrets();
        for (level, data) in client.take_crypto() {
            server.provide(level, &data).unwrap();
        }

        assert!(server.is_complete() && client.is_complete());
        assert!(server.is_resumed() && client.is_resumed());
        assert!(!server.early_data_accepted() && !client.early_data_accepted());
        assert_eq!(
            server_secrets
                .iter()
                .find(|pair| pair.level == Level::Application),
            client_secrets
                .iter()
                .find(|pair| pair.level == Level::Application)
        );
    }

    #[test]
    /// Otherwise mimicking a ticket would resume.
    fn quic_engine_psk_forged_binder_rejected() {
        use crate::conn::ServerResumption;

        let res = ServerResumption::secure_default();
        let make = || make_server_cfg(vec![b"doq".to_vec()]).with_resumption(res.clone());

        let mut server = ServerHandshake::new(Arc::new(make()), b"stp".to_vec());
        let client_cfg = ClientConfig {
            server_name: "localhost".to_string(),
            verify_name: true,
            alpn: vec![b"doq".to_vec()],
            ..insecure_test_client()
        };
        let mut client = ClientHandshake::new(client_cfg, b"ctp".to_vec()).unwrap();
        let (_, _, post) = run_handshake(&mut server, &mut client);
        for (lvl, d) in post {
            client.provide(lvl, &d).unwrap();
        }
        let mut session = client.take_sessions().into_iter().next().unwrap();

        session.psk[0] ^= 0xFF;
        let mut server2 = ServerHandshake::new(Arc::new(make()), b"stp".to_vec());
        let client_cfg2 = ClientConfig {
            server_name: "localhost".to_string(),
            verify_name: true,
            alpn: vec![b"doq".to_vec()],
            session: Some(session),
            ..insecure_test_client()
        };
        let mut client2 = ClientHandshake::new(client_cfg2, b"ctp".to_vec()).unwrap();
        let mut err = None;
        for (lvl, d) in client2.take_crypto().drain(..) {
            if let Err(e) = server2.provide(lvl, &d) {
                err = Some(e);
            }
        }
        assert_eq!(
            err,
            Some(TlsError::BadSignature),
            "위조 binder는 거부되어야"
        );
    }

    #[test]
    fn quic_engine_unknown_ticket_falls_back_to_full() {
        use crate::conn::ServerResumption;

        let res_a = ServerResumption::secure_default();
        let mut server = ServerHandshake::new(
            Arc::new(make_server_cfg(vec![b"doq".to_vec()]).with_resumption(res_a.clone())),
            b"stp".to_vec(),
        );
        let client_cfg = ClientConfig {
            server_name: "localhost".to_string(),
            verify_name: true,
            alpn: vec![b"doq".to_vec()],
            ..insecure_test_client()
        };
        let mut client = ClientHandshake::new(client_cfg, b"ctp".to_vec()).unwrap();
        let (_, _, post) = run_handshake(&mut server, &mut client);
        for (lvl, d) in post {
            client.provide(lvl, &d).unwrap();
        }
        let session = client.take_sessions().into_iter().next().unwrap();

        let res_b = ServerResumption::secure_default();
        let mut server2 = ServerHandshake::new(
            Arc::new(make_server_cfg(vec![b"doq".to_vec()]).with_resumption(res_b)),
            b"stp".to_vec(),
        );
        let client_cfg2 = ClientConfig {
            server_name: "localhost".to_string(),
            verify_name: true,
            alpn: vec![b"doq".to_vec()],
            session: Some(session),
            ..insecure_test_client()
        };
        let mut client2 = ClientHandshake::new(client_cfg2, b"ctp".to_vec()).unwrap();
        let (_, _, _) = run_handshake(&mut server2, &mut client2);
        assert!(server2.is_complete() && client2.is_complete());
        assert!(
            !server2.is_resumed(),
            "모르는 티켓은 전체 핸드셰이크로 폴백"
        );
        assert!(!client2.is_resumed());
        assert!(!client2.early_data_accepted(), "0-RTT는 거부됨");
    }

    #[test]
    fn quic_engine_hello_retry_request() {
        let mut server = ServerHandshake::new(
            Arc::new(make_server_cfg(vec![b"doq".to_vec()])),
            b"stp".to_vec(),
        );
        let client_cfg = ClientConfig {
            server_name: "localhost".to_string(),
            verify_name: true,
            alpn: vec![b"doq".to_vec()],
            send_key_share: false,
            ..insecure_test_client()
        };
        let mut client = ClientHandshake::new(client_cfg, b"ctp".to_vec()).unwrap();

        let first_flight = client.take_crypto();
        let first_hello = HandshakeMsg::parse(&first_flight[0].1).unwrap().unwrap().0;
        let first_hello = ClientHello::from_handshake(&first_hello).unwrap();
        for (lvl, d) in first_flight {
            server.provide(lvl, &d).unwrap();
        }
        let s1 = server.take_crypto();
        assert!(!server.is_complete(), "HRR 후 서버 미완");

        for (lvl, d) in s1 {
            client.provide(lvl, &d).unwrap();
        }

        let c2 = client.take_crypto();
        assert!(!c2.is_empty(), "클라가 CH2를 재전송");
        let second_hello = HandshakeMsg::parse(&c2[0].1).unwrap().unwrap().0;
        let second_hello = ClientHello::from_handshake(&second_hello).unwrap();
        assert_eq!(second_hello.random, first_hello.random);
        assert_eq!(second_hello.session_id, first_hello.session_id);
        for (lvl, d) in c2 {
            server.provide(lvl, &d).unwrap();
        }
        let server_secrets = server.take_secrets();

        for (lvl, d) in server.take_crypto() {
            client.provide(lvl, &d).unwrap();
        }
        let client_secrets = client.take_secrets();

        for (lvl, d) in client.take_crypto() {
            server.provide(lvl, &d).unwrap();
        }
        assert!(
            server.is_complete() && client.is_complete(),
            "HRR 후 핸드셰이크 완료"
        );

        let s_app = server_secrets
            .iter()
            .find(|p| p.level == Level::Application)
            .unwrap();
        let c_app = client_secrets
            .iter()
            .find(|p| p.level == Level::Application)
            .unwrap();
        assert_eq!(s_app, c_app, "HRR 후에도 app 시크릿 일치");
    }

    fn rewrite_messages(data: &[u8], edit: &dyn Fn(&mut HandshakeMsg)) -> Vec<u8> {
        let mut reader = HandshakeReader::new();
        reader.feed(data);
        let mut out = Vec::new();
        while let Some(mut message) = reader.next_message().unwrap() {
            edit(&mut message);
            out.extend_from_slice(&message.encode());
        }
        assert!(!reader.has_pending());
        out
    }

    fn test_client(alpn: &[&[u8]]) -> ClientHandshake {
        let cfg = ClientConfig {
            server_name: "localhost".to_string(),
            alpn: alpn.iter().map(|protocol| protocol.to_vec()).collect(),
            ..insecure_test_client()
        };
        ClientHandshake::new(cfg, b"ctp".to_vec()).unwrap()
    }

    #[test]
    /// After a message that changes the receive level, `provide` processes up to that message and
    /// reports the rest through `has_unconsumed_input`; closing with PROTOCOL_VIOLATION, as RFC
    /// 9001 requires, is the QUIC layer's job.
    fn quic_engine_takes_handshake_data_only_at_the_receive_level() {
        let cfg = Arc::new(make_server_cfg(vec![b"doq".to_vec()]));
        let pair = || {
            (
                test_client(&[b"doq"]),
                ServerHandshake::new(Arc::clone(&cfg), b"stp".to_vec()),
            )
        };

        let (mut client, mut server) = pair();
        let hello = client.take_crypto().remove(0).1;
        assert_eq!(server.receive_level(), Level::Initial);
        assert_eq!(
            server.provide(Level::Handshake, &hello),
            Err(TlsError::UnexpectedMessage),
            "Handshake 수준으로 온 ClientHello"
        );
        assert!(server.take_crypto().is_empty());
        server.provide(Level::Initial, &hello).unwrap();
        assert_eq!(server.receive_level(), Level::Handshake);
        let flight = server.take_crypto();
        assert_eq!(client.receive_level(), Level::Initial);
        assert_eq!(
            client.provide(Level::Handshake, &flight[0].1),
            Err(TlsError::UnexpectedMessage),
            "Handshake 수준으로 온 ServerHello"
        );
        client.provide(Level::Initial, &flight[0].1).unwrap();
        assert_eq!(client.receive_level(), Level::Handshake);
        assert_eq!(
            client.provide(Level::Initial, &flight[1].1),
            Err(TlsError::UnexpectedMessage),
            "Initial 수준으로 온 암호화된 확장"
        );
        client.provide(Level::Handshake, &flight[1].1).unwrap();
        assert_eq!(client.receive_level(), Level::Application);
        for (level, data) in client.take_crypto() {
            server.provide(level, &data).unwrap();
        }
        assert!(server.is_complete() && client.is_complete());
        assert_eq!(server.receive_level(), Level::Application);
        assert!(!server.has_unconsumed_input() && !client.has_unconsumed_input());

        let (mut client, mut server) = pair();
        let hello = client.take_crypto().remove(0).1;
        assert_eq!(
            server.provide(Level::Initial, &[hello.as_slice(), &[20, 0]].concat()),
            Ok(())
        );
        assert!(
            server.has_unconsumed_input(),
            "ClientHello 뒤에 남은 바이트를 알려야 한다"
        );
        assert_eq!(
            server.provide(Level::Handshake, &[]),
            Err(TlsError::UnexpectedMessage),
            "앞 수준에 바이트가 남은 뒤에는 더 받지 않는다"
        );

        let (mut client, mut server) = pair();
        for (level, data) in client.take_crypto() {
            server.provide(level, &data).unwrap();
        }
        let flight = server.take_crypto();
        let spanning = [flight[0].1.as_slice(), &flight[1].1[..2]].concat();
        assert_eq!(client.provide(Level::Initial, &spanning), Ok(()));
        assert!(
            client.has_unconsumed_input(),
            "ServerHello 뒤에 남은 바이트를 알려야 한다"
        );
        assert_eq!(
            client.provide(Level::Handshake, &flight[1].1[2..]),
            Err(TlsError::UnexpectedMessage)
        );
    }

    #[test]
    fn quic_engine_client_handles_cookie_only_and_unoffered_group_retries() {
        let retry = |extension: Extension| {
            ServerHello {
                legacy_version: TLS12,
                random: crate::msg::HRR_RANDOM,
                session_id_echo: Vec::new(),
                cipher_suite: TLS_AES_128_GCM_SHA256,
                extensions: vec![Extension::supported_versions_server(TLS13), extension],
            }
            .to_handshake()
            .encode()
        };
        let hello_in = |flight: Vec<(Level, Vec<u8>)>| {
            assert_eq!(flight.len(), 1);
            assert_eq!(flight[0].0, Level::Initial);
            let message = HandshakeMsg::parse(&flight[0].1).unwrap().unwrap().0;
            ClientHello::from_handshake(&message).unwrap()
        };

        let mut client = test_client(&[b"doq"]);
        let first = hello_in(client.take_crypto());
        client
            .provide(Level::Initial, &retry(Extension::cookie(b"retry-cookie")))
            .unwrap();
        let second = hello_in(client.take_crypto());
        assert!(second.is_valid_retry_of(&first));
        assert_eq!(
            second.ext(EXT_KEY_SHARE),
            first.ext(EXT_KEY_SHARE),
            "쿠키만 담은 요청에는 첫 키 조각을 그대로 보낸다"
        );
        assert_eq!(
            second.ext(EXT_COOKIE).and_then(Extension::as_cookie),
            Some(b"retry-cookie".to_vec())
        );
        assert_eq!(client.receive_level(), Level::Initial);

        assert_eq!(
            test_client(&[b"doq"])
                .provide(Level::Initial, &retry(Extension::key_share_hrr(SECP256R1))),
            Err(TlsError::IllegalParameter),
            "엔진 클라이언트는 P-256 을 제안하지 않는다"
        );
    }

    #[test]
    /// RFC 8446 requires secp256r1 key exchange. The hellos are the engine client's with only
    /// supported groups and key shares changed.
    fn quic_engine_server_negotiates_p256_key_exchange() {
        let p256 = KeyExchange::from_seed(SECP256R1, &[0x32; 32]).unwrap();
        let x25519 = KeyExchange::from_seed(X25519, &[0x31; 32]).unwrap();
        let share = |kx: &KeyExchange| (kx.group(), kx.public_bytes());
        let original = test_client(&[b"doq"]).take_crypto().remove(0).1;
        let hello = |shares: Vec<(u16, Vec<u8>)>, cookie: Option<Vec<u8>>| {
            rewrite_messages(&original, &|message| {
                let mut ch = ClientHello::from_handshake(message).unwrap();
                for extension in &mut ch.extensions {
                    match extension.ext_type {
                        EXT_KEY_SHARE => *extension = Extension::key_share_client(&shares),
                        EXT_SUPPORTED_GROUPS => {
                            *extension = Extension::supported_groups(&[SECP256R1])
                        }
                        _ => {}
                    }
                }
                if let Some(cookie) = &cookie {
                    ch.extensions.push(Extension::cookie(cookie));
                }
                *message = ch.to_handshake();
            })
        };
        let new_server = || {
            ServerHandshake::new(
                Arc::new(make_server_cfg(vec![b"doq".to_vec()])),
                b"stp".to_vec(),
            )
        };
        let server_hello = |server: &mut ServerHandshake| {
            let flight = server.take_crypto();
            assert_eq!(flight[0].0, Level::Initial);
            let message = HandshakeMsg::parse(&flight[0].1).unwrap().unwrap().0;
            ServerHello::from_handshake(&message).unwrap()
        };
        let agreed = |reply: &ServerHello, kx: &KeyExchange| {
            let (group, public) = reply
                .ext(EXT_KEY_SHARE)
                .and_then(Extension::as_key_share_server)
                .unwrap();
            reply.random != crate::msg::HRR_RANDOM
                && group == kx.group()
                && kx.shared_secret(&public).is_some()
        };

        let mut server = new_server();
        server
            .provide(Level::Initial, &hello(vec![share(&p256)], None))
            .unwrap();
        assert!(
            agreed(&server_hello(&mut server), &p256),
            "P-256 조각만 보낸 인사말에는 P-256 으로 답해야 한다"
        );

        for (retry_share, expected) in [
            (share(&p256), Ok(())),
            (share(&x25519), Err(TlsError::IllegalParameter)),
        ] {
            let group = retry_share.0;
            let mut server = new_server();
            server
                .provide(Level::Initial, &hello(Vec::new(), None))
                .unwrap();
            let retry = server_hello(&mut server);
            assert_eq!(retry.random, crate::msg::HRR_RANDOM);
            assert_eq!(
                retry
                    .ext(EXT_KEY_SHARE)
                    .and_then(Extension::as_key_share_hrr),
                Some(SECP256R1)
            );
            let cookie = retry.ext(EXT_COOKIE).and_then(Extension::as_cookie);
            assert_eq!(
                server.provide(Level::Initial, &hello(vec![retry_share], cookie)),
                expected,
                "재시도 인사말의 조각 곡선 {group:#06x}"
            );
            if expected.is_ok() {
                assert!(agreed(&server_hello(&mut server), &p256));
            }
        }
    }

    const TEST_TICKET_PSK: [u8; 32] = [0x44; 32];

    /// `ticket_suite` is the suite that issued the ticket. With `known` false the ticket is sealed
    /// with another key, so the server cannot open it.
    fn resumable_pair(
        ticket_suite: u16,
        known: bool,
    ) -> (ServerConfig, crate::session::TlsSession) {
        use crate::conn::ServerResumption;
        use crate::session::{ResumptionState, Ticketer};

        let now = crate::session::now_ms();
        let age_add = 0x0102_0304;
        let lifetime_secs = 60;
        let max_early_data = 0xffff_ffff;
        let ticketer = Arc::new(Ticketer::from_key([0x5c; 32]));
        let sealing = if known {
            Arc::clone(&ticketer)
        } else {
            Arc::new(Ticketer::from_key([0x5d; 32]))
        };
        let ticket = sealing
            .seal(&ResumptionState {
                server_name: Some("localhost".to_string()),
                suite: ticket_suite,
                psk: TEST_TICKET_PSK.to_vec(),
                alpn: Some(b"doq".to_vec()),
                issued_ms: now,
                age_add,
                lifetime_secs,
                max_early_data,
            })
            .unwrap();
        let server = make_server_cfg(vec![b"doq".to_vec()]).with_resumption(ServerResumption {
            ticketer,
            lifetime_secs,
            max_early_data,
        });
        let session = crate::session::TlsSession {
            server_name: "localhost".to_string(),
            suite: ticket_suite,
            psk: TEST_TICKET_PSK.to_vec(),
            ticket,
            lifetime_secs,
            age_add,
            max_early_data,
            alpn: Some(b"doq".to_vec()),
            server_transport_params: b"stp".to_vec(),
            obtained_at_ms: now,
        };
        (server, session)
    }

    fn resuming_client(session: crate::session::TlsSession, alpn: &[&[u8]]) -> ClientHandshake {
        let cfg = ClientConfig {
            server_name: "localhost".to_string(),
            alpn: alpn.iter().map(|protocol| protocol.to_vec()).collect(),
            session: Some(session),
            enable_early_data: true,
            ..insecure_test_client()
        };
        ClientHandshake::new(cfg, b"ctp".to_vec()).unwrap()
    }

    #[test]
    /// The server prefers AES-128, so resuming a ChaCha20 ticket changes the suite. RFC 8446 allows
    /// resumption with the same hash, and early data only with the same suite.
    fn quic_engine_resumes_across_suites_of_the_same_hash() {
        for (ticket_suite, early) in [
            (TLS_CHACHA20_POLY1305_SHA256, false),
            (TLS_AES_128_GCM_SHA256, true),
        ] {
            let (server_cfg, session) = resumable_pair(ticket_suite, true);
            let mut server = ServerHandshake::new(Arc::new(server_cfg), b"stp".to_vec());
            let mut client = resuming_client(session, &[b"doq"]);
            let (server_secrets, client_secrets, _) = run_handshake(&mut server, &mut client);
            let case = format!("티켓 {ticket_suite:#06x}");
            assert!(server.is_complete() && client.is_complete(), "{case}");
            assert!(server.is_resumed() && client.is_resumed(), "{case}");
            assert_eq!(server.early_data_accepted(), early, "{case}");
            assert_eq!(client.early_data_accepted(), early, "{case}");
            let application = |secrets: &[SecretPair]| {
                secrets
                    .iter()
                    .find(|pair| pair.level == Level::Application)
                    .map(|pair| (pair.client.suite, pair.client.secret.clone()))
            };
            assert_eq!(
                application(&server_secrets),
                application(&client_secrets),
                "{case}"
            );
            assert_eq!(
                application(&server_secrets).map(|(suite, _)| suite),
                Some(TLS_AES_128_GCM_SHA256),
                "{case}"
            );
        }
    }

    #[test]
    /// Either one makes the client close with illegal_parameter.
    fn quic_engine_client_checks_resumed_alpn_and_early_data_suite() {
        let reply = |ticket_suite: u16, known: bool, edit: &dyn Fn(&mut Vec<Extension>)| {
            let (server_cfg, session) = resumable_pair(ticket_suite, known);
            let mut server = ServerHandshake::new(Arc::new(server_cfg), b"stp".to_vec());
            let mut client = resuming_client(session, &[b"doq", b"h3"]);
            for (level, data) in client.take_crypto() {
                server.provide(level, &data).unwrap();
            }
            let flight = server.take_crypto();
            client.provide(flight[0].0, &flight[0].1).unwrap();
            let edited = rewrite_messages(&flight[1].1, &|message| {
                if message.msg_type == HandshakeType::EncryptedExtensions {
                    let mut extensions = parse_ee_extensions(&message.body).unwrap();
                    edit(&mut extensions);
                    let mut body = Writer::new();
                    body.vec16(|w| {
                        extensions
                            .iter()
                            .for_each(|extension| extension.encode_into(w))
                    });
                    message.body = body.buf;
                }
            });
            client.provide(Level::Handshake, &edited)
        };
        let other_protocol = |extensions: &mut Vec<Extension>| {
            for extension in extensions.iter_mut() {
                if extension.ext_type == EXT_ALPN {
                    *extension = Extension::alpn(&[b"h3".as_slice()]);
                }
            }
        };
        let accept_early_data = |extensions: &mut Vec<Extension>| {
            extensions.push(Extension::early_data());
        };

        assert_eq!(
            reply(TLS_AES_128_GCM_SHA256, true, &|_| {}),
            Ok(()),
            "고치지 않은 응답은 받아들여야 한다"
        );
        assert_eq!(
            reply(TLS_AES_128_GCM_SHA256, true, &other_protocol),
            Err(TlsError::IllegalParameter),
            "재개하면서 티켓과 다른 응용 프로토콜을 골랐다"
        );
        assert_eq!(
            reply(TLS_CHACHA20_POLY1305_SHA256, true, &accept_early_data),
            Err(TlsError::IllegalParameter),
            "티켓과 다른 스위트로 재개하면서 조기 데이터를 받았다고 했다"
        );
        assert_eq!(
            reply(TLS_AES_128_GCM_SHA256, false, &accept_early_data),
            Err(TlsError::IllegalParameter),
            "재개하지 않으면서 조기 데이터를 받았다고 했다"
        );
    }

    #[test]
    /// The signatures are all valid and the key types fit, so only the scheme check rejects them.
    /// The engine client offers only SHA-256 among RSA PSS schemes.
    fn quic_engine_client_accepts_only_certificate_verify_schemes_rfc_8446_allows() {
        let (certificate, key) = crate::cert::rsa_test_certificate("localhost");
        for (scheme, expected) in [
            (RSA_PSS_RSAE_SHA256, Ok(())),
            (RSA_PKCS1_SHA256, Err(TlsError::IllegalParameter)),
            (RSA_PSS_RSAE_SHA384, Err(TlsError::IllegalParameter)),
        ] {
            let cfg = ServerConfig {
                cert_chain: vec![certificate.clone()],
                sign_scheme: scheme,
                sign: crate::cert::rsa_test_signer(key.clone(), scheme),
                alpn: vec![b"doq".to_vec()],
                client_ca: None,
                resumption: None,
            };
            let mut server = ServerHandshake::new(Arc::new(cfg), b"stp".to_vec());
            let mut client = test_client(&[b"doq"]);
            for (level, data) in client.take_crypto() {
                server.provide(level, &data).unwrap();
            }
            let result = server
                .take_crypto()
                .into_iter()
                .try_for_each(|(level, data)| client.provide(level, &data));
            assert_eq!(result, expected, "서명 방식 {scheme:#06x}");
            assert_eq!(
                client.is_complete(),
                expected.is_ok(),
                "서명 방식 {scheme:#06x}"
            );
        }
    }

    fn mtls_pair() -> (ServerConfig, crate::conn::ClientCert) {
        use crate::trust::TrustStore;
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(vec!["client.example".to_string()]).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
        let server = ServerConfig {
            client_ca: Some(TrustStore::from_ders([ca_cert.der().as_ref()])),
            ..make_server_cfg(vec![b"doq".to_vec()])
        };
        let client_cert = crate::conn::ClientCert::from_pkcs8(
            vec![leaf_cert.der().to_vec()],
            &leaf_key.serialize_der(),
        )
        .unwrap();
        (server, client_cert)
    }

    fn mtls_client(client_cert: crate::conn::ClientCert) -> ClientHandshake {
        let cfg = ClientConfig {
            server_name: "localhost".to_string(),
            alpn: vec![b"doq".to_vec()],
            client_cert: Some(client_cert),
            ..insecure_test_client()
        };
        ClientHandshake::new(cfg, b"ctp".to_vec()).unwrap()
    }

    #[test]
    /// The server rejects CertificateVerify with RSA PKCS#1 or an unrequested scheme as
    /// illegal_parameter; the signatures are valid and only the scheme label changes, so the scheme
    /// check rejects them, not the key type check. The client accepts only requests with an empty
    /// context, and answers with an empty Certificate when its key cannot sign with a requested
    /// scheme.
    fn quic_engine_client_certificate_rules() {
        let (rsa_certificate, rsa_key) = crate::cert::rsa_test_certificate("client.example");
        for (scheme, expected) in [
            (RSA_PSS_RSAE_SHA256, Ok(())),
            (RSA_PKCS1_SHA256, Err(TlsError::IllegalParameter)),
            (RSA_PSS_RSAE_SHA384, Err(TlsError::IllegalParameter)),
        ] {
            let server_cfg = ServerConfig {
                client_ca: Some(crate::trust::TrustStore::from_ders([
                    rsa_certificate.as_slice()
                ])),
                ..make_server_cfg(vec![b"doq".to_vec()])
            };
            let mut server = ServerHandshake::new(Arc::new(server_cfg), b"stp".to_vec());
            let mut client = mtls_client(crate::conn::ClientCert {
                chain: vec![rsa_certificate.clone()],
                sign_scheme: RSA_PSS_RSAE_SHA256,
                sign: crate::cert::rsa_test_signer(rsa_key.clone(), scheme),
            });
            for (level, data) in client.take_crypto() {
                server.provide(level, &data).unwrap();
            }
            for (level, data) in server.take_crypto() {
                client.provide(level, &data).unwrap();
            }
            let flight = client.take_crypto();
            let relabeled = rewrite_messages(&flight[0].1, &|message| {
                if message.msg_type == HandshakeType::CertificateVerify {
                    let mut verify = CertificateVerify::parse(&message.body).unwrap();
                    verify.algorithm = scheme;
                    message.body = verify.encode();
                }
            });
            assert_eq!(
                server.provide(Level::Handshake, &relabeled),
                expected,
                "서명 방식 {scheme:#06x}"
            );
            assert_eq!(
                server.is_complete(),
                expected.is_ok(),
                "서명 방식 {scheme:#06x}"
            );
        }

        let (server_cfg, _) = mtls_pair();
        let mut server = ServerHandshake::new(Arc::new(server_cfg), b"stp".to_vec());
        let mut client = mtls_client(crate::conn::ClientCert {
            sign_scheme: RSA_PKCS1_SHA256,
            sign: Arc::new(|_: &[u8]| -> Vec<u8> {
                unreachable!("1.3 에서 쓸 수 없는 방식으로 서명하면 안 된다")
            }),
            ..mtls_pair().1
        });
        for (level, data) in client.take_crypto() {
            server.provide(level, &data).unwrap();
        }
        for (level, data) in server.take_crypto() {
            client.provide(level, &data).unwrap();
        }
        let flight = client.take_crypto();
        let mut reader = HandshakeReader::new();
        reader.feed(&flight[0].1);
        let certificate = reader.next_message().unwrap().unwrap();
        assert_eq!(certificate.msg_type, HandshakeType::Certificate);
        assert!(CertificateMsg::parse(&certificate.body)
            .unwrap()
            .entries
            .is_empty());
        assert_eq!(
            reader
                .next_message()
                .unwrap()
                .map(|message| message.msg_type),
            Some(HandshakeType::Finished),
            "빈 Certificate 뒤에는 CertificateVerify 없이 Finished 가 온다"
        );
        assert_eq!(
            server.provide(Level::Handshake, &flight[0].1),
            Err(TlsError::CertificateRequired)
        );

        let (server_cfg, client_cert) = mtls_pair();
        let mut server = ServerHandshake::new(Arc::new(server_cfg), b"stp".to_vec());
        let mut client = mtls_client(client_cert);
        for (level, data) in client.take_crypto() {
            server.provide(level, &data).unwrap();
        }
        let flight = server.take_crypto();
        client.provide(flight[0].0, &flight[0].1).unwrap();
        let with_context = rewrite_messages(&flight[1].1, &|message| {
            if message.msg_type == HandshakeType::CertificateRequest {
                let mut request = crate::cert::CertificateRequestMsg::parse(&message.body).unwrap();
                request.context = vec![1];
                message.body = request.encode();
            }
        });
        assert_eq!(
            client.provide(Level::Handshake, &with_context),
            Err(TlsError::IllegalParameter),
            "핸드셰이크 중의 요청은 문맥이 비어 있어야 한다"
        );
    }
}
