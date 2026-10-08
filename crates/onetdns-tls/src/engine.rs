/*!
 * @brief sans-IO 핸드셰이크 엔진. QUIC가 쓴다.
 *
 * @details 소켓을 만지지 않는다. 핸드셰이크 데이터를 넣으면 상태가 나아가고, 내보낼 데이터와
 *          유도된 비밀을 꺼내 간다.
 * @note conn의 차단 방식 구현과 별개다. 둘이 와이어 원시 요소만 나눠 쓰고 상태 기계는
 *       각자 갖는다.
 */

use crate::cert::{
    certificate_verify_content, tls13_signature_scheme_allowed, CertEntry, CertificateMsg,
    CertificateVerify, REQUESTED_SIGNATURE_SCHEMES,
};
use crate::conn::{
    choose_server_key_share, client_config_wire_is_valid, new_key_exchange, retry_key_share,
    server_config_wire_is_valid, ClientConfig, ServerConfig, ServerKeyShare,
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

/** @brief QUIC 전송 매개변수를 전달하는 확장. */
pub const EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
/** @brief 암호화 수준. 핸드셰이크 데이터가 어느 키로 보호되는지 정한다. */
pub enum Level {
    /** @brief 핸드셰이크를 시작하는 단계. */
    Initial,
    /** @brief 핸드셰이크 중인 단계. */
    Handshake,
    /** @brief 핸드셰이크를 마친 뒤의 단계. */
    Application,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/** @brief 한 방향의 유도된 비밀. */
pub struct Secret {
    /** @brief 이 비밀에 쓰는 암호 스위트. */
    pub suite: u16,
    /** @brief 비밀 값. */
    pub secret: Vec<u8>,
}

impl Drop for Secret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/** @brief 한 수준의 양방향 비밀. */
pub struct SecretPair {
    /** @brief 어느 단계의 비밀인지. */
    pub level: Level,
    /** @brief 클라이언트 쪽 비밀. */
    pub client: Secret,
    /** @brief 서버 쪽 비밀. */
    pub server: Secret,
}

/** @brief 현재 Unix 초. 인증서 유효 기간 판정에 쓴다. */
fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/** @brief 상대가 제안한 것 중 쓸 스위트를 고른다. */
fn choose_suite_quic(offered: &[u16]) -> Option<u16> {
    [
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    ]
    .into_iter()
    .find(|&s| offered.contains(&s))
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

/** @brief 암호화된 확장 메시지를 만든다. 전송 매개변수가 여기 담긴다. */
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

/** @brief 암호화된 확장을 읽는다. 중복과 비정규 형태를 거부한다. */
fn parse_ee_extensions(body: &[u8]) -> Result<Vec<Extension>, TlsError> {
    Extension::parse_vector(body)
}

#[derive(PartialEq, Eq)]
/** @brief 서버 핸드셰이크 진행 상태. */
enum SState {
    /** @brief 첫 메시지를 기다린다. */
    ExpectClientHello,
    /** @brief 클라이언트 인증서를 기다린다. */
    ExpectClientCertificate,
    /** @brief 그 인증서의 소유 증명을 기다린다. */
    ExpectClientCertVerify,
    /** @brief 마무리 메시지를 기다린다. */
    ExpectClientFinished,
    /** @brief 핸드셰이크가 끝났다. */
    Done,
}

/** @brief 서버 쪽 핸드셰이크 상태 기계. */
pub struct ServerHandshake {
    /** @brief 이 서버의 공유 설정. 연결마다 인증서와 신뢰 저장소를 복제하지 않는다. */
    cfg: Arc<ServerConfig>,
    /** @brief 이쪽이 알릴 전송 설정. */
    local_tp: Vec<u8>,
    /** @brief 받은 핸드셰이크 바이트를 모으는 곳. */
    hr: HandshakeReader,
    /** @brief 받을 수준이 바뀔 때 앞 수준의 바이트가 남았는지. 새 수준으로 이어 읽을 수 없다. */
    stranded_input: bool,
    /** @brief 지금 어느 단계인지. */
    state: SState,

    /** @brief 협상한 요약 방식. */
    hash: Hash,
    /** @brief 협상한 암호 스위트. */
    suite: u16,
    /** @brief 클라이언트 쪽 핸드셰이크 비밀. */
    client_hs_secret: Vec<u8>,

    /** @brief 지금까지 오간 핸드셰이크 바이트의 요약. */
    transcript: Option<Transcript>,

    /** @brief 비밀을 이끌어 내는 곳. */
    ks: Option<KeySchedule>,

    /** @brief 받은 클라이언트 인증서. */
    client_cert: Option<X509>,

    /** @brief 앞선 세션을 이어 붙였는지. */
    resumed: bool,

    /** @brief 왕복 없이 온 자료를 받아들였는지. */
    early_accepted: bool,

    /** @brief 그 자료를 풀 비밀. */
    early_secret_out: Option<Secret>,

    /** @brief 다시 보내라고 할 때 담을 값. 상태를 가지고 있지 않으려는 것이다. */
    hrr_cookie: Option<Vec<u8>>,
    /** @brief 다시 보내기 전까지의 요약 앞부분. */
    hrr_prefix: Option<Vec<u8>>,
    /** @brief 다시 보내기에서 이미 고른 암호 스위트. */
    hrr_suite: Option<u16>,
    /** @brief 다시 보내기에서 키 조각을 요청한 곡선. */
    hrr_group: Option<u16>,
    /** @brief 다시 보내라고 하기 전에 받은 첫 메시지. */
    hrr_client_hello: Option<ClientHello>,

    /** @brief 첫 단계로 내보낼 바이트. */
    out_initial: Vec<u8>,
    /** @brief 핸드셰이크 단계로 내보낼 바이트. */
    out_handshake: Vec<u8>,

    /** @brief 핸드셰이크 뒤 단계로 내보낼 바이트. */
    out_application: Vec<u8>,
    /** @brief 위로 넘길 새 비밀들. */
    pending_secrets: Vec<SecretPair>,
    /** @brief 상대가 알린 전송 설정. */
    peer_tp: Option<Vec<u8>>,
    /** @brief 협상한 ALPN. */
    alpn: Option<Vec<u8>>,
    /** @brief 티켓과 결속할 클라이언트 SNI. */
    server_name: Option<String>,
    /** @brief 클라이언트가 PSK-DHE 재접속을 지원하는지. */
    client_allows_resumption: bool,
}

impl Drop for ServerHandshake {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.client_hs_secret.zeroize();
    }
}

impl ServerHandshake {
    /** @brief 설정과 전송 매개변수로 만든다. */
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

    /**
     * @brief 연결이 지금 보유한 가변 핸드셰이크 payload 바이트.
     * @details QUIC 리스너의 전역 메모리 예산이 연결 수에 따른 입력 증폭을 막는 데 쓴다.
     *          공유 ServerConfig는 세대당 한 벌이므로 여기서 세지 않는다.
     */
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

    /**
     * @brief 받은 핸드셰이크 데이터를 넣어 상태를 진행시킨다.
     * @param level 그 데이터가 실려 온 암호화 수준.
     * @details 받을 수준을 바꾸는 메시지 뒤에 같은 수준의 바이트가 남으면 처리하지 않고 둔다.
     *          RFC 9001 은 이것을 QUIC 연결 오류 PROTOCOL_VIOLATION 으로 정하므로 부른 쪽이
     *          has_unconsumed_input 으로 확인해 끊는다. 그 상태로 다시 부르면 이쪽이 거부한다.
     * @retval TlsError::UnexpectedMessage 지금 받을 수준이 아닌 데이터이거나, 앞 수준에 남은
     *         바이트가 있다.
     */
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

    /** @brief 지금 핸드셰이크 메시지를 받을 암호화 수준. */
    pub fn receive_level(&self) -> Level {
        match self.state {
            SState::ExpectClientHello => Level::Initial,
            SState::ExpectClientCertificate
            | SState::ExpectClientCertVerify
            | SState::ExpectClientFinished => Level::Handshake,
            SState::Done => Level::Application,
        }
    }

    /** @brief 받았지만 아직 메시지로 처리하지 않은 바이트가 있는지. */
    pub fn has_unconsumed_input(&self) -> bool {
        self.hr.has_pending()
    }

    /**
     * @brief 재개 제안을 받아들일지 판단한다.
     * @param suite 이번에 고른 스위트. RFC 8446 은 해시가 같은 스위트끼리 PSK 를 함께 쓰게 하지만
     *        조기 데이터는 티켓과 같은 스위트일 때만 받는다.
     * @return 받아들인 티켓과 조기 데이터를 받을 수 있는지.
     * @warning 바인더를 검증한다. 검증하지 않으면 티켓만 흉내 내 남의 세션을 재개할 수 있다.
     */
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

    /**
     * @brief 클라이언트 인사말을 처리하고 서버 차례를 만든다.
     * @details 다시 시도 요청은 재시도 인사말로 핸드셰이크를 마칠 수 있을 때만 보낸다. 재시도
     *          인사말은 지원 곡선과 ALPN 을 바꿀 수 없으므로, 공통 곡선이 없거나 ALPN 이 맞지
     *          않는 인사말은 첫 인사말에서 거절한다. 클라이언트의 서명 방식 목록에 이쪽 방식이
     *          없어도 RFC 8446 대로 가진 인증서로 계속한다.
     * @retval TlsError::NoApplicationProtocol 이쪽이 ALPN 을 쓰는데 합의한 프로토콜이 없다.
     *         RFC 9001 은 QUIC 에서 ALPN 협상을 필수로 정한다.
     */
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

    /** @brief 클라이언트 인증서를 받아 체인을 검증한다. */
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

    /** @brief 클라이언트가 개인키를 갖고 있음을 확인한다. */
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

    /**
     * @brief 클라이언트의 핸드셰이크 확인 값을 검증한다.
     * @warning 이것이 핸드셰이크 위조를 막는 마지막 검사다. 상수 시간으로 비교한다.
     */
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

    /** @brief 내보낼 핸드셰이크 데이터를 꺼낸다. */
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

    /** @brief 새로 유도된 비밀을 꺼낸다. */
    pub fn take_secrets(&mut self) -> Vec<SecretPair> {
        std::mem::take(&mut self.pending_secrets)
    }

    /** @brief 조기 데이터 비밀을 꺼낸다. */
    pub fn take_early_secret(&mut self) -> Option<Secret> {
        self.early_secret_out.take()
    }

    /** @brief 재개로 맺어졌는지. */
    pub fn is_resumed(&self) -> bool {
        self.resumed
    }

    /** @brief 조기 데이터를 받아들였는지. */
    pub fn early_data_accepted(&self) -> bool {
        self.early_accepted
    }

    /** @brief 상대가 보낸 전송 매개변수. */
    pub fn peer_transport_params(&self) -> Option<&[u8]> {
        self.peer_tp.as_deref()
    }

    /** @brief 합의된 응용 프로토콜. */
    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /** @brief 클라이언트 인증서를 확인했는지. */
    pub fn client_authenticated(&self) -> bool {
        self.state == SState::Done && self.cfg.client_ca.is_some() && self.client_cert.is_some()
    }

    /** @brief 확인된 클라이언트 신원. */
    pub fn client_auth_identity(&self) -> Option<String> {
        self.client_cert
            .as_ref()
            .map(|certificate| format!("mtls:{}", short_hex(&certificate.public_key)))
    }

    /** @brief 핸드셰이크가 끝났는지. */
    pub fn is_complete(&self) -> bool {
        self.state == SState::Done
    }
}

#[derive(PartialEq, Eq)]
/** @brief 클라이언트 핸드셰이크 진행 상태. */
enum CState {
    /** @brief 서버의 첫 메시지를 기다린다. */
    ExpectServerHello,
    /** @brief 이어지는 핸드셰이크 메시지를 기다린다. */
    ExpectFlight,
    /** @brief 핸드셰이크가 끝났다. */
    Done,
}

#[derive(Clone, Copy, PartialEq, Eq)]
/** @brief 서버 차례 안에서 어디까지 받았는지. */
enum CFlightState {
    /** @brief 확장 메시지를 기다린다. */
    EncryptedExtensions,
    /** @brief 인증서나 인증서 요구를 기다린다. */
    CertificateOrRequest,
    /** @brief 인증서를 기다린다. */
    Certificate,
    /** @brief 그 인증서의 소유 증명을 기다린다. */
    CertificateVerify,
    /** @brief 마무리 메시지를 기다린다. */
    Finished,
}

/** @brief 클라이언트 쪽 핸드셰이크 상태 기계. */
pub struct ClientHandshake {
    /** @brief 이 클라이언트의 설정. */
    cfg: ClientConfig,
    /** @brief 키를 주고받는 곳. */
    kx: KeyExchange,
    /** @brief 마지막 인사말에서 키 조각을 보낸 곡선. 보내지 않았으면 없다. */
    share_group: Option<u16>,
    /**
     * @brief 서버 인사말 앞까지의 핸드셰이크 기록.
     * @details 다시 시도 요청을 받은 뒤에는 첫 인사말의 해시, 그 요청, 두 번째 인사말을 담는다.
     */
    ch_wire: Vec<u8>,
    /** @brief 이쪽이 마지막으로 보낸 인사말. 서버의 응답을 이것과 대조한다. */
    hello: ClientHello,
    /** @brief 받은 핸드셰이크 바이트를 모으는 곳. */
    hr: HandshakeReader,
    /** @brief 받을 수준이 바뀔 때 앞 수준의 바이트가 남았는지. 새 수준으로 이어 읽을 수 없다. */
    stranded_input: bool,
    /** @brief 지금 어느 단계인지. */
    state: CState,
    /** @brief 핸드셰이크 메시지 흐름에서 어디까지 왔는지. */
    flight_state: CFlightState,
    /** @brief 지금까지 오간 핸드셰이크 바이트의 요약. */
    transcript: Option<Transcript>,
    /** @brief 비밀을 이끌어 내는 곳. */
    ks: Option<KeySchedule>,
    /** @brief 협상한 요약 방식. */
    hash: Hash,
    /** @brief 협상한 암호 스위트. */
    suite: u16,
    /** @brief 클라이언트 쪽 핸드셰이크 비밀. */
    client_hs_secret: Vec<u8>,
    /** @brief 서버 쪽 핸드셰이크 비밀. */
    server_hs_secret: Vec<u8>,
    /** @brief 서버가 보낸 리프 인증서. */
    leaf_cert: Option<X509>,

    /** @brief 서버가 이쪽 인증서를 요구하며 받겠다고 한 서명 방식. 요구하지 않았으면 없다. */
    requested_schemes: Option<Vec<u16>>,

    /** @brief 인증서 소유 증명을 이미 봤는지. */
    seen_cert_verify: bool,

    /** @brief 다시 붙을 때 쓴 앞선 세션. */
    psk_session: Option<crate::session::TlsSession>,
    /** @brief 서버가 그것을 받아들였는지. */
    psk_accepted: bool,
    /** @brief 왕복 없이 자료를 보냈는지. */
    early_offered: bool,
    /** @brief 서버가 그 자료를 받아들였는지. */
    early_accepted: bool,

    /** @brief 그 자료를 봉할 비밀. */
    early_secret_out: Option<Secret>,

    /** @brief 다음에 다시 붙을 때 쓸 비밀. */
    res_master: Vec<u8>,

    /** @brief 서버가 새로 준 세션들. */
    new_sessions: Vec<crate::session::TlsSession>,

    /** @brief 다시 보내라는 요구를 이미 한 번 받았는지. 되풀이하면 무한히 돈다. */
    hrr_done: bool,
    /** @brief 첫 단계로 내보낼 바이트. */
    out_initial: Vec<u8>,
    /** @brief 핸드셰이크 단계로 내보낼 바이트. */
    out_handshake: Vec<u8>,
    /** @brief 위로 넘길 새 비밀들. */
    pending_secrets: Vec<SecretPair>,
    /** @brief 상대가 알린 전송 설정. */
    peer_tp: Option<Vec<u8>>,
    /** @brief 협상한 ALPN. */
    alpn: Option<Vec<u8>>,
    /** @brief 검증한 서버의 인증 경로. */
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
    /** @brief 설정과 전송 매개변수로 만든다. */
    pub fn new(cfg: ClientConfig, local_transport_params: Vec<u8>) -> Result<Self, TlsError> {
        if !client_config_wire_is_valid(&cfg) || local_transport_params.len() > u16::MAX as usize {
            return Err(TlsError::Internal);
        }
        let kx = new_key_exchange(X25519)?;
        let share_group = cfg.send_key_share.then(|| kx.group());
        let session = cfg
            .session
            .clone()
            .filter(|s| s.is_fresh(crate::session::now_ms()) && suite_params(s.suite).is_some());

        let key_shares: Vec<(u16, Vec<u8>)> = share_group
            .map(|group| vec![(group, kx.public_bytes())])
            .unwrap_or_default();
        let mut extensions = vec![
            Extension::supported_versions_client(&[TLS13]),
            Extension::supported_groups(&[X25519]),
            Extension::signature_algorithms(&[
                ED25519,
                ECDSA_SECP256R1_SHA256,
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
            kx,
            share_group,
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

    /**
     * @brief 받은 핸드셰이크 바이트를 넣어 상태를 진행시킨다.
     * @param level 그 데이터가 실려 온 암호화 수준.
     * @details 서버 쪽 provide 와 같은 규칙을 따른다. 받을 수준을 바꾸는 메시지 뒤에 남은 바이트는
     *          처리하지 않고 두며, 부른 쪽이 has_unconsumed_input 으로 확인해 연결을 끊는다.
     * @retval TlsError::UnexpectedMessage 지금 받을 수준이 아닌 데이터이거나, 앞 수준에 남은
     *         바이트가 있다.
     */
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

    /** @brief 지금 핸드셰이크 메시지를 받을 암호화 수준. */
    pub fn receive_level(&self) -> Level {
        match self.state {
            CState::ExpectServerHello => Level::Initial,
            CState::ExpectFlight => Level::Handshake,
            CState::Done => Level::Application,
        }
    }

    /** @brief 받았지만 아직 메시지로 처리하지 않은 바이트가 있는지. */
    pub fn has_unconsumed_input(&self) -> bool {
        self.hr.has_pending()
    }

    /**
     * @brief 다시 시도 요청을 처리한다.
     * @details 요청이 곡선을 고르면 그 곡선의 새 키 조각을 보내고, 쿠키만 담았으면 앞의 키 조각을
     *          그대로 두고 쿠키만 더한다. 해시가 고른 스위트와 다른 재개 제안은 뺀다.
     * @warning 한 번만 받는다. 두 번째가 오면 거부한다. 무한히 다시 시도시키는 것을 막는다.
     *          기록도 규격대로 해시로 바꾼다.
     */
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
            self.kx = new_key_exchange(group)?;
            self.share_group = Some(group);
        }
        let key_shares: Vec<(u16, Vec<u8>)> = self
            .share_group
            .map(|group| vec![(group, self.kx.public_bytes())])
            .unwrap_or_default();
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

    /** @brief 서버 인사말을 처리하고 핸드셰이크 키를 만든다. */
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
        let server_pub = sh.key_share(self.share_group)?;
        let shared = Zeroizing::new(
            self.kx
                .shared_secret(&server_pub)
                .ok_or(TlsError::IllegalParameter)?,
        );

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

    /** @brief 서버 차례의 메시지를 순서대로 처리한다. */
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
                /*
                 * 재개한 세션은 처음 맺을 때와 같은 응용 프로토콜이어야 한다. 조기 데이터는
                 * RFC 8446 대로 티켓과 같은 스위트로 재개할 때만 받아들여질 수 있다.
                 */
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
                    /*
                     * 서버가 받지 않는 서명 방식의 키라면 인증서를 보내지 않고 빈 Certificate 로
                     * 답한다. RFC 8446 은 알맞은 인증서가 없는 클라이언트에 이렇게 하게 하고,
                     * 계속할지는 서버가 정한다.
                     */
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

    /** @brief 핸드셰이크 뒤에 오는 메시지를 처리한다. 세션 티켓이 여기 온다. */
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

    /** @brief 내보낼 핸드셰이크 바이트를 가져간다. */
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

    /** @brief 새로 만들어진 키들을 가져간다. */
    pub fn take_secrets(&mut self) -> Vec<SecretPair> {
        std::mem::take(&mut self.pending_secrets)
    }

    /** @brief 왕복 없이 보낼 자료용 키를 가져간다. */
    pub fn take_early_secret(&mut self) -> Option<Secret> {
        self.early_secret_out.take()
    }

    /** @brief 앞선 세션을 이어 붙였는지. */
    pub fn is_resumed(&self) -> bool {
        self.psk_accepted
    }

    /** @brief 왕복 없이 보낸 자료를 상대가 받아들였는지. */
    pub fn early_data_accepted(&self) -> bool {
        self.early_accepted
    }

    /** @brief 새로 받은 세션 티켓을 꺼낸다. */
    pub fn take_sessions(&mut self) -> Vec<crate::session::TlsSession> {
        std::mem::take(&mut self.new_sessions)
    }

    /** @brief 상대가 알린 전송 설정. */
    pub fn peer_transport_params(&self) -> Option<&[u8]> {
        self.peer_tp.as_deref()
    }

    /** @brief 협상한 ALPN. */
    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /**
     * @brief 검증한 서버의 인증 경로. 리프에서 시작해 이쪽 저장소의 루트로 끝난다.
     * @note 재개한 연결이나 인증서를 검증하지 않은 연결에서는 비어 있다. 리프의 발급자가
     *       필요하면 서버가 보낸 체인이 아니라 이 경로에서 꺼낸다.
     */
    pub fn verified_chain(&self) -> &[X509] {
        &self.verified_chain
    }

    /** @brief 핸드셰이크가 끝났는지. */
    pub fn is_complete(&self) -> bool {
        self.state == CState::Done
    }
}

#[cfg(test)]
/** @brief 실제 구현과의 상호 운용, 재개, 조기 데이터, 그리고 다시 시도 경로. */
mod tests {
    use super::*;

    #[test]
    /** @brief 다른 구현이 만든 인사말에 이쪽이 제대로 답하는지. */
    fn kdig_gnutls_client_hello_produces_server_hello() {
        /** @brief 16진 문자열을 바이트열로. */
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
    /** @brief 암호화된 확장이 정규 형태로 맨 앞에 오는지. */
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
    /**
     * @brief SNI 를 보낸 경우에만 서버의 server_name 응답을 받아들이는지.
     * @details 주소로 붙을 때는 SNI 를 보내지 않는다. RFC 8446 은 보내지 않은 확장에 대한 응답을
     *          받으면 핸드셰이크를 끊게 한다.
     */
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
    /**
     * @brief 암호화된 확장의 결함마다 RFC 8446 과 RFC 9001 이 정한 alert 로 거부하는지.
     * @details 이쪽이 제안한 확장이 올 수 없는 자리에 오면 illegal_parameter, 제안하지 않은
     *          확장이면 unsupported_extension, 전송 매개변수가 빠지면 missing_extension 이다.
     */
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
    /**
     * @brief QUIC 서버가 형식이 깨진 인사말에는 다시 시도 요청을 포함해 아무것도 내지 않는지.
     * @details 서명 방식 목록에 이쪽 방식이 없는 인사말에는 RFC 8446 대로 가진 인증서로 답한다.
     */
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

    /** @brief 테스트용 다시 시도 요청을 만든다. */
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
    /**
     * @brief 이미 보낸 키 조각을 다시 요구하는 요청, 두 번째 다시 시도 요청, 스위트 변경을
     *        각각 RFC 8446 이 정한 alert 로 거부하는지.
     */
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

    /** @brief 테스트용 서버 설정. */
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
    /** @brief QUIC 핸드셰이크마다 인증서와 신뢰 저장소를 깊은 복제하지 않는지. */
    fn server_handshake_retains_shared_server_config() {
        let config = Arc::new(make_server_cfg(vec![b"doq".to_vec()]));
        let certificate = config.cert_chain[0].as_ptr();
        let handshake = ServerHandshake::new(config.clone(), b"transport".to_vec());

        assert!(Arc::ptr_eq(&handshake.cfg, &config));
        assert_eq!(handshake.cfg.cert_chain[0].as_ptr(), certificate);
        assert_eq!(Arc::strong_count(&config), 2);
    }

    /** @brief 검증을 끈 테스트용 클라이언트. 테스트 전용이며 운영 경로에는 없다. */
    fn insecure_test_client() -> ClientConfig {
        ClientConfig {
            roots: None,
            insecure_verifier: Some(
                crate::conn::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            ..Default::default()
        }
    }

    /** @brief 한쪽이 낸 핸드셰이크 데이터를 다른 쪽에 넣는다. */
    fn pump(from: &mut Vec<(Level, Vec<u8>)>, to_provide: &mut dyn FnMut(Level, &[u8])) {
        for (lvl, data) in from.drain(..) {
            to_provide(lvl, &data);
        }
    }

    #[test]
    /** @brief 양쪽이 같은 비밀에 이르는지. */
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
    /** @brief 이름이 다르면 거부하는지. */
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
    /**
     * @brief 응용 프로토콜을 합의하지 못하면 no_application_protocol 로 끝나는지.
     * @details RFC 9001 은 QUIC 에서 ALPN 협상을 필수로 정한다. 서버는 겹치는 프로토콜이 없거나
     *          클라이언트가 ALPN 을 보내지 않았을 때, 클라이언트는 서버가 고르지 않았을 때 끝낸다.
     */
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
    /** @brief 클라이언트 인증이 되는지. */
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
    /**
     * @brief 루트가 바로 발급한 리프 뒤에 이름이 같은 가짜 루트를 붙여 보내도, 엔진이 보관하는
     *        검증 경로는 이쪽 저장소의 루트로 끝나는지.
     */
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
    /** @brief 인증서를 요구했는데 없으면 거부하는지. */
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

    /** @brief 핸드셰이크를 끝까지 돌린다. */
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
    /** @brief 재개와 조기 데이터가 함께 되는지. */
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
    /** @brief HRR 뒤 PSK binder를 다시 계산해 재개하고 변조된 두 번째 binder는 거부하는지. */
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
    /** @brief 위조된 바인더를 거부하는지. 안 하면 티켓만 흉내 내 재개할 수 있다. */
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
    /** @brief 모르는 티켓이면 전체 핸드셰이크로 전환하는지. */
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
    /** @brief 다시 시도 경로가 끝까지 도는지. */
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

    /** @brief 핸드셰이크 바이트에 든 메시지를 하나씩 고쳐 다시 잇는다. */
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

    /** @brief 테스트용 클라이언트. 응용 프로토콜 목록만 정한다. */
    fn test_client(alpn: &[&[u8]]) -> ClientHandshake {
        let cfg = ClientConfig {
            server_name: "localhost".to_string(),
            alpn: alpn.iter().map(|protocol| protocol.to_vec()).collect(),
            ..insecure_test_client()
        };
        ClientHandshake::new(cfg, b"ctp".to_vec()).unwrap()
    }

    #[test]
    /**
     * @brief 엔진이 지금 받을 암호화 수준이 아닌 데이터와, 받을 수준이 바뀐 뒤에 남은 바이트를
     *        unexpected_message 로 거부하는지.
     * @details 받을 수준을 바꾸는 메시지 뒤에 바이트가 남으면 provide 는 그 메시지까지만 처리하고
     *          has_unconsumed_input 으로 알린다. RFC 9001 이 정한 PROTOCOL_VIOLATION 으로 연결을
     *          끊는 일은 QUIC 계층이 한다.
     */
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
    /**
     * @brief 엔진 클라이언트가 쿠키만 담은 다시 시도 요청에는 첫 키 조각과 쿠키로 답하고, 제안하지
     *        않은 곡선을 고른 요청은 illegal_parameter 로 거부하는지.
     */
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
    /**
     * @brief 엔진 서버가 P-256 키 교환을 받아들이고, P-256 으로 다시 시도를 요청했으면 그 곡선의
     *        조각 하나만 받는지.
     * @details RFC 8446 은 secp256r1 키 교환을 반드시 지원하게 한다. 인사말은 엔진 클라이언트가
     *          만든 것에서 지원 곡선과 키 조각만 바꾼다.
     */
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

    /** @brief 테스트 티켓의 재개 비밀. */
    const TEST_TICKET_PSK: [u8; 32] = [0x44; 32];

    /**
     * @brief 서버 설정과 그 서버가 받아들일 세션을 함께 만든다.
     * @param ticket_suite 티켓을 발급한 스위트.
     * @param known 거짓이면 다른 키로 봉한 티켓이라 서버가 열지 못한다.
     */
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

    /** @brief 세션을 제시하며 조기 데이터를 제안하는 클라이언트. */
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
    /**
     * @brief 엔진이 티켓과 해시가 같은 다른 스위트로 재개하고, 조기 데이터는 티켓과 같은
     *        스위트일 때만 받아들이는지.
     * @details 서버는 자기 선호대로 AES-128 을 고르므로 ChaCha20 티켓으로 재개해도 스위트가
     *          바뀐다. RFC 8446 은 해시가 같으면 재개를 허용하고, 조기 데이터는 같은 스위트에서만
     *          허용한다.
     */
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
    /**
     * @brief 서버가 재개하면서 다른 응용 프로토콜을 고르거나, 티켓과 같은 스위트로 재개하지
     *        않았는데 조기 데이터를 받았다고 하면 클라이언트가 illegal_parameter 로 끊는지.
     */
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
    /**
     * @brief 엔진 클라이언트가 RSA 서버의 CertificateVerify 중 RSA PKCS#1 이나 제안하지 않은
     *        방식의 서명을 illegal_parameter 로 거부하고, 제안한 PSS 서명은 받아들이는지.
     * @details 서명 자체는 모두 맞다. 키 종류가 맞는 방식이라 서명 방식 검사만 이를 거부한다.
     *          엔진 클라이언트는 RSA PSS 중 SHA-256 만 제안한다.
     */
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

    /** @brief 클라이언트 인증서를 요구하는 서버 설정과, 그 CA 가 발급한 클라이언트 인증서. */
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

    /** @brief 클라이언트 인증서를 가진 테스트용 클라이언트. */
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
    /**
     * @brief 클라이언트 인증서를 둘러싼 RFC 8446 규칙을 엔진이 양쪽에서 지키는지.
     * @details 서버는 RSA PKCS#1 이나 요청하지 않은 방식의 CertificateVerify 를 illegal_parameter
     *          로 거부한다. 서명은 맞게 만들고 방식 표시만 바꿔, 키 종류 검사가 아니라 서명 방식
     *          검사가 거부하게 한다. 클라이언트는 문맥이 빈 요청만 받고, 요청한 방식으로 서명할 수
     *          없는 키면 빈 Certificate 로 답한다.
     */
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
