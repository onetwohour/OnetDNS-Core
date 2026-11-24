//! Oblivious DoH (RFC 9230). The messages serve both ends: the target opens queries sealed to its
//! key and seals the response to the same HPKE context, and the client (`exchange`) does the
//! reverse. The relay carries them for a proxy.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use onetdns_core::{LruMap, MutexExt};
use onetdns_http2::{H2Error, ObliviousMedia};
use onetdns_proto::Message;
use onetdns_tls::hpke::{
    self, HpkeError, PrivateKey, ReceiverContext, SenderContext, N_ENC, N_H, N_K, N_N, N_PK, N_T,
};
use onetdns_tls::{TlsError, TrustStore};
use zeroize::Zeroizing;

use crate::doh::{self, ConnectError, DohConn};
use crate::{validate_response, Endpoint, ForwardError};

const VERSION: u16 = 0x0001;
const QUERY: u8 = 0x01;
const RESPONSE: u8 = 0x02;
const QUERY_INFO: &[u8] = b"odoh query";

/// max(N_N, N_K).
const RESPONSE_NONCE_LEN: usize = 16;

/// Padding block sizes RFC 8467 recommends for queries and responses.
const QUERY_PADDING_BLOCK: usize = 128;
const RESPONSE_PADDING_BLOCK: usize = 468;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OdohError {
    /// Not a well-formed message, config, or plaintext, or the wrong message type.
    Malformed,
    /// The key ID names no key this target has; RFC 9230 answers it with 401.
    UnknownKey,
    /// Authentication failed, or the padding was not all zeros.
    Decrypt,
    /// No config in the list uses version 1 with this suite.
    NoSupportedConfig,
    /// A DNS message too long for the 16-bit length field.
    TooLong,
}

impl std::fmt::Display for OdohError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            OdohError::Malformed => "malformed Oblivious DoH message",
            OdohError::UnknownKey => "Oblivious DoH key ID does not match the target's key",
            OdohError::Decrypt => "could not decrypt the Oblivious DoH message",
            OdohError::NoSupportedConfig => {
                "the target publishes no Oblivious DoH config with a supported cipher suite"
            }
            OdohError::TooLong => "DNS message too long for Oblivious DoH",
        })
    }
}

impl std::error::Error for OdohError {}

impl From<HpkeError> for OdohError {
    fn from(error: HpkeError) -> Self {
        match error {
            HpkeError::Open => OdohError::Decrypt,
            HpkeError::InvalidKey | HpkeError::MessageLimit | HpkeError::TooLong => {
                OdohError::Malformed
            }
        }
    }
}

/// A target's private key and the config that publishes its public half.
pub struct TargetKey {
    secret: PrivateKey,
    config: PublicConfig,
}

impl TargetKey {
    pub fn new(secret: PrivateKey) -> Self {
        let config = PublicConfig::new(secret.public_key());
        Self { secret, config }
    }

    /// ObliviousDoHConfigs listing this key alone.
    pub fn configs(&self) -> Vec<u8> {
        let contents = &self.config.contents;
        let mut config = Vec::with_capacity(4 + contents.len());
        config.extend_from_slice(&VERSION.to_be_bytes());
        put_u16_len(&mut config, contents);
        let mut out = Vec::with_capacity(2 + config.len());
        put_u16_len(&mut out, &config);
        out
    }

    pub fn public_key(&self) -> [u8; N_PK] {
        self.config.public_key
    }

    pub fn open_query(&self, message: &[u8]) -> Result<OpenedQuery, OdohError> {
        let (key_id, encrypted) = parse_message(message, QUERY)?;
        if key_id != self.config.key_id {
            return Err(OdohError::UnknownKey);
        }
        if encrypted.len() < N_ENC + N_T {
            return Err(OdohError::Malformed);
        }
        let (enc, ciphertext) = encrypted.split_at(N_ENC);
        let mut context = hpke::setup_receiver(enc, &self.secret, QUERY_INFO)?;
        let plaintext = Zeroizing::new(context.open(&query_aad(key_id), ciphertext)?);
        let dns_len = plaintext_dns_len(&plaintext)?;
        Ok(OpenedQuery {
            context,
            plaintext,
            dns_len,
        })
    }
}

/// A query the target opened. Its response must be sealed with the same context.
pub struct OpenedQuery {
    context: ReceiverContext,
    plaintext: Zeroizing<Vec<u8>>,
    dns_len: usize,
}

impl OpenedQuery {
    pub fn dns(&self) -> &[u8] {
        &self.plaintext[2..2 + self.dns_len]
    }

    pub fn seal_response(self, dns: &[u8]) -> Result<Vec<u8>, OdohError> {
        let nonce: [u8; RESPONSE_NONCE_LEN] = onetdns_core::rng::random_array();
        let mut secret = Zeroizing::new([0u8; N_K]);
        self.context.export(b"odoh response", &mut *secret)?;
        let (key, aead_nonce) = response_keys(&secret, &self.plaintext, &nonce)?;
        let plaintext = Zeroizing::new(padded_plaintext(dns, RESPONSE_PADDING_BLOCK, N_T)?);
        let sealed = hpke::seal(&key, &aead_nonce, &response_aad(&nonce), &plaintext);
        Ok(encode_message(RESPONSE, &nonce, &sealed))
    }
}

/// The part of a target's config a client encrypts to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicConfig {
    public_key: [u8; N_PK],
    contents: Vec<u8>,
    key_id: [u8; N_H],
}

impl PublicConfig {
    fn new(public_key: [u8; N_PK]) -> Self {
        let mut contents = Vec::with_capacity(8 + N_PK);
        contents.extend_from_slice(&hpke::KEM_ID.to_be_bytes());
        contents.extend_from_slice(&hpke::KDF_ID.to_be_bytes());
        contents.extend_from_slice(&hpke::AEAD_ID.to_be_bytes());
        put_u16_len(&mut contents, &public_key);
        let mut key_id = [0u8; N_H];
        hpke::expand(&hpke::extract(b"", &contents), b"odoh key id", &mut key_id)
            .expect("N_H is within the HKDF limit");
        Self {
            public_key,
            contents,
            key_id,
        }
    }

    /// Takes the first config in the list with version 1 and this suite, skipping others as RFC
    /// 9230 requires; the list is in the target's order of preference.
    pub fn from_configs(configs: &[u8]) -> Result<Self, OdohError> {
        let mut reader = Reader(configs);
        let mut list = Reader(reader.u16_prefixed()?);
        reader.finish()?;
        if list.0.is_empty() {
            return Err(OdohError::Malformed);
        }
        while !list.0.is_empty() {
            let version = list.u16()?;
            let mut contents = Reader(list.u16_prefixed()?);
            if version != VERSION {
                continue;
            }
            let suite = (contents.u16()?, contents.u16()?, contents.u16()?);
            let public_key = contents.u16_prefixed()?;
            contents.finish()?;
            if suite != (hpke::KEM_ID, hpke::KDF_ID, hpke::AEAD_ID) {
                continue;
            }
            let public_key = public_key.try_into().map_err(|_| OdohError::Malformed)?;
            return Ok(Self::new(public_key));
        }
        Err(OdohError::NoSupportedConfig)
    }

    pub fn seal_query(&self, dns: &[u8]) -> Result<(Vec<u8>, PendingQuery), OdohError> {
        let plaintext = Zeroizing::new(padded_plaintext(dns, QUERY_PADDING_BLOCK, N_ENC + N_T)?);
        let (enc, mut context) = hpke::setup_sender(&self.public_key, QUERY_INFO)?;
        let sealed = context.seal(&query_aad(&self.key_id), &plaintext)?;
        let mut encrypted = Vec::with_capacity(N_ENC + sealed.len());
        encrypted.extend_from_slice(&enc);
        encrypted.extend_from_slice(&sealed);
        let message = encode_message(QUERY, &self.key_id, &encrypted);
        Ok((message, PendingQuery { context, plaintext }))
    }
}

/// A query the client sent; holds what opening its response needs.
pub struct PendingQuery {
    context: SenderContext,
    plaintext: Zeroizing<Vec<u8>>,
}

impl PendingQuery {
    pub fn open_response(&self, message: &[u8]) -> Result<Vec<u8>, OdohError> {
        let (nonce, encrypted) = parse_message(message, RESPONSE)?;
        let mut secret = Zeroizing::new([0u8; N_K]);
        self.context.export(b"odoh response", &mut *secret)?;
        let (key, aead_nonce) = response_keys(&secret, &self.plaintext, nonce)?;
        let plaintext = Zeroizing::new(hpke::open(
            &key,
            &aead_nonce,
            &response_aad(nonce),
            encrypted,
        )?);
        let dns_len = plaintext_dns_len(&plaintext)?;
        Ok(plaintext[2..2 + dns_len].to_vec())
    }
}

/// derive_secrets: the response key and nonce, bound to the query plaintext and the target's fresh
/// response nonce.
fn response_keys(
    secret: &[u8; N_K],
    query_plaintext: &[u8],
    nonce: &[u8],
) -> Result<(Zeroizing<[u8; N_K]>, [u8; N_N]), OdohError> {
    let mut salt = Zeroizing::new(Vec::with_capacity(query_plaintext.len() + 2 + nonce.len()));
    salt.extend_from_slice(query_plaintext);
    put_u16_len(&mut salt, nonce);
    let prk = hpke::extract(&salt, secret);
    let mut key = Zeroizing::new([0u8; N_K]);
    let mut aead_nonce = [0u8; N_N];
    hpke::expand(&prk, b"odoh key", &mut *key)?;
    hpke::expand(&prk, b"odoh nonce", &mut aead_nonce)?;
    Ok((key, aead_nonce))
}

fn query_aad(key_id: &[u8]) -> Vec<u8> {
    let mut aad = vec![QUERY];
    put_u16_len(&mut aad, key_id);
    aad
}

fn response_aad(nonce: &[u8]) -> Vec<u8> {
    let mut aad = vec![RESPONSE];
    put_u16_len(&mut aad, nonce);
    aad
}

/// ObliviousDoHMessagePlaintext with zero padding up to a multiple of `block`. `overhead` is what
/// encryption adds; the padding stops short where the encrypted field would outgrow its 16-bit
/// length.
fn padded_plaintext(dns: &[u8], block: usize, overhead: usize) -> Result<Vec<u8>, OdohError> {
    if dns.is_empty() {
        return Err(OdohError::Malformed);
    }
    let room = usize::from(u16::MAX) - overhead - 4;
    if dns.len() > room {
        return Err(OdohError::TooLong);
    }
    let padding = ((block - dns.len() % block) % block).min(room - dns.len());
    let mut out = Vec::with_capacity(4 + dns.len() + padding);
    put_u16_len(&mut out, dns);
    put_u16_len(&mut out, &vec![0; padding]);
    Ok(out)
}

/// The DNS message length of a plaintext whose padding is all zeros and which ends where the
/// padding does.
fn plaintext_dns_len(plaintext: &[u8]) -> Result<usize, OdohError> {
    let mut reader = Reader(plaintext);
    let dns = reader.u16_prefixed()?;
    let padding = reader.u16_prefixed()?;
    reader.finish()?;
    if dns.is_empty() {
        return Err(OdohError::Malformed);
    }
    if padding.iter().any(|&byte| byte != 0) {
        return Err(OdohError::Decrypt);
    }
    Ok(dns.len())
}

fn encode_message(message_type: u8, key_id: &[u8], encrypted: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + key_id.len() + encrypted.len());
    out.push(message_type);
    put_u16_len(&mut out, key_id);
    put_u16_len(&mut out, encrypted);
    out
}

/// Key ID and encrypted message of an ObliviousDoHMessage of the expected type.
fn parse_message(message: &[u8], expected_type: u8) -> Result<(&[u8], &[u8]), OdohError> {
    let mut reader = Reader(message);
    if reader.u8()? != expected_type {
        return Err(OdohError::Malformed);
    }
    let key_id = reader.u16_prefixed()?;
    let encrypted = reader.u16_prefixed()?;
    reader.finish()?;
    if encrypted.is_empty() {
        return Err(OdohError::Malformed);
    }
    Ok((key_id, encrypted))
}

/// Callers only pass fields whose length was checked to fit 16 bits.
fn put_u16_len(out: &mut Vec<u8>, field: &[u8]) {
    let len = u16::try_from(field.len()).expect("Field length fits the 16-bit prefix");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], OdohError> {
        if self.0.len() < len {
            return Err(OdohError::Malformed);
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, OdohError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, OdohError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u16_prefixed(&mut self) -> Result<&'a [u8], OdohError> {
        let len = self.u16()?;
        self.take(usize::from(len))
    }

    fn finish(&self) -> Result<(), OdohError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(OdohError::Malformed)
        }
    }
}

/// Idle target connections a relay keeps, across all targets.
const MAX_IDLE_RELAY_CONNECTIONS: usize = 16;

/// Relays ObliviousDoHMessages to ODoH targets and Encapsulated Requests to OHTTP gateways.
/// Connections are shared by all clients, as RFC 9230 recommends, so a target cannot group queries
/// by connection; a request takes one out of the pool and puts it back when the target has
/// answered.
pub struct Relay {
    trust: Arc<TrustStore>,
    idle: Mutex<Vec<((SocketAddr, String), DohConn)>>,
}

/// What the target answered.
#[derive(Debug, PartialEq, Eq)]
pub enum Relayed {
    /// A 200 with this body.
    Message(Vec<u8>),
    /// Any other final status.
    Status(u16),
}

/// Why the target gave no answer, named as Proxy-Status error types (RFC 9209).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayError {
    ConnectionRefused,
    ConnectionTimeout,
    ConnectionTerminated,
    TlsCertificate,
    TlsProtocol,
    HttpProtocol,
    HttpResponseTimeout,
}

impl RelayError {
    pub fn proxy_status(self) -> &'static str {
        match self {
            RelayError::ConnectionRefused => "connection_refused",
            RelayError::ConnectionTimeout => "connection_timeout",
            RelayError::ConnectionTerminated => "connection_terminated",
            RelayError::TlsCertificate => "tls_certificate_error",
            RelayError::TlsProtocol => "tls_protocol_error",
            RelayError::HttpProtocol => "http_protocol_error",
            RelayError::HttpResponseTimeout => "http_response_timeout",
        }
    }
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.proxy_status())
    }
}

impl Default for Relay {
    fn default() -> Self {
        Self::with_trust(crate::system_trust())
    }
}

impl Relay {
    pub fn with_trust(trust: Arc<TrustStore>) -> Self {
        Self {
            trust,
            idle: Mutex::new(Vec::new()),
        }
    }

    /// POSTs `message` to the target at `https://server_name/path` on `addr`, without redirects
    /// and without any header from the client. A pooled connection that turns out dead is replaced
    /// once. An Encapsulated Request is sent again only when the gateway certainly did not see it,
    /// since RFC 9458 forbids retrying one it may have processed.
    pub fn send(
        &self,
        addr: SocketAddr,
        server_name: &str,
        path: &str,
        message: &[u8],
        media: ObliviousMedia,
        timeout: Duration,
    ) -> Result<Relayed, RelayError> {
        let deadline = crate::deadline_after(timeout);
        let key = (addr, server_name.to_string());
        let mut retried = false;
        loop {
            let pooled = {
                let mut idle = self.idle.lock_recover();
                let found = idle.iter().position(|(have, _)| *have == key);
                found.map(|index| idle.swap_remove(index).1)
            };
            let reused = pooled.is_some();
            let mut conn = match pooled {
                Some(conn) => conn,
                None => doh::connect_h2(
                    &Endpoint::Direct(addr),
                    server_name,
                    deadline,
                    &self.trust,
                    None,
                )
                .map_err(relay_connect_error)?,
            };
            doh::arm_probe(&mut conn, deadline);
            let result =
                conn.client
                    .oblivious_probed(server_name, path, message, media, |stream| {
                        stream.inner_mut().set_deadline(deadline)
                    });
            let relayed = match result {
                Ok(body) => Relayed::Message(body),
                Err(H2Error::BadStatus(status)) => Relayed::Status(status),
                Err(error)
                    if reused
                        && !retried
                        && Instant::now() < deadline
                        && (media == ObliviousMedia::Odoh || matches!(error, H2Error::Refused)) =>
                {
                    retried = true;
                    continue;
                }
                Err(H2Error::Io) if Instant::now() >= deadline => {
                    return Err(RelayError::HttpResponseTimeout)
                }
                Err(H2Error::Io | H2Error::Closed | H2Error::Refused) => {
                    return Err(RelayError::ConnectionTerminated)
                }
                Err(H2Error::Protocol) => return Err(RelayError::HttpProtocol),
            };
            let mut idle = self.idle.lock_recover();
            if idle.len() == MAX_IDLE_RELAY_CONNECTIONS {
                idle.remove(0);
            }
            idle.push((key, conn));
            return Ok(relayed);
        }
    }
}

fn relay_connect_error(error: ConnectError) -> RelayError {
    match error {
        ConnectError::Tcp(ForwardError::Timeout) => RelayError::ConnectionTimeout,
        ConnectError::Tcp(_) => RelayError::ConnectionRefused,
        ConnectError::Tls(
            TlsError::BadCert
            | TlsError::UnknownCa
            | TlsError::CertificateExpired
            | TlsError::CertificateUnknown,
        )
        | ConnectError::Revoked(_) => RelayError::TlsCertificate,
        ConnectError::Tls(_) => RelayError::TlsProtocol,
        ConnectError::Preface => RelayError::HttpProtocol,
    }
}

/// A cached config is fetched again at a random point between half and nine tenths of this.
const CONFIG_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// After a 401 the new config is fetched at a random point in this window, never at once: the fetch
/// comes from this server's address, and a fetch followed by the same question through the proxy
/// would let the target tie the two together.
const REFETCH_AFTER_UNKNOWN_KEY: (Duration, Duration) =
    (Duration::from_secs(30), Duration::from_secs(300));

/// How long to wait before trying a failed background fetch again.
const RETRY_FAILED_FETCH: (Duration, Duration) =
    (Duration::from_secs(60), Duration::from_secs(600));

const REFRESH_POLL: Duration = Duration::from_secs(30);
const REFRESH_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CACHED_CONFIGS: usize = 64;

type ConfigKey = (String, SocketAddr, crate::TlsCacheScope);

struct CachedConfig {
    config: PublicConfig,
    trust: TrustStore,
    refresh_at: Instant,
    used_at: Instant,
}

/// Shared by every thread, so a target's config is fetched once rather than once per thread.
fn config_cache() -> &'static Mutex<LruMap<ConfigKey, CachedConfig>> {
    static CONFIGS: OnceLock<Mutex<LruMap<ConfigKey, CachedConfig>>> = OnceLock::new();
    CONFIGS.get_or_init(|| Mutex::new(LruMap::new(MAX_CACHED_CONFIGS)))
}

fn random_between((low, high): (Duration, Duration)) -> Duration {
    let span = high.saturating_sub(low).as_millis().max(1) as u64;
    let draw = u64::from_le_bytes(onetdns_core::rng::random_array());
    low + Duration::from_millis(draw % span)
}

fn next_refresh(now: Instant) -> Instant {
    now + random_between((CONFIG_LIFETIME / 2, CONFIG_LIFETIME / 10 * 9))
}

/// Refreshes configs in the background, so no fetch is timed by a query.
fn start_refresher() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let spawned = std::thread::Builder::new()
            .name("odoh-config-refresh".into())
            .spawn(|| loop {
                std::thread::sleep(REFRESH_POLL);
                refresh_due(Instant::now());
            });
        if let Err(error) = spawned {
            onetdns_core::warn!(event = "forward.odoh_refresh_spawn_failed", %error, "Could not start ODoH target config refreshes; a target's new key is picked up only after a restart");
        }
    });
}

/// Fetches the configs due by `now` and forgets the ones no query has used for a lifetime.
fn refresh_due(now: Instant) {
    let mut due = Vec::new();
    config_cache().lock_recover().retain(|key, cached| {
        if now.saturating_duration_since(cached.used_at) > CONFIG_LIFETIME {
            return false;
        }
        if cached.refresh_at <= now {
            due.push((key.clone(), cached.trust.clone()));
        }
        true
    });
    for (key, trust) in due {
        let deadline = Instant::now() + REFRESH_TIMEOUT;
        let fetched = fetch_config((&key.0, key.1), deadline, &trust);
        let mut cache = config_cache().lock_recover();
        let Some(cached) = cache.peek_mut(&key) else {
            continue;
        };
        match fetched {
            Ok(config) => {
                cached.config = config;
                cached.refresh_at = next_refresh(Instant::now());
            }
            Err(error) => {
                onetdns_core::debug!(event = "forward.odoh_config_refresh_failed", target = %key.0, %error, "Could not refresh an ODoH target's key config; keeping the cached one");
                cached.refresh_at = Instant::now() + random_between(RETRY_FAILED_FETCH);
            }
        }
    }
}

/// The proxy request path: `proxy_path` with the target in `targethost` and `targetpath`, encoded
/// as RFC 9230's URI template `{?targethost,targetpath}` expands them.
pub fn proxy_request_path(proxy_path: &str, target_host: &str, target_path: &str) -> String {
    fn encode(value: &str) -> String {
        value
            .bytes()
            .map(|byte| match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    (byte as char).to_string()
                }
                _ => format!("%{byte:02X}"),
            })
            .collect()
    }
    format!(
        "{proxy_path}?targethost={}&targetpath={}",
        encode(target_host),
        encode(target_path)
    )
}

/// Seals the query to the target's key and sends it through the proxy on this thread's pooled
/// connection. A 401 means the target changed its key: the query fails, and the new config is
/// fetched later in the background.
#[allow(clippy::too_many_arguments)]
pub(crate) fn exchange(
    proxy: SocketAddr,
    server_name: &str,
    path: &str,
    target: (&str, SocketAddr),
    wire: &[u8],
    request: &Message,
    timeout: Duration,
    trust: &TrustStore,
) -> Result<Message, ForwardError> {
    let deadline = crate::deadline_after(timeout);
    if wire.len() < 2 {
        return Err(ForwardError::BadResponse);
    }
    let mut query = wire.to_vec();
    query[..2].fill(0);
    let config = target_config(target, deadline, trust)?;
    let (message, pending) = config
        .seal_query(&query)
        .map_err(|_| ForwardError::BadResponse)?;
    let reply = doh::with_pooled(
        &Endpoint::Direct(proxy),
        server_name,
        path,
        deadline,
        trust,
        |conn| {
            doh::arm_probe(conn, deadline);
            let sent = conn.client.oblivious_probed(
                server_name,
                path,
                &message,
                ObliviousMedia::Odoh,
                |stream| stream.inner_mut().set_deadline(deadline),
            );
            match sent {
                Ok(body) => Ok(Ok(body)),
                Err(H2Error::BadStatus(status)) => Ok(Err(status)),
                Err(H2Error::Closed | H2Error::Refused) => {
                    Err(ForwardError::Io("ODoH proxy closed the connection".into()))
                }
                Err(H2Error::Protocol) => Err(ForwardError::BadResponse),
                Err(H2Error::Io) => Err(ForwardError::Io(
                    "I/O error on the ODoH proxy connection".into(),
                )),
            }
        },
    )?;
    match reply {
        Ok(body) => {
            let plaintext = pending
                .open_response(&body)
                .map_err(|_| ForwardError::BadResponse)?;
            let response = Message::parse(&plaintext).map_err(|_| ForwardError::BadResponse)?;
            validate_response(request, &response, Some(0))?;
            Ok(response)
        }
        Err(401) => {
            refetch_later(target, trust);
            Err(ForwardError::Io(
                "The ODoH target no longer accepts its cached key; fetching the new one in the background".into(),
            ))
        }
        Err(status) => Err(ForwardError::Io(format!("ODoH status {status}"))),
    }
}

/// Only the first query to a target fetches its config itself.
fn target_config(
    (name, addr): (&str, SocketAddr),
    deadline: Instant,
    trust: &TrustStore,
) -> Result<PublicConfig, ForwardError> {
    let key = (name.to_string(), addr, crate::tls_cache_scope(trust));
    if let Some(cached) = config_cache().lock_recover().get_mut(&key) {
        cached.used_at = Instant::now();
        return Ok(cached.config.clone());
    }
    let config = fetch_config((name, addr), deadline, trust)?;
    let now = Instant::now();
    config_cache().lock_recover().put(
        key,
        CachedConfig {
            config: config.clone(),
            trust: trust.clone(),
            refresh_at: next_refresh(now),
            used_at: now,
        },
    );
    start_refresher();
    Ok(config)
}

/// The first 401 picks the time. Taking the earliest of every 401's pick would pull it toward the
/// start of the window.
fn refetch_later((name, addr): (&str, SocketAddr), trust: &TrustStore) {
    let key = (name.to_string(), addr, crate::tls_cache_scope(trust));
    if let Some(cached) = config_cache().lock_recover().peek_mut(&key) {
        let now = Instant::now();
        if cached.refresh_at > now + REFETCH_AFTER_UNKNOWN_KEY.1 {
            cached.refresh_at = now + random_between(REFETCH_AFTER_UNKNOWN_KEY);
        }
    }
}

fn fetch_config(
    (name, addr): (&str, SocketAddr),
    deadline: Instant,
    trust: &TrustStore,
) -> Result<PublicConfig, ForwardError> {
    let mut conn =
        doh::connect_h2(&Endpoint::Direct(addr), name, deadline, trust, None).map_err(|error| {
            match error {
                ConnectError::Tcp(error) => error,
                ConnectError::Tls(error) => {
                    crate::note_upstream_connect_failure("odoh", addr, name, &error);
                    ForwardError::Io(format!("ODoH target handshake: {error}"))
                }
                ConnectError::Revoked(error) => error,
                ConnectError::Preface => ForwardError::Io("ODoH target HTTP/2 preface".into()),
            }
        })?;
    conn.client.stream_mut().inner_mut().set_deadline(deadline);
    let body = conn
        .client
        .odoh_configs(name)
        .map_err(|error| match error {
            H2Error::BadStatus(status) => {
                ForwardError::Io(format!("ODoH target config status {status}"))
            }
            _ => ForwardError::Io("Could not fetch the ODoH target config".into()),
        })?;
    PublicConfig::from_configs(&body).map_err(|_| ForwardError::BadResponse)
}

#[cfg(test)]
mod tests {
    use super::*;

    mod client {
        use super::*;
        use std::net::{Ipv4Addr, TcpListener};
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::thread;

        use onetdns_http2::{GatewayReply, Oblivious, ObliviousHttp, ObliviousReply};
        use onetdns_proto::{Name, RData, Record, RecordType};
        use onetdns_tls::{
            server_handshake, signer_from_pkcs8_der, ServerConfig as TlsServerConfig, TlsStream,
        };

        /// Proxy and target in one server: the proxy relays to its own address, as a real proxy
        /// would to another host.
        struct ProxyAndTarget {
            key: Mutex<TargetKey>,
            addr: SocketAddr,
            relay: Relay,
            config_fetches: AtomicUsize,
            relayed_to: Mutex<Vec<(String, String)>>,
        }

        impl Oblivious for ProxyAndTarget {
            fn configs(&self) -> Option<Vec<u8>> {
                self.config_fetches.fetch_add(1, Ordering::Relaxed);
                Some(self.key.lock_recover().configs())
            }

            fn target(&self, message: &[u8]) -> ObliviousReply {
                let key = self.key.lock_recover();
                let opened = match key.open_query(message) {
                    Ok(opened) => opened,
                    Err(OdohError::UnknownKey) => return ObliviousReply::Status("401"),
                    Err(_) => return ObliviousReply::Status("400"),
                };
                let request = Message::parse(opened.dns()).unwrap();
                let mut answer = Message::default();
                answer.header.id = request.header.id;
                answer.header.response = true;
                answer.questions = request.questions.clone();
                answer.answers.push(Record::new(
                    request.questions[0].name.clone(),
                    60,
                    RData::A(Ipv4Addr::new(192, 0, 2, 7)),
                ));
                let sealed = opened.seal_response(&answer.try_encode().unwrap());
                ObliviousReply::Message(sealed.unwrap())
            }

            fn proxy(&self, host: &str, path: &str, message: &[u8]) -> ObliviousReply {
                self.relayed_to
                    .lock_recover()
                    .push((host.to_string(), path.to_string()));
                let timeout = Duration::from_secs(5);
                match self.relay.send(
                    self.addr,
                    "dns.test",
                    path,
                    message,
                    ObliviousMedia::Odoh,
                    timeout,
                ) {
                    Ok(Relayed::Message(message)) => ObliviousReply::Message(message),
                    Ok(Relayed::Status(status)) => ObliviousReply::TargetStatus(status),
                    Err(error) => ObliviousReply::ProxyError {
                        status: "502",
                        error: error.proxy_status(),
                    },
                }
            }
        }

        fn test_tls() -> (Arc<TlsServerConfig>, Arc<TrustStore>) {
            let ck = rcgen::generate_simple_self_signed(vec!["dns.test".to_string()]).unwrap();
            let cert_der = ck.cert.der().to_vec();
            let key_der = ck.key_pair.serialize_der();
            let trust = Arc::new(TrustStore::from_ders([cert_der.as_slice()]));
            let (sign_scheme, sign) = signer_from_pkcs8_der(&key_der).unwrap();
            let tls = Arc::new(TlsServerConfig {
                cert_chain: vec![cert_der],
                sign_scheme,
                sign,
                alpn: vec![b"h2".to_vec()],
                client_ca: None,
                resumption: None,
            });
            (tls, trust)
        }

        fn serve() -> (Arc<ProxyAndTarget>, Arc<TrustStore>) {
            let (tls, trust) = test_tls();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let server = Arc::new(ProxyAndTarget {
                key: Mutex::new(TargetKey::new(PrivateKey::generate())),
                addr: listener.local_addr().unwrap(),
                relay: Relay::with_trust(trust.clone()),
                config_fetches: AtomicUsize::new(0),
                relayed_to: Mutex::new(Vec::new()),
            });
            let shared = server.clone();
            thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut tcp) = stream else { continue };
                    let (tls, server) = (tls.clone(), shared.clone());
                    thread::spawn(move || {
                        let Ok(conn) = server_handshake(&mut tcp, &tls) else {
                            return;
                        };
                        let mut stream = TlsStream::new(conn, tcp);
                        let _ = onetdns_http2::serve_doh_with_deadline_reset(
                            &mut stream,
                            "/dns-query",
                            |_, _| Err("404"),
                            |_| {},
                            &AtomicBool::new(false),
                            Some(&*server as &dyn Oblivious),
                            None,
                        );
                    });
                }
            });
            (server, trust)
        }

        #[test]
        /// The query reaches the target only through the proxy. The target's config is fetched by
        /// the first query, and after a 401 only by the background refresh.
        fn queries_go_through_the_proxy_and_follow_a_key_change() {
            let (server, trust) = serve();
            let target_host = format!("dns.test:{}", server.addr.port());
            let path = proxy_request_path("/dns-query", &target_host, "/dns-query");
            let upstream = crate::Upstream::odoh(
                server.addr,
                "dns.test",
                path.clone(),
                "dns.test",
                server.addr,
            );
            let ask = |id: u16| {
                let request =
                    Message::query(id, Name::from_str("page.test").unwrap(), RecordType::A);
                let wire = request.try_encode().unwrap();
                crate::exchange_one(
                    &upstream,
                    &wire,
                    id,
                    &request,
                    Duration::from_secs(5),
                    &trust,
                )
            };

            for id in [1, 2] {
                let answer = ask(id).unwrap();
                assert_eq!(
                    answer.header.id, 0,
                    "sent with ID 0 like DoH; the caller restores it"
                );
                assert!(matches!(
                    answer.answers[0].rdata,
                    RData::A(ip) if ip == Ipv4Addr::new(192, 0, 2, 7)
                ));
            }
            assert_eq!(server.config_fetches.load(Ordering::Relaxed), 1);
            assert_eq!(
                server.relayed_to.lock_recover()[0],
                (target_host.clone(), "/dns-query".to_string())
            );

            *server.key.lock_recover() = TargetKey::new(PrivateKey::generate());
            assert!(ask(3).is_err(), "the 401 fails the query");
            assert_eq!(
                server.config_fetches.load(Ordering::Relaxed),
                1,
                "a fetch right after the 401 would tie this server's address to the query"
            );
            refresh_due(Instant::now() + REFETCH_AFTER_UNKNOWN_KEY.1);
            assert_eq!(server.config_fetches.load(Ordering::Relaxed), 2);
            ask(4).expect("the refreshed config carries the new key");
            assert_eq!(server.config_fetches.load(Ordering::Relaxed), 2);
            assert_eq!(server.relayed_to.lock_recover().len(), 4);
        }

        /// Answers the first request on its connection, reversed, and closes the connection on the
        /// next without a reply or a GOAWAY, as a server that may have processed it would. Its
        /// OHTTP side is a relay resource, the route that can close a connection.
        struct AnswersOnce {
            answered: AtomicBool,
            requests: Arc<AtomicUsize>,
        }

        impl AnswersOnce {
            fn reply(&self, message: &[u8]) -> ObliviousReply {
                self.requests.fetch_add(1, Ordering::Relaxed);
                if self.answered.swap(true, Ordering::Relaxed) {
                    ObliviousReply::Drop
                } else {
                    ObliviousReply::Message(message.iter().rev().copied().collect())
                }
            }
        }

        impl Oblivious for AnswersOnce {
            fn configs(&self) -> Option<Vec<u8>> {
                None
            }

            fn target(&self, message: &[u8]) -> ObliviousReply {
                self.reply(message)
            }

            fn proxy(&self, _: &str, _: &str, _: &[u8]) -> ObliviousReply {
                unreachable!("not a proxy")
            }
        }

        impl ObliviousHttp for AnswersOnce {
            fn keys(&self) -> Option<Vec<u8>> {
                None
            }

            fn answer(&self, _: &[u8]) -> Option<GatewayReply> {
                None
            }

            fn relays(&self, path: &[u8]) -> bool {
                path == b"/relay"
            }

            fn relay(&self, _: &[u8], encapsulated: &[u8]) -> ObliviousReply {
                self.reply(encapsulated)
            }
        }

        fn serve_answering_once() -> (SocketAddr, Arc<TrustStore>, Arc<AtomicUsize>) {
            let (tls, trust) = test_tls();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let requests = Arc::new(AtomicUsize::new(0));
            let counted = requests.clone();
            thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut tcp) = stream else { continue };
                    let (tls, requests) = (tls.clone(), counted.clone());
                    thread::spawn(move || {
                        let Ok(conn) = server_handshake(&mut tcp, &tls) else {
                            return;
                        };
                        let mut stream = TlsStream::new(conn, tcp);
                        let upstream = AnswersOnce {
                            answered: AtomicBool::new(false),
                            requests,
                        };
                        let _ = onetdns_http2::serve_doh_with_deadline_reset(
                            &mut stream,
                            "/dns-query",
                            |_, _| Err("404"),
                            |_| {},
                            &AtomicBool::new(false),
                            Some(&upstream),
                            Some(&upstream),
                        );
                    });
                }
            });
            (addr, trust, requests)
        }

        #[test]
        /// A pooled connection that ends without an answer may have carried the request to the
        /// server. RFC 9458 forbids sending an Encapsulated Request again then; an ODoH message
        /// goes again on a new connection.
        fn only_odoh_messages_are_sent_again_after_a_pooled_connection_ends() {
            let (addr, trust, requests) = serve_answering_once();
            let relay = Relay::with_trust(trust);
            let send = |path, media| {
                relay.send(
                    addr,
                    "dns.test",
                    path,
                    b"abc",
                    media,
                    Duration::from_secs(5),
                )
            };
            let answered = Ok(Relayed::Message(b"cba".to_vec()));

            assert_eq!(send("/relay", ObliviousMedia::Ohttp), answered);
            assert_eq!(
                send("/relay", ObliviousMedia::Ohttp),
                Err(RelayError::ConnectionTerminated)
            );
            assert_eq!(requests.load(Ordering::Relaxed), 2);

            assert_eq!(send("/dns-query", ObliviousMedia::Odoh), answered);
            assert_eq!(send("/dns-query", ObliviousMedia::Odoh), answered);
            assert_eq!(
                requests.load(Ordering::Relaxed),
                5,
                "the second ODoH message went on the pooled connection, then on a new one"
            );
        }

        #[test]
        fn proxy_request_paths_encode_the_target_as_the_uri_template_does() {
            assert_eq!(
                proxy_request_path("/proxy", "odoh.example:8443", "/dns-query"),
                "/proxy?targethost=odoh.example%3A8443&targetpath=%2Fdns-query"
            );
            assert_eq!(
                proxy_request_path("/p", "[2001:db8::1]", "/a~b_c.d-e"),
                "/p?targethost=%5B2001%3Adb8%3A%3A1%5D&targetpath=%2Fa~b_c.d-e"
            );
        }
    }

    #[test]
    fn relay_reports_a_target_it_cannot_reach() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = closed.local_addr().unwrap();
        drop(closed);
        assert_eq!(
            Relay::default().send(
                addr,
                "odoh.test",
                "/q",
                b"sealed",
                ObliviousMedia::Ohttp,
                Duration::from_secs(10)
            ),
            Err(RelayError::ConnectionRefused)
        );
        assert_eq!(
            RelayError::ConnectionRefused.proxy_status(),
            "connection_refused"
        );
    }

    fn target() -> TargetKey {
        TargetKey::new(PrivateKey::generate())
    }

    fn client_config(target: &TargetKey) -> PublicConfig {
        PublicConfig::from_configs(&target.configs()).unwrap()
    }

    #[test]
    fn a_query_and_its_response_round_trip() {
        let target = target();
        let config = client_config(&target);
        let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x00\x00\x01\x00\x01";
        let (message, pending) = config.seal_query(query).unwrap();
        assert_eq!(message[0], QUERY);

        let opened = target.open_query(&message).unwrap();
        assert_eq!(opened.dns(), query);
        let response = b"response bytes standing in for a DNS answer";
        let sealed = opened.seal_response(response).unwrap();
        assert_eq!(sealed[0], RESPONSE);
        assert_eq!(pending.open_response(&sealed).unwrap(), response);
    }

    #[test]
    fn plaintexts_are_padded_to_the_rfc_8467_blocks() {
        let target = target();
        let config = client_config(&target);
        let (short, _) = config.seal_query(&[1; 10]).unwrap();
        let (longer, _) = config.seal_query(&[1; 100]).unwrap();
        assert_eq!(short.len(), longer.len(), "both pad to one 128-byte block");
        let (over, _) = config.seal_query(&[1; 130]).unwrap();
        assert_eq!(over.len(), short.len() + QUERY_PADDING_BLOCK);

        let padded = padded_plaintext(&[7; 470], RESPONSE_PADDING_BLOCK, N_T).unwrap();
        assert_eq!((padded.len() - 4) % RESPONSE_PADDING_BLOCK, 0);
        assert_eq!(plaintext_dns_len(&padded), Ok(470));
    }

    #[test]
    /// The largest DNS message still seals: padding gives way so the encrypted field keeps a 16-bit
    /// length.
    fn padding_never_outgrows_the_length_field() {
        let target = target();
        let largest = vec![1; usize::from(u16::MAX) - 4 - N_T];
        let opened_query = {
            let (message, _) = client_config(&target).seal_query(&[1; 20]).unwrap();
            target.open_query(&message).unwrap()
        };
        let sealed = opened_query.seal_response(&largest).unwrap();
        assert_eq!(
            sealed.len(),
            1 + 2 + RESPONSE_NONCE_LEN + 2 + usize::from(u16::MAX)
        );
        assert_eq!(
            padded_plaintext(&[1; 65_516], RESPONSE_PADDING_BLOCK, N_T),
            Err(OdohError::TooLong)
        );
        assert_eq!(
            client_config(&target)
                .seal_query(&vec![1; usize::from(u16::MAX) - 4 - N_T])
                .err(),
            Some(OdohError::TooLong),
            "the query's encrypted field also carries the encapsulated key"
        );
    }

    #[test]
    fn config_publishes_the_key_and_its_id() {
        let target = target();
        let configs = target.configs();
        // ObliviousDoHConfigs<..> { version 1, length, contents { 0x20, 1, 1, public_key } }
        assert_eq!(&configs[..2], &((configs.len() - 2) as u16).to_be_bytes());
        assert_eq!(&configs[2..4], &[0, 1]);
        assert_eq!(&configs[6..12], &[0, 0x20, 0, 1, 0, 1]);
        assert_eq!(&configs[14..], &target.public_key());

        let parsed = client_config(&target);
        assert_eq!(parsed.public_key, target.public_key());
        assert_eq!(parsed.key_id, target.config.key_id);
        let mut expected_id = [0u8; N_H];
        hpke::expand(
            &hpke::extract(b"", &configs[6..]),
            b"odoh key id",
            &mut expected_id,
        )
        .unwrap();
        assert_eq!(
            parsed.key_id, expected_id,
            "Expand(Extract(\"\", contents))"
        );
    }

    #[test]
    fn unsupported_configs_are_skipped_for_a_supported_one() {
        let target = target();
        let supported = &target.configs()[2..];
        let mut list = Vec::new();
        // Version 2, which this client does not know.
        list.extend_from_slice(&[0, 2, 0, 3, 9, 9, 9]);
        // Version 1 with a P-256 KEM.
        let p256 = [0, 0x10, 0, 1, 0, 1, 0, 2, 4, 4];
        let mut config = vec![0, 1];
        put_u16_len(&mut config, &p256);
        list.extend_from_slice(&config);
        list.extend_from_slice(supported);
        let mut configs = Vec::new();
        put_u16_len(&mut configs, &list);
        let parsed = PublicConfig::from_configs(&configs).unwrap();
        assert_eq!(parsed.public_key, target.public_key());

        let mut only_unknown = Vec::new();
        put_u16_len(&mut only_unknown, &[0, 2, 0, 3, 9, 9, 9]);
        assert_eq!(
            PublicConfig::from_configs(&only_unknown),
            Err(OdohError::NoSupportedConfig)
        );
        assert_eq!(
            PublicConfig::from_configs(&[0, 0]),
            Err(OdohError::Malformed)
        );
        let mut trailing = target.configs();
        trailing.push(0);
        assert_eq!(
            PublicConfig::from_configs(&trailing),
            Err(OdohError::Malformed)
        );
    }

    #[test]
    fn a_query_for_another_key_is_unknown_not_malformed() {
        let target = target();
        let other = TargetKey::new(PrivateKey::generate());
        let (message, _) = client_config(&other).seal_query(&[1; 20]).unwrap();
        assert!(matches!(
            target.open_query(&message),
            Err(OdohError::UnknownKey)
        ));
    }

    #[test]
    fn tampering_and_wrong_types_are_rejected() {
        let target = target();
        let config = client_config(&target);
        let (message, pending) = config.seal_query(&[1; 20]).unwrap();

        let mut flipped = message.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(matches!(
            target.open_query(&flipped),
            Err(OdohError::Decrypt)
        ));

        let mut as_response = message.clone();
        as_response[0] = RESPONSE;
        assert!(matches!(
            target.open_query(&as_response),
            Err(OdohError::Malformed)
        ));

        let mut trailing = message.clone();
        trailing.push(0);
        assert!(matches!(
            target.open_query(&trailing),
            Err(OdohError::Malformed)
        ));
        assert!(matches!(
            target.open_query(&message[..message.len() - 1]),
            Err(OdohError::Malformed)
        ));

        let response = target
            .open_query(&message)
            .unwrap()
            .seal_response(&[2; 30])
            .unwrap();
        let mut bad_response = response.clone();
        bad_response[5] ^= 1;
        assert_eq!(
            pending.open_response(&bad_response),
            Err(OdohError::Decrypt),
            "the response nonce is authenticated"
        );
        assert_eq!(
            pending.open_response(&message),
            Err(OdohError::Malformed),
            "a query is not a response"
        );
        assert_eq!(pending.open_response(&response).unwrap(), vec![2; 30]);
    }

    #[test]
    fn nonzero_padding_is_a_decryption_failure() {
        let mut plaintext = padded_plaintext(&[1; 3], QUERY_PADDING_BLOCK, N_ENC + N_T).unwrap();
        *plaintext.last_mut().unwrap() = 1;
        assert_eq!(plaintext_dns_len(&plaintext), Err(OdohError::Decrypt));
        assert_eq!(
            padded_plaintext(&[], QUERY_PADDING_BLOCK, N_ENC + N_T),
            Err(OdohError::Malformed)
        );
    }

    #[test]
    fn each_response_draws_a_fresh_nonce() {
        let target = target();
        let config = client_config(&target);
        let (message, pending) = config.seal_query(&[1; 20]).unwrap();
        let first = target
            .open_query(&message)
            .unwrap()
            .seal_response(&[3; 10])
            .unwrap();
        let second = target
            .open_query(&message)
            .unwrap()
            .seal_response(&[3; 10])
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(pending.open_response(&first).unwrap(), vec![3; 10]);
        assert_eq!(pending.open_response(&second).unwrap(), vec![3; 10]);
    }
}
