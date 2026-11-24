//! Oblivious HTTP (RFC 9458): the encapsulation a gateway and a client share, and the client that
//! sends DoH queries through a relay to a gateway.

use std::net::SocketAddr;
use std::time::Duration;

use onetdns_http2::bhttp::{Control, Message as Bhttp};
use onetdns_http2::ObliviousMedia;
use onetdns_proto::Message;
use onetdns_tls::hpke::{
    self, HpkeError, PrivateKey, ReceiverContext, SenderContext, N_ENC, N_K, N_N, N_PK, N_T,
};
use onetdns_tls::TrustStore;
use zeroize::Zeroizing;

use crate::odoh::{self, KeySource, TargetKeys};
use crate::{validate_response, ForwardError};

const REQUEST_LABEL: &[u8] = b"message/bhttp request";
const RESPONSE_LABEL: &[u8] = b"message/bhttp response";

/// Key ID, KEM, KDF and AEAD, as the Encapsulated Request starts.
const HEADER_LEN: usize = 7;

/// max(N_N, N_K).
const RESPONSE_NONCE_LEN: usize = 16;

/// The gateway has one key, so its ID tells clients nothing.
const KEY_ID: u8 = 0;

/// RFC 8467's block for DNS queries. Padding the whole request to it hides the name's length.
const REQUEST_PADDING_BLOCK: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayError {
    /// Too short for a header, an encapsulated key and a tag.
    Malformed,
    /// The key ID or the algorithms name no key configuration this gateway publishes.
    UnknownKey,
    Decrypt,
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            GatewayError::Malformed => "malformed Oblivious HTTP request",
            GatewayError::UnknownKey => {
                "Oblivious HTTP request names a key configuration the gateway does not publish"
            }
            GatewayError::Decrypt => "could not decrypt the Oblivious HTTP request",
        })
    }
}

/// The gateway's private key and the key configuration that publishes its public half.
pub struct GatewayKey {
    secret: PrivateKey,
    public_key: [u8; N_PK],
    header: [u8; HEADER_LEN],
    /// The `application/ohttp-keys` body: the key configuration with a 2-byte length.
    keys: Vec<u8>,
}

impl GatewayKey {
    pub fn new(secret: PrivateKey) -> Self {
        Self::with_id(secret, KEY_ID)
    }

    fn with_id(secret: PrivateKey, key_id: u8) -> Self {
        let public_key = secret.public_key();
        let header = header(key_id);
        let config_len = 1 + 2 + N_PK + 2 + 4;
        let mut keys = Vec::with_capacity(2 + config_len);
        keys.extend_from_slice(&(config_len as u16).to_be_bytes());
        keys.extend_from_slice(&header[..3]);
        keys.extend_from_slice(&public_key);
        keys.extend_from_slice(&4u16.to_be_bytes());
        keys.extend_from_slice(&header[3..]);
        Self {
            secret,
            public_key,
            header,
            keys,
        }
    }

    pub fn public_key(&self) -> [u8; N_PK] {
        self.public_key
    }

    pub fn keys(&self) -> &[u8] {
        &self.keys
    }

    pub fn open_request(&self, encapsulated: &[u8]) -> Result<OpenedRequest, GatewayError> {
        if encapsulated.len() < HEADER_LEN + N_ENC + N_T {
            return Err(GatewayError::Malformed);
        }
        let (header, rest) = encapsulated.split_at(HEADER_LEN);
        if header != self.header {
            return Err(GatewayError::UnknownKey);
        }
        let (enc, ciphertext) = rest.split_at(N_ENC);
        let mut context = hpke::setup_receiver(enc, &self.secret, &request_info(&self.header))
            .map_err(|_| GatewayError::Decrypt)?;
        let request = Zeroizing::new(
            context
                .open(b"", ciphertext)
                .map_err(|_| GatewayError::Decrypt)?,
        );
        let mut enc_bytes = [0u8; N_ENC];
        enc_bytes.copy_from_slice(enc);
        Ok(OpenedRequest {
            context,
            enc: enc_bytes,
            request,
        })
    }
}

/// A request the gateway decapsulated. Its response must be encapsulated with the same context.
pub struct OpenedRequest {
    context: ReceiverContext,
    enc: [u8; N_ENC],
    request: Zeroizing<Vec<u8>>,
}

impl OpenedRequest {
    /// The Binary HTTP request.
    pub fn request(&self) -> &[u8] {
        &self.request
    }

    pub fn seal_response(self, response: &[u8]) -> Result<Vec<u8>, HpkeError> {
        self.seal_response_with(onetdns_core::rng::random_array(), response)
    }

    fn seal_response_with(
        self,
        nonce: [u8; RESPONSE_NONCE_LEN],
        response: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        let mut secret = Zeroizing::new([0u8; RESPONSE_NONCE_LEN]);
        self.context.export(RESPONSE_LABEL, &mut *secret)?;
        let (key, aead_nonce) = response_key(&secret, &self.enc, &nonce)?;
        let sealed = hpke::seal(&key, &aead_nonce, b"", response);
        let mut out = Vec::with_capacity(RESPONSE_NONCE_LEN + sealed.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }
}

/// A gateway's public key, from one of the key configurations it publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyConfig {
    key_id: u8,
    public_key: [u8; N_PK],
}

impl KeyConfig {
    /// The first configuration in an `application/ohttp-keys` body that has this client's KEM,
    /// KDF and AEAD. `None` when there is none, or when anything in the body is encoded wrongly:
    /// RFC 9458 has clients discard such a body whole, since recovering parts of it differently
    /// would let a gateway tell clients apart.
    pub fn from_keys(mut keys: &[u8]) -> Option<Self> {
        let mut found = None;
        while !keys.is_empty() {
            let (len, rest) = keys.split_at_checked(2)?;
            let (config, rest) =
                rest.split_at_checked(usize::from(u16::from_be_bytes([len[0], len[1]])))?;
            let usable = Self::from_config(config)?;
            found = found.or(usable);
            keys = rest;
        }
        found
    }

    /// `None` for a configuration encoded wrongly, `Some(None)` for one with another KEM or
    /// without this client's KDF and AEAD. Another KEM's key length is unknown, so such a
    /// configuration is not read further.
    fn from_config(config: &[u8]) -> Option<Option<Self>> {
        let (&key_id, rest) = config.split_first()?;
        let (kem, rest) = rest.split_at_checked(2)?;
        if kem != hpke::KEM_ID.to_be_bytes() {
            return Some(None);
        }
        let (public_key, rest) = rest.split_at_checked(N_PK)?;
        let (len, suites) = rest.split_at_checked(2)?;
        if usize::from(u16::from_be_bytes([len[0], len[1]])) != suites.len()
            || suites.is_empty()
            || suites.len() % 4 != 0
        {
            return None;
        }
        let wanted = [hpke::KDF_ID.to_be_bytes(), hpke::AEAD_ID.to_be_bytes()].concat();
        let public_key = public_key.try_into().ok()?;
        Some(
            suites
                .chunks_exact(4)
                .any(|suite| suite == wanted)
                .then_some(Self { key_id, public_key }),
        )
    }

    pub fn encapsulate(&self, request: &[u8]) -> Result<(Vec<u8>, PendingRequest), HpkeError> {
        let header = header(self.key_id);
        let (enc, mut context) = hpke::setup_sender(&self.public_key, &request_info(&header))?;
        let sealed = context.seal(b"", request)?;
        Ok((
            [&header[..], &enc, &sealed].concat(),
            PendingRequest { context, enc },
        ))
    }
}

/// A sent request, whose response is opened with the same context.
pub struct PendingRequest {
    context: SenderContext,
    enc: [u8; N_ENC],
}

impl PendingRequest {
    /// The Binary HTTP response.
    pub fn open_response(&self, response: &[u8]) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
        let (nonce, sealed) = response
            .split_at_checked(RESPONSE_NONCE_LEN)
            .ok_or(HpkeError::Open)?;
        let mut secret = Zeroizing::new([0u8; RESPONSE_NONCE_LEN]);
        self.context.export(RESPONSE_LABEL, &mut *secret)?;
        let (key, aead_nonce) = response_key(&secret, &self.enc, nonce)?;
        hpke::open(&key, &aead_nonce, b"", sealed).map(Zeroizing::new)
    }
}

fn header(key_id: u8) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[0] = key_id;
    header[1..3].copy_from_slice(&hpke::KEM_ID.to_be_bytes());
    header[3..5].copy_from_slice(&hpke::KDF_ID.to_be_bytes());
    header[5..7].copy_from_slice(&hpke::AEAD_ID.to_be_bytes());
    header
}

fn request_info(header: &[u8; HEADER_LEN]) -> Vec<u8> {
    [REQUEST_LABEL, &[0], header].concat()
}

/// The response key and nonce, from the secret both ends export, `enc` and the response nonce.
fn response_key(
    secret: &[u8; RESPONSE_NONCE_LEN],
    enc: &[u8; N_ENC],
    nonce: &[u8],
) -> Result<(Zeroizing<[u8; N_K]>, [u8; N_N]), HpkeError> {
    let prk = hpke::extract(&[&enc[..], nonce].concat(), secret);
    let mut key = Zeroizing::new([0u8; N_K]);
    let mut aead_nonce = [0u8; N_N];
    hpke::expand(&prk, b"key", &mut *key)?;
    hpke::expand(&prk, b"nonce", &mut aead_nonce)?;
    Ok((key, aead_nonce))
}

/// Sends the query as a DoH request for `target` inside an Encapsulated Request, through the relay
/// resource `path` on this thread's pooled connection. RFC 9458 lets a gateway answer a stale key
/// with any 4xx, so a 4xx fails the query and the keys are fetched again later in the background.
#[allow(clippy::too_many_arguments)]
pub(crate) fn exchange(
    relay: SocketAddr,
    server_name: &str,
    path: &str,
    (target_host, target_path): (&str, &str),
    gateway: (&str, SocketAddr),
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
    let TargetKeys::Ohttp(config) = odoh::target_keys(KeySource::Ohttp, gateway, deadline, trust)?
    else {
        return Err(ForwardError::BadResponse);
    };
    let mut doh = Bhttp {
        control: Control::Request {
            method: b"POST".to_vec(),
            scheme: b"https".to_vec(),
            authority: target_host.as_bytes().to_vec(),
            path: target_path.as_bytes().to_vec(),
        },
        fields: vec![
            (
                b"content-type".to_vec(),
                b"application/dns-message".to_vec(),
            ),
            (b"accept".to_vec(), b"application/dns-message".to_vec()),
        ],
        content: query,
    }
    .encode();
    doh.resize(doh.len().next_multiple_of(REQUEST_PADDING_BLOCK), 0);
    let (message, pending) = config
        .encapsulate(&doh)
        .map_err(|_| ForwardError::BadResponse)?;
    match odoh::post(
        relay,
        server_name,
        path,
        &message,
        ObliviousMedia::Ohttp,
        deadline,
        trust,
    )? {
        Ok(body) => {
            let plaintext = pending
                .open_response(&body)
                .map_err(|_| ForwardError::BadResponse)?;
            let response = Bhttp::decode(&plaintext).map_err(|_| ForwardError::BadResponse)?;
            match response.control {
                Control::Response(200) => {}
                Control::Response(status) => {
                    return Err(ForwardError::Io(format!(
                        "OHTTP gateway answered DoH status {status}"
                    )))
                }
                Control::Request { .. } => return Err(ForwardError::BadResponse),
            }
            let answer =
                Message::parse(&response.content).map_err(|_| ForwardError::BadResponse)?;
            validate_response(request, &answer, Some(0))?;
            Ok(answer)
        }
        Err(status @ 400..=499) => {
            odoh::refetch_later(KeySource::Ohttp, gateway, trust);
            Err(ForwardError::Io(format!(
                "OHTTP status {status}; the gateway's keys are fetched again in the background in case they changed"
            )))
        }
        Err(status) => Err(ForwardError::Io(format!("OHTTP status {status}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let text = text.replace(' ', "");
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn vector_key() -> GatewayKey {
        let secret = hex("3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a");
        GatewayKey::with_id(PrivateKey::from_bytes(&secret.try_into().unwrap()), 1)
    }

    const VECTOR_REQUEST: &str = "010020000100014b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b4726374e469135906992e1268c594d2a10c695d858c40a026e7965e7d86b83dd440b2c0185204b4d63525";

    #[test]
    /// RFC 9458 appendix A, whose key configuration also lists ChaCha20Poly1305; this gateway
    /// lists AES-128-GCM alone.
    fn the_rfc_example_decapsulates_and_encapsulates() {
        let key = vector_key();
        assert_eq!(
            key.keys,
            hex("0029 01 0020 31e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155 0004 0001 0001")
        );
        let opened = key.open_request(&hex(VECTOR_REQUEST)).unwrap();
        assert_eq!(
            opened.request(),
            hex("00034745540568747470730b6578616d706c652e636f6d012f")
        );
        let nonce = hex("c789e7151fcba46158ca84b04464910d").try_into().unwrap();
        assert_eq!(
            opened.seal_response_with(nonce, &hex("0140c8")).unwrap(),
            hex("c789e7151fcba46158ca84b04464910d86f9013e404feea014e7be4a441f234f857fbd")
        );
    }

    #[test]
    fn requests_for_other_keys_or_damaged_ones_are_refused() {
        let key = vector_key();
        let request = hex(VECTOR_REQUEST);
        let other_id = GatewayKey::with_id(PrivateKey::from_bytes(&[7; 32]), 1);
        assert_eq!(
            other_id.open_request(&request).err(),
            Some(GatewayError::Decrypt),
            "the same ID with another key cannot decrypt"
        );
        let mut wrong_id = request.clone();
        wrong_id[0] = 2;
        assert_eq!(
            key.open_request(&wrong_id).err(),
            Some(GatewayError::UnknownKey)
        );
        let mut chacha = request.clone();
        chacha[6] = 3;
        assert_eq!(
            key.open_request(&chacha).err(),
            Some(GatewayError::UnknownKey)
        );
        let mut tampered = request.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            key.open_request(&tampered).err(),
            Some(GatewayError::Decrypt)
        );
        assert_eq!(
            key.open_request(&request[..HEADER_LEN + N_ENC + N_T - 1])
                .err(),
            Some(GatewayError::Malformed)
        );
    }

    #[test]
    fn a_client_round_trip_carries_the_response() {
        let key = GatewayKey::new(PrivateKey::generate());
        let config = KeyConfig::from_keys(key.keys()).unwrap();
        let (encapsulated, pending) = config.encapsulate(b"request").unwrap();
        let opened = key.open_request(&encapsulated).unwrap();
        assert_eq!(opened.request(), b"request");
        let response = opened.seal_response(b"response").unwrap();
        assert_eq!(*pending.open_response(&response).unwrap(), b"response");
        assert!(pending
            .open_response(&response[..RESPONSE_NONCE_LEN - 1])
            .is_err());
    }

    #[test]
    /// The client takes the first configuration it can use and skips the others whole.
    fn the_client_picks_a_configuration_it_supports() {
        let vector = vector_key();
        // RFC 9458 appendix A: two suites, AES-128-GCM and ChaCha20Poly1305.
        let rfc = hex("002d 01 0020 31e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155 0008 0001 0001 0001 0003");
        let picked = KeyConfig::from_keys(&rfc).unwrap();
        assert_eq!((picked.key_id, picked.public_key), (1, vector.public_key()));

        let p384 = hex("0006 05 0011 aabbcc");
        let chacha_only = hex("0029 02 0020 31e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155 0004 0001 0003");
        let ours = GatewayKey::new(PrivateKey::generate());
        let list = [&p384[..], &chacha_only, ours.keys()].concat();
        assert_eq!(
            KeyConfig::from_keys(&list).unwrap(),
            KeyConfig {
                key_id: KEY_ID,
                public_key: ours.public_key()
            }
        );

        assert_eq!(
            KeyConfig::from_keys(&[&p384[..], &chacha_only].concat()),
            None
        );
        assert_eq!(KeyConfig::from_keys(&rfc[..rfc.len() - 1]), None);
        assert_eq!(KeyConfig::from_keys(&[&rfc[..], &[0]].concat()), None);
        let odd_suites = hex("002b 03 0020 31e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155 0006 0001 0001 0001");
        assert_eq!(
            KeyConfig::from_keys(&[&odd_suites[..], ours.keys()].concat()),
            None,
            "one configuration encoded wrongly discards the whole list"
        );
    }

    mod client {
        use super::*;
        use std::net::{Ipv4Addr, TcpListener};
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::time::Instant;

        use onetdns_core::MutexExt;
        use onetdns_http2::{bhttp, DohAnswer, GatewayReply, ObliviousHttp, ObliviousReply};
        use onetdns_proto::{Name, RData, Record, RecordType};
        use onetdns_tls::{server_handshake, TlsStream};

        use crate::odoh::tests::client::test_tls;
        use crate::odoh::{refresh_due, Relay, Relayed, REFETCH_AFTER_UNKNOWN_KEY};

        /// Relay and gateway in one server: the relay passes requests to its own address, as a
        /// real relay would to another host.
        struct RelayAndGateway {
            key: Mutex<GatewayKey>,
            addr: SocketAddr,
            relay: Relay,
            key_fetches: AtomicUsize,
            relayed: AtomicUsize,
            authorities: Mutex<Vec<Vec<u8>>>,
        }

        impl ObliviousHttp for RelayAndGateway {
            fn keys(&self) -> Option<Vec<u8>> {
                self.key_fetches.fetch_add(1, Ordering::Relaxed);
                Some(self.key.lock_recover().keys().to_vec())
            }

            fn answer(&self, encapsulated: &[u8]) -> Option<GatewayReply> {
                let Ok(opened) = self.key.lock_recover().open_request(encapsulated) else {
                    return Some(GatewayReply::Status("422"));
                };
                if let Ok(bhttp::Message {
                    control: bhttp::Control::Request { authority, .. },
                    ..
                }) = bhttp::Message::decode(opened.request())
                {
                    self.authorities.lock_recover().push(authority);
                }
                let query = bhttp::doh_query(opened.request(), "/dns-query").unwrap();
                let request = Message::parse(&query).unwrap();
                let mut answer = Message::default();
                answer.header.id = request.header.id;
                answer.header.response = true;
                answer.questions = request.questions.clone();
                answer.answers.push(Record::new(
                    request.questions[0].name.clone(),
                    60,
                    RData::A(Ipv4Addr::new(192, 0, 2, 7)),
                ));
                let body = answer.try_encode().unwrap();
                let response = bhttp::doh_response(Ok(DohAnswer { body, max_age: 60 }));
                Some(GatewayReply::Response(
                    opened.seal_response(&response).unwrap(),
                ))
            }

            fn relays(&self, path: &[u8]) -> bool {
                path == b"/relay"
            }

            fn relay(&self, _: &[u8], encapsulated: &[u8]) -> ObliviousReply {
                self.relayed.fetch_add(1, Ordering::Relaxed);
                match self.relay.send(
                    self.addr,
                    "dns.test",
                    onetdns_http2::OHTTP_GATEWAY_PATH,
                    encapsulated,
                    ObliviousMedia::Ohttp,
                    Duration::from_secs(5),
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

        fn serve() -> (Arc<RelayAndGateway>, Arc<TrustStore>) {
            let (tls, trust) = test_tls();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let server = Arc::new(RelayAndGateway {
                key: Mutex::new(GatewayKey::new(PrivateKey::generate())),
                addr: listener.local_addr().unwrap(),
                relay: Relay::with_trust(trust.clone()),
                key_fetches: AtomicUsize::new(0),
                relayed: AtomicUsize::new(0),
                authorities: Mutex::new(Vec::new()),
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
                            None,
                            Some(&*server as &dyn ObliviousHttp),
                        );
                    });
                }
            });
            (server, trust)
        }

        #[test]
        /// The query reaches the gateway only through the relay. The gateway's keys are fetched by
        /// the first query, and after a 4xx only by the background refresh.
        fn queries_go_through_the_relay_and_follow_a_key_change() {
            let (server, trust) = serve();
            let target_host = format!("dns.test:{}", server.addr.port());
            let upstream = crate::Upstream::ohttp(
                server.addr,
                "dns.test",
                "/relay",
                target_host.clone(),
                "/dns-query",
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
            assert_eq!(server.key_fetches.load(Ordering::Relaxed), 1);
            assert_eq!(server.authorities.lock_recover()[0], target_host.as_bytes());

            *server.key.lock_recover() = GatewayKey::new(PrivateKey::generate());
            assert!(ask(3).is_err(), "the 422 fails the query");
            assert_eq!(
                server.key_fetches.load(Ordering::Relaxed),
                1,
                "a fetch right after the 422 would tie this server's address to the query"
            );
            refresh_due(
                Instant::now() + REFETCH_AFTER_UNKNOWN_KEY.1,
                Some(server.addr),
            );
            assert_eq!(server.key_fetches.load(Ordering::Relaxed), 2);
            ask(4).expect("the refreshed keys carry the new one");
            assert_eq!(server.relayed.load(Ordering::Relaxed), 4);
        }
    }
}
