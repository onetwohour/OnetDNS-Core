//! The Oblivious HTTP gateway (RFC 9458) on the DoH listener. It decapsulates the Binary HTTP
//! requests a relay forwards, answers those for the DoH path as DoH queries from the relay, and
//! encapsulates the responses.

use std::net::SocketAddr;

use onetdns_http2::{bhttp, DohAnswer, Gateway, GatewayReply};
use onetdns_tls::hpke::{self, HpkeError, PrivateKey, ReceiverContext, N_ENC, N_K, N_N, N_PK, N_T};
use zeroize::Zeroizing;

use crate::odoh::refused_unless_query;
use crate::transport_observe;

const REQUEST_LABEL: &[u8] = b"message/bhttp request";
const RESPONSE_LABEL: &[u8] = b"message/bhttp response";

/// Key ID, KEM, KDF and AEAD, as the Encapsulated Request starts.
const HEADER_LEN: usize = 7;

/// max(N_N, N_K).
const RESPONSE_NONCE_LEN: usize = 16;

/// The gateway has one key, so its ID tells clients nothing.
const KEY_ID: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GatewayError {
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
pub(crate) struct GatewayKey {
    secret: PrivateKey,
    public_key: [u8; N_PK],
    header: [u8; HEADER_LEN],
    /// The `application/ohttp-keys` body: the key configuration with a 2-byte length.
    keys: Vec<u8>,
}

impl GatewayKey {
    pub(crate) fn new(secret: PrivateKey) -> Self {
        Self::with_id(secret, KEY_ID)
    }

    fn with_id(secret: PrivateKey, key_id: u8) -> Self {
        let public_key = secret.public_key();
        let mut header = [0u8; HEADER_LEN];
        header[0] = key_id;
        header[1..3].copy_from_slice(&hpke::KEM_ID.to_be_bytes());
        header[3..5].copy_from_slice(&hpke::KDF_ID.to_be_bytes());
        header[5..7].copy_from_slice(&hpke::AEAD_ID.to_be_bytes());
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

    pub(crate) fn public_key(&self) -> [u8; N_PK] {
        self.public_key
    }

    pub(crate) fn keys(&self) -> &[u8] {
        &self.keys
    }

    fn open_request(&self, encapsulated: &[u8]) -> Result<OpenedRequest, GatewayError> {
        if encapsulated.len() < HEADER_LEN + N_ENC + N_T {
            return Err(GatewayError::Malformed);
        }
        let (header, rest) = encapsulated.split_at(HEADER_LEN);
        if header != self.header {
            return Err(GatewayError::UnknownKey);
        }
        let (enc, ciphertext) = rest.split_at(N_ENC);
        let mut info = Vec::with_capacity(REQUEST_LABEL.len() + 1 + HEADER_LEN);
        info.extend_from_slice(REQUEST_LABEL);
        info.push(0);
        info.extend_from_slice(header);
        let mut context =
            hpke::setup_receiver(enc, &self.secret, &info).map_err(|_| GatewayError::Decrypt)?;
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
struct OpenedRequest {
    context: ReceiverContext,
    enc: [u8; N_ENC],
    request: Zeroizing<Vec<u8>>,
}

impl OpenedRequest {
    fn seal_response(self, response: &[u8]) -> Result<Vec<u8>, HpkeError> {
        self.seal_response_with(onetdns_core::rng::random_array(), response)
    }

    fn seal_response_with(
        self,
        nonce: [u8; RESPONSE_NONCE_LEN],
        response: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        let mut secret = Zeroizing::new([0u8; RESPONSE_NONCE_LEN]);
        self.context.export(RESPONSE_LABEL, &mut *secret)?;
        let mut salt = [0u8; N_ENC + RESPONSE_NONCE_LEN];
        salt[..N_ENC].copy_from_slice(&self.enc);
        salt[N_ENC..].copy_from_slice(&nonce);
        let prk = hpke::extract(&salt, &*secret);
        let mut key = Zeroizing::new([0u8; N_K]);
        let mut aead_nonce = [0u8; N_N];
        hpke::expand(&prk, b"key", &mut *key)?;
        hpke::expand(&prk, b"nonce", &mut aead_nonce)?;
        let sealed = hpke::seal(&key, &aead_nonce, b"", response);
        let mut out = Vec::with_capacity(RESPONSE_NONCE_LEN + sealed.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }
}

/// The gateway on one DoH connection, whose peer is a relay. `resolve` answers a DNS query as the
/// listener answers DoH from that peer.
pub(crate) struct GatewayConn<'a, R> {
    pub(crate) key: &'a GatewayKey,
    pub(crate) peer: SocketAddr,
    pub(crate) doh_path: &'a str,
    pub(crate) resolve: R,
}

impl<R> Gateway for GatewayConn<'_, R>
where
    R: Fn(&[u8]) -> Result<Option<DohAnswer>, &'static str>,
{
    fn keys(&self) -> Vec<u8> {
        self.key.keys().to_vec()
    }

    fn answer(&self, encapsulated: &[u8]) -> GatewayReply {
        let opened = match self.key.open_request(encapsulated) {
            Ok(opened) => opened,
            Err(error) => {
                transport_observe::record_error("ohttp", "open_request", Some(self.peer), error);
                // RFC 9458 names 422 for a key the gateway does not hold or cannot decrypt with.
                return GatewayReply::Status(if error == GatewayError::Malformed {
                    "400"
                } else {
                    "422"
                });
            }
        };
        let answer = match bhttp::doh_query(&opened.request, self.doh_path) {
            Ok(query) => match refused_unless_query(&query) {
                Some(refused) => Ok(DohAnswer {
                    body: refused,
                    max_age: 0,
                }),
                None => match (self.resolve)(&query) {
                    Ok(Some(answer)) => Ok(answer),
                    Ok(None) => return GatewayReply::Unanswered,
                    Err(status) => Err(status),
                },
            },
            Err(status) => Err(status),
        };
        match opened.seal_response(&bhttp::doh_response(answer)) {
            Ok(sealed) => GatewayReply::Response(sealed),
            Err(error) => {
                transport_observe::record_error("ohttp", "seal_response", Some(self.peer), error);
                GatewayReply::Status("502")
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        crate::edge::parse_hex_bytes(&text.replace(' ', "")).unwrap()
    }

    /// The client half, for tests: encapsulates `request` to `keys` and opens the response.
    pub(crate) struct Client {
        context: hpke::SenderContext,
        enc: [u8; N_ENC],
    }

    impl Client {
        pub(crate) fn encapsulate(keys: &[u8], request: &[u8]) -> (Vec<u8>, Self) {
            let config = &keys[2..];
            let (key_id, kem, public_key) = (config[0], &config[1..3], &config[3..3 + N_PK]);
            let mut header = vec![key_id];
            header.extend_from_slice(kem);
            header.extend_from_slice(&hpke::KDF_ID.to_be_bytes());
            header.extend_from_slice(&hpke::AEAD_ID.to_be_bytes());
            let info = [REQUEST_LABEL, &[0], &header].concat();
            let (enc, mut context) = hpke::setup_sender(public_key, &info).unwrap();
            let sealed = context.seal(b"", request).unwrap();
            (
                [header.as_slice(), &enc, &sealed].concat(),
                Self { context, enc },
            )
        }

        pub(crate) fn open(&self, encapsulated: &[u8]) -> Vec<u8> {
            let (nonce, sealed) = encapsulated.split_at(RESPONSE_NONCE_LEN);
            let mut secret = [0u8; RESPONSE_NONCE_LEN];
            self.context.export(RESPONSE_LABEL, &mut secret).unwrap();
            let prk = hpke::extract(&[&self.enc[..], nonce].concat(), &secret);
            let mut key = [0u8; N_K];
            let mut aead_nonce = [0u8; N_N];
            hpke::expand(&prk, b"key", &mut key).unwrap();
            hpke::expand(&prk, b"nonce", &mut aead_nonce).unwrap();
            hpke::open(&key, &aead_nonce, b"", sealed).unwrap()
        }
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
            *opened.request,
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
    /// A query the resolver leaves unanswered resets the stream; a status it gives, or a request
    /// it never sees, still travels encapsulated.
    fn the_gateway_keeps_the_resolvers_decisions() {
        use onetdns_http2::bhttp::{Control, Message as Bhttp};

        let key = GatewayKey::new(PrivateKey::generate());
        let name = onetdns_proto::Name::from_str("zone.test").unwrap();
        let query = onetdns_proto::Message::query(7, name, onetdns_proto::RecordType::SOA);
        let mut update = query.clone();
        update.header.opcode = 5;
        let request = |dns: &onetdns_proto::Message| {
            Bhttp {
                control: Control::Request {
                    method: b"POST".to_vec(),
                    scheme: b"https".to_vec(),
                    authority: Vec::new(),
                    path: b"/dns-query".to_vec(),
                },
                fields: vec![(
                    b"content-type".to_vec(),
                    b"application/dns-message".to_vec(),
                )],
                content: dns.try_encode().unwrap(),
            }
            .encode()
        };
        let answer = |dns: &onetdns_proto::Message, status: Option<&'static str>| {
            let conn = GatewayConn {
                key: &key,
                peer: "192.0.2.9:4000".parse().unwrap(),
                doh_path: "/dns-query",
                resolve: move |_: &[u8]| match status {
                    Some(status) => Err(status),
                    None => Ok(None),
                },
            };
            let (encapsulated, client) = Client::encapsulate(key.keys(), &request(dns));
            match conn.answer(&encapsulated) {
                GatewayReply::Response(sealed) => {
                    Some(Bhttp::decode(&client.open(&sealed)).unwrap())
                }
                GatewayReply::Unanswered => None,
                GatewayReply::Status(status) => panic!("unencapsulated {status}"),
            }
        };
        assert!(answer(&query, None).is_none());
        assert_eq!(
            answer(&query, Some("429")).unwrap().control,
            Control::Response(429)
        );
        let refused = answer(&update, None).expect("UPDATE never reaches the resolver");
        assert_eq!(
            onetdns_proto::Message::parse(&refused.content)
                .unwrap()
                .header
                .rcode,
            onetdns_proto::ResponseCode::Refused.0
        );
    }

    #[test]
    fn a_client_round_trip_carries_the_response() {
        let key = GatewayKey::new(PrivateKey::generate());
        let (encapsulated, client) = Client::encapsulate(&key.keys, b"request");
        let opened = key.open_request(&encapsulated).unwrap();
        assert_eq!(*opened.request, b"request");
        let response = opened.seal_response(b"response").unwrap();
        assert_eq!(client.open(&response), b"response");
    }
}
