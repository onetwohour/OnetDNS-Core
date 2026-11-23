//! Oblivious DoH (RFC 9230) messages, for both ends: the target opens queries sealed to its key and
//! seals the response to the same HPKE context, and the client does the reverse.

use onetdns_tls::hpke::{
    self, HpkeError, PrivateKey, ReceiverContext, SenderContext, N_ENC, N_H, N_K, N_N, N_PK, N_T,
};
use zeroize::Zeroizing;

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

#[cfg(test)]
mod tests {
    use super::*;

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
