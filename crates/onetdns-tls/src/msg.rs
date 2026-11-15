//! Handshake message encoding and parsing: client and server hellos and their extensions.
//!
//! Non-canonical encodings are rejected. If one meaning could be written several ways,
//! implementations would read it differently, and that difference becomes a way to steer
//! negotiation.

use crate::handshake::{HandshakeMsg, HandshakeType};
use crate::tls12::{EXT_EC_POINT_FORMATS, EXT_EXTENDED_MASTER_SECRET, EXT_RENEGOTIATION_INFO};
use crate::wire::{Reader, Writer};
use crate::TlsError;

pub mod consts {

    pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
    pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
    pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

    pub const X25519: u16 = 0x001d;
    pub const SECP256R1: u16 = 0x0017;
    pub const SECP384R1: u16 = 0x0018;

    pub const ED25519: u16 = 0x0807;
    pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
    pub const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
    pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
    pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
    pub const RSA_PSS_RSAE_SHA512: u16 = 0x0806;
    /// TLS 1.3 uses it only for certificate signatures.
    pub const RSA_PKCS1_SHA256: u16 = 0x0401;
    pub const RSA_PKCS1_SHA384: u16 = 0x0501;
    pub const RSA_PKCS1_SHA512: u16 = 0x0601;

    pub const EXT_SERVER_NAME: u16 = 0;
    pub const EXT_SUPPORTED_GROUPS: u16 = 10;
    pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
    pub const EXT_ALPN: u16 = 16;
    /// Must be the last extension.
    pub const EXT_PRE_SHARED_KEY: u16 = 41;
    pub const EXT_EARLY_DATA: u16 = 42;
    /// TLS 1.3 is negotiated through this.
    pub const EXT_SUPPORTED_VERSIONS: u16 = 43;
    pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
    /// Public values sent ahead to save a round trip.
    pub const EXT_KEY_SHARE: u16 = 51;

    /// Resumption with a key exchange too, keeping forward secrecy.
    pub const PSK_DHE_KE: u8 = 1;
    /// Carried in HelloRetryRequest.
    pub const EXT_COOKIE: u16 = 44;

    pub const TLS13: u16 = 0x0304;
    pub const TLS12: u16 = 0x0303;
    /// A hello whose legacy_version is at or below this is protocol_version.
    pub const SSL30: u16 = 0x0300;
}

/// A ServerHello with this random is a HelloRetryRequest; not telling them apart breaks the
/// handshake.
pub const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

use consts::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    pub ext_type: u16,
    pub data: Vec<u8>,
}

impl Extension {
    pub fn new(ext_type: u16, data: Vec<u8>) -> Self {
        Self { ext_type, data }
    }

    pub fn encode_into(&self, w: &mut Writer) {
        w.u16(self.ext_type);
        w.vec16(|w| w.bytes(&self.data));
    }

    /// Rejects duplicates.
    pub fn parse_list(bytes: &[u8]) -> Result<Vec<Extension>, TlsError> {
        let mut r = Reader::new(bytes);
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        while !r.is_empty() {
            let ext_type = r.u16()?;
            if !seen.insert(ext_type) {
                return Err(TlsError::Decode);
            }
            let data = r.vec16()?.to_vec();
            out.push(Extension { ext_type, data });
        }
        Ok(out)
    }

    pub(crate) fn parse_vector(bytes: &[u8]) -> Result<Vec<Extension>, TlsError> {
        let mut reader = Reader::new(bytes);
        let extensions = Self::parse_list(reader.vec16()?)?;
        if !reader.is_empty() {
            return Err(TlsError::Decode);
        }
        Ok(extensions)
    }

    pub fn find(exts: &[Extension], ext_type: u16) -> Option<&Extension> {
        exts.iter().find(|e| e.ext_type == ext_type)
    }

    pub fn supported_versions_client(versions: &[u16]) -> Extension {
        let mut w = Writer::new();
        w.vec8(|w| {
            for v in versions {
                w.u16(*v);
            }
        });
        Extension::new(EXT_SUPPORTED_VERSIONS, w.buf)
    }

    pub fn supported_versions_server(version: u16) -> Extension {
        let mut w = Writer::new();
        w.u16(version);
        Extension::new(EXT_SUPPORTED_VERSIONS, w.buf)
    }

    pub fn key_share_client(entries: &[(u16, Vec<u8>)]) -> Extension {
        let mut w = Writer::new();
        w.vec16(|w| {
            for (g, k) in entries {
                w.u16(*g);
                w.vec16(|w| w.bytes(k));
            }
        });
        Extension::new(EXT_KEY_SHARE, w.buf)
    }

    pub fn key_share_server(group: u16, key: &[u8]) -> Extension {
        let mut w = Writer::new();
        w.u16(group);
        w.vec16(|w| w.bytes(key));
        Extension::new(EXT_KEY_SHARE, w.buf)
    }

    pub fn supported_groups(groups: &[u16]) -> Extension {
        let mut w = Writer::new();
        w.vec16(|w| {
            for g in groups {
                w.u16(*g);
            }
        });
        Extension::new(EXT_SUPPORTED_GROUPS, w.buf)
    }

    pub fn signature_algorithms(schemes: &[u16]) -> Extension {
        let mut w = Writer::new();
        w.vec16(|w| {
            for s in schemes {
                w.u16(*s);
            }
        });
        Extension::new(EXT_SIGNATURE_ALGORITHMS, w.buf)
    }

    pub fn server_name(host: &str) -> Extension {
        let mut w = Writer::new();
        w.vec16(|w| {
            w.u8(0);
            w.vec16(|w| w.bytes(host.as_bytes()));
        });
        Extension::new(EXT_SERVER_NAME, w.buf)
    }

    pub fn alpn(protocols: &[&[u8]]) -> Extension {
        let mut w = Writer::new();
        w.vec16(|w| {
            for p in protocols {
                w.vec8(|w| w.bytes(p));
            }
        });
        Extension::new(EXT_ALPN, w.buf)
    }

    pub fn psk_key_exchange_modes(modes: &[u8]) -> Extension {
        let mut w = Writer::new();
        w.vec8(|w| w.bytes(modes));
        Extension::new(EXT_PSK_KEY_EXCHANGE_MODES, w.buf)
    }

    pub fn pre_shared_key_client(
        identity: &[u8],
        obfuscated_age: u32,
        binder_len: usize,
    ) -> Extension {
        let mut w = Writer::new();
        w.vec16(|w| {
            w.vec16(|w| w.bytes(identity));
            w.u32(obfuscated_age);
        });
        w.vec16(|w| {
            w.vec8(|w| w.bytes(&vec![0u8; binder_len]));
        });
        Extension::new(EXT_PRE_SHARED_KEY, w.buf)
    }

    pub fn pre_shared_key_server(selected: u16) -> Extension {
        let mut w = Writer::new();
        w.u16(selected);
        Extension::new(EXT_PRE_SHARED_KEY, w.buf)
    }

    pub fn early_data() -> Extension {
        Extension::new(EXT_EARLY_DATA, Vec::new())
    }

    pub fn early_data_nst(max: u32) -> Extension {
        let mut w = Writer::new();
        w.u32(max);
        Extension::new(EXT_EARLY_DATA, w.buf)
    }

    pub fn key_share_hrr(group: u16) -> Extension {
        let mut w = Writer::new();
        w.u16(group);
        Extension::new(EXT_KEY_SHARE, w.buf)
    }

    pub fn as_key_share_hrr(&self) -> Option<u16> {
        let mut r = Reader::new(&self.data);
        let group = r.u16().ok()?;
        r.is_empty().then_some(group)
    }

    pub fn cookie(data: &[u8]) -> Extension {
        let mut w = Writer::new();
        w.vec16(|w| w.bytes(data));
        Extension::new(EXT_COOKIE, w.buf)
    }

    pub fn as_cookie(&self) -> Option<Vec<u8>> {
        let mut r = Reader::new(&self.data);
        let cookie = r.vec16().ok()?.to_vec();
        (!cookie.is_empty() && r.is_empty()).then_some(cookie)
    }

    pub fn as_supported_versions_client(&self) -> Option<Vec<u16>> {
        let mut r = Reader::new(&self.data);
        let list = r.vec8().ok()?;
        if !r.is_empty() || list.is_empty() {
            return None;
        }
        let mut lr = Reader::new(list);
        let mut out = Vec::new();
        while !lr.is_empty() {
            out.push(lr.u16().ok()?);
        }
        Some(out)
    }

    pub fn as_supported_versions_server(&self) -> Option<u16> {
        let mut r = Reader::new(&self.data);
        let version = r.u16().ok()?;
        r.is_empty().then_some(version)
    }

    pub fn as_key_share_client(&self) -> Option<Vec<(u16, Vec<u8>)>> {
        let mut r = Reader::new(&self.data);
        let list = r.vec16().ok()?;
        if !r.is_empty() {
            return None;
        }
        let mut lr = Reader::new(list);
        let mut out = Vec::new();
        while !lr.is_empty() {
            let group = lr.u16().ok()?;
            let key = lr.vec16().ok()?.to_vec();
            if key.is_empty() {
                return None;
            }
            out.push((group, key));
        }
        Some(out)
    }

    pub fn as_key_share_server(&self) -> Option<(u16, Vec<u8>)> {
        let mut r = Reader::new(&self.data);
        let group = r.u16().ok()?;
        let key = r.vec16().ok()?.to_vec();
        (!key.is_empty() && r.is_empty()).then_some((group, key))
    }

    /// None when malformed or when no usable host name is present.
    pub fn as_server_name(&self) -> Option<String> {
        self.parse_server_name().ok().flatten()
    }

    /// An error when malformed; None when there is no host name entry or it is not UTF-8. The list
    /// and the host name must not be empty, and there must be only one host name entry. Entries of
    /// other types are read as length-prefixed values too.
    fn parse_server_name(&self) -> Result<Option<String>, TlsError> {
        let mut r = Reader::new(&self.data);
        let list = r.vec16()?;
        if !r.is_empty() || list.is_empty() {
            return Err(TlsError::Decode);
        }
        let mut lr = Reader::new(list);
        let mut host: Option<&[u8]> = None;
        while !lr.is_empty() {
            let ntype = lr.u8()?;
            let name = lr.vec16()?;
            if ntype == 0 {
                if name.is_empty() || host.is_some() {
                    return Err(TlsError::Decode);
                }
                host = Some(name);
            }
        }
        Ok(host.and_then(|name| String::from_utf8(name.to_vec()).ok()))
    }

    pub fn as_alpn(&self) -> Option<Vec<Vec<u8>>> {
        let mut r = Reader::new(&self.data);
        let list = r.vec16().ok()?;
        if !r.is_empty() || list.is_empty() {
            return None;
        }
        let mut lr = Reader::new(list);
        let mut out = Vec::new();
        while !lr.is_empty() {
            let protocol = lr.vec8().ok()?.to_vec();
            if protocol.is_empty() {
                return None;
            }
            out.push(protocol);
        }
        Some(out)
    }

    /// Returns one protocol from `offered`. UnsupportedExtension when it came without an offer,
    /// Decode when malformed, IllegalParameter when it is not exactly one or not in the offered
    /// list.
    pub(crate) fn selected_alpn(&self, offered: &[Vec<u8>]) -> Result<Vec<u8>, TlsError> {
        if offered.is_empty() {
            return Err(TlsError::UnsupportedExtension);
        }
        let mut protocols = self.as_alpn().ok_or(TlsError::Decode)?;
        if protocols.len() != 1 || !offered.contains(&protocols[0]) {
            return Err(TlsError::IllegalParameter);
        }
        Ok(protocols.remove(0))
    }

    pub fn as_psk_modes(&self) -> Option<Vec<u8>> {
        let mut r = Reader::new(&self.data);
        let modes = r.vec8().ok()?.to_vec();
        (!modes.is_empty() && r.is_empty()).then_some(modes)
    }

    pub fn as_ec_point_formats(&self) -> Option<Vec<u8>> {
        let mut r = Reader::new(&self.data);
        let formats = r.vec8().ok()?.to_vec();
        (!formats.is_empty() && r.is_empty()).then_some(formats)
    }

    pub fn as_supported_groups(&self) -> Option<Vec<u16>> {
        let mut r = Reader::new(&self.data);
        let list = r.vec16().ok()?;
        if !r.is_empty() || list.is_empty() {
            return None;
        }
        let mut lr = Reader::new(list);
        let mut out = Vec::new();
        while !lr.is_empty() {
            out.push(lr.u16().ok()?);
        }
        Some(out)
    }

    pub fn as_signature_algorithms(&self) -> Option<Vec<u16>> {
        let mut reader = Reader::new(&self.data);
        let list = reader.vec16().ok()?;
        if !reader.is_empty() || list.is_empty() {
            return None;
        }
        let mut list_reader = Reader::new(list);
        let mut algorithms = Vec::new();
        while !list_reader.is_empty() {
            algorithms.push(list_reader.u16().ok()?);
        }
        Some(algorithms)
    }

    pub fn as_pre_shared_key_client(&self) -> Option<(Vec<(Vec<u8>, u32)>, Vec<Vec<u8>>)> {
        let mut r = Reader::new(&self.data);
        let ids_raw = r.vec16().ok()?;
        let mut ir = Reader::new(ids_raw);
        let mut identities = Vec::new();
        while !ir.is_empty() {
            let identity = ir.vec16().ok()?.to_vec();
            if identity.is_empty() {
                return None;
            }
            let age = ir.u32().ok()?;
            identities.push((identity, age));
        }
        let binders_raw = r.vec16().ok()?;
        if !r.is_empty() || identities.is_empty() {
            return None;
        }
        let mut br = Reader::new(binders_raw);
        let mut binders = Vec::new();
        while !br.is_empty() {
            let binder = br.vec8().ok()?.to_vec();
            if binder.len() < 32 {
                return None;
            }
            binders.push(binder);
        }
        (identities.len() == binders.len()).then_some((identities, binders))
    }

    pub fn as_pre_shared_key_server(&self) -> Option<u16> {
        let mut r = Reader::new(&self.data);
        let selected = r.u16().ok()?;
        r.is_empty().then_some(selected)
    }

    pub fn as_early_data_max(&self) -> Option<u32> {
        let mut r = Reader::new(&self.data);
        let max = r.u32().ok()?;
        r.is_empty().then_some(max)
    }

    /// None for types this stack does not interpret, which are passed over unread as RFC 8446
    /// requires. QUIC transport parameters are read by the QUIC layer, so they count as not
    /// interpreted here.
    pub fn client_hello_syntax_ok(&self) -> Option<bool> {
        let ok = match self.ext_type {
            EXT_SERVER_NAME => self.parse_server_name().is_ok(),
            EXT_SUPPORTED_GROUPS => self.as_supported_groups().is_some(),
            EXT_SIGNATURE_ALGORITHMS => self.as_signature_algorithms().is_some(),
            EXT_ALPN => self.as_alpn().is_some(),
            EXT_EXTENDED_MASTER_SECRET | EXT_EARLY_DATA => self.data.is_empty(),
            EXT_PRE_SHARED_KEY => self.as_pre_shared_key_client().is_some(),
            EXT_SUPPORTED_VERSIONS => self.as_supported_versions_client().is_some(),
            EXT_COOKIE => self.as_cookie().is_some(),
            EXT_PSK_KEY_EXCHANGE_MODES => self.as_psk_modes().is_some(),
            EXT_KEY_SHARE => self.as_key_share_client().is_some(),
            EXT_RENEGOTIATION_INFO => {
                let mut r = Reader::new(&self.data);
                r.vec8().is_ok() && r.is_empty()
            }
            EXT_EC_POINT_FORMATS => self.as_ec_point_formats().is_some(),
            _ => return None,
        };
        Some(ok)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSessionTicket {
    pub lifetime_secs: u32,
    pub age_add: u32,
    pub nonce: Vec<u8>,
    pub ticket: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl NewSessionTicket {
    pub fn parse(body: &[u8]) -> Result<NewSessionTicket, TlsError> {
        let mut r = Reader::new(body);
        let lifetime_secs = r.u32()?;
        let age_add = r.u32()?;
        let nonce = r.vec8()?.to_vec();
        let ticket = r.vec16()?.to_vec();
        let extensions = Extension::parse_list(r.vec16()?)?;
        if !r.is_empty() || ticket.is_empty() {
            return Err(TlsError::Decode);
        }
        Ok(NewSessionTicket {
            lifetime_secs,
            age_add,
            nonce,
            ticket,
            extensions,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(self.lifetime_secs);
        w.u32(self.age_add);
        w.vec8(|w| w.bytes(&self.nonce));
        w.vec16(|w| w.bytes(&self.ticket));
        w.vec16(|w| {
            for e in &self.extensions {
                e.encode_into(w);
            }
        });
        w.buf
    }

    pub fn max_early_data(&self) -> u32 {
        Extension::find(&self.extensions, EXT_EARLY_DATA)
            .and_then(|e| e.as_early_data_max())
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl ClientHello {
    pub(crate) fn retained_payload_bytes(&self) -> usize {
        self.session_id
            .capacity()
            .saturating_add(
                self.cipher_suites
                    .capacity()
                    .saturating_mul(std::mem::size_of::<u16>()),
            )
            .saturating_add(self.compression_methods.capacity())
            .saturating_add(
                self.extensions
                    .capacity()
                    .saturating_mul(std::mem::size_of::<Extension>()),
            )
            .saturating_add(self.extensions.iter().fold(0usize, |total, extension| {
                total.saturating_add(extension.data.capacity())
            }))
    }

    /// Follows RFC 8446: with supported_versions, only that list counts and legacy_version is
    /// ignored; without it, a legacy_version of 1.2 or higher offers 1.2. A legacy_version of
    /// 0x0304 without the extension still gets a 1.2 answer. ProtocolVersion when legacy_version is
    /// SSL 3.0 or lower; Decode when supported_versions is malformed.
    pub(crate) fn offers_version(&self, version: u16) -> Result<bool, TlsError> {
        if self.legacy_version <= SSL30 {
            return Err(TlsError::ProtocolVersion);
        }
        match self.ext(EXT_SUPPORTED_VERSIONS) {
            Some(extension) => Ok(extension
                .as_supported_versions_client()
                .ok_or(TlsError::Decode)?
                .contains(&version)),
            None => Ok(version == TLS12 && self.legacy_version >= TLS12),
        }
    }

    /// Also checks the extensions RFC 8446 requires of a TLS 1.3 hello: with a PSK offer,
    /// psk_key_exchange_modes; without one, signature_algorithms and supported_groups.
    /// supported_groups and key_share come together or not at all. legacy_version plays no part in
    /// version negotiation, so only SSL 3.0 or lower is rejected.
    ///
    /// The PSK extension must be last: the binder covers the bytes before it, so anything after it
    /// would go unauthenticated.
    pub(crate) fn validate_tls13(&self) -> Result<(), TlsError> {
        if !self.offers_version(TLS13)? {
            return Err(TlsError::ProtocolVersion);
        }
        if self.compression_methods != [0] {
            return Err(TlsError::IllegalParameter);
        }
        if self
            .extensions
            .iter()
            .position(|extension| extension.ext_type == EXT_PRE_SHARED_KEY)
            .is_some_and(|position| position + 1 != self.extensions.len())
        {
            return Err(TlsError::IllegalParameter);
        }
        let has = |ext_type| self.ext(ext_type).is_some();
        let complete = has(EXT_SUPPORTED_GROUPS) == has(EXT_KEY_SHARE)
            && if has(EXT_PRE_SHARED_KEY) {
                has(EXT_PSK_KEY_EXCHANGE_MODES)
            } else {
                has(EXT_SUPPORTED_GROUPS) && has(EXT_SIGNATURE_ALGORITHMS)
            };
        if !complete {
            return Err(TlsError::MissingExtension);
        }
        Ok(())
    }

    /// Picks in this side's preference order. An empty `supported` means ALPN is not used, and
    /// nothing is picked when the client sent no extension. When both sides use ALPN with no
    /// overlap, the handshake ends with NoApplicationProtocol, as RFC 7301 requires.
    pub(crate) fn select_alpn(&self, supported: &[Vec<u8>]) -> Result<Option<Vec<u8>>, TlsError> {
        if supported.is_empty() {
            return Ok(None);
        }
        let Some(extension) = self.ext(EXT_ALPN) else {
            return Ok(None);
        };
        let offered = extension.as_alpn().ok_or(TlsError::Decode)?;
        supported
            .iter()
            .find(|protocol| offered.contains(protocol))
            .cloned()
            .map(Some)
            .ok_or(TlsError::NoApplicationProtocol)
    }

    /// Empty when the extension is absent.
    pub(crate) fn signature_algorithms(&self) -> Vec<u16> {
        self.ext(EXT_SIGNATURE_ALGORITHMS)
            .and_then(Extension::as_signature_algorithms)
            .unwrap_or_default()
    }

    pub(crate) fn offers_signature_scheme(&self, scheme: u16) -> bool {
        self.signature_algorithms().contains(&scheme)
    }

    /// Whether the second ClientHello after a HelloRetryRequest changed only what is allowed.
    pub(crate) fn is_valid_retry_of(&self, first: &ClientHello) -> bool {
        if self.legacy_version != first.legacy_version
            || self.random != first.random
            || self.session_id != first.session_id
            || self.cipher_suites != first.cipher_suites
            || self.compression_methods != first.compression_methods
            || self.ext(EXT_EARLY_DATA).is_some()
        {
            return false;
        }

        let unchanged = |extension: &Extension, other: &ClientHello| {
            other
                .ext(extension.ext_type)
                .is_some_and(|candidate| candidate.data == extension.data)
        };
        for extension in &first.extensions {
            if !matches!(
                extension.ext_type,
                EXT_KEY_SHARE | EXT_COOKIE | EXT_EARLY_DATA | EXT_PRE_SHARED_KEY
            ) && !unchanged(extension, self)
            {
                return false;
            }
        }
        for extension in &self.extensions {
            if !matches!(
                extension.ext_type,
                EXT_KEY_SHARE | EXT_COOKIE | EXT_PRE_SHARED_KEY
            ) && !unchanged(extension, first)
            {
                return false;
            }
        }

        let first_psks = first
            .ext(EXT_PRE_SHARED_KEY)
            .map(Extension::as_pre_shared_key_client);
        let retry_psks = self
            .ext(EXT_PRE_SHARED_KEY)
            .map(Extension::as_pre_shared_key_client);
        match (first_psks, retry_psks) {
            (Some(None), _) | (_, Some(None)) | (None, Some(Some(_))) => false,
            (_, None) => true,
            (Some(Some((first_ids, _))), Some(Some((retry_ids, _)))) => {
                let mut remaining = first_ids.as_slice();
                retry_ids.into_iter().all(|(retry_id, _)| {
                    let Some(position) = remaining
                        .iter()
                        .position(|(first_id, _)| *first_id == retry_id)
                    else {
                        return false;
                    };
                    remaining = &remaining[position + 1..];
                    true
                })
            }
        }
    }

    /// Rejects the whole hello when an extension this stack interprets is malformed. Treating it as
    /// absent would answer hellos other implementations reject, and would even send a
    /// HelloRetryRequest for a hello with a broken key share.
    pub fn parse(body: &[u8]) -> Result<ClientHello, TlsError> {
        let mut r = Reader::new(body);
        let legacy_version = r.u16()?;
        let random: [u8; 32] = r.take(32)?.try_into().map_err(|_| TlsError::Decode)?;
        let session_id = r.vec8()?.to_vec();
        if session_id.len() > 32 {
            return Err(TlsError::Decode);
        }
        let cs = r.vec16()?;
        if cs.is_empty() {
            return Err(TlsError::Decode);
        }
        let mut csr = Reader::new(cs);
        let mut cipher_suites = Vec::new();
        while !csr.is_empty() {
            cipher_suites.push(csr.u16()?);
        }
        let compression_methods = r.vec8()?.to_vec();
        if compression_methods.is_empty() {
            return Err(TlsError::Decode);
        }
        let extensions = Extension::parse_list(r.vec16()?)?;
        if extensions
            .iter()
            .any(|extension| extension.client_hello_syntax_ok() == Some(false))
        {
            return Err(TlsError::Decode);
        }

        if !r.is_empty() {
            return Err(TlsError::Decode);
        }
        Ok(ClientHello {
            legacy_version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(self.legacy_version);
        w.bytes(&self.random);
        w.vec8(|w| w.bytes(&self.session_id));
        w.vec16(|w| {
            for cs in &self.cipher_suites {
                w.u16(*cs);
            }
        });
        w.vec8(|w| w.bytes(&self.compression_methods));
        w.vec16(|w| {
            for e in &self.extensions {
                e.encode_into(w);
            }
        });
        w.buf
    }

    pub fn from_handshake(msg: &HandshakeMsg) -> Result<ClientHello, TlsError> {
        if msg.msg_type != HandshakeType::ClientHello {
            return Err(TlsError::UnexpectedMessage);
        }
        ClientHello::parse(&msg.body)
    }

    pub fn to_handshake(&self) -> HandshakeMsg {
        HandshakeMsg::new(HandshakeType::ClientHello, self.encode())
    }

    pub fn ext(&self, ext_type: u16) -> Option<&Extension> {
        Extension::find(&self.extensions, ext_type)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    /// The client's session ID, echoed back.
    pub session_id_echo: Vec<u8>,
    pub cipher_suite: u16,
    pub extensions: Vec<Extension>,
}

impl ServerHello {
    /// `hrr` says whether this is a HelloRetryRequest. The session ID is compared with the
    /// client's; a difference means a man in the middle changed it. An extension that cannot appear
    /// in this message is IllegalParameter when this side offered that type, since it is in the
    /// wrong place, and UnsupportedExtension when it did not. supported_versions sets the version,
    /// so legacy_version is rejected only at SSL 3.0 or lower.
    pub(crate) fn validate_tls13(&self, hello: &ClientHello, hrr: bool) -> Result<(), TlsError> {
        if self.legacy_version <= SSL30 {
            return Err(TlsError::ProtocolVersion);
        }
        if self.session_id_echo != hello.session_id {
            return Err(TlsError::IllegalParameter);
        }
        let version = self
            .ext(EXT_SUPPORTED_VERSIONS)
            .ok_or(TlsError::MissingExtension)?
            .as_supported_versions_server()
            .ok_or(TlsError::Decode)?;
        if version != TLS13 {
            return Err(TlsError::IllegalParameter);
        }
        for extension in &self.extensions {
            let allowed = matches!(extension.ext_type, EXT_SUPPORTED_VERSIONS | EXT_KEY_SHARE)
                || (hrr && extension.ext_type == EXT_COOKIE)
                || (!hrr && extension.ext_type == EXT_PRE_SHARED_KEY);
            if allowed {
                continue;
            }
            return Err(if hello.ext(extension.ext_type).is_some() {
                TlsError::IllegalParameter
            } else {
                TlsError::UnsupportedExtension
            });
        }
        Ok(())
    }

    /// RFC 8446 requires the chosen group to be among the first hello's supported groups with no
    /// key share sent for it, and the request to change something in the hello. A request with only
    /// a cookie is answered by keeping the first hello's key shares and adding the cookie. Returns
    /// the group to send a key share for in the second hello, or None for a cookie-only request.
    /// IllegalParameter when the request breaks the spec.
    pub(crate) fn validate_retry_request(
        &self,
        hello: &ClientHello,
    ) -> Result<Option<u16>, TlsError> {
        self.validate_tls13(hello, true)?;
        let selected = match self.ext(EXT_KEY_SHARE) {
            Some(extension) => Some(extension.as_key_share_hrr().ok_or(TlsError::Decode)?),
            None => None,
        };
        let offered_groups = hello
            .ext(EXT_SUPPORTED_GROUPS)
            .and_then(Extension::as_supported_groups)
            .unwrap_or_default();
        let shared_groups: Vec<u16> = hello
            .ext(EXT_KEY_SHARE)
            .and_then(Extension::as_key_share_client)
            .unwrap_or_default()
            .into_iter()
            .map(|(group, _)| group)
            .collect();
        match selected {
            Some(group) if !offered_groups.contains(&group) || shared_groups.contains(&group) => {
                Err(TlsError::IllegalParameter)
            }
            Some(group) => Ok(Some(group)),
            None if self.ext(EXT_COOKIE).is_some() => Ok(None),
            None => Err(TlsError::IllegalParameter),
        }
    }

    /// `sent` is the group this side sent a key share for in its last hello, if any.
    /// MissingExtension when there is no key share: this stack never offers resumption without one,
    /// so the server must send it. IllegalParameter when the server picked a group this side sent
    /// no key share for.
    pub(crate) fn key_share(&self, sent: Option<u16>) -> Result<Vec<u8>, TlsError> {
        let (group, key) = self
            .ext(EXT_KEY_SHARE)
            .ok_or(TlsError::MissingExtension)?
            .as_key_share_server()
            .ok_or(TlsError::Decode)?;
        if Some(group) != sent {
            return Err(TlsError::IllegalParameter);
        }
        Ok(key)
    }

    pub fn parse(body: &[u8]) -> Result<ServerHello, TlsError> {
        let mut r = Reader::new(body);
        let legacy_version = r.u16()?;
        let random: [u8; 32] = r.take(32)?.try_into().map_err(|_| TlsError::Decode)?;
        let session_id_echo = r.vec8()?.to_vec();
        if session_id_echo.len() > 32 {
            return Err(TlsError::Decode);
        }
        let cipher_suite = r.u16()?;
        let legacy_compression = r.u8()?;
        if legacy_compression != 0 {
            return Err(TlsError::IllegalParameter);
        }
        let extensions = Extension::parse_list(r.vec16()?)?;

        if !r.is_empty() {
            return Err(TlsError::Decode);
        }
        Ok(ServerHello {
            legacy_version,
            random,
            session_id_echo,
            cipher_suite,
            extensions,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(self.legacy_version);
        w.bytes(&self.random);
        w.vec8(|w| w.bytes(&self.session_id_echo));
        w.u16(self.cipher_suite);
        w.u8(0);
        w.vec16(|w| {
            for e in &self.extensions {
                e.encode_into(w);
            }
        });
        w.buf
    }

    pub fn from_handshake(msg: &HandshakeMsg) -> Result<ServerHello, TlsError> {
        if msg.msg_type != HandshakeType::ServerHello {
            return Err(TlsError::UnexpectedMessage);
        }
        ServerHello::parse(&msg.body)
    }

    pub fn to_handshake(&self) -> HandshakeMsg {
        HandshakeMsg::new(HandshakeType::ServerHello, self.encode())
    }

    pub fn ext(&self, ext_type: u16) -> Option<&Extension> {
        Extension::find(&self.extensions, ext_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_roundtrip_with_extensions() {
        let ch = ClientHello {
            legacy_version: TLS12,
            random: [0x11; 32],
            session_id: vec![0xAB; 32],
            cipher_suites: vec![TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256],
            compression_methods: vec![0],
            extensions: vec![
                Extension::supported_versions_client(&[TLS13]),
                Extension::server_name("dns.example.com"),
                Extension::key_share_client(&[(X25519, vec![0x42; 32])]),
                Extension::alpn(&[b"dot", b"h2"]),
            ],
        };
        let body = ch.encode();
        let back = ClientHello::parse(&body).unwrap();
        assert_eq!(back, ch);

        assert_eq!(
            back.ext(EXT_SUPPORTED_VERSIONS)
                .unwrap()
                .as_supported_versions_client(),
            Some(vec![TLS13])
        );
        assert_eq!(
            back.ext(EXT_SERVER_NAME)
                .unwrap()
                .as_server_name()
                .as_deref(),
            Some("dns.example.com")
        );
        let ks = back
            .ext(EXT_KEY_SHARE)
            .unwrap()
            .as_key_share_client()
            .unwrap();
        assert_eq!(ks.len(), 1);
        assert_eq!(ks[0].0, X25519);
        assert_eq!(ks[0].1, vec![0x42; 32]);
        assert_eq!(
            back.ext(EXT_ALPN).unwrap().as_alpn().unwrap(),
            vec![b"dot".to_vec(), b"h2".to_vec()]
        );
    }

    #[test]
    fn server_hello_roundtrip() {
        let sh = ServerHello {
            legacy_version: TLS12,
            random: [0x55; 32],
            session_id_echo: vec![0xAB; 32],
            cipher_suite: TLS_AES_128_GCM_SHA256,
            extensions: vec![
                Extension::supported_versions_server(TLS13),
                Extension::key_share_server(X25519, &[0x99; 32]),
            ],
        };
        let body = sh.encode();
        let back = ServerHello::parse(&body).unwrap();
        assert_eq!(back, sh);
        assert_eq!(
            back.ext(EXT_SUPPORTED_VERSIONS)
                .unwrap()
                .as_supported_versions_server(),
            Some(TLS13)
        );
        let (g, k) = back
            .ext(EXT_KEY_SHARE)
            .unwrap()
            .as_key_share_server()
            .unwrap();
        assert_eq!(g, X25519);
        assert_eq!(k, vec![0x99; 32]);
    }

    #[test]
    fn handshake_wrapping() {
        let ch = ClientHello {
            legacy_version: TLS12,
            random: [0; 32],
            session_id: vec![],
            cipher_suites: vec![TLS_AES_128_GCM_SHA256],
            compression_methods: vec![0],
            extensions: vec![Extension::supported_versions_client(&[TLS13])],
        };
        let hs = ch.to_handshake();
        assert_eq!(hs.msg_type, HandshakeType::ClientHello);
        let back = ClientHello::from_handshake(&hs).unwrap();
        assert_eq!(back, ch);
    }

    #[test]
    /// As an out-of-order message.
    fn wrong_handshake_type_rejected() {
        let hs = HandshakeMsg::new(HandshakeType::Finished, vec![0; 10]);
        assert_eq!(
            ClientHello::from_handshake(&hs),
            Err(TlsError::UnexpectedMessage)
        );
        assert_eq!(
            ServerHello::from_handshake(&hs),
            Err(TlsError::UnexpectedMessage)
        );
    }

    #[test]
    /// Accepting them would let implementation differences steer negotiation.
    fn noncanonical_extensions_and_hello_fields_are_rejected() {
        let extension = Extension::supported_versions_server(TLS13);
        let mut encoded = Writer::new();
        extension.encode_into(&mut encoded);
        extension.encode_into(&mut encoded);
        assert!(Extension::parse_list(&encoded.buf).is_err());
        let mut vector = Writer::new();
        vector.vec16(|writer| extension.encode_into(writer));
        assert_eq!(
            Extension::parse_vector(&vector.buf).unwrap(),
            vec![extension]
        );
        vector.buf.push(0);
        assert!(Extension::parse_vector(&vector.buf).is_err());

        let with_trailing = Extension::new(EXT_SUPPORTED_VERSIONS, vec![0x03, 0x04, 0]);
        assert_eq!(with_trailing.as_supported_versions_server(), None);
        let empty_alpn = Extension::new(EXT_ALPN, vec![0, 1, 0]);
        assert_eq!(empty_alpn.as_alpn(), None);

        let mut sh = ServerHello {
            legacy_version: TLS12,
            random: [0; 32],
            session_id_echo: Vec::new(),
            cipher_suite: TLS_AES_128_GCM_SHA256,
            extensions: vec![
                Extension::supported_versions_server(TLS13),
                Extension::key_share_server(X25519, &[1; 32]),
            ],
        };
        let hello = hello_with(vec![Extension::alpn(&[b"h2"])]);
        assert_eq!(sh.validate_tls13(&hello, false), Ok(()));
        sh.extensions.push(Extension::alpn(&[b"h2"]));
        assert_eq!(
            sh.validate_tls13(&hello, false),
            Err(TlsError::IllegalParameter)
        );

        let mut body = sh.encode();
        let compression_offset = 2 + 32 + 1 + sh.session_id_echo.len() + 2;
        body[compression_offset] = 1;
        assert_eq!(ServerHello::parse(&body), Err(TlsError::IllegalParameter));
    }

    #[test]
    /// Each reason matches the alert RFC 8446 sets.
    fn tls13_server_hello_rejections_name_their_alert() {
        let hello = hello_with(vec![
            Extension::supported_versions_client(&[TLS13]),
            Extension::alpn(&[b"dot"]),
        ]);
        let base = ServerHello {
            legacy_version: TLS12,
            random: [0; 32],
            session_id_echo: Vec::new(),
            cipher_suite: TLS_AES_128_GCM_SHA256,
            extensions: vec![
                Extension::supported_versions_server(TLS13),
                Extension::key_share_server(X25519, &[1; 32]),
            ],
        };
        assert_eq!(base.validate_tls13(&hello, false), Ok(()));
        assert_eq!(base.validate_tls13(&hello, true), Ok(()));

        let with = |change: &dyn Fn(&mut ServerHello)| {
            let mut sh = base.clone();
            change(&mut sh);
            sh
        };
        let replace_versions = |data: Vec<u8>| {
            move |sh: &mut ServerHello| {
                sh.extensions[0] = Extension::new(EXT_SUPPORTED_VERSIONS, data.clone())
            }
        };
        assert_eq!(
            with(&|sh| sh.legacy_version = 0x0301).validate_tls13(&hello, false),
            Ok(()),
            "지원 버전 확장이 있으면 legacy_version 은 보지 않는다"
        );
        let cases: [(&str, ServerHello, bool, TlsError); 9] = [
            (
                "legacy_version 이 SSL 3.0 이하",
                with(&|sh| sh.legacy_version = 0x0300),
                false,
                TlsError::ProtocolVersion,
            ),
            (
                "세션 번호를 되비추지 않음",
                with(&|sh| sh.session_id_echo = vec![1; 32]),
                false,
                TlsError::IllegalParameter,
            ),
            (
                "지원 버전 확장 없음",
                with(&|sh| {
                    sh.extensions.remove(0);
                }),
                false,
                TlsError::MissingExtension,
            ),
            (
                "지원 버전 확장 형식이 깨짐",
                with(&replace_versions(vec![0x03])),
                false,
                TlsError::Decode,
            ),
            (
                "1.3 이 아닌 버전을 고름",
                with(&replace_versions(vec![0x03, 0x03])),
                false,
                TlsError::IllegalParameter,
            ),
            (
                "제안한 확장을 올 수 없는 자리에 보냄",
                with(&|sh| sh.extensions.push(Extension::alpn(&[b"dot"]))),
                false,
                TlsError::IllegalParameter,
            ),
            (
                "제안하지 않은 확장을 보냄",
                with(&|sh| sh.extensions.push(Extension::new(0x1234, Vec::new()))),
                false,
                TlsError::UnsupportedExtension,
            ),
            (
                "서버 인사말에 쿠키",
                with(&|sh| sh.extensions.push(Extension::cookie(b"cookie"))),
                false,
                TlsError::UnsupportedExtension,
            ),
            (
                "다시 시도 요청에 재개 응답",
                with(&|sh| sh.extensions.push(Extension::pre_shared_key_server(0))),
                true,
                TlsError::UnsupportedExtension,
            ),
        ];
        for (case, sh, hrr, expected) in cases {
            assert_eq!(sh.validate_tls13(&hello, hrr), Err(expected), "{case}");
        }

        let cookie = with(&|sh| sh.extensions.push(Extension::cookie(b"cookie")));
        assert_eq!(
            cookie.validate_tls13(&hello, true),
            Ok(()),
            "다시 시도 요청의 쿠키는 제안하지 않았어도 받아야 한다"
        );
    }

    #[test]
    /// The chosen group must be among the supported groups with no key share sent in the first
    /// hello, and the request must change something in the hello.
    fn hello_retry_request_may_select_another_offered_group_or_carry_only_a_cookie() {
        let hello = hello_with(vec![
            Extension::supported_versions_client(&[TLS13]),
            Extension::supported_groups(&[X25519, SECP256R1]),
            Extension::key_share_client(&[(X25519, vec![1; 32])]),
        ]);
        let retry = |extensions: Vec<Extension>| ServerHello {
            legacy_version: TLS12,
            random: HRR_RANDOM,
            session_id_echo: Vec::new(),
            cipher_suite: TLS_AES_128_GCM_SHA256,
            extensions: [
                vec![Extension::supported_versions_server(TLS13)],
                extensions,
            ]
            .concat(),
        };
        assert_eq!(
            retry(vec![Extension::key_share_hrr(SECP256R1)]).validate_retry_request(&hello),
            Ok(Some(SECP256R1))
        );
        assert_eq!(
            retry(vec![Extension::cookie(b"cookie")]).validate_retry_request(&hello),
            Ok(None),
            "쿠키만 담은 요청에는 첫 키 조각을 그대로 보낸다"
        );
        for (case, extensions) in [
            (
                "이미 키 조각을 보낸 곡선",
                vec![Extension::key_share_hrr(X25519)],
            ),
            (
                "제안하지 않은 곡선",
                vec![Extension::key_share_hrr(SECP384R1)],
            ),
            ("바꿀 것이 없는 요청", Vec::new()),
        ] {
            assert_eq!(
                retry(extensions).validate_retry_request(&hello),
                Err(TlsError::IllegalParameter),
                "{case}"
            );
        }

        let answer = ServerHello {
            random: [0; 32],
            ..retry(vec![Extension::key_share_server(SECP256R1, &[4; 65])])
        };
        assert_eq!(answer.key_share(Some(SECP256R1)), Ok(vec![4; 65]));
        assert_eq!(
            answer.key_share(Some(X25519)),
            Err(TlsError::IllegalParameter),
            "키 조각을 보내지 않은 곡선으로 답하면 안 된다"
        );
        assert_eq!(answer.key_share(None), Err(TlsError::IllegalParameter));
    }

    #[test]
    fn selected_alpn_names_the_reason_for_rejection() {
        let offered = vec![b"dot".to_vec(), b"h2".to_vec()];
        assert_eq!(
            Extension::alpn(&[b"h2"]).selected_alpn(&offered),
            Ok(b"h2".to_vec())
        );
        for (case, extension, ours, expected) in [
            (
                "제안하지 않은 확장",
                Extension::alpn(&[b"h2"]),
                Vec::new(),
                TlsError::UnsupportedExtension,
            ),
            (
                "형식이 깨진 목록",
                Extension::new(EXT_ALPN, vec![0, 1, 0]),
                offered.clone(),
                TlsError::Decode,
            ),
            (
                "프로토콜 둘",
                Extension::alpn(&[b"dot", b"h2"]),
                offered.clone(),
                TlsError::IllegalParameter,
            ),
            (
                "제안하지 않은 프로토콜",
                Extension::alpn(&[b"h3"]),
                offered.clone(),
                TlsError::IllegalParameter,
            ),
        ] {
            assert_eq!(extension.selected_alpn(&ours), Err(expected), "{case}");
        }
    }

    #[test]
    /// The binder's coverage would be wrong.
    fn tls13_psk_extension_must_be_last() {
        let mut ch = ClientHello {
            legacy_version: TLS12,
            random: [0; 32],
            session_id: Vec::new(),
            cipher_suites: vec![TLS_AES_128_GCM_SHA256],
            compression_methods: vec![0],
            extensions: vec![
                Extension::supported_versions_client(&[TLS13]),
                Extension::psk_key_exchange_modes(&[PSK_DHE_KE]),
                Extension::pre_shared_key_client(b"ticket", 0, 32),
                Extension::server_name("dns.example"),
            ],
        };
        assert_eq!(ch.validate_tls13(), Err(TlsError::IllegalParameter));
        ch.extensions.swap(2, 3);
        assert_eq!(ch.validate_tls13(), Ok(()));
    }

    #[test]
    fn tls13_psk_identity_and_binder_minimums_are_enforced() {
        assert!(Extension::pre_shared_key_client(b"", 0, 32)
            .as_pre_shared_key_client()
            .is_none());
        assert!(Extension::pre_shared_key_client(b"ticket", 0, 31)
            .as_pre_shared_key_client()
            .is_none());
        assert!(Extension::pre_shared_key_client(b"ticket", 0, 32)
            .as_pre_shared_key_client()
            .is_some());
    }

    #[test]
    fn tls13_retry_client_hello_preserves_the_first_context() {
        let first = ClientHello {
            legacy_version: TLS12,
            random: [7; 32],
            session_id: vec![9; 32],
            cipher_suites: vec![TLS_AES_128_GCM_SHA256],
            compression_methods: vec![0],
            extensions: vec![
                Extension::supported_versions_client(&[TLS13]),
                Extension::supported_groups(&[X25519]),
                Extension::signature_algorithms(&[ECDSA_SECP256R1_SHA256]),
                Extension::key_share_client(&[]),
                Extension::server_name("dns.example"),
                Extension::psk_key_exchange_modes(&[PSK_DHE_KE]),
                Extension::early_data(),
                Extension::pre_shared_key_client(b"ticket", 1, 32),
            ],
        };
        let mut retry = first.clone();
        *retry
            .extensions
            .iter_mut()
            .find(|extension| extension.ext_type == EXT_KEY_SHARE)
            .unwrap() = Extension::key_share_client(&[(X25519, vec![3; 32])]);
        retry
            .extensions
            .retain(|extension| extension.ext_type != EXT_EARLY_DATA);
        let psk_at = retry.extensions.len() - 1;
        retry
            .extensions
            .insert(psk_at, Extension::cookie(b"retry-cookie"));
        *retry.extensions.last_mut().unwrap() = Extension::pre_shared_key_client(b"ticket", 2, 32);
        assert_eq!(retry.validate_tls13(), Ok(()));
        assert!(retry.is_valid_retry_of(&first));

        let mut changed_name = retry.clone();
        *changed_name
            .extensions
            .iter_mut()
            .find(|extension| extension.ext_type == EXT_SERVER_NAME)
            .unwrap() = Extension::server_name("other.example");
        assert!(!changed_name.is_valid_retry_of(&first));

        let mut new_psk = retry.clone();
        *new_psk.extensions.last_mut().unwrap() =
            Extension::pre_shared_key_client(b"other-ticket", 2, 32);
        assert!(!new_psk.is_valid_retry_of(&first));

        let mut retained_early_data = retry;
        let psk_at = retained_early_data.extensions.len() - 1;
        retained_early_data
            .extensions
            .insert(psk_at, Extension::early_data());
        assert!(!retained_early_data.is_valid_retry_of(&first));
    }

    fn hello_with(extensions: Vec<Extension>) -> ClientHello {
        ClientHello {
            legacy_version: TLS12,
            random: [0; 32],
            session_id: Vec::new(),
            cipher_suites: vec![TLS_AES_128_GCM_SHA256],
            compression_methods: vec![0],
            extensions,
        }
    }

    #[test]
    /// Extensions this stack does not interpret are not looked into.
    fn client_hello_rejects_malformed_extensions_it_interprets() {
        let interpreted = [
            Extension::server_name("dns.example"),
            Extension::supported_groups(&[X25519]),
            Extension::signature_algorithms(&[ECDSA_SECP256R1_SHA256]),
            Extension::alpn(&[b"dot"]),
            Extension::new(EXT_EXTENDED_MASTER_SECRET, Vec::new()),
            Extension::early_data(),
            Extension::supported_versions_client(&[TLS13]),
            Extension::cookie(b"cookie"),
            Extension::psk_key_exchange_modes(&[PSK_DHE_KE]),
            Extension::key_share_client(&[(X25519, vec![1; 32])]),
            Extension::new(EXT_RENEGOTIATION_INFO, vec![0]),
            Extension::new(EXT_EC_POINT_FORMATS, vec![1, 0]),
            Extension::pre_shared_key_client(b"ticket", 0, 32),
        ];
        for extension in interpreted {
            let ext_type = extension.ext_type;
            assert_eq!(
                extension.client_hello_syntax_ok(),
                Some(true),
                "확장 {ext_type}: 정상 형식이어야 한다"
            );
            assert!(
                ClientHello::parse(&hello_with(vec![extension.clone()]).encode()).is_ok(),
                "확장 {ext_type}: 정상 형식이 실린 인사말은 읽어야 한다"
            );
            let mut trailing = extension;
            trailing.data.push(0);
            assert_eq!(
                trailing.client_hello_syntax_ok(),
                Some(false),
                "확장 {ext_type}: 뒤에 바이트가 남으면 형식이 깨진 것이다"
            );
            assert_eq!(
                ClientHello::parse(&hello_with(vec![trailing]).encode()),
                Err(TlsError::Decode),
                "확장 {ext_type}: 형식이 깨진 확장이 실린 인사말은 거부해야 한다"
            );
        }

        let wrong_length = [
            Extension::new(EXT_SUPPORTED_GROUPS, vec![0, 0]),
            Extension::new(EXT_SUPPORTED_GROUPS, vec![0, 1, 0x1d]),
            Extension::new(EXT_SIGNATURE_ALGORITHMS, vec![0, 0]),
            Extension::new(EXT_ALPN, vec![0, 1, 0]),
            Extension::new(EXT_SUPPORTED_VERSIONS, vec![0]),
            Extension::new(EXT_COOKIE, vec![0, 0]),
            Extension::new(EXT_PSK_KEY_EXCHANGE_MODES, vec![0]),
            Extension::key_share_client(&[(X25519, Vec::new())]),
            Extension::pre_shared_key_client(b"ticket", 0, 31),
            Extension::new(EXT_EC_POINT_FORMATS, vec![0]),
        ];
        for extension in wrong_length {
            assert_eq!(
                ClientHello::parse(&hello_with(vec![extension.clone()]).encode()),
                Err(TlsError::Decode),
                "{extension:?}: 규격이 정한 길이를 어기면 거부해야 한다"
            );
        }

        let ignored = hello_with(vec![
            Extension::new(0x0a0a, vec![0xff; 3]),
            Extension::new(0xfe0d, vec![0x00]),
            Extension::new(0x0039, vec![0xff, 0xff]),
        ]);
        assert!(ignored
            .extensions
            .iter()
            .all(|extension| extension.client_hello_syntax_ok().is_none()));
        assert_eq!(
            ClientHello::parse(&ignored.encode()),
            Ok(ignored),
            "해석하지 않는 확장은 내용이 무엇이든 받아들여야 한다"
        );
    }

    #[test]
    /// Well-formed but with no usable name is accepted.
    fn server_name_list_must_be_well_formed() {
        let list = |entries: &[(u8, &[u8])]| {
            let mut w = Writer::new();
            w.vec16(|w| {
                for (name_type, name) in entries {
                    w.u8(*name_type);
                    w.vec16(|w| w.bytes(name));
                }
            });
            Extension::new(EXT_SERVER_NAME, w.buf)
        };
        for (case, extension) in [
            ("빈 목록", list(&[])),
            ("빈 호스트 이름", list(&[(0, b"")])),
            (
                "호스트 이름 두 개",
                list(&[(0, b"a.example"), (0, b"b.example")]),
            ),
            (
                "길이가 잘린 항목",
                Extension::new(EXT_SERVER_NAME, vec![0, 3, 0, 0, 5]),
            ),
        ] {
            assert_eq!(extension.client_hello_syntax_ok(), Some(false), "{case}");
            assert_eq!(extension.as_server_name(), None, "{case}");
        }

        let mixed = list(&[(1, b"opaque"), (0, b"dns.example")]);
        assert_eq!(mixed.as_server_name().as_deref(), Some("dns.example"));
        for (case, extension) in [
            ("다른 종류만 있는 목록", list(&[(1, b"opaque")])),
            ("UTF-8 이 아닌 이름", list(&[(0, &[0xff, 0xfe])])),
        ] {
            assert_eq!(extension.client_hello_syntax_ok(), Some(true), "{case}");
            assert_eq!(extension.as_server_name(), None, "{case}");
        }
    }

    #[test]
    /// Without a PSK offer, signature_algorithms and supported_groups; with one,
    /// psk_key_exchange_modes; supported_groups and key_share go together.
    fn tls13_hello_requires_the_extensions_rfc_8446_mandates() {
        let versions = || Extension::supported_versions_client(&[TLS13]);
        let groups = || Extension::supported_groups(&[X25519]);
        let schemes = || Extension::signature_algorithms(&[ECDSA_SECP256R1_SHA256]);
        let shares = || Extension::key_share_client(&[(X25519, vec![1; 32])]);
        let modes = || Extension::psk_key_exchange_modes(&[PSK_DHE_KE]);
        let psk = || Extension::pre_shared_key_client(b"ticket", 0, 32);

        for (case, extensions, valid) in [
            (
                "완전한 인사말",
                vec![versions(), groups(), schemes(), shares()],
                true,
            ),
            (
                "빈 키 공유",
                vec![
                    versions(),
                    groups(),
                    schemes(),
                    Extension::key_share_client(&[]),
                ],
                true,
            ),
            ("키 공유 없음", vec![versions(), groups(), schemes()], false),
            (
                "지원 곡선 없음",
                vec![versions(), schemes(), shares()],
                false,
            ),
            (
                "서명 방식 없음",
                vec![versions(), groups(), shares()],
                false,
            ),
            ("재개만 제안", vec![versions(), modes(), psk()], true),
            (
                "재개 제안의 서명 방식 생략",
                vec![versions(), groups(), shares(), modes(), psk()],
                true,
            ),
            (
                "재개 방식 없는 재개 제안",
                vec![versions(), groups(), schemes(), shares(), psk()],
                false,
            ),
            (
                "재개 제안의 키 공유 없음",
                vec![versions(), groups(), modes(), psk()],
                false,
            ),
        ] {
            let expected = if valid {
                Ok(())
            } else {
                Err(TlsError::MissingExtension)
            };
            assert_eq!(hello_with(extensions).validate_tls13(), expected, "{case}");
        }

        let complete = || hello_with(vec![versions(), groups(), schemes(), shares()]);
        let mut tls10_legacy = complete();
        tls10_legacy.legacy_version = 0x0301;
        assert_eq!(
            tls10_legacy.validate_tls13(),
            Ok(()),
            "지원 버전 확장이 있으면 legacy_version 은 보지 않는다"
        );
        let mut ssl3_legacy = complete();
        ssl3_legacy.legacy_version = 0x0300;
        let without_versions = hello_with(vec![groups(), schemes(), shares()]);
        let mut compressed = complete();
        compressed.compression_methods = vec![1, 0];
        for (case, hello, expected) in [
            (
                "legacy_version 이 SSL 3.0 이하",
                ssl3_legacy,
                TlsError::ProtocolVersion,
            ),
            (
                "지원 버전에 1.3 이 없음",
                without_versions,
                TlsError::ProtocolVersion,
            ),
            (
                "압축 방식이 null 하나가 아님",
                compressed,
                TlsError::IllegalParameter,
            ),
        ] {
            assert_eq!(hello.validate_tls13(), Err(expected), "{case}");
        }
    }

    #[test]
    fn tls_parsers_no_panic_on_adversarial_input() {
        use crate::cert::{CertificateMsg, CertificateRequestMsg, CertificateVerify};
        use crate::handshake::HandshakeMsg;
        use crate::record::TlsRecord;
        use crate::x509::X509;

        let feed = |b: &[u8]| {
            let _ = TlsRecord::parse(b);
            let _ = HandshakeMsg::parse(b);
            let _ = ClientHello::parse(b);
            let _ = ServerHello::parse(b);
            let _ = Extension::parse_list(b);
            let _ = NewSessionTicket::parse(b);
            let _ = CertificateMsg::parse(b);
            let _ = CertificateRequestMsg::parse(b);
            let _ = CertificateVerify::parse(b);
            let _ = X509::parse(b);
        };

        let mut seed: u32 = 0x9e37_79b9;
        let mut rng = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        for _ in 0..20000 {
            let len = (rng() % 96) as usize;
            let v: Vec<u8> = (0..len).map(|_| (rng() & 0xff) as u8).collect();
            feed(&v);
        }

        let ch = ClientHello {
            legacy_version: TLS12,
            random: [0x11; 32],
            session_id: vec![0xAB; 32],
            cipher_suites: vec![TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256],
            compression_methods: vec![0],
            extensions: vec![
                Extension::supported_versions_client(&[TLS13]),
                Extension::server_name("dns.example.com"),
                Extension::key_share_client(&[(X25519, vec![0x42; 32])]),
                Extension::alpn(&[b"dot", b"h2"]),
            ],
        };
        let sh = ServerHello {
            legacy_version: TLS12,
            random: [0x55; 32],
            session_id_echo: vec![0xAB; 32],
            cipher_suite: TLS_AES_128_GCM_SHA256,
            extensions: vec![
                Extension::supported_versions_server(TLS13),
                Extension::key_share_server(X25519, &[0x99; 32]),
            ],
        };
        let hs = HandshakeMsg::new(HandshakeType::ClientHello, ch.encode());

        let frag = hs.encode();
        let mut rec = vec![22u8, 0x03, 0x03];
        rec.extend_from_slice(&(frag.len() as u16).to_be_bytes());
        rec.extend_from_slice(&frag);

        let valids: Vec<Vec<u8>> = vec![ch.encode(), sh.encode(), hs.encode(), rec];
        for v in &valids {
            for cut in 0..=v.len() {
                feed(&v[..cut]);
                if cut < v.len() {
                    let mut m = v.clone();
                    m[cut] ^= 0xff;
                    feed(&m);
                }
            }
        }
    }
}
