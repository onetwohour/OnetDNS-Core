//! X.509 certificate parsing, limited to the fields this side uses: the public key, validity,
//! names, and the extensions decisions depend on.
//!
//! This parser is where identity decisions start. A duplicated or malformed extension is rejected;
//! accepting it lets implementations read it differently, and that difference is a bypass.

use crate::cert::verify_signature;
use crate::der::{self, bit_string_bytes, Der};
use crate::msg::consts;
use crate::TlsError;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
/// id-ml-dsa-44 (RFC 9881): the key and the signature algorithm share it.
pub(crate) const OID_ML_DSA_44: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11];
/// A key exchange key; it cannot sign.
const OID_X25519: &[u8] = &[0x2b, 0x65, 0x6e];
const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// The curve comes separately as a parameter.
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_EC_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_EC_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_MGF1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const OID_SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_SHA384_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const OID_SHA512_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
/// Hash and salt come as parameters.
const OID_RSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const OID_HASH_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_HASH_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_HASH_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
/// Host name matching uses only the values here.
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
/// Whether it is a CA, and the path length.
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
/// Tells server authentication from client authentication.
const OID_EKU: &[u8] = &[0x55, 0x1d, 0x25];
/// Bounds the names a CA may issue.
const OID_NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];

/// Holds the OCSP address.
const OID_AIA: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
const OID_CRL_DP: &[u8] = &[0x55, 0x1d, 0x1f];
const OID_AD_OCSP: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];

const EKU_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const EKU_CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
const EKU_OCSP_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];
const EKU_ANY: &[u8] = &[0x55, 0x1d, 0x25, 0x00];

const KU_DIGITAL_SIGNATURE: u16 = 1 << 0;
/// Required of a CA.
const KU_KEY_CERT_SIGN: u16 = 1 << 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyAlgorithm {
    Ed25519,
    MlDsa44,
    X25519,
    EcP256,
    EcP384,
    RsaEncryption,
    RsaPss { scheme: u16 },
}

impl PublicKeyAlgorithm {
    /// Without this check, an RSA key could verify an ECDSA signature and similar confusions.
    pub fn allows_signature_scheme(self, scheme: u16) -> bool {
        match self {
            PublicKeyAlgorithm::Ed25519 => scheme == consts::ED25519,
            PublicKeyAlgorithm::MlDsa44 => scheme == consts::MLDSA44,
            PublicKeyAlgorithm::X25519 => false,
            PublicKeyAlgorithm::EcP256 => scheme == consts::ECDSA_SECP256R1_SHA256,
            PublicKeyAlgorithm::EcP384 => scheme == consts::ECDSA_SECP384R1_SHA384,
            PublicKeyAlgorithm::RsaEncryption => matches!(
                scheme,
                consts::RSA_PSS_RSAE_SHA256
                    | consts::RSA_PSS_RSAE_SHA384
                    | consts::RSA_PSS_RSAE_SHA512
                    | consts::RSA_PKCS1_SHA256
                    | consts::RSA_PKCS1_SHA384
                    | consts::RSA_PKCS1_SHA512
            ),
            PublicKeyAlgorithm::RsaPss { scheme: required } => scheme == required,
        }
    }
}

#[derive(Debug, Clone)]
pub struct X509 {
    /// Verification uses these bytes as is.
    pub tbs_raw: Vec<u8>,

    /// 0 means a scheme this side cannot verify. With 0, `verify_signature` passes nothing with any
    /// key, because `allows_signature_scheme` rejects 0 for every key type.
    pub sig_scheme: u16,

    pub signature: Vec<u8>,

    pub public_key: Vec<u8>,
    pub public_key_algorithm: PublicKeyAlgorithm,
    /// For pinning and comparison.
    pub cert_sha256: [u8; 32],
    pub not_before: i64,
    pub not_after: i64,
    pub san_dns: Vec<String>,

    pub san_ip: Vec<IpAddr>,

    /// Used to link the chain.
    pub issuer_raw: Vec<u8>,

    pub subject_raw: Vec<u8>,

    pub is_ca: bool,

    pub path_len: Option<u32>,

    pub key_usage: Option<u16>,

    pub eku_server_auth: Option<bool>,

    pub eku_client_auth: Option<bool>,

    pub name_constraints: Option<NameConstraints>,

    /// Matched against CRLs.
    pub serial: Vec<u8>,

    pub ocsp_urls: Vec<String>,

    pub crl_urls: Vec<String>,

    pub eku_ocsp_signing: bool,
}

impl X509 {
    pub(crate) fn retained_payload_bytes(&self) -> usize {
        self.tbs_raw
            .capacity()
            .saturating_add(self.signature.capacity())
            .saturating_add(self.public_key.capacity())
            .saturating_add(self.issuer_raw.capacity())
            .saturating_add(self.subject_raw.capacity())
            .saturating_add(
                self.san_dns
                    .capacity()
                    .saturating_mul(std::mem::size_of::<String>()),
            )
            .saturating_add(
                self.san_dns
                    .iter()
                    .fold(0usize, |total, name| total.saturating_add(name.capacity())),
            )
            .saturating_add(
                self.san_ip
                    .capacity()
                    .saturating_mul(std::mem::size_of::<IpAddr>()),
            )
            .saturating_add(
                self.name_constraints
                    .as_ref()
                    .map_or(0, NameConstraints::retained_payload_bytes),
            )
            .saturating_add(self.serial.capacity())
            .saturating_add(
                self.ocsp_urls
                    .capacity()
                    .saturating_mul(std::mem::size_of::<String>()),
            )
            .saturating_add(
                self.ocsp_urls
                    .iter()
                    .fold(0usize, |total, url| total.saturating_add(url.capacity())),
            )
            .saturating_add(
                self.crl_urls
                    .capacity()
                    .saturating_mul(std::mem::size_of::<String>()),
            )
            .saturating_add(
                self.crl_urls
                    .iter()
                    .fold(0usize, |total, url| total.saturating_add(url.capacity())),
            )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpConstraint {
    pub address: IpAddr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, Default)]
pub struct NameConstraints {
    pub permitted_dns: Vec<String>,
    pub excluded_dns: Vec<String>,
    pub permitted_ip: Vec<IpConstraint>,
    pub excluded_ip: Vec<IpConstraint>,
}

impl NameConstraints {
    fn retained_payload_bytes(&self) -> usize {
        self.permitted_dns
            .capacity()
            .saturating_mul(std::mem::size_of::<String>())
            .saturating_add(
                self.permitted_dns
                    .iter()
                    .fold(0usize, |total, name| total.saturating_add(name.capacity())),
            )
            .saturating_add(
                self.excluded_dns
                    .capacity()
                    .saturating_mul(std::mem::size_of::<String>()),
            )
            .saturating_add(
                self.excluded_dns
                    .iter()
                    .fold(0usize, |total, name| total.saturating_add(name.capacity())),
            )
            .saturating_add(
                self.permitted_ip
                    .capacity()
                    .saturating_mul(std::mem::size_of::<IpConstraint>()),
            )
            .saturating_add(
                self.excluded_ip
                    .capacity()
                    .saturating_mul(std::mem::size_of::<IpConstraint>()),
            )
    }
}

impl X509 {
    /// Rejects an extension that appears twice: which one applies is undefined, and implementations
    /// choosing differently opens a way around constraints.
    pub fn parse(der: &[u8]) -> Result<X509, TlsError> {
        let mut top = Der::new(der);
        let cert = top.expect(der::SEQUENCE)?;

        if !top.is_empty() {
            return Err(TlsError::BadCert);
        }
        let mut c = Der::new(cert);

        let (tbs_raw, tbs) = c.next_raw()?;
        if tbs.tag != der::SEQUENCE {
            return Err(TlsError::BadCert);
        }
        let sig_algid = c.expect(der::SEQUENCE)?;
        // The certificate is read even with a signature scheme that cannot be verified. A trusted
        // root is where verification starts, not something verified, so dropping older roots
        // self-signed with SHA-1 here would distrust every chain leading to them. With 0 here the
        // signature verifies nothing, so the certificate cannot be used anywhere inside a chain.
        let sig_scheme = scheme_from_sig_algid(sig_algid)?;
        let signature = bit_string_bytes(c.expect(der::BIT_STRING)?)?.to_vec();

        if !c.is_empty() {
            return Err(TlsError::BadCert);
        }

        let mut t = Der::new(tbs.value);
        let f = t.next()?;

        let serial = if f.tag == der::context(0) {
            t.expect(der::INTEGER)?.to_vec()
        } else if f.tag == der::INTEGER {
            f.value.to_vec()
        } else {
            return Err(TlsError::BadCert);
        };

        let tbs_sig_algid = t.expect(der::SEQUENCE)?;
        if tbs_sig_algid != sig_algid {
            return Err(TlsError::BadCert);
        }
        let (issuer_raw, issuer_tlv) = t.next_raw()?;
        if issuer_tlv.tag != der::SEQUENCE {
            return Err(TlsError::BadCert);
        }
        let validity = t.expect(der::SEQUENCE)?;
        let (subject_raw, subject_tlv) = t.next_raw()?;
        if subject_tlv.tag != der::SEQUENCE {
            return Err(TlsError::BadCert);
        }
        let spki = t.expect(der::SEQUENCE)?;

        let mut extensions: Option<&[u8]> = None;
        while !t.is_empty() {
            let tlv = t.next()?;
            if tlv.tag == der::context(3) {
                extensions = Some(tlv.value);
            }
        }

        let mut v = Der::new(validity);
        let not_before = parse_time(v.next()?)?;
        let not_after = parse_time(v.next()?)?;

        if !v.is_empty() {
            return Err(TlsError::BadCert);
        }

        let mut s = Der::new(spki);
        let algid = s.expect(der::SEQUENCE)?;
        let public_key_algorithm = public_key_algorithm_from_algid(algid)?;
        let key = bit_string_bytes(s.expect(der::BIT_STRING)?)?.to_vec();

        if !s.is_empty() || key.is_empty() || !public_key_encoding_valid(public_key_algorithm, &key)
        {
            return Err(TlsError::BadCert);
        }

        let ext = match extensions {
            Some(e) => parse_extensions(e)?,
            None => ParsedExt::default(),
        };

        Ok(X509 {
            tbs_raw: tbs_raw.to_vec(),
            sig_scheme,
            signature,
            public_key: key,
            public_key_algorithm,
            cert_sha256: Sha256::digest(der).into(),
            not_before,
            not_after,
            san_dns: ext.san_dns,
            san_ip: ext.san_ip,
            issuer_raw: issuer_raw.to_vec(),
            subject_raw: subject_raw.to_vec(),
            is_ca: ext.is_ca,
            path_len: ext.path_len,
            key_usage: ext.key_usage,
            eku_server_auth: ext.eku_server_auth,
            eku_client_auth: ext.eku_client_auth,
            name_constraints: ext.name_constraints,
            serial,
            ocsp_urls: ext.ocsp_urls,
            crl_urls: ext.crl_urls,
            eku_ocsp_signing: ext.eku_ocsp_signing,
        })
    }

    pub fn allows_ocsp_signing(&self) -> bool {
        self.eku_ocsp_signing
    }

    pub fn allows_digital_signature(&self) -> bool {
        self.key_usage.is_none_or(|m| m & KU_DIGITAL_SIGNATURE != 0)
    }

    pub fn verify_signature(
        &self,
        scheme: u16,
        content: &[u8],
        signature: &[u8],
    ) -> Result<(), TlsError> {
        if !self.public_key_algorithm.allows_signature_scheme(scheme) {
            return Err(TlsError::BadCert);
        }
        verify_signature(scheme, &self.public_key, content, signature)
    }

    /// UnsupportedCertificate for an RSASSA-PSS public key, whose signature scheme is not handled.
    /// IllegalParameter when the peer's chosen scheme does not fit the key type: the peer's choice
    /// is wrong, not the certificate, so it is not bad_certificate.
    pub fn verify_tls_signature(
        &self,
        scheme: u16,
        content: &[u8],
        signature: &[u8],
    ) -> Result<(), TlsError> {
        if matches!(self.public_key_algorithm, PublicKeyAlgorithm::RsaPss { .. }) {
            return Err(TlsError::UnsupportedCertificate);
        }
        if !self.public_key_algorithm.allows_signature_scheme(scheme) {
            return Err(TlsError::IllegalParameter);
        }
        verify_signature(scheme, &self.public_key, content, signature)
    }

    pub fn allows_cert_sign(&self) -> bool {
        self.key_usage.is_none_or(|m| m & KU_KEY_CERT_SIGN != 0)
    }

    pub fn allows_tls_leaf_usage(&self) -> bool {
        self.key_usage.is_none_or(|m| m & KU_DIGITAL_SIGNATURE != 0)
    }

    pub fn allows_server_auth(&self) -> bool {
        self.eku_server_auth.unwrap_or(true)
    }

    pub fn allows_client_auth(&self) -> bool {
        self.eku_client_auth.unwrap_or(true)
    }

    pub fn verify_signed_by(&self, issuer: &X509) -> Result<(), TlsError> {
        issuer.verify_signature(self.sig_scheme, &self.tbs_raw, &self.signature)
    }

    pub fn verify_self_signed(&self) -> Result<(), TlsError> {
        self.verify_signature(self.sig_scheme, &self.tbs_raw, &self.signature)
    }

    pub fn valid_at(&self, now: i64) -> bool {
        self.not_before <= now && now <= self.not_after
    }

    /// Only subject alternative names count; the legacy subject common name is ignored, since
    /// trusting it would open a path that name constraints do not cover.
    pub fn matches_hostname(&self, host: &str) -> bool {
        let name = match peer_host(host) {
            PeerHost::Ip(ip) => return self.san_ip.contains(&ip),
            PeerHost::Name(name) => name,
        };
        let host = name.to_ascii_lowercase();
        self.san_dns.iter().any(|n| {
            let n = n.trim_end_matches('.').to_ascii_lowercase();
            if let Some(suffix) = n.strip_prefix("*.") {
                matches!(host.split_once('.'), Some((_, rest)) if rest == suffix)
            } else {
                n == host
            }
        })
    }

    /// For diagnostics.
    pub fn issuer_label(&self) -> Option<String> {
        distinguished_name_label(&self.issuer_raw)
    }

    pub fn subject_label(&self) -> Option<String> {
        distinguished_name_label(&self.subject_raw)
    }
}

fn public_key_algorithm_from_algid(algid: &[u8]) -> Result<PublicKeyAlgorithm, TlsError> {
    let mut d = Der::new(algid);
    let oid = d.expect(der::OID)?;
    let algorithm = match oid {
        x if x == OID_ED25519 => {
            if !d.is_empty() {
                return Err(TlsError::BadCert);
            }
            PublicKeyAlgorithm::Ed25519
        }
        x if x == OID_ML_DSA_44 => {
            if !d.is_empty() {
                return Err(TlsError::BadCert);
            }
            PublicKeyAlgorithm::MlDsa44
        }
        x if x == OID_X25519 => {
            if !d.is_empty() {
                return Err(TlsError::BadCert);
            }
            PublicKeyAlgorithm::X25519
        }
        x if x == OID_EC_PUBLIC_KEY => {
            let curve = d.expect(der::OID)?;
            if !d.is_empty() {
                return Err(TlsError::BadCert);
            }
            if curve == OID_EC_P256 {
                PublicKeyAlgorithm::EcP256
            } else if curve == OID_EC_P384 {
                PublicKeyAlgorithm::EcP384
            } else {
                return Err(TlsError::BadCert);
            }
        }
        x if x == OID_RSA_ENCRYPTION => {
            if !d.is_empty() {
                let null = d.next()?;
                if null.tag != 0x05 || !null.value.is_empty() || !d.is_empty() {
                    return Err(TlsError::BadCert);
                }
            }
            PublicKeyAlgorithm::RsaEncryption
        }
        x if x == OID_RSA_PSS => {
            let scheme = pss_scheme_from_params(&mut d)?;
            if scheme == 0 || !d.is_empty() {
                return Err(TlsError::BadCert);
            }
            PublicKeyAlgorithm::RsaPss { scheme }
        }
        _ => return Err(TlsError::BadCert),
    };
    Ok(algorithm)
}

fn public_key_encoding_valid(algorithm: PublicKeyAlgorithm, key: &[u8]) -> bool {
    match algorithm {
        PublicKeyAlgorithm::Ed25519 | PublicKeyAlgorithm::X25519 => key.len() == 32,
        PublicKeyAlgorithm::MlDsa44 => key.len() == 1312,
        PublicKeyAlgorithm::EcP256 => p256::PublicKey::from_sec1_bytes(key).is_ok(),
        PublicKeyAlgorithm::EcP384 => p384::PublicKey::from_sec1_bytes(key).is_ok(),
        PublicKeyAlgorithm::RsaEncryption | PublicKeyAlgorithm::RsaPss { .. } => {
            rsa_public_key_components(key).is_ok()
        }
    }
}

/// Only canonical encodings: allowing forms such as integers with leading zeros would let one key
/// have several encodings with different fingerprints.
pub(crate) fn rsa_public_key_components(key: &[u8]) -> Result<(&[u8], &[u8]), TlsError> {
    /// Strips the sign byte but rejects non-canonical forms.
    fn positive_integer(raw: &[u8]) -> Result<&[u8], TlsError> {
        let (&first, rest) = raw.split_first().ok_or(TlsError::BadCert)?;
        if first == 0 {
            let (&next, _) = rest.split_first().ok_or(TlsError::BadCert)?;
            if next & 0x80 == 0 {
                return Err(TlsError::BadCert);
            }
            Ok(rest)
        } else if first & 0x80 != 0 {
            Err(TlsError::BadCert)
        } else {
            Ok(raw)
        }
    }

    let mut outer = Der::new(key);
    let mut sequence = Der::new(outer.expect(der::SEQUENCE)?);
    if !outer.is_empty() {
        return Err(TlsError::BadCert);
    }
    let modulus = positive_integer(sequence.expect(der::INTEGER)?)?;
    let exponent = positive_integer(sequence.expect(der::INTEGER)?)?;
    if !sequence.is_empty()
        || modulus.len() < 256
        || modulus.len() > 1024
        || (modulus.len() == 256 && modulus[0] & 0x80 == 0)
        || modulus.last().is_none_or(|byte| byte & 1 == 0)
        || exponent.len() > 5
    {
        return Err(TlsError::BadCert);
    }
    let exponent_value = exponent
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    // Exponent 3 is still used by older roots such as Go Daddy Class 2. `onetdns_core::rsa`, which
    // verifies those signatures, rebuilds the whole EM and compares it, so a small exponent offers
    // no forgery path.
    if !(3..=(1u64 << 33) - 1).contains(&exponent_value) || exponent_value & 1 == 0 {
        return Err(TlsError::BadCert);
    }
    Ok((modulus, exponent))
}

pub(crate) enum PeerHost<'a> {
    Ip(IpAddr),
    /// Trailing dot stripped.
    Name(&'a str),
}

/// Strips surrounding whitespace, IPv6 brackets, and the trailing dot; whatever then parses as an
/// address is an address. Certificate name checks and SNI must share this one decision, so that
/// leaving out SNI and checking the IP SAN when connecting by address never disagree.
pub(crate) fn peer_host(host: &str) -> PeerHost<'_> {
    let trimmed = host
        .trim()
        .trim_matches(|c| c == '[' || c == ']')
        .trim_end_matches('.');
    match trimmed.parse::<IpAddr>() {
        Ok(ip) => PeerHost::Ip(ip),
        Err(_) => PeerHost::Name(trimmed),
    }
}

fn distinguished_name_label(raw: &[u8]) -> Option<String> {
    const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
    const OID_O: &[u8] = &[0x55, 0x04, 0x0a];
    let mut top = Der::new(raw);
    let mut name = Der::new(top.expect(der::SEQUENCE).ok()?);
    let mut organization = None;
    while !name.is_empty() {
        let set = name.expect(der::SET).ok()?;
        let mut attrs = Der::new(set);
        while !attrs.is_empty() {
            let mut attr = Der::new(attrs.expect(der::SEQUENCE).ok()?);
            let oid = attr.expect(der::OID).ok()?;
            let value = attr.next().ok()?;
            let text = decode_directory_string(value.tag, value.value)?;
            if oid == OID_CN {
                return Some(text);
            }
            if oid == OID_O && organization.is_none() {
                organization = Some(text);
            }
        }
    }
    organization
}

/// The tag picks among several encodings.
fn decode_directory_string(tag: u8, value: &[u8]) -> Option<String> {
    match tag {
        0x0c | 0x13 | 0x14 | 0x16 => std::str::from_utf8(value).ok().map(str::to_string),
        0x1e if value.len() % 2 == 0 => {
            let units: Vec<u16> = value
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect();
            String::from_utf16(&units).ok()
        }
        _ => None,
    }
}

pub fn scheme_from_sig_algid(algid: &[u8]) -> Result<u16, TlsError> {
    let mut d = Der::new(algid);
    let oid = d.expect(der::OID)?;
    let scheme = match oid {
        x if x == OID_ED25519 => {
            if !d.is_empty() {
                return Err(TlsError::BadCert);
            }
            consts::ED25519
        }
        x if x == OID_ML_DSA_44 => {
            if !d.is_empty() {
                return Err(TlsError::BadCert);
            }
            consts::MLDSA44
        }
        x if x == OID_ECDSA_SHA256 => {
            if !d.is_empty() {
                return Err(TlsError::BadCert);
            }
            consts::ECDSA_SECP256R1_SHA256
        }
        x if x == OID_ECDSA_SHA384 => {
            if !d.is_empty() {
                return Err(TlsError::BadCert);
            }
            consts::ECDSA_SECP384R1_SHA384
        }
        x if x == OID_SHA256_RSA => {
            consume_optional_null(&mut d)?;
            consts::RSA_PKCS1_SHA256
        }
        x if x == OID_SHA384_RSA => {
            consume_optional_null(&mut d)?;
            consts::RSA_PKCS1_SHA384
        }
        x if x == OID_SHA512_RSA => {
            consume_optional_null(&mut d)?;
            consts::RSA_PKCS1_SHA512
        }
        x if x == OID_RSA_PSS => pss_scheme_from_params(&mut d)?,
        // The parameters of a scheme that will not be verified are not interpreted, but they must
        // still be whole DER: a certificate with uninterpreted bytes left over is rejected.
        _ => {
            while !d.is_empty() {
                d.next()?;
            }
            0
        }
    };
    if !d.is_empty() {
        return Err(TlsError::BadCert);
    }
    Ok(scheme)
}

/// Whether it is present differs by algorithm.
fn consume_optional_null(d: &mut Der<'_>) -> Result<(), TlsError> {
    if !d.is_empty() {
        let null = d.next()?;
        if null.tag != 0x05 || !null.value.is_empty() || !d.is_empty() {
            return Err(TlsError::BadCert);
        }
    }
    Ok(())
}

/// The hash, mask function, and salt length must agree.
fn pss_scheme_from_params(d: &mut Der) -> Result<u16, TlsError> {
    let params = d.expect(der::SEQUENCE)?;
    let mut p = Der::new(params);
    let mut hash_oid: Option<Vec<u8>> = None;
    let mut mgf_hash_oid: Option<Vec<u8>> = None;
    let mut salt_len: Option<u32> = None;
    let mut trailer: u32 = 1;
    let mut seen = [false; 4];

    while !p.is_empty() {
        let f = p.next()?;
        let index = match f.tag {
            t if t == der::context(0) => 0,
            t if t == der::context(1) => 1,
            t if t == der::context(2) => 2,
            t if t == der::context(3) => 3,
            _ => return Err(TlsError::BadCert),
        };
        if seen[index] {
            return Err(TlsError::BadCert);
        }
        seen[index] = true;
        match index {
            0 => hash_oid = Some(parse_hash_algid(f.value)?.to_vec()),
            1 => {
                let alg = Der::new(f.value).expect(der::SEQUENCE)?;
                let mut a = Der::new(alg);
                if a.expect(der::OID)? != OID_MGF1 {
                    return Err(TlsError::BadCert);
                }
                let params = a.expect(der::SEQUENCE)?;
                if !a.is_empty() {
                    return Err(TlsError::BadCert);
                }
                mgf_hash_oid = Some(parse_hash_algid_content(params)?.to_vec());
            }
            2 => {
                let value = Der::new(f.value).expect(der::INTEGER)?;
                salt_len = Some(der::uint_value(value)?);
            }
            3 => {
                let value = Der::new(f.value).expect(der::INTEGER)?;
                trailer = der::uint_value(value)?;
            }
            _ => unreachable!(),
        }
    }

    let Some(hash_oid) = hash_oid else {
        return Ok(0);
    };
    let Some(mgf_hash_oid) = mgf_hash_oid else {
        return Ok(0);
    };
    if hash_oid != mgf_hash_oid || trailer != 1 {
        return Ok(0);
    }
    let (scheme, required_salt) = if hash_oid == OID_HASH_SHA256 {
        (consts::RSA_PSS_RSAE_SHA256, 32)
    } else if hash_oid == OID_HASH_SHA384 {
        (consts::RSA_PSS_RSAE_SHA384, 48)
    } else if hash_oid == OID_HASH_SHA512 {
        (consts::RSA_PSS_RSAE_SHA512, 64)
    } else {
        return Ok(0);
    };
    if salt_len != Some(required_salt) {
        return Ok(0);
    }
    Ok(scheme)
}

fn parse_hash_algid(algid: &[u8]) -> Result<&[u8], TlsError> {
    let mut outer = Der::new(algid);
    let alg = outer.expect(der::SEQUENCE)?;
    if !outer.is_empty() {
        return Err(TlsError::BadCert);
    }
    parse_hash_algid_content(alg)
}

fn parse_hash_algid_content(alg: &[u8]) -> Result<&[u8], TlsError> {
    let mut d = Der::new(alg);
    let oid = d.expect(der::OID)?;
    if !d.is_empty() {
        let null = d.next()?;
        if null.tag != 0x05 || !null.value.is_empty() || !d.is_empty() {
            return Err(TlsError::BadCert);
        }
    }
    Ok(oid)
}

#[derive(Default)]
struct ParsedExt {
    san_dns: Vec<String>,
    san_ip: Vec<IpAddr>,
    is_ca: bool,
    path_len: Option<u32>,
    key_usage: Option<u16>,
    eku_server_auth: Option<bool>,
    eku_client_auth: Option<bool>,
    name_constraints: Option<NameConstraints>,
    ocsp_urls: Vec<String>,
    crl_urls: Vec<String>,
    eku_ocsp_signing: bool,
}

pub(crate) struct Extension<'a> {
    pub oid: &'a [u8],
    /// When set and the extension cannot be interpreted, the certificate, CRL, or OCSP response
    /// holding it must not be used.
    pub critical: bool,
    /// The extension value inside the OCTET STRING.
    pub value: &'a [u8],
}

/// Certificates, CRLs, and OCSP responses share this format. Rejects an extension that appears
/// twice: which one is followed differs by implementation, and that difference is a bypass.
pub(crate) fn extensions(seq_content: &[u8]) -> Result<Vec<Extension<'_>>, TlsError> {
    let mut e = Der::new(seq_content);
    let mut out: Vec<Extension<'_>> = Vec::new();
    while !e.is_empty() {
        let mut ex = Der::new(e.expect(der::SEQUENCE)?);
        let oid = ex.expect(der::OID)?;
        if out.iter().any(|seen| seen.oid == oid) {
            return Err(TlsError::BadCert);
        }
        let first = ex.next()?;
        let (critical, value) = match first.tag {
            der::BOOLEAN => (
                der::boolean_value(first.value)?,
                ex.expect(der::OCTET_STRING)?,
            ),
            der::OCTET_STRING => (false, first.value),
            _ => return Err(TlsError::BadCert),
        };
        if !ex.is_empty() {
            return Err(TlsError::BadCert);
        }
        out.push(Extension {
            oid,
            critical,
            value,
        });
    }
    Ok(out)
}

/// Fails on an unknown critical extension.
fn parse_extensions(ext_data: &[u8]) -> Result<ParsedExt, TlsError> {
    let exts = Der::new(ext_data).expect(der::SEQUENCE)?;
    let mut out = ParsedExt::default();

    for Extension {
        oid,
        critical,
        value: val,
    } in extensions(exts)?
    {
        let known = oid == OID_SAN
            || oid == OID_BASIC_CONSTRAINTS
            || oid == OID_KEY_USAGE
            || oid == OID_EKU
            || oid == OID_NAME_CONSTRAINTS
            || oid == OID_AIA
            || oid == OID_CRL_DP;
        if critical && !known {
            return Err(TlsError::BadCert);
        }
        if oid == OID_SAN {
            let names = only_value(val, der::SEQUENCE)?;
            let mut g = Der::new(names);
            while !g.is_empty() {
                let name = g.next()?;
                if name.tag == 0x82 {
                    // dNSName is an IA5String. Taking a non-ASCII value as a name would pass
                    // certificates other verifiers reject.
                    if !name.value.is_ascii() {
                        return Err(TlsError::BadCert);
                    }
                    let s = std::str::from_utf8(name.value).map_err(|_| TlsError::BadCert)?;
                    out.san_dns.push(s.to_string());
                } else if name.tag == 0x87 {
                    match name.value {
                        [a, b, c, d] => out.san_ip.push(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
                        bytes if bytes.len() == 16 => {
                            let mut raw = [0u8; 16];
                            raw.copy_from_slice(bytes);
                            out.san_ip.push(IpAddr::V6(Ipv6Addr::from(raw)));
                        }
                        _ => return Err(TlsError::BadCert),
                    }
                }
            }
        } else if oid == OID_BASIC_CONSTRAINTS {
            // cA BOOLEAN DEFAULT FALSE, then pathLenConstraint INTEGER (0..MAX) OPTIONAL, and
            // nothing else. Passing other orders, duplicates, or unknown values would read it
            // differently from other verifiers.
            let mut outer = Der::new(val);
            let seq = outer.expect(der::SEQUENCE)?;
            if !outer.is_empty() {
                return Err(TlsError::BadCert);
            }
            let mut b = Der::new(seq);
            let mut field = if b.is_empty() { None } else { Some(b.next()?) };
            if let Some(t) = field.filter(|t| t.tag == der::BOOLEAN) {
                out.is_ca = der::boolean_value(t.value)?;
                field = if b.is_empty() { None } else { Some(b.next()?) };
            }
            if let Some(t) = field {
                if t.tag != der::INTEGER {
                    return Err(TlsError::BadCert);
                }
                out.path_len = Some(der::uint_value(t.value)?);
            }
            if !b.is_empty() {
                return Err(TlsError::BadCert);
            }
        } else if oid == OID_KEY_USAGE {
            let bs = only_value(val, der::BIT_STRING)?;
            out.key_usage = Some(decode_key_usage(bit_string_bytes(bs)?));
        } else if oid == OID_EKU {
            let seq = only_value(val, der::SEQUENCE)?;
            let mut k = Der::new(seq);
            let mut server_auth = false;
            let mut client_auth = false;
            while !k.is_empty() {
                let purpose = k.expect(der::OID)?;
                if purpose == EKU_SERVER_AUTH || purpose == EKU_ANY {
                    server_auth = true;
                }
                if purpose == EKU_CLIENT_AUTH || purpose == EKU_ANY {
                    client_auth = true;
                }
                if purpose == EKU_OCSP_SIGNING {
                    out.eku_ocsp_signing = true;
                }
            }
            out.eku_server_auth = Some(server_auth);
            out.eku_client_auth = Some(client_auth);
        } else if oid == OID_NAME_CONSTRAINTS {
            let seq = only_value(val, der::SEQUENCE)?;
            let mut nc = Der::new(seq);
            let mut constraints = NameConstraints::default();
            while !nc.is_empty() {
                let t = nc.next()?;
                if t.tag == der::context(0) {
                    parse_name_subtrees(
                        t.value,
                        &mut constraints.permitted_dns,
                        &mut constraints.permitted_ip,
                        critical,
                    )?;
                } else if t.tag == der::context(1) {
                    parse_name_subtrees(
                        t.value,
                        &mut constraints.excluded_dns,
                        &mut constraints.excluded_ip,
                        critical,
                    )?;
                }
            }
            out.name_constraints = Some(constraints);
        } else if oid == OID_AIA {
            let seq = only_value(val, der::SEQUENCE)?;
            let mut a = Der::new(seq);
            while !a.is_empty() {
                let Ok(adv) = a.expect(der::SEQUENCE) else {
                    break;
                };
                let mut ad = Der::new(adv);
                let Ok(method) = ad.expect(der::OID) else {
                    continue;
                };
                let Ok(loc) = ad.next() else { continue };

                if method == OID_AD_OCSP && loc.tag == 0x86 {
                    if let Ok(s) = std::str::from_utf8(loc.value) {
                        out.ocsp_urls.push(s.to_string());
                    }
                }
            }
        } else if oid == OID_CRL_DP {
            collect_uris(val, &mut out.crl_urls);
        }
    }
    Ok(out)
}

fn collect_uris(data: &[u8], out: &mut Vec<String>) {
    collect_uris_depth(data, out, 0);
}

fn collect_uris_depth(data: &[u8], out: &mut Vec<String>, depth: usize) {
    /// Deeply wrapped certificates would otherwise overflow the stack.
    const MAX_DER_DEPTH: usize = 32;
    if depth >= MAX_DER_DEPTH {
        return;
    }
    let mut d = Der::new(data);
    while !d.is_empty() {
        let Ok(tlv) = d.next() else { break };
        if tlv.tag == 0x86 {
            if let Ok(s) = std::str::from_utf8(tlv.value) {
                if s.starts_with("http") {
                    out.push(s.to_string());
                }
            }
        } else if tlv.tag & 0x20 != 0 {
            collect_uris_depth(tlv.value, out, depth + 1);
        }
    }
}

fn parse_name_subtrees(
    data: &[u8],
    dns: &mut Vec<String>,
    ips: &mut Vec<IpConstraint>,
    _critical: bool,
) -> Result<(), TlsError> {
    let mut d = Der::new(data);
    while !d.is_empty() {
        let st = d.next()?;
        if st.tag != der::SEQUENCE {
            return Err(TlsError::BadCert);
        }
        let mut sub = Der::new(st.value);
        let base = sub.next()?;
        match base.tag {
            0x82 => {
                let value = std::str::from_utf8(base.value).map_err(|_| TlsError::BadCert)?;
                if value.is_empty() || value.as_bytes().contains(&0) {
                    return Err(TlsError::BadCert);
                }
                dns.push(value.to_string());
            }
            0x87 => ips.push(parse_ip_constraint(base.value)?),
            _ => {
                return Err(TlsError::BadCert);
            }
        }

        while !sub.is_empty() {
            let extra = sub.next()?;
            if (extra.tag == 0x80 && extra.value.iter().any(|&b| b != 0)) || extra.tag == 0x81 {
                return Err(TlsError::BadCert);
            }
        }
    }
    Ok(())
}

/// Address followed by mask.
fn parse_ip_constraint(value: &[u8]) -> Result<IpConstraint, TlsError> {
    let (address, mask) = match value.len() {
        8 => (&value[..4], &value[4..]),
        32 => (&value[..16], &value[16..]),
        _ => return Err(TlsError::BadCert),
    };
    let prefix_len = contiguous_prefix_len(mask).ok_or(TlsError::BadCert)?;
    let address = if address.len() == 4 {
        IpAddr::V4(Ipv4Addr::new(
            address[0], address[1], address[2], address[3],
        ))
    } else {
        let mut raw = [0u8; 16];
        raw.copy_from_slice(address);
        IpAddr::V6(Ipv6Addr::from(raw))
    };
    Ok(IpConstraint {
        address,
        prefix_len,
    })
}

/// None when the mask has holes.
fn contiguous_prefix_len(mask: &[u8]) -> Option<u8> {
    let mut prefix = 0u8;
    let mut zero_seen = false;
    for &byte in mask {
        for bit in 0..8 {
            let set = byte & (0x80 >> bit) != 0;
            if set {
                if zero_seen {
                    return None;
                }
                prefix = prefix.checked_add(1)?;
            } else {
                zero_seen = true;
            }
        }
    }
    Some(prefix)
}

fn decode_key_usage(bits: &[u8]) -> u16 {
    let mut mask = 0u16;
    for n in 0u16..9 {
        let (byte, off) = ((n / 8) as usize, n % 8);
        if let Some(&b) = bits.get(byte) {
            if b & (0x80 >> off) != 0 {
                mask |= 1 << n;
            }
        }
    }
    mask
}

/// Ignoring trailing bytes would accept certificates other verifiers reject.
fn only_value(val: &[u8], tag: u8) -> Result<&[u8], TlsError> {
    let mut d = Der::new(val);
    let value = d.expect(tag)?;
    if !d.is_empty() {
        return Err(TlsError::BadCert);
    }
    Ok(value)
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Both two-digit and four-digit year forms occur.
pub fn parse_time(tlv: crate::der::Tlv) -> Result<i64, TlsError> {
    let s = tlv.value;
    let digs = |b: &[u8]| -> Option<i64> {
        let mut n = 0i64;
        for &c in b {
            if !c.is_ascii_digit() {
                return None;
            }
            n = n * 10 + (c - b'0') as i64;
        }
        Some(n)
    };
    let (year, rest) = match tlv.tag {
        0x17 => {
            if s.len() != 13 || s[12] != b'Z' {
                return Err(TlsError::BadCert);
            }
            let yy = digs(&s[0..2]).ok_or(TlsError::BadCert)?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, &s[2..12])
        }
        0x18 => {
            if s.len() != 15 || s[14] != b'Z' {
                return Err(TlsError::BadCert);
            }
            (digs(&s[0..4]).ok_or(TlsError::BadCert)?, &s[4..14])
        }
        _ => return Err(TlsError::BadCert),
    };
    let mo = digs(&rest[0..2]).ok_or(TlsError::BadCert)?;
    let d = digs(&rest[2..4]).ok_or(TlsError::BadCert)?;
    let h = digs(&rest[4..6]).ok_or(TlsError::BadCert)?;
    let mi = digs(&rest[6..8]).ok_or(TlsError::BadCert)?;
    let se = digs(&rest[8..10]).ok_or(TlsError::BadCert)?;
    if !(1..=12).contains(&mo)
        || d < 1
        || d > days_in_month(year, mo)
        || h > 23
        || mi > 59
        || se > 60
    {
        return Err(TlsError::BadCert);
    }
    Ok(days_from_civil(year, mo, d) * 86400 + h * 3600 + mi * 60 + se)
}

/// The DER Time that RFC 5280 requires for certificate validity: UTCTime through 2049,
/// GeneralizedTime from 2050. The year must fit in four digits.
pub fn encode_time(unix: i64) -> Vec<u8> {
    let (y, m, d) = civil_from_days(unix.div_euclid(86400));
    let secs = unix.rem_euclid(86400);
    let clock = format!(
        "{m:02}{d:02}{:02}{:02}{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    );
    let (tag, text) = if (1950..2050).contains(&y) {
        (0x17, format!("{:02}{clock}", y % 100))
    } else {
        (0x18, format!("{y:04}{clock}"))
    };
    let mut out = vec![tag, text.len() as u8];
    out.extend_from_slice(text.as_bytes());
    out
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

pub(crate) fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Ignoring it would drop the constraint.
    fn nameconstraints_critical_unsupported_form_rejected() {
        let data = [0x30, 0x05, 0x81, 0x03, b'a', b'b', b'c'];
        let (mut dns, mut ips) = (Vec::new(), Vec::new());

        assert_eq!(
            parse_name_subtrees(&data, &mut dns, &mut ips, true),
            Err(TlsError::BadCert)
        );

        let (mut dns2, mut ips2) = (Vec::new(), Vec::new());
        assert_eq!(
            parse_name_subtrees(&data, &mut dns2, &mut ips2, false),
            Err(TlsError::BadCert)
        );
    }

    #[test]
    fn nameconstraints_critical_nonzero_minimum_rejected() {
        let data = [0x30, 0x06, 0x82, 0x01, b'a', 0x80, 0x01, 0x01];
        let (mut dns, mut ips) = (Vec::new(), Vec::new());
        assert_eq!(
            parse_name_subtrees(&data, &mut dns, &mut ips, true),
            Err(TlsError::BadCert)
        );
    }

    #[test]
    fn nameconstraints_dns_subtree_still_parses() {
        let mut d = vec![0x30u8, 0x06, 0x82, 0x04];
        d.extend_from_slice(b"ex.c");
        let (mut dns, mut ips) = (Vec::new(), Vec::new());
        assert_eq!(parse_name_subtrees(&d, &mut dns, &mut ips, true), Ok(()));
        assert_eq!(dns, vec!["ex.c".to_string()]);
    }

    #[test]
    fn days_from_civil_known() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), 10957);
        assert_eq!(days_from_civil(2021, 1, 1) * 86400, 1609459200);
    }

    #[test]
    fn encoded_times_parse_back_on_both_sides_of_2050() {
        let utc_end = days_from_civil(2049, 12, 31) * 86400 + 86399;
        for unix in [0, 951_782_400, 1_609_459_199, utc_end, utc_end + 1] {
            let der = encode_time(unix);
            let tlv = crate::der::Der::new(&der).next().unwrap();
            assert_eq!(parse_time(tlv), Ok(unix), "{unix}");
        }
        assert_eq!(encode_time(utc_end), b"\x17\x0d491231235959Z");
        assert_eq!(encode_time(utc_end + 1), b"\x18\x0f20500101000000Z");
    }

    fn utctime(s: &[u8]) -> crate::der::Tlv<'_> {
        crate::der::Tlv {
            tag: 0x17,
            value: s,
        }
    }

    #[test]
    fn pss_scheme_requires_matching_hash_mgf_and_salt() {
        let algid = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x34, 0xa0,
            0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
            0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
            0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
            0x02, 0x02, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x30,
        ];
        assert_eq!(
            scheme_from_sig_algid(&algid).unwrap(),
            consts::RSA_PSS_RSAE_SHA384
        );

        let mut wrong_salt = algid;
        *wrong_salt.last_mut().unwrap() = 0x20;
        assert_eq!(scheme_from_sig_algid(&wrong_salt).unwrap(), 0);
    }

    #[test]
    /// Otherwise schemes get confused.
    fn public_key_algorithm_restricts_signature_schemes() {
        assert!(PublicKeyAlgorithm::Ed25519.allows_signature_scheme(consts::ED25519));
        assert!(!PublicKeyAlgorithm::X25519.allows_signature_scheme(consts::ED25519));
        assert!(!PublicKeyAlgorithm::EcP256.allows_signature_scheme(consts::ECDSA_SECP384R1_SHA384));
        assert!(PublicKeyAlgorithm::RsaPss {
            scheme: consts::RSA_PSS_RSAE_SHA256,
        }
        .allows_signature_scheme(consts::RSA_PSS_RSAE_SHA256));
        assert!(!PublicKeyAlgorithm::RsaPss {
            scheme: consts::RSA_PSS_RSAE_SHA256,
        }
        .allows_signature_scheme(consts::RSA_PKCS1_SHA256));
    }

    #[test]
    /// A scheme that does not fit the key is the peer's fault, not the certificate's, and a wrong
    /// signature is decrypt_error. Mixing them sends the peer the wrong alert.
    fn tls_signature_failures_name_their_cause() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        use p256::pkcs8::DecodePrivateKey;

        let ck = rcgen::generate_simple_self_signed(vec!["dns.example".to_string()]).unwrap();
        let mut cert = X509::parse(ck.cert.der().as_ref()).unwrap();
        let key = SigningKey::from(
            p256::SecretKey::from_pkcs8_der(&ck.key_pair.serialize_der()).unwrap(),
        );
        let signature: Signature = key.sign(b"content");
        let signature = signature.to_der().as_bytes().to_vec();

        assert_eq!(
            cert.verify_tls_signature(consts::ECDSA_SECP256R1_SHA256, b"content", &signature),
            Ok(())
        );
        assert_eq!(
            cert.verify_tls_signature(consts::ECDSA_SECP256R1_SHA256, b"tampered", &signature),
            Err(TlsError::BadSignature)
        );
        assert_eq!(
            cert.verify_tls_signature(consts::RSA_PSS_RSAE_SHA256, b"content", &signature),
            Err(TlsError::IllegalParameter)
        );
        cert.public_key_algorithm = PublicKeyAlgorithm::RsaPss {
            scheme: consts::RSA_PSS_RSAE_SHA256,
        };
        assert_eq!(
            cert.verify_tls_signature(consts::RSA_PSS_RSAE_SHA256, b"content", &signature),
            Err(TlsError::UnsupportedCertificate)
        );
    }

    #[test]
    fn duplicate_extension_rejected() {
        let dup = [
            0x30, 0x16, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30,
            0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00,
        ];
        assert!(matches!(parse_extensions(&dup), Err(TlsError::BadCert)));

        let one = [
            0x30, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00,
        ];
        assert!(parse_extensions(&one).is_ok());
    }

    /// Inserted as a value that belongs nowhere.
    const NULL_TAG: u8 = 0x05;

    /// All test inputs are shorter than 128 bytes.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag, u8::try_from(content.len()).unwrap()];
        out.extend_from_slice(content);
        out
    }

    /// `critical` is the BOOLEAN content byte.
    fn one_extension(oid: &[u8], critical: Option<&[u8]>, value: &[u8]) -> Vec<u8> {
        let mut ext = tlv(der::OID, oid);
        if let Some(critical) = critical {
            ext.extend(tlv(der::BOOLEAN, critical));
        }
        ext.extend(tlv(der::OCTET_STRING, value));
        tlv(der::SEQUENCE, &tlv(der::SEQUENCE, &ext))
    }

    fn basic_constraints(fields: &[u8]) -> Vec<u8> {
        one_extension(OID_BASIC_CONSTRAINTS, None, &tlv(der::SEQUENCE, fields))
    }

    #[test]
    /// Accepting certificates other verifiers reject would split verdicts between verifiers.
    fn extension_structure_is_strict_der() {
        let empty_seq = tlv(der::SEQUENCE, &[]);
        let with_critical =
            |critical: &[u8]| one_extension(OID_BASIC_CONSTRAINTS, Some(critical), &empty_seq);
        assert!(parse_extensions(&with_critical(&[0xFF])).is_ok());
        assert!(parse_extensions(&with_critical(&[0x00])).is_ok());
        for critical in [&[][..], &[0x01], &[0xFF, 0xFF]] {
            assert!(
                parse_extensions(&with_critical(critical)).is_err(),
                "BOOLEAN {critical:02x?}"
            );
        }

        let mut trailing = tlv(der::OID, OID_BASIC_CONSTRAINTS);
        trailing.extend(tlv(der::OCTET_STRING, &empty_seq));
        trailing.extend(tlv(NULL_TAG, &[]));
        let trailing = tlv(der::SEQUENCE, &tlv(der::SEQUENCE, &trailing));
        assert!(parse_extensions(&trailing).is_err(), "extnValue 뒤의 값");

        let mut value_tail = empty_seq.clone();
        value_tail.extend(tlv(NULL_TAG, &[]));
        assert!(
            parse_extensions(&one_extension(OID_BASIC_CONSTRAINTS, None, &value_tail)).is_err(),
            "extnValue 안에서 SEQUENCE 뒤의 값"
        );
    }

    #[test]
    fn basic_constraints_follow_the_grammar() {
        let ca = tlv(der::BOOLEAN, &[0xFF]);
        let zero = tlv(der::INTEGER, &[0x00]);

        let mut ca_zero = ca.clone();
        ca_zero.extend(&zero);
        let parsed = parse_extensions(&basic_constraints(&ca_zero)).unwrap();
        assert!(parsed.is_ca);
        assert_eq!(parsed.path_len, Some(0));

        let parsed = parse_extensions(&basic_constraints(&ca)).unwrap();
        assert!(parsed.is_ca);
        assert_eq!(parsed.path_len, None);

        let mut negative = ca.clone();
        negative.extend(tlv(der::INTEGER, &[0xFF]));
        assert!(
            parse_extensions(&basic_constraints(&negative)).is_err(),
            "pathLen -1"
        );

        let mut huge = ca.clone();
        huge.extend(tlv(der::INTEGER, &[0x01, 0x00, 0x00, 0x00, 0x00]));
        assert!(
            parse_extensions(&basic_constraints(&huge)).is_err(),
            "pathLen 이 u32 를 넘음"
        );

        let mut reversed = zero.clone();
        reversed.extend(&ca);
        assert!(
            parse_extensions(&basic_constraints(&reversed)).is_err(),
            "순서가 뒤바뀜"
        );

        let mut twice = ca.clone();
        twice.extend(&ca);
        assert!(
            parse_extensions(&basic_constraints(&twice)).is_err(),
            "cA 가 두 번"
        );

        let mut extra = ca_zero.clone();
        extra.extend(tlv(NULL_TAG, &[]));
        assert!(
            parse_extensions(&basic_constraints(&extra)).is_err(),
            "모르는 값"
        );
    }

    #[test]
    fn eku_and_san_reject_foreign_values() {
        let mut purposes = tlv(der::OID, EKU_SERVER_AUTH);
        let eku = one_extension(OID_EKU, None, &tlv(der::SEQUENCE, &purposes));
        assert_eq!(parse_extensions(&eku).unwrap().eku_server_auth, Some(true));
        purposes.extend(tlv(NULL_TAG, &[]));
        let eku = one_extension(OID_EKU, None, &tlv(der::SEQUENCE, &purposes));
        assert!(parse_extensions(&eku).is_err());

        let san = |name: &[u8]| one_extension(OID_SAN, None, &tlv(der::SEQUENCE, &tlv(0x82, name)));
        assert_eq!(
            parse_extensions(&san(b"example.com")).unwrap().san_dns,
            ["example.com"]
        );
        assert!(parse_extensions(&san("예시.com".as_bytes())).is_err());
    }

    #[test]
    fn uint_value_rejects_negative_and_non_minimal() {
        assert_eq!(der::uint_value(&[0x00]).unwrap(), 0);
        assert_eq!(der::uint_value(&[0x7F]).unwrap(), 127);
        assert_eq!(der::uint_value(&[0x00, 0x80]).unwrap(), 128);
        assert!(der::uint_value(&[]).is_err());
        assert!(der::uint_value(&[0x80]).is_err());
        assert!(der::uint_value(&[0x00, 0x7F]).is_err());
        assert!(der::uint_value(&[0x01, 0x00, 0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn parse_time_rejects_malformed() {
        assert!(parse_time(utctime(b"240101000000Z")).is_ok());

        assert!(parse_time(utctime(b"241301000000Z")).is_err(), "월 13");
        assert!(parse_time(utctime(b"240132000000Z")).is_err(), "일 32");
        assert!(parse_time(utctime(b"240230000000Z")).is_err(), "2월 30일");
        assert!(parse_time(utctime(b"240101240000Z")).is_err(), "시 24");
        assert!(parse_time(utctime(b"240101006100Z")).is_err(), "분 61");

        assert!(parse_time(utctime(b"240101000000")).is_err(), "Z 없음");
        assert!(parse_time(utctime(b"240101000000Z00")).is_err(), "trailing");

        assert!(parse_time(utctime(b"240229000000Z")).is_ok());
        assert!(parse_time(utctime(b"230229000000Z")).is_err());
    }

    #[test]
    fn rsa_public_key_der_is_canonical_and_meets_security_floor() {
        fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            if body.len() < 128 {
                out.push(body.len() as u8);
            } else {
                out.extend_from_slice(&[0x82, (body.len() >> 8) as u8, body.len() as u8]);
            }
            out.extend_from_slice(body);
            out
        }
        fn key(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
            let mut body = tlv(der::INTEGER, modulus);
            body.extend_from_slice(&tlv(der::INTEGER, exponent));
            tlv(der::SEQUENCE, &body)
        }

        let mut modulus = vec![0u8; 257];
        modulus[1] = 0x80;
        modulus[256] = 1;
        let valid = key(&modulus, &[1, 0, 1]);
        let (n, e) = rsa_public_key_components(&valid).unwrap();
        assert_eq!(n.len(), 256);
        assert_eq!(e, &[1, 0, 1]);

        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(rsa_public_key_components(&trailing).is_err());

        let mut short_modulus = vec![0x7f; 256];
        short_modulus[255] = 1;
        assert!(rsa_public_key_components(&key(&short_modulus, &[1, 0, 1])).is_err());

        let mut even_modulus = modulus.clone();
        even_modulus[256] = 2;
        assert!(rsa_public_key_components(&key(&even_modulus, &[1, 0, 1])).is_err());
        assert!(rsa_public_key_components(&key(&modulus, &[3])).is_ok());
        assert!(rsa_public_key_components(&key(&modulus, &[1])).is_err());
        assert!(rsa_public_key_components(&key(&modulus, &[0, 1, 0, 1])).is_err());

        let mut negative_modulus = modulus[1..].to_vec();
        negative_modulus[0] = 0x80;
        assert!(rsa_public_key_components(&key(&negative_modulus, &[1, 0, 1])).is_err());
    }

    #[test]
    fn parse_real_cert_and_verify_self_signed() {
        let ck = rcgen::generate_simple_self_signed(vec![
            "dns.example.com".to_string(),
            "*.test.example".to_string(),
        ])
        .unwrap();
        let der = ck.cert.der();
        let cert = X509::parse(der.as_ref()).expect("X.509 파싱");

        assert!(cert.matches_hostname("dns.example.com"));
        assert!(cert.matches_hostname("a.test.example"));
        assert!(!cert.matches_hostname("test.example"));
        assert!(!cert.matches_hostname("evil.com"));

        assert_eq!(cert.sig_scheme, consts::ECDSA_SECP256R1_SHA256);

        assert_eq!(cert.public_key.len(), 65);
        assert_eq!(cert.public_key_algorithm, PublicKeyAlgorithm::EcP256);
        assert_eq!(cert.verify_self_signed(), Ok(()));

        assert!(cert.valid_at(cert.not_before));
        assert!(cert.valid_at(cert.not_after));
        assert!(!cert.valid_at(cert.not_before - 1));
        assert!(!cert.valid_at(cert.not_after + 1));

        let mut bad = cert.clone();
        let last = bad.tbs_raw.len() - 1;
        bad.tbs_raw[last] ^= 0xFF;
        assert!(bad.verify_self_signed().is_err());
    }
}
