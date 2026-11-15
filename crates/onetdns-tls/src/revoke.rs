//! Certificate revocation checks over OCSP responses and CRLs. Either must be signed by the issuer,
//! and this side verifies that signature itself.
//!
//! A response without a next update time cannot be trusted forever; reusing a stale one makes a
//! revoked certificate look alive.

use crate::der::{self, bit_string_bytes, Der, Tlv};
use crate::x509::{extensions, parse_time, scheme_from_sig_algid, Extension, X509};
use crate::TlsError;

use sha1::{Digest, Sha1};

const OID_OCSP_BASIC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
/// The OCSP CertID uses SHA-1 by definition.
const OID_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
/// A delta CRL holds only the changes since its base CRL.
const OID_DELTA_CRL_INDICATOR: &[u8] = &[0x55, 0x1d, 0x1b];
/// Sets which of the issuer's certificates a CRL covers.
const OID_ISSUING_DISTRIBUTION_POINT: &[u8] = &[0x55, 0x1d, 0x1c];
const OCSP_CLOCK_SKEW_SECS: i64 = 300;
/// Without a limit a stale response would stay valid forever.
const OCSP_MAX_AGE_WITHOUT_NEXT_UPDATE_SECS: i64 = 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStatus {
    Good,
    Revoked,
    Unknown,
}

fn sha1(data: &[u8]) -> Vec<u8> {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().to_vec()
}

fn der_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let mut b = Vec::new();
        let mut l = len;
        while l > 0 {
            b.push((l & 0xff) as u8);
            l >>= 8;
        }
        b.reverse();
        out.push(0x80 | b.len() as u8);
        out.extend_from_slice(&b);
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    der_len(content.len(), &mut v);
    v.extend_from_slice(content);
    v
}

fn seq(content: &[u8]) -> Vec<u8> {
    tlv(der::SEQUENCE, content)
}

/// Rejects trailing bytes.
fn explicit_extensions(explicit: &[u8]) -> Result<Vec<Extension<'_>>, TlsError> {
    let mut outer = Der::new(explicit);
    let list = outer.expect(der::SEQUENCE)?;
    if !outer.is_empty() {
        return Err(TlsError::BadCert);
    }
    extensions(list)
}

/// The issuer name hash and key hash identify the certificate.
pub fn build_ocsp_request(leaf: &X509, issuer: &X509) -> Vec<u8> {
    let name_hash = sha1(&issuer.subject_raw);
    let key_hash = sha1(&issuer.public_key);

    let mut alg_inner = tlv(der::OID, OID_SHA1);
    alg_inner.extend_from_slice(&[0x05, 0x00]);
    let alg = seq(&alg_inner);

    let mut cert_id = alg;
    cert_id.extend(tlv(der::OCTET_STRING, &name_hash));
    cert_id.extend(tlv(der::OCTET_STRING, &key_hash));
    cert_id.extend(tlv(der::INTEGER, &leaf.serial));
    let cert_id = seq(&cert_id);

    let request = seq(&cert_id);
    let request_list = seq(&request);
    let tbs_request = seq(&request_list);
    seq(&tbs_request)
}

/// The signer must be the issuer or a certificate the issuer authorized for OCSP signing; otherwise
/// anyone could make up a revocation status.
pub fn check_ocsp_response(
    der_bytes: &[u8],
    issuer: &X509,
    leaf_serial: &[u8],
    now: i64,
) -> Result<RevocationStatus, TlsError> {
    let mut top = Der::new(der_bytes);
    let body = top.expect(der::SEQUENCE)?;
    if !top.is_empty() {
        return Err(TlsError::BadCert);
    }
    let mut r = Der::new(body);

    let status = r.next()?;
    if status.tag != 0x0a || status.value != [0] {
        return Err(TlsError::BadCert);
    }

    let rb = r.next()?;
    if rb.tag != der::context(0) || !r.is_empty() {
        return Err(TlsError::BadCert);
    }
    let mut rbd = Der::new(rb.value);
    let inner = rbd.expect(der::SEQUENCE)?;
    if !rbd.is_empty() {
        return Err(TlsError::BadCert);
    }
    let mut ib = Der::new(inner);
    let resp_type = ib.expect(der::OID)?;
    if resp_type != OID_OCSP_BASIC {
        return Err(TlsError::BadCert);
    }
    let basic_der = ib.expect(der::OCTET_STRING)?;
    if !ib.is_empty() {
        return Err(TlsError::BadCert);
    }
    parse_basic_ocsp(basic_der, issuer, leaf_serial, now)
}

#[derive(Debug)]
enum ResponderId {
    ByName(Vec<u8>),
    ByKey(Vec<u8>),
}

fn parse_basic_ocsp(
    der_bytes: &[u8],
    issuer: &X509,
    leaf_serial: &[u8],
    now: i64,
) -> Result<RevocationStatus, TlsError> {
    let mut top = Der::new(der_bytes);
    let body = top.expect(der::SEQUENCE)?;
    if !top.is_empty() {
        return Err(TlsError::BadCert);
    }
    let mut b = Der::new(body);

    let (tbs_raw, tbs_tlv) = b.next_raw()?;
    if tbs_tlv.tag != der::SEQUENCE {
        return Err(TlsError::BadCert);
    }

    let sig_alg = b.expect(der::SEQUENCE)?;
    let scheme = scheme_from_sig_algid(sig_alg)?;
    if scheme == 0 {
        return Err(TlsError::BadCert);
    }
    let signature = bit_string_bytes(b.expect(der::BIT_STRING)?)?.to_vec();

    let mut responder_certs: Vec<X509> = Vec::new();
    if !b.is_empty() {
        let c = b.next()?;
        if c.tag != der::context(0) {
            return Err(TlsError::BadCert);
        }
        let mut cd = Der::new(c.value);
        let certs_seq = cd.expect(der::SEQUENCE)?;
        if !cd.is_empty() {
            return Err(TlsError::BadCert);
        }
        let mut cs = Der::new(certs_seq);
        while !cs.is_empty() {
            let (raw, t) = cs.next_raw()?;
            if t.tag != der::SEQUENCE {
                return Err(TlsError::BadCert);
            }
            responder_certs.push(X509::parse(raw)?);
        }
    }
    if !b.is_empty() {
        return Err(TlsError::BadCert);
    }

    let (responder_id, produced_at, status) =
        parse_response_data(tbs_tlv.value, issuer, leaf_serial, now)?;

    let issuer_signed = responder_id_matches(&responder_id, issuer)
        && issuer.allows_digital_signature()
        && issuer.verify_signature(scheme, tbs_raw, &signature).is_ok();
    let delegated_signed = responder_certs.iter().any(|responder| {
        responder.issuer_raw == issuer.subject_raw
            && responder.allows_ocsp_signing()
            && responder.allows_digital_signature()
            && responder.valid_at(now)
            && responder.verify_signed_by(issuer).is_ok()
            && responder_id_matches(&responder_id, responder)
            && responder
                .verify_signature(scheme, tbs_raw, &signature)
                .is_ok()
    });
    if !issuer_signed && !delegated_signed {
        return Err(TlsError::BadSignature);
    }

    if produced_at > now + OCSP_CLOCK_SKEW_SECS {
        return Ok(RevocationStatus::Unknown);
    }
    Ok(status)
}

/// No response extension is interpreted, so a response with a critical one is not used: critical
/// means a party that does not know the extension must not trust the response.
fn parse_response_data(
    tbs: &[u8],
    issuer: &X509,
    leaf_serial: &[u8],
    now: i64,
) -> Result<(ResponderId, i64, RevocationStatus), TlsError> {
    let mut d = Der::new(tbs);
    let mut responder = d.next()?;

    if responder.tag == der::context(0) {
        let version = Der::new(responder.value).expect(der::INTEGER)?;
        if version.iter().any(|&byte| byte != 0) {
            return Err(TlsError::BadCert);
        }
        responder = d.next()?;
    }
    let responder_id = parse_responder_id(responder)?;

    let produced_at = parse_time(d.next()?)?;
    let responses = d.expect(der::SEQUENCE)?;

    if !d.is_empty() {
        let response_extensions = d.next()?;
        if response_extensions.tag != der::context(1)
            || !d.is_empty()
            || explicit_extensions(response_extensions.value)?
                .iter()
                .any(|ext| ext.critical)
        {
            return Err(TlsError::BadCert);
        }
    }

    let mut rs = Der::new(responses);
    while !rs.is_empty() {
        let single = rs.expect(der::SEQUENCE)?;
        if let Some(status) = parse_single_response(single, issuer, leaf_serial, produced_at, now)?
        {
            return Ok((responder_id, produced_at, status));
        }
    }
    Ok((responder_id, produced_at, RevocationStatus::Unknown))
}

fn parse_responder_id(value: Tlv<'_>) -> Result<ResponderId, TlsError> {
    match value.tag {
        t if t == der::context(1) => {
            let mut name = Der::new(value.value);
            let (raw, tlv) = name.next_raw()?;
            if tlv.tag != der::SEQUENCE || !name.is_empty() {
                return Err(TlsError::BadCert);
            }
            Ok(ResponderId::ByName(raw.to_vec()))
        }

        0x82 => Ok(ResponderId::ByKey(value.value.to_vec())),
        t if t == der::context(2) => {
            let mut key = Der::new(value.value);
            let bytes = key.expect(der::OCTET_STRING)?;
            if !key.is_empty() {
                return Err(TlsError::BadCert);
            }
            Ok(ResponderId::ByKey(bytes.to_vec()))
        }
        _ => Err(TlsError::BadCert),
    }
}

fn responder_id_matches(id: &ResponderId, certificate: &X509) -> bool {
    match id {
        ResponderId::ByName(name) => name == &certificate.subject_raw,
        ResponderId::ByKey(key_hash) => {
            let expected = sha1(&certificate.public_key);
            key_hash.as_slice() == expected.as_slice()
        }
    }
}

/// Also checks the time window. A critical extension on the single response for this certificate
/// makes the response unused, since single extensions are not interpreted either.
fn parse_single_response(
    single: &[u8],
    issuer: &X509,
    leaf_serial: &[u8],
    produced_at: i64,
    now: i64,
) -> Result<Option<RevocationStatus>, TlsError> {
    let mut s = Der::new(single);

    let cert_id = s.expect(der::SEQUENCE)?;
    let mut ci = Der::new(cert_id);
    let alg = ci.expect(der::SEQUENCE)?;
    if !ocsp_hash_algorithm_is_sha1(alg)? {
        return Err(TlsError::BadCert);
    }
    let name_hash = ci.expect(der::OCTET_STRING)?;
    let key_hash = ci.expect(der::OCTET_STRING)?;
    let serial = ci.expect(der::INTEGER)?;
    if !ci.is_empty() {
        return Err(TlsError::BadCert);
    }
    let expected_name_hash = sha1(&issuer.subject_raw);
    let expected_key_hash = sha1(&issuer.public_key);
    if name_hash != expected_name_hash.as_slice()
        || key_hash != expected_key_hash.as_slice()
        || normalize_positive_integer(serial) != normalize_positive_integer(leaf_serial)
    {
        return Ok(None);
    }

    let cs = s.next()?;
    let status = match cs.tag {
        0x80 if cs.value.is_empty() => RevocationStatus::Good,
        0xA1 => {
            let mut revoked = Der::new(cs.value);
            let revocation_time = parse_time(revoked.next()?)?;
            if !revoked.is_empty() {
                let reason = revoked.next()?;
                if reason.tag != der::context(0) || !revoked.is_empty() {
                    return Err(TlsError::BadCert);
                }
                let mut value = Der::new(reason.value);
                let code = value.next()?;
                if code.tag != 0x0a || code.value.len() != 1 || !value.is_empty() {
                    return Err(TlsError::BadCert);
                }
            }
            if revocation_time > now + OCSP_CLOCK_SKEW_SECS {
                RevocationStatus::Unknown
            } else {
                RevocationStatus::Revoked
            }
        }
        0x82 if cs.value.is_empty() => RevocationStatus::Unknown,
        _ => return Err(TlsError::BadCert),
    };

    let this = parse_time(s.next()?)?;
    let mut next: Option<i64> = None;
    let mut seen_extensions = false;
    while !s.is_empty() {
        let field = s.next()?;
        if field.tag == der::context(0) && next.is_none() && !seen_extensions {
            let mut inner = Der::new(field.value);
            next = Some(parse_time(inner.next()?)?);
            if !inner.is_empty() {
                return Err(TlsError::BadCert);
            }
        } else if field.tag == der::context(1) && !seen_extensions {
            if explicit_extensions(field.value)?
                .iter()
                .any(|ext| ext.critical)
            {
                return Err(TlsError::BadCert);
            }
            seen_extensions = true;
        } else {
            return Err(TlsError::BadCert);
        }
    }

    if this > now + OCSP_CLOCK_SKEW_SECS
        || produced_at + OCSP_CLOCK_SKEW_SECS < this
        || next.is_some_and(|next_update| next_update < this)
    {
        return Ok(Some(RevocationStatus::Unknown));
    }

    if status == RevocationStatus::Revoked {
        return Ok(Some(RevocationStatus::Revoked));
    }

    match next {
        Some(next_update) if next_update < now - OCSP_CLOCK_SKEW_SECS => {
            Ok(Some(RevocationStatus::Unknown))
        }
        None if this < now - OCSP_MAX_AGE_WITHOUT_NEXT_UPDATE_SECS
            || produced_at < now - OCSP_MAX_AGE_WITHOUT_NEXT_UPDATE_SECS =>
        {
            Ok(Some(RevocationStatus::Unknown))
        }
        _ => Ok(Some(status)),
    }
}

/// Another hash would not match the request this side built.
fn ocsp_hash_algorithm_is_sha1(algid: &[u8]) -> Result<bool, TlsError> {
    let mut alg = Der::new(algid);
    if alg.expect(der::OID)? != OID_SHA1 {
        return Ok(false);
    }
    if !alg.is_empty() {
        let null = alg.next()?;
        if null.tag != 0x05 || !null.value.is_empty() || !alg.is_empty() {
            return Err(TlsError::BadCert);
        }
    }
    Ok(true)
}

/// Strips leading zeros for serial comparison.
fn normalize_positive_integer(value: &[u8]) -> &[u8] {
    let mut offset = 0;
    while offset + 1 < value.len() && value[offset] == 0 {
        offset += 1;
    }
    &value[offset..]
}

/// A CRL whose signature has been verified.
pub struct Crl {
    revoked: Vec<(Vec<u8>, i64)>,
    pub this_update: i64,
    pub next_update: Option<i64>,
    scope: CrlScope,
}

#[derive(Default)]
/// The scope set by the issuing distribution point extension; without it, every certificate of the
/// issuer. An issuer can split its CRL into shards, each stating its own scope with this extension.
struct CrlScope {
    /// This shard's URIs. When present, one of the distribution point addresses in the certificate
    /// must be among them.
    distribution_point: Option<Vec<String>>,
    only_user_certs: bool,
    only_ca_certs: bool,
}

impl CrlScope {
    /// Distribution points given as a relative name, reason-only lists, indirect lists carrying
    /// another issuer's certificates, and attribute certificate lists are not interpreted, so they
    /// are rejected.
    fn parse(value: &[u8]) -> Result<CrlScope, TlsError> {
        let mut outer = Der::new(value);
        let body = outer.expect(der::SEQUENCE)?;
        if !outer.is_empty() {
            return Err(TlsError::BadCert);
        }
        let mut scope = CrlScope::default();
        let mut fields = Der::new(body);
        let mut previous: Option<u8> = None;
        while !fields.is_empty() {
            let field = fields.next()?;
            let number = field.tag & 0x1f;
            if previous.is_some_and(|before| number <= before) {
                return Err(TlsError::BadCert);
            }
            previous = Some(number);
            match field.tag {
                0xA0 => scope.distribution_point = Some(Self::full_name_uris(field.value)?),
                0x81 => scope.only_user_certs = der::boolean_value(field.value)?,
                0x82 => scope.only_ca_certs = der::boolean_value(field.value)?,
                _ => return Err(TlsError::BadCert),
            }
        }
        if scope.only_user_certs && scope.only_ca_certs {
            return Err(TlsError::BadCert);
        }
        Ok(scope)
    }

    /// Rejects distribution points given as a relative name.
    fn full_name_uris(explicit: &[u8]) -> Result<Vec<String>, TlsError> {
        let mut name = Der::new(explicit);
        let full_name = name.expect(der::context(0))?;
        if !name.is_empty() {
            return Err(TlsError::BadCert);
        }
        let mut names = Der::new(full_name);
        let mut uris = Vec::new();
        while !names.is_empty() {
            let general_name = names.next()?;
            if general_name.tag == 0x86 {
                let uri = std::str::from_utf8(general_name.value).map_err(|_| TlsError::BadCert)?;
                uris.push(uri.to_string());
            }
        }
        Ok(uris)
    }

    fn covers(&self, cert: &X509) -> bool {
        if (self.only_user_certs && cert.is_ca) || (self.only_ca_certs && !cert.is_ca) {
            return false;
        }
        self.distribution_point
            .as_ref()
            .is_none_or(|uris| cert.crl_urls.iter().any(|url| uris.contains(url)))
    }
}

impl Crl {
    /// Verifies the issuer's signature.
    pub fn parse(der_bytes: &[u8], issuer: &X509) -> Result<Crl, TlsError> {
        let mut top = Der::new(der_bytes);
        let body = top.expect(der::SEQUENCE)?;
        if !top.is_empty() {
            return Err(TlsError::BadCert);
        }
        let mut c = Der::new(body);
        let (tbs_raw, tbs_tlv) = c.next_raw()?;
        if tbs_tlv.tag != der::SEQUENCE {
            return Err(TlsError::BadCert);
        }
        let sig_alg = c.expect(der::SEQUENCE)?;
        let scheme = scheme_from_sig_algid(sig_alg)?;
        if scheme == 0 {
            return Err(TlsError::BadCert);
        }
        let signature = bit_string_bytes(c.expect(der::BIT_STRING)?)?.to_vec();
        if !c.is_empty() {
            return Err(TlsError::BadCert);
        }
        issuer.verify_signature(scheme, tbs_raw, &signature)?;

        Self::parse_tbs(tbs_tlv.value, sig_alg, issuer)
    }

    /// The outer and inner algorithms must match.
    fn parse_tbs(tbs: &[u8], outer_sig_alg: &[u8], issuer: &X509) -> Result<Crl, TlsError> {
        let mut d = Der::new(tbs);
        let mut cur = d.next()?;

        if cur.tag == der::INTEGER {
            if cur.value != [1] {
                return Err(TlsError::BadCert);
            }
            cur = d.next()?;
        }

        if cur.tag != der::SEQUENCE || cur.value != outer_sig_alg {
            return Err(TlsError::BadCert);
        }

        let (crl_issuer_raw, crl_issuer) = d.next_raw()?;
        if crl_issuer.tag != der::SEQUENCE || crl_issuer_raw != issuer.subject_raw.as_slice() {
            return Err(TlsError::BadCert);
        }

        let this_update = parse_time(d.next()?)?;

        let mut next_update = None;
        let mut revoked = Vec::new();
        let mut scope = CrlScope::default();
        let mut seen_revoked = false;
        while !d.is_empty() {
            let field = d.next()?;
            match field.tag {
                0x17 | 0x18 if next_update.is_none() && !seen_revoked => {
                    next_update = Some(parse_time(field)?);
                }
                der::SEQUENCE if !seen_revoked => {
                    Self::collect_revoked(field.value, &mut revoked)?;
                    seen_revoked = true;
                }
                t if t == der::context(0) && d.is_empty() => {
                    scope = Self::read_extensions(field.value)?;
                }
                _ => return Err(TlsError::BadCert),
            }
        }
        if next_update.is_some_and(|next| next < this_update) {
            return Err(TlsError::BadCert);
        }
        Ok(Crl {
            revoked,
            this_update,
            next_update,
            scope,
        })
    }

    /// A critical extension that cannot be interpreted makes the CRL unused. The delta CRL
    /// indicator and the issuing distribution point are handled whether critical or not: reading a
    /// delta CRL as a full one misses revocations listed only in the base CRL, and ignoring the
    /// distribution point treats certificates outside its scope as good.
    fn read_extensions(explicit: &[u8]) -> Result<CrlScope, TlsError> {
        let mut scope = CrlScope::default();
        for ext in explicit_extensions(explicit)? {
            if ext.oid == OID_DELTA_CRL_INDICATOR {
                return Err(TlsError::BadCert);
            } else if ext.oid == OID_ISSUING_DISTRIBUTION_POINT {
                scope = CrlScope::parse(ext.value)?;
            } else if ext.critical {
                return Err(TlsError::BadCert);
            }
        }
        Ok(scope)
    }

    /// A critical entry extension that cannot be interpreted makes the whole CRL unused. Other
    /// extensions, such as reason codes and invalidity dates, do not change whether a certificate
    /// is revoked, so they are skipped.
    fn collect_revoked(seq_of: &[u8], out: &mut Vec<(Vec<u8>, i64)>) -> Result<(), TlsError> {
        let mut entries = Der::new(seq_of);
        while !entries.is_empty() {
            let entry = entries.next()?;
            if entry.tag != der::SEQUENCE {
                return Err(TlsError::BadCert);
            }
            let mut fields = Der::new(entry.value);
            let serial = fields.expect(der::INTEGER)?.to_vec();
            let revoked_at = parse_time(fields.next()?)?;
            if !fields.is_empty() {
                let entry_extensions = fields.expect(der::SEQUENCE)?;
                if !fields.is_empty()
                    || extensions(entry_extensions)?.iter().any(|ext| ext.critical)
                {
                    return Err(TlsError::BadCert);
                }
            }
            out.push((serial, revoked_at));
        }
        Ok(())
    }

    /// Another shard from the same issuer has a valid signature too. Without the scope check, a
    /// shard that does not list the certificate could be presented to hide its revocation.
    pub fn covers(&self, cert: &X509) -> bool {
        self.scope.covers(cert)
    }

    /// Unknown when the CRL does not cover the certificate or is itself stale. Serials are compared
    /// with leading zeros stripped, as in OCSP.
    pub fn status(&self, cert: &X509, now: i64) -> RevocationStatus {
        if !self.covers(cert) {
            return RevocationStatus::Unknown;
        }
        let serial = normalize_positive_integer(&cert.serial);
        if let Some((_, revoked_at)) = self
            .revoked
            .iter()
            .find(|(value, _)| normalize_positive_integer(value) == serial)
        {
            return if *revoked_at <= now + OCSP_CLOCK_SKEW_SECS {
                RevocationStatus::Revoked
            } else {
                RevocationStatus::Unknown
            };
        }

        if self.this_update > now + 300 {
            return RevocationStatus::Unknown;
        }
        match self.next_update {
            Some(nu) if nu < now - 300 => RevocationStatus::Unknown,

            None => RevocationStatus::Unknown,
            _ => RevocationStatus::Good,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    fn gen_ca_and_leaf() -> (X509, X509, SigningKey, Vec<u8>) {
        gen_ca_and_leaf_with_name("ca.test")
    }

    fn gen_ca_and_leaf_with_name(ca_name: &str) -> (X509, X509, SigningKey, Vec<u8>) {
        let mut p = rcgen::CertificateParams::new(vec![ca_name.into()]).unwrap();
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name
            .push(rcgen::DnType::CommonName, ca_name);
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_kp = rcgen::KeyPair::generate().unwrap();
        let ca = p.self_signed(&ca_kp).unwrap();
        let ca_der = ca.der().to_vec();
        let ca_x = X509::parse(&ca_der).unwrap();

        let leaf_p = rcgen::CertificateParams::new(vec!["leaf.test".into()]).unwrap();
        let leaf_kp = rcgen::KeyPair::generate().unwrap();
        let leaf = leaf_p.signed_by(&leaf_kp, &ca, &ca_kp).unwrap();
        let leaf_der = leaf.der().to_vec();
        let leaf_x = X509::parse(&leaf_der).unwrap();

        let pkcs8 = ca_kp.serialize_der();
        use p256::pkcs8::DecodePrivateKey;
        let sk = p256::SecretKey::from_pkcs8_der(&pkcs8).unwrap();
        let signing = SigningKey::from(sk);
        (ca_x, leaf_x, signing, leaf_der)
    }

    fn ecdsa_sha256_algid() -> Vec<u8> {
        seq(&tlv(
            der::OID,
            &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
        ))
    }

    fn sign_tbs(signing: &SigningKey, tbs: &[u8]) -> Vec<u8> {
        let sig: Signature = signing.sign(tbs);
        let mut bits = vec![0x00];
        bits.extend_from_slice(sig.to_der().as_bytes());
        tlv(der::BIT_STRING, &bits)
    }

    #[test]
    fn ocsp_request_has_certid_with_serial() {
        let (ca, leaf, _sk, _) = gen_ca_and_leaf();
        let req = build_ocsp_request(&leaf, &ca);

        assert!(window_contains(&req, &leaf.serial));

        assert_eq!(req[0], der::SEQUENCE);
    }

    fn window_contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    fn build_basic_ocsp(
        signing: &SigningKey,
        ca: &X509,
        leaf: &X509,
        status_tag: u8,
        now: i64,
    ) -> Vec<u8> {
        build_basic_ocsp_custom(
            signing,
            ca,
            leaf,
            status_tag,
            now,
            sha1(&ca.subject_raw),
            sha1(&ca.public_key),
            leaf.serial.clone(),
            now - 600,
            Some(now + 3600),
            ca.subject_raw.clone(),
            &[],
            &[],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_basic_ocsp_custom(
        signing: &SigningKey,
        _ca: &X509,
        _leaf: &X509,
        status_tag: u8,
        produced_at: i64,
        name_hash: Vec<u8>,
        key_hash: Vec<u8>,
        serial: Vec<u8>,
        this_update_at: i64,
        next_update_at: Option<i64>,
        responder_name: Vec<u8>,
        single_extensions: &[Vec<u8>],
        response_extensions: &[Vec<u8>],
    ) -> Vec<u8> {
        let alg = seq(&{
            let mut a = tlv(der::OID, OID_SHA1);
            a.extend_from_slice(&[0x05, 0x00]);
            a
        });
        let mut cert_id = alg;
        cert_id.extend(tlv(der::OCTET_STRING, &name_hash));
        cert_id.extend(tlv(der::OCTET_STRING, &key_hash));
        cert_id.extend(tlv(der::INTEGER, &serial));
        let cert_id = seq(&cert_id);

        let cert_status = if status_tag == 0 {
            vec![0x80, 0x00]
        } else {
            let t = gen_time(this_update_at);
            tlv(0xA1, &t)
        };

        let mut single = cert_id;
        single.extend(cert_status);
        single.extend(gen_time(this_update_at));
        if let Some(next_update_at) = next_update_at {
            single.extend(tlv(der::context(0), &gen_time(next_update_at)));
        }
        if !single_extensions.is_empty() {
            single.extend(tlv(der::context(1), &seq(&single_extensions.concat())));
        }
        let single = seq(&single);
        let responses = seq(&single);

        let responder_id = tlv(der::context(1), &responder_name);
        let mut rd = responder_id;
        rd.extend(gen_time(produced_at));
        rd.extend(responses);
        if !response_extensions.is_empty() {
            rd.extend(tlv(der::context(1), &seq(&response_extensions.concat())));
        }
        let tbs = seq(&rd);

        let sig = sign_tbs(signing, &tbs);
        let mut basic = tbs;
        basic.extend(ecdsa_sha256_algid());
        basic.extend(sig);
        seq(&basic)
    }

    fn gen_time(unix: i64) -> Vec<u8> {
        let days = unix.div_euclid(86400);
        let secs = unix.rem_euclid(86400);
        let (y, m, d) = crate::x509::civil_from_days(days);
        let h = secs / 3600;
        let mi = (secs % 3600) / 60;
        let s = secs % 60;
        let txt = format!("{y:04}{m:02}{d:02}{h:02}{mi:02}{s:02}Z");
        tlv(0x18, txt.as_bytes())
    }

    #[test]
    fn ocsp_good_and_revoked_verify() {
        let (ca, leaf, sk, _) = gen_ca_and_leaf();
        let now = 1_700_000_000i64;

        let good = wrap_ocsp(&build_basic_ocsp(&sk, &ca, &leaf, 0, now));
        assert_eq!(
            check_ocsp_response(&good, &ca, &leaf.serial, now).unwrap(),
            RevocationStatus::Good
        );

        let revoked = wrap_ocsp(&build_basic_ocsp(&sk, &ca, &leaf, 1, now));
        assert_eq!(
            check_ocsp_response(&revoked, &ca, &leaf.serial, now).unwrap(),
            RevocationStatus::Revoked
        );
    }

    #[test]
    fn ocsp_bad_signature_rejected() {
        let (ca, leaf, _sk, _) = gen_ca_and_leaf();
        let (_ca2, _l2, other_sk, _) = gen_ca_and_leaf();
        let now = 1_700_000_000i64;

        let forged = wrap_ocsp(&build_basic_ocsp(&other_sk, &ca, &leaf, 0, now));
        assert!(check_ocsp_response(&forged, &ca, &leaf.serial, now).is_err());
    }

    #[test]
    fn ocsp_rejects_wrong_certid_issuer_hashes() {
        let (ca, leaf, sk, _) = gen_ca_and_leaf();
        let now = 1_700_000_000i64;
        let response = build_basic_ocsp_custom(
            &sk,
            &ca,
            &leaf,
            0,
            now,
            vec![0x55; 20],
            sha1(&ca.public_key),
            leaf.serial.clone(),
            now - 60,
            Some(now + 3600),
            ca.subject_raw.clone(),
            &[],
            &[],
        );
        assert_eq!(
            check_ocsp_response(&wrap_ocsp(&response), &ca, &leaf.serial, now).unwrap(),
            RevocationStatus::Unknown
        );
    }

    #[test]
    fn ocsp_good_without_next_update_expires() {
        let (ca, leaf, sk, _) = gen_ca_and_leaf();
        let now = 1_700_000_000i64;
        let response = build_basic_ocsp_custom(
            &sk,
            &ca,
            &leaf,
            0,
            now - OCSP_MAX_AGE_WITHOUT_NEXT_UPDATE_SECS - 1,
            sha1(&ca.subject_raw),
            sha1(&ca.public_key),
            leaf.serial.clone(),
            now - OCSP_MAX_AGE_WITHOUT_NEXT_UPDATE_SECS - 1,
            None,
            ca.subject_raw.clone(),
            &[],
            &[],
        );
        assert_eq!(
            check_ocsp_response(&wrap_ocsp(&response), &ca, &leaf.serial, now).unwrap(),
            RevocationStatus::Unknown
        );
    }

    #[test]
    fn ocsp_responder_id_must_match_signer() {
        let (ca, leaf, sk, _) = gen_ca_and_leaf();
        let (other_ca, _, _, _) = gen_ca_and_leaf_with_name("other-ca.test");
        let now = 1_700_000_000i64;
        let response = build_basic_ocsp_custom(
            &sk,
            &ca,
            &leaf,
            0,
            now,
            sha1(&ca.subject_raw),
            sha1(&ca.public_key),
            leaf.serial.clone(),
            now - 60,
            Some(now + 3600),
            other_ca.subject_raw,
            &[],
            &[],
        );
        assert!(check_ocsp_response(&wrap_ocsp(&response), &ca, &leaf.serial, now).is_err());
    }

    #[test]
    /// Non-critical extensions are skipped.
    fn ocsp_critical_extensions_are_rejected() {
        let (ca, leaf, sk, _) = gen_ca_and_leaf();
        let now = 1_700_000_000i64;
        let respond = |single: &[Vec<u8>], response: &[Vec<u8>]| {
            let basic = build_basic_ocsp_custom(
                &sk,
                &ca,
                &leaf,
                0,
                now,
                sha1(&ca.subject_raw),
                sha1(&ca.public_key),
                leaf.serial.clone(),
                now - 600,
                Some(now + 3600),
                ca.subject_raw.clone(),
                single,
                response,
            );
            check_ocsp_response(&wrap_ocsp(&basic), &ca, &leaf.serial, now)
        };
        let nonce_oid: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];
        let nonce = ext(nonce_oid, false, &tlv(der::OCTET_STRING, &[7; 16]));
        let critical = ext(&[0x2a, 0x03, 0x04], true, &[0x05, 0x00]);

        assert_eq!(
            respond(std::slice::from_ref(&nonce), std::slice::from_ref(&nonce)),
            Ok(RevocationStatus::Good),
            "필수가 아닌 확장은 넘겨야 한다"
        );
        for (case, single, response) in [
            ("응답 확장", vec![], vec![critical.clone()]),
            ("단건 확장", vec![critical.clone()], vec![]),
            (
                "두 번 나온 확장",
                vec![],
                vec![nonce.clone(), nonce.clone()],
            ),
        ] {
            assert_eq!(
                respond(&single, &response),
                Err(TlsError::BadCert),
                "{case}: 거부해야 한다"
            );
        }
    }

    #[test]
    fn explicit_extensions_reject_trailing_bytes() {
        let list = seq(&ext(&[0x2a, 0x03, 0x04], false, &[0x05, 0x00]));
        assert_eq!(explicit_extensions(&list).map(|list| list.len()), Ok(1));
        let mut trailing = list;
        trailing.push(0);
        assert_eq!(
            explicit_extensions(&trailing).map(|list| list.len()),
            Err(TlsError::BadCert),
            "SEQUENCE 뒤에 남은 바이트는 거부해야 한다"
        );
    }

    fn wrap_ocsp(basic: &[u8]) -> Vec<u8> {
        let status = vec![0x0a, 0x01, 0x00];
        let rt = tlv(der::OID, OID_OCSP_BASIC);
        let mut rb_inner = rt;
        rb_inner.extend(tlv(der::OCTET_STRING, basic));
        let response_bytes = tlv(der::context(0), &seq(&rb_inner));
        let mut body = status;
        body.extend(response_bytes);
        seq(&body)
    }

    fn sign_crl(signing: &SigningKey, tbs_fields: &[u8]) -> Vec<u8> {
        let tbs = seq(tbs_fields);
        let sig = sign_tbs(signing, &tbs);
        let mut crl = tbs;
        crl.extend(ecdsa_sha256_algid());
        crl.extend(sig);
        seq(&crl)
    }

    fn build_crl(
        signing: &SigningKey,
        issuer: &X509,
        revoked_serials: &[&[u8]],
        now: i64,
    ) -> Vec<u8> {
        let mut revoked_list = Vec::new();
        for s in revoked_serials {
            let mut entry = tlv(der::INTEGER, s);
            entry.extend(gen_time(now - 3600));
            revoked_list.extend(seq(&entry));
        }
        let mut tbs = ecdsa_sha256_algid();
        tbs.extend_from_slice(&issuer.subject_raw);
        tbs.extend(gen_time(now - 600));
        tbs.extend(gen_time(now + 86400));
        if !revoked_list.is_empty() {
            tbs.extend(seq(&revoked_list));
        }
        sign_crl(signing, &tbs)
    }

    fn ext(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
        let mut body = tlv(der::OID, oid);
        if critical {
            body.extend_from_slice(&[der::BOOLEAN, 0x01, 0xFF]);
        }
        body.extend(tlv(der::OCTET_STRING, value));
        seq(&body)
    }

    fn build_crl_v2(
        signing: &SigningKey,
        issuer: &X509,
        serial: &[u8],
        entry_extensions: &[Vec<u8>],
        crl_extensions: &[Vec<u8>],
        now: i64,
    ) -> Vec<u8> {
        let mut entry = tlv(der::INTEGER, serial);
        entry.extend(gen_time(now - 3600));
        if !entry_extensions.is_empty() {
            entry.extend(seq(&entry_extensions.concat()));
        }
        let mut tbs = tlv(der::INTEGER, &[1]);
        tbs.extend(ecdsa_sha256_algid());
        tbs.extend_from_slice(&issuer.subject_raw);
        tbs.extend(gen_time(now - 600));
        tbs.extend(gen_time(now + 86400));
        tbs.extend(seq(&seq(&entry)));
        if !crl_extensions.is_empty() {
            tbs.extend(tlv(der::context(0), &seq(&crl_extensions.concat())));
        }
        sign_crl(signing, &tbs)
    }

    #[test]
    fn crl_detects_revoked_and_good() {
        let (ca, leaf, sk, _) = gen_ca_and_leaf();
        let now = 1_700_000_000i64;
        let crl_der = build_crl(&sk, &ca, &[&leaf.serial], now);
        let crl = Crl::parse(&crl_der, &ca).unwrap();
        assert_eq!(crl.status(&leaf, now), RevocationStatus::Revoked);
        let mut other = leaf.clone();
        other.serial = vec![0x99, 0x88];
        assert_eq!(crl.status(&other, now), RevocationStatus::Good);
    }

    #[test]
    fn crl_bad_signature_rejected() {
        let (ca, leaf, _sk, _) = gen_ca_and_leaf();
        let (_c2, _l2, other, _) = gen_ca_and_leaf();
        let now = 1_700_000_000i64;
        let crl_der = build_crl(&other, &ca, &[&leaf.serial], now);
        assert!(Crl::parse(&crl_der, &ca).is_err());
    }

    /// Inside the update window of the CRLs rcgen builds.
    const RCGEN_CRL_NOW: i64 = 1_705_276_800;

    /// rcgen needs the original certificate and key to sign a CRL.
    struct CrlIssuer {
        cert: rcgen::Certificate,
        key: rcgen::KeyPair,
        x509: X509,
    }

    fn crl_issuer() -> CrlIssuer {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "crl-ca.test");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let x509 = X509::parse(cert.der()).unwrap();
        CrlIssuer { cert, key, x509 }
    }

    fn issued_with_crl_url(issuer: &CrlIssuer, serial: u64, crl_url: &str, is_ca: bool) -> X509 {
        let mut params = rcgen::CertificateParams::new(vec!["leaf.test".to_string()]).unwrap();
        params.serial_number = Some(rcgen::SerialNumber::from(serial));
        params.crl_distribution_points = vec![rcgen::CrlDistributionPoint {
            uris: vec![crl_url.to_string()],
        }];
        if is_ca {
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        }
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &issuer.cert, &issuer.key).unwrap();
        let x509 = X509::parse(cert.der()).unwrap();
        assert_eq!(x509.crl_urls, [crl_url]);
        x509
    }

    fn idp(url: &str, scope: Option<rcgen::CrlScope>) -> rcgen::CrlIssuingDistributionPoint {
        rcgen::CrlIssuingDistributionPoint {
            distribution_point: rcgen::CrlDistributionPoint {
                uris: vec![url.to_string()],
            },
            scope,
        }
    }

    /// Always carries an authority key identifier and a CRL number, and a reason code and
    /// invalidity date per entry.
    fn rcgen_crl(
        issuer: &CrlIssuer,
        revoked: &[u64],
        distribution_point: Option<rcgen::CrlIssuingDistributionPoint>,
    ) -> Vec<u8> {
        let params = rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2024, 1, 1),
            next_update: rcgen::date_time_ymd(2024, 2, 1),
            crl_number: rcgen::SerialNumber::from(782u64),
            issuing_distribution_point: distribution_point,
            revoked_certs: revoked
                .iter()
                .map(|&serial| rcgen::RevokedCertParams {
                    serial_number: rcgen::SerialNumber::from(serial),
                    revocation_time: rcgen::date_time_ymd(2024, 1, 1),
                    reason_code: Some(rcgen::RevocationReason::KeyCompromise),
                    invalidity_date: Some(rcgen::date_time_ymd(2023, 12, 31)),
                })
                .collect(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        params
            .signed_by(&issuer.cert, &issuer.key)
            .unwrap()
            .der()
            .to_vec()
    }

    #[test]
    /// With the extensions public CAs attach.
    fn crl_with_standard_extensions_is_read() {
        let issuer = crl_issuer();
        let url = "http://crl.test/7.crl";
        let revoked = issued_with_crl_url(&issuer, 0x1001, url, false);
        let good = issued_with_crl_url(&issuer, 0x1002, url, false);
        for distribution_point in [None, Some(idp(url, Some(rcgen::CrlScope::UserCertsOnly)))] {
            let with_idp = distribution_point.is_some();
            let der = rcgen_crl(&issuer, &[0x1001], distribution_point);
            let crl = Crl::parse(&der, &issuer.x509)
                .unwrap_or_else(|e| panic!("배포 지점 확장 {with_idp}: 목록을 읽어야 한다: {e}"));
            assert_eq!(
                crl.status(&revoked, RCGEN_CRL_NOW),
                RevocationStatus::Revoked
            );
            assert_eq!(crl.status(&good, RCGEN_CRL_NOW), RevocationStatus::Good);
        }
    }

    #[test]
    /// The shard does not list this certificate, so treating it as good would hide a revocation.
    fn crl_shard_for_another_distribution_point_does_not_vouch() {
        let issuer = crl_issuer();
        let leaf = issued_with_crl_url(&issuer, 0x2001, "http://crl.test/7.crl", false);
        let shard = |url: &str| {
            let der = rcgen_crl(&issuer, &[0x2002], Some(idp(url, None)));
            Crl::parse(&der, &issuer.x509).unwrap()
        };
        let other = shard("http://crl.test/8.crl");
        assert!(!other.covers(&leaf));
        assert_eq!(
            other.status(&leaf, RCGEN_CRL_NOW),
            RevocationStatus::Unknown
        );
        let own = shard("http://crl.test/7.crl");
        assert!(own.covers(&leaf));
        assert_eq!(own.status(&leaf, RCGEN_CRL_NOW), RevocationStatus::Good);
    }

    #[test]
    fn crl_scope_follows_certificate_kind() {
        let issuer = crl_issuer();
        let url = "http://crl.test/7.crl";
        let leaf = issued_with_crl_url(&issuer, 0x3001, url, false);
        let sub_ca = issued_with_crl_url(&issuer, 0x3002, url, true);
        let scoped = |scope| {
            let der = rcgen_crl(&issuer, &[], Some(idp(url, Some(scope))));
            Crl::parse(&der, &issuer.x509).unwrap()
        };

        let users = scoped(rcgen::CrlScope::UserCertsOnly);
        assert_eq!(users.status(&leaf, RCGEN_CRL_NOW), RevocationStatus::Good);
        assert_eq!(
            users.status(&sub_ca, RCGEN_CRL_NOW),
            RevocationStatus::Unknown
        );

        let cas = scoped(rcgen::CrlScope::CaCertsOnly);
        assert_eq!(cas.status(&leaf, RCGEN_CRL_NOW), RevocationStatus::Unknown);
        assert_eq!(cas.status(&sub_ca, RCGEN_CRL_NOW), RevocationStatus::Good);
    }

    #[test]
    /// Unknown critical extensions, the delta CRL indicator, and scope markers this side does not
    /// handle. Unknown non-critical extensions are skipped.
    fn crl_extensions_it_cannot_interpret_are_rejected() {
        let (ca, leaf, sk, _) = gen_ca_and_leaf();
        let now = 1_700_000_000i64;
        let unknown_oid: &[u8] = &[0x2a, 0x03, 0x04];
        let null = [0x05, 0x00];
        let delta = |critical| ext(OID_DELTA_CRL_INDICATOR, critical, &tlv(der::INTEGER, &[5]));
        let scope = |fields: &[u8]| ext(OID_ISSUING_DISTRIBUTION_POINT, true, &seq(fields));
        let full_name = tlv(
            der::context(0),
            &tlv(der::context(0), &tlv(0x86, b"http://crl.test/7.crl")),
        );
        let relative_name = tlv(
            der::context(0),
            &tlv(der::context(1), &tlv(der::SEQUENCE, &[])),
        );

        let rejected: Vec<(&str, Vec<Vec<u8>>, Vec<Vec<u8>>)> = vec![
            (
                "모르는 필수 목록 확장",
                vec![],
                vec![ext(unknown_oid, true, &null)],
            ),
            (
                "모르는 필수 항목 확장",
                vec![ext(unknown_oid, true, &null)],
                vec![],
            ),
            ("필수 표시가 붙은 델타 목록", vec![], vec![delta(true)]),
            ("필수 표시가 없는 델타 목록", vec![], vec![delta(false)]),
            ("간접 목록", vec![], vec![scope(&tlv(0x84, &[0xFF]))]),
            (
                "일부 사유만 싣는 목록",
                vec![],
                vec![scope(&tlv(0x83, &[0x07, 0x80]))],
            ),
            ("속성 인증서 목록", vec![], vec![scope(&tlv(0x85, &[0xFF]))]),
            (
                "상대 이름으로 적은 배포 지점",
                vec![],
                vec![scope(&relative_name)],
            ),
            (
                "리프와 CA를 함께 고른 범위",
                vec![],
                vec![scope(&[tlv(0x81, &[0xFF]), tlv(0x82, &[0xFF])].concat())],
            ),
            (
                "순서가 뒤바뀐 범위 필드",
                vec![],
                vec![scope(&[tlv(0x81, &[0xFF]), full_name.clone()].concat())],
            ),
            (
                "두 번 나온 목록 확장",
                vec![],
                vec![
                    ext(unknown_oid, false, &null),
                    ext(unknown_oid, false, &null),
                ],
            ),
        ];
        for (case, entry_extensions, crl_extensions) in rejected {
            let der = build_crl_v2(&sk, &ca, &[0x7f], &entry_extensions, &crl_extensions, now);
            assert!(Crl::parse(&der, &ca).is_err(), "{case}: 거부해야 한다");
        }

        let tolerated = build_crl_v2(
            &sk,
            &ca,
            &[0x7f],
            &[ext(unknown_oid, false, &null)],
            &[ext(unknown_oid, false, &null)],
            now,
        );
        let crl = Crl::parse(&tolerated, &ca).expect("필수가 아닌 모르는 확장은 넘겨야 한다");
        assert_eq!(crl.status(&leaf, now), RevocationStatus::Good);
    }

    #[test]
    /// The same number even when the certificate and the CRL write it differently.
    fn crl_serial_comparison_ignores_leading_zeros() {
        let (ca, leaf, sk, _) = gen_ca_and_leaf();
        let now = 1_700_000_000i64;
        let crl = Crl::parse(&build_crl(&sk, &ca, &[&[0x00, 0x01, 0x02]], now), &ca).unwrap();
        let mut padded = leaf.clone();
        padded.serial = vec![0x01, 0x02];
        assert_eq!(crl.status(&padded, now), RevocationStatus::Revoked);
    }
}
