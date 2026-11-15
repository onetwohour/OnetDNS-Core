//! Trust store and chain validation: the peer's chain is followed up to a root this side trusts,
//! checking signatures, validity, usage, name constraints, and path length.
//!
//! A root the peer sends is never trusted as is. It is matched against the store, and the store's
//! copy supplies the constraints; otherwise a copy without constraints would escape name
//! constraints.

use std::sync::OnceLock;

use crate::x509::{IpConstraint, NameConstraints, X509};
use crate::TlsError;

#[derive(Debug, Clone)]
pub struct TrustStore {
    roots: Vec<X509>,
    /// SHA-256 of trusted non-CA certificates; a leaf matching one is trusted without a chain.
    certificate_pins: Vec<[u8; 32]>,
    /// Ties connection and session caches to this trust policy.
    cache_key: [u8; 32],
}

impl Default for TrustStore {
    fn default() -> Self {
        Self::empty()
    }
}

impl TrustStore {
    pub fn empty() -> Self {
        TrustStore {
            roots: Vec::new(),
            certificate_pins: Vec::new(),
            cache_key: [0; 32],
        }
    }

    /// A non-CA certificate becomes a pin.
    pub fn add(&mut self, certificate: X509) {
        let mut key_material = [0u8; 65];
        key_material[..32].copy_from_slice(&self.cache_key);
        key_material[32] = u8::from(certificate.is_ca);
        key_material[33..].copy_from_slice(&certificate.cert_sha256);
        self.cache_key
            .copy_from_slice(&crate::keyschedule::Hash::Sha256.digest(&key_material));
        if certificate.is_ca {
            self.roots.push(certificate);
        } else {
            self.certificate_pins.push(certificate.cert_sha256);
        }
    }

    pub fn from_ders<'a, I: IntoIterator<Item = &'a [u8]>>(ders: I) -> Self {
        let mut s = Self::empty();
        for d in ders {
            if let Ok(c) = X509::parse(d) {
                s.add(c);
            }
        }
        s
    }

    /// Skips entries that cannot be read.
    pub fn from_pem(pem: &[u8]) -> Self {
        let mut s = Self::empty();
        for der in pem_certs(pem) {
            if let Ok(c) = X509::parse(&der) {
                s.add(c);
            }
        }
        s
    }

    /// Fails if any entry is broken. For bundles the operator names: skipping silently would start
    /// without a root meant to be trusted.
    pub fn try_from_pem(pem: &[u8]) -> Result<Self, TlsError> {
        const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
        const END: &[u8] = b"-----END CERTIFICATE-----";
        let mut store = Self::empty();
        let mut rest = pem;
        let mut found = false;
        while let Some(begin) = find(rest, BEGIN) {
            found = true;
            let after = &rest[begin + BEGIN.len()..];
            let end = find(after, END).ok_or(TlsError::Decode)?;
            let der = base64_decode(&after[..end]).ok_or(TlsError::Decode)?;
            store.add(X509::parse(&der)?);
            rest = &after[end + END.len()..];
        }
        if !found || store.is_empty() {
            return Err(TlsError::BadCert);
        }
        Ok(store)
    }

    /// Roots plus certificate pins.
    pub fn len(&self) -> usize {
        self.roots.len() + self.certificate_pins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty() && self.certificate_pins.is_empty()
    }

    pub fn cache_key(&self) -> [u8; 32] {
        self.cache_key
    }

    /// Read on the first call in the process; later calls get a copy. Roots added to the OS store
    /// take effect after a restart. The default client config holds this store, so reading it per
    /// call would reread and parse the whole store on every connection.
    pub fn system() -> TrustStore {
        static SYSTEM: OnceLock<TrustStore> = OnceLock::new();
        SYSTEM.get_or_init(load_system_store).clone()
    }
}

/// Certificates that fail to parse are not trusted and are skipped, with their fingerprint and
/// reason logged; a server reachable only through such a root fails validation, and this log is
/// where to look.
///
/// Loading none is reported as an error: every encrypted upstream would then fail validation, which
/// at the connection looks like nothing more than a validation failure.
fn load_system_store() -> TrustStore {
    let ders = load_system_root_ders();
    let mut store = TrustStore::empty();
    let mut skipped = 0usize;
    for der in &ders {
        match X509::parse(der) {
            Ok(certificate) => store.add(certificate),
            Err(error) => {
                skipped += 1;
                let sha256: String = crate::keyschedule::Hash::Sha256
                    .digest(der)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                onetdns_core::debug!(event = "tls.system_root_skipped", sha256 = %sha256, error = %error, "Skipped a system root certificate that could not be parsed; servers that chain only to it fail verification");
            }
        }
    }
    if store.is_empty() {
        onetdns_core::error!(event = "tls.system_roots_empty", found = ders.len(), "Could not load any system root certificates; cannot verify encrypted upstream DNS server certificates");
    } else if skipped > 0 {
        onetdns_core::info!(event = "tls.system_roots_loaded", roots = store.len(), skipped = skipped, "Loaded system root certificates; the skipped ones could not be parsed and are not trusted");
    } else {
        onetdns_core::debug!(
            event = "tls.system_roots_loaded",
            roots = store.len(),
            "Loaded system root certificates"
        );
    }
    store
}

#[cfg(windows)]
fn load_system_root_ders() -> Vec<Vec<u8>> {
    use core::ffi::c_void;

    #[repr(C)]
    struct CertContext {
        cert_encoding_type: u32,
        pb_cert_encoded: *const u8,
        cb_cert_encoded: u32,
        p_cert_info: *mut c_void,
        h_cert_store: *mut c_void,
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CertOpenSystemStoreW(h_prov: *mut c_void, sz_subsystem: *const u16) -> *mut c_void;
        fn CertEnumCertificatesInStore(
            h_store: *mut c_void,
            p_prev: *const CertContext,
        ) -> *const CertContext;
        fn CertCloseStore(h_store: *mut c_void, dw_flags: u32) -> i32;
    }

    let mut out = Vec::new();
    let name: Vec<u16> = "ROOT".encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let store = CertOpenSystemStoreW(core::ptr::null_mut(), name.as_ptr());
        if store.is_null() {
            return out;
        }
        let mut ctx = CertEnumCertificatesInStore(store, core::ptr::null());
        while !ctx.is_null() {
            let c = &*ctx;
            if !c.pb_cert_encoded.is_null() && c.cb_cert_encoded > 0 {
                let der = std::slice::from_raw_parts(c.pb_cert_encoded, c.cb_cert_encoded as usize)
                    .to_vec();
                out.push(der);
            }
            ctx = CertEnumCertificatesInStore(store, ctx);
        }
        CertCloseStore(store, 0);
    }
    out
}

#[cfg(not(windows))]
fn load_system_root_ders() -> Vec<Vec<u8>> {
    use std::io::Read;

    const MAX_ROOT_BUNDLE: u64 = 16 * 1024 * 1024;
    /// Root bundle paths differ by distribution; the first one found is used.
    const PATHS: &[&str] = &[
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/cert.pem",
    ];
    for p in PATHS {
        let Ok(file) = std::fs::File::open(p) else {
            continue;
        };
        let mut pem = Vec::new();
        if file
            .take(MAX_ROOT_BUNDLE + 1)
            .read_to_end(&mut pem)
            .is_err()
            || pem.len() as u64 > MAX_ROOT_BUNDLE
        {
            continue;
        }
        let ders = pem_certs(&pem);
        if !ders.is_empty() {
            return ders;
        }
    }
    Vec::new()
}

/// Returns the validated path: from the leaf to the store's copy of the root. Certificates the peer
/// sent that are not on the path are left out; a leaf trusted by pin is returned alone.
///
/// Without name matching, anyone with a valid certificate could stand in for another name. The
/// leaf's issuer comes from this path, not from the chain the peer sent: when a root issued the
/// leaf directly, the second certificate the peer sent was never verified.
pub fn verify_chain(
    chain: &[X509],
    store: &TrustStore,
    hostname: &str,
    now: i64,
) -> Result<Vec<X509>, TlsError> {
    verify_chain_for(chain, store, ChainUsage::Server(hostname), now)
}

/// No name matching.
pub fn verify_client_chain(chain: &[X509], store: &TrustStore, now: i64) -> Result<(), TlsError> {
    verify_chain_for(chain, store, ChainUsage::Client, now).map(drop)
}

#[derive(Clone, Copy)]
/// Each use requires a different key usage.
enum ChainUsage<'a> {
    /// The name being connected to.
    Server(&'a str),
    Client,
}

/// Checks signature, validity, CA flag, path length, usage, and name constraints at every step.
/// Returns the validated path, ending in the store's copy of the root.
///
/// UnknownCa when no certificate in the chain has its issuer in the store; CertificateExpired when
/// a certificate on the path is outside its validity; BadCert when the path is wrong in any other
/// way.
///
/// The root is the store's copy; using the peer's would let a copy without constraints escape name
/// constraints.
fn verify_chain_for(
    chain: &[X509],
    store: &TrustStore,
    usage: ChainUsage<'_>,
    now: i64,
) -> Result<Vec<X509>, TlsError> {
    let leaf = chain.first().ok_or(TlsError::BadCert)?;

    match usage {
        ChainUsage::Server(hostname) => {
            if !leaf.matches_hostname(hostname) {
                return Err(TlsError::BadCert);
            }
            if !leaf.allows_server_auth() {
                return Err(TlsError::BadCert);
            }
        }
        ChainUsage::Client => {
            if !leaf.allows_client_auth() {
                return Err(TlsError::BadCert);
            }
        }
    }
    if !leaf.allows_tls_leaf_usage() {
        return Err(TlsError::BadCert);
    }
    if !leaf.valid_at(now) {
        return Err(TlsError::CertificateExpired);
    }

    if store.certificate_pins.contains(&leaf.cert_sha256) {
        return Ok(vec![leaf.clone()]);
    }

    let (anchor_depth, root) = anchor_for(chain, store, now)?;
    let chain = &chain[..=anchor_depth];

    for c in chain {
        if !c.valid_at(now) {
            return Err(TlsError::CertificateExpired);
        }
    }

    for (i, pair) in chain.windows(2).enumerate() {
        let child = &pair[0];
        let issuer = &pair[1];
        if !issuer.is_ca || !issuer.allows_cert_sign() || !allows_chain_usage(issuer, usage) {
            return Err(TlsError::BadCert);
        }
        if child.issuer_raw != issuer.subject_raw {
            return Err(TlsError::BadCert);
        }
        child
            .verify_signed_by(issuer)
            .map_err(|_| TlsError::BadCert)?;

        if let Some(p) = issuer.path_len {
            let below = chain[1..i + 1]
                .iter()
                .filter(|c| c.subject_raw != c.issuer_raw)
                .count() as u32;
            if below > p {
                return Err(TlsError::BadCert);
            }
        }
    }

    let top = chain.last().ok_or(TlsError::BadCert)?;

    if !root.is_ca || !root.allows_cert_sign() || !allows_chain_usage(root, usage) {
        return Err(TlsError::BadCert);
    }
    if !root.valid_at(now) {
        return Err(TlsError::CertificateExpired);
    }

    let root_is_presented_top = root.cert_sha256 == top.cert_sha256;

    if let Some(p) = root.path_len {
        let end = if root_is_presented_top {
            chain.len().saturating_sub(1)
        } else {
            chain.len()
        };
        let below = if end > 1 {
            chain[1..end]
                .iter()
                .filter(|c| c.subject_raw != c.issuer_raw)
                .count() as u32
        } else {
            0
        };
        if below > p {
            return Err(TlsError::BadCert);
        }
    }

    for (ca_index, ca) in chain.iter().enumerate().skip(1) {
        if let Some(nc) = &ca.name_constraints {
            for subordinate in &chain[..ca_index] {
                if !name_constraints_ok(nc, &subordinate.san_dns, &subordinate.san_ip) {
                    return Err(TlsError::BadCert);
                }
            }
        }
    }

    let below_root = if root_is_presented_top {
        &chain[..chain.len().saturating_sub(1)]
    } else {
        chain
    };
    if let Some(nc) = &root.name_constraints {
        for subordinate in below_root {
            if !name_constraints_ok(nc, &subordinate.san_dns, &subordinate.san_ip) {
                return Err(TlsError::BadCert);
            }
        }
    }
    let mut path = below_root.to_vec();
    path.push(root.clone());
    Ok(path)
}

fn allows_chain_usage(cert: &X509, usage: ChainUsage<'_>) -> bool {
    match usage {
        ChainUsage::Server(_) => cert.allows_server_auth(),
        ChainUsage::Client => cert.allows_client_auth(),
    }
}

/// Finds where the chain first reaches the store, walking up from the leaf and checking whether a
/// trusted root signed the certificate or the certificate is itself a trusted root. Looking only at
/// the top fails because peers often send their root as a copy cross-signed by an older root this
/// side does not know; once a trusted root is reached below that copy, the rest is not on the path.
/// Returns the depth reached and the store's root.
///
/// UnknownCa when no issuer name in the chain matches a trusted root. BadCert when a root with a
/// matching issuer name exists but the signature does not match or the root cannot sign
/// certificates; RFC 8446 defines unknown_ca as an issuer that cannot be found and has a bad
/// signature reported as bad_certificate. CertificateExpired when the matching root is outside its
/// validity.
///
/// The root returned is always the store's copy; the peer's copy could be a version with the name
/// constraints stripped.
fn anchor_for<'a>(
    chain: &'a [X509],
    store: &'a TrustStore,
    now: i64,
) -> Result<(usize, &'a X509), TlsError> {
    let mut located_failure = None;
    for (depth, cert) in chain.iter().enumerate() {
        for root in store
            .roots
            .iter()
            .filter(|r| r.subject_raw == cert.issuer_raw)
        {
            let failure = if !root.is_ca
                || !root.allows_cert_sign()
                || cert.verify_signed_by(root).is_err()
            {
                TlsError::BadCert
            } else if !root.valid_at(now) {
                TlsError::CertificateExpired
            } else {
                return Ok((depth, root));
            };
            located_failure.get_or_insert(failure);
        }

        if let Some(root) = store
            .roots
            .iter()
            .find(|root| root.cert_sha256 == cert.cert_sha256)
        {
            return Ok((depth, root));
        }
    }
    Err(located_failure.unwrap_or(TlsError::UnknownCa))
}

/// Every constraint above in the chain applies, so an intermediate CA that issued a name outside
/// its own constraints is caught here.
fn name_constraints_ok(
    nc: &NameConstraints,
    dns_sans: &[String],
    ip_sans: &[std::net::IpAddr],
) -> bool {
    for san in dns_sans {
        if nc.excluded_dns.iter().any(|ex| dns_in_subtree(san, ex)) {
            return false;
        }
    }
    if !nc.permitted_dns.is_empty()
        && dns_sans
            .iter()
            .any(|san| !nc.permitted_dns.iter().any(|p| dns_in_subtree(san, p)))
    {
        return false;
    }

    for san in ip_sans {
        if nc.excluded_ip.iter().any(|ex| ip_in_subtree(*san, ex)) {
            return false;
        }
    }
    if !nc.permitted_ip.is_empty()
        && ip_sans
            .iter()
            .any(|san| !nc.permitted_ip.iter().any(|p| ip_in_subtree(*san, p)))
    {
        return false;
    }
    true
}

fn ip_in_subtree(ip: std::net::IpAddr, constraint: &IpConstraint) -> bool {
    match (ip, constraint.address) {
        (std::net::IpAddr::V4(ip), std::net::IpAddr::V4(base)) => {
            let prefix = constraint.prefix_len.min(32);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(ip) & mask) == (u32::from(base) & mask)
        }
        (std::net::IpAddr::V6(ip), std::net::IpAddr::V6(base)) => {
            let prefix = constraint.prefix_len.min(128);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(ip) & mask) == (u128::from(base) & mask)
        }
        _ => false,
    }
}

/// Only at label boundaries.
fn dns_in_subtree(name: &str, constraint: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let c = constraint
        .trim_end_matches('.')
        .trim_start_matches('.')
        .to_ascii_lowercase();
    if c.is_empty() {
        return true;
    }
    name == c || name.ends_with(&format!(".{c}"))
}

fn pem_certs(pem: &[u8]) -> Vec<Vec<u8>> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(b) = find(rest, BEGIN) {
        let after = &rest[b + BEGIN.len()..];
        let Some(e) = find(after, END) else { break };
        if let Some(der) = base64_decode(&after[..e]) {
            out.push(der);
        }
        rest = &after[e + END.len()..];
    }
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

pub(crate) fn base64_decode(input: &[u8]) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in input {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = val(c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa,
        KeyPair, KeyUsagePurpose, NameConstraints as RcNameConstraints,
    };

    fn ca_and_leaf(host: &str) -> (Vec<u8>, Vec<u8>) {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(
            rcgen::DnType::CommonName,
            format!("OnetDNS Test Root for {host}"),
        );
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(vec![host.to_string()]).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

        (ca_cert.der().to_vec(), leaf_cert.der().to_vec())
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    fn tls_leaf_requires_digital_signature_key_usage() {
        let build = |ku: KeyUsagePurpose| {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(vec!["dns.test".to_string()]).unwrap();
            params.key_usages = vec![ku];
            params.self_signed(&key).unwrap().der().to_vec()
        };
        let agreement_only = X509::parse(&build(KeyUsagePurpose::KeyAgreement)).unwrap();
        assert!(
            !agreement_only.allows_tls_leaf_usage(),
            "keyAgreement 전용 leaf는 거부되어야 한다"
        );
        let signing = X509::parse(&build(KeyUsagePurpose::DigitalSignature)).unwrap();
        assert!(
            signing.allows_tls_leaf_usage(),
            "digitalSignature leaf는 허용되어야 한다"
        );
    }

    #[test]
    fn pinned_self_signed_leaf_verifies() {
        let ck = rcgen::generate_simple_self_signed(vec!["dns.test".to_string()]).unwrap();
        let der = ck.cert.der().to_vec();
        let x = X509::parse(&der);
        assert!(x.is_ok(), "X509::parse 실패: {:?}", x.err());
        let store = TrustStore::from_ders([der.as_slice()]);
        assert_eq!(store.len(), 1, "trust store 비어있음 → parse 실패");
        let leaf = X509::parse(&der).unwrap();
        assert_eq!(
            verify_chain(&[leaf], &store, "dns.test", now()).map(drop),
            Ok(()),
            "verify_chain 실패"
        );
    }

    #[test]
    /// A certificate that does not match a pin has no CA to find an issuer with either, so it is
    /// rejected with unknown_ca.
    fn certificate_pin_requires_exact_der_fingerprint() {
        let ck = rcgen::generate_simple_self_signed(vec!["dns.test".to_string()]).unwrap();
        let pinned_der = ck.cert.der().to_vec();
        let store = TrustStore::from_ders([pinned_der.as_slice()]);

        let mut different_der = pinned_der.clone();
        let last = different_der.len() - 1;
        different_der[last] ^= 0x01;
        let different = X509::parse(&different_der).unwrap();
        assert_eq!(
            verify_chain(&[different], &store, "dns.test", now()).map(drop),
            Err(TlsError::UnknownCa)
        );
    }

    #[test]
    /// With a root whose issuer name matches but whose signature does not, the alert is
    /// bad_certificate; with that root expired, certificate_expired. unknown_ca is only for no
    /// matching root.
    fn located_issuer_failures_keep_their_own_alerts() {
        let (trusted, _) = root_ca_with(|_| {});
        let (impostor, impostor_key) = root_ca_with(|_| {});
        let leaf_der = leaf_signed_by("host.example", &impostor, &impostor_key, |_| {});
        let store = TrustStore::from_ders([trusted.der().as_ref()]);
        assert_eq!(
            verify_chain(
                &[X509::parse(&leaf_der).unwrap()],
                &store,
                "host.example",
                now()
            )
            .map(drop),
            Err(TlsError::BadCert),
            "이름만 같고 키가 다른 루트"
        );

        let (expired, expired_key) = root_ca_with(|params| {
            params.not_before = rcgen::date_time_ymd(2000, 1, 1);
            params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        });
        let leaf_der = leaf_signed_by("host.example", &expired, &expired_key, |_| {});
        let store = TrustStore::from_ders([expired.der().as_ref()]);
        assert_eq!(
            verify_chain(
                &[X509::parse(&leaf_der).unwrap()],
                &store,
                "host.example",
                now()
            )
            .map(drop),
            Err(TlsError::CertificateExpired),
            "만료된 루트"
        );
    }

    #[test]
    fn valid_chain_to_trusted_root() {
        let (ca_der, leaf_der) = ca_and_leaf("host.example");
        let leaf = X509::parse(&leaf_der).unwrap();
        let store = TrustStore::from_ders([ca_der.as_slice()]);
        assert_eq!(store.len(), 1);

        assert_eq!(
            verify_chain(&[leaf], &store, "host.example", now()).map(drop),
            Ok(())
        );
    }

    #[test]
    fn ca_is_recognized_as_ca() {
        let (ca_der, _) = ca_and_leaf("host.example");
        let ca = X509::parse(&ca_der).unwrap();
        assert!(ca.is_ca, "CA 인증서는 basicConstraints cA=TRUE");
    }

    #[test]
    fn wrong_hostname_rejected() {
        let (ca_der, leaf_der) = ca_and_leaf("host.example");
        let leaf = X509::parse(&leaf_der).unwrap();
        let store = TrustStore::from_ders([ca_der.as_slice()]);
        assert_eq!(
            verify_chain(&[leaf], &store, "evil.example", now()).map(drop),
            Err(TlsError::BadCert)
        );
    }

    /// The shape real public servers often send: the peer sends its root as a copy cross-signed by
    /// an older root, and the store holds only the self-signed root, not the cross-signer. Returns
    /// the self-signed root DER, the leaf, the intermediate, and the cross-signed root DER, in that
    /// order.
    fn cross_signed_root_chain(host: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let bridge_key = KeyPair::generate().unwrap();
        let mut bridge_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        bridge_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        bridge_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "OnetDNS Test Bridge");
        let bridge_cert = bridge_params.self_signed(&bridge_key).unwrap();

        let root_key = KeyPair::generate().unwrap();
        let root_params = || {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "OnetDNS Test Root");
            params
        };
        let root_self = root_params().self_signed(&root_key).unwrap();
        let root_cross = root_params()
            .signed_by(&root_key, &bridge_cert, &bridge_key)
            .unwrap();

        let mid_key = KeyPair::generate().unwrap();
        let mut mid_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        mid_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        mid_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "OnetDNS Test Intermediate");
        let mid_cert = mid_params
            .signed_by(&mid_key, &root_self, &root_key)
            .unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(vec![host.to_string()]).unwrap();
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &mid_cert, &mid_key)
            .unwrap();

        (
            root_self.der().to_vec(),
            leaf_cert.der().to_vec(),
            mid_cert.der().to_vec(),
            root_cross.der().to_vec(),
        )
    }

    #[test]
    /// Once a trusted root is reached partway up, nothing above needs checking. Looking only at the
    /// top would fail every server, such as dns.google, that sends a cross-signed copy.
    fn cross_signed_root_at_chain_top_still_anchors() {
        let (root_self, leaf_der, mid_der, cross_der) = cross_signed_root_chain("host.example");
        let store = TrustStore::from_ders([root_self.as_slice()]);
        let chain = [
            X509::parse(&leaf_der).unwrap(),
            X509::parse(&mid_der).unwrap(),
            X509::parse(&cross_der).unwrap(),
        ];
        assert_eq!(
            verify_chain(&chain, &store, "host.example", now()).map(drop),
            Ok(()),
            "교차 서명 사본이 끝에 붙었다고 체인 전체를 버렸습니다"
        );
    }

    #[test]
    /// Keeps "ignore the top" from turning into "accept anything".
    fn chain_without_any_trusted_link_is_still_rejected() {
        let (_root_self, leaf_der, mid_der, cross_der) = cross_signed_root_chain("host.example");
        let (other_root, _) = ca_and_leaf("other.example");
        let store = TrustStore::from_ders([other_root.as_slice()]);
        let chain = [
            X509::parse(&leaf_der).unwrap(),
            X509::parse(&mid_der).unwrap(),
            X509::parse(&cross_der).unwrap(),
        ];
        assert_eq!(
            verify_chain(&chain, &store, "host.example", now()).map(drop),
            Err(TlsError::UnknownCa)
        );
    }

    #[test]
    fn untrusted_root_rejected() {
        let (_ca_der, leaf_der) = ca_and_leaf("host.example");
        let (other_ca_der, _) = ca_and_leaf("other.example");
        let leaf = X509::parse(&leaf_der).unwrap();
        let store = TrustStore::from_ders([other_ca_der.as_slice()]);
        let rejected = verify_chain(&[leaf], &store, "host.example", now()).map(drop);
        assert_eq!(rejected, Err(TlsError::UnknownCa));
        assert_eq!(
            rejected.unwrap_err().alert(),
            Some(48),
            "루트를 찾지 못한 거부는 unknown_ca 로 알려야 합니다"
        );
    }

    #[test]
    fn empty_store_rejects() {
        let (_ca_der, leaf_der) = ca_and_leaf("host.example");
        let leaf = X509::parse(&leaf_der).unwrap();
        let store = TrustStore::empty();
        assert_eq!(
            verify_chain(&[leaf], &store, "host.example", now()).map(drop),
            Err(TlsError::UnknownCa)
        );
    }

    #[test]
    fn outside_validity_rejected() {
        let (ca_der, leaf_der) = ca_and_leaf("host.example");
        let leaf = X509::parse(&leaf_der).unwrap();
        let store = TrustStore::from_ders([ca_der.as_slice()]);

        let long_ago = now() - 100 * 365 * 86400;
        let rejected = verify_chain(&[leaf], &store, "host.example", long_ago).map(drop);
        assert_eq!(rejected, Err(TlsError::CertificateExpired));
        assert_eq!(
            rejected.unwrap_err().alert(),
            Some(45),
            "유효 기간 밖의 인증서는 certificate_expired 로 알려야 합니다"
        );
    }

    #[test]
    fn base64_roundtrip_known() {
        assert_eq!(base64_decode(b"aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode(b"Zm9vYmFy").unwrap(), b"foobar");

        assert_eq!(base64_decode(b"aGVs\nbG8=").unwrap(), b"hello");
    }

    #[test]
    fn ip_name_constraints_enforced() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let nc = NameConstraints {
            permitted_ip: vec![IpConstraint {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefix_len: 8,
            }],
            excluded_ip: vec![IpConstraint {
                address: IpAddr::V4(Ipv4Addr::new(10, 13, 0, 0)),
                prefix_len: 16,
            }],
            ..Default::default()
        };
        assert!(name_constraints_ok(
            &nc,
            &[],
            &[IpAddr::V4(Ipv4Addr::new(10, 12, 1, 5))]
        ));
        assert!(!name_constraints_ok(
            &nc,
            &[],
            &[IpAddr::V4(Ipv4Addr::new(10, 13, 1, 5))]
        ));
        assert!(!name_constraints_ok(
            &nc,
            &[],
            &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5))]
        ));

        let v6 = NameConstraints {
            permitted_ip: vec![IpConstraint {
                address: "2001:db8::".parse::<Ipv6Addr>().map(IpAddr::V6).unwrap(),
                prefix_len: 32,
            }],
            ..Default::default()
        };
        assert!(name_constraints_ok(
            &v6,
            &[],
            &["2001:db8::1".parse().unwrap()]
        ));
        assert!(!name_constraints_ok(
            &v6,
            &[],
            &["2001:4860::1".parse().unwrap()]
        ));
    }

    #[test]
    fn system_roots_load() {
        let store = TrustStore::system();

        assert!(
            !store.is_empty(),
            "시스템 루트 스토어가 비어있음(환경에 CA 번들 없음?)"
        );
    }

    #[test]
    fn pem_parse_extracts_cert() {
        let (ca_der, _) = ca_and_leaf("host.example");
        let pem = rcgen_pem(&ca_der);
        let store = TrustStore::from_pem(pem.as_bytes());
        assert_eq!(store.len(), 1);
    }

    #[test]
    /// Skipping would start without the root.
    fn explicit_pem_bundle_rejects_any_corrupted_certificate() {
        let (ca_der, _) = ca_and_leaf("host.example");
        let pem = format!(
            "{}\n-----BEGIN CERTIFICATE-----\nnot-base64!\n-----END CERTIFICATE-----\n",
            rcgen_pem(&ca_der)
        );
        assert!(TrustStore::try_from_pem(pem.as_bytes()).is_err());
        assert!(TrustStore::try_from_pem(rcgen_pem(&ca_der).as_bytes()).is_ok());
    }

    fn root_ca_with(mutate: impl FnOnce(&mut CertificateParams)) -> (rcgen::Certificate, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        p.distinguished_name
            .push(rcgen::DnType::CommonName, "OnetDNS Test Root");
        mutate(&mut p);
        let cert = p.self_signed(&key).unwrap();
        (cert, key)
    }

    fn leaf_signed_by(
        host: &str,
        ca: &rcgen::Certificate,
        ca_key: &KeyPair,
        mutate: impl FnOnce(&mut CertificateParams),
    ) -> Vec<u8> {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec![host.to_string()]).unwrap();
        mutate(&mut p);
        p.signed_by(&key, ca, ca_key).unwrap().der().to_vec()
    }

    /// The length stays the same, so nothing shifts.
    fn with_unverifiable_sig_algid(der: &[u8]) -> Vec<u8> {
        const ECDSA_SHA256_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        const UNKNOWN_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x09];
        let mut out = der.to_vec();
        let mut replaced = 0;
        for i in 0..out.len().saturating_sub(ECDSA_SHA256_OID.len()) {
            if &out[i..i + ECDSA_SHA256_OID.len()] == ECDSA_SHA256_OID {
                out[i..i + UNKNOWN_OID.len()].copy_from_slice(UNKNOWN_OID);
                replaced += 1;
            }
        }
        assert_eq!(replaced, 2, "서명 식별자는 tbs 안팎에 한 번씩 있어야 한다");
        out
    }

    #[test]
    /// A root is where verification starts, not something verified. Dropping older roots
    /// self-signed with SHA-1 would distrust every chain leading to them.
    fn root_with_unverifiable_self_signature_still_anchors() {
        let (ca_der, leaf_der) = ca_and_leaf("dns.test");
        let patched_ca = with_unverifiable_sig_algid(&ca_der);

        let ca = X509::parse(&patched_ca).expect("이전 방식으로 자기 서명한 루트도 읽어야 한다");
        assert_eq!(ca.sig_scheme, 0);
        assert!(ca.verify_self_signed().is_err());

        let leaf = X509::parse(&leaf_der).unwrap();
        let store = TrustStore::from_ders([patched_ca.as_slice()]);
        assert_eq!(
            verify_chain(&[leaf.clone()], &store, "dns.test", leaf.not_before).map(drop),
            Ok(())
        );
    }

    #[test]
    fn chain_link_with_unverifiable_signature_is_rejected() {
        let (ca_der, leaf_der) = ca_and_leaf("dns.test");
        let patched_leaf = with_unverifiable_sig_algid(&leaf_der);

        let leaf = X509::parse(&patched_leaf).expect("읽히기는 해야 한다");
        assert_eq!(leaf.sig_scheme, 0);

        let store = TrustStore::from_ders([ca_der.as_slice()]);
        assert_eq!(
            verify_chain(&[leaf.clone()], &store, "dns.test", leaf.not_before).map(drop),
            Err(TlsError::BadCert)
        );
    }

    #[test]
    fn leaf_eku_server_auth_required() {
        let (ca, ca_key) = root_ca_with(|_| {});
        let store = TrustStore::from_ders([ca.der().as_ref()]);

        let ok = leaf_signed_by("host.example", &ca, &ca_key, |p| {
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        });
        let ok = X509::parse(&ok).unwrap();
        assert_eq!(
            verify_chain(&[ok], &store, "host.example", now()).map(drop),
            Ok(())
        );

        let bad = leaf_signed_by("host.example", &ca, &ca_key, |p| {
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        });
        let bad = X509::parse(&bad).unwrap();
        assert_eq!(
            verify_chain(&[bad], &store, "host.example", now()).map(drop),
            Err(TlsError::BadCert),
            "serverAuth 없는 EKU는 TLS 서버로 거부되어야"
        );
    }

    #[test]
    fn intermediate_ca_eku_is_applied_to_the_whole_path() {
        let (root, root_key) = root_ca_with(|_| {});
        let store = TrustStore::from_ders([root.der().as_ref()]);

        let int_key = KeyPair::generate().unwrap();
        let mut int_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        int_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        int_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        int_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        int_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Client-only Intermediate");
        let int_cert = int_params.signed_by(&int_key, &root, &root_key).unwrap();

        let leaf = leaf_signed_by("host.example", &int_cert, &int_key, |p| {
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        });
        let leaf = X509::parse(&leaf).unwrap();
        let intermediate = X509::parse(int_cert.der().as_ref()).unwrap();
        assert_eq!(
            verify_chain(&[leaf, intermediate], &store, "host.example", now()).map(drop),
            Err(TlsError::BadCert),
            "serverAuth를 허용하지 않는 중간 CA는 서버 체인에 사용할 수 없습니다"
        );
    }

    #[test]
    fn name_constraints_apply_to_intermediate_certificate_names() {
        let (root, root_key) = root_ca_with(|p| {
            p.name_constraints = Some(RcNameConstraints {
                permitted_subtrees: vec![GeneralSubtree::DnsName("example".into())],
                excluded_subtrees: vec![],
            });
        });
        let store = TrustStore::from_ders([root.der().as_ref()]);

        let int_key = KeyPair::generate().unwrap();
        let mut int_params = CertificateParams::new(vec!["ca.evil".to_string()]).unwrap();
        int_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        int_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        int_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Outside-name Intermediate");
        let int_cert = int_params.signed_by(&int_key, &root, &root_key).unwrap();

        let leaf = leaf_signed_by("host.example", &int_cert, &int_key, |_| {});
        let leaf = X509::parse(&leaf).unwrap();
        let intermediate = X509::parse(int_cert.der().as_ref()).unwrap();
        assert_eq!(
            verify_chain(&[leaf, intermediate], &store, "host.example", now()).map(drop),
            Err(TlsError::BadCert),
            "루트의 Name Constraints는 중간 CA SAN에도 적용되어야 함"
        );
    }

    #[test]
    fn name_constraints_permitted_enforced() {
        let (ca, ca_key) = root_ca_with(|p| {
            p.name_constraints = Some(RcNameConstraints {
                permitted_subtrees: vec![GeneralSubtree::DnsName("example".into())],
                excluded_subtrees: vec![],
            });
        });
        let store = TrustStore::from_ders([ca.der().as_ref()]);

        let inside = leaf_signed_by("host.example", &ca, &ca_key, |_| {});
        let inside = X509::parse(&inside).unwrap();
        assert_eq!(
            verify_chain(&[inside], &store, "host.example", now()).map(drop),
            Ok(())
        );

        let outside = leaf_signed_by("host.evil", &ca, &ca_key, |_| {});
        let outside = X509::parse(&outside).unwrap();
        assert_eq!(
            verify_chain(&[outside], &store, "host.evil", now()).map(drop),
            Err(TlsError::BadCert),
            "permitted 밖 dNSName은 거부되어야"
        );
    }

    #[test]
    fn name_constraints_excluded_enforced() {
        let (ca, ca_key) = root_ca_with(|p| {
            p.name_constraints = Some(RcNameConstraints {
                permitted_subtrees: vec![],
                excluded_subtrees: vec![GeneralSubtree::DnsName("evil.example".into())],
            });
        });
        let store = TrustStore::from_ders([ca.der().as_ref()]);

        let blocked = leaf_signed_by("bad.evil.example", &ca, &ca_key, |_| {});
        let blocked = X509::parse(&blocked).unwrap();
        assert_eq!(
            verify_chain(&[blocked], &store, "bad.evil.example", now()).map(drop),
            Err(TlsError::BadCert),
            "excluded 서브트리는 거부되어야"
        );

        let allowed = leaf_signed_by("good.example", &ca, &ca_key, |_| {});
        let allowed = X509::parse(&allowed).unwrap();
        assert_eq!(
            verify_chain(&[allowed], &store, "good.example", now()).map(drop),
            Ok(())
        );
    }

    #[test]
    fn pathlen_zero_blocks_intermediate() {
        let (root, root_key) = root_ca_with(|p| {
            p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        });
        let store = TrustStore::from_ders([root.der().as_ref()]);

        let int_key = KeyPair::generate().unwrap();
        let mut int_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        int_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        int_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        int_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "OnetDNS Intermediate");
        let int_cert = int_params.signed_by(&int_key, &root, &root_key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(vec!["host.example".to_string()]).unwrap();
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &int_cert, &int_key)
            .unwrap();

        let leaf = X509::parse(leaf_cert.der().as_ref()).unwrap();
        let int = X509::parse(int_cert.der().as_ref()).unwrap();

        assert_eq!(
            verify_chain(&[leaf, int], &store, "host.example", now()).map(drop),
            Err(TlsError::BadCert),
            "pathLen=0 루트 아래 중간 CA는 거부되어야"
        );
    }

    #[test]
    /// The central path for bypassing name constraints.
    fn presented_top_cannot_strip_stored_name_constraints() {
        let root_key = KeyPair::generate().unwrap();
        let mut rp = CertificateParams::new(Vec::<String>::new()).unwrap();
        rp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        rp.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        rp.distinguished_name
            .push(rcgen::DnType::CommonName, "OnetDNS NC Root");
        rp.name_constraints = Some(RcNameConstraints {
            permitted_subtrees: vec![GeneralSubtree::DnsName("example".into())],
            excluded_subtrees: vec![],
        });
        let root = rp.self_signed(&root_key).unwrap();
        let store = TrustStore::from_ders([root.der().as_ref()]);

        let leaf_key = KeyPair::generate().unwrap();
        let mut lp = CertificateParams::new(vec!["host.evil".to_string()]).unwrap();
        lp.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = lp.signed_by(&leaf_key, &root, &root_key).unwrap();

        let mut fp = CertificateParams::new(Vec::<String>::new()).unwrap();
        fp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        fp.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        fp.distinguished_name
            .push(rcgen::DnType::CommonName, "OnetDNS NC Root");
        let forged = fp.self_signed(&root_key).unwrap();
        let mut forged_der = forged.der().to_vec();
        let n = forged_der.len();
        forged_der[n - 1] ^= 0xff;

        let leaf_x = X509::parse(leaf.der().as_ref()).unwrap();
        let forged_x = X509::parse(&forged_der).unwrap();

        assert_eq!(
            verify_chain(&[leaf_x, forged_x], &store, "host.evil", now()).map(drop),
            Err(TlsError::BadCert),
            "제시된 top이 저장 앵커의 이름 제약을 우회해선 안 됨"
        );
    }

    #[test]
    fn presented_root_direct_leaf_pathlen_zero_ok() {
        let (root, root_key) = root_ca_with(|p| {
            p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        });
        let store = TrustStore::from_ders([root.der().as_ref()]);

        let leaf = leaf_signed_by("host.example", &root, &root_key, |_| {});
        let leaf = X509::parse(&leaf).unwrap();
        let root_x = X509::parse(root.der().as_ref()).unwrap();

        assert_eq!(
            verify_chain(&[leaf, root_x], &store, "host.example", now()).map(drop),
            Ok(()),
            "제시된 pathLen=0 루트가 leaf를 직접 서명하면 유효해야"
        );
    }

    #[test]
    fn presented_root_with_intermediate_pathlen_one_ok() {
        let (root, root_key) = root_ca_with(|p| {
            p.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        });
        let store = TrustStore::from_ders([root.der().as_ref()]);

        let int_key = KeyPair::generate().unwrap();
        let mut ip = CertificateParams::new(Vec::<String>::new()).unwrap();
        ip.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ip.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        ip.distinguished_name
            .push(rcgen::DnType::CommonName, "OnetDNS Intermediate");
        let int_cert = ip.signed_by(&int_key, &root, &root_key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let lp = CertificateParams::new(vec!["host.example".to_string()]).unwrap();
        let leaf_cert = lp.signed_by(&leaf_key, &int_cert, &int_key).unwrap();

        let leaf = X509::parse(leaf_cert.der().as_ref()).unwrap();
        let int = X509::parse(int_cert.der().as_ref()).unwrap();
        let root_x = X509::parse(root.der().as_ref()).unwrap();

        assert_eq!(
            verify_chain(&[leaf, int, root_x], &store, "host.example", now()).map(drop),
            Ok(()),
            "제시된 pathLen=1 루트 + 중간 CA 1개는 유효해야"
        );
    }

    #[test]
    fn presented_root_still_enforces_stored_pathlen_zero() {
        let (root, root_key) = root_ca_with(|p| {
            p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        });
        let store = TrustStore::from_ders([root.der().as_ref()]);

        let int_key = KeyPair::generate().unwrap();
        let mut ip = CertificateParams::new(Vec::<String>::new()).unwrap();
        ip.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ip.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        ip.distinguished_name
            .push(rcgen::DnType::CommonName, "OnetDNS Intermediate");
        let int_cert = ip.signed_by(&int_key, &root, &root_key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let lp = CertificateParams::new(vec!["host.example".to_string()]).unwrap();
        let leaf_cert = lp.signed_by(&leaf_key, &int_cert, &int_key).unwrap();

        let leaf = X509::parse(leaf_cert.der().as_ref()).unwrap();
        let int = X509::parse(int_cert.der().as_ref()).unwrap();
        let root_x = X509::parse(root.der().as_ref()).unwrap();

        assert_eq!(
            verify_chain(&[leaf, int, root_x], &store, "host.example", now()).map(drop),
            Err(TlsError::BadCert),
            "제시된 루트여도 저장 pathLen=0 아래 중간 CA는 거부"
        );
    }

    #[test]
    /// The appended certificate shares the root's name but has a different key. On the path, the
    /// revocation check would trust a forged revocation response signed with that key.
    fn root_issued_leaf_path_ends_at_the_stored_root_not_a_presented_impostor() {
        let (root, root_key) = root_ca_with(|_| {});
        let store = TrustStore::from_ders([root.der().as_ref()]);
        let leaf = X509::parse(&leaf_signed_by("host.example", &root, &root_key, |_| {})).unwrap();
        let (impostor, _) = root_ca_with(|_| {});
        let impostor = X509::parse(impostor.der().as_ref()).unwrap();
        let root = X509::parse(root.der().as_ref()).unwrap();
        assert_eq!(impostor.subject_raw, root.subject_raw);

        let path = verify_chain(&[leaf.clone(), impostor], &store, "host.example", now())
            .expect("루트가 바로 발급한 리프는 통과해야 한다");
        let path: Vec<[u8; 32]> = path.iter().map(|cert| cert.cert_sha256).collect();
        assert_eq!(
            path,
            vec![leaf.cert_sha256, root.cert_sha256],
            "경로는 리프와 저장소의 루트로만 이뤄져야 한다"
        );
    }

    #[test]
    fn intermediate_path_keeps_the_intermediate_and_ends_at_the_stored_root() {
        let (root, root_key) = root_ca_with(|_| {});
        let store = TrustStore::from_ders([root.der().as_ref()]);
        let int_key = KeyPair::generate().unwrap();
        let mut ip = CertificateParams::new(Vec::<String>::new()).unwrap();
        ip.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ip.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        ip.distinguished_name
            .push(rcgen::DnType::CommonName, "OnetDNS Intermediate");
        let int_cert = ip.signed_by(&int_key, &root, &root_key).unwrap();
        let leaf = leaf_signed_by("host.example", &int_cert, &int_key, |_| {});

        let leaf = X509::parse(&leaf).unwrap();
        let int = X509::parse(int_cert.der().as_ref()).unwrap();
        let root = X509::parse(root.der().as_ref()).unwrap();
        let path = verify_chain(
            &[leaf.clone(), int.clone(), root.clone()],
            &store,
            "host.example",
            now(),
        )
        .expect("중간 CA를 거친 체인은 통과해야 한다");
        let path: Vec<[u8; 32]> = path.iter().map(|cert| cert.cert_sha256).collect();
        assert_eq!(
            path,
            vec![leaf.cert_sha256, int.cert_sha256, root.cert_sha256],
            "경로는 리프, 중간 CA, 루트 순서여야 한다"
        );
    }

    fn rcgen_pem(der: &[u8]) -> String {
        const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut b = String::new();
        for chunk in der.chunks(3) {
            let n = chunk.len();
            let b0 = chunk[0] as usize;
            let b1 = if n > 1 { chunk[1] as usize } else { 0 };
            let b2 = if n > 2 { chunk[2] as usize } else { 0 };
            b.push(B64[b0 >> 2] as char);
            b.push(B64[((b0 & 3) << 4) | (b1 >> 4)] as char);
            b.push(if n > 1 {
                B64[((b1 & 15) << 2) | (b2 >> 6)] as char
            } else {
                '='
            });
            b.push(if n > 2 { B64[b2 & 63] as char } else { '=' });
        }
        format!("-----BEGIN CERTIFICATE-----\n{b}\n-----END CERTIFICATE-----\n")
    }
}
