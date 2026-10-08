/*!
 * @brief 신뢰 저장소와 체인 검증.
 *
 * @details 상대가 보낸 체인을 이쪽이 믿는 루트까지 이어 본다. 서명, 유효 기간, 용도,
 *          이름 제약, 경로 길이를 전부 확인한다.
 * @warning 상대가 보낸 루트를 그대로 믿지 않는다. 이쪽 저장소에 있는 것과 대조하고,
 *          제약도 이쪽이 가진 사본의 것을 쓴다. 그러지 않으면 제약 없는 사본을 보내
 *          이름 제약을 벗어날 수 있다.
 */

use std::sync::OnceLock;

use crate::x509::{IpConstraint, NameConstraints, X509};
use crate::TlsError;

#[derive(Debug, Clone)]
/** @brief 이쪽이 믿는 루트 인증서들. */
pub struct TrustStore {
    /** @brief 믿는 루트 인증서들. */
    roots: Vec<X509>,
    /** @brief 못 고정해 둔 인증서 지문들. 있으면 이것과도 맞아야 한다. */
    certificate_pins: Vec<[u8; 32]>,
    /** @brief 연결·세션 캐시를 신뢰 정책에 묶는 식별자. */
    cache_key: [u8; 32],
}

impl Default for TrustStore {
    fn default() -> Self {
        Self::empty()
    }
}

impl TrustStore {
    /** @brief 빈 저장소. */
    pub fn empty() -> Self {
        TrustStore {
            roots: Vec::new(),
            certificate_pins: Vec::new(),
            cache_key: [0; 32],
        }
    }

    /** @brief 루트를 하나 넣는다. */
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

    /** @brief DER 목록으로 만든다. */
    pub fn from_ders<'a, I: IntoIterator<Item = &'a [u8]>>(ders: I) -> Self {
        let mut s = Self::empty();
        for d in ders {
            if let Ok(c) = X509::parse(d) {
                s.add(c);
            }
        }
        s
    }

    /** @brief PEM 번들로 만든다. 읽히지 않는 항목은 건너뛴다. */
    pub fn from_pem(pem: &[u8]) -> Self {
        let mut s = Self::empty();
        for der in pem_certs(pem) {
            if let Ok(c) = X509::parse(&der) {
                s.add(c);
            }
        }
        s
    }

    /**
     * @brief PEM 번들로 만들되 하나라도 깨졌으면 실패한다.
     * @note 운영자가 명시한 번들에 쓴다. 조용히 건너뛰면 믿으려던 루트가 빠진 채 시작한다.
     */
    pub fn try_from_pem(pem: &[u8]) -> Result<Self, TlsError> {
        /** @brief 인증서가 시작하는 줄. */
        const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
        /** @brief 인증서가 끝나는 줄. */
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

    /** @brief 신뢰하는 인증서 수. 루트와 인증서 핀을 합친 값이다. */
    pub fn len(&self) -> usize {
        self.roots.len() + self.certificate_pins.len()
    }

    /** @brief 비었는지. */
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty() && self.certificate_pins.is_empty()
    }

    /** @brief 연결·세션 캐시를 이 신뢰 정책에만 묶을 식별자. */
    pub fn cache_key(&self) -> [u8; 32] {
        self.cache_key
    }

    /**
     * @brief 시스템 루트 저장소. 프로세스에서 처음 부를 때 읽고, 그 뒤로는 그 사본을 준다.
     * @note 운영체제 저장소에 넣은 루트는 다시 시작해야 반영된다. 기본 클라이언트 설정이 이
     *       저장소를 담으므로, 부를 때마다 읽으면 연결을 맺을 때마다 저장소 전체를 다시 읽고
     *       파싱한다.
     */
    pub fn system() -> TrustStore {
        /** @brief 처음 읽은 시스템 루트. */
        static SYSTEM: OnceLock<TrustStore> = OnceLock::new();
        SYSTEM.get_or_init(load_system_store).clone()
    }
}

/**
 * @brief 시스템 루트를 읽어 저장소를 만든다.
 * @details 파싱하지 못한 인증서는 믿지 않고 건너뛰되 지문과 사유를 남긴다. 그 루트에만 닿는
 *          서버는 검증에 실패하므로, 원인을 찾을 때 이 기록과 대조한다.
 * @note 하나도 못 읽으면 오류로 알린다. 그 상태에서는 모든 암호화 업스트림이 인증서 검증에
 *       실패하는데, 연결 지점에서는 검증 실패로만 보여 원인을 찾을 수 없다.
 */
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
/** @brief 이 플랫폼의 루트 인증서를 읽는다. */
fn load_system_root_ders() -> Vec<Vec<u8>> {
    use core::ffi::c_void;

    #[repr(C)]
    /** @brief 시스템이 돌려주는 인증서 하나. */
    struct CertContext {
        /** @brief 인증서를 담은 형식. */
        cert_encoding_type: u32,
        /** @brief 인증서 바이트가 있는 곳. */
        pb_cert_encoded: *const u8,
        /** @brief 그 길이. */
        cb_cert_encoded: u32,
        /** @brief 풀어 놓은 인증서 정보. */
        p_cert_info: *mut c_void,
        /** @brief 이 인증서를 담은 저장소. */
        h_cert_store: *mut c_void,
    }

    #[link(name = "crypt32")]
    extern "system" {
        /** @brief 시스템 인증서 저장소를 연다. */
        fn CertOpenSystemStoreW(h_prov: *mut c_void, sz_subsystem: *const u16) -> *mut c_void;
        /** @brief 저장소의 인증서를 하나씩 훑는다. */
        fn CertEnumCertificatesInStore(
            h_store: *mut c_void,
            p_prev: *const CertContext,
        ) -> *const CertContext;
        /** @brief 저장소를 닫는다. */
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
/** @brief 이 기계가 믿는 루트 인증서들을 읽는다. */
fn load_system_root_ders() -> Vec<Vec<u8>> {
    use std::io::Read;

    /** @brief 읽어 들일 루트 번들 크기 상한. */
    const MAX_ROOT_BUNDLE: u64 = 16 * 1024 * 1024;
    /** @brief 배포판마다 다른 루트 번들 경로들. 먼저 찾아지는 것을 쓴다. */
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

/**
 * @brief 서버 체인을 검증하고 호스트 이름까지 대조한다.
 * @return 검증한 인증 경로. 리프에서 시작해 이쪽 저장소에 있는 루트의 사본으로 끝난다.
 *         상대가 보냈어도 경로에 들지 않은 인증서는 담지 않는다. 인증서 핀으로 믿은
 *         리프는 리프 하나만 담는다.
 * @warning 이름 대조를 빼면 유효한 인증서를 가진 아무나 남의 이름을 대신할 수 있다.
 * @warning 리프의 발급자는 상대가 보낸 체인이 아니라 이 경로에서 꺼낸다. 리프를 루트가
 *          바로 발급했으면 상대가 보낸 두 번째 인증서는 아무도 검증하지 않은 값이다.
 */
pub fn verify_chain(
    chain: &[X509],
    store: &TrustStore,
    hostname: &str,
    now: i64,
) -> Result<Vec<X509>, TlsError> {
    verify_chain_for(chain, store, ChainUsage::Server(hostname), now)
}

/** @brief 클라이언트 체인을 검증한다. 이름 대조는 하지 않는다. */
pub fn verify_client_chain(chain: &[X509], store: &TrustStore, now: i64) -> Result<(), TlsError> {
    verify_chain_for(chain, store, ChainUsage::Client, now).map(drop)
}

#[derive(Clone, Copy)]
/** @brief 이 체인을 무엇에 쓰는지. 요구하는 용도가 갈린다. */
enum ChainUsage<'a> {
    /** @brief 서버 인증서로 쓴다. 값은 붙을 이름. */
    Server(&'a str),
    /** @brief 클라이언트 인증서로 쓴다. */
    Client,
}

/**
 * @brief 체인을 루트까지 이어 검증한다.
 *
 * @details 각 단계에서 서명, 유효 기간, CA 여부, 경로 길이, 용도, 이름 제약을 본다.
 * @return 검증한 인증 경로. 마지막 인증서는 저장소에 있는 루트의 사본이다.
 * @retval TlsError::UnknownCa 체인의 어느 인증서도 발급자가 저장소에 없다.
 * @retval TlsError::CertificateExpired 경로의 인증서가 유효 기간 밖이다.
 * @retval TlsError::BadCert 그 밖에 경로가 어긋났다.
 * @warning 루트는 이쪽 저장소의 사본을 쓴다. 상대가 보낸 것을 쓰면 제약을 뺀 사본으로
 *          이름 제약을 벗어날 수 있다.
 */
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

/** @brief 이 인증서가 그 용도에 쓰일 수 있는지. */
fn allows_chain_usage(cert: &X509, usage: ChainUsage<'_>) -> bool {
    match usage {
        ChainUsage::Server(_) => cert.allows_server_auth(),
        ChainUsage::Client => cert.allows_client_auth(),
    }
}

/**
 * @brief 체인이 이쪽 저장소에 처음 닿는 곳을 찾는다.
 *
 * @details 리프에서 위로 올라가며, 그 인증서를 이쪽 루트가 서명했는지 또는 그 인증서 자체가
 *          이쪽 루트인지를 본다. 끝만 보면 안 되는 이유는, 상대가 자기 루트를 이쪽이 모르는
 *          더 오래된 루트가 교차 서명한 사본으로 덧붙여 보내는 것이 흔하기 때문이다. 그
 *          사본 아래에서 이미 이쪽 루트에 닿았다면 위쪽은 경로에 들어가지 않는다.
 * @return 닿은 곳의 깊이와 저장소에 있는 루트.
 * @retval TlsError::UnknownCa 체인의 어느 인증서도 발급자 이름이 이쪽 루트와 맞지 않는다.
 * @retval TlsError::BadCert 발급자 이름이 맞는 루트는 있지만 서명이 맞지 않거나 그 루트가
 *         인증서를 서명할 수 없다. RFC 8446 은 unknown_ca 를 발급자를 찾지 못한 경우로 정하고,
 *         서명이 맞지 않는 인증서는 bad_certificate 로 알리게 한다.
 * @retval TlsError::CertificateExpired 발급자 이름이 맞는 루트가 유효 기간 밖이다.
 * @warning 루트는 언제나 저장소의 사본을 돌려준다. 상대가 보낸 사본을 쓰면 이름 제약을
 *          벗긴 판으로 교체할 수 있다.
 */
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

/**
 * @brief 리프의 이름들이 상위 CA의 제약 안에 있는지.
 * @details 체인 위쪽의 모든 제약이 함께 걸린다. 중간 CA가 자기 제약을 벗어난 이름을
 *          발급했다면 여기서 걸린다.
 */
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

/** @brief 주소가 제약 범위 안인지. */
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

/** @brief 이름이 제약 범위 안인지. 라벨 경계에서만 맞는 것으로 본다. */
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

/** @brief PEM 번들에서 인증서들을 추출한다. */
fn pem_certs(pem: &[u8]) -> Vec<Vec<u8>> {
    /** @brief 인증서 시작 표시. */
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    /** @brief 인증서 끝 표시. */
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

/** @brief 바이트열에서 부분열의 위치. */
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/** @brief base64 디코딩. */
pub(crate) fn base64_decode(input: &[u8]) -> Option<Vec<u8>> {
    /** @brief 문자 하나를 6비트 값으로. */
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
/** @brief 체인 검증의 각 조건과, 제약을 벗기려는 시도의 거부. */
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa,
        KeyPair, KeyUsagePurpose, NameConstraints as RcNameConstraints,
    };

    /** @brief 테스트용 CA와 리프 인증서. */
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

    /** @brief 지금 Unix 초. */
    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    /** @brief 리프에 전자 서명 용도가 없으면 거부하는지. */
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
    /** @brief 고정한 자체 서명 인증서가 통과하는지. */
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
    /**
     * @brief 고정이 바이트까지 정확히 맞아야 하는지.
     * @details 고정과 다른 인증서는 발급자를 찾을 CA 도 없으므로 unknown_ca 로 거부한다.
     */
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
    /**
     * @brief 발급자를 찾은 뒤의 실패를 unknown_ca 로 알리지 않는지.
     * @details 발급자 이름이 맞는 루트가 있는데 서명이 맞지 않으면 bad_certificate, 그 루트가
     *          만료됐으면 certificate_expired 다. unknown_ca 는 이름이 맞는 루트가 없을 때만 쓴다.
     */
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
    /** @brief 정상 체인이 루트까지 이어지는지. */
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
    /** @brief CA 표시가 제대로 읽히는지. */
    fn ca_is_recognized_as_ca() {
        let (ca_der, _) = ca_and_leaf("host.example");
        let ca = X509::parse(&ca_der).unwrap();
        assert!(ca.is_ca, "CA 인증서는 basicConstraints cA=TRUE");
    }

    #[test]
    /** @brief 이름이 다르면 거부하는지. */
    fn wrong_hostname_rejected() {
        let (ca_der, leaf_der) = ca_and_leaf("host.example");
        let leaf = X509::parse(&leaf_der).unwrap();
        let store = TrustStore::from_ders([ca_der.as_slice()]);
        assert_eq!(
            verify_chain(&[leaf], &store, "evil.example", now()).map(drop),
            Err(TlsError::BadCert)
        );
    }

    /**
     * @brief 교차 서명된 루트를 끝에 붙인 체인과 그 루트의 자체 서명본.
     * @details 실제 공개 서버가 흔히 보내는 모양이다. 상대는 자기 루트를 더 오래된 다른
     *          루트가 교차 서명한 사본으로 보내고, 이쪽 저장소에는 그 루트의 자체 서명본만
     *          들어 있다. 교차 서명한 쪽은 저장소에 없다.
     * @return (자체 서명 루트 DER, 리프, 중간, 교차 서명 루트 DER) 순.
     */
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
    /**
     * @brief 체인 끝에 모르는 루트가 교차 서명한 사본이 붙어 있어도 이어지는지.
     * @details 체인 중간에서 이미 이쪽 루트에 닿았다면 그 위는 볼 필요가 없다. 끝만 보면
     *          dns.google처럼 교차 서명 사본을 보내는 서버가 전부 검증에 실패한다.
     */
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
    /**
     * @brief 이쪽 루트에 닿지 못하는 체인은 길이와 무관하게 거부하는지.
     * @details 앞 테스트가 통과하도록 고치면서 "끝을 무시한다"가 "아무거나 받는다"가 되지
     *          않는지 함께 붙든다.
     */
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
    /** @brief 모르는 루트를 unknown_ca 로 거부하는지. */
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
    /** @brief 저장소가 비면 아무것도 통과하지 않는지. */
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
    /** @brief 유효 기간 밖이면 certificate_expired 로 거부하는지. */
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
    /** @brief base64 왕복. */
    fn base64_roundtrip_known() {
        assert_eq!(base64_decode(b"aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode(b"Zm9vYmFy").unwrap(), b"foobar");

        assert_eq!(base64_decode(b"aGVs\nbG8=").unwrap(), b"hello");
    }

    #[test]
    /** @brief 주소 기반 제약이 걸리는지. */
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
    /** @brief 시스템 루트를 읽을 수 있는지. */
    fn system_roots_load() {
        let store = TrustStore::system();

        assert!(
            !store.is_empty(),
            "시스템 루트 스토어가 비어있음(환경에 CA 번들 없음?)"
        );
    }

    #[test]
    /** @brief PEM에서 인증서를 뽑는지. */
    fn pem_parse_extracts_cert() {
        let (ca_der, _) = ca_and_leaf("host.example");
        let pem = rcgen_pem(&ca_der);
        let store = TrustStore::from_pem(pem.as_bytes());
        assert_eq!(store.len(), 1);
    }

    #[test]
    /** @brief 운영자가 명시한 번들은 하나라도 깨지면 실패하는지. 건너뛰면 루트가 빠진 채 시작한다. */
    fn explicit_pem_bundle_rejects_any_corrupted_certificate() {
        let (ca_der, _) = ca_and_leaf("host.example");
        let pem = format!(
            "{}\n-----BEGIN CERTIFICATE-----\nnot-base64!\n-----END CERTIFICATE-----\n",
            rcgen_pem(&ca_der)
        );
        assert!(TrustStore::try_from_pem(pem.as_bytes()).is_err());
        assert!(TrustStore::try_from_pem(rcgen_pem(&ca_der).as_bytes()).is_ok());
    }

    /** @brief 설정을 바꿔 테스트용 루트 CA를 만든다. */
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

    /** @brief 그 CA가 서명한 리프를 만든다. */
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

    /** @brief ECDSA-SHA256 서명 식별자를 이쪽이 모르는 것으로 바꾼다. 길이가 같아 위치가 밀리지 않는다. */
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
    /**
     * @brief 자기 서명이 이쪽이 검증 못 하는 방식이어도 루트로 쓰이는지.
     * @details 루트는 서명을 확인하는 대상이 아니라 확인의 출발점이다. SHA-1으로 자기
     *          서명한 이전 루트를 버리면 그 루트로 이어지는 체인을 전부 못 믿게 된다.
     */
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
    /** @brief 이쪽이 검증 못 하는 방식으로 서명된 인증서는 체인에 못 들어가는지. */
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
    /** @brief 서버 인증 용도가 없는 리프를 거부하는지. */
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
    /** @brief 중간 CA의 용도 제한이 경로 전체에 걸리는지. */
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
    /** @brief 이름 제약이 중간 인증서에도 걸리는지. */
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
    /** @brief 허용 목록이 실제로 걸리는지. */
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
    /** @brief 배제 목록이 실제로 걸리는지. */
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
    /** @brief 경로 길이 0인 CA 아래 중간 CA를 막는지. */
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
    /** @brief 상대가 보낸 루트로 이쪽 저장소의 제약을 벗길 수 없는지. 이것이 이름 제약 우회의 핵심 경로다. */
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
    /** @brief 경로 길이 0인 루트 아래 직접 리프는 되는지. */
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
    /** @brief 경로 길이 1이면 중간 하나가 되는지. */
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
    /** @brief 이쪽 저장소의 경로 길이 제한이 그대로 걸리는지. */
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
    /**
     * @brief 루트가 바로 발급한 리프의 경로에 상대가 덧붙인 인증서 대신 저장소의 루트가 드는지.
     * @details 덧붙인 인증서는 루트와 이름만 같고 키가 다르다. 경로에 들면 폐기 확인이 그 키로
     *          서명한 가짜 폐기 응답을 믿는다.
     */
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
    /** @brief 중간 CA를 거친 경로가 제시된 중간 CA를 담고 저장소의 루트로 끝나는지. */
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

    /** @brief DER을 PEM으로 감싼다. */
    fn rcgen_pem(der: &[u8]) -> String {
        /** @brief base64 문자표. */
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
