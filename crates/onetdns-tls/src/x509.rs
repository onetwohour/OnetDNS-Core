/*!
 * @brief X.509 인증서 파싱.
 *
 * @details 이쪽이 실제로 쓰는 필드만 읽는다. 공개키, 유효 기간, 이름, 그리고 판단에
 *          필요한 확장들이다.
 * @warning 이 파서가 신원 판단의 진입점이다. 확장이 두 번 오거나 형식이 어긋나면 거부한다.
 *          받아들이면 구현마다 다르게 읽어 그 차이가 곧 우회 경로가 된다.
 */

use crate::cert::verify_signature;
use crate::der::{self, bit_string_bytes, Der};
use crate::msg::consts;
use crate::TlsError;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/** @brief Ed25519 서명 키. */
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
/** @brief X25519 키 교환 키. 서명에는 쓸 수 없다. */
const OID_X25519: &[u8] = &[0x2b, 0x65, 0x6e];
/** @brief RSA 키. */
const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/** @brief 타원곡선 키. 곡선은 매개변수로 따로 온다. */
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/** @brief P-256 곡선. */
const OID_EC_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/** @brief P-384 곡선. */
const OID_EC_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
/** @brief PSS의 마스크 생성 함수. */
const OID_MGF1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];
/** @brief ECDSA with SHA-256 서명. */
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/** @brief ECDSA with SHA-384 서명. */
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
/** @brief RSA PKCS#1 with SHA-256 서명. */
const OID_SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
/** @brief RSA PKCS#1 with SHA-384 서명. */
const OID_SHA384_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
/** @brief RSA PKCS#1 with SHA-512 서명. */
const OID_SHA512_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
/** @brief RSA PSS 서명. 해시와 salt를 매개변수로 정한다. */
const OID_RSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
/** @brief SHA-256. */
const OID_HASH_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/** @brief SHA-384. */
const OID_HASH_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
/** @brief SHA-512. */
const OID_HASH_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
/** @brief 주체 대체 이름 확장. 호스트 이름 대조가 여기 든 값으로만 된다. */
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
/** @brief 기본 제약 확장. CA인지와 경로 길이를 정한다. */
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
/** @brief 키 용도 확장. */
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
/** @brief 확장 키 용도. 서버 인증과 클라이언트 인증을 구분한다. */
const OID_EKU: &[u8] = &[0x55, 0x1d, 0x25];
/** @brief 이름 제약 확장. CA가 발급할 수 있는 이름 범위를 묶는다. */
const OID_NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];

/** @brief 기관 정보 접근. OCSP 주소가 여기 있다. */
const OID_AIA: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
/** @brief 폐기 목록 배포 지점. */
const OID_CRL_DP: &[u8] = &[0x55, 0x1d, 0x1f];
/** @brief 기관 정보 중 OCSP 항목. */
const OID_AD_OCSP: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];

/** @brief 서버 인증 용도. */
const EKU_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
/** @brief 클라이언트 인증 용도. */
const EKU_CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
/** @brief OCSP 응답 서명 용도. */
const EKU_OCSP_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];
/** @brief 모든 용도. */
const EKU_ANY: &[u8] = &[0x55, 0x1d, 0x25, 0x00];

/** @brief 전자 서명 용도 비트. */
const KU_DIGITAL_SIGNATURE: u16 = 1 << 0;
/** @brief 인증서 서명 용도 비트. CA에 필요하다. */
const KU_KEY_CERT_SIGN: u16 = 1 << 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 공개키 종류. */
pub enum PublicKeyAlgorithm {
    /** @brief Ed25519 서명. */
    Ed25519,
    /** @brief X25519 키 교환. */
    X25519,
    /** @brief P-256 곡선. */
    EcP256,
    /** @brief P-384 곡선. */
    EcP384,
    /** @brief 이전 채우기를 쓰는 RSA. */
    RsaEncryption,
    /** @brief 무작위 채우기를 쓰는 RSA. */
    RsaPss { scheme: u16 },
}

impl PublicKeyAlgorithm {
    /**
     * @brief 이 키로 그 서명 방식을 쓸 수 있는지.
     * @warning 확인하지 않으면 RSA 키로 ECDSA 서명을 검증하는 식의 혼동이 생긴다.
     */
    pub fn allows_signature_scheme(self, scheme: u16) -> bool {
        match self {
            PublicKeyAlgorithm::Ed25519 => scheme == consts::ED25519,
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
/** @brief 파싱한 인증서. 이쪽이 쓰는 필드만 담는다. */
pub struct X509 {
    /** @brief 서명이 덮는 원래 바이트. 검증할 때 이것을 그대로 쓴다. */
    pub tbs_raw: Vec<u8>,

    /**
     * @brief 서명에 쓴 방식. 0은 이쪽이 검증할 수 없는 방식이라는 뜻이다.
     *
     * @invariant 0이면 verify_signature 가 어떤 키로도 통과시키지 않는다.
     *            allows_signature_scheme 이 모든 키 종류에서 0을 거부하기 때문이다.
     */
    pub sig_scheme: u16,

    /** @brief 서명. */
    pub signature: Vec<u8>,

    /** @brief 공개 키. */
    pub public_key: Vec<u8>,
    /** @brief 그 키의 알고리즘. */
    pub public_key_algorithm: PublicKeyAlgorithm,
    /** @brief 이 인증서의 지문. 못 박기와 비교에 쓴다. */
    pub cert_sha256: [u8; 32],
    /** @brief 이때부터 유효하다. */
    pub not_before: i64,
    /** @brief 이때까지 유효하다. */
    pub not_after: i64,
    /** @brief 이 인증서가 덮는 이름들. */
    pub san_dns: Vec<String>,

    /** @brief 이 인증서가 덮는 주소들. */
    pub san_ip: Vec<IpAddr>,

    /** @brief 발급자 이름의 원래 바이트. 체인을 잇는 데 쓴다. */
    pub issuer_raw: Vec<u8>,

    /** @brief 주체 이름의 원래 바이트. */
    pub subject_raw: Vec<u8>,

    /** @brief 다른 인증서를 발급할 수 있는지. */
    pub is_ca: bool,

    /** @brief 이 아래로 몇 단계까지 발급할 수 있는지. */
    pub path_len: Option<u32>,

    /** @brief 이 키를 어디에 쓸 수 있는지. */
    pub key_usage: Option<u16>,

    /** @brief 서버 인증에 쓸 수 있는지. */
    pub eku_server_auth: Option<bool>,

    /** @brief 클라이언트 인증에 쓸 수 있는지. */
    pub eku_client_auth: Option<bool>,

    /** @brief 이 아래에서 쓸 수 있는 이름의 제한. */
    pub name_constraints: Option<NameConstraints>,

    /** @brief 일련번호. 폐기 목록과 맞춰 본다. */
    pub serial: Vec<u8>,

    /** @brief 폐기 여부를 물어볼 주소. */
    pub ocsp_urls: Vec<String>,

    /** @brief 폐기 목록을 받을 주소. */
    pub crl_urls: Vec<String>,

    /** @brief 폐기 응답에 서명할 수 있는 인증서인지. */
    pub eku_ocsp_signing: bool,
}

impl X509 {
    /** @brief 파싱된 인증서가 별도 힙 버퍼에 보유한 바이트. */
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
/** @brief 주소 기반 이름 제약 하나. */
pub struct IpConstraint {
    /** @brief 제한할 주소. */
    pub address: IpAddr,
    /** @brief 그 대역 길이. */
    pub prefix_len: u8,
}

#[derive(Debug, Clone, Default)]
/** @brief 이름 제약 확장의 내용. 허용과 배제 목록이다. */
pub struct NameConstraints {
    /** @brief 허용하는 이름들. */
    pub permitted_dns: Vec<String>,
    /** @brief 막는 이름들. */
    pub excluded_dns: Vec<String>,
    /** @brief 허용하는 주소 대역들. */
    pub permitted_ip: Vec<IpConstraint>,
    /** @brief 막는 주소 대역들. */
    pub excluded_ip: Vec<IpConstraint>,
}

impl NameConstraints {
    /** @brief 이름 제약 목록의 예약 슬롯과 중첩 문자열이 보유한 바이트. */
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
    /**
     * @brief 인증서를 파싱한다.
     * @warning 같은 확장이 두 번 오면 거부한다. 어느 것을 쓸지 정해지지 않고, 구현마다
     *          다르게 고르면 그 차이로 제약을 우회할 수 있다.
     */
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
        // 검증할 수 없는 서명 방식이어도 인증서 자체는 읽는다. 신뢰 루트는 서명을
        // 확인하는 대상이 아니라 확인의 출발점이라, SHA-1으로 자기 서명한 이전 루트를
        // 여기서 버리면 그 루트로 이어지는 체인을 전부 못 믿게 된다. 이 값이 0이면
        // 그 서명으로는 아무것도 검증되지 않으므로 체인 안의 어느 곳에도 쓰이지 못한다.
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

    /** @brief OCSP 응답을 서명할 수 있는 인증서인지. */
    pub fn allows_ocsp_signing(&self) -> bool {
        self.eku_ocsp_signing
    }

    /** @brief 전자 서명 용도가 있는지. */
    pub fn allows_digital_signature(&self) -> bool {
        self.key_usage.is_none_or(|m| m & KU_DIGITAL_SIGNATURE != 0)
    }

    /** @brief 이 인증서의 공개키로 서명을 검증한다. */
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

    /** @brief TLS 서명 방식으로 검증한다. 키 종류와 방식이 맞아야 한다. */
    pub fn verify_tls_signature(
        &self,
        scheme: u16,
        content: &[u8],
        signature: &[u8],
    ) -> Result<(), TlsError> {
        if matches!(self.public_key_algorithm, PublicKeyAlgorithm::RsaPss { .. }) {
            return Err(TlsError::UnsupportedSig(scheme));
        }
        self.verify_signature(scheme, content, signature)
    }

    /** @brief 다른 인증서를 서명할 수 있는지. CA 판정이다. */
    pub fn allows_cert_sign(&self) -> bool {
        self.key_usage.is_none_or(|m| m & KU_KEY_CERT_SIGN != 0)
    }

    /** @brief 리프 인증서로 쓸 수 있는 용도인지. */
    pub fn allows_tls_leaf_usage(&self) -> bool {
        self.key_usage.is_none_or(|m| m & KU_DIGITAL_SIGNATURE != 0)
    }

    /** @brief 서버 인증에 쓸 수 있는지. */
    pub fn allows_server_auth(&self) -> bool {
        self.eku_server_auth.unwrap_or(true)
    }

    /** @brief 클라이언트 인증에 쓸 수 있는지. */
    pub fn allows_client_auth(&self) -> bool {
        self.eku_client_auth.unwrap_or(true)
    }

    /** @brief 이 인증서가 그 발급자에게 서명됐는지. */
    pub fn verify_signed_by(&self, issuer: &X509) -> Result<(), TlsError> {
        issuer.verify_signature(self.sig_scheme, &self.tbs_raw, &self.signature)
    }

    /** @brief 자기 자신에게 서명됐는지. 루트 판정에 쓴다. */
    pub fn verify_self_signed(&self) -> Result<(), TlsError> {
        self.verify_signature(self.sig_scheme, &self.tbs_raw, &self.signature)
    }

    /** @brief 이 시각에 유효한지. */
    pub fn valid_at(&self, now: i64) -> bool {
        self.not_before <= now && now <= self.not_after
    }

    /**
     * @brief 이 인증서가 그 호스트 이름을 위한 것인지.
     * @warning 주체 대체 이름만 본다. 이전 주체 필드의 공통 이름은 보지 않는다. 그것을
     *          믿으면 이름 제약이 걸리지 않는 경로가 생긴다.
     */
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

    /** @brief 발급자를 사람이 읽을 형태로. 진단용이다. */
    pub fn issuer_label(&self) -> Option<String> {
        distinguished_name_label(&self.issuer_raw)
    }

    /** @brief 주체를 사람이 읽을 형태로. */
    pub fn subject_label(&self) -> Option<String> {
        distinguished_name_label(&self.subject_raw)
    }
}

/** @brief 알고리즘 식별자에서 키 종류를 정한다. */
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

/** @brief 공개키 바이트가 그 종류의 형식에 맞는지. */
fn public_key_encoding_valid(algorithm: PublicKeyAlgorithm, key: &[u8]) -> bool {
    match algorithm {
        PublicKeyAlgorithm::Ed25519 | PublicKeyAlgorithm::X25519 => key.len() == 32,
        PublicKeyAlgorithm::EcP256 => p256::PublicKey::from_sec1_bytes(key).is_ok(),
        PublicKeyAlgorithm::EcP384 => p384::PublicKey::from_sec1_bytes(key).is_ok(),
        PublicKeyAlgorithm::RsaEncryption | PublicKeyAlgorithm::RsaPss { .. } => {
            rsa_public_key_components(key).is_ok()
        }
    }
}

/**
 * @brief RSA 공개키에서 모듈러스와 지수를 추출한다.
 * @warning 정규 인코딩만 받는다. 앞에 0이 붙은 정수 같은 것을 허용하면 같은 키가 여러
 *          형태로 표현돼 지문이 갈린다.
 */
pub(crate) fn rsa_public_key_components(key: &[u8]) -> Result<(&[u8], &[u8]), TlsError> {
    /** @brief 양의 정수를 꺼낸다. 부호 바이트를 걷어내되 비정규 형태는 거부한다. */
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
    // 지수 3은 Go Daddy Class 2 같은 이전 루트가 아직 쓴다. 그 서명을 실제로 검증하는
    // onetdns_core::rsa 가 EM을 전부 다시 만들어 비교하므로 작은 지수로 위조할 경로가 없다.
    if !(3..=(1u64 << 33) - 1).contains(&exponent_value) || exponent_value & 1 == 0 {
        return Err(TlsError::BadCert);
    }
    Ok((modulus, exponent))
}

/** @brief 접속할 호스트가 주소인지 이름인지. */
pub(crate) enum PeerHost<'a> {
    /** @brief IPv4 나 IPv6 주소. */
    Ip(IpAddr),
    /** @brief 호스트 이름. 끝 점은 걷어 냈다. */
    Name(&'a str),
}

/**
 * @brief 접속할 호스트를 주소와 이름으로 가른다.
 * @details 앞뒤 공백과 IPv6 대괄호, 끝 점을 걷어 낸 뒤 주소로 읽히면 주소다. 인증서 이름 확인과
 *          SNI 가 이 판정 하나를 같이 써야, 주소로 붙을 때 SNI 를 빼고 IP SAN 으로 확인하는 두
 *          동작이 어긋나지 않는다.
 */
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

/** @brief 이름 구조에서 읽을 만한 표기를 만든다. */
fn distinguished_name_label(raw: &[u8]) -> Option<String> {
    /** @brief 공통 이름. */
    const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
    /** @brief 조직 이름. */
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

/** @brief 문자열 값을 읽는다. 인코딩이 여럿이라 태그로 갈린다. */
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

/** @brief 서명 알고리즘 식별자에서 TLS 서명 방식 번호를 정한다. */
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
        // 검증하지 않을 방식이라 매개변수의 뜻은 보지 않는다. 다만 DER로서 온전한지는
        // 따져, 뒤에 해석되지 않은 바이트가 남은 인증서는 그대로 거부한다.
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

/** @brief 있으면 널 매개변수를 소비한다. 알고리즘마다 있고 없고가 다르다. */
fn consume_optional_null(d: &mut Der<'_>) -> Result<(), TlsError> {
    if !d.is_empty() {
        let null = d.next()?;
        if null.tag != 0x05 || !null.value.is_empty() || !d.is_empty() {
            return Err(TlsError::BadCert);
        }
    }
    Ok(())
}

/** @brief PSS 매개변수를 읽어 방식을 정한다. 해시와 마스크 함수, salt 길이가 서로 맞아야 한다. */
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

/** @brief 해시 알고리즘 식별자를 읽는다. */
fn parse_hash_algid(algid: &[u8]) -> Result<&[u8], TlsError> {
    let mut outer = Der::new(algid);
    let alg = outer.expect(der::SEQUENCE)?;
    if !outer.is_empty() {
        return Err(TlsError::BadCert);
    }
    parse_hash_algid_content(alg)
}

/** @brief 해시 알고리즘 식별자의 내용을 읽는다. */
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
/** @brief 파싱한 확장들. */
struct ParsedExt {
    /** @brief 이 인증서가 덮는 이름들. */
    san_dns: Vec<String>,
    /** @brief 이 인증서가 덮는 주소들. */
    san_ip: Vec<IpAddr>,
    /** @brief 다른 인증서를 발급할 수 있는지. */
    is_ca: bool,
    /** @brief 이 아래로 몇 단계까지 발급할 수 있는지. */
    path_len: Option<u32>,
    /** @brief 이 키를 어디에 쓸 수 있는지. */
    key_usage: Option<u16>,
    /** @brief 서버 인증에 쓸 수 있는지. */
    eku_server_auth: Option<bool>,
    /** @brief 클라이언트 인증에 쓸 수 있는지. */
    eku_client_auth: Option<bool>,
    /** @brief 이 아래에서 쓸 수 있는 이름의 제한. */
    name_constraints: Option<NameConstraints>,
    /** @brief 폐기 여부를 물어볼 주소. */
    ocsp_urls: Vec<String>,
    /** @brief 폐기 목록을 받을 주소. */
    crl_urls: Vec<String>,
    /** @brief 폐기 응답에 서명할 수 있는 인증서인지. */
    eku_ocsp_signing: bool,
}

/** @brief 확장을 읽는다. 중복은 거부하고, 모르는 필수 확장이 있으면 실패다. */
fn parse_extensions(ext_data: &[u8]) -> Result<ParsedExt, TlsError> {
    let exts = Der::new(ext_data).expect(der::SEQUENCE)?;
    let mut e = Der::new(exts);
    let mut out = ParsedExt::default();

    let mut seen: Vec<&[u8]> = Vec::new();
    while !e.is_empty() {
        let ext = e.expect(der::SEQUENCE)?;
        let mut ex = Der::new(ext);
        let oid = ex.expect(der::OID)?;
        if seen.contains(&oid) {
            return Err(TlsError::BadCert);
        }
        seen.push(oid);

        let n1 = ex.next()?;
        let (critical, val) = if n1.tag == der::BOOLEAN {
            let critical = der::boolean_value(n1.value)?;
            (critical, ex.expect(der::OCTET_STRING)?)
        } else if n1.tag == der::OCTET_STRING {
            (false, n1.value)
        } else {
            return Err(TlsError::BadCert);
        };
        if !ex.is_empty() {
            return Err(TlsError::BadCert);
        }
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
                    // dNSName 은 IA5String 이다. ASCII 가 아닌 값을 이름으로 받아들이면 다른
                    // 검증기가 거절하는 인증서를 이쪽만 통과시킬 수 있다.
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
            // cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX) OPTIONAL 순서이고
            // 그 밖의 값은 없어야 한다. 순서나 중복, 모르는 값을 넘기면 다른 검증기와 다르게 읽는다.
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

/** @brief 이름 구조에서 주소들을 모은다. */
fn collect_uris(data: &[u8], out: &mut Vec<String>) {
    collect_uris_depth(data, out, 0);
}

/** @brief 깊이를 세며 주소를 모은다. 깊이 상한이 무한 중첩을 막는다. */
fn collect_uris_depth(data: &[u8], out: &mut Vec<String>, depth: usize) {
    /** @brief DER 중첩 깊이 상한. 깊게 감싼 인증서에서 스택이 넘치는 것을 막는다. */
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

/** @brief 이름 제약의 하위 트리 목록을 읽는다. */
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

/** @brief 주소 제약을 읽는다. 주소와 마스크가 붙어 온다. */
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

/** @brief 마스크가 연속된 접두사인지 보고 길이를 준다. 구멍이 있으면 없다. */
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

/** @brief 키 용도 비트열을 읽는다. */
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

/**
 * @brief 확장 값이 기대한 태그의 TLV 하나로만 이루어졌는지 보고 그 내용을 준다.
 * @details 뒤에 남는 바이트를 무시하면 다른 검증기가 거절하는 인증서를 이쪽만 받아들인다.
 */
fn only_value(val: &[u8], tag: u8) -> Result<&[u8], TlsError> {
    let mut d = Der::new(val);
    let value = d.expect(tag)?;
    if !d.is_empty() {
        return Err(TlsError::BadCert);
    }
    Ok(value)
}

/** @brief 그 달의 날 수. 윤년을 반영한다. */
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

/** @brief 인증서 시각을 Unix 초로. 두 곳 연도와 네 곳 연도 형식이 모두 온다. */
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

/** @brief 날짜를 기준일부터의 날 수로. */
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[cfg(test)]
/** @brief 확장 파싱 엄격성, 키와 서명 방식 대조, 그리고 시각 해석. */
mod tests {
    use super::*;

    #[test]
    /** @brief 필수인데 이쪽이 못 다루는 제약 형태를 거부하는지. 무시하면 제약이 사라진다. */
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
    /** @brief 규격에 없는 최솟값이 든 제약을 거부하는지. */
    fn nameconstraints_critical_nonzero_minimum_rejected() {
        let data = [0x30, 0x06, 0x82, 0x01, b'a', 0x80, 0x01, 0x01];
        let (mut dns, mut ips) = (Vec::new(), Vec::new());
        assert_eq!(
            parse_name_subtrees(&data, &mut dns, &mut ips, true),
            Err(TlsError::BadCert)
        );
    }

    #[test]
    /** @brief 이름 기반 제약은 정상적으로 읽히는지. */
    fn nameconstraints_dns_subtree_still_parses() {
        let mut d = vec![0x30u8, 0x06, 0x82, 0x04];
        d.extend_from_slice(b"ex.c");
        let (mut dns, mut ips) = (Vec::new(), Vec::new());
        assert_eq!(parse_name_subtrees(&d, &mut dns, &mut ips, true), Ok(()));
        assert_eq!(dns, vec!["ex.c".to_string()]);
    }

    #[test]
    /** @brief 날짜 계산이 알려진 값과 맞는지. */
    fn days_from_civil_known() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), 10957);
        assert_eq!(days_from_civil(2021, 1, 1) * 86400, 1609459200);
    }

    /** @brief 테스트용 시각 값을 만든다. */
    fn utctime(s: &[u8]) -> crate::der::Tlv<'_> {
        crate::der::Tlv {
            tag: 0x17,
            value: s,
        }
    }

    #[test]
    /** @brief PSS 매개변수가 서로 맞을 때만 받아들이는지. */
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
    /** @brief 키 종류가 서명 방식을 제한하는지. 안 하면 방식 혼동이 생긴다. */
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
    /** @brief 확장이 두 번 오면 거부하는지. */
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

    /** @brief 어디에도 속하지 않는 값으로 끼워 넣을 NULL 태그. */
    const NULL_TAG: u8 = 0x05;

    /** @brief 태그와 짧은 길이를 붙인 DER 조각. 테스트 입력은 모두 128바이트보다 짧다. */
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag, u8::try_from(content.len()).unwrap()];
        out.extend_from_slice(content);
        out
    }

    /** @brief 확장 하나만 담은 Extensions. critical 은 BOOLEAN 내용 바이트다. */
    fn one_extension(oid: &[u8], critical: Option<&[u8]>, value: &[u8]) -> Vec<u8> {
        let mut ext = tlv(der::OID, oid);
        if let Some(critical) = critical {
            ext.extend(tlv(der::BOOLEAN, critical));
        }
        ext.extend(tlv(der::OCTET_STRING, value));
        tlv(der::SEQUENCE, &tlv(der::SEQUENCE, &ext))
    }

    /** @brief 주어진 내용을 담은 BasicConstraints 확장. */
    fn basic_constraints(fields: &[u8]) -> Vec<u8> {
        one_extension(OID_BASIC_CONSTRAINTS, None, &tlv(der::SEQUENCE, fields))
    }

    #[test]
    /**
     * @brief 확장의 구조를 DER 그대로만 받아들이는지.
     * @details 다른 검증기가 거절하는 인증서를 이쪽만 받아들이면 검증기마다 판정이 갈린다.
     */
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
    /** @brief BasicConstraints 를 정해진 순서와 값으로만 읽는지. */
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
    /** @brief EKU 안의 OID 가 아닌 값과 ASCII 가 아닌 dNSName 을 거부하는지. */
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
    /** @brief 음이 아닌 INTEGER 를 최소 인코딩으로만 읽는지. */
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
    /** @brief 형식이 깨진 시각을 거부하는지. */
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
    /** @brief RSA 키가 정규 인코딩이고 최소 강도를 넘는지. */
    fn rsa_public_key_der_is_canonical_and_meets_security_floor() {
        /** @brief 태그와 길이를 앞에 붙인 DER 조각. */
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
        /** @brief 테스트용 공개 키 바이트. */
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
    /** @brief 실제 인증서를 읽고 자기 서명을 검증하는지. */
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
