/*!
 * @brief 인증서 메시지와 서명 검증.
 *
 * @details 상대가 보낸 체인을 읽고, 그 개인키를 실제로 갖고 있는지 서명으로 확인한다.
 * @warning 서명 대상에는 고정 접두사와 방향 문자열이 들어간다. 그것이 있어야 클라이언트
 *          서명을 서버 서명으로 재사용하는 교차 프로토콜 공격이 막힌다.
 */

use crate::msg::consts;
use crate::wire::{Reader, Writer};
use crate::TlsError;

/** @brief 체인에 담을 수 있는 인증서 수. */
pub(crate) const MAX_CERTIFICATE_ENTRIES: usize = 16;

/** @brief 체인 구성이 온전한지. 빈 항목이나 지나친 개수를 거른다. */
pub(crate) fn certificate_chain_is_valid(chain: &[Vec<u8>], allow_empty: bool) -> bool {
    if chain.is_empty() {
        return allow_empty;
    }
    if chain.len() > MAX_CERTIFICATE_ENTRIES || chain.iter().any(Vec::is_empty) {
        return false;
    }
    chain
        .iter()
        .try_fold(4usize, |size, certificate| {
            size.checked_add(5)?.checked_add(certificate.len())
        })
        .is_some_and(|size| size <= crate::handshake::MAX_HANDSHAKE_MESSAGE)
}

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 인증서 하나와 그에 붙은 확장. */
pub struct CertEntry {
    /** @brief 인증서 바이트. */
    pub cert_data: Vec<u8>,
    /** @brief 이 인증서에 딸린 확장. */
    pub extensions: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 인증서 메시지. */
pub struct CertificateMsg {
    /** @brief 어느 요청에 대한 답인지. */
    pub request_context: Vec<u8>,
    /** @brief 보낸 인증서들. 리프부터 순서대로. */
    pub entries: Vec<CertEntry>,
}

impl CertificateMsg {
    /**
     * @brief 인증서 메시지를 읽는다.
     * @retval TlsError::Decode 형식이 깨졌거나 빈 인증서가 있다.
     * @retval TlsError::BadCert 인증서가 이쪽이 검증할 개수 상한보다 많다.
     */
    pub fn parse(body: &[u8]) -> Result<CertificateMsg, TlsError> {
        let mut r = Reader::new(body);
        let request_context = r.vec8()?.to_vec();
        let list = r.vec24()?;
        if !r.is_empty() {
            return Err(TlsError::Decode);
        }
        let mut lr = Reader::new(list);
        let mut entries = Vec::new();
        while !lr.is_empty() {
            let cert_data = lr.vec24()?.to_vec();
            if cert_data.is_empty() {
                return Err(TlsError::Decode);
            }
            if entries.len() >= MAX_CERTIFICATE_ENTRIES {
                return Err(TlsError::BadCert);
            }
            let extensions = lr.vec16()?.to_vec();
            entries.push(CertEntry {
                cert_data,
                extensions,
            });
        }
        Ok(CertificateMsg {
            request_context,
            entries,
        })
    }

    /** @brief 인증서 메시지를 쓴다. */
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.vec8(|w| w.bytes(&self.request_context));
        w.vec24(|w| {
            for e in &self.entries {
                w.vec24(|w| w.bytes(&e.cert_data));
                w.vec16(|w| w.bytes(&e.extensions));
            }
        });
        w.buf
    }

    /** @brief 체인의 첫 인증서. 상대의 신원이 여기 있다. */
    pub fn leaf(&self) -> Option<&[u8]> {
        self.entries.first().map(|e| e.cert_data.as_slice())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 클라이언트 인증서 요청. */
pub struct CertificateRequestMsg {
    /** @brief 어느 요청인지 구분하는 값. */
    pub context: Vec<u8>,
    /** @brief 무엇을 받아들일지 알리는 확장. */
    pub extensions: Vec<crate::msg::Extension>,
}

/**
 * @brief 이쪽 1.3 CertificateRequest 가 알리는 서명 방식.
 * @details 클라이언트의 CertificateVerify 는 이 안에서 골라야 한다. RSA PKCS#1 은 인증서 서명을
 *          받기 위해 넣었고, CertificateVerify 에는 RFC 8446 이 금하므로 쓸 수 없다.
 */
pub(crate) const REQUESTED_SIGNATURE_SCHEMES: [u16; 5] = [
    consts::ED25519,
    consts::ECDSA_SECP256R1_SHA256,
    consts::ECDSA_SECP384R1_SHA384,
    consts::RSA_PSS_RSAE_SHA256,
    consts::RSA_PKCS1_SHA256,
];

impl CertificateRequestMsg {
    /** @brief 이쪽이 지원하는 서명 방식을 담은 표준 요청. */
    pub fn standard() -> Self {
        CertificateRequestMsg {
            context: Vec::new(),
            extensions: vec![crate::msg::Extension::signature_algorithms(
                &REQUESTED_SIGNATURE_SCHEMES,
            )],
        }
    }

    /** @brief 인증서를 달라는 메시지를 읽는다. */
    pub fn parse(body: &[u8]) -> Result<CertificateRequestMsg, TlsError> {
        let mut r = Reader::new(body);
        let context = r.vec8()?.to_vec();
        let extensions = crate::msg::Extension::parse_list(r.vec16()?)?;
        if !r.is_empty() {
            return Err(TlsError::Decode);
        }
        Ok(CertificateRequestMsg {
            context,
            extensions,
        })
    }

    /**
     * @brief 핸드셰이크 중에 받은 요청을 확인하고, 이쪽 CertificateVerify 가 골라야 할 서명 방식을
     *        돌려준다.
     * @retval TlsError::IllegalParameter 요청 문맥이 비어 있지 않다. RFC 8446 은 핸드셰이크
     *         중의 요청에 빈 문맥을 요구한다.
     * @retval TlsError::MissingExtension signature_algorithms 가 없다.
     * @retval TlsError::Decode signature_algorithms 형식이 틀렸다.
     */
    pub(crate) fn handshake_signature_algorithms(&self) -> Result<Vec<u16>, TlsError> {
        if !self.context.is_empty() {
            return Err(TlsError::IllegalParameter);
        }
        crate::msg::Extension::find(&self.extensions, consts::EXT_SIGNATURE_ALGORITHMS)
            .ok_or(TlsError::MissingExtension)?
            .as_signature_algorithms()
            .ok_or(TlsError::Decode)
    }

    /** @brief 인증서를 달라는 메시지를 적는다. */
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.vec8(|w| w.bytes(&self.context));
        w.vec16(|w| {
            for e in &self.extensions {
                e.encode_into(w);
            }
        });
        w.buf
    }
}

/**
 * @brief 이 서명 방식으로 1.3 CertificateVerify 를 만들 수 있는지.
 * @param requested 받는 쪽이 signature_algorithms 로 알린 방식.
 * @details RFC 8446 은 받는 쪽이 알린 방식만 쓰게 하고, RSA 는 PSS 만 쓰게 한다. RSA PKCS#1 은
 *          1.3 에서 인증서 서명에만 쓴다.
 */
pub(crate) fn tls13_signature_scheme_allowed(scheme: u16, requested: &[u16]) -> bool {
    !matches!(
        scheme,
        consts::RSA_PKCS1_SHA256 | consts::RSA_PKCS1_SHA384 | consts::RSA_PKCS1_SHA512
    ) && requested.contains(&scheme)
}

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 개인키 소유를 증명하는 서명. */
pub struct CertificateVerify {
    /** @brief 서명에 쓴 방식. */
    pub algorithm: u16,
    /** @brief 서명. */
    pub signature: Vec<u8>,
}

impl CertificateVerify {
    /** @brief 인증서 소유 증명을 읽는다. */
    pub fn parse(body: &[u8]) -> Result<CertificateVerify, TlsError> {
        let mut r = Reader::new(body);
        let algorithm = r.u16()?;
        let signature = r.vec16()?.to_vec();
        if signature.is_empty() || !r.is_empty() {
            return Err(TlsError::Decode);
        }
        Ok(CertificateVerify {
            algorithm,
            signature,
        })
    }

    /**
     * @brief 1.3 CertificateVerify 의 서명을 상대 인증서로 검증한다.
     * @param requested 이쪽이 signature_algorithms 로 알린 방식.
     * @param content certificate_verify_content 로 만든 서명 대상.
     * @retval TlsError::IllegalParameter 서명 방식이 이쪽이 알린 목록에 없거나 RSA PKCS#1 이다.
     */
    pub(crate) fn verify_tls13(
        &self,
        peer: &crate::x509::X509,
        requested: &[u16],
        content: &[u8],
    ) -> Result<(), TlsError> {
        if !tls13_signature_scheme_allowed(self.algorithm, requested) {
            return Err(TlsError::IllegalParameter);
        }
        peer.verify_tls_signature(self.algorithm, content, &self.signature)
    }

    /** @brief 인증서 소유 증명을 적는다. 1.2 와 1.3 의 형식이 같다. */
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(self.algorithm);
        w.vec16(|w| w.bytes(&self.signature));
        w.buf
    }
}

/**
 * @brief 서명 대상 바이트를 만든다.
 * @details 공백 64개, 방향을 뜻하는 문자열, 구분자, 그리고 핸드셰이크 기록 해시를 잇는다.
 * @warning 방향 문자열이 다르므로 클라이언트 서명을 서버 서명으로 되쓸 수 없다. 이것이
 *          교차 프로토콜 공격을 막는 장치다.
 */
pub fn certificate_verify_content(transcript_hash: &[u8], server: bool) -> Vec<u8> {
    let context: &[u8] = if server {
        b"TLS 1.3, server CertificateVerify"
    } else {
        b"TLS 1.3, client CertificateVerify"
    };
    let mut c = vec![0x20u8; 64];
    c.extend_from_slice(context);
    c.push(0x00);
    c.extend_from_slice(transcript_hash);
    c
}

/** @brief 서명 방식에 맞는 검증기로 넘긴다. 모르는 방식은 거부한다. */
pub fn verify_signature(
    scheme: u16,
    public_key: &[u8],
    content: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    match scheme {
        consts::ED25519 => verify_ed25519(public_key, content, signature),
        consts::ECDSA_SECP256R1_SHA256 => verify_ecdsa_p256(public_key, content, signature),
        consts::ECDSA_SECP384R1_SHA384 => verify_ecdsa_p384(public_key, content, signature),
        consts::RSA_PSS_RSAE_SHA256 => verify_rsa_pss_sha256(public_key, content, signature),
        consts::RSA_PSS_RSAE_SHA384 => verify_rsa_pss_sha384(public_key, content, signature),
        consts::RSA_PSS_RSAE_SHA512 => verify_rsa_pss_sha512(public_key, content, signature),
        consts::RSA_PKCS1_SHA256 => verify_rsa_pkcs1_sha256(public_key, content, signature),
        consts::RSA_PKCS1_SHA384 => verify_rsa_pkcs1_sha384(public_key, content, signature),
        consts::RSA_PKCS1_SHA512 => verify_rsa_pkcs1_sha512(public_key, content, signature),
        other => Err(TlsError::UnsupportedSig(other)),
    }
}

/** @brief Ed25519 서명 검증. */
fn verify_ed25519(pk: &[u8], content: &[u8], sig: &[u8]) -> Result<(), TlsError> {
    let pk: [u8; 32] = pk.try_into().map_err(|_| TlsError::BadCert)?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|_| TlsError::BadCert)?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| TlsError::BadSignature)?;
    vk.verify_strict(content, &ed25519_dalek::Signature::from_bytes(&sig))
        .map_err(|_| TlsError::BadSignature)
}

/** @brief P-256 ECDSA 서명 검증. */
fn verify_ecdsa_p256(pk: &[u8], content: &[u8], sig: &[u8]) -> Result<(), TlsError> {
    use p256::ecdsa::signature::Verifier;
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(pk).map_err(|_| TlsError::BadCert)?;
    let sig = p256::ecdsa::Signature::from_der(sig).map_err(|_| TlsError::BadSignature)?;
    vk.verify(content, &sig).map_err(|_| TlsError::BadSignature)
}

/** @brief P-384 ECDSA 서명 검증. */
fn verify_ecdsa_p384(pk: &[u8], content: &[u8], sig: &[u8]) -> Result<(), TlsError> {
    use p384::ecdsa::signature::Verifier;
    let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(pk).map_err(|_| TlsError::BadCert)?;
    let sig = p384::ecdsa::Signature::from_der(sig).map_err(|_| TlsError::BadSignature)?;
    vk.verify(content, &sig).map_err(|_| TlsError::BadSignature)
}

macro_rules! rsa_verify {
    ($name:ident, $verify:path, $hash:expr) => {
        /** @brief 이 알고리즘으로 서명을 검증한다. */
        fn $name(pk: &[u8], content: &[u8], sig: &[u8]) -> Result<(), TlsError> {
            let (n, e) = crate::x509::rsa_public_key_components(pk)?;
            $verify($hash, n, e, content, sig).map_err(|err| match err {
                onetdns_core::rsa::RsaError::BadKey => TlsError::BadCert,
                onetdns_core::rsa::RsaError::BadSignature => TlsError::BadSignature,
            })
        }
    };
}
use onetdns_core::rsa::{verify_pkcs1, verify_pss, RsaHash};
rsa_verify!(verify_rsa_pss_sha256, verify_pss, RsaHash::Sha256);
rsa_verify!(verify_rsa_pss_sha384, verify_pss, RsaHash::Sha384);
rsa_verify!(verify_rsa_pss_sha512, verify_pss, RsaHash::Sha512);
rsa_verify!(verify_rsa_pkcs1_sha256, verify_pkcs1, RsaHash::Sha256);
rsa_verify!(verify_rsa_pkcs1_sha384, verify_pkcs1, RsaHash::Sha384);
rsa_verify!(verify_rsa_pkcs1_sha512, verify_pkcs1, RsaHash::Sha512);

#[cfg(test)]
/**
 * @brief testdata 의 RSA 키로 만든 자기 서명 인증서와 그 키.
 * @details 1.3 에서 금하는 RSA PKCS#1 서명은 RSA 키로만 만들 수 있다. EC 키로 시험하면 키 종류
 *          검사가 먼저 거부하므로 서명 방식 검사를 확인하지 못한다.
 */
pub(crate) fn rsa_test_certificate(
    name: &str,
) -> (
    Vec<u8>,
    std::sync::Arc<onetdns_core::rsa::testsign::TestRsaKey>,
) {
    use onetdns_core::rsa::testsign::TestRsaKey;
    use std::sync::Arc;

    /** @brief rcgen 이 인증서 서명에 쓰는 RSA 키. */
    struct Remote(Arc<TestRsaKey>, Vec<u8>);
    impl rcgen::RemoteKeyPair for Remote {
        fn public_key(&self) -> &[u8] {
            &self.1
        }
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
            Ok(self.0.sign_pkcs1(RsaHash::Sha256, message))
        }
        fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
            &rcgen::PKCS_RSA_SHA256
        }
    }

    let private = crate::trust::base64_decode(include_bytes!(
        "../../../testdata/rsa_test_private_key_2048.pk8.b64"
    ))
    .unwrap();
    let key = Arc::new(TestRsaKey::from_pkcs8(&private).unwrap());
    let public = key.public_key_der();
    let key_pair = rcgen::KeyPair::from_remote(Box::new(Remote(Arc::clone(&key), public))).unwrap();
    let certificate = rcgen::CertificateParams::new(vec![name.to_string()])
        .unwrap()
        .self_signed(&key_pair)
        .unwrap();
    (certificate.der().to_vec(), key)
}

#[cfg(test)]
/** @brief 그 RSA 키로 이 서명 방식의 서명을 만드는 서명자. */
pub(crate) fn rsa_test_signer(
    key: std::sync::Arc<onetdns_core::rsa::testsign::TestRsaKey>,
    scheme: u16,
) -> std::sync::Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync> {
    let (hash, pss) = match scheme {
        consts::RSA_PKCS1_SHA256 => (RsaHash::Sha256, false),
        consts::RSA_PSS_RSAE_SHA256 => (RsaHash::Sha256, true),
        consts::RSA_PSS_RSAE_SHA384 => (RsaHash::Sha384, true),
        consts::RSA_PSS_RSAE_SHA512 => (RsaHash::Sha512, true),
        other => panic!("Not an RSA signature scheme: {other:#06x}"),
    };
    std::sync::Arc::new(move |content: &[u8]| {
        if pss {
            key.sign_pss(hash, content, &vec![0x5a; hash.digest_len()])
        } else {
            key.sign_pkcs1(hash, content)
        }
    })
}

#[cfg(test)]
/** @brief 메시지 왕복, 서명 대상 배치, 그리고 방식별 검증. */
mod tests {
    use super::*;

    #[test]
    /** @brief 인증서 메시지 왕복. */
    fn certificate_msg_roundtrip() {
        let cm = CertificateMsg {
            request_context: vec![],
            entries: vec![
                CertEntry {
                    cert_data: vec![0xAA; 50],
                    extensions: vec![],
                },
                CertEntry {
                    cert_data: vec![0xBB; 30],
                    extensions: vec![],
                },
            ],
        };
        let body = cm.encode();
        let back = CertificateMsg::parse(&body).unwrap();
        assert_eq!(back, cm);
        assert_eq!(back.leaf().unwrap().len(), 50);
    }

    #[test]
    /** @brief 빈 항목과 지나친 개수를 거부하는지. */
    fn certificate_message_rejects_trailing_empty_and_excessive_entries() {
        let valid = CertificateMsg {
            request_context: Vec::new(),
            entries: vec![CertEntry {
                cert_data: vec![1],
                extensions: Vec::new(),
            }],
        }
        .encode();
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(CertificateMsg::parse(&trailing).is_err());

        let empty = CertificateMsg {
            request_context: Vec::new(),
            entries: vec![CertEntry {
                cert_data: Vec::new(),
                extensions: Vec::new(),
            }],
        }
        .encode();
        assert!(CertificateMsg::parse(&empty).is_err());

        let excessive = CertificateMsg {
            request_context: Vec::new(),
            entries: (0..=MAX_CERTIFICATE_ENTRIES)
                .map(|_| CertEntry {
                    cert_data: vec![1],
                    extensions: Vec::new(),
                })
                .collect(),
        }
        .encode();
        assert!(CertificateMsg::parse(&excessive).is_err());
    }

    #[test]
    /** @brief 서명 메시지 왕복. */
    fn certificate_verify_roundtrip() {
        let cv = CertificateVerify {
            algorithm: consts::ED25519,
            signature: vec![0x11; 64],
        };
        let body = cv.encode();
        assert_eq!(CertificateVerify::parse(&body).unwrap(), cv);

        let mut trailing = body;
        trailing.push(0);
        assert!(CertificateVerify::parse(&trailing).is_err());
        assert!(CertificateVerify::parse(&[0x08, 0x07, 0, 0]).is_err());

        let mut request = CertificateRequestMsg::standard().encode();
        request.push(0);
        assert!(CertificateRequestMsg::parse(&request).is_err());
    }

    #[test]
    /**
     * @brief 1.3 CertificateVerify 가 받는 쪽이 알린 방식만 쓰고, RSA 는 PSS 만 쓰는지.
     * @details 서명이 맞아도 방식이 어긋나면 RFC 8446 대로 illegal_parameter 다.
     */
    fn tls13_certificate_verify_requires_a_requested_non_pkcs1_scheme() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        use p256::pkcs8::DecodePrivateKey;

        assert!(tls13_signature_scheme_allowed(
            consts::ED25519,
            &REQUESTED_SIGNATURE_SCHEMES
        ));
        assert!(!tls13_signature_scheme_allowed(
            consts::RSA_PKCS1_SHA256,
            &REQUESTED_SIGNATURE_SCHEMES
        ));
        assert!(!tls13_signature_scheme_allowed(
            consts::RSA_PSS_RSAE_SHA512,
            &REQUESTED_SIGNATURE_SCHEMES
        ));

        let ck = rcgen::generate_simple_self_signed(vec!["dns.test".to_string()]).unwrap();
        let peer = crate::x509::X509::parse(ck.cert.der().as_ref()).unwrap();
        let secret = p256::SecretKey::from_pkcs8_der(&ck.key_pair.serialize_der()).unwrap();
        let content = certificate_verify_content(&[0x5a; 32], true);
        let signature: Signature = SigningKey::from(secret).sign(&content);
        let cv = |algorithm| CertificateVerify {
            algorithm,
            signature: signature.to_der().as_bytes().to_vec(),
        };

        assert_eq!(
            cv(consts::ECDSA_SECP256R1_SHA256).verify_tls13(
                &peer,
                &[consts::ECDSA_SECP256R1_SHA256],
                &content
            ),
            Ok(())
        );
        assert_eq!(
            cv(consts::ECDSA_SECP256R1_SHA256).verify_tls13(&peer, &[consts::ED25519], &content),
            Err(TlsError::IllegalParameter),
            "알리지 않은 방식"
        );

        let (rsa_der, rsa_key) = rsa_test_certificate("dns.test");
        let rsa_peer = crate::x509::X509::parse(&rsa_der).unwrap();
        let rsa_cv = |scheme| CertificateVerify {
            algorithm: scheme,
            signature: rsa_test_signer(rsa_key.clone(), scheme)(&content),
        };
        assert_eq!(
            rsa_cv(consts::RSA_PSS_RSAE_SHA256).verify_tls13(
                &rsa_peer,
                &REQUESTED_SIGNATURE_SCHEMES,
                &content
            ),
            Ok(())
        );
        assert_eq!(
            rsa_cv(consts::RSA_PKCS1_SHA256).verify_tls13(
                &rsa_peer,
                &REQUESTED_SIGNATURE_SCHEMES,
                &content
            ),
            Err(TlsError::IllegalParameter),
            "알렸어도 RSA PKCS#1 은 1.3 서명에 쓸 수 없다"
        );
        assert_eq!(
            rsa_cv(consts::RSA_PSS_RSAE_SHA512).verify_tls13(
                &rsa_peer,
                &REQUESTED_SIGNATURE_SCHEMES,
                &content
            ),
            Err(TlsError::IllegalParameter),
            "서명이 맞아도 알리지 않은 방식"
        );
    }

    #[test]
    /**
     * @brief 핸드셰이크 중의 CertificateRequest 를 RFC 8446 대로 확인하는지.
     * @details 문맥이 비어 있지 않으면 illegal_parameter, signature_algorithms 가 없으면
     *          missing_extension 이다.
     */
    fn handshake_certificate_request_needs_empty_context_and_signature_algorithms() {
        let standard = CertificateRequestMsg::standard();
        assert_eq!(
            standard.handshake_signature_algorithms(),
            Ok(REQUESTED_SIGNATURE_SCHEMES.to_vec())
        );
        let with_context = CertificateRequestMsg {
            context: vec![1],
            ..standard
        };
        assert_eq!(
            with_context.handshake_signature_algorithms(),
            Err(TlsError::IllegalParameter)
        );
        let without_algorithms = CertificateRequestMsg {
            context: Vec::new(),
            extensions: Vec::new(),
        };
        assert_eq!(
            without_algorithms.handshake_signature_algorithms(),
            Err(TlsError::MissingExtension)
        );
        let malformed = CertificateRequestMsg {
            context: Vec::new(),
            extensions: vec![crate::msg::Extension::new(
                consts::EXT_SIGNATURE_ALGORITHMS,
                vec![0, 1],
            )],
        };
        assert_eq!(
            malformed.handshake_signature_algorithms(),
            Err(TlsError::Decode)
        );
    }

    #[test]
    /** @brief 서명 대상 배치가 규격과 맞는지. 다르면 다른 구현과 통하지 않는다. */
    fn cv_content_layout() {
        let th = [0xCDu8; 32];
        let c = certificate_verify_content(&th, true);
        assert_eq!(&c[..64], &[0x20u8; 64]);
        assert_eq!(&c[64..64 + 33], b"TLS 1.3, server CertificateVerify");
        assert_eq!(c[64 + 33], 0x00);
        assert_eq!(&c[64 + 34..], &th);

        assert_ne!(certificate_verify_content(&th, false), c);
    }

    #[test]
    /** @brief Ed25519 검증. */
    fn ed25519_certificate_verify() {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let content = certificate_verify_content(&[0x55; 32], true);
        let sig = sk.sign(&content).to_bytes().to_vec();
        let pk = sk.verifying_key().to_bytes().to_vec();
        assert_eq!(
            verify_signature(consts::ED25519, &pk, &content, &sig),
            Ok(())
        );

        let bad = certificate_verify_content(&[0x66; 32], true);
        assert!(verify_signature(consts::ED25519, &pk, &bad, &sig).is_err());
    }

    #[test]
    /** @brief P-256 검증. */
    fn ecdsa_p256_certificate_verify() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        let sk = SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let content = certificate_verify_content(&[0x77; 32], true);
        let sig: Signature = sk.sign(&content);
        let sig_der = sig.to_der().as_bytes().to_vec();
        let pk = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        assert_eq!(
            verify_signature(consts::ECDSA_SECP256R1_SHA256, &pk, &content, &sig_der),
            Ok(())
        );
        let mut bad_sig = sig_der.clone();
        let n = bad_sig.len();
        bad_sig[n - 1] ^= 0xFF;
        assert!(verify_signature(consts::ECDSA_SECP256R1_SHA256, &pk, &content, &bad_sig).is_err());
    }

    #[test]
    /** @brief P-384 검증. */
    fn ecdsa_p384_certificate_verify() {
        use p384::ecdsa::{signature::Signer, Signature, SigningKey};
        let sk = SigningKey::from_slice(&[0x37u8; 48]).unwrap();
        let content = certificate_verify_content(&[0x88; 48], true);
        let sig: Signature = sk.sign(&content);
        let sig_der = sig.to_der().as_bytes().to_vec();
        let pk = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        assert_eq!(pk.len(), 97);
        assert_eq!(
            verify_signature(consts::ECDSA_SECP384R1_SHA384, &pk, &content, &sig_der),
            Ok(())
        );
        let mut bad = sig_der.clone();
        let n = bad.len();
        bad[n - 1] ^= 0xFF;
        assert!(verify_signature(consts::ECDSA_SECP384R1_SHA384, &pk, &content, &bad).is_err());
    }

    #[test]
    /** @brief 모르는 서명 방식을 거부하는지. */
    fn unknown_scheme_rejected() {
        assert!(matches!(
            verify_signature(0, &[1, 2, 3], b"x", &[4, 5, 6]),
            Err(TlsError::UnsupportedSig(0))
        ));
    }

    #[test]
    /** @brief 지금 쓰는 모든 RSA 방식이 검증되는지. */
    fn rsa_certificate_verify_all_current_schemes() {
        use onetdns_core::rsa::testsign::TestRsaKey;

        let private_der = crate::trust::base64_decode(include_bytes!(
            "../../../testdata/rsa_test_private_key_2048.pk8.b64"
        ))
        .unwrap();
        let key = TestRsaKey::from_pkcs8(&private_der).unwrap();
        let pk_der = key.public_key_der();
        let content = certificate_verify_content(&[0x99; 32], true);
        let cases = [
            (consts::RSA_PSS_RSAE_SHA256, RsaHash::Sha256, true),
            (consts::RSA_PSS_RSAE_SHA384, RsaHash::Sha384, true),
            (consts::RSA_PSS_RSAE_SHA512, RsaHash::Sha512, true),
            (consts::RSA_PKCS1_SHA256, RsaHash::Sha256, false),
            (consts::RSA_PKCS1_SHA384, RsaHash::Sha384, false),
            (consts::RSA_PKCS1_SHA512, RsaHash::Sha512, false),
        ];
        for (scheme, hash, pss) in cases {
            let mut signature = if pss {
                let salt: Vec<u8> = (0..hash.digest_len() as u8).map(|i| i ^ 0x5a).collect();
                key.sign_pss(hash, &content, &salt)
            } else {
                key.sign_pkcs1(hash, &content)
            };
            assert_eq!(
                verify_signature(scheme, &pk_der, &content, &signature),
                Ok(()),
                "scheme {scheme:#06x}"
            );
            signature[0] ^= 0xff;
            assert!(
                verify_signature(scheme, &pk_der, &content, &signature).is_err(),
                "scheme {scheme:#06x} tamper"
            );
        }
    }
}
