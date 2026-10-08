use std::path::Path;

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::EncodePrivateKey;

/** @brief 인증서 준비 중 생길 수 있는 오류. 모두 시작 시점에만 발생한다. */
#[derive(Debug)]
pub enum TlsError {
    /** @brief 파일을 읽고 쓰지 못했다. */
    Io(String),
    /** @brief 인증서를 찾지 못했다. */
    NoCert(String),
    /** @brief 키를 찾지 못했다. */
    NoKey(String),
    /** @brief 자체 서명 인증서를 만들지 못했다. */
    SelfSigned(String),
    /** @brief 인증서의 공개키와 개인키가 다른 쌍이다. 시작 전에 잡아야 하는 설정 실수다. */
    Mismatch(String),
}

impl std::fmt::Display for TlsError {
    /** @brief 사람이 읽을 문구. */
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::Io(s) => write!(f, "Certificate I/O error: {s}"),
            TlsError::NoCert(s) => write!(f, "No certificate found in PEM data: {s}"),
            TlsError::NoKey(s) => write!(f, "No private key found in PEM data: {s}"),
            TlsError::SelfSigned(s) => write!(f, "Could not create a self-signed certificate: {s}"),
            TlsError::Mismatch(s) => write!(f, "Certificate and private key do not match: {s}"),
        }
    }
}

impl std::error::Error for TlsError {}

/** @brief DER 길이 필드를 쓴다. 0x80 이상은 최소 바이트 수의 긴 형식으로 만든다. */
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

/** @brief DER TLV 하나를 만든다. */
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    der_len(content.len(), &mut v);
    v.extend_from_slice(content);
    v
}

/** @brief DER SEQUENCE로 감싼다. */
fn seq(content: &[u8]) -> Vec<u8> {
    tlv(0x30, content)
}

/**
 * @brief 음이 아닌 크기를 DER INTEGER로 만든다.
 *
 * @details DER은 최소 길이를 요구한다. 앞의 0x00은 다음 바이트의 최상위 비트가 설 때만
 *          허용되고, 그 밖의 앞선 0은 잉여 padding이라 엄격한 파서가 거부한다. 반대로
 *          최상위 비트가 섰는데 0을 붙이지 않으면 음수로 읽힌다.
 * @param magnitude 큰 자릿수가 앞에 오는 크기. 앞선 0은 여기서 걷어낸다.
 * @return INTEGER TLV 하나. 크기가 0이면 값 0을 담은 한 바이트가 된다.
 */
fn der_positive_integer(magnitude: &[u8]) -> Vec<u8> {
    let start = magnitude
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(magnitude.len());
    let trimmed = &magnitude[start..];
    if trimmed.is_empty() {
        return tlv(0x02, &[0x00]);
    }
    if trimmed[0] & 0x80 == 0 {
        return tlv(0x02, trimmed);
    }
    let mut content = Vec::with_capacity(trimmed.len() + 1);
    content.push(0x00);
    content.extend_from_slice(trimmed);
    tlv(0x02, &content)
}

/** @brief ecdsa-with-SHA256 OID. 이 크레이트가 만드는 인증서는 P-256만 쓴다. */
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

/** @brief commonName 속성 OID. */
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];

/** @brief subjectAltName 확장 OID. 현대 클라이언트는 CN이 아니라 이쪽만 본다. */
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];

/**
 * @brief 비압축 P-256 공개점 앞에 붙는 SubjectPublicKeyInfo 헤더.
 * @details 곡선과 길이가 고정이라 상수로 둔다. 매번 DER을 조립할 이유가 없다.
 */
const SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/** @brief commonName 하나만 담은 X.509 Name. */
fn x509_name(cn: &str) -> Vec<u8> {
    let attr = {
        let mut c = tlv(0x06, OID_CN);
        c.extend(tlv(0x0c, cn.as_bytes()));
        seq(&c)
    };
    seq(&tlv(0x31, &attr))
}

/** @brief AlgorithmIdentifier. ECDSA는 매개변수를 생략한다. */
fn sig_alg() -> Vec<u8> {
    seq(&tlv(0x06, OID_ECDSA_SHA256))
}

/** @brief dNSName 하나를 담은 subjectAltName 확장. */
fn san_ext(host: &str) -> Vec<u8> {
    let san_value = seq(&tlv(0x82, host.as_bytes()));
    let mut c = tlv(0x06, OID_SAN);
    c.extend(tlv(0x04, &san_value));
    seq(&c)
}

/**
 * @brief 자체 서명 P-256 인증서와 개인키를 DER로 만든다.
 *
 * @details 일련번호는 무작위 16바이트를 DER INTEGER 규칙대로 담아 늘 양수가 되게 한다.
 *          유효 기간은 사실상 만료가 없는 값이다. 자체 서명이라 신뢰의 근거가 기간이
 *          아니라 운영자의 명시적 수용이기 때문이다.
 * @note 키 생성이 루프인 이유는 무작위 32바이트가 곡선 차수 범위를 벗어날 수 있어서다.
 *       벗어난 값을 나머지 연산으로 줄여 쓰면 키 분포가 치우친다.
 */
fn generate_der(hostname: &str) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    let secret = loop {
        let mut b = [0u8; 32];
        onetdns_tls::sys::fill_random(&mut b);
        if let Ok(sk) = p256::SecretKey::from_slice(&b) {
            break sk;
        }
    };
    let signing = SigningKey::from(secret.clone());

    let point = secret.public_key().to_encoded_point(false);
    let mut spki = SPKI_PREFIX.to_vec();
    spki.extend_from_slice(point.as_bytes());

    let version = tlv(0xa0, &tlv(0x02, &[0x02]));
    let mut rnd = [0u8; 16];
    onetdns_tls::sys::fill_random(&mut rnd);
    /* 첫 바이트를 0으로 두지 않는다. 앞선 0을 걷어내면 그만큼 짧은 일련번호가 된다. */
    rnd[0] |= 0x01;
    let serial = der_positive_integer(&rnd);

    let validity = {
        let nb = tlv(0x17, b"200101000000Z");
        let na = tlv(0x17, b"491231235959Z");
        let mut c = nb;
        c.extend(na);
        seq(&c)
    };
    let name = x509_name(hostname);
    let extensions = tlv(0xa3, &seq(&san_ext(hostname)));

    let mut tbs_inner = version;
    tbs_inner.extend(serial);
    tbs_inner.extend(sig_alg());
    tbs_inner.extend(name.clone());
    tbs_inner.extend(validity);
    tbs_inner.extend(name);
    tbs_inner.extend(spki);
    tbs_inner.extend(extensions);
    let tbs = seq(&tbs_inner);

    let sig: Signature = signing.sign(&tbs);
    let sig_der = sig.to_der();
    let mut sig_bits = vec![0x00u8];
    sig_bits.extend_from_slice(sig_der.as_bytes());
    let sig_bitstring = tlv(0x03, &sig_bits);

    let mut cert_inner = tbs;
    cert_inner.extend(sig_alg());
    cert_inner.extend(sig_bitstring);
    let cert_der = seq(&cert_inner);

    let key_der = secret
        .to_pkcs8_der()
        .map_err(|e| TlsError::SelfSigned(e.to_string()))?
        .as_bytes()
        .to_vec();

    Ok((cert_der, key_der))
}

/** @brief PEM이 쓰는 표준 base64 알파벳. */
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** @brief base64로 인코딩한다. 부족한 곳은 =로 채운다. */
fn b64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 0x3f] as char);
        out.push(B64[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/**
 * @brief base64를 디코딩한다. PEM 본문의 줄바꿈을 허용한다.
 * @return 알파벳 밖 문자가 있으면 None. 첫 =에서 멈춘다.
 */
fn b64_decode(s: &str) -> Option<Vec<u8>> {
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
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        if c.is_ascii_whitespace() {
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

/**
 * @brief 해당 라벨의 PEM 블록을 모두 추출한다.
 * @details 인증서 체인은 블록 여러 개로 오므로 순서를 보존해 전부 모은다. 첫 블록만
 *          읽으면 중간 인증서가 빠져 검증이 실패한다.
 */
fn pem_blocks(pem: &str, label: &str) -> Vec<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(b) = rest.find(&begin) {
        let after = &rest[b + begin.len()..];
        let Some(e) = after.find(&end) else { break };
        if let Some(der) = b64_decode(&after[..e]) {
            out.push(der);
        }
        rest = &after[e + end.len()..];
    }
    out
}

/**
 * @brief 개인키 PEM을 PKCS#8 DER로 정규화한다.
 * @details 흔히 쓰이는 SEC1(EC PRIVATE KEY) 형식도 받아 PKCS#8로 바꾼다. 내부 경로는
 *          PKCS#8 하나만 다루게 해 형식 분기를 여기서 끝낸다.
 */
fn key_der_from_pem(pem: &str) -> Option<Vec<u8>> {
    if let Some(d) = pem_blocks(pem, "PRIVATE KEY").into_iter().next() {
        return Some(d);
    }

    let sec1 = pem_blocks(pem, "EC PRIVATE KEY").into_iter().next()?;
    let secret = p256::SecretKey::from_sec1_der(&sec1).ok()?;
    Some(secret.to_pkcs8_der().ok()?.as_bytes().to_vec())
}

/** @brief DER을 64자 줄바꿈이 붙은 PEM으로 감싼다. */
fn der_to_pem(der: &[u8], label: &str) -> String {
    let b64 = b64_encode(der);
    let mut body = String::new();
    for line in b64.as_bytes().chunks(64) {
        body.push_str(&String::from_utf8_lossy(line));
        body.push('\n');
    }
    format!("-----BEGIN {label}-----\n{body}-----END {label}-----\n")
}

/**
 * @brief 자체 서명 인증서 체인과 개인키를 DER로 만든다.
 * @return (인증서 체인, PKCS#8 개인키). 자체 서명이라 체인 길이는 1이다.
 */
pub fn self_signed_material(hostname: &str) -> Result<(Vec<Vec<u8>>, Vec<u8>), TlsError> {
    let (cert, key) = generate_der(hostname)?;
    Ok((vec![cert], key))
}

/** @brief 자체 서명 인증서와 키를 PEM 문자열로 만든다. 파일로 저장할 때 쓴다. */
pub fn generate_self_signed_pem(hostname: &str) -> Result<(String, String), TlsError> {
    let (cert, key) = generate_der(hostname)?;
    Ok((
        der_to_pem(&cert, "CERTIFICATE"),
        der_to_pem(&key, "PRIVATE KEY"),
    ))
}

/** @brief 인라인 PEM 문자열에서 인증서 체인과 키를 읽는다. */
pub fn parse_pem(cert_pem: &str, key_pem: &str) -> Result<(Vec<Vec<u8>>, Vec<u8>), TlsError> {
    let certs = pem_blocks(cert_pem, "CERTIFICATE");
    if certs.is_empty() {
        return Err(TlsError::NoCert("(inline PEM)".to_string()));
    }
    let key =
        key_der_from_pem(key_pem).ok_or_else(|| TlsError::NoKey("(inline PEM)".to_string()))?;
    Ok((certs, key))
}

/**
 * @brief 개인키가 인증서의 공개키와 같은 쌍인지 확인한다.
 * @details 어긋난 쌍은 시작은 되지만 모든 핸드셰이크가 실패한다. 리스너를 열기 전에
 *          잡아야 설정 실수가 조용한 전면 장애로 이어지지 않는다.
 */
pub fn verify_key_matches_cert(cert_der: &[u8], key_pkcs8_der: &[u8]) -> Result<(), TlsError> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::DecodePrivateKey;
    let secret = p256::SecretKey::from_pkcs8_der(key_pkcs8_der)
        .map_err(|e| TlsError::NoKey(format!("Could not parse PKCS#8 P-256 private key: {e}")))?;
    let point = secret.public_key().to_encoded_point(false);
    let x = onetdns_tls::X509::parse(cert_der)
        .map_err(|e| TlsError::NoCert(format!("Could not parse X.509: {e:?}")))?;
    if x.public_key != point.as_bytes() {
        return Err(TlsError::Mismatch(
            "Private key does not match the certificate public key".to_string(),
        ));
    }
    Ok(())
}

/** @brief 인증서 PEM 파일 크기 상한. */
const MAX_CERT_PEM: u64 = 4 * 1024 * 1024;

/** @brief 개인키 PEM 파일 크기 상한. */
const MAX_KEY_PEM: u64 = 1024 * 1024;

/**
 * @brief 크기 상한을 지키며 PEM 파일을 읽는다.
 * @details 메타데이터로 한 번 거르고 읽기 자체도 take로 막는다. 경로가 파이프나 장치
 *          파일을 가리키면 메타데이터 크기가 0이라 첫 검사만으로는 무한 읽기를 못 막는다.
 */
fn read_pem_limited(path: &Path, max: u64) -> Result<String, TlsError> {
    use std::io::Read;
    let meta =
        std::fs::metadata(path).map_err(|e| TlsError::Io(format!("{}: {e}", path.display())))?;
    if !meta.is_file() || meta.len() > max {
        return Err(TlsError::Io(format!(
            "{}: PEM file size or format is out of range",
            path.display()
        )));
    }
    let file =
        std::fs::File::open(path).map_err(|e| TlsError::Io(format!("{}: {e}", path.display())))?;
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| TlsError::Io(format!("{}: {e}", path.display())))?;
    if bytes.len() as u64 > max {
        return Err(TlsError::Io(format!(
            "{}: PEM file is too large",
            path.display()
        )));
    }
    String::from_utf8(bytes)
        .map_err(|_| TlsError::Io(format!("{}: PEM is not valid UTF-8", path.display())))
}

/** @brief 파일에서 인증서 체인과 개인키를 읽는다. */
pub fn load_pem(cert_path: &Path, key_path: &Path) -> Result<(Vec<Vec<u8>>, Vec<u8>), TlsError> {
    let cert_pem = read_pem_limited(cert_path, MAX_CERT_PEM)?;
    let certs = pem_blocks(&cert_pem, "CERTIFICATE");
    if certs.is_empty() {
        return Err(TlsError::NoCert(cert_path.display().to_string()));
    }
    let key_pem = read_pem_limited(key_path, MAX_KEY_PEM)?;
    let key = key_der_from_pem(&key_pem)
        .ok_or_else(|| TlsError::NoKey(key_path.display().to_string()))?;
    Ok((certs, key))
}

#[cfg(test)]
/** @brief 자체 서명 인증서가 이쪽 TLS에 읽히고, 키와 짝이 맞는지. */
mod tests {
    use super::*;

    #[test]
    /**
     * @brief INTEGER가 DER의 최소 길이 규칙을 지키는지.
     *
     * @details 앞의 0x00은 다음 바이트의 최상위 비트가 설 때만 허용된다. 잉여로 붙이면
     *          OpenSSL 계열이 illegal padding으로 거부하고, 필요한데 빠뜨리면 음수로 읽힌다.
     */
    fn integers_are_encoded_at_minimum_length() {
        assert_eq!(der_positive_integer(&[0x7f]), vec![0x02, 0x01, 0x7f]);
        assert_eq!(
            der_positive_integer(&[0x80]),
            vec![0x02, 0x02, 0x00, 0x80],
            "최상위 비트가 서면 0을 붙여 양수로 만든다"
        );
        assert_eq!(
            der_positive_integer(&[0x00, 0x7f]),
            vec![0x02, 0x01, 0x7f],
            "잉여 0은 걷어낸다"
        );
        assert_eq!(
            der_positive_integer(&[0x00, 0x80]),
            vec![0x02, 0x02, 0x00, 0x80],
            "걷어낸 뒤 다시 필요하면 하나만 붙인다"
        );
        assert_eq!(der_positive_integer(&[]), vec![0x02, 0x01, 0x00]);
        assert_eq!(der_positive_integer(&[0x00, 0x00]), vec![0x02, 0x01, 0x00]);
    }

    #[test]
    /**
     * @brief 만들어 낸 인증서의 일련번호가 늘 최소 길이인지.
     *
     * @details 일련번호는 난수라 한 번 만들어 보는 것으로는 절반만 밟는다. 여러 번 만들어
     *          첫 바이트가 양쪽으로 나오는 것을 확인하고, 매번 규칙을 지키는지 본다.
     * @note 이쪽 파서와 GnuTLS는 잉여 padding을 통과시키므로 이 검사가 유일한 방어다.
     */
    fn every_generated_serial_is_minimal_der() {
        let mut saw_high_bit = false;
        let mut saw_low_bit = false;
        for _ in 0..64 {
            let (certs, _key) = self_signed_material("serial.example.test").unwrap();
            let content = first_serial_content(&certs[0]);
            assert!(!content.is_empty(), "일련번호가 비었습니다");
            assert!(
                content[0] & 0x80 == 0,
                "일련번호가 음수로 읽힙니다: {content:02x?}"
            );
            if content[0] == 0x00 {
                saw_high_bit = true;
                assert!(
                    content.len() >= 2 && content[1] & 0x80 != 0,
                    "잉여 padding입니다: {content:02x?}"
                );
            } else {
                saw_low_bit = true;
            }
        }
        assert!(saw_high_bit && saw_low_bit, "난수가 한쪽으로만 나왔습니다");
    }

    /**
     * @brief 인증서 DER에서 첫 INTEGER, 곧 일련번호의 내용을 꺼낸다.
     * @details Certificate SEQUENCE 안의 TBSCertificate SEQUENCE를 열고, 버전을 담은
     *          컨텍스트 태그를 건너뛴 다음 INTEGER를 읽는다. 길이는 짧은 형식만 나온다.
     */
    fn first_serial_content(der: &[u8]) -> Vec<u8> {
        let mut i = 0usize;
        /* Certificate SEQUENCE, TBSCertificate SEQUENCE 두 겹을 연다. */
        for _ in 0..2 {
            assert_eq!(der[i], 0x30, "SEQUENCE를 기대했습니다");
            i += 1;
            i += if der[i] & 0x80 == 0 {
                1
            } else {
                1 + (der[i] & 0x7f) as usize
            };
        }
        if der[i] == 0xa0 {
            let len = der[i + 1] as usize;
            i += 2 + len;
        }
        assert_eq!(der[i], 0x02, "일련번호 INTEGER를 기대했습니다");
        let len = der[i + 1] as usize;
        der[i + 2..i + 2 + len].to_vec()
    }

    #[test]
    /** @brief 이쪽이 만든 인증서를 이쪽 TLS가 읽는지. */
    fn self_signed_parses_with_onetdns_tls() {
        let (certs, key) = self_signed_material("dns.example.test").unwrap();
        assert_eq!(certs.len(), 1);

        let x = onetdns_tls::X509::parse(&certs[0]).expect("X.509 파싱");
        assert!(x.matches_hostname("dns.example.test"), "SAN dNSName 매칭");

        assert!(onetdns_tls::ServerConfig::from_pkcs8(certs[0].clone(), &key).is_some());
    }

    #[test]
    /** @brief PEM 표기의 왕복. */
    fn pem_roundtrip() {
        let (cert_pem, key_pem) = generate_self_signed_pem("h.test").unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        let certs = pem_blocks(&cert_pem, "CERTIFICATE");
        assert_eq!(certs.len(), 1);
        let key = key_der_from_pem(&key_pem).unwrap();
        assert!(onetdns_tls::ServerConfig::from_pkcs8(certs[0].clone(), &key).is_some());
    }

    #[test]
    /** @brief base64가 알려진 값과 맞는지. */
    fn b64_known_vectors() {
        assert_eq!(b64_encode(b"abc"), "YWJj");
        assert_eq!(b64_encode(b"a"), "YQ==");
        assert_eq!(b64_decode("YWJj").unwrap(), b"abc");
    }

    #[test]
    /** @brief 인증서와 키가 짝이 아니면 알아채는지. 모르고 쓰면 핸드셰이크가 전부 실패한다. */
    fn key_cert_match_detects_mismatch() {
        let (certs, key) = self_signed_material("match.test").unwrap();

        assert!(verify_key_matches_cert(&certs[0], &key).is_ok());

        let (_other_certs, other_key) = self_signed_material("other.test").unwrap();
        assert!(verify_key_matches_cert(&certs[0], &other_key).is_err());
    }
}
