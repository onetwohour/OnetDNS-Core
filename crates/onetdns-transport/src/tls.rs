use std::path::Path;

use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::EncodePrivateKey;

/// Certificate setup errors; all occur at startup.
#[derive(Debug)]
pub enum TlsError {
    Io(String),
    NoCert(String),
    NoKey(String),
    SelfSigned(String),
    /// The private key does not match the certificate.
    Mismatch(String),
}

impl std::fmt::Display for TlsError {
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

/// Uses the shortest long form from 0x80 up.
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
    tlv(0x30, content)
}

/// DER requires the minimal length: a leading 0x00 only when the next byte has its top bit set,
/// since without it the value reads as negative, and strict parsers reject any other leading zero.
/// Leading zeros in `magnitude` are dropped; zero encodes as one byte.
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

/// ecdsa-with-SHA256; certificates made here are P-256 only.
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

const OID_CN: &[u8] = &[0x55, 0x04, 0x03];

/// Modern clients read subjectAltName, not the CN.
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];

/// SubjectPublicKeyInfo header for an uncompressed P-256 point; curve and length are fixed.
const SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

fn x509_name(cn: &str) -> Vec<u8> {
    let attr = {
        let mut c = tlv(0x06, OID_CN);
        c.extend(tlv(0x0c, cn.as_bytes()));
        seq(&c)
    };
    seq(&tlv(0x31, &attr))
}

/// ECDSA omits the parameters.
fn sig_alg() -> Vec<u8> {
    seq(&tlv(0x06, OID_ECDSA_SHA256))
}

fn san_ext(host: &str) -> Vec<u8> {
    let san_value = seq(&tlv(0x82, host.as_bytes()));
    let mut c = tlv(0x06, OID_SAN);
    c.extend(tlv(0x04, &san_value));
    seq(&c)
}

/// A self-signed P-256 certificate and its PKCS#8 key, in DER. The serial is 16 random bytes kept
/// positive. The validity practically never expires: trust in a self-signed certificate comes from
/// the operator accepting it, not from its dates. The key is drawn in a loop because a random
/// 32-byte value can fall outside the group order, and reducing it would bias the key.
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

    let point = secret.public_key().to_sec1_point(false);
    let mut spki = SPKI_PREFIX.to_vec();
    spki.extend_from_slice(point.as_bytes());

    let version = tlv(0xa0, &tlv(0x02, &[0x02]));
    let mut rnd = [0u8; 16];
    onetdns_tls::sys::fill_random(&mut rnd);
    // A zero first byte would be stripped and shorten the serial.
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

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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

/// Skips line breaks and stops at the first `=`; `None` on any other character outside the
/// alphabet.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
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

/// Every block with the label, in order: a chain needs its intermediates.
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

/// Accepts PKCS#8 and SEC1 (`EC PRIVATE KEY`) and returns PKCS#8, so callers handle one format.
fn key_der_from_pem(pem: &str) -> Option<Vec<u8>> {
    if let Some(d) = pem_blocks(pem, "PRIVATE KEY").into_iter().next() {
        return Some(d);
    }

    let sec1 = pem_blocks(pem, "EC PRIVATE KEY").into_iter().next()?;
    let secret = p256::SecretKey::from_sec1_der(&sec1).ok()?;
    Some(secret.to_pkcs8_der().ok()?.as_bytes().to_vec())
}

fn der_to_pem(der: &[u8], label: &str) -> String {
    let b64 = b64_encode(der);
    let mut body = String::new();
    for line in b64.as_bytes().chunks(64) {
        body.push_str(&String::from_utf8_lossy(line));
        body.push('\n');
    }
    format!("-----BEGIN {label}-----\n{body}-----END {label}-----\n")
}

/// Returns a one-certificate chain and the PKCS#8 key.
pub fn self_signed_material(hostname: &str) -> Result<(Vec<Vec<u8>>, Vec<u8>), TlsError> {
    let (cert, key) = generate_der(hostname)?;
    Ok((vec![cert], key))
}

pub fn generate_self_signed_pem(hostname: &str) -> Result<(String, String), TlsError> {
    let (cert, key) = generate_der(hostname)?;
    Ok((
        der_to_pem(&cert, "CERTIFICATE"),
        der_to_pem(&key, "PRIVATE KEY"),
    ))
}

pub fn parse_pem(cert_pem: &str, key_pem: &str) -> Result<(Vec<Vec<u8>>, Vec<u8>), TlsError> {
    let certs = pem_blocks(cert_pem, "CERTIFICATE");
    if certs.is_empty() {
        return Err(TlsError::NoCert("(inline PEM)".to_string()));
    }
    let key =
        key_der_from_pem(key_pem).ok_or_else(|| TlsError::NoKey("(inline PEM)".to_string()))?;
    Ok((certs, key))
}

/// A mismatched pair starts but fails every handshake, so it is caught before the listener opens.
pub fn verify_key_matches_cert(cert_der: &[u8], key_pkcs8_der: &[u8]) -> Result<(), TlsError> {
    use p256::elliptic_curve::sec1::ToSec1Point;
    use p256::pkcs8::DecodePrivateKey;
    let secret = p256::SecretKey::from_pkcs8_der(key_pkcs8_der)
        .map_err(|e| TlsError::NoKey(format!("Could not parse PKCS#8 P-256 private key: {e}")))?;
    let point = secret.public_key().to_sec1_point(false);
    let x = onetdns_tls::X509::parse(cert_der)
        .map_err(|e| TlsError::NoCert(format!("Could not parse X.509: {e:?}")))?;
    if x.public_key != point.as_bytes() {
        return Err(TlsError::Mismatch(
            "Private key does not match the certificate public key".to_string(),
        ));
    }
    Ok(())
}

const MAX_CERT_PEM: u64 = 4 * 1024 * 1024;

const MAX_KEY_PEM: u64 = 1024 * 1024;

/// Checks the metadata size and also caps the read: a pipe or device reports size 0.
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
mod tests {
    use super::*;

    #[test]
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
    /// Generates several certificates so both top-bit cases occur. This side's parser and GnuTLS
    /// accept redundant padding, so only this test catches it.
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

    /// The serial's content bytes. Only short-form lengths occur here.
    fn first_serial_content(der: &[u8]) -> Vec<u8> {
        let mut i = 0usize;
        // Certificate, then TBSCertificate.
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
    fn self_signed_parses_with_onetdns_tls() {
        let (certs, key) = self_signed_material("dns.example.test").unwrap();
        assert_eq!(certs.len(), 1);

        let x = onetdns_tls::X509::parse(&certs[0]).expect("X.509 파싱");
        assert!(x.matches_hostname("dns.example.test"), "SAN dNSName 매칭");

        assert!(onetdns_tls::ServerConfig::from_pkcs8(certs[0].clone(), &key).is_some());
    }

    #[test]
    fn pem_roundtrip() {
        let (cert_pem, key_pem) = generate_self_signed_pem("h.test").unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        let certs = pem_blocks(&cert_pem, "CERTIFICATE");
        assert_eq!(certs.len(), 1);
        let key = key_der_from_pem(&key_pem).unwrap();
        assert!(onetdns_tls::ServerConfig::from_pkcs8(certs[0].clone(), &key).is_some());
    }

    #[test]
    fn b64_known_vectors() {
        assert_eq!(b64_encode(b"abc"), "YWJj");
        assert_eq!(b64_encode(b"a"), "YQ==");
        assert_eq!(b64_decode("YWJj").unwrap(), b"abc");
    }

    #[test]
    fn key_cert_match_detects_mismatch() {
        let (certs, key) = self_signed_material("match.test").unwrap();

        assert!(verify_key_matches_cert(&certs[0], &key).is_ok());

        let (_other_certs, other_key) = self_signed_material("other.test").unwrap();
        assert!(verify_key_matches_cert(&certs[0], &other_key).is_err());
    }
}
