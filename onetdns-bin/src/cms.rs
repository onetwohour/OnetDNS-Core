//! CMS SignedData (RFC 5652) carrying its content, the form of a signed Apple configuration
//! profile.

use onetdns_tls::der::{context, INTEGER, OCTET_STRING, OID, SET};
use onetdns_tls::msg::consts::ECDSA_SECP256R1_SHA256;
use onetdns_tls::X509;
use sha2::{Digest, Sha256};

use crate::acme::{seq, tlv};

const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
const OID_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
const OID_CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
const OID_MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

/// Signs `content` with the key of `chain[0]` and carries the whole chain. `sign` returns a DER
/// signature under the TLS signature `scheme`; only ECDSA P-256 with SHA-256, the one key type the
/// TLS listeners load, is accepted.
pub(crate) fn signed_data(
    content: &[u8],
    chain: &[Vec<u8>],
    scheme: u16,
    sign: &dyn Fn(&[u8]) -> Vec<u8>,
) -> Result<Vec<u8>, String> {
    if scheme != ECDSA_SECP256R1_SHA256 {
        return Err(format!(
            "Cannot sign with the key of this certificate (TLS signature scheme {scheme:#06x})"
        ));
    }
    let leaf = chain.first().ok_or("The certificate chain is empty")?;
    let leaf = X509::parse(leaf)
        .map_err(|error| format!("Could not parse the signing certificate: {error:?}"))?;
    let sha256 = seq(&tlv(OID, OID_SHA256));

    let attributes = set_of_content(vec![
        attribute(OID_CONTENT_TYPE, &tlv(OID, OID_DATA)),
        attribute(
            OID_MESSAGE_DIGEST,
            &tlv(OCTET_STRING, &Sha256::digest(content)),
        ),
    ]);
    // The signature covers the attributes tagged as a SET, not as the [0] they are sent under.
    let signature = sign(&tlv(SET, &attributes));

    let mut signer = tlv(INTEGER, &[1]);
    signer.extend(seq(
        &[leaf.issuer_raw.clone(), tlv(INTEGER, &leaf.serial)].concat()
    ));
    signer.extend_from_slice(&sha256);
    signer.extend(tlv(context(0), &attributes));
    signer.extend(seq(&tlv(OID, OID_ECDSA_SHA256)));
    signer.extend(tlv(OCTET_STRING, &signature));

    let mut signed = tlv(INTEGER, &[1]);
    signed.extend(tlv(SET, &sha256));
    signed.extend(seq(&[
        tlv(OID, OID_DATA),
        tlv(context(0), &tlv(OCTET_STRING, content)),
    ]
    .concat()));
    signed.extend(tlv(context(0), &set_of_content(chain.to_vec())));
    signed.extend(tlv(SET, &seq(&signer)));
    Ok(seq(&[
        tlv(OID, OID_SIGNED_DATA),
        tlv(context(0), &seq(&signed)),
    ]
    .concat()))
}

fn attribute(oid: &[u8], value: &[u8]) -> Vec<u8> {
    seq(&[tlv(OID, oid), tlv(SET, value)].concat())
}

/// DER orders the elements of a SET OF by their encodings.
fn set_of_content(mut elements: Vec<Vec<u8>>) -> Vec<u8> {
    elements.sort();
    elements.concat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use onetdns_tls::der::{Der, SEQUENCE};
    use p256::ecdsa::signature::Verifier;

    const CONTENT: &[u8] = b"<plist version=\"1.0\"><dict/></plist>\n";

    fn elements(content: &[u8]) -> Vec<Vec<u8>> {
        let mut der = Der::new(content);
        let mut out = Vec::new();
        while !der.is_empty() {
            out.push(der.next_raw().unwrap().0.to_vec());
        }
        out
    }

    #[test]
    fn signed_data_carries_the_content_the_chain_and_a_valid_signature() {
        let (chain, key) = onetdns_transport::self_signed_material("dns.example").unwrap();
        let (scheme, sign) = onetdns_tls::conn::signer_from_pkcs8_der(&key).unwrap();
        let out = signed_data(CONTENT, &chain, scheme, &*sign).unwrap();
        let leaf = X509::parse(&chain[0]).unwrap();

        let mut top = Der::new(&out);
        let mut info = Der::new(top.expect(SEQUENCE).unwrap());
        assert!(top.is_empty(), "ContentInfo 뒤에 남는 바이트가 있습니다");
        assert_eq!(info.expect(OID).unwrap(), OID_SIGNED_DATA);
        let mut explicit = Der::new(info.expect(context(0)).unwrap());
        let mut signed = Der::new(explicit.expect(SEQUENCE).unwrap());
        assert!(info.is_empty() && explicit.is_empty());

        assert_eq!(signed.expect(INTEGER).unwrap(), [1]);
        let sha256 = seq(&tlv(OID, OID_SHA256));
        assert_eq!(signed.expect(SET).unwrap(), sha256.as_slice());
        let mut encapsulated = Der::new(signed.expect(SEQUENCE).unwrap());
        assert_eq!(encapsulated.expect(OID).unwrap(), OID_DATA);
        let mut wrapped = Der::new(encapsulated.expect(context(0)).unwrap());
        assert_eq!(wrapped.expect(OCTET_STRING).unwrap(), CONTENT);
        assert_eq!(elements(signed.expect(context(0)).unwrap()), chain);
        let mut signers = Der::new(signed.expect(SET).unwrap());
        let mut signer = Der::new(signers.expect(SEQUENCE).unwrap());
        assert!(signed.is_empty() && signers.is_empty());

        assert_eq!(signer.expect(INTEGER).unwrap(), [1]);
        let mut sid = Der::new(signer.expect(SEQUENCE).unwrap());
        assert_eq!(sid.next_raw().unwrap().0, leaf.issuer_raw.as_slice());
        assert_eq!(sid.expect(INTEGER).unwrap(), leaf.serial.as_slice());
        assert_eq!(signer.next_raw().unwrap().0, sha256.as_slice());
        let attributes = signer.expect(context(0)).unwrap();
        assert_eq!(
            signer.next_raw().unwrap().0,
            seq(&tlv(OID, OID_ECDSA_SHA256)).as_slice()
        );
        let signature = signer.expect(OCTET_STRING).unwrap();
        assert!(signer.is_empty());

        let listed = elements(attributes);
        let mut sorted = listed.clone();
        sorted.sort();
        assert_eq!(listed, sorted, "DER SET OF 순서가 아닙니다");
        assert_eq!(
            listed,
            vec![
                attribute(OID_CONTENT_TYPE, &tlv(OID, OID_DATA)),
                attribute(
                    OID_MESSAGE_DIGEST,
                    &tlv(OCTET_STRING, &Sha256::digest(CONTENT))
                ),
            ]
        );

        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&leaf.public_key).unwrap();
        let signature = p256::ecdsa::Signature::from_der(signature).unwrap();
        assert!(
            key.verify(&tlv(SET, attributes), &signature).is_ok(),
            "서명이 SET 태그의 서명 속성을 덮지 않습니다"
        );
    }

    #[test]
    fn certificates_are_in_der_set_order() {
        let (mut chain, _) = onetdns_transport::self_signed_material("dns.example").unwrap();
        let (other, _) = onetdns_transport::self_signed_material("other.example").unwrap();
        chain.extend(other);
        chain.sort();
        chain.reverse();
        let sign = |_: &[u8]| Vec::new();
        let out = signed_data(CONTENT, &chain, ECDSA_SECP256R1_SHA256, &sign).unwrap();
        let mut sorted = chain.clone();
        sorted.sort();
        let tagged = tlv(context(0), &sorted.concat());
        assert!(
            out.windows(tagged.len())
                .any(|window| window == tagged.as_slice()),
            "인증서 집합이 정렬되지 않았습니다"
        );
    }

    #[test]
    fn a_key_other_than_p256_is_refused() {
        let (chain, _) = onetdns_transport::self_signed_material("dns.example").unwrap();
        let sign = |_: &[u8]| Vec::new();
        assert!(signed_data(CONTENT, &chain, 0x0503, &sign).is_err());
        assert!(signed_data(CONTENT, &[], ECDSA_SECP256R1_SHA256, &sign).is_err());
    }
}
