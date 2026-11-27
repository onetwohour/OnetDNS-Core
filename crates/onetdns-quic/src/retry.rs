//! Retry packets and address validation tokens. Before a connection opens, the client shows it can
//! receive at its address, so a spoofed source cannot make this side send large replies to someone
//! else.
//!
//! Tokens are authenticated; a client that could forge one would skip validation.

use std::net::IpAddr;

use sha2::{Digest, Sha256};

use crate::packet::{ptype, VERSION_1};
use crate::protect::Aead;

/// Bump when the token format changes.
const TOKEN_VERSION: u8 = 1;
/// Short, to narrow the window for reuse.
const TOKEN_TTL_SECS: u64 = 30;
const TOKEN_TAG_LEN: usize = 16;
/// Fixed by RFC 9001.
const RETRY_INTEGRITY_KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
/// Fixed by RFC 9001.
const RETRY_INTEGRITY_NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

#[derive(Clone)]
/// Issues and checks tokens; generated per process.
pub struct RetryKey([u8; 32]);

/// Fields read from an Initial packet before decryption.
pub struct InitialHeader<'a> {
    pub dcid: &'a [u8],
    pub scid: &'a [u8],
    pub token: &'a [u8],
}

impl RetryKey {
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        onetdns_tls::sys::fill_random(&mut key);
        Self(key)
    }

    /// Binds the token to the client address, the original connection ID, and the time, and
    /// authenticates all of it.
    pub fn issue(&self, ip: IpAddr, odcid: &[u8], retry_scid: &[u8], now: u64) -> Vec<u8> {
        let mut token = Vec::with_capacity(64);
        token.push(TOKEN_VERSION);
        token.extend_from_slice(&now.to_be_bytes());
        encode_ip(&mut token, ip);
        token.push(odcid.len() as u8);
        token.extend_from_slice(odcid);
        token.push(retry_scid.len() as u8);
        token.extend_from_slice(retry_scid);
        let tag = hmac_sha256(&self.0, &token);
        token.extend_from_slice(&tag[..TOKEN_TAG_LEN]);
        token
    }

    /// Returns the original destination connection ID when the token is valid for this address now.
    pub fn validate(&self, token: &[u8], ip: IpAddr, dcid: &[u8], now: u64) -> Option<Vec<u8>> {
        if token.len() < 1 + 8 + 1 + 4 + 1 + 1 + TOKEN_TAG_LEN {
            return None;
        }
        let (body, tag) = token.split_at(token.len().checked_sub(TOKEN_TAG_LEN)?);
        let expected = hmac_sha256(&self.0, body);
        if !ct_eq(tag, &expected[..TOKEN_TAG_LEN]) {
            return None;
        }
        let mut pos = 0;
        if *body.get(pos)? != TOKEN_VERSION {
            return None;
        }
        pos += 1;
        let issued = u64::from_be_bytes(body.get(pos..pos + 8)?.try_into().ok()?);
        pos += 8;
        if issued > now.saturating_add(5) || now.saturating_sub(issued) > TOKEN_TTL_SECS {
            return None;
        }
        let (bound_ip, used) = decode_ip(body.get(pos..)?)?;
        pos += used;
        if bound_ip != ip {
            return None;
        }
        let odcid_len = *body.get(pos)? as usize;
        pos += 1;
        if odcid_len == 0 || odcid_len > 20 {
            return None;
        }
        let odcid = body.get(pos..pos + odcid_len)?.to_vec();
        pos += odcid_len;
        let retry_len = *body.get(pos)? as usize;
        pos += 1;
        if retry_len == 0 || retry_len > 20 || pos + retry_len != body.len() {
            return None;
        }
        if !ct_eq(body.get(pos..pos + retry_len)?, dcid) {
            return None;
        }
        Some(odcid)
    }
}

pub fn parse_initial_header(packet: &[u8]) -> Option<InitialHeader<'_>> {
    let first = *packet.first()?;
    if first & 0xc0 != 0xc0 || ((first & 0x30) >> 4) != ptype::INITIAL {
        return None;
    }
    if packet.get(1..5)? != VERSION_1.to_be_bytes() {
        return None;
    }
    let mut pos = 5;
    let dcid_len = *packet.get(pos)? as usize;
    pos += 1;
    if dcid_len == 0 || dcid_len > 20 {
        return None;
    }
    let dcid = packet.get(pos..pos + dcid_len)?;
    pos += dcid_len;
    let scid_len = *packet.get(pos)? as usize;
    pos += 1;
    // A zero-length source connection ID is valid and msquic uses one by default; rejecting it
    // would drop those clients' Initial packets silently.
    if scid_len > 20 {
        return None;
    }
    let scid = packet.get(pos..pos + scid_len)?;
    pos += scid_len;
    let (token_len, used) = crate::varint::read(packet.get(pos..)?)?;
    let token_len = usize::try_from(token_len).ok()?;
    if token_len > 256 {
        return None;
    }
    pos += used;
    let token = packet.get(pos..pos + token_len)?;
    Some(InitialHeader { dcid, scid, token })
}

pub fn build_retry(odcid: &[u8], client_scid: &[u8], retry_scid: &[u8], token: &[u8]) -> Vec<u8> {
    let mut packet =
        Vec::with_capacity(7 + client_scid.len() + retry_scid.len() + token.len() + 16);
    packet.push(0xf0);
    packet.extend_from_slice(&VERSION_1.to_be_bytes());
    packet.push(client_scid.len() as u8);
    packet.extend_from_slice(client_scid);
    packet.push(retry_scid.len() as u8);
    packet.extend_from_slice(retry_scid);
    packet.extend_from_slice(token);
    let mut aad = Vec::with_capacity(1 + odcid.len() + packet.len());
    aad.push(odcid.len() as u8);
    aad.extend_from_slice(odcid);
    aad.extend_from_slice(&packet);
    let tag = Aead::Aes128Gcm.seal(&RETRY_INTEGRITY_KEY, &RETRY_INTEGRITY_NONCE, 0, &aad, &[]);
    packet.extend_from_slice(&tag);
    packet
}

/// The tag shows the sender saw the client's Initial; without this check, an off-path attacker
/// could inject a Retry.
pub(crate) fn verify_integrity(odcid: &[u8], packet: &[u8]) -> bool {
    if packet.len() < 16 {
        return false;
    }
    let (body, tag) = packet.split_at(packet.len() - 16);
    let mut aad = Vec::with_capacity(1 + odcid.len() + body.len());
    aad.push(odcid.len() as u8);
    aad.extend_from_slice(odcid);
    aad.extend_from_slice(body);
    let expected = Aead::Aes128Gcm.seal(&RETRY_INTEGRITY_KEY, &RETRY_INTEGRITY_NONCE, 0, &aad, &[]);
    ct_eq(tag, &expected)
}

fn encode_ip(out: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(6);
            out.extend_from_slice(&ip.octets());
        }
    }
}

fn decode_ip(input: &[u8]) -> Option<(IpAddr, usize)> {
    match *input.first()? {
        4 => Some((
            IpAddr::V4(std::net::Ipv4Addr::from(
                <[u8; 4]>::try_from(input.get(1..5)?).ok()?,
            )),
            5,
        )),
        6 => Some((
            IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(input.get(1..17)?).ok()?,
            )),
            17,
        )),
        _ => None,
    }
}

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for index in 0..64 {
        inner_pad[index] ^= block[index];
        outer_pad[index] ^= block[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

/// Constant time; an early return would let timing reveal the tag.
fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9001_a4_retry_integrity_vector() {
        let odcid: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let packet: Vec<u8> = vec![
            0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62,
            0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82,
            0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba,
        ];
        assert!(
            verify_integrity(&odcid, &packet),
            "RFC 9001 A.4 벡터 불일치: 태그 계산이 표준과 다르면 상호운용이 조용히 깨진다"
        );
    }

    #[test]
    fn token_binds_ip_cid_time_and_authentication() {
        let key = RetryKey([7; 32]);
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        let token = key.issue(ip, b"original", b"retrycid", 100);
        assert_eq!(
            key.validate(&token, ip, b"retrycid", 110),
            Some(b"original".to_vec())
        );
        assert!(key
            .validate(&token, "192.0.2.11".parse().unwrap(), b"retrycid", 110)
            .is_none());
        assert!(key.validate(&token, ip, b"othercid", 110).is_none());
        assert!(key.validate(&token, ip, b"retrycid", 131).is_none());
        let mut forged = token;
        forged[3] ^= 1;
        assert!(key.validate(&forged, ip, b"retrycid", 110).is_none());
    }

    #[test]
    fn retry_packet_integrity_binds_original_destination_cid() {
        let mut packet = build_retry(b"original", b"client", b"server", b"token");
        assert!(verify_integrity(b"original", &packet));
        assert!(!verify_integrity(b"different", &packet));
        packet[8] ^= 1;
        assert!(!verify_integrity(b"original", &packet));
    }

    #[test]
    /// msquic clients send this.
    fn initial_header_accepts_zero_length_source_connection_id() {
        let mut packet = vec![0xc0];
        packet.extend_from_slice(&VERSION_1.to_be_bytes());
        packet.push(8);
        packet.extend_from_slice(b"ORIGDCID");
        packet.push(0);
        packet.push(0);
        packet.extend_from_slice(&[0u8; 32]);

        let header = parse_initial_header(&packet).expect("길이 0인 출발지 식별자");
        assert_eq!(header.dcid, b"ORIGDCID");
        assert!(header.scid.is_empty());
        assert!(header.token.is_empty());

        let retry = build_retry(header.dcid, header.scid, b"RETRYCID", b"token");
        assert!(verify_integrity(b"ORIGDCID", &retry));
    }
}
