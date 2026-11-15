//! QUIC packet header encoding and parsing. Long headers are used during the handshake, short
//! headers after it.
//!
//! The parser reads unauthenticated bytes: every length and connection ID size is checked, and no
//! input may panic.

use crate::protect::Aead;
use crate::varint;
use crate::PacketKeys;

pub const VERSION_1: u32 = 0x0000_0001;

pub mod ptype {
    pub const INITIAL: u8 = 0x00;
    pub const ZERO_RTT: u8 = 0x01;
    pub const HANDSHAKE: u8 = 0x02;
    pub const RETRY: u8 = 0x03;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongPacket {
    pub ptype: u8,
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
    pub pn: u64,
    pub payload: Vec<u8>,

    /// Bytes this packet took from the datagram; coalesced packets may follow.
    pub consumed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortPacket {
    pub dcid: Vec<u8>,
    pub pn: u64,
    pub payload: Vec<u8>,
}

/// Read before decryption to find the connection. Short headers carry no length, so `short_cid_len`
/// is the length this side issues.
pub fn destination_connection_id(pkt: &[u8], short_cid_len: usize) -> Option<&[u8]> {
    let first = *pkt.first()?;
    if first & 0x40 == 0 {
        return None;
    }
    if first & 0x80 != 0 {
        if pkt.len() < 6 {
            return None;
        }
        let len = *pkt.get(5)? as usize;
        if len > 20 {
            return None;
        }
        pkt.get(6..6usize.checked_add(len)?)
    } else {
        if short_cid_len == 0 || short_cid_len > 20 {
            return None;
        }
        pkt.get(1..1usize.checked_add(short_cid_len)?)
    }
}

pub fn is_initial_packet(pkt: &[u8]) -> bool {
    pkt.first()
        .is_some_and(|first| first & 0xc0 == 0xc0 && ((first & 0x30) >> 4) == ptype::INITIAL)
        && pkt.get(1..5).is_some_and(|v| v == VERSION_1.to_be_bytes())
}

/// Packet numbers arrive truncated; picks the candidate closest to the largest number seen.
pub fn decode_pn(largest_pn: u64, truncated: u64, pn_nbits: u32) -> u64 {
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;
    let expected = largest_pn.wrapping_add(1);
    let candidate = (expected & !pn_mask) | truncated;
    if candidate + pn_hwin <= expected && candidate + pn_win < (1u64 << 62) {
        candidate + pn_win
    } else if candidate > expected + pn_hwin && candidate >= pn_win {
        candidate - pn_win
    } else {
        candidate
    }
}

#[allow(clippy::too_many_arguments)]
pub fn protect_long(
    aead: Aead,
    keys: &PacketKeys,
    ptype_val: u8,
    dcid: &[u8],
    scid: &[u8],
    token: &[u8],
    pn: u64,
    pn_len: usize,
    payload: &[u8],
) -> Vec<u8> {
    if !(1..=4).contains(&pn_len) || dcid.len() > 20 || scid.len() > 20 || token.len() > 256 {
        return Vec::new();
    }
    let mut pkt = Vec::new();

    let first = 0xc0 | (ptype_val << 4) | ((pn_len - 1) as u8);
    pkt.push(first);
    pkt.extend_from_slice(&VERSION_1.to_be_bytes());
    pkt.push(dcid.len() as u8);
    pkt.extend_from_slice(dcid);
    pkt.push(scid.len() as u8);
    pkt.extend_from_slice(scid);
    if ptype_val == ptype::INITIAL {
        varint::write(&mut pkt, token.len() as u64);
        pkt.extend_from_slice(token);
    }

    let mut plaintext = payload.to_vec();

    plaintext.resize(plaintext.len().max(4usize.saturating_sub(pn_len)), 0);
    varint::write(&mut pkt, (pn_len + plaintext.len() + 16) as u64);
    let pn_offset = pkt.len();
    let pnb = pn.to_be_bytes();
    pkt.extend_from_slice(&pnb[8 - pn_len..]);

    let aad = pkt.clone();
    let ct = aead.seal(&keys.key, &keys.iv, pn, &aad, &plaintext);
    pkt.extend_from_slice(&ct);

    let mut sample = [0u8; 16];
    sample.copy_from_slice(&pkt[pn_offset + 4..pn_offset + 20]);
    let mask = aead.header_mask(&keys.hp, &sample);
    pkt[0] ^= mask[0] & 0x0f;
    for i in 0..pn_len {
        pkt[pn_offset + i] ^= mask[1 + i];
    }
    pkt
}

#[allow(clippy::too_many_arguments)]
pub fn protect_initial(
    aead: Aead,
    keys: &PacketKeys,
    dcid: &[u8],
    scid: &[u8],
    token: &[u8],
    pn: u64,
    pn_len: usize,
    payload: &[u8],
) -> Vec<u8> {
    protect_long(
        aead,
        keys,
        ptype::INITIAL,
        dcid,
        scid,
        token,
        pn,
        pn_len,
        payload,
    )
}

pub fn protect_short(
    aead: Aead,
    keys: &PacketKeys,
    dcid: &[u8],
    pn: u64,
    pn_len: usize,
    payload: &[u8],
    key_phase: bool,
) -> Vec<u8> {
    if !(1..=4).contains(&pn_len) || dcid.len() > 20 {
        return Vec::new();
    }
    let mut pkt = Vec::new();

    let first = 0x40 | (if key_phase { 0x04 } else { 0 }) | ((pn_len - 1) as u8);
    pkt.push(first);
    pkt.extend_from_slice(dcid);
    let pn_offset = pkt.len();
    let pnb = pn.to_be_bytes();
    pkt.extend_from_slice(&pnb[8 - pn_len..]);

    let aad = pkt.clone();
    let mut plaintext = payload.to_vec();
    plaintext.resize(plaintext.len().max(4usize.saturating_sub(pn_len)), 0);
    let ct = aead.seal(&keys.key, &keys.iv, pn, &aad, &plaintext);
    pkt.extend_from_slice(&ct);

    let mut sample = [0u8; 16];
    sample.copy_from_slice(&pkt[pn_offset + 4..pn_offset + 20]);
    let mask = aead.header_mask(&keys.hp, &sample);
    pkt[0] ^= mask[0] & 0x1f;
    for i in 0..pn_len {
        pkt[pn_offset + i] ^= mask[1 + i];
    }
    pkt
}

pub fn unprotect_long(
    aead: Aead,
    keys: &PacketKeys,
    pkt: &[u8],
    largest_pn: u64,
) -> Option<LongPacket> {
    let LongHeader {
        ptype: ptype_val,
        version,
        dcid,
        scid,
        token,
        pn_offset,
        end: pkt_end,
    } = parse_long_header(pkt)?;
    let first0 = pkt[0];

    let sample: [u8; 16] = pkt
        .get(pn_offset + 4..pn_offset + 4 + 16)?
        .try_into()
        .ok()?;
    let mask = aead.header_mask(&keys.hp, &sample);
    let first = first0 ^ (mask[0] & 0x0f);
    let pn_len = ((first & 0x03) + 1) as usize;
    let (pn, pn_bytes) = unmask_pn(pkt, pn_offset, pn_len, &mask, largest_pn)?;

    let mut aad = pkt.get(..pn_offset + pn_len)?.to_vec();
    aad[0] = first;
    aad[pn_offset..pn_offset + pn_len].copy_from_slice(&pn_bytes[..pn_len]);
    let ct = pkt.get(pn_offset + pn_len..pkt_end)?;
    let payload = aead.open(&keys.key, &keys.iv, pn, &aad, ct)?;
    Some(LongPacket {
        ptype: ptype_val,
        version,
        dcid: dcid.to_vec(),
        scid: scid.to_vec(),
        token: token.to_vec(),
        pn,
        payload,
        consumed: pkt_end,
    })
}

/// Long header fields readable before decryption.
struct LongHeader<'a> {
    ptype: u8,
    version: u32,
    dcid: &'a [u8],
    scid: &'a [u8],
    /// Empty unless Initial.
    token: &'a [u8],
    pn_offset: usize,
    /// Coalesced packets may follow.
    end: usize,
}

/// Reads up to the length field. Retry has no length field, so it is refused.
fn parse_long_header(pkt: &[u8]) -> Option<LongHeader<'_>> {
    let first = *pkt.first()?;
    if first & 0x80 == 0 {
        return None;
    }
    let ptype_val = (first & 0x30) >> 4;
    if ptype_val == ptype::RETRY {
        return None;
    }
    let mut pos = 1usize;
    let version = u32::from_be_bytes(pkt.get(pos..pos + 4)?.try_into().ok()?);
    pos += 4;
    let dcid_len = *pkt.get(pos)? as usize;
    if dcid_len > 20 {
        return None;
    }
    pos += 1;
    let dcid = pkt.get(pos..pos + dcid_len)?;
    pos += dcid_len;
    let scid_len = *pkt.get(pos)? as usize;
    if scid_len > 20 {
        return None;
    }
    pos += 1;
    let scid = pkt.get(pos..pos + scid_len)?;
    pos += scid_len;
    let token: &[u8] = if ptype_val == ptype::INITIAL {
        let (tl, n) = varint::read(pkt.get(pos..)?)?;
        let tl = usize::try_from(tl).ok()?;
        if tl > 256 {
            return None;
        }
        pos += n;
        let t = pkt.get(pos..pos + tl)?;
        pos += tl;
        t
    } else {
        &[]
    };
    let (length, n) = varint::read(pkt.get(pos..)?)?;
    pos += n;
    let end = pos.checked_add(usize::try_from(length).ok()?)?;
    if end > pkt.len() {
        return None;
    }
    Some(LongHeader {
        ptype: ptype_val,
        version,
        dcid,
        scid,
        token,
        pn_offset: pos,
        end,
    })
}

/// Lets the caller skip a packet it cannot decrypt and go on with the packets coalesced after it,
/// as RFC 9000 requires; dropping those stalls the handshake. None for a broken header or a Retry.
pub fn long_packet_len(pkt: &[u8]) -> Option<usize> {
    parse_long_header(pkt).map(|header| header.end)
}

pub fn unprotect_short(
    aead: Aead,
    keys: &PacketKeys,
    alt_keys: Option<&PacketKeys>,
    expected_phase: bool,
    pkt: &[u8],
    dcid_len: usize,
    largest_pn: u64,
) -> Option<(ShortPacket, bool)> {
    let first0 = *pkt.first()?;
    if first0 & 0x80 != 0 {
        return None;
    }
    let dcid = pkt.get(1..1 + dcid_len)?.to_vec();
    let pn_offset = 1 + dcid_len;

    let sample: [u8; 16] = pkt
        .get(pn_offset + 4..pn_offset + 4 + 16)?
        .try_into()
        .ok()?;
    let mask = aead.header_mask(&keys.hp, &sample);
    let first = first0 ^ (mask[0] & 0x1f);
    let pn_len = ((first & 0x03) + 1) as usize;
    let key_phase = first & 0x04 != 0;
    let (pn, pn_bytes) = unmask_pn(pkt, pn_offset, pn_len, &mask, largest_pn)?;

    let mut aad = pkt.get(..pn_offset + pn_len)?.to_vec();
    aad[0] = first;
    aad[pn_offset..pn_offset + pn_len].copy_from_slice(&pn_bytes[..pn_len]);
    let ct = pkt.get(pn_offset + pn_len..)?;

    let phase_changed = key_phase != expected_phase;
    let pk = if phase_changed { alt_keys? } else { keys };
    let payload = aead.open(&pk.key, &pk.iv, pn, &aad, ct)?;
    Some((ShortPacket { dcid, pn, payload }, phase_changed))
}

fn unmask_pn(
    pkt: &[u8],
    pn_offset: usize,
    pn_len: usize,
    mask: &[u8; 5],
    largest_pn: u64,
) -> Option<(u64, [u8; 4])> {
    let mut truncated = 0u64;
    let mut pn_bytes = [0u8; 4];
    for i in 0..pn_len {
        pn_bytes[i] = pkt.get(pn_offset + i)? ^ mask[1 + i];
        truncated = (truncated << 8) | pn_bytes[i] as u64;
    }
    let pn = decode_pn(largest_pn, truncated, (pn_len * 8) as u32);
    Some((pn, pn_bytes))
}

pub fn unprotect_initial(aead: Aead, keys: &PacketKeys, pkt: &[u8]) -> Option<(u64, Vec<u8>)> {
    let lp = unprotect_long(aead, keys, pkt, 0)?;
    Some((lp.pn, lp.payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn initial_packet_roundtrip() {
        let dcid = hex("8394c8f03e515708");
        let (client_secret, _) = crate::initial_secrets(&dcid);
        let keys = crate::derive_packet_keys(&client_secret, 16);

        let payload = b"CRYPTO frame: ClientHello bytes would go here (>=padding)";
        let pkt = protect_initial(Aead::Aes128Gcm, &keys, &dcid, b"scid", b"", 2, 4, payload);

        let (pn, pt) = unprotect_initial(Aead::Aes128Gcm, &keys, &pkt).expect("해제");
        assert_eq!(pn, 2);
        assert_eq!(pt, payload);
    }

    #[test]
    fn server_keys_roundtrip_with_pn_len_1() {
        let dcid = hex("8394c8f03e515708");
        let (_, server_secret) = crate::initial_secrets(&dcid);
        let keys = crate::derive_packet_keys(&server_secret, 16);
        let payload = vec![0xABu8; 40];
        let pkt = protect_initial(Aead::Aes128Gcm, &keys, b"", b"", b"", 1, 1, &payload);
        let (pn, pt) = unprotect_initial(Aead::Aes128Gcm, &keys, &pkt).unwrap();
        assert_eq!(pn, 1);
        assert_eq!(pt, payload);
    }

    #[test]
    fn protect_rejects_oversized_connection_ids_and_tokens() {
        let secret = [0x42u8; 32];
        let keys = crate::derive_packet_keys(&secret, 16);
        assert!(protect_initial(
            Aead::Aes128Gcm,
            &keys,
            &[0u8; 21],
            b"scid",
            b"",
            1,
            1,
            &[0u8; 32],
        )
        .is_empty());
        assert!(protect_initial(
            Aead::Aes128Gcm,
            &keys,
            b"dcid",
            b"scid",
            &[0u8; 257],
            1,
            1,
            &[0u8; 32],
        )
        .is_empty());
    }

    #[test]
    fn tampered_packet_fails() {
        let dcid = hex("8394c8f03e515708");
        let (cs, _) = crate::initial_secrets(&dcid);
        let keys = crate::derive_packet_keys(&cs, 16);
        let mut pkt = protect_initial(Aead::Aes128Gcm, &keys, &dcid, b"", b"", 5, 2, &[0u8; 30]);
        let last = pkt.len() - 1;
        pkt[last] ^= 0xFF;
        assert!(unprotect_initial(Aead::Aes128Gcm, &keys, &pkt).is_none());
    }

    #[test]
    fn rfc9000_a3_decode_pn() {
        assert_eq!(decode_pn(0xa82f30ea, 0x9b32, 16), 0xa82f9b32);

        assert_eq!(decode_pn(0, 1, 8), 1);
        assert_eq!(decode_pn(0, 5, 16), 5);
    }

    #[test]
    fn handshake_packet_roundtrip() {
        let secret = [0x5au8; 32];
        let keys = crate::derive_packet_keys(&secret, 16);
        let payload = b"CRYPTO frame: EncryptedExtensions..Finished bytes";
        let pkt = protect_long(
            Aead::Aes128Gcm,
            &keys,
            ptype::HANDSHAKE,
            b"dcid8888",
            b"scid4",
            b"",
            7,
            2,
            payload,
        );
        let lp = unprotect_long(Aead::Aes128Gcm, &keys, &pkt, 0).expect("해제");
        assert_eq!(lp.ptype, ptype::HANDSHAKE);
        assert_eq!(lp.version, VERSION_1);
        assert_eq!(lp.dcid, b"dcid8888");
        assert_eq!(lp.scid, b"scid4");
        assert!(lp.token.is_empty());
        assert_eq!(lp.pn, 7);
        assert_eq!(lp.payload, payload);
        assert_eq!(lp.consumed, pkt.len());
    }

    #[test]
    fn short_packet_roundtrip() {
        let secret = [0x77u8; 32];
        let keys = crate::derive_packet_keys(&secret, 16);
        let dcid = b"SRVCID01";
        let payload = b"\x00\x20 DoQ STREAM frame with DNS message would be here";
        let pkt = protect_short(Aead::Aes128Gcm, &keys, dcid, 42, 2, payload, false);

        assert_eq!(pkt[0] & 0x80, 0);
        let (sp, changed) =
            unprotect_short(Aead::Aes128Gcm, &keys, None, false, &pkt, dcid.len(), 0)
                .expect("해제");
        assert!(!changed);
        assert_eq!(sp.dcid, dcid);
        assert_eq!(sp.pn, 42);
        assert_eq!(sp.payload, payload);
    }

    #[test]
    /// The shape a server sends to a client using zero-length connection IDs. A one-byte frame must
    /// still be padded enough for the header protection sample.
    fn short_packet_with_zero_length_dcid_roundtrips() {
        let secret = [0x5au8; 32];
        let keys = crate::derive_packet_keys(&secret, 16);
        let pkt = protect_short(Aead::Aes128Gcm, &keys, &[], 7, 4, &[0x1e], false);
        assert!(!pkt.is_empty());

        let (sp, _) =
            unprotect_short(Aead::Aes128Gcm, &keys, None, false, &pkt, 0, 0).expect("해제");
        assert!(sp.dcid.is_empty());
        assert_eq!(sp.pn, 7);
        assert_eq!(sp.payload[0], 0x1e);
    }

    #[test]
    fn short_packet_large_pn_decoded() {
        let secret = [0x11u8; 32];
        let keys = crate::derive_packet_keys(&secret, 16);
        let dcid = b"cid00001";
        let pn = 0x10001u64;
        let pkt = protect_short(Aead::Aes128Gcm, &keys, dcid, pn, 2, &[0xCD; 40], false);

        let (sp, _) = unprotect_short(
            Aead::Aes128Gcm,
            &keys,
            None,
            false,
            &pkt,
            dcid.len(),
            0x10000,
        )
        .unwrap();
        assert_eq!(sp.pn, pn);
    }

    #[test]
    fn coalesced_consumed_points_to_next() {
        let secret = [0x33u8; 32];
        let keys = crate::derive_packet_keys(&secret, 16);
        let mut pkt = protect_long(
            Aead::Aes128Gcm,
            &keys,
            ptype::HANDSHAKE,
            b"dddddddd",
            b"ss",
            b"",
            1,
            1,
            &[0xAB; 30],
        );
        let first_len = pkt.len();
        pkt.extend_from_slice(&[0xFF; 17]);
        let lp = unprotect_long(Aead::Aes128Gcm, &keys, &pkt, 0).unwrap();
        assert_eq!(lp.consumed, first_len);
        assert_eq!(lp.payload, vec![0xAB; 30]);
    }
}
