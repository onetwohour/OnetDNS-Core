//! Stateless reset (RFC 9000). A server that no longer has a connection, for example after a
//! restart, tells the client to stop with a packet only the key holder can make for that
//! connection ID.

use crate::retry::hmac_sha256;

pub const TOKEN_LEN: usize = 16;
/// A header byte, 38 unpredictable bits, and the token.
const MIN_RESET_LEN: usize = 21;
/// RFC 9000 asks for one byte less than a packet up to this size; larger ones get this size.
const MAX_RESET_LEN: usize = 43;

/// Derives the reset token of each connection ID. Clients of connections made before a restart
/// accept a reset only if the key is the same, so the caller keeps it.
#[derive(Clone)]
pub struct ResetKey([u8; 32]);

impl ResetKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        onetdns_tls::sys::fill_random(&mut key);
        Self(key)
    }

    /// Announced in the transport parameters of the connection that uses `cid`.
    pub fn token(&self, cid: &[u8]) -> [u8; TOKEN_LEN] {
        let mut token = [0u8; TOKEN_LEN];
        token.copy_from_slice(&hmac_sha256(&self.0, cid)[..TOKEN_LEN]);
        token
    }

    /// The reset for a short header packet of `received_len` bytes sent to `cid`. It is shorter
    /// than that packet, so two endpoints cannot reset each other in a loop and a spoofed source
    /// gets back less than it sent. None when no valid reset is that short.
    pub fn reset_for(&self, cid: &[u8], received_len: usize) -> Option<Vec<u8>> {
        if received_len <= MIN_RESET_LEN {
            return None;
        }
        let len = (received_len - 1).min(MAX_RESET_LEN);
        let mut packet = vec![0u8; len];
        let (head, token) = packet.split_at_mut(len - TOKEN_LEN);
        onetdns_tls::sys::fill_random(head);
        head[0] = 0x40 | (head[0] & 0x3f);
        token.copy_from_slice(&self.token(cid));
        Some(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_depends_on_the_key_and_the_connection_id() {
        let key = ResetKey::new([7; 32]);
        assert_eq!(
            key.token(b"SERVERID"),
            ResetKey::new([7; 32]).token(b"SERVERID")
        );
        assert_ne!(key.token(b"SERVERID"), key.token(b"SERVERIE"));
        assert_ne!(
            key.token(b"SERVERID"),
            ResetKey::new([8; 32]).token(b"SERVERID")
        );
    }

    #[test]
    fn reset_is_a_short_header_packet_smaller_than_what_it_answers() {
        let key = ResetKey::generate();
        for received in [0, 1, 20, MIN_RESET_LEN] {
            assert!(key.reset_for(b"SERVERID", received).is_none(), "{received}");
        }
        for received in [MIN_RESET_LEN + 1, 30, MAX_RESET_LEN + 1, 44, 1200] {
            let reset = key.reset_for(b"SERVERID", received).unwrap();
            assert!(
                reset.len() >= MIN_RESET_LEN && reset.len() < received,
                "{received}"
            );
            assert_eq!(reset.len(), (received - 1).min(MAX_RESET_LEN));
            assert_eq!(reset[0] & 0xc0, 0x40, "header form 0, fixed bit 1");
            assert_eq!(reset[reset.len() - TOKEN_LEN..], key.token(b"SERVERID"));
        }
    }
}
