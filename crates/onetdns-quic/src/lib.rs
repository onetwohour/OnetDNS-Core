//! QUIC and HTTP/3, sans-IO: datagrams go in, the state advances, and datagrams to send come out.
//! The caller does the I/O.

/// Connection state machine.
pub mod conn;
pub mod doq;
pub mod frame;
pub mod h3;
pub mod packet;
pub mod params;
pub mod protect;
pub mod qpack;
pub mod reset;
pub mod retry;
pub mod varint;

pub use conn::{
    ClosePeriod, Connection, PeerClose, QuicDiagnostic, QuicError, Role, MAX_RECV_UDP_PAYLOAD,
};
pub use h3::{H3Client, H3Connection, H3Error, H3Response};

use sha2::Sha256;

/// QUIC version 1 salt for Initial key derivation.
pub const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

pub fn hkdf_expand_label(secret: &[u8], label: &[u8], context: &[u8], out_len: usize) -> Vec<u8> {
    let mut full_label = Vec::with_capacity(6 + label.len());
    full_label.extend_from_slice(b"tls13 ");
    full_label.extend_from_slice(label);

    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let hk = hkdf::Hkdf::<Sha256>::from_prk(secret).expect("PRK length");
    let mut out = vec![0u8; out_len];
    hk.expand(&info, &mut out).expect("HKDF expand length");
    out
}

#[derive(Debug, Clone)]
/// Packet protection keys for one direction.
pub struct PacketKeys {
    pub key: Vec<u8>,

    pub iv: Vec<u8>,

    /// Header protection key.
    pub hp: Vec<u8>,
}

impl Drop for PacketKeys {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
        self.iv.zeroize();
        self.hp.zeroize();
    }
}

pub fn derive_packet_keys(secret: &[u8], key_len: usize) -> PacketKeys {
    PacketKeys {
        key: hkdf_expand_label(secret, b"quic key", b"", key_len),
        iv: hkdf_expand_label(secret, b"quic iv", b"", 12),
        hp: hkdf_expand_label(secret, b"quic hp", b"", key_len),
    }
}

pub fn next_key_update_secret(secret: &[u8]) -> Vec<u8> {
    hkdf_expand_label(secret, b"quic ku", b"", secret.len())
}

/// Only the key and IV change; the header protection key stays, as RFC 9001 requires.
pub fn derive_updated_kv(secret: &[u8], key_len: usize, hp: Vec<u8>) -> PacketKeys {
    PacketKeys {
        key: hkdf_expand_label(secret, b"quic key", b"", key_len),
        iv: hkdf_expand_label(secret, b"quic iv", b"", 12),
        hp,
    }
}

/// Anyone who sees the first connection ID can derive these. Initial protection only stops
/// attackers that cannot see the packets.
pub fn initial_secrets(dcid: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (prk, _) = hkdf::Hkdf::<Sha256>::extract(Some(&INITIAL_SALT), dcid);
    let client = hkdf_expand_label(&prk, b"client in", b"", 32);
    let server = hkdf_expand_label(&prk, b"server in", b"", 32);
    (client, server)
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
    fn rfc9001_a1_initial_keys() {
        let dcid = hex("8394c8f03e515708");
        let (client, server) = initial_secrets(&dcid);

        assert_eq!(
            client,
            hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        );

        assert_eq!(
            server,
            hex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
        );

        let ck = derive_packet_keys(&client, 16);
        assert_eq!(ck.key, hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(ck.iv, hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(ck.hp, hex("9f50449e04a0e810283a1e9933adedd2"));

        let sk = derive_packet_keys(&server, 16);
        assert_eq!(sk.key, hex("cf3a5331653c364c88f0f379b6067e37"));
        assert_eq!(sk.iv, hex("0ac1493ca1905853b0bba03e"));
        assert_eq!(sk.hp, hex("c206b8d9b9f0f37644430b490eeaa314"));
    }

    #[test]
    fn expand_label_known() {
        let secret = [0x42u8; 32];
        let a = hkdf_expand_label(&secret, b"quic key", b"", 16);
        let b = hkdf_expand_label(&secret, b"quic key", b"", 16);
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);

        assert_ne!(a, hkdf_expand_label(&secret, b"quic iv", b"", 16));
    }
}
