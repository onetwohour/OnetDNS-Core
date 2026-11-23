//! TLS 1.2 and 1.3. Two implementations share the wire primitives: conn reads and writes sockets
//! directly and blocks, and engine is sans-IO for QUIC. They are not mixed.
//!
//! This code decides who the peer is. If certificate validation, signature checks, or name matching
//! is loose anywhere, the connection is encrypted without checking whom it talks to.

pub mod aead;
pub mod cert;
pub mod conn;
pub mod der;
pub mod engine;
pub mod handshake;
pub mod hpke;
pub mod keyschedule;
pub mod kx;
pub mod msg;
pub mod record;
pub mod revoke;
pub mod session;
pub mod shared;
pub mod sys;
pub mod tls12;
pub mod trust;
pub mod wire;
pub mod x509;

pub use aead::{Aead, RecordCrypto};
pub use cert::CertificateRequestMsg;
pub use cert::{certificate_verify_content, verify_signature, CertificateMsg, CertificateVerify};
pub use conn::{
    client_handshake, server_handshake, signer_from_pkcs8_der, ClientCert, ClientConfig,
    InsecureVerifier, ServerConfig, TlsConnection, TlsStream,
};
pub use engine::{
    ClientHandshake, Level, Secret, SecretPair, ServerHandshake, EXT_QUIC_TRANSPORT_PARAMETERS,
};
pub use handshake::{HandshakeMsg, HandshakeReader, HandshakeType};
pub use keyschedule::{Hash, KeySchedule, Transcript};
pub use kx::KeyExchange;
pub use msg::{ClientHello, Extension, ServerHello, HRR_RANDOM};
pub use record::{ContentType, RecordReader, TlsRecord, MAX_FRAGMENT};
pub use revoke::{build_ocsp_request, check_ocsp_response, Crl, RevocationStatus};
pub use session::{ResumptionState, Ticketer, TlsSession};
pub use shared::SharedTlsStream;
pub use trust::{verify_chain, verify_client_chain, TrustStore};
pub use wire::{Reader, Writer};
pub use x509::X509;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Each reason maps to exactly one fatal alert, chosen by `alert`. The rejecting site does not pick
/// an alert, so the same rejection never goes out as different alerts depending on the path.
pub enum TlsError {
    Decode,

    RecordOverflow,

    Decrypt,

    BadCert,

    /// The chain reaches none of this side's trusted roots.
    UnknownCa,

    /// Also when a certificate is not yet valid.
    CertificateExpired,

    /// A certificate that passed validation is refused for another reason, such as the revocation
    /// check after the handshake. That policy does not tell a confirmed revocation from an
    /// unchecked one, so certificate_revoked is not used.
    CertificateUnknown,

    /// RFC 7301 requires this of servers, and RFC 9001 has QUIC clients close with this alert when
    /// negotiation fails too.
    NoApplicationProtocol,

    /// A signature, Finished, or PSK binder does not match.
    BadSignature,

    UnsupportedSig(u16),

    Io,

    UnexpectedMessage,

    /// Well-formed, but the value breaks the spec or what was negotiated.
    IllegalParameter,

    HandshakeFailure,

    ProtocolVersion,

    MissingExtension,

    UnsupportedExtension,

    UnsupportedCertificate,

    CertificateRequired,

    /// A local failure unrelated to the peer.
    Internal,

    CloseNotify,

    /// The peer closed at a record boundary without close_notify, as distinct from a cut in the
    /// middle of a record. A protocol above that states its own lengths can treat this as a normal
    /// close at its own message boundary.
    Eof,

    PeerAlert {
        level: u8,
        description: u8,
    },

    /// Sending more would reuse a nonce.
    SeqExhausted,
}

impl TlsError {
    /// None for failures the peer is not told about: I/O failures and the peer's own close, and an
    /// alert from the peer is not answered with an alert. A spent sequence number leaves no nonce
    /// to send an alert with.
    pub fn alert(&self) -> Option<u8> {
        match self {
            TlsError::UnexpectedMessage => Some(10),
            TlsError::Decrypt => Some(20),
            TlsError::RecordOverflow => Some(22),
            TlsError::HandshakeFailure => Some(40),
            TlsError::BadCert => Some(42),
            TlsError::UnsupportedCertificate => Some(43),
            TlsError::CertificateExpired => Some(45),
            TlsError::CertificateUnknown => Some(46),
            TlsError::UnknownCa => Some(48),
            TlsError::IllegalParameter | TlsError::UnsupportedSig(_) => Some(47),
            TlsError::Decode => Some(50),
            TlsError::BadSignature => Some(51),
            TlsError::ProtocolVersion => Some(70),
            TlsError::Internal => Some(80),
            TlsError::MissingExtension => Some(109),
            TlsError::UnsupportedExtension => Some(110),
            TlsError::CertificateRequired => Some(116),
            TlsError::NoApplicationProtocol => Some(120),
            TlsError::Io
            | TlsError::CloseNotify
            | TlsError::Eof
            | TlsError::PeerAlert { .. }
            | TlsError::SeqExhausted => None,
        }
    }
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::Decode => write!(f, "Could not parse TLS message"),
            TlsError::RecordOverflow => write!(f, "TLS record length exceeds the limit"),
            TlsError::Decrypt => write!(f, "Could not decrypt TLS record"),
            TlsError::BadCert => write!(f, "Invalid certificate or public key"),
            TlsError::UnknownCa => write!(f, "Certificate chain does not reach a trusted root"),
            TlsError::CertificateExpired => write!(f, "Certificate is expired or not yet valid"),
            TlsError::CertificateUnknown => write!(f, "Certificate was rejected by local policy"),
            TlsError::NoApplicationProtocol => write!(f, "No common application protocol"),
            TlsError::BadSignature => write!(f, "Signature verification failed"),
            TlsError::UnsupportedSig(s) => write!(f, "Unsupported signature scheme: {s}"),
            TlsError::Io => write!(f, "I/O error on the TLS connection"),
            TlsError::UnexpectedMessage => write!(f, "Unexpected TLS message"),
            TlsError::IllegalParameter => write!(f, "Illegal TLS parameter"),
            TlsError::HandshakeFailure => write!(f, "No acceptable TLS parameters"),
            TlsError::ProtocolVersion => write!(f, "Unsupported TLS version"),
            TlsError::MissingExtension => write!(f, "Required TLS extension is missing"),
            TlsError::UnsupportedExtension => write!(f, "Unsolicited TLS extension"),
            TlsError::UnsupportedCertificate => write!(f, "Unsupported certificate key type"),
            TlsError::CertificateRequired => {
                write!(f, "Peer did not send a required certificate")
            }
            TlsError::Internal => write!(f, "Internal TLS error"),
            TlsError::CloseNotify => write!(f, "Received TLS close_notify"),
            TlsError::Eof => write!(f, "Peer closed the connection without a TLS close_notify"),
            TlsError::PeerAlert { level, description } => write!(
                f,
                "Peer sent a TLS alert: level={level}, description={description}"
            ),
            TlsError::SeqExhausted => write!(f, "TLS record sequence exhausted"),
        }
    }
}

impl std::error::Error for TlsError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_roundtrip() {
        let rec = TlsRecord::new(ContentType::Handshake, vec![1, 2, 3, 4, 5]);
        let bytes = rec.encode();

        assert_eq!(bytes.len(), 10);
        assert_eq!(bytes[0], 22);
        assert_eq!(&bytes[1..3], &[0x03, 0x03]);
        assert_eq!(&bytes[3..5], &[0x00, 0x05]);

        let (back, consumed) = TlsRecord::parse(&bytes).unwrap().unwrap();
        assert_eq!(consumed, 10);
        assert_eq!(back, rec);
    }

    #[test]
    fn record_incomplete_returns_none() {
        let rec = TlsRecord::new(ContentType::ApplicationData, vec![9; 100]);
        let bytes = rec.encode();

        assert!(TlsRecord::parse(&bytes[..4]).unwrap().is_none());
        assert!(TlsRecord::parse(&bytes[..50]).unwrap().is_none());
        assert!(TlsRecord::parse(&bytes).unwrap().is_some());
    }

    #[test]
    fn record_overflow_errors() {
        let mut bytes = vec![23u8, 0x03, 0x03];
        bytes.extend_from_slice(&0xFFFFu16.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 10]);
        assert_eq!(TlsRecord::parse(&bytes), Err(TlsError::RecordOverflow));
    }

    #[test]
    fn record_reader_streams_multiple() {
        let r1 = TlsRecord::new(ContentType::Handshake, vec![1, 2, 3]);
        let r2 = TlsRecord::new(ContentType::ApplicationData, vec![4, 5]);
        let mut stream = r1.encode();
        stream.extend_from_slice(&r2.encode());

        let mut rr = RecordReader::new();

        rr.feed(&stream[..4]);
        assert!(rr.next_record().unwrap().is_none());
        rr.feed(&stream[4..]);
        assert_eq!(rr.next_record().unwrap().unwrap(), r1);
        assert_eq!(rr.next_record().unwrap().unwrap(), r2);
        assert!(rr.next_record().unwrap().is_none());
    }

    #[test]
    fn handshake_roundtrip() {
        let msg = HandshakeMsg::new(HandshakeType::ClientHello, vec![0xAA; 300]);
        let bytes = msg.encode();

        assert_eq!(bytes.len(), 4 + 300);
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[1..4], &[0x00, 0x01, 0x2C]);
        let (back, consumed) = HandshakeMsg::parse(&bytes).unwrap().unwrap();
        assert_eq!(consumed, 304);
        assert_eq!(back, msg);
    }

    #[test]
    fn handshake_reader_spans_records() {
        let msg = HandshakeMsg::new(HandshakeType::ServerHello, vec![7; 50]);
        let full = msg.encode();
        let mut hr = HandshakeReader::new();
        hr.feed(&full[..20]);
        assert!(hr.next_message().unwrap().is_none());
        hr.feed(&full[20..]);
        assert_eq!(hr.next_message().unwrap().unwrap(), msg);
    }

    #[test]
    fn wire_vectors_roundtrip() {
        let mut w = Writer::new();
        w.u16(0x0304);
        w.vec8(|w| w.bytes(b"abc"));
        w.vec16(|w| {
            w.u8(1);
            w.u8(2);
        });
        w.vec24(|w| w.bytes(&[9, 9, 9, 9]));

        let mut r = Reader::new(&w.buf);
        assert_eq!(r.u16().unwrap(), 0x0304);
        assert_eq!(r.vec8().unwrap(), b"abc");
        assert_eq!(r.vec16().unwrap(), &[1, 2]);
        assert_eq!(r.vec24().unwrap(), &[9, 9, 9, 9]);
        assert!(r.is_empty());
    }

    #[test]
    fn wire_bounds_checked() {
        let mut r = Reader::new(&[0x00, 0x05]);
        assert_eq!(r.vec16(), Err(TlsError::Decode));
    }
}
