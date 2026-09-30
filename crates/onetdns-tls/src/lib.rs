/*!
 * @brief TLS 1.2와 1.3.
 *
 * @details 서로 다른 두 구현이 와이어 원시 요소를 나눠 쓴다. conn은 소켓을 직접 읽고 쓰는
 *          차단 방식이고, engine은 QUIC에 붙는 sans-IO 방식이다. 둘을 뒤섞지 않는다.
 * @warning 이쪽은 이 코드로 상대의 신원을 판단한다. 인증서 검증, 서명 확인, 이름 대조가
 *          하나라도 헐거우면 암호화만 하고 상대는 확인하지 않는 꼴이 된다.
 */

/** @brief 레코드 보호. */
pub mod aead;
/** @brief 인증서 체인 검증. */
pub mod cert;
/** @brief 차단 방식 연결. DoT와 TCP 위 DoH가 쓴다. */
pub mod conn;
/** @brief DER 인코딩 파서. */
pub mod der;
/** @brief sans-IO 핸드셰이크 엔진. QUIC가 쓴다. */
pub mod engine;
/** @brief 핸드셰이크 메시지 프레이밍. */
pub mod handshake;
/** @brief 1.3 키 유도 일정. */
pub mod keyschedule;
/** @brief 키 교환. */
pub mod kx;
/** @brief 핸드셰이크 메시지 인코딩과 파싱. */
pub mod msg;
/** @brief 레코드 계층 프레이밍. */
pub mod record;
/** @brief 인증서 폐기 확인. */
pub mod revoke;
/** @brief 세션 재개. */
pub mod session;
/** @brief 난수 등 플랫폼 의존 요소. */
pub mod sys;
/** @brief TLS 1.2 전용 부분. */
pub mod tls12;
/** @brief 신뢰 저장소. */
pub mod trust;
/** @brief 길이 접두사 있는 값 읽기와 쓰기. */
pub mod wire;
/** @brief 인증서 파싱. */
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
pub use trust::{verify_chain, verify_client_chain, TrustStore};
pub use wire::{Reader, Writer};
pub use x509::X509;

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief TLS 처리 실패 사유. */
pub enum TlsError {
    /** @brief 바이트를 읽어 내지 못했다. */
    Decode,

    /** @brief 레코드가 규격 크기를 넘겼다. */
    RecordOverflow,

    /** @brief 암호를 풀지 못했다. */
    Decrypt,

    /** @brief 인증서가 어긋났다. */
    BadCert,

    /** @brief 서명이 맞지 않는다. */
    BadSignature,

    /** @brief 다루지 않는 서명 방식이다. */
    UnsupportedSig(u16),

    /** @brief 주고받는 중 오류가 났다. */
    Io,

    /** @brief 프로토콜을 어긴 순서나 값이다. */
    Protocol,

    /** @brief 상대가 곱게 끝냈다. */
    CloseNotify,

    /**
     * @brief 상대가 종료 알림 없이 레코드 경계에서 연결을 닫았다.
     * @details 레코드 중간에서 끊긴 것과 구분한다. 길이를 스스로 밝히는 위층 프로토콜은
     *          자기 메시지 경계에서 이것을 정상 종료로 볼 수 있다.
     */
    Eof,

    /** @brief 상대가 오류를 알렸다. */
    PeerAlert { level: u8, description: u8 },

    /** @brief 레코드 일련번호를 다 썼다. 더 쓰면 같은 nonce를 되쓴다. */
    SeqExhausted,
}

impl std::fmt::Display for TlsError {
    /** @brief 사람이 읽을 실패 사유. */
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::Decode => write!(f, "Could not parse TLS message"),
            TlsError::RecordOverflow => write!(f, "TLS record length exceeds the limit"),
            TlsError::Decrypt => write!(f, "Could not decrypt TLS record"),
            TlsError::BadCert => write!(f, "Invalid certificate or public key"),
            TlsError::BadSignature => write!(f, "Signature verification failed"),
            TlsError::UnsupportedSig(s) => write!(f, "Unsupported signature scheme: {s}"),
            TlsError::Io => write!(f, "I/O error on the TLS connection"),
            TlsError::Protocol => write!(f, "TLS protocol violation"),
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
/** @brief 레코드와 핸드셰이크 프레이밍, 그리고 와이어 원시 요소의 경계 검사. */
mod tests {
    use super::*;

    #[test]
    /** @brief 레코드 왕복. */
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
    /** @brief 덜 온 레코드는 오류가 아니라 대기인지. */
    fn record_incomplete_returns_none() {
        let rec = TlsRecord::new(ContentType::ApplicationData, vec![9; 100]);
        let bytes = rec.encode();

        assert!(TlsRecord::parse(&bytes[..4]).unwrap().is_none());
        assert!(TlsRecord::parse(&bytes[..50]).unwrap().is_none());
        assert!(TlsRecord::parse(&bytes).unwrap().is_some());
    }

    #[test]
    /** @brief 상한을 넘는 레코드를 거부하는지. */
    fn record_overflow_errors() {
        let mut bytes = vec![23u8, 0x03, 0x03];
        bytes.extend_from_slice(&0xFFFFu16.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 10]);
        assert_eq!(TlsRecord::parse(&bytes), Err(TlsError::RecordOverflow));
    }

    #[test]
    /** @brief 이어 붙은 레코드를 하나씩 꺼내는지. */
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
    /** @brief 핸드셰이크 메시지 왕복. */
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
    /** @brief 레코드 여럿에 걸친 핸드셰이크 메시지를 이어 붙이는지. */
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
    /** @brief 길이 접두사 있는 값의 왕복. */
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
    /** @brief 모자란 바이트에서 오류가 나는지. */
    fn wire_bounds_checked() {
        let mut r = Reader::new(&[0x00, 0x05]);
        assert_eq!(r.vec16(), Err(TlsError::Decode));
    }
}
