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
/**
 * @brief TLS 처리 실패 사유.
 * @details 사유마다 상대에게 알릴 치명 경고가 하나로 정해져 있고 alert 가 그 대응을 맡는다.
 *          거부하는 자리가 경고를 따로 고르지 않으므로, 같은 거부가 경로에 따라 다른 경고로
 *          나가지 않는다.
 */
pub enum TlsError {
    /** @brief 바이트를 읽어 내지 못했다. decode_error 로 알린다. */
    Decode,

    /** @brief 레코드가 규격 크기를 넘겼다. record_overflow 로 알린다. */
    RecordOverflow,

    /** @brief 레코드의 암호를 풀지 못했다. bad_record_mac 으로 알린다. */
    Decrypt,

    /** @brief 인증서나 인증 경로가 어긋났다. bad_certificate 로 알린다. */
    BadCert,

    /** @brief 서명, Finished, PSK 결합자가 맞지 않는다. decrypt_error 로 알린다. */
    BadSignature,

    /** @brief 다루지 않는 서명 방식이다. illegal_parameter 로 알린다. */
    UnsupportedSig(u16),

    /** @brief 주고받는 중 오류가 났다. */
    Io,

    /** @brief 지금 받을 수 없는 메시지나 레코드가 왔다. unexpected_message 로 알린다. */
    UnexpectedMessage,

    /** @brief 형식은 맞지만 값이 규격이나 협상 결과와 맞지 않는다. illegal_parameter 로 알린다. */
    IllegalParameter,

    /** @brief 양쪽이 함께 받아들일 수 있는 매개변수가 없다. handshake_failure 로 알린다. */
    HandshakeFailure,

    /** @brief 상대가 고른 프로토콜 버전을 지원하지 않는다. protocol_version 으로 알린다. */
    ProtocolVersion,

    /** @brief 반드시 있어야 할 확장이 없다. missing_extension 으로 알린다. */
    MissingExtension,

    /** @brief 이쪽이 제안하지 않은 확장이 응답에 왔다. unsupported_extension 으로 알린다. */
    UnsupportedExtension,

    /** @brief 인증서의 공개 키 형식을 다루지 않는다. unsupported_certificate 로 알린다. */
    UnsupportedCertificate,

    /** @brief 요구한 클라이언트 인증서가 오지 않았다. certificate_required 로 알린다. */
    CertificateRequired,

    /** @brief 상대와 무관하게 이쪽 내부에서 실패했다. internal_error 로 알린다. */
    Internal,

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

impl TlsError {
    /**
     * @brief 이 실패를 상대에게 알릴 치명 경고의 설명 코드.
     * @return 상대에게 알리지 않는 실패면 없다. 입출력 실패와 상대의 종료가 그렇고, 상대가
     *         보낸 경고에는 경고로 답하지 않는다. 일련번호 소진은 경고를 보낼 nonce 도 남지
     *         않았다.
     */
    pub fn alert(&self) -> Option<u8> {
        match self {
            TlsError::UnexpectedMessage => Some(10),
            TlsError::Decrypt => Some(20),
            TlsError::RecordOverflow => Some(22),
            TlsError::HandshakeFailure => Some(40),
            TlsError::BadCert => Some(42),
            TlsError::UnsupportedCertificate => Some(43),
            TlsError::IllegalParameter | TlsError::UnsupportedSig(_) => Some(47),
            TlsError::Decode => Some(50),
            TlsError::BadSignature => Some(51),
            TlsError::ProtocolVersion => Some(70),
            TlsError::Internal => Some(80),
            TlsError::MissingExtension => Some(109),
            TlsError::UnsupportedExtension => Some(110),
            TlsError::CertificateRequired => Some(116),
            TlsError::Io
            | TlsError::CloseNotify
            | TlsError::Eof
            | TlsError::PeerAlert { .. }
            | TlsError::SeqExhausted => None,
        }
    }
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
