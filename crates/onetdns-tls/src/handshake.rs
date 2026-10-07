/*!
 * @brief 핸드셰이크 메시지 프레이밍.
 *
 * @details 핸드셰이크 메시지는 레코드 경계와 무관하다. 하나가 여러 레코드에 걸치기도 하고,
 *          한 레코드에 여럿이 들어오기도 한다.
 * @warning 메시지 크기에 상한이 있다. 없으면 길이 필드 하나로 이쪽 메모리를 잡아 둘 수 있다.
 */

use crate::wire::Writer;
use crate::TlsError;

/** @brief 핸드셰이크 메시지 하나의 크기 상한. */
pub const MAX_HANDSHAKE_MESSAGE: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 핸드셰이크 메시지 종류. */
pub struct HandshakeType(pub u8);

#[allow(non_upper_case_globals)]
impl HandshakeType {
    /** @brief 클라이언트가 여는 첫 메시지. */
    pub const ClientHello: HandshakeType = HandshakeType(1);
    /** @brief 서버의 응답. 여기서 스위트와 키가 정해진다. */
    pub const ServerHello: HandshakeType = HandshakeType(2);
    /** @brief 다음 연결의 재개에 쓸 티켓. */
    pub const NewSessionTicket: HandshakeType = HandshakeType(4);
    /** @brief 조기 데이터가 끝났음을 알린다. */
    pub const EndOfEarlyData: HandshakeType = HandshakeType(5);
    /** @brief 암호화된 확장들. 1.3에서 추가됐다. */
    pub const EncryptedExtensions: HandshakeType = HandshakeType(8);
    /** @brief 인증서 체인. */
    pub const Certificate: HandshakeType = HandshakeType(11);

    /** @brief 1.2 전용. 키 교환 값을 전달한다. */
    pub const ServerKeyExchange: HandshakeType = HandshakeType(12);
    /** @brief 클라이언트 인증서를 요청한다. */
    pub const CertificateRequest: HandshakeType = HandshakeType(13);

    /** @brief 1.2 전용. 서버 차례가 끝났음을 알린다. */
    pub const ServerHelloDone: HandshakeType = HandshakeType(14);
    /** @brief 개인키를 실제로 갖고 있음을 증명하는 서명. */
    pub const CertificateVerify: HandshakeType = HandshakeType(15);

    /** @brief 1.2 전용. 클라이언트의 키 교환 값. */
    pub const ClientKeyExchange: HandshakeType = HandshakeType(16);
    /** @brief 핸드셰이크 기록 전체를 확인하는 값. 핸드셰이크 위조를 막는 마지막 검사다. */
    pub const Finished: HandshakeType = HandshakeType(20);
    /** @brief 키를 갱신하자는 요청. */
    pub const KeyUpdate: HandshakeType = HandshakeType(24);
}

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 핸드셰이크 메시지 하나. */
pub struct HandshakeMsg {
    /** @brief 이 메시지의 종류. */
    pub msg_type: HandshakeType,
    /** @brief 이 메시지의 내용. */
    pub body: Vec<u8>,
}

impl HandshakeMsg {
    /** @brief 메시지를 만든다. */
    pub fn new(msg_type: HandshakeType, body: Vec<u8>) -> Self {
        Self { msg_type, body }
    }

    /** @brief 버퍼에 이어 쓴다. */
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let mut w = Writer::new();
        w.u8(self.msg_type.0);
        w.vec24(|w| w.bytes(&self.body));
        out.extend_from_slice(&w.buf);
    }

    /** @brief 새 버퍼에 쓴다. */
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + self.body.len());
        self.encode_into(&mut v);
        v
    }

    /**
     * @brief 바이트열에서 메시지 하나를 읽는다. 덜 왔으면 None이다.
     * @retval TlsError::IllegalParameter 길이 필드가 이쪽 상한을 넘는다. 레코드 크기와는
     *         무관한 값이므로 record_overflow 가 아니다.
     */
    pub fn parse(buf: &[u8]) -> Result<Option<(HandshakeMsg, usize)>, TlsError> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let msg_type = HandshakeType(buf[0]);
        let len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | buf[3] as usize;
        if len > MAX_HANDSHAKE_MESSAGE {
            return Err(TlsError::IllegalParameter);
        }
        if buf.len() < 4 + len {
            return Ok(None);
        }
        Ok(Some((
            HandshakeMsg {
                msg_type,
                body: buf[4..4 + len].to_vec(),
            },
            4 + len,
        )))
    }

    /**
     * @brief 상대의 Finished 가 기대한 검증 값과 같은지 확인한다.
     * @param expected 이쪽이 같은 기록으로 계산한 검증 값.
     * @retval TlsError::UnexpectedMessage Finished 가 올 자리에 다른 메시지가 왔다.
     * @retval TlsError::Decode 길이가 검증 값 길이와 다르다.
     * @retval TlsError::BadSignature 검증 값이 다르다. 비교는 상수 시간이다.
     */
    pub(crate) fn verify_finished(&self, expected: &[u8]) -> Result<(), TlsError> {
        if self.msg_type != HandshakeType::Finished {
            return Err(TlsError::UnexpectedMessage);
        }
        if self.body.len() != expected.len() {
            return Err(TlsError::Decode);
        }
        if !crate::keyschedule::ct_eq(&self.body, expected) {
            return Err(TlsError::BadSignature);
        }
        Ok(())
    }
}

#[derive(Default)]
/**
 * @brief 레코드에서 나온 조각을 모아 핸드셰이크 메시지로 나눠 주는 것.
 * @details 메시지가 레코드 경계와 무관하므로 이 계층이 따로 필요하다.
 */
pub struct HandshakeReader {
    /** @brief 아직 온전한 메시지가 되지 못한 바이트. */
    buf: Vec<u8>,
}

impl HandshakeReader {
    /** @brief 빈 상태. */
    pub fn new() -> Self {
        Self::default()
    }

    /** @brief 아직 완성되지 않은 핸드셰이크 입력의 보유 바이트. */
    pub(crate) fn retained_payload_bytes(&self) -> usize {
        self.buf.capacity()
    }

    /** @brief 레코드에서 나온 조각을 넣는다. */
    pub fn feed(&mut self, fragment: &[u8]) {
        self.buf.extend_from_slice(fragment);
    }

    /** @brief 아직 완성되지 않았거나 꺼내지 않은 바이트가 있는지. */
    pub(crate) fn has_pending(&self) -> bool {
        !self.buf.is_empty()
    }

    /** @brief 다 온 메시지 하나를 꺼낸다. */
    pub fn next_message(&mut self) -> Result<Option<HandshakeMsg>, TlsError> {
        if self.buf.len() > MAX_HANDSHAKE_MESSAGE + 4 {
            self.buf.clear();
            return Err(TlsError::IllegalParameter);
        }
        match HandshakeMsg::parse(&self.buf)? {
            Some((msg, consumed)) => {
                self.buf.drain(..consumed);
                Ok(Some(msg))
            }
            None => Ok(None),
        }
    }
}
