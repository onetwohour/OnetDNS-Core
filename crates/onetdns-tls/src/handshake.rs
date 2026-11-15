//! Handshake message framing. Messages ignore record boundaries: one can span several records, and
//! one record can hold several.
//!
//! Message size is capped; otherwise one length field could hold this side's memory.

use crate::wire::Writer;
use crate::TlsError;

pub const MAX_HANDSHAKE_MESSAGE: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeType(pub u8);

#[allow(non_upper_case_globals)]
impl HandshakeType {
    pub const ClientHello: HandshakeType = HandshakeType(1);
    /// Sets the suite and keys.
    pub const ServerHello: HandshakeType = HandshakeType(2);
    pub const NewSessionTicket: HandshakeType = HandshakeType(4);
    pub const EndOfEarlyData: HandshakeType = HandshakeType(5);
    pub const EncryptedExtensions: HandshakeType = HandshakeType(8);
    pub const Certificate: HandshakeType = HandshakeType(11);

    /// TLS 1.2 only.
    pub const ServerKeyExchange: HandshakeType = HandshakeType(12);
    pub const CertificateRequest: HandshakeType = HandshakeType(13);

    /// TLS 1.2 only.
    pub const ServerHelloDone: HandshakeType = HandshakeType(14);
    /// Proves possession of the private key.
    pub const CertificateVerify: HandshakeType = HandshakeType(15);

    /// TLS 1.2 only.
    pub const ClientKeyExchange: HandshakeType = HandshakeType(16);
    /// Confirms the whole handshake transcript; the last check against a forged handshake.
    pub const Finished: HandshakeType = HandshakeType(20);
    pub const KeyUpdate: HandshakeType = HandshakeType(24);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeMsg {
    pub msg_type: HandshakeType,
    pub body: Vec<u8>,
}

impl HandshakeMsg {
    pub fn new(msg_type: HandshakeType, body: Vec<u8>) -> Self {
        Self { msg_type, body }
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let mut w = Writer::new();
        w.u8(self.msg_type.0);
        w.vec24(|w| w.bytes(&self.body));
        out.extend_from_slice(&w.buf);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + self.body.len());
        self.encode_into(&mut v);
        v
    }

    /// None when the message is incomplete. IllegalParameter when the length exceeds this side's
    /// limit; not record_overflow, since the value has nothing to do with record size.
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

    /// The comparison is constant time. UnexpectedMessage when another message comes in Finished's
    /// place, Decode when the length differs, BadSignature when the value differs.
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
/// Needed because messages ignore record boundaries.
pub struct HandshakeReader {
    buf: Vec<u8>,
}

impl HandshakeReader {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn retained_payload_bytes(&self) -> usize {
        self.buf.capacity()
    }

    pub fn feed(&mut self, fragment: &[u8]) {
        self.buf.extend_from_slice(fragment);
    }

    pub(crate) fn has_pending(&self) -> bool {
        !self.buf.is_empty()
    }

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
