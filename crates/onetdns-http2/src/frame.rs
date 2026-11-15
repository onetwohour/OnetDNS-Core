/// Fixed preface a client sends first (RFC 9113).
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Length 3, type 1, flags 1, stream ID 4.
pub const FRAME_HEADER_LEN: usize = 9;

/// Larger frames are refused unless negotiated.
pub const DEFAULT_MAX_FRAME: usize = 16_384;

pub mod frame_type {
    pub const DATA: u8 = 0x0;
    pub const HEADERS: u8 = 0x1;
    pub const PRIORITY: u8 = 0x2;
    pub const RST_STREAM: u8 = 0x3;
    pub const SETTINGS: u8 = 0x4;
    /// Push is disabled here, so receiving it is a protocol error.
    pub const PUSH_PROMISE: u8 = 0x5;
    pub const PING: u8 = 0x6;
    pub const GOAWAY: u8 = 0x7;
    pub const WINDOW_UPDATE: u8 = 0x8;
    pub const CONTINUATION: u8 = 0x9;
}

/// The same bit means different things per frame type: 0x1 is END_STREAM on DATA and HEADERS, ACK
/// on SETTINGS and PING.
pub mod flags {
    pub const END_STREAM: u8 = 0x1;

    pub const ACK: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
}

pub mod settings {
    pub const HEADER_TABLE_SIZE: u16 = 0x1;
    pub const ENABLE_PUSH: u16 = 0x2;
    pub const MAX_CONCURRENT_STREAMS: u16 = 0x3;
    pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
    pub const MAX_FRAME_SIZE: u16 = 0x5;
    pub const MAX_HEADER_LIST_SIZE: u16 = 0x6;
}

pub mod error_code {
    pub const NO_ERROR: u32 = 0x0;
    pub const PROTOCOL_ERROR: u32 = 0x1;
    pub const INTERNAL_ERROR: u32 = 0x2;
    pub const FLOW_CONTROL_ERROR: u32 = 0x3;
    pub const FRAME_SIZE_ERROR: u32 = 0x6;
    pub const REFUSED_STREAM: u32 = 0x7;
    pub const CANCEL: u32 = 0x8;
    pub const COMPRESSION_ERROR: u32 = 0x9;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// 24 bits on the wire.
    pub length: u32,
    pub frame_type: u8,
    pub flags: u8,

    /// The reserved high bit is always cleared.
    pub stream_id: u32,
}

impl FrameHeader {
    pub fn new(frame_type: u8, flags: u8, stream_id: u32, length: u32) -> Self {
        FrameHeader {
            length,
            frame_type,
            flags,
            stream_id,
        }
    }

    /// Clears the reserved high bit of the stream ID, which the protocol says to ignore; kept, one
    /// stream would appear under two IDs.
    pub fn parse(b: &[u8]) -> Option<FrameHeader> {
        if b.len() < FRAME_HEADER_LEN {
            return None;
        }
        Some(FrameHeader {
            length: u32::from_be_bytes([0, b[0], b[1], b[2]]),
            frame_type: b[3],
            flags: b[4],
            stream_id: u32::from_be_bytes([b[5], b[6], b[7], b[8]]) & 0x7fff_ffff,
        })
    }

    /// Only the low 24 bits of the length are written.
    pub fn encode(&self) -> [u8; FRAME_HEADER_LEN] {
        let l = self.length.to_be_bytes();
        let s = (self.stream_id & 0x7fff_ffff).to_be_bytes();
        [
            l[1],
            l[2],
            l[3],
            self.frame_type,
            self.flags,
            s[0],
            s[1],
            s[2],
            s[3],
        ]
    }

    pub fn has_flag(&self, f: u8) -> bool {
        self.flags & f != 0
    }
}

pub fn write_frame(out: &mut Vec<u8>, frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) {
    let h = FrameHeader::new(frame_type, flags, stream_id, payload.len() as u32);
    out.extend_from_slice(&h.encode());
    out.extend_from_slice(payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_header_roundtrip() {
        let h = FrameHeader::new(frame_type::HEADERS, flags::END_HEADERS, 3, 1000);
        let bytes = h.encode();
        assert_eq!(bytes.len(), 9);
        let back = FrameHeader::parse(&bytes).unwrap();
        assert_eq!(back, h);
        assert_eq!(back.length, 1000);
        assert_eq!(back.frame_type, frame_type::HEADERS);
        assert!(back.has_flag(flags::END_HEADERS));
        assert_eq!(back.stream_id, 3);
    }

    #[test]
    fn reserved_bit_masked() {
        let mut bytes = FrameHeader::new(frame_type::DATA, 0, 1, 0).encode();
        bytes[5] |= 0x80;
        let h = FrameHeader::parse(&bytes).unwrap();
        assert_eq!(h.stream_id, 1);
    }

    #[test]
    fn write_frame_layout() {
        let mut out = Vec::new();
        write_frame(&mut out, frame_type::DATA, flags::END_STREAM, 1, b"hello");
        assert_eq!(out.len(), 9 + 5);
        let h = FrameHeader::parse(&out).unwrap();
        assert_eq!(h.length, 5);
        assert!(h.has_flag(flags::END_STREAM));
        assert_eq!(&out[9..], b"hello");
    }

    #[test]
    fn large_length_24bit() {
        let h = FrameHeader::new(frame_type::DATA, 0, 1, 0x00FF_FFFF);
        let back = FrameHeader::parse(&h.encode()).unwrap();
        assert_eq!(back.length, 0x00FF_FFFF);
    }

    #[test]
    fn http2_parsers_no_panic_on_adversarial_input() {
        use crate::hpack::{decode_int, Decoder as HpackDecoder};
        use crate::huffman;
        let mut seed: u32 = 0x2468_ace0;
        let mut rng = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        for _ in 0..30000 {
            let len = (rng() % 128) as usize;
            let v: Vec<u8> = (0..len).map(|_| (rng() & 0xff) as u8).collect();
            let _ = FrameHeader::parse(&v);
            let _ = decode_int(&v, ((rng() % 8) + 1) as u8);
            let _ = huffman::decode(&v);
            let mut dec = HpackDecoder::new(4096);
            let _ = dec.decode(&v);
        }
    }
}
