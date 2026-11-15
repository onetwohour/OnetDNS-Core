//! QUIC frame encoding and parsing. A decrypted payload still comes from the peer, so frame and ACK
//! range counts are capped; otherwise one packet could take unbounded memory and time.

use crate::varint;

const MAX_PARSED_FRAMES: usize = 1024;
const MAX_PARSED_ACK_RANGES: u64 = 256;
/// Stream IDs must stay below 2^62.
pub const MAX_STREAM_COUNT: u64 = 1 << 60;

/// Frame types from RFC 9000.
pub mod ftype {
    pub const PADDING: u64 = 0x00;
    pub const PING: u64 = 0x01;
    pub const ACK: u64 = 0x02;
    pub const ACK_ECN: u64 = 0x03;
    pub const RESET_STREAM: u64 = 0x04;
    pub const STOP_SENDING: u64 = 0x05;
    pub const CRYPTO: u64 = 0x06;
    /// The low three bits say which fields are present.
    pub const NEW_TOKEN: u64 = 0x07;
    pub const STREAM: u64 = 0x08;
    pub const MAX_DATA: u64 = 0x10;
    pub const MAX_STREAM_DATA: u64 = 0x11;
    pub const MAX_STREAMS_BIDI: u64 = 0x12;
    pub const MAX_STREAMS_UNI: u64 = 0x13;
    pub const DATA_BLOCKED: u64 = 0x14;
    pub const STREAM_DATA_BLOCKED: u64 = 0x15;
    pub const STREAMS_BLOCKED_BIDI: u64 = 0x16;
    pub const STREAMS_BLOCKED_UNI: u64 = 0x17;
    pub const NEW_CONNECTION_ID: u64 = 0x18;
    pub const RETIRE_CONNECTION_ID: u64 = 0x19;
    pub const PATH_CHALLENGE: u64 = 0x1a;
    pub const PATH_RESPONSE: u64 = 0x1b;
    pub const CONNECTION_CLOSE: u64 = 0x1c;
    pub const CONNECTION_CLOSE_APP: u64 = 0x1d;
    pub const HANDSHAKE_DONE: u64 = 0x1e;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Padding(usize),
    Ping,
    Ack {
        largest: u64,
        delay: u64,
        first_range: u64,
        /// `(gap, length)` pairs after the first range, as on the wire.
        ranges: Vec<(u64, u64)>,
    },
    Crypto {
        offset: u64,
        data: Vec<u8>,
    },
    Stream {
        id: u64,
        offset: u64,
        fin: bool,
        data: Vec<u8>,
    },
    ResetStream {
        id: u64,
        error_code: u64,
        final_size: u64,
    },
    StopSending {
        id: u64,
        error_code: u64,
    },
    MaxData(u64),
    MaxStreamData {
        id: u64,
        max: u64,
    },
    MaxStreams {
        uni: bool,
        max: u64,
    },
    /// Kept apart from the other blocked frames because its stream ID is checked against the
    /// receive state.
    StreamDataBlocked {
        id: u64,
        limit: u64,
    },
    ConnectionClose {
        error_code: u64,
        frame_type: Option<u64>,
        reason: Vec<u8>,
    },
    HandshakeDone,

    NewConnectionId {
        /// The handshake connection ID is 0.
        sequence: u64,
        retire_prior_to: u64,
        /// 1 to 20 bytes.
        cid: Vec<u8>,
        reset_token: [u8; 16],
    },

    RetireConnectionId(u64),

    PathChallenge([u8; 8]),

    PathResponse([u8; 8]),

    /// A known type whose contents are checked and dropped.
    Other(u64),
}

/// Every read is bounds-checked.
struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn vi(&mut self) -> Option<u64> {
        let (v, n) = varint::read(self.b.get(self.pos..)?)?;
        self.pos += n;
        Some(v)
    }
    /// None leaves the position unchanged.
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.b.get(self.pos..end)?;
        self.pos += n;
        Some(s)
    }
    fn rest(&mut self) -> &'a [u8] {
        let s = &self.b[self.pos..];
        self.pos = self.b.len();
        s
    }
    fn empty(&self) -> bool {
        self.pos >= self.b.len()
    }
}

/// An unknown frame type fails the whole parse, as RFC 9000 requires: frames carry no length, so
/// the bytes after it cannot be read.
///
/// None on malformed input or past a limit.
pub fn parse(buf: &[u8]) -> Option<Vec<Frame>> {
    let mut c = Cursor { b: buf, pos: 0 };
    let mut out = Vec::new();
    while !c.empty() {
        if out.len() >= MAX_PARSED_FRAMES {
            return None;
        }
        let t = c.vi()?;
        let f = match t {
            ftype::PADDING => {
                let mut n = 1;
                while c.b.get(c.pos) == Some(&0) {
                    c.pos += 1;
                    n += 1;
                }
                Frame::Padding(n)
            }
            ftype::PING => Frame::Ping,
            ftype::ACK | ftype::ACK_ECN => {
                let largest = c.vi()?;
                let delay = c.vi()?;
                let count = c.vi()?;
                if count > MAX_PARSED_ACK_RANGES {
                    return None;
                }
                let first_range = c.vi()?;
                let mut ranges = Vec::with_capacity(usize::try_from(count).ok()?);
                for _ in 0..count {
                    let gap = c.vi()?;
                    let len = c.vi()?;
                    ranges.push((gap, len));
                }
                if t == ftype::ACK_ECN {
                    c.vi()?;
                    c.vi()?;
                    c.vi()?;
                }
                Frame::Ack {
                    largest,
                    delay,
                    first_range,
                    ranges,
                }
            }
            ftype::CRYPTO => {
                let offset = c.vi()?;
                let len = usize::try_from(c.vi()?).ok()?;
                let data = c.take(len)?.to_vec();
                Frame::Crypto { offset, data }
            }
            t if (ftype::STREAM..=ftype::STREAM + 7).contains(&t) => {
                let id = c.vi()?;
                let offset = if t & 0x04 != 0 { c.vi()? } else { 0 };
                let fin = t & 0x01 != 0;
                let data = if t & 0x02 != 0 {
                    let len = usize::try_from(c.vi()?).ok()?;
                    c.take(len)?.to_vec()
                } else {
                    c.rest().to_vec()
                };
                Frame::Stream {
                    id,
                    offset,
                    fin,
                    data,
                }
            }
            ftype::MAX_DATA => Frame::MaxData(c.vi()?),
            ftype::MAX_STREAM_DATA => {
                let id = c.vi()?;
                Frame::MaxStreamData { id, max: c.vi()? }
            }
            ftype::MAX_STREAMS_BIDI | ftype::MAX_STREAMS_UNI => {
                let max = c.vi()?;
                if max > MAX_STREAM_COUNT {
                    return None;
                }
                Frame::MaxStreams {
                    uni: t == ftype::MAX_STREAMS_UNI,
                    max,
                }
            }
            ftype::CONNECTION_CLOSE | ftype::CONNECTION_CLOSE_APP => {
                let error_code = c.vi()?;
                let frame_type = if t == ftype::CONNECTION_CLOSE {
                    Some(c.vi()?)
                } else {
                    None
                };
                let len = usize::try_from(c.vi()?).ok()?;
                let reason = c.take(len)?.to_vec();
                Frame::ConnectionClose {
                    error_code,
                    frame_type,
                    reason,
                }
            }
            ftype::HANDSHAKE_DONE => Frame::HandshakeDone,

            ftype::RESET_STREAM => {
                let id = c.vi()?;
                let error_code = c.vi()?;
                let final_size = c.vi()?;
                Frame::ResetStream {
                    id,
                    error_code,
                    final_size,
                }
            }
            ftype::STOP_SENDING => Frame::StopSending {
                id: c.vi()?,
                error_code: c.vi()?,
            },
            ftype::NEW_TOKEN => {
                let len = usize::try_from(c.vi()?).ok()?;
                if len == 0 {
                    return None;
                }
                c.take(len)?;
                Frame::Other(t)
            }
            ftype::DATA_BLOCKED => {
                c.vi()?;
                Frame::Other(t)
            }
            ftype::STREAM_DATA_BLOCKED => {
                let id = c.vi()?;
                Frame::StreamDataBlocked { id, limit: c.vi()? }
            }
            ftype::STREAMS_BLOCKED_BIDI | ftype::STREAMS_BLOCKED_UNI => {
                // RFC 9000 makes a count above 2^60 a connection error.
                if c.vi()? > MAX_STREAM_COUNT {
                    return None;
                }
                Frame::Other(t)
            }
            ftype::NEW_CONNECTION_ID => {
                let sequence = c.vi()?;
                let retire_prior_to = c.vi()?;
                if retire_prior_to > sequence {
                    return None;
                }
                let cid_len = usize::from(*c.take(1)?.first()?);
                if !(1..=20).contains(&cid_len) {
                    return None;
                }
                let cid = c.take(cid_len)?.to_vec();
                let reset_token = c.take(16)?.try_into().ok()?;
                Frame::NewConnectionId {
                    sequence,
                    retire_prior_to,
                    cid,
                    reset_token,
                }
            }
            ftype::RETIRE_CONNECTION_ID => Frame::RetireConnectionId(c.vi()?),
            ftype::PATH_CHALLENGE => {
                let d: [u8; 8] = c.take(8)?.try_into().ok()?;
                Frame::PathChallenge(d)
            }
            ftype::PATH_RESPONSE => {
                let d: [u8; 8] = c.take(8)?.try_into().ok()?;
                Frame::PathResponse(d)
            }
            _ => return None,
        };
        out.push(f);
    }
    Some(out)
}

pub fn encode(out: &mut Vec<u8>, f: &Frame) {
    match f {
        Frame::Padding(n) => out.extend(std::iter::repeat_n(0u8, *n)),
        Frame::Ping => varint::write(out, ftype::PING),
        Frame::HandshakeDone => varint::write(out, ftype::HANDSHAKE_DONE),
        Frame::Crypto { offset, data } => {
            varint::write(out, ftype::CRYPTO);
            varint::write(out, *offset);
            varint::write(out, data.len() as u64);
            out.extend_from_slice(data);
        }
        Frame::Stream {
            id,
            offset,
            fin,
            data,
        } => {
            let mut t = ftype::STREAM | 0x02;
            if *offset != 0 {
                t |= 0x04;
            }
            if *fin {
                t |= 0x01;
            }
            varint::write(out, t);
            varint::write(out, *id);
            if *offset != 0 {
                varint::write(out, *offset);
            }
            varint::write(out, data.len() as u64);
            out.extend_from_slice(data);
        }
        Frame::ResetStream {
            id,
            error_code,
            final_size,
        } => {
            varint::write(out, ftype::RESET_STREAM);
            varint::write(out, *id);
            varint::write(out, *error_code);
            varint::write(out, *final_size);
        }
        Frame::StopSending { id, error_code } => {
            varint::write(out, ftype::STOP_SENDING);
            varint::write(out, *id);
            varint::write(out, *error_code);
        }
        Frame::Ack {
            largest,
            delay,
            first_range,
            ranges,
        } => {
            varint::write(out, ftype::ACK);
            varint::write(out, *largest);
            varint::write(out, *delay);
            varint::write(out, ranges.len() as u64);
            varint::write(out, *first_range);
            for (gap, len) in ranges {
                varint::write(out, *gap);
                varint::write(out, *len);
            }
        }
        Frame::MaxData(v) => {
            varint::write(out, ftype::MAX_DATA);
            varint::write(out, *v);
        }
        Frame::MaxStreamData { id, max } => {
            varint::write(out, ftype::MAX_STREAM_DATA);
            varint::write(out, *id);
            varint::write(out, *max);
        }
        Frame::MaxStreams { uni, max } => {
            varint::write(
                out,
                if *uni {
                    ftype::MAX_STREAMS_UNI
                } else {
                    ftype::MAX_STREAMS_BIDI
                },
            );
            varint::write(out, *max);
        }
        Frame::StreamDataBlocked { id, limit } => {
            varint::write(out, ftype::STREAM_DATA_BLOCKED);
            varint::write(out, *id);
            varint::write(out, *limit);
        }
        Frame::ConnectionClose {
            error_code,
            frame_type,
            reason,
        } => {
            varint::write(
                out,
                if frame_type.is_some() {
                    ftype::CONNECTION_CLOSE
                } else {
                    ftype::CONNECTION_CLOSE_APP
                },
            );
            varint::write(out, *error_code);
            if let Some(ft) = frame_type {
                varint::write(out, *ft);
            }
            varint::write(out, reason.len() as u64);
            out.extend_from_slice(reason);
        }
        Frame::NewConnectionId {
            sequence,
            retire_prior_to,
            cid,
            reset_token,
        } => {
            varint::write(out, ftype::NEW_CONNECTION_ID);
            varint::write(out, *sequence);
            varint::write(out, *retire_prior_to);
            out.push(cid.len() as u8);
            out.extend_from_slice(cid);
            out.extend_from_slice(reset_token);
        }
        Frame::RetireConnectionId(sequence) => {
            varint::write(out, ftype::RETIRE_CONNECTION_ID);
            varint::write(out, *sequence);
        }
        Frame::PathChallenge(d) => {
            varint::write(out, ftype::PATH_CHALLENGE);
            out.extend_from_slice(d);
        }
        Frame::PathResponse(d) => {
            varint::write(out, ftype::PATH_RESPONSE);
            out.extend_from_slice(d);
        }
        Frame::Other(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(f: Frame) {
        let mut buf = Vec::new();
        encode(&mut buf, &f);
        let parsed = parse(&buf).unwrap();
        assert_eq!(parsed.len(), 1, "프레임 1개");
        assert_eq!(parsed[0], f);
    }

    #[test]
    fn crypto_roundtrip() {
        roundtrip(Frame::Crypto {
            offset: 0,
            data: b"ClientHello...".to_vec(),
        });
        roundtrip(Frame::Crypto {
            offset: 1200,
            data: vec![0xAB; 300],
        });
    }

    #[test]
    fn stream_roundtrip() {
        roundtrip(Frame::Stream {
            id: 0,
            offset: 0,
            fin: true,
            data: b"\x00\x20dnsquery".to_vec(),
        });
        roundtrip(Frame::Stream {
            id: 4,
            offset: 100,
            fin: false,
            data: vec![1, 2, 3],
        });
        roundtrip(Frame::ResetStream {
            id: 4,
            error_code: 0x10,
            final_size: 123,
        });
        roundtrip(Frame::StopSending {
            id: 8,
            error_code: 0x11,
        });
    }

    #[test]
    fn ack_roundtrip() {
        roundtrip(Frame::Ack {
            largest: 10,
            delay: 3,
            first_range: 5,
            ranges: vec![(1, 2), (0, 1)],
        });
    }

    #[test]
    fn close_and_simple_roundtrip() {
        roundtrip(Frame::ConnectionClose {
            error_code: 0,
            frame_type: Some(0),
            reason: b"bye".to_vec(),
        });
        roundtrip(Frame::ConnectionClose {
            error_code: 1,
            frame_type: None,
            reason: vec![],
        });
        roundtrip(Frame::HandshakeDone);
        roundtrip(Frame::Ping);
        roundtrip(Frame::MaxStreams {
            uni: true,
            max: 100,
        });
    }

    #[test]
    fn connection_id_frames_roundtrip() {
        roundtrip(Frame::NewConnectionId {
            sequence: 3,
            retire_prior_to: 2,
            cid: vec![0x5a; 20],
            reset_token: [0xc3; 16],
        });
        roundtrip(Frame::RetireConnectionId(7));
    }

    #[test]
    fn new_connection_id_rejects_bad_lengths() {
        let frame_with = |cid_len: u8, token_len: usize| {
            let mut buf = Vec::new();
            varint::write(&mut buf, ftype::NEW_CONNECTION_ID);
            varint::write(&mut buf, 1);
            varint::write(&mut buf, 0);
            buf.push(cid_len);
            buf.extend(std::iter::repeat_n(1u8, usize::from(cid_len)));
            buf.extend(std::iter::repeat_n(2u8, token_len));
            buf
        };
        assert!(parse(&frame_with(8, 16)).is_some());
        assert!(parse(&frame_with(0, 16)).is_none(), "길이 0 식별자");
        assert!(
            parse(&frame_with(21, 16)).is_none(),
            "20 바이트를 넘는 식별자"
        );
        assert!(parse(&frame_with(8, 15)).is_none(), "잘린 재설정 토큰");
    }

    #[test]
    fn parses_multiple_frames_and_padding() {
        let mut buf = Vec::new();
        encode(&mut buf, &Frame::Ping);
        buf.extend([0u8, 0, 0]);
        encode(
            &mut buf,
            &Frame::Crypto {
                offset: 0,
                data: vec![9, 9],
            },
        );
        let fs = parse(&buf).unwrap();
        assert_eq!(fs[0], Frame::Ping);
        assert_eq!(fs[1], Frame::Padding(3));
        assert_eq!(
            fs[2],
            Frame::Crypto {
                offset: 0,
                data: vec![9, 9]
            }
        );
    }

    #[test]
    fn unknown_frame_errors() {
        assert!(parse(&[0x3f]).is_none());
    }

    #[test]
    fn parser_rejects_excessive_counts_and_invalid_connection_ids() {
        let mut too_many_frames = vec![ftype::PING as u8; MAX_PARSED_FRAMES + 1];
        assert!(parse(&too_many_frames).is_none());
        too_many_frames.pop();
        assert_eq!(parse(&too_many_frames).unwrap().len(), MAX_PARSED_FRAMES);

        let mut too_many_ack_ranges = Vec::new();
        varint::write(&mut too_many_ack_ranges, ftype::ACK);
        varint::write(&mut too_many_ack_ranges, 0);
        varint::write(&mut too_many_ack_ranges, 0);
        varint::write(
            &mut too_many_ack_ranges,
            MAX_PARSED_ACK_RANGES.saturating_add(1),
        );
        varint::write(&mut too_many_ack_ranges, 0);
        assert!(parse(&too_many_ack_ranges).is_none());

        let mut bad_cid = Vec::new();
        varint::write(&mut bad_cid, ftype::NEW_CONNECTION_ID);
        varint::write(&mut bad_cid, 1);
        varint::write(&mut bad_cid, 2);
        bad_cid.push(0);
        bad_cid.extend_from_slice(&[0; 16]);
        assert!(parse(&bad_cid).is_none());

        assert!(parse(&[ftype::NEW_TOKEN as u8, 0]).is_none());
    }

    #[test]
    fn cursor_rejects_offset_overflow_without_advancing() {
        let mut cursor = Cursor { b: &[0], pos: 1 };
        assert!(cursor.take(usize::MAX).is_none());
        assert_eq!(cursor.pos, 1);
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn parser_rejects_varint_lengths_wider_than_usize() {
        let mut crypto = Vec::new();
        varint::write(&mut crypto, ftype::CRYPTO);
        varint::write(&mut crypto, 0);
        varint::write(&mut crypto, u64::from(u32::MAX) + 1);
        assert!(parse(&crypto).is_none());
    }

    #[test]
    fn quic_parsers_no_panic_on_adversarial_input() {
        use crate::qpack::Decoder as QpackDecoder;
        let mut seed: u32 = 0x1357_9bdf;
        let mut rng = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        for _ in 0..30000 {
            let len = (rng() % 128) as usize;
            let v: Vec<u8> = (0..len).map(|_| (rng() & 0xff) as u8).collect();
            let _ = parse(&v);
            let _ = crate::varint::read(&v);
            let _ = crate::qpack::decode_field_section(&v);
            let _ = crate::h3::parse_frames(&v);
            let _ = crate::params::TransportParams::decode(&v);
            let mut dec = QpackDecoder::new(4096);
            let _ = dec.decode_field_section((rng() % 8) as u64, &v);
        }
    }
}
