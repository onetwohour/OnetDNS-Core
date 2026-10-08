/*!
 * @brief QUIC 프레임 인코딩과 파싱.
 *
 * @details 패킷 본문은 프레임의 나열이다. 복호화를 통과한 바이트지만 상대가 만든 것이므로
 *          여전히 신뢰 입력이다.
 * @warning 프레임 수와 확인 구간 수에 상한이 있다. 없으면 패킷 하나로 이쪽 메모리와
 *          처리 시간을 마음대로 늘릴 수 있다.
 */

use crate::varint;

/** @brief 패킷 하나에서 읽을 프레임 수 상한. */
const MAX_PARSED_FRAMES: usize = 1024;
/** @brief 확인 프레임 하나에서 읽을 구간 수 상한. */
const MAX_PARSED_ACK_RANGES: u64 = 256;
/** @brief 스트림 수로 쓸 수 있는 최대값. 스트림 번호가 2^62 미만이어야 하기 때문이다. */
pub const MAX_STREAM_COUNT: u64 = 1 << 60;

/** @brief 프레임 유형 번호들. 규격이 정한 값이다. */
pub mod ftype {
    /** @brief 채움. 패킷 크기를 맞추는 데 쓴다. */
    pub const PADDING: u64 = 0x00;
    /** @brief 살아 있는지 확인하고 응답을 끌어낸다. */
    pub const PING: u64 = 0x01;
    /** @brief 받은 패킷을 확인한다. */
    pub const ACK: u64 = 0x02;
    /** @brief 혼잡 표시를 함께 담은 확인. */
    pub const ACK_ECN: u64 = 0x03;
    /** @brief 스트림을 끊는다. */
    pub const RESET_STREAM: u64 = 0x04;
    /** @brief 더 보내지 말라고 알린다. */
    pub const STOP_SENDING: u64 = 0x05;
    /** @brief 핸드셰이크 데이터를 전달한다. */
    pub const CRYPTO: u64 = 0x06;
    /** @brief 다음 연결에 쓸 토큰을 준다. */
    pub const NEW_TOKEN: u64 = 0x07;
    /** @brief 스트림 데이터를 전달한다. 하위 비트가 어떤 필드가 있는지 정한다. */
    pub const STREAM: u64 = 0x08;
    /** @brief 연결 전체의 흐름 제어 윈도우를 늘린다. */
    pub const MAX_DATA: u64 = 0x10;
    /** @brief 스트림 하나의 윈도우를 늘린다. */
    pub const MAX_STREAM_DATA: u64 = 0x11;
    /** @brief 열 수 있는 양방향 스트림 수를 늘린다. */
    pub const MAX_STREAMS_BIDI: u64 = 0x12;
    /** @brief 열 수 있는 단방향 스트림 수를 늘린다. */
    pub const MAX_STREAMS_UNI: u64 = 0x13;
    /** @brief 연결 윈도우가 막혀 못 보내고 있음을 알린다. */
    pub const DATA_BLOCKED: u64 = 0x14;
    /** @brief 스트림 윈도우가 막혔음을 알린다. */
    pub const STREAM_DATA_BLOCKED: u64 = 0x15;
    /** @brief 양방향 스트림 수가 막혔음을 알린다. */
    pub const STREAMS_BLOCKED_BIDI: u64 = 0x16;
    /** @brief 단방향 스트림 수가 막혔음을 알린다. */
    pub const STREAMS_BLOCKED_UNI: u64 = 0x17;
    /** @brief 새 연결 식별자를 준다. */
    pub const NEW_CONNECTION_ID: u64 = 0x18;
    /** @brief 쓰던 식별자를 버린다. */
    pub const RETIRE_CONNECTION_ID: u64 = 0x19;
    /** @brief 경로가 살아 있는지 묻는다. */
    pub const PATH_CHALLENGE: u64 = 0x1a;
    /** @brief 경로 확인에 답한다. */
    pub const PATH_RESPONSE: u64 = 0x1b;
    /** @brief 전송 오류로 연결을 닫는다. */
    pub const CONNECTION_CLOSE: u64 = 0x1c;
    /** @brief 응용 계층 사유로 연결을 닫는다. */
    pub const CONNECTION_CLOSE_APP: u64 = 0x1d;
    /** @brief 핸드셰이크가 끝났음을 알린다. */
    pub const HANDSHAKE_DONE: u64 = 0x1e;
}

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 해석한 프레임 하나. */
pub enum Frame {
    /** @brief 채우기. */
    Padding(usize),
    /** @brief 살아 있는지 묻는다. */
    Ping,
    /** @brief 받았다고 알린다. */
    Ack {
        /** @brief 받은 가장 큰 패킷 번호. */
        largest: u64,
        /** @brief 그것을 받고 알리기까지 미룬 시간. */
        delay: u64,
        /** @brief 그 번호에서 이어 받은 개수. */
        first_range: u64,
        /** @brief 그 앞의 빈틈과 이어 받은 구간들. */
        ranges: Vec<(u64, u64)>,
    },
    /** @brief 핸드셰이크 자료. */
    Crypto { offset: u64, data: Vec<u8> },
    /** @brief 스트림 자료. */
    Stream {
        /** @brief 이 자료가 담긴 스트림. */
        id: u64,
        /** @brief 이 조각이 시작하는 위치. */
        offset: u64,
        /** @brief 이것이 마지막 조각인지. */
        fin: bool,
        /** @brief 담긴 자료. */
        data: Vec<u8>,
    },
    /** @brief 이 스트림을 끊는다. */
    ResetStream {
        /** @brief 끊을 스트림. */
        id: u64,
        /** @brief 끊는 까닭. */
        error_code: u64,
        /** @brief 그 스트림이 결국 얼마였는지. */
        final_size: u64,
    },
    /** @brief 이 스트림을 그만 보내라고 한다. */
    StopSending { id: u64, error_code: u64 },
    /** @brief 전체로 이만큼까지 허락한다. */
    MaxData(u64),
    /** @brief 이 스트림에 이만큼까지 허락한다. */
    MaxStreamData { id: u64, max: u64 },
    /** @brief 스트림을 이만큼까지 열어도 된다. */
    MaxStreams { uni: bool, max: u64 },
    /**
     * @brief 이 스트림의 윈도우가 막혀 못 보내고 있다.
     * @details 스트림 번호를 보고 받는 쪽 상태를 검사해야 하므로 다른 막힘 알림과 달리 따로 읽는다.
     */
    StreamDataBlocked { id: u64, limit: u64 },
    /** @brief 연결을 닫는다. */
    ConnectionClose {
        /** @brief 닫는 까닭. */
        error_code: u64,
        /** @brief 그 오류를 일으킨 프레임 종류. */
        frame_type: Option<u64>,
        /** @brief 사람이 읽을 사유. */
        reason: Vec<u8>,
    },
    /** @brief 핸드셰이크가 끝났음을 알린다. */
    HandshakeDone,

    /** @brief 경로가 살아 있는지 묻는다. */
    PathChallenge([u8; 8]),

    /** @brief 그 물음에 답한다. */
    PathResponse([u8; 8]),

    /** @brief 이쪽이 다루지 않는 종류. 규격대로 그냥 넘긴다. */
    Other(u64),
}

/** @brief 바이트를 앞에서부터 읽는 커서. 모든 읽기가 경계를 검사한다. */
struct Cursor<'a> {
    /** @brief 읽어 들일 바이트. */
    b: &'a [u8],
    /** @brief 지금 위치. */
    pos: usize,
}

impl<'a> Cursor<'a> {
    /** @brief 가변 길이 정수를 읽는다. */
    fn vi(&mut self) -> Option<u64> {
        let (v, n) = varint::read(self.b.get(self.pos..)?)?;
        self.pos += n;
        Some(v)
    }
    /** @brief 정해진 길이만큼 가져온다. 모자라면 None이고 위치는 그대로다. */
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.b.get(self.pos..end)?;
        self.pos += n;
        Some(s)
    }
    /** @brief 남은 바이트 전부. */
    fn rest(&mut self) -> &'a [u8] {
        let s = &self.b[self.pos..];
        self.pos = self.b.len();
        s
    }
    /** @brief 다 읽었는지. */
    fn empty(&self) -> bool {
        self.pos >= self.b.len()
    }
}

/**
 * @brief 패킷 본문을 프레임 목록으로 읽는다.
 * @warning 모르는 유형을 만나면 전부 실패한다. 건너뛰면 그 뒤 바이트를 프레임으로
 *          잘못 읽게 되고, 그것이 곧 상대가 이쪽 파싱을 조종하는 경로가 된다.
 * @return 형식이 어긋나거나 상한을 넘으면 None.
 */
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
                /*
                 * RFC 9000 은 2^60 을 넘는 값을 표현할 수 없는 스트림 번호로 보고 연결 오류로
                 * 정한다.
                 */
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
                let cid_len = *c.b.get(c.pos)? as usize;
                c.pos += 1;
                if !(1..=20).contains(&cid_len) {
                    return None;
                }
                c.take(cid_len)?;
                c.take(16)?;
                Frame::Other(t)
            }
            ftype::RETIRE_CONNECTION_ID => {
                c.vi()?;
                Frame::Other(t)
            }
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

/** @brief 프레임 하나를 와이어 형태로 쓴다. */
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
/** @brief 각 프레임의 왕복과, 조작된 입력에 패닉하지 않는지. */
mod tests {
    use super::*;

    /** @brief 프레임 하나를 쓰고 되읽어 같은지 확인한다. */
    fn roundtrip(f: Frame) {
        let mut buf = Vec::new();
        encode(&mut buf, &f);
        let parsed = parse(&buf).unwrap();
        assert_eq!(parsed.len(), 1, "프레임 1개");
        assert_eq!(parsed[0], f);
    }

    #[test]
    /** @brief 핸드셰이크 데이터 프레임 왕복. */
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
    /** @brief 스트림 프레임 왕복. 선택 필드 조합까지 본다. */
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
    /** @brief 확인 프레임 왕복. */
    fn ack_roundtrip() {
        roundtrip(Frame::Ack {
            largest: 10,
            delay: 3,
            first_range: 5,
            ranges: vec![(1, 2), (0, 1)],
        });
    }

    #[test]
    /** @brief 종료와 단순 프레임들의 왕복. */
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
    /** @brief 여러 프레임과 채움이 섞인 본문을 읽는지. */
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
    /** @brief 모르는 유형에서 전부 실패하는지. 건너뛰면 그 뒤를 잘못 읽는다. */
    fn unknown_frame_errors() {
        assert!(parse(&[0x3f]).is_none());
    }

    #[test]
    /** @brief 상한을 넘는 개수와 잘못된 식별자를 거부하는지. */
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
    /** @brief 길이가 넘칠 때 위치를 건드리지 않고 실패하는지. */
    fn cursor_rejects_offset_overflow_without_advancing() {
        let mut cursor = Cursor { b: &[0], pos: 1 };
        assert!(cursor.take(usize::MAX).is_none());
        assert_eq!(cursor.pos, 1);
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    /** @brief 이 시스템에서 다룰 수 없는 길이를 거부하는지. */
    fn parser_rejects_varint_lengths_wider_than_usize() {
        let mut crypto = Vec::new();
        varint::write(&mut crypto, ftype::CRYPTO);
        varint::write(&mut crypto, 0);
        varint::write(&mut crypto, u64::from(u32::MAX) + 1);
        assert!(parse(&crypto).is_none());
    }

    #[test]
    /** @brief 어떤 바이트에도 패닉하지 않는지. */
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
