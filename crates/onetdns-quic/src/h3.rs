/*!
 * @brief HTTP/3. DoH3에 필요한 만큼만 구현한다.
 *
 * @details 요청과 응답은 양방향 스트림에, 설정과 QPACK 갱신은 단방향 스트림에 오간다.
 *          일반 목적 HTTP 서버가 아니라 DNS 메시지 한 건을 주고받는 데 맞춰져 있다.
 * @warning 스트림 수와 버퍼 크기에 상한이 여럿 걸려 있다. 스트림당 상한만 두면 스트림을
 *          많이 열어 우회할 수 있어, 연결 전체에도 상한이 필요하다.
 */

use std::collections::{HashMap, HashSet};

use onetdns_http2::valid_header_field;

use crate::conn::{Connection, QuicError};
use crate::{qpack, varint};

/** @brief 본문을 전달하는 프레임. */
pub const FRAME_DATA: u64 = 0x00;
/** @brief 헤더를 전달하는 프레임. */
pub const FRAME_HEADERS: u64 = 0x01;
/** @brief 설정을 전달하는 프레임. 제어 스트림의 첫 프레임이어야 한다. */
pub const FRAME_SETTINGS: u64 = 0x04;

/** @brief 이쪽이 받아들일 QPACK 테이블 크기. */
pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
/** @brief 테이블을 기다리며 멈춰 있어도 되는 스트림 수. */
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;
/** @brief 받아들일 헤더 목록의 펼친 크기. */
pub const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x06;

/** @brief 이쪽이 알릴 QPACK 테이블 크기. */
const QPACK_CAPACITY: u64 = 4096;
/** @brief 이쪽이 알릴 대기 스트림 수. */
const QPACK_BLOCKED: u64 = 16;
/** @brief 헤더 목록의 펼친 크기 상한. 압축 증폭을 막는다. */
const MAX_H3_FIELD_SECTION: u64 = 32 * 1024;
/** @brief 동시에 다룰 요청 스트림 수. */
const MAX_H3_STREAMS: usize = 128;
/** @brief 스트림 하나에 모아 둘 바이트 수. */
const MAX_H3_STREAM_BUFFER: usize = 128 * 1024;
/** @brief 연결 전체에 모아 둘 바이트 수. 스트림당 상한만으로는 스트림을 많이 열어 우회할 수 있다. */
const MAX_H3_CONNECTION_BUFFER: usize = 1024 * 1024;
/** @brief 받아들일 단방향 스트림 수. */
const MAX_H3_UNI_STREAMS: usize = 16;
/** @brief 단방향 스트림 하나에 모아 둘 바이트 수. */
const MAX_H3_UNI_BUFFER: usize = 64 * 1024;
/** @brief 받아들일 DNS 본문 크기. */
const MAX_DNS_BODY: usize = 64 * 1024;
/** @brief 경로에서 뽑을 클라이언트 식별자 길이 상한. */
const MAX_CLIENT_ID: usize = 256;
/** @brief DoH 자원이 받는 메서드. 405 응답에 담아 보낸다. */
const ALLOWED_METHODS: &[u8] = b"GET, POST";

/** @brief 제어 스트림 종류 번호. */
const UNI_CONTROL: u64 = 0x00;
/** @brief QPACK 테이블 갱신 스트림 종류 번호. */
const UNI_QPACK_ENCODER: u64 = 0x02;
/** @brief QPACK 확인 스트림 종류 번호. */
const UNI_QPACK_DECODER: u64 = 0x03;

/** @brief RFC 9114 의 오류 코드. 더 구체적인 코드를 고르지 않은 HTTP/3 규격 위반에 쓴다. */
const H3_GENERAL_PROTOCOL_ERROR: u64 = 0x0101;
/** @brief 제어 스트림이나 QPACK 스트림이 닫혔다. RFC 9114 와 RFC 9204 가 연결 오류로 정했다. */
const H3_CLOSED_CRITICAL_STREAM: u64 = 0x0104;

/** @brief 연결 전체 버퍼 상한 안에 들어가는지. */
fn fits_connection_buffer(buffered: usize, incoming: usize) -> bool {
    buffered
        .checked_add(incoming)
        .is_some_and(|total| total <= MAX_H3_CONNECTION_BUFFER)
}

/** @brief 프레임 하나를 쓴다. 유형과 길이가 앞에 붙는다. */
pub fn encode_frame(out: &mut Vec<u8>, ftype: u64, payload: &[u8]) {
    varint::write(out, ftype);
    varint::write(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

/** @brief 버퍼 전체를 프레임 목록으로 읽는다. */
pub fn parse_frames(buf: &[u8]) -> Option<Vec<(u64, Vec<u8>)>> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    while pos < buf.len() {
        let (t, n) = varint::read(buf.get(pos..)?)?;
        pos += n;
        let (len, n) = varint::read(buf.get(pos..)?)?;
        pos += n;
        let len = usize::try_from(len).ok()?;
        let end = pos.checked_add(len)?;
        let payload = buf.get(pos..end)?.to_vec();
        pos = end;
        out.push((t, payload));
    }
    Some(out)
}

/**
 * @brief 다 온 프레임만 꺼내고 나머지는 남긴다.
 * @details 스트림 데이터는 조각나서 온다. 덜 온 프레임을 오류로 보면 정상 통신이 끊긴다.
 */
fn drain_complete_frames(buf: &mut Vec<u8>) -> Vec<(u64, Vec<u8>)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let Some((t, n1)) = varint::read(&buf[pos..]) else {
            break;
        };
        let Some((len, n2)) = varint::read(&buf[pos + n1..]) else {
            break;
        };
        let Ok(len) = usize::try_from(len) else {
            buf.clear();
            break;
        };
        let Some(header_len) = n1.checked_add(n2) else {
            buf.clear();
            break;
        };
        let Some(total) = header_len.checked_add(len) else {
            buf.clear();
            break;
        };
        let Some(end) = pos.checked_add(total) else {
            buf.clear();
            break;
        };
        if buf.len() < end {
            break;
        }
        let payload_start = pos + header_len;
        out.push((t, buf[payload_start..end].to_vec()));
        pos = end;
    }
    buf.drain(..pos);
    out
}

/**
 * @brief 설정 프레임을 읽는다.
 * @warning 같은 설정이 두 번 오면 거부한다. 어느 값을 쓸지 정해지지 않고, 구현마다 다르게
 *          고르면 그 차이를 노릴 수 있다.
 */
fn parse_settings(payload: &[u8]) -> Result<Vec<(u64, u64)>, ()> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut pos = 0usize;
    while pos < payload.len() {
        let (id, n1) = varint::read(&payload[pos..]).ok_or(())?;
        pos += n1;
        let (v, n2) = varint::read(&payload[pos..]).ok_or(())?;
        pos += n2;
        if matches!(id, 0x02..=0x05) || !seen.insert(id) {
            return Err(());
        }
        out.push((id, v));
    }
    Ok(out)
}

/** @brief 이쪽이 알릴 설정. */
fn our_settings() -> Vec<u8> {
    let mut s = Vec::new();
    varint::write(&mut s, SETTINGS_QPACK_MAX_TABLE_CAPACITY);
    varint::write(&mut s, QPACK_CAPACITY);
    varint::write(&mut s, SETTINGS_QPACK_BLOCKED_STREAMS);
    varint::write(&mut s, QPACK_BLOCKED);
    varint::write(&mut s, SETTINGS_MAX_FIELD_SECTION_SIZE);
    varint::write(&mut s, MAX_H3_FIELD_SECTION);
    s
}

#[derive(Default)]
/** @brief 받고 있는 단방향 스트림 하나. */
struct UniIn {
    /** @brief 아직 온전한 것이 되지 못한 바이트. */
    buf: Vec<u8>,
    /** @brief 이 스트림의 쓰임새. 첫 값을 읽어야 안다. */
    stype: Option<u64>,
    /** @brief 설정 메시지를 이미 봤는지. 두 번 오면 프로토콜 위반이다. */
    settings_seen: bool,
}

/** @brief QPACK 인코더와 디코더, 그리고 제어 스트림 상태. */
struct QpackCtx {
    /** @brief 헤더를 적는 쪽. */
    enc: qpack::Encoder,
    /** @brief 헤더를 읽는 쪽. */
    dec: qpack::Decoder,

    /** @brief 이쪽이 연 제어 스트림. */
    ctrl_sid: Option<u64>,
    /** @brief 이쪽이 연 적는 쪽 스트림. */
    enc_sid: Option<u64>,
    /** @brief 이쪽이 연 읽는 쪽 스트림. */
    dec_sid: Option<u64>,
    /** @brief 제어 스트림의 첫 값을 보냈는지. */
    ctrl_sent: bool,
    /** @brief 적는 쪽 스트림의 첫 값을 보냈는지. */
    enc_sent: bool,
    /** @brief 읽는 쪽 스트림의 첫 값을 보냈는지. */
    dec_sent: bool,
    /** @brief 상대가 연 제어 스트림. */
    peer_ctrl_sid: Option<u64>,
    /** @brief 상대가 연 적는 쪽 스트림. */
    peer_enc_sid: Option<u64>,
    /** @brief 상대가 연 읽는 쪽 스트림. */
    peer_dec_sid: Option<u64>,
    /** @brief 상대가 연 단방향 스트림들의 상태. */
    uni_in: HashMap<u64, UniIn>,
}

/** @brief HashMap의 실제 bucket 수보다 작은 공개 capacity를 보수적으로 환산한다. */
fn hash_map_retained_bytes<K, V>(map: &HashMap<K, V>) -> usize {
    if map.capacity() == 0 {
        return 0;
    }
    map.capacity()
        .saturating_mul(std::mem::size_of::<(K, V)>().saturating_add(1))
        .saturating_mul(2)
        .saturating_add(64)
}

impl QpackCtx {
    /** @brief 초기 상태. */
    fn new() -> Self {
        QpackCtx {
            enc: qpack::Encoder::new(),
            dec: qpack::Decoder::new(QPACK_CAPACITY as usize),
            ctrl_sid: None,
            enc_sid: None,
            dec_sid: None,
            ctrl_sent: false,
            enc_sent: false,
            dec_sent: false,
            peer_ctrl_sid: None,
            peer_enc_sid: None,
            peer_dec_sid: None,
            uni_in: HashMap::new(),
        }
    }

    /** @brief QPACK 테이블과 단방향 제어 입력이 보유한 바이트. */
    fn retained_payload_bytes(&self) -> usize {
        self.enc
            .retained_payload_bytes()
            .saturating_add(self.dec.retained_payload_bytes())
            .saturating_add(hash_map_retained_bytes(&self.uni_in))
            .saturating_add(self.uni_in.values().fold(0usize, |total, stream| {
                total.saturating_add(stream.buf.capacity())
            }))
    }

    /** @brief 제어와 QPACK 스트림을 열고 설정을 보낸다. */
    fn send_setup(&mut self, conn: &mut Connection) -> Result<(), QuicError> {
        if self.ctrl_sid.is_none() {
            self.ctrl_sid = Some(conn.open_uni_stream()?);
        }
        if self.enc_sid.is_none() {
            self.enc_sid = Some(conn.open_uni_stream()?);
        }
        if self.dec_sid.is_none() {
            self.dec_sid = Some(conn.open_uni_stream()?);
        }

        if !self.ctrl_sent {
            let mut data = Vec::new();
            varint::write(&mut data, UNI_CONTROL);
            encode_frame(&mut data, FRAME_SETTINGS, &our_settings());
            send_critical(conn, self.ctrl_sid.ok_or(QuicError::StreamLimit)?, &data)?;
            self.ctrl_sent = true;
        }
        if !self.enc_sent {
            let mut data = Vec::new();
            varint::write(&mut data, UNI_QPACK_ENCODER);
            send_critical(conn, self.enc_sid.ok_or(QuicError::StreamLimit)?, &data)?;
            self.enc_sent = true;
        }
        if !self.dec_sent {
            let mut data = Vec::new();
            varint::write(&mut data, UNI_QPACK_DECODER);
            send_critical(conn, self.dec_sid.ok_or(QuicError::StreamLimit)?, &data)?;
            self.dec_sent = true;
        }
        Ok(())
    }

    /**
     * @brief 단방향 스트림 데이터를 처리한다.
     * @warning 제어 스트림은 연결마다 하나뿐이다. 두 번째가 오면 연결을 끊는다. 첫 프레임이
     *          설정이 아닌 경우도 마찬가지다.
     */
    fn on_uni(&mut self, id: u64, data: &[u8], fin: bool) -> Result<(), ()> {
        if !self.uni_in.contains_key(&id) && self.uni_in.len() >= MAX_H3_UNI_STREAMS {
            return Err(());
        }
        let critical = {
            let u = self.uni_in.entry(id).or_default();
            if u.buf.len().saturating_add(data.len()) > MAX_H3_UNI_BUFFER {
                return Err(());
            }
            u.buf.extend_from_slice(data);
            if u.stype.is_none() {
                match varint::read(&u.buf) {
                    Some((t, n)) => {
                        let peer_sid = match t {
                            UNI_CONTROL => Some(&mut self.peer_ctrl_sid),
                            UNI_QPACK_ENCODER => Some(&mut self.peer_enc_sid),
                            UNI_QPACK_DECODER => Some(&mut self.peer_dec_sid),
                            _ => None,
                        };
                        if let Some(peer_sid) = peer_sid {
                            match *peer_sid {
                                Some(existing) if existing != id => return Err(()),
                                None => *peer_sid = Some(id),
                                Some(_) => {}
                            }
                        }
                        u.stype = Some(t);
                        u.buf.drain(..n);
                    }
                    None if !fin => return Ok(()),
                    None => {}
                }
            }
            match u.stype {
                Some(UNI_CONTROL) => {
                    for (t, payload) in drain_complete_frames(&mut u.buf) {
                        if !u.settings_seen {
                            if t != FRAME_SETTINGS {
                                return Err(());
                            }
                            u.settings_seen = true;
                        } else if t == FRAME_SETTINGS {
                            return Err(());
                        }
                        if t == FRAME_SETTINGS {
                            for (id, v) in parse_settings(&payload)? {
                                if id == SETTINGS_QPACK_MAX_TABLE_CAPACITY {
                                    let cap = usize::try_from(v).map_err(|_| ())?;
                                    self.enc
                                        .set_peer_max_capacity(cap.min(QPACK_CAPACITY as usize));
                                }
                            }
                        }
                    }
                }
                Some(UNI_QPACK_ENCODER) => {
                    let bytes = std::mem::take(&mut u.buf);
                    self.dec.on_encoder_stream(&bytes)?;
                }
                Some(UNI_QPACK_DECODER) => {
                    let bytes = std::mem::take(&mut u.buf);
                    self.enc.on_decoder_stream(&bytes)?;
                }
                _ => u.buf.clear(),
            }
            matches!(
                u.stype,
                Some(UNI_CONTROL | UNI_QPACK_ENCODER | UNI_QPACK_DECODER)
            )
        };
        if fin {
            self.uni_in.remove(&id);
            if critical {
                return Err(());
            }
        }
        Ok(())
    }

    /**
     * @brief 단방향 스트림이 끊겼음을 처리한다.
     * @note 제어와 QPACK 스트림이 끊기면 연결을 이어 갈 수 없다. 규격이 그것을 오류로 정했다.
     */
    fn on_reset(&mut self, id: u64) -> Result<(), ()> {
        let critical = self.peer_ctrl_sid == Some(id)
            || self.peer_enc_sid == Some(id)
            || self.peer_dec_sid == Some(id)
            || self.uni_in.get(&id).is_some_and(|stream| {
                matches!(
                    stream.stype,
                    Some(UNI_CONTROL | UNI_QPACK_ENCODER | UNI_QPACK_DECODER)
                )
            });
        self.uni_in.remove(&id);
        if critical {
            Err(())
        } else {
            Ok(())
        }
    }

    /** @brief 헤더를 인코딩하고 테이블 갱신 지시를 함께 얻는다. */
    fn encode_headers(
        &mut self,
        conn: &mut Connection,
        headers: &[(&[u8], &[u8])],
    ) -> Result<Vec<u8>, QuicError> {
        let (section, enc_bytes) = self.enc.encode_field_section(headers);
        if !enc_bytes.is_empty() {
            if let Some(sid) = self.enc_sid {
                if let Err(error) = send_critical(conn, sid, &enc_bytes) {
                    self.enc.restore_encoder_stream(enc_bytes);
                    return Err(error);
                }
            } else {
                self.enc.restore_encoder_stream(enc_bytes);
                return Err(QuicError::StreamLimit);
            }
        }
        Ok(section)
    }

    /** @brief 쌓인 QPACK 확인 지시를 보낸다. */
    fn flush_decoder_stream(&mut self, conn: &mut Connection) -> Result<(), QuicError> {
        let out = self.dec.take_decoder_stream();
        if !out.is_empty() {
            if let Some(sid) = self.dec_sid {
                if let Err(error) = send_critical(conn, sid, &out) {
                    self.dec.restore_decoder_stream(out);
                    return Err(error);
                }
            } else {
                self.dec.restore_decoder_stream(out);
                return Err(QuicError::StreamLimit);
            }
        }
        Ok(())
    }
}

/**
 * @brief 제어 스트림이나 QPACK 스트림으로 보낸다.
 * @details 이 스트림들이 닫히면 HTTP/3 연결은 이어 갈 수 없다. 상대가 STOP_SENDING 으로
 *          닫은 것을 스트림 오류로 돌려주면 부른 쪽이 연결을 살려 두고, 그 뒤로 헤더 테이블
 *          갱신이 상대에게 닿지 않는다. 그래서 연결 오류로 바꾸고 그 코드로 연결을 닫는다.
 */
fn send_critical(conn: &mut Connection, id: u64, data: &[u8]) -> Result<(), QuicError> {
    match conn.send_stream(id, data, false) {
        Err(QuicError::StreamClosed) => {
            conn.close(H3_CLOSED_CRITICAL_STREAM, "HTTP/3 critical stream closed");
            Err(QuicError::Frame)
        }
        other => other,
    }
}

/** @brief base64url 디코딩. GET 방식 DoH3의 질의가 이 형식으로 온다. */
fn base64url_decode(input: &[u8]) -> Option<Vec<u8>> {
    /** @brief 문자 하나를 6비트 값으로. */
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    if input.is_empty() || input.len() % 4 == 1 || input.contains(&b'=') {
        return None;
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in input {
        let v = val(c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1u32 << bits).wrapping_sub(1);
        }
    }
    (acc == 0).then_some(out)
}

#[derive(Default)]
/** @brief 아직 다 오지 않은 요청 하나. */
struct ReqBuf {
    /** @brief 이 요청에서 모은 바이트. */
    buf: Vec<u8>,
    /** @brief 상대가 다 보냈는지. */
    fin: bool,
    /** @brief 이미 위로 넘겼는지. */
    done: bool,
}

/** @brief 요청이나 응답을 추출한 결과. 아직 덜 온 것과 형식이 틀린 것을 구분한다. */
enum Extracted<T> {
    /** @brief 다 꺼냈다. */
    Done(T),
    /** @brief 아직 못 꺼낸다. 헤더 테이블이 따라오기를 기다린다. */
    Blocked,
    /** @brief 프로토콜에 어긋난다. */
    Bad,
    /**
     * @brief 프로토콜은 맞지만 이 자원이 받지 않는 요청이다.
     *
     * @details 거절하는 까닭을 상태 코드로 담아 보낸다. 400 하나로 접으면 클라이언트가
     *          헤더를 고쳐야 하는지 메서드를 바꿔야 하는지 알 수 없다.
     */
    Refused(&'static [u8]),
}

#[derive(Debug, Clone)]
/** @brief 추출한 DoH3 요청 하나. */
pub struct H3DnsRequest {
    /** @brief 이 요청이 온 스트림. */
    pub stream_id: u64,
    /** @brief 요청에 담긴 질의 바이트. */
    pub wire: Vec<u8>,
    /** @brief 요청한 경로. */
    pub path: Vec<u8>,
    /** @brief 경로에서 읽어 낸 클라이언트 식별자. */
    pub client_id: Option<String>,
}

/**
 * @brief 경로에서 클라이언트 식별자를 추출한다.
 * @details 경로마다 다른 정책을 걸 수 있게 해 준다. 길이에 상한이 있고, 형식이 어긋나면 없다.
 */
fn client_id_from_path(path: &[u8]) -> Option<String> {
    let p = std::str::from_utf8(path).ok()?;
    let base = p.split('?').next().unwrap_or(p).trim_end_matches('/');
    if let Some(id) = base.strip_prefix("/dns-query/") {
        if !id.is_empty() && id.len() <= MAX_CLIENT_ID {
            return Some(id.to_string());
        }
    }
    for kv in p.split('?').nth(1).unwrap_or("").split('&') {
        if let Some(id) = kv
            .strip_prefix("client_id=")
            .or_else(|| kv.strip_prefix("client="))
        {
            if !id.is_empty() && id.len() <= MAX_CLIENT_ID {
                return Some(id.to_string());
            }
        }
    }
    None
}

/**
 * @brief 스트림 버퍼에서 DoH3 요청을 추출한다.
 *
 * @details 프레임 순서와 헤더 규칙을 엄격히 본다. 헤더가 본문보다 먼저 와야 하고,
 *          의사 헤더는 중복될 수 없으며, 알린 길이와 실제 본문 길이가 맞아야 한다.
 * @warning 느슨하게 보면 같은 요청을 서로 다르게 해석하는 구현 차이가 생긴다. 그 차이가
 *          곧 앞단 장비를 우회하는 경로다.
 */
fn extract_dns_request(dec: &mut qpack::Decoder, sid: u64, buf: &[u8]) -> Extracted<H3DnsRequest> {
    let Some(frames) = parse_frames(buf) else {
        return Extracted::Bad;
    };
    let mut method: Option<Vec<u8>> = None;
    let mut scheme: Option<Vec<u8>> = None;
    let mut authority: Option<Vec<u8>> = None;
    let mut host: Option<Vec<u8>> = None;
    let mut path: Option<Vec<u8>> = None;
    let mut content_length: Option<usize> = None;
    let mut content_type: Option<bool> = None;
    let mut headers_seen = false;
    let mut body = Vec::new();
    for (t, payload) in frames {
        if !headers_seen && t == FRAME_DATA {
            return Extracted::Bad;
        }
        match t {
            FRAME_HEADERS => {
                if headers_seen {
                    return Extracted::Bad;
                }
                headers_seen = true;
                match dec.decode_field_section(sid, &payload) {
                    qpack::DecodeResult::Done(headers) => {
                        let mut regular_seen = false;
                        for (n, v) in headers {
                            if !valid_header_field(&n, &v) {
                                return Extracted::Bad;
                            }
                            if n.starts_with(b":") {
                                if regular_seen {
                                    return Extracted::Bad;
                                }
                                let target = match n.as_slice() {
                                    b":method" => &mut method,
                                    b":scheme" => &mut scheme,
                                    b":authority" => &mut authority,
                                    b":path" => &mut path,
                                    _ => return Extracted::Bad,
                                };
                                if target.replace(v).is_some() {
                                    return Extracted::Bad;
                                }
                            } else {
                                regular_seen = true;
                                if matches!(
                                    n.as_slice(),
                                    b"connection"
                                        | b"proxy-connection"
                                        | b"keep-alive"
                                        | b"transfer-encoding"
                                        | b"upgrade"
                                ) {
                                    return Extracted::Bad;
                                }
                                if n == b"content-length" {
                                    if content_length.is_some()
                                        || v.is_empty()
                                        || !v.iter().all(u8::is_ascii_digit)
                                    {
                                        return Extracted::Bad;
                                    }
                                    let Ok(s) = std::str::from_utf8(&v) else {
                                        return Extracted::Bad;
                                    };
                                    let Ok(length) = s.parse::<usize>() else {
                                        return Extracted::Bad;
                                    };
                                    if length > MAX_DNS_BODY {
                                        return Extracted::Bad;
                                    }
                                    content_length = Some(length);
                                } else if n == b"content-type" {
                                    // 형식이 다른 것과 헤더가 겹치는 것은 뜻이 다르다. 겹치는
                                    // 것은 요청 스머글링의 경로라 그대로 400 이고, 다른 형식은
                                    // 415 로 구분해야 클라이언트가 고칠 수 있다.
                                    let is_dns = v.eq_ignore_ascii_case(b"application/dns-message");
                                    if content_type.replace(is_dns).is_some() {
                                        return Extracted::Bad;
                                    }
                                } else if n == b"host" {
                                    if host.replace(v).is_some() {
                                        return Extracted::Bad;
                                    }
                                } else if n == b"te" && v != b"trailers" {
                                    return Extracted::Bad;
                                }
                            }
                        }
                    }
                    qpack::DecodeResult::Blocked => return Extracted::Blocked,
                    qpack::DecodeResult::Error => return Extracted::Bad,
                }
            }
            FRAME_DATA => {
                if body.len().saturating_add(payload.len()) > MAX_DNS_BODY {
                    return Extracted::Bad;
                }
                body.extend_from_slice(&payload)
            }
            FRAME_SETTINGS => return Extracted::Bad,
            _ => {}
        }
    }
    let Some(path) = path else {
        return Extracted::Bad;
    };
    let Some(authority) = authority.as_deref() else {
        return Extracted::Bad;
    };
    if scheme.as_deref() != Some(b"https")
        || authority.is_empty()
        || host.as_deref().is_some_and(|host| host != authority)
    {
        return Extracted::Bad;
    }
    let client_id = client_id_from_path(&path);
    match method.as_deref() {
        Some(b"POST") => {
            if content_type != Some(true) {
                return Extracted::Refused(b"415");
            }
            if content_length.is_some_and(|length| length != body.len()) {
                return Extracted::Bad;
            }
            Extracted::Done(H3DnsRequest {
                stream_id: sid,
                wire: body,
                path,
                client_id,
            })
        }
        Some(b"GET") => {
            if !body.is_empty() || content_length.is_some_and(|length| length != 0) {
                return Extracted::Bad;
            }
            let p = path;
            let Some(query) = p.split(|&c| c == b'?').nth(1) else {
                return Extracted::Bad;
            };
            for kv in query.split(|&c| c == b'&') {
                if let Some(v) = kv.strip_prefix(b"dns=") {
                    return match base64url_decode(v) {
                        Some(d) if d.len() <= MAX_DNS_BODY => Extracted::Done(H3DnsRequest {
                            stream_id: sid,
                            wire: d,
                            path: p,
                            client_id,
                        }),
                        Some(_) | None => Extracted::Bad,
                    };
                }
            }
            Extracted::Bad
        }
        _ => Extracted::Refused(b"405"),
    }
}

/** @brief 서버 쪽 HTTP/3 연결. */
pub struct H3Connection {
    /** @brief 아래에 깔린 QUIC 연결. */
    conn: Connection,
    /** @brief 제어 스트림의 첫 값을 보냈는지. */
    control_sent: bool,
    /** @brief 받고 있는 요청들. */
    requests: HashMap<u64, ReqBuf>,
    /** @brief 위로 넘길 준비가 된 요청들. */
    ready: Vec<H3DnsRequest>,
    /** @brief 헤더 압축 상태. */
    qp: QpackCtx,

    /** @brief 헤더 테이블이 따라오기를 기다리는 요청들. */
    blocked: Vec<(u64, Vec<u8>)>,
}

impl H3Connection {
    /** @brief QUIC 연결 위에 HTTP/3를 얹는다. */
    pub fn new(conn: Connection) -> Self {
        H3Connection {
            conn,
            control_sent: false,
            requests: HashMap::new(),
            ready: Vec::new(),
            qp: QpackCtx::new(),
            blocked: Vec::new(),
        }
    }

    /** @brief 아직 안 보냈으면 제어 스트림 설정을 보낸다. */
    fn maybe_send_control(&mut self) -> Result<(), QuicError> {
        if self.control_sent || !self.conn.is_handshake_complete() || !self.conn.can_send_app() {
            return Ok(());
        }
        self.qp.send_setup(&mut self.conn)?;
        self.control_sent = true;
        Ok(())
    }

    /** @brief 지금 모아 둔 바이트 총량. 연결 상한 판정에 쓴다. */
    fn buffered_bytes(&self) -> usize {
        self.requests
            .values()
            .map(|request| request.buf.len())
            .chain(self.blocked.iter().map(|(_, buf)| buf.len()))
            .chain(self.ready.iter().map(|request| request.wire.len()))
            .fold(0usize, usize::saturating_add)
    }

    /**
     * @brief HTTP/3와 아래 QUIC 연결이 지금 보유한 가변 payload 바이트.
     * @details DoH3 리스너의 전역 메모리 예산이 연결별 상한의 곱을 막는 데 쓴다.
     */
    pub fn retained_payload_bytes(&self) -> usize {
        let requests = hash_map_retained_bytes(&self.requests).saturating_add(
            self.requests.values().fold(0usize, |total, request| {
                total.saturating_add(request.buf.capacity())
            }),
        );
        let blocked = self
            .blocked
            .capacity()
            .saturating_mul(std::mem::size_of::<(u64, Vec<u8>)>())
            .saturating_add(self.blocked.iter().fold(0usize, |total, (_, buf)| {
                total.saturating_add(buf.capacity())
            }));
        let ready = self
            .ready
            .capacity()
            .saturating_mul(std::mem::size_of::<H3DnsRequest>())
            .saturating_add(self.ready.iter().fold(0usize, |total, request| {
                total
                    .saturating_add(request.wire.capacity())
                    .saturating_add(request.path.capacity())
                    .saturating_add(request.client_id.as_ref().map_or(0, String::capacity))
            }));
        self.conn
            .retained_payload_bytes()
            .saturating_add(requests)
            .saturating_add(blocked)
            .saturating_add(ready)
            .saturating_add(self.qp.retained_payload_bytes())
    }

    /** @brief 모은 데이터에서 요청을 추출해 본다. 덜 왔으면 다시 넣어 둔다. */
    fn try_extract(&mut self, id: u64, buf: Vec<u8>) -> Result<(), QuicError> {
        let status = match extract_dns_request(&mut self.qp.dec, id, &buf) {
            Extracted::Done(mut q) => {
                if self.ready.len() >= MAX_H3_STREAMS
                    || !fits_connection_buffer(self.buffered_bytes(), q.wire.len())
                {
                    return Err(QuicError::Frame);
                }
                q.stream_id = id;
                self.ready.push(q);
                return Ok(());
            }
            Extracted::Blocked => {
                if self.blocked.len() < QPACK_BLOCKED as usize
                    && fits_connection_buffer(self.buffered_bytes(), buf.len())
                {
                    self.blocked.push((id, buf));
                    return Ok(());
                }
                return Err(QuicError::Frame);
            }
            Extracted::Bad => b"400".as_slice(),
            Extracted::Refused(status) => status,
        };
        /*
         * 상대가 이 스트림의 답을 이미 거절했으면 보낼 곳이 없을 뿐이다. 그 오류를 올리면
         * recv_datagram 이 실패하고, 부른 쪽은 연결 전체를 버린다.
         */
        match self.send_status(id, status) {
            Ok(()) | Err(QuicError::StreamClosed) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /**
     * @brief 데이터그램 하나를 받아 상태를 진행시킨다.
     * @details HTTP/3 계층에서 연결 오류가 나면 상대에게 알리고 연결을 닫은 뒤 그 오류를
     *          돌려준다. QUIC 계층의 오류는 그 계층이 이미 알렸다.
     */
    pub fn recv_datagram(&mut self, dg: &[u8]) -> Result<(), QuicError> {
        self.conn.recv_datagram(dg)?;
        let processed = self.process_streams();
        if processed.is_err() {
            self.conn
                .close(H3_GENERAL_PROTOCOL_ERROR, "HTTP/3 protocol error");
        }
        processed
    }

    /** @brief QUIC 계층이 내놓은 스트림 데이터를 요청으로 모으고 끊긴 스트림을 정리한다. */
    fn process_streams(&mut self) -> Result<(), QuicError> {
        match self.maybe_send_control() {
            Ok(()) | Err(QuicError::FlowControl | QuicError::StreamLimit) => {}
            Err(error) => return Err(error),
        }
        for (id, _) in self.conn.take_resets() {
            if id & 0x03 == 0x02 {
                self.qp.on_reset(id).map_err(|_| QuicError::Frame)?;
            } else {
                self.requests.remove(&id);
                self.blocked.retain(|(stream_id, _)| *stream_id != id);
                self.ready.retain(|request| request.stream_id != id);
            }
        }
        let events = self.conn.take_readable();
        let mut completed: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut buffered = self.buffered_bytes();
        for (id, data, fin) in events {
            if id & 0x03 == 0x02 {
                self.qp
                    .on_uni(id, &data, fin)
                    .map_err(|_| QuicError::Frame)?;
                continue;
            }
            if id & 0x03 != 0x00 {
                continue;
            }
            if !self.requests.contains_key(&id) && self.requests.len() >= MAX_H3_STREAMS {
                return Err(QuicError::Frame);
            }
            if !fits_connection_buffer(buffered, data.len()) {
                return Err(QuicError::Frame);
            }
            let rb = self.requests.entry(id).or_default();
            if rb.buf.len().saturating_add(data.len()) > MAX_H3_STREAM_BUFFER {
                return Err(QuicError::Frame);
            }
            rb.buf.extend_from_slice(&data);
            buffered += data.len();
            if fin {
                rb.fin = true;
            }
            if rb.fin && !rb.done {
                rb.done = true;
                completed.push((id, std::mem::take(&mut rb.buf)));
            }
        }

        for (id, _) in &completed {
            self.requests.remove(id);
        }

        for (id, buf) in std::mem::take(&mut self.blocked) {
            self.try_extract(id, buf)?;
        }
        for (id, buf) in completed {
            self.try_extract(id, buf)?;
        }
        self.qp.flush_decoder_stream(&mut self.conn)?;
        Ok(())
    }

    /** @brief 완성된 요청들을 메타 정보와 함께 가져간다. */
    pub fn take_requests_meta(&mut self) -> Vec<H3DnsRequest> {
        std::mem::take(&mut self.ready)
    }

    /** @brief 완성된 요청들을 가져간다. */
    pub fn take_requests(&mut self) -> Vec<(u64, Vec<u8>)> {
        self.take_requests_meta()
            .into_iter()
            .map(|r| (r.stream_id, r.wire))
            .collect()
    }

    /** @brief DNS 응답을 보낸다. */
    pub fn send_response(&mut self, id: u64, dns: &[u8], max_age: u32) -> Result<(), QuicError> {
        self.send_response_owned(id, dns.to_vec(), max_age)
    }

    /**
     * @brief 소유권을 넘겨받아 DNS 응답을 보낸다. 복사를 줄인다.
     * @param max_age HTTP 캐시가 신선하다고 볼 시간. RFC 8484가 답변부 최소 TTL을
     *                넘지 못하게 하므로 응답을 만든 쪽이 측정해서 넘긴다.
     */
    pub fn send_response_owned(
        &mut self,
        id: u64,
        dns: Vec<u8>,
        max_age: u32,
    ) -> Result<(), QuicError> {
        self.maybe_send_control()?;
        let cache_control = format!("max-age={max_age}");
        let headers: [(&[u8], &[u8]); 3] = [
            (b":status", b"200"),
            (b"content-type", b"application/dns-message"),
            (b"cache-control", cache_control.as_bytes()),
        ];
        let section = self.qp.encode_headers(&mut self.conn, &headers)?;
        let mut payload = Vec::new();
        encode_frame(&mut payload, FRAME_HEADERS, &section);
        encode_frame(&mut payload, FRAME_DATA, &dns);
        self.conn.send_stream_owned(id, payload, true)
    }

    /** @brief 본문 없이 상태 코드만 보낸다. */
    pub fn send_status(&mut self, id: u64, status: &[u8]) -> Result<(), QuicError> {
        self.maybe_send_control()?;
        // 405 는 받는 메서드를 알려야 한다. 알려 주지 않으면 클라이언트가 무엇으로
        // 다시 물어야 하는지 알 길이 없다.
        let allow: [(&[u8], &[u8]); 2] = [(b":status", status), (b"allow", ALLOWED_METHODS)];
        let plain: [(&[u8], &[u8]); 1] = [(b":status", status)];
        let section = if status == b"405" {
            self.qp.encode_headers(&mut self.conn, &allow)?
        } else {
            self.qp.encode_headers(&mut self.conn, &plain)?
        };
        let mut payload = Vec::new();
        encode_frame(&mut payload, FRAME_HEADERS, &section);
        self.conn.send_stream_owned(id, payload, true)
    }

    /** @brief 내보낼 데이터그램을 꺼낸다. */
    pub fn next_datagram(&mut self) -> Option<Vec<u8>> {
        self.conn.next_datagram()
    }

    /** @brief 핸드셰이크가 끝났는지. */
    pub fn is_handshake_complete(&self) -> bool {
        self.conn.is_handshake_complete()
    }

    /** @brief 이쪽 연결 식별자. */
    pub fn local_connection_id(&self) -> &[u8] {
        self.conn.local_connection_id()
    }

    /** @brief 상대가 알린 전송 매개변수. */
    pub fn peer_transport_params(&self) -> Option<&crate::params::TransportParams> {
        self.conn.peer_transport_params()
    }

    /** @brief 클라이언트 인증서를 확인했는지. */
    pub fn client_authenticated(&self) -> bool {
        self.conn.client_authenticated()
    }

    /** @brief 확인된 클라이언트 신원. */
    pub fn client_auth_identity(&self) -> Option<&str> {
        self.conn.client_auth_identity()
    }

    /** @brief 연결이 닫혔는지. */
    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    /** @brief 밑에 깔린 QUIC 연결. */
    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /** @brief 지금 시각을 알린다. 시간은 밖에서 넣어 준다. */
    pub fn set_now(&mut self, now_ms: u64) {
        self.conn.set_now(now_ms);
    }

    /** @brief 데드라인이 지났을 때 할 일을 한다. */
    pub fn on_timeout(&mut self, now_ms: u64) {
        self.conn.on_timeout(now_ms);
    }
}

#[derive(Default)]
/** @brief 아직 다 오지 않은 응답 하나. */
struct RespBuf {
    /** @brief 이 응답에서 모은 바이트. */
    buf: Vec<u8>,
    /** @brief 다 받았는지. */
    done: bool,
}

/** @brief 클라이언트 쪽 HTTP/3 연결. */
pub struct H3Client {
    /** @brief 아래에 깔린 QUIC 연결. */
    conn: Connection,
    /** @brief 첫 설정을 보냈는지. */
    setup_sent: bool,

    /** @brief 다음에 열 양방향 스트림 번호. */
    next_bidi: u64,
    /** @brief 받고 있는 응답들. */
    resp: HashMap<u64, RespBuf>,

    /** @brief 다 받은 응답들. */
    ready: Vec<(u64, u16, Vec<u8>)>,
    /** @brief 헤더 압축 상태. */
    qp: QpackCtx,

    /** @brief 헤더 테이블이 따라오기를 기다리는 응답들. */
    blocked: Vec<(u64, Vec<u8>)>,
}

impl H3Client {
    /** @brief QUIC 연결 위에 HTTP/3 클라이언트를 얹는다. */
    pub fn new(conn: Connection) -> Self {
        H3Client {
            conn,
            setup_sent: false,
            next_bidi: 0,
            resp: HashMap::new(),
            ready: Vec::new(),
            qp: QpackCtx::new(),
            blocked: Vec::new(),
        }
    }

    /** @brief 아직 안 보냈으면 제어 스트림 설정을 보낸다. */
    fn maybe_send_setup(&mut self) -> Result<(), QuicError> {
        if self.setup_sent {
            return Ok(());
        }
        let ready = (self.conn.is_handshake_complete() && self.conn.can_send_app())
            || self.conn.can_send_early();
        if !ready {
            return Ok(());
        }
        self.qp.send_setup(&mut self.conn)?;
        self.setup_sent = true;
        Ok(())
    }

    /** @brief 핸드셰이크 완료 전에 데이터를 보낼 수 있는지. */
    pub fn can_send_early(&self) -> bool {
        self.conn.can_send_early()
    }

    /** @brief DNS 질의를 요청으로 보낸다. */
    pub fn send_request(
        &mut self,
        authority: &str,
        path: &str,
        body: &[u8],
    ) -> Result<u64, QuicError> {
        self.maybe_send_setup()?;
        let id = self.next_bidi << 2;
        let len_s = body.len().to_string();
        let headers: [(&[u8], &[u8]); 6] = [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", authority.as_bytes()),
            (b":path", path.as_bytes()),
            (b"content-type", b"application/dns-message"),
            (b"content-length", len_s.as_bytes()),
        ];
        let section = self.qp.encode_headers(&mut self.conn, &headers)?;
        let mut payload = Vec::new();
        encode_frame(&mut payload, FRAME_HEADERS, &section);
        encode_frame(&mut payload, FRAME_DATA, body);
        self.conn.send_stream(id, &payload, true)?;
        self.next_bidi += 1;
        Ok(id)
    }

    /** @brief 아직 처리하지 못하고 잡고 있는 바이트. */
    fn buffered_bytes(&self) -> usize {
        self.resp
            .values()
            .map(|response| response.buf.len())
            .chain(self.blocked.iter().map(|(_, buf)| buf.len()))
            .chain(self.ready.iter().map(|(_, _, body)| body.len()))
            .fold(0usize, usize::saturating_add)
    }

    /** @brief 모인 바이트에서 온전한 요청을 꺼낸다. */
    fn try_extract(&mut self, id: u64, buf: Vec<u8>) -> Result<(), QuicError> {
        match extract_dns_response(&mut self.qp.dec, id, &buf) {
            Extracted::Done((status, body)) => {
                if self.ready.len() >= MAX_H3_STREAMS
                    || !fits_connection_buffer(self.buffered_bytes(), body.len())
                {
                    return Err(QuicError::Frame);
                }
                self.ready.push((id, status, body));
            }
            Extracted::Blocked => {
                if self.blocked.len() < QPACK_BLOCKED as usize
                    && fits_connection_buffer(self.buffered_bytes(), buf.len())
                {
                    self.blocked.push((id, buf));
                } else {
                    return Err(QuicError::Frame);
                }
            }
            Extracted::Bad | Extracted::Refused(_) => return Err(QuicError::Frame),
        }
        Ok(())
    }

    /**
     * @brief 받은 데이터그램을 넣는다.
     * @details HTTP/3 계층에서 연결 오류가 나면 상대에게 알리고 연결을 닫은 뒤 그 오류를
     *          돌려준다. QUIC 계층의 오류는 그 계층이 이미 알렸다.
     */
    pub fn recv_datagram(&mut self, dg: &[u8]) -> Result<(), QuicError> {
        self.conn.recv_datagram(dg)?;
        let processed = self.process_streams();
        if processed.is_err() {
            self.conn
                .close(H3_GENERAL_PROTOCOL_ERROR, "HTTP/3 protocol error");
        }
        processed
    }

    /** @brief QUIC 계층이 내놓은 스트림 데이터를 응답으로 모으고 끊긴 스트림을 정리한다. */
    fn process_streams(&mut self) -> Result<(), QuicError> {
        match self.maybe_send_setup() {
            Ok(()) | Err(QuicError::FlowControl | QuicError::StreamLimit) => {}
            Err(error) => return Err(error),
        }
        for (id, _) in self.conn.take_resets() {
            if id & 0x03 == 0x03 {
                self.qp.on_reset(id).map_err(|_| QuicError::Frame)?;
            } else {
                self.resp.remove(&id);
                self.blocked.retain(|(stream_id, _)| *stream_id != id);
                self.ready.retain(|(stream_id, _, _)| *stream_id != id);
                self.ready.push((id, 0, Vec::new()));
            }
        }
        let events = self.conn.take_readable();
        let mut completed: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut buffered = self.buffered_bytes();
        for (id, data, fin) in events {
            if id & 0x03 == 0x03 {
                self.qp
                    .on_uni(id, &data, fin)
                    .map_err(|_| QuicError::Frame)?;
                continue;
            }
            if id & 0x03 != 0x00 {
                continue;
            }
            if !self.resp.contains_key(&id) && self.resp.len() >= MAX_H3_STREAMS {
                return Err(QuicError::Frame);
            }
            if !fits_connection_buffer(buffered, data.len()) {
                return Err(QuicError::Frame);
            }
            let rb = self.resp.entry(id).or_default();
            if rb.buf.len().saturating_add(data.len()) > MAX_H3_STREAM_BUFFER {
                return Err(QuicError::Frame);
            }
            rb.buf.extend_from_slice(&data);
            buffered += data.len();
            if fin && !rb.done {
                rb.done = true;
                completed.push((id, std::mem::take(&mut rb.buf)));
            }
        }
        for (id, _) in &completed {
            self.resp.remove(id);
        }
        for (id, buf) in std::mem::take(&mut self.blocked) {
            self.try_extract(id, buf)?;
        }
        for (id, buf) in completed {
            self.try_extract(id, buf)?;
        }
        self.qp.flush_decoder_stream(&mut self.conn)?;
        Ok(())
    }

    /** @brief 이쪽이 테이블에 넣은 항목 수. */
    pub fn qpack_insert_count(&self) -> u64 {
        self.qp.enc.insert_count()
    }

    /** @brief 상대가 확인한 항목 수. */
    pub fn qpack_known_received(&self) -> u64 {
        self.qp.enc.known_received()
    }

    /** @brief 완성된 응답들을 가져간다. */
    pub fn take_responses(&mut self) -> Vec<(u64, u16, Vec<u8>)> {
        std::mem::take(&mut self.ready)
    }

    /** @brief 이 스트림에 상태만 답한다. */
    pub fn send_status(&mut self, id: u64, status: &[u8]) -> Result<(), QuicError> {
        self.maybe_send_setup()?;
        let headers: [(&[u8], &[u8]); 1] = [(b":status", status)];
        let section = self.qp.encode_headers(&mut self.conn, &headers)?;
        let mut payload = Vec::new();
        encode_frame(&mut payload, FRAME_HEADERS, &section);
        self.conn.send_stream(id, &payload, true)
    }

    /** @brief 내보낼 데이터그램. */
    pub fn next_datagram(&mut self) -> Option<Vec<u8>> {
        self.conn.next_datagram()
    }

    /** @brief 핸드셰이크가 끝났는지. */
    pub fn is_handshake_complete(&self) -> bool {
        self.conn.is_handshake_complete()
    }

    /** @brief 응용 데이터를 보낼 수 있는 상태인지. */
    pub fn can_send_app(&self) -> bool {
        self.conn.can_send_app()
    }

    /** @brief 연결이 닫혔는지. */
    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    /** @brief 아래 연결을 고칠 수 있게. */
    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /** @brief 지금 시각을 알린다. */
    pub fn set_now(&mut self, now_ms: u64) {
        self.conn.set_now(now_ms);
    }

    /** @brief 데드라인이 지났음을 알린다. */
    pub fn on_timeout(&mut self, now_ms: u64) {
        self.conn.on_timeout(now_ms);
    }
}

/**
 * @brief 스트림 버퍼에서 DoH3 응답을 추출한다.
 * @details 요청과 같은 엄격함을 적용한다. 프레임 순서, 상태 헤더 중복, 길이 일치를 모두 본다.
 */
fn extract_dns_response(
    dec: &mut qpack::Decoder,
    sid: u64,
    buf: &[u8],
) -> Extracted<(u16, Vec<u8>)> {
    let Some(frames) = parse_frames(buf) else {
        return Extracted::Bad;
    };
    let mut status: Option<u16> = None;
    let mut content_length: Option<usize> = None;
    let mut dns_content_type = false;
    let mut headers_seen = false;
    let mut body = Vec::new();
    for (t, payload) in frames {
        if !headers_seen && t == FRAME_DATA {
            return Extracted::Bad;
        }
        match t {
            FRAME_HEADERS => {
                if headers_seen {
                    return Extracted::Bad;
                }
                headers_seen = true;
                match dec.decode_field_section(sid, &payload) {
                    qpack::DecodeResult::Done(headers) => {
                        let mut regular_seen = false;
                        for (n, v) in headers {
                            if !valid_header_field(&n, &v) {
                                return Extracted::Bad;
                            }
                            if n.starts_with(b":") {
                                if regular_seen || n != b":status" || status.is_some() {
                                    return Extracted::Bad;
                                }
                                if v.len() != 3 || !v.iter().all(u8::is_ascii_digit) {
                                    return Extracted::Bad;
                                }
                                let parsed = ((v[0] - b'0') as u16) * 100
                                    + ((v[1] - b'0') as u16) * 10
                                    + (v[2] - b'0') as u16;
                                if !(200..=599).contains(&parsed) {
                                    return Extracted::Bad;
                                }
                                status = Some(parsed);
                            } else {
                                regular_seen = true;
                                if matches!(
                                    n.as_slice(),
                                    b"connection"
                                        | b"proxy-connection"
                                        | b"keep-alive"
                                        | b"te"
                                        | b"transfer-encoding"
                                        | b"upgrade"
                                ) {
                                    return Extracted::Bad;
                                }
                                if n == b"content-length" {
                                    if content_length.is_some()
                                        || v.is_empty()
                                        || !v.iter().all(u8::is_ascii_digit)
                                    {
                                        return Extracted::Bad;
                                    }
                                    let Ok(s) = std::str::from_utf8(&v) else {
                                        return Extracted::Bad;
                                    };
                                    let Ok(length) = s.parse::<usize>() else {
                                        return Extracted::Bad;
                                    };
                                    if length > MAX_DNS_BODY {
                                        return Extracted::Bad;
                                    }
                                    content_length = Some(length);
                                } else if n == b"content-type" {
                                    if dns_content_type {
                                        return Extracted::Bad;
                                    }
                                    dns_content_type =
                                        v.eq_ignore_ascii_case(b"application/dns-message");
                                    if !dns_content_type {
                                        return Extracted::Bad;
                                    }
                                }
                            }
                        }
                    }
                    qpack::DecodeResult::Blocked => return Extracted::Blocked,
                    qpack::DecodeResult::Error => return Extracted::Bad,
                }
            }
            FRAME_DATA => {
                if body.len().saturating_add(payload.len()) > MAX_DNS_BODY {
                    return Extracted::Bad;
                }
                body.extend_from_slice(&payload)
            }
            FRAME_SETTINGS => return Extracted::Bad,
            _ => {}
        }
    }
    match status {
        Some(s)
            if content_length.is_none_or(|length| length == body.len())
                && (s != 200 || dns_content_type) =>
        {
            Extracted::Done((s, body))
        }
        None => Extracted::Bad,
        Some(_) => Extracted::Bad,
    }
}

#[cfg(test)]
/** @brief 형식 엄격성, 버퍼 상한, QPACK 동적 테이블, 그리고 조기 데이터 경로. */
mod tests {
    use super::*;

    #[test]
    /** @brief 프레임 왕복. */
    fn frame_roundtrip() {
        let mut buf = Vec::new();
        encode_frame(&mut buf, FRAME_HEADERS, b"hdr");
        encode_frame(&mut buf, FRAME_DATA, b"body-bytes");
        let frames = parse_frames(&buf).unwrap();
        assert_eq!(frames[0], (FRAME_HEADERS, b"hdr".to_vec()));
        assert_eq!(frames[1], (FRAME_DATA, b"body-bytes".to_vec()));
    }

    #[test]
    /** @brief POST 요청에서 DNS 질의를 뽑는지. */
    fn extract_post_request() {
        let dns = b"\x12\x34 fake dns query";
        let mut buf = Vec::new();
        encode_frame(
            &mut buf,
            FRAME_HEADERS,
            &qpack::doh_post_request_headers("h", "/dns-query", dns.len()),
        );
        encode_frame(&mut buf, FRAME_DATA, dns);
        let mut dec = qpack::Decoder::new(4096);
        match extract_dns_request(&mut dec, 0, &buf) {
            Extracted::Done(q) => assert_eq!(q.wire, dns),
            _ => panic!("정적 요청 추출 실패"),
        }
    }

    #[test]
    /** @brief 모르는 프레임이 앞에 와도 무시하고 넘어가는지. 앞으로 늘어날 수 있다. */
    fn grease_before_headers_is_ignored() {
        /** @brief 규격이 무시하라고 정한 프레임 종류. */
        const GREASE_FRAME: u64 = 0x21;
        let dns = b"\x12\x34dns";

        let mut request = Vec::new();
        encode_frame(&mut request, GREASE_FRAME, b"GREASE is the word");
        encode_frame(
            &mut request,
            FRAME_HEADERS,
            &qpack::doh_post_request_headers("h", "/dns-query", dns.len()),
        );
        encode_frame(&mut request, FRAME_DATA, dns);
        let mut request_decoder = qpack::Decoder::new(4096);
        assert!(matches!(
            extract_dns_request(&mut request_decoder, 0, &request),
            Extracted::Done(request) if request.wire == dns
        ));

        let mut response = Vec::new();
        encode_frame(&mut response, GREASE_FRAME, b"GREASE is the word");
        encode_frame(
            &mut response,
            FRAME_HEADERS,
            &encoded_headers(&[
                (b":status", b"200"),
                (b"content-type", b"application/dns-message"),
            ]),
        );
        encode_frame(&mut response, FRAME_DATA, dns);
        let mut response_decoder = qpack::Decoder::new(4096);
        assert!(matches!(
            extract_dns_response(&mut response_decoder, 0, &response),
            Extracted::Done((200, body)) if body == dns
        ));
    }

    /** @brief 헤더 목록을 인코딩한다. */
    fn encoded_headers(headers: &[(&[u8], &[u8])]) -> Vec<u8> {
        qpack::Encoder::new().encode_field_section(headers).0
    }

    /** @brief 이 입력이 잘못된 요청으로 거부되는지 확인한다. */
    fn assert_bad_request(buf: &[u8]) {
        let mut dec = qpack::Decoder::new(4096);
        assert!(matches!(
            extract_dns_request(&mut dec, 0, buf),
            Extracted::Bad
        ));
    }

    #[test]
    /**
     * @brief 거절하는 까닭에 맞는 상태 코드를 고르는지.
     *
     * @details HTTP/1.1 과 HTTP/2 경로는 415 와 405 를 구분해 답하는데 이 경로만 모두 400
     *          으로 접고 있었다. 같은 서버의 세 전송이 다른 답을 하면 클라이언트가 무엇을
     *          고쳐야 할지 알 수 없다. RFC 8484는 다루지 못하는 형식에 415 를 든다.
     * @note 겹친 content-type 은 415 가 아니라 400 이다. 앞단과 뒷단이 같은 바이트열을
     *       다르게 읽게 만드는 경로라 형식 문제와 뜻이 다르다.
     */
    fn request_rejections_carry_the_matching_status() {
        let dns = b"\x12\x34dns";
        let build = |headers: &[(&[u8], &[u8])]| {
            let mut buf = Vec::new();
            encode_frame(&mut buf, FRAME_HEADERS, &encoded_headers(headers));
            encode_frame(&mut buf, FRAME_DATA, dns);
            buf
        };
        let status = |buf: &[u8]| match extract_dns_request(&mut qpack::Decoder::new(4096), 0, buf)
        {
            Extracted::Refused(code) => String::from_utf8_lossy(code).into_owned(),
            Extracted::Done(_) => "200".into(),
            Extracted::Bad => "400".into(),
            Extracted::Blocked => "blocked".into(),
        };

        let base: [(&[u8], &[u8]); 5] = [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", b"dns.test"),
            (b":path", b"/dns-query"),
            (b"content-type", b"application/dns-message"),
        ];
        assert_eq!(status(&build(&base)), "200");

        let mut wrong_type = base;
        wrong_type[4] = (b"content-type", b"text/plain");
        assert_eq!(status(&build(&wrong_type)), "415", "다룰 수 없는 형식");

        assert_eq!(
            status(&build(&base[..4])),
            "415",
            "형식을 아예 밝히지 않은 것도 이쪽이 받는 형식이 아닙니다"
        );

        let mut other_method = base;
        other_method[0] = (b":method", b"PUT");
        assert_eq!(
            status(&build(&other_method)),
            "405",
            "이 자원이 받지 않는 메서드"
        );

        let duplicate_type: [(&[u8], &[u8]); 6] = [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", b"dns.test"),
            (b":path", b"/dns-query"),
            (b"content-type", b"application/dns-message"),
            (b"content-type", b"text/plain"),
        ];
        assert_eq!(
            status(&build(&duplicate_type)),
            "400",
            "겹친 헤더는 형식 문제가 아니라 요청이 어긋난 것입니다"
        );
    }

    #[test]
    /** @brief 프레임 순서, 의사 헤더 중복, 길이 불일치를 거부하는지. */
    fn request_rejects_bad_frame_order_duplicate_pseudo_and_length_mismatch() {
        let mut data_first = Vec::new();
        encode_frame(&mut data_first, FRAME_DATA, b"dns");
        assert_bad_request(&data_first);
        let mut settings = Vec::new();
        encode_frame(&mut settings, FRAME_SETTINGS, b"");
        assert_bad_request(&settings);

        let duplicate_method: [(&[u8], &[u8]); 7] = [
            (b":method", b"POST"),
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"dns.test"),
            (b":path", b"/dns-query"),
            (b"content-type", b"application/dns-message"),
            (b"content-length", b"3"),
        ];
        let mut duplicate = Vec::new();
        encode_frame(
            &mut duplicate,
            FRAME_HEADERS,
            &encoded_headers(&duplicate_method),
        );
        encode_frame(&mut duplicate, FRAME_DATA, b"dns");
        assert_bad_request(&duplicate);

        let headers: [(&[u8], &[u8]); 6] = [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", b"dns.test"),
            (b":path", b"/dns-query"),
            (b"content-type", b"application/dns-message"),
            (b"content-length", b"4"),
        ];
        let mut mismatched = Vec::new();
        let section = encoded_headers(&headers);
        encode_frame(&mut mismatched, FRAME_HEADERS, &section);
        encode_frame(&mut mismatched, FRAME_DATA, b"dns");
        assert_bad_request(&mismatched);

        let mut repeated_headers = Vec::new();
        encode_frame(&mut repeated_headers, FRAME_HEADERS, &section);
        encode_frame(&mut repeated_headers, FRAME_HEADERS, &section);
        assert_bad_request(&repeated_headers);
    }

    #[test]
    /** @brief 헤더 문법 오류와 권한 충돌을 거부하는지. */
    fn request_rejects_invalid_field_syntax_and_authority_conflicts() {
        let valid: [(&[u8], &[u8]); 6] = [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", b"dns.test"),
            (b":path", b"/dns-query"),
            (b"content-type", b"application/dns-message"),
            (b"content-length", b"3"),
        ];
        for (name, value) in [
            (&b"bad\0name"[..], &b"value"[..]),
            (&b"x-test"[..], &b"bad\rvalue"[..]),
            (&b"x-test"[..], &b" leading"[..]),
            (&b"connection"[..], &b"close"[..]),
            (&b"te"[..], &b"gzip"[..]),
            (&b"host"[..], &b"other.test"[..]),
        ] {
            let mut headers = valid.to_vec();
            headers.push((name, value));
            let mut buf = Vec::new();
            encode_frame(&mut buf, FRAME_HEADERS, &encoded_headers(&headers));
            encode_frame(&mut buf, FRAME_DATA, b"dns");
            assert_bad_request(&buf);
        }

        let mut signed_length = valid;
        signed_length[5].1 = b"+3";
        let mut buf = Vec::new();
        encode_frame(&mut buf, FRAME_HEADERS, &encoded_headers(&signed_length));
        encode_frame(&mut buf, FRAME_DATA, b"dns");
        assert_bad_request(&buf);

        let mut matching_host = valid.to_vec();
        matching_host.push((b"host", b"dns.test"));
        let mut buf = Vec::new();
        encode_frame(&mut buf, FRAME_HEADERS, &encoded_headers(&matching_host));
        encode_frame(&mut buf, FRAME_DATA, b"dns");
        let mut dec = qpack::Decoder::new(4096);
        assert!(matches!(
            extract_dns_request(&mut dec, 0, &buf),
            Extracted::Done(request) if request.wire == b"dns"
        ));
    }

    #[test]
    /** @brief 응답에서도 같은 엄격함이 적용되는지. */
    fn response_rejects_bad_order_duplicate_status_and_invalid_metadata() {
        let mut data_first = Vec::new();
        encode_frame(&mut data_first, FRAME_DATA, b"dns");
        let mut dec = qpack::Decoder::new(4096);
        assert!(matches!(
            extract_dns_response(&mut dec, 0, &data_first),
            Extracted::Bad
        ));
        let mut settings = Vec::new();
        encode_frame(&mut settings, FRAME_SETTINGS, b"");
        let mut dec = qpack::Decoder::new(4096);
        assert!(matches!(
            extract_dns_response(&mut dec, 0, &settings),
            Extracted::Bad
        ));

        for headers in [
            vec![
                (b":status".as_slice(), b"200".as_slice()),
                (b":status", b"400"),
            ],
            vec![(b":status".as_slice(), b"200".as_slice())],
            vec![
                (b":status".as_slice(), b"200".as_slice()),
                (b"content-type", b"application/dns-message"),
                (b"content-length", b"4"),
            ],
        ] {
            let mut buf = Vec::new();
            encode_frame(&mut buf, FRAME_HEADERS, &encoded_headers(&headers));
            encode_frame(&mut buf, FRAME_DATA, b"dns");
            let mut dec = qpack::Decoder::new(4096);
            assert!(matches!(
                extract_dns_response(&mut dec, 0, &buf),
                Extracted::Bad
            ));
        }
    }

    #[test]
    /** @brief 응답 헤더 문법 오류를 거부하는지. */
    fn response_rejects_invalid_field_syntax() {
        let valid: [(&[u8], &[u8]); 3] = [
            (b":status", b"200"),
            (b"content-type", b"application/dns-message"),
            (b"content-length", b"3"),
        ];
        for (name, value) in [
            (&b"bad\0name"[..], &b"value"[..]),
            (&b"x-test"[..], &b"bad\nvalue"[..]),
            (&b"x-test"[..], &b"trailing\t"[..]),
            (&b"connection"[..], &b"close"[..]),
            (&b"te"[..], &b"trailers"[..]),
        ] {
            let mut headers = valid.to_vec();
            headers.push((name, value));
            let mut buf = Vec::new();
            encode_frame(&mut buf, FRAME_HEADERS, &encoded_headers(&headers));
            encode_frame(&mut buf, FRAME_DATA, b"dns");
            let mut dec = qpack::Decoder::new(4096);
            assert!(matches!(
                extract_dns_response(&mut dec, 0, &buf),
                Extracted::Bad
            ));
        }

        let mut signed_length = valid;
        signed_length[2].1 = b"+3";
        let mut buf = Vec::new();
        encode_frame(&mut buf, FRAME_HEADERS, &encoded_headers(&signed_length));
        encode_frame(&mut buf, FRAME_DATA, b"dns");
        let mut dec = qpack::Decoder::new(4096);
        assert!(matches!(
            extract_dns_response(&mut dec, 0, &buf),
            Extracted::Bad
        ));
    }

    #[test]
    /** @brief 망가진 응답을 즉시 알리는지. 데드라인까지 기다리면 그만큼 붙잡힌다. */
    fn malformed_response_is_reported_without_waiting_for_timeout() {
        let (mut client, _) = h3_pair();
        let mut invalid = Vec::new();
        encode_frame(&mut invalid, FRAME_DATA, b"not a response");
        assert_eq!(client.try_extract(0, invalid), Err(QuicError::Frame));
    }

    #[test]
    /** @brief 버퍼가 연결 단위로 묶이는지. 스트림당 상한만으로는 우회된다. */
    fn h3_application_buffers_are_connection_bounded() {
        assert!(fits_connection_buffer(MAX_H3_CONNECTION_BUFFER - 1, 1));
        assert!(!fits_connection_buffer(MAX_H3_CONNECTION_BUFFER, 1));
        assert!(!fits_connection_buffer(usize::MAX, 1));
    }

    #[test]
    /** @brief 처리 대기 중인 요청도 버퍼 상한에 잡히는지. */
    fn queued_requests_count_toward_in_progress_server_buffer_limit() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);
        server.ready.push(H3DnsRequest {
            stream_id: 100,
            wire: vec![0; MAX_H3_CONNECTION_BUFFER - 512],
            path: b"/dns-query".to_vec(),
            client_id: None,
        });

        client
            .send_request("dns.example", "/dns-query", &[0x5a; 1024])
            .unwrap();
        let mut rejected = false;
        while let Some(datagram) = client.next_datagram() {
            match server.recv_datagram(&datagram) {
                Ok(()) => {}
                Err(QuicError::Frame) => {
                    rejected = true;
                    break;
                }
                Err(error) => panic!("unexpected QUIC error: {error:?}"),
            }
        }
        assert!(rejected);
    }

    #[test]
    /** @brief 처리 대기 중인 응답도 버퍼 상한에 잡히는지. */
    fn queued_responses_count_toward_in_progress_client_buffer_limit() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);
        let stream_id = client
            .send_request("dns.example", "/dns-query", b"query")
            .unwrap();
        pump_h3(&mut client, &mut server);
        assert_eq!(server.take_requests(), vec![(stream_id, b"query".to_vec())]);
        client
            .ready
            .push((100, 200, vec![0; MAX_H3_CONNECTION_BUFFER - 512]));

        server.send_response(stream_id, &[0x5a; 1024], 0).unwrap();
        let mut rejected = false;
        while let Some(datagram) = server.next_datagram() {
            match client.recv_datagram(&datagram) {
                Ok(()) => {}
                Err(QuicError::Frame) => {
                    rejected = true;
                    break;
                }
                Err(error) => panic!("unexpected QUIC error: {error:?}"),
            }
        }
        assert!(rejected);
    }

    #[test]
    /** @brief base64url 왕복. */
    fn base64url_roundtrip_known() {
        assert_eq!(base64url_decode(b"YWJj").unwrap(), b"abc");

        assert_eq!(base64url_decode(b"YQ").unwrap(), b"a");

        assert_eq!(base64url_decode(b"-_8").unwrap(), vec![0xfb, 0xff]);

        assert!(base64url_decode(b"YQ==").is_none());
        assert!(base64url_decode(b"A").is_none());
        assert!(base64url_decode(b"YR").is_none());
    }

    #[test]
    /** @brief 처리 뒤 비운 H3 요청 버퍼도 allocator가 보유한 capacity만큼 세는지. */
    fn retained_memory_counts_h3_capacity_after_clear() {
        let (_, mut server) = h3_pair();
        let baseline = server.retained_payload_bytes();
        server.requests.insert(
            0,
            ReqBuf {
                buf: vec![0; 4 * 1024],
                fin: false,
                done: false,
            },
        );
        let retained = server.retained_payload_bytes();
        assert!(retained >= baseline.saturating_add(4 * 1024));

        server.requests.get_mut(&0).unwrap().buf.clear();
        assert_eq!(server.retained_payload_bytes(), retained);
    }

    use crate::params::TransportParams;

    /** @brief 설정을 지정해 클라이언트와 서버 짝을 만든다. */
    fn h3_pair_with(
        resumption: Option<onetdns_tls::conn::ServerResumption>,
        session: Option<onetdns_tls::TlsSession>,
    ) -> (H3Client, H3Connection) {
        h3_pair_with_server_tp(resumption, session, TransportParams::server_defaults())
    }

    /** @brief 서버 전송 매개변수를 지정해 짝을 만든다. */
    fn h3_pair_with_server_tp(
        resumption: Option<onetdns_tls::conn::ServerResumption>,
        session: Option<onetdns_tls::TlsSession>,
        server_tp: TransportParams,
    ) -> (H3Client, H3Connection) {
        use p256::pkcs8::DecodePrivateKey;
        use std::sync::Arc;
        let ck = rcgen::generate_simple_self_signed(vec!["dns.example".to_string()]).unwrap();
        let cert_der = ck.cert.der().as_ref().to_vec();
        let key_der = ck.key_pair.serialize_der();
        let signing =
            p256::ecdsa::SigningKey::from(p256::SecretKey::from_pkcs8_der(&key_der).unwrap());
        let scfg = onetdns_tls::ServerConfig {
            cert_chain: vec![cert_der],
            sign_scheme: 0x0403,
            sign: Arc::new(move |content| {
                use p256::ecdsa::{signature::Signer, Signature};
                let sig: Signature = signing.sign(content);
                sig.to_der().as_bytes().to_vec()
            }),
            alpn: vec![b"h3".to_vec()],
            client_ca: None,
            resumption,
        };
        let ccfg = onetdns_tls::ClientConfig {
            server_name: "dns.example".to_string(),
            verify_name: true,
            roots: None,
            insecure_verifier: Some(
                onetdns_tls::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![b"h3".to_vec()],

            enable_early_data: session.is_some(),
            session,
            ..Default::default()
        };
        let server = H3Connection::new(Connection::new_server(
            Arc::new(scfg),
            b"SRV0".to_vec(),
            server_tp,
        ));
        let client = H3Client::new(
            Connection::new_client(
                ccfg,
                b"DCID0000".to_vec(),
                b"CLI0".to_vec(),
                TransportParams::server_defaults(),
            )
            .unwrap(),
        );
        (client, server)
    }

    /** @brief 기본 설정의 클라이언트와 서버 짝. */
    fn h3_pair() -> (H3Client, H3Connection) {
        h3_pair_with(None, None)
    }

    /** @brief 양쪽 데이터그램을 서로 전달해 진행시킨다. */
    fn pump_h3(client: &mut H3Client, server: &mut H3Connection) {
        for _ in 0..30 {
            let mut moved = false;
            while let Some(dg) = client.next_datagram() {
                server.recv_datagram(&dg).unwrap();
                moved = true;
            }
            while let Some(dg) = server.next_datagram() {
                client.recv_datagram(&dg).unwrap();
                moved = true;
            }
            if !moved {
                break;
            }
        }
    }

    #[test]
    /** @brief 망가진 요청에 즉시 오류로 답하는지. */
    fn malformed_request_receives_immediate_bad_request_response() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);

        let mut invalid = Vec::new();
        encode_frame(&mut invalid, FRAME_DATA, b"not a request");
        client.conn_mut().send_stream(0, &invalid, true).unwrap();
        pump_h3(&mut client, &mut server);

        let responses = client.take_responses();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].0, 0);
        assert_eq!(responses[0].1, 400);
    }

    /** @brief RFC 9114 의 H3_REQUEST_CANCELLED. 클라이언트가 요청을 거둘 때 쓴다. */
    const H3_REQUEST_CANCELLED: u64 = 0x010c;

    #[test]
    /**
     * @brief 상대가 요청 스트림 하나를 멈추면 그 스트림만 실패하는지.
     * @details 워커가 늦게 낸 답을 멈춘 스트림에 실으면 스트림 오류여야 한다. 연결 오류로
     *          올리면 서버가 같은 연결에 실린 다른 질의까지 버린다.
     */
    fn stopped_request_stream_fails_alone() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);

        let cancelled = client
            .send_request("dns.example", "/dns-query", b"\x00\x00 cancelled")
            .unwrap();
        pump_h3(&mut client, &mut server);
        assert_eq!(server.take_requests().len(), 1);
        client
            .conn_mut()
            .send_stop_sending_for_test(cancelled, H3_REQUEST_CANCELLED);
        pump_h3(&mut client, &mut server);
        assert_eq!(
            server.send_response(cancelled, b"\x00\x00 late", 60),
            Err(QuicError::StreamClosed)
        );
        assert!(!server.is_closed());

        let next = client
            .send_request("dns.example", "/dns-query", b"\x00\x00 next")
            .unwrap();
        pump_h3(&mut client, &mut server);
        assert_eq!(
            server.take_requests(),
            vec![(next, b"\x00\x00 next".to_vec())]
        );
        server.send_response(next, b"\x00\x00 answer", 60).unwrap();
        pump_h3(&mut client, &mut server);
        assert!(client
            .take_responses()
            .contains(&(next, 200, b"\x00\x00 answer".to_vec())));
    }

    #[test]
    /**
     * @brief 받자마자 내는 상태 답이 멈춘 스트림을 만나도 연결이 남는지.
     * @details 잘못된 요청에는 그 자리에서 400 을 보낸다. 상대가 그 스트림을 이미 멈췄으면
     *          보낼 곳이 없을 뿐이다. recv_datagram 이 실패하면 부른 쪽이 연결을 버린다.
     */
    fn immediate_status_to_a_stopped_stream_keeps_the_connection() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);

        let mut invalid = Vec::new();
        encode_frame(&mut invalid, FRAME_DATA, b"not a request");
        client
            .conn_mut()
            .send_stream(0, &invalid[..1], false)
            .unwrap();
        pump_h3(&mut client, &mut server);
        client
            .conn_mut()
            .send_stop_sending_for_test(0, H3_REQUEST_CANCELLED);
        pump_h3(&mut client, &mut server);
        client
            .conn_mut()
            .send_stream(0, &invalid[1..], true)
            .unwrap();
        pump_h3(&mut client, &mut server);

        assert!(!server.is_closed());
        assert!(server.take_requests().is_empty());
    }

    #[test]
    /**
     * @brief 상대가 이쪽 QPACK 인코더 스트림을 멈추면 연결 오류가 되는지.
     * @details 필수 스트림이 닫히면 HTTP/3 연결은 이어 갈 수 없다. 스트림 오류로 돌려주면
     *          부른 쪽이 연결을 살려 두고, 그 뒤 헤더 테이블 갱신이 상대에게 닿지 않는다.
     */
    fn stopped_critical_stream_is_a_connection_error() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);
        let id = client
            .send_request("dns.example", "/dns-query", b"\x00\x00 query")
            .unwrap();
        pump_h3(&mut client, &mut server);
        assert_eq!(server.take_requests().len(), 1);

        let encoder = server.qp.enc_sid.expect("서버 인코더 스트림");
        client.conn_mut().send_stop_sending_for_test(encoder, 0);
        /*
         * 서버가 돌려줄 RESET_STREAM 은 클라이언트에게도 필수 스트림 종료라서 연결 오류다.
         * 서버의 판정만 보려고 클라이언트가 보낸 것만 전달한다.
         */
        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
        }
        /* 새 max-age 값은 동적 테이블에 넣어야 하므로 인코더 스트림으로 보낼 것이 생긴다. */
        assert_eq!(
            server.send_response(id, b"\x00\x00 answer", 4242),
            Err(QuicError::Frame)
        );
        assert!(
            server.is_closed(),
            "필수 스트림이 닫혔는데 연결을 닫지 않았습니다"
        );
        while let Some(dg) = server.next_datagram() {
            client.conn_mut().recv_datagram(&dg).unwrap();
        }
        assert_eq!(
            client.conn_mut().peer_close().map(|close| close.error_code),
            Some(H3_CLOSED_CRITICAL_STREAM)
        );
    }

    #[test]
    /**
     * @brief HTTP/3 계층의 연결 오류를 상대에게 RFC 9114 코드로 알리는지.
     * @details 제어 스트림은 연결마다 하나뿐이라 두 번째가 오면 연결 오류다. 알리지 않고 버리면
     *          상대는 자기 유휴 데드라인까지 기다린다.
     */
    fn http3_connection_error_reaches_the_peer() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);

        send_second_control_stream(client.conn_mut());
        let mut rejected = false;
        while let Some(dg) = client.next_datagram() {
            if server.recv_datagram(&dg).is_err() {
                rejected = true;
                break;
            }
        }
        assert!(rejected, "두 번째 제어 스트림을 받아들였습니다");
        assert!(server.is_closed());

        while let Some(dg) = server.next_datagram() {
            client.conn_mut().recv_datagram(&dg).unwrap();
        }
        let close = client
            .conn_mut()
            .peer_close()
            .cloned()
            .expect("종료 사유가 오지 않았습니다");
        assert_eq!(close.error_code, H3_GENERAL_PROTOCOL_ERROR);
        assert_eq!(close.frame_type, None, "응용 계층 종료여야 합니다");
    }

    #[test]
    /**
     * @brief 클라이언트도 HTTP/3 계층의 연결 오류를 서버에 RFC 9114 코드로 알리는지.
     * @details 업스트림이 규격을 어기면 클라이언트는 그 연결을 버린다. 알리지 않으면 업스트림은
     *          자기 유휴 데드라인까지 그 연결을 붙들고 있다.
     */
    fn http3_client_connection_error_reaches_the_server() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);

        send_second_control_stream(server.conn_mut());
        let mut rejected = false;
        while let Some(dg) = server.next_datagram() {
            if client.recv_datagram(&dg).is_err() {
                rejected = true;
                break;
            }
        }
        assert!(rejected, "두 번째 제어 스트림을 받아들였습니다");
        assert!(client.is_closed());

        while let Some(dg) = client.next_datagram() {
            server.conn_mut().recv_datagram(&dg).unwrap();
        }
        let close = server
            .conn_mut()
            .peer_close()
            .cloned()
            .expect("종료 사유가 오지 않았습니다");
        assert_eq!(close.error_code, H3_GENERAL_PROTOCOL_ERROR);
        assert_eq!(close.frame_type, None, "응용 계층 종료여야 합니다");
    }

    /**
     * @brief 제어 스트림을 이미 연 연결에서 제어 스트림을 하나 더 열어 설정을 보낸다.
     * @details 제어 스트림은 연결마다 하나뿐이라 받는 쪽에는 HTTP/3 연결 오류다.
     */
    fn send_second_control_stream(conn: &mut Connection) {
        let id = conn.open_uni_stream().unwrap();
        let mut data = Vec::new();
        varint::write(&mut data, UNI_CONTROL);
        encode_frame(&mut data, FRAME_SETTINGS, &our_settings());
        conn.send_stream(id, &data, false).unwrap();
    }

    #[test]
    /** @brief 스트림 한도가 좁아도 필수 스트림이 중복 예약 없이 열리는지. */
    fn h3_setup_stream_limit_queues_critical_stream_without_duplicate_reservations() {
        let mut server_tp = TransportParams::server_defaults();
        server_tp.initial_max_streams_uni = 2;
        let (mut client, mut server) = h3_pair_with_server_tp(None, None, server_tp);
        pump_h3(&mut client, &mut server);

        assert!(client.is_handshake_complete());
        assert_eq!(
            client.send_request("dns.example", "/dns-query", b"\x00\x00 query"),
            Ok(0)
        );
        assert!(!client.is_closed());
        assert!(client.setup_sent);
        assert_eq!(client.qp.ctrl_sid, Some(2));
        assert_eq!(client.qp.enc_sid, Some(6));
        assert_eq!(client.qp.dec_sid, Some(10));
        assert_eq!(client.next_bidi, 1);

        assert_eq!(
            client.send_request("dns.example", "/dns-query", b"\x00\x00 query"),
            Ok(4)
        );
        assert_eq!(client.qp.ctrl_sid, Some(2));
        assert_eq!(client.qp.enc_sid, Some(6));
        assert_eq!(client.qp.dec_sid, Some(10));
        assert_eq!(client.next_bidi, 2);
        assert!(!client.is_closed());
    }

    #[test]
    /** @brief 윈도우가 1바이트여도 큰 요청이 끝까지 진행되는지. */
    fn one_byte_initial_stream_window_progresses_large_h3_request() {
        let mut server_tp = TransportParams::server_defaults();
        server_tp.initial_max_stream_data_bidi_remote = 1;
        let (mut client, mut server) = h3_pair_with_server_tp(None, None, server_tp);
        pump_h3(&mut client, &mut server);

        let dns = vec![0x5a; 4096];
        let stream_id = client
            .send_request("dns.example", "/dns-query", &dns)
            .unwrap();
        pump_h3(&mut client, &mut server);

        assert_eq!(server.take_requests(), vec![(stream_id, dns)]);
        assert!(!client.is_closed());
        assert!(!server.is_closed());
    }

    #[test]
    /** @brief 모르는 단방향 스트림이 닫혀도 상태가 쌓이지 않는지. */
    fn closed_unknown_uni_streams_do_not_exhaust_connection_state() {
        let mut qp = QpackCtx::new();
        let mut stream_type = Vec::new();
        varint::write(&mut stream_type, 0x21);

        for id in 0..(MAX_H3_UNI_STREAMS * 4) as u64 {
            assert_eq!(qp.on_uni(id, &stream_type, true), Ok(()));
            assert!(qp.uni_in.is_empty());
        }
    }

    #[test]
    /** @brief 필수 스트림을 닫으면 연결이 끊기는지. */
    fn closing_critical_uni_stream_is_rejected() {
        for stream_type in [UNI_CONTROL, UNI_QPACK_ENCODER, UNI_QPACK_DECODER] {
            let mut qp = QpackCtx::new();
            let mut data = Vec::new();
            varint::write(&mut data, stream_type);
            assert_eq!(qp.on_uni(2, &data, true), Err(()));
            assert!(qp.uni_in.is_empty());
        }
    }

    #[test]
    /** @brief 필수 스트림을 끊으면 연결이 끊기는지. */
    fn resetting_critical_uni_stream_is_rejected() {
        for stream_type in [UNI_CONTROL, UNI_QPACK_ENCODER, UNI_QPACK_DECODER] {
            let mut qp = QpackCtx::new();
            let mut data = Vec::new();
            varint::write(&mut data, stream_type);
            assert_eq!(qp.on_uni(2, &data, false), Ok(()));
            assert_eq!(qp.on_reset(2), Err(()));
            assert!(qp.uni_in.is_empty());
        }

        let mut qp = QpackCtx::new();
        assert_eq!(qp.on_reset(2), Ok(()));
    }

    #[test]
    /** @brief 필수 스트림이 두 번 열리면 거부하는지. */
    fn duplicate_critical_uni_stream_is_rejected() {
        for stream_type in [UNI_CONTROL, UNI_QPACK_ENCODER, UNI_QPACK_DECODER] {
            let mut qp = QpackCtx::new();
            let mut data = Vec::new();
            varint::write(&mut data, stream_type);

            assert_eq!(qp.on_uni(2, &data, false), Ok(()));
            assert_eq!(qp.on_uni(2, &[], false), Ok(()));
            assert_eq!(qp.on_uni(6, &data, false), Err(()));
        }
    }

    /** @brief 제어 스트림에 보낼 바이트를 만든다. */
    fn control_bytes(frame_type: u64, payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        varint::write(&mut data, UNI_CONTROL);
        encode_frame(&mut data, frame_type, payload);
        data
    }

    #[test]
    /** @brief 제어 스트림의 첫 프레임이 설정 하나여야 하는지. */
    fn control_stream_requires_exactly_one_initial_settings_frame() {
        let mut qp = QpackCtx::new();
        assert_eq!(qp.on_uni(2, &control_bytes(0x21, &[]), false), Err(()));

        let mut qp = QpackCtx::new();
        assert_eq!(
            qp.on_uni(2, &control_bytes(FRAME_SETTINGS, &our_settings()), false),
            Ok(())
        );
        let mut second = Vec::new();
        encode_frame(&mut second, FRAME_SETTINGS, &[]);
        assert_eq!(qp.on_uni(2, &second, false), Err(()));
    }

    #[test]
    /** @brief 설정 중복과 잘린 값을 거부하는지. */
    fn settings_reject_duplicate_ids_and_truncated_values() {
        let mut duplicate = Vec::new();
        for value in [1, 2] {
            varint::write(&mut duplicate, SETTINGS_QPACK_MAX_TABLE_CAPACITY);
            varint::write(&mut duplicate, value);
        }
        let mut qp = QpackCtx::new();
        assert_eq!(
            qp.on_uni(2, &control_bytes(FRAME_SETTINGS, &duplicate), false),
            Err(())
        );

        let mut truncated = Vec::new();
        varint::write(&mut truncated, SETTINGS_QPACK_MAX_TABLE_CAPACITY);
        let mut qp = QpackCtx::new();
        assert_eq!(
            qp.on_uni(2, &control_bytes(FRAME_SETTINGS, &truncated), false),
            Err(())
        );

        for reserved in 0x02..=0x05 {
            let mut payload = Vec::new();
            varint::write(&mut payload, reserved);
            varint::write(&mut payload, 0);
            let mut qp = QpackCtx::new();
            assert_eq!(
                qp.on_uni(2, &control_bytes(FRAME_SETTINGS, &payload), false),
                Err(())
            );
        }
    }

    #[test]
    /** @brief 이쪽 헤더 크기 상한을 상대에게 알리는지. */
    fn settings_advertise_the_decoder_field_section_limit() {
        assert!(parse_settings(&our_settings())
            .unwrap()
            .contains(&(SETTINGS_MAX_FIELD_SECTION_SIZE, MAX_H3_FIELD_SECTION)));
    }

    #[test]
    /** @brief 동적 테이블을 쓴 왕복과 확인 지시가 오가는지. */
    fn h3_dynamic_qpack_roundtrip_and_ack() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);
        assert!(client.is_handshake_complete() && server.is_handshake_complete());

        let dns1 = b"\x00\x00 first dns query bytes";
        let sid1 = client
            .send_request("dns.upstream.example", "/dns-query", dns1)
            .unwrap();
        pump_h3(&mut client, &mut server);
        let reqs = server.take_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].1, dns1);
        assert!(
            client.qpack_insert_count() > 0,
            "동적 테이블에 헤더가 삽입돼야(SETTINGS 교환 후)"
        );

        server
            .send_response(reqs[0].0, b"\x00\x00 answer-1", 0)
            .unwrap();
        pump_h3(&mut client, &mut server);
        let resps = client.take_responses();
        assert_eq!(resps.len(), 1);
        assert_eq!(resps[0].0, sid1);
        assert_eq!(resps[0].1, 200);
        assert_eq!(resps[0].2, b"\x00\x00 answer-1");

        assert_eq!(
            client.qpack_known_received(),
            client.qpack_insert_count(),
            "Section Acknowledgment 수신"
        );

        let inserts_before = client.qpack_insert_count();
        let dns2 = b"\x00\x00 secnd dns query bytes";
        let sid2 = client
            .send_request("dns.upstream.example", "/dns-query", dns2)
            .unwrap();
        pump_h3(&mut client, &mut server);
        let reqs2 = server.take_requests();
        assert_eq!(reqs2.len(), 1);
        assert_eq!(reqs2[0].1, dns2);
        assert_eq!(
            client.qpack_insert_count(),
            inserts_before,
            "재사용: 새 삽입 없음"
        );

        server
            .send_response(reqs2[0].0, b"\x00\x00 answer-2", 0)
            .unwrap();
        pump_h3(&mut client, &mut server);
        let resps2 = client.take_responses();
        assert_eq!(resps2.len(), 1);
        assert_eq!(resps2[0].0, sid2);
        assert_eq!(resps2[0].2, b"\x00\x00 answer-2");
    }

    #[test]
    /** @brief 설정 전에는 정적 테이블만 쓰는지. */
    fn h3_request_before_settings_is_static_only() {
        let (mut client, mut server) = h3_pair();

        for _ in 0..10 {
            let mut moved = false;
            while let Some(dg) = client.next_datagram() {
                server.recv_datagram(&dg).unwrap();
                moved = true;
            }
            if client.is_handshake_complete() {
                break;
            }
            while let Some(dg) = server.next_datagram() {
                client.recv_datagram(&dg).unwrap();
                moved = true;
            }
            if !moved {
                break;
            }
        }
        let dns = b"\x00\x00 early static query";
        let _sid = client.send_request("h.example", "/dns-query", dns).unwrap();
        pump_h3(&mut client, &mut server);
        let reqs = server.take_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].1, dns);
    }

    #[test]
    /** @brief 첫 요청이 조기 데이터로 나가는지. 왕복 하나를 아낀다. */
    fn h3_first_request_rides_zero_rtt() {
        let mut res = onetdns_tls::conn::ServerResumption::secure_default();
        res.max_early_data = 0xffff_ffff;

        let (mut c1, mut s1) = h3_pair_with(Some(res.clone()), None);
        pump_h3(&mut c1, &mut s1);
        let sid = c1
            .send_request("dns.example", "/dns-query", b"\x00\x00 warmup")
            .unwrap();
        pump_h3(&mut c1, &mut s1);
        let r = s1.take_requests();
        assert_eq!(r.len(), 1);
        s1.send_response(r[0].0, b"\x00\x00 warm-resp", 0).unwrap();
        pump_h3(&mut c1, &mut s1);
        assert_eq!(c1.take_responses()[0].0, sid);
        let session = c1
            .conn_mut()
            .take_new_sessions()
            .into_iter()
            .next()
            .expect("세션 티켓");
        assert_eq!(session.alpn.as_deref(), Some(b"h3".as_slice()));

        let (mut c2, mut s2) = h3_pair_with(Some(res), Some(session));
        assert!(c2.can_send_early(), "재개 세션이면 0-RTT 가능");
        let dns = b"\x00\x00 zero-rtt h3 query";
        let sid2 = c2.send_request("dns.example", "/dns-query", dns).unwrap();

        while let Some(dg) = c2.next_datagram() {
            s2.recv_datagram(&dg).unwrap();
        }
        assert!(!s2.is_handshake_complete(), "클라 Finished 전");
        let reqs = s2.take_requests();
        assert_eq!(reqs.len(), 1, "0-RTT로 H3 요청 도착");
        assert_eq!(reqs[0].1, dns);

        pump_h3(&mut c2, &mut s2);
        assert!(c2.is_handshake_complete() && s2.is_handshake_complete());
        assert!(c2.conn_mut().early_data_accepted());
        s2.send_response(reqs[0].0, b"\x00\x00 zr-resp", 0).unwrap();
        pump_h3(&mut c2, &mut s2);
        let resps = c2.take_responses();
        assert_eq!(resps.len(), 1);
        assert_eq!(resps[0].0, sid2);
        assert_eq!(resps[0].1, 200);
    }

    #[test]
    /** @brief 조기 데이터가 거부돼도 요청이 결국 성공하는지. */
    fn h3_zero_rtt_rejected_still_succeeds() {
        let mut res_a = onetdns_tls::conn::ServerResumption::secure_default();
        res_a.max_early_data = 0xffff_ffff;
        let (mut c1, mut s1) = h3_pair_with(Some(res_a), None);
        pump_h3(&mut c1, &mut s1);
        let sid = c1
            .send_request("dns.example", "/dns-query", b"\x00\x00 w")
            .unwrap();
        pump_h3(&mut c1, &mut s1);
        let r = s1.take_requests();
        s1.send_response(r[0].0, b"\x00\x00 wr", 0).unwrap();
        pump_h3(&mut c1, &mut s1);
        let _ = c1.take_responses();
        let _ = sid;
        let session = c1
            .conn_mut()
            .take_new_sessions()
            .into_iter()
            .next()
            .unwrap();

        let res_b = onetdns_tls::conn::ServerResumption::secure_default();
        let (mut c2, mut s2) = h3_pair_with(Some(res_b), Some(session));
        assert!(c2.can_send_early());
        let dns = b"\x00\x00 rejected early h3";
        let sid2 = c2.send_request("dns.example", "/dns-query", dns).unwrap();
        pump_h3(&mut c2, &mut s2);
        assert!(c2.is_handshake_complete() && s2.is_handshake_complete());
        assert!(!c2.conn_mut().early_data_accepted(), "0-RTT 거부");
        let reqs = s2.take_requests();
        assert_eq!(reqs.len(), 1, "1-RTT 재전송으로 요청 도착");
        assert_eq!(reqs[0].1, dns);
        s2.send_response(reqs[0].0, b"\x00\x00 ok", 0).unwrap();
        pump_h3(&mut c2, &mut s2);
        let resps = c2.take_responses();
        assert_eq!(resps.len(), 1);
        assert_eq!(resps[0].0, sid2);
    }
}
