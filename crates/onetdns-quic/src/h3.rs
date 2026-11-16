//! HTTP/3, only as much as DoH3 needs: one DNS message per request. Requests and responses use
//! bidirectional streams; settings and QPACK updates use unidirectional ones.

use std::collections::{HashMap, HashSet};

use onetdns_http2::valid_header_field;

use crate::conn::{ClosePeriod, Connection, QuicError, Role};
use crate::{qpack, varint};

pub const FRAME_DATA: u64 = 0x00;
pub const FRAME_HEADERS: u64 = 0x01;
/// Must be the first frame on the control stream.
pub const FRAME_SETTINGS: u64 = 0x04;
const FRAME_CANCEL_PUSH: u64 = 0x03;
const FRAME_PUSH_PROMISE: u64 = 0x05;
const FRAME_GOAWAY: u64 = 0x07;
const FRAME_MAX_PUSH_ID: u64 = 0x0d;

pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;
pub const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x06;

const QPACK_CAPACITY: u64 = 4096;
const QPACK_BLOCKED: u64 = 16;
/// Caps the expanded header list against compression amplification.
const MAX_H3_FIELD_SECTION: u64 = 32 * 1024;
const MAX_H3_STREAMS: usize = 128;
const MAX_H3_STREAM_BUFFER: usize = 128 * 1024;
/// Per-stream caps alone could be bypassed by opening many streams.
const MAX_H3_CONNECTION_BUFFER: usize = 1024 * 1024;
const MAX_H3_UNI_STREAMS: usize = 16;
const MAX_H3_UNI_BUFFER: usize = 64 * 1024;
const MAX_DNS_BODY: usize = 64 * 1024;
/// For the client ID taken from the path.
const MAX_CLIENT_ID: usize = 256;
/// Sent in the Allow header of a 405.
const ALLOWED_METHODS: &[u8] = b"GET, POST";

const H3_REQUEST_CANCELLED: u64 = 0x010c;

const UNI_CONTROL: u64 = 0x00;
const UNI_PUSH: u64 = 0x01;
const UNI_QPACK_ENCODER: u64 = 0x02;
const UNI_QPACK_DECODER: u64 = 0x03;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Reasons for closing the connection, each sent with its RFC 9114 or RFC 9204 error code.
pub enum H3Error {
    NoError,
    GeneralProtocol,
    Internal,
    StreamCreation,
    ClosedCriticalStream,
    FrameUnexpected,
    FrameError,
    ExcessiveLoad,
    IdError,
    SettingsError,
    MissingSettings,
    Message,
    DecompressionFailed,
    EncoderStream,
    DecoderStream,
}

impl H3Error {
    pub fn code(self) -> u64 {
        match self {
            Self::NoError => 0x0100,
            Self::GeneralProtocol => 0x0101,
            Self::Internal => 0x0102,
            Self::StreamCreation => 0x0103,
            Self::ClosedCriticalStream => 0x0104,
            Self::FrameUnexpected => 0x0105,
            Self::FrameError => 0x0106,
            Self::ExcessiveLoad => 0x0107,
            Self::IdError => 0x0108,
            Self::SettingsError => 0x0109,
            Self::MissingSettings => 0x010a,
            Self::Message => 0x010e,
            Self::DecompressionFailed => 0x0200,
            Self::EncoderStream => 0x0201,
            Self::DecoderStream => 0x0202,
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::NoError => "",
            Self::GeneralProtocol => "HTTP/3 protocol violation",
            Self::Internal => "HTTP/3 internal error",
            Self::StreamCreation => "HTTP/3 stream not allowed",
            Self::ClosedCriticalStream => "HTTP/3 critical stream closed",
            Self::FrameUnexpected => "Unexpected HTTP/3 frame",
            Self::FrameError => "Malformed HTTP/3 frame",
            Self::ExcessiveLoad => "HTTP/3 resource limit exceeded",
            Self::IdError => "Invalid HTTP/3 stream or push ID",
            Self::SettingsError => "Invalid HTTP/3 SETTINGS",
            Self::MissingSettings => "HTTP/3 control stream did not start with SETTINGS",
            Self::Message => "Malformed HTTP/3 message",
            Self::DecompressionFailed => "QPACK field section could not be decoded",
            Self::EncoderStream => "Invalid QPACK encoder instruction",
            Self::DecoderStream => "Invalid QPACK decoder instruction",
        }
    }
}

impl From<H3Error> for QuicError {
    fn from(error: H3Error) -> Self {
        QuicError::Application {
            code: error.code(),
            reason: error.reason(),
        }
    }
}

fn close_with(conn: &mut Connection, error: H3Error) -> QuicError {
    conn.close(error.code(), error.reason());
    error.into()
}

/// A full send buffer means the peer kept sending requests without reading replies, so it is
/// H3_EXCESSIVE_LOAD. An already closed connection keeps its first reason.
fn close_on_stream_error(conn: &mut Connection, error: QuicError) -> QuicError {
    let error = match error {
        QuicError::Application { .. } => error,
        QuicError::FlowControl => H3Error::ExcessiveLoad.into(),
        _ => H3Error::Internal.into(),
    };
    if let QuicError::Application { code, reason } = &error {
        conn.close(*code, reason);
    }
    error
}

/// RFC 9114 reserves these HTTP/2 frame types and makes receiving one a connection error.
fn is_reserved_http2_frame(frame_type: u64) -> bool {
    matches!(frame_type, 0x02 | 0x06 | 0x08 | 0x09)
}

/// RFC 9114 makes a frame longer or shorter than its fields H3_FRAME_ERROR.
fn single_varint(payload: &[u8]) -> Result<u64, H3Error> {
    match varint::read(payload) {
        Some((value, used)) if used == payload.len() => Ok(value),
        _ => Err(H3Error::FrameError),
    }
}

#[derive(Default)]
struct PeerControl {
    /// The latest GOAWAY ID. From a server it is the first request stream it will not process; from
    /// a client, the first push ID it will not accept. RFC 9114 forbids it to grow.
    goaway: Option<u64>,
    /// Cannot decrease.
    max_push_id: Option<u64>,
}

impl PeerControl {
    /// This side neither allows nor sends server push, so every CANCEL_PUSH ID is invalid. A
    /// server's GOAWAY may only carry a client-initiated bidirectional stream ID.
    fn on_frame(&mut self, frame_type: u64, payload: &[u8], role: Role) -> Result<(), H3Error> {
        match frame_type {
            FRAME_DATA | FRAME_HEADERS | FRAME_SETTINGS | FRAME_PUSH_PROMISE => {
                Err(H3Error::FrameUnexpected)
            }
            FRAME_MAX_PUSH_ID if role == Role::Client => Err(H3Error::FrameUnexpected),
            t if is_reserved_http2_frame(t) => Err(H3Error::FrameUnexpected),
            FRAME_CANCEL_PUSH => {
                single_varint(payload)?;
                Err(H3Error::IdError)
            }
            FRAME_GOAWAY => {
                let id = single_varint(payload)?;
                let request_stream = id & 0x03 == 0;
                if (role == Role::Client && !request_stream)
                    || self.goaway.is_some_and(|last| id > last)
                {
                    return Err(H3Error::IdError);
                }
                self.goaway = Some(id);
                Ok(())
            }
            FRAME_MAX_PUSH_ID => {
                let id = single_varint(payload)?;
                if self.max_push_id.is_some_and(|last| id < last) {
                    return Err(H3Error::IdError);
                }
                self.max_push_id = Some(id);
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// Checked before the message content, since RFC 9114 makes control-only frames, reserved HTTP/2
/// types, and DATA before HEADERS connection errors. Only a server may send PUSH_PROMISE, and this
/// side's client never allows push.
fn check_message_frames(frames: &[(u64, Vec<u8>)], role: Role) -> Result<(), H3Error> {
    let mut headers_seen = false;
    for &(frame_type, _) in frames {
        match frame_type {
            FRAME_SETTINGS | FRAME_CANCEL_PUSH | FRAME_GOAWAY | FRAME_MAX_PUSH_ID => {
                return Err(H3Error::FrameUnexpected)
            }
            FRAME_PUSH_PROMISE if role == Role::Client => return Err(H3Error::IdError),
            FRAME_PUSH_PROMISE => return Err(H3Error::FrameUnexpected),
            FRAME_DATA if !headers_seen => return Err(H3Error::FrameUnexpected),
            FRAME_HEADERS => headers_seen = true,
            t if is_reserved_http2_frame(t) => return Err(H3Error::FrameUnexpected),
            _ => {}
        }
    }
    Ok(())
}

fn fits_connection_buffer(buffered: usize, incoming: usize) -> bool {
    buffered
        .checked_add(incoming)
        .is_some_and(|total| total <= MAX_H3_CONNECTION_BUFFER)
}

/// RFC 9204 makes exceeding the advertised blocked stream count QPACK_DECOMPRESSION_FAILED.
fn hold_blocked(
    blocked: &mut Vec<(u64, Vec<u8>)>,
    buffered: usize,
    id: u64,
    buf: Vec<u8>,
) -> Result<(), QuicError> {
    if blocked.len() >= QPACK_BLOCKED as usize {
        return Err(H3Error::DecompressionFailed.into());
    }
    if !fits_connection_buffer(buffered, buf.len()) {
        return Err(H3Error::ExcessiveLoad.into());
    }
    blocked.push((id, buf));
    Ok(())
}

pub fn encode_frame(out: &mut Vec<u8>, ftype: u64, payload: &[u8]) {
    varint::write(out, ftype);
    varint::write(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

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

/// Partial frames stay buffered; stream data arrives in pieces.
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

/// A repeated setting is rejected: which value applies is undefined, and implementations that pick
/// differently can be played against each other.
fn parse_settings(payload: &[u8]) -> Result<Vec<(u64, u64)>, H3Error> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut pos = 0usize;
    while pos < payload.len() {
        let (id, n1) = varint::read(&payload[pos..]).ok_or(H3Error::FrameError)?;
        pos += n1;
        let (v, n2) = varint::read(&payload[pos..]).ok_or(H3Error::FrameError)?;
        pos += n2;
        if matches!(id, 0x02..=0x05) || !seen.insert(id) {
            return Err(H3Error::SettingsError);
        }
        out.push((id, v));
    }
    Ok(out)
}

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
struct UniIn {
    buf: Vec<u8>,
    stype: Option<u64>,
    settings_seen: bool,
}

struct QpackCtx {
    /// Decides which frames and streams the peer may send.
    role: Role,
    enc: qpack::Encoder,
    dec: qpack::Decoder,

    ctrl_sid: Option<u64>,
    enc_sid: Option<u64>,
    dec_sid: Option<u64>,
    ctrl_sent: bool,
    enc_sent: bool,
    dec_sent: bool,
    peer_ctrl_sid: Option<u64>,
    peer_enc_sid: Option<u64>,
    peer_dec_sid: Option<u64>,
    uni_in: HashMap<u64, UniIn>,
    peer_control: PeerControl,
}

/// `HashMap::capacity` is below the real bucket count, so this estimates on the high side.
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
    fn new(role: Role) -> Self {
        QpackCtx {
            role,
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
            peer_control: PeerControl::default(),
        }
    }

    fn retained_payload_bytes(&self) -> usize {
        self.enc
            .retained_payload_bytes()
            .saturating_add(self.dec.retained_payload_bytes())
            .saturating_add(hash_map_retained_bytes(&self.uni_in))
            .saturating_add(self.uni_in.values().fold(0usize, |total, stream| {
                total.saturating_add(stream.buf.capacity())
            }))
    }

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

    /// There is one control stream per connection; a second one, or one not starting with SETTINGS,
    /// closes the connection.
    fn on_uni(&mut self, id: u64, data: &[u8], fin: bool) -> Result<(), H3Error> {
        if !self.uni_in.contains_key(&id) && self.uni_in.len() >= MAX_H3_UNI_STREAMS {
            return Err(H3Error::ExcessiveLoad);
        }
        let critical = {
            let u = self.uni_in.entry(id).or_default();
            if u.buf.len().saturating_add(data.len()) > MAX_H3_UNI_BUFFER {
                return Err(H3Error::ExcessiveLoad);
            }
            u.buf.extend_from_slice(data);
            if u.stype.is_none() {
                match varint::read(&u.buf) {
                    Some((UNI_PUSH, _)) => {
                        return Err(match self.role {
                            Role::Server => H3Error::StreamCreation,
                            Role::Client => H3Error::IdError,
                        });
                    }
                    Some((t, n)) => {
                        let peer_sid = match t {
                            UNI_CONTROL => Some(&mut self.peer_ctrl_sid),
                            UNI_QPACK_ENCODER => Some(&mut self.peer_enc_sid),
                            UNI_QPACK_DECODER => Some(&mut self.peer_dec_sid),
                            _ => None,
                        };
                        if let Some(peer_sid) = peer_sid {
                            match *peer_sid {
                                Some(existing) if existing != id => {
                                    return Err(H3Error::StreamCreation)
                                }
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
                        if u.settings_seen {
                            self.peer_control.on_frame(t, &payload, self.role)?;
                            continue;
                        }
                        if t != FRAME_SETTINGS {
                            return Err(H3Error::MissingSettings);
                        }
                        u.settings_seen = true;
                        for (id, v) in parse_settings(&payload)? {
                            if id == SETTINGS_QPACK_MAX_TABLE_CAPACITY {
                                let cap = usize::try_from(v).unwrap_or(usize::MAX);
                                self.enc
                                    .set_peer_max_capacity(cap.min(QPACK_CAPACITY as usize));
                            }
                        }
                    }
                }
                Some(UNI_QPACK_ENCODER) => {
                    let bytes = std::mem::take(&mut u.buf);
                    self.dec
                        .on_encoder_stream(&bytes)
                        .map_err(|()| H3Error::EncoderStream)?;
                }
                Some(UNI_QPACK_DECODER) => {
                    let bytes = std::mem::take(&mut u.buf);
                    self.enc
                        .on_decoder_stream(&bytes)
                        .map_err(|()| H3Error::DecoderStream)?;
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
                return Err(H3Error::ClosedCriticalStream);
            }
        }
        Ok(())
    }

    /// Resetting the control stream or a QPACK stream is a connection error.
    fn on_reset(&mut self, id: u64) -> Result<(), H3Error> {
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
            Err(H3Error::ClosedCriticalStream)
        } else {
            Ok(())
        }
    }

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

    /// Instructions wait until the decoder stream is open and its type has been sent; sent earlier,
    /// the peer would misread the stream type.
    fn flush_decoder_stream(&mut self, conn: &mut Connection) -> Result<(), QuicError> {
        let Some(sid) = self.dec_sid.filter(|_| self.dec_sent) else {
            return Ok(());
        };
        let out = self.dec.take_decoder_stream();
        if out.is_empty() {
            return Ok(());
        }
        if let Err(error) = send_critical(conn, sid, &out) {
            self.dec.restore_decoder_stream(out);
            return Err(error);
        }
        Ok(())
    }
}

/// Losing one of these streams ends HTTP/3. A STOP_SENDING returned as a stream error would keep
/// the connection up while QPACK updates no longer reach the peer, so it becomes a connection error
/// and closes the connection with that code.
fn send_critical(conn: &mut Connection, id: u64, data: &[u8]) -> Result<(), QuicError> {
    match conn.send_stream(id, data, false) {
        Err(QuicError::StreamClosed) => Err(close_with(conn, H3Error::ClosedCriticalStream)),
        other => other,
    }
}

fn base64url_decode(input: &[u8]) -> Option<Vec<u8>> {
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
struct ReqBuf {
    buf: Vec<u8>,
    fin: bool,
    /// Already handed to the caller.
    done: bool,
}

/// Tells data still arriving from malformed data.
enum Extracted<T> {
    Done(T),
    Blocked,
    /// Rejects that message only.
    Bad,
    /// Frame layout or header compression broke a rule that RFC 9114 or RFC 9204 makes a connection
    /// error. The QPACK state may now differ from the peer's, so later messages on the connection
    /// cannot be trusted.
    Fatal(H3Error),
    /// Valid, but not accepted by this resource; the status code says why. Folding everything into
    /// 400 would not tell the client whether to fix its headers or change the method.
    Refused(&'static [u8]),
}

#[derive(Debug, Clone)]
pub struct H3DnsRequest {
    pub stream_id: u64,
    /// The DNS query.
    pub wire: Vec<u8>,
    pub path: Vec<u8>,
    pub client_id: Option<String>,
}

/// None when malformed or too long.
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

/// TE is allowed only in request headers with the value trailers; the caller checks it.
fn is_connection_specific_field(name: &[u8]) -> bool {
    matches!(
        name,
        b"connection" | b"proxy-connection" | b"keep-alive" | b"transfer-encoding" | b"upgrade"
    )
}

/// Pseudo-headers and connection-specific fields cannot appear in trailers, and TE is allowed only
/// in request headers. Trailer values are not used to read the DNS message.
fn valid_trailer_section(fields: &[(Vec<u8>, Vec<u8>)]) -> bool {
    fields.iter().all(|(name, value)| {
        valid_header_field(name, value)
            && !name.starts_with(b":")
            && !is_connection_specific_field(name)
            && name != b"te"
    })
}

fn decoded<T>(result: qpack::DecodeResult) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Extracted<T>> {
    match result {
        qpack::DecodeResult::Done(fields) => Ok(fields),
        qpack::DecodeResult::Blocked => Err(Extracted::Blocked),
        qpack::DecodeResult::Error => Err(Extracted::Fatal(H3Error::DecompressionFailed)),
    }
}

/// Strict about frame order and header rules: HEADERS before DATA, no duplicate pseudo-headers, and
/// a declared length that matches the body. A request is a header section, a body, and at most one
/// trailer section; HEADERS or DATA after the trailers is a connection error under RFC 9114.
///
/// Reading loosely lets implementations disagree about one request, and that disagreement is a way
/// past front-end devices.
///
/// Both header sections are decoded before their content is checked. A bad request leaves the
/// connection open, so a section dropped undecoded would never be acknowledged to the peer's
/// encoder.
fn extract_dns_request(dec: &mut qpack::Decoder, sid: u64, buf: &[u8]) -> Extracted<H3DnsRequest> {
    let Some(frames) = parse_frames(buf) else {
        return Extracted::Fatal(H3Error::FrameError);
    };
    if let Err(error) = check_message_frames(&frames, Role::Server) {
        return Extracted::Fatal(error);
    }
    let mut head_section: Option<&[u8]> = None;
    let mut trailer_section: Option<&[u8]> = None;
    for (t, payload) in &frames {
        match *t {
            FRAME_HEADERS | FRAME_DATA if trailer_section.is_some() => {
                return Extracted::Fatal(H3Error::FrameUnexpected)
            }
            FRAME_HEADERS if head_section.is_none() => head_section = Some(payload),
            FRAME_HEADERS => trailer_section = Some(payload),
            _ => {}
        }
    }
    let Some(head_section) = head_section else {
        return Extracted::Bad;
    };
    if dec.is_blocked(head_section) || trailer_section.is_some_and(|s| dec.is_blocked(s)) {
        return Extracted::Blocked;
    }
    let head = match decoded(dec.decode_field_section(sid, head_section)) {
        Ok(fields) => fields,
        Err(outcome) => return outcome,
    };
    if let Some(section) = trailer_section {
        match decoded(dec.decode_field_section(sid, section)) {
            Ok(fields) if valid_trailer_section(&fields) => {}
            Ok(_) => return Extracted::Bad,
            Err(outcome) => return outcome,
        }
    }

    let mut method: Option<Vec<u8>> = None;
    let mut scheme: Option<Vec<u8>> = None;
    let mut authority: Option<Vec<u8>> = None;
    let mut host: Option<Vec<u8>> = None;
    let mut path: Option<Vec<u8>> = None;
    let mut content_length: Option<usize> = None;
    let mut content_type: Option<bool> = None;
    let mut regular_seen = false;
    for (n, v) in head {
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
            continue;
        }
        regular_seen = true;
        if is_connection_specific_field(&n) {
            return Extracted::Bad;
        }
        if n == b"content-length" {
            if content_length.is_some() || v.is_empty() || !v.iter().all(u8::is_ascii_digit) {
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
            // A different content type and a repeated header mean different things. A repeated
            // header is a request smuggling path, so it stays 400; a different type gets 415 so the
            // client can fix it.
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
    let mut body = Vec::new();
    for (t, payload) in &frames {
        if *t == FRAME_DATA {
            if body.len().saturating_add(payload.len()) > MAX_DNS_BODY {
                return Extracted::Bad;
            }
            body.extend_from_slice(payload);
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

pub struct H3Connection {
    conn: Connection,
    control_sent: bool,
    /// The first request stream not seen yet.
    next_request: u64,
    /// The ID our GOAWAY announced; requests on it or later streams are not processed.
    goaway: Option<u64>,
    requests: HashMap<u64, ReqBuf>,
    ready: Vec<H3DnsRequest>,
    qp: QpackCtx,

    blocked: Vec<(u64, Vec<u8>)>,
}

impl H3Connection {
    pub fn new(conn: Connection) -> Self {
        H3Connection {
            conn,
            control_sent: false,
            next_request: 0,
            goaway: None,
            requests: HashMap::new(),
            ready: Vec::new(),
            qp: QpackCtx::new(Role::Server),
            blocked: Vec::new(),
        }
    }

    /// Sent once 1-RTT keys exist, even before the handshake completes: QPACK updates that arrive
    /// in 0-RTT need acknowledgments, and the stream that carries them opens here.
    fn maybe_send_control(&mut self) -> Result<(), QuicError> {
        if self.control_sent || !self.conn.can_send_app() {
            return Ok(());
        }
        self.qp.send_setup(&mut self.conn)?;
        self.control_sent = true;
        Ok(())
    }

    /// Sends GOAWAY naming the first request stream not seen yet. Requests on it or later streams
    /// are then dropped unprocessed, which the client learns from the frame; requests already
    /// started are still taken. Fails when the control stream cannot be opened, as before the
    /// handshake has keys for application data.
    pub fn go_away(&mut self) -> Result<(), QuicError> {
        if self.goaway.is_some() {
            return Ok(());
        }
        self.maybe_send_control()?;
        let (true, Some(control)) = (self.control_sent, self.qp.ctrl_sid) else {
            return Err(QuicError::StreamLimit);
        };
        let mut payload = Vec::new();
        varint::write(&mut payload, self.next_request);
        let mut frame = Vec::new();
        encode_frame(&mut frame, FRAME_GOAWAY, &payload);
        send_critical(&mut self.conn, control, &frame)?;
        self.goaway = Some(self.next_request);
        Ok(())
    }

    fn buffered_bytes(&self) -> usize {
        self.requests
            .values()
            .map(|request| request.buf.len())
            .chain(self.blocked.iter().map(|(_, buf)| buf.len()))
            .chain(self.ready.iter().map(|request| request.wire.len()))
            .fold(0usize, usize::saturating_add)
    }

    /// Mutable payload bytes held by HTTP/3 and the QUIC connection under it. The DoH3 listener's
    /// global memory budget uses it so per-connection caps cannot multiply.
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

    fn try_extract(&mut self, id: u64, buf: Vec<u8>) -> Result<(), QuicError> {
        let status = match extract_dns_request(&mut self.qp.dec, id, &buf) {
            Extracted::Done(mut q) => {
                if self.ready.len() >= MAX_H3_STREAMS
                    || !fits_connection_buffer(self.buffered_bytes(), q.wire.len())
                {
                    return Err(H3Error::ExcessiveLoad.into());
                }
                q.stream_id = id;
                self.ready.push(q);
                return Ok(());
            }
            Extracted::Blocked => {
                let buffered = self.buffered_bytes();
                return hold_blocked(&mut self.blocked, buffered, id, buf);
            }
            Extracted::Fatal(error) => return Err(error.into()),
            Extracted::Bad => b"400".as_slice(),
            Extracted::Refused(status) => status,
        };
        // The peer already refused this stream's reply, so there is just nowhere to send it.
        // Returning the error would fail recv_datagram, and the caller would drop the whole
        // connection.
        match self.send_status(id, status) {
            Ok(()) | Err(QuicError::StreamClosed) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// An HTTP/3 connection error is sent to the peer, the connection is closed, and the error is
    /// returned; the QUIC layer has already reported its own errors. A datagram for a closed
    /// connection goes to the QUIC layer only: closing ends every stream, so their requests cannot
    /// be answered.
    pub fn recv_datagram(&mut self, dg: &[u8]) -> Result<(), QuicError> {
        self.conn.recv_datagram(dg)?;
        if self.conn.is_closed() {
            return Ok(());
        }
        self.process_streams()
            .map_err(|error| close_on_stream_error(&mut self.conn, error))
    }

    fn process_streams(&mut self) -> Result<(), QuicError> {
        match self.maybe_send_control() {
            Ok(()) | Err(QuicError::FlowControl | QuicError::StreamLimit) => {}
            Err(error) => return Err(error),
        }
        for (id, _) in self.conn.take_resets() {
            if id & 0x03 == 0x02 {
                self.qp.on_reset(id)?;
            } else {
                self.requests.remove(&id);
                self.blocked.retain(|(stream_id, _)| *stream_id != id);
                self.ready.retain(|request| request.stream_id != id);
                // A reset request's header sections will never be decoded, so tell the peer's
                // encoder.
                self.qp.dec.cancel_stream(id);
            }
        }
        let events = self.conn.take_readable();
        let mut completed: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut buffered = self.buffered_bytes();
        for (id, data, fin) in events {
            if id & 0x03 == 0x02 {
                self.qp.on_uni(id, &data, fin)?;
                continue;
            }
            if id & 0x03 != 0x00 {
                continue;
            }
            if self.goaway.is_some_and(|refused| id >= refused) {
                continue;
            }
            self.next_request = self.next_request.max(id + 4);
            if !self.requests.contains_key(&id) && self.requests.len() >= MAX_H3_STREAMS {
                return Err(H3Error::ExcessiveLoad.into());
            }
            if !fits_connection_buffer(buffered, data.len()) {
                return Err(H3Error::ExcessiveLoad.into());
            }
            let rb = self.requests.entry(id).or_default();
            if rb.buf.len().saturating_add(data.len()) > MAX_H3_STREAM_BUFFER {
                return Err(H3Error::ExcessiveLoad.into());
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

    pub fn take_requests_meta(&mut self) -> Vec<H3DnsRequest> {
        std::mem::take(&mut self.ready)
    }

    pub fn take_requests(&mut self) -> Vec<(u64, Vec<u8>)> {
        self.take_requests_meta()
            .into_iter()
            .map(|r| (r.stream_id, r.wire))
            .collect()
    }

    pub fn send_response(&mut self, id: u64, dns: &[u8], max_age: u32) -> Result<(), QuicError> {
        self.send_response_owned(id, dns.to_vec(), max_age)
    }

    /// `max_age` is the HTTP freshness lifetime. RFC 8484 caps it at the smallest TTL in the answer
    /// section, so the caller computes it.
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

    pub fn send_status(&mut self, id: u64, status: &[u8]) -> Result<(), QuicError> {
        self.maybe_send_control()?;
        // A 405 must list the accepted methods, or the client cannot tell what to retry with.
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

    pub fn next_datagram(&mut self) -> Option<Vec<u8>> {
        self.conn.next_datagram()
    }

    pub fn is_handshake_complete(&self) -> bool {
        self.conn.is_handshake_complete()
    }

    pub fn local_connection_id(&self) -> &[u8] {
        self.conn.local_connection_id()
    }

    pub fn peer_transport_params(&self) -> Option<&crate::params::TransportParams> {
        self.conn.peer_transport_params()
    }

    pub fn client_authenticated(&self) -> bool {
        self.conn.client_authenticated()
    }

    pub fn client_auth_identity(&self) -> Option<&str> {
        self.conn.client_auth_identity()
    }

    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    /// Whether the closing or draining period has also ended.
    pub fn is_terminated(&self) -> bool {
        self.conn.is_terminated()
    }

    /// Keeps only the state the closing or draining period needs. None for an open connection or
    /// when the period has ended.
    pub fn into_close_period(self) -> Option<ClosePeriod> {
        self.conn.into_close_period()
    }

    /// An already closed connection keeps its first reason.
    pub fn close(&mut self, error: H3Error) {
        self.conn.close(error.code(), error.reason());
    }

    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    pub fn set_now(&mut self, now_ms: u64) {
        self.conn.set_now(now_ms);
    }

    pub fn on_timeout(&mut self, now_ms: u64) {
        self.conn.on_timeout(now_ms);
    }
}

#[derive(Default)]
struct RespBuf {
    buf: Vec<u8>,
    done: bool,
    /// The result is out and reading stopped. Data the server sent before seeing STOP_SENDING still
    /// arrives and is dropped; the entry goes when the server ends or resets the stream.
    stopped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H3Response {
    /// Status 200 with application/dns-message.
    Dns(Vec<u8>),
    /// The status of a final response without a DNS message; the body is dropped. A 200 lands here
    /// too when content-type is not exactly application/dns-message, the body exceeds the DNS
    /// message limit, or the response exceeds the stream buffer limit.
    NotDns(u16),
    /// The stream was reset, or the server's GOAWAY said it will not process the request.
    Unanswered,
}

impl H3Response {
    /// Counted toward the connection buffer limit.
    fn held_bytes(&self) -> usize {
        match self {
            H3Response::Dns(body) => body.len(),
            H3Response::NotDns(_) | H3Response::Unanswered => 0,
        }
    }
}

pub struct H3Client {
    conn: Connection,
    setup_sent: bool,

    next_bidi: u64,
    resp: HashMap<u64, RespBuf>,

    ready: Vec<(u64, H3Response)>,
    qp: QpackCtx,

    blocked: Vec<(u64, Vec<u8>)>,

    /// Sent but unanswered. Requests at or above the server's GOAWAY ID are not processed; picking
    /// them from here lets the caller retry them on another connection.
    in_flight: HashSet<u64>,
}

impl H3Client {
    pub fn new(conn: Connection) -> Self {
        H3Client {
            conn,
            setup_sent: false,
            next_bidi: 0,
            resp: HashMap::new(),
            ready: Vec::new(),
            qp: QpackCtx::new(Role::Client),
            blocked: Vec::new(),
            in_flight: HashSet::new(),
        }
    }

    /// The connection stays open and earlier requests can still be answered, but new requests must
    /// go to another connection.
    pub fn is_going_away(&self) -> bool {
        self.qp.peer_control.goaway.is_some()
    }

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

    pub fn can_send_early(&self) -> bool {
        self.conn.can_send_early()
    }

    /// GoingAway after the server's GOAWAY; RFC 9114 forbids new requests then.
    pub fn send_request(
        &mut self,
        authority: &str,
        path: &str,
        body: &[u8],
    ) -> Result<u64, QuicError> {
        if self.is_going_away() {
            return Err(QuicError::GoingAway);
        }
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
        self.in_flight.insert(id);
        Ok(id)
    }

    fn buffered_bytes(&self) -> usize {
        self.resp
            .values()
            .map(|response| response.buf.len())
            .chain(self.blocked.iter().map(|(_, buf)| buf.len()))
            .chain(self.ready.iter().map(|(_, response)| response.held_bytes()))
            .fold(0usize, usize::saturating_add)
    }

    /// One malformed response closes the connection: the next response from that upstream on it
    /// cannot be trusted either.
    fn try_extract(&mut self, id: u64, buf: Vec<u8>) -> Result<(), QuicError> {
        match extract_dns_response(&mut self.qp.dec, id, &buf) {
            Extracted::Done(response) => {
                if self.ready.len() >= MAX_H3_STREAMS
                    || !fits_connection_buffer(self.buffered_bytes(), response.held_bytes())
                {
                    return Err(H3Error::ExcessiveLoad.into());
                }
                self.in_flight.remove(&id);
                self.ready.push((id, response));
                Ok(())
            }
            Extracted::Blocked => {
                let buffered = self.buffered_bytes();
                hold_blocked(&mut self.blocked, buffered, id, buf)
            }
            Extracted::Fatal(error) => Err(error.into()),
            Extracted::Bad | Extracted::Refused(_) => Err(H3Error::Message.into()),
        }
    }

    /// Ends a response over the stream buffer limit at its final status and refuses the rest of the
    /// body. DNS messages are far below that limit, so such a response has no DNS answer. Closing
    /// the connection would lose its other requests, so only this request ends: the rest of the
    /// body is refused with H3_REQUEST_CANCELLED, and the peer's encoder is told its remaining
    /// header sections will not be decoded.
    ///
    /// ExcessiveLoad when the final response headers have not arrived or wait on the table; a
    /// response of unknown status cannot be buffered past the limit.
    fn stop_oversized_response(&mut self, id: u64, received: Vec<u8>) -> Result<(), QuicError> {
        let Some(status) = oversized_response_status(&mut self.qp.dec, id, received)? else {
            return Err(H3Error::ExcessiveLoad.into());
        };
        if self.ready.len() >= MAX_H3_STREAMS {
            return Err(H3Error::ExcessiveLoad.into());
        }
        self.in_flight.remove(&id);
        self.ready.push((id, H3Response::NotDns(status)));
        self.qp.dec.cancel_stream(id);
        self.conn.stop_sending(id, H3_REQUEST_CANCELLED);
        Ok(())
    }

    /// An HTTP/3 connection error is sent to the peer, the connection is closed, and the error is
    /// returned; the QUIC layer has already reported its own errors. A datagram for a closed
    /// connection goes to the QUIC layer only.
    pub fn recv_datagram(&mut self, dg: &[u8]) -> Result<(), QuicError> {
        self.conn.recv_datagram(dg)?;
        if self.conn.is_closed() {
            return Ok(());
        }
        self.process_streams()
            .map_err(|error| close_on_stream_error(&mut self.conn, error))
    }

    fn process_streams(&mut self) -> Result<(), QuicError> {
        match self.maybe_send_setup() {
            Ok(()) | Err(QuicError::FlowControl | QuicError::StreamLimit) => {}
            Err(error) => return Err(error),
        }
        for (id, _) in self.conn.take_resets() {
            if id & 0x03 == 0x03 {
                self.qp.on_reset(id)?;
            } else {
                self.abandon_request(id);
            }
        }
        let events = self.conn.take_readable();
        let mut completed: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut buffered = self.buffered_bytes();
        for (id, data, fin) in events {
            if id & 0x03 == 0x03 {
                self.qp.on_uni(id, &data, fin)?;
                continue;
            }
            if id & 0x03 != 0x00 {
                continue;
            }
            // A request excluded by GOAWAY ends unanswered, so data on its stream is dropped.
            if self.qp.peer_control.goaway.is_some_and(|first| id >= first) {
                continue;
            }
            if !self.resp.contains_key(&id) && self.resp.len() >= MAX_H3_STREAMS {
                return Err(H3Error::ExcessiveLoad.into());
            }
            let rb = self.resp.entry(id).or_default();
            if rb.stopped {
                rb.done |= fin;
                continue;
            }
            if rb.buf.len().saturating_add(data.len()) > MAX_H3_STREAM_BUFFER {
                let mut received = std::mem::take(&mut rb.buf);
                buffered = buffered.saturating_sub(received.len());
                received.extend_from_slice(&data);
                rb.stopped = true;
                rb.done |= fin;
                self.stop_oversized_response(id, received)?;
                continue;
            }
            if !fits_connection_buffer(buffered, data.len()) {
                return Err(H3Error::ExcessiveLoad.into());
            }
            rb.buf.extend_from_slice(&data);
            buffered += data.len();
            if fin && !rb.done {
                rb.done = true;
                completed.push((id, std::mem::take(&mut rb.buf)));
            }
        }
        self.resp.retain(|_, response| !response.done);
        for (id, buf) in std::mem::take(&mut self.blocked) {
            self.try_extract(id, buf)?;
        }
        for (id, buf) in completed {
            self.try_extract(id, buf)?;
        }
        if let Some(first_refused) = self.qp.peer_control.goaway {
            let refused: Vec<u64> = self
                .in_flight
                .iter()
                .copied()
                .filter(|id| *id >= first_refused)
                .collect();
            for id in refused {
                self.abandon_request(id);
            }
        }
        self.qp.flush_decoder_stream(&mut self.conn)?;
        Ok(())
    }

    /// Each request yields one result; for one that already has a result, only its leftover stream
    /// state goes. Its header sections will not be decoded any more, so the peer's encoder is told.
    fn abandon_request(&mut self, id: u64) {
        self.resp.remove(&id);
        if !self.in_flight.remove(&id) {
            return;
        }
        self.blocked.retain(|(stream_id, _)| *stream_id != id);
        self.qp.dec.cancel_stream(id);
        self.ready.push((id, H3Response::Unanswered));
    }

    pub fn qpack_insert_count(&self) -> u64 {
        self.qp.enc.insert_count()
    }

    pub fn qpack_known_received(&self) -> u64 {
        self.qp.enc.known_received()
    }

    /// One result for each request sent with send_request.
    pub fn take_responses(&mut self) -> Vec<(u64, H3Response)> {
        std::mem::take(&mut self.ready)
    }

    pub fn send_status(&mut self, id: u64, status: &[u8]) -> Result<(), QuicError> {
        self.maybe_send_setup()?;
        let headers: [(&[u8], &[u8]); 1] = [(b":status", status)];
        let section = self.qp.encode_headers(&mut self.conn, &headers)?;
        let mut payload = Vec::new();
        encode_frame(&mut payload, FRAME_HEADERS, &section);
        self.conn.send_stream(id, &payload, true)
    }

    pub fn next_datagram(&mut self) -> Option<Vec<u8>> {
        self.conn.next_datagram()
    }

    pub fn is_handshake_complete(&self) -> bool {
        self.conn.is_handshake_complete()
    }

    pub fn can_send_app(&self) -> bool {
        self.conn.can_send_app()
    }

    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    /// An already closed connection keeps its first reason.
    pub fn close(&mut self, error: H3Error) {
        self.conn.close(error.code(), error.reason());
    }

    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    pub fn set_now(&mut self, now_ms: u64) {
        self.conn.set_now(now_ms);
    }

    pub fn on_timeout(&mut self, now_ms: u64) {
        self.conn.on_timeout(now_ms);
    }
}

struct ResponseHead {
    /// 1xx is an interim response before the final one.
    status: u16,
    content_length: Option<usize>,
    /// Exactly one content-type, equal to application/dns-message.
    dns_content_type: bool,
}

/// Interim and final responses follow the same rules; HTTP/3 has no 101. content-type only decides
/// whether the body is a DNS message: a 404 text/html is still a well-formed HTTP message.
///
/// None when malformed.
fn response_head(fields: Vec<(Vec<u8>, Vec<u8>)>) -> Option<ResponseHead> {
    let mut status: Option<u16> = None;
    let mut content_length: Option<usize> = None;
    let mut content_types = 0usize;
    let mut dns_content_type = false;
    let mut regular_seen = false;
    for (n, v) in fields {
        if !valid_header_field(&n, &v) {
            return None;
        }
        if n.starts_with(b":") {
            if regular_seen || n != b":status" || status.is_some() {
                return None;
            }
            if v.len() != 3 || !v.iter().all(u8::is_ascii_digit) {
                return None;
            }
            let parsed =
                ((v[0] - b'0') as u16) * 100 + ((v[1] - b'0') as u16) * 10 + (v[2] - b'0') as u16;
            if !(100..=599).contains(&parsed) || parsed == 101 {
                return None;
            }
            status = Some(parsed);
            continue;
        }
        regular_seen = true;
        if is_connection_specific_field(&n) || n == b"te" {
            return None;
        }
        if n == b"content-length" {
            if content_length.is_some() || v.is_empty() || !v.iter().all(u8::is_ascii_digit) {
                return None;
            }
            content_length = Some(std::str::from_utf8(&v).ok()?.parse::<usize>().ok()?);
        } else if n == b"content-type" {
            content_types += 1;
            dns_content_type = v.eq_ignore_ascii_case(b"application/dns-message");
        }
    }
    Some(ResponseHead {
        status: status?,
        content_length,
        dns_content_type: content_types == 1 && dns_content_type,
    })
}

/// A response is any number of 1xx interim responses, then the final one. Which HEADERS is which
/// shows only after decoding, so they are decoded in order. Interim responses have no body, so DATA
/// before the final response is malformed; DATA before any HEADERS is caught earlier by the frame
/// layout check. Frames after the final response stay in `frames`.
///
/// None when there is no final response.
fn read_final_head(
    dec: &mut qpack::Decoder,
    sid: u64,
    frames: &mut impl Iterator<Item = (u64, Vec<u8>)>,
) -> Result<Option<ResponseHead>, Extracted<H3Response>> {
    for (t, payload) in frames {
        match t {
            FRAME_HEADERS => {
                let fields = decoded(dec.decode_field_section(sid, &payload))?;
                let head = response_head(fields).ok_or(Extracted::Bad)?;
                if head.status >= 200 {
                    return Ok(Some(head));
                }
            }
            FRAME_DATA => return Err(Extracted::Bad),
            _ => {}
        }
    }
    Ok(None)
}

/// Same strictness as requests: frame order, duplicate status, and length match. A response is
/// interim responses, the final response, the body, and at most one trailer section. A well-formed
/// final response is a result even without a DNS message.
///
/// If any section must wait for the table, none is decoded: decoding some and retrying after the
/// wait would acknowledge them twice.
fn extract_dns_response(dec: &mut qpack::Decoder, sid: u64, buf: &[u8]) -> Extracted<H3Response> {
    let Some(frames) = parse_frames(buf) else {
        return Extracted::Fatal(H3Error::FrameError);
    };
    if let Err(error) = check_message_frames(&frames, Role::Client) {
        return Extracted::Fatal(error);
    }
    if frames
        .iter()
        .any(|(t, section)| *t == FRAME_HEADERS && dec.is_blocked(section))
    {
        return Extracted::Blocked;
    }
    let mut frames = frames.into_iter();
    let head = match read_final_head(dec, sid, &mut frames) {
        Ok(Some(head)) => head,
        Ok(None) => return Extracted::Bad,
        Err(outcome) => return outcome,
    };
    let mut trailer_seen = false;
    let mut body = Vec::new();
    for (t, payload) in frames {
        match t {
            FRAME_HEADERS | FRAME_DATA if trailer_seen => {
                return Extracted::Fatal(H3Error::FrameUnexpected)
            }
            FRAME_HEADERS => {
                let fields = match decoded(dec.decode_field_section(sid, &payload)) {
                    Ok(fields) => fields,
                    Err(outcome) => return outcome,
                };
                if !valid_trailer_section(&fields) {
                    return Extracted::Bad;
                }
                trailer_seen = true;
            }
            FRAME_DATA => body.extend_from_slice(&payload),
            _ => {}
        }
    }
    if head
        .content_length
        .is_some_and(|length| length != body.len())
    {
        return Extracted::Bad;
    }
    if head.status == 200 && head.dns_content_type && body.len() <= MAX_DNS_BODY {
        Extracted::Done(H3Response::Dns(body))
    } else {
        Extracted::Done(H3Response::NotDns(head.status))
    }
}

/// Looks only at the complete frames received and decodes up to the final response headers, not the
/// body or trailers. Frame layout or header errors are reported as for a complete response.
///
/// None when the final headers have not arrived or wait on the table.
fn oversized_response_status(
    dec: &mut qpack::Decoder,
    sid: u64,
    mut received: Vec<u8>,
) -> Result<Option<u16>, H3Error> {
    let frames = drain_complete_frames(&mut received);
    check_message_frames(&frames, Role::Client)?;
    match read_final_head(dec, sid, &mut frames.into_iter()) {
        Ok(head) => Ok(head.map(|head| head.status)),
        Err(Extracted::Blocked) => Ok(None),
        Err(Extracted::Fatal(error)) => Err(error),
        Err(_) => Err(H3Error::Message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let mut buf = Vec::new();
        encode_frame(&mut buf, FRAME_HEADERS, b"hdr");
        encode_frame(&mut buf, FRAME_DATA, b"body-bytes");
        let frames = parse_frames(&buf).unwrap();
        assert_eq!(frames[0], (FRAME_HEADERS, b"hdr".to_vec()));
        assert_eq!(frames[1], (FRAME_DATA, b"body-bytes".to_vec()));
    }

    #[test]
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
    fn grease_before_headers_is_ignored() {
        /// A reserved type that must be ignored.
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
            Extracted::Done(H3Response::Dns(body)) if body == dns
        ));
    }

    fn encoded_headers(headers: &[(&[u8], &[u8])]) -> Vec<u8> {
        qpack::Encoder::new().encode_field_section(headers).0
    }

    fn assert_bad_request(buf: &[u8]) {
        let mut dec = qpack::Decoder::new(4096);
        assert!(matches!(
            extract_dns_request(&mut dec, 0, buf),
            Extracted::Bad
        ));
    }

    #[test]
    /// The HTTP/1.1 and HTTP/2 paths answer 415 and 405 too; transports of one server must give the
    /// same answer. A repeated content-type stays 400, since it lets front and back ends read the
    /// same bytes differently.
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
            Extracted::Fatal(error) => format!("{error:?}"),
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
    /// Bad frame order is a connection error; the others reject only that request.
    fn request_rejects_bad_frame_order_duplicate_pseudo_and_length_mismatch() {
        let mut data_first = Vec::new();
        encode_frame(&mut data_first, FRAME_DATA, b"dns");
        let mut settings = Vec::new();
        encode_frame(&mut settings, FRAME_SETTINGS, b"");
        for buf in [data_first, settings] {
            assert!(matches!(
                extract_dns_request(&mut qpack::Decoder::new(4096), 0, &buf),
                Extracted::Fatal(H3Error::FrameUnexpected)
            ));
        }

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
    fn response_rejects_bad_order_duplicate_status_and_invalid_metadata() {
        let mut data_first = Vec::new();
        encode_frame(&mut data_first, FRAME_DATA, b"dns");
        let mut settings = Vec::new();
        encode_frame(&mut settings, FRAME_SETTINGS, b"");
        for buf in [data_first, settings] {
            assert!(matches!(
                extract_dns_response(&mut qpack::Decoder::new(4096), 0, &buf),
                Extracted::Fatal(H3Error::FrameUnexpected)
            ));
        }

        for headers in [
            vec![
                (b":status".as_slice(), b"200".as_slice()),
                (b":status", b"400"),
            ],
            vec![
                (b":status".as_slice(), b"200".as_slice()),
                (b"content-type", b"application/dns-message"),
                (b"content-length", b"4"),
            ],
            vec![
                (b":status".as_slice(), b"404".as_slice()),
                (b"content-type", b"text/html"),
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
    /// content-type and the DNS body limit are DoH rules, not HTTP message format. Treating them as
    /// malformed would close the whole connection with H3_MESSAGE_ERROR on one 404 text/html.
    fn answers_without_a_dns_message_are_not_malformed() {
        fn answer(headers: &[(&[u8], &[u8])], body: &[u8]) -> H3Response {
            match extract_dns_response(
                &mut qpack::Decoder::new(4096),
                0,
                &message(&encoded_headers(headers), &[(FRAME_DATA, body)]),
            ) {
                Extracted::Done(response) => response,
                other => panic!("형식이 온전한 응답을 거부했습니다: {}", outcome(other)),
            }
        }
        let dns: &[u8] = b"\x12\x34dns";
        let page = vec![b'x'; MAX_DNS_BODY + 1];
        let page_length = page.len().to_string();

        assert_eq!(
            answer(
                &[(b":status", b"404"), (b"content-type", b"text/html")],
                b"<html>not found</html>"
            ),
            H3Response::NotDns(404)
        );
        assert_eq!(
            answer(
                &[
                    (b":status", b"404"),
                    (b"content-type", b"text/html"),
                    (b"content-length", page_length.as_bytes()),
                ],
                &page
            ),
            H3Response::NotDns(404),
            "DNS 가 아닌 본문에는 DNS 메시지 상한을 걸지 않습니다"
        );
        assert_eq!(
            answer(&[(b":status", b"503")], b""),
            H3Response::NotDns(503)
        );
        assert_eq!(
            answer(
                &[(b":status", b"200"), (b"content-type", b"text/html")],
                b"<html>portal</html>"
            ),
            H3Response::NotDns(200)
        );
        assert_eq!(
            answer(&[(b":status", b"200")], dns),
            H3Response::NotDns(200)
        );
        assert_eq!(
            answer(
                &[
                    (b":status", b"200"),
                    (b"content-type", b"application/dns-message"),
                    (b"content-type", b"application/dns-message"),
                ],
                dns
            ),
            H3Response::NotDns(200),
            "겹친 content-type 은 본문 형식을 정하지 못합니다"
        );
        assert_eq!(
            answer(
                &[
                    (b":status", b"200"),
                    (b"content-type", b"application/dns-message"),
                    (b"content-length", page_length.as_bytes()),
                ],
                &page
            ),
            H3Response::NotDns(200),
            "DNS 메시지 상한을 넘는 본문은 DNS 메시지가 아닙니다"
        );
        assert_eq!(
            answer(
                &[
                    (b":status", b"200"),
                    (b"content-type", b"Application/DNS-Message"),
                ],
                dns
            ),
            H3Response::Dns(dns.to_vec())
        );
    }

    #[test]
    /// A 404 only means that request failed; closing the connection would lose its other requests.
    fn answer_without_a_dns_message_keeps_the_connection() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);
        let refused = client
            .send_request("dns.example", "/dns-query", b"\x00\x00 refused")
            .unwrap();
        let answered = client
            .send_request("dns.example", "/dns-query", b"\x00\x00 answered")
            .unwrap();
        pump_h3(&mut client, &mut server);
        assert_eq!(server.take_requests().len(), 2);

        let page: &[u8] = b"<html>not found</html>";
        let length = page.len().to_string();
        let headers: [(&[u8], &[u8]); 3] = [
            (b":status", b"404"),
            (b"content-type", b"text/html"),
            (b"content-length", length.as_bytes()),
        ];
        let section = server
            .qp
            .encode_headers(&mut server.conn, &headers)
            .unwrap();
        let mut payload = Vec::new();
        encode_frame(&mut payload, FRAME_HEADERS, &section);
        encode_frame(&mut payload, FRAME_DATA, page);
        server
            .conn_mut()
            .send_stream(refused, &payload, true)
            .unwrap();
        pump_h3(&mut client, &mut server);
        assert_eq!(
            client.take_responses(),
            vec![(refused, H3Response::NotDns(404))]
        );
        assert!(
            !client.is_closed() && !server.is_closed(),
            "DNS 가 아닌 답 하나에 연결이 닫혔습니다"
        );

        server
            .send_response(answered, b"\x00\x00 answer", 0)
            .unwrap();
        pump_h3(&mut client, &mut server);
        assert_eq!(
            client.take_responses(),
            vec![(answered, H3Response::Dns(b"\x00\x00 answer".to_vec()))]
        );
    }

    /// Stream IDs from Stream Cancellations on the peer's QPACK decoder stream. This encoder drops
    /// those instructions, so the test reads them from the QUIC layer. With these small IDs each
    /// one is a single byte.
    fn cancelled_streams(conn: &mut Connection, decoder: u64) -> Vec<u64> {
        conn.take_readable()
            .into_iter()
            .filter(|(id, _, _)| *id == decoder)
            .flat_map(|(_, data, _)| data)
            .filter(|instruction| instruction & 0xc0 == 0x40)
            .map(|instruction| u64::from(instruction & 0x3f))
            .collect()
    }

    #[test]
    /// The result is the final status, the rest of the body is refused with STOP_SENDING, data
    /// arriving meanwhile is dropped, and a Stream Cancellation goes to the peer's encoder.
    fn oversized_response_fails_only_that_request() {
        /// The server side goes through the QUIC layer only. Returns the stream IDs of Stream
        /// Cancellations the client sent meanwhile.
        fn relay(client: &mut H3Client, server: &mut H3Connection) -> Vec<u64> {
            let decoder = client.qp.dec_sid.expect("클라이언트 디코더 스트림");
            let mut cancelled = Vec::new();
            for _ in 0..30 {
                let mut moved = false;
                while let Some(dg) = server.next_datagram() {
                    client.recv_datagram(&dg).unwrap();
                    moved = true;
                }
                while let Some(dg) = client.next_datagram() {
                    server.conn_mut().recv_datagram(&dg).unwrap();
                    moved = true;
                }
                cancelled.extend(cancelled_streams(server.conn_mut(), decoder));
                if !moved {
                    break;
                }
            }
            cancelled
        }

        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);
        let stopped = client
            .send_request("dns.example", "/dns-query", b"\x00\x00 stopped")
            .unwrap();
        let finished = client
            .send_request("dns.example", "/dns-query", b"\x00\x00 finished")
            .unwrap();
        let oversized_dns = client
            .send_request("dns.example", "/dns-query", b"\x00\x00 oversized")
            .unwrap();
        let ended = client
            .send_request("dns.example", "/dns-query", b"\x00\x00 ended")
            .unwrap();
        let answered = client
            .send_request("dns.example", "/dns-query", b"\x00\x00 answered")
            .unwrap();
        pump_h3(&mut client, &mut server);
        assert_eq!(server.take_requests().len(), 5);

        // Sends up to just below the limit first and the rest later. With a long rest, data past
        // the limit and FIN would reach the client before STOP_SENDING, so a short rest is sent
        // alone to put the crossing piece and FIN in one packet.
        let long_page = vec![b'x'; MAX_H3_STREAM_BUFFER + 4096];
        let short_page = vec![b'x'; MAX_H3_STREAM_BUFFER];
        let long_head = MAX_H3_STREAM_BUFFER - 1024;
        let short_head = MAX_H3_STREAM_BUFFER - 100;
        let html: &[u8] = b"text/html";
        let dns: &[u8] = b"application/dns-message";
        let mut tails = Vec::new();
        for (id, status, content_type, page, head_len, fin) in [
            (stopped, b"404", html, &long_page, long_head, false),
            (finished, b"503", html, &long_page, long_head, true),
            (oversized_dns, b"200", dns, &long_page, long_head, false),
            (ended, b"404", html, &short_page, short_head, true),
        ] {
            let headers: [(&[u8], &[u8]); 2] =
                [(b":status", status), (b"content-type", content_type)];
            let section = server
                .qp
                .encode_headers(&mut server.conn, &headers)
                .unwrap();
            let mut payload = Vec::new();
            encode_frame(&mut payload, FRAME_HEADERS, &section);
            encode_frame(&mut payload, FRAME_DATA, page);
            let tail = payload.split_off(head_len);
            server.conn_mut().send_stream(id, &payload, false).unwrap();
            tails.push((id, tail, fin));
        }
        pump_h3(&mut client, &mut server);
        assert!(client.take_responses().is_empty());
        let (_, short_tail, _) = tails.pop().expect("짧은 나머지");
        for (id, tail, fin) in tails {
            server.conn_mut().send_stream(id, &tail, fin).unwrap();
        }
        let mut cancelled = relay(&mut client, &mut server);
        server
            .conn_mut()
            .send_stream(ended, &short_tail, true)
            .unwrap();
        cancelled.extend(relay(&mut client, &mut server));

        let mut responses = client.take_responses();
        responses.sort_by_key(|(id, _)| *id);
        assert_eq!(
            responses,
            vec![
                (stopped, H3Response::NotDns(404)),
                (finished, H3Response::NotDns(503)),
                (oversized_dns, H3Response::NotDns(200)),
                (ended, H3Response::NotDns(404)),
            ]
        );
        assert!(
            !client.is_closed() && !server.is_closed(),
            "버퍼 상한을 넘은 응답에 연결이 닫혔습니다"
        );
        cancelled.sort_unstable();
        assert_eq!(
            cancelled,
            vec![stopped, finished, oversized_dns, ended],
            "읽기를 그만둔 스트림마다 Stream Cancellation 이 나가야 합니다"
        );
        assert_eq!(
            server.conn_mut().send_stream(stopped, b"more", false),
            Err(QuicError::StreamClosed),
            "남은 본문을 STOP_SENDING 으로 거절해야 합니다"
        );
        assert!(
            client.resp.is_empty(),
            "끝난 응답 스트림의 상태가 남았습니다"
        );

        server
            .send_response(answered, b"\x00\x00 answer", 0)
            .unwrap();
        pump_h3(&mut client, &mut server);
        assert_eq!(
            client.take_responses(),
            vec![(answered, H3Response::Dns(b"\x00\x00 answer".to_vec()))]
        );
    }

    #[test]
    /// Waiting for the deadline would hold the request that long. Frame layout errors and message
    /// content errors get different codes.
    fn malformed_response_is_reported_without_waiting_for_timeout() {
        let (mut client, _) = h3_pair();
        let mut data_first = Vec::new();
        encode_frame(&mut data_first, FRAME_DATA, b"not a response");
        assert_eq!(
            client.try_extract(0, data_first),
            Err(H3Error::FrameUnexpected.into())
        );

        let mut without_status = Vec::new();
        encode_frame(
            &mut without_status,
            FRAME_HEADERS,
            &encoded_headers(&[(b"content-type", b"application/dns-message")]),
        );
        encode_frame(&mut without_status, FRAME_DATA, b"dns");
        assert_eq!(
            client.try_extract(4, without_status),
            Err(H3Error::Message.into())
        );
    }

    #[test]
    fn h3_application_buffers_are_connection_bounded() {
        assert!(fits_connection_buffer(MAX_H3_CONNECTION_BUFFER - 1, 1));
        assert!(!fits_connection_buffer(MAX_H3_CONNECTION_BUFFER, 1));
        assert!(!fits_connection_buffer(usize::MAX, 1));
    }

    #[test]
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
                Err(error) if error == H3Error::ExcessiveLoad.into() => {
                    rejected = true;
                    break;
                }
                Err(error) => panic!("unexpected QUIC error: {error:?}"),
            }
        }
        assert!(rejected);
    }

    #[test]
    fn queued_responses_count_toward_in_progress_client_buffer_limit() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);
        let stream_id = client
            .send_request("dns.example", "/dns-query", b"query")
            .unwrap();
        pump_h3(&mut client, &mut server);
        assert_eq!(server.take_requests(), vec![(stream_id, b"query".to_vec())]);
        client.ready.push((
            100,
            H3Response::Dns(vec![0; MAX_H3_CONNECTION_BUFFER - 512]),
        ));

        server.send_response(stream_id, &[0x5a; 1024], 0).unwrap();
        let mut rejected = false;
        while let Some(datagram) = server.next_datagram() {
            match client.recv_datagram(&datagram) {
                Ok(()) => {}
                Err(error) if error == H3Error::ExcessiveLoad.into() => {
                    rejected = true;
                    break;
                }
                Err(error) => panic!("unexpected QUIC error: {error:?}"),
            }
        }
        assert!(rejected);
    }

    #[test]
    fn base64url_roundtrip_known() {
        assert_eq!(base64url_decode(b"YWJj").unwrap(), b"abc");

        assert_eq!(base64url_decode(b"YQ").unwrap(), b"a");

        assert_eq!(base64url_decode(b"-_8").unwrap(), vec![0xfb, 0xff]);

        assert!(base64url_decode(b"YQ==").is_none());
        assert!(base64url_decode(b"A").is_none());
        assert!(base64url_decode(b"YR").is_none());
    }

    #[test]
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

    fn h3_pair_with(
        resumption: Option<onetdns_tls::conn::ServerResumption>,
        session: Option<onetdns_tls::TlsSession>,
    ) -> (H3Client, H3Connection) {
        h3_pair_with_server_tp(resumption, session, TransportParams::server_defaults())
    }

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

    fn h3_pair() -> (H3Client, H3Connection) {
        h3_pair_with(None, None)
    }

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

    fn request_without_path() -> Vec<u8> {
        let mut request = Vec::new();
        encode_frame(
            &mut request,
            FRAME_HEADERS,
            &encoded_headers(&[
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", b"dns.example"),
                (b"content-type", b"application/dns-message"),
            ]),
        );
        encode_frame(&mut request, FRAME_DATA, b"\x00\x00 query");
        request
    }

    #[test]
    /// RFC 9114 makes bad frame order an H3_FRAME_UNEXPECTED connection error, not a 400.
    fn request_frame_order_violation_closes_the_connection() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);

        let mut data_first = Vec::new();
        encode_frame(&mut data_first, FRAME_DATA, b"not a request");
        client.conn_mut().send_stream(0, &data_first, true).unwrap();
        let mut rejected = None;
        while let Some(dg) = client.next_datagram() {
            if let Err(error) = server.recv_datagram(&dg) {
                rejected = Some(error);
                break;
            }
        }
        assert_eq!(rejected, Some(H3Error::FrameUnexpected.into()));
        while let Some(dg) = server.next_datagram() {
            client.conn_mut().recv_datagram(&dg).unwrap();
        }
        assert_eq!(
            client.conn_mut().peer_close().map(|close| close.error_code),
            Some(H3Error::FrameUnexpected.code())
        );
    }

    #[test]
    fn malformed_request_receives_immediate_bad_request_response() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);

        client
            .conn_mut()
            .send_stream(0, &request_without_path(), true)
            .unwrap();
        pump_h3(&mut client, &mut server);

        assert_eq!(client.take_responses(), vec![(0, H3Response::NotDns(400))]);
        assert!(!server.is_closed());
    }

    #[test]
    /// A late reply to a stopped stream must be a stream error; as a connection error, the server
    /// would drop the other queries on the connection.
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
            .stop_sending(cancelled, H3_REQUEST_CANCELLED);
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
            .contains(&(next, H3Response::Dns(b"\x00\x00 answer".to_vec()))));
    }

    #[test]
    /// A reset stream's header sections are never decoded, and without the notice the peer's
    /// encoder cannot release the entries they reference. Checks both response and request streams.
    fn reset_streams_cancel_their_field_sections() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);

        let reset_response = client
            .send_request("dns.example", "/dns-query", b"\x00\x00 reset")
            .unwrap();
        pump_h3(&mut client, &mut server);
        assert_eq!(server.take_requests().len(), 1);
        server
            .conn_mut()
            .send_reset_stream_for_test(reset_response, H3_REQUEST_CANCELLED);
        while let Some(dg) = server.next_datagram() {
            client.recv_datagram(&dg).unwrap();
        }
        assert_eq!(
            client.take_responses(),
            vec![(reset_response, H3Response::Unanswered)]
        );
        let client_decoder = client.qp.dec_sid.expect("클라이언트 디코더 스트림");
        while let Some(dg) = client.next_datagram() {
            server.conn_mut().recv_datagram(&dg).unwrap();
        }
        assert_eq!(
            cancelled_streams(server.conn_mut(), client_decoder),
            vec![reset_response],
            "끊긴 응답 스트림"
        );

        let reset_request = reset_response + 4;
        client
            .conn_mut()
            .send_stream(reset_request, &request_without_path()[..1], false)
            .unwrap();
        pump_h3(&mut client, &mut server);
        client
            .conn_mut()
            .send_reset_stream_for_test(reset_request, H3_REQUEST_CANCELLED);
        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
        }
        let server_decoder = server.qp.dec_sid.expect("서버 디코더 스트림");
        while let Some(dg) = server.next_datagram() {
            client.conn_mut().recv_datagram(&dg).unwrap();
        }
        assert_eq!(
            cancelled_streams(client.conn_mut(), server_decoder),
            vec![reset_request],
            "끊긴 요청 스트림"
        );
        assert!(!client.is_closed() && !server.is_closed());
    }

    /// Announces any ID; `go_away` always names the first request stream not seen.
    fn send_goaway(server: &mut H3Connection, first_unprocessed: u64) {
        let control = server.qp.ctrl_sid.expect("서버 제어 스트림");
        let mut payload = Vec::new();
        varint::write(&mut payload, first_unprocessed);
        let mut frame = Vec::new();
        encode_frame(&mut frame, FRAME_GOAWAY, &payload);
        server
            .conn_mut()
            .send_stream(control, &frame, false)
            .unwrap();
    }

    #[test]
    /// Requests at or above the announced ID are reported at once so they can be retried elsewhere;
    /// earlier ones still get their answers.
    fn goaway_refuses_new_and_unprocessed_requests() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);
        let kept = client
            .send_request("dns.example", "/dns-query", b"\x00\x00 kept")
            .unwrap();
        let unprocessed = client
            .send_request("dns.example", "/dns-query", b"\x00\x00 unprocessed")
            .unwrap();
        pump_h3(&mut client, &mut server);
        assert_eq!(server.take_requests().len(), 2);

        send_goaway(&mut server, unprocessed);
        pump_h3(&mut client, &mut server);
        assert!(client.is_going_away());
        assert_eq!(
            client.take_responses(),
            vec![(unprocessed, H3Response::Unanswered)]
        );
        assert_eq!(
            client.send_request("dns.example", "/dns-query", b"\x00\x00 late"),
            Err(QuicError::GoingAway)
        );

        server.send_response(kept, b"\x00\x00 kept", 0).unwrap();
        server
            .send_response(unprocessed, b"\x00\x00 contradicts goaway", 0)
            .unwrap();
        pump_h3(&mut client, &mut server);
        assert_eq!(
            client.take_responses(),
            vec![(kept, H3Response::Dns(b"\x00\x00 kept".to_vec()))],
            "처리하지 않는다고 알린 요청의 결과가 두 번 나왔습니다"
        );
        assert!(!client.is_closed());
    }

    #[test]
    /// A request the client sent before it learned of the GOAWAY is not processed and is reported
    /// to the client as such; the request the server had already taken is still answered.
    fn go_away_names_the_first_request_not_seen() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);
        let kept = client
            .send_request("dns.example", "/dns-query", b"\x00\x00 kept")
            .unwrap();
        pump_h3(&mut client, &mut server);
        assert_eq!(server.take_requests().len(), 1);

        let raced = client
            .send_request("dns.example", "/dns-query", b"\x00\x00 raced")
            .unwrap();
        server.go_away().unwrap();
        pump_h3(&mut client, &mut server);
        assert!(
            server.take_requests().is_empty(),
            "GOAWAY 뒤에 온 요청을 처리했습니다"
        );
        assert_eq!(
            client.take_responses(),
            vec![(raced, H3Response::Unanswered)]
        );

        server.send_response(kept, b"\x00\x00 kept", 0).unwrap();
        pump_h3(&mut client, &mut server);
        assert_eq!(
            client.take_responses(),
            vec![(kept, H3Response::Dns(b"\x00\x00 kept".to_vec()))]
        );
        assert!(!client.is_closed() && !server.is_closed());
    }

    #[test]
    /// A malformed request gets 400 on the spot. If the peer stopped that stream there is just
    /// nowhere to send it, and failing recv_datagram would make the caller drop the connection.
    fn immediate_status_to_a_stopped_stream_keeps_the_connection() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);

        let invalid = request_without_path();
        client
            .conn_mut()
            .send_stream(0, &invalid[..1], false)
            .unwrap();
        pump_h3(&mut client, &mut server);
        client.conn_mut().stop_sending(0, H3_REQUEST_CANCELLED);
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
    fn stopped_critical_stream_is_a_connection_error() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);
        let id = client
            .send_request("dns.example", "/dns-query", b"\x00\x00 query")
            .unwrap();
        pump_h3(&mut client, &mut server);
        assert_eq!(server.take_requests().len(), 1);

        let encoder = server.qp.enc_sid.expect("서버 인코더 스트림");
        client.conn_mut().stop_sending(encoder, 0);
        // The server's RESET_STREAM would end a critical stream for the client too, so only the
        // client's datagrams are relayed, to see the server's verdict alone.
        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
        }
        // A new max-age value goes into the dynamic table, so there is something for the encoder
        // stream.
        assert_eq!(
            server.send_response(id, b"\x00\x00 answer", 4242),
            Err(H3Error::ClosedCriticalStream.into())
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
            Some(H3Error::ClosedCriticalStream.code())
        );
    }

    #[test]
    /// The code RFC 9204 sets.
    fn reset_qpack_stream_closes_with_closed_critical_stream() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);

        let encoder = client.qp.enc_sid.expect("클라이언트 인코더 스트림");
        client.conn_mut().send_reset_stream_for_test(encoder, 0);
        let mut rejected = None;
        while let Some(dg) = client.next_datagram() {
            if let Err(error) = server.recv_datagram(&dg) {
                rejected = Some(error);
                break;
            }
        }
        assert_eq!(rejected, Some(H3Error::ClosedCriticalStream.into()));
        while let Some(dg) = server.next_datagram() {
            client.conn_mut().recv_datagram(&dg).unwrap();
        }
        let close = client
            .conn_mut()
            .peer_close()
            .cloned()
            .expect("종료 사유가 오지 않았습니다");
        assert_eq!(close.error_code, H3Error::ClosedCriticalStream.code());
        assert_eq!(close.frame_type, None, "응용 계층 종료여야 합니다");
    }

    #[test]
    /// There is one control stream per connection, so a second one is H3_STREAM_CREATION_ERROR.
    /// Dropping it silently would leave the peer waiting until its idle deadline.
    fn http3_connection_error_reaches_the_peer() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);

        send_second_control_stream(client.conn_mut());
        let mut rejected = None;
        while let Some(dg) = client.next_datagram() {
            if let Err(error) = server.recv_datagram(&dg) {
                rejected = Some(error);
                break;
            }
        }
        assert_eq!(
            rejected,
            Some(H3Error::StreamCreation.into()),
            "두 번째 제어 스트림을 받아들였습니다"
        );
        assert!(server.is_closed());

        while let Some(dg) = server.next_datagram() {
            client.conn_mut().recv_datagram(&dg).unwrap();
        }
        let close = client
            .conn_mut()
            .peer_close()
            .cloned()
            .expect("종료 사유가 오지 않았습니다");
        assert_eq!(close.error_code, H3Error::StreamCreation.code());
        assert_eq!(close.frame_type, None, "응용 계층 종료여야 합니다");
    }

    #[test]
    /// Without it the upstream would hold the connection until its idle deadline.
    fn http3_client_connection_error_reaches_the_server() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);

        send_second_control_stream(server.conn_mut());
        let mut rejected = None;
        while let Some(dg) = server.next_datagram() {
            if let Err(error) = client.recv_datagram(&dg) {
                rejected = Some(error);
                break;
            }
        }
        assert_eq!(
            rejected,
            Some(H3Error::StreamCreation.into()),
            "두 번째 제어 스트림을 받아들였습니다"
        );
        assert!(client.is_closed());

        while let Some(dg) = client.next_datagram() {
            server.conn_mut().recv_datagram(&dg).unwrap();
        }
        let close = server
            .conn_mut()
            .peer_close()
            .cloned()
            .expect("종료 사유가 오지 않았습니다");
        assert_eq!(close.error_code, H3Error::StreamCreation.code());
        assert_eq!(close.frame_type, None, "응용 계층 종료여야 합니다");
    }

    fn send_second_control_stream(conn: &mut Connection) {
        let id = conn.open_uni_stream().unwrap();
        let mut data = Vec::new();
        varint::write(&mut data, UNI_CONTROL);
        encode_frame(&mut data, FRAME_SETTINGS, &our_settings());
        conn.send_stream(id, &data, false).unwrap();
    }

    #[test]
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
    fn closed_unknown_uni_streams_do_not_exhaust_connection_state() {
        let mut qp = QpackCtx::new(Role::Server);
        let mut stream_type = Vec::new();
        varint::write(&mut stream_type, 0x21);

        for id in 0..(MAX_H3_UNI_STREAMS * 4) as u64 {
            assert_eq!(qp.on_uni(id, &stream_type, true), Ok(()));
            assert!(qp.uni_in.is_empty());
        }
    }

    #[test]
    fn closing_critical_uni_stream_is_rejected() {
        for stream_type in [UNI_CONTROL, UNI_QPACK_ENCODER, UNI_QPACK_DECODER] {
            let mut qp = QpackCtx::new(Role::Server);
            let mut data = Vec::new();
            varint::write(&mut data, stream_type);
            assert_eq!(
                qp.on_uni(2, &data, true),
                Err(H3Error::ClosedCriticalStream)
            );
            assert!(qp.uni_in.is_empty());
        }
    }

    #[test]
    fn resetting_critical_uni_stream_is_rejected() {
        for stream_type in [UNI_CONTROL, UNI_QPACK_ENCODER, UNI_QPACK_DECODER] {
            let mut qp = QpackCtx::new(Role::Server);
            let mut data = Vec::new();
            varint::write(&mut data, stream_type);
            assert_eq!(qp.on_uni(2, &data, false), Ok(()));
            assert_eq!(qp.on_reset(2), Err(H3Error::ClosedCriticalStream));
            assert!(qp.uni_in.is_empty());
        }

        let mut qp = QpackCtx::new(Role::Server);
        assert_eq!(qp.on_reset(2), Ok(()));
    }

    #[test]
    fn duplicate_critical_uni_stream_is_rejected() {
        for stream_type in [UNI_CONTROL, UNI_QPACK_ENCODER, UNI_QPACK_DECODER] {
            let mut qp = QpackCtx::new(Role::Server);
            let mut data = Vec::new();
            varint::write(&mut data, stream_type);

            assert_eq!(qp.on_uni(2, &data, false), Ok(()));
            assert_eq!(qp.on_uni(2, &[], false), Ok(()));
            assert_eq!(qp.on_uni(6, &data, false), Err(H3Error::StreamCreation));
        }
    }

    fn control_bytes(frame_type: u64, payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        varint::write(&mut data, UNI_CONTROL);
        encode_frame(&mut data, frame_type, payload);
        data
    }

    #[test]
    fn control_stream_requires_exactly_one_initial_settings_frame() {
        let mut qp = QpackCtx::new(Role::Server);
        assert_eq!(
            qp.on_uni(2, &control_bytes(0x21, &[]), false),
            Err(H3Error::MissingSettings)
        );

        let mut qp = QpackCtx::new(Role::Server);
        assert_eq!(
            qp.on_uni(2, &control_bytes(FRAME_SETTINGS, &our_settings()), false),
            Ok(())
        );
        let mut second = Vec::new();
        encode_frame(&mut second, FRAME_SETTINGS, &[]);
        assert_eq!(qp.on_uni(2, &second, false), Err(H3Error::FrameUnexpected));
    }

    #[test]
    fn settings_reject_duplicate_ids_and_truncated_values() {
        let mut duplicate = Vec::new();
        for value in [1, 2] {
            varint::write(&mut duplicate, SETTINGS_QPACK_MAX_TABLE_CAPACITY);
            varint::write(&mut duplicate, value);
        }
        let mut qp = QpackCtx::new(Role::Server);
        assert_eq!(
            qp.on_uni(2, &control_bytes(FRAME_SETTINGS, &duplicate), false),
            Err(H3Error::SettingsError)
        );

        let mut truncated = Vec::new();
        varint::write(&mut truncated, SETTINGS_QPACK_MAX_TABLE_CAPACITY);
        let mut qp = QpackCtx::new(Role::Server);
        assert_eq!(
            qp.on_uni(2, &control_bytes(FRAME_SETTINGS, &truncated), false),
            Err(H3Error::FrameError)
        );

        for reserved in 0x02..=0x05 {
            let mut payload = Vec::new();
            varint::write(&mut payload, reserved);
            varint::write(&mut payload, 0);
            let mut qp = QpackCtx::new(Role::Server);
            assert_eq!(
                qp.on_uni(2, &control_bytes(FRAME_SETTINGS, &payload), false),
                Err(H3Error::SettingsError)
            );
        }
    }

    #[test]
    /// This side never allows server push, so every CANCEL_PUSH is H3_ID_ERROR; only a client may
    /// send MAX_PUSH_ID.
    fn control_stream_rejects_frames_that_belong_elsewhere() {
        let cases: [(u64, Role, Result<(), H3Error>); 14] = [
            (FRAME_DATA, Role::Server, Err(H3Error::FrameUnexpected)),
            (FRAME_HEADERS, Role::Server, Err(H3Error::FrameUnexpected)),
            (
                FRAME_PUSH_PROMISE,
                Role::Client,
                Err(H3Error::FrameUnexpected),
            ),
            (0x02, Role::Server, Err(H3Error::FrameUnexpected)),
            (0x06, Role::Server, Err(H3Error::FrameUnexpected)),
            (0x08, Role::Client, Err(H3Error::FrameUnexpected)),
            (0x09, Role::Client, Err(H3Error::FrameUnexpected)),
            (FRAME_CANCEL_PUSH, Role::Server, Err(H3Error::IdError)),
            (FRAME_CANCEL_PUSH, Role::Client, Err(H3Error::IdError)),
            (
                FRAME_MAX_PUSH_ID,
                Role::Client,
                Err(H3Error::FrameUnexpected),
            ),
            (FRAME_MAX_PUSH_ID, Role::Server, Ok(())),
            (FRAME_GOAWAY, Role::Server, Ok(())),
            (FRAME_GOAWAY, Role::Client, Ok(())),
            (0x21, Role::Client, Ok(())),
        ];
        for (frame_type, role, expected) in cases {
            let mut qp = QpackCtx::new(role);
            let mut data = control_bytes(FRAME_SETTINGS, &our_settings());
            encode_frame(&mut data, frame_type, &[0]);
            assert_eq!(
                qp.on_uni(3, &data, false),
                expected,
                "제어 스트림의 프레임 0x{frame_type:x} ({role:?})"
            );
        }
    }

    #[test]
    /// A server's GOAWAY carries only client-initiated bidirectional stream IDs. Neither frame may
    /// go back on an earlier ID, and content longer or shorter than one value is a frame error.
    fn control_frame_identifiers_follow_rfc_9114() {
        let id = |value: u64| {
            let mut out = Vec::new();
            varint::write(&mut out, value);
            out
        };
        let cases: [(Role, Vec<(u64, Vec<u8>)>, Result<(), H3Error>); 11] = [
            (
                Role::Client,
                vec![
                    (FRAME_GOAWAY, id(8)),
                    (FRAME_GOAWAY, id(8)),
                    (FRAME_GOAWAY, id(4)),
                ],
                Ok(()),
            ),
            (
                Role::Client,
                vec![(FRAME_GOAWAY, id(6))],
                Err(H3Error::IdError),
            ),
            (
                Role::Client,
                vec![(FRAME_GOAWAY, id(4)), (FRAME_GOAWAY, id(8))],
                Err(H3Error::IdError),
            ),
            (
                Role::Server,
                vec![(FRAME_GOAWAY, id(7)), (FRAME_GOAWAY, id(3))],
                Ok(()),
            ),
            (
                Role::Server,
                vec![(FRAME_GOAWAY, id(3)), (FRAME_GOAWAY, id(7))],
                Err(H3Error::IdError),
            ),
            (
                Role::Server,
                vec![
                    (FRAME_MAX_PUSH_ID, id(3)),
                    (FRAME_MAX_PUSH_ID, id(3)),
                    (FRAME_MAX_PUSH_ID, id(9)),
                ],
                Ok(()),
            ),
            (
                Role::Server,
                vec![(FRAME_MAX_PUSH_ID, id(9)), (FRAME_MAX_PUSH_ID, id(3))],
                Err(H3Error::IdError),
            ),
            (
                Role::Client,
                vec![(FRAME_GOAWAY, vec![])],
                Err(H3Error::FrameError),
            ),
            (
                Role::Client,
                vec![(FRAME_GOAWAY, vec![0, 0])],
                Err(H3Error::FrameError),
            ),
            (
                Role::Server,
                vec![(FRAME_MAX_PUSH_ID, vec![0x40])],
                Err(H3Error::FrameError),
            ),
            (
                Role::Server,
                vec![(FRAME_CANCEL_PUSH, vec![0, 0])],
                Err(H3Error::FrameError),
            ),
        ];
        for (role, frames, expected) in cases {
            let mut data = control_bytes(FRAME_SETTINGS, &our_settings());
            for (frame_type, payload) in &frames {
                encode_frame(&mut data, *frame_type, payload);
            }
            let peer_control_stream = match role {
                Role::Client => 3,
                Role::Server => 2,
            };
            assert_eq!(
                QpackCtx::new(role).on_uni(peer_control_stream, &data, false),
                expected,
                "{role:?} 가 받은 제어 프레임 {frames:?}"
            );
        }
    }

    #[test]
    /// A push stream cannot be opened toward a server, and for a client that allows no push its
    /// push ID cannot exist.
    fn uni_stream_errors_carry_their_rfc_codes() {
        let mut push = Vec::new();
        varint::write(&mut push, UNI_PUSH);
        assert_eq!(
            QpackCtx::new(Role::Server).on_uni(2, &push, false),
            Err(H3Error::StreamCreation)
        );
        assert_eq!(
            QpackCtx::new(Role::Client).on_uni(3, &push, false),
            Err(H3Error::IdError)
        );

        let mut bad_encoder = Vec::new();
        varint::write(&mut bad_encoder, UNI_QPACK_ENCODER);
        bad_encoder.push(0x00);
        assert_eq!(
            QpackCtx::new(Role::Server).on_uni(2, &bad_encoder, false),
            Err(H3Error::EncoderStream),
            "없는 항목을 복제하라는 지시"
        );

        let mut bad_decoder = Vec::new();
        varint::write(&mut bad_decoder, UNI_QPACK_DECODER);
        bad_decoder.push(0x00);
        assert_eq!(
            QpackCtx::new(Role::Server).on_uni(2, &bad_decoder, false),
            Err(H3Error::DecoderStream),
            "0 만큼 늘리라는 확인 지시"
        );

        let mut qp = QpackCtx::new(Role::Server);
        let mut unknown = Vec::new();
        varint::write(&mut unknown, 0x21);
        for index in 0..MAX_H3_UNI_STREAMS as u64 {
            assert_eq!(qp.on_uni(index * 4 + 2, &unknown, false), Ok(()));
        }
        assert_eq!(
            qp.on_uni(MAX_H3_UNI_STREAMS as u64 * 4 + 2, &unknown, false),
            Err(H3Error::ExcessiveLoad)
        );

        let mut qp = QpackCtx::new(Role::Server);
        assert_eq!(
            qp.on_uni(2, &vec![0x21; MAX_H3_UNI_BUFFER + 1], false),
            Err(H3Error::ExcessiveLoad)
        );
    }

    #[test]
    /// Bad message content rejects only that message, but RFC 9114 and RFC 9204 make bad frame
    /// layout and undecodable headers connection errors.
    fn message_stream_frame_errors_close_the_connection() {
        let headers = encoded_headers(&[
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", b"dns.example"),
            (b":path", b"/dns-query"),
            (b"content-type", b"application/dns-message"),
        ]);
        let request_with = |frame_type: u64| {
            let mut buf = Vec::new();
            encode_frame(&mut buf, FRAME_HEADERS, &headers);
            encode_frame(&mut buf, frame_type, &[0]);
            buf
        };
        let fatal = |buf: &[u8], role: Role| match role {
            Role::Server => match extract_dns_request(&mut qpack::Decoder::new(4096), 0, buf) {
                Extracted::Fatal(error) => Some(error),
                _ => None,
            },
            Role::Client => match extract_dns_response(&mut qpack::Decoder::new(4096), 0, buf) {
                Extracted::Fatal(error) => Some(error),
                _ => None,
            },
        };

        for frame_type in [
            FRAME_SETTINGS,
            FRAME_CANCEL_PUSH,
            FRAME_GOAWAY,
            FRAME_MAX_PUSH_ID,
            0x02,
            0x06,
            0x08,
            0x09,
        ] {
            for role in [Role::Server, Role::Client] {
                assert_eq!(
                    fatal(&request_with(frame_type), role),
                    Some(H3Error::FrameUnexpected),
                    "메시지 스트림의 프레임 0x{frame_type:x} ({role:?})"
                );
            }
        }
        assert_eq!(
            fatal(&request_with(FRAME_PUSH_PROMISE), Role::Server),
            Some(H3Error::FrameUnexpected),
            "클라이언트는 PUSH_PROMISE 를 보낼 수 없습니다"
        );
        assert_eq!(
            fatal(&request_with(FRAME_PUSH_PROMISE), Role::Client),
            Some(H3Error::IdError),
            "허락하지 않은 푸시입니다"
        );

        let mut data_first = Vec::new();
        encode_frame(&mut data_first, FRAME_DATA, b"dns");
        encode_frame(&mut data_first, FRAME_HEADERS, &headers);
        let mut truncated = Vec::new();
        encode_frame(&mut truncated, FRAME_HEADERS, &headers);
        truncated.pop();
        let mut undecodable = Vec::new();
        encode_frame(&mut undecodable, FRAME_HEADERS, &[0x00, 0x00, 0xff]);
        for role in [Role::Server, Role::Client] {
            assert_eq!(fatal(&data_first, role), Some(H3Error::FrameUnexpected));
            assert_eq!(fatal(&truncated, role), Some(H3Error::FrameError));
            assert_eq!(
                fatal(&undecodable, role),
                Some(H3Error::DecompressionFailed)
            );
        }
    }

    fn outcome<T>(extracted: Extracted<T>) -> String {
        match extracted {
            Extracted::Done(_) => "done".into(),
            Extracted::Blocked => "blocked".into(),
            Extracted::Bad => "bad".into(),
            Extracted::Fatal(error) => format!("{error:?}"),
            Extracted::Refused(status) => String::from_utf8_lossy(status).into_owned(),
        }
    }

    fn message(head: &[u8], rest: &[(u64, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_frame(&mut buf, FRAME_HEADERS, head);
        for (frame_type, payload) in rest {
            encode_frame(&mut buf, *frame_type, payload);
        }
        buf
    }

    #[test]
    /// RFC 9114 allows one trailer section at the end and 1xx interim responses before the final
    /// one; rejecting them breaks conforming peers.
    fn trailers_and_interim_responses_are_accepted() {
        let dns: &[u8] = b"\x12\x34dns";
        let trailer = encoded_headers(&[(b"x-checksum", b"abc")]);

        let request = message(
            &qpack::doh_post_request_headers("h", "/dns-query", dns.len()),
            &[(FRAME_DATA, dns), (FRAME_HEADERS, &trailer)],
        );
        assert!(matches!(
            extract_dns_request(&mut qpack::Decoder::new(4096), 0, &request),
            Extracted::Done(request) if request.wire == dns
        ));

        let response = message(
            &encoded_headers(&[(b":status", b"103"), (b"link", b"</a.css>; rel=preload")]),
            &[
                (
                    FRAME_HEADERS,
                    &encoded_headers(&[
                        (b":status", b"200"),
                        (b"content-type", b"application/dns-message"),
                    ]),
                ),
                (FRAME_DATA, dns),
                (FRAME_HEADERS, &trailer),
            ],
        );
        assert!(matches!(
            extract_dns_response(&mut qpack::Decoder::new(4096), 0, &response),
            Extracted::Done(H3Response::Dns(body)) if body == dns
        ));
    }

    #[test]
    /// HEADERS or DATA after trailers is a frame layout error and closes the connection.
    /// Pseudo-headers or connection-specific fields in trailers, a 101, a body after an interim
    /// response, and a response with no final head are message errors only.
    fn trailer_and_interim_violations_are_rejected() {
        let dns: &[u8] = b"\x12\x34dns";
        let request_head = qpack::doh_post_request_headers("h", "/dns-query", dns.len());
        let final_head = encoded_headers(&[
            (b":status", b"200"),
            (b"content-type", b"application/dns-message"),
        ]);
        let interim_head = encoded_headers(&[(b":status", b"103")]);
        let trailer = encoded_headers(&[(b"x-checksum", b"abc")]);
        let pseudo_trailer = encoded_headers(&[(b":path", b"/other")]);
        let te_trailer = encoded_headers(&[(b"te", b"trailers")]);
        let connection_trailer = encoded_headers(&[(b"connection", b"close")]);
        let request = |rest: &[(u64, &[u8])]| {
            outcome(extract_dns_request(
                &mut qpack::Decoder::new(4096),
                0,
                &message(&request_head, rest),
            ))
        };
        let response = |head: &[u8], rest: &[(u64, &[u8])]| {
            outcome(extract_dns_response(
                &mut qpack::Decoder::new(4096),
                0,
                &message(head, rest),
            ))
        };

        for rest in [
            [
                (FRAME_DATA, dns),
                (FRAME_HEADERS, &trailer[..]),
                (FRAME_DATA, dns),
            ],
            [
                (FRAME_DATA, dns),
                (FRAME_HEADERS, &trailer[..]),
                (FRAME_HEADERS, &trailer[..]),
            ],
        ] {
            assert_eq!(request(&rest), "FrameUnexpected", "요청 트레일러 뒤 프레임");
            assert_eq!(
                response(&final_head, &rest),
                "FrameUnexpected",
                "응답 트레일러 뒤 프레임"
            );
        }
        for bad_trailer in [&pseudo_trailer, &te_trailer, &connection_trailer] {
            let rest = [(FRAME_DATA, dns), (FRAME_HEADERS, &bad_trailer[..])];
            assert_eq!(request(&rest), "bad", "요청 트레일러 내용");
            assert_eq!(response(&final_head, &rest), "bad", "응답 트레일러 내용");
        }

        let switching = encoded_headers(&[(b":status", b"101")]);
        assert_eq!(
            response(
                &switching,
                &[(FRAME_HEADERS, &final_head), (FRAME_DATA, dns)]
            ),
            "bad",
            "HTTP/3 에는 101 응답이 없습니다"
        );
        assert_eq!(
            response(
                &interim_head,
                &[(FRAME_DATA, dns), (FRAME_HEADERS, &final_head)]
            ),
            "bad",
            "중간 응답에는 본문이 없습니다"
        );
        assert_eq!(
            response(&interim_head, &[]),
            "bad",
            "최종 응답 없이 끝난 응답입니다"
        );
    }

    #[test]
    /// Interim responses are skipped and an incomplete last frame is ignored. The status is unknown
    /// when the final headers are missing or wait on the table; format errors match those of a
    /// complete response.
    fn oversized_response_reports_its_final_status() {
        let status = |received: Vec<u8>| {
            oversized_response_status(&mut qpack::Decoder::new(4096), 0, received)
        };
        let unfinished = |mut received: Vec<u8>| {
            received.pop();
            received
        };
        let interim = encoded_headers(&[(b":status", b"103")]);
        let not_found = encoded_headers(&[(b":status", b"404"), (b"content-type", b"text/html")]);
        let dns = encoded_headers(&[
            (b":status", b"200"),
            (b"content-type", b"application/dns-message"),
        ]);

        assert_eq!(
            status(unfinished(message(
                &interim,
                &[(FRAME_HEADERS, &not_found), (FRAME_DATA, b"page")]
            ))),
            Ok(Some(404))
        );
        assert_eq!(
            status(unfinished(message(&dns, &[(FRAME_DATA, b"\x12\x34dns")]))),
            Ok(Some(200))
        );
        assert_eq!(
            status(unfinished(message(&not_found, &[]))),
            Ok(None),
            "덜 온 최종 응답 헤더"
        );
        assert_eq!(
            status(message(&interim, &[])),
            Ok(None),
            "중간 응답뿐인 앞부분"
        );
        assert_eq!(
            status(message(&interim, &[(FRAME_DATA, b"page")])),
            Err(H3Error::Message),
            "중간 응답 뒤의 본문"
        );
        let mut data_first = Vec::new();
        encode_frame(&mut data_first, FRAME_DATA, b"page");
        assert_eq!(
            status(data_first),
            Err(H3Error::FrameUnexpected),
            "헤더보다 앞선 본문"
        );

        let mut encoder = qpack::Encoder::new();
        encoder.set_peer_max_capacity(QPACK_CAPACITY as usize);
        let page_head: [(&[u8], &[u8]); 2] = [(b":status", b"404"), (b"x-page", b"1")];
        let _ = encoder.encode_field_section(&page_head);
        // Fakes an acknowledgment so the encoder references an entry the decoder has not received.
        encoder.on_decoder_stream(&[0x01]).unwrap();
        let (blocked_head, _) = encoder.encode_field_section(&page_head);
        assert_eq!(
            status(message(&blocked_head, &[(FRAME_DATA, b"page")])),
            Ok(None),
            "테이블을 기다리는 최종 응답 헤더"
        );
    }

    /// The header section decodes at once; only the trailer section waits on the table. Returns the
    /// decoder, the message, and the table update the trailer waits for.
    fn message_with_blocked_trailer(head: &[(&[u8], &[u8])]) -> (qpack::Decoder, Vec<u8>, Vec<u8>) {
        let mut encoder = qpack::Encoder::new();
        encoder.set_peer_max_capacity(QPACK_CAPACITY as usize);
        let mut decoder = qpack::Decoder::new(QPACK_CAPACITY as usize);

        // The header section must reference a dynamic entry to produce its own acknowledgment.
        let (_, inserts) = encoder.encode_field_section(&[(b"x-head", b"1")]);
        decoder.on_encoder_stream(&inserts).unwrap();
        encoder
            .on_decoder_stream(&decoder.take_decoder_stream())
            .unwrap();
        let mut head = head.to_vec();
        head.push((b"x-head", b"1"));
        let (head_section, inserts) = encoder.encode_field_section(&head);
        decoder.on_encoder_stream(&inserts).unwrap();
        encoder
            .on_decoder_stream(&decoder.take_decoder_stream())
            .unwrap();

        // Fakes an acknowledgment so the encoder references an entry the decoder has not received.
        let trailer: [(&[u8], &[u8]); 1] = [(b"x-trailer", b"t")];
        let (_, pending_inserts) = encoder.encode_field_section(&trailer);
        encoder.on_decoder_stream(&[0x01]).unwrap();
        let (trailer_section, _) = encoder.encode_field_section(&trailer);

        let bytes = message(
            &head_section,
            &[
                (FRAME_DATA, b"\x12\x34dns"),
                (FRAME_HEADERS, &trailer_section),
            ],
        );
        (decoder, bytes, pending_inserts)
    }

    #[test]
    /// Decoding the header section and retrying after the wait would acknowledge it twice; RFC 9204
    /// makes an acknowledgment for a stream with no unacknowledged sections
    /// QPACK_DECODER_STREAM_ERROR.
    fn blocked_trailer_holds_every_section_acknowledgment() {
        let request_head: [(&[u8], &[u8]); 5] = [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", b"dns.test"),
            (b":path", b"/dns-query"),
            (b"content-type", b"application/dns-message"),
        ];
        let response_head: [(&[u8], &[u8]); 2] = [
            (b":status", b"200"),
            (b"content-type", b"application/dns-message"),
        ];
        for (role, head) in [
            (Role::Server, &request_head[..]),
            (Role::Client, &response_head[..]),
        ] {
            let (mut decoder, bytes, pending_inserts) = message_with_blocked_trailer(head);
            let extract = |decoder: &mut qpack::Decoder| match role {
                Role::Server => outcome(extract_dns_request(decoder, 0, &bytes)),
                Role::Client => outcome(extract_dns_response(decoder, 0, &bytes)),
            };
            assert_eq!(extract(&mut decoder), "blocked", "{role:?}");
            assert!(
                decoder.take_decoder_stream().is_empty(),
                "기다리는 동안 확인 지시를 내보냈습니다 ({role:?})"
            );

            decoder.on_encoder_stream(&pending_inserts).unwrap();
            assert_eq!(
                decoder.take_decoder_stream(),
                vec![0x01],
                "항목 수 증가 지시"
            );
            assert_eq!(extract(&mut decoder), "done", "{role:?}");
            assert_eq!(
                decoder.take_decoder_stream(),
                vec![0x80, 0x80],
                "두 구역에 확인 지시가 하나씩 나가야 합니다 ({role:?})"
            );
        }
    }

    #[test]
    /// RFC 9204 makes exceeding SETTINGS_QPACK_BLOCKED_STREAMS QPACK_DECOMPRESSION_FAILED;
    /// exceeding the buffer limit is this side's resource issue.
    fn blocked_messages_respect_the_advertised_limit() {
        let mut blocked = Vec::new();
        for id in 0..QPACK_BLOCKED {
            assert_eq!(hold_blocked(&mut blocked, 0, id * 4, vec![0]), Ok(()));
        }
        assert_eq!(
            hold_blocked(&mut blocked, 0, QPACK_BLOCKED * 4, vec![0]),
            Err(H3Error::DecompressionFailed.into())
        );
        assert_eq!(
            hold_blocked(&mut Vec::new(), MAX_H3_CONNECTION_BUFFER, 0, vec![0]),
            Err(H3Error::ExcessiveLoad.into())
        );
    }

    #[test]
    fn settings_advertise_the_decoder_field_section_limit() {
        assert!(parse_settings(&our_settings())
            .unwrap()
            .contains(&(SETTINGS_MAX_FIELD_SECTION_SIZE, MAX_H3_FIELD_SECTION)));
    }

    #[test]
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
        assert_eq!(
            client.take_responses(),
            vec![(sid1, H3Response::Dns(b"\x00\x00 answer-1".to_vec()))]
        );

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
        assert_eq!(
            client.take_responses(),
            vec![(sid2, H3Response::Dns(b"\x00\x00 answer-2".to_vec()))]
        );
    }

    #[test]
    /// Inserting before the peer announces a table capacity would send instructions it cannot hold.
    /// The server sends settings as soon as 1-RTT keys exist, so requests queued before the
    /// handshake set this up.
    fn h3_request_before_settings_is_static_only() {
        let (mut client, mut server) = h3_pair();
        let dns = b"\x00\x00 early static query";
        client.send_request("h.example", "/dns-query", dns).unwrap();
        assert_eq!(client.qpack_insert_count(), 0);

        pump_h3(&mut client, &mut server);
        let reqs = server.take_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].1, dns);
    }

    #[test]
    /// A client that remembers the previous connection's settings inserts into the dynamic table in
    /// 0-RTT. If the server opened the acknowledgment stream only after the handshake, the
    /// acknowledgments would have nowhere to go and the connection would fail.
    fn zero_rtt_qpack_inserts_are_acknowledged_before_the_handshake_ends() {
        let mut res = onetdns_tls::conn::ServerResumption::secure_default();
        res.max_early_data = 0xffff_ffff;
        let (mut c1, mut s1) = h3_pair_with(Some(res.clone()), None);
        pump_h3(&mut c1, &mut s1);
        c1.send_request("dns.example", "/dns-query", b"\x00\x00 warmup")
            .unwrap();
        pump_h3(&mut c1, &mut s1);
        let session = c1
            .conn_mut()
            .take_new_sessions()
            .into_iter()
            .next()
            .expect("세션 티켓");

        let (mut c2, mut s2) = h3_pair_with(Some(res), Some(session));
        c2.qp.enc.set_peer_max_capacity(QPACK_CAPACITY as usize);
        let dns = b"\x00\x00 zero-rtt dynamic query";
        let sid = c2.send_request("dns.example", "/dns-query", dns).unwrap();
        assert!(c2.can_send_early());
        assert!(
            c2.qpack_insert_count() > 0,
            "기억한 설정으로 동적 테이블에 넣어야 합니다"
        );

        while let Some(dg) = c2.next_datagram() {
            s2.recv_datagram(&dg).unwrap();
        }
        assert!(!s2.is_handshake_complete(), "클라이언트 Finished 전");
        let reqs = s2.take_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].1, dns);

        while let Some(dg) = s2.next_datagram() {
            c2.recv_datagram(&dg).unwrap();
        }
        assert!(!s2.is_handshake_complete());
        assert!(c2.conn_mut().early_data_accepted());
        assert_eq!(
            c2.qpack_known_received(),
            c2.qpack_insert_count(),
            "서버의 첫 응답에 확인 지시가 실려야 합니다"
        );

        pump_h3(&mut c2, &mut s2);
        s2.send_response(sid, b"\x00\x00 answer", 0).unwrap();
        pump_h3(&mut c2, &mut s2);
        assert_eq!(
            c2.take_responses(),
            vec![(sid, H3Response::Dns(b"\x00\x00 answer".to_vec()))]
        );
    }

    #[test]
    /// A full send buffer can stall stream setup midway; an acknowledgment sent in that gap would
    /// be read as the stream type.
    fn decoder_instructions_wait_for_their_stream_type() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);
        server.qp.dec_sent = false;
        server.qp.dec.restore_decoder_stream(vec![0x01]);

        assert_eq!(server.qp.flush_decoder_stream(&mut server.conn), Ok(()));
        assert_eq!(server.qp.dec.take_decoder_stream(), vec![0x01]);
    }

    #[test]
    /// When the peer's close arrives in the same packet as a request, the QUIC layer keeps the
    /// request and closes. Closing ends every stream, so the request cannot be answered, and taking
    /// it would waste a worker. A packet during the closing period gets only the close frame again.
    fn closed_connection_leaves_pending_requests_alone() {
        let (mut client, mut server) = h3_pair();
        pump_h3(&mut client, &mut server);
        client
            .send_request("dns.example", "/dns-query", b"\x00\x00 pending")
            .unwrap();
        while let Some(dg) = client.next_datagram() {
            server.conn_mut().recv_datagram(&dg).unwrap();
        }
        server.conn_mut().close(H3Error::Internal.code(), "");
        while server.next_datagram().is_some() {}

        client
            .send_request("dns.example", "/dns-query", b"\x00\x00 late")
            .unwrap();
        while let Some(dg) = client.next_datagram() {
            assert_eq!(server.recv_datagram(&dg), Ok(()));
        }
        assert!(server.take_requests().is_empty());
        assert!(
            server.next_datagram().is_some(),
            "closing 기간에는 늦게 온 패킷에 종료 프레임으로 답해야 합니다"
        );
    }

    #[test]
    /// HTTP/3 errors keep their code, a full send buffer is H3_EXCESSIVE_LOAD, and anything else is
    /// internal.
    fn stream_processing_failures_close_with_matching_codes() {
        for (error, expected) in [
            (QuicError::FlowControl, H3Error::ExcessiveLoad),
            (QuicError::StreamLimit, H3Error::Internal),
            (H3Error::FrameError.into(), H3Error::FrameError),
        ] {
            let (mut client, mut server) = h3_pair();
            pump_h3(&mut client, &mut server);
            assert_eq!(
                close_on_stream_error(server.conn_mut(), error),
                expected.into()
            );
            while let Some(dg) = server.next_datagram() {
                client.conn_mut().recv_datagram(&dg).unwrap();
            }
            assert_eq!(
                client.conn_mut().peer_close().map(|close| close.error_code),
                Some(expected.code())
            );
        }
    }

    #[test]
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
        assert_eq!(
            c2.take_responses(),
            vec![(sid2, H3Response::Dns(b"\x00\x00 zr-resp".to_vec()))]
        );
    }

    #[test]
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
