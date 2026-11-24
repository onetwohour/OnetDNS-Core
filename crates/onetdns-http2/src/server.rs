use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::frame::{self, error_code, flags, frame_type, settings, DEFAULT_MAX_FRAME};
use crate::hpack::{self, Decoder};
use crate::wire::{read_exact, read_frame, send_frame, strip_headers, strip_padding};
use crate::{valid_header_field, H2Error};

struct StreamState {
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
    have_headers: bool,
    end_stream: bool,
    /// Receive window left on this stream; consumed bytes are returned with WINDOW_UPDATE.
    recv_window: i64,
}

impl Default for StreamState {
    fn default() -> Self {
        Self {
            headers: Vec::new(),
            body: Vec::new(),
            have_headers: false,
            end_stream: false,
            recv_window: INITIAL_WINDOW,
        }
    }
}

/// Response body the peer's flow-control window has not let through yet; the rest goes out when the
/// window opens.
struct PendingBody {
    body: Vec<u8>,
    /// Bytes of `body` already sent.
    offset: usize,
}

enum AppResponse {
    Status(&'static str),
    Dns(DohAnswer),
    Http(HttpReply),
    /// No answer for this request alone: HTTP/2 resets its stream and keeps the connection.
    Reset,
}

/// A response that is not a DNS answer: status, fields after it, and body.
struct HttpReply {
    status: String,
    fields: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

impl HttpReply {
    /// RFC 9230: ODoH requests and responses must not be cached.
    fn oblivious_message(body: Vec<u8>) -> Self {
        Self {
            status: "200".to_string(),
            fields: vec![
                ("content-type", ODOH_MEDIA_TYPE.to_string()),
                ("cache-control", "no-cache, no-store".to_string()),
            ],
            body,
        }
    }

    fn odoh_configs(body: Vec<u8>) -> Self {
        Self {
            status: "200".to_string(),
            fields: vec![("content-type", "application/octet-stream".to_string())],
            body,
        }
    }

    /// A status the proxy sends for the target, with an RFC 9209 Proxy-Status naming this proxy.
    fn proxy_status(status: String, parameter: String) -> Self {
        Self {
            status,
            fields: vec![("proxy-status", format!("OnetDNS; {parameter}"))],
            body: Vec::new(),
        }
    }

    /// RFC 9458 allows only fields that say nothing about the encapsulated response.
    fn ohttp_response(body: Vec<u8>) -> Self {
        Self {
            status: "200".to_string(),
            fields: vec![
                ("content-type", OHTTP_RESPONSE_MEDIA_TYPE.to_string()),
                ("cache-control", "private, no-store".to_string()),
            ],
            body,
        }
    }

    fn ohttp_keys(body: Vec<u8>) -> Self {
        Self {
            status: "200".to_string(),
            fields: vec![("content-type", OHTTP_KEYS_MEDIA_TYPE.to_string())],
            body,
        }
    }
}

pub const ODOH_MEDIA_TYPE: &str = "application/oblivious-dns-message";

/// Where an Oblivious DoH target publishes its ObliviousDoHConfigs.
pub const ODOH_CONFIGS_PATH: &str = "/.well-known/odohconfigs";

/// The largest ObliviousDoHMessage: a type byte and two fields with 16-bit lengths.
pub const MAX_ODOH_MESSAGE: usize = 1 + 2 * (2 + u16::MAX as usize);

/// Oblivious DoH (RFC 9230) on a DoH listener. This crate only routes requests by media type, path
/// and the proxy variables; the implementor opens, resolves, seals and relays.
pub trait Oblivious {
    /// The ObliviousDoHConfigs served at `ODOH_CONFIGS_PATH`; `None` when this listener is not a
    /// target.
    fn configs(&self) -> Option<Vec<u8>>;

    /// An ObliviousDoHMessage POSTed to the DoH path for this server to answer.
    fn target(&self, message: &[u8]) -> ObliviousReply;

    /// An ObliviousDoHMessage to relay to the target the `targethost` and `targetpath` variables
    /// name, both percent-decoded.
    fn proxy(&self, target_host: &str, target_path: &str, message: &[u8]) -> ObliviousReply;
}

pub enum ObliviousReply {
    /// A 200 carrying this ObliviousDoHMessage.
    Message(Vec<u8>),
    Status(&'static str),
    /// No response; the connection closes, as for a DNS query the handler does not answer.
    Drop,
    /// No response to this message alone. A proxy carries other clients' messages on the same
    /// connection, so closing it would drop theirs too.
    Unanswered,
    /// The target's non-200 status, passed on with Proxy-Status `received-status`.
    TargetStatus(u16),
    /// The proxy relayed nothing back: this status, and the Proxy-Status error type saying why.
    ProxyError {
        status: &'static str,
        error: &'static str,
    },
}

/// RFC 9540's Oblivious Gateway Resource: POST takes encapsulated requests, GET returns the key
/// configuration.
pub const OHTTP_GATEWAY_PATH: &str = "/.well-known/ohttp-gateway";
pub const OHTTP_REQUEST_MEDIA_TYPE: &str = "message/ohttp-req";
pub const OHTTP_RESPONSE_MEDIA_TYPE: &str = "message/ohttp-res";
pub const OHTTP_KEYS_MEDIA_TYPE: &str = "application/ohttp-keys";

/// An Oblivious HTTP gateway (RFC 9458) in front of this listener's DoH path. This crate routes the
/// requests; the implementor decapsulates, answers and encapsulates.
pub trait Gateway {
    /// The `application/ohttp-keys` body served by GET at `OHTTP_GATEWAY_PATH`.
    fn keys(&self) -> Vec<u8>;

    /// An Encapsulated Request POSTed to `OHTTP_GATEWAY_PATH`.
    fn answer(&self, encapsulated: &[u8]) -> GatewayReply;
}

pub enum GatewayReply {
    /// A 200 carrying this Encapsulated Response.
    Response(Vec<u8>),
    /// An error found before the request could be decapsulated, so it cannot be encapsulated
    /// either.
    Status(&'static str),
    /// No response to this request alone. A relay carries other clients' requests on the same
    /// connection, so closing it would drop theirs too.
    Unanswered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Media {
    Dns,
    Oblivious,
    OhttpRequest,
    Other,
}

impl Media {
    pub(crate) fn of(content_type: &[u8]) -> Self {
        if content_type.eq_ignore_ascii_case(b"application/dns-message") {
            Media::Dns
        } else if content_type.eq_ignore_ascii_case(ODOH_MEDIA_TYPE.as_bytes()) {
            Media::Oblivious
        } else if content_type.eq_ignore_ascii_case(OHTTP_REQUEST_MEDIA_TYPE.as_bytes()) {
            Media::OhttpRequest
        } else {
            Media::Other
        }
    }
}

enum Route {
    Doh,
    Respond(AppResponse),
    /// Send nothing and close the connection.
    Drop,
}

/// Routes the Oblivious DoH requests; everything else stays DoH. `oblivious_body` is the body of a
/// POST whose content type is the ODoH one.
fn route_oblivious(
    method: &[u8],
    path: &[u8],
    oblivious_body: Option<&[u8]>,
    expected_path: &str,
    oblivious: Option<&dyn Oblivious>,
) -> Route {
    let path_only = path.split(|&b| b == b'?').next().unwrap_or(b"");
    if method == b"GET" && path_only == ODOH_CONFIGS_PATH.as_bytes() {
        return match oblivious.and_then(Oblivious::configs) {
            Some(configs) => Route::Respond(AppResponse::Http(HttpReply::odoh_configs(configs))),
            None => Route::Respond(AppResponse::Status("404")),
        };
    }
    let Some(body) = oblivious_body else {
        return Route::Doh;
    };
    let Some(oblivious) = oblivious else {
        return Route::Respond(AppResponse::Status(STATUS_UNSUPPORTED_MEDIA_TYPE));
    };
    // Path segments after the DoH path name a client, which means nothing for a message the proxy
    // relayed.
    if path_only != expected_path.as_bytes() {
        return Route::Respond(AppResponse::Status("404"));
    }
    if body.is_empty() {
        return Route::Respond(AppResponse::Status(STATUS_BAD_REQUEST));
    }
    let reply = match proxy_target(path) {
        Ok(None) => oblivious.target(body),
        Ok(Some((host, target_path))) => oblivious.proxy(&host, &target_path, body),
        Err(()) => ObliviousReply::ProxyError {
            status: STATUS_BAD_REQUEST,
            error: "http_request_error",
        },
    };
    let response = match reply {
        ObliviousReply::Message(message) if message.len() <= MAX_ODOH_MESSAGE => {
            AppResponse::Http(HttpReply::oblivious_message(message))
        }
        ObliviousReply::Message(_) => AppResponse::Status(STATUS_BAD_GATEWAY),
        ObliviousReply::Status(status) => AppResponse::Status(status),
        ObliviousReply::Drop => return Route::Drop,
        ObliviousReply::Unanswered => AppResponse::Reset,
        ObliviousReply::TargetStatus(status) => AppResponse::Http(HttpReply::proxy_status(
            status.to_string(),
            format!("received-status={status}"),
        )),
        ObliviousReply::ProxyError { status, error } => AppResponse::Http(HttpReply::proxy_status(
            status.to_string(),
            format!("error={error}"),
        )),
    };
    Route::Respond(response)
}

/// Routes the Oblivious HTTP gateway; `None` leaves the request to the other routes. `ohttp_body` is
/// the body of a POST whose content type is `message/ohttp-req`.
fn route_gateway(
    method: &[u8],
    path: &[u8],
    ohttp_body: Option<&[u8]>,
    gateway: Option<&dyn Gateway>,
) -> Option<AppResponse> {
    let at_gateway = path.split(|&b| b == b'?').next() == Some(OHTTP_GATEWAY_PATH.as_bytes());
    if method == b"GET" && at_gateway {
        return Some(match gateway {
            Some(gateway) => AppResponse::Http(HttpReply::ohttp_keys(gateway.keys())),
            None => AppResponse::Status("404"),
        });
    }
    let body = ohttp_body?;
    let Some(gateway) = gateway else {
        return Some(AppResponse::Status(STATUS_UNSUPPORTED_MEDIA_TYPE));
    };
    if !at_gateway {
        return Some(AppResponse::Status("404"));
    }
    if body.is_empty() {
        return Some(AppResponse::Status(STATUS_BAD_REQUEST));
    }
    Some(match gateway.answer(body) {
        GatewayReply::Response(response) => AppResponse::Http(HttpReply::ohttp_response(response)),
        GatewayReply::Status(status) => AppResponse::Status(status),
        GatewayReply::Unanswered => AppResponse::Reset,
    })
}

/// The `targethost` and `targetpath` variables of a proxy request, percent-decoded. `Ok(None)`
/// when neither is there. Each must appear once, decode to printable ASCII, and the path must
/// start with `/`; anything else is a malformed proxy request.
fn proxy_target(path: &[u8]) -> Result<Option<(String, String)>, ()> {
    let Some(query) = path.splitn(2, |&b| b == b'?').nth(1) else {
        return Ok(None);
    };
    let mut host = None;
    let mut target_path = None;
    for pair in query.split(|&b| b == b'&') {
        let (name, value) = match pair.iter().position(|&b| b == b'=') {
            Some(index) => (&pair[..index], &pair[index + 1..]),
            None => (pair, &[][..]),
        };
        let slot = match name {
            b"targethost" => &mut host,
            b"targetpath" => &mut target_path,
            _ => continue,
        };
        if slot.replace(percent_decode(value)?).is_some() {
            return Err(());
        }
    }
    match (host, target_path) {
        (None, None) => Ok(None),
        (Some(host), Some(path)) if !host.is_empty() && path.starts_with('/') => {
            Ok(Some((host, path)))
        }
        _ => Err(()),
    }
}

fn percent_decode(raw: &[u8]) -> Result<String, ()> {
    let mut out = Vec::with_capacity(raw.len());
    let mut rest = raw;
    while let Some((&byte, tail)) = rest.split_first() {
        if byte == b'%' {
            let [high, low, ..] = *tail else {
                return Err(());
            };
            let digit = |c: u8| (c as char).to_digit(16).ok_or(());
            out.push((digit(high)? * 16 + digit(low)?) as u8);
            rest = &tail[2..];
        } else {
            out.push(byte);
            rest = tail;
        }
    }
    if !out.iter().all(|byte| byte.is_ascii_graphic()) {
        return Err(());
    }
    String::from_utf8(out).map_err(|_| ())
}

/// DoH response body and its HTTP freshness lifetime. This layer does not parse DNS, so whoever
/// built the response measures the lifetime; RFC 8484 caps it at the minimum TTL of the answer
/// section.
pub struct DohAnswer {
    pub body: Vec<u8>,
    /// Cache-Control max-age, in seconds.
    pub max_age: u32,
}

const MAX_H2_STREAMS: usize = 128;

/// DoH queries are far smaller.
const MAX_H2_BODY: usize = 64 * 1024;

/// The largest DNS message.
pub(crate) const MAX_H2_RESPONSE: usize = u16::MAX as usize;

const MAX_H2_HEADER_BLOCK: usize = 32 * 1024;

/// Header bytes buffered across the whole connection. A per-stream cap is not enough: many streams
/// each filling a little would grow without bound.
const MAX_H2_BUFFERED_HEADERS: usize = 1024 * 1024;

const MAX_H2_BUFFERED_REQUESTS: usize = 1024 * 1024;

/// Unsent response bytes across the connection; stops a client that never opens its window.
const MAX_H2_BUFFERED_RESPONSES: usize = 1024 * 1024;

/// Length cap of the client ID taken from the path.
const MAX_CLIENT_ID: usize = 256;

const INITIAL_WINDOW: i64 = 65_535;

/// Exceeding it is FLOW_CONTROL_ERROR.
const MAX_WINDOW: i64 = 0x7fff_ffff;
/// The highest stream ID, named by the GOAWAY that announces a shutdown before the last stream is
/// known.
const MAX_STREAM_ID: u32 = 0x7fff_ffff;
/// Sent with that GOAWAY. Its acknowledgement comes after every stream the client opened before it
/// read the GOAWAY.
const DRAIN_PING: [u8; 8] = *b"draining";

/// Open streams: those still receiving plus those with a response pending.
fn concurrent_streams(
    streams: &HashMap<u32, StreamState>,
    pending: &HashMap<u32, PendingBody>,
) -> usize {
    streams.len().saturating_add(pending.len())
}

/// Serves one DoH connection over HTTP/2. Path segments under `expected_path` become the client ID.
///
/// `handler` turns the query wire and client ID into a response. `None` means no answer: the
/// connection closes without sending anything, since a 5xx would make the client resend the query.
pub fn serve_doh<S, H>(stream: &mut S, expected_path: &str, handler: H) -> Result<(), H2Error>
where
    S: Read + Write,
    H: Fn(&[u8], Option<&str>) -> Result<Option<DohAnswer>, &'static str>,
{
    serve_doh_with_deadline_reset(
        stream,
        expected_path,
        handler,
        |_| {},
        &AtomicBool::new(false),
        None,
        None,
    )
}

/// Calls `reset_deadline` after each complete request, so idle connections time out while busy ones
/// stay open.
///
/// Once `draining` is set, the next frame boundary starts the graceful shutdown of RFC 9113: a
/// GOAWAY naming the highest stream ID and a PING. Streams the client opened before it read that
/// GOAWAY arrive before the PING acknowledgement, and are taken. The acknowledgement brings a second
/// GOAWAY naming the last stream taken; later streams are refused, and the connection closes when
/// the streams it took are answered. A read that fails while draining, which is how an idle
/// connection ends then, sends that second GOAWAY first, so the client knows which requests were
/// not processed and can send them elsewhere.
///
/// Without `oblivious` or `gateway`, Oblivious DoH or Oblivious HTTP requests get the status of any
/// unsupported media type.
pub fn serve_doh_with_deadline_reset<S, H, R>(
    stream: &mut S,
    expected_path: &str,
    handler: H,
    mut reset_deadline: R,
    draining: &AtomicBool,
    oblivious: Option<&dyn Oblivious>,
    gateway: Option<&dyn Gateway>,
) -> Result<(), H2Error>
where
    S: Read + Write,
    H: Fn(&[u8], Option<&str>) -> Result<Option<DohAnswer>, &'static str>,
    R: FnMut(&mut S),
{
    reset_deadline(stream);
    let mut pf = [0u8; 24];
    read_exact(stream, &mut pf)?;
    if pf != frame::PREFACE {
        return Err(H2Error::Protocol);
    }

    let mut settings_payload = Vec::with_capacity(18);
    settings_payload.extend_from_slice(&settings::MAX_CONCURRENT_STREAMS.to_be_bytes());
    settings_payload.extend_from_slice(&(MAX_H2_STREAMS as u32).to_be_bytes());
    settings_payload.extend_from_slice(&settings::MAX_HEADER_LIST_SIZE.to_be_bytes());
    settings_payload.extend_from_slice(&(MAX_H2_HEADER_BLOCK as u32).to_be_bytes());
    settings_payload.extend_from_slice(&settings::ENABLE_PUSH.to_be_bytes());
    settings_payload.extend_from_slice(&0u32.to_be_bytes());
    send_frame(stream, frame_type::SETTINGS, 0, 0, &settings_payload)?;

    let mut dec = Decoder::new(4096);
    let mut streams: HashMap<u32, StreamState> = HashMap::new();
    let mut cont_block: Vec<u8> = Vec::new();
    let mut cont_stream: Option<u32> = None;
    let mut last_client_stream = 0u32;
    let mut peer_settings_seen = false;

    let mut recv_conn_window = INITIAL_WINDOW;
    let mut send_conn_window = INITIAL_WINDOW;
    let mut peer_initial_window = INITIAL_WINDOW;
    let mut peer_max_frame = DEFAULT_MAX_FRAME;
    let mut send_stream_windows: HashMap<u32, i64> = HashMap::new();
    let mut pending: HashMap<u32, PendingBody> = HashMap::new();
    let mut shutdown_announced = false;
    // The GOAWAY naming the last stream taken.
    let mut goaway_sent = false;

    loop {
        flush_pending(
            stream,
            &mut pending,
            &mut send_stream_windows,
            &mut send_conn_window,
            peer_max_frame,
        )?;

        if !shutdown_announced && draining.load(Ordering::Relaxed) {
            send_goaway(stream, MAX_STREAM_ID, error_code::NO_ERROR)?;
            send_frame(stream, frame_type::PING, 0, 0, &DRAIN_PING)?;
            shutdown_announced = true;
        }
        if goaway_sent && streams.is_empty() && pending.is_empty() && cont_stream.is_none() {
            return Ok(());
        }

        let (h, payload) = match read_frame(stream) {
            Ok(v) => v,
            Err(H2Error::Closed) => return Ok(()),
            Err(H2Error::Io) if draining.load(Ordering::Relaxed) => {
                if !goaway_sent {
                    let _ = send_goaway(stream, last_client_stream, error_code::NO_ERROR);
                }
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        if !peer_settings_seen {
            if h.frame_type != frame_type::SETTINGS || h.has_flag(flags::ACK) {
                return Err(H2Error::Protocol);
            }
            peer_settings_seen = true;
        }
        if cont_stream.is_some()
            && !(h.frame_type == frame_type::CONTINUATION && cont_stream == Some(h.stream_id))
        {
            return Err(H2Error::Protocol);
        }
        match h.frame_type {
            frame_type::SETTINGS if !h.has_flag(flags::ACK) => {
                if h.stream_id != 0 || payload.len() % 6 != 0 {
                    return Err(H2Error::Protocol);
                }
                for setting in payload.chunks_exact(6) {
                    let id = u16::from_be_bytes([setting[0], setting[1]]);
                    let value =
                        u32::from_be_bytes([setting[2], setting[3], setting[4], setting[5]]);
                    match id {
                        settings::ENABLE_PUSH if value > 1 => return Err(H2Error::Protocol),
                        settings::INITIAL_WINDOW_SIZE => {
                            if value > MAX_WINDOW as u32 {
                                return Err(H2Error::Protocol);
                            }
                            let next = i64::from(value);
                            let delta = next - peer_initial_window;
                            for window in send_stream_windows.values_mut() {
                                *window = window.checked_add(delta).ok_or(H2Error::Protocol)?;
                                if *window > MAX_WINDOW {
                                    return Err(H2Error::Protocol);
                                }
                            }
                            peer_initial_window = next;
                        }
                        settings::MAX_FRAME_SIZE => {
                            if !(16_384..=16_777_215).contains(&value) {
                                return Err(H2Error::Protocol);
                            }
                            peer_max_frame = value as usize;
                        }

                        settings::HEADER_TABLE_SIZE
                        | settings::MAX_CONCURRENT_STREAMS
                        | settings::MAX_HEADER_LIST_SIZE => {}
                        _ => {}
                    }
                }
                send_frame(stream, frame_type::SETTINGS, flags::ACK, 0, &[])?;
            }
            frame_type::SETTINGS if (h.stream_id != 0 || !payload.is_empty()) => {
                return Err(H2Error::Protocol);
            }
            frame_type::PING if !h.has_flag(flags::ACK) => {
                if h.stream_id != 0 || payload.len() != 8 {
                    return Err(H2Error::Protocol);
                }
                send_frame(stream, frame_type::PING, flags::ACK, 0, &payload)?;
            }
            frame_type::PING if (h.stream_id != 0 || payload.len() != 8) => {
                return Err(H2Error::Protocol);
            }
            frame_type::PING if shutdown_announced && !goaway_sent && payload == DRAIN_PING => {
                send_goaway(stream, last_client_stream, error_code::NO_ERROR)?;
                goaway_sent = true;
            }
            frame_type::GOAWAY => {
                if h.stream_id != 0 || payload.len() < 8 {
                    return Err(H2Error::Protocol);
                }
                return Ok(());
            }
            frame_type::RST_STREAM => {
                if h.stream_id == 0 || payload.len() != 4 {
                    return Err(H2Error::Protocol);
                }
                streams.remove(&h.stream_id);
                pending.remove(&h.stream_id);
                send_stream_windows.remove(&h.stream_id);
                if cont_stream == Some(h.stream_id) {
                    cont_stream = None;
                    cont_block.clear();
                }
            }
            frame_type::WINDOW_UPDATE => {
                if payload.len() != 4 {
                    return Err(H2Error::Protocol);
                }
                let increment = u32::from_be_bytes(payload[..4].try_into().unwrap()) & 0x7fff_ffff;
                if increment == 0 {
                    return Err(H2Error::Protocol);
                }
                if h.stream_id == 0 {
                    send_conn_window = add_window(send_conn_window, increment)?;
                } else if let Some(window) = send_stream_windows.get_mut(&h.stream_id) {
                    *window = add_window(*window, increment)?;
                }
            }
            frame_type::PRIORITY if (h.stream_id == 0 || payload.len() != 5) => {
                return Err(H2Error::Protocol);
            }
            frame_type::PUSH_PROMISE => return Err(H2Error::Protocol),
            frame_type::HEADERS => {
                if h.stream_id == 0 || h.stream_id & 1 == 0 || h.stream_id <= last_client_stream {
                    return Err(H2Error::Protocol);
                }
                last_client_stream = h.stream_id;
                if goaway_sent || concurrent_streams(&streams, &pending) >= MAX_H2_STREAMS {
                    // Decoded all the same: HPACK state belongs to the connection. A block that
                    // continues is collected for a stream that is not kept, then dropped.
                    let block = strip_headers(&payload, h.flags)?;
                    if h.has_flag(flags::END_HEADERS) {
                        dec.decode(block).ok_or(H2Error::Protocol)?;
                    } else {
                        cont_block = block.to_vec();
                        cont_stream = Some(h.stream_id);
                    }
                    send_rst_stream(stream, h.stream_id, error_code::REFUSED_STREAM)?;
                    continue;
                }
                let block = strip_headers(&payload, h.flags)?;
                if block.len() > MAX_H2_HEADER_BLOCK {
                    return undecoded_header_block(stream, last_client_stream);
                }

                reset_deadline(stream);
                send_stream_windows.insert(h.stream_id, peer_initial_window);
                streams.entry(h.stream_id).or_default().end_stream = h.has_flag(flags::END_STREAM);
                if h.has_flag(flags::END_HEADERS) {
                    let headers = dec.decode(block).ok_or(H2Error::Protocol)?;
                    let header_size = header_list_size(&headers);
                    let buffered_headers = streams
                        .iter()
                        .filter(|(stream_id, _)| **stream_id != h.stream_id)
                        .fold(0usize, |size, (_, stream)| {
                            size.saturating_add(header_list_size(&stream.headers))
                        });
                    if header_size > MAX_H2_HEADER_BLOCK
                        || buffered_headers.saturating_add(header_size) > MAX_H2_BUFFERED_HEADERS
                    {
                        streams.remove(&h.stream_id);
                        send_stream_windows.remove(&h.stream_id);
                        send_rst_stream(stream, h.stream_id, error_code::CANCEL)?;
                        continue;
                    }
                    if let Some(st) = streams.get_mut(&h.stream_id) {
                        st.headers = headers;
                        st.have_headers = true;
                    }
                } else {
                    cont_block = block.to_vec();
                    cont_stream = Some(h.stream_id);
                }
                if h.has_flag(flags::END_HEADERS) && h.has_flag(flags::END_STREAM) {
                    if let Some(st) = streams.remove(&h.stream_id) {
                        let Some(response) =
                            process_request(st, expected_path, &handler, oblivious, gateway)?
                        else {
                            return Ok(());
                        };
                        reset_deadline(stream);
                        queue_response(
                            stream,
                            h.stream_id,
                            response,
                            &mut pending,
                            &mut send_stream_windows,
                        )?;
                    }
                }
            }
            frame_type::CONTINUATION => {
                if cont_stream != Some(h.stream_id) {
                    return Err(H2Error::Protocol);
                }
                if cont_block.len().saturating_add(payload.len()) > MAX_H2_HEADER_BLOCK {
                    return undecoded_header_block(stream, last_client_stream);
                }
                cont_block.extend_from_slice(&payload);
                if h.has_flag(flags::END_HEADERS) {
                    let hdrs = dec.decode(&cont_block).ok_or(H2Error::Protocol)?;
                    let header_size = header_list_size(&hdrs);
                    let buffered_headers = streams
                        .iter()
                        .filter(|(stream_id, _)| **stream_id != h.stream_id)
                        .fold(0usize, |size, (_, stream)| {
                            size.saturating_add(header_list_size(&stream.headers))
                        });
                    if header_size > MAX_H2_HEADER_BLOCK
                        || buffered_headers.saturating_add(header_size) > MAX_H2_BUFFERED_HEADERS
                    {
                        streams.remove(&h.stream_id);
                        send_stream_windows.remove(&h.stream_id);
                        cont_stream = None;
                        cont_block.clear();
                        send_rst_stream(stream, h.stream_id, error_code::CANCEL)?;
                        continue;
                    }
                    if let Some(st) = streams.get_mut(&h.stream_id) {
                        st.headers = hdrs;
                        st.have_headers = true;
                    }
                    cont_stream = None;
                    cont_block.clear();
                    let end_stream = streams
                        .get(&h.stream_id)
                        .map(|st| st.end_stream)
                        .unwrap_or(false);
                    if end_stream {
                        if let Some(st) = streams.remove(&h.stream_id) {
                            let Some(response) =
                                process_request(st, expected_path, &handler, oblivious, gateway)?
                            else {
                                return Ok(());
                            };
                            reset_deadline(stream);
                            queue_response(
                                stream,
                                h.stream_id,
                                response,
                                &mut pending,
                                &mut send_stream_windows,
                            )?;
                        }
                    }
                }
            }
            frame_type::DATA => {
                if h.stream_id == 0 {
                    return Err(H2Error::Protocol);
                }
                let flow = i64::try_from(payload.len()).map_err(|_| H2Error::Protocol)?;
                recv_conn_window -= flow;
                if recv_conn_window < 0 {
                    return Err(H2Error::Protocol);
                }
                let buffered_requests = streams.values().fold(0usize, |size, stream| {
                    size.saturating_add(stream.body.len())
                });
                let Some(st) = streams.get_mut(&h.stream_id) else {
                    if h.stream_id & 1 == 0 || h.stream_id > last_client_stream {
                        return Err(H2Error::Protocol);
                    }
                    restore_receive_credit(stream, 0, flow, &mut recv_conn_window)?;
                    pending.remove(&h.stream_id);
                    send_stream_windows.remove(&h.stream_id);
                    send_rst_stream(stream, h.stream_id, error_code::STREAM_CLOSED)?;
                    continue;
                };
                st.recv_window -= flow;
                if st.recv_window < 0 {
                    return Err(H2Error::Protocol);
                }
                let data = strip_padding(&payload, h.flags)?;
                let too_large = st.body.len().saturating_add(data.len()) > MAX_H2_BODY
                    || buffered_requests.saturating_add(data.len()) > MAX_H2_BUFFERED_REQUESTS;
                if !too_large {
                    st.body.extend_from_slice(data);
                }
                restore_receive_credit(stream, 0, flow, &mut recv_conn_window)?;
                restore_receive_credit(stream, h.stream_id, flow, &mut st.recv_window)?;
                if too_large {
                    streams.remove(&h.stream_id);
                    pending.remove(&h.stream_id);
                    send_stream_windows.remove(&h.stream_id);
                    send_rst_stream(stream, h.stream_id, error_code::CANCEL)?;
                    continue;
                }
                if h.has_flag(flags::END_STREAM) {
                    if let Some(st) = streams.remove(&h.stream_id) {
                        let Some(response) =
                            process_request(st, expected_path, &handler, oblivious, gateway)?
                        else {
                            return Ok(());
                        };
                        reset_deadline(stream);
                        queue_response(
                            stream,
                            h.stream_id,
                            response,
                            &mut pending,
                            &mut send_stream_windows,
                        )?;
                    }
                }
            }
            _ => {}
        }
    }
}

/// Exceeding `MAX_WINDOW` is FLOW_CONTROL_ERROR; letting it through would wrap the window and
/// defeat flow control.
fn add_window(current: i64, increment: u32) -> Result<i64, H2Error> {
    let next = current
        .checked_add(i64::from(increment))
        .ok_or(H2Error::Protocol)?;
    if next > MAX_WINDOW {
        return Err(H2Error::Protocol);
    }
    Ok(next)
}

/// Returns consumed receive window to both the connection and the stream.
fn restore_receive_credit<S: Write>(
    stream: &mut S,
    sid: u32,
    amount: i64,
    window: &mut i64,
) -> Result<(), H2Error> {
    if amount <= 0 {
        return Ok(());
    }
    let increment = u32::try_from(amount).map_err(|_| H2Error::Protocol)?;
    *window = add_window(*window, increment)?;
    send_frame(
        stream,
        frame_type::WINDOW_UPDATE,
        0,
        sid,
        &increment.to_be_bytes(),
    )
}

/// Sends pending responses as far as the windows allow: the smaller of the connection and stream
/// windows, in frames of at most the max frame size. Only fully sent streams leave the list.
fn flush_pending<S: Write>(
    stream: &mut S,
    pending: &mut HashMap<u32, PendingBody>,
    stream_windows: &mut HashMap<u32, i64>,
    conn_window: &mut i64,
    peer_max_frame: usize,
) -> Result<(), H2Error> {
    loop {
        let action = pending.iter().find_map(|(sid, body)| {
            let stream_window = *stream_windows.get(sid)?;
            let available = (*conn_window).min(stream_window);
            if available <= 0 {
                return None;
            }
            let remaining = body.body.len().saturating_sub(body.offset);
            if remaining == 0 {
                return Some((*sid, Vec::new(), true));
            }
            let len = remaining
                .min(peer_max_frame)
                .min(usize::try_from(available).ok()?);
            if len == 0 {
                return None;
            }
            let end = body.offset + len;
            Some((
                *sid,
                body.body[body.offset..end].to_vec(),
                end == body.body.len(),
            ))
        });
        let Some((sid, chunk, last)) = action else {
            break;
        };
        let flags = if last { flags::END_STREAM } else { 0 };
        send_frame(stream, frame_type::DATA, flags, sid, &chunk)?;
        let used = i64::try_from(chunk.len()).map_err(|_| H2Error::Protocol)?;
        *conn_window -= used;
        if let Some(window) = stream_windows.get_mut(&sid) {
            *window -= used;
        }
        if last {
            pending.remove(&sid);
            stream_windows.remove(&sid);
        } else if let Some(body) = pending.get_mut(&sid) {
            body.offset += chunk.len();
        }
    }
    Ok(())
}

/// Header list size as the protocol counts it, with 32 bytes of overhead per entry.
fn header_list_size(headers: &[(Vec<u8>, Vec<u8>)]) -> usize {
    headers
        .iter()
        .fold(0usize, |n, (k, v)| n.saturating_add(k.len() + v.len() + 32))
}

fn send_goaway<S: Write>(stream: &mut S, last_stream: u32, code: u32) -> Result<(), H2Error> {
    let mut payload = [0u8; 8];
    payload[..4].copy_from_slice(&(last_stream & 0x7fff_ffff).to_be_bytes());
    payload[4..].copy_from_slice(&code.to_be_bytes());
    send_frame(stream, frame_type::GOAWAY, 0, 0, &payload)
}

/// A header block left undecoded leaves the HPACK table out of step with the client's, so RFC 9113
/// ends the connection rather than the stream.
fn undecoded_header_block<S: Write>(stream: &mut S, last_stream: u32) -> Result<(), H2Error> {
    send_goaway(stream, last_stream, error_code::COMPRESSION_ERROR)?;
    Err(H2Error::Protocol)
}

/// Resets one stream; the connection stays up.
fn send_rst_stream<S: Write>(stream: &mut S, sid: u32, code: u32) -> Result<(), H2Error> {
    send_frame(stream, frame_type::RST_STREAM, 0, sid, &code.to_be_bytes())
}

pub(crate) const STATUS_BAD_REQUEST: &str = "400";

/// An answer exists but cannot be sent as is: a server problem, not a bad request.
pub(crate) const STATUS_BAD_GATEWAY: &str = "502";
pub(crate) const STATUS_METHOD_NOT_ALLOWED: &str = "405";
/// RFC 8484 names this code for a body type the server does not handle.
pub(crate) const STATUS_UNSUPPORTED_MEDIA_TYPE: &str = "415";
/// Sent in the Allow header of a 405.
pub(crate) const ALLOWED_METHODS: &str = "GET, POST";

/// Pseudo-headers come before regular ones, once each, and a content-length must match the body.
/// Loosening the order or duplicate rules is a request smuggling path: a front end and this server
/// would read the same bytes as different requests.
///
/// The media type is that of a POST body; a GET has none.
fn valid_doh_request_headers(
    headers: &[(Vec<u8>, Vec<u8>)],
    body_len: usize,
) -> Result<(&[u8], &[u8], Option<Media>), &'static str> {
    let mut method = None;
    let mut scheme = None;
    let mut authority = None;
    let mut host = None;
    let mut path = None;
    let mut content_length = None;
    let mut content_type = None;
    let mut regular_seen = false;

    for (name, value) in headers {
        if !valid_header_field(name, value) {
            return Err(STATUS_BAD_REQUEST);
        }
        if name.starts_with(b":") {
            if regular_seen {
                return Err(STATUS_BAD_REQUEST);
            }
            let target = match name.as_slice() {
                b":method" => &mut method,
                b":scheme" => &mut scheme,
                b":authority" => &mut authority,
                b":path" => &mut path,
                _ => return Err(STATUS_BAD_REQUEST),
            };
            if target.replace(value.as_slice()).is_some() {
                return Err(STATUS_BAD_REQUEST);
            }
            continue;
        }

        regular_seen = true;
        if name.iter().any(u8::is_ascii_uppercase)
            || matches!(
                name.as_slice(),
                b"connection"
                    | b"proxy-connection"
                    | b"keep-alive"
                    | b"transfer-encoding"
                    | b"upgrade"
            )
        {
            return Err(STATUS_BAD_REQUEST);
        }
        if name == b"content-length" {
            if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                return Err(STATUS_BAD_REQUEST);
            }
            let length = std::str::from_utf8(value)
                .ok()
                .and_then(|text| text.parse::<usize>().ok())
                .ok_or(STATUS_BAD_REQUEST)?;
            if length > MAX_H2_BODY || content_length.replace(length).is_some() {
                return Err(STATUS_BAD_REQUEST);
            }
        } else if name == b"content-type" {
            // A different type and a duplicated header mean different things. A duplicate is a
            // request smuggling path and stays 400; a different type is 415, so the client can fix
            // it.
            if content_type.replace(Media::of(value)).is_some() {
                return Err(STATUS_BAD_REQUEST);
            }
        } else if name == b"host" {
            if host.replace(value.as_slice()).is_some() {
                return Err(STATUS_BAD_REQUEST);
            }
        } else if name == b"te" && value != b"trailers" {
            return Err(STATUS_BAD_REQUEST);
        }
    }

    let method = method.ok_or(STATUS_BAD_REQUEST)?;
    let path = path.ok_or(STATUS_BAD_REQUEST)?;
    let authority = authority.ok_or(STATUS_BAD_REQUEST)?;
    if scheme.ok_or(STATUS_BAD_REQUEST)? != b"https"
        || authority.is_empty()
        || host.is_some_and(|host| host != authority)
    {
        return Err(STATUS_BAD_REQUEST);
    }
    match method {
        b"POST" => {
            if content_length.is_some_and(|length| length != body_len) {
                return Err(STATUS_BAD_REQUEST);
            }
            match content_type {
                Some(Media::Other) | None => Err(STATUS_UNSUPPORTED_MEDIA_TYPE),
                media => Ok((method, path, media)),
            }
        }
        b"GET" if body_len == 0 && content_length.is_none_or(|length| length == 0) => {
            Ok((method, path, None))
        }
        b"GET" => Err(STATUS_BAD_REQUEST),
        _ => Err(STATUS_METHOD_NOT_ALLOWED),
    }
}

/// GET decodes the base64url `dns` parameter; POST uses the body as is. `None` means the handler
/// chose not to answer.
fn process_request<H>(
    st: StreamState,
    expected_path: &str,
    handler: &H,
    oblivious: Option<&dyn Oblivious>,
    gateway: Option<&dyn Gateway>,
) -> Result<Option<AppResponse>, H2Error>
where
    H: Fn(&[u8], Option<&str>) -> Result<Option<DohAnswer>, &'static str>,
{
    if !st.have_headers {
        return Err(H2Error::Protocol);
    }
    let (method, path, media) = match valid_doh_request_headers(&st.headers, st.body.len()) {
        Ok(head) => head,
        Err(status) => return Ok(Some(AppResponse::Status(status))),
    };
    let path_only = path.split(|&b| b == b'?').next().unwrap_or(b"");
    let body_of = |kind| (media == Some(kind)).then_some(st.body.as_slice());
    if let Some(response) = route_gateway(method, path, body_of(Media::OhttpRequest), gateway) {
        return Ok(Some(response));
    }
    match route_oblivious(
        method,
        path,
        body_of(Media::Oblivious),
        expected_path,
        oblivious,
    ) {
        Route::Doh => {}
        Route::Respond(response) => return Ok(Some(response)),
        Route::Drop => return Ok(None),
    }
    let client_id = match match_doh_path(path_only, expected_path) {
        Some(cid) => cid,
        None => return Ok(Some(AppResponse::Status("404"))),
    };
    let query = match method {
        b"POST" => Some(st.body),
        b"GET" => get_dns_param(path),
        _ => None,
    };
    Ok(Some(match query {
        Some(q) if !q.is_empty() => match handler(&q, client_id.as_deref()) {
            Ok(Some(answer)) if answer.body.len() <= MAX_H2_RESPONSE => AppResponse::Dns(answer),
            // An answer that cannot be sent is a server problem, so it stays 5xx.
            Ok(Some(_)) => AppResponse::Status(STATUS_BAD_GATEWAY),
            Ok(None) => return Ok(None),
            Err(status) => AppResponse::Status(status),
        },
        _ => AppResponse::Status(STATUS_BAD_REQUEST),
    }))
}

/// Sends the response headers and as much body as the windows allow; the rest stays pending.
fn queue_response<S: Write>(
    stream: &mut S,
    sid: u32,
    response: AppResponse,
    pending: &mut HashMap<u32, PendingBody>,
    stream_windows: &mut HashMap<u32, i64>,
) -> Result<(), H2Error> {
    match response {
        AppResponse::Status(status) => {
            // A 405 must list the accepted methods, or the client cannot know what to retry with.
            let block = if status == STATUS_METHOD_NOT_ALLOWED {
                hpack::encode_response(&[(":status", status), ("allow", ALLOWED_METHODS)])
            } else {
                hpack::encode_response(&[(":status", status)])
            };
            send_frame(
                stream,
                frame_type::HEADERS,
                flags::END_HEADERS | flags::END_STREAM,
                sid,
                &block,
            )?;
            pending.remove(&sid);
            stream_windows.remove(&sid);
        }
        AppResponse::Dns(answer) => {
            let reply = HttpReply {
                status: "200".to_string(),
                fields: vec![
                    ("content-type", "application/dns-message".to_string()),
                    ("cache-control", format!("max-age={}", answer.max_age)),
                ],
                body: answer.body,
            };
            return queue_reply(stream, sid, reply, pending, stream_windows);
        }
        AppResponse::Http(reply) => {
            return queue_reply(stream, sid, reply, pending, stream_windows);
        }
        AppResponse::Reset => {
            send_rst_stream(stream, sid, error_code::CANCEL)?;
            pending.remove(&sid);
            stream_windows.remove(&sid);
        }
    }
    Ok(())
}

fn queue_reply<S: Write>(
    stream: &mut S,
    sid: u32,
    reply: HttpReply,
    pending: &mut HashMap<u32, PendingBody>,
    stream_windows: &mut HashMap<u32, i64>,
) -> Result<(), H2Error> {
    let body = reply.body;
    let buffered_responses = pending.values().fold(0usize, |size, response| {
        size.saturating_add(response.body.len().saturating_sub(response.offset))
    });
    if buffered_responses.saturating_add(body.len()) > MAX_H2_BUFFERED_RESPONSES {
        pending.remove(&sid);
        stream_windows.remove(&sid);
        return send_rst_stream(stream, sid, error_code::REFUSED_STREAM);
    }
    let content_length = body.len().to_string();
    let mut fields: Vec<(&str, &str)> = vec![(":status", &reply.status)];
    fields.extend(
        reply
            .fields
            .iter()
            .map(|(name, value)| (*name, value.as_str())),
    );
    fields.push(("content-length", &content_length));
    let block = hpack::encode_response(&fields);
    let flags = if body.is_empty() {
        flags::END_HEADERS | flags::END_STREAM
    } else {
        flags::END_HEADERS
    };
    send_frame(stream, frame_type::HEADERS, flags, sid, &block)?;
    if body.is_empty() {
        stream_windows.remove(&sid);
    } else {
        pending.insert(sid, PendingBody { body, offset: 0 });
    }
    Ok(())
}

/// Matches the configured DoH path and extracts the client ID after it. `None` when the path does
/// not match; `Some(None)` when it matches without an ID.
fn match_doh_path(path_only: &[u8], expected: &str) -> Option<Option<String>> {
    if path_only == expected.as_bytes() {
        return Some(None);
    }
    let mut prefix = expected.as_bytes().to_vec();
    prefix.push(b'/');
    let rest = path_only.strip_prefix(prefix.as_slice())?;

    let segment = rest.split(|&b| b == b'/').next().unwrap_or(b"");
    if segment.is_empty() || segment.len() > MAX_CLIENT_ID {
        return None;
    }
    Some(Some(std::str::from_utf8(segment).ok()?.to_string()))
}

const MAX_H1_HEADERS: usize = 16 * 1024;

const MAX_H1_BODY: usize = 64 * 1024;

/// Fallback for clients that did not negotiate h2 in ALPN.
pub fn serve_doh_h1<S, H>(stream: &mut S, expected_path: &str, handler: H) -> Result<(), H2Error>
where
    S: Read + Write,
    H: Fn(&[u8], Option<&str>) -> Result<Option<DohAnswer>, &'static str>,
{
    serve_doh_h1_with_deadline_reset(stream, expected_path, handler, |_| {}, None, None)
}

/// Only Content-Length bodies are accepted, not chunked. An encoding the front end reads
/// differently is a request smuggling path, so unsupported encodings are refused.
pub fn serve_doh_h1_with_deadline_reset<S, H, R>(
    stream: &mut S,
    expected_path: &str,
    handler: H,
    mut reset_deadline: R,
    oblivious: Option<&dyn Oblivious>,
    gateway: Option<&dyn Gateway>,
) -> Result<(), H2Error>
where
    S: Read + Write,
    H: Fn(&[u8], Option<&str>) -> Result<Option<DohAnswer>, &'static str>,
    R: FnMut(&mut S),
{
    reset_deadline(stream);
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        if let Some(pos) = find_sub(&buf, b"\r\n\r\n") {
            if pos > MAX_H1_HEADERS {
                return write_h1_status(stream, "431 Request Header Fields Too Large");
            }
            break pos;
        }
        if buf.len() > MAX_H1_HEADERS {
            return write_h1_status(stream, "431 Request Header Fields Too Large");
        }
        let n = stream.read(&mut tmp).map_err(|_| H2Error::Io)?;
        if n == 0 {
            return Err(H2Error::Closed);
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let head = &buf[..header_end];
    if head
        .iter()
        .enumerate()
        .any(|(index, &byte)| byte == b'\n' && (index == 0 || head[index - 1] != b'\r'))
    {
        return write_h1_status(stream, "400 Bad Request");
    }
    let mut lines = head.split(|&b| b == b'\n');
    let req_line = trim_cr(lines.next().unwrap_or(&[]));
    let mut rl = req_line.split(|&b| b == b' ');
    let method = rl.next().unwrap_or(&[]);
    let target = rl.next().unwrap_or(&[]);
    let version = rl.next().unwrap_or(&[]);
    if method.is_empty()
        || !target.starts_with(b"/")
        || version != b"HTTP/1.1"
        || rl.next().is_some()
    {
        return write_h1_status(stream, "400 Bad Request");
    }

    let mut content_length: Option<usize> = None;
    let mut content_type: Option<Media> = None;
    let mut host_seen = false;
    let mut transfer_encoding = false;
    for line in lines {
        let line = trim_cr(line);
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return write_h1_status(stream, "400 Bad Request");
        };
        let name = &line[..colon];
        if name.is_empty() || !name.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'-') {
            return write_h1_status(stream, "400 Bad Request");
        }
        let mut value = &line[colon + 1..];
        while value
            .first()
            .is_some_and(|&byte| matches!(byte, b' ' | b'\t'))
        {
            value = &value[1..];
        }
        while value
            .last()
            .is_some_and(|&byte| matches!(byte, b' ' | b'\t'))
        {
            value = &value[..value.len() - 1];
        }
        if !value
            .iter()
            .all(|&byte| byte == b'\t' || (byte >= b' ' && byte != 0x7f))
        {
            return write_h1_status(stream, "400 Bad Request");
        }
        if name.eq_ignore_ascii_case(b"host") {
            if host_seen || value.is_empty() {
                return write_h1_status(stream, "400 Bad Request");
            }
            host_seen = true;
        } else if name.eq_ignore_ascii_case(b"content-length") {
            if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                return write_h1_status(stream, "400 Bad Request");
            }
            let Some(parsed) = std::str::from_utf8(value)
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
            else {
                return write_h1_status(stream, "400 Bad Request");
            };
            if content_length.replace(parsed).is_some() {
                return write_h1_status(stream, "400 Bad Request");
            }
        } else if name.eq_ignore_ascii_case(b"content-type") {
            if content_type.replace(Media::of(value)).is_some() {
                return write_h1_status(stream, "400 Bad Request");
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            transfer_encoding = true;
        }
    }

    if transfer_encoding || !host_seen {
        return write_h1_status(stream, "400 Bad Request");
    }

    let path_only = target.split(|&b| b == b'?').next().unwrap_or(b"");
    let is_configs = method == b"GET" && path_only == ODOH_CONFIGS_PATH.as_bytes();
    let client_id = match_doh_path(path_only, expected_path);
    if client_id.is_none() && !is_configs && path_only != OHTTP_GATEWAY_PATH.as_bytes() {
        return write_h1_status(stream, "404 Not Found");
    }

    let query: Option<Vec<u8>> = if method == b"POST" {
        if !matches!(
            content_type,
            Some(Media::Dns | Media::Oblivious | Media::OhttpRequest)
        ) {
            return write_h1_status(stream, "415 Unsupported Media Type");
        }
        let Some(content_length) = content_length else {
            return write_h1_status(stream, "411 Length Required");
        };
        if content_length > MAX_H1_BODY {
            return write_h1_status(stream, "413 Payload Too Large");
        }
        let body_start = header_end + 4;
        let mut body = buf[body_start.min(buf.len())..].to_vec();
        if body.len() > content_length {
            return write_h1_status(stream, "400 Bad Request");
        }
        while body.len() < content_length {
            let remaining = content_length - body.len();
            let read_len = remaining.min(tmp.len());
            let n = stream.read(&mut tmp[..read_len]).map_err(|_| H2Error::Io)?;
            if n == 0 {
                return write_h1_status(stream, "400 Bad Request");
            }
            body.extend_from_slice(&tmp[..n]);
        }
        Some(body)
    } else if method == b"GET" {
        if content_length.is_some_and(|length| length != 0) || buf.len() != header_end + 4 {
            return write_h1_status(stream, "400 Bad Request");
        }
        get_dns_param(target)
    } else {
        return write_h1_status(stream, "405 Method Not Allowed");
    };

    let body_of = |kind| {
        query
            .as_deref()
            .filter(|_| method == b"POST" && content_type == Some(kind))
    };
    if let Some(response) = route_gateway(method, target, body_of(Media::OhttpRequest), gateway) {
        return write_h1_app_response(stream, response);
    }
    match route_oblivious(
        method,
        target,
        body_of(Media::Oblivious),
        expected_path,
        oblivious,
    ) {
        Route::Doh => {}
        Route::Respond(response) => return write_h1_app_response(stream, response),
        Route::Drop => return Ok(()),
    }
    let Some(client_id) = client_id else {
        return write_h1_status(stream, "404 Not Found");
    };

    match query {
        Some(q) if !q.is_empty() => match handler(&q, client_id.as_deref()) {
            Ok(Some(answer)) if answer.body.len() <= MAX_H2_RESPONSE => {
                write_h1_response(stream, &answer.body, answer.max_age)
            }
            Ok(Some(_)) => write_h1_status(stream, "502 Bad Gateway"),
            Ok(None) => Ok(()),
            Err(status) => write_h1_status(stream, &h1_status_line(status)),
        },
        _ => write_h1_status(stream, "400 Bad Request"),
    }
}

fn write_h1_response<S: Write>(stream: &mut S, body: &[u8], max_age: u32) -> Result<(), H2Error> {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nCache-Control: max-age={max_age}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).map_err(|_| H2Error::Io)?;
    stream.write_all(body).map_err(|_| H2Error::Io)?;
    Ok(())
}

fn write_h1_app_response<S: Write>(stream: &mut S, response: AppResponse) -> Result<(), H2Error> {
    match response {
        AppResponse::Status(status) => write_h1_status(stream, &h1_status_line(status)),
        AppResponse::Dns(answer) => write_h1_response(stream, &answer.body, answer.max_age),
        AppResponse::Http(reply) => write_h1_reply(stream, reply),
        // Every HTTP/1.1 response here closes the connection, which then carries nothing else.
        AppResponse::Reset => Ok(()),
    }
}

fn write_h1_reply<S: Write>(stream: &mut S, reply: HttpReply) -> Result<(), H2Error> {
    let mut head = format!("HTTP/1.1 {}\r\n", h1_status_line(&reply.status));
    for (name, value) in &reply.fields {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        reply.body.len()
    ));
    stream.write_all(head.as_bytes()).map_err(|_| H2Error::Io)?;
    stream.write_all(&reply.body).map_err(|_| H2Error::Io)
}

/// HTTP/1.1 status line text after the version. Clients read only the code.
fn h1_status_line(status: &str) -> String {
    let reason = match status {
        "200" => "OK",
        "400" => "Bad Request",
        "401" => "Unauthorized",
        "403" => "Forbidden",
        "404" => "Not Found",
        "415" => "Unsupported Media Type",
        "422" => "Unprocessable Content",
        "429" => "Too Many Requests",
        "502" => "Bad Gateway",
        "504" => "Gateway Timeout",
        _ => "Error",
    };
    format!("{status} {reason}")
}

fn write_h1_status<S: Write>(stream: &mut S, status: &str) -> Result<(), H2Error> {
    // A 405 must list the accepted methods, or the client cannot know what to retry with.
    let allow = if status.starts_with(STATUS_METHOD_NOT_ALLOWED) {
        format!("Allow: {ALLOWED_METHODS}\r\n")
    } else {
        String::new()
    };
    let head =
        format!("HTTP/1.1 {status}\r\n{allow}Content-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).map_err(|_| H2Error::Io)
}

fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Decoded value of the `dns` query parameter.
pub(crate) fn get_dns_param(path: &[u8]) -> Option<Vec<u8>> {
    let q = path.split(|&b| b == b'?').nth(1)?;
    for kv in q.split(|&b| b == b'&') {
        if let Some(v) = kv.strip_prefix(b"dns=") {
            return base64url_decode(v);
        }
    }
    None
}

/// Unpadded only; characters outside the alphabet are rejected.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{deadline_accept, deadline_connect};
    use crate::wire::header;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    fn h2_client_doh(addr: std::net::SocketAddr, dns_query: &[u8], use_get: bool) -> Vec<u8> {
        let mut c = deadline_connect(addr);
        c.write_all(frame::PREFACE).unwrap();

        send_frame(&mut c, frame_type::SETTINGS, 0, 0, &[]).unwrap();

        let path_str;
        let headers: Vec<(&str, &str)> = if use_get {
            let b64 = base64url_encode(dns_query);
            path_str = format!("/dns-query?dns={b64}");
            vec![
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "dns.test"),
                (":path", &path_str),
                ("accept", "application/dns-message"),
            ]
        } else {
            vec![
                (":method", "POST"),
                (":scheme", "https"),
                (":authority", "dns.test"),
                (":path", "/dns-query"),
                ("content-type", "application/dns-message"),
            ]
        };
        let block = hpack::encode_response(&headers);
        let end = if use_get {
            flags::END_HEADERS | flags::END_STREAM
        } else {
            flags::END_HEADERS
        };
        send_frame(&mut c, frame_type::HEADERS, end, 1, &block).unwrap();
        if !use_get {
            send_frame(&mut c, frame_type::DATA, flags::END_STREAM, 1, dns_query).unwrap();
        }

        let mut body = Vec::new();
        let mut got_status_ok = false;
        let mut dec = Decoder::new(4096);
        loop {
            let (h, payload) = match read_frame(&mut c) {
                Ok(v) => v,
                Err(_) => break,
            };
            match h.frame_type {
                frame_type::HEADERS => {
                    let blk = strip_headers(&payload, h.flags).unwrap();
                    let hs = dec.decode(blk).unwrap();
                    if header(&hs, b":status") == Some(b"200") {
                        got_status_ok = true;
                    }
                    if h.has_flag(flags::END_STREAM) {
                        break;
                    }
                }
                frame_type::DATA => {
                    body.extend_from_slice(strip_padding(&payload, h.flags).unwrap());
                    if h.has_flag(flags::END_STREAM) {
                        break;
                    }
                }
                frame_type::SETTINGS if !h.has_flag(flags::ACK) => {
                    send_frame(&mut c, frame_type::SETTINGS, flags::ACK, 0, &[]).unwrap();
                }
                _ => {}
            }
        }
        assert!(got_status_ok, "200 응답 기대");
        body
    }

    fn base64url_encode(data: &[u8]) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut s = String::new();
        for chunk in data.chunks(3) {
            let n = chunk.len();
            let b0 = chunk[0] as usize;
            let b1 = if n > 1 { chunk[1] as usize } else { 0 };
            let b2 = if n > 2 { chunk[2] as usize } else { 0 };
            s.push(T[b0 >> 2] as char);
            s.push(T[((b0 & 3) << 4) | (b1 >> 4)] as char);
            if n > 1 {
                s.push(T[((b1 & 15) << 2) | (b2 >> 6)] as char);
            }
            if n > 2 {
                s.push(T[b2 & 63] as char);
            }
        }
        s
    }

    fn answer(body: Vec<u8>) -> Result<Option<DohAnswer>, &'static str> {
        Ok(Some(DohAnswer { body, max_age: 0 }))
    }

    fn run(use_get: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut s = deadline_accept(&listener);
            serve_doh(&mut s, "/dns-query", |q, _client_id| {
                let mut r = q.to_vec();
                r.reverse();
                answer(r)
            })
            .ok();
        });

        let query = vec![0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00];
        let resp = h2_client_doh(addr, &query, use_get);
        let mut expected = query.clone();
        expected.reverse();
        assert_eq!(resp, expected);
        drop(server);
    }

    #[test]
    fn doh_path_extracts_client_id() {
        assert_eq!(match_doh_path(b"/dns-query", "/dns-query"), Some(None));
        assert_eq!(
            match_doh_path(b"/dns-query/kids-tablet", "/dns-query"),
            Some(Some("kids-tablet".to_string()))
        );

        assert_eq!(
            match_doh_path(b"/dns-query/laptop/extra", "/dns-query"),
            Some(Some("laptop".to_string()))
        );

        assert_eq!(match_doh_path(b"/other", "/dns-query"), None);
        assert_eq!(match_doh_path(b"/dns-querX/x", "/dns-query"), None);

        assert_eq!(match_doh_path(b"/dns-query/", "/dns-query"), None);
    }

    fn owned_headers(headers: &[(&[u8], &[u8])]) -> Vec<(Vec<u8>, Vec<u8>)> {
        headers
            .iter()
            .map(|(name, value)| (name.to_vec(), value.to_vec()))
            .collect()
    }

    #[test]
    /// Each rejection gets the status that matches its reason, the same on both transports. RFC
    /// 8484 names 415 for an unsupported type, and a client seeing it may move to another server.
    ///
    /// A missing content-type is 415 too: RFC 9110 lets it be read as application/octet-stream,
    /// which this server does not accept either.
    ///
    /// A duplicated content-type is 400, not 415: it lets a front end and this server read the same
    /// bytes differently, which is not a type problem.
    fn doh_header_rejections_carry_the_matching_status() {
        let base: [(&[u8], &[u8]); 5] = [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", b"dns.test"),
            (b":path", b"/dns-query"),
            (b"content-type", b"application/dns-message"),
        ];
        assert!(valid_doh_request_headers(&owned_headers(&base), 3).is_ok());

        let mut wrong_type = base;
        wrong_type[4] = (b"content-type", b"text/plain");
        assert_eq!(
            valid_doh_request_headers(&owned_headers(&wrong_type), 3),
            Err("415"),
            "다룰 수 없는 형식은 415 입니다"
        );

        let missing_type: [(&[u8], &[u8]); 4] = [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", b"dns.test"),
            (b":path", b"/dns-query"),
        ];
        assert_eq!(
            valid_doh_request_headers(&owned_headers(&missing_type), 3),
            Err("415"),
            "형식을 아예 밝히지 않은 것도 이쪽이 받는 형식이 아닙니다"
        );

        let mut other_method = base;
        other_method[0] = (b":method", b"PUT");
        assert_eq!(
            valid_doh_request_headers(&owned_headers(&other_method), 3),
            Err("405"),
            "이 자원이 받지 않는 메서드는 405 입니다"
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
            valid_doh_request_headers(&owned_headers(&duplicate_type), 3),
            Err("400"),
            "겹친 헤더는 형식 문제가 아니라 요청이 어긋난 것입니다"
        );
    }

    #[test]
    fn doh_headers_reject_duplicates_bad_order_and_body_length_mismatch() {
        let valid: [(&[u8], &[u8]); 6] = [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", b"dns.test"),
            (b":path", b"/dns-query"),
            (b"content-type", b"application/dns-message"),
            (b"content-length", b"3"),
        ];
        assert!(valid_doh_request_headers(&owned_headers(&valid), 3).is_ok());
        assert!(valid_doh_request_headers(&owned_headers(&valid), 2).is_err());

        let duplicate: [(&[u8], &[u8]); 7] = [
            (b":method", b"POST"),
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"dns.test"),
            (b":path", b"/dns-query"),
            (b"content-type", b"application/dns-message"),
            (b"content-length", b"3"),
        ];
        assert!(valid_doh_request_headers(&owned_headers(&duplicate), 3).is_err());

        let bad_order: [(&[u8], &[u8]); 6] = [
            (b"content-type", b"application/dns-message"),
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", b"dns.test"),
            (b":path", b"/dns-query"),
            (b"content-length", b"3"),
        ];
        assert!(valid_doh_request_headers(&owned_headers(&bad_order), 3).is_err());

        for (name, value) in [
            (&b"bad\0name"[..], &b"value"[..]),
            (&b"x-test"[..], &b"bad\nvalue"[..]),
            (&b"x-test"[..], &b"trailing\t"[..]),
            (&b"te"[..], &b"gzip"[..]),
        ] {
            let mut headers = owned_headers(&valid);
            headers.push((name.to_vec(), value.to_vec()));
            assert!(
                valid_doh_request_headers(&headers, 3).is_err(),
                "{name:?}: {value:?}"
            );
        }

        let mut bad_length = owned_headers(&valid);
        bad_length
            .iter_mut()
            .find(|(name, _)| name == b"content-length")
            .unwrap()
            .1 = b"+3".to_vec();
        assert!(valid_doh_request_headers(&bad_length, 3).is_err());

        let mut matching_host = owned_headers(&valid);
        matching_host.push((b"host".to_vec(), b"dns.test".to_vec()));
        assert!(valid_doh_request_headers(&matching_host, 3).is_ok());
        matching_host.last_mut().unwrap().1 = b"other.test".to_vec();
        assert!(valid_doh_request_headers(&matching_host, 3).is_err());
    }

    #[test]
    fn doh_post_roundtrip() {
        run(false);
    }

    #[test]
    fn doh_get_roundtrip() {
        run(true);
    }

    #[test]
    /// Only servers may push.
    fn server_rejects_client_push_promise() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut stream = deadline_accept(&listener);
            serve_doh(&mut stream, "/dns-query", |query, _| answer(query.to_vec()))
        });

        let mut client = deadline_connect(addr);
        client.write_all(frame::PREFACE).unwrap();
        send_frame(&mut client, frame_type::SETTINGS, 0, 0, &[]).unwrap();
        send_frame(
            &mut client,
            frame_type::PUSH_PROMISE,
            flags::END_HEADERS,
            1,
            &[0, 0, 0, 2],
        )
        .unwrap();
        let (initial, _) = read_frame(&mut client).unwrap();
        assert_eq!(initial.frame_type, frame_type::SETTINGS);
        let (ack, _) = read_frame(&mut client).unwrap();
        assert_eq!(ack.frame_type, frame_type::SETTINGS);
        assert!(ack.has_flag(flags::ACK));
        drop(client);

        assert!(matches!(server.join().unwrap(), Err(H2Error::Protocol)));
    }

    #[test]
    fn server_requires_client_settings_as_first_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut stream = deadline_accept(&listener);
            serve_doh(&mut stream, "/dns-query", |query, _| answer(query.to_vec()))
        });

        let mut client = deadline_connect(addr);
        client.write_all(frame::PREFACE).unwrap();
        send_frame(&mut client, frame_type::PING, 0, 0, &[0; 8]).unwrap();
        let (initial, _) = read_frame(&mut client).unwrap();
        assert_eq!(initial.frame_type, frame_type::SETTINGS);
        drop(client);

        assert!(matches!(server.join().unwrap(), Err(H2Error::Protocol)));
    }

    #[test]
    fn deadline_reset_ignores_control_only_traffic() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let resets = Arc::new(AtomicUsize::new(0));
        let server_resets = resets.clone();
        let server = thread::spawn(move || {
            let mut stream = deadline_accept(&listener);
            serve_doh_with_deadline_reset(
                &mut stream,
                "/dns-query",
                |query, _| answer(query.to_vec()),
                |_| {
                    server_resets.fetch_add(1, Ordering::Relaxed);
                },
                &std::sync::atomic::AtomicBool::new(false),
                None,
                None,
            )
        });

        let mut client = deadline_connect(addr);
        client.write_all(frame::PREFACE).unwrap();
        send_frame(&mut client, frame_type::SETTINGS, 0, 0, &[]).unwrap();
        send_frame(&mut client, frame_type::PING, 0, 0, &[7; 8]).unwrap();
        send_frame(&mut client, frame_type::GOAWAY, 0, 0, &[0; 8]).unwrap();

        assert!(server.join().unwrap().is_ok());
        assert_eq!(resets.load(Ordering::Relaxed), 1);
    }

    fn doh_post_header_block() -> Vec<u8> {
        hpack::encode_response(&[
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "dns.test"),
            (":path", "/dns-query"),
            ("content-type", "application/dns-message"),
        ])
    }

    fn h2_connect(addr: std::net::SocketAddr) -> TcpStream {
        h2_connect_with(addr, &[])
    }

    /// `peer_settings` is the payload of the client's first SETTINGS.
    fn h2_connect_with(addr: std::net::SocketAddr, peer_settings: &[u8]) -> TcpStream {
        let mut client = deadline_connect(addr);
        client.write_all(frame::PREFACE).unwrap();
        send_frame(&mut client, frame_type::SETTINGS, 0, 0, peer_settings).unwrap();
        client
    }

    fn h2_exchange_on(client: &mut TcpStream, sid: u32, query: &[u8]) -> Vec<u8> {
        send_frame(
            client,
            frame_type::HEADERS,
            flags::END_HEADERS,
            sid,
            &doh_post_header_block(),
        )
        .unwrap();
        send_frame(client, frame_type::DATA, flags::END_STREAM, sid, query).unwrap();

        let mut body = Vec::new();
        let mut ok = false;
        let mut dec = Decoder::new(4096);
        loop {
            let Ok((h, payload)) = read_frame(client) else {
                break;
            };
            match h.frame_type {
                frame_type::HEADERS if h.stream_id == sid => {
                    let block = strip_headers(&payload, h.flags).unwrap();
                    if header(&dec.decode(block).unwrap(), b":status") == Some(b"200") {
                        ok = true;
                    }
                }
                frame_type::DATA if h.stream_id == sid => {
                    body.extend_from_slice(strip_padding(&payload, h.flags).unwrap());
                    if h.has_flag(flags::END_STREAM) {
                        break;
                    }
                }
                frame_type::SETTINGS if !h.has_flag(flags::ACK) => {
                    send_frame(client, frame_type::SETTINGS, flags::ACK, 0, &[]).unwrap();
                }
                _ => {}
            }
        }
        assert!(ok, "스트림 {sid}에서 200 응답 기대");
        body
    }

    /// Frames the server sends until it closes the connection.
    fn frames_until_close(client: &mut TcpStream) -> Vec<(frame::FrameHeader, Vec<u8>)> {
        let mut frames = Vec::new();
        while let Ok(frame) = read_frame(client) {
            frames.push(frame);
        }
        frames
    }

    /// The last stream each GOAWAY named, in order.
    fn goaway_last_streams(frames: &[(frame::FrameHeader, Vec<u8>)]) -> Vec<u32> {
        frames
            .iter()
            .filter(|(h, payload)| {
                h.frame_type == frame_type::GOAWAY
                    && payload[4..8] == error_code::NO_ERROR.to_be_bytes()
            })
            .map(|(_, payload)| u32::from_be_bytes(payload[..4].try_into().unwrap()))
            .collect()
    }

    /// Reads up to the server's drain PING, which follows its first GOAWAY.
    fn frames_until_drain_ping(client: &mut TcpStream) -> Vec<(frame::FrameHeader, Vec<u8>)> {
        let mut frames = Vec::new();
        loop {
            let frame = read_frame(client).expect("the server closed before its drain PING");
            let done = frame.0.frame_type == frame_type::PING
                && !frame.0.has_flag(flags::ACK)
                && frame.1 == DRAIN_PING;
            frames.push(frame);
            if done {
                return frames;
            }
        }
    }

    fn answered_on(frames: &[(frame::FrameHeader, Vec<u8>)], sid: u32) -> Vec<u8> {
        frames
            .iter()
            .filter(|(h, _)| h.frame_type == frame_type::DATA && h.stream_id == sid)
            .flat_map(|(h, payload)| strip_padding(payload, h.flags).unwrap().to_vec())
            .collect()
    }

    #[test]
    /// Streams the client opened before it acknowledged the drain PING are answered, including one
    /// open when draining starts. One opened after is refused, so the client knows it was not
    /// processed. The refused stream's header block continues in a second frame, which must not
    /// break the connection.
    fn draining_announces_goaway_and_finishes_streams_it_took() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let draining = Arc::new(AtomicBool::new(false));
        let server_draining = draining.clone();
        let server = thread::spawn(move || {
            let mut stream = deadline_accept(&listener);
            serve_doh_with_deadline_reset(
                &mut stream,
                "/dns-query",
                |query, _| answer(query.to_vec()),
                |_| {},
                &server_draining,
                None,
                None,
            )
        });

        let mut client = h2_connect(addr);
        assert_eq!(h2_exchange_on(&mut client, 1, b"first"), b"first");
        send_frame(
            &mut client,
            frame_type::HEADERS,
            flags::END_HEADERS,
            3,
            &doh_post_header_block(),
        )
        .unwrap();
        draining.store(true, Ordering::Release);
        // Moves the server past a frame boundary, where it sees `draining`.
        send_frame(&mut client, frame_type::PING, 0, 0, &[1; 8]).unwrap();
        send_frame(
            &mut client,
            frame_type::HEADERS,
            flags::END_HEADERS,
            5,
            &doh_post_header_block(),
        )
        .unwrap();
        send_frame(
            &mut client,
            frame_type::DATA,
            flags::END_STREAM,
            5,
            b"in flight",
        )
        .unwrap();
        let mut frames = frames_until_drain_ping(&mut client);
        assert_eq!(goaway_last_streams(&frames), [MAX_STREAM_ID]);
        send_frame(&mut client, frame_type::PING, flags::ACK, 0, &DRAIN_PING).unwrap();
        let block = doh_post_header_block();
        send_frame(&mut client, frame_type::HEADERS, 0, 7, &block[..2]).unwrap();
        send_frame(
            &mut client,
            frame_type::CONTINUATION,
            flags::END_HEADERS,
            7,
            &block[2..],
        )
        .unwrap();
        send_frame(
            &mut client,
            frame_type::DATA,
            flags::END_STREAM,
            3,
            b"second",
        )
        .unwrap();

        frames.extend(frames_until_close(&mut client));
        assert!(server.join().unwrap().is_ok());
        assert_eq!(goaway_last_streams(&frames), [MAX_STREAM_ID, 5]);
        assert!(frames
            .iter()
            .any(|(h, payload)| h.frame_type == frame_type::RST_STREAM
                && h.stream_id == 7
                && *payload == error_code::REFUSED_STREAM.to_be_bytes()));
        assert_eq!(answered_on(&frames, 5), b"in flight");
        assert_eq!(answered_on(&frames, 3), b"second");
    }

    #[test]
    /// A connection accepted just before the listener stopped gets its first request answered:
    /// the client sent it before it could read any GOAWAY.
    fn a_connection_accepted_while_draining_answers_its_first_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut stream = deadline_accept(&listener);
            serve_doh_with_deadline_reset(
                &mut stream,
                "/dns-query",
                |query, _| answer(query.to_vec()),
                |_| {},
                &std::sync::atomic::AtomicBool::new(true),
                None,
                None,
            )
        });

        let mut client = h2_connect(addr);
        assert_eq!(h2_exchange_on(&mut client, 1, b"late"), b"late");
        send_frame(&mut client, frame_type::PING, flags::ACK, 0, &DRAIN_PING).unwrap();
        let frames = frames_until_close(&mut client);
        assert!(server.join().unwrap().is_ok());
        assert_eq!(goaway_last_streams(&frames).last(), Some(&1));
    }

    #[test]
    /// An idle connection that times out while draining says GOAWAY before it closes.
    fn idle_connection_ends_with_goaway_while_draining() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let draining = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server_draining = draining.clone();
        let server = thread::spawn(move || {
            let mut stream = deadline_accept(&listener);
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .unwrap();
            serve_doh_with_deadline_reset(
                &mut stream,
                "/dns-query",
                |query, _| answer(query.to_vec()),
                |_| {},
                &server_draining,
                None,
                None,
            )
        });

        let mut client = h2_connect(addr);
        assert_eq!(h2_exchange_on(&mut client, 1, b"only"), b"only");
        draining.store(true, std::sync::atomic::Ordering::Release);
        let frames = frames_until_close(&mut client);
        assert!(server.join().unwrap().is_ok());
        assert_eq!(goaway_last_streams(&frames).last(), Some(&1));
    }

    #[test]
    /// Past the limit the block is not decoded, so the connection must end; otherwise the peer can
    /// postpone END_HEADERS forever and fill memory.
    fn continuation_flood_ends_the_connection_at_the_header_block_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut stream = deadline_accept(&listener);
            serve_doh(&mut stream, "/dns-query", |query, _| answer(query.to_vec()))
        });

        let mut client = h2_connect(addr);
        send_frame(
            &mut client,
            frame_type::HEADERS,
            0,
            1,
            &doh_post_header_block(),
        )
        .unwrap();

        let chunk = vec![0u8; 4096];
        let mut sent = 0usize;
        let mut goaway = None;
        while sent <= MAX_H2_HEADER_BLOCK * 2 {
            if send_frame(&mut client, frame_type::CONTINUATION, 0, 1, &chunk).is_err() {
                break;
            }
            sent += chunk.len();
            client
                .set_read_timeout(Some(std::time::Duration::from_millis(50)))
                .unwrap();
            if let Ok((h, payload)) = read_frame(&mut client) {
                if h.frame_type == frame_type::GOAWAY {
                    goaway = Some(u32::from_be_bytes(payload[4..8].try_into().unwrap()));
                    break;
                }
            }
        }
        assert_eq!(
            goaway,
            Some(error_code::COMPRESSION_ERROR),
            "헤더 상한을 넘겨도 연결을 끊지 않았습니다. {sent}바이트를 버퍼에 쌓았습니다"
        );
        assert!(
            server.join().unwrap().is_err(),
            "풀지 않은 헤더 블록 뒤에도 연결을 이어 갔습니다"
        );
    }

    #[test]
    /// A reset stream that kept its budget would refuse normal queries after enough cycles.
    /// Requests finish synchronously in the frame loop, so the cycles add no work either.
    fn rapid_reset_cycles_do_not_leak_the_stream_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut stream = deadline_accept(&listener);
            serve_doh(&mut stream, "/dns-query", |query, _| answer(query.to_vec()))
        });

        let mut client = h2_connect(addr);
        let block = doh_post_header_block();
        let cycles = MAX_H2_STREAMS as u32 * 8;
        for index in 0..cycles {
            let sid = index * 2 + 1;
            send_frame(
                &mut client,
                frame_type::HEADERS,
                flags::END_HEADERS,
                sid,
                &block,
            )
            .unwrap();
            send_frame(
                &mut client,
                frame_type::RST_STREAM,
                0,
                sid,
                &error_code::CANCEL.to_be_bytes(),
            )
            .unwrap();
        }

        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let query = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01";
        let echoed = h2_exchange_on(&mut client, cycles * 2 + 1, query);
        assert_eq!(
            echoed, query,
            "{cycles}번 열고 끊은 뒤 정상 질의가 처리되지 않았습니다"
        );
        drop(client);
        let _ = server.join().unwrap();
    }

    const QUERY: &[u8] = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01";

    fn spawn_server<H>(
        handler: H,
    ) -> (
        std::net::SocketAddr,
        thread::JoinHandle<Result<(), H2Error>>,
    )
    where
        H: Fn(&[u8], Option<&str>) -> Result<Option<DohAnswer>, &'static str> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut stream = deadline_accept(&listener);
            serve_doh(&mut stream, "/dns-query", handler)
        });
        (addr, server)
    }

    /// A SETTINGS payload that sets the client's initial stream window.
    fn initial_window(value: u32) -> Vec<u8> {
        let mut payload = settings::INITIAL_WINDOW_SIZE.to_be_bytes().to_vec();
        payload.extend_from_slice(&value.to_be_bytes());
        payload
    }

    fn open_stream(client: &mut TcpStream, sid: u32, block: &[u8]) {
        send_frame(client, frame_type::HEADERS, flags::END_HEADERS, sid, block).unwrap();
    }

    /// Sends `len` body bytes without ending the stream.
    fn send_body(client: &mut TcpStream, sid: u32, len: usize) {
        let chunk = vec![0u8; DEFAULT_MAX_FRAME];
        let mut left = len;
        while left > 0 {
            let n = left.min(chunk.len());
            send_frame(client, frame_type::DATA, 0, sid, &chunk[..n]).unwrap();
            left -= n;
        }
    }

    /// Sends a PING and returns what the server sent before answering it, which is everything it
    /// sent for the frames before the PING.
    fn barrier(client: &mut TcpStream) -> Vec<(frame::FrameHeader, Vec<u8>)> {
        const PAYLOAD: &[u8; 8] = b"barrier!";
        send_frame(client, frame_type::PING, 0, 0, PAYLOAD).unwrap();
        let mut frames = Vec::new();
        loop {
            let frame = read_frame(client).expect("the server closed before its PING answer");
            if frame.0.frame_type == frame_type::PING
                && frame.0.has_flag(flags::ACK)
                && frame.1 == PAYLOAD
            {
                return frames;
            }
            frames.push(frame);
        }
    }

    /// The streams the server reset and its error codes, in order.
    fn resets(frames: &[(frame::FrameHeader, Vec<u8>)]) -> Vec<(u32, u32)> {
        frames
            .iter()
            .filter(|(h, _)| h.frame_type == frame_type::RST_STREAM)
            .map(|(h, payload)| {
                let code = u32::from_be_bytes(payload[..4].try_into().unwrap());
                (h.stream_id, code)
            })
            .collect()
    }

    #[test]
    /// DATA after the request's END_STREAM resets the stream. Its answer, still waiting for window,
    /// must go with it: sending DATA on a stream this side reset breaks RFC 9113, and the waiting
    /// answer would keep its place in the stream and response budgets.
    fn stream_reset_for_late_data_drops_its_pending_answer() {
        let (addr, server) = spawn_server(|query, _| answer(query.to_vec()));
        let mut client = h2_connect_with(addr, &initial_window(0));
        open_stream(&mut client, 1, &doh_post_header_block());
        send_frame(&mut client, frame_type::DATA, flags::END_STREAM, 1, QUERY).unwrap();
        send_frame(&mut client, frame_type::DATA, 0, 1, b"late").unwrap();
        send_frame(
            &mut client,
            frame_type::WINDOW_UPDATE,
            0,
            1,
            &1024u32.to_be_bytes(),
        )
        .unwrap();

        let frames = barrier(&mut client);
        assert!(
            frames
                .iter()
                .any(|(h, _)| h.frame_type == frame_type::HEADERS && h.stream_id == 1),
            "대조군이 무효입니다. 요청에 응답 헤더를 보내지 않았습니다"
        );
        assert_eq!(
            resets(&frames),
            vec![(1, error_code::STREAM_CLOSED)],
            "END_STREAM 뒤에 DATA 를 받은 스트림을 STREAM_CLOSED 로 끊지 않았습니다"
        );
        assert!(
            !frames
                .iter()
                .any(|(h, _)| h.frame_type == frame_type::DATA && h.stream_id == 1),
            "끊은 스트림에 기다리던 답을 보냈습니다"
        );
        drop(client);
        let _ = server.join().unwrap();
    }

    #[test]
    fn data_on_a_stream_never_opened_ends_the_connection() {
        for sid in [1, 2] {
            let (addr, server) = spawn_server(|query, _| answer(query.to_vec()));
            let mut client = h2_connect(addr);
            send_frame(&mut client, frame_type::DATA, flags::END_STREAM, sid, QUERY).unwrap();
            client
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            while read_frame(&mut client).is_ok() {}
            drop(client);
            assert!(
                server.join().unwrap().is_err(),
                "열리지 않은 스트림 {sid} 의 DATA 를 연결 오류로 다루지 않았습니다"
            );
        }
    }

    #[test]
    fn stream_cap_refuses_until_a_stream_closes() {
        let (addr, server) = spawn_server(|query, _| answer(query.to_vec()));
        let mut client = h2_connect(addr);
        let block = doh_post_header_block();
        let over = MAX_H2_STREAMS as u32 * 2 + 1;
        for sid in (1..=over).step_by(2) {
            open_stream(&mut client, sid, &block);
        }
        assert_eq!(
            resets(&barrier(&mut client)),
            vec![(over, error_code::REFUSED_STREAM)],
            "동시 스트림 상한을 넘은 스트림 하나만 거절해야 합니다"
        );

        send_frame(
            &mut client,
            frame_type::RST_STREAM,
            0,
            1,
            &error_code::CANCEL.to_be_bytes(),
        )
        .unwrap();
        assert_eq!(
            h2_exchange_on(&mut client, over + 2, QUERY),
            QUERY,
            "클라이언트가 끊은 스트림의 자리가 돌아오지 않았습니다"
        );
        drop(client);
        let _ = server.join().unwrap();
    }

    #[test]
    /// An answer waiting for window keeps its stream slot until it is sent.
    fn answers_waiting_for_window_hold_their_stream_slots() {
        let (addr, server) = spawn_server(|query, _| answer(query.to_vec()));
        let mut client = h2_connect_with(addr, &initial_window(0));
        let block = doh_post_header_block();
        let over = MAX_H2_STREAMS as u32 * 2 + 1;
        for sid in (1..over).step_by(2) {
            open_stream(&mut client, sid, &block);
            send_frame(&mut client, frame_type::DATA, flags::END_STREAM, sid, QUERY).unwrap();
        }
        open_stream(&mut client, over, &block);
        let frames = barrier(&mut client);
        assert!(
            !frames.iter().any(|(h, _)| h.frame_type == frame_type::DATA),
            "대조군이 무효입니다. 창이 0인데 답을 보냈습니다"
        );
        assert_eq!(
            resets(&frames),
            vec![(over, error_code::REFUSED_STREAM)],
            "창을 기다리는 답이 스트림 자리를 차지하지 않았습니다"
        );

        let opened = initial_window(INITIAL_WINDOW as u32);
        send_frame(&mut client, frame_type::SETTINGS, 0, 0, &opened).unwrap();
        assert_eq!(
            h2_exchange_on(&mut client, over + 2, QUERY),
            QUERY,
            "보낸 답의 스트림 자리가 돌아오지 않았습니다"
        );
        drop(client);
        let _ = server.join().unwrap();
    }

    #[test]
    /// Answers waiting for window are bounded in bytes as well, and sending them returns the bytes.
    fn answers_waiting_for_window_are_bounded_in_bytes() {
        let (addr, server) = spawn_server(|_, _| answer(vec![0x5a; MAX_H2_RESPONSE]));
        let mut client = h2_connect_with(addr, &initial_window(0));
        let block = doh_post_header_block();
        let fit = (MAX_H2_BUFFERED_RESPONSES / MAX_H2_RESPONSE) as u32;
        let over = fit * 2 + 1;
        for sid in (1..=over).step_by(2) {
            open_stream(&mut client, sid, &block);
            send_frame(&mut client, frame_type::DATA, flags::END_STREAM, sid, QUERY).unwrap();
        }
        assert_eq!(
            resets(&barrier(&mut client)),
            vec![(over, error_code::REFUSED_STREAM)],
            "창을 기다리는 답의 바이트 상한을 넘은 스트림을 거절하지 않았습니다"
        );

        let opened = initial_window(INITIAL_WINDOW as u32);
        send_frame(&mut client, frame_type::SETTINGS, 0, 0, &opened).unwrap();
        let all_answers = MAX_H2_RESPONSE as u32 * (fit + 1);
        send_frame(
            &mut client,
            frame_type::WINDOW_UPDATE,
            0,
            0,
            &all_answers.to_be_bytes(),
        )
        .unwrap();
        assert_eq!(
            h2_exchange_on(&mut client, over + 2, QUERY).len(),
            MAX_H2_RESPONSE,
            "보낸 답의 바이트가 돌아오지 않았습니다"
        );
        drop(client);
        let _ = server.join().unwrap();
    }

    #[test]
    /// A request body is cut past MAX_H2_BODY, and the bodies of all open streams past
    /// MAX_H2_BUFFERED_REQUESTS. A stream cut early would draw a second reset from its next DATA
    /// frame, so the exact reset lists also pin the boundaries.
    fn request_bodies_are_bounded_per_stream_and_per_connection() {
        let (addr, server) = spawn_server(|query, _| answer(query.to_vec()));
        let mut client = h2_connect(addr);
        let block = doh_post_header_block();
        open_stream(&mut client, 1, &block);
        send_body(&mut client, 1, MAX_H2_BODY + 1);
        assert_eq!(
            resets(&barrier(&mut client)),
            vec![(1, error_code::CANCEL)],
            "본문 상한을 넘은 스트림을 끊지 않았습니다"
        );

        let fit = (MAX_H2_BUFFERED_REQUESTS / MAX_H2_BODY) as u32;
        let first = 3;
        let over = first + fit * 2;
        for sid in (first..over).step_by(2) {
            open_stream(&mut client, sid, &block);
            send_body(&mut client, sid, MAX_H2_BODY);
        }
        open_stream(&mut client, over, &block);
        send_body(&mut client, over, 1);
        assert_eq!(
            resets(&barrier(&mut client)),
            vec![(over, error_code::CANCEL)],
            "연결 전체의 본문 상한을 넘은 스트림을 끊지 않았습니다"
        );

        send_frame(
            &mut client,
            frame_type::RST_STREAM,
            0,
            first,
            &error_code::CANCEL.to_be_bytes(),
        )
        .unwrap();
        open_stream(&mut client, over + 2, &block);
        send_body(&mut client, over + 2, MAX_H2_BODY);
        assert_eq!(
            resets(&barrier(&mut client)),
            vec![],
            "클라이언트가 끊은 스트림의 본문 몫이 돌아오지 않았습니다"
        );
        drop(client);
        let _ = server.join().unwrap();
    }

    /// A request header block that decodes to nearly MAX_H2_HEADER_BLOCK but stays small on the
    /// wire, by repeating one dynamic table entry. `insert` adds the entry first.
    fn bulky_header_block(insert: bool) -> Vec<u8> {
        const NAME: &[u8] = b"x-pad";
        const VALUE_LEN: usize = 4000;
        let mut block = doh_post_header_block();
        let mut copies = 8;
        if insert {
            block.push(0x40);
            hpack::encode_int(&mut block, NAME.len() as u64, 7, 0);
            block.extend_from_slice(NAME);
            hpack::encode_int(&mut block, VALUE_LEN as u64, 7, 0);
            block.resize(block.len() + VALUE_LEN, b'a');
            copies -= 1;
        }
        // Index 62 is the newest dynamic table entry.
        block.extend(std::iter::repeat_n(0xbe, copies));
        block
    }

    #[test]
    fn buffered_header_lists_are_connection_bounded() {
        let (addr, server) = spawn_server(|query, _| answer(query.to_vec()));
        let mut client = h2_connect(addr);
        let decoded = Decoder::new(4096)
            .decode(&bulky_header_block(true))
            .unwrap();
        let per_stream = header_list_size(&decoded);
        assert!(
            per_stream <= MAX_H2_HEADER_BLOCK,
            "대조군이 무효입니다. 스트림 하나의 헤더가 이미 상한을 넘습니다"
        );
        let fit = (MAX_H2_BUFFERED_HEADERS / per_stream) as u32;
        let over = fit * 2 + 1;
        open_stream(&mut client, 1, &bulky_header_block(true));
        for sid in (3..=over).step_by(2) {
            open_stream(&mut client, sid, &bulky_header_block(false));
        }
        assert_eq!(
            resets(&barrier(&mut client)),
            vec![(over, error_code::CANCEL)],
            "연결 전체의 헤더 상한을 넘은 스트림을 끊지 않았습니다"
        );

        send_frame(
            &mut client,
            frame_type::RST_STREAM,
            0,
            1,
            &error_code::CANCEL.to_be_bytes(),
        )
        .unwrap();
        open_stream(&mut client, over + 2, &bulky_header_block(false));
        assert_eq!(
            resets(&barrier(&mut client)),
            vec![],
            "클라이언트가 끊은 스트림의 헤더 몫이 돌아오지 않았습니다"
        );
        drop(client);
        let _ = server.join().unwrap();
    }

    #[test]
    fn base64url_roundtrip() {
        let data = vec![0u8, 1, 2, 250, 255, 128, 64];
        let enc = base64url_encode(&data);
        assert_eq!(base64url_decode(enc.as_bytes()).unwrap(), data);
        assert!(base64url_decode(b"YQ==").is_none());
        assert!(base64url_decode(b"A").is_none());
        assert!(base64url_decode(b"YR").is_none());
    }

    fn h1_request(addr: std::net::SocketAddr, raw: &[u8]) -> Vec<u8> {
        let mut c = deadline_connect(addr);
        c.write_all(raw).unwrap();
        let mut resp = Vec::new();
        c.read_to_end(&mut resp).unwrap();
        resp
    }

    fn run_h1(get: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut s = deadline_accept(&listener);
            serve_doh_h1(&mut s, "/dns-query", |q, _id| {
                let mut r = q.to_vec();
                r.reverse();
                answer(r)
            })
            .ok();
        });

        let query = vec![0xABu8, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00];
        let raw = if get {
            let b64 = base64url_encode(&query);
            format!("GET /dns-query?dns={b64} HTTP/1.1\r\nHost: dns.test\r\nAccept: application/dns-message\r\n\r\n")
                .into_bytes()
        } else {
            let mut v = format!(
                "POST /dns-query HTTP/1.1\r\nHost: dns.test\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                query.len()
            )
            .into_bytes();
            v.extend_from_slice(&query);
            v
        };
        let resp = h1_request(addr, &raw);
        let split = find_sub(&resp, b"\r\n\r\n").unwrap();
        let head = std::str::from_utf8(&resp[..split]).unwrap();
        assert!(head.starts_with("HTTP/1.1 200"), "200 응답: {head}");
        let body = &resp[split + 4..];
        let mut expected = query.clone();
        expected.reverse();
        assert_eq!(body, &expected[..]);
        drop(server);
    }

    #[test]
    /// RFC 8484 has DoH clients read status codes like any HTTP client. A 5xx means a server fault:
    /// the client resends to the same server, and server error metrics fill with request errors. An
    /// unreadable body is a request error, and HTTP/1.1 and HTTP/2 must agree.
    fn doh_body_rejections_are_client_errors_not_server_errors() {
        /// Sends one request and returns only the status line.
        fn status_for(reply: &'static str) -> String {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                let mut s = deadline_accept(&listener);
                serve_doh_h1(&mut s, "/dns-query", move |_q, _id| Err(reply)).ok();
            });
            let raw = b"POST /dns-query HTTP/1.1\r\nHost: dns.test\r\nContent-Type: application/dns-message\r\nContent-Length: 3\r\n\r\ndns";
            let resp = String::from_utf8_lossy(&h1_request(addr, raw)).to_string();
            server.join().unwrap();
            resp.lines().next().unwrap_or_default().to_string()
        }

        assert!(
            status_for("400").contains(" 400 "),
            "읽지 못한 본문은 요청 잘못이므로 4xx 여야 합니다: {}",
            status_for("400")
        );
        assert!(
            status_for("403").contains(" 403 "),
            "신원이 어긋난 것은 403 이어야 합니다: {}",
            status_for("403")
        );
        assert!(
            status_for("502").contains(" 502 "),
            "답을 만들지 못한 것만 5xx 입니다: {}",
            status_for("502")
        );

        // HTTP/2 must give the same status.
        let mut output = Vec::new();
        let mut pending = HashMap::new();
        let mut windows = HashMap::from([(1, INITIAL_WINDOW)]);
        queue_response(
            &mut output,
            1,
            AppResponse::Status(STATUS_BAD_REQUEST),
            &mut pending,
            &mut windows,
        )
        .unwrap();
        let mut wire = std::io::Cursor::new(output);
        let (frame_header, payload) = read_frame(&mut wire).unwrap();
        let block = strip_headers(&payload, frame_header.flags).unwrap();
        let decoded = Decoder::new(4096).decode(block).unwrap();
        assert!(
            decoded
                .iter()
                .any(|(name, value)| name == b":status" && value == b"400"),
            "HTTP/2 경로가 다른 상태를 냈습니다"
        );
    }

    #[test]
    /// A 5xx instead would make the client resend the query; neither a status line nor HEADERS may
    /// go out.
    fn withheld_answers_end_the_connection_without_a_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut stream = deadline_accept(&listener);
            serve_doh(&mut stream, "/dns-query", |_, _| Ok(None))
        });
        let mut client = deadline_connect(addr);
        client.write_all(frame::PREFACE).unwrap();
        send_frame(&mut client, frame_type::SETTINGS, 0, 0, &[]).unwrap();
        let path = format!(
            "/dns-query?dns={}",
            base64url_encode(&[0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00])
        );
        let block = hpack::encode_response(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "dns.test"),
            (":path", &path),
            ("accept", "application/dns-message"),
        ]);
        send_frame(
            &mut client,
            frame_type::HEADERS,
            flags::END_HEADERS | flags::END_STREAM,
            1,
            &block,
        )
        .unwrap();
        let mut frames = Vec::new();
        while let Ok((frame_header, _)) = read_frame(&mut client) {
            frames.push(frame_header.frame_type);
        }
        assert!(
            matches!(server.join().unwrap(), Ok(())),
            "답하지 않기로 한 것을 HTTP/2 연결 오류로 끝냈습니다"
        );
        assert!(
            frames.iter().all(|kind| *kind == frame_type::SETTINGS),
            "답하지 않기로 한 요청에 HTTP/2 프레임을 보냈습니다: {frames:?}"
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut stream = deadline_accept(&listener);
            serve_doh_h1(&mut stream, "/dns-query", |_, _| Ok(None))
        });
        let raw = b"POST /dns-query HTTP/1.1\r\nHost: dns.test\r\nContent-Type: application/dns-message\r\nContent-Length: 3\r\n\r\ndns";
        let response = h1_request(addr, raw);
        assert!(
            matches!(server.join().unwrap(), Ok(())),
            "답하지 않기로 한 것을 HTTP/1.1 연결 오류로 끝냈습니다"
        );
        assert!(
            response.is_empty(),
            "답하지 않기로 한 요청에 HTTP/1.1 응답을 보냈습니다: {}",
            String::from_utf8_lossy(&response)
        );
    }

    #[test]
    /// RFC 8484 requires explicit freshness no longer than the minimum TTL of the answer section.
    fn doh_responses_declare_their_freshness() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut s = deadline_accept(&listener);
            serve_doh_h1(&mut s, "/dns-query", |_q, _id| {
                Ok(Some(DohAnswer {
                    body: vec![1, 2, 3],
                    max_age: 137,
                }))
            })
            .ok();
        });
        let raw = b"POST /dns-query HTTP/1.1\r\nHost: dns.test\r\nContent-Type: application/dns-message\r\nContent-Length: 3\r\n\r\ndns";
        let resp = String::from_utf8_lossy(&h1_request(addr, raw)).to_ascii_lowercase();
        server.join().unwrap();
        assert!(
            resp.contains("cache-control: max-age=137"),
            "HTTP/1.1 응답에 신선도가 없습니다: {resp}"
        );

        let mut output = Vec::new();
        let mut pending = HashMap::new();
        let mut windows = HashMap::from([(1, INITIAL_WINDOW)]);
        queue_response(
            &mut output,
            1,
            AppResponse::Dns(DohAnswer {
                body: vec![1, 2, 3],
                max_age: 42,
            }),
            &mut pending,
            &mut windows,
        )
        .unwrap();
        let mut wire = std::io::Cursor::new(output);
        let (frame_header, payload) = read_frame(&mut wire).unwrap();
        assert_eq!(frame_header.frame_type, frame_type::HEADERS);
        let block = strip_headers(&payload, frame_header.flags).unwrap();
        let decoded = Decoder::new(4096).decode(block).unwrap();
        assert_eq!(
            header(&decoded, b"cache-control"),
            Some(b"max-age=42".as_slice()),
            "HTTP/2 응답에 신선도가 없습니다"
        );
    }

    #[test]
    fn doh_h1_post_roundtrip() {
        run_h1(false);
    }

    #[test]
    fn doh_h1_get_roundtrip() {
        run_h1(true);
    }

    #[test]
    fn doh_h1_rejects_bad_path() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut s = deadline_accept(&listener);
            serve_doh_h1(&mut s, "/dns-query", |_q, _id| answer(vec![1, 2, 3])).ok();
        });
        let resp = h1_request(addr, b"GET /wrong HTTP/1.1\r\nHost: x\r\n\r\n");
        let head = std::str::from_utf8(&resp).unwrap();
        assert!(head.starts_with("HTTP/1.1 404"), "404: {head}");
        drop(server);
    }

    fn h1_status(raw: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut stream = deadline_accept(&listener);
            serve_doh_h1(&mut stream, "/dns-query", |query, _| answer(query.to_vec())).ok();
        });
        let response = h1_request(addr, &raw);
        server.join().unwrap();
        String::from_utf8(response).unwrap()
    }

    #[test]
    /// RFC 9110 requires Allow on a 405; without it the client cannot know which method to retry
    /// with.
    fn method_not_allowed_lists_the_methods_we_take() {
        let put = b"PUT /dns-query HTTP/1.1\r\nHost: dns.test\r\nContent-Type: application/dns-message\r\nContent-Length: 3\r\n\r\ndns";
        let response = h1_status(put.to_vec());
        assert!(response.starts_with("HTTP/1.1 405"), "{response:?}");
        assert!(
            response.to_ascii_lowercase().contains("allow: get, post"),
            "405 에 Allow 가 없습니다: {response:?}"
        );
    }

    #[test]
    /// Accepting one would let a single request be read as two.
    fn doh_h1_rejects_malformed_or_ambiguous_requests() {
        let no_type = b"POST /dns-query HTTP/1.1\r\nHost: dns.test\r\nContent-Length: 3\r\n\r\ndns";
        let status = h1_status(no_type.to_vec());
        assert!(status.starts_with("HTTP/1.1 415"), "{status:?}");

        let bad_line = b"POST /dns-query HTTP/1.1 extra\r\nHost: dns.test\r\n\r\n";
        assert!(h1_status(bad_line.to_vec()).starts_with("HTTP/1.1 400"));

        let malformed_header = b"GET /dns-query?dns=ZG5z HTTP/1.1\r\nHost dns.test\r\n\r\n";
        assert!(h1_status(malformed_header.to_vec()).starts_with("HTTP/1.1 400"));

        let get_body =
            b"GET /dns-query?dns=ZG5z HTTP/1.1\r\nHost: dns.test\r\nContent-Length: 1\r\n\r\nx";
        assert!(h1_status(get_body.to_vec()).starts_with("HTTP/1.1 400"));

        let signed_length = b"POST /dns-query HTTP/1.1\r\nHost: dns.test\r\nContent-Type: application/dns-message\r\nContent-Length: +3\r\n\r\ndns";
        assert!(h1_status(signed_length.to_vec()).starts_with("HTTP/1.1 400"));

        let control_in_value =
            b"GET /dns-query?dns=ZG5z HTTP/1.1\r\nHost: dns.test\r\nX-Test: a\0b\r\n\r\n";
        assert!(h1_status(control_in_value.to_vec()).starts_with("HTTP/1.1 400"));

        let mut oversized =
            b"GET /dns-query?dns=ZG5z HTTP/1.1\r\nHost: dns.test\r\nX-Fill: ".to_vec();
        oversized.extend(std::iter::repeat_n(b'a', MAX_H1_HEADERS));
        oversized.extend_from_slice(b"\r\n\r\n");
        assert!(h1_status(oversized).starts_with("HTTP/1.1 431"));
    }

    #[test]
    fn doh_h1_caps_handler_response_to_dns_message_size() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut stream = deadline_accept(&listener);
            serve_doh_h1(&mut stream, "/dns-query", |_, _| {
                answer(vec![0; MAX_H2_RESPONSE + 1])
            })
            .ok();
        });
        let raw = b"POST /dns-query HTTP/1.1\r\nHost: dns.test\r\nContent-Type: application/dns-message\r\nContent-Length: 3\r\n\r\ndns";
        let response = h1_request(addr, raw);
        server.join().unwrap();
        assert!(response.starts_with(b"HTTP/1.1 502"));
    }

    #[test]
    /// Uncounted pending responses would make the limit meaningless.
    fn pending_responses_consume_concurrent_stream_budget() {
        let streams = HashMap::new();
        let pending = (0..MAX_H2_STREAMS)
            .map(|index| {
                (
                    (index as u32) * 2 + 1,
                    PendingBody {
                        body: vec![0],
                        offset: 0,
                    },
                )
            })
            .collect();
        assert_eq!(concurrent_streams(&streams, &pending), MAX_H2_STREAMS);
    }

    #[test]
    fn pending_response_bytes_are_connection_bounded() {
        let mut output = Vec::new();
        let mut pending = HashMap::from([(
            1,
            PendingBody {
                body: vec![0; MAX_H2_BUFFERED_RESPONSES],
                offset: 0,
            },
        )]);
        let mut windows = HashMap::from([(3, INITIAL_WINDOW)]);
        queue_response(
            &mut output,
            3,
            AppResponse::Dns(DohAnswer {
                body: vec![1],
                max_age: 0,
            }),
            &mut pending,
            &mut windows,
        )
        .unwrap();
        assert!(!pending.contains_key(&3));
        assert!(!windows.contains_key(&3));

        let mut wire = std::io::Cursor::new(output);
        let (header, payload) = read_frame(&mut wire).unwrap();
        assert_eq!(header.frame_type, frame_type::RST_STREAM);
        assert_eq!(header.stream_id, 3);
        assert_eq!(payload, error_code::REFUSED_STREAM.to_be_bytes());
    }

    /// Reverses the message; "unknown" stands for another key, "drop" for a relay refused outright
    /// and "unanswered" for a query the resolver does not answer.
    struct EchoTarget {
        is_target: bool,
    }

    impl Oblivious for EchoTarget {
        fn configs(&self) -> Option<Vec<u8>> {
            self.is_target.then(|| b"configs".to_vec())
        }

        fn target(&self, message: &[u8]) -> ObliviousReply {
            match message {
                b"unknown" => ObliviousReply::Status("401"),
                b"drop" => ObliviousReply::Drop,
                b"unanswered" => ObliviousReply::Unanswered,
                _ => ObliviousReply::Message(message.iter().rev().copied().collect()),
            }
        }

        /// Echoes where it would relay; a few hosts stand for the ways a relay ends.
        fn proxy(&self, target_host: &str, target_path: &str, message: &[u8]) -> ObliviousReply {
            match target_host {
                "denied.example" => ObliviousReply::ProxyError {
                    status: "403",
                    error: "http_request_denied",
                },
                "down.example" => ObliviousReply::ProxyError {
                    status: "502",
                    error: "connection_refused",
                },
                "rotated.example" => ObliviousReply::TargetStatus(401),
                _ => {
                    let mut echoed = format!("{target_host} {target_path} ").into_bytes();
                    echoed.extend_from_slice(message);
                    ObliviousReply::Message(echoed)
                }
            }
        }
    }

    /// Reverses the request; "unknown" stands for a key it does not hold and "unanswered" for a
    /// query the resolver does not answer.
    struct EchoGateway;

    impl Gateway for EchoGateway {
        fn keys(&self) -> Vec<u8> {
            b"keys".to_vec()
        }

        fn answer(&self, encapsulated: &[u8]) -> GatewayReply {
            match encapsulated {
                b"unknown" => GatewayReply::Status("422"),
                b"unanswered" => GatewayReply::Unanswered,
                _ => GatewayReply::Response(encapsulated.iter().rev().copied().collect()),
            }
        }
    }

    fn h1_oblivious(raw: Vec<u8>, oblivious: Option<EchoTarget>) -> String {
        h1_serve(raw, oblivious, None)
    }

    fn h1_serve(
        raw: Vec<u8>,
        oblivious: Option<EchoTarget>,
        gateway: Option<EchoGateway>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut s = deadline_accept(&listener);
            serve_doh_h1_with_deadline_reset(
                &mut s,
                "/dns-query",
                |q, _| answer(q.to_vec()),
                |_| {},
                oblivious.as_ref().map(|target| target as &dyn Oblivious),
                gateway.as_ref().map(|gateway| gateway as &dyn Gateway),
            )
            .ok();
        });
        let response = String::from_utf8_lossy(&h1_request(addr, &raw)).to_string();
        server.join().unwrap();
        response
    }

    fn h1_gateway_post(
        path: &str,
        content_type: &str,
        body: &[u8],
        gateway: Option<EchoGateway>,
    ) -> String {
        let mut raw = format!(
            "POST {path} HTTP/1.1\r\nHost: dns.test\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        raw.extend_from_slice(body);
        h1_serve(raw, None, gateway)
    }

    #[test]
    fn h1_routes_encapsulated_requests_to_the_gateway() {
        let post = |body: &[u8]| {
            h1_gateway_post(
                OHTTP_GATEWAY_PATH,
                OHTTP_REQUEST_MEDIA_TYPE,
                body,
                Some(EchoGateway),
            )
        };
        let response = post(b"abc");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.contains("\r\ncontent-type: message/ohttp-res\r\n"));
        assert!(response.contains("\r\ncache-control: private, no-store\r\n"));
        assert!(response.ends_with("\r\n\r\ncba"), "{response}");

        let unknown = post(b"unknown");
        assert!(
            unknown.starts_with("HTTP/1.1 422 Unprocessable Content\r\n"),
            "{unknown}"
        );
        assert_eq!(post(b"unanswered"), "");
        let empty = post(b"");
        assert!(empty.starts_with("HTTP/1.1 400 "), "{empty}");

        let get = format!("GET {OHTTP_GATEWAY_PATH} HTTP/1.1\r\nHost: dns.test\r\nAccept: application/ohttp-keys\r\n\r\n")
            .into_bytes();
        let keys = h1_serve(get.clone(), None, Some(EchoGateway));
        assert!(keys.starts_with("HTTP/1.1 200 OK\r\n"), "{keys}");
        assert!(keys.contains("\r\ncontent-type: application/ohttp-keys\r\n"));
        assert!(keys.ends_with("\r\n\r\nkeys"), "{keys}");
        let no_gateway = h1_serve(get, None, None);
        assert!(no_gateway.starts_with("HTTP/1.1 404 "), "{no_gateway}");
    }

    #[test]
    /// The gateway takes encapsulated requests at its own path only, and its path is not a DoH path.
    fn h1_refuses_gateway_requests_it_cannot_serve() {
        let at_doh_path = h1_gateway_post(
            "/dns-query",
            OHTTP_REQUEST_MEDIA_TYPE,
            b"abc",
            Some(EchoGateway),
        );
        assert!(at_doh_path.starts_with("HTTP/1.1 404 "), "{at_doh_path}");
        let no_gateway =
            h1_gateway_post(OHTTP_GATEWAY_PATH, OHTTP_REQUEST_MEDIA_TYPE, b"abc", None);
        assert!(no_gateway.starts_with("HTTP/1.1 415 "), "{no_gateway}");
        let wrong_type =
            h1_gateway_post(OHTTP_GATEWAY_PATH, "text/plain", b"abc", Some(EchoGateway));
        assert!(wrong_type.starts_with("HTTP/1.1 415 "), "{wrong_type}");
        let dns_query = h1_gateway_post(
            OHTTP_GATEWAY_PATH,
            "application/dns-message",
            b"dns",
            Some(EchoGateway),
        );
        assert!(dns_query.starts_with("HTTP/1.1 404 "), "{dns_query}");
    }

    fn h1_oblivious_post(path: &str, body: &[u8], oblivious: Option<EchoTarget>) -> String {
        let mut raw = format!(
            "POST {path} HTTP/1.1\r\nHost: dns.test\r\nContent-Type: application/oblivious-dns-message\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        raw.extend_from_slice(body);
        h1_oblivious(raw, oblivious)
    }

    const TARGET: Option<EchoTarget> = Some(EchoTarget { is_target: true });

    #[test]
    fn h1_routes_oblivious_messages_to_the_target() {
        let response = h1_oblivious_post("/dns-query", b"abc", TARGET);
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.contains("\r\ncontent-type: application/oblivious-dns-message\r\n"));
        assert!(response.contains("\r\ncache-control: no-cache, no-store\r\n"));
        assert!(response.ends_with("\r\n\r\ncba"), "{response}");

        let unknown = h1_oblivious_post("/dns-query", b"unknown", TARGET);
        assert!(unknown.starts_with("HTTP/1.1 401 "), "{unknown}");
        assert_eq!(h1_oblivious_post("/dns-query", b"drop", TARGET), "");
        assert_eq!(h1_oblivious_post("/dns-query", b"unanswered", TARGET), "");
        let empty = h1_oblivious_post("/dns-query", b"", TARGET);
        assert!(empty.starts_with("HTTP/1.1 400 "), "{empty}");
    }

    #[test]
    /// A client ID in the path means nothing for a relayed message, and a listener that is not a
    /// target treats the type like any other it does not take.
    fn h1_refuses_oblivious_messages_it_cannot_serve() {
        let with_id = h1_oblivious_post("/dns-query/laptop", b"abc", TARGET);
        assert!(with_id.starts_with("HTTP/1.1 404 "), "{with_id}");
        let other_path = h1_oblivious_post("/other", b"abc", TARGET);
        assert!(other_path.starts_with("HTTP/1.1 404 "), "{other_path}");
        let no_service = h1_oblivious_post("/dns-query", b"abc", None);
        assert!(no_service.starts_with("HTTP/1.1 415 "), "{no_service}");
    }

    #[test]
    fn h1_routes_proxy_requests_by_their_variables() {
        let relayed = h1_oblivious_post(
            "/dns-query?targethost=odoh.example&targetpath=%2Fdns%2Dquery",
            b"abc",
            TARGET,
        );
        assert!(relayed.starts_with("HTTP/1.1 200 OK\r\n"), "{relayed}");
        assert!(relayed.contains("\r\ncontent-type: application/oblivious-dns-message\r\n"));
        assert!(relayed.contains("\r\ncache-control: no-cache, no-store\r\n"));
        assert!(
            relayed.ends_with("\r\n\r\nodoh.example /dns-query abc"),
            "{relayed}"
        );

        let denied = h1_oblivious_post(
            "/dns-query?targethost=denied.example&targetpath=/q",
            b"abc",
            TARGET,
        );
        assert!(denied.starts_with("HTTP/1.1 403 "), "{denied}");
        assert!(denied.contains("\r\nproxy-status: OnetDNS; error=http_request_denied\r\n"));

        let down = h1_oblivious_post(
            "/dns-query?targethost=down.example&targetpath=/q",
            b"abc",
            TARGET,
        );
        assert!(down.starts_with("HTTP/1.1 502 "), "{down}");
        assert!(down.contains("\r\nproxy-status: OnetDNS; error=connection_refused\r\n"));

        let rotated = h1_oblivious_post(
            "/dns-query?targethost=rotated.example&targetpath=/q",
            b"abc",
            TARGET,
        );
        assert!(rotated.starts_with("HTTP/1.1 401 "), "{rotated}");
        assert!(rotated.contains("\r\nproxy-status: OnetDNS; received-status=401\r\n"));
    }

    #[test]
    fn malformed_proxy_variables_are_request_errors() {
        for query in [
            "targethost=odoh.example",
            "targetpath=/dns-query",
            "targethost=a.example&targethost=b.example&targetpath=/q",
            "targethost=odoh.example&targetpath=dns-query",
            "targethost=odoh%zz.example&targetpath=/q",
            "targethost=odoh%2.example&targetpath=/q",
            "targethost=odoh%20.example&targetpath=/q",
            "targethost=&targetpath=/q",
        ] {
            let response = h1_oblivious_post(&format!("/dns-query?{query}"), b"abc", TARGET);
            assert!(response.starts_with("HTTP/1.1 400 "), "{query}: {response}");
            assert!(
                response.contains("\r\nproxy-status: OnetDNS; error=http_request_error\r\n"),
                "{query}: {response}"
            );
        }
        assert_eq!(
            proxy_target(b"/dns-query?ct=1&targetpath=%2Fq&targethost=Odoh.Example"),
            Ok(Some(("Odoh.Example".to_string(), "/q".to_string()))),
            "other variables are ignored, and case is the caller's to judge"
        );
        assert_eq!(proxy_target(b"/dns-query?dns=AAAB"), Ok(None));
    }

    #[test]
    fn h1_serves_configs_only_on_a_target() {
        let get = b"GET /.well-known/odohconfigs HTTP/1.1\r\nHost: dns.test\r\n\r\n".to_vec();
        let response = h1_oblivious(get.clone(), TARGET);
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.contains("\r\ncontent-type: application/octet-stream\r\n"));
        assert!(response.ends_with("\r\n\r\nconfigs"), "{response}");

        let not_target = h1_oblivious(get.clone(), Some(EchoTarget { is_target: false }));
        assert!(not_target.starts_with("HTTP/1.1 404 "), "{not_target}");
        let plain = h1_oblivious(get, None);
        assert!(plain.starts_with("HTTP/1.1 404 "), "{plain}");
    }

    /// Sends one request on a stream and returns the response header fields and body.
    fn h2_request_on(
        client: &mut TcpStream,
        sid: u32,
        fields: &[(&str, &str)],
        body: &[u8],
    ) -> (Vec<(Vec<u8>, Vec<u8>)>, Vec<u8>) {
        let header_flags = if body.is_empty() {
            flags::END_HEADERS | flags::END_STREAM
        } else {
            flags::END_HEADERS
        };
        let block = hpack::encode_response(fields);
        send_frame(client, frame_type::HEADERS, header_flags, sid, &block).unwrap();
        if !body.is_empty() {
            send_frame(client, frame_type::DATA, flags::END_STREAM, sid, body).unwrap();
        }
        let mut headers = Vec::new();
        let mut response = Vec::new();
        let mut dec = Decoder::new(4096);
        loop {
            let (h, payload) = read_frame(client).expect("the server closed mid-response");
            match h.frame_type {
                frame_type::HEADERS if h.stream_id == sid => {
                    headers = dec
                        .decode(strip_headers(&payload, h.flags).unwrap())
                        .unwrap();
                    if h.has_flag(flags::END_STREAM) {
                        break;
                    }
                }
                frame_type::DATA if h.stream_id == sid => {
                    response.extend_from_slice(strip_padding(&payload, h.flags).unwrap());
                    if h.has_flag(flags::END_STREAM) {
                        break;
                    }
                }
                frame_type::SETTINGS if !h.has_flag(flags::ACK) => {
                    send_frame(client, frame_type::SETTINGS, flags::ACK, 0, &[]).unwrap();
                }
                _ => {}
            }
        }
        (headers, response)
    }

    #[test]
    fn h2_serves_oblivious_messages_and_configs_beside_doh() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut s = deadline_accept(&listener);
            let target = EchoTarget { is_target: true };
            serve_doh_with_deadline_reset(
                &mut s,
                "/dns-query",
                |q, _| answer(q.to_vec()),
                |_| {},
                &AtomicBool::new(false),
                Some(&target),
                None,
            )
            .ok();
        });
        let mut client = h2_connect(addr);
        let post = |path| {
            [
                (":method", "POST"),
                (":scheme", "https"),
                (":authority", "dns.test"),
                (":path", path),
                ("content-type", ODOH_MEDIA_TYPE),
            ]
        };

        let (headers, body) = h2_request_on(&mut client, 1, &post("/dns-query"), b"abc");
        assert_eq!(header(&headers, b":status"), Some(&b"200"[..]));
        assert_eq!(
            header(&headers, b"content-type"),
            Some(ODOH_MEDIA_TYPE.as_bytes())
        );
        assert_eq!(
            header(&headers, b"cache-control"),
            Some(&b"no-cache, no-store"[..])
        );
        assert_eq!(body, b"cba");

        let (headers, _) = h2_request_on(&mut client, 3, &post("/dns-query"), b"unknown");
        assert_eq!(header(&headers, b":status"), Some(&b"401"[..]));
        let (headers, _) = h2_request_on(&mut client, 5, &post("/dns-query/laptop"), b"abc");
        assert_eq!(header(&headers, b":status"), Some(&b"404"[..]));

        let block = hpack::encode_response(&post("/dns-query"));
        open_stream(&mut client, 7, &block);
        send_frame(
            &mut client,
            frame_type::DATA,
            flags::END_STREAM,
            7,
            b"unanswered",
        )
        .unwrap();
        assert_eq!(
            resets(&barrier(&mut client)),
            vec![(7, error_code::CANCEL)],
            "an unanswered message must end its own stream, not the proxy's connection"
        );

        let get = [
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "dns.test"),
            (":path", ODOH_CONFIGS_PATH),
        ];
        let (headers, body) = h2_request_on(&mut client, 9, &get, b"");
        assert_eq!(header(&headers, b":status"), Some(&b"200"[..]));
        assert_eq!(body, b"configs");

        assert_eq!(h2_exchange_on(&mut client, 11, b"dns"), b"dns");
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn h2_serves_the_gateway_beside_doh() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut s = deadline_accept(&listener);
            serve_doh_with_deadline_reset(
                &mut s,
                "/dns-query",
                |q, _| answer(q.to_vec()),
                |_| {},
                &AtomicBool::new(false),
                None,
                Some(&EchoGateway),
            )
            .ok();
        });
        let mut client = h2_connect(addr);
        let post = |path, content_type| {
            [
                (":method", "POST"),
                (":scheme", "https"),
                (":authority", "dns.test"),
                (":path", path),
                ("content-type", content_type),
            ]
        };
        let encapsulated = post(OHTTP_GATEWAY_PATH, OHTTP_REQUEST_MEDIA_TYPE);

        let (headers, body) = h2_request_on(&mut client, 1, &encapsulated, b"abc");
        assert_eq!(header(&headers, b":status"), Some(&b"200"[..]));
        assert_eq!(
            header(&headers, b"content-type"),
            Some(OHTTP_RESPONSE_MEDIA_TYPE.as_bytes())
        );
        assert_eq!(
            header(&headers, b"cache-control"),
            Some(&b"private, no-store"[..])
        );
        assert_eq!(body, b"cba");

        let (headers, _) = h2_request_on(&mut client, 3, &encapsulated, b"unknown");
        assert_eq!(header(&headers, b":status"), Some(&b"422"[..]));
        let at_doh_path = post("/dns-query", OHTTP_REQUEST_MEDIA_TYPE);
        let (headers, _) = h2_request_on(&mut client, 5, &at_doh_path, b"abc");
        assert_eq!(header(&headers, b":status"), Some(&b"404"[..]));
        let wrong_type = post(OHTTP_GATEWAY_PATH, "text/plain");
        let (headers, _) = h2_request_on(&mut client, 7, &wrong_type, b"abc");
        assert_eq!(header(&headers, b":status"), Some(&b"415"[..]));

        let block = hpack::encode_response(&encapsulated);
        open_stream(&mut client, 9, &block);
        send_frame(
            &mut client,
            frame_type::DATA,
            flags::END_STREAM,
            9,
            b"unanswered",
        )
        .unwrap();
        assert_eq!(
            resets(&barrier(&mut client)),
            vec![(9, error_code::CANCEL)],
            "an unanswered request must end its own stream, not the relay's connection"
        );

        let get = [
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "dns.test"),
            (":path", OHTTP_GATEWAY_PATH),
            ("accept", OHTTP_KEYS_MEDIA_TYPE),
        ];
        let (headers, body) = h2_request_on(&mut client, 11, &get, b"");
        assert_eq!(header(&headers, b":status"), Some(&b"200"[..]));
        assert_eq!(
            header(&headers, b"content-type"),
            Some(OHTTP_KEYS_MEDIA_TYPE.as_bytes())
        );
        assert_eq!(body, b"keys");

        assert_eq!(h2_exchange_on(&mut client, 13, b"dns"), b"dns");
        drop(client);
        server.join().unwrap();
    }

    #[test]
    /// The client half of ODoH: configs by GET, messages by POST, and a stale key as status 401.
    fn h2_client_fetches_configs_and_sends_oblivious_messages() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut s = deadline_accept(&listener);
            let target = EchoTarget { is_target: true };
            serve_doh_with_deadline_reset(
                &mut s,
                "/dns-query",
                |q, _| answer(q.to_vec()),
                |_| {},
                &AtomicBool::new(false),
                Some(&target),
                None,
            )
            .ok();
        });
        let mut client = crate::H2Client::connect(deadline_connect(addr)).unwrap();
        assert_eq!(client.odoh_configs("dns.test").unwrap(), b"configs");
        assert_eq!(
            client
                .oblivious_probed("dns.test", "/dns-query", b"abc", |_| {})
                .unwrap(),
            b"cba"
        );
        assert!(matches!(
            client.oblivious_probed("dns.test", "/dns-query", b"unknown", |_| {}),
            Err(H2Error::BadStatus(401))
        ));
        assert_eq!(
            client.query("dns.test", "/dns-query", b"dns").unwrap(),
            b"dns",
            "the connection stays usable after an error status"
        );
        drop(client);
        server.join().unwrap();
    }
}
