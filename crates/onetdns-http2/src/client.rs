use std::io::{Read, Write};

use crate::frame::{error_code, flags, frame_type, settings, DEFAULT_MAX_FRAME};
use crate::hpack::{self, Decoder};
use crate::wire::{read_frame, send_frame, strip_headers, strip_padding};
use crate::{valid_header_field, H2Error};

/// The largest DNS message.
const MAX_DNS_RESPONSE: usize = u16::MAX as usize;

/// The media type a POST carries, the one a 200 response must carry back, and the body cap. A GET
/// without a response media type takes any.
#[derive(Clone, Copy)]
struct Payload {
    request_type: Option<&'static str>,
    response_type: Option<&'static str>,
    max_body: usize,
}

const DNS: Payload = Payload {
    request_type: Some("application/dns-message"),
    response_type: Some("application/dns-message"),
    max_body: MAX_DNS_RESPONSE,
};

const OBLIVIOUS: Payload = Payload {
    request_type: Some(crate::server::ODOH_MEDIA_TYPE),
    response_type: Some(crate::server::ODOH_MEDIA_TYPE),
    max_body: crate::server::MAX_ODOH_MESSAGE,
};

const OHTTP: Payload = Payload {
    request_type: Some(crate::server::OHTTP_REQUEST_MEDIA_TYPE),
    response_type: Some(crate::server::OHTTP_RESPONSE_MEDIA_TYPE),
    max_body: crate::server::MAX_OHTTP_RESPONSE,
};

/// ObliviousDoHConfigs: a list with a 16-bit length. Targets serve it with differing media types.
const ODOH_CONFIGS: Payload = Payload {
    request_type: None,
    response_type: None,
    max_body: 2 + u16::MAX as usize,
};

/// What an opaque relayed POST carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObliviousMedia {
    /// An ObliviousDoHMessage (RFC 9230).
    Odoh,
    /// An Encapsulated Request, answered by an Encapsulated Response (RFC 9458).
    Ohttp,
}

/// Also advertised to the peer in SETTINGS.
const MAX_RESPONSE_HEADERS: usize = 32 * 1024;

/// Cancelled streams remembered. RFC 9113 lets an endpoint bound how long it drops frames for
/// streams it reset. The server stops sending on a stream once it reads RST_STREAM, so late frames
/// arrive within a few queries; a frame for a forgotten stream is a protocol error, like one for an
/// unknown stream.
const MAX_CANCELLED_STREAMS: usize = 8;

/// Connection-specific fields, which may not appear in response headers or trailers. TE is allowed
/// only in requests, with the value trailers, so responses reject it too.
fn is_connection_specific(name: &[u8]) -> bool {
    matches!(
        name,
        b"connection"
            | b"proxy-connection"
            | b"keep-alive"
            | b"te"
            | b"transfer-encoding"
            | b"upgrade"
    )
}

/// Extracts status and content length from response headers. Exactly one :status is allowed; with a
/// duplicate pseudo-header, implementations disagree on which value counts. Interim 1xx and final
/// responses follow the same rules, and HTTP/2 has no 101.
///
/// A 200 must carry one content-type, the request's, and a body within its cap. Other statuses are
/// not read, so neither is checked: rejecting a 404 text/html here would turn a status error into a
/// protocol error.
///
/// `None` means a rule was broken; the caller treats it as a protocol error.
fn response_metadata(
    headers: &[(Vec<u8>, Vec<u8>)],
    payload: Payload,
) -> Option<(u16, Option<usize>)> {
    let mut status = None;
    let mut content_length = None;
    let mut content_types = 0usize;
    let mut expected_type = false;
    let mut regular_seen = false;
    let mut header_size = 0usize;

    for (name, value) in headers {
        header_size = header_size.checked_add(name.len() + value.len() + 32)?;
        if header_size > MAX_RESPONSE_HEADERS || !valid_header_field(name, value) {
            return None;
        }
        if name.starts_with(b":") {
            if regular_seen || name != b":status" || status.is_some() {
                return None;
            }
            if value.len() != 3 || !value.iter().all(u8::is_ascii_digit) {
                return None;
            }
            let parsed = ((value[0] - b'0') as u16) * 100
                + ((value[1] - b'0') as u16) * 10
                + (value[2] - b'0') as u16;
            if !(100..=599).contains(&parsed) || parsed == 101 {
                return None;
            }
            status = Some(parsed);
            continue;
        }

        regular_seen = true;
        if name.iter().any(u8::is_ascii_uppercase) || is_connection_specific(name) {
            return None;
        }
        if name == b"content-length" {
            if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                return None;
            }
            let length = std::str::from_utf8(value).ok()?.parse::<usize>().ok()?;
            if content_length.replace(length).is_some() {
                return None;
            }
        } else if name == b"content-type" {
            content_types += 1;
            expected_type = payload
                .response_type
                .is_none_or(|media_type| value.eq_ignore_ascii_case(media_type.as_bytes()));
        }
    }

    let status = status?;
    let typed = match payload.response_type {
        Some(_) => content_types == 1 && expected_type,
        None => content_types <= 1,
    };
    if status == 200 && (!typed || content_length.is_some_and(|length| length > payload.max_body)) {
        return None;
    }
    Some((status, content_length))
}

/// Trailers may not carry pseudo-headers or connection-specific fields, and the advertised header
/// list cap applies to them too. Their values are never used to interpret the DNS response.
fn valid_trailer_section(fields: &[(Vec<u8>, Vec<u8>)]) -> bool {
    let mut size = 0usize;
    fields.iter().all(|(name, value)| {
        size = size.saturating_add(name.len() + value.len() + 32);
        size <= MAX_RESPONSE_HEADERS
            && valid_header_field(name, value)
            && !name.starts_with(b":")
            && !is_connection_specific(name)
    })
}

/// A body that differs from the announced length is a protocol error.
fn complete_body(body: Vec<u8>, content_length: Option<usize>) -> Result<Vec<u8>, H2Error> {
    if content_length.is_some_and(|length| length != body.len()) {
        return Err(H2Error::Protocol);
    }
    Ok(body)
}

/// HTTP/2 client for a DoH upstream. `S` provides the transport (TLS); this type handles only
/// framing and headers.
pub struct H2Client<S> {
    stream: S,

    dec: Decoder,

    /// Clients use only odd stream IDs.
    next_id: u32,

    peer_settings_seen: bool,

    /// Streams reset without reading the body. Frames the server sent before it saw the reset are
    /// dropped while the stream is listed.
    cancelled: Vec<u32>,
}

impl<S: Read + Write> H2Client<S> {
    /// Sends the preface and initial SETTINGS. Server push is disabled: this client does not handle
    /// it, and a push it did not disable is a protocol error that drops the connection. The header
    /// list cap is advertised too, so the peer does not send oversized headers.
    pub fn connect(mut stream: S) -> Result<Self, H2Error> {
        stream
            .write_all(crate::frame::PREFACE)
            .map_err(|_| H2Error::Io)?;

        let mut settings_payload = Vec::with_capacity(12);
        settings_payload.extend_from_slice(&settings::ENABLE_PUSH.to_be_bytes());
        settings_payload.extend_from_slice(&0u32.to_be_bytes());
        settings_payload.extend_from_slice(&settings::MAX_HEADER_LIST_SIZE.to_be_bytes());
        settings_payload.extend_from_slice(&(MAX_RESPONSE_HEADERS as u32).to_be_bytes());
        send_frame(&mut stream, frame_type::SETTINGS, 0, 0, &settings_payload)?;
        Ok(H2Client {
            stream,
            dec: Decoder::new(4096),
            next_id: 1,
            peer_settings_seen: false,
            cancelled: Vec::new(),
        })
    }

    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn query(
        &mut self,
        authority: &str,
        path: &str,
        dns_wire: &[u8],
    ) -> Result<Vec<u8>, H2Error> {
        self.query_inner(authority, path, Some(dns_wire), DNS, false, |_| {})
    }

    /// Sends a PING with the query for a two-stage deadline. A reused connection may be dead, and
    /// that is unknown until something is sent. A PING reply proves it alive, so `on_alive` can
    /// extend the deadline to give the upstream time to resolve; without one the connection is dead
    /// and the query gives up early.
    pub fn query_probed(
        &mut self,
        authority: &str,
        path: &str,
        dns_wire: &[u8],
        on_alive: impl FnOnce(&mut S),
    ) -> Result<Vec<u8>, H2Error> {
        self.query_inner(authority, path, Some(dns_wire), DNS, true, on_alive)
    }

    /// `query_probed` for an ObliviousDoHMessage or an Encapsulated Request. A non-200 status comes
    /// back as `H2Error::BadStatus` with its code, which an ODoH client acts on: 401 means a stale
    /// key.
    pub fn oblivious_probed(
        &mut self,
        authority: &str,
        path: &str,
        message: &[u8],
        media: ObliviousMedia,
        on_alive: impl FnOnce(&mut S),
    ) -> Result<Vec<u8>, H2Error> {
        let payload = match media {
            ObliviousMedia::Odoh => OBLIVIOUS,
            ObliviousMedia::Ohttp => OHTTP,
        };
        self.query_inner(authority, path, Some(message), payload, true, on_alive)
    }

    /// GETs an Oblivious DoH target's ObliviousDoHConfigs.
    pub fn odoh_configs(&mut self, authority: &str) -> Result<Vec<u8>, H2Error> {
        let path = crate::server::ODOH_CONFIGS_PATH;
        self.query_inner(authority, path, None, ODOH_CONFIGS, false, |_| {})
    }

    /// POSTs `body`, or GETs without one.
    fn query_inner(
        &mut self,
        authority: &str,
        path: &str,
        body: Option<&[u8]>,
        payload: Payload,
        probe: bool,
        on_alive: impl FnOnce(&mut S),
    ) -> Result<Vec<u8>, H2Error> {
        let sid = self.allocate_stream_id()?;

        let clen = body.map(|body| body.len().to_string());
        let mut headers: Vec<(&str, &str)> = vec![
            (":method", if body.is_some() { "POST" } else { "GET" }),
            (":scheme", "https"),
            (":authority", authority),
            (":path", path),
        ];
        if let Some(media_type) = payload.response_type {
            headers.push(("accept", media_type));
        }
        if let (Some(media_type), Some(clen)) = (payload.request_type, &clen) {
            headers.push(("content-type", media_type));
            headers.push(("content-length", clen));
        }

        let block = hpack::encode_response(&headers);
        let end = if body.is_some() { 0 } else { flags::END_STREAM };
        send_frame(
            &mut self.stream,
            frame_type::HEADERS,
            flags::END_HEADERS | end,
            sid,
            &block,
        )?;

        match body {
            None => {}
            Some([]) => send_frame(
                &mut self.stream,
                frame_type::DATA,
                flags::END_STREAM,
                sid,
                &[],
            )?,
            Some(body) => {
                const INITIAL_CONNECTION_WINDOW: usize = 65_535;
                if body.len() > INITIAL_CONNECTION_WINDOW {
                    return Err(H2Error::Protocol);
                }
                let mut chunks = body.chunks(DEFAULT_MAX_FRAME).peekable();
                while let Some(chunk) = chunks.next() {
                    let fl = if chunks.peek().is_none() {
                        flags::END_STREAM
                    } else {
                        0
                    };
                    send_frame(&mut self.stream, frame_type::DATA, fl, sid, chunk)?;
                }
            }
        }
        let ping_token = u64::from(sid).to_be_bytes();
        if probe {
            send_frame(&mut self.stream, frame_type::PING, 0, 0, &ping_token)?;
        }

        self.read_response(sid, ping_token, payload, on_alive)
    }

    /// Errors past 31 bits, which would enter the reserved bit; wrapping around would reuse old IDs
    /// and mix up responses. The connection must then be replaced.
    fn allocate_stream_id(&mut self) -> Result<u32, H2Error> {
        let sid = self.next_id;
        if sid == 0 || sid > 0x7fff_ffff {
            return Err(H2Error::Refused);
        }
        self.next_id = sid
            .checked_add(2)
            .filter(|next| *next <= 0x7fff_ffff)
            .unwrap_or(0);
        Ok(sid)
    }

    /// Returns consumed window to both the connection and the stream. Opening only one stalls a
    /// large response midway, because the peer cannot send the rest.
    fn replenish_receive_window(
        &mut self,
        sid: u32,
        amount: usize,
        stream_open: bool,
    ) -> Result<(), H2Error> {
        if amount == 0 {
            return Ok(());
        }
        let increment = u32::try_from(amount)
            .ok()
            .filter(|increment| *increment <= 0x7fff_ffff)
            .ok_or(H2Error::Protocol)?
            .to_be_bytes();
        send_frame(
            &mut self.stream,
            frame_type::WINDOW_UPDATE,
            0,
            0,
            &increment,
        )?;
        if stream_open {
            send_frame(
                &mut self.stream,
                frame_type::WINDOW_UPDATE,
                0,
                sid,
                &increment,
            )?;
        }
        Ok(())
    }

    /// Resets a stream whose body will not be read, and remembers it. Without the reset the server
    /// keeps sending a body nobody reads, and once the stream window fills it holds the stream
    /// open, taking a concurrent-stream slot.
    fn cancel(&mut self, sid: u32) -> Result<(), H2Error> {
        send_frame(
            &mut self.stream,
            frame_type::RST_STREAM,
            0,
            sid,
            &error_code::CANCEL.to_be_bytes(),
        )?;
        if self.cancelled.len() == MAX_CANCELLED_STREAMS {
            self.cancelled.remove(0);
        }
        self.cancelled.push(sid);
        Ok(())
    }

    /// Reads frames until this stream's response is complete, handling other streams' frames and
    /// control frames (SETTINGS, PING, WINDOW_UPDATE) on the way. A response is any number of 1xx
    /// interim responses, the final response, the body, and at most one trailer section. The body
    /// is capped at content-length, or at the absolute cap without one, so an endless upstream
    /// cannot eat memory.
    ///
    /// `H2Error::BadStatus` means the final status was not 200. Only that stream is reset, without
    /// reading the body, so the connection stays usable.
    fn read_response(
        &mut self,
        sid: u32,
        ping_token: [u8; 8],
        expected: Payload,
        on_alive: impl FnOnce(&mut S),
    ) -> Result<Vec<u8>, H2Error> {
        let mut body = Vec::new();
        let mut final_seen = false;
        let mut content_length: Option<usize> = None;
        let mut on_alive = Some(on_alive);
        loop {
            let (h, payload) = read_frame(&mut self.stream)?;

            let fresh = (h.stream_id == sid
                && matches!(h.frame_type, frame_type::HEADERS | frame_type::DATA))
                || (h.frame_type == frame_type::PING
                    && h.has_flag(flags::ACK)
                    && payload == ping_token);
            if fresh {
                if let Some(alive) = on_alive.take() {
                    alive(&mut self.stream);
                }
            }
            if !self.peer_settings_seen {
                if h.frame_type != frame_type::SETTINGS || h.has_flag(flags::ACK) {
                    return Err(H2Error::Protocol);
                }
                self.peer_settings_seen = true;
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
                            settings::ENABLE_PUSH if value != 0 => return Err(H2Error::Protocol),
                            settings::INITIAL_WINDOW_SIZE if value > 0x7fff_ffff => {
                                return Err(H2Error::Protocol)
                            }
                            settings::MAX_FRAME_SIZE if !(16_384..=16_777_215).contains(&value) => {
                                return Err(H2Error::Protocol)
                            }
                            _ => {}
                        }
                    }
                    send_frame(&mut self.stream, frame_type::SETTINGS, flags::ACK, 0, &[])?;
                }
                frame_type::SETTINGS if h.stream_id != 0 || !payload.is_empty() => {
                    return Err(H2Error::Protocol)
                }
                frame_type::SETTINGS => {}
                frame_type::PING if !h.has_flag(flags::ACK) => {
                    if h.stream_id != 0 || payload.len() != 8 {
                        return Err(H2Error::Protocol);
                    }
                    send_frame(&mut self.stream, frame_type::PING, flags::ACK, 0, &payload)?;
                }
                frame_type::PING if h.stream_id != 0 || payload.len() != 8 => {
                    return Err(H2Error::Protocol)
                }
                frame_type::PING => {}
                frame_type::GOAWAY => {
                    if h.stream_id != 0 || payload.len() < 8 {
                        return Err(H2Error::Protocol);
                    }
                    // RFC 9113: the server answers streams up to the one it names and processed
                    // none after it. Either way this connection opens no more.
                    self.next_id = 0;
                    let last =
                        u32::from_be_bytes(payload[..4].try_into().map_err(|_| H2Error::Protocol)?)
                            & 0x7fff_ffff;
                    if sid > last {
                        return Err(H2Error::Refused);
                    }
                }
                frame_type::RST_STREAM => {
                    if h.stream_id == 0 || payload.len() != 4 {
                        return Err(H2Error::Protocol);
                    }
                    if h.stream_id == sid {
                        return Err(if payload[..] == error_code::REFUSED_STREAM.to_be_bytes() {
                            H2Error::Refused
                        } else {
                            H2Error::Protocol
                        });
                    }
                }
                frame_type::WINDOW_UPDATE => {
                    if payload.len() != 4 {
                        return Err(H2Error::Protocol);
                    }
                    let increment =
                        u32::from_be_bytes(payload[..4].try_into().map_err(|_| H2Error::Protocol)?)
                            & 0x7fff_ffff;
                    if increment == 0 {
                        return Err(H2Error::Protocol);
                    }
                }
                frame_type::PRIORITY if h.stream_id == 0 || payload.len() != 5 => {
                    return Err(H2Error::Protocol)
                }
                frame_type::PRIORITY => {}
                frame_type::HEADERS if h.stream_id == sid => {
                    if !h.has_flag(flags::END_HEADERS) {
                        return Err(H2Error::Protocol);
                    }
                    let blk = strip_headers(&payload, h.flags)?;
                    let hs = self.dec.decode(blk).ok_or(H2Error::Protocol)?;
                    let end_stream = h.has_flag(flags::END_STREAM);
                    if final_seen {
                        // HEADERS after the final response are trailers, and trailers end the
                        // stream.
                        if !end_stream || !valid_trailer_section(&hs) {
                            return Err(H2Error::Protocol);
                        }
                        return complete_body(body, content_length);
                    }
                    let (status, length) =
                        response_metadata(&hs, expected).ok_or(H2Error::Protocol)?;
                    match status {
                        // An interim response only delays the final one: it has no body and does
                        // not end the stream.
                        100..=199 if end_stream => return Err(H2Error::Protocol),
                        100..=199 => {}
                        200 => {
                            final_seen = true;
                            content_length = length;
                            if end_stream {
                                return complete_body(body, content_length);
                            }
                        }
                        _ => {
                            // A stream the server ended is already closed; there is nothing to
                            // reset.
                            if !end_stream {
                                self.cancel(sid)?;
                            }
                            return Err(H2Error::BadStatus(status));
                        }
                    }
                }
                frame_type::DATA if h.stream_id == sid => {
                    if !final_seen {
                        return Err(H2Error::Protocol);
                    }
                    let data = strip_padding(&payload, h.flags)?;
                    if body.len().saturating_add(data.len()) > expected.max_body {
                        return Err(H2Error::Protocol);
                    }
                    body.extend_from_slice(data);

                    let _ = self.replenish_receive_window(
                        sid,
                        payload.len(),
                        !h.has_flag(flags::END_STREAM),
                    );
                    if h.has_flag(flags::END_STREAM) {
                        return complete_body(body, content_length);
                    }
                }
                frame_type::DATA if self.cancelled.contains(&h.stream_id) => {
                    // Bodies of reset streams use connection window too. Not returning what was
                    // dropped shrinks the window with every error response until responses stall.
                    self.replenish_receive_window(h.stream_id, payload.len(), false)?;
                }
                frame_type::HEADERS if self.cancelled.contains(&h.stream_id) => {
                    // Dropped headers still have to be decoded to keep the HPACK dynamic table in
                    // sync with the server.
                    if !h.has_flag(flags::END_HEADERS) {
                        return Err(H2Error::Protocol);
                    }
                    let blk = strip_headers(&payload, h.flags)?;
                    self.dec.decode(blk).ok_or(H2Error::Protocol)?;
                }
                frame_type::HEADERS
                | frame_type::DATA
                | frame_type::PUSH_PROMISE
                | frame_type::CONTINUATION => return Err(H2Error::Protocol),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameHeader;
    use crate::serve_doh;
    use crate::testutil::{deadline_accept, deadline_connect};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    fn owned_headers(headers: &[(&[u8], &[u8])]) -> Vec<(Vec<u8>, Vec<u8>)> {
        headers
            .iter()
            .map(|(name, value)| (name.to_vec(), value.to_vec()))
            .collect()
    }

    #[test]
    fn response_headers_reject_duplicate_status_bad_type_and_oversized_length() {
        let duplicate: [(&[u8], &[u8]); 3] = [
            (b":status", b"200"),
            (b":status", b"200"),
            (b"content-type", b"application/dns-message"),
        ];
        assert!(response_metadata(&owned_headers(&duplicate), DNS).is_none());

        let bad_type: [(&[u8], &[u8]); 2] =
            [(b":status", b"200"), (b"content-type", b"text/plain")];
        assert!(response_metadata(&owned_headers(&bad_type), DNS).is_none());

        let two_types = owned_headers(&[
            (b":status", b"200"),
            (b"content-type", b"application/dns-message"),
            (b"content-type", b"application/dns-message"),
        ]);
        assert!(response_metadata(&two_types, DNS).is_none());

        let oversized = (MAX_DNS_RESPONSE + 1).to_string();
        let oversized_headers = owned_headers(&[
            (b":status", b"200"),
            (b"content-type", b"application/dns-message"),
            (b"content-length", oversized.as_bytes()),
        ]);
        assert!(response_metadata(&oversized_headers, DNS).is_none());
    }

    #[test]
    /// An ODoH request takes back only its own media type, within the ObliviousDoHMessage cap.
    fn oblivious_responses_carry_their_own_media_type() {
        let dns_typed = owned_headers(&[
            (b":status", b"200"),
            (b"content-type", b"application/dns-message"),
        ]);
        assert!(response_metadata(&dns_typed, OBLIVIOUS).is_none());

        let largest = crate::server::MAX_ODOH_MESSAGE.to_string();
        let message = owned_headers(&[
            (b":status", b"200"),
            (b"content-type", b"application/oblivious-dns-message"),
            (b"content-length", largest.as_bytes()),
        ]);
        assert_eq!(
            response_metadata(&message, OBLIVIOUS),
            Some((200, Some(crate::server::MAX_ODOH_MESSAGE)))
        );
        assert!(
            response_metadata(&message, DNS).is_none(),
            "a DoH query must not take an ODoH message for an answer"
        );

        let encapsulated = owned_headers(&[
            (b":status", b"200"),
            (b"content-type", b"message/ohttp-res"),
        ]);
        assert_eq!(response_metadata(&encapsulated, OHTTP), Some((200, None)));
        let request_typed = owned_headers(&[
            (b":status", b"200"),
            (b"content-type", b"message/ohttp-req"),
        ]);
        assert!(
            response_metadata(&request_typed, OHTTP).is_none(),
            "a relay must not pass on a request as a response"
        );
        let too_long = (crate::server::MAX_OHTTP_RESPONSE + 1).to_string();
        let too_long = owned_headers(&[
            (b":status", b"200"),
            (b"content-type", b"message/ohttp-res"),
            (b"content-length", too_long.as_bytes()),
        ]);
        assert!(response_metadata(&too_long, OHTTP).is_none());
    }

    #[test]
    /// Rejecting them would turn a status error into a protocol error.
    fn error_status_is_not_judged_as_a_dns_answer() {
        let html = owned_headers(&[(b":status", b"404"), (b"content-type", b"text/html")]);
        assert_eq!(response_metadata(&html, DNS), Some((404, None)));

        let page_length = (MAX_DNS_RESPONSE + 1).to_string();
        let long_page = owned_headers(&[
            (b":status", b"404"),
            (b"content-type", b"text/html"),
            (b"content-length", page_length.as_bytes()),
        ]);
        assert_eq!(
            response_metadata(&long_page, DNS),
            Some((404, Some(MAX_DNS_RESPONSE + 1)))
        );

        let bare = owned_headers(&[(b":status", b"503")]);
        assert_eq!(response_metadata(&bare, DNS), Some((503, None)));
    }

    #[test]
    fn error_page_yields_bad_status() {
        let page = b"<html>not here</html>";
        let length = page.len().to_string();
        let head = hpack::encode_response(&[
            (":status", "404"),
            ("content-type", "text/html"),
            ("content-length", length.as_str()),
        ]);
        let result = scripted_response(
            true,
            &[
                (frame_type::HEADERS, flags::END_HEADERS, 1, &head),
                (frame_type::DATA, flags::END_STREAM, 1, page),
            ],
        );
        assert!(matches!(result, Err(H2Error::BadStatus(404))), "{result:?}");
    }

    #[test]
    fn response_headers_reject_invalid_field_syntax() {
        let valid: [(&[u8], &[u8]); 2] = [
            (b":status", b"200"),
            (b"content-type", b"application/dns-message"),
        ];
        for (name, value) in [
            (&b"bad\0name"[..], &b"value"[..]),
            (&b"x-test"[..], &b"bad\rvalue"[..]),
            (&b"x-test"[..], &b" leading"[..]),
            (&b"te"[..], &b"trailers"[..]),
        ] {
            let mut headers = owned_headers(&valid);
            headers.push((name.to_vec(), value.to_vec()));
            assert!(
                response_metadata(&headers, DNS).is_none(),
                "{name:?}: {value:?}"
            );
        }

        let mut bad_length = owned_headers(&valid);
        bad_length.push((b"content-length".to_vec(), b"+3".to_vec()));
        assert!(response_metadata(&bad_length, DNS).is_none());
    }

    #[test]
    /// Without a cap an endless sender fills memory.
    fn response_body_is_bounded_without_content_length() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut stream = deadline_accept(&listener);
            let mut preface = [0u8; 24];
            stream.read_exact(&mut preface).unwrap();
            assert_eq!(preface, crate::frame::PREFACE);
            send_frame(&mut stream, frame_type::SETTINGS, 0, 0, &[]).unwrap();
            loop {
                let (header, _) = read_frame(&mut stream).unwrap();
                if header.stream_id == 1 && header.has_flag(flags::END_STREAM) {
                    break;
                }
            }
            let block = hpack::encode_response(&[
                (":status", "200"),
                ("content-type", "application/dns-message"),
            ]);
            send_frame(
                &mut stream,
                frame_type::HEADERS,
                flags::END_HEADERS,
                1,
                &block,
            )
            .unwrap();
            for index in 0..4 {
                let frame_flags = if index == 3 { flags::END_STREAM } else { 0 };
                if send_frame(
                    &mut stream,
                    frame_type::DATA,
                    frame_flags,
                    1,
                    &vec![0; DEFAULT_MAX_FRAME],
                )
                .is_err()
                {
                    break;
                }
            }
        });

        let tcp = deadline_connect(addr);
        let mut client = H2Client::connect(tcp).unwrap();
        let result = client.query("dns.test", "/dns-query", b"query");
        assert!(result.is_err(), "{result:?}");
        server.join().unwrap();
    }

    /// Frame type, flags, stream ID, payload.
    type ScriptedFrame<'a> = (u8, u8, u32, &'a [u8]);

    /// Exchanges one query with a server that answers the first request with `frames`, in order.
    /// `send_settings_first` sends an empty SETTINGS before the request is read.
    fn scripted_response(
        send_settings_first: bool,
        frames: &[ScriptedFrame],
    ) -> Result<Vec<u8>, H2Error> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let frames: Vec<(u8, u8, u32, Vec<u8>)> = frames
            .iter()
            .map(|&(kind, frame_flags, stream_id, payload)| {
                (kind, frame_flags, stream_id, payload.to_vec())
            })
            .collect();
        let server = thread::spawn(move || {
            let mut stream = deadline_accept(&listener);
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut preface = [0u8; 24];
            stream.read_exact(&mut preface).unwrap();
            assert_eq!(preface, crate::frame::PREFACE);
            if send_settings_first {
                send_frame(&mut stream, frame_type::SETTINGS, 0, 0, &[]).unwrap();
            }
            read_request(&mut stream, 1);
            for (kind, frame_flags, stream_id, payload) in &frames {
                // The client may fail on an earlier frame and close, so a failed send does not
                // matter.
                let _ = send_frame(&mut stream, *kind, *frame_flags, *stream_id, payload);
            }
            let mut byte = [0u8; 1];
            while stream.read(&mut byte).is_ok_and(|read| read != 0) {}
        });

        let tcp = deadline_connect(addr);
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut client = H2Client::connect(tcp).unwrap();
        let result = client.query("dns.test", "/dns-query", b"query");
        drop(client);
        server.join().unwrap();
        result
    }

    /// Server side with the preface checked and an empty SETTINGS sent.
    fn accept_client(listener: &TcpListener) -> TcpStream {
        let mut stream = deadline_accept(listener);
        let mut preface = [0u8; 24];
        stream.read_exact(&mut preface).unwrap();
        assert_eq!(preface, crate::frame::PREFACE);
        send_frame(&mut stream, frame_type::SETTINGS, 0, 0, &[]).unwrap();
        stream
    }

    /// Reads until the request stream ends; returns the frames of other streams seen meanwhile.
    fn read_request(stream: &mut TcpStream, sid: u32) -> Vec<(FrameHeader, Vec<u8>)> {
        let mut others = Vec::new();
        loop {
            let (header, payload) = read_frame(stream).unwrap();
            if header.stream_id != sid {
                others.push((header, payload));
            } else if header.has_flag(flags::END_STREAM) {
                return others;
            }
        }
    }

    fn send_headers(stream: &mut TcpStream, sid: u32, block: &[u8], end_stream: bool) {
        let frame_flags = if end_stream {
            flags::END_HEADERS | flags::END_STREAM
        } else {
            flags::END_HEADERS
        };
        send_frame(stream, frame_type::HEADERS, frame_flags, sid, block).unwrap();
    }

    #[test]
    fn first_peer_frame_must_be_non_ack_settings() {
        assert!(matches!(
            scripted_response(false, &[(frame_type::PING, 0, 0, &[0; 8])]),
            Err(H2Error::Protocol)
        ));
        assert!(matches!(
            scripted_response(false, &[(frame_type::SETTINGS, flags::ACK, 0, &[])]),
            Err(H2Error::Protocol)
        ));
    }

    #[test]
    fn malformed_control_frames_are_rejected() {
        let malformed: &[(u8, u8, u32, &[u8])] = &[
            (frame_type::SETTINGS, 0, 1, &[]),
            (frame_type::SETTINGS, flags::ACK, 0, &[0]),
            (frame_type::SETTINGS, 0, 0, &[0, 2, 0, 0, 0, 1]),
            (frame_type::PING, 0, 0, &[0; 7]),
            (frame_type::GOAWAY, 0, 1, &[0; 8]),
            (frame_type::RST_STREAM, 0, 0, &[0; 4]),
            (frame_type::PRIORITY, 0, 0, &[0; 5]),
            (frame_type::WINDOW_UPDATE, 0, 0, &[0; 4]),
        ];
        for &frame in malformed {
            assert!(matches!(
                scripted_response(true, &[frame]),
                Err(H2Error::Protocol)
            ));
        }
    }

    #[test]
    /// A response is any number of interim responses, the final response, the body, and an optional
    /// trailer section. Rejecting them would turn a compliant answer into a protocol error and drop
    /// the connection.
    fn interim_responses_and_trailers_are_accepted() {
        let continue_head = hpack::encode_response(&[(":status", "100")]);
        let early_hints =
            hpack::encode_response(&[(":status", "103"), ("link", "</dns>; rel=preload")]);
        let head = hpack::encode_response(&[
            (":status", "200"),
            ("content-type", "application/dns-message"),
            ("content-length", "6"),
        ]);
        let trailer = hpack::encode_response(&[("x-checksum", "abc")]);
        let result = scripted_response(
            true,
            &[
                (frame_type::HEADERS, flags::END_HEADERS, 1, &continue_head),
                (frame_type::HEADERS, flags::END_HEADERS, 1, &early_hints),
                (frame_type::HEADERS, flags::END_HEADERS, 1, &head),
                (frame_type::DATA, 0, 1, b"answer"),
                (
                    frame_type::HEADERS,
                    flags::END_HEADERS | flags::END_STREAM,
                    1,
                    &trailer,
                ),
            ],
        );
        assert!(
            matches!(&result, Ok(body) if body == b"answer"),
            "중간 응답과 트레일러가 붙은 응답을 받지 못했습니다: {result:?}"
        );
    }

    #[test]
    /// HTTP/2 has no 101. Interim responses cannot end the stream or follow body data. Trailers
    /// must end the stream and carry no pseudo-headers or connection-specific fields. A response
    /// ending in trailers must still match the announced body length.
    fn interim_and_trailer_violations_are_rejected() {
        const MORE: u8 = flags::END_HEADERS;
        const END: u8 = flags::END_HEADERS | flags::END_STREAM;
        let headers = frame_type::HEADERS;
        let data = frame_type::DATA;
        let interim = hpack::encode_response(&[(":status", "103")]);
        let switching = hpack::encode_response(&[(":status", "101")]);
        let head = hpack::encode_response(&[
            (":status", "200"),
            ("content-type", "application/dns-message"),
        ]);
        let longer_head = hpack::encode_response(&[
            (":status", "200"),
            ("content-type", "application/dns-message"),
            ("content-length", "7"),
        ]);
        let trailer = hpack::encode_response(&[("x-checksum", "abc")]);
        let pseudo_trailer = hpack::encode_response(&[(":status", "200")]);
        let connection_trailer = hpack::encode_response(&[("connection", "close")]);
        let te_trailer = hpack::encode_response(&[("te", "trailers")]);
        let with_trailer = |head: &[u8], trailer: &[u8], trailer_flags: u8| {
            vec![
                (headers, MORE, 1, head.to_vec()),
                (data, 0, 1, b"answer".to_vec()),
                (headers, trailer_flags, 1, trailer.to_vec()),
            ]
        };
        let cases = [
            (
                "101 응답",
                vec![
                    (headers, MORE, 1, switching),
                    (headers, MORE, 1, head.clone()),
                    (data, flags::END_STREAM, 1, b"answer".to_vec()),
                ],
            ),
            (
                "스트림을 끝낸 중간 응답",
                vec![(headers, END, 1, interim.clone())],
            ),
            (
                "최종 응답 없이 중간 응답 뒤에 온 본문",
                vec![
                    (headers, MORE, 1, interim),
                    (data, flags::END_STREAM, 1, b"answer".to_vec()),
                ],
            ),
            (
                "스트림을 끝내지 않은 트레일러",
                with_trailer(&head, &trailer, MORE),
            ),
            (
                "의사 헤더를 실은 트레일러",
                with_trailer(&head, &pseudo_trailer, END),
            ),
            (
                "연결 전용 필드를 실은 트레일러",
                with_trailer(&head, &connection_trailer, END),
            ),
            ("TE 를 실은 트레일러", with_trailer(&head, &te_trailer, END)),
            (
                "알린 길이보다 짧은 본문",
                with_trailer(&longer_head, &trailer, END),
            ),
        ];
        for (case, frames) in cases {
            let frames: Vec<ScriptedFrame> = frames
                .iter()
                .map(|(kind, frame_flags, stream_id, payload)| {
                    (*kind, *frame_flags, *stream_id, payload.as_slice())
                })
                .collect();
            let result = scripted_response(true, &frames);
            assert!(
                matches!(result, Err(H2Error::Protocol)),
                "{case}: {result:?}"
            );
        }
    }

    #[test]
    /// The client resets an error response's stream with CANCEL without reading the body. The body
    /// and trailers the server sent before seeing the reset arrive while the next query is read.
    /// The body is dropped but its connection window is returned; the trailers are dropped but
    /// still decoded, because the server refers by index to fields it added to the HPACK dynamic
    /// table.
    fn error_status_cancels_only_that_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let page = vec![b'x'; 3000];
        let page_len = page.len();
        let server = thread::spawn(move || {
            let mut stream = accept_client(&listener);
            read_request(&mut stream, 1);
            let error_head =
                hpack::encode_response(&[(":status", "404"), ("content-type", "text/html")]);
            send_headers(&mut stream, 1, &error_head, false);
            send_frame(&mut stream, frame_type::DATA, 0, 1, &page).unwrap();
            // Trailer with a new-name literal added to the dynamic table, as entry 62.
            let mut trailer = vec![0x40, 9];
            trailer.extend_from_slice(b"x-trailer");
            trailer.extend_from_slice(&[1, b't']);
            send_headers(&mut stream, 1, &trailer, true);

            let mut received = read_request(&mut stream, 3);
            let mut head = hpack::encode_response(&[
                (":status", "200"),
                ("content-type", "application/dns-message"),
            ]);
            head.push(0x80 | 62);
            send_headers(&mut stream, 3, &head, false);
            send_frame(
                &mut stream,
                frame_type::DATA,
                flags::END_STREAM,
                3,
                b"answer",
            )
            .unwrap();
            while let Ok(frame) = read_frame(&mut stream) {
                received.push(frame);
            }
            received
        });

        let mut client = H2Client::connect(deadline_connect(addr)).unwrap();
        let first = client.query("dns.test", "/dns-query", b"one");
        assert!(matches!(first, Err(H2Error::BadStatus(_))), "{first:?}");
        let second = client.query("dns.test", "/dns-query", b"two");
        assert!(
            matches!(&second, Ok(body) if body == b"answer"),
            "오류 상태를 받은 연결로 다음 질의를 주고받지 못했습니다: {second:?}"
        );
        drop(client);

        let received = server.join().unwrap();
        assert!(
            received.iter().any(|(header, payload)| {
                header.frame_type == frame_type::RST_STREAM
                    && header.stream_id == 1
                    && payload[..] == crate::frame::error_code::CANCEL.to_be_bytes()
            }),
            "오류 응답의 스트림을 CANCEL 로 끊지 않았습니다"
        );
        let returned: usize = received
            .iter()
            .filter(|(header, _)| {
                header.frame_type == frame_type::WINDOW_UPDATE && header.stream_id == 0
            })
            .map(|(_, payload)| u32::from_be_bytes(payload[..4].try_into().unwrap()) as usize)
            .sum();
        assert_eq!(
            returned,
            page_len + b"answer".len(),
            "받은 본문만큼 연결 윈도우를 돌려주지 않았습니다"
        );
    }

    #[test]
    /// A stream both sides ended with END_STREAM is closed, and RFC 9113 allows no frame but
    /// PRIORITY on a closed stream.
    fn ended_error_response_is_not_reset() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut stream = accept_client(&listener);
            let mut received = read_request(&mut stream, 1);
            send_headers(
                &mut stream,
                1,
                &hpack::encode_response(&[(":status", "503")]),
                true,
            );
            while let Ok(frame) = read_frame(&mut stream) {
                received.push(frame);
            }
            received
        });

        let mut client = H2Client::connect(deadline_connect(addr)).unwrap();
        let result = client.query("dns.test", "/dns-query", b"query");
        assert!(matches!(result, Err(H2Error::BadStatus(_))), "{result:?}");
        drop(client);
        let received = server.join().unwrap();
        assert!(
            !received
                .iter()
                .any(|(header, _)| header.frame_type == frame_type::RST_STREAM),
            "닫힌 스트림에 RST_STREAM 을 보냈습니다"
        );
    }

    #[test]
    /// Without replenishing, the response stalls midway.
    fn receive_window_is_replenished_across_large_responses() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut stream = deadline_accept(&listener);
            serve_doh(&mut stream, "/dns-query", |_, _| answer(vec![7; 40_000])).unwrap();
        });

        let tcp = deadline_connect(addr);
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut client = H2Client::connect(tcp).unwrap();
        assert_eq!(
            client
                .query("dns.test", "/dns-query", b"one")
                .unwrap()
                .len(),
            40_000
        );
        assert_eq!(
            client
                .query("dns.test", "/dns-query", b"two")
                .unwrap()
                .len(),
            40_000
        );
        drop(client);
        server.join().unwrap();
    }

    /// Reads what the server sends from a script and keeps what the client writes.
    struct Scripted {
        from_server: std::io::Cursor<Vec<u8>>,
        to_server: Vec<u8>,
    }

    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.from_server.read(buf)
        }
    }

    impl Write for Scripted {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.to_server.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn scripted_client(frames: &[ScriptedFrame]) -> H2Client<Scripted> {
        let mut from_server = Vec::new();
        send_frame(&mut from_server, frame_type::SETTINGS, 0, 0, &[]).unwrap();
        for &(kind, frame_flags, stream_id, payload) in frames {
            send_frame(&mut from_server, kind, frame_flags, stream_id, payload).unwrap();
        }
        H2Client::connect(Scripted {
            from_server: std::io::Cursor::new(from_server),
            to_server: Vec::new(),
        })
        .unwrap()
    }

    fn goaway(last_stream: u32) -> Vec<u8> {
        let mut payload = last_stream.to_be_bytes().to_vec();
        payload.extend_from_slice(&error_code::NO_ERROR.to_be_bytes());
        payload
    }

    #[test]
    /// RFC 9113: streams up to the one a GOAWAY names are still answered, as a server shutting
    /// down gracefully first names the highest ID. Streams after it were not processed and can be
    /// sent again elsewhere. Either way the connection opens no more streams.
    fn goaway_ends_only_the_streams_after_the_one_it_names() {
        let head = hpack::encode_response(&[
            (":status", "200"),
            ("content-type", "application/dns-message"),
            ("content-length", "6"),
        ]);
        let (announced, named) = (goaway(0x7fff_ffff), goaway(1));
        let mut client = scripted_client(&[
            (frame_type::GOAWAY, 0, 0, &announced),
            (frame_type::HEADERS, flags::END_HEADERS, 1, &head),
            (frame_type::GOAWAY, 0, 0, &named),
            (frame_type::DATA, flags::END_STREAM, 1, b"answer"),
        ]);
        let answered = client.query("dns.test", "/dns-query", b"query");
        assert!(
            matches!(&answered, Ok(body) if body == b"answer"),
            "GOAWAY 가 처리한다고 한 스트림의 답을 받지 못했습니다: {answered:?}"
        );
        let written = client.stream_mut().to_server.len();
        assert!(matches!(
            client.query("dns.test", "/dns-query", b"query"),
            Err(H2Error::Refused)
        ));
        assert_eq!(
            client.stream_mut().to_server.len(),
            written,
            "GOAWAY 를 받은 연결에 새 요청을 보냈습니다"
        );

        let earlier = goaway(0);
        let mut client = scripted_client(&[(frame_type::GOAWAY, 0, 0, &earlier)]);
        assert!(matches!(
            client.query("dns.test", "/dns-query", b"query"),
            Err(H2Error::Refused)
        ));
    }

    #[test]
    fn stream_ids_never_wrap_into_the_reserved_bit() {
        let mut client = H2Client::connect(std::io::Cursor::new(Vec::new())).unwrap();
        client.next_id = 0x7fff_ffff;
        assert!(matches!(client.allocate_stream_id(), Ok(0x7fff_ffff)));
        assert!(matches!(client.allocate_stream_id(), Err(H2Error::Refused)));
    }

    #[test]
    /// A long-lived connection to a server that only returns errors would grow the list by one per
    /// query.
    fn cancelled_streams_are_bounded() {
        let mut client = H2Client::connect(std::io::Cursor::new(Vec::new())).unwrap();
        for sid in (1..).step_by(2).take(MAX_CANCELLED_STREAMS + 1) {
            client.cancel(sid).unwrap();
        }
        assert_eq!(client.cancelled.len(), MAX_CANCELLED_STREAMS);
        assert!(
            !client.cancelled.contains(&1),
            "가장 오래전에 끊은 스트림을 잊지 않았습니다"
        );
    }

    #[test]
    /// Left on, the peer fills resources this client never uses.
    fn client_preface_disables_unsupported_server_push() {
        let client = H2Client::connect(std::io::Cursor::new(Vec::new())).unwrap();
        let bytes = client.stream.into_inner();
        assert_eq!(&bytes[..crate::frame::PREFACE.len()], crate::frame::PREFACE);
        let mut frame = std::io::Cursor::new(&bytes[crate::frame::PREFACE.len()..]);
        let (header, payload) = read_frame(&mut frame).unwrap();
        assert_eq!(header.frame_type, frame_type::SETTINGS);
        assert_eq!(header.stream_id, 0);
        assert_eq!(
            payload,
            [
                0,
                settings::ENABLE_PUSH as u8,
                0,
                0,
                0,
                0,
                0,
                settings::MAX_HEADER_LIST_SIZE as u8,
                0,
                0,
                0x80,
                0,
            ]
        );
    }

    fn answer(body: Vec<u8>) -> Result<Option<crate::server::DohAnswer>, &'static str> {
        Ok(Some(crate::server::DohAnswer { body, max_age: 0 }))
    }

    #[test]
    fn doh_post_roundtrip_against_serve_doh() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut s = deadline_accept(&listener);
            serve_doh(&mut s, "/dns-query", |q, _cid| {
                let mut r = q.to_vec();
                r.reverse();
                answer(r)
            })
            .ok();
        });

        let tcp = deadline_connect(addr);
        let mut client = H2Client::connect(tcp).unwrap();

        let q1 = vec![0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00];
        let r1 = client.query("dns.test", "/dns-query", &q1).unwrap();
        let mut e1 = q1.clone();
        e1.reverse();
        assert_eq!(r1, e1);

        let q2 = vec![0x11, 0x22, 0x33, 0x44, 0x55];
        let r2 = client.query("dns.test", "/dns-query", &q2).unwrap();
        let mut e2 = q2.clone();
        e2.reverse();
        assert_eq!(r2, e2);

        drop(client);
        server.join().ok();
    }

    #[test]
    fn doh_bad_path_yields_bad_status() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut s = deadline_accept(&listener);
            serve_doh(&mut s, "/dns-query", |q, _cid| answer(q.to_vec())).ok();
        });

        let tcp = deadline_connect(addr);
        let mut client = H2Client::connect(tcp).unwrap();
        let q = vec![0x00, 0x01, 0x02, 0x03];
        let res = client.query("dns.test", "/wrong-path", &q);
        assert!(matches!(res, Err(H2Error::BadStatus(_))));
        drop(client);
        server.join().ok();
    }

    #[test]
    fn doh_large_body_chunked() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut s = deadline_accept(&listener);

            serve_doh(&mut s, "/dns-query", |q, _cid| {
                answer((q.len() as u32).to_be_bytes().to_vec())
            })
            .ok();
        });

        let tcp = deadline_connect(addr);
        let mut client = H2Client::connect(tcp).unwrap();
        let big = vec![0x5A; DEFAULT_MAX_FRAME * 2 + 7];
        let r = client.query("dns.test", "/dns-query", &big).unwrap();
        assert_eq!(r, (big.len() as u32).to_be_bytes().to_vec());
        drop(client);
        server.join().ok();
    }
}
