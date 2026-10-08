use std::io::{Read, Write};

use crate::frame::{flags, frame_type, settings, DEFAULT_MAX_FRAME};
use crate::hpack::{self, Decoder};
use crate::wire::{read_frame, send_frame, strip_headers, strip_padding};
use crate::{valid_header_field, H2Error};

/** @brief 받아들일 DNS 응답 본문 크기 상한. DNS 메시지의 절대 상한과 같다. */
const MAX_DNS_RESPONSE: usize = u16::MAX as usize;

/** @brief 응답 헤더 목록 크기 상한. SETTINGS로 상대에게도 광고한다. */
const MAX_RESPONSE_HEADERS: usize = 32 * 1024;

/**
 * @brief 응답 헤더에서 상태와 본문 길이를 뽑고 검사한다.
 * @details :status는 정확히 하나여야 한다. 중복 의사 헤더를 허용하면 어느 값이 유효한지가
 *          구현마다 갈린다. 200 응답은 content-type이 application/dns-message 하나여야 하고
 *          본문이 DNS 메시지 상한 안이어야 한다. 200이 아닌 응답은 본문을 읽지 않으므로 그
 *          둘을 보지 않는다. 404 text/html 같은 답을 여기서 거부하면 상태 오류가 프로토콜
 *          오류로 바뀐다.
 * @return 규칙을 어기면 None. 호출자는 프로토콜 오류로 처리한다.
 */
fn response_metadata(headers: &[(Vec<u8>, Vec<u8>)]) -> Option<(u16, Option<usize>)> {
    let mut status = None;
    let mut content_length = None;
    let mut content_types = 0usize;
    let mut dns_content_type = false;
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
            if !(200..=599).contains(&parsed) {
                return None;
            }
            status = Some(parsed);
            continue;
        }

        regular_seen = true;
        if name.iter().any(u8::is_ascii_uppercase)
            || matches!(
                name.as_slice(),
                b"connection"
                    | b"proxy-connection"
                    | b"keep-alive"
                    | b"te"
                    | b"transfer-encoding"
                    | b"upgrade"
            )
        {
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
            dns_content_type = value.eq_ignore_ascii_case(b"application/dns-message");
        }
    }

    let status = status?;
    if status == 200
        && (content_types != 1
            || !dns_content_type
            || content_length.is_some_and(|length| length > MAX_DNS_RESPONSE))
    {
        return None;
    }
    Some((status, content_length))
}

/**
 * @brief DoH 업스트림에 붙는 HTTP/2 클라이언트.
 * @details 전송 계층(TLS)은 S가 담당한다. 이 타입은 프레이밍과 헤더만 다룬다.
 */
pub struct H2Client<S> {
    /** @brief 하위 전송 스트림. */
    stream: S,

    /** @brief 헤더를 읽는 쪽. */
    dec: Decoder,

    /** @brief 다음에 쓸 스트림 번호. 클라이언트는 홀수만 쓴다. */
    next_id: u32,

    /** @brief 상대의 첫 SETTINGS를 받았는지. 프로토콜 준수 확인용이다. */
    peer_settings_seen: bool,
}

impl<S: Read + Write> H2Client<S> {
    /**
     * @brief 서문과 초기 SETTINGS를 보내 연결을 연다.
     * @note 서버 푸시를 끈다. 이 클라이언트는 푸시를 처리하지 않으므로, 켜 둔 채
     *       받으면 프로토콜 오류로 연결이 끊긴다.
     * @note 헤더 목록 크기도 함께 광고해 상대가 과도한 헤더를 보내지 않게 한다.
     */
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
        })
    }

    /** @brief 하위 전송을 빌린다. 데드라인 시각 조정 등에 쓴다. */
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /** @brief DNS 질의를 보내고 응답 와이어를 받는다. */
    pub fn query(
        &mut self,
        authority: &str,
        path: &str,
        dns_wire: &[u8],
    ) -> Result<Vec<u8>, H2Error> {
        self.query_inner(authority, path, dns_wire, false, |_| {})
    }

    /**
     * @brief 질의와 함께 PING을 보내 두 단계 데드라인을 만든다.
     * @details 재사용 중인 연결은 죽었는지 살았는지 보내기 전에는 알 수 없다. PING 응답이
     *          오면 연결은 살아 있는 것이므로, 그 시점에 데드라인을 늘려 업스트림의 해석 시간을
     *          기다려 준다. PING도 안 오면 죽은 연결이니 빨리 포기한다.
     * @param on_alive PING 응답이 왔을 때 불린다. 데드라인을 다시 잡는 데 쓴다.
     */
    pub fn query_probed(
        &mut self,
        authority: &str,
        path: &str,
        dns_wire: &[u8],
        on_alive: impl FnOnce(&mut S),
    ) -> Result<Vec<u8>, H2Error> {
        self.query_inner(authority, path, dns_wire, true, on_alive)
    }

    /** @brief 질의 전송과 응답 수신의 공통 구현. */
    fn query_inner(
        &mut self,
        authority: &str,
        path: &str,
        dns_wire: &[u8],
        probe: bool,
        on_alive: impl FnOnce(&mut S),
    ) -> Result<Vec<u8>, H2Error> {
        let sid = self.allocate_stream_id()?;

        let clen = dns_wire.len().to_string();
        let headers: [(&str, &str); 7] = [
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", authority),
            (":path", path),
            ("accept", "application/dns-message"),
            ("content-type", "application/dns-message"),
            ("content-length", &clen),
        ];

        let block = hpack::encode_response(&headers);
        send_frame(
            &mut self.stream,
            frame_type::HEADERS,
            flags::END_HEADERS,
            sid,
            &block,
        )?;

        if dns_wire.is_empty() {
            send_frame(
                &mut self.stream,
                frame_type::DATA,
                flags::END_STREAM,
                sid,
                &[],
            )?;
        } else {
            /** @brief 규격이 정한 처음 흐름 제어 윈도우. */
            const INITIAL_CONNECTION_WINDOW: usize = 65_535;
            if dns_wire.len() > INITIAL_CONNECTION_WINDOW {
                return Err(H2Error::Protocol);
            }
            let mut chunks = dns_wire.chunks(DEFAULT_MAX_FRAME).peekable();
            while let Some(chunk) = chunks.next() {
                let fl = if chunks.peek().is_none() {
                    flags::END_STREAM
                } else {
                    0
                };
                send_frame(&mut self.stream, frame_type::DATA, fl, sid, chunk)?;
            }
        }
        let ping_token = u64::from(sid).to_be_bytes();
        if probe {
            send_frame(&mut self.stream, frame_type::PING, 0, 0, &ping_token)?;
        }

        self.read_response(sid, ping_token, on_alive)
    }

    /**
     * @brief 다음 스트림 번호를 잡는다.
     * @warning 31비트를 넘기면 예약 비트를 침범하므로 오류를 낸다. 되감으면 이전 스트림과
     *          번호가 겹쳐 응답이 뒤섞인다. 이 연결은 버리고 새로 열어야 한다.
     */
    fn allocate_stream_id(&mut self) -> Result<u32, H2Error> {
        let sid = self.next_id;
        if sid == 0 || sid > 0x7fff_ffff {
            return Err(H2Error::Closed);
        }
        self.next_id = sid
            .checked_add(2)
            .filter(|next| *next <= 0x7fff_ffff)
            .unwrap_or(0);
        Ok(sid)
    }

    /**
     * @brief 소비한 만큼 수신 윈도우를 되돌려 준다.
     * @details 연결 윈도우와 스트림 윈도우 둘 다 갱신해야 한다. 하나만 열면 큰 응답이 중간에서
     *          멈춘다. 상대가 남은 데이터를 보낼 수 없기 때문이다.
     */
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

    /**
     * @brief 이쪽 스트림의 응답을 다 받을 때까지 프레임을 읽는다.
     *
     * @details 다른 스트림의 프레임과 제어 프레임(SETTINGS·PING·WINDOW_UPDATE)은 규칙대로
     *          처리하고 넘어간다. 본문은 content-length가 있으면 그 값에서, 없으면
     *          절대 상한에서 잘린다. 끝없이 보내는 업스트림이 메모리를 먹지 못하게 한다.
     */
    fn read_response(
        &mut self,
        sid: u32,
        ping_token: [u8; 8],
        on_alive: impl FnOnce(&mut S),
    ) -> Result<Vec<u8>, H2Error> {
        let mut body = Vec::new();
        let mut status_ok: Option<bool> = None;
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
                    return Err(H2Error::Closed);
                }
                frame_type::RST_STREAM => {
                    if h.stream_id == 0 || payload.len() != 4 {
                        return Err(H2Error::Protocol);
                    }
                    if h.stream_id == sid {
                        return Err(H2Error::Protocol);
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
                    if status_ok.is_some() || !h.has_flag(flags::END_HEADERS) {
                        return Err(H2Error::Protocol);
                    }
                    let blk = strip_headers(&payload, h.flags)?;
                    let hs = self.dec.decode(blk).ok_or(H2Error::Protocol)?;
                    let (status, length) = response_metadata(&hs).ok_or(H2Error::Protocol)?;
                    status_ok = Some(status == 200);
                    content_length = length;
                    if status_ok != Some(true) {
                        return Err(H2Error::BadStatus);
                    }
                    if h.has_flag(flags::END_STREAM) {
                        if content_length.is_some_and(|length| length != body.len()) {
                            return Err(H2Error::Protocol);
                        }
                        return Ok(body);
                    }
                }
                frame_type::DATA if h.stream_id == sid => {
                    if status_ok != Some(true) {
                        return Err(H2Error::Protocol);
                    }
                    let data = strip_padding(&payload, h.flags)?;
                    if body.len().saturating_add(data.len()) > MAX_DNS_RESPONSE {
                        return Err(H2Error::Protocol);
                    }
                    body.extend_from_slice(data);

                    let _ = self.replenish_receive_window(
                        sid,
                        payload.len(),
                        !h.has_flag(flags::END_STREAM),
                    );
                    if h.has_flag(flags::END_STREAM) {
                        if content_length.is_some_and(|length| length != body.len()) {
                            return Err(H2Error::Protocol);
                        }
                        return Ok(body);
                    }
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
/** @brief 헤더와 본문 검증, 흐름 제어, 그리고 실제 왕복. */
mod tests {
    use super::*;
    use crate::serve_doh;
    use crate::testutil::{deadline_accept, deadline_connect};
    use std::net::TcpListener;
    use std::thread;

    /** @brief 테스트용 헤더 목록. */
    fn owned_headers(headers: &[(&[u8], &[u8])]) -> Vec<(Vec<u8>, Vec<u8>)> {
        headers
            .iter()
            .map(|(name, value)| (name.to_vec(), value.to_vec()))
            .collect()
    }

    #[test]
    /** @brief 상태가 겹치거나, 200 응답이 DNS 메시지를 싣지 않았다고 알리면 거부하는지. */
    fn response_headers_reject_duplicate_status_bad_type_and_oversized_length() {
        let duplicate: [(&[u8], &[u8]); 3] = [
            (b":status", b"200"),
            (b":status", b"200"),
            (b"content-type", b"application/dns-message"),
        ];
        assert!(response_metadata(&owned_headers(&duplicate)).is_none());

        let bad_type: [(&[u8], &[u8]); 2] =
            [(b":status", b"200"), (b"content-type", b"text/plain")];
        assert!(response_metadata(&owned_headers(&bad_type)).is_none());

        let two_types = owned_headers(&[
            (b":status", b"200"),
            (b"content-type", b"application/dns-message"),
            (b"content-type", b"application/dns-message"),
        ]);
        assert!(response_metadata(&two_types).is_none());

        let oversized = (MAX_DNS_RESPONSE + 1).to_string();
        let oversized_headers = owned_headers(&[
            (b":status", b"200"),
            (b"content-type", b"application/dns-message"),
            (b"content-length", oversized.as_bytes()),
        ]);
        assert!(response_metadata(&oversized_headers).is_none());
    }

    #[test]
    /**
     * @brief 200이 아닌 응답은 본문 종류와 길이로 거부하지 않는지.
     * @details 거부하면 상태 오류가 프로토콜 오류로 바뀐다.
     */
    fn error_status_is_not_judged_as_a_dns_answer() {
        let html = owned_headers(&[(b":status", b"404"), (b"content-type", b"text/html")]);
        assert_eq!(response_metadata(&html), Some((404, None)));

        let page_length = (MAX_DNS_RESPONSE + 1).to_string();
        let long_page = owned_headers(&[
            (b":status", b"404"),
            (b"content-type", b"text/html"),
            (b"content-length", page_length.as_bytes()),
        ]);
        assert_eq!(
            response_metadata(&long_page),
            Some((404, Some(MAX_DNS_RESPONSE + 1)))
        );

        let bare = owned_headers(&[(b":status", b"503")]);
        assert_eq!(response_metadata(&bare), Some((503, None)));
    }

    #[test]
    /** @brief DoH 경로를 모르는 웹 서버의 404 text/html 답이 상태 오류로 끝나는지. */
    fn error_page_yields_bad_status() {
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
            let page = b"<html>not here</html>";
            let length = page.len().to_string();
            let block = hpack::encode_response(&[
                (":status", "404"),
                ("content-type", "text/html"),
                ("content-length", length.as_str()),
            ]);
            send_frame(
                &mut stream,
                frame_type::HEADERS,
                flags::END_HEADERS,
                1,
                &block,
            )
            .unwrap();
            /* 클라이언트는 헤더만 보고 끊을 수 있으므로 본문 전송 실패는 상관없다. */
            let _ = send_frame(&mut stream, frame_type::DATA, flags::END_STREAM, 1, page);
        });

        let tcp = deadline_connect(addr);
        let mut client = H2Client::connect(tcp).unwrap();
        let result = client.query("dns.test", "/dns-query", b"query");
        assert!(matches!(result, Err(H2Error::BadStatus)), "{result:?}");
        drop(client);
        server.join().unwrap();
    }

    #[test]
    /** @brief 헤더 문법이 어긋나면 거부하는지. */
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
            assert!(response_metadata(&headers).is_none(), "{name:?}: {value:?}");
        }

        let mut bad_length = owned_headers(&valid);
        bad_length.push((b"content-length".to_vec(), b"+3".to_vec()));
        assert!(response_metadata(&bad_length).is_none());
    }

    #[test]
    /** @brief 길이를 안 알려 줘도 본문에 상한이 걸리는지. 없으면 끝없이 보내 메모리를 채운다. */
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

    /** @brief 상대가 보낸 프레임을 처리한 결과. */
    fn peer_frame_result(
        send_settings_first: bool,
        frame_type: u8,
        frame_flags: u8,
        stream_id: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>, H2Error> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let payload = payload.to_vec();
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
            loop {
                let (header, _) = read_frame(&mut stream).unwrap();
                if header.stream_id == 1 && header.has_flag(flags::END_STREAM) {
                    break;
                }
            }
            send_frame(&mut stream, frame_type, frame_flags, stream_id, &payload).unwrap();
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

    #[test]
    /** @brief 상대의 첫 프레임이 규격대로인지 확인하는지. */
    fn first_peer_frame_must_be_non_ack_settings() {
        assert!(matches!(
            peer_frame_result(false, frame_type::PING, 0, 0, &[0; 8]),
            Err(H2Error::Protocol)
        ));
        assert!(matches!(
            peer_frame_result(false, frame_type::SETTINGS, flags::ACK, 0, &[]),
            Err(H2Error::Protocol)
        ));
    }

    #[test]
    /** @brief 어긋난 제어 프레임을 거부하는지. */
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
        for &(kind, frame_flags, stream_id, payload) in malformed {
            assert!(matches!(
                peer_frame_result(true, kind, frame_flags, stream_id, payload),
                Err(H2Error::Protocol)
            ));
        }
    }

    #[test]
    /** @brief 큰 응답에도 흐름 제어 윈도우가 다시 채워지는지. 안 채우면 도중에 멈춘다. */
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

    #[test]
    /** @brief 스트림 번호가 예약 비트를 침범하지 않는지. */
    fn stream_ids_never_wrap_into_the_reserved_bit() {
        let mut client = H2Client::connect(std::io::Cursor::new(Vec::new())).unwrap();
        client.next_id = 0x7fff_ffff;
        assert!(matches!(client.allocate_stream_id(), Ok(0x7fff_ffff)));
        assert!(matches!(client.allocate_stream_id(), Err(H2Error::Closed)));
    }

    #[test]
    /** @brief 서버가 밀어 보내는 것을 처음부터 끄는지. 켜 두면 안 쓰는 자원을 상대가 채운다. */
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

    /** @brief 테스트용 DoH 응답. 수명은 이 테스트들의 관심사가 아니다. */
    fn answer(body: Vec<u8>) -> Result<crate::server::DohAnswer, &'static str> {
        Ok(crate::server::DohAnswer { body, max_age: 0 })
    }

    #[test]
    /** @brief 이쪽 서버와 이쪽 클라이언트의 왕복. */
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
    /** @brief 잘못된 경로가 오류 상태를 내는지. */
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
        assert!(matches!(res, Err(H2Error::BadStatus)));
        drop(client);
        server.join().ok();
    }

    #[test]
    /** @brief 큰 본문이 나뉘어 와도 이어지는지. */
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
