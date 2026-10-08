use std::collections::HashMap;
use std::io::{Read, Write};

use crate::frame::{self, error_code, flags, frame_type, settings, DEFAULT_MAX_FRAME};
use crate::hpack::{self, Decoder};
use crate::wire::{read_exact, read_frame, send_frame, strip_headers, strip_padding};
use crate::{valid_header_field, H2Error};

/** @brief 진행 중인 요청 스트림 하나의 상태. */
struct StreamState {
    /** @brief 이 스트림에서 받은 헤더들. */
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    /** @brief 이 스트림에서 받은 본문. */
    body: Vec<u8>,
    /** @brief 헤더가 다 왔는지. */
    have_headers: bool,
    /** @brief 상대가 다 보냈는지. */
    end_stream: bool,
    /** @brief 이 스트림에 남은 수신 윈도우. 소비한 만큼 WINDOW_UPDATE로 되돌려 준다. */
    recv_window: i64,
}

impl Default for StreamState {
    /** @brief 새 스트림의 초기 상태. 윈도우는 명세가 정한 기본값에서 시작한다. */
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

/**
 * @brief 아직 다 보내지 못한 응답 본문.
 * @details 상대의 흐름 제어 윈도우가 모자라면 여기 남겨 두고, 윈도우가 열릴 때 이어서 보낸다.
 */
struct PendingBody {
    /** @brief 아직 다 보내지 못한 응답 본문. */
    body: Vec<u8>,
    /** @brief 그중 어디까지 보냈는지. */
    offset: usize,
}

/** @brief 요청 처리 결과: 오류 상태 코드이거나 DNS 응답 본문이다. */
enum AppResponse {
    /** @brief 상태만 답한다. */
    Status(&'static str),
    /** @brief DNS 응답을 답한다. */
    Dns(DohAnswer),
}

/**
 * @brief DoH 응답 본문과 HTTP 캐시가 신선하다고 볼 시간.
 *
 * @details 이 계층은 DNS 형식을 모른다. 수명은 응답을 만든 쪽이 측정해서 넘긴다.
 *          RFC 8484는 그 값이 답변부 최소 TTL을 넘지 못하게 규정한다.
 */
pub struct DohAnswer {
    /** @brief DNS 응답 wire. */
    pub body: Vec<u8>,
    /** @brief Cache-Control max-age 초. */
    pub max_age: u32,
}

/** @brief 연결 하나가 동시에 열 수 있는 스트림 수. */
const MAX_H2_STREAMS: usize = 128;

/** @brief 요청 본문 크기 상한. DoH 질의는 이보다 훨씬 작다. */
const MAX_H2_BODY: usize = 64 * 1024;

/** @brief 응답 본문 크기 상한. DNS 메시지의 절대 상한이다. */
const MAX_H2_RESPONSE: usize = u16::MAX as usize;

/** @brief 헤더 블록 하나의 크기 상한. */
const MAX_H2_HEADER_BLOCK: usize = 32 * 1024;

/**
 * @brief 연결 전체에 걸쳐 버퍼링을 허용할 헤더 총량.
 * @warning 스트림별 상한만으로는 부족하다. 스트림을 여러 개 열어 조금씩 채우면 합계가
 *          제한 없이 커지므로, 연결 단위 총량도 함께 막는다.
 */
const MAX_H2_BUFFERED_HEADERS: usize = 1024 * 1024;

/** @brief 연결 전체 요청 본문 버퍼 총량. */
const MAX_H2_BUFFERED_REQUESTS: usize = 1024 * 1024;

/** @brief 연결 전체 미전송 응답 버퍼 총량. 윈도우를 열지 않는 클라이언트를 막는다. */
const MAX_H2_BUFFERED_RESPONSES: usize = 1024 * 1024;

/** @brief 경로에서 뽑는 클라이언트 식별자의 길이 상한. */
const MAX_CLIENT_ID: usize = 256;

/** @brief 흐름 제어 윈도우의 명세 기본값. */
const INITIAL_WINDOW: i64 = 65_535;

/** @brief 흐름 제어 윈도우의 최댓값. 넘기면 FLOW_CONTROL_ERROR다. */
const MAX_WINDOW: i64 = 0x7fff_ffff;

/** @brief 열려 있는 스트림 수: 수신 중인 것과 응답 대기 중인 것의 합. */
fn concurrent_streams(
    streams: &HashMap<u32, StreamState>,
    pending: &HashMap<u32, PendingBody>,
) -> usize {
    streams.len().saturating_add(pending.len())
}

/**
 * @brief DoH 연결 하나를 HTTP/2로 처리한다.
 * @param expected_path 허용할 요청 경로. 그 아래 추가 구간은 클라이언트 식별자가 된다.
 * @param handler 질의 와이어와 클라이언트 식별자를 받아 응답을 만든다.
 */
pub fn serve_doh<S, H>(stream: &mut S, expected_path: &str, handler: H) -> Result<(), H2Error>
where
    S: Read + Write,
    H: Fn(&[u8], Option<&str>) -> Result<DohAnswer, &'static str>,
{
    serve_doh_with_deadline_reset(stream, expected_path, handler, |_| {})
}

/**
 * @brief 데드라인 갱신 훅이 붙은 DoH 서버 루프.
 *
 * @details 서문 확인 → SETTINGS 교환 → 프레임 루프 순이다. 요청이 하나 완결될 때마다
 *          reset_deadline을 불러, 유휴 연결은 끊으면서도 활발한 연결은 유지한다.
 * @param reset_deadline 새 요청을 받았을 때 소켓 데드라인을 다시 잡는다.
 */
pub fn serve_doh_with_deadline_reset<S, H, R>(
    stream: &mut S,
    expected_path: &str,
    handler: H,
    mut reset_deadline: R,
) -> Result<(), H2Error>
where
    S: Read + Write,
    H: Fn(&[u8], Option<&str>) -> Result<DohAnswer, &'static str>,
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

    loop {
        flush_pending(
            stream,
            &mut pending,
            &mut send_stream_windows,
            &mut send_conn_window,
            peer_max_frame,
        )?;

        let (h, payload) = match read_frame(stream) {
            Ok(v) => v,
            Err(H2Error::Closed) => return Ok(()),
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
                if concurrent_streams(&streams, &pending) >= MAX_H2_STREAMS {
                    send_rst_stream(stream, h.stream_id, error_code::REFUSED_STREAM)?;
                    continue;
                }
                let block = strip_headers(&payload, h.flags)?;
                if block.len() > MAX_H2_HEADER_BLOCK {
                    send_rst_stream(stream, h.stream_id, error_code::CANCEL)?;
                    continue;
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
                        let response = process_request(st, expected_path, &handler)?;
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
                    streams.remove(&h.stream_id);
                    send_stream_windows.remove(&h.stream_id);
                    cont_stream = None;
                    cont_block.clear();
                    send_rst_stream(stream, h.stream_id, error_code::CANCEL)?;
                    continue;
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
                            let response = process_request(st, expected_path, &handler)?;
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
                    restore_receive_credit(stream, 0, flow, &mut recv_conn_window)?;
                    send_rst_stream(stream, h.stream_id, error_code::CANCEL)?;
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
                        let response = process_request(st, expected_path, &handler)?;
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

/**
 * @brief 흐름 제어 윈도우를 늘린다.
 * @return 최댓값을 넘으면 오류다. 명세가 FLOW_CONTROL_ERROR로 규정한 상황이며,
 *         그대로 두면 윈도우가 뒤집혀 흐름 제어가 무력화된다.
 */
fn add_window(current: i64, increment: u32) -> Result<i64, H2Error> {
    let next = current
        .checked_add(i64::from(increment))
        .ok_or(H2Error::Protocol)?;
    if next > MAX_WINDOW {
        return Err(H2Error::Protocol);
    }
    Ok(next)
}

/** @brief 소비한 수신 윈도우를 연결과 스트림 양쪽에 되돌려 준다. */
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

/**
 * @brief 윈도우가 허용하는 만큼 미전송 응답을 내보낸다.
 * @details 연결 윈도우와 스트림 윈도우 중 작은 쪽, 그리고 최대 프레임 크기까지가 한 번에 보낼 수
 *          있는 양이다. 다 보낸 스트림만 목록에서 지운다.
 */
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

/** @brief 헤더 목록의 회계상 크기. 항목당 32바이트 오버헤드를 더한다. */
fn header_list_size(headers: &[(Vec<u8>, Vec<u8>)]) -> usize {
    headers
        .iter()
        .fold(0usize, |n, (k, v)| n.saturating_add(k.len() + v.len() + 32))
}

/** @brief 스트림 하나만 끊는다. 연결은 유지된다. */
fn send_rst_stream<S: Write>(stream: &mut S, sid: u32, code: u32) -> Result<(), H2Error> {
    send_frame(stream, frame_type::RST_STREAM, 0, sid, &code.to_be_bytes())
}

/**
 * @brief 요청 헤더가 DoH 규격에 맞는지 검사한다.
 *
 * @details 의사 헤더는 일반 헤더보다 앞에 있어야 하고 각각 하나뿐이어야 한다.
 *          content-length가 있으면 실제 본문 길이와 일치해야 한다.
 * @warning 순서와 중복 규칙을 느슨하게 두면 요청 스머글링(request smuggling)의 경로가 된다.
 *          같은 바이트열을 앞단과 뒷단이 다른 요청으로 해석하게 된다.
 */
/** @brief 요청 자체가 어긋났을 때. */
const STATUS_BAD_REQUEST: &str = "400";

/** @brief 답을 만들었지만 그대로 담아 보낼 수 없을 때. 요청이 아니라 이쪽 사정이다. */
const STATUS_BAD_GATEWAY: &str = "502";
/** @brief 메서드가 이 자원에 쓰이지 않을 때. HTTP/1.1 경로와 같은 코드다. */
const STATUS_METHOD_NOT_ALLOWED: &str = "405";
/** @brief 본문 형식을 다루지 못할 때. RFC 8484가 이곳에 이 코드를 든다. */
const STATUS_UNSUPPORTED_MEDIA_TYPE: &str = "415";
/** @brief DoH 자원이 받는 메서드. 405 응답에 담아 보낸다. */
const ALLOWED_METHODS: &str = "GET, POST";

fn valid_doh_request_headers(
    headers: &[(Vec<u8>, Vec<u8>)],
    body_len: usize,
) -> Result<(&[u8], &[u8]), &'static str> {
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
            /*
             * 형식이 다른 것과 헤더가 겹치는 것은 뜻이 다르다. 겹치는 것은 요청 스머글링의
             * 경로라 그대로 400 이고, 다른 형식은 415 로 구분해야 클라이언트가 고칠 수 있다.
             */
            let is_dns = value.eq_ignore_ascii_case(b"application/dns-message");
            if content_type.replace(is_dns).is_some() {
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
            if content_type == Some(true) {
                Ok((method, path))
            } else {
                Err(STATUS_UNSUPPORTED_MEDIA_TYPE)
            }
        }
        b"GET" if body_len == 0 && content_length.is_none_or(|length| length == 0) => {
            Ok((method, path))
        }
        b"GET" => Err(STATUS_BAD_REQUEST),
        _ => Err(STATUS_METHOD_NOT_ALLOWED),
    }
}

/**
 * @brief 완결된 요청을 처리해 응답을 만든다.
 * @details GET이면 dns 질의 매개변수를 base64url로 디코딩하고, POST면 본문을 그대로 쓴다.
 * @return 오류 상태 코드이거나 DNS 응답 본문.
 */
fn process_request<H>(
    st: StreamState,
    expected_path: &str,
    handler: &H,
) -> Result<AppResponse, H2Error>
where
    H: Fn(&[u8], Option<&str>) -> Result<DohAnswer, &'static str>,
{
    if !st.have_headers {
        return Err(H2Error::Protocol);
    }
    let (method, path) = match valid_doh_request_headers(&st.headers, st.body.len()) {
        Ok(pair) => pair,
        Err(status) => return Ok(AppResponse::Status(status)),
    };
    let path_only = path.split(|&b| b == b'?').next().unwrap_or(b"");
    let client_id = match match_doh_path(path_only, expected_path) {
        Some(cid) => cid,
        None => return Ok(AppResponse::Status("404")),
    };
    let query = match method {
        b"POST" => Some(st.body),
        b"GET" => get_dns_param(path),
        _ => None,
    };
    Ok(match query {
        Some(q) if !q.is_empty() => match handler(&q, client_id.as_deref()) {
            Ok(answer) if answer.body.len() <= MAX_H2_RESPONSE => AppResponse::Dns(answer),
            /* 답을 만들었는데 담아 보낼 수 없는 것은 이쪽 사정이므로 5xx 로 남긴다. */
            Ok(_) => AppResponse::Status(STATUS_BAD_GATEWAY),
            Err(status) => AppResponse::Status(status),
        },
        _ => AppResponse::Status(STATUS_BAD_REQUEST),
    })
}

/** @brief 응답 헤더를 보내고, 본문은 윈도우가 허용하는 만큼만 보낸 뒤 나머지를 미전송으로 남긴다. */
fn queue_response<S: Write>(
    stream: &mut S,
    sid: u32,
    response: AppResponse,
    pending: &mut HashMap<u32, PendingBody>,
    stream_windows: &mut HashMap<u32, i64>,
) -> Result<(), H2Error> {
    match response {
        AppResponse::Status(status) => {
            /*
             * 405 는 받는 메서드를 알려야 한다. 알려 주지 않으면 클라이언트가 무엇으로
             * 다시 물어야 하는지 알 길이 없다.
             */
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
            let body = answer.body;
            let buffered_responses = pending.values().fold(0usize, |size, response| {
                size.saturating_add(response.body.len().saturating_sub(response.offset))
            });
            if buffered_responses.saturating_add(body.len()) > MAX_H2_BUFFERED_RESPONSES {
                pending.remove(&sid);
                stream_windows.remove(&sid);
                return send_rst_stream(stream, sid, error_code::REFUSED_STREAM);
            }
            let content_length = body.len().to_string();
            let cache_control = format!("max-age={}", answer.max_age);
            let block = hpack::encode_response(&[
                (":status", "200"),
                ("content-type", "application/dns-message"),
                ("content-length", &content_length),
                ("cache-control", &cache_control),
            ]);
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
        }
    }
    Ok(())
}

/**
 * @brief 요청 경로가 설정된 DoH 경로인지 보고, 뒤에 붙은 클라이언트 식별자를 추출한다.
 * @return 경로가 맞지 않으면 None. 맞으면 식별자(없을 수 있음)를 돌려준다.
 */
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

/** @brief HTTP/1.1 요청 헤더 크기 상한. */
const MAX_H1_HEADERS: usize = 16 * 1024;

/** @brief HTTP/1.1 요청 본문 크기 상한. */
const MAX_H1_BODY: usize = 64 * 1024;

/**
 * @brief HTTP/1.1로 DoH를 처리한다.
 * @details ALPN에서 h2를 협상하지 못한 클라이언트를 위한 대체 경로다.
 */
pub fn serve_doh_h1<S, H>(stream: &mut S, expected_path: &str, handler: H) -> Result<(), H2Error>
where
    S: Read + Write,
    H: Fn(&[u8], Option<&str>) -> Result<DohAnswer, &'static str>,
{
    serve_doh_h1_with_deadline_reset(stream, expected_path, handler, |_| {})
}

/**
 * @brief 데드라인 갱신 훅이 붙은 HTTP/1.1 DoH 루프.
 * @note Content-Length만 받는다. 청크 전송은 지원하지 않는다. 앞단과 해석이 어긋나면
 *       요청 스머글링이 되므로, 지원하지 않는 인코딩은 받아들이지 않는 편이 안전하다.
 */
pub fn serve_doh_h1_with_deadline_reset<S, H, R>(
    stream: &mut S,
    expected_path: &str,
    handler: H,
    mut reset_deadline: R,
) -> Result<(), H2Error>
where
    S: Read + Write,
    H: Fn(&[u8], Option<&str>) -> Result<DohAnswer, &'static str>,
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
    let mut content_type: Option<bool> = None;
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
            let is_dns = value.eq_ignore_ascii_case(b"application/dns-message");
            if content_type.replace(is_dns).is_some() {
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
    let client_id = match match_doh_path(path_only, expected_path) {
        Some(cid) => cid,
        None => return write_h1_status(stream, "404 Not Found"),
    };

    let query: Option<Vec<u8>> = if method == b"POST" {
        if content_type != Some(true) {
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

    match query {
        Some(q) if !q.is_empty() => match handler(&q, client_id.as_deref()) {
            Ok(answer) if answer.body.len() <= MAX_H2_RESPONSE => {
                write_h1_response(stream, &answer.body, answer.max_age)
            }
            Ok(_) => write_h1_status(stream, "502 Bad Gateway"),
            Err(STATUS_BAD_REQUEST) => write_h1_status(stream, "400 Bad Request"),
            Err(status) => write_h1_status(stream, &format!("{status} Error")),
        },
        _ => write_h1_status(stream, "400 Bad Request"),
    }
}

/** @brief HTTP/1.1 200 응답과 DNS 본문을 쓴다. */
fn write_h1_response<S: Write>(stream: &mut S, body: &[u8], max_age: u32) -> Result<(), H2Error> {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nCache-Control: max-age={max_age}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).map_err(|_| H2Error::Io)?;
    stream.write_all(body).map_err(|_| H2Error::Io)?;
    Ok(())
}

/** @brief 본문 없는 HTTP/1.1 오류 응답을 쓴다. */
fn write_h1_status<S: Write>(stream: &mut S, status: &str) -> Result<(), H2Error> {
    /*
     * 405 는 받는 메서드를 알려야 한다. 알려 주지 않으면 클라이언트가 무엇으로
     * 다시 물어야 하는지 알 길이 없다.
     */
    let allow = if status.starts_with(STATUS_METHOD_NOT_ALLOWED) {
        format!("Allow: {ALLOWED_METHODS}\r\n")
    } else {
        String::new()
    };
    let head =
        format!("HTTP/1.1 {status}\r\n{allow}Content-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).map_err(|_| H2Error::Io)
}

/** @brief 줄 끝의 CR을 떼어 낸다. */
fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

/** @brief 부분열의 위치를 찾는다. */
fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/** @brief GET 경로의 질의 문자열에서 dns 매개변수 값을 추출해 디코딩한다. */
fn get_dns_param(path: &[u8]) -> Option<Vec<u8>> {
    let q = path.split(|&b| b == b'?').nth(1)?;
    for kv in q.split(|&b| b == b'&') {
        if let Some(v) = kv.strip_prefix(b"dns=") {
            return base64url_decode(v);
        }
    }
    None
}

/**
 * @brief base64url을 디코딩한다(RFC 8484의 GET 질의 인코딩).
 * @note 패딩 없는 형태를 받는다. 알파벳 밖 문자는 거부한다.
 */
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

#[cfg(test)]
/** @brief 헤더 검증, 경로 처리, 그리고 두 HTTP 버전의 왕복. */
mod tests {
    use super::*;
    use crate::testutil::{deadline_accept, deadline_connect};
    use crate::wire::header;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    /** @brief HTTP/2로 질의를 보내는 테스트용 클라이언트. */
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

    /** @brief URL용 base64. */
    fn base64url_encode(data: &[u8]) -> String {
        /** @brief base64 문자표. */
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

    /** @brief 테스트용 DoH 응답. 수명은 이 테스트들의 관심사가 아니다. */
    fn answer(body: Vec<u8>) -> Result<DohAnswer, &'static str> {
        Ok(DohAnswer { body, max_age: 0 })
    }

    /** @brief 두 방식으로 왕복해 본다. */
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
    /** @brief 경로에서 클라이언트 식별자를 읽는지. */
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

    /** @brief 테스트용 헤더 목록. */
    fn owned_headers(headers: &[(&[u8], &[u8])]) -> Vec<(Vec<u8>, Vec<u8>)> {
        headers
            .iter()
            .map(|(name, value)| (name.to_vec(), value.to_vec()))
            .collect()
    }

    #[test]
    /**
     * @brief 거절하는 까닭에 맞는 상태 코드를 고르는지.
     *
     * @details HTTP/1.1 경로는 415 와 405 를 구분해 답하는데 HTTP/2 경로는 모두 400 으로
     *          접고 있었다. 같은 서버의 두 전송이 다른 답을 하면 클라이언트가 무엇을
     *          고쳐야 할지 알 수 없다. RFC 8484는 다루지 못하는 형식에 415 를
     *          들고, 그 코드를 본 클라이언트는 다른 서버로 옮겨 갈 수 있다.
     * @note 형식을 아예 밝히지 않은 것도 415 다. RFC 9110은 content-type 이 없으면
     *       application/octet-stream 으로 봐도 된다고 하고, 15.5.16 은 본문을 들여다본
     *       결과로도 415 를 들 수 있다고 한다. 둘 다 이쪽이 받는 형식이 아니다.
     * @note 겹친 content-type 은 415 가 아니라 400 이다. 앞단과 뒷단이 같은 바이트열을
     *       다르게 읽게 만드는 경로라 형식 문제와 뜻이 다르다.
     */
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
    /** @brief 겹치거나 순서가 어긋난 헤더, 길이가 안 맞는 본문을 거부하는지. */
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
    /** @brief 보내기 방식의 왕복. */
    fn doh_post_roundtrip() {
        run(false);
    }

    #[test]
    /** @brief 가져오기 방식의 왕복. */
    fn doh_get_roundtrip() {
        run(true);
    }

    #[test]
    /** @brief 클라이언트가 밀어 보내려는 것을 거부하는지. 규격상 서버만 할 수 있다. */
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
    /** @brief 첫 프레임이 설정인지 확인하는지. */
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
    /** @brief 제어 프레임만 보내는 상대가 데드라인을 늘리지 못하는지. */
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

    /** @brief DoH 요청 헤더 한 벌. 테스트에서 스트림을 열 때 쓴다. */
    fn doh_post_header_block() -> Vec<u8> {
        hpack::encode_response(&[
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "dns.test"),
            (":path", "/dns-query"),
            ("content-type", "application/dns-message"),
        ])
    }

    /** @brief 설정 교환까지 마친 연결을 연다. */
    fn h2_connect(addr: std::net::SocketAddr) -> TcpStream {
        let mut client = deadline_connect(addr);
        client.write_all(frame::PREFACE).unwrap();
        send_frame(&mut client, frame_type::SETTINGS, 0, 0, &[]).unwrap();
        client
    }

    /** @brief 이 연결에서 질의 하나를 주고받는다. 스트림 번호를 지정한다. */
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

    #[test]
    /**
     * @brief 끝나지 않는 CONTINUATION 흐름이 헤더 버퍼를 무한히 키우지 못하는지.
     * @details 상한을 넘는 순간 그 스트림을 끊어야 한다. 끊지 않으면 상대가 END_HEADERS를
     *          영원히 미루며 메모리를 채울 수 있다.
     */
    fn continuation_flood_is_cut_at_the_header_block_limit() {
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
        let mut reset = false;
        while sent <= MAX_H2_HEADER_BLOCK * 2 {
            if send_frame(&mut client, frame_type::CONTINUATION, 0, 1, &chunk).is_err() {
                break;
            }
            sent += chunk.len();
            client
                .set_read_timeout(Some(std::time::Duration::from_millis(50)))
                .unwrap();
            if let Ok((h, _)) = read_frame(&mut client) {
                if h.frame_type == frame_type::RST_STREAM && h.stream_id == 1 {
                    reset = true;
                    break;
                }
            }
        }
        assert!(
            reset,
            "헤더 상한을 넘겨도 스트림을 끊지 않았습니다. {sent}바이트를 버퍼에 쌓았습니다"
        );
        drop(client);
        let _ = server.join().unwrap();
    }

    #[test]
    /**
     * @brief 열자마자 끊기를 되풀이해도 스트림 예산이 새지 않는지.
     * @details 끊긴 스트림이 예산을 물고 있으면 상한만큼 되풀이한 뒤 정상 질의가 거절된다.
     *          요청 처리는 프레임 루프 안에서 동기로 끝나므로 되풀이가 일을 늘리지도 않는다.
     */
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

    #[test]
    /** @brief URL용 base64의 왕복. */
    fn base64url_roundtrip() {
        let data = vec![0u8, 1, 2, 250, 255, 128, 64];
        let enc = base64url_encode(&data);
        assert_eq!(base64url_decode(enc.as_bytes()).unwrap(), data);
        assert!(base64url_decode(b"YQ==").is_none());
        assert!(base64url_decode(b"A").is_none());
        assert!(base64url_decode(b"YR").is_none());
    }

    /** @brief HTTP/1.1로 요청을 보내는 테스트용 클라이언트. */
    fn h1_request(addr: std::net::SocketAddr, raw: &[u8]) -> Vec<u8> {
        let mut c = deadline_connect(addr);
        c.write_all(raw).unwrap();
        let mut resp = Vec::new();
        c.read_to_end(&mut resp).unwrap();
        resp
    }

    /** @brief HTTP/1.1로 왕복해 본다. */
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
    /**
     * @brief 본문을 거절할 때 4xx 와 5xx 를 가려 내는지.
     *
     * @details RFC 8484는 DoH 클라이언트가 다른 HTTP 클라이언트와 같은 방식으로
     *          상태 코드를 해석하게 한다. 그러면 5xx 는 서버 잘못이라는 뜻이라 클라이언트가
     *          같은 서버에 다시 보내고, 서버 오류 지표도 요청 잘못으로 오염된다. 읽지 못한
     *          본문은 요청 잘못이다. HTTP/1.1 과 HTTP/2 가 같은 값을 내야 한다.
     */
    fn doh_body_rejections_are_client_errors_not_server_errors() {
        /** @brief 요청 하나를 보내고 상태 줄만 돌려준다. */
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

        /*
         * HTTP/2 쪽도 같은 값을 내야 한다. 두 경로가 갈리면 클라이언트가 전송에 따라
         * 다른 판단을 하게 된다.
         */
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
    /**
     * @brief DoH 응답이 신선도를 밝히는지.
     *
     * @details RFC 8484는 DoH 서버가 명시적인 신선도를 붙이게 하고 그 값이 답변부
     *          최소 TTL을 넘지 못하게 한다.
     */
    fn doh_responses_declare_their_freshness() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut s = deadline_accept(&listener);
            serve_doh_h1(&mut s, "/dns-query", |_q, _id| {
                Ok(DohAnswer {
                    body: vec![1, 2, 3],
                    max_age: 137,
                })
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
    /** @brief HTTP/1.1 보내기 방식의 왕복. */
    fn doh_h1_post_roundtrip() {
        run_h1(false);
    }

    #[test]
    /** @brief HTTP/1.1 가져오기 방식의 왕복. */
    fn doh_h1_get_roundtrip() {
        run_h1(true);
    }

    #[test]
    /** @brief 잘못된 경로를 거부하는지. */
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

    /** @brief 응답의 상태 줄. */
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
    /**
     * @brief 405 응답이 받는 메서드를 알려 주는지.
     *
     * @details RFC 9110은 405 에 Allow 를 반드시 실으라고 한다. 없으면 클라이언트가
     *          어떤 메서드로 다시 물어야 하는지 알 길이 없어 그냥 포기한다.
     */
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
    /** @brief 경계가 애매한 요청을 거부하는지. 받아들이면 요청 하나가 둘로 읽힌다. */
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
    /** @brief 응답이 DNS 크기 상한을 넘지 않는지. */
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
    /** @brief 아직 못 보낸 응답도 동시 스트림 몫을 쓰는지. 안 세면 상한이 무의미하다. */
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
    /** @brief 못 보낸 응답 바이트에 연결 단위 상한이 걸리는지. */
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
}
