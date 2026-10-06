/*!
 * @brief 프레임 입출력과 패딩 제거 함수.
 */

use std::io::{Read, Write};

use crate::frame::{self, flags, FrameHeader, DEFAULT_MAX_FRAME, FRAME_HEADER_LEN};
use crate::H2Error;

/**
 * @brief 프레임 하나를 읽는다.
 * @warning 페이로드를 할당하기 전에 길이 상한을 검사한다. 선언된 길이를 그대로 믿고
 *          할당하면 9바이트 헤더 하나로 16MiB를 잡게 만들 수 있다.
 */
pub(crate) fn read_frame<S: Read>(stream: &mut S) -> Result<(FrameHeader, Vec<u8>), H2Error> {
    let mut hdr = [0u8; FRAME_HEADER_LEN];
    match stream.read_exact(&mut hdr) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(H2Error::Closed),
        Err(_) => return Err(H2Error::Io),
    }
    let h = FrameHeader::parse(&hdr).ok_or(H2Error::Protocol)?;
    if h.length as usize > DEFAULT_MAX_FRAME {
        return Err(H2Error::Protocol);
    }
    let mut payload = vec![0u8; h.length as usize];
    read_exact(stream, &mut payload)?;
    Ok((h, payload))
}

/** @brief 프레임 하나를 보낸다. 헤더와 본문을 한 번의 쓰기로 내보낸다. */
pub(crate) fn send_frame<S: Write>(
    stream: &mut S,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> Result<(), H2Error> {
    let mut buf = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    frame::write_frame(&mut buf, frame_type, flags, stream_id, payload);
    stream.write_all(&buf).map_err(|_| H2Error::Io)
}

/** @brief 버퍼를 정확히 채운다. 연결 종료와 그 밖의 오류를 구분해 돌려준다. */
pub(crate) fn read_exact<S: Read>(stream: &mut S, buf: &mut [u8]) -> Result<(), H2Error> {
    match stream.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(H2Error::Closed),
        Err(_) => Err(H2Error::Io),
    }
}

/**
 * @brief HEADERS 페이로드에서 패딩과 우선순위 필드를 걷어내 헤더 블록만 남긴다.
 * @warning 패딩 길이가 남은 본문보다 크면 거부한다. 그대로 빼면 길이가 음수로 뒤집힌다.
 */
pub(crate) fn strip_headers(payload: &[u8], fl: u8) -> Result<&[u8], H2Error> {
    let mut p = payload;
    let mut pad = 0usize;
    if fl & flags::PADDED != 0 {
        pad = *p.first().ok_or(H2Error::Protocol)? as usize;
        p = &p[1..];
    }
    if fl & flags::PRIORITY != 0 {
        if p.len() < 5 {
            return Err(H2Error::Protocol);
        }
        p = &p[5..];
    }
    if pad > p.len() {
        return Err(H2Error::Protocol);
    }
    Ok(&p[..p.len() - pad])
}

/** @brief DATA 페이로드에서 패딩을 걷어낸다. 길이 검사는 strip_headers와 같다. */
pub(crate) fn strip_padding(payload: &[u8], fl: u8) -> Result<&[u8], H2Error> {
    if fl & flags::PADDED == 0 {
        return Ok(payload);
    }
    let pad = *payload.first().ok_or(H2Error::Protocol)? as usize;
    let body = &payload[1..];
    if pad > body.len() {
        return Err(H2Error::Protocol);
    }
    Ok(&body[..body.len() - pad])
}

/** @brief 헤더 목록에서 이름으로 값을 찾는다. */
#[cfg(test)]
pub(crate) fn header<'a>(headers: &'a [(Vec<u8>, Vec<u8>)], name: &[u8]) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_slice())
}
