/*!
 * @brief HTTP/2: DoH 전용 구현.
 *
 * @details 범용 HTTP/2 스택이 아니다. DoH가 실제로 쓰는 것만 구현했고, 클라이언트는
 *          POST와 application/dns-message로 고정돼 있다. 서버·클라이언트 모두 서버
 *          푸시나 우선순위 같은 기능을 다루지 않는다.
 */

/** @brief DoH 업스트림에 붙는 클라이언트. */
pub mod client;
/** @brief 프레임 읽고 쓰기. */
pub mod frame;
/** @brief 헤더 압축. */
pub mod hpack;
/** @brief 헤더 압축이 쓰는 글자 부호. */
pub mod huffman;
/** @brief DoH 수신 쪽. */
pub mod server;
/** @brief 테스트용 소켓 헬퍼. */
#[cfg(test)]
mod testutil;
/** @brief 바이트를 읽고 쓰는 기본 도구. */
pub(crate) mod wire;

pub use client::H2Client;
pub use server::{
    serve_doh, serve_doh_h1, serve_doh_h1_with_deadline_reset, serve_doh_with_deadline_reset,
    DohAnswer,
};

/**
 * @brief 헤더 필드가 HTTP/2 규칙을 지키는지.
 *
 * @details 이름은 소문자여야 하고 토큰 문자만 허용한다. 값에는 NUL·CR·LF가 올 수 없고
 *          앞뒤 공백도 안 된다.
 * @warning 이 검사가 헤더 주입 방어다. CR/LF를 통과시키면 값 하나로 헤더를 새로 만들거나
 *          응답을 쪼갤 수 있다. 의사 헤더(:로 시작)는 첫 글자만 예외로 두고, 이름 안에
 *          :가 더 있으면 거부한다.
 */
pub fn valid_header_field(name: &[u8], value: &[u8]) -> bool {
    let token = name.strip_prefix(b":").unwrap_or(name);
    if token.is_empty()
        || !token.iter().all(|&byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
    {
        return false;
    }
    if name != token && name[1..].contains(&b':') {
        return false;
    }
    !value.iter().any(|&byte| matches!(byte, 0 | b'\r' | b'\n'))
        && !value
            .first()
            .is_some_and(|&byte| matches!(byte, b' ' | b'\t'))
        && !value
            .last()
            .is_some_and(|&byte| matches!(byte, b' ' | b'\t'))
}

/** @brief HTTP/2 오류. */
#[derive(Debug)]
pub enum H2Error {
    /** @brief 주고받는 중 오류가 났다. */
    Io,
    /** @brief 프로토콜 위반. 연결을 재사용하지 않고 끊어야 한다. */
    Protocol,

    /** @brief 상대가 연결을 닫았다. 재연결로 복구할 수 있다. */
    Closed,

    /**
     * @brief 200이 아닌 응답 상태. DoH 업스트림이 요청을 거절한 경우다.
     * @details 그 스트림만 끝났으므로 연결은 계속 쓸 수 있다.
     */
    BadStatus,
}
