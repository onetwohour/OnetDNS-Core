/*!
 * @brief DoQ 응용 오류 코드(RFC 9250).
 *
 * @details CONNECTION_CLOSE 의 응용 계층 종료에 싣는다. 서버 리스너와 업스트림 클라이언트가
 *          같은 값을 쓴다.
 */

/** @brief 알릴 오류 없이 연결을 닫는다. */
pub const NO_ERROR: u64 = 0x0;
/** @brief 이쪽 내부 실패로 질의나 연결을 더 이어 갈 수 없다. */
pub const INTERNAL_ERROR: u64 = 0x1;
/** @brief 상대가 DoQ 규격을 어겼다. */
pub const PROTOCOL_ERROR: u64 = 0x2;
/** @brief 부하 때문에 연결을 닫는다. */
pub const EXCESSIVE_LOAD: u64 = 0x4;
