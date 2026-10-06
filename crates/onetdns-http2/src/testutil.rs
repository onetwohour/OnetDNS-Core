/*!
 * @brief 테스트용 소켓 헬퍼.
 *
 * @details 이 크레이트의 테스트는 루프백으로 서로 붙어 진짜 바이트를 주고받는다. 그런데
 *          데드라인을 걸지 않으면 상대가 한 번 멈출 때 테스트도 함께 영원히 멈춘다. 실패로
 *          끝나지 않으므로 어느 테스트가 왜 멈췄는지 아무 기록도 남지 않고, 테스트
 *          바이너리가 자기 파일을 붙잡은 채 남아 다음 빌드까지 막는다. 연결과 수락을
 *          여기로 모아 두면 새 테스트가 이 규칙을 빠뜨릴 수 없다.
 */

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

/** @brief 멈춘 상대를 기다리는 상한. 넘으면 무한 대기 대신 실패로 끝난다. */
pub(crate) const TEST_DEADLINE: Duration = Duration::from_secs(5);

/** @brief 받고 보내는 데드라인을 함께 건다. */
fn arm(sock: TcpStream) -> TcpStream {
    sock.set_read_timeout(Some(TEST_DEADLINE)).unwrap();
    sock.set_write_timeout(Some(TEST_DEADLINE)).unwrap();
    sock
}

/**
 * @brief 데드라인을 건 소켓으로 연결한다.
 *
 * @note 더 짧은 데드라인이 필요한 테스트는 돌려받은 뒤에 다시 걸면 된다.
 */
pub(crate) fn deadline_connect(addr: SocketAddr) -> TcpStream {
    arm(TcpStream::connect(addr).unwrap())
}

/** @brief 데드라인을 건 소켓으로 받는다. 이유는 deadline_connect 와 같다. */
pub(crate) fn deadline_accept(listener: &TcpListener) -> TcpStream {
    let (sock, _) = listener.accept().unwrap();
    arm(sock)
}
