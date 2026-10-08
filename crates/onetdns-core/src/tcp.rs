/*!
 * @brief 절대 데드라인 안에서만 읽고 쓰는 TCP 연결.
 *
 * @details 소켓 제한 시간을 고정값으로 걸면 한 바이트씩 아주 느리게 보내는 상대가 읽기마다 제한
 *          시간을 새로 얻어 연결을 무한정 붙든다. 그래서 읽기와 쓰기마다 데드라인까지 남은 시간을
 *          다시 계산해 소켓에 건다. 종료 신호를 건 연결은 기다리는 동안 그 신호를 STOP_POLL
 *          간격으로 확인하므로, 서버를 멈출 때 데드라인까지 기다리지 않는다.
 */

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/**
 * @brief 종료 신호를 확인하는 간격.
 * @details 종료 신호가 선 연결은 이 시간 안에 끊긴다. 줄이면 기다리는 연결마다 깨어나는 횟수가
 *          늘어난다.
 */
pub const STOP_POLL: Duration = Duration::from_millis(250);

/** @brief 소켓에 읽기와 쓰기 제한 시간을 걸 수 있는 연결. */
pub trait SocketTimeouts {
    /** @brief 읽기 제한 시간을 건다. */
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    /** @brief 쓰기 제한 시간을 건다. */
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl SocketTimeouts for TcpStream {
    /** @brief 소켓에 그대로 건다. */
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }

    /** @brief 소켓에 그대로 건다. */
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, timeout)
    }
}

/** @brief 데드라인까지 남은 시간. 이미 지났으면 TimedOut 오류다. */
pub fn time_left(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| io::ErrorKind::TimedOut.into())
}

/**
 * @brief 절대 데드라인과 종료 신호를 지키는 연결.
 * @details 데드라인은 읽기 한 번이 아니라 데드라인을 다시 잡기 전까지 이 연결로 하는 일 전체에
 *          걸린다. 데드라인이 지나면 읽기와 쓰기가 TimedOut 으로, 종료 신호가 서면
 *          ConnectionAborted 로 끝난다. 종료 신호가 없으면 남은 시간을 한 번에 걸고 기다린다.
 */
pub struct DeadlineTcp<S = TcpStream> {
    /** @brief 실제 연결. */
    stream: S,
    /** @brief 이 시각까지만 기다린다. */
    deadline: Instant,
    /** @brief 하나라도 서면 기다리던 읽기와 쓰기를 끊는다. */
    stop: Vec<Arc<AtomicBool>>,
    /** @brief 데드라인을 마지막으로 잡은 뒤 한 바이트라도 읽었는지. */
    received: bool,
}

impl DeadlineTcp {
    /** @brief 데드라인 안에 접속한다. */
    pub fn connect(addr: SocketAddr, deadline: Instant) -> io::Result<Self> {
        let stream = TcpStream::connect_timeout(&addr, time_left(deadline)?)?;
        Ok(Self::new(stream, deadline))
    }
}

impl<S> DeadlineTcp<S> {
    /** @brief 이어진 연결에 데드라인을 건다. */
    pub fn new(stream: S, deadline: Instant) -> Self {
        Self {
            stream,
            deadline,
            stop: Vec::new(),
            received: false,
        }
    }

    /** @brief 종료 신호를 하나 더 건다. 서버 전체와 리스너 하나처럼 신호가 여럿일 수 있다. */
    pub fn stop_on(mut self, flag: Arc<AtomicBool>) -> Self {
        self.stop.push(flag);
        self
    }

    /** @brief 데드라인을 다시 잡는다. 요청 하나를 마치고 다음 요청을 기다릴 때 쓴다. */
    pub fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = deadline;
        self.received = false;
    }

    /**
     * @brief 데드라인을 다시 잡은 뒤 한 바이트도 받지 못한 채 데드라인이 지났는지.
     * @details 다음 요청을 기다리며 데드라인을 잡았다면 쉬다가 끝난 연결이다. 요청을 보내다 멈춘
     *          상대는 일부라도 보냈으므로 여기에 들지 않는다.
     */
    pub fn idle_expired(&self) -> bool {
        !self.received && Instant::now() >= self.deadline
    }

    /** @brief 실제 연결. 소켓 옵션을 바꾸거나 주소를 읽을 때 쓴다. */
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /** @brief 데드라인과 종료 신호를 떼어 내고 실제 연결을 돌려준다. */
    pub fn into_inner(self) -> S {
        self.stream
    }

    /** @brief 종료 신호가 섰는지. */
    fn stopped(&self) -> bool {
        self.stop.iter().any(|flag| flag.load(Ordering::Relaxed))
    }
}

impl<S: SocketTimeouts> DeadlineTcp<S> {
    /** @brief 이번 대기에 걸 제한 시간. 종료 신호가 섰거나 데드라인이 지났으면 오류다. */
    fn wait(&self) -> io::Result<Duration> {
        if self.stopped() {
            /*
             * read_exact 와 write_all 은 Interrupted 를 끝없이 다시 시도하므로, 종료는 그대로
             * 끝나는 다른 오류로 알린다.
             */
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        let left = time_left(self.deadline)?;
        Ok(if self.stop.is_empty() {
            left
        } else {
            left.min(STOP_POLL)
        })
    }

    /**
     * @brief 제한 시간에 걸려 끝난 대기를 다시 시작할지.
     * @details 종료 신호를 확인하려고 데드라인보다 짧게 잘라 기다린 경우만 다시 시작한다. 그사이
     *          종료 신호가 섰으면 다음 wait 가 ConnectionAborted 로 끝낸다.
     */
    fn waits_again(&self, error: &io::Error) -> bool {
        !self.stop.is_empty()
            && matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            )
            && Instant::now() < self.deadline
    }
}

impl<S: Read + SocketTimeouts> Read for DeadlineTcp<S> {
    /** @brief 남은 시간을 걸고 읽는다. */
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let wait = self.wait()?;
            self.stream.set_read_timeout(Some(wait))?;
            match self.stream.read(buf) {
                Err(error) if self.waits_again(&error) => {}
                result => {
                    self.received |= matches!(result, Ok(n) if n > 0);
                    return result;
                }
            }
        }
    }
}

impl<S: Write + SocketTimeouts> Write for DeadlineTcp<S> {
    /** @brief 남은 시간을 걸고 쓴다. */
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let wait = self.wait()?;
            self.stream.set_write_timeout(Some(wait))?;
            match self.stream.write(buf) {
                Err(error) if self.waits_again(&error) => {}
                result => return result,
            }
        }
    }

    /**
     * @brief 비운다.
     * @note TCP 의 flush 는 기다리지 않으므로 제한 시간을 걸지 않는다. 데드라인은 쓰기가 지킨다.
     */
    fn flush(&mut self) -> io::Result<()> {
        if self.stopped() {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        self.stream.flush()
    }
}

#[cfg(test)]
/** @brief 데드라인과 종료 신호가 지켜지는지. */
mod tests {
    use super::*;
    use std::net::TcpListener;

    /** @brief 접속을 받아 열 바이트를 30밀리초마다 하나씩 보내는 상대. */
    fn slow_drip_peer() -> (SocketAddr, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for byte in 0..10 {
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(30));
            }
        });
        (addr, peer)
    }

    #[test]
    /** @brief 한 바이트씩 흘려 보내는 상대가 읽을 때마다 데드라인을 되살리지 못하는지. */
    fn slow_drip_cannot_extend_the_deadline() {
        let (addr, peer) = slow_drip_peer();
        let started = Instant::now();
        let mut stream = DeadlineTcp::connect(addr, started + Duration::from_millis(120)).unwrap();
        let mut bytes = [0u8; 10];
        let error = stream.read_exact(&mut bytes).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        assert!(started.elapsed() < Duration::from_millis(500));
        peer.join().unwrap();
    }

    #[test]
    /** @brief 종료 신호를 건 연결도 같은 데드라인에 끊기는지. 잘라 기다리는 반복이 데드라인을 넘기지 않아야 한다. */
    fn slow_drip_cannot_extend_the_deadline_while_watching_stop() {
        let (addr, peer) = slow_drip_peer();
        let started = Instant::now();
        let mut stream = DeadlineTcp::connect(addr, started + Duration::from_millis(120))
            .unwrap()
            .stop_on(Arc::new(AtomicBool::new(false)));
        let mut bytes = [0u8; 10];
        let error = stream.read_exact(&mut bytes).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        assert!(started.elapsed() < Duration::from_millis(500));
        peer.join().unwrap();
    }

    #[test]
    /** @brief 종료 신호가 서면 데드라인이 멀어도 기다리던 읽기가 곧 끝나는지. */
    fn stop_ends_a_blocked_read_before_the_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let mut stream = DeadlineTcp::new(server, Instant::now() + Duration::from_secs(30))
            .stop_on(Arc::new(AtomicBool::new(false)))
            .stop_on(stop.clone());
        let reader = std::thread::spawn(move || {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).unwrap_err().kind()
        });
        std::thread::sleep(Duration::from_millis(20));
        let started = Instant::now();
        stop.store(true, Ordering::Release);
        assert_eq!(reader.join().unwrap(), io::ErrorKind::ConnectionAborted);
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(client);
    }

    #[test]
    /** @brief 종료 오류가 read_exact 와 write_all 이 다시 시도하는 종류가 아닌지. */
    fn stop_is_terminal_for_read_write_and_flush() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let mut stream = DeadlineTcp::new(server, Instant::now() + Duration::from_secs(30))
            .stop_on(Arc::new(AtomicBool::new(true)));
        assert_eq!(
            stream.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            stream.write(&[0]).unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            stream.flush().unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        drop(client);
    }

    #[test]
    /** @brief 종료 신호를 확인하려고 잘라 기다려도, 신호가 없으면 늦게 온 데이터를 받는지. */
    fn watching_stop_still_waits_for_late_data() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            std::thread::sleep(STOP_POLL * 2);
            stream.write_all(b"late").unwrap();
        });
        let mut stream = DeadlineTcp::connect(addr, Instant::now() + Duration::from_secs(5))
            .unwrap()
            .stop_on(Arc::new(AtomicBool::new(false)));
        let mut bytes = [0u8; 4];
        stream.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"late");
        peer.join().unwrap();
    }

    #[test]
    /**
     * @brief 데드라인을 잡은 뒤 아무것도 받지 못하고 끝난 대기만 쉬다가 끝난 것으로 보는지.
     * @details 일부라도 보낸 상대를 쉬던 연결로 보면 요청을 보내다 멈춘 것이 정상 종료에 묻힌다.
     */
    fn idle_expiry_requires_silence_since_the_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let wait = Duration::from_millis(100);
        let mut stream = DeadlineTcp::new(server, Instant::now() + wait)
            .stop_on(Arc::new(AtomicBool::new(false)));
        assert!(stream.read(&mut [0u8; 1]).is_err());
        assert!(
            stream.idle_expired(),
            "아무것도 받지 못한 대기를 쉬다가 끝난 것으로 보지 않았습니다"
        );

        client.write_all(&[1]).unwrap();
        stream.set_deadline(Instant::now() + wait);
        assert!(stream.read_exact(&mut [0u8; 2]).is_err());
        assert!(
            !stream.idle_expired(),
            "요청 일부를 받은 대기를 쉬다가 끝난 것으로 보았습니다"
        );

        stream.set_deadline(Instant::now() + wait);
        assert!(stream.read(&mut [0u8; 1]).is_err());
        assert!(
            stream.idle_expired(),
            "데드라인을 다시 잡았는데 앞 대기에서 받은 기록이 남았습니다"
        );
        drop(client);
    }

    #[test]
    /** @brief 이미 지난 데드라인으로는 접속하지 않는지. */
    fn connect_refuses_a_spent_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let error = DeadlineTcp::connect(listener.local_addr().unwrap(), Instant::now())
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
