/*!
 * @brief 외부 공유 캐시 클라이언트.
 *
 * @details 여러 대가 캐시를 나눠 쓸 때 쓴다. 프로토콜은 이 서버가 쓰는 세 명령만 구현한다.
 * @warning 이 캐시가 느리거나 죽어도 질의 처리가 멈추면 안 된다. 데드라인이 짧고, 실패하면
 *          잠시 아예 건너뛴다.
 */

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use onetdns_core::MutexExt;

/** @brief 응답 한 줄의 길이 상한. */
const MAX_RESP_LINE: usize = 4 * 1024;
/** @brief 값 하나의 크기 상한. */
const MAX_BULK_REPLY: usize = 16 * 1024 * 1024;
/** @brief 명령 하나의 데드라인. 짧게 잡아 질의 처리를 붙잡지 않는다. */
const COMMAND_TIMEOUT: Duration = Duration::from_secs(1);
/** @brief 실패 뒤 건너뛸 기간. 죽은 캐시에 매 질의마다 접속을 시도하면 그것이 더 느리다. */
const FAILURE_COOLDOWN: Duration = Duration::from_secs(5);

/** @brief 데드라인이 걸린 TCP. */
struct DeadlineTcp {
    /** @brief 이어진 연결. */
    stream: TcpStream,
    /** @brief 명령 하나의 데드라인. */
    deadline: Instant,
}

impl DeadlineTcp {
    /** @brief 남은 시간만큼만 기다려 접속한다. */
    fn connect(addr: SocketAddr, deadline: Instant) -> std::io::Result<Self> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(std::io::ErrorKind::TimedOut)?;
        let stream = TcpStream::connect_timeout(&addr, remaining)?;
        Ok(Self { stream, deadline })
    }

    /** @brief 데드라인을 다시 잡는다. */
    fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = deadline;
    }

    /** @brief 데드라인까지 남은 시간. */
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| std::io::ErrorKind::TimedOut.into())
    }
}

impl Read for DeadlineTcp {
    /** @brief 남은 시간을 걸고 읽는다. */
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buf)
    }
}

impl Write for DeadlineTcp {
    /** @brief 남은 시간을 걸고 쓴다. */
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buf)
    }

    /** @brief 비운다. */
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.flush()
    }
}

/** @brief 공유 캐시 클라이언트. */
pub struct RedisClient {
    /** @brief 붙을 주소. */
    addr: SocketAddr,
    /** @brief 연결과 실패 시각. */
    state: Mutex<RedisState>,
    /** @brief 서버가 오류로 답한 누적 횟수. 2의 거듭제곱 번째만 기록한다. */
    rejected: std::sync::atomic::AtomicU64,
}

/** @brief 연결과 실패 시각. */
struct RedisState {
    /** @brief 잡고 있는 연결. 없으면 아직 붙지 않았다. */
    conn: Option<DeadlineTcp>,
    /** @brief 이 시각까지는 아예 건너뛴다. */
    retry_after: Option<Instant>,
    /** @brief 직전 명령이 성공했는지. 상태가 바뀔 때만 기록해 명령마다 로그가 쌓이지 않게 한다. */
    healthy: bool,
}

impl RedisClient {
    /** @brief 주소로 만든다. 접속은 처음 쓸 때 한다. */
    pub fn new(addr: SocketAddr) -> Self {
        RedisClient {
            addr,
            state: Mutex::new(RedisState {
                conn: None,
                retry_after: None,
                healthy: true,
            }),
            rejected: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /** @brief 접속한다. */
    fn connect(&self, deadline: Instant) -> std::io::Result<DeadlineTcp> {
        DeadlineTcp::connect(self.addr, deadline)
    }

    /**
     * @brief 명령 하나를 보내고 답을 받는다.
     * @warning 실패하면 연결을 버리고 잠시 건너뛴다. 어긋난 연결을 재사용하면 다음
     *          명령의 답으로 앞 명령의 답을 읽는다.
     */
    fn command(&self, args: &[&[u8]]) -> std::io::Result<RespValue> {
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        let mut state = self.state.lock_recover();
        if state
            .retry_after
            .is_some_and(|retry_after| retry_after > Instant::now())
        {
            return Err(std::io::ErrorKind::WouldBlock.into());
        }
        state.retry_after = None;
        for attempt in 0..2 {
            if state.conn.is_none() {
                match self.connect(deadline) {
                    Ok(connection) => state.conn = Some(connection),
                    Err(error) => {
                        state.retry_after = Some(Instant::now() + FAILURE_COOLDOWN);
                        self.note_failure(&mut state, &error);
                        return Err(error);
                    }
                }
            }
            let stream = state.conn.as_mut().expect("The entry was just inserted");
            stream.set_deadline(deadline);
            match roundtrip(stream, args) {
                Ok(value) => {
                    state.retry_after = None;
                    if !state.healthy {
                        state.healthy = true;
                        onetdns_core::info!(event = "cachedb.recovered", addr = %self.addr, "Shared cache is answering again; resumed using it");
                    }
                    return Ok(value);
                }
                Err(_) if attempt == 0 => {
                    state.conn = None;
                    continue;
                }
                Err(error) => {
                    state.conn = None;
                    state.retry_after = Some(Instant::now() + FAILURE_COOLDOWN);
                    self.note_failure(&mut state, &error);
                    return Err(error);
                }
            }
        }
        Err(std::io::ErrorKind::Other.into())
    }

    /**
     * @brief 공유 캐시가 막 끊겼을 때만 기록한다.
     * @details 실패는 명령마다 반복되므로 상태가 바뀌는 순간만 남긴다. 이 기록이 없으면
     *          공유 캐시가 전부 죽어도 질의는 그대로 처리돼 운영자가 알아챌 길이 없다.
     */
    fn note_failure(&self, state: &mut RedisState, error: &std::io::Error) {
        if !state.healthy {
            return;
        }
        state.healthy = false;
        onetdns_core::warn!(event = "cachedb.unavailable", addr = %self.addr, error = %error, cooldown_secs = FAILURE_COOLDOWN.as_secs(), "Cannot reach the shared cache; skipping it for now. Queries are still answered but the cache is not shared");
    }

    /**
     * @brief 서버가 오류로 답했으면 기록한다.
     * @details 접속과 왕복은 성공했으므로 회로가 열리지 않는다. 인증 거부나 메모리 부족처럼
     *          공유 캐시가 계속 아무 일도 하지 않는 상태가 여기서만 드러난다.
     */
    fn note_reply(&self, command: &str, value: &RespValue) {
        let RespValue::Error(message) = value else {
            return;
        };
        let count = self
            .rejected
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if count.is_power_of_two() {
            onetdns_core::warn!(event = "cachedb.command_rejected", addr = %self.addr, command = command, count = count, reply = %message, "Shared cache server rejected a command; the cache is not being shared");
        }
    }

    /** @brief 값을 읽는다. 실패하면 없는 것으로 본다. */
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let value = self.command(&[b"GET", key]).ok()?;
        self.note_reply("GET", &value);
        match value {
            RespValue::Bulk(b) => Some(b),
            _ => None,
        }
    }

    /** @brief 만료 시간과 함께 값을 넣는다. 실패는 무시한다. */
    pub fn setex(&self, key: &[u8], secs: u64, val: &[u8]) {
        let secs_s = secs.max(1).to_string();
        if let Ok(value) = self.command(&[b"SETEX", key, secs_s.as_bytes(), val]) {
            self.note_reply("SETEX", &value);
        }
    }

    /** @brief 값을 지운다. 실패는 무시한다. */
    pub fn del(&self, key: &[u8]) {
        if let Ok(value) = self.command(&[b"DEL", key]) {
            self.note_reply("DEL", &value);
        }
    }
}

/** @brief 응답 값 하나. */
enum RespValue {
    /** @brief 짧은 문자열 응답. */
    Simple(#[allow(dead_code)] String),
    /** @brief 길이가 붙은 값. */
    Bulk(Vec<u8>),
    /** @brief 값이 없다. */
    Nil,
    /** @brief 수. */
    Int(#[allow(dead_code)] i64),
    /** @brief 오류. */
    Error(String),
}

/** @brief 명령을 보내고 답을 읽는다. */
fn roundtrip(stream: &mut DeadlineTcp, args: &[&[u8]]) -> std::io::Result<RespValue> {
    let mut req = Vec::new();
    req.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
    for a in args {
        req.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        req.extend_from_slice(a);
        req.extend_from_slice(b"\r\n");
    }
    stream.write_all(&req)?;
    stream.flush()?;
    read_reply(stream)
}

/** @brief 한 줄을 읽는다. 길이 상한이 걸린다. */
fn read_line(stream: &mut DeadlineTcp) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    loop {
        if stream.read(&mut b)? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        if b[0] == b'\r' {
            stream.read_exact(&mut b)?;
            if b[0] != b'\n' {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            break;
        }
        out.push(b[0]);
        if out.len() > MAX_RESP_LINE {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
    }
    Ok(out)
}

/**
 * @brief 응답 하나를 읽는다.
 * @warning 배열 응답을 끝까지 소비해야 한다. 중간에 멈추면 남은 바이트가 다음 명령의
 *          답으로 읽혀 연결이 어긋난다.
 */
fn read_reply(stream: &mut DeadlineTcp) -> std::io::Result<RespValue> {
    let line = read_line(stream)?;
    if line.is_empty() {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let rest = &line[1..];
    match line[0] {
        b'+' => Ok(RespValue::Simple(
            String::from_utf8_lossy(rest).into_owned(),
        )),
        b'-' => Ok(RespValue::Error(String::from_utf8_lossy(rest).into_owned())),
        b':' => Ok(RespValue::Int(parse_i64(rest)?)),
        b'$' => {
            let len = parse_i64(rest)?;
            if len == -1 {
                return Ok(RespValue::Nil);
            }
            if len < 0 {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            let len = usize::try_from(len).map_err(|_| std::io::ErrorKind::InvalidData)?;
            if len > MAX_BULK_REPLY {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf)?;
            let mut crlf = [0u8; 2];
            stream.read_exact(&mut crlf)?;
            if crlf != *b"\r\n" {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            Ok(RespValue::Bulk(buf))
        }
        b'*' => {
            let count = parse_i64(rest)?;
            if count == -1 {
                Ok(RespValue::Nil)
            } else {
                Err(std::io::ErrorKind::InvalidData.into())
            }
        }
        _ => Err(std::io::ErrorKind::InvalidData.into()),
    }
}

/** @brief 수를 읽는다. 형식이 어긋나면 오류다. */
fn parse_i64(b: &[u8]) -> std::io::Result<i64> {
    std::str::from_utf8(b)
        .map_err(|_| std::io::ErrorKind::InvalidData)?
        .parse()
        .map_err(|_| std::io::ErrorKind::InvalidData.into())
}

#[cfg(test)]
/** @brief 데드라인 처리, 실패 후 건너뛰기, 그리고 연결이 어긋나지 않는지. */
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    /** @brief 한 바이트씩 흘려 보내는 상대가 데드라인을 늘리지 못하는지. */
    fn deadline_tcp_rejects_slow_drip_reply() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for byte in 0..10 {
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(30));
            }
        });

        let started = Instant::now();
        let mut stream = DeadlineTcp::connect(addr, started + Duration::from_millis(120)).unwrap();
        let mut reply = [0u8; 10];
        let error = stream.read_exact(&mut reply).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ));
        assert!(started.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
    }

    #[test]
    /** @brief 실패 뒤 잠시 아예 건너뛰는지. */
    fn connection_failure_opens_fast_fail_circuit() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let client = RedisClient::new(addr);

        assert!(client.get(b"missing").is_none());
        assert!(client.state.lock_recover().retry_after.is_some());

        let started = Instant::now();
        assert!(client.get(b"missing-again").is_none());
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    /** @brief 수 형식을 엄격히 보고, 배열 응답이 연결을 어긋나게 하지 않는지. */
    fn resp_numeric_fields_are_strict_and_arrays_cannot_desync_connection() {
        assert!(parse_i64(b"12").is_ok());
        assert!(parse_i64(b"").is_err());
        assert!(parse_i64(b"12x").is_err());

        /** @brief 테스트용 응답 바이트를 읽는다. */
        fn read_test_reply(reply: &'static [u8]) -> std::io::Result<RespValue> {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream.write_all(reply).unwrap();
            });
            let mut stream =
                DeadlineTcp::connect(addr, Instant::now() + Duration::from_secs(1)).unwrap();
            let result = read_reply(&mut stream);
            server.join().unwrap();
            result
        }

        assert!(read_test_reply(b"$wat\r\n").is_err());
        assert!(read_test_reply(b"$-2\r\n").is_err());
        assert!(read_test_reply(b"*1\r\n$3\r\nfoo\r\n").is_err());
        assert!(matches!(read_test_reply(b"$-1\r\n"), Ok(RespValue::Nil)));
    }
}
