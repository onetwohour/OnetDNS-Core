//! TCP connections that read and write only within an absolute deadline. A fixed socket timeout
//! lets a peer sending one byte at a time get a fresh timeout on every read and hold the connection
//! forever, so each read and write sets the time left until the deadline. A connection watching
//! stop flags checks them every STOP_POLL while waiting, so stopping the server does not wait for
//! the deadline.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A stopped connection closes within this. Shorter means more wakeups per waiting connection.
pub const STOP_POLL: Duration = Duration::from_millis(250);

pub trait SocketTimeouts {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl SocketTimeouts for TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, timeout)
    }
}

/// TimedOut once the deadline has passed.
pub fn time_left(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| io::ErrorKind::TimedOut.into())
}

/// The deadline covers all work on the connection until set_deadline moves it, not one read. Past
/// it, reads and writes fail with TimedOut; once a stop flag is set, with ConnectionAborted. With
/// no stop flag, the whole remaining time goes into one wait.
pub struct DeadlineTcp<S = TcpStream> {
    stream: S,
    deadline: Instant,
    /// Any set flag ends pending reads and writes.
    stop: Vec<Arc<AtomicBool>>,
    /// Whether anything was read since the deadline was last set.
    received: bool,
}

impl DeadlineTcp {
    pub fn connect(addr: SocketAddr, deadline: Instant) -> io::Result<Self> {
        let stream = TcpStream::connect_timeout(&addr, time_left(deadline)?)?;
        Ok(Self::new(stream, deadline))
    }
}

impl<S> DeadlineTcp<S> {
    pub fn new(stream: S, deadline: Instant) -> Self {
        Self {
            stream,
            deadline,
            stop: Vec::new(),
            received: false,
        }
    }

    /// Adds another stop flag; a connection can watch several, such as the server's and its
    /// listener's.
    pub fn stop_on(mut self, flag: Arc<AtomicBool>) -> Self {
        self.stop.push(flag);
        self
    }

    /// For waiting on the next request after finishing one.
    pub fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = deadline;
        self.received = false;
    }

    /// Whether the deadline passed with nothing read since it was set. With the deadline set to
    /// wait for the next request, that is a connection that went idle; a peer that stalls
    /// mid-request sent something, so it does not count.
    pub fn idle_expired(&self) -> bool {
        !self.received && Instant::now() >= self.deadline
    }

    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Drops the deadline and stop flags.
    pub fn into_inner(self) -> S {
        self.stream
    }

    fn stopped(&self) -> bool {
        self.stop.iter().any(|flag| flag.load(Ordering::Relaxed))
    }
}

impl<S: SocketTimeouts> DeadlineTcp<S> {
    /// Timeout for this wait; an error if stopped or past the deadline.
    fn wait(&self) -> io::Result<Duration> {
        if self.stopped() {
            // read_exact and write_all retry Interrupted forever, so stopping reports an error that
            // ends them.
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        let left = time_left(self.deadline)?;
        Ok(if self.stop.is_empty() {
            left
        } else {
            left.min(STOP_POLL)
        })
    }

    /// Restarts a timed-out wait only when it was cut short of the deadline to check the stop
    /// flags. If a flag was set meanwhile, the next wait ends with ConnectionAborted.
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

    /// No timeout: TCP flush does not wait, and writes enforce the deadline.
    fn flush(&mut self) -> io::Result<()> {
        if self.stopped() {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// Accepts, then sends ten bytes, one every 30 ms.
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
    /// The shortened waits must not run past the deadline.
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
    /// The stop error must not be one that read_exact and write_all retry.
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
    /// Treating a peer that sent part of a request as idle would hide a stalled request among
    /// normal closes.
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
    fn connect_refuses_a_spent_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let error = DeadlineTcp::connect(listener.local_addr().unwrap(), Instant::now())
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
