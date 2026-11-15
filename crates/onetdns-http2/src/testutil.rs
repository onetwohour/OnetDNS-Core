//! Socket helpers with deadlines. These tests exchange real bytes over loopback. Without a
//! deadline, one stalled peer hangs the test forever, with no failure to say which test or why, and
//! the test binary keeps its file locked so the next build fails. Connecting and accepting go
//! through here so new tests cannot skip the deadline.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

/// Past it, a stalled peer fails the test instead of hanging it.
pub(crate) const TEST_DEADLINE: Duration = Duration::from_secs(5);

/// Sets both read and write deadlines.
fn arm(sock: TcpStream) -> TcpStream {
    sock.set_read_timeout(Some(TEST_DEADLINE)).unwrap();
    sock.set_write_timeout(Some(TEST_DEADLINE)).unwrap();
    sock
}

/// Tests that need a shorter deadline set it again on the returned socket.
pub(crate) fn deadline_connect(addr: SocketAddr) -> TcpStream {
    arm(TcpStream::connect(addr).unwrap())
}

pub(crate) fn deadline_accept(listener: &TcpListener) -> TcpStream {
    let (sock, _) = listener.accept().unwrap();
    arm(sock)
}
