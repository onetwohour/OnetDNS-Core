use std::io;
use std::time::Duration;

/// Returns true when the socket became readable in time. An error state counts as readable; the
/// call that follows reports it.
///
/// Unlike a receive timeout or a non-blocking socket, waiting this way leaves the socket's options
/// alone. A listening socket handed to another process shares those options with it.
#[cfg(unix)]
pub fn readable(socket: &impl std::os::fd::AsRawFd, timeout: Duration) -> io::Result<bool> {
    let millis = poll_millis(timeout);
    let mut entry = libc::pollfd {
        fd: socket.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: one entry holding a live descriptor, borrowed for the whole call.
        let ready = unsafe { libc::poll(&mut entry, 1, millis) };
        if ready >= 0 {
            return Ok(ready > 0);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(windows)]
pub fn readable(
    socket: &impl std::os::windows::io::AsRawSocket,
    timeout: Duration,
) -> io::Result<bool> {
    const POLLRDNORM: i16 = 0x0100;

    #[repr(C)]
    struct PollFd {
        fd: usize,
        events: i16,
        revents: i16,
    }

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn WSAPoll(fds: *mut PollFd, count: u32, timeout_ms: i32) -> i32;
    }

    let mut entry = PollFd {
        fd: socket.as_raw_socket() as usize,
        events: POLLRDNORM,
        revents: 0,
    };
    // SAFETY: one entry holding a live socket, borrowed for the whole call.
    let ready = unsafe { WSAPoll(&mut entry, 1, poll_millis(timeout)) };
    if ready < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ready > 0)
}

/// Rounds up, so a short timeout does not become a zero-length poll that never waits.
fn poll_millis(timeout: Duration) -> i32 {
    i32::try_from(timeout.as_nanos().div_ceil(1_000_000)).unwrap_or(i32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::time::Instant;

    #[test]
    fn waits_for_a_datagram_and_times_out_without_one() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let started = Instant::now();
        assert!(!readable(&socket, Duration::from_millis(30)).unwrap());
        assert!(started.elapsed() >= Duration::from_millis(25));

        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"x", socket.local_addr().unwrap()).unwrap();
        assert!(readable(&socket, Duration::from_secs(5)).unwrap());
    }
}
