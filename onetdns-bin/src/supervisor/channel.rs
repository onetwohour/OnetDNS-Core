//! The channel between the supervisor and a worker process it started: one Unix stream socket per
//! worker. The worker finds its end through `CHANNEL_ENV`, speaks first with its protocol and
//! version, and runs once the supervisor answers.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::error::BoxResult;
use crate::handoff::wire::{self, Frame, Reader, Writer, PROTOCOL};
use crate::handoff::LinkError;
use crate::update::VERSION;

/// Names the descriptor of the worker's end.
pub(super) const CHANNEL_ENV: &str = "ONETDNS_SUPERVISOR_CHANNEL";

/// Worker to supervisor. Its layout stays the same in every protocol, so a supervisor can turn
/// away a worker that speaks another one.
pub(super) const HELLO: u8 = 0x10;
pub(super) const READY: u8 = 0x11;
/// Supervisor to worker.
pub(super) const RUN: u8 = 0x20;

/// The supervisor answers within one poll, so this only bounds a supervisor that stopped working.
const ANSWER_WAIT: Duration = Duration::from_secs(30);

pub(super) struct Hello {
    pub(super) protocol: u32,
    pub(super) version: String,
}

impl Hello {
    fn own() -> Frame {
        let mut frame = Frame::new(HELLO);
        let mut out = Writer(&mut frame.payload);
        out.u32(PROTOCOL);
        out.bytes(VERSION.as_bytes());
        frame
    }

    pub(super) fn read(frame: &Frame) -> Result<Self, LinkError> {
        if frame.kind != HELLO || !frame.fds.is_empty() {
            return Err(LinkError::Unreadable);
        }
        let mut input = Reader(&frame.payload);
        let protocol = input.u32()?;
        let version =
            String::from_utf8(input.bytes()?.to_vec()).map_err(|_| LinkError::Unreadable)?;
        input.finish()?;
        Ok(Self { protocol, version })
    }
}

/// True for a frame of `kind` with nothing in it.
pub(super) fn is_bare(frame: &Frame, kind: u8) -> bool {
    frame.kind == kind && frame.payload.is_empty() && frame.fds.is_empty()
}

/// This worker's end, kept for the life of the process.
static CHANNEL: OnceLock<UnixStream> = OnceLock::new();

/// Introduces this process to the supervisor that started it and waits for its answer. False when
/// no supervisor started it.
pub(super) fn join() -> BoxResult<bool> {
    let Ok(named) = std::env::var(CHANNEL_ENV) else {
        return Ok(false);
    };
    std::env::remove_var(CHANNEL_ENV);
    let stream = adopt(&named)?;
    wire::send(&stream, &Hello::own()).map_err(|error| {
        crate::anyhow!(format!(
            "Could not introduce this process to the supervisor: {error}"
        ))
    })?;
    let answer = wire::recv(&stream, Instant::now() + ANSWER_WAIT, &|| false)
        .map_err(|error| crate::anyhow!(format!("The supervisor did not answer: {error}")))?;
    if !is_bare(&answer, RUN) {
        return Err(crate::anyhow!(
            "The supervisor answered with a message this version does not know"
        ));
    }
    let _ = CHANNEL.set(stream);
    Ok(true)
}

/// Tells the supervisor this process is ready.
pub(super) fn ready() -> std::io::Result<()> {
    let channel = CHANNEL.get().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotConnected, "No supervisor channel")
    })?;
    wire::send(channel, &Frame::new(READY))
}

/// The descriptor came through the environment, so it is checked to be an open Unix stream socket
/// before this process owns it, and closed on exec so the processes it starts do not inherit it.
fn adopt(named: &str) -> BoxResult<UnixStream> {
    let invalid = || {
        crate::anyhow!(format!(
            "{CHANNEL_ENV} does not name a supervisor channel: {named}"
        ))
    };
    let fd: libc::c_int = named.parse().map_err(|_| invalid())?;
    if fd < 3 {
        return Err(invalid());
    }
    // SAFETY: F_GETFD only reads the descriptor flags; it fails on a descriptor that is not open.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(invalid());
    }
    let option = |name| {
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `value` and `len` are valid for the size passed.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                name,
                (&raw mut value).cast(),
                &raw mut len,
            )
        };
        (rc == 0).then_some(value)
    };
    if option(libc::SO_DOMAIN) != Some(libc::AF_UNIX)
        || option(libc::SO_TYPE) != Some(libc::SOCK_STREAM)
    {
        return Err(invalid());
    }
    // SAFETY: Same descriptor, checked open above.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(invalid());
    }
    // SAFETY: The supervisor passed this descriptor to this process alone, and the variable naming
    // it is gone, so nothing else owns it.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    debug_assert_eq!(owned.as_raw_fd(), fd);
    Ok(UnixStream::from(owned))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// A change to these bytes is a change to the handoff protocol, which every supervisor reads
    /// first.
    fn the_hello_reads_and_writes_fixed_bytes() {
        let own = Hello::own();
        let mut expected = PROTOCOL.to_be_bytes().to_vec();
        expected.extend_from_slice(&(VERSION.len() as u32).to_be_bytes());
        expected.extend_from_slice(VERSION.as_bytes());
        assert_eq!((own.kind, own.payload.to_vec()), (0x10, expected));

        let mut fixed = Frame::new(HELLO);
        fixed
            .payload
            .extend_from_slice(&[0, 0, 0, 7, 0, 0, 0, 5, b'1', b'.', b'2', b'.', b'3']);
        let hello = Hello::read(&fixed).unwrap();
        assert_eq!((hello.protocol, hello.version.as_str()), (7, "1.2.3"));
        fixed.payload.push(0);
        assert!(Hello::read(&fixed).is_err());
    }

    #[test]
    fn only_an_open_unix_stream_socket_is_adopted() {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        for named in ["", "x", "1", &udp.as_raw_fd().to_string(), "1000000"] {
            assert!(adopt(named).is_err(), "{named}");
        }
        let (ours, theirs) = UnixStream::pair().unwrap();
        let fd = OwnedFd::from(theirs);
        // SAFETY: Clears the flag on a descriptor this test owns.
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, 0) };
        let named = fd.as_raw_fd().to_string();
        std::mem::forget(fd);
        let adopted = adopt(&named).unwrap();
        // SAFETY: Reads the flags of a descriptor `adopted` owns.
        let flags = unsafe { libc::fcntl(adopted.as_raw_fd(), libc::F_GETFD) };
        assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
        drop(ours);
    }
}
