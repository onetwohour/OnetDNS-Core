//! Descriptors passed as ancillary data beside the bytes of a frame, over a Unix stream socket.

use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use super::SocketType;
use crate::handoff::LinkError;

pub(crate) type Stream = UnixStream;
pub(crate) type Passed = OwnedFd;

/// Descriptors ride as ancillary data, so nothing about them follows the payload.
pub(super) const ATTACHED: usize = 0;
/// Linux refuses more than SCM_MAX_FD (253) descriptors in one message.
const FDS_PER_SEND: usize = 250;
/// macOS has no MSG_NOSIGNAL. The Rust runtime ignores SIGPIPE, so a closed peer is an EPIPE error
/// there too.
#[cfg(target_os = "linux")]
const SEND_FLAGS: libc::c_int = libc::MSG_NOSIGNAL;
#[cfg(not(target_os = "linux"))]
const SEND_FLAGS: libc::c_int = 0;

/// macOS refuses every socket option with EINVAL once the peer has closed. A read then returns
/// what is still buffered and does not block, so it needs no timeout.
pub(super) fn set_read_timeout(stream: &Stream, timeout: Duration) -> io::Result<()> {
    match stream.set_read_timeout(Some(timeout)) {
        Err(error) if cfg!(target_os = "macos") && error.raw_os_error() == Some(libc::EINVAL) => {
            Ok(())
        }
        result => result,
    }
}

pub(super) fn write_frame(stream: &Stream, bytes: &[u8], passed: &[Passed]) -> io::Result<()> {
    // Each batch of descriptors rides on one byte and the last on the rest, so all of them arrive
    // before the frame ends.
    let batches: Vec<&[OwnedFd]> = passed.chunks(FDS_PER_SEND).collect();
    if batches.len() > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Too many descriptors for the handoff message",
        ));
    }
    let mut at = 0;
    for (index, batch) in batches.iter().enumerate() {
        let end = if index + 1 == batches.len() {
            bytes.len()
        } else {
            at + 1
        };
        at += send_with_fds(stream, &bytes[at..end], batch)?;
    }
    (&*stream).write_all(&bytes[at..])
}

fn send_with_fds(stream: &UnixStream, bytes: &[u8], fds: &[OwnedFd]) -> io::Result<usize> {
    let raw: Vec<libc::c_int> = fds.iter().map(AsRawFd::as_raw_fd).collect();
    let data_len = u32::try_from(std::mem::size_of_val(raw.as_slice()))
        .expect("A batch of descriptors fits in u32");
    // SAFETY: CMSG_SPACE only computes a length.
    let space = unsafe { libc::CMSG_SPACE(data_len) } as usize;
    let mut control = vec![0u8; space];
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: All-zero bits are a valid initial msghdr.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = space as _;
    // SAFETY: `control` was sized with CMSG_SPACE for these descriptors, so the header and its
    // data fit.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&raw const message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(data_len) as _;
        std::ptr::copy_nonoverlapping(
            raw.as_ptr().cast::<u8>(),
            libc::CMSG_DATA(header),
            data_len as usize,
        );
    }
    loop {
        // SAFETY: The buffer and control data `message` points to live for the whole call.
        let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &raw const message, SEND_FLAGS) };
        match usize::try_from(sent) {
            Ok(sent) => return Ok(sent),
            Err(_) => {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }
}

/// Takes ownership of every descriptor that arrives, closed on exec.
pub(super) fn read_some(
    stream: &Stream,
    buf: &mut [u8],
    fds: &mut Vec<Passed>,
) -> io::Result<usize> {
    const SCM_MAX_FD: u32 = 253;
    let data_len = SCM_MAX_FD * std::mem::size_of::<libc::c_int>() as u32;
    // SAFETY: CMSG_SPACE only computes a length.
    let space = unsafe { libc::CMSG_SPACE(data_len) } as usize;
    let mut control = vec![0u8; space];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // SAFETY: All-zero bits are a valid initial msghdr.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = space as _;
    #[cfg(target_os = "linux")]
    let flags = libc::MSG_CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = 0;
    // SAFETY: The buffer and control data `message` points to live for the whole call.
    let received = unsafe { libc::recvmsg(stream.as_raw_fd(), &raw mut message, flags) };
    let received = usize::try_from(received).map_err(|_| io::Error::last_os_error())?;
    // SAFETY: Kernel-filled control data is walked only with the CMSG macros, within
    // msg_controllen; each SCM_RIGHTS descriptor is new to this process and owned from here on.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&raw const message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(header);
                let bytes = (*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                for index in 0..bytes / std::mem::size_of::<libc::c_int>() {
                    let fd = std::ptr::read_unaligned(data.cast::<libc::c_int>().add(index));
                    // Without MSG_CMSG_CLOEXEC, a process another thread starts before this line
                    // inherits the descriptor.
                    #[cfg(not(target_os = "linux"))]
                    libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                    fds.push(OwnedFd::from_raw_fd(fd));
                }
            }
            header = libc::CMSG_NXTHDR(&raw const message, header);
        }
    }
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Descriptors were cut off",
        ));
    }
    Ok(received)
}

/// Nothing follows the payload here.
pub(super) fn attach(bytes: &[u8]) -> Result<Vec<Passed>, LinkError> {
    if bytes.is_empty() {
        Ok(Vec::new())
    } else {
        Err(LinkError::Unreadable)
    }
}

pub(super) fn socket_type(fd: &Passed) -> Result<SocketType, LinkError> {
    let mut kind: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `kind` and `len` are valid for the size passed.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&raw mut kind).cast(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(LinkError::Unreadable);
    }
    Ok(match kind {
        libc::SOCK_DGRAM => SocketType::Datagram,
        libc::SOCK_STREAM => SocketType::Stream,
        _ => SocketType::Other,
    })
}

/// Both ends of a new stream.
pub(crate) fn pair() -> io::Result<(Stream, Stream)> {
    UnixStream::pair()
}

#[cfg(test)]
pub(crate) fn stream_pair() -> (Stream, Stream) {
    pair().expect("a socket pair")
}
