//! Frames over a named pipe pair. Sockets are duplicated into the peer process, and their
//! WSAPROTOCOL_INFOW records follow the payload.

use std::ffi::c_void;
use std::io;
use std::os::windows::io::{
    AsRawHandle, AsRawSocket, FromRawHandle, FromRawSocket, OwnedHandle, OwnedSocket,
};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use super::SocketType;
use crate::handoff::LinkError;

pub(crate) type Stream = Pipe;
pub(crate) type Passed = OwnedSocket;

/// WSAPROTOCOL_INFOW, which WSASocketW opens a duplicated socket from.
#[repr(C)]
struct ProtocolInfo([u32; 157]);

pub(super) const ATTACHED: usize = std::mem::size_of::<ProtocolInfo>();
const _: () = assert!(ATTACHED == 628);

const PIPE_BUFFER: u32 = 64 * 1024;
const NO_TIMEOUT: u64 = u64::MAX;

#[allow(non_snake_case, clippy::upper_case_acronyms)]
mod win32 {
    use super::{c_void, ProtocolInfo};

    pub const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;
    pub const PIPE_ACCESS_DUPLEX: u32 = 0x3;
    pub const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    pub const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
    pub const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x8;
    pub const GENERIC_READ: u32 = 0x8000_0000;
    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    pub const OPEN_EXISTING: u32 = 3;
    pub const ERROR_BROKEN_PIPE: i32 = 109;
    pub const ERROR_IO_PENDING: i32 = 997;
    pub const WAIT_TIMEOUT: i32 = 258;
    pub const INFINITE: u32 = u32::MAX;

    pub const INVALID_SOCKET: usize = !0;
    pub const FROM_PROTOCOL_INFO: i32 = -1;
    pub const WSA_FLAG_OVERLAPPED: u32 = 0x01;
    pub const WSA_FLAG_NO_HANDLE_INHERIT: u32 = 0x80;
    pub const SOL_SOCKET: i32 = 0xffff;
    pub const SO_TYPE: i32 = 0x1008;
    pub const SOCK_STREAM: i32 = 1;
    pub const SOCK_DGRAM: i32 = 2;

    #[repr(C)]
    pub struct OVERLAPPED {
        pub Internal: usize,
        pub InternalHigh: usize,
        pub Offset: u32,
        pub OffsetHigh: u32,
        pub hEvent: *mut c_void,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn CreateNamedPipeW(
            name: *const u16,
            open_mode: u32,
            pipe_mode: u32,
            max_instances: u32,
            out_buffer: u32,
            in_buffer: u32,
            default_timeout: u32,
            security: *mut c_void,
        ) -> *mut c_void;
        pub fn CreateFileW(
            name: *const u16,
            access: u32,
            share_mode: u32,
            security: *mut c_void,
            disposition: u32,
            flags: u32,
            template: *mut c_void,
        ) -> *mut c_void;
        pub fn CreateEventW(
            security: *mut c_void,
            manual_reset: i32,
            initial_state: i32,
            name: *const u16,
        ) -> *mut c_void;
        pub fn ReadFile(
            file: *mut c_void,
            buffer: *mut u8,
            to_read: u32,
            read: *mut u32,
            overlapped: *mut OVERLAPPED,
        ) -> i32;
        pub fn WriteFile(
            file: *mut c_void,
            buffer: *const u8,
            to_write: u32,
            written: *mut u32,
            overlapped: *mut OVERLAPPED,
        ) -> i32;
        pub fn GetOverlappedResult(
            file: *mut c_void,
            overlapped: *mut OVERLAPPED,
            transferred: *mut u32,
            wait: i32,
        ) -> i32;
        pub fn GetOverlappedResultEx(
            file: *mut c_void,
            overlapped: *mut OVERLAPPED,
            transferred: *mut u32,
            milliseconds: u32,
            alertable: i32,
        ) -> i32;
        pub fn CancelIoEx(file: *mut c_void, overlapped: *mut OVERLAPPED) -> i32;
    }

    #[link(name = "Ws2_32")]
    unsafe extern "system" {
        pub fn WSADuplicateSocketW(socket: usize, process: u32, info: *mut ProtocolInfo) -> i32;
        pub fn WSASocketW(
            family: i32,
            kind: i32,
            protocol: i32,
            info: *mut c_void,
            group: u32,
            flags: u32,
        ) -> usize;
        pub fn getsockopt(
            socket: std::os::windows::io::RawSocket,
            level: i32,
            name: i32,
            value: *mut i8,
            length: *mut i32,
        ) -> i32;
        pub fn WSAGetLastError() -> i32;
    }
}

/// One end of a duplex byte pipe, opened for overlapped I/O so reads and writes can time out.
pub(crate) struct Pipe {
    handle: OwnedHandle,
    /// The process that sockets sent on this end are duplicated into.
    peer: AtomicU32,
    /// Milliseconds, or NO_TIMEOUT.
    read_timeout: AtomicU64,
    write_timeout: AtomicU64,
}

impl Pipe {
    pub(crate) fn from_handle(handle: OwnedHandle) -> Self {
        Self {
            handle,
            peer: AtomicU32::new(0),
            read_timeout: AtomicU64::new(NO_TIMEOUT),
            write_timeout: AtomicU64::new(NO_TIMEOUT),
        }
    }

    pub(crate) fn set_peer(&self, process_id: u32) {
        self.peer.store(process_id, Ordering::Relaxed);
    }

    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.read_timeout.store(millis(timeout), Ordering::Relaxed);
        Ok(())
    }

    pub(crate) fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.write_timeout.store(millis(timeout), Ordering::Relaxed);
        Ok(())
    }

    /// Zero once the other end is closed.
    pub(crate) fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let length = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let timeout = self.read_timeout.load(Ordering::Relaxed);
        // SAFETY: `buf` outlives the operation: overlapped_io returns only once it has ended.
        let read = self.overlapped_io(timeout, |overlapped| unsafe {
            win32::ReadFile(
                self.raw(),
                buf.as_mut_ptr(),
                length,
                std::ptr::null_mut(),
                overlapped,
            )
        });
        match read {
            Err(error) if error.raw_os_error() == Some(win32::ERROR_BROKEN_PIPE) => Ok(0),
            other => other,
        }
    }

    pub(crate) fn write_all(&self, mut buf: &[u8]) -> io::Result<()> {
        let timeout = self.write_timeout.load(Ordering::Relaxed);
        while !buf.is_empty() {
            let length = u32::try_from(buf.len()).unwrap_or(u32::MAX);
            // SAFETY: `buf` outlives the operation: overlapped_io returns only once it has ended.
            let written = self.overlapped_io(timeout, |overlapped| unsafe {
                win32::WriteFile(
                    self.raw(),
                    buf.as_ptr(),
                    length,
                    std::ptr::null_mut(),
                    overlapped,
                )
            })?;
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            buf = &buf[written..];
        }
        Ok(())
    }

    fn raw(&self) -> *mut c_void {
        self.handle.as_raw_handle().cast()
    }

    /// Starts an operation with `start` and waits for it to end, cancelling it once `timeout`
    /// milliseconds pass.
    fn overlapped_io(
        &self,
        timeout: u64,
        start: impl FnOnce(*mut win32::OVERLAPPED) -> i32,
    ) -> io::Result<usize> {
        // SAFETY: Creates an unnamed manual-reset event; the result is checked before use.
        let event = unsafe { win32::CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: A new handle that nothing else owns.
        let event = unsafe { OwnedHandle::from_raw_handle(event.cast()) };
        let mut overlapped = win32::OVERLAPPED {
            Internal: 0,
            InternalHigh: 0,
            Offset: 0,
            OffsetHigh: 0,
            hEvent: event.as_raw_handle().cast(),
        };
        if start(&raw mut overlapped) == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(win32::ERROR_IO_PENDING) {
                return Err(error);
            }
        }
        let wait = u32::try_from(timeout).unwrap_or(win32::INFINITE);
        let mut transferred = 0u32;
        // SAFETY: `overlapped` describes the operation started above on this handle.
        if unsafe {
            win32::GetOverlappedResultEx(
                self.raw(),
                &raw mut overlapped,
                &raw mut transferred,
                wait,
                0,
            )
        } != 0
        {
            return Ok(transferred as usize);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(win32::WAIT_TIMEOUT) {
            return Err(error);
        }
        // The operation still uses `overlapped` and the caller's buffer, so it must end before
        // they go away. It may also have finished just now.
        // SAFETY: As above; the second call waits for the cancelled operation to end.
        unsafe {
            win32::CancelIoEx(self.raw(), &raw mut overlapped);
            if win32::GetOverlappedResult(self.raw(), &raw mut overlapped, &raw mut transferred, 1)
                != 0
            {
                return Ok(transferred as usize);
            }
        }
        Err(io::ErrorKind::TimedOut.into())
    }
}

fn millis(timeout: Option<Duration>) -> u64 {
    timeout.map_or(NO_TIMEOUT, |timeout| {
        u64::try_from(timeout.as_millis()).unwrap_or(NO_TIMEOUT - 1)
    })
}

/// Both ends of a new pipe, neither inheritable. The pipe allows one client, and the second end
/// is that client, so no other process can have connected to it.
pub(crate) fn pipe_pair() -> io::Result<(Pipe, Pipe)> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let name: Vec<u16> = format!(
        r"\\.\pipe\onetdns-handoff-{}-{nanos}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
    .encode_utf16()
    .chain(Some(0))
    .collect();
    // SAFETY: `name` is NUL-terminated; the result is checked before use.
    let server = unsafe {
        win32::CreateNamedPipeW(
            name.as_ptr(),
            win32::PIPE_ACCESS_DUPLEX
                | win32::FILE_FLAG_OVERLAPPED
                | win32::FILE_FLAG_FIRST_PIPE_INSTANCE,
            win32::PIPE_REJECT_REMOTE_CLIENTS,
            1,
            PIPE_BUFFER,
            PIPE_BUFFER,
            0,
            std::ptr::null_mut(),
        )
    };
    if server == win32::INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: A new handle that nothing else owns.
    let server = unsafe { OwnedHandle::from_raw_handle(server.cast()) };
    // SAFETY: As above.
    let client = unsafe {
        win32::CreateFileW(
            name.as_ptr(),
            win32::GENERIC_READ | win32::GENERIC_WRITE,
            0,
            std::ptr::null_mut(),
            win32::OPEN_EXISTING,
            win32::FILE_FLAG_OVERLAPPED,
            std::ptr::null_mut(),
        )
    };
    if client == win32::INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: A new handle that nothing else owns.
    let client = unsafe { OwnedHandle::from_raw_handle(client.cast()) };
    Ok((Pipe::from_handle(server), Pipe::from_handle(client)))
}

pub(super) fn write_frame(stream: &Stream, bytes: &[u8], passed: &[Passed]) -> io::Result<()> {
    if passed.is_empty() {
        return stream.write_all(bytes);
    }
    let peer = stream.peer.load(Ordering::Relaxed);
    if peer == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "The process to pass the sockets to is not known",
        ));
    }
    let mut whole = bytes.to_vec();
    for socket in passed {
        let mut info = ProtocolInfo([0; 157]);
        // SAFETY: `info` is a WSAPROTOCOL_INFOW-sized buffer for the call to fill.
        if unsafe {
            win32::WSADuplicateSocketW(socket.as_raw_socket() as usize, peer, &raw mut info)
        } != 0
        {
            // SAFETY: Reads this thread's last Winsock error.
            return Err(io::Error::from_raw_os_error(unsafe {
                win32::WSAGetLastError()
            }));
        }
        whole.extend(info.0.iter().flat_map(|word| word.to_ne_bytes()));
    }
    stream.write_all(&whole)
}

pub(super) fn read_some(
    stream: &Stream,
    buf: &mut [u8],
    _passed: &mut [Passed],
) -> io::Result<usize> {
    stream.read(buf)
}

/// Opens the sockets the peer duplicated into this process.
pub(super) fn attach(bytes: &[u8]) -> Result<Vec<Passed>, LinkError> {
    if bytes.len() % ATTACHED != 0 {
        return Err(LinkError::Unreadable);
    }
    if !bytes.is_empty() {
        winsock_started()?;
    }
    bytes
        .chunks_exact(ATTACHED)
        .map(|record| {
            let mut info = ProtocolInfo([0; 157]);
            for (word, chunk) in info.0.iter_mut().zip(record.chunks_exact(4)) {
                *word = u32::from_ne_bytes(chunk.try_into().expect("four bytes"));
            }
            // SAFETY: `info` is a WSAPROTOCOL_INFOW record; the result is checked before use.
            let socket = unsafe {
                win32::WSASocketW(
                    win32::FROM_PROTOCOL_INFO,
                    win32::FROM_PROTOCOL_INFO,
                    win32::FROM_PROTOCOL_INFO,
                    (&raw mut info).cast(),
                    0,
                    win32::WSA_FLAG_OVERLAPPED | win32::WSA_FLAG_NO_HANDLE_INHERIT,
                )
            };
            if socket == win32::INVALID_SOCKET {
                return Err(LinkError::Unreadable);
            }
            // SAFETY: A new socket that nothing else owns.
            Ok(unsafe { OwnedSocket::from_raw_socket(socket as u64) })
        })
        .collect()
}

/// WSASocketW needs Winsock started, which the standard library does on its first socket.
fn winsock_started() -> Result<(), LinkError> {
    static STARTED: OnceLock<bool> = OnceLock::new();
    let started = *STARTED
        .get_or_init(|| std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).is_ok());
    if started {
        Ok(())
    } else {
        Err(LinkError::Unreadable)
    }
}

pub(super) fn socket_type(socket: &Passed) -> Result<SocketType, LinkError> {
    let mut kind: i32 = 0;
    let mut length = std::mem::size_of::<i32>() as i32;
    // SAFETY: `kind` and `length` are valid for the size passed.
    let rc = unsafe {
        win32::getsockopt(
            socket.as_raw_socket(),
            win32::SOL_SOCKET,
            win32::SO_TYPE,
            (&raw mut kind).cast(),
            &raw mut length,
        )
    };
    if rc != 0 {
        return Err(LinkError::Unreadable);
    }
    Ok(match kind {
        win32::SOCK_DGRAM => SocketType::Datagram,
        win32::SOCK_STREAM => SocketType::Stream,
        _ => SocketType::Other,
    })
}

/// Both ends of a new pipe, each passing sockets to this process.
#[cfg(test)]
pub(crate) fn stream_pair() -> (Stream, Stream) {
    let (a, b) = pipe_pair().expect("a pipe pair");
    a.set_peer(std::process::id());
    b.set_peer(std::process::id());
    (a, b)
}
