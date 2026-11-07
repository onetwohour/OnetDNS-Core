//! TFTP server for PXE boot. The protocol has no authentication, so this side narrows what it
//! serves and accepts: a file name is a single component, and every open goes through a handle on
//! the root directory. Reopening by path would let the root change between check and use.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use onetdns_core::log::sampled;
use onetdns_core::IpNet;

const OP_RRQ: u16 = 1;
const OP_WRQ: u16 = 2;
const OP_DATA: u16 = 3;
const OP_ACK: u16 = 4;
const OP_ERROR: u16 = 5;
const BLOCK: usize = 512;

/// Block numbers are 16 bits; a transfer stops before they wrap and become ambiguous.
const MAX_CLASSIC_TRANSFER: u64 = (u16::MAX as u64) * (BLOCK as u64) - 1;
const MAX_WRITE: u64 = MAX_CLASSIC_TRANSFER;
const MAX_READ: u64 = MAX_CLASSIC_TRANSFER;
const MAX_TRANSFERS: usize = 16;
/// Keeps temporary file names unique.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

struct TransferGuard(Arc<AtomicUsize>);

impl Drop for TransferGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The served directory, held as a handle so the path cannot be swapped after the check.
struct RootHandle {
    dir: File,
}

impl RootHandle {
    /// Refuses a symlink or a non-directory.
    fn open(root: &Path) -> std::io::Result<Self> {
        let canonical = root.canonicalize()?;
        let metadata = canonical.symlink_metadata()?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(std::io::Error::other("TFTP root is not a safe directory"));
        }
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let dir = options.open(&canonical)?;
        if !dir.metadata()?.is_dir() {
            return Err(std::io::Error::other("TFTP root is not a directory"));
        }
        Ok(Self { dir })
    }

    /// Does not follow symlinks, which could point outside the root.
    fn open_read(&self, name: &str) -> std::io::Result<File> {
        let name =
            safe_file_name(name).ok_or_else(|| std::io::Error::other("Unsafe TFTP file name"))?;
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;

        let name = CString::new(std::ffi::OsStr::new(name).as_bytes())
            .map_err(|_| std::io::Error::other("TFTP file name contains NUL"))?;
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::other("TFTP target is not a regular file"));
        }
        Ok(file)
    }

    /// Refuses an existing entry that is not a regular file: a symlink would overwrite its target.
    fn validate_final_name(&self, name: &str, allow_overwrite: bool) -> std::io::Result<()> {
        use std::ffi::CString;
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;

        let name = CString::new(std::ffi::OsStr::new(name).as_bytes())
            .map_err(|_| std::io::Error::other("TFTP file name contains NUL"))?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let rc = unsafe {
            libc::fstatat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc == 0 {
            let stat = unsafe { stat.assume_init() };
            if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
                return Err(std::io::Error::other(
                    "Existing TFTP target is not a regular file or is a symlink",
                ));
            }

            if !allow_overwrite {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "Overwriting an existing TFTP file is not allowed; check tftp_allow_overwrite",
                ));
            }
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err(error)
        }
    }
}

/// Received under a temporary name and renamed only when complete, so an interrupted upload never
/// leaves a half boot image under the real name.
struct TempUpload {
    file: Option<File>,
    root: Arc<RootHandle>,
    temp_name: String,
    final_name: String,
    allow_overwrite: bool,
    /// Without a commit the temporary file is removed on drop.
    committed: bool,
}

impl TempUpload {
    /// Fails if the name already exists.
    fn create(root: Arc<RootHandle>, name: &str, allow_overwrite: bool) -> std::io::Result<Self> {
        let name =
            safe_file_name(name).ok_or_else(|| std::io::Error::other("Unsafe TFTP file name"))?;
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let nonce = u64::from_le_bytes(onetdns_core::try_random_array::<8>()?);
        let temp_name = format!(
            ".{name}.onetdns-tftp-{}-{seq}-{nonce:016x}.tmp",
            std::process::id()
        );

        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;

        root.validate_final_name(name, allow_overwrite)?;
        let temp_c = CString::new(std::ffi::OsStr::new(&temp_name).as_bytes())
            .map_err(|_| std::io::Error::other("Temporary file name contains NUL"))?;
        let fd = unsafe {
            libc::openat(
                root.dir.as_raw_fd(),
                temp_c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        Ok(Self {
            file: Some(file),
            root,
            temp_name,
            final_name: name.to_string(),
            allow_overwrite,
            committed: false,
        })
    }

    fn file_mut(&mut self) -> std::io::Result<&mut File> {
        self.file
            .as_mut()
            .ok_or_else(|| std::io::Error::other("Upload file is closed"))
    }

    /// Rechecks the target right before renaming; something may have appeared there meanwhile.
    fn commit(mut self) -> std::io::Result<()> {
        if let Some(file) = self.file.take() {
            file.sync_all()?;
            drop(file);
        }
        use std::ffi::CString;
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;

        self.root
            .validate_final_name(&self.final_name, self.allow_overwrite)?;
        let temp = CString::new(std::ffi::OsStr::new(&self.temp_name).as_bytes())
            .map_err(|_| std::io::Error::other("Temporary file name contains NUL"))?;
        let final_name = CString::new(std::ffi::OsStr::new(&self.final_name).as_bytes())
            .map_err(|_| std::io::Error::other("Final file name contains NUL"))?;
        atomic_install(
            self.root.dir.as_raw_fd(),
            temp.as_ptr(),
            final_name.as_ptr(),
            self.allow_overwrite,
        )?;
        self.root.dir.sync_all()?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for TempUpload {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        use std::ffi::CString;
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;

        if let Ok(temp) = CString::new(std::ffi::OsStr::new(&self.temp_name).as_bytes()) {
            let _ = unsafe { libc::unlinkat(self.root.dir.as_raw_fd(), temp.as_ptr(), 0) };
        }
    }
}

/// Without overwrite this must succeed only when the target is absent, in one step: checking and
/// renaming separately would overwrite a file created in between. Platforms without such a rename
/// link the new name and remove the temporary one.
fn atomic_install(
    dirfd: std::os::fd::RawFd,
    temp: *const libc::c_char,
    final_name: *const libc::c_char,
    allow_overwrite: bool,
) -> std::io::Result<()> {
    if allow_overwrite {
        let rc = unsafe { libc::renameat(dirfd, temp, dirfd, final_name) };
        return if rc != 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        };
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                dirfd,
                temp,
                dirfd,
                final_name,
                libc::RENAME_NOREPLACE,
            )
        };
        if rc >= 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();

        match err.raw_os_error() {
            Some(libc::ENOSYS) | Some(libc::EINVAL) => {
                let rc = unsafe { libc::linkat(dirfd, temp, dirfd, final_name, 0) };
                if rc != 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    let _ = unsafe { libc::unlinkat(dirfd, temp, 0) };
                    Ok(())
                }
            }
            _ => Err(err),
        }
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let rc = unsafe { libc::renameatx_np(dirfd, temp, dirfd, final_name, libc::RENAME_EXCL) };
        if rc != 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    {
        let rc = unsafe { libc::linkat(dirfd, temp, dirfd, final_name, 0) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let _ = unsafe { libc::unlinkat(dirfd, temp, 0) };
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Read,
    Write,
}

/// The request kind and file name, or why the packet is malformed.
pub fn parse_request(buf: &[u8]) -> Result<(Op, String), &'static str> {
    if buf.len() < 4 {
        return Err("Packet is too short");
    }
    let op = match u16::from_be_bytes([buf[0], buf[1]]) {
        OP_RRQ => Op::Read,
        OP_WRQ => Op::Write,
        _ => return Err("Not a TFTP RRQ or WRQ request"),
    };
    let mut fields = buf[2..].split(|byte| *byte == 0);
    let name = fields.next().ok_or("File name is missing")?;
    let mode = fields.next().ok_or("Transfer mode is missing")?;
    if name.is_empty() || mode.is_empty() {
        return Err("File name or transfer mode is empty");
    }
    if !mode.eq_ignore_ascii_case(b"octet") {
        return Err("Unsupported TFTP mode");
    }
    let rest: Vec<&[u8]> = fields.collect();
    if rest.last().is_some_and(|value| !value.is_empty()) {
        return Err("The request does not end with a NUL character");
    }
    let options = if rest.last().is_some_and(|value| value.is_empty()) {
        &rest[..rest.len().saturating_sub(1)]
    } else {
        &rest[..]
    };
    if options.len() % 2 != 0
        || options
            .chunks(2)
            .any(|pair| pair[0].is_empty() || pair[1].is_empty())
    {
        return Err("Malformed TFTP option key or value");
    }
    let name = std::str::from_utf8(name).map_err(|_| "File name is not valid UTF-8")?;
    Ok((op, name.to_string()))
}

pub fn data_packet(block: u16, data: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(4 + data.len());
    p.extend_from_slice(&OP_DATA.to_be_bytes());
    p.extend_from_slice(&block.to_be_bytes());
    p.extend_from_slice(data);
    p
}

/// Cuts a long message at a character boundary.
pub fn error_packet(code: u16, msg: &str) -> Vec<u8> {
    let mut end = msg.len().min(256);
    while end > 0 && !msg.is_char_boundary(end) {
        end -= 1;
    }
    let safe = &msg[..end];
    let mut p = Vec::with_capacity(5 + safe.len());
    p.extend_from_slice(&OP_ERROR.to_be_bytes());
    p.extend_from_slice(&code.to_be_bytes());
    p.extend_from_slice(safe.as_bytes());
    p.push(0);
    p
}

pub fn ack_packet(block: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(4);
    p.extend_from_slice(&OP_ACK.to_be_bytes());
    p.extend_from_slice(&block.to_be_bytes());
    p
}

fn parse_ack(buf: &[u8]) -> Option<u16> {
    if buf.len() == 4 && u16::from_be_bytes([buf[0], buf[1]]) == OP_ACK {
        Some(u16::from_be_bytes([buf[2], buf[3]]))
    } else {
        None
    }
}

/// Refuses path separators and parent references, which would reach outside the root.
fn safe_file_name(name: &str) -> Option<&str> {
    let name = name.trim();
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('\0')
        || name.contains('/')
        || name.contains('\\')
        || name.contains(':')
    {
        return None;
    }
    Some(name)
}

/// Stops at the size limit; only a complete upload is renamed into place.
fn serve_write(
    sock: &UdpSocket,
    client: SocketAddr,
    root: Arc<RootHandle>,
    name: &str,
    shutdown: &AtomicBool,
    allow_overwrite: bool,
) -> std::io::Result<u64> {
    let mut upload = TempUpload::create(root, name, allow_overwrite)?;
    let mut written = 0u64;
    let mut last_block: u16 = 0;
    let mut last_ack = ack_packet(0);
    sock.send_to(&last_ack, client)?;

    let mut buf = [0u8; 4 + BLOCK];
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return Err(std::io::ErrorKind::ConnectionAborted.into());
        }
        let mut got = None;
        for _ in 0..6 {
            if shutdown.load(Ordering::Relaxed) {
                return Err(std::io::ErrorKind::ConnectionAborted.into());
            }
            match sock.recv_from(&mut buf) {
                Ok((n, from)) if from == client => {
                    got = Some(n);
                    break;
                }
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    let _ = sock.send_to(&last_ack, client);
                }
                Err(error) => return Err(error),
            }
        }
        let Some(n) = got else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "TFTP write request did not finish in time",
            ));
        };
        if n < 4 {
            continue;
        }
        let op = u16::from_be_bytes([buf[0], buf[1]]);
        if op == OP_ERROR {
            return Err(std::io::Error::other("Client sent ERROR"));
        }
        if op != OP_DATA {
            continue;
        }
        let block = u16::from_be_bytes([buf[2], buf[3]]);
        if block == last_block.wrapping_add(1) {
            let payload = &buf[4..n];
            let next = written
                .checked_add(payload.len() as u64)
                .filter(|size| *size <= MAX_WRITE);
            let Some(next) = next else {
                let _ = sock.send_to(&error_packet(3, "Disk full or allocation exceeded"), client);
                return Err(std::io::Error::other(
                    "TFTP write request exceeds the file size limit",
                ));
            };
            upload.file_mut()?.write_all(payload)?;
            written = next;
            last_block = block;
            last_ack = ack_packet(block);
            if payload.len() == BLOCK && last_block == u16::MAX {
                let _ = sock.send_to(
                    &error_packet(3, "Classic TFTP block limit exceeded"),
                    client,
                );
                return Err(std::io::Error::other(
                    "TFTP write requests whose block number wraps around are not allowed",
                ));
            }
            if payload.len() < BLOCK {
                if let Err(error) = upload.commit() {
                    let _ = sock.send_to(&error_packet(2, "Access denied"), client);
                    return Err(error);
                }
                sock.send_to(&last_ack, client)?;

                for _ in 0..4 {
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    match sock.recv_from(&mut buf) {
                        Ok((m, from)) if from == client && m >= 4 => {
                            let rop = u16::from_be_bytes([buf[0], buf[1]]);
                            let rblk = u16::from_be_bytes([buf[2], buf[3]]);
                            if rop == OP_DATA && rblk == last_block {
                                let _ = sock.send_to(&last_ack, client);
                            } else {
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            break;
                        }
                        Err(_) => break,
                    }
                }
                return Ok(written);
            }

            sock.send_to(&last_ack, client)?;
        } else {
            let _ = sock.send_to(&ack_packet(last_block), client);
        }
    }
}

/// Gives up after a few retransmissions without an ACK.
fn serve_read(sock: &UdpSocket, client: SocketAddr, file: &mut File, shutdown: &AtomicBool) {
    static ABORTED: AtomicU64 = AtomicU64::new(0);
    let mut block: u16 = 1;
    let mut buf = [0u8; BLOCK];
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        let n = match file.read(&mut buf) {
            Ok(n) => n,
            Err(error) => {
                if let Some(count) = sampled(&ABORTED) {
                    onetdns_core::warn!(event = "tftp.read_aborted", %client, block = block, count = count, %error, "Failed to read the boot file; aborted the transfer");
                }
                return;
            }
        };
        let pkt = data_packet(block, &buf[..n]);
        let mut acked = false;
        for _ in 0..5 {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            if let Err(error) = sock.send_to(&pkt, client) {
                if let Some(count) = sampled(&ABORTED) {
                    onetdns_core::warn!(event = "tftp.read_aborted", %client, block = block, count = count, %error, "Could not send a boot file block; aborted the transfer");
                }
                return;
            }
            let mut ack = [0u8; 64];
            match sock.recv_from(&mut ack) {
                Ok((len, from)) if from == client && parse_ack(&ack[..len]) == Some(block) => {
                    acked = true;
                    break;
                }
                _ => {}
            }
        }
        if !acked {
            if let Some(count) = sampled(&ABORTED) {
                onetdns_core::warn!(event = "tftp.read_aborted", %client, block = block, count = count, "No response after five retries; aborted the transfer, so this device cannot finish network boot");
            }
            return;
        }
        if n < BLOCK {
            break;
        }
        if block == u16::MAX {
            let _ = sock.send_to(
                &error_packet(0, "Classic TFTP block limit exceeded"),
                client,
            );
            return;
        }
        block += 1;
    }
}

/// Loopback, or an address inside one of `nets`.
fn source_allowed(source: IpAddr, nets: &[IpNet]) -> bool {
    let source = source.to_canonical();
    source.is_loopback() || nets.iter().any(|net| net.contains(&source))
}

/// Each request gets its own transfer socket. A request from outside the list for its operation
/// is dropped without a reply before it takes a transfer slot, since the source of a UDP request
/// can be forged.
pub fn spawn_tftp(
    root: PathBuf,
    listen: SocketAddr,
    read_allow: Vec<IpNet>,
    writable: bool,
    write_allow: Vec<IpNet>,
    allow_overwrite: bool,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let root = Arc::new(RootHandle::open(&root)?);
    let sock = UdpSocket::bind(listen)?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))?;
    let transfer_bind = SocketAddr::new(sock.local_addr()?.ip(), 0);
    let active = Arc::new(AtomicUsize::new(0));
    std::thread::Builder::new().name("tftp".into()).spawn(move || {
        let mut buf = [0u8; 1024];
        let mut transfers = Vec::new();
        while !shutdown.load(Ordering::Relaxed) {
            reap_transfers(&mut transfers);
            let (n, client) = match sock.recv_from(&mut buf) {
                Ok(x) => x,
                Err(error) => {
                    if !matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) {
                        onetdns_core::warn!(event = "tftp.recv_failed", %error, "Failed to receive a TFTP request");
                    }
                    continue;
                }
            };
            let may_read = source_allowed(client.ip(), &read_allow);
            let may_write = source_allowed(client.ip(), &write_allow);
            let request = match parse_request(&buf[..n]) {
                Ok(request) => request,
                Err(error) => {
                    onetdns_core::debug!(event = "tftp.request_invalid", %client, %error, "Rejected a malformed TFTP request");
                    if may_read || may_write {
                        let _ = sock.send_to(&error_packet(4, "Unsupported TFTP request"), client);
                    }
                    continue;
                }
            };
            let (allowed, operation, list) = match request.0 {
                Op::Read => (may_read, "read", "tftp_read_allow"),
                Op::Write => (may_write, "write", "tftp_write_allow"),
            };
            if !allowed {
                static SOURCE_REFUSED: AtomicU64 = AtomicU64::new(0);
                if let Some(count) = sampled(&SOURCE_REFUSED) {
                    onetdns_core::warn!(event = "tftp.source_refused", %client, operation = operation, list = list, count = count, "Dropped a TFTP request from an address outside the allowed list");
                }
                continue;
            }
            if active
                .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |n| {
                    (n < MAX_TRANSFERS).then_some(n + 1)
                })
                .is_err()
            {
                static BUSY: AtomicU64 = AtomicU64::new(0);
                if let Some(count) = sampled(&BUSY) {
                    onetdns_core::warn!(event = "tftp.busy", %client, limit = MAX_TRANSFERS, count = count, "Rejected a TFTP request because the concurrent transfer limit was reached");
                }
                let _ = sock.send_to(&error_packet(0, "Server busy"), client);
                continue;
            }

            let xfer = match UdpSocket::bind(transfer_bind) {
                Ok(s) => s,
                Err(error) => {
                    onetdns_core::warn!(event = "tftp.transfer_bind_failed", %client, %error, "Could not open a transfer socket; TFTP request not handled");
                    active.fetch_sub(1, Ordering::AcqRel);
                    continue;
                }
            };
            if let Err(error) = xfer.set_read_timeout(Some(Duration::from_secs(2))) {
                onetdns_core::warn!(event = "tftp.transfer_timeout_failed", %client, %error, "Could not set a timeout on the transfer socket; an unresponsive peer can hold it for a long time");
            }
            let root = root.clone();
            let active_worker = active.clone();
            let transfer_shutdown = shutdown.clone();
            let spawn = std::thread::Builder::new()
                .name("tftp-transfer".into())
                .spawn(move || {
                    let _guard = TransferGuard(active_worker);
                    match request {
                        (Op::Read, name) => match root.open_read(&name).and_then(|file| {
                            let meta = file.metadata()?;
                            if !meta.is_file() || meta.len() > MAX_READ {
                                return Err(std::io::Error::other("File size or type limit"));
                            }
                            Ok(file)
                        }) {
                            Ok(mut file) => {
                                let bytes = file.metadata().map(|m| m.len()).unwrap_or(0);
                                onetdns_core::debug!(event = "tftp.sent", %client, file = %name, bytes, "Sent TFTP file");
                                serve_read(&xfer, client, &mut file, &transfer_shutdown);
                            }
                            Err(error) => {
                                static READ_REJECTED: AtomicU64 = AtomicU64::new(0);
                                if let Some(count) = sampled(&READ_REJECTED) {
                                    onetdns_core::warn!(event = "tftp.read_rejected", %client, file = %name, count = count, %error, "Could not serve the requested boot file; this device will fail to network boot");
                                }
                                let _ = xfer.send_to(&error_packet(1, "File not found"), client);
                            }
                        },
                        (Op::Write, name) => {
                            if !writable {
                                static WRITE_REJECTED: AtomicU64 = AtomicU64::new(0);
                                if let Some(count) = sampled(&WRITE_REJECTED) {
                                    onetdns_core::warn!(event = "tftp.write_rejected", %client, file = %name, count = count, "Rejected a TFTP write request because tftp_writable is off");
                                }
                                let _ = xfer.send_to(&error_packet(2, "Write not permitted"), client);
                            } else {
                                match serve_write(
                                    &xfer,
                                    client,
                                    root.clone(),
                                    &name,
                                    &transfer_shutdown,
                                    allow_overwrite,
                                ) {
                                    Ok(bytes) => {
                                        onetdns_core::debug!(event = "tftp.received", %client, file = %name, bytes, "Received TFTP file");
                                    }
                                    Err(error)
                                        if error.kind()
                                            == std::io::ErrorKind::ConnectionAborted => {}
                                    Err(error) => {
                                        static RECEIVE_FAILED: AtomicU64 = AtomicU64::new(0);
                                        let _ = xfer.send_to(&error_packet(2, "Access denied"), client);
                                        if let Some(count) = sampled(&RECEIVE_FAILED) {
                                            onetdns_core::warn!(event = "tftp.receive_failed", %client, file = %name, count = count, %error, "Failed to receive TFTP file");
                                        }
                                    }
                                }
                            }
                        }
                    }
                });
            match spawn {
                Ok(thread) => transfers.push(thread),
                Err(error) => {
                    onetdns_core::warn!(event = "tftp.transfer_spawn_failed", %client, %error, "Could not start a transfer thread; TFTP request not handled");
                    active.fetch_sub(1, Ordering::AcqRel);
                }
            }
        }
        for thread in transfers {
            let _ = thread.join();
        }
    })
}

/// Joins finished transfer threads so their handles do not pile up.
fn reap_transfers(transfers: &mut Vec<std::thread::JoinHandle<()>>) {
    let mut index = 0;
    while index < transfers.len() {
        if transfers[index].is_finished() {
            let thread = transfers.swap_remove(index);
            let _ = thread.join();
        } else {
            index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rrq_and_wrq() {
        let mut rrq = vec![0, OP_RRQ as u8];
        rrq.extend_from_slice(b"boot.bin\0octet\0");
        assert_eq!(parse_request(&rrq).unwrap(), (Op::Read, "boot.bin".into()));

        let wrq = vec![0, OP_WRQ as u8, b'x', 0, b'o', b'c', b't', b'e', b't', 0];
        assert_eq!(parse_request(&wrq).unwrap(), (Op::Write, "x".into()));
        assert!(parse_request(b"\0\x01x\0netascii\0").is_err());
        assert!(parse_request(b"\0\x01x\0").is_err());

        let bad = vec![0, 9u8, b'x', 0];
        assert!(parse_request(&bad).is_err());
    }

    #[test]
    fn only_loopback_and_listed_sources_are_served() {
        let lan: Vec<IpNet> = vec!["192.168.1.0/24".parse().unwrap()];
        for (source, nets, allowed) in [
            ("127.0.0.1", &[][..], true),
            ("::1", &[][..], true),
            ("192.168.1.20", &[][..], false),
            ("192.168.1.20", &lan[..], true),
            ("::ffff:192.168.1.20", &lan[..], true),
            ("192.168.2.20", &lan[..], false),
            ("2001:db8::20", &lan[..], false),
        ] {
            assert_eq!(
                source_allowed(source.parse().unwrap(), nets),
                allowed,
                "{source} in {nets:?}"
            );
        }
    }

    #[test]
    fn ack_packet_format() {
        let a = ack_packet(5);
        assert_eq!(a, vec![0, OP_ACK as u8, 0, 5]);
    }

    #[test]
    fn data_and_error_packets() {
        let d = data_packet(7, b"abc");
        assert_eq!(&d[..4], &[0, OP_DATA as u8, 0, 7]);
        assert_eq!(&d[4..], b"abc");
        let e = error_packet(1, "파일을 찾을 수 없습니다");
        assert_eq!(&e[..4], &[0, OP_ERROR as u8, 0, 1]);
        assert_eq!(e.last(), Some(&0u8));
    }

    #[test]
    fn dirfd_pins_root_against_ancestor_replacement() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!(
            "onetdns-tftp-dirfd-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let root = base.join("root");
        let pinned = base.join("pinned");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(root.join("inside.bin"), b"inside").unwrap();
        std::fs::write(outside.join("secret.bin"), b"outside").unwrap();

        let handle = Arc::new(RootHandle::open(&root).unwrap());
        std::fs::rename(&root, &pinned).unwrap();
        symlink(&outside, &root).unwrap();

        assert!(handle.open_read("secret.bin").is_err());
        let mut inside = String::new();
        handle
            .open_read("inside.bin")
            .unwrap()
            .read_to_string(&mut inside)
            .unwrap();
        assert_eq!(inside, "inside");

        let mut upload = TempUpload::create(handle, "written.bin", false).unwrap();
        upload.file_mut().unwrap().write_all(b"pinned").unwrap();
        upload.commit().unwrap();
        assert_eq!(
            std::fs::read(pinned.join("written.bin")).unwrap(),
            b"pinned"
        );
        assert!(!outside.join("written.bin").exists());

        std::fs::remove_file(&root).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn overwrite_gate_blocks_existing_file_unless_allowed() {
        let base = std::env::temp_dir().join(format!(
            "onetdns-tftp-overwrite-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("existing.bin"), b"original").unwrap();

        let handle = Arc::new(RootHandle::open(&base).unwrap());

        let denied = TempUpload::create(handle.clone(), "existing.bin", false);
        assert_eq!(
            denied.err().map(|e| e.kind()),
            Some(std::io::ErrorKind::AlreadyExists),
            "덮어쓰기 비활성 시 기존 파일은 거부되어야"
        );
        assert_eq!(
            std::fs::read(base.join("existing.bin")).unwrap(),
            b"original"
        );

        let mut upload = TempUpload::create(handle, "existing.bin", true).unwrap();
        upload.file_mut().unwrap().write_all(b"replaced").unwrap();
        upload.commit().unwrap();
        assert_eq!(
            std::fs::read(base.join("existing.bin")).unwrap(),
            b"replaced"
        );

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn concurrent_commit_no_overwrite_only_one_wins() {
        let base = std::env::temp_dir().join(format!(
            "onetdns-tftp-race-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&base).unwrap();
        let handle = Arc::new(RootHandle::open(&base).unwrap());

        let mut a = TempUpload::create(handle.clone(), "race.bin", false).unwrap();
        let mut b = TempUpload::create(handle.clone(), "race.bin", false).unwrap();
        a.file_mut().unwrap().write_all(b"aaaa").unwrap();
        b.file_mut().unwrap().write_all(b"bbbb").unwrap();

        let ta = std::thread::spawn(move || a.commit());
        let tb = std::thread::spawn(move || b.commit());
        let ra = ta.join().unwrap();
        let rb = tb.join().unwrap();

        let oks = [ra.is_ok(), rb.is_ok()].into_iter().filter(|x| *x).count();
        assert_eq!(oks, 1, "덮어쓰기 금지 동시 커밋은 하나만 성공");
        let err = ra
            .err()
            .unwrap_or_else(|| rb.expect_err("성공은 하나뿐이므로 나머지는 반드시 실패"));
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);

        std::fs::remove_dir_all(&base).unwrap();
    }
}

#[cfg(test)]
mod fuzz_tests {
    use super::*;

    #[test]
    fn request_parsing_never_panics_on_malformed_bytes() {
        use crate::fuzzutil::{havoc, Rng};

        let mut seed = vec![0u8, 1];

        seed.extend_from_slice(b"pxelinux.0\0octet\0blksize\x001468\0tsize\x000\0");
        let mut rng = Rng::new(0x7F7F_0BAD_5EED_4321);
        for index in 0..20_000u32 {
            let bytes = if index % 3 == 0 {
                rng.rand_bytes(200)
            } else {
                havoc(&mut rng, &seed)
            };
            let _ = parse_request(&bytes);
        }
    }
}
