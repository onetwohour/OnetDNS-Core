/*!
 * @brief PXE 부팅용 TFTP 서버.
 *
 * @details 네트워크 부팅 클라이언트가 부트 이미지를 받아 가는 경로다. 인증이 없는 프로토콜이라
 *          내줄 것과 받을 것을 이쪽에서 좁혀야 한다.
 * @warning 파일 이름은 이름 한 조각만 받는다. 경로 구분자나 상위 참조가 들어오면 루트
 *          바깥을 읽고 쓴다. 게다가 디렉터리를 핸들로 붙들고 그 안에서만 여닫는다.
 *          경로 문자열로 다시 열면 검사와 사용 사이에 루트가 바뀌어 있을 수 있다.
 */

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use onetdns_core::IpNet;

/** @brief 읽기 요청. */
const OP_RRQ: u16 = 1;
/** @brief 쓰기 요청. */
const OP_WRQ: u16 = 2;
/** @brief 데이터 블록. */
const OP_DATA: u16 = 3;
/** @brief 받았다는 응답. */
const OP_ACK: u16 = 4;
/** @brief 오류. */
const OP_ERROR: u16 = 5;
/** @brief 블록 하나의 크기. */
const BLOCK: usize = 512;

/**
 * @brief 확장 없이 옮길 수 있는 최대 크기.
 * @details 블록 번호가 16비트라 한 바퀴 돌면 앞의 블록과 구분되지 않는다. 그래서 순환하는
 *          지점 앞에서 끊는다.
 */
const MAX_CLASSIC_TRANSFER: u64 = (u16::MAX as u64) * (BLOCK as u64) - 1;
/** @brief 받아들일 파일 크기 상한. */
const MAX_WRITE: u64 = MAX_CLASSIC_TRANSFER;
/** @brief 내줄 파일 크기 상한. */
const MAX_READ: u64 = MAX_CLASSIC_TRANSFER;
/** @brief 동시에 진행할 전송 수. */
const MAX_TRANSFERS: usize = 16;
/** @brief 임시 파일 이름이 겹치지 않게 하는 일련번호. */
static TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

/** @brief 전송이 끝나면 진행 수를 되돌린다. */
struct TransferGuard(Arc<AtomicUsize>);

impl Drop for TransferGuard {
    /** @brief 진행 수를 하나 줄인다. */
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/**
 * @brief 서빙할 디렉터리를 핸들로 붙든 것.
 * @warning 경로 문자열이 아니라 핸들을 잡는다. 문자열로 매번 다시 열면 검사한 뒤
 *          사용하기 전에 그 경로가 다른 곳을 가리키게 바뀔 수 있다.
 */
struct RootHandle {
    /** @brief 서빙할 디렉터리 핸들. 경로 문자열이 아니라 핸들을 잡는다. */
    dir: File,
}

impl RootHandle {
    /** @brief 디렉터리를 연다. 이어진 곳이거나 디렉터리가 아니면 거부한다. */
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

    /**
     * @brief 이 디렉터리 안의 파일을 읽기로 연다.
     * @warning 이어진 곳을 따라가지 않는다. 따라가면 루트 바깥의 파일이 그대로 나간다.
     */
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

    /**
     * @brief 이 이름에 써도 되는지 확인한다.
     * @warning 이미 있는 것이 일반 파일이 아니면 거부한다. 이어진 곳이면 그 끝의 파일을
     *          덮어쓰게 된다.
     */
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

/**
 * @brief 임시 이름으로 받아 두었다가 마지막에 제 이름으로 옮기는 업로드.
 * @details 도중에 끊기면 임시 파일만 남고 원래 파일은 그대로다. 부트 이미지가 반쪽인
 *          채로 놓이면 그것으로 부팅하는 기계가 망가진다.
 */
struct TempUpload {
    /** @brief 쓰고 있는 임시 파일. */
    file: Option<File>,
    /** @brief 이 파일이 놓일 디렉터리. */
    root: Arc<RootHandle>,
    /** @brief 임시 이름. */
    temp_name: String,
    /** @brief 다 받고 나서 옮길 이름. */
    final_name: String,
    /** @brief 이미 있는 파일을 덮어도 되는지. */
    allow_overwrite: bool,
    /** @brief 제 이름으로 옮겼는지. 아니면 임시 파일을 지운다. */
    committed: bool,
}

impl TempUpload {
    /** @brief 임시 파일을 만든다. 같은 이름이 이미 있으면 실패한다. */
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

    /** @brief 쓰고 있는 파일. */
    fn file_mut(&mut self) -> std::io::Result<&mut File> {
        self.file
            .as_mut()
            .ok_or_else(|| std::io::Error::other("Upload file is closed"))
    }

    /**
     * @brief 다 받은 것을 제 이름으로 옮긴다.
     * @details 옮기기 직전에 대상 이름을 다시 확인한다. 받는 동안 그곳에 다른 것이
     *          생겼을 수 있다.
     */
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
    /** @brief 옮기지 못했으면 임시 파일을 지운다. */
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

/**
 * @brief 임시 파일을 제 이름으로 옮긴다.
 * @warning 덮어쓰기를 허용하지 않았으면 대상이 없을 때만 성공해야 한다. 확인하고 옮기는
 *          두 단계로 나누면 그 사이에 생긴 파일을 덮는다.
 * @note 한 단계로 처리하는 방법이 플랫폼마다 다르다. 없으면 링크를 새로 만들고 원본을 지우는 방식을
 *       쓴다.
 */
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
/** @brief 요청 종류. */
pub enum Op {
    /** @brief 파일을 받아 간다. */
    Read,
    /** @brief 파일을 올린다. */
    Write,
}

/**
 * @brief 요청 패킷을 읽는다.
 * @return 요청 종류와 파일 이름. 형식이 어긋나면 사유.
 */
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

/** @brief 데이터 블록 패킷. */
pub fn data_packet(block: u16, data: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(4 + data.len());
    p.extend_from_slice(&OP_DATA.to_be_bytes());
    p.extend_from_slice(&block.to_be_bytes());
    p.extend_from_slice(data);
    p
}

/** @brief 오류 패킷. 메시지가 길면 글자 경계에서 자른다. */
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

/** @brief 받았다는 응답 패킷. */
pub fn ack_packet(block: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(4);
    p.extend_from_slice(&OP_ACK.to_be_bytes());
    p.extend_from_slice(&block.to_be_bytes());
    p
}

/** @brief 응답 패킷의 블록 번호. */
fn parse_ack(buf: &[u8]) -> Option<u16> {
    if buf.len() == 4 && u16::from_be_bytes([buf[0], buf[1]]) == OP_ACK {
        Some(u16::from_be_bytes([buf[2], buf[3]]))
    } else {
        None
    }
}

/**
 * @brief 이 이름을 그대로 써도 되는지.
 * @warning 경로 구분자와 상위 참조를 막는다. 막지 않으면 루트 바깥을 읽고 쓴다.
 */
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

/**
 * @brief 파일 하나를 받는다.
 * @details 임시 이름으로 받고 끝까지 왔을 때만 제 이름으로 옮긴다. 상한을 넘으면 끊는다.
 */
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

/** @brief 파일 하나를 내보낸다. 응답이 없으면 몇 번 다시 보내고 그만둔다. */
fn serve_read(sock: &UdpSocket, client: SocketAddr, file: &mut File, shutdown: &AtomicBool) {
    let mut block: u16 = 1;
    let mut buf = [0u8; BLOCK];
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        let n = match file.read(&mut buf) {
            Ok(n) => n,
            Err(error) => {
                onetdns_core::warn!(event = "tftp.read_aborted", %client, block = block, %error, "Failed to read the boot file; aborted the transfer");
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
                onetdns_core::warn!(event = "tftp.read_aborted", %client, block = block, %error, "Could not send a boot file block; aborted the transfer");
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
            onetdns_core::warn!(event = "tftp.read_aborted", %client, block = block, "No response after five retries; aborted the transfer, so this device cannot finish network boot");
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

/**
 * @brief TFTP 서버를 시작한다.
 * @details 요청마다 전송용 소켓을 따로 열어 그 자리에서 주고받는다. 쓰기는 허용한
 *          대역에서만 받는다.
 */
pub fn spawn_tftp(
    root: PathBuf,
    listen: SocketAddr,
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
    let write_allow = Arc::new(write_allow);
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
            let request = match parse_request(&buf[..n]) {
                Ok(request) => request,
                Err(error) => {
                    onetdns_core::debug!(event = "tftp.request_invalid", %client, %error, "Rejected a malformed TFTP request");
                    let _ = sock.send_to(&error_packet(4, "Unsupported TFTP request"), client);
                    continue;
                }
            };
            if active
                .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |n| {
                    (n < MAX_TRANSFERS).then_some(n + 1)
                })
                .is_err()
            {
                onetdns_core::warn!(event = "tftp.busy", %client, limit = MAX_TRANSFERS, "Rejected a TFTP request because the concurrent transfer limit was reached");
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
            let write_allow = write_allow.clone();
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
                                onetdns_core::warn!(event = "tftp.read_rejected", %client, file = %name, %error, "Could not serve the requested boot file; this device will fail to network boot");
                                let _ = xfer.send_to(&error_packet(1, "File not found"), client);
                            }
                        },
                        (Op::Write, name) => {

                            let src_ok = write_allow.is_empty()
                                || write_allow.iter().any(|n| n.contains(&client.ip()));
                            if !writable || !src_ok {
                                let reason = if writable { "source_not_allowed" } else { "write_disabled" };
                                onetdns_core::warn!(event = "tftp.write_rejected", %client, file = %name, reason = reason, "Rejected a TFTP write request that is not allowed");
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
                                        let _ = xfer.send_to(&error_packet(2, "Access denied"), client);
                                        onetdns_core::warn!(event = "tftp.receive_failed", %client, file = %name, %error, "Failed to receive TFTP file");
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

/** @brief 끝난 전송 스레드를 정리한다. 쌓이면 핸들이 계속 는다. */
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
/** @brief 패킷 형식과, 루트 고정 및 덮어쓰기 관문이 실제로 막는지. */
mod tests {
    use super::*;

    #[test]
    /** @brief 읽기와 쓰기 요청이 읽히는지. */
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
    /** @brief 응답 패킷 형식. */
    fn ack_packet_format() {
        let a = ack_packet(5);
        assert_eq!(a, vec![0, OP_ACK as u8, 0, 5]);
    }

    #[test]
    /** @brief 자료와 오류 패킷 형식. */
    fn data_and_error_packets() {
        let d = data_packet(7, b"abc");
        assert_eq!(&d[..4], &[0, OP_DATA as u8, 0, 7]);
        assert_eq!(&d[4..], b"abc");
        let e = error_packet(1, "파일을 찾을 수 없습니다");
        assert_eq!(&e[..4], &[0, OP_ERROR as u8, 0, 1]);
        assert_eq!(e.last(), Some(&0u8));
    }

    #[test]
    /** @brief 루트 경로가 도중에 바뀌어도 이전 디렉터리 안에서만 움직이는지. */
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
    /** @brief 허용하지 않았으면 기존 파일을 덮지 않는지. */
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
    /** @brief 동시에 같은 이름으로 올려도 하나만 성공하는지. 둘 다 성공하면 덮어쓴 것이다. */
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
/** @brief 망가진 바이트열에도 파서가 패닉하지 않는지. */
mod fuzz_tests {
    use super::*;

    #[test]
    /** @brief 어떤 바이트열이 와도 오류로 끝날 뿐 패닉하지 않는지. */
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
