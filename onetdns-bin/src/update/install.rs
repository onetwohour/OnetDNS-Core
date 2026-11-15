//! The install path and the update files beside it. Every file the swap uses lives in the install
//! path's directory, since only a rename within one file system is atomic. The file names are part
//! of the update contract.

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use super::record::Record;

/// Set by the Linux supervisor for its child, so a process that receives it is a supervised child:
/// the parent handles the update record and the trial, and the child does not. After a swap the
/// child's current_exe ends in " (deleted)", so it uses the path the parent chose at start.
///
/// Empty when the parent could not determine the install path, which still marks the process as a
/// child.
pub(crate) const INSTALL_PATH_ENV: &str = "ONETDNS_SUPERVISOR_INSTALL_PATH";
/// A normal record is a few hundred bytes.
const MAX_RECORD_BYTES: u64 = 4096;
const LOCK_RETRY: Duration = Duration::from_millis(50);

static LOCATED: OnceLock<Located> = OnceLock::new();

struct Located {
    /// Err says why it could not be determined.
    install: Result<Install, String>,
    supervised: bool,
}

/// Called by main before any other thread starts. current_exe answers differently once the running
/// file is replaced, so the path is fixed once at start; clearing the environment variable also
/// needs no other threads running.
pub(crate) fn init() {
    LOCATED.get_or_init(locate);
}

pub(crate) fn current() -> Result<&'static Install, String> {
    LOCATED
        .get_or_init(locate)
        .install
        .as_ref()
        .map_err(Clone::clone)
}

/// A child does not handle the update record.
pub(crate) fn supervised_child() -> bool {
    LOCATED.get_or_init(locate).supervised
}

fn locate() -> Located {
    if let Some(path) = std::env::var_os(INSTALL_PATH_ENV) {
        std::env::remove_var(INSTALL_PATH_ENV);
        let install = if path.is_empty() {
            Err("The supervisor could not find the path of the executable".to_string())
        } else {
            Install::at(PathBuf::from(path))
        };
        return Located {
            install,
            supervised: true,
        };
    }
    let install = std::env::current_exe()
        .map_err(|error| format!("Could not find the path of the running executable: {error}"))
        .and_then(Install::at);
    Located {
        install,
        supervised: false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Install {
    path: PathBuf,
    dir: PathBuf,
    /// Prefix of the sibling names; on Windows, the name without .exe.
    stem: OsString,
    /// Appended back to executable siblings: .exe on Windows, empty elsewhere.
    extension: OsString,
}

/// `windows`: use Windows naming, where a file must end in .exe to run.
fn split_name(name: &OsStr, windows: bool) -> (OsString, OsString) {
    if windows {
        let text = name.to_string_lossy();
        if text.len() > 4 && text.is_char_boundary(text.len() - 4) {
            let (stem, extension) = text.split_at(text.len() - 4);
            if extension.eq_ignore_ascii_case(".exe") {
                return (OsString::from(stem), OsString::from(extension));
            }
        }
    }
    (name.to_os_string(), OsString::new())
}

impl Install {
    /// Refuses a Linux path ending in " (deleted)", which points at an executable already swapped
    /// out.
    pub(crate) fn at(path: PathBuf) -> Result<Self, String> {
        if cfg!(target_os = "linux") && path.to_string_lossy().ends_with(" (deleted)") {
            return Err(
                "The running executable was replaced or removed after it started; restart OnetDNS to update it"
                    .to_string(),
            );
        }
        let name = path
            .file_name()
            .ok_or_else(|| format!("The executable path has no file name: {}", path.display()))?;
        let dir = path
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .ok_or_else(|| format!("The executable path has no directory: {}", path.display()))?
            .to_path_buf();
        let (stem, extension) = split_name(name, cfg!(windows));
        Ok(Self {
            path,
            dir,
            stem,
            extension,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// `executable` appends the extension back.
    fn sibling(&self, suffix: &str, executable: bool) -> PathBuf {
        let mut name = self.stem.clone();
        name.push(".");
        name.push(suffix);
        if executable {
            name.push(&self.extension);
        }
        self.dir.join(name)
    }

    /// The downloaded new executable, awaiting its checks.
    pub(crate) fn staged(&self) -> PathBuf {
        self.sibling("new", true)
    }

    /// For rollback.
    pub(crate) fn previous(&self) -> PathBuf {
        self.sibling("previous", true)
    }

    /// Where a Windows rollback moves the running, failed executable.
    pub(crate) fn failed(&self) -> PathBuf {
        self.sibling("failed", true)
    }

    pub(crate) fn record_path(&self) -> PathBuf {
        self.sibling("update", false)
    }

    /// Serializes applying and record handling.
    fn lock_path(&self) -> PathBuf {
        self.sibling("update.lock", false)
    }

    /// Without them, startup has nothing to handle.
    pub(crate) fn has_update_files(&self) -> bool {
        [self.record_path(), self.staged(), self.failed()]
            .iter()
            .any(|path| path.exists())
    }

    /// Waits up to `wait` while another process holds it. The lock file is really created, so
    /// failing to create it means this process cannot write the install directory. The OS releases
    /// the lock when the process dies.
    pub(crate) fn lock(&self, wait: Duration) -> Result<UpdateLock, LockError> {
        let path = self.lock_path();
        let deadline = Instant::now() + wait;
        loop {
            match try_lock(&path) {
                Ok(Some(file)) => return Ok(UpdateLock { _file: file }),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(LOCK_RETRY),
                Ok(None) => return Err(LockError::Busy),
                Err(error) if is_denied(&error) => return Err(LockError::Denied(error)),
                Err(error) => return Err(LockError::Io(error)),
            }
        }
    }

    /// None when absent. Oversized or non-UTF-8 text reads as empty, which is handled as a stale
    /// record.
    pub(crate) fn read_record(&self) -> io::Result<Option<String>> {
        let file = match File::open(self.record_path()) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Ok(Some(String::new()));
        }
        Ok(Some(String::from_utf8(bytes).unwrap_or_default()))
    }

    pub(crate) fn write_record(&self, _lock: &UpdateLock, record: &Record) -> io::Result<()> {
        crate::atomic_file::atomic_write(&self.record_path(), record.encode().as_bytes())
    }

    /// Succeeds when already absent.
    pub(crate) fn remove_record(&self, _lock: &UpdateLock) -> io::Result<()> {
        remove_if_present(&self.record_path())
    }

    /// After privileges drop, the install directory may not allow new files, so a trial commit
    /// overwrites through a handle opened in advance.
    pub(crate) fn open_record_for_update(&self, _lock: &UpdateLock) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.record_path())
    }

    /// Only call it while no apply is in progress.
    pub(crate) fn remove_leftovers(&self, _lock: &UpdateLock) {
        for path in [self.staged(), self.failed()] {
            if let Err(error) = remove_if_present(&path) {
                onetdns_core::warn!(event = "update.leftover_remove_failed", path = %path.display(), %error, "Could not remove a file left by an earlier update; it is removed at a later start");
            }
        }
    }

    /// Writes the new executable to .new with the previous executable's owner, group, and mode
    /// bits. Refuses when that is not possible, or when the previous file has setuid, setgid, or
    /// file capabilities, since an update cannot reproduce such install steps. On Windows the file
    /// takes the directory's inherited ACL.
    ///
    /// Returns the SHA-256 of the written file.
    pub(crate) fn stage(&self, _lock: &UpdateLock, executable: &[u8]) -> Result<[u8; 32], String> {
        let staged = self.staged();
        let attributes = InstalledAttributes::read(&self.path)?;
        remove_if_present(&staged).map_err(|error| {
            format!(
                "Could not remove the earlier staged file {}: {error}",
                staged.display()
            )
        })?;
        let written = (|| -> io::Result<()> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&staged)?;
            file.write_all(executable)?;
            attributes.apply(&file)?;
            file.sync_all()
        })();
        if let Err(error) = written {
            let _ = std::fs::remove_file(&staged);
            return Err(format!(
                "Could not write the new executable to {}: {error}",
                staged.display()
            ));
        }
        sha256_file(&staged).map_err(|error| {
            format!(
                "Could not read back the new executable {}: {error}",
                staged.display()
            )
        })
    }

    /// Running processes keep the old image. Unix hard-links the install path to .previous and
    /// renames .new over it, so the install path is never missing. Windows cannot delete a running
    /// file but can rename it, so it renames twice; the install path is missing in between, so a
    /// failed second rename undoes the first.
    pub(crate) fn swap(&self, _lock: &UpdateLock) -> io::Result<()> {
        let previous = self.previous();
        remove_if_present(&previous)?;
        #[cfg(unix)]
        {
            std::fs::hard_link(&self.path, &previous)?;
            std::fs::rename(self.staged(), &self.path)?;
            sync_dir(&self.dir)
        }
        #[cfg(not(unix))]
        {
            std::fs::rename(&self.path, &previous)?;
            if let Err(error) = std::fs::rename(self.staged(), &self.path) {
                if let Err(restore) = std::fs::rename(&previous, &self.path) {
                    return Err(io::Error::new(
                        restore.kind(),
                        format!(
                            "{error}; restoring {} also failed ({restore}), so rename it back by hand",
                            self.path.display()
                        ),
                    ));
                }
                return Err(error);
            }
            Ok(())
        }
    }

    /// Skipped when .previous is missing or its hash is not `from_sha256`. Windows moves the
    /// running install file to .failed, then .previous to the install path.
    pub(crate) fn restore_previous(
        &self,
        _lock: &UpdateLock,
        from_sha256: &[u8; 32],
    ) -> Result<(), String> {
        let previous = self.previous();
        let found = sha256_file(&previous).map_err(|error| {
            format!(
                "Cannot revert because the previous executable {} could not be read: {error}",
                previous.display()
            )
        })?;
        if found != *from_sha256 {
            return Err(format!(
                "Cannot revert because {} is not the executable that was replaced",
                previous.display()
            ));
        }
        let moved = (|| -> io::Result<()> {
            #[cfg(unix)]
            {
                std::fs::rename(&previous, &self.path)?;
                sync_dir(&self.dir)
            }
            #[cfg(not(unix))]
            {
                let failed = self.failed();
                remove_if_present(&failed)?;
                std::fs::rename(&self.path, &failed)?;
                if let Err(error) = std::fs::rename(&previous, &self.path) {
                    let _ = std::fs::rename(&failed, &self.path);
                    return Err(error);
                }
                Ok(())
            }
        })();
        moved.map_err(|error| {
            format!(
                "Could not move {} back to {}: {error}",
                previous.display(),
                self.path.display()
            )
        })
    }

    /// The first step of an operator-requested rollback.
    pub(crate) fn stage_previous(&self, _lock: &UpdateLock) -> io::Result<()> {
        remove_if_present(&self.staged())?;
        std::fs::rename(self.previous(), self.staged())
    }

    /// For a rollback that stopped at the preflight.
    pub(crate) fn unstage_previous(&self, _lock: &UpdateLock) -> io::Result<()> {
        std::fs::rename(self.staged(), self.previous())
    }

    pub(crate) fn discard_staged(&self, _lock: &UpdateLock) {
        let staged = self.staged();
        if let Err(error) = remove_if_present(&staged) {
            onetdns_core::warn!(event = "update.staged_remove_failed", path = %staged.display(), %error, "Could not remove the staged executable; it is removed at the next start");
        }
    }
}

/// Released on drop.
pub(crate) struct UpdateLock {
    _file: File,
}

#[cfg(unix)]
impl Drop for UpdateLock {
    /// Unlocks before closing. A flock lock is released only when every handle to the same open
    /// file closes, and a child another thread spawns meanwhile inherits this handle until it
    /// execs. Closing alone would leave the lock held then, and the next lock would think another
    /// update is running. LOCK_UN releases it at once, inherited handles included; its result is
    /// ignored, since closing every handle releases it anyway.
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;

        unsafe { libc::flock(self._file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[derive(Debug)]
pub(crate) enum LockError {
    /// Another process is applying or trialing an update.
    Busy,
    /// This process cannot write the install directory.
    Denied(io::Error),
    Io(io::Error),
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::Busy => f.write_str("Another update is being applied or tried out"),
            LockError::Denied(error) => write!(
                f,
                "This process cannot write to the directory of the executable ({error}); run OnetDNS --cli update as an administrator instead"
            ),
            LockError::Io(error) => write!(f, "Could not open the update lock: {error}"),
        }
    }
}

fn is_denied(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem
    )
}

#[cfg(unix)]
/// Tries flock once; None when another process holds it.
fn try_lock(path: &Path) -> io::Result<Option<File>> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(Some(file));
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EWOULDBLOCK) => return Ok(None),
            _ => return Err(error),
        }
    }
}

#[cfg(windows)]
/// Opens without sharing; None when another process has it open.
fn try_lock(path: &Path) -> io::Result<Option<File>> {
    use std::os::windows::fs::OpenOptionsExt;

    const ERROR_SHARING_VIOLATION: i32 = 32;
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(path)
    {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => Ok(None),
        Err(error) => Err(error),
    }
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

#[cfg(unix)]
/// So a rename survives a power loss.
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

pub(crate) fn sha256_file(path: &Path) -> io::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};

    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

/// Writes through the handle opened before privileges dropped. A power loss mid-write breaks the
/// record, but the next start removes a broken record as stale, so it never disagrees with the
/// executables.
pub(crate) fn overwrite(file: &mut File, text: &str) -> io::Result<()> {
    file.rewind()?;
    file.write_all(text.as_bytes())?;
    file.set_len(text.len() as u64)?;
    file.sync_all()
}

/// Carried from the previous executable to the new one.
struct InstalledAttributes {
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    gid: u32,
    #[cfg(unix)]
    mode: u32,
}

impl InstalledAttributes {
    /// Refuses attributes an update cannot reproduce.
    fn read(path: &Path) -> Result<Self, String> {
        let metadata = std::fs::metadata(path).map_err(|error| {
            format!(
                "Could not read the installed executable {}: {error}",
                path.display()
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o6000 != 0 {
                return Err(format!(
                    "{} has the setuid or setgid bit, which an update cannot reproduce; replace it by hand",
                    path.display()
                ));
            }
            #[cfg(target_os = "linux")]
            if has_file_capabilities(path)? {
                return Err(format!(
                    "{} has file capabilities, which an update cannot reproduce; replace it by hand",
                    path.display()
                ));
            }
            Ok(Self {
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: metadata.mode() & 0o777,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Ok(Self {})
        }
    }

    /// Fails when the owner cannot be set.
    fn apply(&self, file: &File) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            use std::os::unix::io::AsRawFd;
            if unsafe { libc::fchown(file.as_raw_fd(), self.uid, self.gid) } != 0 {
                return Err(io::Error::last_os_error());
            }
            file.set_permissions(std::fs::Permissions::from_mode(self.mode))
        }
        #[cfg(not(unix))]
        {
            let _ = file;
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
fn has_file_capabilities(path: &Path) -> Result<bool, String> {
    use std::os::unix::ffi::OsStrExt;

    let raw = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "The executable path contains a NUL character".to_string())?;
    let size = unsafe {
        libc::getxattr(
            raw.as_ptr(),
            c"security.capability".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size >= 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENODATA) | Some(libc::ENOTSUP) => Ok(false),
        _ => Err(format!(
            "Could not read the file capabilities of {}: {error}",
            path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update::scratch::Scratch;

    #[test]
    /// On Windows, only the executable siblings end in .exe.
    fn sibling_names_follow_the_contract() {
        let dir = PathBuf::from("dir");
        let names = |name: &str, windows: bool| {
            let (stem, extension) = split_name(OsStr::new(name), windows);
            let install = Install {
                path: dir.join(name),
                dir: dir.clone(),
                stem,
                extension,
            };
            [
                install.staged(),
                install.previous(),
                install.failed(),
                install.record_path(),
                install.lock_path(),
            ]
            .map(|path| {
                path.file_name()
                    .expect("이름")
                    .to_string_lossy()
                    .into_owned()
            })
        };
        assert_eq!(
            names("OnetDNS", false),
            [
                "OnetDNS.new",
                "OnetDNS.previous",
                "OnetDNS.failed",
                "OnetDNS.update",
                "OnetDNS.update.lock"
            ]
        );
        assert_eq!(
            names("OnetDNS.exe", true),
            [
                "OnetDNS.new.exe",
                "OnetDNS.previous.exe",
                "OnetDNS.failed.exe",
                "OnetDNS.update",
                "OnetDNS.update.lock"
            ]
        );
        assert_eq!(names("OnetDNS.EXE", true)[0], "OnetDNS.new.EXE");
        assert_eq!(names("onetdns", true)[0], "onetdns.new");
    }

    #[test]
    fn deleted_executable_paths_are_refused() {
        let deleted = Install::at(PathBuf::from("/usr/local/bin/OnetDNS (deleted)"));
        assert_eq!(deleted.is_err(), cfg!(target_os = "linux"));
        assert!(Install::at(PathBuf::from("OnetDNS")).is_err());
    }

    #[test]
    fn lock_is_exclusive_and_released_on_drop() {
        let scratch = Scratch::new("lock");
        let install = scratch.install();
        let held = install.lock(Duration::ZERO).expect("첫 잠금");
        assert!(matches!(
            install.lock(Duration::from_millis(120)),
            Err(LockError::Busy)
        ));
        drop(held);
        install.lock(Duration::ZERO).expect("놓은 뒤의 잠금");
    }

    #[cfg(unix)]
    #[test]
    /// A child another thread spawns meanwhile inherits this handle until it execs; a duplicate
    /// handle to the same open file reproduces that. Closing the file alone would leave the next
    /// lock Busy while the duplicate lives.
    fn released_lock_ignores_inherited_handles() {
        let scratch = Scratch::new("lock-inherited");
        let install = scratch.install();
        let held = install.lock(Duration::ZERO).expect("첫 잠금");
        let inherited = held._file.try_clone().expect("핸들 복제");
        drop(held);
        install
            .lock(Duration::ZERO)
            .expect("복제 핸들이 남은 채 놓은 잠금");
        drop(inherited);
    }

    #[test]
    /// Both read as empty, handled as a stale record.
    fn oversized_or_binary_records_read_as_empty() {
        let scratch = Scratch::new("record");
        let install = scratch.install();
        assert_eq!(install.read_record().expect("없는 기록"), None);
        std::fs::write(install.record_path(), vec![b'a'; 5000]).expect("큰 기록");
        assert_eq!(install.read_record().expect("큰 기록"), Some(String::new()));
        std::fs::write(install.record_path(), [0xff, 0xfe]).expect("깨진 기록");
        assert_eq!(
            install.read_record().expect("깨진 기록"),
            Some(String::new())
        );
    }

    #[test]
    /// No tail of the old record is left.
    fn overwrite_replaces_the_whole_record() {
        let scratch = Scratch::new("overwrite");
        let path = scratch.0.join("record");
        std::fs::write(&path, "state=trial\nlonger tail that must vanish\n").expect("기록");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("핸들");
        overwrite(&mut file, "state=committed\n").expect("덮어쓰기");
        drop(file);
        assert_eq!(
            std::fs::read_to_string(&path).expect("다시 읽기"),
            "state=committed\n"
        );
    }

    /// A process actually running from the install path. The swap only means something against a
    /// running image: Windows cannot delete a running file, and Unix cannot write one.
    struct Running(std::process::Child);

    impl Running {
        /// If it exited, the swap did not touch a running file.
        fn assert_alive(&mut self) {
            assert!(
                self.0.try_wait().expect("자식 프로세스 상태").is_none(),
                "설치 경로에서 실행한 자식 프로세스가 이미 끝났습니다"
            );
        }
    }

    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Copies this test binary to the install path and runs, as a child, a test that only waits.
    fn run_copy_of_this_binary(install: &Install) -> Running {
        std::fs::copy(
            std::env::current_exe().expect("테스트 바이너리"),
            install.path(),
        )
        .expect("설치 경로에 복사");
        let mut command = std::process::Command::new(install.path());
        command
            .args([
                "--ignored",
                "--exact",
                "update::install::tests::waits_while_a_test_swaps_its_executable",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // Linux refuses to exec while a child another test thread spawned holds an inherited write
        // handle to the fresh copy, so this uses the retry the update uses to start a new
        // executable.
        let child = crate::update::apply::spawn(&mut command).expect("설치 경로의 실행");
        std::thread::sleep(Duration::from_millis(300));
        Running(child)
    }

    #[test]
    #[ignore = "맞바꾸기 테스트가 자식 프로세스로 실행한다"]
    /// Does not end until the parent test closes stdin. A fixed sleep could end first where the
    /// parent takes longer, hashing a large test binary several times. The OS closes the pipe if
    /// the parent dies, so nothing is left behind.
    fn waits_while_a_test_swaps_its_executable() {
        let _ = std::io::copy(&mut std::io::stdin(), &mut std::io::sink());
    }

    #[test]
    /// After the swap, the install path holds the new file and .previous the old one; after the
    /// revert, the install path holds the old file again. A changed .previous is not restored.
    fn running_executable_swaps_and_reverts() {
        let scratch = Scratch::new("swap");
        let install = scratch.install();
        let mut running = run_copy_of_this_binary(&install);
        running.assert_alive();
        let old = sha256_file(install.path()).expect("이전 해시");

        let lock = install.lock(Duration::ZERO).expect("잠금");
        let new_bytes = b"new executable bytes".to_vec();
        let staged = install.stage(&lock, &new_bytes).expect(".new 쓰기");
        assert_eq!(staged, sha256_file(&install.staged()).expect(".new 해시"));
        install.swap(&lock).expect("맞바꾸기");
        assert_eq!(std::fs::read(install.path()).expect("설치 경로"), new_bytes);
        assert_eq!(sha256_file(&install.previous()).expect(".previous"), old);
        assert!(!install.staged().exists());

        assert!(
            install.restore_previous(&lock, &[0u8; 32]).is_err(),
            "다른 해시를 주면 되돌리지 않아야 합니다"
        );
        assert_eq!(std::fs::read(install.path()).expect("설치 경로"), new_bytes);

        install.restore_previous(&lock, &old).expect("되돌리기");
        assert_eq!(sha256_file(install.path()).expect("되돌린 설치 경로"), old);
        assert!(!install.previous().exists());
        running.assert_alive();
    }

    #[cfg(unix)]
    #[test]
    fn staged_file_keeps_mode_and_refuses_setuid() {
        use std::os::unix::fs::PermissionsExt;

        let scratch = Scratch::new("mode");
        let install = scratch.install();
        std::fs::write(install.path(), b"old").expect("이전 파일");
        std::fs::set_permissions(install.path(), std::fs::Permissions::from_mode(0o750))
            .expect("권한");
        let lock = install.lock(Duration::ZERO).expect("잠금");
        install.stage(&lock, b"new").expect(".new");
        let mode = std::fs::metadata(install.staged())
            .expect(".new")
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o750);

        std::fs::set_permissions(install.path(), std::fs::Permissions::from_mode(0o4755))
            .expect("setuid");
        assert!(install.stage(&lock, b"new").is_err());
    }
}
