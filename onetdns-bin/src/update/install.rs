/*!
 * @brief 설치 경로와 그 옆에 두는 업데이트 파일.
 *
 * @details 교체에 쓰는 파일은 모두 설치 경로와 같은 디렉터리에 둔다. 같은 파일 시스템 안의
 *          rename 이어야 원자적으로 바뀐다. 파일 이름은 업데이트 계약에 든다.
 */

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use super::record::Record;

/**
 * @brief Linux 감독자가 자식에게 설치 경로를 넘기는 환경 변수.
 * @details 이 변수를 받은 프로세스는 감독자의 자식이다. 업데이트 기록과 시험 실행은 부모가 맡고
 *          자식은 기록을 처리하지 않는다. 자식의 current_exe 는 맞바꾼 뒤에 (deleted) 가 붙으므로
 *          부모가 시작할 때 정한 경로를 받아 쓴다. 부모가 설치 경로를 정하지 못했으면 빈 값을 넘겨
 *          자식이라는 것만 알린다.
 */
pub(crate) const INSTALL_PATH_ENV: &str = "ONETDNS_SUPERVISOR_INSTALL_PATH";
/** @brief 업데이트 기록을 읽을 때의 상한. 정상 기록은 몇백 바이트다. */
const MAX_RECORD_BYTES: u64 = 4096;
/** @brief 잠금을 다시 시도하는 간격. */
const LOCK_RETRY: Duration = Duration::from_millis(50);

/** @brief 프로세스가 시작할 때 정한 설치 경로. */
static LOCATED: OnceLock<Located> = OnceLock::new();

/** @brief 시작할 때 정한 설치 경로와, 감독자의 자식인지. */
struct Located {
    /** @brief 설치 경로. 정하지 못했으면 그 이유. */
    install: Result<Install, String>,
    /** @brief 감독자의 자식인지. */
    supervised: bool,
}

/**
 * @brief 설치 경로를 정한다. 다른 스레드를 띄우기 전에 main 이 부른다.
 * @details 실행 중인 파일이 나중에 바뀌면 current_exe 가 다른 답을 주므로 시작할 때 한 번만 정한다.
 *          환경 변수를 지우는 일도 다른 스레드가 없을 때 해야 한다.
 */
pub(crate) fn init() {
    LOCATED.get_or_init(locate);
}

/** @brief 시작할 때 정한 설치 경로. 정하지 못했으면 그 이유. */
pub(crate) fn current() -> Result<&'static Install, String> {
    LOCATED
        .get_or_init(locate)
        .install
        .as_ref()
        .map_err(Clone::clone)
}

/** @brief 감독자의 자식인지. 자식은 업데이트 기록을 처리하지 않는다. */
pub(crate) fn supervised_child() -> bool {
    LOCATED.get_or_init(locate).supervised
}

/** @brief 환경 변수나 current_exe 로 설치 경로를 찾는다. */
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
/** @brief 설치 경로와 그 옆 파일들의 이름. */
pub(crate) struct Install {
    /** @brief 설치 경로. */
    path: PathBuf,
    /** @brief 설치 경로가 든 디렉터리. */
    dir: PathBuf,
    /** @brief 옆 파일 이름의 앞부분. Windows 는 .exe 를 뗀 이름이다. */
    stem: OsString,
    /** @brief 실행 파일 이름 끝에 다시 붙일 확장자. Windows 는 .exe, 그 밖은 비어 있다. */
    extension: OsString,
}

/**
 * @brief 실행 파일 이름에서 옆 파일 이름의 앞부분과 확장자를 가른다.
 * @param windows Windows 이름 규칙을 쓸지. 실행할 파일이 .exe 로 끝나야 실행되는 플랫폼이다.
 */
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
    /** @brief 이 경로를 설치 경로로 삼는다. */
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

    /** @brief 설치 경로. */
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /** @brief 이 이름 뒤에 붙인 옆 파일. 실행 파일이면 확장자를 다시 붙인다. */
    fn sibling(&self, suffix: &str, executable: bool) -> PathBuf {
        let mut name = self.stem.clone();
        name.push(".");
        name.push(suffix);
        if executable {
            name.push(&self.extension);
        }
        self.dir.join(name)
    }

    /** @brief 내려받아 점검을 기다리는 새 실행 파일. */
    pub(crate) fn staged(&self) -> PathBuf {
        self.sibling("new", true)
    }

    /** @brief 바로 전 실행 파일. 되돌릴 때 쓴다. */
    pub(crate) fn previous(&self) -> PathBuf {
        self.sibling("previous", true)
    }

    /** @brief Windows 에서 되돌릴 때 실행 중이던 실패한 실행 파일을 옮겨 두는 곳. */
    pub(crate) fn failed(&self) -> PathBuf {
        self.sibling("failed", true)
    }

    /** @brief 업데이트 기록. */
    pub(crate) fn record_path(&self) -> PathBuf {
        self.sibling("update", false)
    }

    /** @brief 적용과 기록 처리를 한 번에 하나로 묶는 잠금 파일. */
    fn lock_path(&self) -> PathBuf {
        self.sibling("update.lock", false)
    }

    /** @brief 업데이트가 남긴 파일이 있는지. 없으면 시작할 때 처리할 것이 없다. */
    pub(crate) fn has_update_files(&self) -> bool {
        [self.record_path(), self.staged(), self.failed()]
            .iter()
            .any(|path| path.exists())
    }

    /**
     * @brief 잠금을 잡는다. 다른 프로세스가 쥐고 있으면 wait 동안 기다린다.
     * @details 잠금 파일을 실제로 만들어 보므로, 만들지 못하면 이 프로세스가 설치 디렉터리에 쓸 수
     *          없다는 뜻이다. 잠금은 프로세스가 죽으면 운영체제가 푼다.
     */
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

    /** @brief 기록 파일의 글. 없으면 없다. 글이 UTF-8 이 아니면 빈 글을 돌려 오래된 기록으로 다루게 한다. */
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

    /** @brief 기록을 원자적으로 쓴다. */
    pub(crate) fn write_record(&self, _lock: &UpdateLock, record: &Record) -> io::Result<()> {
        crate::atomic_file::atomic_write(&self.record_path(), record.encode().as_bytes())
    }

    /** @brief 기록을 지운다. 이미 없으면 그대로 성공이다. */
    pub(crate) fn remove_record(&self, _lock: &UpdateLock) -> io::Result<()> {
        remove_if_present(&self.record_path())
    }

    /**
     * @brief 기록을 쓰기 가능으로 연다.
     * @details 권한을 내려놓은 뒤에는 설치 디렉터리에 새 파일을 만들 수 없을 수 있다. 시험 실행의
     *          확정은 이렇게 미리 열어 둔 핸들로 덮어쓴다.
     */
    pub(crate) fn open_record_for_update(&self, _lock: &UpdateLock) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.record_path())
    }

    /** @brief 지난 적용이 남긴 새 실행 파일과 실패한 실행 파일을 지운다. 진행 중인 적용이 없을 때만 부른다. */
    pub(crate) fn remove_leftovers(&self, _lock: &UpdateLock) {
        for path in [self.staged(), self.failed()] {
            if let Err(error) = remove_if_present(&path) {
                onetdns_core::warn!(event = "update.leftover_remove_failed", path = %path.display(), %error, "Could not remove a file left by an earlier update; it is removed at a later start");
            }
        }
    }

    /**
     * @brief 새 실행 파일을 .new 에 쓴다.
     * @details 이전 실행 파일의 소유자, 그룹, 권한 비트를 그대로 준다. 그렇게 할 수 없거나 이전 파일에
     *          setuid, setgid, 파일 capability 가 붙어 있으면 거절한다. 업데이트가 그런 설치 단계를
     *          재현할 수 없기 때문이다. Windows 에서는 디렉터리의 상속 ACL 을 받는다.
     * @return 쓴 파일의 SHA-256.
     */
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

    /**
     * @brief 설치 경로를 .new 로 맞바꾼다. 실행 중인 프로세스는 이전 이미지를 계속 쓴다.
     * @details Unix 는 설치 경로를 .previous 로 하드 링크한 뒤 .new 를 설치 경로로 rename 하므로 설치
     *          경로가 비는 순간이 없다. Windows 는 실행 중인 파일을 지울 수 없지만 이름은 바꿀 수 있어
     *          두 번 rename 한다. 그 사이에는 설치 경로가 비므로 두 번째가 실패하면 첫 번째를 되돌린다.
     */
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

    /**
     * @brief .previous 를 설치 경로로 되돌린다.
     * @param from_sha256 되돌릴 실행 파일의 해시. .previous 가 이것과 다르거나 없으면 되돌리지 않는다.
     * @details Windows 는 실행 중인 설치 파일을 .failed 로 옮긴 뒤 .previous 를 설치 경로로 옮긴다.
     */
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

    /** @brief .previous 를 .new 로 옮긴다. 운영자가 지시한 되돌리기의 첫 단계다. */
    pub(crate) fn stage_previous(&self, _lock: &UpdateLock) -> io::Result<()> {
        remove_if_present(&self.staged())?;
        std::fs::rename(self.previous(), self.staged())
    }

    /** @brief .new 를 .previous 로 돌려놓는다. 되돌리기가 사전 점검에서 멈췄을 때 쓴다. */
    pub(crate) fn unstage_previous(&self, _lock: &UpdateLock) -> io::Result<()> {
        std::fs::rename(self.staged(), self.previous())
    }

    /** @brief .new 를 지운다. */
    pub(crate) fn discard_staged(&self, _lock: &UpdateLock) {
        let staged = self.staged();
        if let Err(error) = remove_if_present(&staged) {
            onetdns_core::warn!(event = "update.staged_remove_failed", path = %staged.display(), %error, "Could not remove the staged executable; it is removed at the next start");
        }
    }
}

/** @brief 잠금을 쥐고 있다는 표시. 떨어뜨리면 파일을 닫아 잠금이 풀린다. */
pub(crate) struct UpdateLock {
    /** @brief 잠금을 건 파일. */
    _file: File,
}

#[derive(Debug)]
/** @brief 잠금을 잡지 못한 이유. */
pub(crate) enum LockError {
    /** @brief 다른 프로세스가 적용 중이거나 시험 실행 중이다. */
    Busy,
    /** @brief 이 프로세스는 설치 디렉터리에 쓸 수 없다. */
    Denied(io::Error),
    /** @brief 그 밖의 입출력 오류. */
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

/** @brief 권한 때문에 실패했는지. */
fn is_denied(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem
    )
}

#[cfg(unix)]
/** @brief 잠금 파일을 열고 flock 을 한 번 시도한다. 다른 프로세스가 쥐고 있으면 없다. */
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
/** @brief 공유를 허용하지 않고 연다. 다른 프로세스가 열어 두었으면 없다. */
fn try_lock(path: &Path) -> io::Result<Option<File>> {
    use std::os::windows::fs::OpenOptionsExt;

    /** @brief 다른 프로세스가 공유를 막고 열어 둔 파일. */
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

/** @brief 있으면 지운다. */
fn remove_if_present(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

#[cfg(unix)]
/** @brief 디렉터리 항목의 변경을 디스크에 내린다. 전원이 나가도 rename 이 사라지지 않게 한다. */
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/** @brief 파일의 SHA-256. */
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

/**
 * @brief 기록 핸들을 이 글로 덮어쓴다.
 * @details 권한을 내려놓은 뒤에도 쓸 수 있게 미리 열어 둔 핸들에 쓴다. 쓰는 도중 전원이 나가면
 *          기록이 깨지지만, 깨진 기록은 다음 시작이 오래된 기록으로 지우므로 실행 파일과 어긋나지
 *          않는다.
 */
pub(crate) fn overwrite(file: &mut File, text: &str) -> io::Result<()> {
    file.rewind()?;
    file.write_all(text.as_bytes())?;
    file.set_len(text.len() as u64)?;
    file.sync_all()
}

/** @brief 이전 실행 파일에서 새 파일로 옮길 속성. */
struct InstalledAttributes {
    #[cfg(unix)]
    /** @brief 소유자. */
    uid: u32,
    #[cfg(unix)]
    /** @brief 그룹. */
    gid: u32,
    #[cfg(unix)]
    /** @brief 권한 비트. */
    mode: u32,
}

impl InstalledAttributes {
    /** @brief 설치된 실행 파일의 속성을 읽고, 업데이트가 재현할 수 없는 속성이면 거절한다. */
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

    /** @brief 새 파일에 같은 소유자와 권한을 준다. 소유자를 맞추지 못하면 실패한다. */
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
/** @brief 파일 capability 확장 속성이 붙어 있는지. */
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
/** @brief 이름 규칙, 잠금, 실제로 실행 중인 파일의 맞바꾸기와 되돌리기. */
mod tests {
    use super::*;
    use crate::update::scratch::Scratch;

    #[test]
    /** @brief 옆 파일 이름이 계약대로인지. Windows 는 실행할 파일만 .exe 로 끝난다. */
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
    /** @brief 맞바꾼 뒤 지워진 실행 파일을 가리키는 경로는 설치 경로로 받지 않는지. */
    fn deleted_executable_paths_are_refused() {
        let deleted = Install::at(PathBuf::from("/usr/local/bin/OnetDNS (deleted)"));
        assert_eq!(deleted.is_err(), cfg!(target_os = "linux"));
        assert!(Install::at(PathBuf::from("OnetDNS")).is_err());
    }

    #[test]
    /** @brief 잠금은 한 번에 하나만 쥐고, 놓으면 다음이 잡는지. */
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

    #[test]
    /** @brief 기록 파일의 상한과 깨진 글. 둘 다 오래된 기록으로 다루도록 빈 글이 된다. */
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
    /** @brief 미리 연 핸들로 덮어쓰면 남은 꼬리 없이 새 글만 남는지. */
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

    /**
     * @brief 설치 경로에서 실제로 실행 중인 프로세스.
     * @details 맞바꾸기는 실행 중인 이미지를 대상으로 해야 의미가 있다. Windows 는 실행 중인 파일을
     *          지울 수 없고, Unix 는 실행 중인 파일에 쓸 수 없다.
     */
    struct Running(std::process::Child);

    impl Running {
        /** @brief 아직 실행 중인지. 끝났으면 맞바꾸기가 실행 중인 파일을 다룬 것이 아니다. */
        fn assert_alive(&mut self) {
            assert!(
                self.0.try_wait().expect("도우미 상태").is_none(),
                "설치 경로에서 띄운 도우미가 이미 끝났습니다"
            );
        }
    }

    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /** @brief 이 테스트 바이너리를 설치 경로에 복사해 오래 기다리는 테스트 하나만 돌린다. */
    fn run_copy_of_this_binary(install: &Install) -> Running {
        std::fs::copy(
            std::env::current_exe().expect("테스트 바이너리"),
            install.path(),
        )
        .expect("설치 경로에 복사");
        let child = std::process::Command::new(install.path())
            .args([
                "--ignored",
                "--exact",
                "update::install::tests::sleeps_while_a_test_swaps_its_executable",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("설치 경로의 실행");
        std::thread::sleep(Duration::from_millis(300));
        Running(child)
    }

    #[test]
    #[ignore = "다른 테스트가 실행 중인 실행 파일로 띄워 쓰는 도우미다"]
    /** @brief 맞바꾸기 테스트가 띄우는 실행 중인 프로세스 역할. */
    fn sleeps_while_a_test_swaps_its_executable() {
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    /**
     * @brief 실행 중인 실행 파일을 맞바꾸고 되돌리는지.
     * @details 맞바꾼 뒤 설치 경로는 새 파일이고 .previous 는 이전 파일이다. 되돌린 뒤에는 설치 경로가
     *          다시 이전 파일이다. .previous 가 바뀐 파일이면 되돌리지 않는다.
     */
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
    /** @brief 새 파일이 이전 파일의 권한 비트를 받고, setuid 가 붙은 설치는 거절하는지. */
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
