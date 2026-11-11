//! Atomic file replacement, and rollback when one of several files fails to change.

use crate::{read_bytes_limited, LOCAL_CA_MAX_BYTES};

/// Replaces `path` so that a crash never leaves a half-written file. An existing file keeps
/// its Unix mode or Windows ACL.
pub fn atomic_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    atomic_write_inner(path, data, false)
}

/// Like [`atomic_write`], but only the owner can read the result.
pub fn atomic_write_secret(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    atomic_write_inner(path, data, true)
}

fn atomic_write_inner(path: &std::path::Path, data: &[u8], secret: bool) -> std::io::Result<()> {
    use std::io::Write;
    atomic_write_with(path, secret, |file| file.write_all(data))
}

/// Writes a temporary file next to `path` and renames it over `path`.
pub(crate) fn atomic_write_with(
    path: &std::path::Path,
    secret: bool,
    write: impl FnOnce(&mut std::fs::File) -> std::io::Result<()>,
) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let fname = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("onetdns");
    let nonce = u64::from_le_bytes(onetdns_core::rng::try_random_array::<8>()?);
    let tmp_name = format!(
        ".{fname}.tmp.{}.{}.{nonce:016x}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let tmp = match dir {
        Some(d) => d.join(&tmp_name),
        None => std::path::PathBuf::from(&tmp_name),
    };

    let write_result = (|| -> std::io::Result<()> {
        let mut f = open_temporary(&tmp, path, secret)?;
        write(&mut f)?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let target_mode = std::fs::metadata(path)
            .ok()
            .map(|m| m.permissions().mode() & 0o7777);
        let mode = if secret { Some(0o600) } else { target_mode };
        if let Some(mode) = mode {
            if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)) {
                let _ = std::fs::remove_file(&tmp);
                return Err(e);
            }
        }
    }
    if let Err(e) = replace_file(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    #[cfg(unix)]
    if let Some(directory) = dir {
        std::fs::File::open(directory)?.sync_all()?;
    }
    Ok(())
}

/// Creates the replacement for `target` with its final ACL: the rename gives `target` this
/// file's ACL, and restricting it afterwards would let another account open it first.
fn open_temporary(
    tmp: &std::path::Path,
    target: &std::path::Path,
    secret: bool,
) -> std::io::Result<std::fs::File> {
    if secret {
        return onetdns_core::fs::create_private_replacing(tmp, target);
    }
    #[cfg(windows)]
    {
        onetdns_core::fs::create_new_like(tmp, target)
    }
    #[cfg(not(windows))]
    {
        let _ = target;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(tmp)
    }
}

#[cfg(windows)]
pub(crate) use onetdns_core::fs::restrict_to_owner as harden_windows_secret_acl;

#[cfg(not(windows))]
pub(crate) fn replace_file(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::rename(src, dst)
}

#[cfg(windows)]
/// Returns once the rename has reached the disk.
pub(crate) fn replace_file(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
    }

    let src_w: Vec<u16> = src.as_os_str().encode_wide().chain(once(0)).collect();
    let dst_w: Vec<u16> = dst.as_os_str().encode_wide().chain(once(0)).collect();
    retry_windows_replace(|| {
        let ok = unsafe {
            MoveFileExW(
                src_w.as_ptr(),
                dst_w.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    })
}

#[cfg(windows)]
/// Retries a replace that collided with an antivirus scan or another short exclusive open.
fn retry_windows_replace(mut replace: impl FnMut() -> std::io::Result<()>) -> std::io::Result<()> {
    // Waits at most 191 ms in total.
    const RETRIES: u32 = 8;
    for attempt in 0..=RETRIES {
        match replace() {
            Ok(()) => return Ok(()),
            Err(error)
                if attempt < RETRIES && matches!(error.raw_os_error(), Some(5 | 32 | 33)) =>
            {
                std::thread::sleep(std::time::Duration::from_millis(1u64 << attempt.min(6)));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("The Windows file replace retry loop always returns")
}

#[derive(Clone)]
/// A file as it was before a change, to put back if the change fails.
pub(crate) struct FileBackup {
    /// `None` when the file did not exist.
    data: Option<Vec<u8>>,
    secret: bool,
}

impl FileBackup {
    pub(crate) fn capture(path: &std::path::Path, secret: bool) -> std::io::Result<Self> {
        match read_bytes_limited(path, LOCAL_CA_MAX_BYTES) {
            Ok(data) => Ok(Self {
                data: Some(data),
                secret,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self { data: None, secret }),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn restore(&self, path: &std::path::Path) -> std::io::Result<()> {
        match &self.data {
            Some(data) if self.secret => atomic_write_secret(path, data),
            Some(data) => atomic_write(path, data),
            None => match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            },
        }
    }
}

#[derive(Clone)]
pub(crate) struct CertKeyBackup {
    cert: FileBackup,
    key: FileBackup,
}

/// Restores both files. Serving stops if only one of them is left changed.
pub(crate) fn rollback_cert_key(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    backup: &CertKeyBackup,
) -> std::io::Result<()> {
    let key_result = backup.key.restore(key_path);
    let cert_result = backup.cert.restore(cert_path);
    match (key_result, cert_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(key_err), Ok(())) => Err(key_err),
        (Ok(()), Err(cert_err)) => Err(cert_err),
        (Err(key_err), Err(cert_err)) => Err(std::io::Error::new(
            key_err.kind(),
            format!("Could not restore both the private key and the certificate file: key={key_err}; certificate={cert_err}"),
        )),
    }
}

/// Replaces the certificate and key together, restoring both if either write fails.
pub(crate) fn commit_cert_key(
    cert_path: &std::path::Path,
    cert_data: &[u8],
    key_path: &std::path::Path,
    key_data: &[u8],
) -> std::io::Result<CertKeyBackup> {
    if cert_path == key_path {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "The certificate and private key must be saved to different file paths",
        ));
    }
    let backup = CertKeyBackup {
        cert: FileBackup::capture(cert_path, false)?,
        key: FileBackup::capture(key_path, true)?,
    };
    if let Err(e) = atomic_write(cert_path, cert_data) {
        if let Err(rollback_err) = rollback_cert_key(cert_path, key_path, &backup) {
            return Err(std::io::Error::new(
                e.kind(),
                format!("Could not save the certificate file, and restoring the previous file also failed: save error={e}; restore error={rollback_err}"),
            ));
        }
        return Err(e);
    }
    if let Err(e) = atomic_write_secret(key_path, key_data) {
        if let Err(rollback_err) = rollback_cert_key(cert_path, key_path, &backup) {
            return Err(std::io::Error::new(
                e.kind(),
                format!("Could not save the private key file, and restoring the previous file also failed: save error={e}; restore error={rollback_err}"),
            ));
        }
        return Err(e);
    }
    Ok(backup)
}

/// Appends a failed rollback to a response message.
pub(crate) fn with_rollback_result(
    primary: String,
    operation: &str,
    result: Result<(), String>,
) -> String {
    match result {
        Ok(()) => primary,
        Err(rollback_error) => format!("{primary}; reverting to the previous configuration also failed: {operation}: {rollback_error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unix_now;

    #[test]
    fn failed_streaming_atomic_write_keeps_previous_file_and_removes_temporary() {
        use std::io::Write as _;

        let path = std::env::temp_dir().join(format!(
            "onetdns-atomic-stream-failure-{}-{}.bin",
            std::process::id(),
            unix_now()
        ));
        atomic_write(&path, b"previous").unwrap();
        let result = atomic_write_with(&path, false, |file| {
            file.write_all(b"partial")?;
            Err(std::io::Error::other("injected streaming failure"))
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"previous");

        let temporary_prefix = format!(
            ".{}.tmp.",
            path.file_name().and_then(|name| name.to_str()).unwrap()
        );
        let leaked = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&temporary_prefix)
            });
        assert!(!leaked, "실패한 스트리밍 임시 파일이 남으면 안 됩니다");
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn rewriting_a_private_file_keeps_its_acl_on_windows() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-atomic-acl-{}-{}.toml",
            std::process::id(),
            unix_now()
        ));
        atomic_write_secret(&path, b"control_token = \"a\"\n").unwrap();
        let private = onetdns_core::fs::access_rules(&path).unwrap();
        assert_eq!(private, onetdns_core::fs::private_rules(&path).unwrap());

        atomic_write(&path, b"control_token = \"b\"\n").unwrap();

        let rules = onetdns_core::fs::access_rules(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(rules, private);
    }

    #[cfg(windows)]
    #[test]
    fn windows_atomic_replace_retries_only_transient_file_conflicts() {
        for raw_error in [5, 32, 33] {
            let mut attempts = 0;
            retry_windows_replace(|| {
                attempts += 1;
                if attempts < 3 {
                    Err(std::io::Error::from_raw_os_error(raw_error))
                } else {
                    Ok(())
                }
            })
            .unwrap();
            assert_eq!(attempts, 3);
        }

        let mut exhausted_attempts = 0;
        let error = retry_windows_replace(|| {
            exhausted_attempts += 1;
            Err(std::io::Error::from_raw_os_error(32))
        })
        .unwrap_err();
        assert_eq!(exhausted_attempts, 9);
        assert_eq!(error.raw_os_error(), Some(32));

        let mut permanent_attempts = 0;
        let error = retry_windows_replace(|| {
            permanent_attempts += 1;
            Err(std::io::Error::from_raw_os_error(87))
        })
        .unwrap_err();
        assert_eq!(permanent_attempts, 1);
        assert_eq!(error.raw_os_error(), Some(87));
    }
}
