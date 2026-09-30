/*!
 * @brief 파일을 원자적으로 바꿔 쓰고, 여러 파일을 함께 바꿀 때 실패하면 되돌린다.
 */

use crate::{read_bytes_limited, LOCAL_CA_MAX_BYTES};

/** @brief 파일을 원자적으로 교체해 쓴다. 중간에 끊겨도 반쪽 파일이 남지 않는다. */
pub fn atomic_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    atomic_write_inner(path, data, false)
}

/** @brief 비밀 파일을 교체해 쓴다. 남이 읽지 못하게 권한을 좁힌다. */
pub fn atomic_write_secret(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    atomic_write_inner(path, data, true)
}

/** @brief 교체 쓰기의 실제 구현. */
fn atomic_write_inner(path: &std::path::Path, data: &[u8], secret: bool) -> std::io::Result<()> {
    use std::io::Write;
    atomic_write_with(path, secret, |file| file.write_all(data))
}

/** @brief 임시 파일에 쓰고 제 이름으로 옮긴다. */
pub(crate) fn atomic_write_with(
    path: &std::path::Path,
    secret: bool,
    write: impl FnOnce(&mut std::fs::File) -> std::io::Result<()>,
) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};

    /** @brief 임시 파일 이름이 겹치지 않게 하는 일련번호. */
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
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        if secret {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        #[cfg(windows)]
        if secret {
            harden_windows_secret_acl(&tmp)?;
        }
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
    let _ = secret;
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

#[cfg(windows)]
/** @brief 비밀 파일의 권한을 좁힌다. 좁히지 않으면 같은 기계의 다른 사용자가 키를 읽는다. */
pub(crate) fn harden_windows_secret_acl(path: &std::path::Path) -> std::io::Result<()> {
    use std::ffi::c_void;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null_mut, NonNull};

    /** @brief 권한 문자열 버전. */
    const SDDL_REVISION_1: u32 = 1;
    /** @brief 접근 목록만 바꾼다는 표시. */
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;

    #[link(name = "Advapi32")]
    extern "system" {
        /** @brief 권한 문자열을 구조체로. */
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string_security_descriptor: *const u16,
            string_sd_revision: u32,
            security_descriptor: *mut *mut c_void,
            security_descriptor_size: *mut u32,
        ) -> i32;
        /** @brief 파일 권한을 건다. */
        fn SetFileSecurityW(
            file_name: *const u16,
            security_information: u32,
            security_descriptor: *mut c_void,
        ) -> i32;
    }
    #[link(name = "Kernel32")]
    extern "system" {
        /** @brief 받은 메모리를 돌려준다. */
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
    }

    let sddl: Vec<u16> = std::ffi::OsStr::new("D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)")
        .encode_wide()
        .chain(once(0))
        .collect();
    let path_w: Vec<u16> = path.as_os_str().encode_wide().chain(once(0)).collect();
    let mut descriptor: *mut c_void = null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    };
    if converted == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let descriptor = NonNull::new(descriptor).ok_or_else(|| {
        std::io::Error::other("Could not convert the Windows security descriptor")
    })?;
    let applied = unsafe {
        SetFileSecurityW(
            path_w.as_ptr(),
            DACL_SECURITY_INFORMATION,
            descriptor.as_ptr(),
        )
    };
    unsafe {
        LocalFree(descriptor.as_ptr());
    }
    if applied == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
/** @brief 파일을 전부 교체한다. */
pub(crate) fn replace_file(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::rename(src, dst)
}

#[cfg(windows)]
/** @brief 파일을 전부 교체한다. 디스크에 닿은 뒤에 돌아온다. */
pub(crate) fn replace_file(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;

    /** @brief 이미 있어도 덮는다. */
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    /** @brief 디스크에 닿은 뒤에 돌아온다. */
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    #[link(name = "Kernel32")]
    extern "system" {
        /** @brief 파일을 옮긴다. */
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
/** @brief 백신·짧은 독점 열기와 겹친 파일 교체만 제한적으로 다시 시도한다. */
fn retry_windows_replace(mut replace: impl FnMut() -> std::io::Result<()>) -> std::io::Result<()> {
    /** @brief 첫 시도 뒤 허용할 재시도 수. 전체 대기는 최대 191 ms다. */
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
/** @brief 고치기 전 파일. 실패하면 되돌린다. */
pub(crate) struct FileBackup {
    /** @brief 고치기 전 내용. 없으면 파일이 없었다는 뜻이다. */
    data: Option<Vec<u8>>,
    /** @brief 비밀 파일이라 권한을 좁혀 되돌려야 하는지. */
    secret: bool,
}

impl FileBackup {
    /** @brief 지금 내용을 담아 둔다. */
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

    /** @brief 담아 둔 내용으로 되돌린다. */
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
/** @brief 바꾸기 전 인증서와 키. */
pub(crate) struct CertKeyBackup {
    /** @brief 바꾸기 전 인증서. */
    cert: FileBackup,
    /** @brief 바꾸기 전 키. */
    key: FileBackup,
}

/** @brief 인증서와 키를 되돌린다. 둘 중 하나만 바뀐 채로 두면 서빙이 전부 멈춘다. */
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

/** @brief 인증서와 키를 함께 바꾼다. */
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

/** @brief 되돌리기 결과까지 붙인 응답 문구. */
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
/** @brief 원자적 쓰기와 되돌리기. */
mod tests {
    use super::*;
    use crate::unix_now;

    #[test]
    /** @brief 쓰다 실패해도 앞 파일이 그대로 남고 임시 파일이 치워지는지. */
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
    /** @brief Windows의 짧은 공유 충돌만 다시 시도하고 다른 오류는 즉시 돌려주는지. */
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
