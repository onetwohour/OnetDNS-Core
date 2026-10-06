/*!
 * @brief 권한 내려놓기.
 *
 * @details 낮은 포트에 묶으려면 처음에 높은 권한이 필요하다. 다 묶은 뒤에는 그 권한을
 *          내려놓아야, 나중에 뚫려도 피해가 그만큼 작다.
 * @warning 순서가 중요하다. 보조 그룹, 그룹, 사용자 순으로 내려놓는다. 사용자를 먼저
 *          바꾸면 그룹을 바꿀 권한이 없어져 그룹만 그대로 남는다.
 * @note 필요한 능력만 남긴다. 낮은 포트 묶기와 네트워크 조작이 그것이고, 나머지는 버린다.
 */

use std::ffi::CString;

/** @brief 낮은 포트에 묶을 수 있는 능력. */
const CAP_NET_BIND_SERVICE: u32 = 10;
/** @brief 브로드캐스트를 보낼 수 있는 능력. */
const CAP_NET_BROADCAST: u32 = 11;
/** @brief 네트워크 설정을 바꿀 수 있는 능력. */
const CAP_NET_ADMIN: u32 = 12;
/** @brief 원시 소켓을 열 수 있는 능력. */
const CAP_NET_RAW: u32 = 13;

/** @brief 내려놓은 뒤에도 남길 능력들. 이것만 있으면 재시작 때 다시 묶을 수 있다. */
const RETAINED_CAPS: &[u32] = &[
    CAP_NET_BIND_SERVICE,
    CAP_NET_BROADCAST,
    CAP_NET_ADMIN,
    CAP_NET_RAW,
];

/** @brief 사용자를 바꿔도 능력을 유지하게 하는 요청. */
const PR_SET_KEEPCAPS: libc::c_int = 8;
/** @brief 덤프 가능 여부. 꺼 두면 비밀이 든 메모리가 파일로 새지 않는다. */
const PR_SET_DUMPABLE: libc::c_int = 4;
/** @brief 앞으로 권한이 오르지 못하게 잠근다. */
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
/** @brief 자식에게 물려줄 능력 조작. */
const PR_CAP_AMBIENT: libc::c_int = 47;
/** @brief 물려줄 능력 하나를 올린다. */
const PR_CAP_AMBIENT_RAISE: libc::c_ulong = 2;
/** @brief 능력 구조 버전. */
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/** @brief 마지막 시스템 오류를 읽을 수 있는 문자열로. */
fn last_err() -> String {
    std::io::Error::last_os_error().to_string()
}

/** @brief 사용자 이름을 번호로. */
fn resolve_uid(user: &str) -> Result<libc::uid_t, String> {
    if let Ok(n) = user.parse::<u32>() {
        return Ok(n);
    }
    let cname = CString::new(user).map_err(|_| "run_as_user contains NUL".to_string())?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return Err(format!("Could not look up run_as_user '{user}'"));
    }
    Ok(pwd.pw_uid)
}

/** @brief 그룹 이름을 번호로. */
fn resolve_gid(group: &str) -> Result<libc::gid_t, String> {
    if let Ok(n) = group.parse::<u32>() {
        return Ok(n);
    }
    let cname = CString::new(group).map_err(|_| "run_as_group contains NUL".to_string())?;
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result: *mut libc::group = std::ptr::null_mut();
    let rc = unsafe {
        libc::getgrnam_r(
            cname.as_ptr(),
            &mut grp,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return Err(format!("Could not look up run_as_group '{group}'"));
    }
    Ok(grp.gr_gid)
}

#[repr(C)]
/** @brief 능력 조작 요청의 헤더. */
struct CapHeader {
    /** @brief 이 구조체의 버전. */
    version: u32,
    /** @brief 권한을 바꿀 프로세스. 0이면 자기 자신. */
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
/** @brief 능력 비트들. */
struct CapData {
    /** @brief 지금 실제로 쓰는 권한. */
    effective: u32,
    /** @brief 쓸 수 있도록 허락된 권한. */
    permitted: u32,
    /** @brief 자식에게 물려줄 권한. */
    inheritable: u32,
}

/** @brief 남길 능력만 설정하고 나머지를 버린다. */
fn set_caps(caps: &[u32]) -> Result<(), String> {
    let header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    for &c in caps {
        let idx = (c >> 5) as usize;
        let bit = 1u32 << (c & 31);
        data[idx].effective |= bit;
        data[idx].permitted |= bit;
        data[idx].inheritable |= bit;
    }
    let rc = unsafe { libc::syscall(libc::SYS_capset, &header as *const CapHeader, data.as_ptr()) };
    if rc != 0 {
        return Err(format!("capset failed: {}", last_err()));
    }
    Ok(())
}

/**
 * @brief 프로세스에서 한 번만 내려간다.
 * @details 세대를 다시 시작해도 프로세스는 그대로라 두 번째 세대부터는 내려간 권한으로 돈다.
 * @return 이번에 내려가려 했으면 그 결과. 이미 한 번 시도했으면 없음.
 */
pub fn drop_privileges_once(user: &str, group: Option<&str>) -> Option<Result<(), String>> {
    /** @brief 권한 내려놓기를 한 번만 하게 한다. */
    static DROP_ONCE: std::sync::Once = std::sync::Once::new();
    let mut outcome = None;
    DROP_ONCE.call_once(|| {
        let result = drop_privileges(user, group);
        if result.is_ok() {
            onetdns_core::info!(
                event = "privdrop.applied",
                user,
                "Dropped user and group privileges and blocked further privilege gain"
            );
        }
        outcome = Some(result);
    });
    outcome
}

/**
 * @brief 지정한 사용자와 그룹으로 내려간다.
 *
 * @details 보조 그룹, 그룹, 사용자 순이다. 사용자를 먼저 바꾸면 그룹을 바꿀 권한이 없어져
 *          그룹만 높은 채로 남는다.
 * @warning 내려간 뒤 실제로 되돌아갈 수 없는지 확인한다. 확인하지 않으면 내려놓은 줄
 *          알았는데 그대로인 경우를 알아채지 못한다.
 */
pub fn drop_privileges(user: &str, group: Option<&str>) -> Result<(), String> {
    let uid = resolve_uid(user)?;
    if uid == 0 {
        return Err("run_as_user refers to UID 0 (root), which is not a lower privilege".into());
    }
    let gid = match group {
        Some(g) => resolve_gid(g)?,
        None => {
            if let Ok(n) = user.parse::<u32>() {
                n
            } else {
                let cname = CString::new(user)
                    .map_err(|_| "The user name to run as contains a NUL character".to_string())?;
                let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
                let mut buf = vec![0 as libc::c_char; 4096];
                let mut result: *mut libc::passwd = std::ptr::null_mut();
                let rc = unsafe {
                    libc::getpwnam_r(
                        cname.as_ptr(),
                        &mut pwd,
                        buf.as_mut_ptr(),
                        buf.len(),
                        &mut result,
                    )
                };
                if rc != 0 || result.is_null() {
                    return Err(format!("Could not find the primary group of user '{user}'"));
                }
                pwd.pw_gid
            }
        }
    };
    if gid == 0 {
        return Err("run_as_group refers to GID 0 (root), which is not a lower privilege".into());
    }

    let current_uid = unsafe { libc::geteuid() };
    let current_gid = unsafe { libc::getegid() };
    if current_uid != 0 {
        if current_uid != uid || current_gid != gid {
            return Err(format!(
                "No permission to switch from UID/GID {current_uid}/{current_gid} to UID/GID {uid}/{gid}"
            ));
        }

        set_caps(RETAINED_CAPS)?;
        for &capability in RETAINED_CAPS {
            let rc = unsafe {
                libc::prctl(
                    PR_CAP_AMBIENT,
                    PR_CAP_AMBIENT_RAISE,
                    capability as libc::c_ulong,
                    0,
                    0,
                )
            };
            if rc != 0 {
                return Err(format!(
                    "PR_CAP_AMBIENT_RAISE({capability}) failed: {}",
                    last_err()
                ));
            }
        }
        if unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(format!("PR_SET_NO_NEW_PRIVS failed: {}", last_err()));
        }
        if unsafe { libc::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(format!("PR_SET_DUMPABLE failed: {}", last_err()));
        }
        return Ok(());
    }

    if unsafe { libc::prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) } != 0 {
        return Err(format!("PR_SET_KEEPCAPS failed: {}", last_err()));
    }

    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        return Err(format!("setgroups failed: {}", last_err()));
    }
    if unsafe { libc::setgid(gid) } != 0 {
        return Err(format!("setgid({gid}) failed: {}", last_err()));
    }
    if unsafe { libc::setuid(uid) } != 0 {
        return Err(format!("setuid({uid}) failed: {}", last_err()));
    }

    if uid != 0 && unsafe { libc::setuid(0) } == 0 {
        return Err(
            "The process can still regain root after dropping privileges, which is unsafe".into(),
        );
    }

    set_caps(RETAINED_CAPS)?;

    if unsafe { libc::prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) } != 0 {
        return Err(format!("Could not clear PR_SET_KEEPCAPS: {}", last_err()));
    }

    for &c in RETAINED_CAPS {
        let rc = unsafe {
            libc::prctl(
                PR_CAP_AMBIENT,
                PR_CAP_AMBIENT_RAISE,
                c as libc::c_ulong,
                0,
                0,
            )
        };
        if rc != 0 {
            return Err(format!("PR_CAP_AMBIENT_RAISE({c}) failed: {}", last_err()));
        }
    }

    if unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(format!("PR_SET_NO_NEW_PRIVS failed: {}", last_err()));
    }

    if unsafe { libc::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(format!("PR_SET_DUMPABLE failed: {}", last_err()));
    }
    Ok(())
}

/**
 * @brief 권한을 낮춘 뒤에도 이 실행 파일을 다시 실행할 수 있는지 확인한다.
 *
 * @details 감독 프로세스는 자식이 죽으면 자기 실행 파일을 다시 실행해 살린다. 파일이
 *          root 만 실행할 수 있는 권한이거나 noexec 로 마운트된 곳에 있으면 낮춘 사용자는
 *          실행하지 못한다.
 * @return 실행할 수 있으면 Ok, 아니면 운영체제가 알려 준 사유.
 * @warning 여기서 확인하지 않으면 첫 자식이 죽는 순간에야 드러난다. 그때는 다시 띄울
 *          수단이 없어 서비스가 돌아오지 못한다.
 */
pub fn executable_still_runnable(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;

    let raw = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "The executable path contains a NUL character".to_string())?;
    if unsafe { libc::access(raw.as_ptr(), libc::X_OK) } == 0 {
        return Ok(());
    }
    Err(last_err())
}
