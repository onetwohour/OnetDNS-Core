//! Drops to the configured user and group before any other thread starts, keeping only the
//! capabilities for low ports and network administration.
//!
//! Capabilities and no_new_privs are per thread: libc applies setgid and setuid to every thread,
//! but keepcaps, capset, and no_new_privs only to the caller. A thread started earlier would lose
//! every capability without being locked; only threads started afterwards inherit the caller's
//! state.
//!
//! Order matters: supplementary groups, group, then user. Changing the user first removes the right
//! to change groups, and the group stays.

use std::ffi::CString;
use std::sync::OnceLock;

const CAP_NET_BIND_SERVICE: u32 = 10;
const CAP_NET_BROADCAST: u32 = 11;
const CAP_NET_ADMIN: u32 = 12;
const CAP_NET_RAW: u32 = 13;

/// Kept after the drop so listeners can be bound again on restart.
const RETAINED_CAPS: &[u32] = &[
    CAP_NET_BIND_SERVICE,
    CAP_NET_BROADCAST,
    CAP_NET_ADMIN,
    CAP_NET_RAW,
];

const PR_SET_KEEPCAPS: libc::c_int = 8;
/// Cleared so memory holding secrets never reaches a core dump.
const PR_SET_DUMPABLE: libc::c_int = 4;
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_RAISE: libc::c_ulong = 2;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// Later generations only check that they run as the same user and group: every thread started
/// after the drop inherits its state, and the kernel cannot tell which threads predate it.
static DROPPED_TO: OnceLock<(libc::uid_t, libc::gid_t)> = OnceLock::new();

fn last_err() -> String {
    std::io::Error::last_os_error().to_string()
}

/// Fails when unreadable; dropping without knowing the process is single-threaded is not safe.
fn running_threads() -> Result<usize, String> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("Could not read /proc/self/status to count threads: {error}"))?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .and_then(|count| count.trim().parse().ok())
        .ok_or_else(|| "/proc/self/status does not report the number of threads".to_string())
}

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
struct CapHeader {
    version: u32,
    /// 0 for the calling thread.
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

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

/// Drops on the first call; later calls only check for the same user and group and fail otherwise.
///
/// The first call fails without dropping while other threads run, since dropping would leave them
/// without capabilities or the lock. Adding or changing run_as_user therefore needs a service
/// restart.
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

    if let Some(&(dropped_uid, dropped_gid)) = DROPPED_TO.get() {
        if (dropped_uid, dropped_gid) == (uid, gid) {
            return Ok(());
        }
        return Err(format!(
            "This process already runs as UID/GID {dropped_uid}/{dropped_gid}; restart the service to run as UID/GID {uid}/{gid}"
        ));
    }
    let threads = running_threads()?;
    if threads != 1 {
        return Err(format!(
            "Cannot drop privileges while {threads} threads are running, because each thread keeps its own capabilities; restart the service so that it drops them before starting other threads"
        ));
    }
    switch_identity(uid, gid)?;
    let _ = DROPPED_TO.set((uid, gid));
    Ok(())
}

/// Drops a single-threaded process to the user and group and locks it. Already running as them, it
/// only sets the kept capabilities and the lock; running as another ordinary user, it fails for
/// lack of permission.
///
/// After the drop it checks that going back is impossible; otherwise a drop that did not take would
/// go unnoticed.
fn switch_identity(uid: libc::uid_t, gid: libc::gid_t) -> Result<(), String> {
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

/// The supervisor re-executes its own binary when a child dies. A root-only executable or a noexec
/// mount stops the dropped user from running it.
///
/// Returns the OS error when it cannot run. Unchecked, this would surface only when the first child
/// dies, with nothing left to restart it.
pub fn executable_still_runnable(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;

    let raw = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "The executable path contains a NUL character".to_string())?;
    if unsafe { libc::access(raw.as_ptr(), libc::X_OK) } == 0 {
        return Ok(());
    }
    Err(last_err())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// The check fails before dropping, so the test process keeps its privileges. Run as root, it
    /// picks a non-zero user and group, since 0 is rejected before threads are counted.
    fn refuses_to_drop_while_other_threads_run() {
        let (stop, stopped) = std::sync::mpsc::channel::<()>();
        let other = std::thread::spawn(move || {
            let _ = stopped.recv();
        });
        let uid = match unsafe { libc::getuid() } {
            0 => 65534,
            uid => uid,
        };
        let gid = match unsafe { libc::getgid() } {
            0 => 65534,
            gid => gid,
        };
        let result = drop_privileges(&uid.to_string(), Some(&gid.to_string()));
        stop.send(()).expect("스레드에 멈추라고 알림");
        other.join().expect("스레드 종료");
        let error = result.expect_err("다른 스레드가 도는데 권한을 내려놓았다");
        assert!(
            error.contains("threads are running"),
            "스레드와 무관한 이유로 실패했다: {error}"
        );
    }
}
