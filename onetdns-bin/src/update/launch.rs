//! Starting the swapped-in binary, which depends on how the server was started.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

#[cfg(unix)]
use super::install::Install;

/// Exit code that asks for the swapped-in binary. A supervisor parent execs the install path on it;
/// a Windows service reports it as its service-specific exit code, and the recovery action restarts
/// the service. Same value as EX_TEMPFAIL.
pub(crate) const UPDATE_EXIT_CODE: i32 = 75;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Launch {
    /// Child of the Linux supervisor; exits with UPDATE_EXIT_CODE and the parent execs the install
    /// path.
    SupervisedChild,
    /// Unix process without a supervisor; shuts down cleanly, then execs the install path.
    SingleProcess,
    /// Windows service; reports UPDATE_EXIT_CODE on stop, and the recovery action restarts it.
    #[cfg(windows)]
    WindowsService,
    /// The operator restarts: a Windows console, or a Windows service without a recovery action.
    Manual,
}

impl Launch {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Launch::SupervisedChild => "supervisor",
            Launch::SingleProcess => "exec",
            #[cfg(windows)]
            Launch::WindowsService => "service",
            Launch::Manual => "manual",
        }
    }
}

struct Server {
    stop: Arc<AtomicBool>,
    #[cfg(windows)]
    service: bool,
}

/// Absent in processes that are not servers, such as management commands.
static SERVER: OnceLock<Server> = OnceLock::new();
/// Set when the server stops to start the swapped-in binary.
static RESTART: AtomicBool = AtomicBool::new(false);

pub(crate) fn register(stop: Arc<AtomicBool>) {
    let _ = SERVER.set(Server {
        stop,
        #[cfg(windows)]
        service: false,
    });
}

#[cfg(windows)]
pub(crate) fn register_service(stop: Arc<AtomicBool>) {
    let _ = SERVER.set(Server {
        stop,
        service: true,
    });
}

/// A Windows service comes back only with a restart recovery action. The operator can change that,
/// so the service manager is asked on every call.
pub(crate) fn current() -> Launch {
    #[cfg(windows)]
    if SERVER.get().is_some_and(|server| server.service) {
        return if crate::service::restarts_on_failure() {
            Launch::WindowsService
        } else {
            Launch::Manual
        };
    }
    if super::install::supervised_child() {
        Launch::SupervisedChild
    } else if cfg!(unix) {
        Launch::SingleProcess
    } else {
        Launch::Manual
    }
}

/// Stops the server cleanly so it starts the installed binary. Call after the apply finishes.
///
/// False when the operator has to restart; the server keeps running then.
pub(crate) fn request_restart() -> bool {
    let Some(server) = SERVER.get() else {
        return false;
    };
    if current() == Launch::Manual {
        return false;
    }
    RESTART.store(true, Ordering::SeqCst);
    server.stop.store(true, Ordering::SeqCst);
    true
}

pub(crate) fn restart_requested() -> bool {
    RESTART.load(Ordering::SeqCst)
}

#[cfg(unix)]
/// Replaces this process with the installed binary, with the same arguments and argv[0]. The PID
/// stays, so the service manager sees no exit. Files and sockets are CLOEXEC, so locks and
/// listeners do not carry over.
///
/// Returns only when exec fails.
pub(crate) fn exec_installed(install: &Install) -> std::io::Error {
    use std::os::unix::process::CommandExt;

    let mut args = std::env::args_os();
    let argv0 = args
        .next()
        .unwrap_or_else(|| install.path().as_os_str().to_os_string());
    std::process::Command::new(install.path())
        .args(args)
        .arg0(argv0)
        .exec()
}

/// Starts the restored binary after a failed trial. A server that never got ready may never check
/// the stop flag, so this does not wait for a clean shutdown. A Windows console cannot start it, so
/// this asks for a restart and exits.
pub(crate) fn start_reverted() -> ! {
    #[cfg(windows)]
    if SERVER.get().is_some_and(|server| server.service) {
        crate::service::exit_for_update();
    }
    #[cfg(unix)]
    match super::install::current() {
        Ok(install) => {
            let error = exec_installed(install);
            onetdns_core::error!(event = "update.revert_exec_failed", path = %install.path().display(), %error, "Could not start the previous version after reverting the update; start OnetDNS again");
        }
        Err(reason) => {
            onetdns_core::error!(event = "update.revert_exec_failed", %reason, "Could not start the previous version after reverting the update; start OnetDNS again");
        }
    }
    #[cfg(not(unix))]
    onetdns_core::error!(
        event = "update.restart_needed",
        "Reverted the update; start OnetDNS again to run the previous version"
    );
    std::process::exit(1)
}

#[cfg(unix)]
/// Starts the swapped-in binary once the server has stopped after an apply. A supervised child
/// exits with the update code and leaves it to the parent. A single process execs it; if that
/// fails, it reverts the swap and execs the restored binary.
///
/// Returns only when neither could start, with the reason.
pub(crate) fn start_installed() -> String {
    if super::install::supervised_child() {
        std::process::exit(UPDATE_EXIT_CODE);
    }
    let install = match super::install::current() {
        Ok(install) => install,
        Err(reason) => return reason,
    };
    let error = exec_installed(install);
    onetdns_core::error!(event = "update.exec_failed", path = %install.path().display(), %error, "Could not start the new version; putting the previous executable back");
    if let Err(reason) =
        super::apply::undo_unstarted(&format!("Could not start the new version: {error}"))
    {
        return reason;
    }
    format!(
        "Could not start the previous version after putting it back at {}: {}",
        install.path().display(),
        exec_installed(install)
    )
}
