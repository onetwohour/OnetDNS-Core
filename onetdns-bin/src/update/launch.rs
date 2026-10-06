/*!
 * @brief 맞바꾼 실행 파일을 띄우는 방법. 서버를 어떻게 띄웠는지에 따라 다르다.
 */

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

#[cfg(unix)]
use super::install::Install;

/**
 * @brief 맞바꾼 실행 파일을 띄워 달라는 종료 코드.
 * @details 감독받는 자식이 이 코드로 끝나면 부모가 설치 경로를 exec 한다. Windows 서비스는 이 값을
 *          서비스 고유 종료 코드로 보고하고, 서비스 관리자의 복구 동작이 서비스를 다시 띄운다.
 *          sysexits 의 EX_TEMPFAIL 과 같은 값이다.
 */
pub(crate) const UPDATE_EXIT_CODE: i32 = 75;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 이 서버가 맞바꾼 실행 파일을 띄우는 방법. */
pub(crate) enum Launch {
    /** @brief Linux 감독자의 자식. UPDATE_EXIT_CODE 로 끝나면 부모가 설치 경로를 exec 한다. */
    SupervisedChild,
    /** @brief 감독자 없이 도는 Unix 프로세스. 정상 종료한 뒤 설치 경로를 exec 한다. */
    SingleProcess,
    /** @brief Windows 서비스. UPDATE_EXIT_CODE 를 보고하고 멈추면 복구 동작이 다시 띄운다. */
    #[cfg(windows)]
    WindowsService,
    /** @brief 운영자가 다시 시작한다. Windows 콘솔과, 복구 동작이 걸리지 않은 Windows 서비스다. */
    Manual,
}

impl Launch {
    /** @brief 상태 응답에 쓰는 이름. */
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

/** @brief 서버로 도는 프로세스가 등록한 것. */
struct Server {
    /** @brief 서버를 정상 종료시키는 플래그. */
    stop: Arc<AtomicBool>,
    /** @brief Windows 서비스로 도는지. */
    #[cfg(windows)]
    service: bool,
}

/** @brief 이 프로세스의 서버. 관리 명령처럼 서버가 아닌 프로세스에는 없다. */
static SERVER: OnceLock<Server> = OnceLock::new();
/** @brief 맞바꾼 실행 파일을 띄우려고 서버를 멈췄는지. */
static RESTART: AtomicBool = AtomicBool::new(false);

/** @brief 서버를 띄우는 진입점이 정지 플래그를 등록한다. */
pub(crate) fn register(stop: Arc<AtomicBool>) {
    let _ = SERVER.set(Server {
        stop,
        #[cfg(windows)]
        service: false,
    });
}

#[cfg(windows)]
/** @brief Windows 서비스 진입점이 정지 플래그를 등록한다. */
pub(crate) fn register_service(stop: Arc<AtomicBool>) {
    let _ = SERVER.set(Server {
        stop,
        service: true,
    });
}

/**
 * @brief 이 서버가 맞바꾼 실행 파일을 띄우는 방법.
 * @details Windows 서비스는 다시 시작하는 복구 동작이 걸려 있어야 다시 뜬다. 운영자가 서비스
 *          설정을 바꿀 수 있으므로 물을 때마다 서비스 관리자에게 확인한다.
 */
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

/**
 * @brief 서버를 정상 종료시키고 설치 경로의 실행 파일을 띄우게 한다. 적용을 마친 뒤에 부른다.
 * @return 운영자가 다시 시작해야 하면 거짓이고, 서버는 그대로 돈다.
 */
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

/** @brief 서버가 멈춘 것이 맞바꾼 실행 파일을 띄우기 위해서인지. */
pub(crate) fn restart_requested() -> bool {
    RESTART.load(Ordering::SeqCst)
}

#[cfg(unix)]
/**
 * @brief 이 프로세스를 설치 경로의 실행 파일로 바꾼다. 인수와 argv[0] 은 그대로 넘긴다.
 * @details PID 가 그대로라 서비스 관리자는 프로세스가 바뀐 것을 알아채지 않는다. 열린 파일과 소켓은
 *          CLOEXEC 이므로 잠금과 수신 소켓도 새 이미지로 넘어가지 않는다.
 * @return 돌아오면 exec 가 실패한 것이고 그 이유다.
 */
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

/**
 * @brief 시험에 실패해 되돌린 직후 되돌린 실행 파일을 띄운다.
 * @details 준비에 이르지 못한 서버는 정지 플래그를 보는 곳까지 오지 못했을 수 있으므로 정상 종료를
 *          기다리지 않는다. Windows 콘솔은 띄울 방법이 없어 다시 시작하라고 알리고 끝낸다.
 */
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
/**
 * @brief 적용을 마치고 멈춘 서버에서 맞바꾼 실행 파일을 띄운다.
 * @details 감독받는 자식은 업데이트 종료 코드로 끝나 부모에게 맡긴다. 단독 프로세스는 exec 하고,
 *          exec 가 실패하면 맞바꾸기를 되돌린 뒤 되돌린 실행 파일을 exec 한다.
 * @return 돌아오면 어느 실행 파일도 띄우지 못한 것이고 그 이유다.
 */
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
