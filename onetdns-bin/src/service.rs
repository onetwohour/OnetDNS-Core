/*!
 * @brief Windows 서비스 등록과 실행.
 *
 * @details 부팅 때 자동으로 뜨게 하려면 서비스로 등록해야 한다. 서비스 제어 관리자와
 *          주고받는 프로토콜은 외부 크레이트 없이 직접 묶었다.
 * @warning 서비스 제어 관리자는 명령줄 한 줄을 받아 다시 쪼갠다. 인수를 규칙대로 감싸지
 *          않으면 경로에 든 공백만으로 엉뚱한 것이 실행 파일로 읽힌다.
 */

use std::ffi::{c_void, OsStr, OsString};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use crate::error::BoxResult;
use onetdns_config::Config;

/** @brief 등록할 서비스 이름. */
const SERVICE_NAME: &str = "OnetDNS";
/** @brief 목록에 보일 이름. */
const SERVICE_DISPLAY: &str = "OnetDNS ad-blocking DNS";

/** @brief 서비스로 뜰 때 쓸 설정 경로. 진입점이 인수를 받지 못해 여기 둔다. */
static CONFIG_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
/** @brief 정지 요청을 서비스 반복에 전하는 플래그. */
static STOP_FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
/** @brief 상태 보고 핸들. 시험 기한을 재는 스레드도 정지를 보고하므로 여기 둔다. */
static STATUS: OnceLock<StatusHandle> = OnceLock::new();

/**
 * @brief 서비스가 실패했을 때 다시 시작하기까지 기다리는 밀리초. 실패할 때마다 다음 값으로 넘어간다.
 * @details 업데이트를 마치고 업데이트 종료 코드로 멈춘 서비스도 첫 값만큼 기다렸다가 다시 뜬다.
 */
const RECOVERY_DELAYS_MS: [u32; 3] = [1_000, 5_000, 30_000];
/** @brief 이만큼(초) 실패가 없으면 실패 횟수를 0 으로 되돌린다. 하루다. */
const RECOVERY_RESET_SECONDS: u32 = 86_400;

#[allow(non_snake_case)]
/** @brief 서비스 제어 관리자 프로토콜. */
mod win32 {
    use super::c_void;

    /** @brief 서비스 제어 관리자 핸들. */
    pub type ScHandle = isize;
    /** @brief 상태 보고용 핸들. */
    pub type ServiceStatusHandle = isize;

    /** @brief 관리자에 붙을 권한. */
    pub const SC_MANAGER_CONNECT: u32 = 0x0001;
    /** @brief 서비스를 만들 권한. */
    pub const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;
    /** @brief 지울 권한. */
    pub const DELETE: u32 = 0x0001_0000;
    /** @brief 설정을 바꿀 권한. */
    pub const SERVICE_CHANGE_CONFIG: u32 = 0x0002;
    /** @brief 상태를 물을 권한. */
    pub const SERVICE_QUERY_STATUS: u32 = 0x0004;
    /** @brief 정지시킬 권한. */
    pub const SERVICE_STOP: u32 = 0x0020;
    /** @brief 설정을 물을 권한. */
    pub const SERVICE_QUERY_CONFIG: u32 = 0x0001;
    /** @brief 시작시킬 권한. 복구 동작에 다시 시작을 걸려면 이 권한으로 연 핸들이어야 한다. */
    pub const SERVICE_START: u32 = 0x0010;
    /** @brief 실패했을 때의 복구 동작 설정. */
    pub const SERVICE_CONFIG_FAILURE_ACTIONS: u32 = 2;
    /** @brief 충돌이 아닌 실패에도 복구 동작을 적용할지 정하는 설정. */
    pub const SERVICE_CONFIG_FAILURE_ACTIONS_FLAG: u32 = 4;
    /** @brief 복구 동작 가운데 서비스를 다시 시작하는 것. */
    pub const SC_ACTION_RESTART: u32 = 1;
    /** @brief 버퍼가 작다. 필요한 크기를 함께 알려 준다. */
    pub const ERROR_INSUFFICIENT_BUFFER: i32 = 122;

    /** @brief 프로세스 하나를 전부 쓰는 서비스. */
    pub const SERVICE_WIN32_OWN_PROCESS: u32 = 0x0010;
    /** @brief 부팅 때 자동으로 뜬다. */
    pub const SERVICE_AUTO_START: u32 = 0x0002;
    /** @brief 시작 실패를 기록만 하고 부팅은 계속한다. */
    pub const SERVICE_ERROR_NORMAL: u32 = 0x0001;
    /** @brief 멈춰 있음. */
    pub const SERVICE_STOPPED: u32 = 0x0001;
    /** @brief 뜨는 중. */
    pub const SERVICE_START_PENDING: u32 = 0x0002;
    /** @brief 돌고 있음. */
    pub const SERVICE_RUNNING: u32 = 0x0004;
    /** @brief 정지 요청을 받는다. */
    pub const SERVICE_ACCEPT_STOP: u32 = 0x0001;
    /** @brief 정지 요청. */
    pub const SERVICE_CONTROL_STOP: u32 = 0x0001;
    /** @brief 상태 확인 요청. */
    pub const SERVICE_CONTROL_INTERROGATE: u32 = 0x0004;
    /** @brief 권한이 모자라다. 관리자 콘솔이 아니면 이것이 온다. */
    pub const ERROR_ACCESS_DENIED: i32 = 5;
    /** @brief 그런 이름의 서비스가 없다. 등록 여부 판정에 쓴다. */
    pub const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
    /** @brief 같은 이름이 이미 있다. */
    pub const ERROR_SERVICE_EXISTS: i32 = 1073;
    /** @brief 다루지 않는 요청에 돌려줄 값. */
    pub const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
    /** @brief 서비스 고유 오류가 있음을 알리는 값. */
    pub const ERROR_SERVICE_SPECIFIC_ERROR: u32 = 1066;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    /** @brief 관리자에 보고할 상태. */
    pub struct ServiceStatus {
        /** @brief 서비스 종류. */
        pub dwServiceType: u32,
        /** @brief 지금 상태. */
        pub dwCurrentState: u32,
        /** @brief 받아들이는 제어 요청. */
        pub dwControlsAccepted: u32,
        /** @brief 종료 코드. */
        pub dwWin32ExitCode: u32,
        /** @brief 서비스 고유 종료 코드. */
        pub dwServiceSpecificExitCode: u32,
        /** @brief 시작 진행 단계. 늘려 가며 보고한다. */
        pub dwCheckPoint: u32,
        /** @brief 다음 보고까지 걸릴 예상 시간. */
        pub dwWaitHint: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    /** @brief 복구 동작 하나. */
    pub struct ScAction {
        /** @brief 동작 종류. */
        pub Type: u32,
        /** @brief 동작하기 전에 기다릴 밀리초. */
        pub Delay: u32,
    }

    #[repr(C)]
    /** @brief 복구 동작 목록. 실패할 때마다 다음 동작으로 넘어간다. */
    pub struct ServiceFailureActionsW {
        /** @brief 이만큼(초) 실패가 없으면 실패 횟수를 0 으로 되돌린다. */
        pub dwResetPeriod: u32,
        /** @brief 재부팅할 때 보낼 메시지. 널이면 바꾸지 않는다. */
        pub lpRebootMsg: *mut u16,
        /** @brief 실행할 명령. 널이면 바꾸지 않는다. */
        pub lpCommand: *mut u16,
        /** @brief 동작 수. */
        pub cActions: u32,
        /** @brief 동작 배열. */
        pub lpsaActions: *mut ScAction,
    }

    #[repr(C)]
    /** @brief 충돌이 아닌 실패에도 복구 동작을 적용할지. */
    pub struct ServiceFailureActionsFlag {
        /** @brief 0 이 아니면 적용한다. */
        pub fFailureActionsOnNonCrashFailures: i32,
    }

    /** @brief 서비스 진입점. */
    pub type ServiceMainProc = Option<extern "system" fn(u32, *mut *mut u16)>;
    /** @brief 제어 요청 핸들러. */
    pub type HandlerExProc = Option<extern "system" fn(u32, u32, *mut c_void, *mut c_void) -> u32>;

    #[repr(C)]
    /** @brief 이름과 진입점을 잇는 테이블의 한 줄. */
    pub struct ServiceTableEntryW {
        /** @brief 서비스 이름. */
        pub lpServiceName: *mut u16,
        /** @brief 그 서비스의 진입점. */
        pub lpServiceProc: ServiceMainProc,
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        /** @brief 서비스 제어 관리자에 붙는다. */
        pub fn OpenSCManagerW(
            machine_name: *const u16,
            database_name: *const u16,
            desired_access: u32,
        ) -> ScHandle;
        /** @brief 서비스를 만든다. */
        pub fn CreateServiceW(
            manager: ScHandle,
            service_name: *const u16,
            display_name: *const u16,
            desired_access: u32,
            service_type: u32,
            start_type: u32,
            error_control: u32,
            binary_path_name: *const u16,
            load_order_group: *const u16,
            tag_id: *mut u32,
            dependencies: *const u16,
            service_start_name: *const u16,
            password: *const u16,
        ) -> ScHandle;
        /** @brief 이미 있는 서비스를 연다. */
        pub fn OpenServiceW(
            manager: ScHandle,
            service_name: *const u16,
            desired_access: u32,
        ) -> ScHandle;
        /** @brief 서비스 상태를 묻는다. */
        pub fn QueryServiceStatus(service: ScHandle, status: *mut ServiceStatus) -> i32;
        /** @brief 서비스에 제어 요청을 보낸다. */
        pub fn ControlService(service: ScHandle, control: u32, status: *mut ServiceStatus) -> i32;
        /** @brief 서비스를 지운다. */
        pub fn DeleteService(service: ScHandle) -> i32;
        /** @brief 서비스의 추가 설정을 바꾼다. */
        pub fn ChangeServiceConfig2W(service: ScHandle, info_level: u32, info: *mut c_void) -> i32;
        /** @brief 서비스의 추가 설정을 읽는다. */
        pub fn QueryServiceConfig2W(
            service: ScHandle,
            info_level: u32,
            buffer: *mut u8,
            buffer_size: u32,
            bytes_needed: *mut u32,
        ) -> i32;
        /** @brief 핸들을 닫는다. */
        pub fn CloseServiceHandle(handle: ScHandle) -> i32;
        /** @brief 관리자와 이어 서비스 진입점을 넘긴다. */
        pub fn StartServiceCtrlDispatcherW(table: *const ServiceTableEntryW) -> i32;
        /** @brief 제어 요청 핸들러를 등록한다. */
        pub fn RegisterServiceCtrlHandlerExW(
            service_name: *const u16,
            handler: HandlerExProc,
            context: *mut c_void,
        ) -> ServiceStatusHandle;
        /** @brief 상태를 보고한다. */
        pub fn SetServiceStatus(
            status_handle: ServiceStatusHandle,
            status: *const ServiceStatus,
        ) -> i32;
    }
}

/** @brief 사라질 때 스스로 닫히는 핸들. */
struct ScHandle(win32::ScHandle);

impl ScHandle {
    /** @brief 핸들을 감싼다. 0이면 실패다. */
    fn new(raw: win32::ScHandle) -> io::Result<Self> {
        if raw == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(raw))
        }
    }
}

impl Drop for ScHandle {
    /** @brief 핸들을 닫는다. */
    fn drop(&mut self) {
        unsafe {
            win32::CloseServiceHandle(self.0);
        }
    }
}

#[derive(Clone, Copy)]
/** @brief 상태 보고용 핸들. */
struct StatusHandle(win32::ServiceStatusHandle);

impl StatusHandle {
    /** @brief 제어 요청 핸들러를 등록하고 핸들을 받는다. */
    fn register() -> io::Result<Self> {
        let name = wide_nul(OsStr::new(SERVICE_NAME))?;
        let raw = unsafe {
            win32::RegisterServiceCtrlHandlerExW(
                name.as_ptr(),
                Some(service_control_handler),
                ptr::null_mut(),
            )
        };
        if raw == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(raw))
        }
    }

    /**
     * @brief 지금 상태를 관리자에 보고한다.
     * @note 뜨는 중에도 주기적으로 보고해야 한다. 끊기면 관리자가 죽은 것으로 보고
     *       시작을 중단시킨다.
     */
    fn report(
        self,
        state: u32,
        accepted: u32,
        service_error: Option<u32>,
        checkpoint: u32,
        wait_hint_ms: u32,
    ) -> io::Result<()> {
        let status = win32::ServiceStatus {
            dwServiceType: win32::SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: accepted,
            dwWin32ExitCode: service_error
                .map(|_| win32::ERROR_SERVICE_SPECIFIC_ERROR)
                .unwrap_or(0),
            dwServiceSpecificExitCode: service_error.unwrap_or(0),
            dwCheckPoint: checkpoint,
            dwWaitHint: wait_hint_ms,
        };
        bool_result(unsafe { win32::SetServiceStatus(self.0, &status) })
    }
}

/** @brief 참거짓으로 오는 결과를 마지막 오류와 함께 돌려준다. */
fn bool_result(value: i32) -> io::Result<()> {
    if value == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/** @brief 문자열을 넓은 문자로 바꾸고 끝을 표시한다. 중간에 끝 표시가 있으면 거부한다. */
fn wide_nul(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = value.encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows service strings cannot contain NUL characters",
        ));
    }
    wide.push(0);
    Ok(wide)
}

/**
 * @brief 인수 하나를 명령줄 규칙대로 감싼다.
 * @warning 관리자는 한 줄을 받아 다시 쪼갠다. 공백이나 따옴표가 든 인수를 감싸지 않으면
 *          경로가 두 조각으로 읽혀 엉뚱한 것이 실행된다.
 * @note 따옴표 앞의 역슬래시는 두 배로 늘려야 한다. 규칙이 그렇게 되어 있다.
 */
fn escape_argument(value: &OsStr) -> io::Result<Vec<u16>> {
    let units: Vec<u16> = value.encode_wide().collect();
    if units.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows service arguments cannot contain NUL characters",
        ));
    }
    let quote = u16::from(b'"');
    let slash = u16::from(b'\\');
    let needs_quote = units.is_empty()
        || units
            .iter()
            .any(|unit| matches!(*unit, 0x09 | 0x0a | 0x0b | 0x20) || *unit == quote);
    if !needs_quote {
        return Ok(units);
    }

    let mut escaped = Vec::with_capacity(units.len() + 2);
    escaped.push(quote);
    let mut index = 0;
    while index < units.len() {
        let start = index;
        while index < units.len() && units[index] == slash {
            index += 1;
        }
        let slashes = index - start;
        if index == units.len() {
            escaped.extend(std::iter::repeat_n(slash, slashes * 2));
            break;
        }
        if units[index] == quote {
            escaped.extend(std::iter::repeat_n(slash, slashes * 2 + 1));
        } else {
            escaped.extend(std::iter::repeat_n(slash, slashes));
        }
        escaped.push(units[index]);
        index += 1;
    }
    escaped.push(quote);
    Ok(escaped)
}

/** @brief 실행 파일과 인수들을 관리자에 넘길 한 줄로 잇는다. */
fn service_command(executable: &OsStr, arguments: &[OsString]) -> io::Result<Vec<u16>> {
    let mut command = escape_argument(executable)?;
    for argument in arguments {
        command.push(u16::from(b' '));
        command.extend(escape_argument(argument)?);
    }
    command.push(0);
    Ok(command)
}

/**
 * @brief 지금 서비스가 등록돼 있는지, 돌고 있는지.
 *
 * @details 관리 화면이 「등록」과 「제거」 중 무엇을 보여 줄지 정하려면 이 값이 필요하다.
 *          상태를 묻는 데는 관리자 권한이 필요 없다. 등록과 제거만 필요하다.
 * @return (등록됨, 돌고 있음). 그런 이름의 서비스가 없으면 (false, false)다.
 */
pub fn status() -> BoxResult<(bool, bool)> {
    let manager = ScHandle::new(unsafe {
        win32::OpenSCManagerW(ptr::null(), ptr::null(), win32::SC_MANAGER_CONNECT)
    })
    .map_err(describe)?;
    let name = wide_nul(OsStr::new(SERVICE_NAME))?;
    let raw = unsafe { win32::OpenServiceW(manager.0, name.as_ptr(), win32::SERVICE_QUERY_STATUS) };
    if raw == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(win32::ERROR_SERVICE_DOES_NOT_EXIST) {
            return Ok((false, false));
        }
        return Err(describe(error).into());
    }
    let service = ScHandle(raw);
    let mut status = win32::ServiceStatus::default();
    bool_result(unsafe { win32::QueryServiceStatus(service.0, &mut status) }).map_err(describe)?;
    let running = matches!(
        status.dwCurrentState,
        win32::SERVICE_RUNNING | win32::SERVICE_START_PENDING
    );
    Ok((true, running))
}

/**
 * @brief 서비스 제어 관리자의 오류를 사람이 읽을 문장으로 바꾼다.
 *
 * @details 권한 부족은 이 기능에서 가장 흔한 실패인데, 원래 문구("액세스가 거부되었습니다")
 *          만으로는 무엇을 해야 하는지 알 수 없다.
 */
fn describe(error: io::Error) -> io::Error {
    let message = match error.raw_os_error() {
        Some(win32::ERROR_ACCESS_DENIED) => {
            "Installing or removing the service needs administrator rights; run it from an elevated console"
        }
        Some(win32::ERROR_SERVICE_EXISTS) => "A service with the same name is already installed",
        Some(win32::ERROR_SERVICE_DOES_NOT_EXIST) => "The service is not installed",
        _ => return error,
    };
    io::Error::new(error.kind(), message)
}

/** @brief 서비스를 등록한다. 설정 경로는 절대 경로로 고정해 둔다. */
pub fn install(config: Option<PathBuf>) -> BoxResult<String> {
    let manager = ScHandle::new(unsafe {
        win32::OpenSCManagerW(
            ptr::null(),
            ptr::null(),
            win32::SC_MANAGER_CONNECT | win32::SC_MANAGER_CREATE_SERVICE,
        )
    })
    .map_err(describe)?;

    let executable = std::env::current_exe()?;
    let mut arguments = vec![OsString::from("service"), OsString::from("run")];
    if let Some(config) = &config {
        let absolute = std::fs::canonicalize(config).unwrap_or_else(|_| config.clone());
        arguments.push(OsString::from("--config"));
        arguments.push(absolute.into_os_string());
    }

    let name = wide_nul(OsStr::new(SERVICE_NAME))?;
    let display = wide_nul(OsStr::new(SERVICE_DISPLAY))?;
    let command = service_command(executable.as_os_str(), &arguments)?;
    let service = ScHandle::new(unsafe {
        win32::CreateServiceW(
            manager.0,
            name.as_ptr(),
            display.as_ptr(),
            win32::SERVICE_CHANGE_CONFIG | win32::SERVICE_START,
            win32::SERVICE_WIN32_OWN_PROCESS,
            win32::SERVICE_AUTO_START,
            win32::SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    })
    .map_err(describe)?;

    if let Err(error) = set_recovery(&service) {
        return Ok(format!(
            "Installed service '{SERVICE_NAME}'; it starts automatically from the next boot. Could not set it to restart after a failure ({error}), so restart the service by hand after an update"
        ));
    }
    Ok(format!(
        "Installed service '{SERVICE_NAME}'; it starts automatically from the next boot and restarts after a failure"
    ))
}

/**
 * @brief 서비스가 실패하면 다시 시작하도록 복구 동작을 건다.
 * @details 업데이트를 마친 서비스는 업데이트 종료 코드를 보고하고 멈춘다. 서비스 관리자는 이것을
 *          충돌이 아닌 실패로 보므로, 그런 실패에도 복구 동작을 적용하는 플래그를 함께 건다. 같은
 *          동작이 서비스가 죽었을 때 다시 띄우는 역할도 한다.
 */
fn set_recovery(service: &ScHandle) -> io::Result<()> {
    let mut actions = RECOVERY_DELAYS_MS.map(|delay| win32::ScAction {
        Type: win32::SC_ACTION_RESTART,
        Delay: delay,
    });
    let mut failure = win32::ServiceFailureActionsW {
        dwResetPeriod: RECOVERY_RESET_SECONDS,
        lpRebootMsg: ptr::null_mut(),
        lpCommand: ptr::null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    bool_result(unsafe {
        win32::ChangeServiceConfig2W(
            service.0,
            win32::SERVICE_CONFIG_FAILURE_ACTIONS,
            (&mut failure as *mut win32::ServiceFailureActionsW).cast(),
        )
    })?;
    let mut flag = win32::ServiceFailureActionsFlag {
        fFailureActionsOnNonCrashFailures: 1,
    };
    bool_result(unsafe {
        win32::ChangeServiceConfig2W(
            service.0,
            win32::SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
            (&mut flag as *mut win32::ServiceFailureActionsFlag).cast(),
        )
    })
}

/**
 * @brief 이 서비스에 다시 시작하는 복구 동작이 걸려 있는지.
 * @details 업데이트를 마친 서비스가 스스로 멈춰도 다시 뜨는지를 이것으로 판단한다. 다시 시작하는
 *          동작이 없거나 충돌이 아닌 실패에 복구 동작을 적용하지 않으면 멈춘 채로 남는다.
 */
pub(crate) fn restarts_on_failure() -> bool {
    match recovery_restarts(SERVICE_NAME) {
        Ok(restarts) => restarts,
        Err(error) => {
            onetdns_core::warn!(event = "service.recovery_query_failed", %error, "Could not read the service recovery settings; an update waits for the service to be restarted by hand");
            false
        }
    }
}

/** @brief 이 이름의 서비스가 실패하면 다시 시작하는지. */
fn recovery_restarts(name: &str) -> io::Result<bool> {
    let manager = ScHandle::new(unsafe {
        win32::OpenSCManagerW(ptr::null(), ptr::null(), win32::SC_MANAGER_CONNECT)
    })?;
    let name = wide_nul(OsStr::new(name))?;
    let service = ScHandle::new(unsafe {
        win32::OpenServiceW(manager.0, name.as_ptr(), win32::SERVICE_QUERY_CONFIG)
    })?;
    let failure = query_config(&service, win32::SERVICE_CONFIG_FAILURE_ACTIONS)?;
    let restarts = failure.len() * 8 >= std::mem::size_of::<win32::ServiceFailureActionsW>() && {
        let failure = unsafe { &*failure.as_ptr().cast::<win32::ServiceFailureActionsW>() };
        !failure.lpsaActions.is_null()
            && unsafe { std::slice::from_raw_parts(failure.lpsaActions, failure.cActions as usize) }
                .iter()
                .any(|action| action.Type == win32::SC_ACTION_RESTART)
    };
    let flag = query_config(&service, win32::SERVICE_CONFIG_FAILURE_ACTIONS_FLAG)?;
    let on_non_crash = flag.len() * 8 >= std::mem::size_of::<win32::ServiceFailureActionsFlag>()
        && unsafe { &*flag.as_ptr().cast::<win32::ServiceFailureActionsFlag>() }
            .fFailureActionsOnNonCrashFailures
            != 0;
    Ok(restarts && on_non_crash)
}

/**
 * @brief 서비스의 추가 설정 하나를 읽는다.
 * @details 8바이트 단위로 잡아 안에 든 포인터와 구조체를 정렬된 채로 읽게 한다.
 * @safety 돌려받은 구조체의 포인터는 이 버퍼 안을 가리키므로 버퍼보다 오래 쓰면 안 된다.
 */
fn query_config(service: &ScHandle, level: u32) -> io::Result<Vec<u64>> {
    let mut needed = 0u32;
    if unsafe { win32::QueryServiceConfig2W(service.0, level, ptr::null_mut(), 0, &mut needed) }
        == 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(win32::ERROR_INSUFFICIENT_BUFFER) {
            return Err(error);
        }
    }
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    let size = u32::try_from(buffer.len() * 8)
        .map_err(|_| io::Error::other("The service setting is too large to read"))?;
    bool_result(unsafe {
        win32::QueryServiceConfig2W(
            service.0,
            level,
            buffer.as_mut_ptr().cast(),
            size,
            &mut needed,
        )
    })?;
    Ok(buffer)
}

/**
 * @brief 업데이트 종료 코드로 서비스 정지를 보고하고 프로세스를 끝낸다.
 * @details 시험에 실패해 되돌린 직후에 부른다. 준비에 이르지 못한 서버는 정상 종료를 기다리지
 *          않는다. 복구 동작이 걸려 있으면 서비스 관리자가 되돌린 실행 파일로 다시 띄운다.
 */
pub(crate) fn exit_for_update() -> ! {
    let code = crate::update::launch::UPDATE_EXIT_CODE;
    if !restarts_on_failure() {
        onetdns_core::error!(
            event = "service.restart_needed",
            "Reverted the update; start the OnetDNS service again to run the previous version"
        );
    }
    if let Some(handle) = STATUS.get() {
        if let Err(error) = handle.report(win32::SERVICE_STOPPED, 0, Some(code as u32), 0, 0) {
            onetdns_core::warn!(event = "service.status_report_failed", state = "stopped", %error, "Could not report status to the service manager");
        }
    }
    std::process::exit(code)
}

/** @brief 서비스를 멈추고 지운다. */
pub fn uninstall() -> BoxResult<String> {
    let manager = ScHandle::new(unsafe {
        win32::OpenSCManagerW(ptr::null(), ptr::null(), win32::SC_MANAGER_CONNECT)
    })
    .map_err(describe)?;
    let name = wide_nul(OsStr::new(SERVICE_NAME))?;
    let service = ScHandle::new(unsafe {
        win32::OpenServiceW(
            manager.0,
            name.as_ptr(),
            win32::SERVICE_QUERY_STATUS | win32::SERVICE_STOP | win32::DELETE,
        )
    })
    .map_err(describe)?;

    let mut status = win32::ServiceStatus::default();
    bool_result(unsafe { win32::QueryServiceStatus(service.0, &mut status) })?;
    if status.dwCurrentState != win32::SERVICE_STOPPED {
        let _ = bool_result(unsafe {
            win32::ControlService(service.0, win32::SERVICE_CONTROL_STOP, &mut status)
        });
    }
    bool_result(unsafe { win32::DeleteService(service.0) })?;
    Ok(format!("Removed service '{SERVICE_NAME}'"))
}

/** @brief 관리자와 이어 서비스로 돈다. */
pub fn run_dispatcher(config: Option<PathBuf>) -> BoxResult<()> {
    let _ = CONFIG_PATH.set(config);
    let mut name = wide_nul(OsStr::new(SERVICE_NAME))?;
    let table = [
        win32::ServiceTableEntryW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(ffi_service_main),
        },
        win32::ServiceTableEntryW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    bool_result(unsafe { win32::StartServiceCtrlDispatcherW(table.as_ptr()) })?;
    Ok(())
}

/** @brief 관리자가 부르는 진입점. */
extern "system" fn ffi_service_main(_argument_count: u32, _arguments: *mut *mut u16) {
    if let Err(error) = service_run() {
        eprintln!("Service error: {error}");
    }
}

/** @brief 관리자의 제어 요청을 받는다. */
extern "system" fn service_control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match control {
        win32::SERVICE_CONTROL_STOP => {
            if let Some(stop) = STOP_FLAG.get() {
                stop.store(true, Ordering::Relaxed);
            }
            0
        }
        win32::SERVICE_CONTROL_INTERROGATE => 0,
        _ => win32::ERROR_CALL_NOT_IMPLEMENTED,
    }
}

/**
 * @brief 서비스가 끝날 때 보고할 서비스 고유 종료 코드. 정상 종료면 없다.
 * @details 시험 중인 새 버전이 준비 전에 오류로 끝났으면 되돌리고 업데이트 종료 코드를 보고해,
 *          복구 동작이 되돌린 버전을 띄우게 한다. 적용을 마치고 멈춘 것이면 같은 코드로 맞바꾼
 *          버전을 띄우게 한다.
 */
fn exit_code(result: &BoxResult<()>) -> Option<u32> {
    let update = crate::update::launch::UPDATE_EXIT_CODE as u32;
    match result {
        Err(error) if crate::update::trial::revert_after_error(error) => Some(update),
        Err(_) => Some(1),
        Ok(()) if crate::update::launch::restart_requested() => Some(update),
        Ok(()) => None,
    }
}

/**
 * @brief 서비스 본체.
 * @details 시작 중에는 진행 중임을 계속 보고하고, 다 뜨면 돌고 있음을 알린다. 정지
 *          요청이 오면 플래그를 설정해 서버 반복을 끝낸다. 설정을 읽기 전에 업데이트 기록을
 *          처리하며, 다른 프로세스의 적용을 기다리는 동안에도 시작 중임을 보고한다.
 */
fn service_run() -> BoxResult<()> {
    let stop = STOP_FLAG
        .get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone();
    stop.store(false, Ordering::Relaxed);
    let status_handle = StatusHandle::register()?;
    let _ = STATUS.set(status_handle);
    crate::update::launch::register_service(stop.clone());

    let start_pending = |checkpoint: u32| {
        status_handle.report(win32::SERVICE_START_PENDING, 0, None, checkpoint, 15_000)
    };
    start_pending(1)?;

    let mut checkpoint = 1;
    let startup = crate::update::trial::on_start(&mut || {
        checkpoint += 1;
        if let Err(error) = start_pending(checkpoint) {
            onetdns_core::warn!(event = "service.status_report_failed", state = "start_pending", %error, "Could not report status to the service manager");
        }
    });
    match startup {
        crate::update::trial::Startup::Normal => {}
        crate::update::trial::Startup::Trial(trial) => crate::update::trial::watch(trial),
        crate::update::trial::Startup::Reverted => crate::update::launch::start_reverted(),
    }

    let config = CONFIG_PATH.get().cloned().flatten();
    if let Err(error) = Config::load_or_default(config.as_deref()) {
        onetdns_core::error!(event = "service.config_load_failed", %error, "Could not read the configuration; not starting the service");
        let result: BoxResult<()> = Err(error.into());
        if let Err(report_error) =
            status_handle.report(win32::SERVICE_STOPPED, 0, exit_code(&result), 0, 0)
        {
            onetdns_core::warn!(event = "service.status_report_failed", state = "stopped", error = %report_error, "Could not report status to the service manager");
        }
        return result;
    }

    let shared = crate::ServeShared::default();
    let mut recovery_error: Option<String> = None;
    let result = loop {
        let cfg = match Config::load_or_default(config.as_deref()) {
            Ok(config) => config,
            Err(error) => match crate::restore_last_applied_config(config.as_deref(), &shared) {
                Ok(true) if recovery_error.is_none() => {
                    onetdns_core::error!(event = "service.config_rolled_back", %error, "Could not read the new configuration; starting with the last configuration that worked");
                    recovery_error = Some(error.to_string());
                    continue;
                }
                Ok(_) => {
                    if let Some(first_error) = recovery_error.take() {
                        break Err(crate::anyhow!(format!(
                            "Could not apply the new configuration, and could not recover the service with the last working configuration either: new configuration error={first_error}; recovery configuration error={error}"
                        )));
                    }
                    break Err(error.into());
                }
                Err(rollback_error) => break Err(rollback_error),
            },
        };
        let cfg_text = config.as_deref().and_then(|path| match Config::read_text(path) {
            Ok(text) => Some(onetdns_core::SecretString::from(text)),
            Err(error) => {
                onetdns_core::warn!(event = "service.config_text_unavailable", path = %path.display(), %error, "Could not read the configuration file text; the dashboard's configuration editor will be empty");
                None
            }
        });
        let ready_handle = status_handle;
        let on_ready: Box<dyn FnOnce() + Send> = Box::new(move || {
            crate::update::trial::commit_active();
            if let Err(error) = ready_handle.report(
                win32::SERVICE_RUNNING,
                win32::SERVICE_ACCEPT_STOP,
                None,
                0,
                0,
            ) {
                onetdns_core::warn!(event = "service.status_report_failed", state = "running", %error, "Could not tell the service manager that the service is running; it may treat startup as failed and stop the service");
            }
        });
        let session_checkpoint = shared.sessions.checkpoint();
        match crate::serve(
            cfg,
            cfg_text,
            config.clone(),
            shared.clone(),
            Some(stop.clone()),
            Some(on_ready),
        ) {
            Ok(true) => {
                recovery_error = None;
                if let Err(error) = start_pending(1) {
                    onetdns_core::warn!(event = "service.status_report_failed", state = "start_pending", %error, "Could not report status to the service manager");
                }
                continue;
            }
            Ok(false) => break Ok(()),
            Err(error) => {
                shared.sessions.restore(session_checkpoint);
                match crate::restore_last_applied_config(config.as_deref(), &shared) {
                    Ok(true) if recovery_error.is_none() => {
                        onetdns_core::error!(event = "service.config_rolled_back", %error, "Could not start with the new configuration; reverting to the last configuration that worked");
                        recovery_error = Some(error.to_string());
                        if let Err(report_error) = start_pending(2) {
                            onetdns_core::warn!(event = "service.status_report_failed", state = "start_pending", error = %report_error, "Could not report status to the service manager");
                        }
                        continue;
                    }
                    Ok(_) => {
                        if let Some(first_error) = recovery_error.take() {
                            break Err(crate::anyhow!(format!(
                                "Could not apply the new configuration, and could not recover the service with the last working configuration either: new configuration error={first_error}; recovery configuration error={error}"
                            )));
                        }
                        break Err(error);
                    }
                    Err(rollback_error) => break Err(rollback_error),
                }
            }
        }
    };

    status_handle.report(win32::SERVICE_STOPPED, 0, exit_code(&result), 0, 0)?;
    result
}

#[cfg(test)]
/** @brief 명령줄 감싸기가 규칙대로인지, 그리고 구조체 배치가 규격과 맞는지. */
mod tests {
    use std::os::windows::ffi::OsStringExt;

    use super::*;

    #[test]
    /** @brief 공백이 든 경로를 감싸되 인수 내용은 바꾸지 않는지. */
    fn service_command_quotes_paths_without_changing_arguments() {
        let command = service_command(
            OsStr::new(r"C:\Program Files\OnetDNS\onetdns.exe"),
            &[
                OsString::from("service"),
                OsString::from("run"),
                OsString::from("--config"),
                OsString::from(r"C:\DNS config\prod.toml"),
            ],
        )
        .unwrap();
        assert_eq!(command.last(), Some(&0));
        assert_eq!(
            OsString::from_wide(&command[..command.len() - 1]),
            OsString::from(
                r#""C:\Program Files\OnetDNS\onetdns.exe" service run --config "C:\DNS config\prod.toml""#
            )
        );
    }

    #[test]
    /** @brief 따옴표와 끝의 역슬래시가 규칙대로 늘어나는지. 안 늘리면 감싸기가 깨진다. */
    fn service_command_escapes_quotes_and_trailing_slashes() {
        assert_eq!(
            OsString::from_wide(&escape_argument(OsStr::new(r#"hello \\"quote\\""#)).unwrap()),
            OsString::from(r#""hello \\\\\"quote\\\\\"""#)
        );
        assert_eq!(
            OsString::from_wide(&escape_argument(OsStr::new(r"C:\path with space\")).unwrap()),
            OsString::from(r#""C:\path with space\\""#)
        );
    }

    #[test]
    /** @brief 중간에 끝 표시가 든 인수를 거부하는지. */
    fn service_command_rejects_embedded_nul() {
        let error = escape_argument(OsStr::new("bad\0argument")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    /** @brief 구조체 크기와 필드 위치가 규격과 같은지. 어긋나면 엉뚱한 메모리를 읽는다. */
    fn win32_service_abi_layout_matches_winsvc_h() {
        let word = std::mem::size_of::<usize>();
        assert_eq!(std::mem::size_of::<win32::ServiceStatus>(), 7 * 4);
        assert_eq!(std::mem::align_of::<win32::ServiceStatus>(), 4);
        assert_eq!(std::mem::size_of::<win32::ServiceTableEntryW>(), 2 * word);
        assert_eq!(std::mem::size_of::<win32::ScAction>(), 2 * 4);
        assert_eq!(
            std::mem::size_of::<win32::ServiceFailureActionsW>(),
            5 * word
        );
        assert_eq!(
            std::mem::offset_of!(win32::ServiceFailureActionsW, cActions),
            3 * word
        );
        assert_eq!(
            std::mem::offset_of!(win32::ServiceFailureActionsW, lpsaActions),
            4 * word
        );
        assert_eq!(std::mem::size_of::<win32::ServiceFailureActionsFlag>(), 4);
    }

    #[test]
    /**
     * @brief 복구 설정을 실제로 읽어 내는지.
     * @details 서비스를 등록하지 않고 확인하려고, 어느 Windows 에나 있는 이벤트 로그 서비스의 설정을
     *          읽기만 한다. 크기를 먼저 묻고 다시 읽는 과정과 구조체 해석이 여기서 돈다.
     */
    fn recovery_settings_of_an_installed_service_can_be_read() {
        recovery_restarts("EventLog").expect("이벤트 로그 서비스의 복구 설정");
        let missing = recovery_restarts("OnetDNS-no-such-service").unwrap_err();
        assert_eq!(
            missing.raw_os_error(),
            Some(win32::ERROR_SERVICE_DOES_NOT_EXIST)
        );
    }
}
