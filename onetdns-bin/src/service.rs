//! Windows service registration and execution, bound to the service control manager directly.

use std::ffi::{c_void, OsStr, OsString};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use crate::error::BoxResult;
use onetdns_config::Config;

const SERVICE_NAME: &str = "OnetDNS";
const SERVICE_DISPLAY: &str = "OnetDNS ad-blocking DNS";

/// The service entry point takes no arguments, so the config path waits here.
static CONFIG_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
static STOP_FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
/// Static because the update trial timer reports a stop too.
static STATUS: OnceLock<StatusHandle> = OnceLock::new();

/// Milliseconds before each successive restart after a failure.
const RECOVERY_DELAYS_MS: [u32; 3] = [1_000, 5_000, 30_000];
/// A day without failures resets the failure count.
const RECOVERY_RESET_SECONDS: u32 = 86_400;

#[allow(non_snake_case)]
mod win32 {
    use super::c_void;

    pub type ScHandle = isize;
    pub type ServiceStatusHandle = isize;

    pub const SC_MANAGER_CONNECT: u32 = 0x0001;
    pub const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;
    pub const DELETE: u32 = 0x0001_0000;
    pub const SERVICE_CHANGE_CONFIG: u32 = 0x0002;
    pub const SERVICE_QUERY_STATUS: u32 = 0x0004;
    pub const SERVICE_STOP: u32 = 0x0020;
    pub const SERVICE_QUERY_CONFIG: u32 = 0x0001;
    pub const SERVICE_START: u32 = 0x0010;
    pub const SERVICE_CONFIG_FAILURE_ACTIONS: u32 = 2;
    pub const SERVICE_CONFIG_FAILURE_ACTIONS_FLAG: u32 = 4;
    pub const SC_ACTION_RESTART: u32 = 1;
    pub const ERROR_INSUFFICIENT_BUFFER: i32 = 122;

    pub const SERVICE_WIN32_OWN_PROCESS: u32 = 0x0010;
    pub const SERVICE_AUTO_START: u32 = 0x0002;
    pub const SERVICE_ERROR_NORMAL: u32 = 0x0001;
    pub const SERVICE_STOPPED: u32 = 0x0001;
    pub const SERVICE_START_PENDING: u32 = 0x0002;
    pub const SERVICE_RUNNING: u32 = 0x0004;
    pub const SERVICE_ACCEPT_STOP: u32 = 0x0001;
    pub const SERVICE_CONTROL_STOP: u32 = 0x0001;
    pub const SERVICE_CONTROL_INTERROGATE: u32 = 0x0004;
    pub const ERROR_ACCESS_DENIED: i32 = 5;
    pub const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
    pub const ERROR_SERVICE_EXISTS: i32 = 1073;
    pub const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
    pub const ERROR_SERVICE_SPECIFIC_ERROR: u32 = 1066;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct ServiceStatus {
        pub dwServiceType: u32,
        pub dwCurrentState: u32,
        pub dwControlsAccepted: u32,
        pub dwWin32ExitCode: u32,
        pub dwServiceSpecificExitCode: u32,
        pub dwCheckPoint: u32,
        pub dwWaitHint: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ScAction {
        pub Type: u32,
        pub Delay: u32,
    }

    #[repr(C)]
    pub struct ServiceFailureActionsW {
        pub dwResetPeriod: u32,
        pub lpRebootMsg: *mut u16,
        pub lpCommand: *mut u16,
        pub cActions: u32,
        pub lpsaActions: *mut ScAction,
    }

    #[repr(C)]
    pub struct ServiceFailureActionsFlag {
        pub fFailureActionsOnNonCrashFailures: i32,
    }

    pub type ServiceMainProc = Option<extern "system" fn(u32, *mut *mut u16)>;
    pub type HandlerExProc = Option<extern "system" fn(u32, u32, *mut c_void, *mut c_void) -> u32>;

    #[repr(C)]
    pub struct ServiceTableEntryW {
        pub lpServiceName: *mut u16,
        pub lpServiceProc: ServiceMainProc,
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        pub fn OpenSCManagerW(
            machine_name: *const u16,
            database_name: *const u16,
            desired_access: u32,
        ) -> ScHandle;
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
        pub fn OpenServiceW(
            manager: ScHandle,
            service_name: *const u16,
            desired_access: u32,
        ) -> ScHandle;
        pub fn QueryServiceStatus(service: ScHandle, status: *mut ServiceStatus) -> i32;
        pub fn ControlService(service: ScHandle, control: u32, status: *mut ServiceStatus) -> i32;
        pub fn DeleteService(service: ScHandle) -> i32;
        pub fn ChangeServiceConfig2W(service: ScHandle, info_level: u32, info: *mut c_void) -> i32;
        pub fn QueryServiceConfig2W(
            service: ScHandle,
            info_level: u32,
            buffer: *mut u8,
            buffer_size: u32,
            bytes_needed: *mut u32,
        ) -> i32;
        pub fn CloseServiceHandle(handle: ScHandle) -> i32;
        pub fn StartServiceCtrlDispatcherW(table: *const ServiceTableEntryW) -> i32;
        pub fn RegisterServiceCtrlHandlerExW(
            service_name: *const u16,
            handler: HandlerExProc,
            context: *mut c_void,
        ) -> ServiceStatusHandle;
        pub fn SetServiceStatus(
            status_handle: ServiceStatusHandle,
            status: *const ServiceStatus,
        ) -> i32;
        pub fn OpenProcessToken(process: isize, desired_access: u32, token: *mut isize) -> i32;
        pub fn GetTokenInformation(
            token: isize,
            information_class: u32,
            information: *mut c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
    }

    pub const TOKEN_QUERY: u32 = 0x0008;
    pub const TOKEN_ELEVATION_CLASS: u32 = 20;
    pub const SEE_MASK_NOCLOSEPROCESS: u32 = 0x0040;
    pub const SEE_MASK_NOASYNC: u32 = 0x0100;
    pub const SW_HIDE: i32 = 0;
    pub const INFINITE: u32 = 0xFFFF_FFFF;
    pub const ERROR_CANCELLED: i32 = 1223;

    #[repr(C)]
    pub struct ShellExecuteInfoW {
        pub cbSize: u32,
        pub fMask: u32,
        pub hwnd: isize,
        pub lpVerb: *const u16,
        pub lpFile: *const u16,
        pub lpParameters: *const u16,
        pub lpDirectory: *const u16,
        pub nShow: i32,
        pub hInstApp: isize,
        pub lpIDList: *mut c_void,
        pub lpClass: *const u16,
        pub hkeyClass: isize,
        pub dwHotKey: u32,
        pub hIcon: isize,
        pub hProcess: isize,
    }

    #[link(name = "shell32")]
    unsafe extern "system" {
        pub fn ShellExecuteExW(info: *mut ShellExecuteInfoW) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn GetCurrentProcess() -> isize;
        pub fn WaitForSingleObject(handle: isize, milliseconds: u32) -> u32;
        pub fn GetExitCodeProcess(process: isize, exit_code: *mut u32) -> i32;
        pub fn CloseHandle(handle: isize) -> i32;
    }
}

struct ScHandle(win32::ScHandle);

impl ScHandle {
    fn new(raw: win32::ScHandle) -> io::Result<Self> {
        if raw == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(raw))
        }
    }
}

impl Drop for ScHandle {
    fn drop(&mut self) {
        unsafe {
            win32::CloseServiceHandle(self.0);
        }
    }
}

#[derive(Clone, Copy)]
struct StatusHandle(win32::ServiceStatusHandle);

impl StatusHandle {
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

    /// Must repeat during startup, or the manager takes the service for dead.
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

fn bool_result(value: i32) -> io::Result<()> {
    if value == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Rejects embedded NULs.
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

/// Quotes one argument by the Windows command-line rules, since one line is split back into
/// arguments. Backslashes before a quote double.
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

fn service_command(executable: &OsStr, arguments: &[OsString]) -> io::Result<Vec<u16>> {
    let mut command = escape_argument(executable)?;
    command.push(u16::from(b' '));
    command.extend(command_parameters(arguments)?);
    Ok(command)
}

/// NUL-terminated.
fn command_parameters(arguments: &[OsString]) -> io::Result<Vec<u16>> {
    let mut line = Vec::new();
    for (index, argument) in arguments.iter().enumerate() {
        if index > 0 {
            line.push(u16::from(b' '));
        }
        line.extend(escape_argument(argument)?);
    }
    line.push(0);
    Ok(line)
}

/// (registered, running). Needs no administrator rights.
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

/// Access denied is the usual failure here, and the OS text does not say what to do.
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

/// Pins the config to an absolute path.
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

/// Installs from any console, asking for administrator rights through UAC when they are missing.
pub fn install_elevating(config: Option<PathBuf>) -> BoxResult<String> {
    if is_elevated()? {
        return install(config);
    }
    if status()?.0 {
        return Err("A service with the same name is already installed".into());
    }
    let mut arguments = vec![OsString::from("service"), OsString::from("install")];
    if let Some(config) = config {
        // The elevated process starts in another directory.
        arguments.push(OsString::from("--config"));
        arguments.push(std::path::absolute(config)?.into_os_string());
    }
    run_elevated(&arguments)?;
    Ok(format!(
        "Installed service '{SERVICE_NAME}'; it starts automatically from the next boot"
    ))
}

/// Removes from any console, asking for administrator rights through UAC when they are missing.
pub fn uninstall_elevating() -> BoxResult<String> {
    if is_elevated()? {
        return uninstall();
    }
    if !status()?.0 {
        return Err("The service is not installed".into());
    }
    run_elevated(&[OsString::from("service"), OsString::from("uninstall")])?;
    Ok(format!("Removed service '{SERVICE_NAME}'"))
}

fn is_elevated() -> io::Result<bool> {
    let mut token = 0;
    // SAFETY: the pseudo handle needs no closing and `token` is a valid out pointer.
    bool_result(unsafe {
        win32::OpenProcessToken(win32::GetCurrentProcess(), win32::TOKEN_QUERY, &mut token)
    })?;
    let mut elevated = 0u32;
    let mut returned = 0u32;
    // SAFETY: `token` is open and TOKEN_ELEVATION is one u32.
    let result = bool_result(unsafe {
        win32::GetTokenInformation(
            token,
            win32::TOKEN_ELEVATION_CLASS,
            (&mut elevated as *mut u32).cast(),
            4,
            &mut returned,
        )
    });
    // SAFETY: closes the handle opened above, once.
    unsafe {
        win32::CloseHandle(token);
    }
    result.map(|()| elevated != 0)
}

/// Runs this executable as administrator and waits. Its console closes with it, so only the exit
/// code comes back.
fn run_elevated(arguments: &[OsString]) -> BoxResult<()> {
    let executable = wide_nul(std::env::current_exe()?.as_os_str())?;
    let parameters = command_parameters(arguments)?;
    let verb = wide_nul(OsStr::new("runas"))?;
    let mut info = win32::ShellExecuteInfoW {
        cbSize: std::mem::size_of::<win32::ShellExecuteInfoW>() as u32,
        fMask: win32::SEE_MASK_NOCLOSEPROCESS | win32::SEE_MASK_NOASYNC,
        hwnd: 0,
        lpVerb: verb.as_ptr(),
        lpFile: executable.as_ptr(),
        lpParameters: parameters.as_ptr(),
        lpDirectory: ptr::null(),
        nShow: win32::SW_HIDE,
        hInstApp: 0,
        lpIDList: ptr::null_mut(),
        lpClass: ptr::null(),
        hkeyClass: 0,
        dwHotKey: 0,
        hIcon: 0,
        hProcess: 0,
    };
    // SAFETY: `info` matches SHELLEXECUTEINFOW and the strings outlive the call.
    if let Err(error) = bool_result(unsafe { win32::ShellExecuteExW(&mut info) }) {
        if error.raw_os_error() == Some(win32::ERROR_CANCELLED) {
            return Err("The administrator prompt was declined, so nothing changed".into());
        }
        return Err(format!("Could not ask for administrator rights: {error}").into());
    }
    if info.hProcess == 0 {
        return Err("Windows did not report the elevated process".into());
    }
    let mut code = 1u32;
    // SAFETY: `hProcess` stays open until the CloseHandle below.
    let read = unsafe {
        win32::WaitForSingleObject(info.hProcess, win32::INFINITE);
        let read = bool_result(win32::GetExitCodeProcess(info.hProcess, &mut code));
        win32::CloseHandle(info.hProcess);
        read
    };
    read?;
    if code != 0 {
        return Err(format!(
            "The elevated command failed with exit code {code}; run it from an administrator console to see why"
        )
        .into());
    }
    Ok(())
}

/// A service stopping with the update exit code is a non-crash failure, so recovery has to be
/// switched on for those too.
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

/// Whether a service that stops itself for an update comes back. Asked each time, since an
/// operator can change the service settings.
pub(crate) fn restarts_on_failure() -> bool {
    match recovery_restarts(SERVICE_NAME) {
        Ok(restarts) => restarts,
        Err(error) => {
            onetdns_core::warn!(event = "service.recovery_query_failed", %error, "Could not read the service recovery settings; an update waits for the service to be restarted by hand");
            false
        }
    }
}

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

/// In 8-byte words, so the structs inside stay aligned. Pointers in the result point into it.
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

/// Called right after reverting an update; recovery starts the reverted executable.
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

extern "system" fn ffi_service_main(_argument_count: u32, _arguments: *mut *mut u16) {
    if let Err(error) = service_run() {
        eprintln!("Service error: {error}");
    }
}

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

/// The service-specific exit code to report; `None` for a clean stop.
fn exit_code(result: &BoxResult<()>) -> Option<u32> {
    let update = crate::update::launch::UPDATE_EXIT_CODE as u32;
    match result {
        Err(error) if crate::update::trial::revert_after_error(error) => Some(update),
        Err(_) => Some(1),
        Ok(()) if crate::update::launch::restart_requested() => Some(update),
        Ok(()) => None,
    }
}

/// Handles the update record before reading the config, reporting progress while it waits.
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
        crate::update::trial::Startup::Trial(trial) => crate::update::trial::hold(trial),
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
mod tests {
    use std::os::windows::ffi::OsStringExt;

    use super::*;

    #[test]
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
    fn elevated_parameters_are_quoted_and_nul_terminated() {
        let line = command_parameters(&[
            OsString::from("service"),
            OsString::from("install"),
            OsString::from("--config"),
            OsString::from(r"C:\Users\A B\OnetDNS.toml"),
        ])
        .unwrap();
        assert_eq!(line.last(), Some(&0));
        assert_eq!(
            OsString::from_wide(&line[..line.len() - 1]),
            OsString::from(r#"service install --config "C:\Users\A B\OnetDNS.toml""#)
        );
    }

    #[test]
    fn the_elevation_of_this_process_can_be_read() {
        is_elevated().expect("token elevation");
    }

    #[test]
    fn shell_execute_info_matches_shellapi_h() {
        let expected = if std::mem::size_of::<usize>() == 8 {
            112
        } else {
            60
        };
        assert_eq!(std::mem::size_of::<win32::ShellExecuteInfoW>(), expected);
    }

    #[test]
    fn service_command_rejects_embedded_nul() {
        let error = escape_argument(OsStr::new("bad\0argument")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
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
    // Reads EventLog, present on every Windows, so nothing has to be installed.
    fn recovery_settings_of_an_installed_service_can_be_read() {
        recovery_restarts("EventLog").expect("이벤트 로그 서비스의 복구 설정");
        let missing = recovery_restarts("OnetDNS-no-such-service").unwrap_err();
        assert_eq!(
            missing.raw_os_error(),
            Some(win32::ERROR_SERVICE_DOES_NOT_EXIST)
        );
    }
}
