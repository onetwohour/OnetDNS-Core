//! Windows workers start from the install path: a running process cannot change its image, so the
//! supervisor stays the version it started as until the service or console starts again. Workers
//! sit in a job object that ends them with the supervisor, so no orphan keeps the ports.

use std::ffi::{c_void, OsStr, OsString};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::os::windows::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::ExitStatus;
use std::sync::atomic::Ordering;
use std::sync::OnceLock;
use std::time::Duration;

use super::channel::CHANNEL_ENV;
use super::supervise::WorkerCommand;
use crate::error::{BoxResult, Context};
use crate::handoff::wire::{self, Frame, Reader, Stream, Writer};
use crate::handoff::LinkError;
use crate::tui::ChildConsole;

/// Names the event the supervisor sets to ask a worker to shut down.
const STOP_ENV: &str = "ONETDNS_SUPERVISOR_STOP";
/// The exit code of a worker the supervisor ends, as the standard library's `Child::kill` uses.
const KILLED: u32 = 1;

#[allow(non_snake_case, clippy::upper_case_acronyms)]
mod win32 {
    use std::ffi::c_void;

    pub type HANDLE = isize;

    pub const WAIT_OBJECT_0: u32 = 0;
    pub const WAIT_TIMEOUT: u32 = 0x102;
    pub const INFINITE: u32 = u32::MAX;
    pub const HANDLE_FLAG_INHERIT: u32 = 0x1;
    pub const DUPLICATE_SAME_ACCESS: u32 = 0x2;
    pub const STD_INPUT_HANDLE: u32 = -10i32 as u32;
    pub const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    pub const STD_ERROR_HANDLE: u32 = -12i32 as u32;
    pub const STARTF_USESTDHANDLES: u32 = 0x100;
    pub const CREATE_SUSPENDED: u32 = 0x4;
    pub const CREATE_UNICODE_ENVIRONMENT: u32 = 0x400;
    pub const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x8_0000;
    pub const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x2_0002;
    pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
    pub const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;
    pub const FILE_TYPE_PIPE: u32 = 3;

    #[repr(C)]
    pub struct SECURITY_ATTRIBUTES {
        pub nLength: u32,
        pub lpSecurityDescriptor: *mut c_void,
        pub bInheritHandle: i32,
    }

    #[repr(C)]
    pub struct STARTUPINFOW {
        pub cb: u32,
        pub lpReserved: *mut u16,
        pub lpDesktop: *mut u16,
        pub lpTitle: *mut u16,
        pub dwX: u32,
        pub dwY: u32,
        pub dwXSize: u32,
        pub dwYSize: u32,
        pub dwXCountChars: u32,
        pub dwYCountChars: u32,
        pub dwFillAttribute: u32,
        pub dwFlags: u32,
        pub wShowWindow: u16,
        pub cbReserved2: u16,
        pub lpReserved2: *mut u8,
        pub hStdInput: HANDLE,
        pub hStdOutput: HANDLE,
        pub hStdError: HANDLE,
    }

    #[repr(C)]
    pub struct STARTUPINFOEXW {
        pub StartupInfo: STARTUPINFOW,
        pub lpAttributeList: *mut c_void,
    }

    #[repr(C)]
    pub struct PROCESS_INFORMATION {
        pub hProcess: HANDLE,
        pub hThread: HANDLE,
        pub dwProcessId: u32,
        pub dwThreadId: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        pub PerProcessUserTimeLimit: i64,
        pub PerJobUserTimeLimit: i64,
        pub LimitFlags: u32,
        pub MinimumWorkingSetSize: usize,
        pub MaximumWorkingSetSize: usize,
        pub ActiveProcessLimit: u32,
        pub Affinity: usize,
        pub PriorityClass: u32,
        pub SchedulingClass: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        pub BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
        /// IO_COUNTERS.
        pub IoInfo: [u64; 6],
        pub ProcessMemoryLimit: usize,
        pub JobMemoryLimit: usize,
        pub PeakProcessMemoryUsed: usize,
        pub PeakJobMemoryUsed: usize,
    }

    #[cfg(target_pointer_width = "64")]
    const _: () = assert!(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() == 144);

    #[repr(C)]
    #[derive(Default)]
    pub struct MEMORYSTATUSEX {
        pub dwLength: u32,
        pub dwMemoryLoad: u32,
        pub ullTotalPhys: u64,
        pub ullAvailPhys: u64,
        pub ullTotalPageFile: u64,
        pub ullAvailPageFile: u64,
        pub ullTotalVirtual: u64,
        pub ullAvailVirtual: u64,
        pub ullAvailExtendedVirtual: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct PROCESS_MEMORY_COUNTERS {
        pub cb: u32,
        pub PageFaultCount: u32,
        pub PeakWorkingSetSize: usize,
        pub WorkingSetSize: usize,
        pub QuotaPeakPagedPoolUsage: usize,
        pub QuotaPagedPoolUsage: usize,
        pub QuotaPeakNonPagedPoolUsage: usize,
        pub QuotaNonPagedPoolUsage: usize,
        pub PagefileUsage: usize,
        pub PeakPagefileUsage: usize,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn GetCurrentProcess() -> HANDLE;
        pub fn WaitForSingleObject(handle: HANDLE, milliseconds: u32) -> u32;
        pub fn GetExitCodeProcess(process: HANDLE, exit_code: *mut u32) -> i32;
        pub fn TerminateProcess(process: HANDLE, exit_code: u32) -> i32;
        pub fn ResumeThread(thread: HANDLE) -> u32;
        pub fn SetEvent(event: HANDLE) -> i32;
        pub fn CreateEventW(
            security: *mut c_void,
            manual_reset: i32,
            initial_state: i32,
            name: *const u16,
        ) -> *mut c_void;
        pub fn DuplicateHandle(
            source_process: HANDLE,
            source: HANDLE,
            target_process: HANDLE,
            target: *mut HANDLE,
            access: u32,
            inherit: i32,
            options: u32,
        ) -> i32;
        pub fn SetHandleInformation(handle: HANDLE, mask: u32, flags: u32) -> i32;
        pub fn GetStdHandle(which: u32) -> isize;
        pub fn GetFileType(file: HANDLE) -> u32;
        pub fn InitializeProcThreadAttributeList(
            list: *mut c_void,
            count: u32,
            flags: u32,
            size: *mut usize,
        ) -> i32;
        pub fn UpdateProcThreadAttribute(
            list: *mut c_void,
            flags: u32,
            attribute: usize,
            value: *const c_void,
            size: usize,
            previous: *mut c_void,
            returned: *mut usize,
        ) -> i32;
        pub fn DeleteProcThreadAttributeList(list: *mut c_void);
        pub fn CreateProcessW(
            application: *const u16,
            command_line: *mut u16,
            process_security: *const c_void,
            thread_security: *const c_void,
            inherit: i32,
            flags: u32,
            environment: *const c_void,
            directory: *const u16,
            startup: *const STARTUPINFOW,
            information: *mut PROCESS_INFORMATION,
        ) -> i32;
        pub fn CreateJobObjectW(security: *const c_void, name: *const u16) -> HANDLE;
        pub fn SetInformationJobObject(
            job: HANDLE,
            class: i32,
            information: *const c_void,
            length: u32,
        ) -> i32;
        pub fn AssignProcessToJobObject(job: HANDLE, process: HANDLE) -> i32;
        pub fn GlobalMemoryStatusEx(status: *mut MEMORYSTATUSEX) -> i32;
        pub fn K32GetProcessMemoryInfo(
            process: HANDLE,
            counters: *mut PROCESS_MEMORY_COUNTERS,
            size: u32,
        ) -> i32;
    }
}

fn raw(handle: &impl AsRawHandle) -> win32::HANDLE {
    handle.as_raw_handle() as win32::HANDLE
}

/// Takes a handle a successful call returned.
///
/// # Safety
/// `handle` must be open and owned by nothing else.
unsafe fn owned(handle: win32::HANDLE) -> OwnedHandle {
    // SAFETY: As the caller promises.
    unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) }
}

fn last_error<T>() -> io::Result<T> {
    Err(io::Error::last_os_error())
}

pub(super) struct Process {
    handle: OwnedHandle,
    id: u32,
    /// Set to ask the worker to shut down.
    stop_event: OwnedHandle,
}

impl Process {
    pub(super) fn id(&self) -> u32 {
        self.id
    }

    pub(super) fn try_wait(&self) -> io::Result<Option<ExitStatus>> {
        self.wait_for(0)
    }

    pub(super) fn wait(&self) -> io::Result<ExitStatus> {
        loop {
            if let Some(status) = self.wait_for(win32::INFINITE)? {
                return Ok(status);
            }
        }
    }

    fn wait_for(&self, milliseconds: u32) -> io::Result<Option<ExitStatus>> {
        // SAFETY: Waits on a process handle this value owns.
        match unsafe { win32::WaitForSingleObject(raw(&self.handle), milliseconds) } {
            win32::WAIT_OBJECT_0 => {
                let mut code = 0u32;
                // SAFETY: `code` is valid for writing.
                if unsafe { win32::GetExitCodeProcess(raw(&self.handle), &raw mut code) } == 0 {
                    return last_error();
                }
                Ok(Some(ExitStatus::from_raw(code)))
            }
            win32::WAIT_TIMEOUT => Ok(None),
            _ => last_error(),
        }
    }

    /// Asks it to shut down.
    pub(super) fn stop(&self) {
        // SAFETY: Sets an event this value owns.
        if unsafe { win32::SetEvent(raw(&self.stop_event)) } == 0 {
            let error = io::Error::last_os_error();
            onetdns_core::warn!(event = "supervisor.shutdown_signal_failed", pid = self.id, %error, "Supervisor could not forward the shutdown signal to the DNS service");
        }
    }

    pub(super) fn kill(&self) {
        // SAFETY: Ends a process this value holds a handle to.
        if unsafe { win32::TerminateProcess(raw(&self.handle), KILLED) } == 0 {
            let error = io::Error::last_os_error();
            if !matches!(self.try_wait(), Ok(Some(_))) {
                onetdns_core::warn!(event = "supervisor.shutdown_signal_failed", pid = self.id, %error, "Supervisor could not forward the shutdown signal to the DNS service");
            }
        }
    }
}

/// Every worker runs the installed executable.
pub(super) fn worker_image() -> BoxResult<PathBuf> {
    crate::update::install::current()
        .map(|install| install.path().to_path_buf())
        .map_err(|reason| crate::anyhow!(reason))
}

/// The worker inherits its end of the channel, its stop event, and copies of the standard handles,
/// and no other handle: the list in its attributes limits inheritance to these.
pub(super) fn spawn(command: &WorkerCommand) -> BoxResult<(Process, Stream)> {
    let (channel, worker_end) =
        wire::pair().with_context(|| "Could not create the channel to the DNS service process")?;
    let started = (|| -> io::Result<(Process, Stream)> {
        // SAFETY: Changes a flag of a handle `worker_end` owns; that copy closes once the worker
        // started.
        if unsafe {
            win32::SetHandleInformation(
                raw(&worker_end),
                win32::HANDLE_FLAG_INHERIT,
                win32::HANDLE_FLAG_INHERIT,
            )
        } == 0
        {
            return last_error();
        }
        let stop_event = inheritable_event()?;
        let standard = [
            win32::STD_INPUT_HANDLE,
            win32::STD_OUTPUT_HANDLE,
            win32::STD_ERROR_HANDLE,
        ]
        .map(inheritable_copy_of_standard);
        let mut inherited = vec![raw(&worker_end), raw(&stop_event)];
        inherited.extend(standard.iter().flatten().map(raw));

        let mut env = command.env.clone();
        env.push((CHANNEL_ENV, raw(&worker_end).to_string().into()));
        env.push((STOP_ENV, raw(&stop_event).to_string().into()));
        let environment = environment_block(&env);
        let mut line = Vec::new();
        push_quoted(&mut line, command.program.as_os_str());
        for arg in &command.args {
            line.push(u16::from(b' '));
            push_quoted(&mut line, arg);
        }
        line.push(0);
        let image: Vec<u16> = command.image.as_os_str().encode_wide().chain([0]).collect();

        let mut attributes = HandleList::new(&inherited)?;
        // SAFETY: All-zero bits are a valid STARTUPINFOEXW to fill in.
        let mut startup: win32::STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = std::mem::size_of::<win32::STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = win32::STARTF_USESTDHANDLES;
        let [input, output, error] = standard.each_ref().map(|copy| copy.as_ref().map_or(0, raw));
        startup.StartupInfo.hStdInput = input;
        startup.StartupInfo.hStdOutput = output;
        startup.StartupInfo.hStdError = error;
        startup.lpAttributeList = attributes.list();
        // SAFETY: All-zero bits are a valid PROCESS_INFORMATION for the call to fill.
        let mut information: win32::PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: The strings are NUL-terminated, the environment block ends in two NULs, and the
        // attribute list and the handles it names outlive the call.
        if unsafe {
            win32::CreateProcessW(
                image.as_ptr(),
                line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                win32::CREATE_SUSPENDED
                    | win32::CREATE_UNICODE_ENVIRONMENT
                    | win32::EXTENDED_STARTUPINFO_PRESENT,
                environment.as_ptr().cast(),
                std::ptr::null(),
                &raw const startup.StartupInfo,
                &raw mut information,
            )
        } == 0
        {
            return last_error();
        }
        // SAFETY: Both handles came from the call that just succeeded.
        let (process, thread) =
            unsafe { (owned(information.hProcess), owned(information.hThread)) };
        let process = Process {
            handle: process,
            id: information.dwProcessId,
            stop_event,
        };
        // Suspended until it is in the job, so nothing it starts escapes it.
        let resumed = job().and_then(|job| {
            // SAFETY: Both handles are open.
            if unsafe { win32::AssignProcessToJobObject(job, raw(&process.handle)) } == 0 {
                return last_error();
            }
            // SAFETY: The thread handle is open.
            if unsafe { win32::ResumeThread(raw(&thread)) } == u32::MAX {
                return last_error();
            }
            Ok(())
        });
        if let Err(error) = resumed {
            process.kill();
            return Err(error);
        }
        // SAFETY: Changes a flag of a handle `process` owns.
        unsafe {
            win32::SetHandleInformation(raw(&process.stop_event), win32::HANDLE_FLAG_INHERIT, 0)
        };
        Ok((process, channel))
    })();
    started.with_context(|| "Could not create the supervised DNS child process")
}

fn inheritable_event() -> io::Result<OwnedHandle> {
    let mut security = win32::SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<win32::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: Creates an unnamed manual-reset event; the result is checked before use.
    let event = unsafe { win32::CreateEventW((&raw mut security).cast(), 1, 0, std::ptr::null()) };
    if event.is_null() {
        return last_error();
    }
    // SAFETY: A new handle that nothing else owns.
    Ok(unsafe { owned(event as win32::HANDLE) })
}

/// None when this process has no such handle, as a service does not.
fn inheritable_copy_of_standard(which: u32) -> Option<OwnedHandle> {
    // SAFETY: Takes no pointers.
    let handle = unsafe { win32::GetStdHandle(which) };
    if handle == 0 || handle == -1 {
        return None;
    }
    let mut copy = 0;
    // SAFETY: Duplicates within this process; the result is checked before use.
    let duplicated = unsafe {
        win32::DuplicateHandle(
            win32::GetCurrentProcess(),
            handle,
            win32::GetCurrentProcess(),
            &raw mut copy,
            0,
            1,
            win32::DUPLICATE_SAME_ACCESS,
        )
    };
    // SAFETY: A new handle that nothing else owns.
    (duplicated != 0).then(|| unsafe { owned(copy) })
}

/// PROC_THREAD_ATTRIBUTE_HANDLE_LIST naming `handles`, which must outlive it.
struct HandleList<'a> {
    /// Eight-byte units, so the list is aligned for the pointers in it.
    storage: Vec<u64>,
    _handles: &'a [win32::HANDLE],
}

impl<'a> HandleList<'a> {
    fn new(handles: &'a [win32::HANDLE]) -> io::Result<Self> {
        let mut size = 0usize;
        // SAFETY: Asks for the size only; this call fails by design and sets `size`.
        unsafe {
            win32::InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &raw mut size)
        };
        let mut storage = vec![0u64; size.div_ceil(8)];
        // SAFETY: `storage` holds at least `size` bytes.
        if unsafe {
            win32::InitializeProcThreadAttributeList(
                storage.as_mut_ptr().cast(),
                1,
                0,
                &raw mut size,
            )
        } == 0
        {
            return last_error();
        }
        let mut list = Self {
            storage,
            _handles: handles,
        };
        // SAFETY: The list was initialized above; the handles outlive it, as the lifetime says.
        if unsafe {
            win32::UpdateProcThreadAttribute(
                list.list(),
                0,
                win32::PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } == 0
        {
            return last_error();
        }
        Ok(list)
    }

    fn list(&mut self) -> *mut c_void {
        self.storage.as_mut_ptr().cast()
    }
}

impl Drop for HandleList<'_> {
    fn drop(&mut self) {
        // SAFETY: Initialized in `new`, and deleted once.
        unsafe { win32::DeleteProcThreadAttributeList(self.list()) };
    }
}

/// The job every worker runs in. Closing its last handle, which happens when the supervisor ends,
/// ends the workers.
fn job() -> io::Result<win32::HANDLE> {
    static JOB: OnceLock<OwnedHandle> = OnceLock::new();
    if let Some(job) = JOB.get() {
        return Ok(raw(job));
    }
    // SAFETY: Creates an unnamed job; the result is checked before use.
    let job = unsafe { win32::CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job == 0 {
        return last_error();
    }
    // SAFETY: A new handle that nothing else owns.
    let job = unsafe { owned(job) };
    let mut limits = win32::JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = win32::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: `limits` is the structure this class names, with its size.
    if unsafe {
        win32::SetInformationJobObject(
            raw(&job),
            win32::JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            (&raw const limits).cast(),
            std::mem::size_of_val(&limits) as u32,
        )
    } == 0
    {
        return last_error();
    }
    Ok(raw(JOB.get_or_init(|| job)))
}

/// This process's environment with `extra` set, sorted by name as Windows keeps it.
fn environment_block(extra: &[(&str, OsString)]) -> Vec<u16> {
    let mut vars: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(name, _)| !extra.iter().any(|(set, _)| name.eq_ignore_ascii_case(set)))
        .collect();
    vars.extend(
        extra
            .iter()
            .map(|(name, value)| (OsString::from(name), value.clone())),
    );
    vars.sort_by_cached_key(|(name, _)| name.to_ascii_uppercase());
    let mut block = Vec::new();
    for (name, value) in &vars {
        block.extend(name.encode_wide());
        block.push(u16::from(b'='));
        block.extend(value.encode_wide());
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

/// Appends `arg` so the C runtime's command line parsing gives it back unchanged.
fn push_quoted(line: &mut Vec<u16>, arg: &OsStr) {
    let quote = u16::from(b'"');
    let backslash = u16::from(b'\\');
    let needs_quotes = arg.is_empty()
        || arg
            .encode_wide()
            .any(|unit| unit == u16::from(b' ') || unit == u16::from(b'\t') || unit == quote);
    if !needs_quotes {
        line.extend(arg.encode_wide());
        return;
    }
    line.push(quote);
    let mut backslashes = 0;
    for unit in arg.encode_wide() {
        if unit == backslash {
            backslashes += 1;
        } else {
            if unit == quote {
                // Doubles the backslashes before it and escapes the quote itself.
                line.extend(std::iter::repeat_n(backslash, backslashes + 1));
            }
            backslashes = 0;
        }
        line.push(unit);
    }
    // Backslashes before the closing quote are doubled so they do not escape it.
    line.extend(std::iter::repeat_n(backslash, backslashes));
    line.push(quote);
}

/// Bytes the system has available and the current worker uses.
pub(super) fn memory(current: &Process) -> Option<(u64, u64)> {
    let mut status = win32::MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<win32::MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    // SAFETY: `status` is sized as dwLength says.
    if unsafe { win32::GlobalMemoryStatusEx(&raw mut status) } == 0 {
        return None;
    }
    let mut counters = win32::PROCESS_MEMORY_COUNTERS {
        cb: std::mem::size_of::<win32::PROCESS_MEMORY_COUNTERS>() as u32,
        ..Default::default()
    };
    // SAFETY: `counters` is sized as cb says, and the process handle is open.
    if unsafe {
        win32::K32GetProcessMemoryInfo(raw(&current.handle), &raw mut counters, counters.cb)
    } == 0
    {
        return None;
    }
    Some((status.ullAvailPhys, counters.WorkingSetSize as u64))
}

/// Error codes of a crash are NTSTATUS values, read best in hexadecimal.
pub(super) fn status_text(status: ExitStatus) -> String {
    let code = status.code().unwrap_or_default() as u32;
    if code >= 0xC000_0000 {
        format!("exit=0x{code:08X}")
    } else {
        format!("exit={code}")
    }
}

/// A frame of `kind` carrying one end of a link, duplicated into `to`. The payload names the handle
/// there and the process at the other end, which sockets are passed to.
pub(super) fn with_stream(
    kind: u8,
    stream: Stream,
    to: &Process,
    peer: &Process,
) -> io::Result<Frame> {
    let mut duplicated = 0;
    // SAFETY: Duplicates a handle `stream` owns into a process this supervisor holds a handle to.
    if unsafe {
        win32::DuplicateHandle(
            win32::GetCurrentProcess(),
            raw(&stream),
            raw(&to.handle),
            &raw mut duplicated,
            0,
            0,
            win32::DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return last_error();
    }
    // Kernel handles fit in 32 bits.
    let handle = u32::try_from(duplicated).map_err(|_| io::ErrorKind::InvalidData)?;
    let mut frame = Frame::new(kind);
    let mut out = Writer(&mut frame.payload);
    out.u32(handle);
    out.u32(peer.id);
    Ok(frame)
}

pub(super) fn take_stream(frame: Frame) -> Result<Stream, LinkError> {
    if !frame.fds.is_empty() {
        return Err(LinkError::Unreadable);
    }
    let mut input = Reader(&frame.payload);
    let handle = input.u32()?;
    let peer = input.u32()?;
    input.finish()?;
    let pipe = owned_pipe(handle as win32::HANDLE).ok_or(LinkError::Unreadable)?;
    pipe.set_peer(peer);
    Ok(pipe)
}

/// Takes a pipe handle the supervisor put in this process, and keeps the processes this one starts
/// from inheriting it.
fn owned_pipe(handle: win32::HANDLE) -> Option<Stream> {
    // SAFETY: GetFileType only reads; a value that is not a handle fails.
    if handle <= 0 || unsafe { win32::GetFileType(handle) } != win32::FILE_TYPE_PIPE {
        return None;
    }
    // SAFETY: The supervisor named this pipe handle for this process alone, so nothing else here
    // owns it.
    let handle = unsafe { owned(handle) };
    // SAFETY: Changes a flag of the handle just taken.
    unsafe { win32::SetHandleInformation(raw(&handle), win32::HANDLE_FLAG_INHERIT, 0) };
    Some(Stream::from_handle(handle))
}

/// The handle came through the environment, so it is checked to be a pipe before this process owns
/// it.
pub(super) fn adopt(named: &str) -> BoxResult<Stream> {
    named
        .parse::<u32>()
        .ok()
        .and_then(|handle| owned_pipe(handle as win32::HANDLE))
        .ok_or_else(|| crate::anyhow!(format!("{named} does not name a supervisor channel handle")))
}

/// Shuts this worker down when the supervisor sets its stop event, as a signal does on Unix.
pub(super) fn prepare_worker() -> BoxResult<()> {
    let Some(named) = std::env::var_os(STOP_ENV) else {
        return Ok(());
    };
    std::env::remove_var(STOP_ENV);
    let handle = named
        .to_str()
        .and_then(|text| text.parse::<u32>().ok())
        .filter(|handle| *handle != 0)
        .ok_or_else(|| {
            crate::anyhow!("The supervisor named a stop event this version cannot use")
        })?;
    // SAFETY: The supervisor made this event inheritable for this process alone and named it
    // here, so nothing else in this process owns it.
    let event = unsafe { owned(handle as win32::HANDLE) };
    // SAFETY: Changes a flag of the handle just taken.
    unsafe { win32::SetHandleInformation(raw(&event), win32::HANDLE_FLAG_INHERIT, 0) };
    std::thread::Builder::new()
        .name("supervisor-stop".to_string())
        .spawn(move || {
            // SAFETY: Waits on the event this thread owns.
            if unsafe { win32::WaitForSingleObject(raw(&event), win32::INFINITE) }
                == win32::WAIT_OBJECT_0
            {
                crate::request_shutdown();
            }
        })
        .with_context(|| "Could not watch for the supervisor's stop request")?;
    Ok(())
}

/// Waits until the predecessor closes `link`, which it does after leaving the console.
pub(super) fn until_released(link: &Stream) -> BoxResult<crate::tui::Wait> {
    let link = link
        .try_clone()
        .with_context(|| "Could not watch the link to the running version")?;
    Ok(Box::new(move |done| {
        while !done.load(Ordering::Acquire) {
            if link.peer_closed() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        false
    }))
}

/// Workers start from the install path anyway; this supervisor stays the version it started as.
pub(super) fn follow_install() -> Result<(), String> {
    Ok(())
}

/// Nothing is handed down: this supervisor never replaces itself.
pub(super) fn adopted() -> BoxResult<Option<(Process, Stream)>> {
    Ok(None)
}

pub(super) fn handed_down_console() -> Option<ChildConsole> {
    None
}

pub(super) fn harden() -> BoxResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::channel::LINK;

    fn this_process() -> Process {
        let mut handle = 0;
        // SAFETY: Duplicates this process's pseudo handle into a real one.
        assert_ne!(
            unsafe {
                win32::DuplicateHandle(
                    win32::GetCurrentProcess(),
                    win32::GetCurrentProcess(),
                    win32::GetCurrentProcess(),
                    &raw mut handle,
                    0,
                    0,
                    win32::DUPLICATE_SAME_ACCESS,
                )
            },
            0
        );
        Process {
            // SAFETY: Just duplicated.
            handle: unsafe { owned(handle) },
            id: std::process::id(),
            stop_event: inheritable_event().unwrap(),
        }
    }

    #[test]
    /// The duplicated handle and the peer's PID ride in the payload; the receiver passes sockets
    /// to that PID.
    fn a_link_arrives_as_a_handle_in_the_receiving_process() {
        let us = this_process();
        let (ours, theirs) = wire::pair().unwrap();
        let link = with_stream(LINK, theirs, &us, &us).unwrap();
        assert_eq!((link.payload.len(), link.fds.len()), (8, 0));
        let taken = take_stream(link).unwrap();
        wire::send(&ours, &Frame::new(LINK)).unwrap();
        let frame = wire::recv(
            &taken,
            std::time::Instant::now() + Duration::from_secs(5),
            &|| false,
        )
        .unwrap();
        assert_eq!(frame.kind, LINK);
        assert!(take_stream(Frame::new(LINK)).is_err());
        assert!(adopt("0").is_err());
        assert!(adopt("x").is_err());
    }

    #[test]
    /// The C runtime splits the line back into the same arguments.
    fn arguments_survive_the_command_line() {
        let quoted = |arg: &str| {
            let mut line = Vec::new();
            push_quoted(&mut line, OsStr::new(arg));
            String::from_utf16(&line).unwrap()
        };
        assert_eq!(quoted("run"), "run");
        assert_eq!(quoted(""), "\"\"");
        assert_eq!(
            quoted(r"C:\Program Files\OnetDNS\OnetDNS.toml"),
            r#""C:\Program Files\OnetDNS\OnetDNS.toml""#
        );
        assert_eq!(quoted(r"C:\dir with space\"), r#""C:\dir with space\\""#);
        assert_eq!(quoted(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(quoted(r#"a\"b c"#), r#""a\\\"b c""#);
    }

    #[test]
    fn the_environment_block_is_sorted_and_doubly_terminated() {
        let block = environment_block(&[
            ("ONETDNS_TEST_B", "2".into()),
            ("onetdns_test_a", "1".into()),
        ]);
        assert_eq!(&block[block.len() - 2..], [0, 0]);
        let text = String::from_utf16(&block).unwrap();
        let names: Vec<String> = text
            .split('\0')
            .filter(|entry| !entry.is_empty())
            .map(|entry| entry.split('=').next().unwrap().to_ascii_uppercase())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        assert!(text.contains("onetdns_test_a=1\0"));
        assert!(text.contains("ONETDNS_TEST_B=2\0"));
    }
}
