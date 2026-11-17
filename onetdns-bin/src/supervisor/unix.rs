//! Linux starts workers from this supervisor's own image through /proc/self/exe; macOS has no such
//! path and starts them from the install path. On both, a successor that took over is handed to the
//! supervisor of its own version by exec.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::sync::atomic::Ordering;

use super::channel::CHANNEL_ENV;
use super::supervise::{Worker, WorkerCommand};
use crate::error::{BoxResult, Context};
use crate::handoff::wire::{Frame, Stream};
use crate::handoff::LinkError;
use crate::tui::ChildConsole;

/// The image this parent is running. The install path would name another version after an
/// update's rename, or gain a ` (deleted)` suffix.
#[cfg(target_os = "linux")]
pub(super) const SELF_IMAGE: &str = "/proc/self/exe";
/// Set when a supervisor execs a new version: the PID of the worker it hands down and the
/// descriptor of its end of that worker's channel.
const ADOPT_ENV: &str = "ONETDNS_SUPERVISOR_ADOPT";
/// The terminal settings handed down with it.
const CONSOLE_ENV: &str = "ONETDNS_SUPERVISOR_CONSOLE";
#[cfg(target_os = "linux")]
const PR_SET_DUMPABLE: libc::c_int = 4;

pub(super) struct Process {
    pid: libc::pid_t,
}

impl Process {
    pub(super) fn id(&self) -> u32 {
        self.pid as u32
    }

    pub(super) fn try_wait(&self) -> io::Result<Option<ExitStatus>> {
        let mut status = 0;
        loop {
            // SAFETY: `status` is valid for writing; WNOHANG returns at once.
            let rc = unsafe { libc::waitpid(self.pid, &raw mut status, libc::WNOHANG) };
            match rc {
                0 => return Ok(None),
                pid if pid == self.pid => return Ok(Some(ExitStatus::from_raw(status))),
                _ => {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                }
            }
        }
    }

    pub(super) fn wait(&self) -> io::Result<ExitStatus> {
        let mut status = 0;
        loop {
            // SAFETY: `status` is valid for writing.
            let rc = unsafe { libc::waitpid(self.pid, &raw mut status, 0) };
            if rc == self.pid {
                return Ok(ExitStatus::from_raw(status));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    /// Asks it to shut down.
    pub(super) fn stop(&self) {
        self.signal(libc::SIGTERM);
    }

    pub(super) fn kill(&self) {
        self.signal(libc::SIGKILL);
    }

    fn signal(&self, signal: libc::c_int) {
        // SAFETY: Signals a child this process has not reaped, so the PID is still its.
        let result = unsafe { libc::kill(self.pid, signal) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                onetdns_core::warn!(event = "supervisor.shutdown_signal_failed", pid = self.pid, %error, "Supervisor could not forward the shutdown signal to the DNS service");
            }
        }
    }
}

/// A worker restarted after a crash runs this supervisor's own version.
#[cfg(target_os = "linux")]
pub(super) fn worker_image() -> BoxResult<PathBuf> {
    Ok(PathBuf::from(SELF_IMAGE))
}

/// After an update's rename no path names this supervisor's own image, so workers run the install
/// path. The supervisor execs the version it holds once that version is confirmed.
#[cfg(target_os = "macos")]
pub(super) fn worker_image() -> BoxResult<PathBuf> {
    crate::update::install::current()
        .map(|install| install.path().to_path_buf())
        .map_err(|reason| crate::anyhow!(reason))
}

pub(super) fn spawn(command: &WorkerCommand) -> BoxResult<(Process, Stream)> {
    let (channel, worker_end) = UnixStream::pair()
        .with_context(|| "Could not create the channel to the DNS service process")?;
    let worker_fd = worker_end.as_raw_fd();
    let mut process = Command::new(command.image);
    process.arg0(command.program);
    process.args(&command.args);
    for (name, value) in &command.env {
        process.env(name, value);
    }
    process.env(CHANNEL_ENV, worker_fd.to_string());
    #[cfg(target_os = "linux")]
    crate::osnet::harden_child_env(&mut process);
    // SAFETY: Runs between fork and exec and calls only fcntl, which is async-signal-safe. The
    // worker's end is the one descriptor kept open across exec.
    unsafe {
        process.pre_exec(move || {
            if libc::fcntl(worker_fd, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = process
        .spawn()
        .with_context(|| "Could not create the supervised DNS child process")?;
    drop(worker_end);
    Ok((
        Process {
            pid: child.id() as libc::pid_t,
        },
        channel,
    ))
}

/// The worker a supervisor of the previous version handed down when it exec'd this one.
pub(super) fn adopted() -> BoxResult<Option<(Process, Stream)>> {
    let Some(named) = std::env::var_os(ADOPT_ENV) else {
        return Ok(None);
    };
    std::env::remove_var(ADOPT_ENV);
    let invalid = || {
        crate::anyhow!(
            "The previous supervisor handed down a DNS service process this version cannot find"
        )
    };
    let (pid, fd) = named
        .to_str()
        .and_then(|text| text.split_once(':'))
        .ok_or_else(invalid)?;
    let pid: libc::pid_t = pid.parse().map_err(|_| invalid())?;
    if pid <= 0 {
        return Err(invalid());
    }
    let channel = adopt(fd)?;
    channel
        .set_nonblocking(true)
        .with_context(|| "Could not use the channel to the DNS service process")?;
    Ok(Some((Process { pid }, channel)))
}

/// The terminal settings a supervisor of the previous version handed down with its worker.
pub(super) fn handed_down_console() -> Option<ChildConsole> {
    let text = std::env::var(CONSOLE_ENV).ok();
    std::env::remove_var(CONSOLE_ENV);
    ChildConsole::decode(&text?)
}

/// Replaces this supervisor with the installed version, which goes on supervising `worker`.
/// Returns only when exec failed, with the reason.
pub(super) fn exec_adopting(worker: &Worker, console: Option<&ChildConsole>) -> String {
    let install = match crate::update::install::current() {
        Ok(install) => install,
        Err(reason) => return reason,
    };
    let fd = worker.channel.as_raw_fd();
    // SAFETY: Clears close-on-exec on a descriptor this process owns, so the new image keeps it.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } < 0 {
        return format!(
            "Could not keep the channel to the DNS service process open: {}",
            io::Error::last_os_error()
        );
    }
    let mut command = crate::update::launch::installed_command(install);
    command.env(ADOPT_ENV, format!("{}:{fd}", worker.process.pid));
    if let Some(console) = console {
        command.env(CONSOLE_ENV, console.encode());
    }
    let error = command.exec();
    // SAFETY: Same descriptor; puts the flag back.
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    format!("Could not start {}: {error}", install.path().display())
}

/// Replaces this process with the installed version. Returns only when exec failed, with the
/// reason.
pub(super) fn follow_install() -> Result<(), String> {
    Err(match crate::update::install::current() {
        Ok(install) => format!(
            "Could not start {}: {}",
            install.path().display(),
            crate::update::launch::exec_installed(install)
        ),
        Err(reason) => reason,
    })
}

/// Workers inherit the core limit.
pub(super) fn harden() -> BoxResult<()> {
    disable_core_dumps()
        .with_context(|| "Could not disable core dumps in the supervisor process")?;
    #[cfg(target_os = "linux")]
    disable_process_dumping()
        .with_context(|| "Could not make the supervisor process non-dumpable")?;
    Ok(())
}

/// A dump would hold keys and tokens, and writing a large one delays the restart.
fn disable_core_dumps() -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn disable_process_dumping() -> io::Result<()> {
    if unsafe { libc::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A child started through `SELF_IMAGE` is named exe, which hides it from top, pgrep and OOM
/// records. Call before starting threads; they inherit the name.
#[cfg(target_os = "linux")]
fn restore_process_name() -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let Some(argv0) = std::env::args_os().next() else {
        return Ok(());
    };
    let Some(name) = Path::new(&argv0).file_name() else {
        return Ok(());
    };
    let name = std::ffi::CString::new(name.as_bytes())?;
    if unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Blocks dumps and restores the process name of a worker, before it starts threads.
#[cfg(target_os = "linux")]
pub(super) fn prepare_worker() -> BoxResult<()> {
    disable_process_dumping()
        .with_context(|| "Could not make the DNS child process non-dumpable")?;
    if let Err(error) = restore_process_name() {
        onetdns_core::warn!(event = "supervisor.process_name_failed", %error, "Could not restore the process name of the DNS service process; it is listed as exe");
    }
    Ok(())
}

/// A macOS worker starts from the install path, which gives it its name.
#[cfg(target_os = "macos")]
pub(super) fn prepare_worker() -> BoxResult<()> {
    Ok(())
}

/// Bytes the system has available and the current worker uses.
#[cfg(target_os = "linux")]
pub(super) fn memory(current: &Process) -> Option<(u64, u64)> {
    memory_of(&current.pid.to_string())
}

/// Bytes the system has available and this process uses.
#[cfg(target_os = "linux")]
pub(super) fn own_memory() -> Option<(u64, u64)> {
    memory_of("self")
}

/// `pid` names a directory under /proc.
#[cfg(target_os = "linux")]
fn memory_of(pid: &str) -> Option<(u64, u64)> {
    let read = |path: &str, field: &str| {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| kib(&text, field))
            .map(|kib| kib * 1024)
    };
    Some((
        read("/proc/meminfo", "MemAvailable:")?,
        read(&format!("/proc/{pid}/status"), "VmRSS:")?,
    ))
}

/// A field in kB from /proc/meminfo or /proc/<pid>/status.
#[cfg(target_os = "linux")]
fn kib(text: &str, field: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix(field))?
        .trim()
        .strip_suffix("kB")?
        .trim()
        .parse()
        .ok()
}

/// Bytes the system has available and the current worker uses.
#[cfg(target_os = "macos")]
pub(super) fn memory(current: &Process) -> Option<(u64, u64)> {
    memory_of(current.pid)
}

/// Bytes the system has available and this process uses.
#[cfg(target_os = "macos")]
pub(super) fn own_memory() -> Option<(u64, u64)> {
    memory_of(libc::pid_t::try_from(std::process::id()).ok()?)
}

/// Available is the share of memory the kernel reports for its memory pressure level.
#[cfg(target_os = "macos")]
fn memory_of(pid: libc::pid_t) -> Option<(u64, u64)> {
    let total: u64 = sysctl(c"hw.memsize")?;
    let level: libc::c_int = sysctl(c"kern.memorystatus_level")?;
    let level = u64::try_from(level).ok().filter(|level| *level <= 100)?;
    // SAFETY: All-zero bits are a valid proc_taskinfo.
    let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    // SAFETY: `info` is valid for `size` bytes.
    let filled =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTASKINFO, 0, (&raw mut info).cast(), size) };
    (filled == size).then_some((total / 100 * level, info.pti_resident_size))
}

/// A sysctl value exactly the size of `T`.
#[cfg(target_os = "macos")]
fn sysctl<T: Default>(name: &std::ffi::CStr) -> Option<T> {
    let mut value = T::default();
    let mut len = std::mem::size_of::<T>();
    // SAFETY: `value` is valid for `len` bytes, and nothing is written to the kernel.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&raw mut value).cast(),
            &raw mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0 && len == std::mem::size_of::<T>()).then_some(value)
}

pub(super) fn status_text(status: ExitStatus) -> String {
    match (status.code(), status.signal()) {
        (Some(code), _) => format!("exit={code}"),
        (_, Some(signal)) => format!("signal={signal}"),
        _ => "unknown".to_string(),
    }
}

/// A frame of `kind` carrying one end of a link. The descriptor goes to whichever process reads
/// the frame.
pub(super) fn with_stream(
    kind: u8,
    stream: Stream,
    _to: &Process,
    _peer: &Process,
) -> io::Result<Frame> {
    let mut frame = Frame::new(kind);
    frame.fds.push(stream.into());
    Ok(frame)
}

pub(super) fn take_stream(mut frame: Frame) -> Result<Stream, LinkError> {
    if !frame.payload.is_empty() || frame.fds.len() != 1 {
        return Err(LinkError::Unreadable);
    }
    Ok(UnixStream::from(frame.fds.remove(0)))
}

/// The descriptor came through the environment, so it is checked to be an open Unix stream socket
/// before this process owns it, and closed on exec so the processes it starts do not inherit it.
pub(super) fn adopt(named: &str) -> BoxResult<Stream> {
    let invalid = || {
        crate::anyhow!(format!(
            "{named} does not name a supervisor channel descriptor"
        ))
    };
    let fd: libc::c_int = named.parse().map_err(|_| invalid())?;
    if fd < 3 {
        return Err(invalid());
    }
    // SAFETY: F_GETFD only reads the descriptor flags; it fails on a descriptor that is not open.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(invalid());
    }
    let family = {
        // SAFETY: All-zero bits are a valid sockaddr_storage.
        let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        // SAFETY: `address` and `len` are valid for the size passed.
        let rc = unsafe { libc::getsockname(fd, (&raw mut address).cast(), &raw mut len) };
        (rc == 0).then_some(libc::c_int::from(address.ss_family))
    };
    let kind = {
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `value` and `len` are valid for the size passed.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&raw mut value).cast(),
                &raw mut len,
            )
        };
        (rc == 0).then_some(value)
    };
    if family != Some(libc::AF_UNIX) || kind != Some(libc::SOCK_STREAM) {
        return Err(invalid());
    }
    // SAFETY: Same descriptor, checked open above.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(invalid());
    }
    // SAFETY: Whoever named this descriptor passed it to this process alone, and the variable
    // naming it is gone, so nothing else owns it.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    debug_assert_eq!(owned.as_raw_fd(), fd);
    Ok(UnixStream::from(owned))
}

/// Waits until the predecessor closes `link`, which it does after leaving the console.
#[cfg(target_os = "linux")]
pub(super) fn until_released(link: &Stream) -> BoxResult<crate::tui::Wait> {
    let link = link
        .try_clone()
        .with_context(|| "Could not watch the link to the running version")?;
    Ok(Box::new(move |done| {
        let mut watched = libc::pollfd {
            fd: link.as_raw_fd(),
            events: libc::POLLRDHUP,
            revents: 0,
        };
        while !done.load(Ordering::Acquire) {
            // SAFETY: one pollfd, as the count says.
            match unsafe { libc::poll(&raw mut watched, 1, 200) } {
                0 => {}
                -1 if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => {}
                _ => return true,
            }
        }
        false
    }))
}

/// Waits until the predecessor closes `link`, which it does after leaving the console. The handoff
/// goes on over the same link meanwhile, so readable data must not end the wait: an edge-triggered
/// read filter wakes on each change, and only its end-of-file flag counts.
#[cfg(target_os = "macos")]
pub(super) fn until_released(link: &Stream) -> BoxResult<crate::tui::Wait> {
    let link = link
        .try_clone()
        .with_context(|| "Could not watch the link to the running version")?;
    // SAFETY: Takes no arguments.
    let queue = unsafe { libc::kqueue() };
    if queue < 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| "Could not watch the link to the running version");
    }
    // SAFETY: kqueue returned a new descriptor this process owns.
    let queue = unsafe { OwnedFd::from_raw_fd(queue) };
    let watch = libc::kevent {
        ident: link.as_raw_fd() as libc::uintptr_t,
        filter: libc::EVFILT_READ,
        flags: libc::EV_ADD | libc::EV_CLEAR,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    // SAFETY: One change and no event buffer, as the counts say.
    if unsafe {
        libc::kevent(
            queue.as_raw_fd(),
            &raw const watch,
            1,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error())
            .with_context(|| "Could not watch the link to the running version");
    }
    Ok(Box::new(move |done| {
        // Closing the watched descriptor would drop the filter.
        let _link = link;
        let wait = libc::timespec {
            tv_sec: 0,
            tv_nsec: 200_000_000,
        };
        // SAFETY: All-zero bits are a valid kevent.
        let mut event: libc::kevent = unsafe { std::mem::zeroed() };
        while !done.load(Ordering::Acquire) {
            // SAFETY: No changes and one event, as the counts say.
            match unsafe {
                libc::kevent(
                    queue.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    &raw mut event,
                    1,
                    &raw const wait,
                )
            } {
                1 if event.flags & libc::EV_EOF != 0 => return true,
                -1 if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted => {
                    return true
                }
                _ => {}
            }
        }
        false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::channel::LINK;

    #[test]
    #[cfg(target_os = "linux")]
    fn memory_figures_are_read_in_kib() {
        let meminfo = "MemTotal:       16318500 kB\nMemAvailable:    9841224 kB\n";
        assert_eq!(kib(meminfo, "MemAvailable:"), Some(9_841_224));
        assert_eq!(kib(meminfo, "MemFree:"), None);
        assert_eq!(kib("VmRSS:\t  51200 kB\n", "VmRSS:"), Some(51_200));
        assert_eq!(kib("VmRSS:\t  51200 MB\n", "VmRSS:"), None);
    }

    #[test]
    /// A link rides as the frame's one descriptor, with nothing in the payload.
    fn a_link_is_the_one_descriptor_of_its_frame() {
        let us = Process {
            pid: std::process::id() as libc::pid_t,
        };
        let (ours, _) = UnixStream::pair().unwrap();
        let link = with_stream(LINK, ours, &us, &us).unwrap();
        assert_eq!((link.payload.len(), link.fds.len()), (0, 1));
        assert!(take_stream(link).is_ok());
        assert!(take_stream(Frame::new(LINK)).is_err());
    }

    #[test]
    fn only_an_open_unix_stream_socket_is_adopted() {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        for named in ["", "x", "1", &udp.as_raw_fd().to_string(), "1000000"] {
            assert!(adopt(named).is_err(), "{named}");
        }
        let (ours, theirs) = UnixStream::pair().unwrap();
        let fd = OwnedFd::from(theirs);
        // SAFETY: Clears the flag on a descriptor this test owns.
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, 0) };
        let named = fd.as_raw_fd().to_string();
        std::mem::forget(fd);
        let adopted = adopt(&named).unwrap();
        // SAFETY: Reads the flags of a descriptor `adopted` owns.
        let flags = unsafe { libc::fcntl(adopted.as_raw_fd(), libc::F_GETFD) };
        assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
        drop(ours);
    }
}
