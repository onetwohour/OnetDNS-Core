//! Process supervisor. The parent loads no filters or caches, so it survives a child that runs
//! out of memory or is killed, and restarts it. It gives up when startup keeps failing.

#[cfg(any(test, target_os = "linux"))]
use std::time::Duration;

#[cfg(any(test, target_os = "linux"))]
const BASE_RESTART_DELAY: Duration = Duration::from_millis(10);
#[cfg(any(test, target_os = "linux"))]
const MAX_RESTART_DELAY: Duration = Duration::from_secs(5);
#[cfg(any(test, target_os = "linux"))]
/// Running this long resets the restart delay.
const STABLE_RUNTIME: Duration = Duration::from_secs(30);
#[cfg(any(test, target_os = "linux"))]
const MAX_STARTUP_FAILURES: u32 = 5;

#[cfg(any(test, target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestartDecision {
    RestartAfter(Duration),
    GiveUp,
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Default)]
struct RestartPolicy {
    crash_streak: u32,
    startup_failures: u32,
}

#[cfg(any(test, target_os = "linux"))]
impl RestartPolicy {
    /// Reaching ready clears the failure count, or occasional crashes of a long-running server
    /// would add up to giving up.
    fn child_exited(&mut self, ready: bool, runtime: Duration) -> RestartDecision {
        if !ready {
            self.startup_failures = self.startup_failures.saturating_add(1);
            if self.startup_failures >= MAX_STARTUP_FAILURES {
                return RestartDecision::GiveUp;
            }
        } else {
            self.startup_failures = 0;
        }

        if runtime >= STABLE_RUNTIME {
            self.crash_streak = 0;
        }
        let shift = self.crash_streak.min(9);
        self.crash_streak = self.crash_streak.saturating_add(1);
        let delay = BASE_RESTART_DELAY
            .saturating_mul(1u32 << shift)
            .min(MAX_RESTART_DELAY);
        RestartDecision::RestartAfter(delay)
    }
}

#[cfg(target_os = "linux")]
mod channel;

#[cfg(target_os = "linux")]
mod linux {
    use super::channel::{self, Hello};
    use super::{RestartDecision, RestartPolicy, MAX_STARTUP_FAILURES};
    use crate::error::{BoxResult, Context};
    use crate::handoff::wire::{self, Frame, FrameReader, PROTOCOL};
    use crate::handoff::LinkError;
    use crate::tui::ChildConsole;
    use crate::update::launch::UPDATE_EXIT_CODE;
    use crate::update::trial::{Startup, Trial};
    use crate::update::VERSION;
    use onetdns_config::Config;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// The image this parent is running. The install path would name another version after an
    /// update's rename, or gain a ` (deleted)` suffix.
    const SELF_IMAGE: &str = "/proc/self/exe";
    const RESTARTS_ENV: &str = "ONETDNS_SUPERVISOR_RESTARTS";
    const POLL_INTERVAL: Duration = Duration::from_millis(20);
    const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
    const PR_SET_DUMPABLE: libc::c_int = 4;

    /// A dump would hold keys and tokens, and writing a large one delays the restart.
    fn disable_core_dumps() -> std::io::Result<()> {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn disable_process_dumping() -> std::io::Result<()> {
        if unsafe { libc::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// A child started through `SELF_IMAGE` is named exe, which hides it from top, pgrep and OOM
    /// records. Call before starting threads; they inherit the name.
    fn restore_process_name() -> std::io::Result<()> {
        use std::os::unix::ffi::OsStrExt;

        let Some(argv0) = std::env::args_os().next() else {
            return Ok(());
        };
        let Some(name) = Path::new(&argv0).file_name() else {
            return Ok(());
        };
        let name = std::ffi::CString::new(name.as_bytes())?;
        if unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// A worker process and the supervisor's end of its channel.
    struct Worker {
        pid: libc::pid_t,
        channel: UnixStream,
        reader: FrameReader,
        /// Cleared once the worker closes its end.
        open: bool,
        greeted: bool,
        ready: bool,
        started: Instant,
    }

    impl Worker {
        /// Handles what the worker sent. Fails when it broke the protocol; the caller then ends it.
        fn poll(&mut self) -> Result<(), String> {
            while self.open {
                match self.reader.read(&self.channel) {
                    Ok(Some(frame)) => self.handle(frame)?,
                    Ok(None) => break,
                    Err(LinkError::Gone) => self.open = false,
                    Err(error) => return Err(error.to_string()),
                }
            }
            Ok(())
        }

        fn handle(&mut self, frame: Frame) -> Result<(), String> {
            if !self.greeted {
                let hello = Hello::read(&frame).map_err(|error| error.to_string())?;
                if (hello.protocol, hello.version.as_str()) != (PROTOCOL, VERSION) {
                    return Err(format!(
                        "It is version {} with handoff protocol {}, not {VERSION} with {PROTOCOL}",
                        hello.version, hello.protocol
                    ));
                }
                self.greeted = true;
                return wire::send(&self.channel, &Frame::new(channel::RUN))
                    .map_err(|error| format!("Could not answer it: {error}"));
            }
            if channel::is_bare(&frame, channel::READY) {
                self.ready = true;
                return Ok(());
            }
            Err(format!("It sent message kind {} out of turn", frame.kind))
        }

        fn try_wait(&self) -> std::io::Result<Option<ExitStatus>> {
            let mut status = 0;
            loop {
                // SAFETY: `status` is valid for writing; WNOHANG returns at once.
                let rc = unsafe { libc::waitpid(self.pid, &raw mut status, libc::WNOHANG) };
                match rc {
                    0 => return Ok(None),
                    pid if pid == self.pid => return Ok(Some(ExitStatus::from_raw(status))),
                    _ => {
                        let error = std::io::Error::last_os_error();
                        if error.kind() != std::io::ErrorKind::Interrupted {
                            return Err(error);
                        }
                    }
                }
            }
        }

        fn wait(&self) -> std::io::Result<ExitStatus> {
            let mut status = 0;
            loop {
                // SAFETY: `status` is valid for writing.
                let rc = unsafe { libc::waitpid(self.pid, &raw mut status, 0) };
                if rc == self.pid {
                    return Ok(ExitStatus::from_raw(status));
                }
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }

    /// `program` is the child's argv[0], the name ps and service managers show.
    fn spawn_child(
        program: &Path,
        config_path: Option<&Path>,
        no_web: bool,
        restarts: u64,
    ) -> BoxResult<Worker> {
        let (channel, worker_end) = UnixStream::pair()
            .with_context(|| "Could not create the channel to the DNS service process")?;
        channel
            .set_nonblocking(true)
            .with_context(|| "Could not create the channel to the DNS service process")?;
        let worker_fd = worker_end.as_raw_fd();
        let mut command = Command::new(SELF_IMAGE);
        command.arg0(program);
        command.arg("run");
        if let Some(path) = config_path {
            command.arg("--config").arg(path);
        }
        if no_web {
            command.arg("--no-web");
        }
        command.arg("--no-supervisor");
        command.env(channel::CHANNEL_ENV, worker_fd.to_string());
        command.env(RESTARTS_ENV, restarts.to_string());
        command.env(
            crate::update::install::INSTALL_PATH_ENV,
            crate::update::install::current()
                .map(|install| install.path().as_os_str().to_os_string())
                .unwrap_or_default(),
        );
        crate::osnet::harden_child_env(&mut command);
        // SAFETY: Runs between fork and exec and calls only fcntl, which is async-signal-safe. The
        // worker's end is the one descriptor kept open across exec.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(worker_fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let process = command
            .spawn()
            .with_context(|| "Could not create the supervised DNS child process")?;
        drop(worker_end);
        Ok(Worker {
            pid: process.id() as libc::pid_t,
            channel,
            reader: FrameReader::default(),
            open: true,
            greeted: false,
            ready: false,
            started: Instant::now(),
        })
    }

    fn signal_child(child: &Worker, signal: libc::c_int) {
        // SAFETY: Signals a child this process has not reaped, so the PID is still its.
        let result = unsafe { libc::kill(child.pid, signal) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                onetdns_core::warn!(event = "supervisor.shutdown_signal_failed", pid = child.pid, %error, "Supervisor could not forward the shutdown signal to the DNS service");
            }
        }
    }

    fn terminate_child(child: &Worker, console: Option<&ChildConsole>) {
        signal_child(child, libc::SIGTERM);
        let deadline = Instant::now() + SHUTDOWN_GRACE;
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if let Some(console) = console {
                        console.child_exited(status);
                    }
                    return;
                }
                Ok(None) => std::thread::sleep(POLL_INTERVAL),
                Err(error) => {
                    onetdns_core::warn!(event = "supervisor.child_wait_failed", pid = child.pid, %error, "Could not check the state of the exiting child process; killing it now");
                    break;
                }
            }
        }
        signal_child(child, libc::SIGKILL);
        match child.wait() {
            Ok(status) => {
                if let Some(console) = console {
                    console.child_exited(status);
                }
            }
            Err(error) => {
                onetdns_core::warn!(event = "supervisor.child_reap_failed", pid = child.pid, %error, "Could not reap the exited child process");
            }
        }
    }

    /// Returns false if a stop arrived first.
    fn sleep_until(delay: Duration, stop: &AtomicBool) -> bool {
        let deadline = Instant::now() + delay;
        while Instant::now() < deadline {
            if stop.load(Ordering::Acquire) {
                return false;
            }
            std::thread::sleep(
                POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
            );
        }
        !stop.load(Ordering::Acquire)
    }

    /// Replaces this process; returning means exec failed, with the reason.
    fn exec_install_path() -> String {
        match crate::update::install::current() {
            Ok(install) => format!(
                "Could not start {}: {}",
                install.path().display(),
                crate::update::launch::exec_installed(install)
            ),
            Err(reason) => reason,
        }
    }

    fn status_text(status: ExitStatus) -> String {
        use std::os::unix::process::ExitStatusExt;
        match (status.code(), status.signal()) {
            (Some(code), _) => format!("exit={code}"),
            (_, Some(signal)) => format!("signal={signal}"),
            _ => "unknown".to_string(),
        }
    }

    /// Also settles updates: a new version that exits before ready or misses its deadline is
    /// reverted, and a child's update exit execs the swapped executable.
    pub fn run(mut config_path: Option<PathBuf>, no_web: bool) -> BoxResult<()> {
        let mut trial = match crate::update::trial::on_start(&mut || {}) {
            Startup::Normal => None,
            Startup::Trial(trial) => Some(trial),
            Startup::Reverted => return Err(crate::anyhow!(exec_install_path())),
        };
        if config_path.is_none() && !no_web {
            config_path = crate::ensure_auto_config()?;
        }
        let program = std::env::current_exe()
            .with_context(|| "Could not find the path of the current executable")?;
        let config = Config::load_or_default(config_path.as_deref())?;
        let run_as = config
            .run_as_user
            .clone()
            .map(|user| (user, config.run_as_group.clone()));
        drop(config);
        disable_core_dumps()
            .with_context(|| "Could not disable core dumps in the supervisor process")?;
        disable_process_dumping()
            .with_context(|| "Could not make the supervisor process non-dumpable")?;

        let stop: Arc<AtomicBool> = crate::install_shutdown_handler();
        let console = ChildConsole::capture();
        let console = console.as_ref();
        let mut policy = RestartPolicy::default();
        let mut restarts = 0u64;
        let mut parent_privileges_dropped = run_as.is_none();

        loop {
            if stop.load(Ordering::Acquire) {
                return Ok(());
            }
            let mut child = spawn_child(&program, config_path.as_deref(), no_web, restarts)?;
            onetdns_core::info!(
                event = "supervisor.child_started",
                pid = child.pid,
                restarts,
                "Started the DNS service process"
            );

            let status = loop {
                if stop.load(Ordering::Acquire) {
                    terminate_child(&child, console);
                    return Ok(());
                }
                if let Err(error) = child.poll() {
                    onetdns_core::error!(event = "supervisor.child_refused", pid = child.pid, %error, "Stopping a DNS service process that does not follow the supervisor protocol");
                    signal_child(&child, libc::SIGKILL);
                    child.open = false;
                }
                if child.ready {
                    if let Some(trial) = trial.take() {
                        trial.commit();
                    }
                    if !parent_privileges_dropped {
                        let (user, group) = run_as.as_ref().expect("run_as is set");
                        if let Err(error) = crate::privdrop::drop_privileges(user, group.as_deref())
                        {
                            terminate_child(&child, console);
                            return Err(crate::anyhow!(format!(
                                "Stopping the service because the supervisor could not drop privileges: {error}"
                            )));
                        }
                        if let Err(error) =
                            crate::privdrop::executable_still_runnable(Path::new(SELF_IMAGE))
                        {
                            terminate_child(&child, console);
                            return Err(crate::anyhow!(format!(
                                "Stopping the service because {user} cannot run {} to restart the DNS service process: {error}",
                                program.display()
                            )));
                        }
                        parent_privileges_dropped = true;
                        onetdns_core::info!(
                            event = "supervisor.privdrop_applied",
                            user,
                            "Dropped the supervisor's privileges"
                        );
                    }
                }
                if trial.as_ref().is_some_and(Trial::expired)
                    && trial.take().is_some_and(Trial::revert_expired)
                {
                    terminate_child(&child, console);
                    return Err(crate::anyhow!(exec_install_path()));
                }
                match child.try_wait()? {
                    Some(status) => break status,
                    None => std::thread::sleep(POLL_INTERVAL),
                }
            };
            if let Some(console) = console {
                console.child_exited(status);
            }

            if stop.load(Ordering::Acquire) {
                return Ok(());
            }
            if let Some(trial) = trial.take() {
                let reason = format!(
                    "The new version exited before it became ready ({})",
                    status_text(status)
                );
                if trial.revert(&reason) {
                    return Err(crate::anyhow!(exec_install_path()));
                }
            } else if status.code() == Some(UPDATE_EXIT_CODE) {
                onetdns_core::info!(
                    event = "supervisor.update_exec",
                    "The DNS service process installed an update; starting the new version"
                );
                let error = exec_install_path();
                onetdns_core::error!(event = "supervisor.update_exec_failed", %error, "Could not start the new version; putting the previous executable back");
                if let Err(error) = crate::update::apply::undo_unstarted(&format!(
                    "Could not start the new version: {error}"
                )) {
                    onetdns_core::error!(event = "supervisor.update_undo_failed", %error, "Could not put the previous executable back; supervising the running version");
                }
                continue;
            }
            let runtime = child.started.elapsed();
            let ready = child.ready;
            match policy.child_exited(ready, runtime) {
                RestartDecision::GiveUp => {
                    return Err(crate::anyhow!(format!(
                        "The DNS child exited {MAX_STARTUP_FAILURES} times in a row before becoming ready ({})",
                        status_text(status)
                    )));
                }
                RestartDecision::RestartAfter(delay) => {
                    restarts = restarts.saturating_add(1);
                    onetdns_core::error!(event = "supervisor.child_restarted",
                        status = %status_text(status),
                        ready,
                        runtime_ms = runtime.as_millis(),
                        delay_ms = delay.as_millis(),
                        restarts,
                        "DNS service process exited abnormally; restarting it"
                    );
                    if !sleep_until(delay, &stop) {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// `None` when not supervised. Also blocks dumps and restores the process name, so call it
    /// before starting threads.
    pub fn take_ready_callback() -> BoxResult<Option<Box<dyn FnOnce() + Send>>> {
        if std::env::var_os(channel::CHANNEL_ENV).is_none() {
            return Ok(None);
        }
        disable_process_dumping()
            .with_context(|| "Could not make the DNS child process non-dumpable")?;
        if let Err(error) = restore_process_name() {
            onetdns_core::warn!(event = "supervisor.process_name_failed", %error, "Could not restore the process name of the DNS service process; it is listed as exe");
        }
        channel::join()?;
        Ok(Some(Box::new(|| {
            if let Err(error) = channel::ready() {
                crate::tui::leave();
                onetdns_core::error!(event = "supervisor.ready_signal_failed", %error, "Could not send the service ready signal; aborting startup");
                std::process::exit(1);
            }
        })))
    }
}

#[cfg(target_os = "linux")]
pub use linux::{run, take_ready_callback};

#[cfg(not(target_os = "linux"))]
pub fn take_ready_callback() -> crate::error::BoxResult<Option<Box<dyn FnOnce() + Send>>> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_failures_are_bounded() {
        let mut policy = RestartPolicy::default();
        for expected_ms in [10, 20, 40, 80] {
            assert_eq!(
                policy.child_exited(false, Duration::from_millis(1)),
                RestartDecision::RestartAfter(Duration::from_millis(expected_ms))
            );
        }
        assert_eq!(
            policy.child_exited(false, Duration::from_millis(1)),
            RestartDecision::GiveUp
        );
    }

    #[test]
    fn ready_child_resets_startup_failures_and_backoff_is_capped() {
        let mut policy = RestartPolicy::default();
        for _ in 0..3 {
            let _ = policy.child_exited(false, Duration::from_millis(1));
        }
        let _ = policy.child_exited(true, Duration::from_secs(1));
        for _ in 0..20 {
            assert_ne!(
                policy.child_exited(true, Duration::from_secs(1)),
                RestartDecision::GiveUp
            );
        }
        assert_eq!(
            policy.child_exited(true, Duration::from_secs(1)),
            RestartDecision::RestartAfter(MAX_RESTART_DELAY)
        );
    }

    #[test]
    fn stable_runtime_resets_restart_delay() {
        let mut policy = RestartPolicy::default();
        let _ = policy.child_exited(true, Duration::from_secs(1));
        let _ = policy.child_exited(true, Duration::from_secs(1));
        assert_eq!(
            policy.child_exited(true, STABLE_RUNTIME),
            RestartDecision::RestartAfter(BASE_RESTART_DELAY)
        );
    }
}
