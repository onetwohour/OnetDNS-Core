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

/// How this process runs under the supervisor that started it.
#[derive(Default)]
pub struct Joined {
    /// Tells the supervisor this process is ready. None without a supervisor.
    pub ready: Option<Box<dyn FnOnce() + Send>>,
    /// Set for a successor: waits until the process it takes over from lets go of the terminal.
    pub console: Option<crate::tui::Wait>,
}

#[cfg(target_os = "linux")]
mod channel;

#[cfg(target_os = "linux")]
mod linux {
    use super::channel::{self, Hello, Reply, Start};
    use super::{Joined, RestartDecision, RestartPolicy, MAX_STARTUP_FAILURES};
    use crate::error::{BoxResult, Context};
    use crate::handoff::wire::{self, Frame, FrameReader, PROTOCOL};
    use crate::handoff::{Link, LinkError, Links};
    use crate::tui::ChildConsole;
    use crate::update::launch::UPDATE_EXIT_CODE;
    use crate::update::trial::{Startup, Trial};
    use crate::update::VERSION;
    use onetdns_config::Config;
    use onetdns_core::MutexExt;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, OnceLock};
    use std::time::{Duration, Instant};

    /// The image this parent is running. The install path would name another version after an
    /// update's rename, or gain a ` (deleted)` suffix.
    const SELF_IMAGE: &str = "/proc/self/exe";
    const RESTARTS_ENV: &str = "ONETDNS_SUPERVISOR_RESTARTS";
    /// Set when a supervisor execs a new version: the PID of the worker it hands down and the
    /// descriptor of its end of that worker's channel.
    const ADOPT_ENV: &str = "ONETDNS_SUPERVISOR_ADOPT";
    /// The terminal settings handed down with it.
    const CONSOLE_ENV: &str = "ONETDNS_SUPERVISOR_CONSOLE";
    const POLL_INTERVAL: Duration = Duration::from_millis(20);
    const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
    /// A successor that has not introduced itself by then is stopped.
    const HELLO_WAIT: Duration = Duration::from_secs(30);
    /// How long the previous worker may take to end once its successor runs everything.
    const END_GRACE: Duration = Duration::from_secs(30);
    /// The predecessor introduces itself as soon as it gets the link.
    const INTRODUCTION_WAIT: Duration = Duration::from_secs(30);
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
        /// Its hello, until the supervisor answers it.
        hello: Option<Hello>,
        answered: bool,
        ready: bool,
        /// Asked for a successor; cleared when the supervisor takes up the request.
        wants_successor: bool,
        /// Runs the install path rather than this supervisor's image.
        installed: bool,
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
            if !self.answered && self.hello.is_none() {
                let hello = Hello::read(&frame).map_err(|error| error.to_string())?;
                if hello.protocol != PROTOCOL {
                    return Err(format!(
                        "It is version {} with handoff protocol {}, not {PROTOCOL}",
                        hello.version, hello.protocol
                    ));
                }
                self.hello = Some(hello);
                return Ok(());
            }
            if self.answered && !self.ready && channel::is_bare(&frame, channel::READY) {
                self.ready = true;
                return Ok(());
            }
            if self.ready && !self.wants_successor && channel::is_bare(&frame, channel::SUCCESSOR) {
                self.wants_successor = true;
                return Ok(());
            }
            Err(format!("It sent message kind {} out of turn", frame.kind))
        }

        /// Lets a worker started from this supervisor's image run on its own.
        fn answer_run(&mut self) -> Result<(), String> {
            let Some(hello) = self.hello.take() else {
                return Ok(());
            };
            if hello.version != VERSION {
                return Err(format!("It is version {}, not {VERSION}", hello.version));
            }
            self.answered = true;
            wire::send(&self.channel, &Frame::new(channel::RUN))
                .map_err(|error| format!("Could not answer it: {error}"))
        }

        fn tell(&self, frame: &Frame) {
            if let Err(error) = wire::send(&self.channel, frame) {
                onetdns_core::warn!(event = "supervisor.send_failed", pid = self.pid, kind = frame.kind, %error, "Could not tell the DNS service process how the update went");
            }
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

    /// Starts `image` as a worker. `program` is its argv[0], the name ps and service managers show.
    fn spawn_worker(
        image: &Path,
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
        let mut command = Command::new(image);
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
            hello: None,
            answered: false,
            ready: false,
            wants_successor: false,
            installed: image != Path::new(SELF_IMAGE),
            started: Instant::now(),
        })
    }

    /// The worker a supervisor of the previous version handed down when it exec'd this one.
    fn adopted_worker() -> BoxResult<Option<Worker>> {
        let Some(named) = std::env::var_os(ADOPT_ENV) else {
            return Ok(None);
        };
        std::env::remove_var(ADOPT_ENV);
        let invalid = || {
            crate::anyhow!("The previous supervisor handed down a DNS service process this version cannot find")
        };
        let (pid, fd) = named
            .to_str()
            .and_then(|text| text.split_once(':'))
            .ok_or_else(invalid)?;
        let pid: libc::pid_t = pid.parse().map_err(|_| invalid())?;
        if pid <= 0 {
            return Err(invalid());
        }
        let channel = channel::adopt(fd)?;
        channel
            .set_nonblocking(true)
            .with_context(|| "Could not use the channel to the DNS service process")?;
        Ok(Some(Worker {
            pid,
            channel,
            reader: FrameReader::default(),
            open: true,
            hello: None,
            answered: true,
            ready: true,
            wants_successor: false,
            installed: false,
            started: Instant::now(),
        }))
    }

    /// Replaces this supervisor with the installed version, which goes on supervising `worker`.
    /// Returns only when exec failed, with the reason.
    fn exec_adopting(worker: &Worker, console: Option<&ChildConsole>) -> String {
        let install = match crate::update::install::current() {
            Ok(install) => install,
            Err(reason) => return reason,
        };
        let fd = worker.channel.as_raw_fd();
        // SAFETY: Clears close-on-exec on a descriptor this process owns, so the new image keeps it.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } < 0 {
            return format!(
                "Could not keep the channel to the DNS service process open: {}",
                std::io::Error::last_os_error()
            );
        }
        let mut command = crate::update::launch::installed_command(install);
        command.env(ADOPT_ENV, format!("{}:{fd}", worker.pid));
        if let Some(console) = console {
            command.env(CONSOLE_ENV, console.encode());
        }
        let error = command.exec();
        // SAFETY: Same descriptor; puts the flag back.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        format!("Could not start {}: {error}", install.path().display())
    }

    /// The successor runs beside the current worker until it takes over, so it needs about as
    /// much memory again. Figures that cannot be read do not stop it.
    fn room_for_successor(pid: libc::pid_t) -> Result<(), String> {
        let read = |path: &str, field: &str| {
            std::fs::read_to_string(path)
                .ok()
                .and_then(|text| kib(&text, field))
        };
        let available = read("/proc/meminfo", "MemAvailable:");
        let used = read(&format!("/proc/{pid}/status"), "VmRSS:");
        match (available, used) {
            (Some(available), Some(used)) if available < used => Err(format!(
                "{} MiB of memory is available, and the new version needs about {} MiB beside the running one",
                available / 1024,
                used / 1024
            )),
            _ => Ok(()),
        }
    }

    /// A field in kB from /proc/meminfo or /proc/<pid>/status.
    fn kib(text: &str, field: &str) -> Option<u64> {
        text.lines()
            .find_map(|line| line.strip_prefix(field))?
            .trim()
            .strip_suffix("kB")?
            .trim()
            .parse()
            .ok()
    }

    /// A worker started from the install path to take over from the current one.
    struct Successor {
        worker: Worker,
        /// Set from its introduction until it is ready: its version is on trial, and the current
        /// worker holds the link to it.
        trial: Option<Trial>,
    }

    enum Failure {
        /// Still running.
        Refused(String),
        /// Exited and reaped.
        Exited(String),
        /// Its trial ran out.
        Expired,
    }

    /// The current worker was told to end because its successor runs everything.
    struct Ending {
        deadline: Instant,
        killed: bool,
    }

    impl Successor {
        fn start(
            program: &Path,
            config_path: Option<&Path>,
            no_web: bool,
            restarts: u64,
            current: &Worker,
        ) -> Result<Self, String> {
            room_for_successor(current.pid)?;
            let install = crate::update::install::current()?;
            let worker = spawn_worker(install.path(), program, config_path, no_web, restarts)
                .map_err(|error| error.to_string())?;
            onetdns_core::info!(
                event = "supervisor.successor_started",
                pid = worker.pid,
                "Started the new version beside the running one"
            );
            Ok(Self {
                worker,
                trial: None,
            })
        }

        /// Moves it along once; ending the current worker once it is ready.
        fn step(&mut self, current: &Worker, ending: &mut Option<Ending>) -> Option<Failure> {
            let worker = &mut self.worker;
            if let Err(error) = worker.poll() {
                return Some(Failure::Refused(format!(
                    "The new version does not follow the supervisor protocol: {error}"
                )));
            }
            if let Some(hello) = worker.hello.take() {
                worker.answered = true;
                match crate::update::trial::for_successor(&hello.version) {
                    Ok(trial) => self.trial = Some(trial),
                    Err(reason) => return Some(Failure::Refused(reason)),
                }
                match link(worker, current) {
                    Ok(()) => {}
                    // It ended and closed its channel; the exit check below says how.
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                        ) => {}
                    Err(error) => {
                        return Some(Failure::Refused(format!(
                            "Could not connect the new version to the running one: {error}"
                        )))
                    }
                }
            }
            if worker.ready {
                if ending.is_none() {
                    if let Some(trial) = self.trial.take() {
                        trial.commit();
                    }
                    current.tell(&Frame::new(channel::END));
                    *ending = Some(Ending {
                        deadline: Instant::now() + END_GRACE,
                        killed: false,
                    });
                }
                return None;
            }
            if !worker.answered && worker.started.elapsed() >= HELLO_WAIT {
                return Some(Failure::Refused(
                    "The new version did not start in time".to_string(),
                ));
            }
            if self.trial.as_ref().is_some_and(Trial::expired) {
                return Some(Failure::Expired);
            }
            match worker.try_wait() {
                Ok(None) => None,
                Ok(Some(status)) => Some(Failure::Exited(format!(
                    "The new version exited before it became ready ({})",
                    status_text(status)
                ))),
                Err(error) => Some(Failure::Exited(format!(
                    "Could not check the state of the new version: {error}"
                ))),
            }
        }

        /// Stops it unless it exited, and tells the current worker: an update on trial was put
        /// back and it serves on; otherwise it restarts the way it does without a successor.
        fn give_up(self, current: Option<&Worker>, failure: Failure) {
            let Successor { worker, trial } = self;
            if !matches!(failure, Failure::Exited(_)) {
                signal_child(&worker, libc::SIGKILL);
                if let Err(error) = worker.wait() {
                    onetdns_core::warn!(event = "supervisor.child_reap_failed", pid = worker.pid, %error, "Could not reap the exited child process");
                }
            }
            let reason = match &failure {
                Failure::Refused(reason) | Failure::Exited(reason) => reason.as_str(),
                Failure::Expired => "The new version did not become ready in time",
            };
            match trial {
                Some(trial) => {
                    match failure {
                        Failure::Expired => trial.revert_expired(),
                        _ => trial.revert(reason),
                    };
                    if let Some(current) = current {
                        current.tell(&Frame::new(channel::CANCEL));
                    }
                }
                None => {
                    onetdns_core::warn!(event = "supervisor.successor_failed", %reason, "The new version cannot take over beside the running one; the running one restarts into it");
                    if let Some(current) = current {
                        current.tell(&channel::no_successor(reason));
                    }
                }
            }
        }
    }

    /// Gives the successor its end of a new link to take over through, and the current worker its
    /// end to hand over through.
    fn link(successor: &Worker, current: &Worker) -> std::io::Result<()> {
        let (handing, taking) = UnixStream::pair()?;
        wire::send(
            &successor.channel,
            &channel::with_stream(channel::TAKE_OVER, taking),
        )?;
        current.tell(&channel::with_stream(channel::LINK, handing));
        Ok(())
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
        match (status.code(), status.signal()) {
            (Some(code), _) => format!("exit={code}"),
            (_, Some(signal)) => format!("signal={signal}"),
            _ => "unknown".to_string(),
        }
    }

    /// Also settles updates: a new version that exits before ready or misses its deadline is
    /// reverted, a child's update exit execs the swapped executable, and a successor that took over
    /// is handed to the supervisor of its own version by exec.
    pub fn run(mut config_path: Option<PathBuf>, no_web: bool) -> BoxResult<()> {
        let mut next = adopted_worker()?;
        // A supervisor that hands a worker down has settled that worker's trial.
        let mut trial = if next.is_some() {
            None
        } else {
            match crate::update::trial::on_start(&mut || {}) {
                Startup::Normal => None,
                Startup::Trial(trial) => Some(trial),
                Startup::Reverted => return Err(crate::anyhow!(exec_install_path())),
            }
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
        let handed_down = std::env::var(CONSOLE_ENV).ok();
        std::env::remove_var(CONSOLE_ENV);
        let console = match (&next, handed_down) {
            (Some(_), Some(text)) => ChildConsole::decode(&text),
            (Some(_), None) => None,
            (None, _) => ChildConsole::capture(),
        };
        let console = console.as_ref();
        let mut policy = RestartPolicy::default();
        let mut restarts = 0u64;
        let mut parent_privileges_dropped = run_as.is_none();

        loop {
            if stop.load(Ordering::Acquire) {
                return Ok(());
            }
            let mut child = match next.take() {
                Some(child) => child,
                None => {
                    let child = spawn_worker(
                        Path::new(SELF_IMAGE),
                        &program,
                        config_path.as_deref(),
                        no_web,
                        restarts,
                    )?;
                    onetdns_core::info!(
                        event = "supervisor.child_started",
                        pid = child.pid,
                        restarts,
                        "Started the DNS service process"
                    );
                    child
                }
            };
            let mut successor: Option<Successor> = None;
            let mut ending: Option<Ending> = None;

            let status = loop {
                if stop.load(Ordering::Acquire) {
                    if let Some(successor) = successor.take() {
                        terminate_child(&successor.worker, console);
                    }
                    terminate_child(&child, console);
                    return Ok(());
                }
                if let Err(error) = child.poll().and_then(|()| child.answer_run()) {
                    onetdns_core::error!(event = "supervisor.child_refused", pid = child.pid, %error, "Stopping a DNS service process that does not follow the supervisor protocol");
                    signal_child(&child, libc::SIGKILL);
                    child.open = false;
                }
                if let Some(failure) = successor
                    .as_mut()
                    .and_then(|successor| successor.step(&child, &mut ending))
                {
                    if let Some(successor) = successor.take() {
                        successor.give_up(Some(&child), failure);
                    }
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
                    if child.installed {
                        onetdns_core::info!(
                            event = "supervisor.update_exec",
                            "Starting the supervisor of the new version"
                        );
                        let error = exec_adopting(&child, console);
                        onetdns_core::error!(event = "supervisor.update_exec_failed", %error, "Could not start the supervisor of the new version; this one goes on, and restarts the previous version if the DNS service process stops");
                        child.installed = false;
                    }
                }
                if trial.as_ref().is_some_and(Trial::expired)
                    && trial.take().is_some_and(Trial::revert_expired)
                {
                    terminate_child(&child, console);
                    return Err(crate::anyhow!(exec_install_path()));
                }
                if child.wants_successor {
                    child.wants_successor = false;
                    if successor.is_some() || ending.is_some() {
                        child.tell(&channel::no_successor(
                            "A new version is already taking over",
                        ));
                    } else {
                        match Successor::start(
                            &program,
                            config_path.as_deref(),
                            no_web,
                            restarts,
                            &child,
                        ) {
                            Ok(started) => successor = Some(started),
                            Err(reason) => {
                                onetdns_core::warn!(event = "supervisor.successor_failed", %reason, "The new version cannot take over beside the running one; the running one restarts into it");
                                child.tell(&channel::no_successor(&reason));
                            }
                        }
                    }
                }
                if let Some(ending) = ending.as_mut() {
                    if !ending.killed && Instant::now() >= ending.deadline {
                        onetdns_core::warn!(
                            event = "supervisor.predecessor_killed",
                            pid = child.pid,
                            "The previous version did not end after the new one took over; killing it"
                        );
                        signal_child(&child, libc::SIGKILL);
                        ending.killed = true;
                    }
                }
                match child.try_wait()? {
                    Some(status) => {
                        if let Some(taking) = successor.take() {
                            if taking.worker.answered {
                                onetdns_core::info!(
                                    event = "supervisor.predecessor_ended",
                                    status = %status_text(status),
                                    "The previous version ended; supervising the new one"
                                );
                                trial = taking.trial;
                                child = taking.worker;
                                ending = None;
                                continue;
                            }
                            taking.give_up(
                                None,
                                Failure::Refused(
                                    "The running version ended before the new one started"
                                        .to_string(),
                                ),
                            );
                        }
                        break status;
                    }
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

    /// Kept for the successor requests of the worker side.
    static LINKS: OnceLock<Arc<Links>> = OnceLock::new();
    /// Set from a successor request until the supervisor says this process serves on.
    static HANDING_OVER: AtomicBool = AtomicBool::new(false);

    /// Introduces this process to the supervisor that started it. A successor also takes the link
    /// to its predecessor into `links`. Blocks dumps and restores the process name, so call it
    /// before starting threads.
    pub fn join(links: &Arc<Links>) -> BoxResult<Joined> {
        if std::env::var_os(channel::CHANNEL_ENV).is_none() {
            return Ok(Joined::default());
        }
        disable_process_dumping()
            .with_context(|| "Could not make the DNS child process non-dumpable")?;
        if let Err(error) = restore_process_name() {
            onetdns_core::warn!(event = "supervisor.process_name_failed", %error, "Could not restore the process name of the DNS service process; it is listed as exe");
        }
        let _ = LINKS.set(links.clone());
        let Some(start) = channel::join()? else {
            return Ok(Joined::default());
        };
        let console = match start {
            Start::Fresh => None,
            Start::Successor(stream) => {
                let key = wire::introduced(&stream, Instant::now() + INTRODUCTION_WAIT).map_err(
                    |error| {
                        crate::anyhow!(format!(
                            "The running version did not introduce itself: {error}"
                        ))
                    },
                )?;
                onetdns_control::adopt_credential_key(&key)
                    .map_err(|error| crate::anyhow!(error))?;
                let watched = stream
                    .try_clone()
                    .with_context(|| "Could not watch the link to the running version")?;
                *links.predecessor.lock_recover() = Some(Link::over(stream));
                Some(until_released(watched))
            }
        };
        Ok(Joined {
            ready: Some(Box::new(|| {
                if let Err(error) = channel::ready() {
                    crate::tui::leave();
                    onetdns_core::error!(event = "supervisor.ready_signal_failed", %error, "Could not send the service ready signal; aborting startup");
                    std::process::exit(1);
                }
            })),
            console,
        })
    }

    /// The predecessor leaves the console before it lets go of the link.
    fn until_released(link: UnixStream) -> crate::tui::Wait {
        Box::new(move |done| {
            let mut watched = libc::pollfd {
                fd: link.as_raw_fd(),
                events: libc::POLLRDHUP,
                revents: 0,
            };
            while !done.load(Ordering::Acquire) {
                // SAFETY: one pollfd, as the count says.
                match unsafe { libc::poll(&raw mut watched, 1, 200) } {
                    0 => {}
                    -1 if std::io::Error::last_os_error().kind()
                        == std::io::ErrorKind::Interrupted => {}
                    _ => return true,
                }
            }
            false
        })
    }

    pub(crate) enum Requested {
        /// The new version is on trial, and the link to it waits in `Links::successor`.
        Linked,
        /// The new version failed and was put back.
        Cancelled,
        /// It cannot take over beside this process.
        Unavailable(String),
    }

    /// Asks the supervisor to start the installed version beside this process.
    pub(crate) fn request_successor() -> Requested {
        HANDING_OVER.store(true, Ordering::Release);
        let stream = match channel::request_successor() {
            Ok(Reply::Link(stream)) => stream,
            Ok(Reply::Cancelled) => {
                HANDING_OVER.store(false, Ordering::Release);
                return Requested::Cancelled;
            }
            Ok(Reply::Fallback(reason)) | Err(reason) => {
                HANDING_OVER.store(false, Ordering::Release);
                return Requested::Unavailable(reason);
            }
        };
        if let Err(error) = wire::introduce(&stream, &onetdns_control::credential_key()) {
            onetdns_core::warn!(event = "handoff.introduce_failed", %error, "Could not introduce this process to the new version");
        }
        if let Some(links) = LINKS.get() {
            *links.successor.lock_recover() = Some(Link::over(stream));
        }
        Requested::Linked
    }

    /// After a handoff, whether this process ends. `handed` is how the handoff went here; the
    /// supervisor's verdict decides.
    pub fn settle(handed: bool, abort: &dyn Fn() -> bool) -> bool {
        let ends = channel::settle(handed, abort);
        if !ends {
            HANDING_OVER.store(false, Ordering::Release);
        }
        ends
    }

    /// While true, a successor may already have read the configuration.
    pub fn handing_over() -> bool {
        HANDING_OVER.load(Ordering::Acquire)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn memory_figures_are_read_in_kib() {
            let meminfo = "MemTotal:       16318500 kB\nMemAvailable:    9841224 kB\n";
            assert_eq!(kib(meminfo, "MemAvailable:"), Some(9_841_224));
            assert_eq!(kib(meminfo, "MemFree:"), None);
            assert_eq!(kib("VmRSS:\t  51200 kB\n", "VmRSS:"), Some(51_200));
            assert_eq!(kib("VmRSS:\t  51200 MB\n", "VmRSS:"), None);
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{handing_over, join, run, settle};
#[cfg(target_os = "linux")]
pub(crate) use linux::{request_successor, Requested};

#[cfg(not(target_os = "linux"))]
pub fn join(_links: &std::sync::Arc<crate::handoff::Links>) -> crate::error::BoxResult<Joined> {
    Ok(Joined::default())
}

#[cfg(not(target_os = "linux"))]
pub fn settle(handed: bool, _abort: &dyn Fn() -> bool) -> bool {
    handed
}

#[cfg(not(target_os = "linux"))]
pub fn handing_over() -> bool {
    false
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
