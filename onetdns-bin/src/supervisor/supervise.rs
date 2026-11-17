//! The supervisor's side: starts the worker, starts it again when it exits abnormally, judges an
//! update on trial, and links a successor to the worker it takes over from.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::channel::{self, Hello};
use super::sys::{self, Process};
use super::{RestartDecision, RestartPolicy, MAX_STARTUP_FAILURES};
use crate::error::{BoxResult, Context};
use crate::handoff::wire::{self, Frame, FrameReader, Stream, PROTOCOL};
use crate::handoff::LinkError;
use crate::tui::ChildConsole;
use crate::update::launch::UPDATE_EXIT_CODE;
use crate::update::trial::{Startup, Trial};

const RESTARTS_ENV: &str = "ONETDNS_SUPERVISOR_RESTARTS";
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
/// A successor that has not introduced itself by then is stopped.
const HELLO_WAIT: Duration = Duration::from_secs(30);
/// How long the previous worker may take to end once its successor runs everything.
const END_GRACE: Duration = Duration::from_secs(30);

/// How to start a worker; the platform adds its end of the channel.
pub(super) struct WorkerCommand<'a> {
    pub(super) image: &'a Path,
    /// argv[0], the name ps and service managers show.
    pub(super) program: &'a Path,
    pub(super) args: Vec<OsString>,
    pub(super) env: Vec<(&'static str, OsString)>,
}

/// A worker process and the supervisor's end of its channel.
pub(super) struct Worker {
    pub(super) process: Process,
    pub(super) channel: Stream,
    reader: FrameReader,
    /// Cleared once the worker closes its end.
    open: bool,
    /// Its hello, until the supervisor answers it.
    hello: Option<Hello>,
    answered: bool,
    ready: bool,
    /// Asked for a successor; cleared when the supervisor takes up the request.
    wants_successor: bool,
    /// Started to take over; once it runs everything, this supervisor execs its version.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    follow: bool,
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

    /// Lets a worker that does not take over run on its own. Returns the version it said it is.
    fn answer_run(&mut self) -> Result<Option<String>, String> {
        let Some(hello) = self.hello.take() else {
            return Ok(None);
        };
        // Started from this supervisor's own image, so it must be this version.
        #[cfg(target_os = "linux")]
        if hello.version != crate::update::VERSION {
            return Err(format!(
                "It is version {}, not {}",
                hello.version,
                crate::update::VERSION
            ));
        }
        self.answered = true;
        wire::send(&self.channel, &Frame::new(channel::RUN))
            .map_err(|error| format!("Could not answer it: {error}"))?;
        Ok(Some(hello.version))
    }

    pub(super) fn tell(&self, frame: &Frame) {
        if let Err(error) = wire::send(&self.channel, frame) {
            onetdns_core::warn!(event = "supervisor.send_failed", pid = self.process.id(), kind = frame.kind, %error, "Could not tell the DNS service process how the update went");
        }
    }
}

/// Starts `image` as a worker.
fn spawn_worker(
    image: &Path,
    program: &Path,
    config_path: Option<&Path>,
    no_web: bool,
    restarts: u64,
) -> BoxResult<Worker> {
    let mut args: Vec<OsString> = vec!["run".into()];
    if let Some(path) = config_path {
        args.push("--config".into());
        args.push(path.into());
    }
    if no_web {
        args.push("--no-web".into());
    }
    args.push("--no-supervisor".into());
    let env = vec![
        (RESTARTS_ENV, restarts.to_string().into()),
        (
            crate::update::install::INSTALL_PATH_ENV,
            crate::update::install::current()
                .map(|install| install.path().as_os_str().to_os_string())
                .unwrap_or_default(),
        ),
    ];
    let (process, channel) = sys::spawn(&WorkerCommand {
        image,
        program,
        args,
        env,
    })?;
    channel
        .set_nonblocking(true)
        .with_context(|| "Could not create the channel to the DNS service process")?;
    Ok(Worker {
        process,
        channel,
        reader: FrameReader::default(),
        open: true,
        hello: None,
        answered: false,
        ready: false,
        wants_successor: false,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        follow: false,
        started: Instant::now(),
    })
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
        super::room_for_successor(sys::memory(&current.process))?;
        let install = crate::update::install::current()?;
        let worker = spawn_worker(install.path(), program, config_path, no_web, restarts)
            .map_err(|error| error.to_string())?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let worker = Worker {
            follow: true,
            ..worker
        };
        onetdns_core::info!(
            event = "supervisor.successor_started",
            pid = worker.process.id(),
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
        match worker.process.try_wait() {
            Ok(None) => None,
            Ok(Some(status)) => Some(Failure::Exited(format!(
                "The new version exited before it became ready ({})",
                sys::status_text(status)
            ))),
            Err(error) => Some(Failure::Exited(format!(
                "Could not check the state of the new version: {error}"
            ))),
        }
    }

    /// Stops it unless it exited, and tells the current worker: an update on trial was put back
    /// and it serves on; otherwise it restarts the way it does without a successor.
    fn give_up(self, current: Option<&Worker>, failure: Failure) {
        let Successor { worker, trial } = self;
        if !matches!(failure, Failure::Exited(_)) {
            worker.process.kill();
            if let Err(error) = worker.process.wait() {
                onetdns_core::warn!(event = "supervisor.child_reap_failed", pid = worker.process.id(), %error, "Could not reap the exited child process");
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

/// Gives the successor its end of a new link to take over through, and the current worker its end
/// to hand over through.
fn link(successor: &Worker, current: &Worker) -> std::io::Result<()> {
    let (handing, taking) = wire::pair()?;
    wire::send(
        &successor.channel,
        &sys::with_stream(
            channel::TAKE_OVER,
            taking,
            &successor.process,
            &current.process,
        )?,
    )?;
    current.tell(&sys::with_stream(
        channel::LINK,
        handing,
        &current.process,
        &successor.process,
    )?);
    Ok(())
}

fn terminate_child(child: &Worker, console: Option<&ChildConsole>) {
    child.process.stop();
    let deadline = Instant::now() + SHUTDOWN_GRACE;
    while Instant::now() < deadline {
        match child.process.try_wait() {
            Ok(Some(status)) => {
                if let Some(console) = console {
                    console.child_exited(status);
                }
                return;
            }
            Ok(None) => std::thread::sleep(POLL_INTERVAL),
            Err(error) => {
                onetdns_core::warn!(event = "supervisor.child_wait_failed", pid = child.process.id(), %error, "Could not check the state of the exiting child process; killing it now");
                break;
            }
        }
    }
    child.process.kill();
    match child.process.wait() {
        Ok(status) => {
            if let Some(console) = console {
                console.child_exited(status);
            }
        }
        Err(error) => {
            onetdns_core::warn!(event = "supervisor.child_reap_failed", pid = child.process.id(), %error, "Could not reap the exited child process");
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
        std::thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
    !stop.load(Ordering::Acquire)
}

/// Puts a worker started after an update on trial, as the supervisor of the previous version.
fn trial_after_update(version: &str) -> Option<Trial> {
    match crate::update::trial::for_successor(version) {
        Ok(trial) => Some(trial),
        Err(reason) => {
            onetdns_core::warn!(event = "update.trial_start_failed", %reason, "Could not put the new version on trial; it runs without the automatic revert");
            None
        }
    }
}

/// Without a config path, finds or creates the config file and gives the workers that path.
pub fn run(config_path: Option<PathBuf>, no_web: bool) -> BoxResult<()> {
    let config_path = match config_path {
        None if !no_web => crate::ensure_auto_config()?,
        given => given,
    };
    supervise(
        config_path,
        no_web,
        crate::install_shutdown_handler(),
        &mut || {},
        None,
    )
}

/// Run by the Windows service, which creates no config file: without `--config` it runs on
/// defaults. `starting` is called while the update record is handled and `ready` once a worker is
/// ready, so the service can report both to the service manager.
#[cfg(windows)]
pub fn run_service(
    config_path: Option<PathBuf>,
    stop: Arc<AtomicBool>,
    starting: &mut dyn FnMut(),
    ready: Box<dyn FnOnce()>,
) -> BoxResult<()> {
    supervise(config_path, false, stop, starting, Some(ready))
}

/// Supervises workers until `stop` is set. Also settles updates: a new version that exits before
/// ready or misses its deadline is reverted, a child's update exit starts the swapped executable,
/// and a successor that took over is handed to the supervisor of its own version where the platform
/// can exec one.
fn supervise(
    config_path: Option<PathBuf>,
    no_web: bool,
    stop: Arc<AtomicBool>,
    starting: &mut dyn FnMut(),
    mut ready: Option<Box<dyn FnOnce()>>,
) -> BoxResult<()> {
    let mut next = sys::adopted()?.map(|(process, channel)| Worker {
        process,
        channel,
        reader: FrameReader::default(),
        open: true,
        hello: None,
        answered: true,
        ready: true,
        wants_successor: false,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        follow: false,
        started: Instant::now(),
    });
    // A supervisor that hands a worker down has settled that worker's trial.
    let mut trial = if next.is_some() {
        None
    } else {
        match crate::update::trial::on_start(starting) {
            Startup::Normal => None,
            Startup::Trial(trial) => Some(trial),
            Startup::Reverted => {
                sys::follow_install().map_err(|reason| crate::anyhow!(reason))?;
                None
            }
        }
    };
    let program = std::env::current_exe()
        .with_context(|| "Could not find the path of the current executable")?;
    let config = onetdns_config::Config::load_or_default(config_path.as_deref())?;
    #[cfg(target_os = "linux")]
    let run_as = config
        .run_as_user
        .clone()
        .map(|user| (user, config.run_as_group.clone()));
    drop(config);
    sys::harden()?;

    let handed_down = sys::handed_down_console();
    let console = if next.is_some() {
        handed_down
    } else {
        ChildConsole::capture()
    };
    let console = console.as_ref();
    let mut policy = RestartPolicy::default();
    let mut restarts = 0u64;
    #[cfg(target_os = "linux")]
    let mut parent_privileges_dropped = run_as.is_none();
    // Set when a worker exited to start the swapped-in version; its hello puts that version on
    // trial.
    let mut after_update = false;

    'workers: loop {
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut child = match next.take() {
            Some(child) => child,
            None => {
                let child = spawn_worker(
                    &sys::worker_image()?,
                    &program,
                    config_path.as_deref(),
                    no_web,
                    restarts,
                )?;
                onetdns_core::info!(
                    event = "supervisor.child_started",
                    pid = child.process.id(),
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
            match child.poll().and_then(|()| child.answer_run()) {
                Ok(Some(version)) if after_update => {
                    after_update = false;
                    trial = trial_after_update(&version);
                }
                Ok(_) => {}
                Err(error) => {
                    onetdns_core::error!(event = "supervisor.child_refused", pid = child.process.id(), %error, "Stopping a DNS service process that does not follow the supervisor protocol");
                    child.process.kill();
                    child.open = false;
                }
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
                if let Some(ready) = ready.take() {
                    ready();
                }
                if let Some(trial) = trial.take() {
                    trial.commit();
                }
                #[cfg(target_os = "linux")]
                if !parent_privileges_dropped {
                    let (user, group) = run_as.as_ref().expect("run_as is set");
                    if let Err(error) = crate::privdrop::drop_privileges(user, group.as_deref()) {
                        terminate_child(&child, console);
                        return Err(crate::anyhow!(format!(
                            "Stopping the service because the supervisor could not drop privileges: {error}"
                        )));
                    }
                    if let Err(error) =
                        crate::privdrop::executable_still_runnable(Path::new(sys::SELF_IMAGE))
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
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                if child.follow {
                    onetdns_core::info!(
                        event = "supervisor.update_exec",
                        "Starting the supervisor of the new version"
                    );
                    let error = sys::exec_adopting(&child, console);
                    onetdns_core::error!(event = "supervisor.update_exec_failed", %error, "Could not start the supervisor of the new version; this one goes on supervising the DNS service process");
                    child.follow = false;
                }
            }
            if trial.as_ref().is_some_and(Trial::expired)
                && trial.take().is_some_and(Trial::revert_expired)
            {
                terminate_child(&child, console);
                sys::follow_install().map_err(|reason| crate::anyhow!(reason))?;
                continue 'workers;
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
                        pid = child.process.id(),
                        "The previous version did not end after the new one took over; killing it"
                    );
                    child.process.kill();
                    ending.killed = true;
                }
            }
            match child.process.try_wait()? {
                Some(status) => {
                    if let Some(taking) = successor.take() {
                        if taking.worker.answered {
                            onetdns_core::info!(
                                event = "supervisor.predecessor_ended",
                                status = %sys::status_text(status),
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
                                "The running version ended before the new one started".to_string(),
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
                sys::status_text(status)
            );
            if trial.revert(&reason) {
                sys::follow_install().map_err(|reason| crate::anyhow!(reason))?;
                continue;
            }
        } else if status.code() == Some(UPDATE_EXIT_CODE) {
            onetdns_core::info!(
                event = "supervisor.update_exec",
                "The DNS service process installed an update; starting the new version"
            );
            match sys::follow_install() {
                Ok(()) => after_update = true,
                Err(error) => {
                    onetdns_core::error!(event = "supervisor.update_exec_failed", %error, "Could not start the new version; putting the previous executable back");
                    if let Err(error) = crate::update::apply::undo_unstarted(&format!(
                        "Could not start the new version: {error}"
                    )) {
                        onetdns_core::error!(event = "supervisor.update_undo_failed", %error, "Could not put the previous executable back; supervising the running version");
                    }
                }
            }
            continue;
        }
        let runtime = child.started.elapsed();
        let ready = child.ready;
        match policy.child_exited(ready, runtime) {
            RestartDecision::GiveUp => {
                return Err(crate::anyhow!(format!(
                    "The DNS child exited {MAX_STARTUP_FAILURES} times in a row before becoming ready ({})",
                    sys::status_text(status)
                )));
            }
            RestartDecision::RestartAfter(delay) => {
                restarts = restarts.saturating_add(1);
                onetdns_core::error!(event = "supervisor.child_restarted",
                    status = %sys::status_text(status),
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
