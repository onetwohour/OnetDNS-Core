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
mod linux {
    use super::{RestartDecision, RestartPolicy, MAX_STARTUP_FAILURES};
    use crate::error::{BoxResult, Context};
    use crate::update::launch::UPDATE_EXIT_CODE;
    use crate::update::trial::{Startup, Trial};
    use onetdns_config::Config;
    use std::net::{SocketAddr, UdpSocket};
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// The image this parent is running. The install path would name another version after an
    /// update's rename, or gain a ` (deleted)` suffix.
    const SELF_IMAGE: &str = "/proc/self/exe";
    const READY_ADDR_ENV: &str = "ONETDNS_SUPERVISOR_READY_ADDR";
    const READY_TOKEN_ENV: &str = "ONETDNS_SUPERVISOR_READY_TOKEN";
    const RESTARTS_ENV: &str = "ONETDNS_SUPERVISOR_RESTARTS";
    const POLL_INTERVAL: Duration = Duration::from_millis(20);
    const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
    const PR_SET_DUMPABLE: libc::c_int = 4;

    enum ReadyState {
        Pending,
        Ready,
    }

    struct ReadinessReceiver {
        socket: UdpSocket,
        token: [u8; 16],
    }

    impl ReadinessReceiver {
        /// Accepts only the token over loopback, or any packet could claim the child is ready.
        fn poll_ready(&self) -> std::io::Result<ReadyState> {
            let mut token = [0u8; 16];

            for _ in 0..64 {
                match self.socket.recv_from(&mut token) {
                    Ok((16, peer)) if peer.ip().is_loopback() && token == self.token => {
                        return Ok(ReadyState::Ready);
                    }
                    Ok(_) => continue,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        return Ok(ReadyState::Pending);
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(ReadyState::Pending)
        }
    }

    fn encode_token(token: &[u8; 16]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(32);
        for byte in token {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    }

    fn decode_token(encoded: &str) -> Option<[u8; 16]> {
        if encoded.len() != 32 {
            return None;
        }
        let mut token = [0u8; 16];
        for (index, byte) in token.iter_mut().enumerate() {
            *byte = u8::from_str_radix(encoded.get(index * 2..index * 2 + 2)?, 16).ok()?;
        }
        Some(token)
    }

    fn readiness_channel() -> std::io::Result<(ReadinessReceiver, SocketAddr, [u8; 16])> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_nonblocking(true)?;
        let address = socket.local_addr()?;
        let token = onetdns_core::rng::try_random_array()?;
        Ok((ReadinessReceiver { socket, token }, address, token))
    }

    fn signal_readiness(address: SocketAddr, token: [u8; 16]) -> std::io::Result<()> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.send_to(&token, address)?;
        Ok(())
    }

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

    struct ManagedChild {
        process: Child,
        readiness: Option<ReadinessReceiver>,
        ready: bool,
        started: Instant,
    }

    impl ManagedChild {
        fn poll_ready(&mut self) -> std::io::Result<bool> {
            if self.ready {
                return Ok(true);
            }
            let Some(receiver) = &self.readiness else {
                return Ok(false);
            };
            match receiver.poll_ready()? {
                ReadyState::Pending => Ok(false),
                ReadyState::Ready => {
                    self.ready = true;
                    self.readiness = None;
                    Ok(true)
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
    ) -> BoxResult<ManagedChild> {
        let (readiness, ready_address, ready_token) = readiness_channel()
            .with_context(|| "Could not create the supervisor readiness channel")?;
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
        command.env(READY_ADDR_ENV, ready_address.to_string());
        command.env(READY_TOKEN_ENV, encode_token(&ready_token));
        command.env(RESTARTS_ENV, restarts.to_string());
        command.env(
            crate::update::install::INSTALL_PATH_ENV,
            crate::update::install::current()
                .map(|install| install.path().as_os_str().to_os_string())
                .unwrap_or_default(),
        );
        crate::osnet::harden_child_env(&mut command);
        let process = command
            .spawn()
            .with_context(|| "Could not create the supervised DNS child process")?;
        Ok(ManagedChild {
            process,
            readiness: Some(readiness),
            ready: false,
            started: Instant::now(),
        })
    }

    fn signal_child(child: &Child, signal: libc::c_int) {
        let result = unsafe { libc::kill(child.id() as libc::pid_t, signal) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                onetdns_core::warn!(event = "supervisor.shutdown_signal_failed", pid = child.id(), %error, "Supervisor could not forward the shutdown signal to the DNS service");
            }
        }
    }

    fn terminate_child(child: &mut Child) {
        signal_child(child, libc::SIGTERM);
        let deadline = Instant::now() + SHUTDOWN_GRACE;
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(POLL_INTERVAL),
                Err(error) => {
                    onetdns_core::warn!(event = "supervisor.child_wait_failed", pid = child.id(), %error, "Could not check the state of the exiting child process; killing it now");
                    break;
                }
            }
        }
        if let Err(error) = child.kill() {
            onetdns_core::warn!(event = "supervisor.child_kill_failed", pid = child.id(), %error, "Could not kill the child process; a process holding the ports may be left behind");
        }
        if let Err(error) = child.wait() {
            onetdns_core::warn!(event = "supervisor.child_reap_failed", pid = child.id(), %error, "Could not reap the exited child process");
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
                pid = child.process.id(),
                restarts,
                "Started the DNS service process"
            );

            let status = loop {
                if stop.load(Ordering::Acquire) {
                    terminate_child(&mut child.process);
                    return Ok(());
                }
                if child.poll_ready()? {
                    if let Some(trial) = trial.take() {
                        trial.commit();
                    }
                    if !parent_privileges_dropped {
                        let (user, group) = run_as.as_ref().expect("run_as is set");
                        if let Err(error) = crate::privdrop::drop_privileges(user, group.as_deref())
                        {
                            terminate_child(&mut child.process);
                            return Err(crate::anyhow!(format!(
                                "Stopping the service because the supervisor could not drop privileges: {error}"
                            )));
                        }
                        if let Err(error) =
                            crate::privdrop::executable_still_runnable(Path::new(SELF_IMAGE))
                        {
                            terminate_child(&mut child.process);
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
                    terminate_child(&mut child.process);
                    return Err(crate::anyhow!(exec_install_path()));
                }
                match child.process.try_wait()? {
                    Some(status) => break status,
                    None => std::thread::sleep(POLL_INTERVAL),
                }
            };

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
        let address = std::env::var(READY_ADDR_ENV).ok();
        let token = std::env::var(READY_TOKEN_ENV).ok();
        std::env::remove_var(READY_ADDR_ENV);
        std::env::remove_var(READY_TOKEN_ENV);
        if address.is_none() && token.is_none() {
            return Ok(None);
        }
        disable_process_dumping()
            .with_context(|| "Could not make the DNS child process non-dumpable")?;
        if let Err(error) = restore_process_name() {
            onetdns_core::warn!(event = "supervisor.process_name_failed", %error, "Could not restore the process name of the DNS service process; it is listed as exe");
        }
        let address = address
            .ok_or_else(|| crate::anyhow!("The supervisor readiness address is missing"))?
            .parse::<SocketAddr>()
            .map_err(|error| {
                crate::anyhow!(format!("Invalid supervisor readiness address: {error}"))
            })?;
        if !address.ip().is_loopback() {
            return Err(crate::anyhow!(
                "The supervisor readiness address is not a loopback address"
            ));
        }
        let token = decode_token(
            token
                .as_deref()
                .ok_or_else(|| crate::anyhow!("The supervisor readiness token is missing"))?,
        )
        .ok_or_else(|| crate::anyhow!("The supervisor readiness token is malformed"))?;
        Ok(Some(Box::new(move || {
            if let Err(error) = signal_readiness(address, token) {
                onetdns_core::error!(event = "supervisor.ready_signal_failed", %error, "Could not send the service ready signal; aborting startup");
                std::process::exit(1);
            }
        })))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn becomes_ready(receiver: &ReadinessReceiver, window: Duration) -> bool {
            let deadline = Instant::now() + window;
            loop {
                if matches!(receiver.poll_ready().expect("poll"), ReadyState::Ready) {
                    return true;
                }
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        #[test]
        fn readiness_requires_matching_token() {
            let (receiver, address, token) = readiness_channel().expect("channel");
            assert_eq!(decode_token(&encode_token(&token)), Some(token));
            assert_eq!(decode_token("not-a-token"), None);
            let mut bogus = token;
            bogus[0] ^= 1;
            signal_readiness(address, bogus).expect("bogus signal");
            // Loopback delivery is not immediate under WSL mirrored networking.
            assert!(!becomes_ready(&receiver, Duration::from_millis(50)));
            signal_readiness(address, token).expect("ready signal");
            assert!(becomes_ready(&receiver, Duration::from_secs(5)));
        }
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
