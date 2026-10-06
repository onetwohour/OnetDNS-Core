/*!
 * @brief 프로세스 감독자.
 *
 * @details 부모는 필터도 캐시도 읽지 않는다. 자식이 죽으면 재시작만 한다. 그래서
 *          자식이 메모리를 다 쓰거나 강제 종료돼도 서비스가 돌아온다.
 * @warning 시작 자체가 계속 실패하면 포기한다. 설정이 틀린 상태로 무한히 재시작하면
 *          로그만 쌓이고 문제는 그대로다.
 * @note 자식이 준비됐다고 알린 뒤에야 안정으로 본다. 묶기 전에 죽는 것과 돌다가 죽는
 *       것은 다르게 다뤄야 한다.
 */

#[cfg(any(test, target_os = "linux"))]
use std::time::Duration;

#[cfg(any(test, target_os = "linux"))]
/** @brief 첫 재시작까지 기다릴 시간. */
const BASE_RESTART_DELAY: Duration = Duration::from_millis(10);
#[cfg(any(test, target_os = "linux"))]
/** @brief 재시작 대기의 상한. 계속 실패해도 이보다 오래 기다리지는 않는다. */
const MAX_RESTART_DELAY: Duration = Duration::from_secs(5);
#[cfg(any(test, target_os = "linux"))]
/** @brief 이만큼 돌았으면 안정으로 보고 대기 시간을 되돌린다. */
const STABLE_RUNTIME: Duration = Duration::from_secs(30);
#[cfg(any(test, target_os = "linux"))]
/** @brief 준비 전에 연달아 죽는 것을 참아 줄 횟수. 넘으면 포기한다. */
const MAX_STARTUP_FAILURES: u32 = 5;

#[cfg(any(test, target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 자식이 죽었을 때의 처분. */
enum RestartDecision {
    /** @brief 이만큼 기다렸다 재시작한다. */
    RestartAfter(Duration),
    /** @brief 더 시작하지 않는다. */
    GiveUp,
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Default)]
/** @brief 재시작 판단 상태. */
struct RestartPolicy {
    /** @brief 연달아 죽은 횟수. 대기 시간을 늘리는 데 쓴다. */
    crash_streak: u32,
    /** @brief 준비 전에 죽은 횟수. 이것이 넘치면 포기한다. */
    startup_failures: u32,
}

#[cfg(any(test, target_os = "linux"))]
impl RestartPolicy {
    /**
     * @brief 자식이 죽었다. 재시작할지 정한다.
     * @details 준비까지 갔다가 죽었으면 실패 횟수를 되돌린다. 그러지 않으면 오래 돌던
     *          서버가 어쩌다 한 번 죽었을 때 누적 횟수로 포기하게 된다.
     */
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
/** @brief 유닉스 전용 감독 구현. */
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

    /**
     * @brief 자식을 띄울 실행 파일. 부모가 지금 실행 중인 이미지를 가리킨다.
     * @details 설치 경로로 띄우면 실행 중인 파일을 rename 으로 갈아 끼운 뒤에는 그 경로가
     *          새 파일을 가리키거나 끝에 (deleted) 가 붙는다. 그러면 재시작한 자식이 부모와
     *          다른 판으로 뜨거나 아예 뜨지 못한다. 이 경로는 디렉터리를 거치지 않고 이미지로
     *          바로 가므로, 권한을 낮춘 뒤 확인할 것도 파일 자체의 실행 권한뿐이다.
     */
    const SELF_IMAGE: &str = "/proc/self/exe";
    /** @brief 자식이 준비를 알릴 주소를 넘기는 환경 변수. */
    const READY_ADDR_ENV: &str = "ONETDNS_SUPERVISOR_READY_ADDR";
    /** @brief 준비 통지에 쓸 토큰. 남이 이 서버의 자식인 척 알리지 못하게 한다. */
    const READY_TOKEN_ENV: &str = "ONETDNS_SUPERVISOR_READY_TOKEN";
    /** @brief 지금까지의 재시작 횟수. 자식이 지표로 내보낸다. */
    const RESTARTS_ENV: &str = "ONETDNS_SUPERVISOR_RESTARTS";
    /** @brief 자식 상태를 확인하는 주기. */
    const POLL_INTERVAL: Duration = Duration::from_millis(20);
    /** @brief 종료를 기다려 줄 시간. 지나면 강제로 끝낸다. */
    const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
    /** @brief 덤프 가능 여부 설정 요청. */
    const PR_SET_DUMPABLE: libc::c_int = 4;

    /** @brief 자식이 준비됐는지. */
    enum ReadyState {
        /** @brief 아직 준비되지 않았다. */
        Pending,
        /** @brief 준비됐다. */
        Ready,
    }

    /** @brief 자식의 준비 통지를 받는 곳. */
    struct ReadinessReceiver {
        /** @brief 통지를 받을 소켓. */
        socket: UdpSocket,
        /** @brief 이 서버의 자식만 아는 토큰. */
        token: [u8; 16],
    }

    impl ReadinessReceiver {
        /**
         * @brief 통지가 왔는지 확인한다.
         * @warning 루프백에서 온 것이고 토큰이 맞아야 한다. 확인하지 않으면 아무나 보낸
         *          패킷으로 자식이 준비됐다고 속일 수 있다.
         */
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

    /** @brief 토큰을 환경 변수에 담을 형태로. */
    fn encode_token(token: &[u8; 16]) -> String {
        /** @brief 16진 문자표. */
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(32);
        for byte in token {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    }

    /** @brief 환경 변수의 토큰을 읽는다. */
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

    /** @brief 준비 통지를 받을 채널를 연다. 주소와 토큰을 함께 준다. */
    fn readiness_channel() -> std::io::Result<(ReadinessReceiver, SocketAddr, [u8; 16])> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_nonblocking(true)?;
        let address = socket.local_addr()?;
        let token = onetdns_core::rng::try_random_array()?;
        Ok((ReadinessReceiver { socket, token }, address, token))
    }

    /** @brief 자식이 준비됐음을 부모에게 알린다. */
    fn signal_readiness(address: SocketAddr, token: [u8; 16]) -> std::io::Result<()> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.send_to(&token, address)?;
        Ok(())
    }

    /**
     * @brief 코어 덤프를 끈다.
     * @warning 덤프에는 키와 토큰이 그대로 담긴다. 그리고 큰 덤프를 쓰는 동안 재시작이
     *          그만큼 늦어진다.
     */
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

    /** @brief 다른 프로세스가 이 서버의 메모리를 들여다보지 못하게 한다. */
    fn disable_process_dumping() -> std::io::Result<()> {
        if unsafe { libc::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /**
     * @brief 프로세스 이름을 argv[0] 의 파일 이름으로 되돌린다.
     * @details 커널은 실행한 경로의 마지막 부분을 프로세스 이름으로 삼으므로 SELF_IMAGE 로
     *          뜬 자식의 이름은 exe 가 된다. 그대로 두면 top, pgrep, killall 과 OOM 기록에서
     *          이 서버를 찾지 못한다.
     * @warning 스레드는 만들어질 때 이름을 물려받으므로 다른 스레드를 띄우기 전에 부른다.
     */
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

    /** @brief 이 서버가 시작한 자식 하나. */
    struct ManagedChild {
        /** @brief 시작한 자식. */
        process: Child,
        /** @brief 이 자식의 준비 통지를 받을 곳. */
        readiness: Option<ReadinessReceiver>,
        /** @brief 준비를 알렸는지. */
        ready: bool,
        /** @brief 시작한 시각. */
        started: Instant,
    }

    impl ManagedChild {
        /** @brief 이 자식이 준비를 알렸는지. */
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

    /**
     * @brief 자식을 시작한다. 준비 통지 주소와 토큰, 설치 경로를 물려준다.
     * @param program 자식의 argv[0]. ps 와 서비스 관리자가 보여 주는 이름이고, 자식은 여기서
     *        프로세스 이름을 되찾는다.
     */
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

    /** @brief 자식에게 신호를 보낸다. */
    fn signal_child(child: &Child, signal: libc::c_int) {
        let result = unsafe { libc::kill(child.id() as libc::pid_t, signal) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                onetdns_core::warn!(event = "supervisor.shutdown_signal_failed", pid = child.id(), %error, "Supervisor could not forward the shutdown signal to the DNS service");
            }
        }
    }

    /** @brief 자식을 끝낸다. 곱게 안 끝나면 강제로 끝낸다. */
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

    /** @brief 기다리되 종료 신호가 오면 곧장 돌아온다. */
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

    /**
     * @brief 이 부모를 설치 경로의 실행 파일로 바꾼다. 인수는 그대로 넘긴다.
     * @return 돌아오면 exec 가 실패한 것이고 그 이유다.
     */
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

    /** @brief 종료 상태를 사람이 읽을 문자열로. */
    fn status_text(status: ExitStatus) -> String {
        use std::os::unix::process::ExitStatusExt;
        match (status.code(), status.signal()) {
            (Some(code), _) => format!("exit={code}"),
            (_, Some(signal)) => format!("signal={signal}"),
            _ => "unknown".to_string(),
        }
    }

    /**
     * @brief 감독 반복을 돌린다.
     * @details 자식을 시작하고, 준비를 기다리고, 죽으면 정책에 따라 재시작한다. 준비된
     *          뒤에는 부모도 권한을 내려놓는다. 업데이트 기록은 부모가 처리한다. 새 버전을
     *          시험하는 동안 자식이 준비 전에 끝나거나 기한을 넘기면 재시작하지 않고 되돌린 뒤
     *          되돌린 실행 파일을 exec 하고, 자식이 업데이트 종료 코드로 끝나면 맞바꾼 실행
     *          파일을 exec 한다.
     */
    pub fn run(mut config_path: Option<PathBuf>, no_web: bool) -> BoxResult<()> {
        let mut trial = match crate::update::trial::on_start(&mut || {}) {
            Startup::Normal => None,
            Startup::Trial(trial) => Some(trial),
            Startup::Reverted => return Err(crate::anyhow!(exec_install_path())),
        };
        if config_path.is_none() && !no_web {
            config_path = crate::ensure_auto_config();
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

    /**
     * @brief 준비를 알릴 방법을 가져간다. 감독 없이 돌면 없다.
     * @details 감독받는 자식이면 덤프를 막고 프로세스 이름을 되찾는 일도 여기서 한다. 다른
     *          스레드가 뜨기 전에 불러야 한다.
     */
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
    /** @brief 준비 통지가 토큰으로 지켜지는지. */
    mod tests {
        use super::*;

        #[test]
        /** @brief 토큰이 다르면 준비로 보지 않는지. 보면 아무나 이 서버의 자식인 척한다. */
        fn readiness_requires_matching_token() {
            let (receiver, address, token) = readiness_channel().expect("channel");
            assert_eq!(decode_token(&encode_token(&token)), Some(token));
            assert_eq!(decode_token("not-a-token"), None);
            let mut bogus = token;
            bogus[0] ^= 1;
            signal_readiness(address, bogus).expect("bogus signal");
            assert!(matches!(
                receiver.poll_ready().expect("poll"),
                ReadyState::Pending
            ));
            signal_readiness(address, token).expect("ready signal");
            assert!(matches!(
                receiver.poll_ready().expect("poll"),
                ReadyState::Ready
            ));
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{run, take_ready_callback};

#[cfg(not(target_os = "linux"))]
/** @brief 준비를 알릴 방법을 가져간다. 감독 없이 돌면 없다. */
pub fn take_ready_callback() -> crate::error::BoxResult<Option<Box<dyn FnOnce() + Send>>> {
    Ok(None)
}

#[cfg(test)]
/** @brief 재시작 정책이 포기 조건과 대기 상한을 지키는지. */
mod tests {
    use super::*;

    #[test]
    /** @brief 준비 전에 연달아 죽으면 결국 포기하는지. */
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
    /** @brief 준비까지 간 자식이 실패 횟수를 되돌리고, 대기 시간에 상한이 있는지. */
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
    /** @brief 오래 돌았으면 대기 시간이 되돌아오는지. */
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
