/*!
 * @brief 검증한 실행 파일로 설치 경로를 맞바꾼다.
 *
 * @details 운영자가 지시한 되돌리기도 .previous 를 원본으로 삼아 같은 절차를 밟는다. 여기서는
 *          맞바꾸기까지만 하고, 새 버전을 띄우는 일은 호출자가 실행 방식에 맞춰 한다.
 */

use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use super::install::{self, Install, UpdateLock};
use super::record::{Record, StartupAction, State};
use super::VERSION;

/** @brief 새 실행 파일의 --version 을 기다리는 시간. */
const VERSION_TIMEOUT: Duration = Duration::from_secs(15);
/** @brief 새 실행 파일의 설정 검사를 기다리는 시간. 영역 원본 데이터베이스에 붙어 보는 시간이 든다. */
const CHECK_TIMEOUT: Duration = Duration::from_secs(60);
/** @brief 점검 출력 가운데 운영자에게 보이는 상한. */
const MAX_OUTPUT_BYTES: usize = 8 * 1024;
/** @brief 점검 프로세스가 끝났는지 확인하는 간격. */
const POLL_INTERVAL: Duration = Duration::from_millis(20);
/** @brief 점검 프로세스가 끝난 뒤 출력 읽기가 끝나기를 기다리는 시간. 손자 프로세스가 파이프를 쥐고 있으면 이만큼만 기다린다. */
const OUTPUT_GRACE: Duration = Duration::from_secs(2);
#[cfg(unix)]
/** @brief 띄우지 못한 새 버전을 되돌릴 때 잠금을 기다리는 시간. 방금 적용한 프로세스가 놓은 뒤다. */
const UNDO_LOCK_WAIT: Duration = Duration::from_secs(5);

const _: () = assert!(
    super::trial::STARTUP_LOCK_WAIT.as_secs() > VERSION_TIMEOUT.as_secs() + CHECK_TIMEOUT.as_secs(),
    "a starting server must outwait the preflight of an update being applied"
);

#[derive(Debug)]
/** @brief 맞바꾼 결과. */
pub(crate) struct Swapped {
    /** @brief 바꾸기 전 버전. */
    pub(crate) from: String,
    /** @brief 설치한 버전. */
    pub(crate) to: String,
}

/**
 * @brief 지금 적용할 수 있는지 내려받기 전에 본다.
 * @details 잠금을 잡아 보고 바로 놓는다. 설치 디렉터리에 쓸 수 없거나 앞선 업데이트의 기동이 끝나지
 *          않았으면 실행 파일을 받기 전에 거절한다. 내려받는 동안에는 잠금을 쥐지 않는다. 그동안
 *          시작하는 서버가 잠금을 기다리지 않게 하려는 것이고, 적용할 때 다시 잡는다.
 */
pub(crate) fn ready_to_apply() -> Result<(), String> {
    let install = install::current()?;
    let _lock = install
        .lock(Duration::ZERO)
        .map_err(|error| error.to_string())?;
    refuse_unfinished(install)
}

/**
 * @brief 서명한 매니페스트로 검증한 실행 파일을 설치 경로에 맞바꿔 넣는다.
 * @param executable 내려받아 크기와 해시를 확인한 실행 파일.
 * @param sha256 매니페스트에 적힌 해시. 디스크에 쓴 파일을 다시 읽어 이것과 맞댄다.
 * @param version 매니페스트의 버전.
 * @param config 서버가 쓰는 설정 파일. 새 버전이 이 설정을 받아들이는지 맞바꾸기 전에 검사한다.
 */
pub(crate) fn apply(
    executable: &[u8],
    sha256: &[u8; 32],
    version: &str,
    config: Option<&Path>,
) -> Result<Swapped, String> {
    let install = install::current()?;
    let lock = install
        .lock(Duration::ZERO)
        .map_err(|error| error.to_string())?;
    refuse_unfinished(install)?;
    let from_sha256 = install::sha256_file(install.path()).map_err(|error| {
        format!(
            "Could not read the installed executable {}: {error}",
            install.path().display()
        )
    })?;
    let staged = install.stage(&lock, executable)?;
    if staged != *sha256 {
        install.discard_staged(&lock);
        return Err(format!(
            "The new executable written to {} does not match the release; the disk may be failing",
            install.staged().display()
        ));
    }
    if let Err(error) = preflight(&install.staged(), version, config) {
        install.discard_staged(&lock);
        return Err(error);
    }
    let pending = Record {
        state: State::Pending,
        from: VERSION.to_string(),
        to: version.to_string(),
        from_sha256,
        to_sha256: staged,
        reason: None,
    };
    swap(install, &lock, pending).inspect_err(|_| install.discard_staged(&lock))
}

/** @brief 이 버전으로 확정된 업데이트가 없을 때의 오류. */
const NOTHING_TO_ROLL_BACK: &str = "There is no confirmed update to go back from";

/**
 * @brief 되돌릴 확정 업데이트가 있는지 잠금을 잡기 전에 본다.
 * @details 기록만 읽고 실행 파일의 해시는 보지 않는다. 되돌릴 것이 없을 때 설치 디렉터리에 잠금
 *          파일을 만들지 않으려는 것이고, 해시는 잠금을 잡은 뒤에 확인한다.
 */
pub(crate) fn rollback_ready() -> Result<(), String> {
    committed(install::current()?)
        .map(|_| ())
        .ok_or_else(|| NOTHING_TO_ROLL_BACK.to_string())
}

/**
 * @brief 확정된 업데이트를 되돌려 이전 버전을 설치 경로에 넣는다.
 * @details .previous 를 .new 로 옮긴 뒤 적용과 같은 사전 점검을 거친다. 점검이나 맞바꾸기에
 *          실패하면 .previous 로 돌려놓는다. 이전 버전의 유일한 사본이기 때문이다.
 */
pub(crate) fn rollback(config: Option<&Path>) -> Result<Swapped, String> {
    rollback_ready()?;
    let install = install::current()?;
    let lock = install
        .lock(Duration::ZERO)
        .map_err(|error| error.to_string())?;
    let record = rollback_record(install)?;
    let previous = install.previous();
    if install::sha256_file(&previous).ok() != Some(record.from_sha256) {
        return Err(format!(
            "Cannot go back to version {} because {} is missing or was changed",
            record.from,
            previous.display()
        ));
    }
    install.stage_previous(&lock).map_err(|error| {
        format!(
            "Could not prepare {} for reinstalling: {error}",
            previous.display()
        )
    })?;
    let pending = Record {
        state: State::Pending,
        from: record.to.clone(),
        to: record.from.clone(),
        from_sha256: record.to_sha256,
        to_sha256: record.from_sha256,
        reason: None,
    };
    let result = preflight(&install.staged(), &record.from, config)
        .and_then(|()| swap(install, &lock, pending));
    if result.is_err() {
        if let Err(error) = install.unstage_previous(&lock) {
            onetdns_core::error!(event = "update.rollback_restore_failed", path = %previous.display(), %error, "Could not move the previous executable back after a failed rollback; it is left as the staged executable");
        }
    }
    result
}

#[cfg(unix)]
/**
 * @brief 맞바꾼 새 버전을 띄우지 못했을 때 이전 실행 파일로 되돌린다.
 * @details 이 프로세스는 이전 버전이고 기록은 pending 이다. 되돌린 뒤 기록을 reverted 로 바꾼다.
 *          Windows 에는 이 프로세스가 새 버전을 직접 띄우는 경로가 없어 쓰지 않는다.
 */
pub(crate) fn undo_unstarted(reason: &str) -> Result<(), String> {
    let install = install::current()?;
    let lock = install
        .lock(UNDO_LOCK_WAIT)
        .map_err(|error| error.to_string())?;
    let record = install
        .read_record()
        .ok()
        .flatten()
        .and_then(|text| Record::parse(&text))
        .filter(|record| record.state == State::Pending && record.from == VERSION)
        .ok_or_else(|| "There is no installed update to put back".to_string())?;
    if super::trial::revert(install, &lock, &record, reason) {
        Ok(())
    } else {
        Err(format!(
            "Could not put the previous executable back at {}",
            install.path().display()
        ))
    }
}

/**
 * @brief 운영자가 되돌릴 수 있는 버전. 이 버전으로 확정된 업데이트가 없으면 없다.
 * @details 설치 경로와 .previous 의 해시는 확인하지 않는다. 상태를 물을 때마다 실행 파일을 읽지
 *          않으려는 것이고, 실제로 되돌릴 때 확인한다.
 */
pub(crate) fn rollback_target() -> Option<String> {
    let install = install::current().ok()?;
    committed(install)
        .filter(|_| install.previous().exists())
        .map(|record| record.from)
}

/** @brief 이 버전으로 확정된 업데이트 기록. 실행 파일의 해시는 보지 않는다. */
fn committed(install: &Install) -> Option<Record> {
    install
        .read_record()
        .ok()
        .flatten()
        .and_then(|text| Record::parse(&text))
        .filter(|record| record.state == State::Committed && record.to == VERSION)
}

/**
 * @brief 앞선 업데이트의 기동이 끝나지 않았으면 거절한다.
 * @details pending 이나 trial 기록이 지금 실행 파일과 맞으면 그 업데이트가 아직 시험 중이거나
 *          시험을 기다린다. 맞지 않는 기록은 다음 시작이 지울 오래된 기록이라 덮어써도 된다.
 */
fn refuse_unfinished(install: &Install) -> Result<(), String> {
    let text = install.read_record().map_err(|error| {
        format!(
            "Could not read the update record {}: {error}",
            install.record_path().display()
        )
    })?;
    let Some(record) = text.as_deref().and_then(Record::parse) else {
        return Ok(());
    };
    if !matches!(record.state, State::Pending | State::Trial) {
        return Ok(());
    }
    let installed = install::sha256_file(install.path()).map_err(|error| {
        format!(
            "Could not read the installed executable {}: {error}",
            install.path().display()
        )
    })?;
    if record.startup_action(VERSION, &installed) == StartupAction::Discard {
        return Ok(());
    }
    Err(format!(
        "Version {} is installed but has not finished starting; restart OnetDNS before applying another update",
        record.to
    ))
}

/** @brief 되돌릴 수 있는 확정 기록. 지금 실행 파일이 그 업데이트로 설치한 것이어야 한다. */
fn rollback_record(install: &Install) -> Result<Record, String> {
    let installed = install::sha256_file(install.path()).map_err(|error| {
        format!(
            "Could not read the installed executable {}: {error}",
            install.path().display()
        )
    })?;
    install
        .read_record()
        .ok()
        .flatten()
        .and_then(|text| Record::parse(&text))
        .filter(|record| record.startup_action(VERSION, &installed) == StartupAction::Keep)
        .ok_or_else(|| NOTHING_TO_ROLL_BACK.to_string())
}

/**
 * @brief 기록을 pending 으로 쓰고 설치 경로를 맞바꾼다.
 * @details 기록을 먼저 쓴다. 맞바꾼 뒤 기록을 쓰다 죽으면 새 실행 파일이 시험 없이 뜨지만, 맞바꾸기
 *          전에 죽으면 다음 시작이 오래된 기록으로 보고 지운다. 실패하면 기록을 지우고 .new 는
 *          호출자가 정리한다.
 */
fn swap(install: &Install, lock: &UpdateLock, pending: Record) -> Result<Swapped, String> {
    install.write_record(lock, &pending).map_err(|error| {
        format!(
            "Could not write the update record {}: {error}",
            install.record_path().display()
        )
    })?;
    if let Err(error) = install.swap(lock) {
        if let Err(remove) = install.remove_record(lock) {
            onetdns_core::warn!(event = "update.record_remove_failed", path = %install.record_path().display(), error = %remove, "Could not remove the update record after a failed replacement; the next start removes it");
        }
        return Err(format!(
            "Could not replace {}: {error}",
            install.path().display()
        ));
    }
    onetdns_core::info!(
        event = "update.installed",
        version = %pending.to,
        previous = %pending.from,
        "Replaced the executable; the new version is tried out when it starts"
    );
    Ok(Swapped {
        from: pending.from,
        to: pending.to,
    })
}

/**
 * @brief 새 실행 파일이 이 기계에서 실행되고 지금 설정을 받아들이는지 맞바꾸기 전에 확인한다.
 * @param config 서버가 쓰는 설정 파일. 없으면 서버처럼 기본 설정을 검사한다.
 */
fn preflight(executable: &Path, version: &str, config: Option<&Path>) -> Result<(), String> {
    let mut command = Command::new(executable);
    command.arg("--version");
    let finished = run_bounded(command, VERSION_TIMEOUT)?;
    if !finished.success || finished.stdout.trim_end() != crate::cli::version_line(version) {
        return Err(format!(
            "The new executable did not report version {version}; {}",
            finished.describe()
        ));
    }
    let mut command = Command::new(executable);
    command.args(["--cli", "check"]);
    if let Some(config) = config {
        command.arg("--config").arg(config);
    }
    let finished = run_bounded(command, CHECK_TIMEOUT)?;
    if !finished.success {
        return Err(format!(
            "The new version rejected the current configuration; {}",
            finished.describe()
        ));
    }
    Ok(())
}

/** @brief 끝난 점검 프로세스. */
struct Finished {
    /** @brief 0 으로 끝났는지. */
    success: bool,
    /** @brief 종료 상태를 사람이 읽는 형태로. */
    status: String,
    /** @brief 표준 출력의 앞부분. */
    stdout: String,
    /** @brief 표준 오류의 앞부분. */
    stderr: String,
}

impl Finished {
    /** @brief 운영자에게 보일 요약. 종료 상태와 출력을 붙인다. */
    fn describe(&self) -> String {
        let output: Vec<&str> = [self.stderr.trim(), self.stdout.trim()]
            .into_iter()
            .filter(|text| !text.is_empty())
            .collect();
        if output.is_empty() {
            format!("it ended with {}", self.status)
        } else {
            format!("it ended with {}: {}", self.status, output.join(" / "))
        }
    }
}

/**
 * @brief 명령을 실행하고 제한 시간 안에 끝나기를 기다린다.
 * @details 출력은 앞부분만 보관하고 나머지는 읽어서 버린다. 읽지 않으면 파이프가 차서 점검
 *          프로세스가 끝나지 못한다.
 */
fn run_bounded(mut command: Command, timeout: Duration) -> Result<Finished, String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(any(windows, target_os = "linux"))]
    crate::osnet::harden_child_env(&mut command);
    let mut child = spawn(&mut command)?;
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
            Ok(None) => {
                stop(&mut child);
                return Err(format!(
                    "The new executable did not finish within {} seconds",
                    timeout.as_secs()
                ));
            }
            Err(error) => {
                stop(&mut child);
                return Err(format!("Could not wait for the new executable: {error}"));
            }
        }
    };
    Ok(Finished {
        success: status.success(),
        status: status.to_string(),
        stdout: collect(stdout),
        stderr: collect(stderr),
    })
}

/**
 * @brief 방금 쓴 실행 파일을 띄운다.
 * @details Linux 는 쓰기로 열린 파일을 실행하지 않는다(ETXTBSY). 다른 스레드가 같은 때 프로세스를
 *          만들면 그 자식이 exec 하기 전까지 우리가 쓴 파일의 핸들을 잠시 물려받으므로, 잠깐 뒤에
 *          다시 시도한다.
 */
fn spawn(command: &mut Command) -> Result<Child, String> {
    #[cfg(target_os = "linux")]
    for _ in 0..20 {
        match command.spawn() {
            Err(error) if error.raw_os_error() == Some(libc::ETXTBSY) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            other => {
                return other.map_err(|error| format!("Could not run the new executable: {error}"))
            }
        }
    }
    command
        .spawn()
        .map_err(|error| format!("Could not run the new executable: {error}"))
}

/** @brief 점검 프로세스를 강제로 끝내고 거둔다. */
fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/** @brief 파이프를 끝까지 읽는 스레드를 띄운다. 앞부분만 보관한다. */
fn drain(pipe: Option<impl Read + Send + 'static>) -> Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::channel();
    if let Some(mut pipe) = pipe {
        let spawned = std::thread::Builder::new()
            .name("update-preflight".to_string())
            .spawn(move || {
                let mut kept = Vec::new();
                let mut buffer = [0u8; 4096];
                loop {
                    match pipe.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(read) => {
                            let room = MAX_OUTPUT_BYTES.saturating_sub(kept.len());
                            kept.extend_from_slice(&buffer[..read.min(room)]);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
                let _ = sender.send(kept);
            });
        if let Err(error) = spawned {
            onetdns_core::warn!(event = "update.preflight_output_lost", %error, "Could not read the output of the update check; it is not shown");
        }
    }
    receiver
}

/** @brief 읽어 둔 출력. 오래 기다리지 않는다. */
fn collect(receiver: Receiver<Vec<u8>>) -> String {
    receiver
        .recv_timeout(OUTPUT_GRACE)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
}
