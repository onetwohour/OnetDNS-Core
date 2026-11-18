//! Swaps the verified executable into the install path. An operator rollback runs the same steps
//! with .previous as the source. This only swaps; the caller starts the new version in whatever way
//! the server runs.

use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use super::install::{self, Install, UpdateLock};
use super::record::{Record, StartupAction, State};
use super::VERSION;

const VERSION_TIMEOUT: Duration = Duration::from_secs(15);
/// Long enough to connect to zone source databases.
const CHECK_TIMEOUT: Duration = Duration::from_secs(60);
/// Check output shown to the operator is cut here.
const MAX_OUTPUT_BYTES: usize = 8 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(20);
/// How long to keep reading output after the check exits, in case a grandchild holds the pipe.
const OUTPUT_GRACE: Duration = Duration::from_secs(2);
/// Lock wait when undoing a new version that failed to start, once the process that applied it lets
/// go.
const UNDO_LOCK_WAIT: Duration = Duration::from_secs(5);

const _: () = assert!(
    super::trial::STARTUP_LOCK_WAIT.as_secs() > VERSION_TIMEOUT.as_secs() + CHECK_TIMEOUT.as_secs(),
    "a starting server must outwait the preflight of an update being applied"
);

#[derive(Debug)]
pub(crate) struct Swapped {
    pub(crate) from: String,
    pub(crate) to: String,
}

/// Checked before the download: takes the lock and releases it at once. A read-only install
/// directory or an unfinished earlier update fails here, before the executable is fetched. The lock
/// is not held during the download, so a server starting meanwhile does not wait for it; applying
/// takes it again.
pub(crate) fn ready_to_apply() -> Result<(), String> {
    let install = install::current()?;
    let _lock = install
        .lock(Duration::ZERO)
        .map_err(|error| error.to_string())?;
    refuse_unfinished(install)
}

/// `executable` has been size- and hash-checked against the manifest; the written file is read back
/// and compared with `sha256` again. Before the swap, the new binary must accept `config`, the
/// server's config file.
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

const NOTHING_TO_ROLL_BACK: &str = "There is no confirmed update to go back from";

/// Checked before locking, from the record alone, so nothing creates a lock file in the install
/// directory when there is nothing to roll back. The executable hash is checked after locking.
pub(crate) fn rollback_ready() -> Result<(), String> {
    committed(install::current()?)
        .map(|_| ())
        .ok_or_else(|| NOTHING_TO_ROLL_BACK.to_string())
}

/// Moves .previous to .new and runs the same preflight as an apply. If the preflight or swap fails,
/// .previous is restored: it is the only copy of the previous version.
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

/// Restores the previous executable when the swapped-in version could not start. This process is
/// the previous version and the record is pending; after the restore, the record becomes reverted.
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

/// The version an operator can roll back to; None without a committed update. Hashes are not
/// checked, so status queries do not read executables; the rollback itself checks them.
pub(crate) fn rollback_target() -> Option<String> {
    let install = install::current().ok()?;
    committed(install)
        .filter(|_| install.previous().exists())
        .map(|record| record.from)
}

/// Executable hashes are not checked.
fn committed(install: &Install) -> Option<Record> {
    install
        .read_record()
        .ok()
        .flatten()
        .and_then(|text| Record::parse(&text))
        .filter(|record| record.state == State::Committed && record.to == VERSION)
}

/// A pending or trial record that matches the current executable means that update is on trial or
/// waiting for one. A record that does not match is stale, removed by the next start, and safe to
/// overwrite.
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

/// The installed executable must be the one that update installed.
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

/// The record goes first. Dying after the swap but before the record would start the new executable
/// without a trial; dying before the swap leaves a record the next start sees as stale and removes.
/// On failure the record is removed; the caller cleans up .new.
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

/// Checks that the new executable runs on this machine and accepts the current config.
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

struct Finished {
    success: bool,
    status: String,
    stdout: String,
    stderr: String,
}

impl Finished {
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

/// Only the start of the output is kept; the rest is read and dropped, since an unread pipe fills
/// up and the check never exits.
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

/// Linux refuses to execute a file open for writing (ETXTBSY). A child forked by another thread at
/// the same moment holds our write handle until it execs, so this retries briefly.
pub(super) fn spawn(command: &mut Command) -> Result<Child, String> {
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

fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Reads the pipe to the end on its own thread, keeping only the start.
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

/// Waits at most OUTPUT_GRACE.
fn collect(receiver: Receiver<Vec<u8>>) -> String {
    receiver
        .recv_timeout(OUTPUT_GRACE)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    /// The child that another thread forked, holding the write handle until it execs, is simulated
    /// by this process holding a handle and closing it shortly after. The kernel refuses execution
    /// while any process has the file open for writing.
    fn spawn_retries_while_the_file_is_open_for_writing() {
        use super::*;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let scratch = crate::update::scratch::Scratch::new("text-busy");
        let path = scratch.0.join("script");
        let mut file = std::fs::File::create(&path).expect("스크립트");
        file.write_all(b"#!/bin/sh\nexit 0\n")
            .expect("스크립트 쓰기");
        file.set_permissions(std::fs::Permissions::from_mode(0o755))
            .expect("실행 권한");

        let refused = Command::new(&path).spawn();
        assert_eq!(
            refused.err().and_then(|error| error.raw_os_error()),
            Some(libc::ETXTBSY),
            "쓰기로 열린 파일의 실행이 거부되지 않아 재시도를 확인할 수 없습니다"
        );

        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(file);
        });
        let mut child = spawn(&mut Command::new(&path)).expect("핸들이 닫힌 뒤의 실행");
        assert!(child.wait().expect("스크립트 종료").success());
        release.join().expect("핸들을 닫는 스레드");
    }
}
