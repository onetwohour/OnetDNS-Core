//! Handles the update record at server start and trial-runs a new version: the trial commits once
//! the server is ready, and reverts on an error before that or past the deadline. The lock is held
//! for the whole trial, so no other process can start an apply meanwhile.

use std::fs::File;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::install::{self, Install, LockError, UpdateLock};
use super::record::{Record, StartupAction, State};
use super::VERSION;

/// Cap on waiting at startup for another process's apply or trial; past it, the server starts
/// without handling the record. An apply runs its preflight while holding the lock, so this must
/// exceed the preflight timeouts combined.
pub(super) const STARTUP_LOCK_WAIT: Duration = Duration::from_secs(120);
const WAIT_REPORT_INTERVAL: Duration = Duration::from_secs(5);
const DEADLINE_POLL: Duration = Duration::from_secs(1);

/// Must exceed the time to start from cached large blocklists on the slowest supported device;
/// shorter, it would revert a healthy new version.
pub(crate) const TRIAL_DEADLINE: Duration = Duration::from_secs(300);

/// No number in it: the dashboard translates this sentence by key, and the deadline is logged when
/// the trial starts.
const DEADLINE_REASON: &str = "The new version did not become ready before the trial deadline";

pub(crate) enum Startup {
    Normal,
    Trial(Trial),
    /// An earlier trial failed and was reverted; this process does not continue, but starts the
    /// restored executable.
    Reverted,
}

/// Holds the lock until committed or reverted.
pub(crate) struct Trial {
    install: &'static Install,
    lock: UpdateLock,
    record: Record,
    /// Opened at trial start. The commit comes after the server is ready, which is after privileges
    /// are dropped, when the install directory may no longer allow new files, so it overwrites
    /// through this handle.
    handle: File,
    started: Instant,
}

/// Called before the server command reads its config. `waiting` is called periodically while
/// another process holds the lock. Without an install path there are no updates, so there is no
/// record either.
pub(crate) fn on_start(waiting: &mut dyn FnMut()) -> Startup {
    match install::current() {
        Ok(install) => process(install, waiting),
        Err(_) => Startup::Normal,
    }
}

/// With no update files present, not even a lock file is created, so runs from a source build leave
/// nothing beside the executable.
fn process(install: &'static Install, waiting: &mut dyn FnMut()) -> Startup {
    if !install.has_update_files() {
        return Startup::Normal;
    }
    let lock = match lock_waiting(install, waiting) {
        Ok(lock) => lock,
        Err(error) => {
            onetdns_core::warn!(event = "update.startup_lock_failed", %error, "Could not take the update lock; starting without processing the update record");
            return Startup::Normal;
        }
    };
    install.remove_leftovers(&lock);
    let record = match install.read_record() {
        Ok(Some(text)) => Record::parse(&text),
        Ok(None) => return Startup::Normal,
        Err(error) => {
            onetdns_core::warn!(event = "update.record_read_failed", path = %install.record_path().display(), %error, "Could not read the update record; starting without processing it");
            return Startup::Normal;
        }
    };
    let Some(record) = record else {
        discard(
            install,
            &lock,
            "The update record does not match the format this version writes",
        );
        return Startup::Normal;
    };
    let installed = match install::sha256_file(install.path()) {
        Ok(hash) => hash,
        Err(error) => {
            onetdns_core::warn!(event = "update.installed_hash_failed", path = %install.path().display(), %error, "Could not read the installed executable; starting without processing the update record");
            return Startup::Normal;
        }
    };
    match record.startup_action(VERSION, &installed) {
        StartupAction::StartTrial => begin(install, lock, record),
        StartupAction::Revert => {
            if revert(
                install,
                &lock,
                &record,
                "The new version stopped before it became ready",
            ) {
                Startup::Reverted
            } else {
                Startup::Normal
            }
        }
        StartupAction::ReportReverted => {
            onetdns_core::warn!(
                event = "update.reverted_earlier",
                version = %record.to,
                running = %record.from,
                reason = %record.reason.as_deref().unwrap_or_default(),
                "An update was reverted; running the previous version"
            );
            Startup::Normal
        }
        StartupAction::AwaitActivation | StartupAction::Keep => Startup::Normal,
        StartupAction::Discard => {
            discard(
                install,
                &lock,
                "The update record does not match the installed executable",
            );
            Startup::Normal
        }
    }
}

/// Puts a successor of `version` on trial for a supervisor still running the previous version: the
/// record must say that version was swapped in and has not started. Does not wait for the lock; the
/// apply that swapped it in has released it.
#[cfg(any(target_os = "linux", windows))]
pub(crate) fn for_successor(version: &str) -> Result<Trial, String> {
    successor_trial(install::current()?, version)
}

#[cfg(any(target_os = "linux", windows))]
fn successor_trial(install: &'static Install, version: &str) -> Result<Trial, String> {
    let lock = install
        .lock(Duration::ZERO)
        .map_err(|error| error.to_string())?;
    let record = install
        .read_record()
        .map_err(|error| format!("Could not read the update record: {error}"))?
        .and_then(|text| Record::parse(&text))
        .ok_or("No update is waiting to start")?;
    let installed = install::sha256_file(install.path())
        .map_err(|error| format!("Could not read the installed executable: {error}"))?;
    if record.startup_action(version, &installed) != StartupAction::StartTrial {
        return Err(format!(
            "The update record does not say that version {version} was installed and waits to start"
        ));
    }
    match begin(install, lock, record) {
        Startup::Trial(trial) => Ok(trial),
        _ => Err("Could not mark the new version as being tried out".to_string()),
    }
}

fn lock_waiting(install: &Install, waiting: &mut dyn FnMut()) -> Result<UpdateLock, LockError> {
    let deadline = Instant::now() + STARTUP_LOCK_WAIT;
    let mut reported = false;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match install.lock(left.min(WAIT_REPORT_INTERVAL)) {
            Err(LockError::Busy) if !left.is_zero() => {
                if !reported {
                    reported = true;
                    onetdns_core::info!(
                        event = "update.startup_lock_wait",
                        "Waiting for another process to finish applying or trying out an update"
                    );
                }
                waiting();
            }
            other => return other,
        }
    }
}

fn discard(install: &Install, lock: &UpdateLock, why: &str) {
    match install.remove_record(lock) {
        Ok(()) => onetdns_core::info!(
            event = "update.record_discarded",
            reason = %why,
            "Removed an update record that no longer applies"
        ),
        Err(error) => {
            onetdns_core::warn!(event = "update.record_discard_failed", path = %install.record_path().display(), %error, "Could not remove an update record that no longer applies")
        }
    }
}

/// The record handle opens first and trial is written through it. Opening it after writing could
/// fail and leave a trial record for a version running untested, and the next start would revert a
/// healthy version.
fn begin(install: &'static Install, lock: UpdateLock, record: Record) -> Startup {
    let record = Record {
        state: State::Trial,
        ..record
    };
    let opened = install
        .open_record_for_update(&lock)
        .and_then(|mut handle| install::overwrite(&mut handle, &record.encode()).map(|()| handle));
    match opened {
        Ok(handle) => {
            onetdns_core::info!(
                event = "update.trial_started",
                version = %record.to,
                previous = %record.from,
                deadline_s = TRIAL_DEADLINE.as_secs(),
                "Trying out the new version; it is reverted unless it becomes ready in time"
            );
            Startup::Trial(Trial {
                install,
                lock,
                record,
                handle,
                started: Instant::now(),
            })
        }
        Err(error) => {
            onetdns_core::error!(event = "update.trial_start_failed", path = %install.record_path().display(), %error, "Could not mark the new version as being tried out; it runs without the automatic revert");
            Startup::Normal
        }
    }
}

/// Returns whether it reverted. If not, the record stays and the next start tries again. That
/// happens when .previous is missing or changed, or the install directory is read-only; either way
/// the current executable keeps running, since stopping would leave no DNS at all.
pub(super) fn revert(install: &Install, lock: &UpdateLock, record: &Record, reason: &str) -> bool {
    if let Err(error) = install.restore_previous(lock, &record.from_sha256) {
        onetdns_core::error!(event = "update.revert_failed", version = %record.to, %error, "Could not revert the update; continuing with the installed executable");
        return false;
    }
    let reverted = Record {
        state: State::Reverted,
        reason: Some(reason.to_string()),
        ..record.clone()
    };
    if let Err(error) = install.write_record(lock, &reverted) {
        onetdns_core::warn!(event = "update.revert_record_failed", path = %install.record_path().display(), %error, "Reverted the update but could not record why");
    }
    onetdns_core::error!(
        event = "update.reverted",
        version = %record.to,
        previous = %record.from,
        %reason,
        "Reverted the update to the previous version"
    );
    true
}

impl Trial {
    pub(crate) fn expired(&self) -> bool {
        self.started.elapsed() >= TRIAL_DEADLINE
    }

    /// The server is ready: commits the record and releases the lock.
    pub(crate) fn commit(self) {
        let Trial {
            mut handle, record, ..
        } = self;
        let committed = Record {
            state: State::Committed,
            ..record
        };
        match install::overwrite(&mut handle, &committed.encode()) {
            Ok(()) => onetdns_core::info!(
                event = "update.committed",
                version = %committed.to,
                "The new version became ready; the update is confirmed"
            ),
            Err(error) => {
                onetdns_core::error!(event = "update.commit_failed", version = %committed.to, %error, "Could not record that the new version became ready; the next start reverts it")
            }
        }
    }

    /// True when reverted; the caller then starts the restored executable.
    pub(crate) fn revert(self, reason: &str) -> bool {
        let Trial {
            install,
            lock,
            record,
            handle,
            ..
        } = self;
        drop(handle);
        revert(install, &lock, &record, reason)
    }

    pub(crate) fn revert_expired(self) -> bool {
        self.revert(DEADLINE_REASON)
    }
}

/// Whichever takes it first handles it: the ready notice, the deadline thread, or the pre-ready
/// error path; the others find it empty. The supervisor parent holds its trial inside its own loop
/// and never uses this slot.
static ACTIVE: Mutex<Option<Trial>> = Mutex::new(None);

fn take_active() -> Option<Trial> {
    ACTIVE.lock().unwrap_or_else(PoisonError::into_inner).take()
}

/// The deadline counts from trial start; start_deadline_timer starts the thread that enforces it.
pub(crate) fn hold(trial: Trial) {
    *ACTIVE.lock().unwrap_or_else(PoisonError::into_inner) = Some(trial);
}

/// Past the deadline, that thread reverts and starts the restored executable itself.
///
/// Call it after the generation drops privileges: an exec'd program inherits the calling thread's
/// user and capabilities, and a thread started before the drop loses its capabilities, so the
/// restored version could not bind low ports.
pub(crate) fn start_deadline_timer() {
    if ACTIVE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .is_none()
    {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("update-trial".to_string())
        .spawn(|| {
            loop {
                let expired = ACTIVE
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .as_ref()
                    .map(Trial::expired);
                match expired {
                    None => return,
                    Some(true) => break,
                    Some(false) => std::thread::sleep(DEADLINE_POLL),
                }
            }
            if take_active().is_some_and(Trial::revert_expired) {
                super::launch::start_reverted();
            }
        });
    if let Err(error) = spawned {
        onetdns_core::error!(event = "update.trial_timer_failed", %error, "Could not start the trial deadline timer; the new version is not reverted if it never becomes ready");
    }
}

/// Called when the server is ready; commits a trial in progress.
pub(crate) fn commit_active() {
    if let Some(trial) = take_active() {
        trial.commit();
    }
}

/// Called when the server fails before getting ready; reverts a trial in progress. True when
/// reverted, and the caller then starts the restored executable.
pub(crate) fn revert_after_error(error: &dyn std::fmt::Display) -> bool {
    take_active().is_some_and(|trial| {
        trial.revert(&format!(
            "The new version stopped with an error before it became ready: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update::scratch::Scratch;

    /// Startup decisions only look at hashes, so it need not be executable.
    const NEW: &[u8] = b"new executable";
    const OLD: &[u8] = b"old executable";

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes).into()
    }

    /// Lives until exit, like the install path chosen at process start.
    fn installed_in(scratch: &Scratch) -> &'static Install {
        Box::leak(Box::new(scratch.install()))
    }

    /// Writes a record in this state into a directory as an update leaves it right after the swap.
    /// Both executables are recorded with this binary's version.
    fn swapped(scratch: &Scratch, state: State) -> &'static Install {
        let install = installed_in(scratch);
        std::fs::write(install.path(), NEW).expect("설치 경로");
        std::fs::write(install.previous(), OLD).expect(".previous");
        let record = Record {
            state,
            from: VERSION.to_string(),
            to: VERSION.to_string(),
            from_sha256: sha256(OLD),
            to_sha256: sha256(NEW),
            reason: (state == State::Reverted).then(|| "earlier".to_string()),
        };
        std::fs::write(install.record_path(), record.encode()).expect("기록");
        install
    }

    fn stored(install: &Install) -> Option<Record> {
        install
            .read_record()
            .expect("기록 읽기")
            .and_then(|text| Record::parse(&text))
    }

    fn stored_state(install: &Install) -> Option<State> {
        stored(install).map(|record| record.state)
    }

    /// For tests where no other process holds the lock.
    fn start(install: &'static Install) -> Startup {
        process(install, &mut || panic!("잠금을 기다릴 일이 없습니다"))
    }

    #[test]
    fn nothing_to_process_leaves_the_directory_alone() {
        let scratch = Scratch::new("trial-none");
        let install = installed_in(&scratch);
        std::fs::write(install.path(), NEW).expect("설치 경로");
        assert!(matches!(start(install), Startup::Normal));
        let names: Vec<_> = std::fs::read_dir(&scratch.0)
            .expect("디렉터리")
            .map(|entry| entry.expect("항목").file_name())
            .collect();
        assert_eq!(
            names,
            [install.path().file_name().expect("이름").to_os_string()]
        );
    }

    #[test]
    fn pending_update_is_tried_out_and_committed() {
        let scratch = Scratch::new("trial-commit");
        let install = swapped(&scratch, State::Pending);
        let Startup::Trial(trial) = start(install) else {
            panic!("시험을 시작해야 합니다");
        };
        assert_eq!(stored_state(install), Some(State::Trial));
        assert!(!trial.expired());
        assert!(
            matches!(install.lock(Duration::ZERO), Err(LockError::Busy)),
            "시험하는 동안에는 잠금을 쥐어야 합니다"
        );
        trial.commit();
        assert_eq!(stored_state(install), Some(State::Committed));
        assert_eq!(std::fs::read(install.path()).expect("설치 경로"), NEW);
        assert_eq!(std::fs::read(install.previous()).expect(".previous"), OLD);
        install.lock(Duration::ZERO).expect("확정한 뒤의 잠금");

        assert!(matches!(start(install), Startup::Normal));
        assert_eq!(
            stored_state(install),
            Some(State::Committed),
            "확정한 기록은 되돌리기에 쓰도록 남긴다"
        );
    }

    #[test]
    #[cfg(any(target_os = "linux", windows))]
    fn a_successor_is_tried_out_only_as_the_version_swapped_in() {
        let scratch = Scratch::new("trial-successor");
        let install = swapped(&scratch, State::Pending);
        assert!(successor_trial(install, "999.0.0").is_err());
        assert_eq!(stored_state(install), Some(State::Pending));

        let held = install.lock(Duration::ZERO).expect("잠금");
        assert!(
            successor_trial(install, VERSION).is_err(),
            "다른 적용이 잠금을 쥐고 있습니다"
        );
        drop(held);

        let trial = successor_trial(install, VERSION).expect("시험");
        assert_eq!(stored_state(install), Some(State::Trial));
        assert!(
            successor_trial(install, VERSION).is_err(),
            "시험 중에는 다시 시작하지 않습니다"
        );
        trial.commit();
        assert_eq!(stored_state(install), Some(State::Committed));
        assert!(
            successor_trial(install, VERSION).is_err(),
            "확정한 업데이트는 시험하지 않습니다"
        );
    }

    #[test]
    /// The previous version restarted before the new one ran.
    fn pending_update_waits_while_the_previous_version_runs() {
        let scratch = Scratch::new("trial-await");
        let install = installed_in(&scratch);
        std::fs::write(install.path(), NEW).expect("설치 경로");
        let record = Record {
            state: State::Pending,
            from: VERSION.to_string(),
            to: "999.0.0".to_string(),
            from_sha256: sha256(OLD),
            to_sha256: sha256(NEW),
            reason: None,
        };
        std::fs::write(install.record_path(), record.encode()).expect("기록");
        assert!(matches!(start(install), Startup::Normal));
        assert_eq!(stored(install), Some(record));
    }

    #[test]
    fn unfinished_trial_is_reverted_at_the_next_start() {
        let scratch = Scratch::new("trial-crash");
        let install = swapped(&scratch, State::Trial);
        assert!(matches!(start(install), Startup::Reverted));
        assert_eq!(std::fs::read(install.path()).expect("설치 경로"), OLD);
        assert!(!install.previous().exists());
        let record = stored(install).expect("되돌린 기록");
        assert_eq!(record.state, State::Reverted);
        assert_eq!(
            record.reason.as_deref(),
            Some("The new version stopped before it became ready")
        );

        assert!(matches!(start(install), Startup::Normal));
        assert_eq!(stored(install), Some(record), "되돌린 기록은 남긴다");
        assert!(
            !install.failed().exists(),
            "Windows 가 옮겨 둔 실패한 실행 파일은 지워야 합니다"
        );
    }

    #[test]
    /// Not reverted when .previous changed or is missing; keeping the record lets the next start
    /// try again.
    fn trial_that_cannot_be_reverted_keeps_its_record() {
        let scratch = Scratch::new("trial-stuck");
        let install = swapped(&scratch, State::Trial);
        std::fs::write(install.previous(), b"changed by hand").expect(".previous");
        assert!(matches!(start(install), Startup::Normal));
        assert_eq!(std::fs::read(install.path()).expect("설치 경로"), NEW);
        assert_eq!(stored_state(install), Some(State::Trial));

        std::fs::remove_file(install.previous()).expect(".previous 지우기");
        assert!(matches!(start(install), Startup::Normal));
        assert_eq!(stored_state(install), Some(State::Trial));
    }

    #[test]
    fn expired_trial_is_reverted_with_the_deadline_as_reason() {
        let scratch = Scratch::new("trial-expired");
        let install = swapped(&scratch, State::Pending);
        let Startup::Trial(trial) = start(install) else {
            panic!("시험을 시작해야 합니다");
        };
        assert!(trial.revert_expired());
        assert_eq!(std::fs::read(install.path()).expect("설치 경로"), OLD);
        let record = stored(install).expect("되돌린 기록");
        assert_eq!(record.state, State::Reverted);
        assert_eq!(
            record.reason.as_deref(),
            Some("The new version did not become ready before the trial deadline")
        );
        install.lock(Duration::ZERO).expect("되돌린 뒤의 잠금");
    }

    #[test]
    /// Must be the only test using this process's trial slot; two would run concurrently and take
    /// each other's trials.
    fn error_before_ready_reverts_the_active_trial_once() {
        let scratch = Scratch::new("trial-error");
        let install = swapped(&scratch, State::Pending);
        let Startup::Trial(trial) = start(install) else {
            panic!("시험을 시작해야 합니다");
        };
        hold(trial);
        assert!(revert_after_error(&"bind failed"));
        assert!(!revert_after_error(&"bind failed"), "이미 되돌린 시험");
        commit_active();
        let record = stored(install).expect("되돌린 기록");
        assert_eq!(record.state, State::Reverted);
        assert_eq!(
            record.reason.as_deref(),
            Some("The new version stopped with an error before it became ready: bind failed")
        );
    }

    #[test]
    /// A broken record, and a committed record pointing at a hand-replaced executable.
    fn stale_records_and_leftovers_are_removed() {
        let scratch = Scratch::new("trial-stale");
        let install = installed_in(&scratch);
        std::fs::write(install.path(), NEW).expect("설치 경로");
        std::fs::write(install.record_path(), "garbage").expect("깨진 기록");
        std::fs::write(install.staged(), b"half written").expect(".new");
        assert!(matches!(start(install), Startup::Normal));
        assert!(!install.record_path().exists(), "깨진 기록");
        assert!(!install.staged().exists(), "남은 .new");

        let install = swapped(&scratch, State::Committed);
        std::fs::write(install.path(), b"replaced by hand").expect("손으로 바꾼 실행 파일");
        assert!(matches!(start(install), Startup::Normal));
        assert!(!install.record_path().exists(), "맞지 않는 확정 기록");
    }
}
