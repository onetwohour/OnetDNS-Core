/*!
 * @brief 서버가 시작할 때 업데이트 기록을 처리하고, 새 버전을 시험 실행한다.
 *
 * @details 시험은 준비 상태에 이르면 확정하고, 준비 전에 실패하거나 기한을 넘기면 되돌린다.
 *          시험하는 동안 잠금을 쥐고 있으므로 그동안 다른 프로세스는 적용을 시작하지 못한다.
 */

use std::fs::File;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::install::{self, Install, LockError, UpdateLock};
use super::record::{Record, StartupAction, State};
use super::VERSION;

/**
 * @brief 시작할 때 다른 프로세스의 적용이나 시험이 끝나기를 기다리는 상한.
 * @details 그래도 잠금을 잡지 못하면 기록을 처리하지 않고 시작한다. 적용은 잠금을 쥔 채 사전
 *          점검을 하므로 점검 제한 시간의 합보다 길어야 한다.
 */
pub(super) const STARTUP_LOCK_WAIT: Duration = Duration::from_secs(120);
/** @brief 잠금을 기다리는 동안 기다리고 있다고 알리는 간격. */
const WAIT_REPORT_INTERVAL: Duration = Duration::from_secs(5);
/** @brief 시험 기한을 확인하는 간격. */
const DEADLINE_POLL: Duration = Duration::from_secs(1);

/**
 * @brief 시험 실행이 준비 상태에 이르러야 하는 기한.
 * @details 지원하는 가장 느린 장치에서 큰 차단 목록을 캐시에서 읽어 시작하는 시간보다 길어야 한다.
 *          짧으면 정상인 새 버전을 되돌린다.
 */
pub(crate) const TRIAL_DEADLINE: Duration = Duration::from_secs(300);

/**
 * @brief 기한이 지나 되돌렸을 때 기록에 남기는 이유.
 * @details 기한을 숫자로 넣지 않는다. 관리 화면이 이 문장을 키로 삼아 번역하고, 기한은 시험을 시작할
 *          때의 로그에 남는다.
 */
const DEADLINE_REASON: &str = "The new version did not become ready before the trial deadline";

/** @brief 서버가 시작할 때 기록을 처리한 결과. */
pub(crate) enum Startup {
    /** @brief 그대로 시작한다. */
    Normal,
    /** @brief 이 버전을 시험 실행한다. */
    Trial(Trial),
    /** @brief 앞선 시험이 실패해 되돌렸다. 이 프로세스는 이어서 돌지 않고 되돌린 실행 파일을 띄운다. */
    Reverted,
}

/** @brief 시험 중인 업데이트. 확정하거나 되돌릴 때까지 잠금을 쥔다. */
pub(crate) struct Trial {
    /** @brief 설치 경로. */
    install: &'static Install,
    /** @brief 업데이트 잠금. 떨어뜨리면 풀린다. */
    lock: UpdateLock,
    /** @brief trial 상태의 기록. */
    record: Record,
    /**
     * @brief 기록 파일 핸들. 시험을 시작할 때 열어 둔다.
     * @details 확정은 준비 상태가 된 뒤, 곧 권한을 내려놓은 뒤에 한다. 그때는 설치 디렉터리에 새
     *          파일을 만들지 못할 수 있어 이 핸들로 덮어쓴다.
     */
    handle: File,
    /** @brief 시험을 시작한 시각. */
    started: Instant,
}

/**
 * @brief 업데이트 기록을 처리한다. 서버를 띄우는 명령이 설정을 읽기 전에 부른다.
 * @param waiting 다른 프로세스가 잠금을 쥐고 있어 기다리는 동안 주기적으로 부른다.
 * @details 설치 경로를 정하지 못했으면 업데이트를 쓸 수 없으므로 처리할 기록도 없다.
 */
pub(crate) fn on_start(waiting: &mut dyn FnMut()) -> Startup {
    match install::current() {
        Ok(install) => process(install, waiting),
        Err(_) => Startup::Normal,
    }
}

/**
 * @brief 이 설치 경로에 남은 업데이트 기록을 처리한다.
 * @details 업데이트가 남긴 파일이 하나도 없으면 잠금 파일도 만들지 않는다. 소스에서 빌드해
 *          띄울 때마다 실행 파일 옆에 파일이 생기지 않게 하려는 것이다.
 */
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

/** @brief 잠금을 기다리며 잡는다. 기다리는 동안 waiting 을 주기적으로 부른다. */
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

/** @brief 지금 실행 파일과 맞지 않는 기록을 지운다. */
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

/**
 * @brief 기록을 trial 로 바꾸고 시험을 시작한다.
 * @details 기록 핸들을 먼저 열고 그 핸들로 trial 을 쓴다. 기록을 쓴 뒤 핸들을 열지 못하면
 *          시험 없이 도는 새 버전의 기록이 trial 로 남아, 다음 시작이 멀쩡한 버전을 되돌린다.
 */
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

/**
 * @brief 이전 실행 파일을 설치 경로로 되돌리고 기록을 reverted 로 바꾼다.
 * @return 되돌렸는지. 되돌리지 못했으면 기록을 그대로 두므로 다음 시작이 다시 되돌려 본다.
 * @details 되돌리지 못하는 경우는 .previous 가 없거나 바뀌었을 때와 설치 디렉터리에 쓸 수 없을
 *          때다. 어느 쪽이든 지금 실행 파일로 계속한다. 멈추면 DNS 가 아예 없어진다.
 */
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
    /** @brief 준비 기한을 넘겼는지. */
    pub(crate) fn expired(&self) -> bool {
        self.started.elapsed() >= TRIAL_DEADLINE
    }

    /** @brief 준비 상태에 이르렀다. 기록을 committed 로 바꾸고 잠금을 푼다. */
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

    /**
     * @brief 시험이 실패했다. 이전 실행 파일로 되돌린다.
     * @return 되돌렸으면 참이고, 호출자는 되돌린 실행 파일을 띄운다.
     */
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

    /** @brief 기한 안에 준비 상태가 되지 않아 되돌린다. */
    pub(crate) fn revert_expired(self) -> bool {
        self.revert(DEADLINE_REASON)
    }
}

/**
 * @brief 이 프로세스가 시험 중인 업데이트.
 * @details 준비 통지, 기한을 재는 스레드, 준비 전 오류 처리 가운데 먼저 꺼낸 쪽이 처리한다.
 *          나머지는 빈 자리를 보고 아무것도 하지 않는다. 감독자 부모는 자기 반복 안에서 시험을
 *          직접 들고 있으므로 이 자리를 쓰지 않는다.
 */
static ACTIVE: Mutex<Option<Trial>> = Mutex::new(None);

/** @brief 걸어 둔 시험을 꺼낸다. */
fn take_active() -> Option<Trial> {
    ACTIVE.lock().unwrap_or_else(PoisonError::into_inner).take()
}

/**
 * @brief 시험을 이 프로세스에 건다.
 * @details 기한은 시험을 시작한 시각부터 잰다. 기한을 재는 스레드는 start_deadline_timer 가 띄운다.
 */
pub(crate) fn hold(trial: Trial) {
    *ACTIVE.lock().unwrap_or_else(PoisonError::into_inner) = Some(trial);
}

/**
 * @brief 걸어 둔 시험이 있으면 기한을 재는 스레드를 띄운다.
 * @details 기한이 지나면 되돌리고 되돌린 실행 파일을 그 스레드에서 곧바로 띄운다.
 * @warning 세대가 권한을 내려놓은 뒤에 불러야 한다. exec 한 프로그램은 부른 스레드의 사용자와
 *          능력을 물려받는데, 내려놓기 전에 뜬 스레드는 능력을 잃어 되돌린 버전이 낮은 포트에
 *          묶지 못한다.
 */
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

/** @brief 서버가 준비 상태에 이르렀을 때 부른다. 시험 중이면 확정한다. */
pub(crate) fn commit_active() {
    if let Some(trial) = take_active() {
        trial.commit();
    }
}

/**
 * @brief 서버가 준비 전에 오류로 끝났을 때 부른다. 시험 중이면 되돌린다.
 * @return 되돌렸으면 참이고, 호출자는 되돌린 실행 파일을 띄운다.
 */
pub(crate) fn revert_after_error(error: &dyn std::fmt::Display) -> bool {
    take_active().is_some_and(|trial| {
        trial.revert(&format!(
            "The new version stopped with an error before it became ready: {error}"
        ))
    })
}

#[cfg(test)]
/** @brief 시작할 때의 기록 처리와, 시험의 확정과 되돌리기. */
mod tests {
    use super::*;
    use crate::update::scratch::Scratch;

    /** @brief 새 버전 실행 파일의 내용. 시작 판정은 해시만 보므로 실행할 수 있는 파일이 아니어도 된다. */
    const NEW: &[u8] = b"new executable";
    /** @brief 이전 버전 실행 파일의 내용. */
    const OLD: &[u8] = b"old executable";

    /** @brief 바이트의 SHA-256. */
    fn sha256(bytes: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes).into()
    }

    /** @brief 프로세스가 시작할 때 정한 설치 경로처럼 끝까지 사는 설치 경로. */
    fn installed_in(scratch: &Scratch) -> &'static Install {
        Box::leak(Box::new(scratch.install()))
    }

    /**
     * @brief 업데이트가 설치 경로를 맞바꾼 직후의 디렉터리에 이 단계의 기록을 쓴다.
     * @details 두 실행 파일 모두 이 바이너리의 버전으로 기록한다.
     */
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

    /** @brief 디스크에 남은 기록. */
    fn stored(install: &Install) -> Option<Record> {
        install
            .read_record()
            .expect("기록 읽기")
            .and_then(|text| Record::parse(&text))
    }

    /** @brief 디스크에 남은 기록의 단계. */
    fn stored_state(install: &Install) -> Option<State> {
        stored(install).map(|record| record.state)
    }

    /** @brief 기록을 처리한다. 다른 프로세스가 잠금을 쥘 일이 없는 테스트에서 쓴다. */
    fn start(install: &'static Install) -> Startup {
        process(install, &mut || panic!("잠금을 기다릴 일이 없습니다"))
    }

    #[test]
    /** @brief 업데이트 파일이 없으면 잠금 파일도 만들지 않고 그대로 시작하는지. */
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
    /** @brief pending 기록이면 시험을 시작하고, 확정하면 committed 로 바꾸고 잠금을 놓는지. */
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
    /** @brief 맞바꾼 새 버전이 아직 뜨지 않았으면 기록을 그대로 두는지. 이전 버전이 다시 시작한 경우다. */
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
    /** @brief 시험이 끝나지 않은 채 남은 기록이면 되돌리고, 그다음 시작은 되돌린 기록을 남겨 두는지. */
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
    /**
     * @brief 되돌릴 수 없으면 지금 실행 파일로 시작하고 trial 기록을 남기는지.
     * @details .previous 가 바뀌었거나 없으면 되돌리지 않는다. 기록을 남겨 두면 다음 시작이 다시 되돌려
     *          본다.
     */
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
    /** @brief 기한을 넘긴 시험은 기한을 이유로 되돌리고 잠금을 놓는지. */
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
    /**
     * @brief 이 프로세스에 건 시험을 준비 전 오류가 한 번만 되돌리는지.
     * @details 이 프로세스의 시험 자리를 쓰는 테스트는 이것 하나여야 한다. 둘이면 동시에 돌면서 서로의
     *          시험을 꺼낸다.
     */
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
    /**
     * @brief 지금 실행 파일과 맞지 않는 기록과 지난 적용이 남긴 파일을 지우는지.
     * @details 깨진 기록과, 손으로 바꾼 실행 파일을 가리키는 확정 기록이다.
     */
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
