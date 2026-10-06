/*!
 * @brief 업데이트 확인, 적용, 되돌리기 작업과 그 상태.
 *
 * @details 관리 API, CLI, 주기 확인이 같은 함수를 부른다. 작업은 한 프로세스에서 한 번에 하나만
 *          돌고, 프로세스 사이는 설치 디렉터리의 잠금이 묶는다. 작업과 확인 결과는 서버 세대가
 *          아니라 프로세스에 속한다. 마지막 확인 결과는 메모리에만 두므로 프로세스가 다시 시작하면
 *          다음 확인 때까지 비어 있다.
 */

use std::path::Path;
use std::sync::{Mutex, Once};
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;
use onetdns_core::MutexExt;

use super::apply::{self, Swapped};
use super::install;
use super::launch;
use super::manifest;
use super::record::Record;
use super::release::{self, Finding, Release};
use super::version::Version;
use super::{RELEASE_TARGET, VERSION};
use crate::cli::UpdateAction;
use crate::http::HostResolver;

/**
 * @brief 처음 주기 확인은 서버가 준비되고 이만큼 뒤에 한다.
 * @details 시작하자마자 죽고 다시 뜨기를 되풀이하는 프로세스가 GitHub API 를 같은 빈도로 부르지 않게
 *          하려는 것이다.
 */
const FIRST_CHECK_DELAY: Duration = Duration::from_secs(10 * 60);
/** @brief 주기 확인 간격. */
const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/** @brief 주기 확인을 할 때가 됐는지 보는 간격. */
const SCHEDULE_TICK: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 업데이트 작업의 종류. */
pub(crate) enum Task {
    /** @brief 새 릴리스를 확인한다. */
    Check,
    /** @brief 확인한 새 버전을 설치한다. */
    Apply,
    /** @brief 확정된 업데이트를 되돌린다. */
    Rollback,
}

impl Task {
    /** @brief 상태 응답과 작업 목록에 쓰는 이름. */
    pub(crate) fn name(self) -> &'static str {
        match self {
            Task::Check => "check",
            Task::Apply => "apply",
            Task::Rollback => "rollback",
        }
    }
}

/** @brief 지금 도는 작업. */
static RUNNING: Mutex<Option<Task>> = Mutex::new(None);

/** @brief 작업을 맡은 동안 쥐는 표. 놓으면 다음 작업을 시작할 수 있다. */
pub(crate) struct Running(Task);

impl Running {
    /** @brief 맡은 작업. */
    pub(crate) fn task(&self) -> Task {
        self.0
    }
}

impl Drop for Running {
    /** @brief 작업이 끝났다고 적는다. */
    fn drop(&mut self) {
        *RUNNING.lock_recover() = None;
    }
}

/** @brief 작업을 시작한다. 다른 업데이트 작업이 돌고 있으면 거절한다. */
pub(crate) fn begin(task: Task) -> Result<Running, String> {
    let mut running = RUNNING.lock_recover();
    if let Some(other) = *running {
        return Err(format!(
            "Another update task ({}) is running; try again when it finishes",
            other.name()
        ));
    }
    *running = Some(task);
    Ok(Running(task))
}

/** @brief 마지막 확인. */
struct Checked {
    /** @brief 확인을 마친 시각. 유닉스 초다. */
    at: u64,
    /** @brief 결과. 확인하지 못했으면 그 이유. */
    outcome: Result<Finding, String>,
}

/** @brief 이 프로세스의 마지막 확인. */
static LAST: Mutex<Option<Checked>> = Mutex::new(None);

/**
 * @brief 이 바이너리가 업데이트에 참여하는지 본다.
 * @return 참여하면 자산 키와 믿는 서명 키. 참여하지 않으면 그 이유.
 */
pub(crate) fn participation() -> Result<(&'static str, Vec<VerifyingKey>), String> {
    let target = RELEASE_TARGET.ok_or_else(|| {
        "This executable was not built by the OnetDNS release workflow, so it does not update itself"
            .to_string()
    })?;
    let keys = manifest::trusted_keys()?;
    if keys.is_empty() {
        return Err(
            "This executable has no release signing key, so it cannot verify releases".to_string(),
        );
    }
    install::current()?;
    Ok((target, keys))
}

/** @brief 새 릴리스를 확인한다. 결과를 남기지도 로그로 알리지도 않는다. */
fn find(resolver: &HostResolver) -> Result<Finding, String> {
    let (target, keys) = participation()?;
    let current = Version::parse(VERSION)
        .ok_or_else(|| format!("The version of this build ({VERSION}) is not a release version"))?;
    release::check(&current, target, &keys, resolver)
}

/** @brief 새 릴리스를 확인하고 결과를 상태 응답과 로그에 남긴다. */
pub(crate) fn check(_running: &Running, resolver: &HostResolver) -> Result<Finding, String> {
    let outcome = find(resolver);
    match &outcome {
        Ok(Finding::UpToDate) => onetdns_core::info!(
            event = "update.up_to_date",
            version = VERSION,
            "No newer OnetDNS release is available"
        ),
        Ok(Finding::Available(release)) => onetdns_core::info!(
            event = "update.available",
            version = %release.version,
            "A newer OnetDNS release is available"
        ),
        Ok(Finding::Manual { version, reason }) => onetdns_core::warn!(
            event = "update.manual_install",
            %version,
            %reason,
            "A newer OnetDNS release cannot be installed automatically; install it manually"
        ),
        Err(error) => onetdns_core::warn!(
            event = "update.check_failed",
            %error,
            "Could not check for a new OnetDNS release"
        ),
    }
    *LAST.lock_recover() = Some(Checked {
        at: crate::unix_now(),
        outcome: outcome.clone(),
    });
    outcome
}

/**
 * @brief 마지막 확인에서 찾은, 설치할 수 있는 릴리스.
 * @param version 운영자가 확인한 버전. 마지막 확인 결과와 다르면 거절한다. 확인 주기 사이에 결과가
 *        바뀌어도 운영자가 본 버전만 설치하려는 것이다.
 */
pub(crate) fn confirmed(version: &str) -> Result<Release, String> {
    match LAST.lock_recover().as_ref().map(|checked| &checked.outcome) {
        Some(Ok(Finding::Available(release))) if release.version == version => Ok(release.clone()),
        Some(Ok(Finding::Available(release))) => Err(format!(
            "The last check found version {}, not {version}; review it before applying",
            release.version
        )),
        _ => Err(format!(
            "The last check did not find version {version} to install; check for updates first"
        )),
    }
}

/**
 * @brief 릴리스를 받아 설치 경로의 실행 파일과 맞바꾼다. 새 버전을 띄우는 일은 호출자가 한다.
 * @param config 서버가 쓰는 설정 파일. 새 버전이 이 설정을 받아들이는지 맞바꾸기 전에 검사한다.
 */
pub(crate) fn install_release(
    _running: &Running,
    release: &Release,
    resolver: &HostResolver,
    config: Option<&Path>,
) -> Result<Swapped, String> {
    apply::ready_to_apply()
        .and_then(|()| release::download(release, resolver))
        .and_then(|executable| {
            apply::apply(&executable, &release.asset.sha256, &release.version, config)
        })
        .inspect_err(|error| {
            onetdns_core::warn!(
                event = "update.apply_failed",
                version = %release.version,
                %error,
                "Could not install the new OnetDNS release"
            );
        })
}

/** @brief 확정된 업데이트를 되돌려 바꾸기 전 버전을 다시 설치한다. 띄우는 일은 호출자가 한다. */
pub(crate) fn rollback(_running: &Running, config: Option<&Path>) -> Result<Swapped, String> {
    apply::rollback(config).inspect_err(|error| {
        onetdns_core::warn!(
            event = "update.rollback_failed",
            %error,
            "Could not reinstall the previous OnetDNS version"
        );
    })
}

/**
 * @brief 맞바꾼 실행 파일을 띄우게 한다. 관리 API 의 작업이 맞바꾼 뒤에 부른다.
 * @return 작업 결과로 남길 문구.
 */
pub(crate) fn activate(swapped: &Swapped) -> String {
    if launch::request_restart() {
        format!(
            "Installed version {}; OnetDNS is restarting into it",
            swapped.to
        )
    } else {
        format!(
            "Installed version {}; restart OnetDNS to start it, and version {} is put back if it does not become ready",
            swapped.to, swapped.from
        )
    }
}

/** @brief 확인 결과를 한 줄로. 작업 목록과 CLI 에 보인다. */
pub(crate) fn describe(finding: &Finding) -> String {
    match finding {
        Finding::UpToDate => format!("OnetDNS {VERSION} is the newest release"),
        Finding::Available(release) => format!(
            "Version {} is available: {}",
            release.version,
            release::release_page(&release.version)
        ),
        Finding::Manual { version, reason } => format!(
            "Version {version} must be installed manually ({reason}): {}",
            release::release_page(version)
        ),
    }
}

/** @brief 값이 있으면 JSON 문자열, 없으면 null. */
fn json_text(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_string(), onetdns_core::json::escape)
}

/**
 * @brief 관리 API 가 보이는 업데이트 상태.
 * @param release_check 주기 확인이 켜져 있는지. 실행 중 설정에서 읽어 넘긴다.
 * @details 실행 파일의 해시는 계산하지 않는다. 화면이 자주 묻는 응답이라 실행 파일을 읽지 않으려는
 *          것이고, 해시는 실제로 적용하거나 되돌릴 때 확인한다.
 */
pub(crate) fn status_json(release_check: bool) -> String {
    let reason = participation().err();
    let task = *RUNNING.lock_recover();
    let (checked_at, result, new_version, detail) = match LAST.lock_recover().as_ref() {
        None => (None, None, None, None),
        Some(Checked { at, outcome }) => {
            let (result, version, detail) = match outcome {
                Ok(Finding::UpToDate) => ("up_to_date", None, None),
                Ok(Finding::Available(release)) => {
                    ("available", Some(release.version.clone()), None)
                }
                Ok(Finding::Manual { version, reason }) => {
                    ("manual", Some(version.clone()), Some(reason.clone()))
                }
                Err(error) => ("failed", None, Some(error.clone())),
            };
            (Some(*at), Some(result), version, detail)
        }
    };
    let record = install::current()
        .ok()
        .and_then(|install| install.read_record().ok().flatten())
        .and_then(|text| Record::parse(&text))
        .map_or_else(
            || "null".to_string(),
            |record| {
                format!(
                    "{{\"state\":\"{}\",\"from\":{},\"to\":{},\"reason\":{}}}",
                    record.state.name(),
                    json_text(Some(&record.from)),
                    json_text(Some(&record.to)),
                    json_text(record.reason.as_deref())
                )
            },
        );
    format!(
        "{{\"version\":{},\"target\":{},\"participating\":{},\"reason\":{},\"launch\":\"{}\",\"release_check\":{},\"task\":{},\"checked_at\":{},\"result\":{},\"new_version\":{},\"release_url\":{},\"detail\":{},\"record\":{},\"rollback\":{}}}",
        json_text(Some(VERSION)),
        json_text(RELEASE_TARGET),
        reason.is_none(),
        json_text(reason.as_deref()),
        launch::current().name(),
        release_check,
        json_text(task.map(Task::name)),
        checked_at.map_or_else(|| "null".to_string(), |at| at.to_string()),
        json_text(result),
        json_text(new_version.as_deref()),
        json_text(new_version.as_deref().map(release::release_page).as_deref()),
        json_text(detail.as_deref()),
        record,
        json_text(apply::rollback_target().as_deref())
    )
}

/** @brief 주기 확인이 읽는 지금 세대의 설정과 이름 해석기. */
struct Feed {
    /** @brief 주기 확인이 켜져 있는지. 그 세대의 실행 중 설정을 읽는다. */
    enabled: Box<dyn Fn() -> bool + Send>,
    /** @brief 릴리스를 받을 때 쓰는 이름 해석기. */
    resolver: HostResolver,
}

/** @brief 가장 최근에 준비된 세대가 넘긴 것. */
static FEED: Mutex<Option<Feed>> = Mutex::new(None);

/**
 * @brief 세대가 준비되면 주기 확인에 그 세대의 설정과 이름 해석기를 넘긴다.
 * @details 처음 부를 때 주기 확인 스레드를 띄운다. 이 스레드는 세대가 끝나도 멈추지 않고 프로세스가
 *          끝날 때까지 돈다. 세대를 바꾸는 동안에는 DNS 가 멈춰 있는데, 몇십 초 걸릴 수 있는 확인을
 *          그동안 기다리지 않으려는 것이다. 업데이트에 참여하지 않는 바이너리는 스레드를 띄우지 않는다.
 */
pub(crate) fn schedule(enabled: impl Fn() -> bool + Send + 'static, resolver: HostResolver) {
    if participation().is_err() {
        return;
    }
    *FEED.lock_recover() = Some(Feed {
        enabled: Box::new(enabled),
        resolver,
    });
    /** @brief 주기 확인 스레드를 한 번만 띄운다. */
    static STARTED: Once = Once::new();
    STARTED.call_once(|| {
        let first = Instant::now() + FIRST_CHECK_DELAY;
        if let Err(error) = std::thread::Builder::new()
            .name("update-check".to_string())
            .spawn(move || run_schedule(first))
        {
            onetdns_core::warn!(
                event = "update.schedule_failed",
                %error,
                "Could not start the periodic release check"
            );
        }
    });
}

/**
 * @brief 때가 되면 새 릴리스를 확인한다.
 * @details 꺼져 있거나 다른 업데이트 작업이 돌고 있으면 다음 틱에 다시 본다. 확인을 마친 뒤에만
 *          다음 확인 시각을 정한다.
 */
fn run_schedule(mut due: Instant) {
    loop {
        std::thread::sleep(SCHEDULE_TICK);
        if Instant::now() < due {
            continue;
        }
        let resolver = FEED
            .lock_recover()
            .as_ref()
            .filter(|feed| (feed.enabled)())
            .map(|feed| feed.resolver.clone());
        let Some(resolver) = resolver else {
            continue;
        };
        let Ok(running) = begin(Task::Check) else {
            continue;
        };
        let _ = check(&running, &resolver);
        due = Instant::now() + CHECK_INTERVAL;
    }
}

/**
 * @brief CLI 의 update 명령.
 * @details 서버를 띄우지 않으므로 맞바꾸기까지만 하고 다시 시작은 운영자에게 맡긴다. 이름 해석과
 *          새 버전의 설정 검사는 넘겨받은 설정 파일을 쓴다.
 */
pub(crate) fn run_cli(action: UpdateAction, config: Option<&Path>) -> Result<(), String> {
    let cfg = onetdns_config::Config::load_or_default(config)
        .map_err(|error| format!("Could not read the configuration: {error}"))?;
    let resolver = crate::filters::blocklist_host_resolver(&cfg);
    match action {
        UpdateAction::Check => {
            let _running = begin(Task::Check)?;
            println!("{}", describe(&find(&resolver)?));
        }
        UpdateAction::Apply { version } => {
            let running = begin(Task::Apply)?;
            let release = match find(&resolver)? {
                Finding::Available(release) => release,
                Finding::UpToDate => {
                    println!("{}", describe(&Finding::UpToDate));
                    return Ok(());
                }
                manual @ Finding::Manual { .. } => return Err(describe(&manual)),
            };
            if let Some(version) = version.filter(|version| *version != release.version) {
                return Err(format!(
                    "The newest release is version {}, not {version}",
                    release.version
                ));
            }
            let swapped = install_release(&running, &release, &resolver, config)?;
            println!(
                "Installed version {} in place of version {}.",
                swapped.to, swapped.from
            );
            println!(
                "Restart OnetDNS to start it. It is tried out when it starts, and version {} is put back if it does not become ready.",
                swapped.from
            );
        }
        UpdateAction::Rollback => {
            let running = begin(Task::Rollback)?;
            let swapped = rollback(&running, config)?;
            println!(
                "Reinstalled version {} in place of version {}.",
                swapped.to, swapped.from
            );
            println!("Restart OnetDNS to start it.");
        }
    }
    Ok(())
}

#[cfg(test)]
/** @brief 작업을 하나씩 돌리는 규칙과 적용할 버전의 확인. */
mod tests {
    use super::*;
    use crate::update::manifest::Asset;

    /** @brief 마지막 확인에서 이 버전을 찾은 것으로 둔다. */
    fn found(version: &str) {
        *LAST.lock_recover() = Some(Checked {
            at: 1,
            outcome: Ok(Finding::Available(Release {
                version: version.to_string(),
                asset: Asset {
                    target: "x86_64-unknown-linux-musl".to_string(),
                    file: manifest::asset_file_name(version, "x86_64-unknown-linux-musl"),
                    size: 1,
                    sha256: [0; 32],
                },
            })),
        });
    }

    #[test]
    /**
     * @brief 작업은 하나씩만 돌고, 적용은 마지막 확인에서 찾은 버전만 받는지.
     * @details 둘 다 프로세스 전역 상태라 테스트 하나에서 차례로 본다.
     */
    fn tasks_run_one_at_a_time_and_apply_only_the_checked_version() {
        let check = begin(Task::Check).expect("첫 작업");
        assert_eq!(check.task(), Task::Check);
        let refused = begin(Task::Apply)
            .err()
            .expect("두 번째 작업은 거절해야 합니다");
        assert!(refused.contains("check"), "{refused}");
        let status: onetdns_core::json::Json =
            onetdns_core::json::parse(&status_json(true)).expect("상태 JSON");
        assert_eq!(
            status.get("task").and_then(|task| task.as_str()),
            Some("check")
        );
        drop(check);
        drop(begin(Task::Rollback).expect("앞 작업이 끝난 뒤"));

        *LAST.lock_recover() = None;
        assert!(confirmed("0.2.0").is_err(), "확인한 적이 없습니다");
        found("0.2.0");
        assert_eq!(
            confirmed("0.2.0").map(|release| release.version),
            Ok("0.2.0".to_string())
        );
        let other = confirmed("0.3.0").expect_err("다른 버전");
        assert!(other.contains("0.2.0"), "{other}");
        *LAST.lock_recover() = Some(Checked {
            at: 2,
            outcome: Err("network down".to_string()),
        });
        assert!(confirmed("0.2.0").is_err(), "확인이 실패한 뒤");

        found("0.2.0");
        let status = onetdns_core::json::parse(&status_json(false)).expect("상태 JSON");
        assert_eq!(
            status.get("result").and_then(|value| value.as_str()),
            Some("available")
        );
        assert_eq!(
            status.get("new_version").and_then(|value| value.as_str()),
            Some("0.2.0")
        );
        assert_eq!(
            status.get("release_url").and_then(|value| value.as_str()),
            Some("https://github.com/onetwohour/OnetDNS-Core/releases/tag/v0.2.0")
        );
        assert_eq!(
            status.get("version").and_then(|value| value.as_str()),
            Some(VERSION)
        );
        assert!(matches!(
            status.get("release_check"),
            Some(onetdns_core::json::Json::Bool(false))
        ));
        assert!(matches!(
            status.get("task"),
            Some(onetdns_core::json::Json::Null)
        ));
        *LAST.lock_recover() = None;
    }

    #[test]
    /** @brief 릴리스 워크플로가 만들지 않은 빌드는 참여하지 않고 그 이유를 보이는지. */
    fn builds_without_a_release_target_do_not_participate() {
        if RELEASE_TARGET.is_some() {
            return;
        }
        let reason = participation().expect_err("참여하지 않아야 합니다");
        assert!(reason.contains("release workflow"), "{reason}");
    }
}
