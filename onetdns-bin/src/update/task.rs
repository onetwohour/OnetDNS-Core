//! Update check, apply, and rollback tasks and their state. The management API, the CLI, and the
//! periodic check all call these functions. One task runs at a time per process, and the install
//! directory lock serializes processes. Tasks and check results belong to the process, not to a
//! server generation; the last check result lives only in memory and is empty after a restart until
//! the next check.

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

/// Delay from server readiness to the first periodic check, so a process stuck in a crash loop does
/// not call the GitHub API on every start.
const FIRST_CHECK_DELAY: Duration = Duration::from_secs(10 * 60);
const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const SCHEDULE_TICK: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Task {
    Check,
    Apply,
    Rollback,
}

impl Task {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Task::Check => "check",
            Task::Apply => "apply",
            Task::Rollback => "rollback",
        }
    }
}

static RUNNING: Mutex<Option<Task>> = Mutex::new(None);

/// Held while a task runs; dropping it lets the next one start.
pub(crate) struct Running(Task);

impl Running {
    pub(crate) fn task(&self) -> Task {
        self.0
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        *RUNNING.lock_recover() = None;
    }
}

/// Fails while another update task runs.
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

struct Checked {
    /// Unix seconds.
    at: u64,
    /// Err holds why the check failed.
    outcome: Result<Finding, String>,
}

static LAST: Mutex<Option<Checked>> = Mutex::new(None);

/// The asset key and trusted signing keys, or why this binary takes no part in updates.
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

/// Neither records nor logs the result.
fn find(resolver: &HostResolver) -> Result<Finding, String> {
    let (target, keys) = participation()?;
    let current = Version::parse(VERSION)
        .ok_or_else(|| format!("The version of this build ({VERSION}) is not a release version"))?;
    release::check(&current, target, &keys, resolver)
}

/// Records the result for the status response and logs it.
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
            "A newer OnetDNS release is out, but this installation cannot update itself to it; install it manually"
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

/// `version` is the one the operator saw. A different result from the last check is refused, so a
/// result that changed between checks never installs a version the operator did not see.
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

/// The caller starts the new version. The new binary must accept `config`, the server's config
/// file, before the swap.
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

/// The caller starts the restored version.
pub(crate) fn rollback(_running: &Running, config: Option<&Path>) -> Result<Swapped, String> {
    apply::rollback(config).inspect_err(|error| {
        onetdns_core::warn!(
            event = "update.rollback_failed",
            %error,
            "Could not reinstall the previous OnetDNS version"
        );
    })
}

/// Called by management API tasks after the swap. Returns the text for the task result.
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

/// One line, for the task list and the CLI.
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

fn json_text(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_string(), onetdns_core::json::escape)
}

/// `release_check` comes from the running config. Executable hashes are not computed, since the
/// dashboard asks often; applying and rolling back check them.
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

/// What the periodic check reads from the current generation.
struct Feed {
    /// Reads that generation's running config.
    enabled: Box<dyn Fn() -> bool + Send>,
    resolver: HostResolver,
}

/// From the most recently ready generation.
static FEED: Mutex<Option<Feed>> = Mutex::new(None);

/// Called when a generation is ready. The first call starts the periodic thread, which outlives
/// generations and runs until the process exits: DNS is paused during a generation switch, and the
/// switch must not wait for a check that can take tens of seconds. A binary that takes no part in
/// updates starts no thread.
pub(crate) fn schedule(enabled: impl Fn() -> bool + Send + 'static, resolver: HostResolver) {
    if participation().is_err() {
        return;
    }
    *FEED.lock_recover() = Some(Feed {
        enabled: Box::new(enabled),
        resolver,
    });
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

/// Checks when due. When checks are off or another update task runs, it looks again next tick. The
/// next due time is set only after a check finishes.
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

/// The CLI update command. It runs no server, so it only swaps and leaves the restart to the
/// operator. Name resolution and the new version's config check use the given config file.
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
mod tests {
    use super::*;
    use crate::update::manifest::Asset;

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
    /// Both are process-wide state, so one test checks them in turn.
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
    fn builds_without_a_release_target_do_not_participate() {
        if RELEASE_TARGET.is_some() {
            return;
        }
        let reason = participation().expect_err("참여하지 않아야 합니다");
        assert!(reason.contains("release workflow"), "{reason}");
    }
}
