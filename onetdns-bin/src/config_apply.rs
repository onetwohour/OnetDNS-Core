//! Writes config edits to the file and decides, by the changed keys, whether to swap them in now or
//! start a new generation.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use onetdns_config::{BackendKind, Config};
use onetdns_core::ArcSwap;

use crate::atomic_file::atomic_write;
use crate::config_keys::ApplyGroup;
use crate::{config_keys, resolver_chain, runtime_preflight, ConfigTextSlot};

/// Local-only name settings decided below the response cache. Their verdicts are cached, so
/// changing them must clear the cache for the new verdict to show at once.
pub(crate) const LOCAL_ONLY_CONFIG_KEYS: &[&str] = &["domain_needed", "bogus_priv", "empty_zones"];

/// Directly changed groups plus the derived groups they must rebuild.
pub(crate) fn hot_reload_groups(
    previous: &Config,
    next: &Config,
    changed: &[String],
) -> Vec<ApplyGroup> {
    let mut groups = key_groups(changed);
    // The chain reads only the plan, so a changed plan rebuilds the chain whatever key changed.
    // Keys in the forward group, such as the query timeout, also feed the forwarders of stub zones
    // and fallback upstreams.
    if resolver_chain::ChainPlan::new(previous) != resolver_chain::ChainPlan::new(next) {
        groups.push(ApplyGroup::Chain);
        groups.sort_unstable();
        groups.dedup();
    }
    groups
}

/// Groups the changed keys pull in through the key table and group dependencies; the chain plan is
/// not compared.
fn key_groups(changed: &[String]) -> Vec<ApplyGroup> {
    let mut groups = changed
        .iter()
        .filter_map(|key| config_keys::hot_group(key))
        .flat_map(|group| [Some(group), group.also_rebuilds()])
        .flatten()
        .collect::<Vec<_>>();
    groups.sort_unstable();
    groups.dedup();
    groups
}

pub(crate) fn backend_uses_forward(backend: BackendKind) -> bool {
    matches!(backend, BackendKind::Forward | BackendKind::Split)
}

/// `plan_inputs`: keys of other groups the plan reads, from `ChainPlan::other_group_inputs`.
fn rebuilds_chain(key: &str, plan_inputs: &[&str]) -> bool {
    plan_inputs.contains(&key) || key_groups(&[key.to_string()]).contains(&ApplyGroup::Chain)
}

/// Changed keys that take effect only after a service restart; empty means all of them hot-swap.
/// Hot apply and the change preview share this one verdict; a separate preview verdict would
/// announce a restarting change as hot.
///
/// With client upstream routes, a change that rebuilds the chain restarts: each route's chain wraps
/// the shared layers and is built once at generation start, never swapped, so rebuilding only the
/// default chain would leave those clients on the old cache size or validation settings. When the
/// key that triggered the rebuild cannot be singled out, a restart is still needed, so every
/// changed key is listed.
pub(crate) fn service_restart_keys(
    current: &Config,
    proposed: &Config,
    changed: &[String],
) -> Vec<String> {
    let mut restart: Vec<String> = changed
        .iter()
        .filter(|key| !config_keys::swappable(key, current, proposed))
        .cloned()
        .collect();
    let routes =
        config_keys::has_client_routes(current) || config_keys::has_client_routes(proposed);
    if routes && hot_reload_groups(current, proposed, changed).contains(&ApplyGroup::Chain) {
        let mut inputs = resolver_chain::ChainPlan::new(current).other_group_inputs();
        inputs.extend(resolver_chain::ChainPlan::new(proposed).other_group_inputs());
        let rebuilding: Vec<String> = changed
            .iter()
            .filter(|key| rebuilds_chain(key, &inputs))
            .cloned()
            .collect();
        restart.extend(if rebuilding.is_empty() {
            changed.to_vec()
        } else {
            rebuilding
        });
        restart.sort();
        restart.dedup();
    }
    restart
}

/// Keys the table marks hot that can still restart under the current config, so the dashboard can
/// warn before applying. Derived from the same rules as `service_restart_keys`: every key whose
/// single change could restart under the current config is included. Keys like `clients`, whose
/// effect depends on the new value, are always included.
pub(crate) fn conditional_hot_reload_keys(now: &Config) -> Vec<&'static str> {
    let routes = config_keys::has_client_routes(now);
    let inputs = resolver_chain::ChainPlan::new(now).other_group_inputs();
    config_keys::hot_keys()
        .filter(|key| {
            config_keys::may_need_new_generation(key, now)
                || (routes && rebuilds_chain(key, &inputs))
        })
        .collect()
}

#[derive(Clone)]
pub(crate) struct ChainRebuild {
    pub(crate) chain: Arc<resolver_chain::DefaultChain>,
    /// Read by the query handler.
    pub(crate) slot: crate::native::ResolverSlot,
}

/// Restarts a generation-owned side task with a new config.
pub(crate) type SecondaryRestart = Arc<dyn Fn(&Config) -> Result<(), String> + Send + Sync>;

/// Handles of the tasks to restart on a config change. The code that fills them runs late in
/// generation start, but hot apply is built before that, so empty slots are taken first and filled
/// later; a hot apply arriving before a slot is filled skips that task.
#[derive(Clone, Default)]
pub(crate) struct RestartHooks {
    pub(crate) chain: Arc<Mutex<Option<ChainRebuild>>>,
    /// Reopens the control listen address.
    pub(crate) control: Arc<Mutex<Option<SecondaryRestart>>>,
    /// Restarts secondary zone refresh.
    pub(crate) secondary: Arc<Mutex<Option<SecondaryRestart>>>,
    /// Restarts DHCP lease sync.
    pub(crate) lease_sync: Arc<Mutex<Option<SecondaryRestart>>>,
    pub(crate) raft: Arc<Mutex<Option<SecondaryRestart>>>,
    pub(crate) zsk_rollover: Arc<Mutex<Option<SecondaryRestart>>>,
    /// Starts the jobs only one process may run: list refresh, DNSSEC re-signing and the upstream
    /// statistics writer.
    pub(crate) singletons: Arc<Mutex<Option<SecondaryRestart>>>,
    /// Matches listen addresses to the config; addresses with unchanged config are left alone.
    pub(crate) listeners: Arc<Mutex<Option<SecondaryRestart>>>,
}

/// Puts the task in the slot and runs it once with the current config. The slot stays locked while
/// it runs, so hot apply cannot restart the same task concurrently.
pub(crate) fn install_restart(
    slot: &Mutex<Option<SecondaryRestart>>,
    hook: SecondaryRestart,
    cfg: &Config,
) -> Result<(), String> {
    use onetdns_core::MutexExt;
    let mut installed = slot.lock_recover();
    installed.insert(hook)(cfg)
}

/// Rebuilds the block engine from the current config and lists, and swaps it in. Returns the block
/// and allow rule counts.
pub(crate) type FilterRebuild =
    Arc<dyn Fn() -> Result<(usize, usize), String> + Send + Sync + 'static>;

pub(crate) type HotConfigApply =
    Arc<dyn Fn(&Config, &[String]) -> Result<(bool, Vec<String>), String> + Send + Sync + 'static>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigApplyMode {
    NoChange,
    /// Swapped in without a restart.
    HotReload,
    /// Needs a restart.
    ServiceRestart,
}

impl ConfigApplyMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NoChange => "no_change",
            Self::HotReload => "hot_reload",
            Self::ServiceRestart => "service_restart",
        }
    }

    pub(crate) fn restart_required(self) -> bool {
        matches!(self, Self::ServiceRestart)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ConfigApplyResult {
    pub(crate) mode: ConfigApplyMode,
    pub(crate) changed: Vec<String>,
}

impl ConfigApplyResult {
    pub(crate) fn json_fields(&self) -> String {
        let changed = self
            .changed
            .iter()
            .map(|key| onetdns_core::json::escape(key))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "\"mode\":\"{}\",\"restart_required\":{},\"reloading\":{},\"changed\":[{}]",
            self.mode.as_str(),
            self.mode.restart_required(),
            self.mode.restart_required(),
            changed
        )
    }
}

pub(crate) fn changed_config_keys(current: &str, proposed: &str) -> Result<Vec<String>, String> {
    let (added, removed, changed) =
        onetdns_config::Config::diff_toml(current, proposed).map_err(|e| e.to_string())?;
    let mut keys = Vec::with_capacity(added.len() + removed.len() + changed.len());
    keys.extend(added);
    keys.extend(removed);
    keys.extend(changed);
    keys.sort();
    keys.dedup();
    Ok(keys)
}

/// Serializes config file edits.
pub(crate) fn config_write_lock() -> &'static Mutex<()> {
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Swaps in or restarts, depending only on what changed.
pub(crate) fn apply_config_edit_smart(
    path: &Option<std::path::PathBuf>,
    prev: &ConfigTextSlot,
    applied: &ConfigTextSlot,
    reload: &Arc<std::sync::atomic::AtomicBool>,
    hot_apply: &HotConfigApply,
    edit: impl FnOnce(&str) -> Result<String, String>,
) -> Result<ConfigApplyResult, String> {
    use onetdns_core::MutexExt;
    let _write_guard = config_write_lock().lock_recover();
    apply_config_edit_smart_locked(path, prev, applied, reload, hot_apply, edit)
}

/// With the config write lock already held.
pub(crate) fn apply_config_edit_smart_locked(
    path: &Option<std::path::PathBuf>,
    prev: &ConfigTextSlot,
    applied: &ConfigTextSlot,
    reload: &Arc<std::sync::atomic::AtomicBool>,
    hot_apply: &HotConfigApply,
    edit: impl FnOnce(&str) -> Result<String, String>,
) -> Result<ConfigApplyResult, String> {
    use onetdns_core::MutexExt;
    use std::sync::atomic::Ordering;
    let Some(p) = path else {
        return Err(
            "There is no configuration file path; the current configuration exists only in memory"
                .to_string(),
        );
    };
    let current =
        onetdns_core::SecretString::from(Config::read_text(p).map_err(|e| e.to_string())?);
    let new_text = onetdns_core::SecretString::from(edit(&current)?);
    let new_cfg = onetdns_config::Config::from_toml_str(&new_text)
        .map_err(|e| format!("The changed configuration is invalid: {e}"))?;
    let changed = changed_config_keys(&current, &new_text)?;
    if changed.is_empty() {
        return Ok(ConfigApplyResult {
            mode: ConfigApplyMode::NoChange,
            changed,
        });
    }
    // Same check as the validate API; letting it through would save a config the server cannot
    // start with after the next restart.
    runtime_preflight(&new_cfg)
        .map_err(|e| format!("The changed configuration is invalid: {e}"))?;

    atomic_write(p, new_text.as_bytes()).map_err(|e| e.to_string())?;
    let (mode, effective_changed) = match hot_apply(&new_cfg, &changed) {
        Ok((true, effective_changed)) => (ConfigApplyMode::HotReload, effective_changed),
        Ok((false, effective_changed)) => {
            reload.store(true, Ordering::Release);
            (ConfigApplyMode::ServiceRestart, effective_changed)
        }
        Err(error) => {
            let restore = atomic_write(p, current.as_bytes())
                .map_err(|e| format!("{error}; restoring the configuration file also failed: {e}"));
            return match restore {
                Ok(()) => Err(error),
                Err(combined) => Err(combined),
            };
        }
    };
    *prev.lock_recover() = Some(current);
    if mode == ConfigApplyMode::HotReload {
        *applied.lock_recover() = Some(new_text);
    }
    Ok(ConfigApplyResult {
        mode,
        changed: effective_changed,
    })
}

/// Untouched keys stay; overwriting the whole file would lose other settings.
pub(crate) fn apply_config_edit(
    path: &Option<std::path::PathBuf>,
    prev: &ConfigTextSlot,
    reload: &Arc<std::sync::atomic::AtomicBool>,
    edit: impl FnOnce(&str) -> Result<String, String>,
) -> Result<(), String> {
    use onetdns_core::MutexExt;
    let _write_guard = config_write_lock().lock_recover();
    apply_config_edit_locked(path, prev, reload, edit)
}

/// With the config write lock already held.
pub(crate) fn apply_config_edit_locked(
    path: &Option<std::path::PathBuf>,
    prev: &ConfigTextSlot,
    reload: &Arc<std::sync::atomic::AtomicBool>,
    edit: impl FnOnce(&str) -> Result<String, String>,
) -> Result<(), String> {
    use onetdns_core::MutexExt;
    use std::sync::atomic::Ordering;
    let Some(p) = path else {
        return Err(
            "There is no configuration file path; the current configuration exists only in memory"
                .to_string(),
        );
    };
    let current =
        onetdns_core::SecretString::from(Config::read_text(p).map_err(|e| e.to_string())?);
    let new_text = onetdns_core::SecretString::from(edit(&current)?);
    onetdns_config::Config::from_toml_str(&new_text)
        .map_err(|e| format!("The changed configuration is invalid: {e}"))?;
    atomic_write(p, new_text.as_bytes()).map_err(|e| e.to_string())?;
    *prev.lock_recover() = Some(current);
    reload.store(true, Ordering::Relaxed);
    Ok(())
}

/// Serializes changes to the running config.
pub(crate) fn runtime_config_update_lock() -> &'static Mutex<()> {
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Reads and changes under the lock, so a concurrent change is not lost.
pub(crate) fn update_runtime_config(
    runtime: &Arc<ArcSwap<Config>>,
    update: impl FnOnce(&mut Config),
) {
    use onetdns_core::MutexExt;
    let _guard = runtime_config_update_lock().lock_recover();
    let mut config = (*runtime.load()).clone();
    update(&mut config);
    runtime.store(Arc::new(config));
}

/// Aligns default-filled values before comparing; otherwise unchanged values would look changed.
pub(crate) fn normalize_config_for_comparison(runtime: &Config, desired: &Config) -> Config {
    let mut normalized = desired.clone();
    let dashboard_default = SocketAddr::from(([127, 0, 0, 1], 8553));
    if normalized.control_listen.is_none() && runtime.control_listen == Some(dashboard_default) {
        normalized.control_listen = Some(dashboard_default);
    }
    normalized
}

/// Sorted.
pub(crate) fn config_changed_keys(runtime: &Config, desired: &Config) -> Vec<String> {
    let mut changed: Vec<String> = config_keys::changed_keys(runtime, desired)
        .map(str::to_string)
        .collect();
    changed.sort_unstable();
    changed
}

/// The config as written in the file.
pub(crate) fn desired_config_json(path: Option<&std::path::Path>, runtime: &Config) -> String {
    let Some(path) = path else {
        return runtime.effective_json();
    };
    let text = match Config::read_text(path) {
        Ok(text) => onetdns_core::SecretString::from(text),
        Err(error) => {
            return format!(
                "{{\"_valid\":false,\"_source\":\"disk\",\"_error\":{}}}",
                onetdns_core::json::escape(&error.to_string())
            );
        }
    };
    match Config::from_toml_str(&text) {
        Ok(config) => config.effective_json(),
        Err(error) => format!(
            "{{\"_valid\":false,\"_source\":\"disk\",\"_error\":{}}}",
            onetdns_core::json::escape(&error.to_string())
        ),
    }
}

/// Keys applying the file would change, and those among them that restart the service. Normalized
/// like the file-apply path and judged by `service_restart_keys`, so what the dashboard asks before
/// applying matches the actual result.
fn config_changed_keys_for_status(
    runtime: &Config,
    desired: &Config,
) -> (Vec<String>, Vec<String>) {
    let desired = normalize_config_for_comparison(runtime, desired);
    let changed = config_changed_keys(runtime, &desired);
    let restart = service_restart_keys(runtime, &desired, &changed);
    (changed, restart)
}

fn disk_change(
    path: &std::path::Path,
    runtime: &Config,
) -> Result<(Vec<String>, Vec<String>), String> {
    let text = onetdns_core::SecretString::from(
        Config::read_text(path).map_err(|error| error.to_string())?,
    );
    let desired = Config::from_toml_str(&text).map_err(|error| error.to_string())?;
    Ok(config_changed_keys_for_status(runtime, &desired))
}

/// Whether the file and the running config diverge, plus the keys that could restart under the
/// current config. The dashboard polls this. The key classification depends on the current config,
/// client routes for example, so it travels here to follow config changes made after the page
/// opened.
pub(crate) fn config_status_json(path: Option<&std::path::Path>, runtime: &Config) -> String {
    use onetdns_core::json::escape;
    let list = |keys: &[String]| keys.iter().map(|key| escape(key)).collect::<Vec<_>>();
    let conditional: Vec<String> = conditional_hot_reload_keys(runtime)
        .into_iter()
        .map(escape)
        .collect();
    let (source, pending) = match path {
        None => ("runtime", Ok((Vec::new(), Vec::new()))),
        Some(path) => ("disk", disk_change(path, runtime)),
    };
    match pending {
        Ok((changed, restart)) => format!(
            "{{\"in_sync\":{},\"source\":\"{source}\",\"changed_keys\":[{}],\"service_restart\":[{}],\"restart_required\":{},\"conditional_hot_reload_keys\":[{}]}}",
            changed.is_empty(),
            list(&changed).join(","),
            list(&restart).join(","),
            !restart.is_empty(),
            conditional.join(",")
        ),
        Err(error) => format!(
            "{{\"in_sync\":false,\"source\":\"{source}\",\"error\":{},\"changed_keys\":[],\"service_restart\":[],\"restart_required\":false,\"conditional_hot_reload_keys\":[{}]}}",
            escape(&error),
            conditional.join(",")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use onetdns_config::{Config, UpstreamStrategy};
    use onetdns_core::{ArcSwap, MutexExt};

    use crate::config_keys::ApplyGroup;
    use crate::{config_keys, unix_now, ConfigTextSlot, CONFIG_FILE_NAME};

    #[test]
    fn failed_config_edit_leaves_file_snapshot_and_reload_untouched() {
        let file_path = std::env::temp_dir().join(format!(
            "onetdns-edit-noop-{}-{}.toml",
            std::process::id(),
            unix_now()
        ));
        std::fs::write(&file_path, "cache_size = 4096\n").unwrap();
        let path = Some(file_path.clone());
        let prev: ConfigTextSlot = Arc::new(Mutex::new(None));
        let reload = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let result = apply_config_edit(&path, &prev, &reload, |_| {
            Err("일치하는 항목이 없습니다".to_string())
        });

        assert!(result.is_err());
        assert!(prev.lock_recover().is_none());
        assert!(!reload.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(
            std::fs::read_to_string(&file_path).unwrap(),
            "cache_size = 4096\n"
        );
        std::fs::remove_file(file_path).unwrap();
    }

    #[test]
    fn runtime_config_updates_preserve_other_recent_changes() {
        let runtime = Arc::new(ArcSwap::from_pointee(Config::default()));
        update_runtime_config(&runtime, |config| config.safe_search = true);
        update_runtime_config(&runtime, |config| {
            config.blocked_services = vec!["youtube".to_string()];
        });
        let current = runtime.load();
        assert!(current.safe_search);
        assert_eq!(current.blocked_services, vec!["youtube".to_string()]);
    }

    #[test]
    /// Hidden, it would look applied.
    fn pending_non_hot_file_change_cannot_be_hidden_by_a_hot_edit() {
        let active = Config::default();
        let mut proposed = active.clone();
        proposed.safe_search = !active.safe_search;
        proposed.run_as_user = Some("onetdns".to_string());

        let changed = config_changed_keys(&active, &proposed);
        assert!(changed.contains(&"safe_search".to_string()));
        assert!(changed.contains(&"run_as_user".to_string()));
        assert!(changed
            .iter()
            .any(|key| !config_keys::swappable(key, &active, &proposed)));
    }

    #[test]
    fn stored_and_active_config_diff_reports_runtime_mismatch() {
        let applied = Config::from_toml_str(
            "backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\ncache_size = 1000\n",
        )
        .unwrap();
        let desired = Config::from_toml_str(
            "backend = \"forward\"\nupstreams = [\"8.8.8.8\"]\ncache_size = 2000\n",
        )
        .unwrap();
        let changed = config_changed_keys(&applied, &desired);
        assert!(changed.contains(&"upstreams".to_string()));
        assert!(changed.contains(&"cache_size".to_string()));
        assert_eq!(changed.iter().filter(|key| *key == "upstreams").count(), 1);
    }

    #[test]
    /// A generic name would interrupt DNS service every time a password changes.
    fn stored_and_active_diff_detects_masked_user_changes() {
        let mut applied = Config::default();
        applied.users = vec![onetdns_config::UserConfig {
            name: "admin".to_string(),
            password_hash: "hash-a".into(),
            role: "admin".to_string(),
        }];
        let mut desired = applied.clone();
        desired.users[0].password_hash = "hash-b".into();
        let changed = config_changed_keys(&applied, &desired);
        assert_eq!(changed, vec!["users".to_string()]);
    }

    #[test]
    /// Missing the masked one would report a token rotation as applied while the old token keeps
    /// working.
    fn masked_change_is_reported_alongside_a_visible_change() {
        let applied = Config {
            control_token: "control-token-a".into(),
            ..Config::default()
        };
        let mut desired = applied.clone();
        desired.control_token = "control-token-b".into();
        desired.cache_size = applied.cache_size + 1;
        let changed = config_changed_keys(&applied, &desired);
        assert!(
            changed.contains(&"control_token".to_string()),
            "{changed:?}"
        );
        assert!(changed.contains(&"cache_size".to_string()), "{changed:?}");
    }

    #[test]
    /// If the summary used names other than the config keys, the apply path would not know them and
    /// would restart the whole service.
    fn counted_summary_keys_map_to_their_hot_groups() {
        let applied = Config::default();
        let mut desired = applied.clone();
        desired.policy.push(onetdns_config::PolicyRule {
            action: "block".into(),
            suffixes: vec!["example.com".into()],
            ..Default::default()
        });
        let changed = config_changed_keys(&applied, &desired);
        assert_eq!(changed, vec!["policy".to_string()]);
        assert_eq!(config_keys::hot_group("policy"), Some(ApplyGroup::Policy));
    }

    #[test]
    /// Skipping it would save a value the validate API rejects, and the server would not start at
    /// the next restart.
    fn config_edit_runs_runtime_preflight_before_writing() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-preflight-edit-{}-{}.toml",
            std::process::id(),
            unix_now()
        ));
        let original = "listen = [\"127.0.0.1:15399\"]\n";
        std::fs::write(&path, original).unwrap();
        let hot_apply: HotConfigApply = Arc::new(|_, _| panic!("검사에 걸린 설정을 적용했습니다"));
        let result = apply_config_edit_smart(
            &Some(path.clone()),
            &Arc::new(Mutex::new(None)),
            &Arc::new(Mutex::new(None)),
            &Arc::new(std::sync::atomic::AtomicBool::new(false)),
            &hot_apply,
            |text| {
                Ok(format!(
                    "{text}zones_postgres = \"postgres://dns:pw@10.1.2.3/zones\"\n"
                ))
            },
        );
        let written = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let error = result.expect_err("원격 PostgreSQL 주소는 거절해야 합니다");
        assert!(error.contains("zones_postgres"), "{error}");
        assert_eq!(written, original);
    }

    #[test]
    fn stored_and_active_diff_detects_masked_control_token_changes() {
        let mut applied = Config {
            control_token: "control-token-a".into(),
            ..Config::default()
        };
        let mut desired = applied.clone();
        desired.control_token = "control-token-b".into();

        assert_eq!(
            config_changed_keys(&applied, &desired),
            vec!["control_token".to_string()]
        );

        applied.control_token = desired.control_token.clone();
        assert!(config_changed_keys(&applied, &desired).is_empty());
    }

    #[test]
    /// The effective config summary lists these only by count or name, so comparing summaries
    /// misses a same-count rotation, and without the changed key no group can apply it.
    fn rotating_a_secret_list_names_the_key_it_changed() {
        let mut applied = Config {
            control_admin_tokens: vec!["admin-old".into()],
            control_readonly_tokens: vec!["ro-old".into()],
            tsig_keys: vec![onetdns_config::TsigKeyConfig {
                name: "key1".to_string(),
                secret: "tsig-old".into(),
            }],
            ..Config::default()
        };

        for (label, mutate) in [
            (
                "control_admin_tokens",
                (|c: &mut Config| c.control_admin_tokens = vec!["admin-new".into()])
                    as fn(&mut Config),
            ),
            ("control_readonly_tokens", |c: &mut Config| {
                c.control_readonly_tokens = vec!["ro-new".into()]
            }),
            ("tsig_keys", |c: &mut Config| {
                c.tsig_keys = vec![onetdns_config::TsigKeyConfig {
                    name: "key1".to_string(),
                    secret: "tsig-new".into(),
                }]
            }),
        ] {
            let mut desired = applied.clone();
            mutate(&mut desired);
            assert_eq!(
                config_changed_keys(&applied, &desired),
                vec![label.to_string()],
                "{label}을 갈았는데 그 이름으로 불리지 않았습니다"
            );
            assert!(
                config_keys::is_hot(label) || label == "tsig_keys",
                "{label}은 무중단 그룹에 있어야 합니다"
            );
            mutate(&mut applied);
            assert!(
                config_changed_keys(&applied, &desired).is_empty(),
                "{label}을 맞춘 뒤에는 달라진 것이 없어야 합니다"
            );
        }
    }

    #[test]
    /// The effective config summary also carries derived items that are not config keys, such as
    /// `mtls_enforced` and `cachedb_redis_password_set`. The key table does not know them, so mixed
    /// into the changed keys they would turn a hot change into a restart.
    fn only_configuration_keys_are_reported_as_changed() {
        let applied = Config::default();
        for (key, mutate) in [
            (
                "tls_client_ca",
                (|c: &mut Config| c.tls_client_ca = Some("ca.pem".into())) as fn(&mut Config),
            ),
            ("cachedb_redis_password", |c: &mut Config| {
                c.cachedb_redis_password = Some("redis-pass".into())
            }),
            ("zones_etcd_password", |c: &mut Config| {
                c.zones_etcd_password = Some("etcd-pass".into())
            }),
        ] {
            let mut desired = applied.clone();
            mutate(&mut desired);
            let changed = config_changed_keys(&applied, &desired);
            assert_eq!(changed, [key], "{key} 하나만 바꿨습니다");
            assert!(
                service_restart_keys(&applied, &desired, &changed).is_empty(),
                "{key} 는 재시작 없이 바뀌어야 합니다"
            );
        }
    }

    #[test]
    /// The summary lists secondary zones by name only. When a change of only the primary address
    /// comes with other keys and this key is missing, the authority group is not swapped, and
    /// secondary refresh keeps pulling from the old primary.
    fn a_secondary_primary_change_is_reported_by_its_key() {
        let applied = Config {
            secondary: vec![onetdns_config::SecondaryZone {
                origin: "b.test".to_string(),
                primary: Some("192.0.2.1".parse().unwrap()),
                ..Default::default()
            }],
            ..Config::default()
        };
        let mut desired = applied.clone();
        desired.secondary[0].primary = Some("192.0.2.2".parse().unwrap());
        let changed = config_changed_keys(&applied, &desired);
        assert_eq!(changed, ["secondary"]);
        assert!(service_restart_keys(&applied, &desired, &changed).is_empty());

        desired.cache_size = applied.cache_size + 1;
        assert_eq!(
            config_changed_keys(&applied, &desired),
            ["cache_size", "secondary"]
        );
    }

    #[test]
    fn desired_config_reports_invalid_disk_file_instead_of_runtime_fallback() {
        let suffix = format!("{}-{}", std::process::id(), unix_now());
        let path = std::env::temp_dir().join(format!("onetdns-invalid-config-{suffix}.toml"));
        std::fs::write(&path, "backend = [broken").unwrap();
        let runtime =
            Config::from_toml_str("backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\n").unwrap();

        let desired = desired_config_json(Some(&path), &runtime);

        assert!(desired.contains("\"_valid\":false"));
        assert!(desired.contains("\"_source\":\"disk\""));
        assert!(!desired.contains("\"upstreams\":[\"1.1.1.1\"]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn web_dashboard_default_listener_does_not_create_false_config_drift() {
        let desired = Config::from_toml_str("cache_size = 4096\n").unwrap();
        let mut runtime = desired.clone();
        runtime.control_listen = Some(SocketAddr::from(([127, 0, 0, 1], 8553)));

        let (changed, _) = config_changed_keys_for_status(&runtime, &desired);
        assert!(
            changed.is_empty(),
            "runtime-only dashboard default: {changed:?}"
        );
    }

    #[test]
    fn runtime_change_comparison_does_not_hide_control_listener_removal() {
        let desired = Config::from_toml_str("cache_size = 4096\n").unwrap();
        let mut runtime = desired.clone();
        runtime.control_listen = Some(SocketAddr::from(([127, 0, 0, 1], 8553)));

        let changed = config_changed_keys(&runtime, &desired);
        assert!(
            changed.contains(&"control_listen".to_string()),
            "{changed:?}"
        );
    }

    #[test]
    fn explicit_control_listener_change_is_still_reported() {
        let desired = Config::from_toml_str(
            "control_listen = \"127.0.0.1:9553\"\ncontrol_token = \"unit-test-token-0123456789\"\n",
        )
        .unwrap();
        let mut runtime = desired.clone();
        runtime.control_listen = Some(SocketAddr::from(([127, 0, 0, 1], 8553)));

        let (changed, _) = config_changed_keys_for_status(&runtime, &desired);
        assert!(
            changed.contains(&"control_listen".to_string()),
            "{changed:?}"
        );
    }

    #[test]
    fn config_status_detects_disk_runtime_divergence() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-cfg-status-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(CONFIG_FILE_NAME);
        let base = "upstreams = [\"1.1.1.1\"]\ncache_size = 4096\n";
        std::fs::write(&path, base).unwrap();
        let runtime = Config::from_toml_str(base).unwrap();

        let status = config_status_json(Some(&path), &runtime);
        assert!(status.contains("\"in_sync\":true"), "{status}");

        std::fs::write(&path, "upstreams = [\"1.1.1.1\"]\ncache_size = 8192\n").unwrap();
        let status = config_status_json(Some(&path), &runtime);
        assert!(status.contains("\"in_sync\":false"), "{status}");
        assert!(status.contains("cache_size"), "{status}");
        assert!(
            status.contains("\"service_restart\":[],\"restart_required\":false"),
            "클라이언트 경로가 없으면 체인 설정은 무중단입니다: {status}"
        );
        assert!(
            status.contains("\"conditional_hot_reload_keys\":[\"clients\"]"),
            "{status}"
        );

        std::fs::write(&path, "cache_size = [broken").unwrap();
        let status = config_status_json(Some(&path), &runtime);
        assert!(status.contains("\"in_sync\":false"), "{status}");
        assert!(status.contains("error"), "{status}");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn encrypted_listener_change_rebuilds_ddr_chain_only_when_needed() {
        let plain = Config::default();
        let mut changed = plain.clone();
        changed.listen_doh = vec!["127.0.0.1:8443".parse().unwrap()];
        let keys = vec!["listen_doh".to_string()];
        assert_eq!(
            hot_reload_groups(&plain, &changed, &keys),
            vec![ApplyGroup::Listeners]
        );

        let mut with_ddr = plain;
        with_ddr.ddr_name = "dns.example".to_string();
        let mut next = changed;
        next.ddr_name = with_ddr.ddr_name.clone();
        assert_eq!(
            hot_reload_groups(&with_ddr, &next, &keys),
            vec![ApplyGroup::Chain, ApplyGroup::Listeners]
        );
    }

    #[test]
    fn forward_settings_rebuild_the_chain_only_when_the_chain_uses_them() {
        let plain = Config::default();
        let mut slower = plain.clone();
        slower.query_timeout_secs = plain.query_timeout_secs + 3;
        let timeout = vec!["query_timeout_secs".to_string()];
        assert_eq!(
            hot_reload_groups(&plain, &slower, &timeout),
            vec![ApplyGroup::Forward]
        );

        let mut with_stub = plain.clone();
        with_stub.stub_zones.push(onetdns_config::StubZone {
            suffix: "corp.test".to_string(),
            servers: vec!["192.0.2.53".to_string()],
        });
        let mut stub_slower = with_stub.clone();
        stub_slower.query_timeout_secs = slower.query_timeout_secs;
        assert_eq!(
            hot_reload_groups(&with_stub, &stub_slower, &timeout),
            vec![ApplyGroup::Chain, ApplyGroup::Forward]
        );

        let mut with_fallback = plain;
        with_fallback.fallback_upstreams = vec!["192.0.2.54".to_string()];
        let mut fallback_parallel = with_fallback.clone();
        fallback_parallel.upstream_strategy = UpstreamStrategy::Parallel;
        assert_eq!(
            hot_reload_groups(
                &with_fallback,
                &fallback_parallel,
                &["upstream_strategy".to_string()]
            ),
            vec![ApplyGroup::Chain, ApplyGroup::Forward]
        );
    }

    #[test]
    /// Editing a zone only swaps the store.
    fn zone_edits_rebuild_the_chain_only_when_the_authority_layer_appears() {
        let zone = |origin: &str| onetdns_config::ZoneConfig {
            origin: origin.to_string(),
            ..Default::default()
        };
        let plain = Config::default();
        let mut one = plain.clone();
        one.zones.push(zone("a.test"));
        let mut two = one.clone();
        two.zones.push(zone("b.test"));
        let keys = vec!["zones".to_string()];
        assert_eq!(
            hot_reload_groups(&plain, &one, &keys),
            vec![ApplyGroup::Authority, ApplyGroup::Chain]
        );
        assert_eq!(
            hot_reload_groups(&one, &two, &keys),
            vec![ApplyGroup::Authority]
        );
        assert_eq!(
            hot_reload_groups(&one, &plain, &keys),
            vec![ApplyGroup::Authority, ApplyGroup::Chain]
        );
    }

    #[test]
    /// The value goes out as DHCP option 15 and also names local hosts in the DHCP DNS layer;
    /// rebuilding only one would make the leased domain and the names DNS answers disagree.
    fn local_domain_change_rebuilds_dhcp_and_the_chain() {
        let plain = Config::default();
        let mut next = plain.clone();
        next.dhcp_local_domain = "home.arpa".to_string();
        let changed = config_changed_keys(&plain, &next);
        assert_eq!(changed, ["dhcp_local_domain"]);
        assert_eq!(
            hot_reload_groups(&plain, &next, &changed),
            vec![ApplyGroup::Chain, ApplyGroup::EdgeServices]
        );
    }

    #[test]
    fn forward_upstream_change_is_hot_reload() {
        let current =
            Config::from_toml_str("backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\n").unwrap();
        let proposed =
            Config::from_toml_str("backend = \"forward\"\nupstreams = [\"8.8.8.8\"]\n").unwrap();
        assert!(config_keys::swappable("upstreams", &current, &proposed));
    }

    #[test]
    /// The forward resolver slot exists from startup regardless of backend, and applying the config
    /// puts a resolver built with the new upstreams into it.
    fn forward_keys_follow_a_backend_switch_without_restart() {
        let current = Config::from_toml_str(
            "backend = \"recurse\"
    upstreams = [\"1.1.1.1\"]
    ",
        )
        .unwrap();
        let proposed = Config::from_toml_str(
            "backend = \"split\"
    upstreams = [\"8.8.8.8\"]
    ",
        )
        .unwrap();
        assert!(config_keys::swappable("backend", &current, &proposed));
        assert!(config_keys::swappable("upstreams", &current, &proposed));
        assert!(!backend_uses_forward(current.backend));
        assert!(backend_uses_forward(proposed.backend));
    }

    #[test]
    fn forward_runtime_tuning_is_hot_reload() {
        let current =
            Config::from_toml_str("backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\n").unwrap();
        let proposed = Config::from_toml_str(
            "backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\nupstream_concurrency = 4\nquery_timeout_secs = 2\n",
        )
        .unwrap();
        assert!(config_keys::swappable(
            "upstream_concurrency",
            &current,
            &proposed
        ));
        assert!(config_keys::swappable(
            "query_timeout_secs",
            &current,
            &proposed
        ));
    }

    #[test]
    /// Route chains are built only at generation start.
    fn client_specific_upstream_tuning_requires_service_restart() {
        let current = Config::from_toml_str(
            "backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\n[[clients]]\nname = \"office\"\nids = [\"192.0.2.0/24\"]\nupstreams = [\"9.9.9.9\"]\n",
        )
        .unwrap();
        let proposed = Config::from_toml_str(
            "backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\nupstream_strategy = \"parallel\"\nupstream_concurrency = 4\nquery_timeout_secs = 2\n[[clients]]\nname = \"office\"\nids = [\"192.0.2.0/24\"]\nupstreams = [\"9.9.9.9\"]\n",
        )
        .unwrap();
        for key in [
            "upstream_strategy",
            "upstream_concurrency",
            "query_timeout_secs",
        ] {
            assert!(!config_keys::swappable(key, &current, &proposed));
        }
        assert!(config_keys::swappable("upstreams", &current, &proposed));
    }

    #[test]
    /// The chain rebuild makes a new recursive resolver from the plan, and the plan includes the
    /// query timeout.
    fn recursive_timeout_is_applied_by_rebuilding_the_chain() {
        let changed = ["query_timeout_secs".to_string()];
        for base in [
            "backend = \"recurse\"\n",
            "backend = \"split\"\nupstreams = [\"1.1.1.1\"]\n",
        ] {
            let current = Config::from_toml_str(base).unwrap();
            let proposed =
                Config::from_toml_str(&format!("{base}query_timeout_secs = 2\n")).unwrap();
            assert!(
                service_restart_keys(&current, &proposed, &changed).is_empty(),
                "{base:?}: 질의 제한 시간만 바꿨는데 재시작합니다"
            );
            assert!(
                hot_reload_groups(&current, &proposed, &changed).contains(&ApplyGroup::Chain),
                "{base:?}: 체인을 다시 만들지 않으면 재귀 리졸버가 이전 제한 시간을 씁니다"
            );
        }
    }

    #[test]
    /// A forwarder is built anew when the new config forwards and the old one did not; the chain
    /// rebuilds when the backend changes.
    fn backend_switch_keeps_forward_tuning_hot() {
        let forward = "upstreams = [\"1.1.1.1\"]\nupstream_strategy = \"parallel\"\nupstream_concurrency = 4\nquery_timeout_secs = 2\n";
        let changed: Vec<String> = [
            "backend",
            "upstream_strategy",
            "upstream_concurrency",
            "query_timeout_secs",
        ]
        .map(String::from)
        .to_vec();
        for (from, to) in [
            ("recurse", "forward"),
            ("forward", "split"),
            ("split", "recurse"),
        ] {
            let current = Config::from_toml_str(&format!(
                "backend = \"{from}\"\nupstreams = [\"1.1.1.1\"]\n"
            ))
            .unwrap();
            let proposed =
                Config::from_toml_str(&format!("backend = \"{to}\"\n{forward}")).unwrap();
            assert!(
                service_restart_keys(&current, &proposed, &changed).is_empty(),
                "{from} 에서 {to} 로 바꾸며 전달 세부 설정을 바꿨는데 재시작합니다"
            );
        }
    }

    #[test]
    fn client_policy_change_is_hot_reload_but_route_change_is_not() {
        let current = Config::from_toml_str(
            "[[clients]]
    name = \"desktop\"
    ids = [\"192.0.2.10/32\"]
    disable_filtering = false
    ",
        )
        .unwrap();
        let policy_only = Config::from_toml_str(
            "[[clients]]
    name = \"desktop\"
    ids = [\"192.0.2.10/32\"]
    disable_filtering = true
    ",
        )
        .unwrap();
        assert!(config_keys::swappable("clients", &current, &policy_only));

        let routed = Config::from_toml_str(
            "[[clients]]
    name = \"desktop\"
    ids = [\"192.0.2.10/32\"]
    upstreams = [\"1.1.1.1\"]
    ",
        )
        .unwrap();
        assert!(!config_keys::swappable("clients", &current, &routed));
    }

    #[test]
    fn first_mac_client_requires_service_restart() {
        let current = Config::from_toml_str("").unwrap();
        let proposed = Config::from_toml_str(
            "[[clients]]
    name = \"phone\"
    mac = [\"00:11:22:33:44:55\"]
    ",
        )
        .unwrap();
        assert!(!config_keys::swappable("clients", &current, &proposed));
    }

    const CLIENT_ROUTE: &str =
        "[[clients]]\nname = \"office\"\nids = [\"192.0.2.0/24\"]\nupstreams = [\"9.9.9.9\"]\n";

    /// `top` holds the top-level key lines; `tables` the table arrays after them.
    fn with_key(top: &str, key: &str, value: &str, tables: &str) -> String {
        let prefix = format!("{key} =");
        let mut text: String = top
            .lines()
            .filter(|line| !line.starts_with(&prefix))
            .map(|line| format!("{line}\n"))
            .collect();
        text.push_str(&format!("{key} = {value}\n{tables}"));
        text
    }

    #[test]
    /// Route chains are built only at generation start, so swapping only the default chain would
    /// leave route clients on the old config. The change preview uses this verdict too; missing
    /// here, the dashboard would announce a restarting change as hot.
    fn chain_changes_restart_while_client_routes_exist() {
        let verdict = |top: &str, key: &str, value: &str, routed: bool| {
            let tables = if routed { CLIENT_ROUTE } else { "" };
            let current = Config::from_toml_str(&format!("{top}{tables}")).unwrap();
            let proposed = Config::from_toml_str(&with_key(top, key, value, tables)).unwrap();
            let changed = config_changed_keys(&current, &proposed);
            assert_eq!(changed, vec![key.to_string()]);
            service_restart_keys(&current, &proposed, &changed)
        };
        let forward = "backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\n";
        let shared = "backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\ncachedb_redis_host = \"127.0.0.1\"\ncachedb_redis_secret = \"0123456789abcdef0123456789abcdef\"\n";

        assert_eq!(verdict(forward, "min_ttl", "120", true), ["min_ttl"]);
        assert!(verdict(forward, "min_ttl", "120", false).is_empty());
        assert_eq!(
            verdict(forward, "dhcp_lease_secs", "7200", true),
            ["dhcp_lease_secs"]
        );
        assert_eq!(
            verdict(shared, "upstreams", "[\"8.8.8.8\"]", true),
            ["upstreams"]
        );
        assert!(verdict(forward, "upstreams", "[\"8.8.8.8\"]", true).is_empty());
        assert!(verdict(forward, "safe_search", "true", true).is_empty());
    }

    #[test]
    fn conditional_keys_follow_the_current_configuration() {
        let forward = "backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\n";
        let plain = Config::from_toml_str(forward).unwrap();
        assert_eq!(conditional_hot_reload_keys(&plain), ["clients"]);

        let recurse = Config::from_toml_str("backend = \"recurse\"\n").unwrap();
        assert_eq!(conditional_hot_reload_keys(&recurse), ["clients"]);

        let routed = Config::from_toml_str(&format!("{forward}{CLIENT_ROUTE}")).unwrap();
        let announced = conditional_hot_reload_keys(&routed);
        for key in [
            "clients",
            "min_ttl",
            "cache_size",
            "dnssec",
            "dhcp_lease_secs",
            "zones",
            "query_timeout_secs",
            "upstream_strategy",
        ] {
            assert!(announced.contains(&key), "{key} must be announced");
        }
        for key in ["safe_search", "block_rules", "upstreams", "listen"] {
            assert!(!announced.contains(&key), "{key} must stay hot");
        }
    }

    #[test]
    /// Tries a value of the right type for each key and fails when a key changes the plan but is
    /// announced as hot. A plan that starts reading another group's key without adding it to
    /// `ChainPlan::other_group_inputs` shows up here.
    ///
    /// Each base config turns on only one of the components that function looks at; turning on
    /// several would let one component's list hide another's missing key.
    fn every_key_that_changes_the_chain_plan_is_announced() {
        let candidates = |kind: &str, meta: &str| -> Vec<String> {
            let quoted = |values: &[&str]| values.iter().map(|v| format!("\"{v}\"")).collect();
            match kind {
                "bool" => vec!["true".into(), "false".into()],
                "enum" => quoted(&meta.split('|').collect::<Vec<_>>()),
                "int" => ["0", "1", "2", "3", "7", "60", "300", "4096"]
                    .map(String::from)
                    .to_vec(),
                "string" => quoted(&[
                    "",
                    "x.example",
                    "192.0.2.7",
                    "127.0.0.1:5353",
                    "/x",
                    "https://x.example/dns-query",
                ]),
                "array" => [
                    "[]",
                    "[\"192.0.2.7\"]",
                    "[\"192.0.2.7:5353\"]",
                    "[\"127.0.0.1:5353\"]",
                    "[\"192.0.2.0/24\"]",
                    "[\"x.example\"]",
                    "[\"https://x.example/dns-query\"]",
                ]
                .map(String::from)
                .to_vec(),
                _ => Vec::new(),
            }
        };
        let forward = "backend = \"forward\"\nupstreams = [\"192.0.2.1\"]\n";
        let bases = [
            (forward.to_string(), ""),
            (
                format!("{forward}fallback_upstreams = [\"192.0.2.2\"]\n"),
                "",
            ),
            (
                forward.to_string(),
                "[[stub_zones]]\nsuffix = \"corp.test\"\nservers = [\"192.0.2.53\"]\n",
            ),
            (
                format!("{forward}cachedb_redis_host = \"127.0.0.1\"\ncachedb_redis_secret = \"0123456789abcdef0123456789abcdef\"\n"),
                "",
            ),
            (
                format!("{forward}ddr_name = \"dns.example\"\nlisten_dot = [\"127.0.0.1:8853\"]\nlisten_doh = [\"127.0.0.1:8443\"]\n"),
                "",
            ),
            (forward.to_string(), "[[zones]]\norigin = \"a.test\"\n"),
            ("backend = \"recurse\"\ndnssec = true\n".to_string(), ""),
            (
                "backend = \"split\"\nupstreams = [\"192.0.2.1\"]\n".to_string(),
                "",
            ),
        ];
        let mut probed = 0;
        for (top, tables) in bases {
            let tables = format!("{tables}{CLIENT_ROUTE}");
            let now = Config::from_toml_str(&format!("{top}{tables}")).unwrap();
            let plan = resolver_chain::ChainPlan::new(&now);
            let announced = conditional_hot_reload_keys(&now);
            for field in onetdns_config::schema::fields() {
                if !config_keys::is_hot(field.key) || announced.contains(&field.key) {
                    continue;
                }
                for value in candidates(field.kind, field.meta) {
                    let text = with_key(&top, field.key, &value, &tables);
                    let Ok(probe) = Config::from_toml_str(&text) else {
                        continue;
                    };
                    probed += 1;
                    assert!(
                        resolver_chain::ChainPlan::new(&probe) == plan,
                        "{} = {value} changes the chain plan, but the dashboard is told it applies without a restart",
                        field.key
                    );
                }
            }
        }
        assert!(probed > 500, "only {probed} probes parsed");
    }

    #[test]
    fn changed_config_keys_are_sorted_and_deduplicated() {
        let cur = "block_rules = [\"a.example\"]\nlisten = [\"127.0.0.1:53\"]\n";
        let new = "block_rules = [\"b.example\"]\nlisten = [\"127.0.0.1:5353\"]\n";
        let keys = changed_config_keys(cur, new).unwrap();
        assert_eq!(keys, vec!["block_rules".to_string(), "listen".to_string()]);
    }
}
