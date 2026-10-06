/*!
 * @brief 설정 편집을 파일에 쓰고, 바뀐 키에 따라 즉시 교체할지 새 세대로 시작할지 정한다.
 */

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use onetdns_config::{BackendKind, Config};
use onetdns_core::ArcSwap;

use crate::atomic_file::atomic_write;
use crate::config_keys::ApplyGroup;
use crate::{config_keys, resolver_chain, runtime_preflight, ConfigTextSlot};

/**
 * @brief 응답 캐시 아래에서 판정하는 로컬 전용 이름 설정들.
 * @details 판정 결과가 캐시에 담기므로, 이 값을 바꾸면 캐시를 비워야 바뀐 판정이 바로 나간다.
 */
pub(crate) const LOCAL_ONLY_CONFIG_KEYS: &[&str] = &["domain_needed", "bogus_priv", "empty_zones"];

/** @brief 직접 바뀐 설정과 그 설정이 다시 만들어야 하는 파생 그룹을 모은다. */
pub(crate) fn hot_reload_groups(
    previous: &Config,
    next: &Config,
    changed: &[String],
) -> Vec<ApplyGroup> {
    let mut groups = key_groups(changed);
    /*
     * 체인은 계획만 읽으므로, 어느 키가 바뀌었든 계획이 달라지면 체인을 다시 만든다.
     * 질의 제한 시간처럼 전달 그룹에 속한 키도 스텁 영역과 예비 업스트림의 전달기에 쓰인다.
     */
    if resolver_chain::ChainPlan::new(previous) != resolver_chain::ChainPlan::new(next) {
        groups.push(ApplyGroup::Chain);
        groups.sort_unstable();
        groups.dedup();
    }
    groups
}

/** @brief 바뀐 키가 키 표와 그룹 사이의 의존으로 끌어오는 그룹. 체인 계획은 비교하지 않는다. */
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

/** @brief 이 backend가 전달 리졸버를 쓰는지. */
pub(crate) fn backend_uses_forward(backend: BackendKind) -> bool {
    matches!(backend, BackendKind::Forward | BackendKind::Split)
}

/**
 * @brief 이 키를 바꾸면 해석 체인을 다시 만드는지.
 * @param plan_inputs 계획이 값을 읽는 다른 그룹의 키들. ChainPlan::other_group_inputs 가 낸다.
 */
fn rebuilds_chain(key: &str, plan_inputs: &[&str]) -> bool {
    plan_inputs.contains(&key) || key_groups(&[key.to_string()]).contains(&ApplyGroup::Chain)
}

/**
 * @brief 바뀐 키 가운데 서비스를 다시 시작해야 반영되는 키들. 비어 있으면 모두 교체한다.
 * @details 교체 적용과 변경 미리보기가 이 판정 하나를 쓴다. 미리보기가 따로 판정하면 실제로는
 *          재시작하는 변경을 무중단이라고 알린다.
 *
 *          클라이언트별 업스트림 경로가 있으면 체인을 다시 만드는 변경은 재시작한다. 경로마다
 *          공통 계층을 감싼 체인은 세대를 시작할 때 한 번만 만들고 교체하지 않으므로, 기본
 *          체인만 다시 만들면 그 경로의 클라이언트는 이전 캐시 크기나 검증 설정으로 답을 받는다.
 *          체인을 다시 만들게 한 키를 가려내지 못해도 재시작은 해야 하므로, 그때는 바뀐 키를
 *          모두 든다.
 */
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

/**
 * @brief 표에서는 교체할 수 있는 키지만 지금 설정에서는 바꾸면 재시작할 수 있는 키들.
 * @details 관리 화면이 적용하기 전에 재시작을 알리는 데 쓴다. service_restart_keys 와 같은
 *          규칙에서 내므로, 지금 설정에서 키 하나만 바꿀 때 그 판정이 재시작할 수 있는 키는
 *          모두 여기에 든다. clients 처럼 무엇으로 바꾸느냐에 따라 갈리는 키는 늘 든다.
 */
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

/** @brief 기본 체인을 다시 만드는 핸들과 그 체인이 들어 있는 슬롯. */
#[derive(Clone)]
pub(crate) struct ChainRebuild {
    /** @brief 기본 체인을 만들고 설치한다. */
    pub(crate) chain: Arc<resolver_chain::DefaultChain>,
    /** @brief 질의 처리기가 읽는 체인 슬롯. */
    pub(crate) slot: crate::native::ResolverSlot,
}

/** @brief 세대가 소유한 보조 작업을 새 설정으로 다시 시작하는 함수. */
pub(crate) type SecondaryRestart = Arc<dyn Fn(&Config) -> Result<(), String> + Send + Sync>;

/**
 * @brief 설정이 바뀌면 다시 시작할 작업들의 핸들.
 * @details 핸들을 채우는 코드는 세대 시작의 뒤쪽에 있지만 핫 적용은 그보다 먼저 만들어진다.
 *          그래서 빈 슬롯을 먼저 잡아 두고 나중에 채운다. 채우기 전에 들어온 핫 적용은 그 작업을
 *          건너뛴다.
 */
#[derive(Clone, Default)]
pub(crate) struct RestartHooks {
    /** @brief 해석 체인을 다시 만들어 교체한다. */
    pub(crate) chain: Arc<Mutex<Option<ChainRebuild>>>,
    /** @brief 관리 수신 주소를 다시 연다. */
    pub(crate) control: Arc<Mutex<Option<SecondaryRestart>>>,
    /** @brief 세컨더리 영역 갱신 작업을 다시 시작한다. */
    pub(crate) secondary: Arc<Mutex<Option<SecondaryRestart>>>,
    /** @brief DHCP 임대 동기화 작업을 다시 시작한다. */
    pub(crate) lease_sync: Arc<Mutex<Option<SecondaryRestart>>>,
    /** @brief Raft 런타임을 다시 시작한다. */
    pub(crate) raft: Arc<Mutex<Option<SecondaryRestart>>>,
    /** @brief ZSK 교체 작업을 다시 시작한다. */
    pub(crate) zsk_rollover: Arc<Mutex<Option<SecondaryRestart>>>,
    /** @brief 수신 주소를 설정에 맞춘다. 설정이 그대로인 주소는 건드리지 않는다. */
    pub(crate) listeners: Arc<Mutex<Option<SecondaryRestart>>>,
}

/**
 * @brief 슬롯에 작업을 넣고 지금 설정으로 한 번 실행한다.
 * @note 실행하는 동안 슬롯을 잠가 두므로 핫 적용이 같은 작업을 동시에 다시 시작하지 못한다.
 */
pub(crate) fn install_restart(
    slot: &Mutex<Option<SecondaryRestart>>,
    hook: SecondaryRestart,
    cfg: &Config,
) -> Result<(), String> {
    use onetdns_core::MutexExt;
    let mut installed = slot.lock_recover();
    installed.insert(hook)(cfg)
}

/**
 * @brief 차단 엔진을 지금 설정과 목록으로 다시 만들어 교체하는 함수.
 * @return 차단 규칙 수와 허용 규칙 수.
 */
pub(crate) type FilterRebuild =
    Arc<dyn Fn() -> Result<(usize, usize), String> + Send + Sync + 'static>;

/** @brief 교체를 실제로 하는 함수. */
pub(crate) type HotConfigApply =
    Arc<dyn Fn(&Config, &[String]) -> Result<(bool, Vec<String>), String> + Send + Sync + 'static>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 설정을 어떻게 반영했는지. */
pub(crate) enum ConfigApplyMode {
    /** @brief 바뀐 것이 없다. */
    NoChange,
    /** @brief 재시작하지 않고 교체했다. */
    HotReload,
    /** @brief 재시작해야 한다. */
    ServiceRestart,
}

impl ConfigApplyMode {
    /** @brief 이름. */
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NoChange => "no_change",
            Self::HotReload => "hot_reload",
            Self::ServiceRestart => "service_restart",
        }
    }

    /** @brief 재시작해야 하는지. */
    pub(crate) fn restart_required(self) -> bool {
        matches!(self, Self::ServiceRestart)
    }
}

#[derive(Debug, Clone)]
/** @brief 설정 반영 결과. */
pub(crate) struct ConfigApplyResult {
    /** @brief 어떻게 반영했는지. */
    pub(crate) mode: ConfigApplyMode,
    /** @brief 달라진 설정 항목들. */
    pub(crate) changed: Vec<String>,
}

impl ConfigApplyResult {
    /** @brief 결과를 JSON 항목들로. */
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

/** @brief 두 설정 텍스트에서 달라진 항목들. */
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

/** @brief 설정 파일을 한 번에 하나씩만 고치게 한다. */
pub(crate) fn config_write_lock() -> &'static Mutex<()> {
    /** @brief 설정 파일 잠금. */
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/** @brief 바뀐 것만 보고 교체하거나 재시작한다. */
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

/** @brief 잠금을 잡은 채로 반영한다. */
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
    /* 검증 API와 같은 기준으로 거른다. 통과시키면 저장한 뒤 재시작할 때 서버가 뜨지 않는다. */
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

/** @brief 설정을 고쳐 저장한다. 건드리지 않은 항목은 그대로 둔다. 전체를 덮어쓰면 다른 설정이 사라진다. */
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

/** @brief 잠금을 잡은 채로 고쳐 저장한다. */
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

/** @brief 적용 중인 설정을 한 번에 하나씩만 고치게 한다. */
pub(crate) fn runtime_config_update_lock() -> &'static Mutex<()> {
    /** @brief 적용 중인 설정 잠금. */
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/** @brief 적용 중인 설정을 고친다. 잠금 안에서 읽고 고쳐야 동시에 온 다른 변경이 사라지지 않는다. */
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

/** @brief 비교 전에 기본값으로 채워진 것을 맞춘다. 안 맞추면 바뀌지 않은 것이 바뀐 것으로 보인다. */
pub(crate) fn normalize_config_for_comparison(runtime: &Config, desired: &Config) -> Config {
    let mut normalized = desired.clone();
    let dashboard_default = SocketAddr::from(([127, 0, 0, 1], 8553));
    if normalized.control_listen.is_none() && runtime.control_listen == Some(dashboard_default) {
        normalized.control_listen = Some(dashboard_default);
    }
    normalized
}

/** @brief 두 설정에서 값이 다른 키들. 이름순이다. */
pub(crate) fn config_changed_keys(runtime: &Config, desired: &Config) -> Vec<String> {
    let mut changed: Vec<String> = config_keys::changed_keys(runtime, desired)
        .map(str::to_string)
        .collect();
    changed.sort_unstable();
    changed
}

/** @brief 파일에 적힌 설정을 JSON으로. */
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

/**
 * @brief 파일에 적힌 설정을 반영하면 바뀌는 항목과 그 가운데 서비스를 다시 시작하는 항목.
 * @details 파일을 반영하는 경로와 같이 비교용으로 맞추고 service_restart_keys 로 판정한다. 그래야
 *          관리 화면이 반영하기 전에 묻는 내용이 실제 반영 결과와 맞는다.
 */
fn config_changed_keys_for_status(
    runtime: &Config,
    desired: &Config,
) -> (Vec<String>, Vec<String>) {
    let desired = normalize_config_for_comparison(runtime, desired);
    let changed = config_changed_keys(runtime, &desired);
    let restart = service_restart_keys(runtime, &desired, &changed);
    (changed, restart)
}

/** @brief 설정 파일을 읽어 config_changed_keys_for_status 로 판정한다. */
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

/**
 * @brief 파일과 지금 적용 중인 설정이 어긋나는지, 그리고 지금 설정에서 바꾸면 재시작할 수 있는 항목을
 *        JSON으로.
 * @details 관리 화면은 이 응답을 주기적으로 읽는다. 항목 분류는 클라이언트 경로처럼 지금 설정에 따라
 *          달라지므로, 화면을 연 뒤에 설정이 바뀌어도 항목 표시가 따라가도록 여기에 함께 싣는다.
 */
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
/** @brief 바뀐 키의 분류와 적용 방식. */
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use onetdns_config::{Config, UpstreamStrategy};
    use onetdns_core::{ArcSwap, MutexExt};

    use crate::config_keys::ApplyGroup;
    use crate::{config_keys, unix_now, ConfigTextSlot, CONFIG_FILE_NAME};

    #[test]
    /** @brief 실패한 설정 편집이 파일, 이전 스냅샷, 재시작 표식을 건드리지 않는지. */
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
    /** @brief 동시에 온 다른 변경이 사라지지 않는지. */
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
    /** @brief 재시작해야 할 변경이 교체로 가려지지 않는지. 가려지면 반영된 줄 안다. */
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
    /** @brief 파일과 적용 중인 설정이 어긋나면 알리는지. */
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
    /**
     * @brief 가려진 사용자 정보의 변화를 계정 변경이라고 짚어 내는지.
     * @details 뭉뚱그린 이름으로 두면 비밀번호를 한 번 바꿀 때마다 DNS 처리가 끊긴다.
     */
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
    /**
     * @brief 요약에 드러난 항목과 가려진 항목이 한 요청에서 함께 바뀌어도 둘 다 짚는지.
     * @details 가려진 항목을 놓치면 토큰을 교체한 요청이 적용된 것으로 보고되고 이전 토큰이
     *          계속 통한다.
     */
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
    /**
     * @brief 개수로 요약된 항목이 늘거나 줄어도 무중단 적용 대상으로 분류되는지.
     * @details 요약에 설정 키와 다른 이름을 쓰면 적용 경로가 그 이름을 몰라 서비스를 전부
     *          재시작한다.
     */
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
    /**
     * @brief 설정을 바꾸는 API가 검증 API와 같은 시작 전 검사를 거치는지.
     * @details 이 검사를 건너뛰면 검증 API는 거절하는 값이 파일에 저장되고, 다음에 재시작할
     *          때 서버가 뜨지 않는다.
     */
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
    /** @brief 가려진 관리 토큰 값만 바뀌어도 토큰 변경으로 분류하는지. */
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
    /**
     * @brief 값만 바뀐 비밀 목록이 제 이름으로 불리는지.
     *
     * @details 유효 설정 요약은 이 목록들을 개수나 이름으로만 싣는다. 요약을 비교해서는 개수가
     *          같은 교체가 드러나지 않고, 바뀐 키를 대지 못하면 그 변경을 반영할 그룹도 정하지
     *          못한다.
     */
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
    /**
     * @brief 바뀐 키 목록에 설정 키만 드는지.
     * @details 유효 설정 요약은 mtls_enforced, cachedb_redis_password_set 처럼 설정 키가 아닌
     *          파생 항목도 싣는다. 그런 이름은 키 표에 없으므로, 바뀐 키에 섞이면 교체할 수 있는
     *          변경이 재시작이 된다.
     */
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
    /**
     * @brief 요약에 영역 이름만 실리는 목록의 세부 값이 바뀌어도 그 키로 불리는지.
     * @details 세컨더리 영역은 요약에 이름만 실린다. 주 서버 주소만 바꾼 변경이 다른 키와 함께
     *          들어올 때 이 키가 빠지면 권한 그룹을 교체하지 않아서, 세컨더리 갱신 작업이 이전 주
     *          서버에서 계속 받아 온다.
     */
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
    /** @brief 파일이 깨졌을 때 적용 중인 설정으로 대신 보여 주지 않는지. */
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
    /** @brief 기본값으로 채운 것이 어긋남으로 보이지 않는지. */
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
    /** @brief 제어 리스너를 뺀 것이 가려지지 않는지. */
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
    /** @brief 제어 리스너를 바꾼 것은 그대로 알리는지. */
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
    /** @brief 파일과 적용 중인 설정의 차이를 찾아내는지. */
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
    /** @brief DDR이 광고하는 수신 주소가 바뀌면 해석 체인도 반드시 다시 만들어지는지. */
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
    /** @brief 전달 설정은 체인이 그 값을 쓰는 전달기가 있을 때만 체인을 다시 만드는지. */
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
    /** @brief 영역이 생기거나 사라질 때만 체인을 다시 만들고, 영역 편집은 저장소 교체로 끝나는지. */
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
    /**
     * @brief 로컬 도메인을 바꾸면 DHCP 서비스와 체인을 함께 다시 만드는지.
     * @details 이 값은 DHCP 옵션 15로 나가고 DHCP DNS 계층의 로컬 이름에도 쓰인다. 한쪽만 다시
     *          만들면 임대에 알린 도메인과 DNS 가 답하는 이름이 어긋난다.
     */
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
    /** @brief 업스트림을 바꾸는 것은 재시작하지 않아도 되는지. */
    fn forward_upstream_change_is_hot_reload() {
        let current =
            Config::from_toml_str("backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\n").unwrap();
        let proposed =
            Config::from_toml_str("backend = \"forward\"\nupstreams = [\"8.8.8.8\"]\n").unwrap();
        assert!(config_keys::swappable("upstreams", &current, &proposed));
    }

    #[test]
    /**
     * @brief 전달을 쓰지 않던 backend에서 전달을 쓰는 backend로 바꾸며 업스트림을 함께 고쳐도
     *        재시작하지 않는지.
     * @details 전달 리졸버 슬롯은 backend와 상관없이 시작할 때 만들어지고, 설정 반영이 새
     *          업스트림으로 만든 리졸버를 그 슬롯에 넣는다.
     */
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
    /** @brief 전달 세부 설정이 재시작하지 않아도 되는지. */
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
    /** @brief 클라이언트별 업스트림 설정은 재시작해야 하는지. 체인을 다시 지어야 한다. */
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
    /**
     * @brief 재귀 리졸버의 질의 제한 시간은 체인을 다시 만들어 재시작 없이 반영하는지.
     * @details 체인을 다시 만들 때 계획으로 재귀 리졸버를 새로 만들고, 계획에 질의 제한 시간이
     *          들어 있다.
     */
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
    /**
     * @brief 처리 방식과 전달 세부 설정을 함께 바꿔도 재시작하지 않는지.
     * @details 전달기는 새 설정이 전달을 쓰고 이전 설정이 쓰지 않았으면 새로 만들고, 체인은
     *          처리 방식이 바뀌면 다시 만든다.
     */
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
    /** @brief 정책만 바뀌면 교체하고, 경로가 바뀌면 재시작하는지. */
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
    /** @brief 하드웨어 주소 기준 클라이언트를 처음 넣으면 재시작하는지. */
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

    /** @brief 업스트림을 따로 쓰는 클라이언트 경로 하나. */
    const CLIENT_ROUTE: &str =
        "[[clients]]\nname = \"office\"\nids = [\"192.0.2.0/24\"]\nupstreams = [\"9.9.9.9\"]\n";

    /**
     * @brief 최상위 키 줄에서 key 를 value 로 바꾼 설정 본문.
     * @param top    최상위 키 줄들.
     * @param tables 최상위 키 뒤에 오는 표 배열들.
     */
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
    /**
     * @brief 클라이언트 경로가 있으면 체인을 다시 만드는 변경을 재시작으로 판정하는지.
     * @details 경로의 체인은 세대를 시작할 때만 만들어지므로, 기본 체인만 교체하면 경로의
     *          클라이언트가 이전 설정으로 답을 받는다. 변경 미리보기도 이 판정을 쓰므로, 여기서
     *          빠지면 관리 화면이 재시작하는 변경을 무중단이라고 알린다.
     */
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
    /** @brief 관리 화면에 알리는 조건부 키가 지금 설정을 따르는지. */
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
    /**
     * @brief 클라이언트 경로가 있을 때 체인 계획을 바꾸는 키를 모두 조건부로 알리는지.
     * @details 키마다 형에 맞는 값을 넣어 보고, 계획이 달라지는데 무중단으로 알리는 키가 있으면
     *          실패한다. 계획이 다른 그룹의 키를 새로 읽으면서 ChainPlan::other_group_inputs 에
     *          넣지 않으면 여기서 드러난다. 기반 설정은 그 함수가 보는 구성 요소를 하나씩만
     *          켠다. 여럿을 함께 켜면 한 구성 요소의 목록이 다른 구성 요소의 빠진 키를 가린다.
     */
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
    /** @brief 달라진 항목 목록이 정렬되고 겹치지 않는지. */
    fn changed_config_keys_are_sorted_and_deduplicated() {
        let cur = "block_rules = [\"a.example\"]\nlisten = [\"127.0.0.1:53\"]\n";
        let new = "block_rules = [\"b.example\"]\nlisten = [\"127.0.0.1:5353\"]\n";
        let keys = changed_config_keys(cur, new).unwrap();
        assert_eq!(keys, vec!["block_rules".to_string(), "listen".to_string()]);
    }
}
