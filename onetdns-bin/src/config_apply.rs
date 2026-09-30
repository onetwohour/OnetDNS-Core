/*!
 * @brief 설정 편집을 파일에 쓰고, 바뀐 키에 따라 즉시 교체할지 새 세대로 시작할지 정한다.
 */

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use onetdns_config::{BackendKind, Config};
use onetdns_core::ArcSwap;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::atomic_file::atomic_write;
use crate::config_keys::ApplyGroup;
use crate::{config_keys, resolver_chain, runtime_preflight, ConfigTextSlot};

/**
 * @brief 응답 캐시 아래에서 판정하는 로컬 전용 이름 설정들.
 * @details 판정 결과가 캐시에 담기므로, 이 값을 바꾸면 캐시를 비워야 바뀐 판정이 바로 나간다.
 */
pub(crate) const LOCAL_ONLY_CONFIG_KEYS: &[&str] = &["domain_needed", "bogus_priv", "empty_zones"];

/** @brief 무엇이 바뀌었느냐에 따라 재시작 여부가 갈리는 설정들. */
pub(crate) const CONDITIONAL_HOT_RELOAD_CONFIG_KEYS: &[&str] = &["clients"];

/** @brief 직접 바뀐 설정과 그 설정이 다시 만들어야 하는 파생 그룹을 모은다. */
pub(crate) fn hot_reload_groups(
    previous: &Config,
    next: &Config,
    changed: &[String],
) -> Vec<ApplyGroup> {
    let mut groups = changed
        .iter()
        .filter_map(|key| config_keys::hot_group(key))
        .collect::<Vec<_>>();
    /*
     * 체인은 계획만 읽으므로, 어느 키가 바뀌었든 계획이 달라지면 체인을 다시 만든다.
     * 질의 제한 시간처럼 전달 그룹에 속한 키도 스텁 영역과 예비 업스트림의 전달기에 쓰인다.
     */
    if resolver_chain::ChainPlan::new(previous) != resolver_chain::ChainPlan::new(next) {
        groups.push(ApplyGroup::Chain);
    }
    /* DHCP 임대 풀은 서비스를 다시 띄우면 새로 만들어지므로, DHCP DNS 계층도 새 풀을 봐야 한다. */
    if groups.contains(&ApplyGroup::EdgeServices) {
        groups.push(ApplyGroup::Chain);
    }
    /* 로컬 도메인은 DHCP 옵션 15로도 나간다. */
    if changed.iter().any(|key| key == "dhcp_local_domain") {
        groups.push(ApplyGroup::EdgeServices);
    }
    // 클러스터 활성 상태나 공용 비밀이 바뀌면 DNS Cookie의 공유 루트도 같은 설정 세대에서
    // 다시 만들어야 한다. native 그룹은 ArcSwap 한 번으로 기존/새 정책 중 하나만 보인다.
    if changed.iter().any(|key| key == "cluster_raft")
        || ((previous.cluster_raft || next.cluster_raft)
            && changed.iter().any(|key| key == "cluster_raft_secret"))
    {
        groups.push(ApplyGroup::Native);
    }
    groups.sort_unstable();
    groups.dedup();
    groups
}

/** @brief 이 backend가 전달 리졸버를 쓰는지. */
pub(crate) fn backend_uses_forward(backend: BackendKind) -> bool {
    matches!(backend, BackendKind::Forward | BackendKind::Split)
}

/** @brief 클라이언트 설정 변화가 재시작를 요구하는지. 경로가 바뀌면 체인을 다시 지어야 한다. */
fn clients_require_service_restart(current: &Config, proposed: &Config) -> bool {
    let current_routes: Vec<_> = current
        .clients
        .iter()
        .filter(|client| !client.upstreams.is_empty())
        .collect();
    let proposed_routes: Vec<_> = proposed
        .clients
        .iter()
        .filter(|client| !client.upstreams.is_empty())
        .collect();

    let routes_changed = current_routes.len() != proposed_routes.len()
        || current_routes
            .iter()
            .zip(proposed_routes.iter())
            .any(|(old, new)| {
                old.ids != new.ids
                    || old.client_ids != new.client_ids
                    || old.mac != new.mac
                    || old.upstreams != new.upstreams
            });
    if routes_changed {
        return true;
    }

    let had_mac = current.clients.iter().any(|client| !client.mac.is_empty());
    let needs_mac = proposed.clients.iter().any(|client| !client.mac.is_empty());
    !had_mac && needs_mac
}

/** @brief 클라이언트별 업스트림 경로가 있는지. */
pub(crate) fn has_client_upstream_routes(config: &Config) -> bool {
    config
        .clients
        .iter()
        .any(|client| !client.upstreams.is_empty())
}

/** @brief 이 변화를 재시작하지 않고 반영할 수 있는지. */
pub(crate) fn is_hot_reload_config_change(current: &Config, proposed: &Config, key: &str) -> bool {
    if !config_keys::is_hot(key) {
        return false;
    }
    let client_routes_active =
        has_client_upstream_routes(current) || has_client_upstream_routes(proposed);
    match key {
        "clients" => !clients_require_service_restart(current, proposed),

        "query_timeout_secs" => {
            current.backend == proposed.backend
                && current.backend == BackendKind::Forward
                && !client_routes_active
        }

        "upstream_strategy" | "upstream_concurrency" => {
            current.backend == proposed.backend && !client_routes_active
        }
        _ => true,
    }
}

/** @brief 새 계획으로 해석 체인을 다시 만들어 교체하는 함수. */
pub(crate) type ChainRebuild =
    Arc<dyn Fn(&resolver_chain::ChainPlan) -> Result<(), String> + Send + Sync>;

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

/** @brief 설정의 지문. */
fn config_fingerprint(config: &Config) -> [u8; 32] {
    /** @brief 프로세스 밖에서 비밀값 후보를 지문과 대조하지 못하게 하는 키. */
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    let debug = Zeroizing::new(format!("{config:?}"));
    let mut digest = Sha256::new();
    digest.update(KEY.get_or_init(onetdns_core::random_array::<32>));
    digest.update((debug.len() as u64).to_le_bytes());
    digest.update(debug.as_bytes());

    // SecretString의 Debug는 반드시 가려져야 한다. 그렇다고 값 변화까지 숨기면 핫 리로드가
    // 비밀번호·토큰 교체를 놓치므로, 외부로 내보내지 않는 키드 지문에만 원문을 넣는다.
    let mut secret = |label: &str, value: &str| {
        digest.update((label.len() as u64).to_le_bytes());
        digest.update(label.as_bytes());
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value.as_bytes());
    };
    secret("control_token", config.control_token.as_str());
    for value in &config.control_admin_tokens {
        secret("control_admin_token", value.as_str());
    }
    for value in &config.control_readonly_tokens {
        secret("control_readonly_token", value.as_str());
    }
    for user in &config.users {
        secret("user_password_hash", user.password_hash.as_str());
    }
    if let Some(value) = &config.zones_etcd_password {
        secret("zones_etcd_password", value.as_str());
    }
    if let Some(value) = &config.zones_postgres {
        secret("zones_postgres", value.as_str());
    }
    if let Some(value) = &config.zones_mysql {
        secret("zones_mysql", value.as_str());
    }
    for key in &config.tsig_keys {
        secret("tsig_secret", key.secret.as_str());
    }
    secret("cluster_raft_secret", config.cluster_raft_secret.as_str());
    secret(
        "cluster_raft_node_key",
        config.cluster_raft_node_key.as_str(),
    );
    digest.finalize().into()
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

/**
 * @brief 두 설정에서 달라진 항목들.
 * @details 요약에 값이 드러나지 않는 항목은 지문을 비교해 찾는다. 요약에 드러난 항목이 같은
 *          요청에서 함께 바뀌었어도 이 탐색은 한다. 건너뛰면 토큰 교체나 일정 삭제가 적용
 *          목록에서 빠져 이전 값이 계속 쓰인다.
 * @note 요약에 드러난 항목이 바뀌었으면, 이름 붙일 수 없는 나머지 차이는 가려낼 수 없다.
 */
pub(crate) fn config_changed_keys(
    runtime: &Config,
    desired: &Config,
) -> Result<Vec<String>, String> {
    use onetdns_core::json::Json;
    let applied = onetdns_core::json::parse(&runtime.effective_json())
        .map_err(|error| format!("Could not compare the running configuration: {error}"))?;
    let wanted = onetdns_core::json::parse(&desired.effective_json())
        .map_err(|error| format!("Could not compare the saved configuration file: {error}"))?;
    let (Json::Obj(applied), Json::Obj(wanted)) = (applied, wanted) else {
        return Err("Configuration comparison data is not a JSON object".to_string());
    };
    /** @brief 이 항목의 값. */
    fn lookup<'a>(pairs: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
        pairs
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }
    let mut changed = Vec::new();
    for (key, value) in &wanted {
        if lookup(&applied, key) != Some(value) {
            changed.push(key.clone());
        }
    }
    for (key, _) in &applied {
        if lookup(&wanted, key).is_none() {
            changed.push(key.clone());
        }
    }

    let summary_changed = !changed.is_empty();
    if config_fingerprint(runtime) != config_fingerprint(desired) {
        // 요약에 개수만 담기거나 아예 빠지는 항목들이 있다. 개수가 같은 채로 값만 달라지면
        // 위 비교로는 드러나지 않는다. 그렇다고 뭉뚱그리면 무중단 대상인 줄 모르고 다시
        // 시작한다. 항목 하나씩 실행 중 값으로 되돌려 보고, 지문이 그대로면 그 항목이 범인이다.
        /** @brief 이 항목만 실행 중 값으로 되돌린다. */
        type Restore = fn(&mut Config, &Config);
        let opaque: &[(&str, Restore)] = &[
            ("users", |probe, live| probe.users = live.users.clone()),
            ("clients", |probe, live| {
                probe.clients = live.clients.clone()
            }),
            ("views", |probe, live| probe.views = live.views.clone()),
            ("policy", |probe, live| probe.policy = live.policy.clone()),
            ("rewrites", |probe, live| {
                probe.rewrites = live.rewrites.clone()
            }),
            ("local_zones", |probe, live| {
                probe.local_zones = live.local_zones.clone()
            }),
            ("local_a", |probe, live| {
                probe.local_a = live.local_a.clone()
            }),
            ("local_aaaa", |probe, live| {
                probe.local_aaaa = live.local_aaaa.clone()
            }),
            ("stub_zones", |probe, live| {
                probe.stub_zones = live.stub_zones.clone()
            }),
            ("dynamic_records", |probe, live| {
                probe.dynamic_records = live.dynamic_records.clone()
            }),
            ("update_policy", |probe, live| {
                probe.update_policy = live.update_policy.clone()
            }),
            ("service_schedule", |probe, live| {
                probe.service_schedule = live.service_schedule.clone()
            }),
            ("tsig_keys", |probe, live| {
                probe.tsig_keys = live.tsig_keys.clone()
            }),
            ("control_token", |probe, live| {
                probe.control_token = live.control_token.clone()
            }),
            ("control_admin_tokens", |probe, live| {
                probe.control_admin_tokens = live.control_admin_tokens.clone()
            }),
            ("control_readonly_tokens", |probe, live| {
                probe.control_readonly_tokens = live.control_readonly_tokens.clone()
            }),
            ("zones_etcd_password", |probe, live| {
                probe.zones_etcd_password = live.zones_etcd_password.clone()
            }),
            ("zones_postgres", |probe, live| {
                probe.zones_postgres = live.zones_postgres.clone()
            }),
            ("zones_mysql", |probe, live| {
                probe.zones_mysql = live.zones_mysql.clone()
            }),
            ("cluster_raft_secret", |probe, live| {
                probe.cluster_raft_secret = live.cluster_raft_secret.clone()
            }),
            ("cluster_raft_node_key", |probe, live| {
                probe.cluster_raft_node_key = live.cluster_raft_node_key.clone()
            }),
        ];
        let mut probe = desired.clone();
        for (name, restore) in opaque {
            let before = config_fingerprint(&probe);
            restore(&mut probe, runtime);
            if config_fingerprint(&probe) != before {
                changed.push((*name).to_string());
            }
        }
        // 하나씩 되돌려도 실행 중 설정과 같아지지 않으면 이름을 붙일 수 없다.
        if !summary_changed && config_fingerprint(&probe) != config_fingerprint(runtime) {
            changed.push("structured_or_secret_config".to_string());
        }
    }
    changed.sort();
    changed.dedup();
    Ok(changed)
}

/** @brief 상태 표시에 쓸 달라진 항목들. */
fn config_changed_keys_for_status(
    runtime: &Config,
    desired: &Config,
) -> Result<Vec<String>, String> {
    let normalized = normalize_config_for_comparison(runtime, desired);
    config_changed_keys(runtime, &normalized)
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

/** @brief 파일과 지금 적용 중인 설정이 어긋나는지 JSON으로. */
pub(crate) fn config_status_json(path: Option<&std::path::Path>, runtime: &Config) -> String {
    let Some(path) = path else {
        return "{\"in_sync\":true,\"source\":\"runtime\",\"changed_keys\":[]}".to_string();
    };
    let text = match Config::read_text(path) {
        Ok(text) => onetdns_core::SecretString::from(text),
        Err(error) => {
            return format!(
                "{{\"in_sync\":false,\"source\":\"disk\",\"error\":{},\"changed_keys\":[]}}",
                onetdns_core::json::escape(&error.to_string())
            );
        }
    };
    let desired = match Config::from_toml_str(&text) {
        Ok(config) => config,
        Err(error) => {
            return format!(
                "{{\"in_sync\":false,\"source\":\"disk\",\"error\":{},\"changed_keys\":[]}}",
                onetdns_core::json::escape(&error.to_string())
            );
        }
    };
    match config_changed_keys_for_status(runtime, &desired) {
        Ok(changed) => {
            let keys: Vec<String> = changed
                .iter()
                .map(|key| onetdns_core::json::escape(key))
                .collect();
            format!(
                "{{\"in_sync\":{},\"source\":\"disk\",\"changed_keys\":[{}]}}",
                changed.is_empty(),
                keys.join(",")
            )
        }
        Err(error) => format!(
            "{{\"in_sync\":false,\"source\":\"disk\",\"error\":{},\"changed_keys\":[]}}",
            onetdns_core::json::escape(&error)
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

        let changed = config_changed_keys(&active, &proposed).unwrap();
        assert!(changed.contains(&"safe_search".to_string()));
        assert!(changed.contains(&"run_as_user".to_string()));
        assert!(changed
            .iter()
            .any(|key| !is_hot_reload_config_change(&active, &proposed, key)));
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
        let changed = config_changed_keys(&applied, &desired).unwrap();
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
        let changed = config_changed_keys(&applied, &desired).unwrap();
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
        let changed = config_changed_keys(&applied, &desired).unwrap();
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
        let changed = config_changed_keys(&applied, &desired).unwrap();
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
            config_changed_keys(&applied, &desired).unwrap(),
            vec!["control_token".to_string()]
        );

        applied.control_token = desired.control_token.clone();
        assert!(config_changed_keys(&applied, &desired).unwrap().is_empty());
    }

    #[test]
    /**
     * @brief 값만 바뀐 비밀 목록이 제 이름으로 불리는지.
     *
     * @details 이 항목들은 요약에 개수나 이름만 실려, 값을 갈아도 개수가 같으면 비교에
     *          드러나지 않는다. 되돌려보기 목록에 없으면 포괄 이름이 붙는데 그 이름은 어느
     *          무중단 그룹에도 없어, 무중단으로 갈 수 있는 키 교체가 재시작이 된다.
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
                config_changed_keys(&applied, &desired).unwrap(),
                vec![label.to_string()],
                "{label}을 갈았는데 그 이름으로 불리지 않았습니다"
            );
            assert!(
                config_keys::is_hot(label) || label == "tsig_keys",
                "{label}은 무중단 그룹에 있어야 합니다"
            );
            mutate(&mut applied);
            assert!(
                config_changed_keys(&applied, &desired).unwrap().is_empty(),
                "{label}을 맞춘 뒤에는 달라진 것이 없어야 합니다"
            );
        }
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

        let changed = config_changed_keys_for_status(&runtime, &desired).unwrap();
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

        let changed = config_changed_keys(&runtime, &desired).unwrap();
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

        let changed = config_changed_keys_for_status(&runtime, &desired).unwrap();
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

        std::fs::write(&path, "cache_size = [broken").unwrap();
        let status = config_status_json(Some(&path), &runtime);
        assert!(status.contains("\"in_sync\":false"), "{status}");
        assert!(status.contains("error"), "{status}");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    /** @brief Raft 쿠키 루트 입력이 바뀌면 cluster와 native 그룹을 함께 준비하는지. */
    fn raft_cookie_root_changes_rebuild_native_features() {
        let previous = Config::default();
        let mut staged = previous.clone();
        staged.cluster_raft_secret = "shared-cluster-secret-at-least-32-bytes".into();
        assert_eq!(
            hot_reload_groups(&previous, &staged, &["cluster_raft_secret".to_string()]),
            vec![ApplyGroup::Cluster],
            "Raft를 켜기 전 비밀 준비는 독립 실행 Cookie를 무효화하지 않습니다"
        );

        let mut next = staged.clone();
        next.cluster_raft = true;

        assert_eq!(
            hot_reload_groups(&staged, &next, &["cluster_raft".to_string()]),
            vec![ApplyGroup::Cluster, ApplyGroup::Native]
        );
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
    /** @brief 업스트림을 바꾸는 것은 재시작하지 않아도 되는지. */
    fn forward_upstream_change_is_hot_reload() {
        let current =
            Config::from_toml_str("backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\n").unwrap();
        let proposed =
            Config::from_toml_str("backend = \"forward\"\nupstreams = [\"8.8.8.8\"]\n").unwrap();
        assert!(is_hot_reload_config_change(
            &current,
            &proposed,
            "upstreams"
        ));
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
        assert!(is_hot_reload_config_change(&current, &proposed, "backend"));
        assert!(is_hot_reload_config_change(
            &current,
            &proposed,
            "upstreams"
        ));
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
        assert!(is_hot_reload_config_change(
            &current,
            &proposed,
            "upstream_concurrency"
        ));
        assert!(is_hot_reload_config_change(
            &current,
            &proposed,
            "query_timeout_secs"
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
            assert!(!is_hot_reload_config_change(&current, &proposed, key));
        }
        assert!(is_hot_reload_config_change(
            &current,
            &proposed,
            "upstreams"
        ));
    }

    #[test]
    /** @brief 가름 데드라인 설정은 체인을 다시 지어야 하는지. */
    fn split_timeout_still_requires_resolver_restart() {
        let current =
            Config::from_toml_str("backend = \"split\"\nupstreams = [\"1.1.1.1\"]\n").unwrap();
        let proposed = Config::from_toml_str(
            "backend = \"split\"\nupstreams = [\"1.1.1.1\"]\nquery_timeout_secs = 2\n",
        )
        .unwrap();
        assert!(!is_hot_reload_config_change(
            &current,
            &proposed,
            "query_timeout_secs"
        ));
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
        assert!(is_hot_reload_config_change(
            &current,
            &policy_only,
            "clients"
        ));

        let routed = Config::from_toml_str(
            "[[clients]]
    name = \"desktop\"
    ids = [\"192.0.2.10/32\"]
    upstreams = [\"1.1.1.1\"]
    ",
        )
        .unwrap();
        assert!(!is_hot_reload_config_change(&current, &routed, "clients"));
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
        assert!(!is_hot_reload_config_change(&current, &proposed, "clients"));
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
