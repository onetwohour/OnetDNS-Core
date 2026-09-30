/*!
 * @brief Raft 클러스터 런타임과 클러스터를 거치는 설정 쓰기.
 */

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use onetdns_config::Config;
use onetdns_core::MutexExt;
use sha2::{Digest, Sha256};

use crate::config_apply::{
    apply_config_edit_locked, apply_config_edit_smart_locked, changed_config_keys,
    config_write_lock, ConfigApplyMode, HotConfigApply,
};
use crate::config_edit::{
    json_to_raft_toml_literal, materialize_mode_acl_patch, remove_config_key, rewrite_config_kv,
    toml_value_to_json, MAX_RAFT_VALUE_DEPTH,
};
use crate::notify::NotifySender;
use crate::zone_signing::SharedZoneSigners;
use crate::zones::apply_zone_mutation;
use crate::{config_keys, http, native, sleep_or_shutdown, ConfigTextSlot};

#[derive(Clone, PartialEq, Eq)]
/** @brief 이 노드의 클러스터 신원. */
struct RaftRuntimeIdentity {
    /** @brief 이 노드 번호. */
    node_id: u64,
    /** @brief 이 노드가 묶을 주소. */
    listen: String,
    /** @brief 다른 노드들의 번호·주소·키. */
    peers: Vec<(u64, String, [u8; 32])>,
    /** @brief 이 노드만의 시드. 노드마다 달라야 한다. */
    node_seed: [u8; 32],
    /** @brief 클러스터 공유 비밀의 지문. 설정이 바뀌었는지 본다. */
    secret_digest: [u8; 32],
    /** @brief 합의 상태를 담아 둘 파일. */
    state_path: PathBuf,
}

#[derive(Clone)]
/** @brief 이 세대에서 Raft 로그 항목을 적용할 방법. */
struct RaftGenerationApply {
    /** @brief 설정을 다시 읽게 하는 플래그. */
    reload: Arc<std::sync::atomic::AtomicBool>,
    /** @brief 재시작하지 않고 교체하는 방법. 없으면 재시작한다. */
    hot_apply: Option<HotConfigApply>,
}

/** @brief Raft 로그 항목을 적용하는 곳. 세대가 바뀌면 교체한다. */
struct RaftApplyContext {
    /** @brief 설정 파일 경로. */
    path: Option<PathBuf>,
    /** @brief 앞선 설정 텍스트. */
    prev: ConfigTextSlot,
    /** @brief 마지막으로 성공한 설정 텍스트. */
    applied: ConfigTextSlot,
    /** @brief 이 세대의 적용 방법. 세대가 바뀌면 교체한다. */
    generation: Mutex<RaftGenerationApply>,
}

impl RaftApplyContext {
    /** @brief 만든다. */
    fn new(
        path: Option<PathBuf>,
        prev: ConfigTextSlot,
        applied: ConfigTextSlot,
        generation: RaftGenerationApply,
    ) -> Self {
        Self {
            path,
            prev,
            applied,
            generation: Mutex::new(generation),
        }
    }

    /**
     * @brief 이 세대의 적용 방법을 끼운다.
     * @details 세대를 새로 시작할 때는 시작하는 동안 설정 파일이 바뀌었는지 보고, 바뀌었으면
     *          다시 읽도록 표시한다. 비교와 교체는 설정 쓰기 잠금 하나 안에서 한다. 적용은
     *          같은 잠금을 잡고 세대를 읽으므로, 비교한 뒤 잠금을 풀고 교체하면 그 사이에 온
     *          변경은 옛 세대에만 알려지고 파일 비교에도 잡히지 않아 사라진다.
     * @param expected_text 이 세대가 읽은 설정 텍스트. 없음은 호출자가 이미 설정 쓰기 잠금을
     *        잡고 있다는 뜻이며, 핫 적용이 그렇게 부른다.
     * @warning 핫 적용은 설정 쓰기 잠금을 잡은 채 지금 파일 내용으로 부른다. 여기서 잠금을
     *          다시 잡으면 멈추고, 부팅 때 텍스트와 비교하면 부팅 뒤 바뀐 파일을 보고 서비스
     *          전체를 재시작한다.
     */
    fn install_generation(
        &self,
        expected_text: Option<&str>,
        generation: RaftGenerationApply,
    ) -> Result<bool, String> {
        let _write_guard = expected_text.map(|_| config_write_lock().lock_recover());
        let changed_during_start = match (self.path.as_deref(), expected_text) {
            (Some(path), Some(expected)) => {
                let current = onetdns_core::SecretString::from(
                    Config::read_text(path).map_err(|error| error.to_string())?,
                );
                current.as_str() != expected
            }
            _ => false,
        };
        *self.generation.lock_recover() = generation.clone();
        if changed_during_start {
            generation
                .reload
                .store(true, std::sync::atomic::Ordering::Release);
        }
        Ok(changed_during_start)
    }

    /**
     * @brief 설정 파일을 요청 전 내용으로 되돌린다. 커밋되지 않은 변경을 이 노드에서 취소한다.
     * @param previous_slot 요청 전의 롤백용 이전 설정. 되돌린 뒤 이 값도 복원해야 설정
     *        롤백 API가 커밋되지 않은 변경을 다시 적용하지 않는다.
     */
    fn restore_text(
        &self,
        text: &str,
        previous_slot: Option<onetdns_core::SecretString>,
    ) -> Result<(), String> {
        let _write_guard = config_write_lock().lock_recover();
        let generation = self.generation.lock_recover().clone();
        let edit = |_: &str| Ok(text.to_string());
        let result = if let Some(hot_apply) = generation.hot_apply.as_ref() {
            apply_config_edit_smart_locked(
                &self.path,
                &self.prev,
                &self.applied,
                &generation.reload,
                hot_apply,
                edit,
            )
            .map(|_| ())
        } else {
            apply_config_edit_locked(&self.path, &self.prev, &generation.reload, edit)
        };
        *self.prev.lock_recover() = previous_slot;
        result
    }

    /** @brief 클러스터가 정한 명령을 적용한다. */
    fn apply_command(&self, data: &[u8]) -> Result<(), String> {
        let patch = decode_raft_command_patch(data)?;
        self.apply_patch(&patch)
    }

    /** @brief 클러스터가 정한 설정 변경을 적용한다. */
    fn apply_patch(&self, patch: &[(String, onetdns_core::json::Json)]) -> Result<(), String> {
        apply_raft_patch(self, patch)
    }
}

/** @brief 실행 중인 클러스터 노드 하나. */
struct RaftRuntime {
    /** @brief 이 노드의 신원. */
    identity: RaftRuntimeIdentity,
    /** @brief Raft 로그 항목을 적용하는 곳. */
    apply: Arc<RaftApplyContext>,
    /** @brief 노드를 조종할 핸들. */
    handle: onetdns_cluster::transport::RaftHandle,
}

/** @brief 이 프로세스의 클러스터 노드. */
static RAFT: std::sync::OnceLock<Mutex<Option<RaftRuntime>>> = std::sync::OnceLock::new();

/** @brief 클러스터 노드가 들어가는 곳. */
fn raft_slot() -> &'static Mutex<Option<RaftRuntime>> {
    RAFT.get_or_init(|| Mutex::new(None))
}

/** @brief 클러스터 노드 핸들. 돌고 있지 않으면 없다. */
pub fn raft_handle() -> Option<onetdns_cluster::transport::RaftHandle> {
    raft_slot()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
        .map(|runtime| runtime.handle.clone())
}

/** @brief 클러스터 노드를 멈춘다. */
pub(crate) fn stop_raft() {
    let runtime = {
        raft_slot()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
    };
    if let Some(runtime) = runtime {
        runtime.handle.shutdown();
    }
}

/** @brief 프로세스가 끝날 때 클러스터 노드를 멈추는 것. */
pub(crate) struct RaftProcessCleanup;

impl Drop for RaftProcessCleanup {
    /** @brief 클러스터 노드를 멈춘다. */
    fn drop(&mut self) {
        stop_raft();
    }
}

/** @brief 16진 문자열을 32바이트로. */
fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/** @brief 클러스터 노드를 시작하거나 이미 있으면 그대로 쓴다. */
pub(crate) fn ensure_raft_runtime(
    cfg: &Config,
    expected_text: Option<&str>,
    path: Option<PathBuf>,
    prev: ConfigTextSlot,
    applied: ConfigTextSlot,
    reload: Arc<std::sync::atomic::AtomicBool>,
    hot_apply: Option<HotConfigApply>,
) -> Result<(), String> {
    let listen = cfg.cluster_raft_listen.clone().ok_or(
        "Raft 고가용성이 켜져 있지만 수신 주소(`cluster_raft_listen`)가 설정되어 있지 않습니다",
    )?;
    let mut peers: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
    let mut peer_keys: std::collections::HashMap<u64, [u8; 32]> = std::collections::HashMap::new();
    let mut ids = vec![cfg.cluster_node_id];
    for p in &cfg.cluster_raft_peers {
        if let Some((id_s, rest)) = p.split_once('@') {
            if let Some((addr, pubkey)) = rest.split_once('#') {
                if let (Ok(id), Some(pk)) = (id_s.trim().parse::<u64>(), hex32(pubkey.trim())) {
                    peers.insert(id, addr.trim().to_string());
                    peer_keys.insert(id, pk);
                    ids.push(id);
                }
            }
        }
    }
    let node_seed = hex32(cfg.cluster_raft_node_key.trim()).ok_or(
        "cluster_raft_node_key에는 32바이트 Ed25519 시드를 64자리 16진수로 입력해야 합니다",
    )?;
    let state_path = path
        .as_ref()
        .map(|config_path| {
            std::path::PathBuf::from(format!(
                "{}.raft-{}.state",
                config_path.display(),
                cfg.cluster_node_id
            ))
        })
        .unwrap_or_else(|| {
            std::path::PathBuf::from(format!("onetdns.raft-{}.state", cfg.cluster_node_id))
        });
    let mut identity_peers = peers
        .iter()
        .filter_map(|(id, address)| peer_keys.get(id).map(|key| (*id, address.clone(), *key)))
        .collect::<Vec<_>>();
    identity_peers.sort_unstable_by_key(|(id, _, _)| *id);
    let identity = RaftRuntimeIdentity {
        node_id: cfg.cluster_node_id,
        listen: listen.clone(),
        peers: identity_peers,
        node_seed,
        secret_digest: Sha256::digest(cfg.cluster_raft_secret.as_bytes()).into(),
        state_path: state_path.clone(),
    };
    let generation = RaftGenerationApply { reload, hot_apply };

    {
        let slot = raft_slot().lock_recover();
        if let Some(runtime) = slot.as_ref().filter(|runtime| runtime.identity == identity) {
            let apply = runtime.apply.clone();
            drop(slot);
            let changed_during_start =
                apply.install_generation(expected_text, generation.clone())?;
            onetdns_core::info!(
                event = "raft.consensus_reused",
                node = cfg.cluster_node_id,
                changed_during_start,
                "DNS 서비스 구성을 교체하면서 기존 Raft 합의 런타임을 유지합니다"
            );
            return Ok(());
        }
    }

    let previous = { raft_slot().lock_recover().take() };
    if let Some(previous) = previous {
        previous.handle.shutdown();
    }

    let apply_context = Arc::new(RaftApplyContext::new(
        path.clone(),
        prev,
        applied,
        generation.clone(),
    ));
    let changed_during_start =
        apply_context.install_generation(expected_text, generation.clone())?;
    let node = onetdns_cluster::RaftNode::new_persistent(
        cfg.cluster_node_id,
        ids,
        onetdns_cluster::Config {
            election_base: 10,
            heartbeat: 3,
        },
        state_path.clone(),
    )
    .map_err(|error| {
        format!(
            "디스크에서 Raft 상태를 복구하지 못했습니다({}): {error}",
            state_path.display()
        )
    })?;
    let mut initial_snapshot = if let Some(snapshot) = node.snapshot() {
        RaftConfigSnapshot::decode(&snapshot.data)?
    } else {
        RaftConfigSnapshot::default()
    };
    for entry in node.applied_entries_after_snapshot() {
        if !entry.data.is_empty() {
            initial_snapshot.merge_command(&entry.data)?;
        }
    }
    let snapshot_state = Arc::new(Mutex::new(initial_snapshot));

    let apply_state = snapshot_state.clone();
    let apply_context_for_entry = apply_context.clone();
    let apply: Box<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync> = Box::new(move |data| {
        apply_context_for_entry.apply_command(data)?;
        apply_state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .merge_command(data)
    });
    let snapshot_for_create = snapshot_state.clone();
    let create_snapshot: Box<dyn Fn() -> Result<Vec<u8>, String> + Send + Sync> =
        Box::new(move || {
            snapshot_for_create
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .encode()
        });
    let install_state = snapshot_state.clone();
    let apply_context_for_snapshot = apply_context.clone();
    let install_snapshot: Box<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync> =
        Box::new(move |data| {
            let next = RaftConfigSnapshot::decode(data)?;
            apply_context_for_snapshot.apply_patch(&next.patch())?;
            *install_state
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = next;
            Ok(())
        });
    let handle = onetdns_cluster::transport::RaftServer::spawn(
        cfg.cluster_node_id,
        listen.clone(),
        peers,
        node,
        50,
        cfg.cluster_raft_secret.as_bytes().to_vec(),
        node_seed,
        peer_keys,
        apply,
        create_snapshot,
        install_snapshot,
    )
    .map_err(|error| format!("Raft 고가용성 기능을 시작하지 못했습니다: {error}"))?;
    *raft_slot().lock_recover() = Some(RaftRuntime {
        identity,
        apply: apply_context,
        handle,
    });
    onetdns_core::info!(event = "raft.consensus_started",
        node = cfg.cluster_node_id,
        listen = %listen,
        peers = cfg.cluster_raft_peers.len(),
        changed_during_start,
        "Raft 클러스터 합의를 시작합니다(리더 선출 및 로그 복제)"
    );
    Ok(())
}

/**
 * @brief 클러스터가 정할 수 있는 설정인지 확인한다.
 * @warning 노드별 설정은 거부한다. 퍼뜨리면 모든 노드가 같은 비밀을 쓰거나 서로 신원이
 *          겹친다.
 */
pub(crate) fn validate_raft_patch_scope(value: &onetdns_core::json::Json) -> Result<(), String> {
    let onetdns_core::json::Json::Obj(pairs) = value else {
        return Err("Raft로 전달하는 설정 변경 내용은 JSON 객체여야 합니다".to_string());
    };
    if let Some((key, _)) = pairs.iter().find(|(key, _)| config_keys::node_local(key)) {
        return Err(format!(
            "{key}는 노드마다 따로 두는 설정이라 Raft로 복제할 수 없습니다. 각 노드에서 별도로 설정하십시오"
        ));
    }
    Ok(())
}

/**
 * @brief 팔로워가 처리 전에 거절할 요청인지. 클러스터 공유 설정을 바꾸는 요청이 대상이다.
 * @details 설정 편집 요청은 본문의 키를 보고 판단한다. 노드별 설정만 바꾸는 편집은 팔로워도
 *          받는다. 본문을 파싱하지 못하면 여기서 거절하지 않고, 요청 처리 단계에서 본문 오류로
 *          응답하게 둔다.
 */
fn cluster_follower_must_reject(path: &str, body: &str) -> bool {
    match path {
        "/v1/block"
        | "/v1/allow"
        | "/v1/restore"
        | "/v1/services"
        | "/v1/safesearch"
        | "/v1/rewrites"
        | "/v1/filter/rules"
        | "/v1/filter/subscriptions"
        | "/v1/clients"
        | "/v1/upstreams"
        | "/v1/config/rollback" => true,
        "/v1/config/set" => match onetdns_core::json::parse(body) {
            Ok(onetdns_core::json::Json::Obj(fields)) => {
                fields.iter().any(|(key, _)| !config_keys::node_local(key))
            }
            _ => false,
        },
        "/v1/config/apply" => match onetdns_config::toml::parse(body) {
            Ok(onetdns_config::toml::Value::Table(fields)) => {
                fields.keys().any(|key| !config_keys::node_local(key))
            }
            _ => false,
        },
        _ => false,
    }
}

/** @brief 클러스터 제안을 하나씩 올리게 하는 잠금. 설정 쓰기 잠금과는 따로 둔다. */
fn cluster_proposal_lock() -> &'static Mutex<()> {
    /** @brief 제안 잠금. */
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/** @brief 클러스터 요청 처리가 실패로 끝났을 때의 응답. */
fn cluster_write_error(status: &'static str, message: String) -> onetdns_control::ApiResponse {
    (
        status,
        "application/json",
        format!("{{\"error\":{}}}", onetdns_core::json::escape(&message)),
    )
}

/** @brief 팔로워가 거절할 때 쓰는 문구. 알면 리더 번호를 알려 준다. */
fn cluster_not_leader_message(leader: Option<u64>) -> String {
    match leader {
        Some(id) => format!(
            "이 노드는 Raft 리더가 아니므로 클러스터 전체에 적용되는 설정을 바꿀 수 없습니다. 리더인 {id}번 노드의 관리 화면에서 변경하십시오"
        ),
        None => "Raft 리더를 선출하는 중이라 클러스터 전체에 적용되는 설정을 바꿀 수 없습니다. 잠시 후 다시 시도하십시오".to_string(),
    }
}

/**
 * @brief 두 설정 파일 내용을 비교해 바뀐 클러스터 공유 설정을 구한다.
 * @return 바뀐 키와 새 값. 삭제된 키의 값은 null 이다. 바뀐 것이 없으면 빈 목록이다.
 */
fn cluster_config_changes(
    before: &str,
    after: &str,
) -> Result<Vec<(String, onetdns_core::json::Json)>, String> {
    let keys: Vec<String> = changed_config_keys(before, after)?
        .into_iter()
        .filter(|key| !config_keys::node_local(key))
        .collect();
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let parsed = onetdns_config::toml::parse(after)?;
    keys.into_iter()
        .map(|key| {
            let value = match parsed.get(&key) {
                Some(value) => toml_value_to_json(value)?,
                None => onetdns_core::json::Json::Null,
            };
            Ok((key, value))
        })
        .collect()
}

/**
 * @brief 상태를 바꾸는 관리 요청을 Raft 합의를 거쳐 처리한다.
 * @details 리더는 요청을 먼저 처리하고, 클러스터 공유 설정이 바뀌었으면 바뀐 값을 제안한다.
 *          제안이 실패하면 설정 파일을 요청 전 상태로 되돌리고 실패로 응답한다. 먼저 처리하는
 *          이유는 요청마다 설정 파일을 고치는 방식이 달라서, 처리 전후 파일 내용을 비교해야
 *          모든 요청을 한 경로로 다룰 수 있기 때문이다.
 *          팔로워는 공유 설정을 바꾸는 요청을 처리 전에 거절한다. 사전에 걸러지지 않은 요청이
 *          공유 설정을 바꿨다면 되돌리고 거절한다. 팔로워에서 바꾼 값은 다음 커밋에 덮어써져
 *          노드 간 설정이 어긋나기 때문이다.
 * @warning 제안은 설정 쓰기 잠금을 잡지 않은 채 커밋을 기다린다. 커밋된 항목을 적용하는 쪽이
 *          그 잠금을 잡기 때문이다. 제안 간 순서는 별도의 제안 잠금으로 보장한다.
 */
pub(crate) fn cluster_routed_write(
    method: &str,
    path: &str,
    body: &str,
    dispatch: &mut dyn FnMut() -> onetdns_control::ApiResponse,
) -> onetdns_control::ApiResponse {
    let runtime = raft_slot()
        .lock_recover()
        .as_ref()
        .map(|runtime| (runtime.handle.clone(), runtime.apply.clone()));
    let Some((handle, context)) = runtime else {
        return dispatch();
    };
    let Some(config_path) = context.path.clone() else {
        return dispatch();
    };
    let leader = handle.is_leader();
    if !leader && cluster_follower_must_reject(path, body) {
        return cluster_write_error("409 Conflict", cluster_not_leader_message(handle.leader()));
    }

    let _proposal = cluster_proposal_lock().lock_recover();
    let read = |when: &str| {
        Config::read_text(&config_path)
            .map(onetdns_core::SecretString::from)
            .map_err(|error| format!("{when} 설정 파일을 읽지 못했습니다: {error}"))
    };
    let before = match read("요청을 처리하기 전에") {
        Ok(text) => text,
        Err(error) => return cluster_write_error("503 Service Unavailable", error),
    };
    let previous_slot = context.prev.lock_recover().clone();
    let response = dispatch();
    if !response.0.starts_with('2') {
        return response;
    }
    let changes =
        read("요청을 처리한 뒤").and_then(|after| cluster_config_changes(&before, &after));
    let (status, message) = match changes {
        Ok(changes) if changes.is_empty() => return response,
        Ok(_) if !leader => ("409 Conflict", cluster_not_leader_message(handle.leader())),
        Ok(changes) => {
            let command = onetdns_core::json::Json::Obj(vec![(
                "patch".to_string(),
                onetdns_core::json::Json::Obj(changes),
            )])
            .to_text();
            /*
             * 확인하지 못한 경우에도 이 노드의 변경은 되돌린다. 나중에 커밋되면 적용 쪽이 이
             * 노드에도 다시 적어 모든 노드가 같아지고, 폐기되면 되돌린 상태가 맞다.
             */
            match handle.propose(command.into_bytes()) {
                Ok(_) => return response,
                Err(onetdns_cluster::transport::ProposalError::Undetermined(error)) => (
                    "503 Service Unavailable",
                    format!("Raft 클러스터가 이 변경을 합의했는지 아직 확인하지 못해 이 노드에서는 되돌렸습니다({error}). 과반의 노드가 연결되어 합의되면 그때 모든 노드에 적용되고, 합의되지 않으면 적용되지 않습니다. 잠시 뒤 설정을 다시 확인하십시오"),
                ),
                Err(error) => (
                    "503 Service Unavailable",
                    format!("변경 내용이 Raft 클러스터에 합의되지 않아 이 노드의 변경도 되돌렸습니다: {error}"),
                ),
            }
        }
        Err(error) => (
            "503 Service Unavailable",
            format!("변경 내용을 Raft 클러스터에 올릴 수 없어 되돌렸습니다: {error}"),
        ),
    };
    let message = match context.restore_text(&before, previous_slot) {
        Ok(()) => message,
        Err(error) => format!("{message}. 이 노드의 설정 파일을 되돌리지도 못했습니다: {error}"),
    };
    onetdns_core::warn!(
        event = "raft.write_rejected",
        method = %method,
        path = %path,
        reason = %message,
        "Raft 에 커밋되지 않은 관리 요청을 되돌렸습니다"
    );
    cluster_write_error(status, message)
}

/** @brief 클러스터 설정 스냅숏의 매직 바이트. */
const RAFT_CONFIG_SNAPSHOT_MAGIC: &[u8; 12] = b"ONETCFGSNAP1";

/** @brief 스냅숏에 담을 설정 항목 수 상한. */
const MAX_RAFT_SNAPSHOT_KEYS: usize = 1_024;

#[derive(Default)]
/** @brief 클러스터가 합의한 설정 스냅숏. */
struct RaftConfigSnapshot {
    /** @brief 클러스터가 합의한 설정 항목들. */
    values: std::collections::BTreeMap<String, onetdns_core::json::Json>,
}

impl RaftConfigSnapshot {
    /** @brief 로그 항목 하나를 스냅숏에 반영한다. 나중 것이 이긴다. */
    fn merge_command(&mut self, data: &[u8]) -> Result<(), String> {
        let patch = decode_raft_command_patch(data)?;
        for (key, value) in patch {
            self.values.insert(key, value);
        }
        Ok(())
    }

    /** @brief 스냅숏을 바이트로 인코딩한다. */
    fn encode(&self) -> Result<Vec<u8>, String> {
        if self.values.is_empty() || self.values.len() > MAX_RAFT_SNAPSHOT_KEYS {
            return Err("Raft 설정 스냅샷 항목 수가 허용 범위를 벗어났습니다".into());
        }
        let mut out = Vec::new();
        out.extend_from_slice(RAFT_CONFIG_SNAPSHOT_MAGIC);
        out.extend_from_slice(&(self.values.len() as u32).to_be_bytes());
        for (key, value) in &self.values {
            if key.is_empty() || key.len() > 128 || key.len() > u16::MAX as usize {
                return Err("Raft 설정 스냅샷 키가 올바르지 않습니다".into());
            }
            out.extend_from_slice(&(key.len() as u16).to_be_bytes());
            out.extend_from_slice(key.as_bytes());
            encode_raft_snapshot_value(value, &mut out, 0)?;
            if out.len() > onetdns_cluster::raft::MAX_SNAPSHOT_BYTES {
                return Err("Raft 설정 스냅샷이 허용 크기를 넘었습니다".into());
            }
        }
        Ok(out)
    }

    /** @brief 바이트를 스냅숏으로 디코딩한다. */
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > onetdns_cluster::raft::MAX_SNAPSHOT_BYTES
            || bytes.get(..RAFT_CONFIG_SNAPSHOT_MAGIC.len())
                != Some(RAFT_CONFIG_SNAPSHOT_MAGIC.as_slice())
        {
            return Err("Raft 설정 스냅샷 헤더가 올바르지 않습니다".into());
        }
        let mut pos = RAFT_CONFIG_SNAPSHOT_MAGIC.len();
        let count = raft_snapshot_take_u32(bytes, &mut pos)? as usize;
        if count == 0 || count > MAX_RAFT_SNAPSHOT_KEYS {
            return Err("Raft 설정 스냅샷 항목 수가 허용 범위를 벗어났습니다".into());
        }
        let mut values = std::collections::BTreeMap::new();
        for _ in 0..count {
            let key_len = raft_snapshot_take_u16(bytes, &mut pos)? as usize;
            if key_len == 0 || key_len > 128 {
                return Err("Raft 설정 스냅샷 키 길이가 올바르지 않습니다".into());
            }
            let key = std::str::from_utf8(raft_snapshot_take(bytes, &mut pos, key_len)?)
                .map_err(|_| "Raft 설정 스냅샷 키가 UTF-8이 아닙니다")?
                .to_string();
            let value = decode_raft_snapshot_value(bytes, &mut pos, 0)?;
            if values.insert(key, value).is_some() {
                return Err("Raft 설정 스냅샷에 중복 키가 있습니다".into());
            }
        }
        if pos != bytes.len() {
            return Err("Raft 설정 스냅샷 끝에 불필요한 데이터가 있습니다".into());
        }
        let patch = onetdns_core::json::Json::Obj(
            values
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        );
        validate_raft_patch_scope(&patch)?;
        for value in values.values() {
            if !matches!(value, onetdns_core::json::Json::Null) {
                json_to_raft_toml_literal(value, 0)?;
            }
        }
        Ok(Self { values })
    }

    /** @brief 스냅숏을 설정 변경 목록으로 바꾼다. */
    fn patch(&self) -> Vec<(String, onetdns_core::json::Json)> {
        self.values
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }
}

/**
 * @brief 값 하나를 스냅숏에 담을 바이트로 인코딩한다.
 * @details 맨 위의 null 은 그 항목을 지웠다는 합의라서 담는다. 배열과 테이블은 설정 파일에
 *          있는 모양 그대로 중첩을 허용하되 깊이를 제한한다.
 */
fn encode_raft_snapshot_value(
    value: &onetdns_core::json::Json,
    out: &mut Vec<u8>,
    depth: usize,
) -> Result<(), String> {
    use onetdns_core::json::Json;
    if depth > MAX_RAFT_VALUE_DEPTH {
        return Err("Raft 설정 스냅샷 값의 중첩이 너무 깊습니다".into());
    }
    match value {
        Json::Null if depth == 0 => out.push(0),
        Json::Bool(false) => out.push(1),
        Json::Bool(true) => out.push(2),
        Json::Num(number) if number.is_finite() => {
            out.push(3);
            out.extend_from_slice(&number.to_bits().to_be_bytes());
        }
        Json::Str(text) => {
            out.push(4);
            let len =
                u32::try_from(text.len()).map_err(|_| "Raft 설정 스냅샷 문자열이 너무 큽니다")?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(text.as_bytes());
        }
        Json::Arr(items) => {
            out.push(5);
            let count =
                u32::try_from(items.len()).map_err(|_| "Raft 설정 스냅샷 배열이 너무 큽니다")?;
            out.extend_from_slice(&count.to_be_bytes());
            for item in items {
                encode_raft_snapshot_value(item, out, depth + 1)?;
            }
        }
        Json::Obj(fields) => {
            out.push(6);
            let count =
                u32::try_from(fields.len()).map_err(|_| "Raft 설정 스냅샷 테이블이 너무 큽니다")?;
            out.extend_from_slice(&count.to_be_bytes());
            for (key, value) in fields {
                let len = u16::try_from(key.len())
                    .map_err(|_| "Raft 설정 스냅샷 테이블의 키가 너무 깁니다")?;
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(key.as_bytes());
                encode_raft_snapshot_value(value, out, depth + 1)?;
            }
        }
        _ => return Err("Raft 설정 스냅샷 값 형식이 지원되지 않습니다".into()),
    }
    Ok(())
}

/** @brief 스냅숏의 바이트를 값으로 디코딩한다. */
fn decode_raft_snapshot_value(
    bytes: &[u8],
    pos: &mut usize,
    depth: usize,
) -> Result<onetdns_core::json::Json, String> {
    use onetdns_core::json::Json;
    /** @brief 배열이나 테이블 하나가 가질 수 있는 항목 수 상한. */
    const MAX_ITEMS: usize = 100_000;
    if depth > MAX_RAFT_VALUE_DEPTH {
        return Err("Raft 설정 스냅샷 값의 중첩이 너무 깊습니다".into());
    }
    let tag = *raft_snapshot_take(bytes, pos, 1)?
        .first()
        .ok_or("Raft 설정 스냅샷 값 태그가 없습니다")?;
    match tag {
        0 if depth == 0 => Ok(Json::Null),
        1 => Ok(Json::Bool(false)),
        2 => Ok(Json::Bool(true)),
        3 => {
            let bits = u64::from_be_bytes(
                raft_snapshot_take(bytes, pos, 8)?
                    .try_into()
                    .map_err(|_| "Raft 설정 스냅샷의 숫자 데이터를 8바이트로 읽을 수 없습니다")?,
            );
            let number = f64::from_bits(bits);
            number
                .is_finite()
                .then_some(Json::Num(number))
                .ok_or_else(|| "Raft 설정 스냅샷 숫자가 유한하지 않습니다".into())
        }
        4 => {
            let len = raft_snapshot_take_u32(bytes, pos)? as usize;
            let text = std::str::from_utf8(raft_snapshot_take(bytes, pos, len)?)
                .map_err(|_| "Raft 설정 스냅샷 문자열이 UTF-8이 아닙니다")?;
            Ok(Json::Str(text.to_string()))
        }
        5 => {
            let count = raft_snapshot_take_u32(bytes, pos)? as usize;
            if count > MAX_ITEMS {
                return Err("Raft 설정 스냅샷 배열 항목이 너무 많습니다".into());
            }
            let mut items = Vec::with_capacity(count.min(1_024));
            for _ in 0..count {
                items.push(decode_raft_snapshot_value(bytes, pos, depth + 1)?);
            }
            Ok(Json::Arr(items))
        }
        6 => {
            let count = raft_snapshot_take_u32(bytes, pos)? as usize;
            if count > MAX_ITEMS {
                return Err("Raft 설정 스냅샷 테이블 항목이 너무 많습니다".into());
            }
            let mut fields: Vec<(String, Json)> = Vec::with_capacity(count.min(1_024));
            for _ in 0..count {
                let len = raft_snapshot_take_u16(bytes, pos)? as usize;
                let key = std::str::from_utf8(raft_snapshot_take(bytes, pos, len)?)
                    .map_err(|_| "Raft 설정 스냅샷 테이블의 키가 UTF-8이 아닙니다")?
                    .to_string();
                if fields.iter().any(|(existing, _)| *existing == key) {
                    return Err("Raft 설정 스냅샷 테이블에 중복 키가 있습니다".into());
                }
                let value = decode_raft_snapshot_value(bytes, pos, depth + 1)?;
                fields.push((key, value));
            }
            Ok(Json::Obj(fields))
        }
        _ => Err("Raft 설정 스냅샷 값 태그가 올바르지 않습니다".into()),
    }
}

/** @brief 바이트를 이만큼 잘라 낸다. */
fn raft_snapshot_take<'a>(
    bytes: &'a [u8],
    pos: &mut usize,
    len: usize,
) -> Result<&'a [u8], String> {
    let end = pos
        .checked_add(len)
        .ok_or("Raft 설정 스냅샷 위치가 범위를 넘었습니다")?;
    let value = bytes
        .get(*pos..end)
        .ok_or("Raft 설정 스냅샷 데이터가 중간에서 잘렸습니다")?;
    *pos = end;
    Ok(value)
}

/** @brief 16비트 수를 잘라 낸다. */
fn raft_snapshot_take_u16(bytes: &[u8], pos: &mut usize) -> Result<u16, String> {
    Ok(u16::from_be_bytes(
        raft_snapshot_take(bytes, pos, 2)?
            .try_into()
            .map_err(|_| "Raft 설정 스냅샷의 16비트 정수 데이터를 읽을 수 없습니다")?,
    ))
}

/** @brief 32비트 수를 잘라 낸다. */
fn raft_snapshot_take_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, String> {
    Ok(u32::from_be_bytes(
        raft_snapshot_take(bytes, pos, 4)?
            .try_into()
            .map_err(|_| "Raft 설정 스냅샷의 32비트 정수 데이터를 읽을 수 없습니다")?,
    ))
}

/** @brief 클러스터에 올릴 제안을 읽는다. 형식이 다르면 거부한다. */
pub(crate) fn parse_cluster_proposal(body: &str) -> Result<onetdns_core::json::Json, String> {
    let json = onetdns_core::json::parse(body)
        .map_err(|error| format!("JSON 요청 본문을 해석할 수 없습니다: {error}"))?;
    let onetdns_core::json::Json::Obj(fields) = json else {
        return Err("Raft 설정 변경 요청은 patch 객체 하나만 포함해야 합니다".into());
    };
    if fields.len() != 1 || fields[0].0 != "patch" {
        return Err("Raft 설정 변경 요청은 patch 객체 하나만 포함해야 합니다".into());
    }
    let patch = fields[0].1.clone();
    let onetdns_core::json::Json::Obj(entries) = &patch else {
        return Err("Raft 설정 변경 요청의 patch는 객체여야 합니다".into());
    };
    if entries.is_empty() || entries.len() > 128 {
        return Err("Raft 설정 변경 항목 수가 허용 범위를 벗어났습니다".into());
    }
    Ok(patch)
}

/** @brief Raft 로그 항목을 설정 변경 목록으로 바꾼다. */
fn decode_raft_command_patch(
    data: &[u8],
) -> Result<Vec<(String, onetdns_core::json::Json)>, String> {
    let text = std::str::from_utf8(data)
        .map_err(|error| format!("Raft 명령이 올바른 UTF-8 문자열이 아닙니다: {error}"))?;
    let json = onetdns_core::json::parse(text)
        .map_err(|error| format!("Raft 명령 JSON 요청 본문이 올바르지 않습니다: {error}"))?;
    let onetdns_core::json::Json::Obj(fields) = &json else {
        return Err("Raft 명령은 patch 객체 하나만 포함해야 합니다".into());
    };
    if fields.len() != 1 || fields[0].0 != "patch" {
        return Err("Raft 명령은 patch 객체 하나만 포함해야 합니다".into());
    }
    let patch_value = json
        .get("patch")
        .ok_or_else(|| "Raft 설정 변경 요청에 patch 객체가 없습니다".to_string())?;
    validate_raft_patch_scope(patch_value)?;
    let onetdns_core::json::Json::Obj(patch) = patch_value else {
        return Err("Raft 설정 변경 요청에 patch 객체가 없습니다".into());
    };
    if patch.is_empty() || patch.len() > 128 {
        return Err("Raft 설정 변경 항목 수가 허용 범위를 벗어났습니다".into());
    }
    let mut patch = patch.clone();
    materialize_mode_acl_patch(&mut patch)?;
    Ok(patch)
}

/** @brief 클러스터가 정한 설정 변경을 실제로 적용한다. */
fn apply_raft_patch(
    context: &RaftApplyContext,
    patch: &[(String, onetdns_core::json::Json)],
) -> Result<(), String> {
    if patch.is_empty() || patch.len() > MAX_RAFT_SNAPSHOT_KEYS {
        return Err("Raft 설정 상태 항목 수가 허용 범위를 벗어났습니다".into());
    }
    validate_raft_patch_scope(&onetdns_core::json::Json::Obj(patch.to_vec()))?;
    let edit = |text: &str| {
        let mut output = text.to_string();
        for (key, value) in patch {
            if key.is_empty() || key.len() > 128 {
                return Err("Raft 설정 항목 이름의 길이가 허용 범위를 벗어났습니다".into());
            }
            output = match value {
                /* null 은 항목을 지우라는 합의다. 빈 값으로 적으면 기본값으로 돌아가지 않는다. */
                onetdns_core::json::Json::Null => remove_config_key(&output, key)?,
                value => rewrite_config_kv(&output, key, &json_to_raft_toml_literal(value, 0)?)?,
            };
        }
        Ok(output)
    };

    let _write_guard = config_write_lock().lock_recover();
    let generation = context.generation.lock_recover().clone();
    let mode = if let Some(hot_apply) = generation.hot_apply.as_ref() {
        apply_config_edit_smart_locked(
            &context.path,
            &context.prev,
            &context.applied,
            &generation.reload,
            hot_apply,
            edit,
        )?
        .mode
    } else {
        apply_config_edit_locked(&context.path, &context.prev, &generation.reload, edit)?;
        ConfigApplyMode::ServiceRestart
    };
    onetdns_core::info!(
        event = "raft.config_applied",
        keys = patch.len(),
        mode = mode.as_str(),
        "Raft로 복제된 설정을 적용했습니다"
    );
    Ok(())
}

/**
 * @brief 클러스터 상태 JSON에 이 노드의 Raft 신원을 붙인다.
 * @details 다른 노드의 cluster_raft_peers 에 적을 공개 키와 그대로 붙여 넣을 항목을 알려
 *          준다. 서명 키만 있으면 Raft를 켜기 전에도 보여 준다. 노드를 연결하려면 켜기 전에
 *          서로의 공개 키를 알아야 하기 때문이다. 서명 키가 없거나 형식이 틀리면 null 이다.
 */
pub(crate) fn with_raft_identity(status: &str, config: &Config) -> String {
    use onetdns_core::json::Json;
    let public_key = hex32(config.cluster_raft_node_key.trim())
        .map(|seed| hex_lower(&onetdns_cluster::transport::node_public_key(&seed)));
    let peer_entry = match (&public_key, &config.cluster_raft_listen) {
        (Some(key), Some(listen)) => {
            Json::Str(format!("{}@{listen}#{key}", config.cluster_node_id))
        }
        _ => Json::Null,
    };
    let identity = Json::Obj(vec![
        ("node_id".into(), Json::Num(config.cluster_node_id as f64)),
        (
            "public_key".into(),
            public_key.map_or(Json::Null, Json::Str),
        ),
        ("peer_entry".into(), peer_entry),
    ]);
    match onetdns_core::json::parse(status) {
        Ok(Json::Obj(mut fields)) => {
            fields.push(("identity".into(), identity));
            Json::Obj(fields).to_text()
        }
        _ => status.to_string(),
    }
}

/** @brief 바이트를 소문자 16진 문자열로. */
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/** @brief 클러스터 없이 실행 중인 상태를 JSON으로. */
pub(crate) fn standalone_cluster_status_json(backend: &str, listeners: usize) -> String {
    format!(
        "{{\"self\":{{\"id\":null,\"role\":\"standalone\",\"backend\":{},\"listeners\":{listeners},\"leader\":null,\"term\":null,\"commit_index\":null,\"last_applied\":null,\"last_index\":null,\"snapshot_index\":null,\"retained_log_entries\":null,\"fatal\":null,\"healthy\":true}},\"peers\":[]}}",
        onetdns_core::json::escape(backend)
    )
}

/** @brief 클러스터 상태를 JSON으로. */
pub(crate) fn peer_cluster_status_json(
    peers: &[String],
    backend: &str,
    listeners: usize,
    resolver: &http::HostResolver,
) -> String {
    let probes: Vec<_> = peers
        .iter()
        .map(|url| {
            let probe_url = url.clone();
            let resolver = resolver.clone();
            let spawned = std::thread::Builder::new()
                .name("cluster-probe".into())
                .spawn(move || {
                    let base = probe_url.trim_end_matches('/');
                    let started = std::time::Instant::now();
                    let healthy = http::get(&format!("{base}/healthz"))
                        .timeout(Duration::from_secs(2))
                        .resolver(resolver)
                        .call()
                        .ok()
                        .and_then(|r| r.into_string().ok())
                        .map(|b| b.trim() == "ok")
                        .unwrap_or(false);
                    (healthy, started.elapsed())
                });
            if let Err(error) = &spawned {
                onetdns_core::warn!(
                    event = "cluster.peer_probe_spawn_failed",
                    peer = %url,
                    error = %error,
                    "상대 노드 상태 조사 스레드를 만들지 못했습니다"
                );
            }
            (url, spawned.ok())
        })
        .collect();

    let items: Vec<String> = probes
        .into_iter()
        .map(|(url, handle)| {

            let outcome = handle.and_then(|handle| handle.join().ok());
            let healthy = outcome.map(|(healthy, _)| healthy).unwrap_or(false);
            let rtt = match outcome {
                Some((true, elapsed)) => elapsed.as_millis().to_string(),
                _ => "null".to_string(),
            };
            format!(
                "{{\"id\":null,\"url\":{},\"healthy\":{healthy},\"role\":\"member\",\"rtt_ms\":{rtt}}}",
                onetdns_core::json::escape(url)
            )
        })
        .collect();
    format!(
        "{{\"self\":{{\"id\":null,\"role\":\"member\",\"backend\":{},\"listeners\":{listeners},\"leader\":null,\"term\":null,\"commit_index\":null,\"last_applied\":null,\"last_index\":null,\"snapshot_index\":null,\"retained_log_entries\":null,\"fatal\":null,\"healthy\":true}},\"peers\":[{}]}}",
        onetdns_core::json::escape(backend),
        items.join(",")
    )
}

/**
 * @brief 하루마다 서명 영역의 RRSIG를 다시 서명하는 스레드를 시작한다.
 * @details 서명 키는 돌 때마다 공유 핸들에서 읽는다. 키 교체나 설정 변경 뒤에도 이전 키로
 *          서명하지 않는다.
 */
pub(crate) fn spawn_resign_timer(
    zone_signers: SharedZoneSigners,
    store: Arc<onetdns_core::ArcSwap<onetdns_authority::ZoneStore>>,
    journal: Arc<Mutex<std::collections::HashMap<Vec<u8>, native::ZoneJournal>>>,
    zone_files: Vec<(onetdns_proto::Name, std::path::PathBuf)>,
    notify: NotifySender,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<Option<std::thread::JoinHandle<()>>> {
    std::thread::Builder::new()
        .name("dnssec-resign".into())
        .spawn(move || loop {
            if sleep_or_shutdown(86_400, &shutdown) {
                break;
            }
            let signers = zone_signers.load();
            for (origin, ctx) in signers.iter() {
                let zone = {
                    let cur = store.load();
                    cur.zones()
                        .iter()
                        .find(|z| z.origin().eq_ignore_case(origin))
                        .cloned()
                };
                let Some(zone) = zone else {
                    continue;
                };
                let path = zone_files
                    .iter()
                    .find(|(candidate, _)| candidate.eq_ignore_case(origin))
                    .map(|(_, path)| path.as_path());
                if let Err(error) = apply_zone_mutation(
                    &store,
                    zone,
                    std::slice::from_ref(&(origin.clone(), ctx.clone())),
                    &journal,
                    path,
                    &notify,
                    "dnssec resign",
                ) {
                    onetdns_core::error!(event = "dnssec.resign_failed", zone = %origin.to_ascii_lower(), %error, "DNSSEC 재서명에 실패해 기존 서명을 유지합니다");
                } else {
                    onetdns_core::info!(event = "dnssec.resigned", zone = %origin.to_ascii_lower(), "RRSIG를 다시 서명하고 영역 일련번호를 갱신했습니다");
                }
            }
        })
        .map(Some)
}

#[cfg(test)]
/** @brief Raft 설정 스냅숏 인코딩과 클러스터 쓰기 경로. */
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use onetdns_config::Config;

    use crate::config_apply::HotConfigApply;
    use crate::config_edit::{json_to_raft_toml_literal, rewrite_config_kv, MAX_RAFT_VALUE_DEPTH};
    use crate::unix_now;

    #[test]
    /** @brief 클러스터로 비밀을 퍼뜨리지 못하는지. 퍼뜨리면 모든 노드가 같은 키를 쓴다. */
    fn raft_config_patch_rejects_secret_material() {
        for key in [
            "cluster_raft_secret",
            "control_token",
            "control_admin_tokens",
            "control_readonly_tokens",
            "tsig_keys",
            "users",
            "zones_etcd_password",
            "zones_postgres",
            "zones_mysql",
        ] {
            let patch =
                onetdns_core::json::parse(&format!(r#"{{"{key}":"secret"}}"#)).expect("valid JSON");
            assert!(validate_raft_patch_scope(&patch).is_err(), "{key}");
        }
        let safe = onetdns_core::json::parse(r#"{"cache_size":4096}"#).unwrap();
        assert!(validate_raft_patch_scope(&safe).is_ok());
    }

    #[test]
    /** @brief 노드마다 달라야 하는 설정을 퍼뜨리지 못하는지. */
    fn raft_config_patch_rejects_node_local_identity() {
        for key in [
            "cluster_node_id",
            "cluster_raft_listen",
            "cluster_raft_peers",
            "cluster_raft_node_key",
        ] {
            let patch = onetdns_core::json::Json::Obj(vec![(
                key.to_string(),
                onetdns_core::json::Json::Str("replacement".into()),
            )]);
            assert!(validate_raft_patch_scope(&patch).is_err(), "{key}");
        }
    }

    #[test]
    /** @brief 설정 스냅숏이 형을 지키며 작게 담기고, 나중 것이 이기는지. */
    fn raft_config_snapshot_is_compact_typed_and_last_write_wins() {
        let mut state = RaftConfigSnapshot::default();
        state
            .merge_command(br#"{"patch":{"cache_size":1024,"mode":"personal"}}"#)
            .unwrap();
        state
            .merge_command(
                br#"{"patch":{"cache_size":4096,"blocklist_urls":["https://example.test/a"]}}"#,
            )
            .unwrap();

        let encoded = state.encode().unwrap();
        assert!(encoded.len() < 512, "최신 값만 보유해 로그보다 작아야 함");
        let decoded = RaftConfigSnapshot::decode(&encoded).unwrap();
        assert_eq!(
            decoded.values.get("cache_size"),
            Some(&onetdns_core::json::Json::Num(4096.0))
        );
        assert!(decoded.values.contains_key("mode"));
        assert!(decoded.values.contains_key("acl_allow"));
        assert!(decoded.values.contains_key("blocklist_urls"));
        assert_eq!(
            decoded.encode().unwrap(),
            encoded,
            "정렬된 canonical 인코딩"
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert!(RaftConfigSnapshot::decode(&trailing).is_err());
    }

    /** @brief 테이블 배열과 노드별 설정이 섞인 설정 파일. 클러스터 복제 테스트가 함께 쓴다. */
    const CLUSTER_FIXTURE: &str = "listen = [\"127.0.0.1:53\"]\ncontrol_listen = \"127.0.0.1:8080\"\nblock_rules = [\"ads.example\"]\ncache_size = 4096\nsafe_browsing = true\n\n[[clients]]\nname = \"kid \\\"room\\\"\"\nids = [\"192.0.2.0/24\"]\nblock = [\"games.example\"]\nsafe_search = true\n\n[[local_zones]]\nname = \"lan\"\nkind = \"static\"\nrecords = [\"nas.lan 192.0.2.10\", \"lan 192.0.2.1\"]\n\n[[rewrites]]\ndomain = \"rw.example\"\nanswer = \"192.0.2.53\"\n";

    #[test]
    /**
     * @brief 공유 설정이 로그 항목과 스냅숏을 거쳐 다른 노드에 같은 값으로 기록되는지.
     * @details 테이블 배열은 인라인 테이블로 기록되므로 파일 모양은 달라지지만 파싱한 값은 같아야 한다.
     *          노드별 설정은 옮겨지지 않고 받는 노드의 값이 남아야 한다.
     */
    fn cluster_changes_replay_to_identical_values_on_another_node() {
        let changes = cluster_config_changes("", CLUSTER_FIXTURE).unwrap();
        let keys: Vec<&str> = changes.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "block_rules",
                "cache_size",
                "clients",
                "local_zones",
                "rewrites",
                "safe_browsing"
            ]
        );

        let command = onetdns_core::json::Json::Obj(vec![(
            "patch".to_string(),
            onetdns_core::json::Json::Obj(changes),
        )])
        .to_text();
        let patch = decode_raft_command_patch(command.as_bytes()).unwrap();
        let mut snapshot = RaftConfigSnapshot::default();
        snapshot.merge_command(command.as_bytes()).unwrap();
        let restored = RaftConfigSnapshot::decode(&snapshot.encode().unwrap()).unwrap();
        assert_eq!(restored.patch(), snapshot.patch());

        let follower = "listen = [\"127.0.0.1:5353\"]\ncontrol_listen = \"127.0.0.1:9090\"\n";
        let mut replayed = follower.to_string();
        for (key, value) in &patch {
            replayed = rewrite_config_kv(
                &replayed,
                key,
                &json_to_raft_toml_literal(value, 0).unwrap(),
            )
            .unwrap();
        }
        Config::from_toml_str(&replayed).unwrap();
        assert!(cluster_config_changes(CLUSTER_FIXTURE, &replayed)
            .unwrap()
            .is_empty());
        let replayed = onetdns_config::toml::parse(&replayed).unwrap();
        assert_eq!(
            replayed
                .get("listen")
                .and_then(|v| v.as_array())
                .map(|v| v.len()),
            Some(1)
        );
        assert_eq!(
            replayed.get("control_listen").and_then(|v| v.as_str()),
            Some("127.0.0.1:9090")
        );
    }

    #[test]
    /** @brief 지운 설정이 null 로 합의되고, 받는 노드에서도 지워지는지. */
    fn cluster_changes_carry_removed_keys_as_null() {
        let after = CLUSTER_FIXTURE.replace("safe_browsing = true\n", "");
        let changes = cluster_config_changes(CLUSTER_FIXTURE, &after).unwrap();
        assert_eq!(
            changes,
            vec![("safe_browsing".to_string(), onetdns_core::json::Json::Null)]
        );
        let mut snapshot = RaftConfigSnapshot::default();
        snapshot
            .merge_command(br#"{"patch":{"safe_browsing":null}}"#)
            .unwrap();
        let restored = RaftConfigSnapshot::decode(&snapshot.encode().unwrap()).unwrap();
        assert_eq!(
            restored.values.get("safe_browsing"),
            Some(&onetdns_core::json::Json::Null)
        );
    }

    #[test]
    /** @brief 스냅숏이 null 을 값 안에 두거나 한도보다 깊은 값을 받지 않는지. */
    fn raft_snapshot_rejects_nested_null_and_excessive_depth() {
        use onetdns_core::json::Json;
        let mut out = Vec::new();
        assert!(encode_raft_snapshot_value(&Json::Arr(vec![Json::Null]), &mut out, 0).is_err());
        let mut deep = Json::Bool(true);
        for _ in 0..=MAX_RAFT_VALUE_DEPTH {
            deep = Json::Arr(vec![deep]);
        }
        assert!(encode_raft_snapshot_value(&deep, &mut Vec::new(), 0).is_err());
        assert!(json_to_raft_toml_literal(&deep, 0).is_err());

        let mut bytes = Vec::new();
        for _ in 0..=MAX_RAFT_VALUE_DEPTH {
            bytes.push(5);
            bytes.extend_from_slice(&1u32.to_be_bytes());
        }
        bytes.push(2);
        assert!(decode_raft_snapshot_value(&bytes, &mut 0, 0).is_err());
    }

    #[test]
    /** @brief 팔로워가 노드별 설정 편집만 받고 클러스터 설정 편집은 처리 전에 거절하는지. */
    fn cluster_follower_rejects_only_shared_config_writes() {
        assert!(cluster_follower_must_reject("/v1/block", ""));
        assert!(cluster_follower_must_reject(
            "/v1/config/set",
            r#"{"listen":["127.0.0.1:53"],"cache_size":1}"#
        ));
        assert!(!cluster_follower_must_reject(
            "/v1/config/set",
            r#"{"listen":["127.0.0.1:53"]}"#
        ));
        assert!(cluster_follower_must_reject(
            "/v1/config/apply",
            "[[clients]]\nname = \"a\"\n"
        ));
        assert!(!cluster_follower_must_reject(
            "/v1/config/apply",
            "tls_cert = \"a.pem\"\n"
        ));
        assert!(!cluster_follower_must_reject("/v1/cache/flush", ""));
        assert!(!cluster_follower_must_reject(
            "/v1/filter/subscriptions/refresh",
            ""
        ));
    }

    #[test]
    /** @brief 서명 키에서 구한 공개 키와 피어 항목이 상태 JSON에 담기는지. */
    fn cluster_status_shows_the_node_public_key_and_peer_entry() {
        let mut config = Config::default();
        config.cluster_node_id = 2;
        config.cluster_raft_listen = Some("10.0.0.2:7100".into());
        /* Ed25519 표준 테스트 벡터의 첫 번째 시드와 공개 키다. */
        config.cluster_raft_node_key =
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60".into();
        let status = with_raft_identity(&standalone_cluster_status_json("forward", 1), &config);
        let json = onetdns_core::json::parse(&status).unwrap();
        let identity = json.get("identity").unwrap();
        let key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        assert_eq!(
            identity.get("public_key").and_then(|v| v.as_str()),
            Some(key)
        );
        assert_eq!(
            identity.get("peer_entry").and_then(|v| v.as_str()),
            Some(format!("2@10.0.0.2:7100#{key}").as_str())
        );
        assert!(json.get("self").is_some());

        config.cluster_raft_node_key = "not-hex".into();
        let status = with_raft_identity(&standalone_cluster_status_json("forward", 1), &config);
        let json = onetdns_core::json::parse(&status).unwrap();
        assert_eq!(
            json.get("identity").and_then(|v| v.get("public_key")),
            Some(&onetdns_core::json::Json::Null)
        );
    }

    #[test]
    /** @brief 지금 형식의 제안만 받는지. */
    fn cluster_proposal_accepts_only_the_current_patch_envelope() {
        assert!(parse_cluster_proposal(r#"{"patch":{"cache_size":4096}}"#).is_ok());
        for invalid in [
            r#"{"cache_size":4096}"#,
            r#"{"op":"config_set","patch":{"cache_size":4096}}"#,
            r#"{"patch":{}}"#,
            r#"{"patch":[],"extra":true}"#,
            r#"{"patch":{"cache_size":4096},"extra":true}"#,
        ] {
            assert!(parse_cluster_proposal(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    /** @brief 클러스터가 정한 설정도 교체로 반영되는지. */
    fn raft_config_patch_uses_hot_apply_without_restart() {
        let file_path = std::env::temp_dir().join(format!(
            "onetdns-raft-hot-{}-{}.toml",
            std::process::id(),
            unix_now()
        ));
        std::fs::write(&file_path, "blocked_response_ttl = 10\n").unwrap();
        let path = Some(file_path.clone());
        let previous = Arc::new(Mutex::new(None));
        let applied = Arc::new(Mutex::new(None));
        let reload = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hot_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called = hot_called.clone();
        let hot_apply: HotConfigApply = Arc::new(move |next, changed| {
            assert_eq!(next.blocked_response_ttl, 11);
            assert_eq!(changed, ["blocked_response_ttl"]);
            called.store(true, std::sync::atomic::Ordering::Release);
            Ok((true, changed.to_vec()))
        });

        let context = RaftApplyContext::new(
            path,
            previous,
            applied.clone(),
            RaftGenerationApply {
                reload: reload.clone(),
                hot_apply: Some(hot_apply),
            },
        );
        context
            .apply_command(br#"{"patch":{"blocked_response_ttl":11}}"#)
            .unwrap();

        assert!(hot_called.load(std::sync::atomic::Ordering::Acquire));
        assert!(!reload.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(
            applied.lock().unwrap().as_deref(),
            Some("blocked_response_ttl = 11\n")
        );
        assert_eq!(
            std::fs::read_to_string(&file_path).unwrap(),
            "blocked_response_ttl = 11\n"
        );
        std::fs::remove_file(file_path).unwrap();
    }

    #[test]
    /** @brief 세대가 바뀌는 사이 온 변경이 사라지지 않는지. */
    fn raft_generation_switch_cannot_lose_a_concurrent_restart_change() {
        let file_path = std::env::temp_dir().join(format!(
            "onetdns-raft-generation-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        /** @brief 테스트 시작 설정. */
        const INITIAL: &str = "cache_size = 4096\n";
        std::fs::write(&file_path, INITIAL).unwrap();
        let old_reload = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let new_reload = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let restart_apply: HotConfigApply = Arc::new(|_, changed| Ok((false, changed.to_vec())));
        let context = Arc::new(RaftApplyContext::new(
            Some(file_path.clone()),
            Arc::new(Mutex::new(None)),
            Arc::new(Mutex::new(None)),
            RaftGenerationApply {
                reload: old_reload,
                hot_apply: Some(restart_apply.clone()),
            },
        ));
        let applier = {
            let context = context.clone();
            std::thread::spawn(move || context.apply_command(br#"{"patch":{"cache_size":8192}}"#))
        };

        context
            .install_generation(
                Some(INITIAL),
                RaftGenerationApply {
                    reload: new_reload.clone(),
                    hot_apply: Some(restart_apply),
                },
            )
            .unwrap();
        applier.join().unwrap().unwrap();

        assert!(
            new_reload.load(std::sync::atomic::Ordering::Acquire),
            "적용이 전환 전이면 파일 차이를 감지하고, 전환 후면 새 콜백을 깨워야 합니다"
        );
        assert_eq!(
            std::fs::read_to_string(&file_path).unwrap(),
            "cache_size = 8192\n"
        );
        std::fs::remove_file(file_path).unwrap();
    }
}
