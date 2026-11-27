//! Raft cluster runtime and config writes routed through the cluster.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use onetdns_config::Config;
use onetdns_core::MutexExt;
use sha2::{Digest, Sha256};

use crate::config_apply::{
    apply_config_edit_smart_locked, changed_config_keys, config_write_lock, HotConfigApply,
};
use crate::config_edit::{
    json_to_raft_toml_literal, materialize_mode_acl_patch, remove_config_key, rewrite_config_kv,
    toml_value_to_json, MAX_RAFT_VALUE_DEPTH,
};
use crate::notify::NotifySender;
use crate::zone_signing::SharedZoneSigners;
use crate::zones::apply_zone_mutation_locked;
use crate::{config_keys, http, native, sleep_or_shutdown, ConfigTextSlot};

#[derive(Clone, PartialEq, Eq)]
struct RaftRuntimeIdentity {
    node_id: u64,
    listen: String,
    /// Node ID, address, and public key of each other node.
    peers: Vec<(u64, String, [u8; 32])>,
    /// Must differ per node.
    node_seed: [u8; 32],
    /// Fingerprint of the cluster secret, for spotting config changes.
    secret_digest: [u8; 32],
    /// Where the consensus state persists.
    state_path: PathBuf,
}

#[derive(Clone)]
struct RaftGenerationApply {
    /// Set to make the config reload.
    reload: Arc<std::sync::atomic::AtomicBool>,
    hot_apply: HotConfigApply,
}

/// Applies Raft log entries; its generation part is replaced at each generation.
struct RaftApplyContext {
    path: Option<PathBuf>,
    /// For rollback.
    prev: ConfigTextSlot,
    /// The last config text that applied successfully.
    applied: ConfigTextSlot,
    generation: Mutex<RaftGenerationApply>,
}

impl RaftApplyContext {
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

    /// A new generation checks whether the config file changed while it started, and if so marks a
    /// reload. The comparison and the swap happen under one config write lock: applying reads the
    /// generation under the same lock, so releasing it between them would let a change arriving in
    /// between reach only the old generation and escape the file comparison too.
    ///
    /// `expected_text`: the config text this generation read. None means the caller already holds
    /// the config write lock, as hot apply does: it calls with the lock held and the current file
    /// contents, so locking again here would deadlock, and comparing against the boot text would
    /// see the file changed since boot and restart the whole service.
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

    /// Restores the config file as it was before the request, cancelling an uncommitted change on
    /// this node. `previous_slot`: the rollback text from before the request; restoring it too
    /// keeps the config rollback API from reapplying the uncommitted change.
    fn restore_text(
        &self,
        text: &str,
        previous_slot: Option<onetdns_core::SecretString>,
    ) -> Result<(), String> {
        let _write_guard = config_write_lock().lock_recover();
        let generation = self.generation.lock_recover().clone();
        let result = apply_config_edit_smart_locked(
            &self.path,
            &self.prev,
            &self.applied,
            &generation.reload,
            &generation.hot_apply,
            |_: &str| Ok(text.to_string()),
        )
        .map(|_| ());
        *self.prev.lock_recover() = previous_slot;
        result
    }

    fn apply_command(&self, data: &[u8]) -> Result<(), String> {
        let patch = decode_raft_command_patch(data)?;
        self.apply_patch(&patch)
    }

    fn apply_patch(&self, patch: &[(String, onetdns_core::json::Json)]) -> Result<(), String> {
        apply_raft_patch(self, patch)
    }
}

struct RaftRuntime {
    identity: RaftRuntimeIdentity,
    apply: Arc<RaftApplyContext>,
    handle: onetdns_cluster::transport::RaftHandle,
}

static RAFT: std::sync::OnceLock<Mutex<Option<RaftRuntime>>> = std::sync::OnceLock::new();

fn raft_slot() -> &'static Mutex<Option<RaftRuntime>> {
    RAFT.get_or_init(|| Mutex::new(None))
}

/// None when not running.
pub fn raft_handle() -> Option<onetdns_cluster::transport::RaftHandle> {
    raft_slot()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
        .map(|runtime| runtime.handle.clone())
}

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

/// Stops the cluster node at process exit.
pub(crate) struct RaftProcessCleanup;

impl Drop for RaftProcessCleanup {
    fn drop(&mut self) {
        stop_raft();
    }
}

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

/// Starts the cluster node, or reuses the one already running.
pub(crate) fn ensure_raft_runtime(
    cfg: &Config,
    expected_text: Option<&str>,
    path: Option<PathBuf>,
    prev: ConfigTextSlot,
    applied: ConfigTextSlot,
    reload: Arc<std::sync::atomic::AtomicBool>,
    hot_apply: HotConfigApply,
) -> Result<(), String> {
    let listen = cfg
        .cluster_raft_listen
        .clone()
        .ok_or("Raft is enabled but no listen address (cluster_raft_listen) is set")?;
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
        "cluster_raft_node_key must be a 32-byte Ed25519 seed written as 64 hexadecimal digits",
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
                "Keeping the running Raft consensus runtime across the DNS service restart"
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
            "Could not recover Raft state from disk ({}): {error}",
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
    let listener = listen
        .parse::<std::net::SocketAddr>()
        .map_err(|_| format!("Invalid Raft listen address (numeric IP:port required): {listen}"))
        .and_then(|address| {
            std::net::TcpListener::bind(address).map_err(|error| {
                format!("Could not open the Raft listening address {address}: {error}")
            })
        })
        .map_err(|error| format!("Could not start Raft: {error}"))?;
    let handle = onetdns_cluster::transport::RaftServer::spawn(
        cfg.cluster_node_id,
        crate::update::VERSION,
        listener,
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
    .map_err(|error| format!("Could not start Raft: {error}"))?;
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
        "Starting Raft cluster consensus (leader election and log replication)"
    );
    Ok(())
}

/// Restarts the cluster node per the config. The second argument is the raw text to check against
/// the agreed config: a generation start passes the text that opened the generation, and a
/// hot-apply restart has none.
pub(crate) type RaftRestart =
    Arc<dyn Fn(&Config, Option<&str>) -> Result<(), String> + Send + Sync>;

pub(crate) fn raft_restart(
    path: Option<PathBuf>,
    prev: ConfigTextSlot,
    applied: ConfigTextSlot,
    reload: Arc<std::sync::atomic::AtomicBool>,
    hot_apply: HotConfigApply,
) -> RaftRestart {
    Arc::new(
        move |next: &Config, expected_text: Option<&str>| -> Result<(), String> {
            // Always stops first; restarting while running would collide on the listen address.
            stop_raft();
            if !next.cluster_raft || next.cluster_node_id == 0 {
                return Ok(());
            }
            ensure_raft_runtime(
                next,
                expected_text,
                path.clone(),
                prev.clone(),
                applied.clone(),
                reload.clone(),
                hot_apply.clone(),
            )
        },
    )
}

/// Rejects per-node settings: replicating them would give every node the same secret or overlapping
/// identities.
pub(crate) fn validate_raft_patch_scope(value: &onetdns_core::json::Json) -> Result<(), String> {
    let onetdns_core::json::Json::Obj(pairs) = value else {
        return Err("A configuration change sent through Raft must be a JSON object".to_string());
    };
    if let Some((key, _)) = pairs.iter().find(|(key, _)| config_keys::node_local(key)) {
        return Err(format!(
            "{key} is a per-node setting and cannot be replicated through Raft; set it on each node"
        ));
    }
    Ok(())
}

/// Requests that change cluster-shared config. Config edits are judged by the keys in the body, so
/// an edit touching only per-node settings passes on a follower. A body that does not parse is not
/// rejected here; request handling answers it with a body error.
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

/// Serializes cluster proposals; separate from the config write lock.
fn cluster_proposal_lock() -> &'static Mutex<()> {
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn cluster_write_error(status: &'static str, message: String) -> onetdns_control::ApiResponse {
    (
        status,
        "application/json",
        format!("{{\"error\":{}}}", onetdns_core::json::escape(&message)),
    )
}

/// Names the leader when known.
fn cluster_not_leader_message(leader: Option<u64>) -> String {
    match leader {
        Some(id) => format!(
            "This node is not the Raft leader, so cluster-wide settings cannot be changed here; make the change on the dashboard of node {id}, the current leader"
        ),
        None => "A Raft leader election is in progress, so cluster-wide settings cannot be changed; try again shortly".to_string(),
    }
}

/// Shared settings that differ between the two config texts, with their new values; a removed key's
/// value is null. Empty when nothing changed.
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

/// Routes a state-changing management request through Raft. The leader handles the request first
/// and, if shared config changed, proposes the new values; when the proposal fails, the config file
/// reverts and the request fails. Handling first lets every request take one path: requests edit
/// the config file in different ways, and comparing the file before and after covers them all.
///
/// A follower rejects requests that change shared config before handling them. If one not caught in
/// advance changed shared config anyway, it is reverted and rejected, since a value changed on a
/// follower would be overwritten at the next commit and the nodes would diverge.
///
/// The proposal waits for the commit without the config write lock, because applying a committed
/// entry takes that lock; the proposal lock keeps proposals in order.
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
            .map_err(|error| format!("Could not read the configuration file {when}: {error}"))
    };
    let before = match read("before handling the request") {
        Ok(text) => text,
        Err(error) => return cluster_write_error("503 Service Unavailable", error),
    };
    let previous_slot = context.prev.lock_recover().clone();
    let response = dispatch();
    if !response.0.starts_with('2') {
        return response;
    }
    let changes = read("after handling the request")
        .and_then(|after| cluster_config_changes(&before, &after));
    let (status, message) = match changes {
        Ok(changes) if changes.is_empty() => return response,
        Ok(_) if !leader => ("409 Conflict", cluster_not_leader_message(handle.leader())),
        Ok(changes) => {
            let command = onetdns_core::json::Json::Obj(vec![(
                "patch".to_string(),
                onetdns_core::json::Json::Obj(changes),
            )])
            .to_text();
            // Even when the outcome is unknown, this node's change is reverted: if it commits
            // later, applying writes it to this node again and all nodes agree; if it is dropped,
            // the reverted state is right.
            match handle.propose(command.into_bytes()) {
                Ok(_) => return response,
                Err(onetdns_cluster::transport::ProposalError::Undetermined(error)) => (
                    "503 Service Unavailable",
                    format!("Could not yet confirm that the Raft cluster agreed on this change, so it was reverted on this node ({error}). If a majority of nodes connect and agree, it will be applied to every node; otherwise it will not be applied. Check the configuration again shortly"),
                ),
                Err(error) => (
                    "503 Service Unavailable",
                    format!("The Raft cluster did not agree on the change, so it was reverted on this node too: {error}"),
                ),
            }
        }
        Err(error) => (
            "503 Service Unavailable",
            format!("Could not submit the change to the Raft cluster, so it was reverted: {error}"),
        ),
    };
    let message = match context.restore_text(&before, previous_slot) {
        Ok(()) => message,
        Err(error) => {
            format!("{message}. Reverting this node's configuration file also failed: {error}")
        }
    };
    onetdns_core::warn!(
        event = "raft.write_rejected",
        method = %method,
        path = %path,
        reason = %message,
        "Rolled back a management request that Raft did not commit"
    );
    cluster_write_error(status, message)
}

const RAFT_CONFIG_SNAPSHOT_MAGIC: &[u8; 12] = b"ONETCFGSNAP1";

const MAX_RAFT_SNAPSHOT_KEYS: usize = 1_024;

#[derive(Default)]
struct RaftConfigSnapshot {
    values: std::collections::BTreeMap<String, onetdns_core::json::Json>,
}

impl RaftConfigSnapshot {
    /// Later entries win.
    fn merge_command(&mut self, data: &[u8]) -> Result<(), String> {
        let patch = decode_raft_command_patch(data)?;
        for (key, value) in patch {
            self.values.insert(key, value);
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, String> {
        if self.values.is_empty() || self.values.len() > MAX_RAFT_SNAPSHOT_KEYS {
            return Err("Raft configuration snapshot has too many or too few entries".into());
        }
        let mut out = Vec::new();
        out.extend_from_slice(RAFT_CONFIG_SNAPSHOT_MAGIC);
        out.extend_from_slice(&(self.values.len() as u32).to_be_bytes());
        for (key, value) in &self.values {
            if key.is_empty() || key.len() > 128 || key.len() > u16::MAX as usize {
                return Err("Raft configuration snapshot has an invalid key".into());
            }
            out.extend_from_slice(&(key.len() as u16).to_be_bytes());
            out.extend_from_slice(key.as_bytes());
            encode_raft_snapshot_value(value, &mut out, 0)?;
            if out.len() > onetdns_cluster::raft::MAX_SNAPSHOT_BYTES {
                return Err("Raft configuration snapshot exceeds the size limit".into());
            }
        }
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > onetdns_cluster::raft::MAX_SNAPSHOT_BYTES
            || bytes.get(..RAFT_CONFIG_SNAPSHOT_MAGIC.len())
                != Some(RAFT_CONFIG_SNAPSHOT_MAGIC.as_slice())
        {
            return Err("Raft configuration snapshot has an invalid header".into());
        }
        let mut pos = RAFT_CONFIG_SNAPSHOT_MAGIC.len();
        let count = raft_snapshot_take_u32(bytes, &mut pos)? as usize;
        if count == 0 || count > MAX_RAFT_SNAPSHOT_KEYS {
            return Err("Raft configuration snapshot has too many or too few entries".into());
        }
        let mut values = std::collections::BTreeMap::new();
        for _ in 0..count {
            let key_len = raft_snapshot_take_u16(bytes, &mut pos)? as usize;
            if key_len == 0 || key_len > 128 {
                return Err("Raft configuration snapshot has an invalid key length".into());
            }
            let key = std::str::from_utf8(raft_snapshot_take(bytes, &mut pos, key_len)?)
                .map_err(|_| "Raft configuration snapshot key is not UTF-8")?
                .to_string();
            let value = decode_raft_snapshot_value(bytes, &mut pos, 0)?;
            if values.insert(key, value).is_some() {
                return Err("Raft configuration snapshot has a duplicate key".into());
            }
        }
        if pos != bytes.len() {
            return Err("Raft configuration snapshot has trailing data".into());
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

    fn patch(&self) -> Vec<(String, onetdns_core::json::Json)> {
        self.values
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }
}

/// A top-level null is kept, since it records agreement to delete the key. Arrays and tables nest
/// as in the config file, up to a depth limit.
fn encode_raft_snapshot_value(
    value: &onetdns_core::json::Json,
    out: &mut Vec<u8>,
    depth: usize,
) -> Result<(), String> {
    use onetdns_core::json::Json;
    if depth > MAX_RAFT_VALUE_DEPTH {
        return Err("Raft configuration snapshot value is nested too deeply".into());
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
            let len = u32::try_from(text.len())
                .map_err(|_| "Raft configuration snapshot string is too large")?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(text.as_bytes());
        }
        Json::Arr(items) => {
            out.push(5);
            let count = u32::try_from(items.len())
                .map_err(|_| "Raft configuration snapshot array is too large")?;
            out.extend_from_slice(&count.to_be_bytes());
            for item in items {
                encode_raft_snapshot_value(item, out, depth + 1)?;
            }
        }
        Json::Obj(fields) => {
            out.push(6);
            let count = u32::try_from(fields.len())
                .map_err(|_| "Raft configuration snapshot table is too large")?;
            out.extend_from_slice(&count.to_be_bytes());
            for (key, value) in fields {
                let len = u16::try_from(key.len())
                    .map_err(|_| "Raft configuration snapshot table key is too long")?;
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(key.as_bytes());
                encode_raft_snapshot_value(value, out, depth + 1)?;
            }
        }
        _ => return Err("Raft configuration snapshot has an unsupported value type".into()),
    }
    Ok(())
}

fn decode_raft_snapshot_value(
    bytes: &[u8],
    pos: &mut usize,
    depth: usize,
) -> Result<onetdns_core::json::Json, String> {
    use onetdns_core::json::Json;
    /// Per array or table.
    const MAX_ITEMS: usize = 100_000;
    if depth > MAX_RAFT_VALUE_DEPTH {
        return Err("Raft configuration snapshot value is nested too deeply".into());
    }
    let tag = *raft_snapshot_take(bytes, pos, 1)?
        .first()
        .ok_or("Raft configuration snapshot value has no tag")?;
    match tag {
        0 if depth == 0 => Ok(Json::Null),
        1 => Ok(Json::Bool(false)),
        2 => Ok(Json::Bool(true)),
        3 => {
            let bits = u64::from_be_bytes(
                raft_snapshot_take(bytes, pos, 8)?
                    .try_into()
                    .map_err(|_| "Raft configuration snapshot number is not 8 bytes long")?,
            );
            let number = f64::from_bits(bits);
            number
                .is_finite()
                .then_some(Json::Num(number))
                .ok_or_else(|| "Raft configuration snapshot number is not finite".into())
        }
        4 => {
            let len = raft_snapshot_take_u32(bytes, pos)? as usize;
            let text = std::str::from_utf8(raft_snapshot_take(bytes, pos, len)?)
                .map_err(|_| "Raft configuration snapshot string is not UTF-8")?;
            Ok(Json::Str(text.to_string()))
        }
        5 => {
            let count = raft_snapshot_take_u32(bytes, pos)? as usize;
            if count > MAX_ITEMS {
                return Err("Raft configuration snapshot array has too many items".into());
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
                return Err("Raft configuration snapshot table has too many entries".into());
            }
            let mut fields: Vec<(String, Json)> = Vec::with_capacity(count.min(1_024));
            for _ in 0..count {
                let len = raft_snapshot_take_u16(bytes, pos)? as usize;
                let key = std::str::from_utf8(raft_snapshot_take(bytes, pos, len)?)
                    .map_err(|_| "Raft configuration snapshot table key is not UTF-8")?
                    .to_string();
                if fields.iter().any(|(existing, _)| *existing == key) {
                    return Err("Raft configuration snapshot table has a duplicate key".into());
                }
                let value = decode_raft_snapshot_value(bytes, pos, depth + 1)?;
                fields.push((key, value));
            }
            Ok(Json::Obj(fields))
        }
        _ => Err("Raft configuration snapshot value has an invalid tag".into()),
    }
}

fn raft_snapshot_take<'a>(
    bytes: &'a [u8],
    pos: &mut usize,
    len: usize,
) -> Result<&'a [u8], String> {
    let end = pos
        .checked_add(len)
        .ok_or("Raft configuration snapshot offset is out of range")?;
    let value = bytes
        .get(*pos..end)
        .ok_or("Raft configuration snapshot is truncated")?;
    *pos = end;
    Ok(value)
}

fn raft_snapshot_take_u16(bytes: &[u8], pos: &mut usize) -> Result<u16, String> {
    Ok(u16::from_be_bytes(
        raft_snapshot_take(bytes, pos, 2)?
            .try_into()
            .map_err(|_| "Could not read a 16-bit integer from the Raft configuration snapshot")?,
    ))
}

fn raft_snapshot_take_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, String> {
    Ok(u32::from_be_bytes(
        raft_snapshot_take(bytes, pos, 4)?
            .try_into()
            .map_err(|_| "Could not read a 32-bit integer from the Raft configuration snapshot")?,
    ))
}

/// Fails on any other envelope.
pub(crate) fn parse_cluster_proposal(body: &str) -> Result<onetdns_core::json::Json, String> {
    let json = onetdns_core::json::parse(body)
        .map_err(|error| format!("Could not parse the JSON request body: {error}"))?;
    let onetdns_core::json::Json::Obj(fields) = json else {
        return Err("A Raft configuration change must contain exactly one patch object".into());
    };
    if fields.len() != 1 || fields[0].0 != "patch" {
        return Err("A Raft configuration change must contain exactly one patch object".into());
    }
    let patch = fields[0].1.clone();
    let onetdns_core::json::Json::Obj(entries) = &patch else {
        return Err("The patch in a Raft configuration change must be an object".into());
    };
    if entries.is_empty() || entries.len() > 128 {
        return Err("A Raft configuration change has too many or too few entries".into());
    }
    Ok(patch)
}

fn decode_raft_command_patch(
    data: &[u8],
) -> Result<Vec<(String, onetdns_core::json::Json)>, String> {
    let text = std::str::from_utf8(data)
        .map_err(|error| format!("Raft command is not valid UTF-8: {error}"))?;
    let json = onetdns_core::json::parse(text)
        .map_err(|error| format!("Raft command JSON is invalid: {error}"))?;
    let onetdns_core::json::Json::Obj(fields) = &json else {
        return Err("A Raft command must contain exactly one patch object".into());
    };
    if fields.len() != 1 || fields[0].0 != "patch" {
        return Err("A Raft command must contain exactly one patch object".into());
    }
    let patch_value = json
        .get("patch")
        .ok_or_else(|| "The Raft configuration change has no patch object".to_string())?;
    validate_raft_patch_scope(patch_value)?;
    let onetdns_core::json::Json::Obj(patch) = patch_value else {
        return Err("The Raft configuration change has no patch object".into());
    };
    if patch.is_empty() || patch.len() > 128 {
        return Err("A Raft configuration change has too many or too few entries".into());
    }
    let mut patch = patch.clone();
    materialize_mode_acl_patch(&mut patch)?;
    Ok(patch)
}

fn raft_patch_edit(
    text: &str,
    patch: &[(String, onetdns_core::json::Json)],
) -> Result<String, String> {
    let mut output = text.to_string();
    for (key, value) in patch {
        if key.is_empty() || key.len() > 128 {
            return Err("Raft configuration key length is out of range".into());
        }
        output = match value {
            // null is agreement to delete the key; writing an empty value would not restore the
            // default.
            onetdns_core::json::Json::Null => remove_config_key(&output, key)?,
            value => rewrite_config_kv(&output, key, &json_to_raft_toml_literal(value, 0)?)?,
        };
    }
    Ok(output)
}

/// Runs the checks applying `patch` would run, without writing anything.
fn check_raft_patch(
    context: &RaftApplyContext,
    patch: &[(String, onetdns_core::json::Json)],
) -> Result<(), String> {
    let path = context
        .path
        .as_deref()
        .ok_or("There is no configuration file for a Raft change to apply to")?;
    let current =
        onetdns_core::SecretString::from(Config::read_text(path).map_err(|e| e.to_string())?);
    let edited = onetdns_core::SecretString::from(raft_patch_edit(&current, patch)?);
    let config = Config::from_toml_str(&edited)
        .map_err(|e| format!("The changed configuration is invalid: {e}"))?;
    crate::runtime_preflight(&config)
        .map_err(|e| format!("The changed configuration is invalid: {e}"))
}

/// Handles `/v1/cluster/propose`. Every node applies a committed entry, and one that fails to
/// apply stops Raft on each of them, so the patch must apply here before it is proposed.
pub(crate) fn propose_config_patch(body: &str) -> Result<u64, String> {
    parse_cluster_proposal(body)?;
    let entries = decode_raft_command_patch(body.as_bytes())?;
    let (handle, context) = raft_slot()
        .lock_recover()
        .as_ref()
        .map(|runtime| (runtime.handle.clone(), runtime.apply.clone()))
        .ok_or("Raft is not configured")?;
    let _proposal = cluster_proposal_lock().lock_recover();
    check_raft_patch(&context, &entries)?;
    Ok(handle.propose(body.as_bytes().to_vec())?)
}

fn apply_raft_patch(
    context: &RaftApplyContext,
    patch: &[(String, onetdns_core::json::Json)],
) -> Result<(), String> {
    if patch.is_empty() || patch.len() > MAX_RAFT_SNAPSHOT_KEYS {
        return Err("Raft configuration state has too many or too few entries".into());
    }
    validate_raft_patch_scope(&onetdns_core::json::Json::Obj(patch.to_vec()))?;

    let _write_guard = config_write_lock().lock_recover();
    let generation = context.generation.lock_recover().clone();
    let mode = apply_config_edit_smart_locked(
        &context.path,
        &context.prev,
        &context.applied,
        &generation.reload,
        &generation.hot_apply,
        |text: &str| raft_patch_edit(text, patch),
    )?
    .mode;
    onetdns_core::info!(
        event = "raft.config_applied",
        keys = patch.len(),
        mode = mode.as_str(),
        "Applied configuration replicated through Raft"
    );
    Ok(())
}

/// Adds this node's Raft identity to the cluster status JSON: the public key and the ready-to-paste
/// entry for other nodes' `cluster_raft_peers`. Shown even before Raft is on as long as a signing
/// key exists, since nodes must know each other's public keys before turning it on. null without a
/// signing key or with a malformed one.
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

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn standalone_cluster_status_json(backend: &str, listeners: usize) -> String {
    format!(
        "{{\"self\":{{\"id\":null,\"role\":\"standalone\",\"backend\":{},\"listeners\":{listeners},\"leader\":null,\"term\":null,\"commit_index\":null,\"last_applied\":null,\"last_index\":null,\"snapshot_index\":null,\"retained_log_entries\":null,\"fatal\":null,\"healthy\":true,\"version\":{}}},\"peers\":[]}}",
        onetdns_core::json::escape(backend),
        onetdns_core::json::escape(crate::update::VERSION)
    )
}

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
                    "Could not start the peer health probe thread"
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
                "{{\"id\":null,\"url\":{},\"healthy\":{healthy},\"role\":\"member\",\"rtt_ms\":{rtt},\"version\":null}}",
                onetdns_core::json::escape(url)
            )
        })
        .collect();
    format!(
        "{{\"self\":{{\"id\":null,\"role\":\"member\",\"backend\":{},\"listeners\":{listeners},\"leader\":null,\"term\":null,\"commit_index\":null,\"last_applied\":null,\"last_index\":null,\"snapshot_index\":null,\"retained_log_entries\":null,\"fatal\":null,\"healthy\":true,\"version\":{}}},\"peers\":[{}]}}",
        onetdns_core::json::escape(backend),
        onetdns_core::json::escape(crate::update::VERSION),
        items.join(",")
    )
}

/// Re-signs the RRSIGs of signed zones daily. The signing keys are read from the shared handle on
/// each run, so a key rollover or config change never leaves it signing with old keys.
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
                // Reads the zone under the lock; reading before locking would let the re-signed old
                // content overwrite a dynamic update that arrived in between.
                let mut journals = journal.lock_recover();
                let zone = store
                    .load()
                    .zones()
                    .iter()
                    .find(|z| z.origin().eq_ignore_case(origin))
                    .cloned();
                let Some(zone) = zone else {
                    continue;
                };
                let path = zone_files
                    .iter()
                    .find(|(candidate, _)| candidate.eq_ignore_case(origin))
                    .map(|(_, path)| path.as_path());
                let resigned = apply_zone_mutation_locked(
                    &store,
                    zone,
                    std::slice::from_ref(&(origin.clone(), ctx.clone())),
                    &mut journals,
                    path,
                    &notify,
                    "dnssec resign",
                );
                drop(journals);
                if let Err(error) = resigned {
                    onetdns_core::error!(event = "dnssec.resign_failed", zone = %origin.to_ascii_lower(), %error, "DNSSEC re-signing failed; keeping the existing signatures");
                } else {
                    onetdns_core::info!(event = "dnssec.resigned", zone = %origin.to_ascii_lower(), "Re-signed RRSIGs and bumped the zone serial");
                }
            }
        })
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use onetdns_config::Config;

    use crate::config_apply::HotConfigApply;
    use crate::config_edit::{json_to_raft_toml_literal, rewrite_config_kv, MAX_RAFT_VALUE_DEPTH};
    use crate::unix_now;

    #[test]
    /// Replicating them would give every node the same key.
    fn raft_config_patch_rejects_secret_material() {
        for key in [
            "cluster_raft_secret",
            "cachedb_redis_secret",
            "cachedb_redis_password",
            "upstream_proxy_password",
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

    /// Mixes table arrays and per-node settings; shared by the replication tests.
    const CLUSTER_FIXTURE: &str = "listen = [\"127.0.0.1:53\"]\ncontrol_listen = \"127.0.0.1:8080\"\nblock_rules = [\"ads.example\"]\ncache_size = 4096\nsafe_browsing = true\n\n[[clients]]\nname = \"kid \\\"room\\\"\"\nids = [\"192.0.2.0/24\"]\nblock = [\"games.example\"]\nsafe_search = true\n\n[[local_zones]]\nname = \"lan\"\nkind = \"static\"\nrecords = [\"nas.lan 192.0.2.10\", \"lan 192.0.2.1\"]\n\n[[rewrites]]\ndomain = \"rw.example\"\nanswer = \"192.0.2.53\"\n";

    #[test]
    /// Table arrays are written as inline tables, so the file looks different but must parse to the
    /// same value. Per-node settings are not carried; the receiving node keeps its own.
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
    fn cluster_status_shows_the_node_public_key_and_peer_entry() {
        let mut config = Config::default();
        config.cluster_node_id = 2;
        config.cluster_raft_listen = Some("10.0.0.2:7100".into());
        // RFC 8032 test vector 1 seed and public key.
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
                hot_apply,
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
    fn a_patch_that_would_not_apply_is_refused_before_it_is_proposed() {
        let file_path = std::env::temp_dir().join(format!(
            "onetdns-raft-check-{}-{}.toml",
            std::process::id(),
            unix_now()
        ));
        std::fs::write(&file_path, "blocked_response_ttl = 10\n").unwrap();
        let hot_apply: HotConfigApply = Arc::new(|_, _| panic!("a check applies nothing"));
        let context = |path| {
            RaftApplyContext::new(
                path,
                Arc::new(Mutex::new(None)),
                Arc::new(Mutex::new(None)),
                RaftGenerationApply {
                    reload: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    hot_apply: hot_apply.clone(),
                },
            )
        };
        let with_file = context(Some(file_path.clone()));
        let check = |body: &str| {
            check_raft_patch(
                &with_file,
                &decode_raft_command_patch(body.as_bytes()).unwrap(),
            )
        };

        check(r#"{"patch":{"blocked_response_ttl":11}}"#).unwrap();
        check(r#"{"patch":{"blocked_response_ttl":null}}"#).unwrap();
        for refused in [
            r#"{"patch":{"blocked_response_ttl":"11"}}"#,
            r#"{"patch":{"version":1}}"#,
            r#"{"patch":{"block_rules":[1]}}"#,
            r#"{"patch":{"no_such_setting":1}}"#,
        ] {
            assert!(check(refused).is_err(), "{refused}");
        }
        assert_eq!(
            std::fs::read_to_string(&file_path).unwrap(),
            "blocked_response_ttl = 10\n"
        );
        assert!(check_raft_patch(
            &context(None),
            &decode_raft_command_patch(br#"{"patch":{"blocked_response_ttl":11}}"#).unwrap(),
        )
        .is_err());
        std::fs::remove_file(file_path).unwrap();
    }

    #[test]
    fn raft_generation_switch_cannot_lose_a_concurrent_restart_change() {
        let file_path = std::env::temp_dir().join(format!(
            "onetdns-raft-generation-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
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
                hot_apply: restart_apply.clone(),
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
                    hot_apply: restart_apply,
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
