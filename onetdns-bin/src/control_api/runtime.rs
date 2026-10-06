/*!
 * @brief 관리 API: 실행 중인 서버의 상태를 보고 다룬다.
 */

use super::*;
use crate::cluster::{
    parse_cluster_proposal, peer_cluster_status_json, raft_handle, standalone_cluster_status_json,
    validate_raft_patch_scope, with_raft_identity,
};
use crate::query_explain::{backend_label, explain_query, simulate_policy};
use std::sync::atomic::Ordering;

impl ControlDeps {
    /** @brief 담아 둔 응답을 모두 비운다. */
    pub(super) fn cache_flush(&self) -> String {
        let n = self
            .cache_slot
            .lock_recover()
            .as_ref()
            .map(|c| c.clear())
            .unwrap_or(0);
        onetdns_core::info!(
            event = "cache.flushed",
            flushed = n,
            "Cleared the response cache"
        );
        format!("{{\"flushed\":{n}}}")
    }

    /** @brief 이 질의가 정책에서 어떻게 판정될지 실제로 묻지 않고 보여 준다. */
    pub(super) fn policy_simulate(&self, body: &str) -> String {
        simulate_policy(&self.policy_engine.load(), &self.filters.filter, body)
    }

    /** @brief 이름 하나를 이 서버의 수신 주소에 실제로 물어본다. */
    pub(super) fn resolve_probe(&self, body: &str) -> Result<String, String> {
        let current = self.runtime_cfg.load();
        let timeout = Duration::from_secs(current.query_timeout_secs.clamp(1, 10));
        resolve_probe(&current.listen, timeout, body)
    }

    /** @brief 이 질의가 어떻게 처리될지 단계마다 설명한다. */
    pub(super) fn explain(&self, body: &str) -> String {
        explain_query(
            &self.policy_engine.load(),
            &self.filters.filter,
            &self.runtime_cfg.load(),
            &self.zones.store.load(),
            body,
        )
    }

    /** @brief 이 노드와 클러스터 동료들의 상태. */
    pub(super) fn cluster_status(&self) -> String {
        let current = self.runtime_cfg.load();
        let backend = backend_label(current.backend);
        let peers = &current.cluster_peers;
        let listeners = current.listen.len();
        let status = match raft_handle() {
            Some(h) => h.status_json(backend, listeners),
            None if peers.is_empty() => standalone_cluster_status_json(backend, listeners),
            None => peer_cluster_status_json(peers, backend, listeners, &self.blocklist_resolver),
        };
        with_raft_identity(&status, &current)
    }

    /** @brief 지금 열려 있는 수신 주소. */
    pub(super) fn listeners_status(&self) -> String {
        use onetdns_core::MutexExt;
        let esc = onetdns_core::json::escape;
        let items: Vec<String> = self
            .listener_reg
            .lock_recover()
            .iter()
            .map(|(proto, configured, bound)| {
                format!(
                    "{{\"protocol\":{},\"configured\":{},\"bound\":{},\"state\":\"listening\"}}",
                    esc(proto),
                    esc(configured),
                    esc(bound)
                )
            })
            .collect();
        format!("[{}]", items.join(","))
    }

    /** @brief 오래 걸리는 작업 목록. */
    pub(super) fn jobs_list(&self) -> String {
        self.jobs.list_json()
    }

    /** @brief 이 작업의 진행 상황. */
    pub(super) fn job_get(&self, id: u64) -> Result<String, String> {
        self.jobs
            .get_json(id)
            .ok_or_else(|| format!("Job not found: {id}"))
    }

    /** @brief 목록 갱신 작업을 띄운다. */
    pub(super) fn job_refresh(&self) -> String {
        let Some(id) = self.jobs.create("refresh-lists") else {
            return "{\"error\":\"Too many jobs are running\",\"busy\":true}".to_string();
        };
        let task_jobs = self.jobs.clone();
        let refresh_lists = self.filters.refresh_url_lists.clone();
        match std::thread::Builder::new()
            .name(format!("refresh-lists-{id}"))
            .spawn(move || match refresh_lists() {
                Ok((block, allow)) => {
                    task_jobs.finish(id, true, format!("block={block} allow={allow}"))
                }
                Err(error) => task_jobs.finish(id, false, error),
            }) {
            Ok(thread) => {
                track_service_thread(&self.service_threads, thread);
                format!("{{\"id\":{id},\"status\":\"running\"}}")
            }
            Err(error) => {
                let message = format!("Could not start the job thread: {error}");
                self.jobs.finish(id, false, message.clone());
                format!(
                    "{{\"id\":{id},\"status\":\"failed\",\"error\":{}}}",
                    onetdns_core::json::escape(&message)
                )
            }
        }
    }

    /** @brief 정책 플러그인마다의 지표. */
    pub(super) fn plugins_metrics(&self) -> String {
        let items: Vec<String> = self
            .policy_engine
            .load()
            .plugin_metrics()
            .into_iter()
            .map(|(name, m)| {
                format!(
                    "{{\"name\":{},\"eval\":{},\"error\":{},\"timeout\":{},\"block\":{},\"latency_us\":{}}}",
                    onetdns_core::json::escape(&name),
                    m.eval_total,
                    m.error_total,
                    m.timeout_total,
                    m.block_total,
                    m.latency_us_total
                )
            })
            .collect();
        format!("[{}]", items.join(","))
    }
}

/** @brief 클러스터에 설정 변경을 제안한다. */
pub(super) fn cluster_propose(body: &str) -> Result<String, String> {
    match raft_handle() {
        Some(h) => {
            let patch = parse_cluster_proposal(body)?;
            validate_raft_patch_scope(&patch)?;
            let idx = h.propose(body.as_bytes().to_vec())?;
            Ok(format!(
                "{{\"committed\":true,\"applied\":true,\"index\":{idx}}}"
            ))
        }
        None => Err("Raft is not configured".to_string()),
    }
}

/** @brief 데이터 경로가 따로 내보내는 지표. */
pub(super) fn metrics_extra() -> String {
    let mut s = String::new();
    let failures = transport_observe::snapshot();
    if !failures.is_empty() {
        s.push_str(
            "# TYPE onetdns_transport_errors_total counter\n# HELP onetdns_transport_errors_total Total handling failures by transport stage\n",
        );
        for (transport, stage, count) in failures {
            s.push_str(&format!(
                "onetdns_transport_errors_total{{transport=\"{transport}\",stage=\"{stage}\"}} {count}\n"
            ));
        }
    }

    let bogus = native::DNSSEC_BOGUS_TOTAL.load(Ordering::Relaxed)
        + onetdns_recurse::validation_bogus_total();
    if bogus > 0 {
        s.push_str(
            "# TYPE onetdns_dnssec_bogus_total counter\n# HELP onetdns_dnssec_bogus_total Responses blocked because DNSSEC validation failed\n",
        );
        s.push_str(&format!("onetdns_dnssec_bogus_total {bogus}\n"));
    }

    let (batches, datagrams) = onetdns_runtime::recv_batch_counters();
    if batches > 0 {
        s.push_str(
            "# TYPE onetdns_udp_recv_batches_total counter\n# HELP onetdns_udp_recv_batches_total UDP batch receive calls\n",
        );
        s.push_str(&format!("onetdns_udp_recv_batches_total {batches}\n"));
        s.push_str(
            "# TYPE onetdns_udp_recv_datagrams_total counter\n# HELP onetdns_udp_recv_datagrams_total Datagrams returned by those calls\n",
        );
        s.push_str(&format!("onetdns_udp_recv_datagrams_total {datagrams}\n"));
    }
    s
}
