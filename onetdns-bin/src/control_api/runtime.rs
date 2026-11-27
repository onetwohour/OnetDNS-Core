//! Management API handlers that read and act on the running server.

use super::*;
use crate::cluster::{
    peer_cluster_status_json, propose_config_patch, raft_handle, standalone_cluster_status_json,
    with_raft_identity,
};
use crate::query_explain::{backend_label, explain_query, simulate_policy};
use std::sync::atomic::Ordering;

impl ControlDeps {
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

    pub(super) fn policy_simulate(&self, body: &str) -> String {
        simulate_policy(&self.policy_engine.load(), &self.filters.filter, body)
    }

    pub(super) fn resolve_probe(&self, body: &str) -> Result<String, String> {
        let handler = self
            .query_handler
            .get()
            .and_then(std::sync::Weak::upgrade)
            .ok_or("This server is not answering queries right now")?;
        resolve_probe(&handler, &self.runtime_cfg.load().listen, body)
    }

    pub(super) fn explain(&self, body: &str) -> String {
        explain_query(
            &self.policy_engine.load(),
            &self.filters.filter,
            &self.runtime_cfg.load(),
            &self.zones.store.load(),
            body,
        )
    }

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

    pub(super) fn jobs_list(&self) -> String {
        self.jobs.list_json()
    }

    pub(super) fn job_get(&self, id: u64) -> Result<String, String> {
        self.jobs
            .get_json(id)
            .ok_or_else(|| format!("Job not found: {id}"))
    }

    /// Starts a background job that refreshes the subscribed lists.
    pub(super) fn job_refresh(&self) -> String {
        let Some(id) = self.jobs.create("refresh-lists") else {
            return "{\"error\":\"Too many jobs are running\",\"busy\":true}".to_string();
        };
        let task_jobs = self.jobs.clone();
        let refresh_lists = self.filters.refresh_url_lists.clone();
        let stop = self.filters.refresh_stop();
        match std::thread::Builder::new()
            .name(format!("refresh-lists-{id}"))
            .spawn(move || match refresh_lists(&stop) {
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

pub(super) fn cluster_propose(body: &str) -> Result<String, String> {
    let idx = propose_config_patch(body)?;
    Ok(format!(
        "{{\"committed\":true,\"applied\":true,\"index\":{idx}}}"
    ))
}

/// Metrics the data path keeps outside the control plane's counters.
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
