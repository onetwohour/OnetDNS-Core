//! Connects the management API callbacks to one server generation through `ControlDeps`.

mod accounts;
mod clients;
mod config;
mod dhcp;
mod filter;
mod runtime;
mod subscriptions;
mod system;
mod tls;
mod upstreams;
mod zones;

use super::*;
use crate::cluster::cluster_routed_write;
use crate::config_apply::{apply_config_edit_smart, ConfigApplyResult, HotConfigApply};
use crate::filter_runtime::FilterState;
use crate::listeners::TlsSlots;
use crate::zones::ZoneState;
use onetdns_control::FilterApply;

/// The handles of this generation that the management API reads and changes.
pub(crate) struct ControlDeps {
    pub(crate) zones: ZoneState,
    pub(crate) filters: FilterState,
    pub(crate) runtime_cfg: Arc<ArcSwap<Config>>,
    /// `None` when running without a config file.
    pub(crate) config_path: Option<PathBuf>,
    /// The config text read when this generation started.
    pub(crate) cfg_text: Option<onetdns_core::SecretString>,
    /// Asks for a new generation.
    pub(crate) reload: Arc<std::sync::atomic::AtomicBool>,
    /// The config text before the last change, for rollback.
    pub(crate) config_prev: ConfigTextSlot,
    pub(crate) applied_config_text: ConfigTextSlot,
    pub(crate) hot_config_apply: HotConfigApply,
    /// Like `hot_config_apply`, but leaves the filter build to the background.
    pub(crate) hot_config_apply_background: HotConfigApply,
    pub(crate) policy_engine: Arc<native::GatedSwap<onetdns_policy::PolicyEngine>>,
    pub(crate) blocklist_resolver: http::HostResolver,
    /// `None` while DHCPv4 is off.
    pub(crate) dhcp_slot: Arc<Mutex<Option<Arc<Mutex<crate::dhcp::LeasePool>>>>>,
    /// `None` while DHCPv6 is off.
    pub(crate) dhcp6_slot: Arc<Mutex<Option<Arc<Mutex<crate::dhcp6::Lease6Pool>>>>>,
    pub(crate) vendor_db: Arc<ArcSwap<mac::VendorDb>>,
    /// `None` until the chain is built.
    pub(crate) cache_slot: Arc<Mutex<Option<cache::CacheHandle>>>,
    /// `None` while not forwarding.
    pub(crate) forward_stats: Arc<Mutex<Option<onetdns_forward::ForwardStats>>>,
    pub(crate) listener_reg: Arc<Mutex<Vec<(&'static str, String, String)>>>,
    /// `None` without an encrypted listener.
    pub(crate) tls_slot_handle: Arc<Mutex<Option<Arc<TlsSlots>>>>,
    pub(crate) jobs: Arc<JobRegistry>,
    /// Threads to join when this generation ends.
    pub(crate) service_threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
}

impl ControlDeps {
    fn edit_config(
        &self,
        edit: impl FnOnce(&str) -> Result<String, String>,
    ) -> Result<ConfigApplyResult, String> {
        self.edit_config_with(FilterApply::Wait, edit)
    }

    /// Edits the config text and applies it, hot or through a new generation as the keys require.
    fn edit_config_with(
        &self,
        filter_apply: FilterApply,
        edit: impl FnOnce(&str) -> Result<String, String>,
    ) -> Result<ConfigApplyResult, String> {
        let hot_apply = match filter_apply {
            FilterApply::Wait => &self.hot_config_apply,
            FilterApply::Background => &self.hot_config_apply_background,
        };
        apply_config_edit_smart(
            &self.config_path,
            &self.config_prev,
            &self.applied_config_text,
            &self.reload,
            hot_apply,
            edit,
        )
    }

    /// Puts changed filter inputs into effect. `Background` returns the current counts at once.
    fn apply_filter(&self, filter_apply: FilterApply) -> Result<(usize, usize), String> {
        match filter_apply {
            FilterApply::Wait => (self.filters.rebuild)(),
            FilterApply::Background => {
                self.filters.deferred_rebuild.request();
                let engine = self.filters.filter.load();
                Ok((engine.block_count(), engine.allow_count()))
            }
        }
    }

    fn filter_apply_status(&self) -> String {
        self.filters.deferred_rebuild.status_json()
    }
}

/// Wraps one method as a callback. Untyped closure parameters would pin `&str` to one lifetime.
macro_rules! bind {
    ($deps:ident . $method:ident ( $($arg:ident : $ty:ty),* )) => {{
        let deps = Arc::clone(&$deps);
        Box::new(move |$($arg: $ty),*| deps.$method($($arg),*))
    }};
}

pub(crate) fn build(deps: ControlDeps) -> onetdns_control::Controls {
    let deps = Arc::new(deps);
    onetdns_control::Controls {
        reload: bind!(deps.rebuild_filter()),
        block_add: bind!(deps.block_add(rule: &str)),
        allow_add: bind!(deps.allow_add(rule: &str)),
        service_set: bind!(deps.service_set(svc: &str, enable: bool, apply: FilterApply)),
        safesearch_set: bind!(deps.safesearch_set(enable: bool)),
        export: bind!(deps.export()),
        import: bind!(deps.import(body: &str)),
        config_validate: bind!(deps.config_validate(toml: &str)),
        config_diff: bind!(deps.config_diff(proposed: &str)),
        config_set_diff: bind!(deps.config_set_diff(body: &str)),
        config_apply: bind!(deps.config_apply(toml: &str)),
        config_set: bind!(deps.config_set(body: &str, apply: FilterApply)),
        config_schema: bind!(deps.config_schema()),
        upstream_test: bind!(deps.upstream_test(body: &str)),
        cache_flush: bind!(deps.cache_flush()),
        rewrites_list: bind!(deps.rewrites_list()),
        rewrite_add: bind!(deps.rewrite_add(body: &str, apply: FilterApply)),
        rewrite_delete: bind!(deps.rewrite_delete(body: &str, apply: FilterApply)),
        services_catalog: bind!(deps.services_catalog()),
        access_list: bind!(deps.access_list()),
        tls_status: bind!(deps.tls_status()),
        tls_validate: bind!(deps.tls_validate()),
        tls_configure: bind!(deps.tls_configure(body: &str)),
        tls_revocation_check: bind!(deps.tls_revocation_check(body: &str)),
        acme_issue: bind!(deps.acme_issue(body: &str)),
        tokens_list: bind!(deps.tokens_list()),
        token_add: bind!(deps.token_add(body: &str)),
        token_delete: bind!(deps.token_delete(body: &str)),
        config_rollback: bind!(deps.config_rollback()),
        policy_simulate: bind!(deps.policy_simulate(body: &str)),
        resolve_probe: bind!(deps.resolve_probe(body: &str)),
        explain: bind!(deps.explain(body: &str)),
        cluster_status: bind!(deps.cluster_status()),
        cluster_propose: Box::new(runtime::cluster_propose),
        cluster_write: Box::new(cluster_routed_write),
        listeners_status: bind!(deps.listeners_status()),
        net_adapters: Box::new(system::net_adapters),
        firewall_set: Box::new(system::firewall_set),
        dns_client_set: bind!(deps.dns_client_set(body: &str)),
        boot_service_status: Box::new(system::boot_service_status),
        #[cfg(windows)]
        boot_service_set: bind!(deps.boot_service_set(body: &str)),
        #[cfg(not(windows))]
        boot_service_set: Box::new(system::boot_service_set),
        dns_client_restore: bind!(deps.dns_client_restore(body: &str)),
        update_status: bind!(deps.update_status()),
        update_check: bind!(deps.update_check()),
        update_apply: bind!(deps.update_apply(version: &str)),
        update_rollback: bind!(deps.update_rollback()),
        metrics_extra: Box::new(runtime::metrics_extra),
        filter_report: bind!(deps.filter_report()),
        filter_top_rules: bind!(deps.filter_top_rules()),
        filter_sources: bind!(deps.filter_sources()),
        subscriptions_list: bind!(deps.subscriptions_list()),
        subscription_add: bind!(deps.subscription_add(body: &str)),
        subscription_remove: bind!(deps.subscription_remove(url: &str, apply: FilterApply)),
        subscription_update: bind!(deps.subscription_update(body: &str, apply: FilterApply)),
        subscription_refresh: bind!(deps.subscription_refresh(body: &str, apply: FilterApply)),
        filter_rules_list: bind!(deps.filter_rules_list()),
        filter_rule_mutate: bind!(deps.filter_rule_mutate(body: &str, add: bool, apply: FilterApply)),
        filter_apply_status: bind!(deps.filter_apply_status()),
        clients_list: bind!(deps.clients_list()),
        upstreams_list: bind!(deps.upstreams_list()),
        jobs_list: bind!(deps.jobs_list()),
        job_get: bind!(deps.job_get(id: u64)),
        job_refresh: bind!(deps.job_refresh()),
        dhcp_leases: bind!(deps.dhcp_leases()),
        dhcp_lease_put: bind!(deps.dhcp_lease_put(body: &str)),
        dhcp_static_list: bind!(deps.dhcp_static_list()),
        dhcp_static_add: bind!(deps.dhcp_static_add(body: &str)),
        dhcp_static_remove: bind!(deps.dhcp_static_remove(identity: &str)),
        client_add: bind!(deps.client_add(body: &str, apply: FilterApply)),
        client_remove: bind!(deps.client_remove(name: &str, apply: FilterApply)),
        client_update: bind!(deps.client_update(body: &str, apply: FilterApply)),
        password_change: bind!(deps.password_change(name: &str, hash: &str)),
        user_create: bind!(deps.user_create(name: &str, hash: &str)),
        upstream_add: bind!(deps.upstream_add(entry: &str)),
        upstream_remove: bind!(deps.upstream_remove(entry: &str)),
        plugins_metrics: bind!(deps.plugins_metrics()),
        zones_list: bind!(deps.zones_list()),
        zone_get: bind!(deps.zone_get(origin: &str)),
        zone_put: bind!(deps.zone_put(origin: &str, text: &str)),
        zone_delete: bind!(deps.zone_delete(origin: &str)),
        zone_record_add: bind!(deps.zone_record_add(origin: &str, body: &str)),
        zone_record_delete: bind!(deps.zone_record_delete(origin: &str, body: &str)),
        zone_dnssec: bind!(deps.zone_dnssec(origin: &str)),
        config_desired: bind!(deps.config_desired()),
        config_effective: bind!(deps.config_effective()),
        config_status: bind!(deps.config_status()),
        config_reload: bind!(deps.config_reload()),
    }
}
