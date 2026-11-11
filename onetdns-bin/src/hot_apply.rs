//! Applies a config change to the running generation without building a new one.

use super::*;
use crate::config_apply::{
    backend_uses_forward, config_changed_keys, hot_reload_groups, normalize_config_for_comparison,
    runtime_config_update_lock, service_restart_keys, HotConfigApply, LOCAL_ONLY_CONFIG_KEYS,
};
use crate::config_apply::{ChainRebuild, RestartHooks, SecondaryRestart};
use crate::edge::{reconcile_edge_services, EdgeServices};
use crate::filter_runtime::FilterState;
use crate::filters::{
    blocklist_host_resolver, build_filter_engine_for_config, preset_list_urls,
    release_subscription_lines, revocation_host_resolver, validate_filter_config,
    FilterBuildInputs,
};
use crate::listeners::{PreparedTls, TlsSlots};
use crate::native_config::{
    build_authority_settings, build_native_features, build_policy_engine, build_views,
    evaluate_lane_gates, runtime_access_control, runtime_rate_limiters, telemetry_consumed,
    DynamicAccessControl, DynamicRateLimiter, LaneFacts, NativeHotState,
};
use crate::notify::NotifyTargets;
use crate::resolver_chain::PreparedChain;
use crate::zones::{build_zone_store, reconcile_zone_watchers, replace_zone_store, ZoneState};
use onetdns_control::FilterApply;
use std::sync::atomic::Ordering;

/// Steps that undo effects already applied. Register a step before causing its effect: one
/// that fails midway may have half-applied it.
#[derive(Default)]
struct Undo<'a>(Vec<Box<dyn FnOnce() -> Result<(), String> + 'a>>);

impl<'a> Undo<'a> {
    fn push(&mut self, step: impl FnOnce() -> Result<(), String> + 'a) {
        self.0.push(Box::new(step));
    }

    /// On failure runs every step in reverse and adds the steps that failed to the error.
    fn check<T>(&mut self, result: Result<T, String>) -> Result<T, String> {
        result.map_err(|error| {
            let failed: Vec<String> = std::mem::take(&mut self.0)
                .into_iter()
                .rev()
                .filter_map(|step| step().err())
                .collect();
            if failed.is_empty() {
                error
            } else {
                format!(
                    "{error}; restoring the previous configuration also failed: {}",
                    failed.join("; ")
                )
            }
        })
    }
}

/// An empty path turns that storage off.
pub(crate) fn persist_opts(cfg: &Config) -> onetdns_control::PersistOpts {
    onetdns_control::PersistOpts {
        querylog_file: cfg
            .querylog_file
            .clone()
            .filter(|path| !path.as_os_str().is_empty()),
        stats_file: cfg
            .stats_file
            .clone()
            .filter(|path| !path.as_os_str().is_empty()),
        flush_secs: cfg.persist_flush_secs,
    }
}

/// The handles of this generation that a hot apply swaps.
pub(crate) struct HotApplyDeps {
    pub(crate) restarts: RestartHooks,
    pub(crate) zones: ZoneState,
    pub(crate) filters: FilterState,
    /// `None` without a dashboard listener.
    pub(crate) console_auth: Arc<Mutex<Option<Arc<onetdns_control::Auth>>>>,
    pub(crate) control_proxy: Arc<ArcSwap<onetdns_control::ProxyPolicy>>,
    pub(crate) runtime_cfg: Arc<ArcSwap<Config>>,
    pub(crate) acl_state: Arc<DynamicAccessControl>,
    pub(crate) rate_state: Arc<DynamicRateLimiter>,
    pub(crate) recorder: onetdns_control::Recorder,
    pub(crate) forward_slot: native::ResolverSlot,
    /// `None` while not forwarding.
    pub(crate) forward_stats: Arc<Mutex<Option<onetdns_forward::ForwardStats>>>,
    /// `None` until the query handler is built.
    pub(crate) native_hot_state: Arc<Mutex<Option<NativeHotState>>>,
    pub(crate) stats: onetdns_control::Stats,
    /// This generation's shutdown flag.
    pub(crate) zone_shutdown: Arc<std::sync::atomic::AtomicBool>,
    /// Threads to join when this generation ends.
    pub(crate) zone_threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    pub(crate) edge_services: Arc<EdgeServices>,
    /// `None` while DHCPv4 is off.
    pub(crate) dhcp_slot: Arc<Mutex<Option<Arc<Mutex<dhcp::LeasePool>>>>>,
    /// `None` while DHCPv6 is off.
    pub(crate) dhcp6_slot: Arc<Mutex<Option<Arc<Mutex<dhcp6::Lease6Pool>>>>>,
    /// `None` without an encrypted listener.
    pub(crate) tls_slots: Arc<Mutex<Option<Arc<TlsSlots>>>>,
    pub(crate) vendor_db: Arc<ArcSwap<mac::VendorDb>>,
    /// Resolves the host names in the server's own HTTP requests.
    pub(crate) blocklist_resolver_slot: Arc<Mutex<http::HostResolver>>,
    /// Resolves the OCSP and CRL hosts of upstream certificates.
    pub(crate) revocation_resolver_slot: Arc<Mutex<http::HostResolver>>,
    /// `None` until the chain is built.
    pub(crate) cache_slot: Arc<Mutex<Option<cache::CacheHandle>>>,
}

/// What `prepare` built, not yet in the running state. The steps are separate functions so
/// their locals do not pile up in one frame; dashboard connection threads have small stacks.
struct Prepared {
    /// `None` when no group changes it.
    native_state: Option<NativeHotState>,
    listeners: Option<SecondaryRestart>,
    raft: Option<SecondaryRestart>,
    lease_sync: Option<SecondaryRestart>,
    /// `None` when the dashboard address is unchanged.
    rebind: Option<SecondaryRestart>,
    chain: Option<ChainRebuild>,
    tls: Option<(PreparedTls, Arc<TlsSlots>)>,
    filter: Option<onetdns_filter::BlockEngine>,
    forward: Option<(Arc<dyn native::Resolver>, onetdns_forward::ForwardStats)>,
    /// `None` until the query handler exists.
    native: Option<native::NativeFeatures>,
    policy: Option<Arc<onetdns_policy::PolicyEngine>>,
    views: Option<Vec<native::NativeView>>,
    users: Option<Vec<onetdns_control::UserCred>>,
    /// Taken by `run_effects`.
    authority: Option<PreparedAuthority>,
    notify_targets: Option<NotifyTargets>,
}

struct PreparedAuthority {
    settings: native::AuthoritySettings,
    /// The store that was running when `store` was built.
    seen: Arc<onetdns_authority::ZoneStore>,
    store: onetdns_authority::ZoneStore,
}

struct Effects {
    chain: Option<PreparedChain>,
}

/// Groups that need the query handler state. Cluster is one because the DNS Cookie server
/// secret derives from the cluster secret.
fn needs_native_state(groups: &[ApplyGroup]) -> bool {
    groups.iter().any(|group| {
        matches!(
            *group,
            ApplyGroup::Chain
                | ApplyGroup::Cluster
                | ApplyGroup::Forward
                | ApplyGroup::Native
                | ApplyGroup::Policy
                | ApplyGroup::Views
                | ApplyGroup::BlockTtl
                | ApplyGroup::LocalTtl
        )
    })
}

/// One hot apply for each way a change can reach the filter.
pub(crate) struct HotAppliers {
    pub(crate) wait: HotConfigApply,
    pub(crate) background: HotConfigApply,
}

pub(crate) fn build(deps: HotApplyDeps) -> HotAppliers {
    let deps = Arc::new(deps);
    let applier = |filter_apply: FilterApply| -> HotConfigApply {
        let deps = Arc::clone(&deps);
        Arc::new(move |next: &Config, _requested_changed: &[String]| deps.apply(next, filter_apply))
    };
    HotAppliers {
        wait: applier(FilterApply::Wait),
        background: applier(FilterApply::Background),
    }
}

impl HotApplyDeps {
    /// Returns false when the change needs a restart.
    fn apply(
        &self,
        next: &Config,
        filter_apply: FilterApply,
    ) -> Result<(bool, Vec<String>), String> {
        let _runtime_update_guard = runtime_config_update_lock().lock_recover();
        let previous_cfg = self.runtime_cfg.load();

        // Defaults filled in at startup are not in the file; comparing with the file alone would
        // read them as removed and close the untouched dashboard listener.
        let next = &normalize_config_for_comparison(&previous_cfg, next);

        let changed = config_changed_keys(&previous_cfg, next);
        if !service_restart_keys(&previous_cfg, next, &changed).is_empty() {
            return Ok((false, changed));
        }

        let groups = hot_reload_groups(&previous_cfg, next, &changed);

        // Only a build can tell whether a list file is usable, so those changes wait for one.
        let defer_filter = filter_apply == FilterApply::Background
            && groups.contains(&ApplyGroup::Filter)
            && !changed
                .iter()
                .any(|key| matches!(key.as_str(), "blocklists" | "allowlists"));
        let _filter_build = (groups.contains(&ApplyGroup::Filter) && !defer_filter)
            .then(|| self.filters.build_lock.lock_recover());

        // hot-apply:begin
        let Some(prepared) = self.prepare(&previous_cfg, next, &groups, defer_filter)? else {
            return Ok((false, changed));
        };
        let mut prepared = prepared;
        let effects = self.run_effects(&previous_cfg, next, &groups, &mut prepared)?;
        self.commit(next, &groups, &changed, *prepared, effects);
        // hot-apply:end

        // A dashboard address or storage file can appear or vanish here, and without a new
        // generation the startup decision would otherwise stay.
        self.recorder.set_collecting(telemetry_consumed(next));
        onetdns_core::info!(
            event = "config.runtime_hot_applied",
            changed = changed.len(),
            keys = ?changed,
            "Updated the running configuration"
        );
        Ok((true, changed))
    }

    /// Builds everything from `next` without touching running state. `None` asks for a restart
    /// because a restart hook is not set up yet.
    fn prepare(
        &self,
        previous: &Config,
        next: &Config,
        groups: &[ApplyGroup],
        defer_filter: bool,
    ) -> Result<Option<Box<Prepared>>, String> {
        let HotApplyDeps {
            restarts:
                RestartHooks {
                    chain: chain_rebuild,
                    lease_sync: lease_sync_restart,
                    raft: raft_restart,
                    listeners: listener_sync,
                    control: control_rebind,
                    ..
                },
            zones:
                ZoneState {
                    store: zone_store,
                    journal: zone_journal,
                    ..
                },
            filters:
                FilterState {
                    sub_meta,
                    rpz_texts,
                    compiled_filter_cache,
                    subscription_cache_dir,
                    ..
                },
            forward_stats,
            native_hot_state,
            tls_slots,
            ..
        } = self;

        let native_state = native_hot_state.lock_recover().clone();
        if native_state.is_none() && needs_native_state(groups) {
            return Ok(None);
        }
        let listeners = if groups.contains(&ApplyGroup::Listeners) {
            let Some(sync) = listener_sync.lock_recover().clone() else {
                return Ok(None);
            };
            Some(sync)
        } else {
            None
        };
        let raft = if groups.contains(&ApplyGroup::Cluster) {
            let Some(restart) = raft_restart.lock_recover().clone() else {
                return Ok(None);
            };
            Some(restart)
        } else {
            None
        };
        let chain = if groups.contains(&ApplyGroup::Chain) {
            let Some(chain) = chain_rebuild.lock_recover().clone() else {
                return Ok(None);
            };
            Some(chain)
        } else {
            None
        };
        let rebind = if groups.contains(&ApplyGroup::ControlTokens)
            && next.control_listen != previous.control_listen
        {
            Some(
                control_rebind
                    .lock_recover()
                    .clone()
                    .ok_or("The dashboard listener is not ready yet")?,
            )
        } else {
            None
        };
        let lease_sync = if groups
            .iter()
            .any(|group| matches!(*group, ApplyGroup::Cluster | ApplyGroup::ControlTokens))
        {
            lease_sync_restart.lock_recover().clone()
        } else {
            None
        };

        // No slot means no listener uses the certificate yet; opening one later builds it from the
        // config of that time.
        let slots = tls_slots.lock_recover().clone();
        let tls = match slots {
            Some(slots) if groups.contains(&ApplyGroup::Tls) => {
                Some((TlsSlots::prepare(next)?, slots))
            }
            _ => None,
        };
        let filter = if defer_filter {
            validate_filter_config(next)?;
            None
        } else if groups.contains(&ApplyGroup::Filter) {
            let subscriptions = sub_meta.lock_recover().clone();
            let rpz_texts_snapshot = rpz_texts.lock_recover().clone();
            Some(build_filter_engine_for_config(
                next,
                &FilterBuildInputs {
                    blocked_services: &next.blocked_services,
                    subscriptions: &subscriptions,
                    overlay_block: &next.block_rules,
                    overlay_allow: &next.allow_rules,
                    refused_domains: &next.refused_domains,
                    rpz_texts: &rpz_texts_snapshot,
                    compiled_filter_cache: compiled_filter_cache.as_deref(),
                    subscription_cache_dir: subscription_cache_dir.as_deref(),
                },
            )?)
        } else {
            None
        };
        let forward = if backend_uses_forward(next.backend)
            && (groups.contains(&ApplyGroup::Forward) || !backend_uses_forward(previous.backend))
        {
            let (resolver, stats) = build_forward_backend(next)?;
            if let Some(previous) = forward_stats.lock_recover().as_ref() {
                stats.seed(&previous.snapshot());
            }
            Some((resolver, stats))
        } else {
            None
        };
        let native = match &native_state {
            Some(state) => Some(build_native_features(
                next,
                Some((previous, &state.features.load())),
            )?),
            None => None,
        };
        let policy = if groups.contains(&ApplyGroup::Policy) {
            Some(Arc::new(build_policy_engine(next)?))
        } else {
            None
        };
        let views = if groups.contains(&ApplyGroup::Views) {
            Some(build_views(next)?)
        } else {
            None
        };
        let users = if groups.contains(&ApplyGroup::ConsoleAccounts) {
            Some(build_user_creds(next)?)
        } else {
            None
        };
        let mut notify_targets = None;
        let authority = if groups.contains(&ApplyGroup::Authority) {
            let settings = build_authority_settings(next)?;
            notify_targets = Some(NotifyTargets::from_config(
                &next.notify,
                &settings.tsig_keys,
            )?);
            // If the store changes before the swap, a dynamic update came in; `run_effects`
            // rebuilds rather than drop it.
            let (seen, store) = {
                let _journals = zone_journal.lock_recover();
                (
                    zone_store.load(),
                    build_zone_store(next, &settings.tsig_keys, &settings.zone_signers)?,
                )
            };
            Some(PreparedAuthority {
                settings,
                seen,
                store,
            })
        } else {
            None
        };
        Ok(Some(Box::new(Prepared {
            native_state,
            listeners,
            raft,
            lease_sync,
            rebind,
            chain,
            tls,
            filter,
            forward,
            native,
            policy,
            views,
            users,
            authority,
            notify_targets,
        })))
    }

    /// Restarts work under `next` and undoes what already restarted if any of it fails. The zone
    /// store is swapped here because zone watchers and secondaries start against the new store.
    fn run_effects(
        &self,
        previous: &Config,
        next: &Config,
        groups: &[ApplyGroup],
        prepared: &mut Prepared,
    ) -> Result<Effects, String> {
        let HotApplyDeps {
            restarts:
                RestartHooks {
                    secondary: secondary_restart,
                    zsk_rollover: zsk_rollover_restart,
                    ..
                },
            zones:
                ZoneState {
                    store: zone_store,
                    journal: zone_journal,
                    watchers: zone_watchers,
                    notify: zone_notify,
                    signers: zone_signers,
                },
            native_hot_state,
            stats,
            zone_shutdown,
            zone_threads,
            edge_services,
            dhcp_slot,
            dhcp6_slot,
            ..
        } = self;

        let mut undo = Undo::default();
        if groups.contains(&ApplyGroup::EdgeServices) {
            undo.push(|| reconcile_edge_services(previous, edge_services, dhcp_slot, dhcp6_slot));
            undo.check(reconcile_edge_services(
                next,
                edge_services,
                dhcp_slot,
                dhcp6_slot,
            ))?;
            onetdns_core::info!(
                event = "edge.reloaded",
                "Restarted DHCP services without stopping DNS"
            );
        }
        // The chain reads the DHCP lease pool, so it is built after DHCP is reconciled.
        let chain = match &prepared.chain {
            Some(chain) => {
                Some(undo.check(chain.chain.prepare(&resolver_chain::ChainPlan::new(next)))?)
            }
            None => None,
        };
        if let Some(sync) = &prepared.listeners {
            undo.push(|| sync(previous));
            undo.check(sync(next))?;
            onetdns_core::info!(
                event = "listener.reloaded",
                plain = next.listen.len(),
                "Matched listening addresses to the configuration; unchanged addresses stayed up"
            );
        }
        if let Some(restart) = &prepared.raft {
            undo.push(|| restart(previous));
            undo.check(restart(next))?;
            onetdns_core::info!(
                event = "cluster.reloaded",
                raft = next.cluster_raft,
                peers = next.cluster_raft_peers.len(),
                "Restarted clustering without stopping DNS"
            );
        }
        if let Some(sync) = &prepared.lease_sync {
            undo.push(|| sync(previous));
            undo.check(sync(next))?;
        }
        if let Some(rebind) = &prepared.rebind {
            undo.push(|| rebind(previous));
            undo.check(rebind(next))?;
        }
        if groups.contains(&ApplyGroup::Persistence) {
            fn storage_error(error: std::io::Error) -> String {
                format!("Could not apply the statistics or query log storage settings: {error}")
            }
            undo.push(|| {
                stats
                    .reconfigure_persist(persist_opts(previous))
                    .map_err(storage_error)
            });
            undo.check(
                stats
                    .reconfigure_persist(persist_opts(next))
                    .map_err(storage_error),
            )?;
        }
        let Some(PreparedAuthority {
            settings,
            seen,
            store,
        }) = prepared.authority.take()
        else {
            return Ok(Effects { chain });
        };
        // Access settings and zones change under one lock; swapping zones first would let a dynamic
        // update write through the old journal path and overwrite the wrong file.
        let native = native_hot_state.lock_recover().clone();
        {
            let mut journals = zone_journal.lock_recover();
            let store = if Arc::ptr_eq(&zone_store.load(), &seen) {
                store
            } else {
                undo.check(build_zone_store(
                    next,
                    &settings.tsig_keys,
                    &settings.zone_signers,
                ))?
            };
            let old_store = zone_store.load();
            let old_signers = zone_signers.load();
            let old_authority = native.as_ref().map(|state| state.authority.load());
            let authority_slot = native.as_ref().map(|state| state.authority.clone());
            undo.push(|| {
                let mut journals = zone_journal.lock_recover();
                zone_signers.store(old_signers);
                if let (Some(slot), Some(old)) = (authority_slot, old_authority) {
                    slot.store(old);
                }
                replace_zone_store(zone_store, &mut journals, old_store);
                Ok(())
            });
            zone_signers.store(Arc::new(settings.zone_signers.clone()));
            if let Some(state) = native.as_ref() {
                state.authority.store(Arc::new(settings));
            }
            replace_zone_store(zone_store, &mut journals, Arc::new(store));
        }
        let watch = |cfg: &Config| {
            reconcile_zone_watchers(
                cfg,
                zone_watchers,
                zone_store,
                zone_journal,
                zone_notify,
                zone_shutdown,
                zone_threads,
            )
        };
        undo.push(move || watch(previous));
        undo.check(watch(next))?;
        for slot in [secondary_restart, zsk_rollover_restart] {
            if let Some(restart) = slot.lock_recover().clone() {
                let undo_restart = restart.clone();
                undo.push(move || undo_restart(previous));
                undo.check(restart(next))?;
            }
        }
        Ok(Effects { chain })
    }

    /// Only puts prepared parts into their slots, so it cannot fail.
    fn commit(
        &self,
        next: &Config,
        groups: &[ApplyGroup],
        changed: &[String],
        prepared: Prepared,
        effects: Effects,
    ) {
        let HotApplyDeps {
            zones: ZoneState {
                notify: zone_notify,
                ..
            },
            filters:
                FilterState {
                    filter,
                    overlay,
                    service_set,
                    refused_domains,
                    safe_search,
                    sub_meta,
                    subscription_cache_dir,
                    sub_urls,
                    sub_titles,
                    sub_disabled,
                    preset_urls,
                    rpz_urls: rpz_url_state,
                    list_refresh_secs,
                    list_generation,
                    deferred_rebuild,
                    ..
                },
            console_auth,
            control_proxy,
            runtime_cfg,
            acl_state,
            rate_state,
            recorder,
            forward_slot,
            forward_stats,
            native_hot_state,
            dhcp_slot,
            vendor_db,
            blocklist_resolver_slot,
            revocation_resolver_slot,
            cache_slot,
            ..
        } = self;
        let Prepared {
            native_state,
            chain,
            tls,
            filter: prepared_filter,
            forward,
            native,
            policy,
            views,
            users,
            notify_targets,
            ..
        } = prepared;

        if let Some((prepared, slots)) = tls {
            slots.install(prepared);
            onetdns_core::info!(
                event = "tls.certificate_reloaded",
                "Replaced the TLS certificate without closing listening addresses"
            );
        }
        if groups
            .iter()
            .any(|group| matches!(*group, ApplyGroup::Chain | ApplyGroup::Forward))
        {
            *blocklist_resolver_slot.lock_recover() = blocklist_host_resolver(next);
            *revocation_resolver_slot.lock_recover() = revocation_host_resolver(next);
        }
        if groups.contains(&ApplyGroup::ControlTokens) {
            if let Some(auth) = console_auth.lock_recover().as_ref() {
                let mut admin = next.control_admin_tokens.clone();
                if !next.control_token.is_empty() {
                    admin.push(next.control_token.clone());
                }
                auth.replace_tokens(admin, next.control_readonly_tokens.clone());
            }
            control_proxy.store(Arc::new(crate::control_proxy_policy(next)));
            onetdns_core::info!(
                event = "control.tokens_reloaded",
                "Updated the control token without stopping DNS"
            );
        }
        if groups.contains(&ApplyGroup::MacVendor) {
            vendor_db.store(Arc::new(mac::VendorDb::load(next.mac_vendor_db.as_deref())));
        }
        if groups.contains(&ApplyGroup::DnssecClock) {
            onetdns_dnssec::set_accept_expired(next.dnssec_accept_expired);
        }
        if groups.contains(&ApplyGroup::Subscriptions) {
            *sub_urls.lock_recover() = next.blocklist_urls.clone();
            let mut titles = next.blocklist_titles.clone();
            titles.resize(next.blocklist_urls.len(), String::new());
            *sub_titles.lock_recover() = titles;
            *sub_disabled.lock_recover() = next.disabled_blocklist_urls.clone();
            *preset_urls.lock_recover() = preset_list_urls(next);
            *rpz_url_state.lock_recover() = next.rpz_urls.clone();
            list_refresh_secs.store(next.list_refresh_secs, Ordering::Release);
            // A new generation makes the refresh threads fetch on their next tick.
            list_generation.fetch_add(1, Ordering::AcqRel);
            onetdns_core::info!(
                event = "filter.subscriptions_reloaded",
                lists = next.blocklist_urls.len(),
                rpz = next.rpz_urls.len(),
                "Changed blocklist subscriptions without interrupting DNS"
            );
        }
        let filter_changed = groups.contains(&ApplyGroup::Filter);
        let filter_deferred = filter_changed && prepared_filter.is_none();
        if filter_changed {
            *overlay.lock_recover() = (next.block_rules.clone(), next.allow_rules.clone());
            *service_set.lock_recover() = next.blocked_services.clone();
            *refused_domains.lock_recover() = next.refused_domains.clone();
        }
        if let Some(engine) = prepared_filter {
            let counts = (engine.block_count(), engine.allow_count());
            filter.store(Arc::new(engine));
            if let Some(dir) = subscription_cache_dir.as_deref() {
                release_subscription_lines(sub_meta, dir);
            }
            onetdns_core::info!(
                event = "filter.rebuilt",
                block = counts.0,
                allow = counts.1,
                "Replaced filter rules with the new configuration"
            );
        }
        if let Some((resolver, stats)) = forward {
            forward_slot.replace(resolver);
            *forward_stats.lock_recover() = Some(stats);
        }
        if let Some(state) = &native_state {
            if groups.contains(&ApplyGroup::BlockTtl) {
                state
                    .block_ttl
                    .store(next.blocked_response_ttl, Ordering::Release);
            }
            if groups.contains(&ApplyGroup::LocalTtl) {
                state.local_ttl.store(next.local_ttl, Ordering::Release);
            }
        }
        if groups.contains(&ApplyGroup::Acl) {
            acl_state.replace(runtime_access_control(next));
        }
        if groups.contains(&ApplyGroup::RateLimit) {
            rate_state.replace(runtime_rate_limiters(next));
        }
        if groups.contains(&ApplyGroup::QueryLog) {
            recorder.reconfigure(
                next.querylog,
                next.anonymize_client_ip,
                next.querylog_ignored.clone(),
                next.querylog_size.max(1),
                next.querylog_retention_secs,
                next.stats_retention_secs,
            );
        }
        if groups.contains(&ApplyGroup::SafeSearch) {
            safe_search.store(next.safe_search, Ordering::Release);
        }
        if groups.contains(&ApplyGroup::Log) {
            onetdns_core::log::set_level_str(next.log_level.as_deref().unwrap_or("info"));
        }
        if groups.contains(&ApplyGroup::QuerySource) {
            onetdns_forward::set_query_source(next.query_source, next.query_source_v6);
        }
        if groups.contains(&ApplyGroup::Revocation) {
            install_revocation_policy(next, revocation_resolver_slot);
        }
        if let Some(targets) = notify_targets {
            zone_notify.replace_targets(targets);
            onetdns_core::info!(
                event = "authority.reloaded",
                zones = next.zones.len(),
                "Replaced the DNS zone configuration without interrupting DNS"
            );
        }

        runtime_cfg.store(Arc::new(next.clone()));
        if filter_deferred {
            deferred_rebuild.request();
        }
        let chain_generation = match (chain, effects.chain) {
            (Some(chain), Some(prepared)) => {
                let installed = chain.chain.install(prepared);
                chain.slot.replace(installed.resolver);
                onetdns_core::info!(
                    event = "chain.rebuilt",
                    "Rebuilt and swapped the resolver chain; DNS kept answering"
                );
                Some((installed.cache, installed.recursor))
            }
            _ => None,
        };

        // The fast path state is published once, after every state that changes answers. Showing
        // the chain generation first would cache answers made under old conditions; bumping the
        // wire generation first would tag entries built from old state as new. The gates are
        // rechecked whatever changed, since the keys that close a path span several groups.
        let native_state = native_state.or_else(|| native_hot_state.lock_recover().clone());
        if let Some(state) = native_state {
            let local_only_changed = native.is_some()
                && changed
                    .iter()
                    .any(|key| LOCAL_ONLY_CONFIG_KEYS.contains(&key.as_str()));
            if native.is_some() {
                state
                    .local_only_names
                    .set(next.domain_needed, next.bogus_priv, next.empty_zones);
            }
            if let Some(policy) = policy {
                state.policy.store(policy);
            }
            if let Some(views) = views {
                state.views.store(Arc::new(views));
            }
            let current = state.features.load();
            let mut features = native.unwrap_or_else(|| (*current).clone());
            match chain_generation {
                Some((cache, recursor)) => features.adopt_chain(
                    wirecache::WireEntryFactory::new(next.min_ttl as u32, next.max_ttl as u32),
                    cache,
                    recursor,
                ),
                None => features.lane_runtime = current.lane_runtime.clone(),
            }
            features.lanes = evaluate_lane_gates(
                next,
                &LaneFacts {
                    dhcp_pool: dhcp_slot.lock_recover().is_some(),
                    views_present: state.views.present(),
                    policy_present: state.policy.present(),
                },
            );
            let responses_changed = groups.iter().any(|group| {
                matches!(
                    *group,
                    ApplyGroup::Chain
                        | ApplyGroup::Forward
                        | ApplyGroup::Native
                        | ApplyGroup::Policy
                        | ApplyGroup::Views
                        | ApplyGroup::LocalTtl
                )
            });
            features.wire_epoch = if responses_changed {
                current.wire_epoch.wrapping_add(1)
            } else {
                current.wire_epoch
            };
            let lanes = features.lanes;
            state.features.store(Arc::new(features));
            if lanes != current.lanes {
                onetdns_core::debug!(
                    event = "do53.lane_switch",
                    wire = lanes.wire,
                    authority = lanes.authority,
                    reactor = lanes.reactor,
                    "Reopened and closed fast paths for the changed configuration"
                );
            }
            // Flush after publishing; flushing first lets a lane still on the old conditions refill
            // the cache.
            if local_only_changed {
                let flushed = cache_slot
                    .lock_recover()
                    .as_ref()
                    .map(|cache| cache.clear())
                    .unwrap_or(0);
                onetdns_core::info!(
                    event = "cache.flushed_for_local_only",
                    flushed,
                    "Cleared the response cache because local-only name handling changed"
                );
            }
        }

        if let Some(users) = users {
            if let Some(auth) = console_auth.lock_recover().as_ref() {
                auth.replace_users(users);
            }
            onetdns_core::info!(
                event = "console.accounts_reloaded",
                accounts = next.users.len(),
                "Updated dashboard accounts without interrupting DNS"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Undo;
    use std::cell::RefCell;

    #[test]
    /// Undoing in registration order would overlap later listeners or jobs with the earlier
    /// ones' old state, and one failed step must not stop the rest.
    fn failure_runs_every_undo_in_reverse() {
        let order = RefCell::new(Vec::new());
        let mut undo = Undo::default();
        undo.push(|| {
            order.borrow_mut().push("edge");
            Ok(())
        });
        undo.push(|| {
            order.borrow_mut().push("listeners");
            Err("port busy".to_string())
        });
        assert_eq!(undo.check(Ok::<_, String>(7)), Ok(7));
        assert!(order.borrow().is_empty());
        undo.push(|| {
            order.borrow_mut().push("cluster");
            Ok(())
        });

        let error = undo
            .check(Err::<(), _>("raft failed".to_string()))
            .unwrap_err();
        assert_eq!(*order.borrow(), ["cluster", "listeners", "edge"]);
        assert_eq!(
            error,
            "raft failed; restoring the previous configuration also failed: port busy"
        );
        assert!(undo.check(Err::<(), _>("again".to_string())).is_err());
        assert_eq!(order.borrow().len(), 3);
    }
}
