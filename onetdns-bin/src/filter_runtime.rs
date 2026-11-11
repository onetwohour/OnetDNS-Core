//! The filter engine and its inputs for one generation, and the jobs that refresh and rebuild it.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use onetdns_config::Config;
use onetdns_core::{ArcSwap, MutexExt};
use onetdns_filter::{BlockEngine, SharedFilter};

use crate::atomic_file::with_rollback_result;
use crate::config_apply::FilterRebuild;
use crate::error::{BoxResult, Context};
use crate::filters::{
    active_subscription_urls, build_filter_engine_for_config, fetch_blocklists_meta,
    fetch_rpz_texts, load_blocklist_cache, load_rpz_cache, preset_list_urls,
    release_subscription_lines, rpz_texts_by_url, service_blocking_paused, try_list_refresh_lock,
    FilterBuildInputs, SubMeta, LIST_REFRESH_BUSY, LIST_REFRESH_TICK_SECS,
    SERVICE_SCHEDULE_TICK_SECS,
};
use crate::native_config::map_block;
use crate::{http, sleep_or_shutdown, ServiceCleanup};

/// Downloads the subscribed lists and rebuilds; returns the block and allow rule counts.
pub(crate) type ListRefresh =
    Arc<dyn Fn() -> Result<(usize, usize), String> + Send + Sync + 'static>;

/// How long a requested rebuild waits for more changes, so a burst costs one build.
const DEFERRED_REBUILD_SETTLE: Duration = Duration::from_millis(250);
/// How often the idle worker checks for shutdown.
const DEFERRED_REBUILD_POLL: Duration = Duration::from_millis(500);

#[derive(Default)]
struct DeferredState {
    queued: bool,
    running: bool,
    /// Why the latest build failed; the running filter stays as it was.
    error: Option<String>,
}

/// Rebuilds the filter after a change was saved and answered. Requests made while a build runs
/// merge into one later build, which reads the newest inputs.
#[derive(Default)]
pub(crate) struct DeferredRebuild {
    state: Mutex<DeferredState>,
    wake: Condvar,
}

impl DeferredRebuild {
    pub(crate) fn request(&self) {
        self.state.lock_recover().queued = true;
        self.wake.notify_all();
    }

    pub(crate) fn status_json(&self) -> String {
        let state = self.state.lock_recover();
        let error = state
            .error
            .as_deref()
            .map_or_else(|| "null".to_string(), onetdns_core::json::escape);
        format!(
            "{{\"pending\":{},\"error\":{error}}}",
            state.queued || state.running
        )
    }

    /// False once `shutdown` is set.
    fn wait_for_request(&self, shutdown: &AtomicBool) -> bool {
        let mut state = self.state.lock_recover();
        loop {
            if shutdown.load(Ordering::Relaxed) {
                return false;
            }
            if state.queued {
                return true;
            }
            state = match self.wake.wait_timeout(state, DEFERRED_REBUILD_POLL) {
                Ok((state, _)) => state,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }

    fn run(
        &self,
        rebuild: &dyn Fn() -> Result<(usize, usize), String>,
        shutdown: &AtomicBool,
        settle: Duration,
    ) {
        while self.wait_for_request(shutdown) {
            std::thread::sleep(settle);
            {
                let mut state = self.state.lock_recover();
                state.queued = false;
                state.running = true;
            }
            // A panic must not leave `running` set, or the dashboard waits forever.
            let result = catch_unwind(AssertUnwindSafe(rebuild))
                .unwrap_or_else(|_| Err("The filter build stopped unexpectedly".to_string()));
            if let Err(error) = &result {
                onetdns_core::warn!(
                    event = "filter.deferred_rebuild_failed",
                    %error,
                    "Could not apply saved filter changes; keeping the previous filter"
                );
            }
            let mut state = self.state.lock_recover();
            state.running = false;
            state.error = result.err();
        }
    }
}

/// The filter engine and its inputs. Every field is a shared handle, so clones see one state.
#[derive(Clone)]
pub(crate) struct FilterState {
    pub(crate) filter: Arc<SharedFilter>,
    /// Block and allow rules added through the management API.
    pub(crate) overlay: Arc<Mutex<(Vec<String>, Vec<String>)>>,
    pub(crate) service_set: Arc<Mutex<Vec<String>>>,
    pub(crate) refused_domains: Arc<Mutex<Vec<String>>>,
    pub(crate) safe_search: Arc<AtomicBool>,
    pub(crate) sub_urls: Arc<Mutex<Vec<String>>>,
    /// Same length as `sub_urls`.
    pub(crate) sub_titles: Arc<Mutex<Vec<String>>>,
    pub(crate) sub_disabled: Arc<Mutex<Vec<String>>>,
    pub(crate) sub_meta: Arc<Mutex<Vec<SubMeta>>>,
    pub(crate) preset_urls: Arc<Mutex<Vec<String>>>,
    pub(crate) rpz_urls: Arc<Mutex<Vec<String>>>,
    pub(crate) rpz_texts: Arc<Mutex<Vec<String>>>,
    /// `None` without a config file.
    pub(crate) compiled_filter_cache: Option<PathBuf>,
    /// `None` without a config file.
    pub(crate) subscription_cache_dir: Option<PathBuf>,
    pub(crate) list_refresh_secs: Arc<AtomicU64>,
    /// Bumped when the lists change, so the refresh jobs fetch without waiting for their period.
    pub(crate) list_generation: Arc<AtomicU64>,
    /// Lets one job at a time change the downloaded lists.
    pub(crate) list_refresh_lock: Arc<Mutex<()>>,
    /// Held for a whole build, so a build that started earlier cannot replace a newer engine.
    pub(crate) build_lock: Arc<Mutex<()>>,
    pub(crate) rebuild: FilterRebuild,
    pub(crate) deferred_rebuild: Arc<DeferredRebuild>,
    pub(crate) refresh_url_lists: ListRefresh,
}

impl FilterState {
    /// Installs the first engine from the cached lists and starts the background jobs.
    pub(crate) fn start(
        cfg: &Config,
        runtime_cfg: &Arc<ArcSwap<Config>>,
        config_path: Option<&Path>,
        blocklist_resolver: &http::HostResolver,
        shutdown: &Arc<AtomicBool>,
        service_cleanup: &ServiceCleanup,
    ) -> BoxResult<Self> {
        let block_response = map_block(cfg);
        let blocklist_cache_dir = config_path
            .and_then(|p| p.parent())
            .map(|p| p.join("blocklist-cache"));
        let compiled_filter_cache = blocklist_cache_dir
            .as_ref()
            .map(|dir| dir.join("compiled-filter.bin"));

        let cached_rpz_texts = load_rpz_cache(&cfg.rpz_urls, blocklist_cache_dir.as_deref());
        let all_rpz_cached = !cfg.rpz_urls.is_empty()
            && cached_rpz_texts.len() == cfg.rpz_urls.len()
            && cached_rpz_texts.iter().all(|text| !text.is_empty());
        let rpz_texts: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(cached_rpz_texts));
        let overlay: Arc<Mutex<(Vec<String>, Vec<String>)>> = Arc::new(Mutex::new((
            cfg.block_rules.clone(),
            cfg.allow_rules.clone(),
        )));
        let refused_domains_state: Arc<Mutex<Vec<String>>> =
            Arc::new(Mutex::new(cfg.refused_domains.clone()));
        let filter = Arc::new(SharedFilter::from_pointee(BlockEngine::empty(
            block_response,
        )));

        let service_set: Arc<Mutex<Vec<String>>> =
            Arc::new(Mutex::new(cfg.blocked_services.clone()));

        let sub_meta: Arc<Mutex<Vec<SubMeta>>> = Arc::new(Mutex::new(vec![]));
        let build_lock = Arc::new(Mutex::new(()));
        let rebuild: FilterRebuild = {
            let build_lock = build_lock.clone();
            let filter = filter.clone();
            let runtime_cfg = runtime_cfg.clone();
            let service_set = service_set.clone();
            let sub_meta = sub_meta.clone();
            let rpz_texts = rpz_texts.clone();
            let overlay = overlay.clone();
            let refused_domains = refused_domains_state.clone();
            let compiled_filter_cache = compiled_filter_cache.clone();
            let subscription_cache_dir = blocklist_cache_dir.clone();
            Arc::new(move || -> Result<(usize, usize), String> {
                let _build = build_lock.lock_recover();
                let current = runtime_cfg.load();
                let subscriptions = sub_meta.lock_recover().clone();
                let (overlay_block, overlay_allow) = {
                    let overlay = overlay.lock_recover();
                    (overlay.0.clone(), overlay.1.clone())
                };
                let blocked_services = service_set.lock_recover().clone();
                let refused_domains = refused_domains.lock_recover().clone();
                let rpz_texts_snapshot = rpz_texts.lock_recover().clone();
                let engine = build_filter_engine_for_config(
                    &current,
                    &FilterBuildInputs {
                        blocked_services: &blocked_services,
                        subscriptions: &subscriptions,
                        overlay_block: &overlay_block,
                        overlay_allow: &overlay_allow,
                        refused_domains: &refused_domains,
                        rpz_texts: &rpz_texts_snapshot,
                        compiled_filter_cache: compiled_filter_cache.as_deref(),
                        subscription_cache_dir: subscription_cache_dir.as_deref(),
                    },
                )?;
                if let Some(dir) = subscription_cache_dir.as_deref() {
                    release_subscription_lines(&sub_meta, dir);
                }
                let counts = (engine.block_count(), engine.allow_count());
                filter.store(Arc::new(engine));
                Ok(counts)
            })
        };

        let sub_urls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(cfg.blocklist_urls.clone()));
        let mut configured_titles = cfg.blocklist_titles.clone();
        configured_titles.resize(cfg.blocklist_urls.len(), String::new());
        configured_titles.truncate(cfg.blocklist_urls.len());
        let sub_titles: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(configured_titles));
        let sub_disabled: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(
            cfg.disabled_blocklist_urls
                .iter()
                .filter(|url| {
                    cfg.blocklist_urls
                        .iter()
                        .any(|configured| configured == *url)
                })
                .cloned()
                .collect(),
        ));
        let preset_urls = Arc::new(Mutex::new(preset_list_urls(cfg)));
        let (subscriptions_settled, had_cached_blocklists) = {
            let active = active_subscription_urls(
                &sub_urls.lock_recover(),
                &sub_disabled.lock_recover(),
                &preset_urls.lock_recover(),
            );
            let cached = load_blocklist_cache(&active, blocklist_cache_dir.as_deref());
            // With every active list cached, or none remote, there is nothing to fetch at start.
            let all_loaded = cached.len() == active.len();
            let had_cached = !cached.is_empty();
            if had_cached {
                *sub_meta.lock_recover() = cached;
            }
            (all_loaded, had_cached)
        };
        let (block, allow) = rebuild().map_err(|error| {
            crate::anyhow!(format!("Could not apply the filter policy: {error}"))
        })?;
        if had_cached_blocklists {
            onetdns_core::info!(
                event = "filter.cache_applied",
                block,
                allow,
                complete = subscriptions_settled,
                "Applied blocklists"
            );
        } else {
            onetdns_core::info!(
                event = "filter.lists_loaded",
                block,
                allow,
                services = cfg.blocked_services.len(),
                "Loaded blocklists"
            );
        }
        {
            let runtime = runtime_cfg.clone();
            let rebuild = rebuild.clone();
            let sd = shutdown.clone();
            let mut applied = service_blocking_paused(cfg, std::time::SystemTime::now());
            let thread = std::thread::Builder::new()
                .name("service-schedule".into())
                .spawn(move || loop {
                    if sleep_or_shutdown(SERVICE_SCHEDULE_TICK_SECS, &sd) {
                        break;
                    }
                    let paused =
                        service_blocking_paused(&runtime.load(), std::time::SystemTime::now());
                    if paused == applied {
                        continue;
                    }
                    match rebuild() {
                        Ok(_) => {
                            applied = paused;
                            onetdns_core::info!(
                                event = "filter.service_schedule_applied",
                                paused,
                                "Reapplied service blocking rules on schedule"
                            );
                        }
                        Err(error) => onetdns_core::warn!(
                            event = "filter.service_schedule_failed",
                            %error,
                            "Could not apply the service blocking schedule; retrying next check"
                        ),
                    }
                })
                .with_context(|| "Could not start the service blocking schedule thread")?;
            service_cleanup.track(thread);
        }
        let list_refresh_lock = Arc::new(Mutex::new(()));
        let refresh_url_lists: ListRefresh = {
            let urls = sub_urls.clone();
            let disabled_urls = sub_disabled.clone();
            let presets = preset_urls.clone();
            let sm = sub_meta.clone();
            let rebuild = rebuild.clone();
            let resolver = blocklist_resolver.clone();
            let cache_dir = blocklist_cache_dir.clone();
            let operation_lock = list_refresh_lock.clone();
            Arc::new(move || {
                let _guard = try_list_refresh_lock(&operation_lock)?;
                let snapshot = urls.lock_recover().clone();
                let disabled = disabled_urls.lock_recover().clone();
                let presets_now = presets.lock_recover().clone();
                let active = active_subscription_urls(&snapshot, &disabled, &presets_now);
                let previous_meta = sm.lock_recover().clone();
                let meta =
                    fetch_blocklists_meta(&active, &resolver, &previous_meta, cache_dir.as_deref());
                *sm.lock_recover() = meta;
                match rebuild() {
                    Ok(counts) => Ok(counts),
                    Err(error) => {
                        *sm.lock_recover() = previous_meta;
                        let error = with_rollback_result(
                            error,
                            "Could not restore the previous runtime state of URL blocklists",
                            rebuild().map(|_| ()),
                        );
                        Err(error)
                    }
                }
            })
        };
        let list_refresh_secs = Arc::new(AtomicU64::new(cfg.list_refresh_secs));
        let list_generation = Arc::new(AtomicU64::new(0));
        {
            let refresh_lists = refresh_url_lists.clone();
            let interval = list_refresh_secs.clone();
            let generation = list_generation.clone();
            let sd = shutdown.clone();
            let mut done_first = subscriptions_settled;
            let thread = std::thread::Builder::new()
                .name("blocklist-refresh".into())
                .spawn(move || {
                    let mut seen_generation = 0u64;
                    let mut waited = 0u64;
                    loop {
                        if sd.load(Ordering::Relaxed) {
                            break;
                        }
                        let period = interval.load(Ordering::Acquire);
                        let now_generation = generation.load(Ordering::Acquire);
                        let due = now_generation != seen_generation
                            || !done_first
                            || (period > 0 && waited >= period);
                        if due {
                            seen_generation = now_generation;
                            done_first = true;
                            waited = 0;
                            match refresh_lists() {
                                Ok((block, _)) => {
                                    onetdns_core::info!(event = "filter.subscription_applied", block, "Applied downloaded blocklists")
                                }
                                Err(error) if error == LIST_REFRESH_BUSY => {
                                    onetdns_core::info!(event = "filter.subscription_refresh_inflight", "A blocklist update is already running")
                                }
                                Err(error) => {
                                    onetdns_core::warn!(event = "filter.subscription_refresh_failed", %error, "Could not update remote blocklists")
                                }
                            }
                        }
                        if sleep_or_shutdown(LIST_REFRESH_TICK_SECS, &sd) {
                            break;
                        }
                        waited = waited.saturating_add(LIST_REFRESH_TICK_SECS);
                    }
                })
                .with_context(|| "Could not start the URL blocklist refresh thread")?;
            service_cleanup.track(thread);
        }

        let rpz_url_state: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(cfg.rpz_urls.clone()));
        {
            let urls = rpz_url_state.clone();
            let rpz_texts = rpz_texts.clone();
            let rebuild3 = rebuild.clone();
            let interval = list_refresh_secs.clone();
            let generation = list_generation.clone();
            let sd = shutdown.clone();
            let resolver = blocklist_resolver.clone();
            let cache_dir = blocklist_cache_dir.clone();
            let mut done_first = all_rpz_cached;
            let mut fetched_urls = cfg.rpz_urls.clone();
            let thread = std::thread::Builder::new()
                .name("rpz-refresh".into())
                .spawn(move || {
                    let mut seen_generation = 0u64;
                    let mut waited = 0u64;
                    loop {
                        if sd.load(Ordering::Relaxed) {
                            break;
                        }
                        let period = interval.load(Ordering::Acquire);
                        let now_generation = generation.load(Ordering::Acquire);
                        let due = now_generation != seen_generation
                            || !done_first
                            || (period > 0 && waited >= period);
                        let urls_now = urls.lock_recover().clone();
                        if !due || (urls_now.is_empty() && fetched_urls.is_empty()) {
                            seen_generation = now_generation;
                            if sleep_or_shutdown(LIST_REFRESH_TICK_SECS, &sd) {
                                break;
                            }
                            waited = waited.saturating_add(LIST_REFRESH_TICK_SECS);
                            continue;
                        }
                        seen_generation = now_generation;
                        done_first = true;
                        waited = 0;
                        let previous = rpz_texts.lock_recover().clone();
                        let kept = rpz_texts_by_url(&fetched_urls, &previous, &urls_now);
                        let fetched =
                            fetch_rpz_texts(&urls_now, &resolver, &kept, cache_dir.as_deref());
                        *rpz_texts.lock_recover() = fetched;
                        let previous_urls = std::mem::replace(&mut fetched_urls, urls_now);
                        match rebuild3() {
                            Ok((b, _)) => onetdns_core::info!(event = "filter.rpz_applied", block = b, "Applied downloaded RPZ rules"),
                            Err(e) => {
                                *rpz_texts.lock_recover() = previous;
                                fetched_urls = previous_urls;
                                let error = with_rollback_result(
                                    e,
                                    "Could not restore the previous RPZ runtime state",
                                    rebuild3().map(|_| ()),
                                );
                                onetdns_core::warn!(event = "filter.rpz_rebuild_failed", error = %error, "Could not rebuild RPZ rules; keeping the previous rules");
                            }
                        }
                        if sleep_or_shutdown(LIST_REFRESH_TICK_SECS, &sd) {
                            break;
                        }
                        waited = waited.saturating_add(LIST_REFRESH_TICK_SECS);
                    }
                })
                .with_context(|| "Could not start the RPZ refresh thread")?;
            service_cleanup.track(thread);
        }
        let deferred_rebuild = Arc::new(DeferredRebuild::default());
        {
            let deferred = deferred_rebuild.clone();
            let rebuild = rebuild.clone();
            let sd = shutdown.clone();
            let thread = std::thread::Builder::new()
                .name("filter-rebuild".into())
                .spawn(move || deferred.run(&*rebuild, &sd, DEFERRED_REBUILD_SETTLE))
                .with_context(|| "Could not start the filter rebuild thread")?;
            service_cleanup.track(thread);
        }
        Ok(Self {
            filter,
            overlay,
            service_set,
            refused_domains: refused_domains_state,
            safe_search: Arc::new(AtomicBool::new(cfg.safe_search)),
            sub_urls,
            sub_titles,
            sub_disabled,
            sub_meta,
            preset_urls,
            rpz_urls: rpz_url_state,
            rpz_texts,
            compiled_filter_cache,
            subscription_cache_dir: blocklist_cache_dir,
            list_refresh_secs,
            list_generation,
            list_refresh_lock,
            build_lock,
            rebuild,
            deferred_rebuild,
            refresh_url_lists,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    const NO_SETTLE: Duration = Duration::ZERO;

    /// Runs the worker until `done`, then stops it.
    fn run_until(
        deferred: &Arc<DeferredRebuild>,
        rebuild: impl Fn() -> Result<(usize, usize), String> + Send + Sync,
        done: impl Fn() -> bool,
    ) {
        let shutdown = AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| deferred.run(&rebuild, &shutdown, NO_SETTLE));
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            while !done() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "worker did not finish"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            shutdown.store(true, Ordering::Relaxed);
            deferred.wake.notify_all();
        });
    }

    fn pending(deferred: &DeferredRebuild) -> bool {
        deferred.status_json().contains("\"pending\":true")
    }

    #[test]
    fn requests_made_during_a_build_merge_into_one_later_build() {
        let deferred = Arc::new(DeferredRebuild::default());
        let builds = AtomicUsize::new(0);
        deferred.request();
        run_until(
            &deferred,
            || {
                if builds.fetch_add(1, Ordering::SeqCst) == 0 {
                    for _ in 0..5 {
                        deferred.request();
                    }
                }
                Ok((0, 0))
            },
            || builds.load(Ordering::SeqCst) >= 2 && !pending(&deferred),
        );
        assert_eq!(builds.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_failed_build_is_reported_and_the_next_success_clears_it() {
        let deferred = Arc::new(DeferredRebuild::default());
        let builds = AtomicUsize::new(0);
        deferred.request();
        run_until(
            &deferred,
            || {
                builds.fetch_add(1, Ordering::SeqCst);
                Err("bad \"rule\"".to_string())
            },
            || builds.load(Ordering::SeqCst) == 1 && !pending(&deferred),
        );
        assert_eq!(
            deferred.status_json(),
            "{\"pending\":false,\"error\":\"bad \\\"rule\\\"\"}"
        );

        deferred.request();
        run_until(
            &deferred,
            || {
                builds.fetch_add(1, Ordering::SeqCst);
                Ok((0, 0))
            },
            || builds.load(Ordering::SeqCst) == 2 && !pending(&deferred),
        );
        assert_eq!(deferred.status_json(), "{\"pending\":false,\"error\":null}");
    }

    #[test]
    fn a_panicking_build_does_not_stay_pending() {
        let deferred = Arc::new(DeferredRebuild::default());
        let builds = AtomicUsize::new(0);
        deferred.request();
        run_until(
            &deferred,
            || {
                builds.fetch_add(1, Ordering::SeqCst);
                panic!("build panicked");
            },
            || builds.load(Ordering::SeqCst) == 1 && !pending(&deferred),
        );
        assert!(deferred.status_json().contains("stopped unexpectedly"));
    }

    #[test]
    fn the_worker_stops_on_shutdown_without_a_request() {
        let deferred = Arc::new(DeferredRebuild::default());
        run_until(&deferred, || Ok((0, 0)), || true);
        assert!(!pending(&deferred));
    }
}
