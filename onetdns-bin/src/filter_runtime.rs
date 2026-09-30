/*!
 * @brief 한 세대 동안 차단 엔진과 그 재료를 들고 있는 상태와, 목록을 주기적으로 다시 받는 작업.
 *
 * @details 핫 적용과 관리 API 는 같은 재료를 고치고 같은 방법으로 엔진을 다시 만든다. 재료를
 *          한 값으로 묶어 두 쪽에 넘기므로 어느 쪽이 고친 재료든 다음 재구성에 들어간다.
 */

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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

/** @brief 구독 목록을 다시 받아 엔진을 다시 만든다. 반환값은 차단과 허용 규칙 수다. */
pub(crate) type ListRefresh =
    Arc<dyn Fn() -> Result<(usize, usize), String> + Send + Sync + 'static>;

/**
 * @brief 차단 엔진과 그 재료.
 * @details 모든 필드가 공유 핸들이므로 복제해도 같은 상태를 가리킨다.
 */
#[derive(Clone)]
pub(crate) struct FilterState {
    /** @brief 지금 쓰는 차단 엔진. */
    pub(crate) filter: Arc<SharedFilter>,
    /** @brief 관리 API 로 더한 차단과 허용 규칙. */
    pub(crate) overlay: Arc<Mutex<(Vec<String>, Vec<String>)>>,
    /** @brief 차단한 서비스 목록. */
    pub(crate) service_set: Arc<Mutex<Vec<String>>>,
    /** @brief 거부할 도메인 목록. */
    pub(crate) refused_domains: Arc<Mutex<Vec<String>>>,
    /** @brief 안전 검색을 켰는지. */
    pub(crate) safe_search: Arc<AtomicBool>,
    /** @brief 구독 주소. */
    pub(crate) sub_urls: Arc<Mutex<Vec<String>>>,
    /** @brief 구독 제목. 구독 주소와 길이가 같다. */
    pub(crate) sub_titles: Arc<Mutex<Vec<String>>>,
    /** @brief 꺼 둔 구독 주소. */
    pub(crate) sub_disabled: Arc<Mutex<Vec<String>>>,
    /** @brief 구독별로 받은 결과. */
    pub(crate) sub_meta: Arc<Mutex<Vec<SubMeta>>>,
    /** @brief 미리 정해 둔 목록 주소. */
    pub(crate) preset_urls: Arc<Mutex<Vec<String>>>,
    /** @brief RPZ 구독 주소. */
    pub(crate) rpz_urls: Arc<Mutex<Vec<String>>>,
    /** @brief 받아 둔 RPZ 본문. */
    pub(crate) rpz_texts: Arc<Mutex<Vec<String>>>,
    /** @brief 컴파일한 차단 엔진을 저장하는 파일. 설정 파일이 없으면 없다. */
    pub(crate) compiled_filter_cache: Option<PathBuf>,
    /** @brief 받은 목록을 저장하는 디렉터리. 설정 파일이 없으면 없다. */
    pub(crate) subscription_cache_dir: Option<PathBuf>,
    /** @brief 목록을 다시 받는 주기. */
    pub(crate) list_refresh_secs: Arc<AtomicU64>,
    /** @brief 목록 구성이 바뀔 때마다 올린다. 갱신 작업은 주기를 기다리지 않고 바로 받는다. */
    pub(crate) list_generation: Arc<AtomicU64>,
    /** @brief 목록 받기를 한 번에 하나만 하게 하는 잠금. */
    pub(crate) list_refresh_lock: Arc<Mutex<()>>,
    /** @brief 지금 재료로 엔진을 다시 만든다. */
    pub(crate) rebuild: FilterRebuild,
    /** @brief 구독 목록을 다시 받아 엔진을 다시 만든다. */
    pub(crate) refresh_url_lists: ListRefresh,
}

impl FilterState {
    /**
     * @brief 받아 둔 사본으로 첫 엔진을 걸고, 일정과 목록 갱신 작업을 시작한다.
     * @param config_path 설정 파일 경로. 목록 사본은 그 옆 디렉터리에 둔다.
     * @param service_cleanup 시작한 스레드를 세대가 끝날 때 기다리도록 넘긴다.
     */
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
        let rebuild: FilterRebuild = {
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
            // 받아 둔 사본이 활성 목록을 모두 덮으면, 그리고 원격 목록이 하나도 없으면
            // 시작 직후에 다시 받을 것이 없다.
            let all_loaded = cached.len() == active.len();
            let had_cached = !cached.is_empty();
            if had_cached {
                *sub_meta.lock_recover() = cached;
            }
            (all_loaded, had_cached)
        };
        let (block, allow) = rebuild()
            .map_err(|error| crate::anyhow!(format!("필터 정책을 적용하지 못했습니다: {error}")))?;
        if had_cached_blocklists {
            onetdns_core::info!(
                event = "filter.cache_applied",
                block,
                allow,
                complete = subscriptions_settled,
                "차단 목록을 걸었습니다"
            );
        } else {
            onetdns_core::info!(
                event = "filter.lists_loaded",
                block,
                allow,
                services = cfg.blocked_services.len(),
                "차단 목록을 불러왔습니다"
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
                    let paused = service_blocking_paused(&runtime.load(), std::time::SystemTime::now());
                    if paused == applied {
                        continue;
                    }
                    match rebuild() {
                        Ok(_) => {
                            applied = paused;
                            onetdns_core::info!(
                                event = "filter.service_schedule_applied",
                                paused,
                                "서비스 차단 일정에 따라 서비스 차단 규칙을 다시 걸었습니다"
                            );
                        }
                        Err(error) => onetdns_core::warn!(
                            event = "filter.service_schedule_failed",
                            %error,
                            "서비스 차단 일정을 적용하지 못했습니다. 다음 확인 주기에 다시 시도합니다"
                        ),
                    }
                })
                .with_context(|| "서비스 차단 일정 스레드를 시작하지 못했습니다")?;
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
                            "URL 차단 목록의 실행 상태를 이전 값으로 되돌리지 못했습니다",
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
                        // 목록이 바뀌면 주기를 기다리지 않고 바로 받아 온다.
                        let due = now_generation != seen_generation
                            || !done_first
                            || (period > 0 && waited >= period);
                        if due {
                            seen_generation = now_generation;
                            done_first = true;
                            waited = 0;
                            match refresh_lists() {
                                Ok((block, _)) => {
                                    onetdns_core::info!(event = "filter.subscription_applied", block, "다운로드한 차단 목록을 적용했습니다")
                                }
                                Err(error) if error == LIST_REFRESH_BUSY => {
                                    onetdns_core::info!(event = "filter.subscription_refresh_inflight", "차단 목록 갱신이 이미 진행 중입니다")
                                }
                                Err(error) => {
                                    onetdns_core::warn!(event = "filter.subscription_refresh_failed", %error, "원격 차단 목록을 갱신하지 못했습니다")
                                }
                            }
                        }
                        if sleep_or_shutdown(LIST_REFRESH_TICK_SECS, &sd) {
                            break;
                        }
                        waited = waited.saturating_add(LIST_REFRESH_TICK_SECS);
                    }
                })
                .with_context(|| "URL 차단 목록 갱신 스레드를 시작하지 못했습니다")?;
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
                            Ok((b, _)) => onetdns_core::info!(event = "filter.rpz_applied", block = b, "다운로드한 RPZ 규칙을 적용했습니다"),
                            Err(e) => {
                                *rpz_texts.lock_recover() = previous;
                                fetched_urls = previous_urls;
                                let error = with_rollback_result(
                                    e,
                                    "RPZ 실행 상태를 이전 값으로 되돌리지 못했습니다",
                                    rebuild3().map(|_| ()),
                                );
                                onetdns_core::warn!(event = "filter.rpz_rebuild_failed", error = %error, "RPZ 규칙을 다시 구성하지 못해 이전 규칙을 유지합니다");
                            }
                        }
                        if sleep_or_shutdown(LIST_REFRESH_TICK_SECS, &sd) {
                            break;
                        }
                        waited = waited.saturating_add(LIST_REFRESH_TICK_SECS);
                    }
                })
                .with_context(|| "RPZ 갱신 스레드를 시작하지 못했습니다")?;
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
            rebuild,
            refresh_url_lists,
        })
    }
}
