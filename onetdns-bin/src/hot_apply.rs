/*!
 * @brief 설정을 세대를 다시 만들지 않고 교체한다.
 *
 * @details 바뀐 키를 config_keys 의 표로 교체 그룹에 나누고, 그룹마다 이 세대의 핸들을
 *          교체한다. 교체할 수 없는 키가 하나라도 섞여 있으면 아무것도 바꾸지 않고 재시작을
 *          요청한다. 어떤 핸들을 교체하는지는 HotApplyDeps 가 모두 드러낸다.
 */

use super::*;
use std::sync::atomic::Ordering;

/** @brief 교체 경로가 바꾸는 이 세대의 핸들. */
pub(crate) struct HotApplyDeps {
    /** @brief 해석 체인을 다시 만든다. 체인을 만들기 전에는 없다. */
    pub(crate) chain_rebuild: Arc<Mutex<Option<ChainRebuild>>>,
    /** @brief 관리 화면 인증. 관리 수신 주소가 없으면 없다. */
    pub(crate) console_auth: Arc<Mutex<Option<Arc<onetdns_control::Auth>>>>,
    /** @brief 실행 중 설정. */
    pub(crate) runtime_cfg: Arc<ArcSwap<Config>>,
    /** @brief 지금 쓰는 차단 엔진. */
    pub(crate) filter: Arc<SharedFilter>,
    /** @brief 관리 API 로 더한 차단과 허용 규칙. */
    pub(crate) overlay: Arc<Mutex<(Vec<String>, Vec<String>)>>,
    /** @brief 차단한 서비스 목록. */
    pub(crate) service_set: Arc<Mutex<Vec<String>>>,
    /** @brief 거부할 도메인 목록. */
    pub(crate) refused_domains: Arc<Mutex<Vec<String>>>,
    /** @brief 안전 검색을 켰는지. */
    pub(crate) safe_search: Arc<std::sync::atomic::AtomicBool>,
    /** @brief 구독별로 받은 결과. */
    pub(crate) sub_meta: Arc<Mutex<Vec<SubMeta>>>,
    /** @brief 받아 둔 RPZ 본문. */
    pub(crate) rpz_texts: Arc<Mutex<Vec<String>>>,
    /** @brief 컴파일한 차단 엔진을 저장하는 파일. */
    pub(crate) compiled_filter_cache: Option<PathBuf>,
    /** @brief 받은 목록을 저장하는 디렉터리. */
    pub(crate) subscription_cache_dir: Option<PathBuf>,
    /** @brief 접근 제어. */
    pub(crate) acl_state: Arc<DynamicAccessControl>,
    /** @brief 속도 제한. */
    pub(crate) rate_state: Arc<DynamicRateLimiter>,
    /** @brief 질의 기록. */
    pub(crate) recorder: onetdns_control::Recorder,
    /** @brief 전달 리졸버 슬롯. */
    pub(crate) forward_slot: native::ResolverSlot,
    /** @brief 업스트림 통계. 전달 경로가 없으면 없다. */
    pub(crate) forward_stats: Arc<Mutex<Option<onetdns_forward::ForwardStats>>>,
    /** @brief 질의 처리기와 함께 교체할 상태. 처리기를 만들기 전에는 없다. */
    pub(crate) native_hot_state: Arc<Mutex<Option<NativeHotState>>>,
    /** @brief 통계. */
    pub(crate) stats: onetdns_control::Stats,
    /** @brief 권한 영역 저장소. */
    pub(crate) zone_store: Arc<ArcSwap<onetdns_authority::ZoneStore>>,
    /** @brief 영역 원본 감시 작업. */
    pub(crate) zone_watchers: Arc<ZoneWatchers>,
    /** @brief 영역이 바뀌었을 때 NOTIFY 를 보낸다. */
    pub(crate) zone_notify: NotifySender,
    /** @brief 이 세대의 종료 플래그. */
    pub(crate) zone_shutdown: Arc<std::sync::atomic::AtomicBool>,
    /** @brief 이 세대가 끝날 때 기다릴 스레드. */
    pub(crate) zone_threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    /** @brief 구독 주소. */
    pub(crate) sub_urls: Arc<Mutex<Vec<String>>>,
    /** @brief 구독 제목. */
    pub(crate) sub_titles: Arc<Mutex<Vec<String>>>,
    /** @brief 꺼 둔 구독 주소. */
    pub(crate) sub_disabled: Arc<Mutex<Vec<String>>>,
    /** @brief 미리 정해 둔 목록 주소. */
    pub(crate) preset_urls: Arc<Mutex<Vec<String>>>,
    /** @brief RPZ 구독 주소. */
    pub(crate) rpz_url_state: Arc<Mutex<Vec<String>>>,
    /** @brief 목록을 다시 받는 주기. */
    pub(crate) list_refresh_secs: Arc<std::sync::atomic::AtomicU64>,
    /** @brief 목록 받기 작업의 세대. 주기를 바꾸면 이전 작업이 멈춘다. */
    pub(crate) list_generation: Arc<std::sync::atomic::AtomicU64>,
    /** @brief DHCP 계열 서비스. */
    pub(crate) edge_services: Arc<EdgeServices>,
    /** @brief DHCPv4 임대 풀. 서비스가 꺼져 있으면 없다. */
    pub(crate) dhcp_slot: Arc<Mutex<Option<Arc<Mutex<dhcp::LeasePool>>>>>,
    /** @brief DHCPv6 임대 풀. 서비스가 꺼져 있으면 없다. */
    pub(crate) dhcp6_slot: Arc<Mutex<Option<Arc<Mutex<dhcp6::Lease6Pool>>>>>,
    /** @brief TLS 인증서 슬롯. 암호화 수신 주소가 없으면 없다. */
    pub(crate) tls_slots: Arc<Mutex<Option<Arc<TlsSlots>>>>,
    /** @brief 세컨더리 영역 갱신 작업을 다시 시작한다. */
    pub(crate) secondary_restart: Arc<Mutex<Option<SecondaryRestart>>>,
    /** @brief ZSK 교체 작업을 다시 시작한다. */
    pub(crate) zsk_rollover_restart: Arc<Mutex<Option<SecondaryRestart>>>,
    /** @brief 영역 서명 키. */
    pub(crate) zone_signers: SharedZoneSigners,
    /** @brief MAC 제조사 데이터베이스. */
    pub(crate) vendor_db: Arc<ArcSwap<mac::VendorDb>>,
    /** @brief 임대 동기화 작업을 다시 시작한다. */
    pub(crate) lease_sync_restart: Arc<Mutex<Option<SecondaryRestart>>>,
    /** @brief Raft 런타임을 다시 시작한다. */
    pub(crate) raft_restart: Arc<Mutex<Option<SecondaryRestart>>>,
    /** @brief 수신 주소를 설정에 맞춘다. */
    pub(crate) listener_sync: Arc<Mutex<Option<SecondaryRestart>>>,
    /** @brief 관리 수신 주소를 다시 연다. */
    pub(crate) control_rebind: Arc<Mutex<Option<SecondaryRestart>>>,
    /** @brief 목록을 받을 때 쓰는 이름 해석기의 교체 슬롯. */
    pub(crate) blocklist_resolver_slot: Arc<Mutex<http::HostResolver>>,
    /** @brief 목록을 받을 때 쓰는 이름 해석기. */
    pub(crate) blocklist_resolver: http::HostResolver,
    /** @brief 응답 캐시. 체인을 만들기 전에는 없다. */
    pub(crate) cache_slot: Arc<Mutex<Option<cache::CacheHandle>>>,
    /** @brief reactor 레인이 쓰는 재귀 리졸버. */
    pub(crate) lane_recursor: Arc<Mutex<Option<Arc<onetdns_recurse::Recursor>>>>,
}

/** @brief 교체 함수를 만든다. */
pub(crate) fn build(deps: HotApplyDeps) -> HotConfigApply {
    let HotApplyDeps {
        chain_rebuild,
        console_auth,
        runtime_cfg,
        filter,
        overlay,
        service_set,
        refused_domains,
        safe_search,
        sub_meta,
        rpz_texts,
        compiled_filter_cache,
        subscription_cache_dir,
        acl_state,
        rate_state,
        recorder,
        forward_slot,
        forward_stats,
        native_hot_state,
        stats,
        zone_store,
        zone_watchers,
        zone_notify,
        zone_shutdown,
        zone_threads,
        sub_urls,
        sub_titles,
        sub_disabled,
        preset_urls,
        rpz_url_state,
        list_refresh_secs,
        list_generation,
        edge_services,
        dhcp_slot,
        dhcp6_slot,
        tls_slots,
        secondary_restart,
        zsk_rollover_restart,
        zone_signers,
        vendor_db,
        lease_sync_restart,
        raft_restart,
        listener_sync,
        control_rebind,
        blocklist_resolver_slot,
        blocklist_resolver,
        cache_slot,
        lane_recursor,
    } = deps;
    Arc::new(move |next: &Config, _requested_changed: &[String]| {
        let _runtime_update_guard = runtime_config_update_lock().lock_recover();
        let previous_cfg = runtime_cfg.load();

        // 시작할 때 채워 넣은 기본값은 파일에 적히지 않는다. 파일만 다시 읽으면
        // 그 항목이 사라진 것으로 보여, 손대지도 않은 관리 주소를 지운 것으로
        // 처리하고 웹 화면을 닫아 버린다.
        let next = &normalize_config_for_comparison(&previous_cfg, next);

        let changed = config_changed_keys(&previous_cfg, next)?;
        if changed
            .iter()
            .any(|key| !is_hot_reload_config_change(&previous_cfg, next, key))
        {
            return Ok((false, changed));
        }

        let groups = hot_reload_groups(&previous_cfg, next, &changed);

        // hot-apply:begin
        if groups.contains(&ApplyGroup::Tls) {
            // 슬롯이 아직 없으면 이 인증서를 쓰는 수신 주소도 없다. 나중에 주소를
            // 열 때 그때 설정으로 만들어지므로 지금 할 일이 없다.
            if let Some(slots) = tls_slots.lock_recover().clone() {
                slots.reload(next)?;
                onetdns_core::info!(
                    event = "tls.certificate_reloaded",
                    "수신 주소를 닫지 않고 TLS 인증서를 교체했습니다"
                );
            }
        }
        if groups.contains(&ApplyGroup::EdgeServices) {
            if let Err(error) =
                reconcile_edge_services(next, &edge_services, &dhcp_slot, &dhcp6_slot)
            {
                /* 설정 파일이 되돌아가므로 서비스도 이전 설정에 맞춘다. */
                if let Err(restore) =
                    reconcile_edge_services(&previous_cfg, &edge_services, &dhcp_slot, &dhcp6_slot)
                {
                    return Err(format!(
                        "{error}; 이전 설정의 DHCP 계열 서비스도 재시작하지 못했습니다: {restore}"
                    ));
                }
                return Err(error);
            }
            onetdns_core::info!(
                event = "edge.reloaded",
                "DHCP 계열 서비스를 DNS를 멈추지 않고 다시 띄웠습니다"
            );
        }
        if groups
            .iter()
            .any(|group| matches!(*group, ApplyGroup::Chain | ApplyGroup::Forward))
        {
            *blocklist_resolver_slot.lock_recover() = blocklist_host_resolver(next);
        }
        if groups.contains(&ApplyGroup::Listeners) {
            let Some(sync) = listener_sync.lock_recover().clone() else {
                return Ok((false, changed));
            };
            if let Err(error) = sync(next) {
                /* 이전 리스너를 먼저 닫았을 수 있으므로 이전 설정으로 다시 연다. */
                if let Err(restore) = sync(&previous_cfg) {
                    return Err(format!(
                        "{error}; 이전 설정의 수신 주소도 다시 열지 못했습니다: {restore}"
                    ));
                }
                return Err(error);
            }
            onetdns_core::info!(
                event = "listener.reloaded",
                plain = next.listen.len(),
                "수신 주소를 설정에 맞췄습니다. 그대로인 주소는 끊기지 않았습니다"
            );
        }
        if groups.contains(&ApplyGroup::Cluster) {
            let Some(restart) = raft_restart.lock_recover().clone() else {
                return Ok((false, changed));
            };
            restart(next)?;
            if let Some(sync) = lease_sync_restart.lock_recover().as_ref() {
                sync(next)?;
            }
            onetdns_core::info!(
                event = "cluster.reloaded",
                raft = next.cluster_raft,
                peers = next.cluster_raft_peers.len(),
                "클러스터를 DNS를 멈추지 않고 다시 띄웠습니다"
            );
        }
        if groups.contains(&ApplyGroup::ControlTokens) {
            if next.control_listen != previous_cfg.control_listen {
                let rebind = control_rebind
                    .lock_recover()
                    .clone()
                    .ok_or("웹 관리 화면의 연결 수신을 아직 준비하지 못했습니다")?;
                rebind(next)?;
            }
            if let Some(auth) = console_auth.lock_recover().as_ref() {
                let mut admin = next.control_admin_tokens.clone();
                if !next.control_token.is_empty() {
                    admin.push(next.control_token.clone());
                }
                auth.replace_tokens(admin, next.control_readonly_tokens.clone());
            }
            if let Some(sync) = lease_sync_restart.lock_recover().as_ref() {
                sync(next)?;
            }
            onetdns_core::info!(
                event = "control.tokens_reloaded",
                "제어 토큰을 DNS를 멈추지 않고 갱신했습니다"
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
            // 세대를 올리면 갱신 스레드가 주기를 기다리지 않고 다음 틱에 받아 온다.
            list_generation.fetch_add(1, Ordering::AcqRel);
            onetdns_core::info!(
                event = "filter.subscriptions_reloaded",
                lists = next.blocklist_urls.len(),
                rpz = next.rpz_urls.len(),
                "DNS 처리를 멈추지 않고 차단 목록 구독을 바꿨습니다"
            );
        }

        let prepared_filter = if groups.contains(&ApplyGroup::Filter) {
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
        let prepared_forward = if backend_uses_forward(next.backend)
            && (groups.contains(&ApplyGroup::Forward)
                || !backend_uses_forward(previous_cfg.backend))
        {
            let (resolver, stats) = build_forward_backend(next)?;
            if let Some(previous) = forward_stats.lock_recover().as_ref() {
                stats.seed(&previous.snapshot());
            }
            Some((resolver, stats))
        } else {
            None
        };
        let native_state = if groups.iter().any(|group| {
            matches!(
                *group,
                ApplyGroup::Chain
                    | ApplyGroup::Forward
                    | ApplyGroup::Native
                    | ApplyGroup::Policy
                    | ApplyGroup::Views
                    | ApplyGroup::BlockTtl
                    | ApplyGroup::LocalTtl
            )
        }) {
            let Some(state) = native_hot_state.lock_recover().clone() else {
                return Ok((false, changed));
            };
            Some(state)
        } else {
            None
        };
        let prepared_native = if groups.contains(&ApplyGroup::Native) {
            let state = native_state.as_ref().expect("native 상태를 확인했습니다");
            let current = state.features.load();
            Some(reconfigure_native_features(&current, next, &changed)?)
        } else {
            None
        };
        let prepared_policy = if groups.contains(&ApplyGroup::Policy) {
            Some(Arc::new(build_policy_engine(next)?))
        } else {
            None
        };
        let prepared_views = if groups.contains(&ApplyGroup::Views) {
            Some(build_views(next)?)
        } else {
            None
        };
        let prepared_persist =
            groups
                .contains(&ApplyGroup::Persistence)
                .then(|| onetdns_control::PersistOpts {
                    querylog_file: next
                        .querylog_file
                        .clone()
                        .filter(|path| !path.as_os_str().is_empty()),
                    stats_file: next
                        .stats_file
                        .clone()
                        .filter(|path| !path.as_os_str().is_empty()),
                    flush_secs: next.persist_flush_secs,
                });

        if let Some(persist) = prepared_persist {
            stats.reconfigure_persist(persist).map_err(|error| {
                format!("통계 또는 질의 기록 저장 설정을 적용하지 못했습니다: {error}")
            })?;
        }

        if let Some(engine) = prepared_filter {
            let counts = (engine.block_count(), engine.allow_count());
            filter.store(Arc::new(engine));
            *overlay.lock_recover() = (next.block_rules.clone(), next.allow_rules.clone());
            *service_set.lock_recover() = next.blocked_services.clone();
            *refused_domains.lock_recover() = next.refused_domains.clone();
            if let Some(dir) = subscription_cache_dir.as_deref() {
                release_subscription_lines(&sub_meta, dir);
            }
            onetdns_core::info!(
                event = "filter.rebuilt",
                block = counts.0,
                allow = counts.1,
                "필터 규칙을 새 설정으로 교체했습니다"
            );
        }
        if let Some((resolver, stats)) = prepared_forward {
            forward_slot.replace(resolver);
            *forward_stats.lock_recover() = Some(stats);
        }
        if let Some(features) = prepared_native {
            let state = native_state.as_ref().expect("native 상태를 확인했습니다");
            state
                .local_only_names
                .set(next.domain_needed, next.bogus_priv, next.empty_zones);
            state.features.store(Arc::new(features));
            if changed
                .iter()
                .any(|key| LOCAL_ONLY_CONFIG_KEYS.contains(&key.as_str()))
            {
                let flushed = cache_slot
                    .lock_recover()
                    .as_ref()
                    .map(|cache| cache.clear())
                    .unwrap_or(0);
                onetdns_core::info!(
                    event = "cache.flushed_for_local_only",
                    flushed,
                    "로컬 전용 이름 처리가 바뀌어 응답 캐시를 비웠습니다"
                );
            }
        }
        if let Some(policy) = prepared_policy {
            native_state
                .as_ref()
                .expect("native 상태를 확인했습니다")
                .policy
                .store(policy);
        }
        if let Some(views) = prepared_views {
            native_state
                .as_ref()
                .expect("native 상태를 확인했습니다")
                .views
                .store(Arc::new(views));
        }
        if groups.contains(&ApplyGroup::BlockTtl) {
            native_state
                .as_ref()
                .expect("native 상태를 확인했습니다")
                .block_ttl
                .store(next.blocked_response_ttl, Ordering::Release);
        }
        if groups.contains(&ApplyGroup::LocalTtl) {
            native_state
                .as_ref()
                .expect("native 상태를 확인했습니다")
                .local_ttl
                .store(next.local_ttl, Ordering::Release);
        }
        if groups.iter().any(|group| {
            matches!(
                *group,
                ApplyGroup::Chain
                    | ApplyGroup::Forward
                    | ApplyGroup::Native
                    | ApplyGroup::Policy
                    | ApplyGroup::Views
                    | ApplyGroup::LocalTtl
            )
        }) {
            native_state
                .as_ref()
                .expect("native 상태를 확인했습니다")
                .wire_epoch
                .fetch_add(1, Ordering::AcqRel);
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
            install_revocation_policy(next, &blocklist_resolver);
        }
        if groups.contains(&ApplyGroup::Authority) {
            // 접근 설정을 먼저 바꾼다. 영역이 먼저 바뀌면 그 사이에 이전 저장 경로로
            // 원격 업데이트가 들어가 엉뚱한 파일을 덮는다.
            let settings = build_authority_settings(next)?;
            let store = build_zone_store(next, &settings.tsig_keys, &settings.zone_signers)?;
            zone_signers.store(Arc::new(settings.zone_signers.clone()));
            let notify_keys = settings.tsig_keys.clone();
            if let Some(state) = native_hot_state.lock_recover().as_ref() {
                state.authority.store(Arc::new(settings));
            }
            zone_store.store(Arc::new(store));
            reconcile_zone_watchers(
                next,
                &zone_watchers,
                &zone_store,
                &zone_notify,
                &zone_shutdown,
                &zone_threads,
            )?;
            if let Some(restart) = secondary_restart.lock_recover().as_ref() {
                restart(next)?;
            }
            if let Some(restart) = zsk_rollover_restart.lock_recover().as_ref() {
                restart(next)?;
            }
            zone_notify.replace_targets(&next.notify, &notify_keys)?;
            onetdns_core::info!(
                event = "authority.reloaded",
                zones = next.zones.len(),
                "DNS 처리를 멈추지 않고 DNS 영역 구성을 교체했습니다"
            );
        }

        let previous_runtime = runtime_cfg.load();
        runtime_cfg.store(Arc::new(next.clone()));
        if groups.contains(&ApplyGroup::Chain) {
            let rebuild = chain_rebuild.lock_recover().clone();
            match rebuild {
                Some(rebuild) => {
                    let rebuilt = rebuild(next).and_then(|()| {
                        cache_slot
                            .lock_recover()
                            .clone()
                            .ok_or_else(|| "새 해석 체인의 응답 캐시 핸들이 없습니다".to_string())
                    });
                    let cache = match rebuilt {
                        Ok(cache) => cache,
                        Err(error) => {
                            runtime_cfg.store(previous_runtime);
                            return Err(error);
                        }
                    };
                    let recursor =
                        matches!(next.backend, BackendKind::Recurse | BackendKind::Split)
                            .then(|| lane_recursor.lock_recover().clone())
                            .flatten();
                    native_state
                        .as_ref()
                        .expect("chain 변경은 native 상태를 준비합니다")
                        .handler
                        .replace_lane_runtime(
                            wirecache::WireEntryFactory::new(
                                next.min_ttl as u32,
                                next.max_ttl as u32,
                            ),
                            cache,
                            recursor,
                            !next.ddr_name.is_empty(),
                        );
                    onetdns_core::info!(
                        event = "chain.rebuilt",
                        "해석 체인을 새로 만들어 교체했습니다. DNS 처리는 멈추지 않았습니다"
                    );
                }
                // 체인을 만들 준비가 아직 안 됐으면 재시작하는 쪽이 안전하다.
                None => return Ok((false, changed)),
            }
        }

        // 빠른 경로는 지어질 때의 설정을 전제로 답한다. 설정이 바뀌었으면 무엇이
        // 바뀌었든 조건을 다시 보고 스위치를 맞춘다. 이것을 빼면 캐시를 껐는데도
        // 이전 답이 계속 나가고, 켠 기능이 없는 것처럼 답한다.
        if let Some(state) = native_hot_state.lock_recover().as_ref() {
            let gates = evaluate_lane_gates(
                next,
                &LaneFacts {
                    dhcp_pool: dhcp_slot.lock_recover().is_some(),
                    views_present: state.views.present(),
                    policy_present: state.policy.present(),
                },
            );
            if state
                .lane_switch
                .set(gates.wire, gates.authority, gates.reactor)
            {
                onetdns_core::debug!(
                    event = "do53.lane_switch",
                    wire = gates.wire,
                    authority = gates.authority,
                    reactor = gates.reactor,
                    "바뀐 설정에 맞춰 빠른 경로를 다시 열고 닫았습니다"
                );
            }
        }

        if groups.contains(&ApplyGroup::ConsoleAccounts) {
            if let Some(auth) = console_auth.lock_recover().as_ref() {
                auth.replace_users(build_user_creds(next)?);
            }
            onetdns_core::info!(
                event = "console.accounts_reloaded",
                accounts = next.users.len(),
                "웹 콘솔 계정 목록을 DNS 처리를 멈추지 않고 갱신했습니다"
            );
        }

        // hot-apply:end
        // 관리 주소나 저장 파일이 이 경로로 생기고 사라진다. 세대를 다시 만들지
        // 않으므로 여기서 다시 정하지 않으면 시작할 때의 판정이 그대로 남는다.
        recorder.set_collecting(telemetry_consumed(next));
        onetdns_core::info!(
            event = "config.runtime_hot_applied",
            changed = changed.len(),
            keys = ?changed,
            "실행 중인 설정을 갱신했습니다"
        );
        Ok((true, changed))
    })
}
