/*!
 * @brief 설정을 세대를 다시 만들지 않고 교체한다.
 *
 * @details 바뀐 키를 config_keys 의 표로 교체 그룹에 나누고, 그룹마다 이 세대의 핸들을
 *          교체한다. 교체할 수 없는 키가 하나라도 섞여 있으면 아무것도 바꾸지 않고 재시작을
 *          요청한다. 어떤 핸들을 교체하는지는 HotApplyDeps 가 모두 드러낸다.
 *
 *          교체는 세 단계로 나뉜다. 준비 단계는 새 설정으로 만들 것을 모두 만들되 실행 중인
 *          상태를 바꾸지 않는다. 효과 단계는 수신 주소, DHCP, 클러스터처럼 다시 시작해야 하는
 *          작업을 새 설정으로 돌리고, 하나라도 실패하면 이미 돌린 것을 이전 설정으로 되돌린다.
 *          반영 단계는 준비한 것을 슬롯에 넣기만 하므로 실패하지 않는다.
 * @invariant 교체가 실패하면 실행 중인 상태는 이전 설정과 같다. 설정 파일도 이전 것으로
 *            돌아가므로, 반쯤 바뀐 상태가 남으면 파일과 다르게 답한다.
 */

use super::*;
use crate::config_apply::{
    backend_uses_forward, config_changed_keys, has_client_upstream_routes, hot_reload_groups,
    is_hot_reload_config_change, normalize_config_for_comparison, runtime_config_update_lock,
    HotConfigApply, LOCAL_ONLY_CONFIG_KEYS,
};
use crate::config_apply::{ChainRebuild, RestartHooks, SecondaryRestart};
use crate::edge::{reconcile_edge_services, EdgeServices};
use crate::filter_runtime::FilterState;
use crate::filters::{
    blocklist_host_resolver, build_filter_engine_for_config, preset_list_urls,
    release_subscription_lines, FilterBuildInputs,
};
use crate::listeners::{PreparedTls, TlsSlots};
use crate::native_config::{
    build_authority_settings, build_policy_engine, build_views, evaluate_lane_gates,
    reconfigure_native_features, runtime_access_control, runtime_rate_limiters, telemetry_consumed,
    DynamicAccessControl, DynamicRateLimiter, LaneFacts, NativeHotState,
};
use crate::notify::NotifyTargets;
use crate::resolver_chain::PreparedChain;
use crate::zones::{build_zone_store, reconcile_zone_watchers, replace_zone_store, ZoneState};
use std::sync::atomic::Ordering;

/**
 * @brief 효과 단계에서 이미 일으킨 효과를 되돌리는 작업들.
 * @details 다시 시작한 작업과 다시 연 주소는 뒤에서 실패해도 새 설정으로 계속 돈다. 실패하면
 *          등록한 작업을 거꾸로 실행해 이전 설정으로 되돌린다. 효과를 일으키기 전에 등록해야
 *          한다. 일으키는 도중에 실패해도 절반쯤 바뀌어 있을 수 있기 때문이다.
 */
#[derive(Default)]
struct Undo<'a>(Vec<Box<dyn FnOnce() -> Result<(), String> + 'a>>);

impl<'a> Undo<'a> {
    /** @brief 되돌릴 작업을 등록한다. */
    fn push(&mut self, step: impl FnOnce() -> Result<(), String> + 'a) {
        self.0.push(Box::new(step));
    }

    /** @brief 실패면 등록한 작업을 모두 거꾸로 실행하고, 되돌리지 못한 것까지 오류에 붙인다. */
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

/** @brief 통계와 질의 기록을 저장할 설정. 경로가 비어 있으면 저장하지 않는다. */
fn persist_opts(cfg: &Config) -> onetdns_control::PersistOpts {
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

/** @brief 교체 경로가 바꾸는 이 세대의 핸들. */
pub(crate) struct HotApplyDeps {
    /** @brief 설정이 바뀌면 다시 시작할 작업들. */
    pub(crate) restarts: RestartHooks,
    /** @brief 권한 영역 상태. */
    pub(crate) zones: ZoneState,
    /** @brief 차단 엔진과 그 재료. */
    pub(crate) filters: FilterState,
    /** @brief 관리 화면 인증. 관리 수신 주소가 없으면 없다. */
    pub(crate) console_auth: Arc<Mutex<Option<Arc<onetdns_control::Auth>>>>,
    /** @brief 실행 중 설정. */
    pub(crate) runtime_cfg: Arc<ArcSwap<Config>>,
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
    /** @brief 이 세대의 종료 플래그. */
    pub(crate) zone_shutdown: Arc<std::sync::atomic::AtomicBool>,
    /** @brief 이 세대가 끝날 때 기다릴 스레드. */
    pub(crate) zone_threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    /** @brief DHCP 계열 서비스. */
    pub(crate) edge_services: Arc<EdgeServices>,
    /** @brief DHCPv4 임대 풀. 서비스가 꺼져 있으면 없다. */
    pub(crate) dhcp_slot: Arc<Mutex<Option<Arc<Mutex<dhcp::LeasePool>>>>>,
    /** @brief DHCPv6 임대 풀. 서비스가 꺼져 있으면 없다. */
    pub(crate) dhcp6_slot: Arc<Mutex<Option<Arc<Mutex<dhcp6::Lease6Pool>>>>>,
    /** @brief TLS 인증서 슬롯. 암호화 수신 주소가 없으면 없다. */
    pub(crate) tls_slots: Arc<Mutex<Option<Arc<TlsSlots>>>>,
    /** @brief MAC 제조사 데이터베이스. */
    pub(crate) vendor_db: Arc<ArcSwap<mac::VendorDb>>,
    /** @brief 목록을 받을 때 쓰는 이름 해석기의 교체 슬롯. */
    pub(crate) blocklist_resolver_slot: Arc<Mutex<http::HostResolver>>,
    /** @brief 목록을 받을 때 쓰는 이름 해석기. */
    pub(crate) blocklist_resolver: http::HostResolver,
    /** @brief 응답 캐시. 체인을 만들기 전에는 없다. */
    pub(crate) cache_slot: Arc<Mutex<Option<cache::CacheHandle>>>,
}

/**
 * @brief 준비 단계에서 만든 것들. 실행 중인 상태에는 아직 들어가지 않았다.
 * @details 효과 단계와 반영 단계는 이것만 읽는다. 단계마다 함수를 나눠 두어야 준비하는 동안
 *          반영 단계의 지역 값까지 한 프레임에 쌓이지 않는다. 관리 연결 스레드는 스택이 작다.
 */
struct Prepared {
    /** @brief 질의 처리기와 함께 교체할 상태. 그 상태를 바꾸는 그룹이 없으면 없다. */
    native_state: Option<NativeHotState>,
    /** @brief 수신 주소를 설정에 맞추는 작업. */
    listeners: Option<SecondaryRestart>,
    /** @brief Raft 를 다시 시작하는 작업. */
    raft: Option<SecondaryRestart>,
    /** @brief 임대 정보 동기화를 다시 시작하는 작업. */
    lease_sync: Option<SecondaryRestart>,
    /** @brief 관리 수신 주소를 다시 여는 작업. 주소가 그대로면 없다. */
    rebind: Option<SecondaryRestart>,
    /** @brief 기본 체인을 다시 만드는 핸들. */
    chain: Option<ChainRebuild>,
    /** @brief 새 인증서와 그것을 넣을 슬롯. */
    tls: Option<(PreparedTls, Arc<TlsSlots>)>,
    /** @brief 새 차단 엔진. */
    filter: Option<onetdns_filter::BlockEngine>,
    /** @brief 새 전달 리졸버와 그 통계. */
    forward: Option<(Arc<dyn native::Resolver>, onetdns_forward::ForwardStats)>,
    /** @brief 새 기능 세트. */
    native: Option<native::NativeFeatures>,
    /** @brief 새 정책 엔진. */
    policy: Option<Arc<onetdns_policy::PolicyEngine>>,
    /** @brief 새 뷰. */
    views: Option<Vec<native::NativeView>>,
    /** @brief 새 관리 화면 계정. */
    users: Option<Vec<onetdns_control::UserCred>>,
    /** @brief 새 권한 영역 설정과 저장소. 효과 단계가 꺼내 쓴다. */
    authority: Option<PreparedAuthority>,
    /** @brief 새 NOTIFY 대상. */
    notify_targets: Option<NotifyTargets>,
}

/** @brief 준비한 권한 영역 설정과 저장소. */
struct PreparedAuthority {
    /** @brief 접근 설정. */
    settings: native::AuthoritySettings,
    /** @brief 저장소를 만들 때 실행 중이던 저장소. */
    seen: Arc<onetdns_authority::ZoneStore>,
    /** @brief 설정으로 만든 저장소. */
    store: onetdns_authority::ZoneStore,
}

/** @brief 효과 단계가 끝난 뒤 반영할 것. */
struct Effects {
    /** @brief 새 기본 체인. DHCP 서비스를 맞춘 뒤에 만든다. */
    chain: Option<PreparedChain>,
}

/** @brief 이 그룹들 중 하나라도 바뀌면 질의 처리기 상태가 있어야 한다. */
fn needs_native_state(groups: &[ApplyGroup]) -> bool {
    groups.iter().any(|group| {
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
    })
}

/** @brief 교체 함수를 만든다. */
pub(crate) fn build(deps: HotApplyDeps) -> HotConfigApply {
    Arc::new(move |next: &Config, _requested_changed: &[String]| deps.apply(next))
}

impl HotApplyDeps {
    /** @brief 바뀐 키가 모두 교체할 수 있으면 교체한다. 재시작해야 하면 거짓을 돌려준다. */
    fn apply(&self, next: &Config) -> Result<(bool, Vec<String>), String> {
        let _runtime_update_guard = runtime_config_update_lock().lock_recover();
        let previous_cfg = self.runtime_cfg.load();

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
        /*
         * 클라이언트별 경로 체인은 세대를 시작할 때 한 번 만들고 교체하지 않는다. 기본 체인만
         * 다시 만들면 그 경로의 클라이언트는 이전 캐시 크기나 검증 설정으로 답을 받는다.
         */
        if groups.contains(&ApplyGroup::Chain)
            && (has_client_upstream_routes(&previous_cfg) || has_client_upstream_routes(next))
        {
            return Ok((false, changed));
        }

        // hot-apply:begin
        let Some(prepared) = self.prepare(&previous_cfg, next, &groups, &changed)? else {
            return Ok((false, changed));
        };
        let mut prepared = prepared;
        let effects = self.run_effects(&previous_cfg, next, &groups, &mut prepared)?;
        self.commit(next, &groups, &changed, *prepared, effects);
        // hot-apply:end

        // 관리 주소나 저장 파일이 이 경로로 생기고 사라진다. 세대를 다시 만들지
        // 않으므로 여기서 다시 정하지 않으면 시작할 때의 판정이 그대로 남는다.
        self.recorder.set_collecting(telemetry_consumed(next));
        onetdns_core::info!(
            event = "config.runtime_hot_applied",
            changed = changed.len(),
            keys = ?changed,
            "Updated the running configuration"
        );
        Ok((true, changed))
    }

    /**
     * @brief 새 설정으로 만들 것을 모두 만든다. 실행 중인 상태는 바꾸지 않는다.
     * @return 교체할 작업이 아직 서지 않아 재시작해야 하면 없음.
     */
    fn prepare(
        &self,
        previous: &Config,
        next: &Config,
        groups: &[ApplyGroup],
        changed: &[String],
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

        let native_state = if needs_native_state(groups) {
            let Some(state) = native_hot_state.lock_recover().clone() else {
                return Ok(None);
            };
            Some(state)
        } else {
            None
        };
        // 교체할 작업이 아직 서지 않았으면 재시작하는 쪽이 안전하다.
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

        // 슬롯이 아직 없으면 이 인증서를 쓰는 수신 주소도 없다. 나중에 주소를 열 때 그때
        // 설정으로 만들어지므로 지금 할 일이 없다.
        let slots = tls_slots.lock_recover().clone();
        let tls = match slots {
            Some(slots) if groups.contains(&ApplyGroup::Tls) => {
                Some((TlsSlots::prepare(next)?, slots))
            }
            _ => None,
        };
        let filter = if groups.contains(&ApplyGroup::Filter) {
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
            Some(state) if groups.contains(&ApplyGroup::Native) => Some(
                reconfigure_native_features(&state.features.load(), next, changed)?,
            ),
            _ => None,
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
            // 만들 때 본 저장소를 기억해 둔다. 반영할 때 저장소가 그새 바뀌었으면 동적 갱신이
            // 들어온 것이므로 다시 만든다. 그대로 넣으면 그 갱신이 사라진다.
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

    /**
     * @brief 다시 시작해야 하는 작업을 새 설정으로 돌린다.
     * @details 하나라도 실패하면 이미 돌린 작업을 이전 설정으로 되돌리고 실패를 돌려준다.
     *          권한 영역 저장소도 여기서 바꾼다. 영역 감시와 세컨더리 작업이 새 저장소를 전제로
     *          시작하기 때문이다.
     */
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
        // 체인은 DHCP 임대 풀을 읽으므로 DHCP 서비스를 맞춘 뒤에 만든다.
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
        // 접근 설정과 영역을 한 잠금 아래에서 바꾼다. 영역이 먼저 바뀌면 그 사이에 이전 저장
        // 경로로 동적 갱신이 들어가 엉뚱한 파일을 덮는다.
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

    /** @brief 준비한 것을 슬롯에 넣는다. 넣기만 하므로 실패하지 않는다. */
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
                    ..
                },
            console_auth,
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
            blocklist_resolver,
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
        }
        if groups.contains(&ApplyGroup::ControlTokens) {
            if let Some(auth) = console_auth.lock_recover().as_ref() {
                let mut admin = next.control_admin_tokens.clone();
                if !next.control_token.is_empty() {
                    admin.push(next.control_token.clone());
                }
                auth.replace_tokens(admin, next.control_readonly_tokens.clone());
            }
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
            // 세대를 올리면 갱신 스레드가 주기를 기다리지 않고 다음 틱에 받아 온다.
            list_generation.fetch_add(1, Ordering::AcqRel);
            onetdns_core::info!(
                event = "filter.subscriptions_reloaded",
                lists = next.blocklist_urls.len(),
                rpz = next.rpz_urls.len(),
                "Changed blocklist subscriptions without interrupting DNS"
            );
        }
        if let Some(engine) = prepared_filter {
            let counts = (engine.block_count(), engine.allow_count());
            filter.store(Arc::new(engine));
            *overlay.lock_recover() = (next.block_rules.clone(), next.allow_rules.clone());
            *service_set.lock_recover() = next.blocked_services.clone();
            *refused_domains.lock_recover() = next.refused_domains.clone();
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
            if let Some(features) = native {
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
                        "Cleared the response cache because local-only name handling changed"
                    );
                }
            }
            if let Some(policy) = policy {
                state.policy.store(policy);
            }
            if let Some(views) = views {
                state.views.store(Arc::new(views));
            }
            if groups.contains(&ApplyGroup::BlockTtl) {
                state
                    .block_ttl
                    .store(next.blocked_response_ttl, Ordering::Release);
            }
            if groups.contains(&ApplyGroup::LocalTtl) {
                state.local_ttl.store(next.local_ttl, Ordering::Release);
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
                state.wire_epoch.fetch_add(1, Ordering::AcqRel);
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
            install_revocation_policy(next, blocklist_resolver);
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
        if let (Some(chain), Some(prepared), Some(state)) = (chain, effects.chain, &native_state) {
            let installed = chain.chain.install(prepared);
            chain.slot.replace(installed.resolver);
            state.handler.replace_lane_runtime(
                wirecache::WireEntryFactory::new(next.min_ttl as u32, next.max_ttl as u32),
                installed.cache,
                installed.recursor,
                !next.ddr_name.is_empty(),
            );
            onetdns_core::info!(
                event = "chain.rebuilt",
                "Rebuilt and swapped the resolver chain; DNS kept answering"
            );
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
                    "Reopened and closed fast paths for the changed configuration"
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
    /**
     * @brief 실패하면 등록한 되돌리기를 거꾸로 모두 실행하고, 되돌리지 못한 것도 오류에 남기는지.
     * @details 앞선 것부터 되돌리면 뒤에서 연 주소나 작업이 앞선 것의 이전 상태와 겹친다. 되돌리기
     *          하나가 실패해도 나머지는 실행해야 실행 중인 상태가 이전 설정에 가장 가까워진다.
     */
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
