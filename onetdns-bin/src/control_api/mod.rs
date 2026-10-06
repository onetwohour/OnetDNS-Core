/*!
 * @brief 관리 API 콜백을 실행 중 서버의 상태에 연결한다.
 *
 * @details 콜백은 서버 세대 하나가 소유한 핸들 묶음 ControlDeps 를 함께 붙든다. 콜백 본문은
 *          API 영역별 파일에 ControlDeps 의 메서드로 있다. ControlDeps 에 없는 세대 상태는 관리
 *          API 가 건드리지 않는다.
 */

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

/** @brief 관리 API 가 읽고 바꾸는 이 세대의 핸들. */
pub(crate) struct ControlDeps {
    /** @brief 권한 영역 상태. */
    pub(crate) zones: ZoneState,
    /** @brief 차단 엔진과 그 재료. */
    pub(crate) filters: FilterState,
    /** @brief 실행 중 설정. */
    pub(crate) runtime_cfg: Arc<ArcSwap<Config>>,
    /** @brief 설정 파일 경로. 없으면 파일 없이 돈다. */
    pub(crate) config_path: Option<PathBuf>,
    /** @brief 이 세대를 시작할 때 읽은 설정 원문. */
    pub(crate) cfg_text: Option<onetdns_core::SecretString>,
    /** @brief 세대를 다시 만들라는 요청. */
    pub(crate) reload: Arc<std::sync::atomic::AtomicBool>,
    /** @brief 직전에 적용했던 설정 원문. 되돌리기에 쓴다. */
    pub(crate) config_prev: ConfigTextSlot,
    /** @brief 지금 적용된 설정 원문. */
    pub(crate) applied_config_text: ConfigTextSlot,
    /** @brief 재시작 없이 설정을 교체한다. */
    pub(crate) hot_config_apply: HotConfigApply,
    /** @brief 정책 엔진. */
    pub(crate) policy_engine: Arc<native::GatedSwap<onetdns_policy::PolicyEngine>>,
    /** @brief 목록을 받을 때 쓰는 이름 해석기. */
    pub(crate) blocklist_resolver: http::HostResolver,
    /** @brief DHCPv4 임대 풀. 서비스가 꺼져 있으면 없다. */
    pub(crate) dhcp_slot: Arc<Mutex<Option<Arc<Mutex<crate::dhcp::LeasePool>>>>>,
    /** @brief DHCPv6 임대 풀. 서비스가 꺼져 있으면 없다. */
    pub(crate) dhcp6_slot: Arc<Mutex<Option<Arc<Mutex<crate::dhcp6::Lease6Pool>>>>>,
    /** @brief MAC 제조사 데이터베이스. */
    pub(crate) vendor_db: Arc<ArcSwap<mac::VendorDb>>,
    /** @brief 응답 캐시. 체인을 만들기 전에는 없다. */
    pub(crate) cache_slot: Arc<Mutex<Option<cache::CacheHandle>>>,
    /** @brief 업스트림 통계. 전달 경로가 없으면 없다. */
    pub(crate) forward_stats: Arc<Mutex<Option<onetdns_forward::ForwardStats>>>,
    /** @brief 열려 있는 수신 주소. */
    pub(crate) listener_reg: Arc<Mutex<Vec<(&'static str, String, String)>>>,
    /** @brief TLS 인증서 슬롯. 암호화 수신 주소가 없으면 없다. */
    pub(crate) tls_slot_handle: Arc<Mutex<Option<Arc<TlsSlots>>>>,
    /** @brief 관리 API 가 시킨 작업. */
    pub(crate) jobs: Arc<JobRegistry>,
    /** @brief 이 세대가 끝날 때 기다릴 스레드. */
    pub(crate) service_threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
}

impl ControlDeps {
    /** @brief 설정 원문을 고쳐 반영한다. 바뀐 항목에 따라 교체하거나 세대를 다시 만든다. */
    fn edit_config(
        &self,
        edit: impl FnOnce(&str) -> Result<String, String>,
    ) -> Result<ConfigApplyResult, String> {
        apply_config_edit_smart(
            &self.config_path,
            &self.config_prev,
            &self.applied_config_text,
            &self.reload,
            &self.hot_config_apply,
            edit,
        )
    }
}

/**
 * @brief 메서드 하나를 관리 API 콜백으로 감싼다. 콜백마다 핸들 묶음을 가리키는 Arc 를 하나씩 쥔다.
 * @details 클로저 인자에 타입을 적지 않으면 &str 인자의 수명이 하나로 굳어 콜백 타입과 맞지 않는다.
 */
macro_rules! bind {
    ($deps:ident . $method:ident ( $($arg:ident : $ty:ty),* )) => {{
        let deps = Arc::clone(&$deps);
        Box::new(move |$($arg: $ty),*| deps.$method($($arg),*))
    }};
}

/** @brief 관리 API 콜백을 만든다. */
pub(crate) fn build(deps: ControlDeps) -> onetdns_control::Controls {
    let deps = Arc::new(deps);
    onetdns_control::Controls {
        reload: bind!(deps.rebuild_filter()),
        block_add: bind!(deps.block_add(rule: &str)),
        allow_add: bind!(deps.allow_add(rule: &str)),
        service_set: bind!(deps.service_set(svc: &str, enable: bool)),
        safesearch_set: bind!(deps.safesearch_set(enable: bool)),
        export: bind!(deps.export()),
        import: bind!(deps.import(body: &str)),
        config_validate: bind!(deps.config_validate(toml: &str)),
        config_diff: bind!(deps.config_diff(proposed: &str)),
        config_set_diff: bind!(deps.config_set_diff(body: &str)),
        config_apply: bind!(deps.config_apply(toml: &str)),
        config_set: bind!(deps.config_set(body: &str)),
        config_schema: bind!(deps.config_schema()),
        upstream_test: bind!(deps.upstream_test(body: &str)),
        cache_flush: bind!(deps.cache_flush()),
        rewrites_list: bind!(deps.rewrites_list()),
        rewrite_add: bind!(deps.rewrite_add(body: &str)),
        rewrite_delete: bind!(deps.rewrite_delete(body: &str)),
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
        subscription_remove: bind!(deps.subscription_remove(url: &str)),
        subscription_update: bind!(deps.subscription_update(body: &str)),
        subscription_refresh: bind!(deps.subscription_refresh(body: &str)),
        filter_rules_list: bind!(deps.filter_rules_list()),
        filter_rule_mutate: bind!(deps.filter_rule_mutate(body: &str, add: bool)),
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
        client_add: bind!(deps.client_add(body: &str)),
        client_remove: bind!(deps.client_remove(name: &str)),
        client_update: bind!(deps.client_update(body: &str)),
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
