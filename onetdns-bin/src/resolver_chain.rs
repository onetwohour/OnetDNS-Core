/*!
 * @brief 설정에서 해석 체인을 조립한다.
 *
 * @details 설정에서 먼저 ChainPlan 을 만들고, 체인은 이 계획만 읽어서 조립한다. 설정이
 *          바뀌면 이전 계획과 새 계획을 비교해 다를 때만 새 체인을 만들어 슬롯에 교체하고,
 *          소켓과 스레드는 그대로 둔다. 계층을 쌓는 순서와 그 이유는 layer-order 문서가 정한다.
 */

use super::*;
use crate::edge::EdgeServices;
use crate::native_config::{ipset_layer_active, recursion_offered_by};
use crate::recursion::{
    detect_dns53_interception, forward_trust_anchors, load_configured_trust_anchors, new_recursor,
    recursor_roots, spawn_rfc5011, spawn_ta_signaling,
};

/**
 * @brief 해석 체인을 조립하는 데 필요한 설정 값.
 *
 * @details 체인 조립 함수는 Config 대신 이 값만 받는다. 따라서 체인에 영향을 주는 설정은
 *          모두 이 구조체에 들어 있고, 두 계획이 같으면 체인을 다시 만들어도 결과가 같다.
 *          설정을 교체할 때 이전 계획과 새 계획을 비교해 체인을 다시 만들지 정한다.
 *
 *          쓰지 않는 구성 요소의 값은 담지 않는다. 재귀를 쓰지 않고 예비 업스트림과 스텁 영역도
 *          없으면 질의 제한 시간이 빠지므로, 그 값만 바꾼 설정은 체인과 캐시를 건드리지 않는다.
 *          조립 함수도 빠진 값을 읽을 수 없다.
 * @invariant 조립 함수가 읽는 값은 모두 이 구조체에서 나온다. 설정을 직접 읽으면 그 값이
 *            바뀌어도 체인을 다시 만들지 않아 이전 값으로 답한다.
 */
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ChainPlan {
    base: BasePlan,
    fallback: Option<ForwarderPlan>,
    forward_validation: Option<ValidationPlan>,
    cachedb: Option<CacheDbPlan>,
    ecs_mode: EcsMode,
    ecs_custom_ip: Option<IpAddr>,
    cache_enabled: bool,
    cache_size: u64,
    sharded_cache: bool,
    cache_shards: usize,
    min_ttl: u64,
    max_ttl: u64,
    neg_min_ttl: u64,
    neg_max_ttl: u64,
    serve_stale_secs: u64,
    serve_expired_reply_ttl: u32,
    serve_expired_ttl_reset: bool,
    serve_expired_client_timeout_ms: u64,
    serve_stale_refresh: bool,
    prefetch: bool,
    prefetch_interval_secs: u64,
    prefetch_min_hits: u32,
    prefetch_ttl_pct: u32,
    local_a: Vec<(String, Ipv4Addr)>,
    local_aaaa: Vec<(String, Ipv6Addr)>,
    name_ratelimit_per_sec: u32,
    name_ratelimit_labels: usize,
    stub_zones: Vec<(String, ForwarderPlan)>,
    dhcp_local_domain: String,
    ipset: Option<IpsetPlan>,
    authority: Option<AuthorityPlan>,
    acme_challenge: bool,
    ddr: Option<DdrPlan>,
    dynamic_records: Vec<onetdns_config::DynamicRecord>,
    /** @brief 공유 캐시에서 기본 체인이 쓰는 이름 공간. 클라이언트 경로는 여기에 경로 이름을 붙인다. */
    cache_namespace: String,
}

/** @brief 처리 방식별 기반 리졸버. 재귀 설정은 재귀를 쓸 때만 담긴다. */
#[derive(Clone, Debug, PartialEq)]
enum BasePlan {
    Forward,
    Recurse(RecursivePlan),
    Split {
        recurse: RecursivePlan,
        default: SplitTarget,
        split_recurse: Vec<String>,
        split_forward: Vec<String>,
    },
}

/** @brief 재귀 리졸버와 재귀 전용 계층의 설정. */
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RecursivePlan {
    query_timeout_secs: u64,
    roots: Vec<SocketAddr>,
    prefer_ip4: bool,
    prefer_ip6: bool,
    do_ip4: bool,
    do_ip6: bool,
    domain_insecure: Vec<String>,
    recursion_limit: u8,
    cname_limit: u8,
    dname_limit: u8,
    ns_recursion_limit: u8,
    recurse_deny_server: Vec<onetdns_core::IpNet>,
    recurse_allow_server: Vec<onetdns_core::IpNet>,
    qname_minimisation_strict: bool,
    harden_referral_path: bool,
    root_key_sentinel: bool,
    val_nsec3_max_iterations: u16,
    ns_cache_size: usize,
    use_caps_for_id: bool,
    lowercase_outgoing: bool,
    dnssec: bool,
    dnssec_strict: bool,
    val_permissive_mode: bool,
    ignore_cd_flag: bool,
    dnssec_anchor_file: Option<std::path::PathBuf>,
    dnssec_rfc5011: bool,
    trust_anchor_signaling: bool,
    harden_below_nxdomain: bool,
    aggressive_nsec: bool,
    cache_size: u64,
    max_ttl: u64,
    neg_min_ttl: u64,
    neg_max_ttl: u64,
}

/**
 * @brief 예비 업스트림이나 스텁 영역 하나로 보내는 전달기의 설정.
 * @details 이 서버의 수신 주소를 함께 담는다. 업스트림이 수신 주소를 가리키면 질의가 이
 *          서버로 되돌아오므로, 수신 주소가 바뀌면 전달기를 다시 만들면서 다시 확인해야 한다.
 */
#[derive(Clone, Debug, PartialEq)]
struct ForwarderPlan {
    servers: Vec<String>,
    bootstrap: Vec<IpAddr>,
    listeners: Vec<SocketAddr>,
    query_timeout_secs: u64,
    upstream_strategy: UpstreamStrategy,
    upstream_concurrency: usize,
}

/** @brief 비재귀 처리 방식에서 업스트림 응답을 직접 검증할 때의 설정. */
#[derive(Clone, Debug, PartialEq)]
struct ValidationPlan {
    dnssec_strict: bool,
    val_permissive_mode: bool,
    ignore_cd_flag: bool,
    domain_insecure: Vec<String>,
    root_key_sentinel: bool,
    dnssec_anchor_file: Option<std::path::PathBuf>,
}

/** @brief 외부 Redis 공유 캐시의 설정. 호스트 이름은 조립할 때 bootstrap 으로 푼다. */
#[derive(Clone, Debug, PartialEq)]
struct CacheDbPlan {
    host: String,
    port: u16,
    bootstrap: Vec<IpAddr>,
    expire_secs: u64,
}

/** @brief 답한 주소를 커널 주소 집합에 넣는 계층의 설정. */
#[derive(Clone, Debug, PartialEq)]
struct IpsetPlan {
    name_v4: Option<String>,
    name_v6: Option<String>,
    domains: Vec<String>,
}

/** @brief 권한 계층의 설정. 영역 원본이 하나라도 있을 때만 담긴다. */
#[derive(Clone, Debug, PartialEq)]
struct AuthorityPlan {
    /** @brief 권한 응답에 RA 비트를 켤지. */
    recursion_offered: bool,
}

/** @brief DDR 계층의 설정. 알릴 전송은 암호화 수신 주소에서 나온다. */
#[derive(Clone, Debug, PartialEq)]
struct DdrPlan {
    name: String,
    endpoints: Vec<layers::DdrEndpoint>,
}

impl ChainPlan {
    /** @brief 설정에서 체인 계획을 만든다. 파일이나 네트워크는 읽지 않는다. */
    pub(crate) fn new(cfg: &Config) -> Self {
        let recursive = || RecursivePlan::new(cfg);
        let base = match cfg.backend {
            BackendKind::Forward => BasePlan::Forward,
            BackendKind::Recurse => BasePlan::Recurse(recursive()),
            BackendKind::Split => BasePlan::Split {
                recurse: recursive(),
                default: cfg.split_default,
                split_recurse: cfg.split_recurse.clone(),
                split_forward: cfg.split_forward.clone(),
            },
        };
        let forwarder = |servers: &[String]| ForwarderPlan {
            servers: servers.to_vec(),
            bootstrap: cfg.bootstrap.clone(),
            listeners: dns_listeners(cfg),
            query_timeout_secs: cfg.query_timeout_secs,
            upstream_strategy: cfg.upstream_strategy,
            upstream_concurrency: cfg.upstream_concurrency,
        };
        Self {
            base,
            fallback: (!cfg.fallback_upstreams.is_empty())
                .then(|| forwarder(&cfg.fallback_upstreams)),
            forward_validation: cfg.forward_validation_active().then(|| ValidationPlan {
                dnssec_strict: cfg.dnssec_strict,
                val_permissive_mode: cfg.val_permissive_mode,
                ignore_cd_flag: cfg.ignore_cd_flag,
                domain_insecure: cfg.domain_insecure.clone(),
                root_key_sentinel: cfg.root_key_sentinel,
                dnssec_anchor_file: cfg.dnssec_anchor_file.clone(),
            }),
            cachedb: cfg.cachedb_redis_host.as_ref().map(|host| CacheDbPlan {
                host: host.clone(),
                port: cfg.cachedb_redis_port,
                bootstrap: cfg.bootstrap.clone(),
                expire_secs: cfg.cachedb_redis_expire_secs,
            }),
            ecs_mode: cfg.ecs_mode,
            ecs_custom_ip: cfg.ecs_custom_ip,
            cache_enabled: cfg.cache_enabled,
            cache_size: cfg.cache_size,
            sharded_cache: cfg.sharded_cache,
            cache_shards: cfg.cache_shards,
            min_ttl: cfg.min_ttl,
            max_ttl: cfg.max_ttl,
            neg_min_ttl: cfg.neg_min_ttl,
            neg_max_ttl: cfg.neg_max_ttl,
            serve_stale_secs: cfg.serve_stale_secs,
            serve_expired_reply_ttl: cfg.serve_expired_reply_ttl,
            serve_expired_ttl_reset: cfg.serve_expired_ttl_reset,
            serve_expired_client_timeout_ms: cfg.serve_expired_client_timeout_ms,
            serve_stale_refresh: cfg.serve_stale_refresh,
            prefetch: cfg.prefetch,
            prefetch_interval_secs: cfg.prefetch_interval_secs,
            prefetch_min_hits: cfg.prefetch_min_hits,
            prefetch_ttl_pct: cfg.prefetch_ttl_pct,
            local_a: cfg.local_a.clone(),
            local_aaaa: cfg.local_aaaa.clone(),
            name_ratelimit_per_sec: cfg.name_ratelimit_per_sec,
            name_ratelimit_labels: cfg.name_ratelimit_labels,
            stub_zones: cfg
                .stub_zones
                .iter()
                .map(|zone| (zone.suffix.clone(), forwarder(&zone.servers)))
                .collect(),
            dhcp_local_domain: cfg.dhcp_local_domain.clone(),
            ipset: ipset_layer_active(cfg).then(|| IpsetPlan {
                name_v4: cfg.ipset_name_v4.clone(),
                name_v6: cfg.ipset_name_v6.clone(),
                domains: cfg.ipset_domains.clone(),
            }),
            authority: authority_sources_configured(cfg).then(|| AuthorityPlan {
                recursion_offered: recursion_offered_by(cfg),
            }),
            acme_challenge: cfg.acme_directory_url.is_some(),
            ddr: (!cfg.ddr_name.is_empty()).then(|| DdrPlan {
                name: cfg.ddr_name.clone(),
                endpoints: ddr_endpoints_from(cfg),
            }),
            dynamic_records: cfg.dynamic_records.clone(),
            cache_namespace: cache_namespace_base(cfg),
        }
    }

    /** @brief 기본 체인이 Split 로컬 주소 계층을 얹는지. */
    pub(crate) fn is_split(&self) -> bool {
        matches!(self.base, BasePlan::Split { .. })
    }

    /** @brief 공유 캐시에서 기본 체인이 쓰는 이름 공간. */
    pub(crate) fn cache_namespace(&self) -> &str {
        &self.cache_namespace
    }
}

impl RecursivePlan {
    fn new(cfg: &Config) -> Self {
        Self {
            query_timeout_secs: cfg.query_timeout_secs,
            roots: recursor_roots(cfg),
            prefer_ip4: cfg.prefer_ip4,
            prefer_ip6: cfg.prefer_ip6,
            do_ip4: cfg.do_ip4,
            do_ip6: cfg.do_ip6,
            domain_insecure: cfg.domain_insecure.clone(),
            recursion_limit: cfg.recursion_limit,
            cname_limit: cfg.cname_limit,
            dname_limit: cfg.dname_limit,
            ns_recursion_limit: cfg.ns_recursion_limit,
            recurse_deny_server: cfg.recurse_deny_server.clone(),
            recurse_allow_server: cfg.recurse_allow_server.clone(),
            qname_minimisation_strict: cfg.qname_minimisation_strict,
            harden_referral_path: cfg.harden_referral_path,
            root_key_sentinel: cfg.root_key_sentinel,
            val_nsec3_max_iterations: cfg.val_nsec3_max_iterations,
            ns_cache_size: cfg.ns_cache_size,
            use_caps_for_id: cfg.use_caps_for_id,
            lowercase_outgoing: cfg.lowercase_outgoing,
            dnssec: cfg.dnssec,
            dnssec_strict: cfg.dnssec_strict,
            val_permissive_mode: cfg.val_permissive_mode,
            ignore_cd_flag: cfg.ignore_cd_flag,
            dnssec_anchor_file: cfg.dnssec_anchor_file.clone(),
            dnssec_rfc5011: cfg.dnssec_rfc5011,
            trust_anchor_signaling: cfg.trust_anchor_signaling,
            harden_below_nxdomain: cfg.harden_below_nxdomain,
            aggressive_nsec: cfg.aggressive_nsec,
            cache_size: cfg.cache_size,
            max_ttl: cfg.max_ttl,
            neg_min_ttl: cfg.neg_min_ttl,
            neg_max_ttl: cfg.neg_max_ttl,
        }
    }

    /** @brief 재귀 질의 하나에 기다리는 시간. */
    pub(crate) fn timeout(&self) -> Duration {
        Duration::from_secs(self.query_timeout_secs)
    }

    /** @brief RFC 5011 앵커 상태를 적을 파일. 설정에 없으면 작업 디렉터리의 기본 파일을 쓴다. */
    pub(crate) fn anchor_state_file(&self) -> std::path::PathBuf {
        self.dnssec_anchor_file
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("onetdns-anchors.txt"))
    }

    /** @brief 재귀가 시작할 루트 서버들. */
    pub(crate) fn roots(&self) -> Vec<SocketAddr> {
        self.roots.clone()
    }

    /** @brief 물어볼 권한 서버를 거르는 거부 목록과 허용 목록. */
    pub(crate) fn server_acl(&self) -> (Vec<onetdns_core::IpNet>, Vec<onetdns_core::IpNet>) {
        (
            self.recurse_deny_server.clone(),
            self.recurse_allow_server.clone(),
        )
    }

    /** @brief 재귀 캐시에 담는 TTL 의 상한. */
    pub(crate) fn max_ttl(&self) -> u32 {
        self.max_ttl as u32
    }
}

impl ForwarderPlan {
    /**
     * @brief 전달할 업스트림을 만든다.
     * @param label  업스트림이 이 서버를 가리킬 때 오류에 넣을 설정 이름.
     * @return 업스트림이 이 서버의 수신 주소를 가리키면 실패.
     */
    fn upstreams(&self, label: &str) -> Result<Vec<onetdns_forward::Upstream>, String> {
        let upstreams = upstream::servers_to_upstreams(&self.servers, &self.bootstrap);
        upstream::ensure_not_listener(&upstreams, &self.listeners, label)?;
        Ok(upstreams)
    }

    /** @brief 업스트림으로 전달기를 만든다. */
    fn forwarder(&self, upstreams: Vec<onetdns_forward::Upstream>) -> onetdns_forward::Forwarder {
        onetdns_forward::Forwarder::with_upstreams(
            upstreams,
            Duration::from_secs(self.query_timeout_secs),
        )
        .with_strategy(forward_strategy(self.upstream_strategy))
        .with_parallel_limit(self.upstream_concurrency)
    }
}

/**
 * @brief 새 재귀 리졸버에 딸려 시작한 보조 작업의 종료 신호.
 * @details 리졸버를 쓰기로 정하기 전에 버리면 작업을 멈춘다. 멈추지 않으면 아무도 쓰지 않는
 *          앵커 핸들을 갱신하는 스레드가 세대가 끝날 때까지 남는다.
 */
pub(crate) struct PendingJobs(Option<Arc<std::sync::atomic::AtomicBool>>);

impl PendingJobs {
    /** @brief 이전 작업을 멈추고 이 작업을 등록한다. 신호가 없으면 이전 작업만 멈춘다. */
    fn adopt(mut self, jobs: &EdgeServices) {
        jobs.replace_all(self.0.take());
    }
}

impl Drop for PendingJobs {
    fn drop(&mut self) {
        if let Some(stop) = self.0.take() {
            stop.store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

/** @brief 계획대로 만든 기반. 재귀를 쓰면 그 리졸버와 딸린 작업을 함께 가진다. */
pub(crate) struct PreparedBase {
    /** @brief 기반 리졸버. */
    resolver: Arc<dyn native::Resolver>,
    /** @brief reactor 레인이 쓸 재귀 리졸버. 전달만 하면 없다. */
    recursor: Option<Arc<onetdns_recurse::Recursor>>,
    /** @brief 재귀 리졸버에 딸린 작업. */
    jobs: PendingJobs,
}

/** @brief 재귀 기반을 만들 때 쓰는 이 세대의 핸들. */
pub(crate) struct RecursiveBase {
    /** @brief 차단 응답 TTL. */
    pub(crate) block_ttl: Arc<std::sync::atomic::AtomicU32>,
    /** @brief NS 이름에 적용하는 차단 엔진. */
    pub(crate) filter: Arc<SharedFilter>,
    /** @brief 로컬 응답 TTL. */
    pub(crate) local_ttl: Arc<std::sync::atomic::AtomicU32>,
    /**
     * @brief 이 세대가 끝날 때 기다릴 스레드.
     * @details ServiceCleanup 은 드롭될 때 스레드를 전부 내린다. 그것을 복제해 넘기면 기반이
     *          사라질 때 서비스가 함께 죽으므로 추적 목록만 넘긴다.
     */
    pub(crate) thread_tracker: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    /** @brief 이 세대의 종료 플래그. */
    pub(crate) shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl RecursiveBase {
    /**
     * @brief 계획대로 재귀 리졸버를 만들고 재귀 전용 계층을 얹는다.
     * @details 딸린 작업은 새 종료 신호로 시작하고 등록하지 않는다. 이전 작업은 이 기반을 설치할
     *          때 멈추므로, 여기서 실패하거나 결과를 버려도 지금 쓰는 리졸버의 작업은 그대로 돈다.
     */
    fn build(&self, plan: &RecursivePlan) -> BoxResult<PreparedBase> {
        let Self {
            block_ttl,
            filter,
            local_ttl,
            thread_tracker,
            shutdown,
        } = self;
        let timeout = plan.timeout();
        let prefer = if plan.prefer_ip6 {
            Some(true)
        } else if plan.prefer_ip4 {
            Some(false)
        } else {
            None
        };
        let insecure: Vec<onetdns_proto::Name> = plan
            .domain_insecure
            .iter()
            .map(|name| {
                onetdns_proto::Name::from_str(name).map_err(|_| {
                    crate::anyhow!(format!(
                        "Invalid DNS name in the DNSSEC validation exceptions: {name}"
                    ))
                })
            })
            .collect::<BoxResult<_>>()?;
        let (deny, allow) = plan.server_acl();
        let jobs_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let jobs = PendingJobs(Some(jobs_stop.clone()));
        let mut recursor = new_recursor(plan.roots(), timeout)
            .with_recursion_limit(plan.recursion_limit)
            .with_cname_limit(plan.cname_limit)
            .with_dname_limit(plan.dname_limit)
            .with_server_acl(deny, allow)
            .with_ip_family(plan.do_ip4, plan.do_ip6, prefer)
            .with_qname_min_strict(plan.qname_minimisation_strict)
            .with_harden_referral_path(plan.harden_referral_path)
            .with_domain_insecure(insecure)
            .with_root_key_sentinel(plan.root_key_sentinel)
            .with_nsec3_max_iterations(plan.val_nsec3_max_iterations)
            .with_ns_cache_max(plan.ns_cache_size)
            .with_recursive_cache_ttl_max(plan.max_ttl())
            .with_ns_side_query_limit(plan.ns_recursion_limit as usize)
            .with_caps_for_id(plan.use_caps_for_id)
            .with_lowercase_outgoing(plan.lowercase_outgoing);
        if plan.dnssec {
            recursor = recursor
                .with_dnssec()
                .with_dnssec_strict(plan.dnssec_strict)
                .with_dnssec_permissive(plan.val_permissive_mode)
                .with_ignore_cd(plan.ignore_cd_flag);

            if let Some(path) = plan.dnssec_anchor_file.as_deref() {
                recursor = recursor.with_trust_anchors(load_configured_trust_anchors(path)?);
            }

            if plan.dnssec_rfc5011 {
                let thread = spawn_rfc5011(plan, recursor.anchors_handle(), jobs_stop.clone())
                    .with_context(|| "Could not start the RFC 5011 trust anchor update thread")?;
                track_service_thread(thread_tracker, thread);
            }
            if plan.trust_anchor_signaling {
                let (deny, allow) = plan.server_acl();
                let thread = spawn_ta_signaling(
                    recursor.anchors_handle(),
                    timeout,
                    plan.roots(),
                    deny,
                    allow,
                    plan.max_ttl(),
                    jobs_stop.clone(),
                )
                .with_context(|| "Could not start the RFC 8145 trust anchor signaling thread")?;
                track_service_thread(thread_tracker, thread);
            }
        }

        if let Some(thread) = detect_dns53_interception(plan.roots(), timeout, shutdown.clone()) {
            track_service_thread(thread_tracker, thread);
        }

        let recursor = Arc::new(recursor);
        let mut base: Arc<dyn native::Resolver> = Arc::new(native::NativeBackend::Recurse {
            recursor: recursor.clone(),
            ns_rpz: Some(filter.clone()),
            block_ttl: block_ttl.clone(),
            local_ttl: local_ttl.clone(),
        });
        if plan.harden_below_nxdomain {
            base = Arc::new(layers::BelowNxdomainLayer::new(
                base,
                plan.cache_size as usize,
                plan.neg_min_ttl as u32,
                plan.neg_max_ttl as u32,
            ));
        }
        if plan.aggressive_nsec {
            base = Arc::new(layers::AggressiveNsecLayer::new(
                base,
                plan.cache_size as usize,
                plan.neg_min_ttl as u32,
                plan.neg_max_ttl as u32,
            ));
        }
        Ok(PreparedBase {
            resolver: base,
            recursor: Some(recursor),
            jobs,
        })
    }
}

/** @brief 계획의 처리 방식에 맞는 기반 리졸버를 만든다. */
pub(crate) struct ResolverBase {
    /** @brief 전달 리졸버 슬롯. */
    pub(crate) forward_slot: native::ResolverSlot,
    /** @brief 재귀 기반. */
    pub(crate) recurse: RecursiveBase,
}

impl ResolverBase {
    /** @brief 전달 기반. 슬롯을 감싸므로 전달 경로를 교체하면 이 기반도 따라간다. */
    fn forward(&self) -> Arc<dyn native::Resolver> {
        Arc::new(self.forward_slot.clone())
    }

    /** @brief 계획의 처리 방식에 맞는 기반을 만든다. */
    fn build(&self, plan: &ChainPlan) -> BoxResult<PreparedBase> {
        Ok(match &plan.base {
            BasePlan::Recurse(recurse) => self.recurse.build(recurse)?,
            BasePlan::Forward => PreparedBase {
                resolver: self.forward(),
                recursor: None,
                jobs: PendingJobs(None),
            },
            BasePlan::Split {
                recurse,
                default,
                split_recurse,
                split_forward,
            } => {
                let default = match default {
                    SplitTarget::Forward => layers::Route::Forward,
                    SplitTarget::Recurse => layers::Route::Recurse,
                };
                let recurse = self.recurse.build(recurse)?;
                PreparedBase {
                    resolver: Arc::new(
                        layers::SplitResolver::new(
                            self.forward(),
                            recurse.resolver,
                            default,
                            split_recurse,
                            split_forward,
                        )
                        .map_err(|error| crate::anyhow!(error))?,
                    ),
                    recursor: recurse.recursor,
                    jobs: recurse.jobs,
                }
            }
        })
    }
}

/**
 * @brief 기본 해석 체인을 만들고 이 세대에 설치한다.
 *
 * @details 만드는 단계는 실패할 수 있지만 이 세대의 상태를 바꾸지 않는다. 설치 단계는 실패하지
 *          않는다. 설정 교체는 다른 준비가 모두 끝난 뒤에 설치하므로, 어느 단계에서 실패해도
 *          지금 쓰는 체인과 그 캐시, 재귀 리졸버의 보조 작업이 그대로 남는다.
 */
pub(crate) struct DefaultChain {
    /** @brief 기반 리졸버를 만드는 핸들. */
    pub(crate) base: ResolverBase,
    /** @brief 공통 계층을 쌓는 핸들. */
    pub(crate) layers: ChainLayers,
    /** @brief 기본 체인의 응답 캐시를 넣어 두는 슬롯. wire 빠른 경로가 읽는다. */
    pub(crate) cache_slot: Arc<Mutex<Option<cache::CacheHandle>>>,
    /** @brief 재귀 리졸버에 딸린 보조 작업. */
    pub(crate) recursor_jobs: Arc<EdgeServices>,
}

/** @brief 만들었지만 아직 설치하지 않은 기본 체인. 설치하지 않고 버리면 딸린 작업도 멈춘다. */
pub(crate) struct PreparedChain {
    /** @brief 공통 계층까지 쌓은 체인. */
    resolver: Arc<dyn native::Resolver>,
    /** @brief 이 체인의 응답 캐시. */
    cache: cache::CacheHandle,
    /** @brief reactor 레인이 쓸 재귀 리졸버. 전달만 하면 없다. */
    recursor: Option<Arc<onetdns_recurse::Recursor>>,
    /** @brief 재귀 리졸버에 딸린 작업. */
    jobs: PendingJobs,
}

/** @brief 설치한 기본 체인. */
pub(crate) struct InstalledChain {
    /** @brief 공통 계층까지 쌓은 체인. */
    pub(crate) resolver: Arc<dyn native::Resolver>,
    /** @brief 이 체인의 응답 캐시. */
    pub(crate) cache: cache::CacheHandle,
    /** @brief reactor 레인이 쓸 재귀 리졸버. 전달만 하면 없다. */
    pub(crate) recursor: Option<Arc<onetdns_recurse::Recursor>>,
}

impl DefaultChain {
    /** @brief 계획대로 기본 체인을 만든다. 이 세대의 상태는 바꾸지 않는다. */
    pub(crate) fn prepare(&self, plan: &ChainPlan) -> Result<PreparedChain, String> {
        let PreparedBase {
            resolver,
            recursor,
            jobs,
        } = self.base.build(plan).map_err(|error| error.to_string())?;
        /*
         * 공유 캐시 이름 공간도 새 계획에서 낸다. 이전 것을 쓰면 처리 방식이나 DNSSEC 을
         * 바꿔도 같은 슬롯을 가리켜, 이전 의미로 담긴 답이 새 설정의 답인 것처럼 나온다.
         */
        let (resolver, cache) = self.layers.wrap_common_layers(
            plan,
            resolver,
            true,
            plan.is_split(),
            plan.cache_namespace(),
        )?;
        Ok(PreparedChain {
            resolver,
            cache,
            recursor,
            jobs,
        })
    }

    /** @brief 캐시와 재귀 리졸버를 올리고 이전 보조 작업을 멈춘다. 체인 슬롯은 호출한 쪽이 바꾼다. */
    pub(crate) fn install(&self, prepared: PreparedChain) -> InstalledChain {
        let PreparedChain {
            resolver,
            cache,
            recursor,
            jobs,
        } = prepared;
        *self.cache_slot.lock_recover() = Some(cache.clone());
        jobs.adopt(&self.recursor_jobs);
        InstalledChain {
            resolver,
            cache,
            recursor,
        }
    }
}

/** @brief 공통 계층을 쌓을 때 쓰는 이 세대의 핸들. */
#[derive(Clone)]
pub(crate) struct ChainLayers {
    /** @brief 차단 응답 TTL. */
    pub(crate) block_ttl: Arc<std::sync::atomic::AtomicU32>,
    /** @brief DHCPv4 임대 풀. 서비스가 꺼져 있으면 없다. */
    pub(crate) dhcp_slot: Arc<Mutex<Option<Arc<Mutex<dhcp::LeasePool>>>>>,
    /** @brief 로컬 응답 TTL. */
    pub(crate) local_ttl: Arc<std::sync::atomic::AtomicU32>,
    /** @brief 업스트림으로 흘리지 않을 이름의 판정. */
    pub(crate) local_only_names: Arc<layers::LocalOnlyNames>,
    /** @brief 캐시 적중을 남길 질의 기록. 없으면 남기지 않는다. */
    pub(crate) recorder: Option<onetdns_control::Recorder>,
    /** @brief 이 세대의 종료 플래그. */
    pub(crate) shutdown: Arc<std::sync::atomic::AtomicBool>,
    /** @brief Split 로컬 주소 응답을 wire 캐시에 넣을 때 쓰는 캐시. */
    pub(crate) split_local_wire_cache: Arc<std::sync::OnceLock<cache::CacheHandle>>,
    /** @brief 권한 영역 저장소. */
    pub(crate) zone_store: Arc<ArcSwap<onetdns_authority::ZoneStore>>,
}

impl ChainLayers {
    /**
     * @brief 기반 위에 공통 계층을 쌓는다. 이 세대의 상태는 바꾸지 않는다.
     * @param report  켜진 기능을 기록에 남길지.
     * @param split_local_addresses  Split 로컬 주소 계층을 얹을지.
     * @param cache_ns  공유 캐시에서 이 체인이 쓰는 이름 공간.
     * @return 쌓은 체인과 그 응답 캐시.
     */
    pub(crate) fn wrap_common_layers(
        &self,
        plan: &ChainPlan,
        mut base: Arc<dyn native::Resolver>,
        report: bool,
        split_local_addresses: bool,
        cache_ns: &str,
    ) -> Result<(Arc<dyn native::Resolver>, cache::CacheHandle), String> {
        let Self {
            block_ttl,
            dhcp_slot,
            local_ttl,
            local_only_names,
            recorder,
            shutdown,
            split_local_wire_cache,
            zone_store,
        } = self;
        // layer-order:begin
        base = Arc::new(layers::LocalOnlyLayer::new(
            base,
            local_only_names.clone(),
            block_ttl.clone(),
        ));

        if let Some(fallback) = &plan.fallback {
            let upstreams = fallback.upstreams("fallback_upstreams")?;
            if !upstreams.is_empty() {
                let fallback: Arc<dyn native::Resolver> = Arc::new(native::NativeBackend::Forward(
                    fallback.forwarder(upstreams),
                ));
                base = Arc::new(layers::FallbackLayer::new(base, fallback));
            }
        }

        /*
         * 예비 업스트림까지 감싼 뒤에 얹는다. 어느 업스트림이 답했든 이 서버가 검증한 것만
         * 위로 올라가고, 위쪽 캐시에는 검증된 응답만 담긴다.
         */
        if let Some(validation) = &plan.forward_validation {
            let insecure_domains = validation
                .domain_insecure
                .iter()
                .map(|name| {
                    onetdns_proto::Name::from_str(name).map_err(|_| {
                        format!("Invalid DNS name in the DNSSEC validation exceptions: {name}")
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            base = Arc::new(dnssecfwd::ForwardValidateLayer::new(
                base,
                Arc::new(onetdns_core::ArcSwap::new(Arc::new(
                    forward_trust_anchors(validation.dnssec_anchor_file.as_deref())
                        .map_err(|error| error.to_string())?,
                ))),
                dnssecfwd::ForwardValidationPolicy {
                    strict: validation.dnssec_strict,
                    permissive: validation.val_permissive_mode,
                    ignore_cd: validation.ignore_cd_flag,
                    insecure_domains,
                    root_key_sentinel: validation.root_key_sentinel,
                },
            ));
        }

        if let Some(cachedb) = &plan.cachedb {
            let addr = cachedb_redis_addr(&cachedb.host, cachedb.port, &cachedb.bootstrap)?;
            let redis = Arc::new(redis::RedisClient::new(addr));
            let namespace = format!("{:x}", Sha256::digest(cache_ns.as_bytes()))[..16].to_string();
            base = Arc::new(layers::CacheDbLayer::new(
                base,
                redis,
                cachedb.expire_secs,
                plan.min_ttl as u32,
                plan.max_ttl as u32,
                namespace,
            ));
            if report {
                onetdns_core::info!(event = "cache.redis_enabled", %addr, "Using external Redis response cache");
            }
        }

        let mut chain = base;
        match plan.ecs_mode {
            EcsMode::Send => {
                if let Some(ip) = plan.ecs_custom_ip {
                    chain = Arc::new(layers::EcsLayer::new(chain, ip));
                }
            }
            EcsMode::Strip => chain = Arc::new(layers::EcsLayer::strip(chain)),
            EcsMode::Off => {}
        }

        let prefetch_backend = plan.prefetch.then(|| chain.clone());
        let response_cache;
        {
            let positive_cache_enabled = plan.cache_enabled && plan.cache_size > 0;
            let shards = if positive_cache_enabled && plan.sharded_cache {
                plan.cache_shards
            } else {
                1
            };
            let cl = cache::CacheLayer::new(
                chain,
                plan.cache_size.max(1) as usize,
                shards,
                plan.min_ttl as u32,
                plan.max_ttl as u32,
                plan.neg_min_ttl as u32,
                plan.neg_max_ttl as u32,
            )
            .with_positive_cache(positive_cache_enabled)
            .with_recorder(recorder.clone());
            response_cache = cl.handle();
            chain = Arc::new(cl);
        }

        if plan.serve_stale_secs > 0 {
            chain = Arc::new(
                layers::ServeStaleLayer::new(
                    chain,
                    Duration::from_secs(plan.serve_stale_secs),
                    plan.cache_size as usize,
                    plan.min_ttl as u32,
                    plan.max_ttl as u32,
                    plan.serve_expired_reply_ttl,
                    plan.serve_expired_ttl_reset,
                    (plan.serve_expired_client_timeout_ms > 0)
                        .then(|| Duration::from_millis(plan.serve_expired_client_timeout_ms)),
                    plan.serve_stale_refresh,
                )
                .with_shutdown(shutdown.clone()),
            );
        }

        if plan.prefetch {
            let backend = prefetch_backend.expect("The handler must be ready when prefetch is on");
            let cache_handle = response_cache.clone();

            let refresher: layers::PrefetchRefresher = Arc::new(move |req| {
                let resp = backend.resolve(req)?;
                if resp.header.rcode == onetdns_proto::ResponseCode::NoError.0
                    && !resp.answers.is_empty()
                {
                    cache_handle.store(req, &resp);
                }
                Some(resp)
            });
            chain = Arc::new(layers::PrefetchLayer::with_policy(
                chain,
                refresher,
                Duration::from_secs(plan.prefetch_interval_secs.max(1)),
                plan.cache_size as usize,
                plan.prefetch_min_hits,
                plan.prefetch_ttl_pct,
                shutdown.clone(),
            ));
        }

        if split_local_addresses && (!plan.local_a.is_empty() || !plan.local_aaaa.is_empty()) {
            let addresses =
                layers::LocalAddressTable::new(&plan.local_a, &plan.local_aaaa, local_ttl.clone())?;
            chain = Arc::new(layers::LocalAddressLayer::new(
                chain,
                Arc::new(addresses),
                Some(split_local_wire_cache.clone()),
            ));
        }

        if plan.name_ratelimit_per_sec > 0 {
            chain = Arc::new(layers::NameRateLimitLayer::new(
                chain,
                plan.name_ratelimit_per_sec,
                plan.name_ratelimit_labels,
            ));
        }

        if !plan.stub_zones.is_empty() {
            let mut stubs: Vec<(String, Arc<dyn native::Resolver>)> = Vec::new();
            for (suffix, zone) in &plan.stub_zones {
                let ups = zone.upstreams(&format!("stub zone '{suffix}'"))?;
                if ups.is_empty() {
                    return Err(format!(
                        "Stub zone '{suffix}' has no usable upstream DNS servers"
                    ));
                }
                let guarded: Arc<dyn native::Resolver> =
                    Arc::new(cache::CacheLayer::failure_guard(
                        Arc::new(native::NativeBackend::Forward(zone.forwarder(ups))),
                        64,
                    ));
                stubs.push((suffix.clone(), guarded));
            }
            chain = Arc::new(layers::StubLayer::new(chain, stubs)?);
        }

        if let Some(pool) = dhcp_slot.lock_recover().as_ref() {
            if !plan.dhcp_local_domain.is_empty() {
                chain = Arc::new(layers::DhcpDnsLayer::new(
                    chain,
                    pool.clone(),
                    &plan.dhcp_local_domain,
                    local_ttl.clone(),
                ));
            }
        }

        if let Some(ipset) = &plan.ipset {
            chain = Arc::new(layers::IpsetLayer::new(
                chain,
                ipset.name_v4.clone(),
                ipset.name_v6.clone(),
                &ipset.domains,
            )?);
        }

        if let Some(authority) = &plan.authority {
            chain = Arc::new(
                layers::AuthorityLayer::new(chain, zone_store.clone())
                    .with_recursion_offered(authority.recursion_offered),
            );
        }

        if plan.acme_challenge {
            chain = Arc::new(layers::AcmeChallengeLayer::new(chain));
        }

        if let Some(ddr) = &plan.ddr {
            if let Some(layer) = layers::DdrLayer::new(chain.clone(), &ddr.name, &ddr.endpoints)? {
                if report {
                    onetdns_core::info!(
                        event = "ddr.enabled",
                        name = %ddr.name,
                        endpoints = ddr.endpoints.len(),
                        "Advertising encrypted DNS upgrade (DDR)"
                    );
                }
                chain = Arc::new(layer);
            }
        }

        if !plan.dynamic_records.is_empty() {
            let dl = layers::DynamicRecordLayer::new(chain.clone(), &plan.dynamic_records)?;
            if !dl.is_empty() {
                if report {
                    onetdns_core::info!(
                        event = "dynamic_records.enabled",
                        count = plan.dynamic_records.len(),
                        "Dynamic DNS records are enabled"
                    );
                }
                chain = Arc::new(dl);
            }
        }

        Ok((chain, response_cache))
        // layer-order:end
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    /** @brief 전달 기반으로 체인을 만드는 핸들. 재귀 기반은 루트로 탐지 질의를 보내므로 쓰지 않는다. */
    fn default_chain() -> DefaultChain {
        let block_ttl = Arc::new(AtomicU32::new(10));
        let local_ttl = Arc::new(AtomicU32::new(10));
        let shutdown = Arc::new(AtomicBool::new(false));
        DefaultChain {
            base: ResolverBase {
                forward_slot: native::ResolverSlot::new(Arc::new(native::UnbuiltForward)),
                recurse: RecursiveBase {
                    block_ttl: block_ttl.clone(),
                    filter: Arc::new(SharedFilter::from_pointee(
                        onetdns_filter::BlockEngine::empty(onetdns_core::BlockResponse::NxDomain),
                    )),
                    local_ttl: local_ttl.clone(),
                    thread_tracker: Arc::default(),
                    shutdown: shutdown.clone(),
                },
            },
            layers: ChainLayers {
                block_ttl,
                dhcp_slot: Arc::default(),
                local_ttl,
                local_only_names: Arc::new(layers::LocalOnlyNames::new(true, true, true)),
                recorder: None,
                shutdown,
                split_local_wire_cache: Arc::default(),
                zone_store: Arc::new(ArcSwap::new(Arc::new(onetdns_authority::ZoneStore::new()))),
            },
            cache_slot: Arc::default(),
            recursor_jobs: Arc::default(),
        }
    }

    /** @brief 전달만 하는 설정. */
    fn forward_config() -> Config {
        let mut cfg = Config::default();
        cfg.backend = BackendKind::Forward;
        cfg.listen = vec!["127.0.0.1:5399".parse().unwrap()];
        cfg
    }

    #[test]
    /**
     * @brief 체인을 만들다 실패하거나 만든 것을 버려도 지금 쓰는 캐시와 보조 작업이 그대로인지.
     * @details 설정 교체는 체인을 다른 준비와 함께 먼저 만들고, 모두 성공한 뒤에 설치한다. 만드는
     *          단계가 캐시 슬롯을 바꾸거나 이전 작업을 멈추면, 교체가 실패했는데도 빠른 경로가 쓰지
     *          않는 캐시를 읽고 신뢰 앵커 갱신이 멈춘다.
     */
    fn preparing_a_chain_leaves_the_running_one_alone() {
        let chain = default_chain();
        let cfg = forward_config();
        let running = chain.install(chain.prepare(&ChainPlan::new(&cfg)).unwrap());
        let old_jobs = chain.recursor_jobs.restart_all();

        let mut broken = cfg.clone();
        broken.fallback_upstreams = vec!["127.0.0.1:5399".to_string()];
        assert!(chain.prepare(&ChainPlan::new(&broken)).is_err());
        drop(chain.prepare(&ChainPlan::new(&cfg)).unwrap());

        let slot = chain.cache_slot.lock_recover().clone().unwrap();
        assert!(slot.ptr_eq(&running.cache));
        assert!(!old_jobs.load(Ordering::Acquire));

        let installed = chain.install(chain.prepare(&ChainPlan::new(&cfg)).unwrap());
        let slot = chain.cache_slot.lock_recover().clone().unwrap();
        assert!(slot.ptr_eq(&installed.cache));
        assert!(!slot.ptr_eq(&running.cache));
        assert!(old_jobs.load(Ordering::Acquire));
    }

    #[test]
    /** @brief 설치하지 않고 버린 체인의 보조 작업이 멈추고, 설치한 체인의 작업은 도는지. */
    fn discarded_recursor_jobs_stop_and_adopted_ones_run() {
        let discarded = Arc::new(AtomicBool::new(false));
        drop(PendingJobs(Some(discarded.clone())));
        assert!(discarded.load(Ordering::Acquire));

        let jobs = EdgeServices::default();
        let adopted = Arc::new(AtomicBool::new(false));
        PendingJobs(Some(adopted.clone())).adopt(&jobs);
        assert!(!adopted.load(Ordering::Acquire));
        PendingJobs(None).adopt(&jobs);
        assert!(adopted.load(Ordering::Acquire));
    }
}
