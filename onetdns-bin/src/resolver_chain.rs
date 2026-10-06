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
    /**
     * @brief 업스트림이 전달한 답을 검증할 때의 방침.
     * @details dnssec 을 켜면 처리 방식과 상관없이 담는다. 클라이언트 경로는 재귀 방식에서도
     *          업스트림에 전달하기 때문이다. 어느 체인에 검증 계층을 얹을지는 ChainBase 가 정한다.
     */
    validation: Option<ValidationPlan>,
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

/** @brief 업스트림이 전달한 답을 이 서버가 직접 검증할 때의 설정. */
#[derive(Clone, Debug, PartialEq)]
struct ValidationPlan {
    dnssec_strict: bool,
    val_permissive_mode: bool,
    ignore_cd_flag: bool,
    domain_insecure: Vec<String>,
    root_key_sentinel: bool,
    dnssec_anchor_file: Option<std::path::PathBuf>,
}

/**
 * @brief 외부 Redis 공유 캐시의 설정. 호스트 이름은 조립할 때 bootstrap 으로 푼다.
 * @details 기본 전달 업스트림과 로컬 전용 이름 판정은 체인을 조립하는 데 쓰지 않는다. 그래도
 *          CacheDbLayer 아래의 답을 바꾸므로 공유 캐시를 쓸 때만 여기에 담아 해석 맥락에 넣는다.
 *          공유 캐시를 쓰지 않으면 이 값들만 바꾼 설정은 체인을 다시 만들지 않는다.
 */
#[derive(Clone, Debug, PartialEq)]
struct CacheDbPlan {
    host: String,
    port: u16,
    bootstrap: Vec<IpAddr>,
    expire_secs: u64,
    secret: onetdns_core::SecretString,
    username: Option<String>,
    password: Option<onetdns_core::SecretString>,
    tls: bool,
    tls_ca: Option<std::path::PathBuf>,
    /**
     * @brief 기본 전달 기반이 질의하는 업스트림.
     * @details 정렬하고 중복을 없앤 목록을 담으므로, 순서만 바꾼 설정으로는 체인을 다시 만들지 않는다.
     */
    upstreams: Vec<String>,
    domain_needed: bool,
    bogus_priv: bool,
    empty_zones: bool,
}

impl CacheDbPlan {
    /** @brief Redis 에 붙는 방법. 호스트 이름은 bootstrap 으로 풀고, TLS 를 쓰면 신뢰 저장소를 읽는다. */
    fn redis_options(&self) -> Result<redis::RedisOptions, String> {
        let addr = cachedb_redis_addr(&self.host, self.port, &self.bootstrap)?;
        let tls = if self.tls {
            Some(redis::RedisTls {
                server_name: self.host.clone(),
                roots: tls_material::cachedb_redis_roots(self.tls_ca.as_deref())?,
            })
        } else {
            None
        };
        let auth = self.password.as_ref().map(|password| redis::RedisAuth {
            username: self.username.clone(),
            password: password.clone(),
        });
        Ok(redis::RedisOptions { addr, tls, auth })
    }
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
            validation: cfg.dnssec_validation_active().then(|| ValidationPlan {
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
                secret: cfg.cachedb_redis_secret.clone(),
                username: cfg.cachedb_redis_username.clone(),
                password: cfg.cachedb_redis_password.clone(),
                tls: cfg.cachedb_redis_tls,
                tls_ca: cfg.cachedb_redis_tls_ca.clone(),
                upstreams: canonical_list(
                    cfg.upstreams
                        .iter()
                        .map(ToString::to_string)
                        .chain(cfg.upstream_urls.iter().cloned()),
                ),
                domain_needed: cfg.domain_needed,
                bogus_priv: cfg.bogus_priv,
                empty_zones: cfg.empty_zones,
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
        }
    }

    /** @brief 기본 체인이 Split 로컬 주소 계층을 얹는지. */
    pub(crate) fn is_split(&self) -> bool {
        matches!(self.base, BasePlan::Split { .. })
    }

    /**
     * @brief 이 계획이 값을 읽는 키 가운데 설정 키 표의 그룹으로는 체인을 다시 만들지 않는 키들.
     * @details 이 키들은 바뀌면 자기 그룹을 교체하고, 계획에 그 값을 읽는 구성 요소가 있으면
     *          체인도 다시 만든다. 영역 원본은 하나라도 있는지가 권한 계층을 얹을지 정하므로
     *          늘 든다. new 가 다른 그룹의 키를 새로 읽으면 여기에도 넣어야 한다. 빠뜨리면
     *          관리 화면이 그 키를 바꿔도 재시작하지 않는다고 알리는데, 클라이언트 경로가 있으면
     *          실제로는 재시작한다.
     */
    pub(crate) fn other_group_inputs(&self) -> Vec<&'static str> {
        let mut keys = vec![
            "zones",
            "zones_dir",
            "zones_db",
            "zones_postgres",
            "zones_mysql",
            "zones_lmdb",
            "zones_etcd",
            "secondary",
            "catalog",
        ];
        if !matches!(self.base, BasePlan::Forward) {
            keys.push("query_timeout_secs");
        }
        if self.fallback.is_some() || !self.stub_zones.is_empty() {
            keys.extend([
                "listen",
                "listen_dot",
                "listen_doh",
                "listen_doq",
                "listen_doh3",
                "listen_dnscrypt",
                "query_timeout_secs",
                "upstream_strategy",
                "upstream_concurrency",
            ]);
        }
        if self.cachedb.is_some() {
            keys.extend([
                "upstreams",
                "upstream_urls",
                "domain_needed",
                "bogus_priv",
                "empty_zones",
            ]);
        }
        if self.ddr.is_some() {
            keys.extend([
                "listen_doh",
                "listen_doh3",
                "listen_dot",
                "listen_doq",
                "doh_path",
            ]);
        }
        keys.sort_unstable();
        keys.dedup();
        keys
    }
}

/**
 * @brief 공통 계층 아래에 까는 기반이 무엇인지.
 * @details 공유 캐시는 이 값으로 이 체인의 해석 맥락과 신뢰 앵커를 정한다.
 */
pub(crate) enum ChainBase {
    /** @brief 계획의 처리 방식대로 만든 기반. 재귀가 DNSSEC 을 검증하면 그 신뢰 앵커를 든다. */
    Planned(Option<Arc<ArcSwap<Vec<onetdns_dnssec::Ds>>>>),
    /** @brief 이 업스트림으로만 전달하는 클라이언트 경로. */
    Route {
        /** @brief 정규화한 업스트림 목록. */
        upstreams: String,
        /**
         * @brief 같은 세대의 재귀 리졸버가 검증에 쓰는 신뢰 앵커. 재귀가 검증하지 않으면 없다.
         * @details 경로의 답도 이 앵커로 검증하므로, RFC 5011 갱신이 기본 체인과 경로에 함께
         *          적용된다.
         */
        anchors: Option<Arc<ArcSwap<Vec<onetdns_dnssec::Ds>>>>,
    },
}

impl ChainBase {
    /** @brief 같은 세대의 재귀 리졸버가 검증에 쓰는 신뢰 앵커. */
    fn recursor_anchors(&self) -> Option<&Arc<ArcSwap<Vec<onetdns_dnssec::Ds>>>> {
        match self {
            ChainBase::Planned(anchors) | ChainBase::Route { anchors, .. } => anchors.as_ref(),
        }
    }

    /**
     * @brief 이 기반이 업스트림에서 받은 답을 그대로 올려 보내는지.
     * @details 그렇다면 dnssec 을 켰을 때 그 위에 검증 계층을 얹는다. 재귀 기반은 위임을 따라
     *          내려가면서 스스로 검증하므로 얹지 않는다. 클라이언트 경로는 처리 방식과 상관없이
     *          업스트림에 전달한다.
     */
    fn forwards(&self, plan: &ChainPlan) -> bool {
        match self {
            ChainBase::Planned(_) => !matches!(plan.base, BasePlan::Recurse(_)),
            ChainBase::Route { .. } => true,
        }
    }
}

/**
 * @brief 공유 캐시에서 이 체인의 답을 가르는 해석 맥락.
 * @details CacheDbLayer 아래에서 답의 내용을 바꾸는 설정만 담는다. 계획과 그 안의 설정 묶음을
 *          모두 필드 단위로 풀어 쓰므로, 필드를 더하면 여기서 담을지 정하기 전에는 컴파일되지
 *          않는다. 목록은 정렬하고 중복을 없애므로 순서만 다른 설정은 같은 맥락을 쓴다. 신뢰
 *          앵커는 실행 중에 바뀌므로 여기에 넣지 않고 CacheDbLayer 가 요청마다 지금 쓰는 앵커를
 *          더한다. ECS 옵션과 DO, CD 비트는 요청 키에 이미 들어간다.
 * @warning 같은 Redis를 쓰는 서버는 이 값이 같을 때만 서로의 답을 쓴다. 답을 바꾸는 값을 빼면
 *          그 설정이 다른 서버가 담은 답을 이 서버가 그대로 쓴다.
 */
fn shared_cache_context(plan: &ChainPlan, cachedb: &CacheDbPlan, base: &ChainBase) -> String {
    let ChainPlan {
        base: planned,
        fallback,
        validation,
        min_ttl,
        max_ttl,
        cachedb: _,
        ecs_mode: _,
        ecs_custom_ip: _,
        cache_enabled: _,
        cache_size: _,
        sharded_cache: _,
        cache_shards: _,
        neg_min_ttl: _,
        neg_max_ttl: _,
        serve_stale_secs: _,
        serve_expired_reply_ttl: _,
        serve_expired_ttl_reset: _,
        serve_expired_client_timeout_ms: _,
        serve_stale_refresh: _,
        prefetch: _,
        prefetch_interval_secs: _,
        prefetch_min_hits: _,
        prefetch_ttl_pct: _,
        local_a: _,
        local_aaaa: _,
        name_ratelimit_per_sec: _,
        name_ratelimit_labels: _,
        stub_zones: _,
        dhcp_local_domain: _,
        ipset: _,
        authority: _,
        acme_challenge: _,
        ddr: _,
        dynamic_records: _,
    } = plan;
    let CacheDbPlan {
        bootstrap,
        upstreams: default_upstreams,
        domain_needed,
        bogus_priv,
        empty_zones,
        host: _,
        port: _,
        expire_secs: _,
        secret: _,
        username: _,
        password: _,
        tls: _,
        tls_ca: _,
    } = cachedb;
    let bootstrap = canonical_list(bootstrap.iter());
    let forward = || format!("forward{{upstreams={default_upstreams:?};bootstrap={bootstrap:?}}}");
    let validation = validation.as_ref().filter(|_| base.forwards(plan));
    let base = match (base, planned) {
        (ChainBase::Route { upstreams, .. }, _) => {
            format!("route{{upstreams={upstreams:?};bootstrap={bootstrap:?}}}")
        }
        (ChainBase::Planned(_), BasePlan::Forward) => forward(),
        (ChainBase::Planned(_), BasePlan::Recurse(recurse)) => {
            format!("recurse{{{}}}", recursion_context(recurse))
        }
        (
            ChainBase::Planned(_),
            BasePlan::Split {
                recurse,
                default,
                split_recurse,
                split_forward,
            },
        ) => format!(
            "split{{{};recurse={{{}}};default={default:?};split_recurse={:?};split_forward={:?}}}",
            forward(),
            recursion_context(recurse),
            canonical_names(split_recurse),
            canonical_names(split_forward),
        ),
    };
    format!(
        "base={base};fallback={:?};validation={:?};domain_needed={domain_needed};\
         bogus_priv={bogus_priv};empty_zones={empty_zones};min_ttl={min_ttl};max_ttl={max_ttl}",
        fallback.as_ref().map(forwarder_context),
        validation.map(validation_context),
    )
}

/**
 * @brief 재귀 설정 가운데 답이나 검증 결과를 바꾸는 값.
 * @details 제한 시간, 캐시 크기, 주소 계열처럼 닿을 수 있는 서버만 바꾸는 값은 넣지 않는다. 그런
 *          값은 실패하는 질의를 늘리거나 줄일 뿐이고 실패한 답은 공유 캐시에 담지 않는다.
 */
fn recursion_context(plan: &RecursivePlan) -> String {
    let RecursivePlan {
        roots,
        domain_insecure,
        recursion_limit,
        cname_limit,
        dname_limit,
        recurse_deny_server,
        recurse_allow_server,
        qname_minimisation_strict,
        harden_referral_path,
        root_key_sentinel,
        val_nsec3_max_iterations,
        dnssec,
        dnssec_strict,
        val_permissive_mode,
        ignore_cd_flag,
        harden_below_nxdomain,
        aggressive_nsec,
        query_timeout_secs: _,
        prefer_ip4: _,
        prefer_ip6: _,
        do_ip4: _,
        do_ip6: _,
        ns_recursion_limit: _,
        ns_cache_size: _,
        use_caps_for_id: _,
        lowercase_outgoing: _,
        dnssec_anchor_file: _,
        dnssec_rfc5011: _,
        trust_anchor_signaling: _,
        cache_size: _,
        max_ttl: _,
        neg_min_ttl: _,
        neg_max_ttl: _,
    } = plan;
    format!(
        "roots={:?};insecure={:?};recursion_limit={recursion_limit};cname_limit={cname_limit};\
         dname_limit={dname_limit};deny={:?};allow={:?};qname_min_strict={qname_minimisation_strict};\
         harden_referral={harden_referral_path};sentinel={root_key_sentinel};\
         nsec3_iterations={val_nsec3_max_iterations};dnssec={dnssec};strict={dnssec_strict};\
         permissive={val_permissive_mode};ignore_cd={ignore_cd_flag};\
         below_nxdomain={harden_below_nxdomain};aggressive_nsec={aggressive_nsec}",
        canonical_list(roots.iter()),
        canonical_names(domain_insecure),
        canonical_list(recurse_deny_server.iter()),
        canonical_list(recurse_allow_server.iter()),
    )
}

/** @brief 전달기 설정 가운데 답을 바꾸는 값. 어느 업스트림에 묻는지다. */
fn forwarder_context(plan: &ForwarderPlan) -> String {
    let ForwarderPlan {
        servers,
        bootstrap,
        listeners: _,
        query_timeout_secs: _,
        upstream_strategy: _,
        upstream_concurrency: _,
    } = plan;
    format!(
        "servers={:?};bootstrap={:?}",
        canonical_list(servers.iter()),
        canonical_list(bootstrap.iter())
    )
}

/** @brief 업스트림 응답 검증 설정 가운데 검증 결과를 바꾸는 값. 신뢰 앵커는 CacheDbLayer 가 더한다. */
fn validation_context(plan: &ValidationPlan) -> String {
    let ValidationPlan {
        dnssec_strict,
        val_permissive_mode,
        ignore_cd_flag,
        domain_insecure,
        root_key_sentinel,
        dnssec_anchor_file: _,
    } = plan;
    format!(
        "strict={dnssec_strict};permissive={val_permissive_mode};ignore_cd={ignore_cd_flag};\
         insecure={:?};sentinel={root_key_sentinel}",
        canonical_names(domain_insecure)
    )
}

/** @brief 정렬하고 중복을 없앤 목록. */
fn canonical_list<T: ToString>(values: impl IntoIterator<Item = T>) -> Vec<String> {
    let mut values: Vec<String> = values.into_iter().map(|value| value.to_string()).collect();
    values.sort_unstable();
    values.dedup();
    values
}

/** @brief 대소문자와 끝 점만 다른 도메인 이름을 같게 만든 목록. */
fn canonical_names(names: &[String]) -> Vec<String> {
    canonical_list(
        names
            .iter()
            .map(|name| name.trim_end_matches('.').to_ascii_lowercase()),
    )
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
    /** @brief 재귀 리졸버가 DNSSEC 검증에 쓰는 신뢰 앵커. 검증하지 않으면 없다. */
    anchors: Option<Arc<ArcSwap<Vec<onetdns_dnssec::Ds>>>>,
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

        let anchors = plan.dnssec.then(|| recursor.anchors_handle());
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
            anchors,
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
                anchors: None,
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
                    anchors: recurse.anchors,
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
    /** @brief 재귀 리졸버가 DNSSEC 검증에 쓰는 신뢰 앵커. 검증하지 않으면 없다. */
    anchors: Option<Arc<ArcSwap<Vec<onetdns_dnssec::Ds>>>>,
    /** @brief 이 체인이 쓰는 공유 캐시 클라이언트. 공유 캐시를 쓰지 않으면 없다. */
    shared_cache: Option<Arc<redis::RedisClient>>,
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
    /** @brief 재귀 리졸버가 DNSSEC 검증에 쓰는 신뢰 앵커. 클라이언트 경로의 검증도 이 앵커를 쓴다. */
    pub(crate) anchors: Option<Arc<ArcSwap<Vec<onetdns_dnssec::Ds>>>>,
    /**
     * @brief 이 체인이 쓰는 공유 캐시 클라이언트. 공유 캐시를 쓰지 않으면 없다.
     * @details 클라이언트 경로도 이 클라이언트를 함께 쓴다. 경로마다 따로 만들면 연결 풀도 따로
     *          생겨, 공유 캐시에 여는 연결 수의 상한이 경로 수만큼 곱해진다.
     */
    pub(crate) shared_cache: Option<Arc<redis::RedisClient>>,
}

impl DefaultChain {
    /** @brief 계획대로 기본 체인을 만든다. 이 세대의 상태는 바꾸지 않는다. */
    pub(crate) fn prepare(&self, plan: &ChainPlan) -> Result<PreparedChain, String> {
        let PreparedBase {
            resolver,
            recursor,
            jobs,
            anchors,
        } = self.base.build(plan).map_err(|error| error.to_string())?;
        let shared_cache = match &plan.cachedb {
            Some(cachedb) => Some(Arc::new(redis::RedisClient::new(cachedb.redis_options()?))),
            None => None,
        };
        let (resolver, cache) = self.layers.wrap_common_layers(
            plan,
            resolver,
            true,
            plan.is_split(),
            ChainBase::Planned(anchors.clone()),
            shared_cache.as_ref(),
        )?;
        Ok(PreparedChain {
            resolver,
            cache,
            recursor,
            anchors,
            shared_cache,
            jobs,
        })
    }

    /** @brief 캐시와 재귀 리졸버를 올리고 이전 보조 작업을 멈춘다. 체인 슬롯은 호출한 쪽이 바꾼다. */
    pub(crate) fn install(&self, prepared: PreparedChain) -> InstalledChain {
        let PreparedChain {
            resolver,
            cache,
            recursor,
            anchors,
            shared_cache,
            jobs,
        } = prepared;
        *self.cache_slot.lock_recover() = Some(cache.clone());
        jobs.adopt(&self.recursor_jobs);
        InstalledChain {
            resolver,
            cache,
            recursor,
            anchors,
            shared_cache,
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
     * @param kind  base 가 어떤 기반인지. 공유 캐시가 해석 맥락과 신뢰 앵커를 정할 때 쓴다.
     * @param shared_cache  이 세대의 체인이 함께 쓰는 공유 캐시 클라이언트. 계획에 공유 캐시가
     *                      있으면 있어야 한다.
     * @return 쌓은 체인과 그 응답 캐시.
     */
    pub(crate) fn wrap_common_layers(
        &self,
        plan: &ChainPlan,
        mut base: Arc<dyn native::Resolver>,
        report: bool,
        split_local_addresses: bool,
        kind: ChainBase,
        shared_cache: Option<&Arc<redis::RedisClient>>,
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
        let mut anchors: Vec<_> = match &kind {
            ChainBase::Planned(recursor) => recursor.iter().cloned().collect(),
            ChainBase::Route { .. } => Vec::new(),
        };
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
         * 위로 올라가고, 위쪽 캐시에는 검증된 응답만 담긴다. 같은 세대의 재귀 리졸버가 있으면
         * 그 앵커를 함께 써서, RFC 5011 갱신이 전달한 답의 검증에도 바로 적용되게 한다.
         */
        if let Some(validation) = plan.validation.as_ref().filter(|_| kind.forwards(plan)) {
            let insecure_domains = validation
                .domain_insecure
                .iter()
                .map(|name| {
                    onetdns_proto::Name::from_str(name).map_err(|_| {
                        format!("Invalid DNS name in the DNSSEC validation exceptions: {name}")
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            let validation_anchors = match kind.recursor_anchors() {
                Some(recursor) => recursor.clone(),
                None => Arc::new(onetdns_core::ArcSwap::new(Arc::new(
                    forward_trust_anchors(validation.dnssec_anchor_file.as_deref())
                        .map_err(|error| error.to_string())?,
                ))),
            };
            if !anchors
                .iter()
                .any(|known| Arc::ptr_eq(known, &validation_anchors))
            {
                anchors.push(validation_anchors.clone());
            }
            base = Arc::new(dnssecfwd::ForwardValidateLayer::new(
                base,
                validation_anchors,
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
            let redis = shared_cache
                .cloned()
                .ok_or("The shared cache client was not prepared for this chain")?;
            let addr = redis.addr();
            base = Arc::new(layers::CacheDbLayer::new(
                base,
                redis,
                layers::CacheDbScope {
                    secret: cachedb.secret.clone(),
                    context: shared_cache_context(plan, cachedb, &kind),
                    anchors,
                },
                cachedb.expire_secs,
                plan.min_ttl as u32,
                plan.max_ttl as u32,
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
                let epoch = cache_handle.epoch();
                let resp = backend.resolve(req)?;
                if resp.header.rcode == onetdns_proto::ResponseCode::NoError.0
                    && !resp.answers.is_empty()
                {
                    cache_handle.store(epoch, req, &resp);
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

    /** @brief 이 설정으로 만든 기본 체인의 공유 캐시 해석 맥락. */
    fn shared_context(cfg: &Config, kind: &ChainBase) -> String {
        let plan = ChainPlan::new(cfg);
        let cachedb = plan
            .cachedb
            .clone()
            .expect("the shared cache is configured");
        shared_cache_context(&plan, &cachedb, kind)
    }

    #[test]
    /**
     * @brief 공유 캐시 해석 맥락이 답을 바꾸는 설정마다 갈리고, 답과 무관한 설정에는 그대로인지.
     * @details 같은 Redis를 쓰는 서버끼리 맥락이 같으면 서로의 답을 그대로 쓴다.
     */
    fn external_cache_context_follows_the_resolution_context() {
        let mut base = forward_config();
        base.cachedb_redis_host = Some("127.0.0.1".to_string());
        base.upstreams = vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()];
        let context = |cfg: &Config| shared_context(cfg, &ChainBase::Planned(None));
        let original = context(&base);

        let changes: Vec<(&str, fn(&mut Config))> = vec![
            ("upstreams", |c| {
                c.upstreams = vec!["198.51.100.1".parse().unwrap()]
            }),
            ("upstream_urls", |c| {
                c.upstream_urls = vec!["https://dns.example/dns-query".into()]
            }),
            ("bootstrap", |c| {
                c.bootstrap = vec!["192.0.2.53".parse().unwrap()]
            }),
            ("fallback_upstreams", |c| {
                c.fallback_upstreams = vec!["192.0.2.54".into()]
            }),
            ("backend", |c| c.backend = BackendKind::Recurse),
            ("split_forward", |c| {
                c.backend = BackendKind::Split;
                c.split_forward = vec!["corp.test".into()];
            }),
            ("dnssec", |c| c.dnssec = !c.dnssec),
            ("dnssec_strict", |c| {
                c.dnssec = true;
                c.dnssec_strict = !c.dnssec_strict;
            }),
            ("domain_needed", |c| c.domain_needed = !c.domain_needed),
            ("bogus_priv", |c| c.bogus_priv = !c.bogus_priv),
            ("empty_zones", |c| c.empty_zones = !c.empty_zones),
            ("min_ttl", |c| c.min_ttl += 1),
            ("max_ttl", |c| c.max_ttl -= 1),
        ];
        for (key, change) in changes {
            let mut changed = base.clone();
            change(&mut changed);
            assert_ne!(context(&changed), original, "{key}");
        }

        let unchanged: Vec<(&str, fn(&mut Config))> = vec![
            ("upstream order", |c| c.upstreams.reverse()),
            ("query_timeout_secs", |c| c.query_timeout_secs += 3),
            ("cache_size", |c| c.cache_size += 1),
            ("cachedb_redis_expire_secs", |c| {
                c.cachedb_redis_expire_secs += 1
            }),
            ("cachedb_redis_port", |c| c.cachedb_redis_port += 1),
        ];
        for (key, change) in unchanged {
            let mut changed = base.clone();
            change(&mut changed);
            assert_eq!(context(&changed), original, "{key}");
        }
        let mut reordered = base.clone();
        reordered.upstreams.reverse();
        assert_eq!(
            ChainPlan::new(&base),
            ChainPlan::new(&reordered),
            "upstream order alone leaves the chain alone"
        );

        let mut recurse = base.clone();
        recurse.backend = BackendKind::Recurse;
        let recursion_changes: Vec<(&str, fn(&mut Config))> = vec![
            ("harden_below_nxdomain", |c| {
                c.harden_below_nxdomain = !c.harden_below_nxdomain
            }),
            ("aggressive_nsec", |c| {
                c.aggressive_nsec = !c.aggressive_nsec
            }),
            ("qname_minimisation_strict", |c| {
                c.qname_minimisation_strict = !c.qname_minimisation_strict
            }),
        ];
        for (key, change) in recursion_changes {
            let mut changed = recurse.clone();
            change(&mut changed);
            assert_ne!(context(&changed), context(&recurse), "{key}");
        }

        let mut split = base.clone();
        split.backend = BackendKind::Split;
        split.split_forward = vec!["corp.test".into()];
        let mut split_case = split.clone();
        split_case.split_forward = vec!["CORP.test.".into()];
        assert_eq!(context(&split), context(&split_case));

        let route = |upstreams: &str| ChainBase::Route {
            upstreams: upstreams.to_string(),
            anchors: None,
        };
        let route_a = shared_context(&base, &route("192.0.2.9"));
        assert_ne!(route_a, original, "client route");
        assert_ne!(
            route_a,
            shared_context(&base, &route("192.0.2.10")),
            "route upstreams"
        );
        let mut validating = recurse.clone();
        validating.dnssec = true;
        let mut stricter = validating.clone();
        stricter.dnssec_strict = !stricter.dnssec_strict;
        assert_ne!(
            shared_context(&validating, &route("192.0.2.9")),
            shared_context(&stricter, &route("192.0.2.9")),
            "the recursive backend validates client route answers too"
        );

        let mut local = base;
        local.cachedb_redis_host = None;
        assert!(ChainPlan::new(&local).cachedb.is_none());
        let local_changes: [fn(&mut Config); 2] = [
            |c| c.upstreams = vec!["198.51.100.1".parse().unwrap()],
            |c| c.bogus_priv = !c.bogus_priv,
        ];
        for change in local_changes {
            let mut changed = local.clone();
            change(&mut changed);
            assert_eq!(
                ChainPlan::new(&local),
                ChainPlan::new(&changed),
                "without Redis these settings leave the chain alone"
            );
        }
    }

    /** @brief 받은 질의의 CD 비트를 적어 두고 SERVFAIL 로 답하는 업스트림. */
    struct CdRecorder(Mutex<Vec<bool>>);

    impl native::Resolver for CdRecorder {
        fn resolve(&self, request: &onetdns_proto::Message) -> Option<onetdns_proto::Message> {
            self.0.lock_recover().push(request.header.checking_disabled);
            let mut response = request.clone();
            response.header.response = true;
            response.header.rcode = onetdns_proto::ResponseCode::ServFail.0;
            Some(response)
        }
    }

    #[test]
    /**
     * @brief 업스트림에 전달하는 체인에만 검증 계층이 얹히는지.
     * @details 검증 계층은 업스트림에 CD 비트를 켜서 묻는다. 클라이언트 경로는 재귀 방식에서도
     *          업스트림에 전달하므로, 이 계층이 빠지면 dnssec 을 켰는데도 검증하지 않은 답이
     *          클라이언트에 나간다. 재귀 기반은 스스로 검증하므로 겹쳐 얹지 않는다.
     */
    fn validation_wraps_every_forwarding_base() {
        let route = || ChainBase::Route {
            upstreams: "192.0.2.9".to_string(),
            anchors: None,
        };
        let cases = [
            (BackendKind::Forward, true, ChainBase::Planned(None), true),
            (BackendKind::Split, true, ChainBase::Planned(None), true),
            (BackendKind::Recurse, true, ChainBase::Planned(None), false),
            (BackendKind::Recurse, true, route(), true),
            (BackendKind::Forward, true, route(), true),
            (BackendKind::Recurse, false, route(), false),
        ];
        let chain = default_chain();
        for (backend, dnssec, kind, validates) in cases {
            let mut cfg = forward_config();
            cfg.backend = backend;
            cfg.dnssec = dnssec;
            let label = format!(
                "{backend:?} dnssec={dnssec} route={}",
                matches!(kind, ChainBase::Route { .. })
            );
            let upstream = Arc::new(CdRecorder(Mutex::default()));
            let (resolver, _) = chain
                .layers
                .wrap_common_layers(
                    &ChainPlan::new(&cfg),
                    upstream.clone(),
                    false,
                    false,
                    kind,
                    None,
                )
                .unwrap();
            let query = onetdns_proto::Message::query(
                7,
                onetdns_proto::Name::from_str("example.com.").unwrap(),
                onetdns_proto::RecordType::A,
            );
            resolver.resolve(&query);
            assert_eq!(
                upstream.0.lock_recover().first().copied(),
                Some(validates),
                "{label}"
            );
        }
    }

    #[test]
    /**
     * @brief 클라이언트 경로가 기본 체인의 공유 캐시 클라이언트와 그 연결 풀을 함께 쓰는지.
     * @details 체인마다 클라이언트를 따로 만들면 연결 풀도 따로 생겨, 같은 세대가 공유 캐시에
     *          여는 연결 수의 상한이 경로 수만큼 곱해진다. 두 체인이 차례로 물으면 뒤의 체인은
     *          앞의 체인이 돌려놓은 연결을 다시 쓴다.
     */
    fn routes_share_the_default_chain_shared_cache_client() {
        let fake = crate::redis::fake::FakeRedis::start(Default::default());
        let mut cfg = forward_config();
        cfg.cachedb_redis_host = Some("127.0.0.1".to_string());
        cfg.cachedb_redis_port = fake.addr.port();
        cfg.cachedb_redis_secret = "0123456789abcdef0123456789abcdef".into();
        let plan = ChainPlan::new(&cfg);
        let chain = default_chain();
        let installed = chain.install(chain.prepare(&plan).unwrap());
        let shared = installed
            .shared_cache
            .clone()
            .expect("the plan uses the shared cache");
        let (route, _) = chain
            .layers
            .wrap_common_layers(
                &plan,
                Arc::new(CdRecorder(Mutex::default())),
                false,
                false,
                ChainBase::Route {
                    upstreams: "192.0.2.9".to_string(),
                    anchors: None,
                },
                Some(&shared),
            )
            .unwrap();
        let query = |name: &str| {
            onetdns_proto::Message::query(
                7,
                onetdns_proto::Name::from_str(name).unwrap(),
                onetdns_proto::RecordType::A,
            )
        };
        installed.resolver.resolve(&query("default.example."));
        route.resolve(&query("route.example."));
        shared.wait_for_writes();
        assert_eq!(
            fake.commands.load(Ordering::Acquire),
            2,
            "one lookup per chain"
        );
        assert_eq!(fake.connections.load(Ordering::Acquire), 1);
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
