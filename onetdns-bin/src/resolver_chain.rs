//! Assembles the resolution chain from the config. A `ChainPlan` is built from the config first,
//! and the chain is assembled from the plan alone. On a config change the old and new plans are
//! compared, and only when they differ is a new chain built and swapped into the slot; sockets and
//! threads stay.
//!
//! The layer order and its reasons are in the layer-order document.

use super::*;
use crate::edge::EdgeServices;
use crate::native_config::{ipset_layer_active, recursion_offered_by};
use crate::recursion::{
    detect_dns53_interception, forward_trust_anchors, load_configured_trust_anchors, new_recursor,
    recursor_roots, spawn_rfc5011, spawn_ta_signaling,
};

/// Config values the chain assembly needs; assembly takes this instead of `Config`, so every
/// setting that affects the chain lives here, and equal plans build equal chains. A config swap
/// compares the old and new plans to decide whether to rebuild.
///
/// Values of unused components are left out: with no recursion, fallback upstreams, or stub zones,
/// the query timeout is absent, so changing only it touches neither the chain nor the cache, and
/// assembly cannot read it either.
///
/// Everything assembly reads comes from this struct. Reading the config directly would leave the
/// chain answering with the old value after that value changes.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ChainPlan {
    base: BasePlan,
    fallback: Option<ForwarderPlan>,
    /// Present whenever dnssec is on, regardless of backend, since client routes forward upstream
    /// even under recursion. `ChainBase` decides which chains get the validation layer.
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

/// Recursion settings are present only when recursion is used.
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
    recurse_opportunistic_encryption: bool,
    recurse_require_encryption: bool,
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

/// Forwarder for one fallback upstream or stub zone. Carries this server's listen addresses: an
/// upstream pointing at one would loop queries back here, so a listen address change must rebuild
/// the forwarder and recheck.
#[derive(Clone, Debug, PartialEq)]
struct ForwarderPlan {
    servers: Vec<String>,
    route: upstream::UpstreamRoute,
    listeners: Vec<SocketAddr>,
    query_timeout_secs: u64,
    upstream_strategy: UpstreamStrategy,
    upstream_concurrency: usize,
}

#[derive(Clone, Debug, PartialEq)]
struct ValidationPlan {
    dnssec_strict: bool,
    val_permissive_mode: bool,
    ignore_cd_flag: bool,
    domain_insecure: Vec<String>,
    root_key_sentinel: bool,
    dnssec_anchor_file: Option<std::path::PathBuf>,
}

/// Host names are resolved through `bootstrap` at assembly. The default forward upstreams and
/// local-only name settings are not used to assemble the chain, but they change answers below
/// `CacheDbLayer`, so they are carried here, into the resolution context, only when the shared
/// cache is on. Without it, changing only these does not rebuild the chain.
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
    /// Sorted and deduplicated, so reordering alone does not rebuild the chain.
    upstreams: Vec<String>,
    domain_needed: bool,
    bogus_priv: bool,
    empty_zones: bool,
}

impl CacheDbPlan {
    /// Resolves the host through `bootstrap` and reads the trust store when TLS is on.
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

#[derive(Clone, Debug, PartialEq)]
struct IpsetPlan {
    name_v4: Option<String>,
    name_v6: Option<String>,
    domains: Vec<String>,
}

/// Present only when at least one zone source exists.
#[derive(Clone, Debug, PartialEq)]
struct AuthorityPlan {
    /// Set RA on authoritative answers.
    recursion_offered: bool,
}

/// The advertised transports come from the encrypted listen addresses.
#[derive(Clone, Debug, PartialEq)]
struct DdrPlan {
    name: String,
    endpoints: Vec<layers::DdrEndpoint>,
}

impl ChainPlan {
    /// Reads no files or network.
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
        let forwarder = |servers: &[String], route: upstream::UpstreamRoute| ForwarderPlan {
            servers: servers.to_vec(),
            route,
            listeners: dns_listeners(cfg),
            query_timeout_secs: cfg.query_timeout_secs,
            upstream_strategy: cfg.upstream_strategy,
            upstream_concurrency: cfg.upstream_concurrency,
        };
        Self {
            base,
            fallback: (!cfg.fallback_upstreams.is_empty()).then(|| {
                forwarder(
                    &cfg.fallback_upstreams,
                    upstream::UpstreamRoute::forwarding(cfg),
                )
            }),
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
                .map(|zone| {
                    let direct = upstream::UpstreamRoute::Direct {
                        bootstrap: cfg.bootstrap.clone(),
                    };
                    (zone.suffix.clone(), forwarder(&zone.servers, direct))
                })
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

    /// Whether the default chain adds the Split local address layer.
    pub(crate) fn is_split(&self) -> bool {
        matches!(self.base, BasePlan::Split { .. })
    }

    /// Keys this plan reads whose config-key-table group does not rebuild the chain. A change to
    /// one swaps its own group, and also rebuilds the chain when the plan has a component reading
    /// it. Zone sources are always included, since whether any exist decides the authority layer.
    ///
    /// When `new` starts reading another group's key, add it here; otherwise the dashboard
    /// announces that key as hot, while with client routes it really restarts.
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
        if self.fallback.is_some() {
            keys.extend([
                "upstream_proxy",
                "upstream_proxy_username",
                "upstream_proxy_password",
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
                "ohttp_gateway",
            ]);
        }
        keys.sort_unstable();
        keys.dedup();
        keys
    }
}

/// What the common layers sit on. The shared cache uses it to pick this chain's resolution context
/// and trust anchors.
pub(crate) enum ChainBase {
    /// The base the plan's backend builds; holds the trust anchors when recursion validates.
    Planned(Option<Arc<ArcSwap<Vec<onetdns_dnssec::Ds>>>>),
    /// Client route forwarding only to these upstreams.
    Route {
        /// Normalized.
        upstreams: String,
        /// Trust anchors the same generation's recursive resolver validates with; None when it does
        /// not validate. Route answers are validated with them too, so RFC 5011 updates apply to
        /// the default chain and routes alike.
        anchors: Option<Arc<ArcSwap<Vec<onetdns_dnssec::Ds>>>>,
    },
}

impl ChainBase {
    fn recursor_anchors(&self) -> Option<&Arc<ArcSwap<Vec<onetdns_dnssec::Ds>>>> {
        match self {
            ChainBase::Planned(anchors) | ChainBase::Route { anchors, .. } => anchors.as_ref(),
        }
    }

    /// Whether this base passes upstream answers up as is; if so and dnssec is on, the validation
    /// layer goes on top. A recursive base validates itself while walking delegations, so it gets
    /// none. Client routes forward regardless of backend.
    fn forwards(&self, plan: &ChainPlan) -> bool {
        match self {
            ChainBase::Planned(_) => !matches!(plan.base, BasePlan::Recurse(_)),
            ChainBase::Route { .. } => true,
        }
    }
}

/// Resolution context separating this chain's answers in the shared cache: only settings below
/// `CacheDbLayer` that change answer content. The plan and its sub-plans are destructured field by
/// field, so a new field does not compile until it is decided here. Lists are sorted and
/// deduplicated, so order alone does not change the context. Trust anchors change at run time, so
/// `CacheDbLayer` adds the current ones per request instead. ECS options and the DO and CD bits are
/// already in the request key.
///
/// Servers sharing a Redis use each other's answers only when this matches; leaving out a value
/// that changes answers would let this server use answers stored by a server configured
/// differently.
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

/// Recursion settings that change answers or validation results. Values that only change which
/// servers are reachable, such as timeouts, cache size, and address families, are left out: they
/// only change how many queries fail, and failed answers are not shared.
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
        recurse_opportunistic_encryption: _,
        recurse_require_encryption: _,
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

/// Which upstreams it asks.
fn forwarder_context(plan: &ForwarderPlan) -> String {
    let ForwarderPlan {
        servers,
        route,
        listeners: _,
        query_timeout_secs: _,
        upstream_strategy: _,
        upstream_concurrency: _,
    } = plan;
    // Through the proxy no name is resolved here, so bootstrap plays no part.
    let bootstrap = match route {
        upstream::UpstreamRoute::Direct { bootstrap } => &bootstrap[..],
        upstream::UpstreamRoute::Socks5(_) => &[],
    };
    format!(
        "servers={:?};bootstrap={:?}",
        canonical_list(servers.iter()),
        canonical_list(bootstrap.iter())
    )
}

/// Trust anchors are added by `CacheDbLayer`.
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

/// Sorted and deduplicated.
fn canonical_list<T: ToString>(values: impl IntoIterator<Item = T>) -> Vec<String> {
    let mut values: Vec<String> = values.into_iter().map(|value| value.to_string()).collect();
    values.sort_unstable();
    values.dedup();
    values
}

/// Names differing only in case or a trailing dot become one.
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
            recurse_opportunistic_encryption: cfg.recurse_opportunistic_encryption,
            recurse_require_encryption: cfg.recurse_require_encryption,
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

    /// Per recursive query.
    pub(crate) fn timeout(&self) -> Duration {
        Duration::from_secs(self.query_timeout_secs)
    }

    /// Defaults to a file in the working directory.
    pub(crate) fn anchor_state_file(&self) -> std::path::PathBuf {
        self.dnssec_anchor_file
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("onetdns-anchors.txt"))
    }

    pub(crate) fn roots(&self) -> Vec<SocketAddr> {
        self.roots.clone()
    }

    /// Deny and allow lists for the authoritative servers asked.
    pub(crate) fn server_acl(&self) -> (Vec<onetdns_core::IpNet>, Vec<onetdns_core::IpNet>) {
        (
            self.recurse_deny_server.clone(),
            self.recurse_allow_server.clone(),
        )
    }

    pub(crate) fn max_ttl(&self) -> u32 {
        self.max_ttl as u32
    }
}

impl ForwarderPlan {
    /// `label` names the setting in the error. Fails when an upstream is one of this server's
    /// listen addresses.
    fn upstreams(&self, label: &str) -> Result<Vec<onetdns_forward::Upstream>, String> {
        let upstreams = upstream::servers_to_upstreams(&self.servers, &self.route);
        upstream::ensure_not_listener(&upstreams, &self.listeners, label)?;
        Ok(upstreams)
    }

    fn forwarder(&self, upstreams: Vec<onetdns_forward::Upstream>) -> onetdns_forward::Forwarder {
        onetdns_forward::Forwarder::with_upstreams(
            upstreams,
            Duration::from_secs(self.query_timeout_secs),
        )
        .with_strategy(forward_strategy(self.upstream_strategy))
        .with_parallel_limit(self.upstream_concurrency)
    }
}

/// Stop signal of side tasks started with a new recursive resolver. Dropped before the resolver is
/// adopted, it stops them; otherwise a thread updating an anchor handle nobody uses would live
/// until the generation ends.
pub(crate) struct PendingJobs(Option<Arc<std::sync::atomic::AtomicBool>>);

impl PendingJobs {
    /// Stops the previous tasks and registers these; with no signal, only stops the previous ones.
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

/// With recursion, also holds the resolver and its tasks.
pub(crate) struct PreparedBase {
    resolver: Arc<dyn native::Resolver>,
    /// For the reactor lane; None when only forwarding.
    recursor: Option<Arc<onetdns_recurse::Recursor>>,
    jobs: PendingJobs,
    /// None without DNSSEC validation.
    anchors: Option<Arc<ArcSwap<Vec<onetdns_dnssec::Ds>>>>,
}

/// This generation's handles for building the recursive base.
pub(crate) struct RecursiveBase {
    pub(crate) block_ttl: Arc<std::sync::atomic::AtomicU32>,
    /// Block engine applied to NS names.
    pub(crate) filter: Arc<SharedFilter>,
    pub(crate) local_ttl: Arc<std::sync::atomic::AtomicU32>,
    /// Threads to wait for at generation end. `ServiceCleanup` stops every thread on drop, and
    /// passing a clone would kill the service when the base is dropped, so only the tracking list
    /// is passed.
    pub(crate) thread_tracker: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    pub(crate) shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl RecursiveBase {
    /// Builds the recursive resolver per the plan and adds the recursion-only layers. Side tasks
    /// start with a fresh stop signal and are not registered; previous tasks stop only when this
    /// base is installed, so failing here, or discarding the result, leaves the running resolver's
    /// tasks alone.
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
            .with_opportunistic_encryption(if plan.recurse_require_encryption {
                Some(onetdns_forward::OpportunisticEncryption::default().required())
            } else {
                plan.recurse_opportunistic_encryption
                    .then(onetdns_forward::OpportunisticEncryption::default)
            })
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

/// Builds the base resolver for the plan's backend.
pub(crate) struct ResolverBase {
    pub(crate) forward_slot: native::ResolverSlot,
    pub(crate) recurse: RecursiveBase,
}

impl ResolverBase {
    /// Wraps the slot, so swapping the forward path carries over.
    fn forward(&self) -> Arc<dyn native::Resolver> {
        Arc::new(self.forward_slot.clone())
    }

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

/// Builds the default resolution chain and installs it in this generation. Building can fail but
/// changes no generation state; installing cannot fail. A config swap installs only after every
/// other preparation succeeded, so a failure at any step leaves the running chain, its cache, and
/// the recursive resolver's side tasks in place.
pub(crate) struct DefaultChain {
    pub(crate) base: ResolverBase,
    pub(crate) layers: ChainLayers,
    /// The default chain's response cache; read by the wire fast path.
    pub(crate) cache_slot: Arc<Mutex<Option<cache::CacheHandle>>>,
    pub(crate) recursor_jobs: Arc<EdgeServices>,
}

/// Built but not installed; dropping it stops its tasks too.
pub(crate) struct PreparedChain {
    resolver: Arc<dyn native::Resolver>,
    cache: cache::CacheHandle,
    /// For the reactor lane; None when only forwarding.
    recursor: Option<Arc<onetdns_recurse::Recursor>>,
    /// None without DNSSEC validation.
    anchors: Option<Arc<ArcSwap<Vec<onetdns_dnssec::Ds>>>>,
    /// None without a shared cache.
    shared_cache: Option<Arc<redis::RedisClient>>,
    jobs: PendingJobs,
}

pub(crate) struct InstalledChain {
    pub(crate) resolver: Arc<dyn native::Resolver>,
    pub(crate) cache: cache::CacheHandle,
    /// For the reactor lane; None when only forwarding.
    pub(crate) recursor: Option<Arc<onetdns_recurse::Recursor>>,
    /// Client route validation uses them too.
    pub(crate) anchors: Option<Arc<ArcSwap<Vec<onetdns_dnssec::Ds>>>>,
    /// Client routes share this client: a client per route would mean a connection pool per route,
    /// multiplying the shared cache connection cap by the number of routes.
    pub(crate) shared_cache: Option<Arc<redis::RedisClient>>,
}

impl DefaultChain {
    /// Changes no generation state.
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

    /// Brings up the cache and the recursive resolver and stops the previous side tasks; the caller
    /// swaps the chain slot.
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

/// This generation's handles for stacking the common layers.
#[derive(Clone)]
pub(crate) struct ChainLayers {
    pub(crate) block_ttl: Arc<std::sync::atomic::AtomicU32>,
    /// None while the DHCPv4 service is off.
    pub(crate) dhcp_slot: Arc<Mutex<Option<Arc<Mutex<dhcp::LeasePool>>>>>,
    pub(crate) local_ttl: Arc<std::sync::atomic::AtomicU32>,
    pub(crate) local_only_names: Arc<layers::LocalOnlyNames>,
    /// Logs cache hits; None logs nothing.
    pub(crate) recorder: Option<onetdns_control::Recorder>,
    pub(crate) shutdown: Arc<std::sync::atomic::AtomicBool>,
    /// The cache Split local address answers go into for the wire path.
    pub(crate) split_local_wire_cache: Arc<std::sync::OnceLock<cache::CacheHandle>>,
    pub(crate) zone_store: Arc<ArcSwap<onetdns_authority::ZoneStore>>,
}

impl ChainLayers {
    /// Changes no generation state. `report` logs the enabled features; `split_local_addresses`
    /// adds the Split local address layer; `kind` says what `base` is, which the shared cache uses
    /// for its context and anchors; `shared_cache` is the client the generation's chains share,
    /// required when the plan has a shared cache. Returns the chain and its response cache.
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

        // Added after the fallback upstreams are wrapped, so whichever upstream answered, only
        // answers this server validated go up, and the caches above hold only validated responses.
        // With a recursive resolver in the same generation, its anchors are shared, so RFC 5011
        // updates apply to forwarded answers at once.
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

    /// Uses a forward base; a recursive base would send probes to the roots.
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

    fn forward_config() -> Config {
        let mut cfg = Config::default();
        cfg.backend = BackendKind::Forward;
        cfg.listen = vec!["127.0.0.1:5399".parse().unwrap()];
        cfg
    }

    #[test]
    /// A config swap builds the chain first with the other preparations and installs only after all
    /// succeed. If building changed the cache slot or stopped the old tasks, a failed swap would
    /// leave the fast path reading an unused cache and anchor updates stopped.
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

    fn shared_context(cfg: &Config, kind: &ChainBase) -> String {
        let plan = ChainPlan::new(cfg);
        let cachedb = plan
            .cachedb
            .clone()
            .expect("the shared cache is configured");
        shared_cache_context(&plan, &cachedb, kind)
    }

    #[test]
    /// Servers sharing a Redis use each other's answers as is when their contexts match.
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
        let mut encrypted = recurse.clone();
        encrypted.recurse_opportunistic_encryption = true;
        assert_eq!(
            context(&encrypted),
            context(&recurse),
            "the transport to authorities leaves answers alone"
        );
        assert_ne!(ChainPlan::new(&encrypted), ChainPlan::new(&recurse));
        let mut required = recurse.clone();
        required.recurse_require_encryption = true;
        assert_eq!(context(&required), context(&recurse));
        assert_ne!(ChainPlan::new(&required), ChainPlan::new(&encrypted));

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

    /// Records the CD bit of each query and answers SERVFAIL.
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
    /// The validation layer asks upstream with CD set. Client routes forward upstream even under
    /// recursion, so without this layer unvalidated answers would reach clients with dnssec on. A
    /// recursive base validates itself, so it is not stacked twice.
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
    /// A client per chain would mean a pool per chain, multiplying the generation's connection cap
    /// by the number of routes. When two chains ask in turn, the second reuses the connection the
    /// first returned.
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
