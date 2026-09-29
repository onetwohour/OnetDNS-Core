/*!
 * @brief 설정에서 해석 체인을 조립한다.
 *
 * @details 체인은 기반 리졸버 위에 공통 계층을 쌓아 만든다. 조립하는 함수가 설정을 인자로
 *          받으므로, 설정이 바뀌면 같은 함수로 새 체인을 만들어 슬롯에 교체하고 소켓과
 *          스레드는 그대로 둔다. 계층을 쌓는 순서와 그 이유는 layer-order 문서가 정한다.
 */

use super::*;

/** @brief 재귀 기반을 만들 때 쓰는 이 세대의 핸들. */
pub(crate) struct RecursiveBase {
    /** @brief 재귀 리졸버에 딸린 보조 작업. 새로 만들 때 이전 작업을 멈춘다. */
    pub(crate) recursor_jobs: Arc<EdgeServices>,
    /** @brief 차단 응답 TTL. */
    pub(crate) block_ttl: Arc<std::sync::atomic::AtomicU32>,
    /** @brief NS 이름에 적용하는 차단 엔진. */
    pub(crate) filter: Arc<SharedFilter>,
    /** @brief reactor 레인이 쓰는 재귀 리졸버. 새로 만든 것으로 바꿔 넣는다. */
    pub(crate) lane_recursor: Arc<Mutex<Option<Arc<onetdns_recurse::Recursor>>>>,
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
    /** @brief 설정대로 재귀 리졸버를 만들고 재귀 전용 계층을 얹는다. */
    fn build(&self, cfg: &Config) -> BoxResult<Arc<dyn native::Resolver>> {
        let Self {
            recursor_jobs,
            block_ttl,
            filter,
            lane_recursor,
            local_ttl,
            thread_tracker,
            shutdown,
        } = self;
        let timeout = Duration::from_secs(cfg.query_timeout_secs);
        let prefer = if cfg.prefer_ip6 {
            Some(true)
        } else if cfg.prefer_ip4 {
            Some(false)
        } else {
            None
        };
        let insecure: Vec<onetdns_proto::Name> = cfg
            .domain_insecure
            .iter()
            .map(|name| {
                onetdns_proto::Name::from_str(name).map_err(|_| {
                    crate::anyhow!(format!(
                        "DNSSEC 검증 예외 DNS 이름이 올바르지 않습니다: {name}"
                    ))
                })
            })
            .collect::<BoxResult<_>>()?;
        let mut recursor = new_recursor(recursor_roots(cfg), timeout)
            .with_recursion_limit(cfg.recursion_limit)
            .with_cname_limit(cfg.cname_limit)
            .with_dname_limit(cfg.dname_limit)
            .with_server_acl(
                cfg.recurse_deny_server.clone(),
                cfg.recurse_allow_server.clone(),
            )
            .with_ip_family(cfg.do_ip4, cfg.do_ip6, prefer)
            .with_qname_min_strict(cfg.qname_minimisation_strict)
            .with_harden_referral_path(cfg.harden_referral_path)
            .with_domain_insecure(insecure)
            .with_root_key_sentinel(cfg.root_key_sentinel)
            .with_nsec3_max_iterations(cfg.val_nsec3_max_iterations)
            .with_ns_cache_max(cfg.ns_cache_size)
            .with_recursive_cache_ttl_max(cfg.max_ttl as u32)
            .with_ns_side_query_limit(cfg.ns_recursion_limit as usize)
            .with_caps_for_id(cfg.use_caps_for_id)
            .with_lowercase_outgoing(cfg.lowercase_outgoing);
        if cfg.dnssec {
            recursor = recursor
                .with_dnssec()
                .with_dnssec_strict(cfg.dnssec_strict)
                .with_dnssec_permissive(cfg.val_permissive_mode)
                .with_ignore_cd(cfg.ignore_cd_flag);

            if let Some(path) = cfg.dnssec_anchor_file.as_deref() {
                recursor = recursor.with_trust_anchors(load_configured_trust_anchors(path)?);
            }

            // 재귀 리졸버를 새로 만들 때마다 이전 보조 작업을 멈춘다. 멈추지 않으면 이전
            // 작업이 이전 앵커 핸들을 갱신하고 스레드도 계속 늘어난다.
            let jobs_stop = recursor_jobs.restart_all();
            if cfg.dnssec_rfc5011 {
                let thread =
                    spawn_rfc5011(cfg, recursor.anchors_handle(), timeout, jobs_stop.clone())
                        .with_context(|| "RFC 5011 신뢰 앵커 갱신 스레드를 시작하지 못했습니다")?;
                track_service_thread(thread_tracker, thread);
            }
            if cfg.trust_anchor_signaling {
                let thread = spawn_ta_signaling(
                    recursor.anchors_handle(),
                    timeout,
                    recursor_roots(cfg),
                    cfg.recurse_deny_server.clone(),
                    cfg.recurse_allow_server.clone(),
                    cfg.max_ttl as u32,
                    jobs_stop.clone(),
                )
                .with_context(|| "RFC 8145 신뢰 앵커 신호 스레드를 시작하지 못했습니다")?;
                track_service_thread(thread_tracker, thread);
            }
        }

        if let Some(thread) =
            detect_dns53_interception(recursor_roots(cfg), timeout, shutdown.clone())
        {
            track_service_thread(thread_tracker, thread);
        }

        let recursor = Arc::new(recursor);
        *lane_recursor.lock_recover() = Some(recursor.clone());
        let mut base: Arc<dyn native::Resolver> = Arc::new(native::NativeBackend::Recurse {
            recursor,
            ns_rpz: Some(filter.clone()),
            block_ttl: block_ttl.clone(),
            local_ttl: local_ttl.clone(),
        });
        if cfg.harden_below_nxdomain {
            base = Arc::new(layers::BelowNxdomainLayer::new(
                base,
                cfg.cache_size as usize,
                cfg.neg_min_ttl as u32,
                cfg.neg_max_ttl as u32,
            ));
        }
        if cfg.aggressive_nsec {
            base = Arc::new(layers::AggressiveNsecLayer::new(
                base,
                cfg.cache_size as usize,
                cfg.neg_min_ttl as u32,
                cfg.neg_max_ttl as u32,
            ));
        }
        Ok(base)
    }
}

/** @brief 설정의 처리 방식에 맞는 기반 리졸버를 만든다. */
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

    /** @brief 설정의 backend 에 맞는 기반을 만든다. */
    pub(crate) fn build(&self, cfg: &Config) -> BoxResult<Arc<dyn native::Resolver>> {
        Ok(match cfg.backend {
            BackendKind::Recurse => self.recurse.build(cfg)?,
            BackendKind::Forward => self.forward(),
            BackendKind::Split => {
                let default = match cfg.split_default {
                    SplitTarget::Forward => layers::Route::Forward,
                    SplitTarget::Recurse => layers::Route::Recurse,
                };
                Arc::new(
                    layers::SplitResolver::new(
                        self.forward(),
                        self.recurse.build(cfg)?,
                        default,
                        &cfg.split_recurse,
                        &cfg.split_forward,
                    )
                    .map_err(|error| crate::anyhow!(error))?,
                )
            }
        })
    }
}

/** @brief 공통 계층을 쌓을 때 쓰는 이 세대의 핸들. */
#[derive(Clone)]
pub(crate) struct ChainLayers {
    /** @brief 차단 응답 TTL. */
    pub(crate) block_ttl: Arc<std::sync::atomic::AtomicU32>,
    /** @brief 기본 체인의 응답 캐시를 넣어 두는 슬롯. wire 빠른 경로가 읽는다. */
    pub(crate) cache_slot: Arc<Mutex<Option<cache::CacheHandle>>>,
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
     * @brief 기반 위에 공통 계층을 쌓는다.
     * @param expose_cache_handle  만든 응답 캐시를 cache_slot 에 넣을지. 기본 체인만 넣는다.
     * @param report  켜진 기능을 기록에 남길지.
     * @param split_local_addresses  Split 로컬 주소 계층을 얹을지.
     * @param cache_ns  공유 캐시에서 이 체인이 쓰는 이름 공간.
     */
    pub(crate) fn wrap_common_layers(
        &self,
        cfg: &Config,
        mut base: Arc<dyn native::Resolver>,
        expose_cache_handle: bool,
        report: bool,
        split_local_addresses: bool,
        cache_ns: &str,
    ) -> Result<Arc<dyn native::Resolver>, String> {
        let Self {
            block_ttl,
            cache_slot,
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

        if !cfg.fallback_upstreams.is_empty() {
            let upstreams = upstream::servers_to_upstreams(&cfg.fallback_upstreams, &cfg.bootstrap);
            if !upstreams.is_empty() {
                ensure_upstreams_not_self(cfg, &upstreams, "fallback_upstreams")?;
                let fallback: Arc<dyn native::Resolver> = Arc::new(native::NativeBackend::Forward(
                    onetdns_forward::Forwarder::with_upstreams(
                        upstreams,
                        Duration::from_secs(cfg.query_timeout_secs),
                    )
                    .with_strategy(forward_strategy(cfg.upstream_strategy))
                    .with_parallel_limit(cfg.upstream_concurrency),
                ));
                base = Arc::new(layers::FallbackLayer::new(base, fallback));
            }
        }

        // 예비 업스트림까지 감싼 뒤에 얹는다. 어느 업스트림이 답했든 이 서버가 검증한 것만
        // 위로 올라가고, 위쪽 캐시에는 검증된 응답만 담긴다.
        if cfg.forward_validation_active() {
            let insecure_domains = cfg
                .domain_insecure
                .iter()
                .map(|name| {
                    onetdns_proto::Name::from_str(name).map_err(|_| {
                        format!("DNSSEC 검증 예외 DNS 이름이 올바르지 않습니다: {name}")
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            base = Arc::new(dnssecfwd::ForwardValidateLayer::new(
                base,
                Arc::new(onetdns_core::ArcSwap::new(Arc::new(
                    forward_trust_anchors(cfg).map_err(|error| error.to_string())?,
                ))),
                dnssecfwd::ForwardValidationPolicy {
                    strict: cfg.dnssec_strict,
                    permissive: cfg.val_permissive_mode,
                    ignore_cd: cfg.ignore_cd_flag,
                    insecure_domains,
                    root_key_sentinel: cfg.root_key_sentinel,
                },
            ));
        }

        if let Some(addr) = cachedb_redis_addr(cfg)? {
            let redis = Arc::new(redis::RedisClient::new(addr));
            let namespace = format!("{:x}", Sha256::digest(cache_ns.as_bytes()))[..16].to_string();
            base = Arc::new(layers::CacheDbLayer::new(
                base,
                redis,
                cfg.cachedb_redis_expire_secs,
                cfg.min_ttl as u32,
                cfg.max_ttl as u32,
                namespace,
            ));
            if report {
                onetdns_core::info!(event = "cache.redis_enabled", %addr, "외부 Redis 응답 캐시를 사용합니다");
            }
        }

        let mut chain = base;
        match cfg.ecs_mode {
            EcsMode::Send => {
                if let Some(ip) = cfg.ecs_custom_ip {
                    chain = Arc::new(layers::EcsLayer::new(chain, ip));
                }
            }
            EcsMode::Strip => chain = Arc::new(layers::EcsLayer::strip(chain)),
            EcsMode::Off => {}
        }

        let prefetch_backend = cfg.prefetch.then(|| chain.clone());
        let mut prefetch_cache: Option<cache::CacheHandle> = None;
        {
            let positive_cache_enabled = cfg.cache_enabled && cfg.cache_size > 0;
            let shards = if positive_cache_enabled && cfg.sharded_cache {
                cfg.cache_shards
            } else {
                1
            };
            let cl = cache::CacheLayer::new(
                chain,
                cfg.cache_size.max(1) as usize,
                shards,
                cfg.min_ttl as u32,
                cfg.max_ttl as u32,
                cfg.neg_min_ttl as u32,
                cfg.neg_max_ttl as u32,
            )
            .with_positive_cache(positive_cache_enabled)
            .with_recorder(recorder.clone());
            if expose_cache_handle {
                *cache_slot.lock_recover() = Some(cl.handle());
            }
            if cfg.prefetch {
                prefetch_cache = Some(cl.handle());
            }
            chain = Arc::new(cl);
        }

        if cfg.serve_stale_secs > 0 {
            chain = Arc::new(
                layers::ServeStaleLayer::new(
                    chain,
                    Duration::from_secs(cfg.serve_stale_secs),
                    cfg.cache_size as usize,
                    cfg.min_ttl as u32,
                    cfg.max_ttl as u32,
                    cfg.serve_expired_reply_ttl,
                    cfg.serve_expired_ttl_reset,
                    (cfg.serve_expired_client_timeout_ms > 0)
                        .then(|| Duration::from_millis(cfg.serve_expired_client_timeout_ms)),
                    cfg.serve_stale_refresh,
                )
                .with_shutdown(shutdown.clone()),
            );
        }

        if cfg.prefetch {
            let backend =
                prefetch_backend.expect("미리 가져오기가 켜져 있으면 핸들러가 준비되어야 합니다");
            let cache_handle = prefetch_cache.expect("prefetch_cache는 cfg.prefetch일 때 설정됨");

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
                Duration::from_secs(cfg.prefetch_interval_secs.max(1)),
                cfg.cache_size as usize,
                cfg.prefetch_min_hits,
                cfg.prefetch_ttl_pct,
                shutdown.clone(),
            ));
        }

        if split_local_addresses && (!cfg.local_a.is_empty() || !cfg.local_aaaa.is_empty()) {
            let addresses =
                layers::LocalAddressTable::new(&cfg.local_a, &cfg.local_aaaa, local_ttl.clone())?;
            chain = Arc::new(layers::LocalAddressLayer::new(
                chain,
                Arc::new(addresses),
                Some(split_local_wire_cache.clone()),
            ));
        }

        if cfg.name_ratelimit_per_sec > 0 {
            chain = Arc::new(layers::NameRateLimitLayer::new(
                chain,
                cfg.name_ratelimit_per_sec,
                cfg.name_ratelimit_labels,
            ));
        }

        if !cfg.stub_zones.is_empty() {
            let mut stubs: Vec<(String, Arc<dyn native::Resolver>)> = Vec::new();
            for z in &cfg.stub_zones {
                let ups = upstream::servers_to_upstreams(&z.servers, &cfg.bootstrap);
                if ups.is_empty() {
                    return Err(format!(
                        "스텁 영역 '{}'에 사용할 수 있는 업스트림 DNS 서버가 없습니다",
                        z.suffix
                    ));
                }
                ensure_upstreams_not_self(cfg, &ups, &format!("스텁 영역 '{}'", z.suffix))?;
                let fwd = onetdns_forward::Forwarder::with_upstreams(
                    ups,
                    Duration::from_secs(cfg.query_timeout_secs),
                )
                .with_strategy(forward_strategy(cfg.upstream_strategy))
                .with_parallel_limit(cfg.upstream_concurrency);
                let guarded: Arc<dyn native::Resolver> =
                    Arc::new(cache::CacheLayer::failure_guard(
                        Arc::new(native::NativeBackend::Forward(fwd)),
                        64,
                    ));
                stubs.push((z.suffix.clone(), guarded));
            }
            if !stubs.is_empty() {
                chain = Arc::new(layers::StubLayer::new(chain, stubs)?);
            }
        }

        if let Some(pool) = dhcp_slot.lock_recover().as_ref() {
            if !cfg.dhcp_local_domain.is_empty() {
                chain = Arc::new(layers::DhcpDnsLayer::new(
                    chain,
                    pool.clone(),
                    &cfg.dhcp_local_domain,
                    local_ttl.clone(),
                ));
            }
        }

        if ipset_layer_active(cfg) {
            chain = Arc::new(layers::IpsetLayer::new(
                chain,
                cfg.ipset_name_v4.clone(),
                cfg.ipset_name_v6.clone(),
                &cfg.ipset_domains,
            )?);
        }

        if authority_sources_configured(cfg) {
            chain = Arc::new(
                layers::AuthorityLayer::new(chain, zone_store.clone())
                    .with_recursion_offered(recursion_offered_by(cfg)),
            );
        }

        if cfg.acme_directory_url.is_some() {
            chain = Arc::new(layers::AcmeChallengeLayer::new(chain));
        }

        if !cfg.ddr_name.is_empty() {
            if let Some(ddr) =
                layers::DdrLayer::new(chain.clone(), &cfg.ddr_name, &ddr_endpoints_from(cfg))?
            {
                if report {
                    onetdns_core::info!(
                        event = "ddr.enabled",
                        name = %cfg.ddr_name,
                        endpoints = ddr_endpoints_from(cfg).len(),
                        "암호화 전송 승격 안내(DDR)를 켭니다"
                    );
                }
                chain = Arc::new(ddr);
            }
        }

        if !cfg.dynamic_records.is_empty() {
            let dl = layers::DynamicRecordLayer::new(chain.clone(), &cfg.dynamic_records)?;
            if !dl.is_empty() {
                if report {
                    onetdns_core::info!(
                        event = "dynamic_records.enabled",
                        count = cfg.dynamic_records.len(),
                        "동적 DNS 레코드 처리를 사용합니다"
                    );
                }
                chain = Arc::new(dl);
            }
        }

        Ok(chain)
        // layer-order:end
    }
}
