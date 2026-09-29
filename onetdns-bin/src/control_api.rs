/*!
 * @brief 관리 API 콜백을 실행 중 서버의 상태에 연결한다.
 *
 * @details 콜백은 서버 세대 하나가 소유한 핸들을 복제해 붙든다. 어떤 핸들을 붙드는지는
 *          ControlDeps 가 모두 드러낸다. 여기 없는 세대 상태는 관리 API 가 건드리지 않는다.
 */

use super::*;
use std::sync::atomic::Ordering;

/** @brief 관리 API 가 읽고 바꾸는 이 세대의 핸들. */
pub(crate) struct ControlDeps {
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
    /** @brief 차단 엔진을 다시 만든다. */
    pub(crate) rebuild: FilterRebuild,
    /** @brief 구독 목록을 다시 받는다. */
    pub(crate) refresh_url_lists:
        Arc<dyn Fn() -> Result<(usize, usize), String> + Send + Sync + 'static>,
    /** @brief 지금 쓰는 차단 엔진. */
    pub(crate) filter: Arc<SharedFilter>,
    /** @brief 관리 API 로 더한 차단과 허용 규칙. */
    pub(crate) overlay: Arc<Mutex<(Vec<String>, Vec<String>)>>,
    /** @brief 차단한 서비스 목록. */
    pub(crate) service_set: Arc<Mutex<Vec<String>>>,
    /** @brief 거부할 도메인 목록. */
    pub(crate) refused_domains_state: Arc<Mutex<Vec<String>>>,
    /** @brief 안전 검색을 켰는지. */
    pub(crate) safe_search_flag: Arc<std::sync::atomic::AtomicBool>,
    /** @brief 정책 엔진. */
    pub(crate) policy_engine: Arc<native::GatedSwap<onetdns_policy::PolicyEngine>>,
    /** @brief 목록을 받을 때 쓰는 이름 해석기. */
    pub(crate) blocklist_resolver: http::HostResolver,
    /** @brief 구독 주소. */
    pub(crate) sub_urls: Arc<Mutex<Vec<String>>>,
    /** @brief 구독별로 받은 결과. */
    pub(crate) sub_meta: Arc<Mutex<Vec<SubMeta>>>,
    /** @brief 꺼 둔 구독 주소. */
    pub(crate) sub_disabled: Arc<Mutex<Vec<String>>>,
    /** @brief 구독 제목. */
    pub(crate) sub_titles: Arc<Mutex<Vec<String>>>,
    /** @brief 미리 정해 둔 목록 주소. */
    pub(crate) preset_urls: Arc<Mutex<Vec<String>>>,
    /** @brief 목록 받기를 한 번에 하나만 하게 하는 잠금. */
    pub(crate) list_refresh_lock: Arc<Mutex<()>>,
    /** @brief 권한 영역 저장소. */
    pub(crate) zone_store: Arc<ArcSwap<onetdns_authority::ZoneStore>>,
    /** @brief 영역 서명 키. */
    pub(crate) zone_signers: SharedZoneSigners,
    /** @brief 영역별 IXFR 기록. */
    pub(crate) ixfr_journal: Arc<Mutex<std::collections::HashMap<Vec<u8>, native::ZoneJournal>>>,
    /** @brief 영역이 바뀌었을 때 NOTIFY 를 보낸다. */
    pub(crate) notify_sender: NotifySender,
    /** @brief DHCPv4 임대 풀. 서비스가 꺼져 있으면 없다. */
    pub(crate) dhcp_slot: Arc<Mutex<Option<Arc<Mutex<dhcp::LeasePool>>>>>,
    /** @brief DHCPv6 임대 풀. 서비스가 꺼져 있으면 없다. */
    pub(crate) dhcp6_slot: Arc<Mutex<Option<Arc<Mutex<dhcp6::Lease6Pool>>>>>,
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

/** @brief 관리 API 콜백을 만든다. */
pub(crate) fn build(deps: ControlDeps) -> onetdns_control::Controls {
    let ControlDeps {
        runtime_cfg,
        config_path,
        cfg_text,
        reload,
        config_prev,
        applied_config_text,
        hot_config_apply,
        rebuild,
        refresh_url_lists,
        filter,
        overlay,
        service_set,
        refused_domains_state,
        safe_search_flag,
        policy_engine,
        blocklist_resolver,
        sub_urls,
        sub_meta,
        sub_disabled,
        sub_titles,
        preset_urls,
        list_refresh_lock,
        zone_store,
        zone_signers,
        ixfr_journal,
        notify_sender,
        dhcp_slot,
        dhcp6_slot,
        vendor_db,
        cache_slot,
        forward_stats,
        listener_reg,
        tls_slot_handle,
        jobs,
        service_threads,
    } = deps;
    let osnet_backup_dir: PathBuf = config_path
        .as_ref()
        .and_then(|p| p.parent())
        .map(|d| d.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    onetdns_control::Controls {
        reload: {
            let r = rebuild.clone();
            Box::new(move || r().map(counts))
        },
        block_add: {
            let r = rebuild.clone();
            let ov = overlay.clone();
            let cp = config_path.clone();
            let runtime = runtime_cfg.clone();
            Box::new(move |d: &str| {
                let result = mutate_user_rule(&ov, cp.as_deref(), &*r, d, false, true)?;
                let rules = ov.lock_recover().clone();
                update_runtime_config(&runtime, |config| {
                    config.block_rules = rules.0;
                    config.allow_rules = rules.1;
                });
                Ok(counts(result))
            })
        },
        allow_add: {
            let r = rebuild.clone();
            let ov = overlay.clone();
            let cp = config_path.clone();
            let runtime = runtime_cfg.clone();
            Box::new(move |d: &str| {
                let result = mutate_user_rule(&ov, cp.as_deref(), &*r, d, true, true)?;
                let rules = ov.lock_recover().clone();
                update_runtime_config(&runtime, |config| {
                    config.block_rules = rules.0;
                    config.allow_rules = rules.1;
                });
                Ok(counts(result))
            })
        },
        service_set: {
            let r = rebuild.clone();
            let ss = service_set.clone();
            let cp = config_path.clone();
            let runtime = runtime_cfg.clone();
            Box::new(move |svc: &str, enable: bool| {
                if enable && onetdns_filter::services::service_rules(svc).is_none() {
                    return Err(format!("알 수 없는 차단 서비스: {svc}"));
                }
                let previous = ss.lock_recover().clone();
                let mut next = previous.clone();
                if enable {
                    if !next.iter().any(|item| item == svc) {
                        next.push(svc.to_string());
                    }
                } else {
                    next.retain(|item| item != svc);
                }
                if let Some(path) = cp.as_deref() {
                    persist_config_string_array(path, "blocked_services", &next)
                        .map_err(|e| e.to_string())?;
                }
                *ss.lock_recover() = next;
                match r() {
                    Ok(value) => {
                        let applied = ss.lock_recover().clone();
                        update_runtime_config(&runtime, |config| {
                            config.blocked_services = applied;
                        });
                        Ok(counts(value))
                    }
                    Err(error) => {
                        *ss.lock_recover() = previous.clone();
                        let error = if let Some(path) = cp.as_deref() {
                            with_rollback_result(
                                error,
                                "차단 서비스 설정을 이전 값으로 되돌리지 못했습니다",
                                persist_config_string_array(path, "blocked_services", &previous)
                                    .map_err(|rollback_error| rollback_error.to_string()),
                            )
                        } else {
                            error
                        };
                        Err(error)
                    }
                }
            })
        },
        safesearch_set: {
            let flag = safe_search_flag.clone();
            let cp = config_path.clone();
            let runtime = runtime_cfg.clone();
            Box::new(move |enable: bool| {
                if let Some(path) = cp.as_deref() {
                    let _write_guard = config_write_lock().lock_recover();
                    let text = onetdns_core::SecretString::from(
                        Config::read_text(path).map_err(|e| e.to_string())?,
                    );
                    let updated = onetdns_core::SecretString::from(rewrite_config_kv(
                        &text,
                        "safe_search",
                        &enable.to_string(),
                    )?);
                    atomic_write(path, updated.as_bytes()).map_err(|e| e.to_string())?;
                }
                flag.store(enable, std::sync::atomic::Ordering::Relaxed);
                update_runtime_config(&runtime, |config| config.safe_search = enable);
                Ok(())
            })
        },

        export: {
            let ov = overlay.clone();
            let ss = service_set.clone();
            let refused = refused_domains_state.clone();
            let flag = safe_search_flag.clone();
            Box::new(move || {
                let (b, a) = {
                    let o = ov.lock_recover();
                    (o.0.clone(), o.1.clone())
                };
                let svcs = ss.lock_recover().clone();
                let refused = refused.lock_recover().clone();
                let arr = |v: &[String]| {
                    v.iter()
                        .map(|s| onetdns_core::json::escape(s))
                        .collect::<Vec<_>>()
                        .join(",")
                };
                format!(
                    "{{\"version\":1,\"block\":[{}],\"allow\":[{}],\"services\":[{}],\"refused_domains\":[{}],\"safe_search\":{}}}",
                    arr(&b),
                    arr(&a),
                    arr(&svcs),
                    arr(&refused),
                    flag.load(std::sync::atomic::Ordering::Relaxed)
                )
            })
        },

        import: {
            let r = rebuild.clone();
            let ov = overlay.clone();
            let ss = service_set.clone();
            let refused_state = refused_domains_state.clone();
            let flag = safe_search_flag.clone();
            let cp = config_path.clone();
            let runtime = runtime_cfg.clone();
            Box::new(move |body: &str| {
                let (block, allow, services, refused, safe_search) = parse_control_backup(body)?;
                let previous_overlay = ov.lock_recover().clone();
                let previous_services = ss.lock_recover().clone();
                let previous_refused = refused_state.lock_recover().clone();
                let previous_safe_search = flag.load(std::sync::atomic::Ordering::Relaxed);
                let _write_guard = config_write_lock().lock_recover();
                let previous_text = if let Some(path) = cp.as_deref() {
                    Some(onetdns_core::SecretString::from(
                        Config::read_text(path).map_err(|e| e.to_string())?,
                    ))
                } else {
                    None
                };
                if let (Some(path), Some(text)) = (cp.as_deref(), previous_text.as_deref()) {
                    let text = onetdns_core::SecretString::from(rewrite_config_string_array(
                        text,
                        "block_rules",
                        &block,
                    )?);
                    let text = onetdns_core::SecretString::from(rewrite_config_string_array(
                        &text,
                        "allow_rules",
                        &allow,
                    )?);
                    let text = onetdns_core::SecretString::from(rewrite_config_string_array(
                        &text,
                        "blocked_services",
                        &services,
                    )?);
                    let text = onetdns_core::SecretString::from(rewrite_config_string_array(
                        &text,
                        "refused_domains",
                        &refused,
                    )?);
                    let text = onetdns_core::SecretString::from(rewrite_config_kv(
                        &text,
                        "safe_search",
                        &safe_search.to_string(),
                    )?);
                    atomic_write(path, text.as_bytes()).map_err(|e| e.to_string())?;
                }
                *ov.lock_recover() = (block, allow);
                *ss.lock_recover() = services;
                *refused_state.lock_recover() = refused;
                flag.store(safe_search, std::sync::atomic::Ordering::Relaxed);
                match r() {
                    Ok(value) => {
                        let rules = ov.lock_recover().clone();
                        let services = ss.lock_recover().clone();
                        let refused = refused_state.lock_recover().clone();
                        let safe_search = flag.load(std::sync::atomic::Ordering::Relaxed);
                        update_runtime_config(&runtime, |config| {
                            config.block_rules = rules.0;
                            config.allow_rules = rules.1;
                            config.blocked_services = services;
                            config.refused_domains = refused;
                            config.safe_search = safe_search;
                        });
                        Ok(counts(value))
                    }
                    Err(error) => {
                        *ov.lock_recover() = previous_overlay;
                        *ss.lock_recover() = previous_services;
                        *refused_state.lock_recover() = previous_refused;
                        flag.store(previous_safe_search, std::sync::atomic::Ordering::Relaxed);
                        let error = if let (Some(path), Some(text)) =
                            (cp.as_deref(), previous_text.as_deref())
                        {
                            with_rollback_result(
                                error,
                                "필터 다운로드 설정을 이전 값으로 되돌리지 못했습니다",
                                atomic_write(path, text.as_bytes())
                                    .map_err(|rollback_error| rollback_error.to_string()),
                            )
                        } else {
                            error
                        };
                        Err(error)
                    }
                }
            })
        },

        config_validate: {
            let path = config_path.clone();
            let startup = cfg_text.clone().unwrap_or_default();
            Box::new(move |toml| {
                let current = match path.as_deref() {
                    Some(p) => {
                        onetdns_core::SecretString::from(Config::read_text(p).map_err(|e| {
                            format!("현재 설정 파일을 읽지 못했습니다({}): {e}", p.display())
                        })?)
                    }
                    None => startup.clone(),
                };
                let merged = merge_config_snippet(&current, toml)?;
                let cfg =
                    onetdns_config::Config::from_toml_str(&merged).map_err(|e| e.to_string())?;
                runtime_preflight(&cfg)
            })
        },

        config_diff: {
            let path = config_path.clone();
            let startup = cfg_text.clone().unwrap_or_default();
            let runtime_cfg = runtime_cfg.clone();
            Box::new(move |proposed: &str| {
                let current = match path.as_deref() {
                    Some(p) => {
                        onetdns_core::SecretString::from(Config::read_text(p).map_err(|e| {
                            format!("현재 설정 파일을 읽지 못했습니다({}): {e}", p.display())
                        })?)
                    }
                    None => startup.clone(),
                };
                let proposed = merge_config_snippet(&current, proposed)?;
                let (added, removed, changed) =
                    onetdns_config::Config::diff_toml(&current, &proposed)
                        .map_err(|e| e.to_string())?;
                let proposed_cfg = onetdns_config::Config::from_toml_str(&proposed)
                    .map_err(|e| format!("변경할 설정을 해석하지 못했습니다: {e}"))?;

                let active_cfg = runtime_cfg.load();
                let effective = config_changed_keys(&active_cfg, &proposed_cfg)?;
                let hot: Vec<String> = effective
                    .iter()
                    .filter(|key| {
                        is_hot_reload_config_change(&active_cfg, &proposed_cfg, key.as_str())
                    })
                    .cloned()
                    .collect();
                let restart: Vec<String> = effective
                    .iter()
                    .filter(|key| {
                        !is_hot_reload_config_change(&active_cfg, &proposed_cfg, key.as_str())
                    })
                    .cloned()
                    .collect();
                let arr = |v: &[String]| {
                    v.iter()
                        .map(|k| onetdns_core::json::escape(k))
                        .collect::<Vec<_>>()
                        .join(",")
                };
                Ok(format!(
                    "{{\"added\":[{}],\"removed\":[{}],\"changed\":[{}],\"effective_changed\":[{}],\"hot_reload\":[{}],\"service_restart\":[{}],\"restart_required\":{}}}",
                    arr(&added),
                    arr(&removed),
                    arr(&changed),
                    arr(&effective),
                    arr(&hot),
                    arr(&restart),
                    !restart.is_empty()
                ))
            })
        },

        config_apply: {
            let path = config_path.clone();
            let prev = config_prev.clone();
            let reload = reload.clone();
            let hot_apply = hot_config_apply.clone();
            let applied = applied_config_text.clone();
            Box::new(move |toml: &str| {
                let result =
                    apply_config_edit_smart(&path, &prev, &applied, &reload, &hot_apply, |text| {
                        merge_config_snippet(text, toml)
                    })?;
                onetdns_core::info!(
                    event = "config.patch_applied",
                    mode = result.mode.as_str(),
                    changed = result.changed.len(),
                    keys = ?result.changed,
                    "설정 변경분을 적용했습니다"
                );
                Ok(format!("{{\"applied\":true,{}}}", result.json_fields()))
            })
        },

        config_set: {
            let path = config_path.clone();
            let prev = config_prev.clone();
            let reload = reload.clone();
            let hot_apply = hot_config_apply.clone();
            let applied = applied_config_text.clone();
            Box::new(move |body: &str| {
                let j = onetdns_core::json::parse(body)
                    .map_err(|_| "JSON 요청 본문을 해석할 수 없습니다".to_string())?;
                let mut pairs = match &j {
                    onetdns_core::json::Json::Obj(p) => p.clone(),
                    _ => {
                        return Err(
                            "요청 본문에는 키와 값으로 이루어진 최상위 객체가 필요합니다"
                                .to_string(),
                        )
                    }
                };
                materialize_mode_acl_patch(&mut pairs)?;
                validate_config_patch_values(&pairs)?;
                if pairs.is_empty() {
                    return Err("변경할 설정 항목이 없습니다".to_string());
                }
                let result =
                    apply_config_edit_smart(&path, &prev, &applied, &reload, &hot_apply, |text| {
                        let mut out = text.to_string();
                        for (k, v) in &pairs {
                            // null은 "이 항목을 지운다"는 뜻이다. 값을 비우는 것과 달리
                            // 기본값으로 돌아가고 선택 항목은 꺼진다.
                            if matches!(v, onetdns_core::json::Json::Null) {
                                out = remove_config_key(&out, k)?;
                                continue;
                            }
                            let lit = json_to_toml_literal(v)?;
                            out = rewrite_config_kv(&out, k, &lit)?;
                        }
                        Ok(out)
                    })?;
                let keys: Vec<String> = pairs
                    .iter()
                    .map(|(k, _)| onetdns_core::json::escape(k))
                    .collect();
                let changed_keys: Vec<&str> = pairs.iter().map(|(key, _)| key.as_str()).collect();
                onetdns_core::info!(
                    event = "config.keys_applied",
                    count = pairs.len(),
                    mode = result.mode.as_str(),
                    keys = ?changed_keys,
                    "설정 항목을 적용했습니다"
                );
                Ok(format!(
                    "{{\"applied\":true,{},\"keys\":[{}]}}",
                    result.json_fields(),
                    keys.join(",")
                ))
            })
        },

        config_schema: {
            let runtime_cfg = runtime_cfg.clone();
            Box::new(move || {
                let keys = onetdns_config::known_keys();
                let list: Vec<String> =
                    keys.iter().map(|k| onetdns_core::json::escape(k)).collect();
                // 교체 판정과 같은 곳에서 낸다. 목록을 따로 들면 화면이 실제로는
                // 무중단인 항목에 "다시 시작"이라고 적는다. 조건부 항목은 지금 설정에서
                // 실제로 재시작하는 것만 조건부로 남긴다.
                let now = runtime_cfg.load();
                let routes = has_client_upstream_routes(&now);
                let conditional_keys: Vec<&str> = CONDITIONAL_HOT_RELOAD_CONFIG_KEYS
                    .iter()
                    .copied()
                    .chain([
                        "query_timeout_secs",
                        "upstream_strategy",
                        "upstream_concurrency",
                    ])
                    .filter(|key| match *key {
                        "query_timeout_secs" => routes || now.backend != BackendKind::Forward,
                        "upstream_strategy" | "upstream_concurrency" => routes,
                        _ => true,
                    })
                    .collect();
                let hot: Vec<String> = keys
                    .iter()
                    .map(|key| -> &str { key })
                    .filter(|key| config_keys::is_hot(key) && !conditional_keys.contains(key))
                    .map(onetdns_core::json::escape)
                    .collect();
                let conditional: Vec<String> = conditional_keys
                    .iter()
                    .map(|key| onetdns_core::json::escape(key))
                    .collect();
                format!(
                "{{\"count\":{},\"keys\":[{}],\"hot_reload_keys\":[{}],\"conditional_hot_reload_keys\":[{}],\"fields\":{},\"note\":\"업스트림 DNS 서버 주소는 실행 중에 바꿀 수 있습니다. 응답 제한 시간, 선택 방식, 동시 요청 수는 클라이언트별 전용 업스트림 DNS 서버가 없고 해당 핸들러를 다시 만들 필요가 없을 때만 즉시 적용됩니다.\"}}",
                keys.len(),
                list.join(","),
                hot.join(","),
                conditional.join(","),
                onetdns_config::schema::schema_json()
            )
            })
        },

        upstream_test: {
            let runtime = runtime_cfg.clone();
            Box::new(move |body: &str| {
                let bootstrap = runtime.load().bootstrap.clone();
                let j = onetdns_core::json::parse(body)
                    .map_err(|_| "JSON 요청 본문을 해석할 수 없습니다".to_string())?;
                let addr_s = j
                    .get("addr")
                    .and_then(|v| v.as_str())
                    .ok_or("`addr` 항목을 입력해야 합니다".to_string())?
                    .trim()
                    .to_string();
                let mut candidates = if addr_s.contains("://") {
                    upstream::native_upstreams(&[], &[addr_s.clone()], &bootstrap)
                } else {
                    let ip: std::net::IpAddr = addr_s
                        .parse()
                        .map_err(|_| format!("IP 주소 형식이 올바르지 않습니다: {addr_s}"))?;
                    vec![onetdns_forward::Upstream::udp(std::net::SocketAddr::new(
                        ip, 53,
                    ))]
                };
                let Some(up) = candidates.pop() else {
                    return Err(format!(
                        "업스트림 DNS 서버 주소 형식이 올바르지 않습니다: {addr_s}"
                    ));
                };
                let fwd =
                    onetdns_forward::Forwarder::with_upstreams(vec![up], Duration::from_secs(3));
                let probe = onetdns_proto::Message::query(
                    0x4f54,
                    onetdns_proto::Name::from_str("example.com")
                        .map_err(|_| "내장 점검용 도메인 이름을 해석하지 못했습니다".to_string())?,
                    onetdns_proto::RecordType::A,
                );
                let start = std::time::Instant::now();
                match fwd.resolve(&probe) {
                    Ok(ans) if !matches!(ans.header.rcode, 0 | 3) => Ok(format!(
                        "{{\"ok\":false,\"error\":{},\"rcode\":{},\"addr\":{}}}",
                        onetdns_core::json::escape(&format!(
                            "업스트림 DNS 서버가 {} 로 답했습니다",
                            native::rcode_str(onetdns_proto::ResponseCode(ans.header.rcode))
                        )),
                        ans.header.rcode,
                        onetdns_core::json::escape(&addr_s)
                    )),
                    Ok(ans) => Ok(format!(
                        "{{\"ok\":true,\"latency_ms\":{},\"rcode\":{},\"answers\":{},\"addr\":{}}}",
                        start.elapsed().as_millis(),
                        ans.header.rcode,
                        ans.answers.len(),
                        onetdns_core::json::escape(&addr_s)
                    )),
                    Err(error) => Ok(format!(
                        "{{\"ok\":false,\"error\":{},\"addr\":{}}}",
                        onetdns_core::json::escape(&error.to_string()),
                        onetdns_core::json::escape(&addr_s)
                    )),
                }
            })
        },

        cache_flush: {
            let slot = cache_slot.clone();
            Box::new(move || {
                let n = slot.lock_recover().as_ref().map(|c| c.clear()).unwrap_or(0);
                onetdns_core::info!(
                    event = "cache.flushed",
                    flushed = n,
                    "응답 캐시를 비웠습니다"
                );
                format!("{{\"flushed\":{n}}}")
            })
        },

        rewrites_list: {
            let runtime = runtime_cfg.clone();
            Box::new(move || {
                let current = runtime.load();
                let items: Vec<String> = current
                    .rewrites
                    .iter()
                    .map(|r| {
                        format!(
                            "{{\"domain\":{},\"answer\":{}}}",
                            onetdns_core::json::escape(&r.domain),
                            onetdns_core::json::escape(&r.answer)
                        )
                    })
                    .collect();
                format!("{{\"rewrites\":[{}]}}", items.join(","))
            })
        },

        rewrite_add: {
            let path = config_path.clone();
            let prev = config_prev.clone();
            let reload = reload.clone();
            let hot_apply = hot_config_apply.clone();
            let applied = applied_config_text.clone();
            Box::new(move |body: &str| {
                let j = onetdns_core::json::parse(body)
                    .map_err(|_| "JSON 요청 본문을 해석할 수 없습니다".to_string())?;
                let domain = j
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .ok_or("`domain` 항목을 입력해야 합니다".to_string())?
                    .to_string();
                let answer = j
                    .get("answer")
                    .and_then(|v| v.as_str())
                    .ok_or("`answer` 항목을 입력해야 합니다".to_string())?
                    .to_string();
                let result =
                    apply_config_edit_smart(&path, &prev, &applied, &reload, &hot_apply, |text| {
                        let cur = onetdns_config::Config::from_toml_str(text)
                            .map_err(|e| e.to_string())?;
                        let mut rw = cur.rewrites;
                        rw.retain(|r| r.domain != domain);
                        rw.push(onetdns_config::Rewrite {
                            domain: domain.clone(),
                            answer: answer.clone(),
                        });
                        rewrite_config_kv(text, "rewrites", &rewrites_to_toml(&rw))
                    })?;
                Ok(format!(
                    "{{\"added\":true,\"domain\":{},{} }}",
                    onetdns_core::json::escape(&domain),
                    result.json_fields()
                ))
            })
        },

        rewrite_delete: {
            let path = config_path.clone();
            let prev = config_prev.clone();
            let reload = reload.clone();
            let hot_apply = hot_config_apply.clone();
            let applied = applied_config_text.clone();
            Box::new(move |body: &str| {
                let j = onetdns_core::json::parse(body)
                    .map_err(|_| "JSON 요청 본문을 해석할 수 없습니다".to_string())?;
                let domain = j
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .ok_or("`domain` 항목을 입력해야 합니다".to_string())?
                    .to_string();
                let mut removed = 0usize;
                let result =
                    apply_config_edit_smart(&path, &prev, &applied, &reload, &hot_apply, |text| {
                        let cur = onetdns_config::Config::from_toml_str(text)
                            .map_err(|e| e.to_string())?;
                        let before = cur.rewrites.len();
                        let rw: Vec<_> = cur
                            .rewrites
                            .into_iter()
                            .filter(|r| r.domain != domain)
                            .collect();
                        removed = before - rw.len();
                        if removed == 0 {
                            return Err(format!("일치하는 주소 변경 규칙이 없습니다: {domain}"));
                        }
                        rewrite_config_kv(text, "rewrites", &rewrites_to_toml(&rw))
                    })?;
                Ok(format!(
                    "{{\"removed\":{removed},\"domain\":{},{} }}",
                    onetdns_core::json::escape(&domain),
                    result.json_fields()
                ))
            })
        },

        services_catalog: {
            let services = service_set.clone();
            Box::new(move || {
                let blocked = services.lock_recover().clone();
                let all: Vec<String> = onetdns_filter::services::catalog()
                    .iter()
                    .map(|service| {
                        let b = blocked.iter().any(|id| id.as_str() == service.id);
                        format!(
                            "{{\"id\":{},\"name\":{},\"group\":{},\"rule_count\":{},\"blocked\":{}}}",
                            onetdns_core::json::escape(service.id),
                            onetdns_core::json::escape(service.name),
                            onetdns_core::json::escape(service.group),
                            service.rules.len(),
                            b
                        )
                    })
                    .collect();
                format!(
                    "{{\"count\":{},\"services\":[{}]}}",
                    all.len(),
                    all.join(",")
                )
            })
        },

        access_list: {
            let runtime = runtime_cfg.clone();
            Box::new(move || {
                let c = runtime.load();
                let arr = |v: &[onetdns_core::IpNet]| {
                    v.iter()
                        .map(|n| onetdns_core::json::escape(&n.to_string()))
                        .collect::<Vec<_>>()
                        .join(",")
                };
                let refused = c
                    .refused_domains
                    .iter()
                    .map(|h| onetdns_core::json::escape(h))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    "{{\"allowed\":[{}],\"blocked\":[{}],\"refused_domains\":[{}]}}",
                    arr(&c.acl_allow),
                    arr(&c.acl_deny),
                    refused
                )
            })
        },

        tls_status: {
            let runtime = runtime_cfg.clone();
            Box::new(move || {
                let current = runtime.load();
                let (cert, key) = (&current.tls_cert, &current.tls_key);
                let listen_doh = current.listen_doh.len();
                let listen_dot = current.listen_dot.len();
                let configured = cert.is_some() && key.is_some();
                format!(
                    "{{\"configured\":{},\"cert\":{},\"key\":{},\"doh_listeners\":{},\"dot_listeners\":{}}}",
                    configured,
                    cert.as_ref().map(|p| onetdns_core::json::escape(&p.display().to_string())).unwrap_or_else(|| "null".into()),
                    key.as_ref().map(|p| onetdns_core::json::escape(&p.display().to_string())).unwrap_or_else(|| "null".into()),
                    listen_doh, listen_dot
                )
            })
        },

        tls_validate: {
            let runtime = runtime_cfg.clone();
            Box::new(move || {
                let current = runtime.load();
                let (Some(cp), Some(kp)) = (&current.tls_cert, &current.tls_key) else {
                    return Err("tls_cert/tls_key 미설정".to_string());
                };
                let (certs, keyder) = onetdns_transport::load_pem(cp, kp)
                    .map_err(|e| format!("PEM 데이터를 불러오지 못했습니다: {e}"))?;
                let chain_len = certs.len();
                let material = inspect_tls_material(&certs, &keyder)?;
                let leaf = material
                    .parsed
                    .first()
                    .ok_or("빈 인증서 체인".to_string())?;
                let now = unix_now() as i64;
                let self_signed = material.self_signed;
                let all_times_valid = material.all_times_valid;
                let chain_links_valid = material.chain_links_valid;
                let chain_constraints_valid = material.chain_constraints_valid;
                let material_valid =
                    all_times_valid && chain_links_valid && chain_constraints_valid;

                let trusted = false;
                let hostname_checked = false;
                let valid = false;
                let days_left = (leaf.not_after - now).div_euclid(86_400);
                let subject = leaf
                    .subject_label()
                    .or_else(|| leaf.san_dns.first().cloned())
                    .unwrap_or_default();
                let issuer = leaf.issuer_label().unwrap_or_default();
                Ok(format!(
                    "{{\"valid\":{valid},\"material_valid\":{material_valid},\"key_matches\":true,\"chain_links_valid\":{chain_links_valid},\"chain_constraints_valid\":{chain_constraints_valid},\"all_times_valid\":{all_times_valid},\"self_signed\":{self_signed},\"trusted\":{trusted},\"hostname_checked\":{hostname_checked},\"validation_scope\":\"material_only\",\"chain_len\":{chain_len},\"subject\":{},\"issuer\":{},\"sans\":{},\"not_before\":{},\"not_after\":{},\"days_left\":{days_left}}}",
                    onetdns_core::json::escape(&subject),
                    onetdns_core::json::escape(&issuer),
                    json_str_array(&leaf.san_dns),
                    leaf.not_before,
                    leaf.not_after,
                ))
            })
        },

        tls_configure: {
            let runtime = runtime_cfg.clone();
            let path = config_path.clone();
            let prev = config_prev.clone();
            let reload = reload.clone();
            Box::new(move |body: &str| {
                let current = runtime.load();
                tls_configure(
                    body,
                    &current.tls_cert,
                    &current.tls_key,
                    &path,
                    &prev,
                    &reload,
                )
            })
        },

        tls_revocation_check: {
            let resolver = blocklist_resolver.clone();
            Box::new(move |body: &str| {
                let j = onetdns_core::json::parse(body)
                    .map_err(|e| format!("JSON 요청 본문을 해석할 수 없습니다: {e}"))?;
                let pem = j
                    .get("certificate_chain")
                    .and_then(|v| v.as_str())
                    .ok_or("`certificate_chain` 항목을 입력해야 합니다")?;
                revoke::check_pem_chain_json(
                    pem,
                    unix_now() as i64,
                    Duration::from_secs(10),
                    resolver.clone(),
                )
            })
        },

        acme_issue: {
            // 실행 중 설정을 본다. 시작할 때 값을 가지고 있으면 ACME 설정을 바꿔도 이전
            // 디렉터리 주소와 이전 도메인으로 발급을 시도한다.
            let runtime = runtime_cfg.clone();
            let resolver = blocklist_resolver.clone();
            let acme_tls_slots = tls_slot_handle.clone();
            Box::new(move |body: &str| {
                acme_issue_run(
                    &runtime.load(),
                    body,
                    resolver.clone(),
                    acme_tls_slots.lock_recover().clone(),
                )
            })
        },

        tokens_list: {
            let runtime = runtime_cfg.clone();
            Box::new(move || {
                let c = runtime.load();
                let mut items: Vec<String> = Vec::new();
                let mut push = |tok: &str, role: &str| {
                    items.push(format!(
                        "{{\"id\":{},\"role\":{},\"masked\":{}}}",
                        onetdns_core::json::escape(&token_id(tok)),
                        onetdns_core::json::escape(role),
                        onetdns_core::json::escape(&token_mask(tok))
                    ));
                };
                for t in &c.control_admin_tokens {
                    push(t, "admin");
                }
                for t in &c.control_readonly_tokens {
                    push(t, "readonly");
                }
                format!("{{\"tokens\":[{}]}}", items.join(","))
            })
        },

        token_add: {
            let path = config_path.clone();
            let prev = config_prev.clone();
            let reload = reload.clone();
            let hot_apply = hot_config_apply.clone();
            let applied = applied_config_text.clone();
            Box::new(move |body: &str| {
                let j = onetdns_core::json::parse(body)
                    .map_err(|_| "JSON 요청 본문을 해석할 수 없습니다".to_string())?;
                let readonly = j.get("role").and_then(|v| v.as_str()) != Some("admin");
                let bytes = onetdns_core::rng::try_random_array::<24>()
                    .map_err(|error| format!("보안 토큰을 만들 난수를 얻지 못했습니다: {error}"))?;
                let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                let key = if readonly {
                    "control_readonly_tokens"
                } else {
                    "control_admin_tokens"
                };
                let tok = token.clone();
                let result =
                    apply_config_edit_smart(&path, &prev, &applied, &reload, &hot_apply, |text| {
                        let cur = onetdns_config::Config::from_toml_str(text)
                            .map_err(|e| e.to_string())?;
                        let mut v = if readonly {
                            cur.control_readonly_tokens
                        } else {
                            cur.control_admin_tokens
                        };
                        v.push(tok.clone().into());
                        rewrite_config_string_array(text, key, &v)
                    })?;
                onetdns_core::info!(
                    event = "control.temp_token_issued",
                    role = key,
                    "임시 관리 토큰을 발급했습니다"
                );
                Ok(format!(
                    "{{\"created\":true,\"role\":{},\"token\":{},\"id\":{},{}}}",
                    onetdns_core::json::escape(if readonly { "readonly" } else { "admin" }),
                    onetdns_core::json::escape(&token),
                    onetdns_core::json::escape(&token_id(&token)),
                    result.json_fields()
                ))
            })
        },

        token_delete: {
            let path = config_path.clone();
            let prev = config_prev.clone();
            let reload = reload.clone();
            let hot_apply = hot_config_apply.clone();
            let applied = applied_config_text.clone();
            Box::new(move |body: &str| {
                let j = onetdns_core::json::parse(body)
                    .map_err(|_| "JSON 요청 본문을 해석할 수 없습니다".to_string())?;
                let id = j
                    .get("id")
                    .and_then(|v| v.as_str())
                    .ok_or("`id` 항목을 입력해야 합니다".to_string())?
                    .to_string();
                let mut removed = 0usize;
                let result =
                    apply_config_edit_smart(&path, &prev, &applied, &reload, &hot_apply, |text| {
                        let (out, count) = remove_token_by_id(text, &id)?;
                        removed = count;
                        Ok(out)
                    })?;
                Ok(format!(
                    "{{\"removed\":{removed},{}}}",
                    result.json_fields()
                ))
            })
        },

        config_rollback: {
            let path = config_path.clone();
            let prev = config_prev.clone();
            let reload = reload.clone();
            let hot_apply = hot_config_apply.clone();
            let applied = applied_config_text.clone();
            Box::new(move || {
                let snapshot = prev.lock_recover().clone();
                let Some(text) = snapshot else {
                    return Err("되돌릴 이전 설정이 없습니다".to_string());
                };
                let result =
                    apply_config_edit_smart(&path, &prev, &applied, &reload, &hot_apply, |_| {
                        Ok(text.as_str().to_owned())
                    })?;
                onetdns_core::info!(
                    event = "config.rollback_applied",
                    mode = result.mode.as_str(),
                    keys = ?result.changed,
                    "이전 설정으로 되돌렸습니다"
                );
                Ok(format!("{{\"rolled_back\":true,{}}}", result.json_fields()))
            })
        },

        policy_simulate: {
            let pol = policy_engine.clone();
            let flt = filter.clone();
            Box::new(move |body: &str| simulate_policy(&pol.load(), &flt, body))
        },

        resolve_probe: {
            let runtime = runtime_cfg.clone();
            Box::new(move |body: &str| {
                let current = runtime.load();
                let timeout = Duration::from_secs(current.query_timeout_secs.clamp(1, 10));
                resolve_probe(&current.listen, timeout, body)
            })
        },

        explain: {
            let pol = policy_engine.clone();
            let flt = filter.clone();
            let runtime = runtime_cfg.clone();
            let zones = zone_store.clone();
            Box::new(move |body: &str| {
                explain_query(&pol.load(), &flt, &runtime.load(), &zones.load(), body)
            })
        },

        cluster_status: {
            let runtime = runtime_cfg.clone();
            let resolver = blocklist_resolver.clone();
            Box::new(move || {
                let current = runtime.load();
                let backend = backend_label(current.backend);
                let peers = &current.cluster_peers;
                let listeners = current.listen.len();
                let status = match raft_handle() {
                    Some(h) => h.status_json(backend, listeners),
                    None if peers.is_empty() => standalone_cluster_status_json(backend, listeners),
                    None => peer_cluster_status_json(peers, backend, listeners, &resolver),
                };
                with_raft_identity(&status, &current)
            })
        },

        cluster_propose: Box::new(move |body: &str| match raft_handle() {
            Some(h) => {
                let patch = parse_cluster_proposal(body)?;
                validate_raft_patch_scope(&patch)?;
                let idx = h.propose(body.as_bytes().to_vec())?;
                Ok(format!(
                    "{{\"committed\":true,\"applied\":true,\"index\":{idx}}}"
                ))
            }
            None => Err("Raft 고가용성 기능이 설정되어 있지 않습니다".to_string()),
        }),

        cluster_write: Box::new(cluster_routed_write),

        listeners_status: {
            let reg = listener_reg.clone();
            Box::new(move || {
                use onetdns_core::MutexExt;
                let esc = onetdns_core::json::escape;
                let items: Vec<String> = reg
                    .lock_recover()
                    .iter()
                    .map(|(proto, configured, bound)| {
                        format!(
                            "{{\"protocol\":{},\"configured\":{},\"bound\":{},\"state\":\"listening\"}}",
                            esc(proto),
                            esc(configured),
                            esc(bound)
                        )
                    })
                    .collect();
                format!("[{}]", items.join(","))
            })
        },

        net_adapters: Box::new(|| {
            let adapters = osnet::list_adapters()?;
            let esc = onetdns_core::json::escape;
            let items: Vec<String> = adapters
                .iter()
                .map(|a| {
                    let dns: Vec<String> = a.dns.iter().map(|d| esc(d)).collect();
                    format!("{{\"name\":{},\"dns\":[{}]}}", esc(&a.name), dns.join(","))
                })
                .collect();
            Ok(format!(
                "{{\"platform\":{},\"adapters\":[{}]}}",
                esc(osnet::platform()),
                items.join(",")
            ))
        }),

        firewall_set: Box::new(|body: &str| {
            let j = onetdns_core::json::parse(body)
                .map_err(|e| format!("JSON 요청 본문이 올바르지 않습니다: {e}"))?;
            let port = j
                .get("port")
                .and_then(|v| v.as_u64())
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
                .ok_or("`port` 항목에 1부터 65535 사이의 값을 입력해야 합니다")?;
            let udp = j.get("udp").and_then(|v| v.as_bool()).unwrap_or(true);
            let tcp = j.get("tcp").and_then(|v| v.as_bool()).unwrap_or(true);
            let action = j.get("action").and_then(|v| v.as_str()).unwrap_or("allow");
            match action {
                "allow" => {
                    osnet::firewall_allow(udp, tcp, port)?;
                    onetdns_core::info!(
                        event = "osnet.firewall_opened",
                        port = port,
                        udp = udp,
                        tcp = tcp,
                        "관리 화면 요청으로 이 기계의 방화벽에서 포트를 열었습니다"
                    );
                }
                "remove" => {
                    osnet::firewall_remove(port)?;
                    onetdns_core::info!(
                        event = "osnet.firewall_closed",
                        port = port,
                        "관리 화면 요청으로 이 기계의 방화벽 규칙을 지웠습니다"
                    );
                }
                other => return Err(format!("알 수 없는 방화벽 동작입니다: {other}")),
            }
            Ok(format!(
                "{{\"ok\":true,\"port\":{port},\"action\":{},\"platform\":{}}}",
                onetdns_core::json::escape(action),
                onetdns_core::json::escape(osnet::platform())
            ))
        }),

        dns_client_set: {
            let backup = osnet_backup_dir.clone();
            Box::new(move |body: &str| {
                let j = onetdns_core::json::parse(body)
                    .map_err(|e| format!("JSON 요청 본문이 올바르지 않습니다: {e}"))?;
                let adapter = j
                    .get("adapter")
                    .and_then(|v| v.as_str())
                    .ok_or("`adapter` 항목을 입력해야 합니다")?;
                let servers: Vec<String> = match j.get("servers") {
                    Some(onetdns_core::json::Json::Arr(a)) => a
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect(),
                    _ => return Err("`servers` 배열을 입력해야 합니다".to_string()),
                };
                if servers.is_empty() {
                    return Err("servers 목록에 한 개 이상의 서버를 입력해야 합니다".to_string());
                }
                osnet::set_dns(adapter, &servers, &backup)?;
                onetdns_core::info!(event = "osnet.client_dns_set", adapter = %adapter, servers = %servers.join(","), "관리 화면 요청으로 이 기계의 DNS 서버 설정을 바꿨습니다. 원래 값은 백업해 뒀습니다");
                Ok(format!(
                    "{{\"ok\":true,\"adapter\":{}}}",
                    onetdns_core::json::escape(adapter)
                ))
            })
        },

        // 부팅 서비스는 Windows에만 있다. 다른 곳에서는 기본 콜백이 "지원하지 않음"을
        // 답하므로 여기서 덮어쓰지 않는다.
        #[cfg(windows)]
        boot_service_status: Box::new(|| match service::status() {
            Ok((installed, running)) => {
                format!("{{\"supported\":true,\"installed\":{installed},\"running\":{running}}}")
            }
            Err(error) => format!(
                "{{\"supported\":true,\"installed\":false,\"running\":false,\"error\":{}}}",
                onetdns_core::json::escape(&error.to_string())
            ),
        }),

        #[cfg(windows)]
        boot_service_set: {
            let path = config_path.clone();
            Box::new(move |body: &str| {
                let j = onetdns_core::json::parse(body)
                    .map_err(|e| format!("JSON 요청 본문이 올바르지 않습니다: {e}"))?;
                let action = j
                    .get("action")
                    .and_then(|v| v.as_str())
                    .ok_or("`action` 항목에 install 또는 uninstall을 입력해야 합니다")?;
                // 서비스로 뜰 때도 지금 쓰는 설정 파일을 그대로 읽어야 한다. 넘기지 않으면
                // 부팅 뒤에 기본 설정으로 떠서 지금 화면에 보이는 것과 다르게 돈다.
                let outcome = match action {
                    "install" => service::install(path.clone()),
                    "uninstall" => service::uninstall(),
                    other => {
                        return Err(format!(
                            "`action`은 install 또는 uninstall이어야 합니다: {other}"
                        ))
                    }
                }
                .map_err(|error| error.to_string())?;
                onetdns_core::info!(
                    event = "service.boot_registration_changed",
                    action = %action,
                    "관리 화면 요청으로 부팅 서비스 등록을 바꿨습니다"
                );
                Ok(format!(
                    "{{\"ok\":true,\"message\":{}}}",
                    onetdns_core::json::escape(&outcome)
                ))
            })
        },

        #[cfg(not(windows))]
        boot_service_status: Box::new(|| {
            "{\"supported\":false,\"installed\":false,\"running\":false}".to_string()
        }),

        #[cfg(not(windows))]
        boot_service_set: Box::new(|_| Err("부팅 서비스 등록은 Windows에서만 됩니다".to_string())),

        dns_client_restore: {
            let backup = osnet_backup_dir.clone();
            Box::new(move |body: &str| {
                let j = onetdns_core::json::parse(body)
                    .map_err(|e| format!("JSON 요청 본문이 올바르지 않습니다: {e}"))?;
                let adapter = j
                    .get("adapter")
                    .and_then(|v| v.as_str())
                    .ok_or("`adapter` 항목을 입력해야 합니다")?;
                osnet::restore_dns(adapter, &backup)?;
                onetdns_core::info!(event = "osnet.client_dns_restored", adapter = %adapter, "관리 화면 요청으로 이 기계의 DNS 서버 설정을 백업해 둔 값으로 되돌렸습니다");
                Ok(format!(
                    "{{\"ok\":true,\"adapter\":{}}}",
                    onetdns_core::json::escape(adapter)
                ))
            })
        },

        metrics_extra: Box::new(|| {
            let mut s = String::new();
            let failures = transport_observe::snapshot();
            if !failures.is_empty() {
                s.push_str(
                    "# TYPE onetdns_transport_errors_total counter\n# HELP onetdns_transport_errors_total 전송 단계별 처리 실패 누적 횟수\n",
                );
                for (transport, stage, count) in failures {
                    s.push_str(&format!(
                        "onetdns_transport_errors_total{{transport=\"{transport}\",stage=\"{stage}\"}} {count}\n"
                    ));
                }
            }

            let bogus = native::DNSSEC_BOGUS_TOTAL.load(Ordering::Relaxed)
                + onetdns_recurse::validation_bogus_total();
            if bogus > 0 {
                s.push_str(
                    "# TYPE onetdns_dnssec_bogus_total counter\n# HELP onetdns_dnssec_bogus_total DNSSEC 검증 실패로 차단한 응답 수\n",
                );
                s.push_str(&format!("onetdns_dnssec_bogus_total {bogus}\n"));
            }

            let (batches, datagrams) = onetdns_runtime::recv_batch_counters();
            if batches > 0 {
                s.push_str(
                    "# TYPE onetdns_udp_recv_batches_total counter\n# HELP onetdns_udp_recv_batches_total UDP 배치 수신 호출 횟수\n",
                );
                s.push_str(&format!("onetdns_udp_recv_batches_total {batches}\n"));
                s.push_str(
                    "# TYPE onetdns_udp_recv_datagrams_total counter\n# HELP onetdns_udp_recv_datagrams_total 그 호출들이 가져온 데이터그램 수\n",
                );
                s.push_str(&format!("onetdns_udp_recv_datagrams_total {datagrams}\n"));
            }
            s
        }),

        filter_report: {
            let flt = filter.clone();
            Box::new(move || flt.load().load_report().to_json())
        },

        filter_top_rules: {
            let flt = filter.clone();
            Box::new(move || {
                let eng = flt.load();
                let items: Vec<String> = eng
                    .top_rule_hits(50)
                    .into_iter()
                    .map(|(rule, hits)| {
                        let rule = onetdns_core::json::escape(&rule);
                        format!("{{\"rule\":{rule},\"hits\":{hits}}}")
                    })
                    .collect();
                format!(
                    "{{\"enabled\":{},\"top\":[{}]}}",
                    eng.hits_enabled(),
                    items.join(",")
                )
            })
        },

        filter_sources: {
            let flt = filter.clone();
            Box::new(move || {
                let eng = flt.load();
                let items: Vec<String> = eng
                    .source_stats()
                    .into_iter()
                    .map(|s| {
                        let source = onetdns_core::json::escape(&s.source);
                        format!(
                            "{{\"source\":{source},\"rules\":{},\"hits\":{}}}",
                            s.rules, s.hits
                        )
                    })
                    .collect();
                format!(
                    "{{\"hits_enabled\":{},\"sources\":[{}]}}",
                    eng.hits_enabled(),
                    items.join(",")
                )
            })
        },

        subscriptions_list: {
            let urls = sub_urls.clone();
            let titles = sub_titles.clone();
            let disabled = sub_disabled.clone();
            let meta = sub_meta.clone();
            let presets = preset_urls.clone();
            Box::new(move || {
                let list = urls.lock_recover().clone();
                let preset_list = presets.lock_recover().clone();
                let names = titles.lock_recover().clone();
                let off = disabled.lock_recover().clone();
                let m = meta.lock_recover();
                let by_url: std::collections::HashMap<&str, &SubMeta> =
                    m.iter().map(|x| (x.url.as_str(), x)).collect();
                let mut lists: Vec<String> = list.iter().enumerate().map(|(i,u)| {
                    let title = names.get(i).cloned().unwrap_or_default();
                    let enabled = !off.iter().any(|x| x == u);
                    match by_url.get(u.as_str()) {
                        Some(sm) => format!("{{\"url\":{},\"title\":{},\"enabled\":{},\"rules\":{},\"updated_unix\":{}}}", onetdns_core::json::escape(u), onetdns_core::json::escape(if title.is_empty(){&sm.title}else{&title}), enabled, sm.rules, sm.updated_unix),
                        None => format!("{{\"url\":{},\"title\":{},\"enabled\":{},\"rules\":0,\"updated_unix\":0}}", onetdns_core::json::escape(u), onetdns_core::json::escape(&title), enabled),
                    }
                }).collect();
                /* 내장 목록도 외부에서 내려받는 목록이다. 숨기면 어디서 받는지, 받아졌는지 볼 수 없다. */
                let builtin: Vec<&String> = preset_list
                    .iter()
                    .filter(|url| !list.contains(url))
                    .collect();
                for url in &builtin {
                    let (rules, updated) = by_url
                        .get(url.as_str())
                        .map_or((0, 0), |meta| (meta.rules, meta.updated_unix));
                    lists.push(format!(
                        "{{\"url\":{},\"title\":\"\",\"enabled\":true,\"rules\":{rules},\"updated_unix\":{updated},\"preset\":{}}}",
                        onetdns_core::json::escape(url),
                        onetdns_core::json::escape(preset_list_kind(url)),
                    ));
                }
                let block_domains: usize = list
                    .iter()
                    .chain(builtin.iter().copied())
                    .filter_map(|url| by_url.get(url.as_str()))
                    .map(|meta| meta.rules)
                    .sum();
                format!(
                    "{{\"count\":{},\"block_domains\":{},\"lists\":[{}]}}",
                    lists.len(),
                    block_domains,
                    lists.join(",")
                )
            })
        },
        subscription_add: {
            let urls = sub_urls.clone();
            let titles = sub_titles.clone();
            let disabled = sub_disabled.clone();
            let presets = preset_urls.clone();
            let sm = sub_meta.clone();
            let rebuild = rebuild.clone();
            let config_path = config_path.clone();
            let resolver = blocklist_resolver.clone();
            let operation_lock = list_refresh_lock.clone();
            let runtime = runtime_cfg.clone();
            Box::new(move |body: &str| {
                let request = onetdns_core::json::parse(body)
                    .map_err(|_| "JSON 요청 본문을 해석할 수 없습니다".to_string())?;
                let url = request
                    .get("url")
                    .and_then(|value| value.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let title = request
                    .get("title")
                    .and_then(|value| value.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !(url.starts_with("http://") || url.starts_with("https://")) {
                    return Err("목록 주소는 http:// 또는 https://로 시작해야 합니다".to_string());
                }

                let _guard = try_list_refresh_lock(&operation_lock)?;
                let previous_urls = urls.lock_recover().clone();
                if previous_urls.iter().any(|item| item == &url) {
                    return Err("이미 등록된 필터 목록입니다".to_string());
                }
                let previous_titles = titles.lock_recover().clone();
                let previous_disabled = disabled.lock_recover().clone();
                let previous_meta = sm.lock_recover().clone();
                let fresh = fetch_blocklist(&url, &resolver, None)?;

                let mut next_urls = previous_urls.clone();
                let mut next_titles = previous_titles.clone();
                next_titles.resize(next_urls.len(), String::new());
                next_urls.push(url.clone());
                next_titles.push(title);
                let mut next_disabled = previous_disabled.clone();
                next_disabled.retain(|item| item != &url);
                persist_subscription_state(
                    config_path.as_deref(),
                    &next_urls,
                    &next_titles,
                    &next_disabled,
                )?;

                *urls.lock_recover() = next_urls.clone();
                *titles.lock_recover() = next_titles;
                *disabled.lock_recover() = next_disabled.clone();
                let active =
                    active_subscription_urls(&next_urls, &next_disabled, &presets.lock_recover());
                let mut next_meta = previous_meta.clone();
                next_meta.retain(|item| active.iter().any(|active_url| active_url == &item.url));
                next_meta.retain(|item| item.url != url);
                next_meta.push(fresh);
                *sm.lock_recover() = next_meta;
                if let Err(error) = rebuild() {
                    *urls.lock_recover() = previous_urls.clone();
                    *titles.lock_recover() = previous_titles.clone();
                    *disabled.lock_recover() = previous_disabled.clone();
                    *sm.lock_recover() = previous_meta;
                    let error = with_rollback_result(
                        error,
                        "구독 설정을 이전 값으로 되돌리지 못했습니다",
                        persist_subscription_state(
                            config_path.as_deref(),
                            &previous_urls,
                            &previous_titles,
                            &previous_disabled,
                        ),
                    );
                    let error = with_rollback_result(
                        error,
                        "구독 필터의 실행 상태를 이전 값으로 되돌리지 못했습니다",
                        rebuild().map(|_| ()),
                    );
                    return Err(error);
                }
                let applied_urls = urls.lock_recover().clone();
                let applied_titles = titles.lock_recover().clone();
                let applied_disabled = disabled.lock_recover().clone();
                update_runtime_config(&runtime, |config| {
                    config.blocklist_urls = applied_urls;
                    config.blocklist_titles = applied_titles;
                    config.disabled_blocklist_urls = applied_disabled;
                });
                Ok("{\"added\":true}".to_string())
            })
        },
        subscription_remove: {
            let urls = sub_urls.clone();
            let titles = sub_titles.clone();
            let disabled = sub_disabled.clone();
            let presets = preset_urls.clone();
            let sm = sub_meta.clone();
            let rebuild = rebuild.clone();
            let config_path = config_path.clone();
            let resolver = blocklist_resolver.clone();
            let operation_lock = list_refresh_lock.clone();
            let runtime = runtime_cfg.clone();
            Box::new(move |url: &str| {
                let target = url.trim();
                let _guard = try_list_refresh_lock(&operation_lock)?;
                let previous_urls = urls.lock_recover().clone();
                let position = previous_urls
                    .iter()
                    .position(|item| item == target)
                    .ok_or_else(|| format!("구독 항목을 찾을 수 없습니다: {target}"))?;
                let previous_titles = titles.lock_recover().clone();
                let previous_disabled = disabled.lock_recover().clone();
                let previous_meta = sm.lock_recover().clone();

                let mut next_urls = previous_urls.clone();
                next_urls.remove(position);
                let mut next_titles = previous_titles.clone();
                next_titles.resize(previous_urls.len(), String::new());
                next_titles.remove(position);
                next_titles.truncate(next_urls.len());
                let mut next_disabled = previous_disabled.clone();
                next_disabled.retain(|item| item != target);
                persist_subscription_state(
                    config_path.as_deref(),
                    &next_urls,
                    &next_titles,
                    &next_disabled,
                )?;

                *urls.lock_recover() = next_urls.clone();
                *titles.lock_recover() = next_titles;
                *disabled.lock_recover() = next_disabled.clone();
                let active =
                    active_subscription_urls(&next_urls, &next_disabled, &presets.lock_recover());
                let next_meta = fetch_blocklists_meta(&active, &resolver, &previous_meta, None);
                *sm.lock_recover() = next_meta;
                if let Err(error) = rebuild() {
                    *urls.lock_recover() = previous_urls.clone();
                    *titles.lock_recover() = previous_titles.clone();
                    *disabled.lock_recover() = previous_disabled.clone();
                    *sm.lock_recover() = previous_meta;
                    let error = with_rollback_result(
                        error,
                        "구독 설정을 이전 값으로 되돌리지 못했습니다",
                        persist_subscription_state(
                            config_path.as_deref(),
                            &previous_urls,
                            &previous_titles,
                            &previous_disabled,
                        ),
                    );
                    let error = with_rollback_result(
                        error,
                        "구독 필터의 실행 상태를 이전 값으로 되돌리지 못했습니다",
                        rebuild().map(|_| ()),
                    );
                    return Err(error);
                }
                let applied_urls = urls.lock_recover().clone();
                let applied_titles = titles.lock_recover().clone();
                let applied_disabled = disabled.lock_recover().clone();
                update_runtime_config(&runtime, |config| {
                    config.blocklist_urls = applied_urls;
                    config.blocklist_titles = applied_titles;
                    config.disabled_blocklist_urls = applied_disabled;
                });
                Ok("{\"removed\":true}".to_string())
            })
        },
        subscription_update: {
            let urls = sub_urls.clone();
            let titles = sub_titles.clone();
            let disabled = sub_disabled.clone();
            let presets = preset_urls.clone();
            let sm = sub_meta.clone();
            let rebuild = rebuild.clone();
            let config_path = config_path.clone();
            let resolver = blocklist_resolver.clone();
            let operation_lock = list_refresh_lock.clone();
            let runtime = runtime_cfg.clone();
            Box::new(move |body: &str| {
                let request = onetdns_core::json::parse(body)
                    .map_err(|_| "JSON 요청 본문을 해석할 수 없습니다".to_string())?;
                let url = request
                    .get("url")
                    .and_then(|value| value.as_str())
                    .unwrap_or("")
                    .trim();
                let enabled = request
                    .get("enabled")
                    .and_then(|value| value.as_bool())
                    .ok_or_else(|| "`enabled` 항목을 입력해야 합니다".to_string())?;

                let _guard = try_list_refresh_lock(&operation_lock)?;
                let current_urls = urls.lock_recover().clone();
                if !current_urls.iter().any(|item| item == url) {
                    return Err(format!("구독 항목을 찾을 수 없습니다: {url}"));
                }
                let current_titles = titles.lock_recover().clone();
                let previous_disabled = disabled.lock_recover().clone();
                let previous_meta = sm.lock_recover().clone();
                let mut next_disabled = previous_disabled.clone();
                if enabled {
                    next_disabled.retain(|item| item != url);
                } else if !next_disabled.iter().any(|item| item == url) {
                    next_disabled.push(url.to_string());
                }
                persist_subscription_state(
                    config_path.as_deref(),
                    &current_urls,
                    &current_titles,
                    &next_disabled,
                )?;
                *disabled.lock_recover() = next_disabled.clone();
                let active = active_subscription_urls(
                    &current_urls,
                    &next_disabled,
                    &presets.lock_recover(),
                );
                let next_meta = fetch_blocklists_meta(&active, &resolver, &previous_meta, None);
                *sm.lock_recover() = next_meta;
                if let Err(error) = rebuild() {
                    *disabled.lock_recover() = previous_disabled.clone();
                    *sm.lock_recover() = previous_meta;
                    let error = with_rollback_result(
                        error,
                        "구독 사용 상태를 이전 값으로 되돌리지 못했습니다",
                        persist_subscription_state(
                            config_path.as_deref(),
                            &current_urls,
                            &current_titles,
                            &previous_disabled,
                        ),
                    );
                    let error = with_rollback_result(
                        error,
                        "구독 필터의 실행 상태를 이전 값으로 되돌리지 못했습니다",
                        rebuild().map(|_| ()),
                    );
                    return Err(error);
                }
                let applied_urls = urls.lock_recover().clone();
                let applied_titles = titles.lock_recover().clone();
                let applied_disabled = disabled.lock_recover().clone();
                update_runtime_config(&runtime, |config| {
                    config.blocklist_urls = applied_urls;
                    config.blocklist_titles = applied_titles;
                    config.disabled_blocklist_urls = applied_disabled;
                });
                Ok(format!("{{\"updated\":true,\"enabled\":{enabled}}}"))
            })
        },
        subscription_refresh: {
            let urls = sub_urls.clone();
            let presets = preset_urls.clone();
            let disabled = sub_disabled.clone();
            let sm = sub_meta.clone();
            let rebuild = rebuild.clone();
            let resolver = blocklist_resolver.clone();
            let operation_lock = list_refresh_lock.clone();
            Box::new(move |body: &str| {
                let request = onetdns_core::json::parse(body)
                    .map_err(|_| "JSON 요청 본문을 해석할 수 없습니다".to_string())?;
                let target = request
                    .get("url")
                    .and_then(|value| value.as_str())
                    .unwrap_or("")
                    .trim();
                let _guard = try_list_refresh_lock(&operation_lock)?;
                let current_urls = urls.lock_recover().clone();
                let builtin = presets.lock_recover().iter().any(|item| item == target);
                if !builtin && !current_urls.iter().any(|item| item == target) {
                    return Err(format!("구독 항목을 찾을 수 없습니다: {target}"));
                }
                if !builtin && disabled.lock_recover().iter().any(|item| item == target) {
                    return Err("사용하지 않도록 설정한 구독은 갱신할 수 없습니다".to_string());
                }
                let fresh = fetch_blocklist(target, &resolver, None)?;
                let previous_meta = sm.lock_recover().clone();
                let mut next_meta = previous_meta.clone();
                match next_meta.iter_mut().find(|item| item.url == target) {
                    Some(item) => *item = fresh,
                    None => next_meta.push(fresh),
                }
                *sm.lock_recover() = next_meta;
                if let Err(error) = rebuild() {
                    *sm.lock_recover() = previous_meta;
                    let error = with_rollback_result(
                        error,
                        "구독 필터의 실행 상태를 이전 값으로 되돌리지 못했습니다",
                        rebuild().map(|_| ()),
                    );
                    return Err(error);
                }
                Ok("{\"refreshed\":true}".to_string())
            })
        },
        filter_rules_list: {
            let ov = overlay.clone();
            let refused = refused_domains_state.clone();
            Box::new(move || {
                let g = ov.lock_recover();
                format!(
                    "{{\"block\":{},\"allow\":{},\"refused_domains\":{}}}",
                    json_str_array(&g.0),
                    json_str_array(&g.1),
                    json_str_array(&refused.lock_recover())
                )
            })
        },
        filter_rule_mutate: {
            let ov = overlay.clone();
            let refused = refused_domains_state.clone();
            let r = rebuild.clone();
            let cp = config_path.clone();
            let runtime = runtime_cfg.clone();
            Box::new(move |body: &str, add: bool| {
                let j = onetdns_core::json::parse(body)
                    .map_err(|_| "JSON 요청 본문을 해석할 수 없습니다".to_string())?;
                let kind = j.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                let rule = j.get("rule").and_then(|v| v.as_str()).unwrap_or("").trim();
                if rule.is_empty() {
                    return Err("`rule` 항목을 입력해야 합니다".to_string());
                }
                match kind {
                    "block" | "allow" => {
                        mutate_user_rule(&ov, cp.as_deref(), &*r, rule, kind == "allow", add)?;
                        let rules = ov.lock_recover().clone();
                        update_runtime_config(&runtime, |config| {
                            config.block_rules = rules.0;
                            config.allow_rules = rules.1;
                        });
                    }
                    "refused_domain" => {
                        let previous = refused.lock_recover().clone();
                        let mut next = previous.clone();
                        if add {
                            if !next.iter().any(|item| item == rule) {
                                next.push(rule.to_string());
                            }
                        } else {
                            next.retain(|item| item != rule);
                        }
                        if let Some(path) = cp.as_deref() {
                            persist_config_string_array(path, "refused_domains", &next)
                                .map_err(|e| e.to_string())?;
                        }
                        *refused.lock_recover() = next;
                        if let Err(error) = r() {
                            *refused.lock_recover() = previous.clone();
                            let error = if let Some(path) = cp.as_deref() {
                                with_rollback_result(
                                    error,
                                    "거절 도메인 설정을 이전 값으로 되돌리지 못했습니다",
                                    persist_config_string_array(path, "refused_domains", &previous)
                                        .map_err(|rollback_error| rollback_error.to_string()),
                                )
                            } else {
                                error
                            };
                            return Err(error);
                        }
                        let applied = refused.lock_recover().clone();
                        update_runtime_config(&runtime, |config| {
                            config.refused_domains = applied;
                        });
                    }
                    _ => {
                        return Err(
                            "kind에는 block, allow 또는 refused_domain을 지정해야 합니다"
                                .to_string(),
                        )
                    }
                }
                Ok("{\"updated\":true}".to_string())
            })
        },
        clients_list: {
            let runtime_cfg = runtime_cfg.clone();
            Box::new(move || {
                let snapshot = runtime_cfg.load();
                let items: Vec<String> = snapshot
                    .clients
                    .iter()
                    .map(|c| {
                        let ids: Vec<String> = c.ids.iter().map(|n| n.to_string()).collect();
                        format!(
                            "{{\"name\":{},\"nets\":{},\"client_ids\":{},\"tags\":{},\"block_rules\":{},\"disable_filtering\":{}}}",
                            onetdns_core::json::escape(&c.name),
                            json_str_array(&ids),
                            json_str_array(&c.client_ids),
                            json_str_array(&c.tags),
                            c.block.len(),
                            c.disable_filtering
                        )
                    })
                    .collect();
                format!("[{}]", items.join(","))
            })
        },

        upstreams_list: {
            let runtime_cfg = runtime_cfg.clone();
            let forward_stats = forward_stats.clone();
            Box::new(move || {
                let snapshot = runtime_cfg.load();
                let mut ups: Vec<String> =
                    snapshot.upstreams.iter().map(|u| u.to_string()).collect();
                ups.extend(snapshot.upstream_urls.clone());

                let stats = forward_stats
                    .lock_recover()
                    .as_ref()
                    .map(|handle| handle.snapshot())
                    .filter(|s| s.len() == ups.len());
                let items: Vec<String> = ups
                    .iter()
                    .enumerate()
                    .map(|(i, addr)| match stats.as_ref().map(|s| &s[i]) {
                        Some(s) => format!(
                            "{{\"id\":{},\"addr\":{},\"queries\":{},\"ok\":{},\"fail\":{},\"ewma_ms\":{:.1}}}",
                            onetdns_core::json::escape(&stable_resource_id("upstream", addr)),
                            onetdns_core::json::escape(addr),
                            s.queries,
                            s.ok,
                            s.fail,
                            s.ewma_ms
                        ),
                        None => format!(
                            "{{\"id\":{},\"addr\":{}}}",
                            onetdns_core::json::escape(&stable_resource_id("upstream", addr)),
                            onetdns_core::json::escape(addr)
                        ),
                    })
                    .collect();
                format!("[{}]", items.join(","))
            })
        },

        jobs_list: {
            let j = jobs.clone();
            Box::new(move || j.list_json())
        },
        job_get: {
            let j = jobs.clone();
            Box::new(move |id: u64| {
                j.get_json(id)
                    .ok_or_else(|| format!("작업을 찾을 수 없습니다: {id}"))
            })
        },

        job_refresh: {
            let jobs = jobs.clone();
            let refresh_lists = refresh_url_lists.clone();
            let service_threads = service_threads.clone();
            Box::new(move || {
                let Some(id) = jobs.create("refresh-lists") else {
                    return "{\"error\":\"진행 중인 작업이 가득 찼습니다\",\"busy\":true}"
                        .to_string();
                };
                let task_jobs = jobs.clone();
                let refresh_lists = refresh_lists.clone();
                match std::thread::Builder::new()
                    .name(format!("refresh-lists-{id}"))
                    .spawn(move || match refresh_lists() {
                        Ok((block, allow)) => {
                            task_jobs.finish(id, true, format!("block={block} allow={allow}"))
                        }
                        Err(error) => task_jobs.finish(id, false, error),
                    }) {
                    Ok(thread) => {
                        track_service_thread(&service_threads, thread);
                        format!("{{\"id\":{id},\"status\":\"running\"}}")
                    }
                    Err(error) => {
                        let message = format!("작업 스레드를 시작하지 못했습니다: {error}");
                        jobs.finish(id, false, message.clone());
                        format!(
                            "{{\"id\":{id},\"status\":\"failed\",\"error\":{}}}",
                            onetdns_core::json::escape(&message)
                        )
                    }
                }
            })
        },

        dhcp_leases: {
            let v4 = dhcp_slot.clone();
            let v6 = dhcp6_slot.clone();
            let vd = vendor_db.clone();
            Box::new(move || {
                let v4 = v4.lock_recover().clone();
                let v6 = v6.lock_recover().clone();
                leases_json(v4.as_ref(), v6.as_ref(), &vd.load())
            })
        },

        dhcp_lease_put: {
            let v4 = dhcp_slot.clone();
            Box::new(move |body: &str| match v4.lock_recover().clone() {
                Some(pool) => apply_lease_sync(&pool, body),
                None => Err("DHCPv4 기능이 설정되어 있지 않습니다".to_string()),
            })
        },

        dhcp_static_list: {
            let v4 = dhcp_slot.clone();
            Box::new(move || static_reservations_json(v4.lock_recover().as_ref()))
        },

        dhcp_static_add: {
            let v4 = dhcp_slot.clone();
            Box::new(move |body: &str| match v4.lock_recover().clone() {
                Some(pool) => apply_static_add(&pool, body),
                None => Err("DHCPv4 기능이 설정되어 있지 않습니다".to_string()),
            })
        },

        dhcp_static_remove: {
            let v4 = dhcp_slot.clone();
            Box::new(move |identity: &str| match v4.lock_recover().clone() {
                Some(pool) => apply_static_remove(&pool, identity),
                None => Err("DHCPv4 기능이 설정되어 있지 않습니다".to_string()),
            })
        },

        client_add: {
            let path = config_path.clone();
            let prev = config_prev.clone();
            let reload = reload.clone();
            let hot_apply = hot_config_apply.clone();
            let applied = applied_config_text.clone();
            Box::new(move |body: &str| {
                let (block, name) = client_block_from_json(body)?;
                let result =
                    apply_config_edit_smart(&path, &prev, &applied, &reload, &hot_apply, |text| {
                        let cfg = onetdns_config::Config::from_toml_str(text)
                            .map_err(|e| e.to_string())?;
                        if cfg.clients.iter().any(|c| c.name == name) {
                            return Err(format!("이미 등록된 클라이언트입니다: {name}"));
                        }
                        let mut t = text.to_string();
                        if !t.ends_with('\n') {
                            t.push('\n');
                        }
                        t.push_str(&block);
                        Ok(t)
                    })?;
                Ok(format!(
                    "{{\"added\":true,\"name\":{},{} }}",
                    onetdns_core::json::escape(&name),
                    result.json_fields()
                ))
            })
        },

        client_remove: {
            let path = config_path.clone();
            let prev = config_prev.clone();
            let reload = reload.clone();
            let hot_apply = hot_config_apply.clone();
            let applied = applied_config_text.clone();
            Box::new(move |name: &str| {
                let name = name.trim().to_string();
                if name.is_empty() {
                    return Err("`name` 항목을 입력해야 합니다".to_string());
                }
                let result =
                    apply_config_edit_smart(&path, &prev, &applied, &reload, &hot_apply, |text| {
                        remove_client_block(text, &name)
                            .ok_or_else(|| format!("클라이언트를 찾을 수 없습니다: {name}"))
                    })?;
                Ok(format!(
                    "{{\"removed\":true,\"name\":{},{} }}",
                    onetdns_core::json::escape(&name),
                    result.json_fields()
                ))
            })
        },

        client_update: {
            let path = config_path.clone();
            let prev = config_prev.clone();
            let reload = reload.clone();
            let hot_apply = hot_config_apply.clone();
            let applied = applied_config_text.clone();
            Box::new(move |body: &str| {
                let j = onetdns_core::json::parse(body)
                    .map_err(|_| "JSON 요청 본문을 해석할 수 없습니다".to_string())?;
                let name = j
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let disable = j
                    .get("disable_filtering")
                    .and_then(|v| v.as_bool())
                    .ok_or("`disable_filtering` 항목을 입력해야 합니다".to_string())?;
                if name.is_empty() {
                    return Err("`name` 항목을 입력해야 합니다".to_string());
                }
                let result =
                    apply_config_edit_smart(&path, &prev, &applied, &reload, &hot_apply, |text| {
                        update_client_disable(text, &name, disable)
                    })?;
                Ok(format!(
                    "{{\"updated\":true,\"name\":{},\"disable_filtering\":{disable},{} }}",
                    onetdns_core::json::escape(&name),
                    result.json_fields()
                ))
            })
        },
        // 계정 변경은 DNS 처리와 무관하다. 무조건 재시작하는 경로를 쓰면 비밀번호를
        // 한 번 바꿀 때마다 이름 풀이가 끊긴다.
        password_change: {
            let path = config_path.clone();
            let prev = config_prev.clone();
            let reload = reload.clone();
            let hot_apply = hot_config_apply.clone();
            let applied = applied_config_text.clone();
            Box::new(move |name: &str, hash: &str| {
                let result =
                    apply_config_edit_smart(&path, &prev, &applied, &reload, &hot_apply, |text| {
                        rewrite_user_password_hash(text, name, hash)
                    })?;
                Ok(format!(
                    "{{\"changed\":true,\"mode\":\"{}\",\"restart_required\":{}}}",
                    result.mode.as_str(),
                    result.mode.restart_required()
                ))
            })
        },
        user_create: {
            let path = config_path.clone();
            let prev = config_prev.clone();
            let reload = reload.clone();
            let hot_apply = hot_config_apply.clone();
            let applied = applied_config_text.clone();
            Box::new(move |name: &str, hash: &str| {
                let result =
                    apply_config_edit_smart(&path, &prev, &applied, &reload, &hot_apply, |text| {
                        append_user_block(text, name, hash)
                    })?;
                Ok(format!(
                    "{{\"created\":true,\"mode\":\"{}\",\"restart_required\":{}}}",
                    result.mode.as_str(),
                    result.mode.restart_required()
                ))
            })
        },
        upstream_add: {
            let path = config_path.clone();
            let prev = config_prev.clone();
            let reload = reload.clone();
            let hot_apply = hot_config_apply.clone();
            let applied = applied_config_text.clone();
            Box::new(move |entry: &str| {
                let entry = entry.trim().to_string();
                if entry.is_empty() {
                    return Err("추가할 업스트림 DNS 서버 주소가 비어 있습니다".to_string());
                }
                let key = upstream_key(&entry);
                let result =
                    apply_config_edit_smart(&path, &prev, &applied, &reload, &hot_apply, |text| {
                        let cfg = onetdns_config::Config::from_toml_str(text)
                            .map_err(|e| e.to_string())?;
                        let mut vals = upstream_values(&cfg, key);
                        if vals.iter().any(|value| value == &entry) {
                            return Err(format!("이미 등록된 업스트림 DNS 서버입니다: {entry}"));
                        }
                        vals.push(entry.clone());
                        // 암호화 업스트림을 처음 적으면 적히지 않은 기본 평문 업스트림이 물러난다.
                        // 여기서 쓰던 목록을 텍스트로 남기지 않으면 목록에서 조용히 사라진다.
                        let text = if key == "upstream_urls"
                            && cfg.upstream_urls.is_empty()
                            && !cfg.upstreams.is_empty()
                        {
                            let plain = upstream_values(&cfg, "upstreams");
                            rewrite_config_string_array(text, "upstreams", &plain)?
                        } else {
                            text.to_string()
                        };
                        rewrite_config_string_array(&text, key, &vals)
                    })?;
                onetdns_core::info!(
                    event = "upstream.added",
                    address = %entry,
                    config_key = key,
                    apply_mode = result.mode.as_str(),
                    "업스트림 DNS 서버를 추가했습니다"
                );
                Ok(format!(
                    "{{\"added\":{},\"id\":{},\"key\":{},{} }}",
                    onetdns_core::json::escape(&entry),
                    onetdns_core::json::escape(&stable_resource_id("upstream", &entry)),
                    onetdns_core::json::escape(key),
                    result.json_fields()
                ))
            })
        },

        upstream_remove: {
            let path = config_path.clone();
            let prev = config_prev.clone();
            let reload = reload.clone();
            let hot_apply = hot_config_apply.clone();
            let applied = applied_config_text.clone();
            Box::new(move |entry: &str| {
                let entry = entry.trim().to_string();
                let key = upstream_key(&entry);
                let result =
                    apply_config_edit_smart(&path, &prev, &applied, &reload, &hot_apply, |text| {
                        let cfg = onetdns_config::Config::from_toml_str(text)
                            .map_err(|e| e.to_string())?;
                        let mut vals = upstream_values(&cfg, key);
                        let before = vals.len();
                        vals.retain(|value| value != &entry);
                        if vals.len() == before {
                            return Err(format!("업스트림 DNS 서버를 찾을 수 없습니다: {entry}"));
                        }
                        rewrite_config_string_array(text, key, &vals)
                    })?;
                onetdns_core::info!(
                    event = "upstream.removed",
                    address = %entry,
                    config_key = key,
                    apply_mode = result.mode.as_str(),
                    "업스트림 DNS 서버를 삭제했습니다"
                );
                Ok(format!(
                    "{{\"removed\":{},\"id\":{},\"key\":{},{} }}",
                    onetdns_core::json::escape(&entry),
                    onetdns_core::json::escape(&stable_resource_id("upstream", &entry)),
                    onetdns_core::json::escape(key),
                    result.json_fields()
                ))
            })
        },

        plugins_metrics: {
            let pol = policy_engine.clone();
            Box::new(move || {
                let items: Vec<String> = pol
                    .load()
                    .plugin_metrics()
                    .into_iter()
                    .map(|(name, m)| {
                        format!(
                            "{{\"name\":{},\"eval\":{},\"error\":{},\"timeout\":{},\"block\":{},\"latency_us\":{}}}",
                            onetdns_core::json::escape(&name),
                            m.eval_total,
                            m.error_total,
                            m.timeout_total,
                            m.block_total,
                            m.latency_us_total
                        )
                    })
                    .collect();
                format!("[{}]", items.join(","))
            })
        },

        zones_list: {
            let zs = zone_store.clone();
            Box::new(move || {
                let store = zs.load();
                let items: Vec<String> = store
                    .zones()
                    .iter()
                    .map(|z| {
                        let records: Vec<String> = zone_records_without_closing_soa(z)
                            .iter()
                            .map(zone_record_json)
                            .collect();
                        format!(
                            "{{\"origin\":{},\"serial\":{},\"records\":{},\"record_items\":[{}]}}",
                            onetdns_core::json::escape(&z.origin().to_ascii_lower()),
                            z.soa().serial,
                            z.axfr_records().len().saturating_sub(2),
                            records.join(",")
                        )
                    })
                    .collect();
                format!("[{}]", items.join(","))
            })
        },

        zone_get: {
            let zs = zone_store.clone();
            Box::new(move |origin: &str| {
                let name = onetdns_proto::Name::from_str(origin)
                    .map_err(|_| format!("DNS 영역 이름 형식이 올바르지 않습니다: {origin}"))?;
                let store = zs.load();
                let zone = store
                    .zones()
                    .iter()
                    .find(|z| z.origin().eq_ignore_case(&name))
                    .ok_or_else(|| format!("DNS 영역을 찾을 수 없습니다: {origin}"))?;
                let records: Vec<String> = zone_records_without_closing_soa(zone)
                    .iter()
                    .map(zone_record_json)
                    .collect();
                Ok(format!(
                    "{{\"origin\":{},\"serial\":{},\"record_count\":{},\"records\":[{}]}}",
                    onetdns_core::json::escape(&zone.origin().to_ascii_lower()),
                    zone.soa().serial,
                    records.len(),
                    records.join(",")
                ))
            })
        },

        zone_put: {
            let zs = zone_store.clone();
            let runtime = runtime_cfg.clone();
            let signers = zone_signers.clone();
            let journal = ixfr_journal.clone();
            let notify = notify_sender.clone();
            Box::new(move |origin: &str, text: &str| {
                let current_cfg = runtime.load();
                let target = zone_api_target(&current_cfg, &zs.load(), origin, "수정")?;
                let key = target.key.clone();
                let zone = onetdns_authority::parse_zone(text, origin)
                    .map_err(|e| format!("DNS 영역 데이터 형식이 올바르지 않습니다: {e}"))?;

                let path = target.path.clone();
                let applied = apply_zone_mutation(
                    &zs,
                    zone,
                    &signers.load(),
                    &journal,
                    path.as_deref(),
                    &notify,
                    "DNS 영역 변경",
                )?;
                onetdns_core::info!(event = "authority.zone_saved", origin = %key, serial = applied.serial, persisted = applied.persisted, "DNS 영역을 저장했습니다");
                Ok(format!(
                    "{{\"origin\":\"{}\",\"serial\":{},\"records\":{},\"persisted\":{},\"signed\":{},\"served\":{}}}",
                    applied.origin,
                    applied.serial,
                    applied.records,
                    applied.persisted,
                    applied.signed,
                    authority_sources_configured(&current_cfg)
                ))
            })
        },

        zone_delete: {
            let zs = zone_store.clone();
            let runtime = runtime_cfg.clone();
            let journal = ixfr_journal.clone();
            Box::new(move |origin: &str| {
                let current_cfg = runtime.load();
                let target = zone_api_target(&current_cfg, &zs.load(), origin, "삭제")?;
                let key = target.key.clone();
                let name = onetdns_proto::Name::from_str(origin)
                    .map_err(|_| format!("DNS 영역 이름 형식이 올바르지 않습니다: {origin}"))?;
                let mut journals = journal.lock().unwrap_or_else(|e| e.into_inner());
                let exists = zs
                    .load()
                    .zones()
                    .iter()
                    .any(|z| z.origin().eq_ignore_case(&name));
                if !exists {
                    return Err(format!("DNS 영역을 찾을 수 없습니다: {origin}"));
                }
                let path = target.path.clone();
                let mut file_removed = false;
                if let Some(p) = path {
                    if p.exists() {
                        std::fs::remove_file(&p).map_err(|e| {
                            format!("DNS 영역 파일을 삭제하지 못했습니다({}): {e}", p.display())
                        })?;
                        file_removed = true;
                    }
                }
                remove_zone(&zs, &name);
                journals.remove(&name.canonical_key());
                onetdns_core::info!(event = "authority.zone_deleted", origin = %key, file_removed, "DNS 영역을 삭제했습니다");
                Ok(format!(
                    "{{\"deleted\":true,\"file_removed\":{file_removed}}}"
                ))
            })
        },

        zone_record_add: {
            let zs = zone_store.clone();
            let runtime = runtime_cfg.clone();
            let signers = zone_signers.clone();
            let journal = ixfr_journal.clone();
            let notify = notify_sender.clone();
            Box::new(move |origin: &str, body: &str| {
                let current_cfg = runtime.load();
                let target = zone_api_target(&current_cfg, &zs.load(), origin, "수정")?;
                let name = onetdns_proto::Name::from_str(origin)
                    .map_err(|_| format!("DNS 영역 이름 형식이 올바르지 않습니다: {origin}"))?;
                let line = body.trim();
                if line.is_empty() {
                    return Err("DNS 레코드 본문이 비어 있습니다".to_string());
                }
                let mut journals = journal.lock().unwrap_or_else(|e| e.into_inner());
                let current = {
                    let store = zs.load();
                    let zone = store
                        .zones()
                        .iter()
                        .find(|z| z.origin().eq_ignore_case(&name))
                        .ok_or_else(|| format!("DNS 영역을 찾을 수 없습니다: {origin}"))?;
                    zone.to_master_file()
                };
                let zone = onetdns_authority::parse_zone(&format!("{current}\n{line}\n"), origin)
                    .map_err(|e| format!("DNS 레코드 형식이 올바르지 않습니다: {e}"))?;
                let path = target.path.clone();
                let applied = apply_zone_mutation_locked(
                    &zs,
                    zone,
                    &signers.load(),
                    &mut journals,
                    path.as_deref(),
                    &notify,
                    "DNS 레코드를 추가했습니다",
                )?;
                onetdns_core::info!(event = "authority.record_added", origin = %applied.origin, serial = applied.serial, "DNS 레코드를 추가했습니다");
                Ok(format!(
                    "{{\"origin\":\"{}\",\"serial\":{},\"records\":{},\"persisted\":{},\"signed\":{}}}",
                    applied.origin, applied.serial, applied.records, applied.persisted, applied.signed
                ))
            })
        },

        zone_record_delete: {
            let zs = zone_store.clone();
            let runtime = runtime_cfg.clone();
            let signers = zone_signers.clone();
            let journal = ixfr_journal.clone();
            let notify = notify_sender.clone();
            Box::new(move |origin: &str, body: &str| {
                let current_cfg = runtime.load();
                let target = zone_api_target(&current_cfg, &zs.load(), origin, "수정")?;
                let name = onetdns_proto::Name::from_str(origin)
                    .map_err(|_| format!("DNS 영역 이름 형식이 올바르지 않습니다: {origin}"))?;
                let j = onetdns_core::json::parse(body).unwrap_or(onetdns_core::json::Json::Null);
                let rname_s = j
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or("`name` 항목을 입력해야 합니다".to_string())?;
                let rtype_s = j
                    .get("type")
                    .and_then(|v| v.as_str())
                    .ok_or("`type` 항목을 입력해야 합니다".to_string())?;

                let rvalue = j
                    .get("value")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|value| !value.is_empty());
                let rtype_num = *qtype_numbers(&[rtype_s.to_string()])
                    .first()
                    .ok_or_else(|| format!("지원하지 않는 DNS 레코드 형식입니다: {rtype_s}"))?;
                if rtype_num == 6 {
                    return Err("SOA 레코드는 삭제할 수 없습니다".to_string());
                }
                let rtype = onetdns_proto::RecordType(rtype_num);
                let rname = resolve_zone_name(rname_s, origin)
                    .ok_or_else(|| format!("DNS 이름 형식이 올바르지 않습니다: {rname_s}"))?;
                let mut journals = journal.lock().unwrap_or_else(|e| e.into_inner());
                let mut recs = {
                    let store = zs.load();
                    let zone = store
                        .zones()
                        .iter()
                        .find(|z| z.origin().eq_ignore_case(&name))
                        .ok_or_else(|| format!("DNS 영역을 찾을 수 없습니다: {origin}"))?;
                    zone.axfr_records()
                };
                recs.pop();
                let before = recs.len();
                recs.retain(|record| {
                    let same_owner = record.name.eq_ignore_case(&rname);
                    let same_type = record.rtype == rtype;
                    let same_value = rvalue
                        .map(|expected| zone_record_value(record) == expected)
                        .unwrap_or(true);
                    !(same_owner && same_type && same_value)
                });
                let removed = before - recs.len();
                if removed == 0 {
                    return Err(format!(
                        "일치하는 DNS 레코드를 찾을 수 없습니다: {rname_s} {rtype_s}"
                    ));
                }
                let zone = onetdns_authority::Zone::from_records(recs)
                    .map_err(|e| format!("DNS 영역을 다시 구성하지 못했습니다: {e}"))?;
                let path = target.path.clone();
                let applied = apply_zone_mutation_locked(
                    &zs,
                    zone,
                    &signers.load(),
                    &mut journals,
                    path.as_deref(),
                    &notify,
                    "DNS 레코드를 삭제했습니다",
                )?;
                onetdns_core::info!(event = "authority.record_deleted", origin = %applied.origin, removed, serial = applied.serial, "DNS 레코드를 삭제했습니다");
                Ok(format!(
                    "{{\"deleted\":{removed},\"origin\":{},\"serial\":{},\"persisted\":{}}}",
                    onetdns_core::json::escape(&applied.origin.to_string()),
                    applied.serial,
                    applied.persisted
                ))
            })
        },

        zone_dnssec: {
            let signers = zone_signers.clone();
            Box::new(move |origin: &str| {
                let name = onetdns_proto::Name::from_str(origin)
                    .map_err(|_| format!("DNS 영역 이름 형식이 올바르지 않습니다: {origin}"))?;
                let signers = signers.load();
                let Some((_, ctx)) = signers.iter().find(|(o, _)| o.eq_ignore_case(&name)) else {
                    return Ok(format!(
                        "{{\"origin\":{},\"signed\":false,\"dnskeys\":[],\"ds\":null}}",
                        onetdns_core::json::escape(&name.to_ascii_lower())
                    ));
                };
                let signer = &ctx.signer;
                let mut keys: Vec<String> = Vec::new();
                let zsk = signer.dnskey();
                let has_ksk = signer.ksk_dnskey().is_some();
                keys.push(format!(
                    "{{\"key_tag\":{},\"flags\":{},\"algorithm\":{},\"role\":\"{}\"}}",
                    zsk.key_tag(),
                    zsk.flags,
                    zsk.algorithm,
                    if has_ksk { "ZSK" } else { "CSK" }
                ));
                if let Some(ksk) = signer.ksk_dnskey() {
                    keys.push(format!(
                        "{{\"key_tag\":{},\"flags\":{},\"algorithm\":{},\"role\":\"KSK\"}}",
                        ksk.key_tag(),
                        ksk.flags,
                        ksk.algorithm
                    ));
                }
                let ds_json = match signer.ds() {
                    Some(ds) => {
                        let hex: String = ds.digest.iter().map(|b| format!("{b:02x}")).collect();
                        format!(
                            "{{\"key_tag\":{},\"algorithm\":{},\"digest_type\":{},\"digest\":\"{}\"}}",
                            ds.key_tag, ds.algorithm, ds.digest_type, hex
                        )
                    }
                    None => "null".to_string(),
                };
                Ok(format!(
                    "{{\"origin\":{},\"signed\":true,\"dnskeys\":[{}],\"ds\":{}}}",
                    onetdns_core::json::escape(&name.to_ascii_lower()),
                    keys.join(","),
                    ds_json
                ))
            })
        },

        config_desired: {
            let c = runtime_cfg.clone();
            let path = config_path.clone();
            Box::new(move || desired_config_json(path.as_deref(), &c.load()))
        },
        config_effective: {
            let c = runtime_cfg.clone();
            Box::new(move || c.load().effective_json())
        },
        config_status: {
            let c = runtime_cfg.clone();
            let path = config_path.clone();
            Box::new(move || config_status_json(path.as_deref(), &c.load()))
        },
        config_reload: {
            let c = runtime_cfg.clone();
            let path = config_path.clone();
            let reload_tls_slots = tls_slot_handle.clone();
            let reload = reload.clone();
            let hot_apply = hot_config_apply.clone();
            let applied = applied_config_text.clone();
            let prev = config_prev.clone();
            Box::new(move || {
                let path = path.as_deref().ok_or_else(|| {
                    "설정 파일 경로가 없어 디스크 설정을 적용할 수 없습니다".to_string()
                })?;
                let text = onetdns_core::SecretString::from(
                    Config::read_text(path).map_err(|error| error.to_string())?,
                );
                let desired = Config::from_toml_str(&text).map_err(|error| error.to_string())?;
                let current = c.load();
                let previous_text = applied.lock_recover().clone();
                let changed = config_changed_keys(&current, &desired)?;
                if changed.is_empty() {
                    if previous_text.as_deref() != Some(text.as_str()) {
                        *prev.lock_recover() = previous_text;
                        *applied.lock_recover() = Some(text);
                    }
                    // 설정 항목이 그대로여도 그 항목이 가리키는 인증서 파일은 갱신되었을 수
                    // 있다. 여기서 보지 않으면 갱신 뒤 다시 시작할 때까지 만료된 인증서를
                    // 계속 내민다.
                    if let Some(slots) = reload_tls_slots.lock_recover().clone() {
                        let swapped = slots.refresh_certificate_files(&current)?;
                        if !swapped.is_empty() {
                            onetdns_core::info!(
                                event = "tls.certificate_reloaded",
                                changed = %swapped.join(","),
                                "수신 주소를 닫지 않고 TLS 인증서를 교체했습니다"
                            );
                            let names: Vec<String> = swapped
                                .iter()
                                .map(|key| onetdns_core::json::escape(key))
                                .collect();
                            return Ok(format!(
                                "{{\"accepted\":true,\"mode\":\"hot_reload\",\"restart_required\":false,\"changed\":[{}]}}",
                                names.join(",")
                            ));
                        }
                    }
                    return Ok("{\"accepted\":false,\"mode\":\"no_change\",\"restart_required\":false,\"changed\":[]}".to_string());
                }

                let (hot_applied, effective_changed) = hot_apply(&desired, &changed)?;
                let changed_json: Vec<String> = effective_changed
                    .iter()
                    .map(|key| onetdns_core::json::escape(key))
                    .collect();
                if hot_applied {
                    *prev.lock_recover() = previous_text;
                    *applied.lock_recover() = Some(text);
                    onetdns_core::info!(
                        event = "config.disk_hot_applied",
                        path = %path.display(),
                        changed = effective_changed.len(),
                        "파일에 저장된 설정을 실행 중인 서비스에 적용했습니다"
                    );
                    return Ok(format!(
                        "{{\"accepted\":true,\"mode\":\"hot_reload\",\"restart_required\":false,\"changed\":[{}]}}",
                        changed_json.join(",")
                    ));
                }
                *prev.lock_recover() = previous_text;
                reload.store(true, std::sync::atomic::Ordering::Release);
                onetdns_core::info!(
                    event = "config.disk_restart_requested",
                    path = %path.display(),
                    changed = effective_changed.len(),
                    "파일에 저장된 설정을 적용하기 위해 DNS 서비스를 다시 시작합니다"
                );
                Ok(format!(
                    "{{\"accepted\":true,\"mode\":\"service_restart\",\"restart_required\":true,\"changed\":[{}]}}",
                    changed_json.join(",")
                ))
            })
        },
    }
}
