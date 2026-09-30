/*!
 * @brief 설정에서 질의 처리기가 쓰는 정책, 접근 제어, 속도 제한, 빠른 경로 조건을 만든다.
 */

use std::path::PathBuf;
use std::sync::Arc;

use onetdns_config::{BackendKind, BlockResponseKind, Config, EcsMode};
use onetdns_core::{AccessControl, BlockResponse, RateLimiter};
use onetdns_security::{CookieKeeper, IpAcl, KeyedRateLimiter, SubnetRateLimiter};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::BoxResult;
use crate::zone_signing::load_zone_signer;
use crate::{
    authority_sources_configured, build_tsig_keys, config_keys, layers, mac, native,
    read_bytes_limited, tsig_for_secondary, PRODUCT_NAME, WASM_MODULE_MAX_BYTES,
};

/** @brief 클라이언트별로 다르게 답할 뷰들을 만든다. */
pub(crate) fn build_views(cfg: &Config) -> Result<Vec<native::NativeView>, String> {
    cfg.views
        .iter()
        .enumerate()
        .map(|(index, v)| {
            let mut nets = Vec::new();
            let mut ids = Vec::new();
            for c in &v.clients {
                match c.parse::<onetdns_core::IpNet>() {
                    Ok(n) => nets.push(n),
                    Err(_) => ids.push(c.clone()),
                }
            }
            let local_a = v
                .local_a
                .iter()
                .enumerate()
                .map(|(item, (name, ip))| {
                    let name = onetdns_proto::Name::from_str(name.trim()).map_err(|_| {
                        format!("views[{index}].local_a[{item}]의 DNS 이름이 올바르지 않습니다")
                    })?;
                    Ok((name.canonical_key(), *ip))
                })
                .collect::<Result<Vec<_>, String>>()?;
            let local_aaaa = v
                .local_aaaa
                .iter()
                .enumerate()
                .map(|(item, (name, ip))| {
                    let name = onetdns_proto::Name::from_str(name.trim()).map_err(|_| {
                        format!("views[{index}].local_aaaa[{item}]의 DNS 이름이 올바르지 않습니다")
                    })?;
                    Ok((name.canonical_key(), *ip))
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(native::NativeView {
                nets,
                ids,
                local_a,
                local_aaaa,
            })
        })
        .collect()
}

/** @brief 누가 무엇을 고칠 수 있는지 정한 규칙들을 만든다. */
fn build_update_policy(cfg: &Config) -> Result<Vec<native::UpdateRule>, String> {
    cfg.update_policy
        .iter()
        .enumerate()
        .map(|(index, r)| {
            let grant = match r.action.as_str() {
                "grant" => true,
                "deny" => false,
                other => {
                    return Err(format!(
                        "update_policy[{index}].action에 허용되지 않은 값이 있습니다: '{other}'"
                    ));
                }
            };
            let types = r
                .types
                .iter()
                .enumerate()
                .map(|(item, rtype)| {
                    onetdns_config::parse_update_rtype(rtype).ok_or_else(|| {
                        format!(
                            "update_policy[{index}].types[{item}]에 허용되지 않은 DNS 레코드 형식이 있습니다: '{rtype}'"
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            native::UpdateRule::new(
                grant,
                &r.identity,
                &r.name,
                types,
            )
            .ok_or_else(|| format!("update_policy[{index}]의 identity 또는 name이 올바르지 않습니다"))
        })
        .collect()
}

/** @brief 교체할 수 있는 접근 제어. 아무것도 막지 않는지를 값싸게 답한다. */
pub(crate) struct DynamicAccessControl {
    /** @brief 지금 걸린 규칙. */
    inner: std::sync::RwLock<Arc<dyn AccessControl>>,
    /** @brief 아무것도 막지 않는지. 복제 없이 답하려고 따로 둔다. */
    trivially_allow: std::sync::atomic::AtomicBool,
}

impl DynamicAccessControl {
    /** @brief 지금 규칙으로 만든다. */
    pub(crate) fn new(inner: Arc<dyn AccessControl>) -> Self {
        let trivially_allow = inner.is_trivially_allow();
        Self {
            inner: std::sync::RwLock::new(inner),
            trivially_allow: std::sync::atomic::AtomicBool::new(trivially_allow),
        }
    }

    /** @brief 규칙을 교체하고 요약 판정도 함께 맞춘다. */
    pub(crate) fn replace(&self, next: Arc<dyn AccessControl>) {
        let trivially_allow = next.is_trivially_allow();
        if !trivially_allow {
            self.trivially_allow
                .store(false, std::sync::atomic::Ordering::Release);
        }
        *self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = next;
        if trivially_allow {
            self.trivially_allow
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

impl AccessControl for DynamicAccessControl {
    /** @brief 이 클라이언트를 받아 줄지. */
    fn check(&self, client: &onetdns_core::ClientInfo) -> onetdns_core::AclDecision {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .check(client)
    }

    /** @brief 아무것도 막지 않는지. 빠른 경로가 이 판정을 믿고 검사를 건너뛴다. */
    fn is_trivially_allow(&self) -> bool {
        self.trivially_allow
            .load(std::sync::atomic::Ordering::Acquire)
    }
}

/** @brief 교체할 수 있는 속도 제한. */
pub(crate) struct DynamicRateLimiter {
    /** @brief 지금 걸린 제한기들. */
    inner: std::sync::RwLock<Vec<Arc<dyn RateLimiter>>>,
    /** @brief 걸린 제한기 수. 복제 없이 답하려고 따로 둔다. */
    active: std::sync::atomic::AtomicUsize,
}

/**
 * @brief 빠른 경로 조건을 볼 때 설정만으로는 알 수 없는 사실들.
 *
 * @details 셋 다 이번 세대 안에서 바뀔 수 있어서 설정에서 다시 계산할 수 없다. DHCP 임대
 *          풀은 세대가 바뀔 때만 서고, 뷰와 정책은 살아 있는 값을 봐야 한다.
 */
pub(crate) struct LaneFacts {
    /** @brief DHCP 임대 풀이 서 있는지. */
    pub(crate) dhcp_pool: bool,
    /** @brief 클라이언트별로 다르게 답할 뷰가 있는지. */
    pub(crate) views_present: bool,
    /** @brief 정책 규칙이 하나라도 있는지. */
    pub(crate) policy_present: bool,
}

/** @brief 세 빠른 경로 각각을 지금 써도 되는지. */
pub(crate) struct LaneGates {
    /** @brief 캐시 적중 UDP 빠른 경로. */
    pub(crate) wire: bool,
    /** @brief 권한 영역 단순 질의 빠른 경로. */
    pub(crate) authority: bool,
    /** @brief 재귀 콜드미스 리액터 레인. */
    pub(crate) reactor: bool,
}

/**
 * @brief 답한 주소를 커널 주소 집합에 넣는 계층이 이 설정에서 붙는지.
 * @details 집합 이름과 대상 도메인이 함께 있어야 하고, 커널 집합은 Linux에만 있다. 붙지 않는
 *          설정으로 빠른 경로를 끄면 하는 일 없이 느려지기만 한다.
 */
pub(crate) fn ipset_layer_active(cfg: &Config) -> bool {
    cfg!(target_os = "linux")
        && (cfg.ipset_name_v4.is_some() || cfg.ipset_name_v6.is_some())
        && !cfg.ipset_domains.is_empty()
}

/**
 * @brief 지금 설정으로 세 빠른 경로가 적격인지 판정한다.
 *
 * @details 시작할 때와 설정을 교체할 때 모두 이 함수 하나만 부른다. 두 곳에서 따로
 *          판정하면 교체한 뒤 레인이 이전 조건으로 남아 없는 기능처럼 답한다. 어느 키가
 *          경로를 닫는지는 config_keys 의 표가 정하고, 여기서는 경로마다의 전제만 본다.
 * @param cfg    판정할 설정.
 * @param facts  설정만으로 알 수 없는 사실들.
 * @return 세 경로 각각의 적격 여부.
 */
pub(crate) fn evaluate_lane_gates(cfg: &Config, facts: &LaneFacts) -> LaneGates {
    use config_keys::{lane_unblocked, Lane};
    let wire = lane_unblocked(Lane::Wire, cfg, facts);
    let authority =
        authority_sources_configured(cfg) && lane_unblocked(Lane::Authority, cfg, facts);
    let reactor = cfg!(unix) && wire && lane_unblocked(Lane::Reactor, cfg, facts);
    LaneGates {
        wire,
        authority,
        reactor,
    }
}

#[derive(Clone)]
/** @brief 설정을 다시 읽을 때 교체할 것들. */
pub(crate) struct NativeHotState {
    /** @brief 빠른 경로의 체인 세대까지 함께 교체할 핸들러. */
    pub(crate) handler: Arc<native::NativeServer>,
    /** @brief 기능 세트. */
    pub(crate) features: Arc<native::NativeFeatureSwap>,
    /** @brief 정책 엔진. */
    pub(crate) policy: Arc<native::GatedSwap<onetdns_policy::PolicyEngine>>,
    /** @brief 클라이언트별 뷰. */
    pub(crate) views: Arc<native::GatedSwap<Vec<native::NativeView>>>,
    /** @brief 차단 답의 수명. */
    pub(crate) block_ttl: Arc<std::sync::atomic::AtomicU32>,
    /** @brief 고정해 둔 주소의 수명. */
    pub(crate) local_ttl: Arc<std::sync::atomic::AtomicU32>,
    /** @brief 밖에 물어보면 안 되는 이름의 범주. */
    pub(crate) local_only_names: Arc<layers::LocalOnlyNames>,
    /** @brief 설정 세대. 이전 세대가 만든 항목이 들어오지 못하게 한다. */
    pub(crate) wire_epoch: Arc<std::sync::atomic::AtomicUsize>,
    /** @brief 빠른 경로 켜짐 여부. */
    pub(crate) lane_switch: Arc<native::LaneSwitch>,
    /** @brief 권한 영역 설정 세트. */
    pub(crate) authority: Arc<onetdns_core::ArcSwap<native::AuthoritySettings>>,
}

impl DynamicRateLimiter {
    /** @brief 지금 제한기들로 만든다. */
    pub(crate) fn new(inner: Vec<Arc<dyn RateLimiter>>) -> Self {
        let active = inner.len();
        Self {
            inner: std::sync::RwLock::new(inner),
            active: std::sync::atomic::AtomicUsize::new(active),
        }
    }

    /** @brief 제한기들을 교체한다. */
    pub(crate) fn replace(&self, next: Vec<Arc<dyn RateLimiter>>) {
        let active = next.len();
        if active != 0 {
            self.active
                .store(active, std::sync::atomic::Ordering::Release);
        }
        let mut inner = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *inner = next;
        if active == 0 {
            self.active.store(0, std::sync::atomic::Ordering::Release);
        }
    }

    /** @brief 걸린 제한기 수. */
    pub(crate) fn layer_count(&self) -> usize {
        self.active.load(std::sync::atomic::Ordering::Acquire)
    }
}

impl RateLimiter for DynamicRateLimiter {
    /** @brief 이번 질의를 받아 줄지. */
    fn check(&self, client: &onetdns_core::ClientInfo) -> onetdns_core::RateDecision {
        if self.active.load(std::sync::atomic::Ordering::Acquire) == 0 {
            return onetdns_core::RateDecision::Permit;
        }
        let guard = self
            .inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard
            .iter()
            .any(|limiter| limiter.check(client) == onetdns_core::RateDecision::Throttle)
        {
            onetdns_core::RateDecision::Throttle
        } else {
            onetdns_core::RateDecision::Permit
        }
    }

    /** @brief 제한이 걸려 있는지. */
    fn is_active(&self) -> bool {
        self.layer_count() != 0
    }
}

/** @brief 설정대로 접근 제어를 만든다. */
pub(crate) fn runtime_access_control(cfg: &Config) -> Arc<dyn AccessControl> {
    Arc::new(
        IpAcl::new(
            cfg.acl_allow.clone(),
            cfg.acl_deny.clone(),
            cfg.acl_default_allow(),
        )
        .with_ids(cfg.acl_allow_ids.clone(), cfg.acl_deny_ids.clone()),
    )
}

/**
 * @brief 설정대로 권한 영역 설정 세트를 만든다.
 *
 * @details 시작할 때와 교체할 때 모두 이 함수만 부른다. 영역 목록에서 저장 경로와
 *          고칠 수 있는 영역이 함께 나오므로 따로 만들면 서로 어긋난다.
 * @return 키나 규칙이 올바르지 않으면 실패. 그때는 이전 설정을 그대로 둔다.
 */
pub(crate) fn build_authority_settings(cfg: &Config) -> Result<native::AuthoritySettings, String> {
    let tsig_keys = build_tsig_keys(cfg)?;
    let zone_signers = cfg
        .zones
        .iter()
        .filter(|zone| zone.dnssec_sign)
        .map(|zone| {
            let origin = onetdns_proto::Name::from_str(&zone.origin)
                .map_err(|_| format!("DNS 영역 이름이 올바르지 않습니다: {}", zone.origin))?;
            Ok((origin, load_zone_signer(zone)?))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let notify_secondaries = cfg
        .secondary
        .iter()
        .chain(&cfg.catalog)
        .filter_map(|s| {
            Some((
                onetdns_proto::Name::from_str(&s.origin).ok()?,
                s.primary?,
                tsig_for_secondary(&tsig_keys, &s.tsig_key).map(|key| key.name.clone()),
            ))
        })
        .collect();
    let notify_catalog_primaries = cfg
        .catalog
        .iter()
        .filter_map(|catalog| {
            Some((
                catalog.primary?,
                tsig_for_secondary(&tsig_keys, &catalog.tsig_key).map(|key| key.name.clone()),
            ))
        })
        .collect();
    Ok(native::AuthoritySettings {
        xfr_allow: cfg.xfr_allow.clone(),
        tsig_keys,
        xfr_tsig_required: cfg.xfr_tsig_required,
        update_allow: cfg.update_allow.clone(),
        update_policy: build_update_policy(cfg)?,
        update_tsig_required: cfg.update_tsig_required,
        zone_files: cfg
            .zones
            .iter()
            .filter_map(|zone| {
                let file = zone.file.clone()?;
                let origin = onetdns_proto::Name::from_str(&zone.origin).ok()?;
                Some((origin, file))
            })
            .collect(),
        update_zones: cfg
            .zones
            .iter()
            .filter_map(|zone| onetdns_proto::Name::from_str(&zone.origin).ok())
            .collect(),
        notify_secondaries,
        notify_catalog_primaries,
        zone_signers,
    })
}

/**
 * @brief 이 설정이 재귀를 제공한다고 알릴지.
 *
 * @details 체인을 다시 만들 때마다 그때 설정으로 다시 본다. 처리 방식이나 업스트림 서버가
 *          바뀌면 답의 RA 비트도 함께 바뀌어야 한다.
 */
pub(crate) fn recursion_offered_by(cfg: &Config) -> bool {
    cfg.backend != BackendKind::Forward
        || !cfg.upstreams.is_empty()
        || !cfg.upstream_urls.is_empty()
}

/** @brief 설정대로 속도 제한을 만든다. */
pub(crate) fn runtime_rate_limiters(cfg: &Config) -> Vec<Arc<dyn RateLimiter>> {
    let mut rate_limiters: Vec<Arc<dyn RateLimiter>> = Vec::new();
    if let Some(srl) = SubnetRateLimiter::new(cfg.subnet_rrl_per_sec, cfg.subnet_rrl_burst, 24, 56)
        .map(|r| r.with_allow(cfg.rate_limit_allow.clone()))
    {
        rate_limiters.push(Arc::new(srl));
    }
    if let Some(rl) = KeyedRateLimiter::new(cfg.rate_limit_per_sec, cfg.rate_limit_burst)
        .map(|r| r.with_allow(cfg.rate_limit_allow.clone()))
    {
        rate_limiters.push(Arc::new(rl));
    }
    rate_limiters
}

/** @brief 설정대로 정책 엔진을 만든다. */
pub(crate) fn build_policy_engine(cfg: &Config) -> Result<onetdns_policy::PolicyEngine, String> {
    use onetdns_policy::{Action, Rule, RuleEngine, WasmPolicy};
    let mut rules = Vec::new();
    for (index, p) in cfg.policy.iter().enumerate() {
        let action = match p.action.as_str() {
            "block" => Action::Block,
            "allow" => Action::Allow,
            "refuse" => Action::Refuse,
            "rewrite" => match p.rewrite.as_ref().and_then(|s| s.parse().ok()) {
                Some(ip) => Action::Rewrite(ip),
                None => {
                    return Err(format!(
                        "policy[{index}].rewrite에는 올바른 IPv4 주소가 필요합니다"
                    ));
                }
            },
            other => {
                return Err(format!(
                    "policy[{index}].action에 허용되지 않은 값이 있습니다: '{other}'"
                ));
            }
        };
        let mut rule = Rule::new(action)
            .with_clients(&p.clients)
            .with_suffixes(&p.suffixes)
            .with_qtypes(&qtype_numbers(&p.qtypes));
        if !p.days.is_empty() || p.start.is_some() || p.end.is_some() {
            let window = parse_time_window(&p.days, &p.start, &p.end).ok_or_else(|| {
                format!("policy[{index}]의 요일 또는 시간 범위가 올바르지 않습니다")
            })?;
            rule = rule.with_window(window);
        }
        rules.push(rule);
    }

    let mut plugins = Vec::new();
    let global_mode = onetdns_policy::FailureMode::parse(&cfg.wasm_fail_mode)
        .map_err(|error| error.to_string())?;
    let mut specs: Vec<(
        std::path::PathBuf,
        Option<String>,
        onetdns_policy::FailureMode,
    )> = cfg
        .wasm_policy
        .iter()
        .map(|p| (p.clone(), None, global_mode))
        .collect();
    for plugin in &cfg.wasm_plugins {
        let mode = match &plugin.fail_mode {
            Some(mode) => onetdns_policy::FailureMode::parse(mode).map_err(|e| e.to_string())?,
            None => global_mode,
        };
        specs.push((plugin.path.clone(), plugin.name.clone(), mode));
    }
    for (path, name, fail_mode) in specs {
        match read_bytes_limited(&path, WASM_MODULE_MAX_BYTES) {
            Ok(bytes) => match WasmPolicy::from_wasm(&bytes) {
                Ok(w) => {
                    let name = name.unwrap_or_else(|| {
                        path.file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("wasm")
                            .to_string()
                    });
                    onetdns_core::info!(event = "policy.wasm_loaded", path = %path.display(), fail_mode = ?fail_mode, "WASM 정책 플러그인을 불러왔습니다");
                    plugins.push(w.with_name(name).with_failure_mode(fail_mode));
                }
                Err(e) => {
                    let error = format!("WASM 정책을 준비하지 못했습니다({}): {e}", path.display());
                    if fail_mode != onetdns_policy::FailureMode::Open {
                        return Err(error);
                    }
                    onetdns_core::error!(event = "policy.wasm_skipped", error = %error, "WASM 정책을 적용하지 않았습니다")
                }
            },
            Err(e) => {
                let error = format!("WASM 정책 파일을 읽지 못했습니다({}): {e}", path.display());
                if fail_mode != onetdns_policy::FailureMode::Open {
                    return Err(error);
                }
                onetdns_core::error!(event = "policy.wasm_skipped", error = %error, "WASM 정책을 적용하지 않았습니다")
            }
        }
    }
    Ok(onetdns_policy::PolicyEngine::new(
        RuleEngine::new(rules),
        plugins,
    ))
}

/** @brief 대시보드가 쓰는 항목 식별자. 목록 순서가 바뀌어도 그대로다. */
pub(crate) fn stable_resource_id(namespace: &str, value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(namespace.as_bytes());
    digest.update([0]);
    digest.update(value.as_bytes());
    let digest = digest.finalize();
    let short = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{namespace}-{short}")
}

/** @brief 로그에 원문을 담지 않으면서 프로세스 안에서 비밀 자원을 구분하는 식별자. */
pub(crate) fn private_resource_id(namespace: &str, value: &str) -> String {
    /** @brief 사전 대입으로 약한 비밀번호를 지문과 대조하지 못하게 하는 프로세스 키. */
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    let mut digest = Sha256::new();
    digest.update(KEY.get_or_init(onetdns_core::random_array::<32>));
    digest.update((namespace.len() as u64).to_le_bytes());
    digest.update(namespace.as_bytes());
    digest.update((value.len() as u64).to_le_bytes());
    digest.update(value.as_bytes());
    let digest = digest.finalize();
    let short = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{namespace}-{short}")
}

/**
 * @brief 질의 종류 이름들을 번호로.
 *
 * @details 약칭은 RecordType::name 이 내는 것을 모두 받는다. 빠진 약칭은 걸러지고,
 *          호출자는 대개 A 로 되돌리므로 물어본 것과 다른 종류를 답하게 된다.
 *          약칭이 없는 종류는 RFC 3597 의 TYPE 표기로 적는다.
 */
pub(crate) fn qtype_numbers(names: &[String]) -> Vec<u16> {
    names
        .iter()
        .filter_map(|s| {
            let u = s.trim().to_ascii_uppercase();
            match u.as_str() {
                "A" => Some(1),
                "NS" => Some(2),
                "CNAME" => Some(5),
                "SOA" => Some(6),
                "PTR" => Some(12),
                "MX" => Some(15),
                "TXT" => Some(16),
                "AAAA" => Some(28),
                "SRV" => Some(33),
                "NAPTR" => Some(35),
                "DNAME" => Some(39),
                "OPT" => Some(41),
                "DS" => Some(43),
                "RRSIG" => Some(46),
                "NSEC" => Some(47),
                "DNSKEY" => Some(48),
                "NSEC3" => Some(50),
                "CDS" => Some(59),
                "CDNSKEY" => Some(60),
                "SVCB" => Some(64),
                "HTTPS" => Some(65),
                "CAA" => Some(257),
                "ANY" => Some(255),
                _ => u.strip_prefix("TYPE").unwrap_or(&u).parse::<u16>().ok(),
            }
        })
        .collect()
}

/** @brief 시간대 설정을 읽는다. */
fn parse_time_window(
    days: &[String],
    start: &Option<String>,
    end: &Option<String>,
) -> Option<onetdns_policy::TimeWindow> {
    if days.is_empty() && start.is_none() && end.is_none() {
        return None;
    }
    let mut mask = 0u8;
    if days.is_empty() {
        mask = 0x7f;
    } else {
        for d in days {
            let wd = match d.as_str() {
                "sun" => 0,
                "mon" => 1,
                "tue" => 2,
                "wed" => 3,
                "thu" => 4,
                "fri" => 5,
                "sat" => 6,
                _ => return None,
            };
            mask |= 1u8 << wd;
        }
    }
    let to_min = |s: &str| -> Option<u16> {
        let (hour, minute) = s.split_once(':')?;
        let hour = hour.parse::<u16>().ok()?;
        let minute = minute.parse::<u16>().ok()?;
        (hour < 24 && minute < 60).then_some(hour * 60 + minute)
    };
    let (start_min, end_min) = match (start.as_deref(), end.as_deref()) {
        (None, None) => (0, 1440),
        (Some(start), Some(end)) => {
            let start = to_min(start)?;
            let end = to_min(end)?;
            if start == end {
                return None;
            }
            (start, end)
        }
        _ => return None,
    };
    Some(onetdns_policy::TimeWindow {
        days: mask,
        start_min,
        end_min,
    })
}

/**
 * @brief 모은 통계와 질의 기록을 볼 수 있는 곳이 있는지.
 *
 * @details 관리 수신 주소가 있으면 대시보드와 REST가, 저장 파일이 있으면 그 파일이 본다.
 *          셋 다 없으면 질의마다 만드는 이벤트는 만들어지자마자 버려진다.
 * @return 볼 곳이 하나라도 있으면 참.
 */
pub(crate) fn telemetry_consumed(cfg: &Config) -> bool {
    let has_file = |path: &Option<PathBuf>| {
        path.as_ref()
            .is_some_and(|path| !path.as_os_str().is_empty())
    };
    cfg.control_listen.is_some() || has_file(&cfg.stats_file) || has_file(&cfg.querylog_file)
}

/** @brief 설정에서 DNS Cookie 정책과 서버 비밀을 만든다. */
fn build_cookie_policy(cfg: &Config) -> native::CookiePolicy {
    if !cfg.cookies.is_enabled() {
        return native::CookiePolicy::default();
    }

    let keeper = if cfg.cluster_raft && cfg.cluster_raft_secret.len() >= 32 {
        // Raft 인증과 쿠키가 같은 원시 키를 직접 공유하지 않도록 문맥을 붙여 별도 루트를
        // 만든다. 같은 클러스터 비밀을 가진 노드는 같은 루트와 epoch 키를 얻게 된다.
        let mut digest = Sha256::new();
        digest.update(b"OnetDNS DNS Cookie cluster master v1\0");
        digest.update(cfg.cluster_raft_secret.as_bytes());
        let digest = Zeroizing::new(<[u8; 32]>::from(digest.finalize()));
        let mut master = Zeroizing::new([0u8; 16]);
        master.copy_from_slice(&digest[..16]);
        CookieKeeper::from_master_secret(&master)
    } else {
        CookieKeeper::random()
    };

    native::CookiePolicy {
        keeper: Some(Arc::new(keeper)),
        strict: cfg.cookies.is_strict(),
    }
}

/** @brief 설정대로 기능 세트를 만든다. */
pub(crate) fn build_native_features(
    cfg: &Config,
    dns64_prefix: Option<[u8; 16]>,
    safe_search: Arc<std::sync::atomic::AtomicBool>,
    recorder: Option<onetdns_control::Recorder>,
    mac_cache: Option<Arc<mac::NeighborCache>>,
) -> Result<native::NativeFeatures, String> {
    let cookies = build_cookie_policy(cfg);
    Ok(native::NativeFeatures {
        block_aaaa: cfg.block_aaaa,
        dns64_prefix,
        dns64_synthall: cfg.dns64_synthall,
        rebind_protection: cfg.rebind_protection,
        rebind_allow: cfg
            .rebind_allow
            .iter()
            .filter_map(|s| {
                onetdns_proto::Name::from_str(
                    s.trim().trim_start_matches("*.").trim_end_matches('.'),
                )
                .ok()
            })
            .collect(),
        bogus_nxdomain: cfg.bogus_nxdomain.clone(),
        recurse_deny_answers: cfg.recurse_deny_answers.clone(),
        recurse_allow_answers: cfg.recurse_allow_answers.clone(),
        rrset_roundrobin: cfg.rrset_roundrobin,
        rotor: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        safe_search,
        nsid: cfg.nsid.as_ref().map(|s| s.clone().into_bytes()),
        cookies,
        recorder,
        mac_cache,
        inflight_max: cfg.max_inflight,
        inflight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        dnstap: build_dnstap(cfg)?,
        edns_buffer: cfg.edns_buffer_size,
        hide_identity: cfg.hide_identity,
        hide_version: cfg.hide_version,
        server_identity: cfg
            .identity
            .clone()
            .or_else(|| cfg.nsid.clone())
            .unwrap_or_else(|| PRODUCT_NAME.to_string())
            .into_bytes(),
        server_version: cfg
            .version
            .clone()
            .unwrap_or_else(|| PRODUCT_NAME.to_string())
            .into_bytes(),
        allow_any: !cfg.deny_any,
        minimal_responses: cfg.minimal_responses,
        padding_block: cfg.edns_padding_block,
        tcp_keepalive_100ms: (cfg.edns_tcp_keepalive_secs > 0)
            .then(|| (cfg.edns_tcp_keepalive_secs.saturating_mul(10)).min(65535) as u16),
        ecs_in_use: cfg.ecs_mode == EcsMode::Send && cfg.ecs_custom_ip.is_some(),
        harden_large_queries: cfg.harden_large_queries,
        domain_needed: cfg.domain_needed,
        bogus_priv: cfg.bogus_priv,
        empty_zones: cfg.empty_zones,
        ddr_enabled: !cfg.ddr_name.is_empty(),
        lane_runtime: None,
    })
}

/** @brief 기능 세트를 교체한다. */
pub(crate) fn reconfigure_native_features(
    current: &native::NativeFeatures,
    cfg: &Config,
    changed: &[String],
) -> Result<native::NativeFeatures, String> {
    let mut next = current.clone();
    next.block_aaaa = cfg.block_aaaa;
    next.dns64_prefix = cfg.dns64_prefix.as_ref().and_then(|prefix| {
        let ip_part = prefix.split('/').next()?;
        let mut octets = ip_part.parse::<std::net::Ipv6Addr>().ok()?.octets();
        octets[12..16].fill(0);
        Some(octets)
    });
    next.dns64_synthall = cfg.dns64_synthall;
    next.rebind_protection = cfg.rebind_protection;
    next.rebind_allow = cfg
        .rebind_allow
        .iter()
        .filter_map(|name| {
            onetdns_proto::Name::from_str(
                name.trim().trim_start_matches("*.").trim_end_matches('.'),
            )
            .ok()
        })
        .collect();
    next.bogus_nxdomain = cfg.bogus_nxdomain.clone();
    next.recurse_deny_answers = cfg.recurse_deny_answers.clone();
    next.recurse_allow_answers = cfg.recurse_allow_answers.clone();
    next.rrset_roundrobin = cfg.rrset_roundrobin;

    next.nsid = cfg.nsid.as_ref().map(|value| value.clone().into_bytes());
    if changed.iter().any(|key| {
        matches!(
            key.as_str(),
            "cookies" | "cluster_raft" | "cluster_raft_secret"
        )
    }) {
        next.cookies = build_cookie_policy(cfg);
    }
    next.inflight_max = cfg.max_inflight;
    if changed
        .iter()
        .any(|key| matches!(key.as_str(), "dnstap_file" | "dnstap_identity"))
    {
        next.dnstap = match (current.dnstap.as_ref(), cfg.dnstap_file.as_ref()) {
            (Some(open), Some(path)) if open.path() == path.as_path() => {
                Some(Arc::new(open.with_identity(dnstap_identity(cfg))))
            }
            _ => build_dnstap(cfg)?,
        };
    }
    next.edns_buffer = cfg.edns_buffer_size;
    next.hide_identity = cfg.hide_identity;
    next.hide_version = cfg.hide_version;
    next.server_identity = cfg
        .identity
        .clone()
        .or_else(|| cfg.nsid.clone())
        .unwrap_or_else(|| PRODUCT_NAME.to_string())
        .into_bytes();
    next.server_version = cfg
        .version
        .clone()
        .unwrap_or_else(|| PRODUCT_NAME.to_string())
        .into_bytes();
    next.allow_any = !cfg.deny_any;
    next.minimal_responses = cfg.minimal_responses;
    next.padding_block = cfg.edns_padding_block;
    next.tcp_keepalive_100ms = (cfg.edns_tcp_keepalive_secs > 0)
        .then(|| (cfg.edns_tcp_keepalive_secs.saturating_mul(10)).min(65535) as u16);
    next.ecs_in_use = cfg.ecs_mode == EcsMode::Send && cfg.ecs_custom_ip.is_some();
    next.harden_large_queries = cfg.harden_large_queries;
    next.domain_needed = cfg.domain_needed;
    next.bogus_priv = cfg.bogus_priv;
    next.empty_zones = cfg.empty_zones;
    Ok(next)
}

/** @brief dnstap 기록에 적을 서버 이름. 따로 정하지 않으면 제품 이름이다. */
fn dnstap_identity(cfg: &Config) -> &str {
    if cfg.dnstap_identity.is_empty() {
        PRODUCT_NAME
    } else {
        &cfg.dnstap_identity
    }
}

/** @brief 질의 기록 파일을 연다. 열지 못하면 조용히 끄지 않고 실패로 알린다. */
fn build_dnstap(cfg: &Config) -> Result<Option<Arc<onetdns_control::DnstapWriter>>, String> {
    let Some(path) = cfg.dnstap_file.as_ref() else {
        return Ok(None);
    };
    let writer =
        onetdns_control::DnstapWriter::create(path, dnstap_identity(cfg)).map_err(|error| {
            format!(
                "dnstap 출력 파일을 열지 못했습니다({}): {error}",
                path.display()
            )
        })?;
    onetdns_core::info!(event = "dnstap.started", path = %path.display(), "질의 기록을 dnstap으로 내보냅니다");
    Ok(Some(Arc::new(writer)))
}

/** @brief 요일 이름들을 비트로. */
pub(crate) fn days_mask(days: &[String]) -> u8 {
    let mut m = 0u8;
    for d in days {
        let bit = match d.as_str() {
            "sun" => 0,
            "mon" => 1,
            "tue" => 2,
            "wed" => 3,
            "thu" => 4,
            "fri" => 5,
            "sat" => 6,
            "all" => {
                m = 0x7f;
                continue;
            }
            _ => return 0,
        };
        m |= 1 << bit;
    }
    m
}

/** @brief 시각 문자열을 분으로. */
pub(crate) fn parse_hhmm(s: &str) -> Option<u32> {
    let (h, m) = s.split_once(':')?;
    let h: u32 = h.trim().parse().ok()?;
    let m: u32 = m.trim().parse().ok()?;
    (h < 24 && m < 60).then_some(h * 60 + m)
}

/** @brief 설정한 차단 방식. */
pub(crate) fn map_block(cfg: &Config) -> BlockResponse {
    match cfg.block_response {
        BlockResponseKind::Nxdomain => BlockResponse::NxDomain,
        BlockResponseKind::ZeroIp => BlockResponse::ZeroIp,
        BlockResponseKind::Refused => BlockResponse::Refused,
        BlockResponseKind::Custom => BlockResponse::Custom {
            v4: cfg.block_ipv4,
            v6: cfg.block_ipv6,
        },
    }
}

/** @brief 질의 종류 이름을 읽는다. */
pub(crate) fn parse_qtype(s: Option<&str>) -> BoxResult<onetdns_proto::RecordType> {
    use onetdns_proto::RecordType as Rt;
    let t = match s {
        None => return Ok(Rt::A),
        Some(t) => t.to_uppercase(),
    };
    Ok(match t.as_str() {
        "A" => Rt::A,
        "AAAA" => Rt::AAAA,
        "CNAME" => Rt::CNAME,
        "DNAME" => Rt::DNAME,
        "MX" => Rt::MX,
        "TXT" => Rt::TXT,
        "NS" => Rt::NS,
        "SOA" => Rt::SOA,
        "PTR" => Rt::PTR,
        "SRV" => Rt::SRV,
        "CAA" => Rt::CAA,
        other => crate::bail!("지원하지 않는 DNS 레코드 유형입니다: {other}"),
    })
}

#[cfg(test)]
/** @brief 정책, 접근 제어, 빠른 경로 조건 구성. */
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    use onetdns_config::{BackendKind, Config, CookieMode, EcsMode};
    use onetdns_core::RateLimiter;
    use onetdns_security::IpAcl;

    use crate::config_keys::ApplyGroup;
    use crate::{config_keys, native};

    #[test]
    /**
     * @brief 화면에 내는 종류 약칭을 그대로 다시 읽어 같은 번호가 되는지.
     * @details 두 테이블이 어긋나면 물어본 종류가 조용히 걸러지고 호출자가 A 로 되돌린다.
     *          CAA 를 물었는데 A 를 설명하는 응답이 나가도 오류 하나 남지 않는다.
     */
    fn every_displayed_qtype_name_parses_back_to_its_own_number() {
        for number in 0u16..=u16::MAX {
            let rtype = onetdns_proto::RecordType(number);
            if rtype.name() == "UNKNOWN" {
                continue;
            }
            assert_eq!(
                qtype_numbers(&[rtype.name().to_string()]),
                vec![number],
                "{} 약칭이 자기 번호로 읽히지 않습니다",
                rtype.name()
            );
        }
        assert_eq!(qtype_numbers(&["TYPE99".to_string()]), vec![99]);
        assert_eq!(qtype_numbers(&["caa".to_string()]), vec![257]);
        assert!(qtype_numbers(&["NOSUCHTYPE".to_string()]).is_empty());
    }

    #[test]
    /**
     * @brief 설정에 적은 요일 이름이 지역 시각으로 바꾼 요일과 같은 위치를 가리키는지.
     * @details 비트를 정하는 곳과 그 비트를 읽는 위치가 갈라져 있어, 한쪽만 바꾸면 모든
     *          시간대 규칙이 하루씩 어긋난 채로도 각 단위 테스트는 그대로 통과한다.
     */
    fn policy_time_window_day_names_match_the_local_weekday_fold() {
        let window = parse_time_window(
            &["fri".to_string()],
            &Some("22:00".to_string()),
            &Some("02:00".to_string()),
        )
        .expect("금요일 밤 구간을 읽지 못했습니다");
        let engine = onetdns_policy::RuleEngine::new(vec![onetdns_policy::Rule::new(
            onetdns_policy::Action::Block,
        )
        .with_window(window)]);
        let at = |minute_of_week: u32| onetdns_policy::PolicyInput {
            client: "192.0.2.1".parse().unwrap(),
            qname: "x.example",
            qtype: 1,
            unix_time: 0,
            local_minute_of_week: minute_of_week,
            transport: onetdns_policy::QueryTransport::Do53Udp,
            client_id: None,
            authenticated: false,
        };
        const THURSDAY: u32 = 4 * 1_440;
        const FRIDAY: u32 = 5 * 1_440;
        const SATURDAY: u32 = 6 * 1_440;

        assert_eq!(
            engine.evaluate(&at(FRIDAY + 23 * 60)),
            onetdns_policy::Action::Block,
            "금요일 23시가 금요일 밤 구간에 들어가지 않음"
        );

        assert_eq!(
            engine.evaluate(&at(SATURDAY + 60)),
            onetdns_policy::Action::Block,
            "자정을 넘긴 토요일 1시가 전날 구간에 들어가지 않음"
        );

        assert_eq!(
            engine.evaluate(&at(THURSDAY + 23 * 60)),
            onetdns_policy::Action::Continue,
            "목요일 23시가 금요일 구간에 걸림"
        );
    }

    #[test]
    /** @brief 서비스 시간표와 정책 규칙이 같은 요일 이름을 같은 비트로 옮기는지. */
    fn schedule_and_policy_day_masks_agree() {
        for (index, name) in ["sun", "mon", "tue", "wed", "thu", "fri", "sat"]
            .iter()
            .enumerate()
        {
            let schedule = days_mask(std::slice::from_ref(&(*name).to_string()));
            let policy = parse_time_window(
                std::slice::from_ref(&(*name).to_string()),
                &Some("09:00".to_string()),
                &Some("18:00".to_string()),
            )
            .expect("요일 하나짜리 구간을 읽지 못했습니다")
            .days;
            assert_eq!(
                schedule,
                1u8 << index,
                "{name}의 서비스 시간표 비트가 다릅니다"
            );
            assert_eq!(
                policy, schedule,
                "{name}의 정책 규칙 비트가 서비스 시간표와 다릅니다"
            );
        }
    }

    #[test]
    /** @brief 잘못된 업데이트 정책 규칙이 조용히 사라지지 않는지. 사라지면 운영자는 걸린 줄 안다. */
    fn invalid_update_policy_name_cannot_disappear_silently() {
        let mut cfg = Config::default();
        cfg.update_policy.push(onetdns_config::UpdatePolicyRule {
            action: "grant".to_string(),
            identity: "bad..identity".to_string(),
            name: "*".to_string(),
            types: vec!["A".to_string()],
        });
        assert!(build_update_policy(&cfg).is_err());
    }

    #[test]
    /** @brief 잘못된 정책 규칙이 건너뛰어지거나 더 넓게 해석되지 않는지. */
    fn invalid_policy_rule_cannot_be_skipped_or_broadened() {
        let mut cfg = Config::default();
        cfg.policy.push(onetdns_config::PolicyRule {
            action: "blokc".to_string(),
            ..Default::default()
        });
        assert!(build_policy_engine(&cfg).is_err());

        cfg.policy[0] = onetdns_config::PolicyRule {
            action: "block".to_string(),
            days: vec!["bogus".to_string()],
            start: Some("08:00".to_string()),
            end: Some("09:00".to_string()),
            ..Default::default()
        };
        assert!(build_policy_engine(&cfg).is_err());
    }

    #[test]
    /** @brief 잘못된 배치 기록이 조용히 사라지지 않는지. */
    fn invalid_view_record_name_cannot_disappear_silently() {
        let mut cfg = Config::default();
        cfg.views.push(onetdns_config::ViewConfig {
            name: "office".to_string(),
            clients: vec!["192.0.2.0/24".to_string()],
            local_a: vec![("bad..name".to_string(), "192.0.2.1".parse().unwrap())],
            local_aaaa: vec![],
        });
        assert!(build_views(&cfg).is_err());
    }

    /** @brief 언제나 막는 테스트용 제한기. */
    struct AlwaysThrottle;

    impl RateLimiter for AlwaysThrottle {
        /** @brief 언제나 막는다. */
        fn check(&self, _client: &onetdns_core::ClientInfo) -> onetdns_core::RateDecision {
            onetdns_core::RateDecision::Throttle
        }
    }

    #[test]
    /** @brief 접근 제어를 교체하면 아무것도 막지 않는지 판정도 함께 바뀌는지. */
    fn dynamic_acl_trivial_gate_tracks_hot_reload() {
        let acl = DynamicAccessControl::new(Arc::new(IpAcl::allow_all()));
        let client = onetdns_core::ClientInfo {
            source_ip: "192.0.2.1".parse().unwrap(),
            client_id: None,
            transport: onetdns_core::Transport::Do53Udp,
            authenticated: false,
        };

        assert!(acl.is_trivially_allow());
        assert_eq!(acl.check(&client), onetdns_core::AclDecision::Allow);

        acl.replace(Arc::new(IpAcl::new(vec![], vec![], false)));
        assert!(!acl.is_trivially_allow());
        assert_eq!(acl.check(&client), onetdns_core::AclDecision::Deny);

        acl.replace(Arc::new(IpAcl::allow_all()));
        assert!(acl.is_trivially_allow());
        assert_eq!(acl.check(&client), onetdns_core::AclDecision::Allow);
    }

    #[test]
    /** @brief 제한기를 교체하면 걸렸는지 판정도 함께 바뀌는지. */
    fn dynamic_rate_limiter_tracks_empty_hot_reload() {
        let limiter = DynamicRateLimiter::new(vec![]);
        let client = onetdns_core::ClientInfo {
            source_ip: "192.0.2.1".parse().unwrap(),
            client_id: None,
            transport: onetdns_core::Transport::Do53Udp,
            authenticated: false,
        };

        assert_eq!(limiter.layer_count(), 0);
        assert!(!limiter.is_active());
        assert_eq!(limiter.check(&client), onetdns_core::RateDecision::Permit);

        limiter.replace(vec![Arc::new(AlwaysThrottle)]);
        assert_eq!(limiter.layer_count(), 1);
        assert!(limiter.is_active());
        assert_eq!(limiter.check(&client), onetdns_core::RateDecision::Throttle);

        limiter.replace(vec![]);
        assert_eq!(limiter.layer_count(), 0);
        assert!(!limiter.is_active());
        assert_eq!(limiter.check(&client), onetdns_core::RateDecision::Permit);
    }

    #[test]
    /** @brief 목록 순서가 바뀌어도 식별자가 그대로인지. */
    fn stable_resource_ids_do_not_depend_on_array_position() {
        let a1 = stable_resource_id("upstream", "https://dns.example/dns-query");
        let a2 = stable_resource_id("upstream", "https://dns.example/dns-query");
        let b = stable_resource_id("upstream", "1.1.1.1");
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
        assert!(a1.starts_with("upstream-"));
    }

    #[test]
    /** @brief 정책 플러그인을 못 올렸을 때 그냥 통과시키지 않는지. */
    fn closed_wasm_policy_rejects_load_failures() {
        let missing = std::env::temp_dir().join(format!(
            "onetdns-missing-policy-{}-{}.wasm",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut config = Config {
            wasm_policy: Some(missing),
            wasm_fail_mode: "closed-refuse".to_string(),
            ..Config::default()
        };
        assert!(build_policy_engine(&config).is_err());

        config.wasm_fail_mode = "open".to_string();
        let engine = build_policy_engine(&config).expect("open 모드는 로드 실패를 허용");
        assert!(engine.is_empty());
    }

    #[test]
    /**
     * @brief 질의마다 읽는 기능 값이 체인 재구성으로 가로채이지 않는지.
     * @details 분류는 체인 목록을 먼저 본다. 체인 목록에도 있으면 기능 세트가 갱신되지 않아
     *          무중단 변경이 저장만 되고 적용되지 않는다.
     */
    fn native_feature_keys_reach_the_native_group() {
        let previous = Config::default();
        for (key, next) in [
            (
                "deny_any",
                Config {
                    deny_any: !previous.deny_any,
                    ..Config::default()
                },
            ),
            (
                "minimal_responses",
                Config {
                    minimal_responses: !previous.minimal_responses,
                    ..Config::default()
                },
            ),
        ] {
            assert_eq!(
                config_keys::hot_group(key),
                Some(ApplyGroup::Native),
                "{key}"
            );
            let features = reconfigure_native_features(
                &native::NativeFeatures::default(),
                &next,
                &[key.to_string()],
            )
            .unwrap();
            assert!(
                features.allow_any != next.deny_any
                    && features.minimal_responses == next.minimal_responses,
                "{key}"
            );
        }
    }

    #[test]
    /** @brief 플러그인마다 정한 실패 처분이 전체 설정을 이기는지. */
    fn per_plugin_fail_mode_overrides_global() {
        let missing = std::env::temp_dir().join(format!(
            "onetdns-missing-plugin-{}-{}.wasm",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut config = Config {
            wasm_fail_mode: "closed-refuse".to_string(),
            ..Config::default()
        };
        config.wasm_plugins = vec![onetdns_config::WasmPluginConfig {
            path: missing,
            name: None,
            fail_mode: Some("open".to_string()),
        }];
        build_policy_engine(&config).expect("항목별 open이 전역 closed보다 우선");

        config.wasm_plugins[0].fail_mode = None;
        assert!(
            build_policy_engine(&config).is_err(),
            "항목별 미지정 시 전역 closed 적용"
        );
    }

    #[test]
    /**
     * @brief 통계를 볼 수 있는 곳을 빠짐없이 세는지.
     *
     * @details 하나라도 빠뜨리면 그 설정을 쓰는 사람은 대시보드나 저장 파일이 비는 것을
     *          보게 되고, 거꾸로 넓게 잡으면 헤드리스 배포가 아무도 읽지 않는 통계에
     *          해석당 CPU의 4분의 1을 낸다.
     */
    fn telemetry_is_collected_only_where_something_reads_it() {
        let mut cfg = Config::default();
        cfg.control_listen = None;
        cfg.stats_file = None;
        cfg.querylog_file = None;
        assert!(
            !telemetry_consumed(&cfg),
            "볼 곳이 하나도 없는데 모으기로 했습니다"
        );

        cfg.control_listen = Some("127.0.0.1:8553".parse().unwrap());
        assert!(
            telemetry_consumed(&cfg),
            "관리 수신 주소가 있으면 모아야 합니다"
        );
        cfg.control_listen = None;

        cfg.stats_file = Some(PathBuf::from("/var/lib/onetdns/stats.json"));
        assert!(
            telemetry_consumed(&cfg),
            "통계 저장 파일이 있으면 모아야 합니다"
        );
        cfg.stats_file = None;

        cfg.querylog_file = Some(PathBuf::from("/var/lib/onetdns/querylog.jsonl"));
        assert!(
            telemetry_consumed(&cfg),
            "질의 기록 파일이 있으면 모아야 합니다"
        );

        // 빈 경로는 끈 것이다. 설정 파일에 키만 남기고 값을 지운 경우가 실제로 있다.
        cfg.querylog_file = Some(PathBuf::new());
        assert!(
            !telemetry_consumed(&cfg),
            "빈 경로를 저장 파일이 있는 것으로 셌습니다"
        );
    }

    #[test]
    /**
     * @brief 무중단으로 바뀌는 설정이 빠른 경로 조건을 깨면 그 경로가 닫히는지.
     *
     * @details 빠른 경로는 지어질 때의 설정을 전제로 답한다. 조건을 깨는 설정을 무중단으로
     *          받아 놓고 경로를 열어 두면 캐시를 껐는데 이전 답이 나가고, 켠 기능이 없는 것
     *          처럼 답한다. 여기서 걸리면 그 설정을 무중단 목록에서 빼거나 조건에 넣어야
     *          한다.
     */
    fn hot_settings_that_break_a_lane_close_that_lane() {
        let facts = LaneFacts {
            dhcp_pool: true,
            views_present: false,
            policy_present: false,
        };
        let base = {
            let mut cfg = Config::default();
            cfg.cache_enabled = true;
            cfg.cache_size = 1000;
            cfg.min_ttl = 0;
            cfg.dhcp_local_domain = String::new();
            cfg
        };
        assert!(
            evaluate_lane_gates(&base, &facts).wire,
            "기본 설정에서 빠른 경로가 열려 있어야 이 테스트가 뜻을 가집니다"
        );

        let breakers: Vec<(&str, fn(&mut Config))> = vec![
            ("cache_enabled", |c| c.cache_enabled = false),
            ("cache_size", |c| c.cache_size = 0),
            ("min_ttl", |c| c.min_ttl = 60),
            ("prefetch", |c| c.prefetch = true),
            ("ecs_mode", |c| c.ecs_mode = EcsMode::Strip),
            ("dns64_prefix", |c| {
                c.dns64_prefix = Some("64:ff9b::/96".to_string())
            }),
            ("rrset_roundrobin", |c| c.rrset_roundrobin = true),
            ("dhcp_local_domain", |c| {
                c.dhcp_local_domain = "lan".to_string()
            }),
            ("name_ratelimit_per_sec", |c| c.name_ratelimit_per_sec = 10),
            ("block_aaaa", |c| c.block_aaaa = true),
            ("domain_needed", |c| c.domain_needed = true),
            ("bogus_priv", |c| c.bogus_priv = true),
            ("empty_zones", |c| c.empty_zones = true),
            ("edns_padding_block", |c| c.edns_padding_block = 128),
            ("cookies", |c| c.cookies = CookieMode::Strict),
            ("dnstap_file", |c| {
                c.dnstap_file = Some(std::path::PathBuf::from("dnstap.log"))
            }),
            ("acme_directory_url", |c| {
                c.acme_directory_url = Some("https://acme.test/dir".to_string())
            }),
            ("dynamic_records", |c| {
                c.dynamic_records.push(onetdns_config::DynamicRecord {
                    name: "www.example.test".to_string(),
                    ..Default::default()
                })
            }),
            ("secondary", |c| {
                c.secondary.push(onetdns_config::SecondaryZone {
                    origin: "slave.test".to_string(),
                    ..Default::default()
                })
            }),
            ("catalog", |c| {
                c.catalog.push(onetdns_config::SecondaryZone {
                    origin: "catalog.test".to_string(),
                    ..Default::default()
                })
            }),
            ("clients", |c| {
                c.clients.push(onetdns_config::ClientConfig {
                    name: "kid".to_string(),
                    upstreams: vec!["9.9.9.9".parse().unwrap()],
                    ..Default::default()
                })
            }),
        ];
        for (key, break_it) in breakers {
            assert!(
                config_keys::is_hot(key),
                "{key}가 무중단 목록에서 빠졌습니다. 테스트를 함께 고치십시오"
            );
            let mut cfg = base.clone();
            break_it(&mut cfg);
            assert!(
                !evaluate_lane_gates(&cfg, &facts).wire,
                "{key}를 무중단으로 켜면 wire 빠른 경로가 닫혀야 합니다"
            );
        }

        let ipset_breakers: [(&str, fn(&mut Config)); 2] = [
            ("ipset_name_v4", |c| {
                c.ipset_name_v4 = Some("blocked4".to_string())
            }),
            ("ipset_name_v6", |c| {
                c.ipset_name_v6 = Some("blocked6".to_string())
            }),
        ];
        for (key, name_it) in ipset_breakers {
            assert!(
                config_keys::is_hot(key),
                "{key}가 무중단 목록에서 빠졌습니다. 테스트를 함께 고치십시오"
            );
            let mut cfg = base.clone();
            name_it(&mut cfg);
            assert!(
                evaluate_lane_gates(&cfg, &facts).wire,
                "{key}만 있고 ipset_domains가 비면 ipset 계층이 없으므로 wire 빠른 경로가 열려 있어야 합니다"
            );
            cfg.ipset_domains = vec!["ads.example".to_string()];
            assert_eq!(
                evaluate_lane_gates(&cfg, &facts).wire,
                !cfg!(target_os = "linux"),
                "{key}와 ipset_domains를 함께 켜면 ipset 계층이 서는 Linux에서만 wire 빠른 경로가 닫혀야 합니다"
            );
        }

        for (key, break_it) in [
            (
                "cachedb_redis_host",
                (|c: &mut Config| c.cachedb_redis_host = Some("127.0.0.1".to_string()))
                    as fn(&mut Config),
            ),
            ("serve_stale_secs", |c: &mut Config| c.serve_stale_secs = 60),
            ("aggressive_nsec", |c: &mut Config| c.aggressive_nsec = true),
            ("harden_below_nxdomain", |c: &mut Config| {
                c.harden_below_nxdomain = true
            }),
            ("stub_zones", |c: &mut Config| {
                c.stub_zones.push(onetdns_config::StubZone {
                    suffix: "corp.test".to_string(),
                    servers: vec!["10.0.0.1".to_string()],
                })
            }),
            ("backend", |c: &mut Config| c.backend = BackendKind::Forward),
        ] {
            assert!(
                config_keys::is_hot(key),
                "{key}가 무중단 목록에서 빠졌습니다. 테스트를 함께 고치십시오"
            );
            let mut cfg = base.clone();
            cfg.backend = BackendKind::Recurse;
            break_it(&mut cfg);
            assert!(
                !evaluate_lane_gates(&cfg, &facts).reactor,
                "{key}를 무중단으로 켜면 리액터 레인이 닫혀야 합니다"
            );
        }
    }

    #[test]
    /** @brief 기본 설정이 실제 질의 기능 세트에도 lenient 쿠키를 만드는지. */
    fn default_native_features_enable_lenient_cookies() {
        let features = build_native_features(
            &Config::default(),
            None,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            None,
            None,
        )
        .unwrap();

        assert!(
            features.cookies.keeper.is_some(),
            "기본 서버 쿠키 비밀 생성"
        );
        assert!(
            !features.cookies.strict,
            "기본값은 쿠키 없는 클라이언트를 거부하지 않음"
        );
    }

    #[test]
    /** @brief 같은 Raft 비밀의 노드는 쿠키를 공유하고 비밀 hot-reload는 즉시 갈리는지. */
    fn raft_nodes_share_cookie_keys_and_secret_reload_rotates_them() {
        let mut first_cfg = Config {
            cluster_raft: true,
            cluster_node_id: 1,
            cluster_raft_secret: "shared-cluster-secret-at-least-32-bytes".into(),
            ..Config::default()
        };
        let mut second_cfg = first_cfg.clone();
        second_cfg.cluster_node_id = 2;
        let build = |cfg: &Config| {
            build_native_features(
                cfg,
                None,
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
                None,
                None,
            )
            .unwrap()
        };
        let cookie = |features: &native::NativeFeatures| {
            features.cookies.keeper.as_ref().unwrap().server_cookie_at(
                &[1, 2, 3, 4, 5, 6, 7, 8],
                "192.0.2.53".parse().unwrap(),
                1_800_000_000,
            )
        };

        let first = build(&first_cfg);
        let second = build(&second_cfg);
        assert_eq!(cookie(&first), cookie(&second), "노드 ID와 무관한 공유 키");

        first_cfg.cluster_raft_secret = "replacement-cluster-secret-at-least-32".into();
        let changed = vec!["cluster_raft_secret".to_string()];
        let reloaded = reconfigure_native_features(&first, &first_cfg, &changed).unwrap();
        assert_ne!(
            cookie(&first),
            cookie(&reloaded),
            "공용 비밀 변경은 새 Cookie 루트를 원자적으로 교체합니다"
        );
    }

    #[test]
    /** @brief DDR은 특수 이름 하나만 가로채므로 나머지 cache-hit·cold-miss 레인을 닫지 않는지. */
    fn ddr_keeps_general_udp_lanes_open() {
        let mut cfg = Config {
            backend: BackendKind::Recurse,
            cache_enabled: true,
            cache_size: 1_000,
            min_ttl: 0,
            ddr_name: "dns.example".to_string(),
            ..Config::default()
        };
        cfg.acme_directory_url = None;
        let gates = evaluate_lane_gates(
            &cfg,
            &LaneFacts {
                dhcp_pool: false,
                views_present: false,
                policy_present: false,
            },
        );
        assert!(gates.wire);
        if cfg!(unix) {
            assert!(gates.reactor);
        }
    }

    #[test]
    /** @brief 권한 빠른 경로도 무중단 설정에 따라 닫히는지. */
    fn hot_settings_that_break_the_authority_lane_close_it() {
        let facts = LaneFacts {
            dhcp_pool: false,
            views_present: false,
            policy_present: false,
        };
        let mut base = Config::default();
        base.zones.push(onetdns_config::ZoneConfig {
            origin: "example.test".to_string(),
            ..Default::default()
        });
        assert!(evaluate_lane_gates(&base, &facts).authority);

        let mut with_acme = base.clone();
        with_acme.acme_directory_url = Some("https://acme.test/dir".to_string());
        assert!(!evaluate_lane_gates(&with_acme, &facts).authority);

        let mut with_dynamic = base;
        with_dynamic
            .dynamic_records
            .push(onetdns_config::DynamicRecord {
                name: "www.example.test".to_string(),
                ..Default::default()
            });
        assert!(!evaluate_lane_gates(&with_dynamic, &facts).authority);
    }

    #[test]
    /** @brief 기록 파일을 못 열었을 때 조용히 끄지 않는지. */
    fn configured_dnstap_open_failure_is_not_silently_disabled() {
        let mut config = Config::default();
        config.dnstap_file = Some(std::env::temp_dir());
        assert!(build_dnstap(&config).is_err());
    }
}
