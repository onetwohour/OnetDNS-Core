//! Builds the query handler's policy, access control, rate limits, and fast-path gates from the
//! config.

use std::path::PathBuf;
use std::sync::Arc;

use onetdns_config::{AclUnlisted, BackendKind, BlockResponseKind, Config, EcsMode};
use onetdns_core::{AccessControl, BlockResponse, RateLimiter};
use onetdns_security::{CookieKeeper, IpAcl, KeyedRateLimiter, SubnetRateLimiter};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::BoxResult;
use crate::zone_signing::load_zone_signer;
use crate::{
    authority_sources_configured, build_tsig_keys, config_keys, layers, native, read_bytes_limited,
    tsig_for_secondary, PRODUCT_NAME, WASM_MODULE_MAX_BYTES,
};

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
                        format!("views[{index}].local_a[{item}] has an invalid DNS name")
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
                        format!("views[{index}].local_aaaa[{item}] has an invalid DNS name")
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
                        "update_policy[{index}].action has a value that is not allowed: '{other}'"
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
                            "update_policy[{index}].types[{item}] has a DNS record type that is not allowed: '{rtype}'"
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
            .ok_or_else(|| format!("update_policy[{index}] has an invalid identity or name"))
        })
        .collect()
}

/// Swappable access control that answers cheaply whether it blocks nothing.
pub(crate) struct DynamicAccessControl {
    inner: std::sync::RwLock<Arc<dyn AccessControl>>,
    /// Kept apart so answering needs no lock.
    trivially_allow: std::sync::atomic::AtomicBool,
}

impl DynamicAccessControl {
    pub(crate) fn new(inner: Arc<dyn AccessControl>) -> Self {
        let trivially_allow = inner.is_trivially_allow();
        Self {
            inner: std::sync::RwLock::new(inner),
            trivially_allow: std::sync::atomic::AtomicBool::new(trivially_allow),
        }
    }

    /// Also updates the trivial-allow flag.
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
    fn check(&self, client: &onetdns_core::ClientInfo) -> onetdns_core::AclDecision {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .check(client)
    }

    /// Transports call this per packet and per connection, so with no rules it answers without
    /// locking.
    fn drops(&self, ip: std::net::IpAddr) -> Option<onetdns_core::DropReason> {
        if self.is_trivially_allow() {
            return None;
        }
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .drops(ip)
    }

    /// Fast paths skip the check on its word.
    fn is_trivially_allow(&self) -> bool {
        self.trivially_allow
            .load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Swappable rate limiting.
pub(crate) struct DynamicRateLimiter {
    inner: std::sync::RwLock<Vec<Arc<dyn RateLimiter>>>,
    /// Kept apart so answering needs no lock.
    active: std::sync::atomic::AtomicUsize,
}

/// Facts the fast-path gates need that the config cannot tell: whether the DHCP lease pool came up,
/// which is known only once a generation starts, and whether views and policy rules exist, read
/// from their live values.
pub(crate) struct LaneFacts {
    pub(crate) dhcp_pool: bool,
    pub(crate) views_present: bool,
    pub(crate) policy_present: bool,
}

/// Whether this config adds the layer that puts answered addresses into a kernel set: it needs both
/// a set name and target domains, and kernel sets exist only on Linux. Closing a fast path for a
/// config that adds no such layer only slows things down.
pub(crate) fn ipset_layer_active(cfg: &Config) -> bool {
    cfg!(target_os = "linux")
        && (cfg.ipset_name_v4.is_some() || cfg.ipset_name_v6.is_some())
        && !cfg.ipset_domains.is_empty()
}

/// Startup and config swaps both call only this; judging in two places would leave a lane on the
/// old conditions after a swap, answering as if a feature did not exist. The `config_keys` table
/// decides which keys close a lane; this checks only each lane's prerequisites.
pub(crate) fn evaluate_lane_gates(cfg: &Config, facts: &LaneFacts) -> native::LaneGates {
    use config_keys::{lane_unblocked, Lane};
    let wire = lane_unblocked(Lane::Wire, cfg, facts);
    let authority =
        authority_sources_configured(cfg) && lane_unblocked(Lane::Authority, cfg, facts);
    let reactor = cfg!(unix) && wire && lane_unblocked(Lane::Reactor, cfg, facts);
    native::LaneGates {
        wire,
        authority,
        reactor,
    }
}

#[derive(Clone)]
/// Swapped on config reload.
pub(crate) struct NativeHotState {
    /// Also carries the fast-path gates and the chain generation.
    pub(crate) features: Arc<native::NativeFeatureSwap>,
    pub(crate) policy: Arc<native::GatedSwap<onetdns_policy::PolicyEngine>>,
    pub(crate) views: Arc<native::GatedSwap<Vec<native::NativeView>>>,
    pub(crate) block_ttl: Arc<std::sync::atomic::AtomicU32>,
    pub(crate) local_ttl: Arc<std::sync::atomic::AtomicU32>,
    pub(crate) local_only_names: Arc<layers::LocalOnlyNames>,
    pub(crate) authority: Arc<onetdns_core::ArcSwap<native::AuthoritySettings>>,
}

impl DynamicRateLimiter {
    pub(crate) fn new(inner: Vec<Arc<dyn RateLimiter>>) -> Self {
        let active = inner.len();
        Self {
            inner: std::sync::RwLock::new(inner),
            active: std::sync::atomic::AtomicUsize::new(active),
        }
    }

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

    pub(crate) fn layer_count(&self) -> usize {
        self.active.load(std::sync::atomic::Ordering::Acquire)
    }
}

impl RateLimiter for DynamicRateLimiter {
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

    fn is_active(&self) -> bool {
        self.layer_count() != 0
    }
}

pub(crate) fn runtime_access_control(cfg: &Config) -> Arc<dyn AccessControl> {
    Arc::new(
        IpAcl::new(
            cfg.acl_allow.clone(),
            cfg.acl_deny.clone(),
            cfg.acl_default_allow(),
        )
        .with_ids(cfg.acl_allow_ids.clone(), cfg.acl_deny_ids.clone())
        .with_drop(cfg.acl_drop.clone())
        .with_unlisted_drop(cfg.acl_unlisted == AclUnlisted::Drop),
    )
}

/// Startup and swaps both call only this: the zone list yields both the storage paths and the
/// editable zones, so building them separately would let them disagree. Fails on an invalid key or
/// rule, keeping the previous settings.
pub(crate) fn build_authority_settings(cfg: &Config) -> Result<native::AuthoritySettings, String> {
    let tsig_keys = build_tsig_keys(cfg)?;
    let zone_signers = cfg
        .zones
        .iter()
        .filter(|zone| zone.dnssec_sign)
        .map(|zone| {
            let origin = onetdns_proto::Name::from_str(&zone.origin)
                .map_err(|_| format!("Invalid DNS zone name: {}", zone.origin))?;
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
        update_targets: cfg
            .zones
            .iter()
            .map(|zone| {
                let file = zone
                    .file
                    .clone()
                    .ok_or_else(|| format!("DNS zone '{}' has no file setting", zone.origin))?;
                let origin = if zone.origin.is_empty() {
                    "."
                } else {
                    zone.origin.as_str()
                };
                let origin = onetdns_proto::Name::from_str(origin)
                    .map_err(|_| format!("Invalid DNS zone name: {}", zone.origin))?;
                Ok(native::UpdateTarget { origin, file })
            })
            .collect::<Result<_, String>>()?,
        notify_secondaries,
        notify_catalog_primaries,
        zone_signers,
    })
}

/// Whether answers advertise recursion (RA). Rechecked with every chain rebuild, so a change of
/// backend or upstreams changes RA too.
pub(crate) fn recursion_offered_by(cfg: &Config) -> bool {
    cfg.backend != BackendKind::Forward
        || !cfg.upstreams.is_empty()
        || !cfg.upstream_urls.is_empty()
}

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
                        "policy[{index}].rewrite needs a valid IPv4 address"
                    ));
                }
            },
            other => {
                return Err(format!(
                    "policy[{index}].action has a value that is not allowed: '{other}'"
                ));
            }
        };
        let mut rule = Rule::new(action)
            .with_clients(&p.clients)
            .with_suffixes(&p.suffixes)
            .with_qtypes(&qtype_numbers(&p.qtypes));
        if !p.days.is_empty() || p.start.is_some() || p.end.is_some() {
            let window = parse_time_window(&p.days, &p.start, &p.end)
                .ok_or_else(|| format!("policy[{index}] has an invalid day or time range"))?;
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
                    onetdns_core::info!(event = "policy.wasm_loaded", path = %path.display(), fail_mode = ?fail_mode, "Loaded WASM policy plugin");
                    plugins.push(w.with_name(name).with_failure_mode(fail_mode));
                }
                Err(e) => {
                    let error = format!(
                        "Could not prepare the WASM policy ({}): {e}",
                        path.display()
                    );
                    if fail_mode != onetdns_policy::FailureMode::Open {
                        return Err(error);
                    }
                    onetdns_core::error!(event = "policy.wasm_skipped", error = %error, "WASM policy was not applied")
                }
            },
            Err(e) => {
                let error = format!(
                    "Could not read the WASM policy file ({}): {e}",
                    path.display()
                );
                if fail_mode != onetdns_policy::FailureMode::Open {
                    return Err(error);
                }
                onetdns_core::error!(event = "policy.wasm_skipped", error = %error, "WASM policy was not applied")
            }
        }
    }
    Ok(onetdns_policy::PolicyEngine::new(
        RuleEngine::new(rules),
        plugins,
    ))
}

/// Dashboard item ID; unaffected by list order.
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

/// Tells secret resources apart within the process without logging the plaintext.
pub(crate) fn private_resource_id(namespace: &str, value: &str) -> String {
    /// Per-process key, so a dictionary attack cannot match weak passwords against the fingerprint.
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

/// Accepts every mnemonic `RecordType::name` produces. A missing mnemonic is filtered out, and
/// callers usually fall back to A, answering a type other than the one asked. Types without a
/// mnemonic use the RFC 3597 TYPE form.
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

/// Whether anything reads the collected statistics and query log: the dashboard and REST when there
/// is a control listen address, or the files when configured. With none, the events built per query
/// are discarded as soon as they are made.
pub(crate) fn telemetry_consumed(cfg: &Config) -> bool {
    let has_file = |path: &Option<PathBuf>| {
        path.as_ref()
            .is_some_and(|path| !path.as_os_str().is_empty())
    };
    cfg.control_listen.is_some() || has_file(&cfg.stats_file) || has_file(&cfg.querylog_file)
}

/// Cluster secret the server cookie secret derives from; None means each node uses a random secret.
fn cookie_root(cfg: &Config) -> Option<&str> {
    (cfg.cluster_raft && cfg.cluster_raft_secret.len() >= 32)
        .then_some(cfg.cluster_raft_secret.as_str())
}

/// `previous`: the running config and cookie policy. When the inputs that decide the server secret
/// are unchanged, that secret carries over; a new secret would invalidate every server cookie
/// clients hold.
fn build_cookie_policy(
    cfg: &Config,
    previous: Option<(&Config, &native::CookiePolicy)>,
) -> native::CookiePolicy {
    if !cfg.cookies.is_enabled() {
        return native::CookiePolicy::default();
    }
    let kept = previous
        .filter(|(running, _)| cookie_root(running) == cookie_root(cfg))
        .and_then(|(_, policy)| policy.keeper.clone());
    let keeper = kept.unwrap_or_else(|| {
        Arc::new(match cookie_root(cfg) {
            Some(secret) => {
                // A context label derives a separate root, so Raft authentication and cookies never
                // share the raw key. Nodes with the same cluster secret get the same root and epoch
                // keys.
                let mut digest = Sha256::new();
                digest.update(b"OnetDNS DNS Cookie cluster master v1\0");
                digest.update(secret.as_bytes());
                let digest = Zeroizing::new(<[u8; 32]>::from(digest.finalize()));
                let mut master = Zeroizing::new([0u8; 16]);
                master.copy_from_slice(&digest[..16]);
                CookieKeeper::from_master_secret(&master)
            }
            None => CookieKeeper::random(),
        })
    });
    native::CookiePolicy {
        keeper: Some(keeper),
        strict: cfg.cookies.is_strict(),
    }
}

/// The last 4 bytes are 0; synthesis fills them with the IPv4 address.
fn dns64_prefix(cfg: &Config) -> Option<[u8; 16]> {
    let address = cfg.dns64_prefix.as_ref()?.split('/').next()?;
    let mut octets = address.parse::<std::net::Ipv6Addr>().ok()?.octets();
    octets[12..16].fill(0);
    Some(octets)
}

/// Startup and config swaps both use this alone. It builds from the whole config without looking at
/// which keys changed: picking fields by the changed keys' groups would miss a key that belongs to
/// another group but also sets a response feature.
///
/// `previous`: the running config and features, None at startup; used only to decide whether the
/// cookie secret and the dnstap stream carry over. Fast-path state is left empty; the caller sets
/// the chain generation and the gates.
pub(crate) fn build_native_features(
    cfg: &Config,
    previous: Option<(&Config, &native::NativeFeatures)>,
) -> Result<native::NativeFeatures, String> {
    Ok(native::NativeFeatures {
        block_aaaa: cfg.block_aaaa,
        dns64_prefix: dns64_prefix(cfg),
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
        nsid: cfg.nsid.as_ref().map(|s| s.clone().into_bytes()),
        cookies: build_cookie_policy(
            cfg,
            previous.map(|(running, features)| (running, &features.cookies)),
        ),
        inflight_max: cfg.max_inflight,
        dnstap: build_dnstap(
            cfg,
            previous.and_then(|(_, features)| features.dnstap.as_ref()),
        )?,
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
        ddr_enabled: !cfg.ddr_name.is_empty(),
        lane_runtime: None,
        lanes: native::LaneGates::default(),
        wire_epoch: 0,
    })
}

/// Defaults to the product name.
fn dnstap_identity(cfg: &Config) -> &str {
    if cfg.dnstap_identity.is_empty() {
        PRODUCT_NAME
    } else {
        &cfg.dnstap_identity
    }
}

/// Fails rather than silently disabling when the file cannot be opened. `open`: the running writer;
/// for the same file its stream continues and only the identity changes, since a second stream on
/// one file would interleave frames.
fn build_dnstap(
    cfg: &Config,
    open: Option<&Arc<onetdns_control::DnstapWriter>>,
) -> Result<Option<Arc<onetdns_control::DnstapWriter>>, String> {
    let Some(path) = cfg.dnstap_file.as_ref() else {
        return Ok(None);
    };
    if let Some(open) = open.filter(|open| open.path() == path.as_path()) {
        return Ok(Some(Arc::new(open.with_identity(dnstap_identity(cfg)))));
    }
    let writer =
        onetdns_control::DnstapWriter::create(path, dnstap_identity(cfg)).map_err(|error| {
            format!(
                "Could not open the dnstap output file ({}): {error}",
                path.display()
            )
        })?;
    onetdns_core::info!(event = "dnstap.started", path = %path.display(), "Exporting the query log over dnstap");
    Ok(Some(Arc::new(writer)))
}

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

/// Minutes since midnight.
pub(crate) fn parse_hhmm(s: &str) -> Option<u32> {
    let (h, m) = s.split_once(':')?;
    let h: u32 = h.trim().parse().ok()?;
    let m: u32 = m.trim().parse().ok()?;
    (h < 24 && m < 60).then_some(h * 60 + m)
}

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
        other => crate::bail!("Unsupported DNS record type: {other}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    use onetdns_config::{BackendKind, Config, CookieMode, EcsMode};
    use onetdns_core::RateLimiter;
    use onetdns_security::IpAcl;

    use crate::{config_keys, native};

    #[test]
    /// If the two tables disagree, the asked type is silently filtered and the caller falls back to
    /// A; a CAA query would get an answer about A without a single error.
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
    /// The bit is set in one place and read in another, so changing only one would shift every time
    /// window rule by a day while each unit test still passes.
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
    /// A vanished rule leaves the operator believing it applies.
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

    struct AlwaysThrottle;

    impl RateLimiter for AlwaysThrottle {
        fn check(&self, _client: &onetdns_core::ClientInfo) -> onetdns_core::RateDecision {
            onetdns_core::RateDecision::Throttle
        }
    }

    #[test]
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
    /// The default allow list holds only private ranges, so a client with a public address matches
    /// no rule. When the config says to drop such clients, the address-only check transports use
    /// must drop them too.
    fn runtime_access_control_carries_the_unlisted_policy() {
        use onetdns_core::{AclDecision, DropReason};
        let client = onetdns_core::ClientInfo {
            source_ip: "203.0.113.1".parse().unwrap(),
            client_id: None,
            transport: onetdns_core::Transport::Do53Udp,
            authenticated: false,
        };
        let mut cfg = Config::default();
        let refusing = runtime_access_control(&cfg);
        assert_eq!(
            refusing.check(&client),
            AclDecision::Deny,
            "대조군이 무효입니다: 기본값은 거부여야 합니다"
        );
        assert_eq!(refusing.drops(client.source_ip), None);

        cfg.acl_unlisted = AclUnlisted::Drop;
        let dropping = runtime_access_control(&cfg);
        assert_eq!(
            dropping.check(&client),
            AclDecision::Drop(DropReason::Unlisted)
        );
        assert_eq!(dropping.drops(client.source_ip), Some(DropReason::Unlisted));
        assert_eq!(
            dropping.drops("192.168.1.10".parse().unwrap()),
            None,
            "허용 목록의 주소를 버렸습니다"
        );
    }

    #[test]
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
    fn stable_resource_ids_do_not_depend_on_array_position() {
        let a1 = stable_resource_id("upstream", "https://dns.example/dns-query");
        let a2 = stable_resource_id("upstream", "https://dns.example/dns-query");
        let b = stable_resource_id("upstream", "1.1.1.1");
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
        assert!(a1.starts_with("upstream-"));
    }

    #[test]
    /// A policy plugin that failed to load does not let queries through.
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
    /// Missing one would leave the dashboard or the file empty for that config; counting too
    /// broadly would make headless deployments pay for statistics nobody reads.
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

        // An empty path means off; configs with the key left and the value cleared do occur.
        cfg.querylog_file = Some(PathBuf::new());
        assert!(
            !telemetry_consumed(&cfg),
            "빈 경로를 저장 파일이 있는 것으로 셌습니다"
        );
    }

    #[test]
    /// Fast paths answer on the assumption of the config they were built with. Accepting a setting
    /// that breaks that assumption hot while the lane stays open would keep serving old answers
    /// after the cache is turned off, or answer as if an enabled feature were absent.
    ///
    /// A failure here means the setting must leave the hot-reload list or join the lane conditions.
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
            ("rebind_protection", |c: &mut Config| {
                c.rebind_protection = true
            }),
            ("bogus_nxdomain", |c: &mut Config| {
                c.bogus_nxdomain = vec!["192.0.2.1/32".parse().unwrap()]
            }),
            ("recurse_deny_answers", |c: &mut Config| {
                c.recurse_deny_answers = vec!["192.0.2.1/32".parse().unwrap()]
            }),
            ("recurse_opportunistic_encryption", |c: &mut Config| {
                c.recurse_opportunistic_encryption = true
            }),
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
    fn default_native_features_enable_lenient_cookies() {
        let features = build_native_features(&Config::default(), None).unwrap();

        assert!(
            features.cookies.keeper.is_some(),
            "기본 서버 쿠키 비밀 생성"
        );
        assert!(
            !features.cookies.strict,
            "기본값은 쿠키 없는 클라이언트를 거부하지 않음"
        );
    }

    /// For a fixed client cookie, address, and time.
    fn server_cookie(features: &native::NativeFeatures) -> Vec<u8> {
        features
            .cookies
            .keeper
            .as_ref()
            .expect("쿠키 비밀이 없습니다")
            .server_cookie_at(
                &[1, 2, 3, 4, 5, 6, 7, 8],
                "192.0.2.53".parse().unwrap(),
                1_800_000_000,
            )
            .to_vec()
    }

    #[test]
    /// A random secret a node used before Raft was on must also switch to the shared root the
    /// moment Raft turns on; otherwise nodes would issue different server cookies, and a client
    /// moving to another node would fail the cookie check.
    fn raft_nodes_share_cookie_keys_and_secret_reload_rotates_them() {
        let first_cfg = Config {
            cluster_raft: true,
            cluster_node_id: 1,
            cluster_raft_secret: "shared-cluster-secret-at-least-32-bytes".into(),
            ..Config::default()
        };
        let mut second_cfg = first_cfg.clone();
        second_cfg.cluster_node_id = 2;
        let build = |cfg: &Config| build_native_features(cfg, None).unwrap();

        let first = build(&first_cfg);
        let second = build(&second_cfg);
        assert_eq!(
            server_cookie(&first),
            server_cookie(&second),
            "노드 ID가 달라도 같은 클러스터 비밀이면 서버 쿠키가 같아야 합니다"
        );

        let mut rotated_cfg = first_cfg.clone();
        rotated_cfg.cluster_raft_secret = "replacement-cluster-secret-at-least-32".into();
        let rotated = build_native_features(&rotated_cfg, Some((&first_cfg, &first))).unwrap();
        assert_ne!(
            server_cookie(&first),
            server_cookie(&rotated),
            "클러스터 비밀을 바꿨는데 이전 쿠키 루트가 남았습니다"
        );
        assert_eq!(
            server_cookie(&rotated),
            server_cookie(&build(&rotated_cfg)),
            "비밀을 바꾼 노드와 새 비밀로 시작한 노드의 서버 쿠키가 달라야 할 이유가 없습니다"
        );

        let standalone_cfg = Config {
            cluster_raft: false,
            ..first_cfg.clone()
        };
        let standalone = build(&standalone_cfg);
        let joined =
            build_native_features(&first_cfg, Some((&standalone_cfg, &standalone))).unwrap();
        assert_eq!(
            server_cookie(&joined),
            server_cookie(&first),
            "Raft를 켰는데 노드의 무작위 쿠키 비밀이 남았습니다"
        );
    }

    #[test]
    /// A new secret would invalidate every server cookie clients hold, and strict mode would refuse
    /// those clients. Changing only the mode, or writing a secret while Raft is off, also leaves
    /// the inputs unchanged.
    fn cookie_secret_survives_reloads_that_keep_its_root() {
        let running_cfg = Config::default();
        let running = build_native_features(&running_cfg, None).unwrap();
        let keeper = |features: &native::NativeFeatures| {
            features
                .cookies
                .keeper
                .clone()
                .expect("쿠키 비밀이 없습니다")
        };

        let unrelated = Config {
            minimal_responses: !running_cfg.minimal_responses,
            ..running_cfg.clone()
        };
        let strict = Config {
            cookies: CookieMode::Strict,
            ..running_cfg.clone()
        };
        let staged_secret = Config {
            cluster_raft: false,
            cluster_raft_secret: "staged-cluster-secret-at-least-32-bytes".into(),
            ..running_cfg.clone()
        };
        for (case, next) in [
            ("다른 키만 바꾼 경우", &unrelated),
            ("엄격 모드로 바꾼 경우", &strict),
            ("Raft를 끈 채 비밀만 적은 경우", &staged_secret),
        ] {
            let reloaded = build_native_features(next, Some((&running_cfg, &running))).unwrap();
            assert!(
                Arc::ptr_eq(&keeper(&running), &keeper(&reloaded)),
                "{case}에 쿠키 비밀을 새로 만들었습니다"
            );
            assert_eq!(reloaded.cookies.strict, next.cookies.is_strict(), "{case}");
        }

        let disabled = Config {
            cookies: CookieMode::Off,
            ..running_cfg.clone()
        };
        assert!(
            build_native_features(&disabled, Some((&running_cfg, &running)))
                .unwrap()
                .cookies
                .keeper
                .is_none(),
            "쿠키를 껐는데 비밀이 남았습니다"
        );
    }

    #[test]
    /// DDR intercepts one special name only, so the other cache-hit and cold-miss lanes stay open.
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
    /// The authority lane closes only for hot settings that change its answers.
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
        assert_eq!(base.cookies, CookieMode::Lenient);
        assert!(
            evaluate_lane_gates(&base, &facts).authority,
            "lenient 쿠키는 COOKIE 옵션이 붙은 질의만 일반 경로로 보내므로 경로를 닫지 않아야 합니다"
        );

        // The authority lane answers optionless A and AAAA queries from the same zone data as the
        // authority layer. Local-only names are decided below the authority layer, NSID and padding
        // change only answers to queries carrying those options, and ACME challenges change only
        // TXT answers, so none of them alter this lane's answers.
        let keepers: Vec<(&str, fn(&mut Config))> = vec![
            ("acme_directory_url", |c| {
                c.acme_directory_url = Some("https://acme.test/dir".to_string())
            }),
            ("domain_needed", |c| c.domain_needed = true),
            ("bogus_priv", |c| c.bogus_priv = true),
            ("empty_zones", |c| c.empty_zones = true),
            ("edns_padding_block", |c| c.edns_padding_block = 128),
            ("nsid", |c| c.nsid = Some("ns1".to_string())),
        ];
        for (key, set) in keepers {
            let mut cfg = base.clone();
            set(&mut cfg);
            assert!(
                evaluate_lane_gates(&cfg, &facts).authority,
                "{key}는 권한 빠른 경로의 답을 바꾸지 않으므로 경로를 닫지 않아야 합니다"
            );
        }

        let breakers: Vec<(&str, fn(&mut Config))> = vec![
            ("dynamic_records", |c| {
                c.dynamic_records.push(onetdns_config::DynamicRecord {
                    name: "www.example.test".to_string(),
                    ..Default::default()
                })
            }),
            ("dns64_prefix", |c| {
                c.dns64_prefix = Some("64:ff9b::/96".to_string())
            }),
            ("rebind_protection", |c| c.rebind_protection = true),
            ("cookies", |c| c.cookies = CookieMode::Strict),
            ("block_aaaa", |c| c.block_aaaa = true),
            ("bogus_nxdomain", |c| {
                c.bogus_nxdomain = vec!["192.0.2.1/32".parse().unwrap()]
            }),
            ("rrset_roundrobin", |c| c.rrset_roundrobin = true),
            ("recurse_deny_answers", |c| {
                c.recurse_deny_answers = vec!["192.0.2.1/32".parse().unwrap()]
            }),
            ("dnstap_file", |c| {
                c.dnstap_file = Some(PathBuf::from("dnstap.log"))
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
                !evaluate_lane_gates(&cfg, &facts).authority,
                "{key}를 무중단으로 켜면 권한 빠른 경로가 닫혀야 합니다"
            );
        }

        for live in [
            LaneFacts {
                views_present: true,
                ..facts
            },
            LaneFacts {
                policy_present: true,
                ..facts
            },
        ] {
            assert!(
                !evaluate_lane_gates(&base, &live).authority,
                "뷰나 정책이 있으면 권한 빠른 경로가 닫혀야 합니다"
            );
        }
    }

    #[test]
    fn configured_dnstap_open_failure_is_not_silently_disabled() {
        let mut config = Config::default();
        config.dnstap_file = Some(std::env::temp_dir());
        assert!(build_dnstap(&config, None).is_err());
    }

    #[test]
    /// A new stream would add another start frame and interleave the old writer's remaining frames
    /// with the new writer's, so readers could not parse the stream.
    fn dnstap_reload_on_the_same_file_keeps_one_stream() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-dnstap-reload-{}-{}.fstrm",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let running_cfg = Config {
            dnstap_file: Some(path.clone()),
            ..Config::default()
        };
        let next_cfg = Config {
            dnstap_identity: "renamed".to_string(),
            ..running_cfg.clone()
        };
        let running = build_native_features(&running_cfg, None).unwrap();
        let reloaded = build_native_features(&next_cfg, Some((&running_cfg, &running))).unwrap();
        assert!(
            reloaded.dnstap.is_some(),
            "교체한 설정에서 dnstap이 꺼졌습니다"
        );

        let content = std::fs::read(&path).unwrap();
        drop((running, reloaded));
        let _ = std::fs::remove_file(&path);
        let starts = content
            .windows(b"protobuf:dnstap.Dnstap".len())
            .filter(|window| *window == b"protobuf:dnstap.Dnstap")
            .count();
        assert_eq!(starts, 1, "같은 파일에 dnstap 스트림을 하나 더 열었습니다");
    }
}
