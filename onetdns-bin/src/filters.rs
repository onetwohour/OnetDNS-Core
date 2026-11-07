//! Downloads and caches blocklists and compiles them with the config into the filter engine.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use onetdns_config::{BackendKind, Config, LocalZone, LocalZoneKind, Rewrite, SplitTarget};
use onetdns_core::{MutexExt, RewriteTarget};
use onetdns_filter::{BlockEngine, EngineParts, LocalZoneAction, StaticZone};
use sha2::{Digest, Sha256};

use crate::atomic_file::{atomic_write, atomic_write_with, with_rollback_result};
use crate::config_apply::config_write_lock;
use crate::config_edit::{rewrite_config_kv, rewrite_config_string_array, toml_string_array};
use crate::native_config::{days_mask, map_block, parse_hhmm};
use crate::recursion::{new_recursor, recursor_roots};
use crate::{http, mac, native, read_text_limited, unix_now, upstream};

/// Validates an added rule; an `@@` rule goes to the allow list from either tab.
pub(crate) fn mutate_user_rule(
    overlay: &Mutex<(Vec<String>, Vec<String>)>,
    config_path: Option<&std::path::Path>,
    rebuild: &dyn Fn() -> Result<(usize, usize), String>,
    rule: &str,
    tab_allow: bool,
    add: bool,
) -> Result<(usize, usize), String> {
    use onetdns_core::MutexExt;

    let rule = rule.trim();
    if rule.is_empty() {
        return Err("`rule` is required".to_string());
    }
    if add {
        onetdns_filter::validate_rule(rule).map_err(|reason| format!("Invalid rule: {reason}"))?;
    }
    let into_allow = tab_allow || rule.starts_with("@@");

    let previous = overlay.lock_recover().clone();
    let mut next = previous.clone();
    if add {
        let list = if into_allow { &mut next.1 } else { &mut next.0 };
        if !list.iter().any(|item| item == rule) {
            list.push(rule.to_string());
        }
    } else {
        next.0.retain(|item| item != rule);
        next.1.retain(|item| item != rule);
    }

    let block_changed = previous.0 != next.0;
    let allow_changed = previous.1 != next.1;

    let persisted_change =
        if let Some(path) = config_path.filter(|_| block_changed || allow_changed) {
            let _write_guard = config_write_lock().lock_recover();
            let previous_text = onetdns_core::SecretString::from(
                Config::read_text(path).map_err(|error| error.to_string())?,
            );
            let mut updated_text = previous_text.clone();
            if block_changed {
                updated_text = onetdns_core::SecretString::from(rewrite_config_string_array(
                    &updated_text,
                    "block_rules",
                    &next.0,
                )?);
            }
            if allow_changed {
                updated_text = onetdns_core::SecretString::from(rewrite_config_string_array(
                    &updated_text,
                    "allow_rules",
                    &next.1,
                )?);
            }
            atomic_write(path, updated_text.as_bytes()).map_err(|error| error.to_string())?;
            Some((path.to_path_buf(), previous_text, updated_text))
        } else {
            None
        };
    *overlay.lock_recover() = next;
    match rebuild() {
        Ok(value) => Ok(value),
        Err(error) => {
            *overlay.lock_recover() = previous;
            let error = if let Some((path, previous_text, updated_text)) = persisted_change {
                let rollback = (|| -> Result<(), String> {
                    let _write_guard = config_write_lock().lock_recover();
                    let current = onetdns_core::SecretString::from(
                        Config::read_text(&path)
                            .map_err(|rollback_error| rollback_error.to_string())?,
                    );
                    if current != updated_text {
                        return Err("The configuration file changed again while the runtime state was being updated, so it was not reverted automatically".to_string());
                    }
                    atomic_write(&path, previous_text.as_bytes())
                        .map_err(|rollback_error| rollback_error.to_string())
                })();
                with_rollback_result(
                    error,
                    "Could not restore the previous rule settings",
                    rollback,
                )
            } else {
                error
            };
            Err(error)
        }
    }
}

fn expand_services(services: &[String]) -> Result<Vec<String>, String> {
    let mut out = vec![];
    for svc in services {
        let rules = onetdns_filter::services::service_rules(svc)
            .ok_or_else(|| format!("Unsupported blocked service: {svc}"))?;
        out.extend(rules.iter().map(|rule| (*rule).to_string()));
    }
    Ok(out)
}

#[derive(Clone)]
/// One downloaded blocklist.
pub(crate) struct SubMeta {
    pub(crate) url: String,
    pub(crate) title: String,
    pub(crate) rules: usize,
    pub(crate) updated_unix: u64,

    /// Raw rule lines, dropped once the engine is compiled and the list is on disk.
    lines: Arc<[String]>,
}

pub(crate) struct FilterBuildInputs<'a> {
    pub(crate) blocked_services: &'a [String],
    pub(crate) subscriptions: &'a [SubMeta],
    /// Block rules from the config.
    pub(crate) overlay_block: &'a [String],
    /// Allow rules from the config.
    pub(crate) overlay_allow: &'a [String],
    /// Suffixes answered with REFUSED.
    pub(crate) refused_domains: &'a [String],
    /// Downloaded RPZ texts.
    pub(crate) rpz_texts: &'a [String],
    pub(crate) compiled_filter_cache: Option<&'a std::path::Path>,
    pub(crate) subscription_cache_dir: Option<&'a std::path::Path>,
}

/// Inside a `service_schedule` window only the service rules are lifted; blocklists and user
/// rules still apply.
pub(crate) fn service_blocking_paused(cfg: &Config, now: std::time::SystemTime) -> bool {
    let windows = cfg
        .service_schedule
        .iter()
        .filter_map(|window| {
            let days = days_mask(&window.days);
            let start_min = parse_hhmm(&window.start)?;
            let end_min = parse_hhmm(&window.end)?;
            (days != 0).then_some(native::SchedWindow {
                days,
                start_min,
                end_min,
            })
        })
        .collect();
    native::Schedule { windows }.is_active(now)
}

/// Compiles every rule source into one engine, so the query path takes no lock and does not
/// allocate.
pub(crate) fn build_filter_engine_for_config(
    config: &Config,
    input: &FilterBuildInputs<'_>,
) -> Result<BlockEngine, String> {
    let blocked_services = input.blocked_services;
    let subscriptions = input.subscriptions;
    let overlay_block = input.overlay_block;
    let overlay_allow = input.overlay_allow;
    let refused_domains = input.refused_domains;
    let rpz_texts = input.rpz_texts;
    let compiled_filter_cache = input.compiled_filter_cache;
    let subscription_cache_dir = input.subscription_cache_dir;
    let services_paused = service_blocking_paused(config, std::time::SystemTime::now());
    let service_rules = if services_paused {
        Vec::new()
    } else {
        expand_services(blocked_services)?
    };
    let fingerprint = compiled_filter_fingerprint(&CompiledFilterInputs {
        blocklists: &config.blocklists,
        allowlists: &config.allowlists,
        service_rules: &service_rules,
        subscriptions,
        subscription_cache_dir,
        overlay_block,
        overlay_allow,
        rewrites: &config.rewrites,
        local_zones: &config.local_zones,
        refused_domains,
        rpz_files: &config.rpz_files,
        rpz_texts,
    });
    let cached =
        compiled_filter_cache.and_then(|path| load_compiled_filter_cache(path, fingerprint));
    let parts = if let Some(parts) = cached {
        onetdns_core::debug!(event = "filter.cache_loaded", "Loaded prebuilt blocklist");
        parts
    } else {
        let disk_subscription_files: Vec<Option<PathBuf>> = subscriptions
            .iter()
            .map(|meta| {
                subscription_cache_dir
                    .map(|dir| dir.join(blocklist_cache_key(&meta.url)))
                    .filter(|path| path.is_file())
            })
            .collect();
        let subscription_sources: Vec<onetdns_filter::SubscriptionSource<'_>> = subscriptions
            .iter()
            .zip(&disk_subscription_files)
            .map(|(meta, file)| onetdns_filter::SubscriptionSource {
                name: &meta.url,
                rules: match file {
                    Some(path) => onetdns_filter::SubscriptionRules::File(path),
                    None => onetdns_filter::SubscriptionRules::Lines(&meta.lines),
                },
            })
            .collect();

        for meta in subscriptions {
            let cached = subscription_cache_dir
                .is_some_and(|dir| dir.join(blocklist_cache_key(&meta.url)).is_file());
            if !cached && meta.lines.is_empty() {
                onetdns_core::warn!(
                    event = "filter.subscription_unavailable",
                    url = %meta.url,
                    "Subscription cache file is missing; this blocklist's rules are not applied"
                );
            }
        }
        let mut extra_block: Vec<&str> = service_rules.iter().map(String::as_str).collect();
        extra_block.extend(overlay_block.iter().map(String::as_str));
        let overlay_allow_refs: Vec<&str> = overlay_allow.iter().map(String::as_str).collect();
        let mut parts = onetdns_filter::load_parts_with_subscriptions(
            &config.blocklists,
            &config.allowlists,
            &subscription_sources,
            &extra_block,
            &overlay_allow_refs,
        )
        .map_err(|error| error.to_string())?;
        merge_config_filters(
            &mut parts,
            &config.rewrites,
            &config.local_zones,
            refused_domains,
            &config.rpz_files,
        )?;
        for text in rpz_texts {
            onetdns_filter::parse_rpz_text(text, &mut parts);
        }
        if let Some(path) = compiled_filter_cache {
            save_compiled_filter_cache(path, &mut parts, fingerprint);
        }
        parts
    };

    let policies = config
        .clients
        .iter()
        .map(|client| -> Result<_, String> {
            let mut ids = client.client_ids.clone();
            ids.extend(client.mac.iter().map(|mac| mac::normalize_mac(mac)));
            let mut block = client.block.clone();
            if !services_paused {
                block.extend(expand_services(&client.blocked_services)?);
            }
            Ok(onetdns_filter::ClientPolicy::with_options(
                client.ids.clone(),
                ids,
                client.tags.clone(),
                &block,
                &client.allow,
                client.disable_filtering,
                client.safe_search,
            )
            .with_log_flags(client.ignore_querylog, client.ignore_stats))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(BlockEngine::new(parts, map_block(config))
        .with_clients(policies)
        .with_hit_tracking(config.track_rule_hits))
}

/// Everything the compiled engine is built from.
struct CompiledFilterInputs<'a> {
    blocklists: &'a [PathBuf],
    allowlists: &'a [PathBuf],
    service_rules: &'a [String],
    subscriptions: &'a [SubMeta],
    subscription_cache_dir: Option<&'a std::path::Path>,
    /// Block rules from the config.
    overlay_block: &'a [String],
    /// Allow rules from the config.
    overlay_allow: &'a [String],
    rewrites: &'a [Rewrite],
    local_zones: &'a [LocalZone],
    /// Suffixes answered with REFUSED.
    refused_domains: &'a [String],
    rpz_files: &'a [PathBuf],
    /// Downloaded RPZ texts.
    rpz_texts: &'a [String],
}

/// The compiled cache is reused only when this matches.
fn compiled_filter_fingerprint(input: &CompiledFilterInputs<'_>) -> [u8; 32] {
    let mut digest = Sha256::new();
    fingerprint_bytes(&mut digest, b"format", b"onetdns-compiled-filter-input-v1");
    fingerprint_files(&mut digest, b"blocklists", input.blocklists);
    fingerprint_files(&mut digest, b"allowlists", input.allowlists);
    fingerprint_strings(&mut digest, b"service-rules", input.service_rules.iter());
    fingerprint_header(
        &mut digest,
        b"subscriptions",
        input.subscriptions.len() as u64,
    );
    for meta in input.subscriptions {
        let cache_path = input
            .subscription_cache_dir
            .map(|dir| dir.join(blocklist_cache_key(&meta.url)))
            .filter(|path| path.is_file());
        if let Some(path) = cache_path {
            fingerprint_files(&mut digest, b"subscription-file", &[path]);
        } else {
            fingerprint_strings(&mut digest, b"subscription-lines", meta.lines.iter());
        }
    }
    fingerprint_strings(&mut digest, b"overlay-block", input.overlay_block.iter());
    fingerprint_strings(&mut digest, b"overlay-allow", input.overlay_allow.iter());

    fingerprint_header(&mut digest, b"rewrites", input.rewrites.len() as u64);
    for rewrite in input.rewrites {
        fingerprint_bytes(&mut digest, b"domain", rewrite.domain.as_bytes());
        fingerprint_bytes(&mut digest, b"answer", rewrite.answer.as_bytes());
    }
    fingerprint_header(&mut digest, b"local-zones", input.local_zones.len() as u64);
    for zone in input.local_zones {
        fingerprint_bytes(&mut digest, b"name", zone.name.as_bytes());
        let kind = match zone.kind {
            LocalZoneKind::Deny => 0,
            LocalZoneKind::Refuse => 1,
            LocalZoneKind::Static => 2,
            LocalZoneKind::Redirect => 3,
            LocalZoneKind::AlwaysNull => 4,
            LocalZoneKind::Transparent => 5,
        };
        fingerprint_bytes(&mut digest, b"kind", &[kind]);
        fingerprint_strings(&mut digest, b"records", zone.records.iter());
    }
    fingerprint_strings(
        &mut digest,
        b"refused-domains",
        input.refused_domains.iter(),
    );
    fingerprint_files(&mut digest, b"rpz-files", input.rpz_files);
    fingerprint_strings(&mut digest, b"rpz-texts", input.rpz_texts.iter());
    digest.finalize().into()
}

/// Drops the raw lines of lists saved on disk; the compiled engine no longer needs them.
pub(crate) fn release_subscription_lines(meta: &Mutex<Vec<SubMeta>>, cache_dir: &std::path::Path) {
    for item in meta.lock_recover().iter_mut() {
        if cache_dir.join(blocklist_cache_key(&item.url)).is_file() {
            item.lines = Vec::new().into();
        }
    }
}

fn fingerprint_header(digest: &mut Sha256, label: &[u8], count: u64) {
    digest.update((label.len() as u64).to_le_bytes());
    digest.update(label);
    digest.update(count.to_le_bytes());
}

fn fingerprint_bytes(digest: &mut Sha256, label: &[u8], bytes: &[u8]) {
    fingerprint_header(digest, label, bytes.len() as u64);
    digest.update(bytes);
}

fn fingerprint_strings<'a>(
    digest: &mut Sha256,
    label: &[u8],
    values: impl ExactSizeIterator<Item = &'a String>,
) {
    fingerprint_header(digest, label, values.len() as u64);
    for value in values {
        fingerprint_bytes(digest, b"value", value.as_bytes());
    }
}

fn fingerprint_files(digest: &mut Sha256, label: &[u8], paths: &[PathBuf]) {
    use std::io::Read;

    const MAX_FILTER_FILE: u64 = 128 * 1024 * 1024;
    fingerprint_header(digest, label, paths.len() as u64);
    for path in paths {
        fingerprint_bytes(digest, b"path", path.to_string_lossy().as_bytes());
        let Ok(file) = std::fs::File::open(path) else {
            fingerprint_bytes(digest, b"file-status", b"unreadable");
            continue;
        };
        let mut reader = file.take(MAX_FILTER_FILE + 1);
        let mut content = Sha256::new();
        let mut total = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        let status = loop {
            match reader.read(&mut buffer) {
                Ok(0) => break b"ok".as_slice(),
                Ok(read) => {
                    total += read as u64;
                    if total > MAX_FILTER_FILE {
                        break b"oversize".as_slice();
                    }
                    content.update(&buffer[..read]);
                }
                Err(_) => break b"unreadable".as_slice(),
            }
        };
        fingerprint_bytes(digest, b"file-status", status);
        if status == b"ok" {
            digest.update(total.to_le_bytes());
            digest.update(content.finalize());
        }
    }
}

fn load_compiled_filter_cache(
    path: &std::path::Path,
    fingerprint: [u8; 32],
) -> Option<EngineParts> {
    use std::io::Read;

    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() > onetdns_filter::MAX_CACHE_BYTES as u64 {
        onetdns_core::warn!(event = "filter.cache_evicted_oversize", path = %path.display(), "Deleted the compiled filter cache because it exceeded the size limit");
        return None;
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(metadata.len() as usize).ok()?;
    let mut file = std::fs::File::open(path)
        .ok()?
        .take(onetdns_filter::MAX_CACHE_BYTES as u64 + 1);
    file.read_to_end(&mut bytes).ok()?;
    if bytes.len() > onetdns_filter::MAX_CACHE_BYTES {
        return None;
    }
    match onetdns_filter::decode_engine_cache(&bytes, fingerprint) {
        Ok(parts) => Some(parts),
        Err(error) => {
            onetdns_core::debug!(event = "filter.cache_unusable", path = %path.display(), %error, "Compiled filter cache is unusable; reprocessing the source rules");
            None
        }
    }
}

/// Streams the engine into a new file and swaps it in, without holding the encoding in memory.
fn save_compiled_filter_cache(
    path: &std::path::Path,
    parts: &mut EngineParts,
    fingerprint: [u8; 32],
) {
    if let Some(parent) = path.parent() {
        if let Err(error) = std::fs::create_dir_all(parent) {
            onetdns_core::warn!(event = "filter.cache_dir_failed", path = %path.display(), %error, "Could not create the compiled filter cache directory");
            return;
        }
    }
    if let Err(error) = atomic_write_with(path, false, |file| {
        onetdns_filter::write_engine_cache(parts, fingerprint, file).map_err(std::io::Error::other)
    }) {
        onetdns_core::warn!(event = "filter.cache_save_failed", path = %path.display(), %error, "Could not save the compiled filter cache");
    }
}

fn parse_list_title(body: &str) -> String {
    for raw in body.lines().take(64) {
        let t = raw.trim();
        let stripped = t
            .strip_prefix('!')
            .or_else(|| t.strip_prefix('#'))
            .map(str::trim);
        if let Some(rest) = stripped {
            if let Some(v) = rest
                .strip_prefix("Title:")
                .or_else(|| rest.strip_prefix("title:"))
            {
                let v = v.trim();
                if !v.is_empty() {
                    return v.to_string();
                }
            }
        }
    }
    String::new()
}

fn count_list_rules(body: &str) -> usize {
    body.lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('!') && !t.starts_with('#')
        })
        .count()
}

/// An HTML error page read as rules would block arbitrary names.
fn looks_like_error_document(body: &str) -> bool {
    let prefix = body
        .trim_start()
        .chars()
        .take(512)
        .collect::<String>()
        .to_ascii_lowercase();
    prefix.starts_with("<!doctype html")
        || prefix.starts_with("<html")
        || prefix.contains("<head>")
        || prefix.contains("<body>")
        || body.as_bytes().contains(&0)
}

fn likely_rpz_rule_count(body: &str) -> usize {
    body.lines()
        .filter(|raw| {
            let line = raw.trim();
            if line.is_empty()
                || line.starts_with(';')
                || line.starts_with('$')
                || line.starts_with('@')
            {
                return false;
            }
            line.split_whitespace().any(|token| {
                matches!(
                    token.to_ascii_uppercase().as_str(),
                    "CNAME" | "A" | "AAAA" | "PTR" | "TXT"
                )
            })
        })
        .count()
}

const BLOCKLIST_MAX_RESPONSE: u64 = 128 * 1024 * 1024;

const HOST_RESOLVER_CACHE_CAPACITY: usize = 512;
const HOST_RESOLVER_CACHE_TTL_MAX_SECS: u64 = 300;
const HOST_RESOLVER_FAILURE_CACHE_TTL: Duration = Duration::from_secs(10);

/// Resolves the host names in the server's own HTTP requests (blocklists, update checks, ACME,
/// cluster peers) the way the server resolves queries, without its filters: through the
/// upstreams when forwarding, from the root when recursing, by name when split. `bootstrap`
/// only finds the upstreams themselves.
pub(crate) fn blocklist_host_resolver(cfg: &Config) -> http::HostResolver {
    let source = match cfg.backend {
        BackendKind::Forward => "The upstream DNS servers",
        BackendKind::Recurse => "The built-in recursive resolver",
        BackendKind::Split => "Split resolution",
    };
    let backend = configured_backend(cfg);
    cached_host_resolver(cfg.max_ttl, move |host, timeout| {
        let backend = backend
            .as_ref()
            .map_err(|error| format!("Cannot look up {host}: {error}"))?;
        resolve_host_addresses(backend, host, source, timeout)
    })
}

/// Resolves the OCSP and CRL hosts in upstream certificates. The check is part of connecting
/// to an upstream, so these names go to `bootstrap`, else the plain `upstreams`, else recursion;
/// asking the upstream under check would connect to it again.
pub(crate) fn revocation_host_resolver(cfg: &Config) -> http::HostResolver {
    let servers = revocation_dns_servers(cfg);
    let recursion = recursive_backend(cfg);
    cached_host_resolver(cfg.max_ttl, move |host, timeout| {
        if servers.is_empty() {
            return resolve_host_addresses(
                &recursion,
                host,
                "The built-in recursive resolver",
                timeout,
            );
        }
        onetdns_forward::resolve_via_bootstrap(host, &servers, timeout)
            .map(|(ip, ttl)| (vec![ip], ttl))
            .ok_or_else(|| {
                format!("The bootstrap DNS servers could not resolve the address: {host}")
            })
    })
}

/// Never this machine: the server may not be serving yet.
fn revocation_dns_servers(cfg: &Config) -> Vec<IpAddr> {
    let mut addresses = if cfg.bootstrap.is_empty() {
        cfg.upstreams.clone()
    } else {
        cfg.bootstrap.clone()
    };
    addresses.retain(|address| {
        !upstream::is_local_ip(*address) && !address.is_unspecified() && !address.is_multicast()
    });
    addresses.sort();
    addresses.dedup();
    addresses
}

/// The configured backend, built apart from the one answering queries.
fn configured_backend(cfg: &Config) -> Result<Arc<dyn native::Resolver>, String> {
    let forward = || crate::build_forward_backend(cfg).map(|(resolver, _stats)| resolver);
    let backend: Arc<dyn native::Resolver> = match cfg.backend {
        BackendKind::Forward => forward()?,
        BackendKind::Recurse => recursive_backend(cfg),
        BackendKind::Split => {
            let default = match cfg.split_default {
                SplitTarget::Forward => crate::layers::Route::Forward,
                SplitTarget::Recurse => crate::layers::Route::Recurse,
            };
            Arc::new(crate::layers::SplitResolver::new(
                forward()?,
                recursive_backend(cfg),
                default,
                &cfg.split_recurse,
                &cfg.split_forward,
            )?)
        }
    };
    Ok(backend)
}

fn recursive_backend(cfg: &Config) -> Arc<dyn native::Resolver> {
    Arc::new(native::NativeBackend::Recurse {
        recursor: Arc::new(
            new_recursor(recursor_roots(cfg), Duration::from_secs(8))
                .with_recursive_cache_ttl_max(cfg.max_ttl as u32),
        ),
        ns_rpz: None,
        block_ttl: Arc::default(),
        local_ttl: Arc::default(),
    })
}

/// Asks for A and AAAA at once and stops at `timeout`, which can be shorter than the backend's
/// own. A lookup still running then ends at the backend's timeout and its answer is dropped.
fn resolve_host_addresses(
    resolver: &Arc<dyn native::Resolver>,
    host: &str,
    source: &str,
    timeout: Duration,
) -> Result<(Vec<IpAddr>, u32), String> {
    let name = onetdns_proto::Name::from_str(host)
        .map_err(|_| format!("Invalid host name in the URL: {host}"))?;
    let deadline = std::time::Instant::now() + timeout;
    let qtypes = [
        onetdns_proto::RecordType::A,
        onetdns_proto::RecordType::AAAA,
    ];
    let (sender, responses) = std::sync::mpsc::channel();
    for qtype in qtypes {
        let query = onetdns_proto::Message::query(0, name.clone(), qtype);
        let resolver = Arc::clone(resolver);
        let sender = sender.clone();
        std::thread::Builder::new()
            .name("host-lookup".into())
            .spawn(move || {
                let _ = sender.send(resolver.resolve(&query));
            })
            .map_err(|error| format!("Cannot look up {host}: {error}"))?;
    }
    drop(sender);
    let mut addresses = Vec::new();
    let mut ttl: Option<u32> = None;
    let mut timed_out = false;
    for _ in qtypes {
        let response = onetdns_core::tcp::time_left(deadline)
            .ok()
            .and_then(|left| responses.recv_timeout(left).ok());
        let Some(response) = response else {
            timed_out = true;
            break;
        };
        let Some(response) = response else {
            continue;
        };
        for answer in response.answers {
            let address = match answer.rdata {
                onetdns_proto::RData::A(ip) => IpAddr::V4(ip),
                onetdns_proto::RData::Aaaa(ip) => IpAddr::V6(ip),
                _ => continue,
            };
            ttl = Some(ttl.map_or(answer.ttl, |current| current.min(answer.ttl)));
            addresses.push(address);
        }
    }
    addresses.sort();
    addresses.dedup();
    if addresses.is_empty() && timed_out {
        return Err(format!("{source} did not answer in time: {host}"));
    }
    if addresses.is_empty() {
        return Err(format!("{source} could not resolve the host name: {host}"));
    }
    Ok((addresses, ttl.unwrap_or(0)))
}

/// Keeps an answer for its TTL, capped by `max_ttl` and five minutes, and a failure briefly.
fn cached_host_resolver(
    max_ttl: u64,
    lookup: impl Fn(&str, Duration) -> Result<(Vec<IpAddr>, u32), String> + Send + Sync + 'static,
) -> http::HostResolver {
    let success_ttl_cap_secs = max_ttl.min(HOST_RESOLVER_CACHE_TTL_MAX_SECS);
    let cache = Mutex::new(onetdns_core::LruMap::<
        String,
        (std::time::Instant, Duration, Result<Vec<IpAddr>, String>),
    >::new(HOST_RESOLVER_CACHE_CAPACITY));
    Arc::new(move |host: &str, timeout: Duration| {
        let cache_key = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some((stored_at, ttl, result)) = cache.lock_recover().get(&cache_key).cloned() {
            if stored_at.elapsed() < ttl {
                return result;
            }
        }
        let (ttl, result) = match lookup(host, timeout) {
            Ok((addresses, authoritative_ttl)) => (
                Duration::from_secs(u64::from(authoritative_ttl).min(success_ttl_cap_secs)),
                Ok(addresses),
            ),
            Err(error) => (HOST_RESOLVER_FAILURE_CACHE_TTL, Err(error)),
        };
        if !ttl.is_zero() {
            cache
                .lock_recover()
                .put(cache_key, (std::time::Instant::now(), ttl, result.clone()));
        }
        result
    })
}

pub(crate) fn fetch_blocklist(
    url: &str,
    resolver: &http::HostResolver,
    cache_dir: Option<&std::path::Path>,
) -> Result<SubMeta, String> {
    let resp = http::get(url)
        .timeout(Duration::from_secs(120))
        .max_response(BLOCKLIST_MAX_RESPONSE)
        .resolver(resolver.clone())
        .deny_private_targets()
        .call()
        .map_err(|error| format!("Could not download the blocklist: {error}"))?;
    if !(200..300).contains(&resp.status) {
        return Err(format!(
            "Blocklist server returned an error status: {}",
            resp.status
        ));
    }
    let body = resp
        .into_string()
        .map_err(|error| format!("Could not read the blocklist response: {error}"))?;
    if body.trim().is_empty() || looks_like_error_document(&body) {
        return Err("Blocklist body is empty or an HTML error page".to_string());
    }
    let rules = count_list_rules(&body);
    if rules == 0 {
        return Err("Blocklist has no valid rules".to_string());
    }
    onetdns_core::debug!(event = "filter.subscription_downloaded", %url, lines = rules, "Downloaded blocklist");
    let updated_unix = unix_now();
    save_blocklist_cache_text(url, updated_unix, &body, cache_dir)?;

    let lines: Vec<String> = if cache_dir.is_some() {
        Vec::new()
    } else {
        body.lines().map(str::to_string).collect()
    };
    Ok(SubMeta {
        url: url.to_string(),
        title: parse_list_title(&body),
        rules,
        updated_unix,
        lines: lines.into(),
    })
}

fn blocklist_cache_key(url: &str) -> String {
    let mut h = 0xcbf29ce484222325u64;
    for b in url.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}.list")
}

fn save_blocklist_cache_text(
    url: &str,
    updated_unix: u64,
    text: &str,
    dir: Option<&std::path::Path>,
) -> Result<(), String> {
    let Some(dir) = dir else {
        return Ok(());
    };
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("Could not create the blocklist cache directory: {e}"))?;
    let path = dir.join(blocklist_cache_key(url));
    let mut body = format!("# onetdns-url:{url}\n# onetdns-updated:{updated_unix}\n");
    body.reserve(text.len() + 1);
    for line in text.lines() {
        body.push_str(line);
        body.push('\n');
    }

    atomic_write(&path, body.as_bytes())
        .map_err(|e| format!("Could not save the blocklist cache ({url}): {e}"))
}

/// Lets the server start with the last lists when downloads fail.
pub(crate) fn load_blocklist_cache(urls: &[String], dir: Option<&std::path::Path>) -> Vec<SubMeta> {
    let Some(dir) = dir else {
        return Vec::new();
    };
    urls.iter()
        .filter_map(|url| {
            let text =
                read_text_limited(&dir.join(blocklist_cache_key(url)), BLOCKLIST_MAX_RESPONSE)
                    .ok()?;
            let mut parts = text.splitn(3, '\n');
            let stored_url = parts
                .next()?
                .trim_end_matches('\r')
                .strip_prefix("# onetdns-url:")?;
            if stored_url != url {
                return None;
            }
            let updated_unix = parts
                .next()
                .map(|line| line.trim_end_matches('\r'))
                .and_then(|v| v.strip_prefix("# onetdns-updated:"))
                .and_then(|v| v.parse().ok())?;
            let body = parts.next()?;
            let rules = count_list_rules(body);
            let title = parse_list_title(body);

            (rules > 0).then(|| SubMeta {
                url: url.clone(),
                title,
                rules,
                updated_unix,
                lines: Vec::new().into(),
            })
        })
        .collect()
}

pub(crate) fn fetch_blocklists_meta(
    urls: &[String],
    resolver: &http::HostResolver,
    previous: &[SubMeta],
    cache_dir: Option<&std::path::Path>,
) -> Vec<SubMeta> {
    let previous_by_url: std::collections::HashMap<&str, &SubMeta> = previous
        .iter()
        .map(|item| (item.url.as_str(), item))
        .collect();
    let mut meta = Vec::new();
    for url in urls {
        match fetch_blocklist(url, resolver, cache_dir) {
            Ok(item) => meta.push(item),
            Err(error) => {
                if let Some(old) = previous_by_url.get(url.as_str()) {
                    onetdns_core::warn!(event = "filter.subscription_refresh_failed_kept", %url, %error, retained_rules = old.rules, "Could not update blocklist; keeping the previous list");
                    meta.push((*old).clone());
                } else {
                    onetdns_core::warn!(event = "filter.subscription_refresh_failed", %url, %error, "Could not update blocklist");
                    meta.push(SubMeta {
                        url: url.clone(),
                        title: String::new(),
                        rules: 0,
                        updated_unix: 0,
                        lines: Vec::new().into(),
                    });
                }
            }
        }
    }
    meta
}

fn rpz_cache_key(url: &str) -> String {
    format!("{}.rpz", blocklist_cache_key(url).trim_end_matches(".list"))
}

fn save_rpz_cache(url: &str, body: &str, dir: Option<&std::path::Path>) -> Result<(), String> {
    let Some(dir) = dir else {
        return Ok(());
    };
    std::fs::create_dir_all(dir)
        .map_err(|error| format!("Could not create the RPZ cache directory: {error}"))?;
    let mut cached = format!(
        "# onetdns-rpz-url:{url}\n# onetdns-updated:{}\n",
        unix_now()
    );
    cached.push_str(body);
    if !cached.ends_with('\n') {
        cached.push('\n');
    }
    atomic_write(&dir.join(rpz_cache_key(url)), cached.as_bytes())
        .map_err(|error| format!("Could not save the RPZ cache ({url}): {error}"))
}

pub(crate) fn load_rpz_cache(urls: &[String], dir: Option<&std::path::Path>) -> Vec<String> {
    let Some(dir) = dir else {
        return vec![String::new(); urls.len()];
    };
    urls.iter()
        .map(|url| {
            let Ok(text) = read_text_limited(&dir.join(rpz_cache_key(url)), BLOCKLIST_MAX_RESPONSE)
            else {
                return String::new();
            };
            let mut lines = text.lines();
            let Some(stored_url) = lines
                .next()
                .and_then(|line| line.strip_prefix("# onetdns-rpz-url:"))
            else {
                return String::new();
            };
            if stored_url != url {
                return String::new();
            }
            let updated = lines
                .next()
                .and_then(|line| line.strip_prefix("# onetdns-updated:"))
                .and_then(|value| value.parse::<u64>().ok());
            if updated.is_none() {
                return String::new();
            }
            let body = lines.collect::<Vec<_>>().join("\n");
            if body.trim().is_empty()
                || looks_like_error_document(&body)
                || likely_rpz_rule_count(&body) == 0
            {
                String::new()
            } else {
                body
            }
        })
        .collect()
}

/// Pairs the kept RPZ texts with the new URL list by URL, one per URL and empty for a URL never
/// fetched. Pairing by position would give a failed URL the rules of the list that moved into
/// its slot after a removal.
pub(crate) fn rpz_texts_by_url(
    old_urls: &[String],
    old_texts: &[String],
    urls: &[String],
) -> Vec<String> {
    urls.iter()
        .map(|url| {
            old_urls
                .iter()
                .position(|old| old == url)
                .and_then(|index| old_texts.get(index))
                .cloned()
                .unwrap_or_default()
        })
        .collect()
}

pub(crate) fn fetch_rpz_texts(
    urls: &[String],
    resolver: &http::HostResolver,
    previous: &[String],
    cache_dir: Option<&std::path::Path>,
) -> Vec<String> {
    let mut out = Vec::with_capacity(urls.len());
    for (index, url) in urls.iter().enumerate() {
        let fetched = http::get(url)
            .timeout(Duration::from_secs(120))
            .max_response(BLOCKLIST_MAX_RESPONSE)
            .resolver(resolver.clone())
            .deny_private_targets()
            .call()
            .and_then(|resp| {
                if !(200..300).contains(&resp.status) {
                    return Err(http::HttpError::Protocol(format!(
                        "HTTP status {}",
                        resp.status
                    )));
                }
                resp.into_string()
            });
        match fetched {
            Ok(body)
                if !body.trim().is_empty()
                    && !looks_like_error_document(&body)
                    && likely_rpz_rule_count(&body) > 0 =>
            {
                onetdns_core::debug!(event = "filter.rpz_downloaded", %url, bytes = body.len(), "Downloaded RPZ rules");
                if let Err(error) = save_rpz_cache(url, &body, cache_dir) {
                    onetdns_core::warn!(event = "filter.rpz_cache_save_failed", %url, %error, "Could not save the RPZ cache file");
                }
                out.push(body);
            }
            Ok(_) => {
                if let Some(old) = previous.get(index) {
                    onetdns_core::warn!(event = "filter.rpz_empty_kept", %url, "Downloaded RPZ data has no usable rules; keeping the previous rules");
                    out.push(old.clone());
                } else {
                    onetdns_core::warn!(event = "filter.rpz_empty", %url, "Downloaded RPZ data has no usable rules");
                    out.push(String::new());
                }
            }
            Err(error) => {
                if let Some(old) = previous.get(index) {
                    onetdns_core::warn!(event = "filter.rpz_refresh_failed_kept", %url, %error, "Could not update RPZ rules; keeping the previous rules");
                    out.push(old.clone());
                } else {
                    onetdns_core::warn!(event = "filter.rpz_download_failed", %url, %error, "Could not download RPZ rules");
                    out.push(String::new());
                }
            }
        }
    }
    out
}

fn merge_config_filters(
    parts: &mut EngineParts,
    rewrites: &[Rewrite],
    local_zones: &[LocalZone],
    refused_domains: &[String],
    rpz_files: &[PathBuf],
) -> Result<(), String> {
    for h in refused_domains {
        parts.refuse.add_suffix(h);
    }
    for (index, rw) in rewrites.iter().enumerate() {
        let target = parse_rewrite_answer(&rw.answer).ok_or_else(|| {
            format!("rewrites[{index}].answer needs a valid IP address or DNS name")
        })?;
        add_rewrite(parts, &rw.domain, target)
            .map_err(|error| format!("rewrites[{index}].domain: {error}"))?;
    }
    for (index, lz) in local_zones.iter().enumerate() {
        apply_local_zone(parts, lz).map_err(|error| format!("local_zones[{index}]: {error}"))?;
    }
    for f in rpz_files {
        let text = read_text_limited(f, BLOCKLIST_MAX_RESPONSE)
            .map_err(|error| format!("Could not read the RPZ file ({}): {error}", f.display()))?;
        onetdns_filter::parse_rpz_text(&text, parts);
    }
    Ok(())
}

fn parse_rewrite_answer(answer: &str) -> Option<RewriteTarget> {
    let a = answer.trim();
    if let Ok(ip) = a.parse::<IpAddr>() {
        Some(RewriteTarget::ip(ip))
    } else {
        onetdns_proto::Name::from_str(a)
            .ok()
            .map(RewriteTarget::Cname)
    }
}

fn add_rewrite(parts: &mut EngineParts, domain: &str, target: RewriteTarget) -> Result<(), String> {
    let domain = domain.trim();
    let parsed = domain.strip_prefix("*.").unwrap_or(domain);
    if parsed.is_empty() || parsed.contains('*') || onetdns_proto::Name::from_str(parsed).is_err() {
        return Err("Not a valid exact name or `*.subdomain` pattern".to_string());
    }
    if domain.starts_with("*.") {
        parts.rewrites.add_suffix(domain, target);
    } else {
        parts.rewrites.add_exact(domain, target);
    }
    Ok(())
}

fn local_answer_target(answer: &onetdns_config::LocalAnswer) -> Result<RewriteTarget, String> {
    Ok(match answer {
        onetdns_config::LocalAnswer::Addresses(ips) => RewriteTarget::Records(
            ips.iter()
                .map(|ip| match ip {
                    IpAddr::V4(v4) => onetdns_proto::RData::A(*v4),
                    IpAddr::V6(v6) => onetdns_proto::RData::Aaaa(*v6),
                })
                .collect(),
        ),
        onetdns_config::LocalAnswer::Alias(name) => RewriteTarget::Cname(
            onetdns_proto::Name::from_str(name)
                .map_err(|_| format!("CNAME target '{name}' is not a valid DNS name"))?,
        ),
    })
}

/// Only the most specific local zone applies to a name, so a transparent zone lifts the
/// enclosing local zone's action and leaves blocklists and user rules alone.
fn apply_local_zone(parts: &mut EngineParts, lz: &LocalZone) -> Result<(), String> {
    if onetdns_proto::Name::from_str(lz.name.trim()).is_err() {
        return Err("name needs a valid DNS zone name".to_string());
    }
    let action = match lz.kind {
        LocalZoneKind::Deny => LocalZoneAction::Deny,
        LocalZoneKind::Refuse => LocalZoneAction::Refuse,
        LocalZoneKind::Transparent => LocalZoneAction::Transparent,
        LocalZoneKind::AlwaysNull => LocalZoneAction::Rewrite(RewriteTarget::Records(vec![
            onetdns_proto::RData::A(Ipv4Addr::UNSPECIFIED),
            onetdns_proto::RData::Aaaa(Ipv6Addr::UNSPECIFIED),
        ])),
        LocalZoneKind::Redirect => {
            let answers = lz.answers()?;
            let [(_, answer)] = answers.as_slice() else {
                return Err(
                    "A redirect zone must have answers only for the zone name itself".to_string(),
                );
            };
            LocalZoneAction::Rewrite(local_answer_target(answer)?)
        }
        LocalZoneKind::Static => {
            let mut data = StaticZone::new(&lz.name);
            for (name, answer) in lz.answers()? {
                data.insert(&name, local_answer_target(&answer)?)?;
            }
            LocalZoneAction::Static(data)
        }
    };
    parts.local_zones.insert(&lz.name, action)
}

/// How often the refresh threads wake to notice a changed list before the period ends.
pub(crate) const LIST_REFRESH_TICK_SECS: u64 = 5;

/// A schedule boundary is noticed up to this late.
pub(crate) const SERVICE_SCHEDULE_TICK_SECS: u64 = 20;

/// Startup and reload both use this, so the presets read back the same after a reload.
pub(crate) fn preset_list_urls(cfg: &Config) -> Vec<String> {
    let mut urls = Vec::new();
    if cfg.safe_browsing {
        urls.extend(
            onetdns_filter::presets::SAFE_BROWSING_LISTS
                .iter()
                .map(|value| value.to_string()),
        );
    }
    if cfg.parental_control {
        urls.extend(
            onetdns_filter::presets::PARENTAL_LISTS
                .iter()
                .map(|value| value.to_string()),
        );
    }
    urls.sort();
    urls.dedup();
    urls
}

pub(crate) const LIST_REFRESH_BUSY: &str = "A blocklist update is already running";

pub(crate) fn try_list_refresh_lock(
    lock: &Mutex<()>,
) -> Result<std::sync::MutexGuard<'_, ()>, String> {
    match lock.try_lock() {
        Ok(guard) => Ok(guard),
        Err(std::sync::TryLockError::Poisoned(error)) => Ok(error.into_inner()),
        Err(std::sync::TryLockError::WouldBlock) => Err(LIST_REFRESH_BUSY.to_string()),
    }
}

/// The setting that turns this preset on, so the dashboard can point to it.
pub(crate) fn preset_list_kind(url: &str) -> &'static str {
    if onetdns_filter::presets::PARENTAL_LISTS.contains(&url) {
        "parental_control"
    } else {
        "safe_browsing"
    }
}

/// Enabled lists, then presets, without duplicates and in order.
pub(crate) fn active_subscription_urls(
    urls: &[String],
    disabled: &[String],
    presets: &[String],
) -> Vec<String> {
    let mut active: Vec<String> = urls
        .iter()
        .filter(|url| !disabled.iter().any(|blocked| blocked == *url))
        .cloned()
        .collect();
    for preset in presets {
        active.push(preset.clone());
    }
    let mut seen = std::collections::HashSet::new();
    active.retain(|url| seen.insert(url.clone()));
    active
}

pub(crate) fn persist_subscription_state(
    path: Option<&std::path::Path>,
    urls: &[String],
    titles: &[String],
    disabled: &[String],
) -> Result<(), String> {
    let Some(p) = path else {
        return Err("There is no configuration file path".to_string());
    };
    let text =
        onetdns_core::SecretString::from(Config::read_text(p).map_err(|error| error.to_string())?);
    let text = onetdns_core::SecretString::from(rewrite_config_kv(
        &text,
        "blocklist_urls",
        &toml_string_array(urls),
    )?);
    let text = onetdns_core::SecretString::from(rewrite_config_kv(
        &text,
        "blocklist_titles",
        &toml_string_array(titles),
    )?);
    let text = onetdns_core::SecretString::from(rewrite_config_kv(
        &text,
        "disabled_blocklist_urls",
        &toml_string_array(disabled),
    )?);
    atomic_write(p, text.as_bytes()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::sync::Mutex;

    use onetdns_config::{Config, LocalZone, LocalZoneKind, Rewrite};
    use onetdns_core::{MutexExt, RewriteTarget};
    use onetdns_filter::{BlockEngine, EngineParts};

    use crate::ensure_resolution_sources_not_self;

    #[test]
    fn compiled_filter_cache_streams_atomically_and_loads() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "onetdns-compiled-filter-cache-{}-{unique}",
            std::process::id()
        ));
        let path = dir.join("filters.bin");
        let fingerprint = [0x5a; 32];
        let mut parts = EngineParts::default();
        parts.block.add_suffix("blocked.example");

        save_compiled_filter_cache(&path, &mut parts, fingerprint);
        let restored = load_compiled_filter_cache(&path, fingerprint).unwrap();
        assert!(restored.block.matches("child.blocked.example"));
        assert!(!restored.block.matches("allowed.example"));
        assert!(load_compiled_filter_cache(&path, [0xa5; 32]).is_none());

        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn invalid_rewrite_and_local_zone_cannot_disappear_silently() {
        let mut parts = EngineParts::default();
        let rewrites = vec![Rewrite {
            domain: "router.example".to_string(),
            answer: "bad..answer".to_string(),
        }];
        assert!(merge_config_filters(&mut parts, &rewrites, &[], &[], &[]).is_err());

        let zones = vec![LocalZone {
            name: "local".to_string(),
            kind: LocalZoneKind::Static,
            records: vec![
                "local 192.0.2.1".to_string(),
                "local target.example".to_string(),
            ],
        }];
        assert!(merge_config_filters(&mut parts, &[], &zones, &[], &[]).is_err());
    }

    #[test]
    /// Loading a static zone like a redirect would answer unlisted names with the same address.
    fn static_local_zone_from_config_answers_listed_names_only() {
        let zones = vec![LocalZone {
            name: "corp.example".to_string(),
            kind: LocalZoneKind::Static,
            records: vec![
                "www.corp.example 192.0.2.2".to_string(),
                "mail.corp.example www.corp.example".to_string(),
            ],
        }];
        let mut parts = EngineParts::default();
        merge_config_filters(&mut parts, &[], &zones, &[], &[]).unwrap();
        let engine = BlockEngine::new(parts, onetdns_core::BlockResponse::ZeroIp);
        let client = onetdns_core::ClientInfo {
            source_ip: "127.0.0.1".parse().unwrap(),
            client_id: None,
            transport: onetdns_core::Transport::Do53Udp,
            authenticated: false,
        };
        let verdict = |q: &str| {
            onetdns_core::FilterEngine::verdict(
                &engine,
                &onetdns_proto::Name::from_str(q).unwrap(),
                onetdns_proto::RecordType::A,
                &client,
            )
        };
        assert!(matches!(
            verdict("www.corp.example"),
            onetdns_core::FilterVerdict::Rewrite(RewriteTarget::Records(_))
        ));
        assert!(matches!(
            verdict("mail.corp.example"),
            onetdns_core::FilterVerdict::Rewrite(RewriteTarget::Cname(_))
        ));
        assert!(matches!(
            verdict("other.corp.example"),
            onetdns_core::FilterVerdict::Block(onetdns_core::BlockResponse::NxDomain)
        ));
        assert!(matches!(
            verdict("corp.example"),
            onetdns_core::FilterVerdict::Block(onetdns_core::BlockResponse::NoData)
        ));
    }

    #[test]
    /// A no-op transparent zone would silently ignore lifting a deny zone; lifting blocklists too
    /// would disable the subscribed lists.
    fn transparent_local_zone_lifts_enclosing_local_zone_only() {
        let zone = |name: &str, kind| LocalZone {
            name: name.to_string(),
            kind,
            records: vec![],
        };
        let zones = vec![
            zone("corp.example", LocalZoneKind::Deny),
            zone("api.corp.example", LocalZoneKind::Transparent),
            zone("ads.api.corp.example", LocalZoneKind::Transparent),
        ];
        let no_lists: [PathBuf; 0] = [];
        let mut parts = onetdns_filter::load_parts_with_subscriptions(
            &no_lists,
            &no_lists,
            &[],
            &["||ads.api.corp.example^"],
            &[],
        )
        .unwrap();
        merge_config_filters(&mut parts, &[], &zones, &[], &[]).unwrap();
        let engine = BlockEngine::new(parts, onetdns_core::BlockResponse::NxDomain);
        let client = onetdns_core::ClientInfo {
            source_ip: "127.0.0.1".parse().unwrap(),
            client_id: None,
            transport: onetdns_core::Transport::Do53Udp,
            authenticated: false,
        };
        let verdict = |q: &str| {
            onetdns_core::FilterEngine::verdict(
                &engine,
                &onetdns_proto::Name::from_str(q).unwrap(),
                onetdns_proto::RecordType::A,
                &client,
            )
        };
        assert!(matches!(
            verdict("www.corp.example"),
            onetdns_core::FilterVerdict::Block(_)
        ));
        assert!(matches!(
            verdict("v1.api.corp.example"),
            onetdns_core::FilterVerdict::Allow
        ));
        assert!(matches!(
            verdict("ads.api.corp.example"),
            onetdns_core::FilterVerdict::Block(_)
        ));
    }

    #[test]
    fn invalid_filter_sources_and_services_cannot_fail_open() {
        assert!(expand_services(&["unknown-service".to_string()]).is_err());

        let mut config = Config::default();
        config.blocklists.push(std::env::temp_dir().join(format!(
            "onetdns-missing-filter-{}-{}.list",
            std::process::id(),
            line!()
        )));
        let input = FilterBuildInputs {
            blocked_services: &[],
            subscriptions: &[],
            overlay_block: &[],
            overlay_allow: &[],
            refused_domains: &[],
            rpz_texts: &[],
            compiled_filter_cache: None,
            subscription_cache_dir: None,
        };
        assert!(build_filter_engine_for_config(&config, &input).is_err());

        config.blocklists.clear();
        config.clients.push(onetdns_config::ClientConfig {
            name: "restricted".to_string(),
            blocked_services: vec!["unknown-service".to_string()],
            ..Default::default()
        });
        assert!(build_filter_engine_for_config(&config, &input).is_err());
    }

    #[test]
    fn service_schedule_pauses_only_service_rules() {
        let services = vec!["youtube".to_string()];
        let kept = vec!["||kept.example^".to_string()];
        let input = FilterBuildInputs {
            blocked_services: &services,
            subscriptions: &[],
            overlay_block: &kept,
            overlay_allow: &[],
            refused_domains: &[],
            rpz_texts: &[],
            compiled_filter_cache: None,
            subscription_cache_dir: None,
        };
        let mut config = Config::default();
        let blocking = build_filter_engine_for_config(&config, &input)
            .unwrap()
            .block_count();

        config.service_schedule = ["00:00", "12:00"]
            .iter()
            .zip(["12:00", "00:00"])
            .map(|(start, end)| onetdns_config::ScheduleWindow {
                days: vec!["all".to_string()],
                start: start.to_string(),
                end: end.to_string(),
            })
            .collect();
        assert!(service_blocking_paused(
            &config,
            std::time::SystemTime::now()
        ));
        let paused = build_filter_engine_for_config(&config, &input)
            .unwrap()
            .block_count();
        assert!(paused < blocking, "{paused} < {blocking}");
        assert!(paused >= 1, "사용자 규칙은 남아야 한다");
    }

    #[test]
    fn user_rule_mutation_validates_and_classifies() {
        let overlay: Mutex<(Vec<String>, Vec<String>)> = Mutex::new((vec![], vec![]));
        let rebuild = || Ok((0usize, 0usize));

        mutate_user_rule(&overlay, None, &rebuild, "@@||ok.example.com^", false, true).unwrap();
        {
            let ov = overlay.lock().unwrap();
            assert!(ov.0.is_empty(), "차단 목록은 비어 있어야 함");
            assert_eq!(ov.1, vec!["@@||ok.example.com^".to_string()]);
        }

        mutate_user_rule(&overlay, None, &rebuild, "||ads.example.com^", false, true).unwrap();
        assert_eq!(
            overlay.lock().unwrap().0,
            vec!["||ads.example.com^".to_string()]
        );

        let e = mutate_user_rule(
            &overlay,
            None,
            &rebuild,
            "||x.example.com^$app=org.example",
            false,
            true,
        )
        .unwrap_err();
        assert!(e.contains("app"), "사유에 수식어 이름 포함: {e}");

        mutate_user_rule(
            &overlay,
            None,
            &rebuild,
            "@@||ok.example.com^",
            false,
            false,
        )
        .unwrap();
        assert!(overlay.lock().unwrap().1.is_empty());
    }

    #[test]
    fn rpz_texts_follow_their_url_after_removal() {
        let old_urls = vec!["https://a/".to_string(), "https://b/".to_string()];
        let old_texts = vec!["A".to_string(), "B".to_string()];
        assert_eq!(
            rpz_texts_by_url(&old_urls, &old_texts, &["https://b/".to_string()]),
            vec!["B".to_string()]
        );
        assert_eq!(
            rpz_texts_by_url(&old_urls, &old_texts, &["https://c/".to_string()]),
            vec![String::new()]
        );
        assert!(rpz_texts_by_url(&old_urls, &old_texts, &[]).is_empty());
    }

    #[test]
    fn active_subscription_urls_are_unique_and_keep_order() {
        let urls = vec![
            "https://big.oisd.nl".to_string(),
            "https://big.oisd.nl".to_string(),
            "https://example.test/list.txt".to_string(),
        ];
        let disabled = vec!["https://example.test/list.txt".to_string()];
        let presets = vec![
            "https://big.oisd.nl".to_string(),
            "https://preset.test/list.txt".to_string(),
        ];
        assert_eq!(
            active_subscription_urls(&urls, &disabled, &presets),
            vec![
                "https://big.oisd.nl".to_string(),
                "https://preset.test/list.txt".to_string(),
            ]
        );
    }

    #[test]
    /// Asking this machine would loop while the server is starting.
    fn revocation_dns_servers_never_include_loopback() {
        let mut config = Config::default();
        config.bootstrap = vec![
            "127.0.0.1".parse().unwrap(),
            "::1".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
        ];
        assert_eq!(
            revocation_dns_servers(&config),
            vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn wildcard_listener_rejects_local_interface_resolution_sources() {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        if socket.connect("192.0.2.1:9").is_err() {
            return;
        }
        let local_ip = socket.local_addr().unwrap().ip();
        if local_ip.is_loopback() || local_ip.is_unspecified() {
            return;
        }

        let mut config = Config::default();
        config.listen = vec!["0.0.0.0:53".parse().unwrap()];
        config.bootstrap = vec![local_ip];
        assert!(ensure_resolution_sources_not_self(&config).is_err());

        config.bootstrap.clear();
        config.root_hints = vec![local_ip];
        assert!(ensure_resolution_sources_not_self(&config).is_err());

        config.root_hints.clear();
        config.upstreams = vec![local_ip];
        assert!(ensure_resolution_sources_not_self(&config).is_err());
        assert!(revocation_dns_servers(&config).is_empty());
    }

    #[test]
    /// `bootstrap` points nowhere, so a lookup sent there would fail.
    fn blocklist_hosts_resolve_through_the_upstreams_not_bootstrap() {
        let upstream = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = upstream.recv_from(&mut buf) {
                let Ok(request) = onetdns_proto::Message::parse(&buf[..n]) else {
                    continue;
                };
                let mut response = onetdns_proto::Message::default();
                response.header.id = request.header.id;
                response.header.response = true;
                response.header.recursion_desired = request.header.recursion_desired;
                response.header.recursion_available = true;
                response.questions = request.questions.clone();
                if let Some(question) = request
                    .questions
                    .first()
                    .filter(|question| question.qtype == onetdns_proto::RecordType::A)
                {
                    response.answers.push(onetdns_proto::Record::new(
                        question.name.clone(),
                        60,
                        onetdns_proto::RData::A(Ipv4Addr::new(192, 0, 2, 7)),
                    ));
                }
                let _ = upstream.send_to(&response.try_encode().unwrap(), from);
            }
        });

        let mut config = Config::default();
        config.upstream_urls = vec![format!("udp://127.0.0.1:{port}")];
        config.bootstrap = vec!["192.0.2.1".parse().unwrap()];
        let resolve = blocklist_host_resolver(&config);
        assert_eq!(
            resolve("lists.example", Duration::from_secs(2)),
            Ok(vec![IpAddr::from([192, 0, 2, 7])])
        );
    }

    #[test]
    fn blocklist_host_lookups_stop_at_the_callers_timeout() {
        // Bound but never read, so queries go unanswered instead of being refused.
        let upstream = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut config = Config::default();
        config.upstream_urls = vec![format!("udp://{}", upstream.local_addr().unwrap())];
        let resolve = blocklist_host_resolver(&config);
        let started = std::time::Instant::now();
        let result = resolve("lists.example", Duration::from_millis(300));
        assert!(started.elapsed() < Duration::from_secs(2), "{result:?}");
        assert!(result.unwrap_err().contains("did not answer in time"));
        drop(upstream);
    }

    #[test]
    fn blocklist_cache_restores_title_from_content() {
        let dir = std::env::temp_dir().join(format!("onetdns-blcache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let url = "https://example.test/list.txt".to_string();
        let item = SubMeta {
            url: url.clone(),
            title: "예시 차단 목록".to_string(),
            rules: 2,
            updated_unix: 12345,
            lines: vec![
                "! Title: 예시 차단 목록".to_string(),
                "||ads.example.com^".to_string(),
                "||track.example.net^".to_string(),
            ]
            .into(),
        };
        save_blocklist_cache_text(
            &item.url,
            item.updated_unix,
            &item.lines.join(
                "
    ",
            ),
            Some(&dir),
        )
        .expect("cache 저장");
        let loaded = load_blocklist_cache(std::slice::from_ref(&url), Some(&dir));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(loaded.len(), 1);

        assert_eq!(loaded[0].title, "예시 차단 목록");
        assert_eq!(loaded[0].rules, 2);
        assert_eq!(loaded[0].updated_unix, 12345);

        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(blocklist_cache_key(&url)),
            format!("# onetdns-url:{url}\n||ads.example.com^\n"),
        )
        .unwrap();
        assert!(load_blocklist_cache(std::slice::from_ref(&url), Some(&dir)).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rpz_cache_requires_the_complete_current_header() {
        let dir = std::env::temp_dir().join(format!("onetdns-rpzcache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let url = "https://example.test/policy.rpz".to_string();
        save_rpz_cache(&url, "bad.example CNAME .\n", Some(&dir)).unwrap();
        let loaded = load_rpz_cache(std::slice::from_ref(&url), Some(&dir));
        assert!(loaded[0].contains("bad.example"));

        std::fs::write(
            dir.join(rpz_cache_key(&url)),
            format!("# onetdns-rpz-url:{url}\nbad.example CNAME .\n"),
        )
        .unwrap();
        assert!(load_rpz_cache(std::slice::from_ref(&url), Some(&dir))[0].is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    /// A changed fingerprint would recompile the engine on every start.
    fn compiled_fingerprint_survives_releasing_subscription_lines() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-compiled-fingerprint-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let item = SubMeta {
            url: "https://example.test/large.txt".into(),
            title: "large".into(),
            rules: 2,
            updated_unix: 42,
            lines: vec!["||ads.example^".to_string(), "||track.example^".to_string()].into(),
        };
        save_blocklist_cache_text(
            &item.url,
            item.updated_unix,
            &item.lines.join(
                "
    ",
            ),
            Some(&dir),
        )
        .unwrap();
        let meta = Mutex::new(vec![item]);
        let calculate = |subscriptions: &[SubMeta]| {
            compiled_filter_fingerprint(&CompiledFilterInputs {
                blocklists: &[],
                allowlists: &[],
                service_rules: &[],
                subscriptions,
                subscription_cache_dir: Some(&dir),
                overlay_block: &[],
                overlay_allow: &[],
                rewrites: &[],
                local_zones: &[],
                refused_domains: &[],
                rpz_files: &[],
                rpz_texts: &[],
            })
        };
        let before = calculate(&meta.lock_recover());
        release_subscription_lines(&meta, &dir);
        let after = calculate(&meta.lock_recover());

        let guard = meta.lock_recover();
        assert!(guard[0].lines.is_empty());
        assert_eq!(guard[0].rules, 2);
        assert_eq!(before, after);
        drop(guard);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
