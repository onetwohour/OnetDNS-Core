/*!
 * @brief 차단 목록을 받아 오고 캐시하며, 설정과 합쳐 필터 엔진을 만든다.
 */

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use onetdns_config::{Config, LocalZone, LocalZoneKind, Rewrite};
use onetdns_core::{MutexExt, RewriteTarget};
use onetdns_filter::{BlockEngine, EngineParts, LocalZoneAction, StaticZone};
use sha2::{Digest, Sha256};

use crate::atomic_file::{atomic_write, atomic_write_with, with_rollback_result};
use crate::config_apply::config_write_lock;
use crate::config_edit::{rewrite_config_kv, rewrite_config_string_array, toml_string_array};
use crate::native_config::{days_mask, map_block, parse_hhmm};
use crate::recursion::{new_recursor, recursor_roots};
use crate::{http, mac, native, read_text_limited, unix_now, upstream};

/** @brief 사용자가 넣은 규칙을 고친다. 형식을 확인하고 종류를 구분한다. */
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
        return Err("`rule` 항목을 입력해야 합니다".to_string());
    }
    if add {
        onetdns_filter::validate_rule(rule)
            .map_err(|reason| format!("유효하지 않은 규칙: {reason}"))?;
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
                        return Err("실행 상태를 갱신하는 동안 설정 파일이 다시 변경되어 자동으로 되돌리지 않았습니다".to_string());
                    }
                    atomic_write(&path, previous_text.as_bytes())
                        .map_err(|rollback_error| rollback_error.to_string())
                })();
                with_rollback_result(
                    error,
                    "규칙 설정을 이전 값으로 되돌리지 못했습니다",
                    rollback,
                )
            } else {
                error
            };
            Err(error)
        }
    }
}

/** @brief 서비스 이름을 그것이 쓰는 도메인 목록으로 편다. */
fn expand_services(services: &[String]) -> Result<Vec<String>, String> {
    let mut out = vec![];
    for svc in services {
        let rules = onetdns_filter::services::service_rules(svc)
            .ok_or_else(|| format!("지원하지 않는 서비스 차단 항목입니다: {svc}"))?;
        out.extend(rules.iter().map(|rule| (*rule).to_string()));
    }
    Ok(out)
}

#[derive(Clone)]
/** @brief 내려받은 목록 하나의 정보. */
pub(crate) struct SubMeta {
    /** @brief 내려받은 곳. */
    pub(crate) url: String,
    /** @brief 목록에 적힌 제목. */
    pub(crate) title: String,
    /** @brief 이 목록에 든 규칙 수. */
    pub(crate) rules: usize,
    /** @brief 마지막으로 내려받은 시각. */
    pub(crate) updated_unix: u64,

    /** @brief 규칙 원문 줄들. 고정한 뒤에는 놓아준다. */
    lines: Arc<[String]>,
}

/** @brief 차단 엔진을 만드는 데 드는 것들. */
pub(crate) struct FilterBuildInputs<'a> {
    /** @brief 차단할 서비스 이름들. */
    pub(crate) blocked_services: &'a [String],
    /** @brief 내려받은 목록들. */
    pub(crate) subscriptions: &'a [SubMeta],
    /** @brief 설정에 적은 차단 규칙. */
    pub(crate) overlay_block: &'a [String],
    /** @brief 설정에 적은 허용 규칙. */
    pub(crate) overlay_allow: &'a [String],
    /** @brief REFUSED로 답할 도메인 접미사. */
    pub(crate) refused_domains: &'a [String],
    /** @brief 영역 형식 목록 글. */
    pub(crate) rpz_texts: &'a [String],
    /** @brief 고정한 결과를 담아 둘 곳. */
    pub(crate) compiled_filter_cache: Option<&'a std::path::Path>,
    /** @brief 내려받은 목록을 담아 둘 곳. */
    pub(crate) subscription_cache_dir: Option<&'a std::path::Path>,
}

/**
 * @brief 지금이 서비스 차단을 멈추는 시간대인지.
 * @details service_schedule의 구간 안에서는 서비스 차단 규칙만 빠진다. 차단 목록과 사용자
 *          규칙은 그대로 건다. 설정 검증을 통과한 구간만 들어오므로 읽지 못하는 구간은 없다.
 */
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

/**
 * @brief 설정대로 차단 엔진을 만든다.
 * @details 내려받은 목록, 파일, 설정에 적은 규칙을 모두 모아 하나로 고정한다. 고정하면
 *          질의 경로에서 잠금도 할당도 없다.
 */
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
        onetdns_core::debug!(
            event = "filter.cache_loaded",
            "미리 만들어 둔 차단 목록을 읽었습니다"
        );
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
                    "구독 캐시 파일이 없어 이 차단 목록의 규칙을 적용하지 못합니다"
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

/** @brief 고정한 결과가 어떤 입력에서 나왔는지. */
struct CompiledFilterInputs<'a> {
    /** @brief 차단 목록 파일들. */
    blocklists: &'a [PathBuf],
    /** @brief 허용 목록 파일들. */
    allowlists: &'a [PathBuf],
    /** @brief 서비스에서 편 규칙들. */
    service_rules: &'a [String],
    /** @brief 내려받은 목록들. */
    subscriptions: &'a [SubMeta],
    /** @brief 내려받은 목록을 담아 둔 곳. */
    subscription_cache_dir: Option<&'a std::path::Path>,
    /** @brief 설정에 적은 차단 규칙. */
    overlay_block: &'a [String],
    /** @brief 설정에 적은 허용 규칙. */
    overlay_allow: &'a [String],
    /** @brief 재작성 규칙. */
    rewrites: &'a [Rewrite],
    /** @brief 영역 규칙. */
    local_zones: &'a [LocalZone],
    /** @brief REFUSED로 답할 도메인 접미사. */
    refused_domains: &'a [String],
    /** @brief 영역 형식 목록 파일들. */
    rpz_files: &'a [PathBuf],
    /** @brief 영역 형식 목록 글. */
    rpz_texts: &'a [String],
}

/** @brief 입력의 지문. 지문이 같아야 고정해 둔 것을 다시 쓸 수 있다. */
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

/** @brief 고정한 뒤 원본 줄들을 놓아준다. 고정한 것만 있으면 되므로 그만큼 메모리가 준다. */
pub(crate) fn release_subscription_lines(meta: &Mutex<Vec<SubMeta>>, cache_dir: &std::path::Path) {
    for item in meta.lock_recover().iter_mut() {
        if cache_dir.join(blocklist_cache_key(&item.url)).is_file() {
            item.lines = Vec::new().into();
        }
    }
}

/** @brief 지문에 항목 헤더를 넣는다. */
fn fingerprint_header(digest: &mut Sha256, label: &[u8], count: u64) {
    digest.update((label.len() as u64).to_le_bytes());
    digest.update(label);
    digest.update(count.to_le_bytes());
}

/** @brief 지문에 바이트를 넣는다. */
fn fingerprint_bytes(digest: &mut Sha256, label: &[u8], bytes: &[u8]) {
    fingerprint_header(digest, label, bytes.len() as u64);
    digest.update(bytes);
}

/** @brief 지문에 문자열들을 넣는다. */
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

/** @brief 지문에 파일 내용을 넣는다. */
fn fingerprint_files(digest: &mut Sha256, label: &[u8], paths: &[PathBuf]) {
    use std::io::Read;

    /** @brief 읽어들일 목록 파일 크기 상한. */
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

/** @brief 고정해 둔 것을 읽는다. 지문이 다르면 쓰지 않는다. */
fn load_compiled_filter_cache(
    path: &std::path::Path,
    fingerprint: [u8; 32],
) -> Option<EngineParts> {
    use std::io::Read;

    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() > onetdns_filter::MAX_CACHE_BYTES as u64 {
        onetdns_core::warn!(event = "filter.cache_evicted_oversize", path = %path.display(), "크기 제한을 넘은 컴파일된 필터 캐시를 삭제했습니다");
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
            onetdns_core::debug!(event = "filter.cache_unusable", path = %path.display(), %error, "컴파일된 필터 캐시를 사용할 수 없어 원본 규칙을 다시 처리합니다");
            None
        }
    }
}

/** @brief 고정한 것을 저장한다. 전체를 메모리에 담지 않고 흘려 쓴 뒤 교체한다. 다음 시작이 훨씬 빠르다. */
fn save_compiled_filter_cache(
    path: &std::path::Path,
    parts: &mut EngineParts,
    fingerprint: [u8; 32],
) {
    if let Some(parent) = path.parent() {
        if let Err(error) = std::fs::create_dir_all(parent) {
            onetdns_core::warn!(event = "filter.cache_dir_failed", path = %path.display(), %error, "컴파일된 필터 캐시 디렉터리를 만들지 못했습니다");
            return;
        }
    }
    if let Err(error) = atomic_write_with(path, false, |file| {
        onetdns_filter::write_engine_cache(parts, fingerprint, file).map_err(std::io::Error::other)
    }) {
        onetdns_core::warn!(event = "filter.cache_save_failed", path = %path.display(), %error, "컴파일된 필터 캐시를 저장하지 못했습니다");
    }
}

/** @brief 목록 본문에서 제목을 찾는다. */
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

/** @brief 목록에 든 규칙 수. */
fn count_list_rules(body: &str) -> usize {
    body.lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('!') && !t.starts_with('#')
        })
        .count()
}

/** @brief 목록 대신 오류 문서를 받은 것 같은지. 그대로 규칙으로 읽으면 엉뚱한 것이 차단된다. */
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

/** @brief 영역 형식 목록에 든 규칙 수. */
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

/** @brief 내려받을 목록 크기 상한. */
const BLOCKLIST_MAX_RESPONSE: u64 = 128 * 1024 * 1024;

/** @brief 이름 해석 결과를 담아 둘 개수. */
const HOST_RESOLVER_CACHE_CAPACITY: usize = 512;

/** @brief 이름 해석 결과를 담아 둘 최대 기간. */
const HOST_RESOLVER_CACHE_TTL_MAX_SECS: u64 = 300;

/** @brief 이름 해석 실패를 기억할 기간. */
const HOST_RESOLVER_FAILURE_CACHE_TTL: Duration = Duration::from_secs(10);

/** @brief 목록을 내려받을 때 이름을 풀 서버들. 자기 자신은 쓰지 않는다. 아직 서빙 전일 수 있다. */
fn blocklist_bootstrap(cfg: &Config) -> Vec<IpAddr> {
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

/** @brief 목록을 내려받을 때 쓸 이름 해석 방법. */
pub(crate) fn blocklist_host_resolver(cfg: &Config) -> http::HostResolver {
    let bootstrap = blocklist_bootstrap(cfg);
    let recursor = Arc::new(
        new_recursor(recursor_roots(cfg), Duration::from_secs(8))
            .with_recursive_cache_ttl_max(cfg.max_ttl as u32),
    );
    let success_ttl_cap_secs = cfg.max_ttl.min(HOST_RESOLVER_CACHE_TTL_MAX_SECS);
    let cache = Arc::new(Mutex::new(onetdns_core::LruMap::<
        String,
        (std::time::Instant, Duration, Result<Vec<IpAddr>, String>),
    >::new(HOST_RESOLVER_CACHE_CAPACITY)));

    Arc::new(move |host: &str, timeout: Duration| {
        let cache_key = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some((stored_at, ttl, result)) = cache.lock_recover().get(&cache_key).cloned() {
            if stored_at.elapsed() < ttl {
                return result;
            }
        }

        let resolved = if !bootstrap.is_empty() {
            onetdns_forward::resolve_via_bootstrap(host, &bootstrap, timeout)
                .map(|(ip, ttl)| (vec![ip], ttl))
                .ok_or_else(|| format!("호스트명 확인용 DNS 서버로 주소를 찾지 못했습니다: {host}"))
        } else {
            let name = onetdns_proto::Name::from_str(host)
                .map_err(|_| format!("다운로드 주소의 호스트 이름이 올바르지 않습니다: {host}"));
            name.and_then(|name| {
                let mut addresses = Vec::new();
                let mut ttl: Option<u32> = None;
                for qtype in [
                    onetdns_proto::RecordType::A,
                    onetdns_proto::RecordType::AAAA,
                ] {
                    let Ok(response) = recursor.resolve(&name, qtype) else {
                        continue;
                    };
                    for answer in response.answers {
                        ttl = Some(ttl.map_or(answer.ttl, |current| current.min(answer.ttl)));
                        match answer.rdata {
                            onetdns_proto::RData::A(ip) => addresses.push(IpAddr::V4(ip)),
                            onetdns_proto::RData::Aaaa(ip) => addresses.push(IpAddr::V6(ip)),
                            _ => {}
                        }
                    }
                }
                addresses.sort();
                addresses.dedup();
                if addresses.is_empty() {
                    Err(format!(
                        "내장 재귀 리졸버로 호스트 이름을 찾지 못했습니다: {host}"
                    ))
                } else {
                    Ok((addresses, ttl.unwrap_or(0)))
                }
            })
        };

        let (ttl, result) = match resolved {
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

/** @brief 목록 하나를 내려받는다. */
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
        .map_err(|error| format!("차단 목록을 내려받지 못했습니다: {error}"))?;
    if !(200..300).contains(&resp.status) {
        return Err(format!(
            "차단 목록 서버가 오류 상태를 반환했습니다: {}",
            resp.status
        ));
    }
    let body = resp
        .into_string()
        .map_err(|error| format!("차단 목록 응답을 읽지 못했습니다: {error}"))?;
    if body.trim().is_empty() || looks_like_error_document(&body) {
        return Err("블록리스트 본문이 비어 있거나 HTML 오류 문서입니다".to_string());
    }
    let rules = count_list_rules(&body);
    if rules == 0 {
        return Err("블록리스트에서 유효 규칙을 찾지 못했습니다".to_string());
    }
    onetdns_core::debug!(event = "filter.subscription_downloaded", %url, lines = rules, "차단 목록을 내려받았습니다");
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

/** @brief 이 주소의 목록을 담아 둘 파일 이름. */
fn blocklist_cache_key(url: &str) -> String {
    let mut h = 0xcbf29ce484222325u64;
    for b in url.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}.list")
}

/** @brief 내려받은 목록을 담아 둔다. */
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
        .map_err(|e| format!("차단 목록 캐시 디렉터리를 만들지 못했습니다: {e}"))?;
    let path = dir.join(blocklist_cache_key(url));
    let mut body = format!("# onetdns-url:{url}\n# onetdns-updated:{updated_unix}\n");
    body.reserve(text.len() + 1);
    for line in text.lines() {
        body.push_str(line);
        body.push('\n');
    }

    atomic_write(&path, body.as_bytes())
        .map_err(|e| format!("차단 목록 캐시를 저장하지 못했습니다({url}): {e}"))
}

/** @brief 담아 둔 목록을 읽는다. 못 받아도 시작할 수 있게 하려는 것이다. */
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

/** @brief 목록들을 내려받고 그 정보를 모은다. */
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
                    onetdns_core::warn!(event = "filter.subscription_refresh_failed_kept", %url, %error, retained_rules = old.rules, "차단 목록을 갱신하지 못해 이전 목록을 유지합니다");
                    meta.push((*old).clone());
                } else {
                    onetdns_core::warn!(event = "filter.subscription_refresh_failed", %url, %error, "차단 목록을 갱신하지 못했습니다");
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

/** @brief 이 주소의 영역 형식 목록을 담아 둘 파일 이름. */
fn rpz_cache_key(url: &str) -> String {
    format!("{}.rpz", blocklist_cache_key(url).trim_end_matches(".list"))
}

/** @brief 내려받은 영역 형식 목록을 담아 둔다. */
fn save_rpz_cache(url: &str, body: &str, dir: Option<&std::path::Path>) -> Result<(), String> {
    let Some(dir) = dir else {
        return Ok(());
    };
    std::fs::create_dir_all(dir)
        .map_err(|error| format!("RPZ 캐시 디렉터리를 만들지 못했습니다: {error}"))?;
    let mut cached = format!(
        "# onetdns-rpz-url:{url}\n# onetdns-updated:{}\n",
        unix_now()
    );
    cached.push_str(body);
    if !cached.ends_with('\n') {
        cached.push('\n');
    }
    atomic_write(&dir.join(rpz_cache_key(url)), cached.as_bytes())
        .map_err(|error| format!("RPZ 캐시를 저장하지 못했습니다({url}): {error}"))
}

/** @brief 담아 둔 영역 형식 목록을 읽는다. */
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

/** @brief 영역 형식 목록들을 내려받는다. */
/**
 * @brief 이전에 받아 둔 RPZ 본문을 새 URL 목록 순서로 다시 정렬한다.
 * @details 받아 둔 본문은 URL 목록과 같은 순서로 놓인다. 목록 가운데 하나를 빼면 뒤쪽이
 *          당겨지므로, 위치로 짝지으면 다운로드에 실패한 URL 위치에 다른 목록의 규칙이 들어간다.
 * @param old_urls 받아 둔 본문이 따르는 URL 목록.
 * @param old_texts 받아 둔 본문.
 * @param urls 새 URL 목록.
 * @return urls와 같은 길이. 받아 둔 적 없는 URL 슬롯은 빈 문자열이다.
 */
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
                        "HTTP 상태 {}",
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
                onetdns_core::debug!(event = "filter.rpz_downloaded", %url, bytes = body.len(), "RPZ 규칙을 내려받았습니다");
                if let Err(error) = save_rpz_cache(url, &body, cache_dir) {
                    onetdns_core::warn!(event = "filter.rpz_cache_save_failed", %url, %error, "RPZ 캐시 파일을 저장하지 못했습니다");
                }
                out.push(body);
            }
            Ok(_) => {
                if let Some(old) = previous.get(index) {
                    onetdns_core::warn!(event = "filter.rpz_empty_kept", %url, "내려받은 RPZ 데이터에 사용할 수 있는 규칙이 없어 이전 규칙을 유지합니다");
                    out.push(old.clone());
                } else {
                    onetdns_core::warn!(event = "filter.rpz_empty", %url, "내려받은 RPZ 데이터에 사용할 수 있는 규칙이 없습니다");
                    out.push(String::new());
                }
            }
            Err(error) => {
                if let Some(old) = previous.get(index) {
                    onetdns_core::warn!(event = "filter.rpz_refresh_failed_kept", %url, %error, "RPZ 규칙을 갱신하지 못해 이전 규칙을 유지합니다");
                    out.push(old.clone());
                } else {
                    onetdns_core::warn!(event = "filter.rpz_download_failed", %url, %error, "RPZ 규칙을 내려받지 못했습니다");
                    out.push(String::new());
                }
            }
        }
    }
    out
}

/** @brief 설정에 적은 규칙을 엔진에 넣는다. */
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
            format!("rewrites[{index}].answer에 올바른 IP 주소 또는 DNS 이름이 필요합니다")
        })?;
        add_rewrite(parts, &rw.domain, target)
            .map_err(|error| format!("rewrites[{index}].domain: {error}"))?;
    }
    for (index, lz) in local_zones.iter().enumerate() {
        apply_local_zone(parts, lz).map_err(|error| format!("local_zones[{index}]: {error}"))?;
    }
    for f in rpz_files {
        let text = read_text_limited(f, BLOCKLIST_MAX_RESPONSE)
            .map_err(|error| format!("RPZ 파일을 읽지 못했습니다({}): {error}", f.display()))?;
        onetdns_filter::parse_rpz_text(&text, parts);
    }
    Ok(())
}

/** @brief 재작성이 답할 값을 읽는다. */
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

/** @brief 재작성 규칙 하나를 넣는다. */
fn add_rewrite(parts: &mut EngineParts, domain: &str, target: RewriteTarget) -> Result<(), String> {
    let domain = domain.trim();
    let parsed = domain.strip_prefix("*.").unwrap_or(domain);
    if parsed.is_empty() || parsed.contains('*') || onetdns_proto::Name::from_str(parsed).is_err() {
        return Err("올바른 정확 일치 이름 또는 `*.하위영역`이 아닙니다".to_string());
    }
    if domain.starts_with("*.") {
        parts.rewrites.add_suffix(domain, target);
    } else {
        parts.rewrites.add_exact(domain, target);
    }
    Ok(())
}

/** @brief 설정에서 읽은 로컬 영역 답을 필터가 쓰는 형태로 바꾼다. */
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
                .map_err(|_| format!("CNAME 대상 '{name}'이 올바른 DNS 이름이 아닙니다"))?,
        ),
    })
}

/**
 * @brief 설정에 적은 영역 규칙을 엔진에 넣는다.
 * @details 영역은 엔진의 로컬 영역 집합에 따로 들어간다. 한 이름에는 가장 구체적인 영역만
 *          걸리므로 transparent 영역은 둘러싼 로컬 영역의 처분만 거두고, 차단 목록과 사용자
 *          규칙에는 손대지 않는다.
 */
fn apply_local_zone(parts: &mut EngineParts, lz: &LocalZone) -> Result<(), String> {
    if onetdns_proto::Name::from_str(lz.name.trim()).is_err() {
        return Err("name에 올바른 DNS 영역 이름이 필요합니다".to_string());
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
                return Err("redirect 영역에는 영역 이름 하나의 답만 있어야 합니다".to_string());
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

/**
 * @brief 목록 갱신 스레드가 한 번 실행되는 간격(초).
 *
 * @details 주기를 기다리는 동안에도 설정이 바뀌었는지 이 간격마다 본다. 짧게 두면 주소를
 *          더한 직후 바로 받아 오지만 그만큼 자주 깬다.
 */
pub(crate) const LIST_REFRESH_TICK_SECS: u64 = 5;

/**
 * @brief 서비스 차단 일정의 경계를 확인하는 간격.
 * @details 일정은 분 단위로 적으므로 경계를 이만큼 늦게 알아챌 수 있다.
 */
pub(crate) const SERVICE_SCHEDULE_TICK_SECS: u64 = 20;

/**
 * @brief 켜 둔 미리 담긴 차단 목록의 주소들.
 *
 * @details 시작할 때와 교체할 때 모두 이 함수만 부른다. 두 곳에서 따로 만들면 켠 뒤
 *          다시 읽었을 때 목록이 서로 달라진다.
 */
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

/** @brief 이미 갱신 중이라는 문구. */
pub(crate) const LIST_REFRESH_BUSY: &str = "블록리스트 갱신 작업이 이미 실행 중";

/** @brief 목록 갱신을 한 번에 하나만 돌게 한다. */
pub(crate) fn try_list_refresh_lock(
    lock: &Mutex<()>,
) -> Result<std::sync::MutexGuard<'_, ()>, String> {
    match lock.try_lock() {
        Ok(guard) => Ok(guard),
        Err(std::sync::TryLockError::Poisoned(error)) => Ok(error.into_inner()),
        Err(std::sync::TryLockError::WouldBlock) => Err(LIST_REFRESH_BUSY.to_string()),
    }
}

/** @brief 내장 목록 주소가 어느 설정에서 왔는지. 화면이 켜고 끄는 곳을 안내할 때 쓴다. */
pub(crate) fn preset_list_kind(url: &str) -> &'static str {
    if onetdns_filter::presets::PARENTAL_LISTS.contains(&url) {
        "parental_control"
    } else {
        "safe_browsing"
    }
}

/** @brief 지금 쓰는 목록 주소들. 겹치지 않게 순서를 지켜 모은다. */
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

/** @brief 목록 구독 상태를 설정에 적는다. */
pub(crate) fn persist_subscription_state(
    path: Option<&std::path::Path>,
    urls: &[String],
    titles: &[String],
    disabled: &[String],
) -> Result<(), String> {
    let Some(p) = path else {
        return Err("설정 파일 경로가 없습니다".to_string());
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
/** @brief 차단 목록 수집, 캐시, 필터 엔진 구성. */
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
    /** @brief 고정한 차단 엔진이 흘려 저장되고 다시 읽히는지. */
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
    /** @brief 잘못된 재작성과 영역 규칙이 조용히 사라지지 않는지. */
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
    /**
     * @brief 설정의 static 영역이 이름별 답을 엔진까지 그대로 옮기는지.
     * @details static을 redirect처럼 로드하면 적지 않은 이름까지 같은 주소로 답해, 없어야 할
     *          이름이 살아난다.
     */
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
    /**
     * @brief 설정의 transparent 영역이 둘러싼 로컬 영역만 거두는지.
     * @details 이 값이 아무것도 하지 않으면 deny 영역 아래를 풀려는 설정이 조용히 무시되고,
     *          차단 목록까지 풀면 구독한 목록이 무력화된다.
     */
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
    /** @brief 목록을 못 읽었을 때 차단이 전부 풀리지 않는지. */
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
    /**
     * @brief 서비스 차단 일정 구간에서는 서비스 규칙만 빠지고 다른 규칙은 남는지.
     * @details 구간 안에서 필터 전체를 건너뛰면 차단 목록과 사용자 규칙까지 풀린다.
     */
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
    /** @brief 사용자 규칙이 검사되고 종류가 갈리는지. */
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
    /** @brief URL 하나를 빼도 남은 URL이 제 본문과 짝지어지는지. */
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
    /** @brief 목록 주소가 겹치지 않고 순서를 지키는지. */
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
    /** @brief 목록을 받을 때 자기 자신에게 묻지 않는지. 물으면 시작 중 순환이 된다. */
    fn blocklist_bootstrap_never_uses_loopback_dns() {
        let mut config = Config::default();
        config.bootstrap = vec![
            "127.0.0.1".parse().unwrap(),
            "::1".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
        ];
        assert_eq!(
            blocklist_bootstrap(&config),
            vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    /** @brief 모든 주소에 묶었을 때 이 기계를 가리키는 이름 해석 출처를 거부하는지. */
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
        assert!(blocklist_bootstrap(&config).is_empty());
    }

    #[test]
    /** @brief 담아 둔 목록에서 제목이 되살아나는지. */
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
    /** @brief 담아 둔 영역 형식 목록의 헤더를 확인하는지. */
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
    /** @brief 원본 줄을 놓아준 뒤에도 지문이 그대로인지. 달라지면 매 시작마다 다시 고정한다. */
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
